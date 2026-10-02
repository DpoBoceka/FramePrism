//! Native FAST lossless JPEG (SOF3, ITU-T T.81) decoder.
//!
//! The speed twin of `ljpeg_ref`: the SAME golden-model contract —
//! SOF3 (lossless) only, 2–16 bit data precision, Nf components,
//! canonical DC Huffman tables from the DHT (per-component selector
//! from the SOS AhAl byte), the standard per-MCU scan order (row y,
//! column x, then components in SOS order), PSV 1..7 with the
//! libjpeg / DNG-SDK Table H.1 formulas, the T.81 edge predictors,
//! the arithmetic (toward -inf) shifts, and the standard JPEG byte
//! stuffing — but the bit machinery is a 64-bit accumulator with a
//! byte-queued refill and the Huffman match is the table-driven
//! canonical form (the accumulated k-bit value v matches length k iff
//! 0 <= v - first(k) < c(k)) instead of the reference model's
//! bit-at-a-time Python-port loop.
//!
//! CONTRACT (the binding one): for every input, the accept/reject
//! verdict, the decoded planes (when accepted), the frame facts, and
//! the error (the variant AND the Display string, incl. the offsets)
//! are IDENTICAL to `ljpeg_ref::decode` — the reference model stays
//! the acceptance authority; this module is a faster implementation
//! of the same model, never a second opinion. The equivalence is
//! pinned by the KATs (the corpus bit-exact canary over the
//! reference's accepted set — incl. the whole-body-divergent streams
//! the reference decodes to the correct planes — + the synthetic
//! corruption equivalence over the failure modes).
//!
//! The measured fp tile-stream format this fast path serves (the
//! per-tile stream facts, measured on the camera corpus): SOF3
//! precision 12, 2 components (the even/odd COLUMN split of the
//! full-nominal tile — 256×368 per component), DHT tcc 0x00 + 0x01
//! (per-component DC tables), NO AC table (DC-only lossless), the
//! SOS Ss = the single PSV of the scan, Se = 0, AhAl = 0. The decoder
//! itself is format-generic (precision 2..16, PSV 1..7, Nf 2..16)
//! exactly like the reference model; the swap rides the fp path only.

use crate::ljpeg_ref::{RefError, RefFrame};

/// One Huffman table: counts per code length (index = length, 1..16) +
/// the symbol values in canonical code order + the precomputed
/// canonical-match arrays (`first` / `prefix` — the D.1 code
/// assignment: first(k+1) = (first(k) + c(k)) * 2, first(1) = 0;
/// prefix(k) = the number of codes shorter than k).
struct Huff {
    counts: [u32; 17],
    vals: Vec<u8>,
    first: [i32; 17],
    prefix: [usize; 17],
}

fn build_huff(payload: &[u8]) -> std::collections::BTreeMap<u8, Huff> {
    let mut out: std::collections::BTreeMap<u8, Huff> = std::collections::BTreeMap::new();
    let mut i = 0usize;
    while i + 17 <= payload.len() {
        let tc_tq = payload[i];
        let counts = &payload[i + 1..i + 17];
        let n: usize = counts.iter().map(|&c| c as usize).sum();
        if i + 17 + n > payload.len() {
            break;
        }
        let vals = payload[i + 17..i + 17 + n].to_vec();
        i += 17 + n;
        let mut counts_arr = [0u32; 17];
        for (k, &c) in counts.iter().enumerate() {
            counts_arr[k + 1] = c as u32;
        }
        let mut first = [0i32; 17];
        for k in 1..16 {
            first[k + 1] = (first[k] + counts_arr[k] as i32) * 2;
        }
        let mut prefix = [0usize; 17];
        for k in 2..17 {
            prefix[k] = prefix[k - 1] + counts_arr[k - 1] as usize;
        }
        out.insert(
            tc_tq,
            Huff {
                counts: counts_arr,
                vals,
                first,
                prefix,
            },
        );
    }
    out
}

/// Bit reader with JPEG bit stuffing (0xFF → skip the following 0x00) +
/// the 64-bit accumulator. The byte-consumption order is IDENTICAL to
/// the reference model's (a byte is pulled exactly when the bit stream
/// demands it; the stuffed zero is skipped in the same position), so
/// the `Truncated` offset on a short stream is the same offset the
/// reference model reports. The invariant: the `nbits` VALID bits sit
/// in the TOP `nbits` positions of `acc` (u64 — a pull is only
/// requested with `nbits < 16`, so the `<< 8` can never push a valid
/// bit out of the width; the 32-bit width would lose the top valid
/// bits on exactly that pull).
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u64,
    nbits: u32,
}

impl<'a> Bits<'a> {
    /// The reference model's `bit()` — one bit MSB-first; the byte
    /// pull (incl. the stuffing skip) happens exactly when the
    /// accumulator is empty.
    fn bit(&mut self) -> Result<u32, RefError> {
        if self.nbits == 0 {
            let b = *self
                .data
                .get(self.pos)
                .ok_or(RefError::Truncated(self.pos))?;
            self.pos += 1;
            if b == 0xFF && self.data.get(self.pos) == Some(&0x00) {
                self.pos += 1; // stuffed zero byte
            }
            self.acc = b as u64;
            self.nbits = 8;
        }
        let b = ((self.acc >> (self.nbits - 1)) & 1) as u32;
        self.nbits -= 1;
        Ok(b)
    }

    /// `n` bits MSB-first (the value-bit pull — the reference model's
    /// `take`; the byte pulls are the same sequence, so a short
    /// stream reports the same `Truncated` offset).
    fn take(&mut self, n: u32) -> Result<u32, RefError> {
        if n == 0 {
            return Ok(0);
        }
        while self.nbits < n {
            let b = *self
                .data
                .get(self.pos)
                .ok_or(RefError::Truncated(self.pos))?;
            self.pos += 1;
            if b == 0xFF && self.data.get(self.pos) == Some(&0x00) {
                self.pos += 1;
            }
            self.acc = (self.acc << 8) | b as u64;
            self.nbits += 8;
        }
        // The MASK is load-bearing: the positions ABOVE the valid
        // region hold the already-consumed code bits (the batch pull
        // only shifts them further up, it never clears them) — the
        // bit-at-a-time reference reader never sees them, so a batch
        // read must mask them out or the consumed bits leak into the
        // value.
        let v = ((self.acc >> (self.nbits - n)) & ((1u64 << n) - 1)) as u32;
        self.nbits -= n;
        Ok(v)
    }
}

/// Canonical Huffman decode (the D.1 code assignment, the table-driven
/// form): the accumulated k-bit value v matches length k iff
/// 0 <= v - first(k) < c(k); the symbol is vals[prefix(k) + rank].
/// The 16-bit exhaustion (no match) fails at the caller's sample
/// position exactly like the reference model.
fn huff_symbol(br: &mut Bits, h: &Huff, pos: usize) -> Result<u8, RefError> {
    let mut v: i32 = 0;
    for k in 1..=16u32 {
        v = (v << 1) | br.bit()? as i32;
        let rank = v - h.first[k as usize];
        let c = h.counts[k as usize];
        if rank >= 0 && rank < c as i32 {
            return Ok(h.vals[h.prefix[k as usize] + rank as usize]);
        }
        // first(k+1) = (first(k) + c(k)) * 2 — precomputed in `first`.
    }
    Err(RefError::HuffmanFailed(pos))
}

/// T.81 predictors, libjpeg / DNG-SDK Table H.1 numbering (a=left,
/// b=up, c=diag) — the reference model's formulas (the arithmetic
/// shifts are Rust's two's-complement `>>`, floor for negatives — the
/// C/libjpeg RIGHT_SHIFT semantics).
#[inline]
fn pred(psv: u32, a: i32, b: i32, c: i32) -> Result<i32, RefError> {
    Ok(match psv {
        1 => a,
        2 => b,
        3 => c,
        4 => a + b - c,
        5 => a + ((b - c) >> 1),
        6 => b + ((a - c) >> 1),
        7 => (a + b) >> 1,
        _ => return Err(RefError::BadPsv(psv)),
    })
}

/// Decode one (Huffman symbol, value bits) → the category difference
/// (the H.1.2 symbol mapping — the reference model's exact rules:
/// cat 0 → 0; cat 16 → -32768; else the cat-bit value with the
/// sign-bit rule).
#[inline]
fn symdiff(br: &mut Bits, cat: u8) -> Result<i32, RefError> {
    if cat == 0 {
        Ok(0)
    } else if cat == 16 {
        Ok(-32768)
    } else {
        let v = br.take(cat as u32)?;
        if v < (1u32 << (cat as u32 - 1)) {
            Ok((v as i32) - ((1i32 << cat as u32) - 1))
        } else {
            Ok(v as i32)
        }
    }
}

/// Decode a SOF3 stream -> (frame facts, per-component planes
/// row-major). The fast twin of `ljpeg_ref::decode` (the module
/// contract binds: identical verdicts / planes / errors).
pub fn decode(jpeg: &[u8]) -> Result<(RefFrame, Vec<Vec<u16>>), RefError> {
    if jpeg.len() < 4 || jpeg[0] != 0xFF || jpeg[1] != 0xD8 {
        return Err(RefError::SyncLost(0));
    }
    let mut i = 2usize;
    let mut dht: std::collections::BTreeMap<u8, Huff> = std::collections::BTreeMap::new();
    let mut sof: Option<&[u8]> = None;
    let mut sos: Option<&[u8]> = None;
    let mut scan_start = 0usize;
    'markers: while i + 4 <= jpeg.len() {
        if jpeg[i] != 0xFF {
            return Err(RefError::SyncLost(i));
        }
        let m = jpeg[i + 1];
        if m == 0xD9 {
            break; // EOI before SOS
        }
        if m == 0x01 || (0xD0..=0xD7).contains(&m) || m == 0xD8 {
            i += 2;
            continue;
        }
        if i + 4 > jpeg.len() {
            return Err(RefError::Truncated(i));
        }
        let ln = u16::from_be_bytes([jpeg[i + 2], jpeg[i + 3]]) as usize;
        if i + 2 + ln > jpeg.len() {
            return Err(RefError::Truncated(i));
        }
        let payload = &jpeg[i + 4..i + 2 + ln];
        match m {
            0xC3 => sof = Some(payload),
            0xC4 => {
                for (k, v) in build_huff(payload) {
                    dht.insert(k, v);
                }
            }
            0xDA => {
                sos = Some(payload);
                scan_start = i + 2 + ln;
                break 'markers;
            }
            0xC0..=0xC2 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => {
                return Err(RefError::NotLossless(m));
            }
            _ => {} // APPn / COM / other markers: skip
        }
        i += 2 + ln;
    }
    let sof = sof.ok_or(RefError::MissingSof)?;
    let sos = sos.ok_or(RefError::MissingSos)?;

    // --- SOF3 (the reference model's validation, verbatim) -----------
    if sof.len() < 6 + 3 {
        return Err(RefError::Truncated(0));
    }
    let precision = sof[0] as u32;
    let (height, width) = (
        (sof[1] as u32) << 8 | sof[2] as u32,
        (sof[3] as u32) << 8 | sof[4] as u32,
    );
    let nf = sof[5] as u32;
    if nf == 0 || (6 + 3 * nf as usize) > sof.len() {
        return Err(RefError::Truncated(0));
    }

    // --- SOS (the reference model's validation, verbatim) ------------
    if sos.len() < 6 {
        return Err(RefError::Truncated(0));
    }
    let ns = sos[0] as usize;
    if 1 + 2 * ns + 3 > sos.len() || ns != nf as usize {
        return Err(RefError::Truncated(0));
    }
    // Per SOS component: (cid, Ah, Al). In lossless mode Al is the
    // point transform (Pt); Ah selects the DC table.
    let mut sos_comps: Vec<(u8, u8, u8)> = Vec::with_capacity(ns);
    for c in 0..ns {
        sos_comps.push((
            sos[1 + 2 * c],
            (sos[2 + 2 * c] >> 4) & 0xF,
            sos[2 + 2 * c] & 0xF,
        ));
    }
    let psv = sos[1 + 2 * ns] as u32; // Ss = PSV for lossless
    let pt = (sos[3 + 2 * ns] & 0xF) as u32; // the SOS last byte's Al = Pt
    if !(1..=7).contains(&psv) {
        return Err(RefError::BadPsv(psv));
    }
    if !(2..=16).contains(&precision) || pt >= precision {
        return Err(RefError::Truncated(0));
    }

    // Per component (in SOS order): its DC table (the reference
    // model's lookup + error, verbatim).
    let mut tables: Vec<&Huff> = Vec::with_capacity(ns);
    for (cid, ah, _al) in &sos_comps {
        let h = dht
            .get(ah)
            .ok_or(RefError::TableMissing { id: *ah, cid: *cid })?;
        tables.push(h);
    }

    // --- entropy (the fast scan — the reference model's sample order,
    //     predictor rules + range checks, verbatim semantics) --------
    let mut br = Bits {
        data: jpeg,
        pos: scan_start,
        acc: 0,
        nbits: 0,
    };
    let edge = 1i32 << (precision - 1 - pt);
    let maxv = 1i32 << precision;
    let (w, h) = (width as usize, height as usize);
    let nf = tables.len();
    let mut comps: Vec<Vec<i32>> = vec![vec![0i32; w * h]; nf];

    // Row 0: col 0 = the edge predictor; the rest = LEFT only
    // (the reference model's y==0 rule — psv-independent).
    for x in 0..w {
        let idx = x;
        for (ci, t) in tables.iter().enumerate() {
            let cat = huff_symbol(&mut br, t, idx)?;
            let d = symdiff(&mut br, cat)?;
            let s = if x == 0 { edge } else { comps[ci][idx - 1] };
            let v = s + d;
            if v < 0 || v >= maxv {
                return Err(RefError::SampleRange { v, p: precision });
            }
            comps[ci][idx] = v;
        }
    }
    // Rows 1..h: col 0 = UP only (the reference model's x==0 rule);
    // the interior = the psv predictor.
    for y in 1..h {
        let base = y * w;
        // col 0 (up only).
        for (ci, t) in tables.iter().enumerate() {
            let idx = base;
            let cat = huff_symbol(&mut br, t, idx)?;
            let d = symdiff(&mut br, cat)?;
            let s = comps[ci][idx - w];
            let v = s + d;
            if v < 0 || v >= maxv {
                return Err(RefError::SampleRange { v, p: precision });
            }
            comps[ci][idx] = v;
        }
        // cols 1..w (the psv predictor).
        for x in 1..w {
            let idx = base + x;
            for (ci, t) in tables.iter().enumerate() {
                let cat = huff_symbol(&mut br, t, idx)?;
                let d = symdiff(&mut br, cat)?;
                let s = pred(
                    psv,
                    comps[ci][idx - 1],
                    comps[ci][idx - w],
                    comps[ci][idx - w - 1],
                )?;
                let v = s + d;
                if v < 0 || v >= maxv {
                    return Err(RefError::SampleRange { v, p: precision });
                }
                comps[ci][idx] = v;
            }
        }
    }

    let planes: Vec<Vec<u16>> = comps
        .into_iter()
        .map(|c| c.into_iter().map(|v| v as u16).collect())
        .collect();
    Ok((
        RefFrame {
            width,
            height,
            nf: nf as u32,
            precision,
            psv,
            pt,
        },
        planes,
    ))
}

