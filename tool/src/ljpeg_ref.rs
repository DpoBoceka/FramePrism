//! Canonical lossless JPEG (SOF3, ITU-T T.81) reference decoder.
//!
//! Rust port of `tools/ljpeg_decode.py` (the PRD's reference decoder) — the
//! acceptance gate for tile decode (guardrail G3): the libjpeg
//! self-roundtrip must never be the acceptance gate, so acceptance decode
//! runs this standard-order model instead.
//!
//! Supported (matches the Python reference):
//! - SOF3 (lossless) only; 2–16 bit data precision; Nf components
//! - canonical DC Huffman tables from DHT (class 0; per-component selector
//!   from the SOS AhAl byte)
//! - standard per-MCU scan order: row y, column x, then components in SOS
//!   order (one sample per component per MCU for 1x1 sampling)
//! - PSV 1..7 with the libjpeg / DNG-SDK Table H.1 formulas (NOTE: numbers
//!   4..7 differ from the T.81 spec's own Table H.1 — do not mix them up);
//!   arithmetic (toward -inf) shifts, exactly as libjpeg's RIGHT_SHIFT
//! - edge predictors per T.81 / DNG-SDK: first sample of each component =
//!   2^(P−Pt−1); rest of first row = left only; first column of later rows
//!   = up only
//! - standard JPEG bit stuffing (0xFF byte followed by a skipped 0x00)

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum RefError {
    #[error("lost JPEG sync at offset {0}")]
    SyncLost(usize),
    #[error("frame header is not SOF3 (lossless)")]
    NotLossless(u8),
    #[error("missing SOF3 frame header")]
    MissingSof,
    #[error("missing SOS scan header")]
    MissingSos,
    #[error("no DC Huffman table {id} for component id {cid}")]
    TableMissing { id: u8, cid: u8 },
    #[error("Huffman code not in table at plane position {0} (corrupt stream?)")]
    HuffmanFailed(usize),
    #[error("bad predictor selection value {0} (need 1..7)")]
    BadPsv(u32),
    #[error("decoded sample {v} outside {p}-bit range")]
    SampleRange { v: i32, p: u32 },
    #[error("truncated data at offset {0}")]
    Truncated(usize),
}

/// SOF3/SOS frame facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefFrame {
    /// Columns per component.
    pub width: u32,
    /// Rows per component.
    pub height: u32,
    /// Number of components.
    pub nf: u32,
    /// Data precision P (2..16).
    pub precision: u32,
    /// Predictor selection value (SOS Ss; libjpeg numbering 1..7).
    pub psv: u32,
    /// Point transform Pt (SOS last byte; 0 for this project).
    pub pt: u32,
}

/// One Huffman table: counts per code length (index = length, 1..16) +
/// symbol values in canonical code order.
struct Huff {
    counts: [u32; 17],
    vals: Vec<u8>,
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
        out.insert(
            tc_tq,
            Huff {
                counts: counts_arr,
                vals,
            },
        );
    }
    out
}

/// Bit reader with JPEG bit stuffing (0xFF → skip the following 0x00).
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u32,
    nbits: u32,
}

impl<'a> Bits<'a> {
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
            self.acc = b as u32;
            self.nbits = 8;
        }
        let b = (self.acc >> (self.nbits - 1)) & 1;
        self.nbits -= 1;
        Ok(b)
    }

    fn take(&mut self, n: u32) -> Result<u32, RefError> {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.bit()?;
        }
        Ok(v)
    }
}

/// Canonical Huffman decode (D.1 code assignment): the accumulated k-bit
/// value v matches length k iff 0 <= v - first(k) < c(k);
/// first(k+1) = (first(k) + c(k)) * 2, first(1) = 0.
fn huff_symbol(br: &mut Bits, h: &Huff, pos: usize) -> Result<u8, RefError> {
    let mut v: i32 = 0;
    let mut first: i32 = 0;
    let mut prefix = 0usize;
    for k in 1..=16u32 {
        v = (v << 1) | br.bit()? as i32;
        let rank = v - first;
        let c = h.counts[k as usize];
        if (0..c as i32).contains(&rank) {
            return Ok(h.vals[prefix + rank as usize]);
        }
        first = (first + c as i32) * 2;
        prefix += c as usize;
    }
    Err(RefError::HuffmanFailed(pos))
}

/// T.81 predictors, libjpeg / DNG-SDK Table H.1 numbering (a=left, b=up,
/// c=diag). Right shifts are arithmetic (C/libjpeg RIGHT_SHIFT semantics;
/// floor for negatives) — matches the Python reference's //.
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

/// Decode a SOF3 stream -> (frame facts, per-component planes row-major).
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

    // --- SOF3 ----------------------------------------------------------------
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
    let mut comp_ids = Vec::with_capacity(nf as usize);
    for c in 0..nf {
        comp_ids.push(sof[6 + 3 * c as usize]); // component id
    }

    // --- SOS -------------------------------------------------------------------
    if sos.len() < 6 {
        return Err(RefError::Truncated(0));
    }
    let ns = sos[0] as usize;
    if 1 + 2 * ns + 3 > sos.len() || ns != nf as usize {
        return Err(RefError::Truncated(0));
    }
    // Per SOS component: (cid, Ah, Al). In lossless mode Al is the point
    // transform (Pt); Ah selects the DC table.
    let mut sos_comps: Vec<(u8, u8, u8)> = Vec::with_capacity(ns);
    for c in 0..ns {
        sos_comps.push((
            sos[1 + 2 * c],
            (sos[2 + 2 * c] >> 4) & 0xF,
            sos[2 + 2 * c] & 0xF,
        ));
    }
    let psv = sos[1 + 2 * ns] as u32; // Ss = PSV for lossless
    let pt = (sos[3 + 2 * ns] & 0xF) as u32; // last byte of the SOS = AhAl; Al = Pt
    if !(1..=7).contains(&psv) {
        return Err(RefError::BadPsv(psv));
    }
    if !(2..=16).contains(&precision) || pt >= precision {
        return Err(RefError::Truncated(0));
    }

    // Per component (in SOS order): its DC table.
    let mut tables: Vec<&Huff> = Vec::with_capacity(ns);
    for (cid, ah, _al) in &sos_comps {
        let h = dht
            .get(ah)
            .ok_or(RefError::TableMissing { id: *ah, cid: *cid })?;
        tables.push(h);
    }

    // --- entropy ----------------------------------------------------------------
    let br = &mut Bits {
        data: jpeg,
        pos: scan_start,
        acc: 0,
        nbits: 0,
    };
    let edge = 1i32 << (precision - 1 - pt);
    let mut comps: Vec<Vec<i32>> = vec![vec![0i32; (width * height) as usize]; nf as usize];
    let (w, h) = (width as usize, height as usize);
    for y in 0..h {
        for x in 0..w {
            let idx = y * w + x;
            for ci in 0..tables.len() {
                let cat = huff_symbol(br, tables[ci], idx)?;
                let d: i32 = if cat == 0 {
                    0
                } else if cat == 16 {
                    -32768
                } else {
                    let v = br.take(cat as u32)?;
                    if v < (1u32 << (cat as u32 - 1)) {
                        (v as i32) - ((1i32 << cat as u32) - 1)
                    } else {
                        v as i32
                    }
                };
                let s = if y == 0 && x == 0 {
                    edge
                } else if y == 0 {
                    comps[ci][idx - 1]
                } else if x == 0 {
                    comps[ci][idx - w]
                } else {
                    pred(
                        psv,
                        comps[ci][idx - 1],
                        comps[ci][idx - w],
                        comps[ci][idx - w - 1],
                    )?
                };
                let v = s + d;
                if v < 0 || v >= (1i32 << precision) {
                    return Err(RefError::SampleRange { v, p: precision });
                }
                comps[ci][idx] = v;
            }
        }
    }
    let _ = &comp_ids; // component ids are carried in the SOF; planes are
                       // returned in SOS order (== SOF order for this project)
    let planes: Vec<Vec<u16>> = comps
        .into_iter()
        .map(|c| c.into_iter().map(|v| v as u16).collect())
        .collect();
    Ok((
        RefFrame {
            width,
            height,
            nf,
            precision,
            psv,
            pt,
        },
        planes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_sof3() {
        // SOI + SOF0 (baseline DCT) instead of SOF3.
        let bad: Vec<u8> = vec![
            0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11,
            0x00,
        ];
        assert!(matches!(decode(&bad), Err(RefError::NotLossless(0xC0))));
        assert!(matches!(
            decode(&[0xFF, 0xD8, 0xFF, 0xD9]),
            Err(RefError::MissingSof)
        ));
    }
}
