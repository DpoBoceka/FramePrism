//! Native T.81 lossless (SOF3) entropy encoder for frameprism tiles.
//!
//! Speed program. Why: the 0.1.0 default path
//! trial-encodes every tile 3× through the libjpeg-turbo FFI shim
//! (3-candidate selection) at ~4.5–5.5 ns/sample. The fixed tile geometry
//! (136×482 wrapped / 272×241 natural planes, 2 components, 1×1 sampling,
//! Pt=0, no restart interval, per-component optimized DC tables) makes a
//! native Rust encoder feasible at ~1.5 ns/sample — the "C lever" — which
//! also enables cheap exact-size candidate selection (the "A lever").
//!
//! CONTRACT: for any (planes, precision, psv) the stream must be
//! BYTE-IDENTICAL to the libjpeg output (`tileenc::encode_planes`) — the
//! oracles are the 0.1.0 lossless goldens. The exact format
//! this module reproduces, pinned from the golden bytes + the patched
//! libjpeg source.
//!
//! Pipeline (mirrors `ljpeg_encode_lossless2` exactly; two-pass shape,
//! the independent Rust DNG CLI's ljpeg92 class):
//! 1. **Histogram pass** (per component): the predictor/difference rules
//!    (first row col 0 = 2^(precision−1); every non-first-row col 0 = Rb
//!    regardless of PSV; PSV predictor for the rest) + the H.1.2.2 symbol
//!    mapping, monomorphized per PSV (no per-sample match).
//! 2. **Table pass**: per-component optimized Huffman table — exact port
//!    of `jpeg_gen_optimal_table` (IJG Annex K.2: pseudo-symbol 256 count
//!    1, two-smallest merge ties → larger index, >16-length adjustment,
//!    pseudo count dropped from the largest length in use) + canonical
//!    codes (Fig. C.1–C.3), packed as (code << 5) | len per symbol.
//! 3. **Emission pass**: markers (SOI → SOF3 → DHT TT=00 → DHT TT=01 →
//!    SOS, per-component DC tables — the patched-libjpeg structure),
//!    then per plane pixel: component-0 symbol, component-1 symbol
//!    (MCU = 1 sample/component, membership [0,1], raster order);
//!    MSB-first 24-bit accumulator, ≤7 bits retained between emits,
//!    0xFF ⇒ 0x00 stuffing; scan end = partial byte padded with ones
//!    (`emit(0x7F, 7)` + reset) + EOI.
//!
//! The trailing even-size pad byte (FFD9 0x00) is added by the CALLER
//! (`encode_tile_candidates`), exactly as in the libjpeg path.
//!
//! Hot-path notes (the Huffman survey record — the independent Rust
//! DNG CLI's ljpeg92 as the speed reference):
//! - predictor is monomorphized per PSV (7 kernel pairs, macro-generated;
//!   the PSV dispatch happens once per plane, never per sample);
//! - one packed (code,len) 32-bit load per symbol (len ≤ 16 fits 5 bits);
//! - no per-symbol or per-table allocation (fixed [..;257] workspaces on
//!   the stack; per-component prev-row buffers reused between passes);
//! - the W8 trait is the seam: a counting writer with the same
//!   semantics makes the size-only (A-lever) pass a drop-in.

use crate::tileenc::{Planes, TileError};

/// Native encode of one oriented tile — same input contract as
/// `tileenc::encode_planes` (`p` comes from `planes_from_tile`), same
/// output shape (raw SOI..EOI stream, even pad applied by the caller).
/// `precision` 8 (native 8-bit lossless), 10 (log10 codes) or 12
/// (lossless); `psv` 1..7.
pub fn encode_planes_native(p: &Planes, precision: u32, psv: i32) -> Result<Vec<u8>, TileError> {
    // Combined-emit seam: the combined-emit variants (byte-identical output,
    // different byte machinery). v1 is the DEFAULT (1.27–1.35×
    // faster wall, byte-identical to `current` and the 0.1.0 goldens —
    // 7,168 tile-candidates + 225f/14,400 tiles + 20f USB + 10f oracle
    // 24,695,978 B + 31,900 cmps / 7,250 size checks, all 0 diffs). Set
    // FRAMEPRISM_EMITTER=current for the original production path below,
    // or =v2 for the batched-flush variant (no measured gain).
    let v = emitter_variant();
    if v != 0 {
        return encode_planes_native_v(p, precision, psv, v);
    }
    check_params(precision, psv)?;
    let (rows, cols) = (p.rows as usize, p.cols as usize);
    let x0 = 1i32 << (precision - 1);
    let mut prev0 = vec![0i32; cols];
    let mut prev1 = vec![0i32; cols];

    // Pass 1: symbol histograms (per component).
    let mut c0 = [0u64; 17];
    let mut c1 = [0u64; 17];
    hist(psv, &p.even, &p.odd, rows, cols, x0, &mut prev0, &mut prev1, &mut c0, &mut c1);
    let t0 = build_table(&c0);
    let t1 = build_table(&c1);

    // Markers.
    let mut w = BitWriter::new();
    w.out.reserve(rows * cols * 4 + 256);
    emit_markers(&mut w, rows, cols, precision, psv, &t0, &t1);

    // Pass 2: entropy (interleaved component 0 / component 1 per pixel).
    prev0.fill(0);
    prev1.fill(0);
    emit(psv, &p.even, &p.odd, rows, cols, x0, &mut prev0, &mut prev1, &t0, &t1, &mut w);
    w.flush(); // pad the final partial byte with ones (T.81 4.5.4)
    w.raw(0xFF);
    w.raw(0xD9); // EOI
    Ok(w.out)
}

/// Stage-exposed histogram pass (the measurement surface): exactly the
/// diff/nbits histogram computation inside `encode_planes_native`.
pub fn native_hist(
    p: &Planes,
    precision: u32,
    psv: i32,
) -> Result<([u64; 17], [u64; 17]), TileError> {
    check_params(precision, psv)?;
    let (rows, cols) = (p.rows as usize, p.cols as usize);
    let x0 = 1i32 << (precision - 1);
    let mut prev0 = vec![0i32; cols];
    let mut prev1 = vec![0i32; cols];
    let mut c0 = [0u64; 17];
    let mut c1 = [0u64; 17];
    hist(psv, &p.even, &p.odd, rows, cols, x0, &mut prev0, &mut prev1, &mut c0, &mut c1);
    Ok((c0, c1))
}

/// Stage-exposed table derivation (the measurement surface): exactly
/// the per-component IJG K.2 optimized tables inside the encode.
pub fn native_tables(c0: &[u64; 17], c1: &[u64; 17]) -> (Table, Table) {
    (build_table(c0), build_table(c1))
}

/// Range checks mirroring `encode_planes`.
fn check_params(precision: u32, psv: i32) -> Result<(), TileError> {
    if precision != 8 && precision != 10 && precision != 12 {
        return Err(TileError::Encode(format!(
            "unsupported precision {precision} (need 8, 10 or 12)"
        )));
    }
    if !(1..=7).contains(&psv) {
        return Err(TileError::Encode(format!("unsupported PSV {psv} (need 1..7)")));
    }
    Ok(())
}

/// SOI → SOF3 → DHT TT=00 → DHT TT=01 → SOS (jcmarker.c order; no DQT in
/// lossless, no DRI, no APPn).
fn emit_markers<W: W8>(w: &mut W, rows: usize, cols: usize, precision: u32, psv: i32, t0: &Table, t1: &Table) {
    w.raw(0xFF);
    w.raw(0xD8); // SOI
    w.raw(0xFF);
    w.raw(0xC3); // SOF3 (lossless)
    w.u16(3 * 2 + 2 + 5 + 1); // Ls = 3*Nf + 2 + 5 + 1 = 14
    w.raw(precision as u8);
    w.u16(rows as u16);
    w.u16(cols as u16);
    w.raw(2); // Nf
    // Component ids are the JCS_UNKNOWN defaults (0, 1) per
    // jpeg_set_defaults — not ci+1 (golden SOF3: 00 11 00 01 11 00).
    w.raw(0); // comp 1: id 0, h/v 1x1, tq 0
    w.raw(0x11);
    w.raw(0);
    w.raw(1); // comp 2: id 1, h/v 1x1, tq 0
    w.raw(0x11);
    w.raw(0);
    emit_dht(w, 0x00, t0); // per-component DC table 0
    emit_dht(w, 0x01, t1); // per-component DC table 1
    w.raw(0xFF);
    w.raw(0xDA); // SOS
    w.u16(2 * 2 + 2 + 1 + 3); // Ls = 2*Ns + 2 + 1 + 3 = 10
    w.raw(2); // Ns
    // Per emit_sos: component id then selector ((dc_tbl_no << 4) | ac),
    // patched per-component DC tables (0, 1).
    w.raw(0); // comp 1 id
    w.raw(0x00); // comp 1 selector
    w.raw(1); // comp 2 id
    w.raw(0x10); // comp 2 selector
    w.raw(psv as u8); // Ss = PSV
    w.raw(0); // Se
    w.raw(0); // Ah/Al
}

/// One DHT marker (DC-only lossless table): FF C4, Ls = 19 + nsym, TT,
/// counts[1..16], huffval in order (jcmarker.c emit_dht).
fn emit_dht(w: &mut impl W8, tt: u8, t: &Table) {
    w.raw(0xFF);
    w.raw(0xC4);
    w.u16((19 + t.nsym) as u16);
    w.raw(tt);
    for &b in &t.bits16 {
        w.raw(b);
    }
    for &v in &t.huffval[..t.nsym as usize] {
        w.raw(v);
    }
}

// ------------------------------------------------------------------ tables

/// Per-component Huffman table: DHT contents + the packed per-symbol
/// (code << 5) | len lookup for the emission hot path (len ≤ 16 needs 5
/// bits; code < 2^16).
#[derive(Debug, Clone, Copy)]
pub struct Table {
    bits16: [u8; 16],
    nsym: u8,
    huffval: [u8; 17],
    pack: [u32; 17],
}

/// Per-symbol code lengths for the 17 lossless-DC symbols (the K.2
/// optimal table's canonical assignment; 0 = unused symbol).
impl Table {
    pub fn code_lens(&self) -> [u32; 17] {
        let mut out = [0u32; 17];
        for (i, &p) in self.pack.iter().enumerate() {
            out[i] = p & 0x1F;
        }
        out
    }
}

/// The 3K gate's candidate-selection key (per-gate — the other gates
/// keep the 0.1.0 size-min contract), measured 
/// on the 114-frame 3K corpus (10,944 tiles): the histogram pass's
/// pre-stuffing expected bit count — per component, Σ freq[sym] ×
/// (code_len[sym] + value_bits(sym)), where value_bits = the symbol's
/// nbits (0 for symbol 0, 0 for the unreachable d=−32768 corner at 17-bit
/// magnitudes). argmin of this over the 3 candidates reproduces 10,943 of
/// 10,944 of the corpus file's stored selections (the one residual is a
/// 7-bit boundary tile where the corpus file's trial stream is believed to
/// diverge from ours on the losing candidate). The final byte size does
/// NOT reproduce the selections (41 tiles where the measured encoder keeps the
/// larger stream). Engine-independent: the histogram pass is a pure
/// function of the planes, so the FFI and native engines select the same
/// candidate.
pub fn expected_bits(p: &Planes, precision: u32, psv: i32) -> Result<u64, TileError> {
    let (h0, h1) = native_hist(p, precision, psv)?;
    let (t0, t1) = native_tables(&h0, &h1);
    let l0 = t0.code_lens();
    let l1 = t1.code_lens();
    let mut bits = 0u64;
    for k in 0..17 {
        // value bits: the symbol's nbits; symbol 16 (the d = −32768
        // corner) carries no payload (mirrors `diff_symbol`).
        let v0 = if k == 16 { 0u32 } else { k as u32 };
        bits += h0[k] * (l0[k] + v0) as u64;
        let v1 = if k == 16 { 0u32 } else { k as u32 };
        bits += h1[k] * (l1[k] + v1) as u64;
    }
    Ok(bits)
}

/// Exact port of `jpeg_gen_optimal_table` (jchuff.c, Annex K.2) for the
/// 17 lossless-DC symbols (0..16) + the canonical code assignment
/// (T.81 Fig. C.1–C.3). `counts[s]` = uses of symbol s.
///
/// Port notes (validated against the golden DHTs): the `others`
/// chain link goes at the TAIL of c1's branch (a head link yields wrong
/// code lengths — measured in the repro), and the pseudo-symbol drop
/// re-checks `bits[i]` as `i` moves down (a constant `bits[16]`
/// condition never terminates).
fn build_table(counts: &[u64; 17]) -> Table {
    const INF: u64 = 1_000_000_000;
    let mut freq = [0u64; 257];
    freq[..17].copy_from_slice(counts);
    freq[256] = 1; // pseudo-symbol 256: reserves the all-ones codeword
    // nz holds packed-position -> symbol; u16 because the pseudo-symbol
    // 256 does not fit in u8 (truncation to 0 silently corrupted freqp).
    let mut nz = [0u16; 257];
    let mut num = 0usize;
    for (i, &f) in freq.iter().enumerate() {
        if f != 0 {
            nz[num] = i as u16;
            num += 1;
        }
    }
    debug_assert!(num >= 2, "at least one real symbol + pseudo 256");
    let mut freqp = [0u64; 257];
    for i in 0..num {
        freqp[i] = freq[nz[i] as usize];
    }
    let mut codesize = [0u32; 257];
    let mut others = [-1i32; 257];
    // Huffman: merge the two smallest (ties → the later index), poison
    // the merged-away node, increment codesize over the merged branch.
    loop {
        let (mut c1, mut c2): (i32, i32) = (-1, -1);
        let (mut v, mut v2) = (INF, INF);
        for (i, &f) in freqp.iter().take(num).enumerate() {
            if f <= v2 {
                if f <= v {
                    c2 = c1;
                    v2 = v;
                    v = f;
                    c1 = i as i32;
                } else {
                    v2 = f;
                    c2 = i as i32;
                }
            }
        }
        if c2 < 0 {
            break; // one merged tree left
        }
        let c1 = c1 as usize;
        let c2 = c2 as usize;
        freqp[c1] += freqp[c2];
        freqp[c2] = INF + 1;
        codesize[c1] += 1;
        let mut i = c1;
        while others[i] >= 0 {
            i = others[i] as usize;
            codesize[i] += 1;
        }
        others[i] = c2 as i32; // link c2 at the TAIL of c1's branch
        codesize[c2] += 1;
        i = c2;
        while others[i] >= 0 {
            i = others[i] as usize;
            codesize[i] += 1;
        }
    }
    // Per-length symbol counts.
    let mut bits = [0u32; 33];
    for i in 0..num {
        bits[codesize[i] as usize] += 1;
    }
    // Prefix positions per length.
    let mut bit_pos = [0usize; 33];
    let mut p = 0usize;
    for i in 1..33 {
        bit_pos[i] = p;
        p += bits[i] as usize;
    }
    // Length adjustment for the >16 case (pair-split from the top).
    let mut i = 32;
    while i > 16 {
        while bits[i] > 0 {
            let mut j = i - 2;
            while bits[j] == 0 {
                j -= 1;
            }
            bits[i] -= 2;
            bits[i - 1] += 1;
            bits[j + 1] += 2;
            bits[j] -= 1;
        }
        i -= 1;
    }
    // Drop the pseudo-symbol 256 from the largest codelength in use.
    while bits[i] == 0 {
        i -= 1;
    }
    debug_assert!((1..=16).contains(&i));
    bits[i] -= 1;
    // Symbols sorted by code length (ties by ascending symbol index).
    let mut huffval = [0u8; 17];
    for k in 0..num - 1 {
        let l = codesize[k] as usize;
        huffval[bit_pos[l]] = nz[k] as u8;
        bit_pos[l] += 1;
    }
    let mut bits16 = [0u8; 16];
    for l in 1..=16 {
        bits16[l - 1] = bits[l] as u8;
    }
    // Canonical codes (Fig. C.1–C.3).
    let mut huffsize = [0u8; 257];
    let mut p2 = 0usize;
    for (l, &n) in bits16.iter().enumerate() {
        for _ in 0..n {
            huffsize[p2] = (l + 1) as u8;
            p2 += 1;
        }
    }
    huffsize[p2] = 0;
    let mut huffcode = [0u32; 257];
    let mut code = 0u32;
    let mut si = huffsize[0] as u32;
    let mut q = 0usize;
    while q < p2 {
        while q < p2 && huffsize[q] as u32 == si {
            huffcode[q] = code;
            code += 1;
            q += 1;
        }
        // code is now 1 more than the last code used for length si; it
        // must still fit in si bits (no all-ones codeword). libjpeg
        // ERREXITs otherwise; our tables cannot trigger it (the
        // pseudo-symbol reserves the slot).
        debug_assert!(code < 1u32 << si, "all-ones codeword must stay free");
        code <<= 1;
        si += 1;
    }
    let mut pack = [0u32; 17];
    for q in 0..p2 {
        let sym = huffval[q] as usize;
        debug_assert!(sym <= 16, "DC lossless maxsymbol = 16");
        pack[sym] = (huffcode[q] << 5) | huffsize[q] as u32;
    }
    Table {
        bits16,
        nsym: (num - 1) as u8,
        huffval,
        pack,
    }
}

// ------------------------------------------------------ predictor / diffs

/// Histogram of both components' symbols (per component) using the exact
/// libjpeg predictor semantics (jclhuff.c + jclossls.c). Dispatches to
/// the per-PSV monomorphized kernels (the predictor expression is
/// compiled into the loop, not matched per sample).
fn hist(
    psv: i32,
    p0: &[u16],
    p1: &[u16],
    rows: usize,
    cols: usize,
    x0: i32,
    prev0: &mut [i32],
    prev1: &mut [i32],
    c0: &mut [u64; 17],
    c1: &mut [u64; 17],
) {
    match psv {
        1 => hist1(p0, p1, rows, cols, x0, prev0, prev1, c0, c1),
        2 => hist2(p0, p1, rows, cols, x0, prev0, prev1, c0, c1),
        3 => hist3(p0, p1, rows, cols, x0, prev0, prev1, c0, c1),
        4 => hist4(p0, p1, rows, cols, x0, prev0, prev1, c0, c1),
        5 => hist5(p0, p1, rows, cols, x0, prev0, prev1, c0, c1),
        6 => hist6(p0, p1, rows, cols, x0, prev0, prev1, c0, c1),
        _ => hist7(p0, p1, rows, cols, x0, prev0, prev1, c0, c1),
    }
}

/// One histogram kernel: the PSV predictor expression is inlined into
/// the non-first-row loop (used for x ≥ 1 only; row 0 uses PREDICTOR1
/// and col 0 of every non-first row uses PREDICTOR2 — both fixed by the
/// libjpeg differencer macros, independent of PSV).
macro_rules! hist_kernel {
    ($name:ident, pred = $pred:expr) => {
        #[allow(unused_variables)]
        fn $name(
            p0: &[u16],
            p1: &[u16],
            rows: usize,
            cols: usize,
            x0: i32,
            prev0: &mut [i32],
            prev1: &mut [i32],
            c0: &mut [u64; 17],
            c1: &mut [u64; 17],
        ) {
            for y in 0..rows {
                let b = y * cols;
                if y == 0 {
                    let s0 = p0[b] as i32;
                    let s1 = p1[b] as i32;
                    c0[diff_symbol(s0 - x0)] += 1;
                    c1[diff_symbol(s1 - x0)] += 1;
                    let (mut l0, mut l1) = (s0, s1);
                    for x in 1..cols {
                        let s0 = p0[b + x] as i32;
                        let s1 = p1[b + x] as i32;
                        c0[diff_symbol(s0 - l0)] += 1; // PREDICTOR1
                        c1[diff_symbol(s1 - l1)] += 1;
                        l0 = s0;
                        l1 = s1;
                    }
                } else {
                    let s0 = p0[b] as i32;
                    let s1 = p1[b] as i32;
                    c0[diff_symbol(s0 - prev0[0])] += 1; // PREDICTOR2
                    c1[diff_symbol(s1 - prev1[0])] += 1;
                    let (mut l0, mut l1) = (s0, s1);
                    for x in 1..cols {
                        let s0 = p0[b + x] as i32;
                        let s1 = p1[b + x] as i32;
                        c0[diff_symbol(s0 - $pred(l0, prev0[x], prev0[x - 1]))] += 1;
                        c1[diff_symbol(s1 - $pred(l1, prev1[x], prev1[x - 1]))] += 1;
                        l0 = s0;
                        l1 = s1;
                    }
                }
                for x in 0..cols {
                    prev0[x] = p0[b + x] as i32;
                    prev1[x] = p1[b + x] as i32;
                }
            }
        }
    };
}

hist_kernel!(hist1, pred = |l, u, ul| l);
hist_kernel!(hist2, pred = |l, u, ul| u);
hist_kernel!(hist3, pred = |l, u, ul| ul);
hist_kernel!(hist4, pred = |l, u, ul| l + u - ul);
hist_kernel!(hist5, pred = |l, u, ul| l + ((u - ul) >> 1));
hist_kernel!(hist6, pred = |l, u, ul| u + ((l - ul) >> 1));
hist_kernel!(hist7, pred = |l, u, ul| (l + u) >> 1);

/// The H.1.2.2 symbol (bit length of the difference magnitude, 0..16) —
/// exact libjpeg semantics (jclhuff.c): the sign test is on the 15th bit
/// of the 16-bit value (d < 0 ⇒ mag = (−d) & 0x7FFF, d = −32768 ⇒
/// 0x8000; else mag = d & 0x7FFF); symbol = bit length of mag.
#[inline(always)]
fn diff_symbol(d: i32) -> usize {
    let mag: u32 = if d & 0x8000 != 0 {
        let m = ((-d) & 0x7FFF) as u32;
        if m == 0 {
            0x8000 // d = -32768: magnitude 32768, symbol 16, no payload
        } else {
            m
        }
    } else {
        (d & 0x7FFF) as u32
    };
    (32 - mag.leading_zeros()) as usize
}

// --------------------------------------------------------------- emission

/// Writer seam: a byte-stuffing bit stream. `BitWriter` stores the
/// bytes; the size-only pass implements the same semantics on a
/// counter (it must track the emitted byte values — the 0xFF stuffing
/// count depends on them) and the sizes are asserted equal.
pub(crate) trait W8 {
    /// Emit `size` (1..=16) bits of `code`, MSB-first, with 0xFF→0x00
    /// byte stuffing (libjpeg jclhuff emit_bits).
    fn emit(&mut self, code: u32, size: u32);
    /// Combined code+payload emit: append `size` (1..=16) bits of
    /// `code` immediately followed by `psize` (0..=15) bits of `payload`
    /// — total ≤ 31. The default (production writers) does the two
    /// separate emits — byte-identical; the combined-emit writers (v1/v2)
    /// override with a single 48-bit-window append.
    fn emit2(&mut self, code: u32, size: u32, payload: u32, psize: u32) {
        debug_assert!(psize <= 15);
        self.emit(code, size);
        if psize != 0 {
            self.emit(payload, psize);
        }
    }
    /// Reserve hint for the output stream (default: ignore).
    fn reserve_hint(&mut self, _n: usize) {}
    /// Raw marker/header byte (no stuffing — markers are FF XX).
    fn raw(&mut self, b: u8);
    /// Big-endian 16-bit field.
    fn u16(&mut self, v: u16);
    /// End of scan: pad the partial byte with ones and reset.
    fn flush(&mut self);
}

/// MSB-first bit writer with 0xFF byte stuffing — exact port of the
/// jclhuff.c (LOSSLESS path) emit_bits/flush_bits: 24-bit accumulator,
/// left-justified, ≤7 bits retained between emits, ≤16 bits per emit.
pub(crate) struct BitWriter {
    pub(crate) out: Vec<u8>,
    buf: u64, // valid bits left-justified in the low 24 bits
    bits: u32,
}

impl BitWriter {
    pub(crate) fn new() -> Self {
        Self {
            out: Vec::new(),
            buf: 0,
            bits: 0,
        }
    }
}

impl W8 for BitWriter {
    #[inline(always)]
    fn emit(&mut self, code: u32, size: u32) {
        debug_assert!((1..=16).contains(&size));
        let mut buf = (code as u64) & ((1u64 << size) - 1);
        let mut bits = self.bits + size; // ≤ 7 + 16 = 23 < 24
        buf <<= 24 - bits;
        buf |= self.buf;
        while bits >= 8 {
            let c = ((buf >> 16) & 0xFF) as u8;
            self.out.push(c);
            if c == 0xFF {
                self.out.push(0);
            }
            buf <<= 8;
            bits -= 8;
        }
        self.buf = buf;
        self.bits = bits;
    }

    #[inline(always)]
    fn raw(&mut self, b: u8) {
        self.out.push(b);
    }

    fn u16(&mut self, v: u16) {
        self.raw((v >> 8) as u8);
        self.raw(v as u8);
    }

    fn flush(&mut self) {
        self.emit(0x7F, 7);
        self.buf = 0;
        self.bits = 0;
    }
}

/// W8 size-only writer: the SAME 24-bit accumulator arithmetic as
/// `BitWriter`, counting bytes instead of storing them. The count is
/// EXACT — stuffing included — because each flushed byte value is
/// recomputed identically and a 0xFF adds the stuffing byte. A pure bit
/// count would be wrong: the stuffing count depends on the values.
pub(crate) struct SizeWriter {
    pub(crate) out_len: usize,
    buf: u64,
    bits: u32,
}

impl SizeWriter {
    pub(crate) fn new() -> Self {
        Self {
            out_len: 0,
            buf: 0,
            bits: 0,
        }
    }
}

impl W8 for SizeWriter {
    #[inline(always)]
    fn emit(&mut self, code: u32, size: u32) {
        debug_assert!((1..=16).contains(&size));
        let mut buf = (code as u64) & ((1u64 << size) - 1);
        let mut bits = self.bits + size; // ≤ 7 + 16 = 23 < 24
        buf <<= 24 - bits;
        buf |= self.buf;
        while bits >= 8 {
            let c = ((buf >> 16) & 0xFF) as u8;
            self.out_len += 1;
            if c == 0xFF {
                self.out_len += 1;
            }
            buf <<= 8;
            bits -= 8;
        }
        self.buf = buf;
        self.bits = bits;
    }

    #[inline(always)]
    fn raw(&mut self, _b: u8) {
        self.out_len += 1;
    }

    fn u16(&mut self, _v: u16) {
        self.out_len += 2;
    }

    fn flush(&mut self) {
        self.emit(0x7F, 7);
        self.buf = 0;
        self.bits = 0;
    }
}

/// Probe: a no-op W8 writer whose `sink` mixes every emitted
/// (code, size) pair — the probe reads the sink back, so LLVM cannot
/// dead-code-eliminate the per-sample predictor/symbol/table arithmetic
/// that the no-op `emit` calls are chained to (without this the void
/// pass would measure only the prev-row copies). One xor per emit
/// (~0.3 ns) is negligible against the tens of ns per sample measured.
pub(crate) struct VoidWriter {
    pub(crate) sink: u64,
}

impl VoidWriter {
    pub(crate) fn new() -> Self {
        Self { sink: 0 }
    }
}

impl W8 for VoidWriter {
    #[inline(always)]
    fn emit(&mut self, code: u32, size: u32) {
        self.sink ^= (code as u64) | ((size as u64) << 32);
    }

    #[inline(always)]
    fn raw(&mut self, b: u8) {
        self.sink ^= b as u64;
    }

    fn u16(&mut self, v: u16) {
        self.sink ^= v as u64;
    }

    fn flush(&mut self) {
        self.sink ^= 0x5A;
    }
}

/// Probe: the emission stage (markers + entropy pass + flush + EOI)
/// on the void writer — isolates the predictor + symbol + table-lookup
/// arithmetic from the byte machinery. The probe passes the already-timed
/// tables; the prev-row buffers are allocated here (production shape: the
/// full encode allocates them once before the hist pass and reuses them
/// here, so the extra allocation is the only structural difference and
/// is < 1 µs at 2 KB).
pub fn native_emit_stage_void(
    p: &Planes,
    precision: u32,
    psv: i32,
    t0: &Table,
    t1: &Table,
) -> Result<u64, TileError> {
    check_params(precision, psv)?;
    let (rows, cols) = (p.rows as usize, p.cols as usize);
    let x0 = 1i32 << (precision - 1);
    let mut prev0 = vec![0i32; cols];
    let mut prev1 = vec![0i32; cols];
    let mut w = VoidWriter::new();
    emit_markers(&mut w, rows, cols, precision, psv, t0, t1);
    prev0.fill(0);
    prev1.fill(0);
    emit(psv, &p.even, &p.odd, rows, cols, x0, &mut prev0, &mut prev1, t0, t1, &mut w);
    w.flush();
    w.raw(0xFF);
    w.raw(0xD9);
    Ok(w.sink)
}

/// One sample: the Huffman code for the nbits category (one packed
/// load), then the nbits payload bits (except nbits == 0 — no payload —
/// or 16: the −32768 special case carries no bits).
#[inline(always)]
fn emit_diff<W: W8>(w: &mut W, t: &Table, d: i32) {
    // The SYMBOL is the payload bit count (nbits); the code length is the
    // packed low 5 bits (libjpeg: ehufsi[nbits] / emit_bits(temp2, nbits)).
    let nbits = diff_symbol(d);
    let e = t.pack[nbits];
    let codelen = e & 0x1F;
    w.emit(e >> 5, codelen);
    if nbits != 0 && nbits != 16 {
        // Payload: the magnitude if d ≥ 0, the nbits-bit one's
        // complement of the magnitude if d < 0 (bit writer masks to
        // nbits bits — libjpeg's emit_bits(temp2, nbits)).
        let mag: u32 = if d & 0x8000 != 0 {
            let m = ((-d) & 0x7FFF) as u32;
            if m == 0 {
                0x8000
            } else {
                m
            }
        } else {
            d as u32
        };
        let payload = if d & 0x8000 != 0 { mag ^ 0x7FFF } else { mag };
        w.emit(payload, nbits as u32);
    }
}

/// Emission dispatch: per-PSV monomorphized kernels, both components in
/// lockstep (MCU order: component 0 then component 1 per pixel).
fn emit<W: W8>(
    psv: i32,
    p0: &[u16],
    p1: &[u16],
    rows: usize,
    cols: usize,
    x0: i32,
    prev0: &mut [i32],
    prev1: &mut [i32],
    t0: &Table,
    t1: &Table,
    w: &mut W,
) {
    match psv {
        1 => emit1(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
        2 => emit2(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
        3 => emit3(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
        4 => emit4(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
        5 => emit5(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
        6 => emit6(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
        _ => emit7(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
    }
}

/// One emission kernel (see hist_kernel! for the predictor rules).
macro_rules! emit_kernel {
    ($name:ident, pred = $pred:expr) => {
        #[allow(unused_variables)]
        fn $name<W: W8>(
            p0: &[u16],
            p1: &[u16],
            rows: usize,
            cols: usize,
            x0: i32,
            prev0: &mut [i32],
            prev1: &mut [i32],
            t0: &Table,
            t1: &Table,
            w: &mut W,
        ) {
            for y in 0..rows {
                let b = y * cols;
                if y == 0 {
                    let s0 = p0[b] as i32;
                    let s1 = p1[b] as i32;
                    emit_diff(w, t0, s0 - x0);
                    emit_diff(w, t1, s1 - x0);
                    let (mut l0, mut l1) = (s0, s1);
                    for x in 1..cols {
                        let s0 = p0[b + x] as i32;
                        let s1 = p1[b + x] as i32;
                        emit_diff(w, t0, s0 - l0); // PREDICTOR1
                        emit_diff(w, t1, s1 - l1);
                        l0 = s0;
                        l1 = s1;
                    }
                } else {
                    let s0 = p0[b] as i32;
                    let s1 = p1[b] as i32;
                    emit_diff(w, t0, s0 - prev0[0]); // PREDICTOR2
                    emit_diff(w, t1, s1 - prev1[0]);
                    let (mut l0, mut l1) = (s0, s1);
                    for x in 1..cols {
                        let s0 = p0[b + x] as i32;
                        let s1 = p1[b + x] as i32;
                        emit_diff(w, t0, s0 - $pred(l0, prev0[x], prev0[x - 1]));
                        emit_diff(w, t1, s1 - $pred(l1, prev1[x], prev1[x - 1]));
                        l0 = s0;
                        l1 = s1;
                    }
                }
                for x in 0..cols {
                    prev0[x] = p0[b + x] as i32;
                    prev1[x] = p1[b + x] as i32;
                }
            }
        }
    };
}

emit_kernel!(emit1, pred = |l, u, ul| l);
emit_kernel!(emit2, pred = |l, u, ul| u);
emit_kernel!(emit3, pred = |l, u, ul| ul);
emit_kernel!(emit4, pred = |l, u, ul| l + u - ul);
emit_kernel!(emit5, pred = |l, u, ul| l + ((u - ul) >> 1));
emit_kernel!(emit6, pred = |l, u, ul| u + ((l - ul) >> 1));
emit_kernel!(emit7, pred = |l, u, ul| (l + u) >> 1);

// ------------------------------------------------------ combined-emit variants
//
// `FRAMEPRISM_EMITTER` variants (default `current` — the production path
// above, untouched): `v1` and `v2` emit the SAME bit stream (gated
// byte-identity vs the current path) with a different byte machinery:
// - v1: ONE combined code+payload emit (≤ 31 bits) on a 48-bit
//   window instead of two ≤16-bit emits on the 24-bit window — halves
//   the per-sample emit calls and accumulator round-trips.
// - v2: v1 + a batched 0xFF-stuffed flush (64-byte stack batch,
//   one vectorized extend per batch instead of a per-byte push).
//
// Byte-identity argument: both writers are MSB-first left-justified
// accumulators that flush the top 8 bits whenever ≥ 8 bits are pending;
// the combined emit appends (code << psize) | payload as one
// (size+psize)-bit run — the bit stream is identical to two consecutive
// emits, so every flushed byte value (and hence every 0xFF stuffing
// decision) is identical. The 48-bit window only widens the internal
// field; extraction takes the top 8 bits exactly as the 24-bit writer
// does. Gated, not argued: the synthetic + real-frame byte-identity checks.

/// Emit-variant selector, read once. `current` = 0 (production path);
/// `v1` = 1; `v2` = 2.
pub fn emitter_variant() -> u8 {
    static V: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
    *V.get_or_init(|| match std::env::var("FRAMEPRISM_EMITTER").ok().as_deref() {
        Some("current") => 0,
        Some("v2") => 2,
        _ => 1, // default: v1 — the measured winner (see encode_planes_native seam note)
    })
}

/// v1 writer: the jclhuff arithmetic on a 48-bit window (≤ 7 bits
/// retained between emits, ≤ 31 bits per combined emit), per-byte push +
/// 0xFF→0x00 stuffing. Same byte stream as `BitWriter` (the 24-bit
/// writer) — the window width only changes internal representation.
pub(crate) struct BitWriterC {
    pub(crate) out: Vec<u8>,
    buf: u64, // valid bits left-justified in the low 48 bits
    bits: u32,
}

impl BitWriterC {
    pub(crate) fn new() -> Self {
        Self { out: Vec::new(), buf: 0, bits: 0 }
    }

    /// Append `size` (1..=31) bits, MSB-first, with 0xFF→0x00 stuffing.
    #[inline(always)]
    fn emit_bits(&mut self, code: u64, size: u32) {
        debug_assert!((1..=31).contains(&size));
        let mut buf = code & ((1u64 << size) - 1);
        let mut bits = self.bits + size; // ≤ 7 + 31 = 38 < 48
        buf <<= 48 - bits;
        buf |= self.buf;
        while bits >= 8 {
            let c = ((buf >> 40) & 0xFF) as u8;
            self.out.push(c);
            if c == 0xFF {
                self.out.push(0);
            }
            buf <<= 8;
            bits -= 8;
        }
        self.buf = buf;
        self.bits = bits;
    }
}

impl W8 for BitWriterC {
    #[inline(always)]
    fn emit(&mut self, code: u32, size: u32) {
        self.emit_bits(code as u64, size);
    }

    #[inline(always)]
    fn emit2(&mut self, code: u32, size: u32, payload: u32, psize: u32) {
        // (code << psize) | payload as one (size+psize)-bit run —
        // identical bit stream to emit(code) + emit(payload).
        let combined = ((code as u64) << psize) | (payload as u64 & ((1u64 << psize) - 1));
        self.emit_bits(combined, size + psize);
    }

    fn reserve_hint(&mut self, n: usize) {
        self.out.reserve(n);
    }

    #[inline(always)]
    fn raw(&mut self, b: u8) {
        self.out.push(b);
    }

    fn u16(&mut self, v: u16) {
        self.raw((v >> 8) as u8);
        self.raw(v as u8);
    }

    fn flush(&mut self) {
        self.emit_bits(0x7F, 7);
        self.buf = 0;
        self.bits = 0;
    }
}

/// v2 writer: v1's 48-bit-window combined-emit arithmetic with a batched
/// 0xFF-stuffed flush — bytes land in a 64-byte stack batch and are
/// expanded + copied out one batch at a time (one vectorized
/// extend_from_slice instead of a per-byte push). Raw bytes flush the
/// pending batch first so the stream order is preserved.
pub(crate) struct BitWriterB {
    pub(crate) out: Vec<u8>,
    buf: u64,
    bits: u32,
    batch: [u8; 64],
    blen: usize,
}

impl BitWriterB {
    pub(crate) fn new() -> Self {
        Self {
            out: Vec::new(),
            buf: 0,
            bits: 0,
            batch: [0; 64],
            blen: 0,
        }
    }

    #[inline(always)]
    fn push(&mut self, c: u8) {
        self.batch[self.blen] = c;
        self.blen += 1;
        if self.blen == 64 {
            self.flush_batch();
        }
    }

    fn flush_batch(&mut self) {
        if self.blen == 0 {
            return;
        }
        let mut e = [0u8; 128];
        let mut m = 0usize;
        for &b in self.batch.iter().take(self.blen) {
            e[m] = b;
            m += 1;
            if b == 0xFF {
                e[m] = 0;
                m += 1;
            }
        }
        self.out.extend_from_slice(&e[..m]);
        self.blen = 0;
    }

    /// Finish: flush the trailing batch; return the stream.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        self.flush_batch();
        std::mem::take(&mut self.out)
    }

    /// Append `size` (1..=31) bits (see BitWriterC::emit_bits).
    #[inline(always)]
    fn emit_bits(&mut self, code: u64, size: u32) {
        debug_assert!((1..=31).contains(&size));
        let mut buf = code & ((1u64 << size) - 1);
        let mut bits = self.bits + size; // ≤ 7 + 31 = 38 < 48
        buf <<= 48 - bits;
        buf |= self.buf;
        while bits >= 8 {
            let c = ((buf >> 40) & 0xFF) as u8;
            self.push(c);
            buf <<= 8;
            bits -= 8;
        }
        self.buf = buf;
        self.bits = bits;
    }
}

impl W8 for BitWriterB {
    #[inline(always)]
    fn emit(&mut self, code: u32, size: u32) {
        self.emit_bits(code as u64, size);
    }

    #[inline(always)]
    fn emit2(&mut self, code: u32, size: u32, payload: u32, psize: u32) {
        let combined = ((code as u64) << psize) | (payload as u64 & ((1u64 << psize) - 1));
        self.emit_bits(combined, size + psize);
    }

    fn reserve_hint(&mut self, n: usize) {
        self.out.reserve(n);
    }

    #[inline(always)]
    fn raw(&mut self, b: u8) {
        self.flush_batch();
        self.out.push(b);
    }

    fn u16(&mut self, v: u16) {
        self.raw((v >> 8) as u8);
        self.raw(v as u8);
    }

    fn flush(&mut self) {
        self.emit_bits(0x7F, 7);
        self.buf = 0;
        self.bits = 0;
    }
}

/// One sample (v1/v2): the same symbol/payload arithmetic as
/// `emit_diff`, emitted as ONE combined code+payload emit. `psize` is 0
/// for nbits 0 and 16 (no payload bits — the −32768 special case
/// carries none, exactly as `emit_diff` skips its second emit).
#[inline(always)]
fn emit_diff_c<W: W8>(w: &mut W, t: &Table, d: i32) {
    let nbits = diff_symbol(d);
    let e = t.pack[nbits];
    let codelen = e & 0x1F;
    let (payload, psize) = if nbits != 0 && nbits != 16 {
        let mag: u32 = if d & 0x8000 != 0 {
            let m = ((-d) & 0x7FFF) as u32;
            if m == 0 {
                0x8000
            } else {
                m
            }
        } else {
            d as u32
        };
        (if d & 0x8000 != 0 { mag ^ 0x7FFF } else { mag }, nbits as u32)
    } else {
        (0, 0)
    };
    w.emit2(e >> 5, codelen, payload, psize);
}

/// Emission dispatch (v1/v2): per-PSV monomorphized kernels.
fn emit_c<W: W8>(
    psv: i32,
    p0: &[u16],
    p1: &[u16],
    rows: usize,
    cols: usize,
    x0: i32,
    prev0: &mut [i32],
    prev1: &mut [i32],
    t0: &Table,
    t1: &Table,
    w: &mut W,
) {
    match psv {
        1 => emit1c(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
        2 => emit2c(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
        3 => emit3c(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
        4 => emit4c(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
        5 => emit5c(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
        6 => emit6c(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
        _ => emit7c(p0, p1, rows, cols, x0, prev0, prev1, t0, t1, w),
    }
}

/// One combined-emit kernel (predictor rules identical to `emit_kernel!`).
macro_rules! emit_kernel_c {
    ($name:ident, pred = $pred:expr) => {
        #[allow(unused_variables)]
        fn $name<W: W8>(
            p0: &[u16],
            p1: &[u16],
            rows: usize,
            cols: usize,
            x0: i32,
            prev0: &mut [i32],
            prev1: &mut [i32],
            t0: &Table,
            t1: &Table,
            w: &mut W,
        ) {
            for y in 0..rows {
                let b = y * cols;
                if y == 0 {
                    let s0 = p0[b] as i32;
                    let s1 = p1[b] as i32;
                    emit_diff_c(w, t0, s0 - x0);
                    emit_diff_c(w, t1, s1 - x0);
                    let (mut l0, mut l1) = (s0, s1);
                    for x in 1..cols {
                        let s0 = p0[b + x] as i32;
                        let s1 = p1[b + x] as i32;
                        emit_diff_c(w, t0, s0 - l0); // PREDICTOR1
                        emit_diff_c(w, t1, s1 - l1);
                        l0 = s0;
                        l1 = s1;
                    }
                } else {
                    let s0 = p0[b] as i32;
                    let s1 = p1[b] as i32;
                    emit_diff_c(w, t0, s0 - prev0[0]); // PREDICTOR2
                    emit_diff_c(w, t1, s1 - prev1[0]);
                    let (mut l0, mut l1) = (s0, s1);
                    for x in 1..cols {
                        let s0 = p0[b + x] as i32;
                        let s1 = p1[b + x] as i32;
                        emit_diff_c(w, t0, s0 - $pred(l0, prev0[x], prev0[x - 1]));
                        emit_diff_c(w, t1, s1 - $pred(l1, prev1[x], prev1[x - 1]));
                        l0 = s0;
                        l1 = s1;
                    }
                }
                for x in 0..cols {
                    prev0[x] = p0[b + x] as i32;
                    prev1[x] = p1[b + x] as i32;
                }
            }
        }
    };
}

emit_kernel_c!(emit1c, pred = |l, u, ul| l);
emit_kernel_c!(emit2c, pred = |l, u, ul| u);
emit_kernel_c!(emit3c, pred = |l, u, ul| ul);
emit_kernel_c!(emit4c, pred = |l, u, ul| l + u - ul);
emit_kernel_c!(emit5c, pred = |l, u, ul| l + ((u - ul) >> 1));
emit_kernel_c!(emit6c, pred = |l, u, ul| u + ((l - ul) >> 1));
emit_kernel_c!(emit7c, pred = |l, u, ul| (l + u) >> 1);

/// The v1/v2 emission stage (markers + combined-emit entropy + flush +
/// EOI) on a variant writer — shared shape, monomorphized per writer.
fn emit_all<W: W8>(
    w: &mut W,
    psv: i32,
    p: &Planes,
    rows: usize,
    cols: usize,
    x0: i32,
    precision: u32,
    t0: &Table,
    t1: &Table,
    prev0: &mut [i32],
    prev1: &mut [i32],
) {
    emit_markers(w, rows, cols, precision, psv, t0, t1);
    prev0.fill(0);
    prev1.fill(0);
    emit_c(psv, &p.even, &p.odd, rows, cols, x0, prev0, prev1, t0, t1, w);
    w.flush(); // pad the final partial byte with ones (T.81 4.5.4)
    w.raw(0xFF);
    w.raw(0xD9); // EOI
}

/// The production pipeline on a combined-emit variant writer
/// (v1: `BitWriterC`, v2: `BitWriterB`). Same hist/table passes as
/// `encode_planes_native` (shared code); same markers, flush, EOI. The
/// bit stream is identical by construction and gated byte-identical,
/// so the output equals the production stream for every
/// (planes, precision, psv).
pub fn encode_planes_native_v(p: &Planes, precision: u32, psv: i32, v: u8) -> Result<Vec<u8>, TileError> {
    check_params(precision, psv)?;
    let (rows, cols) = (p.rows as usize, p.cols as usize);
    let x0 = 1i32 << (precision - 1);
    let mut prev0 = vec![0i32; cols];
    let mut prev1 = vec![0i32; cols];

    // Pass 1: symbol histograms (per component) — same shared pass.
    let mut c0 = [0u64; 17];
    let mut c1 = [0u64; 17];
    hist(psv, &p.even, &p.odd, rows, cols, x0, &mut prev0, &mut prev1, &mut c0, &mut c1);
    let t0 = build_table(&c0);
    let t1 = build_table(&c1);

    if v == 2 {
        let mut w = BitWriterB::new();
        w.reserve_hint(rows * cols * 4 + 256);
        emit_all(&mut w, psv, p, rows, cols, x0, precision, &t0, &t1, &mut prev0, &mut prev1);
        Ok(w.finish())
    } else {
        let mut w = BitWriterC::new();
        w.reserve_hint(rows * cols * 4 + 256);
        emit_all(&mut w, psv, p, rows, cols, x0, precision, &t0, &t1, &mut prev0, &mut prev1);
        Ok(w.out)
    }
}

/// Probe surface: the v1/v2 emission stage (markers + combined-emit
/// entropy + flush + EOI) on its own, for per-stage timing and the
/// stage-level byte check (tables come from the already-timed
/// `native_tables`; prev-row buffers allocated here, production shape).
pub fn native_emit_stage_v(
    v: u8,
    p: &Planes,
    precision: u32,
    psv: i32,
    t0: &Table,
    t1: &Table,
) -> Result<Vec<u8>, TileError> {
    check_params(precision, psv)?;
    let (rows, cols) = (p.rows as usize, p.cols as usize);
    let x0 = 1i32 << (precision - 1);
    let mut prev0 = vec![0i32; cols];
    let mut prev1 = vec![0i32; cols];
    if v == 2 {
        let mut w = BitWriterB::new();
        w.reserve_hint(rows * cols * 4 + 256);
        emit_markers(&mut w, rows, cols, precision, psv, t0, t1);
        prev0.fill(0);
        prev1.fill(0);
        emit_c(psv, &p.even, &p.odd, rows, cols, x0, &mut prev0, &mut prev1, t0, t1, &mut w);
        w.flush();
        w.raw(0xFF);
        w.raw(0xD9);
        Ok(w.finish())
    } else {
        let mut w = BitWriterC::new();
        w.reserve_hint(rows * cols * 4 + 256);
        emit_markers(&mut w, rows, cols, precision, psv, t0, t1);
        prev0.fill(0);
        prev1.fill(0);
        emit_c(psv, &p.even, &p.odd, rows, cols, x0, &mut prev0, &mut prev1, t0, t1, &mut w);
        w.flush();
        w.raw(0xFF);
        w.raw(0xD9);
        Ok(w.out)
    }
}

/// Exact post-even-pad stream length of the native encode — the
/// A-lever sizing pass. Same input contract as `encode_planes_native` and
/// the same pipeline (hist + tables + markers + emission); the emission
/// runs on `SizeWriter` (byte counting, no stores), so the result is the
/// EXACT length the full encode would produce — asserted equal in the
/// unit tests and on real frames, never estimated. The even pad (reference
/// invariant, applied by `tileenc::encode_candidate`) is folded in here
/// because candidate selection compares post-pad sizes.
pub fn encode_planes_native_size(p: &Planes, precision: u32, psv: i32) -> Result<usize, TileError> {
    check_params(precision, psv)?;
    let (rows, cols) = (p.rows as usize, p.cols as usize);
    let x0 = 1i32 << (precision - 1);
    let mut prev0 = vec![0i32; cols];
    let mut prev1 = vec![0i32; cols];

    // Pass 1: symbol histograms (per component).
    let mut c0 = [0u64; 17];
    let mut c1 = [0u64; 17];
    hist(psv, &p.even, &p.odd, rows, cols, x0, &mut prev0, &mut prev1, &mut c0, &mut c1);
    let t0 = build_table(&c0);
    let t1 = build_table(&c1);

    let mut w = SizeWriter::new();
    emit_markers(&mut w, rows, cols, precision, psv, &t0, &t1);
    prev0.fill(0);
    prev1.fill(0);
    emit(psv, &p.even, &p.odd, rows, cols, x0, &mut prev0, &mut prev1, &t0, &t1, &mut w);
    w.flush();
    w.raw(0xFF);
    w.raw(0xD9); // EOI
    Ok(w.out_len + w.out_len % 2)
}

/// Test helper: histogram of one plane (the kernel runs on both planes;
/// feed the same plane twice and read the first count set).
pub fn diff_counts(
    plane: &[u16],
    rows: usize,
    cols: usize,
    precision: u32,
    psv: i32,
) -> [u64; 17] {
    let x0 = 1i32 << (precision - 1);
    let mut prev0 = vec![0i32; cols];
    let mut prev1 = vec![0i32; cols];
    let mut c0 = [0u64; 17];
    let mut c1 = [0u64; 17];
    hist(psv, plane, plane, rows, cols, x0, &mut prev0, &mut prev1, &mut c0, &mut c1);
    c0
}

#[cfg(test)]
mod payload_probe {
    use super::*;

    // Hand table: sym 12 = 10-bit code 1111111110.
    fn table12() -> Table {
        let mut t = Table { bits16: [0; 16], nsym: 1, huffval: [0; 17], pack: [0; 17] };
        t.pack[12] = (1022u32 << 5) | 10;
        t
    }

    #[test]
    fn minus_2048_is_code_1022_plus_12bit_0x7ff() {
        let mut w = BitWriter::new();
        emit_diff(&mut w, &table12(), -2048);
        w.flush();
        // 1111111110 011111111111 + ones-pad => ff 9f ff (stuffed)
        assert_eq!(w.out, vec![0xff, 0x00, 0x9f, 0xff, 0x00]);
    }

    #[test]
    fn plus_4095_is_code_1022_plus_12bit_0xfff() {
        let mut w = BitWriter::new();
        emit_diff(&mut w, &table12(), 4095);
        w.flush();
        // 1111111110 111111111111 + ones-pad => ff bf ff (stuffed)
        assert_eq!(w.out, vec![0xff, 0x00, 0xbf, 0xff, 0x00]);
    }

    #[test]
    fn minus_1_and_plus_1_payloads() {
        // sym 1 (1-bit payload): +1 => payload bit 1, -1 => payload bit 0
        let mut t = table12();
        t.pack[1] = (1u32 << 5) | 1; // sym 1 = 1-bit code 1
        let mut w = BitWriter::new();
        emit_diff(&mut w, &t, 1);
        w.flush();
        // code 1, payload 1, flush 1111111 => 11111111 = ff (stuffed)
        assert_eq!(w.out, vec![0xff, 0x00]);
        let mut w = BitWriter::new();
        emit_diff(&mut w, &t, -1);
        w.flush();
        // code 1, payload 0, flush 1111111 => 10111111 = 0xBF (not 0xFF:
        // no stuffing)
        assert_eq!(w.out, vec![0xbf]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tileenc::{encode_planes, planes_from_tile, Grid, Orient};

    /// Byte-identity harness: the native stream must equal
    /// the libjpeg stream for every (pattern, geometry, precision,
    /// candidate), incl. cross (orient,psv) pairs beyond the measured 3.
    fn assert_native_eq_libjpeg(mosaic: &[u16], frame_w: u32, frame_h: u32, precision: u32, label: &str) {
        let g = Grid::new(frame_w, frame_h);
        let cands = [
            (Orient::Wrapped, 7i32),
            (Orient::Wrapped, 2),
            (Orient::Natural, 1),
            (Orient::Wrapped, 1),
            (Orient::Natural, 7),
        ];
        for r in 0..g.rows {
            for c in 0..g.cols {
                for &(orient, psv) in &cands {
                    let p = planes_from_tile(mosaic, frame_w, frame_h, &g, r, c, orient).unwrap();
                    let native = encode_planes_native(&p, precision, psv).unwrap();
                    let lib = encode_planes(&p, precision, psv).unwrap();
                    assert_eq!(
                        native, lib,
                        "{label}: native != libjpeg ({}x{}, orient {:?}, psv {psv}, precision {precision}, tile {r},{c})",
                        p.rows, p.cols, orient
                    );
                }
            }
        }
    }

    fn mosaic(w: u32, h: u32, f: impl Fn(usize, usize) -> u16) -> Vec<u16> {
        (0..(w * h) as usize)
            .map(|i| f(i % w as usize, i / w as usize))
            .collect()
    }

    /// Stateless pseudo-random 16-bit hash (uniform-ish, reproducible).
    fn hash16(x: usize, y: usize) -> u16 {
        let a = (x as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let b = (y as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
        (a ^ b) as u16
    }

    #[test]
    fn synthetic_byte_identical_full_tile() {
        // Full tile geometry 482x272 (planes 136x482 / 272x241); values
        // within the per-precision sample range (0..4095 / 0..1023).
        for prec in [10u32, 12] {
            let maxv = (1u32 << prec) - 1;
            let pats: [(&str, Box<dyn Fn(usize, usize) -> u16>); 7] = [
                ("zeros", Box::new(|_, _| 0u16)),
                ("flat-max", Box::new(|_, _| maxv as u16)),
                (
                    "ramp",
                    Box::new(move |x, y| ((x * 3 + y * 7) % ((maxv + 1) as usize)) as u16),
                ),
                (
                    "checkerboard",
                    Box::new(move |x, y| if (x + y) % 2 == 0 { 0 } else { maxv as u16 }),
                ),
                (
                    "boundary",
                    Box::new(move |x, y| if x % 3 == 0 { (maxv - 1) as u16 } else { maxv as u16 }),
                ),
                (
                    "sawtooth",
                    Box::new(move |x, y| (((x + y) / 8) % (maxv as usize)) as u16),
                ),
                ("hash", Box::new(|x, y| hash16(x, y))),
            ];
            for (label, f) in &pats {
                let m = mosaic(482, 272, |x, y| f(x, y) & maxv as u16);
                assert_native_eq_libjpeg(&m, 482, 272, prec, label);
            }
        }
    }

    #[test]
    fn synthetic_byte_identical_last_row_and_small() {
        // Last-row (padded) and small/multi-tile geometries.
        let m1 = mosaic(482, 266, |x, y| (((x ^ y) * 5) % 4096) as u16);
        assert_native_eq_libjpeg(&m1, 482, 266, 12, "last-row 482x266 prec12");
        assert_native_eq_libjpeg(&m1, 482, 266, 10, "last-row 482x266 prec10");
        let m2 = mosaic(482, 273, |x, y| ((x + y * 2) % 977) as u16);
        assert_native_eq_libjpeg(&m2, 482, 273, 12, "odd-row 482x273 prec12");
        assert_native_eq_libjpeg(&m2, 482, 273, 10, "odd-row 482x273 prec10");
        // hash16 full-range values are OUT OF RANGE for precisions 10/12
        // (libjpeg's differencing is int16; in-range u16 data makes i32 and
        // int16 arithmetic identical), so bound each pattern to its
        // precision's sample range.
        let m3 = mosaic(982, 300, |x, y| (hash16(x, y) % 4096) as u16);
        assert_native_eq_libjpeg(&m3, 982, 300, 12, "multi-tile 982x300 prec12");
        let m4 = mosaic(982, 300, |x, y| (hash16(x, y) % 1024) as u16);
        assert_native_eq_libjpeg(&m4, 982, 300, 10, "multi-tile 982x300 prec10");
    }

    // --- diff/symbol unit tests (hand-computed) ---

    /// 2×2 plane, precision 12, PSV 7: [[100, 300], [200, 400]],
    /// first-row x = 2048:
    ///   (0,0): 100−2048 = −1948 → 11 bits; (0,1): 300−100 = 200 → 8 bits
    ///   (1,0): 200−100 = 100 → 7 bits [col 0 = Rb];
    ///   (1,1): 400−((300+200)>>1 = 250) = 150 → 8 bits
    #[test]
    fn diff_counts_psv7_hand_computed() {
        let plane: Vec<u16> = vec![100, 300, 200, 400];
        let c = diff_counts(&plane, 2, 2, 12, 7);
        assert_eq!(c[7], 1, "one 7-bit diff");
        assert_eq!(c[8], 2, "two 8-bit diffs");
        assert_eq!(c[11], 1, "one 11-bit diff");
        assert_eq!(c.iter().sum::<u64>(), 4, "every sample counted once");
    }

    /// Precision 10 changes the first-row predictor (x = 512):
    /// single row [512]: diff 0 → symbol 0.
    #[test]
    fn diff_counts_first_row_predictor_per_precision() {
        let c10 = diff_counts(&[512u16], 1, 1, 10, 7);
        assert_eq!(c10[0], 1, "512 − 2^(10−1) = 0 → symbol 0");
        let c12 = diff_counts(&[512u16], 1, 1, 12, 7);
        // 512 − 2048 = −1536 → mag 1536 → 11 bits
        assert_eq!(c12[11], 1);
    }

    /// Non-first-row col 0 uses PREDICTOR2 (up) even for PSV 1/7:
    /// plane [[100], [300]] → row 1 col 0 diff = 300−100 = 200 (8 bits),
    /// NOT (0+100)>>1 = 50 (the PSV-7 expression would mispredict it).
    #[test]
    fn nonfirst_row_col0_is_predictor2() {
        let c1 = diff_counts(&[100u16, 300], 2, 1, 12, 1);
        let c7 = diff_counts(&[100u16, 300], 2, 1, 12, 7);
        assert_eq!(c1[8], 1, "PSV 1 col 0: up-predictor (200 → 8 bits)");
        assert_eq!(c7[8], 1, "PSV 7 col 0: up-predictor, not (0+up)>>1");
    }

    /// The d = −32768 corner (symbol 16, no payload bits downstream).
    #[test]
    fn diff_symbol_corners() {
        assert_eq!(diff_symbol(-32768), 16);
        assert_eq!(diff_symbol(0), 0);
        assert_eq!(diff_symbol(1), 1);
        assert_eq!(diff_symbol(-1), 1);
        assert_eq!(diff_symbol(2048), 12);
    }

    /// Negative-magnitude payload is the nbits-bit one's complement
    /// (libjpeg: temp2 = ~temp (16-bit), emit_bits masks to nbits):
    /// with a table where symbol 1 carries code 0 (1 bit):
    ///   d = +1 → code bit 0, payload bit 1 → "01" + ones pad = 0x7F
    ///   d = −1 → code bit 0, payload bit 0 (1-bit complement of 1) →
    ///            "00" + ones pad = 0x3F
    #[test]
    fn negative_payload_ones_complement() {
        let c = [0u64, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let t = build_table(&c);
        let mut w = BitWriter::new();
        emit_diff(&mut w, &t, 1);
        w.flush();
        assert_eq!(w.out, [0x7F], "+1 → bits 01 padded with ones");
        let mut w = BitWriter::new();
        emit_diff(&mut w, &t, -1);
        w.flush();
        assert_eq!(w.out, [0x3F], "-1 → bits 00 padded with ones");
    }

    // --- exact-size (size-only) unit gates ---

    /// The even-padded length `tileenc::encode_candidate` produces.
    fn padded_len(s: &[u8]) -> usize {
        s.len() + s.len() % 2
    }

    /// Every (tile, candidate) of the synthetic set must satisfy
    /// `size-only == full encode post-pad len` (the unit gate).
    fn assert_size_eq_full(mosaic: &[u16], frame_w: u32, frame_h: u32, precision: u32, label: &str) {
        let g = Grid::new(frame_w, frame_h);
        let cands = [
            (Orient::Wrapped, 7i32),
            (Orient::Wrapped, 2),
            (Orient::Natural, 1),
            (Orient::Wrapped, 1),
            (Orient::Natural, 7),
        ];
        for r in 0..g.rows {
            for c in 0..g.cols {
                for &(orient, psv) in &cands {
                    let p = planes_from_tile(mosaic, frame_w, frame_h, &g, r, c, orient).unwrap();
                    let full = encode_planes_native(&p, precision, psv).unwrap();
                    let sz = encode_planes_native_size(&p, precision, psv).unwrap();
                    assert_eq!(
                        sz,
                        padded_len(&full),
                        "{label}: size-only {sz} != full post-pad {} ({}x{}, {:?}, psv {psv}, prec {precision}, tile {r},{c})",
                        padded_len(&full),
                        p.rows,
                        p.cols,
                        orient
                    );
                }
            }
        }
    }

    /// Gate over the full synthetic set: all tile geometries (full /
    /// last-row / odd-row / multi-tile), both precisions, the 3 reference
    /// (orient,psv) pairs + the 2 cross pairs, all patterns (incl.
    /// constant planes). In-range data only: libjpeg's differencing is
    /// int16, so out-of-range u16 would diverge between the FFI engine
    /// and the native one (a known non-issue — the corpus is in-range);
    /// the symbol-16 / d=−32768 corner is gated at the writer level in
    /// `size_writer_corner_counting`.
    #[test]
    fn size_only_matches_full_len_synthetic() {
        for prec in [10u32, 12] {
            let maxv = (1u32 << prec) - 1;
            let pats: [(&str, Box<dyn Fn(usize, usize) -> u16>); 7] = [
                ("zeros", Box::new(|_, _| 0u16)),
                ("flat-max", Box::new(|_, _| maxv as u16)),
                (
                    "ramp",
                    Box::new(move |x, y| ((x * 3 + y * 7) % ((maxv + 1) as usize)) as u16),
                ),
                (
                    "checkerboard",
                    Box::new(move |x, y| if (x + y) % 2 == 0 { 0 } else { maxv as u16 }),
                ),
                (
                    "boundary",
                    Box::new(move |x, y| if x % 3 == 0 { (maxv - 1) as u16 } else { maxv as u16 }),
                ),
                (
                    "sawtooth",
                    Box::new(move |x, y| (((x + y) / 8) % (maxv as usize)) as u16),
                ),
                ("hash", Box::new(|x, y| hash16(x, y) & maxv as u16)),
            ];
            for (fw, fh) in [(482u32, 272), (482, 266), (482, 273), (982, 300)] {
                for (label, f) in &pats {
                    let m = mosaic(fw, fh, |x, y| f(x, y));
                    assert_size_eq_full(&m, fw, fh, prec, label);
                }
            }
        }
    }

    /// Writer-level corner gate: `SizeWriter` must count exactly what
    /// `BitWriter` stores, step by step, on a sequence covering the
    /// symbol-0 (no payload), symbol-16 / d = −32768 (no payload),
    /// 1-bit payloads, and a 0xFF-stuffing-heavy run.
    #[test]
    fn size_writer_corner_counting() {
        // Hand table: sym 0 = 1-bit code 0; sym 1 = 1-bit code 1;
        // sym 16 = 2-bit code 3.
        let mut t = Table {
            bits16: [0; 16],
            nsym: 0,
            huffval: [0; 17],
            pack: [0; 17],
        };
        t.pack[0] = (0u32 << 5) | 1;
        t.pack[1] = (1u32 << 5) | 1;
        t.pack[16] = (3u32 << 5) | 2;
        // 16 × (code 1, payload 1) = 32 bits of '1' → stuffed FF bytes.
        let diffs: [i32; 22] = [
            0, 1, -1, -32768,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            0, -32768, 1, -1, 0, 1,
        ];
        let mut bw = BitWriter::new();
        let mut sw = SizeWriter::new();
        for (i, &d) in diffs.iter().enumerate() {
            emit_diff(&mut bw, &t, d);
            emit_diff(&mut sw, &t, d);
            assert_eq!(sw.out_len, bw.out.len(), "step {i} (d {d}): count drift");
        }
        bw.flush();
        sw.flush();
        assert_eq!(sw.out_len, bw.out.len(), "after flush");
        bw.raw(0xFF);
        bw.raw(0xD9);
        sw.raw(0xFF);
        sw.raw(0xD9);
        assert_eq!(sw.out_len, bw.out.len(), "after EOI");
        assert!(
            bw.out.windows(2).any(|w| w == [0xFF, 0x00]),
            "the '1' run must have produced a stuffed 0xFF byte"
        );
        assert_eq!(
            sw.out_len + sw.out_len % 2,
            padded_len(&bw.out),
            "post-pad arithmetic consistent"
        );
    }
}

// ----------------------------------------------------- combined-emit test gates
//
// Byte-identity gates for the combined-emit variants (v1/v2):
// (a) writer-level: v1/v2 byte streams == BitWriter byte streams on
//     crafted + pseudo-random emit/emit2 sequences (0xFF-stuffing-heavy);
// (b) tile-level: encode_planes_native (current) ==
//     encode_planes_native_v(1) == encode_planes_native_v(2) on synthetic
//     adversarial planes, both tile geometries, both precisions, all PSVs.

#[cfg(test)]
mod m2_tests {
    use super::*;

    /// Deterministic 16-bit LCG (no external crate).
    struct Rng(u64);
    impl Rng {
        fn next16(&mut self) -> u16 {
            self.0 = self
                .0
                .wrapping_mul(6364136223)
                .wrapping_add(144269);
            (self.0 >> 48) as u16
        }
        fn next_u32_below(&mut self, n: u32) -> u32 {
            self.next16() as u32 % n
        }
    }

    /// (a) Writer-level: a random sequence of combined emits on v1 and v2
    /// must equal the same sequence expanded to two separate emits on the
    /// production writer (and on each other).
    #[test]
    fn combined_emit_matches_split_emits() {
        for v in [1u8, 2] {
            let mut cur = BitWriter::new();
            let mut vw = if v == 1 {
                WBox::C(BitWriterC::new())
            } else {
                WBox::B(BitWriterB::new())
            };
            let mut rng = Rng(0xC0FFEE);
            for _ in 0..4096 {
                let size = 1 + rng.next_u32_below(16);
                let psize = rng.next_u32_below(16);
                let code = rng.next16() as u32 & ((1u32 << size) - 1);
                let payload = rng.next16() as u32 & ((1u32 << psize.min(15)) - 1);
                cur.emit(code, size);
                if psize != 0 {
                    cur.emit(payload, psize);
                }
                vw.emit2(code, size, payload, psize);
            }
            cur.flush();
            vw.flush();
            let vw_out = vw.out();
            assert_eq!(
                cur.out, vw_out,
                "v{v}: combined-emit stream != split-emit stream"
            );
        }
    }

    /// (a) 0xFF-stuffing-heavy: a 31-bit run of ones (max combined emit)
    /// repeated, then shorter combined emits — every v1/v2 output must
    /// equal the production writer's, stuffing included.
    #[test]
    fn combined_emit_stuffing_heavy() {
        for v in [1u8, 2] {
            let mut cur = BitWriter::new();
            let mut vw = if v == 1 {
                WBox::C(BitWriterC::new())
            } else {
                WBox::B(BitWriterB::new())
            };
            // 200 max combined emits (31 one-bits each = 775 one-bits →
            // ~96 stuffed 0xFF bytes), plus 5000 varied emits.
            for _ in 0..200 {
                cur.emit(0xFFFF, 16);
                cur.emit(0x7FFF, 15);
                vw.emit2(0xFFFF, 16, 0x7FFF, 15);
            }
            let mut rng = Rng(42);
            for _ in 0..5000 {
                let size = 1 + rng.next_u32_below(16);
                let psize = rng.next_u32_below(16);
                let code = rng.next16() as u32 & ((1u32 << size) - 1);
                let payload = rng.next16() as u32 & ((1u32 << psize.min(15)) - 1);
                cur.emit(code, size);
                if psize != 0 {
                    cur.emit(payload, psize);
                }
                vw.emit2(code, size, payload, psize);
            }
            cur.flush();
            vw.flush();
            assert_eq!(cur.out, vw.out(), "v{v}: stuffing-heavy stream mismatch");
            assert!(cur.out.windows(2).any(|w| w == [0xFF, 0x00]));
        }
    }

    /// Writer-box helper so one test body drives both variant writers.
    enum WBox {
        C(BitWriterC),
        B(BitWriterB),
    }
    impl WBox {
        fn emit2(&mut self, code: u32, size: u32, payload: u32, psize: u32) {
            match self {
                WBox::C(w) => w.emit2(code, size, payload, psize),
                WBox::B(w) => w.emit2(code, size, payload, psize),
            }
        }
        fn flush(&mut self) {
            match self {
                WBox::C(w) => w.flush(),
                WBox::B(w) => w.flush(),
            }
        }
        fn out(&self) -> Vec<u8> {
            match self {
                WBox::C(w) => w.out.clone(),
                // B keeps a tail batch; clone the finalized form.
                WBox::B(w) => {
                    let mut w2 = BitWriterB {
                        out: w.out.clone(),
                        buf: 0,
                        bits: 0,
                        batch: w.batch,
                        blen: w.blen,
                    };
                    w2.flush_batch();
                    w2.out
                }
            }
        }
    }

    /// (b) Tile-level: full pipeline byte-identity, current == v1 == v2,
    /// on adversarial synthetic planes through the REAL tile geometry
    /// (`planes_from_tile`: full 482×272 → 136×482 wrapped / 272×241
    /// natural, and the clipped last-row 482×266), all 14 (orient,psv)
    /// pairs, both precisions, 7 patterns.
    #[test]
    fn full_tile_variants_identical() {
        use crate::tileenc::{planes_from_tile, Grid, Orient};

        // Deterministic 16-bit hash (uniform-ish, reproducible).
        fn hash16(x: usize, y: usize) -> u16 {
            let h = (x as u64).wrapping_mul(2654435761) ^ (y as u64).wrapping_mul(40503);
            (h ^ h >> 12) as u16
        }
        // The standing test geometries: full tile (1×1 grid), the
        // clipped last-row (tl=266), and multi-tile incl. clipped
        // column/row (3×2 grid).
        let frames: [(u32, u32); 3] = [(482, 272), (482, 266), (982, 300)];
        let pairs: [(Orient, i32); 14] = [
            (Orient::Wrapped, 1),
            (Orient::Wrapped, 2),
            (Orient::Wrapped, 3),
            (Orient::Wrapped, 4),
            (Orient::Wrapped, 5),
            (Orient::Wrapped, 6),
            (Orient::Wrapped, 7),
            (Orient::Natural, 1),
            (Orient::Natural, 2),
            (Orient::Natural, 3),
            (Orient::Natural, 4),
            (Orient::Natural, 5),
            (Orient::Natural, 6),
            (Orient::Natural, 7),
        ];
        for (fw, fh) in frames {
            for prec in [10u32, 12] {
                let maxv = 1 << prec;
                let mut g = Grid::new(fw, fh);
                for r in 0..g.rows {
                    for c in 0..g.cols {
                        for (label, pat) in [
                            ("zeros", Box::new(|x: usize, y: usize| 0u16)),
                            ("flat-max", Box::new(move |x: usize, y: usize| maxv as u16 - 1)),
                            ("ramp", Box::new(move |x: usize, y: usize| ((x * 3 + y * 7) % maxv as usize) as u16)),
                            ("checker", Box::new(move |x: usize, y: usize| if (x + y) % 2 == 0 { 0 } else { maxv as u16 - 1 })),
                            ("random", Box::new(move |x: usize, y: usize| hash16(x, y) % maxv as u16)),
                            ("sawtooth", Box::new(move |x: usize, y: usize| ((x + y * 2) % 13) as u16 * maxv as u16 / 13)),
                            ("gradient", Box::new(move |x: usize, y: usize| (((x + y) % 754) * maxv as usize / 754) as u16)),
                        ] as [(&str, Box<dyn Fn(usize, usize) -> u16>); 7] {
                            let (fwu, fhu) = (fw as usize, fh as usize);
                            let mosaic: Vec<u16> = (0..fwu * fhu)
                                .map(|i| pat(i % fwu, i / fhu))
                                .collect();
                            for &(orient, psv) in &pairs {
                                let p =
                                    planes_from_tile(&mosaic, fw, fh, &g, r, c, orient)
                                        .unwrap();
                                let cur = encode_planes_native(&p, prec, psv).unwrap();
                                let v1 = encode_planes_native_v(&p, prec, psv, 1).unwrap();
                                let v2 = encode_planes_native_v(&p, prec, psv, 2).unwrap();
                                assert_eq!(
                                    cur, v1,
                                    "{label}: v1 != current ({fw}x{fh} tile {r},{c}, {orient:?}, psv {psv}, prec {prec})"
                                );
                                assert_eq!(
                                    cur, v2,
                                    "{label}: v2 != current ({fw}x{fh} tile {r},{c}, {orient:?}, psv {psv}, prec {prec})"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
