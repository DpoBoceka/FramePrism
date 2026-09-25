//! The log10 curve: 12-bit linear values <-> 10-bit log codes.
//!
//! "Lossless 10-bit log" (reference preset `log10`): the raw plane is stored
//! as 10-bit LOG-ENCODED codes in the SAME lossless tile structure as the
//! 12-bit mode (SOF3, PSV 7, 2 even/odd parity-plane components), with
//! `data_precision=10` / `BitsPerSample=10`. The 12-bit value each code
//! represents is signalled by the DNG `LinearizationTable` tag (50712,
//! SHORT, count 1024 = `LUT` below) — the DNG processing model (spec Ch. 5
//! "Mapping Raw Values to Linear Reference Values", verified against the
//! DNG SDK `dng_linearization_info.cpp`: `x = min(x, N-1); x = lut[x]`)
//! maps stored code -> linear value BEFORE black subtraction and the
//! WhiteLevel rescale, so `WhiteLevel` stays 4095 (12-bit, linear domain).
//!
//! CURVE (the exact formula — reproducibility contract): a log mapping where the 10-bit
//! codes span 2 doublings (4x) of the 12-bit linear range, anchored at
//! black and white:
//!
//!     L(c) = round( 4095 * (2^(2c/1023) - 1) / 3 ),   c = 0..1023
//!
//! with `round` = half away from zero (Rust `f64::round`), then forced
//! exact at the anchors (L[0] = 0, L[1023] = 4095) and made monotone
//! non-decreasing (running max — rounding never decreases a value, the
//! pass is a safety invariant, not a correction). Properties:
//! - L(0) = 0, L(1023) = 4095 exactly; every L(c) an exact 12-bit integer
//!   (0..4095) — decoding a stored code is a pure table lookup, no
//!   interpolation (the "exactly invertible for integer 10-bit codes"
//!   requirement).
//! - Monotone non-decreasing: shadow codes are FINER than a 4:1 bit trim
//!   (the first 1024 values 0..1023 map onto 535 distinct 12-bit values;
//!   the 10-bit codes 0..533 cover 12-bit 0..1023 at <= ~1.9 LSB/code
//!   near 0, i.e. sub-2-LSB shadow resolution) while the highlight region
//!   is coarser (by construction of any 1024-code covering of 0..4095).
//! - Encoder mapping `INV[v]` = the smallest code c minimizing
//!   |L(c) - v| (deterministic; ties go to the lower code). Reconstructed
//!   value of v = L[INV[v]].
//!
//! MEASURED on clip A001_001 (full 225 frames, 1,882,692,000 samples,
//! values 253..1995 only — a dark clip; see the decisions.md
//! entry for the stats): max recon error 2 LSB at isolated midtone values
//! (0.029% of samples), mean 0.56 LSB, 99.97% within 1 LSB. The full-
//! range worst case (values the clip never contains, e.g. v=3881 -> 4
//! LSB) is the hard bound `max_recon_error()` — the verify gate.
//!
//! NOTE on the "log" name: this is the 2-octave exponential form of a log
//! mapping (codes ∝ log2(1 + v·3/4095)); the alternative
//! `c = 1023·log2(1+v/4095)` (1 octave) was measured and is strictly
//! worse on A001 (max error 2 with worse entropy proxy, 1.015 vs 1.005
//! bits/sample — see the decisions.md entry).

use std::sync::OnceLock;

pub const LUT_LEN: usize = 1024;
/// 12-bit value each code represents: `LUT[c]` (DNG tag 50712 content).
pub static LUT: OnceLock<[u16; LUT_LEN]> = OnceLock::new();
/// Encoder mapping: 12-bit value -> nearest 10-bit log code (smallest on
/// ties). `INV[v]`.
pub static INV: OnceLock<[u16; 4096]> = OnceLock::new();
/// Hard worst-case reconstruction error over the full 12-bit range
/// (max_v |L[INV[v]] - v|) — the log10 verify gate bound.
pub static MAX_RECON_ERROR: OnceLock<u16> = OnceLock::new();

fn build_lut() -> [u16; LUT_LEN] {
    let mut lut = [0u16; LUT_LEN];
    // Both loops use the loop variable as a VALUE (the LUT index IS the
    // curve input; the second loop reads the possibly-clamped value back),
    // so range loops are the direct form (clippy allow).
    #[allow(clippy::needless_range_loop)]
    for c in 0..LUT_LEN {
        // 2^(2c/1023) = exp((2c/1023) * ln 2); curve anchored 0 -> 4095.
        let t = (c as f64) * (2.0 / 1023.0) * core::f64::consts::LN_2;
        let v = 4095.0 * (t.exp() - 1.0) / 3.0;
        lut[c] = v.round() as u16; // round half away from zero
    }
    lut[0] = 0;
    // Monotone non-decreasing enforcement (safety invariant; the curve is
    // strictly increasing so rounding cannot break order — the pass is
    // kept so a future curve change is caught in the LUT unit test).
    let mut prev = 0u16;
    for l in lut.iter_mut() {
        if *l < prev {
            *l = prev;
        }
        prev = *l;
    }
    lut[LUT_LEN - 1] = 4095;
    lut
}

fn build_inv(lut: &[u16; LUT_LEN]) -> [u16; 4096] {
    // Two-pointer scan: LUT is non-decreasing, so the argmin over c of
    // |LUT[c] - v| is found by advancing while the NEXT code is strictly
    // closer (ties keep the lower code). O(LUT_LEN) total for all v.
    let mut inv = [0u16; 4096];
    let mut c = 0usize;
    for v in 0..4096u32 {
        while c + 1 < LUT_LEN
            && (lut[c + 1] as i32 - v as i32).unsigned_abs()
                < (lut[c] as i32 - v as i32).unsigned_abs()
        {
            c += 1;
        }
        inv[v as usize] = c as u16;
    }
    inv
}

/// The 1024-entry linearization LUT (tag 50712 content, 2048 SHORT bytes).
pub fn lut() -> &'static [u16; LUT_LEN] {
    LUT.get_or_init(build_lut)
}

/// LUT content as file-order SHORT bytes (2048 B) — what the surgery
/// writes out-of-line and the verify gate compares. TIFF type 3 (SHORT)
/// multi-value arrays are stored in the FILE's byte order (little-endian
/// for the fp's II\x2A\x00 files) — NOT big-endian; verified against
/// LibRaw/rawpy (a big-endian LUT made rawpy apply a
/// byte-swapped table: L(135)=274 read as 0x1201=4609 instead of 274).
pub fn lut_bytes() -> Vec<u8> {
    let l = lut();
    let mut out = Vec::with_capacity(LUT_LEN * 2);
    for &v in l {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

/// Encoder mapping 12-bit value -> nearest 10-bit log code.
pub fn inv() -> &'static [u16; 4096] {
    INV.get_or_init(|| build_inv(lut()))
}

/// Hard worst-case |L[INV[v]] - v| over all 12-bit v (the verify gate).
pub fn max_recon_error() -> u16 {
    *MAX_RECON_ERROR.get_or_init(|| {
        let (l, i) = (lut(), inv());
        (0..4096u32)
            .map(|v| (l[i[v as usize] as usize] as i32 - v as i32).unsigned_abs() as u16)
            .max()
            .unwrap_or(0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lut_exactness_and_endpoints() {
        let l = lut();
        assert_eq!(l.len(), 1024);
        assert_eq!(l[0], 0, "L(0) must be exactly 0");
        assert_eq!(l[1023], 4095, "L(1023) must be exactly 4095");
        for (c, (a, b)) in l.iter().zip(l.iter().skip(1)).enumerate() {
            assert!(a <= b, "LUT must be monotone non-decreasing at c={c}");
        }
        // Every entry a valid 12-bit value (structurally true of u16? no:
        // assert the 12-bit bound explicitly — the LUT feeds tag 50712 and
        // the reconstruction compare).
        assert!(l.iter().all(|&v| v <= 4095));
        // Canary: the exact curve (2 doublings, round half away from zero).
        // Computed with an independent Python replica of the formula:
        // L(256) = 566, L(511) = 1363, L(768) = 2500.
        assert_eq!(l[256], 566, "curve drifted: L(256) = {}", l[256]);
        assert_eq!(l[511], 1363, "curve drifted: L(511) = {}", l[511]);
        assert_eq!(l[768], 2500, "curve drifted: L(768) = {}", l[768]);
    }

    #[test]
    fn lut_invertibility_integer_codes() {
        let (l, i) = (lut(), inv());
        // For every 10-bit CODE: the nearest 12-bit value of L(c) is
        // exactly L(c) itself (exactness in the code -> linear direction:
        // no interpolation is ever needed at decode time).
        for c in 0..1024u16 {
            let v = l[c as usize];
            assert_eq!(
                l[i[v as usize] as usize], v,
                "L(INV[L(c)]) != L(c) at c={c}"
            );
        }
        // The encoder map is monotone (v1 < v2 -> INV[v1] <= INV[v2]).
        let mut prev = 0u16;
        for v in 0..4096u32 {
            let c = i[v as usize] as u16;
            assert!(c >= prev, "INV not monotone at v={v}");
            prev = c;
        }
    }

    #[test]
    fn recon_error_bound() {
        // Full-range worst case of THIS curve (documented canary): 4 LSB
        // (at v=3881 — a highlight the A001 clip never reaches; A001
        // maxes out at 2, see the decisions entry).
        assert_eq!(max_recon_error(), 4, "curve worst case drifted");
        let (l, i) = (lut(), inv());
        for v in 0..4096u32 {
            let err = (l[i[v as usize] as usize] as i32 - v as i32).unsigned_abs();
            assert!(err <= max_recon_error() as u32);
        }
    }

    #[test]
    fn lut_bytes_layout() {
        let b = lut_bytes();
        assert_eq!(b.len(), 2048, "tag 50712 = SHORT count 1024 = 2048 B");
        // File-order (little-endian) SHORTs: L(0) = 0x0000, L(1) = 2 =
        // [02 00], L(1023) = 4095 = [FF 0F].
        assert_eq!(&b[0..2], &[0x00, 0x00]);
        assert_eq!(&b[2..4], &[0x02, 0x00]);
        assert_eq!(&b[2046..2048], &[0xFF, 0x0F]);
    }
}
