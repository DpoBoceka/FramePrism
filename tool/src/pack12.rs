//! Native-depth sample unpack/pack (12-bit 2-per-3-bytes, 10-bit
//! per-row bitstream = 4-per-5-bytes, 8-bit 1 byte per sample;
//! DNG-standard order).
//!
//! The 10-bit rule (validated against the DNG SDK reference
//! implementation, dng_read_image::ReadUncompressed — the generic
//! `8 < bitDepth < 16` case — on the CINEMA batch, fp firmware
//! Ver.5.02.0.V91; A001_002/005): a per-ROW big-endian BITSTREAM, samples
//! MSB-first — each row of `width` samples is `width*5/4` bytes and rows
//! never continue into each other (the SDK resets the bit buffer per row;
//! the row ends on a byte boundary when `width` is a multiple of 4 — both
//! of the fp's readouts: 3856, 1936). For such widths the bitstream is
//! equivalent to 4-samples-per-5-byte groups (1.25 B/sample):
//!
//!     word = (b0 << 32) | (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
//!     sample[4k]   = (word >> 30) & 0x3FF     // high 10 bits first
//!     sample[4k+1] = (word >> 20) & 0x3FF
//!     sample[4k+2] = (word >> 10) & 0x3FF
//!     sample[4k+3] = word & 0x3FF
//!
//! 8-bit is the trivial 1-byte-per-sample layout. The bit-exact round-trip
//! gates (in-tool `--verify` + the independent from-spec unpack) are the
//! acceptance proof; the LibRaw-style pixel-exact cross-check applies to
//! the 12-bit rule below (and should be extended to 10/8-bit when an
//! independent decoder build with those precisions is available).
//!
//! VERIFIED pixel-exact against LibRaw (clip A001_001 frame 1):
//! each 3-byte group `b0 b1 b2` is a **big-endian 24-bit word**, samples
//! **MSB-first** — the DNG/TIFF nominal convention:
//!
//!     word = (b0 << 16) | (b1 << 8) | b2
//!     sample[2k]   = (word >> 12) & 0xFFF     // high 12 bits first
//!     sample[2k+1] = word & 0xFFF             // low 12 bits
//!
//! Pixel-exact means: `unpack12(strip)` == LibRaw's `raw_image` for 100%
//! of the 8,367,520 samples of A001_001_000001.DNG (min 253, max 881,
//! mean 271.452). This is the gate — if a future camera/firmware deviates
//! from the nominal convention, this test and the per-release independent-
//! decoder cross-check are what catch it.
//!
//! HISTORY: an earlier pass claimed "LSB-first, fp deviates from spec"
//! based on a flawed cross-layout test (it compared against the wrong
//! alternative). The correct check is pixel-exact equality against an
//! independent decoder (LibRaw), which settles it: the fp writes the
//! standard order.
//!
//! Guarding: a per-frame heuristic (e.g. adjacent-difference statistics)
//! CANNOT reliably distinguish correct from misaligned decoding — measured
//! on real A001 frames the adjacent-MAD/mean ratio is 0.7–1.2 even for
//! correctly decoded near-black noisy scenes. Protection instead comes
//! from: (1) bit-exact roundtrip in `verify`, (2) independent-decoder
//! cross-check (LibRaw/rawpy) per release, (3) the NLE smoke test. If a
//! future firmware changes packing, the NLE check is what catches it.
//!
//! NOTE: a trailing strip may carry a few padding bytes (the fp emits
//! +12 B on 10/12-bit and +8 B on 8-bit, the batch). Unpack exactly
//! `width*height` samples and ignore the rest.

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum PackError {
    #[error("packed buffer too short: need {need} bytes for {w}x{h}, got {have}")]
    TooShort {
        need: usize,
        have: usize,
        w: u32,
        h: u32,
    },
    #[error("odd pixel count {0}; 2-sample (12-bit) packing requires even width*height")]
    OddPixelCount(u64),
    #[error("10-bit width {0} (not a multiple of 4): the per-row 10-bit bitstream must end on a byte boundary")]
    WidthNotMultipleOf4(u32),
    #[error("sample {at} = {value} is above the {max}-bit range; refusing to clip")]
    SampleOutOfRange { at: u64, value: u16, max: u16 },
}

/// Unpack `width*height` 12-bit samples (big-endian word, MSB-first) from
/// `packed` (>= 3*(w*h/2) bytes; trailing padding is ignored).
pub fn unpack12(packed: &[u8], width: u32, height: u32) -> Result<Vec<u16>, PackError> {
    let pixels = (width as u64) * (height as u64);
    if pixels % 2 != 0 {
        return Err(PackError::OddPixelCount(pixels));
    }
    let pixels = pixels as usize;
    let need = pixels / 2 * 3;
    if packed.len() < need {
        return Err(PackError::TooShort {
            need,
            have: packed.len(),
            w: width,
            h: height,
        });
    }
    let groups = pixels / 2;
    let mut out = vec![0u16; pixels];
    for i in 0..groups {
        let o = i * 3;
        let word = (packed[o] as u32) << 16 | (packed[o + 1] as u32) << 8 | packed[o + 2] as u32;
        out[2 * i] = ((word >> 12) & 0xFFF) as u16;
        out[2 * i + 1] = (word & 0xFFF) as u16;
    }
    Ok(out)
}

/// Unpack `width*height` 10-bit samples (the DNG per-row big-endian
/// bitstream, MSB-first — see the module docs; `width` must be a multiple
/// of 4 so each row is exactly `width*5/4` bytes) from `packed` (>=
/// height*width*5/4 bytes; trailing padding is ignored).
pub fn unpack10(packed: &[u8], width: u32, height: u32) -> Result<Vec<u16>, PackError> {
    if width % 4 != 0 {
        return Err(PackError::WidthNotMultipleOf4(width));
    }
    let pixels = (width as u64) * (height as u64);
    let need = (pixels as usize) * 5 / 4;
    if packed.len() < need {
        return Err(PackError::TooShort {
            need,
            have: packed.len(),
            w: width,
            h: height,
        });
    }
    // width % 4 == 0 ⇒ every row is a whole number of 5-byte groups
    // (width/4), so the flat group stream == the per-row bitstream.
    let groups = (pixels as usize) / 4;
    let mut out = vec![0u16; pixels as usize];
    for i in 0..groups {
        let o = i * 5;
        let word = ((packed[o] as u64) << 32)
            | ((packed[o + 1] as u64) << 24)
            | ((packed[o + 2] as u64) << 16)
            | ((packed[o + 3] as u64) << 8)
            | packed[o + 4] as u64;
        out[4 * i] = ((word >> 30) & 0x3FF) as u16;
        out[4 * i + 1] = ((word >> 20) & 0x3FF) as u16;
        out[4 * i + 2] = ((word >> 10) & 0x3FF) as u16;
        out[4 * i + 3] = (word & 0x3FF) as u16;
    }
    Ok(out)
}

/// Unpack `width*height` 8-bit samples (1 byte per sample) from `packed`
/// (>= w*h bytes; trailing padding is ignored). Odd pixel counts are legal
/// here (no 2-sample grouping).
pub fn unpack8(packed: &[u8], width: u32, height: u32) -> Result<Vec<u16>, PackError> {
    let pixels = (width as usize) * (height as usize);
    if packed.len() < pixels {
        return Err(PackError::TooShort {
            need: pixels,
            have: packed.len(),
            w: width,
            h: height,
        });
    }
    Ok(packed[..pixels].iter().map(|&b| b as u16).collect())
}

/// Pack `samples` (8-bit values, 0..=255) into the 1-byte-per-sample
/// layout (the derived 12→8 working tier). Any
/// pixel count is legal (no 2-sample grouping).
pub fn pack8(samples: &[u16]) -> Result<Vec<u8>, PackError> {
    for (i, &v) in samples.iter().enumerate() {
        if v > 255 {
            return Err(PackError::SampleOutOfRange {
                at: i as u64,
                value: v,
                max: 255,
            });
        }
    }
    Ok(samples.iter().map(|&v| v as u8).collect())
}

/// Pack `samples` (10-bit values, 0..=1023) into the DNG per-row bitstream
/// layout — the inverse of `unpack10`: 4 samples per 5-byte group, MSB-
/// first (the derived 12→10 working tier).
/// `width` must be a multiple of 4 (then every row is a whole number of
/// 5-byte groups, so the flat group stream is the per-row bitstream) and
/// `samples.len()` must equal `width * height` for some height.
pub fn pack10(samples: &[u16], width: u32) -> Result<Vec<u8>, PackError> {
    if width % 4 != 0 {
        return Err(PackError::WidthNotMultipleOf4(width));
    }
    if samples.len() % 4 != 0 {
        return Err(PackError::OddPixelCount(samples.len() as u64));
    }
    for (i, &v) in samples.iter().enumerate() {
        if v > 1023 {
            return Err(PackError::SampleOutOfRange {
                at: i as u64,
                value: v,
                max: 1023,
            });
        }
    }
    let mut out = Vec::with_capacity(samples.len() * 5 / 4);
    for chunk in samples.chunks(4) {
        let word = ((chunk[0] as u64) << 30)
            | ((chunk[1] as u64) << 20)
            | ((chunk[2] as u64) << 10)
            | chunk[3] as u64;
        out.extend_from_slice(&word.to_be_bytes()[3..]);
    }
    Ok(out)
}

/// Pack `samples` (12-bit values) into the DNG-standard 2-per-3-bytes
/// layout (big-endian word, MSB-first). `samples.len()` may be even or odd
/// (odd → final group low half is zero).
pub fn pack12(samples: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(samples.len() / 2 * 3 + 3);
    for pair in samples.chunks(2) {
        let s0 = pair[0] as u32 & 0xFFF;
        let s1 = pair.get(1).map(|s| *s as u32 & 0xFFF).unwrap_or(0);
        let word = (s0 << 12) | s1;
        out.push((word >> 16) as u8);
        out.push((word >> 8) as u8);
        out.push(word as u8);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_synthetic() {
        // deterministic pattern covering the full 12-bit range
        let s: Vec<u16> = (0..16384u32).map(|i| ((i * 7919) % 4096) as u16).collect();
        let packed = pack12(&s);
        let back = unpack12(&packed, 1, s.len() as u32).unwrap();
        assert_eq!(back, s);
        assert_eq!(packed.len(), s.len() / 2 * 3);
    }

    #[test]
    fn odd_sample_count_packs_with_zero_low_half() {
        let s: Vec<u16> = vec![0x123, 0x456, 0x789];
        // 3 samples = 1 full group + 1 single (low half = 0) → 2 groups = 6 B
        let packed = pack12(&s);
        assert_eq!(packed.len(), 6);
        // group 2: s0 = 0x789, s1 = 0 → word = 0x789000 → [0x78, 0x90, 0x00]
        assert_eq!(packed[3..6], [0x78, 0x90, 0x00]);
        let back = unpack12(&packed, 1, 2).unwrap(); // ignore the odd tail
        assert_eq!(back, vec![0x123, 0x456]);
    }

    #[test]
    fn known_group() {
        // s0 = 0x123, s1 = 0x456 → word = 0x123456 → b0=0x12 b1=0x34 b2=0x56
        let packed = pack12(&[0x123, 0x456]);
        assert_eq!(packed, vec![0x12, 0x34, 0x56]);
        let back = unpack12(&packed, 2, 1).unwrap();
        assert_eq!(back, vec![0x123, 0x456]);
    }

    #[test]
    fn unpack10_known_group() {
        // 4 samples per 5-byte group, MSB-first (word = s0<<30 | s1<<20 |
        // s2<<10 | s3): [0x123, 0x45, 0x78, 0xAB] → 48 c4 51 e0 ab
        // (cross-checked against the DNG SDK's per-row bitstream loop).
        let packed = [0x48, 0xC4, 0x51, 0xE0, 0xAB];
        let back = unpack10(&packed, 4, 1).unwrap();
        assert_eq!(back, vec![0x123, 0x45, 0x78, 0xAB]);
    }

    #[test]
    fn unpack10_full_range_and_padding_ignored() {
        // 4 samples across the full 10-bit range: 0, 1, 511, 1023
        // word = 0<<30 | 1<<20 | 511<<10 | 1023 = 0x000017FFFF
        // → [0x00, 0x00, 0x17, 0xFF, 0xFF] (the 2 trailing bytes are
        // the ignored end-of-strip padding)
        let packed = [0x00, 0x00, 0x17, 0xFF, 0xFF, 0xAA, 0xBB];
        let back = unpack10(&packed, 4, 1).unwrap();
        assert_eq!(back, vec![0, 1, 511, 1023]);
    }

    #[test]
    fn unpack10_width_not_multiple_of_4_rejected() {
        assert_eq!(
            unpack10(&[0u8; 10], 2, 1),
            Err(PackError::WidthNotMultipleOf4(2))
        );
    }

    #[test]
    fn unpack10_roundtrip() {
        // deterministic pattern covering the full 10-bit range; 8 rows of
        // 8 samples (width a multiple of 4) so the flat-group form is the
        // per-row bitstream.
        let s: Vec<u16> = (0..64u32).map(|i| ((i * 8887) % 1024) as u16).collect();
        let mut packed = vec![0u8; 64 * 5 / 4];
        for (i, chunk) in s.chunks(4).enumerate() {
            let word = ((chunk[0] as u64) << 30)
                | ((chunk[1] as u64) << 20)
                | ((chunk[2] as u64) << 10)
                | chunk[3] as u64;
            packed[i * 5..i * 5 + 5].copy_from_slice(&word.to_be_bytes()[3..]);
        }
        let back = unpack10(&packed, 8, 8).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn unpack8_basic_odd_width_and_padding() {
        let packed = [1u8, 2, 3, 4, 5, 6, 99, 99];
        // 3×2 grid, odd width: all 6 samples, the 2 trailing bytes ignored
        let back = unpack8(&packed, 3, 2).unwrap();
        assert_eq!(back, vec![1, 2, 3, 4, 5, 6]);
        // 2×2 grid of the same buffer: exactly 4 samples
        assert_eq!(unpack8(&packed, 2, 2).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn unpack8_too_short_rejected() {
        let err = unpack8(&[1u8, 2], 2, 2).unwrap_err();
        assert!(matches!(err, PackError::TooShort { need: 4, .. }));
    }

    #[test]
    fn pack10_roundtrip_inverse_of_unpack10() {
        // deterministic pattern across the full 10-bit range; 8 rows of 8
        // samples (width a multiple of 4) — pack10 then unpack10 is the
        // identity, and the packed bytes match the unpack10 test vector.
        let s: Vec<u16> = (0..64u32).map(|i| ((i * 8887) % 1024) as u16).collect();
        let packed = pack10(&s, 8).unwrap();
        assert_eq!(packed.len(), 64 * 5 / 4);
        let back = unpack10(&packed, 8, 8).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn pack10_full_range_group() {
        // 0, 1, 511, 1023 → word 0x000017FFFF → [00 00 17 FF FF]
        // (the unpack10_full_range_and_padding_ignored vector, inverted).
        assert_eq!(pack10(&[0, 1, 511, 1023], 4).unwrap(), vec![0x00, 0x00, 0x17, 0xFF, 0xFF]);
    }

    #[test]
    fn pack10_rejects_bad_width_and_range() {
        assert!(matches!(
            pack10(&[0u16; 4], 2),
            Err(PackError::WidthNotMultipleOf4(2))
        ));
        assert!(matches!(
            pack10(&[0u16; 6], 4),
            Err(PackError::OddPixelCount(6))
        ));
        assert!(matches!(
            pack10(&[0u16, 0, 1024, 0], 4),
            Err(PackError::SampleOutOfRange { at: 2, value: 1024, max: 1023 })
        ));
    }

    #[test]
    fn pack8_roundtrip_and_range() {
        let s: Vec<u16> = (0..16u32).map(|i| ((i * 17) % 256) as u16).collect();
        let packed = pack8(&s).unwrap();
        assert_eq!(packed.len(), 16);
        assert_eq!(unpack8(&packed, 4, 4).unwrap(), s);
        // odd width is legal (no 2-sample grouping)
        assert_eq!(pack8(&[1, 2, 3]).unwrap(), vec![1, 2, 3]);
        assert!(matches!(
            pack8(&[0u16, 256]),
            Err(PackError::SampleOutOfRange { at: 1, value: 256, max: 255 })
        ));
    }

    #[test]
    fn real_a001_strip_golden() {
        let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let buf = match std::fs::read(p) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                return;
            }
        };
        let f = crate::tiff::read(&buf).unwrap();
        let packed = f.strip_slice(&buf);
        let s = unpack12(packed, f.width, f.height).unwrap();
        assert_eq!(s.len(), (f.width * f.height) as usize);
        // 12-bit contract: nothing above 4095 (structurally true).
        assert!(s.iter().all(|v| *v <= 4095));
        // Canary stats for this fixed testdata frame (measured,
        // cross-verified pixel-exact against LibRaw): min 253, max 881,
        // mean 271.452.
        let mn = s.iter().min().copied().unwrap_or(u16::MAX);
        let mx = s.iter().max().copied().unwrap_or(0);
        assert_eq!((mn, mx), (253, 881), "min/max drifted: ({mn}, {mx})");
        let mean: f64 = s.iter().map(|v| *v as f64).sum::<f64>() / s.len() as f64;
        assert!(
            (270.5..272.5).contains(&mean),
            "mean {mean} drifted from ~271.45"
        );
        // roundtrip through pack12
        let re = pack12(&s);
        assert_eq!(
            &re[..(f.width * f.height / 2 * 3) as usize],
            &packed[..(f.width * f.height / 2 * 3) as usize]
        );
    }
}
