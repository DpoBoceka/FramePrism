//! Verification — non-negotiable before calling the tool correct.
//!
//! 1. **Bit-exact (MVP gate):** unpack the input strip with
//!    `pack12::unpack12` (12-bit packed -> 16-bit samples) and decode the
//!    output JPEG with `codec::decode_lossless` (-> 16-bit samples);
//!    compare element-by-element. Any mismatch = hard fail. (The 16-bit
//!    comparison catches codec bugs; the packing contract is separately
//!    cross-checked against an independent decoder per release.)
//! 2. **Metadata:** the output header must equal the input header except the
//!    two patched tags (259, 279) — TimeCodes(51043), FrameRate(51044) and
//!    all Sigma private tags byte-identical by construction; asserted here.
//! 3. **NLE roundtrip (manual, every release):** load the sequence in
//!    the NLE — TC continuity, frame rate, waveform.
//! 4. **Independent cross-check (per release):** decode input + output with
//!    LibRaw/rawpy and compare.
//! 5. **Tile acceptance (G3):** the tile bit-exact gate is the
//!    GOLDEN-MODEL decode (`ljpeg_ref`, Rust port of tools/ljpeg_decode.py
//!    — standard T.81 per-MCU order), NOT the libjpeg self-roundtrip: the
//!    pixel-order bug (the pre-fix commit) passed the self-roundtrip on 100%
//!    of frames while LibRaw read 78% wrong pixels. The libjpeg decode
//!    remains a fast pre-check only.

use crate::tiff::{Frame, Meta};
use thiserror::Error;

/// Reconstruction error statistics for one log10 frame (12-bit input vs
/// LUT-inverted 10-bit codes): the log10 analog of the bit-exact gate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Log10Stats {
    /// Worst |recon - input| in 12-bit LSB (gated against
    /// `crate::log10::max_recon_error()`).
    pub max_err: u16,
    /// Mean |recon - input| in 12-bit LSB.
    pub mean_abs: f64,
    /// Fraction of samples within 1 LSB.
    pub pct_le_1: f64,
    /// Total samples compared.
    pub samples: u64,
}

/// Lossy (34892) reconstruction error statistics for one frame, in the
/// 8-bit domain: decoded 8-bit tiles vs the source downshifted `v12 >> 4`
/// (the 12→8 shift cancels, so this isolates the JPEG DCT error).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LossyStats {
    /// Mean absolute error (8-bit LSB, 0..255).
    pub mae: f64,
    /// Peak signal-to-noise ratio (dB), 8-bit domain (peak 255).
    pub psnr: f64,
    /// Worst absolute error (8-bit LSB).
    pub max_err: u8,
    /// Total samples compared.
    pub samples: u64,
}

/// Reference tag-7 (12-bit DCT parity tiles) reconstruction statistics for
/// one frame, in the 12-bit domain: the both-scan assembly
/// (`dct2s::assemble_frame` over our four tiles, curve applied) vs the
/// original 12-bit plane (phase B, the G2 pixel-gate numbers).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReferenceDctStats {
    /// Mean absolute error (12-bit LSB, 0..4095).
    pub mae: f64,
    /// Worst absolute error (12-bit LSB).
    pub max_abs: u32,
    /// The DQT table scale actually used (1.0 = the measured preset table
    /// verbatim; CBR modes binary-search this per frame).
    pub table_scale: f64,
    /// Total samples compared.
    pub samples: u64,
    /// The per-frame MAE ratio r = our_MAE / reference_MAE (with --reference-mae-
    /// tsv). Used by the per-PRESET distribution gate (G2, );
    /// None when the measured MAE is unavailable.
    pub mae_ratio: Option<f64>,
}

#[derive(Error, Debug, Clone, PartialEq)]
pub enum VerifyError {
    #[error("decoded output dimensions {dw}x{dh} != input {w}x{h}")]
    DimMismatch { w: u32, h: u32, dw: u32, dh: u32 },
    #[error(
        "bit-exact mismatch: first differing sample at index {index} (in={a}, out={b}) of {n}"
    )]
    BitMismatch {
        index: usize,
        a: u16,
        b: u16,
        n: usize,
    },
    #[error("log10 reconstruction error {max_err} LSB exceeds the curve bound {bound} LSB")]
    Log10ErrorBound { max_err: u16, bound: u16 },
    #[error("lossy MAE {mae:.2} > 128 sanity bound (PSNR {psnr:.1} dB); codec pair broken")]
    LossySanity { mae: f64, psnr: f64 },
    #[error("tile ({r},{c}) bit-exact mismatch: first differing sample at index {index} (in={a}, out={b})")]
    TileBitMismatch {
        r: u32,
        c: u32,
        index: usize,
        a: u16,
        b: u16,
    },
    #[error("header not preserved: {n} unexpected byte difference(s); first at offset {first}")]
    HeaderDiff { n: usize, first: u64 },
    #[error("output length {0} != strip_offset + jpeg length {1}")]
    OutputLengthWrong(usize, usize),
    #[error("unpack input strip failed: {0}")]
    UnpackInput(#[from] crate::pack12::PackError),
    #[error("decode output jpeg failed: {0}")]
    DecodeOutput(#[from] crate::codec::CodecError),
    #[error("lossy tile decode failed: {0}")]
    LossyDecode(#[from] crate::lossy::LossyError),
    #[error("tile encode/decode failed: {0}")]
    TileCodec(#[from] crate::tileenc::TileError),
    #[error("parse tiled output failed: {0}")]
    ParseOutput(#[from] crate::tiff::ParseError),
    #[error("endianness changed: input {0:?}, output {1:?}")]
    EndianChanged(crate::tiff::Endian, crate::tiff::Endian),
    #[error("output IFD0 is missing tag {tag} (0x{tag:04X})")]
    TagMissing { tag: u16 },
    #[error("output IFD0 unexpectedly has tag {tag} (0x{tag:04X})")]
    TagUnexpected { tag: u16 },
    #[error("tag {tag} (0x{tag:04X}) differs: type {ityp}->{otyp}, count {icount}->{ocount}")]
    TagTypeChanged {
        tag: u16,
        ityp: u16,
        otyp: u16,
        icount: u32,
        ocount: u32,
    },
    #[error("tag {tag} (0x{tag:04X}) value bytes differ (input {ilen} B, output {olen} B)")]
    TagValueDiffers { tag: u16, ilen: usize, olen: usize },
    #[error("tile tag {tag} (0x{tag:04X}) value wrong: expected {expected:?}, got {got:?}")]
    TileTagValueWrong {
        tag: u16,
        expected: Vec<u8>,
        got: Vec<u8>,
    },
}

/// Decode `jpeg` and compare against the unpacked input plane (bit-exact).
pub fn bit_exact(frame: &Frame, src: &[u8], jpeg: &[u8]) -> Result<(), VerifyError> {
    let packed = frame.strip_slice(src);
    let in_samples = crate::pack12::unpack12(packed, frame.width, frame.height)?;
    let (out_samples, dw, dh) = crate::codec::decode_lossless(jpeg, frame.bits_per_sample as u8)?;
    if (dw, dh) != (frame.width, frame.height) {
        return Err(VerifyError::DimMismatch {
            w: frame.width,
            h: frame.height,
            dw,
            dh,
        });
    }
    for (i, (a, b)) in in_samples.iter().zip(out_samples.iter()).enumerate() {
        if a != b {
            return Err(VerifyError::BitMismatch {
                index: i,
                a: *a,
                b: *b,
                n: in_samples.len(),
            });
        }
    }
    Ok(())
}

/// Assert `out` equals `src` byte-for-byte over the preserved header, with
/// differences allowed ONLY at the two patched tag values.
pub fn metadata_preserved(src: &[u8], out: &[u8], frame: &Frame) -> Result<(), VerifyError> {
    let so = frame.strip_offset as usize;
    if out.len() < so {
        return Err(VerifyError::OutputLengthWrong(out.len(), so));
    }
    let cvo = frame.compression_value_offset as usize;
    let sco = frame.strip_count_value_offset as usize;
    let mut diffs = 0usize;
    let mut first: Option<u64> = None;
    for i in 0..so {
        if src[i] == out[i] {
            continue;
        }
        if i == cvo || i == cvo + 1 || (i >= sco && i < sco + 4) {
            continue; // the two patched tags
        }
        diffs += 1;
        if first.is_none() {
            first = Some(i as u64);
        }
    }
    if diffs > 0 {
        return Err(VerifyError::HeaderDiff {
            n: diffs,
            first: first.unwrap_or(0),
        });
    }
    Ok(())
}

// ------------------------------------------------------------------ tile

/// Tile-mode bit-exact gate: decode every tile and reassemble the mosaic
/// in tile order, compare against the unpacked 12-bit source
/// sample-by-sample (the 12-bit gate; `expected_precision` 12). Two-stage
/// by design (G3):
/// 1. libjpeg self-roundtrip — FAST pre-CHECK ONLY (it shared the
///    pre-fix pixel-order mis-interpretation and cannot gate);
///   2. golden-model decode (`ljpeg_ref`, standard T.81 per-MCU order) —
///      the ACCEPTANCE gate; an independent cross-check (rawpy/LibRaw)
///      runs per release on top.
pub fn bit_exact_tiled(
    frame: &Frame,
    src: &[u8],
    grid: &crate::tileenc::Grid,
    tiles: &[Vec<u8>],
) -> Result<(), VerifyError> {
    let packed = frame.strip_slice(src);
    let in_samples = crate::pack12::unpack12(packed, frame.width, frame.height)?;
    bit_exact_tiled_plane(&in_samples, frame.width, frame.height, grid, tiles, 12)
}

/// Tile-mode bit-exact gate core over an ALREADY-UNPACKED reference plane
/// (review: the worker passes its own unpacked plane, so `--verify`
/// no longer unpacks the strip a second time). `expected_precision` = the
/// tile streams' SOF3 data precision (12 = lossless / 12-bit source,
/// 10 = log10 codes, 8 = native 8-bit lossless). Two-stage by design
/// (G3):
/// 1. libjpeg self-roundtrip — FAST pre-CHECK ONLY (it shared the
///    pre-fix pixel-order mis-interpretation and cannot gate);
///   2. golden-model decode (`ljpeg_ref`, standard T.81 per-MCU order) —
///      the ACCEPTANCE gate; an independent cross-check (rawpy/LibRaw)
///      runs per release on top.
pub fn bit_exact_tiled_plane(
    in_samples: &[u16],
    w: u32,
    h: u32,
    grid: &crate::tileenc::Grid,
    tiles: &[Vec<u8>],
    expected_precision: u32,
) -> Result<(), VerifyError> {
    if tiles.len() != (grid.cols * grid.rows) as usize {
        return Err(VerifyError::DimMismatch {
            w,
            h,
            dw: grid.cols * grid.rows,
            dh: 0,
        });
    }
    for r in 0..grid.rows {
        for c in 0..grid.cols {
            let i = (r * grid.cols + c) as usize;
            let rect =
                crate::tileenc::tile_region(w, h, grid, r, c).map_err(VerifyError::TileCodec)?;
            // Stage 1: fast libjpeg pre-check (NOT the acceptance gate).
            let _ =
                crate::tileenc::decode_tile_ljpeg(&tiles[i], &rect, expected_precision, grid.th)?;
            // Stage 2: golden-model (standard T.81 order) decode — GATE.
            let back = crate::tileenc::decode_tile(&tiles[i], &rect, expected_precision, grid.th)?;
            let base = (rect.y0 as usize) * w as usize + rect.x0 as usize;
            for y in 0..rect.tl as usize {
                for x in 0..rect.tw as usize {
                    let src_i = base + y * w as usize + x;
                    let a = in_samples[src_i];
                    let b = back[y * rect.tw as usize + x];
                    if a != b {
                        return Err(VerifyError::TileBitMismatch {
                            r,
                            c,
                            index: y * rect.tw as usize + x,
                            a,
                            b,
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

/// Log10 tile-mode CONTENT gate (the log10 analog of `bit_exact_tiled`):
/// decode every tile (10-bit lossless codes, golden-model acceptance path,
/// plus the libjpeg pre-check), reassemble the mosaic, invert each code with the
/// `log10` LUT (L(c) = the 12-bit linear value the code represents), and
/// compare against the unpacked 12-bit source sample-by-sample WITH
/// TOLERANCE — the log10 mode is quantizing by design (that is the whole
/// point: 10 codes carry 12 bits' worth of a dark scene). The hard bound
/// is the curve's full-range worst case (`log10::max_recon_error()` = 4
/// LSB for the 2-octave curve); on A001 the measured worst case is 2 LSB
/// Returns the frame's error
/// stats (max / mean / fraction-within-1-LSB) for the report.
pub fn log10_content_tiled(
    frame: &Frame,
    src: &[u8],
    grid: &crate::tileenc::Grid,
    tiles: &[Vec<u8>],
) -> Result<Log10Stats, VerifyError> {
    let packed = frame.strip_slice(src);
    let in_samples = crate::pack12::unpack12(packed, frame.width, frame.height)?;
    log10_content_tiled_plane(&in_samples, frame.width, frame.height, grid, tiles)
}

/// Log10 CONTENT gate core over an ALREADY-UNPACKED 12-bit reference plane — see
/// `log10_content_tiled` for the contract.
pub fn log10_content_tiled_plane(
    in_samples: &[u16],
    w: u32,
    h: u32,
    grid: &crate::tileenc::Grid,
    tiles: &[Vec<u8>],
) -> Result<Log10Stats, VerifyError> {
    if tiles.len() != (grid.cols * grid.rows) as usize {
        return Err(VerifyError::DimMismatch {
            w,
            h,
            dw: grid.cols * grid.rows,
            dh: 0,
        });
    }
    let bound = crate::log10::max_recon_error();
    let lut = crate::log10::lut();
    let mut max_err = 0u16;
    let mut sum_abs: u64 = 0;
    let mut le_1: u64 = 0;
    let mut n: u64 = 0;
    for r in 0..grid.rows {
        for c in 0..grid.cols {
            let i = (r * grid.cols + c) as usize;
            let rect =
                crate::tileenc::tile_region(w, h, grid, r, c).map_err(VerifyError::TileCodec)?;
            // Stage 1: fast libjpeg pre-check (NOT the acceptance gate).
            let _ = crate::tileenc::decode_tile_ljpeg(&tiles[i], &rect, 10, grid.th)?;
            // Stage 2: golden-model (standard T.81 order) decode — GATE.
            let codes = crate::tileenc::decode_tile(&tiles[i], &rect, 10, grid.th)?;
            let base = (rect.y0 as usize) * w as usize + rect.x0 as usize;
            for y in 0..rect.tl as usize {
                for x in 0..rect.tw as usize {
                    let code = codes[y * rect.tw as usize + x];
                    let recon = lut[code as usize] as i32;
                    let a = in_samples[base + y * w as usize + x] as i32;
                    let err = (recon - a).unsigned_abs() as u16;
                    if err > max_err {
                        max_err = err;
                    }
                    sum_abs += err as u64;
                    if err <= 1 {
                        le_1 += 1;
                    }
                    n += 1;
                }
            }
        }
    }
    if max_err > bound {
        return Err(VerifyError::Log10ErrorBound { max_err, bound });
    }
    Ok(Log10Stats {
        max_err,
        mean_abs: sum_abs as f64 / n as f64,
        pct_le_1: le_1 as f64 / n as f64 * 100.0,
        samples: n,
    })
}

/// Shared lossy (34892) content comparison: decode every 8-bit
/// baseline-DCT tile (via `crate::lossy::decode_tile8_rected`, which
/// enforces SOF dims == tile region + 1 component), reassemble the
/// mosaic, and compute MAE + PSNR vs the 8-bit reference plane `ref8`
/// (`ref_w` × `ref_h`, row-major) in the tile grid `grid`. Lossy by design,
/// so no hard error bound — but the decode/geometry enforcement catches
/// codec-pair bugs, and a sanity bound (MAE < 128) guards against a grossly
/// broken codec (random error averages ~128).
/// Public (review: the worker passes its own downshifted 8-bit
/// plane, so `--verify` no longer unpacks the strip a second time).
pub fn lossy_stats_from_ref(
    ref8: &[u8],
    ref_w: u32,
    ref_h: u32,
    grid: &crate::tileenc::Grid,
    tiles: &[Vec<u8>],
) -> Result<LossyStats, VerifyError> {
    if tiles.len() != (grid.cols * grid.rows) as usize {
        return Err(VerifyError::DimMismatch {
            w: ref_w,
            h: ref_h,
            dw: grid.cols * grid.rows,
            dh: 0,
        });
    }
    let mut sum_abs: u64 = 0;
    let mut sum_sq: f64 = 0.0;
    let mut max_err = 0u8;
    let mut n: u64 = 0;
    for r in 0..grid.rows {
        for c in 0..grid.cols {
            let i = (r * grid.cols + c) as usize;
            let rect = crate::tileenc::tile_region(ref_w, ref_h, grid, r, c)
                .map_err(VerifyError::TileCodec)?;
            let back = crate::lossy::decode_tile8_rected(&tiles[i], &rect)?;
            let base = (rect.y0 as usize) * ref_w as usize + rect.x0 as usize;
            for y in 0..rect.tl as usize {
                for x in 0..rect.tw as usize {
                    let s = base + y * ref_w as usize + x;
                    let a = ref8[s] as i32;
                    let b = back[y * rect.tw as usize + x] as i32;
                    let err = (a - b).abs();
                    let e8 = err as u8;
                    if (err as u8) > max_err {
                        max_err = e8;
                    }
                    sum_abs += err as u64;
                    sum_sq += (err as f64) * (err as f64);
                    n += 1;
                }
            }
        }
    }
    if n == 0 {
        return Err(VerifyError::DimMismatch {
            w: ref_w,
            h: ref_h,
            dw: 0,
            dh: 0,
        });
    }
    let mae = sum_abs as f64 / n as f64;
    let mse = sum_sq / n as f64;
    let psnr = if mse == 0.0 {
        f64::INFINITY
    } else {
        10.0 * ((255.0 * 255.0) / mse).log10()
    };
    if mae > 128.0 {
        return Err(VerifyError::LossySanity { mae, psnr });
    }
    Ok(LossyStats {
        mae,
        psnr,
        max_err,
        samples: n,
    })
}

/// Lossy (34892) tiled content gate (full resolution): reference
/// = the source downshifted `v12 >> 4` (the 12→8 shift cancels, isolating
/// the DCT error).
pub fn lossy_content_tiled(
    frame: &Frame,
    src: &[u8],
    grid: &crate::tileenc::Grid,
    tiles: &[Vec<u8>],
) -> Result<LossyStats, VerifyError> {
    let packed = frame.strip_slice(src);
    let in12 = crate::pack12::unpack12(packed, frame.width, frame.height)?;
    let ref8: Vec<u8> = in12.iter().map(|v| (*v >> 4) as u8).collect();
    lossy_stats_from_ref(&ref8, frame.width, frame.height, grid, tiles)
}

/// Lossy (34892) tiled content gate for the downscale2x combination
/// (× 0.2): reference = the 2×-decimated plane downshifted
/// `v12 >> 4` (8-bit), compared over the half-resolution tile grid.
pub fn lossy_content_downscale_tiled(
    frame: &Frame,
    src: &[u8],
    grid: &crate::tileenc::Grid,
    tiles: &[Vec<u8>],
) -> Result<LossyStats, VerifyError> {
    let packed = frame.strip_slice(src);
    let full = crate::pack12::unpack12(packed, frame.width, frame.height)?;
    let rule = crate::downscale::decimation_rule(src, frame);
    let (half, hw, hh) = crate::downscale::decimate2x(&full, frame.width, frame.height, rule);
    let ref8: Vec<u8> = half.iter().map(|v| (*v >> 4) as u8).collect();
    lossy_stats_from_ref(&ref8, hw, hh, grid, tiles)
}

/// Downscale2x + lossless CONTENT gate: unpack the FULL-
/// resolution strip, decimate 2× with the frame's CFA decimation rule
/// (`crate::downscale::decimation_rule` + `decimate2x` — reference staircase
/// for the fp's symmetric pattern, phase-exact otherwise), and compare
/// BIT-EXACT against the golden-model decode of the half-resolution tiles
/// (12-bit precision, 16-tile grid for A001). The decimated plane is the
/// reference — the downscale is lossless by construction (pure pixel
/// selection), so any mismatch is an encoder/surgery bug.
pub fn bit_exact_downscale_tiled(
    frame: &Frame,
    src: &[u8],
    grid: &crate::tileenc::Grid,
    tiles: &[Vec<u8>],
) -> Result<(), VerifyError> {
    let packed = frame.strip_slice(src);
    let full = crate::pack12::unpack12(packed, frame.width, frame.height)?;
    let rule = crate::downscale::decimation_rule(src, frame);
    let (half, hw, hh) = crate::downscale::decimate2x(&full, frame.width, frame.height, rule);
    bit_exact_tiled_plane(&half, hw, hh, grid, tiles, 12)
}

/// Downscale2x + log10 CONTENT gate: as `bit_exact_downscale_
/// tiled` but the tiles carry 10-bit LOG codes — invert each code with the
/// `log10` LUT and compare against the decimated 12-bit plane WITH
/// TOLERANCE (hard bound `log10::max_recon_error()`; on A001 the measured
/// full-res worst case is 2 LSB). Returns the frame's error stats.
pub fn log10_content_downscale_tiled(
    frame: &Frame,
    src: &[u8],
    grid: &crate::tileenc::Grid,
    tiles: &[Vec<u8>],
) -> Result<Log10Stats, VerifyError> {
    let packed = frame.strip_slice(src);
    let full = crate::pack12::unpack12(packed, frame.width, frame.height)?;
    let rule = crate::downscale::decimation_rule(src, frame);
    let (half, hw, hh) = crate::downscale::decimate2x(&full, frame.width, frame.height, rule);
    log10_content_tiled_plane(&half, hw, hh, grid, tiles)
}

/// Tile-mode metadata gate (position-independent content comparison — the
/// tile output's IFD table grew by one entry and its out-of-line data
/// shifted by 12 bytes, so a byte-position diff like strip mode is not
/// meaningful). Expected tag-level delta: {259: 1->7, 273/278/279: dropped,
/// 322/323/324/325: added}. Everything else — including every sub-IFD tag —
/// must match byte-for-byte in type, count and value.
pub fn metadata_preserved_tiled(
    src: &[u8],
    out: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
) -> Result<(), VerifyError> {
    metadata_preserved_tiled_impl(src, out, frame, tiles, BpsArm::Keep, false, false, false, None)
}

/// Log10 tile-mode metadata gate: the tile gate plus the 10-bit log
/// expected-diff set: {259: 1->7, 258: 12->10, 273/278/279: dropped,
/// 322/323/324/325: added, 50712: added (SHORT count 1024, value = the
/// log10 LUT)}. WhiteLevel (50717) and BlackLevel (50714) must be
/// UNCHANGED (they are linear-domain tags applied after the LUT).
pub fn metadata_preserved_tiled_log10(
    src: &[u8],
    out: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
) -> Result<(), VerifyError> {
    metadata_preserved_tiled_impl(src, out, frame, tiles, BpsArm::TwelveToTen, true, false, false, None)
}

/// Lossy tile-mode metadata gate (34892/LinearRaw/8-bit). Expected
/// tag-level delta: {259: 1->34892, 258: 12->8, 262: 32803->34892,
/// 273/278/279: dropped, 50721/50722 ColorMatrix: dropped, 322/323/324/325:
/// added, 50712: added (SHORT count 256, value = the lossy LUT), 51111:
/// added (BYTE count 16, value = recomputed NewRawImageDigest)}. CFA tags
/// (33421/33422/50711) and BlackLevel (50713/50714) and WhiteLevel (50717)
/// must be UNCHANGED (kept byte-identical — the task decision). Everything
/// else must match byte-for-byte.
pub fn metadata_preserved_tiled_lossy(
    src: &[u8],
    out: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
) -> Result<(), VerifyError> {
    metadata_preserved_tiled_impl(src, out, frame, tiles, BpsArm::TwelveToEight, false, false, true, None)
}

/// Downscale2x + lossless tile-mode metadata gate . Expected
/// tag-level delta: {256: W/2, 257: H/2, 259: 1->7, 273/278/279: dropped,
/// 322/323/324/325: added, 50719: source/2 elementwise, 50720:
/// each/2, 50829: each/2, 51089/51090/51091: added = the source 50720
/// value verbatim}. Everything else must match byte-for-byte (see
/// surgery.rs module docs for the rationale of every patched/inserted
/// tag).
pub fn metadata_preserved_tiled_downscale(
    src: &[u8],
    out: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
) -> Result<(), VerifyError> {
    metadata_preserved_tiled_impl(src, out, frame, tiles, BpsArm::Keep, false, true, false, None)
}

/// Downscale2x + log10 tile-mode metadata gate: the
/// downscale2x set plus the log10 set {258: 12->10, 50712: added}.
pub fn metadata_preserved_tiled_downscale_log10(
    src: &[u8],
    out: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
) -> Result<(), VerifyError> {
    metadata_preserved_tiled_impl(src, out, frame, tiles, BpsArm::TwelveToTen, true, true, false, None)
}

/// Downscale2x + lossy tile-mode metadata gate (× ): the
/// downscale2x set plus the lossy set {259: 1->34892, 258: 12->8, 262:
/// 32803->34892, 50721/50722 dropped, 50712 added, 51111 added}.
pub fn metadata_preserved_tiled_downscale_lossy(
    src: &[u8],
    out: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
) -> Result<(), VerifyError> {
    metadata_preserved_tiled_impl(
        src,
        out,
        frame,
        tiles,
        BpsArm::TwelveToEight,
        false,
        true,
        true,
        None,
    )
}

/// Tag-7 (12-bit DCT parity tiles) metadata gate (phase
/// B). Expected tag-level delta: {259: 1→7, 273/278/279: dropped,
/// 322/323/324/325: added (322 = 1928, 323 = 1088 — the 2×2 parity-tile
/// grid), 50712: added (SHORT count 4096, value = the corpus curve bytes
/// the encoder wrote — byte-copied from the reference when given,
/// the embedded A001 constant otherwise)}. BitsPerSample (258 = 12),
/// Photometric (262 = 32803 CFA), the ColorMatrix (50721/50722) and
/// DNGBackwardVersion (50707) must be UNCHANGED — the tag-7 lossy keeps
/// the CFA photometric and needs no version floor (compression 7). No
/// NewRawImageDigest (51111). Everything else matches byte-for-byte.
pub fn metadata_preserved_tiled_reference_dct(
    src: &[u8],
    out: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
    curve: &[u8],
) -> Result<(), VerifyError> {
    metadata_preserved_tiled_impl(src, out, frame, tiles, BpsArm::Keep, false, false, false, Some(curve))
}

/// Log10 tile-mode metadata gate for the @8 identity-promotion arm (the
/// measured FHD mode row — 1936×1090 @8 log10): the
/// log10 expected-diff set MINUS the 50712 add (the source's native
/// 256-entry 50712 is CARRIED as-is — the generic value-equality check;
/// the surgery never adds a second 50712) PLUS the @8 BPS split
/// {258: 8→10} (the mode tier's measured BPS10 container — the identity
/// promotion; the lossless tier's no-promotion decision is scoped to the
/// lossless tier): {259: 1→7, 258: 8→10, 273/278/279: dropped, 322/323/
/// 324/325: added}. WhiteLevel (50717) / BlackLevel (50714) must be
/// unchanged.
pub fn metadata_preserved_tiled_log10_promoted(
    src: &[u8],
    out: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
) -> Result<(), VerifyError> {
    metadata_preserved_tiled_impl(
        src,
        out,
        frame,
        tiles,
        BpsArm::EightToTen,
        false,
        false,
        false,
        None,
    )
}

/// Downscale2x tile-mode metadata gate for the @8 identity-promotion arm
/// (the measured FHD mode row — 968×545 ds2x of a
/// 1936×1090 @8 frame): the downscale2x set PLUS the @8 BPS split
/// {258: 8→10} (the mode tier's measured BPS10 container — the identity
/// promotion) — NO 50712 add (the source's native 256-entry table is
/// CARRIED as-is): {256/257: halved, 259: 1→7, 258: 8→10, 273/278/279:
/// dropped, 322/323/324/325: added, 51089/51090/51091: added (the source
/// 50720 verbatim), 50719/50720/50829: halved}.
pub fn metadata_preserved_tiled_downscale_promoted(
    src: &[u8],
    out: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
) -> Result<(), VerifyError> {
    metadata_preserved_tiled_impl(
        src,
        out,
        frame,
        tiles,
        BpsArm::EightToTen,
        false,
        true,
        false,
        None,
    )
}

/// The per-arm BitsPerSample (258) expected diff — the measured per-
/// (mode × depth) contract (FHD mode rows add the
/// @8 identity-promotion arm): the mode tiers store 8-bit content in the
/// measured BPS10 container (258 8→10); the lossless tier's @8 rows keep
/// the input depth (the no-promotion decision — the tier scope)
/// and ride `Keep`.
enum BpsArm {
    /// 258 unchanged (the lossless tier's rows — incl. the FHD mode @10
    /// raw-passthrough + the ds2x @12/@10 rows — and every legacy
    /// geometry).
    Keep,
    /// 258 12→10 (the 10-bit container — the log10 @12 arm).
    TwelveToTen,
    /// 258 12→8 (the lossy tier).
    TwelveToEight,
    /// 258 8→10 (the mode tiers' @8 identity promotion — the log10 @8 +
    /// ds2x @8 rows; the sample values unchanged, repacked at BPS10).
    EightToTen,
}

fn metadata_preserved_tiled_impl(
    src: &[u8],
    out: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
    bps: BpsArm,
    lut_add: bool,
    ds2x: bool,
    lossy: bool,
    reference_dct_curve: Option<&[u8]>,
) -> Result<(), VerifyError> {
    let m_src = crate::tiff::read_meta(src)?;
    let m_out = crate::tiff::read_meta(out)?;
    if m_src.endianness != m_out.endianness {
        return Err(VerifyError::EndianChanged(
            m_src.endianness,
            m_out.endianness,
        ));
    }
    let e = m_out.endianness;
    let base_drop: [u16; 3] = [273, 278, 279];
    // Lossy additionally drops the ColorMatrix (50721/50722) so fColorPlanes
    // becomes 1 (SamplesPerPixel 1 valid for LinearRaw).
    let drop: Vec<u16> = if lossy {
        base_drop
            .iter()
            .copied()
            .chain([50721, 50722].iter().copied())
            .collect()
    } else {
        base_drop.to_vec()
    };
    let add: [u16; 4] = [322, 323, 324, 325];
    let add_extra: [u16; 1] = [crate::surgery::LUT_TAG]; // 50712, log10 + lossy
    let add_digest: [u16; 1] = [crate::surgery::DIGEST_TAG]; // 51111, lossy only
    let proxy: [u16; 3] = crate::surgery::PROXY_TAGS; // 51089-91, downscale2x

    fn value_of(
        _m: &Meta,
        _e: crate::tiff::Endian,
        buf: &[u8],
        en: &crate::tiff::IfdEntry,
    ) -> Vec<u8> {
        // TIFF C14 type sizes (review: the old map fell through to
        // tsz=1 for 13/14/17/18 and mis-sized 12/15): 12 IFD = 4, 13 IFD8 /
        // 14 SLOFFSET / 15 DOUBLE / 16 LONG8 / 17 SLONG8 = 8, 18 RATIONAL8 = 16.
        let tsz = match en.typ {
            1 | 2 | 7 | 11 => 1,
            3 | 8 => 2,
            4 | 9 | 12 => 4,
            5 | 10 | 13 | 14 | 15 | 16 | 17 => 8,
            18 => 16,
            _ => 1, // unknown: compare the raw 4-byte field only
        };
        let sz = tsz * en.count as u64;
        if sz <= 4 {
            en.value_raw[..tsz as usize * en.count as usize].to_vec()
        } else {
            let (p, end) = en
                .out_of_line
                .expect("out-of-line entry must have a pointer");
            let _ = end;
            buf[p as usize..p as usize + sz as usize].to_vec()
        }
    }

    // LONG values of a value byte slice, file endianness.
    let u32s_of = |buf: &[u8]| -> Vec<u32> { buf.chunks_exact(4).map(|c| e.u32(c)).collect() };

    // --- IFD0 -------------------------------------------------------------
    let src_tags: std::collections::BTreeSet<u16> =
        m_src.ifd0.entries.iter().map(|en| en.tag).collect();
    let out_tags: std::collections::BTreeSet<u16> =
        m_out.ifd0.entries.iter().map(|en| en.tag).collect();
    let mut expect_tags: std::collections::BTreeSet<u16> = src_tags
        .iter()
        .copied()
        .filter(|t| !drop.contains(t))
        .chain(add.iter().copied())
        .collect();
    // The 50712 add is the log10 @12 ARM's expected diff (the LUT ADD —
    // `lut_add`); the @8 arm's native 256-entry table is CARRIED (the
    // generic value-equality check covers it) and the @10 raw arm adds
 // none — measured 50712 mechanics per arm.
    if lut_add || lossy || reference_dct_curve.is_some() {
        expect_tags.insert(add_extra[0]);
    }
    if lossy {
        expect_tags.extend(add_digest.iter().copied());
    }
    if ds2x {
        expect_tags.extend(proxy.iter().copied());
    }
    for t in &expect_tags {
        if !out_tags.contains(t) {
            return Err(VerifyError::TagMissing { tag: *t });
        }
    }
    for t in &out_tags {
        if !expect_tags.contains(t) {
            return Err(VerifyError::TagUnexpected { tag: *t });
        }
    }
    for en in &m_out.ifd0.entries {
        let sen = m_src
            .ifd0
            .entries
            .iter()
            .find(|x| x.tag == en.tag)
            .filter(|x| !drop.contains(&x.tag));
        match sen {
            None => {
                // New tile tags: 322/323 exact values, 325 exact counts,
                // 324 = contiguous offsets ending exactly at EOF; 50712
                // (log10) = the exact LUT bytes; 51089/51090/51091
                // (downscale2x) = the source 50720 value verbatim.
                match en.tag {
                    50712 => {
                        // LinearizationTable: SHORT, count 1024 (log10),
                        // 256 (lossy) or 4096 (tag-7: the corpus
                        // curve, byte-copied by the encoder). Out-of-line
                        // value must equal the mode's exact bytes.
                        let (expected, want_count) = if lossy {
                            (crate::lossy::lut_bytes(), 256)
                        } else if let Some(c) = reference_dct_curve {
                            (c.to_vec(), 4096)
                        } else {
                            (crate::log10::lut_bytes(), 1024)
                        };
                        if en.typ != 3 || en.count != want_count {
                            return Err(VerifyError::TagTypeChanged {
                                tag: en.tag,
                                ityp: 3,
                                otyp: en.typ,
                                icount: want_count,
                                ocount: en.count,
                            });
                        }
                        let got = value_of(&m_out, e, out, en);
                        if got != expected {
                            return Err(VerifyError::TileTagValueWrong {
                                tag: en.tag,
                                expected: expected[..16].to_vec(),
                                got: got[..16.min(got.len())].to_vec(),
                            });
                        }
                    }
                    51111 => {
                        // NewRawImageDigest (lossy): BYTE count 16, out-of-
                        // line. Value must equal the recomputed MD5 of the
                        // per-tile MD5s in 324 (tile) order.
                        if !lossy {
                            return Err(VerifyError::TagUnexpected { tag: en.tag });
                        }
                        if en.typ != 1 || en.count != 16 {
                            return Err(VerifyError::TagTypeChanged {
                                tag: en.tag,
                                ityp: 1,
                                otyp: en.typ,
                                icount: 16,
                                ocount: en.count,
                            });
                        }
                        let got = value_of(&m_out, e, out, en);
                        let expected = crate::lossy::new_raw_image_digest(tiles);
                        if got != expected.to_vec() {
                            return Err(VerifyError::TileTagValueWrong {
                                tag: en.tag,
                                expected: expected.to_vec(),
                                got: got[..16.min(got.len())].to_vec(),
                            });
                        }
                    }
                    322 | 323 => {
                        // 482×272 (the 4×4/4×8 tile grids), 252×252 (the
                        // 3024×2010 Open Gate 3K measured grid — the
 // per-gate contract, ), 242×274 (the
                        // FHD @12/@8 grid) / 484×274 (the FHD @10 grid)
                        // (the per-(geometry × depth) contract — the
 // measured FHD grid) or
                        // 1928×1088 (the tag-7 2×2
                        // parity-tile grid).
                        let (want_w, want_l) = if reference_dct_curve.is_some() {
                            (1928u32, 1088u32)
                        } else if crate::tileenc::is_3k_gate(frame.width, frame.height) {
                            (252u32, 252u32)
                        } else {
                            // The native-depth path's source BPS is the
                            // encoded BPS (`bps_patch = None`) — the
                            // FHD gate derives its per-depth grid here;
                            // every other gate derives 482×272 (the
                            // byte-invariance pin).
                            crate::tileenc::gate_tile_dims_depth(
                                frame.width,
                                frame.height,
                                frame.bits_per_sample as u32,
                            )
                        };
                        let expected: Vec<u8> = if en.tag == 322 {
                            want_w.to_le_bytes().to_vec()
                        } else {
                            want_l.to_le_bytes().to_vec()
                        };
                        let got = value_of(&m_out, e, out, en);
                        if got != expected {
                            return Err(VerifyError::TileTagValueWrong {
                                tag: en.tag,
                                expected,
                                got,
                            });
                        }
                    }
                    325 => {
                        let mut expected = Vec::with_capacity(tiles.len() * 4);
                        for t in tiles {
                            expected.extend_from_slice(&(t.len() as u32).to_le_bytes());
                        }
                        let got = value_of(&m_out, e, out, en);
                        if got != expected {
                            return Err(VerifyError::TileTagValueWrong {
                                tag: en.tag,
                                expected,
                                got,
                            });
                        }
                    }
                    324 => {
                        let (p, _) = en.out_of_line.ok_or(VerifyError::TileTagValueWrong {
                            tag: 324,
                            expected: vec![],
                            got: vec![0],
                        })?;
                        let n = en.count as usize;
                        if n != tiles.len() {
                            return Err(VerifyError::TileTagValueWrong {
                                tag: 324,
                                expected: vec![],
                                got: (n as u32).to_le_bytes().to_vec(),
                            });
                        }
                        let mut prev = 0u64;
                        for i in 0..n {
                            let o = e.u32(&out[p as usize + i * 4..p as usize + i * 4 + 4]) as u64;
                            if o == 0 || o >= out.len() as u64 || (i > 0 && o <= prev) {
                                return Err(VerifyError::TileTagValueWrong {
                                    tag: 324,
                                    expected: vec![],
                                    got: o.to_le_bytes().to_vec(),
                                });
                            }
                            // strict contiguity — o[i] ==
                            // o[i-1] + len[i-1]. Impossible from the current
                            // assembly (tiles are appended back-to-back and
                            // the last ends at EOF), but a hypothetical
                            // mid-stream offset misplacement that preserved
                            // monotonicity + the EOF end would pass the loose
                            // check.
                            if i > 0 && o != prev + tiles[i - 1].len() as u64 {
                                return Err(VerifyError::TileTagValueWrong {
                                    tag: 324,
                                    expected: vec![],
                                    got: o.to_le_bytes().to_vec(),
                                });
                            }
                            prev = o;
                        }
                        // Last tile must end exactly at EOF.
                        let last_o = e
                            .u32(&out[p as usize + (n - 1) * 4..p as usize + (n - 1) * 4 + 4])
                            as u64;
                        if last_o + tiles[n - 1].len() as u64 != out.len() as u64 {
                            return Err(VerifyError::TileTagValueWrong {
                                tag: 324,
                                expected: vec![],
                                got: last_o.to_le_bytes().to_vec(),
                            });
                        }
                    }
                    51089..=51091 => {
                        // Proxy signalling (downscale2x): LONG count 2,
                        // out-of-line, value = the source's 50720
                        // (DefaultCropSize) verbatim — the original's
                        // default final size (× DefaultScale, absent ⇒ 1.0).
                        if !ds2x {
                            return Err(VerifyError::TagUnexpected { tag: en.tag });
                        }
                        if en.typ != 4 || en.count != 2 {
                            return Err(VerifyError::TagTypeChanged {
                                tag: en.tag,
                                ityp: 4,
                                otyp: en.typ,
                                icount: 2,
                                ocount: en.count,
                            });
                        }
                        let src_crop = m_src
                            .ifd0
                            .entries
                            .iter()
                            .find(|x| x.tag == 50720)
                            .ok_or(VerifyError::TagMissing { tag: 50720 })?;
                        let got = value_of(&m_out, e, out, en);
                        let expected = value_of(&m_src, e, src, src_crop);
                        if got != expected {
                            return Err(VerifyError::TileTagValueWrong {
                                tag: en.tag,
                                expected,
                                got,
                            });
                        }
                    }
                    _ => {
                        return Err(VerifyError::TagUnexpected { tag: en.tag });
                    }
                }
            }
            Some(x) => {
                if x.typ != en.typ || x.count != en.count {
                    return Err(VerifyError::TagTypeChanged {
                        tag: en.tag,
                        ityp: x.typ,
                        otyp: en.typ,
                        icount: x.count,
                        ocount: en.count,
                    });
                }
                if en.tag == 259 {
                    // Compression: 1 -> 7 (lossless/log10) or 1 -> 34892
                    // (lossy), in-line SHORT.
                    let want = if lossy { 34892u16 } else { 7 };
                    let got = e.u16(&en.value_raw);
                    if got != want {
                        return Err(VerifyError::TileTagValueWrong {
                            tag: 259,
                            expected: want.to_le_bytes().to_vec(),
                            got: en.value_raw[..2].to_vec(),
                        });
                    }
                    continue;
                }
                if en.tag == 258
                    && matches!(
                        bps,
                        BpsArm::TwelveToTen | BpsArm::TwelveToEight | BpsArm::EightToTen
                    )
                {
                    // BitsPerSample: 12 -> 10 (the log10 @12 arm), 12 -> 8
                    // (lossy) or 8 -> 10 (the mode tiers' @8 identity
 // promotion — FHD mode rows),
                    // in-line SHORT.
                    let (src_want, want) = match bps {
                        BpsArm::TwelveToTen => (12u16, 10u16),
                        BpsArm::TwelveToEight => (12u16, 8u16),
                        BpsArm::EightToTen => (8u16, 10u16),
                        BpsArm::Keep => unreachable!("the 258 arm check is Keep-excluded"),
                    };
                    let src_v = e.u16(&x.value_raw);
                    let got = e.u16(&en.value_raw);
                    if src_v != src_want || got != want {
                        return Err(VerifyError::TileTagValueWrong {
                            tag: 258,
                            expected: want.to_le_bytes().to_vec(),
                            got: en.value_raw[..2].to_vec(),
                        });
                    }
                    continue;
                }
                if en.tag == 262 && lossy {
                    // PhotometricInterpretation: 32803 (CFA) -> 34892
                    // (LinearRaw), in-line SHORT (lossy only).
                    let src_v = e.u16(&x.value_raw);
                    let got = e.u16(&en.value_raw);
                    if src_v != 32803 || got != 34892 {
                        return Err(VerifyError::TileTagValueWrong {
                            tag: 262,
                            expected: 34892u16.to_le_bytes().to_vec(),
                            got: en.value_raw[..2].to_vec(),
                        });
                    }
                    continue;
                }
                if ds2x && (en.tag == 256 || en.tag == 257) {
                    // ImageWidth/ImageLength: halved, in-line LONG.
                    let src_v = e.u32(&x.value_raw);
                    let got = e.u32(&en.value_raw);
                    if got != src_v / 2 {
                        return Err(VerifyError::TileTagValueWrong {
                            tag: en.tag,
                            expected: (src_v / 2).to_le_bytes().to_vec(),
                            got: en.value_raw.to_vec(),
                        });
                    }
                    continue;
                }
                if ds2x && matches!(en.tag, 50719 | 50720 | 50829) {
                    // Downscale2x crop/area tags (out-of-line LONG arrays):
                    // every element halved with an integer floor — 50720
                    // DefaultCropSize and 50829 ActiveArea (the half-
                    // resolution proxy geometry), and 50719 DefaultCropOrigin
                    // (the measured ds2x writes
                    // the elementwise floor of the source origin — (8,5) →
                    // (4,2) — not the spec default (0,0);
                    // the spec permits any origin within the crop).
                    // Type/count preserved by surgery (in-place patch).
                    let a = value_of(&m_src, e, src, x);
                    let src_vals = u32s_of(&a);
                    let expected_vals: Vec<u32> = src_vals.iter().map(|v| v / 2).collect();
                    let b = value_of(&m_out, e, out, en);
                    let got_vals = u32s_of(&b);
                    if got_vals != expected_vals {
                        return Err(VerifyError::TagValueDiffers {
                            tag: en.tag,
                            ilen: a.len(),
                            olen: b.len(),
                        });
                    }
                    continue;
                }
                if (lossy || ds2x) && en.tag == 50707 {
                    // DNGBackwardVersion (review: the lossy (34892)
                    // and ds2x (proxy tags) plans enforce ≥ 1.4.0.0 — the
                    // output must equal max(source, 0x01040000). A source
                    // already at/above the minimum (the fp frame) stays
                    // byte-identical, so this arm is an equality check then).
                    // Version values are fixed-order BYTE[4] (major,
                    // minor, tweak, bugfix) — the canonical 0x01040000 is
                    // the BIG-endian reading of the bytes, not a
                    // file-endian LONG.
                    let a = value_of(&m_src, e, src, x);
                    let b = value_of(&m_out, e, out, en);
                    if a.len() != 4 || b.len() != 4 {
                        return Err(VerifyError::TagValueDiffers {
                            tag: en.tag,
                            ilen: a.len(),
                            olen: b.len(),
                        });
                    }
                    let sv = u32::from_be_bytes(a.as_slice().try_into().unwrap());
                    let ov = u32::from_be_bytes(b.as_slice().try_into().unwrap());
                    if ov != sv.max(crate::surgery::BACKWARD_VERSION_MIN) {
                        return Err(VerifyError::TagValueDiffers {
                            tag: en.tag,
                            ilen: 4,
                            olen: 4,
                        });
                    }
                    continue;
                }
                if en.count == 1
                    && en.out_of_line.is_none()
                    && x.out_of_line.is_none()
                    && crate::tiff::is_ifd_pointer(en.typ, en.tag)
                {
                    // IFD pointer (the fp's 34665 ExifIFD, type 4 count 1):
                    // the surgical layout shifts the table by exactly the
                    // IFD growth (out − in entries × 12); the 3K re-layout
                    // (the measured packing rule) places it at the computed
                    // ExifIFD body offset of the OUTPUT's own tag-set
 // parameters (the generalization). The lossless
                    // arms (E∈{59,60} × N=96) reproduce the fixed variant
 // constants exactly (the : the
                    // 50712-carrying set → 0x6ee; the 50712-less set → 0x6e2);
                    // the mode arms ride the computed offset (the 24-tile /
                    // LUT-ADD / proxy-ADD layouts — never a hand constant).
                    // Derived from the OUTPUT's measured E / N / 50712 region
 // / proxy presence (the free-packing decision).
                    // 0 (no sub-IFD) stays 0.
                    let src_v = e.u32(&x.value_raw);
                    let got_v = e.u32(&en.value_raw);
                    let expected = if src_v == 0 {
                        0u32
                    } else if crate::tileenc::is_3k_gate(frame.width, frame.height) {
                        let e_out = m_out.ifd0.entries.len() as u16;
                        let n_tiles = m_out
                            .ifd0
                            .entries
                            .iter()
                            .find(|en| en.tag == 324)
                            .map(|en| en.count)
                            .unwrap_or(0);
                        let lut_region = m_out
                            .ifd0
                            .entries
                            .iter()
                            .find(|en| en.tag == crate::surgery::LUT_TAG)
                            .and_then(|en| en.out_of_line)
                            .map(|(p, end)| (end - p) as u32);
                        let n_proxy = crate::surgery::PROXY_TAGS
                            .iter()
                            .filter(|t| {
                                m_out.ifd0.entries.iter().any(|en| en.tag == **t)
                            })
                            .count() as u32;
                        crate::surgery::t3k_mode_exif_off(
                            e_out, n_tiles, lut_region, n_proxy,
                        )
                    } else {
                        let shift =
                            (m_out.ifd0.entries.len() as i64 - m_src.ifd0.entries.len() as i64) * 12;
                        src_v.wrapping_add(shift as u32)
                    };
                    if got_v != expected {
                        return Err(VerifyError::TagValueDiffers {
                            tag: en.tag,
                            ilen: 4,
                            olen: 4,
                        });
                    }
                    continue;
                }
                let a = value_of(&m_src, e, src, x);
                let b = value_of(&m_out, e, out, en);
                if a != b {
                    return Err(VerifyError::TagValueDiffers {
                        tag: en.tag,
                        ilen: a.len(),
                        olen: b.len(),
                    });
                }
            }
        }
    }

    // --- sub-IFDs (Exif/GPS/Interop): tag set + values identical ----------
    if m_src.sub_ifds.len() != m_out.sub_ifds.len() {
        return Err(VerifyError::TagUnexpected { tag: 34665 });
    }
    for (a, b) in m_src.sub_ifds.iter().zip(m_out.sub_ifds.iter()) {
        if a.entries.len() != b.entries.len() {
            return Err(VerifyError::TagUnexpected { tag: 34665 });
        }
        for (xen, yen) in a.entries.iter().zip(b.entries.iter()) {
            if xen.tag != yen.tag || xen.typ != yen.typ || xen.count != yen.count {
                return Err(VerifyError::TagTypeChanged {
                    tag: yen.tag,
                    ityp: xen.typ,
                    otyp: yen.typ,
                    icount: xen.count,
                    ocount: yen.count,
                });
            }
            let x = value_of(&m_src, e, src, xen);
            let y = value_of(&m_out, e, out, yen);
            if yen.tag == 37500 && crate::tileenc::is_3k_gate(frame.width, frame.height) {
                // The 3K SI7MA internal pointer patch (the measured
                // contract — `surgery::T3K_SI7MA_PTRS`): the 57 in-blob
                // 4-byte pointers each move by the blob's move delta
                // (output pointer − input pointer); every other byte is
                // byte-identical.
                let min_len =
                    *crate::surgery::T3K_SI7MA_PTRS.last().expect("non-empty") as usize + 4;
                let (sp, _) = xen.out_of_line.expect("37500 is out-of-line");
                let (op, _) = yen.out_of_line.expect("37500 is out-of-line");
                if x.len() < min_len || x.len() != y.len() {
                    return Err(VerifyError::TagValueDiffers {
                        tag: yen.tag,
                        ilen: x.len(),
                        olen: y.len(),
                    });
                }
                let delta = op.wrapping_sub(sp) as u32;
                let mut expected = x.clone();
                for &pos in crate::surgery::T3K_SI7MA_PTRS.iter() {
                    let p = pos as usize;
                    let v = e.u32(&expected[p..p + 4]).wrapping_add(delta);
                    e.put_u32(&mut expected[p..p + 4], 0, v);
                }
                if expected != y {
                    return Err(VerifyError::TagValueDiffers {
                        tag: yen.tag,
                        ilen: x.len(),
                        olen: y.len(),
                    });
                }
                continue;
            }
            if x != y {
                return Err(VerifyError::TagValueDiffers {
                    tag: yen.tag,
                    ilen: x.len(),
                    olen: y.len(),
                });
            }
        }
    }
    Ok(())
}
