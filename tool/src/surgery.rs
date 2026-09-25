//! Byte-level TIFF surgery: replace the raw strip with a lossless-JPEG
//! stream, patch two tags, truncate the tail.
//!
//! WHY SURGERY: rebuilding the DNG from a
//! parsed tag table risks losing tag order, Sigma private blocks, ExifIFD,
//! UMD. Surgery keeps the original bytes intact except for the data region,
//! so all metadata is preserved structurally.
//!
//! VERIFIED fp layout (clip A001_001):
//!   [0      ..  78,848)   header: IFD0 (58 tags) + ExifIFD + all metadata;
//!                         ALL 33 out-of-line regions + IFD structures
//!                         end <= 78,756 (< strip start)
//!   [78,848 .. 12,630,140) single uncompressed 12-bit strip (12,551,292 B)
//!   [12,630,140 .. end)    388 B zero tail
//!
//! The invariant is ENFORCED by `tiff::read` (frame is refused otherwise),
//! which makes the fp pass trivially safe:
//!   output = src[0..strip_offset) + jpeg
//!   patched in place (inside the copied header):
//! - tag 259 Compression: 1 (none) -> 7 (JPEG-lossless)
//!     - tag 279 StripByteCounts: old -> jpeg.len()
//!       tag 273 (StripOffsets) is UNCHANGED — the JPEG is written at the same
//!       file offset, so no pointer anywhere needs to be shifted.
//!
//! TILE MODE (`apply_tiled`, ): the output is 64 lossless tiles
//! instead of one strip. The IFD table must SHRINK by 3 entries (273
//! StripOffsets, 278 RowsPerStrip, 279 StripByteCounts — the reference
//! golden drops all three) and GROW by 4 (322 TileWidth, 323 TileLength,
//! 324 TileOffsets, 325 TileByteCounts — LONG type, mirroring the golden)
//! → net +1 entry → the IFD table at file offset 8 grows by 12 bytes and
//! the whole out-of-line data blob (end of IFD0 .. data_end) shifts by
//! +12; every file pointer into that blob (out-of-line entry pointers,
//! sub-IFD table pointers, sub-IFD out-of-line pointers, next-IFD
//! pointers) is rewritten +12. The 324/325 arrays are appended after the
//! shifted blob; tiles follow contiguously. Metadata CONTENT is preserved
//! byte-for-byte (verified position-independently by
//! `verify::metadata_preserved_tiled`).
//!
//! LOG10 TILE MODE (`apply_tiled_log10`, ): the same tile surgery
//! plus the 10-bit log signalling: tag 258 BitsPerSample 12 → 10 (in-line
//! SHORT, patched), and tag 50712 LinearizationTable (SHORT, count 1024,
//! out-of-line 2048 B = the `log10::LUT`) inserted at its sorted position.
//! The IFD grows by 2 entries → net +24 blob shift; the LUT array sits
//! between the 325 array and the first tile. WhiteLevel (50717) is NOT
//! touched — it stays 4095, the 12-bit value in the LINEAR domain after
//! the LUT (spec Ch. 5: linearization → black subtraction → WhiteLevel
//! rescale; verified against the DNG SDK dng_linearization_info.cpp).
//!
//! DOWNSCALE2X (`apply_tiled_downscale[_log10]`, ): the tile
//! surgery (optionally the log10 signalling on top) re-encoding the
//! HALF-resolution plane (3856×2170 → 1928×1085, `crate::downscale::
//! decimate2x`), plus the proxy geometry patches (all measured on the fp
//! frame):
//!   - tag 256 ImageWidth 3856 → 1928, 257 ImageLength 2170 → 1085
//!     (in-line LONG, value field patched);
//!   - tag 50719 DefaultCropOrigin (8,5) → (4,2) (out-of-line LONG×2,
//!     patched in the blob): the elementwise integer floor of the SOURCE
//!     50719 (`ds2x_crop_origin`): the measured
//!     ds2x writes exactly this truncation ((8,5) → (4,2)) and the spec permits any origin within the crop;
//!     the tag's type/count are preserved (in-place LONG×2 patch);
//!   - tag 50720 DefaultCropSize (3840,2160) → (1920,1080) (out-of-line
//!     LONG×2, patched); this makes the SDK's IsProxy() true (1920×1080 ≠
//!     OriginalDefaultCropSize 3840×2160);
//!   - tag 50829 ActiveArea (0,0,2170,3856) → (0,0,1085,1928) (out-of-line
//!     LONG×4, patched — the full proxy frame);
//!   - proxy signalling inserted (out-of-line LONG×2 each, values after
//!     the LUT array / before the first tile): 51089 OriginalDefaultFinalSize
//!     = 51090 OriginalBestQualityFinalSize = 51091 OriginalDefaultCropSize
//!     = (3840,2160) — the ORIGINAL's DefaultCropSize × DefaultScale
//!     (DefaultScale absent ⇒ 1.0), per spec p.65-66 + the DNG SDK's
//!     SetDefaultOriginalSizes semantics (NOT the full sensor 3856×2170);
//!   - DNGVersion 50706 / DNGBackwardVersion 50707: the proxy tags
//!     require DNG ≥ 1.4.0.0 (spec Issue 11), so the
//!     surgery ENFORCES 50707 ≥ 0x01040000 — patching it in place when the
//!     source is below the minimum (the fp frame is already exactly
//!     1.4.0.0 → no-op on A001, output byte-identical;
//!   - CFA tags (33421 (2,2), 33422 (0,1,1,2), 50711 CFALayout 1) UNCHANGED
//!     — the decimation is CFA-phase-correct (reference staircase on the fp's
//!     symmetric W G / G R pattern: every output position carries its
//!     declared class; phase-exact fallback for asymmetric patterns — see
//!     downscale.rs), so the CFA structure is preserved and the tags stay
//!     valid;
//!   - 50781 RawDataUniqueID, 50740 DNGPrivateData, ExifIFD, TimeCodes
//!     51043, FrameRate 51044, TStop 51058 and every other tag UNCHANGED
//!     (50781 kept by the log10 precedent: an image identifier, not a
//!     check-value over stored bytes — readers do not validate it against
//!     the data; DNGPrivateData/ExifIFD kept for reference parity — the SDK's
//!     own proxy path clears them, but that is for SDK-generated proxies
//!     and Resolve relinking does not depend on either).
//!
//! The IFD grows by 3 entries (proxy tags) on top of the +1 tile-surgery
//! entry → lossless+ds2x net +4 → +48 B blob shift; log10+ds2x net +5 →
//! +60 B. Expected-diff sets: lossless+ds2x = {256, 257, 259: 1→7,
//! 273/278/279 out, 322–325 in, 50719, 50720, 50829 patched, 51089/51090/
//! 51091 in}; log10+ds2x = the same + {258: 12→10, 50712 in}. Everything
//! else must match byte-for-byte (verify::metadata_preserved_tiled_*).
//!
//!
//! Correctness invariants (enforced by `verify` + tests):
//! - strip mode: output[0..strip_offset) == input[0..strip_offset) except
//!   exactly the two patched tag values (verify::metadata_preserved)
//! - tile mode: per-tag content equality (verify::metadata_preserved_tiled)
//! - decoded output == unpacked input plane bit-exactly (verify::bit_exact /
//!   verify::bit_exact_tiled)

use crate::tiff::{Frame, IfdEntry, IfdTable};
use thiserror::Error;

/// Tags dropped by the tile surgery (present in the reference golden too:
/// 273/279 are replaced by the tile tags, 278 RowsPerStrip is irrelevant
/// for tiled images).
pub const DROPPED_TAGS: [u16; 3] = [273, 278, 279];
/// New tile tags (LONG type, mirroring the reference golden's 322/323).
pub const TILE_TAGS: [u16; 4] = [322, 323, 324, 325];
/// The log10-mode extra tag: LinearizationTable (SHORT, count 1024).
pub const LUT_TAG: u16 = 50712;
/// Lossy-mode digest tag: NewRawImageDigest (BYTE count 16).
pub const DIGEST_TAG: u16 = 51111;
/// Proxy-signalling tags (DNG 1.4.0.0, spec p.65-66): OriginalDefaultFinalSize,
/// OriginalBestQualityFinalSize, OriginalDefaultCropSize.
pub const PROXY_TAGS: [u16; 3] = [51089, 51090, 51091];
/// DNGBackwardVersion (tag 50707). Lossy (Compression 34892, spec Issue 11)
/// and the downscale2x proxy tags (51089-51091) both
/// require DNG ≥ 1.4.0.0 — enforced by patching 50707 in place when the
/// source is below the minimum (the fp frame is already at
/// exactly 0x01040000, so this is a no-op on A001 and
/// the output stays byte-identical).
pub const BACKWARD_VERSION_TAG: u16 = 50707;
/// The minimum DNGBackwardVersion the lossy/proxy tag plans require.
pub const BACKWARD_VERSION_MIN: u32 = 0x01040000; // 1.4.0.0

/// Downscale2x proxy geometry — the half-resolution target's
/// dimension/crop tags + the Original* proxy signalling values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ds2x {
    /// New ImageWidth (tag 256) — the decimated frame width.
    pub width: u32,
    /// New ImageLength (tag 257) — the decimated frame height.
    pub height: u32,
    /// New DefaultCropOrigin (tag 50719): the elementwise integer floor of
    /// the source 50719 (`ds2x_crop_origin`) — (8,5) → (4,2) for the fp,
    /// matching the measured ds2x.
    pub crop_origin: [u32; 2],
    /// New DefaultCropSize (tag 50720) — the original crop × 1/2.
    pub crop_size: [u32; 2],
    /// New ActiveArea (tag 50829) — (left, top, bottom, right) of the full
    /// proxy frame.
    pub active_area: [u32; 4],
    /// 51089/51090/51091 value (width, length): the ORIGINAL's DefaultFinal
    /// size = its DefaultCropSize × DefaultScale (scale absent ⇒ 1.0 — the
    /// original 50720 value, (3840,2160) for the fp).
    pub original_size: [u32; 2],
}

/// Downscale2x DefaultCropOrigin truncation: the
/// elementwise integer floor of the SOURCE 50719. The only observed
/// producer (the measured ds2x) writes exactly this — the fp's
/// (8,5) → (4,2); the spec permits any origin within
/// the crop, so matching the measured encoder is cheaper and more faithful than the
/// spec default (0,0). The surgery keeps the tag's type/count (in-place
/// patch of the out-of-line values), so the numeric rule is all that
/// matters.
pub fn ds2x_crop_origin(src: [u32; 2]) -> [u32; 2] {
    [src[0] / 2, src[1] / 2]
}

/// The tag-level diff a tile surgery applies beyond the base tile swap
/// (273/278/279 dropped, 322-325 added, 259 patched). One plan per mode
/// keeps `apply_tiled_inner` a single code path; the lossless plan is
/// byte-identical to the pre-lossy implementation (verified on frame 1).
#[derive(Clone, Debug)]
pub struct TilePlan {
    /// New value for tag 258 BitsPerSample (in-line SHORT). None = keep.
    pub bps_patch: Option<u16>,
    /// New value for tag 259 Compression (in-line SHORT): 7 lossless,
    /// 34892 lossy.
    pub compression: u16,
    /// New value for tag 262 PhotometricInterpretation (in-line SHORT):
    /// None = keep (32803 CFA), Some(34892) = lossy LinearRaw.
    pub photometric_patch: Option<u16>,
    /// Tags dropped in addition to the base strip tags (273/278/279):
    /// lossy drops the ColorMatrix (50721/50722) so fColorPlanes=1 makes
    /// SamplesPerPixel 1 valid for LinearRaw.
    pub extra_drop: &'static [u16],
    /// LinearizationTable (50712): (count, file-order SHORT bytes). log10
    /// = (1024, 2048 B), lossy = (256, 512 B). None = no LUT.
    pub lut: Option<(u32, Vec<u8>)>,
    /// NewRawImageDigest (51111): 16 B, MD5 of the per-tile MD5s (lossy
    /// only; the SDK lossy-digest convention).
    pub digest: Option<[u8; 16]>,
    /// Tile dimensions written to tags 322/323: (482, 272) for the
    /// 4×4/4×8 grids (lossless/log10/lossy) and (1928, 1088) for the
    /// dct12 2×2 parity-tile grid.
    pub tile_dims: (u32, u32),
}

impl TilePlan {
    pub fn tile_w(&self) -> u32 {
        self.tile_dims.0
    }
    pub fn tile_h(&self) -> u32 {
        self.tile_dims.1
    }
}

impl TilePlan {
    /// The MVP lossless plan (byte-identical to the original `apply_tiled`).
    pub fn lossless() -> Self {
        TilePlan {
            bps_patch: None,
            compression: 7,
            photometric_patch: None,
            extra_drop: &[],
            lut: None,
            digest: None,
            tile_dims: (482, 272),
        }
    }
    /// The native-depth lossless plan at the gate's MEASURED tile
    /// geometry (the per-(geometry × depth) contract — `tileenc::
    /// gate_tile_dims_depth`): the FHD gate's depth-varying grid (242×274
 /// @12/8, 484×274 @10 — the measured contract),
    /// every other (geometry × depth) combination the 482×272 default
    /// (byte-identical to `lossless()` — the byte-invariance pin). The
    /// only field that differs from `lossless()` is `tile_dims`
    /// (tags 322/323 — the grid the tile encoder ran on).
    pub fn lossless_gate(frame_w: u32, frame_h: u32, depth: u32) -> Self {
        TilePlan {
            tile_dims: crate::tileenc::gate_tile_dims_depth(frame_w, frame_h, depth),
            ..Self::lossless()
        }
    }
 /// The gate's per-(geometry × depth) log10 plan (the 
 /// FHD + OG2K mode rows, + the UHD @12
    /// contract — the per-ARM measured mechanics, the R0.4 bookkeeping
    /// gap (3) closed):
    /// @12: BitsPerSample 12→10 + the 1024-entry log LUT ADD (the
 /// tool's own embedded A001 LUT — the measured LUT decision: the
 /// reference's per-frame table is its calibration payload, the 
    /// free class; the tool writes its own self-consistent table) + the
    /// per-gate grid (UHD 482×272 — BYTE-IDENTICAL to `log10()`, the
    /// named mode control; FHD 242×274 @12/@8 / 484×274 @10; OG2K the
    /// depth-invariant 252×336); @10 (FHD/OG2K): BitsPerSample
    /// unchanged (10) + NO LUT + the per-gate grid — the raw 10-bit
    /// passthrough arm (the measured maxdiff 0 vs the raw samples —
    /// the mode's container stores the raw samples, content-identical
    /// to the gate's lossless @10 plane); @8 (FHD/OG2K): BitsPerSample
    /// 8→10 identity promotion + NO LUT patch (the source's native
    /// 256-entry 50712 is CARRIED as-is — the `lut: None` carry
    /// semantics of `apply_tiled_inner`; the surgery never adds a
    /// second 50712) + the per-gate grid (FHD 242×274; OG2K 252×336).
    pub fn log10_gate(frame_w: u32, frame_h: u32, depth: u32) -> Self {
        let tile_dims = crate::tileenc::gate_tile_dims_depth(frame_w, frame_h, depth);
        match depth {
            10 => TilePlan {
                bps_patch: None,
                lut: None,
                tile_dims,
                ..Self::lossless()
            },
            8 => TilePlan {
                bps_patch: Some(10),
                lut: None,
                tile_dims,
                ..Self::lossless()
            },
            _ => TilePlan {
                bps_patch: Some(10),
                lut: Some((1024, crate::log10::lut_bytes())),
                tile_dims,
                ..Self::lossless()
            },
        }
    }
    /// The gate's per-(geometry × source depth) downscale2x plan (the
 /// FHD + OG2K mode rows, + the
    /// UHD @12 contract — the
    /// R0.4 bookkeeping gaps (1)+(2) closed): the tile dims follow
    /// `gate_tile_dims_depth` on the SOURCE geometry (the ds2x output
    /// inherits the source's measured per-depth grid: UHD @12 482×272 —
    /// BYTE-IDENTICAL to `lossless()`, the named mode control; FHD
    /// 242×274 @12 / 484×274 @10 / 242×274 @8; OG2K the depth-
 /// invariant 252×336 at every depth — the measured contract); the @8 arm = the mode
    /// tier's measured BPS10 container (BitsPerSample 8→10 identity
 /// promotion — the lossless tier's no-promotion decision is scoped to
    /// the lossless tier; the sample values unchanged, repacked at
    /// BPS10). The source's native 256-entry 50712 is CARRIED as-is
    /// (`lut: None`) — the surgery never adds a second 50712.
    pub fn downscale_gate(frame_w: u32, frame_h: u32, depth: u32) -> Self {
        let tile_dims = crate::tileenc::gate_tile_dims_depth(frame_w, frame_h, depth);
        match depth {
            8 => TilePlan {
                bps_patch: Some(10),
                tile_dims,
                ..Self::lossless()
            },
            _ => TilePlan {
                tile_dims,
                ..Self::lossless()
            },
        }
    }
    /// log10 plan: BitsPerSample 12→10 + the 1024-entry log LUT.
    pub fn log10() -> Self {
        TilePlan {
            bps_patch: Some(10),
            compression: 7,
            photometric_patch: None,
            extra_drop: &[],
            lut: Some((1024, crate::log10::lut_bytes())),
            digest: None,
            tile_dims: (482, 272),
        }
    }
    /// Lossy plan (34892 / LinearRaw / 8-bit): BitsPerSample 12→8,
    /// Compression 1→34892, Photometric 32803→34892, ColorMatrix dropped,
    /// 256-entry 12-bit LUT + NewRawImageDigest.
    pub fn lossy(digest: [u8; 16]) -> Self {
        TilePlan {
            bps_patch: Some(8),
            compression: 34892,
            photometric_patch: Some(34892),
            extra_drop: &[50721, 50722],
            lut: Some((256, crate::lossy::lut_bytes())),
            digest: Some(digest),
            tile_dims: (482, 272),
        }
    }
    /// Reference tag-7 (12-bit DCT parity tiles) plan: Compression 1→7,
    /// BitsPerSample and Photometric UNCHANGED (12 / 32803 CFA — the tag-7
    /// lossy keeps the CFA photometric), 322/323 = 1928/1088 (the 2×2
    /// parity-tile grid), 50712 = the corpus 4096-entry curve (byte-copied
    /// from the corpus / embedded constant), no digest, no
    /// ColorMatrix drop, no DNGBackwardVersion patch (compression 7 needs
    /// no version floor).
    pub fn reference_dct(curve: Vec<u8>) -> Self {
        debug_assert_eq!(
            curve.len(),
            crate::lossydct::CURVE_LEN * 2,
            "dct12 50712 = SHORT × 4096 = 8192 B"
        );
        TilePlan {
            bps_patch: None,
            compression: 7,
            photometric_patch: None,
            extra_drop: &[],
            lut: Some((4096, curve)),
            digest: None,
            tile_dims: (1928, 1088),
        }
    }
}

/// Read a LONG (type 4) tag's values from the file's IFD0 (inline n=1 or
/// out-of-line n>1). Refuses non-LONG / repeated tags.
pub fn ifd_tag_longs(src: &[u8], frame: &Frame, tag: u16) -> Result<Vec<u32>, SurgeryError> {
    let e = frame.endianness;
    let hits: Vec<&IfdEntry> = frame
        .ifd0
        .entries
        .iter()
        .filter(|en| en.tag == tag)
        .collect();
    if hits.len() != 1 {
        return Err(if hits.is_empty() {
            SurgeryError::TagMissing(tag)
        } else {
            SurgeryError::TagRepeated(tag, hits.len())
        });
    }
    let en = hits[0];
    if en.typ != 4 {
        return Err(SurgeryError::TagLayoutWrong {
            tag,
            got_typ: en.typ,
            got_count: en.count,
            want_typ: 4,
            want_count: en.count,
        });
    }
    let base = match en.out_of_line {
        Some((p, _)) => p,
        None => {
            if en.count != 1 {
                return Err(SurgeryError::TagLayoutWrong {
                    tag,
                    got_typ: en.typ,
                    got_count: en.count,
                    want_typ: 4,
                    want_count: 1,
                });
            }
            return Ok(vec![e.u32(&en.value_raw)]);
        }
    };
    let mut out = Vec::with_capacity(en.count as usize);
    for i in 0..en.count {
        let o = (base + i as u64 * 4) as usize;
        out.push(e.u32(&src[o..o + 4]));
    }
    Ok(out)
}

/// Read a SHORT (typ 3) or LONG (typ 4) tag as u32 values; `None` when the
/// tag is absent, `Err` when it is present but malformed for this read
/// (repeated, unexpected type). Used by `downscale::decimation_rule` for
/// 50966/33421 (pattern dims) and 50969/50970 (CFA anchor).
pub fn ifd_tag_u32s_opt(
    src: &[u8],
    frame: &Frame,
    tag: u16,
) -> Result<Option<Vec<u32>>, SurgeryError> {
    let e = frame.endianness;
    let hits: Vec<&IfdEntry> = frame
        .ifd0
        .entries
        .iter()
        .filter(|en| en.tag == tag)
        .collect();
    if hits.is_empty() {
        return Ok(None);
    }
    if hits.len() != 1 {
        return Err(SurgeryError::TagRepeated(tag, hits.len()));
    }
    let en = &hits[0];
    match en.typ {
        4 => {
            let base = match en.out_of_line {
                Some((p, _)) => p,
                None => {
                    if en.count != 1 {
                        return Err(SurgeryError::TagLayoutWrong {
                            tag,
                            got_typ: en.typ,
                            got_count: en.count,
                            want_typ: 4,
                            want_count: 1,
                        });
                    }
                    return Ok(Some(vec![e.u32(&en.value_raw)]));
                }
            };
            Ok(Some(
                (0..en.count)
                    .map(|i| {
                        let o = (base + i as u64 * 4) as usize;
                        e.u32(&src[o..o + 4])
                    })
                    .collect(),
            ))
        }
        3 => {
            let sz = en.count as u64 * 2;
            let vb = if sz <= 4 {
                en.value_raw[..sz as usize].to_vec()
            } else {
                let (p, _) = en.out_of_line.ok_or(SurgeryError::TagLayoutWrong {
                    tag,
                    got_typ: en.typ,
                    got_count: en.count,
                    want_typ: en.typ,
                    want_count: en.count,
                })?;
                src[p as usize..(p + sz) as usize].to_vec()
            };
            Ok(Some(
                (0..en.count)
                    .map(|i| e.u16(&vb[i as usize * 2..i as usize * 2 + 2]) as u32)
                    .collect(),
            ))
        }
        t => Err(SurgeryError::TagLayoutWrong {
            tag,
            got_typ: t,
            got_count: en.count,
            want_typ: 3,
            want_count: en.count,
        }),
    }
}

/// Read a BYTE (typ 1) or UNDEFINED (typ 7) tag as raw bytes; `None` when
/// the tag is absent. Used by `downscale::decimation_rule` for the CFA
/// pattern (50967 DNG / 33422 legacy; the fp writes 33422 BYTE n=4).
pub fn ifd_tag_bytes_opt(
    src: &[u8],
    frame: &Frame,
    tag: u16,
) -> Result<Option<Vec<u8>>, SurgeryError> {
    let hits: Vec<&IfdEntry> = frame
        .ifd0
        .entries
        .iter()
        .filter(|en| en.tag == tag)
        .collect();
    if hits.is_empty() {
        return Ok(None);
    }
    if hits.len() != 1 {
        return Err(SurgeryError::TagRepeated(tag, hits.len()));
    }
    let en = &hits[0];
    if en.typ != 1 && en.typ != 7 {
        return Err(SurgeryError::TagLayoutWrong {
            tag,
            got_typ: en.typ,
            got_count: en.count,
            want_typ: 1,
            want_count: en.count,
        });
    }
    let sz = en.count as u64;
    let vb = if sz <= 4 {
        en.value_raw[..sz as usize].to_vec()
    } else {
        let (p, _) = en.out_of_line.ok_or(SurgeryError::TagLayoutWrong {
            tag,
            got_typ: en.typ,
            got_count: en.count,
            want_typ: en.typ,
            want_count: en.count,
        })?;
        src[p as usize..(p + sz) as usize].to_vec()
    };
    Ok(Some(vb))
}

#[derive(Error, Debug)]
pub enum SurgeryError {
    #[error("tag {0} (0x{0:04X}) missing; tile surgery expects it once")]
    TagMissing(u16),
    #[error("tag {0} (0x{0:04X}) present {1} times; tile surgery expects it once")]
    TagRepeated(u16, usize),
    #[error("tag {tag} (0x{tag:04X}) has type {got_typ}/count {got_count}; surgery wants LONG({want_typ}) — refusing")]
    TagLayoutWrong {
        tag: u16,
        got_typ: u16,
        got_count: u32,
        want_typ: u16,
        want_count: u32,
    },
    #[error("IFD0 entries are not sorted by tag id; refusing to re-emit")]
    TableNotSorted,
    #[error("out-of-line pointer for tag {tag} (0x{tag:04X}) at {ptr} is outside the data blob [{start}..{end})")]
    PointerOutsideBlob {
        tag: u16,
        ptr: u64,
        start: u64,
        end: u64,
    },
    #[error("next-IFD pointer {0} not inside the data blob; cannot shift")]
    NextIfdPointer(u32),
    #[error("tag {tag} (0x{tag:04X}) is not in-line SHORT count 1; cannot patch its value")]
    TagValueNotInLine { tag: u16 },
    #[error("the derive surgery reads a 12-bit master (BitsPerSample=12); got {0}")]
    DeriveSourceNotTwelveBit(u16),
    #[error("the derive surgery writes an 8- or 10-bit raw strip; got {0}")]
    DeriveTargetNotEightOrTen(u16),
    #[error("DNGBackwardVersion (50707) missing; the {what} plan requires DNG ≥ 1.4.0.0 (spec Issue 11)")]
    BackwardVersionMissing { what: &'static str },
    #[error("DNGBackwardVersion (50707) layout {got_typ}/{got_count} is not BYTE×4 or LONG×1 in-line; cannot enforce ≥ 1.4.0.0")]
    BackwardVersionLayout { got_typ: u16, got_count: u32 },
    #[error("tag {tag} (0x{tag:04X}) carries {count} IFD pointers; the surgery shifts only single (count 1) inline IFD pointers — refusing")]
    IfdPointerArray { tag: u16, count: u32 },
    #[error("IFD0 sits at offset {0}, not 8; the tile-surgery layout model requires IFD0 right after the 8-byte TIFF header")]
    Ifd0OffsetWrong(u64),
    #[error("empty tile list")]
    NoTiles,
    #[error("frame {width}×{height} is not the Open Gate 3K gate (3024×2010); the 3K re-layout surgery applies to that gate only")]
    ThreeKGate { width: u32, height: u32 },
    #[error("the 3K template expects {want} tiles (the 12×8 grid); got {got}")]
    ThreeKTileCount { want: u32, got: u32 },
    #[error("tag {tag} (0x{tag:04X}) is not in the 3K template's region map for the frame's measured tag set (the {variant} variant); the measured template covers the A001 OG3K tag sets only (loud by design — the named refusal, never a mis-layout)")]
    ThreeKTemplateTag {
        tag: u16,
        variant: &'static str,
    },
    #[error("tag {tag} (0x{tag:04X}) region size {got} != the 3K template's {want}; the template is size-guarded (the A001 OG3K tag set contract)")]
    ThreeKTemplateSize { tag: u16, want: u64, got: u64 },
    #[error("the 3K template expects exactly one sub-IFD (the ExifIFD); got {0}")]
    ThreeKSubIfdCount(usize),
    #[error("the 3K template expects the {what} next-IFD pointer to be 0 (no chained IFD); got {got}")]
    ThreeKChainedIfd { what: &'static str, got: u32 },
}

/// Result of the surgery, ready to write (tmp + rename in the worker).
#[derive(Clone, Debug)]
pub struct FrameOutput {
    pub bytes: Vec<u8>,
    pub bytes_in: usize,
    pub bytes_out: usize,
}

/// Produce the compressed file bytes from the original file + a JPEG stream.
pub fn apply(src: &[u8], frame: &Frame, jpeg: &[u8]) -> FrameOutput {
    let so = frame.strip_offset as usize;
    debug_assert!(so < src.len(), "strip offset past end of input");
    debug_assert!(
        frame.compression_value_offset < frame.strip_offset
            && frame.strip_count_value_offset < frame.strip_offset,
        "patch offsets must lie inside the preserved header"
    );
    let mut out = Vec::with_capacity(so + jpeg.len());
    out.extend_from_slice(&src[..so]);
    frame
        .endianness
        .put_u16(&mut out, frame.compression_value_offset, 7);
    frame
        .endianness
        .put_u32(&mut out, frame.strip_count_value_offset, jpeg.len() as u32);
    out.extend_from_slice(jpeg);
    FrameOutput {
        bytes_in: src.len(),
        bytes_out: out.len(),
        bytes: out,
    }
}

/// The file offset of the 2-byte in-line value field of the (single)
/// in-line SHORT count-1 IFD0 entry for `tag` (the
/// derive surgery): the IFD structure layout is `off` = the 16-bit count
/// word, entry i at `off + 2 + 12*i`, value field at `+8` — the same
/// arithmetic `tiff::read_ifd` parses with, so the offset is exact for any
/// IFD0 position. Refuses a missing/duplicated tag or a non-inline layout
/// (a SHORT count 1 is always in-line per the TIFF rule sz <= 4; the check
/// is a belt against a future parser change).
fn ifd0_inline_short_value_offset(frame: &Frame, tag: u16) -> Result<u64, SurgeryError> {
    let hits = frame.ifd0.entries.iter().filter(|en| en.tag == tag).count();
    if hits == 0 {
        return Err(SurgeryError::TagMissing(tag));
    }
    if hits > 1 {
        return Err(SurgeryError::TagRepeated(tag, hits));
    }
    let idx = frame
        .ifd0
        .entries
        .iter()
        .position(|en| en.tag == tag)
        .unwrap();
    let en = &frame.ifd0.entries[idx];
    if en.typ != 3 || en.count != 1 || en.out_of_line.is_some() {
        return Err(SurgeryError::TagValueNotInLine { tag });
    }
    Ok(frame.ifd0.off + 2 + (idx as u64) * 12 + 8)
}

/// DERIVED-DEPTH strip surgery (the 12→8/10
/// working tier): the strip-mode layout contract of `apply` (the header is
/// copied byte-for-byte, the new data lands at the SAME strip offset so no
/// pointer moves, the zero tail is truncated) with two value patches:
///   - tag 258 BitsPerSample: 12 → `bits_out` (8 or 10; in-line SHORT
///     count 1 — the fp layout, same precondition as the log10/lossy
///     bps_patch in the tile surgery);
///   - tag 279 StripByteCounts: → `strip.len()` (in-line LONG count 1 —
///     the same assumption `apply` makes with `put_u32`).
///
/// tag 273 (StripOffsets) is UNCHANGED and tag 259 (Compression) stays 1
/// (uncompressed): the output is a genuine uncompressed CFA DNG at the
/// derived depth — the camera-native shape the archive-layout gate reads
/// (W×H single strip, `strip` = the packed derived samples at the
/// depth rule: 8-bit 1 B/sample, 10-bit per-row 4-per-5-bytes,
/// zero pad), not a compressed one. Everything else (TimeCodes 51043,
/// ExifIFD, the SIGMA blob, all DNG tags) is byte-identical to the
/// master — the lossless-surgery pattern. The 12-bit lossless paths
/// (`apply`, `apply_tiled*`) are untouched.
pub fn apply_derive_strip(
    src: &[u8],
    frame: &Frame,
    bits_out: u16,
    strip: &[u8],
) -> Result<FrameOutput, SurgeryError> {
    if frame.bits_per_sample != 12 {
        return Err(SurgeryError::DeriveSourceNotTwelveBit(frame.bits_per_sample));
    }
    if bits_out != 8 && bits_out != 10 {
        return Err(SurgeryError::DeriveTargetNotEightOrTen(bits_out));
    }
    let so = frame.strip_offset as usize;
    debug_assert!(so < src.len(), "strip offset past end of input");
    let bps_off = ifd0_inline_short_value_offset(frame, 258)?;
    debug_assert!(
        frame.strip_count_value_offset < frame.strip_offset,
        "patch offsets must lie inside the preserved header"
    );
    let mut out = Vec::with_capacity(so + strip.len());
    out.extend_from_slice(&src[..so]);
    frame.endianness.put_u16(&mut out, bps_off, bits_out);
    frame.endianness.put_u32(&mut out, frame.strip_count_value_offset, strip.len() as u32);
    out.extend_from_slice(strip);
    Ok(FrameOutput {
        bytes_in: src.len(),
        bytes_out: out.len(),
        bytes: out,
    })
}

/// Emit one IFD entry as 12 bytes. `ptr_shift` (12 for the tile surgery)
/// is added to every pointer that references the shifted data blob:
/// out-of-line value pointers and inline IFD-pointer values (type 4/12/13
/// count 1: the fp carries ExifIFD 34665 as LONG, not IFD — see
/// `crate::tiff::is_ifd_pointer`; a type-12-only check left 34665 stale in
/// every tile-mode output).
fn emit_entry(out: &mut Vec<u8>, e: crate::tiff::Endian, en: &IfdEntry, ptr_shift: u64) {
    out.extend_from_slice(&en.tag.to_le_bytes());
    out.extend_from_slice(&en.typ.to_le_bytes());
    out.extend_from_slice(&en.count.to_le_bytes());
    let is_ptr =
        en.out_of_line.is_some() || (en.count == 1 && crate::tiff::is_ifd_pointer(en.typ, en.tag));
    if is_ptr {
        let old = e.u32(&en.value_raw);
        // 0 = "no such IFD" (absent sub-IFD pointer); keep it as-is.
        let new = if old == 0 {
            0
        } else {
            old.wrapping_add(ptr_shift as u32)
        };
        out.extend_from_slice(&new.to_le_bytes());
    } else {
        out.extend_from_slice(&en.value_raw);
    }
}

/// Emit a full IFD table (count word + entries + next-IFD pointer).
fn emit_ifd_table(out: &mut Vec<u8>, e: crate::tiff::Endian, t: &IfdTable, ptr_shift: u64) {
    out.extend_from_slice(&(t.entries.len() as u16).to_le_bytes());
    for en in &t.entries {
        emit_entry(out, e, en, ptr_shift);
    }
    let next = if t.next_ifd == 0 {
        0u32
    } else {
        // next-IFD pointers live inside the shifted blob (validated by caller).
        t.next_ifd.wrapping_add(ptr_shift as u32)
    };
    out.extend_from_slice(&next.to_le_bytes());
}

/// Validate that every pointer in `tables` that references the data blob
/// actually points inside `[data_start..data_end)`; out-of-line IFD-pointer
/// ARRAYS (count > 1) are refused — their individual pointers sit inside the
/// blob and would each need +shift, which the emitters do not do (the fp
/// layout has none: IFD0's 34665 and all sub-IFD pointers are inline
/// count-1 LONGs, shifted by `emit_entry`'s `is_ifd_pointer` rule).
fn validate_pointers(
    tables: &[IfdTable],
    data_start: u64,
    data_end: u64,
) -> Result<(), SurgeryError> {
    for t in tables {
        for en in &t.entries {
            // the documented refusal clause, now backed by code.
            // A type-4/12/13/14 count>1 entry for an IFD-pointer tag would
            // get its array pointer shifted while the in-array pointers stay
            // stale — and the verify gate (byte-identical blob compare)
            // would not catch it.
            if crate::tiff::is_ifd_pointer(en.typ, en.tag) && en.count > 1 {
                return Err(SurgeryError::IfdPointerArray {
                    tag: en.tag,
                    count: en.count,
                });
            }
            if let Some((ptr, end)) = en.out_of_line {
                if ptr < data_start || end > data_end {
                    return Err(SurgeryError::PointerOutsideBlob {
                        tag: en.tag,
                        ptr,
                        start: data_start,
                        end: data_end,
                    });
                }
            }
            if t.next_ifd != 0 {
                let p = t.next_ifd as u64;
                if p < data_start || p >= data_end {
                    return Err(SurgeryError::NextIfdPointer(t.next_ifd));
                }
            }
        }
    }
    Ok(())
}

/// Tile-mode surgery: `tiles` are the per-tile lossless JPEG
/// streams in grid order (row-major). See the module docs for the layout.
pub fn apply_tiled(
    src: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
) -> Result<FrameOutput, SurgeryError> {
    // The tile dims ride the per-(geometry × depth) contract
    // (`gate_tile_dims_depth` — the FHD gate's depth-varying grid);
    // the source BPS is the ENCODED BPS on the native-depth path
    // (`bps_patch = None`). Every (geometry × depth) combination other
    // than FHD derives the 482×272 plan — byte-identical to the
    // historical `TilePlan::lossless()` (the byte-invariance pin).
    apply_tiled_inner(
        src,
        frame,
        tiles,
        &TilePlan::lossless_gate(frame.width, frame.height, frame.bits_per_sample as u32),
        None,
    )
}

/// Log10 tile-mode surgery: the tile surgery plus the per-(geometry ×
/// depth) log10 signalling (measured contract —
/// `TilePlan::log10_gate`): the UHD @12 arm is byte-identical to the
/// historical `TilePlan::log10()` (BitsPerSample 12 → 10 + the 1024-
/// entry LinearizationTable — the named mode control, the byte-invariance);
/// the FHD @12 arm = the same LUT mechanics on the measured 242×274
/// grid; the FHD @10 arm = the raw 10-bit passthrough (no BPS patch, no
/// LUT — the measured maxdiff 0 vs the raw samples); the FHD @8 arm =
/// the identity-promoted BPS10 container (BitsPerSample 8 → 10; the
/// source's native 256-entry 50712 CARRIED as-is — the `lut: None` carry
/// semantics — never a second 50712). `tiles` are the per-arm tile
/// streams (10-bit log codes for the @12 arm, the raw samples for the
/// @10/@8 arms). See the module docs for the layout and the expected-
/// diff set.
pub fn apply_tiled_log10(
    src: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
) -> Result<FrameOutput, SurgeryError> {
    apply_tiled_inner(
        src,
        frame,
        tiles,
        &TilePlan::log10_gate(frame.width, frame.height, frame.bits_per_sample as u32),
        None,
    )
}

/// Downscale2x tile-mode surgery: the tile surgery over the
/// HALF-resolution plane plus the proxy geometry patches + Original*
/// signalling (see the module docs), at the gate's per-depth grid: the
/// per-(geometry × source depth) ARM (measured
/// contract — `TilePlan::downscale_gate`): the tile dims follow
/// `gate_tile_dims_depth` on the source (the source's measured per-depth
/// grid — the FHD 242/484/242×274 rows; the UHD @12 arm is byte-
/// identical to the historical `TilePlan::lossless()` — the named mode
/// control), and the @8 arm = the mode tier's measured BPS10 container
/// (BitsPerSample 8 → 10 identity promotion — the lossless tier's no-
/// promotion decision is scoped to the lossless tier; the source's native
/// 256-entry 50712 is CARRIED as-is — never a second 50712). The
/// reference omits the 51089-91 Original* proxy tags on its ds2x
/// outputs; the tool's own ds2x design ADDS them (the free header
/// packing — the tool keeps its own design; the reference is the interop
/// oracle, not the byte spec). `tiles` are the per-arm tile streams of
/// the decimated frame; `ds` carries the target geometry (built by the
/// worker from the source frame).
pub fn apply_tiled_downscale(
    src: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
    ds: &Ds2x,
) -> Result<FrameOutput, SurgeryError> {
    apply_tiled_inner(
        src,
        frame,
        tiles,
        &TilePlan::downscale_gate(frame.width, frame.height, frame.bits_per_sample as u32),
        Some(ds),
    )
}

/// Downscale2x + log10 tile-mode surgery: `apply_tiled_downscale`
/// plus the log10 signalling (BitsPerSample 12 → 10 + LinearizationTable).
/// `tiles` are 10-bit-code tile streams of the decimated frame.
pub fn apply_tiled_downscale_log10(
    src: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
    ds: &Ds2x,
) -> Result<FrameOutput, SurgeryError> {
    apply_tiled_inner(src, frame, tiles, &TilePlan::log10(), Some(ds))
}

/// Lossy tile-mode surgery (34892/LinearRaw/8-bit): the tile
/// surgery over 8-bit baseline-DCT tile streams with the lossy tag plan
/// (BitsPerSample 12→8, Compression 1→34892, Photometric 32803→34892,
/// ColorMatrix dropped, 256-entry LUT + NewRawImageDigest `digest`).
pub fn apply_tiled_lossy(
    src: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
    digest: [u8; 16],
) -> Result<FrameOutput, SurgeryError> {
    apply_tiled_inner(src, frame, tiles, &TilePlan::lossy(digest), None)
}

/// Lossy + downscale2x tile-mode surgery (× ): the lossy plan
/// over the half-resolution 8-bit tile streams + the proxy geometry patches.
pub fn apply_tiled_downscale_lossy(
    src: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
    ds: &Ds2x,
    digest: [u8; 16],
) -> Result<FrameOutput, SurgeryError> {
    apply_tiled_inner(src, frame, tiles, &TilePlan::lossy(digest), Some(ds))
}

/// Reference tag-7 (12-bit DCT parity tiles) tile-mode surgery: the tile
/// surgery with the `TilePlan::reference_dct` tag plan (Compression 1→7,
/// 322/323 = 1928/1088, 50712 = the corpus curve byte-copied; everything
/// else — 258, 262, ColorMatrix, 50707 — unchanged). `tiles` are the four
/// self-contained 12-bit two-scan parity-tile streams in grid order.
pub fn apply_tiled_reference_dct(
    src: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
    curve: &[u8],
) -> Result<FrameOutput, SurgeryError> {
    apply_tiled_inner(
        src,
        frame,
        tiles,
        &TilePlan::reference_dct(curve.to_vec()),
        None,
    )
}

// =====================================================================
// Open Gate 3K (3024×2010) — the measured reference re-layout (the .5
// pin, ; the A001_006 golden 3-frame corpus). The NLE media-
// offline root cause: the pre-fix encoder wrote 3K frames on the
// 482×272 grid (the surgical layout below), which DaVinci Resolve
// 21.1.0 rejects; the measured 3K output uses a 252×252
// 12×8 grid AND a full header re-layout, measured from the corpus.
//
// The reference 3K output does NOT use the surgical blob-shift layout
// (the one the UHD reference uses, which `apply_tiled_inner`
// reproduces byte-identically). It re-lays the header in ascending TAG
// ORDER: IFD0 (59 entries) + every out-of-line region at the template
// offsets below (content byte-copied from the original — per-tag
// content identity), the ExifIFD block moved to 34665's tag-order
// position (body @ 0x6e2; its external regions in tag order — 37500
// moved from the original's last position to its tag-order slot),
// 50740 moved to its tag-order position, the new 324/325 tile arrays @
// 0x3a2/0x522, the 51058 (DNGPrivateData) region @ 0x136a8, and the 96
// tiles @ 0x136b0 (contiguous,
// index order, ending exactly at EOF). The template offsets are
// constant across frames (measured: identical across
// A001_006_000001/000057/000114); the only per-frame variable header
// content is the 324/325 arrays.
//
// BOUNDARY (loud by design): the template is valid for the OG3K A001
// tag sets (firmware 5.02-modified, mode 98) — TWO measured tag-set
// variants (the ): the 50712-less set (the @12 +
// @10 OG3K originals — the 58-entry IFD0; the measured
// values) and the 50712-carrying set (the 8-bit OG3K originals carry
// the camera-native 50712 LinearizationTable, SHORT × 256 — the
// 59-entry IFD0; the measured values below). The variant
// is selected by the frame's MEASURED TAG SET (the 50712 presence —
// the discriminator is the tag set, not the depth label). Every
// template region is size-guarded against the original's declared
// size, every out-of-line entry is validated against the selected
// variant's region map, and the IFD entry counts are pinned — a tag
// set outside the selected variant or a size drift fails with a named
// error BEFORE any write (the loud refusal — never a silent
// layout, never a panic).
// =====================================================================

/// The 3K template's ExifIFD body offset — also the IFD0 34665 pointer
/// value in the re-laid output (the verify gate's expected 34665 for the
/// 3K gate; the surgical +12 shift rule does not apply here — the
/// re-layout moves the table, it does not shift it).
pub const T3K_EXIF_OFF: u32 = 0x6e2;

/// 3K template layout constants (measured — provenance in the section
/// above).
const T3K_IFD0_ENTRIES: u16 = 59; // 58 original − 273/278/279 + 322/323/324/325
const T3K_EXIF_ENTRIES: u16 = 47;
const T3K_EXIF_BODY: u32 = 570; // 2 + 47×12 + 4
const T3K_324_OFF: u32 = 0x3a2; // 96 × 4 B
const T3K_325_OFF: u32 = 0x522; // 96 × 4 B
/// The tile data offset: the 96 tiles sit contiguously here in index
/// order, ending exactly at EOF (the decode gate's assembly contract).
const T3K_TILES_OFF: u32 = 0x136b0;
const T3K_TILES: u32 = 96; // 12 × 8

/// The 8-byte slot between the 51041 and 51043 regions (0x13690..0x13698):
/// unreferenced by any IFD tag, but the reference writes a
/// frame-independent constant there (the original's slot holds
/// per-frame sensor bytes — the reference replaces them). Measured
/// constant across the 3-frame corpus.
const T3K_51041_51043_SLOT_OFF: u32 = 0x13690;
const T3K_51041_51043_SLOT: [u8; 8] = [
    0x94, 0x09, 0xe6, 0xfc, 0xf5, 0xb2, 0x50, 0x3e,
];

/// The 37500 (the Sigma SI7MA blob, 54338 B) internal pointer contract
/// (measured, constant across the 3-frame corpus): the blob carries
/// 57 file-absolute 4-byte pointers at these in-blob offsets; the
/// reference re-layout patches each by the blob's move delta
/// (`T3K_37500_OFF − the original's pointer`) — a mechanical
/// pointer-update, NOT a re-target (the measured golden values are
/// the old values plus the delta, exactly). The rest of the blob is
/// byte-copied.
pub const T3K_SI7MA_PTRS: [u32; 57] = [
    20, 32, 56, 80, 116, 128, 140, 152, 164, 176, 188, 200, 212, 224,
    236, 296, 308, 320, 368, 380, 392, 416, 428, 440, 452, 464, 476,
    488, 548, 584, 596, 608, 644, 788, 824, 848, 872, 884, 908, 920,
    932, 944, 956, 980, 992, 1004, 1016, 1052, 1064, 1076, 1088, 1100,
    1112, 1124, 1148, 1160, 1172,
];

/// The 3K template's top-level out-of-line regions: (tag, template
/// offset, size). The list order = the re-laid file order (ascending
/// tag order); the sizes are the size-guard contract.
const T3K_TOP: [(u16, u32, u32); 33] = [
    (270, 0x2d2, 64),
    (271, 0x312, 6),
    (272, 0x318, 11),
    (282, 0x324, 8),
    (283, 0x32c, 8),
    (305, 0x334, 25),
    (306, 0x34e, 20),
    (315, 0x362, 64),
    (33432, 0x6a2, 64),
    (50708, 0xdf14, 11),
    (50714, 0xdf20, 32),
    (50719, 0xdf40, 8),
    (50720, 0xdf48, 8),
    (50721, 0xdf50, 72),
    (50722, 0xdf98, 72),
    (50728, 0xdfe0, 24),
    (50730, 0xdff8, 8),
    (50731, 0xe000, 8),
    (50732, 0xe008, 8),
    (50735, 0xe010, 9),
    (50736, 0xe01a, 32),
    (50740, 0xe03a, 6734),
    (50781, 0xfa88, 16),
    (50829, 0xfa98, 16),
    (50937, 0xfaa8, 12),
    (50938, 0xfab4, 864),
    (50939, 0xfe14, 864),
    (50940, 0x10174, 1024),
    (51022, 0x10574, 12564),
    (51041, 0x13688, 8),
    (51043, 0x13698, 8),
    (51044, 0x136a0, 8),
    (51058, 0x136a8, 8),
];

/// The 3K template's ExifIFD external regions: (tag, template offset,
/// size) — tag order (37500 at its tag-order slot, not the original's
/// last position).
const T3K_EXIF: [(u16, u32, u32); 25] = [
    (33434, 0x91c, 8),
    (33437, 0x924, 8),
    (36867, 0x92c, 20),
    (36868, 0x940, 20),
    (36880, 0x954, 7),
    (36881, 0x95c, 7),
    (36882, 0x964, 7),
    (37377, 0x96c, 8),
    (37378, 0x974, 8),
    (37379, 0x97c, 8),
    (37380, 0x984, 8),
    (37381, 0x98c, 8),
    (37382, 0x994, 8),
    (37386, 0x99c, 8),
    (37500, 0x9a4, 54338),
    (37510, 0xdde6, 72),
    (41486, 0xde2e, 8),
    (41487, 0xde36, 8),
    (41988, 0xde3e, 8),
    (42016, 0xde46, 33),
    (42033, 0xde68, 12),
    (42034, 0xde74, 32),
    (42035, 0xde94, 24),
    (42036, 0xdeac, 96),
    (42240, 0xdf0c, 8),
];

// =====================================================================
// The 50712 tag-set variant of the 3K re-layout template (the
// measured values — the on the mirrored
// A001_012 @8 reference corpus — the A001_012
// f000001/000049/000097 golden 3-frame sample).
//
// The measured @8 layout = the SAME re-layout algorithm over the
// 50712-carrying tag set: the camera-native 50712
// (LinearizationTable, SHORT × 256 = 512 B out-of-line — present ONLY
// on the 8-bit OG3K originals, the 59-entry IFD0) adds one 12-byte
// IFD0 entry (the IFD0 table grows 714 → 726 B) + the 512 B 50712
// region. The measured per-tag structure (NO frame-to-frame variation
// across the 3-frame corpus): uniform +12 on every template region
// with tag < 50712 (incl. all 25 ExifIFD regions + the 34665 pointer
// + the 324/325 arrays), the 512 B 50712 region at 0xdf2c..0xe12c in
// tag order (between 50708 and 50714), and +524 (0x20c = 12 + 512) on
// every region after the insertion point (the 50714..51058 regions +
// the tile data + the 51041/51043 slot). The 51041/51043 slot
// constant is variant-specific (measured frame-independent across the
// same 3 frames). The shared values — 47 ExifIFD entries, the 570 B
// ExifIFD body, the 96 tiles, the 57 SI7MA in-blob pointers — are
// tag-set-invariant (the existing constants).
// =====================================================================

/// The 50712 variant's ExifIFD body offset (+ the IFD0 34665 pointer
/// value in the re-laid output; the verify gate's expected 34665 for
/// the 50712-carrying tag set).
pub const T3K_50712_EXIF_OFF: u32 = 0x6ee;

/// The 50712 variant's re-laid IFD0 entry count (59 original — the
/// camera-native 50712 entry — − 273/278/279 + 322/323/324/325).
const T3K_50712_IFD0_ENTRIES: u16 = 60;
const T3K_50712_324_OFF: u32 = 0x3ae; // 96 × 4 B
const T3K_50712_325_OFF: u32 = 0x52e; // 96 × 4 B
/// The 50712 variant's tile data offset (the 96 tiles sit
/// contiguously here in index order, ending exactly at EOF).
const T3K_50712_TILES_OFF: u32 = 0x138bc;

/// The 50712 variant's 8-byte slot between the 51041 and 51043
/// regions (0x1389c..0x138a4): variant-specific measured constant
/// (frame-independent across the 3-frame corpus; the default
/// variant's slot holds a different constant).
const T3K_50712_SLOT_OFF: u32 = 0x1389c;
const T3K_50712_SLOT: [u8; 8] = [
    0xec, 0xf4, 0xb9, 0xcf, 0xa2, 0x64, 0x8d, 0x3e,
];

/// The 50712 variant's top-level out-of-line regions: (tag, template
/// offset, size) — the measured values (the section above); the list
/// order = the re-laid file order (ascending tag order), 50712 at its
/// tag-order slot (between 50708 and 50714).
const T3K_50712_TOP: [(u16, u32, u32); 34] = [
    (270, 0x2de, 64),
    (271, 0x31e, 6),
    (272, 0x324, 11),
    (282, 0x330, 8),
    (283, 0x338, 8),
    (305, 0x340, 25),
    (306, 0x35a, 20),
    (315, 0x36e, 64),
    (33432, 0x6ae, 64),
    (50708, 0xdf20, 11),
    (50712, 0xdf2c, 512),
    (50714, 0xe12c, 32),
    (50719, 0xe14c, 8),
    (50720, 0xe154, 8),
    (50721, 0xe15c, 72),
    (50722, 0xe1a4, 72),
    (50728, 0xe1ec, 24),
    (50730, 0xe204, 8),
    (50731, 0xe20c, 8),
    (50732, 0xe214, 8),
    (50735, 0xe21c, 9),
    (50736, 0xe226, 32),
    (50740, 0xe246, 6734),
    (50781, 0xfc94, 16),
    (50829, 0xfca4, 16),
    (50937, 0xfcb4, 12),
    (50938, 0xfcc0, 864),
    (50939, 0x10020, 864),
    (50940, 0x10380, 1024),
    (51022, 0x10780, 12564),
    (51041, 0x13894, 8),
    (51043, 0x138a4, 8),
    (51044, 0x138ac, 8),
    (51058, 0x138b4, 8),
];

/// The 50712 variant's ExifIFD external regions: (tag, template
/// offset, size) — the measured values (the +12 shift; all ExifIFD
/// tags < 50712; 37500 at its tag-order slot).
const T3K_50712_EXIF: [(u16, u32, u32); 25] = [
    (33434, 0x928, 8),
    (33437, 0x930, 8),
    (36867, 0x938, 20),
    (36868, 0x94c, 20),
    (36880, 0x960, 7),
    (36881, 0x968, 7),
    (36882, 0x970, 7),
    (37377, 0x978, 8),
    (37378, 0x980, 8),
    (37379, 0x988, 8),
    (37380, 0x990, 8),
    (37381, 0x998, 8),
    (37382, 0x9a0, 8),
    (37386, 0x9a8, 8),
    (37500, 0x9b0, 54338),
    (37510, 0xddf2, 72),
    (41486, 0xde3a, 8),
    (41487, 0xde42, 8),
    (41988, 0xde4a, 8),
    (42016, 0xde52, 33),
    (42033, 0xde74, 12),
    (42034, 0xde80, 32),
    (42035, 0xde94, 24),
    (42036, 0xdeac, 96),
    (42240, 0xdf18, 8),
];

/// The per-tag-set variant of the 3K re-layout template (the
/// selection): the discriminator is the frame's
/// MEASURED TAG SET, not the depth label — the 50712-carrying set
/// (the camera-native 50712 on the 8-bit OG3K originals) →
/// `T3K_TEMPLATE_50712` (the 60-entry variant); the 50712-less set
/// (the @12 + @10 OG3K originals) → `T3K_TEMPLATE` (the existing
/// 59-entry template, the values — UNCHANGED). A tag set
/// outside the selected variant's region map is refused LOUD
/// ( — `SurgeryError::ThreeKTemplateTag`), never mis-laid-out.
struct T3KLayout {
    /// The top-level out-of-line regions: (tag, template offset, size).
    top: &'static [(u16, u32, u32)],
    /// The ExifIFD external regions: (tag, template offset, size).
    exif: &'static [(u16, u32, u32)],
    /// The re-laid ExifIFD body offset (+ the IFD0 34665 pointer
    /// value).
    exif_off: u32,
    /// The re-laid IFD0 entry count (the original's count − 3 dropped
    /// + 4 tile tags).
    ifd0_entries: u16,
    /// The re-laid 324/325 tile-array offsets.
    off_324: u32,
    off_325: u32,
    /// The tile data offset (the 96 tiles sit contiguously here,
    /// ending exactly at EOF).
    tiles_off: u32,
    /// The 51041/51043 slot offset (the 8-B slot constant — variant-
    /// specific by the effective output tag set; the constants
    /// `T3K_50712_SLOT` / `T3K_51041_51043_SLOT` are written directly
    /// by the builder's assembly).
    slot_off: u32,
}

/// The existing 3K template — the 50712-less tag set (the @12 + @10
/// OG3K originals; the measured values — UNCHANGED).
const T3K_TEMPLATE: T3KLayout = T3KLayout {
    top: &T3K_TOP,
    exif: &T3K_EXIF,
    exif_off: T3K_EXIF_OFF,
    ifd0_entries: T3K_IFD0_ENTRIES,
    off_324: T3K_324_OFF,
    off_325: T3K_325_OFF,
    tiles_off: T3K_TILES_OFF,
    slot_off: T3K_51041_51043_SLOT_OFF,
};

/// The 50712 tag-set variant (the 8-bit OG3K originals — the 
/// measured values; the section above).
const T3K_TEMPLATE_50712: T3KLayout = T3KLayout {
    top: &T3K_50712_TOP,
    exif: &T3K_50712_EXIF,
    exif_off: T3K_50712_EXIF_OFF,
    ifd0_entries: T3K_50712_IFD0_ENTRIES,
    off_324: T3K_50712_324_OFF,
    off_325: T3K_50712_325_OFF,
    tiles_off: T3K_50712_TILES_OFF,
    slot_off: T3K_50712_SLOT_OFF,
};

/// The measured 3K re-layout packing rule (the, report.md
/// §9): the 4 reference mode layouts (log10 @12/@10/@8 + ds2x @12/
/// @10/@8 on the mirrored A001_010/011/012 corpus) + the 2 pre-existing
/// lossless anchors pack EXACTLY by this rule — the fixed templates
/// are its N=96 / no-proxy instances. The walk: IFD0 @ 8 (E entries)
/// → the top-level out-of-line regions from the IFD0 end (270 at the
/// end itself; each subsequent region at the 2-BYTE alignment of the
/// previous end — the measured rule is align2, NOT align4: the odd-
/// sized regions (272 size 11, 305 size 25) force a 1-byte pad, and
/// the RATIONAL 50736 sits at 0xe01a — 2-byte aligned, never 4-byte)
/// with 324/325 (N×4 B each) at their tag-order slots (between 315 and
/// 33432) → the ExifIFD body (the 570 B table) at the 33432 end's
/// alignment → the 25 ExifIFD regions (align2 packing)
/// → the bottom regions (align2 packing; the 50712 region at its
/// tag-order slot between 50708 and 50714 when the output tag set has
/// 50712) → the tail (51041, the 8-B slot, 51043, 51044, 51058, then
/// the 51089-91 proxy values — the tool's ds2x ADD — contiguous 8 B
/// each from the 51022 end's alignment) → the N tiles contiguous to
/// EOF. The region SIZES are tag-set-invariant (the measured corpus
/// sizes — the template maps); only the offsets are computed (the
/// free-packing decision: the mode arms mirror the measured
/// computed offsets, never a pad-to-variant-constant).
struct T3KLayoutComputed {
    /// Every IFD0 out-of-line region in file order: (tag, dst offset,
    /// size) — the top regions + 324/325 + 33432 + the bottom regions
    /// (+ the 50712 region when present in the output tag set).
    regions: Vec<(u16, u32, u32)>,
    /// The ExifIFD external regions in file order: (tag, dst offset,
    /// size).
    exif: Vec<(u16, u32, u32)>,
    /// The re-laid ExifIFD body offset (+ the IFD0 34665 pointer
    /// value).
    exif_off: u32,
    /// The re-laid 324/325 tile-array offsets.
    off_324: u32,
    off_325: u32,
    /// The re-laid IFD0 entry count (the output's tag-set count).
    ifd0_entries: u16,
    /// The 51041/51043 slot offset (the 8 B slot constant — variant-
    /// specific by the effective output tag set).
    slot_off: u32,
    /// The 50712 (LUT) region offset (the log10 @12 ADD — None when
    /// the output tag set has no 50712 region here: the carried 50712
    /// rides its bottom-region offset in `regions`).
    off_lut: Option<u32>,
    /// The 51089-91 proxy value offsets (the ds2x ADD — zeroed when
    /// absent).
    proxy_offs: [u32; 3],
    /// The tile data offset (the N tiles sit contiguously here,
    /// ending exactly at EOF).
    tiles_off: u32,
}

/// The packing rule's walk (pure — no source access): the computed
/// per-arm layout from the output's parameters (the IFD0 entry count
/// E, the tile count N, the 50712 region size when the output tag set
/// has 50712 (None = absent), the proxy value count 0/3). The
/// byte-invariance guard: the two lossless instances (E=59/N=96/no 50712
/// /no proxy → `T3K_TEMPLATE`; E=60/N=96/50712-512 B/no proxy →
/// `T3K_TEMPLATE_50712`) compute the fixed template's offsets EXACTLY
/// (asserted in `apply_tiled_3k_arm`).
fn t3k_packing(
    ifd0_entries: u16,
    n_tiles: u32,
    lut_region: Option<u32>,
    n_proxy: u32,
) -> T3KLayoutComputed {
    let a2 = |p: u64| (p + 1) & !1;
    let mut pos = 8 + 2 + (ifd0_entries as u64) * 12 + 4; // the IFD0 end
    let mut regions: Vec<(u16, u32, u32)> = Vec::new();
    // The top-level lead regions (sizes tag-set-invariant — the
    // measured corpus sizes): 270 at the IFD0 end itself, the rest at
    // align4.
    const TOP_LEAD: [(u16, u32); 8] = [
        (270, 64),
        (271, 6),
        (272, 11),
        (282, 8),
        (283, 8),
        (305, 25),
        (306, 20),
        (315, 64),
    ];
    for (i, &(tag, size)) in TOP_LEAD.iter().enumerate() {
        if i > 0 {
            pos = a2(pos);
        }
        regions.push((tag, pos as u32, size));
        pos += size as u64;
    }
    // 324/325 (N×4 B each) at their tag-order slots.
    let off_324 = a2(pos) as u32;
    pos = off_324 as u64 + n_tiles as u64 * 4;
    let off_325 = a2(pos) as u32;
    pos = off_325 as u64 + n_tiles as u64 * 4;
    // 33432.
    pos = a2(pos);
    regions.push((33432, pos as u32, 64));
    pos += 64;
    // The ExifIFD body (the 570 B table) + the 25 external regions
    // (align4 packing; the sizes tag-set-invariant — `T3K_EXIF`).
    let exif_off = a2(pos) as u32;
    let mut epos = a2(exif_off as u64 + T3K_EXIF_BODY as u64);
    let mut exif: Vec<(u16, u32, u32)> = Vec::new();
    for &(tag, _, size) in T3K_EXIF.iter() {
        epos = a2(epos);
        exif.push((tag, epos as u32, size));
        epos += size as u64;
    }
    pos = epos; // the bottom continues from the exif regions' end
    // The bottom regions (align2 packing; the 50712 region at its
    // tag-order slot between 50708 and 50714 when the output tag set
    // has 50712 — the ADD or the carry, same slot).
    const BOTTOM: [(u16, u32); 20] = [
        (50708, 11),
        (50714, 32),
        (50719, 8),
        (50720, 8),
        (50721, 72),
        (50722, 72),
        (50728, 24),
        (50730, 8),
        (50731, 8),
        (50732, 8),
        (50735, 9),
        (50736, 32),
        (50740, 6734),
        (50781, 16),
        (50829, 16),
        (50937, 12),
        (50938, 864),
        (50939, 864),
        (50940, 1024),
        (51022, 12564),
    ];
    let mut off_lut = None;
    let mut inserted_lut = false;
    if let Some(lr) = lut_region {
        for &(tag, size) in BOTTOM.iter() {
            if !inserted_lut && tag > LUT_TAG {
                pos = a2(pos);
                off_lut = Some(pos as u32);
                regions.push((LUT_TAG, pos as u32, lr));
                pos += lr as u64;
                inserted_lut = true;
            }
            pos = a2(pos);
            regions.push((tag, pos as u32, size));
            pos += size as u64;
        }
    } else {
        for &(tag, size) in BOTTOM.iter() {
            pos = a2(pos);
            regions.push((tag, pos as u32, size));
            pos += size as u64;
        }
    }
    // The tail: 51041, the 8-B slot, 51043, 51044, 51058, then the
    // 51089-91 proxy values (the tool's ds2x ADD — tag order: after
    // 51058, before the tiles), contiguous 8 B each from the 51022
    // end's alignment. The four tagged tail regions join `regions`
    // (the pointer rewrite + the content copy); the slot is untagged
    // (the variant constant — `slot_off`).
    pos = a2(pos);
    let off_51041 = pos as u32;
    regions.push((51041, off_51041, 8));
    pos += 8;
    let slot_off = pos as u32;
    pos += 8;
    let off_51043 = pos as u32;
    regions.push((51043, off_51043, 8));
    pos += 8;
    let off_51044 = pos as u32;
    regions.push((51044, off_51044, 8));
    pos += 8;
    let off_51058 = pos as u32;
    regions.push((51058, off_51058, 8));
    pos += 8;
    let mut proxy_offs = [0u32; 3];
    for slot in proxy_offs[..n_proxy as usize].iter_mut() {
        pos = a2(pos);
        *slot = pos as u32;
        pos += 8;
    }
    let tiles_off = pos as u32;
    T3KLayoutComputed {
        regions,
        exif,
        exif_off,
        off_324,
        off_325,
        ifd0_entries,
        slot_off,
        off_lut,
        proxy_offs,
        tiles_off,
    }
}

/// The per-arm computed 34665 expectation (the mode arms —
/// the free-packing decision): the measured packing rule applied
/// to the output's own tag-set parameters (the verify gate's expected
/// 34665 for the mode arms — derived from the OUTPUT's measured E / N
/// / 50712 region / proxy presence, never a hand-computed constant).
pub fn t3k_mode_exif_off(
    e_ifd0: u16,
    n_tiles: u32,
    lut_region: Option<u32>,
    n_proxy: u32,
) -> u32 {
    t3k_packing(e_ifd0, n_tiles, lut_region, n_proxy).exif_off
}

/// Emit one 12-byte IFD entry at `at`: tag/type/count re-emitted in
/// file endianness + the value field = `inline_value` (a patched
/// in-line value) or `ptr` (a mapped out-of-line / IFD pointer) or the
/// entry's own value bytes (in-line, untouched).
fn emit_entry_mapped(
    out: &mut [u8],
    at: usize,
    e: crate::tiff::Endian,
    en: &IfdEntry,
    inline_value: Option<[u8; 4]>,
    ptr: Option<u32>,
) {
    let mut raw = [0u8; 8];
    e.put_u16(&mut raw, 0, en.tag);
    e.put_u16(&mut raw, 2, en.typ);
    e.put_u32(&mut raw, 4, en.count);
    out[at..at + 8].copy_from_slice(&raw);
    match (inline_value, ptr) {
        (Some(v), None) => out[at + 8..at + 12].copy_from_slice(&v),
        (None, Some(p)) => {
            let mut v = [0u8; 4];
            e.put_u32(&mut v, 0, p);
            out[at + 8..at + 12].copy_from_slice(&v)
        }
        (None, None) => out[at + 8..at + 12].copy_from_slice(&en.value_raw),
        _ => unreachable!("an entry gets either a value patch or a mapped pointer, never both"),
    }
}

/// Emit one freshly-created IFD entry at `at` (the 322/323/324/325
/// insertions — all in-line LONG count 1 in the 3K template).
fn emit_entry_new(
    out: &mut [u8],
    at: usize,
    e: crate::tiff::Endian,
    tag: u16,
    typ: u16,
    count: u32,
    value: u32,
) {
    let mut raw = [0u8; 8];
    e.put_u16(&mut raw, 0, tag);
    e.put_u16(&mut raw, 2, typ);
    e.put_u32(&mut raw, 4, count);
    out[at..at + 8].copy_from_slice(&raw);
    let mut v = [0u8; 4];
    e.put_u32(&mut v, 0, value);
    out[at + 8..at + 12].copy_from_slice(&v);
}

/// The per-arm output plan of the parameterized 3K re-layout builder
/// (the R1 — the fixed 3K templates are the byte-identical
/// LOSSLESS instances of the measured packing rule; the mode arms are
/// the measured per-arm instances — the free-packing decision).
/// The source-side tag-set validation (the variant selection + the
/// size guards + the loud refusal) is arm-invariant (the
/// source is the same OG3K original at every arm); only the OUTPUT's
/// tag set / layout / per-tag value patches vary per arm.
struct T3KArmPlan<'a> {
    /// The 258 (BitsPerSample) patch: the log10 arms (12→10 the code
    /// plane; 8→10 the identity promotion) + the ds2x @8 arm (the
    /// identity promotion) → 10; None = unchanged (the lossless arms
    /// + the log10 @10 raw passthrough + the ds2x @12/@10 arms).
    bps_patch: Option<u16>,
    /// The 50712 (LinearizationTable) ADD: (count, file-order SHORT
    /// bytes) — the log10 @12 arm's 1024-entry tool LUT (the measured
 /// LUT decision: the measured per-frame table is the calibration
 /// payload, the free class). None = the source's 50712
    /// state is CARRIED (absent stays absent; the @8's 256-entry
    /// native table rides its computed bottom-region offset — never a
    /// second 50712).
    lut: Option<(u32, Vec<u8>)>,
    /// The ds2x arm's proxy geometry: the 51089-91 ADD (3 ×
    /// (width, length) out-of-line LONG×2 = the source's
    /// DefaultCropSize ×3 — the tool's own ds2x design) + the 256/257
    /// halving (the in-line LONG patches) + the 50719/50720/50829
    /// out-of-line value halving.
    ds: Option<&'a Ds2x>,
    /// The expected tile count (96 = the full-res 12×8; 24 = the ds2x
    /// 6×4 on the 1512×1005 plane — the source's 252×252 grid).
    want_tiles: u32,
}

impl<'a> T3KArmPlan<'a> {
    /// The lossless arm (the byte-identical template instance — the
    /// expected-diff set is the existing lossless plan: 259 → 7, the
    /// strip tags dropped, 322-325 added; BitsPerSample UNCHANGED).
    fn lossless() -> Self {
        Self {
            bps_patch: None,
            lut: None,
            ds: None,
            want_tiles: T3K_TILES,
        }
    }

    /// The log10 arms (the measured per-depth content plans): @12 =
    /// the 10-bit log codes (258 12→10) + the 1024-entry tool LUT ADD;
    /// @10 = the raw 10-bit passthrough (258 unchanged, no 50712 — the
    /// plan is field-equal to the lossless @10 arm: the measured
    /// content identity); @8 = the 8-bit samples identity-promoted
    /// into the BPS10 container (258 8→10; the native 256-entry 50712
    /// CARRIED).
    fn log10(bps: u16) -> Self {
        match bps {
            12 => Self {
                bps_patch: Some(10),
                lut: Some((1024, crate::log10::lut_bytes())),
                ds: None,
                want_tiles: T3K_TILES,
            },
            10 => Self {
                bps_patch: None,
                lut: None,
                ds: None,
                want_tiles: T3K_TILES,
            },
            8 => Self {
                bps_patch: Some(10),
                lut: None,
                ds: None,
                want_tiles: T3K_TILES,
            },
            _ => unreachable!("the archive layout guards the native depths 8/10/12"),
        }
    }

    /// The ds2x arm (the measured downscale2x content plan): the
    /// 2×-decimated 1512×1005 plane on the 252×252 grid (6×4 = 24
    /// tiles), precision 12/10 + the @8 identity promotion (258 8→10),
    /// the 51089-91 proxy ADD (the tool's own ds2x design — the
 /// reference omits them, the free header packing) + the
    /// 256/257 halving + the 50719/50720/50829 out-of-line halving.
    fn downscale(bps: u16, ds: &'a Ds2x) -> Self {
        let g = crate::tileenc::Grid::for_dims(
            ds.width,
            ds.height,
            crate::tileenc::GATE_3K_TILE_W,
            crate::tileenc::GATE_3K_TILE_H,
        );
        Self {
            bps_patch: (bps == 8).then_some(10),
            lut: None,
            ds: Some(ds),
            want_tiles: g.cols * g.rows,
        }
    }
}

/// Open Gate 3K (3024×2010) tile-mode surgery: the measured reference
/// re-layout (the section above). `tiles` are the 96 per-tile lossless
/// streams of the 252×252 grid in index (raster) order. Region CONTENT
/// is byte-copied from the original (per-tag content identity — the
/// verify gate's contract); only the layout (the IFD tables' pointers
/// + the region offsets) is the template's.
///
/// The tile surgery's tag diff is the existing lossless plan (259 → 7,
/// 273/278/279 dropped, 322/323/324/325 added at 322/323 = 252/252),
/// with BitsPerSample UNCHANGED (the native depth is preserved).
///
/// The re-layout template is selected by the frame's MEASURED TAG SET
/// (the — the discriminator is the tag set, not
/// the depth label): the 50712-carrying set (the camera-native 50712
/// on the 8-bit OG3K originals) → the 60-entry 50712 variant (the
/// measured values); the 50712-less set (the @12 + @10
/// originals) → the existing 59-entry template (UNCHANGED). A tag set
/// outside the selected variant's region map is refused LOUD with
/// `ThreeKTemplateTag` BEFORE any write (the named refusal —
/// the former panic site).
///
/// The lossless arm of the parameterized builder (the R1 —
/// the byte-identical template instance; the mode arms are
/// `apply_tiled_3k_log10` / `apply_tiled_3k_downscale`).
pub fn apply_tiled_3k(
    src: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
) -> Result<FrameOutput, SurgeryError> {
    apply_tiled_3k_arm(src, frame, tiles, &T3KArmPlan::lossless())
}

/// The OG3K log10 mode surgery (the measured mode rows — the
/// 3024×2010 full-res plane on the 252×252 grid, 96 tiles): the
/// per-depth content plan (T3KArmPlan::log10) over the measured
/// re-layout — the packing rule on the per-arm output tag set (the
/// free-packing decision: the @12 arm's LUT ADD grows IFD0 to 60
/// entries + the 2048 B 50712 region at its computed tag-order slot;
/// the @10 arm = the lossless @10 layout EXACTLY (the field-equal
/// plan); the @8 arm carries the native 256-entry 50712 at its
/// computed offset).
pub fn apply_tiled_3k_log10(
    src: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
) -> Result<FrameOutput, SurgeryError> {
    apply_tiled_3k_arm(src, frame, tiles, &T3KArmPlan::log10(frame.bits_per_sample))
}

/// The OG3K downscale2x mode surgery (the measured mode rows
/// — the 2×-decimated 1512×1005 plane on the 252×252 grid, 24 tiles):
/// the ds2x content plan (T3KArmPlan::downscale) over the measured
/// re-layout — the packing rule on the per-arm output tag set (the
/// free-packing decision: the 51089-91 proxy ADD grows IFD0 by 3
/// entries + the 24 B proxy values at their computed tail offsets;
/// the @8 arm's BPS promotion is 258 8→10, the native 256-entry 50712
/// CARRIED at its computed offset).
pub fn apply_tiled_3k_downscale(
    src: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
    ds: &Ds2x,
) -> Result<FrameOutput, SurgeryError> {
    apply_tiled_3k_arm(src, frame, tiles, &T3KArmPlan::downscale(frame.bits_per_sample, ds))
}

/// The parameterized 3K re-layout builder (the R1): the
/// measured packing rule (T3KLayoutComputed) over the per-arm output
/// plan. The source-side validation is arm-invariant (the section
/// above); the per-arm assembly: the output tag set = the source's
/// minus the strip tags plus 322-325 + the plan's ADDs (the 50712 LUT
/// / the 51089-91 proxy), the per-arm value patches (259 → 7; 258 the
/// plan's BPS patch; 256/257 the ds2x halving; 34665 the computed
/// ExifIFD offset; the out-of-line pointers the computed offsets; the
/// ds2x crop-tag value halving), the slot constant by the EFFECTIVE
/// OUTPUT TAG SET (the discriminator: the 50712-present set's
/// variant constant; the 50712-less set's default constant — the
/// source-based selection of the lossless arms is the same), and the
/// LUT / proxy regions (the plan's content).
fn apply_tiled_3k_arm(
    src: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
    plan: &T3KArmPlan,
) -> Result<FrameOutput, SurgeryError> {
    if frame.width != crate::tileenc::GATE_3K_W || frame.height != crate::tileenc::GATE_3K_H {
        return Err(SurgeryError::ThreeKGate {
            width: frame.width,
            height: frame.height,
        });
    }
    if tiles.len() as u32 != plan.want_tiles {
        return Err(SurgeryError::ThreeKTileCount {
            want: plan.want_tiles,
            got: tiles.len() as u32,
        });
    }
    let e = frame.endianness;
    let itab = &frame.ifd0;

 // The tag-set variant (the selection — the
    // discriminator is the frame's MEASURED TAG SET, not the depth
    // label): the 50712-carrying set (the camera-native 50712 on the
    // 8-bit OG3K originals) → the 60-entry variant; the 50712-less
    // set (the @12 + @10 OG3K originals) → the existing template.
    let has_50712 = itab.entries.iter().any(|en| en.tag == 50712);
    let tmpl: &T3KLayout = if has_50712 {
        &T3K_TEMPLATE_50712
    } else {
        &T3K_TEMPLATE
    };
    let variant_name: &'static str = if has_50712 { "50712" } else { "default" };

    // The ds2x arm's preconditions (the FHD/OG2K ds2x guards mirrored —
    // `apply_tiled_inner`'s ds2x subset): 256/257 in-line LONG count 1
    // (the halving patches the value field in place); the crop/area
    // tags out-of-line LONG at their measured counts; the source must
    // not already be a proxy (the idempotence guard); + the DNG
    // BackwardVersion ≥ 1.4.0.0 (the proxy tags' spec requirement —
    // the fp frame carries exactly 0x01040000, so the patch is a
    // no-op — the guard + the verify arm are the contract).
    let mut backward_patch: Option<u32> = None;
    if let Some(ds) = plan.ds {
        for &tag in [256u16, 257].iter() {
            let en = itab
                .entries
                .iter()
                .find(|en| en.tag == tag)
                .ok_or(SurgeryError::TagMissing(tag))?;
            if en.typ != 4 || en.count != 1 || en.out_of_line.is_some() {
                return Err(SurgeryError::TagLayoutWrong {
                    tag,
                    got_typ: en.typ,
                    got_count: en.count,
                    want_typ: 4,
                    want_count: 1,
                });
            }
        }
        for (tag, count) in [(50719u16, 2u32), (50720, 2), (50829, 4)] {
            let hits: Vec<&IfdEntry> =
                itab.entries.iter().filter(|en| en.tag == tag).collect();
            if hits.len() != 1 {
                return Err(if hits.is_empty() {
                    SurgeryError::TagMissing(tag)
                } else {
                    SurgeryError::TagRepeated(tag, hits.len())
                });
            }
            let en = hits[0];
            if en.typ != 4 || en.count != count || en.out_of_line.is_none() {
                return Err(SurgeryError::TagLayoutWrong {
                    tag,
                    got_typ: en.typ,
                    got_count: en.count,
                    want_typ: 4,
                    want_count: count,
                });
            }
        }
        for &tag in PROXY_TAGS.iter() {
            if itab.entries.iter().any(|en| en.tag == tag) {
                return Err(SurgeryError::TagRepeated(tag, 1));
            }
        }
        debug_assert_eq!(ds.width * 2, frame.width, "ds2x width must be frame width / 2");
        debug_assert_eq!(ds.height * 2, frame.height, "ds2x height must be frame height / 2");
        let bvn: Vec<&IfdEntry> = itab
            .entries
            .iter()
            .filter(|en| en.tag == BACKWARD_VERSION_TAG)
            .collect();
        if bvn.is_empty() {
            return Err(SurgeryError::BackwardVersionMissing {
                what: "downscale2x proxy",
            });
        }
        if bvn.len() != 1 {
            return Err(SurgeryError::TagRepeated(BACKWARD_VERSION_TAG, bvn.len()));
        }
        let en = bvn[0];
        let inline4 = (en.typ == 1 && en.count == 4) || (en.typ == 4 && en.count == 1);
        if en.out_of_line.is_some() || !inline4 {
            return Err(SurgeryError::BackwardVersionLayout {
                got_typ: en.typ,
                got_count: en.count,
            });
        }
        let src_v = u32::from_be_bytes(en.value_raw);
        if src_v < BACKWARD_VERSION_MIN {
            backward_patch = Some(BACKWARD_VERSION_MIN);
        }
    }

 // The per-arm output tag-set parameters (the discriminator
    // — the effective OUTPUT tag set = the source's tag set ∪ the
    // plan's measured ADDs): the IFD0 entry count (source − the 3
    // dropped strip tags + the 4 tile tags + the LUT ADD (log10 @12)
    // + the 3 proxy tags (ds2x)), the 50712 region in the output (the
    // ADD's 1024-entry LUT / the source's carried 256-entry table /
    // absent), and the proxy value count (0 / 3).
    let n_proxy = if plan.ds.is_some() { 3 } else { 0 };
    let lut_region: Option<u32> = match (&plan.lut, has_50712) {
        (Some((count, _)), _) => Some(*count * 2),
        (None, true) => {
            let cnt = itab
                .entries
                .iter()
                .find(|en| en.tag == 50712)
                .expect("50712 presence checked above")
                .count;
            Some(cnt * 2)
        }
        (None, false) => None,
    };
    let e_out = (itab.entries.len() as u16)
        - DROPPED_TAGS.len() as u16
        + TILE_TAGS.len() as u16
        + u16::from(plan.lut.is_some())
        + n_proxy as u16;
    // The measured packing rule on the per-arm parameters (the
 // free-packing decision). Byte-invariance guard: the two
    // lossless instances compute the fixed template's offsets EXACTLY
    // (the debug-build assertion — the release contract is the
 // byte-identity itself, pinned by the byte-invariance controls + the
    // suite goldens).
    let layout = t3k_packing(e_out, plan.want_tiles, lut_region, n_proxy);
    if plan.lut.is_none() && plan.ds.is_none() {
        let tmpl = if has_50712 { &T3K_TEMPLATE } else { &T3K_TEMPLATE_50712 };
        debug_assert_eq!(layout.ifd0_entries, tmpl.ifd0_entries);
        debug_assert_eq!(layout.exif_off, tmpl.exif_off);
        debug_assert_eq!(layout.off_324, tmpl.off_324);
        debug_assert_eq!(layout.off_325, tmpl.off_325);
        debug_assert_eq!(layout.tiles_off, tmpl.tiles_off);
        debug_assert_eq!(layout.slot_off, tmpl.slot_off);
        debug_assert_eq!(
            layout.regions,
            tmpl.top.iter().map(|&(t, o, s)| (t, o, s)).collect::<Vec<_>>(),
            "the lossless instance must pack the fixed template EXACTLY (the byte-invariance guard)"
        );
        debug_assert_eq!(
            layout.exif,
            tmpl.exif.iter().map(|&(t, o, s)| (t, o, s)).collect::<Vec<_>>(),
            "the lossless instance's Exif regions must pack the fixed template EXACTLY"
        );
    }

    // --- preconditions (the lossless subset + the template guards) ----
    for &tag in DROPPED_TAGS.iter() {
        let n = itab.entries.iter().filter(|en| en.tag == tag).count();
        if n != 1 {
            return Err(if n == 0 {
                SurgeryError::TagMissing(tag)
            } else {
                SurgeryError::TagRepeated(tag, n)
            });
        }
    }
    for &tag in TILE_TAGS.iter() {
        if itab.entries.iter().any(|en| en.tag == tag) {
            return Err(SurgeryError::TagRepeated(tag, 1));
        }
    }
    // 259 (Compression) is always patched; in-line SHORT count 1 (the
    // fp layout) so the new value (7) fits the 2-byte value field.
    {
        let en = itab
            .entries
            .iter()
            .find(|en| en.tag == 259)
            .ok_or(SurgeryError::TagMissing(259))?;
        if en.typ != 3 || en.count != 1 || en.out_of_line.is_some() {
            return Err(SurgeryError::TagValueNotInLine { tag: 259 });
        }
    }
    for pair in itab.entries.windows(2) {
        if pair[0].tag >= pair[1].tag {
            return Err(SurgeryError::TableNotSorted);
        }
    }
    if itab.off != 8 {
        return Err(SurgeryError::Ifd0OffsetWrong(itab.off));
    }
    if itab.next_ifd != 0 {
        return Err(SurgeryError::ThreeKChainedIfd {
            what: "IFD0",
            got: itab.next_ifd,
        });
    }
    if frame.sub_ifds.len() != 1 {
        return Err(SurgeryError::ThreeKSubIfdCount(frame.sub_ifds.len()));
    }
    // 34665 (the ExifIFD pointer): in-line LONG count 1 (the fp layout
    // carries it as type 4, not type 12 — see `crate::tiff::is_ifd_pointer`).
    let exif_en = itab
        .entries
        .iter()
        .find(|en| en.tag == 34665)
        .ok_or(SurgeryError::TagMissing(34665))?;
    if exif_en.count != 1
        || exif_en.out_of_line.is_some()
        || !crate::tiff::is_ifd_pointer(exif_en.typ, exif_en.tag)
    {
        return Err(SurgeryError::TagLayoutWrong {
            tag: 34665,
            got_typ: exif_en.typ,
            got_count: exif_en.count,
            want_typ: 4,
            want_count: 1,
        });
    }
    let exif_ifd = &frame.sub_ifds[0];
    if e.u32(&exif_en.value_raw) as u64 != exif_ifd.off {
        return Err(SurgeryError::PointerOutsideBlob {
            tag: 34665,
            ptr: exif_ifd.off,
            start: e.u32(&exif_en.value_raw) as u64,
            end: e.u32(&exif_en.value_raw) as u64 + 1,
        });
    }
    if exif_ifd.entries.len() as u16 != T3K_EXIF_ENTRIES {
        return Err(SurgeryError::ThreeKTemplateSize {
            tag: 34665,
            want: T3K_EXIF_ENTRIES as u64,
            got: exif_ifd.entries.len() as u64,
        });
    }
    if exif_ifd.next_ifd != 0 {
        return Err(SurgeryError::ThreeKChainedIfd {
            what: "ExifIFD",
            got: exif_ifd.next_ifd,
        });
    }
    // Every template region: present exactly once, out-of-line, inside
    // the data blob, and EXACTLY the template size (the size guard —
    // the boundary fails loud, never silently) — against the SELECTED
 // VARIANT's region map (the : the guards
    // validate the frame's measured tag set, not one fixed tag set).
    let data_start = itab.struct_range.end;
    let data_end = frame.data_end;
    for &(tag, _, size) in tmpl.top.iter() {
        let hits: Vec<&IfdEntry> = itab.entries.iter().filter(|en| en.tag == tag).collect();
        if hits.len() != 1 {
            return Err(if hits.is_empty() {
                SurgeryError::TagMissing(tag)
            } else {
                SurgeryError::TagRepeated(tag, hits.len())
            });
        }
        let en = hits[0];
        let (ptr, end) = match en.out_of_line {
            Some(r) => r,
            None => {
                return Err(SurgeryError::ThreeKTemplateSize {
                    tag,
                    want: size as u64,
                    got: 0,
                })
            }
        };
        if ptr < data_start || end > data_end {
            return Err(SurgeryError::PointerOutsideBlob {
                tag,
                ptr,
                start: data_start,
                end: data_end,
            });
        }
        if end - ptr != size as u64 {
            return Err(SurgeryError::ThreeKTemplateSize {
                tag,
                want: size as u64,
                got: end - ptr,
            });
        }
    }
    for &(tag, _, size) in tmpl.exif.iter() {
        let hits: Vec<&IfdEntry> = exif_ifd.entries.iter().filter(|en| en.tag == tag).collect();
        if hits.len() != 1 {
            return Err(if hits.is_empty() {
                SurgeryError::TagMissing(tag)
            } else {
                SurgeryError::TagRepeated(tag, hits.len())
            });
        }
        let en = hits[0];
        let (ptr, end) = match en.out_of_line {
            Some(r) => r,
            None => {
                return Err(SurgeryError::ThreeKTemplateSize {
                    tag,
                    want: size as u64,
                    got: 0,
                })
            }
        };
        if ptr < data_start || end > data_end {
            return Err(SurgeryError::PointerOutsideBlob {
                tag,
                ptr,
                start: data_start,
                end: data_end,
            });
        }
        if end - ptr != size as u64 {
            return Err(SurgeryError::ThreeKTemplateSize {
                tag,
                want: size as u64,
                got: end - ptr,
            });
        }
    }

 // (the loud-refusal fix — the reinforced
    // preconditions): every out-of-line entry of the frame's MEASURED
    // tag set (IFD0 + ExifIFD) must be in the selected variant's
    // region map at the variant's size. A tag set outside the variant
    // is refused LOUD before any write (the named refusal — the former
 // `.expect` panic site; the refusal never writes, the 
    // hard-stop pattern).
    for en in itab.entries.iter() {
        let (ptr, end) = match en.out_of_line {
            None => continue,
            Some(r) => r,
        };
        match tmpl.top.iter().find(|(tag, _, _)| *tag == en.tag) {
            Some((_, _, size)) => {
                if end - ptr != *size as u64 {
                    return Err(SurgeryError::ThreeKTemplateSize {
                        tag: en.tag,
                        want: *size as u64,
                        got: end - ptr,
                    });
                }
            }
            None => {
                return Err(SurgeryError::ThreeKTemplateTag {
                    tag: en.tag,
                    variant: variant_name,
                });
            }
        }
    }
    for en in exif_ifd.entries.iter() {
        let (ptr, end) = match en.out_of_line {
            None => continue,
            Some(r) => r,
        };
        match tmpl.exif.iter().find(|(tag, _, _)| *tag == en.tag) {
            Some((_, _, size)) => {
                if end - ptr != *size as u64 {
                    return Err(SurgeryError::ThreeKTemplateSize {
                        tag: en.tag,
                        want: *size as u64,
                        got: end - ptr,
                    });
                }
            }
            None => {
                return Err(SurgeryError::ThreeKTemplateTag {
                    tag: en.tag,
                    variant: variant_name,
                });
            }
        }
    }

    // --- assemble (the per-arm computed layout) -------------------------
    let total = layout.tiles_off as usize + tiles.iter().map(|t| t.len()).sum::<usize>();
    let mut out = vec![0u8; total];
    out[..8].copy_from_slice(&src[..8]); // the TIFF header (byte-identical)

    // The 324 (TileOffsets) + 325 (TileByteCounts) arrays: the tiles sit
    // contiguously at the arm's tile offset in index order (the assembly
    // contract the decode gate enforces: monotonic contiguity + EOF
    // end).
    let mut cur = layout.tiles_off;
    for i in 0..tiles.len() {
        let t = &tiles[i];
        let mut raw = [0u8; 4];
        e.put_u32(&mut raw, 0, cur);
        out[layout.off_324 as usize + i * 4..layout.off_324 as usize + i * 4 + 4]
            .copy_from_slice(&raw);
        e.put_u32(&mut raw, 0, t.len() as u32);
        out[layout.off_325 as usize + i * 4..layout.off_325 as usize + i * 4 + 4]
            .copy_from_slice(&raw);
        cur += t.len() as u32;
    }
    debug_assert_eq!(cur, total as u32);

    // The new IFD0 table @ 8: the original entries minus 273/278/279,
    // plus the arm's new tags at their sorted positions (322/323/324/
    // 325 always; 50712 on the log10 @12 LUT ADD; 51089-91 on the ds2x
    // proxy ADD); 259 → 7; 258 the plan's BPS patch; 256/257 the ds2x
    // halving; 50707 the BackwardVersion patch (the ds2x arm); every
    // out-of-line pointer rewritten to the arm's computed offset
    // (34665 → the arm's ExifIFD body offset; 50712 → the LUT region
    // on the ADD, its computed bottom-region offset on the carry). In-
    // line values otherwise copied verbatim (per-tag content identity).
    let new_tags: Vec<(u16, u16, u32, u32)> = {
        let mut v: Vec<(u16, u16, u32, u32)> = vec![
            (322, 4, 1, crate::tileenc::GATE_3K_TILE_W),
            (323, 4, 1, crate::tileenc::GATE_3K_TILE_H),
            (324, 4, plan.want_tiles, layout.off_324),
            (325, 4, plan.want_tiles, layout.off_325),
        ];
        if let Some((count, _)) = &plan.lut {
            v.push((LUT_TAG, 3, *count, layout.off_lut.expect("the LUT ADD computes its region")));
        }
        if let Some(_ds) = plan.ds {
            for (&tag, &off) in PROXY_TAGS.iter().zip(layout.proxy_offs.iter()) {
                v.push((tag, 4, 2, off));
            }
        }
        v
    };
    debug_assert!(new_tags.windows(2).all(|w| w[0].0 < w[1].0));
    {
        let mut raw = [0u8; 2];
        e.put_u16(&mut raw, 0, layout.ifd0_entries);
        out[8..10].copy_from_slice(&raw);
    }
    let mut ins = 0usize;
    let mut off = 10usize;
    for en in &itab.entries {
        if DROPPED_TAGS.contains(&en.tag) {
            continue;
        }
        while ins < new_tags.len() && new_tags[ins].0 < en.tag {
            let (tag, typ, count, value) = new_tags[ins];
            emit_entry_new(&mut out, off, e, tag, typ, count, value);
            off += 12;
            ins += 1;
        }
        let inline_value = match en.tag {
            259 => {
                let mut raw = en.value_raw;
                e.put_u16(&mut raw, 0, 7); // in-line SHORT, file endianness
                Some(raw)
            }
            258 if plan.bps_patch.is_some() => {
                let mut raw = en.value_raw;
                e.put_u16(&mut raw, 0, plan.bps_patch.expect("checked")); // in-line SHORT
                Some(raw)
            }
            256 if plan.ds.is_some() => {
                let mut raw = en.value_raw;
                e.put_u32(&mut raw, 0, plan.ds.expect("checked").width); // in-line LONG
                Some(raw)
            }
            257 if plan.ds.is_some() => {
                let mut raw = en.value_raw;
                e.put_u32(&mut raw, 0, plan.ds.expect("checked").height); // in-line LONG
                Some(raw)
            }
            BACKWARD_VERSION_TAG if backward_patch.is_some() => {
                // The version value is a fixed-order BYTE[4] array
                // (major, minor, tweak, bugfix) — the canonical bytes
                // [01 04 00 00], NOT a file-endian LONG (the guard
                // above measured the contract; the fp frame is already
                // at the minimum, so this arm is normally a no-op).
                let mut raw = en.value_raw;
                raw[..4].copy_from_slice(&BACKWARD_VERSION_MIN.to_be_bytes());
                Some(raw)
            }
            _ => None,
        };
        let ptr = if en.tag == 34665 {
            Some(layout.exif_off)
        } else if en.tag == LUT_TAG && plan.lut.is_some() {
            // The log10 @12 LUT ADD: the new region's computed offset.
            Some(layout.off_lut.expect("the LUT ADD computes its region"))
        } else if en.out_of_line.is_some() {
 // (the loud-refusal fix): the reinforced
            // precondition validates every out-of-line tag against the
            // variant, so this belt-and-suspenders lookup cannot miss
            // — but the contract is the NAMED refusal, never a panic.
            Some(
                layout
                    .regions
                    .iter()
                    .find(|(tg, _, _)| *tg == en.tag)
                    .ok_or(SurgeryError::ThreeKTemplateTag {
                        tag: en.tag,
                        variant: variant_name,
                    })?
                    .1,
            )
        } else {
            None
        };
        emit_entry_mapped(&mut out, off, e, en, inline_value, ptr);
        off += 12;
    }
    while ins < new_tags.len() {
        let (tag, typ, count, value) = new_tags[ins];
        emit_entry_new(&mut out, off, e, tag, typ, count, value);
        off += 12;
        ins += 1;
    }
    debug_assert_eq!(off, 10 + layout.ifd0_entries as usize * 12);
    // next-IFD = 0 (measured on the golden; guarded above).
    out[off..off + 4].copy_from_slice(&[0u8; 4]);

    // The top-level + bottom regions (content byte-copied from the
    // original; the ds2x arm's crop-tag value patches below).
    for &(tag, toff, size) in layout.regions.iter() {
        if tag == LUT_TAG && plan.lut.is_some() {
            continue; // the ADD region — the plan's content, not a source copy
        }
        let en = itab.entries.iter().find(|en| en.tag == tag).expect("validated above");
        let (ptr, end) = en.out_of_line.expect("validated out-of-line above");
        out[toff as usize..toff as usize + size as usize]
            .copy_from_slice(&src[ptr as usize..end as usize]);
    }
    // The ds2x arm's out-of-line value patches (the measured halving —
    // 50719/50720 LONG count 2, 50829 LONG count 4 — the regions are
    // EXACTLY the patch bytes).
    if let Some(ds) = plan.ds {
        let mut longs = |tag: u16, vs: &[u32]| {
            let (_, toff, _) = layout
                .regions
                .iter()
                .find(|(t, _, _)| *t == tag)
                .expect("validated above");
            for (i, &v) in vs.iter().enumerate() {
                let mut raw = [0u8; 4];
                e.put_u32(&mut raw, 0, v);
                out[(*toff as usize + i * 4)..(*toff as usize + i * 4 + 4)]
                    .copy_from_slice(&raw);
            }
        };
        longs(50719, &ds.crop_origin);
        longs(50720, &ds.crop_size);
        longs(50829, &ds.active_area);
    }
    // The 51041/51043 slot: the variant's frame-independent constant of
 // the EFFECTIVE OUTPUT TAG SET (the discriminator: the
    // 50712-present set — the source's carried 50712 or the log10 @12
    // ADD — the 50712 variant's constant; the 50712-less set — the
    // default constant; the lossless arms' source-based selection is
 // the same). The slot is unreferenced (the free class) —
    // the measured mode outputs carry per-frame sensor residue here,
    // the tool writes the variant constant.
    let slot: [u8; 8] = if has_50712 || plan.lut.is_some() {
        T3K_50712_SLOT
    } else {
        T3K_51041_51043_SLOT
    };
    out[layout.slot_off as usize..layout.slot_off as usize + 8].copy_from_slice(&slot);
    // The LUT region (the log10 @12 ADD — the tool's 1024-entry LUT
    // bytes at the computed offset).
    if let Some((_, bytes)) = &plan.lut {
        let o = layout.off_lut.expect("the LUT ADD computes its region") as usize;
        out[o..o + bytes.len()].copy_from_slice(bytes);
    }
    // The proxy Original* values (the ds2x ADD — 51089, 51090, 51091
    // = the same (width, length) LONG pair ×3 = the source's
    // DefaultCropSize — the tool's own ds2x design).
    if let Some(ds) = plan.ds {
        for k in 0..3usize {
            for (j, v) in [ds.original_size[0], ds.original_size[1]].iter().enumerate() {
                let mut raw = [0u8; 4];
                e.put_u32(&mut raw, 0, *v);
                let o = layout.proxy_offs[k] as usize + j * 4;
                out[o..o + 4].copy_from_slice(&raw);
            }
        }
    }

    // The ExifIFD body @ the arm's ExifIFD offset: re-emitted (47
    // entries; the external pointers → the arm's computed Exif offsets;
    // the in-line values verbatim; next-IFD 0 — measured).
    {
        let mut raw = [0u8; 2];
        e.put_u16(&mut raw, 0, T3K_EXIF_ENTRIES);
        out[layout.exif_off as usize..layout.exif_off as usize + 2].copy_from_slice(&raw);
    }
    let mut eoff = layout.exif_off as usize + 2;
    for en in &exif_ifd.entries {
        let ptr = match en.out_of_line {
            None => None,
 // (the loud-refusal fix — the ExifIFD
            // side): the reinforced precondition validates every
            // out-of-line ExifIFD tag against the variant; the NAMED
            // refusal, never a panic.
            Some(_) => Some(
                layout
                    .exif
                    .iter()
                    .find(|(tg, _, _)| *tg == en.tag)
                    .ok_or(SurgeryError::ThreeKTemplateTag {
                        tag: en.tag,
                        variant: variant_name,
                    })?
                    .1,
            ),
        };
        emit_entry_mapped(&mut out, eoff, e, en, None, ptr);
        eoff += 12;
    }
    debug_assert_eq!(eoff, (layout.exif_off + T3K_EXIF_BODY) as usize - 4);
    out[eoff..eoff + 4].copy_from_slice(&[0u8; 4]); // next-IFD = 0 (measured)
    for &(tag, toff, size) in layout.exif.iter() {
        let en = exif_ifd
            .entries
            .iter()
            .find(|en| en.tag == tag)
            .expect("validated above");
        let (ptr, end) = en.out_of_line.expect("validated out-of-line above");
        out[toff as usize..toff as usize + size as usize]
            .copy_from_slice(&src[ptr as usize..end as usize]);
        if tag == 37500 {
            // The SI7MA internal pointer patch (the measured contract
            // above): each of the 57 in-blob pointers moves by the
            // blob's move delta.
            let delta = (toff as u64).wrapping_sub(ptr) as u32;
            for &pos in T3K_SI7MA_PTRS.iter() {
                let at = toff as u64 + pos as u64;
                let v = e.u32(&out[at as usize..at as usize + 4]);
                e.put_u32(&mut out[at as usize..at as usize + 4], 0, v.wrapping_add(delta));
            }
        }
    }

    // The tiles (index order, EOF-terminated).
    let mut tpos = layout.tiles_off as usize;
    for t in tiles {
        out[tpos..tpos + t.len()].copy_from_slice(t);
        tpos += t.len();
    }
    debug_assert_eq!(tpos, total);

    Ok(FrameOutput {
        bytes_in: src.len(),
        bytes_out: out.len(),
        bytes: out,
    })
}

/// Shared tile-surgery assembly. `plan` describes the mode-specific tag
/// diff (BitsPerSample/Compression/Photometric patches, extra drops, LUT,
/// digest); `ds` is the downscale2x proxy geometry (tag patches +
/// 51089/51090/51091 insertion). `TilePlan::lossless()` is byte-identical
/// to the pre-lossy implementation.
fn apply_tiled_inner(
    src: &[u8],
    frame: &Frame,
    tiles: &[Vec<u8>],
    plan: &TilePlan,
    ds: Option<&Ds2x>,
) -> Result<FrameOutput, SurgeryError> {
    let e = frame.endianness;
    if tiles.is_empty() {
        return Err(SurgeryError::NoTiles);
    }
    let itab = &frame.ifd0;
    let n_lut_tags = if plan.lut.is_some() { 1 } else { 0 };
    let n_digest_tags = if plan.digest.is_some() { 1 } else { 0 };
    let n_extra_drop = plan.extra_drop.len() as i64;
    let n_proxy_tags = if ds.is_some() { 3 } else { 0 };

    // --- preconditions ----------------------------------------------------
    for &tag in DROPPED_TAGS.iter().chain(plan.extra_drop.iter()) {
        let n = itab.entries.iter().filter(|en| en.tag == tag).count();
        if n != 1 {
            return Err(if n == 0 {
                SurgeryError::TagMissing(tag)
            } else {
                SurgeryError::TagRepeated(tag, n)
            });
        }
    }
    for &tag in TILE_TAGS.iter() {
        if itab.entries.iter().any(|en| en.tag == tag) {
            return Err(SurgeryError::TagRepeated(tag, 1));
        }
    }
    if plan.lut.is_some() {
        match itab.entries.iter().filter(|en| en.tag == LUT_TAG).count() {
            0 => {}
            n => return Err(SurgeryError::TagRepeated(LUT_TAG, n)),
        }
    }
    if plan.digest.is_some() {
        match itab
            .entries
            .iter()
            .filter(|en| en.tag == DIGEST_TAG)
            .count()
        {
            0 => {}
            n => return Err(SurgeryError::TagRepeated(DIGEST_TAG, n)),
        }
    }
    if plan.bps_patch.is_some() {
        // 258 must be in-line SHORT (the fp layout; a different layout
        // would need a different surgery than a value patch).
        let en = itab
            .entries
            .iter()
            .find(|en| en.tag == 258)
            .ok_or(SurgeryError::TagMissing(258))?;
        if en.typ != 3 || en.count != 1 || en.out_of_line.is_some() {
            return Err(SurgeryError::TagValueNotInLine { tag: 258 });
        }
    }
    // 259 (Compression) is always patched; it must be in-line SHORT count 1
    // (the fp layout) so the new value fits the 2-byte value field.
    {
        let en = itab
            .entries
            .iter()
            .find(|en| en.tag == 259)
            .ok_or(SurgeryError::TagMissing(259))?;
        if en.typ != 3 || en.count != 1 || en.out_of_line.is_some() {
            return Err(SurgeryError::TagValueNotInLine { tag: 259 });
        }
    }
    if plan.photometric_patch.is_some() {
        // 262 (PhotometricInterpretation) patched for lossy; in-line SHORT.
        let en = itab
            .entries
            .iter()
            .find(|en| en.tag == 262)
            .ok_or(SurgeryError::TagMissing(262))?;
        if en.typ != 3 || en.count != 1 || en.out_of_line.is_some() {
            return Err(SurgeryError::TagValueNotInLine { tag: 262 });
        }
    }
    if let Some(ds) = ds {
        // 256/257 must be in-line LONG count 1 (the fp layout) so the new
        // dimensions can be patched into the value field in place.
        for &tag in [256u16, 257].iter() {
            let en = itab
                .entries
                .iter()
                .find(|en| en.tag == tag)
                .ok_or(SurgeryError::TagMissing(tag))?;
            if en.typ != 4 || en.count != 1 || en.out_of_line.is_some() {
                return Err(SurgeryError::TagLayoutWrong {
                    tag,
                    got_typ: en.typ,
                    got_count: en.count,
                    want_typ: 4,
                    want_count: 1,
                });
            }
        }
        // Crop/area tags: out-of-line LONG, patched inside the blob. The
        // (fp-verified) layout: 50719/50720 LONG count 2, 50829 LONG count 4.
        for (tag, count) in [(50719u16, 2u32), (50720, 2), (50829, 4)] {
            let hits: Vec<&IfdEntry> = itab.entries.iter().filter(|en| en.tag == tag).collect();
            if hits.len() != 1 {
                return Err(if hits.is_empty() {
                    SurgeryError::TagMissing(tag)
                } else {
                    SurgeryError::TagRepeated(tag, hits.len())
                });
            }
            let en = hits[0];
            if en.typ != 4 || en.count != count || en.out_of_line.is_none() {
                return Err(SurgeryError::TagLayoutWrong {
                    tag,
                    got_typ: en.typ,
                    got_count: en.count,
                    want_typ: 4,
                    want_count: count,
                });
            }
        }
        // The source must not already be a proxy (idempotence guard).
        for &tag in PROXY_TAGS.iter() {
            if itab.entries.iter().any(|en| en.tag == tag) {
                return Err(SurgeryError::TagRepeated(tag, 1));
            }
        }
        debug_assert_eq!(
            ds.width * 2,
            frame.width,
            "ds2x width must be frame width / 2"
        );
        debug_assert_eq!(
            ds.height * 2,
            frame.height,
            "ds2x height must be frame height / 2"
        );
    }
    for pair in itab.entries.windows(2) {
        if pair[0].tag >= pair[1].tag {
            return Err(SurgeryError::TableNotSorted);
        }
    }
    let data_start = itab.struct_range.end; // all out-of-line data starts here
    let data_end = frame.data_end;
    let mut tables = vec![itab.clone()];
    tables.extend(frame.sub_ifds.iter().cloned());
    validate_pointers(&tables, data_start, data_end)?;
    // the layout model re-emits IFD0 at a fixed position (the
    // 8-byte header points at offset 8); a release build with IFD0 elsewhere
    // would silently write a table the header does not point at. Hard error.
    if itab.off != 8 {
        return Err(SurgeryError::Ifd0OffsetWrong(itab.off));
    }

    // --- DNGBackwardVersion enforcement ----------------------------
    // Lossy (34892) and the ds2x proxy tags (51089-51091) both require DNG
    // ≥ 1.4.0.0 (spec Issue 11). Patch 50707 in
    // place (in-line 4-byte value, file endianness) when the source is
    // below the minimum; a source already ≥ 1.4.0.0 is left byte-identical
    // (the fp frame is exactly 0x01040000).
    let mut backward_patch: Option<u32> = None;
    if plan.compression == 34892 || ds.is_some() {
        let hits: Vec<&IfdEntry> = itab
            .entries
            .iter()
            .filter(|en| en.tag == BACKWARD_VERSION_TAG)
            .collect();
        if hits.is_empty() {
            return Err(SurgeryError::BackwardVersionMissing {
                what: if plan.compression == 34892 {
                    "lossy (34892)"
                } else {
                    "downscale2x proxy"
                },
            });
        }
        if hits.len() != 1 {
            return Err(SurgeryError::TagRepeated(BACKWARD_VERSION_TAG, hits.len()));
        }
        let en = hits[0];
        // The fp frame carries 50707 as BYTE (type 1) count 4, in-line
        // (measured); LONG count 1 is the other legal inline
        // shape for a 4-byte version value.
        let inline4 = (en.typ == 1 && en.count == 4) || (en.typ == 4 && en.count == 1);
        if en.out_of_line.is_some() || !inline4 {
            return Err(SurgeryError::BackwardVersionLayout {
                got_typ: en.typ,
                got_count: en.count,
            });
        }
        let src_v = u32::from_be_bytes(en.value_raw);
        // NOTE: a DNG version value is a fixed-order BYTE[4] array
        // (major, minor, tweak, bugfix) — the canonical 0x01040000 is the
        // BIG-endian reading of the stored bytes [01 04 00 00], NOT a
        // file-endian LONG (the fp is an II file whose 50707 bytes are
        // [01 04 00 00] = 1.4.0.0; an LE read would give 0x00000401).
        if src_v < BACKWARD_VERSION_MIN {
            backward_patch = Some(BACKWARD_VERSION_MIN);
        }
    }

    // --- geometry ----------------------------------------------------------
    let n_old = itab.entries.len() as i64;
    let n_new = n_old - DROPPED_TAGS.len() as i64 - n_extra_drop
        + TILE_TAGS.len() as i64
        + n_lut_tags as i64
        + n_digest_tags as i64
        + n_proxy_tags as i64;
    let shift = ((n_new - n_old) * 12) as u64; // +12 / +24 / +48 / +60
    debug_assert!(
        shift > 0,
        "tile IFD must grow (drop 3+extra, add 4+lut+digest+proxy)"
    );

    let off324 = data_end + shift; // 324 array right after the shifted blob
    let off325 = off324 + (tiles.len() as u64) * 4;
    // Running cursor for the out-of-line arrays, laid out in emission order:
    // 324, 325, LUT, digest, proxy, then the tiles. Each present array sits
    // right after the previous; `tile_start` is the final cursor.
    let mut pos = off325 + (tiles.len() as u64) * 4; // just past the 325 array
    let off_lut = match &plan.lut {
        Some((_, bytes)) => {
            let o = pos;
            pos += bytes.len() as u64;
            o
        }
        None => 0,
    };
    let off_digest = match &plan.digest {
        Some(_) => {
            let o = pos;
            pos += 16;
            o
        }
        None => 0,
    };
    let off_proxy = match ds {
        Some(_) => {
            let o = pos;
            pos += 24; // 3 × LONG×2
            o
        }
        None => 0,
    };
    let tile_start = pos;

    let mut offs = Vec::with_capacity(tiles.len());
    let mut cur = tile_start;
    for t in tiles {
        offs.push(cur);
        cur += t.len() as u64;
    }

    // New tags in tag order (inserted at their sorted positions): 322/323
    // (inline LONG), 324/325 (inline LONG pointers to the arrays),
    // 50712 (out-of-line LONG pointer to the LUT array) when log10/lossy,
    // 51089/51090/51091 (out-of-line LONG pointers to the proxy value
    // array) when downscale2x, and 51111 (out-of-line LONG pointer to the
    // 16-byte digest) when lossy. `value` is the final file offset /
    // constant; `typ` LONG for all except the LUT (SHORT) and digest (BYTE).
    let new_tags: Vec<(u16, u16, u32, u32)> = {
        let mut v: Vec<(u16, u16, u32, u32)> = vec![
            (322, 4, 1, plan.tile_w()),
            (323, 4, 1, plan.tile_h()),
            (324, 4, tiles.len() as u32, off324 as u32),
            (325, 4, tiles.len() as u32, off325 as u32),
        ];
        if let Some((count, _)) = &plan.lut {
            v.push((LUT_TAG, 3, *count, off_lut as u32)); // SHORT type
        }
        if let Some(_ds) = ds {
            // 3 × (width, length) out-of-line LONG×2, contiguous.
            for k in 0..3u64 {
                v.push((PROXY_TAGS[k as usize], 4, 2, (off_proxy + k * 8) as u32));
            }
        }
        if plan.digest.is_some() {
            v.push((DIGEST_TAG, 1, 16, off_digest as u32)); // BYTE type
        }
        v
    };
    debug_assert!(new_tags.windows(2).all(|w| w[0].0 < w[1].0));

    // downscale2x out-of-line patches, in file order: (tag, new value
    // bytes, file endianness). Applied to the blob after it is copied.
    let ds_patches: Vec<(u16, Vec<u8>)> = match ds {
        Some(ds) => {
            let longs = |vs: &[u32]| -> Vec<u8> {
                let mut b = Vec::with_capacity(vs.len() * 4);
                for &v in vs {
                    let mut raw = [0u8; 4];
                    e.put_u32(&mut raw, 0, v);
                    b.extend_from_slice(&raw);
                }
                b
            };
            vec![
                (50719, longs(&ds.crop_origin)),
                (50720, longs(&ds.crop_size)),
                (50829, longs(&ds.active_area)),
            ]
        }
        None => Vec::new(),
    };

    // --- assemble ----------------------------------------------------------
    let mut out: Vec<u8> = Vec::with_capacity(cur as usize);
    out.extend_from_slice(&src[..8]); // TIFF header incl. IFD offset (byte-identical)

    // New IFD0 table: original entries minus DROPPED_TAGS + plan.extra_drop,
    // plus the new tags inserted at their sorted positions; 259 patched to
    // `plan.compression` (7 lossless / 34892 lossy); 258 patched to
    // `plan.bps_patch` when set; 262 patched to `plan.photometric_patch`
    // when set; 256/257 patched to the decimated dimensions when
    // downscale2x; blob pointers shifted.
    out.extend_from_slice(&(n_new as u16).to_le_bytes());
    let mut inserted = 0usize;
    for en in &itab.entries {
        if DROPPED_TAGS.contains(&en.tag) || plan.extra_drop.contains(&en.tag) {
            continue;
        }
        while inserted < new_tags.len() && new_tags[inserted].0 < en.tag {
            let (tag, typ, count, value) = new_tags[inserted];
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&typ.to_le_bytes());
            out.extend_from_slice(&count.to_le_bytes());
            out.extend_from_slice(&value.to_le_bytes());
            inserted += 1;
        }
        let mut en2 = *en;
        if en.tag == 259 {
            let mut raw = en2.value_raw;
            e.put_u16(&mut raw, 0, plan.compression); // in-line SHORT, file endianness
            en2.value_raw = raw;
        }
        if en.tag == 258 {
            if let Some(bps) = plan.bps_patch {
                let mut raw = en2.value_raw;
                e.put_u16(&mut raw, 0, bps); // in-line SHORT, file endianness
                en2.value_raw = raw;
            }
        }
        if en.tag == 262 {
            if let Some(ph) = plan.photometric_patch {
                let mut raw = en2.value_raw;
                e.put_u16(&mut raw, 0, ph); // in-line SHORT, file endianness
                en2.value_raw = raw;
            }
        }
        if let Some(ds) = ds {
            if en.tag == 256 || en.tag == 257 {
                let mut raw = en2.value_raw;
                e.put_u32(
                    &mut raw,
                    0,
                    if en.tag == 256 { ds.width } else { ds.height },
                );
                en2.value_raw = raw; // in-line LONG, file endianness
            }
        }
        if en.tag == BACKWARD_VERSION_TAG {
            if let Some(v) = backward_patch {
                // Version values are fixed-order BYTE[4] (major..bugfix),
                // not file-endian — write the canonical bytes.
                en2.value_raw = v.to_be_bytes();
            }
        }
        emit_entry(&mut out, e, &en2, shift);
    }
    while inserted < new_tags.len() {
        let (tag, typ, count, value) = new_tags[inserted];
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&typ.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
        inserted += 1;
    }
    out.extend_from_slice(&itab.next_ifd.to_le_bytes());

    // Shifted data blob (byte-identical content, +shift). The sub-IFD
    // tables inside it are re-emitted fresh below (their pointers move too).
    let blob_out_start = 8 + 2 + (n_new as usize) * 12 + 4;
    out.extend_from_slice(&src[data_start as usize..data_end as usize]);

    // downscale2x: patch the crop/area tag values in place inside the
    // shifted blob (their pointers moved by +shift with the blob).
    for (tag, new_value) in &ds_patches {
        let en = itab
            .entries
            .iter()
            .find(|en| en.tag == *tag)
            .expect("validated above");
        let (p, end) = en.out_of_line.expect("validated out-of-line above");
        let pos = blob_out_start + (p - data_start) as usize;
        let len = (end - p) as usize;
        debug_assert_eq!(
            new_value.len(),
            len,
            "patch size must match the tag's declared size"
        );
        out[pos..pos + len].copy_from_slice(new_value);
    }

    // 324 (TileOffsets) + 325 (TileByteCounts) arrays, the LUT array
    // (log10/lossy), the digest (lossy), the proxy Original* values
    // (downscale2x), then the tiles.
    // LONG = 4 bytes each: cast to u32 explicitly (u64::to_le_bytes would
    // emit 8 bytes and shift the next array into the middle of this one).
    for &o in &offs {
        debug_assert!(o < u32::MAX as u64, "tile offset does not fit a LONG");
        out.extend_from_slice(&(o as u32).to_le_bytes());
    }
    for t in tiles {
        out.extend_from_slice(&(t.len() as u32).to_le_bytes());
    }
    if let Some((_, bytes)) = &plan.lut {
        out.extend_from_slice(bytes);
    }
    if let Some(digest) = &plan.digest {
        out.extend_from_slice(digest);
    }
    if let Some(ds) = ds {
        // 51089, 51090, 51091 — the same (width, length) LONG pair ×3.
        for _ in 0..3 {
            for v in [ds.original_size[0], ds.original_size[1]] {
                let mut raw = [0u8; 4];
                e.put_u32(&mut raw, 0, v);
                out.extend_from_slice(&raw);
            }
        }
    }
    for t in tiles {
        out.extend_from_slice(t);
    }

    // Re-emit sub-IFD tables at their shifted positions (the blob copy left
    // the old pointer values there; overwrite with the shifted ones).
    for st in &frame.sub_ifds {
        let start = (st.off + shift) as usize;
        let size = (st.struct_range.end - st.struct_range.start) as usize;
        let mut fresh: Vec<u8> = Vec::with_capacity(size);
        emit_ifd_table(&mut fresh, e, st, shift);
        debug_assert_eq!(fresh.len(), size);
        out[start..start + size].copy_from_slice(&fresh);
    }

    Ok(FrameOutput {
        bytes_in: src.len(),
        bytes_out: out.len(),
        bytes: out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;


    /// The ds2x 50719 truncation rule — elementwise
    /// integer floor of the SOURCE DefaultCropOrigin. The measured
    /// ds2x writes exactly this ((8,5) → (4,2)); an
    /// odd-odd source floors each element independently ((7,3) → (3,1)).
    #[test]
    fn ds2x_crop_origin_truncates_source_elementwise() {
        // The real fp source (A001 f1 50719 = LONG count 2 [8, 5]).
        assert_eq!(ds2x_crop_origin([8, 5]), [4, 2]);
        // Odd-odd source: floor per element.
        assert_eq!(ds2x_crop_origin([7, 3]), [3, 1]);
        // Degenerate origins stay valid (within the crop).
        assert_eq!(ds2x_crop_origin([0, 0]), [0, 0]);
        assert_eq!(ds2x_crop_origin([1, 1]), [0, 0]);
    }

    /// Acceptance (log10): A001 f1 end-to-end — 10-bit log codes through
    /// the tile encoder + log10 surgery + BOTH log10 verify gates (LUT-
    /// inverted reconstruction within the curve bound + the log10
    /// expected-diff metadata set), and the reconstruction error stats
    /// match the measured A001 canaries (max 2 LSB — isolated midtones,
    /// mean ~0.56, 99.97% within 1 LSB).
    #[test]
    fn real_a001_frame1_log10_end_to_end() {
        let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let src = match std::fs::read(p) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                return;
            }
        };
        let frame = crate::tiff::read(&src).unwrap();
        let packed = frame.strip_slice(&src);
        let samples = crate::pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let inv = crate::log10::inv();
        let codes: Vec<u16> = samples.iter().map(|v| inv[*v as usize]).collect();

        let grid = crate::tileenc::Grid::new(frame.width, frame.height);
        let mut tiles = Vec::with_capacity((grid.cols * grid.rows) as usize);
        for r in 0..grid.rows {
            for c in 0..grid.cols {
                tiles.push(
                    crate::tileenc::encode_tile(&codes, frame.width, frame.height, &grid, r, c, 10)
                        .unwrap(),
                );
            }
        }
        // Content gate: LUT-inverted reconstruction within the curve bound.
        let stats = crate::verify::log10_content_tiled(&frame, &src, &grid, &tiles)
            .expect("log10 content gate");
        assert!(stats.max_err <= crate::log10::max_recon_error());
        // A001 f1 canaries (measured full-clip worst case = 2 LSB; f1's
        // own max is within that — keep the assertion at the clip bound so
        // the test is stable, and record the frame stats below).
        assert!(
            stats.max_err <= 2,
            "f1 max err {} drifted from the A001 canary",
            stats.max_err
        );
        assert!(
            (0.4..0.8).contains(&stats.mean_abs),
            "f1 mean err {} drifted",
            stats.mean_abs
        );
        assert!(
            stats.pct_le_1 > 99.9,
            "f1 within-1-LSB fraction {} drifted",
            stats.pct_le_1
        );
        eprintln!(
            "log10 f1: max {} mean {:.4} <=1:{:.3}% ({} samples)",
            stats.max_err, stats.mean_abs, stats.pct_le_1, stats.samples
        );

        // Surgery: BitsPerSample 12->10 + tag 50712 added.
        let out = apply_tiled_log10(&src, &frame, &tiles).expect("log10 surgery");
        // Metadata gate: the log10 expected-diff set.
        crate::verify::metadata_preserved_tiled_log10(&src, &out.bytes, &frame, &tiles)
            .expect("log10 metadata gate");
        // Geometry: the file must end at the last tile (the LUT array sits
        // between the 325 array and the tiles — 2048 B before them).
        let tile_total: usize = tiles.iter().map(|t| t.len()).sum();
        let expected_end = (frame.data_end + 24 + 256 + 256 + 2048 + tile_total as u64) as usize;
        assert_eq!(out.bytes.len(), expected_end, "log10 file layout drift");
        // Ratio sanity: 10-bit log on this dark clip must beat the 12-bit
        // single-strip (2.17:1) by a wide margin; the full-clip run
        // measures against the 12-bit tile lossless (574 MB) baseline.
        let ratio = out.bytes_in as f64 / out.bytes_out as f64;
        eprintln!(
            "log10 f1: {} -> {} B ({:.2}:1)",
            out.bytes_in, out.bytes_out, ratio
        );
        assert!(
            ratio > 4.0,
            "log10 f1 ratio {ratio:.2} below the expected ~6:1"
        );
    }

    /// Acceptance (downscale2x + lossless): A001 f1 end-to-end — decimate
    /// 2× (reference staircase — the CFA-phase-correct rule; the old even/even
    /// was a single-phase plane with a color cast), 16
    /// half-resolution tiles (4×4 grid; last row 482×269
    /// padded to full-272 geometry), downscale surgery (256/257 halved,
    /// 50719/50720/50829 patched, 51089/51090/51091 added) + BOTH verify
    /// gates (bit-exact vs the decimated reference plane + the ds2x
    /// expected-diff metadata set).
    #[test]
    fn real_a001_frame1_downscale2x_end_to_end() {
        let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let src = match std::fs::read(p) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                return;
            }
        };
        let frame = crate::tiff::read(&src).unwrap();
        let packed = frame.strip_slice(&src);
        let samples = crate::pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let rule = crate::downscale::decimation_rule(&src, &frame);
        let (half, hw, hh) =
            crate::downscale::decimate2x(&samples, frame.width, frame.height, rule);
        assert_eq!((hw, hh), (1928, 1085));

        let grid = crate::tileenc::Grid::new(hw, hh);
        assert_eq!(
            (grid.cols, grid.rows),
            (4, 4),
            "1928x1085 must be 4x4 = 16 tiles"
        );
        let mut tiles = Vec::with_capacity(16);
        for r in 0..grid.rows {
            for c in 0..grid.cols {
                let rect = crate::tileenc::tile_region(hw, hh, &grid, r, c).unwrap();
                if r < 3 {
                    assert_eq!((rect.tw, rect.tl), (482, 272));
                } else {
                    // Last-row tiles: 482×269 → padded to full-272 geometry
                    // (reference contract; wraps allowed — the old
                    // LibRaw-safety natural-forcing was superseded by the
                    // the parity decision).
                    assert_eq!((rect.tw, rect.tl), (482, 269));
                }
                // Adaptive encode (the measured 3 candidates); the content
                // gate below decodes every tile and checks bit-exactness
                // vs the decimated reference plane regardless of the
                // per-tile orientation/PSV choice.
                tiles.push(crate::tileenc::encode_tile(&half, hw, hh, &grid, r, c, 12).unwrap());
            }
        }

        // Content gate: bit-exact vs the decimated reference plane.
        crate::verify::bit_exact_downscale_tiled(&frame, &src, &grid, &tiles)
            .expect("downscale content gate");

        let origin = ifd_tag_longs(&src, &frame, 50719).unwrap();
        assert_eq!(origin.len(), 2, "fp 50719 must be count 2");
        let ds = crate::surgery::Ds2x {
            width: hw,
            height: hh,
            crop_origin: crate::surgery::ds2x_crop_origin([origin[0], origin[1]]),
            crop_size: [1920, 1080],
            active_area: [0, 0, 1085, 1928],
            original_size: [3840, 2160],
        };
        let out = apply_tiled_downscale(&src, &frame, &tiles, &ds).expect("downscale surgery");

        // Metadata gate: the ds2x expected-diff set.
        crate::verify::metadata_preserved_tiled_downscale(&src, &out.bytes, &frame, &tiles)
            .expect("downscale metadata gate");

        // Geometry: 58 entries - 3 strip + 4 tile + 3 proxy = 62 entries →
        // +48 B shift; file = header + IFD + blob + 324/325 arrays (16×4
        // each) + proxy values (24 B) + tiles.
        let tile_total: usize = tiles.iter().map(|t| t.len()).sum();
        let expected_end = (frame.data_end + 48 + 64 + 64 + 24 + tile_total as u64) as usize;
        assert_eq!(out.bytes.len(), expected_end, "downscale file layout drift");
        // Re-parse the output: 62 IFD0 entries, 256/257 halved, proxy tags
        // present with the original crop size.
        let meta = crate::tiff::read_meta(&out.bytes).expect("downscale output must parse");
        assert_eq!(
            meta.ifd0.entries.len(),
            62,
            "expected 62 IFD0 entries (58-3+4+3)"
        );
        let get = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag).unwrap();
        assert_eq!(meta.endianness.u32(&get(256).value_raw), 1928);
        assert_eq!(meta.endianness.u32(&get(257).value_raw), 1085);
        assert_eq!(meta.endianness.u16(&get(259).value_raw), 7);
        for &tag in [51089u16, 51090, 51091].iter() {
            let en = get(tag);
            assert_eq!(en.typ, 4, "tag {tag} must be LONG");
            assert_eq!(en.count, 2);
            let (p, _) = en.out_of_line.expect("proxy tag out-of-line");
            let w = meta.endianness.u32(&out.bytes[p as usize..p as usize + 4]);
            let l = meta
                .endianness
                .u32(&out.bytes[p as usize + 4..p as usize + 8]);
            assert_eq!(
                (w, l),
                (3840, 2160),
                "tag {tag} must carry the original crop size"
            );
        }
        // TimeCodes 51043 untouched (out-of-line, blob-copied).
        let tc_in = {
            let m_in = crate::tiff::read_meta(&src).unwrap();
            let en = m_in.ifd0.entries.iter().find(|en| en.tag == 51043).unwrap();
            let (p, _) = en.out_of_line.unwrap();
            src[p as usize..p as usize + 8].to_vec()
        };
        let en = get(51043);
        let (p, _) = en.out_of_line.unwrap();
        assert_eq!(
            tc_in,
            out.bytes[p as usize..p as usize + 8].to_vec(),
            "TimeCodes must be byte-identical"
        );

        let ratio = out.bytes_in as f64 / out.bytes_out as f64;
        eprintln!(
            "downscale2x f1: {} -> {} B ({:.2}:1 over full-res input)",
            out.bytes_in, out.bytes_out, ratio
        );
        // Half-resolution plane: ~1/4 of the 12-bit packed data + 16 (not
        // 64) tile streams → expect well above the full-res 5.18:1 f1.
        assert!(
            ratio > 9.0,
            "downscale f1 ratio {ratio:.2} below the expected ~10:1"
        );

        // Negative gate: the FULL-resolution lossless output must FAIL the
        // ds2x metadata gate (256 is not halved) — the expected-diff sets
        // are combination-specific.
        let out_full =
            apply_tiled(&src, &frame, &full_tiles(&samples)).expect("full-res lossless surgery");
        assert!(
            crate::verify::metadata_preserved_tiled_downscale(
                &src,
                &out_full.bytes,
                &frame,
                &full_tiles(&samples)
            )
            .is_err(),
            "full-res output must fail the ds2x metadata gate"
        );
    }

    /// Encode the full-resolution 64-tile set (helper for the negative
    /// gate check in the downscale test).
    fn full_tiles(samples: &[u16]) -> Vec<Vec<u8>> {
        let g = crate::tileenc::Grid::new(3856, 2170);
        let mut v = Vec::with_capacity(64);
        for r in 0..g.rows {
            for c in 0..g.cols {
                v.push(crate::tileenc::encode_tile(samples, 3856, 2170, &g, r, c, 12).unwrap());
            }
        }
        v
    }

    /// Acceptance (downscale2x + log10): A001 f1 end-to-end — the log10
    /// curve applied to the DEIMATED plane (log codes are mode-orthogonal
    /// to the proxy geometry), 10-bit tiles at half resolution, surgery
    /// with both the log10 and ds2x tag sets, both gates.
    #[test]
    fn real_a001_frame1_downscale2x_log10_end_to_end() {
        let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let src = match std::fs::read(p) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                return;
            }
        };
        let frame = crate::tiff::read(&src).unwrap();
        let packed = frame.strip_slice(&src);
        let samples = crate::pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let rule = crate::downscale::decimation_rule(&src, &frame);
        let (half, hw, hh) =
            crate::downscale::decimate2x(&samples, frame.width, frame.height, rule);
        let inv = crate::log10::inv();
        let codes: Vec<u16> = half.iter().map(|v| inv[*v as usize]).collect();

        let grid = crate::tileenc::Grid::new(hw, hh);
        let mut tiles = Vec::with_capacity(16);
        for r in 0..grid.rows {
            for c in 0..grid.cols {
                tiles.push(crate::tileenc::encode_tile(&codes, hw, hh, &grid, r, c, 10).unwrap());
            }
        }
        // Content gate: LUT-inverted reconstruction within the curve bound.
        let stats = crate::verify::log10_content_downscale_tiled(&frame, &src, &grid, &tiles)
            .expect("downscale log10 content gate");
        assert!(stats.max_err <= crate::log10::max_recon_error());
        // A001 dark clip: the full-res canary worst case is 2 LSB; the
        // decimated plane is a sub-lattice of the same values → same bound.
        assert!(
            stats.max_err <= 2,
            "f1 ds2x log10 max err {} drifted from the A001 canary",
            stats.max_err
        );
        eprintln!(
            "ds2x log10 f1: max {} mean {:.4} <=1:{:.3}% ({} samples)",
            stats.max_err, stats.mean_abs, stats.pct_le_1, stats.samples
        );

        let origin = ifd_tag_longs(&src, &frame, 50719).unwrap();
        let ds = crate::surgery::Ds2x {
            width: hw,
            height: hh,
            crop_origin: crate::surgery::ds2x_crop_origin([origin[0], origin[1]]),
            crop_size: [1920, 1080],
            active_area: [0, 0, 1085, 1928],
            original_size: [3840, 2160],
        };
        let out = apply_tiled_downscale_log10(&src, &frame, &tiles, &ds)
            .expect("downscale log10 surgery");

        // Metadata gate: the ds2x + log10 expected-diff set.
        crate::verify::metadata_preserved_tiled_downscale_log10(&src, &out.bytes, &frame, &tiles)
            .expect("downscale log10 metadata gate");

        // Geometry: 58 - 3 + 4 + 1 (LUT) + 3 (proxy) = 63 entries → +60 B;
        // file end = blob + 60 + 324/325 arrays + LUT (2048) + proxy (24)
        // + tiles.
        let tile_total: usize = tiles.iter().map(|t| t.len()).sum();
        let expected_end = (frame.data_end + 60 + 64 + 64 + 2048 + 24 + tile_total as u64) as usize;
        assert_eq!(
            out.bytes.len(),
            expected_end,
            "downscale log10 file layout drift"
        );
        let meta = crate::tiff::read_meta(&out.bytes).unwrap();
        assert_eq!(meta.ifd0.entries.len(), 63);
        let get = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag).unwrap();
        assert_eq!(
            meta.endianness.u16(&get(258).value_raw),
            10,
            "BitsPerSample must be 10"
        );
        assert_eq!(meta.endianness.u32(&get(256).value_raw), 1928);
        assert_eq!(get(50712).count, 1024, "LUT tag present");

        let ratio = out.bytes_in as f64 / out.bytes_out as f64;
        eprintln!(
            "ds2x log10 f1: {} -> {} B ({:.2}:1 over full-res input)",
            out.bytes_in, out.bytes_out, ratio
        );
        // 10-bit codes at half resolution: above the full-res log10 7.14:1.
        assert!(
            ratio > 12.0,
            "downscale log10 f1 ratio {ratio:.2} below the expected ~14:1"
        );
    }

    /// Acceptance (lossy 34892/LinearRaw/8-bit): A001 f1 end-to-end — the
    /// 12→8 downshift (`v12 >> 4`), 8-bit baseline-DCT tiles (q60 = vbr-hq
    /// preset), the lossy tag surgery (Compression 1→34892, BitsPerSample
    /// 12→8, Photometric 32803→34892, ColorMatrix 50721/50722 dropped,
    /// LinearizationTable 50712 SHORT×256, NewRawImageDigest 51111
    /// BYTE×16) and BOTH verify gates (the 8-bit MAE/PSNR content gate +
    /// the lossy expected-diff metadata set, which recomputes the digest).
    #[test]
    fn real_a001_frame1_lossy_end_to_end() {
        let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let src = match std::fs::read(p) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                return;
            }
        };
        let frame = crate::tiff::read(&src).unwrap();
        let packed = frame.strip_slice(&src);
        let samples = crate::pack12::unpack12(packed, frame.width, frame.height).unwrap();
        // 12 → 8 downshift (the 12→8 shift cancels in the content gate, so
        // the MAE/PSNR isolates the JPEG DCT error).
        let plane8: Vec<u8> = samples.iter().map(|v| (*v >> 4) as u8).collect();
        let grid = crate::tileenc::Grid::new(frame.width, frame.height);
        let q = crate::lossy::VBR_HQ_QUALITY;
        let mut tiles = Vec::with_capacity((grid.cols * grid.rows) as usize);
        for r in 0..grid.rows {
            for c in 0..grid.cols {
                let rect =
                    crate::tileenc::tile_region(frame.width, frame.height, &grid, r, c).unwrap();
                tiles.push(crate::lossy::encode_tile8(&plane8, frame.width, &rect, q).unwrap());
            }
        }
        // Content gate: 8-bit MAE/PSNR vs the downshifted source.
        let stats = crate::verify::lossy_content_tiled(&frame, &src, &grid, &tiles)
            .expect("lossy content gate");
        eprintln!(
            "lossy f1 q{q}: mae {:.3} psnr {:.1} dB max {} ({} samples)",
            stats.mae, stats.psnr, stats.max_err, stats.samples
        );
        assert_eq!(stats.samples, (frame.width as u64) * (frame.height as u64));
        // Canary (measured on this dark clip: MAE ~0.34, PSNR
        // ~51 dB at q60). Loose bounds — the values are content-dependent,
        // but the sanity floor guards a broken codec pair.
        assert!(
            stats.mae < 5.0,
            "lossy f1 MAE {} above the dark-clip canary",
            stats.mae
        );
        assert!(
            stats.psnr > 45.0,
            "lossy f1 PSNR {} below the dark-clip canary",
            stats.psnr
        );

        // Surgery: the lossy tag plan + the NewRawImageDigest.
        let digest = crate::lossy::new_raw_image_digest(&tiles);
        let out = apply_tiled_lossy(&src, &frame, &tiles, digest).expect("lossy surgery");

        // Metadata gate: the lossy expected-diff set (recomputes the digest
        // from the tiles and checks the LUT bytes, the tag values, and that
        // everything else — CFA, BlackLevel, WhiteLevel 4095 — is unchanged).
        crate::verify::metadata_preserved_tiled_lossy(&src, &out.bytes, &frame, &tiles)
            .expect("lossy metadata gate");

        // Geometry: 58 - 5 (273/278/279 + 50721/50722) + 4 (tile) + 1 (LUT)
        // + 1 (digest) = 59 entries → +12 B shift; file end = blob + 12 +
        // 324/325 arrays (256 each) + LUT (512) + digest (16) + tiles.
        let tile_total: usize = tiles.iter().map(|t| t.len()).sum();
        let expected_end =
            (frame.data_end + 12 + 256 + 256 + 512 + 16 + tile_total as u64) as usize;
        assert_eq!(out.bytes.len(), expected_end, "lossy file layout drift");

        // Re-parse the output: 59 IFD0 entries + the lossy tag values.
        let meta = crate::tiff::read_meta(&out.bytes).expect("lossy output must parse");
        assert_eq!(
            meta.ifd0.entries.len(),
            59,
            "expected 59 IFD0 entries (58-5+6)"
        );
        let get = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag).unwrap();
        assert_eq!(
            meta.endianness.u16(&get(259).value_raw),
            34892,
            "Compression must be 34892"
        );
        assert_eq!(
            meta.endianness.u16(&get(258).value_raw),
            8,
            "BitsPerSample must be 8"
        );
        assert_eq!(
            meta.endianness.u16(&get(262).value_raw),
            34892,
            "Photometric must be 34892 (LinearRaw)"
        );
        assert_eq!(get(50712).count, 256, "LUT tag SHORT count 256");
        assert_eq!(get(51111).count, 16, "digest tag BYTE count 16");
        // ColorMatrix dropped; WhiteLevel kept at 4095 (LUT present ⇒ the
        // 12-bit white level; the source is already 4095).
        assert!(
            meta.ifd0.entries.iter().all(|en| en.tag != 50721),
            "50721 must be dropped"
        );
        assert!(
            meta.ifd0.entries.iter().all(|en| en.tag != 50722),
            "50722 must be dropped"
        );
        assert_eq!(
            meta.endianness.u32(&get(50717).value_raw),
            4095,
            "WhiteLevel kept at 4095"
        );
        // Digest value = the recomputed MD5 of the per-tile MD5s.
        let (dp, _) = get(51111).out_of_line.expect("digest out-of-line");
        assert_eq!(
            out.bytes[dp as usize..dp as usize + 16],
            digest.to_vec(),
            "digest mismatch"
        );

        let ratio = out.bytes_in as f64 / out.bytes_out as f64;
        eprintln!(
            "lossy f1 q{q}: {} -> {} B ({:.2}:1 over full-res input)",
            out.bytes_in, out.bytes_out, ratio
        );
        // Dark clip: even q60 compresses far beyond 10:1 (content-dependent;
        // the CBR modes are the ones that target a specific ratio).
        assert!(
            ratio > 10.0,
            "lossy f1 ratio {ratio:.2} below the expected dark-clip ratio"
        );

        // Negative gate: the lossless output must FAIL the lossy metadata
        // gate (259 is 7, not 34892) — the expected-diff sets are
        // mode-specific.
        let lt = full_tiles(&samples);
        let out_ll = apply_tiled(&src, &frame, &lt).expect("lossless surgery for negative gate");
        assert!(
            crate::verify::metadata_preserved_tiled_lossy(&src, &out_ll.bytes, &frame, &lt)
                .is_err(),
            "lossless output must fail the lossy metadata gate"
        );
    }

    #[test]
    fn real_a001_surgery() {
        let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let src = match std::fs::read(p) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                return;
            }
        };
        let frame = crate::tiff::read(&src).unwrap();
        let packed = frame.strip_slice(&src);
        let samples = crate::pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let jpeg =
            crate::codec::encode_lossless(&samples, frame.width, frame.height, 12).expect("encode");
        let out = apply(&src, &frame, &jpeg);

        // header preserved except the two patched tags
        crate::verify::metadata_preserved(&src, &out.bytes, &frame)
            .expect("header must be byte-preserved");
        // bit-exact roundtrip
        crate::verify::bit_exact(&frame, &src, &jpeg).expect("bit-exact");

        // geometry sanity
        assert_eq!(out.bytes_out, frame.strip_offset as usize + jpeg.len());
        assert!(out.bytes_out < out.bytes_in, "lossless must shrink");
        let ratio = out.bytes_in as f64 / out.bytes_out as f64;
        eprintln!(
            "surgery frame 1: {} -> {} B ({:.2}:1)",
            out.bytes_in, out.bytes_out, ratio
        );
        assert!(
            ratio > 1.5,
            "expected > 1.5:1 on this dark clip, got {ratio:.2}"
        );

        // re-parse the OUTPUT as a frame (it is now Compression=7; tiff::read
        // refuses compressed input by design — instead just check the patched
        // values landed where tiff said they would).
        let comp = u16::from_le_bytes([
            out.bytes[frame.compression_value_offset as usize],
            out.bytes[frame.compression_value_offset as usize + 1],
        ]);
        assert_eq!(comp, 7);
        let cnt = u32::from_le_bytes([
            out.bytes[frame.strip_count_value_offset as usize],
            out.bytes[frame.strip_count_value_offset as usize + 1],
            out.bytes[frame.strip_count_value_offset as usize + 2],
            out.bytes[frame.strip_count_value_offset as usize + 3],
        ]);
        assert_eq!(cnt as usize, jpeg.len());
    }

    // ------------------------------------------------- 50707 enforcement

    /// The value-field file offset of 50707 (DNGBackwardVersion) in a
    /// parsed fp frame's IFD0 (inline 4-byte value).
    fn backward_version_offset(frame: &crate::tiff::Frame) -> u64 {
        let itab = &frame.ifd0;
        for (i, en) in itab.entries.iter().enumerate() {
            if en.tag == 50707 {
                assert!(en.out_of_line.is_none(), "50707 must be in-line");
                assert_eq!((en.typ, en.count), (1, 4), "fp 50707 = BYTE count 4");
                return itab.off + 2 + (i as u64) * 12 + 8;
            }
        }
        panic!("50707 not found in IFD0");
    }

    /// Read 50707 out of a (possibly output) file via the metadata parse.
    /// The version value is a fixed-order BYTE[4] array (major, minor,
    /// tweak, bugfix) — 0x01040000 is the big-endian reading of the stored
    /// bytes [01 04 00 00] (NOT a file-endian LONG).
    fn read_backward_version(bytes: &[u8]) -> u32 {
        let meta = crate::tiff::read_meta(bytes).unwrap();
        let en = meta.ifd0.entries.iter().find(|en| en.tag == 50707).unwrap();
        u32::from_be_bytes(en.value_raw)
    }

    /// end-to-end: a source frame with DNGBackwardVersion
    /// BELOW 1.4.0.0 (the fp frame is exactly 1.4.0.0; this test lowers a
    /// scratch copy to 1.3.0.0) must come out ≥ 1.4.0.0 in every plan that
    /// requires it (lossy 34892, ds2x proxy tags), while lossless leaves
    /// it untouched. The verify gate enforces out == max(src, 1.4.0.0).
    #[test]
    fn real_a001_backward_version_enforced() {
        let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let src = match std::fs::read(p) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                return;
            }
        };
        let frame = crate::tiff::read(&src).unwrap();
        // The fp frame is exactly 1.4.0.0.
        assert_eq!(read_backward_version(&src), 0x01040000);

        // Lower a scratch copy to 1.3.0.0 (the 4-byte in-line value is a
        // fixed-order BYTE[4] major.minor.tweak.bugfix — [01 03 00 00]).
        let mut low = src.clone();
        let off = backward_version_offset(&frame) as usize;
        low[off..off + 4].copy_from_slice(&0x01030000u32.to_be_bytes());
        let low_frame = crate::tiff::read(&low).unwrap();
        assert_eq!(read_backward_version(&low), 0x01030000);

        // Synthetic small tiles (surgery + metadata gates only — the
        // content gate is covered by the mode e2e tests).
        let tiles64: Vec<Vec<u8>> = vec![vec![0xABu8; 16]; 64];
        let tiles16: Vec<Vec<u8>> = vec![vec![0xCDu8; 16]; 16];

        // --- lossy plan: 50707 bumped to 1.4.0.0 --------------------------
        let digest = crate::lossy::new_raw_image_digest(&tiles64);
        let out = apply_tiled_lossy(&low, &low_frame, &tiles64, digest)
            .expect("lossy surgery on below-1.4 source");
        assert_eq!(
            read_backward_version(&out.bytes),
            0x01040000,
            "lossy output must be ≥ 1.4.0.0"
        );
        crate::verify::metadata_preserved_tiled_lossy(&low, &out.bytes, &low_frame, &tiles64)
            .expect("lossy metadata gate with bumped 50707");

        // --- negative gate: an output that DID NOT bump 50707 must fail --
        let mut bad = out.bytes.clone();
        let bad_meta = crate::tiff::read_meta(&bad).unwrap();
        for (i, en) in bad_meta.ifd0.entries.iter().enumerate() {
            if en.tag == 50707 {
                let o = bad_meta.ifd0.off as usize + 2 + i * 12 + 8;
                bad[o..o + 4].copy_from_slice(&0x01030000u32.to_be_bytes());
            }
        }
        assert!(
            crate::verify::metadata_preserved_tiled_lossy(&low, &bad, &low_frame, &tiles64)
                .is_err(),
            "an un-bumped 50707 must FAIL the lossy metadata gate"
        );

        // --- ds2x plan: the proxy tags require 1.4 too --------------------
        let origin = ifd_tag_longs(&low, &low_frame, 50719).unwrap();
        let ds = crate::surgery::Ds2x {
            width: 1928,
            height: 1085,
            crop_origin: crate::surgery::ds2x_crop_origin([origin[0], origin[1]]),
            crop_size: [1920, 1080],
            active_area: [0, 0, 1085, 1928],
            original_size: [3840, 2160],
        };
        let out = apply_tiled_downscale(&low, &low_frame, &tiles16, &ds)
            .expect("ds2x surgery on below-1.4 source");
        assert_eq!(
            read_backward_version(&out.bytes),
            0x01040000,
            "ds2x output must be ≥ 1.4.0.0"
        );
        crate::verify::metadata_preserved_tiled_downscale(&low, &out.bytes, &low_frame, &tiles16)
            .expect("ds2x metadata gate with bumped 50707");

        // --- lossless plan: 50707 is NOT enforced (no 1.4-only tags) ------
        let out = apply_tiled(&low, &low_frame, &tiles64).expect("lossless surgery");
        assert_eq!(
            read_backward_version(&out.bytes),
            0x01030000,
            "lossless keeps 50707 byte-identical"
        );
        crate::verify::metadata_preserved_tiled(&low, &out.bytes, &low_frame, &tiles64)
            .expect("lossless metadata gate with un-bumped 50707");

        // --- a source already ≥ 1.4.0.0 (the fp itself) is untouched ------
        let out = apply_tiled_lossy(
            &src,
            &frame,
            &tiles64,
            crate::lossy::new_raw_image_digest(&tiles64),
        )
        .expect("lossy surgery on the 1.4.0.0 original");
        assert_eq!(read_backward_version(&out.bytes), 0x01040000);
        // And the 50707 VALUE FIELD bytes are identical to the source's
        // (no patch applied → the output stays byte-identical there).
        let soff = backward_version_offset(&frame) as usize;
        assert_eq!(
            &src[soff..soff + 4],
            &out.bytes[soff..soff + 4],
            "no-op patch must leave 50707 bytes untouched"
        );
    }

    /// the validate_pointers refusal clause — an IFD-pointer
    /// tag with count > 1 (its in-array pointers would stay stale) is
    /// refused; the fp's count-1 inline shape passes.
    #[test]
    fn validate_pointers_refuses_ifd_pointer_array() {
        use crate::tiff::{IfdEntry, IfdTable};
        let arr = IfdEntry {
            tag: 34665,
            typ: 4,
            count: 2,
            value_raw: [0, 0, 0, 0],
            out_of_line: Some((100, 108)),
        };
        let t = IfdTable {
            off: 8,
            struct_range: 8..22,
            entries: vec![arr],
            next_ifd: 0,
        };
        assert!(matches!(
            validate_pointers(&[t], 0, 200),
            Err(SurgeryError::IfdPointerArray {
                tag: 34665,
                count: 2
            })
        ));
        // C14 SLOFFSET (14) is an IFD-pointer type too.
        let sloff = IfdEntry {
            tag: 330,
            typ: 14,
            count: 3,
            value_raw: [0, 0, 0, 0],
            out_of_line: Some((100, 124)),
        };
        let t = IfdTable {
            off: 8,
            struct_range: 8..22,
            entries: vec![sloff],
            next_ifd: 0,
        };
        assert!(matches!(
            validate_pointers(&[t], 0, 300),
            Err(SurgeryError::IfdPointerArray { .. })
        ));
        // The fp shape: count-1 inline IFD pointer — allowed.
        let ok = IfdEntry {
            tag: 34665,
            typ: 4,
            count: 1,
            value_raw: [8, 0, 0, 0],
            out_of_line: None,
        };
        let t = IfdTable {
            off: 8,
            struct_range: 8..22,
            entries: vec![ok],
            next_ifd: 0,
        };
        assert!(validate_pointers(&[t], 0, 200).is_ok());
    }

    /// f2/f113/f225 decode-and-compare (the acceptance
    /// criterion covers the full clip; cargo test previously decoded only
    /// f1). Lossless tile surgery + the bit-exact gate on three spread-out
    /// frames of A001.
    #[test]
    fn real_a001_f2_f113_f225_decode_and_compare() {
        for name in ["000002", "000113", "000225"] {
            let p = format!("../testdata/originals/A001_001/A001_001_20260701_{name}.DNG");
            let src = match std::fs::read(&p) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("skip: {p} ({err})");
                    return;
                }
            };
            let frame = crate::tiff::read(&src).unwrap();
            let packed = frame.strip_slice(&src);
            let samples = crate::pack12::unpack12(packed, frame.width, frame.height).unwrap();
            let grid = crate::tileenc::Grid::new(frame.width, frame.height);
            let mut tiles = Vec::with_capacity(64);
            for r in 0..grid.rows {
                for c in 0..grid.cols {
                    tiles.push(
                        crate::tileenc::encode_tile(
                            &samples,
                            frame.width,
                            frame.height,
                            &grid,
                            r,
                            c,
                            12,
                        )
                        .unwrap(),
                    );
                }
            }
            // The acceptance gate: golden-model decode == unpacked input.
            crate::verify::bit_exact_tiled(&frame, &src, &grid, &tiles)
                .unwrap_or_else(|err| panic!("{name}: bit-exact gate: {err}"));
            // Surgery + the metadata expected-diff set.
            let out = apply_tiled(&src, &frame, &tiles).expect("surgery");
            crate::verify::metadata_preserved_tiled(&src, &out.bytes, &frame, &tiles)
                .unwrap_or_else(|err| panic!("{name}: metadata gate: {err}"));
            eprintln!(
                "{name}: {} -> {} B ({:.2}:1) bit-exact + metadata OK",
                out.bytes_in,
                out.bytes_out,
                out.bytes_in as f64 / out.bytes_out as f64
            );
        }
    }
}
