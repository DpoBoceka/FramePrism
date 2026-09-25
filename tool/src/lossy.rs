//! Lossy cDNG (Compression 34892, PhotometricInterpretation LinearRaw) —
//! The parked lossy tier: VBR HQ/LT + CBR 3/4/5/7:1 presets.
//!
//! MECHANISM (the DNG 1.7.1 contract;
//! reference decoders DNG SDK
//! `dng_read_image::DecodeLossyJPEG` + LibRaw `lossy_dng_load_raw`):
//!
//! - The 12-bit source plane is reduced to 8-bit with a plain right-shift
//!   `code8 = v12 >> 4` (task-specified; 16:1 quantization, 4-bit LSB drop).
//!   The shift is an encoder-side pre-transform — the STORED data is natively
//!   8-bit integer, exactly what 34892 requires ("Lossy JPEG is allowed for
//!   IFDs that use 8-bit integer data", spec p.21).
//! - Each DNG tile (the SAME 482×272 reference grid as the lossless modes;
//!   A001 → 8×8 = 64 tiles, last row 266 tall) is ONE self-contained
//!   **baseline DCT JPEG (SOF0)** stream, **1 component**, 8-bit, whose
//!   SOF width/height EQUAL the tile area and whose component count EQUALS
//!   the plane count. The reference decoders enforce both:
//!     * DNG SDK `DecodeLossyJPEG`: `imageWidth==tileArea.W() &&
//!       imageHeight==tileArea.H() && numComponents==planes` else
//!       "JPEG dimensions do not match tile". For mono LinearRaw (ColorMatrix
//!       dropped → fColorPlanes=1) planes=1 ⇒ **1 component, SOF==tile area**.
//!     * LibRaw `lossy_dng_load_raw`: `cinfo.output_components==colors` else
//!       throw. MEASURED MONO-LOSSY REJECTION (the bundled LibRaw
//!       build instrumented + rawpy 0.25 on the same outputs): for a 34892 frame
//!       `identify` sets `filters = 0`, so `colors = tiff_samples = 1`
//!       REGARDLESS of the CFA tags (there is no CFAPlaneColor in the fp
//!       frame, and none would matter — the CFA tags do not feed `colors`
//!       for 34892 frames). `unpack()` then routes on
//!       `imgdata.idata.filters || P1.colors == 1` → the "single color →
//!       decode to raw_image" branch allocates ONLY `raw_image`, leaving
//!       `imgdata.image` NULL; `lossy_dng_load_raw` starts with
//!       `if (!image) throw LIBRAW_EXCEPTION_IO_CORRUPT` → -100009 →
//!       rawpy `LibRawIOError('Input/output error')` at `.raw_image` (open
//!       itself succeeds). So NO CFA tag configuration makes this LibRaw
//!       version decode a mono lossy cDNG — the rejection is the decoder's
//!       allocation path, not the tags. The DNG-SDK family (Resolve/Fusion)
//!       decodes 1-component LinearRaw fine and is the archive target; the
//!       own decode is the acceptance gate. (A 3-SAMPLE lossy DNG takes
//!       the other unpack branch — `image` allocated — which is why the
//!       SDK glue routes 3-sample lossy to the DNG SDK.)
//! - The even/odd 2-component parity-plane structure of the LOSSLESS modes
//!   does NOT carry over: it is a lossless-predictor device (PSV 7 on
//!   same-phase planes) and 34892 + mono LinearRaw is 1-component. Each lossy
//!   tile is a standard single-component DCT JPEG of the tile's 8-bit region.
//!
//! TAGS (the lossy expected-diff set — see `verify::
//! metadata_preserved_tiled_lossy` and `surgery::TilePlan`):
//!   - 258 BitsPerSample 12 → 8; 259 Compression 1 → 34892; 262
//!     PhotometricInterpretation 32803 → 34892 (in-line SHORT patches).
//!   - 50721/50722 ColorMatrix1/2 DROPPED (→ fColorPlanes=1 ⇒ SamplesPerPixel
//!     1 valid for LinearRaw; keeping them would force spp=3, invalid for
//!     1-plane data).
//!   - 50712 LinearizationTable ADDED (SHORT count 256): `LUT[i] = i*16`,
//!     the 12-bit linear value (bin lower edge) represented by 8-bit code i.
//!     WhiteLevel (50717) stays **4095** (12-bit linear domain — legal
//!     because a LUT is present ⇒ SDK maxWhite=65535). This signals the
//!     12→8 mapping so SDK/NLE decoders reconstruct 12-bit linear.
//!   - 51111 NewRawImageDigest ADDED (16 B) = MD5(concat of per-tile MD5s in
//!     324 order) — the SDK's lossy-digest convention; 50972 is absent
//!     in the source so nothing is dropped.
//!   - 322/323/324/325 tile tags ADDED, 273/278/279 strip tags DROPPED.
//!   - DNGVersion/DNGBackwardVersion (50706/50707): ENFORCED ≥ 1.4.0.0
//!     (0x01040000) — 34892 requires it (spec Issue 11); the surgery
//!     patches 50707 in place when the source is below. The fp frame is
//!     already exactly 1.4.0.0 → no-op on A001.
//!   - CFA tags (33421 CFARepeatPatternDim [2,2], 33422 CFAPattern [0,1,1,2],
//!     50711 CFALayout 1) and BlackLevel (50713/50714) KEPT byte-identical
//!     (the corrected contract): the spec
//!     does not forbid CFA tags under LinearRaw; the SDK only WARNS via
//!     CheckCFA (non-fatal); a 1-sample CFA rewrite was evaluated and
//!     REJECTED as a fix for the LibRaw rejection (measured: it cannot reach
//!     the decoder's allocation path — see above); tags kept for Resolve
//!     color metadata. TimeCodes/FrameRate/TStop/Serial/DNGPrivateData/
//!     ExifIFD/NoiseProfile/OpcodeList3/50781 all KEPT.
//!
//! RATE CONTROL:
//!   - CBR k: per-frame target = in_bytes / k (in_bytes = the ORIGINAL frame
//!     file size). libjpeg quality (1..100) is binary-searched so the TOTAL
//!     output file lands closest-under target*1.05 (a quality→size monotonic
//!     search; a ±3 linear refinement window guards small non-monotonicities).
//!   - VBR HQ/LT: fixed per-mode quality (no per-frame search), validated on
//!     A001 against reference's published ~3–4:1 (HQ) / ~4–6:1 (LT).

use std::sync::OnceLock;

use thiserror::Error;

/// The lossy 8-bit LinearizationTable: `LUT[i] = i * 16` (the 12-bit linear
/// value, bin lower edge, represented by 8-bit code i of `v12 >> 4`).
pub const LUT_LEN: usize = 256;
pub static LUT: OnceLock<[u16; LUT_LEN]> = OnceLock::new();

fn build_lut() -> [u16; LUT_LEN] {
    let mut lut = [0u16; LUT_LEN];
    // `i` is the LUT index AND the value input (i * 16) — range loop is the
    // direct form (clippy allow).
    #[allow(clippy::needless_range_loop)]
    for i in 0..LUT_LEN {
        lut[i] = (i * 16) as u16; // i*16 ≤ 255*16 = 4080 < 4096
    }
    lut
}

/// The 256-entry LUT (tag 50712 content).
pub fn lut() -> &'static [u16; LUT_LEN] {
    LUT.get_or_init(build_lut)
}

/// LUT content as file-order SHORT bytes (512 B) — little-endian for the fp's
/// II\x2A\x00 files (same byte-order contract as `log10::lut_bytes`; a
/// big-endian LUT made rawpy apply a byte-swapped table — the decisions).
///
pub fn lut_bytes() -> Vec<u8> {
    let l = lut();
    let mut out = Vec::with_capacity(LUT_LEN * 2);
    for &v in l {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

#[derive(Error, Debug, Clone, PartialEq)]
pub enum LossyError {
    #[error("libjpeg lossy encode failed: {0}")]
    Encode(String),
    #[error("libjpeg lossy decode failed: {0}")]
    Decode(String),
    #[error("decoded tile {rows}x{cols} ncomp={nc} does not match the tile area {tw}x{tl} (1 component)")]
    GeometryMismatch {
        rows: u32,
        cols: u32,
        nc: u32,
        tw: u32,
        tl: u32,
    },
}

// --------------------------------------------------------------------- FFI

// C ABI declarations live in `crate::ljpeg_ffi` (single home, ).
use crate::ljpeg_ffi::{
    ljpeg_comp_error, ljpeg_comp_free, ljpeg_comp_new, ljpeg_decode_lossy1, ljpeg_decomp_error,
    ljpeg_decomp_free, ljpeg_decomp_new, ljpeg_encode_lossy1, ljpeg_free_buffer,
};

fn err_str(ptr: *const core::ffi::c_char, default: &str) -> String {
    if ptr.is_null() {
        return default.to_string();
    }
    // SAFETY: non-null C string owned by the shim handle (valid until the
    // next call on it), read only through `CStr`.
    unsafe {
        core::ffi::CStr::from_ptr(ptr)
            .to_string_lossy()
            .into_owned()
    }
}

/// Encode one tile's 8-bit region as a 1-component baseline DCT JPEG (SOF0).
/// `plane8` is the full frame (frame_w × frame_h, row-major); `rect` is the
/// tile area. The stream's SOF dims == (rect.tw, rect.tl), 1 component.
pub fn encode_tile8(
    plane8: &[u8],
    frame_w: u32,
    rect: &crate::tileenc::TileRect,
    quality: u32,
) -> Result<Vec<u8>, LossyError> {
    let tw = rect.tw as usize;
    let tl = rect.tl as usize;
    let fw = frame_w as usize;
    let mut tile = vec![0u8; tw * tl];
    for y in 0..tl {
        let s = (rect.y0 as usize + y) * fw + rect.x0 as usize;
        tile[y * tw..y * tw + tw].copy_from_slice(&plane8[s..s + tw]);
    }
    // SAFETY: `ljpeg_comp_new` is the shim's allocator (calloc); the
    // pointer is null-checked here and `ljpeg_comp_free`d on every exit
    // path below.
    let h = unsafe { ljpeg_comp_new() };
    if h.is_null() {
        return Err(LossyError::Encode("ljpeg_comp_new returned null".into()));
    }
    let mut outbuf: *mut u8 = std::ptr::null_mut();
    let mut outsize: core::ffi::c_ulong = 0;
    // SAFETY: live handle; `tile` outlives the call; `&mut outbuf/outsize`
    // are null-initialized locals the shim writes. On success `outbuf` is
    // malloc'd by the shim and freed exactly once below.
    let rc = unsafe {
        ljpeg_encode_lossy1(
            h,
            tile.as_ptr(),
            tw as core::ffi::c_int,
            tl as core::ffi::c_int,
            quality as core::ffi::c_int,
            &mut outbuf,
            &mut outsize,
        )
    };
    if rc != 0 {
        let msg = err_str(unsafe { ljpeg_comp_error(h) }, "encode failed");
        unsafe { ljpeg_comp_free(h) };
        return Err(LossyError::Encode(msg));
    }
    // SAFETY: rc == 0 ⇒ `outbuf` is valid for `outsize` bytes (shim-owned);
    // copied out before the single `ljpeg_free_buffer`.
    let jpeg = unsafe { std::slice::from_raw_parts(outbuf, outsize as usize) }.to_vec();
    // SAFETY: single free of the shim-malloc'd buffer + single free of the
    // handle, both now past their last use.
    unsafe {
        ljpeg_free_buffer(outbuf as *mut core::ffi::c_void);
        ljpeg_comp_free(h);
    }
    Ok(jpeg)
}

/// Decode one lossy tile stream (1-component 8-bit baseline DCT). Returns the
/// tile bytes (rows*cols) + the SOF dims + component count. The caller checks
/// the dims against the tile area (`decode_tile8_rected`).
pub fn decode_tile8(jpeg: &[u8]) -> Result<(Vec<u8>, u32, u32, u32), LossyError> {
    // SAFETY: `ljpeg_decomp_new` is the shim's allocator (calloc); the
    // pointer is null-checked here and `ljpeg_decomp_free`d on every exit
    // path below.
    let h = unsafe { ljpeg_decomp_new() };
    if h.is_null() {
        return Err(LossyError::Decode("ljpeg_decomp_new returned null".into()));
    }
    let mut out: *mut u8 = std::ptr::null_mut();
    let mut w: core::ffi::c_int = 0;
    let mut ht: core::ffi::c_int = 0;
    let mut nc: core::ffi::c_int = 0;
    // SAFETY: live handle; `jpeg` is a `&[u8]` borrow outliving the call,
    // `jpeg.len()` its exact length; the four `&mut` out-params are
    // initialized locals the shim writes. On success `out` is malloc'd by
    // the shim (ht × nc × w bytes) and freed exactly once below.
    let rc = unsafe {
        ljpeg_decode_lossy1(
            h,
            jpeg.as_ptr(),
            jpeg.len() as core::ffi::c_long,
            &mut out,
            &mut w,
            &mut ht,
            &mut nc,
        )
    };
    if rc != 0 {
        let msg = err_str(unsafe { ljpeg_decomp_error(h) }, "decode failed");
        unsafe { ljpeg_decomp_free(h) };
        return Err(LossyError::Decode(msg));
    }
    let (rows, cols, ncomp) = (ht as u32, w as u32, nc as u32);
    // SAFETY: rc == 0 ⇒ `out` holds rows × cols × ncomp bytes (the shim's
    // ht × nc × w allocation), copied out before the single
    // `ljpeg_free_buffer`.
    let bytes = unsafe { std::slice::from_raw_parts(out, (rows * cols * ncomp) as usize) }.to_vec();
    unsafe {
        ljpeg_free_buffer(out as *mut core::ffi::c_void);
        ljpeg_decomp_free(h);
    }
    Ok((bytes, rows, cols, ncomp))
}

/// Decode one lossy tile and verify its SOF dims == the tile area + 1
/// component (the DecodeLossyJPEG contract). Returns the tile bytes
/// (rect.tw × rect.tl, row-major).
pub fn decode_tile8_rected(
    jpeg: &[u8],
    rect: &crate::tileenc::TileRect,
) -> Result<Vec<u8>, LossyError> {
    let (bytes, rows, cols, ncomp) = decode_tile8(jpeg)?;
    if ncomp != 1 || rows != rect.tl || cols != rect.tw {
        return Err(LossyError::GeometryMismatch {
            rows,
            cols,
            nc: ncomp,
            tw: rect.tw,
            tl: rect.tl,
        });
    }
    Ok(bytes)
}

/// NewRawImageDigest (51111): MD5(concat of per-tile MD5s, in 324/tile order).
/// No JPEGTables tag is written (each tile is self-contained), so there is no
/// tables-digest prefix.
pub fn new_raw_image_digest(tiles: &[Vec<u8>]) -> [u8; 16] {
    use md5::compute;
    let mut concat = Vec::with_capacity(tiles.len() * 16);
    for t in tiles {
        concat.extend_from_slice(&compute(t).0);
    }
    compute(concat).0
}

// --------------------------------------------------------------- rate control

/// Fixed-quality presets for the VBR modes. Chosen on A001 to land near
/// reference's published ratios (HQ ~3–4:1, LT ~4–6:1 over the 12-bit input).
/// Validated in the full-clip run.
pub const VBR_HQ_QUALITY: u32 = 60;
pub const VBR_LT_QUALITY: u32 = 35;

/// Total output-file size for a given quality: the fixed surgery prefix
/// (header + IFD + blob + 324/325/LUT/digest arrays — content-independent)
/// plus the tile bytes. `prefix` is measured once (surgery with reference
/// tiles) and reused.
pub fn total_size(prefix: u64, tiles: &[Vec<u8>]) -> u64 {
    prefix + tiles.iter().map(|t| t.len() as u64).sum::<u64>()
}
/// Binary-search libjpeg quality (1..100) for the total output size closest
/// UNDER `limit` (= target*1.05), assuming total(q) increases with q. `total`
/// maps a quality to the total output size for that quality (the caller
/// caches the tile encodes so each quality is encoded once). Returns the
/// chosen quality. A ±3 linear refinement around the binary-search result
/// guards small quality→size non-monotonicities.
pub fn search_quality(limit: u64, total: &dyn Fn(u32) -> u64) -> u32 {
    // Binary search the largest q with total(q) <= limit.
    let (mut lo, mut hi, mut ans) = (1u32, 100u32, 1u32);
    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        if total(mid) <= limit {
            ans = mid;
            lo = mid + 1;
        } else {
            hi = mid.saturating_sub(1);
        }
    }
    // Linear refinement over [ans-3, ans+3] (clamped): pick the q whose total
    // is closest to limit from below (ties → higher q). This also catches a
    // small non-monotonic dip just above the binary-search boundary.
    let lo_r = ans.saturating_sub(3).max(1);
    let hi_r = (ans + 3).min(100);
    let mut best_q = ans;
    let mut best_size = total(ans);
    for q in lo_r..=hi_r {
        let s = total(q);
        if s <= limit && s >= best_size {
            best_q = q;
            best_size = s;
        }
    }
    best_q
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------- search_quality
    //
    // `search_quality` was claimed "unit-tested" in the w5 report but had
    // zero tests. These cover: the monotone curve (binary-search + refine
    // pick the largest-under-limit q), ties (→ higher q), a non-monotone
    // dip at/just beyond the ±3 refine window, and the documented
    // q1-over-limit behavior (q1 is returned; the limit is violated
    // rather than the encoder silently failing).

    /// total(q) = base + q*step (strictly monotone).
    fn monotone_total(base: u64, step: u64) -> impl Fn(u32) -> u64 {
        move |q: u32| base + q as u64 * step
    }

    #[test]
    fn search_quality_monotone_curve() {
        // total(q) = 1000 + q*100; limit 5500 → the largest q with
        // total(q) ≤ 5500 is q=45 (exactly at the limit).
        let q = search_quality(5500, &monotone_total(1000, 100));
        assert_eq!(q, 45, "monotone: largest-under-limit q");
        // limit 5450 → q=44 (5500 overshoots; 5400 is the closest under).
        let q = search_quality(5450, &monotone_total(1000, 100));
        assert_eq!(q, 44);
        // limit below total(1) → q1 (documented: the limit is violated
        // rather than erroring — caller-side CBR reporting notes this).
        let q = search_quality(1050, &monotone_total(1000, 100));
        assert_eq!(q, 1);
        // limit above total(100) → q100.
        let q = search_quality(20_000, &monotone_total(1000, 100));
        assert_eq!(q, 100);
    }

    #[test]
    fn search_quality_tie_prefers_higher_quality() {
        // Flat size curve (per-stream optimized Huffman can produce exact
        // ties): every q is under the limit and ties on size → the HIGHEST
        // quality wins (best rate/quality trade).
        let q = search_quality(5000, &|_| 5000);
        assert_eq!(q, 100, "flat curve → q100");
        // Tie at the boundary: total(44) == total(45) = 5450 (the limit),
        // q≥46 over → q45 must win the tie (higher quality).
        let total = |q: u32| {
            if q == 44 || q == 45 {
                5450
            } else {
                1000 + q as u64 * 100
            }
        };
        let q = search_quality(5450, &total);
        assert_eq!(q, 45, "boundary tie → higher q");
    }

    #[test]
    fn search_quality_boundary_dip_within_refine_window() {
        // A dip BEYOND the naive binary-search answer but inside the ±3
        // refine window: total is monotone 1000+q*100 except total(47)=5400
        // (a non-monotone dip). limit 5450: the monotone assumption says
        // q=44 (5400); the dip at q47 is ALSO under the limit and ties
        // q44's size → higher q (47) must win.
        let total = |q: u32| {
            if q == 47 {
                5400
            } else {
                1000 + q as u64 * 100
            }
        };
        let q = search_quality(5450, &total);
        assert_eq!(q, 47, "the refine window must recover a dip within ±3");
    }

    #[test]
    fn search_quality_dip_beyond_refine_window_stays_under_limit() {
        // A dip FARTHER than ±3 from the monotone boundary (q45 here) is
        // NOT recovered (known limitation, review — a suboptimal q
        // is picked, but the result must still be UNDER the limit (rate /
        // quality, not correctness, is at stake)).
        let total = |q: u32| {
            if q == 55 {
                5000 // a dip well beyond the q=45 boundary + the ±3 window
            } else {
                1000 + q as u64 * 100
            }
        };
        let limit = 5500;
        let q = search_quality(limit, &total);
        assert!(total(q) <= limit, "chosen q must stay under the limit");
        assert_eq!(q, 45, "dip beyond the window: boundary q wins");
    }

    #[test]
    fn search_quality_q1_over_limit_is_documented() {
        // total(1) > limit → q1 is returned and the limit is VIOLATED
        // (review: the CBR path reports this rather than failing;
        // on the A001 clip every frame's q100 is under every limit, so
        // this case needs a pathological size curve to exercise).
        let q = search_quality(100, &|q: u32| 10_000 + q as u64);
        assert_eq!(q, 1, "q1 fallback");
        assert!(10_001 > 100, "the limit is violated by construction");
        // And the result is always in range.
        for limit in [0u64, 1, 5, 100, 10_000, 1_000_000] {
            let q = search_quality(limit, &|q: u32| 500 + q as u64);
            assert!((1..=100).contains(&q), "limit {limit}: q={q} out of range");
        }
    }

    #[test]
    fn lut_exactness() {
        let l = lut();
        assert_eq!(l.len(), 256);
        assert_eq!(l[0], 0, "LUT[0] must be exactly 0");
        assert_eq!(l[255], 4080, "LUT[255] = 255*16");
        for i in 0..256 {
            assert_eq!(l[i], (i * 16) as u16);
            assert!(l[i] <= 4095);
        }
    }

    #[test]
    fn lut_bytes_layout() {
        let b = lut_bytes();
        assert_eq!(b.len(), 512, "tag 50712 = SHORT count 256 = 512 B");
        assert_eq!(&b[0..2], &[0x00, 0x00]); // LUT[0] = 0
        assert_eq!(&b[2..4], &[0x10, 0x00]); // LUT[1] = 16
        assert_eq!(&b[510..512], &[0xF0, 0x0F]); // LUT[255] = 4080 = 0x0FF0
    }

    #[test]
    fn downshift_matches_lut_inverse() {
        // code = v>>4; LUT[code] = the bin lower edge ≤ v < LUT[code]+16.
        let l = lut();
        for v in 0..4096u16 {
            let c = (v >> 4) as usize;
            assert_eq!(l[c], (c * 16) as u16);
            let lo = l[c] as u32;
            assert!((v as u32) >= lo);
            assert!((v as u32) < lo + 16);
        }
    }

    #[test]
    fn digest_stable_and_order_sensitive() {
        let a = vec![vec![1u8, 2, 3], vec![4, 5, 6]];
        let b = vec![vec![4u8, 5, 6], vec![1, 2, 3]];
        let da = new_raw_image_digest(&a);
        let db = new_raw_image_digest(&b);
        assert_eq!(da, new_raw_image_digest(&a), "digest must be deterministic");
        assert_ne!(da, db, "digest must be order-sensitive (tile order)");
        // MD5 of a single empty-tile set: known structure check (16 bytes).
        assert_eq!(new_raw_image_digest(&[]).len(), 16);
    }

    /// CBR lowering on REALISTIC content (review / 18d): a full-frame
    /// high-entropy 8-bit plane (3856×2170 — the kind of content the dark
    /// A001 clip never produces; every A001 frame selects q100, so the
    /// lowering branch was never exercised) drives the real per-tile
    /// libjpeg encodes through `search_quality`. The chosen quality must
    /// drop below 100 and the total must land under the CBR-4 limit.
    #[test]
    fn cbr_lowering_on_realistic_content() {
        use crate::tileenc::{tile_region, Grid};
        let (fw, fh) = (3856u32, 2170u32);
        // Deterministic high-entropy plane (LCG): incompressible-ish, so
        // even q100 overshoots every CBR limit here (stabilo LCG — same
        // sequence on every platform, test stays reproducible).
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let mut plane8 = vec![0u8; (fw * fh) as usize];
        for b in plane8.iter_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (state >> 33) as u8;
        }
        let g = Grid::new(fw, fh);
        assert_eq!((g.cols, g.rows), (8, 8));
        let rects: Vec<crate::tileenc::TileRect> = (0..g.rows)
            .flat_map(|r| (0..g.cols).map(move |c| tile_region(fw, fh, &g, r, c).unwrap()))
            .collect();
        let encode_all = |q: u32| -> Vec<Vec<u8>> {
            rects
                .iter()
                .map(|r| crate::lossy::encode_tile8(&plane8, fw, r, q).unwrap())
                .collect()
        };
        // The CBR-4 limit over the fp f1 input size (12,630,528 B):
        // in_bytes/4 * 1.05 = 3,312,987. q100 on this content must
        // overshoot it (that is the premise the test asserts first).
        let limit = (12_630_528u64 / 4) * 105 / 100;
        let t100_tiles = encode_all(100);
        let t100 = crate::lossy::total_size(0, &t100_tiles);
        assert!(
            t100 > limit,
            "premise: q100 must overshoot the CBR-4 limit (q100={t100}, limit={limit})"
        );
        // The same per-quality cache the worker's CBR path uses.
        let cache: std::cell::RefCell<std::collections::HashMap<u32, Vec<Vec<u8>>>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
        cache.borrow_mut().insert(100, t100_tiles);
        let total_fn = |q: u32| -> u64 {
            let t = {
                let mut c = cache.borrow_mut();
                match c.get(&q) {
                    Some(t) => t.clone(),
                    None => {
                        let t = encode_all(q);
                        c.insert(q, t.clone());
                        t
                    }
                }
            };
            crate::lossy::total_size(0, &t)
        };
        let q = crate::lossy::search_quality(limit, &total_fn);
        assert!(
            q < 100,
            "the lowering branch must engage on hard content (q={q})"
        );
        let total = total_fn(q);
        assert!(
            total <= limit,
            "chosen q={q} must land under the limit (total={total}, limit={limit})"
        );
        eprintln!("cbr4 lowering: q100={t100} B → q{q} total={total} B (limit {limit})");
    }

    /// Synthetic 8-bit tiles: encode + decode roundtrip at a few qualities,
    /// verifying the SOF dims == tile area + 1 component for full and
    /// clipped (last-row/col) tiles. A 982×300 frame = 3×2 tile grid (last
    /// col clipped to tw=18, last row to tl=28).
    #[test]
    fn lossy_tile_roundtrip_geometry() {
        use crate::tileenc::{tile_region, Grid};
        let (fw, fh) = (982u32, 300u32);
        let g = Grid::new(fw, fh);
        assert_eq!((g.cols, g.rows), (3, 2));
        let plane: Vec<u8> = (0..(fw * fh) as usize)
            .map(|i| ((i * 7) & 0xFF) as u8)
            .collect();
        for (r, c) in [(0u32, 0u32), (0, 2), (1, 0), (1, 2)] {
            let rect = tile_region(fw, fh, &g, r, c).unwrap();
            let src_tile: Vec<u8> = (0..rect.tl as usize)
                .flat_map(|y| {
                    let base = (rect.y0 as usize + y) * (fw as usize) + rect.x0 as usize;
                    plane[base..base + rect.tw as usize].iter().copied()
                })
                .collect();
            let mut mean_errs: Vec<f64> = Vec::new();
            for q in [10u32, 50, 90] {
                let jpeg = encode_tile8(&plane, fw, &rect, q).unwrap();
                // SOF dims == tile area + 1 component (the DecodeLossyJPEG
                // contract) — decode_tile8_rected enforces this.
                let back = decode_tile8_rected(&jpeg, &rect).unwrap();
                assert_eq!(back.len(), (rect.tw * rect.tl) as usize);
                // Lossy: not bit-exact, but a sane codec pair preserves the
                // mean closely (this pattern is noisy/high-freq, so q10 is
                // lossy — the sanity bound is on q90 + monotone decrease).
                let mean_err: f64 = back
                    .iter()
                    .zip(src_tile.iter())
                    .map(|(a, b)| (*a as i32 - *b as i32).abs() as f64)
                    .sum::<f64>()
                    / back.len() as f64;
                mean_errs.push(mean_err);
            }
            // q90 must be close (sane encode/decode pair); quality must be
            // monotone (higher q → lower error) for this pattern.
            assert!(
                mean_errs[2] < 5.0,
                "q90 mean err {} too high (bad codec pair)",
                mean_errs[2]
            );
            assert!(
                mean_errs[0] > mean_errs[2],
                "quality must be monotone (q10 {} !> q90 {})",
                mean_errs[0],
                mean_errs[2]
            );
        }
    }
}
