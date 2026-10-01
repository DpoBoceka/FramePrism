//! Hand-written C ABI declarations for the ljpeg shim
//! (`tool/ljpeg_shim.c`, compiled and linked by `build.rs`).
//!
//! consolidation: this used to be triplicated — each of `lossydct`,
//! `tileenc` and `lossy` carried its own `extern "C"` block (plus
//! per-bin copies in the `t21cmp`/`t21probe` diagnostic bins), nine
//! declarations of `ljpeg_comp_new` total. The shared declarations were
//! verified textually identical across the copies (union below); the bins
//! now import from here as well. Signatures were cross-checked against
//! the C source (the cross-check table
//! p7_crosscheck.tsv) — they are the project's real UB surface, so keep
//! this module the single home and re-run that cross-check after any
//! shim change.
//!
//! Every declaration is called from Rust only under `unsafe` with a
//! `// SAFETY:` comment at the call site; the call-site invariants are
//! uniform (documented per call site, summarized here once):
//! - handles (`ljpeg_comp_new` / `ljpeg_decomp_new`) are null-checked
//!   immediately and released through `ljpeg_comp_free` /
//!   `ljpeg_decomp_free` on every exit path (the shim `free()`s the
//!   handle; a double-free would be a C-side bug, not a Rust-side one);
//! - input slices (`rows` / `coeffs` / `buf`) are borrowed for the
//!   duration of the call and outlived by their owning `Vec`/`&[u8]`;
//! - every `outbuf`/`out` argument is a LOCAL `*mut _` initialized to
//!   null, written by the C side, and any non-null buffer it produces is
//!   owned by the shim (malloc/`jpeg_mem_dest`) and released exactly
//!   once with `ljpeg_free_buffer`.

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};

/// Opaque encoder handle (`ljpeg_comp`, ljpeg_shim.c).
pub type LjpegComp = c_void;
/// Opaque decoder handle (`ljpeg_decomp`, ljpeg_shim.c).
pub type LjpegDecomp = c_void;

extern "C" {
    pub fn ljpeg_comp_new() -> *mut LjpegComp;
    pub fn ljpeg_comp_free(h: *mut LjpegComp);
    /// Frees a buffer returned by one of the `ljpeg_encode_*` /
    /// `ljpeg_decode_*` functions (malloc'd on the C side).
    pub fn ljpeg_free_buffer(p: *mut c_void);
    /// Last error message of the handle ("" if none); the pointer is
    /// valid until the next call on the same handle.
    pub fn ljpeg_comp_error(h: *mut LjpegComp) -> *const c_char;

    /// Baseline DCT (SOF1) encode, 12-bit samples, custom 16-bit
    /// quantization table — one parity plane of one reference tag-7 tile
    /// (see ljpeg_shim.c for the pipeline provenance). Declared for the
    /// shim's full ABI surface; unused in-crate (the production path is
 /// `ljpeg_encode_coeff12` after the D1 islow-DCT fix).
    pub fn ljpeg_encode_dct12(
        h: *mut LjpegComp,
        rows: *const i16,
        width: c_int,
        height: c_int,
        table: *const u16,
        outbuf: *mut *mut u8,
        outsize: *mut c_ulong,
    ) -> c_int;
    /// Baseline DCT (SOF1) encode from pre-computed dequantized 12-bit
    /// coefficients (raw-coefficient API) — the production reference tag-7
    /// encode leg.
    pub fn ljpeg_encode_coeff12(
        h: *mut LjpegComp,
        coeffs: *const i16,
        width: c_int,
        height: c_int,
        table: *const u16,
        outbuf: *mut *mut u8,
        outsize: *mut c_ulong,
    ) -> c_int;
    /// 2-component raw lossless (SOF3) encode, per-pixel-interleaved
    /// rows, 8/10/12-bit precision — the lossless + log10 tile encoders
    /// (8-bit goes through the plain 8-bit scanline API in the shim;
    /// see ljpeg_shim.c header notes).
    pub fn ljpeg_encode_lossless2(
        h: *mut LjpegComp,
        rows: *const i16,
        width: c_int,
        height: c_int,
        psv: c_int,
        precision: c_int,
        outbuf: *mut *mut u8,
        outsize: *mut c_ulong,
    ) -> c_int;
    /// Baseline DCT (SOF0) encode, single component, 8-bit — the lossy
    /// cDNG (Compression 34892, LinearRaw) tile encoder.
    pub fn ljpeg_encode_lossy1(
        h: *mut LjpegComp,
        rows: *const u8,
        width: c_int,
        height: c_int,
        quality: c_int,
        outbuf: *mut *mut u8,
        outsize: *mut c_ulong,
    ) -> c_int;

    pub fn ljpeg_decomp_new() -> *mut LjpegDecomp;
    pub fn ljpeg_decomp_free(h: *mut LjpegDecomp);
    pub fn ljpeg_decomp_error(h: *mut LjpegDecomp) -> *const c_char;
    /// Decode a lossless (SOF3) stream into a malloc'd
    /// per-pixel-interleaved `short` buffer.
    pub fn ljpeg_decode_lossless(
        h: *mut LjpegDecomp,
        buf: *const u8,
        len: c_long,
        out: *mut *mut i16,
        width: *mut c_int,
        height: *mut c_int,
        ncomp: *mut c_int,
        expected_precision: c_int,
    ) -> c_int;
    /// Decode a baseline DCT (SOF0) 8-bit stream into a malloc'd
    /// row-major `u8` buffer.
    pub fn ljpeg_decode_lossy1(
        h: *mut LjpegDecomp,
        buf: *const u8,
        len: c_long,
        out: *mut *mut u8,
        width: *mut c_int,
        height: *mut c_int,
        ncomp: *mut c_int,
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    //! The fp-structure conformance KAT — the durable,
    //! committed, camera-free form of the 2026-09-30 conformance probe
    //! (the scratch probe + its renders live in the lane
    //! evidence dir, never committed). The settled conformance facts:
    //!
    //! - the fp tag-7 tiles are 2-component lossless SOF3: even/odd
    //!   COLUMN interleave (the DNG-spec scheme), precision 12, PSV 7
    //!   (the (left+up)/2 predictor);
    //! - the streams are FULL-NOMINAL: every one of the 48 tiles of a
    //!   3856×2170 frame carries a full 256×368 per-component stream
    //!   (the recombined tile is 512×368) — the ragged 272-px last
    //!   column, 330-px last row and 272×330 corner carry full-nominal
    //!   streams that the decoder must CLIP;
    //! - the grid is 8×6 = 48 tiles (TIFF tags 324/325, ascending).
    //!
    //! Test-only by contract (the byte-freeze lane): no
    //! product surface, no new crate, no flag, no testdata / oracle
    //! change. The corpus-conditional test RUNs when the mirrored frame
    //! is present in the worktree and SKIPs on a fresh checkout (the
    //! house `real_a001_strip_golden` pattern) — the suite pin holds
    //! either way.

    use core::ffi::CStr;

    use super::*;

    /// The fp conformance geometry (the probe's settled facts, pinned).
    const FP_STREAM_W: i32 = 256; // per-component stream width (SOF3 Xsize)
    const FP_STREAM_H: i32 = 368; // per-component stream height (SOF3 Ysize)
    const FP_TILE_W: u32 = 512; // recombined tile width (2 × stream width)
    const FP_TILE_H: u32 = 368; // recombined tile height
    const FP_FRAME_W: u32 = 3856;
    const FP_FRAME_H: u32 = 2170;
    const FP_TILES: usize = 48; // 8 cols × 6 rows

    /// The R1.3 canary pins — the M0 measurement (2026-09-30) on the
    /// mirrored corpus frame f000001, through the product engine (the
    /// house canary pattern: exact min/max, windowed mean / CFA class
    /// means ±1). The probe's values are the cross-check and agree
    /// within the 1-code CFA tolerance: CFA 627/789/789/502 (measured
    /// 627.0194/788.8449/789.4640/501.6324), the isotropy ratio
    /// 1.000 (measured 0.99974, within [0.9, 1.1]), mean|Δx| 224.84 /
    /// mean|Δy| 224.90 (measured 224.8377 / 224.8972).
    const PIN_MIN: u16 = 256;
    const PIN_MAX: u16 = 4095;
    const PIN_MEAN: f64 = 676.7750905883703; // plane mean over all 8,367,520 px
    const PIN_CFA_R0C0: f64 = 627.019415300536;
    const PIN_CFA_R0C1: f64 = 788.8449011617776;
    const PIN_CFA_R1C0: f64 = 789.4640331509698;
    const PIN_CFA_R1C1: f64 = 501.6323602065808;

    /// The shim's last error string (the `ljpeg_comp_error` /
    /// `ljpeg_decomp_error` pattern from `tileenc`).
    fn fp_err_str(ptr: *const c_char, default: &str) -> String {
        if ptr.is_null() {
            return default.to_string();
        }
        // SAFETY: non-null C string owned by the shim handle (valid
        // until the next call on it), read only through `CStr`.
        unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
    }

    /// A deterministic full-range 12-bit `w`×`h` plane (the house
    /// `test_plane` construction: gradient + per-pixel jitter — no
    /// floats, no PRNG; spans 0..=4095).
    fn fp_test_plane(w: usize, h: usize) -> Vec<u16> {
        (0..(w * h))
            .map(|i| {
                let x = i % w;
                let y = i / w;
                ((((x * 63 + y * 63) % 4096) + (i % 97)) % 4096) as u16
            })
            .collect()
    }

    /// Encode one 2-component per-pixel-interleaved tile stream through
    /// the product encoder (`ljpeg_encode_lossless2`, PSV 7, precision
    /// 12 — the fp encode contract). `rows` = height × 2×width shorts.
    fn fp_encode_lossless2(rows: &[i16], width: i32, height: i32) -> Vec<u8> {
        // SAFETY: `ljpeg_comp_new` is the shim's allocator (calloc); the
        // pointer is null-checked and `ljpeg_comp_free`d on every exit
        // path below.
        let h = unsafe { ljpeg_comp_new() };
        assert!(!h.is_null(), "ljpeg_comp_new returned null");
        let mut outbuf: *mut u8 = core::ptr::null_mut();
        let mut outsize: c_ulong = 0;
        // SAFETY: live handle; `rows` (height × 2×width per-pixel
        // interleaved shorts — the layout the shim documents) outlives
        // the call; PSV 7 and precision 12 are inside the shim's 1..7 /
        // 8..12 ranges; `&mut outbuf` / `&mut outsize` are
        // null-initialized locals the shim writes. On success `outbuf`
        // is malloc'd by the shim and freed exactly once below.
        let rc = unsafe {
            ljpeg_encode_lossless2(
                h,
                rows.as_ptr(),
                width,
                height,
                7,
                12,
                &mut outbuf,
                &mut outsize,
            )
        };
        if rc != 0 {
            let msg = fp_err_str(unsafe { ljpeg_comp_error(h) }, "encode failed");
            unsafe { ljpeg_comp_free(h) };
            panic!("ljpeg_encode_lossless2 failed: {msg}");
        }
        let jpeg = unsafe { core::slice::from_raw_parts(outbuf, outsize as usize) }.to_vec();
        // SAFETY: single free of the shim-malloc'd buffer + the handle,
        // both now past their last use.
        unsafe {
            ljpeg_free_buffer(outbuf as *mut c_void);
            ljpeg_comp_free(h);
        }
        jpeg
    }

    /// Decode one lossless SOF3 stream through the product engine
    /// (`ljpeg_decode_lossless` over the pinned libjpeg-turbo prefix),
    /// expected precision 12. Returns (per-pixel-interleaved samples —
    /// height × 2×width shorts — , width, height, ncomp).
    fn fp_decode_lossless(buf: &[u8]) -> (Vec<i16>, i32, i32, i32) {
        // SAFETY: `ljpeg_decomp_new` is the shim's allocator (calloc);
        // the pointer is null-checked and `ljpeg_decomp_free`d on every
        // exit path below.
        let h = unsafe { ljpeg_decomp_new() };
        assert!(!h.is_null(), "ljpeg_decomp_new returned null");
        let mut out: *mut i16 = core::ptr::null_mut();
        let mut w: c_int = 0;
        let mut ht: c_int = 0;
        let mut nc: c_int = 0;
        // SAFETY: live handle; `buf` is a `&[u8]` borrow outliving the
        // call and `buf.len()` its exact length; the four `&mut`
        // out-params are initialized locals the shim writes. On success
        // `out` is malloc'd by the shim (ht × nc × w shorts) and freed
        // exactly once below.
        let rc = unsafe {
            ljpeg_decode_lossless(
                h,
                buf.as_ptr(),
                buf.len() as c_long,
                &mut out,
                &mut w,
                &mut ht,
                &mut nc,
                12,
            )
        };
        if rc != 0 {
            let msg = fp_err_str(unsafe { ljpeg_decomp_error(h) }, "decode failed");
            unsafe { ljpeg_decomp_free(h) };
            panic!("ljpeg_decode_lossless failed (rc {rc}): {msg}");
        }
        let total = (ht as usize) * (w as usize) * (nc as usize);
        let samples = unsafe { core::slice::from_raw_parts(out, total) }.to_vec();
        // SAFETY: single free of the shim-malloc'd buffer + the handle.
        unsafe {
            ljpeg_free_buffer(out as *mut c_void);
            ljpeg_decomp_free(h);
        }
        (samples, w, ht, nc)
    }

    /// Split a recombined `w`×`h` plane into its even/odd COLUMN
    /// component planes (each `w/2`×`h`) — the DNG-spec 2-component
    /// scheme (the fp split).
    fn fp_split_even_odd(plane: &[u16], w: usize, h: usize) -> (Vec<u16>, Vec<u16>) {
        assert!(w % 2 == 0, "the even/odd column split needs an even width");
        let half = w / 2;
        let mut even = vec![0u16; half * h];
        let mut odd = vec![0u16; half * h];
        for y in 0..h {
            for x in 0..w {
                let v = plane[y * w + x];
                let d = y * half + x / 2;
                if x % 2 == 0 {
                    even[d] = v;
                } else {
                    odd[d] = v;
                }
            }
        }
        (even, odd)
    }

    /// Build the shim's per-pixel-interleaved row buffer (row y =
    /// [c0(0), c1(0), c0(1), c1(1), ...]) from two `cols`×`rows`
    /// component planes.
    fn fp_interleave_rows(even: &[u16], odd: &[u16], cols: usize, rows: usize) -> Vec<i16> {
        let mut out = vec![0i16; rows * cols * 2];
        for y in 0..rows {
            for x in 0..cols {
                out[y * cols * 2 + 2 * x] = even[y * cols + x] as i16;
                out[y * cols * 2 + 2 * x + 1] = odd[y * cols + x] as i16;
            }
        }
        out
    }

    /// Clip-recombine: from the per-pixel-interleaved `sw`×`sh`
    /// 2-component stream samples, take the top-left `vw`×`vh`
    /// recombined region (vw ≤ 2×sw, vh ≤ sh), even/odd columns — the
    /// FULL-NOMINAL clip the fp decoder applies to ragged-edge tiles
    /// (vw == 2×sw and vh == sh = the exact-geometry interior tile).
    fn fp_clip_recombine(samples: &[i16], sw: i32, sh: i32, vw: usize, vh: usize) -> Vec<u16> {
        assert!(vw <= (sw as usize) * 2, "visible width exceeds 2× the stream width");
        assert!(vh <= sh as usize, "visible height exceeds the stream height");
        let mut out = vec![0u16; vw * vh];
        for y in 0..vh {
            for x in 0..vw {
                let s = ((y as i32 * sw + (x / 2) as i32) * 2 + (x % 2) as i32) as usize;
                out[y * vw + x] = samples[s] as u16;
            }
        }
        out
    }

    // R1.1 — the fp-tile-shape 2-component round-trip (the codec level).
    #[test]
    fn kat_fp_geometry_2comp_roundtrip() {
        // A deterministic 512×368 plane (the fp tile shape, full
        // 0..=4095 range) → the even/odd COLUMN split into two 256×368
        // component planes → the per-pixel-interleaved 256-wide rows
        // (the shim's input contract) → `ljpeg_encode_lossless2` (PSV
        // 7, precision 12) → `ljpeg_decode_lossless` (expected
        // precision 12) → the even/odd recombine → bit-exact == the
        // original plane.
        let plane = fp_test_plane(FP_TILE_W as usize, FP_TILE_H as usize);
        assert_eq!(
            (
                plane.iter().min().copied().unwrap_or(u16::MAX),
                plane.iter().max().copied().unwrap_or(0)
            ),
            (0, 4095),
            "the KAT plane must span the full 12-bit range"
        );
        let (even, odd) = fp_split_even_odd(&plane, FP_TILE_W as usize, FP_TILE_H as usize);
        let sw = FP_STREAM_W as usize;
        let sh = FP_STREAM_H as usize;
        assert_eq!((even.len(), odd.len()), (sw * sh, sw * sh));
        let rows = fp_interleave_rows(&even, &odd, sw, sh);
        let stream = fp_encode_lossless2(&rows, FP_STREAM_W, FP_STREAM_H);
        assert!(!stream.is_empty(), "the encoded fp stream must not be empty");
        let (back, w, ht, nc) = fp_decode_lossless(&stream);
        assert_eq!(
            (w, ht, nc),
            (FP_STREAM_W, FP_STREAM_H, 2),
            "the fp stream shape: 256×368, 2 components"
        );
        let got = fp_clip_recombine(&back, w, ht, FP_TILE_W as usize, FP_TILE_H as usize);
        assert_eq!(got, plane, "the fp-tile-shape round-trip must be bit-exact");
    }

    // R1.2 — the FULL-NOMINAL padding semantics (the ragged-edge clip).
    #[test]
    fn kat_fp_ragged_padding_roundtrip() {
        // The fp corner tile: a 272×330 visible region inside the
        // FULL-NOMINAL 512×368 tile (stream 256×368 per component — the
        // ragged tiles carry full-nominal streams). The padding pixels
        // are deterministic here but NOT asserted — the KAT asserts the
        // CLIP semantics: encode the full 256×368 stream (visible +
        // padding), decode, clip to the 272×330 visible region →
        // bit-exact == the visible plane, regardless of the padding
        // content. (The 512×368 interior-tile variant is test 1 — exact
        // geometry, no clip.)
        const VW: usize = 272; // 3856 − 7×512 (the ragged last column)
        const VH: usize = 330; // 2170 − 5×368 (the ragged last row)
        let visible = fp_test_plane(VW, VH);
        assert_eq!(
            (
                visible.iter().min().copied().unwrap_or(u16::MAX),
                visible.iter().max().copied().unwrap_or(0)
            ),
            (0, 4095),
            "the KAT plane must span the full 12-bit range"
        );
        let (even, odd) = fp_split_even_odd(&visible, VW, VH); // 136×330 each
        let sw = FP_STREAM_W as usize;
        let sh = FP_STREAM_H as usize;
        let half_v = VW / 2; // 136 visible columns per component
        // Pad each component to the FULL-NOMINAL 256×368 (deterministic
        // padding content, not asserted — the fp quirk: the stream is
        // full-nominal).
        let mut ce = vec![0u16; sw * sh];
        let mut co = vec![0u16; sw * sh];
        for y in 0..sh {
            for x in 0..sw {
                let in_visible = x < half_v && y < VH;
                let pad = ((x * 31 + y * 17) % 4096) as u16;
                ce[y * sw + x] = if in_visible { even[y * half_v + x] } else { pad };
                co[y * sw + x] = if in_visible { odd[y * half_v + x] } else { pad };
            }
        }
        let rows = fp_interleave_rows(&ce, &co, sw, sh);
        let stream = fp_encode_lossless2(&rows, FP_STREAM_W, FP_STREAM_H);
        assert!(!stream.is_empty(), "the encoded fp stream must not be empty");
        let (back, w, ht, nc) = fp_decode_lossless(&stream);
        assert_eq!((w, ht, nc), (FP_STREAM_W, FP_STREAM_H, 2));
        // The CLIP: the full-nominal stream back to the 272×330 visible
        // region → bit-exact == the visible plane.
        let got = fp_clip_recombine(&back, w, ht, VW, VH);
        assert_eq!(
            got, visible,
            "the FULL-NOMINAL clip must recover the visible plane bit-exactly"
        );
    }

    // R1.3 — the corpus-conditional real-frame decode (the corpus
    // canary). RUNs when the mirrored frame is present, SKIPs on a
    // fresh checkout.
    #[test]
    fn kat_fp_frame_corpus_decode() {
        let p = "../testdata/originals/A001_013/A001_013_20260930_000001.DNG";
        let buf = match std::fs::read(p) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                return;
            }
        };
        // The tiff reader's generic IFD path (`read_meta` — the
        // strip-layout `read` refuses tiled frames by design) parses
        // the fp container (the IFD sits at the file tail, 59 tags).
        let meta =
            crate::tiff::read_meta(&buf).expect("the fp tag-7 container must parse via the tiff reader");
        let entries = &meta.ifd0.entries;
        let entry = |tag: u16| -> &crate::tiff::IfdEntry {
            entries.iter().find(|e| e.tag == tag).unwrap_or_else(|| {
                panic!("IFD tag {tag} missing from the fp container")
            })
        };
        let long1 = |tag: u16| -> u32 {
            let e = entry(tag);
            assert_eq!(e.typ, 4, "tag {tag}: expected LONG (4)");
            assert_eq!(e.count, 1, "tag {tag}: expected count 1");
            u32::from_le_bytes(e.value_raw)
        };
        let longs = |tag: u16| -> Vec<u32> {
            let e = entry(tag);
            assert_eq!(e.typ, 4, "tag {tag}: expected LONG (4)");
            let (start, end) = e
                .out_of_line
                .unwrap_or_else(|| panic!("tag {tag}: expected out-of-line value"));
            assert_eq!(end - start, e.count as u64 * 4, "tag {tag}: value size");
            (0..e.count as usize)
                .map(|k| {
                    let s = (start + (k as u64) * 4) as usize;
                    u32::from_le_bytes(buf[s..s + 4].try_into().unwrap())
                })
                .collect()
        };
        let w = long1(256); // ImageWidth
        let h = long1(257); // ImageLength
        let tw = long1(322); // TileWidth
        let th = long1(323); // TileLength
        let offs = longs(324); // TileOffsets
        let lens = longs(325); // TileByteCounts
        // The conformance geometry (the probe's settled facts):
        assert_eq!((w, h), (FP_FRAME_W, FP_FRAME_H), "the fp frame is 3856×2170");
        assert_eq!((tw, th), (FP_TILE_W, FP_TILE_H), "the fp tiles are 512×368 nominal");
        assert_eq!(offs.len(), FP_TILES, "the fp frame carries 48 tile streams");
        assert_eq!(lens.len(), FP_TILES, "the fp frame carries 48 tile streams");
        let ncols = ((w + tw - 1) / tw) as usize;
        let nrows = ((h + th - 1) / th) as usize;
        assert_eq!(ncols * nrows, FP_TILES, "the fp grid is 8×6 = 48 tiles");
        // Decode every tile via the product engine and assert the
        // measured structure per tile: stream 256×368, ncomp=2,
        // precision 12 — ALL 48 (the FULL-NOMINAL fact: the ragged-edge
        // tiles carry full-nominal streams).
        let mut plane = vec![0u16; (w * h) as usize];
        for r in 0..nrows {
            for c in 0..ncols {
                let ti = r * ncols + c;
                let off = offs[ti] as usize;
                let len = lens[ti] as usize;
                assert!(off + len <= buf.len(), "tile {ti}: stream out of range");
                let (samples, sw, sh, nc) = fp_decode_lossless(&buf[off..off + len]);
                assert_eq!(
                    (sw, sh, nc),
                    (FP_STREAM_W, FP_STREAM_H, 2),
                    "tile {ti} (col {c}, row {r}): FULL-NOMINAL 256×368 2-comp stream, precision 12"
                );
                // Even/odd column recombine + the padding clip (the
                // visible top-left region of the full-nominal tile).
                let bx = c * tw as usize;
                let by = r * th as usize;
                let vw = (FP_TILE_W.min(w - bx as u32)) as usize;
                let vh = (FP_TILE_H.min(h - by as u32)) as usize;
                let tile = fp_clip_recombine(&samples, sw, sh, vw, vh);
                for y in 0..vh {
                    let d = (by + y) * (w as usize) + bx;
                    plane[d..d + vw].copy_from_slice(&tile[y * vw..y * vw + vw]);
                }
            }
        }
        // Canary stats — the M0 measurement pins (the house canary
        // pattern: exact min/max, windowed mean; the probe's values are
        // the cross-check).
        let mn = plane.iter().min().copied().unwrap_or(u16::MAX);
        let mx = plane.iter().max().copied().unwrap_or(0);
        assert_eq!((mn, mx), (PIN_MIN, PIN_MAX), "plane min/max drifted: ({mn}, {mx})");
        let sum: u64 = plane.iter().map(|v| *v as u64).sum();
        let mean = sum as f64 / plane.len() as f64;
        assert!(
            ((PIN_MEAN - 1.0)..(PIN_MEAN + 1.0)).contains(&mean),
            "plane mean {mean} drifted from ~{PIN_MEAN}"
        );
        // The 2×2 CFA class means + the gradient isotropy over the
        // interior (the probe's accumulation: the boundary ring
        // excluded — the apples-to-apples cross-check).
        let wz = w as usize;
        let hz = h as usize;
        let mut csum = [[0u64; 2]; 2];
        let mut ccount = [[0u64; 2]; 2];
        let mut n: u64 = 0;
        let mut sx: u64 = 0;
        let mut sy: u64 = 0;
        for y in 1..hz - 1 {
            for x in 1..wz - 1 {
                let i = y * wz + x;
                csum[y % 2][x % 2] += plane[i] as u64;
                ccount[y % 2][x % 2] += 1;
                n += 1;
                let dx = plane[i] as i32 - plane[i - 1] as i32;
                let dy = plane[i] as i32 - plane[i - wz] as i32;
                sx += dx.abs() as u64;
                sy += dy.abs() as u64;
            }
        }
        let cmean = |r: usize, c: usize| csum[r][c] as f64 / ccount[r][c] as f64;
        let (m00, m01, m10, m11) = (cmean(0, 0), cmean(0, 1), cmean(1, 0), cmean(1, 1));
        assert!(
            ((PIN_CFA_R0C0 - 1.0)..(PIN_CFA_R0C0 + 1.0)).contains(&m00),
            "CFA r0c0 {m00} drifted from ~{PIN_CFA_R0C0}"
        );
        assert!(
            ((PIN_CFA_R0C1 - 1.0)..(PIN_CFA_R0C1 + 1.0)).contains(&m01),
            "CFA r0c1 {m01} drifted from ~{PIN_CFA_R0C1}"
        );
        assert!(
            ((PIN_CFA_R1C0 - 1.0)..(PIN_CFA_R1C0 + 1.0)).contains(&m10),
            "CFA r1c0 {m10} drifted from ~{PIN_CFA_R1C0}"
        );
        assert!(
            ((PIN_CFA_R1C1 - 1.0)..(PIN_CFA_R1C1 + 1.0)).contains(&m11),
            "CFA r1c1 {m11} drifted from ~{PIN_CFA_R1C1}"
        );
        let ratio = (sx as f64 / n as f64) / (sy as f64 / n as f64);
        assert!(
            (0.9..1.1).contains(&ratio),
            "the even/odd rebuild must be isotropic (mean|Δx|/mean|Δy| = {ratio}, outside [0.9, 1.1])"
        );
    }
}
