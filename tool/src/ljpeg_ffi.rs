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
