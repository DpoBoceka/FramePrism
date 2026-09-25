//! Lossless JPEG (ITU-T T.81) encode/decode via libjpeg-turbo's TurboJPEG C
//! API (v3, libjpeg-turbo 3.2.0 — signatures verified against the installed
//! header; reference copy in deps/libjpeg-turbo).
//!
//! Pipeline (per frame): 12-bit packed strip (DNG standard order — see
//! `pack12.rs`) → `pack12::unpack12`
//! → 16-bit samples → lossless JPEG at 12-bit precision (single-component,
//! TJPF_GRAY) → JPEG stream for `surgery`. Decode is the inverse (verify).
//!
//! API surface (hand-rolled FFI, ~40 lines). CRITICAL: the v3
//! tj3Compress*/tj3Decompress* `pitch` parameter is **samples per row**, not
//! bytes per row (v2 tjCompress used bytes). For single-component gray that
//! is `width` (tjPixelSize[TJPF_GRAY] = 1). Passing bytes (width*2) makes the
//! library over-read the source buffer and segfault.
//!
//!     h = tjInitCompress();
//!     tj3Set(h, TJPARAM_LOSSLESS, 1);          // = 15
//!     tj3Set(h, TJPARAM_PRECISION, 12);        // = 7
//!     tj3Compress12(h, short* src, w, w /*pitch=width samples/row*/, h, TJPF_GRAY /* 6 */, &buf, &size);
//!     tj3Free(buf); tj3Destroy(h);
//!
//! NOTE the init functions keep their legacy names (tjInitCompress /
//! tjInitDecompress); only the Set/Compress/Decompress/Free family is
//! "tj3*". Output buffer from tj3Compress* must be freed with tj3Free.
//!
//! Linking: build.rs links libturbojpeg from Homebrew (jpeg-turbo formula,
//! JPEG_TURBO_PREFIX env override).

use std::ffi::{c_char, c_void};

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum CodecError {
    #[error("libjpeg-turbo error: {0}")]
    Jpeg(String),
    #[error("unsupported bit precision {0} (need 12 or 16)")]
    UnsupportedPrecision(u8),
    #[error("empty JPEG input")]
    EmptyInput,
}

// Verified values from turbojpeg.h (libjpeg-turbo 3.2.0) — probe-confirmed.
const TJPARAM_JPEGWIDTH: i32 = 5;
const TJPARAM_JPEGHEIGHT: i32 = 6;
const TJPARAM_PRECISION: i32 = 7;
const TJPARAM_LOSSLESS: i32 = 15;
const TJPF_GRAY: i32 = 6;

extern "C" {
    fn tjInitCompress() -> *mut c_void;
    fn tjInitDecompress() -> *mut c_void;
    fn tj3Destroy(handle: *mut c_void);
    fn tj3Free(buffer: *mut c_void);
    fn tj3Set(handle: *mut c_void, param: i32, value: i32) -> i32;
    fn tj3Get(handle: *mut c_void, param: i32) -> i32;
    fn tj3GetErrorStr(handle: *mut c_void) -> *mut c_char;
    fn tj3Compress12(
        handle: *mut c_void,
        src: *const i16,
        width: i32,
        pitch: i32,
        height: i32,
        pixel_format: i32,
        jpeg_buf: *mut *mut u8,
        jpeg_size: *mut usize,
    ) -> i32;
    fn tj3Compress16(
        handle: *mut c_void,
        src: *const u16,
        width: i32,
        pitch: i32,
        height: i32,
        pixel_format: i32,
        jpeg_buf: *mut *mut u8,
        jpeg_size: *mut usize,
    ) -> i32;
    fn tj3Decompress12(
        handle: *mut c_void,
        jpeg_buf: *const u8,
        jpeg_size: usize,
        dst_buf: *mut i16,
        pitch: i32,
        pixel_format: i32,
    ) -> i32;
    fn tj3Decompress16(
        handle: *mut c_void,
        jpeg_buf: *const u8,
        jpeg_size: usize,
        dst_buf: *mut u16,
        pitch: i32,
        pixel_format: i32,
    ) -> i32;
    fn tj3DecompressHeader(handle: *mut c_void, jpeg_buf: *const u8, jpeg_size: usize) -> i32;
}

fn err_str(handle: *mut c_void) -> String {
    // SAFETY: `handle` is a live tj3 handle (checked non-null before every
    // call site); `tj3GetErrorStr` returns a C string owned by the handle
    // (valid until the next call on it), read only through `CStr`.
    let p = unsafe { tj3GetErrorStr(handle) };
    if p.is_null() {
        return "unknown libjpeg-turbo error".to_string();
    }
    // SAFETY: non-null C string pointer from `tj3GetErrorStr` (NUL-terminated
    // by libjpeg-turbo).
    unsafe { std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned() }
}

/// Encode 16-bit samples (one per pixel, row-major) as lossless JPEG at the
/// given data precision (12 for fp footage; 16 for 14/16-bit input later).
pub fn encode_lossless(
    samples: &[u16],
    width: u32,
    height: u32,
    bits: u8,
) -> Result<Vec<u8>, CodecError> {
    // SAFETY: `tjInitCompress` is a plain allocator-style init; the pointer
    // is null-checked here and released with `tj3Destroy` on every exit
    // path below.
    let handle = unsafe { tjInitCompress() };
    if handle.is_null() {
        return Err(CodecError::Jpeg("tjInitCompress returned null".into()));
    }
    for (param, value) in [(TJPARAM_LOSSLESS, 1), (TJPARAM_PRECISION, bits as i32)] {
        // SAFETY: live handle; both params are valid TJPARAM_* ids (the
        // constants above, verified against turbojpeg.h 3.2.0).
        if unsafe { tj3Set(handle, param, value) } != 0 {
            let msg = err_str(handle);
            unsafe { tj3Destroy(handle) };
            return Err(CodecError::Jpeg(msg));
        }
    }
    let mut out: *mut u8 = std::ptr::null_mut();
    let mut size: usize = 0;
    // pitch = samples/row (v3 semantics); gray = 1 sample/px
    let pitch = width as i32;
    // SAFETY (the tj3Compress12/16 call): live handle (null-checked above);
    // `samples` is a `&[u16]` borrow that outlives the call (u16/i16 are
    // the same width — the 12-bit path re-borrows the bytes as i16);
    // `pitch = width` = samples/row per the v3 contract (passing bytes is
    // the documented over-read segfault); `&mut out`/`&mut size` are
    // initialized locals written by the library. On success `out` is
    // owned by the library and freed exactly once below with `tj3Free`.
    let rc = match bits {
        12 => unsafe {
            tj3Compress12(
                handle,
                samples.as_ptr() as *const i16,
                width as i32,
                pitch,
                height as i32,
                TJPF_GRAY,
                &mut out,
                &mut size,
            )
        },
        16 => unsafe {
            tj3Compress16(
                handle,
                samples.as_ptr(),
                width as i32,
                pitch,
                height as i32,
                TJPF_GRAY,
                &mut out,
                &mut size,
            )
        },
        _ => {
            let _ = err_str(handle);
            unsafe { tj3Destroy(handle) };
            return Err(CodecError::UnsupportedPrecision(bits));
        }
    };
    if rc != 0 {
        let msg = err_str(handle);
        unsafe { tj3Destroy(handle) };
        return Err(CodecError::Jpeg(msg));
    }
    // SAFETY: `rc == 0` here — `out` is non-null and points at `size`
    // bytes owned by libjpeg-turbo; copied out before `tj3Free` (single
    // free) and `tj3Destroy` (single destroy, after the buffer is no
    // longer needed).
    let jpeg = unsafe { std::slice::from_raw_parts(out, size) }.to_vec();
    unsafe {
        tj3Free(out as *mut c_void);
        tj3Destroy(handle);
    }
    Ok(jpeg)
}

/// Decode lossless JPEG back into 16-bit samples + image dimensions.
pub fn decode_lossless(jpeg: &[u8], bits: u8) -> Result<(Vec<u16>, u32, u32), CodecError> {
    if jpeg.is_empty() {
        return Err(CodecError::EmptyInput);
    }
    // SAFETY: `tjInitDecompress` is a plain allocator-style init; the
    // pointer is null-checked here and released with `tj3Destroy` on every
    // exit path below.
    let handle = unsafe { tjInitDecompress() };
    if handle.is_null() {
        return Err(CodecError::Jpeg("tjInitDecompress returned null".into()));
    }
    // NOTE: TJPARAM_LOSSLESS is read-only in decompression instances —
    // libjpeg auto-detects lossless JPEG from the SOF markers. The 12/16-bit
    // function selection below matches the input image's data precision.
    // SAFETY: live handle; `jpeg` is a `&[u8]` borrow outliving the call
    // and `jpeg.len()` its exact length (the header is parsed from
    // precisely that buffer).
    if unsafe { tj3DecompressHeader(handle, jpeg.as_ptr(), jpeg.len()) } != 0 {
        let msg = err_str(handle);
        unsafe { tj3Destroy(handle) };
        return Err(CodecError::Jpeg(msg));
    }
    // SAFETY: live handle; `TJPARAM_JPEGWIDTH/HEIGHT` are valid TJPARAM_*
    // ids, read only after the header parse succeeded above.
    let width = unsafe { tj3Get(handle, TJPARAM_JPEGWIDTH) } as u32;
    let height = unsafe { tj3Get(handle, TJPARAM_JPEGHEIGHT) } as u32;
    // Magnitude bound (the a5 finding): on a degenerate stream
    // `tj3DecompressHeader` can "succeed" and report garbage dimensions
    // (~ u32::MAX); the allocation `(width*height) * 2 B` then panics
    // (`capacity overflow`). The bound keeps `samples*2 < usize::MAX` with
    // margin (real frame: 3856x2170 ~= 8.4e6 samples) — a header that
    // claims more is refused, not allocated.
    if width == 0 || height == 0
        || (width as u64).saturating_mul(height as u64) > u64::MAX / 4
    {
        let msg = err_str(handle);
        unsafe { tj3Destroy(handle) };
        return Err(CodecError::Jpeg(format!(
            "implausible JPEG dimensions {width}x{height} — refusing to allocate ({msg})"
        )));
    }
    let mut dst = vec![0u16; (width as usize) * (height as usize)];
    // pitch = samples/row (v3 semantics); gray = 1 sample/px
    let pitch = width as i32;
    // SAFETY (the tj3Decompress12/16 call): live handle; the header parse
    // set `width`/`height` from this exact buffer and `dst` is sized
    // `width*height` with `pitch = width` samples/row, so the write is
    // fully in-bounds; `jpeg` outlives the call. The library allocates no
    // output buffer in this direction (it writes into `dst`).
    let rc = match bits {
        12 => unsafe {
            tj3Decompress12(
                handle,
                jpeg.as_ptr(),
                jpeg.len(),
                dst.as_mut_ptr() as *mut i16,
                pitch,
                TJPF_GRAY,
            )
        },
        16 => unsafe {
            tj3Decompress16(
                handle,
                jpeg.as_ptr(),
                jpeg.len(),
                dst.as_mut_ptr(),
                pitch,
                TJPF_GRAY,
            )
        },
        _ => {
            unsafe { tj3Destroy(handle) };
            return Err(CodecError::UnsupportedPrecision(bits));
        }
    };
    if rc != 0 {
        let msg = err_str(handle);
        unsafe { tj3Destroy(handle) };
        return Err(CodecError::Jpeg(msg));
    }
    unsafe { tj3Destroy(handle) };
    Ok((dst, width, height))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64×64 12-bit test plane: diagonal gradient + per-pixel jitter,
    /// full 0..4095 range, deterministic.
    fn test_plane(w: u32, h: u32) -> Vec<u16> {
        let (w, h) = (w as usize, h as usize);
        (0..(w * h))
            .map(|i| {
                let x = i % w;
                let y = i / w;
                ((((x * 63 + y * 63) % 4096) + (i % 97)) as u16) % 4096
            })
            .collect()
    }

    #[test]
    fn roundtrip_12bit_synthetic() {
        let s = test_plane(64, 64);
        let jpeg = encode_lossless(&s, 64, 64, 12).expect("encode");
        assert!(!jpeg.is_empty());
        let (back, w, h) = decode_lossless(&jpeg, 12).expect("decode");
        assert_eq!((w, h), (64, 64));
        assert_eq!(back, s, "lossless roundtrip must be bit-exact");
    }

    #[test]
    fn roundtrip_16bit_synthetic() {
        let s: Vec<u16> = (0..(64 * 64)).map(|i| (i * 41761 % 65536) as u16).collect();
        let jpeg = encode_lossless(&s, 64, 64, 16).expect("encode 16-bit");
        let (back, w, h) = decode_lossless(&jpeg, 16).expect("decode 16-bit");
        assert_eq!((w, h), (64, 64));
        assert_eq!(back, s);
    }

    #[test]
    fn real_a001_roundtrip() {
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
        let s = crate::pack12::unpack12(packed, f.width, f.height).unwrap();
        let jpeg = encode_lossless(&s, f.width, f.height, 12).expect("encode real frame");
        let (back, w, h) = decode_lossless(&jpeg, 12).expect("decode real frame");
        assert_eq!((w, h), (f.width, f.height));
        assert_eq!(back, s, "real frame must roundtrip bit-exact");
        eprintln!(
            "real-frame LJPEG: {} bytes in (packed) -> {} B jpeg ({:.2}:1)",
            packed.len(),
            jpeg.len(),
            packed.len() as f64 / jpeg.len() as f64
        );
    }
}
