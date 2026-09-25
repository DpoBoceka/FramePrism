//! Fuzz target: the TIFF/DNG parsers (`frameprism::tiff::{read, read_meta}`)
//! must be total-safe on ANY byte string — every read bounds-checked,
//! typed errors, no panics (declared in `tiff.rs`'s module doc; review
//! .
//!
//! Run (requires `cargo install cargo-fuzz` + a nightly toolchain):
//!
//!     cargo fuzz run tiff_parse            # default seeds in corpus/
//!     cargo fuzz run tiff_parse -max-time 60

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Both parsers must return a typed error or a parse, never panic.
    let _ = frameprism::tiff::read(data);
    let _ = frameprism::tiff::read_meta(data);
});