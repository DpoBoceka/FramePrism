//! Fuzz target: the hand-rolled MHL XML parser (`frameprism::ascmhl::
//! {parse_lite, parse_hashlist}` — the strict conformant-v2.0 hashlist
//! import surface, ) must be total-safe on ANY byte string:
//! every read bounds-checked, the recursive element parse is
//! depth-bounded (`MAX_ELEMENT_DEPTH` — the total-safety
//! finding: an unbounded recursion over a hostile 350,000 B depth-50,000
//! nesting input was a stack overflow → SIGABRT [exit 134, not a
//! typed error]; the guard converts it to the named refusal), typed
//! errors, no panics.
//!
//! Run (requires `cargo install cargo-fuzz` + a nightly toolchain):
//!
//!     cargo fuzz run mhl_parse            # default seeds in corpus/
//!     cargo fuzz run mhl_parse -max-time 60
//!
//! The GATE boundary (the layering decision): this is the
//! DEV-TIME layer — NOT a gate step. The gate's MHL coverage = the
//! lib suite's named tests (the 34 refusal battery + the 55a
//! edge-class battery + the depth regression); the in-tree pinned
//! corpus (`ci/check-fuzz.sh`, the 25 fixtures) is DECODE-scoped
//! (`frameprism decode` — the MHL parse does not go through decode).
//! The fuzzer's bytes → the valid-UTF-8 view: `parse_lite` /
//! `parse_hashlist` take `&str` (Rust's type system is the encoding
//! gate — invalid UTF-8 = a defined no-op here; the file seam's
//! non-UTF-8 class = the typed io error, the named-tests' layer).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return, // the encoding gate (the type system) — a defined no-op
    };
    // The pure parse call set (no I/O, fast): the total-safety claim =
    // no panic / no abort — a typed error or a parse (the depth bound
    // named as the mechanism above).
    let _ = frameprism::ascmhl::parse_lite(s);
    let _ = frameprism::ascmhl::parse_hashlist(s, "fuzz.mhl");
});
