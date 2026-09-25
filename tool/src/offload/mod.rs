//! The verified offload (two-destination ingest — the pass-through
//! engine).
//!
//! Semantics: `<in>` = the source of truth. For EVERY frame +
//! non-DNG sidecar file in the `<in>` tree (WAV/XMP are FIRST-CLASS
//! members — the probe fact: the fp writes a separate per-clip WAV +
//! `SPP_metadata.xmp` on the card):
//!   1. re-scan the source sha256 (a fresh hash per run — never a
//!      carried ledger value);
//!   2. copy the file to the `--to` dest (mirrored subpaths,
//!      mtime-preserving, std::fs streaming — NO shell, NO cp); an
//!      existing dest file is OVERWRITTEN (a re-run is idempotent +
//!      re-verified — the repair-loop re-copy rides LATER on this
//!      manifest; it is not built here);
//!   3. re-scan the copy sha256;
//!   4. append a row to `<OUT_DIR>/<CLIP>.offload-manifest.tsv`
//!      (file, size, source_sha256, dest_sha256, verdict) + the
//!      per-clip verdict blocks.
//!
//! Verdicts: `OK` / `SIZE_MISMATCH` / `SHA_MISMATCH` / `COPY_FAIL` —
//! ANY dirty row = a named FAIL line + rc=1 AFTER the encode
//! completes (the encode is not blocked by the copy; the VERDICT is
//! — the caller carries the count in `worker::Report::
//! offload_dirty_rows`).
//!
//! The re-audit/verify path: `frameprism audit` on a dir carrying the
//! offload manifest re-verifies the DEST against the recorded rows
//! (the `reverify` part — a post-run dest corruption is named here,
//! rc=1).
//!
//! The standalone `frameprism offload <in> <to> [<to> ...]` surface
//! (the pass-through engine — offload NEVER transforms: the
//! byte-copy + verify is the whole contract, on ANY tree, ANY
//! camera, ANY format — the transform stays on the encode path): the
//! copy+verify core (`offload_core` — the 1-dest shape, the `--to`
//! step's body extracted; `offload_to` is the thin encode-path
//! wrapper, the call site unchanged; `offload_core_multi` — the
//! multi-destination fan-out: each source file's bytes are read
//! ONCE and written to EVERY dest, the source sha256 computed ONCE
//! and shared by every dest's rows (the card read is the bottleneck
//! — N dests cost one card pass), each dest file hashed after its
//! write) + the per-clip camera/format detection (a REPORT, not a
//! gate, run ONCE — the `camera` module's next-to-the-resolver
//! scanner; offload never refuses on identity) + the offload run
//! report (the `.frameprism-run-report.md` pattern at EVERY dest
//! root — each report carries the WHOLE run: the detection block
//! once + one per-dest section per dest — exactly one `created:`
//! line; the 1-dest rendering is byte-identical to the 1-dest
//! shape) + the per-destination verification + status (the
//! verdict/FAIL line formats — the `(dest <dir>)` slot; the N>1
//! stderr is the per-dest blocks) + the rc (rc=0 every dest clean;
//! rc=1 ANY dirty dest — every dest named; rc=2 the pre-write
//! refusals — they cover every dest, before any copy: the
//! self-mirror guard per dest, the duplicate-dest refusal, the
//! per-dest writability probe) + the job report at EVERY dest root
//! (the structured job-report format: the session + summary blocks
//! + the per-clip blocks, the three file forms
//! `.frameprism-job-report.md` / `.csv` / `.html` — the `jobreport`
//! module's emitters; the save-with-job placement, automatic, no
//! flag; written AFTER the per-clip manifests + the run report —
//! the RECORD, not the gate: the rc semantics are unchanged, a
//! write failure is the named hard-error band; the per-file
//! copy+verify durations (the std-Instant write+verify window per
//! (file, dest) in `offload_core_multi`) + the run duration ride
//! ONLY in the job report — the manifests / the run report / the
//! stderr surface are untouched by the timing) + the ascmhl history
//! at EVERY dest root (the industry provenance standard's
//! media-hash-list record, the ASC MHL, the `urn:ASC:MHL:v2.0`
//! lineage — the manifest written beside every offload copy): the
//! `ascmhl/` directory + the `NNNN_<dest-basename>_YYYY-MM-DD_HHMMSSZ
//! .mhl` manifest (the generation-1 `transfer` process + the
//! `original` actions, the c4/C4ID hashes — the hand-rolled
//! SHA-512 + base58, std-only) + the `ascmhl_chain.xml` (the C4ID of
//! each generation's manifest bytes — the append-only re-run model:
//! a re-run onto a dest that already carries a history APPENDS the
//! new generation, the old records preserved byte-for-byte, never a
//! clobber); the pinned ignore set (the history covers the MEDIA,
//! not the frameprism records); the write position: LAST — after the
//! per-clip manifests + the run report + the job report (the records
//! stand first — a write failure is the named hard-error band, the
//! records already stand); automatic (no flag — like the job
//! report), silent on success (the stderr surface is unchanged); the
//! run's creation instant (the run report's `created` unix seconds)
//! is the manifest's creationdate + the file name's date/time (one
//! run instant); the writing side ONLY (this module carries no MHL
//! verify pass — the `ascmhl` module's surface).
//!
//! std-only (no new crates): the copy lands via the atomic-copy seam
//! (the interruption safety): `std::fs::copy` to a TEMP file +
//! `rename` onto the final path, so the final path holds ONLY
//! complete, verified files — an interrupted job (SIGKILL / crash /
//! power) leaves the temp, never a partial at the final media path;
//! the stale-temp cleanup at stage 0 (after the dest probes, before
//! the first source read) removes a prior interrupted job's temps
//! (the named note line); the temp name's `._*` prefix rides the
//! ascmhl manifest's PRE-EXISTING ignore pattern (the
//! zero-manifest-byte-change fact — the temp is invisible to the
//! history, and the name never rides on the wire — the job id is
//! per-process, by design); the digests reuse
//! `crate::jxl::sha256_hex` (one read per file, the codebase
//! convention — the largest batch member is the 531 MB proxy .mov,
//! well within a one-shot read).
//!
//! The durability seam (the fsync-before-rename): the media copy's
//! bytes are filesystem-synchronized (`sync_all`) BEFORE the rename
//! — the atomic-copy seam's sync rides the copy's existing failure
//! path (a sync failure = the named error, the temp deleted, the row
//! CopyFail with the detail) + the fan-out's per-dest open handle is
//! synced before its rename (a sync failure = that dest marked DIRTY
//! in the fan-out's existing per-dest failure class — the other
//! dests continue) + a best-effort directory sync after the
//! successful rename (the rename's dir-entry update — the pinned note
//! on failure, the content copy stands). The record writers (the
//! per-clip manifest, the run report, the job report, the ascmhl
//! manifest + chain) ride the same seam: the mandatory `sync_file`
//! in their named hard-error bands + the best-effort dir sync. What
//! the seam does NOT claim: physical durability — the drive/card
//! write-cache behavior is platform-specific; the tool's guarantee
//! stops at the filesystem synchronization (the `durability` module
//! — the honest vocabulary).
//!
//! The part layout (the six named conceptual parts — each a
//! `pub mod` below; the cross-module surface is re-exported at this
//! root, so the external `crate::offload::` paths are unchanged):
//! the traversal + source inventory (`traversal`) · the fan-out
//! transfer engine (`transfer`) · the manifests (`manifests`) · the
//! form validation (`forms`) · the report orchestration (`report`) ·
//! the re-verify (`reverify`).

pub mod forms;
pub mod manifests;
pub mod reverify;
pub mod report;
pub mod traversal;
pub mod transfer;

#[cfg(test)]
pub(crate) mod testutil;

pub use self::forms::{Args, OffloadForm, run, settle_form};
pub(crate) use self::forms::check_to_band;
pub use self::manifests::{
    Manifest, MANIFEST_MAGIC, MANIFEST_SUFFIX, OffloadRow,
    Verdict, offload_manifest_name, parse_manifest,
};
pub(crate) use self::manifests::clip_key_of_rel;
pub use self::reverify::reverify;
pub use self::report::{
    ClipBlock, OffloadReport, SourceOutcome, run_offload, run_offload_multi,
    run_offload_multi_sources, write_offload_run_report, write_offload_run_reports,
};
pub use self::traversal::check_dest_writable;
pub(crate) use self::traversal::{check_root_bound, collect_all_files};
pub use self::transfer::{
    ClipSlice, OffloadCore, OffloadCoreMulti, offload_core, offload_core_multi,
    offload_to,
};
