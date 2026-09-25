//! The per-frame parallelism + the directory orchestration (the
//! encode pipeline's module root).
//!
//! Frames are fully independent → `rayon` par_iter. Expected
//! bottleneck order: disk read → LJPEG encode → disk write. Read
//! frame, parse (tiff), unpack (pack12), encode, surgery, optional
//! verify, atomic write (tmp file + rename in the output dir —
//! nothing left half-written). The `--checksums` sidecar writes
//! `<OUT_DIR>/<CLIP>.checksums.tsv` (file, size, crc32c, sha256, the
//! 4 camera-metadata columns) over all output frames after the run.
//! Resume semantics: frames whose output already exists are SKIPPED
//! (not errors) unless --force. Non-DNG sidecars (WAV,
//! SPP_metadata.xmp) are copied through. Any parse/encode/verify
//! error = that frame fails; the run reports it and exits non-zero
//! at the end.
//!
//! The part layout (the five named conceptual parts — each a `pub mod`
//! below; the cross-module surface is re-exported at this root, so the
//! external `crate::worker::` paths are unchanged): the ingest +
//! discovery (`ingest`) · the encode pipeline (`encode`) · the report
//! writer (`report`) · the checksums — the frame-metadata reads
//! (`checksums`) · the sidecar + cleanup (`sidecar`). The shared test
//! helpers (the cfg(test) surface) ride in `testutil`.

pub mod checksums;
pub mod encode;
pub mod ingest;
pub mod report;
pub mod sidecar;

#[cfg(test)]
pub(crate) mod testutil;

pub use self::checksums::{
    EXIF_IFD_TAG, EXPOSURE_TAG, FRAME_RATE_TAG, ISO_TAG, Smpte12m, TC_FRAME_RATE,
    TC_TAG, TC_TAG_COUNT, FrameMetadata, frame_number_from_stem,
    parse_timecodes_field, read_frame_metadata, read_timecodes_tag,
};
pub use self::encode::{
    CoreFrame, LossyFormat, MemFrame, Mode, ReferenceDctOpts, ReferenceStructure,
    encode_frame_memory, vctx,
};
pub(crate) use self::encode::is_archive_layout;
pub use self::ingest::{
    IngestGateReport, SUBSET_MARKER, collect_dng_frames, ingest_gate,
    ingest_gate_subset, set_subset_flag, subset_flag, write_ingest_manifest,
};
pub use self::report::{
    ClipVerdict, FrameStats, Outcome, ReelPairVerdict, ReelVerdict, Report,
    clip_key_of, display_clip, g2_distribution_gate_is_fatal, process_dir,
    reel_check,
};
#[cfg(test)]
pub use self::testutil::{bcd16, synth_tiff};
