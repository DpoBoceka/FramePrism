//! The frame classifier — the frame CLASS dimension (the
//! mixed-compression arc's D1 move): a pure, IFD-only,
//! structure-keyed classification of a DNG frame from its parsed IFD
//! structure (`tiff::read_meta`'s `Meta`). No pixel access, no tag-7
//! stream decode, no file I/O beyond the parsed structure — the
//! discriminator tags are in-line count-1 values (the `IfdEntry`
//! fields) and the tile count is an entry `count` (the out-of-line
//! TileOffsets value is never read).
//!
//! The classes (the pinned names):
//! - `RawUncompressed` — compression 1 + strip (no 322/323): the
//!   existing encode input class (the behavior on such frames is
//!   byte-invariant);
//! - `FpCameraLossless` — compression 7 + the fp camera's lossless
//!   engine tile structure (the measured fingerprint: 512×368 tiles,
//!   48 tiles, on 3856×2170 — the probe facts, the
//!   design-record addendum; the v1 carry
//!   class);
//! - `FramePrismArchive` — compression 7 + a grid in the tool's
//!   MEASURED archive grid set (the gate contract's data —
//!   `tileenc::gate_tile_dims_depth` + the expected tile count for the
//!   frame's own geometry; the grid set is DATA read through the gate
//!   contract, NOT a hardcoded list in this module — the
//!   no-hardcoded-geometry rule; the decode/verify-verb class);
//! - `Unknown` — any other structure: the named-refusal class.
//!
//! **The classifier's domain (the amended
//! R1/R2):** the classifier is a function over SUCCESSFULLY-PARSED
//! structures. `Unknown` = a READABLE structure that cannot be placed
//! in a measured class. A frame whose tiff parse FAILS (including the
//! existing named `ParseError::MissingTag { tag: 259 }` class, tiff
//! :52/:451 — a missing/unreadable Compression tag) is OUTSIDE the
//! class contract's domain: it keeps the EXISTING per-frame named
//! refusal at the encode site (the corrupt-frame semantics — the named
//! per-frame FAIL, the run continues; the wording + behavior
//! byte-invariant, zero new wordings). The clip-class contract's SET
//! is the classes of the frames WITH a readable compression structure
//! (`in_contract_domain`); a parse-failed frame does not enter the
//! set. The pre-job refusal keeps its full value: a clip carrying a
//! READABLE archive / unknown-grid frame is still refused pre-job.
//! Rationale: conflating the parse-failure class with the
//! named-refusal class would force the out-of-fence fixture-builder
//! edits (the worker/audit testutil builders carry NO tag 259 — the
//! `{Unknown}` clip refusal would break their gate.is_pass() tests)
//! for zero measured benefit (259 is present on every measured real
//! frame).
//!
//! The named refusal wordings (R5, the pinned verbatim forms the
//! tests assert) + the clip-class contract (R2's executable half: the
//! allowed per-clip class SETS — `{RawUncompressed}` ·
//! `{RawUncompressed, FpCameraLossless}` — any other set = the clip
//! level's named refusal) + the per-frame class/action registry (the
//! encode/carry site's note — the report's provenance claim; the
//! `sourcecheck` registry pattern: one run per process, no reset).

use std::collections::{BTreeMap, BTreeSet};

use crate::tiff::{Endian, IfdEntry, IfdTable, Meta};

/// The frame class (the pinned names).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FrameClass {
    /// Compression 1 + strip structure (no 322/323) — the stock raw
    /// input.
    RawUncompressed,
    /// Compression 7 + the fp camera's lossless-engine tile structure
    /// (512×368 tiles × 48 on 3856×2170 — the measured fingerprint).
    FpCameraLossless,
    /// Compression 7 + a grid in the tool's measured FramePrism
    /// archive grid set (the gate contract's data).
    FramePrismArchive,
    /// Any other structure — the named-refusal class.
    Unknown,
}

impl FrameClass {
    /// The manifest/report name (the pinned vocabulary).
    pub fn name(self) -> &'static str {
        match self {
            FrameClass::RawUncompressed => "raw-uncompressed",
            FrameClass::FpCameraLossless => "fp-camera-lossless",
            FrameClass::FramePrismArchive => "frameprism-archive",
            FrameClass::Unknown => "unknown",
        }
    }
}

/// The per-frame action of the encode run's policy table (the
/// provenance record's `action` column).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameAction {
    /// The existing encode path (the bit-exact round-trip verify).
    Encoded,
    /// The byte-exact source copy (the verify = the source-sha match).
    Carried,
    /// The transcode (the fp-camera class's
    /// lossless cell, the default): the fp frame is decoded through the
    /// the fp-camera lossless decode path + re-encoded through the existing archive path.
    /// The D4 vocabulary's `transcoded:fp-hardware` — the class is the
    /// fp-camera class, the vendor is the fp hardware (the decode is
    /// the camera's own lossless engine), the action is the transcode.
    /// The verify = the archive bit-exact drill on the output + the
    /// transcode-fidelity check (decode(output) == the decoded input
    /// plane, pixel-exact) — NEVER the carried source-sha match (the
    /// output differs from the source by design).
    Transcoded,
}

impl FrameAction {
    /// The manifest/report name (the pinned vocabulary).
    pub fn name(self) -> &'static str {
        match self {
            FrameAction::Encoded => "encoded",
            FrameAction::Carried => "carried",
            FrameAction::Transcoded => "transcoded",
        }
    }
}

/// The measured IFD structure of the frame (the discriminator tags —
/// the classifier's pure input summary). `None` = the tag is absent
/// or not a readable in-line count-1 SHORT/LONG value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameStructure {
    /// Tag 259 (Compression).
    pub compression: Option<u16>,
    /// Tag 256 (ImageWidth).
    pub width: Option<u32>,
    /// Tag 257 (ImageLength).
    pub height: Option<u32>,
    /// Tag 258 (BitsPerSample).
    pub bits_per_sample: Option<u16>,
    /// Tag 322 (TileWidth).
    pub tile_width: Option<u32>,
    /// Tag 323 (TileLength).
    pub tile_height: Option<u32>,
    /// Tag 324 (TileOffsets) count = the tile count (the value itself
    /// is out-of-line and NEVER read — the count field is the
    /// discriminator).
    pub tile_count: Option<u32>,
    /// Tiled structure (322 or 323 present — the tiff parse's own
    /// TiledInput predicate).
    pub tiled: bool,
}

/// The fp camera's lossless-engine fingerprint (the measured facts —
/// the probe: 512×368 tiles, 48 tiles, on 3856×2170; the
/// R5 wording names the fingerprint verbatim).
const FP_TILE_W: u32 = 512;
const FP_TILE_H: u32 = 368;
const FP_FRAME_W: u32 = 3856;
const FP_FRAME_H: u32 = 2170;

/// The in-line count-1 value of an entry (SHORT type 3 / LONG type 4,
/// the two TIFF types the discriminator tags carry): `None` when the
/// tag is not a readable in-line count-1 value (another type, a count
/// ≠ 1, or an out-of-line value) — the classifier degrades to the
/// `Unknown` class rather than guessing.
fn inline_value(entry: &IfdEntry, e: Endian) -> Option<u64> {
    match entry.typ {
        3 if entry.count == 1 && entry.out_of_line.is_none() => {
            Some(e.u16(&entry.value_raw[0..2]) as u64)
        }
        4 if entry.count == 1 && entry.out_of_line.is_none() => {
            Some(e.u32(&entry.value_raw[0..4]) as u64)
        }
        _ => None,
    }
}

/// Read one discriminator tag's in-line value from an IFD table (the
/// first entry for the tag; absent / unreadable = `None`).
fn tag_value(ifd: &IfdTable, e: Endian, tag: u16) -> Option<u64> {
    ifd.entries
        .iter()
        .find(|en| en.tag == tag)
        .and_then(|en| inline_value(en, e))
}

/// The frame's measured IFD structure (the classifier's pure input —
/// `Meta` = the `read_meta` parse result; the sub-IFDs are NOT
/// consulted — the discriminator tags live in IFD0).
pub fn structure_from_ifd0(meta: &Meta) -> FrameStructure {
    let s = FrameStructure {
        compression: tag_value(&meta.ifd0, meta.endianness, 259)
            .map(|v| v as u16),
        width: tag_value(&meta.ifd0, meta.endianness, 256).map(|v| v as u32),
        height: tag_value(&meta.ifd0, meta.endianness, 257).map(|v| v as u32),
        bits_per_sample: tag_value(&meta.ifd0, meta.endianness, 258)
            .map(|v| v as u16),
        tile_width: tag_value(&meta.ifd0, meta.endianness, 322).map(|v| v as u32),
        tile_height: tag_value(&meta.ifd0, meta.endianness, 323).map(|v| v as u32),
        tile_count: meta
            .ifd0
            .entries
            .iter()
            .find(|en| en.tag == 324)
            .map(|en| en.count),
        tiled: meta
            .ifd0
            .entries
            .iter()
            .any(|en| en.tag == 322 || en.tag == 323),
    };
    s
}

/// The expected tile count of the (w×h) frame on the (tw×th) grid
/// (the standard DNG edge-tile tiling: the ragged edge tiles at the
/// full grid geometry — `ceil(w/tw) × ceil(h/th)`).
pub fn expected_tiles(w: u32, h: u32, tw: u32, th: u32) -> u64 {
    if tw == 0 || th == 0 {
        return 0;
    }
    (w.div_ceil(tw) as u64) * (h.div_ceil(th) as u64)
}

/// The tool's MEASURED archive grid set membership for the frame's own
/// structure: the frame's grid (322/323) must equal the gate contract's
/// measured grid for the frame's geometry (the per-(geometry × depth)
/// data — `tileenc::gate_tile_dims_depth`: the 482×272 legacy default +
/// the 252×252 / 242×274 / 484×274 / 252×336 / 964×272 measured rows)
/// AND the tile count (324) must equal the expected tiling of that grid
/// on the frame's dimensions (a 482×272 frame with a wrong tile count
/// is NOT the tool's measured structure — the `Unknown` class). The
/// depth (258) selects the per-depth grid; an unreadable depth checks
/// the union over the tool's three unpackable depths.
fn archive_grid_match(s: &FrameStructure) -> bool {
    let (Some(w), Some(h), Some(tw), Some(th), Some(count)) =
        (s.width, s.height, s.tile_width, s.tile_height, s.tile_count)
    else {
        return false;
    };
    if expected_tiles(w, h, tw, th) != count as u64 {
        return false;
    }
    match s.bits_per_sample {
        Some(bps) => crate::tileenc::gate_tile_dims_depth(w, h, bps as u32) == (tw, th),
        None => [8u32, 10, 12]
            .iter()
            .any(|&d| crate::tileenc::gate_tile_dims_depth(w, h, d) == (tw, th)),
    }
}

/// Classify a measured structure (the pure decision):
/// - compression 1 + strip (no 322/323) → `RawUncompressed`;
/// - compression 7 + tiled → the grid check: the fp-camera fingerprint
///   (512×368 × 48 on 3856×2170 AT 12-BPS — the bps pin, R5:
///   the measured fp arm is 12-bit; the 8-bit camera variant — the
///   59-tag IFD + the 50712 × 256 LinearizationTable — has NO corpus on
///   disk (every measured fp clip is 12-bit 3856×2170), so it is the
///   named refusal, not the arm: the same grid at bps 8 is NOT the
///   fp-camera class — `Unknown` + the unknown-row wording, never a
///   misclassification into the 12-bit arm; the 8-bit decode arm is
///   deferred to a corpus run — the design record's benefit-map row
///   stands as the future work, named in the measurement record) →
///   `FpCameraLossless`; a grid in the tool's measured archive grid set
///   → `FramePrismArchive`; any other tiled grid → `Unknown`;
/// - any other readable compression value (incl. a non-tiled 7 — the
///   single-strip lossless shape, not a measured structure) →
///   `Unknown`. A structure with NO readable compression value
///   (absent / another type / count ≠ 1) also classifies `Unknown` —
///   the readable-but-unplaceable structure; the clip-class contract's
///   DOMAIN predicate (`in_contract_domain`) keeps it OUT of the
///   contract's set (the parse-failure class — the encode site's
///   existing named refusal, the domain clause).
pub fn classify_structure(s: &FrameStructure) -> FrameClass {
    match s.compression {
        Some(1) if !s.tiled => FrameClass::RawUncompressed,
        Some(7) if s.tiled => {
            if s.tile_width == Some(FP_TILE_W)
                && s.tile_height == Some(FP_TILE_H)
                && s.width == Some(FP_FRAME_W)
                && s.height == Some(FP_FRAME_H)
                && s.bits_per_sample == Some(12) // the R5 refusal pin: the fp arm is 12-bit measured; the 8-bit variant is the named refusal, not the arm
                && s.tile_count == Some(expected_tiles(FP_FRAME_W, FP_FRAME_H, FP_TILE_W, FP_TILE_H) as u32)
            {
                FrameClass::FpCameraLossless
            } else if archive_grid_match(s) {
                FrameClass::FramePrismArchive
            } else {
                FrameClass::Unknown
            }
        }
        _ => FrameClass::Unknown,
    }
}

/// Classify a frame from its parsed IFD structure (the `read_meta`
/// result — the classifier's whole input; the file bytes are never
/// read past the IFD).
pub fn classify(meta: &Meta) -> FrameClass {
    classify_structure(&structure_from_ifd0(meta))
}

// =====================================================================
// The named refusal wordings (R5 — the pinned verbatim forms; `{}` =
// the filled value; the tests assert them byte-for-byte).
// =====================================================================

/// `unknown tile grid for a lossless frame (322/323 = {W}×{H}, {N}
/// tiles): not the fp-camera grid (512×368×48) nor a measured
/// FramePrism archive grid — frame {name}`. A missing measured value
/// fills `-` (the honest absence — the structure deviated in the
/// unreadable way).
pub fn unknown_tile_grid_line(
    w: Option<u32>,
    h: Option<u32>,
    n: Option<u32>,
    name: &str,
) -> String {
    let f = |v: Option<u32>| v.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
    format!(
        "unknown tile grid for a lossless frame (322/323 = {}×{}, {} tiles): not the fp-camera grid (512×368×48) nor a measured FramePrism archive grid — frame {}",
        f(w),
        f(h),
        f(n),
        name
    )
}

/// `FramePrism archive frame as encode input: the decode/verify verbs
/// only — frame {name}`.
pub fn frameprism_archive_line(name: &str) -> String {
    format!(
        "FramePrism archive frame as encode input: the decode/verify verbs only — frame {name}"
    )
}

/// `compression {N} not supported (supported: 1 [raw], 7
/// [lossless]) — frame {name}`.
pub fn compression_unsupported_line(n: u16, name: &str) -> String {
    format!(
        "compression {n} not supported (supported: 1 [raw], 7 [lossless]) — frame {name}"
    )
}

/// `fp-camera lossless frame × mode {mode}: the mixed-mode rows are
/// unmeasured (the v1 row is the lossless carry) — frame {name}`.
pub fn fp_camera_mode_line(mode: &str, name: &str) -> String {
    format!(
        "fp-camera lossless frame × mode {mode}: the mixed-mode rows are unmeasured (the v1 row is the lossless carry) — frame {name}"
    )
}

/// The clip-class contract's display of a class set (the deterministic
/// form: the class names in the enum order, `, `-joined,
/// brace-wrapped — the single class reads `{raw-uncompressed}`).
pub fn class_set_display(set: &BTreeSet<FrameClass>) -> String {
    let names: Vec<&str> = set.iter().map(|c| c.name()).collect();
    format!("{{{}}}", names.join(", "))
}

/// The clip class contract's DOMAIN predicate (the
/// amended R1/R2): a frame enters the contract's set IFF its structure
/// carries a readable compression value (tag 259 as an in-line
/// count-1 SHORT/LONG). A frame whose compression is absent /
/// unreadable is the parse-failure class (the strict parse's
/// `MissingTag(259)` — the existing named class, tiff :52/:451) and
/// stays on the existing per-frame named refusal at the encode site
/// (the corrupt-frame semantics — byte-invariant, zero new wordings).
pub fn in_contract_domain(s: &FrameStructure) -> bool {
    s.compression.is_some()
}

/// The clip class contract (R2's executable half): the allowed
/// per-clip class SETS are `{RawUncompressed}` (the existing class —
/// the behavior on such clips is byte-invariant) and
/// `{RawUncompressed, FpCameraLossless}` (the mixed contract —
/// A001_013's shape). Any other non-empty set (a lone
/// `FpCameraLossless`, any `FramePrismArchive`, any `Unknown`, ...)
/// = the named refusal. The set is built over the contract's domain
/// only (`in_contract_domain` — the readable-compression frames); an
/// empty set (no frame carries a readable compression) is outside the
/// contract's domain — the parse-failure frames ride the encode
/// site's per-frame named refusals (the existing behavior stands).
pub fn allowed_clip_class_set(set: &BTreeSet<FrameClass>) -> bool {
    if set.len() == 1 {
        return set.contains(&FrameClass::RawUncompressed);
    }
    set.len() == 2
        && set.contains(&FrameClass::RawUncompressed)
        && set.contains(&FrameClass::FpCameraLossless)
}

/// `clip class contract violated: {class-set} (allowed: the raw class;
/// the mixed {raw, fp-camera} set) — first offender {name}`.
pub fn clip_class_contract_line(set: &BTreeSet<FrameClass>, first_offender: &str) -> String {
    format!(
        "clip class contract violated: {} (allowed: the raw class; the mixed {{raw, fp-camera}} set) — first offender {first_offender}",
        class_set_display(set)
    )
}

// =====================================================================
// The per-frame class/action registry (the encode/carry site's note —
// the report's provenance claim). The `sourcecheck` registry pattern
// (the pins/selection/qc OnceLock convention — a process-wide static;
// one run per process, no reset needed): keyed by the sidecar row key
// (the output-relative frame path, POSIX — the worker `process`
// closure's `rel`); absent key = a non-encode caller (the resume-skip
// / the failed frame — the caller's report-site fallback).
// =====================================================================

static FRAME_ACTIONS: std::sync::OnceLock<std::sync::Mutex<BTreeMap<String, (FrameClass, FrameAction)>>> =
    std::sync::OnceLock::new();

fn action_registry() -> &'static std::sync::Mutex<BTreeMap<String, (FrameClass, FrameAction)>> {
    FRAME_ACTIONS.get_or_init(Default::default)
}

/// Note one frame's class + action at the encode/carry site (the
/// policy table's verdict for the frame the run processed).
pub fn note_frame_action(rel: &str, class: FrameClass, action: FrameAction) {
    action_registry()
        .lock()
        .expect("frame-action registry poisoned")
        .insert(rel.to_string(), (class, action));
}

/// Claim one frame's class + action (the report's provenance write
/// site). `None` = the run did not process this frame (the resume-skip
/// / the failed frame / a non-encode caller) — the caller's
/// write-site fallback.
pub fn claim_frame_action(rel: &str) -> Option<(FrameClass, FrameAction)> {
    action_registry()
        .lock()
        .expect("frame-action registry poisoned")
        .get(rel)
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tiff::{IfdEntry, IfdTable};

    /// A synthetic in-test IFD (the classifier's input is the parsed
    /// structure — no file needed): one entry per (tag, typ, count,
    /// in-line value). `typ` 3 = SHORT (the u16 in `value`), 4 = LONG
    /// (the u32 in `value`); `count` > 1 (the out-of-line class — the
    /// TileOffsets shape) carries NO value (the count is the
    /// discriminator).
    fn synth_ifd(
        endian: Endian,
        entries: &[(u16, u16, u32, u32)],
    ) -> Meta {
        let ifd_entries: Vec<IfdEntry> = entries
            .iter()
            .map(|&(tag, typ, count, value)| {
                let mut value_raw = [0u8; 4];
                if typ == 3 {
                    value_raw[0..2].copy_from_slice(&(value as u16).to_le_bytes());
                } else if typ == 4 {
                    value_raw[0..4].copy_from_slice(&value.to_le_bytes());
                }
                IfdEntry {
                    tag,
                    typ,
                    count,
                    value_raw,
                    out_of_line: None,
                }
            })
            .collect();
        Meta {
            endianness: endian,
            ifd0: IfdTable {
                off: 0,
                struct_range: 0u64..0u64,
                entries: ifd_entries,
                next_ifd: 0,
            },
            sub_ifds: vec![],
        }
    }

    #[test]
    fn frameclass_raw_strip_is_raw_uncompressed() {
        // Compression 1, strip (no 322/323) — the stock A001 raw class
        // (the SHORT types the raw frames carry).
        let meta = synth_ifd(
            Endian::Little,
            &[(256, 3, 1, 3856), (257, 3, 1, 2170), (258, 3, 1, 12), (259, 3, 1, 1)],
        );
        let s = structure_from_ifd0(&meta);
        assert_eq!(s.compression, Some(1));
        assert!(!s.tiled, "a strip frame has no 322/323");
        assert_eq!(classify(&meta), FrameClass::RawUncompressed);
    }

    #[test]
    fn frameclass_fp_camera_grid_is_fp_camera_lossless() {
        // Compression 7, 322/323 = 512×368, 48 tiles, 256/257 =
        // 3856×2170 (the LONG types the fp frames carry — the
        // measured tag dump) → the fp-camera fingerprint.
        let meta = synth_ifd(
            Endian::Little,
            &[
                (256, 4, 1, 3856),
                (257, 4, 1, 2170),
                (258, 3, 1, 12),
                (259, 3, 1, 7),
                (322, 4, 1, 512),
                (323, 4, 1, 368),
                (324, 4, 48, 0),
            ],
        );
        let s = structure_from_ifd0(&meta);
        assert!(s.tiled);
        assert_eq!(s.tile_count, Some(48));
        assert_eq!(
            expected_tiles(3856, 2170, 512, 368),
            48,
            "the fingerprint's tile count is the expected tiling"
        );
        assert_eq!(classify(&meta), FrameClass::FpCameraLossless);
    }

    #[test]
    fn frameclass_archive_grid_and_unknown_refusal() {
        // (a) Compression 7, 322/323 = 482×272 (the 482 legacy archive
        // grid) on 3856×2170 @12, 64 tiles (the expected tiling) → the
        // tool's measured archive grid set → FramePrismArchive.
        let meta = synth_ifd(
            Endian::Little,
            &[
                (256, 4, 1, 3856),
                (257, 4, 1, 2170),
                (258, 3, 1, 12),
                (259, 3, 1, 7),
                (322, 4, 1, 482),
                (323, 4, 1, 272),
                (324, 4, 64, 0),
            ],
        );
        assert_eq!(
            crate::tileenc::gate_tile_dims_depth(3856, 2170, 12),
            (482, 272),
            "the 482×272 legacy grid is the gate contract's UHD @12 row"
        );
        assert_eq!(classify(&meta), FrameClass::FramePrismArchive);

        // (b) Compression 7, 322/323 = 300×300, 1 tile: not the
        // fp-camera fingerprint, not a measured archive grid →
        // Unknown (the named-refusal class — the wording names the
        // deviating grid, pinned verbatim).
        let meta = synth_ifd(
            Endian::Little,
            &[(259, 3, 1, 7), (322, 4, 1, 300), (323, 4, 1, 300), (324, 4, 1, 0)],
        );
        assert_eq!(classify(&meta), FrameClass::Unknown);
        let s = structure_from_ifd0(&meta);
        assert_eq!(
            unknown_tile_grid_line(s.tile_width, s.tile_height, s.tile_count, "f.DNG"),
            "unknown tile grid for a lossless frame (322/323 = 300×300, 1 tiles): not the fp-camera grid (512×368×48) nor a measured FramePrism archive grid — frame f.DNG"
        );

        // (c) Compression 5 (JPEG) — any other compression value →
        // Unknown (the compression wording names the value, pinned
        // verbatim).
        let meta = synth_ifd(Endian::Little, &[(259, 3, 1, 5)]);
        assert_eq!(classify(&meta), FrameClass::Unknown);
        assert_eq!(
            compression_unsupported_line(5, "f.DNG"),
            "compression 5 not supported (supported: 1 [raw], 7 [lossless]) — frame f.DNG"
        );
    }
}
