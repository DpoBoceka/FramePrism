//! The encode pipeline — the mode model + the per-frame encode.
//!
//! The mode model: `Mode` (lossless default / Log10 / the VBR presets) ·
//! `LossyFormat` (the lossy tier — the 8-bit / 34892 / LinearRaw /
//! dct12 forms) · `ReferenceDctOpts` + `ReferenceStructure` (the
//! DCT reference structure — the TSV read). The layout predicates
//! (`is_tile_layout` / `is_archive_layout` — the tile-geometry routing):
//! A001-layout frames (3856x2170, 12-bit packed) ride the reference-
//! product-structure tile encoder (64 tiles x 2-component even/odd
//! column-plane lossless JPEG, PSV 7) + tile surgery + tile verify; any
//! other layout (none today) falls back to the single-strip path.
//!
//! The pipeline: `encode_core` (the per-frame encode — the full-buffer
//! card read is the design bottleneck) · `run`
//! (the per-frame runner: the encode + the optional verify + the atomic
//! write — tmp file + rename, nothing half-written) ·
//! `encode_frame_memory` (the in-memory entry — the dryrun surface).
//! `CoreFrame` / `MemFrame` are the frame carriers; `vctx` is the
//! encode-error context. The cross-part seams: the verdict model (the
//! `report` part: `FrameStats` / `Outcome` / `Report`) + the frame-
//! metadata reads (the `checksums` part) + the per-frame processing
//! helpers (the `report` part: `collect` / `read_reference_mae` /
//! `build_ds2x`).

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};

use super::report::{FrameStats, build_ds2x, read_reference_mae};

/// Encoding mode. `Lossless` is the default and the MVP behavior; the lossy
/// modes (34892/LinearRaw/8-bit) and `Log10` compose with
/// `--downscale2x`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// 12-bit samples, lossless tile JPEG .
    Lossless,
    /// 10-bit log codes, lossless tile JPEG + LinearizationTable .
    Log10,
    /// Lossy VBR high-quality preset (fixed libjpeg quality,).
    VbrHq,
    /// Lossy VBR light preset (fixed libjpeg quality,).
    VbrLt,
    /// Lossy CBR ~3:1 (per-frame quality binary-search,).
    Cbr3,
    /// Lossy CBR ~4:1 (per-frame quality binary-search,).
    Cbr4,
    /// Lossy CBR ~5:1 (per-frame quality binary-search,).
    Cbr5,
    /// Lossy CBR ~7:1 (per-frame quality binary-search,).
    Cbr7,
}

impl Mode {
    /// True for the five lossy (34892) modes.
    pub fn is_lossy(self) -> bool {
        matches!(
            self,
            Mode::VbrHq | Mode::VbrLt | Mode::Cbr3 | Mode::Cbr4 | Mode::Cbr5 | Mode::Cbr7
        )
    }
    /// The CBR target ratio k for the CBR modes (None otherwise).
    pub fn cbr_k(self) -> Option<u32> {
        match self {
            Mode::Cbr3 => Some(3),
            Mode::Cbr4 => Some(4),
            Mode::Cbr5 => Some(5),
            Mode::Cbr7 => Some(7),
            _ => None,
        }
    }
}

/// Which lossy wire format the lossy modes target (phase B).
/// `Mode` (the quality preset) is orthogonal to the wire format: the six
/// presets exist for BOTH formats — VBR = the measured preset table
/// verbatim, CBR = the base table scale binary-searched per frame to the
/// `in_bytes/k` size target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossyFormat {
    /// 34892/LinearRaw/8-bit (experimental/archive —
 /// dct12 is the default since the re-pin).
    K34892,
    /// Reference tag-7: 12-bit DCT parity tiles under DNG Compression 7
    /// (; docs/format-dct12.md).
    ReferenceDct,
}

/// dct12 run options. Ignored unless the lossy
/// format is `ReferenceDct`. Both absent = defaults: the embedded A001
/// curve (byte-identical to every reference's 50712 — measured
/// 12/12) and the p99-only pixel gate (no reference-MAE band).
#[derive(Clone, Debug, Default)]
pub struct ReferenceDctOpts {
    /// Reference DNG (any preset/frame of the clip): the 50712
    /// curve is byte-copied from it instead of the embedded constant.
    pub reference_ref: Option<PathBuf>,
    /// The measured per-frame reference MAE table
    /// (`quality_<preset>.tsv`: frame, mae, … tab-separated): when
    /// present, `--verify`'s G2 pixel gate adds the per-frame catastrophe
    /// ceiling (our MAE < 2.0× the measured same-frame MAE) and the
    /// per-PRESET distribution gate (FATAL for vbr-hq/vbr-lt,
    /// informational for CBR — see `g2_distribution_gate_is_fatal`).
    pub reference_mae_tsv: Option<PathBuf>,
    /// The measured per-frame reference STRUCTURE table (;
    /// tab-separated: frame, v_ratio, h_ratio, dem2_wg, dem2_gr,
    /// dem2_wr — the corpus golden's d2diag/d2demo signature, the 
    /// sweep output): when present, `--verify`'s structure gates
    /// use the per-frame reference-anchored bands (`gate_structure` upper
    /// bounds + the FATAL `gate_demosaic`); without it the
    /// reference-independent floors of `gate_structure` stay FATAL and the
    /// demosaic values are informational (same optional-anchor pattern as
    /// `reference_mae_tsv`).
    pub reference_structure_tsv: Option<PathBuf>,
}

/// The reference same-frame structure anchor: the corpus golden
/// frame's decoded 2-period ratios (v = between-row class structure, h =
/// within-row banding) + demosaic-proxy chroma stds (W−G/G−R/W−R),
/// measured with the d2diag/d2demo protocol (the sweep output;
/// `read_reference_structure` parses it per frame).
#[derive(Clone, Debug)]
pub struct ReferenceStructure {
    pub v_ratio: f64,
    pub h_ratio: f64,
    pub dem2: [f64; 3],
}

fn read_reference_structure(tsv: &Path, frame_file: &str) -> Result<ReferenceStructure> {
    let text = std::fs::read_to_string(tsv)
        .with_context(|| format!("read reference structure tsv {}", tsv.display()))?;
    for line in text.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() >= 6 && cols[0] == frame_file {
            let parse = |c: &str, what: &str| -> Result<f64> {
                c.parse::<f64>().with_context(|| {
                    format!(
                        "reference structure tsv {}: bad {what} in row {}",
                        tsv.display(),
                        cols[0]
                    )
                })
            };
            return Ok(ReferenceStructure {
                v_ratio: parse(cols[1], "v_ratio")?,
                h_ratio: parse(cols[2], "h_ratio")?,
                dem2: [
                    parse(cols[3], "dem2 W-G")?,
                    parse(cols[4], "dem2 G-R")?,
                    parse(cols[5], "dem2 W-R")?,
                ],
            });
        }
    }
    Err(anyhow::anyhow!(
        "reference structure tsv {} has no row for frame {}",
        tsv.display(),
        frame_file
    ))
}

/// A001 frame layout (3856×2170, 12-bit packed) → tile encoder .
const TILE_W_FRAME: u32 = 3856;
const TILE_H_FRAME: u32 = 2170;

/// FHD readout geometry: the fp's second
/// readout, 1936×1090 (DefaultCropSize 1920×1080 at origin (8,5) — the
/// centered window; the same 482×272 tile grid applies, 5×5 tiles with
/// standard DNG edge clipping).
const TILE_W_FRAME_FHD: u32 = 1936;
const TILE_H_FRAME_FHD: u32 = 1090;

/// Open Gate 2K readout geometry: the
/// fp's third readout on the modified firmware 5.02 (the version string
/// is unchanged — the gyro recording is additive),
/// 2016×1344 (3:2) at the native 12-bit. The same 482×272 tile grid
/// applies, 5×5 tiles with standard DNG edge clipping (2016 = 4·482 + 88,
/// 1344 = 4·272 + 256); measured on clip A001_001 (203 frames, 24 fps).
const TILE_W_FRAME_2K: u32 = 2016;
const TILE_H_FRAME_2K: u32 = 1344;

/// Open Gate 3K readout geometry: the
/// fp's fourth readout on the modified firmware 5.02 line — the
/// UNOFFICIAL mode 98 (the per-clip GyroFlow calibration names it
/// `"3024x2010 @24.000 (mode 98)"`, `"official": false`; the version
/// string is unchanged — the gyro recording is
/// additive), 3024×2010 (≈3:2) at the native 12-bit. The measured
/// reference 252×252 tile grid applies (12×8 tiles — 3024 = 12·252
/// exact, one 246 px edge row encoded at the full 252 geometry; the
/// reference header re-layout — `surgery::apply_tiled_3k`); measured on
/// clip A001_006 (114 frames, 24 fps) + the reference golden parity
/// .
const TILE_W_FRAME_3K: u32 = 3024;
const TILE_H_FRAME_3K: u32 = 2010;

fn is_tile_layout(frame: &crate::tiff::Frame) -> bool {
    frame.width == TILE_W_FRAME && frame.height == TILE_H_FRAME && frame.bits_per_sample == 12
}

/// Native-depth archive eligibility: the fp's four readout geometries
/// at the three native depths (8/10/12-bit). The
/// lossless (non-downscale) encode path accepts these at the frame's NATIVE
/// BitsPerSample (no up-conversion — the output 258 is the input's). The
/// other modes (log10/lossy/downscale2x): the UHD-12 tile layout
/// (`is_tile_layout`) — lossy stays measured there only — and the
/// mode rows : log10 (non-downscale) +
/// downscale2x (lossless) on the FHD layout (1936×1090 @12/10/8) and the
/// OG2K layout (2016×1344 @12/10/8), the measured per-depth arms; every
/// other mode × geometry × depth combination has no measured reference,
/// and the named refusals below keep them loud (the A+C boundary). The depth
/// match is the predicate's (the routing layer is generic over the native
/// depths); the PROFILE pins what was measured per geometry (the identity
/// layer — the 10/8-bit rows of all four readout geometries are measured:
/// the UHD rows: 0.1.0; the FHD + OG2K rows: the 
/// measurement ; the OG3K 12-bit row: the 
/// measurement ; the OG3K 10/8-bit rows: the 
/// measurement  — a frame at a profiled (geometry × depth)
/// passes this predicate and resolves to the archive layout at the camera
/// gate; a genuinely unprofiled combination is refused there as the named
/// class-3 unmeasured-depth mismatch).
pub(crate) fn is_archive_layout(frame: &crate::tiff::Frame) -> bool {
    matches!(
        (frame.width, frame.height),
        (TILE_W_FRAME, TILE_H_FRAME)
            | (TILE_W_FRAME_FHD, TILE_H_FRAME_FHD)
            | (TILE_W_FRAME_2K, TILE_H_FRAME_2K)
            | (TILE_W_FRAME_3K, TILE_H_FRAME_3K)
    ) && matches!(frame.bits_per_sample, 8 | 10 | 12)
}

/// The encoded frame at the buffer seam: the surgery output
/// bytes + the stats tuple — everything `run` needs for the write + the
/// FrameStats, and everything the dry run needs for the in-memory
/// sample (the bytes stay in RAM).
pub struct CoreFrame {
    pub bytes: Vec<u8>,
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub log10: Option<crate::verify::Log10Stats>,
    pub lossy: Option<crate::verify::LossyStats>,
    pub quality: Option<u32>,
    pub reference_dct: Option<crate::verify::ReferenceDctStats>,
    /// The frame class the policy table routed this frame on (the
    /// mixed-compression contract — the write layer's provenance note
    /// + the per-action verify gates read it).
    pub class: crate::frameclass::FrameClass,
    /// The per-frame action of the policy verdict (the provenance
    /// record's `action` column — the item-123 R1: the transcoded
    /// frame's class is the fp-camera class but its action is
    /// `Transcoded`, never `Carried` — the write layer's verify gate
    /// is action-keyed: the carried source-sha match applies to
    /// `Carried` only, a transcoded output differs from its source by
    /// design and verifies through the archive drill + the
    /// transcode-fidelity check).
    pub action: crate::frameclass::FrameAction,
}

/// The in-memory per-frame encode result (the dry-run sample
/// table row): the encoded bytes + the per-frame measurement (source B,
/// encoded B, ratio, the encode+verify wall ms, the verify-pass wall
/// ms — the report's per-frame encode/verify split).
pub struct MemFrame {
    pub file: String,
    pub bytes: Vec<u8>,
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub ratio: f64,
    /// The encode+verify wall ms (no write — the in-memory caller).
    pub ms: f64,
    /// The verify-pass wall ms (the decode + the content/metadata
    /// gates) — the encode wall is `ms - verify_ms`.
    pub verify_ms: f64,
}

// =====================================================================
// The per-frame policy table (the mixed-compression contract — the
// class × mode table, the design's D3 move): the v1 row is the
// MEASURED one (the lossless row — the raw class encodes as today,
// byte-frozen); the fp-camera class's lossless cell is the item-123
// R0 ruling: TRANSCODE by default (the fp frame is decoded through the
// item-122 path + re-encoded through the existing archive path — every
// output frame is in the measured, NLE-verified archive contract);
// the `--carry` flag is the explicit opt-in for the byte-exact source
// copy (the item-121 row — the provenance opt-in + the unproven-
// structure fallback; a no-op outside the fp-camera class, so the
// raw-only behavior is untouched by construction); every other row =
// the pinned named refusal (the `frameclass` wordings — the fp-camera
// × {log10, lossy, downscale2x} rows are the v1 boundary, the log10/
// ds2x × mixed-as-Transcode rows are LATER, not item 123; the archive
// class is the decode/verify-verb class, the unknown class is the
// named refusal). The dry-run sample dispatch mirrors this table (one
// function, one contract).
// =====================================================================

/// The per-frame policy verdict (the table's output cell).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramePolicy {
    /// The existing encode path (the bit-exact round-trip verify —
    /// the raw class, byte-frozen).
    Encode,
    /// The byte-exact source copy (no pixel access — the carried
    /// frame's verify = the source-sha match, never a decode). The
    /// `--carry` opt-in (the item-121 row, the provenance opt-in).
    Carry,
    /// The transcode (the item-123 R0 ruling — the fp-camera class's
    /// lossless cell, the default): decode the fp frame through the
    /// item-122 path + re-encode through the existing archive path
    /// (the output is a frame in the tool's measured archive contract;
    /// the verify = the archive bit-exact drill on the output + the
    /// transcode-fidelity check — decode(output) == the decoded input
    /// plane, pixel-exact).
    Transcode,
    /// The pinned named refusal (the `frameclass` wordings).
    RefuseNamed,
}

/// The policy table (class × mode → the verdict): the four classes ×
/// the four rows (lossless / log10 / lossy / downscale2x) — the lossless
/// row is the measured contract (raw = Encode, fp-camera = the R0
/// ruling cell: Transcode by default, Carry under the explicit
/// `--carry` opt-in), the rest is the pinned named refusal. `carry`
/// flips ONE cell (the fp-camera × lossless cell: Transcode → Carry);
/// the other 15 cells are carry-invariant (the flag is a no-op
/// outside the fp-camera class).
pub fn policy(
    class: crate::frameclass::FrameClass,
    mode: Mode,
    downscale: bool,
    carry: bool,
) -> FramePolicy {
    match class {
        crate::frameclass::FrameClass::RawUncompressed => FramePolicy::Encode,
        crate::frameclass::FrameClass::FpCameraLossless => {
            if mode == Mode::Lossless && !downscale {
                if carry {
                    FramePolicy::Carry
                } else {
                    FramePolicy::Transcode
                }
            } else {
                FramePolicy::RefuseNamed
            }
        }
        crate::frameclass::FrameClass::FramePrismArchive
        | crate::frameclass::FrameClass::Unknown => FramePolicy::RefuseNamed,
    }
}

// =====================================================================
// The `--carry` process-wide flag (the item-123 R0 ruling — the
// explicit opt-in for the fp-camera frames' byte-exact source copy
// instead of the transcode default). The `subset_flag` / `resume`
// pattern: `main` sets it before the dispatch; the encode path's
// `run` (the 14-arg `process_dir` signature is unchanged) reads it
// per frame; the dry-run seam takes it explicitly (`dryrun::Opts::
// carry` — the in-process tests set it directly). A no-op outside the
// fp-camera class (the raw-only path is byte-frozen by construction).
// =====================================================================

static CARRY_FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set the `--carry` opt-in (the CLI site, before the dispatch).
pub fn set_carry_flag(carry: bool) {
    CARRY_FLAG.store(carry, std::sync::atomic::Ordering::Relaxed);
}

/// Read the `--carry` opt-in (the encode path's `run` — the encode
/// run's flag is stable for the run's duration; the dry-run seam
/// reads `Opts::carry` instead, never this).
pub fn carry_flag() -> bool {
    CARRY_FLAG.load(std::sync::atomic::Ordering::Relaxed)
}

// =====================================================================
// The `--trial` process-wide flag (the item-126 Stage-1 ruling — the
// base default's per-tile size-min trial, BYTE-FROZEN, behind a flag;
// the `--carry` precedent: the old behavior behind a flag). The 482
// grid's SELECTION DEFAULT flipped to the fixed single W7 candidate
// (today's `--fast` behavior — the flip's named give-up is the
// reference-product byte parity the trial bought, at the measured
// 2.67× workload factor; that contract lives on the `--trial` path +
// the re-pointed m1gate gate). The `subset_flag` / `resume` pattern:
// `main` sets it before the dispatch (the encode path's site + the
// dry-run dispatch's site — the estimate dispatches before the encode
// run's process-flag site, the 123 note); the 12/10-bit lossless
// tile loop's selection condition reads it. 482-scoped by construction
// — on the other grids the flag is accepted-but-inert (their shipped
// selection is unaffected) and the ds2x (downscale) rows keep the
// trial default (the other grids' byte-invariance pin).
// =====================================================================

static TRIAL_FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set the `--trial` opt-in (the CLI site, before the dispatch).
pub fn set_trial_flag(trial: bool) {
    TRIAL_FLAG.store(trial, std::sync::atomic::Ordering::Relaxed);
}

/// Read the `--trial` opt-in (the encode path's tile loop — the encode
/// run's flag is stable for the run's duration; the in-process tests
/// set it explicitly per the `set_carry_flag` corpus-KAT pattern).
pub fn trial_flag() -> bool {
    TRIAL_FLAG.load(std::sync::atomic::Ordering::Relaxed)
}

// =====================================================================
// The fp temporal-oracle (item 124 — R2, the owner's ruling (a)) —
// the resolver builder + the census count plumbing
// =====================================================================
// The tile-local drill (the item-122 R4 site in decode.rs) refuses a
// whole-body-divergent fp tile (the camera encoder's non-canonical
// whole-body lossless coding — 3/17,376 tiles measured, the
// adjudication 2026-09-30) unless the thread-local oracle slot
// (the encode's own thread — the PM gate ruling, 2026-10-01)
// carries a ctx (the fp TRANSCODE path only — `process_dir` /
// the dry-run sample set it around a frame's encode; the decode
// verb, carry, archive, and jxl paths never set it). The ctx's
// resolver answers the drill's gate: "for this frame's disputed
// tile i, is there a SAME-CLASS temporal neighbor whose SAME TILE is
// drill-verified (the canonical form), and what is its decoded
// full-nominal plane?" — the drill then accepts iff the planes match
// within the pinned bound (`decode::FP_TEMPORAL_MAX_DELTA`).

/// The fp temporal-oracle resolver builder (item 124 — R2): the
/// per-frame ctx the fp TRANSCODE path's callers set around a
/// frame's encode measurement. The resolver closure walks the
/// frame's ordinal ± 2k outward (k = 1, 2, … — the fp frames are the
/// ODD ordinals, 2 apart, the clip's alternating structure): the
/// candidate must be in `clip` (the clip's frame list — the ordinal
/// in range) AND pre-pass-classified `fp-camera-lossless` (the class
/// check is the generic guard; a raw / archive / unknown neighbor is
/// skipped, never a verified neighbor). The winning candidate's same
/// tile is read (READ-ONLY — the resolver never writes; the neighbor
/// bytes are cached per clip) + single-tile verified through the
/// product's own drill core (`decode::fp_verify_tile_full_nominal` —
/// the 4-call core, strict-or-bounded-tail). `Ok(plane)` = the
/// neighbor's decoded full-nominal tile plane (the oracle's
/// comparison domain) — memoized (neighbor, tile) → accept; `Err` =
/// the candidate is not a verified neighbor (a whole-body divergence
/// at this tile, a geometry mismatch, a read failure) — the reject is
/// memoized too, and the walk continues OUTWARD to the next k (a
/// farther same-class neighbor may be the clean one). The clip's
/// ordinal boundary (both directions past the clip's own ordinal
/// range) = `None` — no verified neighbor at this tile (the existing
/// named refusal stands — the no-neighbor path the NO-NEIGHBOR PIN
/// byte-pins). Both outcomes memoized: a disputed frame drills a
/// neighbor tile at most once per clip (the walk is over the small
/// tile count, the memo makes it O(1) after the first miss).
/// (the disputed name the drill passes must match the encoded
/// frame's name; a stale / mis-set ctx never answers another frame's
/// drill — the safe direction: a mismatched name resolves `None` and
/// the refusal stands).
///
/// The oracle's neighbor read cache (item 124 — the R2 contract's
/// read-only side): neighbor absolute path → the file bytes
/// (`None` = the read failed — the candidate is rejected); each
/// neighbor frame is read at most once per frame.
type FpTemporalBytesCache =
    std::sync::Mutex<std::collections::HashMap<String, Option<Vec<u8>>>>;

/// The oracle's single-tile memo: (neighbor name, tile idx) → the
/// verified plane (`Some`) / the rejected candidate (`None`) — both
/// outcomes memoized (the walk never re-drills a settled tile).
type FpTemporalMemo =
    std::sync::Mutex<std::collections::HashMap<(String, usize), Option<Vec<u16>>>>;

pub(crate) fn fp_temporal_resolver(
    input_root: &Path,
    clip: &[(PathBuf, crate::frameclass::FrameClass, Option<u64>)],
    frame_name: &str,
) -> crate::decode::FpTemporalOracleCtx {
    // The encoded frame's ordinal (the walk's origin — the product's
    // existing parse of the file field; `None` = not the fp pattern →
    // no walk, every tile resolves `None`).
    let frame_ord = Path::new(frame_name)
        .file_stem()
        .and_then(|s| s.to_str())
        .and_then(crate::worker::checksums::frame_number_from_stem);
    // The owned data (the ctx is the thread-local slot — the
    // closure must be `'static`: the input root + the clip list are
    // CLONED, the caches are moved — the clip is the small frame list
    // of the run, the set happens once per frame).
    let input_root = input_root.to_path_buf();
    let clip = clip.to_vec();
    // The encoded frame's name (the cross-check: the ctx answers ONLY
    // the drill of the frame it was built for — the disputed name the
    // drill passes must match the encoded frame's name; a stale /
    // mis-set ctx never answers another frame's drill — the safe
    // direction: a mismatched name resolves `None` and the refusal
    // stands).
    let frame_name = frame_name.to_string();
    let bytes_cache: FpTemporalBytesCache =
        std::sync::Mutex::new(std::collections::HashMap::new());
    // The single-tile memo (the type alias above): (neighbor name,
    // tile idx) → the verified plane / the rejected candidate — both
    // outcomes memoized.
    let memo: FpTemporalMemo =
        std::sync::Mutex::new(std::collections::HashMap::new());
    // The clip's ordinal range (the walk's boundary — a candidate
    // ordinal is possible only within the clip's own frame ordinals;
    // an `None` bound (no ordinal in the clip) = unbounded on that
    // side — the candidate lookup still requires a clip member).
    let (min_ord, max_ord) = clip.iter().fold((Option::<u64>::None, Option::<u64>::None), |(lo, hi), &(_, _, o)| {
        match o {
            Some(v) => (
                lo.map(|l| l.min(v)).or(Some(v)),
                hi.map(|h| h.max(v)).or(Some(v)),
            ),
            None => (lo, hi),
        }
    });
    let resolve: crate::decode::FpTemporalResolver =
        Box::new(move |name, tile_idx| {
            // The cross-check first (the ctx is per-frame — a name
            // mismatch = no answer, the refusal stands).
            if name != frame_name {
                return None;
            }
            let ord = match frame_ord {
                Some(o) => o,
                None => return None,
            };
            // The ±2k outward walk (k = 1, 2, …): the candidate
            // ordinals ord±2k (the fp parity — the even ordinals are
            // the raw frames' structure; the class check below is
            // the generic guard that enforces it). `name` (the
            // disputed frame's file name, the drill's `what`) rides
            // along for the memo's key + the candidate's verify
            // naming (the seam's error context).
            let mut k: u64 = 1;
            loop {
                let step = 2 * k;
                let cands: [Option<u64>; 2] = [
                    ord.checked_sub(step)
                        .filter(|o| min_ord.map(|m| *o >= m).unwrap_or(true)),
                    ord.checked_add(step)
                        .filter(|o| max_ord.map(|m| *o <= m).unwrap_or(true)),
                ];
                for cand_ord in cands.into_iter().flatten() {
                    // The candidate must be a clip member pre-pass-
                    // classified fp-camera-lossless — otherwise skip
                    // (the alternating parity is the clip's structure;
                    // the class check is the generic guard).
                    let Some((cand_path, cand_class, _)) = clip
                        .iter()
                        .find(|(_, _, o)| *o == Some(cand_ord))
                    else {
                        continue;
                    };
                    if *cand_class != crate::frameclass::FrameClass::FpCameraLossless {
                        continue;
                    }
                    let cand_name = cand_path
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    // The memo (both outcomes — a settled tile is
                    // never re-drilled): hit = the walk's answer.
                    let key = (cand_name.clone(), tile_idx);
                    {
                        let m = memo
                            .lock()
                            .expect("the fp temporal memo lock poisoned");
                        if let Some(v) = m.get(&key) {
                            return v.clone();
                        }
                    }
                    // The candidate's same tile, verified through the
                    // product's own drill core (the single-tile seam —
                    // the 4-call core, strict-or-bounded-tail):
                    // `Ok` = the drill-verified canonical form (the
                    // neighbor's decoded full-nominal plane); `Err`
                    // = the candidate is not a verified neighbor at
                    // this tile (a whole-body divergence there, a
                    // geometry mismatch, a read failure) — the reject
                    // is memoized + the walk continues outward.
                    let plane = neighbor_tile_plane(
                        &input_root,
                        cand_path,
                        &cand_name,
                        tile_idx,
                        &bytes_cache,
                    );
                    {
                        let mut m = memo
                            .lock()
                            .expect("the fp temporal memo lock poisoned");
                        m.insert(key, plane.clone());
                    }
                    if plane.is_some() {
                        return plane;
                    }
                }
                // The next k outward — the boundary: both directions
                // past the clip's ordinal range = no more candidates
                // (the no-neighbor path — the existing named refusal
                // stands; the NO-NEIGHBOR PIN's shape).
                let (beyond_lo, beyond_hi) = (
                    ord.checked_sub(2 * (k + 1))
                        .map(|o| min_ord.map(|m| o < m).unwrap_or(false))
                        .unwrap_or(true),
                    ord.checked_add(2 * (k + 1))
                        .map(|o| max_ord.map(|m| o > m).unwrap_or(false))
                        .unwrap_or(true),
                );
                if beyond_lo && beyond_hi {
                    return None;
                }
                k += 1;
            }
        });
    crate::decode::FpTemporalOracleCtx {
        resolve,
        verified: std::sync::atomic::AtomicUsize::new(0),
    }
}

/// The resolver's single-tile read + verify (item 124 — R2): the
/// neighbor frame's tile `tile_idx` decoded through the product's own
/// drill core. `None` = the candidate is not a verified neighbor (the
/// read / parse / geometry / drill failed at any step — the safe
/// direction: an unverifiable candidate is NEVER an oracle answer).
fn neighbor_tile_plane(
    input_root: &Path,
    cand_path: &Path,
    cand_name: &str,
    tile_idx: usize,
    bytes_cache: &std::sync::Mutex<std::collections::HashMap<String, Option<Vec<u8>>>>,
) -> Option<Vec<u16>> {
    // The neighbor's bytes (read-only, cached per clip — the path is
    // joined against the input root when relative; the callers pass
    // the clip's frame paths, relative to the input root).
    let cand_abs = if cand_path.is_absolute() {
        cand_path.to_path_buf()
    } else {
        input_root.join(cand_path)
    };
    let cache_key = cand_abs.display().to_string();
    let bytes = {
        let mut c = bytes_cache
            .lock()
            .expect("the fp temporal bytes-cache lock poisoned");
        match c.get(&cache_key) {
            Some(v) => v.clone(),
            None => {
                let v = std::fs::read(&cand_abs).ok();
                c.insert(cache_key, v.clone());
                v
            }
        }
    }?;
    // The neighbor's IFD (the grid pin — the fp camera's measured
    // 512×368 tile structure; a different geometry is not a same-
    // class neighbor — the safe direction).
    let meta = crate::tiff::read_meta(&bytes).ok()?;
    let s = crate::frameclass::structure_from_ifd0(&meta);
    let (tw, th) = (s.tile_width?, s.tile_height?);
    if tw != 512 || th != 368 {
        return None; // not the fp camera's tile structure
    }
    let (width, height) = (s.width?, s.height?);
    let bps = s.bits_per_sample? as u32;
    // The drill's grid (the product's own derivation — `decode_\
    // j92_frame` derives it from the FILE's own 322/323, not the
    // frame dims: the fp camera's 512×368 source grid — 8×6 = 48
    // tiles; the same derivation the disputed frame's own drill ran).
    let grid = crate::tileenc::Grid::for_dims(width, height, tw, th);
    if (tile_idx as u32) >= grid.cols * grid.rows {
        return None;
    }
    let r = (tile_idx as u32) / grid.cols;
    let c = (tile_idx as u32) % grid.cols;
    // The tile stream's location (the product's own 324/325 LONG
    // out-of-line read — the same seam the decode path uses):
    let (offs, lens) = crate::decode::tile_offsets_and_lens(&meta, &bytes, cand_name).ok()?;
    if tile_idx >= offs.len() {
        return None;
    }
    let stored = &bytes[offs[tile_idx] as usize..offs[tile_idx] as usize + lens[tile_idx] as usize];
    // The single-tile drill core (the product's own 4-call core —
    // strict-or-bounded-tail; `Ok` = the drill-verified neighbor's
    // decoded full-nominal plane — the oracle's comparison domain):
    crate::decode::fp_verify_tile_full_nominal(stored, width, height, &grid, r, c, bps, cand_name).ok()
}

// =====================================================================
// The per-frame fp temporal-verified count (item 124 — R4 — the
// census count plumbing)
// =====================================================================
// The clip's census term (`· temporal-verified {n}`) source: the
// encode run's per-frame oracle-verified tile count, noted at the
// process_dir write site (the frame's ctx counter read before the
// clear — the same thread that set the thread-local ctx: the
// frame's `process` closure, any jobs incl. the default 0 = the
// full pool) and claimed
// by the report's census write site per sidecar row key. Absent key
// = 0 (the non-transcode callers — the raw class / the carry / the
// resume-skip — and every clip the oracle verified nothing).
static FP_TEMPORAL_VERIFIED: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeMap<String, usize>>,
> = std::sync::OnceLock::new();

/// Note a frame's oracle-verified tile count (item 124 — R4): the
/// process_dir write site (the frame's ctx counter, read before the
/// ctx clear — the same thread). The note replaces any earlier value
/// for the key (a frame encodes once per run — the resume-skip
/// never re-encodes, never re-notes).
pub(crate) fn note_fp_temporal_verified(rel: &str, n: usize) {
    let map = FP_TEMPORAL_VERIFIED
        .get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));
    map.lock()
        .expect("the fp temporal verified registry lock poisoned")
        .insert(rel.to_string(), n);
}

/// Claim a frame's oracle-verified tile count (item 124 — R4): the
/// report's census write site (per sidecar row key — the same key
/// the frameclass provenance claim uses). Absent = 0 (the 123 shape
/// — no term, byte-frozen).
pub(crate) fn claim_fp_temporal_verified(rel: &str) -> usize {
    FP_TEMPORAL_VERIFIED
        .get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
        .lock()
        .expect("the fp temporal verified registry lock poisoned")
        .get(rel)
        .copied()
        .unwrap_or(0)
}

/// The mode's fill value for the fp-camera refusal line (deterministic
/// and honest: the preset family is named `lossy`, the downscale is
/// additive — the line names the UNMEASURED row; the preset's
/// specifics are the lossy-format's own named lines). The dry-run
/// sample dispatch's mirror uses the same naming (one mode name, one
/// place).
pub fn mode_name(mode: Mode, downscale: bool) -> String {
    let base: &str = match mode {
        Mode::Lossless => "lossless",
        Mode::Log10 => "log10",
        _ => "lossy",
    };
    if downscale {
        format!("{base}+downscale2x")
    } else {
        base.to_string()
    }
}

/// The pinned refusal line for a refused row (the wording chosen by
/// the class + the measured structure — the R5 pinned forms, byte-for-
/// byte). `None` = the Unknown row without a nameable structure (no
/// readable compression value, not tiled) — the strict parse's own
/// named line (the MissingTag / the structural class) stands in its
/// place; it is still a named refusal (only the generic TiledInput
/// line stays classifier-free, and it is the strict parse's). The
/// dry-run sample dispatch's mirror uses the same chooser (one line,
/// one place).
pub fn refusal_line(
    class: crate::frameclass::FrameClass,
    s: &crate::frameclass::FrameStructure,
    name: &str,
    mode: Mode,
    downscale: bool,
) -> Option<String> {
    use crate::frameclass as fc;
    match class {
        fc::FrameClass::FpCameraLossless => Some(fc::fp_camera_mode_line(
            &mode_name(mode, downscale),
            name,
        )),
        fc::FrameClass::FramePrismArchive => Some(fc::frameprism_archive_line(name)),
        fc::FrameClass::Unknown => {
            if s.tiled {
                Some(fc::unknown_tile_grid_line(
                    s.tile_width, s.tile_height, s.tile_count, name,
                ))
            } else {
                s.compression
                    .map(|c| fc::compression_unsupported_line(c, name))
            }
        }
        fc::FrameClass::RawUncompressed => None, // unreachable (the policy cell is Encode)
    }
}

/// The verify-class error context: a verify-gate failure is
/// named at the line level (`verify: <err>`). The normal-path per-frame
/// FAIL line gains the class prefix on a verify failure — stdout is NOT
/// a byte contract; the verdict/total lines keep their shape
/// byte-stable.
/// The verify-class error prefix (the classification): every
/// VERIFY-GATE failure inside `encode_core` is tagged `verify: {e}` by
/// this constructor, so a failure message starting with `verify: ` is
/// a sample VERIFY failure (the round-trip broke — the codec's
/// honesty anchor failed) and anything else is an ENCODE failure
/// (parse/structural/IO). `dryrun::is_verify_failure` consumes the
/// prefix (the G6 classification test proves the routing).
pub fn vctx(e: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("verify: {e}")
}

/// The per-frame encode+verify core at the buffer seam (the
/// dry-run sample encode runs this and keeps the encoded bytes in RAM):
/// everything from the source read through the verify gates. The ATOMIC
/// tmp+rename write is NOT here (`run` = this core + the write; the
/// in-memory caller = this core without the write — the dry run never
/// touches `<dest>`, not even the dir).
#[allow(clippy::too_many_arguments)]
fn encode_core(
    src: &Path,
    verify: bool,
    mode: Mode,
    downscale: bool,
    fast: bool,
    lossy_format: LossyFormat,
    reference: &ReferenceDctOpts,
    qc_rel: Option<&str>,
    profiles: Option<&crate::camera::ProfileSet>,
    carry: bool,
    verify_ms: &mut f64,
) -> Result<CoreFrame> {
    //: The item-125 profile phase (`read` — the source file's fs::read,
    // the worker path's read site; the guard is a checked no-op at the
    // gate OFF):
    let buf = {
        let _p = crate::profile::phase("read").start();
        let raw = std::fs::read(src).with_context(|| format!("read {}", src.display()))?;
        raw
    };
    //: the source-sha anchor at the READ SITE (the verify-
    // before-wipe gate): hash the source buffer DURING the encode read
    // — one read, one hash (the buffer is already in memory for the
    // decode — NO second full-file read; the card I/O is the
    // bottleneck). Keyed by the sidecar row key (the report's
    // `<CLIP>.sources.tsv` record claims it); absent key = a
    // non-encode caller (no note).
    if let Some(qc_rel) = qc_rel {
        crate::sourcecheck::note_source_sha(qc_rel, &crate::jxl::sha256_hex(&buf));
    }
    //: the frame-class dispatch (the mixed-compression contract — the
    // class × mode table): classify from the IFD-only structure
    // (read_meta — the pixel-free parse — the classifier never reads
    // past the IFD) and route BEFORE the strict strip parse.
    // RawUncompressed = the existing path below, byte-frozen (the
    // strict read + the routing are unchanged for the raw class);
    // FpCameraLossless × lossless = the Carry (the byte-exact source
    // copy — no pixel access, no decode, no re-pack, no rewrite — the
    // tmp+rename write is the write layer's, the carried frame's
    // verify = the source-sha match there); every other row = the
    // pinned named refusal (the frameclass wordings — the generic
    // TiledInput line is unreachable here: every tag-7 frame is
    // classified before the strict read; it survives for the
    // non-encode `tiff::read` callers only).
    let meta = crate::tiff::read_meta(&buf)?;
    let class = crate::frameclass::classify(&meta);
    let structure = crate::frameclass::structure_from_ifd0(&meta);
    let file_name = src
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let src_len = buf.len() as u64;
    // The `--carry` opt-in (the explicit parameter — the encode run's
    // `run` passes the process-wide flag; the dry-run seam passes its
    // `Opts::carry`; the raw class is carry-invariant, the flag is a
    // no-op there).
    let verdict = policy(class, mode, downscale, carry);
    match verdict {
        FramePolicy::Encode => {
            // The raw class — the existing path, byte-frozen.
        }
        FramePolicy::Carry => {
            // The Carry (the item-121 row — the `--carry` opt-in):
            // the source bytes pass through untouched — the frame is
            // the output.
            let len = buf.len() as u64;
            return Ok(CoreFrame {
                bytes: buf,
                in_bytes: len,
                out_bytes: len,
                log10: None,
                lossy: None,
                quality: None,
                reference_dct: None,
                class: crate::frameclass::FrameClass::FpCameraLossless,
                action: crate::frameclass::FrameAction::Carried,
            });
        }
        FramePolicy::Transcode => {
            // The Transcode (the item-123 R0 ruling — the fp-camera ×
            // lossless cell, the default): the frame is DECODED through
            // the item-122 shipped path (the R4 bounded-tail drill
            // gates the INPUT — a corrupt fp frame is a loud named
            // refusal here, before any encode) and RE-ENCODED through
            // the existing archive path below (the synthetic raw-
            // equivalent source — the fp's own IFD0 metadata on the
            // strip-layout contract the surgery's layout model
            // requires — so the archive branch + the existing verify
            // gates run UNCHANGED).
        }
        FramePolicy::RefuseNamed => {
            if let Some(line) = refusal_line(class, &structure, &file_name, mode, downscale) {
                anyhow::bail!("{line}");
            }
            // The Unknown row without a nameable structure: the strict
            // parse's own named line stands (the fall-through below —
            // still a named refusal, never a silent skip).
        }
    }
    //: the source seam — raw (the strict parse + the strip unpack,
    // unchanged) or transcode (the decoded plane + the synthetic raw-
    // equivalent source). `tc_in` = the decoded input plane kept alive
    // for the transcode-fidelity check (R1 verify (b) — the output's
    // decoded plane must equal it pixel-exactly); present only on the
    // transcoded frame's verify pass.
    let (buf, frame, samples, tc_in): (Vec<u8>, crate::tiff::Frame, Vec<u16>, Option<Vec<u16>>) =
        match verdict {
            FramePolicy::Transcode => {
                let (tw, th, plane) = crate::decode::decode_j92_frame(&buf, &file_name)?;
                // The item-125 profile phase (`source-synth` — the
                // `fp_transcode_source` synthetic raw-equivalent buffer
                // build; the guard is a checked no-op at the gate OFF):
                let (syn_buf, syn_frame) = {
                    let _p = crate::profile::phase("source-synth").start();
                    fp_transcode_source(&meta, &buf, &file_name)?
                };
                if (tw, th) != (syn_frame.width, syn_frame.height) {
                    anyhow::bail!(
                        "transcode seam: the decoded plane {tw}×{th} disagrees with the IFD structure {}×{} — frame {file_name} (the decode and the IFD must agree; a delta is a STOP finding, not a tuning question)",
                        syn_frame.width, syn_frame.height
                    );
                }
                let tc_in = if verify { Some(plane.clone()) } else { None };
                (syn_buf, syn_frame, plane, tc_in)
            }
            _ => {
                let frame = crate::tiff::read(&buf)?;
                let packed = frame.strip_slice(&buf);
                let samples = match frame.bits_per_sample {
                    8 => crate::pack12::unpack8(packed, frame.width, frame.height),
                    10 => crate::pack12::unpack10(packed, frame.width, frame.height),
                    _ => crate::pack12::unpack12(packed, frame.width, frame.height),
                }?;
                (buf, frame, samples, None)
            }
        };
    let is_transcode = matches!(verdict, FramePolicy::Transcode);
    //: the per-frame camera identity gate (the encode surface):
    // the run-gate prepass in process_dir resolved EVERY frame against
    // the profile set before any write; this layer re-resolves the
    // ALREADY-PARSED frame against the same loaded set (no second
    // parse — the identity rides the Frame's verbatim IFD0) and refuses
    // a file changed between the gate and the encode, named, before any
    // write. A profiled frame passes to the routing EXACTLY as before
    // (the A001 profile = the embedded constants — the routing at the
    // native-depth / tile / single-strip paths is untouched). The
    // transcode's synthetic source carries the fp frame's verbatim
    // IFD0 — the identity gate runs on it unchanged.
    if let Some(set) = profiles {
        let ident = crate::camera::identity_from_ifd0(&frame.ifd0, &buf)
            .map_err(|err| anyhow::anyhow!("camera identity: {err}"))?;
        if let crate::camera::Resolution::Mismatch(m) = crate::camera::resolve(set, &ident) {
            anyhow::bail!("{}", m.named_line());
        }
    }
    // Native-depth unpack (8/10/12-bit are all parse-eligible;
    // the same DNG nominal convention the pack12 12-bit rule verified
    // pixel-exact — big-endian word, MSB-first, trailing padding
    // ignored). The transcode's samples are the DECODED plane (the
    // item-122 path — the strip unpack is the raw arm's; the seam's
    // match above carries both).
    // (c)+(a): the single-pass decoded-plane stats (the exposure
    // min/max/mean + the black/blank variance) — they RIDE this unpack
    // (ONE pass, no second decode — the pinned execution order: the
    // cheap (b) check runs on the sidecar sha rows later, before the
    // (a)+(c) report rendering) and NEVER alter the encode pipeline
    // (observation only — the byte contract). The stats flow through
    // the qc registry (worker::FrameStats is shared with the jxl path
    // — the read-only constructor), keyed by the sidecar row key
    // (absent = a non-encode caller: no stats, no note).
    if let Some(qc_rel) = qc_rel {
        crate::qc::note(
            qc_rel,
            crate::qc::frame_stats(qc_rel, &samples, frame.bits_per_sample as u32),
        );
    }
    // downscale2x decimation rule from the CFA tags (reference
    // staircase for the fp's symmetric W G / G R pattern; phase-exact
    // fallback for asymmetric patterns / non-zero anchors). Computed once
    // per frame; the verify gates re-derive the same rule (downscale::
    // decimation_rule is a pure tag read).
    let ds_rule = crate::downscale::decimation_rule(&buf, &frame);

    let (out, log10_stats, lossy_stats, quality, reference_stats) =
        if mode == Mode::Lossless && !downscale && !is_tile_layout(&frame) && is_archive_layout(&frame) {
            // ---------- native-depth tile path ----------
            // FHD 1936×1090 (any native depth) + Open Gate 2K 2016×1344
            // (any native depth) + 8/10-bit inputs (any archive
            // geometry): the SAME reference tile structure at the
            // frame's NATIVE BPS precision (8/10/12 — the DNG
            // BitsPerSample is preserved: TilePlan bps_patch = None, so
            // the expected-diff set is the existing lossless plan), on
            // the gate's MEASURED grid (the per-(geometry × depth)
            // contract — `Grid::for_depth`: the FHD gate's depth-varying
            // grid 242×274 @12/8 / 484×274 @10, every other gate the
            // unchanged contract — the byte-invariance pin). Lossless
            // non-downscale only: the FHD + OG2K log10/downscale2x
 // measured rows (contract) ride the mode branch below; every other mode
            // stays on the UHD-12 tile branch (the named refusals in the
            // strip fallback cover the unmeasured combinations — the
            // A+C boundary).
            let precision = frame.bits_per_sample as u32;
            let grid = crate::tileenc::Grid::for_depth(
                frame.width,
                frame.height,
                frame.bits_per_sample as u32,
            );
            let mut tiles = Vec::with_capacity((grid.cols * grid.rows) as usize);
            if fast {
                for r in 0..grid.rows {
                    for c in 0..grid.cols {
                        tiles.push(crate::tileenc::encode_tile_fast(
                            &samples,
                            frame.width,
                            frame.height,
                            &grid,
                            r,
                            c,
                            precision,
                        )?);
                    }
                }
            } else {
                for r in 0..grid.rows {
                    for c in 0..grid.cols {
                        tiles.push(crate::tileenc::encode_tile(
                            &samples,
                            frame.width,
                            frame.height,
                            &grid,
                            r,
                            c,
                            precision,
                        )?);
                    }
                }
            }
            if verify {
                let _tv = Instant::now();
                // Content gate BEFORE surgery (the worker's own unpacked
                // plane — no second unpack; the decode side accepts the
                // stream's SOF3 precision, so the gate runs at the native
                // depth).
                crate::verify::bit_exact_tiled_plane(
                    &samples,
                    frame.width,
                    frame.height,
                    &grid,
                    &tiles,
                    precision,
                )
                .map_err(vctx)?;
                *verify_ms += _tv.elapsed().as_secs_f64();
            }
            // The Open Gate 3K gate (3024×2010) encodes on the measured
            // 252×252 grid through the measured reference re-layout
            // surgery (`apply_tiled_3k` — the NLE media-offline fix);
            // the FHD gate (1936×1090) encodes on its per-depth
            // measured grid (242×274 @12/8, 484×274 @10) through the
            // surgical `apply_tiled` path (the per-gate `tile_dims`
            // ride the plan — `TilePlan::lossless_gate`); every other
            // native-depth geometry keeps the surgical 482×272 path
            // (byte-invariant).
            let out = if crate::tileenc::is_3k_gate(frame.width, frame.height) {
                crate::surgery::apply_tiled_3k(&buf, &frame, &tiles)
                    .map_err(|e| anyhow::anyhow!("tile surgery: {e}"))?
            } else {
                crate::surgery::apply_tiled(&buf, &frame, &tiles)
                    .map_err(|e| anyhow::anyhow!("tile surgery: {e}"))?
            };
            if verify {
                let _tv = Instant::now();
                // The expected-diff set is the existing lossless plan
                // (259 → 7, the strip tags dropped, 322-325 added;
                // BitsPerSample UNCHANGED — native depth preserved).
                crate::verify::metadata_preserved_tiled(&buf, &out.bytes, &frame, &tiles)
                    .map_err(vctx)?;
                *verify_ms += _tv.elapsed().as_secs_f64();
            }
            (out, None, None, None, None)
        } else if (crate::tileenc::is_fhd_gate(frame.width, frame.height)
            || crate::tileenc::is_og2k_gate(frame.width, frame.height)
            || crate::tileenc::is_3k_gate(frame.width, frame.height)
            || (crate::tileenc::is_uhd_gate(frame.width, frame.height)
                && frame.bits_per_sample != 12))
            && is_archive_layout(&frame)
            && ((mode == Mode::Log10 && !downscale) || (mode == Mode::Lossless && downscale))
        {
            // ---------- FHD + OG2K + OG3K + UHD @10/@8 mode path (the
 // measured contract — the per-gate mode
 // onboarding, ) ----------
 // The FHD gate's (1936×1090 @12/10/8 — ) + the OG2K
 // gate's (2016×1344 @12/10/8 — ) + the OG3K gate's
 // (3024×2010 @12/10/8 — ) + the UHD gate's @10/@8
 // mode rows (3856×2170 @10/8 — ; the @12 UHD mode
            // rows are EXCLUDED — the frozen 0.1.0-era outputs on the
 // `is_tile_layout` branch: the byte-invariance's 2-mode
            // controls) measured mode rows.
            // The branch is gate-generic: the per-depth grid rides
            // `gate_tile_dims_depth` (the FHD per-depth grid 242×274
            // @12/@8 / 484×274 @10; the OG2K depth-invariant 252×336;
            // the OG3K depth-invariant 252×252 — all measured), the
            // family rides `gate_candidates` (the
            // grid×mode-keyed routing — `FHD_CANDIDATES` /
            // `OG2K_CANDIDATES` / `CANDIDATES` on the full-resolution
            // rows, the DS2X families on the half-resolution geometry),
            // and the surgery/verify per-arm wrappers are gate-generic
            // (the frame-driven crop + the per-arm BPS/LUT plans; the
            // OG3K rows ride the measured 3K re-layout surgery —
            // `apply_tiled_3k_log10` / `apply_tiled_3k_downscale`).
            // - log10 (non-downscale): the full-resolution plane on the
            //   measured per-depth grid, precision 10, the grid-keyed
            //   gate family (`gate_candidates_for_grid` →
            //   `FHD_CANDIDATES` / `OG2K_CANDIDATES` — the 3-member
 // {W7, W6, N5} — the censuses ZERO 0 · MULTI 0).
            //   Per-arm content: @12 = the 10-bit log codes (12-bit →
            //   codes via the built-in LUT's inverse; the tool writes its
 // own embedded A001 1024 LUT — the measured LUT decision: the
            //   reference's per-frame table is its calibration payload,
 // the free class); @10 = the raw 10-bit passthrough
            //   (the measured maxdiff 0 vs the raw samples — content-
            //   identical to the gate's lossless @10 plane); @8 = the
            //   8-bit samples identity-promoted into the measured BPS10
            //   container (the mode tier's BPS split — the lossless
 // tier's no-promotion decision is scoped to the lossless
            //   tier; the source's native 256-entry 50712 CARRIED as-is,
            //   never a second 50712).
            // - downscale2x (lossless): the 2×-decimated half-resolution
            //   plane (the FHD gate: 968×545; the OG2K gate: 1008×672;
            //   the OG3K gate: 1512×1005 — the tool's own staircase
            //   decimation — the measured
            //   decimation is the interop boundary, the measured δ
 // decision: the tool keeps its own staircase) on the
            //   source's measured per-depth grid via `gate_tile_dims_depth`
            //   (FHD: 242×274 @12/@8 → 4×2 = 8 tiles, 484×274 @10 → 2×2
            //   = 4 tiles; the bottom-row tiles are the 271-content-row
            //   half-row tiles on the 274-row plane — the odd-height
            //   interop shape. OG2K: the depth-invariant 252×336 → 4×2 =
 // 8 tiles — full-tile edge rows only, the measured
            //   no-half-row verdict. OG3K: the depth-invariant 252×252 →
            //   6×4 = 24 tiles — the bottom-row tiles are the 249-
            //   content-row half-row tiles on the 252-row plane),
            //   precision 12/10/10 (the @8 arm
            //   identity-promoted into the BPS10 container), the
            //   grid×mode-keyed DS2X family
            //   (`gate_candidates_for_grid` → `DS2X_FHD_CANDIDATES` —
 // the 2-member {W6, N5}, W7 never observed — the 
 // decision (c); `DS2X_OG2K_CANDIDATES` — the 3-member
 // {W7, W6, N5}, W7 observed on the ds2x corpus — 
 // ; `DS2X_OG3K_CANDIDATES` — the 3-member {W7, W2, N1},
 // W7 observed on the ds2x corpus — ).
            // The FHD + OG2K log10 + downscale2x combination remains the
            // named refusal (the unmeasured combination — the A+C
            // boundary; the refusal below names the measured set).
 // The mode plane (the UHD-12 branch's ownership pattern —
            // `samples` is MOVED into `plane_native`, no per-frame clone;
            // log10 @12 derives the code plane as a new vec; the verify
            // gates reference `plane_native` / `plane` by ref). The
            // per-arm precision: log10 all arms = 10 (the code plane /
            // the raw 10-bit / the identity-promoted 8-bit in the BPS10
            // container); ds2x = the source depth (12/10) — the @8 arm
            // identity-promoted to 10 (the mode tier's BPS split).
            let (plane_native, pnw, pnh) = if mode == Mode::Log10 {
                (samples, frame.width, frame.height)
            } else {
                // downscale2x: the tool's own staircase decimation (the
                // reference's decimation is the interop boundary — the
 // measured δ decision: the tool keeps its own staircase).
                // @8 = the decimated 8-bit values identity-promoted into
                // the BPS10 container (the mode tier's BPS split).
                crate::downscale::decimate2x(&samples, frame.width, frame.height, ds_rule)
            };
            // The per-arm stored precision (the measured per-arm BPS
            // split): log10 = 10 at every depth (the mode's 10bit_log
            // container — the @12 codes / the @10 raw passthrough / the
            // @8 identity promotion); ds2x = the source's depth, except
            // the @8 arm (the measured 8→10 identity promotion — the
            // mode tier's BPS split).
            let precision = if mode == Mode::Log10 || frame.bits_per_sample == 8 {
                10u32
            } else {
                frame.bits_per_sample as u32
            };
            let codes: Option<Vec<u16>> =
                if mode == Mode::Log10 && frame.bits_per_sample == 12 {
                    // @12: the 10-bit log codes (12-bit → codes via the
                    // built-in LUT's inverse — a new vec; the raw 12-bit
                    // samples stay for the content gate's LUT
                    // reconstruction).
                    let inv = crate::log10::inv();
                    Some(plane_native.iter().map(|v| inv[*v as usize]).collect())
                } else {
                    // log10 @10: the raw 10-bit passthrough (the measured
                    // maxdiff 0); log10 @8: the 8-bit samples as-is in
                    // the BPS10 container (the identity promotion — the
                    // values unchanged); ds2x: the decimated plane.
                    None
                };
            let plane: &[u16] = codes.as_deref().unwrap_or(&plane_native);
            let (pw, ph) = (pnw, pnh);
            // The per-depth grid (the source's measured FHD per-depth grid
            // — 242×274 @12/@8, 484×274 @10): full-resolution on the
            // log10 rows, the 968×545 plane on the ds2x rows (the ds2x
            // output inherits the source's per-depth grid — the measured
            // contract).
            let (tw, th) = crate::tileenc::gate_tile_dims_depth(
                frame.width,
                frame.height,
                frame.bits_per_sample as u32,
            );
            let grid = crate::tileenc::Grid::for_dims(pw, ph, tw, th);
            let mut tiles = Vec::with_capacity((grid.cols * grid.rows) as usize);
            // --fast = the gate's measured family's index-0 candidate
            // (the per-gate pattern — the FHD rows: FHD_CANDIDATES[0] /
            // DS2X_FHD_CANDIDATES[0] = Wrapped PSV7 / Wrapped PSV6),
            // skipping the per-tile trial encode. Same engine seam
            // (FRAMEPRISM_ENGINE) and even-pad as the adaptive path;
            // bit-exact lossless either way (verify is decode-side and
            // orientation-agnostic).
            if fast {
                for r in 0..grid.rows {
                    for c in 0..grid.cols {
                        tiles.push(crate::tileenc::encode_tile_fast(
                            plane, pw, ph, &grid, r, c, precision,
                        )?);
                    }
                }
            } else {
                for r in 0..grid.rows {
                    for c in 0..grid.cols {
                        tiles.push(crate::tileenc::encode_tile(
                            plane, pw, ph, &grid, r, c, precision,
                        )?);
                    }
                }
            }
            let mut stats = None;
            if verify {
                let _tv = Instant::now();
                // Content gate BEFORE surgery (decode the in-memory tiles
                // against the encoded plane — no second unpack). The @12
                // log10 row runs the LUT reconstruction with tolerance
                // (the quantization — bound = the curve's worst case);
                // every other arm is bit-exact by construction (the raw
                // passthrough / the identity promotion / the tool's own
                // decimation plane).
                if mode == Mode::Log10 && frame.bits_per_sample == 12 {
                    stats = Some(crate::verify::log10_content_tiled_plane(
                        &plane_native, pnw, pnh, &grid, &tiles,
                    )?);
                } else {
                    crate::verify::bit_exact_tiled_plane(
                        plane, pw, ph, &grid, &tiles, precision,
                    )?;
                }
                *verify_ms += _tv.elapsed().as_secs_f64();
            }
 // The per-arm measured expected-diff set (the 
            // contract): log10 @12 = the LUT ADD + 258 12→10; log10 @10 =
            // the raw passthrough (the lossless set — 258 unchanged, no
            // 50712); log10 @8 = the identity promotion (258 8→10, the
            // native 256-entry 50712 CARRIED — the promoted gate); ds2x
            // @12/@10 = the ds2x set (258 unchanged + the 51089-91 proxy
 // tags — the tool's own ds2x design ADDS them, the free
            // header packing); ds2x @8 = the ds2x set + the identity
            // promotion (258 8→10 — the promoted ds2x gate).
            let ds = downscale.then(|| build_ds2x(&buf, &frame)).transpose()?;
            let is_3k = crate::tileenc::is_3k_gate(frame.width, frame.height);
            let out = if mode == Mode::Log10 {
                if is_3k {
                    crate::surgery::apply_tiled_3k_log10(&buf, &frame, &tiles)
                } else {
                    crate::surgery::apply_tiled_log10(&buf, &frame, &tiles)
                }
            } else if is_3k {
                crate::surgery::apply_tiled_3k_downscale(
                    &buf,
                    &frame,
                    &tiles,
                    ds.as_ref().unwrap(),
                )
            } else {
                crate::surgery::apply_tiled_downscale(
                    &buf,
                    &frame,
                    &tiles,
                    ds.as_ref().unwrap(),
                )
            }
            .map_err(|err| anyhow::anyhow!("tile surgery: {err}"))?;
            if verify {
                let _tv = Instant::now();
                if mode == Mode::Log10 {
                    match frame.bits_per_sample {
                        12 => crate::verify::metadata_preserved_tiled_log10(
                            &buf, &out.bytes, &frame, &tiles,
                        )
                        .map_err(vctx)?,
                        10 => crate::verify::metadata_preserved_tiled(
                            &buf, &out.bytes, &frame, &tiles,
                        )
                        .map_err(vctx)?,
                        _ => crate::verify::metadata_preserved_tiled_log10_promoted(
                            &buf, &out.bytes, &frame, &tiles,
                        )
                        .map_err(vctx)?,
                    }
                } else {
                    if frame.bits_per_sample == 8 {
                        crate::verify::metadata_preserved_tiled_downscale_promoted(
                            &buf, &out.bytes, &frame, &tiles,
                        )
                        .map_err(vctx)?
                    } else {
                        crate::verify::metadata_preserved_tiled_downscale(
                            &buf, &out.bytes, &frame, &tiles,
                        )
                        .map_err(vctx)?
                    }
                }
                *verify_ms += _tv.elapsed().as_secs_f64();
            }
            (out, stats, None, None, None)
        } else if is_tile_layout(&frame) {
        if mode.is_lossy() && lossy_format == LossyFormat::ReferenceDct {
            // ---------- reference tag-7 path (phase B) ----------
            // 12-bit parity planes (pre-curve domain via the inverse of
            // the 50712 curve), 2×12-bit baseline-DCT encodes per tile
            // (even/odd frame rows), stitched into the tag-7 two-scan
            // tile structure; tag plan 259→7, 322/323 = 1928/1088,
            // 50712 = the curve bytes (byte-copied from the corpus
            // file when given, the embedded A001 constant otherwise).
            if downscale {
                anyhow::bail!("--lossy-format dct12 does not combine with --downscale2x");
            }
            let (curve, curve_src) = match &reference.reference_ref {
                Some(p) => crate::lossydct::read_reference_curve(p)
                    .map_err(|e| anyhow::anyhow!("reference curve: {e}"))?,
                None => (
                    crate::lossydct::REFERENCE_CURVE,
                    crate::lossydct::CurveSrc::Embedded,
                ),
            };
            // A reference curve that differs from the embedded A001
            // constant is a different clip — the byte-copy contract still
            // holds (the corpus file's bytes are what get written), but the
            // G1/G2 measured bands (A001) no longer apply; say so.
            if curve_src == crate::lossydct::CurveSrc::ReferenceFile
                && curve != crate::lossydct::REFERENCE_CURVE
            {
                eprintln!("note: the reference curve differs from the embedded A001 constant (different clip?)");
            }
            let curve_bytes = crate::lossydct::curve_bytes(&curve);
            let inv = crate::lossydct::inv_lut(&curve);
            // (lossy v2→v3): the PRODUCTION pre-domain is the RAW
            // source — the class-structure-preserving transform now lives
            // in the DCT domain (encode_tiles_t21: the j=7 column → 0
            // erases the within-row (−1)^x 2-period banding; the cross-
            // scan DC mix G = 8 preserves the between-row class structure
            // the demosaic needs for local color — v3 /, 2026-
            // the mix is the tile's band-limited D' = G·D −
 // (G−1)·box(2K+1)(D), K = 16 — the closure: the
            // per-block G·D amplified the inter-scan DC step at every 8-px
            // boundary, the measured gain is scale-dependent
            // (per-block 7-10×, coarse-scale ~1×)). The 20b source-space
            // 2-tap (cfa_lowpass_h) is RETIRED from the production path
            // (kept in the crate for diagnostics): it erased the h-2period
            // AND crushed the inter-row class structure (decoded v-2period
            // 0.08–0.12× source vs the measured 1.00×) — the 
            // orange/cyan cast in Resolve playback.
 // c D3 stands: the 3×3 box runs on the FULL-FRAME
            // parity planes before the tile cut (no edge-replicate at the
 // tile borders — the pre-20c per-tile box3 left the D3 seam
            // line at x=1928/y=1088, the user's vertical center line),
 // then cuts into tiles + plateau clamp.
            let planes = crate::lossydct::full_frame_planes(
                &samples,
                frame.width,
                frame.height,
                &inv,
                &curve,
            )
            .map_err(|e| anyhow::anyhow!("pre-domain: {e}"))?;
            // Source planes (raw — the CFA-contrast gate's
            // source-referenced backstop measures the real CFA energy;
            // with the DCT-domain transform the input planes are the raw
            // source themselves, so this is the same content as `planes`
            // pre-snap/pre-quant).
            let src_orig_planes =
                crate::lossydct::build_source_planes(&samples, frame.width, frame.height)
                    .map_err(|e| anyhow::anyhow!("source planes (gate): {e}"))?;
            // Table + tiles: VBR = the measured preset table verbatim;
            // CBR = per-frame binary search over the base-table scale for
            // the total size closest under in_bytes/k × 1.05 (the fixed
            // surgery prefix is content-independent — measure it once,
            // mirroring the 34892 CBR path).
            let (table, table_scale, tiles) = match mode.cbr_k() {
                None => {
                    let t = match mode {
                        Mode::VbrHq => crate::lossydct::BASE_TABLE,
                        Mode::VbrLt => crate::lossydct::LT_TABLE,
                        _ => unreachable!("is_lossy + cbr_k None ⇒ VBR"),
                    };
                    let tiles = crate::lossydct::encode_tiles_t21(&planes, &t)
                        .map_err(|e| anyhow::anyhow!("dct12 tile encode: {e}"))?;
                    (t, 1.0, tiles)
                }
                Some(k) => {
                    let limit = (buf.len() as u64 / k as u64) * 105 / 100; // in_bytes/k × 1.05
                    let ref_tiles =
                        crate::lossydct::encode_tiles_t21(&planes, &crate::lossydct::BASE_TABLE)
                            .map_err(|e| anyhow::anyhow!("dct12 CBR reference encode: {e}"))?;
                    let ref_out = crate::surgery::apply_tiled_reference_dct(
                        &buf,
                        &frame,
                        &ref_tiles,
                        &curve_bytes,
                    )
                    .map_err(|e| anyhow::anyhow!("dct12 prefix surgery: {e}"))?;
                    let prefix = ref_out.bytes_out as u64
                        - ref_tiles.iter().map(|t| t.len() as u64).sum::<u64>();
                    // Cache per-scale encodes so the search never encodes
                    // the same scale twice (key = the f64 bits).
                    let cache: std::cell::RefCell<std::collections::HashMap<u64, Vec<Vec<u8>>>> =
                        std::cell::RefCell::new(std::collections::HashMap::new());
                    cache.borrow_mut().insert(1.0f64.to_bits(), ref_tiles);
                    let total_fn = |s: f64| -> u64 {
                        let t = {
                            let mut c = cache.borrow_mut();
                            match c.get(&s.to_bits()) {
                                Some(t) => t.clone(),
                                None => {
                                    let t = crate::lossydct::encode_tiles_t21(
                                        &planes,
                                        &crate::lossydct::scale_table(s),
                                    )
                                    .expect("dct12 encode for CBR search");
                                    c.insert(s.to_bits(), t.clone());
                                    t
                                }
                            }
                        };
                        prefix + t.iter().map(|x| x.len() as u64).sum::<u64>()
                    };
                    let s = crate::lossydct::search_scale(limit, &total_fn);
                    let tiles = cache
                        .borrow()
                        .get(&s.to_bits())
                        .cloned()
                        .expect("final tiles in cache");
                    (crate::lossydct::scale_table(s), s, tiles)
                }
            };
            let out = crate::surgery::apply_tiled_reference_dct(&buf, &frame, &tiles, &curve_bytes)
                .map_err(|e| anyhow::anyhow!("tile surgery: {e}"))?;
            let mut stats = None;
            if verify {
                let _tv = Instant::now();
                // G1 (structure): per-tile marker/SOS/SOF/DQT check.
                for t in &tiles {
                    crate::lossydct::check_tile_structure(t, &table)
                        .map_err(|e| anyhow::anyhow!("verify: G1 structure: {e}"))?;
                }
                // G2 (pixels): both-scan assembly
                // vs the original 12-bit plane. Per frame: the catastrophe
                // ceiling r = our_MAE / reference_MAE < 2.0 (with
                // --reference-mae-tsv) + scan-completeness (odd/even MAE ratio
                // in [0.1, 10.0] + the content-scale-aware dead-scan MAE
                // backstop — the b2-review F1 calibration fix + the 
                // content-scale-aware ceiling; see
                // lossydct::check_scan_completeness) + CBR size within ±5%
                // of in_bytes/k. The
                // per-frame [0.5×,1.5×] band + per-frame p99 cap are RETIRED
                // (the measured max 59.85 > its p99 59.68); the per-PRESET
                // distribution gate (mean/p50/count) is applied at the end of
                // the run over all frames of the preset.
                let curve_padded = crate::dct2s::linearization_curve(Some(&curve));
                let decoded = crate::dct2s::assemble_frame(
                    &tiles.iter().map(|t| t.as_slice()).collect::<Vec<_>>(),
                    crate::lossydct::TILE_W,
                    crate::lossydct::TILE_H,
                    frame.width,
                    frame.height,
                    &curve_padded,
                )
                .map_err(|e| anyhow::anyhow!("verify: G2 decode: {e}"))?;
                let (mae, max_abs) = crate::lossydct::pixel_mae(&decoded, &samples);
                // G2 scan-completeness: the two parities (scan 0 even /
                // scan 1 odd rows) must be the same order of magnitude —
                // a dead/missing/corrupted scan is an automatic FAIL
                // (phase-A lesson), independent of the MAE band.: the
                // dead-scan backstop is content-scale-aware (ceiling_p =
                // max(100, 0.75 × src_parity_mean_p)) — the per-parity
                // SOURCE means are the new input.
                let (even_mae, odd_mae, _mx) =
                    crate::lossydct::parity_mae(&decoded, &samples, frame.width);
                let (even_src_mean, odd_src_mean) =
                    crate::lossydct::src_parity_means(&samples, frame.width);
                crate::lossydct::check_scan_completeness(
                    even_mae,
                    odd_mae,
                    even_src_mean,
                    odd_src_mean,
                )
                .map_err(|e| anyhow::anyhow!("verify: G2 scan-completeness: {e}"))?;
                let frame_file = src
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let reference_mae = reference
                    .reference_mae_tsv
                    .as_ref()
                    .map(|p| read_reference_mae(p, &frame_file))
                    .transpose()?;
                let cbr_target = mode.cbr_k().map(|k| buf.len() as u64 / k as u64);
                crate::lossydct::gate_pixels(
                    mae,
                    reference_mae.unwrap_or(0.0),
                    cbr_target,
                    out.bytes_out as u64,
                )
                .map_err(|e| anyhow::anyhow!("verify: G2 gate: {e}"))?;
 // G2 CFA gates (FATAL, re-scoped by 20b — D1/D2
                // encode defects; vbr + cbr; NOT the lossless family):
                // per-tile scan0 CFA-contrast ratio (recon pre-domain /
                // input pre-domain) in [0, 2.0] where the input carries
                // meaningful CFA energy, + the source-referenced backstop
                // (recon ≤ 2× the source's CFA contrast — the anti-
                // amplification invariant in the CFA-erased-input world of
                // 20b; the old ratio form alone is blind to it because the
                // full-image MAE and the erased-input ratio average the
                // structured CFA error away). Phase for the per-class gate
                // from tag 50719.
                crate::lossydct::gate_cfa_contrast(&tiles, &planes, &src_orig_planes, &curve)
                    .map_err(|e| anyhow::anyhow!("verify: G2 cfa-contrast: {e}"))?;
                let origin = crate::surgery::ifd_tag_longs(&buf, &frame, 50719)
                    .map_err(|e| anyhow::anyhow!("G2 50719: {e}"))?;
                if origin.len() != 2 {
                    anyhow::bail!(
                        "G2 50719: DefaultCropOrigin must be LONG×2 (got {})",
                        origin.len()
                    );
                }
                crate::lossydct::gate_class_means(
                    &decoded,
                    &samples,
                    frame.width,
                    [origin[0], origin[1]],
                )
                .map_err(|e| anyhow::anyhow!("verify: G2 per-class mean: {e}"))?;
 // G2 seam gate (FATAL, — D3): |err| on the middle
                // column pair x∈{1927,1928} and row pair y∈{1087,1088} vs
                // the local baseline (cols 1916–1926 ∪ 1930–1940 / rows
                // 1076–1086 ∪ 1090–1100) < 1.5× — a structural seam line at
                // the frame middle (the user's vertical center line) is an
                // encode defect, vbr + cbr.
                let seam =
                    crate::lossydct::gate_seam(&decoded, &samples, frame.width, frame.height)
                        .map_err(|e| anyhow::anyhow!("verify: G2 seam: {e}"))?;
                let (sv, sh) = (seam.v, seam.h);
                eprintln!("  seam: v {sv:.3} / h {sh:.3} (limit 1.5)");
                // G2 structure gates (FATAL, vbr + cbr — the
                // cast-regression backstop, the defect class the
                // 20b/20c/20d gates were blind to: they measured per-class
                // MEANS + MAE + seam, all ≈ reference, while the decoded
                // per-pixel CFA class structure was crushed → the NLE
                // demosaic's local color ≈ 0 → the orange/cyan cast):
                // (1) `gate_structure`: the decoded 2-period ratios
                // (h = within-row banding, v = between-row class
                // structure — d2diag protocol, full frame) inside the
                // reference-anchored bands (v ∈ [max(0.5, 0.5×reference_v),
                // max(1.4, 3.5×reference_v)] — the v-floor 
                // recalibrated from the fixed 0.7,
                // h ≤ max(1.0, 2×reference_h); the
                // reference-independent floors v ≥ 0.5 and h ≤ 1.0
                // stay FATAL without the anchor);
                // (2) `gate_demosaic`: the demosaic-proxy chroma stds
                // (W−G/G−R/W−R — d2demo protocol) inside
                // [max(0.5×, −0.03 abs visibility slack),
                // max(2×, 0.75 abs)] of the measured same-frame
                // values (FATAL with the anchor; informational
                // without);
                // (3) the flat-region seam step (INFORMATIONAL — seam
                // verdict: the measured encoder shows the same artifact class
                // at up to ±18 LSB clip-wide; the existing ratio gate
                // above is unchanged).
                // The reference anchors come from --reference-structure-tsv (the
                // reference golden's per-frame d2diag/d2demo signature — the
                // sweep output), the same optional-anchor pattern
                // as --reference-mae-tsv.
                let reference_structure = reference
                    .reference_structure_tsv
                    .as_ref()
                    .map(|p| read_reference_structure(p, &frame_file))
                    .transpose()?;
                let (sh_ratio, sv_ratio) = crate::lossydct::structure_ratios(
                    &decoded,
                    &samples,
                    frame.width,
                    frame.height,
                );
                crate::lossydct::gate_structure(
                    sh_ratio,
                    sv_ratio,
                    reference_structure.as_ref().map(|v| (v.v_ratio, v.h_ratio)),
                )
                .map_err(|e| anyhow::anyhow!("verify: G2 structure: {e}"))?;
                eprintln!(
                    "  structure: v {sv_ratio:.3} / h {sh_ratio:.3}{}",
                    if reference_structure.is_some() {
                        " (reference-anchored bands)"
                    } else {
                        " (reference-independent floors only — no --reference-structure-tsv)"
                    }
                );
                let chroma = crate::lossydct::demosaic_chroma(
                    &decoded,
                    frame.width,
                    frame.height,
                    [origin[0], origin[1]],
                );
                crate::lossydct::gate_demosaic(chroma, reference_structure.as_ref().map(|v| v.dem2))
                    .map_err(|e| anyhow::anyhow!("verify: G2 demosaic: {e}"))?;
                let (c0, c1, c2) = (chroma[0], chroma[1], chroma[2]);
                eprintln!(
                    "  demosaic W-G {c0:.3} / G-R {c1:.3} / W-R {c2:.3}{}",
                    if reference_structure.is_some() {
                        " (reference-anchored bands)"
                    } else {
                        " (informational — no --reference-structure-tsv)"
                    }
                );
                let flat =
                    crate::lossydct::seam_flat_steps(&decoded, &samples, frame.width, frame.height)
                        .map_err(|e| anyhow::anyhow!("verify: G2 seam flat: {e}"))?;
                eprintln!(
                    "  seam flat (informational): col {cs:+.3} (refs {c1:+.3} / {c2:+.3}) | row {rs:+.3} (ref {rf:+.3})",
                    cs = flat.col_seam,
                    c1 = flat.col_ref1,
                    c2 = flat.col_ref2,
                    rs = flat.row_seam,
                    rf = flat.row_ref,
                );
                // The per-frame MAE ratio r = our/reference (None without
                // --reference-mae-tsv) — fed to the per-preset distribution gate.
                let mae_ratio = reference_mae.filter(|v| *v > 0.0).map(|v| mae / v);
                // Metadata: the tag-7 expected-diff set.
                crate::verify::metadata_preserved_tiled_reference_dct(
                    &buf,
                    &out.bytes,
                    &frame,
                    &tiles,
                    &curve_bytes,
                )
                .map_err(vctx)?;
                stats = Some(crate::verify::ReferenceDctStats {
                    mae,
                    max_abs,
                    table_scale,
                    samples: decoded.len() as u64,
                    mae_ratio,
                });
                *verify_ms += _tv.elapsed().as_secs_f64();
            }
            (out, None, None, None, stats)
        } else if mode.is_lossy() {
            // ---------- lossy path (34892/LinearRaw/8-bit) ----------
            // 12-bit plane (decimated 2× when --downscale2x), then the 12→8
            // downshift (`v12 >> 4`) — the downshift runs AFTER decimation so
            // the 2×2 box average stays in the 12-bit domain.
            // `samples` is MOVED (the verify gates take the
            // plane / re-derive from it; the strip is never re-unpacked).
            let (plane12, pw, ph) = if downscale {
                crate::downscale::decimate2x(&samples, frame.width, frame.height, ds_rule)
            } else {
                (samples, frame.width, frame.height)
            };
            let plane8: Vec<u8> = plane12.iter().map(|v| (*v >> 4) as u8).collect();
            let grid = crate::tileenc::Grid::new(pw, ph);
            // Per-tile rects so each quality evaluation only re-runs the
            // libjpeg DCT (encode_tile8 re-slices the rect from `plane8`).
            let mut rects: Vec<crate::tileenc::TileRect> =
                Vec::with_capacity((grid.cols * grid.rows) as usize);
            for r in 0..grid.rows {
                for c in 0..grid.cols {
                    rects.push(
                        crate::tileenc::tile_region(pw, ph, &grid, r, c)
                            .map_err(|e| anyhow::anyhow!("tile_region: {e}"))?,
                    );
                }
            }
            let encode_all = |q: u32| -> Result<Vec<Vec<u8>>> {
                rects
                    .iter()
                    .map(|rect| {
                        crate::lossy::encode_tile8(&plane8, pw, rect, q)
                            .map_err(|e| anyhow::anyhow!("lossy tile encode: {e}"))
                    })
                    .collect()
            };
            let (quality, tiles) = match mode.cbr_k() {
                None => {
                    // VBR fixed-quality preset.
                    let q = match mode {
                        Mode::VbrHq => crate::lossy::VBR_HQ_QUALITY,
                        Mode::VbrLt => crate::lossy::VBR_LT_QUALITY,
                        _ => unreachable!("is_lossy + cbr_k None ⇒ VBR"),
                    };
                    (q, encode_all(q)?)
                }
                Some(k) => {
                    // CBR: binary-search the libjpeg quality for the total
                    // output size closest UNDER `in_bytes/k * 1.05`. The fixed
                    // surgery prefix (header + IFD + blob + arrays) is content-
                    // independent, so measure it once with reference tiles.
                    let ref_q = 50u32;
                    let ref_tiles = encode_all(ref_q)?;
                    let ref_digest = crate::lossy::new_raw_image_digest(&ref_tiles);
                    let ds_ref = if downscale {
                        Some(build_ds2x(&buf, &frame)?)
                    } else {
                        None
                    };
                    let ref_out = match ds_ref.as_ref() {
                        Some(ds) => crate::surgery::apply_tiled_downscale_lossy(
                            &buf, &frame, &ref_tiles, ds, ref_digest,
                        ),
                        None => {
                            crate::surgery::apply_tiled_lossy(&buf, &frame, &ref_tiles, ref_digest)
                        }
                    }
                    .map_err(|e| anyhow::anyhow!("prefix surgery: {e}"))?;
                    let prefix = ref_out.bytes_out as u64
                        - ref_tiles.iter().map(|t| t.len() as u64).sum::<u64>();
                    let limit = (buf.len() as u64 / k as u64) * 105 / 100; // in_bytes/k * 1.05
                                                                           // Cache per-quality encodes so the binary search + ±3
                                                                           // refinement never encode the same quality twice.
                    let cache: std::cell::RefCell<std::collections::HashMap<u32, Vec<Vec<u8>>>> =
                        std::cell::RefCell::new(std::collections::HashMap::new());
                    cache.borrow_mut().insert(ref_q, ref_tiles);
                    let total_fn = |q: u32| -> u64 {
                        let t = {
                            let mut c = cache.borrow_mut();
                            match c.get(&q) {
                                Some(t) => t.clone(),
                                None => {
                                    let t = encode_all(q).expect("lossy encode for CBR search");
                                    c.insert(q, t.clone());
                                    t
                                }
                            }
                        };
                        crate::lossy::total_size(prefix, &t)
                    };
                    let q = crate::lossy::search_quality(limit, &total_fn);
                    let tiles = cache
                        .borrow()
                        .get(&q)
                        .cloned()
                        .expect("final tiles in cache");
                    (q, tiles)
                }
            };
            // Content gate: decode the 8-bit tiles vs the downshifted source
            // (full-res, or the decimated plane when --downscale2x).
            // The worker's own 8-bit plane is the reference —
            // no second strip unpack.
            let lossy_stats = if verify {
                let _tv = Instant::now();
                let s = Some(
                    crate::verify::lossy_stats_from_ref(&plane8, pw, ph, &grid, &tiles)
                        .map_err(vctx)?,
                );
                *verify_ms += _tv.elapsed().as_secs_f64();
                s
            } else {
                None
            };
            let digest = crate::lossy::new_raw_image_digest(&tiles);
            let ds = downscale.then(|| build_ds2x(&buf, &frame)).transpose()?;
            let out = match ds.as_ref() {
                Some(ds) => {
                    crate::surgery::apply_tiled_downscale_lossy(&buf, &frame, &tiles, ds, digest)
                }
                None => crate::surgery::apply_tiled_lossy(&buf, &frame, &tiles, digest),
            }
            .map_err(|e| anyhow::anyhow!("tile surgery: {e}"))?;
            if verify {
                let _tv = Instant::now();
                match ds.as_ref() {
                    Some(_) => crate::verify::metadata_preserved_tiled_downscale_lossy(
                        &buf, &out.bytes, &frame, &tiles,
                    )
                    .map_err(vctx)?,
                    None => crate::verify::metadata_preserved_tiled_lossy(
                        &buf, &out.bytes, &frame, &tiles,
                    )
                    .map_err(vctx)?,
                }
                *verify_ms += _tv.elapsed().as_secs_f64();
            }
            (out, None, lossy_stats, Some(quality), None)
        } else {
            // ---------- existing 12/10-bit lossless path (/ 0.2) ----------
            //: reference-structure encoder — 64 tiles × 2-component
            // (even/odd column planes) lossless JPEG, PSV 7, per-tile Huffman.
            // log10 mode: the SAME structure over 10-bit log codes.
            // downscale2x: the SAME structure over the 2×-decimated plane
            // (1928×1085 → 4×4 tiles) + the proxy tag surgery.
            // `samples` is MOVED into `plane12` (no 16.7 MB
            // per-frame clone). log10 derives the code plane as a new vec;
            // lossless encodes the 12-bit plane directly (borrowed, never
            // moved — the verify gates reference `plane12` by ref).
            let (plane12, pw, ph) = if downscale {
                crate::downscale::decimate2x(&samples, frame.width, frame.height, ds_rule)
            } else {
                (samples, frame.width, frame.height)
            };
            let precision = match mode {
                Mode::Lossless => 12u32,
                Mode::Log10 => 10u32,
                _ => unreachable!("non-lossy branch"),
            };
            // The plane to encode: log10 code plane (a new vec) or the
            // 12-bit plane as-is. `plane12` stays owned here for the
            // verify gates.
            let codes: Option<Vec<u16>> = if mode == Mode::Log10 {
                let inv = crate::log10::inv();
                Some(plane12.iter().map(|v| inv[*v as usize]).collect())
            } else {
                None
            };
            let plane: &[u16] = codes.as_deref().unwrap_or(&plane12);
            let grid = crate::tileenc::Grid::new(pw, ph);
            let mut tiles = Vec::with_capacity((grid.cols * grid.rows) as usize);
            // --fast = single fixed candidate (Wrapped PSV 7), skipping
            // the 3-candidate per-tile trial encode. Same engine seam
            // (FRAMEPRISM_ENGINE) and even-pad as the adaptive path; bit-exact
            // lossless either way (verify is decode-side and orientation-
            // agnostic).
            // The item-126 Stage-1 selection-default flip (the 482 grid):
            // the no-flag default routes through this same `--fast`
            // selection (the family's fixed W7 head — `encode_tile_fast`);
            // `--trial` restores the base default's size-min trial
            // (byte-frozen — the R4-KAT4 contract). The flip's covered set
            // = exactly the (grid × mode) set the shipped `--fast` flag
            // touches on the 482 non-downscale grid (this branch's lossless
            // + log10 rows — the tile loop is mode-agnostic; the code
            // citation is in the lane's report.md). The ds2x (downscale)
            // rows + every OTHER grid's shipped selection stay on the
            // trial / shipped discipline UNTOUCHED (the STOP-5 second
            // contract — `is_482_grid` + the `!downscale` guard).
            let use_fast = fast
                || (!trial_flag() && !downscale && crate::tileenc::is_482_grid(&grid));
            if use_fast {
                for r in 0..grid.rows {
                    for c in 0..grid.cols {
                        // The item-125 profile phase (`archive-encode` —
                        // the output frame's encode, the per-tile call
                        // sites summed; the guard is a checked no-op at
                        // the gate OFF):
                        let _pe = crate::profile::phase("archive-encode").start();
                        tiles.push(crate::tileenc::encode_tile_fast(
                            plane, pw, ph, &grid, r, c, precision,
                        )?);
                    }
                }
            } else {
                for r in 0..grid.rows {
                    for c in 0..grid.cols {
                        let _pe = crate::profile::phase("archive-encode").start();
                        tiles.push(crate::tileenc::encode_tile(
                            plane, pw, ph, &grid, r, c, precision,
                        )?);
                    }
                }
            }
            let mut stats = None;
            if verify {
                // The item-125 profile phase (`archive-drill` — the
                // output's bit-exact re-encode verify (the verify
                // gate's drill), summed over its call sites; the guard
                // is a checked no-op at the gate OFF):
                let _pd = crate::profile::phase("archive-drill").start();
                // Content gate BEFORE surgery (decode the in-memory tiles
                // against the worker's own 12-bit plane — review, no
                // second unpack). The metadata gate runs after surgery on
                // the output bytes (combination-specific expected-diff
                // set), mirroring the lossless path.
                match (mode, downscale) {
                    (Mode::Lossless, _) => {
                        crate::verify::bit_exact_tiled_plane(
                            &plane12, pw, ph, &grid, &tiles, 12,
                        )?;
                    }
                    (Mode::Log10, _) => {
                        stats = Some(crate::verify::log10_content_tiled_plane(
                            &plane12, pw, ph, &grid, &tiles,
                        )?);
                    }
                    _ => unreachable!("non-lossy branch"),
                }
            }
            let ds = downscale.then(|| build_ds2x(&buf, &frame)).transpose()?;
            // The item-125 profile phase (`archive-encode` — the output
            // frame's encode, the surgery call site):
            let out = {
                let _pe = crate::profile::phase("archive-encode").start();
                match (mode, downscale) {
                    (Mode::Lossless, false) => crate::surgery::apply_tiled(&buf, &frame, &tiles),
                    (Mode::Log10, false) => crate::surgery::apply_tiled_log10(&buf, &frame, &tiles),
                    (Mode::Lossless, true) => crate::surgery::apply_tiled_downscale(
                        &buf,
                        &frame,
                        &tiles,
                        ds.as_ref().unwrap(),
                    ),
                    (Mode::Log10, true) => crate::surgery::apply_tiled_downscale_log10(
                        &buf,
                        &frame,
                        &tiles,
                        ds.as_ref().unwrap(),
                    ),
                    _ => unreachable!("non-lossy branch"),
                }
                .map_err(|err| anyhow::anyhow!("tile surgery: {err}"))?
            };
            if verify {
                let _tv = Instant::now();
                // The item-125 profile phase (`archive-drill` — the
                // metadata gate half of the verify drill, summed with
                // the content gate's site):
                let _pd = crate::profile::phase("archive-drill").start();
                match (mode, downscale) {
                    (Mode::Lossless, false) => {
                        crate::verify::metadata_preserved_tiled(&buf, &out.bytes, &frame, &tiles)
                            .map_err(vctx)?
                    }
                    (Mode::Log10, false) => crate::verify::metadata_preserved_tiled_log10(
                        &buf, &out.bytes, &frame, &tiles,
                    )
                    .map_err(vctx)?,
                    (Mode::Lossless, true) => crate::verify::metadata_preserved_tiled_downscale(
                        &buf, &out.bytes, &frame, &tiles,
                    )
                    .map_err(vctx)?,
                    (Mode::Log10, true) => crate::verify::metadata_preserved_tiled_downscale_log10(
                        &buf, &out.bytes, &frame, &tiles,
                    )
                    .map_err(vctx)?,
                    _ => unreachable!("non-lossy branch"),
                }
                *verify_ms += _tv.elapsed().as_secs_f64();
            }
            (out, stats, None, None, None)
        }
    } else {
        // Fallback: single-strip lossless LJPEG (kept for other 12-bit
        // layouts; `codec::encode_lossless` is 12/16-bit only — an
        // 8/10-bit input at a non-archive geometry fails loud there).
        // The archive geometries (UHD/FHD × 8/10/12-bit) are handled by
        // the tile paths above: the native-depth path (lossless,
 // non-downscale), the FHD mode path (the 
        // measured FHD log10/downscale2x rows — 1936×1090 @12/10/8) and
        // the UHD-12 branch (log10/lossy/downscale2x). The unmeasured
        // mode combinations (the FHD log10 + --downscale2x combination,
        // every other geometry's log10/lossy/downscale2x) have no single-
        // strip path (refusing beats half-support — the A+C boundary).
        if mode == Mode::Log10 {
            anyhow::bail!(
                "log10 mode requires the measured mode layout — the A001 UHD-12 tile layout (3856x2170, 12-bit packed) or the FHD layout (1936x1090, 8/10/12-bit, non-downscale — the measured rows) or the OG2K layout (2016x1344, 8/10/12-bit, non-downscale — the measured rows) or the OG3K layout (3024x2010, 8/10/12-bit, non-downscale — the measured rows) or the UHD layout (3856x2170, 10/8-bit, non-downscale — the measured rows); the unmeasured combination {}x{} @ {}-bit (downscale: {}) is the named refusal",
                frame.width,
                frame.height,
                frame.bits_per_sample,
                if downscale { "on" } else { "off" }
            );
        }
        if mode.is_lossy() {
            anyhow::bail!(
                "lossy modes require the A001 tile layout ({}x{}, 12-bit packed)",
                frame.width,
                frame.height
            );
        }
        if downscale {
            anyhow::bail!(
                "downscale2x requires the measured mode layout — the A001 UHD-12 tile layout (3856x2170, 12-bit packed) or the FHD lossless layout (1936x1090, 8/10/12-bit — the measured rows) or the OG2K lossless layout (2016x1344, 8/10/12-bit — the measured rows) or the OG3K lossless layout (3024x2010, 8/10/12-bit — the measured rows) or the UHD lossless layout (3856x2170, 10/8-bit — the measured rows); the unmeasured combination {}x{} @ {}-bit is the named refusal",
                frame.width,
                frame.height,
                frame.bits_per_sample
            );
        }
        let jpeg = crate::codec::encode_lossless(
            &samples,
            frame.width,
            frame.height,
            frame.bits_per_sample as u8,
        )?;
        let out = crate::surgery::apply(&buf, &frame, &jpeg);
        if verify {
            let _tv = Instant::now();
            crate::verify::bit_exact(&frame, &buf, &jpeg).map_err(vctx)?;
            crate::verify::metadata_preserved(&buf, &out.bytes, &frame).map_err(vctx)?;
            *verify_ms += _tv.elapsed().as_secs_f64();
        }
        (out, None, None, None, None)
    };

    //: the TRANSCODE-FIDELITY check (the item-123 R1, verify (b)):
    // the transcoded frame's verify is (a) the archive bit-exact drill
    // on the output (the existing encoded-row verify — the branch's
    // `bit_exact_tiled_plane` + `metadata_preserved_tiled`, unchanged)
    // + (b) this: decode the OUTPUT through the archive path (the
    // item-122 decode — the W7/W2/N1 restore drills ride inside) and
    // require PIXEL-EXACTNESS with the decoded input plane. The
    // input's fp bytes differ from the output's bytes by design (the
    // transcode re-encodes through our codec) — the check is
    // semantic (the u16 plane), named in the row.
    if let Some(in_plane) = tc_in {
        let _tv = Instant::now();
        // The item-125 profile phase (`fidelity-decode` — the
        // transcode-fidelity check's output decode, summed):
        let (ow, oh, out_plane) = {
            let _pd = crate::profile::phase("fidelity-decode").start();
            crate::decode::decode_j92_frame(&out.bytes, &file_name).map_err(vctx)?
        };
        // The item-125 profile phase (`fidelity-compare` — the pixel
        // compare of the fidelity check):
        let mismatch = {
            let _pc = crate::profile::phase("fidelity-compare").start();
            (ow, oh) != (frame.width, frame.height) || out_plane != in_plane
        };
        if mismatch {
            anyhow::bail!(vctx(format!(
                "transcode-fidelity: frame {file_name} — the decoded output ({}×{}, {} px) is not pixel-exact with the decoded input plane ({} px): the transcode is lossless by construction, a delta is a decode→encode seam bug",
                ow, oh, out_plane.len(), in_plane.len()
            )));
        }
        *verify_ms += _tv.elapsed().as_secs_f64();
    }

    Ok(CoreFrame {
        bytes: out.bytes,
        // The input's honest size: the transcoded frame's input is the
        // fp source (the synthetic seam's buffer is the re-laid source
        // metadata, NOT the frame's input size).
        in_bytes: if is_transcode { src_len } else { out.bytes_in as u64 },
        out_bytes: out.bytes_out as u64,
        log10: log10_stats,
        lossy: lossy_stats,
        quality,
        reference_dct: reference_stats,
        class: if is_transcode {
            crate::frameclass::FrameClass::FpCameraLossless
        } else {
            crate::frameclass::FrameClass::RawUncompressed
        },
        action: if is_transcode {
            crate::frameclass::FrameAction::Transcoded
        } else {
            crate::frameclass::FrameAction::Encoded
        },
    })
}

/// per-frame encode/verify run (clippy too_many_arguments allow —
/// flat parameter list, not an API).: this is now the thin write
/// layer over `encode_core` (the buffer seam — the dry run's in-memory
/// sample encode shares the core). The `ms` still spans read→write
/// (the FrameStats contract unchanged); the skip/force pre-check stays
/// in `process_one` (the pre-existing behavior stands).
#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    src: &Path,
    dst: &Path,
    verify: bool,
    mode: Mode,
    downscale: bool,
    fast: bool,
    lossy_format: LossyFormat,
    reference: &ReferenceDctOpts,
    qc_rel: Option<&str>,
    profiles: Option<&crate::camera::ProfileSet>,
) -> Result<FrameStats> {
    let t0 = Instant::now();
    let mut verify_ms = 0.0;
    let cf = encode_core(
        src,
        verify,
        mode,
        downscale,
        fast,
        lossy_format,
        reference,
        qc_rel,
        profiles,
        // The `--carry` opt-in (the encode run's process-wide flag —
        // `main` sets it before the dispatch; the dry-run seam passes
        // its `Opts::carry` explicitly instead).
        carry_flag(),
        &mut verify_ms,
    )?;
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = dst.with_extension("dng.tmp");
    std::fs::write(&tmp, &cf.bytes).with_context(|| format!("write {}", tmp.display()))?;
    if let Err(err) = std::fs::rename(&tmp, dst) {
        let _ = std::fs::remove_file(&tmp); // atomicity: nothing half-written
        return Err(err).with_context(|| format!("rename {} -> {}", tmp.display(), dst.display()));
    }
    //: the frame-class provenance note at the write site (the report's
    // per-frame provenance claim — the note is keyed by the sidecar row
    // key the encode was called with; a written frame is a processed
    // frame: the action is the policy verdict's executed form —
    // encoded (the raw class) / carried (the `--carry` opt-in) /
    // transcoded (the item-123 R0 ruling — the fp-camera class's
    // default, the `transcoded:fp-hardware` D4 vocabulary)).
    if let Some(qc_rel) = qc_rel {
        crate::frameclass::note_frame_action(qc_rel, cf.class, cf.action);
    }
    //: the carried frame's verify gate (the mixed-compression
    // contract, action-keyed since the item-123 Transcode cell): a
    // CARRIED frame's verify = the source-sha match — the bytes on
    // disk must equal the source bytes byte-for-byte (never a decode;
    // the decode-side verify of a carried frame is the item-122
    // scope). The write is the tmp+rename byte-exact copy — a
    // mismatch means the disk write corrupted the copy (the named
    // verify-gate refusal, the `verify: ` class prefix). The
    // TRANSCODED frame's verify is NOT this (its output differs from
    // its source by design — the archive drill + the transcode-
    // fidelity check in `encode_core` are its verify).
    if verify && cf.action == crate::frameclass::FrameAction::Carried {
        let (_, sha, _) = crate::jxl::digest_stream_path(dst)
            .with_context(|| format!("verify-read {} (the carried frame's source-sha match)", dst.display()))?;
        let src_sha = crate::jxl::sha256_hex(&cf.bytes);
        if sha != src_sha {
            anyhow::bail!(
                "verify: carried frame {} is not byte-identical to the source (the carried frame's verify = the source-sha match: the carried sha {} ≠ the source sha {} — never a decode; the decode-side verify is the item-122 scope)",
                dst.file_name().unwrap_or_default().to_string_lossy(),
                sha,
                src_sha
            );
        }
    }
    Ok(FrameStats {
        file: src
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        in_bytes: cf.in_bytes,
        out_bytes: cf.out_bytes,
        ratio: cf.in_bytes as f64 / cf.out_bytes as f64,
        ms: t0.elapsed().as_secs_f64() * 1000.0,
        log10: cf.log10,
        lossy: cf.lossy,
        quality: cf.quality,
        reference_dct: cf.reference_dct,
    })
}

/// The in-memory per-frame encode+verify (the dry-run sample
/// encode): `encode_core` without the write — the encoded bytes stay in
/// RAM (the dry run never touches `<dest>`, not even the dir). `ms` =
/// the encode+verify wall; `verify_ms` = the verify-pass wall (the
/// report's per-frame encode/verify split).
#[allow(clippy::too_many_arguments)]
pub fn encode_frame_memory(
    src: &Path,
    verify: bool,
    mode: Mode,
    downscale: bool,
    fast: bool,
    lossy_format: LossyFormat,
    reference: &ReferenceDctOpts,
    qc_rel: Option<&str>,
    profiles: Option<&crate::camera::ProfileSet>,
    carry: bool,
) -> Result<MemFrame> {
    let t0 = Instant::now();
    let mut verify_ms = 0.0;
    let cf = encode_core(
        src,
        verify,
        mode,
        downscale,
        fast,
        lossy_format,
        reference,
        qc_rel,
        profiles,
        carry,
        &mut verify_ms,
    )?;
    let file = src
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    Ok(MemFrame {
        file,
        bytes: cf.bytes,
        in_bytes: cf.in_bytes,
        out_bytes: cf.out_bytes,
        ratio: cf.in_bytes as f64 / cf.out_bytes as f64,
        ms,
        verify_ms,
    })
}

// =====================================================================
// The fp-camera Transcode source synthesis (the item-123 R1 — the (T)
// ruling cell's encode seam): the fp frame's OWN IFD0 metadata (the
// camera identity, the per-frame TimeCodes, the exposure, the ExifIFD
// + sub-IFDs — everything the archive contract carries) is re-laid
// out on the STRIP-LAYOUT CONTRACT the existing archive encode path +
// the existing verify gates require (the raw frames' shape): IFD0 at
// offset 8; the 273/278/279 strip tags in place of the fp's 322-325
// tile tags (the surgery drops the strip tags and adds the archive
// 322-325 — the exact expected-diff set the raw path rides); 259 = 1
// (the raw contract — the surgery patches 1→7 exactly as the raw
// path); every out-of-line region (IFD0 entry values + the sub-IFD
// bodies + their out-of-line entries) relocated contiguously behind
// the IFD, every pointer re-targeted. The fp layout cannot ride the
// surgery's contiguous-blob model directly (its IFD sits at the file
// TAIL and its out-of-line data is split around the 4.3 MB tile blob
// — the 2026-09-30 probe facts): the synthesis is the seam that makes
// the EXISTING path run UNCHANGED on the fp's metadata. The result of
// the existing archive encode path over (syn_buf, syn_frame, the
// decoded plane) is then a frame in the tool's measured archive
// contract (482×272 × 64, 259 = 7) carrying the fp frame's metadata.
// =====================================================================

/// The synthetic raw-equivalent source + its parsed `Frame` (the
/// Transcode dispatch's input to the existing archive encode path).
/// `meta` = the fp frame's `tiff::read_meta` parse (the classifier
/// already accepted the fp class — the shape preconditions are
/// re-asserted here: a structural deviation is a loud named refusal,
/// never a silent mis-synthesis). `buf` = the fp source bytes (the
/// out-of-line region CONTENT is byte-copied from it — the values are
/// relocated, never reinterpreted). Returns the synthetic buffer
/// (IFD0 at offset 8 + the relocated out-of-line regions, no data
/// blob — the strip is zero-length at EOF) + the `Frame` over it
/// (the surgery's `apply_tiled` + the verify gates consume exactly
/// this shape, unchanged).
fn fp_transcode_source(
    meta: &crate::tiff::Meta,
    buf: &[u8],
    what: &str,
) -> Result<(Vec<u8>, crate::tiff::Frame)> {
    use crate::tiff::{Frame, IfdEntry, IfdTable, Region};
    let e = meta.endianness;
    let ifd0 = &meta.ifd0;

    /// One inline count-1 value (SHORT type 3 / LONG type 4 — the two
    /// TIFF types the discriminator tags carry): `None` when the tag
    /// is not a readable in-line count-1 value.
    fn inline1(en: &IfdEntry, e: crate::tiff::Endian) -> Option<u64> {
        if en.count != 1 || en.out_of_line.is_some() {
            return None;
        }
        match en.typ {
            3 => Some(e.u16(&en.value_raw[0..2]) as u64),
            4 => Some(e.u32(&en.value_raw[0..4]) as u64),
            _ => None,
        }
    }
    let tag1 = |tag: u16| -> Option<u64> {
        ifd0
            .entries
            .iter()
            .find(|en| en.tag == tag)
            .and_then(|en| inline1(en, e))
    };

    // --- preconditions (the fp shape, re-asserted) -------------------
    if (tag1(256), tag1(257), tag1(258)) != (Some(3856), Some(2170), Some(12)) {
        anyhow::bail!(
            "{what}: transcode source synthesis refused: the fp shape preconditions are not met (256/257/258 = 3856/2170/12 inline count-1; got {}/{}/{})",
            tag1(256).map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            tag1(257).map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            tag1(258).map(|v| v.to_string()).unwrap_or_else(|| "-".into())
        );
    }
    let en259 = ifd0
        .entries
        .iter()
        .find(|en| en.tag == 259)
        .ok_or_else(|| anyhow::anyhow!("{what}: transcode source synthesis refused: tag 259 absent"))?;
    if en259.typ != 3 || en259.count != 1 || en259.out_of_line.is_some() || e.u16(&en259.value_raw[0..2]) != 7 {
        anyhow::bail!("{what}: transcode source synthesis refused: tag 259 is not the in-line SHORT count-1 compression 7 (the fp contract; typ {}, count {}, inline {})", en259.typ, en259.count, en259.out_of_line.is_none());
    }
    for tag in [322u16, 323, 324] {
        if !ifd0
            .entries
            .iter()
            .any(|en| en.tag == tag)
        {
            anyhow::bail!("{what}: transcode source synthesis refused: tag {tag} absent (the fp tile structure)");
        }
    }
    for tag in [273u16, 278, 279] {
        if ifd0.entries.iter().any(|en| en.tag == tag) {
            anyhow::bail!("{what}: transcode source synthesis refused: tag {tag} present (the fp frame is tiled — the strip tags are the synthesis's, never the source's)");
        }
    }
    if ifd0.next_ifd != 0 {
        anyhow::bail!("{what}: transcode source synthesis refused: IFD0 next_ifd is nonzero (the fp layout is a single IFD0 + the pointer-keyed sub-IFDs)");
    }

    // --- collect the out-of-line regions to relocate ------------------
    // Every out-of-line value (IFD0 entries, minus the dropped fp tile
    // tags 322-325; sub-IFD entries) + every sub-IFD STRUCTURE (the
    // ExifIFD body et al. — tag 0, the `Region` convention). The 324/
    // 325 arrays are the fp tile arrays — dropped with their tags
    // (the surgery re-adds the archive's own 324/325).
    let mut regions: Vec<(u16, u64, u64)> = Vec::new(); // (tag, start, end)
    for en in &ifd0.entries {
        if en.tag == 322 || en.tag == 323 || en.tag == 324 || en.tag == 325 {
            continue;
        }
        if let Some((p, end)) = en.out_of_line {
            regions.push((en.tag, p, end));
        }
    }
    for sub in &meta.sub_ifds {
        regions.push((0, sub.struct_range.start, sub.struct_range.end));
        for en in &sub.entries {
            if let Some((p, end)) = en.out_of_line {
                regions.push((en.tag, p, end));
            }
        }
    }
    // Validate: in bounds + pairwise non-overlapping (a violation is a
    // structural anomaly — a loud named refusal, never a partial copy).
    let len = buf.len() as u64;
    let mut sorted = regions.clone();
    sorted.sort_by_key(|r| r.1);
    for (i, r) in sorted.iter().enumerate() {
        if r.1 >= len || r.2 > len || r.1 >= r.2 {
            anyhow::bail!("{what}: transcode source synthesis refused: out-of-line region [{}..) is malformed (bounds {})", r.1, len);
        }
        if i > 0 {
            let prev = &sorted[i - 1];
            if r.1 < prev.2 {
                anyhow::bail!("{what}: transcode source synthesis refused: the out-of-line regions overlap ([{}..) over [{}..))", r.1, prev.1);
            }
        }
    }

    // --- the synthetic IFD0 (the raw-equivalent shape) -----------------
    // 59 fp entries − 4 (the fp tile tags 322-325) + 3 (the strip tags
    // 273/278/279) = 58 — the raw frames' entry count (the surgery's
    // +1 growth then lands on the identical 59-entry output shape the
    // raw path rides — the byte-invariance pin).
    const SYN_ENTRY_COUNT: u16 = 58;
    let ifd0_size = 2 + (SYN_ENTRY_COUNT as u64) * 12 + 4;
    let data_start = 8 + ifd0_size;
    // The relocated regions sit contiguously behind the IFD, in the
    // source's address order (the content bytes are copied verbatim).
    let mut cursor = data_start;
    let mut new_offsets: Vec<(u64, u64, u64)> = Vec::with_capacity(sorted.len()); // (old start, old end, new start)
    let mut body_map: Vec<(u64, u64)> = Vec::new(); // (old body off, new body off)
    for &(_tag, start, end) in &sorted {
        new_offsets.push((start, end, cursor));
        if _tag == 0 {
            body_map.push((start, cursor));
        }
        cursor += end - start;
    }
    let data_end = cursor;
    // Pointer remap: old absolute offset → new (the piecewise mapping
    // over the relocated regions). Every pointer the IFD carries must
    // land inside a region (the parse's own validity) — a miss is a
    // named refusal.
    let remap = |p: u64, what_ptr: &str| -> Result<u64> {
        for &(s, e2, ns) in &new_offsets {
            if p >= s && p < e2 {
                return Ok(ns + (p - s));
            }
        }
        Err(anyhow::anyhow!(
            "{what}: transcode source synthesis refused: the {what_ptr} (offset {p}) does not point inside a relocated out-of-line region (a structural anomaly — named, never a silent remap)"
        ))
    };
    let new_body_offsets: Vec<u64> = meta
        .sub_ifds
        .iter()
        .map(|sub| {
            body_map
                .iter()
                .find(|(old, _)| *old == sub.struct_range.start)
                .map(|(_, ns)| *ns)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{what}: transcode source synthesis refused: the sub-IFD structure at offset {} was not collected (a structural anomaly)",
                        sub.struct_range.start
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut syn_entries: Vec<IfdEntry> = ifd0
        .entries
        .iter()
        .filter(|en| !matches!(en.tag, 322..=325))
        .map(|en| {
            let mut en = *en;
            if let Some((p, end)) = en.out_of_line {
                let ns = remap(p, "out-of-line value pointer")?;
                let mut raw = [0u8; 4];
                e.put_u32(&mut raw, 0, ns as u32);
                en.value_raw = raw;
                en.out_of_line = Some((ns, ns + (end - p)));
            } else if en.count == 1 && crate::tiff::is_ifd_pointer(en.typ, en.tag) {
                // The sub-IFD pointer (the fp's 34665 ExifIFD, type 4
                // count 1): inline value = the body offset → re-target
                // to the relocated body. 0 (absent sub-IFD) stays 0.
                let old = e.u32(&en.value_raw) as u64;
                if old != 0 {
                    let idx = meta
                        .sub_ifds
                        .iter()
                        .position(|sub| sub.off == old)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "{what}: transcode source synthesis refused: the sub-IFD pointer (offset {old}) names no collected sub-IFD structure"
                            )
                        })?;
                    let mut raw = [0u8; 4];
                    e.put_u32(&mut raw, 0, new_body_offsets[idx] as u32);
                    en.value_raw = raw;
                }
            }
            // 259 (Compression): the raw contract value (1 — the
            // surgery patches 1→7 exactly as the raw path rides).
            if en.tag == 259 {
                let mut v = [0u8; 2];
                e.put_u16(&mut v, 0, 1);
                en.value_raw[0..2].copy_from_slice(&v);
            }
            Ok(en)
        })
        .collect::<Result<Vec<_>>>()?;
    // The strip tags (the raw contract: LONG count 1, in-line — the
    // measured raw shape). 273 = the zero-length strip at EOF (the
    // synthetic source carries no data blob); 278 = the full height;
    // 279 = 0 (the strip length).
    let strip_entry = |tag: u16, value: u32| {
        let mut raw = [0u8; 4];
        e.put_u32(&mut raw, 0, value);
        IfdEntry {
            tag,
            typ: 4,
            count: 1,
            value_raw: raw,
            out_of_line: None,
        }
    };
    syn_entries.push(strip_entry(273, data_end as u32));
    syn_entries.push(strip_entry(278, 2170));
    syn_entries.push(strip_entry(279, 0));
    syn_entries.sort_by_key(|en| en.tag);
    debug_assert_eq!(syn_entries.len(), SYN_ENTRY_COUNT as usize);
    debug_assert!(syn_entries.windows(2).all(|w| w[0].tag < w[1].tag));

    // --- the synthetic buffer ------------------------------------------
    let mut out: Vec<u8> = Vec::with_capacity(cursor as usize);
    out.extend_from_slice(&buf[0..4]); // the TIFF magic (the fp's endianness)
    let mut raw = [0u8; 4];
    e.put_u32(&mut raw, 0, 8);
    out.extend_from_slice(&raw); // IFD0 at offset 8 (the surgery's hard invariant)
    let mut countw = [0u8; 2];
    e.put_u16(&mut countw, 0, SYN_ENTRY_COUNT);
    out.extend_from_slice(&countw);
    for en in &syn_entries {
        let mut b = [0u8; 12];
        e.put_u16(&mut b, 0, en.tag);
        e.put_u16(&mut b, 2, en.typ);
        e.put_u32(&mut b, 4, en.count);
        b[8..12].copy_from_slice(&en.value_raw);
        out.extend_from_slice(&b);
    }
    let mut next = [0u8; 4];
    e.put_u32(&mut next, 0, 0);
    out.extend_from_slice(&next);
    for &(_tag, s, e2) in &sorted {
        out.extend_from_slice(&buf[s as usize..e2 as usize]);
    }
    debug_assert_eq!(out.len(), cursor as usize);

    // --- the synthetic sub-IFD tables ----------------------------------
    // NOTE the ORDER: the buffer's region copy is done above (the struct
    // regions included — their bytes carry the SOURCE's pointer values,
    // stale in the synthetic layout). The sub-IFD tables are built AFTER
    // the buffer so the re-emission below can patch them in place: the
    // synthetic buffer must be SELF-CONSISTENT (verify's `read_meta`
    // re-parses it and follows the struct's own pointers — stale ones
    // read the wrong content; the surgery does the same struct
    // re-emission on the output side, this is the source-side twin).
    let mut syn_subs: Vec<IfdTable> = Vec::with_capacity(meta.sub_ifds.len());
    for (i, sub) in meta.sub_ifds.iter().enumerate() {
        let ns = new_body_offsets[i];
        let size = sub.struct_range.end - sub.struct_range.start;
        let mut entries = Vec::with_capacity(sub.entries.len());
        for en in &sub.entries {
            let mut en = *en;
            if let Some((p, end)) = en.out_of_line {
                let nsp = remap(p, "sub-IFD out-of-line value pointer")?;
                let mut r = [0u8; 4];
                e.put_u32(&mut r, 0, nsp as u32);
                en.value_raw = r;
                en.out_of_line = Some((nsp, nsp + (end - p)));
            }
            entries.push(en);
        }
        let next_ifd = if sub.next_ifd == 0 {
            0
        } else {
            // A chained sub-IFD: the pointer sits inside a
            // relocated region (the corpus carries none — 0).
            remap(sub.next_ifd as u64, "sub-IFD next-IFD pointer")? as u32
        };
        // The re-emitted struct (count word + the 12-byte entries with
        // the re-targeted pointers + the next-IFD word) — same size as
        // the source struct (the entry count is preserved), written
        // over the stale region copy at the relocated position.
        let mut fresh: Vec<u8> = Vec::with_capacity(size as usize);
        let mut cw = [0u8; 2];
        e.put_u16(&mut cw, 0, entries.len() as u16);
        fresh.extend_from_slice(&cw);
        for en in &entries {
            let mut b = [0u8; 12];
            e.put_u16(&mut b, 0, en.tag);
            e.put_u16(&mut b, 2, en.typ);
            e.put_u32(&mut b, 4, en.count);
            b[8..12].copy_from_slice(&en.value_raw);
            fresh.extend_from_slice(&b);
        }
        let mut nw = [0u8; 4];
        e.put_u32(&mut nw, 0, next_ifd);
        fresh.extend_from_slice(&nw);
        debug_assert_eq!(fresh.len(), size as usize);
        out[ns as usize..ns as usize + fresh.len()].copy_from_slice(&fresh);
        syn_subs.push(IfdTable {
            off: ns,
            struct_range: ns..ns + size,
            entries,
            next_ifd,
        });
    }

    // --- the synthetic Frame -------------------------------------------
    let value_off = |tag: u16| -> u64 {
        8 + 2 + (syn_entries.iter().position(|en| en.tag == tag).unwrap() as u64) * 12 + 8
    };
    let frame = Frame {
        endianness: e,
        width: 3856,
        height: 2170,
        bits_per_sample: 12,
        compression: 1, // the synthetic contract (259 patched 1→7 by the surgery)
        strip_offset: data_end, // the zero-length strip at EOF
        strip_count: 0,
        strip_range: data_end..data_end,
        regions: sorted
            .iter()
            .zip(new_offsets.iter())
            .map(|(&r, &o)| {
                let (tag, _s, e2) = r;
                let ns = o.2;
                Region { tag, start: ns, end: ns + (e2 - _s) }
            })
            .collect(),
        compression_value_offset: value_off(259),
        strip_count_value_offset: value_off(279),
        ifd0: IfdTable {
            off: 8,
            struct_range: 8..(8 + ifd0_size),
            entries: syn_entries.clone(),
            next_ifd: 0,
        },
        sub_ifds: syn_subs,
        data_end,
        file_size: cursor,
    };
    Ok((out, frame))
}
// =====================================================================
// Ingest safety gate — the safety
// primitives: per-clip frame-number contiguity, the manifest-declared
// frame count, and the per-frame SMPTE 12M TimeCodes continuity from
// DNG tag 51043. The gate is unconditional (no escape flag) and
// follows the audit philosophy (loud, named, no silent skip).
//
// FAIL classes: FRAME_GAP, FRAME_DUP, COUNT_MISMATCH, TC_GAP,
// TC_OVERLAP, TC_MISSING — each with the frame pair + the raw values.
// Defensive classes for anomalies the decisions leave unnamed (no fp
// footage exhibits either — pinned from disk):
// FRAME_BADNAME (a .DNG stem
// without an all-digit final field — cannot be ordered), TC_MALFORMED
// (the tag present but unparsable, or an unparseable header — a corrupt
// header is named, never passed), MANIFEST_BAD (a corrupt input
// manifest.tsv — the declared count cannot be trusted).
//
// TC ground truth (verified against the whole CINEMA batch
// — 631/631 frames; the "8 B SMPTE 12M" shorthand, the
// measured layout pinned): tag 51043 is TIFF type 1 (BYTE) count 8,
// the payload = 4 BCD bytes + 4 NUL padding, byte order [FF, SS, MM,
// HH] (tens digit in the high nibble). The BCD decoding was pinned as
// the only candidate continuous at exactly +1/frame across the batch
// (24 fps non-drop — tag 51044 = 24000/1000, verified on every clip).
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::testutil::*;
    use crate::worker::{Outcome, process_dir};
    /// Atomicity under write failure — nothing half-written.
    /// The output dir is made READ-ONLY (non-root), so the tmp write cannot
    /// succeed; the per-frame run must FAIL at the tmp-write step, and no
    /// `.tmp` file may be left behind (the dst never exists, so
    /// resume-skip is not involved). Targeted at the per-frame `run` seam
    /// directly: at the process_dir level a read-only out dir now fails
    /// at the ingest-manifest write (which precedes every frame write),
    /// not at the frame write the test is about.
    #[test]
    fn atomic_write_failure_leaves_nothing_half_written() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let src = match std::fs::read(p) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                return;
            }
        };
        //: the camera gate resolves the frame against the
        // profile set (the A001 identity = the embedded constants —
        // the override is the test's FRAMEPRISM_PROFILES).
        camera_profile_override();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tmp = std::env::temp_dir().join("frameprism_atomic_test");
            let _ = std::fs::remove_dir_all(&tmp);
            let input = tmp.join("in");
            let output = tmp.join("out");
            std::fs::create_dir_all(&input).unwrap();
            let src_path = input.join("A001_001_20260701_000001.DNG");
            std::fs::write(&src_path, &src).unwrap();
            std::fs::create_dir_all(&output).unwrap();
            // Block writes: the output dir is read-only (non-root user).
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o555)).unwrap();

            let dst = output.join("A001_001_20260701_000001.DNG");
            let err = crate::worker::encode::run(
                &src_path,
                &dst,
                false,
                Mode::Lossless,
                false,
                false, // fast (lossless single-candidate) — off in this test
                LossyFormat::K34892,
                &ReferenceDctOpts::default(),
                None, // qc_rel
                None, // profiles: the in-process override
            )
            .expect_err("the read-only out dir must fail the tmp write");
            assert!(
                err.to_string().contains("write"),
                "the failure must be at the tmp-write step: {err}"
            );
            // Restore perms before checking/cleaning.
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o755)).unwrap();
            // Atomicity: no .tmp file survived the failed write, no dst.
            assert!(!dst.exists(), "no dst may appear");
            let leftovers: Vec<std::path::PathBuf> = std::fs::read_dir(&output)
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .collect();
            assert!(
                leftovers.is_empty(),
                "no leftovers in the output dir: {leftovers:?}"
            );
            let _ = std::fs::remove_dir_all(&tmp);
        }
    }

    /// TRIPWIRE (pinned): the
    /// ORIGINAL v3-era expectation (cbr7 f196/f197 = the flat-tail frames with
    /// per-frame MAE ratio r = our/reference < 0.5; `--verify` +
    /// `--reference-mae-tsv` must SUCCEED with the informational CBR distribution
    /// line — the b2-review F1 scope fix) is STALE against the shipped v4-2tap
    /// encoder: the v3-era 0.5×reference structure floor predates v4's
    /// measured v-ratio band (dark 0.091–0.341 / bright 0.272–0.346, both
    /// clips),
    /// so every A001 frame now fails the G2 structure floor gate BY DESIGN
    /// (the lossy family is DEFERRED with the band re-derivation as re-open
    /// condition (b)). This test pins the v4-era outcome verbatim:
    /// all three frames must fail at the floor with the exact
    /// deterministic v_ratio values (0.096 / 0.165 / 0.166). Two alarm
    /// directions: (1) any ENCODE-PATH drift moves the values → this fails;
    /// (2) a band RE-DERIVATION without flipping this test back to the
    /// SUCCEED assertion → this fails; the flip is re-open condition (c) and
    /// must land with (b). The name keeps its original spelling for
    /// suite-line continuity; this doc comment is the current contract.
    #[test]
    fn real_cbr7_verify_with_reference_mae_tsv_succeeds_despite_r_below_half() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        let proj = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let originals = proj.join("../testdata/originals/A001_001");
        let tsv = std::path::PathBuf::from(
            std::env::var("FRAMEPRISM_CBR7_QUALITY_TSV")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    // the default relative path (absent → the test skips)
                    proj.join("quality_cbr7.tsv")
                }),
        );
        let names = [
            "A001_001_20260701_000001.DNG", // in-band frame (r ~ 1.0)
            "A001_001_20260701_000196.DNG", // flat tail: r < 0.5
            "A001_001_20260701_000197.DNG", // flat tail: r < 0.5
        ];
        let mut missing = Vec::new();
        for n in &names {
            if !originals.join(n).exists() {
                missing.push(n.to_string());
            }
        }
        if !tsv.exists() || !missing.is_empty() {
            eprintln!(
                "SKIP real_cbr7_verify_with_reference_mae_tsv: corpus or quality tsv absent (missing: {:?})",
                if tsv.exists() { missing } else { vec!["quality_cbr7.tsv".to_string()] }
            );
            return;
        }
        //: the camera gate resolves the frames against the
        // profile set (the A001 identity = the embedded constants —
        // the override is the test's FRAMEPRISM_PROFILES).
        camera_profile_override();
        let tmp = std::env::temp_dir().join(format!("frameprism-g2-scoping-{}", std::process::id()));
        let (in_dir, out_dir) = (tmp.join("in"), tmp.join("out"));
        std::fs::create_dir_all(&in_dir).unwrap();
        for n in &names {
            std::fs::copy(originals.join(n), in_dir.join(n)).unwrap();
        }
        let opts = ReferenceDctOpts {
            reference_ref: None,
            reference_mae_tsv: Some(tsv.to_path_buf()),
            reference_structure_tsv: None,
        };
        // v4-era tripwire: the call must RETURN a report (per-frame
        // gate failures are collected, not fatal to the call), and every frame
        // must fail at the stale v3-era structure floor with the exact
        // pinned v_ratio.
        let report = process_dir(
            &in_dir,
            &out_dir,
            true,
            true,
            3,
            Mode::Cbr7,
            false,
            false, // fast (lossless single-candidate) — off in this test
            false,
            LossyFormat::ReferenceDct,
            &opts,
            None, // --to
            false, // qc_gate
        )
        .expect("cbr7 --verify with reference MAE tsv must RETURN a report (per-frame gate failures are collected, not fatal to the call — b2 F1 scope fix)");
        let mut failed: Vec<(String, String)> = Vec::new();
        for o in &report.outcomes {
            match o {
                Outcome::Done(st) => panic!(
                    "{} DONE — the v4-era tripwire expects the G2 structure floor failure; if the bands were re-derived, flip this test back to the SUCCEED assertion (re-open condition (c))",
                    st.file
                ),
                Outcome::Skipped { file, .. } => {
                    panic!("{file} must be encoded (fresh output dir)")
                }
                Outcome::Failed { file, error } => failed.push((file.clone(), error.clone())),
            }
        }
        assert_eq!(
            failed.len(),
            3,
            "all three frames must fail the stale v3-era structure floor (the v4 v-ratio band 0.091–0.341 sits below the 0.500 floor on every A001 frame); if this trips, either the encode path drifted or the bands were re-derived without the re-open condition (c) flip"
        );
        // Deterministic pins (binary, verified via the CLI
        // probe + the suite baseline): f001 0.096 / f196 0.165 / f197 0.166.
        // Any encode-path change moves these values → the test alarms.
        let pinned: Vec<(&str, &str)> = vec![
            ("A001_001_20260701_000001.DNG", "v_ratio 0.096"),
            ("A001_001_20260701_000196.DNG", "v_ratio 0.165"),
            ("A001_001_20260701_000197.DNG", "v_ratio 0.166"),
        ];
        for (name, vr) in pinned {
            let (_, e) = failed
                .iter()
                .find(|(f, _)| f == name)
                .unwrap_or_else(|| panic!("{name} missing from the failed set: {failed:?}"));
            assert!(
                e.contains("between-row class structure crushed"),
                "{name}: the failure must be the structure floor gate, not a different gate: {e}"
            );
            assert!(
                e.contains(vr),
                "{name}: the pinned v4-era v_ratio changed — encode-path drift (or a band re-derivation that must land with re-open condition (c)): {e}"
            );
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ===================================================================
    // — the camera identity gate (the OPTION (a) mechanism)
    // ===================================================================

    /// The G3 invariance guard (the routing layer): the
    /// existing geometries route EXACTLY as before the predicate
    /// extension (the additive match arm cannot change an existing
    /// routing decision — the oracles are the byte-level proof at the
    /// ship gate), and the new Open Gate 2K + 3K geometries are
    /// archive-eligible at the three native depths (the depth-match
 /// decision — the predicate is generic over 8/10/12) but NOT the tile
    /// layout (the tile branch stays the UHD-12 only — mirroring
    /// 1936×1090).
    #[test]
    fn routing_predicates_unchanged_and_2k_archive_only() {
        for (w, h, bps, tile, archive) in [
            (3856u32, 2170u32, 12u16, true, true),  // UHD-12: the shipped pair
            (3856u32, 2170u32, 10, false, true),    // UHD 10-bit: archive only
            (1936u32, 1090u32, 12, false, true),    // FHD-12: archive only
            (1936u32, 1090u32, 8, false, true),     // FHD 8-bit: archive only
            (2016u32, 1344u32, 12, false, true),    // Open Gate 2K-12: archive only (new)
            (2016u32, 1344u32, 10, false, true),    // the depth-match decision: 10 passes
            (2016u32, 1344u32, 8, false, true),     // the depth-match decision: 8 passes
            (3024u32, 2010u32, 12, false, true),    // Open Gate 3K-12: archive only (new)
            (3024u32, 2010u32, 10, false, true),    // the depth-match decision: 10 passes
            (3024u32, 2010u32, 8, false, true),     // the depth-match decision: 8 passes
            (1024u32, 768u32, 12, false, false),    // a foreign geometry: neither
        ] {
            let frame = crate::tiff::read(&crate::camera::synth_dng_frame(
                "SIGMA", "SIGMA fp", w, h, bps, 32803, Some([0u8; 8]),
            ))
            .unwrap_or_else(|e| panic!("synthetic {w}x{h} @{bps} must parse: {e}"));
            assert_eq!(is_tile_layout(&frame), tile, "is_tile_layout {w}x{h} @{bps}");
            assert_eq!(is_archive_layout(&frame), archive, "is_archive_layout {w}x{h} @{bps}");
        }
    }

    /// The Open Gate 2K grid geometry (the `tileenc` surface,
    /// test 6b): `Grid::new(2016, 1344)` = a 5×5 grid
    /// over the 482×272 tiles, BOTH edges clipped (2016 = 4·482 + 88 →
    /// the last column 88 wide; 1344 = 4·272 + 256 → the last row 256
    /// tall — the 982×300 clipped-column test's shape, the exact rect
    /// assertions). LIVES IN THE WORKER TESTS (not tileenc.rs) so the
    /// commit's touch-set stays within the fence list.
    #[test]
    fn open_gate_2k_grid_geometry() {
        use crate::tileenc::{plane_orient, tile_region, Grid};
        let g = Grid::new(2016, 1344);
        assert_eq!((g.cols, g.rows), (5, 5));
        let r00 = tile_region(2016, 1344, &g, 0, 0).unwrap();
        assert_eq!((r00.x0, r00.y0, r00.tw, r00.tl), (0, 0, 482, 272));
        let r04 = tile_region(2016, 1344, &g, 0, 4).unwrap();
        assert_eq!(
            (r04.x0, r04.tw),
            (1928, 88),
            "last column: 4·482=1928, 2016-1928=88"
        );
        let r40 = tile_region(2016, 1344, &g, 4, 0).unwrap();
        assert_eq!(
            (r40.y0, r40.tl),
            (1088, 256),
            "last row: 4·272=1088, 1344-1088=256"
        );
        let r44 = tile_region(2016, 1344, &g, 4, 4).unwrap();
        assert_eq!(
            (r44.x0, r44.y0, r44.tw, r44.tl),
            (1928, 1088, 88, 256),
            "the clipped corner: both edges at once"
        );
        // The clipped corner's plane orientation (88×256 — tl even +
        // divisible → wrapped: 256/2 = 128 rows of 88) + the full tile's
        // (136×482 wrapped, as at 3856-wide).
        assert_eq!(plane_orient(88, 256), (128, 88));
        assert_eq!(plane_orient(482, 272), (136, 482));
    }

    /// The Open Gate 3K grid geometry (the `tileenc` surface,
 /// test 7a, RE-PINNED to the measured reference
    /// contract): `Grid::new(3024, 2010)` = a 12×8 grid over the 252×252
    /// tiles (3024 = 12·252 exact; 2010 = 7·252 + 246 → one 246 px edge
    /// row encoded at the full 252 geometry — the generalized padding
    /// rule). The pre-fix 482×272 7×8 routing (the NLE media-offline
    /// root cause) is the legacy decode-side acceptance only.
    /// LIVES IN THE WORKER TESTS (not tileenc.rs) so the
    /// commit's touch-set stays within the fence list.
    #[test]
    fn open_gate_3k_grid_geometry() {
        use crate::tileenc::{gate_tile_dims, plane_orient, tile_region, Grid};
        assert_eq!(gate_tile_dims(3024, 2010), (252, 252));
        // The other gates keep the 482×272 contract (byte-invariance):
        assert_eq!(gate_tile_dims(3856, 2170), (482, 272));
        assert_eq!(gate_tile_dims(2016, 1344), (482, 272));
        assert_eq!(gate_tile_dims(1936, 1090), (482, 272));
        let g = Grid::new(3024, 2010);
        assert_eq!((g.cols, g.rows, g.tw, g.th), (12, 8, 252, 252));
        let r00 = tile_region(3024, 2010, &g, 0, 0).unwrap();
        assert_eq!((r00.x0, r00.y0, r00.tw, r00.tl), (0, 0, 252, 252));
        let r011 = tile_region(3024, 2010, &g, 0, 11).unwrap();
        assert_eq!(
            (r011.x0, r011.tw),
            (2772, 252),
            "last column: 11·252=2772, 3024-2772=252 (exact — no ragged column)"
        );
        let r70 = tile_region(3024, 2010, &g, 7, 0).unwrap();
        assert_eq!(
            (r70.y0, r70.tl),
            (1764, 246),
            "the edge row: 7·252=1764, 2010-1764=246 (encoded at full 252 geometry)"
        );
        let r711 = tile_region(3024, 2010, &g, 7, 11).unwrap();
        assert_eq!(
            (r711.x0, r711.y0, r711.tw, r711.tl),
            (2772, 1764, 252, 246),
            "the edge-row corner"
        );
        // The 246 px edge row's plane orientation: tl even +
        // 246·(252/2) = 30996 = 123·252 divisible → wrapped: 123 rows of
        // 252 (the full-geometry pad rule: padded_tl_for(246, 252) =
        // 252). The full tile's (252×252 → tl even, 252·126 = 31752 =
        // 126·252 divisible → wrapped: 126 rows of 252).
        assert_eq!(plane_orient(252, 246), (123, 252));
        assert_eq!(plane_orient(252, 252), (126, 252));
        assert_eq!(crate::tileenc::padded_tl_for(246, 252), 252);
        // The legacy 482 grid over the same frame (the decode-side
        // backward-compat shape — 7×8 = 56 tiles):
        let g482 = Grid::for_dims(3024, 2010, 482, 272);
        assert_eq!((g482.cols, g482.rows), (7, 8));
    }

    /// The FHD (1936×1090) per-(geometry × depth) grid (the
 /// `tileenc` surface — the measured reference contract, 
 /// 12-clip batch): the FHD grid VARIES WITH DEPTH
    /// within the geometry — @12: 242×274 (8×4 = 32 tiles; 242×8 =
    /// 1936 exact, the last row 268 encoded at the full 274 geometry),
    /// @10: 484×274 (4×4 = 16 tiles; 484×4 = 1936 exact), @8: 242×274
    /// (the 8-bit input FOLDS to the @12 grid — the measured fold rule;
 /// our @8 output stores BPS8, the reference stores BPS10 —,
    /// the promotion is NOT replicated). Every OTHER (geometry × depth)
    /// combination keeps the unchanged contract (the byte-invariance
    /// pin: 3K → 252×252 depth-invariant, UHD/2K/other → 482×272;
    /// the 2-arg legacy `gate_tile_dims` UNCHANGED). LIVES IN THE
    /// WORKER TESTS (not tileenc.rs) so the commit's touch-set stays
    /// within the fence list (the 2K/3K grid-geometry test pattern).
    #[test]
    fn fhd_grid_geometry() {
        use crate::tileenc::{
            gate_tile_dims, gate_tile_dims_depth, is_fhd_gate, plane_orient,
            tile_region, Grid, GATE_FHD_H, GATE_FHD_TILE_H, GATE_FHD_TILE_W_10,
            GATE_FHD_TILE_W_12, GATE_FHD_W,
        };
        // The FHD gate constants + predicate:
        assert_eq!((GATE_FHD_W, GATE_FHD_H), (1936, 1090));
        assert_eq!(GATE_FHD_TILE_W_12, 242, "the @12 grid width (242×8 = 1936 exact)");
        assert_eq!(GATE_FHD_TILE_W_10, 484, "the @10 grid width (484×4 = 1936 exact)");
        assert_eq!(GATE_FHD_TILE_H, 274, "the FHD tile height (both grids)");
        assert!(is_fhd_gate(1936, 1090));
        assert!(!is_fhd_gate(3024, 2010));
        assert!(!is_fhd_gate(3856, 2170));
        // The per-(geometry × depth) contract — the FHD depth-varying
 // grid (the measured rows):
        assert_eq!(gate_tile_dims_depth(1936, 1090, 12), (242, 274), "FHD @12: the 242×274 grid");
        assert_eq!(gate_tile_dims_depth(1936, 1090, 10), (484, 274), "FHD @10: the 484×274 grid");
        assert_eq!(gate_tile_dims_depth(1936, 1090, 8), (242, 274), "FHD @8: the 8-bit input folds to the @12 grid");
        // The other (geometry × depth) combinations UNCHANGED (the
        // byte-invariance pin):
        for depth in [8u32, 10, 12] {
            assert_eq!(gate_tile_dims_depth(3024, 2010, depth), (252, 252), "3K depth-invariant (the 3K row)");
            assert_eq!(gate_tile_dims_depth(2016, 1344, depth), (252, 336), "OG2K depth-invariant (the OG2K row)");
        }
 // The UHD row (the onboarding — MEASURED, not
        // "unchanged"): @10 → 964×272 (the measured per-depth grid);
        // @12/@8 → 482×272 UNCHANGED (the @12 in-profile measured
        // match; the @8 the measured 482×272 choice):
        assert_eq!(gate_tile_dims_depth(3856, 2170, 10), (964, 272), "UHD @10: the 964×272 grid (the UHD @10 row)");
        assert_eq!(gate_tile_dims_depth(3856, 2170, 12), (482, 272), "UHD @12: the 482×272 grid UNCHANGED (the in-profile measured match)");
        assert_eq!(gate_tile_dims_depth(3856, 2170, 8), (482, 272), "UHD @8: the 482×272 grid UNCHANGED (the measured choice)");
        assert_eq!(gate_tile_dims_depth(1024, 768, 12), (482, 272), "a foreign geometry: unchanged");
        // The 2-arg legacy contract UNCHANGED (the pre-measurement FHD
        // default — the decode-side backward-compat shape + every
        // existing caller's byte-invariance):
        assert_eq!(gate_tile_dims(1936, 1090), (482, 272));
        // The @12/@8 grid: 8×4 = 32 tiles (242×8 = 1936 exact; the last
        // row 1090 − 3×274 = 268 encoded at the FULL 274 geometry):
        let g12 = Grid::for_depth(1936, 1090, 12);
        assert_eq!((g12.cols, g12.rows, g12.tw, g12.th), (8, 4, 242, 274));
        let r00 = tile_region(1936, 1090, &g12, 0, 0).unwrap();
        assert_eq!((r00.x0, r00.y0, r00.tw, r00.tl), (0, 0, 242, 274));
        let r07 = tile_region(1936, 1090, &g12, 0, 7).unwrap();
        assert_eq!((r07.x0, r07.tw), (1694, 242), "last column: 7·242=1694, 1936-1694=242 (exact)");
        let r30 = tile_region(1936, 1090, &g12, 3, 0).unwrap();
        assert_eq!((r30.y0, r30.tl), (822, 268), "the edge row: 3·274=822, 1090-822=268 (full-274 geometry)");
        let r37 = tile_region(1936, 1090, &g12, 3, 7).unwrap();
        assert_eq!((r37.x0, r37.y0, r37.tw, r37.tl), (1694, 822, 242, 268), "the edge-row corner");
        // The edge row's plane orientation (242×268 — tl even +
        // 268·(242/2) = 32428 = 134·242 divisible → wrapped: 134 rows of
        // 242) + the full tile's (242×274 → 274·121 = 33154 = 137·242
        // divisible → wrapped: 137 rows of 242) + the edge row's pad to
        // the full 274 geometry (the generic padding rule):
        assert_eq!(plane_orient(242, 268), (134, 242));
        assert_eq!(plane_orient(242, 274), (137, 242));
        assert_eq!(crate::tileenc::padded_tl_for(268, 274), 274);
        // The @10 grid: 4×4 = 16 tiles (484×4 = 1936 exact; same 268
        // edge row):
        let g10 = Grid::for_depth(1936, 1090, 10);
        assert_eq!((g10.cols, g10.rows, g10.tw, g10.th), (4, 4, 484, 274));
        let r33 = tile_region(1936, 1090, &g10, 3, 3).unwrap();
        assert_eq!((r33.x0, r33.y0, r33.tw, r33.tl), (1452, 822, 484, 268), "the @10 edge-row corner");
        // The @10 edge row's plane orientation (484×268 — 268·242 =
        // 64856 = 134·484 divisible → wrapped: 134 rows of 484) + the
        // full tile's (484×274 → 274·242 = 66308 = 137·484 divisible →
        // wrapped: 137 rows of 484):
        assert_eq!(plane_orient(484, 268), (134, 484));
        assert_eq!(plane_orient(484, 274), (137, 484));
        // The @8 grid FOLDS to the @12 grid (the measured fold rule):
        let g8 = Grid::for_depth(1936, 1090, 8);
        assert_eq!((g8.cols, g8.rows, g8.tw, g8.th), (8, 4, 242, 274), "FHD @8 = the @12 grid");
        // The FHD per-gate candidate family (the measured reference
        // contract — the 80/80-tile census: the measured FHD tiles
        // sit outside the 482 legacy family {W7, W2, N1}; the observed
        // combos ONLY wrapped-PSV6 / natural-PSV5 / wrapped-PSV7). The
        // family is GRID-KEYED, never global:
        use crate::tileenc::{
            CANDIDATES, FHD_CANDIDATES, OG2K_CANDIDATES, gate_candidates,
            gate_candidates_for_grid,
        };
        assert_eq!(
            FHD_CANDIDATES,
            [
                (crate::tileenc::Orient::Wrapped, 7),
                (crate::tileenc::Orient::Wrapped, 6),
                (crate::tileenc::Orient::Natural, 5)
            ],
            "the measured FHD family (index 0 = the global FAST_CANDIDATE stream)"
        );
        assert_eq!(CANDIDATES[0], (crate::tileenc::Orient::Wrapped, 7), "the legacy family's index 0");
        assert_eq!(CANDIDATES[1], (crate::tileenc::Orient::Wrapped, 2), "the legacy family's wrapped PSV2");
        assert_eq!(CANDIDATES[2], (crate::tileenc::Orient::Natural, 1), "the legacy family's natural PSV1");
        // Encode-side key (the frame's gate geometry — the production
        // path always encodes FHD on the FHD grids):
        assert!(gate_candidates(1936, 1090) == &FHD_CANDIDATES, "FHD geometry → the FHD family");
        assert!(gate_candidates(3856, 2170) == &CANDIDATES, "UHD geometry → the legacy family");
        assert!(gate_candidates(2016, 1344) == &OG2K_CANDIDATES, "OG2K geometry → the measured OG2K family (the OG2K row)");
        assert!(gate_candidates(3024, 2010) == &CANDIDATES, "3K geometry → the legacy family (the 3K handling)");
        // Decode-side key (the FILE's grid — the backward-compat shape:
        // the legacy 482×272 FHD archives stay on the legacy family):
        assert!(
            gate_candidates_for_grid(1936, 1090, 242, 274) == &FHD_CANDIDATES,
            "the FHD @12/@8 grid → the FHD family"
        );
        assert!(
            gate_candidates_for_grid(1936, 1090, 484, 274) == &FHD_CANDIDATES,
            "the FHD @10 grid → the FHD family"
        );
        assert!(
            gate_candidates_for_grid(1936, 1090, 482, 272) == &CANDIDATES,
            "the legacy 482×272 FHD archives → the legacy family (staying decodable)"
        );
        assert!(
            gate_candidates_for_grid(3024, 2010, 252, 252) == &CANDIDATES,
            "the 3K 252×252 grid → the legacy family (UNCHANGED)"
        );
        assert!(
            gate_candidates_for_grid(3024, 2010, 482, 272) == &CANDIDATES,
            "the legacy 482×272 3K shape → the legacy family (UNCHANGED)"
        );
        assert!(
            gate_candidates_for_grid(3856, 2170, 482, 272) == &CANDIDATES,
            "UHD 482×272 → the legacy family (UNCHANGED)"
        );
    }

    /// The Open Gate 2K (2016×1344) per-gate grid (the `tileenc`
 /// surface, the onboarding G2 — the measured 
 /// contract): a DEPTH-INVARIANT 252×336 grid at all three
    /// depths (252×8 = 2016 exact, 336×4 = 1344 exact — a clean 8×4 =
    /// 32-tile grid, NO partial tiles — unlike the FHD's ragged edge
    /// row). The 8-bit input does NOT fold (no per-depth grids — the
    /// measured depth-invariance; our @8 output stores BPS8 — the
    /// reference's measured 8→10 identity promotion is NOT replicated —
 ///, the no-promotion boundary note in
    /// `docs/camera-profiles.md`). Every OTHER (geometry × depth)
    /// combination keeps the unchanged contract (the byte-invariance
    /// pin: 3K → 252×252 depth-invariant, FHD → the per-depth grids
 ///, UHD/other → 482×272; the 2-arg legacy
    /// `gate_tile_dims` + `Grid::new` UNCHANGED — the pre-fix 482×272
    /// 5×5 decode-side shape stays the legacy OG2K acceptance — the
    /// pinned `open_gate_2k_grid_geometry` test). LIVES IN THE WORKER
    /// TESTS (not tileenc.rs) so the commit's touch-set stays within
    /// the fence list.
    #[test]
    fn og2k_grid_geometry() {
        use crate::tileenc::{
            gate_tile_dims, gate_tile_dims_depth, is_og2k_gate, plane_orient,
            tile_region, Grid, GATE_OG2K_H, GATE_OG2K_TILE_H, GATE_OG2K_TILE_W,
            GATE_OG2K_W,
        };
        // The OG2K gate constants + predicate:
        assert_eq!((GATE_OG2K_W, GATE_OG2K_H), (2016, 1344));
        assert_eq!(GATE_OG2K_TILE_W, 252, "the grid width (252×8 = 2016 exact)");
        assert_eq!(GATE_OG2K_TILE_H, 336, "the grid height (336×4 = 1344 exact)");
        assert!(is_og2k_gate(2016, 1344));
        assert!(!is_og2k_gate(1936, 1090));
        assert!(!is_og2k_gate(3856, 2170));
        // The per-(geometry × depth) contract — the OG2K
 // depth-invariant grid (the measured rows):
        assert_eq!(gate_tile_dims_depth(2016, 1344, 12), (252, 336), "OG2K @12: the 252×336 grid");
        assert_eq!(gate_tile_dims_depth(2016, 1344, 10), (252, 336), "OG2K @10: the 252×336 grid (depth-invariant)");
        assert_eq!(gate_tile_dims_depth(2016, 1344, 8), (252, 336), "OG2K @8: the 252×336 grid (depth-invariant — no fold)");
        // The other (geometry × depth) combinations UNCHANGED (the
        // byte-invariance pin):
        for depth in [8u32, 10, 12] {
            assert_eq!(gate_tile_dims_depth(3024, 2010, depth), (252, 252), "3K depth-invariant (the 3K row)");
        }
 // The UHD row (the onboarding — MEASURED, not
        // "unchanged"): @10 → 964×272 (the measured per-depth grid);
        // @12/@8 → 482×272 UNCHANGED (the @12 in-profile measured
        // match; the @8 the measured 482×272 choice):
        assert_eq!(gate_tile_dims_depth(3856, 2170, 10), (964, 272), "UHD @10: the 964×272 grid (the UHD @10 row)");
        assert_eq!(gate_tile_dims_depth(3856, 2170, 12), (482, 272), "UHD @12: the 482×272 grid UNCHANGED (the in-profile measured match)");
        assert_eq!(gate_tile_dims_depth(3856, 2170, 8), (482, 272), "UHD @8: the 482×272 grid UNCHANGED (the measured choice)");
        assert_eq!(gate_tile_dims_depth(1936, 1090, 12), (242, 274), "FHD @12 (the FHD row)");
        assert_eq!(gate_tile_dims_depth(1936, 1090, 10), (484, 274), "FHD @10 (the FHD row)");
        assert_eq!(gate_tile_dims_depth(1936, 1090, 8), (242, 274), "FHD @8 (the FHD @8 fold)");
        assert_eq!(gate_tile_dims_depth(1024, 768, 12), (482, 272), "a foreign geometry: unchanged");
        // The 2-arg legacy contract UNCHANGED (the pre-measurement
        // default — the decode-side backward-compat shape: the legacy
        // pre-fix 482×272 5×5 OG2K archives stay decodable + every
        // existing caller's byte-invariance):
        assert_eq!(gate_tile_dims(2016, 1344), (482, 272));
        // The measured grid: 8×4 = 32 tiles (252×8 = 2016 exact,
        // 336×4 = 1344 exact — a clean grid, NO partial tiles — the
        // last tile is a full 252×336):
        let g = Grid::for_depth(2016, 1344, 12);
        assert_eq!((g.cols, g.rows, g.tw, g.th), (8, 4, 252, 336));
        let r00 = tile_region(2016, 1344, &g, 0, 0).unwrap();
        assert_eq!((r00.x0, r00.y0, r00.tw, r00.tl), (0, 0, 252, 336));
        let r07 = tile_region(2016, 1344, &g, 0, 7).unwrap();
        assert_eq!((r07.x0, r07.tw), (1764, 252), "last column: 7·252=1764, 2016-1764=252 (exact)");
        let r30 = tile_region(2016, 1344, &g, 3, 0).unwrap();
        assert_eq!((r30.y0, r30.tl), (1008, 336), "last row: 3·336=1008, 1344-1008=336 (exact — no edge row)");
        let r37 = tile_region(2016, 1344, &g, 3, 7).unwrap();
        assert_eq!((r37.x0, r37.y0, r37.tw, r37.tl), (1764, 1008, 252, 336), "the last tile: a full 252×336");
        // The tile's plane orientation (252×336 — 336·(252/2) =
        // 42336 = 168·252 divisible → wrapped: 168 rows of 252):
        assert_eq!(plane_orient(252, 336), (168, 252));
        // The depth-invariance: the @10 and @8 grids = the @12 grid
        // (no fold — unlike the FHD's @8 → @12 fold; the @8 no-promotion
        // — BPS8 out — is pinned in the structural gate):
        let g10 = Grid::for_depth(2016, 1344, 10);
        assert_eq!((g10.cols, g10.rows, g10.tw, g10.th), (8, 4, 252, 336), "OG2K @10 = the @12 grid (depth-invariant)");
        let g8 = Grid::for_depth(2016, 1344, 8);
        assert_eq!((g8.cols, g8.rows, g8.tw, g8.th), (8, 4, 252, 336), "OG2K @8 = the @12 grid (depth-invariant — no fold)");
        // The OG2K per-gate candidate family (the measured reference
        // contract — the 288/288-tile census: the measured OG2K
        // tiles sit outside the 482 legacy family {W7, W2, N1}; the
        // observed combos ONLY wrapped-PSV6 (dominant) / natural-PSV5
        // / wrapped-PSV7 — the same 3 members as the FHD measured
        // family). The family is GRID-KEYED, never global:
        use crate::tileenc::{
            CANDIDATES, FHD_CANDIDATES, OG2K_CANDIDATES, gate_candidates,
            gate_candidates_for_grid,
        };
        assert_eq!(
            OG2K_CANDIDATES,
            [
                (crate::tileenc::Orient::Wrapped, 7),
                (crate::tileenc::Orient::Wrapped, 6),
                (crate::tileenc::Orient::Natural, 5)
            ],
            "the measured OG2K family (index 0 = the global FAST_CANDIDATE stream)"
        );
        assert_eq!(CANDIDATES[0], (crate::tileenc::Orient::Wrapped, 7), "the legacy family's index 0");
        assert_eq!(CANDIDATES[1], (crate::tileenc::Orient::Wrapped, 2), "the legacy family's wrapped PSV2");
        assert_eq!(CANDIDATES[2], (crate::tileenc::Orient::Natural, 1), "the legacy family's natural PSV1");
        // Encode-side key (the frame's gate geometry — the production
        // path always encodes OG2K on the 252×336 grid):
        assert!(gate_candidates(2016, 1344) == &OG2K_CANDIDATES, "OG2K geometry → the OG2K family");
        assert!(gate_candidates(1936, 1090) == &FHD_CANDIDATES, "FHD geometry → the FHD family (the FHD handling)");
        assert!(gate_candidates(3856, 2170) == &CANDIDATES, "UHD geometry → the legacy family");
        assert!(gate_candidates(3024, 2010) == &CANDIDATES, "3K geometry → the legacy family (the 3K handling)");
        // Decode-side key (the FILE's grid — the backward-compat shape:
        // the legacy 482×272 OG2K archives stay on the legacy family):
        assert!(
            gate_candidates_for_grid(2016, 1344, 252, 336) == &OG2K_CANDIDATES,
            "the OG2K 252×336 grid → the OG2K family (all depths — depth-invariant)"
        );
        assert!(
            gate_candidates_for_grid(2016, 1344, 482, 272) == &CANDIDATES,
            "the legacy 482×272 OG2K archives → the legacy family (staying decodable)"
        );
        assert!(
            gate_candidates_for_grid(1936, 1090, 242, 274) == &FHD_CANDIDATES,
            "the FHD @12/@8 grid → the FHD family (UNCHANGED)"
        );
        assert!(
            gate_candidates_for_grid(1936, 1090, 484, 274) == &FHD_CANDIDATES,
            "the FHD @10 grid → the FHD family (UNCHANGED)"
        );
        assert!(
            gate_candidates_for_grid(3024, 2010, 252, 252) == &CANDIDATES,
            "the 3K 252×252 grid → the legacy family (UNCHANGED)"
        );
        assert!(
            gate_candidates_for_grid(3856, 2170, 482, 272) == &CANDIDATES,
            "UHD 482×272 → the legacy family (UNCHANGED)"
        );
    }

    /// The UHD (3856×2170) per-(geometry × depth) grid (the `tileenc`
 /// surface — the measured reference contract, 12-clip
 /// batch — the onboarding G4, the LAST
    /// measured row): the @10 grid VARIES to 964×272 (4×8 = 32 tiles;
    /// 964×4 = 3856 EXACT — no edge column; 2170 = 7×272 + 266 → the
    /// LAST ROW 266 px encoded at the FULL 272 geometry — the generic
    /// edge-tile padding rule); the @12 + @8 grids KEEP the 482×272
    /// default UNCHANGED (8×8 = 64 tiles — the @12 in-profile measured
    /// match, the @8 the measured 482×272 choice). Every
    /// OTHER (geometry × depth) combination keeps the unchanged contract
    /// (the byte-invariance pin: 3K → 252×252 depth-invariant (the
 /// row), FHD → the per-depth grids, OG2K →
 /// 252×336 depth-invariant, foreign → 482×272; the 2-arg
    /// legacy `gate_tile_dims` + `Grid::new` UNCHANGED — the 482×272 8×8
    /// decode-side shape stays the UHD @12/@8 contract + the legacy
 /// acceptance of the pre-existing @10 archives). The 964×272 grid's
    /// MEASURED family = the 482 legacy family's members {W-PSV7,
 /// W-PSV2, N-PSV1} (the 96/96-tile census over the mirrored
    /// A001_002 @10 corpus — every stored reference tile byte-identical
    /// to exactly one re-encode, ZERO outside; the grid-keyed routing
    /// keeps `CANDIDATES` for the UHD grids, the 482×272 grid UNCHANGED
    /// at every other geometry — the per-gate scoping discipline). LIVES
    /// IN THE WORKER TESTS (not tileenc.rs) so the commit's touch-set
    /// stays within the fence list (the 2K/3K/FHD/OG2K grid-geometry
    /// test pattern).
    #[test]
    fn uhd10_grid_geometry() {
        use crate::tileenc::{
            gate_tile_dims, gate_tile_dims_depth, is_uhd_gate, plane_orient,
            tile_region, Grid, GATE_UHD_H, GATE_UHD_TILE_W_10, GATE_UHD_W,
            TILE_H, TILE_W,
        };
        // The UHD gate constants + predicate:
        assert_eq!((GATE_UHD_W, GATE_UHD_H), (3856, 2170));
        assert_eq!(GATE_UHD_TILE_W_10, 964, "the @10 grid width (964×4 = 3856 exact)");
        assert!(is_uhd_gate(3856, 2170));
        assert!(!is_uhd_gate(1936, 1090));
        assert!(!is_uhd_gate(2016, 1344));
        assert!(!is_uhd_gate(3024, 2010));
        // The per-(geometry × depth) contract — the UHD @10 grid
 // (the measured row, ) + the @12/@8 UNCHANGED:
        assert_eq!(gate_tile_dims_depth(3856, 2170, 10), (964, 272), "UHD @10: the 964×272 grid (the measured per-depth grid)");
        assert_eq!(gate_tile_dims_depth(3856, 2170, 12), (482, 272), "UHD @12: the 482×272 grid UNCHANGED (the in-profile measured match)");
        assert_eq!(gate_tile_dims_depth(3856, 2170, 8), (482, 272), "UHD @8: the 482×272 grid UNCHANGED (the measured choice)");
        // The other (geometry × depth) combinations UNCHANGED (the
        // byte-invariance pin):
        for depth in [8u32, 10, 12] {
            assert_eq!(gate_tile_dims_depth(3024, 2010, depth), (252, 252), "3K depth-invariant (the 3K row)");
            assert_eq!(gate_tile_dims_depth(2016, 1344, depth), (252, 336), "OG2K depth-invariant (the OG2K row)");
        }
        assert_eq!(gate_tile_dims_depth(1936, 1090, 12), (242, 274), "FHD @12 (the FHD row)");
        assert_eq!(gate_tile_dims_depth(1936, 1090, 10), (484, 274), "FHD @10 (the FHD row)");
        assert_eq!(gate_tile_dims_depth(1936, 1090, 8), (242, 274), "FHD @8 (the FHD @8 fold)");
        assert_eq!(gate_tile_dims_depth(1024, 768, 12), (482, 272), "a foreign geometry: unchanged");
        // The 2-arg legacy contract UNCHANGED (the pre-measurement
        // default — the decode-side backward-compat shape + the @12/@8
        // UHD in-profile contract + every existing caller's
        // byte-invariance):
        assert_eq!(gate_tile_dims(3856, 2170), (482, 272));
        let g_legacy = Grid::new(3856, 2170);
        assert_eq!((g_legacy.cols, g_legacy.rows), (8, 8), "the 482×272 UHD grid = 8×8 = 64 tiles");
        // The @10 grid: 4×8 = 32 tiles (964×4 = 3856 EXACT — no edge
        // column; 2170 = 7×272 + 266 → the last row 266 px at the FULL
        // 272 geometry):
        let g10 = Grid::for_depth(3856, 2170, 10);
        assert_eq!((g10.cols, g10.rows, g10.tw, g10.th), (4, 8, 964, 272));
        let r00 = tile_region(3856, 2170, &g10, 0, 0).unwrap();
        assert_eq!((r00.x0, r00.y0, r00.tw, r00.tl), (0, 0, 964, 272));
        let r03 = tile_region(3856, 2170, &g10, 0, 3).unwrap();
        assert_eq!((r03.x0, r03.tw), (2892, 964), "last column: 3·964=2892, 3856-2892=964 (exact — no ragged column)");
        let r70 = tile_region(3856, 2170, &g10, 7, 0).unwrap();
        assert_eq!((r70.y0, r70.tl), (1904, 266), "the edge row: 7·272=1904, 2170-1904=266 (full-272 geometry)");
        let r73 = tile_region(3856, 2170, &g10, 7, 3).unwrap();
        assert_eq!((r73.x0, r73.y0, r73.tw, r73.tl), (2892, 1904, 964, 266), "the edge-row corner");
        // The edge row's plane orientation (964×266 — 266·(964/2) =
        // 128212 = 133·964 divisible → wrapped: 133 rows of 964) + the
        // full tile's (964×272 → 272·482 = 131104 = 136·964 divisible
        // → wrapped: 136 rows of 964) + the edge row's pad to the full
        // 272 geometry (the generic padding rule):
        assert_eq!(plane_orient(964, 266), (133, 964));
        assert_eq!(plane_orient(964, 272), (136, 964));
        assert_eq!(crate::tileenc::padded_tl_for(266, 272), 272);
        // The @12/@8 grids: 8×8 = 64 tiles UNCHANGED (the 482×272
        // default):
        let g12 = Grid::for_depth(3856, 2170, 12);
        assert_eq!((g12.cols, g12.rows, g12.tw, g12.th), (8, 8, 482, 272), "UHD @12 = the 482×272 grid UNCHANGED");
        let g8 = Grid::for_depth(3856, 2170, 8);
        assert_eq!((g8.cols, g8.rows, g8.tw, g8.th), (8, 8, 482, 272), "UHD @8 = the 482×272 grid UNCHANGED");
        // The UHD per-grid candidate family (the measured reference
        // contract — the 96/96-tile census over the mirrored A001_002
        // @10 corpus: the 964×272 grid's measured family = the 482
        // legacy family's members {W-PSV7, W-PSV2, N-PSV1}, ZERO
        // outside — no separate family constant; the grid-keyed
        // routing keeps `CANDIDATES` for the UHD grids, the 482×272
        // grid UNCHANGED at every other geometry):
        use crate::tileenc::{
            CANDIDATES, FHD_CANDIDATES, OG2K_CANDIDATES, gate_candidates,
            gate_candidates_for_grid,
        };
        assert_eq!(
            CANDIDATES,
            [
                (crate::tileenc::Orient::Wrapped, 7),
                (crate::tileenc::Orient::Wrapped, 2),
                (crate::tileenc::Orient::Natural, 1)
            ],
            "the legacy family (the 964×272 grid's measured family — the census)"
        );
        // Encode-side key (the frame's gate geometry — the UHD gate's
        // BOTH grids run on the legacy family: the @12/@8 482×272 grid
        // + the @10 964×272 grid):
        assert!(gate_candidates(3856, 2170) == &CANDIDATES, "UHD geometry → the legacy family (= the 964×272 grid's measured family)");
        assert!(gate_candidates(1936, 1090) == &FHD_CANDIDATES, "FHD geometry → the FHD family (the FHD handling)");
        assert!(gate_candidates(2016, 1344) == &OG2K_CANDIDATES, "OG2K geometry → the OG2K family (the OG2K handling)");
        assert!(gate_candidates(3024, 2010) == &CANDIDATES, "3K geometry → the legacy family (the 3K handling)");
        // Decode-side key (the FILE's grid — the backward-compat shape:
 // the UHD @10 964×272 archives + the UHD @12/@8 + the pre-existing
        // @10 482×272 archives all run on the legacy family):
        assert!(
            gate_candidates_for_grid(3856, 2170, 964, 272) == &CANDIDATES,
            "the UHD @10 964×272 grid → the legacy family (the measured family — the census)"
        );
        assert!(
            gate_candidates_for_grid(3856, 2170, 482, 272) == &CANDIDATES,
            "the UHD 482×272 grid → the legacy family (@12/@8 in-profile + the legacy @10 output — UNCHANGED)"
        );
        assert!(
            gate_candidates_for_grid(1936, 1090, 242, 274) == &FHD_CANDIDATES,
            "the FHD @12/@8 grid → the FHD family (UNCHANGED)"
        );
        assert!(
            gate_candidates_for_grid(1936, 1090, 484, 274) == &FHD_CANDIDATES,
            "the FHD @10 grid → the FHD family (UNCHANGED)"
        );
        assert!(
            gate_candidates_for_grid(2016, 1344, 252, 336) == &OG2K_CANDIDATES,
            "the OG2K 252×336 grid → the OG2K family (UNCHANGED)"
        );
        assert!(
            gate_candidates_for_grid(3024, 2010, 252, 252) == &CANDIDATES,
            "the 3K 252×252 grid → the legacy family (UNCHANGED)"
        );
        // The --fast index-0 stream on the 964×272 grid = the measured
        // family's index 0 = Wrapped PSV7 (the global FAST_CANDIDATE —
        // the same stream as every other gate's index 0):
        assert_eq!(
            crate::tileenc::FAST_CANDIDATE,
            CANDIDATES[0],
            "the --fast UHD@10 stream = the measured family's index 0"
        );
    }

    /// The Open Gate 3K (3024×2010, 12-bit, the modified firmware 5.02
    /// line's UNOFFICIAL mode 98): the measured 252×252 grid contract
 /// end to end (RE-PINNED — the pre-fix version ran a
    /// SYNTHETIC frame through the 482×272 grid: the NLE media-offline
    /// root cause). The profiled REAL frame (the corpus A001_006 f1 —
    /// the template's measured tag set; absent → the test skips, the
 /// project corpus pattern) passes the camera gate (the identity
    /// layer), the routing predicate (`is_archive_layout`) selects the
    /// native-depth tile path on the 252×252 grid (12×8 = 96 tiles;
    /// NOT the single-strip LJPEG fallback), the measured reference
    /// re-layout surgery runs (`apply_tiled_3k` — the tag plan: 273/
    /// 278/279 out, 322-325 in at 322/323 = 252/252, 259 patched 1→7,
    /// 324/325 at 96 entries), the encode's OWN verify runs
    /// (`bit_exact_tiled_plane` + `metadata_preserved_tiled`, the
    /// verify=true surface — including the per-gate 322/323 pair + the
    /// template's 34665 expectation), and the native depth is preserved
    /// (the output BitsPerSample 258 = the input's 12 — no
    /// up-conversion).
    #[test]
    fn open_gate_3k_archive_branch_end_to_end() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        let p = "../testdata/originals/A001_006/A001_006_20260920_000001.DNG";
        let bytes = match std::fs::read(p) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                return;
            }
        };
        let (input, output, base) =
            camera_gate_fixture("open-gate-3k", "A001_006_20260920_000001.DNG", &bytes);
        let report = process_dir(
            &input,
            &output,
            true, // verify: the encode's own verify (the archive path's
                  // bit_exact_tiled_plane + metadata_preserved_tiled)
            false,
            1,
            Mode::Lossless,
            false,
            false, // fast
            false, // checksums
            LossyFormat::K34892,
            &ReferenceDctOpts::default(),
            None, // --to
            false, // qc_gate
        )
        .expect("the Open Gate 3K frame must encode (the archive branch)");
        assert!(
            matches!(report.outcomes[0], Outcome::Done(_)),
            "the Open Gate 3K frame must be Done: {:?}",
            report.outcomes[0]
        );
        let out_path = output.join("A001_006_20260920_000001.DNG");
        assert!(out_path.is_file());
        let out = std::fs::read(&out_path).unwrap();
        // The ARCHIVE branch's tag plan on the output (the strip
        // fallback keeps 259 = 1 + no tile tags — the discriminator):
        // the tile tags present at 96 entries + the JPEG-lossless
        // compression + the 252×252 grid = the measured 3K contract ran,
        // not the single-strip LJPEG fallback (and not the legacy
        // 482×272 grid).
        let meta = crate::tiff::read_meta(&out)
            .expect("the encoded output must read_meta (the tile-mode surface)");
        let e = meta.endianness;
        let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
        let t259 = find(259).expect("tag 259 must be present");
        assert_eq!(
            e.u16(&t259.value_raw),
            7,
            "tag 259 must be JPEG-lossless (the tile path patches 1→7)"
        );
        let t322 = find(322).expect("tag 322 (TileWidth) — the tile plan");
        assert_eq!(e.u32(&t322.value_raw), 252, "322 = 252 (the measured 3K tile width)");
        let t323 = find(323).expect("tag 323 (TileLength) — the tile plan");
        assert_eq!(e.u32(&t323.value_raw), 252, "323 = 252 (the measured 3K tile height)");
        // The 3024×2010 frame on the 252×252 grid = a 12×8 grid = 96
        // tiles (the 324/325 tile arrays carry one entry per tile):
        let t324 = find(324).expect("tag 324 (TileOffsets) — the tile plan");
        assert_eq!(t324.count, 96, "324 = 96 tile offsets (the 12×8 grid)");
        let t325 = find(325).expect("tag 325 (TileByteCounts) — the tile plan");
        assert_eq!(t325.count, 96, "325 = 96 tile byte counts (the 12×8 grid)");
        // The native depth is preserved (the output 258 = the input's):
        let t258 = find(258).expect("tag 258 (BitsPerSample) must be present");
        assert_eq!(
            e.u16(&t258.value_raw),
            12,
            "the output BitsPerSample must be the input's (12 — no up-conversion)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


    /// PARITY (the measured reference contract — the interop oracle +
    /// benchmark, NOT the acceptance): the 3K 252\u{00d7}252 grid encode
    /// is BYTE-IDENTICAL to the SoC's lossless output on every corpus
    /// frame (the maintainer's reference corpus) — the measured
    /// byte-identity evidence. Corpus-conditional (skip when the corpus
    /// is absent) so the gate also holds on a clean checkout.
    #[test]
    fn golden_3k_encode_byte_identical() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        // The spec's R3 gate: the 3 measured sample frames (f1 = the
        // 64/64-tile measurement frame, f57 middle, f114 last). The full
        // 114-frame corpus was probed out-of-gate (the report records
        // 113/114 byte-identical — the one residual is the documented
        // selection-boundary tile of frame 91, outside the gate scope).
        let dir = "../testdata/originals/A001_006";
        let gdir = "../testdata/reference/lossless/A001_006";
        let mut names: Vec<String> = vec![
            "A001_006_20260920_000001.DNG".into(),
            "A001_006_20260920_000057.DNG".into(),
            "A001_006_20260920_000114.DNG".into(),
        ];
        if !std::path::Path::new(&format!("{dir}/{}", names[0])).exists() {
            eprintln!("skip: the A001_006 3K corpus is absent");
            return;
        }
        names.retain(|n| std::path::Path::new(&format!("{gdir}/{n}")).exists());
        if names.is_empty() {
            eprintln!("skip: the A001_006 3K golden corpus is absent");
            return;
        }
        for n in &names {
            let bytes = std::fs::read(format!("{dir}/{n}")).unwrap();
            let gold_p = format!("{gdir}/{n}");
            let (input, output, base) = camera_gate_fixture(&format!("golden-3k-{n}"), n, &bytes);
            let report = process_dir(
                &input,
                &output,
                true, // verify: the encode's own verify surface
                false,
                1,
                Mode::Lossless,
                false,
                false, // fast — the 3-candidate adaptive encode (parity)
                false, // checksums
                LossyFormat::K34892,
                &ReferenceDctOpts::default(),
                None, // --to
                false, // qc_gate
            )
            .expect("process_dir (the dir plumbing)");
            assert!(
                matches!(report.outcomes[0], Outcome::Done(_)),
                "the golden 3K frame must encode Done: {:?}",
                report.outcomes[0]
            );
            let out = std::fs::read(output.join(n)).expect("the encoded output must exist");
            let gold = std::fs::read(&gold_p).unwrap();
            if out.len() != gold.len() {
                panic!(
                    "{n}: output size {} != the reference golden's {} (byte-identity)",
                    out.len(),
                    gold.len()
                );
            }
            if out != gold {
                let idx = out
                    .iter()
                    .zip(gold.iter())
                    .position(|(a, b)| a != b)
                    .unwrap();
                panic!(
                    "{n}: output != the reference golden (first diff at byte {idx} of {})",
                    out.len()
                );
            }
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    /// THE GOLDEN ENCODE TEST — the FHD per-(geometry × depth) grid
 /// (the structural contract, the measured reference
 /// contract, 12-clip batch): encode the
    /// mirrored FHD ORIGINAL frames and assert, per frame: (a) encode
    /// SUCCESS + the STRUCTURAL PIN — 322/323 = the per-depth expected
    /// pair (242/274 for @12/@8; 484/274 for @10), the tile count (32
    /// for @12/@8; 16 for @10), BitsPerSample = the input depth
 /// (12/10/8 — NO promotion — ), PhotometricInterpretation
    /// 32803, Compression 7; (b) the DECODE ROUND-TRIP PIXEL-EXACT vs
    /// the original (the golden-decode pattern on the encoded output —
    /// the shipped decode path incl. the restore-drill, the FHD family
    /// grid-keyed). NOT a byte comparison against the corpus
 /// (the corpus = the interop oracle + the benchmark, not
    /// a byte spec — the corpus frames serve the structural
    /// cross-check in the decode golden test). The sample frames (the
    /// 3-frame pattern — first/middle/last): A001_004 @12 (97 frames):
    /// 000001/000049/000097 · A001_005 @10 (97): 000001/000049/000097
    /// · A001_006 @8 (101): 000001/000051/000101. Corpus-conditional
 /// (skip when the corpus is absent — the project pattern); on the
    /// machine that carries the corpus the gate MUST run it (RAN-not-
    /// skipped).
    #[test]
    fn golden_fhd_encode_structural() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        // (clip dir, input depth, expected 322/323, expected tile
        // count, the 3 sample frames — the spec's R3 rows):
        let cases: [(&str, u16, (u32, u32), u32, [String; 3]); 3] = [
            (
                "A001_004_20260924",
                12,
                (242, 274),
                32,
                [
                    "A001_004_20260924_000001.DNG".into(),
                    "A001_004_20260924_000049.DNG".into(),
                    "A001_004_20260924_000097.DNG".into(),
                ],
            ),
            (
                "A001_005_20260924",
                10,
                (484, 274),
                16,
                [
                    "A001_005_20260924_000001.DNG".into(),
                    "A001_005_20260924_000049.DNG".into(),
                    "A001_005_20260924_000097.DNG".into(),
                ],
            ),
            (
                "A001_006_20260924",
                8,
                (242, 274),
                32,
                [
                    "A001_006_20260924_000001.DNG".into(),
                    "A001_006_20260924_000051.DNG".into(),
                    "A001_006_20260924_000101.DNG".into(),
                ],
            ),
        ];
        for (clip, depth, (want_tw, want_th), want_tiles, names) in cases {
            let dir = format!("../testdata/originals/{clip}");
            let names = names.to_vec();
            if !std::path::Path::new(&format!("{dir}/{}", names[0])).exists() {
                eprintln!("skip: the {clip} FHD corpus is absent");
                continue;
            }
            let names: Vec<String> = names
                .into_iter()
                .filter(|n| std::path::Path::new(&format!("{dir}/{n}")).exists())
                .collect();
            if names.is_empty() {
                eprintln!("skip: the {clip} FHD corpus is absent");
                continue;
            }
            for n in &names {
                let bytes = std::fs::read(format!("{dir}/{n}")).unwrap();
                let (input, output, base) = camera_gate_fixture(&format!("golden-fhd-{n}"), n, &bytes);
                let report = process_dir(
                    &input,
                    &output,
                    true, // verify: the encode's own verify surface
                    false,
                    1,
                    Mode::Lossless,
                    false,
                    false, // fast — the 3-candidate adaptive encode (the project selection over the FHD family)
                    false, // checksums
                    LossyFormat::K34892,
                    &ReferenceDctOpts::default(),
                    None, // --to
                    false, // qc_gate
                )
                .expect("process_dir (the dir plumbing)");
                assert!(
                    matches!(report.outcomes[0], Outcome::Done(_)),
                    "the golden FHD frame must encode Done: {n}: {:?}",
                    report.outcomes[0]
                );
                let out = std::fs::read(output.join(n)).expect("the encoded output must exist");
                // (a) the structural pin (the measured per-depth contract):
                let meta = crate::tiff::read_meta(&out)
                    .expect("the encoded output must read_meta (the tile-mode surface)");
                let e = meta.endianness;
                let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
                let t259 = find(259).expect("tag 259 must be present");
                assert_eq!(e.u16(&t259.value_raw), 7, "{n}: Compression 7 (tiled lossless)");
                let t262 = find(262).expect("tag 262 must be present");
                assert_eq!(
                    e.u16(&t262.value_raw),
                    32803,
                    "{n}: PhotometricInterpretation 32803 (CFA)"
                );
                let t258 = find(258).expect("tag 258 must be present");
                assert_eq!(
                    e.u16(&t258.value_raw),
                    depth,
                    "{n}: BitsPerSample = the input depth ({depth} — NO promotion)"
                );
                let t322 = find(322).expect("tag 322 (TileWidth) — the tile plan");
                assert_eq!(
                    e.u32(&t322.value_raw),
                    want_tw,
                    "{n}: 322 = {want_tw} (the per-depth FHD grid)"
                );
                let t323 = find(323).expect("tag 323 (TileLength) — the tile plan");
                assert_eq!(e.u32(&t323.value_raw), want_th, "{n}: 323 = {want_th}");
                let t324 = find(324).expect("tag 324 (TileOffsets) — the tile plan");
                assert_eq!(t324.count, want_tiles, "{n}: 324 = {want_tiles} tile offsets (the FHD grid)");
                let t325 = find(325).expect("tag 325 (TileByteCounts) — the tile plan");
                assert_eq!(t325.count, want_tiles, "{n}: 325 = {want_tiles} tile byte counts");
                // (b) the decode round-trip pixel-exact vs the original
                // (the golden-decode pattern on the encoded output —
                // the shipped decode path incl. the restore-drill):
                let (dw, dh, decoded) = crate::decode::decode_frame_p1(
                    &crate::decode::FrameRef::J92 {
                        src: output.join(n),
                        name: n.clone(),
                    },
                    std::path::Path::new("."),
                    std::path::Path::new("djxl"),
                    0,
                )
                .unwrap_or_else(|err| panic!("{n}: decode round-trip: {err}"));
                assert_eq!((dw, dh), (1936, 1090), "{n}: the round-trip geometry");
                let frame = crate::tiff::read(&bytes)
                    .unwrap_or_else(|err| panic!("{n}: original parse: {err}"));
                let expected = match depth {
                    12 => crate::pack12::unpack12(frame.strip_slice(&bytes), frame.width, frame.height),
                    10 => crate::pack12::unpack10(frame.strip_slice(&bytes), frame.width, frame.height),
                    _ => crate::pack12::unpack8(frame.strip_slice(&bytes), frame.width, frame.height),
                }
                .unwrap_or_else(|err| panic!("{n}: original unpack: {err}"));
                assert_eq!(
                    decoded, expected,
                    "{n}: the decode round-trip != the original samples (pixel-exact)"
                );
                let _ = std::fs::remove_dir_all(&base);
            }
        }
    }

 /// PARITY (the measured reference contract, — the
 /// 12-clip batch, the onboarding G2): the OG2K
    /// goldens encode at the MEASURED per-gate grid (252×336 at all
    /// three depths — the measured depth-invariance, 32 tiles), the
    /// 3-candidate adaptive encode over the grid-keyed OG2K family
 /// (project size-min — : no reference-matching key), the
    /// NO-PROMOTION @8 (BPS8 out; the measured 8→10
    /// identity promotion NOT replicated). Per frame: (a) the
    /// structural pin (322/323 = 252×336, 32 tiles, BPS = the input
    /// depth — NO promotion, Photometric 32803, Compression 7);
    /// (b) the DECODE ROUND-TRIP PIXEL-EXACT vs the original (the
    /// golden-decode pattern on the encoded output — the shipped
    /// decode path incl. the restore-drill, the OG2K family
    /// grid-keyed). NOT a byte comparison against the corpus
 /// (the corpus = the interop oracle + the benchmark,
    /// not a byte spec — the corpus frames serve the
    /// structural cross-check in the decode golden test). The sample
    /// frames (the 3-frame pattern — first/middle/last): A001_007 @12
    /// (97 frames): 000001/000049/000097 · A001_008 @10 (97):
    /// 000001/000049/000097 · A001_009 @8 (100): 000001/000050/000100.
 /// The mirror placement (the maintainer's corpus layout — ):
    /// `../testdata/originals_A001_00X/` (the spec's path text
 /// `testdata/originals/A001_00X_20260924/` is superseded by the
    /// measured disk layout). Corpus-conditional (skip when the
 /// corpus is absent — the project pattern); on the machine that
    /// carries the corpus the gate MUST run it (RAN-not-skipped).
    #[test]
    fn golden_og2k_encode_structural() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        // (clip dir, input depth, expected 322/323, expected tile
        // count, the 3 sample frames — the spec's R3 rows):
        let cases: [(&str, u16, (u32, u32), u32, [String; 3]); 3] = [
            (
                "A001_007",
                12,
                (252, 336),
                32,
                [
                    "A001_007_20260924_000001.DNG".into(),
                    "A001_007_20260924_000049.DNG".into(),
                    "A001_007_20260924_000097.DNG".into(),
                ],
            ),
            (
                "A001_008",
                10,
                (252, 336),
                32,
                [
                    "A001_008_20260924_000001.DNG".into(),
                    "A001_008_20260924_000049.DNG".into(),
                    "A001_008_20260924_000097.DNG".into(),
                ],
            ),
            (
                "A001_009",
                8,
                (252, 336),
                32,
                [
                    "A001_009_20260924_000001.DNG".into(),
                    "A001_009_20260924_000050.DNG".into(),
                    "A001_009_20260924_000100.DNG".into(),
                ],
            ),
        ];
        for (clip, depth, (want_tw, want_th), want_tiles, names) in cases {
 // The mirror placement (the maintainer's corpus layout — ):
            let dir = format!("../testdata/originals_{clip}");
            let names = names.to_vec();
            if !std::path::Path::new(&format!("{dir}/{}", names[0])).exists() {
                eprintln!("skip: the {clip} OG2K corpus is absent");
                continue;
            }
            let names: Vec<String> = names
                .into_iter()
                .filter(|n| std::path::Path::new(&format!("{dir}/{n}")).exists())
                .collect();
            if names.is_empty() {
                eprintln!("skip: the {clip} OG2K corpus is absent");
                continue;
            }
            for n in &names {
                let bytes = std::fs::read(format!("{dir}/{n}")).unwrap();
                let (input, output, base) = camera_gate_fixture(&format!("golden-og2k-{n}"), n, &bytes);
                let report = process_dir(
                    &input,
                    &output,
                    true, // verify: the encode's own verify surface
                    false,
                    1,
                    Mode::Lossless,
                    false,
                    false, // fast — the 3-candidate adaptive encode (the project selection over the OG2K family)
                    false, // checksums
                    LossyFormat::K34892,
                    &ReferenceDctOpts::default(),
                    None, // --to
                    false, // qc_gate
                )
                .expect("process_dir (the dir plumbing)");
                assert!(
                    matches!(report.outcomes[0], Outcome::Done(_)),
                    "the golden OG2K frame must encode Done: {n}: {:?}",
                    report.outcomes[0]
                );
                let out = std::fs::read(output.join(n)).expect("the encoded output must exist");
                // (a) the structural pin (the measured depth-invariant
                // contract — 252×336 at all three depths):
                let meta = crate::tiff::read_meta(&out)
                    .expect("the encoded output must read_meta (the tile-mode surface)");
                let e = meta.endianness;
                let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
                let t259 = find(259).expect("tag 259 must be present");
                assert_eq!(e.u16(&t259.value_raw), 7, "{n}: Compression 7 (tiled lossless)");
                let t262 = find(262).expect("tag 262 must be present");
                assert_eq!(
                    e.u16(&t262.value_raw),
                    32803,
                    "{n}: PhotometricInterpretation 32803 (CFA)"
                );
                let t258 = find(258).expect("tag 258 must be present");
                assert_eq!(
                    e.u16(&t258.value_raw),
                    depth,
                    "{n}: BitsPerSample = the input depth ({depth} — NO promotion)"
                );
                let t322 = find(322).expect("tag 322 (TileWidth) — the tile plan");
                assert_eq!(
                    e.u32(&t322.value_raw),
                    want_tw,
                    "{n}: 322 = {want_tw} (the depth-invariant OG2K grid)"
                );
                let t323 = find(323).expect("tag 323 (TileLength) — the tile plan");
                assert_eq!(e.u32(&t323.value_raw), want_th, "{n}: 323 = {want_th}");
                let t324 = find(324).expect("tag 324 (TileOffsets) — the tile plan");
                assert_eq!(t324.count, want_tiles, "{n}: 324 = {want_tiles} tile offsets (the OG2K grid)");
                let t325 = find(325).expect("tag 325 (TileByteCounts) — the tile plan");
                assert_eq!(t325.count, want_tiles, "{n}: 325 = {want_tiles} tile byte counts");
                // (b) the decode round-trip pixel-exact vs the original
                // (the golden-decode pattern on the encoded output —
                // the shipped decode path incl. the restore-drill):
                let (dw, dh, decoded) = crate::decode::decode_frame_p1(
                    &crate::decode::FrameRef::J92 {
                        src: output.join(n),
                        name: n.clone(),
                    },
                    std::path::Path::new("."),
                    std::path::Path::new("djxl"),
                    0,
                )
                .unwrap_or_else(|err| panic!("{n}: decode round-trip: {err}"));
                assert_eq!((dw, dh), (2016, 1344), "{n}: the round-trip geometry");
                let frame = crate::tiff::read(&bytes)
                    .unwrap_or_else(|err| panic!("{n}: original parse: {err}"));
                let expected = match depth {
                    12 => crate::pack12::unpack12(frame.strip_slice(&bytes), frame.width, frame.height),
                    10 => crate::pack12::unpack10(frame.strip_slice(&bytes), frame.width, frame.height),
                    _ => crate::pack12::unpack8(frame.strip_slice(&bytes), frame.width, frame.height),
                }
                .unwrap_or_else(|err| panic!("{n}: original unpack: {err}"));
                assert_eq!(
                    decoded, expected,
                    "{n}: the decode round-trip != the original samples (pixel-exact)"
                );
                let _ = std::fs::remove_dir_all(&base);
            }
        }
    }

    /// THE GOLDEN ENCODE TEST — the UHD @10 per-(geometry × depth) grid
 /// (the structural contract, the measured reference contract,
 /// 12-clip batch — the 
 /// onboarding G4, the LAST measured row): encode the mirrored
    /// A001_002 @10 ORIGINAL frames and assert, per frame: (a) encode
    /// SUCCESS + the STRUCTURAL PIN — 322/323 = 964×272 (the measured
    /// @10 grid, 4×8 = 32 tiles — 964×4 = 3856 exact; the last row 266
    /// px at the full 272 geometry), the tile count 32, BitsPerSample =
 /// the input depth 10 (NO promotion — ), Photometric
    /// Interpretation 32803, Compression 7, the tag surface preserved
    /// (the IFD0 count 59 = the 58-entry original − 273/278/279 +
    /// 322/323/324/325; the @10 tag set has NO camera-native 50712 —
 /// the 50712 is the 8-bit class), the strip geometry (the 
    /// record: the original's StripByteCounts = W×H×bps/8 + 12 — the
    /// 10-bit packing's measured +12), the encode's OWN verify ON
    /// (process_dir verify = true: bit_exact_tiled_plane +
    /// metadata_preserved_tiled); (b) the DECODE ROUND-TRIP PIXEL-EXACT
    /// vs the original (the golden-decode pattern on the encoded
    /// output — the shipped decode path incl. the restore-drill, the
    /// grid-keyed legacy family — the 964×272 grid's measured family).
 /// NOT a byte comparison against the corpus (the
    /// corpus = the interop oracle + the benchmark, not a byte spec
    /// — the corpus frames serve the structural cross-check in
    /// the decode golden test). The sample frames (the 3-frame pattern
    /// — first/middle/last): A001_002 @10 (99 frames):
 /// 000001/000050/000099. The mirror placement (the maintainer's corpus
    /// layout): `../testdata/originals_A001_002/`. Corpus-conditional
 /// (skip when the corpus is absent — the project pattern); on the
    /// machine that carries the corpus the gate MUST run it (RAN-not-
    /// skipped).
    #[test]
    fn golden_uhd10_encode_structural() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        // (clip dir, input depth, expected 322/323, expected tile
        // count, expected output IFD0 count, the original's strip
 // geometry Δ (the record: W×H×bps/8 + 12), the 3 sample
        // frames — the spec's R3 row):
        let cases: [(&str, u16, (u32, u32), u32, u16, u64, [String; 3]); 1] = [
            (
                "A001_002",
                10,
                (964, 272),
                32,
                59, // 58 original − 273/278/279 + 322/323/324/325
                12, // the original's StripByteCounts = W×H×bps/8 + 12 (the strip-geometry record)
                [
                    "A001_002_20260924_000001.DNG".into(),
                    "A001_002_20260924_000050.DNG".into(),
                    "A001_002_20260924_000099.DNG".into(),
                ],
            ),
        ];
        for (clip, depth, (want_tw, want_th), want_tiles, want_ifd0, strip_delta, names) in cases {
 // The mirror placement (the maintainer's corpus layout):
            let dir = format!("../testdata/originals_{clip}");
            let names = names.to_vec();
            if !std::path::Path::new(&format!("{dir}/{}", names[0])).exists() {
                eprintln!("skip: the {clip} UHD@10 corpus is absent");
                continue;
            }
            let names: Vec<String> = names
                .into_iter()
                .filter(|n| std::path::Path::new(&format!("{dir}/{n}")).exists())
                .collect();
            if names.is_empty() {
                eprintln!("skip: the {clip} UHD@10 corpus is absent");
                continue;
            }
            for n in &names {
                let bytes = std::fs::read(format!("{dir}/{n}")).unwrap();
                let (input, output, base) = camera_gate_fixture(&format!("golden-uhd10-{n}"), n, &bytes);
                let report = process_dir(
                    &input,
                    &output,
                    true, // verify: the encode's own verify surface (round-trip verify ON)
                    false,
                    1,
                    Mode::Lossless,
                    false,
                    false, // fast — the 3-candidate adaptive encode (the size-min over the 964×272 grid's measured family)
                    false, // checksums
                    LossyFormat::K34892,
                    &ReferenceDctOpts::default(),
                    None, // --to
                    false, // qc_gate
                )
                .expect("process_dir (the dir plumbing)");
                assert!(
                    matches!(report.outcomes[0], Outcome::Done(_)),
                    "the golden UHD@10 frame must encode Done: {n}: {:?}",
                    report.outcomes[0]
                );
 // The strip geometry on the original (the record —
                // the 10-bit packing's measured +12):
                let orig_frame = crate::tiff::read(&bytes)
                    .unwrap_or_else(|err| panic!("{n}: original parse: {err}"));
                let want_strip = orig_frame.width as u64 * orig_frame.height as u64 * orig_frame.bits_per_sample as u64 / 8
                    + strip_delta;
                assert_eq!(
                    orig_frame.strip_count,
                    want_strip,
                    "{n}: the original's StripByteCounts (the strip geometry Δ=+{strip_delta} — the measured record)"
                );
                let out = std::fs::read(output.join(n)).expect("the encoded output must exist");
                // (a) the structural pin (the measured @10 contract):
                let meta = crate::tiff::read_meta(&out)
                    .expect("the encoded output must read_meta (the tile-mode surface)");
                let e = meta.endianness;
                let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
                let t259 = find(259).expect("tag 259 must be present");
                assert_eq!(e.u16(&t259.value_raw), 7, "{n}: Compression 7 (tiled lossless)");
                let t262 = find(262).expect("tag 262 must be present");
                assert_eq!(
                    e.u16(&t262.value_raw),
                    32803,
                    "{n}: PhotometricInterpretation 32803 (CFA)"
                );
                let t258 = find(258).expect("tag 258 must be present");
                assert_eq!(
                    e.u16(&t258.value_raw),
                    depth,
                    "{n}: BitsPerSample = the input depth ({depth} — NO promotion)"
                );
                let t322 = find(322).expect("tag 322 (TileWidth) — the tile plan");
                assert_eq!(
                    e.u32(&t322.value_raw),
                    want_tw,
                    "{n}: 322 = {want_tw} (the measured @10 UHD grid)"
                );
                let t323 = find(323).expect("tag 323 (TileLength) — the tile plan");
                assert_eq!(e.u32(&t323.value_raw), want_th, "{n}: 323 = {want_th}");
                let t324 = find(324).expect("tag 324 (TileOffsets) — the tile plan");
                assert_eq!(t324.count, want_tiles, "{n}: 324 = {want_tiles} tile offsets (the 4×8 grid)");
                let t325 = find(325).expect("tag 325 (TileByteCounts) — the tile plan");
                assert_eq!(t325.count, want_tiles, "{n}: 325 = {want_tiles} tile byte counts");
                // The tag surface preserved (the IFD0 count + the NO
                // camera-native 50712 on the @10 tag set — the 50712
                // is the 8-bit class):
                assert_eq!(
                    meta.ifd0.entries.len() as u16,
                    want_ifd0,
                    "{n}: the output IFD0 count (the tag surface preserved)"
                );
                assert!(
                    find(50712).is_none(),
                    "{n}: the @10 tag set has no camera-native 50712 (the 50712 is the 8-bit class)"
                );
                // (b) the decode round-trip pixel-exact vs the original
                // (the golden-decode pattern on the encoded output —
                // the shipped decode path incl. the restore-drill):
                let (dw, dh, decoded) = crate::decode::decode_frame_p1(
                    &crate::decode::FrameRef::J92 {
                        src: output.join(n),
                        name: n.clone(),
                    },
                    std::path::Path::new("."),
                    std::path::Path::new("djxl"),
                    0,
                )
                .unwrap_or_else(|err| panic!("{n}: decode round-trip: {err}"));
                assert_eq!((dw, dh), (3856, 2170), "{n}: the round-trip geometry");
                let expected = crate::pack12::unpack10(orig_frame.strip_slice(&bytes), orig_frame.width, orig_frame.height)
                    .unwrap_or_else(|err| panic!("{n}: original unpack10: {err}"));
                assert_eq!(
                    decoded, expected,
                    "{n}: the decode round-trip != the original samples (pixel-exact)"
                );
                let _ = std::fs::remove_dir_all(&base);
            }
        }
    }

 /// PARITY (the measured reference contract, — the
 /// 12-clip batch, the onboarding G3): the OG3K
    /// (Open Gate 3K) goldens encode at the MEASURED per-gate grid
    /// (252×252 at all three depths — the measured depth-invariance,
 /// a clean 12×8 = 96-tile grid — the machinery: the
    /// legacy 482×272 family {W-PSV7, W-PSV2, N-PSV1} grid-keyed on
    /// 252×252, the measured selection key = the hist-pass's
    /// pre-stuffing expected bit count), the 3-candidate adaptive
    /// encode, the NO-PROMOTION @8 (BPS8 out; the measured
    /// 8→10 identity promotion NOT replicated). Per frame: (a) the
    /// structural pin (322/323 = 252×252, 96 tiles, BPS = the input
    /// depth — NO promotion, Photometric 32803, Compression 7, the
    /// tag surface preserved — the IFD0 count + the 50712
    /// camera-native on the @8 (the 50712-carrying tag set selects the
    /// 60-entry 3K re-layout variant), the strip geometry Δ=+0 on the
    /// original); (b) the DECODE ROUND-TRIP PIXEL-EXACT vs the
    /// original (the golden-decode pattern on the encoded output — the
    /// shipped decode path incl. the restore-drill, the 3K family
    /// grid-keyed). NOT a byte comparison against the corpus
 /// (the corpus = the interop oracle + the benchmark,
    /// not a byte spec — the corpus frames serve the
    /// structural cross-check in the decode golden test). The sample
    /// frames (the 3-frame pattern — first/middle/last): A001_011 @10
    /// (99 frames): 000001/000050/000099 · A001_012 @8 (97 frames):
 /// 000001/000049/000097. The mirror placement (the maintainer's corpus
    /// layout): `../testdata/originals_A001_011/` +
    /// `../testdata/originals_A001_012/`. Corpus-conditional (skip
 /// when the corpus is absent — the project pattern); on the machine
    /// that carries the corpus the gate MUST run it (RAN-not-skipped).
    #[test]
    fn golden_og3k_encode_structural() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        // (clip dir, input depth, expected 322/323, expected tile
        // count, expected output IFD0 count, the 50712 camera-native
        // (present ONLY on the @8 tag set), the 3 sample frames — the
        // spec's R3 rows):
        let cases: [(&str, u16, (u32, u32), u32, u16, bool, [String; 3]); 2] = [
            (
                "A001_011",
                10,
                (252, 252),
                96,
                59, // 58 original − 273/278/279 + 322/323/324/325
                false,
                [
                    "A001_011_20260924_000001.DNG".into(),
                    "A001_011_20260924_000050.DNG".into(),
                    "A001_011_20260924_000099.DNG".into(),
                ],
            ),
            (
                "A001_012",
                8,
                (252, 252),
                96,
                60, // 59 original (the 50712 camera-native) − 3 + 4
                true,
                [
                    "A001_012_20260924_000001.DNG".into(),
                    "A001_012_20260924_000049.DNG".into(),
                    "A001_012_20260924_000097.DNG".into(),
                ],
            ),
        ];
        for (clip, depth, (want_tw, want_th), want_tiles, want_ifd0, has_50712, names) in cases {
 // The mirror placement (the maintainer's corpus layout):
            let dir = format!("../testdata/originals_{clip}");
            let names = names.to_vec();
            if !std::path::Path::new(&format!("{dir}/{}", names[0])).exists() {
                eprintln!("skip: the {clip} OG3K corpus is absent");
                continue;
            }
            let names: Vec<String> = names
                .into_iter()
                .filter(|n| std::path::Path::new(&format!("{dir}/{n}")).exists())
                .collect();
            if names.is_empty() {
                eprintln!("skip: the {clip} OG3K corpus is absent");
                continue;
            }
            for n in &names {
                let bytes = std::fs::read(format!("{dir}/{n}")).unwrap();
                let (input, output, base) = camera_gate_fixture(&format!("golden-og3k-{n}"), n, &bytes);
                let report = process_dir(
                    &input,
                    &output,
                    true, // verify: the encode's own verify surface
                    false,
                    1,
                    Mode::Lossless,
                    false,
                    false, // fast — the 3-candidate adaptive encode (the measured 3K selection key)
                    false, // checksums
                    LossyFormat::K34892,
                    &ReferenceDctOpts::default(),
                    None, // --to
                    false, // qc_gate
                )
                .expect("process_dir (the dir plumbing)");
                assert!(
                    matches!(report.outcomes[0], Outcome::Done(_)),
                    "the golden OG3K frame must encode Done: {n}: {:?}",
                    report.outcomes[0]
                );
                // The strip geometry on the original (the measured
                // input contract: StripByteCounts = W×H×bps/8 —
                // Δ = +0):
                let orig_frame = crate::tiff::read(&bytes)
                    .unwrap_or_else(|err| panic!("{n}: original parse: {err}"));
                let want_strip =
                    orig_frame.width as u64 * orig_frame.height as u64 * orig_frame.bits_per_sample as u64 / 8;
                assert_eq!(
                    orig_frame.strip_count,
                    want_strip,
                    "{n}: the original's StripByteCounts (the strip geometry Δ=+0)"
                );
                let out = std::fs::read(output.join(n)).expect("the encoded output must exist");
                // (a) the structural pin (the measured depth-invariant
                // contract — 252×252 at all depths):
                let meta = crate::tiff::read_meta(&out)
                    .expect("the encoded output must read_meta (the tile-mode surface)");
                let e = meta.endianness;
                let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
                let t259 = find(259).expect("tag 259 must be present");
                assert_eq!(e.u16(&t259.value_raw), 7, "{n}: Compression 7 (tiled lossless)");
                let t262 = find(262).expect("tag 262 must be present");
                assert_eq!(
                    e.u16(&t262.value_raw),
                    32803,
                    "{n}: PhotometricInterpretation 32803 (CFA)"
                );
                let t258 = find(258).expect("tag 258 must be present");
                assert_eq!(
                    e.u16(&t258.value_raw),
                    depth,
                    "{n}: BitsPerSample = the input depth ({depth} — NO promotion)"
                );
                let t322 = find(322).expect("tag 322 (TileWidth) — the tile plan");
                assert_eq!(
                    e.u32(&t322.value_raw),
                    want_tw,
                    "{n}: 322 = {want_tw} (the depth-invariant OG3K grid)"
                );
                let t323 = find(323).expect("tag 323 (TileLength) — the tile plan");
                assert_eq!(e.u32(&t323.value_raw), want_th, "{n}: 323 = {want_th}");
                let t324 = find(324).expect("tag 324 (TileOffsets) — the tile plan");
                assert_eq!(t324.count, want_tiles, "{n}: 324 = {want_tiles} tile offsets (the 12×8 grid)");
                let t325 = find(325).expect("tag 325 (TileByteCounts) — the tile plan");
                assert_eq!(t325.count, want_tiles, "{n}: 325 = {want_tiles} tile byte counts");
                // The tag surface preserved (the IFD0 count + the
                // 50712 camera-native on the @8 — the 50712-carrying
                // tag set selects the 60-entry 3K re-layout variant):
                assert_eq!(
                    meta.ifd0.entries.len() as u16,
                    want_ifd0,
                    "{n}: the output IFD0 count (the tag surface preserved)"
                );
                if has_50712 {
                    let t50712 = find(50712)
                        .expect("tag 50712 (the camera-native LinearizationTable — the @8 tag set)");
                    assert!(
                        t50712.out_of_line.is_some(),
                        "{n}: the 50712 is out-of-line (the 512 B LinearizationTable)"
                    );
                }
                // (b) the decode round-trip pixel-exact vs the original
                // (the golden-decode pattern on the encoded output —
                // the shipped decode path incl. the restore-drill):
                let (dw, dh, decoded) = crate::decode::decode_frame_p1(
                    &crate::decode::FrameRef::J92 {
                        src: output.join(n),
                        name: n.clone(),
                    },
                    std::path::Path::new("."),
                    std::path::Path::new("djxl"),
                    0,
                )
                .unwrap_or_else(|err| panic!("{n}: decode round-trip: {err}"));
                assert_eq!((dw, dh), (3024, 2010), "{n}: the round-trip geometry");
                let expected = match depth {
                    10 => crate::pack12::unpack10(
                        orig_frame.strip_slice(&bytes),
                        orig_frame.width,
                        orig_frame.height,
                    ),
                    _ => crate::pack12::unpack8(
                        orig_frame.strip_slice(&bytes),
                        orig_frame.width,
                        orig_frame.height,
                    ),
                }
                .unwrap_or_else(|err| panic!("{n}: original unpack: {err}"));
                assert_eq!(
                    decoded, expected,
                    "{n}: the decode round-trip != the original samples (pixel-exact)"
                );
                let _ = std::fs::remove_dir_all(&base);
            }
        }
    }

 /// (the named test — the loud-refusal
    /// pin): a frame whose MEASURED TAG SET matches NEITHER 3K variant
    /// (an out-of-template out-of-line tag planted on the mirrored
 /// OG3K originals — the planted-field pattern) is refused
    /// LOUD with the verbatim named refusal BEFORE any write (no
    /// panic, no partial output — the refusal never writes, the
 /// hard-stop pattern). Both variants are pinned: the
    /// 50712-less tag set (the A001_011 @10 original → the default
    /// variant) and the 50712-carrying tag set (the A001_012 @8
    /// original → the 50712 variant). Corpus-conditional (skip when
 /// the corpus is absent — the project pattern).
    #[test]
    fn d103_1_planted_out_of_template_tag_loud_refusal() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        // (clip, the selected variant's name, the one original):
        let cases: [(&str, &str, &str); 2] = [
            ("A001_011", "default", "A001_011_20260924_000001.DNG"),
            ("A001_012", "50712", "A001_012_20260924_000001.DNG"),
        ];
        for (clip, variant, n) in cases {
            let p = format!("../testdata/originals_{clip}/{n}");
            if !std::path::Path::new(&p).exists() {
                eprintln!("skip: {p} (absent)");
                return;
            }
            let bytes = std::fs::read(&p).unwrap();
            let mut frame = crate::tiff::read(&bytes)
                .unwrap_or_else(|err| panic!("{n}: original parse: {err}"));
            // The planted tag: an out-of-line entry outside BOTH 3K
            // variants' region maps (50723 — a real DNG tag, absent
            // from both measured tag sets), at its tag-sorted position
 // (the TableNotSorted guard must not preempt the 
            // refusal).
            let pos = frame
                .ifd0
                .entries
                .iter()
                .position(|en| en.tag > 50723)
                .unwrap_or(frame.ifd0.entries.len());
            frame.ifd0.entries.insert(
                pos,
                crate::tiff::IfdEntry {
                    tag: 50723,
                    typ: 3, // SHORT
                    count: 100, // 200 B — the out-of-line layout
                    value_raw: [0x00, 0x34, 0x13, 0x00], // the pointer (LE)
                    out_of_line: Some((0x13400, 0x134c8)),
                },
            );
            // 96 placeholder tiles (the tile-count guard passes; the
            // refusal must land at the tag-set guard — before any
            // write).
            let tiles: Vec<Vec<u8>> = vec![vec![0u8; 100]; 96];
            let res = crate::surgery::apply_tiled_3k(&bytes, &frame, &tiles);
            let err = match res {
                Err(e) => e,
                Ok(_) => panic!("{n}: the planted tag set must be refused (no output)"),
            };
 // The verbatim pinned refusal (the named wording
            // — the variant is named):
            assert_eq!(
                err.to_string(),
                format!(
                    "tag 50723 (0xC623) is not in the 3K template's region map for the frame's measured tag set (the {variant} variant); the measured template covers the A001 OG3K tag sets only (loud by design — the named refusal, never a mis-layout)"
                ),
                "{n}: the pinned refusal wording"
            );
            // The refusal never writes: the Err path precedes the
            // output allocation (the function is pure — no partial
            // output exists).
        }
    }

    // =================================================================
 // The FHD mode rows ( — measured
    // contract): the 1936×1090 gate's measured log10 + downscale2x
    // rows at @12/@10/@8. Corpus (the G2/G3/G4 corpus-noting pattern —
    // the mode corpus is date-suffix-free): the originals
    // `../testdata/originals_A001_00X/` (A001_004 @12 97 frames ·
    // A001_005 @10 97 · A001_006 @8 101 — the 3-frame sample pattern
    // first/middle/last: 000001/000049/000097 · 000001/000051/000101).
    // =================================================================

    /// An IFD entry's value bytes (in-line ≤ 4 B or out-of-line by the
    /// pointer range — the golden tests' value cross-check seam).
    fn ifd_value(buf: &[u8], e: crate::tiff::Endian, en: &crate::tiff::IfdEntry) -> Vec<u8> {
        let tsz = match en.typ {
            1 | 2 | 7 | 11 => 1,
            3 | 8 => 2,
            4 | 9 | 12 => 4,
            _ => 1,
        };
        let sz = tsz * en.count as usize;
        if sz <= 4 {
            en.value_raw[..tsz * en.count as usize].to_vec()
        } else {
            let (p, end) = en
                .out_of_line
                .expect("the out-of-line entry must have a pointer");
            buf[p as usize..end as usize].to_vec()
        }
    }

    /// The mode encode goldens' shared machinery (the per-row named
 /// gates wrap this — rows, ):
    /// encodes the 3 mirrored ORIGINAL frames of the gate's corpus
 /// (`../testdata/originals_A001_00X/`) through the work binary's
    /// encode path (process_dir, verify ON — the per-arm measured
    /// content + metadata gate runs inside the encode) and asserts the
 /// per-row structural pin (the structural contract — the
    /// geometry · the per-arm stored BPS · Compression 7 ·
    /// Photometric 32803 · the tag surface [the IFD0 count = the source
 /// count + the per-row expected-diff delta — the measured
 /// formula] · the 50712 mechanics per [absent / the 1024 LUT /
    /// the carried native 256 — the @8 arm: the value CARRIED verbatim
    /// from the source] · the per-depth grid + tile count · [ds2x: the
    /// 51089-91 proxy tags — the tool's own ds2x design] · the round-
    /// trip verify ON [the shipped decode path incl. the restore-drill
    /// — the per-gate family; the ds2x rows: the odd-height content-
    /// rows drill on the 271-content-row bottom-row tiles (the FHD
 /// ds2x geometry) — the decision (b); the OG2K ds2x
 /// geometry runs the plain full-tile semantics — the 
    /// no-half-row verdict]). Returns per frame the (name, the
    /// encoded output bytes, the decoded round-trip samples, the
    /// original unpacked samples) for the caller's per-row content-class
    /// assertion (the measured rows: the @12 log10 codes / the raw
    /// passthrough / the identity promotion / the tool's own decimation
    /// plane). Corpus-conditional (skip when the corpus is absent — the
 /// project pattern); on the machine that carries the corpus the gate
    /// MUST run it (RAN-not-skipped).
    fn golden_mode_encode_row(
        tag: &str,
        clip: &str,
        depth: u16,
        mode: Mode,
        downscale: bool,
        want_geom: (u32, u32),
        want_bps: u16,
        want_grid: (u32, u32),
        want_tiles: u32,
        want_lut: Option<u32>,
        want_ifd0_delta: i64,
        names: [String; 3],
    ) -> Vec<(String, Vec<u8>, Vec<u16>, Vec<u16>)> {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        let dir = format!("../testdata/originals_{clip}");
        let mut out: Vec<(String, Vec<u8>, Vec<u16>, Vec<u16>)> = Vec::new();
        for n in names.iter() {
            let p = format!("{dir}/{n}");
            if !std::path::Path::new(&p).exists() {
                eprintln!("skip: the {clip} mode corpus is absent ({p})");
                return Vec::new();
            }
            let bytes = std::fs::read(&p).unwrap();
            let (input, output, base) =
                camera_gate_fixture(&format!("mode-{tag}-{n}"), n, &bytes);
            let report = process_dir(
                &input,
                &output,
                true, // verify: the per-arm measured content + metadata gates
                false,
                1,
                mode,
                downscale,
                false, // fast — the adaptive project selection over the per-gate family
                false, // checksums
                LossyFormat::K34892,
                &ReferenceDctOpts::default(),
                None, // --to
                false, // qc_gate
            )
            .expect("process_dir (the dir plumbing)");
            assert!(
                matches!(report.outcomes[0], Outcome::Done(_)),
                "the {tag} golden frame must encode Done: {n}: {:?}",
                report.outcomes[0]
            );
            let outb =
                std::fs::read(output.join(n)).expect("the encoded output must exist");
            // The structural pin (the measured per-arm contract):
            let meta = crate::tiff::read_meta(&outb)
                .expect("the encoded output must read_meta (the tile-mode surface)");
            let e = meta.endianness;
            let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
            let tag32 = |tag: u16| e.u32(&find(tag).expect("tag present").value_raw);
            let tag16 = |tag: u16| e.u16(&find(tag).expect("tag present").value_raw);
            assert_eq!((tag32(256), tag32(257)), want_geom, "{n}: the output geometry");
            assert_eq!(tag16(259), 7, "{n}: Compression 7 (tiled)");
            assert_eq!(tag16(262), 32803, "{n}: PhotometricInterpretation 32803 (CFA)");
            assert_eq!(tag16(258), want_bps, "{n}: the per-arm stored BPS");
            assert_eq!((tag32(322), tag32(323)), want_grid, "{n}: the per-depth grid");
            assert_eq!(
                find(324).unwrap().count,
                want_tiles,
                "{n}: the tile count (324)"
            );
            assert_eq!(
                find(325).unwrap().count,
                want_tiles,
                "{n}: the tile byte counts (325)"
            );
 // The 50712 mechanics (the measured per-arm contract):
            // None = ABSENT; Some(count) = PRESENT at the measured count.
            // The @8 arm (the source carries the camera-native 256-entry
 // table): the value is CARRIED verbatim (the measured
            // byte-identity across all 9 @8 files — the carry, not a
            // duplicate: the surgery never adds a second 50712).
            let src_meta = crate::tiff::read_meta(&bytes).expect("the source must read_meta");
            match want_lut {
                None => {
                    assert!(
                        find(50712).is_none(),
                        "{n}: 50712 must be ABSENT (the measured {tag} row)"
                    );
                }
                Some(cnt) => {
                    let t = find(50712)
                        .unwrap_or_else(|| panic!("{n}: 50712 must be present (count {cnt})"));
                    assert_eq!(t.count, cnt, "{n}: 50712 count (the measured {tag} row)");
                    if let (Some(st), Some(_)) = (
                        src_meta
                            .ifd0
                            .entries
                            .iter()
                            .find(|x| x.tag == 50712),
                        find(50712).and_then(|t| t.out_of_line),
                    ) {
                        let gotv = ifd_value(&outb, e, t);
                        let srcv = ifd_value(&bytes, src_meta.endianness, st);
                        assert_eq!(gotv, srcv, "{n}: 50712 CARRIED verbatim (the @8 identity)");
                    }
                }
            }
            // The tag surface (the IFD0 count = the source count + the
 // per-row expected-diff delta — the measured formula):
            assert_eq!(
                meta.ifd0.entries.len() as i64,
                src_meta.ifd0.entries.len() as i64 + want_ifd0_delta,
                "{n}: the IFD0 tag-surface count (source + the {tag} expected-diff delta)"
            );
            // [ds2x] the proxy geometry (the tool's own ds2x design —
            // the reference omits the 51089-91 tags; the tool's design
 // ADDS them — the free header packing):
            if downscale {
                for tag in [51089u16, 51090, 51091] {
                    assert!(
                        find(tag).is_some(),
                        "{n}: the {tag} proxy tag (the tool's own ds2x design)"
                    );
                }
            }
            // The decode round-trip (the shipped decode path incl. the
            // restore-drill — the per-gate family; the ds2x rows run
            // the odd-height content-rows drill on the 271-content-row
 // bottom-row tiles — the decision (b)):
            let (dw, dh, decoded) = crate::decode::decode_frame_p1(
                &crate::decode::FrameRef::J92 {
                    src: output.join(n),
                    name: n.clone(),
                },
                std::path::Path::new("."),
                std::path::Path::new("djxl"),
                0,
            )
            .unwrap_or_else(|err| panic!("{n}: decode round-trip: {err}"));
            assert_eq!((dw, dh), want_geom, "{n}: the round-trip geometry");
            let frame = crate::tiff::read(&bytes)
                .unwrap_or_else(|err| panic!("{n}: original parse: {err}"));
            let expected = match depth {
                12 => crate::pack12::unpack12(frame.strip_slice(&bytes), frame.width, frame.height),
                10 => crate::pack12::unpack10(frame.strip_slice(&bytes), frame.width, frame.height),
                _ => crate::pack12::unpack8(frame.strip_slice(&bytes), frame.width, frame.height),
            }
            .unwrap_or_else(|err| panic!("{n}: original unpack: {err}"));
            out.push((n.clone(), outb, decoded, expected));
            let _ = std::fs::remove_dir_all(&base);
        }
        out
    }

 /// THE GOLDEN ENCODE TEST — the FHD log10 @12 row (the 
 /// measured contract): the 1936×1090 @12 log10 row — the
    /// 10-bit log codes on the measured 242×274 grid (32 tiles), the
    /// 258 12→10 BPS split, the 50712 1024 LUT ADD (the tool's own
 /// embedded A001 LUT — the measured LUT decision: the measured
 /// per-frame table is the calibration payload, the free
    /// class — the structural pin = presence + count, NOT the table
 /// content), the FHD family {W7, W6, N5} (the census 32/32,
    /// ZERO 0 · MULTI 0). Content class = the quantized code plane (the
    /// round-trip = the LUT codes — the ≤1-LSB residual vs the
 /// reference's own per-frame LUT is the measured interop
    /// boundary, NOT a contract). Corpus
    /// `../testdata/originals_A001_004/` (3 frames).
    #[test]
    fn golden_fhd_log10_12_encode_structural() {
        let rows = golden_mode_encode_row(
            "log10-12",
            "A001_004",
            12,
            Mode::Log10,
            false,
            (1936, 1090),
            10,
            (242, 274),
            32,
            Some(1024),
            2, // 58 − 3 strip + 4 tile + 1 LUT = 60 (the measured formula)
            [
                "A001_004_20260924_000001.DNG".into(),
                "A001_004_20260924_000049.DNG".into(),
                "A001_004_20260924_000097.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        let inv = crate::log10::inv();
        for (n, _out, decoded, orig) in rows {
            // The content class: the 10-bit log codes (12-bit → codes
            // via the built-in LUT's inverse — the round-trip = the
 // code plane, NOT the raw samples — the interop
            // boundary, the quantization).
            let expected_codes: Vec<u16> = orig.iter().map(|v| inv[*v as usize]).collect();
            assert_eq!(
                decoded, expected_codes,
                "{n}: the round-trip = the log10 code plane (the @12 content class)"
            );
        }
    }

 /// THE GOLDEN ENCODE TEST — the FHD log10 @10 row (the 
 /// measured contract): the 1936×1090 @10 log10 row — the
    /// RAW 10-BIT PASSTHROUGH (the measured maxdiff 0 vs the raw
    /// samples — the mode's container stores the raw samples) on the
    /// measured 484×274 grid (16 tiles), 258 unchanged (10), NO 50712
    /// (the measured ABSENT). Content class = the raw samples
 /// (content-identical to the FHD lossless @10 plane — the 
    /// verdict; pinned BYTE-IDENTICAL: the same plane / grid / family
    /// + the field-equal per-arm plan [bps_patch None, lut None,
    /// tile_dims (484,274)]). Corpus `../testdata/originals_A001_005/`
    /// (3 frames).
    #[test]
    fn golden_fhd_log10_10_encode_structural() {
        let names: [String; 3] = [
            "A001_005_20260924_000001.DNG".into(),
            "A001_005_20260924_000049.DNG".into(),
            "A001_005_20260924_000097.DNG".into(),
        ];
        let rows = golden_mode_encode_row(
            "log10-10",
            "A001_005",
            10,
            Mode::Log10,
            false,
            (1936, 1090),
            10,
            (484, 274),
            16,
            None, // the measured ABSENT (no 50712)
            1, // 58 − 3 strip + 4 tile = 59 (the measured formula)
            names,
        );
        if rows.is_empty() {
            return;
        }
        for (n, _out, decoded, orig) in &rows {
            // The content class: the RAW 10-bit passthrough (the
            // measured maxdiff 0 vs the raw samples).
            assert_eq!(
                decoded, orig,
                "{n}: the round-trip = the raw 10-bit samples (the @10 raw-passthrough content class)"
            );
        }
 // The measured content identity (the verdict): the log10
        // @10 output = the lossless @10 output BYTE-IDENTICAL (the
        // same plane / grid / family; the per-arm plans are field-
        // equal: bps_patch None + lut None + tile_dims (484,274)).
        let dir = "../testdata/originals_A001_005";
        for (n, log10_out, _decoded, _orig) in &rows {
            let bytes = std::fs::read(format!("{dir}/{n}")).unwrap();
            let (input, output, base) =
                camera_gate_fixture(&format!("mode-log10-10-lossless-{n}"), n, &bytes);
            let report = process_dir(
                &input,
                &output,
                true,
                false,
                1,
                Mode::Lossless, // the lossless @10 control (the native-depth path)
                false,
                false,
                false,
                LossyFormat::K34892,
                &ReferenceDctOpts::default(),
                None,
                false,
            )
            .expect("process_dir (the lossless @10 control)");
            assert!(
                matches!(report.outcomes[0], Outcome::Done(_)),
                "the lossless @10 control must encode Done: {n}: {:?}",
                report.outcomes[0]
            );
            let lossless_out =
                std::fs::read(output.join(n)).expect("the lossless @10 output must exist");
            assert_eq!(
                *log10_out, lossless_out,
                "{n}: the log10 @10 output != the lossless @10 output (the measured content identity — byte-identical)"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
    }

 /// THE GOLDEN ENCODE TEST — the FHD log10 @8 row (the 
 /// measured contract): the 1936×1090 @8 log10 row — the
    /// 8-bit samples IDENTITY-promoted into the measured BPS10
    /// container (258 8→10 — the mode tier's BPS split; the lossless
 /// tier's no-promotion decision is scoped to the lossless tier) on
    /// the measured 242×274 grid (32 tiles); the camera-native 256-
 /// entry 50712 CARRIED VERBATIM (the tag-set-variant
    /// pattern — the surgery carries it, never duplicates it: a second
    /// 50712 = the measured gap the carry semantics close). Content
    /// class = the raw 8-bit samples (the measured maxdiff 0; the ×4-
    /// scaled hypothesis measured REJECTED — maxdiff 765). Corpus
    /// `../testdata/originals_A001_006/` (3 frames).
    #[test]
    fn golden_fhd_log10_8_encode_structural() {
        let rows = golden_mode_encode_row(
            "log10-8",
            "A001_006",
            8,
            Mode::Log10,
            false,
            (1936, 1090),
            10, // the identity promotion (258 8→10)
            (242, 274),
            32,
            Some(256), // the camera-native table CARRIED (the helper pins the verbatim value)
            1, // 59 − 3 strip + 4 tile = 60 (the measured formula)
            [
                "A001_006_20260924_000001.DNG".into(),
                "A001_006_20260924_000051.DNG".into(),
                "A001_006_20260924_000101.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, _out, decoded, orig) in rows {
            // The content class: the 8-bit samples identity-promoted
            // (the values unchanged, zero-extended into the BPS10
            // container — the measured maxdiff 0 vs the raw samples).
            assert_eq!(
                decoded, orig,
                "{n}: the round-trip = the 8-bit samples (the @8 identity-promotion content class)"
            );
        }
    }

 /// THE GOLDEN ENCODE TEST — the FHD ds2x @12 row (the 
 /// measured contract): the 968×545 @12 downscale2x row —
    /// the 2×-decimated plane (the tool's own staircase decimation —
    /// the measured decimation is the interop boundary, the
 /// measured δ decision: the tool keeps its own staircase) on the
    /// measured 242×274 grid (4×2 = 8 tiles; the bottom-row tiles =
    /// the 271-content-row half-row tiles on the 274-row plane — the
    /// odd-height interop shape), 258 unchanged (12), the grid×mode-
 /// keyed 2-member DS2X family {W6, N5} (the decision (c)
    /// — W7 never observed, the superset rejected), the 51089-91
    /// proxy tags (the tool's own ds2x design — the reference omits
 /// them, the free class). Content class = the tool's own
    /// decimation plane (bit-exact by construction). Corpus
    /// `../testdata/originals_A001_004/` (3 frames).
    #[test]
    fn golden_fhd_ds2x_12_encode_structural() {
        ds2x_encode_row_content("ds2x-12", "A001_004", 12, (968, 545), 12, (242, 274), 8, [
            "A001_004_20260924_000001.DNG".into(),
            "A001_004_20260924_000049.DNG".into(),
            "A001_004_20260924_000097.DNG".into(),
        ]);
    }

 /// THE GOLDEN ENCODE TEST — the FHD ds2x @10 row (the 
 /// measured contract): the 968×545 @10 downscale2x row —
    /// the measured 484×274 grid (2×2 = 4 tiles), 258 unchanged (10),
    /// the 2-member DS2X family {W6, N5}. Content class = the tool's
    /// own decimation plane. Corpus
    /// `../testdata/originals_A001_005/` (3 frames).
    #[test]
    fn golden_fhd_ds2x_10_encode_structural() {
        ds2x_encode_row_content("ds2x-10", "A001_005", 10, (968, 545), 10, (484, 274), 4, [
            "A001_005_20260924_000001.DNG".into(),
            "A001_005_20260924_000049.DNG".into(),
            "A001_005_20260924_000097.DNG".into(),
        ]);
    }

 /// THE GOLDEN ENCODE TEST — the FHD ds2x @8 row (the 
 /// measured contract): the 968×545 @8 downscale2x row —
    /// the measured 242×274 grid (4×2 = 8 tiles), the 258 8→10
    /// identity promotion (the mode tier's BPS split), the camera-
    /// native 256-entry 50712 CARRIED VERBATIM, the 2-member DS2X
    /// family {W6, N5}. Content class = the tool's own decimation
    /// plane (the 8-bit values zero-extended into the BPS10
    /// container). Corpus `../testdata/originals_A001_006/` (3
    /// frames).
    #[test]
    fn golden_fhd_ds2x_8_encode_structural() {
        ds2x_encode_row_content("ds2x-8", "A001_006", 8, (968, 545), 10, (242, 274), 8, [
            "A001_006_20260924_000001.DNG".into(),
            "A001_006_20260924_000051.DNG".into(),
            "A001_006_20260924_000101.DNG".into(),
        ]);
    }

    /// The ds2x rows' encode golden seam (the per-row named gates
    /// above wrap this): the shared structural pin (the geometry
    /// 968×545 · the per-arm stored BPS · the per-depth grid + tile
    /// count · the 51089-91 proxy tags · the 50712 mechanics [absent
    /// @12/@10, the carried native 256 @8] · the tag surface) via the
    /// shared machinery + the per-row content-class assertion: the
    /// decode round-trip = the tool's own staircase decimation plane
    /// (bit-exact by construction — the measured decimation is the
 /// interop boundary, the measured δ decision: the tool keeps its
    /// own staircase; the interop acceptance = the decode of the
    /// reference's files, NEVER a decimation byte-parity assertion).
    fn ds2x_encode_row_content(
        tag: &str,
        clip: &str,
        depth: u16,
        want_geom: (u32, u32),
        want_bps: u16,
        want_grid: (u32, u32),
        want_tiles: u32,
        names: [String; 3],
    ) {
        let rows = golden_mode_encode_row(
            tag,
            clip,
            depth,
            Mode::Lossless,
            true, // --downscale2x
            want_geom,
            want_bps,
            want_grid,
            want_tiles,
            if depth == 8 { Some(256) } else { None }, // the @8 arm: the carried native 256
            4, // 58 − 3 strip + 4 tile + 3 proxy = 62 (the @8 row: 59 → 63 — the measured formula)
            names,
        );
        if rows.is_empty() {
            return;
        }
        for (n, _out, decoded, orig) in rows {
            // The content class: the tool's own staircase decimation
            // plane (the deterministic decimation of the unpacked
            // original — bit-exact by construction; the rule is the
            // frame's CFA-tag-derived decimation rule — the same pure
            // tag read the encode path uses).
            let dir = format!("../testdata/originals_{clip}");
            let bytes = std::fs::read(format!("{dir}/{n}")).unwrap();
            let frame = crate::tiff::read(&bytes)
                .unwrap_or_else(|err| panic!("{n}: original parse: {err}"));
            let rule = crate::downscale::decimation_rule(&bytes, &frame);
            let (expected, ew, eh) =
                crate::downscale::decimate2x(&orig, frame.width, frame.height, rule);
            assert_eq!((ew, eh), want_geom, "{n}: the decimated geometry");
            assert_eq!(
                decoded, expected,
                "{n}: the round-trip = the tool's own decimation plane (the ds2x {tag} content class)"
            );
        }
    }

 /// FHD MODE grid geometry — the log10 mode rows (the 
 /// measured contract — one integration table test per mode,
    /// the G4 pattern): the log10 mode's measured grid / BPS / 50712
    /// mechanics per depth arm, asserted on the routing machinery (the
    /// per-depth grid via `gate_tile_dims_depth` + `Grid::for_depth`
    /// — the mode's grid = the per-depth lossless grid; the family =
    /// the grid-keyed FHD family; the per-arm `TilePlan::log10_gate`
    /// plans: @12 = the 1024 LUT ADD + 258 12→10; @10 = the raw
    /// passthrough (no BPS patch, no LUT); @8 = the identity promotion
    /// (258 8→10, the native 256-entry 50712 CARRIED — `lut: None`).
    /// The UHD @12 arm = byte-identical to the historical
 /// `TilePlan::log10` (the named mode control — the byte-invariance).
    /// LIVES IN THE WORKER TESTS (not tileenc.rs) so the commit's
    /// touch-set stays within the fence list (the G4 pattern).
    #[test]
    fn fhd_log10_grid_geometry() {
        use crate::tileenc::{gate_candidates_for_grid, gate_tile_dims_depth, Grid, FHD_CANDIDATES};
        // The per-depth grids (the mode's grid = the per-depth lossless
        // grid — the measured contract):
        assert_eq!(gate_tile_dims_depth(1936, 1090, 12), (242, 274), "log10 @12: the 242×274 grid");
        assert_eq!(gate_tile_dims_depth(1936, 1090, 10), (484, 274), "log10 @10: the 484×274 grid");
        assert_eq!(gate_tile_dims_depth(1936, 1090, 8), (242, 274), "log10 @8: the 8-bit arm folds to the @12 grid");
        // Grid + tile count + edge geometry:
        let g12 = Grid::for_depth(1936, 1090, 12);
        assert_eq!((g12.cols, g12.rows, g12.tw, g12.th), (8, 4, 242, 274), "log10 @12: 8×4 = 32 tiles");
        let g10 = Grid::for_depth(1936, 1090, 10);
        assert_eq!((g10.cols, g10.rows, g10.tw, g10.th), (4, 4, 484, 274), "log10 @10: 4×4 = 16 tiles");
        let g8 = Grid::for_depth(1936, 1090, 8);
        assert_eq!((g8.cols, g8.rows, g8.tw, g8.th), (8, 4, 242, 274), "log10 @8: 8×4 = 32 tiles");
        // The bottom-row half-row tile (268 content rows on the 274-row
        // plane — the odd-height shape, the full-274 geometry):
        let r30 = crate::tileenc::tile_region(1936, 1090, &g12, 3, 0).unwrap();
        assert_eq!((r30.y0, r30.tl), (822, 268), "the edge row: 3·274=822, 1090-822=268");
        assert_eq!(crate::tileenc::padded_tl_for(268, 274), 274, "the edge row's pad to the full 274 geometry");
        // The family = the grid-keyed FHD family (the 3-member {W7, W6,
 // N5} — the census 32/32 + 16/16 + 32/32, ZERO 0 · MULTI 0):
        assert_eq!(gate_candidates_for_grid(1936, 1090, 242, 274), FHD_CANDIDATES, "the @12/@8 grid rides the FHD family");
        assert_eq!(gate_candidates_for_grid(1936, 1090, 484, 274), FHD_CANDIDATES, "the @10 grid rides the FHD family");
        // The per-arm plans (`TilePlan::log10_gate`):
        let p12 = crate::surgery::TilePlan::log10_gate(1936, 1090, 12);
        assert_eq!(p12.bps_patch, Some(10), "@12: 258 12→10");
        assert_eq!(p12.tile_dims, (242, 274), "@12: the 242×274 grid");
        let (cnt, lut) = p12.lut.as_ref().expect("@12: the 1024 LUT ADD");
        assert_eq!(*cnt, 1024, "@12: the 1024-entry LUT");
        assert_eq!(lut, &crate::log10::lut_bytes(), "@12: the tool's own embedded A001 LUT (the measured LUT decision)");
        let p10 = crate::surgery::TilePlan::log10_gate(1936, 1090, 10);
        assert_eq!(p10.bps_patch, None, "@10: 258 unchanged (the raw 10-bit passthrough)");
        assert_eq!(p10.tile_dims, (484, 274), "@10: the 484×274 grid");
        assert_eq!(p10.lut, None, "@10: NO 50712 (the measured ABSENT)");
        let p8 = crate::surgery::TilePlan::log10_gate(1936, 1090, 8);
        assert_eq!(p8.bps_patch, Some(10), "@8: 258 8→10 (the identity promotion)");
        assert_eq!(p8.tile_dims, (242, 274), "@8: the 242×274 grid");
        assert_eq!(p8.lut, None, "@8: the native 256-entry 50712 CARRIED (never a second 50712)");
        // The UHD @12 arm = byte-identical to the historical
 // `TilePlan::log10` (the named mode control — the byte-invariance):
        let u = crate::surgery::TilePlan::log10_gate(3856, 2170, 12);
        let h = crate::surgery::TilePlan::log10();
        assert_eq!(u.bps_patch, h.bps_patch, "UHD @12 arm: the BPS split unchanged");
        assert_eq!(u.tile_dims, h.tile_dims, "UHD @12 arm: the 482×272 grid unchanged");
        assert_eq!(u.lut.as_ref().map(|(c, b)| (*c, b.len())), h.lut.as_ref().map(|(c, b)| (*c, b.len())), "UHD @12 arm: the LUT unchanged");
        assert_eq!(u.compression, h.compression, "UHD @12 arm: the compression unchanged");
        assert_eq!(u.photometric_patch, h.photometric_patch, "UHD @12 arm: the photometric unchanged");
    }

 /// FHD MODE grid geometry — the ds2x mode rows (the 
 /// measured contract — one integration table test per mode,
    /// the G4 pattern): the ds2x mode's measured 968×545 gate — the
    /// geometry constants + predicate, the per-depth grids (the
    /// source's FHD per-depth grid via `gate_tile_dims_depth` — the
    /// ds2x output inherits it), the 271-content-row bottom-row tiles
    /// (the odd-height interop shape), the grid×mode-keyed 2-member
 /// DS2X family (the decision (c) — W7 never observed,
    /// the superset rejected; the family is NEVER keyed on the grid
    /// alone — the SAME tile dimensions on the 1936×1090 rows ride
    /// `FHD_CANDIDATES`), the `--fast` = the family's index-0 stream
    /// (W6 at the ds2x geometry; the global W7 at every other geometry
    /// — the byte-invariance pin), the per-arm `TilePlan::downscale_
    /// gate` plans (@12/@10: 258 unchanged; @8: the identity
 /// promotion), and the variable-length `CandidateSet` (the decision
    /// (c) mechanical accommodation) + the self-sourced plane re-encode
 /// round-trip (the decision (b) machinery: `planes_from_tile_rows` +
    /// `encode_tile_planes` reproduce each candidate stream byte-
    /// exactly — the deterministic engine on identical samples). LIVES
    /// IN THE WORKER TESTS (not tileenc.rs) so the commit's touch-set
    /// stays within the fence list (the G4 pattern).
    #[test]
    fn fhd_ds2x_grid_geometry() {
        use crate::tileenc::{
            gate_candidates, gate_candidates_for_grid, gate_tile_dims_depth, is_fhd_ds2x_gate,
            tile_region, CANDIDATES, DS2X_FHD_CANDIDATES, FAST_CANDIDATE, FHD_CANDIDATES, Grid,
            Orient, GATE_FHD_DS2X_H, GATE_FHD_DS2X_W,
        };
        // The gate constants + predicate:
        assert_eq!((GATE_FHD_DS2X_W, GATE_FHD_DS2X_H), (968, 545), "the ds2x gate geometry (1936/2 × 1090/2)");
        assert!(is_fhd_ds2x_gate(968, 545));
        assert!(!is_fhd_ds2x_gate(1928, 1085), "the legacy UHD ds2x output is a different geometry");
        assert!(!is_fhd_ds2x_gate(1936, 1090), "the full-res FHD geometry is not the ds2x gate");
 // The measured family (the decision (c): the 2-member
        // set EXACTLY — W7 never observed, the superset rejected — an
        // unmeasured member is an unmeasured stream class, the A+C
        // boundary):
        assert_eq!(DS2X_FHD_CANDIDATES, [(Orient::Wrapped, 6), (Orient::Natural, 5)], "the measured ds2x family = the 2-member W6/N5 set exactly");
        assert_ne!(DS2X_FHD_CANDIDATES[0], FAST_CANDIDATE, "the ds2x fast stream = the family's index 0 (W6), NOT the global W7");
        assert_eq!(FAST_CANDIDATE, FHD_CANDIDATES[0], "the FHD fast stream stays the global W7 (the byte-invariance pin)");
        // The per-depth grids (the source's FHD per-depth grid — the
        // ds2x output inherits it — the measured contract):
        assert_eq!(gate_tile_dims_depth(1936, 1090, 12), (242, 274));
        assert_eq!(gate_tile_dims_depth(1936, 1090, 10), (484, 274));
        assert_eq!(gate_tile_dims_depth(1936, 1090, 8), (242, 274));
        // The 968×545 grids: 4×2 = 8 tiles @12/@8, 2×2 = 4 tiles @10;
        // the bottom-row tiles = the 271-content-row half-row tiles on
        // the 274-row plane (the odd-height interop shape — 545−274 =
        // 271, ODD):
        let g12 = Grid::for_dims(968, 545, 242, 274);
        assert_eq!((g12.cols, g12.rows, g12.tw, g12.th), (4, 2, 242, 274), "ds2x @12/@8: 4×2 = 8 tiles");
        let r10 = tile_region(968, 545, &g12, 1, 0).unwrap();
        assert_eq!((r10.x0, r10.y0, r10.tw, r10.tl), (0, 274, 242, 271), "the bottom-row half-row tile: 271 content rows (ODD) on the 274-row plane");
        assert_eq!(crate::tileenc::padded_tl_for(271, 274), 274, "the bottom-row tile's pad to the full 274 geometry");
        let g10 = Grid::for_dims(968, 545, 484, 274);
        assert_eq!((g10.cols, g10.rows, g10.tw, g10.th), (2, 2, 484, 274), "ds2x @10: 2×2 = 4 tiles");
        let r11 = tile_region(968, 545, &g10, 1, 1).unwrap();
        assert_eq!((r11.x0, r11.y0, r11.tw, r11.tl), (484, 274, 484, 271), "the @10 bottom-row half-row tile");
        // The family routing (the grid×mode key — the ds2x geometry IS
        // the mode key): 968×545 on the ds2x grids = the 2-member DS2X
        // family; the SAME tile dimensions on the 1936×1090
        // lossless/log10 rows = the 3-member FHD family (the family is
        // NEVER keyed on the grid alone); 968×545 on any other grid =
        // the legacy family (NOT an eligible ds2x shape — the decode-
        // side named refusal — the 482×272 grid at 968×545 is
        // unmeasured, the A+C boundary):
        assert_eq!(gate_candidates(968, 545), DS2X_FHD_CANDIDATES, "the encode-side routing: the ds2x gate → the DS2X family");
        assert_eq!(gate_candidates_for_grid(968, 545, 242, 274), DS2X_FHD_CANDIDATES, "968×545 @ 242×274 → the DS2X family");
        assert_eq!(gate_candidates_for_grid(968, 545, 484, 274), DS2X_FHD_CANDIDATES, "968×545 @ 484×274 → the DS2X family");
        assert_eq!(gate_candidates_for_grid(1936, 1090, 242, 274), FHD_CANDIDATES, "the SAME tile dims on the full-res geometry ride the FHD family (NEVER a grid-only key)");
        assert_eq!(gate_candidates_for_grid(1936, 1090, 484, 274), FHD_CANDIDATES, "the SAME tile dims on the full-res geometry ride the FHD family (NEVER a grid-only key)");
        assert_eq!(gate_candidates_for_grid(968, 545, 482, 272), CANDIDATES, "the 482×272 grid at 968×545 = the legacy family (the unmeasured shape — the decode-side named refusal)");
        // The per-arm plans (`TilePlan::downscale_gate`):
        let d12 = crate::surgery::TilePlan::downscale_gate(1936, 1090, 12);
        assert_eq!(d12.bps_patch, None, "@12: 258 unchanged (12)");
        assert_eq!(d12.tile_dims, (242, 274), "@12: the measured 242×274 grid");
        let d10 = crate::surgery::TilePlan::downscale_gate(1936, 1090, 10);
        assert_eq!(d10.bps_patch, None, "@10: 258 unchanged (10)");
        assert_eq!(d10.tile_dims, (484, 274), "@10: the measured 484×274 grid");
        let d8 = crate::surgery::TilePlan::downscale_gate(1936, 1090, 8);
        assert_eq!(d8.bps_patch, Some(10), "@8: 258 8→10 (the identity promotion)");
        assert_eq!(d8.tile_dims, (242, 274), "@8: the measured 242×274 grid");
        // The UHD @12 arm = byte-identical to the historical
        // `TilePlan::lossless()` (the named mode control — the
 // byte-invariance):
        let u = crate::surgery::TilePlan::downscale_gate(3856, 2170, 12);
        let h = crate::surgery::TilePlan::lossless();
        assert_eq!(u.bps_patch, h.bps_patch, "UHD @12 arm: the BPS unchanged");
        assert_eq!(u.tile_dims, h.tile_dims, "UHD @12 arm: the 482×272 grid unchanged");
        assert_eq!(u.lut, h.lut, "UHD @12 arm: no LUT");
        assert_eq!(u.compression, h.compression, "UHD @12 arm: the compression unchanged");
 // The variable-length CandidateSet (the decision (c)
        // mechanical accommodation — the fixed [; 3] arrays → Vecs):
        // the 968×545 grid returns the 2-member streams; the 1936×1090
        // grid keeps the 3.
        let plane: Vec<u16> = (0..968 * 545).map(|i| (i % 4096) as u16).collect();
        let rect00 = tile_region(968, 545, &g12, 0, 0).unwrap();
        let (_t, (streams, sizes, best)) =
            crate::tileenc::encode_tile_candidates(&plane, 968, 545, &g12, 0, 0, 12).unwrap();
        assert_eq!(streams.len(), 2, "the ds2x family = 2 members (the variable-length CandidateSet)");
        assert_eq!(sizes.len(), 2, "the ds2x sizes = 2 members");
        assert!(best < 2, "the ds2x chosen index in the 2-member family");
        // `--fast` at the ds2x geometry = the measured family's index-0
 // stream (W6 — the decision (c) pattern):
        let fast = crate::tileenc::encode_tile_fast(&plane, 968, 545, &g12, 0, 0, 12).unwrap();
        assert_eq!(fast, streams[0], "--fast = the measured family's index-0 stream (W6) at the ds2x geometry");
 // The self-sourced plane re-encode round-trip (the 
 // decision (b) machinery): the tool's pad plane, re-split by
        // `planes_from_tile_rows` (the inverse of the tile assembly)
        // + re-encoded by `encode_tile_planes`, reproduces each
        // candidate stream byte-exactly (the deterministic engine on
        // identical samples — the drill's acceptance core).
        for (i, &(orient, psv)) in DS2X_FHD_CANDIDATES.iter().enumerate() {
            let p = crate::tileenc::planes_from_tile(&plane, 968, 545, &g12, 0, 0, orient).unwrap();
            let full = crate::tileenc::tile_from_planes(&p).unwrap();
            let back = crate::tileenc::planes_from_tile_rows(&full, &rect00, g12.th, orient).unwrap();
            let re = crate::tileenc::encode_tile_planes(&back, 12, psv).unwrap();
            assert_eq!(re, streams[i], "candidate {i}: the self-sourced re-encode reproduces the stream byte-exactly");
        }
    }

    // =================================================================
 // The OG2K mode rows ( — measured
    // contract): the 2016×1344 gate's measured log10 + downscale2x
 // rows at @12/@10/@8 (the second work of the mode-onboarding
 // stream — the machinery, the OG2K measured seams).
    // Corpus (the G2/G3/G4 corpus-noting pattern — the mode corpus is
    // date-suffix-free): the originals `../testdata/originals_A001_00X/`
    // (A001_007 @12 97 frames · A001_008 @10 97 · A001_009 @8 101 —
    // the 3-frame sample pattern first/middle/last:
    // 000001/000049/000097 · 000001/000050/000100).
    // =================================================================

 /// THE GOLDEN ENCODE TEST — the OG2K log10 @12 row (the 
 /// measured contract — ): the 2016×1344 @12 log10
    /// row — the 10-bit log codes on the measured depth-invariant
    /// 252×336 grid (4×2 = 8 tiles ×4 = 32 tiles), the 258 12→10 BPS
    /// split, the 50712 1024 LUT ADD (the tool's own embedded A001 LUT
 /// — the measured LUT decision: the measured per-frame table is
 /// the calibration payload, the free class — the structural
    /// pin = presence + count, NOT the table content), the
 /// grid-keyed `OG2K_CANDIDATES` family {W7, W6, N5} (the 
 /// census 32/32 + 32/32 + 32/32, ZERO 0 · MULTI 0). Content
    /// class = the quantized code plane (the round-trip = the LUT
    /// codes — the ≤1-LSB residual vs the corpus per-frame LUT
 /// is the measured interop boundary, NOT a contract).
    /// Corpus `../testdata/originals_A001_007/` (3 frames).
    #[test]
    fn golden_og2k_log10_12_encode_structural() {
        let rows = golden_mode_encode_row(
            "og2k-log10-12",
            "A001_007",
            12,
            Mode::Log10,
            false,
            (2016, 1344),
            10,
            (252, 336),
            32,
            Some(1024),
            2, // 58 − 3 strip + 4 tile + 1 LUT = 60 (the measured formula)
            [
                "A001_007_20260924_000001.DNG".into(),
                "A001_007_20260924_000049.DNG".into(),
                "A001_007_20260924_000097.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        let inv = crate::log10::inv();
        for (n, _out, decoded, orig) in rows {
            // The content class: the 10-bit log codes (12-bit → codes
            // via the built-in LUT's inverse — the round-trip = the
 // code plane, NOT the raw samples — the interop
            // boundary, the quantization).
            let expected_codes: Vec<u16> = orig.iter().map(|v| inv[*v as usize]).collect();
            assert_eq!(
                decoded, expected_codes,
                "{n}: the round-trip = the log10 code plane (the @12 content class)"
            );
        }
    }

 /// THE GOLDEN ENCODE TEST — the OG2K log10 @10 row (the 
 /// measured contract — ): the 2016×1344 @10 log10
    /// row — the RAW 10-BIT PASSTHROUGH (the measured maxdiff 0 vs the
    /// raw samples — the mode's container stores the raw samples) on
    /// the measured depth-invariant 252×336 grid (32 tiles), 258
    /// unchanged (10), NO 50712 (the measured ABSENT). Content class =
    /// the raw samples (content-identical to the OG2K lossless @10
 /// plane — the verdict; pinned BYTE-IDENTICAL: the same
    /// plane / grid / family + the field-equal per-arm plan
    /// [bps_patch None, lut None, tile_dims (252,336)]). Corpus
    /// `../testdata/originals_A001_008/` (3 frames).
    #[test]
    fn golden_og2k_log10_10_encode_structural() {
        let rows = golden_mode_encode_row(
            "og2k-log10-10",
            "A001_008",
            10,
            Mode::Log10,
            false,
            (2016, 1344),
            10,
            (252, 336),
            32,
            None, // the measured ABSENT (no 50712)
            1, // 58 − 3 strip + 4 tile = 59 (the measured formula)
            [
                "A001_008_20260924_000001.DNG".into(),
                "A001_008_20260924_000049.DNG".into(),
                "A001_008_20260924_000097.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, _out, decoded, orig) in &rows {
            // The content class: the RAW 10-bit passthrough (the
            // measured maxdiff 0 vs the raw samples).
            assert_eq!(
                decoded, orig,
                "{n}: the round-trip = the raw 10-bit samples (the @10 raw-passthrough content class)"
            );
        }
 // The measured content identity (the verdict): the
        // log10 @10 output = the lossless @10 output BYTE-IDENTICAL
        // (the same plane / grid / family; the per-arm plans are field-
        // equal: bps_patch None + lut None + tile_dims (252,336)).
        let dir = "../testdata/originals_A001_008";
        for (n, log10_out, _decoded, _orig) in &rows {
            let bytes = std::fs::read(format!("{dir}/{n}")).unwrap();
            let (input, output, base) =
                camera_gate_fixture(&format!("mode-log10-10-lossless-{n}"), n, &bytes);
            let report = process_dir(
                &input,
                &output,
                true,
                false,
                1,
                Mode::Lossless, // the lossless @10 control (the native-depth path)
                false,
                false,
                false,
                LossyFormat::K34892,
                &ReferenceDctOpts::default(),
                None,
                false,
            )
            .expect("process_dir (the lossless @10 control)");
            assert!(
                matches!(report.outcomes[0], Outcome::Done(_)),
                "the lossless @10 control must encode Done: {n}: {:?}",
                report.outcomes[0]
            );
            let lossless_out =
                std::fs::read(output.join(n)).expect("the lossless @10 output must exist");
            assert_eq!(
                *log10_out, lossless_out,
                "{n}: the log10 @10 output != the lossless @10 output (the measured content identity — byte-identical)"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
    }

 /// THE GOLDEN ENCODE TEST — the OG2K log10 @8 row (the 
 /// measured contract — ): the 2016×1344 @8 log10
    /// row — the 8-bit samples IDENTITY-promoted into the measured
    /// BPS10 container (258 8→10 — the mode tier's BPS split; the
 /// lossless tier's no-promotion decision is scoped to the lossless
    /// tier) on the measured depth-invariant 252×336 grid (32 tiles);
 /// the camera-native 256-entry 50712 CARRIED VERBATIM (the 
    /// measured byte-identity across all 9 @8 files — the carry, not a
    /// duplicate). Content class = the raw 8-bit samples (the measured
    /// maxdiff 0; the ×4-scaled hypothesis measured REJECTED). Corpus
    /// `../testdata/originals_A001_009/` (3 frames).
    #[test]
    fn golden_og2k_log10_8_encode_structural() {
        let rows = golden_mode_encode_row(
            "og2k-log10-8",
            "A001_009",
            8,
            Mode::Log10,
            false,
            (2016, 1344),
            10, // the identity promotion (258 8→10)
            (252, 336),
            32,
            Some(256), // the camera-native table CARRIED (the helper pins the verbatim value)
            1, // 59 − 3 strip + 4 tile = 60 (the measured formula)
            [
                "A001_009_20260924_000001.DNG".into(),
                "A001_009_20260924_000050.DNG".into(),
                "A001_009_20260924_000100.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, _out, decoded, orig) in rows {
            // The content class: the 8-bit samples identity-promoted
            // (the values unchanged, zero-extended into the BPS10
            // container — the measured maxdiff 0 vs the raw samples).
            assert_eq!(
                decoded, orig,
                "{n}: the round-trip = the 8-bit samples (the @8 identity-promotion content class)"
            );
        }
    }

 /// THE GOLDEN ENCODE TEST — the OG2K ds2x @12 row (the 
 /// measured contract — ): the 1008×672 @12
    /// downscale2x row — the 2×-decimated plane (the tool's own
    /// staircase decimation — the measured decimation is the
 /// interop boundary, the measured δ decision: the tool keeps its own
    /// staircase) on the measured depth-invariant 252×336 grid (4×2 =
 /// 8 tiles — full-tile edge rows only — the measured
    /// no-half-row verdict), 258 unchanged (12), the grid×mode-keyed
    /// 3-member `DS2X_OG2K_CANDIDATES` family {W7, W6, N5} (the 24/24 census — W7 observed, the 3-member set
 /// EXACTLY — the decision (c)), the 51089-91 proxy tags (the tool's
 /// own ds2x design — the reference omits them, the free
    /// class). Content class = the tool's own decimation plane (bit-
    /// exact by construction). Corpus
    /// `../testdata/originals_A001_007/` (3 frames).
    #[test]
    fn golden_og2k_ds2x_12_encode_structural() {
        ds2x_encode_row_content("og2k-ds2x-12", "A001_007", 12, (1008, 672), 12, (252, 336), 8, [
            "A001_007_20260924_000001.DNG".into(),
            "A001_007_20260924_000049.DNG".into(),
            "A001_007_20260924_000097.DNG".into(),
        ]);
    }

 /// THE GOLDEN ENCODE TEST — the OG2K ds2x @10 row (the 
 /// measured contract — ): the 1008×672 @10
    /// downscale2x row — the measured depth-invariant 252×336 grid
    /// (4×2 = 8 tiles), 258 unchanged (10), the 3-member
    /// `DS2X_OG2K_CANDIDATES` family {W7, W6, N5}. Content class = the
    /// tool's own decimation plane. Corpus
    /// `../testdata/originals_A001_008/` (3 frames).
    #[test]
    fn golden_og2k_ds2x_10_encode_structural() {
        ds2x_encode_row_content("og2k-ds2x-10", "A001_008", 10, (1008, 672), 10, (252, 336), 8, [
            "A001_008_20260924_000001.DNG".into(),
            "A001_008_20260924_000049.DNG".into(),
            "A001_008_20260924_000097.DNG".into(),
        ]);
    }

 /// THE GOLDEN ENCODE TEST — the OG2K ds2x @8 row (the 
 /// measured contract — ): the 1008×672 @8
    /// downscale2x row — the measured depth-invariant 252×336 grid
    /// (4×2 = 8 tiles), the 258 8→10 identity promotion (the mode
    /// tier's BPS split), the camera-native 256-entry 50712 CARRIED
    /// VERBATIM, the 3-member `DS2X_OG2K_CANDIDATES` family {W7, W6,
    /// N5}. Content class = the tool's own decimation plane (the 8-bit
    /// values zero-extended into the BPS10 container). Corpus
    /// `../testdata/originals_A001_009/` (3 frames).
    #[test]
    fn golden_og2k_ds2x_8_encode_structural() {
        ds2x_encode_row_content("og2k-ds2x-8", "A001_009", 8, (1008, 672), 10, (252, 336), 8, [
            "A001_009_20260924_000001.DNG".into(),
            "A001_009_20260924_000050.DNG".into(),
            "A001_009_20260924_000100.DNG".into(),
        ]);
    }

 /// THE GOLDEN ENCODE TEST — the OG3K log10 @12 row (the 
 /// measured contract — ): the 3024×2010 @12 log10
    /// row — the 10-bit log codes on the measured depth-invariant
    /// 252×252 grid (12×8 = 96 tiles; the bottom-row tiles are the
    /// 246-content-row half-row tiles — the odd-height interop shape),
    /// the 258 12→10 BPS split, the 50712 1024 LUT ADD (the tool's own
 /// embedded A001 LUT — the measured LUT decision: the measured
 /// per-frame table is the calibration payload, the free
    /// class — the structural pin = presence + count, NOT the table
 /// content), the 3K family `CANDIDATES` {W7, W2, N1} (the census
    /// 864/864 tiles, ZERO 0 · MULTI 0). Content class = the quantized
    /// code plane (the round-trip = the LUT codes). Corpus
    /// `../testdata/originals_A001_010/` (3 frames).
    #[test]
    fn golden_og3k_log10_12_encode_structural() {
        let rows = golden_mode_encode_row(
            "og3k-log10-12",
            "A001_010",
            12,
            Mode::Log10,
            false,
            (3024, 2010),
            10,
            (252, 252),
            96,
            Some(1024),
            2, // 58 − 3 strip + 4 tile + 1 LUT = 60 (the measured formula)
            [
                "A001_010_20260924_000001.DNG".into(),
                "A001_010_20260924_000050.DNG".into(),
                "A001_010_20260924_000101.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        let inv = crate::log10::inv();
        for (n, _out, decoded, orig) in rows {
            // The content class: the 10-bit log codes (12-bit → codes
            // via the built-in LUT's inverse — the round-trip = the
 // code plane, NOT the raw samples — the interop
            // boundary, the quantization).
            let expected_codes: Vec<u16> = orig.iter().map(|v| inv[*v as usize]).collect();
            assert_eq!(
                decoded, expected_codes,
                "{n}: the round-trip = the log10 code plane (the @12 content class)"
            );
        }
    }

 /// THE GOLDEN ENCODE TEST — the OG3K log10 @10 row (the 
 /// measured contract — ): the 3024×2010 @10 log10
    /// row — the RAW 10-BIT PASSTHROUGH (the measured maxdiff 0 vs the
    /// raw samples — the mode's container stores the raw samples) on
    /// the measured depth-invariant 252×252 grid (12×8 = 96 tiles), 258
    /// unchanged (10), NO 50712 (the measured ABSENT). Content class =
    /// the raw samples (content-identical to the OG3K lossless @10
 /// plane — the verdict; pinned BYTE-IDENTICAL: the same
    /// plane / grid / family + the field-equal per-arm plan
    /// [bps_patch None, lut None, tile_dims (252,252)]). Corpus
    /// `../testdata/originals_A001_011/` (3 frames).
    #[test]
    fn golden_og3k_log10_10_encode_structural() {
        let rows = golden_mode_encode_row(
            "og3k-log10-10",
            "A001_011",
            10,
            Mode::Log10,
            false,
            (3024, 2010),
            10,
            (252, 252),
            96,
            None, // the measured ABSENT (no 50712)
            1, // 58 − 3 strip + 4 tile = 59 (the measured formula)
            [
                "A001_011_20260924_000001.DNG".into(),
                "A001_011_20260924_000050.DNG".into(),
                "A001_011_20260924_000099.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, _out, decoded, orig) in &rows {
            // The content class: the RAW 10-bit passthrough (the
            // measured maxdiff 0 vs the raw samples).
            assert_eq!(
                decoded, orig,
                "{n}: the round-trip = the raw 10-bit samples (the @10 raw-passthrough content class)"
            );
        }
 // The measured content identity (the verdict): the
        // log10 @10 output = the lossless @10 output BYTE-IDENTICAL
        // (the same plane / grid / family; the per-arm plans are field-
        // equal: bps_patch None + lut None + tile_dims (252,252)).
        let dir = "../testdata/originals_A001_011";
        for (n, log10_out, _decoded, _orig) in &rows {
            let bytes = std::fs::read(format!("{dir}/{n}")).unwrap();
            let (input, output, base) =
                camera_gate_fixture(&format!("mode-log10-10-lossless-{n}"), n, &bytes);
            let report = process_dir(
                &input,
                &output,
                true,
                false,
                1,
                Mode::Lossless, // the lossless @10 control (the native-depth path)
                false,
                false,
                false,
                LossyFormat::K34892,
                &ReferenceDctOpts::default(),
                None,
                false,
            )
            .expect("process_dir (the lossless @10 control)");
            assert!(
                matches!(report.outcomes[0], Outcome::Done(_)),
                "the lossless @10 control must encode Done: {n}: {:?}",
                report.outcomes[0]
            );
            let lossless_out =
                std::fs::read(output.join(n)).expect("the lossless @10 output must exist");
            assert_eq!(
                *log10_out, lossless_out,
                "{n}: the log10 @10 output != the lossless @10 output (the measured content identity — byte-identical)"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
    }

 /// THE GOLDEN ENCODE TEST — the OG3K log10 @8 row (the 
 /// measured contract — ): the 3024×2010 @8 log10
    /// row — the 8-bit samples IDENTITY-promoted into the measured
    /// BPS10 container (258 8→10 — the mode tier's BPS split; the
 /// lossless tier's no-promotion decision is scoped to the lossless
    /// tier) on the measured depth-invariant 252×252 grid (12×8 = 96
    /// tiles); the camera-native 256-entry 50712 CARRIED VERBATIM (the
 /// measured byte-identity across all @8 files — the carry, not a
    /// duplicate). Content class = the raw 8-bit samples (the measured
    /// maxdiff 0; the ×4-scaled hypothesis measured REJECTED). Corpus
    /// `../testdata/originals_A001_012/` (3 frames).
    #[test]
    fn golden_og3k_log10_8_encode_structural() {
        let rows = golden_mode_encode_row(
            "og3k-log10-8",
            "A001_012",
            8,
            Mode::Log10,
            false,
            (3024, 2010),
            10, // the identity promotion (258 8→10)
            (252, 252),
            96,
            Some(256), // the camera-native table CARRIED (the helper pins the verbatim value)
            1, // 59 − 3 strip + 4 tile = 60 (the measured formula)
            [
                "A001_012_20260924_000001.DNG".into(),
                "A001_012_20260924_000049.DNG".into(),
                "A001_012_20260924_000097.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, _out, decoded, orig) in rows {
            // The content class: the 8-bit samples identity-promoted
            // (the values unchanged, zero-extended into the BPS10
            // container — the measured maxdiff 0 vs the raw samples).
            assert_eq!(
                decoded, orig,
                "{n}: the round-trip = the 8-bit samples (the @8 identity-promotion content class)"
            );
        }
    }

 /// THE GOLDEN ENCODE TEST — the OG3K ds2x @12 row (the 
 /// measured contract — ): the 1512×1005 @12
    /// downscale2x row — the 2×-decimated plane (the tool's own
    /// staircase decimation — the measured decimation is the interop
 /// boundary, the measured δ decision: the tool keeps its own
    /// staircase) on the measured depth-invariant 252×252 grid (6×4 =
    /// 24 tiles; the bottom-row tiles are the 249-content-row half-row
    /// tiles — the odd-height interop shape), 258 unchanged (12), the
    /// grid×mode-keyed 3-member `DS2X_OG3K_CANDIDATES` family {W7, W2,
 /// N1} (the census 24/24 tiles — W7 observed, the
 /// 3-member set EXACTLY — the decision (c)), the 51089-91 proxy tags
    /// (the tool's own ds2x design — the reference omits them, the
 /// free class). Content class = the tool's own decimation
    /// plane (bit-exact by construction). Corpus
    /// `../testdata/originals_A001_010/` (3 frames).
    #[test]
    fn golden_og3k_ds2x_12_encode_structural() {
        ds2x_encode_row_content("og3k-ds2x-12", "A001_010", 12, (1512, 1005), 12, (252, 252), 24, [
            "A001_010_20260924_000001.DNG".into(),
            "A001_010_20260924_000050.DNG".into(),
            "A001_010_20260924_000101.DNG".into(),
        ]);
    }

 /// THE GOLDEN ENCODE TEST — the OG3K ds2x @10 row (the 
 /// measured contract — ): the 1512×1005 @10
    /// downscale2x row — the measured depth-invariant 252×252 grid
    /// (6×4 = 24 tiles), 258 unchanged (10), the 3-member
    /// `DS2X_OG3K_CANDIDATES` family {W7, W2, N1}. Content class = the
    /// tool's own decimation plane. Corpus
    /// `../testdata/originals_A001_011/` (3 frames).
    #[test]
    fn golden_og3k_ds2x_10_encode_structural() {
        ds2x_encode_row_content("og3k-ds2x-10", "A001_011", 10, (1512, 1005), 10, (252, 252), 24, [
            "A001_011_20260924_000001.DNG".into(),
            "A001_011_20260924_000050.DNG".into(),
            "A001_011_20260924_000099.DNG".into(),
        ]);
    }

 /// THE GOLDEN ENCODE TEST — the OG3K ds2x @8 row (the 
 /// measured contract — ): the 1512×1005 @8
    /// downscale2x row — the measured depth-invariant 252×252 grid
    /// (6×4 = 24 tiles), the 258 8→10 identity promotion (the mode
    /// tier's BPS split), the camera-native 256-entry 50712 CARRIED
    /// VERBATIM, the 3-member `DS2X_OG3K_CANDIDATES` family {W7, W2,
    /// N1}. Content class = the tool's own decimation plane (the 8-bit
    /// values zero-extended into the BPS10 container). Corpus
    /// `../testdata/originals_A001_012/` (3 frames).
    #[test]
    fn golden_og3k_ds2x_8_encode_structural() {
        ds2x_encode_row_content("og3k-ds2x-8", "A001_012", 8, (1512, 1005), 10, (252, 252), 24, [
            "A001_012_20260924_000001.DNG".into(),
            "A001_012_20260924_000049.DNG".into(),
            "A001_012_20260924_000097.DNG".into(),
        ]);
    }

    // =================================================================
 // The UHD mode rows ( — measured
    // contract — the mirrored reference mode corpus): the 3856×2170
    // log10 rows (full-res) + the 1928×1085 ds2x rows at @10/@8 — the
 // PER-DEPTH measured grids (the per-depth inheritance — :
    // 964×272 @10, 482×272 @8); the @12 UHD mode rows are the frozen
 // 0.1.0-era outputs (the byte-invariance's 2-mode controls — out
    // of scope). Corpus (the G4 corpus-noting pattern — the mode
    // corpus is date-suffix-free): the originals
    // `../testdata/originals_A001_00{2,3}/` (A001_002 @10 · A001_003
    // @8 — the 3-frame sample pattern first/middle/last:
    // 000001/000050/000099 · 000001/000049/000098).
    // =================================================================

 /// THE GOLDEN ENCODE TEST — the UHD log10 @10 row (the 
 /// measured contract — ): the 3856×2170 @10 log10
    /// row — the raw 10-bit passthrough on the measured 964×272 grid
    /// (4×8 = 32 tiles; the bottom-row tiles are the 266-content-row
    /// half-row tiles — the odd-height interop shape), 258 unchanged
    /// (10), the 50712 ABSENT, the gate's `CANDIDATES` family {W7,
 /// W2, N1} (the census 96/96 tiles, ZERO 0 · MULTI 0).
    /// Content class = the raw 10-bit samples (the measured maxdiff 0
    /// — the @10 raw-passthrough identity HOLDS at UHD). Corpus
    /// `../testdata/originals_A001_002/` (3 frames).
    #[test]
    fn golden_uhd_log10_10_encode_structural() {
        let rows = golden_mode_encode_row(
            "uhd-log10-10",
            "A001_002",
            10,
            Mode::Log10,
            false,
            (3856, 2170),
            10,
            (964, 272),
            32,
            None, // the measured ABSENT (no 50712)
            1, // 58 − 3 strip + 4 tile = 59 (the measured formula)
            [
                "A001_002_20260924_000001.DNG".into(),
                "A001_002_20260924_000050.DNG".into(),
                "A001_002_20260924_000099.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, _out, decoded, orig) in &rows {
            // The content class: the RAW 10-bit passthrough (the
            // measured maxdiff 0 vs the raw samples — the identity
 // HOLDS at UHD, the verdict).
            assert_eq!(
                decoded, orig,
                "{n}: the round-trip = the raw 10-bit samples (the @10 raw-passthrough content class)"
            );
        }
 // The measured content identity (the verdict): the
        // log10 @10 output = the lossless @10 output BYTE-IDENTICAL
        // (the same plane / grid / family; the per-arm plans are field-
        // equal: bps_patch None + lut None + tile_dims (964,272); the
        // reference's own log10 @10 size = the tool's size, 2610614 B
 // at f000001 — the layout diff, report.md §8).
        let dir = "../testdata/originals_A001_002";
        for (n, log10_out, _decoded, _orig) in &rows {
            let bytes = std::fs::read(format!("{dir}/{n}")).unwrap();
            let (input, output, base) =
                camera_gate_fixture(&format!("mode-log10-10-lossless-{n}"), n, &bytes);
            let report = process_dir(
                &input,
                &output,
                true,
                false,
                1,
                Mode::Lossless, // the lossless @10 control (the native-depth path)
                false,
                false,
                false,
                LossyFormat::K34892,
                &ReferenceDctOpts::default(),
                None,
                false,
            )
            .expect("process_dir (the lossless @10 control)");
            assert!(
                matches!(report.outcomes[0], Outcome::Done(_)),
                "the lossless @10 control must encode Done: {n}: {:?}",
                report.outcomes[0]
            );
            let ls_out =
                std::fs::read(output.join(n)).expect("the lossless @10 output must exist");
            assert_eq!(
                log10_out, &ls_out,
                "{n}: the log10 @10 output = the lossless @10 output byte-identical (the measured content identity)"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
    }

 /// THE GOLDEN ENCODE TEST — the UHD log10 @8 row (the 
 /// measured contract — ): the 3856×2170 @8 log10
    /// row — the 8-bit samples identity-promoted into the measured
    /// BPS10 container on the measured 482×272 grid (8×8 = 64 tiles;
    /// the bottom-row tiles are the 266-content-row half-row tiles),
    /// the 258 8→10 identity promotion (the mode tier's BPS split),
    /// the camera-native 256-entry 50712 CARRIED VERBATIM, the gate's
 /// `CANDIDATES` family {W7, W2, N1} (the census
    /// 192/192 tiles, ZERO 0 · MULTI 0). Content class = the raw 8-bit
    /// samples (the measured maxdiff 0 — the identity promotion). Corpus
    /// `../testdata/originals_A001_003/` (3 frames).
    #[test]
    fn golden_uhd_log10_8_encode_structural() {
        let rows = golden_mode_encode_row(
            "uhd-log10-8",
            "A001_003",
            8,
            Mode::Log10,
            false,
            (3856, 2170),
            10, // the measured 8→10 identity promotion
            (482, 272),
            64,
            Some(256), // the camera-native table CARRIED (the helper pins the verbatim value)
            1, // 59 − 3 strip + 4 tile = 60 (the measured formula)
            [
                "A001_003_20260924_000001.DNG".into(),
                "A001_003_20260924_000049.DNG".into(),
                "A001_003_20260924_000098.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, _out, decoded, orig) in &rows {
            // The content class: the identity promotion (the 8-bit
            // values unchanged — the measured maxdiff 0).
            assert_eq!(
                decoded, orig,
                "{n}: the round-trip = the raw 8-bit samples (the @8 identity-promotion content class)"
            );
        }
    }

 /// THE GOLDEN ENCODE TEST — the UHD ds2x @10 row (the 
 /// measured contract — ): the 1928×1085 @10
    /// downscale2x row — the tool's own staircase decimation on the
    /// measured 964×272 grid (2×4 = 8 tiles; the bottom-row tiles are
    /// the 269-content-row half-row tiles — the odd-height interop
    /// shape), 258 unchanged (10), the 2-member `DS2X_UHD_964_CANDIDATES`
 /// family {W2, N1} (the census 24/24 tiles — W7 never
    /// observed — ZERO 0 · MULTI 0). Content class = the tool's own
 /// decimation plane (the δ decision: the measured decimation
    /// is the interop boundary — never a byte-parity assertion). Corpus
    /// `../testdata/originals_A001_002/` (3 frames).
    #[test]
    fn golden_uhd_ds2x_10_encode_structural() {
        ds2x_encode_row_content("uhd-ds2x-10", "A001_002", 10, (1928, 1085), 10, (964, 272), 8, [
            "A001_002_20260924_000001.DNG".into(),
            "A001_002_20260924_000050.DNG".into(),
            "A001_002_20260924_000099.DNG".into(),
        ]);
    }

 /// THE GOLDEN ENCODE TEST — the UHD ds2x @8 row (the 
 /// measured contract — ): the 1928×1085 @8
    /// downscale2x row — the tool's own staircase decimation on the
    /// measured 482×272 grid (4×4 = 16 tiles; the bottom-row tiles are
    /// the 269-content-row half-row tiles — the odd-height interop
    /// shape), the 258 8→10 identity promotion (the mode tier's BPS
    /// split), the camera-native 256-entry 50712 CARRIED VERBATIM, the
    /// 3-member `DS2X_UHD_482_CANDIDATES` family {W7, W2, N1} (the
 /// census 48/48 tiles — W7 observed — ZERO 0 · MULTI
    /// 0). Content class = the tool's own decimation plane (the 8-bit
    /// values zero-extended into the BPS10 container). Corpus
    /// `../testdata/originals_A001_003/` (3 frames).
    #[test]
    fn golden_uhd_ds2x_8_encode_structural() {
        ds2x_encode_row_content("uhd-ds2x-8", "A001_003", 8, (1928, 1085), 10, (482, 272), 16, [
            "A001_003_20260924_000001.DNG".into(),
            "A001_003_20260924_000049.DNG".into(),
            "A001_003_20260924_000098.DNG".into(),
        ]);
    }

 /// OG2K MODE grid geometry — the log10 mode rows (the 
 /// measured contract — one integration table test per mode,
    /// the G4 pattern): the log10 mode's measured grid / BPS / 50712
    /// mechanics per depth arm, asserted on the routing machinery (the
    /// depth-invariant grid via `gate_tile_dims_depth` +
    /// `Grid::for_depth` — the OG2K mode's grid = the OG2K per-depth
    /// lossless grid, 252×336 at every depth; the family = the
    /// grid-keyed `OG2K_CANDIDATES`; the per-arm
    /// `TilePlan::log10_gate` plans: @12 = the 1024 LUT ADD + 258
    /// 12→10; @10 = the raw passthrough (no BPS patch, no LUT); @8 =
    /// the identity promotion (258 8→10, the native 256-entry 50712
    /// CARRIED — `lut: None`). The UHD @12 arm = byte-identical to the
    /// historical `TilePlan::log10()` (the named mode control — the
 /// byte-invariance). LIVES IN THE WORKER TESTS (not tileenc.rs) so the
    /// commit's touch-set stays within the fence list (the G4
    /// pattern).
    #[test]
    fn og2k_log10_grid_geometry() {
        use crate::tileenc::{gate_candidates_for_grid, gate_tile_dims_depth, Grid, OG2K_CANDIDATES};
        // The per-depth grids (the mode's grid = the per-depth
        // lossless grid — the OG2K measured contract: DEPTH-INVARIANT
        // 252×336 at every depth):
        assert_eq!(gate_tile_dims_depth(2016, 1344, 12), (252, 336), "log10 @12: the depth-invariant 252×336 grid");
        assert_eq!(gate_tile_dims_depth(2016, 1344, 10), (252, 336), "log10 @10: the depth-invariant 252×336 grid");
        assert_eq!(gate_tile_dims_depth(2016, 1344, 8), (252, 336), "log10 @8: the depth-invariant 252×336 grid (no per-depth variant at OG2K)");
        // Grid + tile count + edge geometry (full-tile edge rows only —
        // 2016 = 8×252 exact, 1344 = 4×336 exact):
        let g12 = Grid::for_depth(2016, 1344, 12);
        assert_eq!((g12.cols, g12.rows, g12.tw, g12.th), (8, 4, 252, 336), "log10 @12: 8×4 = 32 tiles");
        let g10 = Grid::for_depth(2016, 1344, 10);
        assert_eq!((g10.cols, g10.rows, g10.tw, g10.th), (8, 4, 252, 336), "log10 @10: 8×4 = 32 tiles");
        let g8 = Grid::for_depth(2016, 1344, 8);
        assert_eq!((g8.cols, g8.rows, g8.tw, g8.th), (8, 4, 252, 336), "log10 @8: 8×4 = 32 tiles");
        // The bottom-row edge tile: FULL 336 content rows (no half-row
 // class at OG2K — 1344 = 4×336 exact — the measured
        // verdict):
        let r30 = crate::tileenc::tile_region(2016, 1344, &g12, 3, 0).unwrap();
        assert_eq!((r30.y0, r30.tl), (1008, 336), "the edge row: 3·336=1008, 1344-1008=336 (FULL tile height)");
        // The family (grid-keyed — the mode's full-resolution rows
        // ride the gate family):
        assert_eq!(gate_candidates_for_grid(2016, 1344, 252, 336), OG2K_CANDIDATES, "2016×1344 @ 252×336 → the OG2K family");
        // The per-arm plans (`TilePlan::log10_gate`):
        let l12 = crate::surgery::TilePlan::log10_gate(2016, 1344, 12);
        assert_eq!(l12.bps_patch, Some(10), "@12: 258 12→10");
        assert!(l12.lut.is_some(), "@12: the 1024 LUT ADD");
        assert_eq!(l12.tile_dims, (252, 336), "@12: the measured depth-invariant grid");
        let l10 = crate::surgery::TilePlan::log10_gate(2016, 1344, 10);
        assert_eq!(l10.bps_patch, None, "@10: the raw passthrough (no BPS patch)");
        assert!(l10.lut.is_none(), "@10: no LUT");
        assert_eq!(l10.tile_dims, (252, 336), "@10: the measured depth-invariant grid");
        let l8 = crate::surgery::TilePlan::log10_gate(2016, 1344, 8);
        assert_eq!(l8.bps_patch, Some(10), "@8: 258 8→10 (the identity promotion)");
        assert!(l8.lut.is_none(), "@8: no LUT ADD (the native 256-entry 50712 CARRIED)");
        assert_eq!(l8.tile_dims, (252, 336), "@8: the measured depth-invariant grid");
        // The UHD @12 arm = byte-identical to the historical
        // `TilePlan::log10()` (the named mode control — the
 // byte-invariance):
        let u = crate::surgery::TilePlan::log10_gate(3856, 2170, 12);
        let h = crate::surgery::TilePlan::log10();
        assert_eq!(u.bps_patch, h.bps_patch, "UHD @12 arm: the BPS patch identical");
        assert_eq!(u.tile_dims, h.tile_dims, "UHD @12 arm: the 482×272 grid unchanged");
        assert_eq!(u.lut, h.lut, "UHD @12 arm: the LUT identical");
        assert_eq!(u.compression, h.compression, "UHD @12 arm: the compression unchanged");
    }

 /// OG2K MODE grid geometry — the ds2x mode rows (the 
 /// measured contract — one integration table test per
    /// mode, the G4 pattern): the 1008×672 ds2x gate (the OG2K
    /// geometry's measured downscale2x output — 2016/2 × 1344/2) +
    /// its measured 3-member family + the per-depth grid inheritance
    /// (the source's OG2K depth-invariant 252×336 grid at 1008×672:
    /// 4×2 = 8 tiles at every depth — full-tile edge rows only, the
 /// measured no-half-row verdict) + the grid×mode-keyed family
    /// routing (the SAME 252×336 grids keep `OG2K_CANDIDATES` on the
    /// 2016×1344 lossless/log10 rows — NEVER a grid-only key; the
    /// unmeasured 482×272 grid at 1008×672 = the legacy family — the
    /// decode-side named refusal) + the `--fast` = the family's
    /// index-0 stream (W7 = the global `FAST_CANDIDATE` at this
    /// geometry — the byte-invariance pin) + the per-arm
    /// `TilePlan::downscale_gate` plans (@12/@10: 258 unchanged; @8:
    /// the identity promotion) + the UHD @12 arm byte-identical to the
    /// historical `TilePlan::lossless()` (the named mode control — the
 /// byte-invariance). LIVES IN THE WORKER TESTS (not tileenc.rs) so the
    /// commit's touch-set stays within the fence list (the G4
    /// pattern).
    #[test]
    fn og2k_ds2x_grid_geometry() {
        use crate::tileenc::{
            gate_candidates, gate_candidates_for_grid, gate_tile_dims_depth, is_og2k_ds2x_gate,
            tile_region, CANDIDATES, DS2X_OG2K_CANDIDATES, FAST_CANDIDATE, OG2K_CANDIDATES, Grid,
            Orient, DS2X_FHD_CANDIDATES, GATE_OG2K_DS2X_H, GATE_OG2K_DS2X_W,
        };
        // The gate constants + predicate:
        assert_eq!((GATE_OG2K_DS2X_W, GATE_OG2K_DS2X_H), (1008, 672), "the ds2x gate geometry (2016/2 × 1344/2)");
        assert!(is_og2k_ds2x_gate(1008, 672));
        assert!(!is_og2k_ds2x_gate(2016, 1344), "the full-res OG2K geometry is not the ds2x gate");
        assert!(!is_og2k_ds2x_gate(968, 545), "the FHD ds2x geometry is a different gate");
 // The measured family (the census — the 24/24-tile
        // ds2x corpus: W7 observed (1 tile in 4 frames) + W6 (3–6/
        // frame) + N5 (2–4/frame), ZERO outside → the 3-member set
 // EXACTLY — the decision (c): family = exactly the measured set;
        // contrast the FHD ds2x's 2-member set where W7 was never
        // observed):
        assert_eq!(DS2X_OG2K_CANDIDATES, [(Orient::Wrapped, 7), (Orient::Wrapped, 6), (Orient::Natural, 5)], "the measured ds2x family = the 3-member W7/W6/N5 set exactly (W7 observed — the census)");
        assert_eq!(DS2X_OG2K_CANDIDATES[0], FAST_CANDIDATE, "the ds2x fast stream = the family's index 0 (W7) = the global FAST_CANDIDATE");
        assert_eq!(FAST_CANDIDATE, OG2K_CANDIDATES[0], "the OG2K fast stream stays the global W7 (the byte-invariance pin)");
        assert_ne!(&DS2X_OG2K_CANDIDATES[..], &DS2X_FHD_CANDIDATES[..], "the OG2K ds2x family (3-member) != the FHD ds2x family (2-member)");
        // The per-depth grids (the source's OG2K depth-invariant grid —
        // the ds2x output inherits it — the measured contract):
        assert_eq!(gate_tile_dims_depth(2016, 1344, 12), (252, 336));
        assert_eq!(gate_tile_dims_depth(2016, 1344, 10), (252, 336));
        assert_eq!(gate_tile_dims_depth(2016, 1344, 8), (252, 336));
        // The 1008×672 grid: 4×2 = 8 tiles at every depth; the edge
        // tiles are FULL-tile rows (1008 = 4×252 exact, 672 = 2×336
 // exact — the measured no-half-row verdict):
        let g12 = Grid::for_dims(1008, 672, 252, 336);
        assert_eq!((g12.cols, g12.rows, g12.tw, g12.th), (4, 2, 252, 336), "ds2x @12: 4×2 = 8 tiles");
        let r10 = tile_region(1008, 672, &g12, 1, 0).unwrap();
        assert_eq!((r10.x0, r10.y0, r10.tw, r10.tl), (0, 336, 252, 336), "the bottom-row tile: FULL 336 content rows (no half-row class at OG2K)");
        // The family routing (the grid×mode key — the ds2x geometry IS
        // the mode key): 1008×672 on the 252×336 grid = the 3-member
        // DS2X family; the SAME 252×336 tile dimensions on the 2016×1344
        // lossless/log10 rows = `OG2K_CANDIDATES` (the family is NEVER
        // keyed on the grid alone); 1008×672 on any other grid = the
        // legacy family (NOT an eligible ds2x shape — the decode-side
        // named refusal — the 482×272 grid at 1008×672 is unmeasured,
        // the A+C boundary):
        assert_eq!(gate_candidates(1008, 672), DS2X_OG2K_CANDIDATES, "the encode-side routing: the ds2x gate → the DS2X family");
        assert_eq!(gate_candidates_for_grid(1008, 672, 252, 336), DS2X_OG2K_CANDIDATES, "1008×672 @ 252×336 → the DS2X family");
        assert_eq!(gate_candidates_for_grid(2016, 1344, 252, 336), OG2K_CANDIDATES, "the SAME 252×336 tile dims on the full-res geometry ride the OG2K family (NEVER a grid-only key)");
        assert_eq!(gate_candidates_for_grid(1008, 672, 482, 272), CANDIDATES, "the 482×272 grid at 1008×672 = the legacy family (the unmeasured shape — the decode-side named refusal)");
        // The per-arm plans (`TilePlan::downscale_gate`):
        let d12 = crate::surgery::TilePlan::downscale_gate(2016, 1344, 12);
        assert_eq!(d12.bps_patch, None, "@12: 258 unchanged (12)");
        assert_eq!(d12.tile_dims, (252, 336), "@12: the measured depth-invariant grid");
        let d10 = crate::surgery::TilePlan::downscale_gate(2016, 1344, 10);
        assert_eq!(d10.bps_patch, None, "@10: 258 unchanged (10)");
        assert_eq!(d10.tile_dims, (252, 336), "@10: the measured depth-invariant grid");
        let d8 = crate::surgery::TilePlan::downscale_gate(2016, 1344, 8);
        assert_eq!(d8.bps_patch, Some(10), "@8: 258 8→10 (the identity promotion)");
        assert_eq!(d8.tile_dims, (252, 336), "@8: the measured depth-invariant grid");
        // The UHD @12 arm = byte-identical to the historical
        // `TilePlan::lossless()` (the named mode control — the
 // byte-invariance):
        let u = crate::surgery::TilePlan::downscale_gate(3856, 2170, 12);
        let h = crate::surgery::TilePlan::lossless();
        assert_eq!(u.bps_patch, h.bps_patch, "UHD @12 arm: the BPS unchanged");
        assert_eq!(u.tile_dims, h.tile_dims, "UHD @12 arm: the 482×272 grid unchanged");
        assert_eq!(u.lut, h.lut, "UHD @12 arm: no LUT");
        assert_eq!(u.compression, h.compression, "UHD @12 arm: the compression unchanged");
        // The 3-member CandidateSet (the variable-length family): the
        // 1008×672 grid returns the 3-member streams; the 2016×1344
        // grid keeps its 3.
        let plane: Vec<u16> = (0..1008 * 672).map(|i| (i % 4096) as u16).collect();
        let rect00 = tile_region(1008, 672, &g12, 0, 0).unwrap();
        let (_t, (streams, sizes, best)) =
            crate::tileenc::encode_tile_candidates(&plane, 1008, 672, &g12, 0, 0, 12).unwrap();
        assert_eq!(streams.len(), 3, "the ds2x family = 3 members (W7 observed — the census)");
        assert_eq!(sizes.len(), 3, "the ds2x sizes = 3 members");
        assert!(best < 3, "the ds2x chosen index in the 3-member family");
        // `--fast` at the ds2x geometry = the measured family's index-0
        // stream (W7 = the global FAST_CANDIDATE — the global fast path
        // is byte-identical to the family's index-0 stream at this
        // geometry — the byte contract):
        let fast = crate::tileenc::encode_tile_fast(&plane, 1008, 672, &g12, 0, 0, 12).unwrap();
        assert_eq!(fast, streams[0], "--fast = the measured family's index-0 stream (W7) at the ds2x geometry");
        // The self-sourced plane re-encode round-trip (the drill's
        // acceptance machinery): the tool's pad plane, re-split by
        // `planes_from_tile_rows` + re-encoded by `encode_tile_planes`,
        // reproduces each candidate stream byte-exactly (the
        // deterministic engine on identical samples).
        for (i, &(orient, psv)) in DS2X_OG2K_CANDIDATES.iter().enumerate() {
            let p = crate::tileenc::planes_from_tile(&plane, 1008, 672, &g12, 0, 0, orient).unwrap();
            let full = crate::tileenc::tile_from_planes(&p).unwrap();
            let back = crate::tileenc::planes_from_tile_rows(&full, &rect00, g12.th, orient).unwrap();
            let re = crate::tileenc::encode_tile_planes(&back, 12, psv).unwrap();
            assert_eq!(re, streams[i], "candidate {i}: the self-sourced re-encode reproduces the stream byte-exactly");
        }
    }

 /// OG3K MODE grid geometry — the log10 mode rows (the 
 /// measured contract — the per-gate mode onboarding;
    /// one integration table test per mode, the G4 pattern): the 3024×2010
    /// gate's depth-invariant 252×252 grid at full resolution (12×8 = 96
    /// tiles at every depth; 3024 = 12×252 exact, 2010 = 7×252 + 246 —
    /// the bottom-row tiles are the 246-content-row half-row tiles on
    /// the 252-row plane, the odd-height interop shape) + the
    /// grid×mode-keyed family routing (the 252×252 grids carry the 3K
    /// family `CANDIDATES` on the 3024×2010 lossless/log10 rows — the
    /// measured members {W7, W2, N1}; the SAME 252×252 grids on the
    /// 1512×1005 ds2x geometry ride `DS2X_OG3K_CANDIDATES` — the mode is
    /// part of the family key, NEVER a grid-only key) + the `--fast` =
    /// the family's index-0 stream (W7 = the global `FAST_CANDIDATE`).
    /// LIVES IN THE WORKER TESTS (not tileenc.rs) so the commit's
    /// touch-set stays within the fence list (the G4 pattern).
    #[test]
    fn og3k_log10_grid_geometry() {
        use crate::tileenc::{
            gate_candidates, gate_candidates_for_grid, gate_tile_dims_depth, tile_region,
            CANDIDATES, DS2X_OG3K_CANDIDATES, FAST_CANDIDATE, GATE_3K_TILE_H, GATE_3K_TILE_W, Grid,
            Orient,
        };
        // The per-depth grids (the mode's grid = the source's OG3K depth-
        // invariant 252×252 grid at every depth — the measured contract):
        assert_eq!(gate_tile_dims_depth(3024, 2010, 12), (252, 252), "log10 @12: the depth-invariant 252×252 grid");
        assert_eq!(gate_tile_dims_depth(3024, 2010, 10), (252, 252), "log10 @10: the depth-invariant 252×252 grid");
        assert_eq!(gate_tile_dims_depth(3024, 2010, 8), (252, 252), "log10 @8: the depth-invariant 252×252 grid (no per-depth variant at OG3K)");
        assert_eq!((GATE_3K_TILE_W, GATE_3K_TILE_H), (252, 252), "the OG3K gate's measured tile dims");
        // Grid + tile count + edge geometry (12×8 = 96 tiles at every
        // depth; 3024 = 12×252 exact, 2010 = 7×252 + 246):
        let g12 = Grid::for_depth(3024, 2010, 12);
        assert_eq!((g12.cols, g12.rows, g12.tw, g12.th), (12, 8, 252, 252), "log10 @12: 12×8 = 96 tiles");
        let g10 = Grid::for_depth(3024, 2010, 10);
        assert_eq!((g10.cols, g10.rows, g10.tw, g10.th), (12, 8, 252, 252), "log10 @10: 12×8 = 96 tiles");
        let g8 = Grid::for_depth(3024, 2010, 8);
        assert_eq!((g8.cols, g8.rows, g8.tw, g8.th), (12, 8, 252, 252), "log10 @8: 12×8 = 96 tiles");
        // The bottom-row edge tile: the 246-content-row half-row tile
        // (7×252 = 1764, 2010 - 1764 = 246 — the odd-height interop
        // shape, the decode drill's content-rows-only semantics):
        let r7 = tile_region(3024, 2010, &g12, 7, 0).unwrap();
        assert_eq!((r7.y0, r7.tl), (1764, 246), "the bottom row: 7·252=1764, 2010-1764=246 (the half-row content)");
        // A full interior tile: FULL 252 content rows:
        let r0 = tile_region(3024, 2010, &g12, 0, 0).unwrap();
        assert_eq!((r0.x0, r0.y0, r0.tw, r0.tl), (0, 0, 252, 252), "the interior tile: FULL 252×252");
        // The family routing (the grid×mode key — the full-resolution
        // log10/lossless rows ride the 3K family `CANDIDATES`; the
        // measured members {W7, W2, N1}):
        assert_eq!(CANDIDATES, [(Orient::Wrapped, 7), (Orient::Wrapped, 2), (Orient::Natural, 1)], "the 3K family = the 3-member W7/W2/N1 set (the measured members)");
        assert_eq!(gate_candidates(3024, 2010), CANDIDATES, "the encode-side routing: the 3K gate → the 3K family");
        assert_eq!(gate_candidates_for_grid(3024, 2010, 252, 252), CANDIDATES, "3024×2010 @ 252×252 → the 3K family (the lossless/log10 rows)");
        // The grid×mode key: the SAME 252×252 tile dimensions on the
        // 1512×1005 ds2x geometry ride the DS2X family (NEVER a
        // grid-only key):
        assert_eq!(gate_candidates_for_grid(1512, 1005, 252, 252), DS2X_OG3K_CANDIDATES, "the SAME 252×252 tile dims on the ds2x geometry ride the DS2X family");
        // The `--fast` = the family's index-0 stream (W7 = the global
        // FAST_CANDIDATE at this geometry — the byte-invariance pin):
        assert_eq!(CANDIDATES[0], FAST_CANDIDATE, "the OG3K fast stream = the family's index 0 (W7) = the global FAST_CANDIDATE");
    }

 /// OG3K MODE grid geometry — the ds2x mode rows (the 
 /// measured contract — the per-gate mode onboarding;
    /// one integration table test per mode, the G4 pattern): the 1512×1005
    /// ds2x gate (the OG3K geometry's measured downscale2x output —
    /// 3024/2 × 2010/2) + its measured 3-member family + the per-depth
    /// grid inheritance (the source's OG3K depth-invariant 252×252 grid
    /// at 1512×1005: 6×4 = 24 tiles at every depth; 1512 = 6×252 exact,
    /// 1005 = 3×252 + 249 — the bottom-row tiles are the 249-content-row
    /// half-row tiles on the 252-row plane) + the grid×mode-keyed family
    /// routing (the SAME 252×252 grids keep `CANDIDATES` on the 3024×2010
    /// lossless/log10 rows — NEVER a grid-only key; the unmeasured 482×272
    /// grid at 1512×1005 = the legacy family — the decode-side named
    /// refusal) + the `--fast` = the family's index-0 stream (W7 = the
    /// global `FAST_CANDIDATE` at this geometry — the byte-invariance
    /// pin). LIVES IN THE WORKER TESTS (not tileenc.rs) so the commit's
    /// touch-set stays within the fence list (the G4 pattern).
    #[test]
    fn og3k_ds2x_grid_geometry() {
        use crate::tileenc::{
            gate_candidates, gate_candidates_for_grid, gate_tile_dims_depth, is_og3k_ds2x_gate,
            tile_region, CANDIDATES, DS2X_OG3K_CANDIDATES, FAST_CANDIDATE, Grid, Orient,
            GATE_OG3K_DS2X_H, GATE_OG3K_DS2X_W,
        };
        // The gate constants + predicate:
        assert_eq!((GATE_OG3K_DS2X_W, GATE_OG3K_DS2X_H), (1512, 1005), "the ds2x gate geometry (3024/2 × 2010/2)");
        assert!(is_og3k_ds2x_gate(1512, 1005));
        assert!(!is_og3k_ds2x_gate(3024, 2010), "the full-res OG3K geometry is not the ds2x gate");
        assert!(!is_og3k_ds2x_gate(1008, 672), "the OG2K ds2x geometry is a different gate");
        assert!(!is_og3k_ds2x_gate(968, 545), "the FHD ds2x geometry is a different gate");
 // The measured family (the census — the 24/24-tile
        // ds2x corpus: W7 observed (5–6 tiles/frame) + W2 + N1, ZERO
 // outside → the 3-member set EXACTLY — the decision (c); the same
        // members as the 3K lossless family `CANDIDATES` but the per-
        // gate provenance is separate: the ds2x 24/24-tile census vs the
        // lossless 576/576 + log10 864/864 censuses):
        assert_eq!(DS2X_OG3K_CANDIDATES, [(Orient::Wrapped, 7), (Orient::Wrapped, 2), (Orient::Natural, 1)], "the measured ds2x family = the 3-member W7/W2/N1 set exactly (the census)");
        assert_eq!(DS2X_OG3K_CANDIDATES[0], FAST_CANDIDATE, "the ds2x fast stream = the family's index 0 (W7) = the global FAST_CANDIDATE");
        assert_eq!(DS2X_OG3K_CANDIDATES, CANDIDATES, "the OG3K ds2x family = the same 3 members as the 3K lossless family (the separate provenance)");
        // The per-depth grids (the source's OG3K depth-invariant grid —
        // the ds2x output inherits it — the measured contract):
        assert_eq!(gate_tile_dims_depth(3024, 2010, 12), (252, 252));
        assert_eq!(gate_tile_dims_depth(3024, 2010, 10), (252, 252));
        assert_eq!(gate_tile_dims_depth(3024, 2010, 8), (252, 252));
        // The 1512×1005 grid: 6×4 = 24 tiles at every depth; the edge
        // tiles are the 249-content-row half-row tiles (1512 = 6×252
        // exact, 1005 = 3×252 + 249 — the odd-height interop shape):
        let g12 = Grid::for_dims(1512, 1005, 252, 252);
        assert_eq!((g12.cols, g12.rows, g12.tw, g12.th), (6, 4, 252, 252), "ds2x @12: 6×4 = 24 tiles");
        let r30 = tile_region(1512, 1005, &g12, 3, 0).unwrap();
        assert_eq!((r30.x0, r30.y0, r30.tw, r30.tl), (0, 756, 252, 249), "the bottom-row tile: 3·252=756, 1005-756=249 (the half-row content)");
        // The family routing (the grid×mode key — the ds2x geometry IS
        // the mode key): 1512×1005 on the 252×252 grid = the 3-member
        // DS2X family; the SAME 252×252 tile dimensions on the 3024×2010
        // lossless/log10 rows = `CANDIDATES` (the family is NEVER keyed
        // on the grid alone); 1512×1005 on any other grid = the legacy
        // family (NOT an eligible ds2x shape — the decode-side named
        // refusal — the 482×272 grid at 1512×1005 is unmeasured, the
        // A+C boundary):
        assert_eq!(gate_candidates(1512, 1005), DS2X_OG3K_CANDIDATES, "the encode-side routing: the ds2x gate → the DS2X family");
        assert_eq!(gate_candidates_for_grid(1512, 1005, 252, 252), DS2X_OG3K_CANDIDATES, "1512×1005 @ 252×252 → the DS2X family");
        assert_eq!(gate_candidates_for_grid(3024, 2010, 252, 252), CANDIDATES, "the SAME 252×252 tile dims on the full-res geometry ride the 3K family (NEVER a grid-only key)");
        assert_eq!(gate_candidates_for_grid(1512, 1005, 482, 272), CANDIDATES, "the 482×272 grid at 1512×1005 = the legacy family (the unmeasured shape — the decode-side named refusal)");
        // The `--fast` = the family's index-0 stream (W7 = the global
        // FAST_CANDIDATE at this geometry — the byte-invariance pin):
        assert_eq!(DS2X_OG3K_CANDIDATES[0], FAST_CANDIDATE, "the OG3K ds2x fast stream = the family's index 0 (W7) = the global FAST_CANDIDATE");
    }

 /// UHD MODE grid geometry — the log10 mode rows (the 
 /// measured contract — — one integration table
    /// test per mode, the G4 pattern): the log10 mode's measured grid /
    /// BPS / 50712 mechanics per depth arm, asserted on the routing
    /// machinery (the per-depth grid via `gate_tile_dims_depth` — the
    /// mode's grid = the per-depth lossless grid — the per-depth
 /// inheritance, : 964×272 @10, 482×272 @8; the family =
    /// the gate's existing `CANDIDATES` routing — the measured {W7,
 /// W2, N1} on BOTH grids — the censuses 96/96 + 192/192,
    /// ZERO 0 · MULTI 0 — W6/N5 never observed; the per-arm
    /// `TilePlan::log10_gate` plans: @10 = the raw passthrough (no BPS
    /// patch, no LUT — the measured maxdiff 0); @8 = the identity
    /// promotion (258 8→10, the native 256-entry 50712 CARRIED —
    /// `lut: None`)). LIVES IN THE WORKER TESTS (not tileenc.rs) so
    /// the commit's touch-set stays within the fence list (the G4
    /// pattern).
    #[test]
    fn uhd_log10_grid_geometry() {
        use crate::tileenc::{gate_candidates_for_grid, gate_tile_dims_depth, Grid, CANDIDATES};
        // The per-depth grids (the mode's grid = the per-depth
        // lossless grid — the measured contract — the per-depth
 // inheritance, ):
        assert_eq!(gate_tile_dims_depth(3856, 2170, 10), (964, 272), "log10 @10: the 964×272 grid");
        assert_eq!(gate_tile_dims_depth(3856, 2170, 8), (482, 272), "log10 @8: the 482×272 grid (the measured per-depth rule)");
        // Grid + tile count + edge geometry:
        let g10 = Grid::for_depth(3856, 2170, 10);
        assert_eq!((g10.cols, g10.rows, g10.tw, g10.th), (4, 8, 964, 272), "log10 @10: 4×8 = 32 tiles");
        let g8 = Grid::for_depth(3856, 2170, 8);
        assert_eq!((g8.cols, g8.rows, g8.tw, g8.th), (8, 8, 482, 272), "log10 @8: 8×8 = 64 tiles");
        // The bottom-row half-row tile (266 content rows on the 272-row
        // plane — the odd-height shape at the full 272 geometry — the
 // lossless class — the census: single-match every
        // frame on the bottom-row tiles):
        let r70 = crate::tileenc::tile_region(3856, 2170, &g10, 7, 0).unwrap();
        assert_eq!((r70.y0, r70.tl), (1904, 266), "the edge row @10: 7·272=1904, 2170-1904=266");
        let r70b = crate::tileenc::tile_region(3856, 2170, &g8, 7, 0).unwrap();
        assert_eq!((r70b.y0, r70b.tl), (1904, 266), "the edge row @8: 7·272=1904, 2170-1904=266");
        assert_eq!(crate::tileenc::padded_tl_for(266, 272), 272, "the edge row's pad to the full 272 geometry");
        // The family = the gate's existing family routing (`CANDIDATES`
 // — the measured {W7, W2, N1} on BOTH grids — the censuses
        // 96/96 @964 + 192/192 @482, ZERO 0 · MULTI 0 — W6/N5 never
        // observed — the log10 rows ride the gate's family as the
        // FHD/OG2K pattern):
        assert_eq!(gate_candidates_for_grid(3856, 2170, 964, 272), CANDIDATES, "log10 @10: the 964×272 grid rides the gate family");
        assert_eq!(gate_candidates_for_grid(3856, 2170, 482, 272), CANDIDATES, "log10 @8: the 482×272 grid rides the gate family");
        // The per-arm plans (`TilePlan::log10_gate`):
        let p10 = crate::surgery::TilePlan::log10_gate(3856, 2170, 10);
        assert_eq!(p10.bps_patch, None, "@10: 258 unchanged (the raw 10-bit passthrough — the measured maxdiff 0)");
        assert_eq!(p10.tile_dims, (964, 272), "@10: the 964×272 grid");
        assert_eq!(p10.lut, None, "@10: NO 50712 (the measured ABSENT)");
        let p8 = crate::surgery::TilePlan::log10_gate(3856, 2170, 8);
        assert_eq!(p8.bps_patch, Some(10), "@8: 258 8→10 (the identity promotion)");
        assert_eq!(p8.tile_dims, (482, 272), "@8: the 482×272 grid");
        assert_eq!(p8.lut, None, "@8: the native 256-entry 50712 CARRIED (never a second 50712)");
    }

 /// UHD MODE grid geometry — the ds2x mode rows (the 
 /// measured contract — — one integration table
    /// test per mode, the G4 pattern): the ds2x mode's measured
    /// 1928×1085 gate — the geometry constants + predicate, the per-
    /// depth grids (the source's UHD per-depth grid via
    /// `gate_tile_dims_depth` — the per-depth inheritance — 964×272
    /// @10 → 2×4 = 8 tiles, 482×272 @8 → 4×4 = 16 tiles), the 269-
    /// content-row bottom-row tiles (1085 = 3×272 + 269 at BOTH grids
    /// — the odd-height interop shape — the decode drill's content-
 /// rows-only semantics, the decision (b)), the GRID-
    /// KEYED DS2X families (the FIRST ds2x geometry with TWO measured
    /// grids — the grid IS in the family key: the 964×272 grid →
    /// `DS2X_UHD_964_CANDIDATES` the 2-member {W2, N1} — W7 never
 /// observed — the census 24/24; the 482×272 grid →
 /// `DS2X_UHD_482_CANDIDATES` the 3-member {W7, W2, N1} — the 
    /// census 48/48; the SAME 964/482×272 tile dimensions on the
    /// 3856×2170 full-res rows ride `CANDIDATES` — the family is
    /// NEVER keyed on the grid or the geometry alone), the `--fast` =
    /// the family's index-0 stream (W2 at the 964 grid — the ONLY ds2x
    /// geometry where the `--fast` stream ≠ the global W7 — the FHD ds2x W6 pattern; W7 at the 482 grid = the global), and
    /// the per-arm `TilePlan::downscale_gate` plans (@10: 258
    /// unchanged; @8: the identity promotion). LIVES IN THE WORKER
    /// TESTS (not tileenc.rs) so the commit's touch-set stays within
    /// the fence list (the G4 pattern).
    #[test]
    fn uhd_ds2x_grid_geometry() {
        use crate::tileenc::{
            gate_candidates_for_grid, gate_tile_dims_depth, is_uhd_ds2x_gate,
            tile_region, CANDIDATES, DS2X_UHD_482_CANDIDATES, DS2X_UHD_964_CANDIDATES,
            FAST_CANDIDATE, Grid, Orient, GATE_UHD_DS2X_H, GATE_UHD_DS2X_W,
        };
        // The gate constants + predicate:
        assert_eq!((GATE_UHD_DS2X_W, GATE_UHD_DS2X_H), (1928, 1085), "the ds2x gate geometry (3856/2 × 2170/2)");
        assert!(is_uhd_ds2x_gate(1928, 1085));
        assert!(!is_uhd_ds2x_gate(3856, 2170), "the full-res UHD geometry is not the ds2x gate");
        assert!(!is_uhd_ds2x_gate(968, 545), "the FHD ds2x geometry is a different gate");
 // The measured families (the censuses — the decision
        // (c): the measured family EXACTLY):
        assert_eq!(DS2X_UHD_964_CANDIDATES, [(Orient::Wrapped, 2), (Orient::Natural, 1)], "ds2x @10 (the 964 grid): the measured 2-member W2/N1 family EXACTLY (W7 never observed — the superset rejected)");
        assert_ne!(DS2X_UHD_964_CANDIDATES[0], FAST_CANDIDATE, "the ds2x @10 fast stream ≠ the global W7 (the FHD ds2x W6 pattern — the ONLY ds2x geometry where --fast ≠ W7)");
        assert_eq!(DS2X_UHD_482_CANDIDATES, [(Orient::Wrapped, 7), (Orient::Wrapped, 2), (Orient::Natural, 1)], "ds2x @8 (the 482 grid): the measured 3-member W7/W2/N1 family EXACTLY (W7 observed on the ds2x-@8 corpus)");
        assert_eq!(DS2X_UHD_482_CANDIDATES, CANDIDATES, "the 482-grid ds2x family = the same 3 members as the legacy 482 family (the separate per-gate ds2x provenance)");
        // The per-depth grids (the source's UHD per-depth grid — the
        // per-depth inheritance — the ds2x output inherits it — the
        // measured contract):
        assert_eq!(gate_tile_dims_depth(3856, 2170, 10), (964, 272), "ds2x @10: the 964×272 grid");
        assert_eq!(gate_tile_dims_depth(3856, 2170, 8), (482, 272), "ds2x @8: the 482×272 grid");
        // The 1928×1085 grids: 2×4 = 8 tiles @10, 4×4 = 16 tiles @8;
        // the bottom-row tiles are the 269-content-row half-row tiles
        // (1085 = 3×272 + 269 at both grids — the odd-height interop
        // shape):
        let g10 = Grid::for_dims(1928, 1085, 964, 272);
        assert_eq!((g10.cols, g10.rows, g10.tw, g10.th), (2, 4, 964, 272), "ds2x @10: 2×4 = 8 tiles (1928 = 2×964 exact)");
        let g8 = Grid::for_dims(1928, 1085, 482, 272);
        assert_eq!((g8.cols, g8.rows, g8.tw, g8.th), (4, 4, 482, 272), "ds2x @8: 4×4 = 16 tiles (1928 = 4×482 exact)");
        let r30 = tile_region(1928, 1085, &g10, 3, 0).unwrap();
        assert_eq!((r30.x0, r30.y0, r30.tw, r30.tl), (0, 816, 964, 269), "the bottom-row tile @10: 3·272=816, 1085-816=269 (the half-row content)");
        let r30b = tile_region(1928, 1085, &g8, 3, 3).unwrap();
        assert_eq!((r30b.x0, r30b.y0, r30b.tw, r30b.tl), (1446, 816, 482, 269), "the bottom-row tile @8: 3·482=1446, 3·272=816, 1085-816=269");
        // The family routing (the grid×mode×GRID key — the first ds2x
        // geometry with TWO measured grids): 1928×1085 on the 964×272
        // grid = the 2-member family; on the 482×272 grid = the 3-
        // member family; the SAME 964/482×272 tile dimensions on the
        // 3856×2170 full-res rows ride `CANDIDATES` (the family is
        // NEVER keyed on the grid or the geometry alone):
        assert_eq!(gate_candidates_for_grid(1928, 1085, 964, 272), DS2X_UHD_964_CANDIDATES, "1928×1085 @ 964×272 → the 2-member ds2x family");
        assert_eq!(gate_candidates_for_grid(1928, 1085, 482, 272), DS2X_UHD_482_CANDIDATES, "1928×1085 @ 482×272 → the 3-member ds2x family");
        assert_eq!(gate_candidates_for_grid(3856, 2170, 964, 272), CANDIDATES, "the SAME 964×272 tile dims on the full-res geometry ride the gate family (NEVER a grid-only key)");
        assert_eq!(gate_candidates_for_grid(3856, 2170, 482, 272), CANDIDATES, "the SAME 482×272 tile dims on the full-res geometry ride the gate family (NEVER a grid-only key)");
        // The `--fast` = the family's index-0 stream (W2 at the 964
        // grid — the byte contract at this geometry; W7 at the 482
        // grid = the global FAST_CANDIDATE — the OG2K/OG3K ds2x
        // pattern):
        assert_eq!(DS2X_UHD_964_CANDIDATES[0], (Orient::Wrapped, 2), "the ds2x @10 fast stream = the family's index 0 (W2)");
        assert_eq!(DS2X_UHD_482_CANDIDATES[0], FAST_CANDIDATE, "the ds2x @8 fast stream = the family's index 0 (W7) = the global FAST_CANDIDATE");
        // The per-arm plans (`TilePlan::downscale_gate`):
        let p10 = crate::surgery::TilePlan::downscale_gate(3856, 2170, 10);
        assert_eq!(p10.bps_patch, None, "@10: 258 unchanged (10)");
        assert_eq!(p10.tile_dims, (964, 272), "@10: the 964×272 grid (the per-depth inheritance)");
        let p8 = crate::surgery::TilePlan::downscale_gate(3856, 2170, 8);
        assert_eq!(p8.bps_patch, Some(10), "@8: 258 8→10 (the identity promotion)");
        assert_eq!(p8.tile_dims, (482, 272), "@8: the 482×272 grid (the per-depth inheritance)");
    }
    // =====================================================================
    // Item 123 — the transcode row + the policy-matrix completion (R4,
    // R5, R7).
    // =====================================================================

    /// R4 + R5 — the FULL 16-cell policy matrix pinned (one named
    /// test): the four classes × the four rows (lossless / log10 /
    /// lossy (VbrHq) / downscale2x) × BOTH `--carry` values. The
    /// ruling cell (fp-camera × lossless) flips with the flag
    /// (Transcode by default — the R0 ruling; Carry under the explicit
    /// opt-in); the other 15 cells are carry-invariant (the flag is a
    /// no-op outside the fp-camera class — the raw-only behavior is
    /// untouched by construction). jxl × mixed = N/A (verified at the
    /// lane: `jxl.rs` carries ZERO frameclass/policy references — the
    /// jxl tier never reaches the class × mode table; the named N/A,
    /// not an unasserted cell). The R5 8-bit fp row: the synthetic
    /// 8-bit fp-shape fixture (the 512×368 × 48 fingerprint at bps 8
    /// — the 8-bit camera variant, no corpus on disk) classifies
    /// `Unknown` and refuses NAMED with the existing unknown-row
    /// wording (never a misclassification into the 12-bit arm — the
    /// classifier's bps-12 pin, the R5 refusal pin); the 12-bit
    /// fingerprint still classifies the fp class (zero-drift).
    #[test]
    fn kat_policy_matrix_completion() {
        use crate::frameclass as fc;
        // The 16 cells × both carry values (the pinned matrix).
        for carry in [false, true] {
            // raw: Encode on every row (carry-invariant — the flag is
            // a no-op outside the fp-camera class).
            for (mode, ds) in [
                (Mode::Lossless, false),
                (Mode::Log10, false),
                (Mode::VbrHq, false),
                (Mode::Lossless, true),
            ] {
                assert_eq!(
                    policy(fc::FrameClass::RawUncompressed, mode, ds, carry),
                    FramePolicy::Encode,
                    "raw × ({mode:?}, ds {ds}, carry {carry}): the raw class encodes on every row (byte-frozen, carry-invariant)"
                );
            }
            // fp-camera: the ruling cell + the v1 boundary rows.
            assert_eq!(
                policy(fc::FrameClass::FpCameraLossless, Mode::Lossless, false, carry),
                if carry { FramePolicy::Carry } else { FramePolicy::Transcode },
                "fp × lossless × carry {carry}: the R0 ruling cell (Transcode by default, Carry under the explicit opt-in)"
            );
            for (mode, ds) in [
                (Mode::Log10, false),
                (Mode::VbrHq, false),
                (Mode::Lossless, true),
            ] {
                assert_eq!(
                    policy(fc::FrameClass::FpCameraLossless, mode, ds, carry),
                    FramePolicy::RefuseNamed,
                    "fp × ({mode:?}, ds {ds}) × carry {carry}: the v1 boundary row (the log10/ds2x × mixed-as-Transcode rows are LATER, not item 123)"
                );
            }
            // archive + unknown: RefuseNamed on every row (carry-invariant).
            for cls in [
                fc::FrameClass::FramePrismArchive,
                fc::FrameClass::Unknown,
            ] {
                for (mode, ds) in [
                    (Mode::Lossless, false),
                    (Mode::Log10, false),
                    (Mode::VbrHq, false),
                    (Mode::Lossless, true),
                ] {
                    assert_eq!(
                        policy(cls, mode, ds, carry),
                        FramePolicy::RefuseNamed,
                        "{cls:?} × ({mode:?}, ds {ds}) × carry {carry}: the pinned named refusal (carry-invariant)"
                    );
                }
            }
        }
        // The v1 boundary refusal wordings (byte-pinned, unchanged):
        assert_eq!(
            refusal_line(
                fc::FrameClass::FramePrismArchive,
                &fc::FrameStructure {
                    compression: Some(7),
                    width: Some(3856),
                    height: Some(2170),
                    bits_per_sample: Some(12),
                    tile_width: Some(482),
                    tile_height: Some(272),
                    tile_count: Some(64),
                    tiled: true,
                },
                "f.DNG",
                Mode::Lossless,
                false
            ),
            Some(fc::frameprism_archive_line("f.DNG")),
            "the archive-class refusal wording (byte-pinned)"
        );
        assert_eq!(
            refusal_line(
                fc::FrameClass::FpCameraLossless,
                &fc::FrameStructure {
                    compression: Some(7),
                    width: Some(3856),
                    height: Some(2170),
                    bits_per_sample: Some(12),
                    tile_width: Some(512),
                    tile_height: Some(368),
                    tile_count: Some(48),
                    tiled: true,
                },
                "f.DNG",
                Mode::Log10,
                false
            ),
            Some(fc::fp_camera_mode_line("log10", "f.DNG")),
            "the fp-camera mode-row refusal wording (byte-pinned)"
        );
        // R5 — the 8-bit fp row (the refusal pin): the same 512×368 ×
        // 48 fingerprint at bps 8 is NOT the fp-camera class (the
        // measured arm is 12-bit; the 8-bit variant — the 59-tag +
        // 50712×256 variant, no corpus on disk — is the named
        // refusal, never the arm).
        let fp12 = fc::FrameStructure {
            compression: Some(7),
            width: Some(3856),
            height: Some(2170),
            bits_per_sample: Some(12),
            tile_width: Some(512),
            tile_height: Some(368),
            tile_count: Some(48),
            tiled: true,
        };
        assert_eq!(
            fc::classify_structure(&fp12),
            fc::FrameClass::FpCameraLossless,
            "the 12-bit fp fingerprint classifies the fp class (zero-drift)"
        );
        let fp8 = fc::FrameStructure {
            bits_per_sample: Some(8),
            ..fp12
        };
        assert_eq!(
            fc::classify_structure(&fp8),
            fc::FrameClass::Unknown,
            "the 8-bit fp-shape fixture (R5): Unknown, never the 12-bit arm"
        );
        assert_eq!(
            refusal_line(fc::FrameClass::Unknown, &fp8, "f.DNG", Mode::Lossless, false),
            Some(fc::unknown_tile_grid_line(Some(512), Some(368), Some(48), "f.DNG")),
            "the 8-bit fp row refuses NAMED with the existing unknown-row wording (byte-pinned)"
        );
    }

    /// R7.2 — the transcode round-trip corpus KAT: the f000001
    /// transcode through the ruling default → the output is a VALID
    /// ARCHIVE FRAME (482×272 × 64, 259 = 7) + decode(output) ==
    /// decode(input) PIXEL-EXACT (the transcode-fidelity check the
    /// verify pass runs in `encode_core`) + the canary plane
    /// re-asserted on the OUTPUT plane (the item-120/122 pins,
    /// re-derived here on the transcoded output — a delta is a STOP
    /// finding) + the provenance row (the `transcoded` action, the
    /// D4 vocabulary) + the resume-skip semantics (the re-run with
    /// `--resume` + the checksums sidecar: the transcoded rows skip
    /// via the existing output-sha row mechanism, the output bytes
    /// unchanged). Corpus-conditional (the mirrored A001_013).
    #[test]
    fn kat_transcode_roundtrip_corpus() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        let input = std::path::Path::new("../testdata/originals/A001_013");
        let fpsrc = input.join("A001_013_20260930_000001.DNG");
        if !fpsrc.is_file() {
            eprintln!("skip: no A001_013 testdata corpus");
            return;
        }
        camera_profile_override();
        crate::worker::set_subset_flag(true);
        crate::worker::set_carry_flag(false); // the ruling default (explicit — the corpus KAT)
        // The in-process profile set (the camera identity's
        // resolution — the override slot).
        let profiles = crate::camera::resolve_profiles().expect("the profile set resolves");
        let src_bytes = std::fs::read(&fpsrc).expect("the corpus frame reads");
        // The temp input root with the clip subdir (the report's clip
        // key = the relpath's parent — a flat input root would write
        // the dotfile report, not the `A001_013`-keyed one):
        let tmp0 = std::env::temp_dir().join(format!("frameprism-transcode-{}", std::process::id()));
        let in_root = tmp0.join("in");
        let clip_src = input;
        let _ = std::fs::remove_dir_all(&tmp0);
        std::fs::create_dir_all(in_root.join("A001_013")).unwrap();
        for f in ["A001_013_20260930_000001.DNG", "A001_013_20260930_000002.DNG", "A001_013_20260930_000723.DNG"] {
            std::fs::copy(clip_src.join(f), in_root.join("A001_013").join(f)).unwrap();
        }
        let input = &in_root;
        // (a) The transcode encode (verify ON — the archive drill +
        // the transcode-fidelity check ride in the encode).
        let mf = encode_frame_memory(
            &fpsrc,
            true,
            Mode::Lossless,
            false,
            false,
            LossyFormat::K34892,
            &ReferenceDctOpts::default(),
            None,
            Some(&profiles),
            false, // carry = the ruling default (the transcode)
        )
        .expect("the f000001 transcode encodes (the ruling default)");
        assert_eq!(
            mf.in_bytes,
            src_bytes.len() as u64,
            "the transcoded frame's honest input size = the fp source's bytes (NOT the synthetic seam's buffer)"
        );
        let out = mf.bytes.clone();
        // (b) The output is a VALID ARCHIVE FRAME (the tool's
        // measured archive contract — the 482×272 × 64 grid, 259 = 7):
        let meta = crate::tiff::read_meta(&out).expect("the transcoded output reads (the archive surface)");
        let e = meta.endianness;
        let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
        assert_eq!(e.u16(&find(259).expect("259 present").value_raw), 7, "the output Compression = 7 (the archive contract)");
        assert_eq!(e.u16(&find(258).expect("258 present").value_raw), 12, "the output BPS = 12 (the fp domain)");
        assert_eq!(e.u32(&find(322).expect("322 present").value_raw), 482, "the output TileWidth = 482 (the archive grid)");
        assert_eq!(e.u32(&find(323).expect("323 present").value_raw), 272, "the output TileLength = 272 (the archive grid)");
        assert_eq!(find(324).expect("324 present").count, 64, "the output tile count = 64 (the 482×272 × 3856×2170 grid)");
        // (c) The transcode-fidelity: decode(output) == decode(input)
        // PIXEL-EXACT (the item-122 decode on both — the archive drill
        // on the output rides inside).
        let (w_in, h_in, p_in) = crate::decode::decode_j92_frame(&src_bytes, "fp-in").expect("the fp input decodes (the item-122 path)");
        let (w_out, h_out, p_out) = crate::decode::decode_j92_frame(&out, "fp-out").expect("the transcoded output decodes (the archive path)");
        assert_eq!((w_in, h_in), (3856, 2170), "the fp input geometry");
        assert_eq!((w_out, h_out), (3856, 2170), "the output geometry (the UHD readout)");
        assert_eq!(p_in, p_out, "the transcode is pixel-exact: decode(output) == decode(input)");
        // (d) The canary plane re-asserted on the OUTPUT plane (the
        // item-120/122 pins — re-declared here on the transcoded
        // output; a delta is a STOP finding):
        const FP_PIN_MIN: u16 = 256;
        const FP_PIN_MAX: u16 = 4095;
        const FP_PIN_MEAN: f64 = 676.7750905883703;
        const FP_PIN_CFA_R0C0: f64 = 627.019415300536;
        const FP_PIN_CFA_R0C1: f64 = 788.8449011617776;
        const FP_PIN_CFA_R1C0: f64 = 789.4640331509698;
        const FP_PIN_CFA_R1C1: f64 = 501.6323602065808;
        let mn = p_out.iter().min().copied().unwrap_or(u16::MAX);
        let mx = p_out.iter().max().copied().unwrap_or(0);
        assert_eq!((mn, mx), (FP_PIN_MIN, FP_PIN_MAX), "the transcoded output's plane min/max drifted");
        let sum: u64 = p_out.iter().map(|v| *v as u64).sum();
        let mean = sum as f64 / p_out.len() as f64;
        assert!(
            ((FP_PIN_MEAN - 1.0)..(FP_PIN_MEAN + 1.0)).contains(&mean),
            "the transcoded output's plane mean {mean} drifted from ~{FP_PIN_MEAN}"
        );
        // The 2×2 CFA class means over the interior (the boundary
        // ring excluded — the item-122 canary's apples-to-apples form):
        let wz = 3856usize;
        let hz = 2170usize;
        let mut csum = [[0u64; 2]; 2];
        let mut ccount = [[0u64; 2]; 2];
        for y in 1..hz - 1 {
            for x in 1..wz - 1 {
                let i = y * wz + x;
                csum[y % 2][x % 2] += p_out[i] as u64;
                ccount[y % 2][x % 2] += 1;
            }
        }
        let cmean = |y: usize, x: usize| csum[y][x] as f64 / ccount[y][x] as f64;
        for (got, want, label) in [
            (cmean(0, 0), FP_PIN_CFA_R0C0, "R0C0"),
            (cmean(0, 1), FP_PIN_CFA_R0C1, "R0C1"),
            (cmean(1, 0), FP_PIN_CFA_R1C0, "R1C0"),
            (cmean(1, 1), FP_PIN_CFA_R1C1, "R1C1"),
        ] {
            assert!(
                ((want - 0.5)..(want + 0.5)).contains(&got),
                "the transcoded output's CFA {label} mean {got} drifted from ~{want}"
            );
        }
        // (e) The provenance row + the resume-skip: the 3-frame mixed
        // clip through the encode run (the ruling default) — the fp
        // rows are the `transcoded` action (the D4 vocabulary); the
        // re-run with `--resume` + the checksums sidecar skips every
        // row (the transcoded rows via the existing output-sha row
        // mechanism) with the output bytes unchanged.
        // NOTE the sticky flag sets: `set_subset_flag` (the item-121
        // documented sticky set — safe: no test asserts continuity
        // via process_dir) + `resume::set_flag(true)` (the ONCE
        // semantics — set TRUE here, never false: a fresh-dir resume
        // run is a full re-encode (no sidecar → nothing skips, the
        // documented semantics), so run (1) below is fresh-equivalent
        // under the flag; no existing test asserts the run report's
        // `resumed` line, and a resume scan over a sidecar-less
        // output is behaviorally a no-op for the fresh-dir tests —
        // the analysis recorded in the lane report).
        let out_dir = tmp0.join("out");
        crate::resume::set_flag(true);
        let rep1 = process_dir(
            input,
            &out_dir,
            true, // verify (the transcoded frames' verify = the archive drill + the transcode-fidelity check)
            false,
            1,
            Mode::Lossless,
            false,
            false,
            true, // checksums (the sidecar rows — the resume-skip's mechanism)
            LossyFormat::K34892,
            &ReferenceDctOpts::default(),
            None,
            false,
        )
        .expect("the mixed clip encodes (the ruling default)");
        assert_eq!(rep1.outcomes.len(), 3, "all 3 frames processed: {rep1:?}");
        assert!(
            rep1.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
            "all 3 Done under the ruling default (2 transcoded + 1 encoded): {rep1:?}"
        );
        // The fp outputs are NOT the source bytes (the transcode
        // re-encodes — the output differs from the source by design):
        for n in ["A001_013_20260930_000001.DNG", "A001_013_20260930_000723.DNG"] {
            let ob = std::fs::read(out_dir.join("A001_013").join(n)).expect("the fp output exists");
            let sb = std::fs::read(input.join("A001_013").join(n)).expect("the fp source exists");
            assert_ne!(ob, sb, "{n}: the transcoded output differs from its source (by design)");
        }
        // The provenance row (the per-clip report — captured BEFORE
        // the re-run's report rewrite): the `transcoded` action, the
        // source-sha column = the source's sha256.
        let report = std::fs::read_to_string(out_dir.join("A001_013.frameprism-report.md"))
            .expect("the per-clip report is written");
        let sha1 = crate::jxl::sha256_stream_path(
            input.join("A001_013").join("A001_013_20260930_000001.DNG").as_path(),
        ).expect("the source sha");
        assert!(
            report.contains(&format!("A001_013_20260930_000001.DNG\tfp-camera-lossless\ttranscoded\t{sha1}")),
            "the f000001 provenance row (class fp-camera-lossless, action transcoded, the source sha):\n{report}"
        );
        assert!(
            report.contains("class census: raw-uncompressed 1 (encoded 1 · carried 0) · fp-camera-lossless 2 (encoded 0 · carried 0 · transcoded 2)"),
            "the census line (the transcoded term):\n{report}"
        );
        // The resume-skip: the re-run (the flag is already on) —
        // every row skips via the sidecar's output-sha rows (the
        // transcoded rows included — the existing mechanism, no new
        // code), the output bytes unchanged.
        let before: std::collections::BTreeMap<String, Vec<u8>> = std::fs::read_dir(out_dir.join("A001_013"))
            .unwrap()
            .filter_map(|e| {
                let p = e.unwrap().path();
                let is_dng = p.extension().is_some_and(|x| x == "DNG");
                let name = p.file_name().map(|fn_| fn_.to_string_lossy().into_owned());
                is_dng.then_some(name).flatten().zip(std::fs::read(&p).ok())
            })
            .collect();
        let rep2 = process_dir(
            input,
            &out_dir,
            true,
            false,
            1,
            Mode::Lossless,
            false,
            false,
            true,
            LossyFormat::K34892,
            &ReferenceDctOpts::default(),
            None,
            false,
        )
        .expect("the re-run (resume) completes");
        assert_eq!(rep2.outcomes.len(), 3, "the re-run: all 3 rows accounted: {rep2:?}");
        assert!(
            rep2.outcomes.iter().all(|o| matches!(o, Outcome::Skipped { .. })),
            "the re-run with --resume skips every row (the transcoded rows via the output-sha row): {rep2:?}"
        );
        for (n, b) in &before {
            assert_eq!(
                std::fs::read(out_dir.join("A001_013").join(n)).expect("the output is still there"),
                *b,
                "{n}: the resume re-run left the output bytes unchanged"
            );
        }
        let _ = std::fs::remove_dir_all(&tmp0);
    }

    /// R7.3 — the 3-frame mixed clip under BOTH flag values + the
    /// dry-run both-estimates + the raw-only byte-freeze. (T)
    /// default: all 3 outputs archive-class, 0 carried — the census
    /// `fp-camera-lossless 2 (encoded 0 · carried 0 · transcoded 2)`;
    /// the fp provenance rows = `transcoded`. `--carry`: the 2 fp
    /// byte-exact + the 1 raw encoded — the item-121 structure, the
    /// census `(encoded 0 · carried 2)`. The dry-run reports BOTH
    /// estimates (both flag values — the md record's both-estimates
    /// line + the census line). The raw-only A001_001 clip under the
    /// default: the census line byte-identical to the item-121 form
    /// (the byte-freeze — no `both estimates` line, no `transcoded`
    /// term). Corpus-conditional.
    #[test]
    fn kat_transcode_clip_default_and_flag() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        let mixed = std::path::Path::new("../testdata/originals/A001_013");
        let raw = std::path::Path::new("../testdata/originals/A001_001");
        if !mixed.join("A001_013_20260930_000001.DNG").is_file() || !raw.join("A001_001_20260701_000001.DNG").is_file() {
            eprintln!("skip: no A001_013/A001_001 testdata corpus");
            return;
        }
        camera_profile_override();
        crate::worker::set_subset_flag(true); // the 3-frame A001_013 clip's FRAME_GAP (the documented sticky set)
        let tmp = std::env::temp_dir().join(format!("frameprism-transcode-flag-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // The temp input roots with the clip subdirs (the report's
        // clip key = the relpath's parent — a flat input root writes
        // the dotfile report, not the clip-keyed one):
        let in_mixed = tmp.join("in-mixed");
        let in_raw = tmp.join("in-raw");
        std::fs::create_dir_all(in_mixed.join("A001_013")).unwrap();
        std::fs::create_dir_all(in_raw.join("A001_001")).unwrap();
        for f in ["A001_013_20260930_000001.DNG", "A001_013_20260930_000002.DNG", "A001_013_20260930_000723.DNG"] {
            std::fs::copy(mixed.join(f), in_mixed.join("A001_013").join(f)).unwrap();
        }
        for f in ["A001_001_20260701_000001.DNG", "A001_001_20260701_000002.DNG", "A001_001_20260701_000003.DNG"] {
            std::fs::copy(raw.join(f), in_raw.join("A001_001").join(f)).unwrap();
        }
        let mixed = &in_mixed;
        let raw = &in_raw;
        // --- (T) the ruling default ---------------------------------
        crate::worker::set_carry_flag(false);
        let out_t = tmp.join("out-t");
        let rep_t = process_dir(
            mixed,
            &out_t,
            true,
            false,
            1,
            Mode::Lossless,
            false,
            false,
            false,
            LossyFormat::K34892,
            &ReferenceDctOpts::default(),
            None,
            false,
        )
        .expect("the mixed clip encodes (the ruling default)");
        assert!(
            rep_t.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
            "(T): all 3 Done: {rep_t:?}"
        );
        let report_t = std::fs::read_to_string(out_t.join("A001_013.frameprism-report.md")).expect("the report (T)");
        assert!(
            report_t.contains("class census: raw-uncompressed 1 (encoded 1 · carried 0) · fp-camera-lossless 2 (encoded 0 · carried 0 · transcoded 2)"),
            "(T): the census (2 transcoded, 0 carried):\n{report_t}"
        );
        for n in ["A001_013_20260930_000001.DNG", "A001_013_20260930_000723.DNG"] {
            assert!(
                report_t.contains(&format!("{n}\tfp-camera-lossless\ttranscoded\t")),
                "(T): the {n} provenance row (action transcoded):\n{report_t}"
            );
            // Every (T) output is in the measured archive contract
            // (the ruling: every output frame archive-class — the
            // 482×272 × 64 grid, 259 = 7):
            let ob = std::fs::read(out_t.join("A001_013").join(n)).expect("the (T) output exists");
            let om = crate::tiff::read_meta(&ob).expect("the (T) output reads");
            let oe = om.endianness;
            let ofind = |tag: u16| om.ifd0.entries.iter().find(|en| en.tag == tag);
            assert_eq!(oe.u16(&ofind(259).expect("259").value_raw), 7, "(T) {n}: Compression 7 (archive-class)");
            assert_eq!(oe.u32(&ofind(322).expect("322").value_raw), 482, "(T) {n}: the archive grid");
        }
        // --- the `--carry` opt-in ------------------------------------
        crate::worker::set_carry_flag(true);
        let out_c = tmp.join("out-c");
        let rep_c = process_dir(
            mixed,
            &out_c,
            true,
            false,
            1,
            Mode::Lossless,
            false,
            false,
            false,
            LossyFormat::K34892,
            &ReferenceDctOpts::default(),
            None,
            false,
        )
        .expect("the mixed clip encodes (--carry)");
        assert!(
            rep_c.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
            "(--carry): all 3 Done: {rep_c:?}"
        );
        let report_c = std::fs::read_to_string(out_c.join("A001_013.frameprism-report.md")).expect("the report (--carry)");
        assert!(
            report_c.contains("class census: raw-uncompressed 1 (encoded 1 · carried 0) · fp-camera-lossless 2 (encoded 0 · carried 2)"),
            "(--carry): the census (the item-121 structure — 2 carried):\n{report_c}"
        );
        for n in ["A001_013_20260930_000001.DNG", "A001_013_20260930_000723.DNG"] {
            assert_eq!(
                std::fs::read(out_c.join("A001_013").join(n)).expect("the carried output exists"),
                std::fs::read(mixed.join("A001_013").join(n)).expect("the source exists"),
                "(--carry) {n}: the fp output is the byte-exact source copy"
            );
            assert!(
                report_c.contains(&format!("{n}\tfp-camera-lossless\tcarried\t")),
                "(--carry): the {n} provenance row (action carried):\n{report_c}"
            );
        }
        // --- the dry-run BOTH estimates (both flag values) -----------
        let carried_bytes = std::fs::metadata(in_mixed.join("A001_013").join("A001_013_20260930_000001.DNG")).unwrap().len()
            + std::fs::metadata(in_mixed.join("A001_013").join("A001_013_20260930_000723.DNG")).unwrap().len();
        for (carry, tag) in [(false, "t"), (true, "c")] {
            let o = crate::dryrun::Opts {
                dest: tmp.join(format!("dry-{tag}")),
                k_override: None,
                report: Some(tmp.join(format!("dry-{tag}.md"))),
                mode: Mode::Lossless,
                lossy_format: LossyFormat::K34892,
                reference: ReferenceDctOpts::default(),
                downscale: false,
                fast: false,
                jobs: 2,
                carry,
                verify_flag: false,
            };
            let (verdict, rc) = crate::dryrun::estimate(mixed, &o);
            assert!(
                matches!(verdict, crate::dryrun::Verdict::Pass) && rc == 0,
                "the dry run passes (carry {carry}): {verdict:?} {rc}"
            );
            let md = std::fs::read_to_string(tmp.join(format!("dry-{tag}.md"))).expect("the dry-run record");
            assert!(
                md.contains(&format!("class census: A001_013 — raw-uncompressed 1 · fp-camera-lossless 2 (carried bytes {carried_bytes})")),
                "the dry-run census line (carry {carry}):\n{md}"
            );
            assert!(
                md.contains("both estimates (the mixed clip — carried vs transcoded: size)"),
                "the dry-run BOTH estimates line (carry {carry}):\n{md}"
            );
            if carry {
                assert!(
                    md.contains(&format!("projected carried (the fp-camera lossless frames — the byte copy, no re-encode): 2 frame(s) — {carried_bytes} B")),
                    "the carried line (the item-121 form, the --carry scenario):\n{md}"
                );
            } else {
                assert!(
                    md.contains(&format!("projected transcoded (the fp-camera lossless frames — the ruling default: the decode + the re-encode through the archive path): 2 frame(s) — {carried_bytes} B source")),
                    "the transcoded line (the ruling default scenario):\n{md}"
                );
            }
        }
        // --- the raw-only byte-freeze ---------------------------------
        crate::worker::set_carry_flag(false);
        let o = crate::dryrun::Opts {
            dest: tmp.join("dry-r"),
            k_override: None,
            report: Some(tmp.join("dry-r.md")),
            mode: Mode::Lossless,
            lossy_format: LossyFormat::K34892,
            reference: ReferenceDctOpts::default(),
            downscale: false,
            fast: false,
            jobs: 2,
            carry: false,
            verify_flag: false,
        };
        let (verdict, rc) = crate::dryrun::estimate(raw, &o);
        assert!(
            matches!(verdict, crate::dryrun::Verdict::Pass) && rc == 0,
            "the raw-only dry run passes: {verdict:?} {rc}"
        );
        let md = std::fs::read_to_string(tmp.join("dry-r.md")).expect("the raw-only record");
        assert!(
            md.contains("class census: A001_001 — raw-uncompressed 3 (carried bytes 0)"),
            "the raw-only census line (the item-121 form — byte-frozen):\n{md}"
        );
        assert!(
            !md.contains("both estimates"),
            "the raw-only record has NO both-estimates line (the plans coincide — the pre-contract shape):\n{md}"
        );
        assert!(
            !md.contains("transcoded"),
            "the raw-only record has NO transcoded term (byte-frozen):\n{md}"
        );
        // The encode-run byte-freeze surface (the census line under
        // the default — the raw-only clip's item-121 form):
        let out_r = tmp.join("out-r");
        let rep_r = process_dir(
            raw,
            &out_r,
            true,
            false,
            1,
            Mode::Lossless,
            false,
            false,
            false,
            LossyFormat::K34892,
            &ReferenceDctOpts::default(),
            None,
            false,
        )
        .expect("the raw-only clip encodes (byte-frozen)");
        assert!(
            rep_r.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
            "raw-only: all 3 Done: {rep_r:?}"
        );
        let report_r = std::fs::read_to_string(out_r.join("A001_001.frameprism-report.md")).expect("the raw-only report");
        assert!(
            report_r.contains("class census: raw-uncompressed 3 (encoded 3 · carried 0)"),
            "the raw-only census line (the item-121 form — byte-frozen):\n{report_r}"
        );
        assert!(
            !report_r.contains("frameclass — the per-frame provenance"),
            "the raw-only clip has NO provenance section (the R6 clause — byte-frozen):\n{report_r}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // =====================================================================
    // The item-124 KATs (the fp temporal-oracle class — the owner's
    // ruling (a)). The corpus = the `A001_013_miniclips` mirror (the
    // PM-prepared 124 KAT corpus — the three mini-clip sets + f279;
    // the 121/123 `A001_013` mirror stays the 3 standing frames and
    // is NEVER sampled/written by the 124 KATs). All three KATs hold
    // the `ENV_LOCK` (the corpus tests' serializing mutex) — the
    // thread-local oracle slot is touched only by the 124 surface
    // (the process_dir / the dry-run sample / these KATs) and is now
    // per-TEST-THREAD (the PM gate ruling — parallel KATs cannot
    // cross-set a slot even without the lock), so the
    // ENV_LOCK-held KATs are mutually exclusive by construction.
    // =====================================================================

    /// The pinned whole-body refusal wording (the 122 pin — the KATs'
    /// shared byte-pinned constant; the oracle adds acceptance, never
    /// a new or changed refusal line).
    const FP_WHOLE_BODY_REFUSAL: &str = "fp-camera tile prefix mismatch (the stored tile differs from the Natural-PSV1 re-encode OUTSIDE the measured bounded tail — the final data byte + its stuffing / the even-size 0x00 pad / the post-EOI 0x00 pad; a flip in the header or entropy prefix = corrupt stream; the fp bounded-tail restore-drill integrity check, the M0 RULING #1)";

    /// KAT 1 — `kat_fp_temporal_oracle_contract` (synthetic +
    /// corpus-conditional): (i) the NO-ctx invariance — the corpus
    /// f277 (a disputed frame) with no ctx set: the EXISTING named
    /// refusal, the wording byte-pinned (the 122 pin re-asserted at
    /// the 124 base); (ii) the BOUND unit pin — the accept
    /// predicate: max-delta 256 → accept, 257 → refuse (the exact
    /// boundary, synthetic planes, no corpus); (iii) the OUT-OF-
    /// BAND-NEIGHBOR safety — the synthetic clip {f277, f278, f279*}
    /// where f279* = the corpus f279 with its tile (5,4) stream
    /// replaced by the product's own re-encode of (f279's decoded
    /// tile (5,4) plane + a uniform offset (the spec's +500 — this
    /// corpus's tile re-encodes 1 byte over the slot for offsets
    /// 0–999, so the KAT takes the first of the ladder [500, 1000,
    /// 2000] whose re-encode fits: the layout's honesty, the
    /// out-of-band property = any offset ≥ 300 ≫ the bound),
    /// clamped 4095, 0x00-padded post-EOI to the original stream
    /// length — the measured inert pad class; the replaced tile is
    /// DRILL-VERIFIED — its re-encode is the canonical form of the
    /// offset plane — yet its plane is out of band): f277 transcodes
    /// REFUSED (the existing wording) — a verified neighbor must not
    /// rescue an out-of-band plane.
    #[test]
    fn kat_fp_temporal_oracle_contract() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        crate::worker::set_carry_flag(false);
        let miniclips = std::path::Path::new("../testdata/originals/A001_013_miniclips");
        let f277 = "A001_013_20260930_000277.DNG";
        let f278 = "A001_013_20260930_000278.DNG";
        let f279 = "A001_013_20260930_000279.DNG";
        if !miniclips.join(f277).is_file() || !miniclips.join(f278).is_file() {
            eprintln!("skip: no A001_013_miniclips testdata corpus");
            return;
        }
        // (i) The NO-ctx invariance (the decode verb + every KAT call
        // site: no ctx → the strict, byte-frozen path): f277 with the
        // slot explicitly cleared = the EXISTING named refusal,
        // tile (5,4), the wording byte-pinned (the 122 pin).
        crate::decode::set_fp_temporal_oracle(None);
        let buf277 = std::fs::read(miniclips.join(f277)).expect("the corpus f277 reads");
        let err = crate::decode::decode_j92_frame(&buf277, f277)
            .err()
            .expect("f277 with no ctx must refuse (the whole-body tile)");
        assert_eq!(
            err.to_string(),
            format!("{f277}: tile (5,4): {FP_WHOLE_BODY_REFUSAL}"),
            "the no-ctx refusal is the 122 wording, byte-identical: {err}"
        );
        // (ii) The BOUND unit pin (synthetic planes, no corpus): the
        // accept predicate's exact boundary — max-delta 256 accepts
        // (the bound is inclusive), 257 refuses; the plane-length
        // mismatch (a geometry anomaly) never accepts.
        let a: Vec<u16> = (0..(512 * 368)).map(|i| ((i * 7) % 4096) as u16).collect();
        let mut b = a.clone();
        b[1000] = (a[1000] as u32 + 256).min(4095) as u16;
        assert!(
            crate::decode::fp_temporal_in_band(&a, &b),
            "max-delta 256 = the bound: accept (the exact boundary)"
        );
        let mut c = a.clone();
        c[1000] = (a[1000] as u32 + 257).min(4095) as u16;
        assert!(
            !crate::decode::fp_temporal_in_band(&a, &c),
            "max-delta 257 > the bound: refuse (the exact boundary)"
        );
        assert!(
            !crate::decode::fp_temporal_in_band(&a, &b[..b.len() - 1]),
            "the plane-length mismatch NEVER accepts (the safe direction)"
        );
        assert_eq!(crate::decode::FP_TEMPORAL_MAX_DELTA, 256, "the pinned bound");
        // (iii) The OUT-OF-BAND-NEIGHBOR safety (corpus-conditional on
        // f279 — the PM's STOP-1 materialization in the mirror): the
        // synthetic neighbor f279* (the tile (5,4) stream swapped to
        // the product's own re-encode of the +500-offset plane —
        // drill-verified by construction, yet out of band) must NOT
        // rescue f277's disputed tile: the refusal stands.
        if !miniclips.join(f279).is_file() {
            eprintln!("skip (iii): no f279 in the miniclips mirror (the (i)/(ii) contract holds)");
            crate::decode::set_fp_temporal_oracle(None);
            return;
        }
        let buf279 = std::fs::read(miniclips.join(f279)).expect("the corpus f279 reads");
        // The f279* construction (the product's own seams — the
        // single-tile drill seam decodes + verifies the clean
        // neighbor's tile; the planes/re-encode seams build the
        // canonical form of the offset plane):
        let meta279 = crate::tiff::read_meta(&buf279).expect("f279 parses");
        let s279 = crate::frameclass::structure_from_ifd0(&meta279);
        assert_eq!(
            (s279.tile_width, s279.tile_height),
            (Some(512), Some(368)),
            "f279 is the fp camera's tile structure (the measured fingerprint)"
        );
        let (offs279, lens279) =
            crate::decode::tile_offsets_and_lens(&meta279, &buf279, f279).expect("f279's tiles read");
        let i44 = 5 * 8 + 4; // tile (r=5, c=4) of the 8-column grid = i 44
        let o44 = offs279[i44] as usize;
        let l44 = lens279[i44] as usize;
        let stored44 = &buf279[o44..o44 + l44];
        let grid = crate::tileenc::Grid::for_dims(3856, 2170, 512, 368);
        let rect = crate::tileenc::tile_region(3856, 2170, &grid, 5, 4).expect("the tile region");
        let full_rect = crate::tileenc::TileRect {
            tw: grid.tw,
            tl: grid.th,
            ..rect
        };
        let full = crate::decode::fp_verify_tile_full_nominal(
            stored44, 3856, 2170, &grid, 5, 4, 12, f279,
        )
        .expect("f279's tile (5,4) is drill-verified (the adjudication's clean fp frame)");
        // The uniform offset (clamped 4095) — the out-of-band
        // neighbor's plane. The offset's job is to be FAR past the
        // bound (the measured in-band max is ~63 — the rejection is
        // guaranteed for any offset ≥ 300: the worst-case plane
        // delta is offset − the in-band band ≫ 256; the spec's named
        // value = +500). The synthetic stream must also FIT the tile
        // slot (the 0x00 post-EOI pad is an append — the re-encode
        // never exceeds the original length): this corpus's tile (5,4)
        // re-encodes 1 byte OVER the camera's stored length for
        // offsets 0–999 (the camera's entropy tail is 1 byte leaner
        // — the bounded-tail class), so the KAT takes the first
        // offset of the ladder [500 (the spec's value), 1000, 2000]
        // whose canonical re-encode fits (deterministic on this
        // corpus — the layout's honesty, not a tuning knob).
        let mut off: Option<Vec<u16>> = None;
        let mut offset_used: u32 = 0;
        for off_v in [500u32, 1000, 2000] {
            let candidate: Vec<u16> = full
                .iter()
                .map(|&v| (v as u32 + off_v).min(4095) as u16)
                .collect();
            let planes = crate::tileenc::planes_from_tile_rows(
                &candidate, &full_rect, grid.th, crate::tileenc::Orient::Natural,
            )
            .expect("the offset plane's tile rows");
            let re = crate::tileenc::encode_tile_planes(&planes, 12, 1)
                .expect("the offset plane's canonical re-encode");
            if re.len() <= l44 {
                off = Some(candidate);
                offset_used = off_v;
                break;
            }
        }
        let off = off.unwrap_or_else(|| {
            panic!("no offset of the ladder [500, 1000, 2000] fits the tile slot (l44 = {l44}) — the corpus's entropy tail is anomalous")
        });
        assert!(
            offset_used >= 300,
            "the offset is out of band (the worst-case plane delta = offset − the in-band band ≫ 256): {offset_used}"
        );
        let planes = crate::tileenc::planes_from_tile_rows(
            &off, &full_rect, grid.th, crate::tileenc::Orient::Natural,
        )
        .expect("the offset plane's tile rows");
        let re = crate::tileenc::encode_tile_planes(&planes, 12, 1)
            .expect("the offset plane's canonical re-encode");
        assert!(
            re.len() <= l44,
            "the offset re-encode fits the tile slot: {} <= {l44}",
            re.len()
        );
        // The 0x00 post-EOI pad to the original stream length (the
        // measured inert pad class — the file length + the 325
        // lengths are unchanged by the swap):
        let mut new44 = re;
        new44.resize(l44, 0x00);
        let mut buf279s = buf279.clone();
        buf279s[o44..o44 + l44].copy_from_slice(&new44);
        // The scratch clip {f277, f278, f279*} (the clip subdirs —
        // the report's clip key = the relpath's parent):
        let tmp = std::env::temp_dir().join(format!("frameprism-oracle-contract-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let inp = tmp.join("in").join("A001_013");
        std::fs::create_dir_all(&inp).unwrap();
        std::fs::copy(miniclips.join(f277), inp.join(f277)).unwrap();
        std::fs::copy(miniclips.join(f278), inp.join(f278)).unwrap();
        std::fs::write(inp.join(f279), &buf279s).unwrap();
        let out = tmp.join("out");
        let rep = process_dir(
            &tmp.join("in"),
            &out,
            true,
            false,
            1,
            Mode::Lossless,
            false,
            false,
            false,
            LossyFormat::K34892,
            &ReferenceDctOpts::default(),
            None,
            false,
        )
        .expect("the synthetic clip runs (the f277 refusal is a per-frame Failed, not a run bail)");
        // f277 = the EXISTING named refusal (a verified neighbor must
        // NOT rescue an out-of-band plane — the bound is the oracle's
        // safety, not its goal):
        let o277 = rep
            .outcomes
            .iter()
            .find(|o| matches!(o, Outcome::Failed { file, .. } if file == f277))
            .expect("f277 must be the Failed outcome (the refusal stands)");
        let Outcome::Failed { error, .. } = o277 else {
            panic!("f277's outcome is the Failed variant (the named refusal): {o277:?}");
        };
        assert_eq!(
            error,
            &format!("{f277}: tile (5,4): {FP_WHOLE_BODY_REFUSAL}"),
            "the out-of-band-neighbor refusal is the EXISTING wording, byte-identical: {error}"
        );
        // f278 (raw) + f279* (fp, the swapped tile canonical by
        // construction) = Done (the clip's other frames are
        // unaffected — the oracle's scope is the disputed tile's
        // own frame):
        assert!(
            rep.outcomes.iter().filter(|o| matches!(o, Outcome::Done(_))).count() == 2,
            "f278 + f279* encode (the refusal is f277's alone): {rep:?}"
        );
        crate::decode::set_fp_temporal_oracle(None);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// KAT 2 — `kat_fp_temporal_oracle_corpus_clip` (corpus-conditional
    /// on the mirrored A001_013_miniclips): the three disputed-frame
    /// mini-clips (real consecutive frames, each TC/FRAME_GAP-
    /// conformant): {f275, f276, f277, f278} · {f285, f286, f287,
    /// f288} · {f393, f394, f395, f396} — the (T) default encode at
    /// the DEFAULT JOBS (jobs = 0 — the full rayon pool — the
    /// product's default encode configuration, the par_iter path):
    /// 4/4 processed, the disputed frame transcoded with the temporal-
    /// verified count = 1 (the adjudicated tile: (5,4)/(0,5)/(5,4));
    /// the default-jobs run is the REGRESSION PIN for the PM gate
    /// find (2026-10-01) — the oracle ctx slot is thread-local
    /// precisely so the parallel path passes (the original
    /// process-wide slot raced the sibling frames' set/clear on the
    /// pool threads and this clip refused 3/4 at the default jobs;
    /// the KAT's original jobs=1 contract had masked it — a re-
    /// introduced shared per-frame state fails this run loud);
    /// the census line carries `· temporal-verified 1`; the provenance
    /// row = `transcoded` + the source-sha (unchanged columns); the
    /// disputed output = a VALID ARCHIVE FRAME (the 482×272 grid, 259
    /// = 7, 258 = 12, 64 tiles) and decode(output) == the drill-
    /// decoded input plane PIXEL-EXACT (the transcode-fidelity check
    /// runs UNCHANGED); the 2 raw frames' outputs decode pixel-exact
    /// vs the raw strips; the DECODE verb on the disputed frame alone
    /// (no ctx) = the existing named refusal; the DRY-RUN over the
    /// 4-frame mini-clip (the worker's decision-1 ruling (a): k = 4 =
    /// the full sample — the disputed + both raw + the fp neighbor) =
    /// DRY RUN PASS (the sample transcodes via the oracle — verified
    /// via the fp neighbor; the both-estimates line present; the
    /// census carries the temporal-verified term) + the NO-NEIGHBOR
    /// PIN: the 2-frame clip {raw-neighbor, disputed} (frame-
    /// contiguous, ingest-conformant, NO fp neighbor) = the EXISTING
    /// named refusal stands (the resolver's None → the byte-identical
    /// wording — the oracle's boundary pinned on both sides).
    #[test]
    fn kat_fp_temporal_oracle_corpus_clip() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        crate::worker::set_carry_flag(false);
        let miniclips = std::path::Path::new("../testdata/originals/A001_013_miniclips");
        // The three mini-clips: [fp-clean, raw, fp-disputed, raw] +
        // the disputed frame's adjudicated tile (r, c) + the NO-
        // NEIGHBOR pair (raw-neighbor = the even ordinal, the
        // disputed = the odd):
        let clips: [(usize, usize, usize, usize, (u32, u32)); 3] = [
            (275, 276, 277, 278, (5, 4)),
            (285, 286, 287, 288, (0, 5)),
            (393, 394, 395, 396, (5, 4)),
        ];
        let name = |n: usize| format!("A001_013_20260930_{n:06}.DNG");
        for (fa, _raw_a, fd, fb, _) in &clips {
            if !miniclips.join(name(*fa)).is_file()
                || !miniclips.join(name(*fd)).is_file()
                || !miniclips.join(name(*fb)).is_file()
            {
                eprintln!("skip: no A001_013_miniclips testdata corpus");
                return;
            }
        }
        for (fa, raw_a, fd, fb, (dr, dc)) in clips {
            let n_fa = name(fa);
            let n_ra = name(raw_a);
            let n_fd = name(fd);
            let n_fb = name(fb);
            let tmp = std::env::temp_dir().join(format!("frameprism-oracle-clip-{fd}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&tmp);
            let in_root = tmp.join("in");
            let clip_dir = in_root.join("A001_013");
            std::fs::create_dir_all(&clip_dir).unwrap();
            for n in [&n_fa, &n_ra, &n_fd, &n_fb] {
                std::fs::copy(miniclips.join(n), clip_dir.join(n)).unwrap();
            }
            let out = tmp.join("out");
            // --- the (T) default encode (the ruling default — no
            // --carry): 4/4 processed, the disputed frame oracle-
            // verified via the fp neighbor (the temporal-verified
            // count = 1 — the adjudicated tile). THE DEFAULT JOBS
            // (jobs = 0 — the full rayon pool — the product's
            // default encode configuration, the par_iter path): the
            // regression pin for the PM gate find (2026-10-01) — the
            // oracle ctx slot is THREAD-LOCAL precisely so this
            // default-jobs run passes (the process-wide slot raced
            // the sibling frames' set/clear on the pool threads and
            // this clip refused 3/4; the KAT's original jobs=1
            // contract had masked it — the serial path only). If
            // shared per-frame state is ever re-introduced, this
            // run fails loud.
            let rep = process_dir(
                &in_root,
                &out,
                true,
                false,
                0, // the DEFAULT jobs (the full pool — the parallel path pinned)
                Mode::Lossless,
                false,
                false,
                false,
                LossyFormat::K34892,
                &ReferenceDctOpts::default(),
                None,
                false,
            )
            .expect("the 4-frame mini-clip encodes under the (T) default");
            assert!(
                rep.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
                "4/4 Done (the disputed frame transcodes via the oracle): {rep:?}"
            );
            let report =
                std::fs::read_to_string(out.join("A001_013.frameprism-report.md")).expect("the clip report");
            // The census line: the temporal-verified term (the
            // clip's oracle-verified whole-body tile count = 1 —
            // ONLY the disputed frame's adjudicated tile):
            assert!(
                report.contains(&format!(
                    "class census: raw-uncompressed 2 (encoded 2 · carried 0) · fp-camera-lossless 2 (encoded 0 · carried 0 · transcoded 2 · temporal-verified 1)"
                )),
                "the census carries `· temporal-verified 1` (the adjudicated tile only):\n{report}"
            );
            // The provenance: the disputed row = transcoded + the
            // source-sha (the unchanged columns) + the note clause:
            assert!(
                report.contains(&format!("{n_fd}\tfp-camera-lossless\ttranscoded\t")),
                "the disputed frame's provenance row (action transcoded):\n{report}"
            );
            assert!(
                report.contains("the temporal-verified tile's verify = the decoded plane matched the decoded same-class neighbor's tile plane within the pinned bound (FP_TEMPORAL_MAX_DELTA = 256 — the whole-body drill divergence, the item-124 class)"),
                "the provenance note clause is present:\n{report}"
            );
            // The disputed output = a VALID ARCHIVE FRAME (the
            // 482×272 grid, 259 = 7, 258 = 12, the 64-tile 324
            // count):
            let out_fd = std::fs::read(out.join("A001_013").join(&n_fd)).expect("the disputed output exists");
            let om = crate::tiff::read_meta(&out_fd).expect("the disputed output parses");
            let oe = om.endianness;
            let ofind = |tag: u16| om.ifd0.entries.iter().find(|en| en.tag == tag);
            assert_eq!(oe.u16(&ofind(259).expect("259").value_raw), 7, "the disputed output is Compression 7 (archive-class)");
            assert_eq!(oe.u16(&ofind(258).expect("258").value_raw), 12, "the disputed output is 12-bit");
            assert_eq!(oe.u32(&ofind(322).expect("322").value_raw), 482, "the archive grid");
            assert_eq!(oe.u32(&ofind(323).expect("323").value_raw), 272, "the archive grid");
            assert_eq!(ofind(324).expect("324").count, 64, "the 64-tile count (the 324 array's count field — the value is out-of-line)");
            // The transcode-fidelity check (UNCHANGED — the KAT's own
            // run of it): decode(output) == the drill-decoded input
            // plane, PIXEL-EXACT. The input's decode runs under the
            // oracle ctx (the encode path's own context — the
            // disputed tile is oracle-rescued; the KAT's resolver
            // clip = the scratch clip's frame list); the output's
            // decode runs with no ctx (the archive frame is
            // drill-clean — the strict path).
            let buf_fd = std::fs::read(clip_dir.join(&n_fd)).expect("the disputed source reads");
            let clip_list: Vec<(std::path::PathBuf, crate::frameclass::FrameClass, Option<u64>)> = vec![
                (format!("A001_013/{n_fa}").parse().unwrap(), crate::frameclass::FrameClass::FpCameraLossless, Some(fa as u64)),
                (format!("A001_013/{n_ra}").parse().unwrap(), crate::frameclass::FrameClass::RawUncompressed, Some(raw_a as u64)),
                (format!("A001_013/{n_fd}").parse().unwrap(), crate::frameclass::FrameClass::FpCameraLossless, Some(fd as u64)),
                (format!("A001_013/{n_fb}").parse().unwrap(), crate::frameclass::FrameClass::RawUncompressed, Some(fb as u64)),
            ];
            crate::decode::set_fp_temporal_oracle(Some(
                crate::worker::encode::fp_temporal_resolver(&in_root, &clip_list, &n_fd),
            ));
            let (w, h, plane_in) =
                crate::decode::decode_j92_frame(&buf_fd, &n_fd)
                    .expect("the disputed source decodes under the oracle ctx");
            crate::decode::set_fp_temporal_oracle(None);
            assert_eq!((w, h), (3856, 2170), "the fp frame's geometry");
            let (_, _, plane_out) =
                crate::decode::decode_j92_frame(&out_fd, &n_fd)
                    .expect("the disputed output decodes (the archive drill, no ctx)");
            assert_eq!(
                plane_in, plane_out,
                "transcode fidelity: decode(output) == the drill-decoded input plane, pixel-exact"
            );
            // The 2 raw outputs decode pixel-exact vs the raw strips
            // (the product's own seams: the tiff read + the strip
            // slice + the 12-bit unpack):
            for n_raw in [&n_ra, &n_fb] {
                let raw_src = std::fs::read(clip_dir.join(n_raw)).expect("the raw source reads");
                let rf = crate::tiff::read(&raw_src).expect("the raw frame parses");
                assert_eq!(rf.compression, 1, "the raw frame is Compression 1");
                let plane_raw = crate::pack12::unpack12(rf.strip_slice(&raw_src), rf.width, rf.height)
                    .expect("the raw strip unpacks (12-bit)");
                let raw_out = std::fs::read(out.join("A001_013").join(n_raw)).expect("the raw output exists");
                let (_, _, plane_ro) =
                    crate::decode::decode_j92_frame(&raw_out, n_raw)
                        .expect("the raw output decodes (no ctx — the archive drill)");
                assert_eq!(
                    plane_raw, plane_ro,
                    "{n_raw}: the raw output decodes pixel-exact vs the raw strip"
                );
            }
            // The DECODE verb on the disputed frame alone (no ctx) =
            // the EXISTING named refusal (the decode surface is
            // unchanged — the oracle's context never active there):
            crate::decode::set_fp_temporal_oracle(None);
            let derr = crate::decode::decode_j92_frame(&buf_fd, &n_fd)
                .err()
                .expect("the disputed frame alone (no ctx) must refuse");
            assert_eq!(
                derr.to_string(),
                format!("{n_fd}: tile ({dr},{dc}): {FP_WHOLE_BODY_REFUSAL}"),
                "the decode-verb refusal is the EXISTING wording, byte-identical: {derr}"
            );
            // --- the DRY-RUN over the 4-frame mini-clip (the
            // decision-1 ruling (a): k = 4 = the full sample — the
            // disputed + both raw + the fp neighbor) = DRY RUN PASS:
            // the sample transcodes via the oracle (the disputed
            // verified via the fp neighbor), the both-estimates line
            // present, the census carries the temporal-verified term.
            let fp_a_b = std::fs::metadata(clip_dir.join(&n_fa)).unwrap().len();
            let fp_d_b = std::fs::metadata(clip_dir.join(&n_fd)).unwrap().len();
            let carried = fp_a_b + fp_d_b;
            let o = crate::dryrun::Opts {
                dest: tmp.join(format!("dry-{fd}")),
                k_override: None, // k = clamp_k(4) = 4 — the full sample
                report: Some(tmp.join(format!("dry-{fd}.md"))),
                mode: Mode::Lossless,
                lossy_format: LossyFormat::K34892,
                reference: ReferenceDctOpts::default(),
                downscale: false,
                fast: false,
                jobs: 1,
                carry: false, // the (T) default scenario
                verify_flag: false,
            };
            let (verdict, rc) = crate::dryrun::estimate(&in_root, &o);
            assert!(
                matches!(verdict, crate::dryrun::Verdict::Pass) && rc == 0,
                "the 4-frame mini-clip dry run PASSES (the sample transcodes via the oracle): {verdict:?} {rc}"
            );
            let md = std::fs::read_to_string(tmp.join(format!("dry-{fd}.md"))).expect("the dry-run record");
            assert!(
                md.contains(&format!(
                    "class census: A001_013 — raw-uncompressed 2 · fp-camera-lossless 2 · temporal-verified 1 (carried bytes {carried})"
                )),
                "the dry-run census carries the temporal-verified term:\n{md}"
            );
            assert!(
                md.contains("both estimates (the mixed clip — carried vs transcoded: size)"),
                "the both-estimates line is present:\n{md}"
            );
            assert!(
                md.contains(&format!(
                    "projected transcoded (the fp-camera lossless frames — the ruling default: the decode + the re-encode through the archive path): 2 frame(s) — {carried} B source"
                )),
                "the transcoded scenario line (the (T) default):\n{md}"
            );
            // --- the NO-NEIGHBOR PIN (the oracle's boundary, the
            // refusing side): the 2-frame clip {raw-neighbor,
            // disputed} (frame-contiguous, ingest-conformant, NO fp
            // neighbor — the fp neighbors are 2 ordinals away, both
            // outside the clip) = the EXISTING named refusal stands
            // (the resolver's None → the byte-identical wording).
            let in2 = tmp.join("in-2");
            let clip2 = in2.join("A001_013");
            std::fs::create_dir_all(&clip2).unwrap();
            std::fs::copy(clip_dir.join(&n_ra), clip2.join(&n_ra)).unwrap();
            std::fs::copy(clip_dir.join(&n_fd), clip2.join(&n_fd)).unwrap();
            let o2 = crate::dryrun::Opts {
                dest: tmp.join(format!("dry-nn-{fd}")),
                k_override: None, // k = 2 = the full sample
                report: Some(tmp.join(format!("dry-nn-{fd}.md"))),
                mode: Mode::Lossless,
                lossy_format: LossyFormat::K34892,
                reference: ReferenceDctOpts::default(),
                downscale: false,
                fast: false,
                jobs: 1,
                carry: false,
                verify_flag: false,
            };
            let (v2, rc2) = crate::dryrun::estimate(&in2, &o2);
            match v2 {
                crate::dryrun::Verdict::Encode { name: ename, err } => {
                    assert_eq!(rc2, 1, "the no-neighbor dry run = the named refusal (rc=1)");
                    assert_eq!(ename, n_fd, "the refusal names the disputed frame");
                    assert_eq!(
                        err,
                        format!("{n_fd}: tile ({dr},{dc}): {FP_WHOLE_BODY_REFUSAL}"),
                        "the no-neighbor refusal is the EXISTING wording, byte-identical (the resolver's None path): {err}"
                    );
                }
                other => panic!("the no-neighbor dry run must be the disputed frame's named refusal (the resolver's None): {other:?}"),
            }
            // The no-neighbor record: the census line stays the
            // 123 shape (no temporal-verified term — nothing was
            // verified), no both-estimates surprise (the refusal
            // still prints the estimate — the carried bytes are
            // exact):
            let md2 = std::fs::read_to_string(tmp.join(format!("dry-nn-{fd}.md"))).expect("the no-neighbor record");
            assert!(
                md2.contains(&format!(
                    "class census: A001_013 — raw-uncompressed 1 · fp-camera-lossless 1 (carried bytes {fp_d_b})"
                )),
                "the no-neighbor census line = the 123 shape (NO temporal-verified term — nothing was verified):\n{md2}"
            );
            assert!(
                !md2.contains("temporal-verified"),
                "the no-neighbor record carries NO temporal-verified term:\n{md2}"
            );
            crate::decode::set_fp_temporal_oracle(None);
            let _ = std::fs::remove_dir_all(&tmp);
        }
    }

    /// KAT 3 — `kat_fp_temporal_oracle_byte_freeze` (corpus-
    /// conditional, the 123 pattern): the raw-only A001_001 3-frame
    /// clip (the symlink mirror — the 3 frames are members of the
    /// 225): the encode census line in the item-123 shape with NO
    /// temporal-verified term, NO provenance section, NO both-
    /// estimates line (the raw-only shape BYTE-FROZEN under the
    /// lane); the raw-only dry-run surface in the item-123 shape (no
    /// new lines); the `--help` surface assertion = the flag-
    /// declaration census over the CLI surface's source (the
    /// `#[arg(long` sites in the CLI model + the subcommand root) +
    /// the README's pinned Commands block (the doc-drift gate's
    /// byte-diff target) carries no temporal/oracle vocabulary.
    /// Re-pointed at the item-126 Stage-1 (the selection-default
    /// flip): the ONLY new flag in the CLI model is `--trial` (the
    /// byte-frozen trial opt-in — the census re-pin 28 → 29);
    /// the subcommand root (10) + the README's Commands block stay
    /// UNCHANGED (the flag is a root-level encode flag — no
    /// subcommand surface).
    #[test]
    fn kat_fp_temporal_oracle_byte_freeze() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        crate::worker::set_carry_flag(false);
        let raw = std::path::Path::new("../testdata/originals/A001_001");
        let names = [
            "A001_001_20260701_000001.DNG",
            "A001_001_20260701_000002.DNG",
            "A001_001_20260701_000003.DNG",
        ];
        for n in &names {
            if !raw.join(n).is_file() {
                eprintln!("skip: no A001_001 testdata corpus");
                return;
            }
        }
        let tmp = std::env::temp_dir().join(format!("frameprism-oracle-freeze-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let in_root = tmp.join("in");
        let clip_dir = in_root.join("A001_001");
        std::fs::create_dir_all(&clip_dir).unwrap();
        for n in &names {
            std::fs::copy(raw.join(n), clip_dir.join(n)).unwrap();
        }
        // --- the encode-run byte-freeze (the raw-only clip — the
        // 123 shape stands: no term, no provenance section):
        let out = tmp.join("out");
        let rep = process_dir(
            &in_root,
            &out,
            true,
            false,
            1,
            Mode::Lossless,
            false,
            false,
            false,
            LossyFormat::K34892,
            &ReferenceDctOpts::default(),
            None,
            false,
        )
        .expect("the raw-only clip encodes (byte-frozen)");
        assert!(
            rep.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
            "raw-only: all 3 Done: {rep:?}"
        );
        let report =
            std::fs::read_to_string(out.join("A001_001.frameprism-report.md")).expect("the raw-only report");
        assert!(
            report.contains("class census: raw-uncompressed 3 (encoded 3 · carried 0)"),
            "the raw-only census line (the item-123 shape — byte-frozen):\n{report}"
        );
        assert!(
            !report.contains("temporal-verified"),
            "the raw-only report carries NO temporal-verified term (n = 0 — byte-frozen):\n{report}"
        );
        assert!(
            !report.contains("frameclass — the per-frame provenance"),
            "the raw-only clip has NO provenance section (byte-frozen):\n{report}"
        );
        // --- the raw-only dry-run surface (the item-123 shape — no
        // new lines, no term, no both-estimates):
        let o = crate::dryrun::Opts {
            dest: tmp.join("dry-r"),
            k_override: None,
            report: Some(tmp.join("dry-r.md")),
            mode: Mode::Lossless,
            lossy_format: LossyFormat::K34892,
            reference: ReferenceDctOpts::default(),
            downscale: false,
            fast: false,
            jobs: 1,
            carry: false,
            verify_flag: false,
        };
        let (verdict, rc) = crate::dryrun::estimate(&in_root, &o);
        assert!(
            matches!(verdict, crate::dryrun::Verdict::Pass) && rc == 0,
            "the raw-only dry run passes: {verdict:?} {rc}"
        );
        let md = std::fs::read_to_string(tmp.join("dry-r.md")).expect("the raw-only record");
        assert!(
            md.contains("class census: A001_001 — raw-uncompressed 3 (carried bytes 0)"),
            "the raw-only census line (the item-123 shape — byte-frozen):\n{md}"
        );
        assert!(
            !md.contains("temporal-verified"),
            "the raw-only record carries NO temporal-verified term (byte-frozen):\n{md}"
        );
        assert!(
            !md.contains("both estimates"),
            "the raw-only record has NO both-estimates line (byte-frozen):\n{md}"
        );
        assert!(
            !md.contains("transcoded"),
            "the raw-only record has NO transcoded term (byte-frozen):\n{md}"
        );
        // --- the `--help` surface (the item-126 Stage-1 re-point —
        // the ONLY new flag in the CLI model is `--trial`):
        // the in-process form = the flag-declaration census over the
        // CLI surface's source (the `#[arg(long` sites in the CLI
        // model + the subcommand root — a new flag is a new
        // declaration) + the README's pinned Commands block (the
        // doc-drift gate's byte-diff target) carries no temporal/
        // oracle vocabulary (the subcommand surface is UNCHANGED —
        // `--trial` is a root-level encode flag):
        let cli_model = std::fs::read_to_string("src/cli_model.rs").expect("the CLI model reads");
        let main_rs = std::fs::read_to_string("src/main.rs").expect("the CLI root reads");
        let count_arg = |s: &str| s.matches("#[arg(long").count();
        assert_eq!(
            count_arg(&cli_model),
            29,
            "the CLI model's flag census (the 891906d base of 28 + the item-126 Stage-1's --trial ONLY — the re-pin)"
        );
        assert_eq!(
            count_arg(&main_rs),
            10,
            "NO new CLI flag at the subcommand root (the 891906d census — the --trial flag is a root-level encode flag)"
        );
        let readme = std::fs::read_to_string("../README.md").expect("the README reads");
        let begin = readme.find("frameprism-help-commands:begin").expect("the README's help block begins");
        let end = readme[begin..].find("frameprism-help-commands:end").expect("the README's help block ends");
        let block = &readme[begin..begin + end];
        assert!(
            !block.contains("temporal") && !block.contains("oracle"),
            "NO new subcommand/flag surface is documented (the subcommand surface is unchanged by the Stage-1 — the doc-drift gate enforces the byte-equality)"
        );
        crate::decode::set_fp_temporal_oracle(None);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // =====================================================================
    // item 126 — the Stage-1 fast-default flip (the 482 grid's selection
    // default → the fixed single W7 candidate — today's `--fast`
    // behavior; the base default's size-min trial, BYTE-FROZEN, on
    // `--trial`). The five KATs (the suite 600 → 605 — the M1-gated
    // enumeration). All corpus-conditional (the mirrored A001_013 /
    // A001_001 clips — the 123/125 pattern), all pin the flag state
    // EXPLICITLY (the in-process process-flag pattern), all restore
    // the flags at the tail (the state never leaks into the sibling
    // tests).
    // =====================================================================

    /// KAT 1 — `kat_fastdefault_corpus` (the corpus decode-bit-exact
    /// canary + the structure census): the 6 corpus frames (the A001_013
    /// clip — the fp-decoded planes + the raw — + the A001_001 raw clip)
    /// under the Stage-1 default (NO flag): every frame encodes Done
    /// with the per-frame VERIFY gate (the decode-bit-exact oracle —
    /// decode(output) == the source plane, the item-122 decode on the
    /// fp frames / the strip unpack on the raw frames, re-asserted
    /// EXPLICITLY below), and the output structure is the 482 grid
    /// contract UNCHANGED by the flip (259 = 7 · 258 = 12 · 322 = 482
    /// · 323 = 272 · 324 count 64 — the selection touches ONLY which
    /// candidate stream is emitted per tile; every structural field is
    /// identical).
    #[test]
    fn kat_fastdefault_corpus() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        crate::worker::set_carry_flag(false);
        crate::worker::set_trial_flag(false); // the Stage-1 default (explicit — the corpus KAT)
        let clips: [(&str, [&str; 3], bool); 2] = [
            (
                "A001_013",
                [
                    "A001_013_20260930_000001.DNG",
                    "A001_013_20260930_000002.DNG",
                    "A001_013_20260930_000723.DNG",
                ],
                true, // the frame gap (f2 → f723) → the subset opt-in
            ),
            (
                "A001_001",
                [
                    "A001_001_20260701_000001.DNG",
                    "A001_001_20260701_000002.DNG",
                    "A001_001_20260701_000003.DNG",
                ],
                false, // no gap — the 123 shape
            ),
        ];
        for (clip, _, _) in clips {
            if !std::path::Path::new(&format!("../testdata/originals/{clip}")).is_dir() {
                eprintln!("skip: no {clip} testdata corpus");
                crate::worker::set_subset_flag(false);
                return;
            }
        }
        let tmp = std::env::temp_dir().join(format!("frameprism-fastdefault-corpus-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        for (clip, names, subset) in clips {
            crate::worker::set_subset_flag(subset);
            let in_root = tmp.join(format!("in-{clip}"));
            let clip_dir = in_root.join(clip);
            std::fs::create_dir_all(&clip_dir).unwrap();
            for n in &names {
                std::fs::copy(format!("../testdata/originals/{clip}/{n}"), clip_dir.join(n)).unwrap();
            }
            let out = tmp.join(format!("out-{clip}"));
            let rep = process_dir(
                &in_root, &out, true, false, 1, Mode::Lossless, false, false, false,
                LossyFormat::K34892, &ReferenceDctOpts::default(), None, false,
            )
            .expect("the clip encodes (the Stage-1 default)");
            assert!(
                rep.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
                "all frames Done (the per-frame verify gate = the decode-bit-exact oracle): {rep:?}"
            );
            for n in &names {
                let buf = std::fs::read(clip_dir.join(n)).unwrap();
                let outb = std::fs::read(out.join(clip).join(n)).unwrap();
                // (a) The structure census (the 482 grid contract —
                // UNCHANGED by the flip):
                let meta = crate::tiff::read_meta(&outb).expect("the output reads");
                let e = meta.endianness;
                let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
                assert_eq!(e.u16(&find(259).expect("259").value_raw), 7, "{n}: Compression 7 (the archive contract)");
                assert_eq!(e.u16(&find(258).expect("258").value_raw), 12, "{n}: BPS 12 (the fp domain)");
                assert_eq!(e.u32(&find(322).expect("322").value_raw), 482, "{n}: TileWidth 482 (the archive grid)");
                assert_eq!(e.u32(&find(323).expect("323").value_raw), 272, "{n}: TileLength 272 (the archive grid)");
                assert_eq!(find(324).expect("324").count, 64, "{n}: the 482×272 × 3856×2170 tile count = 64");
                // (b) The decode-bit-exact canary, re-asserted
                // EXPLICITLY (the item-122 decode on the fp frames /
                // the strip unpack on the raw frames — the transcode
                // KAT's fidelity check):
                let (w, h, p_out) = crate::decode::decode_j92_frame(&outb, "out").expect("the output decodes");
                assert_eq!((w, h), (3856, 2170), "{n}: the output geometry (the UHD readout)");
                let p_in = match crate::tiff::read(&buf) {
                    Ok(f) => crate::pack12::unpack12(f.strip_slice(&buf), f.width, f.height).expect("the raw unpack"),
                    Err(_) => crate::decode::decode_j92_frame(&buf, "in").expect("the fp input decodes (the item-122 path)").2,
                };
                assert_eq!(p_out, p_in, "{n}: the decode-bit-exact canary (decode(output) == the source plane, pixel-exact)");
            }
            crate::worker::set_subset_flag(false);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// KAT 2 — `kat_fastdefault_determinism`: the A001_001 clip under
    /// the Stage-1 default, TWO fresh dests → BYTE-IDENTICAL per frame
    /// (the selection's determinism: the fixed single W7 candidate has
    /// no trial-content dependence — the double-encode contract of the
    /// spec's R0 acceptance list).
    #[test]
    fn kat_fastdefault_determinism() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        crate::worker::set_carry_flag(false);
        crate::worker::set_trial_flag(false);
        let raw = std::path::Path::new("../testdata/originals/A001_001");
        let names = [
            "A001_001_20260701_000001.DNG",
            "A001_001_20260701_000002.DNG",
            "A001_001_20260701_000003.DNG",
        ];
        for n in &names {
            if !raw.join(n).is_file() {
                eprintln!("skip: no A001_001 testdata corpus");
                return;
            }
        }
        let tmp = std::env::temp_dir().join(format!("frameprism-fastdefault-determ-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let in_root = tmp.join("in");
        let clip_dir = in_root.join("A001_001");
        std::fs::create_dir_all(&clip_dir).unwrap();
        for n in &names {
            std::fs::copy(raw.join(n), clip_dir.join(n)).unwrap();
        }
        for dest in ["a", "b"] {
            let out = tmp.join(format!("out-{dest}"));
            let rep = process_dir(
                &in_root, &out, true, false, 1, Mode::Lossless, false, false, false,
                LossyFormat::K34892, &ReferenceDctOpts::default(), None, false,
            )
            .expect("the clip encodes (the Stage-1 default)");
            assert!(
                rep.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
                "run {dest}: all 3 Done: {rep:?}"
            );
        }
        for n in &names {
            let a = std::fs::read(tmp.join("out-a/A001_001").join(n)).expect("run a reads");
            let b = std::fs::read(tmp.join("out-b/A001_001").join(n)).expect("run b reads");
            assert_eq!(a, b, "{n}: the double-encode is BYTE-IDENTICAL (the fixed W7 candidate — no trial-content dependence)");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// KAT 3 — `kat_fastdefault_size_band`: the per-frame size delta
    /// (the Stage-1 default − the `--trial` base default) over the 6
    /// corpus frames. The in-lane measured band (the R1 census — the
    /// lane's report.md): +18,536 … +23,068 B/frame (the A001_001 raw
    /// frames run warmer than the A001_013 fp-decoded planes; the total
    /// over the 6 frames = +121,984 B). The container scaffolding is
    /// invariant, so the DNG-level delta == the tile-stream delta (the
    /// binary A/B's total matches the per-tile probe's total EXACTLY).
    /// The band pin: 0 < Δ ≤ 25,000 B/frame (the measured max +23,068
    /// with headroom).
    #[test]
    fn kat_fastdefault_size_band() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        crate::worker::set_carry_flag(false);
        let clips: [(&str, [&str; 3], bool); 2] = [
            (
                "A001_013",
                [
                    "A001_013_20260930_000001.DNG",
                    "A001_013_20260930_000002.DNG",
                    "A001_013_20260930_000723.DNG",
                ],
                true,
            ),
            (
                "A001_001",
                [
                    "A001_001_20260701_000001.DNG",
                    "A001_001_20260701_000002.DNG",
                    "A001_001_20260701_000003.DNG",
                ],
                false,
            ),
        ];
        for (clip, _, _) in clips {
            if !std::path::Path::new(&format!("../testdata/originals/{clip}")).is_dir() {
                eprintln!("skip: no {clip} testdata corpus");
                crate::worker::set_subset_flag(false);
                crate::worker::set_trial_flag(false);
                return;
            }
        }
        let tmp = std::env::temp_dir().join(format!("frameprism-fastdefault-band-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        for (clip, names, subset) in clips {
            crate::worker::set_subset_flag(subset);
            crate::worker::set_trial_flag(false); // the Stage-1 default
            let in_root = tmp.join(format!("in-{clip}"));
            let clip_dir = in_root.join(clip);
            std::fs::create_dir_all(&clip_dir).unwrap();
            for n in &names {
                std::fs::copy(format!("../testdata/originals/{clip}/{n}"), clip_dir.join(n)).unwrap();
            }
            let out_default = tmp.join(format!("out-default-{clip}"));
            let rep = process_dir(
                &in_root, &out_default, true, false, 1, Mode::Lossless, false, false, false,
                LossyFormat::K34892, &ReferenceDctOpts::default(), None, false,
            )
            .expect("the clip encodes (the Stage-1 default)");
            assert!(
                rep.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
                "the {clip} default run: all Done: {rep:?}"
            );
            crate::worker::set_trial_flag(true); // the byte-frozen trial
            let out_trial = tmp.join(format!("out-trial-{clip}"));
            let rep = process_dir(
                &in_root, &out_trial, true, false, 1, Mode::Lossless, false, false, false,
                LossyFormat::K34892, &ReferenceDctOpts::default(), None, false,
            )
            .expect("the clip encodes (the --trial flag)");
            assert!(
                rep.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
                "the {clip} trial run: all Done: {rep:?}"
            );
            for n in &names {
                let s_default = std::fs::metadata(out_default.join(clip).join(n)).expect("the default output exists").len();
                let s_trial = std::fs::metadata(out_trial.join(clip).join(n)).expect("the trial output exists").len();
                let d = s_default as i64 - s_trial as i64;
                assert!(
                    d > 0 && d <= 25_000,
                    "{n}: the per-frame size delta {d:+} B is inside the measured band (0 < Δ ≤ 25,000 B; the in-lane measured 18,536 … 23,068)"
                );
            }
            crate::worker::set_subset_flag(false);
        }
        crate::worker::set_trial_flag(false);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// KAT 4 — `kat_fastdefault_trial_byte_freeze` (the byte-frozen
    /// contract): the `--trial` output over the 6 corpus frames is
    /// BYTE-IDENTICAL to the base 1eb7a78 no-flag output (the base
    /// default's trial, the reference-product byte-parity contract at
    /// the measured 2.67× workload factor — the Stage-1 flip's named
    /// give-up, now the flag's contract). Pinned in-process by the
    /// per-frame MD5 + the exact size (the sha256 goldens — the full
    /// 64-hex set — ride the lane's report.md + the binary A/B record;
    /// the crate carries no sha256 dependency, and the MD5 is the house
    /// digest — the lossy tables-digest precedent). The verify gate
    /// (the decode-bit-exact oracle) + the 482 grid structure census
    /// ride along (the trial output is the 0.1.0 adaptive shape).
    #[test]
    fn kat_fastdefault_trial_byte_freeze() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        crate::worker::set_carry_flag(false);
        // The base 1eb7a78 no-flag (trial) output goldens — the
        // (name, MD5, size) set (the sha256 set in the lane's
        // report.md):
        const GOLDENS: [(&str, [u8; 16], u64); 6] = [
            ("A001_013/A001_013_20260930_000001.DNG", [0x55, 0xab, 0xef, 0xd9, 0xf6, 0x4e, 0x23, 0x4a, 0xe6, 0x78, 0x21, 0xc5, 0x0f, 0x4b, 0xae, 0x1b], 3_989_058),
            ("A001_013/A001_013_20260930_000002.DNG", [0x34, 0x85, 0x89, 0xbe, 0x82, 0xb9, 0xc9, 0x23, 0x39, 0x8d, 0x21, 0xfc, 0xef, 0x26, 0xdb, 0x1f], 3_988_410),
            ("A001_013/A001_013_20260930_000723.DNG", [0xf7, 0x41, 0xc1, 0xa2, 0xb3, 0x00, 0x01, 0x0d, 0x8a, 0xf0, 0x1c, 0x6e, 0x60, 0xd2, 0x6e, 0xfd], 3_977_614),
            ("A001_001/A001_001_20260701_000001.DNG", [0x15, 0x3f, 0xc8, 0xc4, 0x72, 0xbe, 0xbb, 0x75, 0x36, 0xd8, 0x0a, 0x5e, 0xc2, 0x3b, 0x74, 0x3e], 2_421_732),
            ("A001_001/A001_001_20260701_000002.DNG", [0x67, 0x7d, 0xe8, 0x8e, 0x94, 0xea, 0x2d, 0x11, 0xc6, 0xfc, 0x38, 0xd7, 0x51, 0x32, 0xd5, 0x7a], 2_422_014),
            ("A001_001/A001_001_20260701_000003.DNG", [0x3a, 0x08, 0x17, 0x30, 0xdf, 0x8d, 0xd8, 0xb6, 0x56, 0xc4, 0x6f, 0x7d, 0x37, 0xd3, 0x38, 0xc2], 2_441_348),
        ];
        for clip in ["A001_013", "A001_001"] {
            if !std::path::Path::new(&format!("../testdata/originals/{clip}")).is_dir() {
                eprintln!("skip: no {clip} testdata corpus");
                crate::worker::set_trial_flag(false);
                return;
            }
        }
        let tmp = std::env::temp_dir().join(format!("frameprism-fastdefault-freeze-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let clips: [(&str, [&str; 3], bool); 2] = [
            (
                "A001_013",
                [
                    "A001_013_20260930_000001.DNG",
                    "A001_013_20260930_000002.DNG",
                    "A001_013_20260930_000723.DNG",
                ],
                true,
            ),
            (
                "A001_001",
                [
                    "A001_001_20260701_000001.DNG",
                    "A001_001_20260701_000002.DNG",
                    "A001_001_20260701_000003.DNG",
                ],
                false,
            ),
        ];
        for (clip, names, subset) in clips {
            crate::worker::set_subset_flag(subset);
            crate::worker::set_trial_flag(true); // the byte-frozen trial
            let in_root = tmp.join(format!("in-{clip}"));
            let clip_dir = in_root.join(clip);
            std::fs::create_dir_all(&clip_dir).unwrap();
            for n in &names {
                std::fs::copy(format!("../testdata/originals/{clip}/{n}"), clip_dir.join(n)).unwrap();
            }
            let out = tmp.join(format!("out-{clip}"));
            let rep = process_dir(
                &in_root, &out, true, false, 1, Mode::Lossless, false, false, false,
                LossyFormat::K34892, &ReferenceDctOpts::default(), None, false,
            )
            .expect("the clip encodes (the --trial flag)");
            assert!(
                rep.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
                "the {clip} trial run: all Done (the verify gate = the decode-bit-exact oracle): {rep:?}"
            );
            for n in &names {
                let rel = format!("{clip}/{n}");
                let g = GOLDENS.iter().find(|(p, _, _)| *p == rel).expect("the golden is pinned");
                let outb = std::fs::read(out.join(clip).join(n)).expect("the trial output exists");
                assert_eq!(
                    md5::compute(&outb).0,
                    g.1,
                    "{n}: the --trial output's MD5 drifted from the base 1eb7a78 no-flag output (the byte-frozen contract)"
                );
                assert_eq!(
                    outb.len() as u64,
                    g.2,
                    "{n}: the --trial output's size drifted from the base 1eb7a78 no-flag output (the byte-frozen contract)"
                );
                // The 482 grid structure (the trial output = the 0.1.0
                // adaptive shape — the census rides the byte-freeze):
                let meta = crate::tiff::read_meta(&outb).expect("the trial output reads");
                let e = meta.endianness;
                let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
                assert_eq!(e.u16(&find(259).expect("259").value_raw), 7, "{n}: Compression 7");
                assert_eq!(e.u32(&find(322).expect("322").value_raw), 482, "{n}: TileWidth 482");
                assert_eq!(e.u32(&find(323).expect("323").value_raw), 272, "{n}: TileLength 272");
                assert_eq!(find(324).expect("324").count, 64, "{n}: the 64-tile grid");
            }
            crate::worker::set_subset_flag(false);
        }
        crate::worker::set_trial_flag(false);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// KAT 5 — `kat_fastdefault_fast_noop` (the `--fast` surface + the
    /// flag-pair refusal + the help wording): (i) the `--fast` output
    /// == the Stage-1 default output, the A001_001 clip, BYTE-IDENTICAL
    /// per frame (the flag is a no-op on the 482 grid — its behavior IS
    /// the new default); (ii) the `--fast`×`--trial` refusal wording +
    /// the help wording, pinned at the SOURCE level (the `cli_model` /
    /// `dispatch` modules are bin modules — the suite's in-process form
    /// reads their declarations, the census KAT's pattern — the PM-gated
    /// exact wording); (iii) the binary-level rc=2 + the rendered
    /// `--help` lines, when the release binary is resolvable next to the
    /// test binary (the CI-conditional pattern — the honest skip note
    /// otherwise).
    #[test]
    fn kat_fastdefault_fast_noop() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        crate::worker::set_carry_flag(false);
        crate::worker::set_trial_flag(false);
        // (i) The no-op on the 482 grid (the A001_001 raw clip):
        let raw = std::path::Path::new("../testdata/originals/A001_001");
        let names = [
            "A001_001_20260701_000001.DNG",
            "A001_001_20260701_000002.DNG",
            "A001_001_20260701_000003.DNG",
        ];
        for n in &names {
            if !raw.join(n).is_file() {
                eprintln!("skip: no A001_001 testdata corpus");
                return;
            }
        }
        let tmp = std::env::temp_dir().join(format!("frameprism-fastdefault-noop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let in_root = tmp.join("in");
        let clip_dir = in_root.join("A001_001");
        std::fs::create_dir_all(&clip_dir).unwrap();
        for n in &names {
            std::fs::copy(raw.join(n), clip_dir.join(n)).unwrap();
        }
        for (fast, dest) in [(false, "default"), (true, "fast")] {
            let out = tmp.join(format!("out-{dest}"));
            let rep = process_dir(
                &in_root, &out, true, false, 1, Mode::Lossless, false, fast, false,
                LossyFormat::K34892, &ReferenceDctOpts::default(), None, false,
            )
            .expect("the clip encodes (fast / default)");
            assert!(
                rep.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
                "the {dest} run: all 3 Done: {rep:?}"
            );
        }
        for n in &names {
            let d = std::fs::read(tmp.join("out-default/A001_001").join(n)).expect("the default output reads");
            let f = std::fs::read(tmp.join("out-fast/A001_001").join(n)).expect("the fast output reads");
            assert_eq!(d, f, "{n}: --fast == the Stage-1 default output on the 482 grid (the no-op)");
        }
        // (ii) The source-level wording pins (the PM-gated exact
        // wording — the source normalized: the doc comments wrap across
        // the `///` lines, so the pin matches the WHITESPACE-NORMALIZED
        // doc text, the same invariant the rendered --help pin uses):
        let norm_src = |p: &str| -> String {
            std::fs::read_to_string(p)
                .expect("the source reads")
                .lines()
                .filter(|l| l.trim_start().starts_with("///"))
                .map(|l| l.trim_start().trim_start_matches("///").trim())
                .collect::<Vec<_>>()
                .join(" ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let cm = norm_src("src/cli_model.rs");
        assert!(
            cm.contains("On the 482 grid: now the default — accepted for compatibility (its output matches the default); on the other grids: the single-candidate per-gate family head, unchanged"),
            "the --fast doc carries the PM-gated split wording (the 482 grid: now the default; the other grids: the family head, unchanged)"
        );
        assert!(
            cm.contains("The base default's 3-candidate size-min trial selection on the 482 grid (the pre-Stage-1 default, byte-frozen — the reference-product byte-parity contract at the measured 2.67× workload factor)"),
            "the --trial doc carries the PM-gated wording (the byte-frozen base default's trial, the named give-up)"
        );
        let dispatch = std::fs::read_to_string("src/dispatch.rs").expect("the dispatch reads");
        assert!(
            dispatch.contains("refused: --fast and --trial are mutually exclusive (they select conflicting per-tile selection contracts: --fast = the fixed single W7 candidate, --trial = the base default's 3-candidate size-min trial; on the 482 grid --fast is a no-op against the Stage-1 default — drop one of the flags)"),
            "the --fast×--trial refusal wording is byte-pinned (the unconditional rc=2 contract)"
        );
        // (iii) The binary-level surface (CI-conditional — the release
        // binary next to the test binary, when the build produced it):
        let bin = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("frameprism")))
            .or_else(|| std::env::current_exe().ok().and_then(|p| p.parent().and_then(|d| d.parent()).map(|d| d.join("frameprism"))));
        if let Some(bin) = bin.as_ref().filter(|p| p.is_file()) {
            let r = std::process::Command::new(bin)
                .args(["/nonexistent-in-126", "/nonexistent-out-126", "--fast", "--trial"])
                .output()
                .expect("the refusal run executes");
            assert_eq!(r.status.code(), Some(2), "the --fast×--trial refusal is rc=2 (unconditional — before any path dispatch)");
            assert!(
                String::from_utf8_lossy(&r.stderr).contains("refused: --fast and --trial are mutually exclusive"),
                "the refusal wording renders verbatim on stderr"
            );
            let h = std::process::Command::new(bin).arg("--help").output().expect("the --help run executes");
            let help = String::from_utf8_lossy(&h.stdout);
            let norm: String = help.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                norm.contains("On the 482 grid: now the default — accepted for compatibility (its output matches the default); on the other grids: the single-candidate per-gate family head, unchanged"),
                "the rendered --help carries the --fast split wording"
            );
            assert!(
                norm.contains("The base default's 3-candidate size-min trial selection on the 482 grid (the pre-Stage-1 default, byte-frozen"),
                "the rendered --help carries the --trial line"
            );
        } else {
            eprintln!("note: the release binary is not resolvable next to the test binary — the binary-level refusal/--help checks are skipped (the source-level pins above stand)");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// item 125 — the per-phase profiler's sidecar contract (the
    /// env-gated measurement surface — the stable phase-string
    /// contract + the gate-OFF byte-freeze). Corpus-conditional on
    /// the mirrored A001_013 (the 3 standing frames — f000001 fp /
    /// f000002 raw / f000723 fp, the 123 KAT's clip shape).
    /// `process_dir` called directly (the ingest gate is the CLI
    /// level — the 124 KAT's pattern) at the DEFAULT jobs (jobs = 0
    /// — the full pool — the parallel path the 723-clip run
    /// exercises; the profiler's thread-local accumulator + the
    /// mutex-serialized flush are the parallel-path contract).
    /// (i) gate OFF (default): the 3-frame clip run → NO
    /// `.frameprism-profile.tsv` in the dest + the output bytes =
    /// the no-gate baseline (the lane-internal byte-freeze
    /// re-assertion). (ii) gate ON (`test_set(true)`): the sidecar
    /// exists; the header is `file \t phase \t ns`; every frame has
    /// a `read` row; the fp frames (f000001, f000723) have ALL of
    /// the eight phases; the raw frame (f000002) has exactly
    /// `read` / `archive-encode` / `archive-drill` (NO fp/fidelity
    /// phase); every ns > 0; no phase name outside the contract set.
    /// (iii) gate OFF after ON (`test_set(false)`, fresh dest): the
    /// byte-freeze re-asserted (the sidecar absent — the gate is a
    /// value, not a sticky flag).
    #[test]
    fn kat_profile_sidecar_contract() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        crate::worker::set_carry_flag(false);
        // The 3 standing frames' ordinals (1, 2, 723) carry a
        // FRAME_GAP (the documented sticky set — the 123 KAT's form):
        crate::worker::set_subset_flag(true);
        // The gate is a VALUE (not a sticky flag): the default (i)
        // starts with an explicit OFF.
        crate::profile::test_set(false);
        let clip = std::path::Path::new("../testdata/originals/A001_013");
        let names = [
            "A001_013_20260930_000001.DNG",
            "A001_013_20260930_000002.DNG",
            "A001_013_20260930_000723.DNG",
        ];
        for n in &names {
            if !clip.join(n).is_file() {
                eprintln!("skip: no A001_013 testdata corpus");
                return;
            }
        }
        let tmp = std::env::temp_dir().join(format!("frameprism-profile-kat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let in_root = tmp.join("in");
        std::fs::create_dir_all(in_root.join("A001_013")).unwrap();
        for n in &names {
            std::fs::copy(clip.join(n), in_root.join("A001_013").join(n)).unwrap();
        }
        let run = |out: &std::path::Path| {
            process_dir(
                &in_root,
                out,
                true,
                false,
                0, // the DEFAULT jobs (the full pool — the 124 KAT's pattern)
                Mode::Lossless,
                false,
                false,
                false,
                LossyFormat::K34892,
                &ReferenceDctOpts::default(),
                None,
                false,
            )
            .expect("the 3-frame standing clip encodes")
        };
        let outputs = |out: &std::path::Path| -> [Vec<u8>; 3] {
            [
                std::fs::read(out.join("A001_013").join(names[0])).expect("the output 1 reads"),
                std::fs::read(out.join("A001_013").join(names[1])).expect("the output 2 reads"),
                std::fs::read(out.join("A001_013").join(names[2])).expect("the output 3 reads"),
            ]
        };
        // --- (i) the gate OFF (the default) ---------------------------
        let out_off1 = tmp.join("out-off-1");
        let rep = run(&out_off1);
        assert!(
            rep.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
            "(i): all 3 Done (the gate OFF — the default run): {rep:?}"
        );
        assert!(
            !out_off1.join(".frameprism-profile.tsv").exists(),
            "(i): the gate OFF creates NO sidecar (the default surface is byte-frozen)"
        );
        let off1 = outputs(&out_off1);
        // --- (ii) the gate ON ------------------------------------------
        crate::profile::test_set(true);
        let out_on = tmp.join("out-on");
        let rep = run(&out_on);
        assert!(
            rep.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
            "(ii): all 3 Done (the gate ON — the profiler never changes the run's behavior): {rep:?}"
        );
        // The profiler never touches the pixels/bytes of any output —
        // the gate-ON outputs are byte-identical to the no-gate
        // baseline (the byte-freeze at the measurement run itself):
        let on = outputs(&out_on);
        for (i, n) in names.iter().enumerate() {
            assert_eq!(
                on[i], off1[i],
                "(ii) {n}: the gate-ON output is BYTE-IDENTICAL to the no-gate baseline"
            );
        }
        let sidecar = out_on.join(".frameprism-profile.tsv");
        let text =
            std::fs::read_to_string(&sidecar).expect("the sidecar exists at the gate ON");
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some("file\tphase\tns"),
            "the sidecar's header row (the contract's exact form)"
        );
        // The stable phase-name contract (the exact 8 names):
        let contract: [&str; 8] = [
            "read",
            "fp-input-decode",
            "fp-input-drill",
            "source-synth",
            "archive-encode",
            "archive-drill",
            "fidelity-decode",
            "fidelity-compare",
        ];
        let mut per_frame: std::collections::BTreeMap<String, std::collections::BTreeMap<String, u128>> =
            std::collections::BTreeMap::new();
        for line in lines {
            let cols: Vec<&str> = line.split('\t').collect();
            assert_eq!(
                cols.len(),
                3,
                "the sidecar's row shape (file \t phase \t ns): {line:?}"
            );
            let ns: u128 = cols[2].parse().expect("the sidecar's ns column parses");
            assert!(ns > 0, "the sidecar's ns > 0 (the phase ran): {line:?}");
            assert!(
                contract.contains(&cols[1]),
                "the sidecar's phase name is inside the contract set (no unknown phase): {line:?}"
            );
            let m = per_frame.entry(cols[0].to_string()).or_default();
            *m.entry(cols[1].to_string()).or_insert(0) += ns;
        }
        // Every frame of the clip has rows (incl. a `read` row) + the
        // per-frame phase sets (the RAW/FP row contract):
        assert_eq!(
            per_frame.len(),
            3,
            "(ii): every frame of the clip has a row (every frame's `read` phase ran):\n{text}"
        );
        let phases_of =
            |f: &str| -> std::collections::BTreeSet<String> {
                per_frame
                    .get(f)
                    .map(|m| m.keys().cloned().collect())
                    .unwrap_or_default()
            };
        let all8: std::collections::BTreeSet<String> =
            contract.iter().map(|s| s.to_string()).collect();
        let raw3: std::collections::BTreeSet<String> =
            ["read", "archive-encode", "archive-drill"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(
            phases_of(names[0]),
            all8,
            "(ii): the fp frame f000001's row = ALL eight phases:\n{text}"
        );
        assert_eq!(
            phases_of(names[2]),
            all8,
            "(ii): the fp frame f000723's row = ALL eight phases:\n{text}"
        );
        assert_eq!(
            phases_of(names[1]),
            raw3,
            "(ii): the raw frame f000002's row = `read` / `archive-encode` / `archive-drill` ONLY (NO fp/fidelity phase):\n{text}"
        );
        // --- (iii) the gate OFF after ON --------------------------------
        crate::profile::test_set(false);
        let out_off2 = tmp.join("out-off-2");
        let rep = run(&out_off2);
        assert!(
            rep.outcomes.iter().all(|o| matches!(o, Outcome::Done(_))),
            "(iii): all 3 Done (the gate OFF after ON): {rep:?}"
        );
        assert!(
            !out_off2.join(".frameprism-profile.tsv").exists(),
            "(iii): the gate OFF after ON creates NO sidecar (the gate is a value, not a sticky flag)"
        );
        // The byte-freeze re-asserted: the gate-OFF-after-ON outputs
        // are byte-identical to the no-gate baseline's (the lane-
        // internal byte-freeze — the profiler's default-surface
        // invariance under the gate's full value cycle):
        let off2 = outputs(&out_off2);
        for (i, n) in names.iter().enumerate() {
            assert_eq!(
                off2[i], off1[i],
                "(iii) {n}: the gate-OFF-after-ON output is BYTE-IDENTICAL to the no-gate baseline"
            );
        }
        // The gate restored (the process-wide state never leaks into
        // the sibling tests — the default stands):
        crate::profile::test_set(false);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
