//! The profile-measure measurement core + the profile-measure verb
//! (the measurement — R1/R2/R3: the bounded-read scan over a source
//! tree (clips) + the per-(geometry × depth) census + the
//! temporal-bound derivation (the 4× house rule on the divergent-tile
//! census — the item-124 machinery quoted from source) + the
//! candidate-profile writer (the loader's inverse — a pure fn over
//! the measurement) + the verb's surface: the `--out`-required
//! candidate write (the house's atomic temp+rename, the explicit path
//! only) + the multi-root composition (the pure census merge — the
//! read path is the frozen per-root scan) + the report surface).
//!
//! **The bounded-read fence (the reuse is the contract — the
//! tripwire's binding):** the scan performs NO new read class. Per
//! frame: the EXISTING frame-class scan (`preflight::frame_class_scan`
//! — the 512 KiB window + the sanctioned `BadIfdOffset` full-file
//! fallback, the ingest gate's per-frame site) + the identity window
//! (`camera::read_detection_prefix`'s 1 MiB prefix → `tiff::read_meta`
//! → `camera::identity_from_ifd0` — the encode pre-pass's read class;
//! the fp camera's tail-IFD frames ride the sanctioned full-file
//! fallback — the pre-pass exception class, the note line is the
//! pre-pass's own wording, byte-identical). The fp-camera frames'
//! tile census rides the TRANSFORM-class full read (the tripwire's
//! documented out-of-scope sibling — the encode/decode consumes the
//! frame in RAM; the anchor pattern + wording are the encode site's)
//! — ONE read per fp frame (the identity's full-file class rides the
//! same read; the frame is read ONCE total), and the divergent-tile
//! census's same-class neighbor consults the bounded neighbor cache
//! (the oracle's read-only side — silent by design; the measure pass
//! reads strictly LESS than the encode path, which re-reads the
//! oracle's neighbor per disputed tile). The structural constants
//! (the predicate cores, the per-depth grids, the drill, the metric)
//! are PURE — the sites the encode path's pre-pass already consults.
//! See the module's tripwire registration in `lib.rs` (the three
//! recorded keep sites — the pre-pass exception + the transform-class
//! frame read + the neighbor read — the existing sanctioned classes,
//! each anchored + wording-pinned there).
//!
//! **The measured constants (quoted — no invention, the spec's
//! condition 6):** the delta metric = `decode::fp_temporal_in_band`'s
//! comparison (the max `|a − b|` over the disputed tile's decoded
//! full-nominal plane vs the verified same-class neighbor's same-tile
//! plane — this module's `max_delta` is that expression, parity-pinned
//! against the predicate's exact 256-accept / 257-refuse boundary).
//! The 4× house rule = the `decode::FP_TEMPORAL_MAX_DELTA` rationale's
//! line ("256 = 4× the measured worst, named") — the derivation:
//! `bound = 4 × (the max delta over the batch's whole-body-divergent
//! tiles)`. The divergent-tile detector = the drill's fp arm (the
//! 4-call core `decode::fp_verify_tile_full_nominal`: `Ok` =
//! drill-verified decoded full-nominal plane, `Err` = the tile fails
//! the drill — the whole-body-divergent class when the tile decodes).
//! The neighbor walk = the temporal-oracle resolver's contract (the
//! ordinal ± 2k outward, the same-clip same-class candidates, the
//! drill-verified same tile, the ordinal-boundary stop). The grid
//! constants = `tileenc::gate_tile_dims_depth` + the GATE_* set +
//! `Grid::for_dims` (the per-(geometry × depth) contract).
//!
//! **The writer's target shape (the loader's expectation — the
//! committed `profiles/a001-sigma-fp.profile`'s structure):** the
//! magic line + the provenance header comments (the loader skips `#`
//! lines) + the fixed key rows (`version` / `tool_version` /
//! `camera` / `make` / `model` / `photometric` / `naming`) + the
//! repeated `geometry: W H bits preds` rows. The loader's format has
//! NO temporal-bound key (an unknown key is the named refusal) — the
//! measured bound rides the header comment (the provenance class; the
//! committed profile's own header is exactly it), and the
//! zero-divergent batch OMITS it (the named report line stands — the
//! loader's behavior for a bound-less profile is the NORM: the
//! committed pin itself is bound-less, and the temporal acceptance is
//! the tool's constant + the fp-transcode path's ctx, never
//! profile-keyed — the strict default).
//!
//! NO measurement semantics in the write: `candidate_profile` is a
//! pure fn (`Measurement` → the profile file string). The file write
//! is the verb's `--out`-required surface (this module's `run` — the
//! house's atomic temp+rename, the explicit path only: a missing
//! parent dir is the named refusal, no partial write).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::Args as ClapArgs;

use crate::camera;
use crate::frameclass;
use crate::tiff;
use crate::tileenc;

/// The divergent-tile delta metric (the item-124 machinery —
/// QUOTED from `decode::fp_temporal_in_band`'s comparison): the max
/// `|a − b|` (the 12-bit domain) over the disputed tile's decoded
/// full-nominal plane vs the verified same-class neighbor's same-tile
/// plane. `None` = a plane-length mismatch (a geometry anomaly the
/// walk should never produce — the metric is unmeasurable; the
/// `fp_temporal_in_band` parity = NEVER accepts, the safe direction).
/// The KAT parity-pins this against the predicate's exact boundary
/// (256 → accept / 257 → refuse — the `FP_TEMPORAL_MAX_DELTA`
/// boundary).
pub(crate) fn max_delta(full: &[u16], neighbor: &[u16]) -> Option<u16> {
    if full.len() != neighbor.len() || full.is_empty() {
        return None;
    }
    Some(
        full.iter()
            .zip(neighbor.iter())
            .map(|(a, b)| (*a as i32 - *b as i32).unsigned_abs() as u16)
            .max()
            .unwrap_or(0),
    )
}

/// One measured frame (the scan's per-frame record — the bounded
/// reads only: the class scan + the identity window; the fp frames'
/// full bytes are read at the census pass, never stored here).
pub struct FrameRecord {
    /// The root-relative display (the report lines' file field).
    pub rel: String,
    /// The clip key (the ingest gate's convention — the frame's
    /// relative parent dir, `""` = the input root).
    pub clip: String,
    /// The frame number (the last `_`-separated stem field, all
    /// digits — `None` = the FRAME_BADNAME class; the neighbor walk
    /// is unmeasurable for such a frame).
    pub ordinal: Option<u64>,
    pub class: frameclass::FrameClass,
    /// The self-described identity (the identity window's read) —
    /// `None` = the UNDETERMINED arm-1 class (no readable identity).
    pub identity: Option<camera::FrameIdentity>,
}

/// The per-(geometry × depth) census row (R1's readout row): the
/// (W×H, bits, CFA/photometric) → the layout class (the predicates'
/// result — the canonical `tile,archive` order; empty = no predicate
/// confirms — the UNDETERMINED arm-2 class, named, never a profile
/// row) + the tile grid dims (the structural constants per
/// readout×depth — `gate_tile_dims_depth`'s tile size + the grid W×H
/// = `Grid::for_dims`'s div_ceil counts) + the row's frame count.
#[derive(Clone)]
pub struct GeometryRowMeasured {
    pub width: u32,
    pub height: u32,
    pub bits: u16,
    /// The row's CFA photometric (the identity's tag 262 — uniform
    /// over the batch by the writer's single-camera contract).
    pub photometric: u16,
    /// The predicates' result (the canonical order; empty = the
    /// arm-2 unconfirmed readout).
    pub predicates: Vec<&'static str>,
    pub tile_w: u32,
    pub tile_h: u32,
    pub grid_cols: u32,
    pub grid_rows: u32,
    /// The frame count at this readout×depth.
    pub frames: u64,
    /// The distinct clip count at this readout×depth.
    pub clips: u64,
}

/// The per-readout (W×H) coverage census (R1: the frame count + the
/// clip count — the report line shape).
#[derive(Clone)]
pub struct ReadoutCoverage {
    pub width: u32,
    pub height: u32,
    pub frames: u64,
    pub clips: u64,
}

/// One whole-body-divergent tile of the batch (R2's census entry —
/// the drill's class: the tile that fails the 4-call drill core; the
/// delta = the metric over its decoded full-nominal plane vs the
/// verified same-class neighbor's same-tile plane — `None` = no
/// drill-verified neighbor at this tile (the ordinal-boundary /
/// no-neighbor class — the delta is unmeasurable, the tile is still
/// census-counted)).
#[derive(Clone)]
pub struct DivergentTile {
    pub frame: String,
    pub ordinal: Option<u64>,
    /// The tile's (row, col) on the frame's own grid (the file's
    /// 322/333-derived grid — the drill's grid).
    pub tile: (u32, u32),
    /// The row-major tile index (the drill's loop index).
    pub tile_index: usize,
    pub delta: Option<u16>,
}

/// The temporal-bound measurement (R2): the divergent-tile census
/// over the batch + the band (the max measured delta) + the bound
/// (`4 × the band` — the house rule, the quoted 4×; the exact
/// boundary semantics = `≤ bound` accepts, the
/// `FP_TEMPORAL_MAX_DELTA` contract). `band = None` = zero MEASURABLE
/// divergent tiles (zero divergent at all, or divergent-without-a-
/// verified-neighbor only) → the bound is unmeasurable → the
/// candidate profile OMITS the bound row + the report carries the
/// named line.
pub struct TemporalBound {
    /// The census (deterministic order: the frame ordinal — the
    /// ordinal-less frames last, by name — then the tile index).
    pub divergent: Vec<DivergentTile>,
    pub band: Option<u16>,
    pub bound: Option<u16>,
}

/// The measure pass's full result (the scan + the census + the bound
/// + the writer's inputs).
pub struct Measurement {
    /// The source tree (the report's source line).
    pub root: String,
    pub clips: u64,
    pub frames_total: u64,
    /// The per-class census (deterministic class order — the pinned
    /// vocabulary's `name()`).
    pub frames_by_class: Vec<(frameclass::FrameClass, u64)>,
    /// The per-(W, H, bits) rows (deterministic (W, H, bits) order).
    pub rows: Vec<GeometryRowMeasured>,
    /// The per-(W, H) coverage census (deterministic (W, H) order).
    pub readouts: Vec<ReadoutCoverage>,
    /// The batch-uniform identity (the writer's make/model/photometric
    /// input) — `None` = no readable identity at all (the writer's
    /// named error — the single-camera batch contract).
    pub identity: Option<camera::FrameIdentity>,
    /// The measured frame-file convention (the writer's `naming:`
    /// input — `<CLIP>_<YYYYMMDD>_<NNNNNN>.DNG`) — `None` = the stems
    /// do not converge (the writer's named error).
    pub naming: Option<String>,
    /// The derived camera id (the writer's `camera:` input — the
    /// footage derivation: `<first stem field>-<model-slug>` —
    /// `None` = the batch-uniform identity or the stem field is
    /// absent (the writer's named error)).
    pub camera_id: Option<String>,
    /// The arm-1 frames (no readable identity — the named lines).
    pub unidentifiable: Vec<String>,
    /// The arm-2 frames (a readable identity no predicate confirms —
    /// the named lines).
    pub unconfirmed: Vec<String>,
    pub temporal: TemporalBound,
}

// =====================================================================
// The identity window (the pre-pass's read class — the bounded
// prefix + the sanctioned full-file fallback, the pre-pass's note
// wording)
// =====================================================================

/// The identity window (M0.2's reuse — the L1 pre-pass's read class):
/// the bounded 1 MiB detection prefix → `read_meta` →
/// `identity_from_ifd0`; the fp camera's tail-IFD frames (the IFD0
/// beyond the prefix) ride the SANCTIONED full-file fallback (the
/// pre-pass exception class — the note line is the pre-pass's own
/// wording, byte-identical). `None` = unreadable / unparseable / no
/// readable identity tag (the UNDETERMINED arm-1 class — the caller
/// names it).
fn identity_window(src: &Path) -> Option<camera::FrameIdentity> {
    let buf = match camera::read_detection_prefix(src) {
        Ok(b) => b,
        Err(_) => return None,
    };
    match tiff::read_meta(&buf) {
        Ok(m) => camera::identity_from_ifd0(&m.ifd0, &buf).ok(),
        Err(tiff::ParseError::BadIfdOffset(_, _)) => {
            eprintln!(
                "note: {} — the camera-identity IFD beyond the 1 MiB detection prefix; reading the full file",
                src.display()
            );
            let full = match std::fs::read(src) {
                Ok(b) => b,
                Err(_) => return None,
            };
            match tiff::read_meta(&full) {
                Ok(m) => camera::identity_from_ifd0(&m.ifd0, &full).ok(),
                Err(_) => None,
            }
        }
        Err(_) => None,
    }
}

// =====================================================================
// The stem conventions (the naming + the camera id — the footage
// derivations, M0.8)
// =====================================================================

/// The per-frame stem fields (the naming-convention measurement's
/// input — the `_`-separated fields of the file stem).
fn stem_fields(path: &Path) -> Option<Vec<String>> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.split('_').map(|f| f.to_string()).collect())
}

/// The measured frame-file convention (the writer's `naming:` input —
/// M0.8's footage derivation): the stems share the pattern
/// `<prefix…>_<date8>_<seq6>` (≥ 3 fields; field[-2] = 8 digits — the
/// date; field[-1] = 6 digits — the frame number; the prefix = the
/// fields 0..len−2 — the clip), and the FIRST prefix field is
/// batch-uniform (the camera designation — the id's derivation).
/// `None` = non-convergent stems (the writer's named error — the
/// convention is unmeasured).
fn measure_naming(frames: &[PathBuf]) -> Option<String> {
    let mut first_field: Option<String> = None;
    for p in frames {
        let fields = stem_fields(p)?;
        if fields.len() < 3 {
            return None;
        }
        let date = &fields[fields.len() - 2];
        let seq = &fields[fields.len() - 1];
        if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if seq.len() != 6 || !seq.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if let Some(f) = &first_field {
            if &fields[0] != f {
                return None; // the camera designation must be batch-uniform
            }
        } else {
            first_field = Some(fields[0].clone());
        }
    }
    first_field.map(|_| "<CLIP>_<YYYYMMDD>_<NNNNNN>.DNG".to_string())
}

/// The derived camera id (M0.8's footage derivation — no invention):
/// `<first stem field (lowercased)>-<model-slug>` (the slug =
/// lowercased, whitespace → `-`): the A001 footage + model
/// SIGMA fp → `a001-sigma-fp` (the committed profile's row, reproduced
/// from the footage alone; the make rides the `make:` row — the id
/// is the model's designation, the committed id's structure).
fn camera_id_of(first_field: &str, model: &str) -> String {
    let slug = |s: &str| {
        s.trim()
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join("-")
    };
    format!("{}-{}", slug(first_field), slug(model))
}

// =====================================================================
// The divergent-tile census (R2 — the drill's class over the batch)
// =====================================================================

/// The divergent-tile census (R2 — the batch's whole-body-divergent
/// tiles, the drill's class): over the fp-class frames (in the
/// ordinal order — the walk's determinism), the per-tile 4-call drill
/// core (`decode::fp_verify_tile_full_nominal` — the EXISTING
/// detector: `Ok` = drill-verified decoded full-nominal plane, `Err`
/// = the tile fails the drill); a failed tile that DECODES is the
/// whole-body-divergent class (the decode failure is the corrupt
/// class — the named frame note, never a divergent tile). Each
/// divergent tile's delta = the quoted metric over its decoded
/// full-nominal plane vs the verified same-class neighbor's same-tile
/// plane (the walk: the ordinal ± 2k outward — the temporal-oracle
/// resolver's contract — the same-clip same-class candidates, the
/// drill-verified same tile, the ordinal-boundary stop). The bound =
/// `4 × the max measured delta` (the house rule, the quoted 4×); zero
/// measurable divergent tiles = the band unmeasurable (`band` /
/// `bound` = `None` — the candidate omits the bound row, the report
/// carries the named line). The fp frames' identities (the pass-1
/// deferral — the tail-IFD identity from the census read's full
/// bytes) are settled here; the arm-1 failures ride `unidentifiable`.
fn divergent_census(
    root: &Path,
    recs: &mut [(PathBuf, FrameRecord)],
    unidentifiable: &mut Vec<String>,
) -> TemporalBound {
    // The fp frames' (path, record) pairs in the ordinal order (the
    // ordinal-less last, by name — the deterministic census order).
    let mut fp: Vec<usize> = (0..recs.len())
        .filter(|&i| recs[i].1.class == frameclass::FrameClass::FpCameraLossless)
        .collect();
    fp.sort_by(|&a, &b| {
        recs[a]
            .1
            .ordinal
            .cmp(&recs[b].1.ordinal)
            .then_with(|| recs[a].1.rel.cmp(&recs[b].1.rel))
    });
    if fp.is_empty() {
        return TemporalBound {
            divergent: Vec::new(),
            band: None,
            bound: None,
        };
    }
    // The clip ordinal ranges (the walk's boundary — the clip's own
    // ordinal range over ALL its frames, the resolver's min/max
    // shape).
    let mut clip_range: BTreeMap<String, (Option<u64>, Option<u64>)> = BTreeMap::new();
    for (_, r) in recs.iter() {
        if let Some(o) = r.ordinal {
            let e = clip_range.entry(r.clip.clone()).or_insert((None, None));
            e.0 = Some(e.0.map(|lo| lo.min(o)).unwrap_or(o));
            e.1 = Some(e.1.map(|hi| hi.max(o)).unwrap_or(o));
        }
    }
    // The ordinal → record-index map per clip (the walk's candidate
    // domain — the fp-class records; the resolver's same-class
    // filter).
    let mut by_clip_ord: BTreeMap<String, BTreeMap<u64, usize>> = BTreeMap::new();
    for i in &fp {
        if let Some(o) = recs[*i].1.ordinal {
            by_clip_ord
                .entry(recs[*i].1.clip.clone())
                .or_default()
                .insert(o, *i);
        }
    }
    // The neighbor bytes cache (the oracle's read-only side — the
    // candidate's full bytes, read at most once per candidate;
    // silent by design).
    let mut bytes_cache: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();

    let mut divergent: Vec<DivergentTile> = Vec::new();
    for &frame_idx in &fp {
        // The record fields (the frame loop's own copies — the
        // neighbor walk's shared borrows of `recs` stay disjoint from
        // this frame's scoped settle).
        let rel = recs[frame_idx].1.rel.clone();
        let clip = recs[frame_idx].1.clip.clone();
        let ordinal = recs[frame_idx].1.ordinal;
        let path = recs[frame_idx].0.clone();
        let abs = if path.is_absolute() {
            path
        } else {
            root.join(&rel)
        };
        // The frame's bytes (the transform-class read — the frame is
        // consumed in RAM for the drill census; the identity's
        // full-file class for the fp frames' tail-IFD identity rides
        // this same read — the frame is read ONCE total).
        let bytes = match std::fs::read(&abs).with_context(|| format!("read {}", abs.display())) {
            Ok(b) => b,
            Err(err) => {
                eprintln!(
                    "note: {} — the measure census: {err} (the transform-class read — the frame is uncounted in the divergent census)",
                    rel
                );
                continue;
            }
        };
        // The header (the identity + the structure — the file's own
        // IFD: the drill's grid derivation, the product's own
        // derivation the drill runs).
        let meta = match tiff::read_meta(&bytes) {
            Ok(m) => m,
            Err(err) => {
                eprintln!(
                    "note: {} — the measure census: the frame's header does not parse ({err}) — the frame is uncounted in the divergent census",
                    rel
                );
                continue;
            }
        };
        // Settle the fp frame's identity (the pass-1 deferral — the
        // tail-IFD identity from the full bytes; the arm-1 named line
        // on failure) — the scoped mutable borrow (the neighbor
        // walk's shared borrows of `recs` follow it).
        {
            let r = &mut recs[frame_idx].1;
            if r.identity.is_none() {
                match camera::identity_from_ifd0(&meta.ifd0, &bytes) {
                    Ok(id) => r.identity = Some(id),
                    Err(_) => {
                        eprintln!(
                            "note: {rel} — no readable camera identity (the measure census: the UNDETERMINED arm-1 class — the row is uncounted)"
                        );
                        unidentifiable.push(rel.clone());
                    }
                }
            }
        }
        let structure = frameclass::structure_from_ifd0(&meta);
        let (Some(w), Some(h)) = (structure.width, structure.height) else {
            eprintln!(
                "note: {} — the measure census: the frame's geometry is unreadable (the structural-anomaly class — the frame is uncounted in the divergent census)",
                rel
            );
            continue;
        };
        let (Some(tw), Some(th)) = (structure.tile_width, structure.tile_height) else {
            eprintln!(
                "note: {} — the measure census: the frame's tile structure is unreadable (the structural-anomaly class — the frame is uncounted in the divergent census)",
                rel
            );
            continue;
        };
        let bps = match structure.bits_per_sample {
            Some(b) => b,
            None => {
                eprintln!(
                    "note: {} — the measure census: the frame's BitsPerSample is unreadable (the structural-anomaly class — the frame is uncounted in the divergent census)",
                    rel
                );
                continue;
            }
        };
        let grid = tileenc::Grid::for_dims(w, h, tw, th);
        let (offs, lens) =
            match crate::decode::tile_offsets_and_lens(&meta, &bytes, &rel) {
                Ok(v) => v,
                Err(err) => {
                    eprintln!(
                        "note: {} — the measure census: the tile stream is unreadable ({err}) — the frame is uncounted in the divergent census",
                        rel
                    );
                    continue;
                }
            };
        if offs.len() as u64 != (grid.cols * grid.rows) as u64 {
            eprintln!(
                "note: {} — the measure census: the tile count {} mismatches the file's own grid {}x{} (the structural-anomaly class — the frame is uncounted in the divergent census)",
                rel,
                offs.len(),
                grid.cols,
                grid.rows
            );
            continue;
        }
        for i in 0..offs.len() {
            let r = (i / grid.cols as usize) as u32;
            let c = (i % grid.cols as usize) as u32;
            let (o, l) = (offs[i] as usize, lens[i] as usize);
            if o + l > bytes.len() {
                eprintln!(
                    "note: {} — the measure census: tile ({r},{c})'s byte range is out of bounds (the structural-anomaly class — the tile is uncounted)",
                    rel
                );
                continue;
            }
            let stored = &bytes[o..o + l];
            // The drill's verdict (the EXISTING 4-call core — the
            // detector: `Ok` = the drill-verified decoded
            // full-nominal plane — drill-clean; `Err` = the tile
            // fails the drill).
            let verdict = crate::decode::fp_verify_tile_full_nominal(
                stored, w, h, &grid, r, c, bps as u32, &rel,
            );
            let Err(_) = verdict else {
                continue; // drill-clean (the census's silent class)
            };
            // The divergent class vs the corrupt class (the explicit
            // decode — a decode-failed tile is the corrupt class,
            // never a divergent one).
            let rect = match tileenc::tile_region(w, h, &grid, r, c) {
                Ok(rct) => rct,
                Err(err) => {
                    eprintln!(
                        "note: {} — the measure census: tile ({r},{c})'s region is unmeasurable ({err}) — the tile is uncounted",
                        rel
                    );
                    continue;
                }
            };
            let full_rect = tileenc::TileRect {
                tw: grid.tw,
                tl: grid.th,
                ..rect
            };
            let full = match tileenc::decode_tile_full_nominal_fast(
                stored,
                &full_rect,
                bps as u32,
                grid.tw,
                grid.th,
            ) {
                Ok(f) => f,
                Err(err) => {
                    eprintln!(
                        "note: {} — the measure census: tile ({r},{c})'s drill failure is a decode failure ({err}) — the corrupt class, not a divergent tile",
                        rel
                    );
                    continue;
                }
            };
            // The whole-body-divergent tile (the drill's class): the
            // neighbor walk (the temporal-oracle resolver's contract
            // — the ordinal ± 2k outward, the same-clip same-class
            // candidates, the drill-verified same tile, the
            // ordinal-boundary stop) → the delta (the quoted metric).
            let mut delta: Option<u16> = None;
            let ord = ordinal;
            let (min_ord, max_ord) = clip_range
                .get(&clip)
                .map(|(lo, hi)| (*lo, *hi))
                .unwrap_or((None, None));
            if let (Some(o), Some(ords)) = (ord, by_clip_ord.get(&clip)) {
                let mut k: u64 = 1;
                loop {
                    let mut consulted = false;
                    for cand in [o.saturating_sub(2 * k), o.saturating_add(2 * k)]
                        .iter()
                        .filter(|&&cc| {
                            min_ord.map(|lo| cc >= lo).unwrap_or(true)
                                && max_ord.map(|hi| cc <= hi).unwrap_or(true)
                        })
                    {
                        if let Some(&ni) = ords.get(cand) {
                            consulted = true;
                            let (npath, nrec) = (&recs[ni].0, &recs[ni].1);
                            // The neighbor's bytes (the oracle's
                            // read-only side — the bounded cache: the
                            // candidate is read at most once, silent
                            // by design).
                            let nkey = nrec.rel.clone();
                            let nabs = if npath.is_absolute() {
                                npath.as_path().to_path_buf()
                            } else {
                                root.join(npath)
                            };
                            let nbytes: Option<Vec<u8>> = match bytes_cache.get(&nkey) {
                                Some(v) => v.clone(),
                                None => {
                                    let v = std::fs::read(&nabs).ok();
                                    bytes_cache.insert(nkey.clone(), v.clone());
                                    v
                                }
                            };
                            let Some(nbytes) = nbytes else {
                                continue;
                            };
                            let nmeta = match tiff::read_meta(&nbytes) {
                                Ok(m) => m,
                                Err(_) => continue,
                            };
                            let (noffs, nlens) = match crate::decode::tile_offsets_and_lens(
                                &nmeta, &nbytes, &nrec.rel,
                            ) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            if i >= noffs.len() {
                                continue;
                            }
                            let (no, nl) = (noffs[i] as usize, nlens[i] as usize);
                            if no + nl > nbytes.len() {
                                continue;
                            }
                            let nstored = &nbytes[no..no + nl];
                            // The neighbor's same tile through the
                            // product's own drill core (`Ok` = the
                            // drill-verified decoded full-nominal
                            // plane — the oracle's comparison domain).
                            match crate::decode::fp_verify_tile_full_nominal(
                                nstored, w, h, &grid, r, c, bps as u32, &nrec.rel,
                            ) {
                                Ok(nplane) => {
                                    delta = max_delta(&full, &nplane);
                                    break;
                                }
                                Err(_) => continue, // not a verified neighbor — the walk continues
                            }
                        }
                    }
                    if delta.is_some() {
                        break;
                    }
                    // The ordinal-boundary stop (the resolver's
                    // no-neighbor path — both directions past the
                    // clip's ordinal range at the next step = no
                    // more candidates).
                    let beyond_lo =
                        o.saturating_sub(2 * (k + 1)) < min_ord.unwrap_or(u64::MAX);
                    let beyond_hi = o.saturating_add(2 * (k + 1)) > max_ord.unwrap_or(0);
                    if !consulted && beyond_lo && beyond_hi {
                        break;
                    }
                    k += 1;
                }
            }
            divergent.push(DivergentTile {
                frame: rel.clone(),
                ordinal,
                tile: (r, c),
                tile_index: i,
                delta,
            });
        }
    }
    // The deterministic order (the frame ordinal — the ordinal-less
    // frames last, by name — then the tile index).
    divergent.sort_by(|a, b| {
        (a.ordinal, &a.frame, a.tile_index).cmp(&(b.ordinal, &b.frame, b.tile_index))
    });
    // The band (the max measured delta) + the bound (the 4× house
    // rule — the quoted "4× the measured worst, named").
    let band = divergent.iter().filter_map(|d| d.delta).max();
    let bound = band.map(|b| b.saturating_mul(4));
    TemporalBound {
        divergent,
        band,
        bound,
    }
}

// =====================================================================
// The measure pass (R1 + R2 — the scan + the census + the bound)
// =====================================================================

/// The measure pass (R1 + R2): the scan over a source tree (clips) —
/// the bounded reads only (M0.2's reuse map) — + the per-(geometry ×
/// depth) census + the coverage census + the divergent-tile census +
/// the bound. NO writes (the candidate-profile string is the
/// writer's output — `candidate_profile`).
pub fn measure_tree(root: &Path) -> Result<Measurement, String> {
    // The frame discovery (the worker's existing DNG walk — the
    // sorted, symlink-skipping, AppleDouble-skipping tree walk).
    let frames = crate::worker::ingest::collect_dng_frames(root).map_err(|e| {
        format!(
            "profile-measure: frame discovery under {}: {e}",
            root.display()
        )
    })?;
    if frames.is_empty() {
        return Err(format!(
            "profile-measure: no .DNG frames under {} (the measure pass needs a frame source — the named absence, not an empty profile)",
            root.display()
        ));
    }

    // Pass 1 — per frame: the class + the identity (the bounded
    // reads). The fp frames' identity defers to the census pass (the
    // transform-class read carries the full bytes — the frame is read
    // ONCE total for both).
    let mut recs: Vec<(PathBuf, FrameRecord)> = Vec::new();
    let mut unidentifiable: Vec<String> = Vec::new();
    let mut unconfirmed: Vec<String> = Vec::new();
    for src in &frames {
        let rel = src
            .strip_prefix(root)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| src.display().to_string());
        let clip = crate::worker::report::clip_key_of(root, src);
        let stem = src
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let ordinal = crate::worker::checksums::frame_number_from_stem(&stem);
        // The frame-class scan (the EXISTING ingest-gate site — the
        // 512 KiB window + the sanctioned full-file fallback, the
        // named note line).
        let (class, _structure) = crate::preflight::frame_class_scan(src);
        let identity = if class == frameclass::FrameClass::FpCameraLossless {
            None // settled at the census pass (the transform-class read)
        } else {
            identity_window(src)
        };
        if identity.is_none() {
            // The arm-1 class (the non-fp frames — the fp frames'
            // identity is settled at the census pass): the named line.
            eprintln!(
                "note: {rel} — no readable camera identity (the measure census: the UNDETERMINED arm-1 class — the row is uncounted)"
            );
            unidentifiable.push(rel.clone());
        }
        recs.push((
            src.clone(),
            FrameRecord {
                rel,
                clip,
                ordinal,
                class,
                identity,
            },
        ));
    }

    // Pass 2 — the divergent-tile census (R2) over the fp frames (the
    // drill's class — the transform-class reads settle the fp frames'
    // identities first, so the row census below sees every frame's
    // identity).
    let mut recs_mut: Vec<(PathBuf, FrameRecord)> = std::mem::take(&mut recs);
    let temporal = divergent_census(root, &mut recs_mut, &mut unidentifiable);
    recs = recs_mut;

    // The class census (the pinned vocabulary's `name()`).
    let mut class_counts: BTreeMap<frameclass::FrameClass, u64> = BTreeMap::new();
    for (_, r) in &recs {
        *class_counts.entry(r.class).or_insert(0) += 1;
    }
    let frames_by_class: Vec<(frameclass::FrameClass, u64)> =
        class_counts.into_iter().collect();

    // The (W, H, bits) census (the identity's geometry × depth) + the
    // identity uniformity (the writer's single-camera contract).
    let mut row_acc: BTreeMap<(u32, u32, u16), (u64, BTreeSet<String>)> = BTreeMap::new();
    let mut readout_frames: BTreeMap<(u32, u32), u64> = BTreeMap::new();
    let mut readout_clips: BTreeMap<(u32, u32), BTreeSet<String>> = BTreeMap::new();
    let mut identity: Option<camera::FrameIdentity> = None;
    for (_, r) in &recs {
        let id = match &r.identity {
            Some(i) => i,
            None => continue, // the arm-1 class — named at the read site
        };
        // The identity uniformity (make/model — the batch is ONE
        // camera; a drift = the writer's named error at the writer
        // site, the census records the FIRST identity + names the
        // drift frames).
        match identity.as_ref() {
            Some(first) if first.make != id.make || first.model != id.model => {
                eprintln!(
                    "note: {} — camera identity {} {} drifts from the batch's {} {} (the measure census: the single-camera contract — the frame is uncounted in the rows)",
                    r.rel, id.make, id.model, first.make, first.model
                );
                unidentifiable.push(r.rel.clone());
                continue;
            }
            None => identity = Some(id.clone()),
            _ => {}
        }
        // The predicates' result (the pure cores — the confirmers):
        // the UNDETERMINED arm-2 class (no predicate confirms the
        // geometry) = the named line, never a profile row.
        if !crate::worker::encode::is_tile_geometry(id.width, id.height, id.bits_per_sample)
            && !crate::worker::encode::is_archive_geometry(id.width, id.height, id.bits_per_sample)
        {
            eprintln!(
                "note: {} — no layout predicate confirms the geometry {}x{} @{}-bit (the measure census: the UNDETERMINED arm-2 class — the readout is uncounted in the geometry rows)",
                r.rel, id.width, id.height, id.bits_per_sample
            );
            unconfirmed.push(r.rel.clone());
            continue;
        }
        let key = (id.width, id.height, id.bits_per_sample);
        let e = row_acc.entry(key).or_insert((0, BTreeSet::new()));
        e.0 += 1;
        e.1.insert(r.clip.clone());
        *readout_frames.entry((id.width, id.height)).or_insert(0) += 1;
        readout_clips
            .entry((id.width, id.height))
            .or_default()
            .insert(r.clip.clone());
    }

    // The rows (the structural constants per readout×depth — the
    // predicates' result in the canonical order + the grid dims) in
    // deterministic (W, H, bits) order.
    let first_identity = identity.clone();
    let mut rows: Vec<GeometryRowMeasured> = Vec::new();
    for ((w, h, bits), (n, clipset)) in &row_acc {
        let (tw, th) = tileenc::gate_tile_dims_depth(*w, *h, *bits as u32);
        let grid = tileenc::Grid::for_dims(*w, *h, tw, th);
        let mut preds: Vec<&'static str> = Vec::new();
        if crate::worker::encode::is_tile_geometry(*w, *h, *bits) {
            preds.push(camera::PRED_TILE);
        }
        if crate::worker::encode::is_archive_geometry(*w, *h, *bits) {
            preds.push(camera::PRED_ARCHIVE);
        }
        rows.push(GeometryRowMeasured {
            width: *w,
            height: *h,
            bits: *bits,
            photometric: first_identity
                .as_ref()
                .map(|i| i.photometric)
                .unwrap_or(0),
            predicates: preds,
            tile_w: tw,
            tile_h: th,
            grid_cols: grid.cols,
            grid_rows: grid.rows,
            frames: *n,
            clips: clipset.len() as u64,
        });
    }

    // The coverage census (per readout W×H: the frame count + the
    // clip count — the report line shape).
    let readouts: Vec<ReadoutCoverage> = readout_frames
        .iter()
        .map(|(k, n)| ReadoutCoverage {
            width: k.0,
            height: k.1,
            frames: *n,
            clips: readout_clips.get(k).map(|s| s.len() as u64).unwrap_or(0),
        })
        .collect();

    // The naming convention + the camera id (the footage derivations —
    // the batch-uniform identity's make/model + the stems' pattern).
    let naming = measure_naming(&frames);
    let camera_id = match (&naming, &identity) {
        (Some(_), Some(id)) => frames
            .first()
            .and_then(|p| stem_fields(p))
            .and_then(|f| f.into_iter().next())
            .map(|f| camera_id_of(&f, &id.model)),
        _ => None,
    };

    let clips: BTreeSet<String> = recs.iter().map(|(_, r)| r.clip.clone()).collect();

    Ok(Measurement {
        root: root.display().to_string(),
        clips: clips.len() as u64,
        frames_total: recs.len() as u64,
        frames_by_class,
        rows,
        readouts,
        identity,
        naming,
        camera_id,
        unidentifiable,
        unconfirmed,
        temporal,
    })
}

// =====================================================================
// The candidate-profile writer (R3 — the loader's inverse)
// =====================================================================

/// The candidate-profile writer (R3): the measured constants → the
/// profile file in the COMMITTED format (the a001 profile's
/// structure — the loader's expectation: the magic line + the
/// provenance header comments + the fixed key rows + the repeated
/// `geometry:` rows). The metadata: `version: 1`
/// (`camera::PROFILE_VERSION`) + `tool_version:` the current
/// (`env!("CARGO_PKG_VERSION")`). The measured bound rides the header
/// comment (the format has NO bound key — an unknown key is the
/// loader's named refusal; the zero-divergent case OMITS the bound
/// line — the named report line stands). NO file write (the pure fn
/// → the string; the write is the verb's `--out`-required surface).
pub fn candidate_profile(m: &Measurement) -> Result<String, String> {
    // The writer's named errors (the single-camera batch contract —
    // the loader's inverse is for ONE camera per file, the committed
    // format's shape).
    let identity = m.identity.as_ref().ok_or_else(|| {
        "profile-measure: the candidate profile needs a batch-uniform camera identity (no readable Make/Model — the UNDETERMINED arm-1 class, or a multi-value identity — the batch is not a single camera)".to_string()
    })?;
    let naming = m.naming.clone().ok_or_else(|| {
        "profile-measure: the frame-file convention is unmeasured (the stems do not converge on the <CLIP>_<YYYYMMDD>_<NNNNNN>.DNG pattern — the naming row is not writable)".to_string()
    })?;
    let camera_id = m.camera_id.clone().ok_or_else(|| {
        "profile-measure: the camera id is unmeasured (the stem's first field / the batch-uniform identity is absent — the camera row is not writable)".to_string()
    })?;
    let confirmed: Vec<&GeometryRowMeasured> = m
        .rows
        .iter()
        .filter(|r| !r.predicates.is_empty())
        .collect();
    if confirmed.is_empty() {
        return Err(
            "profile-measure: no confirmed (geometry × depth) rows (a profile must pin at least one measured readout/depth — the loader's own named refusal stands)".to_string(),
        );
    }
    let mut s = String::new();
    s.push_str(camera::PROFILE_MAGIC);
    s.push('\n');
    s.push_str(&format!(
        "# {camera_id} — written FROM the measurement (frameprism profile-measure {})\n",
        env!("CARGO_PKG_VERSION")
    ));
    s.push_str(&format!(
        "# the measured batch: {} clip(s), {} frame(s)\n",
        m.clips, m.frames_total
    ));
    match (&m.temporal.band, &m.temporal.bound) {
        (Some(band), Some(bound)) => {
            s.push_str(&format!(
                "# temporal bound: {bound} = 4× the measured batch divergent-tile band (max delta {band} over {} whole-body-divergent tile(s)) — the item-124 class (the tool's pinned constant FP_TEMPORAL_MAX_DELTA = 256 stands for the pinned path)\n",
                m.temporal.divergent.len()
            ));
        }
        (None, None) => {
            // The zero-measurable case: the bound row is OMITTED (the
            // named report line stands — the strict default).
        }
        _ => unreachable!("the band and the bound are Some/None together"),
    }
    s.push_str(&format!("version: {}\n", camera::PROFILE_VERSION));
    s.push_str(&format!("tool_version: {}\n", env!("CARGO_PKG_VERSION")));
    s.push_str(&format!("camera: {camera_id}\n"));
    s.push_str(&format!("make: {}\n", identity.make));
    s.push_str(&format!("model: {}\n", identity.model));
    s.push_str(&format!("photometric: {}\n", identity.photometric));
    s.push_str(&format!("naming: {naming}\n"));
    for r in &confirmed {
        s.push_str(&format!(
            "geometry: {} {} {} {}\n",
            r.width,
            r.height,
            r.bits,
            r.predicates.join(",")
        ));
    }
    Ok(s)
}

// =====================================================================
// The measure report (the report line shape — R1's coverage census)
// =====================================================================

/// The measure report (the report line shape — the coverage census:
/// per readout the frame count + the clip count; per readout×depth
/// the layout class + the grid dims; the class census; the bound —
/// or the NAMED absence line (zero measurable divergent tiles → the
/// bound is unmeasurable, the candidate omits the bound row — the
/// strict default)). A pure fn over the measurement (the per-frame
/// named lines ride the note lines at the read sites — the house
/// note class).
pub fn measurement_report(m: &Measurement) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "profile-measure census: {} clip(s), {} frame(s) ({})\n",
        m.clips, m.frames_total, m.root
    ));
    // The class census (the pinned vocabulary's `name()`).
    let class_line: Vec<String> = m
        .frames_by_class
        .iter()
        .map(|(c, n)| format!("{} {}", c.name(), n))
        .collect();
    s.push_str(&format!("class census: {}\n", class_line.join(" · ")));
    // The coverage census (per readout: the frame count + the clip
    // count) + the readout rows (the layout class + the grid dims).
    for rc in &m.readouts {
        s.push_str(&format!(
            "readout {}x{}: {} frame(s) in {} clip(s)\n",
            rc.width, rc.height, rc.frames, rc.clips
        ));
        for r in m
            .rows
            .iter()
            .filter(|r| r.width == rc.width && r.height == rc.height)
        {
            let preds = if r.predicates.is_empty() {
                "none (the UNDETERMINED arm-2 class — unconfirmed)".to_string()
            } else {
                r.predicates.join(",")
            };
            s.push_str(&format!(
                "  {}x{} @{}-bit (photometric {}): {} — grid {}x{} ({}x{}) — {} frame(s)\n",
                r.width,
                r.height,
                r.bits,
                r.photometric,
                preds,
                r.tile_w,
                r.tile_h,
                r.grid_cols,
                r.grid_rows,
                r.frames
            ));
        }
    }
    // The bound — or the named absence (the strict default).
    match (&m.temporal.band, &m.temporal.bound) {
        (Some(band), Some(bound)) => {
            s.push_str(&format!(
                "temporal bound: {bound} = 4× the measured batch divergent-tile band (max delta {band} over {} whole-body-divergent tile(s)) — the item-124 class (the tool's pinned constant FP_TEMPORAL_MAX_DELTA = 256 stands for the pinned path)\n",
                m.temporal.divergent.len()
            ));
        }
        (None, None) => {
            s.push_str(
                "temporal bound: unmeasured (zero whole-body-divergent tiles in the batch — the bound row is omitted; the strict default stands: no temporal acceptance from the profile)\n",
            );
        }
        _ => unreachable!("the band and the bound are Some/None together"),
    }
    s
}

// =====================================================================
// The profile-measure verb (the CLI surface — the measure → review →
// pin onboarding): the Args + the named refusals + the multi-root
// composition (the pure census merge) + the run (the report surface +
// the atomic write to the explicit --out path only)
// =====================================================================

/// The `--out`-REQUIRED NAMED usage refusal (the owner's ruling —
/// verbatim; the KAT pins it exact).
pub const OUT_REQUIRED_REFUSAL: &str = "usage: profile-measure requires --out <FILE> (the candidate profile is a reviewed artifact — the tool writes it where you say, nowhere else)";

/// The missing-parent-dir NAMED write refusal (the `--out`'s parent
/// absent — the candidate is written to the explicit path only: no
/// dir is created, no partial write; the KAT pins the form).
pub fn missing_parent_refusal(out: &Path) -> String {
    format!(
        "usage: profile-measure --out {}: the parent dir does not exist (the candidate profile is a reviewed artifact written to the explicit --out path only — no dir is created, no partial write)",
        out.display()
    )
}

/// The SOURCE-not-a-directory NAMED usage refusal (the pre-scan band
/// — the named line; the KAT pins the behavior).
pub fn not_a_dir_refusal(source: &Path) -> String {
    format!("profile-measure: SOURCE is not a directory: {}", source.display())
}

/// The `frameprism profile-measure` CLI arguments (the
/// `Cmd::ProfileMeasure` payload — the subcommand args live in the
/// lib, not `main.rs`, per the shared CLI restructure contract).
#[derive(ClapArgs, Debug)]
pub struct Args {
    /// The source tree(s) of clips to measure (one or more — a camera
    /// batch can span dirs; every source is scanned read-only, the
    /// bounded-read pass — the sources are never modified)
    #[arg(
        value_name = "SOURCE",
        num_args = 1..,
        required = true
    )]
    pub source: Vec<PathBuf>,

    /// The candidate profile's output path (REQUIRED — the candidate
    /// is a reviewed artifact: the tool writes it where you say,
    /// nowhere else; the parent dir must exist — a missing parent is
    /// the named refusal, no partial write)
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// The multi-root composition (R1's ruling — the PURE census merge;
/// the read path is the frozen per-root `measure_tree`, unchanged —
/// NO core restructure): one or more source trees → the per-root
/// measurements (each root's own bounded-read pass + its own
/// within-root neighbor walk) → the pure merge: the coverage census
/// per readout merged (the frame + clip counts summed — a clip name
/// shared by two roots counts once per root; the per-root census' union
/// is unmeasurable from it), the class census merged (the pinned
/// vocabulary's order), the rows merged per (W,H,bits) (the counts
/// summed; the predicates / grid dims / photometric are pure over the
/// uniform identity + geometry — identical across roots by
/// construction), the divergent-tile census concatenated + re-sorted
/// with `measure_tree`'s EXACT comparator (the stable order — the root
/// argument order breaks any cross-root ties) with the band the max
/// over the MERGED census + the bound 4× (the frozen formula), and the
/// naming / camera id re-derived over the concatenated frame list (the
/// batch-wide single-camera contract — the existing discovery walk, a
/// directory walk only: NO new read class, the tripwire untouched).
/// The cross-root identity drift (a later root a different camera) =
/// the named note + that root's rows excluded (the L4 within-root
/// drift's cross-root mirror — the frames stay counted in the totals +
/// the class census). The single-source case = the core's own
/// measurement returned as-is (the verb and the core agree by
/// construction — the continuity smoke's teeth).
pub fn measure_sources(roots: &[&Path]) -> Result<Measurement, String> {
    if roots.is_empty() {
        return Err(
            "profile-measure: no SOURCE trees (the batch needs at least one tree of clips)".to_string(),
        );
    }
    let mss: Vec<Measurement> = roots
        .iter()
        .map(|r| measure_tree(r))
        .collect::<Result<Vec<_>, _>>()?;
    if mss.len() == 1 {
        return Ok(mss
            .into_iter()
            .next()
            .expect("the single measurement"));
    }
    merge_measurements(roots, &mss)
}

/// The pure census merge over the per-root measurements (no read
/// site — the composition is over the measurements only + the
/// discovery walk for the batch-wide naming / camera id).
fn merge_measurements(
    roots: &[&Path],
    mss: &[Measurement],
) -> Result<Measurement, String> {
    // The batch-uniform identity (the argument order: the first
    // readable identity) + the cross-root drift verdict (the
    // single-camera contract — the L4 within-root drift's cross-root
    // mirror: a later root a different camera = the named note + its
    // rows uncounted).
    let identity = mss
        .iter()
        .find(|m| m.identity.is_some())
        .and_then(|m| m.identity.clone());
    let drifted: Vec<bool> = mss
        .iter()
        .map(|m| {
            matches!(
                (&identity, &m.identity),
                (Some(a), Some(b)) if a.make != b.make || a.model != b.model
            )
        })
        .collect();
    for (i, is_drifted) in drifted.iter().enumerate() {
        if *is_drifted {
            let m = &mss[i];
            let id = m
                .identity
                .as_ref()
                .expect("a drifted root has a readable identity");
            let first = identity
                .as_ref()
                .expect("a drift implies the merged identity");
            eprintln!(
                "note: {} — camera identity {} {} drifts from the batch's {} {} (the measure census: the single-camera contract — the root's frames are uncounted in the rows)",
                m.root, id.make, id.model, first.make, first.model
            );
        }
    }
    // The rows + the readouts (the drifted roots' contribution
    // excluded — the L4 within-root semantics' cross-root mirror) +
    // the class census (every frame, drift included — the L4
    // within-root shape) + the named lists (concatenated; the
    // drifted roots' named entry = their root line).
    let mut row_acc: BTreeMap<(u32, u32, u16), (u64, u64)> = BTreeMap::new();
    let mut row_first: BTreeMap<(u32, u32, u16), GeometryRowMeasured> = BTreeMap::new();
    let mut readout_acc: BTreeMap<(u32, u32), (u64, u64)> = BTreeMap::new();
    let mut readout_first: BTreeMap<(u32, u32), ReadoutCoverage> = BTreeMap::new();
    let mut class_acc: BTreeMap<frameclass::FrameClass, u64> = BTreeMap::new();
    let mut unidentifiable: Vec<String> = Vec::new();
    let mut unconfirmed: Vec<String> = Vec::new();
    for (m, is_drifted) in mss.iter().zip(drifted.iter()) {
        for (c, n) in &m.frames_by_class {
            *class_acc.entry(*c).or_insert(0) += n;
        }
        unidentifiable.extend(m.unidentifiable.iter().cloned());
        unconfirmed.extend(m.unconfirmed.iter().cloned());
        if *is_drifted {
            unidentifiable.push(m.root.clone());
            continue;
        }
        for r in &m.rows {
            let key = (r.width, r.height, r.bits);
            row_first.entry(key).or_insert_with(|| r.clone());
            let e = row_acc.entry(key).or_insert((0, 0));
            e.0 += r.frames;
            e.1 += r.clips;
        }
        for rc in &m.readouts {
            let key = (rc.width, rc.height);
            readout_first.entry(key).or_insert_with(|| rc.clone());
            let e = readout_acc.entry(key).or_insert((0, 0));
            e.0 += rc.frames;
            e.1 += rc.clips;
        }
    }
    let mut rows: Vec<GeometryRowMeasured> = Vec::new();
    for (key, (frames, clips)) in &row_acc {
        let mut r = row_first
            .get(key)
            .expect("the row's first occurrence")
            .clone();
        r.frames = *frames;
        r.clips = *clips;
        rows.push(r);
    }
    let readouts: Vec<ReadoutCoverage> = readout_acc
        .iter()
        .map(|(key, (frames, clips))| {
            let mut rc = readout_first
                .get(key)
                .expect("the readout's first occurrence")
                .clone();
            rc.frames = *frames;
            rc.clips = *clips;
            rc
        })
        .collect();
    // The divergent-tile census (the concatenation re-sorted with
    // `measure_tree`'s EXACT comparator — the stable order; the band
    // the max over the MERGED census; the bound 4× — the frozen
    // formula).
    let mut divergent: Vec<DivergentTile> = Vec::new();
    for m in mss {
        divergent.extend(m.temporal.divergent.iter().cloned());
    }
    divergent.sort_by(|a, b| {
        (a.ordinal, &a.frame, a.tile_index)
            .cmp(&(b.ordinal, &b.frame, b.tile_index))
    });
    let band = divergent.iter().filter_map(|d| d.delta).max();
    let bound = band.map(|b| b.saturating_mul(4));
    // The batch-wide naming + the camera id (the concatenated frame
    // list — the EXISTING discovery walk: a directory walk only, no
    // new read class; the same contract a single pass over the
    // combined frames would derive).
    let mut frames: Vec<PathBuf> = Vec::new();
    for r in roots {
        frames.extend(
            crate::worker::ingest::collect_dng_frames(r)
                .map_err(|e| {
                    format!(
                        "profile-measure: frame discovery under {}: {e}",
                        r.display()
                    )
                })?,
        );
    }
    let naming = measure_naming(&frames);
    let camera_id = match (&naming, &identity) {
        (Some(_), Some(id)) => frames
            .first()
            .and_then(|p| stem_fields(p))
            .and_then(|f| f.into_iter().next())
            .map(|f| camera_id_of(&f, &id.model)),
        _ => None,
    };
    Ok(Measurement {
        root: mss
            .iter()
            .map(|m| m.root.clone())
            .collect::<Vec<_>>()
            .join(", "),
        clips: mss.iter().map(|m| m.clips).sum(),
        frames_total: mss.iter().map(|m| m.frames_total).sum(),
        frames_by_class: class_acc.into_iter().collect(),
        rows,
        readouts,
        identity,
        naming,
        camera_id,
        unidentifiable,
        unconfirmed,
        temporal: TemporalBound {
            divergent,
            band,
            bound,
        },
    })
}
/// The candidate's write (the house's user-facing artifact idiom —
/// the hidden same-dir temp + the atomic rename, the
/// `derived::write_manifest` / `checksums::write_sidecar` pattern:
/// a kill mid-write never leaves a torn candidate; the explicit path
/// only — the caller's pre-scan parent-dir check stands, no dir is
/// created here; the leftover tmp is cleaned on the write/rename
/// failure).
fn write_candidate(out: &Path, content: &str) -> std::io::Result<()> {
    let name = out
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "candidate.profile".to_string());
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let tmp = parent.join(format!(".{name}.profile-measure.tmp"));
    if let Err(err) = std::fs::write(&tmp, content).and_then(|_| std::fs::rename(&tmp, out))
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(())
}

/// The `Cmd::ProfileMeasure` match arm (main.rs): run the
/// measurement + the candidate write, return the process exit code
/// (0 = the report printed + the candidate written; 2 = the named
/// pre-scan refusals / the discovery + the writer's named errors /
/// the write failure — the candidate is the verb's only artifact:
/// it is not written = the refusal band).
pub fn run(args: &Args) -> ExitCode {
    // The `--out`-REQUIRED usage refusal (the owner's ruling — the
    // named line, the rc=2 band; before the first read).
    let out = match &args.out {
        Some(p) => p.clone(),
        None => {
            eprintln!("error: {}", OUT_REQUIRED_REFUSAL);
            return ExitCode::from(2);
        }
    };
    // The missing-parent-dir write refusal (no dir is created, no
    // partial write — before the first read).
    if !out.parent().map(|p| p.is_dir()).unwrap_or(false) {
        eprintln!("error: {}", missing_parent_refusal(&out));
        return ExitCode::from(2);
    }
    // The sources (the pre-scan band — a non-directory SOURCE is the
    // named refusal).
    for s in &args.source {
        if !s.is_dir() {
            eprintln!("error: {}", not_a_dir_refusal(s));
            return ExitCode::from(2);
        }
    }
    // The measurement (the frozen read-only pass — one source = the
    // core's own `measure_tree`; more = the pure census merge).
    let roots: Vec<&Path> = args.source.iter().map(|p| p.as_path()).collect();
    let m = match measure_sources(&roots) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };
    // The report surface (stdout — the measure's output IS the
    // report: the coverage census per readout + the class census +
    // the divergent-tile census (the count + the band + the bound, or
    // the named zero-case line); the UNDETERMINED arms' named lines
    // ride the scan's note lines — the L4 report shape).
    print!("{}", measurement_report(&m));
    // The candidate (the L4 pure writer — the loader's inverse).
    let cand = match candidate_profile(&m) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };
    // The write (the explicit path only — the house's atomic
    // temp+rename: a kill mid-write never leaves a torn candidate).
    match write_candidate(&out, &cand) {
        Ok(()) => {
            println!(
                "candidate profile written: {} (the measured candidate — review it, then keep it with the camera's pins to pin the camera)",
                out.display()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: write {}: {err:#}", out.display());
            ExitCode::from(2)
        }
    }
}

// =====================================================================
// The KATs (the house inline pattern — the census's pins)
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // The synthetic fp-frame builder (the house materializer
    // mechanism — the L2 precedent: the deterministic splitmix64
    // 512×368 plane, the tool's own Natural-PSV1 encode = the
    // drill-clean stored tile, the 13-entry IFD0's measured fp
    // container shape — compression 7 + 512×368 + the out-of-line
    // 324/325 + the TimeCodes). The prefix flip
    // (`bad_tile[12] ^= 0x01`) = the whole-body-divergent class (the
    // drill's named refusal — the L2 KAT's pinned mechanism).
    fn synth_fp_frame(make: &str, model: &str, tc: [u8; 8], divergent_tile0: bool) -> (Vec<u8>, Vec<u8>) {
        // The deterministic high-entropy plane (the splitmix64 — the
        // camera-free test ground truth; the high entropy lands the
        // tile streams at the fp camera's per-tile class, so the
        // tail-IFD offset lands beyond the detection prefixes — the
        // sanctioned full-file reads fire, as on the real frames).
        let plane: Vec<u16> = (0..(512 * 368))
            .map(|i| {
                let mut x = (i as u64)
                    .wrapping_mul(0x9E3779B97F4A7C15)
                    .wrapping_add(0xD1B54A32D192ED03);
                x ^= x >> 30;
                x = x.wrapping_mul(0xBF58476D1CE4E5B9);
                x ^= x >> 27;
                x ^= x >> 31;
                (x & 0x0FFF) as u16
            })
            .collect();
        let full_rect = tileenc::TileRect {
            x0: 0,
            y0: 0,
            tw: 512,
            tl: 368,
        };
        let planes = tileenc::planes_from_tile_rows(&plane, &full_rect, 368, tileenc::Orient::Natural)
            .expect("the plane's Natural orientation rows");
        let good = tileenc::encode_tile_planes(&planes, 12, 1).expect("the Natural-PSV1 encode");
        let mut bad = good.clone();
        bad[12] ^= 0x01; // the prefix flip — the whole-body class
        let tile0 = if divergent_tile0 { &bad } else { &good };
        let tiles: Vec<Vec<u8>> = (0..48)
            .map(|i| if i == 0 { tile0.clone() } else { good.clone() })
            .collect();
        let make_b = format!("{make}\0").into_bytes();
        let model_b = format!("{model}\0").into_bytes();
        let blob_len: u64 = tiles.iter().map(|t| t.len() as u64).sum();
        let ifd_size: u64 = 2 + 13 * 12 + 4;
        let ifd_off = 8 + blob_len;
        let make_off = ifd_off + ifd_size;
        let model_off = make_off + make_b.len() as u64;
        let o324_off = model_off + model_b.len() as u64;
        let o325_off = o324_off + (tiles.len() as u64) * 4;
        let tc_off = o325_off + (tiles.len() as u64) * 4;
        let mut offs = Vec::with_capacity(tiles.len());
        let mut cursor: u64 = 8;
        for t in &tiles {
            offs.push(cursor);
            cursor += t.len() as u64;
        }
        let mut b = Vec::new();
        b.extend_from_slice(b"II*\0");
        b.extend_from_slice(&(ifd_off as u32).to_le_bytes());
        for t in &tiles {
            b.extend_from_slice(t);
        }
        b.extend_from_slice(&13u16.to_le_bytes());
        let emit = |b: &mut Vec<u8>, tag: u16, typ: u16, count: u32, val: u32| {
            b.extend_from_slice(&tag.to_le_bytes());
            b.extend_from_slice(&typ.to_le_bytes());
            b.extend_from_slice(&count.to_le_bytes());
            b.extend_from_slice(&val.to_le_bytes());
        };
        emit(&mut b, 256, 4, 1, 3856);
        emit(&mut b, 257, 4, 1, 2170);
        emit(&mut b, 258, 4, 1, 12);
        emit(&mut b, 259, 3, 1, 7);
        emit(&mut b, 262, 4, 1, 32803);
        emit(&mut b, 271, 2, make_b.len() as u32, make_off as u32);
        emit(&mut b, 272, 2, model_b.len() as u32, model_off as u32);
        emit(&mut b, 277, 4, 1, 1);
        emit(&mut b, 322, 4, 1, 512);
        emit(&mut b, 323, 4, 1, 368);
        emit(&mut b, 324, 4, tiles.len() as u32, o324_off as u32);
        emit(&mut b, 325, 4, tiles.len() as u32, o325_off as u32);
        emit(&mut b, 51043, 1, 8, tc_off as u32);
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&make_b);
        b.extend_from_slice(&model_b);
        for o in &offs {
            b.extend_from_slice(&(*o as u32).to_le_bytes());
        }
        for t in &tiles {
            b.extend_from_slice(&(t.len() as u32).to_le_bytes());
        }
        b.extend_from_slice(&tc);
        (b, good)
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "frameprism-measure-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("the temp dir");
        d
    }

    // KAT-1 — the scan over the committed fixtures (the oracle10
    // 10-frame sample, copied to a temp dir — the corpus-free house
    // pattern): the readout row + the coverage census line
    // BYTE-pinned (the predicates' result + the grid dims + the
    // counts) + the writer's inputs (the identity + the naming + the
    // footage-derived camera id) + the report line shape.
    #[test]
    fn scan_census_committed_fixtures() {
        let src = Path::new("../ci/oracle10/src");
        if !src.exists() {
            eprintln!("skip: {} (absent)", src.display());
            return;
        }
        let root = tmp_dir("oracle10");
        for p in std::fs::read_dir(src).expect("the oracle10 dir").flatten() {
            let name = p.file_name();
            if name.to_string_lossy().to_ascii_lowercase().ends_with(".dng") {
                std::fs::copy(p.path(), root.join(&name)).expect("the copy");
            }
        }
        let m = measure_tree(&root).expect("the scan");
        assert_eq!(m.frames_total, 10, "the oracle10 sample is 10 frames");
        assert_eq!(m.clips, 1, "the sample is one clip (the input root)");
        // The class census (the pinned vocabulary's `name()` — the
        // measured composition pinned at M1).
        let classes: Vec<String> = m
            .frames_by_class
            .iter()
            .map(|(c, n)| format!("{} {}", c.name(), n))
            .collect();
        assert_eq!(classes, vec!["raw-uncompressed 10"], "the oracle10 sample's class (the original A001 raw footage — the M1 measurement)");
        // The readout row (the predicates' result + the grid dims —
        // the M0.6's quoted constants): 3856×2170 @12 = the tile
        // layout (3856×2170@12 is the ONLY tile predicate) + the
        // archive layout → `tile,archive`; the grid = the 482×272
        // default, 8×8 (64 tiles — the manifest's "64 tiles 482x272").
        assert_eq!(m.rows.len(), 1, "one readout×depth (3856×2170@12)");
        let r = &m.rows[0];
        assert_eq!((r.width, r.height, r.bits), (3856, 2170, 12));
        assert_eq!(r.predicates, vec![camera::PRED_TILE, camera::PRED_ARCHIVE]);
        assert_eq!((r.tile_w, r.tile_h, r.grid_cols, r.grid_rows), (482, 272, 8, 8));
        assert_eq!(r.frames, 10);
        assert_eq!(r.clips, 1);
        // The coverage census (per readout: the frame count + the
        // clip count).
        assert_eq!(m.readouts.len(), 1);
        assert_eq!(
            (
                m.readouts[0].width,
                m.readouts[0].height,
                m.readouts[0].frames,
                m.readouts[0].clips
            ),
            (3856, 2170, 10, 1)
        );
        // The identity (the self-description — the committed profile's
        // camera).
        let id = m.identity.as_ref().expect("the identity");
        assert_eq!(
            (id.make.as_str(), id.model.as_str(), id.photometric),
            ("SIGMA", "SIGMA fp", 32803)
        );
        // The naming convention (the measured pattern) + the camera
        // id (the footage derivation — the sample's FPTEST
        // designation).
        assert_eq!(m.naming.as_deref(), Some("<CLIP>_<YYYYMMDD>_<NNNNNN>.DNG"));
        assert_eq!(m.camera_id.as_deref(), Some("fptest-sigma-fp"));
        // The report line shape (the coverage census — the pinned
        // form).
        let report = measurement_report(&m);
        let expected = format!(
            "profile-measure census: 1 clip(s), 10 frame(s) ({})\nclass census: raw-uncompressed 10\nreadout 3856x2170: 10 frame(s) in 1 clip(s)\n  3856x2170 @12-bit (photometric 32803): tile,archive — grid 482x272 (8x8) — 10 frame(s)\ntemporal bound: unmeasured (zero whole-body-divergent tiles in the batch — the bound row is omitted; the strict default stands: no temporal acceptance from the profile)\n",
            root.display()
        );
        assert_eq!(report, expected, "the report line shape (the pinned form)");
        // The writer over the fixture measurement (the candidate's
        // shape — the loader parses it; KAT-5's round trip pins the
        // structure here too).
        let cand = candidate_profile(&m).expect("the writer");
        let parsed = camera::parse_profile(&cand).expect("the loader's parse");
        assert_eq!(parsed.camera, "fptest-sigma-fp");
        assert_eq!(parsed.geometries.len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    // KAT-2 — the synthetic geometry matrix (the 4 readout
    // geometries × the 3 native depths — `synth_dng_frame`): the
    // per-row layout class (the predicates' result) + the grid dims
    // BYTE-pinned (the M0.6's quoted grid constants — the
    // `gate_tile_dims_depth` contract).
    #[test]
    fn scan_census_synthetic_geometry_matrix() {
        let root = tmp_dir("matrix");
        let cases: [((u32, u32), u16, Vec<&'static str>, (u32, u32, u32, u32)); 12] = [
            ((3856, 2170), 12, vec![camera::PRED_TILE, camera::PRED_ARCHIVE], (482, 272, 8, 8)),
            ((3856, 2170), 10, vec![camera::PRED_ARCHIVE], (964, 272, 4, 8)),
            ((3856, 2170), 8, vec![camera::PRED_ARCHIVE], (482, 272, 8, 8)),
            ((1936, 1090), 12, vec![camera::PRED_ARCHIVE], (242, 274, 8, 4)),
            ((1936, 1090), 10, vec![camera::PRED_ARCHIVE], (484, 274, 4, 4)),
            ((1936, 1090), 8, vec![camera::PRED_ARCHIVE], (242, 274, 8, 4)),
            ((2016, 1344), 12, vec![camera::PRED_ARCHIVE], (252, 336, 8, 4)),
            ((2016, 1344), 10, vec![camera::PRED_ARCHIVE], (252, 336, 8, 4)),
            ((2016, 1344), 8, vec![camera::PRED_ARCHIVE], (252, 336, 8, 4)),
            ((3024, 2010), 12, vec![camera::PRED_ARCHIVE], (252, 252, 12, 8)),
            ((3024, 2010), 10, vec![camera::PRED_ARCHIVE], (252, 252, 12, 8)),
            ((3024, 2010), 8, vec![camera::PRED_ARCHIVE], (252, 252, 12, 8)),
        ];
        let mut i = 0u32;
        for ((w, h), bits, want_preds, (tw, th, gc, gr)) in &cases {
            i += 1;
            let name = format!("MX_{:08}_{:06}.DNG", 20260101u32, i);
            let bytes = crate::camera::synth_dng_frame("SIGMA", "SIGMA fp", *w, *h, *bits, 32803, None);
            std::fs::write(root.join(&name), &bytes).expect("the fixture");
            let scan = measure_tree(&root).expect("the scan");
            let row = scan
                .rows
                .iter()
                .find(|r| r.width == *w && r.height == *h && r.bits == *bits)
                .expect("the row");
            assert_eq!(
                row.predicates.as_slice(),
                want_preds.as_slice(),
                "{}x{} @{}: the predicates' result (the confirmers)",
                w,
                h,
                bits
            );
            assert_eq!(
                (row.tile_w, row.tile_h, row.grid_cols, row.grid_rows),
                (*tw, *th, *gc, *gr),
                "{}x{} @{}: the grid dims (the quoted gate_tile_dims_depth contract)",
                w,
                h,
                bits
            );
        }
        // The full scan's shape (12 rows, 4 readouts, the coverage).
        let m = measure_tree(&root).expect("the scan");
        assert_eq!(m.rows.len(), 12);
        assert_eq!(m.readouts.len(), 4);
        for rc in &m.readouts {
            assert_eq!(rc.frames, 3, "three depths per readout");
            assert_eq!(rc.clips, 1);
        }
        // The writer's inputs (the uniform identity + the convention
        // + the footage-derived id — the single-clip MX batch).
        assert_eq!(m.camera_id.as_deref(), Some("mx-sigma-fp"));
        assert_eq!(m.naming.as_deref(), Some("<CLIP>_<YYYYMMDD>_<NNNNNN>.DNG"));
        // The zero-divergent bound (the synthetic raw frames — no fp
        // tiles to drill): the named absence (the strict default).
        assert_eq!(m.temporal.bound, None);
        assert!(
            measurement_report(&m).contains(
                "temporal bound: unmeasured (zero whole-body-divergent tiles in the batch — the bound row is omitted; the strict default stands: no temporal acceptance from the profile)"
            ),
            "the named absence line (the strict default)"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // KAT-3 — the bound derivation (the synthetic divergent batch:
    // frame 000001 clean + frame 000003 the tile-0 prefix-flip
    // divergent — the house materializer mechanism): the census =
    // EXACTLY 1 divergent tile (frame 3, tile 0 — the walk reaches
    // frame 1, 2k apart, the same-clip same-class contract), the
    // delta D pinned, the band = D + the bound = 4D pinned (the 4×
    // rule's execution), the metric's exact-boundary parity pinned.
    #[test]
    fn bound_derivation_divergent_batch() {
        let root = tmp_dir("bound");
        let (clean, good_tile) = synth_fp_frame("SIGMA", "SIGMA fp", [0; 8], false);
        let (divergent, _) = synth_fp_frame("SIGMA", "SIGMA fp", [0; 8], true);
        std::fs::write(
            root.join("FPB_001_20260101_000001.DNG"),
            &clean,
        )
        .expect("the clean frame");
        std::fs::write(
            root.join("FPB_001_20260101_000003.DNG"),
            &divergent,
        )
        .expect("the divergent frame");
        let m = measure_tree(&root).expect("the scan");
        // The census: EXACTLY 1 divergent tile (frame 3, tile 0).
        assert_eq!(
            m.temporal.divergent.len(),
            1,
            "one whole-body-divergent tile in the batch (the drill's class; the 47 drill-clean tiles are the census's silent class)"
        );
        let d = &m.temporal.divergent[0];
        assert_eq!(d.frame, "FPB_001_20260101_000003.DNG");
        assert_eq!(d.ordinal, Some(3));
        assert_eq!(d.tile, (0, 0), "the tile-0 prefix flip");
        assert_eq!(d.tile_index, 0);
        let delta = d
            .delta
            .expect("the verified neighbor's same tile (frame 1, 2k apart) — the delta is measurable");
        assert!(delta <= 4095, "the 12-bit domain's delta");
        // The band + the bound (the 4× house rule — the quoted 4×).
        assert_eq!(m.temporal.band, Some(delta));
        assert_eq!(m.temporal.bound, Some(delta.saturating_mul(4)));
        // The report line (the pinned form over the measurement).
        assert!(
            measurement_report(&m).contains(&format!(
                "temporal bound: {} = 4× the measured batch divergent-tile band (max delta {} over 1 whole-body-divergent tile(s))",
                delta * 4,
                delta
            )),
            "the bound line (the pinned form)"
        );
        // The writer's bound row (the header comment — the format has
        // NO bound key; the loader skips it).
        let cand = candidate_profile(&m).expect("the writer");
        assert!(
            cand.contains(&format!(
                "# temporal bound: {} = 4× the measured batch divergent-tile band (max delta {} over 1 whole-body-divergent tile(s)) — the item-124 class (the tool's pinned constant FP_TEMPORAL_MAX_DELTA = 256 stands for the pinned path)",
                delta * 4,
                delta
            )),
            "the candidate's bound row (the provenance comment)"
        );
        assert!(
            cand.contains("geometry: 3856 2170 12 tile,archive"),
            "the measured row"
        );
        // The metric's parity (the quoted expression vs the
        // predicate's EXACT boundary — 256 → accept / 257 → refuse —
        // the `FP_TEMPORAL_MAX_DELTA` boundary): the synthetic
        // boundary pin over the metric + the predicate's own
        // behavior at the boundary (the parity: the metric's value
        // IS the predicate's comparison).
        {
            let base: Vec<u16> = vec![100; 64];
            let at_bound: Vec<u16> = (0..64).map(|i| if i == 0 { 356 } else { 100 }).collect();
            let over_bound: Vec<u16> = (0..64).map(|i| if i == 0 { 357 } else { 100 }).collect();
            assert_eq!(max_delta(&base, &at_bound), Some(256));
            assert_eq!(max_delta(&base, &over_bound), Some(257));
            assert!(
                crate::decode::fp_temporal_in_band(&base, &at_bound),
                "256 → accept (the exact boundary — the ≤ contract)"
            );
            assert!(
                !crate::decode::fp_temporal_in_band(&base, &over_bound),
                "257 → refuse (the exact boundary)"
            );
            assert_eq!(max_delta(&base, &base), Some(0));
            assert_eq!(
                max_delta(&base, &vec![1; 63]),
                None,
                "the length mismatch — the unmeasurable class (never accepts, the safe direction)"
            );
            // The drill core's domain (the good tile's decoded plane
            // — the comparison domain the census uses).
            let grid = tileenc::Grid::for_dims(3856, 2170, 512, 368);
            let good_plane = crate::decode::fp_verify_tile_full_nominal(
                &good_tile, 3856, 2170, &grid, 0, 0, 12, "kat-good",
            )
            .expect("the good tile's drill core (the comparison domain)");
            assert_eq!(good_plane.len(), 512 * 368);
            assert!(
                crate::decode::fp_temporal_in_band(&good_plane, &good_plane),
                "the self-comparison → 0 → accept (the metric's identity)"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    // KAT-4 — the zero-divergent case (the clean synthetic fp
    // batch): zero divergent tiles → the band unmeasurable → the
    // bound is OMITTED from the candidate + the NAMED report line
    // pinned + the candidate still parses (the strict default — the
    // loader's behavior for a bound-less profile is the NORM, M0.7).
    #[test]
    fn bound_zero_divergent_omitted_named() {
        let root = tmp_dir("zerobound");
        let (a, _) = synth_fp_frame("SIGMA", "SIGMA fp", [0; 8], false);
        let (b, _) = synth_fp_frame("SIGMA", "SIGMA fp", [0; 8], false);
        std::fs::write(
            root.join("FZB_001_20260101_000001.DNG"),
            &a,
        )
        .expect("the frame");
        std::fs::write(
            root.join("FZB_001_20260101_000003.DNG"),
            &b,
        )
        .expect("the frame");
        let m = measure_tree(&root).expect("the scan");
        assert!(
            m.temporal.divergent.is_empty(),
            "zero whole-body-divergent tiles (the clean batch)"
        );
        assert_eq!(m.temporal.band, None);
        assert_eq!(m.temporal.bound, None);
        // The named report line (the pinned form — the strict
        // default).
        let report = measurement_report(&m);
        assert!(
            report.contains(
                "temporal bound: unmeasured (zero whole-body-divergent tiles in the batch — the bound row is omitted; the strict default stands: no temporal acceptance from the profile)"
            ),
            "the named absence line: {report}"
        );
        // The candidate OMITS the bound row (the zero case — the
        // header carries no bound line) + still parses (the strict
        // default — the loader's norm for a bound-less profile).
        let cand = candidate_profile(&m).expect("the writer");
        assert!(
            !cand.contains("temporal bound:"),
            "the bound row is omitted (the zero case)"
        );
        let parsed = camera::parse_profile(&cand).expect("the loader parses the bound-less candidate (the norm)");
        assert_eq!(parsed.geometries.len(), 1);
        assert_eq!(
            (
                parsed.geometries[0].width,
                parsed.geometries[0].height,
                parsed.geometries[0].bits
            ),
            (3856, 2170, 12)
        );
        assert_eq!(
            parsed.geometries[0].predicates,
            vec![camera::PRED_TILE, camera::PRED_ARCHIVE]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // KAT-5 — the round trip (the writer as the loader's INVERSE):
    // the writer's output → `parse_profile` Ok → the structural rows
    // preserved; the write→load→write byte-stability on the
    // structural rows (the metadata excluded); the magic / key-order
    // pins; the body's `temporal_*` row → the loader's named
    // `unknown key` refusal (the format boundary — the bound rides
    // the header comment, never the body).
    #[test]
    fn writer_round_trip_loader_inverse() {
        let root = tmp_dir("roundtrip");
        let (a, _) = synth_fp_frame("SIGMA", "SIGMA fp", [0; 8], false);
        std::fs::write(root.join("FRT_001_20260101_000001.DNG"), &a).expect("the frame");
        let m = measure_tree(&root).expect("the scan");
        let cand = candidate_profile(&m).expect("the writer");
        // The shape pins (the loader's expectation — the committed
        // format).
        let lines: Vec<&str> = cand.lines().collect();
        assert_eq!(lines[0], camera::PROFILE_MAGIC, "the magic line (line 1)");
        let key_order: Vec<&str> = lines
            .iter()
            .copied()
            .filter(|l| !l.starts_with('#'))
            .take(7)
            .map(|l| l.split_once(':').unwrap().0)
            .collect();
        assert_eq!(
            key_order,
            vec!["version", "tool_version", "camera", "make", "model", "photometric", "naming"],
            "the committed key order (the a001 profile's shape)"
        );
        assert!(cand.contains("version: 1\n"), "the format version");
        assert!(
            cand.contains("tool_version: 0.3.0\n"),
            "the current tool version (the metadata ruling)"
        );
        assert!(
            cand.contains("camera: frt-sigma-fp\n"),
            "the footage-derived camera id"
        );
        assert!(cand.contains("make: SIGMA\n"));
        assert!(cand.contains("model: SIGMA fp\n"));
        assert!(cand.contains("photometric: 32803\n"));
        assert!(cand.contains("naming: <CLIP>_<YYYYMMDD>_<NNNNNN>.DNG\n"));
        // The round trip (the loader parses the writer's output — the
        // structural rows preserved).
        let p1 = camera::parse_profile(&cand).expect("the loader's parse (the inverse)");
        assert_eq!(p1.version, 1);
        assert_eq!(p1.make, "SIGMA");
        assert_eq!(p1.model, "SIGMA fp");
        assert_eq!(p1.photometric, 32803);
        assert_eq!(p1.naming, "<CLIP>_<YYYYMMDD>_<NNNNNN>.DNG");
        assert_eq!(p1.geometries.len(), 1);
        let g = &p1.geometries[0];
        assert_eq!((g.width, g.height, g.bits), (3856, 2170, 12));
        assert_eq!(
            g.predicates,
            vec![camera::PRED_TILE, camera::PRED_ARCHIVE]
        );
        // The write→load→write byte-stability on the structural rows
        // (the loader round-trip reconstructs the measurement's
        // structural inputs — the identity's geometry rows + the
        // metadata rows; the header regenerates deterministically).
        let m2 = Measurement {
            root: m.root.clone(),
            clips: m.clips,
            frames_total: m.frames_total,
            frames_by_class: m.frames_by_class.clone(),
            rows: m.rows.clone(),
            readouts: m.readouts.clone(),
            identity: Some(camera::FrameIdentity {
                make: p1.make.clone(),
                model: p1.model.clone(),
                width: g.width,
                height: g.height,
                bits_per_sample: g.bits,
                photometric: p1.photometric,
            }),
            naming: Some(p1.naming.clone()),
            camera_id: Some(p1.camera.clone()),
            unidentifiable: Vec::new(),
            unconfirmed: Vec::new(),
            temporal: TemporalBound {
                divergent: Vec::new(),
                band: None,
                bound: None,
            },
        };
        let cand2 = candidate_profile(&m2).expect("the re-write (load → write)");
        let structural = |s: &str| -> Vec<String> {
            s.lines()
                .filter(|l| !l.starts_with('#'))
                .filter(|l| !l.starts_with("tool_version:"))
                .map(|l| l.to_string())
                .collect()
        };
        assert_eq!(
            structural(&cand),
            structural(&cand2),
            "the structural rows' write→load→write byte-stability (the metadata excluded)"
        );
        // The format boundary (the bound is NEVER a body key — the
        // loader's named refusal; the bound rides the header
        // comment).
        let with_body_bound = format!("{cand}\ntemporal_max_delta: 256\n");
        let err = camera::parse_profile(&with_body_bound)
            .expect_err("the unknown key — the format boundary");
        assert!(
            err.contains("unknown key: temporal_max_delta"),
            "the loader's named unknown-key refusal: {err}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // KAT-6 — the loader's behavior for a profile WITHOUT the bound
    // row (the M0.7 decision point pinned as a KAT): the committed
    // `profiles/a001-sigma-fp.profile` parses Ok WITHOUT any bound
    // row — the absence is the NORM (the committed pin itself is
    // bound-less; the temporal acceptance is the tool's constant +
    // the fp-transcode path's ctx, never profile-keyed — the strict
    // default).
    #[test]
    fn loader_no_bound_row_is_the_norm() {
        let text = std::fs::read_to_string("../profiles/a001-sigma-fp.profile")
            .expect("the committed profile (the pinned path)");
        assert!(
            !text
                .lines()
                .any(|l| !l.starts_with('#')
                    && l.split_once(':')
                        .map(|(k, _)| k.trim() == "temporal_max_delta")
                        .unwrap_or(false)),
            "the committed profile carries NO bound row (the format has no bound key — the M0.7's on-disk truth)"
        );
        let p = camera::parse_profile(&text)
            .expect("the loader parses the bound-less committed profile (the pinned path's norm)");
        assert_eq!(p.camera, "a001-sigma-fp");
        assert_eq!(
            p.geometries.len(),
            12,
            "the committed profile's 12 readout×depth rows"
        );
    }

    // KAT-7 — the A001 reproduction (R4 — the corpus-conditional, the
    // house skip pattern): the measure pass over the A001 batch (the
    // canonical worktree placement `../testdata/originals_A001_013`
    // — the maintainer's corpus layout — or the test-only env
    // override `FRAMEPRISM_A001_013_SOURCE` — M3 points it at the
    // disk mirror) → the row-level reproduction (EVERY measured
    // geometry row BYTE-IDENTICAL to the committed profile's row for
    // the same readout — the pin is a function of the footage) + the
    // EXACT diff (the pinned expectation — the M0.9's measured diff:
    // the absent geometry rows + the tool_version line + the header
    // provenance — and NOTHING else). Absent both sources = the
    // named skip (the fresh CI stays at the base suite line).
    #[test]
    fn a001_reproduction_corpus_conditional() {
        let canonical = Path::new("../testdata/originals_A001_013");
        let root = match std::env::var("FRAMEPRISM_A001_013_SOURCE") {
            Ok(p) if !p.is_empty() => PathBuf::from(p),
            _ => canonical.to_path_buf(),
        };
        if !root.join("A001_013_20260930_000001.DNG").exists() {
            eprintln!(
                "skip: {} (absent — the A001_013 corpus; the named skip, the house pattern)",
                root.display()
            );
            return;
        }
        let committed_text =
            std::fs::read_to_string("../profiles/a001-sigma-fp.profile")
                .expect("the committed profile");
        let committed = camera::parse_profile(&committed_text).expect("the committed profile's parse");
        let m = measure_tree(&root).expect("the scan over the A001 batch");

        // The batch's census (the M0.9's measured shape — the single
        // clip, the 723-frame mixed batch: 362 fp-camera + 361 raw,
        // the 3856×2170@12 readout).
        assert_eq!(m.clips, 1, "the A001_013 batch is one clip");
        assert_eq!(
            m.frames_total,
            723,
            "the 723-frame batch (the L2 clip-level proof's count)"
        );
        let class_map: std::collections::BTreeMap<&str, u64> = m
            .frames_by_class
            .iter()
            .map(|(c, n)| (c.name(), *n))
            .collect();
        assert_eq!(
            class_map.get("fp-camera-lossless").copied(),
            Some(362),
            "the 362 fp-camera frames (the L2 proof's count)"
        );
        assert_eq!(
            class_map.get("raw-uncompressed").copied(),
            Some(361),
            "the 361 raw frames (the L2 proof's count)"
        );
        // The measured readout (the batch's geometry — the fp AND the
        // raw frames share the 3856×2170@12 readout).
        assert_eq!(
            m.rows.len(),
            1,
            "one readout×depth in the batch (the M0.9's measured shape)"
        );
        let r = &m.rows[0];
        assert_eq!(
            (r.width, r.height, r.bits),
            (3856, 2170, 12),
            "the readout (measured, not guessed)"
        );
        assert_eq!(
            r.predicates,
            vec![camera::PRED_TILE, camera::PRED_ARCHIVE]
        );
        assert_eq!((r.tile_w, r.tile_h, r.grid_cols, r.grid_rows), (482, 272, 8, 8));
        assert_eq!(r.frames, 723);

        // THE ROW-LEVEL REPRODUCTION (the acceptance's teeth — the
        // pin is a function of the footage): the measured geometry
        // row BYTE-IDENTICAL to the committed profile's row for the
        // same (W, H, bits).
        let committed_row = committed
            .geometries
            .iter()
            .find(|g| g.width == r.width && g.height == r.height && g.bits == r.bits)
            .expect("the committed profile carries the batch's readout row");
        assert_eq!(
            format!(
                "geometry: {} {} {} {}",
                r.width,
                r.height,
                r.bits,
                r.predicates.join(",")
            ),
            format!(
                "geometry: {} {} {} {}",
                committed_row.width,
                committed_row.height,
                committed_row.bits,
                committed_row.predicates.join(",")
            ),
            "the measured row = the committed row (byte-identical incl. the predicates — the reproduction)"
        );

        // THE CANDIDATE (the writer over the measurement) + the EXACT
        // DIFF (the pinned expectation — the M0.9's measured diff,
        // not a guess).
        let cand = candidate_profile(&m).expect("the writer over the A001 measurement");
        let cand_lines: Vec<&str> = cand.lines().collect();
        let body: Vec<&str> = cand_lines.iter().copied().filter(|l| !l.starts_with('#')).collect();
        let committed_lines: Vec<&str> = committed_text.lines().collect();
        let committed_body: Vec<&str> =
            committed_lines.iter().copied().filter(|l| !l.starts_with('#')).collect();
        // The equal body rows (the metadata — the camera id's footage
        // derivation + the identity's measured rows + the version +
        // the naming).
        for row in [
            "version: 1",
            "camera: a001-sigma-fp",
            "make: SIGMA",
            "model: SIGMA fp",
            "photometric: 32803",
            "naming: <CLIP>_<YYYYMMDD>_<NNNNNN>.DNG",
        ] {
            assert!(
                body.iter().any(|l| *l == row),
                "the candidate carries the committed row: {row}"
            );
            assert!(
                committed_body.iter().any(|l| *l == row),
                "the committed profile carries: {row}"
            );
        }
        // The tool_version (the EXACT diff's metadata component — the
        // writer's current version vs the committed 0.1.0).
        let tv = format!("tool_version: {}", env!("CARGO_PKG_VERSION"));
        assert!(body.iter().any(|l| *l == tv.as_str()), "the candidate's tool_version = the current (the diff's metadata component)");
        assert!(
            committed_body.iter().any(|l| *l == "tool_version: 0.1.0"),
            "the committed 0.1.0 (the diff's metadata component)"
        );
        // The geometry rows' EXACT diff (the pinned expectation — the
        // candidate's row set = the measured readout; the committed's
        // absent rows = the 11 readouts the corpus does not carry).
        let cand_geom: Vec<String> = body
            .iter()
            .filter(|l| l.starts_with("geometry:"))
            .map(|l| l.to_string())
            .collect();
        let committed_geom: Vec<String> = committed_body
            .iter()
            .filter(|l| l.starts_with("geometry:"))
            .map(|l| l.to_string())
            .collect();
        assert_eq!(
            cand_geom,
            vec!["geometry: 3856 2170 12 tile,archive".to_string()],
            "the candidate's geometry rows (the measured readout — the M0.9's measured shape)"
        );
        let absent: Vec<&str> = committed_geom
            .iter()
            .filter(|g| !cand_geom.iter().any(|c| c.as_str() == g.as_str()))
            .map(|s| s.as_str())
            .collect();
        assert_eq!(
            absent,
            vec![
                "geometry: 3856 2170 10 archive",
                "geometry: 3856 2170 8 archive",
                "geometry: 1936 1090 12 archive",
                "geometry: 1936 1090 10 archive",
                "geometry: 1936 1090 8 archive",
                "geometry: 2016 1344 12 archive",
                "geometry: 2016 1344 10 archive",
                "geometry: 2016 1344 8 archive",
                "geometry: 3024 2010 12 archive",
                "geometry: 3024 2010 10 archive",
                "geometry: 3024 2010 8 archive",
            ],
            "the EXACT diff's geometry component (the pinned expectation — the 11 absent rows, the M0.9's measured diff)"
        );
        // The divergent-tile census (the batch's 3 corpus-divergent
        // tiles — the L2 clip-level proof's f277 t(5,4) / f287
        // t(0,5) / f395 t(5,4), the linear 44 / 5 / 44 on the 8×6
        // grid) + the bound (the 4× house rule over the measured
        // band).
        assert_eq!(
            m.temporal.divergent.len(),
            3,
            "the 3 corpus-divergent tiles (the L2 proof's census)"
        );
        let tiles: Vec<(u64, (u32, u32))> = m
            .temporal
            .divergent
            .iter()
            .map(|d| (d.ordinal.expect("the ordinal"), d.tile))
            .collect();
        assert_eq!(
            tiles,
            vec![(277, (5, 4)), (287, (0, 5)), (395, (5, 4))],
            "the divergent tiles (the L2 proof's exact census — the drill's class)"
        );
        assert!(
            m.temporal
                .divergent
                .iter()
                .all(|d| d.delta.is_some()),
            "each divergent tile's verified neighbor — the delta is measurable"
        );
        assert_eq!(
            m.temporal.band,
            m.temporal
                .divergent
                .iter()
                .filter_map(|d| d.delta)
                .max(),
            "the band = the max measured delta"
        );
        assert_eq!(
            m.temporal.bound,
            m.temporal.band.map(|b| b.saturating_mul(4)),
            "the bound = 4× the band (the house rule)"
        );
        // The header's bound row (the provenance comment — the diff's
        // bound component — the committed header carries none).
        let bound_line = cand_lines
            .iter()
            .find(|l| l.starts_with("# temporal bound:"))
            .expect("the candidate's bound row (the header comment — the zero case's omission is KAT-4's pin)");
        assert!(
            bound_line.contains(&format!(
                " = 4× the measured batch divergent-tile band (max delta {} over 3 whole-body-divergent tile(s))",
                m.temporal.band.expect("the band")
            )),
            "the bound row's pinned form: {bound_line}"
        );
        assert!(
            !committed_lines
                .iter()
                .any(|l| l.starts_with("# temporal bound:")),
            "the committed header carries NO bound row (the diff's bound component — the M0.9's measured diff)"
        );
        // The report's bound line (the pinned form over the batch).
        assert!(
            measurement_report(&m).contains(&format!(
                "temporal bound: {} = 4× the measured batch divergent-tile band (max delta {} over 3 whole-body-divergent tile(s))",
                m.temporal.bound.expect("the bound"),
                m.temporal.band.expect("the band")
            )),
            "the report's bound line (the pinned form)"
        );
    }

    // KAT-8 — the `--out`-REQUIRED usage refusal (the owner's
    // ruling — the verbatim line + the rc=2 band; the refusal
    // precedes the discovery walk — no source is read).
    #[test]
    fn profile_measure_out_required_refusal() {
        assert_eq!(
            OUT_REQUIRED_REFUSAL,
            "usage: profile-measure requires --out <FILE> (the candidate profile is a reviewed artifact — the tool writes it where you say, nowhere else)",
            "the verbatim line (the owner's ruling — the KAT's pin)"
        );
        let args = Args {
            source: vec![PathBuf::from("/does-not-matter-for-the-refusal-shape")],
            out: None,
        };
        assert_eq!(run(&args), ExitCode::from(2), "the rc=2 band (before any read)");
    }

    // KAT-9 — the missing-parent-dir write refusal (the named line +
    // the rc=2 band + NO partial file + NO dir created — the
    // pre-scan refusal, zero work) + the SOURCE-not-a-directory
    // refusal (the same pre-scan band).
    #[test]
    fn profile_measure_missing_parent_refusal() {
        let base = tmp_dir("missingparent");
        let out = base.join("no-such-dir").join("candidate.profile");
        assert_eq!(
            missing_parent_refusal(&out),
            format!(
                "usage: profile-measure --out {}: the parent dir does not exist (the candidate profile is a reviewed artifact written to the explicit --out path only — no dir is created, no partial write)",
                out.display()
            ),
            "the named line (the pinned form)"
        );
        let args = Args {
            source: vec![base.clone()],
            out: Some(out.clone()),
        };
        assert_eq!(run(&args), ExitCode::from(2), "the rc=2 band (before the scan — zero work)");
        assert!(!out.exists(), "no partial file");
        assert!(!base.join("no-such-dir").exists(), "no dir created");
        // The SOURCE-not-a-directory refusal (the pre-scan band — the
        // parent exists, the source does not).
        let args2 = Args {
            source: vec![base.join("not-a-dir")],
            out: Some(base.join("candidate.profile")),
        };
        assert_eq!(run(&args2), ExitCode::from(2), "the rc=2 band (the source's named refusal)");
        assert!(!base.join("candidate.profile").exists(), "no partial file (the source's refusal)");
        let _ = std::fs::remove_dir_all(&base);
    }

    // KAT-10 — the write continuity (the verb over the synthetic
    // batch: the written file BYTE-IDENTICAL to the core's own
    // candidate — the verb and the core agree; the atomic write
    // leaves no hidden tmp behind).
    #[test]
    fn profile_measure_write_continuity() {
        let root = tmp_dir("verbcont");
        let (a, _) = synth_fp_frame("SIGMA", "SIGMA fp", [0; 8], false);
        std::fs::write(root.join("FVC_001_20260101_000001.DNG"), &a).expect("the frame");
        let outdir = tmp_dir("verbcont-out");
        let out = outdir.join("fvc-sigma-fp.profile");
        let args = Args {
            source: vec![root.clone()],
            out: Some(out.clone()),
        };
        assert_eq!(run(&args), ExitCode::SUCCESS, "the clean run (the report + the write)");
        let written = std::fs::read_to_string(&out).expect("the written candidate");
        let m = measure_tree(&root).expect("the core's own scan");
        let cand = candidate_profile(&m).expect("the core's own writer");
        assert_eq!(
            written, cand,
            "the verb's write = the core's candidate (byte-identical — the verb and the core agree)"
        );
        // The atomic write's cleanup (no hidden tmp left behind).
        let leftovers: Vec<String> = std::fs::read_dir(&outdir)
            .expect("the out dir")
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with('.') && n.ends_with(".profile-measure.tmp"))
            .collect();
        assert!(leftovers.is_empty(), "the hidden tmp is renamed away (no leftover)");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outdir);
    }

    // KAT-11 — the multi-root pure census merge (two roots, the same
    // camera, two clips — the per-readout coverage census merged: the
    // frame + clip counts summed; the class census merged; the row's
    // frames summed + the clips 2; the naming + the camera id over
    // the concatenated stems; the census line over the joined roots
    // — the pinned form).
    #[test]
    fn profile_measure_multi_root_census_merge() {
        let r1 = tmp_dir("mroot1");
        let r2 = tmp_dir("mroot2");
        let c1 = r1.join("MRA_001");
        let c2 = r2.join("MRA_002");
        std::fs::create_dir_all(&c1).expect("the clip dir");
        std::fs::create_dir_all(&c2).expect("the clip dir");
        let f1 = crate::camera::synth_dng_frame("SIGMA", "SIGMA fp", 3856, 2170, 12, 32803, None);
        let f2 = crate::camera::synth_dng_frame("SIGMA", "SIGMA fp", 3856, 2170, 12, 32803, None);
        std::fs::write(c1.join("MRA_001_20260101_000001.DNG"), &f1).expect("the frame");
        std::fs::write(c2.join("MRA_002_20260101_000001.DNG"), &f2).expect("the frame");
        let roots: Vec<&Path> = vec![r1.as_path(), r2.as_path()];
        let m = measure_sources(&roots).expect("the merged measurement");
        assert_eq!(m.frames_total, 2, "the frame total (the sum)");
        assert_eq!(m.clips, 2, "the clip count (the per-root sum — distinct names)");
        let classes: Vec<String> = m
            .frames_by_class
            .iter()
            .map(|(c, n)| format!("{} {}", c.name(), n))
            .collect();
        assert_eq!(classes, vec!["raw-uncompressed 2"], "the class census (the merge)");
        assert_eq!(m.rows.len(), 1, "one readout×depth (the merge)");
        let r = &m.rows[0];
        assert_eq!((r.width, r.height, r.bits), (3856, 2170, 12));
        assert_eq!(r.predicates, vec![camera::PRED_TILE, camera::PRED_ARCHIVE]);
        assert_eq!(r.frames, 2, "the row's frame count (the sum)");
        assert_eq!(r.clips, 2, "the row's clip count (the merge — two distinct clips)");
        assert_eq!(m.readouts.len(), 1);
        assert_eq!(
            (m.readouts[0].frames, m.readouts[0].clips),
            (2, 2),
            "the coverage census (the merge)"
        );
        let id = m.identity.as_ref().expect("the batch-uniform identity");
        assert_eq!((id.make.as_str(), id.model.as_str()), ("SIGMA", "SIGMA fp"));
        assert_eq!(
            m.naming.as_deref(),
            Some("<CLIP>_<YYYYMMDD>_<NNNNNN>.DNG"),
            "the batch-wide naming (the concatenated stems)"
        );
        assert_eq!(
            m.camera_id.as_deref(),
            Some("mra-sigma-fp"),
            "the footage-derived id (the first frame's first field)"
        );
        assert_eq!(m.temporal.bound, None, "the raw frames — no divergent tiles");
        // The census line (the pinned form over the joined roots).
        let report = measurement_report(&m);
        assert!(
            report.starts_with(&format!(
                "profile-measure census: 2 clip(s), 2 frame(s) ({}, {})\n",
                r1.display(),
                r2.display()
            )),
            "the census line over the joined roots:\n{report}"
        );
        // The writer over the merged measurement (the merged counts'
        // row shape — the structural rows' form unchanged).
        let cand = candidate_profile(&m).expect("the writer over the merge");
        assert!(cand.contains("camera: mra-sigma-fp\n"), "the merged camera id: {cand}");
        assert!(
            cand.contains("geometry: 3856 2170 12 tile,archive\n"),
            "the merged row: {cand}"
        );
        let _ = std::fs::remove_dir_all(&r1);
        let _ = std::fs::remove_dir_all(&r2);
    }

    // KAT-12 — the multi-root divergent census merge (one root's
    // synthetic divergent batch + one root's clean synthetic batch:
    // the merged census = the divergent root's tile only; the band
    // the max over the MERGED census; the bound 4× — the frozen
    // formula; the merged candidate's bound line over the merged
    // count).
    #[test]
    fn profile_measure_multi_root_bound_merge() {
        let r1 = tmp_dir("mband1");
        let r2 = tmp_dir("mband2");
        let c1 = r1.join("FMB_001");
        let c2 = r2.join("FMB_002");
        std::fs::create_dir_all(&c1).expect("the clip dir");
        std::fs::create_dir_all(&c2).expect("the clip dir");
        let (clean, _) = synth_fp_frame("SIGMA", "SIGMA fp", [0; 8], false);
        let (divergent, _) = synth_fp_frame("SIGMA", "SIGMA fp", [0; 8], true);
        std::fs::write(c1.join("FMB_001_20260101_000001.DNG"), &clean).expect("the clean frame");
        std::fs::write(c1.join("FMB_001_20260101_000003.DNG"), &divergent).expect("the divergent frame");
        let (a, _) = synth_fp_frame("SIGMA", "SIGMA fp", [0; 8], false);
        let (b, _) = synth_fp_frame("SIGMA", "SIGMA fp", [0; 8], false);
        std::fs::write(c2.join("FMB_002_20260101_000001.DNG"), &a).expect("the clean frame");
        std::fs::write(c2.join("FMB_002_20260101_000003.DNG"), &b).expect("the clean frame");
        let roots: Vec<&Path> = vec![r1.as_path(), r2.as_path()];
        let m = measure_sources(&roots).expect("the merged measurement");
        // The merged divergent census: EXACTLY the divergent root's
        // tile (the clean root contributes nothing — the census over
        // the batch).
        assert_eq!(
            m.temporal.divergent.len(),
            1,
            "one whole-body-divergent tile in the batch (the merged census)"
        );
        let d = &m.temporal.divergent[0];
        assert_eq!(d.frame, "FMB_001/FMB_001_20260101_000003.DNG");
        assert_eq!(d.ordinal, Some(3));
        assert_eq!(d.tile, (0, 0), "the tile-0 prefix flip (the KAT-3 mechanism)");
        let delta = d
            .delta
            .expect("the verified neighbor's same tile — the delta is measurable");
        // The band the max over the MERGED census + the bound 4×
        // (the frozen formula).
        assert_eq!(m.temporal.band, Some(delta), "the band (the max over the merged census)");
        assert_eq!(
            m.temporal.bound,
            Some(delta.saturating_mul(4)),
            "the bound (the frozen 4×)"
        );
        // The merged candidate's bound line (over the merged count —
        // 1 tile over the whole batch).
        let cand = candidate_profile(&m).expect("the writer over the merge");
        assert!(
            cand.contains(&format!(
                "# temporal bound: {} = 4× the measured batch divergent-tile band (max delta {} over 1 whole-body-divergent tile(s))",
                delta * 4,
                delta
            )),
            "the merged bound line (the merged count):\n{cand}"
        );
        // The class census (the merge over the fp frames).
        let classes: Vec<String> = m
            .frames_by_class
            .iter()
            .map(|(c, n)| format!("{} {}", c.name(), n))
            .collect();
        assert_eq!(
            classes,
            vec!["fp-camera-lossless 4"],
            "the class census (4 fp frames over the two roots)"
        );
        let _ = std::fs::remove_dir_all(&r1);
        let _ = std::fs::remove_dir_all(&r2);
    }

    // KAT-13 — the FULL-TREE A001 reproduction (the R4 UPGRADED
    // acceptance — the corpus-conditional, the house skip pattern):
    // the measure over the FULL original tree (the env override
    // `FRAMEPRISM_A001_ORIGINALS_SOURCE` or the canonical worktree
    // placement `../testdata/originals_A001` — absent both = the
    // named skip; the fresh CI stays at the base suite line) →
    // EVERY committed geometry row the tree covers REPRODUCED
    // byte-identical + the EXACT candidate-vs-committed diff (the
    // M0's MEASURED diff — the header provenance + the tool_version +
    // the bound comment — and NOTHING else; the tree covers all 12
    // committed rows, so the absent-row component is empty).
    #[test]
    fn a001_full_tree_reproduction_corpus_conditional() {
        let canonical = Path::new("../testdata/originals_A001");
        let root = match std::env::var("FRAMEPRISM_A001_ORIGINALS_SOURCE") {
            Ok(p) if !p.is_empty() => PathBuf::from(p),
            _ => canonical.to_path_buf(),
        };
        let present = root.join("A001_013_20260930_000001.DNG").exists()
            || root.join("A001_013").join("A001_013_20260930_000001.DNG").exists();
        if !present {
            eprintln!(
                "skip: {} (absent — the A001 full-tree corpus; the named skip, the house pattern)",
                root.display()
            );
            return;
        }
        let committed_text =
            std::fs::read_to_string("../profiles/a001-sigma-fp.profile")
                .expect("the committed profile");
        let m = measure_tree(&root).expect("the scan over the full tree");

        // The batch's census (the M0's MEASURED shape — the 13-clip
        // tree on disk (A001_001..A001_013), the 1924-frame batch:
        // 362 fp-camera (all in A001_013) + 1562 raw-uncompressed).
        assert_eq!(
            m.clips, 13,
            "the 13-clip tree (A001_001..A001_013 — the measured census)"
        );
        assert_eq!(m.frames_total, 1924, "the 1924-frame batch (the measured census)");
        let class_map: std::collections::BTreeMap<&str, u64> = m
            .frames_by_class
            .iter()
            .map(|(c, n)| (c.name(), *n))
            .collect();
        assert_eq!(
            class_map.get("fp-camera-lossless").copied(),
            Some(362),
            "the 362 fp-camera frames (all in A001_013 — the L2/L4 proof's clip)"
        );
        assert_eq!(
            class_map.get("raw-uncompressed").copied(),
            Some(1562),
            "the 1562 raw frames (the other 12 clips + A001_013's raw side)"
        );

        // THE ROW-LEVEL REPRODUCTION (the acceptance's teeth — the
        // pin is a function of the footage): the measured row set =
        // the committed profile's 12 rows EXACTLY — every committed
        // row the tree covers is REPRODUCED byte-identical (the tree
        // covers all 12 — the absent-row component of the diff is
        // empty).
        let committed = camera::parse_profile(&committed_text).expect("the committed profile's parse");
        assert_eq!(
            committed.geometries.len(),
            12,
            "the committed profile's 12 readout×depth rows"
        );
        assert_eq!(m.rows.len(), 12, "the 12 measured readout×depth rows (the measured census)");
        let committed_row_str: Vec<String> = committed
            .geometries
            .iter()
            .map(|g| {
                format!(
                    "geometry: {} {} {} {}",
                    g.width, g.height, g.bits, g.predicates.join(",")
                )
            })
            .collect();
        for r in &m.rows {
            let measured = format!(
                "geometry: {} {} {} {}",
                r.width, r.height, r.bits, r.predicates.join(",")
            );
            assert!(
                committed_row_str.iter().any(|c| c == &measured),
                "the measured row byte-identical to a committed row (the reproduction): {measured}"
            );
        }

        // THE EXACT DIFF (the pinned expectation — the M0's measured
        // diff, not a guess): the body diff = the tool_version line
        // ONLY (0.1.0 → the current); the 12 geometry rows + the 6
        // metadata rows present in both, byte-identical; the header
        // diff = the provenance (the candidate's 4 header lines vs
        // the committed's provenance block) + the candidate's bound
        // comment (the committed header carries none).
        let cand = candidate_profile(&m).expect("the writer over the full-tree measurement");
        let cand_lines: Vec<&str> = cand.lines().collect();
        let committed_lines: Vec<&str> = committed_text.lines().collect();
        fn body_of<'a>(lines: &[&'a str]) -> Vec<&'a str> {
            lines.iter().copied().filter(|l| !l.starts_with('#')).collect()
        }
        let cand_body = body_of(&cand_lines);
        let committed_body = body_of(&committed_lines);
        for row in [
            "version: 1",
            "camera: a001-sigma-fp",
            "make: SIGMA",
            "model: SIGMA fp",
            "photometric: 32803",
            "naming: <CLIP>_<YYYYMMDD>_<NNNNNN>.DNG",
        ] {
            assert!(
                cand_body.iter().any(|l| *l == row) && committed_body.iter().any(|l| *l == row),
                "the equal body row: {row}"
            );
        }
        // The geometry rows' EXACT diff (the pinned expectation — the
        // row sets equal: the candidate's 12 measured rows = the
        // committed's 12; the tree covers every committed row, so
        // the absent-row component is EMPTY).
        let cand_geom: Vec<&str> = cand_body.iter().filter(|l| l.starts_with("geometry:")).copied().collect();
        let committed_geom: Vec<&str> = committed_body
            .iter()
            .filter(|l| l.starts_with("geometry:"))
            .copied()
            .collect();
        assert_eq!(cand_geom.len(), 12, "the candidate's 12 geometry rows (the measured readouts)");
        assert_eq!(committed_geom.len(), 12, "the committed's 12 geometry rows");
        let cand_geom_set: std::collections::BTreeSet<&str> = cand_geom.iter().copied().collect();
        let committed_geom_set: std::collections::BTreeSet<&str> =
            committed_geom.iter().copied().collect();
        assert_eq!(
            cand_geom_set, committed_geom_set,
            "the geometry row sets equal — every committed row the tree covers REPRODUCED byte-identical (the absent-row component empty)"
        );
        // The tool_version (the body diff's ONLY component — the
        // writer's current version vs the committed 0.1.0) + the
        // body's exact shape (nothing else differs).
        let tv = format!("tool_version: {}", env!("CARGO_PKG_VERSION"));
        assert!(
            cand_body.iter().any(|l| *l == tv.as_str()),
            "the candidate's tool_version (the diff's metadata component)"
        );
        assert!(
            committed_body.iter().any(|l| *l == "tool_version: 0.1.0"),
            "the committed 0.1.0 (the diff's metadata component)"
        );
        assert_eq!(
            cand_body.len(),
            19,
            "the candidate's body: 7 metadata + 12 geometry (nothing else)"
        );
        assert_eq!(
            committed_body.len(),
            19,
            "the committed's body: 7 metadata + 12 geometry (nothing else)"
        );
        let equal_body = [
            "version: 1",
            "camera: a001-sigma-fp",
            "make: SIGMA",
            "model: SIGMA fp",
            "photometric: 32803",
            "naming: <CLIP>_<YYYYMMDD>_<NNNNNN>.DNG",
        ];
        let cand_other: Vec<&str> = cand_body
            .iter()
            .copied()
            .filter(|l| !l.starts_with("geometry:") && *l != tv.as_str() && !equal_body.contains(l))
            .collect();
        assert!(
            cand_other.is_empty(),
            "no other candidate body row (the body diff = the tool_version only): {cand_other:?}"
        );

        // The header (the diff's provenance + bound components): the
        // candidate's 4 header lines (the magic + the id line + the
        // batch line + the bound line) over the MEASURED values (the
        // band 28, the bound 112, the 3 tiles); the committed header
        // carries NO bound line (the committed pin itself is
        // bound-less — the norm).
        let cand_header: Vec<&str> = cand_lines.iter().copied().take_while(|l| l.starts_with('#')).collect();
        assert_eq!(
            cand_header.len(),
            4,
            "the candidate's header: the magic + 3 provenance lines"
        );
        assert_eq!(cand_header[0], camera::PROFILE_MAGIC, "the magic line (line 1)");
        assert_eq!(
            cand_header[1],
            format!("# a001-sigma-fp — written FROM the measurement (frameprism profile-measure {})", env!("CARGO_PKG_VERSION")),
            "the id line (the writer's frozen form over the footage-derived id)"
        );
        assert_eq!(
            cand_header[2],
            "# the measured batch: 13 clip(s), 1924 frame(s)",
            "the batch line (the measured census)"
        );
        assert_eq!(
            cand_header[3],
            "# temporal bound: 112 = 4× the measured batch divergent-tile band (max delta 28 over 3 whole-body-divergent tile(s)) — the item-124 class (the tool's pinned constant FP_TEMPORAL_MAX_DELTA = 256 stands for the pinned path)",
            "the bound line (the measured values — the diff's bound component)"
        );
        assert!(
            !committed_lines.iter().any(|l| l.starts_with("# temporal bound:")),
            "the committed header carries NO bound line (the diff's bound component)"
        );

        // The divergent census (the batch's 3 corpus-divergent
        // tiles — all in A001_013, the L2/L4 proof's clip): the
        // measured band 28 → the bound 112 (the 4× house rule).
        assert_eq!(
            m.temporal.divergent.len(),
            3,
            "the 3 corpus-divergent tiles (the L2/L4 proof's census)"
        );
        let tiles: Vec<(u64, (u32, u32))> = m
            .temporal
            .divergent
            .iter()
            .map(|d| (d.ordinal.expect("the ordinal"), d.tile))
            .collect();
        assert_eq!(
            tiles,
            vec![(277, (5, 4)), (287, (0, 5)), (395, (5, 4))],
            "the divergent tiles (the L2/L4 proof's exact census)"
        );
        assert!(
            m.temporal
                .divergent
                .iter()
                .all(|d| d.frame.starts_with("A001_013/")),
            "the divergent tiles are all in A001_013 (the fp-camera clip)"
        );
        assert!(
            m.temporal
                .divergent
                .iter()
                .all(|d| d.delta.is_some()),
            "each divergent tile's verified neighbor — the delta is measurable"
        );
        assert_eq!(m.temporal.band, Some(28), "the band (the measured max delta — the L4 proof's value)");
        assert_eq!(
            m.temporal.bound,
            Some(112),
            "the bound (4× the band — the house rule)"
        );
        // The report's bound line (the pinned form over the batch).
        assert!(
            measurement_report(&m).contains(
                "temporal bound: 112 = 4× the measured batch divergent-tile band (max delta 28 over 3 whole-body-divergent tile(s))"
            ),
            "the report's bound line (the pinned form over the measured batch)"
        );
    }
}
