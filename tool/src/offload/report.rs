//! The offload's report orchestration: the standalone run entry
//! points (the pre-write refusals → the core → the records → the
//! stderr → the rc), the run-report multi-shape rendering + the
//! job-report + the ascmhl integration (the `created:` / `host:` /
//! `profiles:` emission sites), the verdict + status line rendering.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};

use super::manifests::{OffloadRow, Verdict, clip_key_of_rel, write_offload_manifest};
use super::traversal::{
    canonicalize_path, check_dest_writable, is_path_prefix, top_level_names,
};
use super::transfer::{OffloadCoreMulti, offload_core_multi};

/// One per-clip verdict block (the clip key = the ingest-manifest key
/// space: the relpath's parent dir, "" = the source root).
#[derive(Clone, Debug)]
pub struct ClipBlock {
    pub clip: String,
    pub total: u64,
    pub ok: u64,
}


/// The offload result over the whole `<in>` tree (all files).
#[derive(Clone, Debug)]
pub struct OffloadReport {
    pub input: PathBuf,
    pub dest: PathBuf,
    pub rows: Vec<OffloadRow>,
    pub clips: Vec<ClipBlock>,
}


impl OffloadReport {
    /// The dirty row count (0 = the verify-before-wipe gate is clean).
    pub fn dirty_count(&self) -> usize {
        self.rows.iter().filter(|r| r.verdict != Verdict::Ok).count()
    }

    /// The named FAIL lines (deterministic order: the row order).
    pub fn fail_lines(&self) -> Vec<String> {
        self.rows
            .iter()
            .filter(|r| r.verdict != Verdict::Ok)
            .map(|r| {
                let clip = clip_key_of_rel(&r.file);
                if r.verdict == Verdict::CopyFail {
                    format!(
                        "FAIL COPY_FAIL clip={}: {}: {}",
                        crate::worker::display_clip(&clip),
                        r.file,
                        r.detail
                    )
                } else {
                    format!(
                        "FAIL {} clip={}: {} ({})",
                        r.verdict.as_str(),
                        crate::worker::display_clip(&clip),
                        r.file,
                        r.detail
                    )
                }
            })
            .collect()
    }

    /// The verify-before-wipe line (the exact formats):
    /// `offload: VERIFIED <n>/<n> (dest <dir>)` or `offload: REFUSE
    /// <k> named row(s) (dest <dir>)`.
    pub fn verdict_line(&self) -> String {
        let total = self.rows.len();
        if self.dirty_count() == 0 {
            format!(
                "offload: VERIFIED {total}/{total} (dest {})",
                self.dest.display()
            )
        } else {
            format!(
                "offload: REFUSE {} named row(s) (dest {})",
                self.dirty_count(),
                self.dest.display()
            )
        }
    }

    /// The PAIR verdict line (the multi-shape — the `--source`
    /// form's per-(source, dest) pair line: the existing line's shape
    /// with the source slot added — the legacy `verdict_line()` is
    /// byte-frozen, this is the new multi-form): `offload:
    /// VERIFIED <n>/<n> (source <in>, dest <d>)` / `offload:
    /// REFUSE <k> named row(s) (source <in>, dest <d>)` — the source
    /// slot = the source AS GIVEN on the CLI (the report's `input`),
    /// the dest slot = the canonical dest (the report's `dest`).
    pub fn pair_verdict_line(&self) -> String {
        let total = self.rows.len();
        if self.dirty_count() == 0 {
            format!(
                "offload: VERIFIED {total}/{total} (source {}, dest {})",
                self.input.display(),
                self.dest.display()
            )
        } else {
            format!(
                "offload: REFUSE {} named row(s) (source {}, dest {})",
                self.dirty_count(),
                self.input.display(),
                self.dest.display()
            )
        }
    }
}


/// The standalone offload (the 1-dest call — the frozen contract):
/// `run_offload_multi` over a single dest — the pre-write refusals
/// (the input exists + is a dir, the self-mirror guard, the dest
/// probe — before any write), the read-only pre-copy detection scan,
/// the copy+verify core, the per-clip manifests (the mirrored clip
/// roots — beside the mirrored clip), the run report (the dest
/// root), the stderr verdict (the encode idiom), the rc.
pub fn run_offload(input: &Path, dest: &Path) -> Result<ExitCode> {
    let d = dest.to_path_buf();
    run_offload_multi(input, std::slice::from_ref(&d))
}


/// The standalone N-dest offload (the multi-destination fan-out —
/// `frameprism offload <in> <to> [<to> ...]`): the pre-write
/// refusals (the input exists + is a dir — checked once; the
/// self-mirror guard per dest; the duplicate-dest refusal — named,
/// never silently deduped; the per-dest writability probe — the N
/// probes complete before the first source read: ZERO partial
/// writes anywhere), the read-only pre-copy detection scan (ONCE —
/// the detection is source-side), the read-once/write-N core (the
/// source's sha256 computed once, shared by every dest's rows), the
/// per-dest per-clip manifests (the mirrored clip roots — the
/// `dest` header row is that dest), the run report at EVERY dest
/// root (each carries the whole run — all N dests' status; the
/// detection block once), the per-dest stderr verdict (the existing
/// line formats — the per-dest blocks; every dest named), the rc
/// (rc=0 every dest clean; rc=1 ANY dirty dest).
pub fn run_offload_multi(input: &Path, dests: &[PathBuf]) -> Result<ExitCode> {
    if dests.is_empty() {
        bail!("the offload needs at least one dest (frameprism offload <in> <to> [<to> ...])");
    }
    // The pre-write refusals (the rc=2 band — named, ZERO partial
    // writes anywhere): the input exists + is a dir (checked once)…
    if !input.is_dir() {
        bail!(
            "the offload input {} is not a directory (the card tree — the offload mirrors it, it does not encode it)",
            input.display()
        );
    }
    // … the self-mirror guard, now against EVERY dest (the mirror
    // would copy every file onto itself — the named refusal); the
    // best-effort canonical forms (a missing dest or a symlink loop
    // falls into the writability-probe band, named there).
    let input_abs = std::fs::canonicalize(input)
        .with_context(|| format!("canonicalize the offload input {}", input.display()))?;
    let mut dest_forms: Vec<(PathBuf, Option<PathBuf>)> = Vec::with_capacity(dests.len());
    for dest in dests {
        let canonical = std::fs::canonicalize(dest).ok();
        if let Some(ref c) = canonical {
            if *c == input_abs {
                bail!(
                    "the offload input {} and dest {} are the same dir (the mirror would copy every file onto itself — name a distinct dest)",
                    input.display(),
                    dest.display()
                );
            }
        }
        dest_forms.push((dest.clone(), canonical));
    }
    // … the (input, dest) NESTING band:
    // the identity is the guard above; nesting in EITHER direction
    // is the named refusal (the dest inside the input = the mirror
    // writes INTO the source tree + re-runs multiply it; the input
    // inside the dest = the mirror writes into the dest root that
    // holds the source, overwriting pre-existing content). The
    // parent-walk canonical form: a MISSING dest resolves through
    // its existing ancestor — the band fires BEFORE the probe
    // creates it (the zero-residue refusal); the None class (the
    // symlink loop) falls into the writability-probe band, named
    // there.
    for dest in dests {
        let Some(dest_c) = canonicalize_path(dest) else {
            continue;
        };
        if is_path_prefix(&input_abs, &dest_c) {
            bail!(
                "the offload dest {} is inside the source {} (the mirror would write the mirrored tree into the source — name a dest outside the source)",
                dest.display(),
                input.display()
            );
        }
        if is_path_prefix(&dest_c, &input_abs) {
            bail!(
                "the offload source {} is inside the dest {} (the mirror would write into the dest root that holds the source — the mirrored paths may overwrite its pre-existing content; name a dest outside the source)",
                input.display(),
                dest.display()
            );
        }
    }
    // … the duplicate-dest refusal (`to_i` == `to_j`, i≠j — a user
    // error, named loudly: the fan-out refuses the duplicate, it does
    // not silently dedupe it; the canonicalized-path equality catches
    // the symlinked alias too).
    for i in 0..dest_forms.len() {
        for j in (i + 1)..dest_forms.len() {
            let same = match (&dest_forms[i].1, &dest_forms[j].1) {
                (Some(a), Some(b)) => a == b,
                (None, None) => dest_forms[i].0 == dest_forms[j].0,
                _ => false,
            };
            if same {
                bail!(
                    "the offload dests {} and {} are the same dir (a duplicate dest — name each dest once; the fan-out refuses the duplicate, it does not silently dedupe it)",
                    dests[i].display(),
                    dests[j].display()
                );
            }
        }
    }
    // … and the per-dest writability probe (the existing named
    // refusal — create + the write-probe; the N probes complete
    // before the first source read).
    for dest in dests {
        check_dest_writable(dest)?;
    }
    // The read-only pre-copy detection scan (ONCE — the detection is
    // source-side; a REPORT, not a gate; identity never refuses here
    // — the input-tree walk error is the refusal class).
    let detection = crate::camera::offload_detections(input).map_err(|e| {
        anyhow::anyhow!("the offload detection scan of {}: {e}", input.display())
    })?;
    // The clip key space (the detection's sorted keys — the ingest
    // key space; "" = the source root): the per-clip manifest slices
    // + the per-clip report numbers.
    let clip_keys: Vec<String> = detection
        .clips
        .iter()
        .map(|c| c.key.clone())
        .collect();
    // The read-once/write-N core (each source file's bytes are read
    // ONCE + its sha256 computed ONCE — the card read is the
    // bottleneck; every dest gets the write + the per-dest re-scan).
    // The phase wall clock (the job report's run duration — the
    // run total; the durations ride ONLY in the job report —
    // R-INV-A).
    let core_start = std::time::Instant::now();
    let outcome = offload_core_multi(input, dests, &clip_keys)
        .with_context(|| format!("the offload of {} to {} dest(s)", input.display(), dests.len()))?;
    let run_seconds = core_start.elapsed().as_secs_f64();
    // The per-dest per-clip manifests (the standalone placement: at
    // the mirrored clip root — the manifest rides BESIDE the
    // mirrored clip; the `dest` header row = that dest — the wire
    // contract: the path-independent reverify inherits them
    // unchanged). Written AFTER the copy (a source file that happens
    // to carry a manifest's name is mirrored first; the manifest
    // then stands as the clip's record).
    for (i, dest) in dests.iter().enumerate() {
        let report = &outcome.reports[i];
        for slice in &outcome.per_clip[i] {
            let (dir, name) =
                per_clip_manifest_placement(&input_abs, dest, &slice.key)?;
            let clip_report = OffloadReport {
                input: report.input.clone(),
                dest: report.dest.clone(),
                rows: slice.rows.clone(),
                clips: vec![ClipBlock {
                    clip: slice.key.clone(),
                    total: slice.total,
                    ok: slice.ok,
                }],
            };
            write_offload_manifest(&dir, &name, &clip_report)
                .with_context(|| {
                    format!(
                        "write the per-clip offload manifest for clip {}",
                        crate::worker::display_clip(&slice.key)
                    )
                })?;
        }
    }
    // The run report at EVERY dest root (each carries the WHOLE run
    // — all N dests' status: the detection block once + one per-dest
    // section per dest; exactly ONE `created:` line each). The run's
    // creation instant (the run report's `created` unix seconds) is
    // captured HERE and shared with the ascmhl history (one run
    // instant — the manifest's creationdate + the
    // file name's date/time + this `created:` line are the SAME
    // instant, UTC).
    let report_dests: Vec<PathBuf> = outcome.reports.iter().map(|r| r.dest.clone()).collect();
    let run_created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    write_offload_run_reports_at(
        &report_dests,
        &detection,
        &outcome.reports,
        &outcome.skipped,
        run_created,
    )?;
    // The job report at EVERY dest root (the
    // the structured job-report format, the documented 2024.2 baseline
    // (b): the session + summary blocks + the per-clip blocks, the
    // three file forms md/csv/html — the save-with-job placement,
    // automatic, no flag). The write position: AFTER the per-clip
    // manifests + the run report (the records stand first — the job
    // report is the RECORD, not the gate: the rc semantics are
    // unchanged; a write failure is the named hard-error band —
    // the manifests + the run report already stand). The per-file
    // durations ride ONLY here (R-INV-A). The job identifier (the
    // manual's Job Identifier: the run's identity + date/time stamp)
    // is the run's UTC timestamp — ONE stamp for every dest's
    // report.
    let job_created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let job_id = crate::jobreport::utc_timestamp(job_created);
    for (i, dest) in report_dests.iter().enumerate() {
        let data = crate::jobreport::build(
            &outcome.reports[i],
            &detection,
            &outcome.copied_ms[i],
            &outcome.skipped[i],
            job_created,
            &job_id,
            run_seconds,
        );
        crate::jobreport::write(dest, &data)
            .with_context(|| format!("write the job report at dest {}", dest.display()))?;
    }
    // The ascmhl history at EVERY dest root (the industry
    // provenance standard's media-hash-list record, the ASC MHL, the
    // `urn:ASC:MHL:v2.0` lineage): the `ascmhl/` dir + the
    // `NNNN_<dest-basename>_YYYY-MM-DD_HHMMSSZ.mhl` manifest (the
    // generation-1 `transfer`/`original` semantics) + the
    // `ascmhl_chain.xml` (the append-only re-run model — a re-run
    // onto a dest that already carries a history appends the new
    // generation, the old records preserved byte-for-byte). The
    // write position: LAST — after the copy + verify + the per-clip
    // manifests + the run report + the job report (the records stand
    // first — the provenance record comes after the verification
    // records; a write failure is the named hard-error band, the
    // records already stand). Automatic (no flag — like the
    // job report), silent on success (R-INV-A: the stderr surface
    // gains no line). The creation instant = the run's creation
    // instant (the run report's `created` line). The writing
    // side only (the MHL verify pass + the encode surface's `--to`
    // = the named follow-ups).
    for (i, dest) in report_dests.iter().enumerate() {
        crate::ascmhl::write_history(&outcome.reports[i].dest, run_created)
            .with_context(|| format!("write the ascmhl history at dest {}", dest.display()))?;
    }
    // The per-dest stderr verdict (the existing line formats — the
    // per-dest blocks: that dest's FAIL lines + its `OFFLOAD FAIL`
    // line, or its verdict line when the dest is clean — every dest
    // named), then the rc (any dirty dest = rc=1).
    for line in fanout_stderr_lines(&outcome.reports) {
        eprintln!("{line}");
    }
    if outcome.reports.iter().any(|r| r.dirty_count() > 0) {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}


/// The fan-out's stderr surface (the line-format contract — the
/// EXISTING formats only, composed per dest: that dest's FAIL lines
/// (the `fail_lines()` formats verbatim — the dest context comes
/// from the block's own named lines) + that dest's `OFFLOAD FAIL`
/// line (the existing format; the verify-before-wipe tail is the
/// all-N phrasing when N>1 — the N=1 wording byte-unchanged) or,
/// when the dest is clean, that dest's verdict line (the existing
/// format — the `(dest <dir>)` slot already names the dest).
pub(crate) fn fanout_stderr_lines(reports: &[OffloadReport]) -> Vec<String> {
    let n = reports.len();
    let mut lines: Vec<String> = Vec::new();
    for r in reports {
        if r.dirty_count() > 0 {
            lines.extend(r.fail_lines());
            let gate = if n == 1 {
                "the source tree is reusable only after the dest verifies clean"
            } else {
                &format!("the source tree is reusable only after all {n} dests verify clean")
            };
            lines.push(format!(
                "OFFLOAD FAIL — {} dirty row(s) (dest {}): the named FAIL lines above (the verify-before-wipe gate holds: {gate})",
                r.dirty_count(),
                r.dest.display()
            ));
        } else {
            lines.push(r.verdict_line());
        }
    }
    lines
}

// ---------------------------------------------------------------------------
// The multi-source concurrent offload (the `--source` form — multiple
// cards → ALL destinations in one job: N sources each fanned to ALL M
// dests, the per-source work CONCURRENT (one std::thread per source —
// the sources do not wait on each other; the card reads overlap — the
// bandwidth-maximizing class), the per-dest-root artifacts (run
// report + job report + ascmhl) in a SERIALIZED TAIL after all
// sources join. The legacy positional form (`run_offload_multi`
// above) is untouched — the byte-identical anchor).
// ---------------------------------------------------------------------------


/// One source's pipeline outcome for the artifact tail (the phase-1
/// return, collected in the given source order): the detection scan +
/// the per-dest core outcome when the source's thread completed; the
/// named error (the detection / core / per-clip-manifest band, or the
/// thread panic) when it failed — the tail renders the completed
/// pairs and the failed source's named `source failed:` block in the
/// place of its copy block (the deterministic refusal rendering, no
/// table). The completed sources' mirrors stand (the partial state is
/// named, not hidden — every (pair) status is named in the stderr).
/// (No derive: the contained scans/outcomes are owned, constructed
/// once by the phase-1 join and consumed by the phase-2 tail.)
pub struct SourceOutcome {
    /// The source AS GIVEN on the CLI (the run report's `input:`
    /// lines, the job report's session `input:` lines + the `source`
    /// column's value, the pair verdict lines' source slot — the
    /// given-order convention).
    pub source: PathBuf,
    /// The source's detection scan (the thread's scan — `None` when
    /// the scan itself failed: the run report's `### source:` section
    /// renders the named `source failed:` line instead of the
    /// detection lines).
    pub detection: Option<crate::camera::OffloadDetectionScan>,
    /// The per-dest core outcome (the given dest order — `None` when
    /// the core / the per-clip manifests failed).
    pub core: Option<OffloadCoreMulti>,
    /// The named error (`None` = the source's thread completed — the
    /// reports carry the pair statuses).
    pub failure: Option<String>,
}


/// The standalone MULTI-SOURCE offload (the `--source` form — N
/// sources, each fanned to ALL M dests in ONE job): the phase-0
/// serial pre-write refusals (per-source dir check; the self-mirror
/// guard PER PAIR; the duplicate-dest refusal — named, never
/// silently deduped; the nested-source refusal; the cross-source
/// top-level name collision; the shared source-basename refusal; the
/// per-dest writability probe — ALL complete before the first write:
/// ZERO partial writes anywhere) + the job-level `created` capture
/// (ONE instant for the whole job — the run report header, the job
/// report's session, and the ascmhl all use it; the single-
/// `created:` rule); stage 1 CONCURRENT: one std::thread per source
/// (the given order) running the existing single-source N-dest
/// pipeline (the detection scan → the read-once/write-M core → the
/// per-clip manifests — the per-source writes are DISJOINT paths: the
/// mirrored entry names are collision-free across sources by the
/// cross-source collision refusal + the source-root manifest names
/// are disjoint by the shared-basename refusal; the dest ROOT dirs
/// were created serially in stage 0 — no shared-dir creation race; NO
/// shared mutable state between threads); stage 2 SERIALIZED TAIL
/// (the dests in the given order, after ALL threads join): per dest
/// the run report (the multi-shape rendering — each file carries the
/// WHOLE job) → the job report (the multi-shape — the `source`
/// column) → the ascmhl (the existing call — the dest tree is FINAL,
/// the merged mirror; ONE generation per dest per JOB — a run = the
/// whole job; silent on success). The stderr: the per-pair lines in
/// the given order (the sources outer, the dests inner) + the named
/// source-thread failures + the job-level line (the totals across
/// pairs). The rc: 0 = every pair clean; 1 = ANY pair dirty (all
/// pairs named — the sweep) or a source-thread failure; 2 = the
/// phase-0 refusals (the bail! band — the `run` wrapper maps Err →
/// 2).
pub fn run_offload_multi_sources(
    sources: &[PathBuf],
    dests: &[PathBuf],
) -> Result<ExitCode> {
    if dests.is_empty() {
        bail!("the offload needs at least one dest (frameprism offload <in> <to> [<to> ...])");
    }
    // The job's phase wall clock (the multi job report's summary
    // duration: the WHOLE-JOB window — the phase-0 start → the
    // tail's write for this dest).
    let job_start = std::time::Instant::now();
 // Stage 0 — the serial pre-write refusals (the rc=2 band —
    // named, ZERO partial writes anywhere; ALL complete before the
    // first write and before the dest probes).
    // (c) Each source: exists + is a dir (the input band, per source).
    for source in sources {
        if !source.is_dir() {
            bail!(
                "the offload input {} is not a directory (the card tree — the offload mirrors it, it does not encode it)",
                source.display()
            );
        }
    }
    // The canonical forms (the per-pair self-mirror guard, the
    // nested-source + shared-basename checks, and the source-root
    // manifests' placement all read them).
    let mut source_abs: Vec<PathBuf> = Vec::with_capacity(sources.len());
    for source in sources {
        source_abs.push(
            std::fs::canonicalize(source)
                .with_context(|| format!("canonicalize the offload source {}", source.display()))?,
        );
    }
    // The dest canonical forms (the best-effort band — a missing
    // dest or a symlink loop falls into the writability-probe band,
    // named there).
    let dest_forms: Vec<(PathBuf, Option<PathBuf>)> = dests
        .iter()
        .map(|dest| {
            let canonical = std::fs::canonicalize(dest).ok();
            (dest.clone(), canonical)
        })
        .collect();
    // (b) The self-mirror guard, now PER PAIR (for every (source,
    // dest) pair — the existing wording names the pair: it carries
    // the source + the dest verbatim).
    for (source, source_c) in sources.iter().zip(source_abs.iter()) {
        for (dest, dest_c) in &dest_forms {
            if let Some(ref c) = dest_c {
                if *c == *source_c {
                    bail!(
                        "the offload input {} and dest {} are the same dir (the mirror would copy every file onto itself — name a distinct dest)",
                        source.display(),
                        dest.display()
                    );
                }
            }
        }
    }
    // (a) The duplicate-dest refusal (`to_i` == `to_j`, i≠j — the
    // existing refusal, unchanged wording; the canonicalized-path
    // equality catches the symlinked alias too).
    for i in 0..dest_forms.len() {
        for j in (i + 1)..dest_forms.len() {
            let same = match (&dest_forms[i].1, &dest_forms[j].1) {
                (Some(a), Some(b)) => a == b,
                (None, None) => dest_forms[i].0 == dest_forms[j].0,
                _ => false,
            };
            if same {
                bail!(
                    "the offload dests {} and {} are the same dir (a duplicate dest — name each dest once; the fan-out refuses the duplicate, it does not silently dedupe it)",
                    dests[i].display(),
                    dests[j].display()
                );
            }
        }
    }
    // (d) The nested-source refusal: any source's canonical path is
    // a (proper, component-wise) prefix of another's → the mirror
    // semantics are undefined (one source would ride the other's
    // subtree).
    for i in 0..source_abs.len() {
        for j in (i + 1)..source_abs.len() {
            if is_path_prefix(&source_abs[i], &source_abs[j])
                || is_path_prefix(&source_abs[j], &source_abs[i])
            {
                bail!(
                    "the offload sources {} and {} are nested (one is inside the other) — the mirror semantics are undefined; name the sources at the same level",
                    sources[i].display(),
                    sources[j].display()
                );
            }
        }
    }
    // (g) The per-pair (source, dest) NESTING band (
    // the multi-source form): identity is the existing (b)
    // guard; nesting in EITHER direction is the named refusal —
    // the mirror would write into the source tree / into the dest
    // root that holds the source (the pre-existing content at the
    // mirrored paths is overwritten via the mismatch path). Every
    // (source, dest) pair — the same parent-walk canonical form as
    // (d)'s single-source sibling: a MISSING dest resolves through
    // its existing ancestor (the band fires before the probe
    // creates it), the None class falls into the writability-probe
    // band.
    for (source, source_c) in sources.iter().zip(source_abs.iter()) {
        for dest in dests {
            let Some(dest_c) = canonicalize_path(dest) else {
                continue;
            };
            if is_path_prefix(source_c, &dest_c) {
                bail!(
                    "the offload dest {} is inside the source {} (the mirror would write the mirrored tree into the source — name a dest outside the source)",
                    dest.display(),
                    source.display()
                );
            }
            if is_path_prefix(&dest_c, source_c) {
                bail!(
                    "the offload source {} is inside the dest {} (the mirror would write into the dest root that holds the source — the mirrored paths may overwrite its pre-existing content; name a dest outside the source)",
                    source.display(),
                    dest.display()
                );
            }
        }
    }
    // (e) The cross-source top-level name collision: a DEPTH-1 read
    // of each source (the top-level entry names — files AND dirs;
    // read-only, before the core's full walk). Any entry name common
    // to two different sources = a named refusal (the dest tree
    // would merge two sources' entries under one name — the mirror
    // is per-name). The check is WITHIN the job only: an existing
    // dest entry from a PREVIOUS run is NOT a collision (the mirror
    // is idempotent — re-run semantics stand). Deterministic: the
    // first (i, j) pair in the given order, the first common name in
    // sorted order. NAMED RESIDUAL (shared with (f)): case-differing
    // names stay outside the exact-match check.
    let depth1: Vec<std::collections::BTreeSet<String>> =
        sources.iter().map(|s| top_level_names(s)).collect::<Result<_>>()?;
    for i in 0..depth1.len() {
        for j in (i + 1)..depth1.len() {
            let common = depth1[i].iter().find(|name| depth1[j].contains(*name));
            if let Some(name) = common {
                bail!(
                    "the clip dir/file {} is present in both offload sources {} and {} — the offload refuses to merge two sources' entries under one dest (rename the clip dirs on one card)",
                    name,
                    sources[i].display(),
                    sources[j].display()
                );
            }
        }
    }
    // (f) The shared source-basename refusal: the source-root
    // manifest name = the source's basename + the manifest suffix —
    // two sources with the exact-equal CANONICALIZED basenames (e.g.
    // /a/card + /b/card — distinct paths, distinct top-level
    // entries; (d)/(e) both pass) would race the same tmp + rename
 // at EVERY dest root in stage 1. The basenames come from the
    // same canonical paths (d) uses. NAMED RESIDUAL (shared with
    // (e)): case-differing basenames on case-insensitive dest
    // filesystems stay outside the exact-match check.
    for i in 0..source_abs.len() {
        for j in (i + 1)..source_abs.len() {
            match (source_abs[i].file_name(), source_abs[j].file_name()) {
                (Some(a), Some(b)) if a == b => bail!(
                    "the offload sources {} and {} share the source-root manifest name {} (both sources' basenames are {}) — the source-root offload manifests would collide at the dest roots; name the source dirs distinctly",
                    sources[i].display(),
                    sources[j].display(),
                    b.to_string_lossy(),
                    b.to_string_lossy()
                ),
                _ => {}
            }
        }
    }
    // (a) The per-dest writability probe (the existing named refusal
    // — create + the write-probe; the M probes complete before the
    // first source read: ZERO partial writes).
    for dest in dests {
        check_dest_writable(dest)?;
    }
    // The job-level `created` capture (ONE instant for the whole job
    // — the run report header, the job report's session, and the
    // ascmhl all use it; the single-`created:` rule).
    let job_created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
 // Stage 1 — CONCURRENT: one std::thread per source (the given
    // order). Each thread runs its source's pipeline: the detection
    // scan (per source) → the read-once/write-M core → the per-clip
    // manifests (per (source, dest, clip) — the existing
    // writers/placement; the `dest:` header row = that dest, the
    // `input:` header row = this source). NO shared mutable state
    // between threads (the scoped borrows are shared IMMUTABLE; each
    // thread's data is its own; the join collects — the concurrency
    // proof is structural: the threads are spawned before any dest
    // write). A thread Err (the core/manifest band) or a JoinError
    // (the panic) = the named source failure — the COMPLETED
    // sources' mirrors stand (the partial state is named, not
    // hidden).
    let mut outcomes: Vec<SourceOutcome> = Vec::with_capacity(sources.len());
    std::thread::scope(|s| {
        let handles: Vec<std::thread::ScopedJoinHandle<Result<(crate::camera::OffloadDetectionScan, OffloadCoreMulti)>>> =
            sources
                .iter()
                .enumerate()
                .map(|(i, source)| {
                    let source_c = source_abs[i].clone();
                    s.spawn(move || {
                        // The read-only pre-copy detection scan
                        // (per source; a REPORT, not a gate —
                        // identity never refuses here — the
                        // input-tree walk error is the refusal
                        // class).
                        let detection =
                            crate::camera::offload_detections(source).map_err(|e| {
                                anyhow::anyhow!(
                                    "the offload detection scan of {}: {e}",
                                    source.display()
                                )
                            })?;
                        // The clip key space (the detection's
                        // sorted keys — the ingest key space; "" =
                        // the source root).
                        let clip_keys: Vec<String> = detection
                            .clips
                            .iter()
                            .map(|c| c.key.clone())
                            .collect();
                        // The read-once/write-M core (each source
                        // file's bytes are read ONCE + its sha256
                        // computed ONCE — the card read is the
                        // bottleneck; every dest gets the write +
                        // the per-dest re-scan).
                        let core = offload_core_multi(source, dests, &clip_keys)
                            .with_context(|| {
                                format!(
                                    "the offload of {} to {} dest(s)",
                                    source.display(),
                                    dests.len()
                                )
                            })?;
                        // The per-(source, dest, clip) manifests
                        // (the standalone placement: at the
                        // mirrored clip root — the manifest rides
                        // BESIDE the mirrored clip; the source-root
                        // key ("") rides the source's own name at
                        // the dest root). The per-source writes are
                        // DISJOINT paths (the mirrored entry names
                        // are collision-free across sources by (e) +
                        // the source-root manifest names are
                        // disjoint by (f); the dest ROOT dirs were
 // created serially in stage 0 — no
                        // shared-dir creation race).
                        for (j, dest) in dests.iter().enumerate() {
                            let report = &core.reports[j];
                            for slice in &core.per_clip[j] {
                                let (dir, name) =
                                    per_clip_manifest_placement(&source_c, dest, &slice.key)?;
                                let clip_report = OffloadReport {
                                    input: source.clone(),
                                    dest: report.dest.clone(),
                                    rows: slice.rows.clone(),
                                    clips: vec![ClipBlock {
                                        clip: slice.key.clone(),
                                        total: slice.total,
                                        ok: slice.ok,
                                    }],
                                };
                                write_offload_manifest(&dir, &name, &clip_report)
                                    .with_context(|| {
                                        format!(
                                            "write the per-clip offload manifest for clip {}",
                                            crate::worker::display_clip(&slice.key)
                                        )
                                    })?;
                            }
                        }
                        Ok((detection, core))
                    })
                })
                .collect();
        for (i, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(Ok((detection, core))) => outcomes.push(SourceOutcome {
                    source: sources[i].clone(),
                    detection: Some(detection),
                    core: Some(core),
                    failure: None,
                }),
                Ok(Err(err)) => outcomes.push(SourceOutcome {
                    source: sources[i].clone(),
                    detection: None,
                    core: None,
                    failure: Some(format!("{err:#}")),
                }),
                Err(_) => outcomes.push(SourceOutcome {
                    source: sources[i].clone(),
                    detection: None,
                    core: None,
                    failure: Some(
                        "the offload source's thread panicked (the named thread-panic band — the core/manifest errors are the named Errs, not panics)"
                            .to_string(),
                    ),
                }),
            }
        }
    });
 // Stage 2 — the SERIALIZED TAIL (the dests in the given order,
    // after ALL threads join — the dest tree is FINAL, the merged
    // mirror). Per dest: the run report (the multi-shape rendering —
    // each file carries the WHOLE job — the same content at every
    // dest root) → the job report (the multi-shape — the `source`
    // column, the per-pair verdict lines) → the ascmhl (the
    // existing call — ONE generation per dest per JOB — a run = the
    // whole job; silent on success). A tail artifact write failure
    // = the named Err, the records that wrote stand.
    // The canonical dests (the given order — the core's canonical
    // forms; a dest whose sources all failed before the core is
    // canonicalized directly — the phase-0 probe created it).
    let mut dest_canon: Vec<PathBuf> = Vec::with_capacity(dests.len());
    for (j, dest) in dests.iter().enumerate() {
        let canon = outcomes
            .iter()
            .find_map(|o| o.core.as_ref().map(|core| core.reports[j].dest.clone()));
        let canon = match canon {
            Some(c) => c,
            None => std::fs::canonicalize(dest)
                .with_context(|| format!("canonicalize the offload dest dir {}", dest.display()))?,
        };
        dest_canon.push(canon);
    }
    // The run report's content (the whole job — the multi-shape;
    // exactly ONE `created:` line — the job's single creation
    // instant; the same file at every dest root).
    let run_md = render_offload_run_report_multi(&outcomes, &dest_canon, job_created);
    // The job identifier (the manual's Job Identifier: the run's
    // identity + date/time stamp) — the job's SINGLE UTC timestamp
    // (ONE job — the single-identifier rule: the same `job:`
    // line at every dest's report).
    let job_id = crate::jobreport::utc_timestamp(job_created);
    for (j, dest) in dest_canon.iter().enumerate() {
        // 1. The run report (the whole job — the multi-shape).
        let path = dest.join(crate::report::RUN_REPORT_NAME);
        std::fs::write(&path, &run_md)
            .with_context(|| format!("write the offload run report {}", path.display()))?;
        // The durability seam: the run report's bytes are
        // filesystem-synchronized (a sync failure = the named
        // hard-error band) + the best-effort dir sync of the dest
        // root.
        crate::durability::sync_file(&path, "offload run report")?;
        crate::durability::sync_dir_best_effort(dest);
        // 2. The job report (this dest — the multi-shape). The
        // session's `created:` + the `job:` identifier = the job's
        // single creation instant (one created instant for the
        // whole job); the summary's `duration:` = the WHOLE-JOB
        // window (the phase-0 start → the tail's write for this
        // dest).
        let run_seconds = job_start.elapsed().as_secs_f64();
        let data = crate::jobreport::build_multi(
            &outcomes,
            j,
            &dest.display().to_string(),
            job_created,
            &job_id,
            run_seconds,
        );
        crate::jobreport::write_multi(dest, &data)
            .with_context(|| format!("write the job report at dest {}", dest.display()))?;
        // 3. The ascmhl history (the dest tree is FINAL — the merged
        // mirror; the model unchanged: ONE generation per
        // dest per JOB — a run = the whole job; the creation
        // instant = the job's creation instant — the run report's
        // `created:` line; silent on success — the stderr surface
        // gains no line; a write failure = the named hard-error
        // band, the records already stand).
        crate::ascmhl::write_history(dest, job_created)
            .with_context(|| format!("write the ascmhl history at dest {}", dest.display()))?;
    }
    // The multi-shape stderr (the given order — the sources outer,
    // the dests inner) — the pure composition (the existing line
    // formats + the pair slots + the source-thread failures + the
    // job-level line), eprinted in order (the
    // rendering is pure, the test asserts the exact composition).
    for line in multi_stderr_lines(&outcomes, &dest_canon, dests.len()) {
        eprintln!("{line}");
    }
    // The rc: 0 = every pair clean (no thread failures); 1 = ANY
    // pair dirty (all pairs named — the sweep) or a source-thread
    // failure; 2 = the phase-0 refusals (the bail! band — the `run`
    // wrapper maps Err → 2).
    let any_failed = outcomes.iter().any(|o| o.failure.is_some());
    let total_dirty: usize = outcomes
        .iter()
        .filter(|o| o.failure.is_none())
        .map(|o| {
            o.core
                .as_ref()
                .map(|c| c.reports.iter().map(|r| r.dirty_count()).sum::<usize>())
                .unwrap_or(0)
        })
        .sum();
    if any_failed || total_dirty > 0 {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}


/// The multi-shape stderr's pure composition (the given order — the
/// sources outer, the dests inner): the completed pairs' per-pair
/// lines (the clean pair's pair line — the multi-form; the dirty
/// pair's fail lines — the existing formats — + the pair's `OFFLOAD
/// FAIL` line — the existing template + the source slot), the failed
/// sources' named lines (at their given-order position — the sweep:
/// every (pair) status is named), then the job-level line (the totals
/// across the completed pairs — the uniform multi-shape, M=1
/// included — the single-source flag form rides the same rendering;
/// the `ONLY when M>1` clause is overridden by the
/// explicit `1 source(s) × N dest(s)` assertion — the uniformity
/// decision).
fn multi_stderr_lines(
    outcomes: &[SourceOutcome],
    dest_canon: &[PathBuf],
    dests: usize,
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut total_ok = 0u64;
    let mut total_files = 0u64;
    let mut total_dirty = 0usize;
    for o in outcomes {
        if let Some(err) = &o.failure {
            lines.push(format!(
                "OFFLOAD FAIL — source {}: {}",
                o.source.display(),
                err
            ));
            continue;
        }
        let core = o.core.as_ref().expect("the completed source carries its core outcome");
        for (j, dest) in dest_canon.iter().enumerate() {
            let report = &core.reports[j];
            total_files += report.rows.len() as u64;
            if report.dirty_count() > 0 {
                total_dirty += report.dirty_count();
                for line in report.fail_lines() {
                    lines.push(line.clone());
                }
                lines.push(format!(
                    "OFFLOAD FAIL — {} dirty row(s) (source {}, dest {}): the named FAIL lines above (the verify-before-wipe gate holds: the source tree is reusable only after all {} dests verify clean)",
                    report.dirty_count(),
                    o.source.display(),
                    dest.display(),
                    dests
                ));
            } else {
                total_ok += report.rows.len() as u64;
                lines.push(report.pair_verdict_line());
            }
        }
    }
    if total_dirty == 0 {
        lines.push(format!(
            "offload: VERIFIED {total_ok}/{total_files} ({} source(s) × {} dest(s))",
            outcomes.len(),
            dests
        ));
    } else {
        lines.push(format!(
            "offload: REFUSE {total_dirty} named row(s) ({} source(s) × {} dest(s))",
            outcomes.len(),
            dests
        ));
    }
    lines
}


/// The pair copy block (the multi-shape's per-(source, dest)
/// rendering): the existing copy-block content for the pair — the
/// per-clip table (the source's detection's clip order — the
/// existing per-clip formats), the totals line, the `## skipped`
/// section (the pinned format — the multi-shape's composed
/// surface: the section rides the pair block exactly as the legacy
/// shape carries it — the same format + the same pinned placement:
/// PRESENT ONLY WHEN ≥1 row of that pair was skipped, after the
/// copy block's `totals:` line, before the `## failures` section,
/// before the pair verdict line), the `## failures` section (when
/// that pair is dirty — the existing FAIL-line formats) — under the
/// multi header `## copy — source: <in>` and closed by the PAIR
/// verdict line (the multi-form — the source + dest slots). The
/// legacy `render_copy_block` (the `## copy` header + the dest-slot
/// verdict line) is byte-frozen for the legacy shape.
fn render_copy_block_pair(
    report: &OffloadReport,
    detection: &crate::camera::OffloadDetectionScan,
    source: &Path,
    skipped: &[bool],
) -> String {
    let mut md = String::new();
    md.push_str(&format!("## copy — source: {}\n\n", source.display()));
    md.push_str("clip\tfiles\tsource B\n");
    let mut tot_files = 0u64;
    let mut tot_bytes = 0u64;
    for c in &detection.clips {
        let rows: Vec<&OffloadRow> = report
            .rows
            .iter()
            .filter(|r| clip_key_of_rel(&r.file) == c.key)
            .collect();
        let bytes: u64 = rows.iter().map(|r| r.size).sum();
        tot_files += rows.len() as u64;
        tot_bytes += bytes;
        md.push_str(&format!(
            "{}\t{}\t{}\n",
            crate::worker::display_clip(&c.key),
            rows.len(),
            bytes
        ));
    }
    md.push_str(&format!("totals: {tot_files} file(s) — {tot_bytes} B\n"));
    // The `## skipped` section (the pinned format — the
    // composed multi-surface: PRESENT ONLY WHEN ≥1 row of this pair
    // was skipped; one line per clip WITH ≥1 skip, the detection
    // clip order + the totals line — the same rendering as the
    // legacy shape's section).
    let skip_total: u64 = skipped.iter().filter(|s| **s).count() as u64;
    if skip_total > 0 {
        md.push_str("\n## skipped\n\n");
        md.push_str("clip\tfiles\tskipped\n");
        for c in &detection.clips {
            let (files, skips) = report
                .rows
                .iter()
                .enumerate()
                .filter(|(_, r)| clip_key_of_rel(&r.file) == c.key)
                .fold((0u64, 0u64), |(f, s), (j, _)| (f + 1, s + u64::from(skipped[j])));
            if skips > 0 {
                md.push_str(&format!(
                    "{}\t{}\t{}\n",
                    crate::worker::display_clip(&c.key),
                    files,
                    skips
                ));
            }
        }
        md.push_str(&format!(
            "totals: {skip_total} file(s) skipped (already present, sha256-verified — not re-copied)\n"
        ));
    }
    if report.dirty_count() > 0 {
        md.push_str("\n## failures\n\n");
        for line in report.fail_lines() {
            md.push_str(&format!("{line}\n"));
        }
    }
    md.push_str(&format!("\n{}\n", report.pair_verdict_line()));
    md
}


/// The multi-shape run report's rendering (the `--source` form — the
/// `.frameprism-run-report.md` pattern, ONE at EVERY dest root — each
/// file carries the WHOLE job: the same content at every dest root):
/// the `<M> source(s)` title (M=1 renders `1 source(s)` — the
/// uniform rendering, no singular special case), exactly ONE
/// `created:` line (the job's single creation
/// instant), the tool + host lines, ONE `input:` line PER SOURCE
/// (the given order — the sources as given), the `dest:` line when
/// N=1 (the canonical dest), the `clips:` total across
/// the sources · the `files:` total at the dest, one `### source:`
/// section per source (that source's detection lines — the existing
/// per-clip formats verbatim — or the named `source failed:` line
/// when the source's scan is absent), then (N>1 ONLY)
/// one `### destination:` section per dest carrying the per-source
/// `## copy — source:` blocks (the existing copy-block content for
/// the (source, dest) pair + the PAIR verdict line; a failed
/// source's block = the pinned `## copy — source: <in>` + `source
/// failed: <err> (no copy)` — the deterministic refusal rendering,
/// no table). N=1: no `### destination:` section — the copy blocks
/// follow the source sections directly.
fn render_offload_run_report_multi(
    outcomes: &[SourceOutcome],
    dests_canon: &[PathBuf],
    created: u64,
) -> String {
    let m = outcomes.len();
    let n = dests_canon.len();
    let host = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    let mut md = String::new();
    md.push_str(&format!("# frameprism offload run report — {m} source(s)\n\n"));
    md.push_str(&format!("created: {created} (unix seconds, UTC)\n"));
    md.push_str(&format!("tool: frameprism {}\n", env!("CARGO_PKG_VERSION")));
    md.push_str(&format!("host: {host}\n"));
    for o in outcomes {
        md.push_str(&format!("input: {}\n", o.source.display()));
    }
    if n == 1 {
        md.push_str(&format!("dest: {}\n", dests_canon[0].display()));
    }
    // clips: the total clips across the sources (the available
    // scans) · files: the total rows at the dest (the completed
    // cores' rows — the mirror's file set is dest-independent; a
    // failed source contributes 0).
    let total_clips: usize = outcomes
        .iter()
        .map(|o| o.detection.as_ref().map(|d| d.clips.len()).unwrap_or(0))
        .sum();
    let total_files: u64 = outcomes
        .iter()
        .map(|o| o.core.as_ref().map(|c| c.reports[0].rows.len() as u64).unwrap_or(0))
        .sum();
    md.push_str(&format!("clips: {total_clips} · files: {total_files}\n\n"));
    // The `### source:` sections (the given order).
    for o in outcomes {
        md.push_str(&format!("### source: {}\n\n", o.source.display()));
        match &o.detection {
            Some(d) => {
                for c in &d.clips {
                    md.push_str(&format!(
                        "{}: {}\n",
                        crate::worker::display_clip(&c.key),
                        c.class.line()
                    ));
                }
                md.push('\n');
            }
            None => md.push_str(&format!(
                "source failed: {} (no copy)\n\n",
                o.failure.as_deref().unwrap_or("-")
            )),
        }
    }
    // The per-dest sections (N>1) or the direct copy
    // blocks (N=1).
    for (j, dest) in dests_canon.iter().enumerate() {
        if n > 1 {
            md.push_str(&format!("### destination: {}\n\n", dest.display()));
        }
        for (i, o) in outcomes.iter().enumerate() {
            match &o.core {
                Some(core) => {
                    let detection = o
                        .detection
                        .as_ref()
                        .expect("the completed source carries its detection scan");
                    md.push_str(&render_copy_block_pair(
                        &core.reports[j],
                        detection,
                        &o.source,
                        &core.skipped[j],
                    ));
                }
                None => md.push_str(&format!(
                    "## copy — source: {}\n\nsource failed: {} (no copy)\n",
                    o.source.display(),
                    o.failure.as_deref().unwrap_or("-")
                )),
            }
            if i + 1 < outcomes.len() {
                md.push('\n');
            }
        }
        if j + 1 < n {
            md.push('\n');
        }
    }
    md
}


/// The standalone per-clip manifest's placement (the mirrored clip
/// root — the manifest rides BESIDE the mirrored clip — the
/// `--to` encode placement's consistency: the encode writes its
/// single whole-tree manifest at the run's output root named by the
/// source clip's name; this writes the clip's manifest at the
/// clip's mirrored root named by the clip's leaf dir name). The
/// source-root key ("") rides the input's own name at the dest
/// root.
fn per_clip_manifest_placement(
    input_abs: &Path,
    dest: &Path,
    key: &str,
) -> Result<(PathBuf, String)> {
    if key.is_empty() {
        let name = crate::checksums::clip_name(input_abs)?;
        Ok((dest.to_path_buf(), name))
    } else {
        let leaf = key.rsplit('/').next().unwrap_or(key);
        Ok((dest.join(key), leaf.to_string()))
    }
}


/// The per-clip copy rendering (the `## copy` section: the per-clip
/// table + the totals — the deterministic numbers, the optional
/// `## skipped` section (the duplicate detection's record:
/// PRESENT ONLY WHEN ≥1 row was skipped — the zero-skip run renders
/// byte-identically to the shape without the `## skipped` section; one line per clip WITH
/// ≥1 skip, the detection clip order + the totals line; the
/// placement: after the copy block's `totals:` line, before the
/// `## failures` section (when present), before the verdict line),
/// the optional `## failures` section — the existing FAIL-line
/// formats, present only when dirty, the verdict line — the existing
/// format `OffloadReport::verdict_line`). Shared by the 1-dest and
/// the N>1 run-report shapes.
fn render_copy_block(
    report: &OffloadReport,
    detection: &crate::camera::OffloadDetectionScan,
    skipped: &[bool],
) -> String {
    let mut md = String::new();
    md.push_str("## copy\n\n");
    md.push_str("clip\tfiles\tsource B\n");
    let mut tot_files = 0u64;
    let mut tot_bytes = 0u64;
    for c in &detection.clips {
        let rows: Vec<&OffloadRow> = report
            .rows
            .iter()
            .filter(|r| clip_key_of_rel(&r.file) == c.key)
            .collect();
        let bytes: u64 = rows.iter().map(|r| r.size).sum();
        tot_files += rows.len() as u64;
        tot_bytes += bytes;
        md.push_str(&format!(
            "{}\t{}\t{}\n",
            crate::worker::display_clip(&c.key),
            rows.len(),
            bytes
        ));
    }
    md.push_str(&format!("totals: {tot_files} file(s) — {tot_bytes} B\n"));
    // The `## skipped` section (the duplicate detection's
    // record, the pinned rendering): PRESENT ONLY WHEN ≥1 row
    // was skipped (the zero-skip run is byte-identical to the
    // shape without the section). One line per clip WITH ≥1 skip
    // (the detection clip order — a clip with zero skips gets NO
    // row) + the totals line.
    let skip_total: u64 = skipped.iter().filter(|s| **s).count() as u64;
    if skip_total > 0 {
        md.push_str("\n## skipped\n\n");
        md.push_str("clip\tfiles\tskipped\n");
        for c in &detection.clips {
            let (files, skips) = report
                .rows
                .iter()
                .enumerate()
                .filter(|(_, r)| clip_key_of_rel(&r.file) == c.key)
                .fold((0u64, 0u64), |(f, s), (j, _)| (f + 1, s + u64::from(skipped[j])));
            if skips > 0 {
                md.push_str(&format!(
                    "{}\t{}\t{}\n",
                    crate::worker::display_clip(&c.key),
                    files,
                    skips
                ));
            }
        }
        md.push_str(&format!(
            "totals: {skip_total} file(s) skipped (already present, sha256-verified — not re-copied)\n"
        ));
    }
    if report.dirty_count() > 0 {
        md.push_str("\n## failures\n\n");
        for line in report.fail_lines() {
            md.push_str(&format!("{line}\n"));
        }
    }
    md.push_str(&format!("\n{}\n", report.verdict_line()));
    md
}


/// The standalone offload's run report (the
/// `.frameprism-run-report.md` pattern — ONE at the dest root,
/// exactly ONE `created:` line, the report conventions): the
/// per-clip detection lines (the deterministic named classes), the
/// copy summary (files/bytes per clip — the deterministic numbers),
/// the `## skipped` section (present only when ≥1 row was
/// skipped), the FAIL lines (the existing formats — the `## failures`
/// section, present only when dirty), the verdict line (the
/// existing format — `OffloadReport::verdict_line`).
pub fn write_offload_run_report(
    dest: &Path,
    detection: &crate::camera::OffloadDetectionScan,
    report: &OffloadReport,
    skipped: &[bool],
) -> Result<PathBuf> {
    let d = dest.to_path_buf();
    let one = vec![skipped.to_vec()];
    write_offload_run_reports(
        std::slice::from_ref(&d),
        detection,
        std::slice::from_ref(report),
        &one,
    )
    .map(|paths| paths.into_iter().next().expect("the 1-dest run report"))
}


/// The run report's rendering with the caller's creation instant
/// (the wall-clock capture moved out — `run_offload_multi` shares
/// the instant with the ascmhl history (one run
/// instant — the run report's `created` line + the ascmhl
/// manifest's creationdate + the file name's stamp are the SAME
/// instant, UTC); the rendering is byte-identical for the same
/// instant — the deterministic contract is untouched).
fn write_offload_run_reports_at(
    dests: &[PathBuf],
    detection: &crate::camera::OffloadDetectionScan,
    reports: &[OffloadReport],
    skipped: &[Vec<bool>],
    created: u64,
) -> Result<Vec<PathBuf>> {
    if dests.len() != reports.len() {
        bail!(
            "the offload run report's dest count ({}) and report count ({}) differ (one report per dest)",
            dests.len(),
            reports.len()
        );
    }
    if skipped.len() != reports.len() {
        bail!(
            "the offload run report's dest count ({}) and skip-vector count ({}) differ (one skip vector per dest)",
            reports.len(),
            skipped.len()
        );
    }
    let host = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    let report0 = &reports[0];
    let in_name = report0
        .input
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| report0.input.display().to_string());
    let mut md = String::new();
    md.push_str(&format!("# frameprism offload run report — {in_name}\n\n"));
    md.push_str(&format!("created: {created} (unix seconds, UTC)\n"));
    md.push_str(&format!("tool: frameprism {}\n", env!("CARGO_PKG_VERSION")));
    md.push_str(&format!("host: {host}\n"));
    md.push_str(&format!("input: {}\n", report0.input.display()));
    if reports.len() == 1 {
        md.push_str(&format!("dest: {}\n", report0.dest.display()));
    }
    md.push_str(&format!("{}\n", detection.profiles_line));
    md.push_str(&format!(
        "clips: {} · files: {}\n\n",
        detection.clips.len(),
        report0.rows.len()
    ));
    md.push_str("## detection\n\n");
    for c in &detection.clips {
        md.push_str(&format!(
            "{}: {}\n",
            crate::worker::display_clip(&c.key),
            c.class.line()
        ));
    }
    md.push('\n');
    for (i, report) in reports.iter().enumerate() {
        if reports.len() > 1 {
            md.push_str(&format!("### destination: {}\n\n", report.dest.display()));
        }
        md.push_str(&render_copy_block(report, detection, &skipped[i]));
        if i + 1 < reports.len() {
            md.push('\n');
        }
    }
    let mut paths = Vec::with_capacity(dests.len());
    for dest in dests {
        let path = dest.join(crate::report::RUN_REPORT_NAME);
        std::fs::write(&path, &md)
            .with_context(|| format!("write the offload run report {}", path.display()))?;
        // The durability seam: the run report's bytes are
        // filesystem-synchronized (a sync failure = the named
        // hard-error band) + the best-effort dir sync of the dest
        // root.
        crate::durability::sync_file(&path, "offload run report")?;
        crate::durability::sync_dir_best_effort(dest);
        paths.push(path);
    }
    Ok(paths)
}


/// The fan-out's run report (ONE at EVERY dest root — each file
/// carries the WHOLE run: all N dests' status). N=1: byte-identical
/// to the pre-fan-out rendering (the header's single `dest:` line,
/// the detection block, the per-clip rendering, the verdict line —
/// no per-dest section). N>1: the header WITHOUT the single `dest:`
/// line (the section headers name every dest), the detection block
/// ONCE (the detection is source-side, run once), then one per-dest
/// section per dest — the named header line `### destination:
/// <dest>` + that dest's per-clip blocks (the existing per-clip
/// rendering) + that dest's verdict line (verbatim). Exactly ONE
/// `created:` line per file.
pub fn write_offload_run_reports(
    dests: &[PathBuf],
    detection: &crate::camera::OffloadDetectionScan,
    reports: &[OffloadReport],
    skipped: &[Vec<bool>],
) -> Result<Vec<PathBuf>> {
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    write_offload_run_reports_at(dests, detection, reports, skipped, created)
}
#[cfg(test)]
mod tests {
    use super::*;

    use super::super::manifests::MANIFEST_MAGIC;
    use super::super::{Args, run, settle_form};

    use crate::offload::testutil::*;
    #[test]
    fn verdict_line_refuse_format() {
        let report = OffloadReport {
            input: PathBuf::from("/in"),
            dest: PathBuf::from("/dest"),
            rows: vec![
                OffloadRow {
                    file: "a.DNG".into(),
                    size: 1,
                    source_sha: "s".into(),
                    dest_sha: "d".into(),
                    verdict: Verdict::Ok,
                    detail: String::new(),
                },
                OffloadRow {
                    file: "b.DNG".into(),
                    size: 1,
                    source_sha: "s".into(),
                    dest_sha: "-".into(),
                    verdict: Verdict::CopyFail,
                    detail: "no space left".into(),
                },
            ],
            clips: vec![],
        };
        assert_eq!(report.verdict_line(), "offload: REFUSE 1 named row(s) (dest /dest)");
        assert_eq!(report.dirty_count(), 1);
        let fail = report.fail_lines();
        assert_eq!(fail.len(), 1);
        assert!(fail[0].starts_with("FAIL COPY_FAIL clip="), "{fail:?}");
        assert!(fail[0].contains("no space left"));
    }

    // =================================================================
    // The standalone `frameprism offload <in> <to>` surface (the
    // pass-through engine — offload NEVER transforms)
    // =================================================================


    /// The N>1 run-report shape (the minimum set, test 8): the
    /// per-dest section headers present + pinned (the `###
    /// destination: <dest>` shape), the per-clip blocks + the verdict
    /// lines under their own dest's section, the detection block
    /// singular, exactly ONE `created:` line; every dest root's
    /// report carries the WHOLE run (byte-identical content).
    #[test]
    fn fanout_run_report_n_shape_per_dest_sections() {
        profile_override_a001();
        let (base, input) = standalone_tree("fanout2report");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        let rc = run_offload_multi(&input_c, &[d1.clone(), d2.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS);
        let d1c = std::fs::canonicalize(&d1).unwrap();
        let d2c = std::fs::canonicalize(&d2).unwrap();
        let tr = read_report(&d1);
        // The header (the N>1 shape: the single `dest:` line is gone
        // — the section headers name every dest; exactly ONE
        // `created:` line).
        assert!(
            tr.starts_with("# frameprism offload run report — in\n\n"),
            "{tr}"
        );
        assert_eq!(
            tr.lines().filter(|l| l.starts_with("created:")).count(),
            1,
            "exactly one created: line:\n{tr}"
        );
        assert!(
            !tr.lines().any(|l| l.starts_with("dest: ")),
            "no single dest: header line (N>1):\n{tr}"
        );
        assert!(tr.contains("clips: 4 · files: 7"), "the run's clip + file numbers:\n{tr}");
        // The detection block ONCE (the source-side, run-once scan —
        // singular, not repeated per dest).
        assert_eq!(tr.matches("## detection").count(), 1, "{tr}");
        assert_eq!(
            tr.matches("A001_001: profiled a001-sigma-fp (profile v1)").count(),
            1,
            "the detection line is singular (not per-dest):\n{tr}"
        );
        // The per-dest sections: the pinned header shape + the
        // per-clip rendering + the verdict line under their own
        // dest's section, the dest order.
        let s1 = format!("### destination: {}\n\n## copy\n\nclip\tfiles\tsource B\n", d1c.display());
        let s2 = format!("### destination: {}\n\n## copy\n\nclip\tfiles\tsource B\n", d2c.display());
        let i1 = tr.find(&s1).expect("the dest-1 section header (the pinned shape):\n{tr}");
        let i2 = tr.find(&s2).expect("the dest-2 section header (the pinned shape):\n{tr}");
        assert!(i1 < i2, "the dest order: the sections ride the named order");
        // The per-clip blocks (the existing rendering) + the verdict
        // lines under their own sections; the file ends with the
        // last dest's verdict line.
        assert!(tr[i1..i2].contains("totals: 7 file(s) —"), "the dest-1 copy totals under its section:\n{tr}");
        assert!(
            tr.contains(&format!("\noffload: VERIFIED 7/7 (dest {})\n\n### destination: {}", d1c.display(), d2c.display())),
            "the dest-1 verdict line (verbatim) closes its section, then the dest-2 header:\n{tr}"
        );
        assert!(
            tr.ends_with(&format!("\noffload: VERIFIED 7/7 (dest {})\n", d2c.display())),
            "the run ends with the last dest's verdict line:\n{tr}"
        );
        // The other dest's root carries the WHOLE run too (the
        // report content is the same at every dest root — a mirror
        // records the provenance of the run, not just its own half).
        assert_eq!(tr, read_report(&d2), "every dest root's report carries the whole run");
        let _ = std::fs::remove_dir_all(&base);
    }

    // =================================================================
    // The job reports (the structured job-report format,
    // the documented 2024.2 baseline (b): the session + summary
    // blocks + the per-clip blocks, the three file forms md/csv/html
    // at EVERY dest root, the save-with-job placement, automatic, no
    // flag — the record, not the gate). The line-level idiom (the
    // wall clock: assert the named lines + the deterministic values,
    // the durations by FORMAT class only — `\d+ ms` / `\d+\.\d s` —
    // never by value; NEVER whole-byte for the job-report files).
    // =================================================================


    /// The clean N-dest run → the job reports exist + are complete
    /// (the 3-clip tree → 2 dests, the variadic form):
    /// all SIX files present (3 per dest root, the exact names); the
    /// md: the session block lines (input/dest/created/tool — the
    /// created by format), the summary block (the total count + size
    /// EXACT, the verdict line VERBATIM), the per-clip blocks (the
    /// detection lines VERBATIM per clip, the file count/size EXACT,
    /// the per-file rows — the relpath/size/shas/verdict EXACT, the
    /// copied_ms by format); the csv: the header row VERBATIM, one
    /// row per file (the EXACT values, the row order), the trailing
    /// newline; the html: the doctype + the tables' rows (the same
    /// values), the escaped content.
    #[test]
    fn job_report_clean_n_dest_run_complete() {
        profile_override_a001();
        let (base, input) = standalone_tree("job2clean");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        let rc = run_offload_multi(&input_c, &[d1.clone(), d2.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "every row OK at every dest");
        let d1c = std::fs::canonicalize(&d1).unwrap();
        let d2c = std::fs::canonicalize(&d2).unwrap();
        // The source sizes + shas (the independent values — the
        // gate idiom; the row order within a clip = the
        // sorted relpath order).
        let rels = [
            "A001_001/SPP_metadata.xmp",
            "A001_001/clip.wav",
            "A001_001/f1.DNG",
            "B002_002/f1.DNG",
            "C003_003/clip.wav",
            "manifest.tsv",
            "root.wav",
        ];
        let mut sizes: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        let mut shas: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
        let mut total = 0u64;
        for rel in rels {
            let bytes = std::fs::read(input.join(rel)).unwrap();
            sizes.insert(rel, bytes.len());
            shas.insert(rel, crate::jxl::sha256_hex(&bytes));
            total += bytes.len() as u64;
        }
        for (d, dc) in [(d1c.clone(), d1c.clone()), (d2c.clone(), d2c.clone())] {
            // All SIX files: 3 per dest root, the exact names.
            let (md, csv, html) = job_report_files(&d);
            // The md — the session block (the input as given, the
            // dest's own canonical path, the created by format, the
            // tool line, the job identifier by format).
            assert!(md.starts_with("# frameprism job report\n\n"), "the title:\n{md}");
            assert!(
                md.contains(&format!("input: {}\n", input_c.display())),
                "the input path (as given):\n{md}"
            );
            assert!(md.contains(&format!("dest: {}\n", dc.display())), "the dest path:\n{md}");
            let created = md
                .lines()
                .find(|l| l.starts_with("created: "))
                .unwrap_or_else(|| panic!("the created: line:\n{md}"));
            let stamp = created
                .strip_prefix("created: ")
                .unwrap()
                .strip_suffix(" (unix seconds, UTC)")
                .unwrap_or_else(|| panic!("the created by format: {created:?}"));
            assert!(!stamp.is_empty() && stamp.bytes().all(|b| b.is_ascii_digit()), "the created's unix seconds: {stamp:?}");
            assert!(
                md.contains(&format!("tool: frameprism {}\n", env!("CARGO_PKG_VERSION"))),
                "the tool + version line (the OSS name):\n{md}"
            );
            let job = md
                .lines()
                .find(|l| l.starts_with("job: "))
                .unwrap_or_else(|| panic!("the job identifier line:\n{md}"));
            assert!(
                utc_format(job.strip_prefix("job: ").unwrap()),
                "the job identifier by format (the UTC timestamp): {job:?}"
            );
            // The md — the summary block (the total count + size
            // EXACT, the run duration by format, the per-dest
            // verdict line VERBATIM).
            let sum = md_section(&md, "summary");
            assert!(sum.contains("files: 7\n"), "the total file count EXACT:\n{sum}");
            assert!(sum.contains(&format!("size: {total} B\n")), "the total size EXACT:\n{sum}");
            assert!(
                sum.lines().any(duration_s_line),
                "the run duration by format class (\\d+.\\d s):\n{sum}"
            );
            assert!(
                sum.contains(&format!("offload: VERIFIED 7/7 (dest {})\n", dc.display())),
                "the per-dest verdict line VERBATIM:\n{sum}"
            );
            // The md — the per-clip blocks (the detection lines
            // VERBATIM per clip — the three-class formats from the
            // code; the file count/size EXACT; the per-file rows
            // EXACT, the copied_ms by format).
            let root = md_section(&md, ".");
            assert!(root.contains("non-DNG media\n"), "the root's detection line verbatim:\n{root}");
            assert!(root.contains(&format!("size: {} B\n", sizes["manifest.tsv"] + sizes["root.wav"])), "the root's size EXACT:\n{root}");
            md_row_verdict(root, "manifest.tsv", sizes["manifest.tsv"], &shas["manifest.tsv"], &shas["manifest.tsv"], "OK", "no");
            md_row_verdict(root, "root.wav", sizes["root.wav"], &shas["root.wav"], &shas["root.wav"], "OK", "no");
            let a = md_section(&md, "A001_001");
            assert!(
                a.contains("profiled a001-sigma-fp (profile v1)\n"),
                "the profiled detection line verbatim:\n{a}"
            );
            assert!(a.contains("files: 3\n"), "the clip's file count EXACT:\n{a}");
            assert!(
                a.contains(&format!("size: {} B\n", sizes["A001_001/SPP_metadata.xmp"] + sizes["A001_001/clip.wav"] + sizes["A001_001/f1.DNG"])),
                "the clip's size EXACT:\n{a}"
            );
            assert!(a.lines().any(duration_ms_line), "the clip's duration by format class (\\d+ ms):\n{a}");
            md_row_verdict(a, "A001_001/SPP_metadata.xmp", sizes["A001_001/SPP_metadata.xmp"], &shas["A001_001/SPP_metadata.xmp"], &shas["A001_001/SPP_metadata.xmp"], "OK", "no");
            md_row_verdict(a, "A001_001/clip.wav", sizes["A001_001/clip.wav"], &shas["A001_001/clip.wav"], &shas["A001_001/clip.wav"], "OK", "no");
            md_row_verdict(a, "A001_001/f1.DNG", sizes["A001_001/f1.DNG"], &shas["A001_001/f1.DNG"], &shas["A001_001/f1.DNG"], "OK", "no");
            let b = md_section(&md, "B002_002");
            assert!(
                b.contains("unprofiled camera TEST MAKE TEST MODEL\n"),
                "the unprofiled detection line verbatim:\n{b}"
            );
            md_row_verdict(b, "B002_002/f1.DNG", sizes["B002_002/f1.DNG"], &shas["B002_002/f1.DNG"], &shas["B002_002/f1.DNG"], "OK", "no");
            let c = md_section(&md, "C003_003");
            assert!(c.contains("non-DNG media\n"), "the non-DNG detection line verbatim:\n{c}");
            md_row_verdict(c, "C003_003/clip.wav", sizes["C003_003/clip.wav"], &shas["C003_003/clip.wav"], &shas["C003_003/clip.wav"], "OK", "no");
            // The csv — the header row VERBATIM (NO comment magic),
            // one row per file (the EXACT values, the row order: per
            // clip, the detection's sorted clip-key order; the rows'
            // own order within a clip), the trailing newline (no
            // BOM).
            let cl: Vec<&str> = csv.lines().collect();
            assert_eq!(cl[0], crate::jobreport::CSV_HEADER, "the EXACT header row first");
            assert_eq!(cl.len(), 8, "the header + one row per file:\n{csv}");
            assert_eq!(csv.as_bytes()[0], b'c', "no BOM");
            assert!(csv.ends_with('\n'), "the trailing newline");
            csv_row_verdict(&cl, 1, "", "manifest.tsv", sizes["manifest.tsv"], &shas["manifest.tsv"], &shas["manifest.tsv"], "OK", "0");
            csv_row_verdict(&cl, 2, "", "root.wav", sizes["root.wav"], &shas["root.wav"], &shas["root.wav"], "OK", "0");
            csv_row_verdict(&cl, 3, "A001_001", "A001_001/SPP_metadata.xmp", sizes["A001_001/SPP_metadata.xmp"], &shas["A001_001/SPP_metadata.xmp"], &shas["A001_001/SPP_metadata.xmp"], "OK", "0");
            csv_row_verdict(&cl, 4, "A001_001", "A001_001/clip.wav", sizes["A001_001/clip.wav"], &shas["A001_001/clip.wav"], &shas["A001_001/clip.wav"], "OK", "0");
            csv_row_verdict(&cl, 5, "A001_001", "A001_001/f1.DNG", sizes["A001_001/f1.DNG"], &shas["A001_001/f1.DNG"], &shas["A001_001/f1.DNG"], "OK", "0");
            csv_row_verdict(&cl, 6, "B002_002", "B002_002/f1.DNG", sizes["B002_002/f1.DNG"], &shas["B002_002/f1.DNG"], &shas["B002_002/f1.DNG"], "OK", "0");
            csv_row_verdict(&cl, 7, "C003_003", "C003_003/clip.wav", sizes["C003_003/clip.wav"], &shas["C003_003/clip.wav"], &shas["C003_003/clip.wav"], "OK", "0");
            // The html — the doctype + the tables' rows (the same
            // values as the csv) + the escaped content.
            assert!(html.starts_with("<!doctype html>"), "the doctype");
            assert!(html.ends_with("</html>\n"), "the self-contained file");
            assert!(
                html.contains(&format!("<pre>offload: VERIFIED 7/7 (dest {dest})</pre>", dest = dc.display())),
                "the verdict line in the <pre>:\n{html}"
            );
            assert!(
                html.contains(&format!(
                    "<td>A001_001</td><td>A001_001/f1.DNG</td><td>{}</td><td>{}</td><td>{}</td><td>OK</td>",
                    sizes["A001_001/f1.DNG"],
                    shas["A001_001/f1.DNG"],
                    shas["A001_001/f1.DNG"]
                )),
                "the table's row (the same values as the csv):\n{html}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The dirty run (the existing in-run COPY_FAIL idiom): the job
    /// report's per-file row carries the named verdict
    /// (COPY_FAIL) + the summary's verdict line = the REFUSE format
    /// VERBATIM; the rc is the run's rc=1 (the job report does not
    /// change it).
    #[test]
    fn job_report_dirty_run_refuse_shape() {
        profile_override_a001();
        let (base, input) = standalone_tree("job2dirty");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        // The existing in-run COPY_FAIL idiom (a DIR at the file's
        // mirror path — the pre-write band passes, the copy itself
        // fails NAMED).
        std::fs::create_dir_all(d.join("A001_001/f1.DNG")).unwrap();
        let rc = run_offload(&input_c, &d).unwrap();
        assert_eq!(rc, ExitCode::from(1), "the dirty row → the run's rc=1 (the job report does not change it)");
        let dc = std::fs::canonicalize(&d).unwrap();
        let (md, csv, _html) = job_report_files(&d);
        // The summary's verdict line = the REFUSE format VERBATIM.
        assert!(
            md.contains(&format!("offload: REFUSE 1 named row(s) (dest {})\n", dc.display())),
            "the REFUSE verdict line verbatim:\n{md}"
        );
        // The per-file row carries the named verdict (COPY_FAIL) +
        // the no-copy token (`-`) for the dest sha256; the clean
        // rows ride (the verdict is carried, the run is not killed
        // mid-copy).
        let f1 = std::fs::read(input.join("A001_001/f1.DNG")).unwrap();
        let sha = crate::jxl::sha256_hex(&f1);
        let sec = md_section(&md, "A001_001");
        md_row_verdict(sec, "A001_001/f1.DNG", f1.len(), &sha, "-", "COPY_FAIL", "no");
        md_row_verdict(sec, "A001_001/clip.wav", 9, &crate::jxl::sha256_hex(b"RIFF-wave"), &crate::jxl::sha256_hex(b"RIFF-wave"), "OK", "no");
        let cl: Vec<&str> = csv.lines().collect();
        let row = cl
            .iter()
            .find(|l| l.contains("A001_001/f1.DNG"))
            .unwrap_or_else(|| panic!("the csv row for the failed file:\n{csv}"));
        assert!(
            row.starts_with(&format!("A001_001,A001_001/f1.DNG,{},{},-,COPY_FAIL,", f1.len(), sha)),
            "the csv row's named verdict + the no-copy token: {row:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The R-INV-A proof (the contract artifacts untouched): the
    /// manifests (the parsed columns — no duration column; the
    /// EXACT 5-column line; the known header keys only; the shas
    /// against an INDEPENDENT hash — the in-test round-trip: the
    /// job-report run's manifest bytes are the pre-job-report
    /// manifest's bytes), the run report's rendering (the pinned
    /// shape — no duration token), the stderr lines (no
    /// duration lines — the existing tests cover the surface, the
    /// suite green UNCHANGED).
    #[test]
    fn job_report_run_contract_artifacts_untouched() {
        profile_override_a001();
        let (base, input) = standalone_tree("job2inv");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        let rc = run_offload(&input_c, &d).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS);
        // The manifests (the wire contract — the in-test round-
        // trip): the parse's 5-column rows hard-fail a 6th duration
        // column; the EXACT column line; the known header keys only
        // (a new key would be the named v2 channel, not this version);
        // no duration token anywhere.
        let mpath = d.join("in.offload-manifest.tsv");
        let m = crate::offload::parse_manifest(&mpath).unwrap();
        assert_eq!(m.rows.len(), 2, "the parsed columns (no duration column)");
        let text = std::fs::read_to_string(&mpath).unwrap();
        assert!(
            text.contains("file\tsize\tsource_sha256\tdest_sha256\tverdict"),
            "the EXACT 5-column line"
        );
        assert!(
            !text.lines().any(|l| l.contains("duration") || l.contains("copied_ms") || l.contains(" ms")),
            "no duration token anywhere in the manifest:\n{text}"
        );
        let col = text.find("file\tsize\tsource_sha256\tdest_sha256\tverdict").unwrap();
        let known = ["version", "clip", "created", "input", "dest", "tool_version", "host", "files", "clips"];
        for line in text[..col].lines().skip(1) {
            let key = line.split_once(':').map(|(k, _)| k).unwrap_or(line);
            assert!(known.contains(&key), "a known header key only (no new key): {line:?}");
        }
        // The shas against an INDEPENDENT hash (the gate
        // idiom): every manifest row's source_sha256 = the fresh
        // source sha256.
        for (file, size, src_sha, _dst_sha) in &m.rows {
            let bytes = std::fs::read(input.join(file)).unwrap();
            assert_eq!(bytes.len() as u64, *size, "the row's size: {file}");
            assert_eq!(&crate::jxl::sha256_hex(&bytes), src_sha, "the row's sha (independent): {file}");
        }
        let (_, bad) = crate::offload::reverify(&m);
        assert_eq!(bad, 0, "the manifest re-verifies clean");
        // The run report's rendering (the pinned shape — the
        // 1-dest form UNCHANGED by the timing): the exact header,
        // ONE created: line, NO duration token (the durations ride
        // ONLY in the job report — R-INV-A).
        let tr = read_report(&d);
        assert!(tr.starts_with("# frameprism offload run report — in\n"), "the 1-dest run report's pinned header:\n{tr}");
        assert_eq!(tr.lines().filter(|l| l.starts_with("created:")).count(), 1, "ONE created: line:\n{tr}");
        assert!(!tr.contains("duration") && !tr.contains("ms"), "no duration token in the run report:\n{tr}");
        // The job report files are the ADDITION (the three exact
        // names) — the records the suite already pins stand.
        let (md, _csv, _html) = job_report_files(&d);
        assert!(md.starts_with("# frameprism job report\n"), "the job report is the new artifact family");
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The comma-in-filename (a mirrored file whose name carries a
    /// `,`): the CSV row is RFC-4180-quoted + parseable (the test
    /// round-trips the row split), the md's code span carries it
    /// verbatim, the html's text node carries it.
    #[test]
    fn job_report_comma_filename_csv_quoting() {
        profile_override_a001();
        let base = std::env::temp_dir().join(format!("frameprism_jobreport_comma_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        std::fs::create_dir_all(input.join("C1")).unwrap();
        std::fs::write(input.join("C1/a,b.DNG"), b"comma-payload").unwrap();
        std::fs::write(input.join("C1/quote\".wav"), b"q").unwrap();
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        let rc = run_offload(&input_c, &d).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS);
        let (md, csv, html) = job_report_files(&d);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], crate::jobreport::CSV_HEADER);
        // The comma-in-filename: the RFC-4180-quoted field + the
        // round-trip (the parser undoes the quoting).
        let comma_row = lines.iter().find(|l| l.contains("a,b.DNG")).unwrap_or_else(|| panic!("the comma row:\n{csv}"));
        assert!(comma_row.contains("\"C1/a,b.DNG\""), "RFC-4180-minimal quoting (the comma → double-quoted): {comma_row:?}");
        let fields = parse_csv_line(comma_row);
        assert_eq!(fields.len(), 8, "the round-trip's 8 columns: {fields:?}");
        assert_eq!(fields[0], "C1", "the clip cell: {fields:?}");
        assert_eq!(fields[1], "C1/a,b.DNG", "the round-trip (the quote-doubling undone): {fields:?}");
        // The quote-in-filename: quoted + the embedded quote
        // doubled + the round-trip.
        let quote_row = lines.iter().find(|l| l.contains(".wav")).unwrap_or_else(|| panic!("the quote row:\n{csv}"));
        assert!(quote_row.contains("\"C1/quote\"\".wav\""), "the embedded quote doubled: {quote_row:?}");
        assert_eq!(parse_csv_line(quote_row)[1], "C1/quote\".wav", "the round-trip");
        // The md's code span carries it verbatim; the html's text
        // node carries it.
        assert!(md.contains("`C1/a,b.DNG`"), "the md's code span verbatim:\n{md}");
        assert!(html.contains("<td>C1/a,b.DNG</td>"), "the html's text node:
{html}");
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The ampersand/angle-brackets-in-filename: the HTML escaping
    /// (`&amp;` `&lt;` `&gt;` — the test asserts the escaped forms
    /// present, the raw forms absent from the text nodes); the CSV
    /// unquoted-safe (no comma/quote in the name → unquoted).
    #[test]
    fn job_report_ampersand_filename_html_escaping() {
        profile_override_a001();
        let base = std::env::temp_dir().join(format!("frameprism_jobreport_amp_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        std::fs::create_dir_all(input.join("C1")).unwrap();
        std::fs::write(input.join("C1/we<&ird>.DNG"), b"amp-payload").unwrap();
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        let rc = run_offload(&input_c, &d).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS);
        let (md, csv, html) = job_report_files(&d);
        // The HTML escaping (the escaped forms present, the raw
        // forms absent from the text nodes).
        assert!(html.contains("we&lt;&amp;ird&gt;.DNG"), "the escaped forms present:\n{html}");
        assert!(!html.contains("we<&ird>.DNG"), "the raw forms absent from the text nodes:\n{html}");
        // The CSV unquoted-safe (no comma/quote in the name →
        // unquoted).
        let line = csv.lines().find(|l| l.contains("we<&ird>.DNG")).unwrap_or_else(|| panic!("the csv row:\n{csv}"));
        assert!(!line.contains('"'), "unquoted-safe (no comma/quote/newline in the name): {line:?}");
        assert!(line.contains("C1,C1/we<&ird>.DNG,"), "the plain field: {line:?}");
        // The md: the code span carries the name verbatim (the md
        // needs no escaping).
        assert!(md.contains("`C1/we<&ird>.DNG`"), "the md's code span verbatim:\n{md}");
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The write-failure band: a dest root that becomes
    /// unwritable for the job-report write ONLY (the md's name is
    /// occupied by a DIR — the manifest + run-report writes, other
    /// names, succeed) → the named refusal, the error rc, the
    /// manifests + run report already written (the records stand
    /// before the job report).
    #[test]
    fn job_report_write_failure_band_records_stand() {
        profile_override_a001();
        let (base, input) = standalone_tree("job2fail");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        // The dest root exists + is writable for the records, but
        // the job-report md's NAME is occupied by a DIR: the
        // job-report write (and only it) fails.
        std::fs::create_dir_all(&d).unwrap();
        std::fs::create_dir_all(d.join(crate::jobreport::MD_NAME)).unwrap();
        let err = run_offload(&input_c, &d).unwrap_err();
        assert!(
            err.to_string().contains("write the job report at dest"),
            "the named hard-error band (the manifest writers' .with_context class): {err:#}"
        );
        // The error rc (the `run` surface turns the Err into the
        // error rc — the run's rc becomes the error rc). The legacy
        // form (the flags absent — the single-source form).
        let rc = run(&Args {
            input: Some(input_c.clone()),
            source: vec![],
            dest: vec![],
            to: vec![d.clone()],
        });
        assert_eq!(rc, ExitCode::from(2), "the error rc");
        // The records stand BEFORE the job report: the manifests +
        // the run report are already written + re-verify clean; the
        // job report's csv + html are absent (the md's write failed
        // first — its name is the dir).
        let m = crate::offload::parse_manifest(&d.join("in.offload-manifest.tsv")).unwrap();
        let (_, bad) = crate::offload::reverify(&m);
        assert_eq!(bad, 0, "the manifest re-verifies clean (the records stand)");
        let m2 = crate::offload::parse_manifest(&d.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
        let (_, bad2) = crate::offload::reverify(&m2);
        assert_eq!(bad2, 0, "the clip manifest re-verifies clean (the records stand)");
        assert!(d.join(crate::report::RUN_REPORT_NAME).is_file(), "the run report stands");
        assert!(!d.join(crate::jobreport::CSV_NAME).is_file(), "the csv is absent (the md's write failed first)");
        assert!(!d.join(crate::jobreport::HTML_NAME).is_file(), "the html is absent");
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The single-dest shape: exactly 3
    /// job-report files at the one dest root, the content contract
    /// per the clean-run test — the 1-dest invariant preserved (the
    /// single-dest tests green UNCHANGED).
    #[test]
    fn job_report_single_dest_shape() {
        profile_override_a001();
        let (base, input) = standalone_tree("job1");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        let rc = run_offload(&input_c, &d).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS);
        let dc = std::fs::canonicalize(&d).unwrap();
        // Exactly 3 job-report files at the one dest root (the
        // exact pinned names — no more, no less).
        let mut names: Vec<String> = std::fs::read_dir(&dc)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".frameprism-job-report"))
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![".frameprism-job-report.csv", ".frameprism-job-report.html", ".frameprism-job-report.md"],
            "exactly the three pinned names"
        );
        // The content contract (the 1-dest shape).
        let (md, csv, html) = job_report_files(&d);
        assert!(md.starts_with("# frameprism job report\n\n"), "the title");
        assert!(md.contains(&format!("dest: {}\n", dc.display())), "the dest's own session line");
        assert!(
            md.contains(&format!("offload: VERIFIED 7/7 (dest {})\n", dc.display())),
            "the verdict line verbatim:\n{md}"
        );
        assert!(md.contains("profiled a001-sigma-fp (profile v1)\n"), "the profiled detection line verbatim");
        assert!(md.contains("unprofiled camera TEST MAKE TEST MODEL\n"), "the unprofiled detection line verbatim");
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 8, "the header + one row per file:\n{csv}");
        assert_eq!(lines[0], crate::jobreport::CSV_HEADER, "the EXACT header row");
        assert!(html.starts_with("<!doctype html>"), "the doctype");
        assert!(html.ends_with("</html>\n"), "the self-contained file");
        // The 1-dest invariant preserved: the run report is the
        // pre-job-report shape (the existing single-dest tests green
        // UNCHANGED pin it byte-for-byte).
        let tr = read_report(&d);
        assert!(tr.starts_with("# frameprism offload run report — in\n"), "the 1-dest run report shape");
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The duration format (the line-level): the per-clip
    /// `duration:` lines match the pinned format class (`\d+ ms`);
    /// the summary's run duration matches the pinned format class
    /// (`\d+.\d s`); the CSV's copied_ms column is the integer ms —
    /// the values are NOT pinned (the wall clock).
    #[test]
    fn job_report_duration_line_format() {
        profile_override_a001();
        let (base, input) = standalone_tree("job2dur");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        let rc = run_offload(&input_c, &d).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS);
        let (md, csv, _html) = job_report_files(&d);
        // The per-clip `duration:` lines (one per clip — the 4 clip
        // keys of the fixture tree) match the pinned format class;
        // the summary's run duration matches its class.
        let mut ms_lines = 0;
        let mut s_lines = 0;
        for line in md.lines() {
            if duration_ms_line(line) {
                ms_lines += 1;
            } else if duration_s_line(line) {
                s_lines += 1;
            }
        }
        assert_eq!(ms_lines, 4, "one per-clip `duration: <n> ms` line per clip:\n{md}");
        assert_eq!(s_lines, 1, "the summary's `duration: <n.n> s` line:\n{md}");
        // The CSV's copied_ms column is the integer ms (the format
        // class — the values are NOT pinned).
        for line in csv.lines().skip(1) {
            let tail = line.rsplit(',').next().unwrap();
            assert!(
                !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()),
                "copied_ms the integer ms: {line:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    // =================================================================
    // The ascmhl history (the industry provenance
    // standard's media-hash-list record written beside every offload
    // copy: the run-level integration)
    // =================================================================


    /// The clean 2-dest run → the ascmhl per dest (test 8): the
    /// `ascmhl/` dir at BOTH dest roots (the exact manifest file name
    /// shape — `0001_<dest-basename>_YYYY-MM-DD_HHMMSSZ.mhl`), the
    /// chain present (the C4ID of the manifest's bytes), the
    /// manifest's `<hash>` set = EXACTLY the managed media files (the
    /// ignore set proven end-to-end: the offload manifests / run
    /// report / job reports are NOT records in the ascmhl), the
    /// roothash present, the process = `transfer`, the actions =
    /// `original`; the manifest's creationdate + the file name's
    /// stamp = the run's creation instant (the run report's
    /// `created:` unix seconds); the records carry no ascmhl
    /// content (R-INV-A — the pinned tests green UNCHANGED are
    /// the byte-level proof).
    #[test]
    fn ascmhl_history_per_dest_clean_two_dest_run() {
        profile_override_a001();
        let (base, input) = standalone_tree("mhl2dest");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        let rc = run_offload_multi(&input_c, &[d1.clone(), d2.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "the clean run stays rc=0");
        for (d, dest_name) in [(d1.clone(), "to1"), (d2.clone(), "to2")] {
            // The ascmhl dir at the dest root: EXACTLY one manifest
            // + the chain (the generation-1 history).
            let ascmhl_dir = d.join("ascmhl");
            assert!(ascmhl_dir.is_dir(), "the ascmhl dir at {:?}", d);
            let mut names: Vec<String> = std::fs::read_dir(&ascmhl_dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            assert_eq!(names.len(), 2, "the manifest + the chain: {names:?}");
            let manifest_name = names
                .iter()
                .find(|n| n.ends_with(".mhl"))
                .expect("the manifest")
                .clone();
            assert!(names.contains(&"ascmhl_chain.xml".to_string()), "the chain");
            // The exact file name shape (the spec's 6.3):
            // `0001_<dest-basename>_YYYY-MM-DD_HHMMSSZ.mhl` — the
            // 0001 numbering, the dest's basename.
            let prefix = format!("0001_{dest_name}_");
            assert!(
                manifest_name.starts_with(&prefix) && manifest_name.ends_with(".mhl"),
                "the 0001 numbering + the dest's basename: {manifest_name}"
            );
            // The run report's `created:` unix seconds (the run's
            // creation instant) — the manifest's creationdate + the
            // file name's stamp are the SAME instant.
            let run_report = read_report(&d);
            let created_line = run_report
                .lines()
                .find(|l| l.starts_with("created: "))
                .expect("the run report's created: line");
            let created_unix: u64 = created_line["created: ".len()..]
                .split(' ')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            let ts = crate::jobreport::utc_timestamp(created_unix); // YYYY-MM-DDTHH:MM:SSZ
            let stamp = format!("{}_{}Z", &ts[..10], ts[11..ts.len() - 1].replace(':', ""));
            assert_eq!(
                manifest_name,
                format!("{prefix}{stamp}.mhl"),
                "the file name's date/time = the run's creation instant (Zulu)"
            );
            // The manifest's content (the generation-1 transfer
            // record — the structure + the managed set, proven
            // end-to-end).
            let xml =
                std::fs::read_to_string(ascmhl_dir.join(&manifest_name)).unwrap();
            let root = crate::ascmhl::parse_lite(&xml).expect("the manifest is well-formed");
            assert_eq!(root.name, "hashlist");
            assert_eq!(crate::ascmhl::attr(&root, "version"), Some("2.0"));
            assert_eq!(
                crate::ascmhl::attr(&root, "xmlns"),
                Some("urn:ASC:MHL:v2.0"),
                "the v2.0 lineage's namespace"
            );
            // The creationdate = the run's creation instant (UTC).
            let creationdate = root.children[0].children[0].text.as_str();
            assert_eq!(
                creationdate,
                format!("{}+00:00", &ts[..ts.len() - 1]),
                "the creationdate = the run report's created instant"
            );
            // The process = transfer; the roothash present (the
            // content + structure containers, each one c4).
            let processinfo = &root.children[1];
            assert_eq!(processinfo.children[0].text, "transfer", "the process");
            let roothash = &processinfo.children[1];
            assert_eq!(roothash.name, "roothash");
            assert_eq!(
                roothash.children.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
                vec!["content", "structure"],
                "the roothash's containers"
            );
            // The hashes: EXACTLY the managed media files (the
            // end-to-end proof: the 7 mirrored media files — the
            // offload manifests / the run report / the job reports
            // are NOT records in the ascmhl) + the 3 clip dirs;
            // the post-order (the children before the dir).
            let hashes = &root.children[2];
            assert_eq!(hashes.name, "hashes");
            let entries: Vec<(String, String)> = hashes
                .children
                .iter()
                .map(|e| (e.name.clone(), e.children[0].text.clone()))
                .collect();
            assert_eq!(
                entries,
                vec![
                    ("hash".into(), "A001_001/SPP_metadata.xmp".into()),
                    ("hash".into(), "A001_001/clip.wav".into()),
                    ("hash".into(), "A001_001/f1.DNG".into()),
                    ("directoryhash".into(), "A001_001".into()),
                    ("hash".into(), "B002_002/f1.DNG".into()),
                    ("directoryhash".into(), "B002_002".into()),
                    ("hash".into(), "C003_003/clip.wav".into()),
                    ("directoryhash".into(), "C003_003".into()),
                    ("hash".into(), "manifest.tsv".into()),
                    ("hash".into(), "root.wav".into()),
                ],
                "the managed set = the media only (the ignore set ignores end-to-end), the post-order"
            );
            // The c4 elements: the FILE's c4 = the C4ID of the DEST
            // file's bytes (the copy's content — the independent
            // recompute) + `action="original"` (the generation-1
            // semantics); the roothash/directoryhash container c4s
            // carry the `hashdate` only (the reference's worked
            // examples: the `action` is the file hash's attribute).
            for e in &hashes.children {
                if e.name == "hash" {
                    let c4el = &e.children[1];
                    assert_eq!(c4el.name, "c4", "the one-algorithm set (c4)");
                    assert_eq!(
                        crate::ascmhl::attr(c4el, "action"),
                        Some("original"),
                        "the generation-1 action"
                    );
                    assert_eq!(
                        crate::ascmhl::attr(c4el, "hashdate"),
                        Some(creationdate),
                        "the hashdate = the run's creation instant"
                    );
                    let rel = &e.children[0].text;
                    assert_eq!(
                        crate::ascmhl::c4(&std::fs::read(d.join(rel)).unwrap()),
                        c4el.text,
                        "the c4 of the DEST file's bytes: {rel}"
                    );
                } else {
                    let (content, structure) = (&e.children[1], &e.children[2]);
                    assert_eq!(content.name, "content");
                    assert_eq!(structure.name, "structure");
                    for container in [content, structure] {
                        let c4el = &container.children[0];
                        assert_eq!(c4el.name, "c4", "the one-algorithm set (c4)");
                        assert_eq!(
                            crate::ascmhl::attr(c4el, "action"),
                            None,
                            "the container's c4 carries no action (the reference's shape)"
                        );
                        assert_eq!(
                            crate::ascmhl::attr(c4el, "hashdate"),
                            Some(creationdate),
                            "the hashdate = the run's creation instant"
                        );
                    }
                }
            }
            // The chain (one record: the manifest's file name + the
            // C4ID of the manifest file's bytes).
            let chain = std::fs::read_to_string(ascmhl_dir.join("ascmhl_chain.xml")).unwrap();
            let recs = crate::ascmhl::read_chain(&chain).expect("the chain's records");
            assert_eq!(recs.len(), 1, "one generation");
            assert_eq!(
                recs[0],
                (
                    1,
                    manifest_name.clone(),
                    crate::ascmhl::c4(xml.as_bytes())
                ),
                "the chain's c4 = the C4ID of the manifest's bytes"
            );
            // R-INV-A — no ascmhl content enters the records (the
            // offload manifests + the run report + the job report;
            // the existing pinned tests green UNCHANGED are the
            // byte-level proof — the statement holds: the offload
            // adds nothing here the records don't cover).
            for artifact in [
                d.join("A001_001/A001_001.offload-manifest.tsv"),
                d.join("in.offload-manifest.tsv"),
                d.join(crate::report::RUN_REPORT_NAME),
                d.join(crate::jobreport::MD_NAME),
                d.join(crate::jobreport::CSV_NAME),
                d.join(crate::jobreport::HTML_NAME),
            ] {
                let body = std::fs::read_to_string(&artifact).unwrap();
                assert!(
                    !body.contains("ascmhl"),
                    "no ascmhl content in {}",
                    artifact.display()
                );
            }
        }
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The failure band (test 10): the ascmhl write failure
    /// (the ascmhl dir pre-created as a FILE at the dest root — the
    /// writer's create fails) → the named refusal, the error rc
    /// (the `run`'s rc=2 band), the records (the per-clip manifests
    /// + the run report + the job reports) already stand.
    #[test]
    fn ascmhl_write_failure_is_the_named_band_records_stand() {
        profile_override_a001();
        let (base, input) = standalone_tree("mhlfail");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to1");
        // The test idiom: the ascmhl dir pre-created as a FILE at
        // the dest root (the dest dir itself exists + is writable —
        // the probe passes; the writer's create fails).
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("ascmhl"), b"the blocker (a file, not a dir)").unwrap();
        let err = run_offload_multi(&input_c, &[d.clone()]).expect_err("the ascmhl write fails");
        let chain = format!("{err:#}");
        assert!(
            chain.contains("write the ascmhl history at dest"),
            "the outer named band: {chain}"
        );
        assert!(
            chain.contains("create the ascmhl dir"),
            "the inner named refusal: {chain}"
        );
        // The records already stand (the write position: LAST —
        // the provenance record comes after the verification
        // records).
        assert!(
            d.join(crate::report::RUN_REPORT_NAME).is_file(),
            "the run report stands"
        );
        assert!(
            d.join(crate::jobreport::MD_NAME).is_file(),
            "the job report stands"
        );
        assert!(
            d.join("A001_001/A001_001.offload-manifest.tsv").is_file(),
            "the per-clip manifest stands"
        );
        assert!(
            d.join("ascmhl").is_file(),
            "the blocker stands (never clobbered)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    // =================================================================
    // The multi-source concurrent offload (the `--source` form — N
    // sources each fanned to ALL M dests in one job; the per-source
    // work CONCURRENT — one std::thread per source, the sources do
    // not wait on each other; the per-dest-root artifacts ride the
    // SERIALIZED TAIL after all sources join. The legacy positional
    // form is byte-frozen — the `offload_legacy_frozen` test below
    // is the in-suite anchor).
    // =================================================================


    /// The 2-source × 2-dest clean job: rc=0; the 4 pair
    /// lines EXACT + the job-level line EXACT (the
    /// pure-composition assertion); the
    /// per-(source,dest,clip) manifests at the mirrored clip roots
    /// (the `dest:` header = that dest; the `input:` header = that
    /// source, as given); the run report at EACH dest (the exact
    /// multi-shape rendering — the 2 `input:` lines, the 2
    /// `### source:` sections, the `### destination:` sections with
    /// the `## copy — source:` blocks, exactly ONE `created:` line —
    /// the SAME content at every dest root); the job report at each
    /// dest (the session's 2 `input:` lines, the CSV header EXACTLY
    /// the CSV header pin, the `source` column's values = the sources as
    /// given); the ascmhl at each dest: exactly ONE 0001 generation +
    /// the chain, the per-entry set covering BOTH sources' entries
    /// (the ignore set — the offload manifests / the run report /
    /// the job reports / the ascmhl's own artifacts are NOT records).
    #[test]
    fn offload_multi_2src_2dest_clean() {
        profile_override_a001();
        let (base, card_a, card_b) = multi_trees("clean2x2");
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        let rc = run(&multi_args(
            vec![card_a.clone(), card_b.clone()],
            vec![d1.clone(), d2.clone()],
        ));
        assert_eq!(rc, ExitCode::SUCCESS, "every pair clean = rc 0");
        let d1c = std::fs::canonicalize(&d1).unwrap();
        let d2c = std::fs::canonicalize(&d2).unwrap();
        // The merged byte mirror at both dests (both sources'
        // entries — the concurrent phase-1's disjoint writes).
        for (src, rels) in [
            (&card_a, vec!["A001_001/f1.DNG", "A001_001/f2.DNG", "S001_001/clip.wav"]),
            (&card_b, vec!["B002_002/f1.DNG", "T001_001/clip.wav"]),
        ] {
            for rel in rels {
                let bytes = std::fs::read(src.join(rel)).unwrap();
                for d in [&d1c, &d2c] {
                    assert_eq!(
                        bytes,
                        std::fs::read(d.join(rel)).unwrap(),
                        "the merged byte mirror: {d:?}/{rel}"
                    );
                }
            }
        }
        // The per-(source, dest, clip) manifests (the mirrored clip
        // roots — the `dest:` header = that dest; the `input:` header
        // = that source, as given).
        for (d, dc) in [(d1.clone(), d1c.clone()), (d2.clone(), d2c.clone())] {
            for (src, clips) in [
                (&card_a, vec![("A001_001", 2usize), ("S001_001", 1)]),
                (&card_b, vec![("B002_002", 1usize), ("T001_001", 1)]),
            ] {
                for (clip, n) in clips {
                    let path = d.join(format!("{clip}/{clip}.offload-manifest.tsv"));
                    let m = crate::offload::parse_manifest(&path).unwrap();
                    assert_eq!(m.rows.len(), n, "the clip's own rows: {d:?}/{clip}");
                    assert_eq!(m.dest, dc, "the manifest's dest header = ITS dest");
                    let (_, bad) = crate::offload::reverify(&m);
                    assert_eq!(bad, 0, "{d:?}/{clip}: the clip manifest re-verifies clean");
                    let text = std::fs::read_to_string(&path).unwrap();
                    assert!(
                        text.contains(&format!("input: {}\n", src.display())),
                        "the manifest's input header = that source, as given: {d:?}/{clip}"
                    );
                }
            }
        }
        // The run report at EACH dest — the exact multi-shape
        // rendering (the same content at every dest root — each file
        // carries the WHOLE job). The free lines are normalized in
        // the expected text: `created:` (the job's single creation
        // instant — extracted from the rendering) + `host:` (the
        // platform line).
        let s_a: u64 = ["A001_001/f1.DNG", "A001_001/f2.DNG"]
            .iter()
            .map(|rel| std::fs::metadata(card_a.join(rel)).unwrap().len())
            .sum::<u64>()
            + 9;
        let s_b: u64 = std::fs::metadata(card_b.join("B002_002/f1.DNG"))
            .unwrap()
            .len()
            + 12;
        let block = |src: &Path, d: &Path, s: u64| {
            format!(
                "## copy — source: {src}\n\nclip\tfiles\tsource B\n{a001}\t2\t{s1}\nS001_001\t1\t9\ntotals: 3 file(s) — {s} B\n\noffload: VERIFIED 3/3 (source {src}, dest {d})\n",
                src = src.display(),
                d = d.display(),
                s1 = s - 9,
                a001 = "A001_001",
            )
        };
        let block_b = |src: &Path, d: &Path| {
            format!(
                "## copy — source: {src}\n\nclip\tfiles\tsource B\nB002_002\t1\t{s1}\nT001_001\t1\t12\ntotals: 2 file(s) — {s} B\n\noffload: VERIFIED 2/2 (source {src}, dest {d})\n",
                src = src.display(),
                d = d.display(),
                s1 = s_b - 12,
                s = s_b,
            )
        };
        for (d, other) in [(d1.clone(), d2c.clone()), (d2.clone(), d1c.clone())] {
            let tr = read_report(&d);
            // The identical content at every dest root.
            let tr_other = read_report(&other);
            assert_eq!(tr, tr_other, "the run report carries the WHOLE job — the same content at every dest root");
            assert_eq!(
                tr.lines().filter(|l| l.starts_with("created: ")).count(),
                1,
                "exactly ONE created: line (the job's single creation instant): {tr}"
            );
            let created = tr
                .lines()
                .find(|l| l.starts_with("created: "))
                .unwrap()
                .to_string();
            let host = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
            let expected = format!(
                "# frameprism offload run report — 2 source(s)\n\n{created}\ntool: frameprism {}\nhost: {host}\ninput: {a}\ninput: {b}\nclips: 4 · files: 5\n\n### source: {a}\n\nA001_001: profiled a001-sigma-fp (profile v1)\nS001_001: non-DNG media\n\n### source: {b}\n\nB002_002: unprofiled camera TEST MAKE TEST MODEL\nT001_001: non-DNG media\n\n### destination: {d1}\n\n{ba1}\n{bb1}\n### destination: {d2}\n\n{ba2}\n{bb2}",
                env!("CARGO_PKG_VERSION"),
                host = host,
                a = card_a.display(),
                b = card_b.display(),
                d1 = d1c.display(),
                d2 = d2c.display(),
                ba1 = block(&card_a, &d1c, s_a),
                bb1 = block_b(&card_b, &d1c),
                ba2 = block(&card_a, &d2c, s_a),
                bb2 = block_b(&card_b, &d2c),
            );
            assert_eq!(
                tr, expected,
                "the exact multi-shape run report rendering (the free lines normalized — created: + host:): {d:?}"
            );
        }
        // The job report at each dest (the multi-shape — the session's
        // 2 `input:` lines, the CSV header EXACTLY the pinned header, the
        // `source` column's values = the sources as given, the
        // per-pair verdict lines, the per-clip tables' `source`
        // column after `file`).
        for (d, dc) in [(d1.clone(), d1c.clone()), (d2.clone(), d2c.clone())] {
            let csv = std::fs::read_to_string(d.join(crate::jobreport::CSV_NAME)).unwrap();
            let lines: Vec<&str> = csv.lines().collect();
            assert_eq!(
                lines[0],
                "clip,file,size_bytes,source_sha256,dest_sha256,verdict,source,skipped,copied_ms",
                "the CSV header pin (the `source` column after `verdict` — the prefix verbatim)"
            );
            // The row order (the sorted union clip-key order: the
            // source order within a clip) → the `source` column's
            // values (index 6): cardA, cardA, cardB, cardA, cardB.
            let src_values: Vec<&str> = lines[1..]
                .iter()
                .map(|l| l.split(',').nth(6).unwrap())
                .collect();
            assert_eq!(
                src_values,
                vec![
                    card_a.display().to_string().as_str(),
                    card_a.display().to_string().as_str(),
                    card_b.display().to_string().as_str(),
                    card_a.display().to_string().as_str(),
                    card_b.display().to_string().as_str(),
                ],
                "the source column's values = the sources as given (the deterministic row order)"
            );
            let md = std::fs::read_to_string(d.join(crate::jobreport::MD_NAME)).unwrap();
            assert!(
                md.contains(&format!("input: {}\n", card_a.display())),
                "the session's input line (cardA as given): {d:?}\n{md}"
            );
            assert!(
                md.contains(&format!("input: {}\n", card_b.display())),
                "the session's input line (cardB as given): {d:?}\n{md}"
            );
            assert!(
                md.contains(&format!("offload: VERIFIED 3/3 (source {}, dest {})", card_a.display(), dc.display())),
                "the per-pair verdict line (cardA — the multi-form): {d:?}\n{md}"
            );
            assert!(
                md.contains(&format!("offload: VERIFIED 2/2 (source {}, dest {})", card_b.display(), dc.display())),
                "the per-pair verdict line (cardB — the multi-form): {d:?}\n{md}"
            );
            assert!(
                md.contains("| file | source | size | source_sha256 | dest_sha256 | verdict | skipped | copied_ms |"),
                "the per-clip table's `source` column after `file`: {d:?}\n{md}"
            );
        }
        // The ascmhl at each dest: exactly ONE 0001 generation + the
        // chain; the per-entry set covers BOTH sources' entries (the
        // ignore set — the offload manifests / the run report / the
        // job reports / the ascmhl's own artifacts are NOT records).
        for (d, dest_name) in [(d1.clone(), "to1"), (d2.clone(), "to2")] {
            let ascmhl_dir = d.join("ascmhl");
            let mut names: Vec<String> = std::fs::read_dir(&ascmhl_dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            assert_eq!(names.len(), 2, "the manifest + the chain: {names:?}");
            let manifest_name = names.iter().find(|n| n.ends_with(".mhl")).unwrap().clone();
            assert!(names.contains(&"ascmhl_chain.xml".to_string()), "the chain");
            let prefix = format!("0001_{dest_name}_");
            assert!(
                manifest_name.starts_with(&prefix) && manifest_name.ends_with(".mhl"),
                "the 0001 numbering + the dest's basename: {manifest_name}"
            );
            let xml = std::fs::read_to_string(ascmhl_dir.join(&manifest_name)).unwrap();
            let root = crate::ascmhl::parse_lite(&xml).expect("the manifest is well-formed");
            let hashes = &root.children[2];
            assert_eq!(hashes.name, "hashes");
            let mut entries: Vec<String> = hashes
                .children
                .iter()
                .map(|e| {
                    e.children
                        .first()
                        .map(|p| p.text.trim().to_string())
                        .expect("the hash entry's <path> child")
                })
                .collect();
            entries.sort();
            assert_eq!(
                entries,
                vec![
                    String::from("A001_001"),
                    String::from("A001_001/f1.DNG"),
                    String::from("A001_001/f2.DNG"),
                    String::from("B002_002"),
                    String::from("B002_002/f1.DNG"),
                    String::from("S001_001"),
                    String::from("S001_001/clip.wav"),
                    String::from("T001_001"),
                    String::from("T001_001/clip.wav"),
                ],
                "the merged media set (BOTH sources' entries): {d:?}"
            );
        }
        // The 4 pair lines EXACT + the job-level line EXACT
        // — the pure composition (the rendering is pure, the test
        // asserts the exact lines).
        let o1 = SourceOutcome {
            source: PathBuf::from("/cardA"),
            detection: None,
            core: Some(OffloadCoreMulti {
                reports: vec![
                    OffloadReport { input: PathBuf::from("/cardA"), dest: PathBuf::from("/d1"), rows: vec![row_ok("a"), row_ok("b"), row_ok("c")], clips: vec![] },
                    OffloadReport { input: PathBuf::from("/cardA"), dest: PathBuf::from("/d2"), rows: vec![row_ok("a"), row_ok("b"), row_ok("c")], clips: vec![] },
                ],
                copied_ms: vec![vec![1, 1, 1], vec![1, 1, 1]],
                skipped: vec![vec![false; 3], vec![false; 3]],
                per_clip: vec![],
            }),
            failure: None,
        };
        let o2 = SourceOutcome {
            source: PathBuf::from("/cardB"),
            detection: None,
            core: Some(OffloadCoreMulti {
                reports: vec![
                    OffloadReport { input: PathBuf::from("/cardB"), dest: PathBuf::from("/d1"), rows: vec![row_ok("d"), row_ok("e")], clips: vec![] },
                    OffloadReport { input: PathBuf::from("/cardB"), dest: PathBuf::from("/d2"), rows: vec![row_ok("d"), row_ok("e")], clips: vec![] },
                ],
                copied_ms: vec![vec![1, 1], vec![1, 1]],
                skipped: vec![vec![false; 2], vec![false; 2]],
                per_clip: vec![],
            }),
            failure: None,
        };
        assert_eq!(
            multi_stderr_lines(&[o1, o2], &[PathBuf::from("/d1"), PathBuf::from("/d2")], 2),
            vec![
                "offload: VERIFIED 3/3 (source /cardA, dest /d1)".to_string(),
                "offload: VERIFIED 3/3 (source /cardA, dest /d2)".to_string(),
                "offload: VERIFIED 2/2 (source /cardB, dest /d1)".to_string(),
                "offload: VERIFIED 2/2 (source /cardB, dest /d2)".to_string(),
                "offload: VERIFIED 10/10 (2 source(s) × 2 dest(s))".to_string(),
            ],
            "the 4 pair lines + the job-level line (the totals across pairs) — the exact composition"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The 1-source flag form (the single-source MULTI-shape, CLI-reachable incl. single-dest:
    /// `offload --source s1 --dest d1`): rc=0; the run report is the
    /// multi-shape (the `### source:` section, the `dest:` line —
    /// N=1 — the `## copy — source:` blocks following the source
    /// sections directly — no `### destination:` section — the pair
    /// line WITH the source slot); the job-level `1 source(s) × 1
    /// dest(s)` line (the uniform rendering — the assertion that
    /// overrides the `ONLY when M>1` clause); asserted NOT
    /// byte-equal to the legacy positional rendering (the documented
    /// multi-shape lines differ).
    #[test]
    fn offload_multi_1source_flag_form() {
        profile_override_a001();
        let (base, card_a, _card_b) = multi_trees("flagsingle");
        let d1 = base.join("to1");
        let rc = run(&multi_args(vec![card_a.clone()], vec![d1.clone()]));
        assert_eq!(rc, ExitCode::SUCCESS, "the clean pair = rc 0");
        let d1c = std::fs::canonicalize(&d1).unwrap();
        let tr = read_report(&d1);
        assert!(
            tr.starts_with("# frameprism offload run report — 1 source(s)\n\n"),
            "the multi title (M=1 renders `1 source(s)` — the uniform rendering, no singular special case): {tr}"
        );
        assert_eq!(
            tr.lines().filter(|l| l.starts_with("created: ")).count(),
            1,
            "exactly ONE created: line: {tr}"
        );
        assert!(
            tr.contains(&format!("dest: {}\n", d1c.display())),
            "the N=1 `dest:` line (the canonical dest): {tr}"
        );
        assert!(!tr.contains("### destination: "), "no per-dest sections at N=1: {tr}");
        assert!(
            tr.contains(&format!("### source: {}\n", card_a.display())),
            "the ### source: section: {tr}"
        );
        assert!(
            tr.contains(&format!("## copy — source: {}\n", card_a.display())),
            "the ## copy — source: block (the multi header): {tr}"
        );
        assert!(
            tr.contains(&format!("offload: VERIFIED 3/3 (source {}, dest {})\n", card_a.display(), d1c.display())),
            "the pair line WITH the source slot (the multi-form): {tr}"
        );
        // The job-level `1 source(s) × 1 dest(s)` line (the uniform
        // multi-shape — the pure-composition assertion, the
        // idiom).
        let o = SourceOutcome {
            source: PathBuf::from("/s"),
            detection: None,
            core: Some(OffloadCoreMulti {
                reports: vec![OffloadReport {
                    input: PathBuf::from("/s"),
                    dest: PathBuf::from("/d"),
                    rows: vec![row_ok("a"), row_ok("b"), row_ok("c")],
                    clips: vec![],
                }],
                copied_ms: vec![vec![1, 1, 1]],
                skipped: vec![vec![false; 3]],
                per_clip: vec![],
            }),
            failure: None,
        };
        assert_eq!(
            multi_stderr_lines(std::slice::from_ref(&o), std::slice::from_ref(&PathBuf::from("/d")), 1),
            vec![
                "offload: VERIFIED 3/3 (source /s, dest /d)".to_string(),
                "offload: VERIFIED 3/3 (1 source(s) × 1 dest(s))".to_string(),
            ],
            "the M=1 job-level line (the uniform rendering)"
        );
        // The NOT-byte-equal proof: the legacy positional rendering
        // of the SAME source to a legacy dest differs from the
        // multi-shape rendering (the documented multi-shape lines
        // differ — the `## copy` vs `## copy — source:` blocks, the
        // pair line's source slot, the multi title, the per-source
        // sections).
        let d_leg = base.join("legacy");
        let rc_leg = run_offload_multi(&std::fs::canonicalize(&card_a).unwrap(), &[d_leg.clone()]).unwrap();
        assert_eq!(rc_leg, ExitCode::SUCCESS, "the legacy clean run");
        let tr_leg = read_report(&d_leg);
        assert_ne!(tr, tr_leg, "the multi-shape rendering is NOT byte-equal to the legacy rendering");
        assert!(
            tr_leg.contains("## copy\n"),
            "the legacy `## copy` block (no source slot): {tr_leg}"
        );
        assert!(!tr.contains("\n## copy\n"), "the multi-shape has no legacy `## copy` block: {tr}");
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The dirty sweep: one pair dirtied (a dest mirror
    /// path pre-created as a DIRECTORY where a source file must land
    /// → the COPY_FAIL band): rc=1; the pair lines (3 VERIFIED + 1
    /// REFUSE with the pair slots); the OFFLOAD FAIL line names the
    /// pair (the template — the existing format + the source
    /// slot); the job-level REFUSE line with the dirty total; the
    /// OTHER 3 pairs' mirrors complete (the sweep — no pair is
    /// stopped by another's failure).
    #[test]
    fn offload_multi_dirty_sweep() {
        profile_override_a001();
        let (base, card_a, card_b) = multi_trees("dirtysweep");
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        // The pre-write bands pass (the probes create the dest roots)
        // …
        std::fs::create_dir_all(&d1).unwrap();
        std::fs::create_dir_all(&d2).unwrap();
        // … then d2's f1.DNG mirror path is occupied by a DIR (the
        // existing COPY_FAIL idiom): the (cardA, d2) pair's named
        // row — the other 3 pairs stay clean (the sweep).
        std::fs::create_dir_all(d2.join("A001_001/f1.DNG")).unwrap();
        let rc = run(&multi_args(
            vec![card_a.clone(), card_b.clone()],
            vec![d1.clone(), d2.clone()],
        ));
        assert_eq!(rc, ExitCode::from(1), "any dirty pair = rc 1 AFTER the run");
        let d1c = std::fs::canonicalize(&d1).unwrap();
        let d2c = std::fs::canonicalize(&d2).unwrap();
        // The (cardA, d2) pair: the named row (the reverify surface —
        // the existing format; the other 2 rows stand at d2).
        let m = crate::offload::parse_manifest(&d2c.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
        let (l, bad) = crate::offload::reverify(&m);
        assert_eq!(bad, 1, "exactly the named row: {l:?}");
        assert!(
            l.iter().any(|line| line.starts_with("FAIL offload A001_001/f1.DNG")),
            "the named row (the existing reverify format): {l:?}"
        );
        assert_eq!(
            std::fs::read(d2c.join("A001_001/f2.DNG")).unwrap(),
            std::fs::read(card_a.join("A001_001/f2.DNG")).unwrap(),
            "the clean rows stand at d2 (the sweep within the pair)"
        );
        // The OTHER 3 pairs' mirrors complete (the sweep — no pair is
        // stopped by another's failure): cardA's clean pair at d1 +
        // cardB's both pairs.
        for rel in ["A001_001/f1.DNG", "A001_001/f2.DNG", "S001_001/clip.wav"] {
            assert_eq!(
                std::fs::read(d1c.join(rel)).unwrap(),
                std::fs::read(card_a.join(rel)).unwrap(),
                "cardA's clean pair at d1: {rel}"
            );
        }
        for rel in ["B002_002/f1.DNG", "T001_001/clip.wav"] {
            for d in [&d1c, &d2c] {
                assert_eq!(
                    std::fs::read(d.join(rel)).unwrap(),
                    std::fs::read(card_b.join(rel)).unwrap(),
                    "cardB's pairs at {d:?}: {rel}"
                );
            }
        }
        // The run report (carries the WHOLE job — the dirty pair's
        // section: the `## failures` section + the named FAIL line
        // (the existing format) + the pair's REFUSE line (the count
        // named — the multi-form with the pair slots)).
        let tr = read_report(&d1);
        assert!(
            tr.contains("FAIL COPY_FAIL clip=A001_001: A001_001/f1.DNG"),
            "the dirty pair's named FAIL line (the existing format): {tr}"
        );
        assert!(
            tr.contains(&format!("offload: REFUSE 1 named row(s) (source {}, dest {})\n", card_a.display(), d2c.display())),
            "the dirty pair's REFUSE line (the count named — the pair slots): {tr}"
        );
        assert!(
            tr.contains(&format!("offload: VERIFIED 3/3 (source {}, dest {})\n", card_a.display(), d1c.display())),
            "cardA's clean pair at d1 (every pair named): {tr}"
        );
        assert!(tr.contains("## failures"), "the failures section under the dirty pair's block: {tr}");
        // The stderr composition EXACT (the template — the
        // existing formats + the source slot + the job-level REFUSE
        // line — the pure-composition assertion).
        let o1 = SourceOutcome {
            source: PathBuf::from("/cardA"),
            detection: None,
            core: Some(OffloadCoreMulti {
                reports: vec![
                    OffloadReport { input: PathBuf::from("/cardA"), dest: PathBuf::from("/d1"), rows: vec![row_ok("a"), row_ok("b")], clips: vec![] },
                    OffloadReport { input: PathBuf::from("/cardA"), dest: PathBuf::from("/d2"), rows: vec![row_ok("a"), row_ok("b"), row_fail("c")], clips: vec![] },
                ],
                copied_ms: vec![vec![1, 1], vec![1, 1, 1]],
                skipped: vec![vec![false; 2], vec![false; 3]],
                per_clip: vec![],
            }),
            failure: None,
        };
        let o2 = SourceOutcome {
            source: PathBuf::from("/cardB"),
            detection: None,
            core: Some(OffloadCoreMulti {
                reports: vec![
                    OffloadReport { input: PathBuf::from("/cardB"), dest: PathBuf::from("/d1"), rows: vec![row_ok("d")], clips: vec![] },
                    OffloadReport { input: PathBuf::from("/cardB"), dest: PathBuf::from("/d2"), rows: vec![row_ok("d")], clips: vec![] },
                ],
                copied_ms: vec![vec![1], vec![1]],
                skipped: vec![vec![false; 1], vec![false; 1]],
                per_clip: vec![],
            }),
            failure: None,
        };
        assert_eq!(
            multi_stderr_lines(&[o1, o2], &[PathBuf::from("/d1"), PathBuf::from("/d2")], 2),
            vec![
                "offload: VERIFIED 2/2 (source /cardA, dest /d1)".to_string(),
                "FAIL COPY_FAIL clip=.: c: no space left".to_string(),
                "OFFLOAD FAIL — 1 dirty row(s) (source /cardA, dest /d2): the named FAIL lines above (the verify-before-wipe gate holds: the source tree is reusable only after all 2 dests verify clean)".to_string(),
                "offload: VERIFIED 1/1 (source /cardB, dest /d1)".to_string(),
                "offload: VERIFIED 1/1 (source /cardB, dest /d2)".to_string(),
                "offload: REFUSE 1 named row(s) (2 source(s) × 2 dest(s))".to_string(),
            ],
            "the dirty sweep's exact stderr (the template + the job-level REFUSE line)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The phase-0 + form bands (each: rc=2, the named
    /// line verbatim, ZERO files written to any dest — the
    /// created-empty-dest-dir refusal). The form
    /// bands ride `settle_form`'s pure seam (the exact line
    /// assertion); the phase-0 bands ride
    /// `run_offload_multi_sources`'s `Err` seam (the named `Err` —
    /// the `run` wrapper eprints + maps to rc=2).
    #[test]
    fn offload_multi_refusals() {
        profile_override_a001();
        let (base, card_a, _card_b) = multi_trees("refusals");
        let sa = std::fs::canonicalize(&card_a).unwrap();
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        // The zero-files assertion (the created-empty-dest-dir band:
        // the dests may exist as empty dirs — NO files anywhere at
        // the dest roots).
        let zero_files = || {
            for dest in [&d1, &d2] {
                if dest.is_dir() {
                    for entry in std::fs::read_dir(dest).unwrap() {
                        let e = entry.unwrap();
                        assert!(
                            !e.path().is_file(),
                            "zero files written to the dest root: {:?}",
                            e.path()
                        );
                    }
                }
            }
        };
        // (a) `--source` given AND the positional input given (the
        // EXISTING wording verbatim — the band (i) shape).
        let err = settle_form(&Args {
            input: Some(base.join("positional")),
            source: vec![card_a.clone()],
            dest: vec![d1.clone()],
            to: vec![],
        })
        .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "the sources are named once: either the positional input (the single-source form) or --source (the multi-source form) — not both",
            "the band (i) line verbatim"
        );
        // (b) neither given (the bare `offload` — the wording).
        let err = settle_form(&Args {
            input: None,
            source: vec![],
            dest: vec![],
            to: vec![],
        })
        .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "the offload needs a source: the positional input (the single-source form) or --source (the multi-source form)",
            "the band (b) line verbatim"
        );
        // (h) `--dest` given AND the positional input given (the
        // band (ii) shape — the new guard).
        let err = settle_form(&Args {
            input: Some(base.join("positional")),
            source: vec![],
            dest: vec![d1.clone()],
            to: vec![base.join("positional-to")],
        })
        .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "the dests are named once: either the positional dests (the single-source form) or --dest (the multi-source form) — not both",
            "the band (ii) line verbatim"
        );
        // (i) `--source` given AND `--dest` absent (the band (iii)
        // shape).
        let err = settle_form(&Args {
            input: None,
            source: vec![card_a.clone()],
            dest: vec![],
            to: vec![],
        })
        .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "the multi-source form names its dests with --dest (the positional dests are the single-source form's)",
            "the band (iii) line verbatim"
        );
        // (j) `--dest` given AND `--source` absent (the band (iv)
        // shape).
        let err = settle_form(&Args {
            input: None,
            source: vec![],
            dest: vec![d1.clone()],
            to: vec![],
        })
        .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "--dest names the multi-source form's dests (the single-source form names its input positionally)",
            "the band (iv) line verbatim"
        );
        zero_files();
        // (c) The nested sources (one source inside the
        // other: the mirror semantics are undefined).
        let nested = base.join("nested");
        let inner = nested.join("inner");
        std::fs::create_dir_all(inner.join("N001_001")).unwrap();
        std::fs::write(inner.join("N001_001/f1.DNG"), b"nested-frame").unwrap();
        let err = run_offload_multi_sources(&[nested.clone(), inner.clone()], &[d1.clone()])
            .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "the offload sources {} and {} are nested (one is inside the other) — the mirror semantics are undefined; name the sources at the same level",
                nested.display(),
                inner.display()
            ),
            "the nested-source refusal verbatim (the sources as given)"
        );
        zero_files();
        // (d) The cross-source top-level name collision (a
        // clip dir present in BOTH sources: the offload refuses to
        // merge two sources' entries under one name).
        let ca = base.join("cardX");
        let cb = base.join("cardY");
        std::fs::create_dir_all(ca.join("A001_001")).unwrap();
        std::fs::create_dir_all(cb.join("A001_001")).unwrap();
        std::fs::write(ca.join("A001_001/f1.DNG"), b"x-frame").unwrap();
        std::fs::write(cb.join("A001_001/f1.DNG"), b"y-frame").unwrap();
        let err = run_offload_multi_sources(&[ca.clone(), cb.clone()], &[d1.clone()])
            .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "the clip dir/file A001_001 is present in both offload sources {} and {} — the offload refuses to merge two sources' entries under one dest (rename the clip dirs on one card)",
                ca.display(),
                cb.display()
            ),
            "the cross-source collision refusal verbatim (the sources as given)"
        );
        zero_files();
        // (e) The self-mirror pair (the existing guard wording names
        // the pair — source A == dest 2, dest 1 clean).
        let err = run_offload_multi_sources(&[sa.clone()], &[d1.clone(), sa.clone()])
            .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "the offload input {} and dest {} are the same dir (the mirror would copy every file onto itself — name a distinct dest)",
                sa.display(),
                sa.display()
            ),
            "the per-pair self-mirror guard verbatim (the pair named)"
        );
        zero_files();
        // (f) The duplicate dest (the existing refusal, unchanged
        // wording — the canonicalized-path equality).
        let err = run_offload_multi_sources(&[sa.clone()], &[d1.clone(), d1.clone()])
            .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "the offload dests {} and {} are the same dir (a duplicate dest — name each dest once; the fan-out refuses the duplicate, it does not silently dedupe it)",
                d1.display(),
                d1.display()
            ),
            "the duplicate-dest refusal verbatim (unchanged wording)"
        );
        zero_files();
        // (g) The shared source basename (the
        // source-root manifest name: two sources whose
        // CANONICALIZED basenames are exact-equal; (d)/(e) both
        // pass — distinct paths, distinct top-level entries).
        let a_card = base.join("a").join("card");
        let b_card = base.join("b").join("card");
        std::fs::create_dir_all(a_card.join("M001_001")).unwrap();
        std::fs::create_dir_all(b_card.join("K001_001")).unwrap();
        std::fs::write(a_card.join("M001_001/f1.DNG"), b"a-frame").unwrap();
        std::fs::write(b_card.join("K001_001/f1.DNG"), b"b-frame").unwrap();
        let err = run_offload_multi_sources(&[a_card.clone(), b_card.clone()], &[d1.clone()])
            .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!(
                "the offload sources {} and {} share the source-root manifest name card (both sources' basenames are card) — the source-root offload manifests would collide at the dest roots; name the source dirs distinctly",
                a_card.display(),
                b_card.display()
            ),
            "the shared source-basename refusal verbatim (the sources as given, the common basename)"
        );
        zero_files();
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The re-run append: the 2-source job run twice
    /// onto the same dests: the ascmhl 0002 APPEND (the 0001 record
    /// byte-preserved), the manifests rewritten
    /// idempotently, the media byte-identical.
    #[test]
    fn offload_multi_rerun_append() {
        profile_override_a001();
        let (base, card_a, card_b) = multi_trees("rerun");
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        let sources = vec![card_a.clone(), card_b.clone()];
        let dests = vec![d1.clone(), d2.clone()];
        let rc1 = run(&multi_args(sources.clone(), dests.clone()));
        assert_eq!(rc1, ExitCode::SUCCESS, "the first job");
        // The 0001 manifest's bytes (before the re-run — the
        // byte-preserved proof) + the media bytes.
        let mhl_0001 = |d: &Path| -> (String, Vec<u8>) {
            let dir = d.join("ascmhl");
            let name = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .into_iter()
                .find(|n| n.starts_with("0001_"))
                .expect("the 0001 manifest");
            let bytes = std::fs::read(dir.join(&name)).unwrap();
            (name, bytes)
        };
        let (name1, bytes1) = mhl_0001(&d1);
        let (name2, bytes2) = mhl_0001(&d2);
        let media = |d: &Path| -> Vec<(String, Vec<u8>)> {
            [
                "A001_001/f1.DNG",
                "A001_001/f2.DNG",
                "S001_001/clip.wav",
                "B002_002/f1.DNG",
                "T001_001/clip.wav",
            ]
            .iter()
            .map(|rel| (rel.to_string(), std::fs::read(d.join(rel)).unwrap()))
            .collect()
        };
        let media1 = media(&d1);
        let media2 = media(&d2);
        // The second job (the re-run onto the same dests).
        let rc2 = run(&multi_args(sources, dests));
        assert_eq!(rc2, ExitCode::SUCCESS, "the re-run");
        for (d, pre_name, pre_bytes) in [(d1.clone(), name1, bytes1), (d2.clone(), name2, bytes2)] {
            let dir = d.join("ascmhl");
            let mut names: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            assert_eq!(names.len(), 3, "the 0001 + the 0002 + the chain: {names:?}");
            // The 0001 record BYTE-PRESERVED (the re-run APPENDS the 0002 generation; it never rewrites
            // the 0001).
            assert_eq!(
                std::fs::read(dir.join(&pre_name)).unwrap(),
                pre_bytes,
                "the 0001 record byte-preserved: {d:?}"
            );
            assert!(
                names.iter().any(|n| n.starts_with("0002_")),
                "the 0002 append: {names:?}"
            );
        }
        // The media byte-identical (the idempotent re-run) + the
        // manifests rewritten idempotently (the reverify surface —
        // the clean rows re-verify).
        assert_eq!(media(&d1), media1, "d1's media byte-identical");
        assert_eq!(media(&d2), media2, "d2's media byte-identical");
        for d in [&d1, &d2] {
            let dc = std::fs::canonicalize(d).unwrap();
            let m = crate::offload::parse_manifest(&dc.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
            let (_, bad) = crate::offload::reverify(&m);
            assert_eq!(bad, 0, "the rewritten manifest re-verifies clean: {d:?}");
        }
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The named source-thread failure (the directed
    /// seam: a source DNG file chmod-000 between the
    /// walk and the read — the detection scan degrades the
    /// unreadable sample to the `unprofiled camera - -` line (the
    /// report, not a gate — the stderr note), then the core's
    /// `std::fs::read` fails (Permission denied) → the named source
    /// failure: the `OFFLOAD FAIL — source <in>: …` line + rc=1 +
    /// the OTHER source's pair lines VERIFIED (the sweep) + the tail
    /// renders the failed source's `source failed:` block (the
    /// pinned wording).
    #[test]
    fn offload_multi_thread_failure_named() {
        profile_override_a001();
        let (base, card_a, card_b) = multi_trees("threadfail");
        // The directed seam: cardA's DNG chmod-000 (the read fails —
        // the detection degrades, the core's read refuses named).
        let victim = card_a.join("A001_001/f1.DNG");
        std::fs::write(&victim, b"locked-frame").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        let rc = run(&multi_args(
            vec![card_a.clone(), card_b.clone()],
            vec![d1.clone(), d2.clone()],
        ));
        assert_eq!(rc, ExitCode::from(1), "a source-thread failure = rc 1");
        let d1c = std::fs::canonicalize(&d1).unwrap();
        // The failed source: NO copy (the core refused before the
        // first write — the dest tree carries no cardA entry).
        assert!(!d1c.join("A001_001").exists(), "cardA's mirror is absent (the failure is before any copy)");
        assert!(!d1c.join("S001_001").exists(), "cardA's sidecar clip is absent (the failure is before any copy)");
        // The OTHER source's pairs complete (the sweep — the named
        // line + the pair lines VERIFIED).
        let d2c = std::fs::canonicalize(&d2).unwrap();
        for d in [&d1c, &d2c] {
            assert_eq!(
                std::fs::read(d.join("B002_002/f1.DNG")).unwrap(),
                std::fs::read(card_b.join("B002_002/f1.DNG")).unwrap(),
                "cardB's mirror stands: {d:?}"
            );
        }
        // The tail renders the failed source's `source failed:` block
        // (the pinned wording — the deterministic refusal
        // rendering, no table): the `### source:` section's line +
        // the copy block's line (the named error carries the core's
        // read refusal).
        let tr = read_report(&d1);
        assert!(
            tr.contains(&format!("### source: {}\n\nsource failed: ", card_a.display())),
            "the ### source: section's named failure line: {tr}"
        );
        assert!(
            tr.contains("re-scan the offload source"),
            "the named error carries the core's read refusal: {tr}"
        );
        assert!(
            tr.contains(&format!("## copy — source: {}\n\nsource failed: ", card_a.display())),
            "the copy block's named failure line (the deterministic refusal rendering, no table): {tr}"
        );
        // The completed source's pair lines stand (the sweep — the
        // pair slots).
        assert!(
            tr.contains(&format!("offload: VERIFIED 2/2 (source {}, dest {})", card_b.display(), d1c.display())),
            "cardB's pair line VERIFIED (the sweep): {tr}"
        );
        // The named line's exact shape (the pure-composition
        // assertion): `OFFLOAD FAIL — source <in>:
        // <the named error>` at the source's given-order position.
        let o_fail = SourceOutcome {
            source: PathBuf::from("/cardA"),
            detection: None,
            core: None,
            failure: Some(
                "the offload of /cardA to 2 dest(s): re-scan the offload source /cardA/A001_001/f1.DNG: Permission denied (os error 13)".to_string(),
            ),
        };
        let o_ok = SourceOutcome {
            source: PathBuf::from("/cardB"),
            detection: None,
            core: Some(OffloadCoreMulti {
                reports: vec![
                    OffloadReport { input: PathBuf::from("/cardB"), dest: PathBuf::from("/d1"), rows: vec![row_ok("d")], clips: vec![] },
                    OffloadReport { input: PathBuf::from("/cardB"), dest: PathBuf::from("/d2"), rows: vec![row_ok("d")], clips: vec![] },
                ],
                copied_ms: vec![vec![1], vec![1]],
                skipped: vec![vec![false; 1], vec![false; 1]],
                per_clip: vec![],
            }),
            failure: None,
        };
        assert_eq!(
            multi_stderr_lines(&[o_fail, o_ok], &[PathBuf::from("/d1"), PathBuf::from("/d2")], 2),
            vec![
                "OFFLOAD FAIL — source /cardA: the offload of /cardA to 2 dest(s): re-scan the offload source /cardA/A001_001/f1.DNG: Permission denied (os error 13)".to_string(),
                "offload: VERIFIED 1/1 (source /cardB, dest /d1)".to_string(),
                "offload: VERIFIED 1/1 (source /cardB, dest /d2)".to_string(),
                "offload: VERIFIED 2/2 (2 source(s) × 2 dest(s))".to_string(),
            ],
            "the named source failure's exact line (the sweep — the completed pairs' lines stand)"
        );
        // The cleanup (the chmod-000 file — the dir's permissions
        // stand, the removal is fine).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).ok();
        }
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The legacy positional form FROZEN (the legacy-shape anchor
    /// in-suite): the legacy 3-clip × 2-dest run (no flags — the
    /// single-source form): the run report + the per-clip manifests
    /// EXACT per the rendering contract (the test normalizes only
    /// the documented free lines — the `created:` stamps, the
    /// `host:` line, the `profiles:` line); the job report's
    /// legacy-shape session + the legacy verdict lines; the rc.
    /// (The stderr line set = the pure `fanout_stderr_lines`
    /// composition over the legacy reports; the
    /// ascmhl bytes = the baseline capture of the pre-job-report
    /// binary's renderings.)
    #[test]
    fn offload_legacy_frozen() {
        profile_override_a001();
        let (base, input) = standalone_tree("legacyfrozen");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        let rc = run_offload_multi(&input_c, &[d1.clone(), d2.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "the legacy clean run = rc 0");
        let d1c = std::fs::canonicalize(&d1).unwrap();
        let d2c = std::fs::canonicalize(&d2).unwrap();
        // The run report (N>1 legacy shape) — the EXACT rendering
        // (the free lines normalized: `created:` + the `profiles:`
        // line extracted from the rendering, the `host:` line built
        // — the documented free set).
        let tr = read_report(&d1);
        let tr2 = read_report(&d2);
        assert_eq!(tr, tr2, "the legacy run report carries the WHOLE run — the same content at every dest root");
        assert_eq!(
            tr.lines().filter(|l| l.starts_with("created: ")).count(),
            1,
            "exactly one created: line: {tr}"
        );
        let created = tr.lines().find(|l| l.starts_with("created: ")).unwrap().to_string();
        let profiles = tr.lines().find(|l| l.starts_with("profiles: ")).unwrap().to_string();
        let host = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
        let s_a: u64 = std::fs::metadata(input.join("A001_001/f1.DNG")).unwrap().len() + 9 + 7;
        let s_b: u64 = std::fs::metadata(input.join("B002_002/f1.DNG")).unwrap().len();
        let s_root: u64 =
            std::fs::metadata(input.join("root.wav")).unwrap().len()
                + std::fs::metadata(input.join("manifest.tsv")).unwrap().len();
        let s_c: u64 = std::fs::metadata(input.join("C003_003/clip.wav")).unwrap().len();
        let s_tot: u64 = s_root + s_a + s_b + s_c;
        let copy = format!(
            "## copy\n\nclip\tfiles\tsource B\n.\t2\t{s_root}\nA001_001\t3\t{s_a}\nB002_002\t1\t{s_b}\nC003_003\t1\t{s_c}\ntotals: 7 file(s) — {s_tot} B",
        );
        let expected = format!(
            "# frameprism offload run report — in\n\n{created}\ntool: frameprism {}\nhost: {host}\ninput: {in}\n{profiles}\nclips: 4 · files: 7\n\n## detection\n\n.: non-DNG media\nA001_001: profiled a001-sigma-fp (profile v1)\nB002_002: unprofiled camera TEST MAKE TEST MODEL\nC003_003: non-DNG media\n\n### destination: {d1}\n\n{copy}\n\noffload: VERIFIED 7/7 (dest {d1})\n\n### destination: {d2}\n\n{copy}\n\noffload: VERIFIED 7/7 (dest {d2})\n",
            env!("CARGO_PKG_VERSION"),
            in = input_c.display(),
            d1 = d1c.display(),
            d2 = d2c.display(),
        );
        assert_eq!(
            tr, expected,
            "the legacy run report's EXACT rendering (the free lines normalized — created: + host: + profiles:): {d1:?}"
        );
        // The per-clip manifests (the legacy placement — the
        // mirrored clip roots + the dest root's `in` name) — the
        // EXACT rendering (the free lines normalized: the
        // `created:` stamps + the `host:` line; the input/dest
        // paths + the rows' shas are deterministic — the shas
        // computed over the fixture bytes).
        for (d, dc) in [(d1.clone(), d1c.clone()), (d2.clone(), d2c.clone())] {
            for (clip, rows) in [
                ("A001_001", vec!["A001_001/SPP_metadata.xmp", "A001_001/clip.wav", "A001_001/f1.DNG"]),
                ("B002_002", vec!["B002_002/f1.DNG"]),
                ("C003_003", vec!["C003_003/clip.wav"]),
                ("", vec!["manifest.tsv", "root.wav"]),
            ] {
                let name = if clip.is_empty() { "in" } else { clip };
                let path = if clip.is_empty() {
                    d.join("in.offload-manifest.tsv")
                } else {
                    d.join(clip).join(format!("{clip}.offload-manifest.tsv"))
                };
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|err| panic!("the per-clip manifest {path:?}: {err}"));
                let lines: Vec<&str> = text.lines().collect();
                assert_eq!(lines[0], MANIFEST_MAGIC, "the magic line");
                assert_eq!(lines[1], "version: 1");
                assert_eq!(
                    lines[2],
                    &format!("clip: {name}"),
                    "the clip header (the root clip's name — the input's basename at the dest root)"
                );
                let created = lines[3];
                assert!(
                    created.starts_with("created: ") && created.ends_with(" (unix seconds, UTC)"),
                    "the created: line (the free line — normalized): {created}"
                );
                assert_eq!(lines[4], &format!("input: {}", input_c.display()));
                assert_eq!(lines[5], &format!("dest: {}", dc.display()));
                assert_eq!(lines[6], &format!("tool_version: {}", env!("CARGO_PKG_VERSION")));
                let host_line = lines[7];
                assert!(
                    host_line.starts_with("host: "),
                    "the host: line (the free line — normalized): {host_line}"
                );
                assert_eq!(lines[8], &format!("files: {}", rows.len()));
                assert_eq!(lines[9], "clips: 1");
                assert_eq!(lines[10], "file\tsize\tsource_sha256\tdest_sha256\tverdict");
                let row_start = 11;
                for (i, rel) in rows.iter().enumerate() {
                    let bytes = std::fs::read(input.join(rel)).unwrap();
                    let sha = crate::jxl::sha256_hex(&bytes);
                    let size = std::fs::metadata(input.join(rel)).unwrap().len();
                    assert_eq!(
                        lines[row_start + i],
                        &format!("{rel}\t{size}\t{sha}\t{sha}\tOK"),
                        "the row (the deterministic sha/size — the clean run)"
                    );
                }
                assert_eq!(lines[row_start + rows.len()], "# per-clip verdicts");
                let clip_cell = if clip.is_empty() { "(input root)" } else { clip };
                assert_eq!(
                    lines[row_start + rows.len() + 1],
                    &format!("clip: {clip_cell} files: {} ok: {} dirty: 0", rows.len(), rows.len())
                );
                assert_eq!(
                    lines[row_start + rows.len() + 2],
                    &format!("verdict: VERIFIED {}/{}", rows.len(), rows.len())
                );
            }
        }
        // The job report's legacy shape (the session's single
        // `input:` line + the legacy verdict lines — the `source`
        // column ABSENT — the legacy CSV header byte-frozen). Each
        // dest's md carries its OWN dest's verdict line (the
        // per-dest session's stderr block).
        for (d, dc) in [(d1.clone(), d1c.clone()), (d2.clone(), d2c.clone())] {
            let md = std::fs::read_to_string(d.join(crate::jobreport::MD_NAME)).unwrap();
            assert!(
                md.contains(&format!("input: {}\n", input_c.display())),
                "the legacy session's input line: {d:?}\n{md}"
            );
            assert_eq!(
                md.matches("input: ").count(),
                1,
                "the legacy session's SINGLE input line: {md}"
            );
            let csv = std::fs::read_to_string(d.join(crate::jobreport::CSV_NAME)).unwrap();
            assert_eq!(
                csv.lines().next().unwrap(),
                "clip,file,size_bytes,source_sha256,dest_sha256,verdict,skipped,copied_ms",
                "the legacy CSV header = the shipped pin (the `skipped` column only — no `source` column: the legacy form is single-source)"
            );
            assert!(
                md.contains(&format!("offload: VERIFIED 7/7 (dest {})", dc.display())),
                "the legacy verdict line (the dest-slot form — no source slot): {d:?}\n{md}"
            );
        }
        // The stderr line set (the pure composition over the legacy
        // reports: the N>1 per-dest blocks + the
        // existing line formats).
        let clean1 = OffloadReport {
            input: input_c.clone(),
            dest: d1c.clone(),
            rows: (0..7).map(|_| row_ok("x")).collect(),
            clips: vec![],
        };
        let clean2 = OffloadReport {
            input: input_c.clone(),
            dest: d2c.clone(),
            rows: (0..7).map(|_| row_ok("x")).collect(),
            clips: vec![],
        };
        assert_eq!(
            fanout_stderr_lines(&[clean1, clean2]),
            vec![
                format!("offload: VERIFIED 7/7 (dest {})", d1c.display()),
                format!("offload: VERIFIED 7/7 (dest {})", d2c.display()),
            ],
            "the legacy stderr's exact line set (the N>1 per-dest blocks)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    // =================================================================
    // The duplicate detection ("copy just what's new": the
    // automatic sha256-based skip of the offload copy path — a dest
    // file already present with matching content (size + sha256) is
    // verified only, NOT re-copied; the skip is NOT dirty — the row
    // is OK; the wire contracts stay frozen — the skip fact rides the
    // run report's `## skipped` section + the job report's
    // `skipped` column only). The named test set.
    // =================================================================


}
