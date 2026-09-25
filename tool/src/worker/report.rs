//! The report writer — the per-frame processing + the run-report
//! surface.
//!
//! `process_dir` is the directory orchestrator (the encode entry point
//! — the main.rs dispatch): the `--to` band (the self-referential +
//! nesting refusal — the named rc=2 before any frame) + the dest
//! writability probe + the frame/sidecar collection (`collect` — the
//! symlink-loop guard, the Apple-double shadow skip) + the clip
//! selection (`apply_selection` — the run's active selection, absent =
//! the full set) + the live encode-metrics window + the camera-identity
//! pre-pass (the profiles load ONCE per run; every selected frame
//! resolves against the set BEFORE any write — the unknown camera =
//! the named refusal, 0 compressed) + the per-frame processing
//! (`process_one` → the encode part's `run`) + the sidecar row emission
//! (the `sidecar` part) + the G2 per-PRESET distribution gate (FATAL
//! only for the VBR presets) + the `--to` offload (the encode
//! completes, THEN the copy verifies) + the reports (the crate
//! `report` module's writers) → `Report`.
//!
//! The verdict model: `FrameStats` (the per-frame stats — the size /
//! the verify timings / the reference MAE ratio) · `Outcome` (the per-
//! frame verdict) · `Report` (the run verdict — the main.rs / dryrun /
//! report consumers). The reel verdicts (`ClipVerdict` /
//! `ReelPairVerdict` / `ReelVerdict` + `reel_check`) — the reel
//! continuity the ingest gate's manifest carries. The clip identity:
//! `clip_key_of` / `display_clip` (the heavy offload/ + sourcecheck +
//! report consumers) + `parse_manifest_counts`. The
//! `g2_distribution_gate_is_fatal` predicate (the VBR-only scoping).

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use rayon::prelude::*;

use super::encode::{LossyFormat, Mode, ReferenceDctOpts, run};
use super::ingest::{ingest_gate, ingest_gate_subset, subset_flag, write_ingest_manifest};
use super::sidecar::{ChecksumsRow, append_sidecar_row, emit_frame_line};

#[derive(Clone, Debug)]
pub struct FrameStats {
    pub file: String,
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub ratio: f64,
    pub ms: f64,
    /// log10 mode only: reconstruction error stats (12-bit LSB).
    pub log10: Option<crate::verify::Log10Stats>,
    /// lossy mode only: 8-bit MAE/PSNR vs the downshifted source.
    pub lossy: Option<crate::verify::LossyStats>,
    /// lossy mode only: the libjpeg quality actually used (fixed for VBR,
    /// binary-searched per frame for CBR).
    pub quality: Option<u32>,
    /// reference tag-7 mode only: the G2 both-scan reconstruction stats
    /// (12-bit domain) + the table scale used.
    pub reference_dct: Option<crate::verify::ReferenceDctStats>,
}

#[derive(Clone, Debug)]
pub enum Outcome {
    Done(FrameStats),
    Skipped { file: String, in_bytes: u64 },
    Failed { file: String, error: String },
}

/// G2 distribution-gate scoping — see `gate_distribution`:
/// the per-PRESET MAE-ratio distribution gate (mean ∈ [0.10,1.20],
/// p50 ∈ [0.10,1.40], count(r>1.5) ≤ 5; count(r<0.5) is informational
/// only — the 20d recalibration made the gate one-sided, "not worse than
/// the measured encoder") is FATAL only for the VBR presets — it was calibrated on
/// vbr-hq and is a quality-contract gate for VBR. For CBR presets the same
/// line is printed but INFORMATIONAL (never fatal): a content-dependent
/// pre-domain approximation cannot hold a VBR quality-distribution band
/// on CBR (its fine budgets expose the pre-domain staircase on high-HF
/// frames, and its flat tail runs BETTER than the measured encoder with r<0.5);
/// the CBR contract is the per-frame size target (±5%) + catastrophe
/// ceiling (r<2.0) + scan-completeness, enforced on ALL presets by the
/// per-frame gate.
pub fn g2_distribution_gate_is_fatal(mode: Mode) -> bool {
    matches!(mode, Mode::VbrHq | Mode::VbrLt)
}

#[derive(Clone, Debug)]
pub struct Report {
    pub outcomes: Vec<Outcome>,
    pub copied_sidecars: Vec<String>,
    /// Checksums tsv path (written when `--checksums`).
    pub checksums: Option<PathBuf>,
    /// The two-destination offload: `Some(k)` when
    /// `--to` was given — `k` = the named dirty offload row count
    /// (0 = the verify-before-wipe gate is clean; > 0 = the named FAIL
    /// lines were printed at the offload step + rc=1, AFTER the encode
    /// completes — the encode is not blocked by the copy; the verdict
    /// is). `None` = no `--to` on this run.
    pub offload_dirty_rows: Option<usize>,
}

/// Process every .DNG under `input` (recursively; subfolder layout mirrored
/// into `output`) into `output`. Non-DNG files are copied through.
/// `jobs = 0` uses the default rayon pool (all cores); otherwise a
/// dedicated pool of `jobs` threads is used. `downscale` = the
/// `--downscale2x` half-resolution working-file mode (composable with the
/// mode). `checksums` writes the `<OUT_DIR>/<CLIP>.checksums.tsv` after a
/// frame-less-failure run. `to` = the two-destination offload dest
/// (see the offload step at the end of the run). Clip
/// names come from
/// `crate::checksums::clip_name` (shared with `--verify-checksums`,
/// review: one helper, refuse empty). The parameter count is the
/// CLI surface — not worth a wrapper struct (clippy allow).
#[allow(clippy::too_many_arguments)]
pub fn process_dir(
    input: &Path,
    output: &Path,
    verify: bool,
    force: bool,
    jobs: usize,
    mode: Mode,
    downscale: bool,
    fast: bool,
    checksums: bool,
    lossy_format: LossyFormat,
    reference: &ReferenceDctOpts,
    to: Option<&Path>,
    qc_gate: bool,
) -> Result<Report> {
    std::fs::create_dir_all(output)
        .with_context(|| format!("create output dir {}", output.display()))?;

    // --to: the self-referential + nesting band:
    // the dest must be DISJOINT from the input AND the output
    // (the post-encode mirror overwrites the encode product with the
    // raw source / writes the mirror into the source tree otherwise
    // — the total + silent product loss AFTER the run reports
    // success). The named rc=2 BEFORE any frame, BEFORE the probe's
    // dir creation (the zero-residue refusal). The shared helper is
    // the single code path (the jxl path's band is the same call —
    // the finding is the scope unit, the
    // two encode tiers are its entry points).
    if let Some(dest) = to {
        crate::offload::check_to_band(input, output, dest)?;
        // The two-destination dest must exist + be
        // WRITABLE before any frame (the named rc=2 startup refusal —
        // an unwritable camera-disk copy target is discovered at
        // startup, not mid-reel). The verify itself runs after the
        // encode (the encode is not blocked by the copy; the
        // verdict is).
        crate::offload::check_dest_writable(dest).with_context(|| {
            format!("--to dest {} (the two-destination offload target)", dest.display())
        })?;
    }

    let mut frames: Vec<(PathBuf, PathBuf)> = Vec::new(); // (in, out)
    let mut sidecars: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut visited = std::collections::HashSet::new(); // symlink-loop guard
    collect(
        input,
        input,
        output,
        &mut frames,
        &mut sidecars,
        &mut visited,
    )?;
    frames.sort_by(|a, b| a.0.cmp(&b.0));
    sidecars.sort_by(|a, b| a.0.cmp(&b.0));

    // --- C9 clip selection -------------------
    // The collected frames + sidecars restricted to the run's active
    // selection (absent = the full set — the byte-identity path, the
    // filter is a no-op). The gate + the encode + the sidecar copy +
    // the run-sidecar all operate on the restricted set below.
    apply_selection(input, &mut frames, &mut sidecars);

    // ---: the live encode metrics (predict-then-measure) ------
    // The sampling window begins BEFORE the camera-identity pre-pass
    // (the full-buffer read is the card read — the design
    // bottleneck — so the window's total read carries the card rate on
    // a cold source; the per-frame line's delta is measured from the
    // previous snapshot, the first line's window spans begin→frame-0).
    // The jxl tier never begins (the subprocess tier's I/O is invisible
    // to the process-level counters — the report renders the named
    // non-scope line). Unmeasurable = the named n/a (never a silent 0).
    crate::live::begin(frames.len());

    // --- camera identity gate
    // OPTION (a)) ------------------------------------------
    // The profile set is loaded ONCE per run (the pins-pattern
    // resolution: the FRAMEPRISM_PROFILES file (the legacy
    // FRAMEPRISM_PROFILES name is honored) -> <cwd>/profiles ->
    // <exe-dir>/profiles; unresolvable / a corrupt profile = the named
    // rc=2 — the tool does not encode without its camera identity,
    // the same posture as the pins) and passed down to the per-frame
    // gate in run() — not per frame. EVERY frame of the selected set
    // is resolved against the set BEFORE any write (the FROZEN posture
    // made explicit: an unknown camera / an unmeasured readout / depth
    // / CFA is the named refusal — 0 compressed, nothing written to
    // the output dir, the established refusal mechanics: the named
    // FAIL lines ride the per-frame class + the run summary + rc=2).
    // The A001 profile = the embedded constants: a profiled frame
    // resolves to the SAME layout class the predicates route (the
    // identity gate is AHEAD of the routing, never a rewrite). The
    // gate reads the header only (tiff::read_meta — the identity tags;
    // the encode's own tiff::read in run() is the full parse — the
    // pre-write identity check, like the ingest gate's header reads;
    // the resolution never re-parses a frame for the identity). A
    // 0-frame run has nothing to identify (no load, no refusal —
    // the pre-record behavior stands).
    let profiles = if frames.is_empty() {
        None
    } else {
        Some(
            crate::camera::resolve_profiles().map_err(|err| {
                anyhow::anyhow!(
                    "resolve the camera profile set (the pins-pattern resolution: the FRAMEPRISM_PROFILES file (the legacy FRAMEPRISM_PROFILES name is honored) -> <cwd>/profiles -> <exe-dir>/profiles): {err}"
                )
            })?,
        )
    };
    if let Some(set) = &profiles {
        let mut camera_failures: Vec<String> = Vec::new();
        for (src, _) in &frames {
            let file = src
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| src.display().to_string());
            // The bounded prefix read (the camera identity's
            // measured reach is 79,280 B over the committed fixtures
            // — the bound is 1 MiB); the FAIL wording below is the
            // pre-record one.
            let buf = match crate::camera::read_detection_prefix(src) {
                Ok(b) => b,
                Err(err) => {
                    camera_failures.push(format!(
                        "FAIL {file}: camera identity: read {}: {err}",
                        src.display()
                    ));
                    continue;
                }
            };
            let meta = match crate::tiff::read_meta(&buf) {
                Ok(m) => m,
                Err(err) => {
                    camera_failures.push(format!("FAIL {file}: camera identity: {err}"));
                    continue;
                }
            };
            let ident = match crate::camera::identity_from_ifd0(&meta.ifd0, &buf) {
                Ok(i) => i,
                Err(err) => {
                    camera_failures.push(format!("FAIL {file}: camera identity: {err}"));
                    continue;
                }
            };
            if let crate::camera::Resolution::Mismatch(m) = crate::camera::resolve(set, &ident) {
                camera_failures.push(format!("FAIL {file}: {}", m.named_line()));
            }
        }
        if !camera_failures.is_empty() {
            for line in &camera_failures {
                eprintln!("{line}");
            }
            eprintln!(
                "CAMERA GATE FAIL — {} frame(s) refused, 0 compressed (the named FAIL lines above)",
                camera_failures.len()
            );
            return Err(anyhow::anyhow!(
                "camera gate: {} named FAIL line(s) — refusing to compress (see the FAIL lines above)",
                camera_failures.len()
            ));
        }
    }

    // --- ingest safety gate --------------
    // Unconditional BY DEFAULT (no escape flag) and BEFORE anything
    // is written (the sidecar copy + the frame encode): (a) the per-clip
    // frame-number contiguity (FRAME_GAP / FRAME_DUP), (b) the
    // manifest.tsv declared frame count (COUNT_MISMATCH — a hard gate
    // only when the manifest is present in the input root; absent = the
    // named INFO line, not a FAIL), and (c) the per-frame SMPTE 12M
    // TimeCodes continuity from DNG tag 51043 (TC_GAP / TC_OVERLAP /
    // TC_MISSING). The NAMED opt-in `--subset` (the
    // re-verify) waives EXACTLY the four continuity classes (FRAME_GAP
    // / FRAME_DUP / TC_GAP / TC_OVERLAP) — every other class (incl.
    // the cross-clip REEL_OVERLAP + the upstream profile-resolution
    // refusals) stays a hard refusal; the named line + the ledger's v3
    // `context` marker record the waiver (SUBSET_MARKER).
    // FAIL = the named FAIL block + rc!=0 + 0 frames compressed
    // (the existing refusal pattern — nothing is written to the output
    // dir); PASS = the compact verdict block (one line per clip) + the
    // ingest-manifest record (the `audit` surface prints it and
    // re-derives it from the source DNGs when present).
    let frame_ins: Vec<PathBuf> = frames.iter().map(|(src, _)| src.clone()).collect();
    let gate = if subset_flag() {
        ingest_gate_subset(input, &frame_ins)
    } else {
        ingest_gate(input, &frame_ins)
    };
    let gate_failures = gate.failures();
    if !gate_failures.is_empty() {
        for line in &gate_failures {
            eprintln!("{line}");
        }
        // The reel FAIL is the named cross-clip half (the disk
        // must not unlock — a double capture cannot be trusted):
        // the reel-specific refusal line rides the same rc=2 class.
        if !gate.reel.failures.is_empty() {
            eprintln!(
                "REEL GATE FAIL — {} cross-clip TC overlap(s) (double capture — the ingest cannot be trusted; the camera disk stays locked)",
                gate.reel.failures.len()
            );
        }
        eprintln!(
            "INGEST GATE FAIL — {} frame(s) across {} clip(s) refused, 0 compressed (the named FAIL lines above)",
            gate.frames_total,
            gate.clips.len()
        );
        return Err(anyhow::anyhow!(
            "ingest safety gate: {} named FAIL line(s) — refusing to compress (see the FAIL lines above)",
            gate_failures.len()
        ));
    }
    for c in &gate.clips {
        eprintln!(
            "PASS ingest-gate clip={}: {} frame(s) (manifest: {}) range {} TC {}",
            display_clip(&c.clip),
            c.frames_found,
            match c.manifest_declared {
                Some(d) => format!("{d}"),
                None => "n/a".into(),
            },
            match c.frame_range {
                Some((a, b)) => format!("{a}..{b}"),
                None => "-".into(),
            },
            match (&c.tc_start, &c.tc_end) {
                (Some(a), Some(b)) => format!("{a}..{b}"),
                (Some(a), None) | (None, Some(a)) => format!("{a}..?"),
                (None, None) => "-".into(),
            }
        );
    }
    if !gate.manifest_present {
        eprintln!(
            "INFO no manifest.tsv in {} — expected-frame-count check skipped (frames found: {})",
            input.display(),
            gate.frames_total
        );
    }
    let gate_manifest =
        write_ingest_manifest(output, input, &gate).with_context(|| {
            format!("write the ingest manifest to {}", output.display())
        })?;
    eprintln!("ingest manifest: {}", gate_manifest.display());

    // ---: the --resume verified-skip
    // scan + the status surface (the start/clip lines) ---------------
    // The scan runs BEFORE the first frame/byte (after the gate + the
    // ingest record — the selection already applied, the gate
    // already ran): it reads the existing sidecar + the
    // source-sha manifest, cleans the interrupted run's
    // leftover temps, and builds the skip plan. A corrupt
    // sidecar is a named hard error (the `resume:` prefix — the
    // pre-run class, NO ledger row). --force + --resume: the force
    // wins — the skip plan is cleared (the full re-encode) + the named
    // line; the plan still registers (the report's `resumed:` line
    // renders the zero form).
    let resume_active = crate::resume::flag();
    let resume_plan = if resume_active {
        let clip0 = crate::checksums::clip_name(input)
            .map_err(|err| anyhow::anyhow!("resume: derive the clip name: {err}"))?;
        let mut plan = crate::resume::scan(input, output, &clip0, &frames)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        for note in &plan.notes {
            eprintln!("resume: {note}");
        }
        if force && !plan.skip.is_empty() {
            eprintln!(
                "resume: --force set — the {} verified skip(s) are NOT applied (full re-encode)",
                plan.skip.len()
            );
            plan.skip.clear();
        }
        Some(plan)
    } else {
        None
    };
    crate::resume::set_current(resume_plan.as_ref().cloned());
    // Re-encode frames (an existing stale output, a sha mismatch, a
    // changed source, a missing row) must OVERWRITE: force is ON for
    // the whole resume run (a non-resume run keeps the caller's force).
    let force_eff = force || resume_active;
    let est_eta_s =
        (crate::preflight::eta_minutes("j92", gate.frames_total as usize) * 60.0) as u64;
    // The status start + per-clip lines (after the scan — the real
    // `resumed` count — BEFORE the first frame/byte; the file itself
    // was truncated at run start by `main`). J92 legacy encode only
    // (the jxl path never opens the surface — current() = None there).
    if let Some(st) = crate::status::current() {
        let resumed_k = resume_plan.as_ref().map(|p| p.skipped()).unwrap_or(0);
        st.emit(&format!(
            "{{\"run\":{},\"input\":{},\"out\":{},\"codec\":{},\"phase\":{},\"clips\":{},\"frames_total\":{},\"est_eta_s\":{est_eta_s},\"resumed\":{resumed_k}}}",
            crate::status::jstr(&st.run_id),
            crate::status::jstr(&input.to_string_lossy()),
            crate::status::jstr(&output.to_string_lossy()),
            crate::status::jstr("j92"),
            crate::status::jstr("start"),
            gate.clips.len(),
            gate.frames_total
        ));
        for (i, c) in gate.clips.iter().enumerate() {
            st.emit(&format!(
                "{{\"phase\":{},\"clip\":{},\"clip_i\":{},\"clips\":{},\"frames_clip\":{}}}",
                crate::status::jstr("clip"),
                crate::status::jstr(&c.clip),
                i + 1,
                gate.clips.len(),
                c.frames_found
            ));
        }
    }
    // The clip name (the sidecar's `<CLIP>` — the run-start sidecar
    // header needs it; the name was derived lazily at the
    // end-of-run write site — same helper, same refusal).
    let clip0: Option<String> = match (checksums, resume_active) {
        (true, _) | (_, true) => Some(
            crate::checksums::clip_name(input)
                .with_context(|| format!("derive the clip name from {}", input.display()))?,
        ),
        _ => None,
    };
    // The incremental v3 sidecar: the header lands at run start
    // (the file is the crash-recovery record from the first frame on);
    // the completed rows append per frame; the final canonical rewrite
    // (sorted) at completion. The append handle is the single writer
    // (the rows are mutex-guarded; the O_APPEND writes are one line
    // each).
    let mut sidecar_rows: Vec<ChecksumsRow> = Vec::new();
    let sidecar_rows = std::sync::Mutex::new(&mut sidecar_rows);
    let sidecar_file: std::sync::Mutex<Option<std::fs::File>> =
        std::sync::Mutex::new(None);
    let sidecar_meta_errors: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    if checksums {
        if let Some(cn) = &clip0 {
            // The header only (a fresh run: the file is created now; a
            // resume run: the previous file's rows were consumed by the
            // scan — the file is rebuilt from the plan + this run's
            // rows; the FINAL bytes are the canonical rewrite below).
            // `write_sidecar` with zero rows = the exact header bytes
            // (the one byte source, the parity is structural).
            crate::checksums::write_sidecar(output, cn, &[])
                .with_context(|| "write the run sidecar header (the run-start record)")?;
            let path = output.join(crate::checksums::checksums_name(cn));
            let f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .with_context(|| format!("open the run sidecar for append {}", path.display()))?;
            *sidecar_file.lock().unwrap() = Some(f);
        }
    }

    // --- (c): the qc record (<CLIP>.qc.tsv — the additive
    // per-frame v4 content) ------------------------------------------
    // The final-sidecar UNION pattern:
    // the PRIOR record's
    // rows (the skipped / earlier frames — parsed NOW, before the
    // header overwrite — the parity: the previous file's rows are
    // consumed now, like the resume plan for the checksums sidecar; the
    // torn tail is NAMED + discarded) + this run's rows (the decoded
    // frames — the fresh decode wins per frame key) → the same final
    // clip state produces the SAME bytes whether the run was fresh or
    // resumed (rows keyed by frame name, sorted — a pure function of
    // the final state). The qc record is a DERIVED-STATS record — NOT
    // an audit surface (the integrity rides the checksums.tsv rows; a
    // corrupt prior record is a named note + the prior rows dropped,
    // never a run killer; the gap lands in the `partial:` note).
    let mut qc_claimed: Vec<(crate::qc::QcRow, crate::qc::QcFrame)> = Vec::new();
    let qc_frames = std::sync::Mutex::new(&mut qc_claimed);
    let qc_file: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);
    let mut prior_qc: Vec<crate::qc::QcRow> = Vec::new();
    if checksums {
        if let Some(cn) = &clip0 {
            let qc_path = output.join(crate::qc::qc_name(cn));
            if qc_path.is_file() {
                match crate::qc::parse_qc(&qc_path) {
                    Ok((rows, torn)) => {
                        if let Some(t) = torn {
                            eprintln!(
                                "qc: torn tail in {} — the final line is incomplete (the named discard — its frame re-encodes or stays named in the `partial:` note): {t:?}",
                                crate::qc::qc_name(cn)
                            );
                        }
                        prior_qc = rows;
                    }
                    Err(err) => {
                        eprintln!(
                            "qc: note: cannot parse the prior {} ({err}) — the prior rows are dropped (the fresh rows stand; the `partial:` note names the gap)",
                            crate::qc::qc_name(cn)
                        );
                    }
                }
            }
            // The header only (a fresh run: the file is created now; a
            // resume run: the previous file's rows were consumed above
            // — the file is rebuilt from the prior + this run's rows;
            // the FINAL bytes are the canonical union rewrite below).
            // `write_qc` with zero rows = the exact header bytes (the
            // one byte source, the parity is structural).
            crate::qc::write_qc(output, cn, &[], gate.frames_total as usize, &[])
                .with_context(|| "write the qc record header (the run-start record)")?;
            let path = output.join(crate::qc::qc_name(cn));
            let f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .with_context(|| format!("open the qc record for append {}", path.display()))?;
            *qc_file.lock().unwrap() = Some(f);
        }
    }

    // The sidecar copy runs AFTER the gate (a FAIL leaves
    // nothing in the output dir — the gate refuses before ANY write).
    // The sidecar set includes the input's manifest.tsv when present —
    // copying it before the gate would have leaked it into a refused
    // output dir.
    let mut copied = Vec::new();
    for (src, dst) in &sidecars {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Atomic sidecar copy (tmp + rename) so a crash
        // cannot leave a torn sidecar that resume would skip forever;
        // report ONLY sidecars actually copied (skipped = not reported).
        if dst.exists() && !force {
            continue;
        }
        let tmp = dst.with_extension("sidecar.tmp");
        if let Err(err) = std::fs::copy(src, &tmp).and_then(|_| std::fs::rename(&tmp, dst)) {
            let _ = std::fs::remove_file(&tmp); // best-effort cleanup
            return Err(err)
                .with_context(|| format!("copy sidecar {} -> {}", src.display(), dst.display()));
        }
        copied.push(
            src.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        );
    }

    let t0 = Instant::now();
    //: the encode + the per-frame sidecar append + the status
    // lines. The POSITIONAL outcome order (the frames order) is the
    // clip_stats contract (report.rs indexes `outcomes[i]` over
    // `frames[i]`) — the plan's skips happen INSIDE the map (not a
    // partition before it), so the order is preserved by the
    // par_iter().collect() contract.
    let total_frames = frames.len();
    let done_count = std::sync::atomic::AtomicUsize::new(0);
    let process = |src: &Path, dst: &Path| -> Outcome {
        // The sidecar row key (the output-relative frame path, POSIX —
        // the sidecar + the qc record's shared key; the (b) dup
        // check + the qc union both ride it).
        let rel = dst
            .strip_prefix(output)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        // the verified skip (the plan) — no encode, no naive
        // existence check (the plan's decision IS the skip decision;
        // its sha was re-verified against the on-disk output at scan
        // time). The sidecar row reuses the verified plan row (the
        // bytes are unchanged — size/crc/meta stay valid).
        if let Some(plan) = &resume_plan {
            if let Some(row) = plan.skip.get(&rel) {
                append_sidecar_row(
                    dst,
                    &rel,
                    checksums,
                    &clip0,
                    &sidecar_rows,
                    &sidecar_file,
                    &sidecar_meta_errors,
                    Some(row),
                );
                emit_frame_line(src, dst, input, output, true, &done_count, total_frames, est_eta_s, &t0);
                crate::live::note_skipped();
                return Outcome::Skipped {
                    file: src
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    in_bytes: std::fs::metadata(src).map(|m| m.len()).unwrap_or(0),
                };
            }
        }
        let outcome = process_one(
            src,
            dst,
            verify,
            force_eff,
            mode,
            downscale,
            fast,
            lossy_format,
            reference,
            Some(&rel),
            profiles.as_ref(),
        );
        //: the live metrics sampling (the extended per-frame
        // stdout line for a Done frame — the running-ETA observation;
        // a Skipped/Failed frame counts for `left` + advances the delta
        // window without a line).
        match &outcome {
            Outcome::Done(s) => {
                crate::live::note_done(&s.file, s.in_bytes, s.out_bytes, s.ratio, s.ms)
            }
            _ => crate::live::note_skipped(),
        }
        // The per-frame sidecar row (Done only — the bytes are re-
        // hashed from the ON-DISK output file + the metadata from the
        // output header: the verification, not the trust; a read /
        // header failure lands in the named error set — the run fails
        // before the final sidecar, the pre-record write_checksums
        // bail parity).
        if matches!(outcome, Outcome::Done(_)) {
            append_sidecar_row(
                dst,
                &rel,
                checksums,
                &clip0,
                &sidecar_rows,
                &sidecar_file,
                &sidecar_meta_errors,
                None,
            );
            // (c): the per-frame qc stats — claimed from the
            // decode-site registry (the Done frames only — a verified
            // skip is NOT re-decoded, its row carries from the prior
            // record at the final union). The claim is unconditional
            // (the (a)+(c) report sections reflect every decoded frame
            // of the run); the incremental qc RECORD append rides the
            // sidecar gate (checksums on: the file handle is set — the
            // crash record, the parity; the final canonical union
            // rewrite is the byte contract; checksums off: no record,
            // the stats stand in the report only).
            if let Some(qf) = crate::qc::claim(&rel) {
                let row = crate::qc::QcRow::from_frame(&qf);
                qc_frames.lock().unwrap().push((row.clone(), qf));
                if let Ok(mut g) = qc_file.lock() {
                    if let Some(f) = g.as_mut() {
                        use std::io::Write as _;
                        let _ = f.write_all(row.line().as_bytes());
                    }
                }
            }
        }
        emit_frame_line(src, dst, input, output, false, &done_count, total_frames, est_eta_s, &t0);
        outcome
    };
    let outcomes: Vec<Outcome> = if jobs > 0 {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(jobs).build()?;
        pool.install(|| frames.par_iter().map(|(src, dst)| process(src, dst)).collect())
    } else {
        frames.par_iter().map(|(src, dst)| process(src, dst)).collect()
    };
    let elapsed = t0.elapsed().as_secs_f64();
    //: the live window ends after the encode (the final
    // snapshot + the totals — the report's `## live` section reads
    // `live::last()`; the sidecar/report writes after this point are
    // the named ± for the written total).
    crate::live::finish();

    let done: Vec<&FrameStats> = outcomes
        .iter()
        .filter_map(|o| match o {
            Outcome::Done(s) => Some(s),
            _ => None,
        })
        .collect();
    let total_in: u64 = outcomes
        .iter()
        .map(|o| match o {
            Outcome::Done(s) => s.in_bytes,
            Outcome::Skipped { in_bytes, .. } => *in_bytes,
            Outcome::Failed { .. } => 0,
        })
        .sum();
    let total_out: u64 = done.iter().map(|s| s.out_bytes).sum();
    let failed = outcomes
        .iter()
        .filter(|o| matches!(o, Outcome::Failed { .. }))
        .count();
    let skipped = outcomes
        .iter()
        .filter(|o| matches!(o, Outcome::Skipped { .. }))
        .count();
    let avg_ms = if done.is_empty() {
        0.0
    } else {
        done.iter().map(|s| s.ms).sum::<f64>() / done.len() as f64
    };
    let total_ratio = if total_out > 0 {
        total_in as f64 / total_out as f64
    } else {
        0.0
    };
    let jobs = if jobs > 0 {
        jobs
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    };
    eprintln!(
        "{done} frame(s) compressed in {elapsed:.1}s (avg {avg:.0} ms/frame, {jobs} jobs), \
         {skipped} skipped, {failed} failed: {total_in} B -> {total_out} B ({ratio:.2}:1)",
        done = done.len(),
        elapsed = elapsed,
        avg = avg_ms,
        skipped = skipped,
        failed = failed,
        ratio = total_ratio,
    );

    //: the per-frame sidecar row reads (the output header parse +
    // the whole-file re-hash) — a failure here is the named hard error
    // (the pre-record write_checksums bail parity: the run fails BEFORE
    // the final sidecar + the reports; the incremental file is
    // removed — the failed-run contract: no sidecar).
    {
        let errs: Vec<String> = sidecar_meta_errors.lock().unwrap().clone();
        if !errs.is_empty() {
            if let Some(cn) = &clip0 {
                let _ = std::fs::remove_file(output.join(crate::checksums::checksums_name(cn)));
            }
            for e in &errs {
                eprintln!("error: {e}");
            }
            return Err(anyhow::anyhow!(
                "sidecar row: {} named failure(s) — the run fails before the final sidecar (the write_checksums bail parity)",
                errs.len()
            ));
        }
    }

    // The final sidecar union rows (hoisted: the (b) duplicate
    // check + the qc record's final union both ride the SAME row set —
    // the run's rows ∪ the walk's extras, the write_sidecar input).
    let mut all_rows: Option<Vec<ChecksumsRow>> = None;
    let checksums_path = if checksums {
        if failed > 0 {
            eprintln!("skipping --checksums: {failed} frame(s) failed");
            //: the incremental sidecar (the header + the
            // completed rows) must NOT survive a failed run (the
            // pre-record contract: no sidecar on a frame failure).
            //: the incremental qc record (the derived-stats class
            // — the same failed-run contract: no final record).
            if let Some(cn) = &clip0 {
                let _ = std::fs::remove_file(output.join(crate::checksums::checksums_name(cn)));
                let _ = std::fs::remove_file(output.join(crate::qc::qc_name(cn)));
            }
            None
        } else {
            let cn = clip0.as_ref().unwrap();
            // The final canonical rewrite (sorted by rel — the
            // write_checksums byte contract). The row set = this
            // run's rows (the verified plan skips + the re-hashed
            // encodes) UNIONed with every other output .DNG (the
            // pre-record sidecar covers EVERY output frame — the walk is
            // the parity source; the run frames' rows win, hashed this
            // run). Byte-identical to the uninterrupted run's sidecar.
            let mut rows: Vec<ChecksumsRow> =
                sidecar_rows.lock().unwrap().clone();
            let run_rels: std::collections::BTreeSet<String> =
                rows.iter().map(|r| r.0.clone()).collect();
            let mut extra: Vec<(String, PathBuf)> = Vec::new();
            crate::checksums::walk_dng(output, output, &mut extra)?;
            for (rel, p) in &extra {
                if run_rels.contains(rel) {
                    continue;
                }
                // The streaming triple (size + crc + sha in
                // one bounded pass — never the whole frame in a
                // `Vec`); the `read {}` context is the pre-record one.
                let (size, sha, crc) =
                    crate::jxl::digest_stream_path(p).with_context(|| format!("read {}", p.display()))?;
                let meta = crate::worker::read_frame_metadata(p)
                    .map_err(|err| anyhow::anyhow!("{err}"))?;
                rows.push((
                    rel.clone(),
                    size,
                    crc,
                    sha,
                    crate::checksums::meta_columns(&meta),
                ));
            }
            if rows.is_empty() {
                anyhow::bail!("no .DNG frames in output dir {}", output.display());
            }
            all_rows = Some(rows.clone());
            Some(crate::checksums::write_sidecar(output, cn, &rows)?)
        }
    } else {
        None
    };
    //: the post-encode verify summary line (the `phase:"verify"`
    // event — frames_ok = the non-failed frame count).
    if let Some(st) = crate::status::current() {
        st.emit(&format!(
            "{{\"phase\":{},\"frames_total\":{total_frames},\"frames_ok\":{}}}",
            crate::status::jstr("verify"),
            total_frames - failed
        ));
    }

    // ---: the (a)+(b)+(c) QC assembly -------------------------
    // The (b) duplicate check (NO decode — the final sidecar sha rows:
    // the cheap check on the existing rows, the pinned execution order
    // — runs BEFORE the (a)+(c) report rendering); the (a) black/blank
    // + the (c) exposure stats come from the decode-site registry
    // (already computed — one pass over the decode the encode needed);
    // the qc record's final canonical union rewrite (the union
    // pattern — the requirement: the prior rows + this
    // run's rows → the same final clip state = the same bytes fresh vs
    // resumed; the named `partial:` = the torn-tail edge — never
    // silent); the report state (the report renders it — the
    // encode-time computation is the authority, the report is the
    // record's echo); the gate verdict (the named-negative
    // convention — the run COMPLETES: no data loss, the files are
    // written; the gate is a verdict, not a preflight refusal).
    let claimed: Vec<(crate::qc::QcRow, crate::qc::QcFrame)> = qc_frames.lock().unwrap().clone();
    // (b) the consecutive identical-sha pairs, grouped by clip (the
    // rel's parent — the ingest key space; the sorted rel = the frame
    // order, the zero-padded names). Absent = the sidecar rows are
    // absent (named in the report — never a silent skip).
    let dups_by_clip: std::collections::BTreeMap<String, Vec<crate::qc::DupPair>> =
        match &all_rows {
            Some(rows) => {
                let mut sorted: Vec<(String, String)> =
                    rows.iter().map(|r| (r.0.clone(), r.3.clone())).collect();
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
                let mut by_clip: std::collections::BTreeMap<String, Vec<(String, String)>> =
                    std::collections::BTreeMap::new();
                for (rel, sha) in sorted {
                    by_clip
                        .entry(crate::qc::clip_key_of_rel(&rel))
                        .or_default()
                        .push((rel, sha));
                }
                by_clip
                    .into_iter()
                    .map(|(k, v)| (k, crate::qc::dup_pairs(&v)))
                    .filter(|(_, d)| !d.is_empty())
                    .collect()
            }
            None => std::collections::BTreeMap::new(),
        };
    // The per-clip (a)+(c) assembly (the gate's clip order — the
    // report's loop order; a frame's clip = the rel's parent — the
    // same key space as the ingest gate).
    let mut clips_qc: Vec<crate::qc::ClipQc> = Vec::new();
    for c in &gate.clips {
        let frames: Vec<crate::qc::QcFrame> = claimed
            .iter()
            .filter(|(_, f)| crate::qc::clip_key_of_rel(&f.rel) == c.clip)
            .map(|(_, f)| f.clone())
            .collect();
        let black: Vec<(String, u32, u128, u64)> = frames
            .iter()
            .filter(|f| f.black)
            .map(|f| (f.rel.clone(), f.range(), f.var_num, f.n))
            .collect();
        let dups = dups_by_clip.get(&c.clip).cloned().unwrap_or_default();
        clips_qc.push(crate::qc::ClipQc {
            clip: c.clip.clone(),
            decoded: frames.len(),
            total: c.frames_found as usize,
            moments: if frames.is_empty() {
                None
            } else {
                Some(crate::qc::clip_moments(&frames))
            },
            black,
            dups,
            dups_available: all_rows.is_some(),
        });
    }
    // The named candidate lines (the report-only default: the (a)+(b)
    // candidates are ALWAYS named — loud, not silent; the gate mode
    // adds the verdict below). The exact variance numerator is
    // rendered (the record's echo — the verdict is reproducible from
    // the recorded threshold + values).
    for cq in &clips_qc {
        for (rel, range, var_num, n) in &cq.black {
            let variance = if *n == 0 {
                0.0
            } else {
                *var_num as f64 / (*n as f64 * *n as f64)
            };
            eprintln!(
                "QC BLACK {rel} — range={range} < {range_floor} OR variance={var:.3} < {var_floor} (the pinned threshold qc::BLACK_RANGE_FLOOR / qc::BLACK_VAR_FLOOR — the 12-bit fp domain)",
                range_floor = crate::qc::BLACK_RANGE_FLOOR,
                var_floor = crate::qc::BLACK_VAR_FLOOR,
                var = variance
            );
        }
        for d in &cq.dups {
            eprintln!(
                "QC DUP {} == {} — identical output sha256 {}… (the file-level duplicate — the same file written twice; a pixel-level double-capture with an advanced TC yields different output bytes and is NOT caught — the documented v1 gap)",
                d.a,
                d.b,
                &d.sha[..d.sha.len().min(16)]
            );
        }
    }
    // The qc record's final canonical union rewrite (the union
    // pattern — the requirement): the prior rows + this
    // run's rows (the fresh decode wins per frame key), sorted by
    // frame name; the named `partial:` = the walk universe's frames
    // absent from both the prior record and this run (the torn-tail
    // edge — named, never silent; the union is the primary path).
    if checksums && failed == 0 {
        if let Some(cn) = &clip0 {
            let fresh_rows: Vec<crate::qc::QcRow> =
                claimed.iter().map(|(r, _)| r.clone()).collect();
            let prior_files: std::collections::BTreeSet<String> =
                prior_qc.iter().map(|r| r.file.clone()).collect();
            let fresh_files: std::collections::BTreeSet<String> =
                fresh_rows.iter().map(|r| r.file.clone()).collect();
            // The walk universe (the final sidecar row set — every
            // output frame; absent here = the no-frames bail already
            // fired, so the universe is the sidecar's rows).
            let walk_universe: std::collections::BTreeSet<String> = all_rows
                .as_ref()
                .map(|rows| rows.iter().map(|r| r.0.clone()).collect())
                .unwrap_or_default();
            let mut partial: Vec<String> = walk_universe
                .iter()
                .filter(|rel| !fresh_files.contains(*rel) && !prior_files.contains(*rel))
                .cloned()
                .collect();
            partial.sort();
            let merged = crate::qc::union_rows(&prior_qc, &fresh_rows);
            crate::qc::write_qc(output, cn, &merged, walk_universe.len(), &partial)
                .with_context(|| format!("write the qc record {}", crate::qc::qc_name(cn)))?;
        }
    }
    // The gate verdict (the named-negative convention — the
    // run COMPLETES: no data loss, the files are written; the gate is
    // a verdict, not a preflight refusal). The rc contribution is read
    // by the CLI from the report state (the gate_hits count — 0 when
    // the gate is off: the default run never gates).
    let qc_hits: usize = clips_qc.iter().map(|c| c.black.len() + c.dups.len()).sum();
    if qc_gate {
        if qc_hits > 0 {
            eprintln!(
                "QC GATE FAIL — {qc_hits} named row(s) (the --qc-gate verdict — the run completes: no data loss, the files are written; the gate is a verdict, not a preflight refusal)"
            );
        } else {
            eprintln!("qc gate: PASS — 0 named row(s) (the --qc-gate verdict — the (a) black/blank + the (b) duplicate checks clean)");
        }
    } else if qc_hits > 0 {
        eprintln!(
            "qc: report-only (the default) — {qc_hits} named candidate row(s) above (the (a) black/blank + the (b) duplicate); --qc-gate = the gate (rc=2)"
        );
    }
    crate::qc::set_current(Some(crate::qc::RunState {
        gate: qc_gate,
        clips: clips_qc,
    }));

    // G2 per-PRESET distribution gate (locked;
    // recalibrated to one-sided "not worse than the
    // reference" — see `gate_distribution` for the spec + rationale): the
    // per-frame MAE ratios r_i = our_MAE_i / reference_MAE_i (from
    // --reference-mae-tsv) over ALL frames of the preset are checked against
    // the measured quality band at the distribution level — mean(r) ∈
    // [0.10,1.20], p50(r) ∈ [0.10,1.40], count(r>1.5) ≤ 5. count(r<0.5) is
    // NOT gated (being better than the measured encoder is the 20b design intent) —
    // it stays on this INFORMATIONAL line, printed for every mode, so the
    // count is always observable. **VBR-scoped: FATAL only for
    // vbr-hq/vbr-lt** (the gate was calibrated on vbr-hq; for CBR presets
    // the line is informational — the CBR contract is the per-frame size
    // ±5% + catastrophe ceiling r<2.0 + scan-completeness, enforced per
    // frame above on ALL presets). The per-frame [0.5×,1.5×] band +
    // per-frame p99 cap are retired (the measured max 59.85 > its p99
    // 59.68, so a per-frame cap is unachievable even by the measured encoder).
    // Applied only for dct12 with --verify and a reference MAE TSV
    // present.
    if verify && lossy_format == LossyFormat::ReferenceDct && reference.reference_mae_tsv.is_some() {
        let ratios: Vec<f64> = done
            .iter()
            .filter_map(|s| s.reference_dct.as_ref().and_then(|v| v.mae_ratio))
            .collect();
        if ratios.is_empty() {
            eprintln!(
                "G2 distribution: no per-frame MAE ratios (--reference-mae-tsv not matched); skipping"
            );
        } else {
            let mean = ratios.iter().sum::<f64>() / ratios.len() as f64;
            let mut sorted = ratios.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let p50 = sorted[sorted.len() / 2];
            let mx = sorted.last().copied().unwrap_or(0.0);
            let gt15 = ratios.iter().filter(|r| **r > 1.5).count();
            let lt05 = ratios.iter().filter(|r| **r < 0.5).count();
            let fatal = g2_distribution_gate_is_fatal(mode);
            eprintln!(
                "G2 distribution ({} frames, {}): mean {mean:.3} p50 {p50:.3} max {mx:.3} | r>1.5: {gt15} r<0.5: {lt05}",
                ratios.len(),
                if fatal { "FATAL gate" } else { "informational (CBR mode)" }
            );
            if fatal {
                crate::lossydct::gate_distribution(&ratios)
                    .map_err(|e| anyhow::anyhow!("G2 distribution gate: {e}"))?;
            }
        }
    }

    // --to: the verified offload runs AFTER the
    // encode completes (the encode is not blocked by the copy; the
    // VERDICT is — any dirty row is a named FAIL + rc=1 carried in the
    // Report; the verify-before-wipe line lands in the run report
    //: the camera disk is only reusable after BOTH
    // destinations verify clean).
    let offload_report = if let Some(dest) = to {
        let r = crate::offload::offload_to(input, output, dest)
            .with_context(|| format!("the --to offload to {}", dest.display()))?;
        if r.dirty_count() > 0 {
            for line in r.fail_lines() {
                eprintln!("{line}");
            }
            eprintln!(
                "OFFLOAD FAIL — {} dirty row(s) (dest {}): the named FAIL lines above (the verify-before-wipe gate holds: the camera disk is reusable only after BOTH destinations verify clean)",
                r.dirty_count(),
                dest.display()
            );
        } else {
            eprintln!("{}", r.verdict_line());
        }
        Some(r)
    } else {
        None
    };

    // The per-clip + run offload reports: at the end
    // of every encode run. The ingest-gate verdict is the SOURCE (the
    // ingest record — the report renders it, never re-derives it);
    // the j92 codec version = the jpeg-turbo build line (build.rs);
    // the per-clip report is deterministic (no wall clock), the
    // run report carries exactly ONE `created:` line.
    let _reports = crate::report::write_reports(
        output,
        input,
        "j92",
        crate::report::jpeg_turbo_build(),
        &gate,
        &frames,
        &outcomes,
        offload_report.as_ref(),
        checksums_path.as_ref(),
    )
    .with_context(|| "write the offload reports")?;

    Ok(Report {
        outcomes,
        copied_sidecars: copied,
        checksums: checksums_path,
        offload_dirty_rows: offload_report.as_ref().map(|r| r.dirty_count()),
    })
}

/// Collect frames (`.dng`) + sidecars (everything else) under `base`,
/// mirroring the subfolder layout into `output_root`.
/// symlinked entries are skipped and every descended-into directory is
/// tracked by (dev, ino) — a symlink cycle can no longer recurse
/// unboundedly (the posture is refuse/nonzero, not stack overflow).
fn collect(
    base: &Path,
    dir: &Path,
    output_root: &Path,
    frames: &mut Vec<(PathBuf, PathBuf)>,
    sidecars: &mut Vec<(PathBuf, PathBuf)>,
    visited: &mut std::collections::HashSet<(u64, u64)>,
) -> Result<()> {
    let meta = std::fs::metadata(dir)?;
    let id = crate::file_id(&meta);
    if !visited.insert(id) {
        return Ok(()); // already visited — symlink cycle (or hard-link fan-in)
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            // Refuse symlinked entries in the input tree (the worker mirrors
            // real directories; a symlink that escapes `base` would land
            // outside `output_root`).
            continue;
        }
        //: an AppleDouble shadow twin is never a frame nor a
        // sidecar — skip (the xattr-less-volume source-tree shape: a
        // `._*.DNG` shadow would otherwise be ENCODED as a frame; the
        // shadow is a macOS artifact, not user content).
        if entry.file_name().to_str().is_some_and(crate::is_apple_double) {
            continue;
        }
        let rel = p.strip_prefix(base).unwrap_or(&p);
        let dst = output_root.join(rel);
        if p.is_dir() {
            collect(base, &p, output_root, frames, sidecars, visited)?;
        } else if p.is_file() {
            let is_dng = p
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("dng"))
                .unwrap_or(false);
            if is_dng {
                frames.push((p, dst));
            } else {
                sidecars.push((p, dst));
            }
        }
    }
    Ok(())
}

/// per-frame work item for `process_dir` (clippy too_many_arguments
/// allow — the flat parameter list is the internal plumbing, not an API).
#[allow(clippy::too_many_arguments)]
fn process_one(
    src: &Path,
    dst: &Path,
    verify: bool,
    force: bool,
    mode: Mode,
    downscale: bool,
    fast: bool,
    lossy_format: LossyFormat,
    reference: &ReferenceDctOpts,
    qc_rel: Option<&str>,
    profiles: Option<&crate::camera::ProfileSet>,
) -> Outcome {
    let file = src
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| src.display().to_string());
    if dst.exists() && !force {
        let in_bytes = std::fs::metadata(src).map(|m| m.len()).unwrap_or(0);
        return Outcome::Skipped { file, in_bytes };
    }
    match run(
        src,
        dst,
        verify,
        mode,
        downscale,
        fast,
        lossy_format,
        reference,
        qc_rel,
        profiles,
    ) {
        Ok(stats) => Outcome::Done(stats),
        Err(err) => {
            eprintln!("FAIL {file}: {err:#}");
            Outcome::Failed {
                file,
                error: format!("{err:#}"),
            }
        }
    }
}

/// Look up a frame's measured reference MAE in a `quality_<preset>.tsv`
/// (tab-separated, first column = frame file name, second = mae — the
/// dct2s quality TSV, STEP 0). `Err` when the file or the row is
/// missing (a silent skip would turn the G2 band gate into a no-op).
pub(crate) fn read_reference_mae(tsv: &Path, frame_file: &str) -> Result<f64> {
    let text = std::fs::read_to_string(tsv)
        .with_context(|| format!("read reference MAE tsv {}", tsv.display()))?;
    for line in text.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() >= 2 && cols[0] == frame_file {
            return cols[1].parse::<f64>().with_context(|| {
                format!(
                    "reference MAE tsv {}: bad mae value in row {}",
                    tsv.display(),
                    cols[0]
                )
            });
        }
    }
    Err(anyhow::anyhow!(
        "reference MAE tsv {} has no row for frame {}",
        tsv.display(),
        frame_file
    ))
}

/// Build the downscale2x proxy geometry from the source frame .
/// `original_size` = the source's DefaultCropSize (50720) verbatim — the
/// original's default final size (DefaultScale absent ⇒ ×1.0). `crop_origin`
/// = the elementwise floor of the source's DefaultCropOrigin (50719) —
/// the measured ds2x writes this truncation
/// ((8,5) → (4,2)), not the spec default (0,0).
pub(crate) fn build_ds2x(src: &[u8], frame: &crate::tiff::Frame) -> Result<crate::surgery::Ds2x> {
    let crop = crate::surgery::ifd_tag_longs(src, frame, 50720)?;
    if crop.len() != 2 {
        anyhow::bail!(
            "DefaultCropSize (50720) must be count 2, got {}",
            crop.len()
        );
    }
    let origin = crate::surgery::ifd_tag_longs(src, frame, 50719)?;
    if origin.len() != 2 {
        anyhow::bail!(
            "DefaultCropOrigin (50719) must be count 2, got {}",
            origin.len()
        );
    }
    let active = crate::surgery::ifd_tag_longs(src, frame, 50829)?;
    if active.len() != 4 {
        anyhow::bail!("ActiveArea (50829) must be count 4, got {}", active.len());
    }
    Ok(crate::surgery::Ds2x {
        width: frame.width / 2,
        height: frame.height / 2,
        crop_origin: crate::surgery::ds2x_crop_origin([origin[0], origin[1]]),
        crop_size: [crop[0] / 2, crop[1] / 2],
        active_area: [active[0] / 2, active[1] / 2, active[2] / 2, active[3] / 2],
        original_size: [crop[0], crop[1]],
    })
}

/// The clip key of a collected frame = its parent dir relative to the
/// ingest root ("" = directly under the root — the flat single-clip
/// layout). The fp writes one clip per directory, so the directory is
/// the clip; the manifest's relpath parent dir uses the SAME key space
/// (the count gate compares in it). `pub` for the run report
/// module (the per-clip stats aggregate over the SAME key space).
/// The C9 clip selection filter: the
/// collected frames + sidecars restricted to the run's active
/// selection (absent = the full set — the byte-identity path, this
/// filter is a no-op). Frames: the clip key (the parent dir relative
/// to the input — `clip_key_of`) must be in the selected set. Sidecars:
/// only the selected clips' sidecars — the input-root sidecars (clip
/// key "" — the input's manifest.tsv / run-level records) are NOT
/// mirrored into a partial output (they declare the full tree;
/// documented).
fn apply_selection(
    input: &Path,
    frames: &mut Vec<(PathBuf, PathBuf)>,
    sidecars: &mut Vec<(PathBuf, PathBuf)>,
) {
    let Some(active) = crate::selection::current() else {
        return;
    };
    let sel = &active.selected;
    frames.retain(|(src, _)| sel.contains(&clip_key_of(input, src)));
    sidecars.retain(|(src, _)| {
        let k = clip_key_of(input, src);
        !k.is_empty() && sel.contains(&k)
    });
}

pub fn clip_key_of(root: &Path, frame_in: &Path) -> String {
    frame_in
        .strip_prefix(root)
        .ok()
        .and_then(|rel| rel.parent().filter(|p| !p.as_os_str().is_empty()))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The display form of a clip key ("" = the input root itself) —
/// shared with the audit's ingest-continuity surface.
pub fn display_clip(clip: &str) -> String {
    if clip.is_empty() {
        ".".into()
    } else {
        clip.to_string()
    }
}

/// The `input/manifest.tsv` expected-count ledger (the ingest manifest
/// written at offload — e.g. a batch-manifest file:
/// an optional header line + one row per file, relpath relative to the
/// ingest root. Returns the declared DNG frame count per clip key (the
/// relpath's parent dir — the same key space as `clip_key_of`; a flat
/// row maps to "" = the input root). A row that is not
/// `relpath<TAB>…` with a non-empty relpath is a hard named error
/// (MANIFEST_BAD — a corrupt ledger cannot be trusted).
pub(crate) fn parse_manifest_counts(path: &Path) -> Result<std::collections::BTreeMap<String, u64>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut counts: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        let lineno = i + 1;
        if line.is_empty() {
            continue;
        }
        let (rel, _rest) = match line.split_once('\t') {
            Some(kv) => kv,
            None => {
                if i == 0 {
                    continue; // a bare title line (no tab)
                }
                return Err(format!(
                    "manifest {} line {lineno}: not a `relpath<TAB>…` row: {line:?}",
                    path.display()
                ));
            }
        };
        if rel == "relpath" || rel.is_empty() {
            if rel.is_empty() {
                return Err(format!(
                    "manifest {} line {lineno}: empty relpath column",
                    path.display()
                ));
            }
            continue; // the known header row
        }
        if rel.rsplit('.')
            .next()
            .map(|s| s.eq_ignore_ascii_case("dng"))
            .unwrap_or(false)
        {
            let clip = match rel.rfind('/') {
                Some(pos) => rel[..pos].to_string(),
                None => String::new(),
            };
            *counts.entry(clip).or_insert(0) += 1;
        }
    }
    Ok(counts)
}

/// One clip's gate verdict — the compact PASS block + the named
/// FAIL lines.
#[derive(Clone, Debug, PartialEq)]
pub struct ClipVerdict {
    /// The clip key (the relative frame dir; "" = the input root).
    pub clip: String,
    /// The .DNG frames found on disk in this clip.
    pub frames_found: u64,
    /// The manifest.tsv declared DNG count for this clip (None = no
    /// manifest.tsv in the input root, or the clip is undeclared).
    pub manifest_declared: Option<u64>,
    /// The (min, max) frame number over the parseable frames (None = no
    /// parseable frame).
    pub frame_range: Option<(u64, u64)>,
    /// The TC display of the first/last parseable frame that carries a
    /// TC (None = no parseable frame carries one).
    pub tc_start: Option<String>,
    pub tc_end: Option<String>,
    /// The absolute 24 fps frame count (the tag 51044 arithmetic domain
    /// — `Smpte12m::total_frames`) of the first/last parseable frame
    /// that carries a TC (None = no parseable frame carries one) — the
    /// reel gate's per-clip tc_first/tc_last accessors (the
    /// tc_start/tc_end display strings stay the human form).
    pub tc_first_frames: Option<u64>,
    pub tc_last_frames: Option<u64>,
    /// The named FAIL lines (each `FAIL <CLASS> clip=<key>: …`).
    pub failures: Vec<String>,
}

/// One reel-gate pair verdict: the
/// cross-clip TC continuity check between clip N and clip N+1 in
/// ingest order. The gate shape is PINNED by the measured fp fact
/// (the continuous running clock, the NO cross-clip overlap):
/// clip N+1's TC start must be STRICTLY GREATER than clip N's TC end;
/// equal or earlier = overlap (double capture) = the named FAIL. The
/// gaps between clips are FREE (no declared window, no span-continuity
/// claim — the inter-take gaps are real inter-take wall time).
#[derive(Clone, Debug, PartialEq)]
pub struct ReelPairVerdict {
    /// The clip keys of the adjacent pair (ingest order).
    pub clip_prev: String,
    pub clip_next: String,
    /// The TC display of clip N's last parseable TC frame / clip N+1's
    /// first (None = that clip carries no parseable TC — the pair is
    /// incomparable; the absence is already named per frame by the
    /// per-clip TC_MISSING lines).
    pub prev_tc_end: Option<String>,
    pub next_tc_first: Option<String>,
    /// The absolute-frame delta (next tc_first − prev tc_end) — None =
    /// the pair is incomparable (a side without a parseable TC).
    pub delta: Option<i64>,
    /// True when the pair passes (strictly after) or is incomparable
    /// (no FAIL is invented for what the per-clip gates already name).
    pub ok: bool,
    /// The named FAIL line (None when ok / incomparable).
    pub fail_line: Option<String>,
}

/// The reel gate's verdict over the whole ingest (all adjacent clip
/// pairs in ingest order). A pair is incomparable (not a FAIL) when
/// either clip carries no parseable TC — the per-frame TC_MISSING
/// lines name that clip already.
#[derive(Clone, Debug, PartialEq)]
pub struct ReelVerdict {
    /// One entry per adjacent clip pair (ingest order).
    pub pairs: Vec<ReelPairVerdict>,
    /// The named FAIL lines (deterministic order: the pair order).
    pub failures: Vec<String>,
}

impl ReelVerdict {
    pub fn is_pass(&self) -> bool {
        self.failures.is_empty()
    }
}

/// The reel gate: over `clips` in
/// ingest order (the offload-manifest order — the sorted clip key
/// order, the same order the offload's per-clip blocks and the gate's
/// own clip list use), clip N+1's TC first frame must be STRICTLY
/// AFTER clip N's TC last frame (in the absolute 24 fps frame count).
/// Equal or earlier = the named `REEL_OVERLAP` FAIL (a double capture
/// — the same frames captured twice; the ingest cannot be trusted). A
/// gap of any size (including a big one) = PASS (the gaps are free —
/// the measured fact: no span-continuity claim). The within-clip
/// strict +1/frame contract is untouched — the reel gate is
/// the BETWEEN-clips half.
pub fn reel_check(clips: &[ClipVerdict]) -> ReelVerdict {
    let mut pairs: Vec<ReelPairVerdict> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for w in clips.windows(2) {
        let (a, b) = (&w[0], &w[1]);
        match (a.tc_last_frames, b.tc_first_frames) {
            (Some(prev_end), Some(next_first)) => {
                let delta = next_first as i64 - prev_end as i64;
                if delta > 0 {
                    pairs.push(ReelPairVerdict {
                        clip_prev: a.clip.clone(),
                        clip_next: b.clip.clone(),
                        prev_tc_end: a.tc_end.clone(),
                        next_tc_first: b.tc_start.clone(),
                        delta: Some(delta),
                        ok: true,
                        fail_line: None,
                    });
                } else {
                    let relation = if delta == 0 {
                        "equal".to_string()
                    } else {
                        format!("earlier by {} frame(s)", -delta)
                    };
                    let line = format!(
                        "FAIL REEL_OVERLAP clip={} -> clip={}: TC end of {} ({}) vs TC first of {} ({}): {relation}, delta {delta} (expected > 0 — strictly after; the gaps between clips are free — an overlap is a double capture)",
                        display_clip(&a.clip),
                        display_clip(&b.clip),
                        display_clip(&a.clip),
                        a.tc_end.clone().unwrap_or_else(|| "-".into()),
                        display_clip(&b.clip),
                        b.tc_start.clone().unwrap_or_else(|| "-".into()),
                    );
                    failures.push(line.clone());
                    pairs.push(ReelPairVerdict {
                        clip_prev: a.clip.clone(),
                        clip_next: b.clip.clone(),
                        prev_tc_end: a.tc_end.clone(),
                        next_tc_first: b.tc_start.clone(),
                        delta: Some(delta),
                        ok: false,
                        fail_line: Some(line),
                    });
                }
            }
            _ => pairs.push(ReelPairVerdict {
                clip_prev: a.clip.clone(),
                clip_next: b.clip.clone(),
                prev_tc_end: a.tc_end.clone(),
                next_tc_first: b.tc_start.clone(),
                delta: None,
                ok: true,
                fail_line: None,
            }),
        }
    }
    ReelVerdict { pairs, failures }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::testutil::*;
    /// A symlinked directory cycle must not recurse
    /// unboundedly (symlinked entries are refused; (dev,ino) visited-set),
    /// and sidecars are reported only when actually copied (a second run
    /// skips the existing one and reports nothing).
    #[test]
    fn collect_refuses_symlink_cycles_and_sidecar_report() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        let tmp = std::env::temp_dir().join("frameprism_symlink_test");
        let _ = std::fs::remove_dir_all(&tmp);
        let input = tmp.join("in");
        std::fs::create_dir_all(input.join("a/b")).unwrap();
        std::fs::write(input.join("note.txt"), b"sidecar").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(input.join("a"), input.join("a/b/loop")).unwrap();
        }
        let output = tmp.join("out");

        // First run: completes without recursing into the cycle; 0 frames,
        // 1 sidecar copied + reported. (Empty subdirs are not mirrored —
        // the worker only creates dirs that receive files; the symlinked
        // `loop` entry is refused, not mirrored.)
        let report = process_dir(
            &input,
            &output,
            false,
            false,
            1,
            Mode::Lossless,
            false,
            false, // fast (lossless single-candidate) — off in this test
            false,
            LossyFormat::K34892,
            &ReferenceDctOpts::default(),
            None, // --to
            false, // qc_gate
        )
        .expect("symlink cycle must not break the run");
        assert!(report.outcomes.is_empty(), "no .DNG frames in this fixture");
        assert_eq!(report.copied_sidecars, vec!["note.txt".to_string()]);
        assert!(output.join("note.txt").exists());
        assert!(
            !output.join("a/b/loop").exists(),
            "symlinked entries are refused"
        );

        // Second run: the sidecar exists → skipped → NOT reported
        // (review: report only actually-copied names).
        let report = process_dir(
            &input,
            &output,
            false,
            false,
            1,
            Mode::Lossless,
            false,
            false, // fast (lossless single-candidate) — off in this test
            false,
            LossyFormat::K34892,
            &ReferenceDctOpts::default(),
            None, // --to
            false, // qc_gate
        )
        .expect("second run");
        assert!(
            report.copied_sidecars.is_empty(),
            "skipped sidecar must not be reported"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// b2-review F1 (unit): the per-PRESET MAE-ratio distribution gate is
    /// FATAL only for the VBR presets; CBR presets print the line but never
    /// fail on it. Regression guard: before the scope fix, `--verify` +
    /// `--reference-mae-tsv` on a CBR preset exited nonzero on
    /// `count(r<0.5) > 0` (the flat-tail frames where we are 2:1 BETTER
    /// than the measured encoder) even though every per-frame hard gate passed.
    #[test]
    fn g2_distribution_gate_scoping_is_vbr_only() {
        assert!(g2_distribution_gate_is_fatal(Mode::VbrHq));
        assert!(g2_distribution_gate_is_fatal(Mode::VbrLt));
        assert!(!g2_distribution_gate_is_fatal(Mode::Cbr3));
        assert!(!g2_distribution_gate_is_fatal(Mode::Cbr4));
        assert!(!g2_distribution_gate_is_fatal(Mode::Cbr5));
        assert!(!g2_distribution_gate_is_fatal(Mode::Cbr7));
        assert!(!g2_distribution_gate_is_fatal(Mode::Lossless));
        assert!(!g2_distribution_gate_is_fatal(Mode::Log10));
    }

    /// The four foreign-camera variants (a)-(d) through process_dir:
    /// each must be the NAMED refusal (the run-gate summary) + ZERO
    /// output (the gate refuses before any compressed write — the
    /// output dir is empty). The exact class lines are pinned by the
    /// camera.rs resolver tests; the frames carry a valid TimeCodes
    /// tag so the camera gate (not the TC gate) is the refusal under
    /// test (identity precedes integrity).
    #[test]
    fn p8d11_gate_refuses_the_four_foreign_variants_named_zero_output() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        let variants: [(&str, &str, u32, u32, u16, u16); 4] = [
            ("a", "ACME", 1024, 768, 12, 32803), // class 1: unknown camera
            ("b", "SIGMA", 4000, 3000, 12, 32803), // class 2: unmeasured geometry
            ("c", "SIGMA", 3856, 2170, 14, 32803), // class 3: unmeasured depth
            ("d", "SIGMA", 3856, 2170, 12, 1), // class 4: CFA photometric mismatch
        ];
        for (tag, model, w, h, bps, photo) in &variants {
            let make = if *tag == "a" { "ACME" } else { "SIGMA" };
            let model = if *tag == "a" { "ACME-1" } else { "SIGMA fp" };
            let bytes = crate::camera::synth_dng_frame(
                make, model, *w, *h, *bps, *photo, Some([0u8; 8]),
            );
            let (input, output, base) =
                camera_gate_fixture(tag, "A001_001_20260701_000001.DNG", &bytes);
            let err = process_dir(
                &input,
                &output,
                false,
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
            .unwrap_err();
            let msg = format!("{err:?}");
            assert!(
                msg.contains("camera gate: 1 named FAIL line(s)"),
                "variant ({tag}) — the run-gate named refusal: {msg}"
            );
            // The refusal leaves NOTHING in the output dir (0
            // compressed — the gate fires before any write).
            let leftovers = std::fs::read_dir(&output)
                .map(|rd| rd.flatten().count())
                .unwrap_or(0);
            assert_eq!(leftovers, 0, "variant ({tag}) — the refused run writes nothing");
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    /// A profiled (A001-identity) frame passes the gate to the routing
    /// UNCHANGED: the FHD 1936x1090 @10 synthetic (the archive layout —
    /// the native-depth tile path) encodes end to end.
    #[test]
    fn p8d11_gate_passes_a_profiled_frame_end_to_end() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        let bytes = crate::camera::synth_dng_frame(
            "SIGMA", "SIGMA fp", 1936, 1090, 10, 32803, Some([0u8; 8]),
        );
        let (input, output, base) =
            camera_gate_fixture("profiled", "A001_001_20260701_000001.DNG", &bytes);
        let report = process_dir(
            &input,
            &output,
            false,
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
        .expect("a profiled frame must encode (the gate is a no-op for A001)");
        assert!(
            matches!(report.outcomes[0], Outcome::Done(_)),
            "the profiled frame must be Done: {:?}",
            report.outcomes[0]
        );
        assert!(output.join("A001_001_20260701_000001.DNG").is_file());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The Open Gate 2K (2016×1344, 12-bit, the modified
    /// firmware 5.02): the new geometry rides the ARCHIVE branch end to
    /// end. The profiled frame passes the camera gate (the new
    /// `2016 1344 12 archive` row — the identity layer), the routing
    /// predicate (`is_archive_layout`) selects the native-depth tile
    /// path (NOT the single-strip LJPEG fallback — the output carries
    /// the tile tag plan: 273/278/279 out, 322-325 in, 259 patched
    /// 1→7 — surgery.rs), the encode's OWN verify runs
    /// (`bit_exact_tiled_plane` + `metadata_preserved_tiled`, the
    /// verify=true surface), and the native depth is preserved (the
    /// output BitsPerSample 258 = the input's 12 — no up-conversion).
 /// RE-PINNED (the onboarding G2):
    /// the output's tile grid is the MEASURED per-gate 252×336 (the
 /// depth-invariant contract — the work's NAMED DIFF —
    /// supersedes the legacy pre-fix 482×272 shape; the test's
    /// discriminator — the tile path ran, not the fallback — is
    /// unchanged).
    #[test]
    fn open_gate_2k_rides_the_archive_branch_end_to_end() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        let bytes = crate::camera::synth_dng_frame(
            "SIGMA", "SIGMA fp", 2016, 1344, 12, 32803, Some([0u8; 8]),
        );
        let (input, output, base) =
            camera_gate_fixture("open-gate-2k", "A001_001_20260918_000001.DNG", &bytes);
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
        .expect("the Open Gate 2K frame must encode (the archive branch)");
        assert!(
            matches!(report.outcomes[0], Outcome::Done(_)),
            "the Open Gate 2K frame must be Done: {:?}",
            report.outcomes[0]
        );
        let out_path = output.join("A001_001_20260918_000001.DNG");
        assert!(out_path.is_file());
        let out = std::fs::read(&out_path).unwrap();
        // The ARCHIVE branch's tag plan on the output (the strip
        // fallback keeps 259 = 1 + no tile tags — the discriminator):
        // the tile tags present + the JPEG-lossless compression = the
        // tile path ran, not the single-strip LJPEG fallback.
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
 // RE-PINNED : the measured per-gate OG2K
 // grid 252×336 (the work's NAMED DIFF — the legacy 482×272 shape
        // is the decode-side backward-compat acceptance only):
        assert_eq!(e.u32(&t322.value_raw), 252, "322 = 252 (the measured OG2K tile width)");
        let t323 = find(323).expect("tag 323 (TileLength) — the tile plan");
        assert_eq!(e.u32(&t323.value_raw), 336, "323 = 336 (the measured OG2K tile height)");
        // The native depth is preserved (the output 258 = the input's):
        let t258 = find(258).expect("tag 258 (BitsPerSample) must be present");
        assert_eq!(
            e.u16(&t258.value_raw),
            12,
            "the output BitsPerSample must be the input's (12 — no up-conversion)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The unresolvable profile set = the named refusal (the tool does
 // not encode without its camera identity — the posture decision, same
    // as the pins). The pure resolution core over two empty dirs
    // (no env file, no profiles/ under either candidate) = the named
    // unresolvable class — the deterministic test surface (no env /
    // process-state probing).
    #[test]
    fn p8d11_unresolvable_set_is_the_named_refusal() {
        let tmp = std::env::temp_dir().join(format!("frameprism-camera-unresolvable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("cwd")).unwrap();
        std::fs::create_dir_all(tmp.join("exe")).unwrap();
        let err = crate::camera::resolve_core(None, &tmp.join("cwd"), &tmp.join("exe")).unwrap_err();
        assert!(
            err.starts_with("camera profile set unresolvable"),
            "{err}"
        );
        assert!(err.contains("the tool does not encode"), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ===================================================================
    // Ingest safety gate: TC parse + the synthetic-clip gate
    // ===================================================================

    #[test]
    fn process_dir_refuses_unwritable_to_before_any_frame() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        // The --to startup refusal: the dest is
        // probed BEFORE any frame (the rc=2 wiring in main) — a path
        // under a file is the named startup error.
        let base = std::env::temp_dir().join(format!("frameprism-unwritable-to-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("blocker"), b"file").unwrap();
        let input = base.join("in");
        std::fs::create_dir_all(&input).unwrap(); // an empty tree is fine: the probe precedes the gate
        let err = process_dir(
            &input,
            &base.join("out"),
            false,
            false,
            1,
            Mode::Lossless,
            false,
            false,
            false,
            LossyFormat::K34892,
            &ReferenceDctOpts::default(),
            Some(&base.join("blocker/dest")),
            false, // qc_gate
        )
        .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("create the --to dest dir") && msg.contains("blocker/dest"),
            "the named startup refusal: {msg}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The j92 entry point's `--to` band wiring:
    /// the six topologies through `process_dir` — the named
    /// refusal BEFORE any frame + the zero-writes proof (the output
    /// dir holds no frame; the distinct dest is never created —
    /// the band fires before the probe's dir creation). The empty
    /// input tree is fine: the band precedes the gate (the audit
    /// idiom). The shared helper's topology table + the exact lines
    /// are unit-pinned in offload/forms.rs
    /// (`to_band_six_topologies_refuse_named`); this battery
    /// proves the j92 wiring.
    #[test]
    fn to_band_refuses_before_any_frame() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        let base = std::env::temp_dir().join(format!(
            "frameprism-worker-to-band-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let entries = |p: &Path| {
            std::fs::read_dir(p).map(|rd| rd.flatten().count()).unwrap_or(0)
        };
        let top_files = |p: &Path| {
            std::fs::read_dir(p)
                .map(|rd| rd.flatten().filter(|e| e.path().is_file()).count())
                .unwrap_or(0)
        };
        let refuse = |tag: &str, input: &Path, output: &Path, to: &Path, phrase: &str| {
            let err = process_dir(
                input,
                output,
                false,
                false,
                1,
                Mode::Lossless,
                false,
                false,
                false,
                LossyFormat::K34892,
                &ReferenceDctOpts::default(),
                Some(to),
                false, // qc_gate
            )
            .unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains(phrase), "{tag}: the named refusal — {msg}");
        };
        // (1) identity output — the headline case.
        let in1 = base.join("1").join("in");
        let out1 = base.join("1").join("out");
        std::fs::create_dir_all(&in1).unwrap();
        refuse("1 identity-output", &in1, &out1, &out1, "is the encode output");
        assert_eq!(entries(&out1), 0, "1: the output dir holds nothing (the zero-writes proof)");
        // (2) the dest nested in the output.
        let in2 = base.join("2").join("in");
        let out2 = base.join("2").join("out");
        std::fs::create_dir_all(&in2).unwrap();
        let to2 = out2.join("sub");
        refuse("2 nested-in-output", &in2, &out2, &to2, "is inside the encode output");
        assert!(!to2.exists(), "2: the dest was never created (the band precedes the probe)");
        assert_eq!(entries(&out2), 0, "2: the output dir holds nothing");
        // (3) the output nested in the dest.
        let in3 = base.join("3").join("in");
        let outer3 = base.join("3").join("outer");
        let out3 = outer3.join("out");
        std::fs::create_dir_all(&in3).unwrap();
        refuse("3 output-nested-in-to", &in3, &out3, &outer3, "contains the encode output");
        assert_eq!(top_files(&outer3), 0, "3: the dest root holds no file (only the output dir)");
        // (4) identity input — the verify-only no-op (refused,
        // not documented).
        let in4 = base.join("4").join("in");
        let out4 = base.join("4").join("out");
        std::fs::create_dir_all(&in4).unwrap();
        refuse("4 identity-input", &in4, &out4, &in4, "is the encode input");
        assert_eq!(entries(&in4), 0, "4: the input tree is untouched");
        assert_eq!(entries(&out4), 0, "4: the output dir holds nothing");
        // (5) the dest nested in the input (the card-surface class).
        let in5 = base.join("5").join("in");
        let out5 = base.join("5").join("out");
        std::fs::create_dir_all(&in5).unwrap();
        let to5 = in5.join("sub");
        refuse("5 nested-in-input", &in5, &out5, &to5, "is inside the encode input");
        assert!(!to5.exists(), "5: the dest was never created (the band precedes the probe)");
        assert_eq!(entries(&out5), 0, "5: the output dir holds nothing");
        // (6) the input nested in the dest.
        let outer6 = base.join("6").join("outer2");
        let in6 = outer6.join("in");
        let out6 = base.join("6").join("out");
        std::fs::create_dir_all(&in6).unwrap();
        refuse("6 input-nested-in-to", &in6, &out6, &outer6, "contains the encode input");
        assert_eq!(top_files(&outer6), 0, "6: the dest root holds no file (only the input dir)");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The benign-config regression pin (the band must
    /// NOT over-refuse): a `--to` outside both trees completes the
    /// encode + the post-encode offload. The product at the output
    /// is the encode result (NOT the raw source — the
    /// regression property: the product is intact), the dest holds
    /// the RAW mirror byte-identical (the offload's contract). The
    /// jxl benign pin is not added (the shared band
    /// = one code path — the jxl startup path has no codec-
    /// specific divergence before the band site).
    #[test]
    fn to_outside_both_completes() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        camera_profile_override();
        let bytes = crate::camera::synth_dng_frame(
            "SIGMA", "SIGMA fp", 1936, 1090, 10, 32803, Some([0u8; 8]),
        );
        let name = "A001_001_20260701_000001.DNG";
        let base = std::env::temp_dir().join(format!(
            "frameprism-benign-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        std::fs::create_dir_all(&input).unwrap();
        std::fs::write(input.join(name), &bytes).unwrap();
        let output = base.join("out");
        let to = base.join("to-dest");
        let report = process_dir(
            &input,
            &output,
            false,
            false,
            1,
            Mode::Lossless,
            false,
            false, // fast
            false, // checksums
            LossyFormat::K34892,
            &ReferenceDctOpts::default(),
            Some(&to),
            false, // qc_gate
        )
        .expect("the disjoint --to must complete (the band must not over-refuse)");
        assert!(
            matches!(report.outcomes[0], Outcome::Done(_)),
            "the frame encodes: {:?}",
            report.outcomes[0]
        );
        // The encode product at the output — and it is NOT the raw
        // source (the regression property: a self-referential
        // `--to` would have overwritten it with the raw source).
        let product =
            std::fs::read(output.join(name)).expect("the encoded frame at the output");
        assert_ne!(product, bytes, "the product is the encode result, not the raw source");
        // The --to dest holds the RAW mirror (the post-encode
        // offload's contract — the source bytes, byte-identical).
        let mirror = std::fs::read(to.join(name)).expect("the raw mirror at the --to dest");
        assert_eq!(mirror, bytes, "the mirror is the raw source, byte-identical");
        let _ = std::fs::remove_dir_all(&base);
    }

    // =====================================================================
    // — the reel gate (the cross-clip TC continuity — the
    // between-clips half of). The gate shape is pinned by the
 // measured fp fact: tc_first monotonicity + overlap;
    // the gaps between clips are FREE (no span-continuity claim).
    // =====================================================================

    #[test]
    fn p72_reel_check_synthetic_sequences() {
        // Monotonic pass: B starts one frame after A ends (delta +1).
        let clips = vec![
            synth_clip("A", Some((0, 0, 0, 0)), Some((0, 0, 0, 10))),
            synth_clip("B", Some((0, 0, 0, 11)), Some((0, 0, 0, 20))),
        ];
        let v = reel_check(&clips);
        assert!(v.is_pass(), "monotonic must pass: {:?}", v.failures);
        assert_eq!(v.pairs.len(), 1);
        assert_eq!(v.pairs[0].delta, Some(1));
        // Big-gap free pass: a 1000-frame inter-take gap is a PASS
        // (the explicit no-span-continuity assertion — gaps are free).
        let clips = vec![
            synth_clip("A", Some((0, 0, 0, 0)), Some((0, 0, 0, 10))),
            synth_clip("C", Some((0, 1, 0, 0)), Some((0, 1, 0, 10))),
        ];
        let v = reel_check(&clips);
        assert!(v.is_pass(), "a big gap must pass (free): {:?}", v.failures);
        assert_eq!(v.pairs[0].delta, Some(1440 - 10), "the 1430-frame inter-take gap is free (24 fps: 1 min = 1440 frames)");
        // Equal-boundary fail: B's first frame == A's last frame
        // (delta 0 = overlap — the named equal case).
        let clips = vec![
            synth_clip("A", Some((0, 0, 0, 0)), Some((0, 0, 0, 10))),
            synth_clip("B", Some((0, 0, 0, 10)), Some((0, 0, 0, 20))),
        ];
        let v = reel_check(&clips);
        assert!(!v.is_pass(), "equal boundary must fail");
        assert_eq!(v.failures.len(), 1);
        assert!(v.failures[0].starts_with("FAIL REEL_OVERLAP clip=A -> clip=B"), "{:?}", v.failures);
        assert!(v.failures[0].contains("equal"), "the named relation: {:?}", v.failures);
        assert!(v.failures[0].contains("delta 0"), "the raw delta: {:?}", v.failures);
        assert_eq!(v.pairs[0].delta, Some(0));
        assert!(!v.pairs[0].ok);
        // Overlap fail: B starts 5 frames BEFORE A ends (delta -5).
        let clips = vec![
            synth_clip("A", Some((0, 0, 0, 0)), Some((0, 0, 0, 10))),
            synth_clip("B", Some((0, 0, 0, 5)), Some((0, 0, 0, 15))),
        ];
        let v = reel_check(&clips);
        assert!(!v.is_pass(), "overlap must fail");
        assert!(v.failures[0].contains("earlier by 5 frame(s)"), "{:?}", v.failures);
        assert_eq!(v.pairs[0].delta, Some(-5));
        // Incomparable pair (a side without a parseable TC) is NOT a
        // FAIL — the absence is already named per frame (TC_MISSING).
        let clips = vec![
            synth_clip("A", Some((0, 0, 0, 0)), Some((0, 0, 0, 10))),
            synth_clip("B", None, None),
        ];
        let v = reel_check(&clips);
        assert!(v.is_pass(), "an incomparable pair is not a FAIL: {:?}", v.failures);
        assert_eq!(v.pairs[0].delta, None);
        // A single clip = no pairs = PASS (the reel check is a no-op).
        let v = reel_check(&[synth_clip("A", Some((0, 0, 0, 0)), Some((0, 0, 0, 10)))]);
        assert!(v.is_pass());
        assert!(v.pairs.is_empty());
        // Three clips: every adjacent pair is checked (ingest order).
        let clips = vec![
            synth_clip("A", Some((0, 0, 0, 0)), Some((0, 0, 0, 10))),
            synth_clip("B", Some((0, 0, 0, 11)), Some((0, 0, 0, 20))),
            synth_clip("C", Some((0, 0, 0, 5)), Some((0, 0, 0, 30))),
        ];
        let v = reel_check(&clips);
        assert!(!v.is_pass(), "the second pair overlaps: {:?}", v.failures);
        assert_eq!(v.failures.len(), 1, "only the B -> C pair fails: {:?}", v.failures);
        assert!(v.failures[0].starts_with("FAIL REEL_OVERLAP clip=B -> clip=C"), "{:?}", v.failures);
    }

    /// G2-7 (the encode source walker — `collect`): the smallest shape
    /// (one real frame + a `._<frame>.DNG` garbage shadow in the source
    /// tree + a non-DNG `._*` shadow) → the encode/ingest path sees
    /// ONLY the real frames (no phantom frame row; no `._*` sidecar in
    /// the mirror). Direct unit vector on the private `collect` (the
    /// dry-run substitution was unnecessary — the same `collect` is
    /// the ingest's frame/sidecar split).
    #[test]
    fn spec7_g2_collect_skips_the_apple_double_shadows() {
        let tmp = std::env::temp_dir().join(format!("frameprism-spec7-g2-collect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("A001_20260101_000001.DNG"), b"frame-bytes").unwrap();
        // The field shape: a BINARY shadow twin of the frame (the
        // pre-fix class: ENCODED as a frame) + a non-DNG shadow (the
        // pre-fix class: mirrored as a sidecar).
        std::fs::write(tmp.join("._A001_20260101_000001.DNG"), vec![0xFFu8, 0xFE, 0xFF]).unwrap();
        std::fs::write(tmp.join("._notes.txt"), b"shadow-bytes").unwrap();
        let out_root = tmp.join("out");
        let mut frames: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut sidecars: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut visited = std::collections::HashSet::new();
        collect(&tmp, &tmp, &out_root, &mut frames, &mut sidecars, &mut visited).unwrap();
        assert_eq!(frames.len(), 1, "only the real frame is a frame: {frames:?}");
        assert_eq!(frames[0].0, tmp.join("A001_20260101_000001.DNG"), "{frames:?}");
        assert!(sidecars.is_empty(), "no `._*` sidecar in the mirror: {sidecars:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
