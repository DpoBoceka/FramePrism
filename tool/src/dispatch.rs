//! The dispatch — the command execution.
//!
//! `pin_gate` (the A1 pin self-check — resolve the pins file, probe
//! the FULL contract set, and either record the state for the run
//! report or refuse NAMED + rc=2 + zero output before the first
//! byte) · `finish_tier` (the per-tier post-processing: the summary,
//! the report write, the verdict, the A3 ledger row, the status end
//! line, the rc) · `run_both` (the `--codec both` dispatch:
//! sequential j92 → jxl, fail-fast on the j92 verdict) ·
//! `tier_summary` (the final both line's per-tier segment) ·
//! `ENCODE_USAGE_PREFIXES` (the named usage-class refusals of the
//! legacy encode — a usage-class rc=2 never starts a run, so it
//! appends NO ledger row; the `REFUSED_*` classes are the safety
//! gates') · `dryrun_dispatch` (the `--dry-run` predict-then-measure
//! arc) · `run` (the single-tier encode: the scope guards + the
//! j92/jxl routing) · `print_summary` (the human summary) ·
//! `display_jobs` · `write_report` (the TSV report —
//! manifest-compatible columns).

use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use frameprism::{ledger, pins, preflight, worker};

use crate::cli_model::{
    cli_args_string, selection_column, subset_context, tier_cli,
    Cli, CodecArg, JxlEffortArg, LossyFormatArg, ModeArg,
};

/// The legacy encode's per-tier post-processing (the extraction
/// of main's Ok/Err match — the standalone dispatch + the both
/// dispatch's per-tier runs share it VERBATIM: the summary, the
/// report write (its early rc=2 return is preserved — BEFORE the
/// ledger row + the status end line, the pre-existing order), the verdict,
/// the A3 ledger row, the status end line, the rc). Returns
/// (rc, verdict, total, ok, failed). `command` = the ledger's command
/// column (standalone = `legacy`; the both tiers = the actual CLI
/// string). `emit_status` = the end line (standalone j92 +
/// the both's j92 tier; the jxl tier never emits — the jxl path has no
/// status lines,: the both run's status file is the j92 block
/// only).
pub(crate) fn finish_tier(
    cli: &Cli,
    input: &Path,
    output: &Path,
    result: Result<worker::Report, anyhow::Error>,
    elapsed_s: f64,
    n_frames: u64,
    emit_status: bool,
    command: &str,
) -> (ExitCode, &'static str, usize, usize, usize) {
    match result {
        Ok(report) => {
            print_summary(cli, input, output, &report, elapsed_s);
            if let Some(path) = &cli.report {
                match write_report(path, &report, cli.verify) {
                    Ok(()) => eprintln!("report written to {}", path.display()),
                    Err(err) => {
                        eprintln!("error: failed to write report {}: {err:#}", path.display());
                        return (ExitCode::from(2), "FAIL", 0, 0, 0);
                    }
                }
            }
            let failed = report
                .outcomes
                .iter()
                .filter(|o| matches!(o, worker::Outcome::Failed { .. }))
                .count();
            let ok = report.outcomes.len() - failed;
            // the --qc-gate verdict count (the (a)+(b) named rows
            // — the encode-time computation is the authority: the
            // j92 tier's process_dir recorded the run's QC state
            // before the reports; the jxl path / a run without the
            // decode site carries none (0 — the jxl path's --qc-gate
            // is the named no-op note)). 0 when the gate is off
            // (the default run never gates — report-only).
            let qc_hits = frameprism::qc::current().map(|st| st.gate_hits()).unwrap_or(0);
            let verdict: &'static str = if failed > 0
                || report.offload_dirty_rows.map(|k| k > 0).unwrap_or(false)
            {
                "FAIL"
            } else if qc_hits > 0 {
                // The --qc-gate verdict (the named-negative
                // convention — a distinct verdict, not a FAIL: the
                // run COMPLETES, no data loss, the files are written;
                // the gate is a verdict, not a preflight refusal).
                "QC_GATE"
            } else {
                "OK"
            };
            // The A3 ops-ledger row (the completed encode run — incl.
            // --to; the run journal's -history input).
            ledger::append_quiet(&ledger::Row {
                created: ledger::now_secs(),
                command: command.into(),
                tool_version: env!("CARGO_PKG_VERSION").into(),
                input: ledger::canon(input),
                output: ledger::canon(output),
                codec: cli.codec.to_string(),
                frames: report.outcomes.len() as u64,
                verdict: verdict.into(),
                duration_s: elapsed_s as u64,
                dest: cli
                    .to
                    .clone()
                    .map(|d| ledger::canon(&d))
                    .unwrap_or_default(),
                selection: selection_column(),
                // The NAMED subset opt-in's marker (the v3
                // `context` column — the same string as the per-clip
                // report's named line; empty = the default path).
                context: subset_context(cli),
            });
            // the end line (the verdict + the measured duration +
            // the resume count — the machine-readable run record).
            if emit_status {
                if let Some(st) = frameprism::status::current() {
                    st.emit(&format!(
                        "{{\"phase\":{},\"verdict\":{},\"frames_total\":{},\"frames_ok\":{},\"resumed\":{},\"duration_s\":{}}}",
                        frameprism::status::jstr("end"),
                        frameprism::status::jstr(verdict),
                        report.outcomes.len(),
                        ok,
                        frameprism::resume::current().map(|p| p.skipped()).unwrap_or(0),
                        elapsed_s as u64
                    ));
                }
            }
            let exit = if failed > 0 {
                ExitCode::from(1)
            } else if report.offload_dirty_rows.map(|k| k > 0).unwrap_or(false) {
                // The two-destination offload: any dirty row
                // is a named FAIL (the lines landed on stderr at the
                // offload step; the verdict line is in the run
                // report) → rc=1 AFTER the encode completes (the
                // encode is not blocked by the copy; the verdict is).
                ExitCode::from(1)
            } else if qc_hits > 0 {
                // the --qc-gate verdict (the named-
                // negative convention — the run COMPLETES: no data
                // loss, the files are written; the gate is a verdict,
                // not a preflight refusal). rc=2 = the verdict class
                // (distinct from the rc=1 failure class).
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            };
            (exit, verdict, report.outcomes.len(), ok, failed)
        }
        Err(err) => {
            // the end line on a failed run (verdict FAIL — the
            // named line above is the stderr record).
            if emit_status {
                if let Some(st) = frameprism::status::current() {
                    st.emit(&format!(
                        "{{\"phase\":{},\"verdict\":{},\"duration_s\":{}}}",
                        frameprism::status::jstr("end"),
                        frameprism::status::jstr("FAIL"),
                        elapsed_s as u64
                    ));
                }
            }
            // The A3 ledger: the safety-gate refusals name their class
            // (the ingest gate — both codecs' messages carry
            // "ingest"); a run-level error is a run that started and
            // failed → FAIL; the usage-class scope guards / input
            // checks never start a run → no row.
            let msg = format!("{err:#}");
            if !ENCODE_USAGE_PREFIXES.iter().any(|p| msg.starts_with(p)) {
                let verdict = if msg.contains("ingest") {
                    "REFUSED_INGEST"
                } else {
                    "FAIL"
                };
                ledger::append_quiet(&ledger::Row {
                    created: ledger::now_secs(),
                    command: command.into(),
                    tool_version: env!("CARGO_PKG_VERSION").into(),
                    input: ledger::canon(input),
                    output: ledger::canon(output),
                    codec: cli.codec.to_string(),
                    frames: n_frames,
                    verdict: verdict.into(),
                    duration_s: elapsed_s as u64,
                    dest: cli
                        .to
                        .clone()
                        .map(|d| ledger::canon(&d))
                        .unwrap_or_default(),
                    selection: selection_column(),
                    // A gate-refused run (incl. the
                    // REFUSED_INGEST kept-class refusal under the
                    // flag) still ran under the NAMED subset opt-in —
                    // the marker is honest for the refusal row too.
                    context: subset_context(cli),
                });
            }
            eprintln!("error: {err:#}");
            (ExitCode::from(2), "FAIL", 0, 0, 0)
        }
    }
}

/// The `--codec both` dispatch: sequential j92 → jxl —
/// the working tier FIRST: a dead run still has a usable working
/// archive), each tier its existing standalone path (the tier_cli copy
/// carries the per-tier codec/to/report). The both-specific surface =
/// the named lines only (the tier headers on stderr, the combined
/// preflight lines from guard_both, the final summary line on
/// stdout).
pub(crate) fn run_both(cli: &Cli, input: &Path, output: &Path, n_frames: u64) -> ExitCode {
    let out_jxl = preflight::jxl_sibling(output);
    let to_jxl = cli
        .to
        .as_ref()
        .map(|d| preflight::jxl_sibling(d));
    let command = cli_args_string();

    eprintln!("tier 1/2: j92 → {}", output.display());
    let tier92 = tier_cli(cli, CodecArg::J92, cli.to.clone(), cli.report.clone());
    let t92 = Instant::now();
    let result92 = run(&tier92, input, output);
    let (ec92, v92, n92, ok92, failed92) = finish_tier(
        &tier92,
        input,
        output,
        result92,
        t92.elapsed().as_secs_f64(),
        n_frames,
        true,
        &command,
    );
    let d92 = t92.elapsed().as_secs_f64();

    // fail-fast: the jxl tier starts ONLY if the j92 tier's
    // verdict is OK (a source-side failure fails both tiers — the
    // named line + the j92 tier's rc flavor; the OUT-jxl dir is NEVER
    // created: jxl::process_dir is its only creator and it never
    // runs).
    if v92 != "OK" {
        eprintln!("jxl tier not started (the j92 tier verdict is FAIL)");
        return ec92;
    }

    eprintln!("tier 2/2: jxl → {}", out_jxl.display());
    let tierx = tier_cli(
        cli,
        CodecArg::Jxl,
        to_jxl,
        cli
            .report
            .as_ref()
            .map(|p| preflight::jxl_sibling(p)),
    );
    let tx = Instant::now();
    let resultx = run(&tierx, input, &out_jxl);
    let (ecx, vxl, nxl, okx, failedx) = finish_tier(
        &tierx,
        input,
        &out_jxl,
        resultx,
        tx.elapsed().as_secs_f64(),
        n_frames,
        false,
        &command,
    );
    let dxl = tx.elapsed().as_secs_f64();

    // the final summary line (the per-tier frame counts +
    // durations — the human record of the two-tier run).
    println!(
        "both: {} + {}",
        tier_summary(v92, n92, ok92, failed92, d92),
        tier_summary(vxl, nxl, okx, failedx, dxl)
    );
    // rc: 0 iff both tiers OK; a tier FAIL = 1 (the failed tier's
    // rows/lines are the record; the OK tier stays on disk).
    if ecx == ExitCode::SUCCESS && ec92 == ExitCode::SUCCESS && v92 == "OK" && vxl == "OK" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// The final both line's per-tier segment (the shape): OK tiers
/// carry the frame count + duration; a FAIL tier carries the ok/failed
/// split.
fn tier_summary(verdict: &str, total: usize, ok: usize, failed: usize, d: f64) -> String {
    if failed == 0 {
        format!("{verdict} ({total} frames, {d:.1}s)")
    } else {
        format!("{verdict} ({ok} ok, {failed} failed, {d:.1}s)")
    }
}

/// The named usage-class refusals of the legacy encode (the A3 ledger
/// semantics — a usage-class rc=2 never starts a run, so it appends NO
/// ledger row; the `REFUSED_*` classes are reserved for the safety
/// gates). The prefixes are the in-tree bail messages of `run()` +
/// `jxl.rs` (the scope guards); a new pre-run bail added later appends
/// a spurious FAIL row at worst (never a lost one).
const ENCODE_USAGE_PREFIXES: &[&str] = &[
    "input is not a directory",
    "input and output must differ",
    "--jxl-effort requires",
    "--jxl-parallel requires",
    "--codec jxl is lossless-only",
    "--codec jxl does not combine",
    "--reference-ref/--reference-mae-tsv/--reference-structure-tsv require",
    // the resume scan's pre-run refusals (the corrupt sidecar,
    // the clip-name derivation — no frame/byte was written, so NO
    // ledger row, the usage-class semantics).
    "resume:",
    // the defensive both-dispatch invariant (never fires — the
    // both dispatch clones the tiers with the canonical codecs).
    "--codec both does not dispatch",
];

/// The A1 pin self-check gate (the archive-producing commands — the
/// legacy encode, bake, bake --iso): resolve the pins file,
/// probe the FULL contract set (a j92 run on a
/// drifted machine is a drifted machine), and either record the state
/// for the run report (Ok) or refuse NAMED (Err — the FAIL lines are
/// already on stderr + the REFUSED_PIN ledger row appended; the caller
/// returns rc=2 — ZERO output: the gate runs before any file is
/// created).
pub(crate) fn pin_gate(
    pins_flag: Option<&Path>,
    resolve: &pins::Resolve,
    command: &str,
    codec: &str,
    input: &Path,
    output: &Path,
) -> Result<(), ()> {
    let (path, probed) = pins::resolve_pins_path(pins_flag);
    let report = match &path {
        None => {
            // NOT found = a NAMED skip line (never silent, NOT a
            // refusal — installed-from-brew users have no repo; the CI
            // entrypoint remains the enforcement surface).
            let r = pins::PinReport {
                path: None,
                probed,
                states: vec![],
                note: None,
            };
            eprintln!("{}", r.skip_line());
            pins::set_current(r);
            return Ok(());
        }
        Some(p) => {
            let rows = match pins::parse_pins(p) {
                Ok(r) => r,
                Err(err) => {
                    // A corrupt pins file: named (not a silent skip, not
                    // a refusal — the contract file is unreadable; the
                    // CI entrypoint is the enforcement surface).
                    let note = format!(
                        "unreadable pins file {} ({err}) — pin self-check skipped (the CI entrypoint remains the enforcement surface)",
                        p.display()
                    );
                    eprintln!("note: pins: {note}");
                    let r = pins::PinReport {
                        path: None,
                        probed,
                        states: vec![],
                        note: Some(note),
                    };
                    pins::set_current(r);
                    return Ok(());
                }
            };
            pins::PinReport {
                path: Some(p.clone()),
                probed,
                states: pins::check(&rows, resolve),
                note: None,
            }
        }
    };
    if report.any_fail() {
        for line in report.fail_lines() {
            eprintln!("{line}");
        }
        eprintln!(
            "FAIL pin: {} component(s) drifted or missing — refusing (0 bytes written; the pins file is the byte-identity contract)",
            report.fail_lines().len()
        );
        pins::set_current(report.clone());
        ledger::append_quiet(&ledger::Row {
            created: ledger::now_secs(),
            command: command.into(),
            tool_version: env!("CARGO_PKG_VERSION").into(),
            input: ledger::canon(input),
            output: ledger::canon(output),
            codec: codec.into(),
            frames: 0,
            verdict: "REFUSED_PIN".into(),
            duration_s: 0,
            dest: String::new(),
            // The pin gate runs BEFORE the selection resolution (the
            // A1-first order): the column is always empty here.
            selection: String::new(),
            // The pin gate runs BEFORE the ingest gate (the run never
            // started): the column is always empty here.
            context: String::new(),
        });
        return Err(());
    }
    eprintln!("{}", report.pass_line());
    pins::set_current(report);
    Ok(())
}

/// The `--dry-run` dispatch ( the predict-then-measure arc):
/// the named surface refusals (rc=2 — the codec + the flag combos),
/// then the estimate (the verdict + the exit code from the dryrun
/// module). The encode flags flow into the sample encode
/// (`--mode`/`--lossy-format`/`--reference-*`/`--downscale2x`/`--fast`);
/// `--verify` is subsumed (the sample ALWAYS verifies — the honesty
/// anchor); `--jobs` is named-ignored (the sample loop is sequential —
/// the per-frame wall is jobs-independent); `--report` = the markdown
/// estimate record (NOT the TSV report — the TSV contract is the
/// encode mode's, frozen; the semantics split by mode is named).
pub(crate) fn dryrun_dispatch(cli: &Cli, input: &Path, output: &Path) -> ExitCode {
    // The named refusals (rc=2 — the dry run's surface is the
    // in-process j92 seam + the estimate-only flags).
    if cli.codec != CodecArg::J92 {
        eprintln!(
            "error: --codec {} is not supported with --dry-run (the in-memory seam is the in-process j92 encode; the jxl tier is the cjxl subprocess — it writes by design; the live `## live` section renders the named non-scope line)",
            cli.codec
        );
        return ExitCode::from(2);
    }
    let mut bad: Vec<&str> = Vec::new();
    if cli.to.is_some() {
        bad.push("--to");
    }
    if cli.resume {
        bad.push("--resume");
    }
    if cli.force {
        bad.push("--force");
    }
    if cli.checksums {
        bad.push("--checksums");
    }
    if cli.verify_checksums {
        bad.push("--verify-checksums");
    }
    if cli.qc_gate {
        bad.push("--qc-gate");
    }
    if cli.clips.is_some() {
        bad.push("--clips");
    }
    if cli.skip.is_some() {
        bad.push("--skip");
    }
    if cli.pins.is_some() {
        bad.push("--pins");
    }
    if cli.jxl_effort.is_some() {
        bad.push("--jxl-effort");
    }
    if cli.jxl_parallel.is_some() {
        bad.push("--jxl-parallel");
    }
    if cli.subset {
        bad.push("--subset");
    }
    if !bad.is_empty() {
        eprintln!(
            "error: {} is not supported with --dry-run (the dry run archives nothing — the named refusal; the estimate takes the encode flags --mode/--lossy-format/--reference-*/--downscale2x/--fast + --verify (subsumed) + --jobs (named-ignored) + --report (the markdown record) + --dry-run-frames)",
            bad.join(" ")
        );
        return ExitCode::from(2);
    }
    // The mode / the lossy format / the reference-file opts (the run conversions
    // mirrored — the reference-combo refusal included, the named line
    // byte-identical to the encode mode's).
    let mode = match cli.mode {
        ModeArg::Lossless => worker::Mode::Lossless,
        ModeArg::Log10 => worker::Mode::Log10,
        ModeArg::VbrHq => worker::Mode::VbrHq,
        ModeArg::VbrLt => worker::Mode::VbrLt,
        ModeArg::Cbr3 => worker::Mode::Cbr3,
        ModeArg::Cbr4 => worker::Mode::Cbr4,
        ModeArg::Cbr5 => worker::Mode::Cbr5,
        ModeArg::Cbr7 => worker::Mode::Cbr7,
    };
    let lossy_format = match cli.lossy_format {
        LossyFormatArg::K34892 => worker::LossyFormat::K34892,
        LossyFormatArg::ReferenceDct => worker::LossyFormat::ReferenceDct,
    };
    if (cli.reference_ref.is_some()
        || cli.reference_mae_tsv.is_some()
        || cli.reference_structure_tsv.is_some())
        && (!mode.is_lossy() || lossy_format != worker::LossyFormat::ReferenceDct)
    {
        eprintln!("error: --reference-ref/--reference-mae-tsv/--reference-structure-tsv require a lossy --mode with --lossy-format dct12");
        return ExitCode::from(2);
    }
    frameprism::dryrun::set_dryrun_flag(true);
    let opts = frameprism::dryrun::Opts {
        dest: output.to_path_buf(),
        k_override: cli.dry_run_frames,
        report: cli.report.clone(),
        mode,
        lossy_format,
        reference: worker::ReferenceDctOpts {
            reference_ref: cli.reference_ref.clone(),
            reference_mae_tsv: cli.reference_mae_tsv.clone(),
            reference_structure_tsv: cli.reference_structure_tsv.clone(),
        },
        downscale: cli.downscale2x,
        fast: cli.fast,
        jobs: cli.jobs,
        verify_flag: cli.verify,
    };
    let (_verdict, rc) = frameprism::dryrun::estimate(input, &opts);
    ExitCode::from(rc)
}

pub(crate) fn run(cli: &Cli, input: &Path, output: &Path) -> anyhow::Result<worker::Report> {
    if !input.is_dir() {
        anyhow::bail!("input is not a directory: {}", input.display());
    }
    if input == output {
        anyhow::bail!("input and output must differ");
    }
    // Scope guard (effort): --jxl-effort is only meaningful with
    // --codec jxl / both (both: it applies to the jxl tier);
    // an explicit flag on the j92 path is a hard reject (consistent
    // with the v1 lossless-only rejections). Absent flag + --codec
    // jxl = the e7 default, no rejection. (The j92 message is
    // byte-identical to the pre-existing one.)
    if cli.jxl_effort.is_some() && cli.codec == CodecArg::J92 {
        anyhow::bail!("--jxl-effort requires --codec jxl (got --codec j92)");
    }
    // Scope guard (the jxl-parallel flag): --jxl-parallel
    // is only meaningful with --codec jxl / both (both: it
    // applies to the jxl tier); an explicit flag on the j92 path is a hard reject
    // (consistent with the effort guard). Absent flag + --codec jxl =
    // the auto default, no rejection. (The jxl.rs helper is consulted
    // for the j92/jxl paths exactly as before — the j92 rejection
    // message is byte-identical; both admits the flag, since the
    // helper's message would name the wrong codec for the both
    // dispatch.)
    if cli.codec != CodecArg::Both {
        if let Some(msg) =
            frameprism::jxl::parallel_scope_refusal(&cli.codec.to_string(), cli.jxl_parallel.is_some())
        {
            anyhow::bail!("{msg}");
        }
    }
    // both never reaches run (run_both dispatches the per-tier
    // clones with the canonical codecs) — a defensive named bail keeps
    // the invariant loud (usage-class: no ledger row, rc=2).
    if cli.codec == CodecArg::Both {
        anyhow::bail!("--codec both does not dispatch through the single-tier run path (internal — a both-dispatch bug)");
    }
    if cli.codec == CodecArg::Jxl {
        // the v1 resume scope is the j92 encode + the bake
        // commands — the jxl sidecar is plane-based (the resume is the
        // named follow-up): the named rc=2 BEFORE any frame (the
        // ENCODE_USAGE_PREFIXES' `--codec jxl does not combine` class —
        // no ledger row, the pre-run refusal).
        if cli.resume {
            anyhow::bail!(
                "--codec jxl does not combine with --resume in v1 (the jxl sidecar is plane-based — the resume is refused named before any frame; re-run without --resume)"
            );
        }
        // JXL composition rejections (v1: clear error + nonzero exit,
        // never a silent ignore). `--checksums` is a no-op with a note
        // (the jxl sidecar is mandatory and a superset).
        if !matches!(cli.mode, ModeArg::Lossless) {
            anyhow::bail!(
                "--codec jxl is lossless-only in v1: --mode must be lossless (got {})",
                cli.mode
            );
        }
        if cli.downscale2x {
            anyhow::bail!("--codec jxl does not combine with --downscale2x in v1");
        }
        if cli.fast {
            anyhow::bail!("--codec jxl does not combine with --fast in v1");
        }
        if cli.checksums {
            eprintln!("note: --checksums is a no-op for --codec jxl (the mandatory <CLIP>.jxl-checksums.tsv sidecar is always written)");
        }
        if cli.qc_gate {
            // the deterministic QC class rides the j92 DECODE
            // site (the single pass over the decoded planes); the jxl
            // path is out of scope in v1 — the named no-op note (the
            // run proceeds, no gate, no qc record). A --codec both run
            // carries the QC in the j92 tier.
            eprintln!("note: --qc-gate is a no-op for --codec jxl in v1 (the deterministic QC class rides the j92 decode site — the run proceeds without the gate or the <CLIP>.qc.tsv record; a --codec both run carries the QC in the j92 tier)");
        }
        let effort = cli.jxl_effort.unwrap_or(JxlEffortArg::E7).as_u32();
        let opts = frameprism::jxl::JxlOpts {
            cjxl_bin: cli.cjxl_bin.clone(),
            djxl_bin: cli.djxl_bin.clone(),
            threads: cli.jobs,
            effort,
            // 0 = the auto default (all cores) — resolve_parallel
            // inside process_dir.
            parallel: cli.jxl_parallel.unwrap_or(0),
        };
        return frameprism::jxl::process_dir(input, output, cli.verify, cli.force, &opts, cli.to.as_deref());
    }
    let mode = match cli.mode {
        ModeArg::Lossless => worker::Mode::Lossless,
        ModeArg::Log10 => worker::Mode::Log10,
        ModeArg::VbrHq => worker::Mode::VbrHq,
        ModeArg::VbrLt => worker::Mode::VbrLt,
        ModeArg::Cbr3 => worker::Mode::Cbr3,
        ModeArg::Cbr4 => worker::Mode::Cbr4,
        ModeArg::Cbr5 => worker::Mode::Cbr5,
        ModeArg::Cbr7 => worker::Mode::Cbr7,
    };
    let lossy_format = match cli.lossy_format {
        LossyFormatArg::K34892 => worker::LossyFormat::K34892,
        LossyFormatArg::ReferenceDct => worker::LossyFormat::ReferenceDct,
    };
    if (cli.reference_ref.is_some()
        || cli.reference_mae_tsv.is_some()
        || cli.reference_structure_tsv.is_some())
        && (!mode.is_lossy() || lossy_format != worker::LossyFormat::ReferenceDct)
    {
        anyhow::bail!("--reference-ref/--reference-mae-tsv/--reference-structure-tsv require a lossy --mode with --lossy-format dct12");
    }
    let reference = worker::ReferenceDctOpts {
        reference_ref: cli.reference_ref.clone(),
        reference_mae_tsv: cli.reference_mae_tsv.clone(),
        reference_structure_tsv: cli.reference_structure_tsv.clone(),
    };
    worker::process_dir(
        input,
        output,
        cli.verify,
        cli.force,
        cli.jobs,
        mode,
        cli.downscale2x,
        cli.fast,
        // --qc-gate implies the sidecar pass (the (b) duplicate
        // check rides the sidecar sha rows; the per-frame record lands
        // in <CLIP>.qc.tsv). The j92 path's only qc-gate wiring: the
        // gate verdict is read from the run's QC state in
        // finish_tier (rc=2, the QC_GATE verdict).
        cli.checksums || cli.qc_gate,
        lossy_format,
        &reference,
        cli.to.as_deref(),
        cli.qc_gate,
    )
}

fn print_summary(cli: &Cli, input: &Path, output: &Path, report: &worker::Report, total_s: f64) {
    let done: Vec<&worker::FrameStats> = report
        .outcomes
        .iter()
        .filter_map(|o| match o {
            worker::Outcome::Done(s) => Some(s),
            _ => None,
        })
        .collect();
    let skipped = report
        .outcomes
        .iter()
        .filter(|o| matches!(o, worker::Outcome::Skipped { .. }))
        .count();
    let failed: Vec<&worker::Outcome> = report
        .outcomes
        .iter()
        .filter(|o| matches!(o, worker::Outcome::Failed { .. }))
        .collect();

    println!();
    println!(
        "frameprism {} — {}",
        env!("CARGO_PKG_VERSION"),
        input.display()
    );
    println!("input : {}", input.display());
    println!("output: {}", output.display());
    println!(
        "mode  : {}{}  lossy-format: {}  verify: {}  force: {}  jobs: {}",
        cli.mode,
        if cli.downscale2x {
            " + downscale2x"
        } else {
            ""
        },
        cli.lossy_format,
        cli.verify,
        cli.force,
        display_jobs(cli.jobs)
    );
    if cli.codec == CodecArg::Jxl {
        println!(
            "jxl-parallel: {} ({} concurrent cjxl processes across the reel; auto = all cores — jobs = the per-cjxl thread budget)",
            cli.jxl_parallel.map_or_else(|| "auto".to_string(), |n| n.to_string()),
            cli.jxl_parallel.unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
            })
        );
    }
    if let Some(path) = &report.checksums {
        if cli.codec == CodecArg::Jxl {
            println!("jxl sidecar: {}", path.display());
        } else {
            println!("checksums: {}", path.display());
        }
    }
    if !report.copied_sidecars.is_empty() {
        println!("sidecars copied: {}", report.copied_sidecars.join(", "));
    }
    if done.is_empty() {
        println!("no frames compressed (all skipped?)");
        return;
    }
    println!();
    println!("frame  in_bytes  out_bytes  ratio   ms");
    for s in &done {
        match (&s.log10, &s.lossy, &s.reference_dct) {
            (Some(st), None, None) => {
                println!(
                "{:<32} {:>10} {:>10} {:>6.2}:1 {:>8.0}  log10 err max {} mean {:.4} (<=1: {:.4}%)",
                s.file, s.in_bytes, s.out_bytes, s.ratio, s.ms, st.max_err, st.mean_abs, st.pct_le_1
            )
            }
            (None, Some(st), None) => println!(
                "{:<32} {:>10} {:>10} {:>6.2}:1 {:>8.0}  lossy q{} mae {:.2} psnr {:.1}dB",
                s.file,
                s.in_bytes,
                s.out_bytes,
                s.ratio,
                s.ms,
                s.quality.unwrap_or(0),
                st.mae,
                st.psnr
            ),
            (None, None, Some(st)) => println!(
                "{:<32} {:>10} {:>10} {:>6.2}:1 {:>8.0}  dct12 mae {:.2} max {} scale {:.3}",
                s.file, s.in_bytes, s.out_bytes, s.ratio, s.ms, st.mae, st.max_abs, st.table_scale
            ),
            _ => println!(
                "{:<32} {:>10} {:>10} {:>6.2}:1 {:>8.0}",
                s.file, s.in_bytes, s.out_bytes, s.ratio, s.ms
            ),
        }
    }
    let total_in: u64 = done.iter().map(|s| s.in_bytes).sum();
    let total_out: u64 = done.iter().map(|s| s.out_bytes).sum();
    println!(
        "\ntotal: {} frames ({} skipped, {} failed) — {} -> {} B = {:.2}:1, wall {:.1}s",
        done.len(),
        skipped,
        failed.len(),
        total_in,
        total_out,
        if total_out > 0 {
            total_in as f64 / total_out as f64
        } else {
            0.0
        },
        total_s
    );
    for o in &failed {
        if let worker::Outcome::Failed { file, error } = o {
            println!("FAILED: {file}: {error}");
        }
    }
}

fn display_jobs(jobs: usize) -> String {
    if jobs == 0 {
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0);
        format!("all cores ({n})")
    } else {
        jobs.to_string()
    }
}

/// Write the TSV report (manifest-compatible columns). the
/// `verify` column reflects whether `--verify` was actually on (it was
/// hardcoded "1" before).
fn write_report(
    path: &std::path::Path,
    report: &worker::Report,
    verify: bool,
) -> anyhow::Result<()> {
    let vcol = if verify { "1" } else { "0" };
    let mut lines = Vec::new();
    lines.push("file\tin_bytes\tout_bytes\tratio\tms\tverify\ttool".to_string());
    for o in &report.outcomes {
        if let worker::Outcome::Done(s) = o {
            lines.push(format!(
                "{}\t{}\t{}\t{:.2}\t{:.0}\t{vcol}\tframeprism {}",
                s.file,
                s.in_bytes,
                s.out_bytes,
                s.ratio,
                s.ms,
                env!("CARGO_PKG_VERSION")
            ));
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, lines.join("\n") + "\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use frameprism::worker::FrameStats;

    fn stats(file: &str, log10: Option<frameprism::verify::Log10Stats>) -> worker::Report {
        worker::Report {
            outcomes: vec![worker::Outcome::Done(FrameStats {
                file: file.into(),
                in_bytes: 12_630_528,
                out_bytes: 2_000_000,
                ratio: 6.3,
                ms: 100.0,
                log10,
                lossy: None,
                quality: None,
                reference_dct: None,
            })],
            copied_sidecars: vec![],
            checksums: None,
            offload_dirty_rows: None,
        }
    }

    #[test]
    fn write_report_writes_rows() {
        let tmp = std::env::temp_dir().join("frameprism_report_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("report.tsv");
        let r = stats(
            "a.dng",
            Some(frameprism::verify::Log10Stats {
                max_err: 2,
                mean_abs: 0.56,
                pct_le_1: 99.97,
                samples: 8_367_520,
            }),
        );
        write_report(&p, &r, true).unwrap();
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(content.starts_with("file\tin_bytes\tout_bytes\tratio\tms\tverify\ttool\n"));
        assert!(content.contains("a.dng\t12630528\t2000000\t6.30\t100\t1\tframeprism"));
        // without --verify the column says 0.
        write_report(&p, &r, false).unwrap();
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(content.contains("a.dng\t12630528\t2000000\t6.30\t100\t0\tframeprism"));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
