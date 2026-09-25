//! frameprism — lossless (later lossy) CinemaDNG sequence compressor.
//!
//! Built for uncompressed CinemaDNG from the Sigma fp (12-bit, 1
//! sample/pixel CFA, 12-bit packed, DNG standard order). MVP:
//! re-encode each frame's raw Bayer plane as lossless Huffman JPEG
//! (ITU-T T.81) inside the same DNG container — all metadata
//! preserved structurally (byte surgery).
//!
//! The engine lives in the `frameprism` library crate (`src/lib.rs`);
//! this binary is the CLI (and the cargo-fuzz target exercises the
//! lib's `tiff` module — `tool/fuzz/fuzz_targets/tiff_parse.rs`).
//!
//! The part layout (the two named conceptual parts — each a `mod`
//! below; the internal call sites ride the `use` surface, the bin
//! entry stays at this root): the CLI model (`cli_model` — the clap
//! surface: the mode/codec/effort/format/zstd enums, the `Cli`
//! struct + the CLI-string + the ledger-column helpers) · the
//! dispatch (`dispatch` — the command execution: the pin self-check
//! gate, the per-tier runs + the both dispatch, the run's scope
//! guards, the summary + the TSV report writer, the usage-class
//! refusal band). `enum Cmd` (the subcommand surface) rides at this
//! root: enum variants and their fields always share the visibility
//! of the enum (no per-field qualifier is permitted), and `fn
//! main()` destructures the `Bake` / `Ledger` struct-variant fields
//! — the enum's home is the module that destructures them. The
//! `--help` surface is the external contract (the doc-drift gate
//! byte-diffs the built binary's `--help` against the pinned
//! copy).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

// Cli::parse() / Cli::try_parse_from (the tripwires) are Parser trait methods
use clap::Parser;

use frameprism::{checksums, ledger, pins, preflight, worker};

mod cli_model;
mod dispatch;

use crate::cli_model::{
    cli_args_string, selection_column, Cli, CodecArg, ZstdMode,
};
use crate::dispatch::{dryrun_dispatch, finish_tier, pin_gate, run, run_both};

/// Subcommands (one per feature). Absent = the legacy positional
/// `input`/`output` surface, which parses and behaves identically
/// (`subcommand_negates_reqs = true` on the parser; the legacy dispatch
/// is untouched when no subcommand word is present).
#[derive(Debug, clap::Subcommand)]
enum Cmd {
    /// Package an encoded clip dir into a tar[.zst] archive + a
    /// per-file sha256 manifest. --iso: write a mountable ISO image
    /// instead; --reel-out: ride the signed reel manifest + its .sig
    /// on the image.
    Bake {
        /// Encoded clip dir (.DNGs for j92; 4× .jxl per frame + the
        /// *.jxl-checksums.tsv sidecar for jxl). Read-only input —
        /// never modified.
        input: PathBuf,

        /// Output dir for <clip>.tar[.zst] + <clip>.bake-manifest.tsv
        /// (created if missing) — or, with --iso, the IMAGE PATH
        /// (e.g. reel.iso; the parent dir is created if missing)
        output: PathBuf,

        /// zstd level for the archive container: none | 9 | 19
        /// (default: detection — j92 → 19, jxl → none; an explicit
        /// value always wins)
        #[arg(long, value_enum)]
        zstd: Option<ZstdMode>,

        /// Overwrite an existing archive (default: reject, rc=2)
        #[arg(long)]
        force: bool,

        /// Resumable bake: the final archive object WITH a verifying
        /// `.sha256` sidecar (re-hashed) + the manifest = done → the
        /// named skip, no re-bake; without it (or a stale file_count)
        /// = interrupted → the leftover temps are cleaned up + named
        /// and the bake redoes from zero. Absent = an existing archive
        /// is refused without --force.
        #[arg(long)]
        resume: bool,

        /// <output> is an IMAGE PATH (e.g. reel.iso), not a dir — the
        /// reel's per-clip archives + manifests are staged and imaged
        /// as a hybrid ISO9660+Joliet+RockRidge disk image (the
        /// pinned in-process fstool 0.4.33 writer + the pin-times
        /// pass — no external binary) that mounts natively on
        /// macOS/Windows/Linux; the mount is the audit surface
        #[arg(long)]
        iso: bool,

        /// Pins file for the pin self-check (the flag opts the check
        /// IN; the optional VALUE is an explicit pins file, else the
        /// default resolution: `FRAMEPRISM_PINS` env (the legacy
        /// `<cwd>/ci/pins.tsv` → `<exe_dir>/../ci/pins.tsv`; not
        /// found = a named skip line, never a refusal)
        #[arg(long, num_args = 0..=1)]
        pins: Option<Option<PathBuf>>,

        /// Comma separated clip keys to BAKE (tree: the clip folder
        /// names; flat --iso: the frame name prefixes; flat: the
        /// single clip name). Every name must exist in the input's
        /// clip key space (unknown = the named rc=2 before any file);
        /// `--clips` + `--skip` naming the same clip = named rc=2;
        /// the effective set empty = named rc=2. Absent = the full
        /// set. The selection is journaled (the ledger's `selection`
        /// column) + the bake summary carries the `selection:` line.
        #[arg(long)]
        clips: Option<String>,

        /// Comma separated clip keys to LEAVE OUT (the complement of
        /// the encode universe — the tree's clip folders / the flat
        /// --iso prefix groups / the flat clip name). The resolution
        /// rules are `--clips`' (unknown name / conflict / empty
        /// effective set = the named rc=2 before any file). Absent =
        /// no exclusions.
        #[arg(long)]
        skip: Option<String>,

        /// The reel dir (`--iso` only): the dir the signed reel
        /// manifest + its `.sig` live in (the `bake <out> <reel-dir>`
        /// output dir, AFTER `frameprism sign` ran on its reel manifest).
        /// The sealed ISO stages the SIGNED manifest + the `.sig` as
        /// the `provenance/` bundle at the image root (the reader
        /// extracts `provenance/` and runs `frameprism verify
        /// provenance/reel.reel-manifest.tsv --key <pubkey>`). The
        /// sealing checks refuse named (rc=2, zero partial files): the
        /// manifest + `.sig` present, the envelope well-formed, and
        /// the envelope's `manifest_sha256` binding the manifest
        /// bytes. On the non-iso path = the named usage refusal.
        /// Absent = the existing image shape.
        #[arg(long)]
        reel_out: Option<PathBuf>,
    },

    /// Decode an encoded clip dir to 16-bit PAM frames.
    Decode(frameprism::decode::Args),
    /// Offload (mirror + verify) a source tree to one or more
    /// destinations — no encode: every file (the frames + the
    /// sidecars — any camera, any format) is re-scanned (sha256 —
    /// the source's bytes are read ONCE per file), copied to EVERY
    /// destination (mirrored subpaths, mtime preserved), re-scanned
    /// after each write, and rowed into the per-clip offload
    /// manifests at each destination (the `dest` header row is that
    /// dest) + the run report at each destination root (the report
    /// carries the whole run — every dest's status). The two forms:
    /// the single-source form — the positional `in` (the source) +
    /// the positional `to` dests (the legacy shape, byte-identical) —
    /// and the multi-source form — `--source <SOURCE>...` (the
    /// sources) + `--dest <DEST>...` (the dests; every source fanned
    /// to every dest in one job; the per-source work runs
    /// concurrently — one std::thread per source, the sources do not
    /// wait on each other; the per-dest-root artifacts ride the
    /// serialized tail after all sources join — one ascmhl
    /// generation per dest per job). The positionals are the
    /// single-source form's: the mixed-form/all-absent refusals are
    /// the named rc=2 bands. The camera/format detection is a report,
    /// never a gate (the offload copies + verifies any tree).
    /// Per-destination verification + status: rc=0 every row OK at
    /// every dest; rc=1 any dirty row at any dest (the named FAIL
    /// lines, after the run — every dest named); rc=2 the pre-write
    /// refusals (the self-mirror guard per dest, the duplicate-dest
    /// refusal, the per-dest writability probe — before any copy).
    Offload(frameprism::offload::Args),
    /// Verify every file the sidecars list (size + sha256, + crc32c
    /// where present). rc=0 clean, rc=1 offenders named, rc=2 usage.
    Audit(frameprism::audit::AuditArgs),
    /// Re-copy audit offenders from a pristine master (the master must
    /// itself verify; the original is kept as <file>.pre-restore).
    Restore(frameprism::audit::RestoreArgs),
    /// Derive 8/10-bit working DNGs from 12-bit masters (pinned v>>4 /
    /// v>>2).
    Derive(frameprism::derived::Args),
    /// Per-frame pixel comparison of two encodes; deterministic
    /// --report; --strict = exit 1 on any delta.
    Diff(frameprism::diff::Args),
    /// Re-copy + re-verify the dirty rows of an offload manifest from
    /// the source tree.
    Repair(frameprism::repair::Args),
    /// Show the ops ledger + the rotation report (last audit older
    /// than N days).
    Ledger {
        /// List only rows from the last N days (and the rotation
        /// window).
        #[arg(long)]
        since: Option<u64>,

        /// One JSON object per row (lines) for scripting — the
        /// rotation report + the warnings land on stderr (stdout
        /// stays the pure JSON stream).
        #[arg(long)]
        json: bool,
    },
    /// Sign the reel manifest (ed25519, deterministic; the manifest
    /// bytes are never touched).
    Sign(frameprism::provenance::SignArgs),
    /// Verify a signed reel manifest (sha256 + key identity +
    /// signature).
    Verify(frameprism::provenance::VerifyArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // subcommand dispatch: a present subcommand word bypasses the
    // legacy positional dispatch entirely (`subcommand_negates_reqs =
    // true`); absent = the legacy `frameprism in out …` surface,
    // behavior-identical (the oracle + suite gate this).
    if let Some(cmd) = cli.command {
        return match cmd {
            Cmd::Bake { input, output, zstd, force, iso, pins: pins_flag, clips: clips_flag, skip: skip_flag, resume, reel_out } => {
                let zstd = match zstd {
                    None => None,
                    Some(ZstdMode::None) => Some(0),
                    Some(ZstdMode::L9) => Some(9),
                    Some(ZstdMode::L19) => Some(19),
                };
                let t0 = Instant::now();
                let command = if iso { "bake-iso" } else { "bake" };
                // (the seal gate's check 6): `--reel-out` is an
                // --iso-only flag (the provenance bundle seals INTO
                // the image — the working-tier bake does not stage it)
                // — the named usage refusal BEFORE the first byte (no
                // status line, no ledger row).
                if !iso {
                    if let Some(reel_out) = &reel_out {
                        eprintln!(
                            "error: {}",
                            frameprism::bake::reel_out_non_iso_refusal(reel_out)
                        );
                        return ExitCode::from(2);
                    }
                }
                // the status surface — truncated BEFORE the
                // first byte; the start line carries the phase
                // (the bake/iso transition, the same shape).
                let run_id = frameprism::status::open();
                if let (Some(st), Some(rid)) = (frameprism::status::current(), run_id) {
                    st.emit(&format!(
                        "{{\"run\":{},\"input\":{},\"out\":{},\"phase\":{}}}",
                        frameprism::status::jstr(&rid),
                        frameprism::status::jstr(&input.to_string_lossy()),
                        frameprism::status::jstr(&output.to_string_lossy()),
                        frameprism::status::jstr(if iso { "iso" } else { "bake" })
                    ));
                }
                // The pin self-check BEFORE the first
                // byte (cjxl/djxl = the tool's runtime
                // defaults — the FULL contract set is probed; the
                // in-process zstd/tar/fstool components resolve to the
                // embedded crate versions, not PATH binaries).
                let resolve = pins::Resolve {
                    cjxl: PathBuf::from("cjxl"),
                    djxl: PathBuf::from("djxl"),
                };
                if let Some(explicit) = pins_flag.as_ref() {
                    if pin_gate(
                        explicit.as_ref().map(|p| p.as_path()),
                        &resolve,
                        command,
                        "-",
                        &input,
                        &output,
                    )
                    .is_err()
                    {
                        return ExitCode::from(2);
                    }
                }
                // The clip selection — parse + resolve
                // BEFORE the first byte (a malformed name, an unknown
                // name, a clips∩skip conflict, or an empty effective
                // set = the named rc=2 usage refusal, no ledger row).
                // The universe = the input's clip key space (tree: the
                // clip folder names; flat --iso: the frame name prefix
                // groups; flat: the single clip name).
                let sel_flags = match frameprism::selection::Flags::new(clips_flag, skip_flag) {
                    Ok(f) => f,
                    Err(err) => {
                        eprintln!("error: {err}");
                        return ExitCode::from(2);
                    }
                };
                if sel_flags.present() {
                    let universe = match frameprism::bake::selection_universe(&input, iso) {
                        Ok(u) => u,
                        Err(err) => {
                            eprintln!("error: selection: {err:#}");
                            return ExitCode::from(2);
                        }
                    };
                    let sel = match sel_flags.resolve(&universe) {
                        Ok(s) => s,
                        Err(err) => {
                            eprintln!("error: {err}");
                            return ExitCode::from(2);
                        }
                    };
                    frameprism::selection::set_current(sel.map(|s| frameprism::selection::Active {
                        selected: s,
                        universe: universe.len(),
                    }));
                }
                let result = if iso {
                    frameprism::bake::run_iso(
                        &input,
                        &output,
                        zstd,
                        force,
                        resume,
                        reel_out.as_deref(),
                    )
                } else {
                    frameprism::bake::run(&input, &output, zstd, force, resume)
                };
                match result {
                    Ok(outcome) => {
                        if let Some(st) = frameprism::status::current() {
                            st.emit(&format!(
                                "{{\"phase\":{},\"verdict\":{},\"duration_s\":{}}}",
                                frameprism::status::jstr("end"),
                                frameprism::status::jstr("OK"),
                                t0.elapsed().as_secs()
                            ));
                        }
                        // The A3 ops-ledger row (the completed bake
                        // run — the rotation report's input).
                        ledger::append_quiet(&ledger::Row {
                            created: ledger::now_secs(),
                            command: command.into(),
                            tool_version: env!("CARGO_PKG_VERSION").into(),
                            input: ledger::canon(&input),
                            output: ledger::canon(&output),
                            codec: outcome.codec,
                            frames: outcome.frames,
                            verdict: "OK".into(),
                            duration_s: t0.elapsed().as_secs(),
                            dest: String::new(),
                            selection: selection_column(),
                            // The bake verb never runs under --subset
                            // (the encode verbs carry the flag): the
                            // column is always empty here.
                            context: String::new(),
                        });
                        ExitCode::SUCCESS
                    }
                    Err(err) => {
                        if let Some(st) = frameprism::status::current() {
                            st.emit(&format!(
                                "{{\"phase\":{},\"verdict\":{},\"duration_s\":{}}}",
                                frameprism::status::jstr("end"),
                                frameprism::status::jstr("FAIL"),
                                t0.elapsed().as_secs()
                            ));
                        }
                        eprintln!("error: {err:#}");
                        // The A3 ledger: a mid-run failure is the FAIL
                        // row; the named pre-run usage refusals never
                        // start a run (no row — the REFUSED_* classes
                        // are the safety gates').
                        let msg = format!("{err:#}");
                        if !frameprism::bake::is_usage_refusal(&msg) {
                            ledger::append_quiet(&ledger::Row {
                                created: ledger::now_secs(),
                                command: command.into(),
                                tool_version: env!("CARGO_PKG_VERSION").into(),
                                input: ledger::canon(&input),
                                output: ledger::canon(&output),
                                codec: "-".into(),
                                frames: 0,
                                verdict: "FAIL".into(),
                                duration_s: t0.elapsed().as_secs(),
                                dest: String::new(),
                                selection: selection_column(),
                                // The bake verb never runs under
                                // --subset (the encode verbs carry the
                                // flag): the column is always empty
                                // here.
                                context: String::new(),
                            });
                        }
                        ExitCode::from(2)
                    }
                }
            }
            Cmd::Decode(args) => frameprism::decode::run(&args),
            Cmd::Offload(args) => frameprism::offload::run(&args),
            Cmd::Audit(args) => frameprism::audit::run_audit(&args),
            Cmd::Restore(args) => frameprism::audit::run_restore(&args),
            Cmd::Derive(args) => frameprism::derived::run(&args),
            Cmd::Diff(args) => frameprism::diff::run(&args),
            // The re-copy delta — the repair loop ( the named
            // rows, the selective re-copy, the fresh re-verify, the
            // verdict flip on the full set.
            Cmd::Repair(args) => frameprism::repair::run(&args),
            // The A3 ledger reader (read-only over the journal — the
            // writer is the run paths).
            Cmd::Ledger { since, json } => ledger::run(since, json),
            // The provenance signature ( the sign / verify
            // verbs (the finding rc=1 / the refusal rc=2 convention —
            // the no-mint key posture: the tool verifies, it does not
            // mint).
            Cmd::Sign(args) => frameprism::provenance::run_sign(&args),
            Cmd::Verify(args) => frameprism::provenance::run_verify(&args),
        };
    }

    // The legacy positional surface is EXACT (positional `input` +
    // `output`; the oracle + suite gate it). The fields are `Option` at
    // the clap level for one reason only: clap 4.6.6 misparses
    // `<subcommand> <pos> <pos>` when the top-level positionals are
    // REQUIRED (with `subcommand_negates_reqs`) — `bake a b` failed with
    // "required argument was not provided: input" (rc=2). Verified on a
    // minimal clap 4.6.6 repro (bake path; the decode path
    // shares this hunk). The required-check moves here: same rc=2,
    // clap-mirrored message; every valid invocation parses identically.
    let (input, output) = match (cli.input.clone(), cli.output.clone()) {
        (Some(input), Some(output)) => (input, output),
        (input, output) => {
            let n_missing = usize::from(input.is_none()) + usize::from(output.is_none());
            if n_missing == 2 {
                eprintln!("error: the following required arguments were not provided:\n  input\n  output\n\nFor more information, try '--help'.");
            } else {
                let which = if input.is_none() { "input" } else { "output" };
                eprintln!("error: the following required argument was not provided:\n  {which}\n\nFor more information, try '--help'.");
            }
            return ExitCode::from(2);
        }
    };

    // The standalone checksums pass is the J92 checksums tsv; the JXL
    // sidecar is a different format and is checked by `--verify`
    // (sidecar sha256 re-check + djxl decode round-trip). Refuse the
    // combination instead of silently verifying the wrong file.
    if cli.verify_checksums && cli.codec == CodecArg::Jxl {
        eprintln!(
            "error: --verify-checksums is the J92 checksums pass; --codec jxl integrity is checked by --verify (sidecar sha256 re-check + djxl decode round-trip)"
        );
        return ExitCode::from(2);
    }
    // --verify-checksums with --codec both is the named
    // refusal — with both, the pass is ambiguous (the j92 tier's
    // standalone verify? both tiers?); the jxl tier's integrity is
    // checked by --verify.
    if cli.verify_checksums && cli.codec == CodecArg::Both {
        eprintln!(
            "error: --verify-checksums is the J92 standalone checksums pass and is ambiguous with --codec both (the jxl tier's integrity is checked by --verify — run the standalone --codec j92 verify pass instead)"
        );
        return ExitCode::from(2);
    }
    // --resume with --codec both is the named refusal —
    // the jxl sidecar is plane-based (the open item); the recovery
    // contract is the per-tier standalone runs (the j92 tier's
    // verified --resume; the jxl tier's --force re-run), not a
    // tier-spanning resume.
    if cli.resume && cli.codec == CodecArg::Both {
        eprintln!(
            "error: --codec both does not combine with --resume in v1 (recovery is the per-tier standalone runs: the j92 tier's --resume, the jxl tier's --force re-run — re-run each tier standalone)"
        );
        return ExitCode::from(2);
    }

    // Standalone verification pass: no encoding, just re-read + recompute.
    if cli.verify_checksums {
        // the clip name comes from the SAME helper as
        // `--checksums` (a trailing-slash input used to derive two
        // different tsv file names in the two passes).
        let clip = match checksums::clip_name(&input) {
            Ok(c) => c,
            Err(err) => {
                eprintln!("error: checksum verification: {err:#}");
                return ExitCode::from(2);
            }
        };
        match checksums::verify_checksums(&output, &clip) {
            Ok(rows) => {
                let bad = rows.iter().filter(|r| !r.ok).count();
                for r in &rows {
                    if !r.ok {
                        println!("FAIL {} — {}", r.file, r.problem.as_deref().unwrap_or("?"));
                    }
                }
                println!(
                    "checksum verification: {}/{} file(s) OK",
                    rows.len() - bad,
                    rows.len()
                );
                return if bad == 0 {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                };
            }
            Err(err) => {
                eprintln!("error: checksum verification: {err:#}");
                return ExitCode::from(2);
            }
        }
    }

    let t0 = Instant::now();
    let codec_str = cli.codec.to_string();
    // --- --dry-run (predict-then-measure) ---------------------
    // The estimate dispatches BEFORE the pin gate / the A2 preflight /
    // the status surface / the selection: the dry run archives nothing
    // (no ledger row, no status line, no output dir — the named scope;
    // the A2 corpus-rate guard is replaced by the MEASURED fit-check,
    // no fixed corpus rate). Creates nothing under <dest> (not even
    // the dir); the `--report FILE` markdown is the dry run's record.
    if cli.dry_run {
        return dryrun_dispatch(&cli, &input, &output);
    }
    // --- The pin self-check BEFORE the first frame/byte ---
    // (the Risks-row mitigation — a drifted cjxl/djxl
    // would silently change the archive bytes: the named refusal +
    // rc=2 + zero output, the ingest gate's pattern). Resolution:
    // the --cjxl-bin/--djxl-bin flags where this run has them
    // (the encode path), else the tool's runtime defaults
    // (the in-process zstd/tar/fstool components resolve to the
    // embedded crate versions).
    let pin_resolve = pins::Resolve {
        cjxl: cli.cjxl_bin.clone(),
        djxl: cli.djxl_bin.clone(),
    };
    if let Some(explicit) = cli.pins.as_ref() {
        if pin_gate(
            explicit.as_ref().map(|p| p.as_path()),
            &pin_resolve,
            "legacy",
            &codec_str,
            &input,
            &output,
        )
        .is_err()
        {
            return ExitCode::from(2);
        }
    }
    // --- The clip selection — parse + resolve BEFORE
    // the first frame (a malformed name, an unknown name, a
    // clips∩skip conflict, or an empty effective set = the named rc=2
    // usage refusal, no ledger row). The universe = the distinct clip
    // keys of the input's .DNG frames (`clip_key_of` — the parent dir
    // relative to the input: the tree folder names; "" for a flat
    // single-clip layout — a flat selection is a named refusal, the
    // flat layout has no clip names). The resolution lands in the
    // process-wide `selection::current` (the pins.rs OnceLock
    // convention); `worker::process_dir` reads it to filter the
    // collected frames + sidecars (absent = the full set — the
    // byte-identity path).
    let sel_flags = match frameprism::selection::Flags::new(cli.clips.clone(), cli.skip.clone()) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };
    if sel_flags.present() {
        let src_frames = match worker::collect_dng_frames(&input) {
            Ok(f) => f,
            Err(err) => {
                eprintln!("error: selection: scan the source frames: {err}");
                return ExitCode::from(2);
            }
        };
        let mut universe: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for src in &src_frames {
            universe.insert(worker::clip_key_of(&input, src));
        }
        let sel = match sel_flags.resolve(&universe) {
            Ok(s) => s,
            Err(err) => {
                eprintln!("error: {err}");
                return ExitCode::from(2);
            }
        };
        // v1: --codec jxl / both + a selection = the named refusal
        // BEFORE any frame (the jxl path's frame collection is a
        // separate path in the out-of-scope jxl.rs — the flag was
        // parsed + the names validated first, exactly per the design
        // decision; both rides the same v1 scope). The jxl
        // line renders byte-identical to the pre-existing message (the
        // codec name is the only variable).
        if sel.is_some() && matches!(cli.codec, CodecArg::Jxl | CodecArg::Both) {
            eprintln!(
                "error: --codec {} does not combine with --clips/--skip in v1 (the jxl path's frame collection is a separate path — the selection is refused named before any frame)",
                cli.codec
            );
            return ExitCode::from(2);
        }
        frameprism::selection::set_current(
            sel.map(|s| frameprism::selection::Active {
                selected: s,
                universe: universe.len(),
            }),
        );
    }
    // --- A2 +: the preflight space + ETA guard —
    // the same gate position (before the first frame/byte — before
    // process_dir creates the output dir, so a refusal writes 0 files).
    // both = ONE combined reservation (the sum of the per-tier
    // estimates — a j92-only reservation would approve a run that
    // fills the disk 3/4 through the jxl tier).
    let (n_frames, input_bytes) = match preflight::scan_source(&input) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("error: preflight: scan the source frames: {err}");
            return ExitCode::from(2);
        }
    };
    let refusal = if cli.codec == CodecArg::Both {
        preflight::guard_both(n_frames, input_bytes, &output).err()
    } else {
        preflight::guard(&codec_str, n_frames, input_bytes, &output).err()
    };
    if let Some(r) = refusal {
        eprintln!("{}", r.line);
        ledger::append_quiet(&ledger::Row {
            created: ledger::now_secs(),
            // the both refusal row carries the actual CLI
            // string (the standalone row keeps the `legacy` label).
            command: if cli.codec == CodecArg::Both {
                cli_args_string()
            } else {
                "legacy".into()
            },
            tool_version: env!("CARGO_PKG_VERSION").into(),
            input: ledger::canon(&input),
            output: ledger::canon(&output),
            codec: codec_str.clone(),
            frames: n_frames as u64,
            verdict: r.class.into(),
            duration_s: t0.elapsed().as_secs(),
            dest: cli
                .to
                .clone()
                .map(|d| ledger::canon(&d))
                .unwrap_or_default(),
            selection: selection_column(),
            // The preflight guard runs BEFORE the ingest gate (the
            // run never started): the column is always empty here.
            context: String::new(),
        });
        return ExitCode::from(2);
    }

    // the status surface (the j92 legacy encode + the both run's
    // j92 block — the jxl path carries NO status lines in v1, ) +
    // the run's `--resume` flag (the scan gate in process_dir). The
    // file is truncated BEFORE the first byte; the start line
    // lands in process_dir after the gate + the resume scan (the real
    // `resumed` count).: a both run opens it ONCE before
    // the j92 tier — the file carries the j92 block only (0 jxl
    // lines), the standalone-j92 schema.
    frameprism::resume::set_flag(cli.resume);
    // The `--subset` NAMED opt-in (the two encode paths' gate
    // call sites read it; absent = the default hard gate).
    frameprism::worker::set_subset_flag(cli.subset);
    if matches!(cli.codec, CodecArg::J92 | CodecArg::Both) {
        let _ = frameprism::status::open();
    }

    // the both dispatch (sequential j92 → jxl, ) — each tier
    // runs its standalone path + the standalone post-processing
    // (finish_tier).
    if cli.codec == CodecArg::Both {
        return run_both(&cli, &input, &output, n_frames as u64);
    }

    let result = run(&cli, &input, &output);
    finish_tier(
        &cli,
        &input,
        &output,
        result,
        t0.elapsed().as_secs_f64(),
        n_frames as u64,
        cli.codec == CodecArg::J92,
        "legacy",
    )
    .0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_model::{LossyFormatArg, ModeArg};

    // H1/H2 (the OSS-purity tripwire + the escape-hatch
    // liveness): the rendered CLI help — the user surface — must be
    // free of internal-project state (project-structure IDs, the
    // proprietary family names, the internal vocabulary) AND
    // the parked lossy escape hatch must still PARSE while staying
    // invisible in the rendered help. In-process clap render —
    // deterministic, no binary exec, no FS.
    //
    // The blocklist is the minimum set (case-sensitive as written);
    // it is implemented dependency-free (the tool has no `regex`
    // crate — no Cargo.* change, fence-safe): literal substrings +
    // byte scanners, semantics-preserving for these specific
    // patterns. A hit means the rendered text is genuinely internal-project state:
    // fix the TEXT, never weaken this test .
 // token adjustments: `maintainer`→`maintainer-boarded` + `DIT`→word-boundary,
    // because NOTICE.md carries verbatim third-party license texts (Apache-2.0)
    // containing those substrings — the escalation on the record, the rewording
    // preserves coverage; never weaken this test.
    #[test]
    fn help_surface_is_oss_clean() {
        // The digit-class scanners (dependency-free semantics for the
        // spec patterns): `X[0-9]` / `X[0-9]+` = an ASCII digit
        // immediately after the prefix; `P[0-9A-Z]+-` / `R[0-9]-` =
        // the letter, the class run, then the dash.
        fn digit_after(hay: &str, prefix: &str) -> bool {
            hay.match_indices(prefix).any(|(i, _)| {
                hay[i + prefix.len()..]
                    .chars()
                    .next()
                    .map_or(false, |c| c.is_ascii_digit())
            })
        }
        fn p_id_dash(hay: &str) -> bool {
            let b = hay.as_bytes();
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'P' {
                    let mut j = i + 1;
                    while j < b.len()
                        && (b[j].is_ascii_digit() || b[j].is_ascii_uppercase())
                    {
                        j += 1;
                    }
                    if j > i + 1 && j < b.len() && b[j] == b'-' {
                        return true;
                    }
                }
                i += 1;
            }
            false
        }
        fn r_id_dash(hay: &str) -> bool {
            let b = hay.as_bytes();
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'R' {
                    let mut j = i + 1;
                    while j < b.len() && b[j].is_ascii_digit() {
                        j += 1;
                    }
                    if j > i + 1 && j < b.len() && b[j] == b'-' {
                        return true;
                    }
                }
                i += 1;
            }
            false
        }
 // `DIT` word-boundary (the token adjustment): a hit requires
        // a non-word byte before and after the literal (ASCII word = [A-Za-z0-9])
        // — `DISTRIBUTION`/`CONDITIONS` no longer match, a bare `DIT` token still
        // does.
        fn dit_word(hay: &str) -> bool {
            let b = hay.as_bytes();
            let mut i = 0;
            while i + 3 <= b.len() {
                if b[i] == b'D' && b[i + 1] == b'I' && b[i + 2] == b'T' {
                    let before = i == 0 || !b[i - 1].is_ascii_alphanumeric();
                    let after = i + 3 == b.len() || !b[i + 3].is_ascii_alphanumeric();
                    if before && after {
                        return true;
                    }
                }
                i += 1;
            }
            false
        }

        // Render every help surface in-process (the top-level long
        // help + each subcommand's rendered long help — the same text
        // the on-disk `frameprism --help` / `frameprism <sub> --help` print).
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let mut surfaces: Vec<(String, String)> =
            vec![("top".to_string(), cmd.render_long_help().to_string())];
        for sc in cmd.get_subcommands() {
            let mut sc = sc.clone();
            surfaces.push((
                sc.get_name().to_string(),
                sc.render_long_help().to_string(),
            ));
        }

        // H1 — the blocklist (the minimum set, case-sensitive):
        // absent from every rendered surface.
        for (name, hay) in &surfaces {
            for pat in [
                "ROADMAP",
                "vendor",
                "lane-P",
                "bake-lane",
                "owner-boarded",
                "plateau",
                "2076",
                "D-21",
                "D13",
            ] {
                assert!(
                    !hay.contains(pat),
                    "H1: blocklist literal `{pat}` matched in the rendered {name} help — reword the text, never this test"
                );
            }
            for (pat, prefix) in [
                ("Phase [0-9]", "Phase "),
                ("item [0-9]", "item "),
                ("task [0-9]+", "task "),
                ("SPEC [0-9]", "SPEC "),
            ] {
                assert!(
                    !digit_after(hay, prefix),
                    "H1: blocklist `{pat}` matched in the rendered {name} help — reword the text, never this test"
                );
            }
            assert!(
                !p_id_dash(hay),
                "H1: blocklist `P[0-9A-Z]+-` matched in the rendered {name} help — reword the text, never this test"
            );
            assert!(
                !r_id_dash(hay),
                "H1: blocklist `R[0-9]-` matched in the rendered {name} help — reword the text, never this test"
            );
            assert!(
                !dit_word(hay),
                "H1: blocklist `DIT` (word-boundary) matched in the rendered {name} help — reword the text, never this test"
            );
        }

        // H2 — the parked lossy escape hatch: hidden, not removed. The
        // values + flags still PARSE (clap try_parse_from, parse level
        // only — no encode, no FS) …
        let parsed = Cli::try_parse_from(["frameprism", "--mode", "cbr4"]).unwrap();
        assert!(matches!(parsed.mode, ModeArg::Cbr4));
        let parsed = Cli::try_parse_from([
            "frameprism",
            "--mode",
            "vbr-hq",
            "--lossy-format",
            "34892",
            "--reference-ref",
            "ref.dng",
        ])
        .unwrap();
        assert!(matches!(parsed.lossy_format, LossyFormatArg::K34892));
        assert_eq!(parsed.reference_ref.as_deref(), Some(std::path::Path::new("ref.dng")));
        let parsed = Cli::try_parse_from([
            "frameprism",
            "--mode",
            "cbr7",
            "--reference-mae-tsv",
            "mae.tsv",
            "--reference-structure-tsv",
            "structure.tsv",
        ])
        .unwrap();
        assert!(parsed.reference_mae_tsv.is_some());
        assert!(parsed.reference_structure_tsv.is_some());

        // … and none of the hidden surfaces renders in the help (the
        // reference-family word is already covered by the H1 blocklist).
        let all: String = surfaces
            .iter()
            .map(|(_, h)| h.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        for token in [
            "vbr-hq",
            "vbr-lt",
            "cbr3",
            "cbr4",
            "cbr5",
            "cbr7",
            "34892",
            "lossy-format",
            "reference-ref",
            "reference-mae-tsv",
            "reference-structure-tsv",
        ] {
            assert!(
                !all.contains(token),
                "H2: the hidden lossy surface `{token}` must not render in the help"
            );
        }
    }

    // The README purity tripwire (the file list extends
    // to the contributor doc + the changelog): the OSS landing page + the
    // contributor doc + the changelog get the same rule as the help
    // tripwire — no internal-project state in the user-facing text.
    // Reads README.md + CONTRIBUTING.md + CHANGELOG.md relative to the
    // manifest dir (tool/../* — the manifest dir is `tool/`, all three at
    // the repo root); deterministic, no FS beyond those three files.
    //
    // The blocklist: the case-INSENSITIVE reference-family word pair (zero
    // occurrences in any of the three docs — the rewording goal + the
    // filenames the
    // Docs table no longer indexes) + the
    // case-SENSITIVE H1 set. Explicitly legal (deliberately NOT
    // blocked): `Sigma fp` (the reference camera, named once), `A001`
    // (the committed fixture's frame names),
    // `dct12`, the docs/ path strings.
    //
    // A hit means the doc is genuinely internal-project state: fix the TEXT, never
    // weaken this test. A pattern colliding with legitimate doc wording
    // is an escalation (pattern + matched text + proposed rewording),
    // never a unilateral edit.
 // token adjustments: `maintainer`→`maintainer-boarded` + `DIT`→word-boundary,
    // because NOTICE.md carries verbatim third-party license texts (Apache-2.0)
    // containing those substrings — the escalation on the record, the rewording
    // preserves coverage; never weaken this test.
    #[test]
    fn readme_is_oss_clean() {
        // The tripwired public docs (the file list — same
        // blocklist, same idiom per file).
        for name in ["README.md", "CONTRIBUTING.md", "CHANGELOG.md", "NOTICE.md", ".github/SECURITY.md"] {
            let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../")
                .join(name);
            let hay = std::fs::read_to_string(&file).unwrap_or_else(|e| {
                panic!("readme_is_oss_clean: cannot read {file:?}: {e}")
            });

            // Case-INSensitive: the two reference-family words (the patterns
            // are already lowercase; lowercase the haystack).
            let lower = hay.to_lowercase();
            for pat in ["vendor"] {
                assert!(
                    !lower.contains(pat),
                    "{name}: case-insensitive blocklist `{pat}` matched — reword the text, never this test"
                );
            }

            // Case-sensitive (the H1 set): literal substrings first …
            for pat in [
                "ROADMAP",
                "lane-P",
                "bake-lane",
                "owner-boarded",
                "plateau",
                "2076",
                "D-21",
                "D13",
            ] {
                assert!(
                    !hay.contains(pat),
                    "{name}: blocklist literal `{pat}` matched — reword the text, never this test"
                );
            }
            // … then the digit-class scanners (dependency-free semantics —
            // the same idiom as the help tripwire: the prefix, then an
            // ASCII digit; `P[0-9A-Z]+-` / `R[0-9]-` = the letter, the
            // class run, then the dash).
            fn digit_after(hay: &str, prefix: &str) -> bool {
                hay.match_indices(prefix).any(|(i, _)| {
                    hay[i + prefix.len()..]
                        .chars()
                        .next()
                        .map_or(false, |c| c.is_ascii_digit())
                })
            }
            fn p_id_dash(hay: &str) -> bool {
                let b = hay.as_bytes();
                let mut i = 0;
                while i < b.len() {
                    if b[i] == b'P' {
                        let mut j = i + 1;
                        while j < b.len()
                            && (b[j].is_ascii_digit() || b[j].is_ascii_uppercase())
                        {
                            j += 1;
                        }
                        if j > i + 1 && j < b.len() && b[j] == b'-' {
                            return true;
                        }
                    }
                    i += 1;
                }
                false
            }
            fn r_id_dash(hay: &str) -> bool {
                let b = hay.as_bytes();
                let mut i = 0;
                while i < b.len() {
                    if b[i] == b'R' {
                        let mut j = i + 1;
                        while j < b.len() && b[j].is_ascii_digit() {
                            j += 1;
                        }
                        if j > i + 1 && j < b.len() && b[j] == b'-' {
                            return true;
                        }
                    }
                    i += 1;
                }
                false
            }
 // `DIT` word-boundary (the token adjustment): a hit
            // requires a non-word byte before and after the literal (ASCII
            // word = [A-Za-z0-9]) — `DISTRIBUTION`/`CONDITIONS` no longer
            // match, a bare `DIT` token still does.
            fn dit_word(hay: &str) -> bool {
                let b = hay.as_bytes();
                let mut i = 0;
                while i + 3 <= b.len() {
                    if b[i] == b'D' && b[i + 1] == b'I' && b[i + 2] == b'T' {
                        let before = i == 0 || !b[i - 1].is_ascii_alphanumeric();
                        let after = i + 3 == b.len() || !b[i + 3].is_ascii_alphanumeric();
                        if before && after {
                            return true;
                        }
                    }
                    i += 1;
                }
                false
            }
            for (pat, prefix) in [
                ("Phase [0-9]", "Phase "),
                ("item [0-9]", "item "),
                ("task [0-9]+", "task "),
                ("SPEC [0-9]", "SPEC "),
            ] {
                assert!(
                    !digit_after(&hay, prefix),
                    "{name}: blocklist `{pat}` matched — reword the text, never this test"
                );
            }
            assert!(
                !p_id_dash(&hay),
                "{name}: blocklist `P[0-9A-Z]+-` matched — reword the text, never this test"
            );
            assert!(
                !r_id_dash(&hay),
                "{name}: blocklist `R[0-9]-` matched — reword the text, never this test"
            );
            assert!(
                !dit_word(&hay),
                "{name}: blocklist `DIT` (word-boundary) matched — reword the text, never this test"
            );
        }
    }
}
