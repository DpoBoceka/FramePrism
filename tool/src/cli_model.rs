//! The CLI model — the clap surface.
//!
//! The parse-level enums: `ModeArg` (lossless / log10 / the parked
//! lossy presets — hidden from the rendered help, parseable — the
//! escape hatch) · `CodecArg` (j92 / jxl / both) · `JxlEffortArg`
//! (the e4/e7/e9 ladder — unmeasured efforts rejected by clap) ·
//! `LossyFormatArg` (34892 / dct12) · `ZstdMode` (the bake
//! container compression: none / 9 / 19). `Cli` = the top-level
//! parse (the required-check lives in the dispatch's legacy path for
//! the clap 4.6.6 positional + subcommand misparse — same rc=2,
//! clap-mirrored message; every valid invocation parses identically
//! — `subcommand_negates_reqs` on the parser). The helpers:
//! `cli_args_string` (the both run's ledger command column) ·
//! `tier_cli` (the per-tier CLI copy) · `selection_column` /
//! `subset_context` (the ledger's v2 selection + v3 context
//! columns). The `Cmd` subcommand enum rides at the crate root (the
//! variant-field visibility rule — see the root's module doc).

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

// the Cli field type: the subcommand enum rides at the root (the E0449 decision)
use crate::Cmd;

/// Encoding mode (the lossy tier is parked).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum ModeArg {
    /// 12-bit samples, lossless tile JPEG (the default).
    Lossless,
    /// 10-bit log codes: same lossless tile structure at data precision
    /// 10 + LinearizationTable (50712).
    Log10,
    // The parked lossy tier is hidden from the rendered help
    // (invisible in --help / -h) but stays parseable — the escape hatch.
    /// Lossy VBR high-quality (34892/LinearRaw/8-bit, fixed quality).
    #[value(hide = true)]
    VbrHq,
    /// Lossy VBR light (34892/LinearRaw/8-bit, fixed quality).
    #[value(hide = true)]
    VbrLt,
    /// Lossy CBR ~3:1 (per-frame quality binary-search).
    #[value(hide = true)]
    Cbr3,
    /// Lossy CBR ~4:1 (per-frame quality binary-search).
    #[value(hide = true)]
    Cbr4,
    /// Lossy CBR ~5:1 (per-frame quality binary-search).
    #[value(hide = true)]
    Cbr5,
    /// Lossy CBR ~7:1 (per-frame quality binary-search).
    #[value(hide = true)]
    Cbr7,
}

impl std::fmt::Display for ModeArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ModeArg::Lossless => "lossless",
            ModeArg::Log10 => "log10",
            ModeArg::VbrHq => "vbr-hq",
            ModeArg::VbrLt => "vbr-lt",
            ModeArg::Cbr3 => "cbr3",
            ModeArg::Cbr4 => "cbr4",
            ModeArg::Cbr5 => "cbr5",
            ModeArg::Cbr7 => "cbr7",
        })
    }
}

/// Output codec (the JXL flag). `j92` = today's path
/// (byte-identical 0.2.0 behavior — the regression gate is the 10f
/// oracle + suite); `jxl` = JXL modular lossless, 4 × 2×2 sub-plane
/// `.jxl` per frame (cjxl 0.12.0 subprocess; effort = `--jxl-effort`,
/// default e7) + the mandatory `<CLIP>.jxl-checksums.tsv` sidecar.
/// JXL is lossless-only: no `--mode` combos, no `--downscale2x`, no
/// `--fast` (v1 rejects with a clear error, not a silent ignore).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum CodecArg {
    /// J92 lossless tile JPEG inside the DNG container (the default).
    J92,
    /// JXL modular lossless (effort via `--jxl-effort`, default e7),
    /// 4 × `.jxl` per frame (the 2×2 sub-planes) + the mandatory
    /// jxl-checksums sidecar. `--jobs` sets the cjxl/djxl thread budget
    /// (0 = all cores; N = `--num_threads=N`).
    Jxl,
    /// Both tiers in one command: sequential j92 (the working tier →
    /// `output`) then jxl (the archival tier → `output-jxl`), each tier
    /// running its standalone path unchanged (the both run's trees are
    /// byte-identical to the two standalone runs). The space guard
    /// reserves both tiers' estimates (the combined preflight); the run
    /// report + ledger are per-tier (two rows, the codec column
    /// canonical). v1 scope — the named rc=2 refusals: no tier-spanning
    /// resume (the jxl tier's recovery is the standalone `--force`
    /// re-run), no `--clips`/`--skip` (the jxl path has no selection in
    /// v1), no `--verify-checksums` (the pass is ambiguous).
    Both,
}

impl std::fmt::Display for CodecArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CodecArg::J92 => "j92",
            CodecArg::Jxl => "jxl",
            CodecArg::Both => "both",
        })
    }
}

/// JXL encoder effort (the effort flag): restricted to the
/// ladder only (unmeasured efforts 0-3 / 5-8 are rejected
/// by clap), default behavior = 7 (was e9 before this flag). Flows
/// into the cjxl `-e` invocation and the sidecar `effort` column.
/// the effort ladder: e7 4.6× faster encode than e9
/// for +1.3…2.7% size; e4 10.9× for +1.9…10.1%.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum JxlEffortArg {
    /// fastest.
    #[value(name = "4")]
    E4,
    /// default.
    #[value(name = "7")]
    E7,
    /// smallest size (slowest).
    #[value(name = "9")]
    E9,
}

impl JxlEffortArg {
    /// The cjxl `-e` value.
    pub(crate) fn as_u32(self) -> u32 {
        match self {
            JxlEffortArg::E4 => 4,
            JxlEffortArg::E7 => 7,
            JxlEffortArg::E9 => 9,
        }
    }
}

impl std::fmt::Display for JxlEffortArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            JxlEffortArg::E4 => "4",
            JxlEffortArg::E7 => "7",
            JxlEffortArg::E9 => "9",
        })
    }
}

/// Lossy wire format (): the mode preset (quality) is
/// orthogonal to the wire format — the six presets target either
/// 34892/LinearRaw/8-bit or the tag-7 12-bit DCT parity tiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum LossyFormatArg {
    /// 34892/LinearRaw/8-bit (experimental/archive — NLE-unreadable per the
    /// a recorded decision; not the default).
    #[value(name = "34892")]
    K34892,
    /// Reference tag-7: 12-bit DCT parity tiles under DNG Compression 7
    /// (the dct12 lossy format; docs/format-dct12.md; the
    /// default production lossy family).
    #[value(name = "dct12")]
    ReferenceDct,
}

impl std::fmt::Display for LossyFormatArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LossyFormatArg::K34892 => "34892",
            LossyFormatArg::ReferenceDct => "dct12",
        })
    }
}

/// Bake container compression (`--zstd` for `frameprism bake`):
/// `none` = plain tar (store), `9`/`19` = tar|zstd at that
/// level. J92 output:
/// −4.4…−13.8% (granularity > codec level); JXL incompressible (0% in
/// all 10 containers) — detection therefore defaults j92 → 19 and
/// jxl → none; an explicit `--zstd` always wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum ZstdMode {
    /// Plain tar (store) — no compression (the jxl detection default).
    None,
    /// tar|zstd -9 (fast compression; when encode time matters).
    #[value(name = "9")]
    L9,
    /// tar|zstd -19 (maximum compression; the j92 detection default).
    #[value(name = "19")]
    L19,
}

#[derive(Parser, Debug)]
#[command(
    name = "frameprism",
    version,
    about = "A lossless, verifiable CinemaDNG archive tool with an integrated safe-offload workflow (camera card → drives → archive)",
    after_long_help = "Design notes + the per-flag rc semantics: docs/cli.md\nThe dct12 format (the parked lossy tier): docs/format-dct12.md",
    subcommand_negates_reqs = true
)]
pub(crate) struct Cli {
    /// Directory containing the source .dng frame sequence (recursed)
    pub(crate) input: Option<PathBuf>,

    /// Directory to write the compressed sequence to (created if missing)
    pub(crate) output: Option<PathBuf>,

    /// Encoding mode: lossless (12-bit, default) / log10 (10-bit log)
    #[arg(long, value_enum, default_value_t = ModeArg::Lossless)]
    pub(crate) mode: ModeArg,

    // The parked lossy tier is hidden from the rendered help
    // (invisible in --help / -h) but stays parseable — the escape hatch
    // (the parse-path refusal messages are unchanged).
    /// Lossy wire format: dct12 = the tag-7
    /// 12-bit DCT parity tiles (DNG Compression 7; the default — production
    /// lossy family); 34892 = 34892/LinearRaw/8-bit (experimental/archive,
    /// NLE-unreadable (a recorded decision). Only meaningful with a lossy --mode.
    #[arg(long, hide = true, value_enum, default_value_t = LossyFormatArg::ReferenceDct)]
    pub(crate) lossy_format: LossyFormatArg,

    /// Reference DNG (any preset/frame of the clip) for
    /// --lossy-format dct12: the 50712 curve is byte-copied from it
    /// (default: the embedded A001 curve constant).
    #[arg(long, hide = true)]
    pub(crate) reference_ref: Option<PathBuf>,

    /// Measured per-frame reference MAE TSV (dct2s quality format: frame,
    /// mae, …) for --lossy-format dct12 --verify: the G2 pixel gate
    /// then also requires our MAE within [0.5×, 1.5×] of the measured
    /// same-frame MAE (default: the p99-only gate).
    #[arg(long, hide = true)]
    pub(crate) reference_mae_tsv: Option<PathBuf>,

    /// Measured per-frame reference STRUCTURE TSV ( tab-separated:
    /// frame, v_ratio, h_ratio, dem2_wg, dem2_gr, dem2_wr — the corpus
    /// golden's d2diag/d2demo signature) for --lossy-format dct12
    /// --verify: the structure gates then use the per-frame
    /// reference-anchored bands (gate_structure upper bounds + the FATAL
    /// gate_demosaic; default: the reference-independent floors only —
    /// informational demosaic line).
    #[arg(long, hide = true)]
    pub(crate) reference_structure_tsv: Option<PathBuf>,

    /// Half-resolution working file (proxy): CFA-phase-correct 2×
    /// decimation of the camera's W G / G R pattern, re-encoded in the
    /// same tile structure + DNG proxy signalling (51089/51090/51091 =
    /// the original crop size). Composable with `--mode` (the stats
    /// ratio stays against the full-resolution input).
    #[arg(long)]
    pub(crate) downscale2x: bool,

    /// Single-candidate fast mode (lossless only): skip the per-tile
    /// trial encode and always use the fixed Wrapped PSV 7 candidate
    /// (bit-exact lossless, verify unaffected). Composes with
    /// `--downscale2x`
    #[arg(long)]
    pub(crate) fast: bool,

    /// Bit-exact verify per frame (lossless: decode out == unpack in;
    /// log10: LUT-inverted reconstruction within the curve bound + the
    /// mode's metadata expected-diff set)
    #[arg(long)]
    pub(crate) verify: bool,

    /// Overwrite/skip-over existing outputs (default: skip = resume)
    #[arg(long)]
    pub(crate) force: bool,

    /// Verified resume: a frame skips ONLY if its output exists AND the
    /// sidecar row's sha256 verifies over the on-disk output AND the
    /// source sha (when the input carries it) matches the row; anything
    /// else re-encodes (a missing frame, a corrupted output, a changed
    /// source). j92 only — `--codec jxl` + `--resume` is the named rc=2
    #[arg(long)]
    pub(crate) resume: bool,

    /// Opt in to ingesting a sparse subset: the ingest safety gate runs
    /// with the four within-clip continuity checks waived (a sparse
    /// subset is legal by construction); every other class stays a hard
    /// refusal. The waiver is recorded named in the per-clip report +
    /// the ledger row
    #[arg(long)]
    pub(crate) subset: bool,

    /// Also write a TSV report to this path (manifest-compatible columns)
    #[arg(long)]
    pub(crate) report: Option<PathBuf>,

    /// Estimate the compression rate + ETA on this footage by encoding a
    /// pinned sample in memory; creates nothing under <dest>
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Explicit dry-run sample size K (1 ≤ K ≤ N; K=N = the full-clip
    /// measurement). Absent = the default clamp (10% of N, floored at
    /// 20, capped at 60); K=0 or K>N = the named usage refusal (rc=2,
    /// before the gate)
    #[arg(long)]
    pub(crate) dry_run_frames: Option<u64>,

    /// Output codec: j92 (the default) or jxl (JXL modular lossless,
    /// 4 × `.jxl` per frame + the mandatory jxl-checksums sidecar;
    /// lossless only; encoder effort via --jxl-effort, default e7)
    #[arg(long, value_enum, default_value_t = CodecArg::J92)]
    pub(crate) codec: CodecArg,

    /// JXL encoder effort for `--codec jxl` only: 4 | 7 | 9 (default 7;
    /// unmeasured efforts are rejected). Explicit `--jxl-effort` +
    /// `--codec j92` is rejected (rc=2: "--jxl-effort requires --codec jxl")
    #[arg(long, value_enum)]
    pub(crate) jxl_effort: Option<JxlEffortArg>,

    /// JXL encode parallelism for `--codec jxl` only: the number of
    /// concurrent `cjxl` processes. 0 (default) = all cores, 1 =
    /// serial, >= 2 = that many. `--jobs` is unchanged (the per-cjxl
    /// thread budget). Explicit `--jxl-parallel` + `--codec j92` is
    /// rejected (rc=2: "--jxl-parallel requires --codec jxl")
    #[arg(long)]
    pub(crate) jxl_parallel: Option<usize>,

    /// cjxl binary for `--codec jxl` (path or PATH name; default `cjxl`)
    #[arg(long, default_value = "cjxl")]
    pub(crate) cjxl_bin: PathBuf,

    /// djxl binary for `--codec jxl` `--verify` (path or PATH name;
    /// default `djxl`). Same binary family/version as cjxl.
    #[arg(long, default_value = "djxl")]
    pub(crate) djxl_bin: PathBuf,

    /// After the run, write <OUT_DIR>/<CLIP>.checksums.tsv (file, size,
    /// crc32c — CRC-32C Castagnoli) over every output frame
    #[arg(long)]
    pub(crate) checksums: bool,

    /// Run ONLY the checksum verification pass: re-read
    /// <OUT_DIR>/<CLIP>.checksums.tsv and every listed file, recompute
    /// size + CRC-32C; nonzero exit on any mismatch or missing file (no
    /// frames are encoded in this mode)
    #[arg(long)]
    pub(crate) verify_checksums: bool,

    /// Per-clip QC gate: the deterministic checks — black/blank frames +
    /// file-level duplicate frames — become hard gates: any hit → the
    /// run COMPLETES (no data loss — the files are written) and exits
    /// rc=2 with the named rows (the gate is a verdict, not a preflight
    /// refusal). Absent (default) = report only: the exposure stats +
    /// the candidates are always named in the run report (the additive
    /// <CLIP>.qc.tsv per-frame record + the clip-level moments); the run
    /// never gates. j92 decode site only: `--codec jxl` + `--qc-gate` =
    /// the named no-op note (v1)
    #[arg(long)]
    pub(crate) qc_gate: bool,

    /// Worker thread count (0 = all cores, the default)
    #[arg(long, default_value_t = 0)]
    pub(crate) jobs: usize,

    /// Also mirror every input file to <dest> (mirrored subpaths,
    /// mtime-preserving) + write the per-file verify manifest
    /// <CLIP>.offload-manifest.tsv (the verify-before-unmount gate).
    /// Dirty rows = named FAIL lines + rc=1 AFTER the encode; the dest
    /// is probed at startup (unwritable = rc=2 before any frame). Both
    /// the j92 and the jxl paths
    #[arg(long)]
    pub(crate) to: Option<PathBuf>,

    /// Pins file for the pin self-check: the byte-identity contracts
    /// probed BEFORE the first frame/byte (a drift/missing binary = the
    /// named refusal rc=2, zero output). The flag opts the check IN
    /// (absent = no pin gate); without a value: `FRAMEPRISM_PINS` env (the legacy
    /// `<cwd>/ci/pins.tsv` → `<exe_dir>/../ci/pins.tsv` (not found = a
    /// named skip line, never a refusal)
    #[arg(long, num_args = 0..=1)]
    pub(crate) pins: Option<Option<PathBuf>>,

    /// Comma separated clip keys to ENCODE (the input's clip key space —
    /// the frame parent dirs relative to the input root). Unknown name /
    /// `--clips` + `--skip` conflict / empty effective set = the named
    /// rc=2 before any frame. Absent = the full set. The selection is
    /// journaled (the ledger's `selection` column) + the run report
    /// carries the `selection:` line
    #[arg(long)]
    pub(crate) clips: Option<String>,

    /// Comma separated clip keys to LEAVE OUT (the complement of the
    /// encode universe). The resolution rules are `--clips`' (unknown
    /// name / conflict / empty effective set = the named rc=2 before
    /// any frame). Absent = no exclusions.
    #[arg(long)]
    pub(crate) skip: Option<String>,

    /// subcommand (absent = the legacy positional `input` /
    /// `output` dispatch, behavior-identical — `subcommand_negates_reqs`
    /// on the parser)
    #[command(subcommand)]
    pub(crate) command: Option<Cmd>,
}

/// The actual CLI string ( the both run's ledger rows carry
/// it in the command column, incl. `--codec both`; the standalone rows
/// keep the `legacy` label).
pub(crate) fn cli_args_string() -> String {
    std::env::args().collect::<Vec<String>>().join(" ")
}

/// The per-tier CLI copy ( the both dispatch's tiers override
/// exactly the codec + the tier's `--to` dest + the tier's `--report`
/// path; everything else is the CLI as given (the tiers run their
/// standalone paths byte-unchanged). `command` stays None — the
/// legacy dispatch is reached only when no subcommand word is present
/// (the subcommand path returned earlier in main()). The manual copy:
/// the subcommand `Args` structs (decode/audit/derived) do not
/// derive Clone, and those files are out of scope.
pub(crate) fn tier_cli(cli: &Cli, codec: CodecArg, to: Option<PathBuf>, report: Option<PathBuf>) -> Cli {
    Cli {
        input: cli.input.clone(),
        output: cli.output.clone(),
        mode: cli.mode,
        lossy_format: cli.lossy_format,
        reference_ref: cli.reference_ref.clone(),
        reference_mae_tsv: cli.reference_mae_tsv.clone(),
        reference_structure_tsv: cli.reference_structure_tsv.clone(),
        downscale2x: cli.downscale2x,
        fast: cli.fast,
        verify: cli.verify,
        force: cli.force,
        resume: cli.resume,
        subset: cli.subset,
        dry_run: cli.dry_run,
        dry_run_frames: cli.dry_run_frames,
        report,
        codec,
        jxl_effort: cli.jxl_effort,
        jxl_parallel: cli.jxl_parallel,
        cjxl_bin: cli.cjxl_bin.clone(),
        djxl_bin: cli.djxl_bin.clone(),
        checksums: cli.checksums,
        verify_checksums: cli.verify_checksums,
        qc_gate: cli.qc_gate,
        jobs: cli.jobs,
        to,
        pins: cli.pins.clone(),
        clips: cli.clips.clone(),
        skip: cli.skip.clone(),
        command: None,
    }
}

/// The ledger's v2 `selection` column: the run's active
/// selection (its sorted processed set) — empty = the full set or a
/// run with no selection (the v1 file keeps its 10-column shape for
/// these rows — the one-time bump fires on the first selected row).
pub(crate) fn selection_column() -> String {
    match frameprism::selection::current() {
        Some(a) => frameprism::selection::selection_string(Some(&a.selected)),
        None => String::new(),
    }
}

/// The v3 ledger `context` column for the encode rows: the
/// `--subset` marker — the SAME string as the per-clip report's named
/// line (byte-stable, no wall clock, no path) — present iff the run
/// ran under the NAMED subset opt-in; empty otherwise (the default
/// rows keep today's exact bytes — the marker is the named door's
/// journal entry, not a default-path byte).
pub(crate) fn subset_context(cli: &Cli) -> String {
    if cli.subset {
        frameprism::worker::SUBSET_MARKER.to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cmd;

    // The offload surface (the standalone pass-through mirror +
    // verify — the subcommand's help + parse, the tripwire names the
    // surface: the H1 blocklist above renders EVERY subcommand's
    // help including this one; this pins the parse + the rendered
    // usage + re-asserts the blocklist on the offload surface alone).
    #[test]
    fn offload_help_surface_parses_and_renders() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let offload = cmd
            .get_subcommands()
            .into_iter()
            .find(|sc| sc.get_name() == "offload")
            .expect("the offload subcommand is registered");
        let rendered = offload.clone().render_long_help().to_string();
        // The rendered usage line (the pinned line — the OVERRIDDEN
        // usage on the offload Args: the two positionals — `in` now
        // optional at the parse level (the multi-source form has no
        // positionals), `to` variadic — + the two multi-source form
        // flags): `frameprism offload [in] <to>... [--source
        // <SOURCE>... --dest <DEST>...]` (bin-target
        // tests do not move the `--lib` pin).
        assert!(
            rendered.contains("Usage: frameprism offload [in] <to>... [--source <SOURCE>... --dest <DEST>...]"),
            "the pinned usage line renders:\n{rendered}"
        );
        // The blocklist (the H1 set, the same idiom as
        // help_surface_is_oss_clean — the surface named):
        // absent from the rendered offload help.
        for pat in [
            "ROADMAP",
            "vendor",
            "lane-P",
            "bake-lane",
            "owner",
            "plateau",
            "DIT",
            "2076",
            "D-21",
            "D13",
            "Phase 1",
            "item 1",
            "task 1",
        ] {
            assert!(
                !rendered.contains(pat),
                "blocklist literal `{pat}` matched in the rendered offload help — reword the text, never this test:\n{rendered}"
            );
        }
        // The parse (the positional arity — one dest):
        // `frameprism offload <in> <to>` (the single-source form —
        // the flags absent; the flags' parse defaults: `source`
        // empty, `dest` empty).
        let parsed = Cli::try_parse_from(["frameprism", "offload", "/card", "/mirror"]).unwrap();
        match parsed.command {
            Some(Cmd::Offload(args)) => {
                assert_eq!(args.input, Some(std::path::PathBuf::from("/card")));
                assert_eq!(args.to, vec![std::path::PathBuf::from("/mirror")]);
                assert!(args.source.is_empty());
                assert!(args.dest.is_empty());
            }
            other => panic!("the offload parse: {other:?}"),
        }
        // The parse (the fan-out arity — N dests):
        // `frameprism offload <in> <to> [<to> ...]`.
        let parsed = Cli::try_parse_from(["frameprism", "offload", "/card", "/m1", "/m2", "/m3"]).unwrap();
        match parsed.command {
            Some(Cmd::Offload(args)) => {
                assert_eq!(args.input, Some(std::path::PathBuf::from("/card")));
                assert_eq!(
                    args.to,
                    vec![
                        std::path::PathBuf::from("/m1"),
                        std::path::PathBuf::from("/m2"),
                        std::path::PathBuf::from("/m3"),
                    ]
                );
            }
            other => panic!("the offload fan-out parse: {other:?}"),
        }
        // The parse (the multi-source form — NO positionals; the
        // sources + the dests are named with the flags — the
        // invocation shape): `frameprism offload --source <SOURCE>...
        // --dest <DEST>...` (a single `--source` + a single `--dest`
        // = the single-source multi-shape, incl. single-dest).
        let parsed = Cli::try_parse_from([
            "frameprism",
            "offload",
            "--source",
            "/cardA",
            "/cardB",
            "--dest",
            "/d1",
            "/d2",
        ])
        .unwrap();
        match parsed.command {
            Some(Cmd::Offload(args)) => {
                assert_eq!(args.input, None);
                assert_eq!(
                    args.source,
                    vec![
                        std::path::PathBuf::from("/cardA"),
                        std::path::PathBuf::from("/cardB")
                    ]
                );
                assert_eq!(
                    args.dest,
                    vec![
                        std::path::PathBuf::from("/d1"),
                        std::path::PathBuf::from("/d2")
                    ]
                );
                assert!(
                    args.to.is_empty(),
                    "the multi-form has no positional dests"
                );
            }
            other => panic!("the offload multi-form parse: {other:?}"),
        }
        // The parse (the single-source multi-shape,
        // CLI-reachable incl. single-dest): `frameprism offload
        // --source <SOURCE> --dest <DEST>`.
        let parsed = Cli::try_parse_from([
            "frameprism",
            "offload",
            "--source",
            "/cardA",
            "--dest",
            "/d1",
        ])
        .unwrap();
        match parsed.command {
            Some(Cmd::Offload(args)) => {
                assert_eq!(args.input, None);
                assert_eq!(args.source, vec![std::path::PathBuf::from("/cardA")]);
                assert_eq!(args.dest, vec![std::path::PathBuf::from("/d1")]);
                assert!(args.to.is_empty());
            }
            other => panic!("the offload single-source multi-shape parse: {other:?}"),
        }
    }
}
