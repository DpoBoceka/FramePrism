//! The arg + row/report model: the `frameprism audit` /
//! `restore` CLI args (`AuditArgs` / `RestoreArgs`), the
//! sidecar row model (`Row` — the file column + the expected
//! digests), the sidecar classes (`SidecarKind` / `Sidecar`),
//! the offender (`Offender`), and the per-sidecar report
//! (`SidecarReport`).

use std::path::PathBuf;

use clap::Args as ClapArgs;

/// The `frameprism audit` CLI arguments (the `Cmd::Audit` payload — the
/// subcommand args live here, not in `main.rs`, per the shared CLI
/// convention).
#[derive(ClapArgs, Debug)]
pub struct AuditArgs {
    /// The encoded clip dir to audit (the sidecar lives INSIDE it —
    /// discovery is by glob, never by dir-basename derivation; the
    /// offload mirror's re-verify record + the `ascmhl/` MHL history
    /// are the detection-driven additional surfaces — the MHL arm is
    /// inert on a dir without `ascmhl/`, byte-identical to pre-existing).
    pub input: PathBuf,
    /// Parallel file-read pool for the sweep (0 = all cores, the
    /// default).
    #[arg(long, default_value_t = 0)]
    pub jobs: usize,
    /// Verify-against-source (the direct card archive): the LIVE
    /// source tree (the mounted card — a single clip dir or the
    /// multi-clip tree; the clip key = the folder name, matching the
    /// record's `clip:` key — a mismatch = the named rc=2, zero
    /// partial verdicts). Every row of every
    /// discovered `<CLIP>.sources.tsv` record in `<input>` is re-read
    /// from the source + re-hashed (the offload row vocabulary: OK /
    /// MISSING / SIZE_MISMATCH / SHA_MISMATCH — named per row; loud,
    /// named, no silent skip), and the CARD verdict is printed (the
    /// release-gate claim — the tool NEVER wipes the card: the card is
    /// reusable ONLY after `CARD UNLOCKED`; the format is the
    /// operator's action). A corrupt record (bad magic / bad column
    /// count) = the named hard rc=2 (the records-class refusal); an
    /// absent source / an absent record = the named `CARD
    /// UNVERIFIABLE` line (the source rows are NOT verified; the
    /// archive audit is unaffected — the rc follows the archive audit
    /// result). Absent = the pre-existing audit (unchanged output + rc +
    /// verdicts).
    #[arg(long)]
    pub source: Option<PathBuf>,
}

/// The `frameprism restore` CLI arguments (the `Cmd::Restore` payload).
#[derive(ClapArgs, Debug)]
pub struct RestoreArgs {
    /// The (possibly corrupted) encoded clip dir. The arbiter is ITS
    /// sidecar, never the master's.
    pub input: PathBuf,
    /// The pristine master clip dir (the restore candidates; never
    /// modified).
    #[arg(long)]
    pub from: PathBuf,
    /// Restore ONE frame only (1-based, sorted frame-stem order = the
    /// decode convention); absent = every offender.
    #[arg(long)]
    pub frame: Option<u32>,
    /// Parallel file-read pool (0 = all cores, the default).
    #[arg(long, default_value_t = 0)]
    pub jobs: usize,
    /// Overwrite an existing `<file>.pre-restore` (default: reject,
    /// rc=2).
    #[arg(long)]
    pub force: bool,
}

/// One sidecar row: the file column + the expected digests.
#[derive(Clone, Debug)]
pub(crate) struct Row {
    /// The file column (relative to the clip dir — the same resolution
    /// `checksums::verify_checksums` uses).
    pub(crate)file: String,
    pub(crate)size: u64,
    pub(crate)sha: String,
    /// The expected crc32c (None when the format has no crc column —
    /// neither shipped format, but the parse is permissive).
    pub(crate)crc: Option<u32>,
    /// The frame stem (the 1-based `--frame` numbering key: j92 = the
    /// file stem; jxl = the stem with the `_p2_XX` plane suffix
    /// stripped).
    pub(crate)stem: String,
}

/// The sidecar class (the per-format parse + sweep). The J92/JXL
/// checksums sidecars cover LOOSE files in the clip dir; the bake
/// manifest covers the ARCHIVE members (the sealed-tier audit
/// surface — the frames live inside the per-clip tar parts).
#[derive(Debug)]
pub(crate) enum SidecarKind {
    /// A `*.checksums.tsv` / `*.jxl-checksums.tsv` sidecar.
    Checksums,
    /// A `*.bake-manifest.tsv` manifest: the optional explicit
    /// archive part list (None = the single derived
    /// `<clip>.<container>` archive, the v2 manifest without the
    /// additive `archive:` field).
    Bake {
        parts: Option<Vec<String>>,
        clip: String,
        container: String,
    },
}

/// One parsed sidecar (a checksums sidecar or a bake manifest).
#[derive(Debug)]
pub(crate) struct Sidecar {
    pub(crate)name: String,
    pub(crate)kind: SidecarKind,
    pub(crate)rows: Vec<Row>,
}

/// One offender: the row, the first failing problem, the target path.
#[derive(Debug)]
pub(crate) struct Offender {
    pub(crate)row: Row,
    pub(crate)problem: String,
    pub(crate)target: PathBuf,
}

/// The audit result over one sidecar.
#[derive(Debug)]
pub(crate) struct SidecarReport {
    pub(crate)sidecar: String,
    pub(crate)rows: Vec<Row>,
    pub(crate)offenders: Vec<Offender>,
}
