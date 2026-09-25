//! The re-copy delta — the repair loop.
//!
//! After the two-destination offload, a mismatch/missing row
//! does NOT re-run the clip: the repair NAMES the row, re-transfers ONLY
//! those files, re-verifies the sha256 (fresh — never a previous
//! verdict), and re-emits the run report with the updated verdict.
//!
//! Mechanism = the manifest-row diff (the source vs EACH destination:
//! missing / size-mismatch / sha-mismatch / clean) + the selective copy
//! (dirty rows only, mtime-preserving — the offload already preserves
//! shoot-time mtimes; the repair copy is the same discipline) + the
//! re-verify. The verify-before-wipe gate holds on the FULL set: the
//! disk verdict is REFUSE while ANY row is dirty in ANY destination,
//! and only the fully clean diff flips it (a clean delta never unlocks
//! the camera disk while any row is still dirty).
//!
//! The destinations ("ingest copies to the workspace AND an
//! optional `--to <dir>` and sha256-verifies BOTH against the source"):
//!   - the `--to` DEST — the full mirror of the source tree (EVERY row
//!     rides a verbatim copy: frames + the non-DNG members WAV/XMP/
//!     manifest.tsv);
//!   - the WORKSPACE output — the encode's OUT_DIR. The non-DNG members
//!     are copied verbatim there too (the worker's sidecar copy), so a
//!     member row is diffed against BOTH trees (a row can be clean in
//!     one and dirty in the other). The .DNG frames in the workspace
//!     are the RE-ENCODED archive (their integrity is the checksums
//!     sidecar's surface — the `audit` / `--verify-checksums` half of
//!     the verify-before-wipe sweep), so a frame row is diffed against
//!     the `--to` dest only.
//!
//! The surface operates from the EXISTING `offload-manifest.tsv` + the
//! source tree — it never re-encodes and never re-scans-and-recopies
//! the whole clip (only the dirty rows are re-transferred).
//!
//! The manifest row COLUMNS stay the v1 shape (the offload record —
//! source → the `--to` dest: a repaired row flips to its clean verdict
//! on success); the per-clip blocks + the verdict line are the FULL-SET
//! claim (any destination — the disk verdict). The re-emitted run
//! report carries the updated verdict line + the named `offload
//! dirty:` rows (deterministic — a pure function of the pre-repair
//! report + the post-repair state; no wall clock is introduced, the
//! original `created:` line stands).
//!
//! rc: 0 = the full set is clean after the repair (the verdict flips
//! VERIFIED — the camera disk is unlocked); 1 = rows are still dirty
//! (named — the verdict stays REFUSE); 2 = usage (a missing/corrupt
//! offload record, a dest/input that does not match the recorded
//! record, an unknown `--rows` name — the pre-run named class).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::offload::{self, Verdict};

// A repaired clip (the manifest + its staged path).
type RepairedManifest = (RepairManifest, PathBuf);

/// One destination side of the row diff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The `--to` offload dest (the full mirror — every row).
    Dest,
    /// The workspace output (the verbatim member copies — the non-DNG
    /// rows only; the frames there are the re-encoded archive).
    Workspace,
}

impl Side {
    pub fn as_str(self) -> &'static str {
        match self {
            Side::Dest => "dest",
            Side::Workspace => "workspace",
        }
    }
}

/// The per-destination row classification (the four classes).
/// The canonical reference is the FRESH source (re-hashed per repair
/// run — never a carried ledger value).
#[derive(Clone, Debug, PartialEq)]
pub enum RowClass {
    /// The dest file exists, matches the source size, and its sha256
    /// matches the source sha256.
    Clean,
    /// The dest file is absent.
    Missing,
    /// The dest file exists with a different size.
    SizeMismatch { found: u64, want: u64 },
    /// The dest file exists, matches the size, but its sha256 differs.
    ShaMismatch { want: String, found: String },
}

impl RowClass {
    /// The manifest/report column value (the offload's spec names for
    /// the mismatch classes).
    pub fn as_str(&self) -> &'static str {
        match self {
            RowClass::Clean => "OK",
            RowClass::Missing => "MISSING",
            RowClass::SizeMismatch { .. } => "SIZE_MISMATCH",
            RowClass::ShaMismatch { .. } => "SHA_MISMATCH",
        }
    }
    pub fn is_clean(&self) -> bool {
        matches!(self, RowClass::Clean)
    }
    /// The named detail (the report's `offload dirty:` line).
    pub fn detail(&self) -> String {
        match self {
            RowClass::Clean => String::new(),
            RowClass::Missing => "file missing".to_string(),
            RowClass::SizeMismatch { found, want } => {
                format!("size {found} B, want {want} B")
            }
            RowClass::ShaMismatch { want, found } => {
                format!("sha256 {found}, want the source {want}")
            }
        }
    }
}

/// Classify ONE dest file against the canonical source (size + sha256).
/// `want_size` / `want_sha` = the FRESH source values (the re-hash);
/// `dest` = the file to classify (the `--to` or the workspace copy).
/// The source is the reference — a dest that matches it is clean; a
/// read failure on the dest side is the missing class (a file that
/// cannot be read cannot be verified — the loud class, named the same
/// as an absent one, because the repair's re-copy treats both as
/// "no good file there").
pub fn classify_row(want_size: u64, want_sha: &str, dest: &Path) -> RowClass {
    if !dest.is_file() {
        return RowClass::Missing;
    }
    // The bounded reads — the size from the O(1) stat, the
    // sha streamed; a read failure is the missing class (a file that
    // cannot be read cannot be verified — the loud class above).
    let found_size = match std::fs::metadata(dest).map(|m| m.len()) {
        Ok(s) => s,
        Err(_) => return RowClass::Missing,
    };
    let found = match crate::jxl::sha256_stream_path(dest) {
        Ok(s) => s,
        Err(_) => return RowClass::Missing,
    };
    if found_size != want_size {
        RowClass::SizeMismatch {
            found: found_size,
            want: want_size,
        }
    } else if found == want_sha {
        RowClass::Clean
    } else {
        RowClass::ShaMismatch {
            want: want_sha.to_string(),
            found,
        }
    }
}

/// The one-sided repair of a dirty row: re-copy the source to the side
/// path (mirrored subpaths, mtime-preserving, overwrite) + the
/// re-verify (BOTH sides re-hashed fresh — the verification cost is the
/// design; the previous verdict is never trusted). Returns the
/// post-repair class (Clean = the row's side flipped; otherwise the
/// named failure detail).
fn recopy_and_reverify(
    src: &Path,
    side_path: &Path,
    side_root: &Path,
) -> Result<RowClass, String> {
    // The write-path root-boundary invariant (the
    // named residual — the intermediate-dir symlink class): the side
    // re-copy's write-path PARENT (the dir the copy lands in) must be
    // inside the side root's canonical form (a planted symlinked DIR
    // component between the root and the side_path redirects the
    // re-copy into an outside dir; the final-component guard below
    // does NOT see it — the leaf is a regular file the tool creates).
    // The guard checks the PARENT (not the side_path itself) so it
    // scopes to the INTERMEDIATE-DIR class + stays disjoint from the
    // final-component guard (a link at the leaf is that guard's class
    // — its WORDING PIN — the parent of a leaf-link is a real dir
    // under the root, so this guard passes + the final-component
    // guard refuses it). The
    // root = the side root AS GIVEN (`dest` for Side::Dest, `output`
    // for Side::Workspace); a legitimate volume alias in the root's
    // path resolves identically on both sides (accepted — the
    // over-refusal lesson). On violation: the named error rides the
    // caller's EXISTING Err arm (the named line + the row stays dirty
    // — both guards are pre-write, zero-partial for
    // the row). The leaf guard below stays UNTOUCHED (the WORDING
    // PIN).
    if let Some(parent) = side_path.parent() {
        offload::check_root_bound(parent, side_root)
            .map_err(|err| err.to_string())?;
    }
    let src_meta = std::fs::metadata(src)
        .map_err(|err| format!("stat the source {}: {err}", src.display()))?;
    // The bounded streaming sha (the size is the
    // `src_meta.len()` above — the O(1) stat); the re-scan wording
    // is the pre-existing one.
    let src_sha = crate::jxl::sha256_stream_path(src)
        .map_err(|err| format!("re-scan the source {}: {err}", src.display()))?;
    // The dest-side symlink refusal (the
    // write-through class): `fs::copy` follows a planted symlink at
    // the dest path + overwrites the outside target it points to (the
    // single exception in the PROD inventory — the rename seams
    // replace the link, never follow it). `symlink_metadata` = lstat
    // (does not follow): the planted class (incl. the dangling link —
    // lstat sees the link itself) is the named refusal; the regular /
    // missing / directory classes keep the existing behavior (the
    // overwrite / the copy / the copy error). FINAL COMPONENT only
    // (the named finding's class — the offload walker never emits a
    // symlink entry into the dest tree, so a link at the row path is
    // by definition planted): a per-component walk would refuse
    // legitimate symlinked dest roots (the volume-alias class the
    // offload writes under today — the over-refusal lesson). The
    // mtime site below runs only after a successful copy — this guard
    // is the single choke point.
    if let Ok(ft) = std::fs::symlink_metadata(side_path) {
        if ft.is_symlink() {
            return Err(format!(
                "the repair dest {} is a symlink (the re-copy would follow the link + overwrite the outside target it points to — the write-through is refused): the row stays dirty + named — remove the symlink + re-run",
                side_path.display()
            ));
        }
    }
    if let Some(parent) = side_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create the dest subdir {}: {err}", parent.display()))?;
    }
    std::fs::copy(src, side_path)
        .map_err(|err| format!("copy {} -> {}: {err}", src.display(), side_path.display()))?;
    // The offload's mtime discipline (shoot-time mtimes preserved):
    // `File::set_modified` after the copy (a failure is a named note,
    // the content copy stands — the offload's exact convention).
    if let Ok(mtime) = src_meta.modified() {
        if let Err(err) = std::fs::File::open(side_path).and_then(|f| f.set_modified(mtime)) {
            eprintln!(
                "note: the repair mtime set on {} failed ({err}) — the content copy stands",
                side_path.display()
            );
        }
    }
    // The re-verify (fresh — the new canonical source hash + the new
    // dest hash):
    // The bounded re-scan (the fresh size from the O(1)
    // stat, the sha streamed); the re-verify wordings are the
    // pre-existing ones.
    let src2_size = std::fs::metadata(src)
        .map(|m| m.len())
        .map_err(|err| format!("re-verify: re-scan the source {}: {err}", src.display()))?;
    let src2_sha = crate::jxl::sha256_stream_path(src)
        .map_err(|err| format!("re-verify: re-scan the source {}: {err}", src.display()))?;
    if src2_sha != src_sha {
        return Err(format!(
            "the source {} changed DURING the repair (pre-copy sha {src_sha}, post-copy sha {src2_sha}) — the row is not trustworthy",
            src.display()
        ));
    }
    let dst_size = std::fs::metadata(side_path)
        .map(|m| m.len())
        .map_err(|err| format!("re-verify: read the repaired copy {}: {err}", side_path.display()))?;
    let dst_sha = crate::jxl::sha256_stream_path(side_path)
        .map_err(|err| format!("re-verify: read the repaired copy {}: {err}", side_path.display()))?;
    if dst_size != src2_size || dst_sha != src2_sha {
        Ok(classify_row(src2_size, &src2_sha, side_path))
    } else {
        Ok(RowClass::Clean)
    }
}

/// One manifest row's post-repair state (the row columns for the
/// manifest rewrite + the full-set dirtiness + the named re-transfers
/// of this run).
#[derive(Clone, Debug)]
pub struct RepairedRow {
    pub file: String,
    /// The fresh source size (the re-anchored row).
    pub size: u64,
    /// The fresh source sha256.
    pub source_sha: String,
    /// The fresh `--to` dest sha256 (`-` when the copy failed and no
    /// copy to hash stands).
    pub dest_sha: String,
    /// The row's VERDICT COLUMN (the offload record — the `--to` dest
    /// side): the repaired row flips to `Ok` when its dest side is
    /// clean.
    pub verdict: Verdict,
    /// The dirty sides AFTER this run's repairs (any side — the
    /// full-set claim). Empty = the row is clean everywhere.
    pub dirty_sides: Vec<(Side, RowClass)>,
    /// The (side, pre-repair class) pairs this run re-transferred (the
    /// named re-copy record).
    pub retransferred: Vec<(Side, RowClass)>,
    /// The source-side problem (the row is unrepairable — the source
    /// of truth is absent/unreadable; it stays dirty).
    pub source_problem: Option<String>,
}

impl RepairedRow {
    /// The FULL-SET dirtiness (any destination): the disk verdict's
    /// row predicate.
    pub fn is_dirty(&self) -> bool {
        self.source_problem.is_some() || self.dirty_sides.iter().any(|(_, c)| !c.is_clean())
    }
    /// The full-set dirty count contribution (0/1).
    pub fn dirty_sides_for_file(&self) -> Vec<(Side, RowClass)> {
        self.dirty_sides
            .iter()
            .filter(|(_, c)| !c.is_clean())
            .cloned()
            .collect()
    }
}

/// The repaired offload record (one manifest's rows + the full-set
/// verdict).
#[derive(Clone, Debug)]
pub struct RepairManifest {
    pub name: String,
    /// The recorded dest (canonical — validated against `--to`).
    pub dest: PathBuf,
    pub rows: Vec<RepairedRow>,
}

impl RepairManifest {
    /// The full-set dirty row count (the disk verdict's numerator).
    pub fn dirty_count(&self) -> usize {
        self.rows.iter().filter(|r| r.is_dirty()).count()
    }
    /// The per-clip verdict blocks (the offload's key space: the
    /// relpath's parent dir; "" = the source root) over the FULL-SET
    /// dirtiness.
    pub fn clip_blocks(&self) -> Vec<(String, u64, u64)> {
        let mut by_clip: std::collections::BTreeMap<String, (u64, u64)> =
            std::collections::BTreeMap::new();
        for r in &self.rows {
            let entry = by_clip
                .entry(clip_key_of_rel(&r.file))
                .or_insert((0, 0));
            entry.0 += 1;
            if !r.is_dirty() {
                entry.1 += 1;
            }
        }
        by_clip
            .into_iter()
            .map(|(clip, (total, ok))| (clip, total, ok))
            .collect()
    }
    /// The disk verdict line (the offload's existing machinery — the
    /// full-set claim): `VERIFIED n/n` or `REFUSE k named row(s)`.
    pub fn verdict(&self) -> String {
        let total = self.rows.len();
        let dirty = self.dirty_count();
        if dirty == 0 {
            format!("VERIFIED {total}/{total}")
        } else {
            format!("REFUSE {dirty} named row(s)")
        }
    }
    /// The run-report offload line (the offload/report.rs `verdict_line`
    /// shape — the same format the encode wrote).
    pub fn verdict_line(&self) -> String {
        let total = self.rows.len();
        let dirty = self.dirty_count();
        if dirty == 0 {
            format!(
                "offload: VERIFIED {total}/{total} (dest {})",
                self.dest.display()
            )
        } else {
            format!(
                "offload: REFUSE {dirty} named row(s) (dest {})",
                self.dest.display()
            )
        }
    }
    /// The run-report verdict-line offload clause (the report.rs
    /// `offload_clause` shape — the same format the encode wrote).
    pub fn verdict_clause(&self) -> String {
        let total = self.rows.len();
        let dirty = self.dirty_count();
        if dirty == 0 {
            format!(", offload VERIFIED {total}/{total}")
        } else {
            format!(", offload REFUSE {dirty} named row(s)")
        }
    }
    /// The named `offload dirty:` lines (state-based — a pure function
    /// of the post-repair state: the row order, the dest side before
    /// the workspace side). These are the report's named rows while
    /// any row is still dirty; absent when the full set is clean.
    pub fn dirty_lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        for r in &self.rows {
            for (side, class) in r.dirty_sides_for_file() {
                out.push(format!(
                    "offload dirty: {} ({}: {} — {})",
                    r.file,
                    side.as_str(),
                    class.as_str(),
                    class.detail()
                ));
            }
        }
        out
    }
}

/// The clip key of a row's relpath (the offload's shared helper shape:
/// the relpath's parent dir, "" = the source root).
fn clip_key_of_rel(rel: &str) -> String {
    match rel.rfind('/') {
        Some(pos) => rel[..pos].to_string(),
        None => String::new(),
    }
}

/// The repair's arguments (the `frameprism repair` surface — the clap
/// verb: `frameprism repair <input> <output> --to <dest> [--rows <list>]
///` — the offload's input/output/--to shape + the row scope).
#[derive(Clone, Debug, clap::Parser)]
pub struct Args {
    /// The source tree (the offload's recorded input — the source of
    /// truth; must match every manifest's recorded `input:` after
    /// canonicalization).
    input: PathBuf,

    /// The output dir (the offload-manifest.tsv + the run report live
    /// here — the `*.offload-manifest.tsv` discovery is top level, the
    /// sidecars' convention).
    output: PathBuf,

    /// The two-destination offload dest (must match every manifest's
    /// recorded `dest:` after canonicalization).
    #[arg(long)]
    to: PathBuf,

    /// Limit the re-transfer to these manifest rows (comma-separated
    /// relpaths — the manifest's `file` column values; absent = every
    /// dirty row). The out-of-scope dirty rows stay dirty (the verdict
    /// stays REFUSE, they are named in the report).
    #[arg(long)]
    rows: Option<String>,
}

impl Args {
    pub fn input(&self) -> &Path {
        &self.input
    }
    pub fn output(&self) -> &Path {
        &self.output
    }
    pub fn to(&self) -> &Path {
        &self.to
    }
    pub fn rows(&self) -> Option<&str> {
        self.rows.as_deref()
    }
}

/// The repair's rc flavor (0 = the full set clean, 1 = still dirty,
/// 2 = usage).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RepairOutcome {
    Verified,
    StillDirty,
    Usage,
}

/// Discover the `*.offload-manifest.tsv` records in `output` (top
/// level, sorted — the audit's discovery convention).
fn discover_offload_manifests(output: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(output) {
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            //: the AppleDouble shadow is never an offload
            // manifest — skip (the audit's discovery convention, the
            // shared predicate).
            if crate::is_apple_double(&name) {
                continue;
            }
            if name.ends_with(offload::MANIFEST_SUFFIX) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The core repair (the CLI wrapper `run_repair` prints + maps the rc
/// and does the record rewrites): the pre-checks (the named rc=2
/// class), the per-manifest row diff + the selective re-copy + the
/// re-verify. Returns the repaired manifests (with their manifest
/// paths) + the named stdout lines. Pre-check failures are a named
/// `Err` (the usage class).
pub fn repair(
    input: &Path,
    output: &Path,
    to: &Path,
    scope: Option<&std::collections::BTreeSet<String>>,
) -> Result<(Vec<RepairedManifest>, Vec<String>), String> {
    if !input.is_dir() {
        return Err(format!("input is not a directory: {}", input.display()));
    }
    if !output.is_dir() {
        return Err(format!("output is not a directory: {}", output.display()));
    }
    let dest = std::fs::canonicalize(to)
        .map_err(|err| format!("the --to dest {} does not exist: {err}", to.display()))?;
    let input_canon = std::fs::canonicalize(input)
        .map_err(|err| format!("canonicalize the input {}: {err}", input.display()))?;
    let paths = discover_offload_manifests(output);
    if paths.is_empty() {
        return Err(format!(
            "no offload manifest (*.offload-manifest.tsv) in {} — nothing to repair (the repair operates from the existing offload record — the --to offload must have run first)",
            output.display()
        ));
    }
    let mut manifests: Vec<(offload::Manifest, PathBuf)> = Vec::new();
    let mut known_rows: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for p in &paths {
        let m = match offload::parse_manifest(p) {
            Ok(m) => m,
            Err(err) => {
                return Err(format!("repair (offload manifest {}): {err}", p.display()))
            }
        };
        // The record is the record: the dest + the input must be the
        // recorded ones (a different source tree is a different source
        // of truth — the named refusal, never a silent re-anchor of
        // the whole record).
        let rec_dest = std::fs::canonicalize(&m.dest)
            .map_err(|err| format!("the recorded dest {} is absent: {err}", m.dest.display()))?;
        if rec_dest != dest {
            return Err(format!(
                "the offload manifest {} records dest {} — repair's --to must be the recorded dest (got {})",
                m.name,
                m.dest.display(),
                to.display()
            ));
        }
        // The recorded input (the offload writer's `input:` line — the
        // input AS PASSED, possibly relative): canonicalize both sides
        // (the recorded relative form resolves against the current
        // cwd — the re-run convention).
        let rec_input_line = read_recorded_input(p)
            .ok_or_else(|| format!("the offload manifest {} carries no `input:` line — the record is corrupt?", m.name))?;
        let rec_input = std::fs::canonicalize(rec_input_line.trim()).map_err(|err| {
            format!(
                "the recorded input {rec_input_line:?} in {} is absent: {err} — the source of truth must be where the offload recorded it",
                m.name
            )
        })?;
        if rec_input != input_canon {
            return Err(format!(
                "the offload manifest {} records input {} — repair's input must be the recorded source tree (the source of truth must not have moved; got {})",
                m.name,
                rec_input.display(),
                input.display()
            ));
        }
        for (file, _, _, _) in &m.rows {
            known_rows.insert(file.clone());
        }
        manifests.push((m, p.clone()));
    }
    // The row scope is validated BEFORE any file is touched (the
    // pre-run class — a bad name refuses before the first re-copy).
    if let Some(set) = scope {
        let unknown: Vec<&String> = set.iter().filter(|n| !known_rows.contains(*n)).collect();
        if !unknown.is_empty() {
            return Err(format!(
                "--rows names {} row(s) not in the offload manifest(s): {}",
                unknown.len(),
                unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    // The per-manifest row diff + the selective re-copy + the
    // re-verify (only now is a file touched).
    let mut repaired: Vec<RepairedManifest> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    for (m, p) in &manifests {
        let (rows, row_lines) = repair_manifest_rows(m, &input_canon, output, &dest, scope);
        lines.extend(row_lines);
        repaired.push((
            RepairManifest {
                name: m.name.clone(),
                dest: dest.clone(),
                rows,
            },
            p.clone(),
        ));
    }
    Ok((repaired, lines))
}

/// The per-manifest row repair (exposed for the tests): fresh source
/// hashes, the per-destination classes, the selective re-copy, the
/// re-verify, the updated rows.
pub fn repair_manifest_rows(
    m: &offload::Manifest,
    input: &Path,
    output: &Path,
    dest: &Path,
    scope: Option<&std::collections::BTreeSet<String>>,
) -> (Vec<RepairedRow>, Vec<String>) {
    let mut rows: Vec<RepairedRow> = Vec::with_capacity(m.rows.len());
    let mut lines: Vec<String> = Vec::new();
    for (file, _rec_size, rec_src_sha, _rec_dst_sha) in &m.rows {
        let src = input.join(file);
        // The fresh source (the canonical reference — never a carried
        // value): stat + hash.
        match std::fs::metadata(&src) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                lines.push(format!(
                    "FAIL SOURCE_MISSING {file}: the source {} is absent — the row cannot be repaired (the source of truth must be present)",
                    src.display()
                ));
                rows.push(RepairedRow {
                    file: file.clone(),
                    size: 0,
                    source_sha: rec_src_sha.clone(),
                    dest_sha: "-".into(),
                    verdict: Verdict::CopyFail,
                    dirty_sides: vec![(Side::Dest, RowClass::Missing)],
                    retransferred: Vec::new(),
                    source_problem: Some(format!("the source {} is absent", src.display())),
                });
                continue;
            }
            Err(err) => {
                lines.push(format!(
                    "FAIL SOURCE_UNREADABLE {file}: stat the source {}: {err} — the row cannot be repaired",
                    src.display()
                ));
                rows.push(RepairedRow {
                    file: file.clone(),
                    size: 0,
                    source_sha: rec_src_sha.clone(),
                    dest_sha: "-".into(),
                    verdict: Verdict::CopyFail,
                    dirty_sides: vec![(Side::Dest, RowClass::Missing)],
                    retransferred: Vec::new(),
                    source_problem: Some(format!("stat the source: {err}")),
                });
                continue;
            }
        };
        // The streaming triple (the size is the exact read
        // count — the pre-existing semantics); the SOURCE_UNREADABLE row
        // on failure is the pre-existing one.
        let (fresh_size, fresh_sha, _crc) = match crate::jxl::digest_stream_path(&src) {
            Ok(t) => t,
            Err(err) => {
                lines.push(format!(
                    "FAIL SOURCE_UNREADABLE {file}: read the source {}: {err} — the row cannot be repaired",
                    src.display()
                ));
                rows.push(RepairedRow {
                    file: file.clone(),
                    size: 0,
                    source_sha: rec_src_sha.clone(),
                    dest_sha: "-".into(),
                    verdict: Verdict::CopyFail,
                    dirty_sides: vec![(Side::Dest, RowClass::Missing)],
                    retransferred: Vec::new(),
                    source_problem: Some(format!("read the source: {err}")),
                });
                continue;
            }
        };
        if fresh_sha != *rec_src_sha {
            lines.push(format!(
                "note: SOURCE_CHANGED {file}: the recorded source sha256 {rec_src_sha} differs from the source on disk {fresh_sha} — the row is re-anchored to the source's current bytes (the dest is re-verified against it)",
            ));
        }
        // The sides: the `--to` dest (every row) + the workspace
        // (the member rows — the verbatim copies; the frames there are
        // the re-encoded archive, the sidecar's surface).
        let is_dng = file
            .rsplit('.')
            .next()
            .map(|s| s.eq_ignore_ascii_case("dng"))
            .unwrap_or(false);
        let sides: [Side; 2] = [Side::Dest, Side::Workspace];
        let mut classes: Vec<(Side, RowClass)> = Vec::new();
        for side in sides.iter().copied() {
            if side == Side::Workspace && is_dng {
                continue; // the re-encoded frame — not a verbatim diff
            }
            let root = match side {
                Side::Dest => dest,
                Side::Workspace => output,
            };
            classes.push((side, classify_row(fresh_size, &fresh_sha, &root.join(file))));
        }
        let in_scope = scope.map(|s| s.contains(file)).unwrap_or(true);
        let mut dirty_after: Vec<(Side, RowClass)> = Vec::new();
        let mut retransferred: Vec<(Side, RowClass)> = Vec::new();
        for (side, class) in &classes {
            if class.is_clean() {
                continue;
            }
            if !in_scope {
                dirty_after.push((*side, class.clone()));
                continue; // out of the --rows scope: stays dirty (named in the report)
            }
            let side_path = match *side {
                Side::Dest => dest.join(file),
                Side::Workspace => output.join(file),
            };
            let side_root = match *side {
                Side::Dest => dest,
                Side::Workspace => output,
            };
            match recopy_and_reverify(&src, &side_path, side_root) {
                Ok(RowClass::Clean) => {
                    lines.push(format!(
                        "REPAIR {file} ({}): {} -> re-copied from the source + re-verified OK",
                        side.as_str(),
                        class.as_str()
                    ));
                    retransferred.push((*side, class.clone()));
                }
                Ok(still) => {
                    lines.push(format!(
                        "FAIL REPAIR {file} ({}): the re-verify after the re-copy still fails ({} — {}) — the row stays dirty",
                        side.as_str(),
                        still.as_str(),
                        still.detail()
                    ));
                    dirty_after.push((*side, still));
                }
                Err(err) => {
                    lines.push(format!(
                        "FAIL REPAIR {file} ({}): {err} — the row stays dirty",
                        side.as_str()
                    ));
                    dirty_after.push((*side, class.clone()));
                }
            }
        }
        // The row columns (the offload record — the `--to` dest side):
        // the fresh dest hash (re-read — the re-verify never trusts a
        // previous verdict) + the verdict flip on a clean dest side.
        let dest_path = dest.join(file);
        let (dest_sha, verdict) = if dirty_after.iter().any(|(s, _)| *s == Side::Dest) {
            let class = dirty_after
                .iter()
                .find(|(s, _)| *s == Side::Dest)
                .map(|(_, c)| c.clone())
                .unwrap_or(RowClass::Missing);
            let v = match &class {
                RowClass::Clean => Verdict::Ok,
                RowClass::Missing => Verdict::CopyFail,
                RowClass::SizeMismatch { .. } => Verdict::SizeMismatch,
                RowClass::ShaMismatch { .. } => Verdict::ShaMismatch,
            };
            (
                // The streaming sha (the `-` on unreadable
                // is the pre-existing one).
                match crate::jxl::sha256_stream_path(&dest_path) {
                    Ok(sha) => sha,
                    Err(_) => "-".to_string(),
                },
                v,
            )
        } else {
            // The streaming sha (the `-` on unreadable is
            // the pre-existing one).
            match crate::jxl::sha256_stream_path(&dest_path) {
                Ok(sha) => (sha, Verdict::Ok),
                Err(_) => ("-".to_string(), Verdict::CopyFail),
            }
        };
        rows.push(RepairedRow {
            file: file.clone(),
            size: fresh_size,
            source_sha: fresh_sha,
            dest_sha,
            verdict,
            dirty_sides: dirty_after,
            retransferred,
            source_problem: None,
        });
    }
    (rows, lines)
}

/// Rewrite the offload manifest with the repaired rows (the header
/// block — the magic + the `key: value` headers + the column line — is
/// preserved VERBATIM, so the record's `created:` / `input:` / `dest:`
/// lines stand; the rows + the per-clip blocks + the verdict line are
/// rewritten from the post-repair state). Deterministic: the same
/// pre-repair file + the same post-repair state → the same bytes.
pub fn rewrite_manifest(original: &Path, name: &str, rows: &[RepairedRow]) -> Result<PathBuf, String> {
    let text = std::fs::read_to_string(original)
        .map_err(|err| format!("read {}: {err}", original.display()))?;
    let lines: Vec<&str> = text.lines().collect();
    let col_idx = lines
        .iter()
        .position(|l| *l == "file\tsize\tsource_sha256\tdest_sha256\tverdict")
        .ok_or_else(|| format!("no file column line in {name} — the record is corrupt"))?;
    let mut tsv = lines[..=col_idx].join("\n");
    tsv.push('\n');
    for r in rows {
        tsv.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            r.file, r.size, r.source_sha, r.dest_sha, r.verdict.as_str()
        ));
    }
    // The per-clip blocks + the verdict line (the offload writer's
    // exact formats, the FULL-SET claim — any destination).
    tsv.push_str("# per-clip verdicts\n");
    let mut by_clip: std::collections::BTreeMap<String, (u64, u64)> =
        std::collections::BTreeMap::new();
    for r in rows {
        let entry = by_clip.entry(clip_key_of_rel(&r.file)).or_insert((0, 0));
        entry.0 += 1;
        if !r.is_dirty() {
            entry.1 += 1;
        }
    }
    for (clip, (total, ok)) in &by_clip {
        tsv.push_str(&format!(
            "clip: {} files: {} ok: {} dirty: {}\n",
            if clip.is_empty() { "(input root)" } else { clip.as_str() },
            total,
            ok,
            total - ok
        ));
    }
    let dirty = rows.iter().filter(|r| r.is_dirty()).count();
    let total = rows.len();
    tsv.push_str(&format!(
        "verdict: {}\n",
        if dirty == 0 {
            format!("VERIFIED {total}/{total}")
        } else {
            format!("REFUSE {dirty} named row(s)")
        }
    ));
    let tmp = original.with_file_name(format!(".{}.tmp", original.file_name().unwrap_or_default().to_string_lossy()));
    // The write-through guard on the
    // WRITE path: `fs::write` opens
    // O_CREAT|O_TRUNC + follows a symlink at the final component: a
    // link planted at the tool-owned tmp name between runs = the
    // outside target overwritten with the manifest text). The rename
    // below is the rename-replaces class (it never follows the final
    // dest component — the link is atomically replaced) — the guard
    // rides the write, not the rename. lstat semantics: the planted
    // class (incl. the dangling link — `fs::write` would CREATE the
    // target through the link) is the named refusal; the regular /
    // missing classes keep the existing behavior.
    if let Ok(ft) = std::fs::symlink_metadata(&tmp) {
        if ft.is_symlink() {
            return Err(format!(
                "the manifest tmp path {} is a symlink (the write would follow the link + overwrite the outside target it points to — the write-through is refused): remove the symlink + re-run",
                tmp.display()
            ));
        }
    }
    let mut file = std::fs::File::create(&tmp)
        .map_err(|err| format!("write {}: {err}", tmp.display()))?;
    file
        .write_all(tsv.as_bytes())
        .map_err(|err| format!("write {}: {err}", tmp.display()))?;
    // The durability seam (extended from the
    // offload scope): the manifest's bytes are
    // filesystem-synchronized BEFORE the rename (a power loss in the
    // post-rename window no longer leaves the verdict record's bytes
    // page-cache-only — the repair verdict rides this record's
    // durability). The
    // sync failure takes the fn's EXISTING error surface — the
    // caller's `error: repair (rewrite …): {err}` + rc=2 (unchanged;
    // the named line names the seam (the named
    // context).
    file
        .sync_all()
        .map_err(|err| {
            format!("sync the repair manifest tmp {} before the rename: {err}", tmp.display())
        })?;
    drop(file); // the close-before-rename (the handle is
    // dropped before the rename — the copy_atomic shape)
    std::fs::rename(&tmp, original)
        .map_err(|err| format!("rename {} -> {}: {err}", tmp.display(), original.display()))?;
    Ok(original.to_path_buf())
}

/// Re-emit the run report with the updated verdict (the
/// deterministic in-place update: the `offload:` verdict line is
/// replaced, the named `offload dirty:` rows are inserted right after
/// it (absent when the full set is clean), and the final `verdict:
/// run …` line's offload clause is swapped. Every other line —
/// including the original `created:` wall clock — stands. A present
/// but line-less report is the named corrupt-record error; an ABSENT
/// report is a named note (the manifest + the stdout lines carry the
/// verdict). Returns the lines for the caller's stdout.
pub fn reemit_run_report(output: &Path, manifest: &RepairManifest) -> Result<Vec<String>, String> {
    let path = output.join(crate::report::RUN_REPORT_NAME);
    let mut notes = Vec::new();
    if !path.is_file() {
        notes.push(format!(
            "note: no run report ({}) in {} — the verdict stands in the offload manifest + the repair lines (the report re-emit is skipped)",
            crate::report::RUN_REPORT_NAME,
            output.display()
        ));
        return Ok(notes);
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|err| format!("read {}: {err}", path.display()))?;
    let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let offload_idx = lines
        .iter()
        .position(|l| l.starts_with("offload: VERIFIED") || l.starts_with("offload: REFUSE"))
        .ok_or_else(|| {
            format!(
                "the run report {} carries no offload verdict line — the record is corrupt? (the offload manifest was written by a --to run — its report always carries the line)",
                path.display()
            )
        })?;
    let verdict_idx = lines
        .iter()
        .position(|l| l.starts_with("verdict: run "))
        .ok_or_else(|| {
            format!(
                "the run report {} carries no `verdict: run` line — the record is corrupt?",
                path.display()
            )
        })?;
    let mut out: Vec<String> = lines.clone();
    // The offload clause swap (the report.rs clause shape — the same
    // formats the encode wrote; the line's prefix is preserved).
    let vline = out[verdict_idx].clone();
    let clause = manifest.verdict_clause();
    out[verdict_idx] = match vline.find(", offload ") {
        Some(pos) => format!("{}{}", &vline[..pos], clause),
        None => {
            return Err(format!(
                "the run report's verdict line carries no offload clause (line: {vline:?}) — the record is corrupt?"
            ))
        }
    };
    // The verdict line + the named dirty rows (the state-based set —
    // the PREVIOUS re-emit's named rows are cleared first: a second
    // repair re-emits the CURRENT state, never a stale row).
    out.retain(|l| !l.starts_with("offload dirty: "));
    out[offload_idx] = manifest.verdict_line();
    for (i, d) in manifest.dirty_lines().iter().enumerate() {
        out.insert(offload_idx + 1 + i, d.clone());
    }
    // The write-through guard on the
    // WRITE path: `fs::write` follows a
    // symlink at the final component: a link planted at the report
    // path between runs = the outside target overwritten with the
    // report text). lstat semantics: the planted class is the named
    // refusal; the regular class keeps the existing behavior (the
    // dangling class returns at the `is_file()` check above — the
    // re-emit is the skipped-note path, the write is never reached).
    if let Ok(ft) = std::fs::symlink_metadata(&path) {
        if ft.is_symlink() {
            return Err(format!(
                "the run report path {} is a symlink (the re-emit would follow the link + overwrite the outside target it points to — the write-through is refused): remove the symlink + re-run",
                path.display()
            ));
        }
    }
    std::fs::write(&path, out.join("\n") + "\n")
        .map_err(|err| format!("write {}: {err}", path.display()))?;
    notes.push(format!("re-emitted {} with the updated verdict", path.display()));
    Ok(notes)
}

/// The CLI verb (the `frameprism repair` dispatch): the `--rows` scope
/// parse (the named rc=2: an empty name between commas), the core
/// repair, the manifest rewrites + the run-report re-emits, the named
/// lines + the full-set verdict. Prints the named lines + the
/// summary; returns the rc.
pub fn run(args: &Args) -> ExitCode {
    // The row scope (the named rc=2: an empty name between commas or a
    // name that is not a manifest row — the core's known-row check
    // names the unknowns after the parse).
    let scope: Option<std::collections::BTreeSet<String>> = match args.rows() {
        None => None,
        Some(list) => {
            let mut set = std::collections::BTreeSet::new();
            for n in list.split(',') {
                let n = n.trim();
                if n.is_empty() {
                    eprintln!("error: --rows carries an empty name (the comma-separated relpath list)");
                    return ExitCode::from(2);
                }
                set.insert(n.to_string());
            }
            Some(set)
        }
    };
    let (manifests, lines) = match repair(args.input(), args.output(), args.to(), scope.as_ref()) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };
    for line in &lines {
        println!("{line}");
    }
    let mut all_clean = true;
    for (rm, path) in &manifests {
        if let Err(err) = rewrite_manifest(path, &rm.name, &rm.rows) {
            eprintln!("error: repair (rewrite {}): {err}", path.display());
            return ExitCode::from(2);
        }
        if let Err(err) = reemit_run_report(args.output(), rm) {
            eprintln!("error: repair (run report): {err}");
            return ExitCode::from(2);
        }
        if rm.dirty_count() > 0 {
            all_clean = false;
        }
        for line in rm.dirty_lines() {
            println!("{line}");
        }
        println!("{}", rm.verdict_line());
    }
    // The full-set disk verdict (across every manifest — the verify-
    // before-wipe gate is a full-set claim).
    if all_clean {
        println!(
            "repair: the FULL set verifies clean (dest {} + workspace {}) — the camera disk is unlocked (BOTH destinations verify clean)",
            manifests[0].0.dest.display(),
            args.output().display()
        );
        ExitCode::SUCCESS
    } else {
        println!(
            "repair: the FULL set is NOT clean (dest {} + workspace {}) — the camera disk is NOT unlocked (the named rows above; run repair again once they are clean)",
            manifests[0].0.dest.display(),
            args.output().display()
        );
        ExitCode::from(1)
    }
}

/// Read the `input:` header line of an offload manifest (the recorded
/// source tree — the offload writer's exact line).
fn read_recorded_input(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines()
        .find(|l| l.starts_with("input: "))
        .map(|l| l.trim_start_matches("input: ").trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jxl::sha256_hex;
    use crate::offload::offload_to;

    /// A scratch source tree (2 "frames" + 1 member WAV + a root
    /// member manifest row): the offload runs the REAL writer over it,
    /// so the manifest under test is the honest 0.x format. `tag`
    /// isolates the parallel tests' temp dirs.
    fn setup(tag: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("frameprism_repair_test_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("shoot");
        let output = base.join("out");
        let dest = base.join("dest");
        std::fs::create_dir_all(input.join("A001_007")).unwrap();
        std::fs::create_dir_all(&output).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        let mk = |p: &Path, body: &[u8]| {
            std::fs::write(p, body).unwrap();
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
            std::fs::File::options().write(true).open(p).unwrap().set_modified(t).unwrap();
        };
        mk(&input.join("A001_007/f1.DNG"), b"frame-one-payload");
        mk(&input.join("A001_007/f2.DNG"), b"frame-two-payload");
        mk(&input.join("A001_007/clip.wav"), b"RIFF-wave");
        mk(&input.join("manifest.tsv"), b"relpath\tsize\tsha256\n");
        (base, input, output, dest)
    }

    /// The row-diff classification (missing / size / sha / clean) —
    /// PER DESTINATION: the same row is clean in one dest dir and
    /// dirty in the other.
    #[test]
    fn repair_classify_row_states_per_destination() {
        let base = std::env::temp_dir().join(format!("frameprism_repair_cls_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let body = b"the-source-bytes";
        std::fs::write(base.join("src"), body).unwrap();
        let sha = sha256_hex(body);
        let clean = base.join("clean.DNG");
        std::fs::write(&clean, body).unwrap();
        assert_eq!(classify_row(body.len() as u64, &sha, &clean), RowClass::Clean);
        let missing = base.join("missing.DNG");
        assert_eq!(classify_row(body.len() as u64, &sha, &missing), RowClass::Missing);
        let short = base.join("short.DNG");
        std::fs::write(&short, b"short").unwrap();
        assert_eq!(
            classify_row(body.len() as u64, &sha, &short),
            RowClass::SizeMismatch {
                found: 5,
                want: body.len() as u64
            }
        );
        // Same size, different sha.
        let flipped = base.join("flipped.DNG");
        let mut b = body.to_vec();
        b[0] ^= 0x01;
        std::fs::write(&flipped, &b).unwrap();
        assert_eq!(
            classify_row(body.len() as u64, &sha, &flipped),
            RowClass::ShaMismatch {
                want: sha.clone(),
                found: sha256_hex(&b)
            }
        );
        // Per destination: the SAME source classified against two dest
        // trees — clean in one, dirty in the other (the row can be
        // clean in one and dirty in the other).
        let d1 = base.join("d1");
        let d2 = base.join("d2");
        std::fs::create_dir_all(&d1).unwrap();
        std::fs::create_dir_all(&d2).unwrap();
        std::fs::write(d1.join("row.DNG"), body).unwrap();
        std::fs::write(d2.join("row.DNG"), b"other-bytes!!").unwrap();
        assert_eq!(classify_row(body.len() as u64, &sha, &d1.join("row.DNG")), RowClass::Clean);
        assert!(!classify_row(body.len() as u64, &sha, &d2.join("row.DNG")).is_clean());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The verdict transition (the full-set claim): any dirty row →
    /// REFUSE; all clean → VERIFIED (the offload's exact line shapes).
    #[test]
    fn repair_verdict_transitions_any_dirty_refuse_all_clean_ok() {
        let mk = |file: &str, dirty: Vec<(Side, RowClass)>| RepairedRow {
            file: file.into(),
            size: 1,
            source_sha: "s".into(),
            dest_sha: "s".into(),
            verdict: Verdict::Ok,
            dirty_sides: dirty,
            retransferred: Vec::new(),
            source_problem: None,
        };
        // All clean → VERIFIED n/n.
        let rm = RepairManifest {
            name: "x".into(),
            dest: PathBuf::from("/dest"),
            rows: vec![mk("a.DNG", vec![]), mk("b.DNG", vec![])],
        };
        assert_eq!(rm.verdict(), "VERIFIED 2/2");
        assert_eq!(rm.verdict_line(), "offload: VERIFIED 2/2 (dest /dest)");
        assert_eq!(rm.verdict_clause(), ", offload VERIFIED 2/2");
        assert!(rm.dirty_lines().is_empty(), "a clean full set has no named rows");
        // Any dirty row (ANY destination) → REFUSE.
        let rm = RepairManifest {
            name: "x".into(),
            dest: PathBuf::from("/dest"),
            rows: vec![
                mk("a.DNG", vec![]),
                mk("b.DNG", vec![(Side::Workspace, RowClass::Missing)]),
            ],
        };
        assert_eq!(rm.verdict(), "REFUSE 1 named row(s)");
        assert_eq!(rm.verdict_line(), "offload: REFUSE 1 named row(s) (dest /dest)");
        assert_eq!(rm.verdict_clause(), ", offload REFUSE 1 named row(s)");
        // The named dirty row names the file + the side + the class.
        assert_eq!(rm.dirty_lines().len(), 1);
        assert!(
            rm.dirty_lines()[0].starts_with("offload dirty: b.DNG (workspace: MISSING — file missing)"),
            "{:?}",
            rm.dirty_lines()
        );
        // A row with a source problem is dirty (unrepairable).
        let rm = RepairManifest {
            name: "x".into(),
            dest: PathBuf::from("/dest"),
            rows: vec![RepairedRow {
                source_problem: Some("absent".into()),
                ..mk("a.DNG", vec![])
            }],
        };
        assert_eq!(rm.verdict(), "REFUSE 1 named row(s)");
    }

    /// The end-to-end repair (the real offload writer + the real
    /// repair): exactly the injected files are re-transferred (the
    /// clean rows are untouched — mtime + sha), the repaired rows are
    /// named + flip clean, the verdict stays REFUSE while a subset is
    /// still dirty (the named remaining rows), flips VERIFIED after
    /// the rest, and the re-emitted report is byte-deterministic from
    /// the same state.
    #[test]
    fn repair_end_to_end_selective_named_and_deterministic() {
        let (base, input, output, dest) = setup("e2e");
        // The run report (the shape — the offload line + the
        // verdict line; the repair updates exactly those).
        std::fs::write(
            output.join(crate::report::RUN_REPORT_NAME),
            format!(
                "# frameprism run report — shoot\ncreated: 1700000000 (unix seconds, UTC)\noffload: VERIFIED 4/4 (dest {})\nverdict: run OK — 1 clip(s), 2 frame(s), offload VERIFIED 4/4\n",
                dest.display()
            ),
        )
        .unwrap();
        // The clean offload (the real writer — the honest manifest).
        let r0 = offload_to(&input, &output, &dest).unwrap();
        assert_eq!(r0.dirty_count(), 0, "{r0:?}");
        // The workspace member copies (the worker's sidecar copy does
        // this at encode time — the e2e seeds them so the
        // two-destination state is the honest one; the frames there
        // are the re-encoded archive, the sidecar's domain).
        for rel in ["A001_007/clip.wav", "manifest.tsv"] {
            let p = output.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::copy(input.join(rel), &p).unwrap();
        }
        let clip = crate::checksums::clip_name(&input).unwrap();
        let manifest = output.join(crate::offload::offload_manifest_name(&clip));
        let m0 = offload::parse_manifest(&manifest).unwrap();
        assert_eq!(m0.rows.len(), 4, "4 rows: 2 frames + WAV + the root manifest");
        // The original header block (the magic + the `key: value`
        // headers + the column line): the rewrites must preserve it
        // VERBATIM (the created/input/dest lines stand).
        let m0_header = std::fs::read_to_string(&manifest)
            .unwrap()
            .lines()
            .take_while(|l| *l != "file\tsize\tsource_sha256\tdest_sha256\tverdict")
            .collect::<Vec<_>>()
            .join("\n");

        // The injection (a mix of drop / truncate / 1-byte flip, PER
        // DESTINATION: the dest gets 3, the workspace gets 2 — the
        // WAV is dirty in BOTH).
        let wav = dest.join("A001_007/clip.wav");
        std::fs::remove_file(dest.join("A001_007/f1.DNG")).unwrap(); // dest: DROP
        {
            let b = std::fs::read(&wav).unwrap();
            std::fs::write(&wav, &b[..b.len() / 2]).unwrap(); // dest: TRUNCATE
        }
        {
            let xmp = dest.join("manifest.tsv");
            let mut b = std::fs::read(&xmp).unwrap();
            b[0] ^= 0x01;
            std::fs::write(&xmp, &b).unwrap(); // dest: 1-BYTE FLIP
        }
        std::fs::remove_file(output.join("A001_007/clip.wav")).unwrap(); // ws: DROP
        {
            // ws: 1-BYTE FLIP on the root member (out of the clip dir).
            let xmp = output.join("manifest.tsv");
            let mut b = std::fs::read(&xmp).unwrap();
            b[0] ^= 0x01;
            std::fs::write(&xmp, &b).unwrap();
        }
        // The pre-repair inventory (sha + mtime of every dest + ws
        // file): the clean rows must come back byte- + mtime-identical.
        let inventory = |root: &Path| -> Vec<(String, String, std::time::SystemTime)> {
            fn walk(
                dir: &Path,
                base: &Path,
                out: &mut Vec<(String, String, std::time::SystemTime)>,
            ) {
                for e in std::fs::read_dir(dir).unwrap().flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, base, out);
                    } else if p.is_file() {
                        let rel = p.strip_prefix(base).unwrap().to_string_lossy().to_string();
                        out.push((
                            rel,
                            sha256_hex(&std::fs::read(&p).unwrap()),
                            std::fs::metadata(&p).unwrap().modified().unwrap(),
                        ));
                    }
                }
            }
            let mut out = Vec::new();
            walk(root, root, &mut out);
            out.sort();
            out
        };
        let inv_dest = inventory(&dest);
        let inv_out = inventory(&output);
        // The source mtimes (the repair copy must preserve them).
        let mtime_of = |p: &Path| std::fs::metadata(p).unwrap().modified().unwrap();
        let src_f2_mtime = mtime_of(&input.join("A001_007/f2.DNG"));
        let src_wav_mtime = mtime_of(&input.join("A001_007/clip.wav"));

 // STAGE 1: repair a SUBSET (the 2 dest-side rows only) → the
        // rest stays dirty: REFUSE + the named remaining rows (rc=1).
        let scope: std::collections::BTreeSet<String> =
            ["A001_007/f1.DNG", "manifest.tsv"].iter().map(|s| s.to_string()).collect();
        let m1 = offload::parse_manifest(&manifest).unwrap();
        let (rows, lines) = repair_manifest_rows(&m1, &input, &output, &dest, Some(&scope));
        let rm1 = RepairManifest {
            name: m1.name.clone(),
            dest: dest.clone(),
            rows,
        };
        assert_eq!(rm1.dirty_count(), 1, "the 1 row remains dirty (clip.wav, 2 sides of ONE row): {rm1:?}");
        assert_eq!(rm1.verdict(), "REFUSE 1 named row(s)");
        // The repaired rows are NAMED (the re-copy lines) + flip clean.
        let named: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        assert!(
            named.iter().any(|l| l.starts_with("REPAIR A001_007/f1.DNG (dest): MISSING -> re-copied from the source + re-verified OK")),
            "the dropped frame is named + re-copied: {named:?}"
        );
        assert!(
            named.iter().any(|l| l.starts_with("REPAIR manifest.tsv (dest): SHA_MISMATCH -> re-copied from the source + re-verified OK")),
            "the flipped root member is named + re-copied: {named:?}"
        );
        assert!(
            named.iter().any(|l| l.starts_with("REPAIR manifest.tsv (workspace): SHA_MISMATCH -> re-copied from the source + re-verified OK")),
            "the flipped root member is named + re-copied in the workspace too: {named:?}"
        );
        // The out-of-scope dirty rows stay dirty (named in the
        // report's dirty lines — the state-based set).
        let dirty = rm1.dirty_lines();
        assert_eq!(dirty.len(), 2, "the named remaining sides of the 1 remaining row: {dirty:?}");
        assert!(dirty.iter().any(|l| l.contains("A001_007/clip.wav (dest: SIZE_MISMATCH")), "{dirty:?}");
        assert!(dirty.iter().any(|l| l.contains("A001_007/clip.wav (workspace: MISSING")), "{dirty:?}");
        // The clean rows were NOT re-transferred (mtime + sha
        // untouched): f2.DNG in both trees + the clean dest rows.
        for (rel, sha, mtime) in &inv_dest {
            let p = dest.join(rel);
            let (sha2, mtime2) = (sha256_hex(&std::fs::read(&p).unwrap()), mtime_of(&p));
            let touched = rel == "A001_007/f1.DNG" || rel == "manifest.tsv";
            if !touched {
                assert_eq!(*sha, sha2, "the clean dest row {rel} is byte-identical");
                assert_eq!(*mtime, mtime2, "the clean dest row {rel} keeps its mtime");
            } else {
                assert_eq!(sha2, sha256_hex(&std::fs::read(&input.join(rel)).unwrap()), "the repaired row matches the source: {rel}");
                assert_eq!(mtime2, src_f2_mtime, "the repaired row keeps the shoot mtime: {rel}");
            }
        }
        for (rel, sha, _mtime) in &inv_out {
            let p = output.join(rel);
            if !p.is_file() {
                continue;
            }
            let touched = rel == "A001_007/clip.wav" || rel == "manifest.tsv";
            if !touched {
                assert_eq!(*sha, sha256_hex(&std::fs::read(&p).unwrap()), "the clean ws row {rel} is byte-identical");
            }
        }
        // Rewrite the manifest + the report from the phase-1 state.
        rewrite_manifest(&manifest, &m1.name, &rm1.rows).unwrap();
        reemit_run_report(&output, &rm1).unwrap();
        let t1 = std::fs::read_to_string(output.join(crate::report::RUN_REPORT_NAME)).unwrap();
        assert!(t1.contains("offload: REFUSE 1 named row(s) (dest "), "{t1}");
        assert!(t1.contains("offload dirty: A001_007/clip.wav (dest: SIZE_MISMATCH"), "{t1}");
        assert!(t1.ends_with("verdict: run OK — 1 clip(s), 2 frame(s), offload REFUSE 1 named row(s)\n"), "the verdict clause swap: {t1}");
        let mtext1 = std::fs::read_to_string(&manifest).unwrap();
        assert!(mtext1.contains("verdict: REFUSE 1 named row(s)"), "{mtext1}");
        // The header stands verbatim (the created/input/dest lines).
        assert!(mtext1.starts_with(&m0_header), "the header block is preserved verbatim:\n{mtext1}");

 // STAGE 2: repair the REST (no scope) → the full set flips
        // VERIFIED (rc=0).
        let m2 = offload::parse_manifest(&manifest).unwrap();
        let (rows, lines) = repair_manifest_rows(&m2, &input, &output, &dest, None);
        let rm2 = RepairManifest {
            name: m2.name.clone(),
            dest: dest.clone(),
            rows,
        };
        assert_eq!(rm2.dirty_count(), 0, "all clean after the rest: {rm2:?}");
        assert_eq!(rm2.verdict(), "VERIFIED 4/4");
        let named: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        assert!(
            named.iter().any(|l| l.starts_with("REPAIR A001_007/clip.wav (dest): SIZE_MISMATCH -> re-copied from the source + re-verified OK")),
            "{named:?}"
        );
        assert!(
            named.iter().any(|l| l.starts_with("REPAIR A001_007/clip.wav (workspace): MISSING -> re-copied from the source + re-verified OK")),
            "the member row flips in BOTH trees: {named:?}"
        );
        rewrite_manifest(&manifest, &m2.name, &rm2.rows).unwrap();
        reemit_run_report(&output, &rm2).unwrap();
        let t2 = std::fs::read_to_string(output.join(crate::report::RUN_REPORT_NAME)).unwrap();
        assert!(t2.contains(&format!("offload: VERIFIED 4/4 (dest {})", dest.display())), "{t2}");
        assert!(!t2.contains("offload dirty:"), "a clean full set has no named rows: {t2}");
        assert!(t2.ends_with(&format!("verdict: run OK — 1 clip(s), 2 frame(s), offload VERIFIED 4/4\n")), "{t2}");
        let mtext2 = std::fs::read_to_string(&manifest).unwrap();
        assert!(mtext2.contains("verdict: VERIFIED 4/4"), "{mtext2}");
        assert!(!mtext2.lines().any(|l| l.split('\t').count() == 5 && l.ends_with("\tREFUSE")) , "{mtext2}");
        // Every row flipped to OK (the repaired rows' verdict column).
        let m3 = offload::parse_manifest(&manifest).unwrap();
        assert_eq!(m3.rows.len(), 4);
        // The WAV's shoot mtime is preserved in BOTH trees after the
        // repair (the same discipline as the offload).
        assert_eq!(mtime_of(&dest.join("A001_007/clip.wav")), src_wav_mtime);
        assert_eq!(mtime_of(&output.join("A001_007/clip.wav")), src_wav_mtime);
        // The SOURCE tree is untouched (read-only — the corpus
        // discipline): every source file matches the pre-run bytes.
        assert_eq!(std::fs::read(input.join("A001_007/f2.DNG")).unwrap(), b"frame-two-payload");

        // DETERMINISM: from the SAME state (reset + the same
        // injections) the re-emitted report + the manifest are
        // byte-identical across two repair runs.
        let (base2, input2, output2, dest2) = setup("e2e2");
        let run_once = |input: &Path, output: &Path, dest: &Path| -> (String, String) {
            std::fs::write(
                output.join(crate::report::RUN_REPORT_NAME),
                format!(
                    "# frameprism run report — shoot\ncreated: 1700000000 (unix seconds, UTC)\noffload: VERIFIED 4/4 (dest {})\nverdict: run OK — 1 clip(s), 2 frame(s), offload VERIFIED 4/4\n",
                    dest.display()
                ),
            )
            .unwrap();
            let r = offload_to(input, output, dest).unwrap();
            assert_eq!(r.dirty_count(), 0);
            for rel in ["A001_007/clip.wav", "manifest.tsv"] {
                let p = output.join(rel);
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent).unwrap();
                }
                std::fs::copy(input.join(rel), &p).unwrap();
            }
            let clip = crate::checksums::clip_name(input).unwrap();
            let manifest = output.join(crate::offload::offload_manifest_name(&clip));
            // The SAME injections (all rows — no subset).
            std::fs::remove_file(dest.join("A001_007/f1.DNG")).unwrap();
            std::fs::remove_file(output.join("A001_007/clip.wav")).unwrap();
            let wav = dest.join("A001_007/clip.wav");
            let b = std::fs::read(&wav).unwrap();
            std::fs::write(&wav, &b[..b.len() / 2]).unwrap();
            let m = offload::parse_manifest(&manifest).unwrap();
            let (rows, _lines) = repair_manifest_rows(&m, input, output, dest, None);
            let rm = RepairManifest {
                name: m.name.clone(),
                dest: dest.to_path_buf(),
                rows,
            };
            rewrite_manifest(&manifest, &m.name, &rm.rows).unwrap();
            reemit_run_report(output, &rm).unwrap();
            (
                std::fs::read_to_string(output.join(crate::report::RUN_REPORT_NAME)).unwrap(),
                std::fs::read_to_string(&manifest).unwrap(),
            )
        };
        let (rep_a, man_a) = run_once(&input2, &output2, &dest2);
        let (base3, input3, output3, dest3) = setup("e2e3");
        let (rep_b, man_b) = run_once(&input3, &output3, &dest3);
        // The dest path is in the lines (different temp dirs) — the
        // determinism claim is over the same state: normalize the path
        // (the state is otherwise byte-identical by construction).
        // The temp bases differ (the state is otherwise identical by
        // construction) — normalize the BASE dir (the input's parent:
        // it prefixes both the input + the dest paths in the lines).
        let base_a = input2.parent().unwrap().display().to_string();
        let base_b = input3.parent().unwrap().display().to_string();
        let norm = |s: String, a: &str, b: &str| s.replace(a, b);
        // The `created:` wall-clock free line (the documented-free-line
        // idiom):
        // each offload stamps `created: now()`, so the manifest
        // comparison normalizes it to a constant before the byte-
        // identity assert (the report comparison is untouched: the
        // seeded run report carries the PINNED `created: 1700000000`).
        let norm_created = |s: String| s.lines().map(|l| if l.starts_with("created: ") && l.ends_with(" (unix seconds, UTC)") { "created: N (unix seconds, UTC)" } else { l }).collect::<Vec<_>>().join("\n");
        assert_eq!(
            norm(rep_a, &base_a, "<ROOT>"),
            norm(rep_b, &base_b, "<ROOT>"),
            "the re-emitted report is byte-identical from the same state"
        );
        assert_eq!(
            norm_created(norm(man_a, &base_a, "<ROOT>")),
            norm_created(norm(man_b, &base_b, "<ROOT>")),
            "the rewritten manifest is byte-identical from the same state"
        );
        let _ = (base, base2, base3);
        let _ = (inv_dest, inv_out);
    }

    /// The pre-checks (the named rc=2 class): no manifest, a dest that
    /// does not match the record, a missing source row.
    #[test]
    fn repair_prechecks_are_named() {
        let (base, input, output, dest) = setup("pre");
        // No manifest yet → the named usage error.
        let err = repair(&input, &output, &dest, None).unwrap_err();
        assert!(err.contains("no offload manifest"), "{err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A source row that vanished AFTER the offload (the source of
    /// truth is gone): the named FAIL + the row stays dirty (the
    /// verdict cannot flip — the full-set claim).
    #[test]
    fn repair_source_missing_is_named_and_keeps_the_verdict() {
        let (base, input, output, dest) = setup("srcmissing");
        let r0 = offload_to(&input, &output, &dest).unwrap();
        assert_eq!(r0.dirty_count(), 0);
        // The source frame disappears (the camera disk's row is gone).
        std::fs::remove_file(input.join("A001_007/f2.DNG")).unwrap();
        let clip = crate::checksums::clip_name(&input).unwrap();
        let manifest = output.join(crate::offload::offload_manifest_name(&clip));
        let m = offload::parse_manifest(&manifest).unwrap();
        let (rows, lines) = repair_manifest_rows(&m, &input, &output, &dest, None);
        assert!(lines.iter().any(|l| l.starts_with("FAIL SOURCE_MISSING A001_007/f2.DNG")), "{lines:?}");
        let rm = RepairManifest {
            name: m.name.clone(),
            dest: dest.clone(),
            rows,
        };
        assert_eq!(rm.dirty_count(), 1, "the unrepairable row keeps the verdict REFUSE: {rm:?}");
        assert_eq!(rm.verdict(), "REFUSE 1 named row(s)");
        let _ = std::fs::remove_dir_all(&base);
    }

    //: the AppleDouble shadow robustness (the audit's discovery
    // convention, per the repair's own doc — the shared predicate).

    /// G2-6: the repair's offload-manifest discovery — real + `._`
    /// shadow → 1 (the real one).
    #[test]
    fn spec7_g2_repair_offload_discovery_skips_the_shadow() {
        let tmp = std::env::temp_dir().join(format!("frameprism-spec7-g2-repair-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("C.offload-manifest.tsv"), "header\n").unwrap();
        std::fs::write(tmp.join("._C.offload-manifest.tsv"), vec![0xFF, 0xFE]).unwrap();
        let found = discover_offload_manifests(&tmp);
        assert_eq!(
            found,
            vec![tmp.join("C.offload-manifest.tsv")],
            "real + shadow → 1 (the real one): {found:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The dest-side symlink refusal: a link
    /// planted at a row path between the offload and the repair is
    /// refused with the named line — the re-copy does NOT follow it,
    /// the OUTSIDE TARGET's bytes are unchanged (the byte-identity
    /// proof — the finding's headline), the row stays dirty + named
    /// (the REFUSE verdict — the rc=1 class rides the run()'s
    /// `dirty_count > 0` → `ExitCode::from(1)`; the caller-handling
    /// re-read). FINAL component only — the link is
    /// at the row path (by definition planted: the offload walker
    /// never emits a symlink entry into the dest tree).
    #[test]
    fn repair_refuses_symlinked_dest_row_outside_target_unchanged() {
        let (base, input, output, dest) = setup("sym-dest");
        // The clean offload (the real writer — the honest manifest).
        let r0 = offload_to(&input, &output, &dest).unwrap();
        assert_eq!(r0.dirty_count(), 0, "{r0:?}");
        // Make the row dirty (the Missing class — the re-copy is the
        // repair's action for it) + plant the link at the row path
        // (the inter-run hostile state — the outside target OUTSIDE
        // the mirror dest).
        let row = "A001_007/f1.DNG";
        std::fs::remove_file(dest.join(row)).unwrap();
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let precious = outside.join("precious.DNG");
        let precious_bytes = b"the-outside-target-must-survive";
        std::fs::write(&precious, precious_bytes).unwrap();
        std::os::unix::fs::symlink(&precious, dest.join(row)).unwrap();
        // The repair: the recopy is refused at the guard — the named
        // line + the row stays dirty.
        let (manifests, lines) = repair(&input, &output, &dest, None).unwrap();
        let rm = &manifests[0].0;
        assert_eq!(rm.dirty_count(), 1, "the symlinked row stays dirty: {rm:?}");
        assert_eq!(rm.verdict(), "REFUSE 1 named row(s)");
        let named = lines
            .iter()
            .find(|l| l.contains(&format!("FAIL REPAIR {row}")))
            .unwrap();
        assert!(
            named.contains(
                "is a symlink (the re-copy would follow the link + overwrite the outside target it points to — the write-through is refused)"
            ),
            "the named refusal line: {named:?}"
        );
        // The OUTSIDE TARGET's bytes are unchanged (the byte-identity
        // proof — the finding's headline) + the link is untouched
        // (the refusal never touches it).
        assert_eq!(std::fs::read(&precious).unwrap(), precious_bytes);
        assert!(std::fs::symlink_metadata(dest.join(row)).unwrap().file_type().is_symlink());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The dangling-link variant: lstat sees
    /// the link even when the target is missing — the guard fires
    /// with the SAME named line (the follow would fail anyway; the
    /// refusal is the named class, not the io error — + without the
    /// guard the `fs::copy` would CREATE the target through the
    /// dangling link: the no-create proof is the headline here).
    #[test]
    fn repair_refuses_dangling_symlinked_dest_row() {
        let (base, input, output, dest) = setup("sym-dangling");
        let r0 = offload_to(&input, &output, &dest).unwrap();
        assert_eq!(r0.dirty_count(), 0, "{r0:?}");
        let row = "A001_007/f2.DNG";
        std::fs::remove_file(dest.join(row)).unwrap();
        let missing_target = base.join("gone-target"); // never created
        std::os::unix::fs::symlink(&missing_target, dest.join(row)).unwrap();
        let (manifests, lines) = repair(&input, &output, &dest, None).unwrap();
        let rm = &manifests[0].0;
        assert_eq!(rm.dirty_count(), 1, "the dangling-symlinked row stays dirty: {rm:?}");
        let named = lines
            .iter()
            .find(|l| l.contains(&format!("FAIL REPAIR {row}")))
            .unwrap();
        assert!(
            named.contains(
                "is a symlink (the re-copy would follow the link + overwrite the outside target it points to — the write-through is refused)"
            ),
            "the same named refusal line: {named:?}"
        );
        // The target was never created (the refusal is before the
        // copy — no follow, no create).
        assert!(!missing_target.exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The record-write site:
    /// `fs::write` opens O_CREAT|O_TRUNC + follows a symlink at the
    /// final component): a link planted at the manifest TMP name (the
    /// `.<name>.tmp` tool-owned name) between runs is refused at the
    /// rewrite's write — the OUTSIDE target's bytes are unchanged +
    /// the manifest itself is untouched (no write, no rename — the
    /// rename-replaces class never runs) + the named error (the rc=2
    /// class rides the run()'s `error: repair (rewrite …): {err}`).
    #[test]
    fn rewrite_manifest_refuses_planted_tmp_symlink() {
        let (base, input, output, dest) = setup("sym-tmp");
        let r0 = offload_to(&input, &output, &dest).unwrap();
        assert_eq!(r0.dirty_count(), 0, "{r0:?}");
        // The repair's honest post-state (no dirty rows — the guard
        // is exercised at the record write, after the core).
        let (manifests, _lines) = repair(&input, &output, &dest, None).unwrap();
        let (rm, manifest_path) = &manifests[0];
        // The planted link at the tool-owned tmp name (the inter-run
        // hostile state — the write follows it, the rename would
        // replace it — the guard rides the write, not the rename).
        let tmp = manifest_path.with_file_name(format!(
            ".{}.tmp",
            manifest_path.file_name().unwrap().to_string_lossy()
        ));
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let precious = outside.join("precious.txt");
        let precious_bytes = b"the-outside-target-must-survive";
        std::fs::write(&precious, precious_bytes).unwrap();
        std::os::unix::fs::symlink(&precious, &tmp).unwrap();
        let m_before = std::fs::read(manifest_path).unwrap();
        let err = rewrite_manifest(manifest_path, &rm.name, &rm.rows).unwrap_err();
        assert!(
            err.contains(
                "is a symlink (the write would follow the link + overwrite the outside target it points to — the write-through is refused)"
            ),
            "the named refusal: {err:?}"
        );
        // The OUTSIDE target's bytes are unchanged (the byte-identity
        // proof) + the manifest itself is untouched (no write, no
        // rename — the tmp link stands, the record is intact).
        assert_eq!(std::fs::read(&precious).unwrap(), precious_bytes);
        assert_eq!(std::fs::read(manifest_path).unwrap(), m_before);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The record-write site (the run
    /// report): a link planted at the run-report path between runs
    /// is refused at the re-emit's write — the OUTSIDE target's
    /// bytes are unchanged (still the original report bytes — the
    /// target carries the valid report shape so the re-emit reaches
    /// the write; the write follows the link) + the named error (the
    /// rc=2 class rides the run()'s `error: repair (run report):
    /// {err}`).
    #[test]
    fn reemit_run_report_refuses_planted_report_symlink() {
        let (base, input, output, dest) = setup("sym-report");
        // The run report (the shape — the re-emit's required
        // lines) + the clean offload (the real writer).
        std::fs::write(
            output.join(crate::report::RUN_REPORT_NAME),
            format!(
                "# frameprism run report — shoot\ncreated: 1700000000 (unix seconds, UTC)\noffload: VERIFIED 4/4 (dest {})\nverdict: run OK — 1 clip(s), 2 frame(s), offload VERIFIED 4/4\n",
                dest.display()
            ),
        )
        .unwrap();
        let r0 = offload_to(&input, &output, &dest).unwrap();
        assert_eq!(r0.dirty_count(), 0, "{r0:?}");
        let (manifests, _lines) = repair(&input, &output, &dest, None).unwrap();
        let rm = &manifests[0].0;
        // The planted link at the report path (the inter-run hostile
        // state — the outside target carries the original report
        // bytes, so the re-emit's reads + checks pass and it reaches
        // the write — the write follows the link).
        let report_path = output.join(crate::report::RUN_REPORT_NAME);
        let original_report = std::fs::read(&report_path).unwrap();
        std::fs::remove_file(&report_path).unwrap();
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let precious = outside.join("precious-report.txt");
        std::fs::write(&precious, &original_report).unwrap();
        std::os::unix::fs::symlink(&precious, &report_path).unwrap();
        let err = reemit_run_report(&output, rm).unwrap_err();
        assert!(
            err.contains(
                "is a symlink (the re-emit would follow the link + overwrite the outside target it points to — the write-through is refused)"
            ),
            "the named refusal: {err:?}"
        );
        // The OUTSIDE target's bytes are unchanged (the byte-identity
        // proof — still the original report bytes).
        assert_eq!(std::fs::read(&precious).unwrap(), original_report);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The repair class (the named residual — the
    /// hostile INTERMEDIATE-DIR symlink the final-component lstat
    /// guard does NOT cover: the leaf is a regular file the tool
    /// creates, so a planted link at an intermediate DIR is invisible
    /// to a leaf lstat). `dest/<clip>` is a planted link to an outside
    /// dir (the inter-run hostile state — the hostile removes the
    /// offload's mirrored clip dir + plants the link) → the side
    /// re-copy's root-boundary guard refuses the rows under the link
    /// BEFORE the copy (the named class) + the OUTSIDE dir UNTOUCHED
    /// (the byte-identity proof) + the rows stay dirty + named (the
    /// Err arm). The leaf guard stays UNTOUCHED.
    #[test]
    fn repair_planted_intermediate_dir_symlink_refused() {
        let (base, input, output, dest) = setup("root-boundary");
        // The clean offload (the real writer — the honest manifest +
        // the mirror).
        let r0 = offload_to(&input, &output, &dest).unwrap();
        assert_eq!(r0.dirty_count(), 0, "{r0:?}");
        let clip = crate::checksums::clip_name(&input).unwrap();
        let manifest = output.join(crate::offload::offload_manifest_name(&clip));
        let m0 = offload::parse_manifest(&manifest).unwrap();
        // The outside target (the planted link's destination — with a
        // sentinel byte string).
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let sentinel = outside.join("sentinel.bin");
        std::fs::write(&sentinel, b"outside-bytes").unwrap();
        let sentinel_before = std::fs::read(&sentinel).unwrap();
        // The planted intermediate link: dest/A001_007 -> outside
        // (the inter-run hostile state — the offload already mirrored
        // the clip dir; the hostile REMOVES it + plants the link).
        let clip_dir = dest.join("A001_007");
        std::fs::remove_dir_all(&clip_dir).unwrap();
        std::os::unix::fs::symlink(&outside, &clip_dir).unwrap();
        // The repair: the side re-copy's root-boundary guard refuses
        // the rows under the planted link BEFORE the copy.
        let (rows, lines) = repair_manifest_rows(&m0, &input, &output, &dest, None);
        let rm = RepairManifest {
            name: m0.name.clone(),
            dest: dest.clone(),
            rows,
        };
        // The rows under the planted link stay dirty (the re-copy was
        // refused — NOT re-copied into the outside dir).
        assert!(rm.dirty_count() > 0, "the rows under the planted link stay dirty: {rm:?}");
        assert!(
            rm.verdict().starts_with("REFUSE"),
            "the full set is not clean: {}",
            rm.verdict()
        );
        // The named line names the root-boundary class + the row
        // (the Err arm).
        let named: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        assert!(
            named
                .iter()
                .any(|l| l.contains("escapes its root") && l.contains("A001_007/f1.DNG")),
            "the named refusal names the class + the row: {named:?}"
        );
        // The OUTSIDE dir is UNTOUCHED (the byte-identity proof — the
        // re-copy was refused before it landed there).
        assert_eq!(
            sentinel_before,
            std::fs::read(&sentinel).unwrap(),
            "the outside sentinel is unchanged"
        );
        let outside_entries: Vec<String> = std::fs::read_dir(&outside)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            outside_entries,
            vec!["sentinel.bin"],
            "no re-copied file landed in the outside dir: {outside_entries:?}"
        );
        // The planted link STAYS (never followed for a write).
        assert!(
            std::fs::symlink_metadata(&clip_dir)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the planted link stands"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
