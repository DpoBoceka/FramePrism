//! per-clip + run offload reports (the recorded decision).
//!
//!
//! The cart's "automated offload report" as text, not the
//! PDF/contact-sheet ceremony: at the end of every encode run (j92 AND
//! jxl paths) the tool writes
//!   - `<OUT_DIR>/<CLIP>.frameprism-report.md` per clip (the clip key =
//!     the ingest-manifest's — the relpath's parent dir, "" = the
//!     input root → the dotfile `.frameprism-report.md`), and
//!   - ONE `<OUT_DIR>/.frameprism-run-report.md` for the run.
//!
//! determinism: the per-clip report carries NO wall clock at all
//! (diffable; same inputs → byte-identical), the run report carries
//! exactly ONE `created:` line (the bake-manifest pattern). Both are
//! human-readable markdown.
//!
//! The gap/continuity VERDICT is the SOURCE (the ingest-gate
//! record — `worker::IngestGateReport`, the single struct the
//! ingest-manifest.tsv is serialized from); the report RENDERS it,
//! never re-derives it. The per-codec checksum summary is the run's
//! own numbers (the outcomes: source raw vs encoded per clip). The
//! camera metadata for the jxl path lands HERE (the JXL
//! sidecar is oracle-pinned and byte-frozen — its metadata is the
//! report's, the J92 sidecar carries the v3 columns).
//!
//! The `audit` verb prints the report's verdict line when a report is
//! present (`audit_report_lines` — additive output, no rc change: the
//! encode-time gate is the verdict's authority, the line is the
//! record's echo).

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::worker::{clip_key_of, display_clip, IngestGateReport, Outcome};

/// The run report file name (ONE per run, at the output root — the dot
/// keeps it out of the clip-name space).
pub const RUN_REPORT_NAME: &str = ".frameprism-run-report.md";

/// The per-clip report file name (the clip key = the ingest-manifest's;
/// a flat single-clip run → the dotfile `.frameprism-report.md`).
pub fn per_clip_report_name(key: &str) -> String {
    format!("{key}.frameprism-report.md")
}

/// The j92 codec version line — the jpeg-turbo BUILD resolved at
/// compile time (build.rs, recorded decision: the line carries the
/// absolute prefix path because same version from a different prefix
/// = a different byte contract). build.rs emits the env
/// unconditionally (the missing-.pc case is the named "unknown
/// (prefix …)" value — the fallback IS the value, never a silent
/// omission).
pub fn jpeg_turbo_build() -> &'static str {
    env!("FRAMEPRISM_JPEG_TURBO_BUILD")
}

/// The run's per-codec numbers for one clip (the run's OWN numbers —
/// the outcomes, not a re-scan): the source raw bytes (Done + Skipped,
/// the summary-line convention), the encoded bytes (Done only), the
/// skipped/failed counts.
struct ClipStats {
    in_bytes: u64,
    out_bytes: u64,
    done: usize,
    skipped: usize,
    failed: usize,
}

fn clip_stats(
    input: &Path,
    frames: &[(PathBuf, PathBuf)],
    outcomes: &[Outcome],
    key: &str,
) -> ClipStats {
    let mut s = ClipStats {
        in_bytes: 0,
        out_bytes: 0,
        done: 0,
        skipped: 0,
        failed: 0,
    };
    for (i, (src, _)) in frames.iter().enumerate() {
        if clip_key_of(input, src) != key {
            continue;
        }
        match &outcomes[i] {
            Outcome::Done(st) => {
                s.in_bytes += st.in_bytes;
                s.out_bytes += st.out_bytes;
                s.done += 1;
            }
            Outcome::Skipped { in_bytes, .. } => {
                s.in_bytes += *in_bytes;
                s.skipped += 1;
            }
            Outcome::Failed { .. } => s.failed += 1,
        }
    }
    s
}

fn ratio(in_b: u64, out_b: u64) -> f64 {
    if out_b > 0 {
        in_b as f64 / out_b as f64
    } else {
        0.0
    }
}

// ---------------------------------------------------------------------------
// The non-frame members
// ---------------------------------------------------------------------------

/// The magic line of the member record `<CLIP>.members.tsv` (the
/// additive next-to pattern — the v2→v3 additive precedent; the v3
/// `<CLIP>.checksums.tsv` + the additive `<CLIP>.qc.tsv` ride the same
/// name space).
pub const MEMBERS_MAGIC: &str = "# frameprism member record";

/// The member record column line: one row per non-frame file of the
/// clip (the clip-relative path — path-independent, the record
/// survives a move of the tree), the size, the sha256 (lowercase
/// 64-hex — the canonical digest the re-verify checks against), the
/// verdict (the output copy's state at report time).
pub const MEMBERS_COLUMNS: &str = "file\tsize\tsha256\tverdict";

/// The member record file name for a clip: `<CLIP>.members.tsv` (the
/// flat key "" → the dotfile `.members.tsv` — the per-clip report's
/// convention).
pub fn members_name(clip: &str) -> String {
    format!("{clip}.members.tsv")
}

/// One member record row.
#[derive(Clone, Debug, PartialEq)]
pub struct MembersRow {
    /// The clip-relative path (POSIX; a top-level member is its
    /// basename).
    pub file: String,
    pub size: u64,
    /// The source file's sha256 (the canonical row value — `"-"` for
    /// the unreadable-source row).
    pub sha: String,
    /// `OK` | `MISSING …` | `SIZE_MISMATCH …` | `SHA_MISMATCH …` |
    /// `SRC_UNREADABLE …` (the named verdicts — the audit philosophy:
    /// every dirty row is named, nothing is skipped silently).
    pub verdict: String,
}

/// The parsed member record (the audit's parse surface — the strict
/// shape, the offload-manifest convention).
#[derive(Clone, Debug)]
pub struct MembersRecord {
    /// The clip key ("" = the input root — the flat clip).
    pub clip: String,
    pub rows: Vec<MembersRow>,
    /// The record's own verdict line (the report's echo: `verdict: OK
    /// K/K` / `verdict: REFUSE N named row(s)`).
    pub verdict_line: String,
}

/// The tool's own record names (the degenerate in-place
/// input==output case: the tool's records are not clip content — the
/// member record never carries a row about itself). Dotfiles are
/// excluded too (the offload manifest covers EVERY file — the two
/// surfaces are complementary: the member record = the named clip
/// content, the offload manifest = the full-file integrity).
fn is_tool_record(name: &str) -> bool {
    name.starts_with('.')
        || name == RUN_REPORT_NAME
        || name.ends_with(".frameprism-report.md")
        || name.ends_with(".checksums.tsv")
        || name.ends_with(".qc.tsv")
        || name.ends_with(".members.tsv")
        || name.ends_with(".offload-manifest.tsv")
        || name.ends_with(".ingest-manifest.tsv")
        || name.ends_with(".derive-manifest.tsv")
        || name.ends_with(".reel-manifest.tsv")
        || name.ends_with(".bake-manifest.tsv")
}

/// The non-frame members of a clip (the clip's INPUT dir, the
/// `collect` discipline: the mirrored subfolder layout, symlinked
/// entries skipped, the (dev, ino) cycle guard): the non-.DNG regular
/// files (case-insensitive extension, the worker's `is_dng` rule)
/// minus the tool's own records, clip-relative, sorted by rel.
fn collect_members(base: &Path, dir: &Path) -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    let mut visited: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
    fn walk(
        base: &Path,
        dir: &Path,
        out: &mut Vec<(String, PathBuf)>,
        visited: &mut std::collections::HashSet<(u64, u64)>,
    ) -> std::io::Result<()> {
        let meta = std::fs::metadata(dir)?;
        let id = (meta.dev(), meta.ino());
        if !visited.insert(id) {
            return Ok(()); // the cycle guard (the collect parity)
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            let ft = entry.file_type()?;
            if ft.is_symlink() {
                continue; // the collect discipline: symlinked entries skipped
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if p.is_dir() {
                walk(base, &p, out, visited)?;
            } else if p.is_file() {
                let is_dng = p
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("dng"))
                    .unwrap_or(false);
                if is_dng || is_tool_record(&name) {
                    continue;
                }
                let rel = p
                    .strip_prefix(base)
                    .ok()
                    .map(|r| r.to_string_lossy().replace('\\', "/"))
                    .unwrap_or(name.clone());
                out.push((rel, p));
            }
        }
        Ok(())
    }
    let _ = walk(base, dir, &mut out, &mut visited);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// The verdict of one member (the output copy's state at report time —
/// the source is the row's record; the copy is re-verified): `OK` |
/// `MISSING` | `SIZE_MISMATCH` | `SHA_MISMATCH` | `SRC_UNREADABLE`.
fn member_verdict(src: &Path, dst: &Path) -> (u64, String, String) {
    // The bounded reads — the size from the O(1) stat, the
    // sha streamed (`SHA256_CHUNK`-buffered — never the whole file in
    // a `Vec`); the UNREADABLE wordings are the pre-existing ones.
    let size = match std::fs::metadata(src).map(|m| m.len()) {
        Ok(s) => s,
        Err(err) => {
            return (
                0,
                "-".into(),
                format!("SRC_UNREADABLE ({err}) — the row is named, not invented"),
            )
        }
    };
    let sha = match crate::jxl::sha256_stream_path(src) {
        Ok(s) => s,
        Err(err) => {
            return (
                0,
                "-".into(),
                format!("SRC_UNREADABLE ({err}) — the row is named, not invented"),
            )
        }
    };
    let verdict = if !dst.is_file() {
        "MISSING (the output copy is absent — the member was not carried)".into()
    } else {
        let dst_size = match std::fs::metadata(dst).map(|m| m.len()) {
            Ok(s) => s,
            Err(err) => {
                return (size, sha, format!("DST_UNREADABLE ({err})"))
            }
        };
        let dst_sha = match crate::jxl::sha256_stream_path(dst) {
            Ok(s) => s,
            Err(err) => {
                return (size, sha, format!("DST_UNREADABLE ({err})"))
            }
        };
        if dst_size != size {
            format!(
                "SIZE_MISMATCH (src {} B, dst {} B)",
                size,
                dst_size
            )
        } else if dst_sha != sha {
            format!(
                "SHA_MISMATCH (src {}, dst {})",
                &sha[..sha.len().min(16)],
                &dst_sha[..16.min(sha.len())]
            )
        } else {
            "OK".into()
        }
    };
    (size, sha, verdict)
}

/// The per-clip members (the INPUT clip dir → the OUTPUT copy's
/// verdicts). `key` = the clip key ("" = the input root).
fn clip_members(input: &Path, output: &Path, key: &str) -> Vec<(String, u64, String, String)> {
    let clip_dir = if key.is_empty() {
        input.to_path_buf()
    } else {
        input.join(key)
    };
    if !clip_dir.is_dir() {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for (rel, src) in collect_members(&clip_dir, &clip_dir) {
        let dst = if key.is_empty() {
            output.join(&rel)
        } else {
            output.join(key).join(&rel)
        };
        let (size, sha, verdict) = member_verdict(&src, &dst);
        rows.push((rel, size, sha, verdict));
    }
    rows
}

/// The output-root-relative frame path (POSIX) — the sidecar row key
/// (the worker `process` closure's `rel`): the read-site source-sha
/// registry's key (.
fn dst_rel(output: &Path, dst: &Path) -> String {
    dst.strip_prefix(output)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| dst.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default())
}

/// The per-clip source rows for the `<CLIP>.sources.tsv` record
/// (the verify-before-wipe gate — the encode-input anchor):
/// EVERY source file of the clip — the DNG frames AND the non-frame
/// members (WAV/XMP) — with the clip-relative path, the size, and the
/// sha256 AS READ AT ENCODE (the card bytes at ingest — the offload
/// `source_sha256` column pattern applied to the encode input). The
/// sha site, in order of preference (the card I/O is the bottleneck):
/// 1. the `--to` run's offload report (it re-scanned + hashed EVERY
///    source file — the source_sha column is the anchor; zero extra
///    reads), 2. the decode-site registry (the worker's `run` noted
///    the source buffer's sha DURING the encode read — one read, one
///    hash, no second full-file read), 3. the write-site read (this
///    run did not read the file — the resume-skip / the jxl path / the
///    failed frame: one read; the named absence "-" when unreadable —
///    the row can never verify, the card is REFUSED on it). The size
///    is the as-read byte count (the Done frame's `in_bytes`; the
///    skip's metadata; the failed frame's on-disk stat). Rows sorted
///    by path (the record's contract); deterministic (no wall clock).
fn clip_source_rows(
    input: &Path,
    output: &Path,
    key: &str,
    frames: &[(PathBuf, PathBuf)],
    outcomes: &[Outcome],
    offload: Option<&crate::offload::OffloadReport>,
) -> Vec<(String, u64, String)> {
    let base = if key.is_empty() {
        input.to_path_buf()
    } else {
        input.join(key)
    };
    // The offload's source-sha lookup (the `--to` run: the source rows
    // are keyed by the input-root-relative path — the same key space as
    // the sidecar rel for the frames, `{key}/{rel}` for the members).
    let offload_map: std::collections::BTreeMap<&str, &crate::offload::OffloadRow> = offload
        .map(|r| r.rows.iter().map(|row| (row.file.as_str(), row)).collect())
        .unwrap_or_default();
    let mut rows: Vec<(String, u64, String)> = Vec::new();
    for (i, (src, dst)) in frames.iter().enumerate() {
        if clip_key_of(input, src) != key {
            continue;
        }
        let rel = src
            .strip_prefix(&base)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| {
                src.file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default()
            });
        let size = match &outcomes[i] {
            Outcome::Done(s) => s.in_bytes,
            Outcome::Skipped { in_bytes, .. } => *in_bytes,
            Outcome::Failed { .. } => std::fs::metadata(src).map(|m| m.len()).unwrap_or(0),
        };
        let rel_key = dst_rel(output, dst);
        let sha = if let Some(row) = offload_map.get(rel_key.as_str()) {
            row.source_sha.clone()
        } else if let Some(sha) = crate::sourcecheck::claim_source_sha(&rel_key) {
            sha
        } else {
            // The write-site fallback (this run did not read the
            // frame's source — the resume-skip / the jxl path / the
            // failed frame): one streaming read (the
            // bounded sha), the named absence when unreadable.
            match crate::jxl::sha256_stream_path(src) {
                Ok(sha) => sha,
                Err(_) => "-".into(),
            }
        };
        rows.push((rel, size, sha));
    }
    // The non-frame members (the clip's INPUT dir — the
    // collect_members discipline: the tool's own records excluded):
    // the offload's source sha when present, else read + hash (they
    // are small — the card-I/O note applies to the frames, not to the
    // members).
    for (mrel, msrc) in collect_members(&base, &base) {
        let offload_key = if key.is_empty() {
            mrel.clone()
        } else {
            format!("{key}/{mrel}")
        };
        let size = std::fs::metadata(&msrc).map(|m| m.len()).unwrap_or(0);
        let sha = if let Some(row) = offload_map.get(offload_key.as_str()) {
            row.source_sha.clone()
        } else {
            match crate::jxl::sha256_stream_path(&msrc) {
                Ok(sha) => sha,
                Err(_) => "-".into(),
            }
        };
        rows.push((mrel, size, sha));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

/// Write the member record `<CLIP>.members.tsv` (temp + rename — the
/// atomic-write convention: a kill mid-write leaves the previous
/// complete record in place, never a torn final file). Deterministic
/// bytes (no wall clock — the contract): the same clip state →
/// the same record.
pub fn write_members_record(
    output: &Path,
    key: &str,
    rows: &[(String, u64, String, String)],
) -> std::io::Result<PathBuf> {
    let dirty = rows.iter().filter(|r| r.3 != "OK").count();
    let verdict = if dirty == 0 {
        format!("verdict: OK {}/{}", rows.len(), rows.len())
    } else {
        format!("verdict: REFUSE {dirty} named row(s)")
    };
    let mut tsv = String::new();
    tsv.push_str(MEMBERS_MAGIC);
    tsv.push('\n');
    tsv.push_str("version: 1\n");
    tsv.push_str(&format!("tool_version: {}\n", env!("CARGO_PKG_VERSION")));
    tsv.push_str(&format!("clip: {key}\n"));
    tsv.push_str("note: the non-frame members of the clip (stored as-is: the determinism/repair claim does NOT apply — repair = re-copy, never re-encode; the frames are re-encodable byte-identical, the members are not)\n");
    tsv.push_str("note: the bake archives the members unchanged as named reel-object members (no re-compression)\n");
    tsv.push_str(MEMBERS_COLUMNS);
    tsv.push('\n');
    for (file, size, sha, verdict) in rows {
        tsv.push_str(&format!("{file}\t{size}\t{sha}\t{verdict}\n"));
    }
    tsv.push_str(&verdict);
    tsv.push('\n');
    let path = output.join(members_name(key));
    let tmp = output.join(format!(".{key}.members.tsv.tmp"));
    std::fs::write(&tmp, tsv)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Parse a member record (this module's writer — the strict shape):
/// the magic line, the header keys, the exact column line, the
/// 4-column data rows, the verdict line. A corrupt record is an Err
/// (the loud class — the audit turns it into the named hard rc=2, the
/// offload-manifest convention).
pub fn parse_members_record(path: &Path) -> Result<MembersRecord, String> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("read the member record {name}: {err}"))?;
    let lines: Vec<&str> = text.lines().collect();
    let first = lines
        .first()
        .ok_or_else(|| format!("empty member record {name}"))?;
    if *first != MEMBERS_MAGIC {
        return Err(format!(
            "{name} is not a frameprism member record (first line {first:?}, want {MEMBERS_MAGIC:?})"
        ));
    }
    let mut clip = String::new();
    let mut rows = Vec::new();
    let mut verdict_line = String::new();
    let mut in_data = false;
    for (idx, line) in lines.iter().enumerate().skip(1) {
        let lineno = idx + 1;
        if !in_data {
            if *line == MEMBERS_COLUMNS {
                in_data = true;
            } else if let Some(v) = line.strip_prefix("clip: ") {
                clip = v.to_string();
            }
            // the other header keys (version / tool_version / note) —
            // additive by convention.
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if let Some(v) = line.strip_prefix("verdict: ") {
            verdict_line = v.to_string();
            continue;
        }
        if !line.contains('\t') {
            return Err(format!("bad row in {name} line {lineno} (want 4 tab-separated columns: file, size, sha256, verdict): {line:?}"));
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 4 {
            return Err(format!(
                "bad row in {name} line {lineno}: {} columns (want 4: file, size, sha256, verdict)",
                f.len()
            ));
        }
        let size: u64 = f[1]
            .parse()
            .map_err(|_| format!("bad size column {:?} in {name} line {lineno}", f[1]))?;
        rows.push(MembersRow {
            file: f[0].to_string(),
            size,
            sha: f[2].to_string(),
            verdict: f[3].to_string(),
        });
    }
    if !in_data {
        return Err(format!("no column line in {name} (the member record is corrupt?)"));
    }
    Ok(MembersRecord {
        clip,
        rows,
        verdict_line,
    })
}

/// Re-verify a member record against the tree the record lives in
/// (the audit's surface — path-independent: the rows are CLIP-
/// RELATIVE + the record sits at the tree root next to the clip dir,
/// so a move of the whole tree keeps the record verifiable): each
/// row's file (resolved against the clip key's dir in `record_dir`)
/// against the recorded size + sha256. Returns (the named lines, the
/// bad row count) — a post-run member corruption (or a vanished file)
/// is named on that row (the audit philosophy: the named offender, not
/// a silent skip).
pub fn reverify_members(rec: &MembersRecord, record_dir: &Path) -> (Vec<String>, usize) {
    let mut lines = Vec::new();
    let mut bad = 0usize;
    for row in &rec.rows {
        let target = if rec.clip.is_empty() {
            record_dir.join(&row.file)
        } else {
            record_dir.join(&rec.clip).join(&row.file)
        };
        let problem = if !target.is_file() {
            Some(format!("MISSING (the recorded member is absent from the tree — {})", target.display()))
        } else {
            // The bounded reads — the size from the O(1)
            // stat, the sha streamed; the problem wordings are the
            // pre-existing ones.
            match std::fs::metadata(&target).map(|m| m.len()) {
                Err(err) => Some(format!("UNREADABLE ({err})")),
                Ok(size) => {
                    if size != row.size {
                        Some(format!(
                            "SIZE_MISMATCH (recorded {} B, on disk {} B)",
                            row.size,
                            size
                        ))
                    } else {
                        match crate::jxl::sha256_stream_path(&target) {
                            Err(err) => Some(format!("UNREADABLE ({err})")),
                            Ok(sha) => {
                                if row.sha != "-" && sha != row.sha {
                                    Some(format!(
                                        "SHA_MISMATCH (recorded {}, on disk {})",
                                        &row.sha[..row.sha.len().min(16)],
                                        &sha[..16]
                                    ))
                                } else {
                                    None
                                }
                            }
                        }
                    }
                }
            }
        };
        if let Some(p) = problem {
            bad += 1;
            lines.push(format!(
                "FAIL member {}{}{}: {p}",
                rec.clip,
                if rec.clip.is_empty() { "" } else { "/" },
                row.file
            ));
        }
    }
    let display = if rec.clip.is_empty() { ".".to_string() } else { rec.clip.clone() };
    lines.push(format!(
        "audit: members {}/{} file(s) OK ({display})",
        rec.rows.len() - bad,
        rec.rows.len()
    ));
    (lines, bad)
}


/// Write the per-clip reports + the ONE run report for this run
/// . Called at the end of every encode run (j92 +
/// jxl), AFTER the encode + the checksums sidecar + the optional
/// `--to` offload (the run report carries the offload verdict line).
/// `codec` = "j92" | "jxl"; `codec_version` = the cjxl version line
/// (jxl) or `jpeg_turbo_build()` (j92); `j92_sidecar` = the written
/// checksums/jxl-checksums sidecar path when present (None = a
/// frame-failed run skipped it). Returns the report paths written
/// (the per-clip ones in the gate's clip order + the run report).
///
/// The `--to` dispatch (the additive half): when
/// `offload = Some` the run report + the per-clip reports carry the
/// `## offload` section — the verdict line + the FAIL lines + the
/// per-clip blocks (the existing `OffloadReport` formats, verbatim)
/// and the per-clip detection lines (the scanner's line formats,
/// verbatim — one scanner, both surfaces; report, not gate). The
/// section renders ONLY when `offload = Some`: without `--to` the
/// reports are byte-identical to the pre-dispatch shape (C1), the
/// per-clip reports gain no wall clock (C4), and the run report keeps
/// exactly ONE `created:` line.
pub fn write_reports(
    output: &Path,
    input: &Path,
    codec: &str,
    codec_version: &str,
    gate: &IngestGateReport,
    frames: &[(PathBuf, PathBuf)],
    outcomes: &[Outcome],
    offload: Option<&crate::offload::OffloadReport>,
    sidecar: Option<&PathBuf>,
) -> Result<Vec<PathBuf>> {
    let tool = format!("frameprism {}", env!("CARGO_PKG_VERSION"));
    let sidecar_name = sidecar
        .map(|p| {
            p.file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let mut written: Vec<PathBuf> = Vec::new();

    // The offload dispatch on the encode surface (the additive half
    // ): when `--to` ran (offload = Some), the run +
    // the per-clip reports carry the `## offload` section (the
    // verdict line + the FAIL lines + the per-clip blocks, the
    // existing formats verbatim) + the per-clip detection lines (the
    // scanner — ONE scanner, both surfaces; report, not gate —
    // the encode's profile gate already ran ahead of any write). The
    // scan runs here (the renderer has `input` — the call sites are
    // untouched); a scan failure is the named loud Err (the module's
    // idiom: a named FAIL, not a silent empty). Additive: without
    // `--to` (offload = None) nothing is scanned, rendered, or read
    // for the offload — the reports are byte-identical to the
    // pre-dispatch shape (C1).
    let detection = match offload {
        Some(_) => Some(
            crate::camera::offload_detections(input).map_err(|err| {
                anyhow::anyhow!(
                    "the offload detection scan of {}: {err}",
                    input.display()
                )
            })?,
        ),
        None => None,
    };

    // The per-clip reports (deterministic: no wall clock).
    for c in &gate.clips {
        let stats = clip_stats(input, frames, outcomes, &c.clip);
        // The camera metadata for this clip (the jxl path's
        // record — the J92 sidecar carries the same values per frame
        // in its v3 columns): read from the clip's first source frame
        // (the header is per-clip constant on the fp — the 51044 /
        // ExifIFD values do not vary frame-to-frame; the per-frame
        // column is the sidecar's).
        let first_src = frames
            .iter()
            .find(|(src, _)| clip_key_of(input, src) == c.clip)
            .map(|(src, _)| src.clone());
        let meta = match first_src {
            Some(p) => match crate::worker::read_frame_metadata(&p) {
                Ok(m) => m,
                Err(err) => bail!(
                    "read the clip metadata (a corrupt header is a named FAIL, not a silent empty): {err}"
                ),
            },
            None => crate::worker::FrameMetadata::default(),
        };
        let manifest_declared = match c.manifest_declared {
            Some(d) => format!("manifest: {d}"),
            None => "manifest: absent — the expected-frame-count check was skipped".into(),
        };
        let verdict = if c.manifest_declared.is_some() {
            format!(
                "ingest-gate PASS ({} frame(s): frame-number contiguity + manifest count + TC continuity +1/frame)",
                c.frames_found
            )
        } else {
            format!(
                "ingest-gate PASS ({} frame(s): frame-number contiguity + TC continuity +1/frame — no manifest.tsv, the expected-frame-count check was skipped)",
                c.frames_found
            )
        };
        let sidecar_line = match sidecar {
            Some(_) if codec == "j92" => {
                let n = c.frames_found;
                format!(
                    "{sidecar_name} (v3: the 4 contract columns + timecode/framerate/iso/exposure — {n} row(s))"
                )
            }
            Some(_) => format!(
                "{sidecar_name} (oracle-pinned format — the camera metadata above is this path's record)"
            ),
            None => "absent (the --checksums pass is skipped when a frame fails)".into(),
        };
        let mut md = String::new();
        md.push_str(&format!("# frameprism report — clip {}\n\n", display_clip(&c.clip)));
        md.push_str(&format!("tool: {tool}\n"));
        md.push_str(&format!("codec: {codec} ({codec_version})\n"));
        md.push_str(&format!("frames: {} ({})\n", c.frames_found, manifest_declared));
        md.push_str(&format!(
            "frame range: {}\n",
            c.frame_range
                .map(|(a, b)| format!("{a}..{b}"))
                .unwrap_or_else(|| "-".into())
        ));
        md.push_str(&format!(
            "TC range: {}\n",
            match (&c.tc_start, &c.tc_end) {
                (Some(a), Some(b)) => format!("{a}..{b}"),
                (Some(a), None) | (None, Some(a)) => format!("{a}..?"),
                (None, None) => "-".into(),
            }
        ));
        md.push_str(&format!("verdict: {verdict}\n"));
        // The (--subset) named line — present IFF the gate ran
        // under the named continuity waiver (byte-stable — no wall
        // clock, no path; the marker is the report/ledger shared
        // string — the honesty property).
        if gate.subset {
            md.push_str(crate::worker::SUBSET_MARKER);
            md.push('\n');
        }
        md.push_str(&format!(
            "source raw: {} B ({} frame(s))\n",
            stats.in_bytes,
            stats.done + stats.skipped
        ));
        md.push_str(&format!(
            "encoded: {} B ({:.2}:1)\n",
            stats.out_bytes,
            ratio(stats.in_bytes, stats.out_bytes)
        ));
        if stats.skipped > 0 {
            md.push_str(&format!(
                "skipped: {} frame(s) (existing outputs kept)\n",
                stats.skipped
            ));
        }
        if stats.failed > 0 {
            md.push_str(&format!(
                "failed: {} frame(s) (named in the run summary)\n",
                stats.failed
            ));
        }
        // The A2 ETA line (the per-clip half — report.rs lands the
        // "per clip" print; the label is the contract). The
        // frame count + the rate make it deterministic (holds).
        md.push_str(&format!(
            "eta: {}\n",
            crate::preflight::eta_report_line(codec, c.frames_found as usize)
        ));
        md.push_str(&format!(
            "framerate: {}\n",
            meta
                .framerate
                .map(|(n, d)| format!("{n}/{d} (tag 51044)"))
                .unwrap_or_else(|| "absent (tag 51044 not in the DNG header)".into())
        ));
        md.push_str(&format!(
            "iso: {}\n",
            meta
                .iso
                .clone()
                .map(|v| format!("{v} (ExifIFD tag 34855)"))
                .unwrap_or_else(|| "absent (ExifIFD tag 34855 not in the DNG header)".into())
        ));
        md.push_str(&format!(
            "exposure: {}\n",
            meta
                .exposure
                .map(|(n, d)| format!("{n}/{d} s (ExifIFD tag 34853)"))
                .unwrap_or_else(|| {
                    "absent (tag 34853 not in the DNG header — the fixed empty sidecar column)"
                        .into()
                })
        ));
        md.push_str(&format!("sidecar: {sidecar_line}\n"));
        //: the non-frame members section (the clip's INPUT dir
        // → the OUTPUT copy's verdicts — the row is sha-verified, the
        // determinism/repair claim does NOT apply: the members are
        // stored as-is, repair = re-copy, never re-encode; the bake
        // archives them unchanged as named reel-object members). The
        // record <CLIP>.members.tsv is written when members are
        // present (the audit's re-verify surface — path-independent
        // rows, the record survives a move of the tree).
        let members = clip_members(input, output, &c.clip);
        if members.is_empty() {
            md.push_str("members: none — the clip carries no non-frame files\n");
        } else {
            md.push_str("\n## members — the non-frame files (stored as-is)\n");
            md.push_str(MEMBERS_COLUMNS);
            md.push('\n');
            for (file, size, sha, verdict) in &members {
                md.push_str(&format!("{file}\t{size}\t{sha}\t{verdict}\n"));
            }
            let dirty = members.iter().filter(|m| m.3 != "OK").count();
            md.push_str(&format!(
                "members verdict: {}\n",
                if dirty == 0 {
                    format!("OK {}/{}", members.len(), members.len())
                } else {
                    format!("REFUSE {dirty} named row(s)")
                }
            ));
            md.push_str("note: the members are stored as-is — the determinism/repair claim does NOT apply (repair = re-copy, never re-encode; the frames are re-encodable byte-identical, the members are not); the bake archives them unchanged as named reel-object members (no re-compression)\n");
            write_members_record(output, &c.clip, &members)
                .with_context(|| format!("write the member record {}", members_name(&c.clip)))?;
        }
        //: the QC section (the deterministic class — the run
        // report's additive section; the encode-time computation is
        // the authority, the report is the record's echo — the
        // ingest-gate pattern). The jxl path renders the named absent
        // line (the deterministic QC class rides the j92 decode site —
        // out of scope in v1). The per-clip report stays deterministic
        // (no wall clock — the state is the run's own computation).
        if codec == "j92" {
            match crate::qc::current() {
                Some(st) => match st.clips.iter().find(|q| q.clip == c.clip) {
                    Some(qc) => {
                        md.push_str("\n## qc — the deterministic class\n");
                        md.push_str(&format!(
                            "qc mode: {}\n",
                            if st.gate {
                                "gate (--qc-gate — the (a) black/blank + the (b) duplicate are the named-negative verdicts: any hit → the run completes and exits rc=2)"
                            } else {
                                "report-only (the default — the (a)/(b) candidates are always named; the run never gates; --qc-gate = the gate)"
                            }
                        ));
                        md.push_str(&format!(
                            "qc frames: {} of {} decoded this run (the clip moments cover the decoded set — a resume-skip is not re-decoded)\n",
                            qc.decoded, qc.total
                        ));
                        // (a) the black/blank rows (the pinned floors —
                        // the 12-bit fp domain only; other depths =
                        // stats only, no verdict).
                        if qc.black.is_empty() {
                            md.push_str("(a) black/blank: PASS — 0 named frame(s)\n");
                        } else {
                            md.push_str(&format!(
                                "(a) black/blank: {} named frame(s)\n",
                                qc.black.len()
                            ));
                            for (rel, range, var_num, n) in &qc.black {
                                let variance = if *n == 0 {
                                    0.0
                                } else {
                                    *var_num as f64 / (*n as f64 * *n as f64)
                                };
                                md.push_str(&format!(
                                    "(a) QC BLACK {rel} — range={range} < {range_floor} OR variance={var:.3} < {var_floor} (the pinned threshold)\n",
                                    range_floor = crate::qc::BLACK_RANGE_FLOOR,
                                    var_floor = crate::qc::BLACK_VAR_FLOOR,
                                    var = variance
                                ));
                            }
                        }
                        md.push_str(&format!(
                            "(a) threshold: range < {range_floor} OR variance < {var_floor} (the pinned constants qc::BLACK_RANGE_FLOOR / qc::BLACK_VAR_FLOOR — the {bps}-bit fp domain; other depths = stats only, no verdict)\n",
                            range_floor = crate::qc::BLACK_RANGE_FLOOR,
                            var_floor = crate::qc::BLACK_VAR_FLOOR,
                            bps = crate::qc::QC_VERDICT_BPS
                        ));
                        // (b) the duplicate pairs (the file-level v1
                        // scope — the output DNG sha256 rows, no
                        // decode; the pixel-level gap is documented +
                        // parked).
                        if !qc.dups_available {
                            md.push_str("(b) duplicate (file-level — the output DNG sha256 rows, no decode): absent — the sidecar sha rows are absent (the --checksums pass is off or the run failed — the check is named absent, not silently skipped)\n");
                        } else if qc.dups.is_empty() {
                            md.push_str("(b) duplicate (file-level — the output DNG sha256 rows, no decode): PASS — 0 pair(s)\n");
                        } else {
                            md.push_str(&format!(
                                "(b) duplicate (file-level — the output DNG sha256 rows, no decode): {} named pair(s)\n",
                                qc.dups.len()
                            ));
                            for d in &qc.dups {
                                md.push_str(&format!(
                                    "(b) QC DUP {} == {} — identical output sha256 {}…\n",
                                    d.a,
                                    d.b,
                                    &d.sha[..d.sha.len().min(16)]
                                ));
                            }
                        }
                        md.push_str("(b) note: (b) catches FILE-LEVEL duplication (the same file written twice); a pixel-level double-capture with an advanced TC yields different output bytes (the output carries the source TC, tag 51043) — the pixel-level gap is documented + parked (no decode-based pixel-dup check in v1)\n");
                        // (c) the exposure stats (the clip-level
                        // moments — never a gate: a "−2 EV" reading is
                        // a number in both the report and the record,
                        // never a verdict).
                        md.push_str("(c) exposure — clip moments over the decoded raw plane (\"per channel\" = the raw channel — the fp DNG is a single 1-sample/pixel plane):\n");
                        match &qc.moments {
                            Some(m) => md.push_str(&format!(
                                "(c) min {min} · max {max} · mean {mean:.3} · std {std:.3} · p1 {p1} · p99 {p99} (n = {n} raw samples)\n",
                                min = m.min,
                                max = m.max,
                                mean = m.mean(),
                                std = m.std(),
                                p1 = m.p1,
                                p99 = m.p99,
                                n = m.n
                            )),
                            None => md.push_str("(c) absent — no frame decoded this run (a resume-skip is not re-decoded — the stats ride the decode)\n"),
                        }
                        md.push_str("(c) note: the \"−2 EV\" reading is the number above (the machine-readable record) — never a gate ((c) is report-only by the split)\n");
                    }
                    None => {
                        md.push_str("qc: absent — no decode-site stats for this clip this run (the encode pass did not decode its frames)\n");
                    }
                },
                None => {
                    md.push_str("qc: absent (the deterministic QC class rides the j92 decode site — the stats are recorded when the encode pass ran)\n");
                }
            }
        } else {
            md.push_str("qc: absent (the deterministic QC class rides the j92 decode site — the jxl path is out of scope in v1; a --codec both run carries it in the j92 tier)\n");
        }
        //: the source-sha anchor (the verify-before-wipe gate):
        // the additive next-to record `<CLIP>.sources.tsv` (written for
        // EVERY encode run — the encode's input provenance: the DNG
        // frames + the non-frame members, clip-relative, the source
        // bytes as read at encode) + the deterministic reference
        // section (the row count + the anchor note — no wall clock).
        // NEW FILE: no existing record's bytes change (the byte
        // contract).
        let src_rows = clip_source_rows(input, output, &c.clip, frames, outcomes, offload);
        crate::sourcecheck::write_sources_record(output, &c.clip, &src_rows)
            .with_context(|| format!("write the source record {}", crate::sourcecheck::sources_name(&c.clip)))?;
        md.push_str("\n## sources — the encode-input anchor (the verify-before-wipe gate)\n");
        md.push_str(&format!(
            "sources record: {} — {} row(s) (every source file of the clip — the DNG frames + the non-frame members; the source bytes as read at encode)\n",
            crate::sourcecheck::sources_name(&c.clip),
            src_rows.len()
        ));
        md.push_str("note: `audit --source <card-root>` re-hashes these rows against the live source (the card) — the card is reusable only after CARD UNLOCKED (the tool never wipes the card — the format is the operator's action)\n");
        //: the offload dispatch section (the `--to` run — the
        // additive half): the clip's detection line (the
        // scanner's format verbatim — report, not gate; the
        // no-value token `-` when the clip carries no files in the
        // source tree — total + honest) + the clip's offload block
        // (the whole-tree report's per-clip verdict-block idiom:
        // files / ok / dirty; 0/0/0 when the clip has no offload
        // rows — the core's 0/0 slicing idiom). Deterministic
        // (no wall clock — the per-clip contract); ABSENT when `--to`
        // did not run (C1).
        if let (Some(det), Some(r)) = (&detection, offload) {
            md.push_str("\n## offload — the --to mirror (the verify-before-wipe gate)\n");
            let det_line = det
                .clips
                .iter()
                .find(|d| d.key == c.clip)
                .map(|d| d.class.line())
                .unwrap_or_else(|| "-".into());
            md.push_str(&format!("detection: {det_line}\n"));
            let block = r.clips.iter().find(|b| b.clip == c.clip);
            md.push_str(&format!(
                "files: {total} ok: {ok} dirty: {dirty}\n",
                total = block.map(|b| b.total).unwrap_or(0),
                ok = block.map(|b| b.ok).unwrap_or(0),
                dirty = block.map(|b| b.total - b.ok).unwrap_or(0)
            ));
        }
        let path = output.join(per_clip_report_name(&c.clip));
        std::fs::write(&path, md)
            .with_context(|| format!("write the per-clip report {}", path.display()))?;
        written.push(path);
    }

    // The ONE run report (exactly one `created:` wall-clock line).
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let host = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    let total_in: u64 = gate
        .clips
        .iter()
        .map(|c| clip_stats(input, frames, outcomes, &c.clip).in_bytes)
        .sum();
    let total_out: u64 = gate
        .clips
        .iter()
        .map(|c| clip_stats(input, frames, outcomes, &c.clip).out_bytes)
        .sum();
    let total_failed: usize = gate
        .clips
        .iter()
        .map(|c| clip_stats(input, frames, outcomes, &c.clip).failed)
        .sum();
    let mut md = String::new();
    md.push_str(&format!("# frameprism run report — {}\n\n", crate::checksums::clip_name(input)?));
    md.push_str(&format!("created: {created} (unix seconds, UTC)\n"));
    md.push_str(&format!("tool: {tool}\n"));
    md.push_str(&format!("host: {host}\n"));
    md.push_str(&format!("codec: {codec} ({codec_version})\n"));
    // The A1 pin block (the tool/versions block — every report says
    // what pins were enforced on its bytes). Absent = the run did not
    // run the check (the pure-read verbs; the encode/bake paths always
    // set it — `pins::set_current`).
    if let Some(pr) = crate::pins::current() {
        for line in pr.report_lines() {
            md.push_str(&line);
            md.push('\n');
        }
    }
    md.push_str(&format!("input: {}\n", input.display()));
    md.push_str(&format!("output: {}\n", output.display()));
    //: the pinned exFAT destination note (byte-stable — the
    // volume's fstypename is deterministic, no wall clock; ABSENT on
    // APFS — the report stays byte-identical to the pre-note shape).
    // The stdout preflight emission (main.rs / dryrun.rs) is the note's
    // other home; this is its record. The probe is advisory — `None`
    // (unreadable volume) = no line, never a write failure.
    if let Some(fstype) = crate::preflight::volume_fstype(output) {
        if crate::preflight::is_xattr_less_volume(&fstype) {
            md.push_str(&format!(
                "{}\n",
                crate::preflight::apple_double_note(&fstype, output)
            ));
        }
    }
    md.push_str(&format!(
        "clips: {} · frames: {}\n",
        gate.clips.len(),
        gate.frames_total
    ));
    // The selection line (ALWAYS present
    // regardless of the path): full set = `selection: all — N of N
    // clip(s)`; partial = `selection: <list> — partial: k of N
    // clip(s)` (the sorted list = the run's effective processed set;
    // the gate + the frames above cover exactly that set).
    md.push_str(&format!(
        "selection: {}\n",
        crate::selection::report_line(crate::selection::current(), gate.clips.len())
    ));
    // The resume line (ALWAYS present — K = the verified-skip
    // count of the run's --resume scan; 0 for a fresh run and the jxl
    // path — no plan, the jxl resume is the v1 refusal). The scan's
    // named notes (the torn tail / stale rows / the temp cleanup / the
    // no-sidecar note / the source-manifest status) ride the
    // `resumed note:` lines (the deterministic shape — no wall clock).
    let resumed_plan = crate::resume::current();
    md.push_str(&format!(
        "resumed: {} of {} frame(s) (verified from sidecar)\n",
        resumed_plan.map(|p| p.skipped()).unwrap_or(0),
        gate.frames_total
    ));
    if let Some(p) = resumed_plan {
        for note in &p.notes {
            md.push_str(&format!("resumed note: {note}\n"));
        }
    }
    md.push_str("clip\tframes\tmanifest\tframe range\tTC range\tsource B\tencoded B\tratio\tverdict\n");
    for c in &gate.clips {
        let s = clip_stats(input, frames, outcomes, &c.clip);
        md.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.2}:1\tPASS\n",
            display_clip(&c.clip),
            c.frames_found,
            c.manifest_declared
                .map(|d| d.to_string())
                .unwrap_or_else(|| "absent".into()),
            c.frame_range
                .map(|(a, b)| format!("{a}..{b}"))
                .unwrap_or_else(|| "-".into()),
            match (&c.tc_start, &c.tc_end) {
                (Some(a), Some(b)) => format!("{a}..{b}"),
                (Some(a), None) | (None, Some(a)) => format!("{a}..?"),
                (None, None) => "-".into(),
            },
            s.in_bytes,
            s.out_bytes,
            ratio(s.in_bytes, s.out_bytes)
        ));
    }
    md.push_str(&format!(
        "totals: source {total_in} B -> encoded {total_out} B ({:.2}:1)\n",
        ratio(total_in, total_out)
    ));
    // The A2 ETA line (the total — the start-of-run print is on
    // stderr; the measured corpus rates, the label is the contract).
    md.push_str(&format!(
        "eta: {}\n",
        crate::preflight::eta_report_line(codec, gate.frames_total as usize)
    ));
    //: the qc line (the run-level verdict line — the encode-time
    // computation is the authority; the jxl path renders the named
    // absent line — the deterministic QC class rides the j92 decode
    // site, out of scope in v1). No wall clock (the contract —
    // the run report's single `created:` line stands alone).
    if codec == "j92" {
        match crate::qc::current() {
            Some(st) => {
                let hits: usize = st
                    .clips
                    .iter()
                    .map(|c| c.black.len() + c.dups.len())
                    .sum();
                if st.gate {
                    if hits > 0 {
                        md.push_str(&format!(
                            "qc: GATE FAIL — {hits} named row(s) (--qc-gate — the run completes: no data loss, the files are written; the gate is a verdict, not a preflight refusal)\n"
                        ));
                    } else {
                        md.push_str("qc: gate PASS — 0 named row(s) (--qc-gate — the (a) black/blank + the (b) duplicate checks clean)\n");
                    }
                } else if hits > 0 {
                    md.push_str(&format!(
                        "qc: report-only — {hits} named candidate row(s) ((a) black/blank + (b) duplicate; --qc-gate = the gate, rc=2)\n"
                    ));
                } else {
                    md.push_str("qc: report-only — 0 named candidate row(s)\n");
                }
            }
            None => md.push_str("qc: absent (the deterministic QC class rides the j92 decode site — the stats are recorded when the encode pass ran)\n"),
        }
    } else {
        md.push_str("qc: absent (the deterministic QC class rides the j92 decode site — the jxl path is out of scope in v1; a --codec both run carries it in the j92 tier)\n");
    }
    if let Some(r) = offload {
        md.push_str(&format!("{}\n", r.verdict_line()));
        md.push_str(
            "offload note: the non-DNG members (WAV/XMP/manifest.tsv/…) ride the offload rows as first-class members — the determinism/repair claim for them is re-copy, never re-encode.\n",
        );
    }
    let offload_clause = match offload {
        Some(r) if r.dirty_count() == 0 => {
            format!(", offload VERIFIED {}/{}", r.rows.len(), r.rows.len())
        }
        Some(r) => format!(
            ", offload REFUSE {} named row(s)",
            r.dirty_count()
        ),
        None => String::new(),
    };
    let run_state = if total_failed > 0 {
        format!(
            "run DEGRADED — {} clip(s), {} frame(s), {} frame(s) failed{offload_clause}",
            gate.clips.len(),
            gate.frames_total,
            total_failed
        )
    } else {
        format!(
            "run OK — {} clip(s), {} frame(s){offload_clause}",
            gate.clips.len(),
            gate.frames_total
        )
    };
    md.push_str(&format!("verdict: {run_state}\n"));
    //: the additive `## live` section (the final totals — the
    // non-pinned region; the per-frame TSV + sidecar machine contracts
    // are untouched — NO columns added, the ms/MB-s data is stdout +
    // markdown only). The in-process encode's window (the process-level
    // disk I/O + the CPU + the frames/s). The jxl tier never begins the
    // in-process sampling — its cjxl subprocess I/O is invisible to the
    // process-level counters: the named non-scope line (the honesty
    // rule; unmeasurable = the named n/a, never a silent 0).
    md.push_str("\n## live — the encode metrics (the predict-then-measure arc)\n");
    match crate::live::last() {
        Some(t) => {
            md.push_str(&format!("- frames: {}/{} done\n", t.frames_done, t.frames_total));
            md.push_str(&format!("- wall: {:.1}s — {:.2} frames/s\n", t.wall_s, t.fps));
            md.push_str(&format!(
                "- total read: {} B — mean {} MB/s, peak {} MB/s (process-level backing-store I/O — a page-cache hit does not count; a warm source shows the smaller number, named)\n",
                t.read_total.map_or_else(|| "n/a".into(), |b| b.to_string()),
                t.read_mean_mbs.map_or_else(|| "n/a".into(), |x| format!("{x:.2}")),
                t.read_peak_mbs.map_or_else(|| "n/a".into(), |x| format!("{x:.2}")),
            ));
            md.push_str(&format!(
                "- total written: {} B — mean {} MB/s (± the manifests/sidecars written after the live window: named)\n",
                t.write_total.map_or_else(|| "n/a".into(), |b| b.to_string()),
                t.write_mean_mbs.map_or_else(|| "n/a".into(), |x| format!("{x:.2}")),
            ));
            md.push_str(&format!(
                "- cpu% (multi-core): {} mean (the % can exceed 100 — that is the load)\n",
                t.cpu_mean_pct.map_or_else(|| "n/a".into(), |x| format!("{x:.1}")),
            ));
        }
        None => md.push_str(
            "- (no live totals — the jxl tier's cjxl subprocess I/O is invisible to the \
             process-level counters: the named non-scope; or the FFI is unavailable on \
             this platform: the named n/a, never a silent 0)\n",
        ),
    }
    //: the offload dispatch section (the `--to` run — the additive
    // half): the per-clip detection lines (the
    // scanner's formats verbatim — ONE scanner, both surfaces), the
    // per-clip blocks (the whole-tree report's ClipBlocks — the
    // manifest's block order), the FAIL lines (the existing
    // `fail_lines()` formats verbatim — present only when dirty,
    // the `## failures` idiom), and the verdict line (the
    // existing format verbatim). The original inline verdict line +
    // the offload note + the verdict clause stand untouched above
    // (the existing output bytes stand; this section is purely
    // additive). ABSENT when `--to` did not run (C1); no wall clock
    // (the run report's single `created:` line stands alone — C4).
    if let (Some(det), Some(r)) = (&detection, offload) {
        md.push_str("\n## offload — the --to mirror (the verify-before-wipe gate)\n");
        md.push_str(&format!("{}\n", det.profiles_line));
        for d in &det.clips {
            md.push_str(&format!(
                "{}: {}\n",
                display_clip(&d.key),
                d.class.line()
            ));
        }
        md.push_str("clip\trows\tok\n");
        for b in &r.clips {
            md.push_str(&format!("{}\t{}\t{}\n", display_clip(&b.clip), b.total, b.ok));
        }
        if r.dirty_count() > 0 {
            md.push('\n');
            for line in r.fail_lines() {
                md.push_str(&format!("{line}\n"));
            }
        }
        md.push_str(&format!("\n{}\n", r.verdict_line()));
    }
    let path = output.join(RUN_REPORT_NAME);
    std::fs::write(&path, md)
        .with_context(|| format!("write the run report {}", path.display()))?;
    written.push(path);

    Ok(written)
}

/// The `audit` verb's report surface: the verdict
/// line of every report present in `input` (top level, sorted by
/// name — the discovery convention of the sidecars). Additive
/// output: the lines are the record's echo (the encode-time gate is
/// the verdict's authority); a present-but-corrupt record (no
/// `verdict:` line) is named, not skipped. `Vec` (not `Result`) — the
/// audit caller prints them; rc is untouched by this surface.
pub fn audit_report_lines(input: &Path) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(input) {
        for e in rd.flatten() {
            if !e.path().is_file() {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            if name == RUN_REPORT_NAME
                || name.ends_with(".frameprism-report.md")
            {
                names.push(name);
            }
        }
    }
    names.sort();
    let mut lines = Vec::new();
    for name in &names {
        let text = match std::fs::read_to_string(input.join(name)) {
            Ok(t) => t,
            Err(err) => {
                lines.push(format!(
                    "report: {name} — (unreadable: {err} — the record is corrupt?)"
                ));
                continue;
            }
        };
        match text.lines().find(|l| l.starts_with("verdict: ")) {
            Some(v) => lines.push(format!("report: {name} — {}", v.trim_start_matches("verdict: "))),
            None => lines.push(format!(
                "report: {name} — (no verdict line — the record is corrupt?)"
            )),
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offload::{OffloadReport, OffloadRow, Verdict};
    use crate::worker::{FrameStats, Smpte12m};

    /// Build a PASS IngestGateReport over a synthetic 2-clip tree
    /// (the synth discipline: real minimal files on disk — the
    /// gate reads them) + the (frames, outcomes) pairs.
    fn synth_run(base: &Path) -> (
        IngestGateReport,
        Vec<(PathBuf, PathBuf)>,
        Vec<Outcome>,
    ) {
        let input = base.join("in");
        std::fs::create_dir_all(input.join("A001_001")).unwrap();
        std::fs::create_dir_all(input.join("A001_002")).unwrap();
        let tc = |f: u8| Smpte12m {
            hh: 22,
            mm: 0,
            ss: 0,
            ff: f,
        };
        // The synth: a minimal LE TIFF with tag 51043 (the
        // gate needs it; the report's metadata read of the first
        // frame tolerates the rest being absent — the fixed-empty
        // columns).
        fn synth_frame(tc: &Smpte12m) -> Vec<u8> {
            // header (8) + IFD0 (2 + 12) + the 8-byte value
            let mut b = Vec::new();
            b.extend_from_slice(b"II*\0");
            b.extend_from_slice(&8u32.to_le_bytes());
            let n: u16 = 1;
            b.extend_from_slice(&n.to_le_bytes());
            b.extend_from_slice(&51043u16.to_le_bytes());
            b.extend_from_slice(&1u16.to_le_bytes()); // BYTE
            b.extend_from_slice(&8u32.to_le_bytes());
            // header(8) + count(2) + entry(12) + next-IFD(4) = the
            // value sits at 26.
            let val_off: u32 = 8 + 2 + 12 + 4;
            b.extend_from_slice(&val_off.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes()); // next IFD
            let payload: [u8; 4] = [
                crate::worker::bcd16(tc.ff),
                crate::worker::bcd16(tc.ss),
                crate::worker::bcd16(tc.mm),
                crate::worker::bcd16(tc.hh),
            ];
            b.extend_from_slice(&payload);
            b.extend_from_slice(&[0u8; 4]);
            b
        }
        let files: Vec<(&str, Smpte12m)> = vec![
            ("A001_001/A001_001_20260914_000001.DNG", tc(0)),
            ("A001_001/A001_001_20260914_000002.DNG", tc(1)),
            ("A001_002/A001_002_20260914_000001.DNG", tc(2)),
        ];
        let mut paths: Vec<PathBuf> = Vec::new();
        for (rel, t) in &files {
            let p = input.join(rel);
            std::fs::write(&p, synth_frame(t)).unwrap();
            paths.push(p);
        }
        let gate = crate::worker::ingest_gate(&input, &paths);
        assert!(gate.is_pass(), "{:?}", gate.failures());
        let frames: Vec<(PathBuf, PathBuf)> = paths
            .iter()
            .map(|p| (p.clone(), base.join("out").join(p.file_name().unwrap())))
            .collect();
        let outcomes: Vec<Outcome> = frames
            .iter()
            .map(|_| {
                Outcome::Done(FrameStats {
                    file: "x".into(),
                    in_bytes: 1000,
                    out_bytes: 400,
                    ratio: 2.5,
                    ms: 1.0,
                    log10: None,
                    lossy: None,
                    quality: None,
                    reference_dct: None,
                })
            })
            .collect();
        (gate, frames, outcomes)
    }

    fn clean_offload() -> OffloadReport {
        OffloadReport {
            input: PathBuf::from("/in"),
            dest: PathBuf::from("/dest"),
            rows: vec![OffloadRow {
                file: "a.DNG".into(),
                size: 1,
                source_sha: "s".into(),
                dest_sha: "s".into(),
                verdict: Verdict::Ok,
                detail: String::new(),
            }],
            clips: vec![],
        }
    }

    #[test]
    fn reports_per_clip_deterministic_and_run_has_one_created() {
        let base = std::env::temp_dir().join("frameprism_report_test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("out")).unwrap();
        let (gate, frames, outcomes) = synth_run(&base);
        let p1 = write_reports(
            &base.join("out"),
            &base.join("in"),
            "j92",
            jpeg_turbo_build(),
            &gate,
            &frames,
            &outcomes,
            Some(&clean_offload()),
            Some(&base.join("out").join("X.checksums.tsv")),
        )
        .unwrap();
        // 2 per-clip + 1 run = 3 paths.
        assert_eq!(p1.len(), 3);
        let c1 = base.join("out").join("A001_001.frameprism-report.md");
        let c2 = base.join("out").join("A001_002.frameprism-report.md");
        let run = base.join("out").join(RUN_REPORT_NAME);
        assert!(c1.is_file() && c2.is_file() && run.is_file());
        let t1 = std::fs::read_to_string(&c1).unwrap();
        assert!(!t1.contains("created:"), "per-clip: no wall clock");
        assert!(t1.contains("verdict: ingest-gate PASS (2 frame(s)"));
        assert!(t1.contains("TC range: 22:00:00:00..22:00:00:01"));
        assert!(t1.contains("source raw: 2000 B (2 frame(s))"));
        assert!(t1.contains("encoded: 800 B (2.50:1)"));
        // The fixed-empty metadata columns (the synth frames carry no
        // 51044/ExifIFD — absent, not invented).
        assert!(t1.contains("framerate: absent (tag 51044 not in the DNG header)"));
        assert!(t1
            .contains("exposure: absent (tag 34853 not in the DNG header — the fixed empty sidecar column)"));
        // The run report: EXACTLY one created: line + the offload line
        // in the exact format + the verdict.
        let tr = std::fs::read_to_string(&run).unwrap();
        let created = tr.lines().filter(|l| l.starts_with("created:")).count();
        assert_eq!(created, 1, "exactly one created: line:\n{tr}");
        assert!(tr.contains("offload: VERIFIED 1/1 (dest /dest)"));
        assert!(tr.contains("verdict: run OK — 2 clip(s), 3 frame(s), offload VERIFIED 1/1"));
        // Determinism: the per-clip report is a pure function of the
        // inputs (re-write → byte-identical).
        let p2 = write_reports(
            &base.join("out"),
            &base.join("in"),
            "j92",
            jpeg_turbo_build(),
            &gate,
            &frames,
            &outcomes,
            Some(&clean_offload()),
            Some(&base.join("out").join("X.checksums.tsv")),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(&c1).unwrap(),
            std::fs::read(&p2[0]).unwrap(),
            "per-clip report byte-identical on re-write"
        );
        // The audit surface: the verdict lines, one per report.
        let lines = audit_report_lines(&base.join("out"));
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines.iter().all(|l| l.starts_with("report: ")));
        assert!(lines
            .iter()
            .any(|l| l.contains("run OK — 2 clip(s), 3 frame(s), offload VERIFIED 1/1")));
        // No offload: the verdict has no offload clause.
        let p3 = write_reports(
            &base.join("out"),
            &base.join("in"),
            "j92",
            jpeg_turbo_build(),
            &gate,
            &frames,
            &outcomes,
            None,
            None,
        )
        .unwrap();
        let tr3 = std::fs::read_to_string(&p3[2]).unwrap();
        assert!(tr3.contains("verdict: run OK — 2 clip(s), 3 frame(s)\n"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn reports_carry_the_a2_eta_and_the_a1_pins_block() {
        let base = std::env::temp_dir().join("frameprism_report_pins_test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("out")).unwrap();
        let (gate, frames, outcomes) = synth_run(&base);
        // A1: record the resolved pin state (the run report's A1 block
        // reads it — the single CLI process sets it once before the run).
        crate::pins::set_current(crate::pins::PinReport {
            path: Some(base.join("ci/pins.tsv")),
            probed: vec![],
            states: vec![crate::pins::PinState {
                component: "cjxl/djxl".into(),
                expected: "v0.12.0 1cad73c".into(),
                found: "cjxl ok | djxl ok".into(),
                ok: true,
                skip_note: None,
            }],
            note: None,
        });
        let p = write_reports(
            &base.join("out"),
            &base.join("in"),
            "j92",
            jpeg_turbo_build(),
            &gate,
            &frames,
            &outcomes,
            None,
            None,
        )
        .unwrap();
        let clip = base.join("out").join("A001_001.frameprism-report.md");
        let run = base.join("out").join(RUN_REPORT_NAME);
        let tc = std::fs::read_to_string(&clip).unwrap();
        // A2: the per-clip ETA line (deterministic — the frame count +
        // the rate; no wall clock, holds).
        assert!(
            tc.contains("eta: ~ 0.0 min for 2 frame(s) at 405 ms/frame (measured corpus rate, not a guarantee)"),
            "{tc}"
        );
        assert!(!tc.contains("created:"), "per-clip: no wall clock");
        let tr = std::fs::read_to_string(&run).unwrap();
        // A2: the total ETA line (3 frames across the 2 clips).
        assert!(
            tr.contains("eta: ~ 0.0 min for 3 frame(s) at 405 ms/frame (measured corpus rate, not a guarantee)"),
            "{tr}"
        );
        // A1: the pin block in the run report's tool/versions block
        // (every report says what pins were enforced on its bytes).
        assert!(tr.contains("pins: "), "{tr}");
        assert!(
            tr.contains("  cjxl/djxl: OK — expected v0.12.0 1cad73c — found cjxl ok | djxl ok"),
            "{tr}"
        );
        assert_eq!(
            tr.lines().filter(|l| l.starts_with("created:")).count(),
            1,
            "the A1 block adds no wall-clock line: {tr}"
        );
        let _ = std::fs::remove_dir_all(&base);
        let _ = p;
    }

    #[test]
    fn report_names_a_refuse_offload() {
        let base = std::env::temp_dir().join("frameprism_report_refuse_test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("out")).unwrap();
        let (gate, frames, outcomes) = synth_run(&base);
        let mut off = clean_offload();
        off.rows.push(OffloadRow {
            file: "b.DNG".into(),
            size: 1,
            source_sha: "s".into(),
            dest_sha: "-".into(),
            verdict: Verdict::CopyFail,
            detail: "no space left".into(),
        });
        let p = write_reports(
            &base.join("out"),
            &base.join("in"),
            "j92",
            jpeg_turbo_build(),
            &gate,
            &frames,
            &outcomes,
            Some(&off),
            None,
        )
        .unwrap();
        let tr = std::fs::read_to_string(&p[2]).unwrap();
        assert!(tr.contains("offload: REFUSE 1 named row(s) (dest /dest)"));
        assert!(tr.contains("offload REFUSE 1 named row(s)"));
        let _ = std::fs::remove_dir_all(&base);
    }

    ///: the member record arc — the input carries a non-DNG
    /// member (the WAV) + the tool's own records are excluded (the
    /// degenerate in-place case); the record is written for the clip
    /// with members, the parse roundtrips, and the re-verify is clean
    /// on the tree the record lives in (path-independent: the rows are
    /// clip-relative, the record sits next to the clip dir).
    #[test]
    fn members_record_written_parsed_and_reverified() {
        let base = std::env::temp_dir().join(format!("frameprism_members_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("out")).unwrap();
        let (gate, frames, outcomes) = synth_run(&base);
        // The member: a non-DNG file of clip A001_001 (the input side)
        // + its output copy (the encode carries non-DNG files through,
        // the collect discipline).
        let wav_in = base.join("in/A001_001/A001_001_20260701.WAV");
        let wav_out = base.join("out/A001_001/A001_001_20260701.WAV");
        std::fs::create_dir_all(base.join("out/A001_001")).unwrap();
        std::fs::write(&wav_in, b"wav-bytes").unwrap();
        std::fs::write(&wav_out, b"wav-bytes").unwrap();
        // A clip WITHOUT members (A001_002) → no record, the honest
        // none line.
        let p = write_reports(
            &base.join("out"),
            &base.join("in"),
            "j92",
            jpeg_turbo_build(),
            &gate,
            &frames,
            &outcomes,
            None,
            None,
        )
        .unwrap();
        // The record: present for the clip with the member, absent for
        // the member-less clip.
        let rec = base.join("out/A001_001.members.tsv");
        assert!(rec.is_file(), "the member record is written for the clip with members");
        assert!(!base.join("out/A001_002.members.tsv").is_file(), "no record for the member-less clip");
        let text = std::fs::read_to_string(&rec).unwrap();
        assert!(text.contains("clip: A001_001"));
        assert!(text.contains("A001_001_20260701.WAV\t9\t"), "the row: clip-relative file + size 9 (the wav-bytes content)");
        assert!(text.contains("OK"));
        assert!(text.contains("verdict: OK 1/1"));
        // The per-clip report carries the members section + the sha.
        let clip = std::fs::read_to_string(base.join("out/A001_001.frameprism-report.md")).unwrap();
        assert!(clip.contains("## members — the non-frame files (stored as-is)"));
        assert!(clip.contains("A001_001_20260701.WAV"));
        assert!(clip.contains("members verdict: OK 1/1"));
        // The parse roundtrip (the audit's parse surface).
        let m = parse_members_record(&rec).unwrap();
        assert_eq!(m.clip, "A001_001");
        assert_eq!(m.rows.len(), 1);
        assert_eq!(m.rows[0].file, "A001_001_20260701.WAV");
        assert_eq!(m.rows[0].size, 9);
        assert_eq!(m.rows[0].verdict, "OK");
        // The re-verify: clean on the tree the record lives in.
        let (lines, bad) = reverify_members(&m, &base.join("out"));
        assert_eq!(bad, 0, "{lines:?}");
        assert_eq!(lines, vec!["audit: members 1/1 file(s) OK (A001_001)"], "{lines:?}");
        // The re-verify is PATH-INDEPENDENT (the SURVIVE A MOVE arc):
        // move the whole tree → the same record still verifies.
        let moved = base.join("out_moved");
        std::fs::rename(&base.join("out"), &moved).unwrap();
        let (lines, bad) = reverify_members(&m, &moved);
        assert_eq!(bad, 0, "the record survives a move of the tree: {lines:?}");
        // The TAMPER arc: a 1-byte flip → the named offender (rc=1
        // contribution), the row named with the recorded vs on-disk
        // sha.
        let tampered = moved.join("A001_001/A001_001_20260701.WAV");
        let mut b = std::fs::read(&tampered).unwrap();
        b[0] ^= 0xFF;
        std::fs::write(&tampered, b).unwrap();
        let (lines, bad) = reverify_members(&m, &moved);
        assert_eq!(bad, 1, "the tampered member is the named offender: {lines:?}");
        assert!(lines[0].starts_with("FAIL member A001_001/A001_001_20260701.WAV: SHA_MISMATCH"), "{lines:?}");
        assert!(lines[1].contains("audit: members 0/1 file(s) OK"), "{lines:?}");
        // A corrupt record → the loud parse Err (the audit's rc=2
        // class).
        let corrupt = base.join("corrupt.members.tsv");
        std::fs::write(&corrupt, "not a record\n").unwrap();
        assert!(parse_members_record(&corrupt).is_err(), "a non-record file is the loud parse error");
        let _ = std::fs::remove_dir_all(&base);
    }

    ///: the per-clip report's QC section — the jxl path renders
    /// the named absent line (the deterministic QC class rides the
    /// j92 decode site — out of scope in v1), the j92 path without a
    /// recorded run state renders the honest absent line (never a
    /// silent omission, never invented stats).
    #[test]
    fn qc_section_rendering_by_path() {
        let base = std::env::temp_dir().join(format!("frameprism_qc_report_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("out")).unwrap();
        let (gate, frames, outcomes) = synth_run(&base);
        // The jxl path: the named absent line (the state is never set
        // here — the codec guard is what renders the line).
        let p = write_reports(
            &base.join("out"),
            &base.join("in"),
            "jxl",
            "cjxl 0.12.0",
            &gate,
            &frames,
            &outcomes,
            None,
            None,
        )
        .unwrap();
        let clip = std::fs::read_to_string(base.join("out/A001_001.frameprism-report.md")).unwrap();
        assert!(
            clip.contains("qc: absent (the deterministic QC class rides the j92 decode site — the jxl path is out of scope in v1; a --codec both run carries it in the j92 tier)"),
            "{clip}"
        );
        let run = std::fs::read_to_string(&p[2]).unwrap();
        assert!(run.contains("qc: absent (the deterministic QC class rides the j92 decode site — the jxl path is out of scope in v1; a --codec both run carries it in the j92 tier)"), "{run}");
        // The j92 path: the QC surface is ALWAYS present — the exact
        // line depends on the run's recorded state (a process-wide
        // OnceLock the encode path sets — test-order dependent), so
        // the arc assertion is the surface's PRESENCE + the 
        // contract (no second created: line), not the state's text.
        let p = write_reports(
            &base.join("out"),
            &base.join("in"),
            "j92",
            jpeg_turbo_build(),
            &gate,
            &frames,
            &outcomes,
            None,
            None,
        )
        .unwrap();
        let clip = std::fs::read_to_string(base.join("out/A001_001.frameprism-report.md")).unwrap();
        let has_qc_section = clip.contains("## qc — the deterministic class")
            || clip.lines().any(|l| l.starts_with("qc: "));
        assert!(has_qc_section, "the j92 per-clip report always carries the QC surface:\n{clip}");
        let run = std::fs::read_to_string(&p[2]).unwrap();
        // The run report's qc line is present (the j92 path) + no
        // second created: line (the contract holds).
        assert!(
            run.lines().any(|l| l.starts_with("qc: ")), "the j92 run report carries the qc line:\n{run}"
        );
        assert_eq!(run.lines().filter(|l| l.starts_with("created:")).count(), 1, "{run}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn lane4_named_subset_line_present_iff_the_flag() {
        // The per-clip report carries the named line EXACTLY
        // when the gate ran under the NAMED subset opt-in (the
        // honesty property — the same string the ledger's v3 context
        // column carries; byte-stable, no wall clock, no path).
        let base = std::env::temp_dir().join(format!("frameprism_report_lane4_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("out")).unwrap();
        let (mut gate, frames, outcomes) = synth_run(&base);
        // Default (the flag absent): the line is ABSENT.
        gate.subset = false;
        let p1 = write_reports(
            &base.join("out"),
            &base.join("in"),
            "j92",
            jpeg_turbo_build(),
            &gate,
            &frames,
            &outcomes,
            None,
            None,
        )
        .unwrap();
        let t1 = std::fs::read_to_string(&p1[0]).unwrap();
        assert!(
            !t1.contains(crate::worker::SUBSET_MARKER),
            "default path: the named line is absent:\n{t1}"
        );
        // The flag active: the line is PRESENT — verbatim, right after
        // the verdict line, on EVERY per-clip report.
        gate.subset = true;
        let p2 = write_reports(
            &base.join("out"),
            &base.join("in"),
            "j92",
            jpeg_turbo_build(),
            &gate,
            &frames,
            &outcomes,
            None,
            None,
        )
        .unwrap();
        for p in &p2 {
            let t = std::fs::read_to_string(p).unwrap();
            if p.file_name().map(|f| f == RUN_REPORT_NAME).unwrap_or(false) {
                continue; // the run report is not a per-clip report
            }
            let lines: Vec<&str> = t.lines().collect();
            let marker_idx = lines
                .iter()
                .position(|l| l == &crate::worker::SUBSET_MARKER)
                .expect("the exact named line, verbatim");
            assert!(
                lines[marker_idx - 1].starts_with("verdict: ingest-gate PASS"),
                "the named line rides right after the verdict line:\n{t}"
            );
        }
        // The marker is the shared constant (report + ledger use the
        // SAME string — the byte-stable marker).
        assert_eq!(
            crate::worker::SUBSET_MARKER,
            "ingest-gate: subset (continuity waived — re-verify)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    //: the exFAT destination note — the ABSENT half (G3: the
    // report stays byte-identical to the pre-note shape on APFS; the
    // existing pinned run-report assertions above are that proof —
    // this is the explicit absence assertion).

    #[test]
    fn spec7_run_report_carries_no_exfat_note_on_the_gate_host_volume() {
        let base = std::env::temp_dir().join(format!("frameprism-spec7-report-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("out")).unwrap();
        let (gate, frames, outcomes) = synth_run(&base);
        write_reports(
            &base.join("out"),
            &base.join("in"),
            "j92",
            jpeg_turbo_build(),
            &gate,
            &frames,
            &outcomes,
            None,
            None,
        )
        .unwrap();
        let tr = std::fs::read_to_string(base.join("out").join(RUN_REPORT_NAME)).unwrap();
        assert!(
            !tr.contains("note: destination volume"),
            "the exFAT note line is ABSENT on the gate host's tmp volume (APFS — the report is byte-identical to the pre-note shape):\n{tr}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    ///: the offload dispatch on the encode surface (the additive
    /// half): with `--to` (offload = Some) the run + the per-clip
    /// reports gain the `## offload` section — the per-clip
    /// detection lines (the scanner's line format verbatim — the
    /// synth frames carry no identity: `unprofiled camera - -`, the
    /// no-value token, stable across the profile-set state), the
    /// per-clip blocks (the ClipBlocks), and the verdict line (the
    /// existing format verbatim). Without `--to` (offload = None) the
    /// section is ABSENT (C1: the reports are byte-identical to the
    /// pre-dispatch shape) and the per-clip reports gain no wall
    /// clock (C4) while the run report keeps exactly ONE created:
    /// line.
    #[test]
    fn reports_offload_section_additive_and_absent_without_to() {
        let base = std::env::temp_dir().join(format!("frameprism_report_offload_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("out")).unwrap();
        let (gate, frames, outcomes) = synth_run(&base);
        // The offload report over the synth tree (the clip blocks
        // match the synth clip keys — the manifest's block order).
        let mut off = clean_offload();
        off.clips = vec![
            crate::offload::ClipBlock {
                clip: "A001_001".into(),
                total: 2,
                ok: 2,
            },
            crate::offload::ClipBlock {
                clip: "A001_002".into(),
                total: 1,
                ok: 1,
            },
        ];
        let p = write_reports(
            &base.join("out"),
            &base.join("in"),
            "j92",
            jpeg_turbo_build(),
            &gate,
            &frames,
            &outcomes,
            Some(&off),
            None,
        )
        .unwrap();
        let run = base.join("out").join(RUN_REPORT_NAME);
        let tr = std::fs::read_to_string(&run).unwrap();
        // The run report's `## offload` section (the additive half):
        // the per-clip detection lines + the per-clip blocks + the
        // verdict line (the existing format verbatim).
        assert!(tr.contains("## offload — the --to mirror (the verify-before-wipe gate)"), "{tr}");
        assert!(tr.contains("A001_001: unprofiled camera - -"), "{tr}");
        assert!(tr.contains("A001_002: unprofiled camera - -"), "{tr}");
        assert!(tr.contains("clip\trows\tok"), "{tr}");
        assert!(tr.contains("A001_001\t2\t2"), "{tr}");
        assert!(tr.contains("A001_002\t1\t1"), "{tr}");
        assert!(tr.contains("offload: VERIFIED 1/1 (dest /dest)"), "{tr}");
        // The clean run: no FAIL lines (the dirty-only idiom).
        assert!(!tr.contains("FAIL "), "clean offload: no FAIL lines:\n{tr}");
        // C4: the section adds no wall clock — the run report keeps
        // exactly ONE created: line.
        assert_eq!(tr.lines().filter(|l| l.starts_with("created:")).count(), 1, "{tr}");
        // The per-clip reports: the section with the clip's own
        // detection line + the clip's block numbers (the manifest's
        // per-clip verdict-block idiom), no wall clock (C4).
        for (name, block) in [
            ("A001_001.frameprism-report.md", "files: 2 ok: 2 dirty: 0"),
            ("A001_002.frameprism-report.md", "files: 1 ok: 1 dirty: 0"),
        ] {
            let t = std::fs::read_to_string(base.join("out").join(name)).unwrap();
            assert!(t.contains("## offload — the --to mirror (the verify-before-wipe gate)"), "{t}");
            assert!(t.contains("detection: unprofiled camera - -"), "{t}");
            assert!(t.contains(block), "{t}");
            assert!(!t.contains("created:"), "per-clip: no wall clock (C4):\n{t}");
        }
        // C1: without `--to` the section is ABSENT (byte-identical to
        // the pre-dispatch shape — no offload content at all).
        let p2 = write_reports(
            &base.join("out"),
            &base.join("in"),
            "j92",
            jpeg_turbo_build(),
            &gate,
            &frames,
            &outcomes,
            None,
            None,
        )
        .unwrap();
        let tr2 = std::fs::read_to_string(&p2[2]).unwrap();
        assert!(!tr2.contains("## offload"), "without --to: no offload section:\n{tr2}");
        assert!(!tr2.contains("offload:"), "without --to: no offload line:\n{tr2}");
        for name in ["A001_001.frameprism-report.md", "A001_002.frameprism-report.md"] {
            let t = std::fs::read_to_string(base.join("out").join(name)).unwrap();
            assert!(!t.contains("## offload"), "without --to: the per-clip section is absent:\n{t}");
            assert!(!t.contains("detection:"), "without --to: no detection line:\n{t}");
        }
        let _ = std::fs::remove_dir_all(&base);
        let _ = p;
    }

    ///: the offload dispatch's dirty-run + third-class arc: the FAIL
    /// lines ride the run report's `## offload` section verbatim (the
    /// existing `fail_lines()` format — the same bytes stderr gets),
    /// the clip's block numbers carry the dirty count (files / ok /
    /// dirty), and the sidecar-only clip's detection line is the
    /// scanner's third class (`non-DNG media` — the report, not a
    /// gate: the offload copies + verifies any tree).
    #[test]
    fn reports_offload_section_dirty_lines_and_the_nondng_class() {
        let base = std::env::temp_dir().join(format!("frameprism_report_offload_dirty_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("out")).unwrap();
        let (gate, frames, outcomes) = synth_run(&base);
        // The third class: a sidecar-only clip (no DNG frames — the
        // detection scan's `non-DNG media`; not in the gate's clip
        // set — the per-clip reports are the encoded clips').
        let sidecar_clip = base.join("in/A001_003");
        std::fs::create_dir_all(&sidecar_clip).unwrap();
        std::fs::write(sidecar_clip.join("A001_003_20260701.WAV"), b"wav-bytes").unwrap();
        // The dirty offload: one COPY_FAIL row of clip A001_001 + the
        // per-clip blocks (the dirty clip: 2 rows, 1 ok).
        let mut off = clean_offload();
        off.rows.push(OffloadRow {
            file: "A001_001/f1.DNG".into(),
            size: 1,
            source_sha: "s".into(),
            dest_sha: "-".into(),
            verdict: Verdict::CopyFail,
            detail: "no space left".into(),
        });
        off.clips = vec![
            crate::offload::ClipBlock {
                clip: "A001_001".into(),
                total: 2,
                ok: 1,
            },
            crate::offload::ClipBlock {
                clip: "A001_002".into(),
                total: 1,
                ok: 1,
            },
        ];
        let p = write_reports(
            &base.join("out"),
            &base.join("in"),
            "j92",
            jpeg_turbo_build(),
            &gate,
            &frames,
            &outcomes,
            Some(&off),
            None,
        )
        .unwrap();
        let tr = std::fs::read_to_string(&p[2]).unwrap();
        // The section: the third-class detection line (verbatim), the
        // FAIL line (the existing format verbatim — the same bytes
        // stderr gets), the verdict line (the REFUSE format).
        assert!(tr.contains("## offload — the --to mirror (the verify-before-wipe gate)"), "{tr}");
        assert!(tr.contains("A001_003: non-DNG media"), "{tr}");
        assert!(tr.contains("FAIL COPY_FAIL clip=A001_001: A001_001/f1.DNG: no space left"), "{tr}");
        assert!(tr.contains("offload: REFUSE 1 named row(s) (dest /dest)"), "{tr}");
        assert_eq!(tr.lines().filter(|l| l.starts_with("created:")).count(), 1, "{tr}");
        // The dirty clip's per-clip report carries the block numbers
        // with the dirty count.
        let t = std::fs::read_to_string(base.join("out/A001_001.frameprism-report.md")).unwrap();
        assert!(t.contains("files: 2 ok: 1 dirty: 1"), "{t}");
        assert!(!t.contains("created:"), "per-clip: no wall clock (C4):\n{t}");
        let _ = std::fs::remove_dir_all(&base);
    }
}
