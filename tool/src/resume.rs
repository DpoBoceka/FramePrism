//! `--resume`: the verified-skip plan.
//!
//!: resume is a MANIFEST DIFF, never a process-state machine. The
//! per-frame skip decision (ALL must hold to skip):
//!
//!   (1) the output frame file exists;
//!   (2) a sidecar row for the frame exists in the output's
//!       `<CLIP>.checksums.tsv` AND its sha256 verifies over the on-disk
//!       output file (RE-HASHED — the verification cost is the design;
//!       the skip is never trusted from the row alone);
//!   (3) if the input carries the source-sha manifest (an
//!       `*.offload-manifest.tsv` at the input root — the
//!       `file → source_sha256` rows), the source frame's sha256 (re-
//!       hashed) matches the row for that source file.
//!
//! A frame that fails ANY check re-encodes. The re-encode is the
//! repair path (a missing frame, a corrupted output frame, a source
//! that changed on the card) — the final sidecar is byte-identical to
//! the uninterrupted run's (the /incremental write, worker.rs).
//!
//! Torn-row rules: a SIGTERM mid-append can leave the sidecar's
//! last line incomplete. A torn LAST line (the file lacks its trailing
//! newline and the final line fails the row parse) = a named discard —
//! that frame re-encodes (the row is unusable, the frame is safe to
//! redo); a failed parse ANYWHERE ELSE = a named hard error (rc=2
//! before the first frame/byte — the sidecar is corrupt, the loud
//! class). Rows for files outside the current frame set (a different
//! selection, an older input) are STALE: a named count, excluded from
//! the final sidecar. No sidecar at all = nothing is verified, every
//! frame re-encodes (the named note — resume without a sidecar is a
//! full re-encode, never a wrong skip).
//!
//! `scan` also cleans the interrupted run's leftover temp files in the
//! output tree (the temp + rename writes — a killed frame leaves
//! its `.dng.tmp`, a killed sidecar copy its `.sidecar.tmp`, a killed
//! ingest-manifest write its `.ingest-manifest.tsv.tmp`; the final
//! atomic rename never completed, so no partial product file exists) —
//! the cleanup is a named count line.
//!
//! The plan is process-global (the pins.rs / selection.rs OnceLock
//! convention): `worker::process_dir` scans and registers it; the run
//! report renders the `resumed:` line from `current()`.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static CURRENT: OnceLock<Option<Plan>> = OnceLock::new();

/// The run's `--resume` flag (main, before the encode — the scan
/// gate in `process_dir`).
static FLAG: OnceLock<bool> = OnceLock::new();

/// One parsed sidecar row (v2: 4 columns — the metadata columns are
/// the fixed empty strings; v3: the 4 contract columns + the 4
/// camera-metadata columns).
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub file: String,
    pub size: u64,
    pub crc: u32,
    pub sha: String,
    /// (timecode, framerate, iso, exposure) — the v3 columns, pre-
    /// formatted (the `write_sidecar` shape; v2 rows = all empty).
    pub meta: [String; 4],
}

/// The run's verified-skip plan .
#[derive(Clone, Debug, Default)]
pub struct Plan {
    /// rel (POSIX, output-relative) → the verified row (its sha was
    /// re-checked against the on-disk output at scan time).
    pub skip: BTreeMap<String, Row>,
    /// The named lines (torn tail / stale rows / temp cleanup / no
    /// sidecar / source manifest) — the run report's `resumed note:`
    /// lines.
    pub notes: Vec<String>,
    /// The input carried the source-sha manifest ((3) was
    /// ACTIVE for this scan).
    pub source_sha_present: bool,
}

impl Plan {
    /// The skip count (the report's `resumed: K of N`).
    pub fn skipped(&self) -> usize {
        self.skip.len()
    }
}

/// Register the run's plan process-wide (called ONCE by
/// `worker::process_dir` after the scan — `None` for a non-resume run,
/// so the report's `resumed:` line renders the zero form).
pub fn set_current(plan: Option<Plan>) {
    let _ = CURRENT.set(plan);
}

/// The run's plan (None = no `--resume` — the report renders
/// `resumed: 0 of N`).
pub fn current() -> Option<&'static Plan> {
    CURRENT.get().and_then(|p| p.as_ref())
}

/// Whether this run was started with `--resume` (set ONCE by `main`
/// before the encode — the scan gate in `process_dir`).
pub fn flag() -> bool {
    *FLAG.get().unwrap_or(&false)
}

/// Set the run's `--resume` flag (main, before `run()`).
pub fn set_flag(v: bool) {
    let _ = FLAG.set(v);
}

/// The temp-file suffixes a killed encode leaves in the output tree
/// (the temp + rename writers; the rename never completed).
const TEMP_SUFFIXES: &[&str] = &[".dng.tmp", ".sidecar.tmp"];

/// Remove the interrupted run's leftover temp files under `output`
/// (recursive, the collect() symlink discipline) and return the
/// removed names (output-relative, sorted). Best-effort: a removal
/// failure is named on stderr, never an error.
pub fn clean_temp_files(output: &Path) -> Vec<String> {
    let mut removed: Vec<String> = Vec::new();
    let mut visited: HashSet<crate::DirId> = HashSet::new();
    clean_temp_dir(output, output, &mut removed, &mut visited);
    removed.sort();
    removed
}

fn is_temp_name(name: &str) -> bool {
    if name.starts_with('.') && name.ends_with(".ingest-manifest.tsv.tmp") {
        return true;
    }
    // The canonical sidecar rewrite's temp (write_sidecar's temp +
    // rename — /): a dotfile, the clip-qualified name.
    if name.starts_with('.') && name.ends_with(".checksums.tsv.tmp") {
        return true;
    }
    TEMP_SUFFIXES.iter().any(|s| name.ends_with(s))
}

fn clean_temp_dir(
    root: &Path,
    dir: &Path,
    removed: &mut Vec<String>,
    visited: &mut HashSet<crate::DirId>,
) {
    let Ok(id) = crate::dir_id(dir) else {
        return;
    };
    if !visited.insert(id) {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let ft = match entry.file_type() {
            Ok(f) => f,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            clean_temp_dir(root, &p, removed, visited);
            continue;
        }
        if is_temp_name(&name) {
            match std::fs::remove_file(&p) {
                Ok(()) => {
                    let rel = p
                        .strip_prefix(root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .replace('\\', "/");
                    removed.push(rel);
                }
                Err(err) => eprintln!(
                    "resume: note: cannot remove leftover temp {} ({err}) — left in place",
                    p.display()
                ),
            }
        }
    }
}

/// Parse ONE sidecar row (v2: 4 columns, v3: 8). The strict shape —
/// a row that fails here is either the named torn tail (the last line
/// of a killed append) or the loud corrupt-sidecar error (elsewhere).
fn parse_row(line: &str) -> Result<Row, String> {
    let f: Vec<&str> = line.split('\t').collect();
    let (meta, _ncols) = if f.len() == 8 {
        (
            [
                f[4].to_string(),
                f[5].to_string(),
                f[6].to_string(),
                f[7].to_string(),
            ],
            8,
        )
    } else if f.len() == 4 {
        (
            [
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ],
            4
        )
    } else {
        return Err(format!("{} columns (want 4 or 8)", f.len()));
    };
    let size: u64 = f[1]
        .parse()
        .map_err(|_| format!("bad size column {:?}", f[1]))?;
    let crc: u32 = u32::from_str_radix(f[2], 16)
        .ok()
        .filter(|_| f[2].len() == 8)
        .ok_or_else(|| format!("bad crc32c column {:?}", f[2]))?;
    let sha = f[3];
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("bad sha256 column {sha:?}"));
    }
    Ok(Row {
        file: f[0].to_string(),
        size,
        crc,
        sha: sha.to_ascii_lowercase(),
        meta,
    })
}

/// Parse an existing sidecar file into rows. Returns `(rows, torn_tail)`
/// — `torn_tail` = the raw final line of a killed mid-append (discarded
/// and named; its frame re-encodes). A failed parse anywhere else is an
/// Err (the loud class). Stale-row handling is the caller's (it knows
/// the frame set).
/// The parse mode: a v3 file starts with the `#` magic (the header
/// block runs until the V3_COLUMNS line); a v2 file starts with data
/// rows directly (no header — the byte-untouched old shape).
#[derive(PartialEq)]
enum ParseMode {
    Undecided,
    Header,
    Data,
}

fn parse_sidecar(path: &Path) -> Result<(BTreeMap<String, Row>, Option<String>), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("read the sidecar {}: {err}", path.display()))?;
    let mut rows: BTreeMap<String, Row> = BTreeMap::new();
    let mut mode = ParseMode::Undecided;
    let lines: Vec<&str> = content.lines().collect();
    for (idx, line) in lines.iter().copied().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match mode {
            ParseMode::Undecided => {
                if line.starts_with('#') {
                    mode = ParseMode::Header;
                    continue;
                }
                mode = ParseMode::Data;
            }
            ParseMode::Header => {
                if line == crate::checksums::V3_COLUMNS {
                    mode = ParseMode::Data;
                    continue;
                }
                if line.starts_with("version:") && line != "version: 3" {
                    return Err(format!(
                        "unsupported sidecar version in {} line {} ({line:?}) — only v2 (no header) and v3 are accepted",
                        path.display(),
                        idx + 1
                    ));
                }
                // The header key lines (version: / tool_version:).
                continue;
            }
            ParseMode::Data => {}
        }
        let last = idx + 1 == lines.len() && !content.ends_with('\n');
        match parse_row(line) {
            Ok(row) => {
                if rows.contains_key(&row.file) {
                    return Err(format!(
                        "duplicate sidecar row for {} in {} line {}",
                        row.file,
                        path.display(),
                        idx + 1
                    ));
                }
                rows.insert(row.file.clone(), row);
            }
            Err(_why) if last => {
                // The torn tail: a killed mid-append left the
                // final line incomplete — named discard, NOT the loud
                // error (the frame re-encodes; the rest of the file is
                // intact).
                continue;
            }
            Err(why) => {
                return Err(format!(
                    "corrupt sidecar row in {} line {}: {why} — the sidecar is corrupt (the loud class; the run refuses before the first frame/byte)",
                    path.display(),
                    idx + 1
                ));
            }
        }
    }
    // The torn-tail line (if any) for the named note: the file lacks
    // its trailing newline AND the final line fails the row parse.
    let torn = if content.ends_with('\n') || lines.is_empty() {
        None
    } else {
        match parse_row(lines.last().unwrap()) {
            Ok(_) => None, // a final line that PARSES is usable (lenient).
            Err(_) => Some(lines.last().unwrap().to_string()),
        }
    };
    Ok((rows, torn))
}

/// Load the source-sha map from the input root (the
/// `*.offload-manifest.tsv` files — the `file → source_sha256` rows;
/// `file` = the input-relative POSIX path; ALL the manifests at the
/// root are merged — the per-clip layout writes one per
/// clip, so a multi-clip input must not lose the later clips). Absent
/// = None ((3) is inactive — the documented limitation, the named
/// note at scan time).
fn source_sha_map(input: &Path) -> Option<(String, BTreeMap<String, String>)> {
    let Ok(rd) = std::fs::read_dir(input) else {
        return None;
    };
    let mut candidates: Vec<String> = rd
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .ends_with(".offload-manifest.tsv")
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    if candidates.is_empty() {
        return None;
    }
    candidates.sort();
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let mut names: Vec<String> = Vec::new();
    for name in &candidates {
        let path = input.join(name);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        names.push(name.clone());
        for line in content.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            // The row shape: file\tsize\tsource_sha256\tdest_sha256\tverdict
            if f.len() == 5 && f[2].len() == 64 && f[2].chars().all(|c| c.is_ascii_hexdigit()) {
                map.insert(f[0].to_string(), f[2].to_ascii_lowercase());
            }
        }
    }
    if names.is_empty() {
        return None;
    }
    let label = if names.len() == 1 {
        names.into_iter().next().unwrap()
    } else {
        format!("{} — the {} manifest(s) merged", names.join(", "), names.len())
    };
    Some((label, map))
}

/// The verified-skip scan over the run's selected frame set.
/// `clip` = the output clip name (the sidecar's `<CLIP>`). Called
/// BEFORE the first frame/byte (after the ingest gate); a corrupt
/// sidecar is a named hard error (the `resume:` prefix — no ledger
/// row, the pre-run class).
pub fn scan(
    input: &Path,
    output: &Path,
    clip: &str,
    frames: &[(PathBuf, PathBuf)],
) -> Result<Plan, String> {
    let mut plan = Plan::default();

    //: the interrupted run's leftover temps (the named count).
    let cleaned = clean_temp_files(output);
    if !cleaned.is_empty() {
        let shown: Vec<String> = cleaned.iter().take(5).cloned().collect();
        plan.notes.push(format!(
            "cleaned {} leftover temp file(s) from an interrupted run ({}){}",
            cleaned.len(),
            shown.join(", "),
            if cleaned.len() > 5 { " …" } else { "" }
        ));
    }

    // The existing sidecar (absent = nothing verified — the named note).
    let sidecar = output.join(crate::checksums::checksums_name(clip));
    let existing: BTreeMap<String, Row> = if sidecar.exists() {
        let (rows, torn) = parse_sidecar(&sidecar)
            .map_err(|e| format!("resume: {e}"))?;
        if let Some(torn) = torn {
            let preview: String = torn.chars().take(48).collect();
            plan.notes.push(format!(
                "torn sidecar tail ({preview}…) — the incomplete row was discarded; its frame re-encodes (the kill-matrix case)"
            ));
        }
        rows
    } else {
        plan.notes.push(
            "no sidecar in the output — nothing verified, every frame re-encodes (resume without a sidecar is a full re-encode)".into(),
        );
        BTreeMap::new()
    };

    // (3): the source-sha manifest in the input root.
    let source = source_sha_map(input);
    if let Some((name, _)) = &source {
        plan.source_sha_present = true;
        plan.notes.push(format!(
            "source-sha manifest present ({name}) — source-change detection is ACTIVE"
        ));
    } else {
        plan.notes.push(
            "no source-sha manifest in the input — source-change detection is INACTIVE (the documented limitation: a source that changed with the same output sha is undetectable here)".into(),
        );
    }

    // The frame set (selected) — the rel keys the rows must match.
    let frame_rels: HashSet<String> = frames
        .iter()
        .filter_map(|(_, dst)| dst.strip_prefix(output).ok())
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect();
    let stale: Vec<String> = existing
        .keys()
        .filter(|f| !frame_rels.contains(*f))
        .cloned()
        .collect();
    if !stale.is_empty() {
        plan.notes.push(format!(
            "{} stale sidecar row(s) for files outside the current frame set — excluded from the final sidecar ({})",
            stale.len(),
            stale.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                + if stale.len() > 5 { " …" } else { "" }
        ));
    }

    // per frame: (1) dst exists, (2) the row's sha verifies over
    // the on-disk output, (3) the source sha matches the manifest row.
    for (src, dst) in frames {
        let Ok(rel) = dst.strip_prefix(output) else {
            continue;
        };
        let rel_s = rel.to_string_lossy().replace('\\', "/");
        if !dst.exists() {
            continue;
        }
        let Some(row) = existing.get(&rel_s) else {
            continue;
        };
        // The streaming sha (the verify is hash-only); the
        // resume error wording is the pre-existing one.
        let sha = match crate::jxl::sha256_stream_path(dst) {
            Ok(s) => s,
            Err(err) => {
                return Err(format!(
                    "resume: read the output frame {} for the sha verify: {err}",
                    dst.display()
                ));
            }
        };
        if sha != row.sha {
            plan.notes.push(format!(
                "{rel_s} re-encodes (sidecar sha mismatch — the output file differs from the sidecar row)"
            ));
            continue;
        }
        if let Some((src_manifest, map)) = &source {
            if let Ok(src_rel) = src.strip_prefix(input) {
                let src_rel_s = src_rel.to_string_lossy().replace('\\', "/");
                if let Some(expected) = map.get(&src_rel_s) {
                    // The streaming source sha (hash-only);
                    // the resume error wording is the pre-existing one.
                    let src_sha = match crate::jxl::sha256_stream_path(src) {
                        Ok(s) => s,
                        Err(err) => {
                            return Err(format!(
                                "resume: read the source frame {} for the source-sha check: {err}",
                                src.display()
                            ));
                        }
                    };
                    if src_sha != *expected {
                        plan.notes.push(format!(
                            "{rel_s} re-encodes (source changed — the source sha256 differs from the {src_manifest} row)"
                        ));
                        continue;
                    }
                }
            }
        }
        plan.skip.insert(rel_s, row.clone());
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jxl::sha256_hex;

    fn sha_of(b: &[u8]) -> String {
        sha256_hex(b)
    }

    /// A v3 sidecar over `files` (rel → bytes), written to `out/clip.checksums.tsv`.
    fn write_v3(out: &Path, clip: &str, files: &[(&str, &[u8])]) -> PathBuf {
        let mut tsv = String::from(
            "# frameprism checksums sidecar\nversion: 3\ntool_version: 0.4.0\n",
        );
        tsv.push_str(crate::checksums::V3_COLUMNS);
        tsv.push('\n');
        for (rel, bytes) in files {
            tsv.push_str(&format!(
                "{}\t{}\t{:08x}\t{}\t\t\t\t\n",
                rel,
                bytes.len(),
                crate::checksums::crc32c(bytes),
                sha_of(bytes)
            ));
        }
        let p = out.join(format!("{clip}.checksums.tsv"));
        std::fs::write(&p, tsv).unwrap();
        p
    }

    fn tree(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
    }

    #[test]
    fn scan_skips_only_fully_verified_frames() {
        let base = std::env::temp_dir().join(format!("frameprism_resume_scan_{}", std::process::id()));
        let (input, output) = (base.join("in"), base.join("out"));
        tree(&input);
        tree(&output);
        let f1 = b"frame-one-bytes";
        let f2 = b"frame-two-bytes";
        let f3 = b"frame-three-bytes";
        // Sources: flat (the rel = the basename in both trees).
        std::fs::write(input.join("a.DNG"), f1).unwrap();
        std::fs::write(input.join("b.DNG"), f2).unwrap();
        std::fs::write(input.join("c.DNG"), f3).unwrap();
        // Outputs: a + b match the sidecar; c's output is tampered;
        // d's output is missing entirely.
        std::fs::write(output.join("a.DNG"), f1).unwrap();
        std::fs::write(output.join("b.DNG"), f2).unwrap();
        std::fs::write(output.join("c.DNG"), b"tampered-bytes!").unwrap();
        write_v3(&output, "clip", &[("a.DNG", f1), ("b.DNG", f2), ("c.DNG", f3)]);
        let frames = vec![
            (input.join("a.DNG"), output.join("a.DNG")),
            (input.join("b.DNG"), output.join("b.DNG")),
            (input.join("c.DNG"), output.join("c.DNG")),
            (input.join("d.DNG"), output.join("d.DNG")),
        ];
        std::fs::write(input.join("d.DNG"), b"frame-four-bytes").unwrap();
        let plan = scan(&input, &output, "clip", &frames).unwrap();
        assert_eq!(plan.skip.len(), 2, "{plan:?}");
        assert!(plan.skip.contains_key("a.DNG"));
        assert!(plan.skip.contains_key("b.DNG"));
        assert!(plan.notes.iter().any(|n| n.contains("c.DNG re-encodes (sidecar sha mismatch")));
        assert!(!plan.source_sha_present);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn scan_detects_a_changed_source_via_the_offload_manifest() {
        let base = std::env::temp_dir().join(format!("frameprism_resume_src_{}", std::process::id()));
        let (input, output) = (base.join("shoot"), base.join("out"));
        tree(&input.join("A001_001"));
        tree(&output.join("A001_001"));
        let f1 = b"clip-frame-one";
        std::fs::write(input.join("A001_001").join("a.DNG"), f1).unwrap();
        std::fs::write(output.join("A001_001").join("a.DNG"), f1).unwrap();
        // The manifest at the input root: file = the input-
        // relative POSIX path; the row's source sha = the ORIGINAL
        // bytes — the source on disk is now flipped (the G1(h) case).
        let original = b"clip-frame-one-orig";
        std::fs::write(
            input.join("clip.offload-manifest.tsv"),
            format!(
                "# frameprism offload manifest\nversion: 1\nclip: clip\nfile\tsize\tsource_sha256\tdest_sha256\tverdict\nA001_001/a.DNG\t{}\t{}\t{}\tOK\n",
                original.len(),
                sha_of(original),
                sha_of(original)
            ),
        )
        .unwrap();
        write_v3(
            &output,
            "clip",
            &[("A001_001/a.DNG", f1)],
        );
        let frames = vec![(
            input.join("A001_001").join("a.DNG"),
            output.join("A001_001").join("a.DNG"),
        )];
        let plan = scan(&input, &output, "clip", &frames).unwrap();
        assert!(plan.source_sha_present, "{plan:?}");
        assert_eq!(plan.skip.len(), 0, "the flipped source must NOT skip: {plan:?}");
        assert!(
            plan.notes
                .iter()
                .any(|n| n.contains("source changed — the source sha256 differs")),
            "{plan:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn scan_torn_tail_is_a_named_discard_not_an_error() {
        let base = std::env::temp_dir().join(format!("frameprism_resume_torn_{}", std::process::id()));
        let (input, output) = (base.join("in"), base.join("out"));
        tree(&input);
        tree(&output);
        let f1 = b"frame-one";
        let f2 = b"frame-two";
        std::fs::write(input.join("a.DNG"), f1).unwrap();
        std::fs::write(input.join("b.DNG"), f2).unwrap();
        std::fs::write(output.join("a.DNG"), f1).unwrap();
        std::fs::write(output.join("b.DNG"), f2).unwrap();
        // a complete row for a + a TORN row for b (the killed mid-
        // append: no trailing newline, the sha cut off).
        let mut tsv = String::from(
            "# frameprism checksums sidecar\nversion: 3\ntool_version: 0.4.0\n",
        );
        tsv.push_str(crate::checksums::V3_COLUMNS);
        tsv.push('\n');
        tsv.push_str(&format!(
            "a.DNG\t{}\t{:08x}\t{}\t\t\t\t\n",
            f1.len(),
            crate::checksums::crc32c(f1),
            sha_of(f1)
        ));
        tsv.push_str(&format!("b.DNG\t{}\t{:08x}\t{}", f2.len(), crate::checksums::crc32c(f2), &sha_of(f2)[..20]));
        std::fs::write(output.join("clip.checksums.tsv"), tsv).unwrap();
        let frames = vec![
            (input.join("a.DNG"), output.join("a.DNG")),
            (input.join("b.DNG"), output.join("b.DNG")),
        ];
        let plan = scan(&input, &output, "clip", &frames).unwrap();
        assert_eq!(plan.skip.len(), 1, "{plan:?}");
        assert!(plan.skip.contains_key("a.DNG"));
        assert!(
            plan.notes.iter().any(|n| n.contains("torn sidecar tail")),
            "{plan:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn scan_corrupt_row_away_from_the_tail_is_a_loud_error() {
        let base = std::env::temp_dir().join(format!("frameprism_resume_corrupt_{}", std::process::id()));
        let (input, output) = (base.join("in"), base.join("out"));
        tree(&input);
        tree(&output);
        let f1 = b"frame-one";
        std::fs::write(input.join("a.DNG"), f1).unwrap();
        std::fs::write(output.join("a.DNG"), f1).unwrap();
        let f2 = b"frame-two";
        std::fs::write(input.join("b.DNG"), f2).unwrap();
        std::fs::write(output.join("b.DNG"), f2).unwrap();
        // A bad row in the MIDDLE (a truncated sha) + a valid final
        // line with its newline: the torn-tail leniency must NOT apply.
        let mut tsv = String::from(
            "# frameprism checksums sidecar\nversion: 3\ntool_version: 0.4.0\n",
        );
        tsv.push_str(crate::checksums::V3_COLUMNS);
        tsv.push('\n');
        tsv.push_str("a.DNG\t9\t01234567\tZZ\n"); // corrupt (bad sha)
        tsv.push_str(&format!("b.DNG\t{}\t{:08x}\t{}\t\t\t\t\n", f2.len(), crate::checksums::crc32c(f2), sha_of(f2)));
        std::fs::write(output.join("clip.checksums.tsv"), tsv).unwrap();
        let frames = vec![
            (input.join("a.DNG"), output.join("a.DNG")),
            (input.join("b.DNG"), output.join("b.DNG")),
        ];
        let err = scan(&input, &output, "clip", &frames).unwrap_err();
        assert!(err.starts_with("resume: corrupt sidecar row"), "{err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn scan_v2_sidecar_rows_parse_with_empty_meta() {
        let base = std::env::temp_dir().join(format!("frameprism_resume_v2_{}", std::process::id()));
        let (input, output) = (base.join("in"), base.join("out"));
        tree(&input);
        tree(&output);
        let f1 = b"v2-frame";
        std::fs::write(input.join("a.DNG"), f1).unwrap();
        std::fs::write(output.join("a.DNG"), f1).unwrap();
        std::fs::write(
            output.join("clip.checksums.tsv"),
            format!("a.DNG\t{}\t{:08x}\t{}\n", f1.len(), crate::checksums::crc32c(f1), sha_of(f1)),
        )
        .unwrap();
        let frames = vec![(input.join("a.DNG"), output.join("a.DNG"))];
        let plan = scan(&input, &output, "clip", &frames).unwrap();
        assert_eq!(plan.skip.len(), 1, "{plan:?}");
        let row = &plan.skip["a.DNG"];
        assert_eq!(
            row.meta,
            [String::new(), String::new(), String::new(), String::new()],
            "v2 = the fixed empty meta columns"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn clean_temp_files_removes_only_the_interrupted_run_temps() {
        let base = std::env::temp_dir().join(format!("frameprism_resume_tmp_{}", std::process::id()));
        tree(&base.join("A001_001"));
        std::fs::write(base.join("a.DNG"), b"keep").unwrap();
        std::fs::write(base.join("a.dng.tmp"), b"kill-me").unwrap();
        std::fs::write(base.join("A001_001").join("b.sidecar.tmp"), b"kill-me").unwrap();
        std::fs::write(base.join(".clip.ingest-manifest.tsv.tmp"), b"kill-me").unwrap();
        std::fs::write(base.join("clip.checksums.tsv"), b"keep").unwrap();
        let removed = clean_temp_files(&base);
        assert_eq!(
            removed,
            vec![".clip.ingest-manifest.tsv.tmp", "A001_001/b.sidecar.tmp", "a.dng.tmp"],
            "{removed:?}"
        );
        assert!(base.join("a.DNG").exists());
        assert!(base.join("clip.checksums.tsv").exists());
        let _ = std::fs::remove_dir_all(&base);
    }
}
