//! The offload's per-clip manifests: the
//! `<CLIP>.offload-manifest.tsv` writer + parser (the file, size,
//! source_sha256, dest_sha256, verdict columns + the per-clip verdict
//! blocks; the magic line + the legacy magic's parse-acceptance), the
//! row + the verdict types.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::OffloadReport;

/// The offload manifest suffix (the clip-name prefix is shared with the
/// ingest manifest: `<CLIP>.offload-manifest.tsv`, CLIP =
/// `checksums::clip_name(input)` — the SAME naming as the run-sidecars).
pub const MANIFEST_SUFFIX: &str = ".offload-manifest.tsv";


/// The offload manifest magic line (the bake-manifest-v2 pattern: the
/// magic + additive `key: value` headers + the column line + the rows).
pub const MANIFEST_MAGIC: &str = "# frameprism offload manifest";


/// The per-file verdict (the audit philosophy: every dirty row is
/// named, nothing is skipped silently).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    SizeMismatch,
    ShaMismatch,
    CopyFail,
}


impl Verdict {
    /// The manifest column value (the exact spec names).
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Ok => "OK",
            Verdict::SizeMismatch => "SIZE_MISMATCH",
            Verdict::ShaMismatch => "SHA_MISMATCH",
            Verdict::CopyFail => "COPY_FAIL",
        }
    }
}


/// One offload row (the manifest columns + the named COPY_FAIL /
/// mismatch detail).
#[derive(Clone, Debug)]
pub struct OffloadRow {
    /// The file's path RELATIVE to the source root (POSIX separators;
    /// a top-level file is its basename — the worker `collect`
    /// convention).
    pub file: String,
    /// The source size in bytes (the dest size when the verdict is
    /// `OK`/`SHA_MISMATCH`; the source size for `SIZE_MISMATCH` — the
    /// mismatch itself is in `detail`).
    pub size: u64,
    /// The source sha256 (lowercase 64-hex — the canonical digest the
    /// re-verify checks the dest against).
    pub source_sha: String,
    /// The dest copy's sha256 (`-` when `COPY_FAIL` — no copy to hash).
    pub dest_sha: String,
    pub verdict: Verdict,
    /// `""` when `OK`; the named detail otherwise (the copy error /
    /// the mismatch figures).
    pub detail: String,
}


/// The offload manifest file name for a clip (cf. the ingest manifest
/// naming — `checksums::clip_name` is the shared clip helper).
pub fn offload_manifest_name(clip: &str) -> String {
    format!("{clip}{MANIFEST_SUFFIX}")
}


/// The clip key of an offload row's relpath (the parent dir, "" = the
/// source root — the SAME key space as the ingest manifest: the
/// relpath's parent dir). `pub(crate)` — the camera module's offload
/// detection scan groups the files by this key.
pub(crate) fn clip_key_of_rel(rel: &str) -> String {
    match rel.rfind('/') {
        Some(pos) => rel[..pos].to_string(),
        None => String::new(),
    }
}


/// Write `<output>/<CLIP>.offload-manifest.tsv` (the bake-manifest-v2
/// pattern: the magic + the additive `key: value` headers + the column
/// line + the rows + the per-clip verdict blocks + the verdict line).
/// The `created:` line is the run's wall clock (the manifest is the
/// offload RECORD — the deterministic no-wall-clock contract is the
/// run reports'.
pub(crate) fn write_offload_manifest(
    output: &Path,
    clip: &str,
    report: &OffloadReport,
) -> Result<PathBuf> {
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let host = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    let mut tsv = format!(
        "{MANIFEST_MAGIC}\n\
         version: 1\n\
         clip: {clip}\n\
         created: {created} (unix seconds, UTC)\n\
         input: {}\n\
         dest: {}\n\
         tool_version: {}\n\
         host: {host}\n\
         files: {}\n\
         clips: {}\n\
         file\tsize\tsource_sha256\tdest_sha256\tverdict\n",
        report.input.display(),
        report.dest.display(),
        env!("CARGO_PKG_VERSION"),
        report.rows.len(),
        report.clips.len()
    );
    for r in &report.rows {
        tsv.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            r.file, r.size, r.source_sha, r.dest_sha, r.verdict.as_str()
        ));
    }
    tsv.push_str("# per-clip verdicts\n");
    for c in &report.clips {
        tsv.push_str(&format!(
            "clip: {} files: {} ok: {} dirty: {}\n",
            if c.clip.is_empty() { "(input root)" } else { c.clip.as_str() },
            c.total,
            c.ok,
            c.total - c.ok
        ));
    }
    let dirty = report.dirty_count();
    tsv.push_str(&format!(
        "verdict: {}\n",
        if dirty == 0 {
            format!(
                "VERIFIED {}/{}",
                report.rows.len(),
                report.rows.len()
            )
        } else {
            format!("REFUSE {dirty} named row(s)")
        }
    ));
    let path = output.join(offload_manifest_name(clip));
    let tmp = output.join(format!(".{clip}{MANIFEST_SUFFIX}.tmp"));
    std::fs::write(&tmp, tsv).with_context(|| format!("write {}", tmp.display()))?;
    // The durability seam: the manifest's bytes are
    // filesystem-synchronized before the rename (a sync failure =
    // the named hard-error band — the job fails exactly as a write
    // failure does).
    crate::durability::sync_file(&tmp, "offload manifest")?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    // The best-effort dir sync of the landed manifest (the rename's
    // dir-entry update — the pinned note on failure, the content
    // stands).
    crate::durability::sync_dir_best_effort(output);
    Ok(path)
}

// ---------------------------------------------------------------------------
// The standalone `frameprism offload <in> <to>` surface (the
// pass-through engine — no encode, any tree: the per-clip manifests
// at the mirrored clip roots + the run report at the dest root + the
// rc)
// ---------------------------------------------------------------------------


/// One parsed offload manifest (the v1 format — this module's writer;
/// the additive header convention: unknown `key: value` keys are
/// skipped, so a v2+ stays parseable by this reader).
#[derive(Debug)]
pub struct Manifest {
    pub name: String,
    pub clip: String,
    pub dest: PathBuf,
    /// (file, size, source_sha256, dest_sha256) per row (sorted row
    /// order). The re-verify checks the dest disk against `size` +
    /// `source_sha256` (the canonical source digest).
    pub rows: Vec<(String, u64, String, String)>,
}


/// Parse an offload manifest (the v1 format): the magic line, the
/// `key: value` headers (`clip` + `dest` required), the `file\tsize\t
/// source_sha256\tdest_sha256\tverdict` column line, then the rows. A
/// bad magic, a missing clip/dest, a bad size field, or a non-5-column
/// row is a hard named error (rc=2 usage — the bake-manifest parse
/// convention).
pub fn parse_manifest(path: &Path) -> Result<Manifest, String> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tsv = std::fs::read_to_string(path)
        .map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut lines = tsv.lines().enumerate();
    let (_, magic) = lines.next().ok_or_else(|| format!("empty offload manifest {name}"))?;
    if magic != MANIFEST_MAGIC {
        return Err(format!(
            "{name} is not a frameprism offload manifest (first line {magic:?}, want {MANIFEST_MAGIC:?})"
        ));
    }
    let mut clip: Option<String> = None;
    let mut dest: Option<PathBuf> = None;
    let mut rows: Vec<(String, u64, String, String)> = Vec::new();
    let mut column_seen = false;
    for (i, line) in lines {
        let lineno = i + 1;
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            continue; // the per-clip verdict section marker
        }
        if line.contains('\t') {
            if line == "file\tsize\tsource_sha256\tdest_sha256\tverdict" {
                column_seen = true;
                continue;
            }
            if !column_seen {
                return Err(format!(
                    "row in {name} line {lineno} before the file column line"
                ));
            }
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() != 5 {
                return Err(format!(
                    "bad row in {name} line {lineno}: {} columns (want 5: file, size, source_sha256, dest_sha256, verdict)",
                    fields.len()
                ));
            }
            let size: u64 = fields[1]
                .parse()
                .map_err(|_| format!("bad size field in {name} line {lineno}: {}", fields[1]))?;
            rows.push((
                fields[0].to_string(),
                size,
                fields[2].to_string(),
                fields[3].to_string(),
            ));
            continue;
        }
        // a `key: value` header line (the column line has tabs; the
        // per-clip verdict section's `clip: …` lines repeat the `clip`
        // key AFTER the header block — the `if clip.is_none()` guard
        // keeps the first (header) value; the `verdict:` line + every
        // unknown key fall through — additive by convention).
        let (key, value) = match line.split_once(':') {
            Some(kv) => kv,
            None => {
                return Err(format!(
                    "bad line in {name} line {lineno} (not a header field or a row): {line:?}"
                ))
            }
        };
        match key.trim() {
            "clip" if clip.is_none() => clip = Some(value.trim().to_string()),
            "dest" if dest.is_none() => dest = Some(PathBuf::from(value.trim())),
            _ => {} // version / created / input / tool_version / host / files / clips / verdict / per-clip blocks / …
        }
    }
    let clip = clip.ok_or_else(|| format!("no clip field in {name}"))?;
    let dest = dest
        .ok_or_else(|| format!("no dest field in {name}"))?
        .to_path_buf();
    if !column_seen {
        return Err(format!("no file column line in {name}"));
    }
    Ok(Manifest {
        name,
        clip,
        dest,
        rows,
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    use super::super::{offload_to, reverify};

    use crate::offload::testutil::*;


}
