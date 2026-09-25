//! The reel-level manifest: one
//! `reel.reel-manifest.tsv` per multi-clip bake — the reel-granularity
//! self-description of the sealed tier.
//!
//! Written ONLY when the bake stages MORE THAN ONE clip archive
//! (a tree bake or a flat multi-clip `--iso` bake; single-clip
//! bakes write NOTHING new — the byte-identity contract). Location:
//! the bake output root — a tree `bake`: the output dir; a `--iso`
//! bake: STAGED AT THE IMAGE ROOT, next to the clip archives (the
//! sealed ISO is self-describing at reel granularity). The columns are
//! exactly the task's list (no additions):
//! `clip  codec  archive  archive_sha256  manifest  manifest_sha256  frames`
//! — a multi-part clip lists the comma-joined part names (part order)
//! + the aligned per-part sha256s. `frames` = the clip's frame count
//! (.DNG frames for j92; the distinct frame stems for jxl — 4 plane
//! files per frame).
//!
//! The per-clip archive/manifest bytes are UNCHANGED: B6's per-object
//! sha sidecars close the tamper class for the objects themselves; the
//! reel rows anchor the reel→clip graph (which archive parts + which
//! per-clip manifest belong to which clip, at which shas).
//!
//! The `audit` verb: a dir containing the manifest = REEL audit —
//! every row's archive part(s) + per-clip bake manifest are
//! re-verified (sha256) at the dir root (the offenders named
//! clip + object), on top of the existing per-clip surface (the
//! root's sidecars/manifests + the recursive clip-subdir audits — the
//! `discover_all` gap fix). The verdict line (exact):
//! `audit: reel <dir>: <N> clip(s), <K> frame(s) OK (reel manifest v1)`.

use std::path::Path;

/// The fixed reel-manifest file name.
pub const REEL_MANIFEST_NAME: &str = "reel.reel-manifest.tsv";
const MAGIC: &str = "# frameprism reel manifest";
const COLUMNS: &str = "clip\tcodec\tarchive\tarchive_sha256\tmanifest\tmanifest_sha256\tframes";

/// One reel row: a clip's archive object(s) + per-clip bake manifest
/// (names relative to the manifest's dir — the bake output root / the
/// image root) + the clip's frame count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReelRow {
    pub clip: String,
    pub codec: String,
    /// The archive basenames (one entry per part, part order).
    pub archives: Vec<String>,
    /// The per-part archive sha256 (aligned with `archives`).
    pub archive_shas: Vec<String>,
    /// The per-clip bake-manifest basename.
    pub manifest: String,
    pub manifest_sha: String,
    pub frames: u64,
}

/// The parsed reel manifest (the additive-versioned format — the magic
/// line is required; unknown `key: value` headers are skipped, the
/// bake-manifest-v2 convention: old records stay valid).
#[derive(Clone, Debug)]
pub struct ReelManifest {
    pub name: String,
    pub version: String,
    pub created: u64,
    pub tool_version: String,
    /// The header's `clips:` count (checked against the row count).
    pub clips: Option<u64>,
    /// The header's `frames:` count (checked against the row sum).
    pub frames: Option<u64>,
    pub rows: Vec<ReelRow>,
}

impl ReelManifest {
    /// The reel's total frame count (the verdict line's K).
    pub fn frames_total(&self) -> u64 {
        self.rows.iter().map(|r| r.frames).sum()
    }
}

/// Render the manifest (the bake's writer). `created` = the wall clock
/// (the non-iso path) or the pinned --iso epoch (the staged content
/// must be deterministic for the sealed image to be).
pub fn render(created: u64, rows: &[ReelRow]) -> String {
    let frames: u64 = rows.iter().map(|r| r.frames).sum();
    let mut tsv = format!(
        "{MAGIC}\n\
         version: 1\n\
         created: {created} (unix seconds, UTC)\n\
         tool_version: {}\n\
         clips: {}\n\
         frames: {frames}\n\
         {COLUMNS}\n",
        env!("CARGO_PKG_VERSION"),
        rows.len()
    );
    for r in rows {
        tsv.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            r.clip,
            r.codec,
            r.archives.join(", "),
            r.archive_shas.join(", "),
            r.manifest,
            r.manifest_sha,
            r.frames
        ));
    }
    tsv
}

/// Parse a reel manifest. A bad magic, a bad header field, a non-7-
/// column row, a row before the column line, a sha/frames field that
/// is not well-formed, a part-name/sha count misalignment, or a
/// header `clips:`/`frames:` disagreement is a hard named error (the
/// rc=2 usage contract — the same convention as the bake-manifest
/// parse).
pub fn parse(path: &Path) -> Result<ReelManifest, String> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tsv = std::fs::read_to_string(path)
        .map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut lines = tsv.lines().enumerate();
    let (_, magic) = lines.next().ok_or_else(|| format!("empty reel manifest {name}"))?;
    if magic != MAGIC {
        return Err(format!(
            "{name} is not a frameprism reel manifest (first line {magic:?}, want {MAGIC:?})"
        ));
    }
    let mut version = String::new();
    let mut created: Option<u64> = None;
    let mut tool_version = String::new();
    let mut clips: Option<u64> = None;
    let mut frames: Option<u64> = None;
    let mut rows: Vec<ReelRow> = Vec::new();
    let mut column_seen = false;
    for (i, line) in lines {
        let lineno = i + 1;
        if line.is_empty() {
            continue;
        }
        if line.contains('\t') {
            if line == COLUMNS {
                column_seen = true;
                continue;
            }
            if !column_seen {
                return Err(format!(
                    "row in {name} line {lineno} before the clip column line"
                ));
            }
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() != 7 {
                return Err(format!(
                    "bad row in {name} line {lineno}: {} columns (want 7: clip, codec, archive, archive_sha256, manifest, manifest_sha256, frames)",
                    fields.len()
                ));
            }
            let archives: Vec<String> = fields[2].split(',').map(|s| s.trim().to_string()).collect();
            let shas: Vec<String> = fields[3].split(',').map(|s| s.trim().to_string()).collect();
            if archives.len() != shas.len() || archives.is_empty() {
                return Err(format!(
                    "bad row in {name} line {lineno}: the archive part names ({}) and the archive sha fields ({}) must be aligned and non-empty",
                    archives.len(),
                    shas.len()
                ));
            }
            for sha in &shas {
                if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(format!(
                        "bad archive_sha256 field in {name} line {lineno}: {sha:?} (want 64 hex digits)"
                    ));
                }
            }
            if fields[5].len() != 64 || !fields[5].chars().all(|c| c.is_ascii_hexdigit()) {
                let bad = fields[5];
                return Err(format!(
                    "bad manifest_sha256 field in {name} line {lineno}: {bad:?} (want 64 hex digits)"
                ));
            }
            let frames = fields[6]
                .parse::<u64>()
                .map_err(|_| {
                    let bad = fields[6];
                    format!("bad frames field in {name} line {lineno}: {bad:?}")
                })?;
            rows.push(ReelRow {
                clip: fields[0].to_string(),
                codec: fields[1].to_string(),
                archives,
                archive_shas: shas,
                manifest: fields[4].to_string(),
                manifest_sha: fields[5].to_string(),
                frames,
            });
            continue;
        }
        let (key, value) = match line.split_once(':') {
            Some(kv) => kv,
            None => {
                return Err(format!(
                    "bad line in {name} line {lineno} (not a header field or a row): {line:?}"
                ))
            }
        };
        match key.trim() {
            "version" => version = value.trim().to_string(),
            "created" => {
                // `created: <epoch> (unix seconds, UTC)` — the epoch
                // field (the same convention as the bake/ingest
                // manifests' header lines).
                let v = value.trim();
                let epoch = v.split(' ').next().unwrap_or(v);
                created = Some(
                    epoch
                        .parse::<u64>()
                        .map_err(|_| format!("bad created field in {name} line {lineno}: {v:?}"))?,
                );
            }
            "tool_version" => tool_version = value.trim().to_string(),
            "clips" => clips = Some(
                value
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| format!("bad clips field in {name} line {lineno}: {value:?}"))?,
            ),
            "frames" => frames = Some(
                value
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| format!("bad frames field in {name} line {lineno}: {value:?}"))?,
            ),
            _ => {} // future keys (the header is additive)
        }
    }
    if rows.is_empty() {
        return Err(format!("no rows in {name}"));
    }
    if let Some(c) = clips {
        if c != rows.len() as u64 {
            return Err(format!(
                "clips {c} in {name} does not match the {} row(s)",
                rows.len()
            ));
        }
    }
    if let Some(f) = frames {
        let total: u64 = rows.iter().map(|r| r.frames).sum();
        if f != total {
            return Err(format!("frames {f} in {name} does not match the row sum {total}"));
        }
    }
    Ok(ReelManifest {
        name,
        version,
        created: created.unwrap_or(0),
        tool_version,
        clips,
        frames,
        rows,
    })
}

/// Re-verify every row's objects at `base` (the dir the manifest sits
/// in): each archive part + the per-clip bake manifest (sha256).
/// Returns the offenders `(clip, object, problem)` in row order (the
/// audit's FAIL lines name clip + object). The per-clip MEMBER bytes
/// are the per-clip bake-manifest sweep's job (the bake-manifest surface) —
/// the reel rows anchor the reel→clip graph, not the member bytes.
pub fn check_rows(m: &ReelManifest, base: &Path) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    for r in &m.rows {
        for (i, a) in r.archives.iter().enumerate() {
            let p = base.join(a);
            if !p.is_file() {
                out.push((r.clip.clone(), a.clone(), format!("archive missing: {a}")));
                continue;
            }
            // The streaming sha (the re-verify is
            // hash-only); the problem wordings are the pre-existing
            // ones.
            match crate::jxl::sha256_stream_path(&p) {
                Err(err) => out.push((r.clip.clone(), a.clone(), format!("unreadable archive {a}: {err}"))),
                Ok(disk) => {
                    if disk != r.archive_shas[i] {
                        out.push((
                            r.clip.clone(),
                            a.clone(),
                            format!(
                                "archive sha256 mismatch: manifest {}, disk {disk}",
                                r.archive_shas[i]
                            ),
                        ));
                    }
                }
            }
        }
        let p = base.join(&r.manifest);
        if !p.is_file() {
            out.push((
                r.clip.clone(),
                r.manifest.clone(),
                format!("bake-manifest missing: {}", r.manifest),
            ));
            continue;
        }
        match std::fs::read(&p) {
            Err(err) => out.push((
                r.clip.clone(),
                r.manifest.clone(),
                format!("unreadable bake-manifest {}: {err}", r.manifest),
            )),
            Ok(bytes) => {
                let disk = crate::jxl::sha256_hex(&bytes);
                if disk != r.manifest_sha {
                    out.push((
                        r.clip.clone(),
                        r.manifest.clone(),
                        format!(
                            "bake-manifest sha256 mismatch: manifest {}, disk {disk}",
                            r.manifest_sha
                        ),
                    ));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(clip: &str, frames: u64) -> (ReelRow, Vec<u8>, Vec<u8>) {
        // The archive + manifest bytes for a synthetic row: the sha
        // fields are computed from the bytes the render/parse round-
        // trip must agree with.
        let arc = format!("{clip}-archive-bytes").into_bytes();
        let man = format!("{clip}-manifest-bytes").into_bytes();
        let r = ReelRow {
            clip: clip.into(),
            codec: "j92".into(),
            archives: vec![format!("{clip}.tar.zst")],
            archive_shas: vec![crate::jxl::sha256_hex(&arc)],
            manifest: format!("{clip}.bake-manifest.tsv"),
            manifest_sha: crate::jxl::sha256_hex(&man),
            frames,
        };
        (r, arc, man)
    }

    #[test]
    fn render_parse_roundtrip_and_check_rows() {
        let tmp = std::env::temp_dir().join(format!("frameprism-reel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let (r1, a1, m1) = row("A001_001", 72);
        let (r2, a2, m2) = row("A001_002", 166);
        let rows = vec![r1.clone(), r2.clone()];
        let text = render(1_789_344_000, &rows);
        let p = tmp.join(REEL_MANIFEST_NAME);
        std::fs::write(&p, &text).unwrap();
        // The object files (the clean case).
        std::fs::write(tmp.join(&r1.archives[0]), &a1).unwrap();
        std::fs::write(tmp.join(&r1.manifest), &m1).unwrap();
        std::fs::write(tmp.join(&r2.archives[0]), &a2).unwrap();
        std::fs::write(tmp.join(&r2.manifest), &m2).unwrap();
        let m = parse(&p).unwrap();
        assert_eq!(m.version, "1");
        assert_eq!(m.created, 1_789_344_000);
        assert_eq!(m.rows.len(), 2);
        assert_eq!(m.rows[0].frames, 72);
        assert_eq!(m.frames_total(), 238);
        assert!(check_rows(&m, &tmp).is_empty(), "clean objects pass");
        // The flipped archive: the named clip + object offender.
        std::fs::write(tmp.join(&r2.archives[0]), b"flipped").unwrap();
        let off = check_rows(&m, &tmp);
        assert_eq!(off.len(), 1, "{off:?}");
        assert_eq!(off[0].0, "A001_002");
        assert_eq!(off[0].1, "A001_002.tar.zst");
        assert!(off[0].2.contains("sha256 mismatch"), "{off:?}");
        // The missing manifest: named.
        std::fs::remove_file(tmp.join(&r1.manifest)).unwrap();
        let off = check_rows(&m, &tmp);
        assert!(
            off.iter().any(|(c, o, p)| c == "A001_001" && o == &r1.manifest && p.contains("missing")),
            "{off:?}"
        );
        // A bad row (6 columns) = the named parse error.
        let h64 = "0".repeat(64);
        std::fs::write(&p, format!("{MAGIC}\nversion: 1\n{COLUMNS}\nA\tj92\tx\t{h64}\ty\t{h64}\n")).unwrap();
        assert!(parse(&p).unwrap_err().contains("6 columns"));
        // A bad magic = the named parse error.
        std::fs::write(&p, "# nope\n").unwrap();
        assert!(parse(&p).unwrap_err().contains("not a frameprism reel manifest"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn multipart_row_roundtrips_comma_aligned() {
        let r = ReelRow {
            clip: "BIG".into(),
            codec: "j92".into(),
            archives: vec!["BIG.part01.tar.zst".into(), "BIG.part02.tar.zst".into()],
            archive_shas: vec!["a".repeat(64), "b".repeat(64)],
            manifest: "BIG.bake-manifest.tsv".into(),
            manifest_sha: "c".repeat(64),
            frames: 4000,
        };
        let m = parse_to_text(&[r.clone()]);
        assert!(m.contains("BIG\tj92\tBIG.part01.tar.zst, BIG.part02.tar.zst\t"), "{m}");
        // A misaligned part/sha row = the named parse error.
        let h64 = "0".repeat(64);
        let bad = format!("{MAGIC}\nversion: 1\n{COLUMNS}\nBIG\tj92\tp1, p2\t{h64}\tBIG.bake-manifest.tsv\t{h64}\t1\n");
        let tmp = std::env::temp_dir().join(format!("frameprism-reel-bad-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join(REEL_MANIFEST_NAME);
        std::fs::write(&p, bad).unwrap();
        assert!(parse(&p).unwrap_err().contains("aligned"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Render without a file (the row text assertion helper).
    fn parse_to_text(rows: &[ReelRow]) -> String {
        render(0, rows)
    }
}
