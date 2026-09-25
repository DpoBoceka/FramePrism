//! The sidecar integrity engine: the sidecar discovery (the
//! GLOB discovery + the archive-object sha sidecars + the
//! per-clip subdirs), the per-format sidecar parse (the J92 v2
//! / the JXL rows), the bake-manifest sweep (the sealed-tier
//! audit surface — the tar member streaming), the generic row
//! audit (the recompute + the offender naming) + the report
//! rendering.

use std::io;
use std::path::{Path, PathBuf};

use crate::jxl;
use super::model::{Offender, Row, Sidecar, SidecarKind, SidecarReport};

/// Discover the audit sidecars in `input` (top level, by glob): the
/// checksums sidecars (`*.jxl-checksums.tsv` / `*.checksums.tsv` — a
/// jxl name matches the checksums glob too, so the classification is
/// by the jxl suffix first) and, when `include_bake`, the sealed-tier
/// `*.bake-manifest.tsv` manifests. Sorted by path (the deterministic
/// report order).
fn discover_all(input: &Path, include_bake: bool) -> Vec<(PathBuf, bool)> {
    let mut out: Vec<(PathBuf, bool)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(input) {
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            //: the AppleDouble shadow twin is never a frameprism
            // sidecar — skip (the xattr-less-volume artifact; the
            // field's incident: the shadow changed behavior
            // at every glob-driven discovery boundary).
            if crate::is_apple_double(&name) {
                continue;
            }
            if name.ends_with(".jxl-checksums.tsv") || name.ends_with(".checksums.tsv") {
                out.push((p, false));
            } else if include_bake && name.ends_with(".bake-manifest.tsv") {
                out.push((p, true));
            }
        }
    }
    out.sort();
    out
}

/// One B6 archive-object sha sidecar's audit result (
/// B6): the sidecar file name, the object it names (the file name
/// minus the `.sha256` suffix), the expected sha256, and the named
/// problem (None = clean). The object-sha sidecars are the ONE-LINER
/// verify after any move/copy (`sha256sum -c` in the object dir): the
/// sealed-tier seam for "the ISO moved to another disk". The existing
/// audit behavior on sidecar-less trees is UNCHANGED (the v2
/// byte-identity carve-out applies — a `.sha256` file is itself a
/// sidecar, so a dir with only them is audited, not rc=2).
// The diagnostic fields (`sidecar`/`object`/`expected`) are read by
// the tests + the named lines carry them via `offender`/`problem`;
// the non-test print path uses the latter two only.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ObjectShaAudit {
    /// The sidecar file name (`<object>.sha256`).
    pub sidecar: String,
    /// The object name (the sidecar name minus `.sha256`).
    pub object: String,
    /// The expected sha256 (the sidecar's line; empty when the
    /// sidecar itself is the offender).
    pub expected: String,
    /// The named offender (the object for object problems, the
    /// sidecar for sidecar problems) + the problem text.
    pub offender: String,
    pub problem: Option<String>,
}

/// Discover the B6 object sha sidecars in `input` (top level, the
/// same discovery convention as the other sidecars). The `audit`
/// verb only — `restore`'s loose-file repair semantics are unchanged
/// (it discovers with `include_bake = false`, which gates this too).
pub(crate) fn discover_object_sha_sidecars(input: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(input) {
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            //: the AppleDouble shadow is never an object-sha
            // sidecar — skip (the shared predicate, one rule, every
            // boundary).
            if crate::is_apple_double(&name) {
                continue;
            }
            if name.ends_with(".sha256") && name != ".sha256" {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The clip subdirs carrying at least one recognized sidecar (the
/// recursive audit's surface — the tree shape where the per-clip
/// sidecars live in the clip folders and the ROOT has none): one
/// `(clip key, (reports, object-sha audits))` per clip subdir (a full
/// `audit_dir` of the subdir — the same surface as the root), in
/// clip-name order. Only consulted when the root's own sidecar
/// discovery failed (a root-sidecar dir takes the existing path
/// byte-identical — R-INV); a clip dir with no sidecar is not an
/// audited clip (skipped — the root's `discover_all` convention).
pub(crate) fn discover_clip_subdirs(
    input: &Path,
    jobs: usize,
) -> Vec<(String, Vec<SidecarReport>, Vec<ObjectShaAudit>)> {
    let mut out: Vec<(String, Vec<SidecarReport>, Vec<ObjectShaAudit>)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(input) {
        for e in rd.flatten() {
            let p = e.path();
            let ft = match e.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if !ft.is_dir() || ft.is_symlink() {
                continue;
            }
            let key = match e.file_name().to_str() {
                Some(k) if !k.is_empty() => k.to_string(),
                _ => continue,
            };
            // A clip subdir with no sidecar of its own = not an
            // audited clip (skip — the root's no-sidecar discovery
            // convention).
            match audit_dir(&p, jobs, true) {
                Ok(d) => out.push((key, d.0, d.1)),
                Err(_) => continue,
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Parse + verify ONE B6 object sha sidecar (the sha256sum-compatible
/// line `<sha256>  <name>` — TWO spaces, no directory component, one
/// line). Mismatch = a named offender; an orphan sidecar (no object)
/// = a named ORPHAN (a moved object is exactly the seam this closes
/// — loud, not silent); a malformed sidecar = a named offender (the
/// sidecar itself).
pub(crate) fn audit_object_sha(input: &Path, path: &Path) -> ObjectShaAudit {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let object = name.trim_end_matches(".sha256").to_string();
    let mut expected = String::new();
    let parse_problem: Option<String> = match std::fs::read_to_string(path) {
        Err(err) => Some(format!("unreadable sidecar: {err}")),
        Ok(text) => {
            let non_empty: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
            match non_empty.as_slice() {
                [] => Some("empty sidecar (no sha256 line)".into()),
                [line] => {
                    let (sha, rest) = match line.split_once("  ") {
                        Some((a, b)) => (a, b),
                        None => {
                            return ObjectShaAudit {
                                sidecar: name.clone(),
                                object: object.clone(),
                                expected: String::new(),
                                offender: name.clone(),
                                problem: Some(
                                    "malformed sidecar (expected the sha256sum line `<sha256>  <name>` — two spaces, no directory component)"
                                        .into(),
                                ),
                            };
                        }
                    };
                    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
                        return ObjectShaAudit {
                            sidecar: name.clone(),
                            object: object.clone(),
                            expected: String::new(),
                            offender: name.clone(),
                            problem: Some(format!(
                                "malformed sidecar (the sha field {sha:?} is not 64 hex digits)"
                            )),
                        };
                    }
                    if rest != object {
                        return ObjectShaAudit {
                            sidecar: name.clone(),
                            object: object.clone(),
                            expected: sha.to_string(),
                            offender: name.clone(),
                            problem: Some(format!(
                                "malformed sidecar (the name field {rest:?} does not match the object the sidecar file name names: {object:?})"
                            )),
                        };
                    }
                    expected = sha.to_string();
                    None
                }
                _ => Some(format!(
                    "malformed sidecar ({} non-empty line(s); the sidecar names exactly one object)",
                    non_empty.len()
                )),
            }
        }
    };
    if let Some(problem) = parse_problem {
        return ObjectShaAudit {
            sidecar: name.clone(),
            object: object.clone(),
            expected,
            offender: name.clone(),
            problem: Some(problem),
        };
    }
    // The object itself: missing = the named ORPHAN; present = the sha sweep.
    let object_path = input.join(&object);
    let problem = if !object_path.exists() {
        Some(format!(
            "ORPHAN — the object {object} is missing (a moved object? the sidecar outlives its object — re-bake the sidecar or delete it)"
        ))
    } else {
        // The streaming object sha (the bounded read:
        // the `SHA256_CHUNK` buffer, never the whole file — the
        // one-shot `fs::read` is gone). The wording is unchanged.
        match crate::jxl::sha256_stream_path(&object_path) {
            Err(err) => Some(format!("unreadable object {object}: {err}")),
            Ok(disk) => {
                if disk != expected {
                    Some(format!("sha256 mismatch: sidecar {expected}, disk {disk}"))
                } else {
                    None
                }
            }
        }
    };
    ObjectShaAudit {
        offender: object.clone(),
        sidecar: name,
        object,
        expected,
        problem,
    }
}

pub(crate) fn parse_size(s: &str, what: &str, lineno: usize) -> Result<u64, String> {
    s.parse()
        .map_err(|_| format!("bad size field in {what} line {lineno}: {s:?}"))
}

fn parse_crc(s: &str, what: &str, lineno: usize) -> Result<u32, String> {
    u32::from_str_radix(s, 16)
        .map_err(|_| format!("bad crc32c field in {what} line {lineno}: {s:?}"))
}

/// The frame stem for a sidecar file column (the `--frame` key): j92 =
/// the file stem; jxl = the stem minus the `_p2_XX` plane suffix (the
/// plane column is the arbiter for the suffix).
fn stem_of(file: &str, jxl: bool, plane: Option<&str>) -> Result<String, String> {
    let base = Path::new(file)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("cannot derive a frame stem from file column {file:?}"))?;
    if !jxl {
        return Ok(base);
    }
    let plane = plane.ok_or_else(|| {
        format!("cannot derive a frame stem from {file:?} (no plane column)")
    })?;
    let suffix = format!("_{plane}");
    base.strip_suffix(&suffix)
        .map(|s| s.to_string())
        .ok_or_else(|| {
            format!(
                "file column {file:?} does not end with its plane suffix {suffix:?}"
            )
        })
}

/// Parse one sidecar (J92 v2 or JXL by name suffix).
fn parse_sidecar(path: &Path) -> Result<Sidecar, String> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let jxl = name.ends_with(".jxl-checksums.tsv");
    let tsv = std::fs::read_to_string(path)
        .map_err(|err| format!("read {}: {err}", path.display()))?;
    // The v3 j92 sidecar: the magic line identifies
    // it (v2 files never start with it — the v2 parse path is
    // byte-untouched). v3 rows carry the 4 v2 contract columns
    // UNCHANGED in place and order + the additive camera-metadata
    // columns (timecode, framerate, iso, exposure); the sweep reads
    // the first 4.
    let v3 = !jxl
        && matches!(
            tsv.lines().next(),
            Some(m) if m == crate::checksums::V3_MAGIC
        );
    let mut rows = Vec::new();
    for (i, line) in tsv.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        if !line.contains('\t') {
            continue; // the v3 magic + the `key: value` header block
        }
        if line.starts_with("file\t") {
            continue; // the column line (v2 + v3)
        }
        let lineno = i + 1;
        let fields: Vec<&str> = line.split('\t').collect();
        let row = if jxl {
            if fields.len() < 5 {
                return Err(format!(
                    "bad row in {name} line {lineno}: {} columns (JXL rows need at least 5: file, size, sha256, crc32c, plane)",
                    fields.len()
                ));
            }
            Row {
                file: fields[0].to_string(),
                size: parse_size(fields[1], &name, lineno)?,
                // JXL column order: file, size, SHA256, crc32c, plane.
                sha: fields[2].to_string(),
                crc: Some(parse_crc(fields[3], &name, lineno)?),
                stem: stem_of(fields[0], true, Some(fields[4]))?,
            }
        } else if v3 {
            if fields.len() != 8 {
                return Err(format!(
                    "bad row in {name} line {lineno}: {} columns (the v3 sidecar rows carry exactly 8: file, size, crc32c, sha256, timecode, framerate, iso, exposure)",
                    fields.len()
                ));
            }
            // The first 4 = the v2 sweep contract (column order
            // unchanged in place); the additive columns (4+) are the
            // report's surface, not the sweep's.
            Row {
                file: fields[0].to_string(),
                size: parse_size(fields[1], &name, lineno)?,
                // J92 v2/v3 column order: file, size, crc32c, SHA256.
                crc: Some(parse_crc(fields[2], &name, lineno)?),
                sha: fields[3].to_string(),
                stem: stem_of(fields[0], false, None)?,
            }
        } else {
            match fields.len() {
                4 => Row {
                    file: fields[0].to_string(),
                    size: parse_size(fields[1], &name, lineno)?,
                    // J92 v2 column order: file, size, crc32c, SHA256.
                    crc: Some(parse_crc(fields[2], &name, lineno)?),
                    sha: fields[3].to_string(),
                    stem: stem_of(fields[0], false, None)?,
                },
                3 => {
                    return Err(format!(
                        "sidecar {name} predates the sha256 column (line {lineno} has 3 columns) — regenerate with --checksums on a fresh encode"
                    ))
                }
                n => {
                    return Err(format!(
                        "bad row in {name} line {lineno}: {n} columns (want 4: file, size, crc32c, sha256)"
                    ))
                }
            }
        };
        rows.push(row);
    }
    if rows.is_empty() {
        return Err(format!("no rows in {name}"));
    }
    Ok(Sidecar {
        name,
        kind: SidecarKind::Checksums,
        rows,
    })
}

/// Parse a bake manifest (the v2 format — `tool/src/bake.rs`): the
/// magic line, the `key: value` header lines (`clip`, `container`,
/// `file_count` required; the optional `archive:` part list — the
/// additive field, present only when parts > 1),
/// the `relpath\tsize\tsha256` column line, then the rows. Unknown
/// header keys are skipped (the header is additive by convention —
/// `created`/`tool_version`/`codec`/`zstd_level`/`tar_version`/
/// `zstd_version`/`host`); a file_count/row-count mismatch, a bad
/// size field, a non-3-column row, or a row before the column line
/// is a hard named error (rc=2 usage).
fn parse_bake_manifest(path: &Path) -> Result<Sidecar, String> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tsv = std::fs::read_to_string(path)
        .map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut lines = tsv.lines().enumerate();
    let (_, magic) = lines.next().ok_or_else(|| format!("empty bake manifest {name}"))?;
    if magic != "# frameprism bake manifest" {
        return Err(format!(
            "{name} is not a frameprism bake manifest (first line {magic:?}, want \"# frameprism bake manifest\")"
        ));
    }
    let mut clip: Option<String> = None;
    let mut container: Option<String> = None;
    let mut file_count: Option<u64> = None;
    let mut parts: Option<Vec<String>> = None;
    let mut rows: Vec<Row> = Vec::new();
    let mut column_line_seen = false;
    for (i, line) in lines {
        let lineno = i + 1;
        if line.is_empty() {
            continue;
        }
        if line.contains('\t') {
            if line == "relpath\tsize\tsha256" {
                column_line_seen = true;
                continue;
            }
            if !column_line_seen {
                return Err(format!(
                    "row in {name} line {lineno} before the relpath column line"
                ));
            }
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() != 3 {
                return Err(format!(
                    "bad row in {name} line {lineno}: {} columns (want 3: relpath, size, sha256)",
                    fields.len()
                ));
            }
            rows.push(Row {
                file: fields[0].to_string(),
                size: parse_size(fields[1], &name, lineno)?,
                sha: fields[2].to_string(),
                crc: None, // the bake manifest rows carry no crc column
                stem: stem_of(fields[0], false, None)?,
            });
            continue;
        }
        // a `key: value` header line (the column line has tabs, never
        // `:`; unknown keys are skipped — the header is additive).
        let (key, value) = match line.split_once(':') {
            Some(kv) => kv,
            None => {
                return Err(format!(
                    "bad line in {name} line {lineno} (not a header field or a row): {line:?}"
                ))
            }
        };
        match key.trim() {
            "clip" => clip = Some(value.trim().to_string()),
            "container" => container = Some(value.trim().to_string()),
            "file_count" => file_count = Some(parse_size(value.trim(), &name, lineno)?),
            "archive" => {
                let names: Vec<String> = value
                    .trim()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if names.is_empty() {
                    return Err(format!("empty archive part list in {name} line {lineno}"));
                }
                parts = Some(names);
            }
            _ => {} // created / tool_version / codec / zstd_level / tar_version / zstd_version / host / …
        }
    }
    let clip = clip.ok_or_else(|| format!("no clip field in {name}"))?;
    let container = container.ok_or_else(|| format!("no container field in {name}"))?;
    let file_count = file_count.ok_or_else(|| format!("no file_count field in {name}"))?;
    if file_count != rows.len() as u64 {
        return Err(format!(
            "file_count {file_count} in {name} does not match the {} row(s)",
            rows.len()
        ));
    }
    if rows.is_empty() {
        return Err(format!("no rows in {name}"));
    }
    Ok(Sidecar {
        name,
        kind: SidecarKind::Bake { parts, clip, container },
        rows,
    })
}

/// The bake-manifest sweep context (see `bake_context`): the part
/// list + the member→part map.
#[derive(Debug)]
struct BakeContext {
    /// The part list, as the manifest names them (the `archive:` field
    /// or the single derived archive).
    parts: Vec<String>,
    /// member name → part name (built by the in-process listing per
    /// part — the member map takes what the archive lists, exactly as
    /// the legacy `tar -tf` did).
    map: std::collections::BTreeMap<String, String>,
}

/// Open an archive part for the in-process read (the `tar -tf` /
/// `tar -xO` replacement): the part is the raw tar OR a zstd frame
/// over the tar — the format is SNIFFED from the frame magic (the
/// zstd magic `28 B5 2F FD`, the bsdtar auto-decompress parity — the
/// name is never consulted), so BOTH the in-process-written
/// containers and the legacy system-tar containers (the bsdtar
/// `--no-mac-metadata` output) read identically (the D4 legacy
/// decision: any `._*` member the legacy archive lists is simply
/// carried in the member map — a member the manifest doesn't
/// reference is never looked up, the SAME semantics as the legacy
/// `tar -tf`).
fn open_container_part(p: &Path) -> std::io::Result<Box<dyn std::io::Read>> {
    use std::io::Read;
    let mut file = std::fs::File::open(p)?;
    // The magic sniff WITHOUT losing the head bytes (a short part
    // reads fewer than 4 — the head chains back in front of the
    // file either way): `28 B5 2F FD` = the zstd frame magic.
    let mut head = [0u8; 4];
    let n = file.read(&mut head)?;
    let head = head[0..n].to_vec();
    let zst = n >= 4 && head[0] == 0x28 && head[1] == 0xB5 && head[2] == 0x2F && head[3] == 0xFD;
    let chain = std::io::Cursor::new(head).chain(file);
    if zst {
        // The in-process zstd decoder (single-stream; the concatenated-
        // frame tolerant — a legacy multi-frame container reads too).
        zstd::stream::Decoder::new(chain)
            .map(|dec| Box::new(dec) as Box<dyn std::io::Read>)
    } else {
        Ok(Box::new(chain))
    }
}

/// Build the bake-manifest member context: the part list + the
/// member→part map (one in-process listing per part — the
/// `tar -tf` parity: the member map takes what the archive lists,
/// including any directory or `._*` members a legacy container
/// carries). A part MISSING on disk stays in the list (its rows are
/// the named offenders); a part whose listing FAILS is a hard error
/// (the audit surface itself is broken — named, rc=2); a member name
/// listed in two parts is a manifest inconsistency (hard error,
/// named).
fn bake_context(
    input: &Path,
    parts: Option<Vec<String>>,
    clip: &str,
    container: &str,
) -> Result<BakeContext, String> {
    let parts: Vec<String> = match parts {
        Some(p) if !p.is_empty() => p,
        Some(_) => return Err("bake manifest has an empty archive part list".to_string()),
        None => vec![format!("{clip}.{container}")],
    };
    let mut map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for part in &parts {
        let p = input.join(part);
        if !p.is_file() {
            continue; // the rows name the missing part (the offenders)
        }
        let reader = match open_container_part(&p) {
            Ok(r) => r,
            Err(err) => {
                return Err(format!("container read failed for {part}: {err}"));
            }
        };
        let mut archive = tar::Archive::new(reader);
        let entries = match archive.entries() {
            Ok(e) => e,
            Err(err) => return Err(format!("container read failed for {part}: {err}")),
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => return Err(format!("container read failed for {part}: {err}")),
            };
            let line = match entry.path() {
                Ok(n) => n.to_string_lossy().into_owned(),
                Err(err) => return Err(format!("container read failed for {part}: {err}")),
            };
            if line.is_empty() {
                continue;
            }
            if map.insert(line.clone(), part.clone()).is_some() {
                return Err(format!(
                    "member {line} is listed in more than one archive part ({}) — manifest inconsistency",
                    parts.join(", ")
                ));
            }
        }
    }
    Ok(BakeContext { parts, map })
}

/// Check one bake-manifest row against its archive part (one
/// in-process single-member stream — the `tar -xO` parity: the
/// sealed-tier audit surface, stream, hash, compare; NO scratch). The
/// first mismatch is the named problem (size → sha256, the manifest's
/// two data columns); the part is named in the problem when the
/// manifest carries an explicit multi-part list (the split-tier
/// contract).
fn check_bake_row(input: &Path, ctx: &BakeContext, row: &Row) -> Option<String> {
    use std::io::Read;
    let part = match ctx.map.get(&row.file) {
        None => {
            return Some(format!(
                "member not found in any archive part (looked in: {})",
                ctx.parts.join(", ")
            ))
        }
        Some(p) => p,
    };
    let p = input.join(part);
    if !p.is_file() {
        return Some(format!(
            "archive part missing: {} (cannot verify member)",
            part
        ));
    }
    let reader = match open_container_part(&p) {
        Ok(r) => r,
        Err(err) => return Some(format!("member unreadable from {part}: {err}")),
    };
    let mut archive = tar::Archive::new(reader);
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(err) => return Some(format!("member unreadable from {part}: {err}")),
    };
    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(err) => return Some(format!("member unreadable from {part}: {err}")),
        };
        let name = match entry.path() {
            Ok(n) => n.to_string_lossy().into_owned(),
            Err(err) => return Some(format!("member unreadable from {part}: {err}")),
        };
        if name != row.file {
            continue;
        }
        // The single-member stream → hash → compare (the `tar -xOf`
        // parity: the member bytes stream into memory, no scratch
        // file — the same profile as the legacy subprocess's captured
        // stdout).
        let mut bytes: Vec<u8> = Vec::new();
        if let Err(err) = entry.read_to_end(&mut bytes) {
            return Some(format!("member unreadable from {part}: {err}"));
        }
        let size = bytes.len() as u64;
        let sha = jxl::sha256_hex(&bytes);
        let prefix = if ctx.parts.len() > 1 {
            format!("part {part}: ")
        } else {
            String::new()
        };
        if size != row.size {
            return Some(format!(
                "{prefix}size mismatch: manifest {}, disk {size}",
                row.size
            ));
        }
        if sha != row.sha {
            return Some(format!(
                "{prefix}sha256 mismatch: manifest {}, disk {sha}",
                row.sha
            ));
        }
        return None;
    }
    // The member was in the listing map but the re-scan found no such
    // entry (a corrupt or shifting archive — the listing and the row
    // pass disagree): the same named class as the legacy `tar -xOf`
    // refusal.
    Some(format!("member unreadable from {part}: the entry is absent on the re-scan"))
}

/// Sweep the bake-manifest rows (parallel file-read pool; `jobs == 0`
/// = all cores) — one in-process single-member stream per row (the
/// `tar -xO` parity). Results in ROW order (deterministic reporting).
fn sweep_bake(rows: &[Row], input: &Path, ctx: &BakeContext, jobs: usize) -> Vec<Option<String>> {
    let want = if jobs == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    } else {
        jobs
    };
    let n = want.max(1).min(rows.len().max(1));
    if n == 1 {
        return rows.iter().map(|r| check_bake_row(input, ctx, r)).collect();
    }
    let mut results = vec![None; rows.len()];
    std::thread::scope(|s| {
        let chunk = rows.len().div_ceil(n);
        let mut handles = Vec::new();
        for (ci, c) in rows.chunks(chunk).enumerate() {
            let start = ci * chunk;
            let input = input.to_path_buf();
            handles.push(s.spawn(move || {
                c.iter()
                    .enumerate()
                    .map(|(i, r)| (start + i, check_bake_row(&input, ctx, r)))
                    .collect::<Vec<_>>()
            }));
        }
        for h in handles {
            for (i, res) in h.join().expect("sweep thread panicked") {
                results[i] = res;
            }
        }
    });
    results
}

/// Check one row against the on-disk file (ONE streaming
/// read; the FIRST mismatch is the named problem — size → sha256 →
/// crc32c). The O(1) size stat gates the streaming pass, which
/// computes the sha256 (+ the crc32c when the row carries one) over
/// `SHA256_CHUNK`-sized chunks — the one-shot `fs::read` of the whole
/// file is gone (the O(file) heap was the machine incident's root).
/// The crc32c is updated bit-wise in the pass (the reflected
/// polynomial 0x82F63B78 — the `checksums` module's table is a
/// memoization of this same update, init 0xFFFFFFFF + xorout
/// 0xFFFFFFFF: result-identical, no table needed here — the touch-
/// set keeps checksums.rs out of this module).
fn check_row(target: &Path, row: &Row) -> Option<String> {
    use std::io::Read;
    let size = match std::fs::metadata(target) {
        Ok(m) => m.len(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Some("file missing".to_string())
        }
        Err(err) => return Some(format!("unreadable: {err}")),
    };
    if size != row.size {
        return Some(format!(
            "size mismatch: sidecar {}, disk {size}",
            row.size
        ));
    }
    let need_crc = row.crc.is_some();
    let mut sha = jxl::Sha256State::new();
    let mut crc = 0xFFFF_FFFFu32;
    let mut f = match std::fs::File::open(target) {
        Ok(f) => f,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Some("file missing".to_string())
        }
        Err(err) => return Some(format!("unreadable: {err}")),
    };
    let mut buf = vec![0u8; jxl::SHA256_CHUNK];
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) => return Some(format!("unreadable: {err}")),
        };
        let chunk = &buf[..n];
        sha.update(chunk);
        if need_crc {
            for &b in chunk {
                crc ^= b as u32;
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0x82_F6_3B_78
                    } else {
                        crc >> 1
                    };
                }
            }
        }
    }
    let disk_sha = jxl::sha256_hex_of(sha.finalize());
    if disk_sha != row.sha {
        return Some(format!("sha256 mismatch: sidecar {}, disk {disk_sha}", row.sha));
    }
    if let Some(expected_crc) = row.crc {
        let disk = crc ^ 0xFFFF_FFFF;
        if disk != expected_crc {
            return Some(format!(
                "crc32c mismatch: sidecar {expected_crc:08x}, disk {disk:08x}"
            ));
        }
    }
    None
}

/// Sweep the rows (parallel file-read pool; `jobs == 0` = all cores).
/// Results in ROW order (deterministic reporting).
fn sweep(rows: &[Row], input: &Path, jobs: usize) -> Vec<Option<String>> {
    let want = if jobs == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    } else {
        jobs
    };
    let n = want.max(1).min(rows.len().max(1));
    if n == 1 {
        return rows
            .iter()
            .map(|r| check_row(&input.join(&r.file), r))
            .collect();
    }
    let mut results = vec![None; rows.len()];
    std::thread::scope(|s| {
        let chunk = rows.len().div_ceil(n);
        let mut handles = Vec::new();
        for (ci, c) in rows.chunks(chunk).enumerate() {
            let start = ci * chunk;
            let input = input.to_path_buf();
            handles.push(s.spawn(move || {
                c.iter()
                    .enumerate()
                    .map(|(i, r)| (start + i, check_row(&input.join(&r.file), r)))
                    .collect::<Vec<_>>()
            }));
        }
        for h in handles {
            for (i, res) in h.join().expect("sweep thread panicked") {
                results[i] = res;
            }
        }
    });
    results
}

/// Audit every sidecar in `input` (discovery + parse + sweep).
/// `include_bake` = also audit the `*.bake-manifest.tsv` manifests
/// (the sealed-tier audit surface — the `audit` verb passes true;
/// `restore` passes false, its repair semantics are loose-file) AND
/// the B6 archive-object sha sidecars (`*.sha256` — the same gate).
/// Returns (the checksums/bake sidecar reports, the object-sha
/// audits) in deterministic order.
pub(crate) fn audit_dir(
    input: &Path,
    jobs: usize,
    include_bake: bool,
) -> Result<(Vec<SidecarReport>, Vec<ObjectShaAudit>), String> {
    let paths = discover_all(input, include_bake);
    let sha_paths = if include_bake {
        discover_object_sha_sidecars(input)
    } else {
        Vec::new()
    };
    if paths.is_empty() && sha_paths.is_empty() {
        return Err(format!(
            "no sidecar in {} (looked for *.checksums.tsv / *.jxl-checksums.tsv)",
            input.display()
        ));
    }
    let mut reports = Vec::new();
    for (p, is_bake) in &paths {
        let (sidecar, bake_ctx) = if *is_bake {
            let sc = parse_bake_manifest(p)?;
            let (parts, clip, container) = match &sc.kind {
                SidecarKind::Bake { parts, clip, container } => {
                    (parts.clone(), clip.clone(), container.clone())
                }
                SidecarKind::Checksums => unreachable!("bake path parses a bake kind"),
            };
            (sc, Some(bake_context(input, parts, &clip, &container)?))
        } else {
            (parse_sidecar(p)?, None)
        };
        let problems = if let Some(ctx) = &bake_ctx {
            sweep_bake(&sidecar.rows, input, ctx, jobs)
        } else {
            sweep(&sidecar.rows, input, jobs)
        };
        let offenders = problems
            .into_iter()
            .enumerate()
            .filter_map(|(i, problem)| {
                problem.map(|problem| Offender {
                    row: sidecar.rows[i].clone(),
                    problem,
                    target: input.join(&sidecar.rows[i].file),
                })
            })
            .collect();
        reports.push(SidecarReport {
            sidecar: sidecar.name.clone(),
            rows: sidecar.rows,
            offenders,
        });
    }
    // The B6 object sha sidecars (one audit each — the object's full
    // bytes against the sidecar's line).
    let object_shas: Vec<ObjectShaAudit> =
        sha_paths.iter().map(|p| audit_object_sha(input, p)).collect();
    Ok((reports, object_shas))
}

/// Print the per-sidecar offenders + summary lines (+ the B6
/// object-sha lines: one FAIL per offender + the per-sidecar class
/// summary).
pub(crate) fn print_reports(reports: &[SidecarReport], object_shas: &[ObjectShaAudit]) {
    for r in reports {
        for o in &r.offenders {
            println!("FAIL {} — {}", o.row.file, o.problem);
        }
        println!(
            "audit: {}/{} file(s) OK ({})",
            r.rows.len() - r.offenders.len(),
            r.rows.len(),
            r.sidecar
        );
    }
    for o in object_shas {
        if let Some(problem) = &o.problem {
            println!("FAIL {} — {problem}", o.offender);
        }
    }
    if !object_shas.is_empty() {
        let ok = object_shas.iter().filter(|o| o.problem.is_none()).count();
        println!(
            "audit: {ok}/{} object sha sidecar(s) OK (B6: the archive-object sidecars)",
            object_shas.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
use std::process::ExitCode;
    use crate::audit::testutil::*;

    // =====================================================================
    // The archive-object sha sidecars
    // =====================================================================

    #[test]
    fn b6_object_sha_sidecar_clean_mismatch_orphan() {
        let tmp = std::env::temp_dir().join(format!("frameprism-b6-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // Clean: the object passes its sidecar (the sha256sum format).
        let sha = mk_object_sha(&tmp, "A001_001.tar.zst", b"archive-bytes");
        let (reports, shas) = audit_dir(&tmp, 1, true).unwrap();
        assert!(reports.is_empty(), "{reports:?}");
        assert_eq!(shas.len(), 1, "{shas:?}");
        assert!(shas[0].problem.is_none(), "{:?}", shas[0]);
        assert_eq!(shas[0].sidecar, "A001_001.tar.zst.sha256");
        assert_eq!(shas[0].expected, sha);
        // The 1-byte flip: the sha256 mismatch is named.
        std::fs::write(tmp.join("A001_001.tar.zst"), b"archive-byteS").unwrap();
        let (_, shas) = audit_dir(&tmp, 1, true).unwrap();
        let problem = shas[0].problem.as_deref().unwrap();
        assert!(problem.starts_with("sha256 mismatch:"), "{problem:?}");
        assert_eq!(shas[0].offender, "A001_001.tar.zst");
        // The moved object (sidecar kept): the named ORPHAN.
        let _ = std::fs::remove_file(tmp.join("A001_001.tar.zst"));
        let (_, shas) = audit_dir(&tmp, 1, true).unwrap();
        let problem = shas[0].problem.as_deref().unwrap();
        assert!(problem.starts_with("ORPHAN"), "{problem:?}");
        // A malformed sidecar (one space) = the named offender (the
        // sidecar itself).
        std::fs::write(tmp.join("A001_001.tar.zst"), b"archive-bytes").unwrap();
        std::fs::write(
            tmp.join("A001_001.tar.zst.sha256"),
            format!("{sha} A001_001.tar.zst\n"),
        )
        .unwrap();
        let (_, shas) = audit_dir(&tmp, 1, true).unwrap();
        let problem = shas[0].problem.as_deref().unwrap();
        assert!(problem.starts_with("malformed sidecar"), "{problem:?}");
        // restore's discovery (include_bake = false) is UNCHANGED: a
        // B6-only dir is the no-sidecar rc=2 for restore semantics.
        assert!(audit_dir(&tmp, 1, false)
            .unwrap_err()
            .starts_with("no sidecar in "));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn b6_object_sha_audit_verb_end_to_end() {
        let tmp = std::env::temp_dir().join(format!("frameprism-b6-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        mk_object_sha(&tmp, "reel.iso", b"sealed-image-bytes");
        // Clean audit of a B6 dir: rc=0 (the sidecar IS the sidecar —
        // the no-sidecar rc=2 does not fire).
        assert_eq!(run(&tmp), ExitCode::SUCCESS, "a clean B6 dir is rc 0");
        // The flipped image: rc=1 (the named offender).
        std::fs::write(tmp.join("reel.iso"), b"sealed-image-byteS").unwrap();
        assert_eq!(run(&tmp), ExitCode::from(1), "a flipped B6 object is the named rc 1");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// G2-4: the audit's sidecar discovery (`discover_all`) —
    /// `.jxl-checksums.tsv` + `.bake-manifest.tsv` + their `._` shadows
    /// → 2 (the reals).
    #[test]
    fn spec7_g2_discover_all_skips_the_shadows() {
        let tmp = std::env::temp_dir().join(format!("frameprism-spec7-g2-discoverall-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("C.jxl-checksums.tsv"), "header\n").unwrap();
        std::fs::write(tmp.join("._C.jxl-checksums.tsv"), vec![0xFF, 0xFE]).unwrap();
        std::fs::write(tmp.join("C.bake-manifest.tsv"), "header\n").unwrap();
        std::fs::write(tmp.join("._C.bake-manifest.tsv"), vec![0xFF, 0xFE]).unwrap();
        let found = discover_all(&tmp, true);
        assert_eq!(
            found.len(),
            2,
            "the two reals + their shadows → 2: {found:?}"
        );
        let names: Vec<String> = found.iter().map(|(p, _)| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
        assert_eq!(names, vec!["C.bake-manifest.tsv", "C.jxl-checksums.tsv"], "{names:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// G2-5: the audit's object-sha sidecar discovery — real `.sha256`
    /// + `._` shadow → 1 (the real one).
    #[test]
    fn spec7_g2_object_sha_discovery_skips_the_shadow() {
        let tmp = std::env::temp_dir().join(format!("frameprism-spec7-g2-objectsha-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("obj.part01.tar.zst.sha256"), "deadbeef  obj.part01.tar.zst\n").unwrap();
        std::fs::write(tmp.join("._obj.part01.tar.zst.sha256"), vec![0xFF, 0xFE]).unwrap();
        let found = discover_object_sha_sidecars(&tmp);
        assert_eq!(
            found,
            vec![tmp.join("obj.part01.tar.zst.sha256")],
            "real + shadow → 1 (the real one): {found:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn audit_genuine_no_record_tree_keeps_the_no_sidecar_refusal() {
        // A dir with no sidecars, no ingest record, no offload
        // record: the EXISTING no-sidecar refusal (unchanged;
        // the message byte-identical — the stable contract string
        // `audit_dir` produces, `run_audit` prints as
        // `error: audit: {err}`).
        let tmp = std::env::temp_dir().join(format!("frameprism-norecord_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("notes.txt"), b"nothing to audit").unwrap();
        assert_eq!(run(&tmp), ExitCode::from(2), "the genuine no-record tree = the unchanged rc=2");
        let err = audit_dir(&tmp, 1, true).unwrap_err();
        assert_eq!(
            err,
            format!("no sidecar in {} (looked for *.checksums.tsv / *.jxl-checksums.tsv)", tmp.display()),
            "the no-sidecar message is byte-identical (the stable contract)"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // -------------------------------------------------------------------
    // The streaming conversions (the reverify +
    // check_row wordings UNCHANGED — the value-identical pins + the
    // bit-wise crc's table-form cross-check on real file I/O)
    // -------------------------------------------------------------------

    /// The re-verify + the row check, streaming,
    /// unchanged: the `reverify` verdict lines VALUE-identical to the
    /// one-shot-era expectations (the pinned wordings; the disk shas
    /// re-derived with the module's ONE-SHOT `sha256_hex` — the
    /// cross-proof the streaming re-verify's digests agree) + the
    /// `check_row` tamper offender wordings UNCHANGED (the existing
    /// audit surface tests pass unmodified — the proof complement;
    /// the crc path is cross-checked against `checksums::crc32c`'s
    /// TABLE form on real file I/O — the bit-wise streaming crc is
    /// result-identical).
    #[test]
    fn reverify_streaming_unchanged() {
        let base = std::env::temp_dir().join(format!(
            "frameprism_audit_reverify_stream_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        std::fs::create_dir_all(input.join("A001_001")).unwrap();
        let bytes: Vec<u8> = (0..1000u32).map(|i| ((i.wrapping_mul(31)) % 253) as u8).collect();
        std::fs::write(input.join("A001_001/f1.DNG"), &bytes).unwrap();
        let dest = base.join("out");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let rc = crate::offload::run_offload_multi(&input_c, &[dest.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "the fixture offload = rc 0");
        let m = crate::offload::parse_manifest(&dest.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
        let file = "A001_001/f1.DNG";
        let target = dest.join(file);
        let src_sha = jxl::sha256_hex(&bytes);
        // The CLEAN re-verify (the pinned summary line).
        let (lines, bad) = crate::offload::reverify(&m);
        assert_eq!(bad, 0, "the clean re-verify: {lines:?}");
        assert_eq!(
            lines,
            vec![format!(
                "audit: offload 1/1 file(s) OK ({}, dest {})",
                m.name,
                m.dest.display()
            )],
            "the clean summary line, pinned: {lines:?}"
        );
        // The SHA_MISMATCH (one flipped byte — the same size): the
        // disk sha re-derived with the ONE-SHOT helper (the cross-
        // proof), the line value-identical.
        let mut tampered = bytes.clone();
        tampered[0] ^= 0xFF;
        std::fs::write(&target, &tampered).unwrap();
        let (lines, bad) = crate::offload::reverify(&m);
        assert_eq!(bad, 1, "the tampered re-verify: {lines:?}");
        assert_eq!(
            lines[0],
            format!(
                "FAIL offload {file}: SHA_MISMATCH: source sha256 {src_sha}, disk {}",
                jxl::sha256_hex(&tampered)
            ),
            "the SHA_MISMATCH line, pinned: {lines:?}"
        );
        assert_eq!(
            lines[1],
            format!("audit: offload 0/1 file(s) OK ({}, dest {})", m.name, m.dest.display())
        );
        // The SIZE_MISMATCH (one appended byte): the line
        // value-identical (the disk size, pinned wording).
        let extended = { let mut e = bytes.clone(); e.push(0xAB); e };
        std::fs::write(&target, &extended).unwrap();
        let (lines, bad) = crate::offload::reverify(&m);
        assert_eq!(bad, 1, "the size-mismatch re-verify: {lines:?}");
        assert_eq!(
            lines[0],
            format!("FAIL offload {file}: SIZE_MISMATCH: manifest {} B, disk {} B", bytes.len(), extended.len()),
            "the SIZE_MISMATCH line, pinned: {lines:?}"
        );
        // The missing file: the pinned line.
        std::fs::remove_file(&target).unwrap();
        let (lines, bad) = crate::offload::reverify(&m);
        assert_eq!(bad, 1, "the missing-file re-verify: {lines:?}");
        assert_eq!(
            lines[0],
            format!("FAIL offload {file}: file missing in the offload dest {}", m.dest.display()),
            "the missing-file line, pinned: {lines:?}"
        );
        // check_row — the wordings UNCHANGED + the bit-wise crc's
        // table-form cross-check (a clean row with a crc column =
        // None only when the bit-wise streaming crc == the table
        // form's crc over the same on-disk file).
        let row = Row {
            file: "f1.DNG".to_string(),
            size: bytes.len() as u64,
            sha: src_sha.clone(),
            crc: Some(crate::checksums::crc32c(&bytes)),
            stem: "f1".to_string(),
        };
        let plain = base.join("f1.DNG");
        std::fs::write(&plain, &bytes).unwrap();
        assert_eq!(check_row(&plain, &row), None, "the clean row (bit-wise crc == table form): {plain:?}");
        // The sha tamper (the wording pinned + the one-shot disk sha).
        std::fs::write(&plain, &tampered).unwrap();
        assert_eq!(
            check_row(&plain, &row),
            Some(format!("sha256 mismatch: sidecar {src_sha}, disk {}", jxl::sha256_hex(&tampered))),
            "the check_row sha wording, pinned"
        );
        // The size mismatch (the wording pinned — checked BEFORE any
        // content read, the streaming pass's stat gate).
        std::fs::write(&plain, &extended).unwrap();
        assert_eq!(
            check_row(&plain, &row),
            Some(format!("size mismatch: sidecar {}, disk {}", bytes.len(), extended.len())),
            "the check_row size wording, pinned"
        );
        // The crc mismatch (the disk value = the TABLE form's crc of
        // the on-disk file — the cross-check, the wording pinned).
        std::fs::write(&plain, &bytes).unwrap();
        let bad_row = Row {
            file: row.file.clone(),
            size: row.size,
            sha: row.sha.clone(),
            crc: Some(0xDEAD_BEEF),
            stem: row.stem.clone(),
        };
        assert_eq!(
            check_row(&plain, &bad_row),
            Some(format!(
                "crc32c mismatch: sidecar deadbeef, disk {:08x}",
                crate::checksums::crc32c(&bytes)
            )),
            "the check_row crc wording, pinned (disk = the table form)"
        );
        // The missing file (the wording pinned).
        std::fs::remove_file(&plain).unwrap();
        assert_eq!(check_row(&plain, &row), Some("file missing".to_string()), "the check_row missing wording, pinned");
        let _ = std::fs::remove_dir_all(&base);
    }

    // =====================================================================
 // The in-process reader (the D4 legacy decision)
    // =====================================================================

 /// T2 (the D4 legacy decision): the committed legacy
 /// bsdtar fixture — built on the project machine
    /// (macos aarch64) with the EXACT legacy invocation
    /// (`tar --no-mac-metadata -cf - -C in <files…> | zstd -19 -q
    /// -T0 -o in.tar.zst`) on the system tools of the day — bsdtar
    /// 3.5.3 - libarchive 3.5.3 + zstd v1.5.7 (upstream author: Yann
    /// Collet). Provenance: `ci/container-legacy/README.md`.
    ///
    /// The asset = DATA, not a regeneration fixture: the sha256 below
    /// is pinned — the test re-hashes the committed file FIRST (the
    /// fixture's integrity re-proven on every run), then the
    /// in-process reader must read it: the member listing carries the
    /// 3 .DNGs (the bare member names — the manifest's relpath
    /// namespace) and each row's single-member stream hash passes
    /// against the INDEPENDENT expectations below (the members'
    /// generation-time sizes + sha256s — not read back from the
    /// fixture itself). A missing member / a bad stream hash is a
    /// named problem (the legacy container would audit FAIL, not
    /// skip).
    #[test]
    fn legacy_bsdtar_fixture_read() {
        let fixture = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../ci/container-legacy/legacy-clip.tar.zst"
        ));
        let bytes = std::fs::read(fixture)
            .expect("the committed legacy fixture is in the clone-ready tree (ci/container-legacy/)");
        let sha = jxl::sha256_hex(&bytes);
        assert_eq!(
            sha, "794e66066828c71afc864bc384615dc694f96848c5b7070eaaeef65b1380f9e8",
            "the fixture's pinned sha256 — a drift breaks the legacy-compatibility pin (the provenance note: ci/container-legacy/README.md)"
        );
        // The audit input dir: the fixture AS the clip's archive + a
        // hand-written manifest (the rows' size + sha256 columns are
        // the independent generation-time expectations).
        let tmp =
            std::env::temp_dir().join(format!("frameprism-legacy-fixture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("in.tar.zst"), &bytes).unwrap();
        std::fs::write(
            tmp.join("in.bake-manifest.tsv"),
            "# frameprism bake manifest\n\
             clip: in\n\
             container: tar.zst\n\
             file_count: 3\n\
             relpath\tsize\tsha256\n\
             L001_001_20260914_000001.DNG\t4096\t03ba6338939a0589937a311fe85de3fcb3e942e551f5b5fb4007e8e750022d83\n\
             L001_002_20260914_000001.DNG\t12288\t60db360acf44ddfe3e79df7ea66a3d5e08a66baae2cbd4c7eac0b92138abe65e\n\
             L001_003_20260914_000001.DNG\t7168\tb540dc66beaf4497f4891c8eb67d201b20e07aa8ebf98e2f013e9439df4227a8\n",        )
        .unwrap();
        let (reports, _shas) = audit_dir(&tmp, 1, true)
            .expect("the legacy container audits (no usage-level refusal)");
        // The sweep ran the 3 rows against the fixture (the member
        // listing + each row's stream hash): one report, 3 rows, ZERO
        // offenders (a missing member / a bad stream hash would be a
        // named offender, not a skip).
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert_eq!(reports[0].rows.len(), 3, "{reports:?}");
        assert!(
            reports[0].offenders.is_empty(),
            "the legacy bsdtar container reads clean in-process (the member listing + the 3 row stream-hashes pass): {reports:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

 /// T4 : the level-none RAW-TAR container round-trip —
    /// the in-process writer's `.tar` part (no zstd frame — the
    /// jxl-detect clip's auto path) reads back in-process: the member
    /// listing + each row's stream hash pass (the `open_container_part`
    /// magic sniff's raw-tar branch — no zstd frame magic → the raw
    /// reader).
    #[test]
    fn level_none_raw_tar_roundtrip() {
        let base =
            std::env::temp_dir().join(format!("frameprism-rawtar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let in_dir = base.join("in");
        std::fs::create_dir_all(&in_dir).unwrap();
        std::fs::write(in_dir.join("X001_001_20260914_000001.jxl"), vec![7u8; 3000]).unwrap();
        std::fs::write(in_dir.join("X001_002_20260914_000001.jxl"), vec![9u8; 5000]).unwrap();
        let out = base.join("out");
        crate::bake::run(&in_dir, &out, None, false, false)
            .expect("the level-none bake (jxl-detect → raw tar)");
        // The part is a raw tar (no zstd frame magic at its head).
        let part = out.join("in.tar");
        assert!(part.is_file(), "the container is the raw tar part: {part:?}");
        let head = std::fs::read(&part).unwrap();
        assert!(
            !(head.len() >= 4 && head[0] == 0x28 && head[1] == 0xB5 && head[2] == 0x2F && head[3] == 0xFD),
            "level none: no zstd frame magic (the raw-tar part)"
        );
        let (reports, _shas) = audit_dir(&out, 1, true)
            .expect("the raw-tar container audits (no usage-level refusal)");
        // One report (the clip's bake manifest), 2 rows, ZERO
        // offenders (the listing + the row stream-hashes pass).
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert_eq!(reports[0].rows.len(), 2, "{reports:?}");
        assert!(
            reports[0].offenders.is_empty(),
            "the level-none raw-tar container reads clean in-process: {reports:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
