//! The record audit: the ingest-continuity surface (the ingest
//! manifest's re-derivation via `worker::ingest_gate` from the
//! .DNG frames + the recorded-vs-re-derived disagreement) + the
//! offload-mirror re-verify surface (the `offload::reverify`
//! primitive over the recorded rows).

use std::path::{Path, PathBuf};

use crate::worker;
use super::sidecars::parse_size;

// =====================================================================
// Ingest-continuity surface
// =====================================================================

/// One per-clip row of the ingest manifest (the gate record —
/// `worker::write_ingest_manifest`).
#[derive(Debug)]
struct IngestRow {
    clip: String,
    frames: u64,
    manifest_declared: Option<u64>,
    frame_range: Option<(u64, u64)>,
    tc_start: Option<String>,
    tc_end: Option<String>,
}

/// The parsed ingest manifest (the additive versioned format — the
/// magic line is required, unknown `key: value` headers are skipped —
/// the bake-manifest-v2 convention; old records stay valid).
#[derive(Debug)]
struct IngestManifest {
    name: String,
    clip: String,
    version: String,
    gate: String,
    manifest_flag: Option<String>,
    frames_total: u64,
    rows: Vec<IngestRow>,
}

/// Parse an ingest manifest (the v1 format — `worker::write_ingest_
/// manifest`): the magic line, the `key: value` header lines (`clip`
/// required), the `clip\tframes\tmanifest_declared\tframe_range\
/// tc_start\ttc_end` column line, then the rows. A bad magic, a
/// missing clip field, a bad size/range field, a non-6-column row, or
/// a row before the column line is a hard named error (rc=2 usage —
/// the same convention as the bake-manifest parse).
fn parse_ingest_manifest(path: &Path) -> Result<IngestManifest, String> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tsv = std::fs::read_to_string(path)
        .map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut lines = tsv.lines().enumerate();
    let (_, magic) = lines.next().ok_or_else(|| format!("empty ingest manifest {name}"))?;
    if magic != "# frameprism ingest manifest" {
        return Err(format!(
            "{name} is not a frameprism ingest manifest (first line {magic:?}, want \"# frameprism ingest manifest\")"
        ));
    }
    let mut clip: Option<String> = None;
    let mut version = String::new();
    let mut gate = String::new();
    let mut manifest_flag: Option<String> = None;
    let mut frames_total: u64 = 0;
    let mut rows: Vec<IngestRow> = Vec::new();
    let mut column_seen = false;
    for (i, line) in lines {
        let lineno = i + 1;
        if line.is_empty() {
            continue;
        }
        if line.contains('\t') {
            if line == "clip\tframes\tmanifest_declared\tframe_range\ttc_start\ttc_end" {
                column_seen = true;
                continue;
            }
            if !column_seen {
                return Err(format!(
                    "row in {name} line {lineno} before the clip column line"
                ));
            }
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() != 6 {
                return Err(format!(
                    "bad row in {name} line {lineno}: {} columns (want 6: clip, frames, manifest_declared, frame_range, tc_start, tc_end)",
                    fields.len()
                ));
            }
            let frames = parse_size(fields[1], &name, lineno)?;
            let declared = if fields[2] == "-" {
                None
            } else {
                Some(parse_size(fields[2], &name, lineno)?)
            };
            let range = if fields[3] == "-" {
                None
            } else {
                let rng = fields[3];
                let (a, b) = rng
                    .split_once("..")
                    .ok_or_else(|| format!("bad frame_range {rng:?} in {name} line {lineno}"))?;
                Some((parse_size(a, &name, lineno)?, parse_size(b, &name, lineno)?))
            };
            rows.push(IngestRow {
                clip: fields[0].to_string(),
                frames,
                manifest_declared: declared,
                frame_range: range,
                tc_start: (fields[4] != "-").then(|| fields[4].to_string()),
                tc_end: (fields[5] != "-").then(|| fields[5].to_string()),
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
            "version" => version = value.trim().to_string(),
            "clip" => clip = Some(value.trim().to_string()),
            "gate" => gate = value.trim().to_string(),
            "manifest" => manifest_flag = Some(value.trim().to_string()),
            "frames" => frames_total = parse_size(value.trim(), &name, lineno)?,
            _ => {} // created / tool_version / host / clips / future keys
        }
    }
    let clip = clip.ok_or_else(|| format!("no clip field in {name}"))?;
    Ok(IngestManifest {
        name,
        clip,
        version,
        gate,
        manifest_flag,
        frames_total,
        rows,
    })
}

/// Discover the `*.ingest-manifest.tsv` records in `input` (top level,
/// sorted by path — the same discovery convention as the sidecars).
pub(crate) fn discover_ingest_manifests(input: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(input) {
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            // G1 (THE DEMONSTRATED BUG): the binary `._<clip>
            // .ingest-manifest.tsv` shadow ended in the suffix and was
            // parsed (the `stream did not contain valid UTF-8` rc=2,
            // pre-verdict) — the shadow is skipped, never read.
            if crate::is_apple_double(&name) {
                continue;
            }
            if name.ends_with(".ingest-manifest.tsv") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Discover the `*.offload-manifest.tsv` records (the two-destination
/// offload) in `input` (top level,
/// sorted by path — the same discovery convention as the sidecars).
fn discover_offload_manifests(input: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(input) {
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            //: the AppleDouble shadow is never an offload
            // manifest — skip (the shared predicate).
            if crate::is_apple_double(&name) {
                continue;
            }
            if name.ends_with(crate::offload::MANIFEST_SUFFIX) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Discover the standalone offload mirror's records (the
/// re-verify-a-backup-later surface): the
/// `*.offload-manifest.tsv` at `<input>` top level AND one level
/// deeper (the mirrored clip roots —
/// `<input>/<CLIP>/<CLIP>.offload-manifest.tsv`; the standalone
/// `offload` mirror's shape, exactly one level deep by construction
/// — a deeper walk would audit records the tool never wrote at those
/// depths). Sorted by path, the AppleDouble shadows skipped (the
/// shared predicate), the `MANIFEST_SUFFIX` match — the
/// `discover_offload_manifests` conventions (the top level IS that
/// discovery; the clip subdirs are the one-level extension).
pub(crate) fn discover_offload_mirror_manifests(input: &Path) -> Vec<PathBuf> {
    let mut out = discover_offload_manifests(input);
    if let Ok(rd) = std::fs::read_dir(input) {
        for e in rd.flatten() {
            let ft = match e.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if !ft.is_dir() || ft.is_symlink() {
                continue;
            }
            // The AppleDouble shadow of a clip dir is never a mirror
            // clip root — skip (the shared predicate).
            let key = e.file_name().to_string_lossy().into_owned();
            if crate::is_apple_double(&key) {
                continue;
            }
            let clip = e.path();
            if let Ok(rd2) = std::fs::read_dir(&clip) {
                for e2 in rd2.flatten() {
                    let p2 = e2.path();
                    if !p2.is_file() {
                        continue;
                    }
                    let name = e2.file_name().to_string_lossy().into_owned();
                    //: the AppleDouble shadow is never an offload
                    // manifest — skip (the shared predicate).
                    if crate::is_apple_double(&name) {
                        continue;
                    }
                    if name.ends_with(crate::offload::MANIFEST_SUFFIX) {
                        out.push(p2);
                    }
                }
            }
        }
    }
    out.sort();
    out
}

/// Discover the `*.members.tsv` member records (the non-frame members
/// of a clip, the additive next-to record: the
/// flat clip's `.members.tsv` dotfile included — the top-level
/// discovery convention of the other sidecars, sorted by path).
pub(crate) fn discover_members_records(input: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(input) {
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            //: the AppleDouble shadow is never a members
            // record — skip (the shared predicate).
            if crate::is_apple_double(&name) {
                continue;
            }
            if name == ".members.tsv" || name.ends_with(".members.tsv") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The ingest-continuity audit result: the lines for the caller to
/// print (in order) + the offender count (the rc contribution).
#[derive(Debug)]
pub struct IngestAuditResult {
    pub lines: Vec<String>,
    pub bad: usize,
}

/// The no-sidecar error from `audit_dir` (the stable contract message
/// — the one the ingest-manifest-only carve-out matches; a dir with a
/// sidecar of ANY kind never produces it).
pub(crate) fn is_no_sidecar_error(err: &str) -> bool {
    err.starts_with("no sidecar in ")
}

/// The ingest-continuity section of `frameprism audit` : 
/// for each `*.ingest-manifest.tsv` in `input` — the recorded
/// verdict (the per-clip rows) + the re-derivation of the SAME gate
/// (`worker::ingest_gate`) from the .DNG frames present in `input`
/// (the encoded outputs carry tag 51043 verbatim — the surgery's
/// metadata-preserved gate guarantees it). No DNGs present = the
/// recorded verdict + the named note (the re-derivation is not run —
/// re-derive from source DNGs ONLY when present). A re-derived
/// FAIL or a recorded-vs-re-derived disagreement = the named FAIL
/// lines (rc=1, the existing audit convention). `None` = no ingest
/// manifest in the dir (the caller prints nothing — the existing
/// sidecar-only output + rc stay byte-identical).
pub fn audit_ingest_manifests(input: &Path) -> Result<Option<IngestAuditResult>, String> {
    let paths = discover_ingest_manifests(input);
    if paths.is_empty() {
        return Ok(None);
    }
    let frames = worker::collect_dng_frames(input)?;
    let mut lines: Vec<String> = Vec::new();
    let mut bad = 0usize;
    for p in &paths {
        let m = parse_ingest_manifest(p)?;
        lines.push(format!(
            "ingest continuity ({}): recorded {} — clip {}, manifest version {}, {} clip(s), {} frame(s), input manifest {}",
            m.name, m.gate, m.clip, m.version, m.rows.len(), m.frames_total,
            m.manifest_flag.as_deref().unwrap_or("unknown")
        ));
        for r in &m.rows {
            lines.push(format!(
                "  clip={}: {} frame(s) (manifest: {}) range {} TC {}",
                worker::display_clip(&r.clip),
                r.frames,
                r.manifest_declared
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "-".into()),
                r.frame_range
                    .map(|(a, b)| format!("{a}..{b}"))
                    .unwrap_or_else(|| "-".into()),
                match (&r.tc_start, &r.tc_end) {
                    (Some(a), Some(b)) => format!("{a}..{b}"),
                    (Some(a), None) | (None, Some(a)) => format!("{a}..?"),
                    (None, None) => "-".into(),
                }
            ));
        }
        let mut manifest_bad = false;
        if frames.is_empty() {
            lines.push(format!(
                "  note: no DNG frames in {} — re-derivation not run (recorded verdict only)",
                input.display()
            ));
        } else {
            let gate = worker::ingest_gate(input, &frames);
            if !gate.is_pass() {
                for line in gate.failures() {
                    lines.push(line);
                }
                manifest_bad = true;
                lines.push(format!(
                    "FAIL {} — re-derived gate is FAIL (recorded verdict: {})",
                    m.name, m.gate
                ));
            } else {
                // The recorded-vs-re-derived agreement: the fields both
                // sides always know (per-clip frames / frame range / TC
                // range) + the manifest count when the re-derivation
                // also saw a manifest.tsv (absent on one side = not
                // comparable, not a mismatch). Both directions: a clip
                // recorded but gone from disk, or re-derived but never
                // recorded (added after the ingest).
                let mut mismatches: Vec<String> = Vec::new();
                for r in &m.rows {
                    match gate.clips.iter().find(|c| c.clip == r.clip) {
                        None => mismatches.push(format!(
                            "clip {} is recorded but has no DNG frames on disk (not re-derived)",
                            worker::display_clip(&r.clip)
                        )),
                        Some(g) => {
                            if g.frames_found != r.frames {
                                mismatches.push(format!(
                                    "clip {}: frames recorded {} vs re-derived {}",
                                    worker::display_clip(&r.clip),
                                    r.frames,
                                    g.frames_found
                                ));
                            }
                            if g.frame_range != r.frame_range {
                                mismatches.push(format!(
                                    "clip {}: frame range recorded {:?} vs re-derived {:?}",
                                    worker::display_clip(&r.clip),
                                    r.frame_range,
                                    g.frame_range
                                ));
                            }
                            if g.tc_start.as_deref() != r.tc_start.as_deref()
                                || g.tc_end.as_deref() != r.tc_end.as_deref()
                            {
                                mismatches.push(format!(
                                    "clip {}: TC range recorded {}..{} vs re-derived {}..{}",
                                    worker::display_clip(&r.clip),
                                    r.tc_start.clone().unwrap_or_else(|| "-".into()),
                                    r.tc_end.clone().unwrap_or_else(|| "-".into()),
                                    g.tc_start.clone().unwrap_or_else(|| "-".into()),
                                    g.tc_end.clone().unwrap_or_else(|| "-".into())
                                ));
                            }
                            if let Some(d) = r.manifest_declared {
                                if let Some(gd) = g.manifest_declared {
                                    if gd != d {
                                        mismatches.push(format!(
                                            "clip {}: manifest-declared count recorded {d} vs re-derived {gd}",
                                            worker::display_clip(&r.clip)
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                for g in &gate.clips {
                    if !m.rows.iter().any(|r| r.clip == g.clip) {
                        mismatches.push(format!(
                            "clip {} is re-derived from disk but was never recorded (added after the ingest?)",
                            worker::display_clip(&g.clip)
                        ));
                    }
                }
                if mismatches.is_empty() {
                    lines.push(format!(
                        "  re-derived from {} DNG frame(s) in {}: PASS — matches the recorded verdict",
                        frames.len(),
                        input.display()
                    ));
                } else {
                    manifest_bad = true;
                    for x in &mismatches {
                        lines.push(format!(
                            "FAIL {} — recorded verdict disagrees with the re-derived gate: {x}",
                            m.name
                        ));
                    }
                }
            }
            // The reel re-derivation (from the DNGs — the
            // pattern): the per-clip tc_first sequence +
            // the monotonicity verdict. Runs on BOTH branches
            // (the named pair line(s) are printed VERBATIM by the
            // re-derived-gate-FAIL branch above when the reel
            // fails — a reel violation is a gate FAIL that rides
            // the audit's documented offender rc=1; this block adds the
            // sequence + the reel verdict line only).
            let seq = gate
                .clips
                .iter()
                .map(|c| {
                    format!(
                        "{}:{}",
                        worker::display_clip(&c.clip),
                        c.tc_start.clone().unwrap_or_else(|| "-".into())
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            if gate.reel.is_pass() {
                lines.push(format!(
                    "  reel gate: PASS — tc_first sequence [{seq}] ({} pair(s): all strictly after the previous clip's tc_end — the gaps are free)",
                    gate.reel.pairs.len()
                ));
            } else {
                lines.push(format!(
                    "  reel gate: FAIL — tc_first sequence [{seq}] ({} named REEL_OVERLAP pair(s))",
                    gate.reel.failures.len()
                ));
            }
        }
        bad += usize::from(manifest_bad);
        lines.push(format!(
            "audit: ingest continuity {} ({})",
            if manifest_bad { "FAIL" } else { &m.gate },
            m.name
        ));
    }
    //: the camera line (the additive identity surface — the
    // keyless claim: the profile set + the DNG frames, nothing else —
    // the audit does not need the archive bytes nor a key). The SAMPLE
    // is the first frame of the dir (deterministic — the v1 sample; a
    // full per-frame audit resolution is a candidate, the
    // encode already resolved every frame at encode time). The line is
    // OPTIONAL for the PASS (like the signature ABSENT line): ABSENT
    // leaves the verdict untouched; a MISMATCH is the named offender
    // (the audit-side re-derived violation rides rc=1 — the encode
    // path keeps rc=2).
    let (camera_line, camera_bad) = crate::camera::audit_camera_line(input, &frames);
    if camera_bad {
        bad += 1;
    }
    lines.push(camera_line);
    Ok(Some(IngestAuditResult { lines, bad }))
}

/// The offload re-verify audit result: the lines for the caller to
/// print (in order — the per-manifest re-verify lines, the surface's
/// verdict line last when the standalone branch fired) + the
/// offender count (the rc contribution).
#[derive(Debug)]
pub struct OffloadAuditResult {
    pub lines: Vec<String>,
    pub bad: usize,
}

/// The offload re-verify section of `frameprism audit` (the
/// re-verify-a-backup-later pass): for each discovered
/// `*.offload-manifest.tsv` record — the re-read of every row's DEST
/// file against the recorded size + the canonical source sha256
/// (`offload::reverify` — the line formats are the contract,
/// verbatim — never a fork). `standalone` = the standalone branch
/// fired (the no-sidecar dir carrying the records): the discovery is
/// the two-level (root + the one-level clip roots — the mirror's
/// shape) + the surface's verdict line lands at the end (the
/// reel/recursive verdict-line idiom; its count is the
/// surface's own — every dirty row, never stopping at the first
/// offender). A sidecar-carrying dir keeps the top-level-only
/// discovery + the per-manifest lines only (the encode-side shape,
/// unchanged — R-INV). `Ok(None)` = no record discovered (the caller
/// prints nothing — the existing output + rc stand byte-identical).
/// A bad manifest (parse) = the named hard error (the caller's rc=2
/// — the usage contract, the ingest-manifest convention).
pub fn audit_offload_manifests(
    input: &Path,
    standalone: bool,
) -> Result<Option<OffloadAuditResult>, String> {
    let paths = if standalone {
        discover_offload_mirror_manifests(input)
    } else {
        discover_offload_manifests(input)
    };
    if paths.is_empty() {
        return Ok(None);
    }
    let mut lines: Vec<String> = Vec::new();
    let mut bad: usize = 0;
    let mut manifests: usize = 0;
    let mut rows: usize = 0;
    for p in &paths {
        let m = crate::offload::parse_manifest(p)?;
        manifests += 1;
        rows += m.rows.len();
        let (rlines, rbad) = crate::offload::reverify(&m);
        bad += rbad;
        lines.extend(rlines);
    }
    if standalone {
        if bad == 0 {
            lines.push(format!(
                "audit: offload re-verify {}: {} manifest(s), {} row(s) OK",
                input.display(),
                manifests,
                rows
            ));
        } else {
            lines.push(format!(
                "audit: offload re-verify {}: {} manifest(s), {} row(s) FAIL ({} named offender(s))",
                input.display(),
                manifests,
                rows,
                bad
            ));
        }
    }
    Ok(Some(OffloadAuditResult { lines, bad }))
}

#[cfg(test)]
mod tests {
    use super::*;
use std::process::ExitCode;
    use crate::audit::testutil::*;

    #[test]
    fn audit_ingest_recorded_and_rederived_clean() {
        let tmp = std::env::temp_dir().join(format!("frameprism-a12-clean-{}", std::process::id()));
        mk_audit_dir(
            &tmp,
            &[(
                "A",
                vec![
                    ("A_20260101_000001.DNG", tc_of(0, 0, 0, 0)),
                    ("A_20260101_000002.DNG", tc_of(0, 0, 0, 1)),
                    ("A_20260101_000003.DNG", tc_of(0, 0, 0, 2)),
                ],
            )],
            None,
        );
        assert_eq!(run(&tmp), ExitCode::SUCCESS, "clean record + clean re-derivation = rc 0 (the no-sidecar carve-out prints the note to stderr)");
        // The re-derivation actually ran against the on-disk frames.
        let res = audit_ingest_manifests(&tmp).unwrap().unwrap();
        assert_eq!(res.bad, 0);
        assert!(
            res.lines.iter().any(|l| l.starts_with("ingest continuity (")),
            "the recorded-verdict header line: {res:?}"
        );
        assert!(
            res.lines.iter().any(|l| l.contains("clip=A: 3 frame(s)")),
            "the per-clip row: {res:?}"
        );
        assert!(
            res.lines.iter().any(|l| l.contains("re-derived from 3 DNG frame(s)")),
            "the re-derivation verdict: {res:?}"
        );
        let mname = format!("{}.ingest-manifest.tsv", tmp.file_name().unwrap().to_string_lossy());
        assert!(
            res.lines.iter().any(|l| l == &format!("audit: ingest continuity PASS ({mname})")),
            "the summary line: {res:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn audit_ingest_no_dngs_recorded_only() {
        let tmp = std::env::temp_dir().join(format!("frameprism-a12-nodng-{}", std::process::id()));
        mk_audit_dir(
            &tmp,
            &[("A", vec![("A_20260101_000001.DNG", tc_of(0, 0, 0, 0))])],
            None,
        );
        // Remove the DNGs: the record stands alone (the encoded-dir shape
        // with no source DNGs — recorded verdict only).
        let _ = std::fs::remove_dir_all(tmp.join("A"));
        assert_eq!(run(&tmp), ExitCode::SUCCESS, "recorded PASS, no DNGs = rc 0");
        let res = audit_ingest_manifests(&tmp).unwrap().unwrap();
        assert_eq!(res.bad, 0);
        assert!(
            res.lines.iter().any(|l| l.contains("no DNG frames in") && l.contains("re-derivation not run (recorded verdict only)")),
            "the named note: {res:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn audit_ingest_rederived_tc_gap_named() {
        let tmp = std::env::temp_dir().join(format!("frameprism-a12-tc-{}", std::process::id()));
        mk_audit_dir(
            &tmp,
            &[("A", vec![
                ("A_20260101_000001.DNG", tc_of(0, 0, 0, 0)),
                ("A_20260101_000002.DNG", tc_of(0, 0, 0, 1)),
            ])],
            None,
        );
        // Corrupt frame 3's TC on disk AFTER the record (a 2-frame skip
        // at the pair 2->3): the re-derivation must name the TC_GAP even
        // though the record says PASS.
        let a = tmp.join("A");
        std::fs::write(a.join("A_20260101_000003.DNG"), synthetic_dng(Some(tc_payload(&tc_of(0, 0, 0, 4))))).unwrap();
        assert_eq!(run(&tmp), ExitCode::from(1), "a re-derived TC FAIL = rc 1 (the existing audit convention)");
        let res = audit_ingest_manifests(&tmp).unwrap().unwrap();
        assert!(res.bad >= 1);
        assert!(
            res.lines.iter().any(|l| l.starts_with("FAIL TC_GAP") && l.contains("00:00:00:01 -> 00:00:00:04") && l.contains("delta +3")),
            "the named TC_GAP with the raw TCs + delta: {res:?}"
        );
        assert!(
            res.lines.iter().any(|l| l.starts_with("FAIL ") && l.contains("re-derived gate is FAIL (recorded verdict: PASS)")),
            "the stale-record FAIL: {res:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn audit_ingest_recorded_rederived_mismatch_named() {
        let tmp = std::env::temp_dir().join(format!("frameprism-a12-mm-{}", std::process::id()));
        // Record claims 4 frames for clip A; disk has 3 (a frame dropped
        // after the ingest). The gate re-derives clean (no contiguity
        // fault), but the count disagreement is a named FAIL.
        mk_audit_dir(
            &tmp,
            &[("A", vec![
                ("A_20260101_000001.DNG", tc_of(0, 0, 0, 0)),
                ("A_20260101_000002.DNG", tc_of(0, 0, 0, 1)),
                ("A_20260101_000003.DNG", tc_of(0, 0, 0, 2)),
            ])],
            Some(&[("A", 4)]),
        );
        assert_eq!(run(&tmp), ExitCode::from(1), "recorded/re-derived disagreement = rc 1");
        let res = audit_ingest_manifests(&tmp).unwrap().unwrap();
        assert!(
            res.lines.iter().any(|l| l.starts_with("FAIL ") && l.contains("frames recorded 4 vs re-derived 3")),
            "the named count disagreement: {res:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // =====================================================================
    // — the reel gate's audit re-derivation (the pattern:
    // audit re-derives the gate FROM THE DNGs, not from the record).
    // The re-derived reel violation rides the documented audit
    // offender class (rc=1) (the ingest gate's rc=2 is the encode-time refusal).
    // =====================================================================

    #[test]
    fn p72_audit_reel_rederived_pass_monotonic_sequence_reported() {
        // Two clips in TC order (A: 0..2, B: 5..6 — a free 2-frame gap
        // is NOT a span claim): the re-derivation reports the
        // per-clip tc_first sequence + the monotonicity verdict.
        let tmp = std::env::temp_dir().join(format!("frameprism-a72-pass-{}", std::process::id()));
        mk_audit_dir(
            &tmp,
            &[
                (
                    "A",
                    vec![
                        ("A_20260101_000001.DNG", tc_of(0, 0, 0, 0)),
                        ("A_20260101_000002.DNG", tc_of(0, 0, 0, 1)),
                        ("A_20260101_000003.DNG", tc_of(0, 0, 0, 2)),
                    ],
                ),
                (
                    "B",
                    vec![
                        ("B_20260101_000001.DNG", tc_of(0, 0, 0, 5)),
                        ("B_20260101_000002.DNG", tc_of(0, 0, 0, 6)),
                    ],
                ),
            ],
            None,
        );
        assert_eq!(run(&tmp), ExitCode::SUCCESS, "a monotonic reel is rc 0");
        let res = audit_ingest_manifests(&tmp).unwrap().unwrap();
        assert_eq!(res.bad, 0, "{res:?}");
        assert!(
            res.lines.iter().any(|l| l.contains("reel gate: PASS")),
            "the reel verdict line: {res:?}"
        );
        assert!(
            res.lines.iter().any(|l| l.contains("tc_first sequence [A:00:00:00:00, B:00:00:00:05]")),
            "the per-clip tc_first sequence: {res:?}"
        );
        assert!(
            res.lines.iter().any(|l| l.contains("(1 pair(s): all strictly after the previous clip's tc_end")),
            "the pair count + the free-gap wording: {res:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn p72_audit_reel_rederived_overlap_named_offender_rc1() {
        // The REVERSED order (clip dir A carries the LATER TC range
        // 3..5, clip dir B the earlier 0..2 — the ingest order is A, B
        // by the sorted clip keys): the on-disk reel is an overlap. The
        // record says PASS (the recorded claim — the gate refused at
        // ingest, so this simulates a post-ingest divergence); the
        // audit re-derives FROM THE DNGs and names the offender
 // (rc=1 — the audit's documented offender class, the rc decision).
        let tmp = std::env::temp_dir().join(format!("frameprism-a72-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("A")).unwrap();
        std::fs::create_dir_all(tmp.join("B")).unwrap();
        std::fs::write(tmp.join("A/A_20260101_000001.DNG"), synthetic_dng(Some(tc_payload(&tc_of(0, 0, 0, 3))))).unwrap();
        std::fs::write(tmp.join("A/A_20260101_000002.DNG"), synthetic_dng(Some(tc_payload(&tc_of(0, 0, 0, 4))))).unwrap();
        std::fs::write(tmp.join("A/A_20260101_000003.DNG"), synthetic_dng(Some(tc_payload(&tc_of(0, 0, 0, 5))))).unwrap();
        std::fs::write(tmp.join("B/B_20260101_000001.DNG"), synthetic_dng(Some(tc_payload(&tc_of(0, 0, 0, 0))))).unwrap();
        std::fs::write(tmp.join("B/B_20260101_000002.DNG"), synthetic_dng(Some(tc_payload(&tc_of(0, 0, 0, 1))))).unwrap();
        std::fs::write(tmp.join("B/B_20260101_000003.DNG"), synthetic_dng(Some(tc_payload(&tc_of(0, 0, 0, 2))))).unwrap();
        // The gate over the on-disk frames: the reel FAIL (the ingest
        // refuses — the record is the recorded-claim simulation).
        let frames = worker::collect_dng_frames(&tmp).unwrap();
        let gate = worker::ingest_gate(&tmp, &frames);
        assert!(!gate.is_pass(), "the fixture must fail its own reel gate: {:?}", gate.failures());
        assert!(gate.clips.iter().all(|c| c.failures.is_empty()), "the per-clip gates stay clean");
        worker::write_ingest_manifest(&tmp, &tmp, &gate).unwrap();
        // The audit: the named offender (rc=1) + the reel verdict line
        // + the sequence + the verbatim pair line.
        assert_eq!(run(&tmp), ExitCode::from(1), "a re-derived reel violation is the named rc 1 (the audit's offender class — the rc decision)");
        let res = audit_ingest_manifests(&tmp).unwrap().unwrap();
        assert_eq!(res.bad, 1, "{res:?}");
        assert!(
            res.lines.iter().any(|l| l.contains("reel gate: FAIL")),
            "the reel verdict line: {res:?}"
        );
        assert!(
            res.lines.iter().any(|l| l.contains("tc_first sequence [A:00:00:00:03, B:00:00:00:00]")),
            "the sequence (the divergence is visible): {res:?}"
        );
        assert!(
            res.lines.iter().any(|l| l.contains("FAIL REEL_OVERLAP clip=A -> clip=B")),
            "the named pair line, verbatim: {res:?}"
        );
        assert!(
            res.lines.iter().any(|l| l.contains("earlier by 5 frame(s)")),
            "the named relation + magnitude (delta = next_first 0 - prev_end 5 = -5): {res:?}"
        );
        assert!(
            res.lines.iter().any(|l| l.starts_with("audit: ingest continuity FAIL (")),
            "the summary flips FAIL: {res:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // -------------------------------------------------------------------
    //: the AppleDouble `._*` shadow robustness (the
    // field incident — the binary shadow changed behavior at every
    // glob-driven discovery boundary; the shared predicate skips it).
    // -------------------------------------------------------------------

    /// G1 — the regression shape (THE DEMONSTRATED BUG, fixed): a
    /// tree with a valid `A.ingest-manifest.tsv` + a BINARY
    /// `._A.ingest-manifest.tsv` (garbage bytes — the field shape) →
    /// discovery returns exactly ONE (the real one) and the audit
    /// proceeds (no UTF-8 refusal — the pre-fix class was the
    /// `stream did not contain valid UTF-8` rc=2, pre-verdict).
    #[test]
    fn spec7_g1_ingest_manifest_discovery_skips_the_binary_shadow() {
        let tmp = std::env::temp_dir().join(format!("frameprism-spec7-g1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let clip = tmp.join("A");
        std::fs::create_dir_all(&clip).unwrap();
        std::fs::write(
            clip.join("A_20260101_000001.DNG"),
            synthetic_dng(Some(tc_payload(&tc_of(0, 0, 0, 0)))),
        )
        .unwrap();
        std::fs::write(
            clip.join("A_20260101_000002.DNG"),
            synthetic_dng(Some(tc_payload(&tc_of(0, 0, 0, 1)))),
        )
        .unwrap();
        // The valid record (the real one — the SAME worker functions
        // the ingest pass uses; the record's name = the input root's
        // clip name — the single-clip-reel convention, the field's
        // `CINEMA.ingest-manifest.tsv` shape).
        let frames = worker::collect_dng_frames(&tmp).unwrap();
        let gate = worker::ingest_gate(&tmp, &frames);
        assert!(gate.is_pass(), "the fixture must pass its own gate: {:?}", gate.failures());
        worker::write_ingest_manifest(&tmp, &tmp, &gate).unwrap();
        let clip = crate::checksums::clip_name(&tmp).unwrap();
        let real = tmp.join(format!("{clip}.ingest-manifest.tsv"));
        // The BINARY shadow (the field shape — garbage bytes, not
        // UTF-8): it ends in the suffix, so the pre-fix discovery
        // returned it and the pre-fix parse refused.
        std::fs::write(tmp.join(format!("._{clip}.ingest-manifest.tsv")), vec![0xFFu8, 0xFE, 0xFF, 0x00, 0xFF]).unwrap();
        // G1 suite-level: discovery returns EXACTLY the real path.
        let found = discover_ingest_manifests(&tmp);
        assert_eq!(
            found,
            vec![real],
            "the shadow must not be discovered: {found:?}"
        );
        // The audit's ingest-continuity path PROCEEDS (the pre-fix
        // refusal was this call's Err → the rc=2 pre-verdict class):
        let res = audit_ingest_manifests(&tmp)
            .expect("the audit must proceed — the pre-fix class was the `stream did not contain valid UTF-8` Err (rc=2, pre-verdict)");
        let res = res.expect("the real manifest was discovered");
        assert_eq!(res.bad, 0, "the clean fixture's ingest continuity is clean: {res:?}");
        // The full verb: the shadowed tree audits clean (the shadow is
        // invisible to the audit — no rc=2, no named offender).
        assert_eq!(
            run(&tmp),
            ExitCode::SUCCESS,
            "the shadowed tree audits clean (the rc=2 pre-verdict UTF-8 refusal is gone)"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// G2-2: the audit's offload-manifest discovery — real + `._`
    /// shadow → 1 (the real one).
    #[test]
    fn spec7_g2_offload_manifest_discovery_skips_the_shadow() {
        let tmp = std::env::temp_dir().join(format!("frameprism-spec7-g2-offload-{}", std::process::id()));
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

    /// G2-3: the audit's members-record discovery — real + `._` shadow
    /// → 1 (the real one).
    #[test]
    fn spec7_g2_members_record_discovery_skips_the_shadow() {
        let tmp = std::env::temp_dir().join(format!("frameprism-spec7-g2-members-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("C.members.tsv"), "header\n").unwrap();
        std::fs::write(tmp.join("._C.members.tsv"), vec![0xFF, 0xFE]).unwrap();
        let found = discover_members_records(&tmp);
        assert_eq!(
            found,
            vec![tmp.join("C.members.tsv")],
            "real + shadow → 1 (the real one): {found:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // =====================================================================
    // The standalone offload mirror's re-verify surface (the re-
    // verify-a-backup-later pass — the no-sidecar branch; the encode-
    // side shape is R-INV, pinned below)
    // =====================================================================

    #[test]
    fn audit_standalone_mirror_clean_rc0_and_ok_verdict() {
        let (base, mirror) = mk_offload_mirror("clean");
        assert_eq!(
            run(&mirror),
            ExitCode::SUCCESS,
            "every row verifies clean = rc 0 (the no-sidecar carve-out prints the note to stderr)"
        );
        // The pure surface half (the lines + the rc contribution):
        // 3 manifests (2 clip roots + the source-root manifest), 4
        // rows, zero offenders, zero FAIL lines.
        let res = audit_offload_manifests(&mirror, true)
            .unwrap()
            .expect("the mirror's records were discovered");
        assert_eq!(res.bad, 0, "{res:?}");
        assert!(
            res.lines.iter().all(|l| !l.starts_with("FAIL ")),
            "zero FAIL lines: {res:?}"
        );
        // The surface's verdict line (the one new format — the
        // reel/recursive verdict-line idiom, pinned).
        assert_eq!(
            res.lines.last().map(String::as_str),
            Some(
                format!("audit: offload re-verify {}: 3 manifest(s), 4 row(s) OK", mirror.display())
                    .as_str()
            ),
            "the OK verdict line: {res:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn audit_standalone_mirror_sha_mismatch_named_rc1() {
        let (base, mirror) = mk_offload_mirror("sha");
        // Flip one byte of one mirrored dest file (same size — the
        // post-run corruption the re-verify exists to catch).
        let victim = mirror.join("A001_001/f1.wav");
        let mut buf = std::fs::read(&victim).unwrap();
        buf[0] ^= 0xFF;
        std::fs::write(&victim, buf).unwrap();
        assert_eq!(run(&mirror), ExitCode::from(1), "the dirty row = the named rc 1");
        let res = audit_offload_manifests(&mirror, true).unwrap().unwrap();
        assert_eq!(res.bad, 1, "exactly the corrupted row: {res:?}");
        assert!(
            res.lines.iter().any(|l| l.starts_with("FAIL offload A001_001/f1.wav") && l.contains("SHA_MISMATCH: source sha256")),
            "the named SHA_MISMATCH line (the reverify format verbatim): {res:?}"
        );
        assert_eq!(
            res.lines.last().map(String::as_str),
            Some(
                format!(
                    "audit: offload re-verify {}: 3 manifest(s), 4 row(s) FAIL (1 named offender(s))",
                    mirror.display()
                )
                .as_str()
            ),
            "the verdict line carries the count: {res:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn audit_standalone_mirror_file_missing_named_rc1() {
        let (base, mirror) = mk_offload_mirror("missing");
        std::fs::remove_file(mirror.join("B002_002/g1.wav")).unwrap();
        assert_eq!(
            run(&mirror),
            ExitCode::from(1),
            "the vanished dest file = the named rc 1"
        );
        let res = audit_offload_manifests(&mirror, true).unwrap().unwrap();
        assert_eq!(res.bad, 1, "{res:?}");
        assert!(
            res.lines.iter().any(|l| l.starts_with("FAIL offload B002_002/g1.wav") && l.contains("file missing in the offload dest")),
            "the named missing line (the reverify format verbatim): {res:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn audit_standalone_mirror_size_mismatch_named_rc1() {
        let (base, mirror) = mk_offload_mirror("size");
        // A dest file with the wrong size vs the recorded row
        // (8 B recorded, 5 B on disk — the SIZE check fires first,
        // named).
        std::fs::write(mirror.join("A001_001/f1.wav"), b"short").unwrap();
        assert_eq!(
            run(&mirror),
            ExitCode::from(1),
            "the size-mismatched row = the named rc 1"
        );
        let res = audit_offload_manifests(&mirror, true).unwrap().unwrap();
        assert_eq!(res.bad, 1, "{res:?}");
        assert!(
            res.lines.iter().any(|l| l.starts_with("FAIL offload A001_001/f1.wav") && l.contains("SIZE_MISMATCH: manifest 8 B, disk 5 B")),
            "the named SIZE_MISMATCH line (the reverify format verbatim): {res:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn audit_standalone_mirror_bad_manifest_rc2() {
        // A corrupt magic → the named hard rc=2 (the usage contract —
        // the record is untrustable, never a silent skip).
        let (base, mirror) = mk_offload_mirror("bad");
        std::fs::write(
            mirror.join("B002_002/B002_002.offload-manifest.tsv"),
            "# not a manifest\n",
        )
        .unwrap();
        assert_eq!(
            run(&mirror),
            ExitCode::from(2),
            "a corrupt manifest = the named hard rc=2, not a silent skip"
        );
        let err = audit_offload_manifests(&mirror, true).unwrap_err();
        assert!(
            err.contains("is not a frameprism offload manifest"),
            "the named refusal: {err}"
        );
        // A bad row (a non-5-column row) is the same class.
        let (base2, mirror2) = mk_offload_mirror("badrow");
        let p = mirror2.join("B002_002/B002_002.offload-manifest.tsv");
        let mut t = std::fs::read_to_string(&p).unwrap();
        t.push_str("g1.wav\t5\n");
        std::fs::write(&p, t).unwrap();
        assert_eq!(run(&mirror2), ExitCode::from(2), "a bad row = the same named class");
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&base2);
    }

    #[test]
    fn audit_encode_side_tree_with_sidecar_and_top_level_manifest_unchanged() {
        // The encode-side shape (R-INV): a sidecar-carrying dir with
        // a top-level offload manifest + a clip-subdir manifest the
        // pre-audit audit never swept. The audit takes the sidecar
        // path (no standalone note) + sweeps the TOP-LEVEL record
        // only, the pre-audit lines only (no surface verdict line).
        let tmp = std::env::temp_dir().join(format!("frameprism-rinv_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir_all(tmp.join("A001_001")).unwrap();
        let tmp_c = std::fs::canonicalize(&tmp).unwrap();
        let frame = b"encoded-frame-bytes";
        std::fs::write(tmp.join("f1.DNG"), frame).unwrap();
        let crc = crate::checksums::crc32c(frame);
        let sha = crate::jxl::sha256_hex(frame);
        std::fs::write(
            tmp.join("CLIP.checksums.tsv"),
            format!("file\tsize\tcrc32c\tsha256\nf1.DNG\t{}\t{crc:08x}\t{sha}\n", frame.len()),
        )
        .unwrap();
        // The top-level manifest (the encode output's shape — beside
        // the sidecars) + the clip-subdir manifest (the standalone
        // shape, present here ONLY to prove the encode-side sweep
        // does not reach it).
        mk_offload_manifest(&tmp.join("C.offload-manifest.tsv"), "CLIP", &tmp_c, &[("f1.DNG", frame)]);
        let clipf = b"clip-frame-bytes";
        std::fs::write(tmp.join("A001_001/g1.DNG"), clipf).unwrap();
        mk_offload_manifest(
            &tmp.join("A001_001/A001_001.offload-manifest.tsv"),
            "A001_001",
            &tmp_c.join("A001_001"),
            &[("g1.DNG", clipf)],
        );
        // The sweep (the pure half): the top-level record ONLY — the
        // per-manifest line only, NO surface verdict line (R-INV:
        // the encode-side output is the pre-audit output).
        let res = audit_offload_manifests(&tmp_c, false)
            .unwrap()
            .expect("the top-level record was discovered");
        assert_eq!(res.bad, 0, "{res:?}");
        assert_eq!(res.lines.len(), 1, "the per-manifest line only: {res:?}");
        assert!(
            res.lines[0].starts_with("audit: offload 1/1 file(s) OK (C.offload-manifest.tsv"),
            "the per-manifest line format: {res:?}"
        );
        assert!(
            !res.lines.iter().any(|l| l.starts_with("audit: offload re-verify ")),
            "no surface verdict line on the encode-side shape: {res:?}"
        );
        assert!(
            !res.lines.iter().any(|l| l.contains("A001_001.offload-manifest.tsv")),
            "the clip-subdir record is NOT swept on a sidecar-carrying dir: {res:?}"
        );
        // The full verb: the sidecar path stands (rc=0 — the sidecar
        // sweep + the top-level record clean; the standalone note
        // never fires).
        assert_eq!(run(&tmp_c), ExitCode::SUCCESS, "the sidecar-carrying dir audits as pre-audit");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn audit_standalone_mirror_skips_the_apple_double_shadows() {
        // The binary `._` shadow twins (the field incident
        // shape — the shared predicate at every glob-driven discovery
        // boundary): the audit sees the real manifests only.
        let (base, mirror) = mk_offload_mirror("shadow");
        std::fs::write(
            mirror.join("._B002_002.offload-manifest.tsv"),
            vec![0xFFu8, 0xFE, 0xFF, 0x00, 0xFF],
        )
        .unwrap();
        std::fs::write(
            mirror.join("B002_002/._B002_002.offload-manifest.tsv"),
            vec![0xFFu8, 0xFE, 0xFF, 0x00, 0xFF],
        )
        .unwrap();
        // The two-level discovery returns EXACTLY the 3 real paths
        // (sorted; the shadows invisible — the shared predicate).
        let found = discover_offload_mirror_manifests(&mirror);
        assert_eq!(
            found,
            vec![
                mirror.join("A001_001/A001_001.offload-manifest.tsv"),
                mirror.join("B002_002/B002_002.offload-manifest.tsv"),
                mirror.join("in.offload-manifest.tsv"),
            ],
            "real manifests only, sorted: {found:?}"
        );
        // The full verb proceeds clean (the pre-fix class was the
        // `stream did not contain valid UTF-8` rc=2, pre-verdict).
        assert_eq!(
            run(&mirror),
            ExitCode::SUCCESS,
            "the shadowed mirror audits clean (the shadow is invisible to the audit)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn audit_standalone_mirror_sweeps_every_manifest_not_just_the_first() {
        // Two manifests, one dirty: the sweep NEVER stops at the
        // first offender — every manifest's rows are re-read,
        // the clean manifests' rows named absent-of-FAIL (their own
        // per-manifest lines), the dirty row named.
        let (base, mirror) = mk_offload_mirror("sweep");
        // Corrupt the MIDDLE manifest's file (the sweep order is the
        // sorted path order: A001_001, then B002_002, then the
        // source-root manifest — a sweep that stopped at the first
        // offender would skip the last one).
        std::fs::remove_file(mirror.join("B002_002/g1.wav")).unwrap();
        assert_eq!(run(&mirror), ExitCode::from(1), "the dirty row = the named rc 1");
        let res = audit_offload_manifests(&mirror, true).unwrap().unwrap();
        assert_eq!(res.bad, 1, "exactly the missing row: {res:?}");
        assert!(
            res.lines.iter().any(|l| l.starts_with("FAIL offload B002_002/g1.wav")),
            "the dirty row named: {res:?}"
        );
        assert!(
            res.lines.iter().any(|l| l.starts_with("audit: offload 2/2 file(s) OK (A001_001.offload-manifest.tsv")),
            "the clean first manifest swept (its rows named absent-of-FAIL): {res:?}"
        );
        assert!(
            res.lines.iter().any(|l| l.starts_with("audit: offload 1/1 file(s) OK (in.offload-manifest.tsv")),
            "the manifest AFTER the dirty one swept too (never stops at the first): {res:?}"
        );
        assert_eq!(
            res.lines.last().map(String::as_str),
            Some(
                format!(
                    "audit: offload re-verify {}: 3 manifest(s), 4 row(s) FAIL (1 named offender(s))",
                    mirror.display()
                )
                .as_str()
            ),
            "the verdict line: {res:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
