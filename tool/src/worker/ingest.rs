//! The ingest + discovery — the ingest gate / camera gate surface.
//!
//! `ingest_gate` / `ingest_gate_subset` (the `ingest_gate_impl` body):
//! the pre-encode safety gate over the collected frames — the TC
//! continuity classes (the gap / the count mismatch / the duplicate /
//! the skip-gap-overlap / the missing + malformed + bad-name — the
//! named refusal lines; the `--subset` waiver: the four continuity
//! classes waived, the kept classes stay hard) + the reel continuity
//! (the `report` part's `reel_check`) + the manifest counts + the
//! verdict fields (`IngestGateReport` — the crate `report` module
//! renders it, never re-derives it). `SUBSET_MARKER` +
//! `set_subset_flag` / `subset_flag` (the process-wide subset flag —
//! the main.rs dispatch sets it; the `ledger` / `report` / `jxl`
//! consumers read it). `write_ingest_manifest` (the per-clip
//! `.ingest-manifest.tsv` — the v1 format: the clip rows + the gate
//! record + the reel record; the `audit` module's re-derivation parses
//! it) + `collect_dng_frames` (the discovery read — the audit frame
//! re-derivation, the Apple-double shadow skip).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::checksums::{Smpte12m, frame_number_from_stem, read_timecodes_tag};
use super::report::{ClipVerdict, ReelVerdict, clip_key_of, display_clip, parse_manifest_counts, reel_check};

/// The ingest gate's report over the whole input root (all clips).
#[derive(Clone, Debug, PartialEq)]
pub struct IngestGateReport {
    pub clips: Vec<ClipVerdict>,
    pub frames_total: u64,
    /// The `--subset` waiver was active (the named
    /// opt-in): the report/ledger surfaces render `SUBSET_MARKER` from
    /// it; false = the default hard gate (the named line is absent).
    pub subset: bool,
    /// A manifest.tsv was present in the input root (the count gate is
    /// a hard gate) — vs absent (the named INFO line, not a FAIL).
    pub manifest_present: bool,
    /// The manifest path (the present case).
    pub manifest_path: Option<PathBuf>,
    /// A hard failure outside any single clip (MANIFEST_BAD: a corrupt
    /// input manifest.tsv).
    pub global_failures: Vec<String>,
    /// The reel gate (the cross-clip TC continuity — the
    /// between-clips half of 's TC contract).
    pub reel: ReelVerdict,
}

impl IngestGateReport {
    pub fn is_pass(&self) -> bool {
        self.global_failures.is_empty()
            && self.clips.iter().all(|c| c.failures.is_empty())
            && self.reel.is_pass()
    }
    /// Every named FAIL line (deterministic order: the global failures,
    /// then the clips in sorted key order, then the reel pairs in
    /// ingest order).
    pub fn failures(&self) -> Vec<String> {
        let mut v = self.global_failures.clone();
        for c in &self.clips {
            v.extend(c.failures.iter().cloned());
        }
        v.extend(self.reel.failures.iter().cloned());
        v
    }
}

/// One frame's gate inputs (the file name + the parsed frame number +
/// the TimeCodes read).
#[derive(Debug)]
struct GateFrame {
    file: String,
    num: Option<u64>,
    tc: Result<Option<Smpte12m>, String>,
}

/// The `--subset` named line (the random-subset waiver):
/// the byte-stable marker the per-clip report + the ledger's v3
/// `context` column carry when the flag is active (the honesty
/// property: a subset claim is visible in EVERY output artifact — the
/// SAME string in both surfaces, no wall clock, no path).
pub const SUBSET_MARKER: &str =
    "ingest-gate: subset (continuity waived — re-verify)";

/// The run's `--subset` flag (the NAMED subset opt-in).
/// Process-wide state (the pins.rs / selection.rs / resume.rs
/// OnceLock convention — the CLI has one run per process): `main`
/// records it before the encode; the two encode paths' gate call
/// sites (j92 + jxl) read it. Absent (the default) = `false` = the
/// unconditional hard gate (the byte-identity path).
static SUBSET_FLAG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Record the `--subset` flag (main, before the encode; a second set
/// is a silent no-op).
pub fn set_subset_flag(subset: bool) {
    let _ = SUBSET_FLAG.set(subset);
}

/// The run's `--subset` flag (false = the default hard gate).
pub fn subset_flag() -> bool {
    *SUBSET_FLAG.get().unwrap_or(&false)
}

/// The ingest safety gate — the DEFAULT hard path
/// (`subset = false`). `input` = the ingest root
/// (a clip dir, or a batch root with the per-clip subdirs + the
/// optional `manifest.tsv`); `frames` = the collected source .DNG paths
/// in ANY order (the gate groups + sorts per clip). The per-frame
/// TimeCodes are read from the source files (the 512 KiB header window
/// — `read_timecodes_tag`).
///
/// Unconditional + loud (the audit philosophy): every offender is
/// named (the frame pair + the raw values), nothing is skipped
/// silently. A failing report must refuse the ingest (0 frames
/// compressed) — `process_dir` does that; the gate itself never writes.
pub fn ingest_gate(input: &Path, frames: &[PathBuf]) -> IngestGateReport {
    ingest_gate_impl(input, frames, false)
}

/// The `--subset` variant (the NAMED opt-in for the
/// re-verify): the gate runs with EXACTLY the four within-clip
/// continuity classes waived (FRAME_GAP / FRAME_DUP / TC_GAP /
/// TC_OVERLAP — the sparse subset is legal by construction). Every
/// OTHER class stays a hard refusal: FRAME_BADNAME, TC_MISSING,
/// TC_MALFORMED, COUNT_MISMATCH, MANIFEST_BAD, the cross-clip
/// REEL_OVERLAP (the double-capture disk-lock class — a distinct
/// purpose, recorded decision), and the profile-resolution
/// refusals (the upstream camera-identity gate, untouched by this
/// change). The report carries `subset: true` (the named line's source —
/// the per-clip report + the ledger's v3 `context` column render
/// `SUBSET_MARKER` from it). The default path (`ingest_gate`) is
/// byte-identical to the pre-existing gate.
pub fn ingest_gate_subset(input: &Path, frames: &[PathBuf]) -> IngestGateReport {
    ingest_gate_impl(input, frames, true)
}

fn ingest_gate_impl(input: &Path, frames: &[PathBuf], subset: bool) -> IngestGateReport {
    // (b) the manifest-declared counts (the hard gate only when
    // present; a corrupt ledger = the named MANIFEST_BAD refusal).
    let manifest_path = input.join("manifest.tsv");
    let manifest_present = manifest_path.is_file();
    let mut global_failures: Vec<String> = Vec::new();
    let manifest_counts: Option<std::collections::BTreeMap<String, u64>> = if manifest_present {
        match parse_manifest_counts(&manifest_path) {
            Ok(c) => Some(c),
            Err(reason) => {
                global_failures.push(format!(
                    "FAIL MANIFEST_BAD clip={}: {reason}",
                    display_clip("")
                ));
                None
            }
        }
    } else {
        None
    };

    // Group the frames by clip key (the full relative parent dir — the
    // BTreeMap gives the deterministic clip order).
    let mut by_clip: std::collections::BTreeMap<String, Vec<usize>> =
        std::collections::BTreeMap::new();
    for (i, src) in frames.iter().enumerate() {
        by_clip.entry(clip_key_of(input, src)).or_default().push(i);
    }

    let mut clips: Vec<ClipVerdict> = Vec::new();
    for (clip, idxs) in &by_clip {
        let mut v = ClipVerdict {
            clip: clip.clone(),
            frames_found: idxs.len() as u64,
            manifest_declared: manifest_counts.as_ref().and_then(|m| m.get(clip).copied()),
            frame_range: None,
            tc_start: None,
            tc_end: None,
            tc_first_frames: None,
            tc_last_frames: None,
            failures: Vec::new(),
        };
        let mut gs: Vec<GateFrame> = Vec::with_capacity(idxs.len());
        for &i in idxs {
            let src = &frames[i];
            let file = src
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let stem = src
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            gs.push(GateFrame {
                file,
                num: frame_number_from_stem(&stem),
                tc: read_timecodes_tag(src),
            });
        }
        // FRAME_BADNAME (defensive): a .DNG without an all-digit final
        // stem field cannot be ordered — named, never silently dropped.
        for g in &gs {
            if g.num.is_none() {
                v.failures.push(format!(
                    "FAIL FRAME_BADNAME clip={}: {} has no numeric frame field (want the fp pattern <clip>_<date>_NNNNNN.DNG)",
                    display_clip(clip),
                    g.file
                ));
            }
        }
        // The per-frame TC presence (EVERY frame — the fp always carries
        // tag 51043; absence is an ingest anomaly worth naming).
        for g in &gs {
            match &g.tc {
                Ok(None) => v.failures.push(format!(
                    "FAIL TC_MISSING clip={}: {} has no TimeCodes tag 51043 (the fp always carries it — an ingest anomaly)",
                    display_clip(clip),
                    g.file
                )),
                Err(reason) => {
                    let file = g.file.clone();
                    v.failures.push(format!(
                        "FAIL TC_MALFORMED clip={}: {file}: {reason}",
                        display_clip(clip)
                    ));
                }
                Ok(Some(_)) => {}
            }
        }
        // The ordered parseable frames (by number, then file name).
        let mut ordered: Vec<&GateFrame> = gs.iter().filter(|g| g.num.is_some()).collect();
        ordered.sort_by(|a, b| a.num.cmp(&b.num).then_with(|| a.file.cmp(&b.file)));
        if let (Some(first), Some(last)) = (ordered.first(), ordered.last()) {
            v.frame_range = Some((first.num.unwrap(), last.num.unwrap()));
        }
        // (a) frame-number contiguity: duplicates + gaps.
        let mut prev: Option<&GateFrame> = None;
        for g in &ordered {
            if let Some(p) = prev {
                let (pn, gn) = (p.num.unwrap(), g.num.unwrap());
                if pn == gn {
                    // The four within-clip continuity classes are
                    // waived under `--subset` — the sparse
                    // subset is legal by construction; the other
                    // classes keep pushing unconditionally below.
                    if !subset {
                        v.failures.push(format!(
                            "FAIL FRAME_DUP clip={}: frame {gn} in both {} and {}",
                            display_clip(clip),
                            p.file,
                            g.file
                        ));
                    }
                } else if gn > pn + 1 {
                    let missing = gn - pn - 1;
                    let list = if missing <= 8 {
                        (pn + 1..gn).map(|n| n.to_string()).collect::<Vec<_>>().join(",")
                    } else {
                        format!("{}…{}", pn + 1, gn - 1)
                    };
                    if !subset {
                        v.failures.push(format!(
                            "FAIL FRAME_GAP clip={}: frame {pn} ({}) -> frame {gn} ({}): {missing} frame(s) missing ({list})",
                            display_clip(clip),
                            p.file,
                            g.file
                        ));
                    }
                }
            }
            prev = Some(g);
        }
        // (b) the manifest-declared count (hard gate when present).
        if let Some(declared) = v.manifest_declared {
            if declared != v.frames_found {
                v.failures.push(format!(
                    "FAIL COUNT_MISMATCH clip={}: manifest.tsv declares {declared} frame(s), found {} on disk",
                    display_clip(clip),
                    v.frames_found
                ));
            }
        }
        // (c) the per-frame TC continuity: ONLY between parseable
        // frames with CONSECUTIVE numbers (a non-consecutive pair is
        // already named FRAME_GAP; a duplicate's pair FRAME_DUP — no
        // double-report). delta = +1 (24 fps non-drop) = OK; ≥ +2 =
        // TC_GAP; ≤ 0 = TC_OVERLAP.
        for w in ordered.windows(2) {
            let (a, b) = (w[0], w[1]);
            let (an, bn) = (a.num.unwrap(), b.num.unwrap());
            if an == bn || bn != an + 1 {
                continue;
            }
            let (ta, tb) = match (&a.tc, &b.tc) {
                (Ok(Some(x)), Ok(Some(y))) => (x, y),
                _ => continue, // missing/malformed — already named per frame
            };
            let delta = tb.total_frames() as i64 - ta.total_frames() as i64;
            if delta == 1 {
                continue; // the 24 fps non-drop step — OK
            }
            if delta > 1 {
                if !subset {
                    v.failures.push(format!(
                        "FAIL TC_GAP clip={}: frames {an} -> {bn} ({} / {}): TC {} -> {}, delta +{delta} (expected +1)",
                        display_clip(clip),
                        a.file,
                        b.file,
                        ta.display(),
                        tb.display()
                    ));
                }
            } else {
                if !subset {
                    v.failures.push(format!(
                        "FAIL TC_OVERLAP clip={}: frames {an} -> {bn} ({} / {}): TC {} -> {}, delta {delta} (expected +1)",
                        display_clip(clip),
                        a.file,
                        b.file,
                        ta.display(),
                        tb.display()
                    ));
                }
            }
        }
        // The per-clip TC range (the first/last parseable frame that
        // carries a TC) + the absolute frame counts (the reel
        // gate's arithmetic domain).
        let tc_of = |g: &GateFrame| g.tc.as_ref().ok().and_then(|t| *t);
        v.tc_start = ordered.iter().find_map(|g| tc_of(g).map(|t| t.display()));
        v.tc_end = ordered.iter().rev().find_map(|g| tc_of(g).map(|t| t.display()));
        v.tc_first_frames = ordered
            .iter()
            .find_map(|g| tc_of(g).map(|t| t.total_frames()));
        v.tc_last_frames = ordered
            .iter()
            .rev()
            .find_map(|g| tc_of(g).map(|t| t.total_frames()));
        clips.push(v);
    }

    // The reel gate (the cross-clip TC continuity — the
    // between-clips half of): over the clips in ingest order
    // (the BTreeMap clip key order = the offload-manifest order),
    // clip N+1's TC start must be strictly after clip N's TC end;
    // equal or earlier = the named REEL_OVERLAP FAIL (a double
    // capture). Gaps of any size are free (the measured fact — no
    // span-continuity claim).
    let reel = reel_check(&clips);

    IngestGateReport {
        clips,
        frames_total: frames.len() as u64,
        subset,
        manifest_present,
        manifest_path: if manifest_present {
            Some(manifest_path)
        } else {
            None
        },
        global_failures,
        reel,
    }
}

/// Write the ingest-manifest record: `<output>/<CLIP>.ingest-
/// manifest.tsv`, the bake-manifest-v2 pattern (the magic line + the
/// additive `key: value` headers + the column line + the per-clip
/// rows; unknown header keys are skipped on read, so the format stays
/// additive + versioned — old records stay valid). Written on the gate
/// PASS, BEFORE the encode (the verdict is recorded even if the encode
/// later fails per frame); NOT written on a gate FAIL (the refusal
/// leaves nothing — the existing pattern).
pub fn write_ingest_manifest(
    output: &Path,
    input: &Path,
    gate: &IngestGateReport,
) -> Result<PathBuf> {
    let clip = crate::checksums::clip_name(input)?;
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let host = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    let mut tsv = format!(
        "# frameprism ingest manifest\n\
         version: 1\n\
         clip: {clip}\n\
         created: {created} (unix seconds, UTC)\n\
         tool_version: {}\n\
         host: {host}\n\
         gate: PASS\n\
         manifest: {}\n\
         clips: {}\n\
         frames: {}\n\
         clip\tframes\tmanifest_declared\tframe_range\ttc_start\ttc_end\n",
        env!("CARGO_PKG_VERSION"),
        if gate.manifest_present { "present" } else { "absent" },
        gate.clips.len(),
        gate.frames_total
    );
    // The reel verdict record (the additive header convention —
    // unknown keys are skipped on read, so the format stays additive:
    // pre-records parse unchanged). Written on the gate PASS only
    // (a reel FAIL refuses the ingest before the record exists — the
    // pattern), so the line is always the PASS form.
    let reel_line = if gate.clips.len() <= 1 {
        String::from("reel: PASS (1 clip — no cross-clip pairs to check)")
    } else if gate.reel.failures.is_empty() {
        String::from("reel: PASS (tc_first strictly after the previous clip's tc_end across the ingest — the gaps are free, no span-continuity claim)")
    } else {
        // Unreachable on a PASS (the reel failures are a gate FAIL —
        // the refusal leaves nothing); the named form keeps the
        // invariant loud if the caller ever writes a FAIL record.
        format!(
            "reel: FAIL ({} named REEL_OVERLAP pair(s))",
            gate.reel.failures.len()
        )
    };
    tsv.push_str(&reel_line);
    tsv.push('\n');
    for c in &gate.clips {
        tsv.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            c.clip,
            c.frames_found,
            c.manifest_declared
                .map(|d| d.to_string())
                .unwrap_or_else(|| "-".into()),
            c.frame_range
                .map(|(a, b)| format!("{a}..{b}"))
                .unwrap_or_else(|| "-".into()),
            c.tc_start.clone().unwrap_or_else(|| "-".into()),
            c.tc_end.clone().unwrap_or_else(|| "-".into())
        ));
    }
    let path = output.join(format!("{clip}.ingest-manifest.tsv"));
    let tmp = output.join(format!(".{clip}.ingest-manifest.tsv.tmp"));
    std::fs::write(&tmp, tsv)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(path)
}

/// Recursively enumerate the .DNG frames under `root` (sorted absolute
/// paths) — the audit re-derivation's frame set.
/// Mirrors the worker's `collect` discipline: symlinked entries are
/// skipped (cycle/escape guard) and the (dev, ino) visited set makes a
/// hard-link fan-in / cycle a no-op, never a recursion.
pub fn collect_dng_frames(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut visited: std::collections::HashSet<crate::DirId> = std::collections::HashSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let id = crate::dir_id(&dir)
            .map_err(|err| format!("read dir {}: {err}", dir.display()))?;
        if !visited.insert(id) {
            continue;
        }
        for entry in std::fs::read_dir(&dir)
            .map_err(|err| format!("read dir {}: {err}", dir.display()))?
        {
            let entry = entry.map_err(|err| format!("read dir {}: {err}", dir.display()))?;
            let p = entry.path();
            let ft = entry
                .file_type()
                .map_err(|err| format!("file type {}: {err}", p.display()))?;
            if ft.is_symlink() {
                continue; // the worker's refusal: symlinked entries
            }
            //: the AppleDouble shadow is never a frame — skip
            // (the audit re-derivation would otherwise report 2×
            // frames on a shadowed tree).
            if entry.file_name().to_str().is_some_and(crate::is_apple_double) {
                continue;
            }
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                let is_dng = p
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("dng"))
                    .unwrap_or(false);
                if is_dng {
                    out.push(p);
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::testutil::*;
    #[test]
    fn gate_clean_clip_pass_and_verdict_fields() {
        let tmp = std::env::temp_dir().join(format!("frameprism-gate-clean-{}", std::process::id()));
        let frames = synth_root(
            &tmp,
            &[("A", vec![
                ("A_20260101_000001.DNG", Some(t(0, 0, 0, 0))),
                ("A_20260101_000002.DNG", Some(t(0, 0, 0, 1))),
                ("A_20260101_000003.DNG", Some(t(0, 0, 0, 2))),
            ])],
            Some("relpath\tsize\tsha256\nA/A_20260101_000001.DNG\t1\t-\nA/A_20260101_000002.DNG\t1\t-\nA/A_20260101_000003.DNG\t1\t-\n"),
        );
        let gate = ingest_gate(&tmp, &frames);
        assert!(gate.manifest_present);
        assert!(gate.is_pass(), "clean clip must pass: {:?}", gate.failures());
        assert_eq!(gate.clips.len(), 1);
        let v = &gate.clips[0];
        assert_eq!(v.clip, "A");
        assert_eq!(v.frames_found, 3);
        assert_eq!(v.manifest_declared, Some(3));
        assert_eq!(v.frame_range, Some((1, 3)));
        assert_eq!(v.tc_start.as_deref(), Some("00:00:00:00"));
        assert_eq!(v.tc_end.as_deref(), Some("00:00:00:02"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn gate_gap_and_count_mismatch() {
        let tmp = std::env::temp_dir().join(format!("frameprism-gate-gap-{}", std::process::id()));
        let manifest = "relpath\tsize\tsha256\nA/A_20260101_000001.DNG\t1\t-\nA/A_20260101_000002.DNG\t1\t-\nA/A_20260101_000003.DNG\t1\t-\n";
        let _ = synth_root(
            &tmp,
            &[("A", vec![
                ("A_20260101_000001.DNG", Some(t(0, 0, 0, 0))),
                ("A_20260101_000002.DNG", Some(t(0, 0, 0, 1))),
                ("A_20260101_000003.DNG", Some(t(0, 0, 0, 2))),
            ])],
            Some(manifest),
        );
        // Remove frame 2 → a gap (1 -> 3) + the count mismatch (3 declared,
        // 2 found).
        std::fs::remove_file(tmp.join("A/A_20260101_000002.DNG")).unwrap();
        let frames = collect_dng_frames(&tmp).unwrap();
        let gate = ingest_gate(&tmp, &frames);
        assert!(!gate.is_pass());
        let f = gate.failures();
        assert!(
            f.iter().any(|l| l.starts_with("FAIL FRAME_GAP") && l.contains("frame 1") && l.contains("frame 3") && l.contains("missing (2)")),
            "want the named FRAME_GAP with the pair + the missing number: {f:?}"
        );
        assert!(
            f.iter().any(|l| l.starts_with("FAIL COUNT_MISMATCH") && l.contains("declares 3") && l.contains("found 2")),
            "want the named COUNT_MISMATCH: {f:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn gate_duplicate() {
        let tmp = std::env::temp_dir().join(format!("frameprism-gate-dup-{}", std::process::id()));
        let _ = synth_root(
            &tmp,
            &[("A", vec![
                ("A_20260101_000001.DNG", Some(t(0, 0, 0, 0))),
                ("A_20260101_000002.DNG", Some(t(0, 0, 0, 1))),
                // A duplicate of frame 2 (same number, a different date field).
                ("A_20260102_000002.DNG", Some(t(0, 0, 0, 1))),
                ("A_20260101_000003.DNG", Some(t(0, 0, 0, 2))),
            ])],
            None,
        );
        let frames = collect_dng_frames(&tmp).unwrap();
        let gate = ingest_gate(&tmp, &frames);
        assert!(!gate.is_pass());
        let f = gate.failures();
        assert!(
            f.iter().any(|l| l.starts_with("FAIL FRAME_DUP") && l.contains("frame 2") && l.contains("A_20260101_000002.DNG") && l.contains("A_20260102_000002.DNG")),
            "want the named FRAME_DUP naming BOTH files: {f:?}"
        );
        // No gap (the distinct numbers are 1,2,3) + no count gate (no manifest).
        assert!(!f.iter().any(|l| l.starts_with("FAIL FRAME_GAP")), "no gap expected: {f:?}");
        assert!(!f.iter().any(|l| l.starts_with("FAIL COUNT_MISMATCH")), "no manifest: {f:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn gate_tc_skip_gap_overlap() {
        let tmp = std::env::temp_dir().join(format!("frameprism-gate-tc-skip-{}", std::process::id()));
        // Clip B: TCs 0, +1, then a 2-frame skip (pair 2->3: delta +3 =
        // TC_GAP) and a rewind (pair 3->4: delta -2 = TC_OVERLAP).
        let _ = synth_root(
            &tmp,
            &[("B", vec![
                ("B_20260101_000001.DNG", Some(t(0, 0, 0, 0))),
                ("B_20260101_000002.DNG", Some(t(0, 0, 0, 1))),
                ("B_20260101_000003.DNG", Some(t(0, 0, 0, 4))),
                ("B_20260101_000004.DNG", Some(t(0, 0, 0, 2))),
            ])],
            None,
        );
        let frames = collect_dng_frames(&tmp).unwrap();
        let gate = ingest_gate(&tmp, &frames);
        assert!(!gate.is_pass());
        let f = gate.failures();
        assert!(
            f.iter().any(|l| l.starts_with("FAIL TC_GAP") && l.contains("frames 2 -> 3") && l.contains("00:00:00:01 -> 00:00:00:04") && l.contains("delta +3")),
            "want the named TC_GAP with the pair + raw TCs + delta: {f:?}"
        );
        assert!(
            f.iter().any(|l| l.starts_with("FAIL TC_OVERLAP") && l.contains("frames 3 -> 4") && l.contains("00:00:00:04 -> 00:00:00:02") && l.contains("delta -2")),
            "want the named TC_OVERLAP for the rewind side of the skip: {f:?}"
        );
        // Pair 1->2 (delta +1) is clean — not named.
        assert!(!f.iter().any(|l| l.contains("frames 1 -> 2")), "clean pair must not be named: {f:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn gate_tc_missing_and_malformed_and_badname() {
        let tmp = std::env::temp_dir().join(format!("frameprism-gate-tc-missing-{}", std::process::id()));
        let _ = synth_root(
            &tmp,
            &[("C", vec![
                ("C_20260101_000001.DNG", Some(t(0, 0, 0, 0))),
                ("C_20260101_000002.DNG", None), // tag 51043 absent → TC_MISSING
            ])],
            None,
        );
        // A malformed payload (a non-BCD nibble) on frame 1 of clip D.
        let d = tmp.join("D");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("D_20260101_000001.DNG"), synthetic_dng(Some(&[0x5A, 0x51, 0x53, 0x22, 0, 0, 0, 0]), 1, 8, None)).unwrap();
        // A non-fp-named DNG in clip E → FRAME_BADNAME.
        let e = tmp.join("E");
        std::fs::create_dir_all(&e).unwrap();
        std::fs::write(e.join("E_reference.DNG"), synthetic_dng(Some(&tc_payload(&t(0, 0, 0, 0))), 1, 8, None)).unwrap();
        let frames = collect_dng_frames(&tmp).unwrap();
        let gate = ingest_gate(&tmp, &frames);
        assert!(!gate.is_pass());
        let f = gate.failures();
        assert!(
            f.iter().any(|l| l.starts_with("FAIL TC_MISSING") && l.contains("C_20260101_000002.DNG") && l.contains("51043")),
            "want the named TC_MISSING: {f:?}"
        );
        assert!(
            f.iter().any(|l| l.starts_with("FAIL TC_MALFORMED") && l.contains("D_20260101_000001.DNG")),
            "want the named TC_MALFORMED: {f:?}"
        );
        assert!(
            f.iter().any(|l| l.starts_with("FAIL FRAME_BADNAME") && l.contains("E_reference.DNG")),
            "want the named FRAME_BADNAME: {f:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn gate_manifest_bad_refuses_named() {
        let tmp = std::env::temp_dir().join(format!("frameprism-gate-manifest-bad-{}", std::process::id()));
        let _ = synth_root(
            &tmp,
            &[("A", vec![("A_20260101_000001.DNG", Some(t(0, 0, 0, 0)))])],
            Some("relpath\tsize\tsha256\nnot-a-tabbed-row\n"), // a data row without a tab
        );
        let frames = collect_dng_frames(&tmp).unwrap();
        let gate = ingest_gate(&tmp, &frames);
        assert!(!gate.is_pass(), "a corrupt ledger must refuse the ingest");
        let f = gate.failures();
        assert!(
            f.iter().any(|l| l.starts_with("FAIL MANIFEST_BAD") && l.contains("not a `relpath<TAB>…` row")),
            "want the named MANIFEST_BAD with the offending row: {f:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // =====================================================================
    // The `--subset` NAMED opt-in (the random-subset waiver)
    // =====================================================================

    #[test]
    fn lane4_subset_waives_exactly_the_four_continuity_classes() {
        // One synthetic root carrying all four within-clip continuity
        // classes at once: clip A = the sparse original-name shape
        // (FRAME_GAP — the re-verify shape), clip B = a TC skip + a
        // TC rewind (TC_GAP / TC_OVERLAP), clip C = a duplicate frame
        // number (FRAME_DUP). The per-clip TC ranges are NON-
        // OVERLAPPING (the reel-clean shape — REEL_OVERLAP is a kept
        // class and must not fire here).
        let tmp = std::env::temp_dir().join(format!("frameprism-lane4-4cls-{}", std::process::id()));
        let _ = synth_root(
            &tmp,
            &[
                ("A", vec![
                    ("A_20260101_000001.DNG", Some(t(0, 0, 1, 0))),
                    ("A_20260101_000003.DNG", Some(t(0, 0, 1, 2))),
                    ("A_20260101_000005.DNG", Some(t(0, 0, 1, 4))),
                ]),
                ("B", vec![
                    ("B_20260101_000001.DNG", Some(t(0, 0, 2, 0))),
                    ("B_20260101_000002.DNG", Some(t(0, 0, 2, 1))),
                    ("B_20260101_000003.DNG", Some(t(0, 0, 2, 4))),
                    ("B_20260101_000004.DNG", Some(t(0, 0, 2, 2))),
                ]),
                ("C", vec![
                    ("C_20260101_000001.DNG", Some(t(0, 0, 3, 0))),
                    ("C_20260101_000002.DNG", Some(t(0, 0, 3, 1))),
                    ("C_20260102_000002.DNG", Some(t(0, 0, 3, 1))),
                    ("C_20260101_000003.DNG", Some(t(0, 0, 3, 2))),
                ]),
            ],
            None,
        );
        let frames = collect_dng_frames(&tmp).unwrap();
        // The DEFAULT path (byte-identical to pre-existing — the exact
        // refusal line text is the pin):
        let gate = ingest_gate(&tmp, &frames);
        assert!(!gate.subset, "the default gate is not a subset run");
        assert!(!gate.is_pass());
        let f = gate.failures();
        assert!(
            f.iter().any(|l| l == "FAIL FRAME_GAP clip=A: frame 1 (A_20260101_000001.DNG) -> frame 3 (A_20260101_000003.DNG): 1 frame(s) missing (2)"),
            "exact default FRAME_GAP line: {f:?}"
        );
        assert!(
            f.iter().any(|l| l == "FAIL TC_GAP clip=B: frames 2 -> 3 (B_20260101_000002.DNG / B_20260101_000003.DNG): TC 00:00:02:01 -> 00:00:02:04, delta +3 (expected +1)"),
            "exact default TC_GAP line: {f:?}"
        );
        assert!(
            f.iter().any(|l| l == "FAIL TC_OVERLAP clip=B: frames 3 -> 4 (B_20260101_000003.DNG / B_20260101_000004.DNG): TC 00:00:02:04 -> 00:00:02:02, delta -2 (expected +1)"),
            "exact default TC_OVERLAP line: {f:?}"
        );
        assert!(
            f.iter().any(|l| l == "FAIL FRAME_DUP clip=C: frame 2 in both C_20260101_000002.DNG and C_20260102_000002.DNG"),
            "exact default FRAME_DUP line: {f:?}"
        );
        // The `--subset` variant: EXACTLY those four classes waived —
        // the sparse ingest is legal by construction, 0 failures.
        let sub = ingest_gate_subset(&tmp, &frames);
        assert!(sub.subset, "the subset report carries the flag");
        assert!(sub.is_pass(), "the four continuity classes are waived under --subset: {:?}", sub.failures());
        assert!(sub.failures().is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn lane4_subset_kept_classes_stay_hard() {
        // Every class OUTSIDE the four continuity classes is a hard
        // refusal under `--subset` (the waiver never widens):
        // (a) TC_MISSING — a frame without tag 51043;
        // (b) FRAME_BADNAME — a non-fp frame name;
        // (c) COUNT_MISMATCH — the manifest declares more than found
        // (the sparse random-subset shape: the FRAME_GAP is waived, the count
        // gate is not);
        // (d) MANIFEST_BAD — a corrupt manifest.tsv;
        // (e) REEL_OVERLAP — the cross-clip double-capture class (the
        // ≥2-clip test-only fixture; a distinct safety purpose —
 // never waived, recorded decision).
        let frames = |
            tmp: &Path,
            clips: &[(&str, Vec<(&str, Option<Smpte12m>)>)],
            manifest: Option<&str>,
        | -> (IngestGateReport, IngestGateReport) {
            let _ = synth_root(tmp, clips, manifest);
            let f = collect_dng_frames(tmp).unwrap();
            (ingest_gate(tmp, &f), ingest_gate_subset(tmp, &f))
        };
        // (a) TC_MISSING
        let tmp = std::env::temp_dir().join(format!("frameprism-lane4-a-{}", std::process::id()));
        let (gate, sub) = frames(
            &tmp,
            &[("A", vec![
                ("A_20260101_000001.DNG", Some(t(0, 0, 0, 0))),
                ("A_20260101_000002.DNG", None),
            ])],
            None,
        );
        for g in [&gate, &sub] {
            assert!(!g.is_pass(), "TC_MISSING must refuse under the flag");
            assert!(
                g.failures()
                    .iter()
                    .any(|l| l.starts_with("FAIL TC_MISSING") && l.contains("A_20260101_000002.DNG")),
                "named TC_MISSING: {:?}",
                g.failures()
            );
        }
        // (b) FRAME_BADNAME
        let tmp = std::env::temp_dir().join(format!("frameprism-lane4-b-{}", std::process::id()));
        let _ = synth_root(
            &tmp,
            &[("A", vec![("A_20260101_000001.DNG", Some(t(0, 0, 0, 0)))])],
            None,
        );
        std::fs::write(
            tmp.join("A/A_reference.DNG"),
            synthetic_dng(Some(&tc_payload(&t(0, 0, 0, 1))), 1, 8, None),
        )
        .unwrap();
        let f = collect_dng_frames(&tmp).unwrap();
        let gate = ingest_gate(&tmp, &f);
        let sub = ingest_gate_subset(&tmp, &f);
        for g in [&gate, &sub] {
            assert!(!g.is_pass(), "FRAME_BADNAME must refuse under the flag");
            assert!(
                g.failures()
                    .iter()
                    .any(|l| l.starts_with("FAIL FRAME_BADNAME") && l.contains("A_reference.DNG")),
                "named FRAME_BADNAME: {:?}",
                g.failures()
            );
        }
        // (c) COUNT_MISMATCH (the sparse shape + a manifest declaring 4)
        let tmp = std::env::temp_dir().join(format!("frameprism-lane4-c-{}", std::process::id()));
        let (gate, sub) = frames(
            &tmp,
            &[("A", vec![
                ("A_20260101_000001.DNG", Some(t(0, 0, 1, 0))),
                ("A_20260101_000003.DNG", Some(t(0, 0, 1, 2))),
                ("A_20260101_000005.DNG", Some(t(0, 0, 1, 4))),
            ])],
            Some("relpath\tsize\tsha256\nA/A_20260101_000001.DNG\t1\t-\nA/A_20260101_000003.DNG\t1\t-\nA/A_20260101_000005.DNG\t1\t-\nA/A_20260101_000007.DNG\t1\t-\n"),
        );
        // Default: the gap + the count both named; subset: the gap
        // waived, the count still a hard refusal.
        assert!(
            gate.failures()
                .iter()
                .any(|l| l.starts_with("FAIL FRAME_GAP"))
                && gate
                    .failures()
                    .iter()
                    .any(|l| l.starts_with("FAIL COUNT_MISMATCH")),
            "default: the gap + the count both named: {:?}",
            gate.failures()
        );
        assert!(!sub.is_pass(), "COUNT_MISMATCH must refuse under the flag");
        assert!(
            !sub
                .failures()
                .iter()
                .any(|l| l.starts_with("FAIL FRAME_GAP")),
            "the gap IS waived under the flag: {:?}",
            sub.failures()
        );
        assert!(
            sub.failures()
                .iter()
                .any(|l| l == "FAIL COUNT_MISMATCH clip=A: manifest.tsv declares 4 frame(s), found 3 on disk"),
            "exact kept COUNT_MISMATCH line under the flag: {:?}",
            sub.failures()
        );
        // (d) MANIFEST_BAD
        let tmp = std::env::temp_dir().join(format!("frameprism-lane4-d-{}", std::process::id()));
        let (gate, sub) = frames(
            &tmp,
            &[("A", vec![("A_20260101_000001.DNG", Some(t(0, 0, 0, 0)))])],
            Some("relpath\tsize\tsha256\nnot-a-tabbed-row\n"),
        );
        for g in [&gate, &sub] {
            assert!(!g.is_pass(), "MANIFEST_BAD must refuse under the flag");
            assert!(
                g.failures()
                    .iter()
                    .any(|l| l.starts_with("FAIL MANIFEST_BAD")),
                "named MANIFEST_BAD: {:?}",
                g.failures()
            );
        }
        // (e) REEL_OVERLAP (the cross-clip class — the test-only
        // ≥2-clip fixture: clip Q's TC first is EARLIER than clip P's
        // TC last = the double-capture shape).
        let tmp = std::env::temp_dir().join(format!("frameprism-lane4-e-{}", std::process::id()));
        let (gate, sub) = frames(
            &tmp,
            &[
                ("P", vec![
                    ("P_20260101_000001.DNG", Some(t(0, 0, 0, 0))),
                    ("P_20260101_000002.DNG", Some(t(0, 0, 0, 1))),
                    ("P_20260101_000003.DNG", Some(t(0, 0, 0, 2))),
                ]),
                ("Q", vec![
                    ("Q_20260101_000001.DNG", Some(t(0, 0, 0, 1))),
                    ("Q_20260101_000002.DNG", Some(t(0, 0, 0, 2))),
                    ("Q_20260101_000003.DNG", Some(t(0, 0, 0, 3))),
                ]),
            ],
            None,
        );
        for g in [&gate, &sub] {
            assert!(!g.is_pass(), "REEL_OVERLAP must refuse under the flag");
            assert!(
                g.failures().iter().any(|l| l ==
                    "FAIL REEL_OVERLAP clip=P -> clip=Q: TC end of P (00:00:00:02) vs TC first of Q (00:00:00:01): earlier by 1 frame(s), delta -1 (expected > 0 — strictly after; the gaps between clips are free — an overlap is a double capture)"),
                "exact kept REEL_OVERLAP line under the flag: {:?}",
                g.failures()
            );
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn ingest_manifest_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("frameprism-manifest-roundtrip-{}", std::process::id()));
        let frames = synth_root(
            &tmp,
            &[("A", vec![
                ("A_20260101_000001.DNG", Some(t(0, 0, 0, 0))),
                ("A_20260101_000002.DNG", Some(t(0, 0, 0, 1))),
            ])],
            None,
        );
        let gate = ingest_gate(&tmp, &frames);
        assert!(gate.is_pass());
        let out = tmp.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let p = write_ingest_manifest(&out, &tmp, &gate).unwrap();
        let clip = tmp.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(p, out.join(format!("{clip}.ingest-manifest.tsv")));
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "# frameprism ingest manifest");
        assert!(lines.iter().any(|l| l.starts_with("version: 1")), "the additive version field: {text:?}");
        assert!(lines.iter().any(|l| l.starts_with("gate: PASS")), "the recorded verdict: {text:?}");
        assert!(lines.iter().any(|l| l.starts_with("manifest: absent")), "no manifest.tsv in the synth root: {text:?}");
        assert!(
            lines.iter().any(|l| *l == "clip\tframes\tmanifest_declared\tframe_range\ttc_start\ttc_end"),
            "the column line: {text:?}"
        );
        assert!(
            lines.iter().any(|l| *l == "A\t2\t-\t1..2\t00:00:00:00\t00:00:00:01"),
            "the per-clip row (frames, no declared count, range, TC range): {text:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // =================================================================
    // The per-frame camera
    // metadata (the sidecar v3 columns) + the residual (G:
    // the gate order-independence proof) + the --to startup
    // refusal (the encode path's rc=2 wiring; the offload engine is
    // unit-tested in the offload module, the report in report.rs).
    // =================================================================

    #[test]
    fn residual_g_gate_is_order_independent() {
        // (G): the ingest gate sorts frames by
        // (clip, frame number) before the TC-continuity check — a
        // shuffled input order must produce the SAME verdict (the card
        // reader hands files back in no particular order).
        let base = std::env::temp_dir().join(format!("frameprism-residual-g-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let a1 = base.join("A");
        let a2 = base.join("B");
        std::fs::create_dir_all(&a1).unwrap();
        std::fs::create_dir_all(&a2).unwrap();
        let frames = [
            (a1.join("A_20260101_000001.DNG"), t4(0, 0, 0, 0)),
            (a1.join("A_20260101_000002.DNG"), t4(0, 0, 0, 1)),
            (a1.join("A_20260101_000003.DNG"), t4(0, 0, 0, 2)),
            (a2.join("B_20260101_000001.DNG"), t4(0, 0, 0, 3)),
            (a2.join("B_20260101_000002.DNG"), t4(0, 0, 0, 4)),
        ];
        for (p, tc) in &frames {
            std::fs::write(p, synth_tiff((tc[0], tc[1], tc[2], tc[3]), None, None, None)).unwrap();
        }
        let mut sorted: Vec<PathBuf> = frames.iter().map(|(p, _)| p.clone()).collect();
        sorted.sort();
        let gate_sorted = ingest_gate(&base, &sorted);
        // A shuffled (reversed) input order — the verdict is identical.
        let mut shuffled: Vec<PathBuf> = frames.iter().map(|(p, _)| p.clone()).collect();
        shuffled.reverse();
        let gate_shuffled = ingest_gate(&base, &shuffled);
        assert!(gate_shuffled.is_pass(), "shuffled: {:?}", gate_shuffled.failures());
        assert_eq!(gate_sorted, gate_shuffled, "the gate verdict is order-independent");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn p72_gate_reordered_clips_are_a_named_reel_fail() {
        // A two-clip tree ingested in REVERSED TC order: the clip with
        // the LATER TC range sits in the earlier (sort order) dir —
        // clip B (TC 3..6) before clip A (TC 0..2) is impossible in a
        // continuous clock, so the reel gate names the overlap.
        let tmp = std::env::temp_dir().join(format!("frameprism-p72-r-{}", std::process::id()));
        let frames = synth_root(
            &tmp,
            &[
                // Clip dir "B" carries the LATER range (0,0,0,3)..(0,0,0,6);
                // clip dir "A" the earlier (0,0,0,0)..(0,0,0,2) — but the
                // ingest order (sorted clip keys) is A, B: A ends at 2, B
                // starts at 3... that is MONOTONIC. To build the reversed
                // order: put the later range in the EARLIER dir name.
                (
                    "A",
                    vec![
                        ("A_20260101_000001.DNG", Some(t(0, 0, 0, 3))),
                        ("A_20260101_000002.DNG", Some(t(0, 0, 0, 4))),
                        ("A_20260101_000003.DNG", Some(t(0, 0, 0, 5))),
                    ],
                ),
                (
                    "B",
                    vec![
                        ("B_20260101_000001.DNG", Some(t(0, 0, 0, 0))),
                        ("B_20260101_000002.DNG", Some(t(0, 0, 0, 1))),
                        ("B_20260101_000003.DNG", Some(t(0, 0, 0, 2))),
                    ],
                ),
            ],
            None,
        );
        let gate = ingest_gate(&tmp, &frames);
        assert!(!gate.is_pass(), "reversed TC order must fail the reel gate");
        // The per-clip gates stay clean (the named line is the reel's).
        assert!(
            gate.clips.iter().all(|c| c.failures.is_empty()),
            "the per-clip gates pass: {:?}",
            gate.clips.iter().map(|c| c.failures.clone()).collect::<Vec<_>>()
        );
        assert_eq!(gate.reel.failures.len(), 1, "one named reel line: {:?}", gate.reel.failures);
        let line = &gate.reel.failures[0];
        assert!(line.starts_with("FAIL REEL_OVERLAP clip=A -> clip=B"), "the ingest order in the name: {line}");
        assert!(line.contains("00:00:00:05"), "the prev clip's tc_end: {line}");
        assert!(line.contains("00:00:00:00"), "the next clip's tc_first: {line}");
        assert!(line.contains("earlier by 5 frame(s)"), "the named relation + magnitude: {line}");
        // The gate-level surface carries the line (the rc=2 path + the
        // audit re-derivation read it from here).
        assert!(gate.failures().iter().any(|l| l == line), "failures() carries the reel line");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn p72_gate_missing_middle_clip_passes_with_a_free_gap() {
        // The NO-span-continuity assertion: three clips in TC order,
        // the MIDDLE one removed — the remaining tc_firsts are
        // monotonic with a free gap, so the reel check PASSES (no
        // false positive) and the per-clip gates run on the present
        // clips.
        let tmp = std::env::temp_dir().join(format!("frameprism-p72-m-{}", std::process::id()));
        let _frames = synth_root(
            &tmp,
            &[
                (
                    "A",
                    vec![
                        ("A_20260101_000001.DNG", Some(t(0, 0, 0, 0))),
                        ("A_20260101_000002.DNG", Some(t(0, 0, 0, 1))),
                    ],
                ),
                (
                    "B",
                    vec![
                        ("B_20260101_000001.DNG", Some(t(0, 0, 0, 2))),
                        ("B_20260101_000002.DNG", Some(t(0, 0, 0, 3))),
                    ],
                ),
                (
                    "C",
                    vec![
                        ("C_20260101_000001.DNG", Some(t(0, 0, 1, 0))),
                        ("C_20260101_000002.DNG", Some(t(0, 0, 1, 1))),
                    ],
                ),
            ],
            None,
        );
        // The middle clip is removed (the missing-clip case).
        std::fs::remove_file(tmp.join("B/B_20260101_000001.DNG")).unwrap();
        std::fs::remove_file(tmp.join("B/B_20260101_000002.DNG")).unwrap();
        std::fs::remove_dir_all(tmp.join("B")).unwrap();
        let frames = collect_dng_frames(&tmp).unwrap();
        let gate = ingest_gate(&tmp, &frames);
        assert!(gate.is_pass(), "the free gap is not a span claim: {:?}", gate.failures());
        assert_eq!(gate.clips.len(), 2, "the present clips: {:?}", gate.clips.len());
        assert_eq!(gate.reel.pairs.len(), 1);
        assert!(gate.reel.pairs[0].ok, "the A -> C pair passes: {:?}", gate.reel.pairs);
        assert_eq!(gate.reel.pairs[0].delta, Some(24 - 1), "the free 23-frame gap (no window, no claim)");
        // The per-clip gates still ran on the present clips.
        assert!(gate.clips.iter().all(|c| c.failures.is_empty()));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn p72_ingest_manifest_carries_the_reel_record() {
        // The additive `reel:` header line (PASS form only — the
        // refusal leaves nothing): 2 clips = the multi-clip record,
        // 1 clip = the no-pair record; the pre-parser shape
        // (unknown key) stays parseable (the audit's own parser).
        let tmp = std::env::temp_dir().join(format!("frameprism-p72-im-{}", std::process::id()));
        let frames = synth_root(
            &tmp,
            &[
                (
                    "A",
                    vec![
                        ("A_20260101_000001.DNG", Some(t(0, 0, 0, 0))),
                        ("A_20260101_000002.DNG", Some(t(0, 0, 0, 1))),
                    ],
                ),
                (
                    "B",
                    vec![
                        ("B_20260101_000001.DNG", Some(t(0, 0, 0, 5))),
                        ("B_20260101_000002.DNG", Some(t(0, 0, 0, 6))),
                    ],
                ),
            ],
            None,
        );
        let gate = ingest_gate(&tmp, &frames);
        assert!(gate.is_pass(), "{:?}", gate.failures());
        let p = write_ingest_manifest(&tmp, &tmp, &gate).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("reel: PASS (tc_first strictly after the previous clip's tc_end across the ingest — the gaps are free, no span-continuity claim)"), "the multi-clip reel record: {text}");
        // The single-clip form.
        let tmp1 = std::env::temp_dir().join(format!("frameprism-p72-im1-{}", std::process::id()));
        let frames1 = synth_root(
            &tmp1,
            &[("A", vec![("A_20260101_000001.DNG", Some(t(0, 0, 0, 0)))] )],
            None,
        );
        let gate1 = ingest_gate(&tmp1, &frames1);
        assert!(gate1.is_pass(), "{:?}", gate1.failures());
        let p1 = write_ingest_manifest(&tmp1, &tmp1, &gate1).unwrap();
        let text1 = std::fs::read_to_string(&p1).unwrap();
        assert!(text1.contains("reel: PASS (1 clip — no cross-clip pairs to check)"), "the single-clip record: {text1}");
        // The tc_first/tc_last accessors feed the reel record (the
        // arithmetic domain, not the display strings).
        let a = &gate.clips[0];
        assert_eq!(a.tc_first_frames, Some(0));
        assert_eq!(a.tc_last_frames, Some(1));
        let b = &gate.clips[1];
        assert_eq!(b.tc_first_frames, Some(5));
        assert_eq!(b.tc_last_frames, Some(6));
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&tmp1);
    }

    //: the AppleDouble `._*` shadow robustness (the
    // field incident — a re-encode from an exFAT tree that was a
    // previous macOS write destination would carry the shadows).

    /// G2-8 (the audit frame re-derivation — `collect_dng_frames`):
    /// real frame + `._` shadow → 1 (the pre-fix class: 2× phantom
    /// frames on a shadowed tree).
    #[test]
    fn spec7_g2_collect_dng_frames_skips_the_shadow() {
        let tmp = std::env::temp_dir().join(format!("frameprism-spec7-g2-frames-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("A001_20260101_000001.DNG"), b"frame-bytes").unwrap();
        std::fs::write(tmp.join("._A001_20260101_000001.DNG"), vec![0xFFu8, 0xFE, 0xFF]).unwrap();
        let frames = collect_dng_frames(&tmp).unwrap();
        assert_eq!(
            frames,
            vec![tmp.join("A001_20260101_000001.DNG")],
            "real frame + shadow → 1 (the reals only): {frames:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
