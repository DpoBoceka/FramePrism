//! `frameprism diff`: the frame-level
//! pixel comparator over two encodes of (hopefully) the same source.
//!
//! Contract (the recorded decisions):
//! - **CLI**: `frameprism diff INPUT1 INPUT2 [--strict] [--report PATH]
//!   [--jobs N] [--djxl-bin PATH]`. The codec is AUTO-DETECTED per
//!   input (the layout sniff: a dir of `.DNG` frames = j92; the jxl
//!   4-plane layout = jxl; a plain file / an empty / an ambiguous /
//!   a contradictory dir = a NAMED rc=2 refusal BEFORE any decode —
//!   the usage class, 0 files, no ledger row). Same-codec pairs are
//!   the 3-candidate / tool-version-migration use case; cross-codec
//!   pairs (the `both` run's OUT + OUT-jxl) prove the cross-tier
//!   lossless contract at the decoded-pixel level.
//! - **Comparison is ALWAYS at the decoded-pixel level** — the
//!   containers differ across tiers, so never a byte compare: both
//!   sides go through `decode::decode_frame_p1` (the shipped p1
//!   mosaic plane, w×h u16, both codecs). This module composes the
//!   EXISTING public decode API (`collect_frames` +
//!   `decode_frame_p1` + the public `FrameRef` fields) — `decode.rs`
//!   is never touched.
//! - **Pairing**: by (clip_key, stem) — clip_key = the parent dir
//!   relative to the input root (the relative-path convention; "" for
//!   the flat single-clip layout), stem = the j92 `.DNG` name minus
//!   its suffix = the jxl 4-plane prefix. A SET-JOIN on the key, not
//!   positional (both collectors are sorted encoder-order, but the
//!   join is the key). A key on only one side → the named per-key
//!   `MISSING` line (which side) — rc=1 (structural). A decode
//!   failure (the j92 round-trip loud-fail / any djxl error) or a
//!   dimension mismatch → the named per-frame `FAILED` line — rc=1.
//! - **Per-frame numbers**: px_diff (count of differing pixels),
//!   delta_min / delta_max (the |Δ| over the u16 values — plain
//!   absolute difference), lsb_k = the MINIMAL k with all
//!   |Δ| < 2^k (0 for an identical frame — the "N-LSB-differing"
//!   number). Per-frame delta histogram (DELTA frames only): the
//!   |Δ| → pixel-count distribution as `d=<Δ>:<count>` entries
//!   sorted by Δ ascending; plus the run-level histogram (|Δ| →
//!   TOTAL pixel count across the whole run, sorted ascending).
//! - **The report is DETERMINISTIC**: the `--report` file
//!   carries NO wall clock at all (no `created:` line — unlike the
//!   encode reports: the same inputs are BYTE-IDENTICAL across
//!   runs) and NO absolute paths (clip / frame keys only). Rows
//!   sorted by (clip, frame). The stdout summary is the single
//!   stable line `diff: <N> frame(s) compared — <n> IDENTICAL, <n>
//!   DELTA, <n> MISSING, <n> FAILED` + one named line per frame.
//! - **rc**: default — 0 when the comparison COMPLETED (every
//!   frame on both sides either IDENTICAL or DELTA-named — a delta
//!   is a FINDING, not a failure); 1 on any structural (MISSING /
//!   FAILED). `--strict` — 0 only when every frame is IDENTICAL
//!   (any DELTA → 1; the structural 1 still applies).
//! - **Ledger**: ONE row per COMPLETED run — command `diff`,
//!   codec = the detected pair (`j92+jxl` / `j92+j92` / `jxl+jxl`),
//!   input/output = the two roots (ledger::canon), frames = the
//!   union key count, verdict ∈ `diff-IDENTICAL` (no
//!   DELTA/MISSING/FAILED) / `diff-DELTA` (≥1 DELTA, completed) /
//!   `diff-FAIL` (≥1 MISSING or FAILED). Refusals = NO row.
//! - **Posture**: READ-ONLY on the inputs (no output tree, no
//!   preflight space guard, NO status lines — v1, the audit/decode
//!   posture; the status surface is the encode/bake jobs). The jxl
//!   temp PAMs land in a per-run scratch
//!   `$TMPDIR/frameprism-diff-{pid}-{nanos}` (best-effort cleanup; a
//! concurrent run's scratch is never touched — the 
//!   convention). The frame loop is SEQUENTIAL (deterministic; the
//!   probe: a 147-frame cross-tier diff ≈ 52 s wall — the
//!   decision). The djxl binary is fail-fast checked (`--version`)
//!   BEFORE the first frame when either side is jxl (the
//!   jxl::version_line discipline — decode.rs's copy is private, so
//!   this module probes directly with the same error shape).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;

use crate::decode::{self, Codec, FrameRef};
use crate::jxl::PLANES;

/// The `frameprism diff` CLI arguments (the `Cmd::Diff` payload — the
/// subcommand args live here, not in `main.rs`, per the shared CLI
/// restructure contract).
#[derive(ClapArgs, Debug)]
pub struct Args {
    /// The first encoded clip tree to compare (j92: `.DNG` frames;
    /// jxl: 4 × `.jxl` per frame + the sidecar — auto-detected; a
    /// plain file / an empty / an ambiguous / a contradictory dir is
    /// a named rc=2 refusal before any decode).
    pub input1: PathBuf,
    /// The second encoded clip tree (the same layout rules as input1
    /// — the two sides may be the SAME codec (the tool-version /
    /// 3-candidate use case) or different (the cross-tier lossless
    /// contract: the `both` run's OUT + OUT-jxl)).
    pub input2: PathBuf,
    /// Exit 1 on ANY delta (default: a delta is a FINDING — rc=0
    /// when the comparison completed; a MISSING/FAILED frame is
    /// rc=1 either way).
    #[arg(long)]
    pub strict: bool,
    /// Write the deterministic diff report to PATH (NO wall clock,
    /// NO absolute paths — the same inputs are byte-identical
    /// across runs). Absent = the stdout summary + the per-frame
    /// lines only.
    #[arg(long)]
    pub report: Option<PathBuf>,
    /// Thread budget: the djxl `--num_threads` for the jxl side
    /// (0 = the binary's default threads); the j92 side runs the
    /// in-process decode. The frame loop itself is sequential
    /// (deterministic — the report is sorted anyway).
    #[arg(long, default_value_t = 0)]
    pub jobs: usize,
    /// djxl binary for the jxl decode (path or PATH name; default
    /// `djxl` — the pinned v0.12.0; fail-fast `--version` probe
    /// before the first frame when either side is jxl).
    #[arg(long, default_value = "djxl")]
    pub djxl_bin: PathBuf,
}

// ---------------------------------------------------------------------------
// the pure compare core (fixture-free — the unit tests drive it with
// vectors)
// ---------------------------------------------------------------------------

/// The per-frame comparison result over two same-shape planes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameDelta {
    /// Count of differing pixels.
    pub px_diff: usize,
    /// The smallest |Δ| over the differing pixels (0 when identical).
    pub delta_min: u16,
    /// The largest |Δ| over the differing pixels (0 when identical).
    pub delta_max: u16,
    /// The minimal k with all |Δ| < 2^k (0 for an identical frame —
    /// the "N-LSB-differing" number).
    pub lsb_k: u32,
    /// The |Δ| → pixel-count histogram (sorted by Δ ascending;
    /// empty when identical).
    pub hist: BTreeMap<u16, usize>,
}

/// The per-frame comparison: plain absolute difference over the
/// u16 planes (same length — the caller checks the dimensions).
pub fn compare_planes(a: &[u16], b: &[u16]) -> FrameDelta {
    let mut px_diff = 0usize;
    let mut delta_min = u16::MAX;
    let mut delta_max = 0u16;
    let mut hist: BTreeMap<u16, usize> = BTreeMap::new();
    for (x, y) in a.iter().zip(b.iter()) {
        if x == y {
            continue;
        }
        px_diff += 1;
        let d = x.abs_diff(*y);
        if d < delta_min {
            delta_min = d;
        }
        if d > delta_max {
            delta_max = d;
        }
        *hist.entry(d).or_insert(0) += 1;
    }
    if px_diff == 0 {
        FrameDelta {
            px_diff: 0,
            delta_min: 0,
            delta_max: 0,
            lsb_k: 0,
            hist,
        }
    } else {
        FrameDelta {
            px_diff,
            delta_min,
            delta_max,
            lsb_k: lsb_k_of(delta_max),
            hist,
        }
    }
}

/// The minimal k with 2^k > max_delta (max_delta > 0) = its bit
/// length; k = 0 is reserved for the identical frame.
pub fn lsb_k_of(max_delta: u16) -> u32 {
    debug_assert!(max_delta > 0, "lsb_k_of(0) is undefined — identical frames use k = 0");
    16u32 - max_delta.leading_zeros()
}

/// The run verdict: structural outranks the delta, which
/// outranks the clean identity.
pub fn run_verdict(n_delta: usize, n_missing: usize, n_failed: usize) -> &'static str {
    if n_missing + n_failed > 0 {
        "diff-FAIL"
    } else if n_delta > 0 {
        "diff-DELTA"
    } else {
        "diff-IDENTICAL"
    }
}

/// The rc matrix: structural (MISSING/FAILED) → 1 either way;
/// otherwise --strict → 1 on any DELTA; otherwise 0.
pub fn exit_code(n_delta: usize, n_missing: usize, n_failed: usize, strict: bool) -> u8 {
    if n_missing + n_failed > 0 || strict && n_delta > 0 {
        1
    } else {
        0
    }
}

/// The ledger codec-pair string: the detected pair, in the
/// input1→input2 order.
pub fn codec_pair_str(a: Codec, b: Codec) -> String {
    format!("{}+{}", codec_str(a), codec_str(b))
}

/// The one-spelling codec name (the ledger/both convention: j92 /
/// jxl).
fn codec_str(c: Codec) -> &'static str {
    match c {
        Codec::J92 => "j92",
        Codec::Jxl => "jxl",
    }
}

/// The frame key: (clip_key, stem) — clip_key = the parent dir
/// relative to the (canonical) input root ("" for the flat layout),
/// stem = the j92 `.DNG` name minus its suffix = the jxl 4-plane
/// prefix.
pub fn frame_key(frame: &FrameRef, root_canon: &Path) -> (String, String) {
    match frame {
        FrameRef::J92 { src, .. } => {
            let canon = src.canonicalize().ok();
            let rel = canon
                .as_ref()
                .and_then(|c| c.strip_prefix(root_canon).ok())
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| src.clone());
            let clip = rel
                .parent()
                .map(|d| d.to_string_lossy().into_owned())
                .filter(|s| !s.is_empty())
                .unwrap_or_default();
            let stem = rel
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            (clip, stem)
        }
        FrameRef::Jxl { dir, stem } => {
            let canon = dir.canonicalize().ok();
            let clip = canon
                .as_ref()
                .and_then(|c| c.strip_prefix(root_canon).ok())
                .map(|p| p.to_string_lossy().into_owned())
                .filter(|s| !s.is_empty())
                .unwrap_or_default();
            (clip, stem.clone())
        }
    }
}

/// The report key display: `clip/stem` (the stem alone when flat).
pub fn key_display(clip: &str, stem: &str) -> String {
    if clip.is_empty() {
        stem.to_string()
    } else {
        format!("{clip}/{stem}")
    }
}

/// The per-frame line (the stdout + the report share it): the
/// verdict + the named detail.
pub fn frame_line(clip: &str, stem: &str, verdict: &str, detail: &str) -> String {
    if detail.is_empty() {
        format!("{}  {verdict}", key_display(clip, stem))
    } else {
        format!("{}  {verdict} {detail}", key_display(clip, stem))
    }
}

/// The deterministic report: NO wall clock (no `created:`
/// line — the same inputs render byte-identically), NO absolute
/// paths (clip / frame keys only), rows sorted by (clip, frame) —
/// the caller hands the results pre-sorted; the DELTA frames are
/// the report's histogram source (per-frame + the run-level
/// aggregate).
pub fn render_report(
    version: &str,
    codec1: Codec,
    codec2: Codec,
    n1: usize,
    n2: usize,
    strict: bool,
    verdict: &str,
    frames: &[(String, String, String, String, Option<FrameDelta>)],
    run_hist: &BTreeMap<u16, usize>,
) -> String {
    let (n_id, n_de, n_mi, n_fa) = counts(frames.iter().map(|(_, _, v, _, _)| v.as_str()));
    let mut s = String::new();
    s.push_str("frameprism diff report (v1)\n");
    s.push_str(&format!("tool: frameprism {version}\n"));
    s.push_str(&format!("input1: {} ({n1} frame(s))\n", codec_str(codec1)));
    s.push_str(&format!("input2: {} ({n2} frame(s))\n", codec_str(codec2)));
    s.push_str(&format!("frames compared: {}\n", frames.len()));
    s.push_str(&format!("identical: {n_id}\n"));
    s.push_str(&format!("delta: {n_de}\n"));
    s.push_str(&format!("missing: {n_mi}\n"));
    s.push_str(&format!("failed: {n_fa}\n"));
    s.push_str(&format!("strict: {}\n", if strict { "on" } else { "off" }));
    s.push_str(&format!("verdict: {verdict}\n"));
    s.push('\n');
    s.push_str("frames (sorted by clip, frame)\n");
    for (clip, stem, verdict, detail, _) in frames {
        s.push_str(&frame_line(clip, stem, verdict, detail));
        s.push('\n');
    }
    if frames.iter().any(|(_, _, v, _, d)| v == "DELTA" && d.is_some()) {
        s.push('\n');
        s.push_str("per-frame delta histograms (DELTA frames only)\n");
        for (clip, stem, verdict, _, delta) in frames {
            if verdict != "DELTA" {
                continue;
            }
            s.push_str(&key_display(clip, stem));
            s.push('\n');
            for (d, c) in delta.as_ref().expect("the DELTA frame holds its delta").hist.iter() {
                s.push_str(&format!("  d={d}:{c}\n"));
            }
        }
        s.push('\n');
        s.push_str("run-level delta histogram\n");
        for (d, c) in run_hist {
            s.push_str(&format!("d={d}:{c}\n"));
        }
    }
    s
}

/// Count the (IDENTICAL, DELTA, MISSING, FAILED) tuples over a
/// verdict iterator (the summary + the report header share it).
fn counts<'a>(it: impl Iterator<Item = &'a str>) -> (usize, usize, usize, usize) {
    let mut id = 0usize;
    let mut de = 0usize;
    let mut mi = 0usize;
    let mut fa = 0usize;
    for v in it {
        match v {
            "IDENTICAL" => id += 1,
            "DELTA" => de += 1,
            "MISSING" => mi += 1,
            "FAILED" => fa += 1,
            _ => {}
        }
    }
    (id, de, mi, fa)
}

// ---------------------------------------------------------------------------
// the layout sniff: mirrors the decode.rs collector predicates
// (collect_j92's .DNG walk + cross-codec diagnostic; collect_jxl's
// 4-plane grouping + name rule + completeness) with the diff's own
// named refusals
// ---------------------------------------------------------------------------

/// Detect the input layout: a dir of `.DNG` frames = j92; the jxl
/// 4-plane layout = jxl; everything else (a plain file, an empty
/// dir, an ambiguous dir, an unrecognized / incomplete jxl layout)
/// = the NAMED refusal (the rc=2 usage class — before any decode).
fn sniff(root: &Path) -> Result<Codec> {
    if !root.is_dir() {
        bail!(
            "diff input is not a directory: {} (a plain file — a single .DNG is accepted as ONE frame by the `decode` verb, but `diff` wants two TREE pairs; give it the clip dirs)",
            root.display()
        );
    }
    let mut dng_count = 0u64;
    let mut jxl_count = 0u64;
    let mut visited = std::collections::HashSet::new();
    // (dir, stem) → the 4 plane slots seen
    let mut groups: BTreeMap<(String, String), [bool; 4]> = BTreeMap::new();
    walk_sniff(root, root, &mut visited, &mut |p, rel| {
        let name = p
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if ext_is(p, "dng") {
            dng_count += 1;
            let _ = rel;
            return Ok(());
        }
        if ext_is(p, "jxl") {
            jxl_count += 1;
            let mut matched = false;
            for (i, plane) in PLANES.iter().enumerate() {
                let suffix = format!("_{plane}.jxl");
                if let Some(stem) = name.strip_suffix(&suffix) {
                    if stem.is_empty() {
                        bail!("unparseable jxl frame name: {name}");
                    }
                    let dir_rel = p
                        .parent()
                        .unwrap()
                        .strip_prefix(root)
                        .unwrap_or_else(|_| p.parent().unwrap())
                        .to_string_lossy()
                        .into_owned();
                    groups
                        .entry((dir_rel, stem.to_string()))
                        .or_insert([false; 4])[i] = true;
                    matched = true;
                    break;
                }
            }
            if !matched {
                bail!(
                    "unrecognized .jxl name (expected <stem>_p2_{{00,01,10,11}}.jxl): {name}"
                );
            }
        }
        Ok(())
    })?;
    if dng_count > 0 && jxl_count > 0 {
        bail!(
            "ambiguous diff input {} ({dng_count} .DNG + {jxl_count} .jxl file(s) — one input must be ONE codec's layout; split the trees)",
            root.display()
        );
    }
    if dng_count > 0 {
        return Ok(Codec::J92);
    }
    if jxl_count > 0 {
        let mut bad: Vec<String> = Vec::new();
        for ((dir_rel, stem), planes) in &groups {
            if !planes.iter().all(|&b| b) {
                let missing: Vec<&str> = planes
                    .iter()
                    .enumerate()
                    .filter(|(_, &b)| !b)
                    .map(|(i, _)| PLANES[i])
                    .collect();
                bad.push(format!(
                    "{stem} in {}: missing plane(s) {}",
                    if dir_rel.is_empty() { root.display().to_string() } else { format!("{}/{}", root.display(), dir_rel) },
                    missing.join(", ")
                ));
            }
        }
        if !bad.is_empty() {
            bail!(
                "incomplete jxl frame group(s) in {} (the 4-plane layout requires all 4 planes per frame): {}",
                root.display(),
                bad.join("; ")
            );
        }
        return Ok(Codec::Jxl);
    }
    bail!(
        "no frames in diff input {} (no .DNG or .jxl files — empty or an unrecognized layout)",
        root.display()
    );
}

/// The sniff's walk (mirrors decode.rs's `walk`: recurses, refuses
/// symlinked entries — the cycle/escape guard — the (dev, ino)
/// visited set for symlink fan-in).
#[cfg(unix)]
fn walk_sniff(
    base: &Path,
    dir: &Path,
    visited: &mut std::collections::HashSet<(u64, u64)>,
    visit_file: &mut dyn FnMut(&Path, &Path) -> Result<()>,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(dir)
        .with_context(|| format!("read dir {}", dir.display()))?;
    let id = (meta.dev(), meta.ino());
    if !visited.insert(id) {
        return Ok(());
    }
    let entries =
        std::fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue; // refuse symlinked entries (cycle/escape guard)
        }
        if p.is_dir() {
            walk_sniff(base, &p, visited, visit_file)?;
        } else if p.is_file() {
            let rel = p.strip_prefix(base).unwrap_or(&p);
            visit_file(&p, rel)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn walk_sniff(
    base: &Path,
    dir: &Path,
    _visited: &mut std::collections::HashSet<(u64, u64)>,
    visit_file: &mut dyn FnMut(&Path, &Path) -> Result<()>,
) -> Result<()> {
    let entries =
        std::fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        if p.is_dir() {
            walk_sniff(base, &p, _visited, visit_file)?;
        } else if p.is_file() {
            let rel = p.strip_prefix(base).unwrap_or(&p);
            visit_file(&p, rel)?;
        }
    }
    Ok(())
}

fn ext_is(p: &Path, want: &str) -> bool {
    p.extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case(want))
        .unwrap_or(false)
}

/// First line of `bin --version` (the named fail-fast before the
/// first frame — the jxl::version_line discipline; decode.rs's copy
/// is private, so the diff probes directly with the same shape).
fn version_line(bin: &Path) -> Result<String> {
    let out = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .with_context(|| format!("run {} --version", bin.display()))?;
    if !out.status.success() {
        bail!(
            "{} --version failed (rc {:?}): {}",
            bin.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string())
}

// ---------------------------------------------------------------------------
// entry
// ---------------------------------------------------------------------------

/// The `Cmd::Diff` match arm (main.rs): run the diff, return the
/// process exit code (2 = pre-run error / refusal, 1 = structural or
/// --strict delta, 0 = clean).
pub fn run(args: &Args) -> ExitCode {
    let t0 = Instant::now();
    match run_inner(args) {
        Ok(out) => {
            // The per-frame named lines (sorted by (clip, frame)) +
            // the single-line summary.
            for (clip, stem, verdict, detail, _) in &out.lines {
                println!("{}", frame_line(clip, stem, verdict, detail));
            }
            println!(
                "diff: {} frame(s) compared — {} IDENTICAL, {} DELTA, {} MISSING, {} FAILED",
                out.lines.len(),
                out.n_identical,
                out.n_delta,
                out.n_missing,
                out.n_failed
            );
            // The deterministic report — a write failure is a
            // named rc=2 BEFORE the ledger row (the finish_tier
            // convention: the row records a completed + recorded run).
            if let Some(path) = &args.report {
                match std::fs::write(path, out.report_text.clone()) {
                    Ok(()) => eprintln!("report written to {}", path.display()),
                    Err(err) => {
                        eprintln!("error: failed to write report {}: {err:#}", path.display());
                        let _ = std::fs::remove_dir_all(&out.scratch);
                        return ExitCode::from(2);
                    }
                }
            }
            // The ledger row: ONE row per COMPLETED run.
            crate::ledger::append_quiet(&crate::ledger::Row {
                created: crate::ledger::now_secs(),
                command: "diff".into(),
                tool_version: env!("CARGO_PKG_VERSION").into(),
                input: crate::ledger::canon(&args.input1),
                output: crate::ledger::canon(&args.input2),
                codec: out.codec_pair,
                frames: out.lines.len() as u64,
                verdict: out.verdict,
                duration_s: t0.elapsed().as_secs(),
                dest: String::new(),
                // The diff verb has no selection flags (v1): the
                // column is always empty.
                selection: String::new(),
                // The diff verb never runs under --subset (the encode
                // verbs carry the flag): the column is always empty.
                context: String::new(),
            });
            let _ = std::fs::remove_dir_all(&out.scratch); // best-effort
            let rc = exit_code(out.n_delta, out.n_missing, out.n_failed, args.strict);
            ExitCode::from(rc)
        }
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

struct Outcome {
    /// The per-frame lines, sorted by (clip, frame): (clip, stem,
    /// verdict, detail, the delta when DELTA).
    lines: Vec<(String, String, String, String, Option<FrameDelta>)>,
    n_identical: usize,
    n_delta: usize,
    n_missing: usize,
    n_failed: usize,
    verdict: String,
    codec_pair: String,
    report_text: String,
    scratch: PathBuf,
}

fn run_inner(args: &Args) -> Result<Outcome> {
    // The layout sniff — the named rc=2 refusals, BEFORE any
    // decode (0 files, no ledger row — the usage class).
    let codec1 = sniff(&args.input1)?;
    let codec2 = sniff(&args.input2)?;

    // The djxl fail-fast (the jxl::version_line discipline) when
    // either side is jxl — BEFORE the first frame.
    if codec1 == Codec::Jxl || codec2 == Codec::Jxl {
        let _ = version_line(&args.djxl_bin)?;
    }

    // The frame sets (the shipped collectors — the same cross-codec
    // diagnostics; a mismatch would have been refused by the sniff
    // already, so these are the encoder-order lists).
    let frames1 = decode::collect_frames(codec1, &args.input1)?;
    let frames2 = decode::collect_frames(codec2, &args.input2)?;

    // The keyed sides: (clip_key, stem) → the frame ref. The
    // canonical roots make the strip_prefix stable (a relative input
    // path, a symlinked root — /tmp on macOS).
    let root1 = std::fs::canonicalize(&args.input1)
        .with_context(|| format!("canonicalize diff input1 {}", args.input1.display()))?;
    let root2 = std::fs::canonicalize(&args.input2)
        .with_context(|| format!("canonicalize diff input2 {}", args.input2.display()))?;
    let mut side1: BTreeMap<(String, String), FrameRef> = BTreeMap::new();
    for f in &frames1 {
        side1.insert(frame_key(f, &root1), f.clone());
    }
    let mut side2: BTreeMap<(String, String), FrameRef> = BTreeMap::new();
    for f in &frames2 {
        side2.insert(frame_key(f, &root2), f.clone());
    }

    // The jxl PAM scratch (the per-run convention — a concurrent
    // run's scratch is never touched).
    let scratch = make_scratch()?;

    // The frame loop (SEQUENTIAL — the probe decision: a 147-
    // frame cross-tier diff ≈ 52 s wall; the report is sorted
    // anyway).
    let mut lines: Vec<(String, String, String, String, Option<FrameDelta>)> = Vec::new();
    let mut run_hist: BTreeMap<u16, usize> = BTreeMap::new();
    for key in side1
        .keys()
        .chain(side2.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<(String, String)>>() {
        let (clip, stem) = (&key.0, &key.1);
        match (side1.get(&key), side2.get(&key)) {
            (Some(a), Some(b)) => {
                let ra = decode::decode_frame_p1(a, &scratch, &args.djxl_bin, args.jobs);
                let rb = decode::decode_frame_p1(b, &scratch, &args.djxl_bin, args.jobs);
                match (ra, rb) {
                    (Ok((w1, h1, pa)), Ok((w2, h2, pb))) => {
                        if (w1, h1) != (w2, h2) {
                            lines.push((
                                clip.clone(),
                                stem.clone(),
                                "FAILED".into(),
                                format!(
                                    "dimension mismatch: input1 {w1}×{h1} vs input2 {w2}×{h2}"
                                ),
                                None,
                            ));
                        } else {
                            let d = compare_planes(&pa, &pb);
                            if d.px_diff == 0 {
                                lines.push((clip.clone(), stem.clone(), "IDENTICAL".into(), String::new(), None));
                            } else {
                                for (dv, c) in d.hist.iter() {
                                    *run_hist.entry(*dv).or_insert(0) += c;
                                }
                                let detail = format!(
                                    "px_diff={} delta_min={} delta_max={} lsb_k={}",
                                    d.px_diff, d.delta_min, d.delta_max, d.lsb_k
                                );
                                lines.push((
                                    clip.clone(),
                                    stem.clone(),
                                    "DELTA".into(),
                                    detail,
                                    Some(d),
                                ));
                            }
                        }
                    }
                    (Err(ea), Ok(_)) => lines.push((
                        clip.clone(),
                        stem.clone(),
                        "FAILED".into(),
                        format!("input1 decode failed: {ea:#}"),
                        None,
                    )),
                    (Ok(_), Err(eb)) => lines.push((
                        clip.clone(),
                        stem.clone(),
                        "FAILED".into(),
                        format!("input2 decode failed: {eb:#}"),
                        None,
                    )),
                    (Err(ea), Err(eb)) => lines.push((
                        clip.clone(),
                        stem.clone(),
                        "FAILED".into(),
                        format!("input1 decode failed: {ea:#}; input2 decode failed: {eb:#}"),
                        None,
                    )),
                }
            }
            (Some(_), None) => lines.push((
                clip.clone(),
                stem.clone(),
                "MISSING".into(),
                "only in input1".into(),
                None,
            )),
            (None, Some(_)) => lines.push((
                clip.clone(),
                stem.clone(),
                "MISSING".into(),
                "only in input2".into(),
                None,
            )),
            (None, None) => unreachable!("the union key set"),
        }
    }

    let n_identical = lines.iter().filter(|(_, _, v, _, _)| v == "IDENTICAL").count();
    let n_delta = lines.iter().filter(|(_, _, v, _, _)| v == "DELTA").count();
    let n_missing = lines.iter().filter(|(_, _, v, _, _)| v == "MISSING").count();
    let n_failed = lines.iter().filter(|(_, _, v, _, _)| v == "FAILED").count();
    let verdict = run_verdict(n_delta, n_missing, n_failed).to_string();
    let codec_pair = codec_pair_str(codec1, codec2);
    let report_text = render_report(
        env!("CARGO_PKG_VERSION"),
        codec1,
        codec2,
        frames1.len(),
        frames2.len(),
        args.strict,
        &verdict,
        &lines,
        &run_hist,
    );

    Ok(Outcome {
        lines,
        n_identical,
        n_delta,
        n_missing,
        n_failed,
        verdict,
        codec_pair,
        report_text,
        scratch,
    })
}

/// The per-run scratch root: `$TMPDIR/frameprism-diff-{pid}-{nanos}`
/// (TMPDIR absent → /tmp; the nanos suffix = the per-run uniqueness
/// — a concurrent run's scratch is never touched).
fn make_scratch() -> Result<PathBuf> {
    let tmp = std::env::var("TMPDIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"));
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let p = tmp.join(format!("frameprism-diff-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&p)
        .with_context(|| format!("create scratch dir {}", p.display()))?;
    Ok(p)
}

// ---------------------------------------------------------------------------
// unit tests (additive — the pure core; the sniff is exercised over
// a temp dir, no project fixtures)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_identical_planes() {
        let a = vec![0u16, 4095, 2048, 7];
        let d = compare_planes(&a, &a);
        assert_eq!(d.px_diff, 0);
        assert_eq!((d.delta_min, d.delta_max), (0, 0));
        assert_eq!(d.lsb_k, 0);
        assert!(d.hist.is_empty());
    }

    #[test]
    fn compare_known_deltas() {
        let a = vec![0, 1, 3, 4, 10, 100];
        let b = vec![0, 3, 0, 10, 10, 107];
        let d = compare_planes(&a, &b);
        // Δ = 0, 2, 3, 6, 0, 7
        assert_eq!(d.px_diff, 4);
        assert_eq!(d.delta_min, 2);
        assert_eq!(d.delta_max, 7);
        assert_eq!(d.lsb_k, 3, "2^3 = 8 > 7; 2^2 = 4 is not");
        assert_eq!(d.hist[&2], 1);
        assert_eq!(d.hist[&3], 1);
        assert_eq!(d.hist[&6], 1);
        assert_eq!(d.hist[&7], 1);
    }

    #[test]
    fn lsb_k_boundaries() {
        assert_eq!(lsb_k_of(1), 1, "2^1 = 2 > 1");
        assert_eq!(lsb_k_of(2), 2, "2^2 = 4 > 2; 2^1 = 2 is not");
        assert_eq!(lsb_k_of(3), 2, "2^2 = 4 > 3");
        assert_eq!(lsb_k_of(4), 3, "2^3 = 8 > 4; 2^2 = 4 is not");
        assert_eq!(lsb_k_of(4095), 12, "2^12 = 4096 > 4095");
    }

    #[test]
    fn verdict_and_rc_matrix() {
        assert_eq!(run_verdict(0, 0, 0), "diff-IDENTICAL");
        assert_eq!(run_verdict(3, 0, 0), "diff-DELTA");
        assert_eq!(run_verdict(3, 1, 0), "diff-FAIL");
        assert_eq!(run_verdict(0, 0, 2), "diff-FAIL");
        // the rc matrix 
        assert_eq!(exit_code(0, 0, 0, false), 0);
        assert_eq!(exit_code(5, 0, 0, false), 0, "a delta is a finding — not a failure");
        assert_eq!(exit_code(5, 0, 0, true), 1, "--strict: any delta → 1");
        assert_eq!(exit_code(0, 1, 0, false), 1, "structural → 1");
        assert_eq!(exit_code(0, 0, 1, true), 1, "structural outranks strict");
    }

    #[test]
    fn codec_pair_strings() {
        assert_eq!(codec_pair_str(Codec::J92, Codec::Jxl), "j92+jxl");
        assert_eq!(codec_pair_str(Codec::J92, Codec::J92), "j92+j92");
        assert_eq!(codec_pair_str(Codec::Jxl, Codec::J92), "jxl+j92");
        assert_eq!(codec_pair_str(Codec::Jxl, Codec::Jxl), "jxl+jxl");
    }

    #[test]
    fn frame_key_j92_nested_and_flat() {
        // A real temp file (the strip_prefix needs an existing path).
        let dir = std::env::temp_dir().join(format!("frameprism-diff-test-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()));
        let nested = dir.join("CLIP_A");
        std::fs::create_dir_all(&nested).unwrap();
        let f = nested.join("f001.DNG");
        std::fs::write(&f, b"x").unwrap();
        let root = dir.canonicalize().unwrap();
        let k = frame_key(&FrameRef::J92 { src: f.clone(), name: "f001.DNG".into() }, &root);
        assert_eq!(k, ("CLIP_A".into(), "f001".into()));
        let flat = dir.join("g001.DNG");
        std::fs::write(&flat, b"x").unwrap();
        let k2 = frame_key(&FrameRef::J92 { src: flat.clone(), name: "g001.DNG".into() }, &root);
        assert_eq!(k2, (String::new(), "g001".into()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn frame_key_jxl() {
        let dir = std::env::temp_dir().join(format!("frameprism-diff-test-x-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()));
        let nested = dir.join("CLIP_B");
        std::fs::create_dir_all(&nested).unwrap();
        let root = dir.canonicalize().unwrap();
        let k = frame_key(
            &FrameRef::Jxl { dir: nested.clone(), stem: "f002".into() },
            &root,
        );
        assert_eq!(k, ("CLIP_B".into(), "f002".into()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn report_is_deterministic_and_clockless() {
        let frames: Vec<(String, String, String, String, Option<FrameDelta>)> = vec![
            (
                "A".into(),
                "f1".into(),
                "IDENTICAL".into(),
                String::new(),
                None,
            ),
            (
                "A".into(),
                "f2".into(),
                "DELTA".into(),
                "px_diff=2 delta_min=1 delta_max=2 lsb_k=2".into(),
                Some(FrameDelta {
                    px_diff: 2,
                    delta_min: 1,
                    delta_max: 2,
                    lsb_k: 2,
                    hist: {
                        let mut m = BTreeMap::new();
                        m.insert(1, 1);
                        m.insert(2, 1);
                        m
                    },
                }),
            ),
        ];
        let mut run_hist = BTreeMap::new();
        run_hist.insert(1, 1);
        run_hist.insert(2, 1);
        let r1 = render_report("0.4.0", Codec::J92, Codec::Jxl, 2, 2, false, "diff-DELTA", &frames, &run_hist);
        let r2 = render_report("0.4.0", Codec::J92, Codec::Jxl, 2, 2, false, "diff-DELTA", &frames, &run_hist);
        assert_eq!(r1, r2, "same inputs → byte-identical report");
        assert!(!r1.contains("created:"), "no wall clock line");
        assert!(!r1.contains("/Users"), "no absolute paths");
        assert!(r1.contains("input1: j92 (2 frame(s))"));
        assert!(r1.contains("input2: jxl (2 frame(s))"));
        assert!(r1.contains("A/f1  IDENTICAL"));
        assert!(r1.contains("A/f2  DELTA px_diff=2 delta_min=1 delta_max=2 lsb_k=2"));
        assert!(r1.contains("d=1:1"));
        assert!(r1.contains("d=2:1"));
    }

    #[test]
    fn report_identity_run_has_no_histogram_sections() {
        let frames: Vec<(String, String, String, String, Option<FrameDelta>)> = vec![(
            String::new(),
            "solo".into(),
            "IDENTICAL".into(),
            String::new(),
            None,
        )];
        let r = render_report("0.4.0", Codec::J92, Codec::J92, 1, 1, true, "diff-IDENTICAL", &frames, &BTreeMap::new());
        assert!(!r.contains("delta histograms"), "no histogram section without DELTA frames:\n{r}");
        assert!(r.contains("solo  IDENTICAL"), "flat layout: the stem alone");
        assert!(r.contains("strict: on"));
    }

    #[test]
    fn sniff_rejects_named() {
        let base = std::env::temp_dir().join(format!("frameprism-diff-sniff-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()));
        // empty dir
        std::fs::create_dir_all(&base).unwrap();
        assert!(sniff(&base).unwrap_err().to_string().contains("no frames in diff input"));
        // a plain file
        let f = base.join("not-a-dir.DNG");
        std::fs::write(&f, b"x").unwrap();
        assert!(sniff(&f).unwrap_err().to_string().contains("not a directory"));
        // a j92 dir
        let j92 = base.join("j92");
        std::fs::create_dir_all(&j92).unwrap();
        std::fs::write(j92.join("a.DNG"), b"x").unwrap();
        assert!(matches!(sniff(&j92).unwrap(), Codec::J92));
        // a jxl dir (the 4-plane layout)
        let jxl = base.join("jxl");
        std::fs::create_dir_all(&jxl).unwrap();
        for p in PLANES {
            std::fs::write(jxl.join(format!("s1_{p}.jxl")), b"x").unwrap();
        }
        assert!(matches!(sniff(&jxl).unwrap(), Codec::Jxl));
        // ambiguous
        let amb = base.join("amb");
        std::fs::create_dir_all(&amb).unwrap();
        std::fs::write(amb.join("a.DNG"), b"x").unwrap();
        for p in PLANES {
            std::fs::write(amb.join(format!("s1_{p}.jxl")), b"x").unwrap();
        }
        assert!(sniff(&amb).unwrap_err().to_string().contains("ambiguous diff input"));
        // incomplete group
        let inc = base.join("inc");
        std::fs::create_dir_all(&inc).unwrap();
        std::fs::write(inc.join("s1_p2_00.jxl"), b"x").unwrap();
        std::fs::write(inc.join("s1_p2_01.jxl"), b"x").unwrap();
        let e = sniff(&inc).unwrap_err().to_string();
        assert!(e.contains("incomplete jxl frame group"), "{e}");
        assert!(e.contains("s1"), "{e}");
        // an unrecognized jxl name
        let bad = base.join("bad");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("s1_p9_00.jxl"), b"x").unwrap();
        assert!(sniff(&bad).unwrap_err().to_string().contains("unrecognized .jxl name"));
        let _ = std::fs::remove_dir_all(&base);
    }
}
