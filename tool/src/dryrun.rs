//! The `--dry-run` estimate (the predict-then-measure arc,
//! first half) + the process-state flag (the pins/selection/resume
//! OnceLock convention — the `--subset` template:
//! `static DRYRUN_FLAG`, `set_dryrun_flag`, `dryrun_flag`).
//!
//! Contract (the shape):
//! - The dry run CREATES NOTHING: the sample encode runs in RAM
//!   (`worker::encode_frame_memory` — the buffer seam) with the VERIFY
//!   pass ALWAYS on (the decode + the bit-exact compare — the honesty
//!   anchor), never touches `<dest>` (not even the dir), writes no
//!   sidecars/manifests, and appends NO ledger row (named in the
//!   report: `dry run: no ledger row (no archive action, no
//!   reservation commit)` — the ledger is the archive-action record;
//!   the `--report FILE` markdown is the dry run's record).
//! - The estimate is a MEASURED sample, not a model — the entropy
//!   stage is what knows the size, so the number is real; the SPREAD
//!   is the honest output (min/median/p90/max), never a point
//!   estimate; the projections are the honest RANGE (the p10-ratio
//!   bound = the LARGEST size = the worst case).
//! - The sample selection is the SAME pinned SplitMix64 as
//! `tools/m3_reverify.sh` (the gate's selection — the composition
//! property: a K=60 dry-run sample IS the gate sample for the
//!   same clip + seed; the selection sha is the harness-canonical
//!   form — the G2 byte-level proof).
//! - Named refusals: the codec/flag combos + the K range + the gate's
//!   kept classes + the space = rc=2; the sample verify failure + the
//!   sample encode failure = rc=1 (the estimate is still printed — the
//!   verdict is the refusal, the archive action is NOT sanctioned).

use std::path::{Path, PathBuf};

// =====================================================================
// The process-state flag (the pins/selection/resume OnceLock
// convention — the CLI sets it; the lower layers can tell a dry-run
// context from an archive action).
// =====================================================================

static DRYRUN_FLAG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Set the process-wide dry-run flag (the CLI dispatch, once).
pub fn set_dryrun_flag(dry_run: bool) {
    let _ = DRYRUN_FLAG.set(dry_run);
}

/// The process-wide dry-run flag (absent = false — the pre-existing
/// behavior stands).
pub fn dryrun_flag() -> bool {
    *DRYRUN_FLAG.get().unwrap_or(&false)
}

/// The default LCG seed (the gate default — the canonical hex form on
/// the sample line: `0x20260916`).
pub const SEED: u64 = 0x2026_0916;

/// The byte-stable marker line (NO wall clock, NO path; K/N
/// are the established variables, so the same (K, N) yields the same
/// bytes). Distinct from the subset run's `SUBSET_MARKER` — the
/// ledger/report must distinguish the two purposes (the subset marker
/// rides the archive-action record; the dry-run marker rides the
/// estimate record only — no ledger row exists to carry it).
pub fn marker_line(k: usize, n: usize) -> String {
    format!(
        "dry-run: estimate ({k} of {n} sampled, continuity waived for the sparse sample)"
    )
}

// =====================================================================
// The pinned selection (the LCG, mirrored in Rust — the gate G2 is
// the byte-level proof against the bash implementation).
// =====================================================================

/// One SplitMix64 draw (the harness's exact arithmetic — the
/// wrapping u64 ops + the LOGICAL shifts are Rust's u64 ops by
/// construction; the state update is part of the draw, harness form:
/// `state=(state+0x9E3779B97F4A7C15) mod 2^64; z=state; …`).
pub fn lcg_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z ^= z >> 30;
    z = z.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z ^= z >> 27;
    z = z.wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    z
}

/// Rejection-sample K distinct indices in `[0, N)` — the SAME draw
/// order as the harness (draw, `mod N`, reject duplicates, until K
/// distinct). Returns in DRAW order (the report table + the sha sort
/// ascending separately — the harness canonical form).
pub fn lcg_select(n: u64, k: u64, seed: u64) -> Vec<u64> {
    assert!(n >= 1 && k >= 1 && k <= n, "lcg_select: 1 ≤ k ≤ n");
    let mut state = seed;
    let mut seen = std::collections::BTreeSet::new();
    let mut out: Vec<u64> = Vec::with_capacity(k as usize);
    while out.len() < k as usize {
        let idx = lcg_next(&mut state) % n;
        if seen.insert(idx) {
            out.push(idx);
        }
    }
    out
}

/// The selection sha in the HARNESS-CANONICAL form (`tools/m3_reverify.sh`
/// read from disk — the G8 checkpoint): the sha256 of the ASCENDING
/// numeric indices joined by `,` + ONE trailing `\n` (the harness
/// sorts `SEL` with `LC_ALL=C sort -n` = numeric ascending, joins with
/// the `IFS=,` echo, and hashes `"$sel_str"$'\n'`). The digest =
/// `crate::jxl::sha256_hex` (the hand-rolled FIPS 180-4 — one
/// implementation, no new crate).
pub fn selection_sha(indices: &[u64]) -> String {
    let mut sorted: Vec<u64> = indices.to_vec();
    sorted.sort_unstable();
    let joined: String = sorted
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");
    crate::jxl::sha256_hex(format!("{joined}\n").as_bytes())
}

/// The default K (the -approved clamp rule): `min(N, min(max(20,
/// ceil(N/10)), 60))` — 10% of the clip, floored at 20 (below that the
/// band is too wide), capped at 60 (the standard shape; also the memory
/// bound).
pub fn clamp_k(n: u64) -> u64 {
    let tenth = n.div_ceil(10); // ceil(N/10)
    n.min(60.min(20.max(tenth)))
}

// =====================================================================
// The stats + the projection (the harness's stats function,
// mirrored from `tools/m5_ratio_band.sh`'s awk).
// =====================================================================

/// The median (the harness form: the middle value for odd N, the
/// mean of the two middle for even N). `v` is sorted ascending.
pub fn median_sorted(v: &[f64]) -> f64 {
    let n = v.len();
    assert!(n >= 1, "median_sorted: non-empty");
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// The nearest-rank percentile (1-indexed rank = `ceil(p·N)`, clamped
/// to `[1, N]` — the harness's form: its p90 rank =
/// `int((9n+9)/10)` = `ceil(0.9n)`). `v` is sorted ascending.
pub fn percentile_nearest_rank_sorted(v: &[f64], p: f64) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    let n = v.len();
    let rank = ((p * n as f64).ceil() as usize).clamp(1, n);
    Some(v[rank - 1])
}

/// The ratio band (the harness form): min / median (the harness
/// median) / p90 (nearest-rank) / max. `ratios` unsorted.
pub struct Band {
    pub min: f64,
    pub median: f64,
    pub p90: f64,
    pub max: f64,
    /// The projection quantiles (nearest-rank p10/p50/p90 — the
    /// p50 NEAREST-RANK, which differs from the harness median at
    /// even K — the ETA/p50 wording is nearest-rank).
    pub p10: f64,
    pub p50: f64,
    pub p90_rank: f64,
}

pub fn band(ratios: &[f64]) -> Band {
    let mut s: Vec<f64> = ratios.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Band {
        min: s[0],
        median: median_sorted(&s),
        p90: percentile_nearest_rank_sorted(&s, 0.90).unwrap(),
        max: s[s.len() - 1],
        p10: percentile_nearest_rank_sorted(&s, 0.10).unwrap(),
        p50: percentile_nearest_rank_sorted(&s, 0.50).unwrap(),
        p90_rank: percentile_nearest_rank_sorted(&s, 0.90).unwrap(),
    }
}

/// The projection at quantile ratio `r` in the FALLBACK form:
/// `total_source / r` (rounded to bytes).
pub fn project_total_ratio(total_source: u64, r: f64) -> u64 {
    (total_source as f64 / r).round() as u64
}

/// The projection at quantile ratio `ratio_q` in the PRIMARY form
/// (per-frame-then-sum — "the per-frame ratio applied to the
/// per-frame source bytes, summed — the child verifies which form the
/// harness stats support and uses the per-frame-then-sum form if the
/// encode sizes are per-frame known"): the SAMPLED frames at their
/// MEASURED per-frame encoded bytes + the UNSAMPLED frames at
/// `src_i / ratio_q` (the sum is rounded once — the per-frame values
/// are not pre-rounded).
pub fn project_per_frame(sum_sampled_enc: u64, unsampled_src: &[u64], ratio_q: f64) -> u64 {
    let tail: f64 = unsampled_src.iter().map(|s| *s as f64 / ratio_q).sum();
    (sum_sampled_enc as f64 + tail).round() as u64
}

/// The ETA: the per-frame wall's p50 / p95
/// (nearest-rank) × N frames (ms).
pub fn eta_ms(ms: &[f64], n: u64) -> (Option<f64>, Option<f64>) {
    let mut s: Vec<f64> = ms.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    (
        percentile_nearest_rank_sorted(&s, 0.50).map(|m| m * n as f64),
        percentile_nearest_rank_sorted(&s, 0.95).map(|m| m * n as f64),
    )
}

// =====================================================================
// The estimate (the driver).
// =====================================================================

/// The dry-run inputs (the CLI surface — the encode flags that the
/// in-memory seam honors).
pub struct Opts {
    /// `<dest>` — REQUIRED (the same CLI shape): the fit-check target.
    pub dest: PathBuf,
    /// The explicit `--dry-run-frames K` (absent = the clamp rule).
    pub k_override: Option<u64>,
    /// The `--report FILE` markdown (the dry run's record).
    pub report: Option<PathBuf>,
    pub mode: crate::worker::Mode,
    pub lossy_format: crate::worker::LossyFormat,
    pub reference: crate::worker::ReferenceDctOpts,
    pub downscale: bool,
    pub fast: bool,
    /// The CLI `--jobs` (named-ignored: the sample loop is sequential
    /// — the per-frame wall is jobs-independent, the frame encode is
    /// single-threaded; the line is printed).
    pub jobs: usize,
    /// The CLI `--verify` flag (subsumed — the sample ALWAYS verifies;
    /// the named note is printed when present).
    pub verify_flag: bool,
}

/// The estimate's verdict (the exit-code mapping: Pass=0, the
/// rc=2 class = Space/KRange/Gate, the rc=1 class =
/// Verify/Encode).
#[derive(Debug)]
pub enum Verdict {
    Pass,
    Space,
    KRange,
    Gate,
    /// The sample failed round-trip (the named frame).
    Verify(String),
    /// The sample encode failed (the named frame + the error).
    Encode { name: String, err: String },
}

impl Verdict {
    pub fn exit_code(&self) -> u8 {
        match self {
            Verdict::Pass => 0,
            Verdict::Space | Verdict::KRange | Verdict::Gate => 2,
            Verdict::Verify(_) | Verdict::Encode { .. } => 1,
        }
    }
}

/// The sample-failure classification (the two named classes,
/// G6): every VERIFY-GATE failure inside `encode_core` is tagged with
/// the `verify: ` prefix by `worker::vctx`, so a failure message
/// starting with `verify: ` is a sample VERIFY failure (the round-trip
/// broke — the codec's honesty anchor failed) and anything else is an
/// ENCODE failure (parse/structural/IO). Both refuse with rc=1 and
/// both still print the estimate over the measured partial sample.
pub fn is_verify_failure(err_msg: &str) -> bool {
    err_msg.starts_with("verify: ")
}

/// One measured sample frame (the report's per-frame row).
struct Measured {
    name: String,
    src_b: u64,
    enc_b: u64,
    ratio: f64,
    ms: f64,
    verify_ms: f64,
}

/// The estimate . Prints the named lines (stdout + stderr),
/// writes the `--report` markdown when requested, and returns the
/// (verdict, exit code). Never writes under `dest` (not even the dir);
/// never appends a ledger row. The per-frame encode lines ride the
/// live-metrics surface (`crate::live` — the dry run drives the same
/// begin/note_done/finish over its sequential sample loop).
pub fn estimate(input: &Path, o: &Opts) -> (Verdict, u8) {
    // --- the frame collection (the worker's path-sorted, case-
    // insensitive .dng collection — the index space of the selection) ---
    let frames = match crate::worker::collect_dng_frames(input) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("error: dry-run: scan the source frames: {err}");
            return (Verdict::Gate, 1);
        }
    };
    let n = frames.len();
    if n == 0 {
        eprintln!("error: no .dng frames under {}", input.display());
        return (Verdict::Gate, 1);
    }
    let n64 = n as u64;

    // --- the sample size (the K-range refusal is BEFORE the gate —
    // the usage class) ---
    let (k, rule) = match o.k_override {
        Some(kk) => {
            if kk == 0 || kk > n64 {
                eprintln!(
                    "DRY RUN REFUSED — k-range: --dry-run-frames {kk} is out of range (1 ≤ K ≤ N={n64}; K=N is the legal full-clip measurement — run without --dry-run-frames for the clamp default)"
                );
                return (Verdict::KRange, 2);
            }
            (kk as usize, "the explicit --dry-run-frames")
        }
        None => (clamp_k(n64) as usize, "the 10% default, clamp [20,60]"),
    };
    let k64 = k as u64;

    // --- the sample line + the selection (the pinned section) ---
    println!(
        "dry-run: sample {k} of {n} ({rule}), seed 0x{SEED:x}"
    );
    let selected = crate::dryrun::lcg_select(n64, k64, SEED);
    let sha = selection_sha(&selected);
    println!("selection_sha256: {sha}");
    println!("{}", marker_line(k, n));

    // The frame metadata (the source bytes — the projection inputs;
    // the file sizes, no reads).
    let src_sizes: Vec<u64> = frames
        .iter()
        .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .collect();
    let total_source: u64 = src_sizes.iter().sum();

    // --- the free-space probe (the preflight mechanism reused — the
    // nearest-existing-ancestor `df` probe; the fit-check target) ---
    let probe = crate::preflight::probe_target(&o.dest);
    let free = match crate::jxl::free_bytes(&probe) {
        Ok(f) => Some(f),
        Err(err) => {
            eprintln!(
                "DRY RUN REFUSED — space: the free-space probe failed (df: {err:#}) — the fit-check is unmeasurable (named; never a silent pass)"
            );
            return (Verdict::Space, 2);
        }
    };
    let free = free.unwrap();

    //: the exFAT destination note (honest here too: the dry run
    // writes nothing, but the tree WILL be shadowed when the user runs
    // the real encode — the fit-check's volume is the note's volume).
    // Emitted before any sample work (the preflight-equivalent gate
    // position); advisory — a probe `None` = no note, never a refusal.
    if let Some(fstype) = crate::preflight::volume_fstype(&probe) {
        if crate::preflight::is_xattr_less_volume(&fstype) {
            println!("{}", crate::preflight::apple_double_note(&fstype, &o.dest));
        }
    }

    // --- the sample-size note (the worst-case RAM — the line) ---
    // The per-frame residency: the source buffer + the unpacked plane
    // (≈ the source order of magnitude) + the encoded bytes (≤ the
    // source) ≈ 3× the source frame (the named coefficient).
    let max_sample_src = selected.iter().map(|i| src_sizes[*i as usize]).max().unwrap_or(0);
    let ram_b = (max_sample_src as u128 * 3).saturating_mul(k64 as u128) as u64;
    println!(
        "sample: worst-case RAM ≈ {} MB ({k} × ~3× the source frame: the source buffer + the unpacked plane + the encoded bytes, in RAM) — free {:.1} GB on {}",
        ram_b / 1_048_576,
        free as f64 / 1_073_741_824.0,
        o.dest.display(),
    );
    println!(
        "sample: encoded SEQUENTIALLY in RAM (deterministic per-frame order + the running-ETA observation; the per-frame wall is jobs-independent — the frame encode is single-threaded; --jobs {} is ignored for the sample loop, named)",
        o.jobs
    );
    if o.verify_flag {
        println!("sample: --verify is subsumed — the dry-run sample ALWAYS verifies (the decode + the bit-exact compare, the honesty anchor)");
    }

    // --- the camera profiles (the upstream profile-resolution
    // refusals stay HARD BEFORE the gate — the named rc=2, the
    // process_dir resolution mirrored) ---
    let profiles = match crate::camera::resolve_profiles() {
        Ok(p) => Some(p),
        Err(err) => {
            eprintln!(
                "error: resolve the camera profile set (the pins-pattern resolution: the FRAMEPRISM_PROFILES file -> <cwd>/profiles -> <exe-dir>/profiles): {err}"
            );
            return (Verdict::Gate, 2);
        }
    };

    // --- the ingest gate on the SAMPLE (the waiver, reused):
    // the four within-clip continuity classes waived (the sparse
    // sample is legal by construction); EVERY kept class still refuses
    // (FRAME_BADNAME, TC_MISSING, TC_MALFORMED, COUNT_MISMATCH,
    // MANIFEST_BAD, REEL_OVERLAP — the existing named lines + the
    // dry-run wrapper line, rc=2). ---
    let sample_frames: Vec<PathBuf> = selected
        .iter()
        .map(|i| frames[*i as usize].clone())
        .collect();
    let gate = crate::worker::ingest_gate_subset(input, &sample_frames);
    let gate_failures = gate.failures();
    if !gate_failures.is_empty() {
        for line in &gate_failures {
            eprintln!("{line}");
        }
        if !gate.reel.failures.is_empty() {
            eprintln!(
                "REEL GATE FAIL — {} cross-clip TC overlap(s) (double capture — the ingest cannot be trusted; the camera disk stays locked)",
                gate.reel.failures.len()
            );
        }
        eprintln!(
            "DRY RUN REFUSED — gate: {} named FAIL line(s) (the existing named lines above; 0 sampled, nothing written — the archive action is NOT sanctioned)",
            gate_failures.len()
        );
        return (Verdict::Gate, 2);
    }

    // --- the sample encode (in RAM, verify always on — the live
    // metrics drive the same surface over the sequential loop) ---
    let ascending: Vec<u64> = {
        let mut a = selected.clone();
        a.sort_unstable();
        a
    };
    crate::live::begin(k);
    let mut measured: Vec<Measured> = Vec::with_capacity(k);
    let mut measured_idx: Vec<u64> = Vec::with_capacity(k);
    let mut refusal: Option<Verdict> = None;
    for &idx in &ascending {
        let path = &frames[idx as usize];
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let res = crate::worker::encode_frame_memory(
            path,
            true, // the verify pass ALWAYS (the honesty anchor)
            o.mode,
            o.downscale,
            o.fast,
            o.lossy_format,
            &o.reference,
            None, // the dry run is a fresh measurement — no sourcecheck/qc registry
            profiles.as_ref(),
        );
        match res {
            Ok(mf) => {
                crate::live::note_done(&mf.file, mf.in_bytes, mf.out_bytes, mf.ratio, mf.ms);
                measured.push(Measured {
                    name,
                    src_b: mf.in_bytes,
                    enc_b: mf.out_bytes,
                    ratio: mf.ratio,
                    ms: mf.ms,
                    verify_ms: mf.verify_ms,
                });
                measured_idx.push(idx);
            }
            Err(err) => {
                crate::live::note_skipped();
                let msg = format!("{err:#}");
                let v = if is_verify_failure(&msg) {
                    eprintln!("FAIL {name}: {msg}");
                    Verdict::Verify(name)
                } else {
                    eprintln!("FAIL {name}: {msg}");
                    Verdict::Encode { name, err: msg }
                };
                refusal = Some(v);
                break;
            }
        }
    }
    crate::live::finish();

    // --- the estimate (printed on EVERY path — the refusal
    // still prints the estimate; on a partial sample the band is over
    // the measured frames, named) ---
    let m = measured.len();
    let full = m == k;
    let ratios: Vec<f64> = measured.iter().map(|x| x.ratio).collect();
    let bd = if m > 0 { Some(band(&ratios)) } else { None };

    if let (Some(b), Some(free_b)) = (&bd, Some(free)) {
        let (w_total, l_total, b_total) = (
            project_total_ratio(total_source, b.p10),
            project_total_ratio(total_source, b.p50),
            project_total_ratio(total_source, b.p90_rank),
        );
        let sum_sampled_enc: u64 = measured.iter().map(|x| x.enc_b).sum();
        // The per-frame-then-sum form covers ALL n frames: the measured
        // frames at their measured encoded bytes, and every UNMEASURED
        // frame (selected but not reached — a PARTIAL sample refusal —
        // and the non-selected) at `src_bytes / ratio_q`. Tracking the
        // measured INDEXES (not just the selected set) keeps this form
        // on the same n-frame population as the `total_source/ratio_q`
        // fallback.
        let measured_set: std::collections::BTreeSet<u64> =
            measured_idx.iter().copied().collect();
        let unsampled_src: Vec<u64> = (0..n64)
            .filter(|i| !measured_set.contains(i))
            .map(|i| src_sizes[i as usize])
            .collect();
        let (w_sum, l_sum, b_sum) = (
            project_per_frame(sum_sampled_enc, &unsampled_src, b.p10),
            project_per_frame(sum_sampled_enc, &unsampled_src, b.p50),
            project_per_frame(sum_sampled_enc, &unsampled_src, b.p90_rank),
        );
        // The worst case = the LARGER of the two forms' p10 bounds
        // (the conservative reservation — no silent under-reservation).
        let worst = w_total.max(w_sum);
        println!(
            "estimate: ratio band {:.2} / {:.2} / {:.2} / {:.2} (min / median / p90 / max — measured {m} of {n}{partial})",
            b.min, b.median, b.p90, b.max,
            m = m,
            partial = if full { String::new() } else { " — PARTIAL sample (the refusal above)".to_string() },
        );
        println!(
            "estimate: archive (j92) — worst (p10 ratio) {worst} B / likely (p50) {} B / best (p90 ratio) {} B (per-frame-then-sum: {w_sum} / {l_sum} / {b_sum} B; the total_source/ratio_q fallback: {w_total} / {l_total} / {b_total} B)",
            l_total.max(l_sum),
            b_total.min(b_sum),
        );
        println!(
            "estimate: offload (raw copy) — {total_source} B (the exact total source bytes — the offload is a copy, the trivial-but-named line)"
        );
        let fits = worst <= free_b;
        println!(
            "estimate: {} fit — {}: free {free_b} B vs worst case {worst} B (the measured p10-ratio bound — no fixed corpus rate)",
            o.dest.display(),
            if fits { "FITS" } else { "DOES NOT FIT" },
        );
        let (e50, e95) = eta_ms(
            &measured.iter().map(|x| x.ms).collect::<Vec<_>>(),
            n64,
        );
        println!(
            "estimate: ETA encode+verify: {} (p50) / {} (p95) — not a guarantee (the card read rate dominates; the sample was read from the same source class)",
            crate::live::fmt_mss(e50),
            crate::live::fmt_mss(e95),
        );
        if o.report.is_some() {
            let _ = write_report(
                input,
                o,
                n,
                k,
                rule,
                &sha,
                &ascending,
                &frames,
                total_source,
                &measured,
                bd,
                (w_total, l_total, b_total),
                (w_sum, l_sum, b_sum),
                worst,
                free_b,
                fits,
                (e50, e95),
                full,
                &refusal,
            );
        }
        println!("dry run: no ledger row (no archive action, no reservation commit)");
        if let Some(v) = refusal {
            match &v {
                Verdict::Verify(name) => println!(
                    "DRY RUN REFUSED — verify: frame {name} not bit-exact"
                ),
                Verdict::Encode { name, err } => println!(
                    "DRY RUN REFUSED — encode: frame {name}: {err}"
                ),
                _ => unreachable!("the refusal here is the sample-class only"),
            }
            let rc = v.exit_code();
            return (v, rc);
        }
        if !fits {
            println!(
                "DRY RUN REFUSED — space: projected worst case {worst} B does not fit {} ({} B available)",
                o.dest.display(),
                free_b
            );
            return (Verdict::Space, 2);
        }
        println!(
            "DRY RUN PASS — {m} of {n} sampled, verify {m}/{m} bit-exact, archive range {}–{} B (p50 {} B), fits {}",
            b_total.min(b_sum),
            worst,
            l_total.max(l_sum),
            o.dest.display(),
        );
        return (Verdict::Pass, 0);
    }

    // The sample produced nothing (a failure at frame 0): the named
    // refusal, the estimate is the partial (empty) named line.
    let _ = (free, m);
    if o.report.is_some() {
        let _ = write_report(
            input,
            o,
            n,
            k,
            rule,
            &sha,
            &ascending,
            &frames,
            total_source,
            &measured,
            None,
            (0, 0, 0),
            (0, 0, 0),
            0,
            free,
            false,
            (None, None),
            full,
            &refusal,
        );
    }
    println!("dry run: no ledger row (no archive action, no reservation commit)");
    match refusal {
        Some(v) => {
            match &v {
                Verdict::Verify(name) => {
                    println!("DRY RUN REFUSED — verify: frame {name} not bit-exact")
                }
                Verdict::Encode { name, err } => {
                    println!("DRY RUN REFUSED — encode: frame {name}: {err}")
                }
                _ => unreachable!(),
            }
            let rc = v.exit_code();
            (v, rc)
        }
        None => unreachable!("a refusal exists when the sample produced nothing"),
    }
}

/// The `--report` markdown (the dry run's record — the
/// deterministic/non-deterministic split, the harness pattern).
fn write_report(
    input: &Path,
    o: &Opts,
    n: usize,
    k: usize,
    rule: &str,
    sha: &str,
    ascending: &[u64],
    frames: &[PathBuf],
    total_source: u64,
    measured: &[Measured],
    bd: Option<crate::dryrun::Band>,
    total_form: (u64, u64, u64),
    sum_form: (u64, u64, u64),
    worst: u64,
    free_b: u64,
    fits: bool,
    eta: (Option<f64>, Option<f64>),
    full: bool,
    refusal: &Option<Verdict>,
) -> std::io::Result<()> {
    let path = o.report.clone().unwrap();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut md = String::new();
    md.push_str("# dry-run estimate (the predict-then-measure arc)\n\n");
    md.push_str(&format!("input: {}\n", input.display()));
    md.push_str(&format!("dest (the fit-check target — never created by the dry run): {}\n\n", o.dest.display()));
    //: the pinned exFAT destination note (byte-stable — the
    // volume's fstypename is deterministic, no wall clock; ABSENT on
    // APFS — the report stays byte-identical to the pre-note shape).
    if let Some(fstype) = crate::preflight::volume_fstype(&crate::preflight::probe_target(&o.dest)) {
        if crate::preflight::is_xattr_less_volume(&fstype) {
            md.push_str(&format!(
                "{}\n\n",
                crate::preflight::apple_double_note(&fstype, &o.dest)
            ));
        }
    }
    md.push_str("## dry-run estimate\n\n");
    md.push_str(&format!(
        "sample line: dry-run: sample {k} of {n} ({rule}), seed 0x{SEED:x}\n"
    ));
    md.push_str(&format!("selection_sha256: {sha}\n\n"));
    md.push_str("selection (the LCG seed above; index → filename, the path-sorted frame order):\n\n");
    md.push_str("| index | filename |\n|---|---|\n");
    for &idx in ascending {
        let name = frames[idx as usize]
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        md.push_str(&format!("| {idx} | {name} |\n"));
    }
    md.push_str("\nper-frame (the sample — source B, encoded B, ratio 2dp; NO per-frame ms here — that's the non-pinned section):\n\n");
    md.push_str("| filename | source B | encoded B | ratio |\n|---|---|---|---|\n");
    for x in measured {
        md.push_str(&format!(
            "| {} | {} | {} | {:.2} |\n",
            x.name, x.src_b, x.enc_b, x.ratio
        ));
    }
    match &bd {
        Some(b) => {
            md.push_str(&format!(
                "\nratio band (nearest-rank, 2dp): min {min:.2} / median {median:.2} / p90 {p90:.2} / max {max:.2} (measured {m} of {n}{partial})\n\n",
                min = b.min,
                median = b.median,
                p90 = b.p90,
                max = b.max,
                m = measured.len(),
                partial = if full { "" } else { " — PARTIAL sample (the refusal above)" },
            ));
            md.push_str(&format!(
                "projected archive (j92): worst (p10 ratio) {w_total} B / likely (p50) {l_total} B / best (p90 ratio) {b_total} B\n",
                w_total = total_form.0,
                l_total = total_form.1,
                b_total = total_form.2,
            ));
            md.push_str(&format!(
                "  (sum form — the per-frame ratio applied to the per-frame source bytes, summed: the SAMPLED frames at their MEASURED encoded bytes + the unsampled at src_i/ratio_q: worst {w} B / likely {l} B / best {b} B; the total_source / ratio_q fallback: {ft:.0} B / {fl:.0} B / {fb:.0} B)\n\n",
                w = sum_form.0,
                l = sum_form.1,
                b = sum_form.2,
                ft = total_form.0 as f64,
                fl = total_form.1 as f64,
                fb = total_form.2 as f64,
            ));
            md.push_str(&format!(
                "projected raw offload: {total_source} B (the exact total source bytes — the offload is a copy, the trivial-but-named line)\n\n"
            ));
            md.push_str(&format!(
                "space verdict: worst case {worst} B (the p10-ratio bound = the LARGEST size = the worst case; the line names the measured number the fit-check uses — no fixed corpus rate. The LIVE free-space measurement + the FITS/DOES NOT FIT verdict ride the non-pinned section — the volume state is the environment, not the source, so it is excluded from the byte-identical region)\n\n"
            ));
        }
        None => {
            md.push_str("\nratio band: n/a (the sample produced no measured frames — the refusal below)\n\n");
        }
    }
    // The marker line (present iff --dry-run — always here;
    // the per-clip report's placement clause — the dry run writes no
    // per-clip report (it creates nothing under <dest>), so the
    // estimate record is its home).
    md.push_str(&format!("{}\n\n", marker_line(k, n)));

    md.push_str("## non-pinned (wall-dependent)\n\n");
    if bd.is_some() {
        md.push_str(&format!(
            "space fit-check: {} — free {free_b} B vs worst case {worst} B: {}\n\n",
            o.dest.display(),
            if fits { "FITS" } else { "DOES NOT FIT" },
        ));
    }
    md.push_str(&format!(
        "sample verify {}/{} bit-exact{}\n",
        measured.len(),
        k,
        if full && measured.len() == k { "" } else { " — REFUSED (the refusal below; the archive action is NOT sanctioned)" },
    ));
    md.push_str("per-frame (encode+verify wall ms + the verify-pass ms — the encode wall is ms − verify ms):\n\n");
    md.push_str("| filename | ms | verify ms |\n|---|---|---|\n");
    for x in measured {
        md.push_str(&format!("| {} | {:.0} | {:.0} |\n", x.name, x.ms, x.verify_ms));
    }
    md.push_str(&format!(
        "\nETA encode+verify: {} (p50) / {} (p95) — not a guarantee (the card read rate dominates; the sample was read from the same source class)\n",
        crate::live::fmt_mss(eta.0),
        crate::live::fmt_mss(eta.1),
    ));
    let version = env!("CARGO_PKG_VERSION");
    let exe_sha = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::read(&p).ok())
        .map(|b| crate::jxl::sha256_hex(&b))
        .unwrap_or_else(|| "n/a".into());
    let ncpu = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    md.push_str(&format!(
        "binary: frameprism {version} sha256 {exe_sha}\nmachine: {}/{}, {ncpu} cores\n",
        std::env::consts::OS,
        std::env::consts::ARCH,
    ));

    md.push_str("\n## live — the sample-encode metrics (the process-level window; the card read rate is the headline number)\n\n");
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
                "- total written: {} B — mean {} MB/s (the dry run writes NOTHING under <dest> — the write counter here is the report file + the OS noise; the encode's bytes are the in-RAM measurement)\n",
                t.write_total.map_or_else(|| "n/a".into(), |b| b.to_string()),
                t.write_mean_mbs.map_or_else(|| "n/a".into(), |x| format!("{x:.2}")),
            ));
            md.push_str(&format!(
                "- cpu% (multi-core): {} mean (the % can exceed 100 — that is the load)\n",
                t.cpu_mean_pct.map_or_else(|| "n/a".into(), |x| format!("{x:.1}")),
            ));
        }
        None => md.push_str("- (no live totals — the FFI is unavailable on this platform: the named n/a, never a silent 0)\n"),
    }

    md.push_str("\ndry run: no ledger row (no archive action, no reservation commit)\n");
    if let Some(v) = refusal {
        md.push_str("\nverdict: ");
        match v {
            Verdict::Pass => md.push_str("DRY RUN PASS"),
            Verdict::Space => {
                md.push_str(&format!(
                    "DRY RUN REFUSED — space: projected worst case {worst} B does not fit {} ({} B available)",
                    o.dest.display(),
                    free_b
                ))
            }
            Verdict::KRange => md.push_str("DRY RUN REFUSED — k-range (the usage class — before the gate)"),
            Verdict::Gate => md.push_str("DRY RUN REFUSED — gate (the kept-class FAIL lines above)"),
            Verdict::Verify(name) => {
                md.push_str(&format!("DRY RUN REFUSED — verify: frame {name} not bit-exact"))
            }
            Verdict::Encode { name, err } => {
                md.push_str(&format!("DRY RUN REFUSED — encode: frame {name}: {err}"))
            }
        }
        md.push('\n');
    }
    std::fs::write(&path, md)?;
    Ok(())
}

// =====================================================================
// Tests (the G6 additive suite — the pinned vectors + the named
// fixtures).
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The clamp rule (the G6 vectors: N=10→10, N=100→20, N=300→30,
    /// N=1000→60; + the G1 clip: N=72→20).
    #[test]
    fn clamp_rule_vectors() {
        assert_eq!(clamp_k(10), 10);
        assert_eq!(clamp_k(100), 20);
        assert_eq!(clamp_k(72), 20);
        assert_eq!(clamp_k(300), 30);
        assert_eq!(clamp_k(1000), 60);
        // The boundaries: N=1 → 1; N=20 → 20; N=600 → 60; N=10_000 → 60.
        assert_eq!(clamp_k(1), 1);
        assert_eq!(clamp_k(20), 20);
        assert_eq!(clamp_k(600), 60);
        assert_eq!(clamp_k(10_000), 60);
    }

    /// The G6 sample-failure classification: the `verify: ` prefix
    /// (stamped by `worker::vctx` on every VERIFY-GATE failure inside
    /// `encode_core`) → the verify class; anything else → the encode
    /// class.
    #[test]
    fn g6_failure_classification() {
        assert!(is_verify_failure("verify: not bit-exact"));
        assert!(is_verify_failure("verify: G2 decode: bad JFIF"));
        assert!(!is_verify_failure("parse: not a TIFF container"));
        assert!(!is_verify_failure("read: I/O error"));
        assert!(!is_verify_failure(""));
        assert!(!is_verify_failure("verify:")); // the prefix is `verify: ` (with the space)
    }

    /// The end-to-end prefix contract: `worker::vctx` produces exactly
    /// the string `is_verify_failure` keys on, so any verify-gate
    /// failure routed through `encode_core` is classified as the
    /// verify class.
    #[test]
    fn g6_vctx_prefix_contract() {
        let e = crate::worker::vctx("not bit-exact");
        let msg = format!("{e:#}");
        assert_eq!(msg, "verify: not bit-exact");
        assert!(is_verify_failure(&msg));
    }

    /// The LCG draw vectors (the python3/bash-cross-validated
    /// raw draw stream,
    /// case 1: seed 0x20260916, N=72 — the `z mod N` per LCG step,
    /// 3200 raw draws IDENTICAL between the python3 reference and the
    /// bash harness): the first 10 draws.
    #[test]
    fn lcg_draw_vectors_default_seed() {
        let mut s = 0x2026_0916u64;
        let draws: Vec<u64> = (0..10).map(|_| lcg_next(&mut s) % 72).collect();
        assert_eq!(
            draws,
            vec![4, 30, 62, 57, 11, 34, 61, 56, 13, 9],
            "the SplitMix64 draw stream (z mod N) must match the python3/bash reference (cross-validated)"
        );
        // + a second-seed vector (the xval case 2: seed 0xdeadbeef… the
        // case-4 stream, seed 0, N=72, first 10: 7 36 55 52 67 66 41 44 35 38).
        let mut s0 = 0u64;
        let draws0: Vec<u64> = (0..10).map(|_| lcg_next(&mut s0) % 72).collect();
        assert_eq!(draws0, vec![7, 36, 55, 52, 67, 66, 41, 44, 35, 38]);
    }

    /// The selection-sha vector (the G2 expectation — the byte-level
    /// proof): the harness's measured A001_001 K=60 default-seed
    /// selection (the measured table) + its sha.
    const M3_A001_001_IDX: [u64; 60] = [
        0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13,
        14, 15, 17, 18, 19, 20, 22, 23, 25, 27, 28, 29,
        30, 31, 33, 34, 35, 38, 39, 41, 42, 43, 44, 45,
        46, 47, 48, 49, 50, 51, 52, 53, 54, 56, 57, 59,
        60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
    ];

    #[test]
    fn selection_sha_g2_vector() {
        assert_eq!(
            selection_sha(&M3_A001_001_IDX),
            "5623a17f9528d32da2905f96f4272ccf6223471bab77ec5cd06770242b90ec30",
            "the harness-canonical form (the ascending numeric indices + one trailing newline) must hash to the pinned reference sha"
        );
    }

    /// The RUST selection itself (the G2 unit-level half): the Rust
    /// `lcg_select(72, 60, 0x20260916)` must REPRODUCE the pinned table
    /// (the composition property: a K=60 dry-run sample IS the gate
    /// sample for the same clip + seed).
    #[test]
    fn rust_selection_matches_m3_table() {
        let sel = lcg_select(72, 60, SEED);
        let mut sorted: Vec<u64> = sel.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted.as_slice(),
            M3_A001_001_IDX.as_slice(),
            "the Rust LCG selection (N=72, K=60, the pinned seed) must be the pinned reference selection"
        );
    }

    /// The selection-sha harness canonical form (the python3
    /// cross-check of the exact byte form — the reverify's
    /// `sha256_of_str "$sel_str"$'\n'`).
    #[test]
    fn selection_sha_canonical_form() {
        // 3 draws over N=72, K=3 (the G2 clip): the selection is the
        // rejection sample; the sha is over the SORTED indices.
        let sel = lcg_select(72, 3, SEED);
        let mut sorted = sel.clone();
        sorted.sort_unstable();
        let joined: String = sorted.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        assert_eq!(selection_sha(&sel), crate::jxl::sha256_hex(format!("{joined}\n").as_bytes()));
        // + the selection is 3 distinct indices in [0, 72).
        assert_eq!(sel.len(), 3);
        assert!(sel.iter().all(|i| *i < 72));
        assert_eq!(sel.len(), sel.iter().collect::<std::collections::BTreeSet<_>>().len());
    }

    /// The stats (the harness form): the median (odd = the middle,
    /// even = the mean of the two middle) + the nearest-rank
    /// percentiles (the p90 rank = int((9n+9)/10)).
    #[test]
    fn stats_m5_form() {
        assert_eq!(median_sorted(&[1.0, 2.0, 3.0, 4.0, 5.0]), 3.0);
        assert_eq!(median_sorted(&[1.0, 2.0, 3.0, 4.0]), 2.5);
        let v: Vec<f64> = (1..=60).map(|x| x as f64).collect();
        // p90 rank = int((9*60+9)/10) = 54 → the 54th value = 54.0.
        assert_eq!(percentile_nearest_rank_sorted(&v, 0.90), Some(54.0));
        // p10 rank = ceil(6) = 6 → 6.0.
        assert_eq!(percentile_nearest_rank_sorted(&v, 0.10), Some(6.0));
        // p50 rank = ceil(30) = 30 → 30.0 (the NEAREST-RANK p50 —
        // distinct from the harness median 30.5 at even N).
        assert_eq!(percentile_nearest_rank_sorted(&v, 0.50), Some(30.0));
        let b = band(&v);
        assert_eq!(b.min, 1.0);
        assert_eq!(b.max, 60.0);
        assert_eq!(b.median, 30.5);
        assert_eq!(b.p90, 54.0);
    }

    /// The projection forms (the per-frame-then-sum primary + the
    /// total/ratio fallback).
    #[test]
    fn projection_forms() {
        // 4 frames, 2 sampled (measured 100→40 each), 2 unsampled
        // (200 src each), ratio_q = 2.5.
        assert_eq!(project_per_frame(80, &[200, 200], 2.5), 80 + 160);
        assert_eq!(project_total_ratio(800, 2.5), 320);
        // Rounding: the sum is rounded once.
        assert_eq!(project_per_frame(0, &[1, 1], 3.0), 1); // 2/3 → 0.67 → 1
    }

    /// The ETA (the nearest-rank p50/p95 × N).
    #[test]
    fn eta_form() {
        // 4 frames of 100/200/300/400 ms, N=10: p50 rank = 2 → 200;
        // p95 rank = ceil(3.8) = 4 → 400.
        let (e50, e95) = eta_ms(&[300.0, 100.0, 400.0, 200.0], 10);
        assert_eq!(e50, Some(200.0 * 10.0));
        assert_eq!(e95, Some(400.0 * 10.0));
    }

    /// The marker line (the G6 verbatim pin — the byte-stable constant
    /// for a known (K, N)).
    #[test]
    fn marker_line_verbatim() {
        assert_eq!(
            marker_line(60, 3047),
            "dry-run: estimate (60 of 3047 sampled, continuity waived for the sparse sample)"
        );
        assert_eq!(
            marker_line(20, 72),
            "dry-run: estimate (20 of 72 sampled, continuity waived for the sparse sample)"
        );
    }

    /// The process-state flag (the OnceLock convention — the set/get
    /// pair; absent = false).
    #[test]
    fn dryrun_flag_process_state() {
        // NOTE: this test process may have the flag set by another
        // test's ordering — assert the GET-able contract (the
        // pre-set value is whatever the process state is; the SET is
        // the once-only contract, verified by the second set being a
        // no-op).
        let _ = dryrun_flag();
        set_dryrun_flag(true);
        assert!(dryrun_flag());
    }
}
