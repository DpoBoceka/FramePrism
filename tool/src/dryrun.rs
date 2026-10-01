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
// The per-population encoded projection (the R0 ruling —
// R3, the both-estimates machinery): the same two projection forms
// (the total_source/ratio_q fallback + the per-frame-then-sum) at the
// band's quantiles, over a CHOSEN population — the raw frames only
// (the `--carry` scenario: the fp frames ride the carried line) or
// the FULL population (the transcoded ruling: the fp frames at the
// measured band). The measured frames inside the population ride at
// their measured encoded bytes; the unmeasured ones at src_i/ratio_q.
// Raw-only input: the two populations coincide — the pre-contract
// number.
// =====================================================================
fn pop_encoded(
    measured: &[Measured],
    measured_idx: &[u64],
    class_scans: &[(crate::frameclass::FrameClass, crate::frameclass::FrameStructure)],
    src_sizes: &[u64],
    n64: u64,
    pop_all: bool,
    pop_src: u64,
    p10: f64,
    p50: f64,
    p90: f64,
) -> (u64, u64, u64, u64, u64, u64) {
    let measured_set: std::collections::BTreeSet<u64> =
        measured_idx.iter().copied().collect();
    let in_pop = |i: usize| {
        pop_all
            || class_scans[i].0 == crate::frameclass::FrameClass::RawUncompressed
    };
    let sum_sampled_enc: u64 = measured
        .iter()
        .zip(measured_idx.iter())
        .filter(|(_, &i)| in_pop(i as usize))
        .map(|(x, _)| x.enc_b)
        .sum();
    let unsampled_src: Vec<u64> = (0..n64)
        .filter(|i| !measured_set.contains(i) && in_pop(*i as usize))
        .map(|i| src_sizes[i as usize])
        .collect();
    (
        project_total_ratio(pop_src, p10),
        project_total_ratio(pop_src, p50),
        project_total_ratio(pop_src, p90),
        project_per_frame(sum_sampled_enc, &unsampled_src, p10),
        project_per_frame(sum_sampled_enc, &unsampled_src, p50),
        project_per_frame(sum_sampled_enc, &unsampled_src, p90),
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
    /// The CLI `--carry` opt-in (the R0 ruling — the
    /// fp-camera frames' byte-exact source copy instead of the
    /// transcode default): the sample dispatch + the both-estimates
    /// logic both key on it (the dry run's explicit seam — the
    /// encode run's process-wide flag is the encode path's).
    pub carry: bool,
    /// The CLI `--verify` flag (subsumed — the sample ALWAYS verifies;
    /// the named note is printed when present).
    pub verify_flag: bool,
}

/// The mixed clip's BOTH estimates (the R0 ruling — R3):
/// the two archive plans the user can run — `--carry` (the explicit
/// opt-in: the raw frames encoded + the fp frames the byte-exact
/// source copy) and the transcode (the default: every frame at the
/// measured band — the fp frames re-encoded through the archive path).
/// Each carries its size projection (the worst/likely/best of the two
/// projection forms) + the ETA (encode+verify, the per-frame wall's
/// p50/p95 × its population's frame count — the carried scenario's
/// ETA covers the encoded population only; the byte copy is an
/// unmeasured path, honestly named). The fit-check target = the WORST
/// of the two plans (both are named; the user's plan choice is never
/// an under-reservation). Raw-only input: the two populations
/// coincide (carried bytes = 0) — the pre-contract number.
#[derive(Debug, Clone)]
pub struct BothEstimates {
    /// The carried scenario (`--carry`): the raw frames' encoded
    /// worst/likely/best + the exact carried bytes (the byte copy).
    pub carried_encoded_worst: u64,
    pub carried_encoded_likely: u64,
    pub carried_encoded_best: u64,
    pub carried_bytes: u64,
    pub carried_n: u64,
    pub carried_eta: (Option<f64>, Option<f64>),
    /// The transcoded scenario (the default): the FULL population's
    /// encoded worst/likely/best (the fp frames at the measured band).
    pub transcoded_worst: u64,
    pub transcoded_likely: u64,
    pub transcoded_best: u64,
    pub transcoded_eta: (Option<f64>, Option<f64>),
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

    //: the frame-class census (the mixed-compression contract — the
    // pre-sample-line census, R3): the IFD-only scan rides preflight
    // (the 512 KiB window read + the named full-file fallback — the
    // fp frames' tail IFD; the malformed/IO class degrades to
    // Unknown, which the contract check below names). The census's
    // fp-camera bytes ARE the carried estimate's exact bytes (the
    // byte copy — no re-encode; the sample's fp frames are treated
    // as carry, no encode). The CLIP-CLASS CONTRACT check runs
    // BEFORE the sample line (the 0-frames-touched pre-job refusal —
    // the established mechanism): any clip whose class set is not one
    // of the allowed sets ({raw-uncompressed} · the mixed
    // {raw-uncompressed, fp-camera-lossless} set) refuses the dry run
    // (rc=2 — the pinned clip-contract wording, then the dry-run
    // wrapper; nothing sampled, nothing written).
    let src_sizes: Vec<u64> = frames
        .iter()
        .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .collect();
    let total_source: u64 = src_sizes.iter().sum();
    let class_scans = crate::preflight::scan_frame_classes(&frames);
    let carried_n: u64 = class_scans
        .iter()
        .filter(|(c, _)| *c == crate::frameclass::FrameClass::FpCameraLossless)
        .count() as u64;
    let mut by_clip: std::collections::BTreeMap<String, Vec<usize>> =
        std::collections::BTreeMap::new();
    for (i, p) in frames.iter().enumerate() {
        by_clip
            .entry(crate::worker::report::clip_key_of(input, p))
            .or_default()
            .push(i);
    }
    let mut clip_census: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<crate::frameclass::FrameClass, u64>,
    > = std::collections::BTreeMap::new();
    let mut clip_carried: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    for (clip, idxs) in &by_clip {
        for &i in idxs {
            let (cls, _structure) = class_scans[i];
            *clip_census
                .entry(clip.clone())
                .or_default()
                .entry(cls)
                .or_default() += 1;
            if cls == crate::frameclass::FrameClass::FpCameraLossless {
                *clip_carried.entry(clip.clone()).or_default() += src_sizes[i];
            }
        }
    }
    let carried_bytes: u64 = clip_carried.values().sum();
    // The encoded estimate's population (the raw frames — the
    // contract check below guarantees the class set ⊆ {raw, fp}, so
    // the split is exact).
    let total_source_raw = total_source - carried_bytes;
    let mut census_lines: Vec<String> = Vec::new();
    for (clip, idxs) in &by_clip {
        let census = &clip_census[clip];
        // The contract's DOMAIN (the PM ruling — the amended R1/R2):
        // the set = the classes of the frames WITH a readable
        // compression structure; a parse-failed frame (e.g. the
        // strict parse's `MissingTag(259)`) does not enter the set —
        // it stays on the existing per-frame named refusal at the
        // encode site (the corrupt-frame semantics — byte-invariant,
        // zero new wordings); an empty set is outside the contract's
        // domain — the existing behavior stands.
        let domain: Vec<usize> = idxs
            .iter()
            .copied()
            .filter(|&i| crate::frameclass::in_contract_domain(&class_scans[i].1))
            .collect();
        let set: std::collections::BTreeSet<crate::frameclass::FrameClass> =
            domain.iter().map(|&i| class_scans[i].0).collect();
        if !set.is_empty() && !crate::frameclass::allowed_clip_class_set(&set) {
            let name_of = |i: usize| {
                frames[i]
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default()
            };
            // The first offender = the first frame (the path-sorted
            // frame order) of the clip whose class is outside the
            // allowed pair; the shape-only refusal (the lone
            // fp-camera set — the spec's two-set contract) names the
            // clip's first frame.
            let offender = domain
                .iter()
                .find(|&&i| !matches!(
                    class_scans[i].0,
                    crate::frameclass::FrameClass::RawUncompressed
                        | crate::frameclass::FrameClass::FpCameraLossless
                ))
                .copied()
                .map(name_of)
                .or_else(|| idxs.first().copied().map(name_of))
                .unwrap_or_default();
            let line = crate::frameclass::clip_class_contract_line(&set, &offender);
            eprintln!("{line}");
            eprintln!(
                "DRY RUN REFUSED — clip class: the clip-class contract refusal above (the pre-job refusal: 0 sampled, nothing written — the archive action is NOT sanctioned)"
            );
            return (Verdict::Gate, 2);
        }
        let parts: Vec<String> = census
            .iter()
            .map(|(c, cnt)| format!("{} {cnt}", c.name()))
            .collect();
        let bytes = clip_carried.get(clip).copied().unwrap_or(0);
        census_lines.push(format!(
            "class census: {} — {} (carried bytes {bytes})",
            crate::worker::report::display_clip(clip),
            parts.join(" · ")
        ));
    }
    for line in &census_lines {
        println!("{line}");
    }

    // --- the sample line + the selection (the pinned section) ---
    println!(
        "dry-run: sample {k} of {n} ({rule}), seed 0x{SEED:x}"
    );
    let selected = crate::dryrun::lcg_select(n64, k64, SEED);
    let sha = selection_sha(&selected);
    println!("selection_sha256: {sha}");
    println!("{}", marker_line(k, n));

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
    // The temporal-oracle resolver's clip list (the encode
    // run's process_dir mirror): the frames as (path relative to the
    // input root, the pre-scan class, the ordinal from the frame
    // field) — the resolver's candidate domain (the class is the
    // pre-scan's — the dry-run's own pre-pass; zero extra I/O).
    let oracle_clip: Vec<(
        std::path::PathBuf,
        crate::frameclass::FrameClass,
        Option<u64>,
    )> = frames
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let rel = p
                .strip_prefix(input)
                .map(|q| q.to_path_buf())
                .unwrap_or_else(|_| p.clone());
            let ord = p
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(crate::worker::checksums::frame_number_from_stem);
            (rel, class_scans[i].0, ord)
        })
        .collect();
    // The per-clip temporal-verified count (R4, the census
    // term's source — the clip key = the report's clip key; the
    // sample-derived data the post-sample census-line amendment
    // carries into the record).
    let mut clip_temporal: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut measured: Vec<Measured> = Vec::with_capacity(k);
    let mut measured_idx: Vec<u64> = Vec::with_capacity(k);
    let mut refusal: Option<Verdict> = None;
    for &idx in &ascending {
        let path = &frames[idx as usize];
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let (cls, structure) = class_scans[idx as usize];
        //: the policy table's sample dispatch (the mixed-compression
        // contract — the dry-run mirror of the encode-side table, ONE
        // function, the R0 ruling row): the raw class = the
        // existing measured sample encode (unchanged); the fp-camera
        // class on the lossless row = the RULING cell — Transcode by
        // default (the sample encode through the transcode seam — the
        // decode + the re-encode through the archive path, verify
        // always on: the archive drill + the fidelity check ride in
        // the measurement) or Carry under the explicit `--carry`
        // opt-in (no encode — the census's exact bytes are the
        // carried estimate); the other rows = the table's named
        // refusal (the chooser's pinned wording — the contract check
        // above passes for the {raw, fp-camera} sets, so the live
        // case is the fp frame × the non-lossless mode row: the
        // established sample-failure mechanism — the estimate still
        // prints, the named refusal, rc=1). The chooser's None = the
        // parse-failure class (no readable compression — the strict
        // parse's own named line, the `MissingTag(259)` — byte-
        // invariant, the ruling's domain clause): it routes through
        // the existing sample encode, which fires it.
        match crate::worker::encode::policy(cls, o.mode, o.downscale, o.carry) {
            crate::worker::encode::FramePolicy::Encode
            | crate::worker::encode::FramePolicy::Transcode => {
                // The encode treatment: the raw class (unchanged) or
                // the fp-camera class's transcode (the ruling default
                // — the measurement IS the transcode: the decode +
                // the re-encode through the existing archive path).
            }
            crate::worker::encode::FramePolicy::Carry => {
                // The carry treatment: no pixel access, no encode —
                // the source bytes ARE the output (the encode run's
                // tmp+rename write copies them; the carried frame's
                // verify = the source-sha match, never a decode — the
                // fp-camera lossless decode's scope).
                crate::live::note_done(&name, src_sizes[idx as usize], src_sizes[idx as usize], 1.0, 0.0);
                continue;
            }
            crate::worker::encode::FramePolicy::RefuseNamed => {
                if let Some(line) = crate::worker::encode::refusal_line(
                    cls, &structure, &name, o.mode, o.downscale,
                ) {
                    crate::live::note_skipped();
                    eprintln!("FAIL {name}: {line}");
                    refusal = Some(Verdict::Encode { name, err: line });
                    break;
                }
                // The parse-failure class: the encode path's own
                // named line (the strict parse) fires below.
            }
        }
        // The temporal-oracle ctx (the encode run's
        // process_dir mirror): the fp sample frame's transcode
        // measurement runs under the resolver (the disputed
        // whole-body tile is accepted only via the verified same-
        // class neighbor within the pinned bound); every other
        // sample frame runs with no ctx (the strict drill stands —
        // the byte-frozen path). The set/clear wraps the encode
        // call ONLY (the Carry arm `continue`d before it, the
        // RefuseNamed arm breaks around it) — the error path
        // included: the clear runs BEFORE the `match res` (the Err
        // arm breaks the loop — the ctx never leaks into the next
        // frame or the post-sample estimate).
        let fp_sample =
            cls == crate::frameclass::FrameClass::FpCameraLossless;
        if fp_sample {
            crate::decode::set_fp_temporal_oracle(Some(
                crate::worker::encode::fp_temporal_resolver(input, &oracle_clip, &name),
            ));
        } else {
            crate::decode::set_fp_temporal_oracle(None);
        }
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
            o.carry,
        );
        if fp_sample {
            // The frame's verified count BEFORE the clear (the same
            // thread — the dry run's sequential sample loop), noted
            // to the clip's total (the census term's source).
            let n = crate::decode::fp_temporal_verified_count();
            crate::decode::set_fp_temporal_oracle(None);
            if n > 0 {
                *clip_temporal
                    .entry(crate::worker::report::clip_key_of(input, path))
                    .or_insert(0) += n;
            }
        } else {
            crate::decode::set_fp_temporal_oracle(None);
        }
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

    // The temporal-verified census term (the sample-derived
    // amendment of the pre-sample census line): the clip's oracle-
    // verified whole-body tile count (the disputed tiles the sample's
    // transcodes rescued) joins the census line of the clips whose
    // sampled fp frames verified a tile — ONLY when n > 0 (the raw-
    // only + the no-verified-neighbor shapes stand byte-frozen at
    // n = 0 — the 123 line, verbatim). The amendment rides the
    // RECORD (the md, written after the sample) — the stdout census
    // line stays the pre-sample shape (it prints before the sample;
    // the term is sample-derived data).
    if !clip_temporal.is_empty() {
        for (ci, (clip, _idxs)) in by_clip.iter().enumerate() {
            if let Some(&nv) = clip_temporal.get(clip) {
                if nv > 0 {
                    let line = census_lines[ci].as_str();
                    if let Some(pos) = line.find(" (carried bytes") {
                        census_lines[ci] = format!(
                            "{} · temporal-verified {nv}{}",
                            &line[..pos],
                            &line[pos..]
                        );
                    }
                }
            }
        }
    }

    // --- the estimate (printed on EVERY path — the refusal
    // still prints the estimate; on a partial sample the band is over
    // the measured frames, named) ---
    let m = measured.len();
    let full = m == k;
    let ratios: Vec<f64> = measured.iter().map(|x| x.ratio).collect();
    let bd = if m > 0 { Some(band(&ratios)) } else { None };

    if let (Some(b), Some(free_b)) = (&bd, Some(free)) {
        //: the encoded estimate's population (the R0 ruling
        // — the both-estimates contract): the CARRIED scenario
        // (`--carry` — the raw frames at the measured band; the fp
        // frames ride the carried line at the exact source bytes) +
        // the TRANSCODED scenario (the ruling default — the FULL
        // population at the measured band: the fp frames re-encoded
        // through the archive path). Raw-only input: the two
        // populations coincide (carried_bytes = 0) — the pre-
        // contract number (the raw-only lines stay byte-frozen).
        let (rw_t, rl_t, rb_t, rw_s, rl_s, rb_s) = pop_encoded(
            &measured, &measured_idx, &class_scans, &src_sizes, n64,
            false, total_source_raw, b.p10, b.p50, b.p90_rank,
        );
        let (aw_t, al_t, ab_t, aw_s, al_s, ab_s) = pop_encoded(
            &measured, &measured_idx, &class_scans, &src_sizes, n64,
            true, total_source, b.p10, b.p50, b.p90_rank,
        );
        // The per-scenario worst/likely/best (the conservative
        // reservation: the LARGER of the two projection forms' p10
        // bound for the worst, the p50's larger for the likely, the
        // p90's smaller for the best — the pre-contract form's
        // arithmetic, per population).
        let raw_worst = rw_t.max(rw_s);
        let raw_likely = rl_t.max(rl_s);
        let raw_best = rb_t.min(rb_s);
        let all_worst = aw_t.max(aw_s);
        let all_likely = al_t.max(al_s);
        let all_best = ab_t.min(ab_s);
        // The two plans' TOTAL size (the fit-check inputs): the
        // carried plan = the raw encoded worst + the exact carried
        // bytes (the byte copy); the transcoded plan = the full
        // population's encoded worst. The fit-check target = the
        // WORST of the two plans (both are named — the user's plan
        // choice is never an under-reservation). Raw-only:
        // carried_bytes = 0 + the populations coincide → the pre-
        // contract worst_combined (byte-frozen).
        let carried_plan_worst = raw_worst.saturating_add(carried_bytes);
        let transcoded_plan_worst = all_worst;
        let worst_combined = carried_plan_worst.max(transcoded_plan_worst);
        // The per-scenario ETA (the per-frame wall's p50/p95 × the
        // scenario's encoded population's frame count): the carried
        // plan encodes the RAW frames only (the byte copy is an
        // unmeasured path — honestly named); the transcoded plan
        // encodes EVERY frame (under `--carry` the fp frames ride at
        // the measured rate — the unmeasured delta is named).
        let ms_in_pop = |pop_all: bool| -> Vec<f64> {
            measured
                .iter()
                .zip(measured_idx.iter())
                .filter(|(_, &i)| {
                    pop_all
                        || class_scans[i as usize].0
                            == crate::frameclass::FrameClass::RawUncompressed
                })
                .map(|(x, _)| x.ms)
                .collect()
        };
        let (c50, c95) = eta_ms(&ms_in_pop(false), n64 - carried_n);
        let (t50, t95) = eta_ms(&ms_in_pop(true), n64);
        let both = BothEstimates {
            carried_encoded_worst: raw_worst,
            carried_encoded_likely: raw_likely,
            carried_encoded_best: raw_best,
            carried_bytes,
            carried_n,
            carried_eta: (c50, c95),
            transcoded_worst: all_worst,
            transcoded_likely: all_likely,
            transcoded_best: all_best,
            transcoded_eta: (t50, t95),
        };
        let mixed = carried_bytes > 0;
        // The PRIMARY scenario's lines (the estimate's home — the
        // ruling default under the default flags, the carried plan
        // under `--carry`): raw-only input is primary-raw either
        // way (the populations coincide) — the pre-contract lines
        // verbatim (byte-frozen).
        let primary = if mixed && !o.carry {
            (all_worst, all_likely, all_best, aw_s, al_s, ab_s, aw_t, al_t, ab_t)
        } else {
            (raw_worst, raw_likely, raw_best, rw_s, rl_s, rb_s, rw_t, rl_t, rb_t)
        };
        println!(
            "estimate: ratio band {:.2} / {:.2} / {:.2} / {:.2} (min / median / p90 / max — measured {m} of {n}{band_pop}{partial})",
            b.min, b.median, b.p90, b.max,
            m = m,
            band_pop = if !mixed || o.carry { " raw" } else { " — the raw + the transcoded fp frames" },
            partial = if full { String::new() } else { " — PARTIAL sample (the refusal above)".to_string() },
        );
        if mixed {
            if o.carry {
                println!(
                    "estimate: carried (the fp-camera lossless frames — the byte copy, no re-encode) — {carried_n} frame(s) — {carried_bytes} B (the exact source bytes; the carried frame's verify = the source-sha match — the decode-side verify is the fp-camera lossless decode's scope)"
                );
            } else {
                println!(
                    "estimate: transcoded (the fp-camera lossless frames — the ruling default: the decode + the re-encode through the archive path) — {carried_n} frame(s) — {carried_bytes} B source (the fp frames ride the measured band; the output is in the archive contract — the transcode-fidelity check: decode(output) == the decoded input plane, pixel-exact)"
                );
            }
            // The BOTH estimates (R3 — the dry run reports the
            // carried vs the transcoded plan: size + ETA, both
            // named; the fit-check = the worst of the two).
            println!(
                "estimate: both estimates (the mixed clip — carried vs transcoded: size + ETA) — carried (--carry): {raw_worst} B worst / {raw_likely} B likely / {raw_best} B best encoded + {carried_bytes} B carried (exact) = {carried_plan_worst} B worst; ETA encode+verify {} (p50) / {} (p95) (the raw frames' encode — the fp byte copy is an unmeasured path, honestly named) — transcoded (the ruling default): {transcoded_plan_worst} B worst / {all_likely} B likely / {all_best} B best; ETA encode+verify {} (p50) / {} (p95); the fit-check = the worst of the two plans (both named)",
                crate::live::fmt_mss(c50),
                crate::live::fmt_mss(c95),
                crate::live::fmt_mss(t50),
                crate::live::fmt_mss(t95),
            );
        }
        println!(
            "estimate: archive (j92) — worst (p10 ratio) {w} B / likely (p50) {l} B / best (p90 ratio) {bst} B (per-frame-then-sum: {ws} / {ls} / {bs} B; the total_source/ratio_q fallback: {wt} / {lt} / {bt} B; {pop_note})",
            w = primary.0, l = primary.1, bst = primary.2,
            ws = primary.3, ls = primary.4, bs = primary.5,
            wt = primary.6, lt = primary.7, bt = primary.8,
            pop_note = if !mixed || o.carry {
                "the raw frames' population — the carried frames ride the carried line"
            } else {
                "the full population — the fp frames at the measured band (the ruling default)"
            },
        );
        println!(
            "estimate: offload (raw copy) — {total_source} B (the exact total source bytes — the offload is a copy, the trivial-but-named line)"
        );
        let fits = worst_combined <= free_b;
        println!(
            "estimate: {} fit — {}: free {free_b} B vs worst case {worst_combined} B (the measured p10-ratio bound over the raw frames{fit_note} — no fixed corpus rate)",
            o.dest.display(),
            if fits { "FITS" } else { "DOES NOT FIT" },
            fit_note = if !mixed { "" } else if o.carry { " + the carried bytes (exact)" } else { " (the fit-check = the worse of the two plans — the carried scenario and the transcoded ruling)" },
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
                (primary.6, primary.7, primary.8),
                (primary.3, primary.4, primary.5),
                worst_combined,
                free_b,
                fits,
                (e50, e95),
                full,
                &refusal,
                carried_n,
                carried_bytes,
                &census_lines,
                // The both estimates: the MIXED input only (the raw-
                // only record stays the pre-contract shape — the plans
                // coincide, no both-estimates line; the byte-freeze).
                mixed.then_some(&both),
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
                "DRY RUN REFUSED — space: projected worst case {worst_combined} B does not fit {} ({} B available)",
                o.dest.display(),
                free_b
            );
            return (Verdict::Space, 2);
        }
        if mixed {
            if o.carry {
                println!(
                    "DRY RUN PASS — {m} of {n} sampled ({m} raw encoded + {} treated as carry — no encode of the fp frames), verify {m}/{m} bit-exact, encoded range {}–{} B (p50 {} B) + carried {carried_bytes} B (exact), fits {}",
                    k - m,
                    raw_best,
                    raw_worst,
                    raw_likely,
                    o.dest.display(),
                );
            } else {
                let raw_m = measured
                    .iter()
                    .zip(measured_idx.iter())
                    .filter(|(_, &i)| {
                        class_scans[i as usize].0
                            == crate::frameclass::FrameClass::RawUncompressed
                    })
                    .count();
                println!(
                    "DRY RUN PASS — {m} of {n} sampled ({raw_m} raw encoded + {} fp transcoded — the ruling default), verify {m}/{m} bit-exact, encoded range {}–{} B (p50 {} B), fits {}",
                    m - raw_m,
                    all_best,
                    all_worst,
                    all_likely,
                    o.dest.display(),
                );
            }
        } else {
            println!(
                "DRY RUN PASS — {m} of {n} sampled, verify {m}/{m} bit-exact, archive range {}–{} B (p50 {} B), fits {}",
                raw_best,
                raw_worst,
                raw_likely,
                o.dest.display(),
            );
        }
        return (Verdict::Pass, 0);
    }

    //: the all-carry sample (the mixed-compression contract): every
    // sampled frame treated as carry — no measured raw ratio. The
    // carried estimate is EXACT (the census's source bytes); the
    // encoded estimate = the conservative preflight bound (the j92
    // lower bound × the margin — the preflight mechanism: the
    // estimate is a lower bound, the margin buys the incident),
    // named. The fit-check = the carried bytes + the bound.
    if m == 0 && carried_bytes > 0 {
        let mult = match crate::preflight::margin() {
            Ok(m) => m,
            Err(s) => {
                eprintln!(
                    "DRY RUN REFUSED — margin: FRAMEPRISM_PREFLIGHT_MULT {s} does not parse as a float (the all-carry sample's encoded estimate is the conservative preflight bound — the margin must be measurable; named; never a default)"
                );
                return (Verdict::Gate, 2);
            }
        };
        let raw_worst = crate::preflight::estimate("j92", total_source_raw, mult);
        let worst_combined = carried_bytes.saturating_add(raw_worst);
        println!(
            "estimate: carried (the fp-camera lossless frames — the byte copy, no re-encode) — {carried_n} frame(s) — {carried_bytes} B (the exact source bytes; the carried frame's verify = the source-sha match — the decode-side verify is the fp-camera lossless decode's scope)"
        );
        println!(
            "estimate: encoded (the raw class) — {} frame(s) — {total_source_raw} B source; no measured raw ratio (all {k} samples were carried — the fp class): the conservative preflight bound (j92 2.0:1 lower bound × the margin) — worst {raw_worst} B",
            n64 - carried_n
        );
        let fits = worst_combined <= free;
        println!(
            "estimate: {} fit — {}: free {free} B vs worst case {worst_combined} B (the carried bytes exact + the raw frames at the conservative preflight bound — no fixed corpus rate)",
            o.dest.display(),
            if fits { "FITS" } else { "DOES NOT FIT" },
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
                None,
                (0, 0, 0),
                (0, 0, 0),
                worst_combined,
                free,
                fits,
                (None, None),
                false,
                &refusal,
                carried_n,
                carried_bytes,
                &census_lines,
                None, // the all-carry sample: no measured band — the both-estimates are unmeasurable (the conservative preflight bound is the named estimate)
            );
        }
        println!("dry run: no ledger row (no archive action, no reservation commit)");
        if !fits {
            println!(
                "DRY RUN REFUSED — space: projected worst case {worst_combined} B does not fit {} ({} B available)",
                o.dest.display(),
                free
            );
            return (Verdict::Space, 2);
        }
        println!(
            "DRY RUN PASS — {m} of {n} sampled ({k} treated as carry — no encode of the fp frames; the encoded estimate = the conservative preflight bound), carried {carried_bytes} B (exact), fits {}",
            o.dest.display()
        );
        return (Verdict::Pass, 0);
    }

    // The sample produced nothing (a failure at frame 0): the named
    // refusal, the estimate is the partial (empty) named line. (The
    // all-carry sample is the branch above — this path is m = 0 with
    // no carried bytes: the carried parameters are 0/0, the census
    // lines render as-is.)
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
            0,
            0,
            &census_lines,
            None, // the empty sample: no measured band — the both-estimates are unmeasurable (the named refusal is the report)
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
    // The carried census (the mixed-compression contract — the
    // fp-camera frames' frame count + the exact carried bytes; 0/0
    // on the raw-only input — the record's shape is the pre-contract
    // shape + the census lines).
    carried_n: u64,
    carried_bytes: u64,
    // The pre-sample-line census lines (the exact stdout lines — the
    // the temporal-verified term amended in for the record when
    // any; n = 0 = the verbatim stdout line, byte-frozen).
    census_lines: &[String],
    // The both estimates (the R0 ruling — R3): the mixed
    // clip's carried vs transcoded plans (size + ETA); None on the
    // raw-only input (the plans coincide — the pre-contract shape) +
    // the no-measured-band paths (the conservative bound / the named
    // refusal).
    both: Option<&BothEstimates>,
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
    //: the class census (the mixed-compression contract — the
    // pre-sample-line census's exact stdout lines, verbatim — the
    // record's additive section; the raw-only input's shape gains
    // the single raw census line, the pre-contract sections below
    // are unchanged).
    for line in census_lines {
        md.push_str(line);
        md.push('\n');
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
                "projected archive (j92): worst (p10 ratio) {w_total} B / likely (p50) {l_total} B / best (p90 ratio) {b_total} B ({pop_note})\n",
                w_total = total_form.0,
                l_total = total_form.1,
                b_total = total_form.2,
                pop_note = if carried_bytes > 0 && !o.carry {
                    "the full population — the fp frames at the measured band (the ruling default)"
                } else {
                    "the raw frames' population — the carried frames ride the carried line"
                },
            ));
            if carried_bytes > 0 {
                if o.carry {
                    md.push_str(&format!(
                        "projected carried (the fp-camera lossless frames — the byte copy, no re-encode): {carried_n} frame(s) — {carried_bytes} B (the exact source bytes; the carried frame's verify = the source-sha match — the decode-side verify is the fp-camera lossless decode's scope)\n\n"
                    ));
                } else {
                    md.push_str(&format!(
                        "projected transcoded (the fp-camera lossless frames — the ruling default: the decode + the re-encode through the archive path): {carried_n} frame(s) — {carried_bytes} B source (the fp frames ride the measured band; the output is in the archive contract)\n\n"
                    ));
                }
            }
            if let Some(both) = both {
                if o.carry {
                    let cw = both.carried_encoded_worst;
                    let cl = both.carried_encoded_likely;
                    let cb = both.carried_encoded_best;
                    let tw = both.transcoded_worst;
                    let tl = both.transcoded_likely;
                    let tb = both.transcoded_best;
                    md.push_str(&format!(
                        "both estimates (the mixed clip — carried vs transcoded: size): carried (--carry) {cw} B worst / {cl} B likely / {cb} B best encoded + {carried_bytes} B carried (exact) = {} B worst vs transcoded (the ruling default) {tw} B worst / {tl} B likely / {tb} B best; the fit-check = the worst of the two plans (both named — the ETAs ride the non-pinned section)\n\n",
                        cw.saturating_add(carried_bytes)
                    ));
                } else {
                    let cw = both.carried_encoded_worst;
                    let cl = both.carried_encoded_likely;
                    let cb = both.carried_encoded_best;
                    let tw = both.transcoded_worst;
                    let tl = both.transcoded_likely;
                    let tb = both.transcoded_best;
                    md.push_str(&format!(
                        "both estimates (the mixed clip — carried vs transcoded: size): transcoded (the ruling default) {tw} B worst / {tl} B likely / {tb} B best vs carried (--carry) {cw} B worst / {cl} B likely / {cb} B best encoded + {carried_bytes} B carried (exact) = {} B worst; the fit-check = the worst of the two plans (both named — the ETAs ride the non-pinned section)\n\n",
                        cw.saturating_add(carried_bytes)
                    ));
                }
            }
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
                "space verdict: worst case {worst} B (the p10-ratio bound over the raw frames{carried_note} = the LARGEST size = the worst case; the line names the measured number the fit-check uses — no fixed corpus rate. The LIVE free-space measurement + the FITS/DOES NOT FIT verdict ride the non-pinned section — the volume state is the environment, not the source, so it is excluded from the byte-identical region)\n\n",
                carried_note = if carried_bytes == 0 {
                    ""
                } else if o.carry {
                    " + the carried bytes (exact)"
                } else {
                    " (the fit-check = the worse of the two plans — the carried scenario and the transcoded ruling)"
                },
            ));
        }
        None => {
            if carried_bytes > 0 {
                md.push_str("\nratio band: n/a (no measured raw ratio — every sampled frame was carried, the fp class; the encoded estimate is the conservative preflight bound above)\n\n");
            } else {
                md.push_str("\nratio band: n/a (the sample produced no measured frames — the refusal below)\n\n");
            }
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
        // The both-estimates' per-scenario ETAs (the per-frame wall's
        // p50/p95 × the scenario's encoded population's frame count —
        // wall-dependent, the non-pinned section's home; the carried
        // plan's ETA covers the encoded population only — the byte
        // copy is an unmeasured path, honestly named).
        if let Some(both) = both {
            md.push_str(&format!(
                "both estimates — ETA encode+verify: carried (--carry) {} (p50) / {} (p95) (the raw frames' encode — the fp byte copy is an unmeasured path) vs transcoded (the ruling default) {} (p50) / {} (p95)\n\n",
                crate::live::fmt_mss(both.carried_eta.0),
                crate::live::fmt_mss(both.carried_eta.1),
                crate::live::fmt_mss(both.transcoded_eta.0),
                crate::live::fmt_mss(both.transcoded_eta.1),
            ));
        }
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

    /// R7 test 6 — the dry-run's mixed-clip census + estimates
    /// (corpus conditional — skip if the 3-frame A001_013 mirror is
    /// absent, the fresh-checkout skip pattern). The dry-run over the
    /// mixed clip (the contract accepted — the pre-sample-line census
    /// fires, the sample's policy dispatch treats the fp frames as
    /// the carry (no encode), the raw frame is the measured sample):
    /// - the verdict is PASS (rc=0) + the estimate completes in
    ///   finite time;
    /// - the record carries the class census line (the per-class
    ///   counts + the exact carried bytes — the 2 fp frames' source
    ///   sizes) + the carried-estimate line (the exact source bytes,
    ///   no encode) + the encoded projection (the raw frames'
    ///   population);
    /// - nothing is written under `dest` (the dry run's discipline
    ///   — not even the dir).
    #[test]
    fn dryrun_mixed_census_and_estimates() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        let input = std::path::Path::new("../testdata/originals/A001_013");
        if !input.is_dir() {
            eprintln!("skip: no A001_013 testdata corpus");
            return;
        }
        let srcs = [
            "A001_013_20260930_000001.DNG",
            "A001_013_20260930_000002.DNG",
            "A001_013_20260930_000723.DNG",
        ];
        for s in &srcs {
            assert!(input.join(s).is_file(), "the corpus frame is missing: {s}");
        }
        let tmp = std::env::temp_dir().join(format!("frameprism-dryrun-mixed-{}", std::process::id()));
        let dest = tmp.join("dest");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // The in-process profile set (the test's stand-in for
        // FRAMEPRISM_PROFILES — the camera identity's resolution is
        // the CWD/probe candidates otherwise; the override is the
        // process-global slot, the Once idempotent).
        crate::worker::testutil::camera_profile_override();
        // The R0 ruling moved this test's behavior: the
        // fp × lossless cell is now the TRANSCODE default; the
        // assertions below describe the `--carry` opt-in (the carry
        // contract, kept verbatim) — the flag is set explicitly
        // (the ruling-moved rewire; every assertion unchanged).
        let opts = Opts {
            dest: dest.clone(),
            k_override: None, // the clamp rule: N=3 → K=N (the full-clip measurement — all 3 frames sampled)
            report: Some(tmp.join("estimate.md")),
            mode: crate::worker::Mode::Lossless,
            lossy_format: crate::worker::LossyFormat::K34892,
            reference: crate::worker::ReferenceDctOpts {
                reference_ref: None,
                reference_mae_tsv: None,
                reference_structure_tsv: None,
            },
            downscale: false,
            fast: false,
            jobs: 2,
            carry: true, // the ruling-moved rewire (R0): the carried scenario
            verify_flag: false,
        };
        let t0 = std::time::Instant::now();
        let (verdict, rc) = estimate(input, &opts);
        let elapsed = t0.elapsed();
        assert!(
            matches!(verdict, Verdict::Pass) && rc == 0,
            "the mixed clip's dry run passes (the {{raw, fp-camera}} contract is accepted): {verdict:?} {rc}"
        );
        assert!(
            elapsed.as_secs() < 120,
            "the estimate completes in finite time (the sample's 1 raw encode + 2 carry skips; the fp frames are NEVER encoded): {elapsed:?}"
        );

        // The record: the class census line (the per-class counts +
        // the exact carried bytes — the 2 fp frames' source sizes)
        // + the carried-estimate line (the exact source bytes, no
        // encode) + the encoded projection (the raw frames'
        // population — the carried frames ride the carried line).
        let report = std::fs::read_to_string(tmp.join("estimate.md")).expect("the --report record is written");
        let carried_bytes = std::fs::metadata(input.join(srcs[0])).unwrap().len()
            + std::fs::metadata(input.join(srcs[2])).unwrap().len();
        assert!(
            report.contains(&format!(
                "class census: . — raw-uncompressed 1 · fp-camera-lossless 2 (carried bytes {carried_bytes})"
            )),
            "the class census line (the pre-sample-line census — the exact carried bytes):\n{report}"
        );
        assert!(
            report.contains(&format!(
                "projected carried (the fp-camera lossless frames — the byte copy, no re-encode): 2 frame(s) — {carried_bytes} B"
            )),
            "the carried-estimate line (the exact source bytes — no encode):\n{report}"
        );
        assert!(
            report.contains("projected archive (j92): worst (p10 ratio)"),
            "the encoded projection (the raw frames' population):\n{report}"
        );
        assert!(
            report.contains(&format!("\n| {s} |", s = srcs[1])),
            "the raw frame's measured sample row (the only encode in the sample — the line-start anchor: the selection table's rows are `| index | name |`):\n{report}"
        );
        // The fp frames have NO measured sample row (the carry
        // treatment — they are never encoded; the per-frame table is
        // the measured population only). They DO appear in the
        // selection table (the index → filename rows — the pre-
        // existing section), so the anchor is the line start (the
        // measured row's form: `| name | src B | enc B | ratio |`).
        for s in [&srcs[0], &srcs[2]] {
            assert!(
                !report.contains(&format!("\n| {s} |")),
                "the carried frame {s} has no measured sample row (never encoded):\n{report}"
            );
        }

        // The discipline: nothing written under `dest` (not even the
        // dir).
        assert!(!dest.exists(), "the dry run never writes under dest (not even the dir)");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
