//! per-clip QC — the deterministic class (the
//! split): what raw DNG pixels support without
//! interpretation — (a) **black/blank frame**: a deterministic
//! pixel-range/variance floor on the decoded planes (per frame; the
//! threshold is PINNED IN THE RECORD — the code constants below + the
//! value carried in the qc record header and the report, so the verdict
//! is reproducible from the recorded threshold); (b) **duplicate frame**:
//! consecutive frames with identical OUTPUT-FILE sha256 from the existing
//! sidecar rows (NO decode — nearly free; v1 = the file-level check, the
//! Recorded decision — see the v1-scope note below); (c) **exposure
//! stats**: a single pass over the decoded planes — per-frame min / max /
//! mean (+ the (a) variance) → the additive per-frame record
//! `<CLIP>.qc.tsv`; clip-level min / max / mean / std / p1 / p99 → the
//! run report. (d) **focus**: OUT OF SCOPE (no code, no sharpness
//! stat — parked).
//!
//! Split rule (pinned): DEFAULT = REPORT ONLY — the stats + the (a)/(b)
//! candidates are always named in the report; the default run NEVER
//! changes rc or blocks the batch. `--qc-gate` = (a)+(b) become GATES:
//! any hit → the run COMPLETES (no data loss — the files are written)
//! and exits rc=2 with the named rows (the named-negative
//! convention — the gate is a verdict, not a preflight refusal). (c) is
//! never a gate (a "−2 EV" reading becomes a number in both the report
//! and the record, never a verdict).
//!
//! **The v4 placement decision:** the
//! -pinned literal placement (per-frame stats as in-file "v4 = v3
//! columns + new columns" of `<CLIP>.checksums.tsv`) is SUPERSEDED by
//! the byte contract: `resume::parse_row` (a read-only strict parser)
//! accepts exactly 4 or 8 sidecar columns + the `version: 3` header, and
//! the plan-row reuse (the read-only `resume::Row`) cannot carry new
//! columns — so an in-file v4 could NEVER meet the sidecar
//! byte-identity for resumed runs (a resumed run never re-decodes the
//! skipped frames), and would regress the shipped `--resume`/`audit`
//! accept-paths. The per-frame v4 content therefore rides the additive
//! `<CLIP>.qc.tsv` record written NEXT TO `<CLIP>.checksums.tsv` (the
//! same next-to additive pattern the member record uses — the
//! v2→v3 additive pattern); `<CLIP>.checksums.tsv` stays v3
//! byte-identical (the v2 AND v3 parse paths byte-untouched), and the
//! JXL sidecar (a separate per-plane row table with its own writer in
//! `jxl.rs`, oracle-pinned) is untouched.
//!
//! **The union contract (the final-sidecar union pattern, the
//! requirement):** a run's final `<CLIP>.qc.tsv` = the prior
//! file's rows (the skipped / earlier frames — parsed at run start, the
//! torn tail NAMED + discarded) UNIONED with this run's rows (the
//! decoded frames — the fresh decode wins per frame key), SORTED BY FRAME
//! NAME — a pure function of the final clip state: the same state
//! produces the same bytes whether the run was fresh or resumed. A frame
//! that cannot be carried (the named torn-tail edge) is a `partial:`
//! note — named, never silent (the fallback for the impossible case; the
//! union is the primary path).
//!
//! **Not an audit surface (the requirement):** the qc record
//! is a DERIVED-STATS record, not a content-integrity record — the
//! integrity rides the `<CLIP>.checksums.tsv` rows (the file bytes);
//! re-verifying the stats would mean re-decoding the pixels, which
//! `audit` does not do (the audit re-derives metadata from the DNG
//! headers, never the planes). `audit` and `--verify-checksums` do not
//! consume this file.
//!
//! **The (b) duplicate check's v1 scope (the recorded decision, verbatim):** the
//! shipped per-frame sidecar sha256 is the sha of the OUTPUT DNG file,
//! and the output frame carries the source TC (tag 51043) — so a real
//! double-capture (identical pixels, advanced TC) yields DIFFERENT output
//! bytes → the file-sha duplicate check catches FILE-LEVEL duplication
//! (the same file written twice — the injected-fixture class), NOT
//! pixel-level double-captures. v1 scope = the file-level check (nearly
//! free, from the existing sidecar rows). The pixel-level gap is
//! documented + parked — no decode-based pixel-dup check.
//!
//! **Numeric determinism:** the gate math is EXACT INTEGER (u128) — the
//! variance is the integer numerator N·Σx² − (Σx)² over N² (no f64 in
//! the gate, no catastrophic cancellation); the recorded values (mean /
//! variance / std) render at fixed 3-decimal precision from the exact
//! rationals. No explicit `f` format specifier (rustc 1.98.1: precision-
//! only `{:.3}`). Deterministic: same input → byte-identical record.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// (a) the black/blank RANGE floor (raw levels, the 12-bit fp domain): a
/// frame whose raw values span fewer than this many levels carries no
/// content (a black frame sits at the sensor offset — a few levels; a
/// blank frame is constant — zero range). Pinned code constant — the
/// value is carried in the qc record header + the report so the verdict
/// is reproducible from the recorded threshold.
pub const BLACK_RANGE_FLOOR: u32 = 32;

/// (a) the black/blank VARIANCE floor (variance units, the 12-bit fp
/// domain; std ≈ 16): a flat frame (constant or near-constant) has a
/// variance below this floor. The gate compares the EXACT integer
/// variance numerator: `var_num < BLACK_VAR_FLOOR · N²` (no f64 in the
/// gate math). Pinned code constant (recorded like BLACK_RANGE_FLOOR).
pub const BLACK_VAR_FLOOR: u64 = 256;

/// The depth domain of the (a) verdict: the fp's native 12-bit raw.
/// bps != 12 (the derived 8/10-bit tiers, the 10-bit log path) → the
/// stats are recorded, the verdict is NOT applied (the floor is pinned
/// to the 12-bit domain) — named in the report, never a silent no-op.
pub const QC_VERDICT_BPS: u32 = 12;

/// One frame's single-pass decoded-plane stats (the (a)+(c) content of
/// the v4 record): the exact integer moments (min / max / Σx / Σx² / N)
/// and the per-value histogram (the clip-level p1/p99 source) + the (a)
/// verdict at the pinned floors (the 12-bit domain only).
#[derive(Clone, Debug)]
pub struct QcFrame {
    /// The sidecar row key (the output-relative frame path, POSIX).
    pub rel: String,
    /// The frame's BitsPerSample (8 / 10 / 12 — the unpack depth).
    pub bps: u32,
    pub min: u32,
    pub max: u32,
    /// The sample count (width·height of the decoded plane).
    pub n: u64,
    /// Σx (exact).
    pub sum: u64,
    /// Σx² (exact).
    pub sumsq: u64,
    /// The exact variance numerator: N·Σx² − (Σx)² (≥ 0; the variance =
    /// var_num / N² as an exact rational — no cancellation, no f64 in
    /// the gate math).
    pub var_num: u128,
    /// The (a) verdict (the 12-bit domain only — bps == QC_VERDICT_BPS;
    /// other depths = false, the named no-verdict).
    pub black: bool,
    /// The per-value histogram (2^bps bins) — the clip-level p1/p99
    /// source (transient memory: 12-bit = 4096 bins = 32 KiB per frame).
    pub hist: Vec<u64>,
}

impl QcFrame {
    /// The mean (the exact rational sum/N rendered as f64).
    pub fn mean(&self) -> f64 {
        if self.n == 0 {
            0.0
        } else {
            self.sum as f64 / self.n as f64
        }
    }

    /// The variance (the exact rational var_num/N² rendered as f64).
    pub fn variance(&self) -> f64 {
        if self.n == 0 {
            0.0
        } else {
            self.var_num as f64 / (self.n as f64 * self.n as f64)
        }
    }

    /// The pixel range (max − min, exact).
    pub fn range(&self) -> u32 {
        self.max - self.min
    }
}

/// (a) the black/blank predicate at the pinned floors (the exact integer
/// comparison — the gate math never touches f64): a frame is black/blank
/// when its pixel RANGE is below the range floor OR its variance is
/// below the variance floor (the "pixel-range/variance floor").
pub fn is_black(range: u32, var_num: u128, n: u64) -> bool {
    range < BLACK_RANGE_FLOOR
        || var_num < (BLACK_VAR_FLOOR as u128) * (n as u128) * (n as u128)
}

/// The single pass over the decoded plane (the (c) stats + the (a)
/// variance — ONE pass, the pinned execution order: the stats RIDE the
/// decode the encode already needs, no second decode). `samples` = the
/// worker's unpacked native-depth plane (u16, width·height, the unpack
/// contract: values < 2^bps); `bps` = the frame's BitsPerSample (8/10/12).
/// The stats NEVER alter the encode pipeline (observation only).
pub fn frame_stats(rel: &str, samples: &[u16], bps: u32) -> QcFrame {
    let n = samples.len() as u64;
    if n == 0 {
        return QcFrame {
            rel: rel.to_string(),
            bps,
            min: 0,
            max: 0,
            n: 0,
            sum: 0,
            sumsq: 0,
            var_num: 0,
            black: false,
            hist: vec![0; 1 << bps.min(16)],
        };
    }
    let bins = 1u64 << bps;
    let mut hist = vec![0u64; bins as usize];
    let (mut mn, mut mx) = (u32::MAX, 0u32);
    let mut sum: u64 = 0;
    let mut sumsq: u64 = 0;
    for &s in samples {
        let v = s as u32;
        if v < mn {
            mn = v;
        }
        if v > mx {
            mx = v;
        }
        sum += v as u64;
        sumsq += (v as u64) * (v as u64);
        hist[v as usize] += 1;
    }
    // The exact variance numerator (u128 — no f64, no cancellation):
    // N·Σx² − (Σx)² ≥ 0 (the Cauchy–Schwarz identity).
    let var_num = (n as u128) * (sumsq as u128) - (sum as u128) * (sum as u128);
    let range = mx - mn;
    let black = bps == QC_VERDICT_BPS && is_black(range, var_num, n);
    QcFrame {
        rel: rel.to_string(),
        bps,
        min: mn,
        max: mx,
        n,
        sum,
        sumsq,
        var_num,
        black,
        hist,
    }
}

/// The clip-level moments (the (c) report content): min / max / mean /
/// std / p1 / p99 over the WHOLE-CLIP raw sample population (the summed
/// per-frame histograms + moments — integer-exact). "Per channel" = the
/// raw sensor channel: the fp DNG is a single 1-sample/pixel raw plane
/// (no demosaic in the archive pipeline — one channel).
#[derive(Clone, Debug)]
pub struct ClipMoments {
    /// The frames in the population (the decoded set).
    pub frames: usize,
    /// The sample count (the summed N).
    pub n: u64,
    pub min: u32,
    pub max: u32,
    /// Σx over the population (exact).
    pub sum: u64,
    /// The exact population variance numerator: N·Σx² − (Σx)².
    pub var_num: u128,
    /// The p1 / p99 sample values (the histogram percentiles).
    pub p1: u32,
    pub p99: u32,
}

impl ClipMoments {
    /// The population mean (the exact rational rendered as f64).
    pub fn mean(&self) -> f64 {
        if self.n == 0 {
            0.0
        } else {
            self.sum as f64 / self.n as f64
        }
    }

    /// The population std (the exact variance rational's square root).
    pub fn std(&self) -> f64 {
        if self.n == 0 {
            0.0
        } else {
            (self.var_num as f64 / (self.n as f64 * self.n as f64)).sqrt()
        }
    }
}

/// The percentile value at `p` (0-100) over a histogram population:
/// rank = ceil(p·N/100) = (p·N + 99)/100 (exact integer); the value =
/// the smallest raw value whose cumulative population count reaches the
/// rank. The deterministic formula (the report renders the integer value).
fn percentile_value(hist: &[u64], total: u64, p: u64) -> u32 {
    if total == 0 {
        return 0;
    }
    let rank = (p * total).div_ceil(100);
    let mut acc = 0u64;
    for (v, c) in hist.iter().enumerate() {
        acc += c;
        if acc >= rank {
            return v as u32;
        }
    }
    hist.len().saturating_sub(1) as u32
}

/// The clip-level moments over a frame set (the summed population — the
/// frames of ONE clip; a clip is one capture, a single depth; a mixed
/// depth set is handled by bin-padding, the moments stay exact).
pub fn clip_moments(frames: &[QcFrame]) -> ClipMoments {
    if frames.is_empty() {
        return ClipMoments {
            frames: 0,
            n: 0,
            min: 0,
            max: 0,
            sum: 0,
            var_num: 0,
            p1: 0,
            p99: 0,
        };
    }
    let bins = frames
        .iter()
        .map(|f| 1u64 << f.bps)
        .max()
        .unwrap_or(1) as usize;
    let mut hist = vec![0u64; bins];
    let (mut mn, mut mx) = (u32::MAX, 0u32);
    let mut n: u64 = 0;
    let mut sum: u64 = 0;
    let mut sumsq: u64 = 0;
    for f in frames {
        if f.n == 0 {
            continue;
        }
        n += f.n;
        sum += f.sum;
        sumsq += f.sumsq;
        if f.min < mn {
            mn = f.min;
        }
        if f.max > mx {
            mx = f.max;
        }
        for (v, c) in f.hist.iter().enumerate() {
            hist[v] += c;
        }
    }
    if n == 0 {
        return ClipMoments {
            frames: frames.len(),
            n: 0,
            min: 0,
            max: 0,
            sum: 0,
            var_num: 0,
            p1: 0,
            p99: 0,
        };
    }
    let var_num = (n as u128) * (sumsq as u128) - (sum as u128) * (sum as u128);
    ClipMoments {
        frames: frames.len(),
        n,
        min: mn,
        max: mx,
        sum,
        var_num,
        p1: percentile_value(&hist, n, 1),
        p99: percentile_value(&hist, n, 99),
    }
}

/// One (b) duplicate pair: two CONSECUTIVE frames (frame order = the
/// sidecar row order — the sorted rel, the zero-padded frame names) with
/// the identical OUTPUT-FILE sha256 (the file-level check, v1 scope).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DupPair {
    pub a: String,
    pub b: String,
    pub sha: String,
}

/// (b) the duplicate check over the per-clip sidecar sha rows (NO decode
/// — the rows are the existing sidecar content): the consecutive
/// identical-sha pairs, in row order. A run of k identical frames yields
/// k−1 pairs (each consecutive pair is named).
pub fn dup_pairs(rows: &[(String, String)]) -> Vec<DupPair> {
    let mut out = Vec::new();
    for w in rows.windows(2) {
        let (a, sa) = &w[0];
        let (b, sb) = &w[1];
        if !sa.is_empty() && sa == sb {
            out.push(DupPair {
                a: a.clone(),
                b: b.clone(),
                sha: sa.clone(),
            });
        }
    }
    out
}

/// The clip key of a sidecar row's relpath (the parent dir, "" = the
/// input root — the SAME key space as the ingest manifest: the relpath's
/// parent dir, the offload/worker convention).
pub fn clip_key_of_rel(rel: &str) -> String {
    match rel.rfind('/') {
        Some(pos) => rel[..pos].to_string(),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// The decode-site registry (the process-wide state)
// ---------------------------------------------------------------------------

/// The decode-site registry (the pins/selection/resume OnceLock pattern):
/// the worker's encode hook `note`s each decoded frame's stats (keyed by
/// the sidecar row key — the output-relative frame path); the per-frame
/// append site `claim`s them and the final union reads the remainder.
/// `worker::FrameStats` is shared with the jxl path (a read-only
/// constructor in `jxl.rs`), so the stats flow through this registry,
/// not a FrameStats field — the encode hook observes the decoded planes
/// without altering the encode pipeline.
static FRAMES: OnceLock<Mutex<HashMap<String, QcFrame>>> = OnceLock::new();

fn frames() -> &'static Mutex<HashMap<String, QcFrame>> {
    FRAMES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The encode decode site: record one frame's stats (the keyed note —
/// a same-key re-note replaces, the last writer wins per frame).
pub fn note(rel: &str, qc: QcFrame) {
    frames().lock().unwrap().insert(rel.to_string(), qc);
}

/// Claim one frame's stats (the per-frame append site — removes the
/// key; absent = the frame was not decoded this run, e.g. a skip).
pub fn claim(rel: &str) -> Option<QcFrame> {
    frames().lock().unwrap().remove(rel)
}

/// Drain the remainder (the final union's safety net: any noted frame
/// the append site did not claim — e.g. a frame that failed after the
/// decode).
pub fn drain() -> Vec<QcFrame> {
    frames().lock().unwrap().drain().map(|(_, q)| q).collect()
}

/// The union of the prior record's rows + this run's rows: this run's
/// row WINS per frame key (the fresh decode is the verification, not the
/// trust — the checksums union convention), the remainder carries from
/// the prior file; SORTED BY FILE (the deterministic byte order — the
/// union contract: the same final clip state produces the same bytes
/// whether the run was fresh or resumed).
pub fn union_rows(prior: &[QcRow], fresh: &[QcRow]) -> Vec<QcRow> {
    let mut merged: HashMap<String, QcRow> = HashMap::new();
    for r in prior {
        merged.insert(r.file.clone(), r.clone());
    }
    for r in fresh {
        merged.insert(r.file.clone(), r.clone());
    }
    let mut out: Vec<QcRow> = merged.into_values().collect();
    out.sort_by(|a, b| a.file.cmp(&b.file));
    out
}

// ---------------------------------------------------------------------------
// The qc record (<CLIP>.qc.tsv — the additive per-frame v4 content)
// ---------------------------------------------------------------------------

/// The qc record magic line (the v2→v3 additive pattern: the header
/// block identifies the file; the row table is the per-frame v4 content
/// — the v3 `<CLIP>.checksums.tsv` stays byte-identical next to it).
pub const QC_MAGIC: &str = "# frameprism qc sidecar";

/// The qc record column line: the per-frame v4 content (the exposure
/// min/max/mean — the pinned (c) columns — + the (a) range/variance +
/// the black/blank verdict). Fixed 3-decimal rendering of the exact
/// rationals (the deterministic numeric formatting).
pub const QC_COLUMNS: &str =
    "file\tbps\traw_min\traw_max\traw_mean\trange\tvariance\tblack";

/// The qc record file name for a clip: `<CLIP>.qc.tsv` (the sidecar's
/// next-to sibling — the same name space as `<CLIP>.checksums.tsv`).
pub fn qc_name(clip: &str) -> String {
    format!("{clip}.qc.tsv")
}

/// One qc record row (the on-disk form — the pre-formatted columns; the
/// single row-shape source for the incremental append + the final
/// canonical write, the checksums `row_line` parity).
#[derive(Clone, Debug, PartialEq)]
pub struct QcRow {
    pub file: String,
    pub bps: u32,
    pub min: u32,
    pub max: u32,
    /// The mean at the fixed 3-decimal form (the recorded value).
    pub mean: String,
    pub range: u32,
    /// The variance at the fixed 3-decimal form (the exact rational's
    /// rendering — the recorded value).
    pub variance: String,
    pub black: bool,
}

impl QcRow {
    /// The row from a decoded frame's stats (the one formatter for both
    /// writers — the byte parity is structural).
    pub fn from_frame(f: &QcFrame) -> QcRow {
        QcRow {
            file: f.rel.clone(),
            bps: f.bps,
            min: f.min,
            max: f.max,
            mean: format!("{:.3}", f.mean()),
            range: f.range(),
            variance: format!("{:.3}", f.variance()),
            black: f.black,
        }
    }

    /// The on-disk line (`\n`-terminated; the `black` column is 0/1).
    pub fn line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            self.file,
            self.bps,
            self.min,
            self.max,
            self.mean,
            self.range,
            self.variance,
            u8::from(self.black)
        )
    }
}

/// The qc record header block (the deterministic byte prefix — no wall
/// clock: the record is diffable, the run report's contract).
/// `rows` = the record's row count, `frames_total` = the run's frame
/// count (the coverage: K of N), `partial` = the named frame(s) not
/// decodable this run and absent from the prior record (the torn-tail
/// edge — named, never silent; the union is the primary path).
pub fn qc_header(clip: &str, rows: usize, frames_total: usize, partial: &[String]) -> String {
    let mut h = String::new();
    h.push_str(QC_MAGIC);
    h.push('\n');
    h.push_str("version: 1\n");
    h.push_str(&format!("tool_version: {}\n", env!("CARGO_PKG_VERSION")));
    h.push_str(&format!("clip: {clip}\n"));
    h.push_str("note: the additive per-frame exposure record (the \"v4\" sidecar content; <CLIP>.checksums.tsv stays v3 byte-identical — the byte contract over the literal in-file placement)\n");
    h.push_str(&format!(
        "threshold: black/blank = range < {BLACK_RANGE_FLOOR} OR variance < {BLACK_VAR_FLOOR} (the pinned constants qc::BLACK_RANGE_FLOOR / qc::BLACK_VAR_FLOOR — the {QC_VERDICT_BPS}-bit fp domain; other depths = stats only, no verdict)\n"
    ));
    h.push_str(&format!("rows: {rows} of {frames_total}\n"));
    if partial.is_empty() {
        h.push_str("partial: none\n");
    } else {
        h.push_str(&format!(
            "partial: {} — {} frame(s) not decodable this run and absent from the prior record (named): {}\n",
            partial.len(),
            partial.len(),
            partial.join(", ")
        ));
    }
    h.push_str(QC_COLUMNS);
    h.push('\n');
    h
}

/// Write the canonical qc record (temp + rename — the atomic
/// final write: a kill mid-write leaves the previous complete record in
/// place, never a torn final file; the hidden tmp is the named pattern
/// resume cleans up). The rows are SORTED BY FILE (the deterministic
/// byte order — the union contract).
pub fn write_qc(
    out_dir: &Path,
    clip: &str,
    rows: &[QcRow],
    frames_total: usize,
    partial: &[String],
) -> std::io::Result<PathBuf> {
    let mut rows: Vec<_> = rows.to_vec();
    rows.sort_by(|a, b| a.file.cmp(&b.file));
    let mut tsv = qc_header(clip, rows.len(), frames_total, partial);
    for r in &rows {
        tsv.push_str(&r.line());
    }
    let path = out_dir.join(qc_name(clip));
    let tmp = out_dir.join(format!(".{clip}.qc.tsv.tmp"));
    std::fs::write(&tmp, tsv)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Parse a qc record (this module's writer — the strict shape): the
/// magic line, the header keys (a no-tab `key: value` block), the exact
/// column line, the 8-column data rows. Returns `(rows, torn_tail)` —
/// the torn tail = the raw final line of a killed mid-append (the named
/// discard, the parity — the frame re-encodes or stays named in the
/// `partial:` note); a failed parse anywhere else is an Err (the loud
/// class — the corrupt-record is named, never a silent skip).
pub fn parse_qc(path: &Path) -> Result<(Vec<QcRow>, Option<String>), String> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tsv = std::fs::read_to_string(path)
        .map_err(|err| format!("read the qc record {name}: {err}"))?;
    let lines: Vec<&str> = tsv.lines().collect();
    let first = lines
        .first()
        .ok_or_else(|| format!("empty qc record {name}"))?;
    if *first != QC_MAGIC {
        return Err(format!(
            "{name} is not a frameprism qc record (first line {first:?}, want {QC_MAGIC:?})"
        ));
    }
    let mut rows = Vec::new();
    let mut in_data = false;
    for (idx, line) in lines.iter().enumerate().skip(1) {
        let lineno = idx + 1;
        if !in_data {
            if *line == QC_COLUMNS {
                in_data = true;
            }
            // the header key lines (version / tool_version / clip /
            // note / threshold / rows / partial) — additive by
            // convention; no parse beyond the column line's arrival.
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if !line.contains('\t') {
            continue; // a tolerated no-tab line (the header-key shape)
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 8 {
            // The torn tail (the parity): the killed mid-append's
            // final line — named discard, NOT the loud error (only as
            // the file's final line without a trailing newline).
            let last = idx + 1 == lines.len() && !tsv.ends_with('\n');
            if last {
                continue;
            }
            return Err(format!(
                "bad row in {name} line {lineno}: {} columns (want 8: file, bps, raw_min, raw_max, raw_mean, range, variance, black)",
                f.len()
            ));
        }
        let bps: u32 = f[1]
            .parse()
            .map_err(|_| format!("bad bps column {:?} in {name} line {lineno}", f[1]))?;
        if !matches!(bps, 8 | 10 | 12) {
            return Err(format!("bad bps column {:?} in {name} line {lineno} (want 8, 10 or 12)", f[1]));
        }
        let min: u32 = f[2]
            .parse()
            .map_err(|_| format!("bad raw_min column {:?} in {name} line {lineno}", f[2]))?;
        let max: u32 = f[3]
            .parse()
            .map_err(|_| format!("bad raw_max column {:?} in {name} line {lineno}", f[3]))?;
        if f[4].is_empty() {
            return Err(format!("bad raw_mean column (empty) in {name} line {lineno}"));
        }
        let range: u32 = f[5]
            .parse()
            .map_err(|_| format!("bad range column {:?} in {name} line {lineno}", f[5]))?;
        if range != max - min {
            return Err(format!(
                "inconsistent range column {:?} in {name} line {lineno} (want {} = max - min)",
                f[5],
                max - min
            ));
        }
        if f[6].is_empty() {
            return Err(format!("bad variance column (empty) in {name} line {lineno}"));
        }
        let black = match f[7] {
            "0" => false,
            "1" => true,
            other => {
                return Err(format!(
                    "bad black column {:?} in {name} line {lineno} (want 0 or 1)",
                    other
                ))
            }
        };
        rows.push(QcRow {
            file: f[0].to_string(),
            bps,
            min,
            max,
            mean: f[4].to_string(),
            range,
            variance: f[6].to_string(),
            black,
        });
    }
    if !in_data {
        return Err(format!("no column line in {name} (the qc record is corrupt?)"));
    }
    // The torn-tail line (if any): the file lacks its trailing newline
    // AND the final line failed the row parse — the raw line is
    // returned for the named note.
    let torn = if tsv.ends_with('\n') || lines.is_empty() {
        None
    } else {
        let last_line = lines.last().unwrap();
        let f: Vec<&str> = last_line.split('\t').collect();
        if f.len() == 8 && in_data && last_line.contains('\t') {
            None // a final line that PARSES is usable (lenient, the resume parity).
        } else {
            Some(last_line.to_string())
        }
    };
    Ok((rows, torn))
}

// ---------------------------------------------------------------------------
// The run state (the report's source — the encode-time computation is
// the authority, the report is the record's echo)
// ---------------------------------------------------------------------------

/// One clip's QC verdicts + stats for the run-report surface.
#[derive(Clone, Debug)]
pub struct ClipQc {
    pub clip: String,
    /// The frames decoded this run (the stats' coverage).
    pub decoded: usize,
    /// The clip's frame total (the gate's frames_found).
    pub total: usize,
    /// (c) the clip-level moments over the decoded set (absent = no
    /// frame decoded — the honest none).
    pub moments: Option<ClipMoments>,
    /// (a) the named black/blank rows: (rel, range, the exact variance
    /// numerator, n).
    pub black: Vec<(String, u32, u128, u64)>,
    /// (b) the named duplicate pairs.
    pub dups: Vec<DupPair>,
    /// (b) availability: false = the sidecar sha rows were absent
    /// (the --checksums pass off / a failed run — the check is named
    /// absent, not silently skipped).
    pub dups_available: bool,
}

/// The run's QC state (the process-wide record the report renders; the
/// CLI process sets it once before the reports — the pins/selection/
/// resume OnceLock pattern; a second set is a silent no-op).
#[derive(Clone, Debug)]
pub struct RunState {
    /// `--qc-gate` on (the verdict mode vs the report-only default).
    pub gate: bool,
    /// The per-clip state (the gate's clip order).
    pub clips: Vec<ClipQc>,
}

impl RunState {
    /// The gate's hit count (the rc contribution): the (a)+(b) named
    /// rows across the clips (0 when the gate is off — the default run
    /// never gates).
    pub fn gate_hits(&self) -> usize {
        if !self.gate {
            return 0;
        }
        self.clips
            .iter()
            .map(|c| c.black.len() + c.dups.len())
            .sum()
    }
}

static CURRENT: OnceLock<Option<RunState>> = OnceLock::new();

/// Record the run's QC state (the single CLI process sets it once
/// before the reports — the encode path's computation; the jxl path
/// never sets it, its report renders the named absent line).
pub fn set_current(state: Option<RunState>) {
    let _ = CURRENT.set(state);
}

/// The run's QC state (the report's source; absent = the jxl path / a
/// run without the j92 decode site).
pub fn current() -> Option<&'static RunState> {
    CURRENT.get().and_then(|o| o.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The unit gate (E2E dark clip class): the all-zero plane → the
    /// black verdict + min=max=0 (the exact 12-bit domain).
    #[test]
    fn all_zero_plane_is_black() {
        let samples = vec![0u16; 1024];
        let q = frame_stats("zero.DNG", &samples, 12);
        assert_eq!(q.min, 0);
        assert_eq!(q.max, 0);
        assert_eq!(q.mean(), 0.0);
        assert_eq!(q.variance(), 0.0);
        assert_eq!(q.var_num, 0);
        assert!(q.black, "the all-zero plane is the black verdict");
        assert_eq!(q.n, 1024);
    }

    /// The unit gate: the constant plane → variance 0 (the exact
    /// integer numerator — no cancellation) + the blank verdict (the
    /// range floor: zero range = no content).
    #[test]
    fn constant_plane_has_zero_variance() {
        let samples = vec![1000u16; 512];
        let q = frame_stats("flat.DNG", &samples, 12);
        assert_eq!(q.min, 1000);
        assert_eq!(q.max, 1000);
        assert_eq!(q.var_num, 0, "the constant plane's variance numerator is exactly 0");
        assert_eq!(q.variance(), 0.0);
        assert!(q.black, "the constant plane is the blank verdict (range 0 < the floor)");
        // The mean is exact: 1000.000.
        let row = QcRow::from_frame(&q);
        assert_eq!(row.mean, "1000.000");
        assert_eq!(row.variance, "0.000");
    }

    /// The unit gate: the known gradient → exact min/max/mean (hand-
    /// computed): 0..15 (16 samples) → min 0, max 15, mean 7.5, Σx = 120,
    /// Σx² = 1240, var_num = 16·1240 − 120² = 5440, variance = 5440/256
    /// = 21.25.
    #[test]
    fn known_gradient_exact_stats() {
        let samples: Vec<u16> = (0..16).collect();
        let q = frame_stats("grad.DNG", &samples, 12);
        assert_eq!(q.min, 0);
        assert_eq!(q.max, 15);
        assert_eq!(q.sum, 120);
        assert_eq!(q.sumsq, 1240);
        assert_eq!(q.var_num, 5440);
        assert!(
            (q.mean() - 7.5).abs() < 1e-12,
            "the mean is exactly 7.5 (got {})",
            q.mean()
        );
        assert!((q.variance() - 21.25).abs() < 1e-12, "the variance is exactly 21.25");
        let row = QcRow::from_frame(&q);
        assert_eq!(row.mean, "7.500");
        assert_eq!(row.variance, "21.250");
        assert_eq!(row.range, 15);
    }

    /// The full-range ramp (0..4095) → NOT black (the range + variance
    /// are far above the pinned floors — the dark-but-not-black class
    /// must pass clean; A001_001 is the E2E instance).
    #[test]
    fn full_range_ramp_is_not_black() {
        let samples: Vec<u16> = (0..4096).map(|i| (i % 4096) as u16).collect();
        let q = frame_stats("ramp.DNG", &samples, 12);
        assert_eq!(q.min, 0);
        assert_eq!(q.max, 4095);
        assert!(!q.black, "the full-range ramp carries content (not black/blank)");
    }

    /// The unit gate: the duplicate check on synthetic sidecar sha
    /// sequences — identical consecutive → named; none → clean.
    #[test]
    fn dup_pairs_synthetic_sequences() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        // f1=f2 (a), f3 (b), f4=f5=f6 (a) → the pairs (f1,f2) + (f4,f5)
        // + (f5,f6): a run of 3 yields 2 consecutive pairs.
        let rows = vec![
            ("f1".to_string(), a.clone()),
            ("f2".to_string(), a.clone()),
            ("f3".to_string(), b.clone()),
            ("f4".to_string(), a.clone()),
            ("f5".to_string(), a.clone()),
            ("f6".to_string(), a.clone()),
        ];
        let dups = dup_pairs(&rows);
        assert_eq!(dups.len(), 3);
        assert_eq!(dups[0].a, "f1");
        assert_eq!(dups[0].b, "f2");
        assert_eq!(dups[0].sha, a);
        assert_eq!(dups[1].a, "f4");
        assert_eq!(dups[1].b, "f5");
        assert_eq!(dups[2].a, "f5");
        assert_eq!(dups[2].b, "f6");
        // None identical → clean.
        let clean = vec![
            ("f1".to_string(), a.clone()),
            ("f2".to_string(), b.clone()),
            ("f3".to_string(), a),
        ];
        assert!(dup_pairs(&clean).is_empty(), "no consecutive duplicates → clean");
        // Empty sha (the absent-row guard) → never a dup.
        let empty = vec![
            ("f1".to_string(), String::new()),
            ("f2".to_string(), String::new()),
        ];
        assert!(dup_pairs(&empty).is_empty());
    }

    /// The unit gate: the threshold pinning — the same pixels + the
    /// recorded threshold (the pinned constants) → the same verdict, at
    /// the exact boundaries (the floors are strict `<`): range 32 /
    /// variance at the floor → NOT black; range 31 / variance just
    /// below → black.
    #[test]
    fn threshold_pinning_is_exact_and_reproducible() {
        // The boundaries (the exact integer gate math): range is
        // tested with the variance FAR above its floor (the OR must
        // not fire on the other clause), and vice versa.
        let big = u128::MAX;
        assert!(
            !is_black(BLACK_RANGE_FLOOR, big, 100),
            "range AT the floor is not black (strict <)"
        );
        assert!(
            is_black(BLACK_RANGE_FLOOR - 1, big, 100),
            "range below the floor is black (the variance far above its floor — the range clause alone)"
        );
        let n = 100u64;
        let at_floor = (BLACK_VAR_FLOOR as u128) * (n as u128) * (n as u128);
        assert!(!is_black(1000, at_floor, n), "variance AT the floor is not black (strict <)");
        assert!(is_black(1000, at_floor - 1, n), "variance just below the floor is black");
        // The same pixels + the recorded threshold → the same verdict
        // (the constants are the record — reproducible from the
        // recorded threshold):
        let samples = vec![10u16; 64];
        let q1 = frame_stats("x.DNG", &samples, 12);
        let q2 = frame_stats("x.DNG", &samples, 12);
        assert_eq!(q1.black, q2.black, "the verdict is a pure function of the pixels + the pinned floors");
        assert!(q1.black);
    }

    /// The (a) domain rule: bps != 12 → the stats are computed, the
    /// verdict is NOT applied (the floor is pinned to the 12-bit fp
    /// domain — the named no-verdict, never a false gate).
    #[test]
    fn the_verdict_is_12bit_domain_only() {
        let zero8 = vec![0u16; 256];
        let q8 = frame_stats("z8.DNG", &zero8, 8);
        assert!(
            !q8.black,
            "an 8-bit all-zero plane carries stats but NOT the (a) verdict (the 12-bit domain)"
        );
        assert_eq!(q8.min, 0);
        assert_eq!(q8.max, 0);
        let zero10 = vec![0u16; 1024];
        let q10 = frame_stats("z10.DNG", &zero10, 10);
        assert!(!q10.black);
    }

    /// The clip-level moments on synthetic populations (the exact
    /// integer math): two frames sharing a known histogram → the exact
    /// min/max/mean/std/p1/p99.
    #[test]
    fn clip_moments_exact_on_synthetic_population() {
        // Frame 1: 0,1,2,3 (n=4, Σx=6, Σx²=14).
        let s1: Vec<u16> = vec![0, 1, 2, 3];
        // Frame 2: 4,5,6,7 (n=4, Σx=22, Σx²=126).
        let s2: Vec<u16> = vec![4, 5, 6, 7];
        let q1 = frame_stats("f1.DNG", &s1, 12);
        let q2 = frame_stats("f2.DNG", &s2, 12);
        let m = clip_moments(&[q1.clone(), q2.clone()]);
        assert_eq!(m.frames, 2);
        assert_eq!(m.n, 8);
        assert_eq!(m.min, 0);
        assert_eq!(m.max, 7);
        // The population 0..7: mean 3.5; Σx = 28, Σx² = 140;
        // var_num = 8·140 − 28² = 1120 − 784 = 336; var = 336/64 =
        // 5.25; std = sqrt(5.25) (the direct check: Σ(x−3.5)² = 42,
        // /8 = 5.25 ✓).
        assert_eq!(m.sum, 28);
        assert_eq!(m.var_num, 336);
        assert!((m.mean() - 3.5).abs() < 1e-12);
        assert!((m.std() - 5.25_f64.sqrt()).abs() < 1e-12);
        // p1: rank = ceil(1·8/100) = 1 → the smallest value with
        // cumulative count ≥ 1 = 0. p99: rank = ceil(99·8/100) = 8 →
        // the value at the 8th sample (cumulative) = 7.
        assert_eq!(m.p1, 0, "p1 = the first sample value (rank 1 of 8)");
        assert_eq!(m.p99, 7, "p99 = the last sample value (rank 8 of 8)");
        // The empty set → the honest zeros.
        let m0 = clip_moments(&[]);
        assert_eq!(m0.n, 0);
        assert_eq!(m0.frames, 0);
    }

    /// The record's write/parse roundtrip + determinism (two writes →
    /// byte-identical; the rows sorted by file — the union contract).
    #[test]
    fn qc_record_roundtrip_and_deterministic() {
        let base = std::env::temp_dir().join(format!("frameprism_qc_test_{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let mk = |rel: &str, v: u16| -> QcRow {
            let samples = vec![v; 64];
            QcRow::from_frame(&frame_stats(rel, &samples, 12))
        };
        // Unsorted input (the union's sorted-write contract).
        let rows = vec![mk("f3.DNG", 100), mk("f1.DNG", 200), mk("f2.DNG", 300)];
        write_qc(&base, "clip", &rows, 3, &[]).unwrap();
        let p = base.join("clip.qc.tsv");
        let bytes1 = std::fs::read(&p).unwrap();
        // Two fresh runs from the same state → identical bytes.
        write_qc(&base, "clip", &rows, 3, &[]).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), bytes1, "the record is byte-deterministic");
        // The roundtrip: the parse agrees with the rows (sorted).
        let (parsed, torn) = parse_qc(&p).unwrap();
        assert!(torn.is_none());
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].file, "f1.DNG");
        assert_eq!(parsed[1].file, "f2.DNG");
        assert_eq!(parsed[2].file, "f3.DNG");
        assert_eq!(parsed[0], mk("f1.DNG", 200));
        // The header carries the pinned threshold (the verdict is
        // reproducible from the recorded threshold).
        let text = String::from_utf8(bytes1).unwrap();
        assert!(text.contains(&format!(
            "threshold: black/blank = range < {BLACK_RANGE_FLOOR} OR variance < {BLACK_VAR_FLOOR}"
        )));
        assert!(text.contains("rows: 3 of 3"));
        assert!(text.contains("partial: none"));
        assert!(!text.contains("created:"), "no wall clock (the contract)");
        // The partial note (the named gap — never silent).
        write_qc(&base, "clip", &rows, 4, &["f4.DNG".to_string()]).unwrap();
        let t2 = std::fs::read_to_string(&p).unwrap();
        assert!(t2.contains("partial: 1 — 1 frame(s) not decodable this run and absent from the prior record (named): f4.DNG"));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The torn tail (the parity): a killed mid-append's final line
    /// (no trailing newline, truncated) → the named discard, the rest
    /// of the file intact.
    #[test]
    fn qc_parse_named_torn_tail() {
        let base = std::env::temp_dir().join(format!("frameprism_qc_torn_{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let p = base.join("clip.qc.tsv");
        let good = format!(
            "{}\nversion: 1\ntool_version: t\nclip: clip\nrows: 2 of 2\npartial: none\n{}\nf1.DNG\t12\t0\t100\t50.000\t100\t0.000\t0\n",
            QC_MAGIC, QC_COLUMNS
        );
        // The killed append: a truncated final line without a trailing
        // newline (a torn row — 4 fields of 8, no \n).
        std::fs::write(&p, format!("{good}f2.DNG\t12\t0\t")).unwrap();
        let (rows, torn) = parse_qc(&p).unwrap();
        assert_eq!(rows.len(), 1, "the intact row parses");
        assert_eq!(rows[0].file, "f1.DNG");
        assert_eq!(torn.as_deref(), Some("f2.DNG\t12\t0\t"), "the torn tail is named");
        // A clean file → no torn tail.
        std::fs::write(&p, good.as_str()).unwrap();
        let (rows, torn) = parse_qc(&p).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(torn.is_none());
        // A corrupt MIDDLE row → the loud Err (not the silent discard).
        std::fs::write(&p, format!("{good}f2.DNG\tXX\t0\t100\t50.000\t100\t0.000\t0\n")).unwrap();
        assert!(parse_qc(&p).is_err(), "a bad row mid-file is the loud class");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The union: this run's rows win per frame key, the remainder
    /// carries from the prior, sorted (the union contract — the same
    /// final clip state = the same bytes fresh vs resumed).
    #[test]
    fn union_rows_fresh_wins_and_sorted() {
        let mk = |file: &str, mean: &str| QcRow {
            file: file.to_string(),
            bps: 12,
            min: 0,
            max: 100,
            mean: mean.to_string(),
            range: 100,
            variance: "1.000".into(),
            black: false,
        };
        let prior = vec![mk("f1.DNG", "10.000"), mk("f2.DNG", "20.000"), mk("f3.DNG", "30.000")];
        let fresh = vec![mk("f3.DNG", "33.333"), mk("f4.DNG", "40.000")];
        let merged = union_rows(&prior, &fresh);
        assert_eq!(merged.len(), 4);
        assert_eq!(merged[0].file, "f1.DNG");
        assert_eq!(merged[0].mean, "10.000", "the carried row stands");
        assert_eq!(merged[1].file, "f2.DNG");
        assert_eq!(merged[2].file, "f3.DNG");
        assert_eq!(merged[2].mean, "33.333", "the fresh row wins per key");
        assert_eq!(merged[3].file, "f4.DNG");
        // A fresh-only run (no prior) = the fresh rows, sorted.
        let only = union_rows(&[], &fresh);
        assert_eq!(only.len(), 2);
        assert_eq!(only[0].file, "f3.DNG");
    }

    /// The registry (the decode-site flow): note/claim/drain (a same-
    /// key re-note replaces; a claim removes; the drain takes the
    /// remainder).
    #[test]
    fn registry_note_claim_drain() {
        let s = vec![5u16; 8];
        note("r1.DNG", frame_stats("r1.DNG", &s, 12));
        note("r2.DNG", frame_stats("r2.DNG", &s, 12));
        // The same-key re-note replaces (the last writer wins).
        let s2 = vec![9u16; 8];
        note("r1.DNG", frame_stats("r1.DNG", &s2, 12));
        let c1 = claim("r1.DNG").unwrap();
        assert_eq!(c1.min, 9, "the re-note's value stands");
        assert!(claim("r1.DNG").is_none(), "a claim removes the key");
        let rest = drain();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].rel, "r2.DNG");
        assert!(drain().is_empty());
    }

    /// The clip key of a relpath (the offload/worker convention: the
    /// parent dir, "" = the root).
    #[test]
    fn clip_key_of_rel_helper() {
        assert_eq!(clip_key_of_rel("A001_007/f1.DNG"), "A001_007");
        assert_eq!(clip_key_of_rel("f1.DNG"), "");
        assert_eq!(clip_key_of_rel("a/b/f1.DNG"), "a/b");
    }
}
