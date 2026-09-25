//! The offload job report (the structured job-report format
//! report, the documented 2024.2 baseline (b)): the run's record,
//! written at EVERY standalone-offload dest root at the run's end
//! (the save-with-job placement), automatic (no flag — the manual's
//! model: "automatically be generated without further prompting after
//! offloading has finished"), in three file forms: the markdown
//! (`.frameprism-job-report.md` — the manual's "Text" class, the
//! tool's report idiom), the plain CSV (`.frameprism-job-report.csv` —
//! the manual's spreadsheet form), and the self-contained HTML
//! (`.frameprism-job-report.html` — the tool's own variant beyond the
//! manual's three types).
//!
//! The two documented detail levels in ONE report —
//! the manual's Detailed/Summary split is a GUI preference, not a
//! data difference (the run-report precedent):
//!   - the session block (the Summary "session information"): the
//!     input path (as given), the dest path, `created:` (the job
//!     report's own write moment — a separate stamp from the run
//!     report's created line, no equality required), the tool +
//!     version line (the OSS name), the job identifier line (v1:
//!     `job: <created-UTC-timestamp>` — the manual's Job Identifier
//!     is the run's identity + date/time stamp);
//!   - the summary block (the Summary level): the total file count,
//!     the total size (bytes), the run duration (seconds, 1-decimal —
//!     the wall clock of the run's copy+verify phase), and the
//!     per-dest verdict line VERBATIM (the existing
//!     `offload::OffloadReport::verdict_line` format — the
//!     zero-new-offload-vocabulary rule);
//!   - the per-clip blocks (the Detailed level): for each clip (the
//!     detection's sorted clip keys, the row order) the detection
//!     line VERBATIM (the `camera::DetectionClass::line` three-class
//!     formats — the report-not-gate identity), the clip's file count
//!     + total size, the clip's copy+verify duration (ms), and the
//!     per-file table (one row per file: the relpath, the size, the
//!     source_sha256, the dest_sha256, the verdict, the skipped
//!     column (the duplicate detection: `yes`/`no` in the
//!     md/HTML, `1`/`0` in the CSV), the copied_ms).
//!
//! THE MEDIA-DETAILS BOUNDARY:
//! the standalone offload is pass-through — the DNG payload is NOT
//! parsed (no TC/frame-rate/frame-count extraction on the offload
//! path; the detection reads the Make/Model headers only). The
//! per-clip media details are the detection identity + the file
//! counts/sizes/durations/verdicts. The encode path's ingest gate
//! carries the frame/TC details.
//!
//! THE DURATIONS (the one new measurement this change adds): the
//! per-file copy+verify duration (the per-(file, dest) write +
//! dest-side verify window, measured with `std::time::Instant` in
//! `offload::offload_core_multi` — the read-once source side is
//! amortized across the dests; not a pure I/O throughput number) +
//! the run total (seconds, 1-decimal). A SKIPPED row's `copied_ms`
//! (the duplicate detection: the dest file already present
//! with matching content, verified only — NOT re-copied) = the
//! verify-only window (the pre-check stat + read + hash; NO write):
//! skipped rows carry the verify-only window (no write). The
//! durations ride ONLY in the job report (the md/csv/html files) —
//! the offload manifests, the run report, the stderr surface are
//! UNTOUCHED by the timing (R-INV-A — the deterministic contract
//! artifacts stay byte-frozen).
//!
//! The job report is a RECORD, not a gate: the run's rc
//! semantics are UNCHANGED (rc 0/1/2 per the offload contract); the
//! report renders the run's verification results, it never re-verify
//! or re-hashes. Its write position: AFTER the copy + verify + the
//! per-clip manifests + the run report (the records stand first); a
//! job-report write failure is the named hard-error band (the
//! manifest writers' `.with_context` class — the error surfaces, the
//! run's rc becomes the error rc — the data integrity is already
//! gated by the verify-before-wipe, the job report is the record
//! layer).
//!
//! The ENCODE SURFACE'S `--to` PATH GETS NO JOB REPORT IN v1 (14b's
//! encode surface stays frozen — the named follow-up candidate; the
//! encode runs carry their own run report + the ingest records).
//!
//! std-only (no new crates): the emitters are
//! hand-rolled string building over the report data (the pure
//! renderers take the assembled `JobReport` — this module owns the
//! one-module-per-surface emitters + the escaping helpers). The CSV
//! is PLAIN: the first line = the EXACT header row (NO comment magic
//! — a `#` line would break spreadsheet loading; the named deliberate
//! deviation from the manifest TSV idiom), one data row per file (the
//! deterministic row order: per clip, the detection's sorted clip-key
//! order; the rows' own order within a clip), RFC-4180-minimal
//! quoting (a field containing a comma / quote / newline is
//! double-quoted, embedded quotes doubled), no BOM, LF line endings,
//! a trailing newline. The HTML is ONE self-contained file: the
//! doctype + the html wrapper, the inline style only (zero external
//! resources, zero JavaScript, zero images), the session + summary
//! blocks, one table per clip (the CSV's columns, the header row =
//! the CSV's column names), the verdict line in a `<pre>`, the text
//! properly escaped (`&`/`<`/`>`). The job report is a wall-clock
//! record (like the run report's created line) — its tests assert at
//! line level, never whole-byte; the durations assert by FORMAT class
//! only (`\d+ ms` / `\d+\.\d s`), never by value.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The job report's three file names (the EXACT pinned names — the
/// dest-root report pattern, the `.frameprism-run-report.md`
/// precedent).
pub const MD_NAME: &str = ".frameprism-job-report.md";
/// The plain CSV's name (the manual's spreadsheet form).
pub const CSV_NAME: &str = ".frameprism-job-report.csv";
/// The self-contained HTML's name (the tool's own variant).
pub const HTML_NAME: &str = ".frameprism-job-report.html";

/// The CSV's column header row (the EXACT pinned names — the first
/// line of the file, plain: NO comment magic — the named deliberate
/// deviation from the manifest TSV idiom). The `skipped` column
/// (the duplicate detection's pin move, named: inserted
/// immediately before `copied_ms`; `1`/`0` — a skip row is `1`).
pub const CSV_HEADER: &str =
    "clip,file,size_bytes,source_sha256,dest_sha256,verdict,skipped,copied_ms";

/// One per-file job-report row (the per-file table's columns — the
/// per-dest values: the dest sha256 / the verdict / the copied_ms are
/// that dest's).
#[derive(Clone, Debug)]
pub struct JobFile {
    /// The file's path RELATIVE to the dest root (= the source
    /// relpath — the mirrored subpath).
    pub file: String,
    /// The file's size in bytes (the source size).
    pub size: u64,
    /// The source sha256 (lowercase 64-hex).
    pub source_sha: String,
    /// The dest copy's sha256 (`-` when `COPY_FAIL` — no copy to
    /// hash).
    pub dest_sha: String,
    /// The row verdict's `as_str()` (OK/SIZE_MISMATCH/
    /// SHA_MISMATCH/COPY_FAIL).
    pub verdict: String,
    /// The skip fact (the duplicate detection: true when
    /// the dest file was already present with matching content
    /// (size + sha256) and was verified only, NOT re-copied — the
    /// row's verdict is OK: the dest content WAS verified; the row
    /// struct / the manifests / the verdict lines stay frozen — the
    /// skip is a RUN fact that rides the job report's `skipped`
    /// column + the run report's `## skipped` section only).
    pub skipped: bool,
    /// The per-(file, dest) copy+verify duration in ms (the write +
    /// the dest-side verify window; a skipped row's window =
    /// the verify-only duration — the pre-check stat + read + hash;
    /// NO write).
    pub copied_ms: u64,
}

/// One clip's job-report block (the per-clip section's content).
#[derive(Clone, Debug)]
pub struct JobClip {
    /// The clip key (the ingest key space; "" = the source root — the
    /// CSV/HTML clip cell is "" for the source-root files).
    pub key: String,
    /// The detection line VERBATIM (the `camera::DetectionClass::line`
    /// three-class formats — the report-not-gate identity).
    pub detection: String,
    /// The clip's file count (all verdicts).
    pub files: u64,
    /// The clip's total size (bytes — the source sizes).
    pub size: u64,
    /// The clip's copy+verify duration (ms — the sum of the rows'
    /// copied_ms).
    pub duration_ms: u64,
    /// The clip's rows (the deterministic row order).
    pub rows: Vec<JobFile>,
}

/// The job report's data (the assembly's output — the pure emitters'
/// input; one per dest).
#[derive(Clone, Debug)]
pub struct JobReport {
    /// The input path (as given).
    pub input: String,
    /// The dest path (the canonical dest root).
    pub dest: String,
    /// The job report's own write moment (unix seconds, UTC — a
    /// separate stamp from the run report's created line).
    pub created: u64,
    /// The job identifier (v1: the run's UTC timestamp — the
    /// manual's Job Identifier: the run's identity + date/time stamp).
    pub job: String,
    /// The tool + version line (the OSS name).
    pub tool: String,
    /// The total file count (all rows, all verdicts).
    pub total_files: u64,
    /// The total size (bytes).
    pub total_size: u64,
    /// The run's copy+verify phase duration (seconds — the wall
    /// clock; rendered 1-decimal).
    pub run_seconds: f64,
    /// The per-dest verdict line VERBATIM (`offload::OffloadReport::
    /// verdict_line` — the zero-new-offload-vocabulary rule).
    pub verdict: String,
    /// The per-clip blocks (the detection's sorted clip-key order —
    /// the row order).
    pub clips: Vec<JobClip>,
}

/// Assemble one dest's job report (the pure assembly over the run's
/// data — no new measurement here: the durations arrive from the
/// core's per-(file, dest) windows + the run's phase wall clock; the
/// clip order is the detection's sorted clip-key order, every
/// offload row's clip key is a detection key by construction — the
/// same source walk).
pub fn build(
    report: &crate::offload::OffloadReport,
    detection: &crate::camera::OffloadDetectionScan,
    copied_ms: &[u64],
    skipped: &[bool],
    created: u64,
    job: &str,
    run_seconds: f64,
) -> JobReport {
    let mut total_files = 0u64;
    let mut total_size = 0u64;
    for r in &report.rows {
        total_files += 1;
        total_size += r.size;
    }
    let mut clips = Vec::with_capacity(detection.clips.len());
    for c in &detection.clips {
        let mut rows = Vec::new();
        let mut files = 0u64;
        let mut size = 0u64;
        let mut duration_ms = 0u64;
        for (j, r) in report.rows.iter().enumerate() {
            if crate::offload::clip_key_of_rel(&r.file) == c.key {
                files += 1;
                size += r.size;
                duration_ms += copied_ms[j];
                rows.push(JobFile {
                    file: r.file.clone(),
                    size: r.size,
                    source_sha: r.source_sha.clone(),
                    dest_sha: r.dest_sha.clone(),
                    verdict: r.verdict.as_str().to_string(),
                    skipped: skipped[j],
                    copied_ms: copied_ms[j],
                });
            }
        }
        clips.push(JobClip {
            key: c.key.clone(),
            detection: c.class.line(),
            files,
            size,
            duration_ms,
            rows,
        });
    }
    JobReport {
        input: report.input.display().to_string(),
        dest: report.dest.display().to_string(),
        created,
        job: job.to_string(),
        tool: format!("frameprism {}", env!("CARGO_PKG_VERSION")),
        total_files,
        total_size,
        run_seconds,
        verdict: report.verdict_line(),
        clips,
    }
}

/// The md (the run-report/ingest-report
/// conventions: the `# frameprism job report` title, the labeled
/// session lines, the `## summary` + the `## <clip>` sections, the
/// per-file table as a markdown table — the file names in backtick
/// code spans (the pipe-in-filename hazard is handled by the code
/// spans, named), the detection lines + the verdict line VERBATIM
/// lines, the durations: per-clip `duration: <n> ms`, the run
/// `duration: <n.n> s`).
pub fn render_md(r: &JobReport) -> String {
    let mut s = String::new();
    s.push_str("# frameprism job report\n\n");
    s.push_str(&format!("input: {}\n", r.input));
    s.push_str(&format!("dest: {}\n", r.dest));
    s.push_str(&format!("created: {} (unix seconds, UTC)\n", r.created));
    s.push_str(&format!("tool: {}\n", r.tool));
    s.push_str(&format!("job: {}\n\n", r.job));
    s.push_str("## summary\n\n");
    s.push_str(&format!("files: {}\n", r.total_files));
    s.push_str(&format!("size: {} B\n", r.total_size));
    s.push_str(&format!("duration: {:.1} s\n", r.run_seconds));
    s.push_str(&format!("{}\n", r.verdict));
    for c in &r.clips {
        s.push_str(&format!(
            "\n## {}\n\n",
            crate::worker::display_clip(&c.key)
        ));
        s.push_str(&format!("{}\n", c.detection));
        s.push_str(&format!("files: {}\n", c.files));
        s.push_str(&format!("size: {} B\n", c.size));
        s.push_str(&format!("duration: {} ms\n\n", c.duration_ms));
        s.push_str("| file | size | source_sha256 | dest_sha256 | verdict | skipped | copied_ms |\n");
        s.push_str("|---|---|---|---|---|---|---|\n");
        for f in &c.rows {
            s.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} | {} |\n",
                f.file,
                f.size,
                f.source_sha,
                f.dest_sha,
                f.verdict,
                if f.skipped { "yes" } else { "no" },
                f.copied_ms
            ));
        }
    }
    s
}

/// The CSV (the plain form — the first line = the header row, NO
/// comment magic; one data row per file, the deterministic row order
/// (per clip, the detection's sorted clip-key order; the rows' own
/// order within a clip); the columns' values: `clip` = the clip key
/// ("" = the source-root files), `file` = the dest-relative path,
/// `verdict` = the row verdict's `as_str()`, `copied_ms` = the
/// integer ms; RFC-4180-minimal quoting; no BOM, LF line endings, a
/// trailing newline).
pub fn render_csv(r: &JobReport) -> String {
    let mut s = String::new();
    s.push_str(CSV_HEADER);
    s.push('\n');
    for c in &r.clips {
        for f in &c.rows {
            let size = f.size.to_string();
            let ms = f.copied_ms.to_string();
            let row = [
                c.key.as_str(),
                f.file.as_str(),
                size.as_str(),
                f.source_sha.as_str(),
                f.dest_sha.as_str(),
                f.verdict.as_str(),
                if f.skipped { "1" } else { "0" },
                ms.as_str(),
            ];
            s.push_str(&row.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
            s.push('\n');
        }
    }
    s
}

/// RFC-4180-minimal quoting: a field containing a comma / quote /
/// newline is double-quoted, embedded quotes doubled.
pub fn csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r')
    {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// The HTML (the tool's own variant — ONE self-contained file: the
/// doctype + the html wrapper, the inline style only (zero external
/// resources, zero JavaScript, zero images), the session + summary
/// blocks, one table per clip (the same columns as the CSV, the
/// header row = the CSV's column names), the verdict line in a
/// `<pre>`, the text properly escaped (`&`/`<`/`>`); deterministic
/// modulo the wall-clock values).
pub fn render_html(r: &JobReport) -> String {
    let mut s = String::new();
    s.push_str("<!doctype html>\n<html>\n<head>\n");
    s.push_str("<meta charset=\"utf-8\">\n");
    s.push_str("<title>frameprism job report</title>\n");
    s.push_str("<style>\n");
    s.push_str("body { font-family: sans-serif; margin: 2em; color: #111; }\n");
    s.push_str("table { border-collapse: collapse; margin: 0.5em 0 1.5em; }\n");
    s.push_str("th, td { border: 1px solid #888; padding: 2px 10px; text-align: left; }\n");
    s.push_str("pre { background: #f4f4f4; padding: 8px; overflow-x: auto; }\n");
    s.push_str("h1 { border-bottom: 2px solid #888; padding-bottom: 4px; }\n");
    s.push_str("</style>\n</head>\n<body>\n");
    s.push_str("<h1>frameprism job report</h1>\n");
    s.push_str("<dl>\n");
    s.push_str(&format!("<dt>input</dt><dd>{}</dd>\n", html_escape(&r.input)));
    s.push_str(&format!("<dt>dest</dt><dd>{}</dd>\n", html_escape(&r.dest)));
    s.push_str(&format!("<dt>created</dt><dd>{} (unix seconds, UTC)</dd>\n", r.created));
    s.push_str(&format!("<dt>tool</dt><dd>{}</dd>\n", html_escape(&r.tool)));
    s.push_str(&format!("<dt>job</dt><dd>{}</dd>\n", html_escape(&r.job)));
    s.push_str("</dl>\n");
    s.push_str("<h2>summary</h2>\n<dl>\n");
    s.push_str(&format!("<dt>files</dt><dd>{}</dd>\n", r.total_files));
    s.push_str(&format!("<dt>size</dt><dd>{} B</dd>\n", r.total_size));
    s.push_str(&format!("<dt>duration</dt><dd>{:.1} s</dd>\n", r.run_seconds));
    s.push_str("</dl>\n");
    s.push_str(&format!("<pre>{}</pre>\n", html_escape(&r.verdict)));
    for c in &r.clips {
        s.push_str(&format!(
            "<h2>{}</h2>\n",
            html_escape(&crate::worker::display_clip(&c.key))
        ));
        s.push_str(&format!("<p>{}</p>\n", html_escape(&c.detection)));
        s.push_str(&format!("<p>files: {}</p>\n", c.files));
        s.push_str(&format!("<p>size: {} B</p>\n", c.size));
        s.push_str(&format!("<p>duration: {} ms</p>\n", c.duration_ms));
        s.push_str("<table>\n<tr>");
        for h in CSV_HEADER.split(',') {
            s.push_str(&format!("<th>{h}</th>"));
        }
        s.push_str("</tr>\n");
        for f in &c.rows {
            s.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                html_escape(&c.key),
                html_escape(&f.file),
                f.size,
                html_escape(&f.source_sha),
                html_escape(&f.dest_sha),
                html_escape(&f.verdict),
                if f.skipped { "yes" } else { "no" },
                f.copied_ms
            ));
        }
        s.push_str("</table>\n");
    }
    s.push_str("</body>\n</html>\n");
    s
}

/// The HTML text-node escaping (`&`/`<`/`>` — the browser-safe form;
/// the CSV needs none of these — its quoting is the RFC-4180 rule).
pub fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Write the job report's three files at the dest root (the
/// save-with-job placement — the dest-root report pattern). A
/// write failure is the named hard-error band (the manifest writers'
/// `.with_context` class — the record, not the gate: the per-clip
/// manifests + the run report already stand). The durability seam:
/// each file's bytes are filesystem-synchronized
/// (`sync_file`) after its write (a sync failure = the same named
/// hard-error band) + the dest root's best-effort dir sync after the
/// three.
pub fn write(dest_root: &Path, report: &JobReport) -> Result<PathBuf> {
    let md = render_md(report);
    let csv = render_csv(report);
    let html = render_html(report);
    for (name, body) in [(MD_NAME, &md), (CSV_NAME, &csv), (HTML_NAME, &html)] {
        let path = dest_root.join(name);
        std::fs::write(&path, body)
            .with_context(|| format!("write the job report file {}", path.display()))?;
        // The durability seam: the report file's bytes are
        // filesystem-synchronized (a sync failure = the named
        // hard-error band).
        crate::durability::sync_file(&path, "job report file")?;
    }
    // The best-effort dir sync of the dest root (the records'
    // dir-entry updates — the pinned note on failure, the records
    // stand).
    crate::durability::sync_dir_best_effort(dest_root);
    Ok(dest_root.join(MD_NAME))
}

/// The multi-shape CSV's column header row (the `--source` form —
/// the EXACT pinned names: the `source` column pinned immediately
/// AFTER `verdict` + the `skipped` column pinned between `verdict`
/// and `copied_ms` (the duplicate detection — the same
/// column's position as the legacy `CSV_HEADER`'s pin — the column
/// prefix stays verbatim for the consumers, the new facts
/// append). The legacy `CSV_HEADER` is byte-frozen for the legacy
/// shape.
pub const CSV_HEADER_MULTI: &str =
    "clip,file,size_bytes,source_sha256,dest_sha256,verdict,source,skipped,copied_ms";

/// The multi-shape md table's header (the `--source` form — the
/// `source` column pinned immediately AFTER `file` — the file-
/// identity grouping — + the `skipped` column at the shipped
/// position (between `verdict` and `copied_ms` — the same position
/// as the legacy md table); the position differs from the CSV's pin
/// by design — the column prefix stays verbatim for the CSV's
/// consumers).
const MD_TABLE_HEADER_MULTI: &str =
    "| file | source | size | source_sha256 | dest_sha256 | verdict | skipped | copied_ms |";

/// The multi-shape HTML table's column names (the same after-`file`
/// position as the md table — NOT the CSV's order — + the `skipped`
/// column at the shipped position (after `verdict`); the
/// HTML's header row carries these names verbatim).
const HTML_TABLE_HEADER_MULTI: &str =
    "clip,file,source,size_bytes,source_sha256,dest_sha256,verdict,skipped,copied_ms";

/// One per-file multi-shape job-report row (the legacy `JobFile` +
/// the `source` column — the source AS GIVEN on the CLI, matching
/// the session block's `input:` line).
#[derive(Clone, Debug)]
pub struct JobFileMulti {
    /// The file's path RELATIVE to the dest root (= the source
    /// relpath — the mirrored subpath).
    pub file: String,
    /// The file's size in bytes (the source size).
    pub size: u64,
    /// The source sha256 (lowercase 64-hex).
    pub source_sha: String,
    /// The dest copy's sha256 (`-` when `COPY_FAIL` — no copy to
    /// hash).
    pub dest_sha: String,
    /// The row verdict's `as_str()` (OK/SIZE_MISMATCH/
    /// SHA_MISMATCH/COPY_FAIL).
    pub verdict: String,
    /// The source AS GIVEN on the CLI (the `source` column's value —
    /// matches the session block's `input:` line).
    pub source: String,
    /// The skip fact (the duplicate detection: true when
    /// this file was already present at the dest with matching
    /// content (size + sha256) and was verified ONLY, NOT re-copied
    /// — the row is `Ok` (the dest content WAS verified against the
    /// source); md/HTML `yes`/`no`, CSV `1`/`0`).
    pub skipped: bool,
    /// The per-(file, dest) copy+verify duration in ms (the write +
    /// the dest-side verify window). A SKIPPED row's window =
    /// the verify-only duration (the pre-check stat + read + hash;
    /// NO write — the duration semantics).
    pub copied_ms: u64,
}

/// One clip's multi-shape job-report block (the per-clip section's
/// content — the legacy `JobClip` + the multi rows; the clip keys
/// are unique across sources by the cross-source top-level name
/// refusal, the source-root key ("") may be shared — the per-file
/// table's `source` column carries the ownership).
#[derive(Clone, Debug)]
pub struct JobClipMulti {
    /// The clip key (the ingest key space; "" = the source root —
    /// the CSV/HTML clip cell is "" for the source-root files).
    pub key: String,
    /// The detection line VERBATIM (the first source in the given
    /// order that carries the key — the three-class formats).
    pub detection: String,
    /// The clip's file count (all verdicts — across the sources at
    /// this dest).
    pub files: u64,
    /// The clip's total size (bytes — the source sizes).
    pub size: u64,
    /// The clip's copy+verify duration (ms — the sum of the rows'
    /// copied_ms — across the sources at this dest).
    pub duration_ms: u64,
    /// The clip's rows (the deterministic row order: the source
    /// order, the source's row order within).
    pub rows: Vec<JobFileMulti>,
}

/// The multi-shape job report's data (the `--source` form — the
/// legacy `JobReport` + the multi session/summary/rows: ONE `input:`
/// line PER SOURCE (the given order), the per-pair verdict lines
/// (one per source — a failed source's line = the pinned `source
/// failed: <err> (no copy)`), the per-clip blocks with the `source`
/// column, the WHOLE-JOB window duration).
#[derive(Clone, Debug)]
pub struct JobReportMulti {
    /// The sources AS GIVEN on the CLI (the given order — one
    /// session `input:` line each).
    pub inputs: Vec<String>,
    /// The dest path (the canonical dest root).
    pub dest: String,
    /// The job's single creation instant (unix seconds, UTC:
    /// ONE instant for the whole job — the run report's `created:`
    /// line + the ascmhl's creationdate share it; the single-
    /// `created:` rule).
    pub created: u64,
    /// The job identifier (the job's single UTC timestamp — ONE job
    /// — the single-identifier rule: the same `job:` line at
    /// every dest's report).
    pub job: String,
    /// The tool + version line (the OSS name).
    pub tool: String,
    /// The total file count (all rows at this dest — across ALL
    /// sources — the completed pairs' rows).
    pub total_files: u64,
    /// The total size (bytes — across ALL sources at this dest).
    pub total_size: u64,
    /// The WHOLE-JOB window duration (seconds — the phase-0 start →
    /// the tail's write for this dest; rendered 1-decimal).
    pub run_seconds: f64,
    /// The per-pair verdict lines (one per source, the given order —
    /// the multi-form pair lines; a failed source's line = the
    /// pinned `source failed: <err> (no copy)`).
    pub verdicts: Vec<String>,
    /// The per-clip blocks (the sorted union of the sources' clip
    /// keys — the row order).
    pub clips: Vec<JobClipMulti>,
}

/// Assemble one dest's multi-shape job report (the pure assembly
/// over the job's data — the per-(source, dest) pair outcomes: the
/// rows (the source's row order), the copied_ms (the source's row
/// order), the detection lines (the first source that carries the
/// key); no new measurement here — the durations arrive from the
/// core's per-(file, dest) windows + the job's phase wall clock).
pub fn build_multi(
    pairs: &[crate::offload::SourceOutcome],
    dest_idx: usize,
    dest: &str,
    created: u64,
    job: &str,
    run_seconds: f64,
) -> JobReportMulti {
    let inputs: Vec<String> = pairs
        .iter()
        .map(|p| p.source.display().to_string())
        .collect();
    // The per-pair verdict lines (one per source, the given order —
    // the multi-form pair line; a failed source = the pinned
    // `source failed:` line — the deterministic refusal rendering).
    let mut verdicts: Vec<String> = Vec::with_capacity(pairs.len());
    for p in pairs {
        if let Some(err) = &p.failure {
            verdicts.push(format!("source failed: {err} (no copy)"));
        } else {
            let report = &p
                .core
                .as_ref()
                .expect("the completed source carries its core outcome")
                .reports[dest_idx];
            verdicts.push(report.pair_verdict_line());
        }
    }
    // The union clip keys (the available scans' keys — the sorted
    // order: the clip keys are unique across sources by the
    // cross-source top-level name refusal; the source-root key ("")
    // may be shared — the per-file table's `source` column carries
 // the ownership).
    let mut keys: Vec<String> = Vec::new();
    for p in pairs {
        if let Some(d) = &p.detection {
            for c in &d.clips {
                if !keys.contains(&c.key) {
                    keys.push(c.key.clone());
                }
            }
        }
    }
    keys.sort();
    // The per-clip blocks (the rows: the source order, the source's
    // row order within; the detection line: the first source in the
    // given order that carries the key).
    let mut total_files = 0u64;
    let mut total_size = 0u64;
    let mut clips: Vec<JobClipMulti> = Vec::new();
    for key in &keys {
        let detection_line = pairs
            .iter()
            .find_map(|p| {
                p.detection
                    .as_ref()
                    .and_then(|d| d.clips.iter().find(|c| c.key == *key).map(|c| c.class.line()))
            })
            .unwrap_or_else(|| "-".to_string());
        let mut rows: Vec<JobFileMulti> = Vec::new();
        let mut files = 0u64;
        let mut size = 0u64;
        let mut duration_ms = 0u64;
        for p in pairs {
            if let Some(core) = &p.core {
                let report = &core.reports[dest_idx];
                let ms = &core.copied_ms[dest_idx];
                let skips = &core.skipped[dest_idx];
                for (j, r) in report.rows.iter().enumerate() {
                    if crate::offload::clip_key_of_rel(&r.file) == *key {
                        files += 1;
                        size += r.size;
                        duration_ms += ms[j];
                        total_files += 1;
                        total_size += r.size;
                        rows.push(JobFileMulti {
                            file: r.file.clone(),
                            size: r.size,
                            source_sha: r.source_sha.clone(),
                            dest_sha: r.dest_sha.clone(),
                            verdict: r.verdict.as_str().to_string(),
                            source: p.source.display().to_string(),
                            skipped: skips[j],
                            copied_ms: ms[j],
                        });
                    }
                }
            }
        }
        if !rows.is_empty() {
            clips.push(JobClipMulti {
                key: key.clone(),
                detection: detection_line,
                files,
                size,
                duration_ms,
                rows,
            });
        }
    }
    JobReportMulti {
        inputs,
        dest: dest.to_string(),
        created,
        job: job.to_string(),
        tool: format!("frameprism {}", env!("CARGO_PKG_VERSION")),
        total_files,
        total_size,
        run_seconds,
        verdicts,
        clips,
    }
}

/// The multi-shape md (the legacy
/// `render_md` + the multi session/summary/rows: ONE `input:` line
/// PER SOURCE, the per-pair verdict lines in the summary, the
/// per-clip tables with the `source` column AFTER `file`).
pub fn render_md_multi(r: &JobReportMulti) -> String {
    let mut s = String::new();
    s.push_str("# frameprism job report\n\n");
    for in_ in &r.inputs {
        s.push_str(&format!("input: {in_}\n"));
    }
    s.push_str(&format!("dest: {}\n", r.dest));
    s.push_str(&format!("created: {} (unix seconds, UTC)\n", r.created));
    s.push_str(&format!("tool: {}\n", r.tool));
    s.push_str(&format!("job: {}\n\n", r.job));
    s.push_str("## summary\n\n");
    s.push_str(&format!("files: {}\n", r.total_files));
    s.push_str(&format!("size: {} B\n", r.total_size));
    s.push_str(&format!("duration: {:.1} s\n", r.run_seconds));
    for v in &r.verdicts {
        s.push_str(&format!("{v}\n"));
    }
    for c in &r.clips {
        s.push_str(&format!(
            "\n## {}\n\n",
            crate::worker::display_clip(&c.key)
        ));
        s.push_str(&format!("{}\n", c.detection));
        s.push_str(&format!("files: {}\n", c.files));
        s.push_str(&format!("size: {} B\n", c.size));
        s.push_str(&format!("duration: {} ms\n\n", c.duration_ms));
        s.push_str(MD_TABLE_HEADER_MULTI);
        s.push('\n');
        s.push_str("|---|---|---|---|---|---|---|---|---|\n");
        for f in &c.rows {
            s.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} | {} | {} |\n",
                f.file, f.source, f.size, f.source_sha, f.dest_sha, f.verdict, if f.skipped { "yes" } else { "no" }, f.copied_ms
            ));
        }
    }
    s
}

/// The multi-shape CSV (the plain form — the first line =
/// `CSV_HEADER_MULTI`, NO comment magic; one data row per file — the
/// deterministic row order (per clip, the sorted union clip-key
/// order; the rows' own order within a clip: the source order, the
/// source's row order within); the `source` column = the source as
/// given (after `verdict` — the prefix verbatim); RFC-4180-
/// minimal quoting; no BOM, LF line endings, a trailing newline).
pub fn render_csv_multi(r: &JobReportMulti) -> String {
    let mut s = String::new();
    s.push_str(CSV_HEADER_MULTI);
    s.push('\n');
    for c in &r.clips {
        for f in &c.rows {
            let size = f.size.to_string();
            let ms = f.copied_ms.to_string();
            let skipped = if f.skipped { "1" } else { "0" };
            let row = [
                c.key.as_str(),
                f.file.as_str(),
                size.as_str(),
                f.source_sha.as_str(),
                f.dest_sha.as_str(),
                f.verdict.as_str(),
                f.source.as_str(),
                skipped,
                ms.as_str(),
            ];
            s.push_str(&row.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
            s.push('\n');
        }
    }
    s
}

/// The multi-shape HTML (the tool's own variant — ONE self-contained
/// file: the doctype + the html wrapper, the inline style only, the
/// session block (one `input` entry PER SOURCE) + the summary block
/// (the per-pair verdict lines, one `<pre>` each), one table per
/// clip (the multi table's columns — the `source` column after
/// `file` — NOT the CSV's order), the text properly escaped
/// (`&`/`<`/`>`); deterministic modulo the wall-clock values).
pub fn render_html_multi(r: &JobReportMulti) -> String {
    let mut s = String::new();
    s.push_str("<!doctype html>\n<html>\n<head>\n");
    s.push_str("<meta charset=\"utf-8\">\n");
    s.push_str("<title>frameprism job report</title>\n");
    s.push_str("<style>\n");
    s.push_str("body { font-family: sans-serif; margin: 2em; color: #111; }\n");
    s.push_str("table { border-collapse: collapse; margin: 0.5em 0 1.5em; }\n");
    s.push_str("th, td { border: 1px solid #888; padding: 2px 10px; text-align: left; }\n");
    s.push_str("pre { background: #f4f4f4; padding: 8px; overflow-x: auto; }\n");
    s.push_str("h1 { border-bottom: 2px solid #888; padding-bottom: 4px; }\n");
    s.push_str("</style>\n</head>\n<body>\n");
    s.push_str("<h1>frameprism job report</h1>\n");
    s.push_str("<dl>\n");
    for in_ in &r.inputs {
        s.push_str(&format!("<dt>input</dt><dd>{}</dd>\n", html_escape(in_)));
    }
    s.push_str(&format!("<dt>dest</dt><dd>{}</dd>\n", html_escape(&r.dest)));
    s.push_str(&format!("<dt>created</dt><dd>{} (unix seconds, UTC)</dd>\n", r.created));
    s.push_str(&format!("<dt>tool</dt><dd>{}</dd>\n", html_escape(&r.tool)));
    s.push_str(&format!("<dt>job</dt><dd>{}</dd>\n", html_escape(&r.job)));
    s.push_str("</dl>\n");
    s.push_str("<h2>summary</h2>\n<dl>\n");
    s.push_str(&format!("<dt>files</dt><dd>{}</dd>\n", r.total_files));
    s.push_str(&format!("<dt>size</dt><dd>{} B</dd>\n", r.total_size));
    s.push_str(&format!("<dt>duration</dt><dd>{:.1} s</dd>\n", r.run_seconds));
    s.push_str("</dl>\n");
    for v in &r.verdicts {
        s.push_str(&format!("<pre>{}</pre>\n", html_escape(v)));
    }
    for c in &r.clips {
        s.push_str(&format!(
            "<h2>{}</h2>\n",
            html_escape(&crate::worker::display_clip(&c.key))
        ));
        s.push_str(&format!("<p>{}</p>\n", html_escape(&c.detection)));
        s.push_str(&format!("<p>files: {}</p>\n", c.files));
        s.push_str(&format!("<p>size: {} B</p>\n", c.size));
        s.push_str(&format!("<p>duration: {} ms</p>\n", c.duration_ms));
        s.push_str("<table>\n<tr>");
        for h in HTML_TABLE_HEADER_MULTI.split(',') {
            s.push_str(&format!("<th>{h}</th>"));
        }
        s.push_str("</tr>\n");
        for f in &c.rows {
            s.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                html_escape(&c.key),
                html_escape(&f.file),
                html_escape(&f.source),
                f.size,
                html_escape(&f.source_sha),
                html_escape(&f.dest_sha),
                html_escape(&f.verdict),
                if f.skipped { "yes" } else { "no" },
                f.copied_ms
            ));
        }
        s.push_str("</table>\n");
    }
    s.push_str("</body>\n</html>\n");
    s
}

/// Write the multi-shape job report's three files at the dest root
/// (the save-with-job placement — the dest-root report
/// pattern — the legacy `write` untouched). A write failure is the
/// named hard-error band (the record, not the gate: the per-clip
/// manifests + the run report already stand). The durability seam:
/// each file's bytes are filesystem-synchronized
/// (`sync_file`) after its write (a sync failure = the same named
/// hard-error band) + the dest root's best-effort dir sync after the
/// three.
pub fn write_multi(dest_root: &Path, report: &JobReportMulti) -> Result<PathBuf> {
    let md = render_md_multi(report);
    let csv = render_csv_multi(report);
    let html = render_html_multi(report);
    for (name, body) in [(MD_NAME, &md), (CSV_NAME, &csv), (HTML_NAME, &html)] {
        let path = dest_root.join(name);
        std::fs::write(&path, body)
            .with_context(|| format!("write the job report file {}", path.display()))?;
        // The durability seam: the report file's bytes are
        // filesystem-synchronized (a sync failure = the named
        // hard-error band).
        crate::durability::sync_file(&path, "job report file")?;
    }
    // The best-effort dir sync of the dest root (the records'
    // dir-entry updates — the pinned note on failure, the records
    // stand).
    crate::durability::sync_dir_best_effort(dest_root);
    Ok(dest_root.join(MD_NAME))
}

/// The job identifier's UTC timestamp (the v1 job line — the
/// manual's Job Identifier: the run's identity + date/time stamp):
/// the ISO-8601 form `YYYY-MM-DDTHH:MM:SSZ` (std-only — the
/// civil-from-days arithmetic over the unix seconds, no datetime
/// crate).
pub fn utc_timestamp(unix: u64) -> String {
    let (y, mo, d) = civil_from_days((unix / 86_400) as i64);
    let secs_of_day = unix % 86_400;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        mo,
        d,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// The civil calendar date of a unix-day count (the Howard Hinnant
/// civil-from-days algorithm — the std-only half of the UTC
/// timestamp).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pure emitters over a hand-built report (no FS, no wall
    /// clock beyond the given `created` — the emitter-level contract:
    /// the CSV's plain header + the RFC-4180 quoting, the HTML's
    /// escaping, the UTC timestamp's known values).
    fn fixture() -> JobReport {
        JobReport {
            input: "/in".into(),
            dest: "/out".into(),
            created: 1_758_000_000,
            job: utc_timestamp(1_758_000_000),
            tool: "frameprism 0.2.0".into(),
            total_files: 3,
            total_size: 42,
            run_seconds: 0.4,
            verdict: "offload: VERIFIED 3/3 (dest /out)".into(),
            clips: vec![
                JobClip {
                    key: "C1".into(),
                    detection: "non-DNG media".into(),
                    files: 2,
                    size: 40,
                    duration_ms: 5,
                    rows: vec![
                        JobFile {
                            file: "C1/a.DNG".into(),
                            size: 40,
                            source_sha: "s1".into(),
                            dest_sha: "s1".into(),
                            verdict: "OK".into(),
                            skipped: true,
                            copied_ms: 3,
                        },
                        JobFile {
                            file: "C1/b.wav".into(),
                            size: 0,
                            source_sha: "s2".into(),
                            dest_sha: "s2".into(),
                            verdict: "OK".into(),
                            skipped: false,
                            copied_ms: 2,
                        },
                    ],
                },
                JobClip {
                    key: "".into(),
                    detection: "non-DNG media".into(),
                    files: 1,
                    size: 2,
                    duration_ms: 1,
                    rows: vec![JobFile {
                        file: "r.wav".into(),
                        size: 2,
                        source_sha: "s3".into(),
                        dest_sha: "s3".into(),
                        verdict: "OK".into(),
                        skipped: false,
                        copied_ms: 1,
                    }],
                },
            ],
        }
    }

    #[test]
    fn jobreport_emitters_the_pinned_contract() {
        let r = fixture();
        // The CSV (the plain form — the header first, NO comment
        // magic; the row order = per clip, the detection order; the
        // "" clip cell = the source-root files; the trailing
        // newline).
        let csv = render_csv(&r);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], CSV_HEADER, "the EXACT header row first");
        assert_eq!(
            lines,
            vec![
                CSV_HEADER,
                "C1,C1/a.DNG,40,s1,s1,OK,1,3",
                "C1,C1/b.wav,0,s2,s2,OK,0,2",
                ",r.wav,2,s3,s3,OK,0,1",
            ],
            "one row per file, the deterministic row order"
        );
        assert!(csv.ends_with('\n'), "the trailing newline");
        // RFC-4180-minimal quoting: the comma / quote / newline cases
        // (the doubling of the embedded quote).
        assert_eq!(csv_field("a"), "a", "plain: unquoted");
        assert_eq!(csv_field("a,b"), "\"a,b\"", "the comma: quoted");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"", "the quote: doubled");
        assert_eq!(csv_field("a\nb"), "\"a\nb\"", "the newline: quoted");
        // The HTML (ONE self-contained file — the doctype, the
        // escaping, the header row = the CSV's column names, the
        // verdict in the <pre>).
        let html = render_html(&r);
        assert!(html.starts_with("<!doctype html>\n<html>"), "the doctype + the wrapper");
        assert!(html.ends_with("</html>\n"), "the closed file");
        assert!(html.contains("<style>"), "the inline style only");
        assert!(
            !html.contains("http://") && !html.contains("https://"),
            "zero external resources"
        );
        assert!(
            !html.contains("script"),
            "zero JavaScript"
        );
        assert!(html.contains("<th>clip</th><th>file</th><th>size_bytes</th><th>source_sha256</th><th>dest_sha256</th><th>verdict</th><th>skipped</th><th>copied_ms</th>"), "the header row = the CSV's column names");
        assert!(html.contains("<pre>offload: VERIFIED 3/3 (dest /out)</pre>"), "the verdict line in the <pre>");
        // The escaping (`&`/`<`/`>`).
        assert_eq!(html_escape("a&b<c>d"), "a&amp;b&lt;c&gt;d");
        assert_eq!(html_escape("plain"), "plain");
        // The md (the title, the labeled session
        // lines, the summary + the per-clip sections, the code-span
        // file names, the VERBATIM lines).
        let md = render_md(&r);
        assert!(md.starts_with("# frameprism job report\n\n"), "the title");
        assert!(md.contains("input: /in\n"), "the labeled session lines");
        assert!(md.contains("created: 1758000000 (unix seconds, UTC)\n"), "the created by format");
        assert!(md.contains("job: "), "the job identifier line");
        assert!(md.contains("## summary\n"), "the summary section");
        assert!(md.contains("duration: 0.4 s\n"), "the run duration (1-decimal)");
        assert!(md.contains("offload: VERIFIED 3/3 (dest /out)\n"), "the verdict line verbatim");
        assert!(md.contains("## C1\n"), "the per-clip section");
        assert!(md.contains("non-DNG media\n"), "the detection line verbatim");
        assert!(md.contains("| `C1/a.DNG` | 40 | s1 | s1 | OK | yes | 3 |\n"), "the code-span file name");
        assert!(md.contains("duration: 5 ms\n"), "the per-clip duration");
        // The UTC timestamp (the known values — the epoch + the
        // fixture's stamp + a leap-day boundary).
        assert_eq!(utc_timestamp(0), "1970-01-01T00:00:00Z", "the epoch");
        assert_eq!(utc_timestamp(1_758_000_000), "2025-09-16T05:20:00Z", "the fixture's stamp");
        assert_eq!(utc_timestamp(1_582_934_400), "2020-02-29T00:00:00Z", "the leap day");
    }

    /// The skipped column's pin (the duplicate detection,
    /// the surface pin): the CSV header row EXACTLY the new
    /// pinned string (`skipped` inserted immediately before
    /// `copied_ms`); a skip row's cell `1`, a copy row's cell `0`;
    /// the md table's `yes`/`no`; the HTML cell follows the md.
    #[test]
    fn jobreport_skipped_column_pin() {
        let r = fixture();
        // The CSV header (the pin MOVED, named
        // — the EXACT pinned string).
        assert_eq!(
            CSV_HEADER,
            "clip,file,size_bytes,source_sha256,dest_sha256,verdict,skipped,copied_ms",
            "the new pinned header"
        );
        let csv = render_csv(&r);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], CSV_HEADER, "the pinned header row first");
        // The skip row's cell `1` + the copy rows' cells `0` (the
        // column = immediately before copied_ms — the cell order).
        let a: Vec<&str> = lines[1].split(',').collect();
        assert_eq!(
            (a.len(), a[6].to_string(), a[7].to_string()),
            (8, "1".into(), "3".into()),
            "the skip row: the `1` cell before the copied_ms cell: {:?}",
            lines[1]
        );
        let b: Vec<&str> = lines[2].split(',').collect();
        assert_eq!(b[6], "0", "the copy row's cell `0` (row 2): {:?}", lines[2]);
        let c: Vec<&str> = lines[3].split(',').collect();
        assert_eq!(c[6], "0", "the copy row's cell `0` (row 3): {:?}", lines[3]);
        // The md table (the `yes`/`no` cells — the column header +
        // the per-row cells).
        let md = render_md(&r);
        assert!(
            md.contains("| file | size | source_sha256 | dest_sha256 | verdict | skipped | copied_ms |\n"),
            "the md table's pinned header: \n{md}"
        );
        assert!(md.contains("| `C1/a.DNG` | 40 | s1 | s1 | OK | yes | 3 |\n"), "the skip row's md cell `yes`: \n{md}");
        assert!(md.contains("| `C1/b.wav` | 0 | s2 | s2 | OK | no | 2 |\n"), "the copy row's md cell `no`: \n{md}");
        assert!(md.contains("| `r.wav` | 2 | s3 | s3 | OK | no | 1 |\n"), "the copy row's md cell `no`: \n{md}");
        // The HTML cell (follows the md: `yes`/`no`) — the row's
        // cell order (clip, file, size, src, dst, verdict, skipped,
        // copied_ms).
        let html = render_html(&r);
        assert!(
            html.contains("<td>C1</td><td>C1/a.DNG</td><td>40</td><td>s1</td><td>s1</td><td>OK</td><td>yes</td><td>3</td></tr>"),
            "the skip row's HTML cell `yes`: \n{html}"
        );
        assert!(
            html.contains("<td>C1</td><td>C1/b.wav</td><td>0</td><td>s2</td><td>s2</td><td>OK</td><td>no</td><td>2</td></tr>"),
            "the copy row's HTML cell `no`: \n{html}"
        );
        // The `skipped` header cell (the header row = the CSV's
        // column names — the pin move rides the HTML header too).
        assert!(html.contains("<th>skipped</th><th>copied_ms</th>"), "the HTML's skipped header cell: \n{html}");
    }
}
