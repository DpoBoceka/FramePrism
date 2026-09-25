//! The append-only ops ledger (the run journal, A3;
//! the media report without the PDF ceremony).
//!
//! One TSV row per COMPLETED run in `~/.frameprism/ledger.tsv` (override:
//! the `FRAMEPRISM_LEDGER` env; the dir is created 0700 if absent): the
//! encode runs (`command = legacy`, j92 + jxl, incl. `--to`), bake,
//! bake --iso — and the completed `audit` runs (`command = audit`,
//! `verdict = OK/FAIL` — the rotation report's input; the decode /
//! restore / proxy / derive verbs are pure reads or derived tiers and
//! append nothing). A write failure is a NAMED warning line, NOT a
//! run failure (the archive completes; the journal degrades loudly).
//! The ledger is OUTSIDE the repo (user state) — never in the byte
//! contracts, never in the oracles — and the `ledger` subcommand is
//! READ-ONLY over it (the writer is the run paths).
//!
//! Row columns (the versioned header `version: 1` / `version: 2` /
//! `version: 3`):
//! created (unix
//! seconds — the ONLY wall-clock column; the log is explicitly
//! non-deterministic by design), command (legacy|bake|bake-iso|audit),
//! tool_version, input (root path), output (root path), codec, frames,
//! verdict (OK | REFUSED_<class> | FAIL), duration_s, dest (the `--to`
//! dir or empty), and — v2 — selection (the run's effective
//! processed set: the sorted comma-joined clip keys; empty = the full
//! set or a run that did not start) + — v3 — context (the
//! run's named context marker: the `--subset` line — the
//! `worker::SUBSET_MARKER` string when the run ran under the named
//! continuity waiver; empty = no marker). Paths are canonicalized at
//! write (the rotation
//! report matches the audit rows' `input` against the bake rows'
//! `output` — the same reel must match regardless of how the operator
//! typed the path).
//!
//! Versioning: the writer writes `version: 3` ONLY for
//! a new file; an existing v1 file gets the ONE-TIME atomic header bump
//! on the first row that carries a selection (to v2) or a context (to
//! v3 — a context row on a v1 file bumps straight to v3); an existing
//! v2 file gets the one-time atomic bump to v3 on the first row that
//! carries a context (the header lines are
//! rewritten to the new version — no row rewrites: the existing 10-/11-
//! column rows stay in place and the reader accepts ALL row shapes in
//! ALL file versions). A full-set + no-context row on a v1/v2 file
//! keeps today's exact bytes (the ledger behavior for a non-selected,
//! non-subset run is unchanged); in a v3 file EVERY row carries the
//! 12-column shape (a default row = today's 11 fields + the trailing
//! EMPTY context field — the shape is per-file). An unknown-version
//! file is a named refused append (the journal degrades loudly).
//!
//! Verdict classes: `OK` = the run completed clean; `FAIL` = the run
//! started and ended non-clean (encode frame failures / dirty offload
//! rows, audit offenders, a mid-run bake failure); `REFUSED_<class>` =
//! a named safety gate refused BEFORE any output (`REFUSED_PIN` the
//! A1 self-check, `REFUSED_SPACE` the A2 preflight guard,
//! `REFUSED_INGEST` the ingest gate). Usage-class rc=2s (a bad input
//! dir, an existing archive without `--force`, the scope guards) are
//! NOT rows — no run started.
//!
//! Reader discipline: a malformed row is a NAMED skip + continue (the
//! log is never fatal to a run, but the reader names its damage).
//! `--since <Ndays>` lists rows from the last N days AND is the
//! rotation window; absent, the list is the full journal and the
//! window is the 90-day default. The rotation report: for every
//! DISTINCT `output` with a completed bake/bake-iso row, the age of
//! its most recent audit row (`input == output`); a reel with no audit
//! row within the window is listed
//! `ROTATE <output>: last audit <age> days ago` (never audited →
//! `last audit never`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The file's versioned header (line 1) — the v1 files (the 10-column
/// rows).
pub const VERSION_LINE: &str = "version: 1";
/// The column header (line 2) of a v1 file — the column order IS the
/// contract.
pub const COLUMN_HEADER: &str =
    "created\tcommand\ttool_version\tinput\toutput\tcodec\tframes\tverdict\tduration_s\tdest";
/// The v2 versioned header (line 1) — the writer writes
/// `version: 2` ONLY for a new file (the existing v1 file gets the
/// one-time atomic bump on the first row that carries a selection —
/// see `append_to`).
pub const VERSION_LINE_V2: &str = "version: 2";
/// The v2 column header (line 2) — v1 + the `selection` column (the
/// run's effective processed set; empty = the full set or a run that
/// did not start).
pub const COLUMN_HEADER_V2: &str =
    "created\tcommand\ttool_version\tinput\toutput\tcodec\tframes\tverdict\tduration_s\tdest\tselection";
/// The v3 versioned header (line 1) — the writer writes
/// `version: 3` ONLY for a new file (the existing v1/v2 files get the
/// one-time atomic bump on the first row that carries a context — see
/// `append_to`).
pub const VERSION_LINE_V3: &str = "version: 3";
/// The v3 column header (line 2) — v2 + the `context` column (the
/// run's named context marker: the `--subset` line —
/// `worker::SUBSET_MARKER` when the run ran under the named continuity
/// waiver; empty = no marker).
pub const COLUMN_HEADER_V3: &str =
    "created\tcommand\ttool_version\tinput\toutput\tcodec\tframes\tverdict\tduration_s\tdest\tselection\tcontext";
/// The rotation default window (N = 90 days).
pub const DEFAULT_ROTATION_DAYS: u64 = 90;
const SECONDS_PER_DAY: u64 = 86_400;

/// One ledger row (the columns of `COLUMN_HEADER_V3` — the v1 rows
/// are the same columns with `selection` + `context` empty; the v2
/// rows carry `context` empty).
#[derive(Clone, Debug)]
pub struct Row {
    pub created: u64,
    pub command: String,
    pub tool_version: String,
    pub input: String,
    pub output: String,
    pub codec: String,
    pub frames: u64,
    pub verdict: String,
    pub duration_s: u64,
    pub dest: String,
    /// The run's effective processed set: the sorted
    /// comma-joined clip keys; empty = the full set or a run that did
    /// not start (the v1 file keeps its 10-column shape for these
    /// rows).
    pub selection: String,
    /// The run's named context marker (the `--subset` line):
    /// `worker::SUBSET_MARKER` when the run ran under the named
    /// continuity waiver, empty otherwise (a v1/v2 file carries no
    /// context column — the reader treats its absence as empty).
    pub context: String,
}

impl Row {
    /// The TSV line (v1 — the 10 columns of `COLUMN_HEADER`; the
    /// `selection` column must be empty — the v1 file stays v1 for a
    /// full-set run).
    pub fn line(&self) -> String {
        debug_assert!(
            self.selection.is_empty(),
            "a v1 row has an empty selection column"
        );
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.created,
            self.command,
            self.tool_version,
            self.input,
            self.output,
            self.codec,
            self.frames,
            self.verdict,
            self.duration_s,
            self.dest
        )
    }

    /// The TSV line (v2 — the 11 columns of `COLUMN_HEADER_V2`; an
    /// empty selection = the full-set row in a v2 file: today's 10
    /// columns + the trailing empty field).
    pub fn line_v2(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.created,
            self.command,
            self.tool_version,
            self.input,
            self.output,
            self.codec,
            self.frames,
            self.verdict,
            self.duration_s,
            self.dest,
            self.selection
        )
    }

    /// The TSV line (v3 — the 12 columns of `COLUMN_HEADER_V3`; a
    /// default (flag-absent) row keeps today's 11-field shape + the
    /// trailing EMPTY context field — the shape is per-file: a v3
    /// header ⇒ every row carries the 12-column form).
    pub fn line_v3(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.created,
            self.command,
            self.tool_version,
            self.input,
            self.output,
            self.codec,
            self.frames,
            self.verdict,
            self.duration_s,
            self.dest,
            self.selection,
            self.context
        )
    }

    /// One JSON object (the `--json` line — the columns, in order —
    /// incl. the v2 `selection` + the v3 `context` columns).
    pub fn json(&self) -> String {
        let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            "{{\"created\":{},\"command\":\"{}\",\"tool_version\":\"{}\",\"input\":\"{}\",\"output\":\"{}\",\"codec\":\"{}\",\"frames\":{},\"verdict\":\"{}\",\"duration_s\":{},\"dest\":\"{}\",\"selection\":\"{}\",\"context\":\"{}\"}}",
            self.created,
            esc(&self.command),
            esc(&self.tool_version),
            esc(&self.input),
            esc(&self.output),
            esc(&self.codec),
            self.frames,
            esc(&self.verdict),
            self.duration_s,
            esc(&self.dest),
            esc(&self.selection),
            esc(&self.context)
        )
    }
}

/// The ledger path: `FRAMEPRISM_LEDGER` override, else
/// `~/.frameprism/ledger.tsv`.
pub fn ledger_path() -> PathBuf {
    if let Ok(p) = std::env::var("FRAMEPRISM_LEDGER") {
        return PathBuf::from(p);
    }
    match std::env::var_os("HOME") {
        Some(h) if !h.is_empty() => PathBuf::from(h).join(".frameprism/ledger.tsv"),
        _ => PathBuf::from(".frameprism/ledger.tsv"),
    }
}

/// The unix-seconds clock (the row's `created` — the only wall-clock
/// column).
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Canonicalize for the record (a moved/renamed input path must not
/// break the rotation match); the given string on failure.
pub fn canon(p: &Path) -> String {
    std::fs::canonicalize(p)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_else(|_| p.to_string_lossy().into_owned())
}

#[cfg(unix)]
fn set_dir_0700(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(
        p,
        std::fs::Permissions::from_mode(0o700),
    );
}

/// Append one row to `path` (creates the dir 0700 + the versioned
/// header when the file is absent/empty — a NEW file gets the v3
/// header; the versioning of an EXISTING file follows the
/// one-time-bump rule: a v1 file stays v1 for a no-selection +
/// no-context row — today's exact 10-column bytes — and gets its
/// header lines atomically bumped on the first row that carries a
/// selection (to v2) or a context (to v3 — a context row on a v1 file
/// bumps straight to v3); a v2 file gets the one-time bump to v3 on
/// the first row that carries a context (a no-context row stays
/// 11-column + the v2 header). In a v3 file EVERY row carries the
/// 12-column shape (a default row = today's 11 fields + the trailing
/// EMPTY context field — the shape is per-file). No row rewrites: the
/// existing 10-/11-column rows stay in place (the reader accepts ALL
/// row shapes in ALL file versions); an unknown-version file is a
/// named refused append).
pub fn append_to(path: &Path, row: &Row) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create the ledger dir {}: {e}", parent.display()))?;
            set_dir_0700(parent);
        }
    }
    let (existing, text) = match std::fs::read_to_string(path) {
        Ok(t) => (true, t),
        Err(_) => (false, String::new()),
    };
    let fresh = !existing || text.is_empty();
    let mut buf = String::new();
    if fresh {
        buf.push_str(VERSION_LINE_V3);
        buf.push('\n');
        buf.push_str(COLUMN_HEADER_V3);
        buf.push('\n');
        buf.push_str(&row.line_v3());
        buf.push('\n');
        use std::io::Write;
        return std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("open the ledger {}: {e}", path.display()))?
            .write_all(buf.as_bytes())
            .map_err(|e| format!("append to the ledger {}: {e}", path.display()));
    }
    let lines: Vec<&str> = text.lines().collect();
    let first = lines.first().copied().unwrap_or("");
    if first == VERSION_LINE_V3 {
        // The v3 file: EVERY row carries the 12-column shape (a
        // default row = today's 11 fields + the trailing EMPTY context
        // field — the shape is per-file). A torn last line (no
        // trailing newline) is repaired in the SAME write (atomicity).
        if !text.ends_with('\n') {
            buf.push('\n');
        }
        buf.push_str(&row.line_v3());
        buf.push('\n');
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("open the ledger {}: {e}", path.display()))?
            .write_all(buf.as_bytes())
            .map_err(|e| format!("append to the ledger {}: {e}", path.display()))?;
        return Ok(());
    }
    if first == VERSION_LINE_V2 {
        if row.context.is_empty() {
            // A no-context row on a v2 file: today's exact 11-column
            // bytes (the header is untouched — the file stays v2). A
            // torn last line is repaired in the SAME write (atomicity).
            if !text.ends_with('\n') {
                buf.push('\n');
            }
            buf.push_str(&row.line_v2());
            buf.push('\n');
            use std::io::Write;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("open the ledger {}: {e}", path.display()))?
                .write_all(buf.as_bytes())
                .map_err(|e| format!("append to the ledger {}: {e}", path.display()))?;
            return Ok(());
        }
        // The ONE-TIME atomic header bump to v3: the first
        // context-bearing row rewrites the v2 header lines to v3 (no
        // row rewrites — the existing 10-/11-column rows stay in
        // place), then the 12-column row is appended.
        if lines.len() < 2 || lines[1] != COLUMN_HEADER_V2 {
            return Err(format!(
                "unexpected v2 ledger header (line 2 of {} is not the v2 column header) — the bump is refused, the file is not rewritten",
                path.display()
            ));
        }
        return bump_header_v3(path, &lines, row);
    }
    if first == VERSION_LINE {
        if row.context.is_empty() && row.selection.is_empty() {
            // A no-selection + no-context row on a v1 file: today's
            // exact bytes (the 10-column row; the header is untouched —
            // the file stays v1). A torn last line is repaired in the
            // same write.
            if !text.ends_with('\n') {
                buf.push('\n');
            }
            buf.push_str(&row.line());
            buf.push('\n');
            use std::io::Write;
            return std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("open the ledger {}: {e}", path.display()))?
                .write_all(buf.as_bytes())
                .map_err(|e| format!("append to the ledger {}: {e}", path.display()));
        }
        if row.context.is_empty() {
            // The ONE-TIME atomic header bump: the v1 header
            // lines are rewritten to v2 (the data rows are NOT
            // rewritten — the existing 10-column rows stay in place),
            // then the 11-column row is appended. The rewrite is
            // atomic (tmp + rename) so the journal is never left torn.
            if lines.len() < 2 || lines[1] != COLUMN_HEADER {
                return Err(format!(
                    "unexpected v1 ledger header (line 2 of {} is not the v1 column header) — the bump is refused, the file is not rewritten",
                    path.display()
                ));
            }
            buf.push_str(VERSION_LINE_V2);
            buf.push('\n');
            buf.push_str(COLUMN_HEADER_V2);
            buf.push('\n');
            for l in lines.iter().skip(2) {
                if l.trim().is_empty() {
                    continue;
                }
                buf.push_str(l);
                buf.push('\n');
            }
            buf.push_str(&row.line_v2());
            buf.push('\n');
            let tmp = path.with_file_name(format!("{}.ledger-tmp", path.file_name().and_then(|s| s.to_str()).unwrap_or("ledger")));
            std::fs::write(&tmp, &buf)
                .map_err(|e| format!("write the ledger tmp {}: {e}", tmp.display()))?;
            std::fs::rename(&tmp, path)
                .map_err(|e| format!("rename the ledger tmp {} -> {}: {e}", tmp.display(), path.display()))?;
            return Ok(());
        }
        // A context row on a v1 file: the ONE-TIME atomic bump goes
        // STRAIGHT to v3 (the v3 header — the context column is the
        // run of record; the existing 10-column rows stay in place,
        // the reader accepts all row shapes).
        if lines.len() < 2 || lines[1] != COLUMN_HEADER {
            return Err(format!(
                "unexpected v1 ledger header (line 2 of {} is not the v1 column header) — the bump is refused, the file is not rewritten",
                path.display()
            ));
        }
        return bump_header_v3(path, &lines, row);
    }
    if first.starts_with("version: ") && first != VERSION_LINE_V2 && first != VERSION_LINE {
        // A recognized version marker with an unknown version: the
        // file's layout is untrustable — the named refused append
        // (the journal degrades loudly; the reader names the same
        // file and reads no rows from it).
        return Err(format!(
            "unknown ledger version in {} (line 1 is {first:?}) — the append is refused, the file is not touched",
            path.display()
        ));
    }
    // No recognized version header (a malformed/foreign file): the
    // row is appended in its natural shape (the reader names the
    // damaged file — the append is the loud degradation, not a
    // silent rewrite).
    buf.push_str(&if row.context.is_empty() {
        if row.selection.is_empty() {
            row.line()
        } else {
            row.line_v2()
        }
    } else {
        row.line_v3()
    });
    buf.push('\n');
    use std::io::Write;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open the ledger {}: {e}", path.display()))?
        .write_all(buf.as_bytes())
        .map_err(|e| format!("append to the ledger {}: {e}", path.display()))
}

/// The ONE-TIME atomic header bump to v3 (the v2→v3 and
/// v1→v3 rewrites): rewrites the file's header lines to the v3 header
/// (the data rows are NOT rewritten — the existing 10-/11-column rows
/// stay in place; the reader accepts ALL row shapes in ALL file
/// versions), then appends the 12-column row. The rewrite is atomic
/// (tmp + rename) so the journal is never left torn. `lines` = the
/// current file's lines (line 1 = the version marker, line 2 = the
/// old column header).
fn bump_header_v3(path: &Path, lines: &[&str], row: &Row) -> Result<(), String> {
    let mut buf = String::new();
    buf.push_str(VERSION_LINE_V3);
    buf.push('\n');
    buf.push_str(COLUMN_HEADER_V3);
    buf.push('\n');
    for l in lines.iter().skip(2) {
        if l.trim().is_empty() {
            continue;
        }
        buf.push_str(l);
        buf.push('\n');
    }
    buf.push_str(&row.line_v3());
    buf.push('\n');
    let tmp = path.with_file_name(format!("{}.ledger-tmp", path.file_name().and_then(|s| s.to_str()).unwrap_or("ledger")));
    std::fs::write(&tmp, &buf)
        .map_err(|e| format!("write the ledger tmp {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("rename the ledger tmp {} -> {}: {e}", tmp.display(), path.display()))?;
    Ok(())
}

/// Append one row to the ledger path (the run paths call this).
pub fn append(row: &Row) -> Result<(), String> {
    append_to(&ledger_path(), row)
}

/// Append one row; a write failure is the NAMED warning line, NOT a
/// run failure (the archive completes; the journal degrades loudly).
pub fn append_quiet(row: &Row) {
    if let Err(e) = append(row) {
        eprintln!(
            "WARN ledger: {e} — the run completes; the journal degrades loudly (the archive is not affected)"
        );
    }
}

/// Read the ledger (the reader discipline): `rows` (in file order —
/// newest last) + `warnings` (the named damage: an unknown version, an
/// unexpected header, a malformed row — each names its line).
pub fn read(path: &Path) -> (Vec<Row>, Vec<String>) {
    let mut rows = Vec::new();
    let mut warnings = Vec::new();
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(err) => {
            warnings.push(format!("unreadable ledger {}: {err}", path.display()));
            return (rows, warnings);
        }
    };
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return (rows, warnings);
    }
    // Line 1: the versioned header. An unknown version = the layout
    // is untrustable: named, and the data rows are not read.
    let first = lines[0];
    // v1 or v2 or v3 (the writer writes `version: 3` for new
    // files; the existing v1/v2 files get the one-time bump — the
    // reader accepts ALL versions, and ALL row shapes (10 columns = a
    // v1 row, selection + context empty; 11 columns = the v2 row,
    // context empty; 12 columns = the v3 row) in ALL file versions —
    // a bumped file legally carries the pre-bump rows).
    let (is_v2, is_v3) = match first.strip_prefix("version: ") {
        Some(v) if v.trim() == "1" => (false, false),
        Some(v) if v.trim() == "2" => (true, false),
        Some(v) if v.trim() == "3" => (false, true),
        Some(v) => {
            warnings.push(format!(
                "unknown ledger version {v:?} (line 1; this tool writes version: 1, version: 2, or version: 3) — the rows are not read"
            ));
            return (rows, warnings);
        }
        None => {
            warnings.push(format!(
                "no version header (line 1 of {} is {:?}; expected `version: 1`, `version: 2`, or `version: 3`) — the rows are not read",
                path.display(),
                first
            ));
            return (rows, warnings);
        }
    };
    // Line 2: the column header (skipped; a different one is named).
    let mut start = 1;
    if start < lines.len() {
        let expect = if is_v3 {
            COLUMN_HEADER_V3
        } else if is_v2 {
            COLUMN_HEADER_V2
        } else {
            COLUMN_HEADER
        };
        if lines[start] != expect {
            warnings.push(format!(
                "unexpected column header (line {}): {:?} — the line is skipped",
                start + 1,
                lines[start]
            ));
        }
        start += 1;
    }
    for (i, line) in lines.iter().enumerate().skip(start) {
        if line.trim().is_empty() {
            continue;
        }
        let n = i + 1; // the 1-based line number (the named skip)
        let cols: Vec<&str> = line.split('\t').collect();
        let (selection, context) = match cols.len() {
            10 => (String::new(), String::new()),
            11 => (cols[10].to_string(), String::new()),
            12 => (cols[10].to_string(), cols[11].to_string()),
            len => {
                warnings.push(format!(
                    "line {n} malformed ({} column(s), expected 10, 11, or 12) — skipped",
                    len
                ));
                continue;
            }
        };
        match (
            cols[0].parse::<u64>(),
            cols[6].parse::<u64>(),
            cols[8].parse::<u64>(),
        ) {
            (Ok(created), Ok(frames), Ok(duration_s)) => rows.push(Row {
                created,
                command: cols[1].to_string(),
                tool_version: cols[2].to_string(),
                input: cols[3].to_string(),
                output: cols[4].to_string(),
                codec: cols[5].to_string(),
                frames,
                verdict: cols[7].to_string(),
                duration_s,
                dest: cols[9].to_string(),
                selection,
                context,
            }),
            (created, frames, duration) => {
                let which: Vec<String> = [
                    (created.is_err(), "created"),
                    (frames.is_err(), "frames"),
                    (duration.is_err(), "duration_s"),
                ]
                .iter()
                .filter(|(bad, _)| *bad)
                .map(|(_, which)| which.to_string())
                .collect();
                let which = which.join(" + ");
                warnings.push(format!(
                    "line {n} malformed (bad {which}) — skipped"
                ));
            }
        }
    }
    (rows, warnings)
}

/// The rotation report (the exact line shape): the
/// `ROTATE` lines + the reel count. A reel = a DISTINCT `output` with
/// a COMPLETED (`verdict = OK`) bake/bake-iso row; its audit rows are
/// the `audit` rows with `input == output`. Needs rotation = no audit
/// row, or the most recent one older than `window_days`.
pub fn rotation_report(rows: &[Row], window_days: u64, now: u64) -> (Vec<String>, usize) {
    let mut reels: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for r in rows {
        if (r.command == "bake" || r.command == "bake-iso") && r.verdict == "OK" {
            reels.insert(r.output.clone());
        }
    }
    let n_reels = reels.len();
    let mut out = Vec::new();
    for reel in &reels {
        let audits: Vec<u64> = rows
            .iter()
            .filter(|r| r.command == "audit" && &r.input == reel)
            .map(|r| r.created)
            .collect();
        match audits.iter().max() {
            None => out.push(format!("ROTATE {reel}: last audit never")),
            Some(&last) => {
                let age = now.saturating_sub(last) / SECONDS_PER_DAY;
                if age > window_days {
                    out.push(format!("ROTATE {reel}: last audit {age} days ago"));
                }
            }
        }
    }
    (out, n_reels)
}

/// The `frameprism ledger [--since <Ndays>] [--json]` subcommand
/// (read-only over the journal). rc=0 always (the reader is never
/// fatal — its damage is named, on stderr).
pub fn run(since: Option<u64>, json: bool) -> ExitCode {
    let path = ledger_path();
    if !path.exists() {
        println!(
            "ledger: not found at {} (no rows yet — the run paths are the writer)",
            path.display()
        );
        return ExitCode::SUCCESS;
    }
    let (rows, warnings) = read(&path);
    for w in &warnings {
        eprintln!("WARN ledger: {w}");
    }
    let now = now_secs();
    let window = since.unwrap_or(DEFAULT_ROTATION_DAYS);
    let listed: Vec<&Row> = match since {
        Some(n) => {
            let cutoff = now.saturating_sub(n * SECONDS_PER_DAY);
            rows.iter().filter(|r| r.created >= cutoff).collect()
        }
        None => rows.iter().collect(),
    };
    let (rotate, n_reels) = rotation_report(&rows, window, now);
    if json {
        for r in &listed {
            println!("{}", r.json());
        }
        eprintln!(
            "rotation (audit within {window} days): {n_reels} reel output(s) with a completed bake/bake-iso row"
        );
        for line in &rotate {
            eprintln!("{line}");
        }
        return ExitCode::SUCCESS;
    }
    let tail = if warnings.is_empty() {
        String::new()
    } else {
        format!(", {} named row(s) skipped", warnings.len())
    };
    println!(
        "ledger: {} ({} row(s) of {}{tail} — newest last)",
        path.display(),
        listed.len(),
        rows.len()
    );
    for r in &listed {
        // The v2 `selection` column + the v3 `context` column
        // (additive): a full-set / no-marker row keeps today's exact
        // line shape (no trailing fields).
        let sel_field = if r.selection.is_empty() {
            String::new()
        } else {
            format!("\tsel={}", r.selection)
        };
        let ctx_field = if r.context.is_empty() {
            String::new()
        } else {
            format!("\tcontext={}", r.context)
        };
        println!(
            "{}\t{}\t{}\t{}\tframes={}\t{}s\tin={}\tout={}\tdest={}{}{}",
            r.created,
            r.command,
            r.codec,
            r.verdict,
            r.frames,
            r.duration_s,
            r.input,
            r.output,
            if r.dest.is_empty() { "-" } else { r.dest.as_str() },
            sel_field,
            ctx_field
        );
    }
    println!();
    println!(
        "rotation (audit within {window} days): {n_reels} reel output(s) with a completed bake/bake-iso row"
    );
    if n_reels == 0 {
        println!("rotation: no baked reel outputs recorded");
    } else if rotate.is_empty() {
        println!("rotation: clean — every baked reel output has an audit row within {window} days");
    } else {
        for line in &rotate {
            println!("{line}");
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        created: u64,
        command: &str,
        input: &str,
        output: &str,
        verdict: &str,
    ) -> Row {
        Row {
            created,
            command: command.into(),
            tool_version: "0.4.0".into(),
            input: input.into(),
            output: output.into(),
            codec: "j92".into(),
            frames: 72,
            verdict: verdict.into(),
            duration_s: 10,
            dest: String::new(),
            selection: String::new(),
            context: String::new(),
        }
    }

    #[test]
    fn append_writes_v3_header_and_roundtrips() {
        let tmp = std::env::temp_dir().join("frameprism_ledger_append_test");
        let _ = std::fs::remove_dir_all(&tmp);
        let p = tmp.join("sub/ledger.tsv");
        let a = row(1_000, "legacy", "/in", "/out", "OK");
        let mut b = row(2_000, "bake", "/out-clip", "/out", "OK");
        b.selection = "A001_001,A001_006".into();
        append_to(&p, &a).unwrap();
        append_to(&p, &b).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // A NEW file gets the v3 header (the writer writes
        // version: 3 for a new file) — in a v3 file EVERY row carries
        // the 12-column shape (the default row = today's 11 fields +
        // the trailing EMPTY context field — the shape is per-file).
        assert_eq!(lines[0], VERSION_LINE_V3);
        assert_eq!(lines[1], COLUMN_HEADER_V3);
        assert_eq!(lines[2], a.line_v3());
        assert_eq!(lines[3], b.line_v3());
        // The extra pin: a default (flag-absent) row in a v3 file
        // keeps today's 11-field shape + the context field EMPTY (not
        // omitted).
        assert_eq!(a.line_v3(), a.line_v2() + "\t");
        let (rows, warnings) = read(&p);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].verdict, "OK");
        assert_eq!(rows[0].selection, "");
        assert_eq!(rows[0].context, "");
        assert_eq!(rows[1].command, "bake");
        assert_eq!(rows[1].selection, "A001_001,A001_006");
        assert_eq!(rows[1].context, "");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn v2_file_context_row_bumps_header_once() {
        // a v2 file + a context-bearing row — the ONE-TIME
        // atomic bump to v3: the header lines are
        // rewritten to v3, the existing 11-column row stays BYTE-
        // STABLE, the new row is the 12-column shape + the marker. A
        // LATER default row is appended as the 12-column shape with
        // the context field EMPTY (the shape is per-file: v3 header ⇒
        // every row 12 columns). No second rewrite (the prefix stays
        // byte-stable).
        let tmp = std::env::temp_dir().join("frameprism_ledger_v3_bump_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("ledger.tsv");
        let old_row = "1000\tlegacy\t0.4.0\t/in\t/out\tj92\t72\tOK\t10\t\t";
        std::fs::write(&p, format!("{VERSION_LINE_V2}\n{COLUMN_HEADER_V2}\n{old_row}\n")).unwrap();
        // A no-context row on a v2 file: the 11-column shape, the
        // header untouched (the file stays v2).
        let plain = row(1_200, "legacy", "/in", "/out", "OK");
        append_to(&p, &plain).unwrap();
        let after_plain = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<&str> = after_plain.lines().collect();
        assert_eq!(lines[0], VERSION_LINE_V2, "a no-context row does not bump");
        assert_eq!(lines[3], plain.line_v2());
        // The FIRST context-bearing row: the one-time atomic bump.
        let mut ctx = row(1_500, "legacy", "/in", "/out", "OK");
        ctx.context = crate::worker::SUBSET_MARKER.into();
        append_to(&p, &ctx).unwrap();
        let after_bump = std::fs::read_to_string(&p).unwrap();
        lines = after_bump.lines().collect();
        assert_eq!(lines[0], VERSION_LINE_V3);
        assert_eq!(lines[1], COLUMN_HEADER_V3);
        assert_eq!(lines[2], old_row, "the v2 row is NOT rewritten");
        assert_eq!(lines[3], plain.line_v2(), "the v2 row is NOT rewritten (second)");
        assert_eq!(lines[4], ctx.line_v3());
        // The LATER default row: no second rewrite — the prefix is
        // byte-stable; the row keeps the 12-column shape + the EMPTY
        // context field (the per-file shape pin).
        let full = row(2_000, "legacy", "/in", "/out", "OK");
        append_to(&p, &full).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with(&after_bump), "the bumped prefix must be byte-stable");
        lines = text.lines().collect();
        assert_eq!(lines[5], full.line_v3());
        assert_eq!(full.line_v3(), full.line_v2() + "\t");
        // The reader accepts the bumped file (all row shapes).
        let (rows, warnings) = read(&p);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].context, "");
        assert_eq!(rows[1].context, "");
        assert_eq!(rows[2].context, crate::worker::SUBSET_MARKER);
        assert_eq!(rows[3].context, "");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn v1_file_context_row_bumps_straight_to_v3() {
        // a context row on a v1 file bumps STRAIGHT to v3 (the
        // v3 header is the run of record — the context column is
        // present); the existing 10-column row stays byte-stable. A
        // no-selection + no-context row on a v1 file keeps today's
        // exact 10-column bytes (the file stays v1).
        let tmp = std::env::temp_dir().join("frameprism_ledger_v3_from_v1_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("ledger.tsv");
        let old_row = "1000\tlegacy\t0.4.0\t/in\t/out\tj92\t72\tOK\t10\t";
        std::fs::write(&p, format!("{VERSION_LINE}\n{COLUMN_HEADER}\n{old_row}\n")).unwrap();
        // The no-selection + no-context row: the file stays v1.
        let plain = row(1_200, "legacy", "/in", "/out", "OK");
        append_to(&p, &plain).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], VERSION_LINE, "a no-marker row does not bump");
        assert_eq!(lines[2], old_row);
        assert_eq!(lines[3], plain.line());
        // The context row: the one-time atomic bump straight to v3.
        let mut ctx = row(1_500, "legacy", "/in", "/out", "OK");
        ctx.context = crate::worker::SUBSET_MARKER.into();
        append_to(&p, &ctx).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], VERSION_LINE_V3);
        assert_eq!(lines[1], COLUMN_HEADER_V3);
        assert_eq!(lines[2], old_row, "the v1 row is NOT rewritten");
        assert_eq!(lines[3], plain.line(), "the v1 row is NOT rewritten (second)");
        assert_eq!(lines[4], ctx.line_v3());
        let (rows, warnings) = read(&p);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[2].context, crate::worker::SUBSET_MARKER);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn reader_accepts_v3_mixed_row_shapes() {
        // a hand-assembled v3 file with ALL row shapes (a
        // pre-bump 10-column row, a pre-bump 11-column row, and the
        // 12-column row) — all parse (the reader accepts 10/11/12
        // columns in ALL file versions); a 9-column row is named.
        let tmp = std::env::temp_dir().join("frameprism_ledger_v3_mixed_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("ledger.tsv");
        std::fs::write(
            &p,
            format!(
                "{VERSION_LINE_V3}\n{COLUMN_HEADER_V3}\n1000\tlegacy\t0.4.0\t/in\t/out\tj92\t72\tOK\t10\t\n2000\tlegacy\t0.4.0\t/in\t/out\tj92\t72\tOK\t10\t\tA001_001,A001_006\n3000\tlegacy\t0.4.0\t/in\t/out\tj92\t72\tOK\t10\t\t\t{marker}\n4000\tlegacy\t0.4.0\t/in\t/out\tj92\t72\tOK\n",
                marker = crate::worker::SUBSET_MARKER
            ),
        )
        .unwrap();
        let (rows, warnings) = read(&p);
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert_eq!(rows[0].context, ""); // the 10-column row
        assert_eq!(rows[1].context, ""); // the 11-column row
        assert_eq!(rows[1].selection, "A001_001,A001_006");
        assert_eq!(rows[2].context, crate::worker::SUBSET_MARKER); // the 12-column row
        assert!(
            warnings.iter().any(|w| w.contains("line 6 malformed") && w.contains("column(s)")),
            "{warnings:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn json_line_carries_context_escaped() {
        // the --json line carries the v3 `context` column
        // (escaped, in order — after `selection`).
        let mut r = row(1_700_000_000, "legacy", "/in", "/out", "OK");
        r.selection = "A001_001".into();
        r.context = crate::worker::SUBSET_MARKER.into();
        let j = r.json();
        assert!(
            j.ends_with(&format!(r#""selection":"A001_001","context":"{}"}}"#, crate::worker::SUBSET_MARKER)),
            "{j:?}"
        );
        // A default row: the column is present + empty (the reader /
        // consumer sees the shape, not a surprise field).
        let plain = row(1_700_000_000, "legacy", "/in", "/out", "OK");
        let jp = plain.json();
        assert!(jp.ends_with(r#""selection":"","context":""}"#), "{jp:?}");
    }

    #[test]
    fn v1_file_full_set_row_keeps_v1_bytes() {
        // A v1 file + a full-set (empty selection) append: today's
        // exact 10-column row, the header untouched (the file stays
        // v1 — the ledger behavior for a non-selected run is
        // unchanged).
        let tmp = std::env::temp_dir().join("frameprism_ledger_v1_full_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("ledger.tsv");
        let old_row = "1000\tlegacy\t0.4.0\t/in\t/out\tj92\t72\tOK\t10\t";
        std::fs::write(&p, format!("{VERSION_LINE}\n{COLUMN_HEADER}\n{old_row}\n")).unwrap();
        let full = row(2_000, "legacy", "/in", "/out", "OK");
        append_to(&p, &full).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], VERSION_LINE);
        assert_eq!(lines[1], COLUMN_HEADER);
        assert_eq!(lines[2], old_row);
        assert_eq!(lines[3], full.line());
        let (rows, warnings) = read(&p);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.selection.is_empty()));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn v1_file_selected_row_bumps_header_once() {
        // The one-time bump: the first row that carries a
        // selection rewrites the v1 header to v2 (no row rewrites —
        // the existing 10-column row stays in place) + appends the
        // 11-column row. A LATER append (even a full-set one) does
        // NOT rewrite again (the bytes before it are stable) and
        // appends the 11-column shape. An unknown-version file is the
        // named refused append (the file is untouched).
        let tmp = std::env::temp_dir().join("frameprism_ledger_bump_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("ledger.tsv");
        let old_row = "1000\tlegacy\t0.4.0\t/in\t/out\tj92\t72\tOK\t10\t";
        std::fs::write(&p, format!("{VERSION_LINE}\n{COLUMN_HEADER}\n{old_row}\n")).unwrap();
        let mut sel = row(1_500, "legacy", "/in", "/out", "OK");
        sel.selection = "A001_001".into();
        append_to(&p, &sel).unwrap();
        let after_bump = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = after_bump.lines().collect();
        assert_eq!(lines[0], VERSION_LINE_V2);
        assert_eq!(lines[1], COLUMN_HEADER_V2);
        assert_eq!(lines[2], old_row); // the v1 row is NOT rewritten
        assert_eq!(lines[3], sel.line_v2());
        // The reader accepts the bumped file (both row shapes).
        let (rows, warnings) = read(&p);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].selection, "");
        assert_eq!(rows[1].selection, "A001_001");
        // The LATER append: no second rewrite — the prefix before the
        // new row is byte-stable; the full-set row in a v2 file keeps
        // the 11-column shape (the trailing empty field).
        let full = row(2_000, "legacy", "/in", "/out", "OK");
        append_to(&p, &full).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with(&after_bump), "the bumped prefix must be byte-stable");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], VERSION_LINE_V2);
        assert_eq!(lines[4], full.line_v2());
        let (rows, warnings) = read(&p);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[2].selection, "");
        // An unknown-version file: the named refused append (the file
        // is untouched).
        let p2 = tmp.join("foreign.tsv");
        std::fs::write(&p2, "version: 99\nwhatever\n").unwrap();
        let before = std::fs::read_to_string(&p2).unwrap();
        let err = append_to(&p2, &row(3_000, "legacy", "/in", "/out", "OK")).unwrap_err();
        assert!(err.contains("unknown ledger version"), "{err:?}");
        assert_eq!(std::fs::read_to_string(&p2).unwrap(), before);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn reader_accepts_both_row_shapes() {
        // A hand-assembled v2 file with a 10-column row (the pre-bump
        // shape) + an 11-column row: both parse (the selection is
        // empty / carried respectively); a 9-column row is named.
        let tmp = std::env::temp_dir().join("frameprism_ledger_mixed_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("ledger.tsv");
        std::fs::write(
            &p,
            format!(
                "{VERSION_LINE_V2}\n{COLUMN_HEADER_V2}\n1000\tlegacy\t0.4.0\t/in\t/out\tj92\t72\tOK\t10\t\n2000\tlegacy\t0.4.0\t/in\t/out\tj92\t72\tOK\t10\t\tA001_001,A001_006\n3000\tlegacy\t0.4.0\t/in\t/out\tj92\t72\tOK\n"
            ),
        )
        .unwrap();
        let (rows, warnings) = read(&p);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0].selection, "");
        assert_eq!(rows[1].selection, "A001_001,A001_006");
        assert!(
            warnings.iter().any(|w| w.contains("line 5 malformed") && w.contains("column(s)")),
            "{warnings:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn reader_names_malformed_rows_and_continues() {
        let tmp = std::env::temp_dir().join("frameprism_ledger_malformed_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("ledger.tsv");
        std::fs::write(
            &p,
            format!(
                "{VERSION_LINE}\n{COLUMN_HEADER}\n1000\tlegacy\t0.4.0\t/in\t/out\tj92\t72\tOK\t10\t\nbad-row-too-few-cols\n2000\tbake\t0.4.0\t/in\t/out\tj92\tnotanumber\tOK\t10\t\n"
            ),
        )
        .unwrap();
        let (rows, warnings) = read(&p);
        assert_eq!(rows.len(), 1, "{rows:?}");
        // File line 3 = the valid 1000 row (no warning); line 4 = the
        // too-few-cols row; line 5 = the bad-frames row.
        assert!(
            warnings.iter().any(|w| w.contains("line 4 malformed") && w.contains("column(s)")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("line 5 malformed") && w.contains("bad frames")),
            "{warnings:?}"
        );
        // An unknown version: named, the rows are not read.
        std::fs::write(&p, "version: 99\ncreated\tcommand\n1000\tlegacy\n").unwrap();
        let (rows, warnings) = read(&p);
        assert!(rows.is_empty());
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("unknown ledger version") && w.contains("99")),
            "{warnings:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rotation_names_exactly_the_stale_reel() {
        // The synthetic: 2 reels — reelA's last audit 10 days old,
        // reelB audited yesterday; window N = 7 → exactly reelA.
        let now = 1_000_000_000u64;
        let d = |days: u64| now - days * SECONDS_PER_DAY;
        let rows = vec![
            row(d(80), "bake", "/clip-a", "/reelA", "OK"),
            row(d(10), "audit", "/reelA", "", "OK"),
            row(d(1), "bake-iso", "/clip-b", "/reelB", "OK"),
            row(d(1), "audit", "/reelB", "", "OK"),
            // A refused bake row never starts a reel (no output).
            row(d(2), "bake", "/clip-c", "/reelC", "REFUSED_PIN"),
        ];
        let (rotate, n_reels) = rotation_report(&rows, 7, now);
        assert_eq!(n_reels, 2, "{rows:?}");
        assert_eq!(rotate.len(), 1, "{rotate:?}");
        assert_eq!(rotate[0], "ROTATE /reelA: last audit 10 days ago");
        // A never-audited reel is named too.
        let rows2 = vec![row(d(30), "bake", "/clip-d", "/reelD", "OK")];
        let (rotate, _) = rotation_report(&rows2, 90, now);
        assert_eq!(rotate, vec!["ROTATE /reelD: last audit never"]);
    }

    #[test]
    fn json_line_carries_the_columns_escaped() {
        let r = row(
            1_700_000_000,
            "legacy",
            "/in \"quoted\"",
            "/out",
            "REFUSED_SPACE",
        );
        let j = r.json();
        assert!(j.starts_with("{\"created\":1700000000,"), "{j:?}");
        assert!(j.contains(r#"\"quoted\""#), "{j:?}");
        assert!(j.contains(r#""verdict":"REFUSED_SPACE""#), "{j:?}");
        assert!(j.ends_with(r#""dest":"","selection":"","context":""}"#), "{j:?}");
        // The v2 selection column is carried (escaped).
        let mut s = row(1_700_000_000, "legacy", "/in", "/out", "OK");
        s.selection = "A001_001,A001_\"006\"".into();
        let js = s.json();
        assert!(
            js.ends_with(r#""selection":"A001_001,A001_\"006\"","context":""}"#),
            "{js:?}"
        );
    }
}
