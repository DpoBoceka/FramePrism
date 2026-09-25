//! Machine-readable progress surface.
//!
//! The append-only JSONL at `~/.frameprism/status.jsonl` (override: the
//! `FRAMEPRISM_STATUS` env — the test + gate hook).: the file is in the
//! HOME dir, NEVER inside the input or output tree (it can never become
//! an archive member / an encoded frame).: the file is TRUNCATED at
//! run start (before the first frame/byte) and then append-only — one
//! compact one-line JSON event per record; a SIGTERM'd run leaves the
//! lines written so far (last-writer-wins for concurrent runs — a
//! documented property, not a gate).
//!
//! Event shapes (the fields are the contract — the values are live):
//!
//!     {"run":"<start-secs>-<pid>","input":"...","out":"...","codec":"j92",
//!      "phase":"start","clips":2,"frames_total":147,"est_eta_s":600,"resumed":41}
//!     {"phase":"clip","clip":"A001_001","clip_i":1,"clips":2,"frames_clip":72}
//!     {"phase":"encode","clip":"A001_001","frame":"A001_001_...000001.DNG",
//!      "frames_done":42,"frames_total":147,"resumed":0,"rate_fps":2.10,"eta_s":50.0}
//!     {"phase":"verify","frames_total":147,"frames_ok":147}
//!     {"phase":"end","verdict":"OK","frames_total":147,"frames_ok":147,
//!      "resumed":41,"duration_s":68}
//!
//! The bake commands carry the same shape with `phase:"bake"` /
//! `phase:"iso"` on the start line (the `codec`/`clips` fields are
//! absent there — the bake has no per-frame unit). The JXL path carries
//! NO status lines in v1 (resume is refused there; the surface is
//! the j92 encode + the bake commands).
//!
//! The surface is additive: an emit failure (a read-only HOME, a full
//! disk mid-run) never fails the run — the lines are progress, not the
//! product (the product's integrity is the sidecar's job). Open failure
//! (the dir cannot be created / the file cannot be truncated) is a named
//! stderr note + the run proceeds WITHOUT the surface.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Mutex, OnceLock};

/// The process-wide status surface (the pins.rs / selection.rs
/// OnceLock convention — one CLI run per process, set ONCE by `main`).
static CURRENT: OnceLock<Option<Status>> = OnceLock::new();

/// One open status file (truncated at open, append-only after).
pub struct Status {
    path: PathBuf,
    /// The run id (`<start-secs>-<pid>` — the line's `run` field).
    pub run_id: String,
    file: Mutex<std::fs::File>,
}

/// The status path: the `FRAMEPRISM_STATUS` override, else
/// `~/.frameprism/status.jsonl` (the ledger's dir convention).
pub fn status_path() -> PathBuf {
    if let Ok(p) = std::env::var("FRAMEPRISM_STATUS") {
        return PathBuf::from(p);
    }
    match std::env::var_os("HOME") {
        Some(h) if !h.is_empty() => PathBuf::from(h).join(".frameprism/status.jsonl"),
        _ => PathBuf::from(".frameprism/status.jsonl"),
    }
}

/// Best-effort 0700 on unix; a no-op on other targets (the std-only
/// `Permissions` surface carries no mode bits — the
/// source-portability fallback).
fn set_dir_0700(p: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            p,
            std::fs::Permissions::from_mode(0o700),
        );
    }
    #[cfg(not(unix))]
    {
        let _ = p;
    }
}

/// Open (CREATE + TRUNCATE) `path` for the status surface, 0600,
/// creating the parent dir 0700 when missing. No env read, no
/// registration — `open()` wraps this with `status_path()` + the run
/// id.
fn open_at(path: &Path) -> Option<Status> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            match std::fs::create_dir_all(parent) {
                Ok(()) => set_dir_0700(parent),
                Err(err) => {
                    eprintln!(
                        "note: status: cannot create {} ({err}) — the progress surface is OFF for this run",
                        parent.display()
                    );
                    return None;
                }
            }
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true);
    opts.truncate(true);
    opts.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = match opts.open(path) {
        Ok(f) => f,
        Err(err) => {
            eprintln!(
                "note: status: cannot open {} ({err}) — the progress surface is OFF for this run",
                path.display()
            );
            return None;
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(0o600),
        );
    }
    Some(Status {
        run_id: String::new(),
        path: path.to_path_buf(),
        file: Mutex::new(file),
    })
}

/// Open the run's status file (truncating any previous run's lines
/// BEFORE the first frame/byte) and register it process-wide.
/// Returns the run id (`<start-secs>-<pid>` — the line's `run` field)
/// or None (named note already on stderr; the run proceeds without
/// the surface).
pub fn open() -> Option<String> {
    let path = status_path();
    let mut st = open_at(&path)?;
    st.run_id = format!("{}-{}", crate::ledger::now_secs(), process::id());
    let run_id = st.run_id.clone();
    set_current(Some(st));
    Some(run_id)
}

/// Register the process-wide surface (`None` = the surface is off for
/// this run — the JXL path + the open-failure path). Ignored after the
/// first set (the OnceLock; a run sets it once).
pub fn set_current(st: Option<Status>) {
    let _ = CURRENT.set(st);
}

/// The process-wide surface (None = off — every emit is a no-op).
pub fn current() -> Option<&'static Status> {
    CURRENT.get().and_then(|s| s.as_ref())
}

impl Status {
    /// The file's path (the report / the gate evidence).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one already-formatted JSON line (the `{"phase":...}`
    /// shapes in the module docs). Errors are swallowed (the additive
    /// contract — a progress line never fails the run).
    pub fn emit(&self, line: &str) {
        let Ok(mut f) = self.file.lock() else {
            return;
        };
        let mut buf = Vec::with_capacity(line.len() + 2);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        let _ = f.write_all(&buf);
        let _ = f.flush();
    }
}

/// Escape a JSON string VALUE (unquoted — wrap with `format!("\"{}\"", esc(s))`):
/// backslash, quote, and the control chars get their canonical
/// `\uXXXX` / `\n`-class forms. Paths are the only expected input;
/// the escaping keeps the line parseable regardless.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// A JSON string literal (quoted + escaped).
pub fn jstr(s: &str) -> String {
    format!("\"{}\"", esc(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    #[test]
    fn esc_covers_the_json_control_chars() {
        assert_eq!(esc("plain"), "plain");
        assert_eq!(esc("a\\b\"c"), "a\\\\b\\\"c");
        assert_eq!(esc("l1\nl2\rl3\tt"), "l1\\nl2\\rl3\\tt");
        assert_eq!(esc("\u{0001}"), "\\u0001");
    }

    #[test]
    fn open_at_creates_0700_dir_and_0600_file_and_appends_lines() {
        let base = std::env::temp_dir().join(format!("frameprism_status_open_at_{}", process::id()));
        // Pre-create an outer dir (0755, as create_dir_all leaves it) so
        // the assertion targets the IMMEDIATE parent open_at creates +
        // chmods (the posture: the status dir, not every ancestor).
        let dir = base.join("outer");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("inner/status.jsonl");
        let st = open_at(&path).expect("open");
        st.emit(r#"{"phase":"start","clips":2}"#);
        st.emit(r#"{"phase":"encode","frame":"a.DNG"}"#);
        drop(st);
        let bytes = std::fs::read(&path).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text:?}");
        assert!(lines[0].starts_with("{\"phase\":\"start\""));
        // The immediate parent (the status dir) is 0700 + the file 0600.
        let parent = path.parent().unwrap();
        let pm = std::fs::metadata(parent).unwrap();
        let fm = std::fs::metadata(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(pm.permissions().mode() & 0o777, 0o700, "status dir 0700");
            assert_eq!(fm.permissions().mode() & 0o777, 0o600, "file 0600");
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn open_truncates_the_previous_run_and_sets_current() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        let dir = std::env::temp_dir().join(format!("frameprism_status_open_{}", process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("status.jsonl");
        std::fs::write(&path, b"stale line from a previous run\n").unwrap();
        std::env::set_var("FRAMEPRISM_STATUS", &path);
        // A previous set (if any test raced the OnceLock) — the OnceLock
        // is process-wide, so only the FIRST open() in this process
        // registers; the truncate + the run id must still be right.
        let _id = open();
        std::env::remove_var("FRAMEPRISM_STATUS");
        // Whatever got registered, the FILE is truncated (open_at ran).
        let mut buf = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();
        assert_eq!(buf, "", "truncated at run start: {buf:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// (G4): the status START line's field set + shape — assembled
    /// with the EXACT worker template (the jq-parseable + field-set proof
    /// on the live file is gate G2). String values are jstr-quoted, the
    /// numerics are bare, the key order is the documented one.
    #[test]
    fn start_line_carries_the_documented_field_set() {
        // The worker.rs start-line template, verbatim.
        let line = format!(
            "{{\"run\":{},\"input\":{},\"out\":{},\"codec\":{},\"phase\":{},\"clips\":{},\"frames_total\":{},\"est_eta_s\":{eta},\"resumed\":{resumed}}}",
            jstr("1789466979-27905"),
            jstr("/in/tree\"with\"quote"),
            jstr("/out"),
            jstr("j92"),
            jstr("start"),
            2usize,
            147usize,
            eta = 59u64,
            resumed = 0usize
        );
        // The field set, in order (no nesting - top-level keys only):
        // each key appears exactly where the documented order says.
        let mut pos = 0;
        for k in [
            "run", "input", "out", "codec", "phase", "clips",
            "frames_total", "est_eta_s", "resumed",
        ] {
            let needle = format!("\"{k}\":");
            let i = line[pos..]
                .find(&needle)
                .unwrap_or_else(|| panic!("key {k} missing/out of order: {line}"));
            pos += i + needle.len();
        }
        // The string values are quoted + escaped (the quote in the path
        // survived jstr); the numerics are bare.
        assert!(line.contains(r#""input":"/in/tree\"with\"quote""#), "{line}");
        assert!(line.contains(r#""clips":2,"#), "bare numeric: {line}");
        assert!(line.starts_with("{\"run\":\"1789466979-27905\"") && line.ends_with('}'), "{line}");
    }
}
