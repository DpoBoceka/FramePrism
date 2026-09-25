//! Tool-side pin self-check at startup (the Risks-row
//! mitigation that was promised and never landed).
//!
//! The version pins in `ci/pins.tsv` are the byte-identity contracts
//! (a version drift would silently change the archive bytes). Until
//! now they were enforced by CI only (`ci/check.sh` → `ci/check-pins.sh`);
//! this module adds the tool-side half: BEFORE the first frame/byte of
//! output on every command that PRODUCES archive bytes (the legacy
//! encode — j92 + jxl paths; bake; bake --iso) the tool parses the pins
//! file, probes each version row the SAME way the tool would use the
//! binary at runtime, and REFUSES NAMED (rc=2, zero output) on a drift
//! (the version string missing the expected substring) or a missing
//! binary. The check does NOT apply to pure reads (decode/audit/
//! restore) or derive (no archive bytes).
//!
//! Pins resolution (the recorded decision): the `--pins <path>` flag → the
//! `FRAMEPRISM_PINS` env → `<cwd>/ci/pins.tsv` (repo checkouts) →
//! `<exe_dir>/../ci/pins.tsv`. NOT found = a NAMED skip line in the
//! output + the report (never silent, NOT a refusal —
//! installed-from-brew users have no repo; the CI entrypoint remains
//! the enforcement surface). There is NO escape flag (the
//! `--allow-unpinned` decision is PARKED — do not add it).
//!
//! Row semantics (the `ci/check-pins.sh` reference implementation):
//! - `version-contains <flag>`: `<bin> <flag>`'s first non-empty line
//!   (stdout, then stderr) must CONTAIN the expected string.
//! - `toml-grep`: the tool row — SELF-SATISFIED (the binary IS the
//!   tool): found = the running version, always OK, recorded for the
//!   report.
//! - `probed-by-check.sh`: the suite/oracle rows — probed by CI, not
//!   by the tool: recorded as a skip note, never a refusal.
//!
//! The FULL contract set is probed on every archive-producing command
//! (the encode path probes cjxl/djxl ALWAYS — a j92 run
//! on a machine with a drifted cjxl is a drifted machine; the same
//! holds for the rest of the set — the pins file IS the contract set).
//! The resolved pin state lands in the run report's tool/versions block
//! (the A1 line) so every report says what pins were enforced on its
//! bytes.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// One row of `pins.tsv` (columns 1+2 are the contract; column 3 = the
/// probe spec `version-contains <flag>` | `toml-grep` |
/// `probed-by-check.sh`; column 4 = the note).
#[derive(Debug)]
pub struct PinRow {
    pub component: String,
    pub expected: String,
    pub probe: String,
    pub note: String,
}

/// One resolved component state (the report block line).
#[derive(Clone, Debug)]
pub struct PinState {
    pub component: String,
    pub expected: String,
    /// The probe output (the first line per binary; `missing` for a
    /// missing binary). For the `cjxl/djxl` row: `cjxl <line> | djxl
    /// <line>`. The tool row carries the running version.
    pub found: String,
    pub ok: bool,
    /// A named skip note (the `probed-by-check.sh` rows + the
    /// unresolvable probe rows) — recorded, never a refusal.
    pub skip_note: Option<String>,
}

/// The resolved pin state of one archive-producing run (the A1 block
/// of the run report).
#[derive(Clone, Debug)]
pub struct PinReport {
    /// The pins file used (None = not found → the named skip).
    pub path: Option<PathBuf>,
    /// The probed candidates (the skip line names them).
    pub probed: Vec<String>,
    pub states: Vec<PinState>,
    /// A named note (a corrupt/unreadable pins file — the skip shape,
    /// not a refusal: the CI entrypoint is the enforcement surface).
    pub note: Option<String>,
}

impl PinReport {
    /// Any drifted/missing component (the skip notes never refuse).
    pub fn any_fail(&self) -> bool {
        self.states
            .iter()
            .any(|s| !s.ok && s.skip_note.is_none())
    }

    /// The named FAIL lines (the exact shape: one per drifted/
    /// missing component).
    pub fn fail_lines(&self) -> Vec<String> {
        self.states
            .iter()
            .filter(|s| !s.ok && s.skip_note.is_none())
            .map(|s| {
                format!(
                    "FAIL pin {}: expected {}, found {}",
                    s.component, s.expected, s.found
                )
            })
            .collect()
    }

    /// The named skip line (never silent, not a refusal).
    pub fn skip_line(&self) -> String {
        format!(
            "note: pins: not found ({}) — pin self-check skipped (the CI entrypoint remains the enforcement surface)",
            self.probed.join(", ")
        )
    }

    /// The compact PASS line (stderr, the gate style of the ingest
    /// gate's PASS block).
    pub fn pass_line(&self) -> String {
        let ok = self
            .states
            .iter()
            .filter(|s| s.ok)
            .count();
        format!(
            "PASS pins: {}/{} OK ({})",
            ok,
            self.states.len(),
            self.path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        )
    }

    /// The run report's tool/versions block (the A1 line).
    pub fn report_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        match (&self.note, &self.path) {
            (Some(note), _) => {
                lines.push(format!("pins: skipped — {note}"));
            }
            (None, None) => lines.push(self.skip_line()),
            (None, Some(p)) => {
                let ok = self.states.iter().filter(|s| s.ok).count();
                lines.push(format!(
                    "pins: {} — {}/{} OK (the A1 self-check — the pins enforced on this run's bytes)",
                    p.display(),
                    ok,
                    self.states.len()
                ));
                for s in &self.states {
                    let status = if let Some(note) = &s.skip_note {
                        format!("skip — {note}")
                    } else if s.ok {
                        "OK".to_string()
                    } else {
                        "DRIFT".to_string()
                    };
                    lines.push(format!(
                        "  {}: {} — expected {} — found {}",
                        s.component, status, s.expected, s.found
                    ));
                }
            }
        }
        lines
    }
}

/// The runtime binary resolution for one run (each probed binary
/// is resolved the SAME way the tool would use it at runtime — the
/// command's flags where it has them, else the command's defaults).
#[derive(Clone, Debug)]
pub struct Resolve {
    pub cjxl: PathBuf,
    pub djxl: PathBuf,
}

/// Resolve the pins file: the `--pins` flag → `FRAMEPRISM_PINS` →
/// `<cwd>/ci/pins.tsv` → `<exe_dir>/../ci/pins.tsv`. Returns (the
/// found path or None, the probed candidates — the skip line names
/// them).
pub fn resolve_pins_path(flag: Option<&Path>) -> (Option<PathBuf>, Vec<String>) {
    let mut probed: Vec<String> = Vec::new();
    if let Some(p) = flag {
        probed.push(p.display().to_string());
        if p.is_file() {
            return (Some(p.to_path_buf()), probed);
        }
    }
    if let Ok(env) = std::env::var("FRAMEPRISM_PINS") {
        let p = PathBuf::from(&env);
        probed.push(env);
        if p.is_file() {
            return (Some(p), probed);
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let p = cwd.join("ci/pins.tsv");
        probed.push(p.display().to_string());
        if p.is_file() {
            return (Some(p), probed);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("../ci/pins.tsv");
            probed.push(p.display().to_string());
            if p.is_file() {
                return (Some(p), probed);
            }
        }
    }
    (None, probed)
}

/// Parse `pins.tsv` (the header line is skipped). Columns:
/// `component`, `expected`, `probe`, `path-or-note` (the note may be
/// absent).
pub fn parse_pins(path: &Path) -> std::io::Result<Vec<PinRow>> {
    let text = std::fs::read_to_string(path)?;
    let mut rows = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 3 {
            continue; // malformed row — the reader discipline: named by
        } // the CI check-pins.sh (the enforcement surface); the tool
        if cols[0] == "component" {
            continue; // the header
        }
        rows.push(PinRow {
            component: cols[0].to_string(),
            expected: cols[1].to_string(),
            probe: cols[2].to_string(),
            note: cols.get(3).copied().unwrap_or_default().to_string(),
        });
    }
    Ok(rows)
}

/// Probe `<bin> <flag>` → the first non-empty line (stdout, then
/// stderr — the `check-pins.sh` / bake `version_line` convention).
/// `Err("missing")` = the binary is not spawnable.
fn probe_line(bin: &Path, flag: &str) -> Result<String, String> {
    let out = Command::new(bin)
        .arg(flag)
        .output()
        .map_err(|_| "missing".to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    Ok(
        stdout
            .lines()
            .chain(stderr.lines())
            .find(|l| !l.trim().is_empty())
            .map(|l| l.trim().to_string())
            .unwrap_or_else(|| "empty output".to_string()),
    )
}

/// Run the self-check over `rows` with the run's `resolve` (the full
/// contract set — every version row is probed).
pub fn check(rows: &[PinRow], resolve: &Resolve) -> Vec<PinState> {
    rows.iter()
        .map(|row| {
            let probe_type = row.probe.split_whitespace().next().unwrap_or_default();
            let flag = row.probe.split_whitespace().nth(1).unwrap_or_default();
            match probe_type {
                "version-contains" => {
                    let probe_one = |bin: &Path| -> (String, bool) {
                        match probe_line(bin, flag) {
                            Err(e) => (e, false),
                            Ok(l) => (l.clone(), l.contains(&row.expected)),
                        }
                    };
                    match row.component.as_str() {
                        // The row probes BOTH binaries (the check-pins.sh
                        // reference: cjxl + djxl, one row).
                        "cjxl/djxl" => {
                            let (cl, cok) = probe_one(&resolve.cjxl);
                            let (dl, dok) = probe_one(&resolve.djxl);
                            PinState {
                                component: row.component.clone(),
                                expected: row.expected.clone(),
                                found: format!("cjxl {cl} | djxl {dl}"),
                                ok: cok && dok,
                                skip_note: None,
                            }
                        }
                        // A new version row the tool cannot resolve:
                        // named + recorded, not fatal (the CI
                        // check-pins.sh is the enforcement surface).
                        other => PinState {
                            component: row.component.clone(),
                            expected: row.expected.clone(),
                            found: "unresolved (the tool has no runtime resolution for this component)".into(),
                            ok: true,
                            skip_note: Some(format!(
                                "unresolvable version row {other:?} — recorded only (the CI check-pins.sh is the enforcement surface)"
                            )),
                        },
                    }
                }
 // The in-process container components  + the
 // in-process ISO writer : the
                // `lock-grep <name>` rows — the expected string is
                // asserted against the value EMBEDDED IN THE BUILT
                // BINARY: the `tar` row = the tar crate version
                // (build.rs reads it from the committed Cargo.lock —
                // the lock IS the pin); the `zstd` row (probe
                // `lock-grep zstd-sys`) = the bundled libzstd version
                // (the runtime `zstd_safe::version_string()` — the
                // pinned zstd-sys `+zstd.<libzstd>` lock suffix is
                // the CI's assertion of the same value); the `fstool`
                // row (probe `lock-grep fstool`) = the pinned fstool
                // crate version (build.rs env from the committed
                // Cargo.lock — the in-process ISO writer for
                // `bake --iso`, no PATH binary). The CI
                // check-pins.sh asserts the same expected against the
                // same lock, so the two surfaces cannot drift
                // independently. No PATH binary is probed — the
                // in-process path has none.
                "lock-grep" => {
                    let name = row.probe.split_whitespace().nth(1).unwrap_or_default();
                    let (embedded, known) = match name {
                        "tar" => (
                            env!("FRAMEPRISM_TAR_CRATE_VERSION").to_string(),
                            row.component == "tar",
                        ),
                        "zstd-sys" => (
                            zstd::zstd_safe::version_string().to_string(),
                            row.component == "zstd",
                        ),
                        "fstool" => (
                            env!("FRAMEPRISM_FSTOOL_CRATE_VERSION").to_string(),
                            row.component == "fstool",
                        ),
                        _ => (String::new(), false),
                    };
                    PinState {
                        component: row.component.clone(),
                        expected: row.expected.clone(),
                        found: if known {
                            format!("{name} {embedded} (tool/Cargo.lock — embedded)")
                        } else {
                            format!("unresolved lock-grep name {name:?} (component {})", row.component)
                        },
                        ok: known && embedded == row.expected,
                        skip_note: None,
                    }
                }
                // The tool row (toml-grep): self-satisfied (the binary
                // IS the tool — found = the running
                // version, always OK, recorded for the report).
                "toml-grep" => PinState {
                    component: row.component.clone(),
                    expected: row.expected.clone(),
                    found: env!("CARGO_PKG_VERSION").to_string(),
                    ok: true,
                    skip_note: None,
                },
                // The suite/oracle rows: probed by check.sh, not by the
                // tool — a skip note, never a refusal.
                _ => PinState {
                    component: row.component.clone(),
                    expected: row.expected.clone(),
                    found: "recorded".to_string(),
                    ok: true,
                    skip_note: Some(
                        "probed by check.sh (the CI entrypoint remains the enforcement surface)".into(),
                    ),
                },
            }
        })
        .collect()
}

static CURRENT: OnceLock<PinReport> = OnceLock::new();

/// The canonical pin-set string
/// the provenance signature's `pin_set:` field): the version rows'
/// `component=version` lines, sorted by component name and joined by
/// "; " — the same source `ci/check-pins.sh` asserts. The `cjxl/djxl`
/// row contributes TWO lines (the row probes both binaries:
/// `cjxl=<expected>` + `djxl=<expected>`); the `toml-grep` tool row
/// contributes `tool=<the running version>` (the row is self-
/// satisfied — the running binary IS the tool, the `check()`
/// convention); the `sha256-equal` byte pins + the
/// `probed-by-check.sh` CI rows are excluded (no component version
/// string). The string is the CONTRACT (the pinned version strings),
/// not the live probe state — deterministic for a given pins file
/// (NO binary probing: the signature envelope must be byte-
/// reproducible, and the live version lines carry environment
/// specifics — e.g. the cjxl CPU-features suffix — that a reader decades from now
/// could never re-derive). Additive accessor (no behavior
/// change to the existing resolution/check surface.
pub fn pin_set_canonical(rows: &[PinRow]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for row in rows {
        let probe_type = row.probe.split_whitespace().next().unwrap_or_default();
        match probe_type {
            "version-contains" | "lock-grep" => {
 // The in-process container components  ride
                // the `lock-grep` probe — the component=expected pair
                // is the pin contract exactly as for the version rows.
                if row.component == "cjxl/djxl" {
                    parts.push(format!("cjxl={}", row.expected));
                    parts.push(format!("djxl={}", row.expected));
                } else {
                    parts.push(format!("{}={}", row.component, row.expected));
                }
            }
            "toml-grep" => {
                parts.push(format!("tool={}", env!("CARGO_PKG_VERSION")));
            }
            _ => {} // the sha256-equal byte pins + the probed-by-check.sh CI rows
        }
    }
    parts.sort();
    parts.join("; ")
}

/// The resolved canonical pin-set string (the `sign` input):
/// the pins path resolution (the convention: the `flag` → the
/// `FRAMEPRISM_PINS` env → `<cwd>/ci/pins.tsv` → `<exe_dir>/../ci/pins.tsv`)
/// and the parse + the canonicalization. `Err` = the named refusal
/// (the pins file is missing / unreadable — the pin set is the
/// envelope's provenance binding; a sign without it is the named
/// records-class refusal, zero partial operations).
pub fn resolved_pin_set(flag: Option<&Path>) -> Result<String, String> {
    let (path, probed) = resolve_pins_path(flag);
    let p = path.ok_or_else(|| {
        format!("pins file not found (probed: {})", probed.join(", "))
    })?;
    let rows =
        parse_pins(&p).map_err(|e| format!("unreadable pins file {}: {e}", p.display()))?;
    Ok(pin_set_canonical(&rows))
}

/// Record the run's pin state (the single CLI process sets it once,
/// before the archive-producing run; the run report's A1 block reads
/// it). A second set is a silent no-op (the CLI has one run per
/// process).
pub fn set_current(r: PinReport) {
    let _ = CURRENT.set(r);
}

/// The run's pin state (None = the run did not run the check — e.g. a
/// pure-read verb; the report carries no pins block).
pub fn current() -> Option<&'static PinReport> {
    CURRENT.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake probe binary printing a fixed version line.
    fn fake_bin(dir: &Path, name: &str, line: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\necho \"{line}\"\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut m = std::fs::metadata(&p).unwrap().permissions();
            m.set_mode(0o755);
            std::fs::set_permissions(&p, m).unwrap();
        }
        p
    }

    #[test]
    fn parse_pins_roundtrip() {
        let tmp = std::env::temp_dir().join("frameprism_pins_parse_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("pins.tsv");
        std::fs::write(
            &p,
            "component\texpected\tprobe\tpath-or-note\n\
cjxl/djxl\tv0.12.0 1cad73c\tversion-contains --version\tnote a\n\
tool\t0.4.0\ttoml-grep\tnote b\n\
suite\t202 passed; 0 failed; 1 ignored\tprobed-by-check.sh\tnote c\n",
        )
        .unwrap();
        let rows = parse_pins(&p).unwrap();
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert_eq!(rows[0].component, "cjxl/djxl");
        assert_eq!(rows[0].expected, "v0.12.0 1cad73c");
        assert_eq!(rows[0].probe, "version-contains --version");
        assert_eq!(rows[0].note, "note a");
        assert_eq!(rows[1].probe, "toml-grep");
        assert_eq!(rows[2].probe, "probed-by-check.sh");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn check_version_rows_ok_drift_missing() {
        let tmp = std::env::temp_dir().join("frameprism_pins_check_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let rows = vec![
            PinRow {
                component: "zstd".into(),
                // the in-process lock-grep row: the expected is the
                // bundled libzstd version — the embedded value (the
                // runtime version_string of the pinned zstd-sys) must
                // equal it.
                expected: zstd::zstd_safe::version_string().into(),
                probe: "lock-grep zstd-sys".into(),
                note: String::new(),
            },
            PinRow {
                component: "tar".into(),
                expected: "9.9.9".into(), // the drift row
                probe: "lock-grep tar".into(),
                note: String::new(),
            },
            PinRow {
                component: "fstool".into(),
 // The in-process ISO writer row : the
                // expected IS the embedded value (build.rs env from
                // the committed Cargo.lock — self-satisfied).
                expected: env!("FRAMEPRISM_FSTOOL_CRATE_VERSION").into(),
                probe: "lock-grep fstool".into(),
                note: String::new(),
            },
            PinRow {
                // The missing-binary case (re-pinned from the retired
                // xorriso row to the cjxl/djxl row — the only
                // remaining version-contains row; both probes missing
                // → the row fails).
                component: "cjxl/djxl".into(),
                expected: "v0.12.0 1cad73c".into(),
                probe: "version-contains --version".into(),
                note: String::new(),
            },
        ];
        let resolve = Resolve {
            cjxl: tmp.join("missing-cjxl"),
            djxl: tmp.join("missing-djxl"),
        };
        let states = check(&rows, &resolve);
        // The embedded lock-grep row self-satisfies (the expected IS
        // the embedded value — the build.rs env from the committed
        // lock; the two surfaces cannot drift independently).
        assert!(states[0].ok, "{:?}", states[0]);
        assert!(
            states[0].found.contains("(tool/Cargo.lock — embedded)"),
            "{:?}",
            states[0]
        );
        // Drift: the expected is not the embedded crate version.
        assert!(!states[1].ok, "{:?}", states[1]);
        assert!(!states[1].found.contains("9.9.9"), "{:?}", states[1]);
        // The fstool row self-satisfies (the embedded build.rs env).
        assert!(states[2].ok, "{:?}", states[2]);
        assert!(
            states[2].found.contains("(tool/Cargo.lock — embedded)"),
            "{:?}",
            states[2]
        );
        // Missing binaries (the cjxl/djxl row probes both — both
        // missing).
        assert!(!states[3].ok, "{:?}", states[3]);
        assert_eq!(states[3].found, "cjxl missing | djxl missing");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn check_cjxl_djxl_row_probes_both() {
        let tmp = std::env::temp_dir().join("frameprism_pins_cjxl_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let good = fake_bin(&tmp, "cjxl-good", "cjxl v0.12.0 1cad73c [_NEON_]");
        let rows = vec![PinRow {
            component: "cjxl/djxl".into(),
            expected: "v0.12.0 1cad73c".into(),
            probe: "version-contains --version".into(),
            note: String::new(),
        }];
        // Both good → one OK state.
        let resolve = Resolve {
            cjxl: good.clone(),
            djxl: good.clone(),
        };
        let states = check(&rows, &resolve);
        assert!(states[0].ok, "{:?}", states[0]);
        assert!(states[0].found.starts_with("cjxl cjxl v0.12.0"), "{:?}", states[0]);
        // One drifted → the row fails (named per row; the found text
        // carries both probe outputs).
        let bad = fake_bin(&tmp, "djxl-bad", "djxl v9.9.9 fake");
        let resolve = Resolve {
            cjxl: good.clone(),
            djxl: bad,
        };
        let states = check(&rows, &resolve);
        assert!(!states[0].ok, "{:?}", states[0]);
        assert!(states[0].found.contains("djxl v9.9.9 fake"), "{:?}", states[0]);
        // The fail line is the exact shape.
        let report = PinReport {
            path: Some(tmp.join("pins.tsv")),
            probed: vec![],
            states,
            note: None,
        };
        let lines = report.fail_lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].starts_with(
                "FAIL pin cjxl/djxl: expected v0.12.0 1cad73c, found "
            ),
            "{lines:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn check_tool_row_self_satisfied_and_ci_rows_skip() {
        let rows = vec![
            PinRow {
                component: "tool".into(),
                expected: "0.1.1".into(),
                probe: "toml-grep".into(),
                note: String::new(),
            },
            PinRow {
                component: "suite".into(),
                expected: "202 passed; 0 failed; 1 ignored".into(),
                probe: "probed-by-check.sh".into(),
                note: String::new(),
            },
        ];
        let resolve = Resolve {
            cjxl: PathBuf::from("cjxl"),
            djxl: PathBuf::from("djxl"),
        };
        let states = check(&rows, &resolve);
        // the tool row is always OK (found = the running version
        // — a pins file expecting an older tool never refuses).
        assert!(states[0].ok, "{:?}", states[0]);
        assert_eq!(states[0].found, env!("CARGO_PKG_VERSION"));
        // The CI rows are skip notes (recorded, never a refusal).
        assert!(states[1].ok);
        assert!(states[1]
            .skip_note
            .as_deref()
            .unwrap_or_default()
            .contains("probed by check.sh"));
        let report = PinReport {
            path: Some(PathBuf::from("/pins.tsv")),
            probed: vec!["/pins.tsv".into()],
            states,
            note: None,
        };
        assert!(!report.any_fail(), "{report:?}");
    }

    #[test]
    fn resolve_pins_path_prefers_flag() {
        let tmp = std::env::temp_dir().join("frameprism_pins_resolve_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let p = tmp.join("pins.tsv");
        std::fs::write(&p, "component\texpected\tprobe\n").unwrap();
        let (found, probed) = resolve_pins_path(Some(&p));
        assert_eq!(found, Some(p.clone()));
        assert!(probed.contains(&p.display().to_string()));
        // A missing flag path falls through to the (cwd/exe) candidates
        // and reports None when none exists (the named skip).
        let missing = tmp.join("nope.tsv");
        let (found, probed) = resolve_pins_path(Some(&missing));
        assert!(probed.contains(&missing.display().to_string()));
        let _ = std::fs::remove_dir_all(&tmp);
        // (found may be Some here if the test process happens to run in
        // a repo checkout with ci/pins.tsv — the contract under test is
        // the flag-first ordering + the probed list.)
        let _ = found;
    }
}
