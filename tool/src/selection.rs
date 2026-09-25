//! Clip selection (C9): `--clips <a,b,c>` /
//! `--skip <a,b,c>` on the legacy encode command AND `bake` (both
//! codecs at the flag level — the jxl ENCODE path refuses the
//! combination named in v1, see `main.rs`; the j92 encode filter +
//! the bake work for both codecs' artifacts).
//!
//! The clip name = the run's clip key space: for the encode, the
//! frame's parent dir relative to the ingest root
//! (`worker::clip_key_of` — "" = a flat single-clip layout); for the
//! bake, the clip folder name (tree) / the frame-name prefix group
//! (flat multi-clip `--iso`) / the dir basename (flat single-clip).
//! A selected run processes EXACTLY the named (minus skipped) clips;
//! an unknown name, a `--clips` ∩ `--skip` conflict, or an empty
//! effective set = a NAMED refusal rc=2 BEFORE any frame (a typo must
//! not silently shrink the job — the usage class, no ledger row).
//!
//! The selection is journaled (the ledger's 11th `selection` column —
//! empty = the full set) and lands in the run report (the
//! `selection:` line — `report::write_reports` reads `current()`).
//!
//! Process-wide state (the `pins.rs` `OnceLock` convention — the CLI
//! has one run per process): `main` resolves the selection against
//! the input's clip universe and records it via `set_current`;
//! `worker::process_dir` reads it to filter the collected frames +
//! sidecars (the only worker change here). Absent selection
//! (no flags) = the full set = `None` = the byte-identity path.

use std::collections::BTreeSet;
use std::sync::OnceLock;

/// The active selection of this process's run.
#[derive(Clone, Debug)]
pub struct Active {
    /// The selected clip keys (sorted, deduped — the effective set).
    pub selected: BTreeSet<String>,
    /// The input's total clip count (the report's `k of n` denominator).
    pub universe: usize,
}

static CURRENT: OnceLock<Option<Active>> = OnceLock::new();

/// Record the resolved selection (the single CLI process sets it once
/// before the run; a second set is a silent no-op).
pub fn set_current(a: Option<Active>) {
    // `CURRENT: OnceLock<Option<Active>>` — `set` takes the value
    // (the Option itself): Some(Active) = the selected set, None =
    // no flags were given (the full set).
    let _ = CURRENT.set(a);
}

/// The run's active selection (None = no flags — the full set).
pub fn current() -> Option<&'static Active> {
    CURRENT.get().and_then(|o| o.as_ref())
}

/// The parsed (not-yet-resolved) selection flags.
#[derive(Clone, Debug, Default)]
pub struct Flags {
    /// The `--clips` list (empty = the flag was absent).
    pub clips: Vec<String>,
    /// The `--skip` list (empty = the flag was absent).
    pub skip: Vec<String>,
}

impl Flags {
    /// Parse + malformed-check both flag values (comma-separated clip
    /// names; an empty token is a named refusal — a stray comma is a
    /// typo, not an empty clip). `None` = the flag was absent.
    pub fn new(clips: Option<String>, skip: Option<String>) -> Result<Self, String> {
        Ok(Flags {
            clips: match clips {
                Some(v) => parse_list("--clips", &v)?,
                None => Vec::new(),
            },
            skip: match skip {
                Some(v) => parse_list("--skip", &v)?,
                None => Vec::new(),
            },
        })
    }

    /// True when either flag was given (a selection is active).
    pub fn present(&self) -> bool {
        !self.clips.is_empty() || !self.skip.is_empty()
    }

    /// Resolve the effective selection against the input's clip
    /// universe (the distinct clip keys): the selected keys, or `None`
    /// when no flag was given (the full set — the byte-identity path).
    /// Named refusals: an unknown name, a clips∩skip conflict, an empty
    /// effective set (see `resolve`).
    pub fn resolve(&self, universe: &BTreeSet<String>) -> Result<Option<BTreeSet<String>>, String> {
        resolve(&self.clips, &self.skip, universe)
    }
}

/// Parse one `--clips`/`--skip` value (comma-separated clip names).
/// An empty token is a named malformed (the value is echoed).
pub fn parse_list(flag: &str, value: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for tok in value.split(',') {
        let t = tok.trim();
        if t.is_empty() {
            return Err(format!(
                "{flag}: empty clip name in {value:?} (clip names are comma-separated — no empty entries; a stray comma is a named refusal, not an empty clip)"
            ));
        }
        out.push(t.to_string());
    }
    Ok(out)
}

/// Resolve the effective selection against the input's clip universe
/// (the distinct clip keys, any order). `clips`/`skip` = the parsed
/// lists (empty = the flag absent). Returns the selected keys (sorted)
/// or `None` (no flags = the full set). Named refusals:
/// - an unknown name (a typo must not silently shrink the job — the
///   input's clip keys are listed for the operator);
/// - a `--clips` ∩ `--skip` conflict (a clip cannot be both);
/// - an empty effective set (`--skip` naming every clip).
pub fn resolve(
    clips: &[String],
    skip: &[String],
    universe: &BTreeSet<String>,
) -> Result<Option<BTreeSet<String>>, String> {
    if clips.is_empty() && skip.is_empty() {
        return Ok(None); // no flags — the full set (the byte-identity path)
    }
    let mut unknown: Vec<&String> = Vec::new();
    for c in clips.iter().chain(skip.iter()) {
        if !universe.contains(c) {
            unknown.push(c);
        }
    }
    if !unknown.is_empty() {
        let avail: Vec<&str> = universe.iter().map(|s| s.as_str()).collect();
        return Err(format!(
            "unknown clip name(s) in the selection: {} (the input's clip keys: {})",
            unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
            if avail.is_empty() {
                "<none — the input has no frames>".to_string()
            } else {
                avail.join(", ")
            }
        ));
    }
    let conflict: Vec<&String> = skip.iter().filter(|s| clips.contains(s)).collect();
    if !conflict.is_empty() {
        return Err(format!(
            "--clips and --skip name the same clip(s): {} (a clip cannot be both included and skipped)",
            conflict.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    let effective: BTreeSet<String> = if clips.is_empty() {
        universe
            .iter()
            .filter(|k| !skip.contains(*k))
            .cloned()
            .collect()
    } else {
        clips.iter().cloned().collect()
    };
    if effective.is_empty() {
        return Err(format!(
            "the selection names no clips (clips: {}, skip: {}) — an empty run is a named refusal",
            join_or_dash(clips),
            join_or_dash(skip)
        ));
    }
    Ok(Some(effective))
}

/// The selection string for the ledger's 11th column: the
/// comma-joined effective set; empty string = the full set.
pub fn selection_string(sel: Option<&BTreeSet<String>>) -> String {
    match sel {
        None => String::new(),
        Some(s) => s.iter().cloned().collect::<Vec<_>>().join(","),
    }
}

/// The run report's `selection:` line body (the run report ALWAYS
/// carries the line — full or partial). `processed` = the clip count
/// the run actually processed (the gate's clip count — equals the
/// selected count on a partial run, the universe on a full run).
/// The EXPLICIT full-set (every clip named, `selected == universe`)
/// renders the `all — N of N` shape, identical to the no-selection arm
/// (the `partial: N of N` reading is faithful but contradictory —
/// the cosmetic); the ledger's 11th column
/// (`selection_string`) stays the explicit list — the canonical
/// record.
pub fn report_line(active: Option<&Active>, processed: usize) -> String {
    match active {
        None => format!("all — {processed} of {processed} clip(s)"),
        Some(a) if a.selected.len() == a.universe => {
            format!("all — {processed} of {processed} clip(s)")
        }
        Some(a) => format!(
            "{} — partial: {} of {} clip(s)",
            a.selected
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            a.selected.len(),
            a.universe
        ),
    }
}

fn join_or_dash(v: &[String]) -> String {
    if v.is_empty() {
        "-".to_string()
    } else {
        v.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn universe(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }
    fn list(s: &str) -> Vec<String> {
        s.split(',').map(|t| t.to_string()).collect()
    }

    #[test]
    fn parse_list_rejects_empty_tokens_named() {
        assert_eq!(parse_list("--clips", "a,b").unwrap(), vec!["a", "b"]);
        assert!(parse_list("--clips", "a,,b").unwrap_err().contains("--clips: empty clip name"));
        assert!(parse_list("--skip", ",a").unwrap_err().contains("--skip: empty clip name"));
    }

    #[test]
    fn resolve_full_set_when_no_flags() {
        let u = universe(&["A", "B"]);
        assert_eq!(resolve(&[], &[], &u).unwrap(), None);
    }

    #[test]
    fn resolve_subset_and_skip() {
        let u = universe(&["A", "B", "C"]);
        assert_eq!(
            resolve(&list("B,A"), &[], &u).unwrap().unwrap(),
            universe(&["A", "B"])
        );
        assert_eq!(resolve(&[], &list("C"), &u).unwrap().unwrap(), universe(&["A", "B"]));
    }

    #[test]
    fn resolve_refuses_unknown_conflict_empty_named() {
        let u = universe(&["A", "B"]);
        let e = resolve(&list("A,BOGUS"), &[], &u).unwrap_err();
        assert!(e.contains("unknown clip name(s)") && e.contains("BOGUS"), "{e}");
        assert!(e.contains("A, B"), "the input's clip keys are listed: {e}");
        let e = resolve(&list("A"), &list("A"), &u).unwrap_err();
        assert!(e.contains("the same clip(s)") && e.contains("A"), "{e}");
        let e = resolve(&[], &list("A,B"), &u).unwrap_err();
        assert!(e.contains("names no clips"), "{e}");
    }

    #[test]
    fn report_line_none_shape_is_all_of_all() {
        assert_eq!(report_line(None, 5), "all — 5 of 5 clip(s)");
    }

    #[test]
    fn report_line_explicit_full_set_renders_all_of_all() {
        // the EXPLICIT full-set (every clip named in --clips): the
        // new shape — identical to the no-selection arm (no more the
        // contradictory `partial: 7 of 7`).
        let a = Active {
            selected: universe(&["A", "B", "C"]),
            universe: 3,
        };
        assert_eq!(report_line(Some(&a), 3), "all — 3 of 3 clip(s)");
    }

    #[test]
    fn report_line_true_partial_shape_is_pinned() {
        // the EXISTING true-partial contract (2-of-7): pinned so the
        // full-set special-case can't regress it.
        let a = Active {
            selected: universe(&["A", "B"]),
            universe: 7,
        };
        assert_eq!(
            report_line(Some(&a), 2),
            "A, B — partial: 2 of 7 clip(s)"
        );
    }
}
