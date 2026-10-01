//! The env-gated per-phase profiler (item 125 — the transcode-path
//! profile, the measurement surface): the `FRAMEPRISM_PROFILE=1` env
//! gate (absent / other = INACTIVE — the default run is
//! BYTE-IDENTICAL to the base: no timers written, no sidecar created,
//! no stdout/stderr change, no output change). ACTIVE = the per-frame
//! phase wall-times accumulate in the thread-local (the per-phase
//! SUM — a tile loop that runs 48× contributes one summed row) and
//! the sidecar writer (`<dest>/.frameprism-profile.tsv`, the
//! dotfile-sidecar pattern — the `.frameprism-report.md` /
//! `.frameprism-run-report.md` / ingest-manifest siblings) receives
//! one row per (frame, phase) at the frame's completion (every path
//! incl. the error path — a frame that fails after its read writes
//! the phases it completed; a resume-skipped frame writes NO row —
//! the honest contract, named).
//!
//! The guarantee set (the 124-strength byte-freeze): the guard's
//! inactive form is ONE atomic load + a stack struct — no `Instant`,
//! no heap allocation, no lock, no measurable call; the profiler
//! NEVER touches the pixels/bytes of any output (it measures wall
//! time of existing calls and writes a SEPARATE dotfile). The
//! per-frame flush serializes on the sidecar's mutex (723 small
//! writes — the overhead is in the measurement itself and is named
//! as such in the lane's report — the profiled vs the unprofiled
//! control's wall pair IS the profiler's own cost).
//!
//! The phases (the stable string contract — the exact names):
//! `read` (the worker path's source fs::read) · `fp-input-decode`
//! (the 48 fp input tiles' decode, summed) · `fp-input-drill` (the
//! 48 fp input tiles' re-encode + compare — the item-124 oracle
//! consult inside — summed) · `source-synth` (the
//! `fp_transcode_source` build) · `archive-encode` (the output
//! frame's encode) · `archive-drill` (the output's bit-exact
//! re-encode verify gate — the item-123 "archive bit-exact drill on
//! the output" — summed) · `fidelity-decode` (the transcode-fidelity
//! check's output decode, summed) · `fidelity-compare` (the fidelity
//! check's pixel compare). The RAW frame's row = `read`,
//! `archive-encode`, `archive-drill` ONLY (no fp phases, no fidelity
//! — the raw path's verify is the bit-exact drill only); the FP
//! frame's row = all eight. The guard sites are the A001
//! default-lossless path (the lane's measurement target — the
//! 723-clip + the KAT's standing clip); the other layout/mode
//! branches are outside the lane's measurement scope (named in the
//! lane's report).

use std::collections::HashMap;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// The process-wide gate (the `FRAMEPRISM_PROFILE` env's run-entry
/// form — the CARRY_FLAG house pattern: set ONCE at the run entry
/// (`init_from_env`), read by every guard). The test seam
/// (`test_set`) writes the value directly (the KAT's entry — the
/// gate is a VALUE, not a sticky flag).
static GATE: AtomicBool = AtomicBool::new(false);
/// The env was read ONCE (the run entry): the first `init_from_env`
/// of the process consumes the env var; the later run entries (the
/// test process's subsequent `process_dir` calls) never re-read —
/// the `test_set` value stands.
static ENV_READ: AtomicBool = AtomicBool::new(false);
/// The sidecar writer (the process-wide single writer — the
/// per-frame flush serializes on this mutex).
static SIDECAR: Mutex<Option<BufWriter<std::fs::File>>> = Mutex::new(None);

// The thread-local phase accumulator (the item-124 thread-local
// pattern — the per-thread sums so the pool threads' frames never
// interleave; the per-phase SUM: a tile loop that runs 48×
// contributes one summed row).
thread_local! {
    static ACC: std::cell::RefCell<HashMap<&'static str, u128>> =
        std::cell::RefCell::new(HashMap::new());
}

/// The stable phase-name contract (the exact strings — the sidecar's
/// row domain; the KAT's no-unknown-phase check) in the sidecar's
/// per-frame row order.
const PHASES: [&str; 8] = [
    "read",
    "fp-input-decode",
    "fp-input-drill",
    "source-synth",
    "archive-encode",
    "archive-drill",
    "fidelity-decode",
    "fidelity-compare",
];

/// Read the gate's env var ONCE at the run entry (R0: the env is
/// read ONCE — the first `process_dir` of the process consumes it;
/// absent / a value other than `1` = INACTIVE). Later run entries
/// are no-ops (the `test_set` seam's value stands).
pub fn init_from_env() {
    if ENV_READ.swap(true, Ordering::Relaxed) {
        return;
    }
    GATE.store(std::env::var("FRAMEPRISM_PROFILE").as_deref() == Ok("1"), Ordering::Relaxed);
}

/// The test seam (the KAT's entry): set the gate's value directly
/// (bypassing the env — the test process's `process_dir` runs never
/// re-read the env after the first, so the value stands until the
/// next `test_set`).
// The seam is read by the tests only (the worker/encode.rs test
// module's KAT); the non-test build path never calls it.
#[allow(dead_code)]
pub(crate) fn test_set(active: bool) {
    GATE.store(active, Ordering::Relaxed);
}

/// The gate's current value (the call-site guard — the flush's
/// per-frame allocation rides this check so the gate OFF allocates
/// nothing at the call site either).
pub(crate) fn active() -> bool {
    GATE.load(Ordering::Relaxed)
}

/// The RAII phase guard's entry (R0's guard type — the
/// `profile::phase("name").start()` form): `start()` at the region's
/// head; the guard's DROP (the region's scope end — the `?` /
/// `bail!` early-return paths included) accumulates the wall into
/// the thread-local. INACTIVE = one atomic load + a stack struct
/// (no `Instant`, no heap allocation, no lock — the checked no-op).
pub struct Phase {
    name: &'static str,
}

/// Name a phase (the stable string contract — the `PHASES` domain).
pub fn phase(name: &'static str) -> Phase {
    Phase { name }
}

impl Phase {
    /// Start the region's guard (the gate read — the INACTIVE form
    /// carries no timer, so its drop is a plain no-op).
    pub fn start(self) -> PhaseGuard {
        PhaseGuard {
            name: self.name,
            start: if GATE.load(Ordering::Relaxed) {
                Some(Instant::now())
            } else {
                None
            },
        }
    }
}

/// The started phase guard (the drop accumulates the region's wall
/// into the thread-local's per-phase sum — the partial time on the
/// early-return paths included: a frame that fails after its read
/// writes the phases it completed).
pub struct PhaseGuard {
    name: &'static str,
    start: Option<Instant>,
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        if let Some(t) = self.start {
            let ns = t.elapsed().as_nanos();
            ACC.with(|a| {
                let mut m = a.borrow_mut();
                *m.entry(self.name).or_insert(0) += ns;
            });
        }
    }
}

/// Open the sidecar when the gate is active (the run entry's
/// frame-loop start): `<dest>/.frameprism-profile.tsv` (the
/// dotfile-sidecar pattern), the header row `file \t phase \t ns`.
/// Gate inactive = a no-op guard (the zero default change — no file
/// touched). The returned guard CLOSES (flushes) the writer at the
/// run's end on EVERY path (the RAII form — the early Err returns
/// included). A fresh run truncates (the measurement window is the
/// run's). An open failure = the named note + the run proceeds
/// WITHOUT the sidecar (the profiler never changes the run's
/// behavior — the safe direction).
pub fn open_sidecar(dest: &Path) -> SidecarGuard {
    if !GATE.load(Ordering::Relaxed) {
        return SidecarGuard;
    }
    let path = dest.join(".frameprism-profile.tsv");
    match std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
    {
        Ok(f) => {
            let mut w = BufWriter::new(f);
            let _ = w.write_all(b"file\tphase\tns\n");
            *SIDECAR.lock().unwrap() = Some(w);
        }
        Err(err) => {
            eprintln!(
                "profile: note: cannot open the sidecar {} ({err}) — the run proceeds without the sidecar (the profiler never changes the run's behavior)",
                path.display()
            );
        }
    }
    SidecarGuard
}

/// The sidecar's run-end guard (the close/flush on drop).
pub struct SidecarGuard;

impl Drop for SidecarGuard {
    fn drop(&mut self) {
        if let Some(mut w) = SIDECAR.lock().unwrap().take() {
            let _ = w.flush();
        }
    }
}

/// Flush the CURRENT THREAD's frame rows (one row per completed
/// phase, in the contract order) + clear the accumulator (the
/// per-frame reset — the pool threads' frames never interleave).
/// Called at the frame's completion on EVERY path (Done + Failed —
/// a frame that fails after its read writes the phases it
/// completed). Gate inactive or sidecar unopen = a no-op.
pub(crate) fn flush_frame(file: &str) {
    if !GATE.load(Ordering::Relaxed) {
        return;
    }
    let mut rows: Vec<(&'static str, u128)> = PHASES
        .iter()
        .copied()
        .filter_map(|p| ACC.with(|a| a.borrow().get(p).copied()).map(|ns| (p, ns)))
        .collect();
    // The defensive tail: a phase name outside the contract (a
    // wiring bug) still lands (named, last) — the KAT's
    // no-unknown-phase check turns it loud.
    let mut extras: Vec<(&'static str, u128)> = ACC
        .with(|a| {
            a.borrow()
                .iter()
                .filter(|(k, _)| !PHASES.contains(k))
                .map(|(k, v)| (*k, *v))
                .collect()
        });
    extras.sort();
    rows.extend(extras);
    if rows.is_empty() {
        ACC.with(|a| a.borrow_mut().clear());
        return;
    }
    if let Ok(mut g) = SIDECAR.lock() {
        if let Some(w) = g.as_mut() {
            for (p, ns) in &rows {
                let _ = writeln!(w, "{file}\t{p}\t{ns}");
            }
            let _ = w.flush();
        }
    }
    ACC.with(|a| a.borrow_mut().clear());
}

/// Clear the accumulator WITHOUT a row (the resume-skipped frame's
/// honest no-row contract — the named form: the skip path never
/// writes a row).
pub(crate) fn clear_frame() {
    ACC.with(|a| a.borrow_mut().clear());
}
