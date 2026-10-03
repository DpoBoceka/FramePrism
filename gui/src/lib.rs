//! The headless job runner (the GUI's in-process core surface — NO
//! window or GPU import anywhere in this path: the selftest + the
//! suite run it without a display).
//!
//! The GUI consumes the core IN-PROCESS (the path dependency — no
//! FFI, no facade crate): the encode job is the worker's
//! `process_dir`, the clip list is the camera's offload detection
//! scan (the SAME walk as the copy — the offload key space by
//! construction). The GUI depends on the core directly and
//! re-exports nothing from it.
//!
//! The v1 surface is the encode: the source dir → the clip list → the
//! encode job with per-clip progress. The core exposes no live
//! frame-level progress (the honest unit is the CLIP) and no cancel
//! handle (the job runs to completion — there is no cancel, an
//! honest absence).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// One clip row of the scan (the offload key space — the SAME walk as
/// the copy, by construction). `class` = the detection's class as the
/// core's own stable display string (`profiled <camera> (profile
/// v<n>)` / `unprofiled camera <make> <model>` / `non-DNG media`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClipRow {
    pub key: String,
    pub class: String,
}

/// The shared job state (the per-job `Arc<Mutex<JobState>>` — the
/// std-only shared surface the UI polls at ~4 Hz; the per-job worker
/// thread owns the writes). `total` = the selected clip count (set at
/// the job start) · `done` = the clips that completed clean (a
/// failed clip increments NOTHING — `last_error` names it) ·
/// `current` = the clip key the job is on (set before each clip) ·
/// `finished` + `verdict` are set once, at the loop's end.
#[derive(Clone, Debug, Default)]
pub struct JobState {
    pub total: usize,
    pub done: usize,
    pub current: Option<String>,
    pub last_error: Option<String>,
    pub finished: bool,
    pub verdict: Option<String>,
}

/// The scan: one row per file-bearing clip key (the sorted clip key
/// order). An empty scan = an EMPTY vec (the UI renders the honest
/// `no clips detected` line — never a silent empty list). The error
/// is the core's own named line (the walk failure, the unresolvable
/// tree).
pub fn clips(source: &Path) -> Result<Vec<ClipRow>, String> {
    let scan = frameprism::camera::offload_detections(source)?;
    Ok(scan
        .clips
        .into_iter()
        .map(|c| ClipRow {
            key: c.key,
            class: c.class.line(),
        })
        .collect())
}

/// The GUI is the arbiter of its OWN contract's input domain (the
/// facade precedent — the core remains the arbiter of the encode
/// semantics): the v1 encode surface offers exactly the two modes.
/// `lossless` / `log10` map; anything else is the NAMED refusal
/// (the input string in the line).
pub fn arbiter(mode: &str) -> Result<frameprism::worker::Mode, String> {
    match mode {
        "lossless" => Ok(frameprism::worker::Mode::Lossless),
        "log10" => Ok(frameprism::worker::Mode::Log10),
        other => Err(format!(
            "unsupported mode '{other}' — the gui encode surface offers: lossless, log10"
        )),
    }
}

/// The in-place-dest guard (the first-use incident class): a dest
/// that IS the source, or sits INSIDE it, would be written over by
/// the encode. Both sides are canonicalized (a missing dest = the
/// NOT-inside case — the encode creates it; the guard cannot refuse
/// what does not exist). `Some` = the NAMED refusal line (the job
/// does not start, 0 files written); `None` = the dest is outside.
pub fn in_place_refusal(source: &Path, dest: &Path) -> Option<String> {
    let src = std::fs::canonicalize(source).ok()?;
    let dst = match std::fs::canonicalize(dest) {
        Ok(d) => d,
        Err(_) => return None,
    };
    if dst == src || dst.starts_with(&src) {
        Some(
            "refusal: the destination is inside the source (an in-place encode is refused — the source would be written over)"
                .to_string(),
        )
    } else {
        None
    }
}

/// The job's start transition (the worker thread's first step): the
/// fields reset to the pre-clip baseline, `total` = the selected
/// count.
pub(crate) fn job_begin(state: &mut JobState, total: usize) {
    state.total = total;
    state.done = 0;
    state.current = None;
    state.last_error = None;
    state.finished = false;
    state.verdict = None;
}

/// The pre-clip transition: `current` names the clip BEFORE the
/// encode starts (the UI's "the current clip" row).
pub(crate) fn clip_begin(state: &mut JobState, key: &str) {
    state.current = Some(key.to_string());
}

/// The post-clip transition: a clean clip increments `done`; a
/// failed clip sets `last_error` (the core's display line) and
/// increments NOTHING — the job CONTINUES (the verdict aggregates).
pub(crate) fn clip_result(state: &mut JobState, ok: bool, error: Option<String>) {
    if ok {
        state.done += 1;
    } else if let Some(err) = error {
        state.last_error = Some(err);
    }
}

/// The post-loop transition: `finished` + `verdict`, set once.
pub(crate) fn job_finish(state: &mut JobState) {
    state.finished = true;
    state.verdict = Some(verdict_line(state.total, state.done));
}

/// The VERBATIM verdict line: `rc=0 (all clips clean)` when every
/// selected clip completed clean, else `rc=1 (<k> of <n> clips
/// failed)` (`<k>` = the failed count).
pub(crate) fn verdict_line(total: usize, done: usize) -> String {
    if done == total {
        "rc=0 (all clips clean)".to_string()
    } else {
        format!("rc=1 ({} of {} clips failed)", total - done, total)
    }
}

/// The pre-job checks, in order (each failure = the named line — the
/// job does not start, 0 files written): (1) the source exists + is
/// a dir · (2) the arbiter already ran (the CALLER'S check — the
/// `Mode` parameter is the proof; nothing to re-check in-process) ·
/// (3) the in-place guard · (4) the selected list is non-empty.
///
/// Then the per-job std thread (the facade precedent): `total` = the
/// selected count; per selected clip key (sorted order — the
/// deterministic job order): `input = source.join(key)` (key `""` =
/// the source root — the process_dir semantics, no special case),
/// `output = dest.join(key)`, the core's `process_dir` with the CLI
/// default surface (the mode slot = the arbiter's output). `Ok`
/// increments `done`; `Err` sets `last_error` (the core's display
/// line) + CONTINUES. After the loop: `finished` + `verdict`.
pub fn start_encode(
    source: &Path,
    dest: &Path,
    mode: frameprism::worker::Mode,
    selected: &[String],
    state: Arc<Mutex<JobState>>,
) -> Result<(), String> {
    if !source.is_dir() {
        return Err(format!(
            "refusal: the source dir is missing or not a directory ({})",
            source.display()
        ));
    }
    if let Some(refusal) = in_place_refusal(source, dest) {
        return Err(refusal);
    }
    if selected.is_empty() {
        return Err("refusal: no clips selected (the selection is empty)".to_string());
    }
    let mut keys: Vec<String> = selected.to_vec();
    keys.sort();
    let total = keys.len();
    let source = source.to_path_buf();
    let dest = dest.to_path_buf();
    std::thread::spawn(move || {
        {
            // The per-job lock (this thread is the sole writer until
            // the UI polls; a poisoned lock = an earlier panic —
            // the named unwind, not a silent skip).
            let mut s = state.lock().unwrap();
            job_begin(&mut s, total);
        }
        for key in &keys {
            {
                let mut s = state.lock().unwrap();
                clip_begin(&mut s, key);
            }
            // The CLI default surface (the encode parity contract —
            // the mode slot = the arbiter's output; every other slot
            // = the CLI default as of the encode verb's call site).
            let res = frameprism::worker::process_dir(
                &source.join(key),
                &dest.join(key),
                false, // verify — the CLI default
                false, // force — the CLI default
                0, // jobs — the default pool (all cores)
                mode, // the arbiter's output
                false, // downscale — the CLI default
                false, // fast — the CLI default
                false, // checksums — the CLI default
                frameprism::worker::LossyFormat::ReferenceDct, // the CLI default
                &frameprism::worker::ReferenceDctOpts {
                    reference_ref: None,
                    reference_mae_tsv: None,
                    reference_structure_tsv: None,
                }, // the CLI default construction
                None, // to — the CLI default
                false, // qc_gate — the CLI default
            );
            let mut s = state.lock().unwrap();
            match res {
                Ok(_) => clip_result(&mut s, true, None),
                Err(err) => clip_result(&mut s, false, Some(err.to_string())),
            }
        }
        let mut s = state.lock().unwrap();
        job_finish(&mut s);
    });
    Ok(())
}

// ---------------------------------------------------------------------
// The headless selftest (the R4 surface — the gate's teeth; NO window,
// NO GPU — the lib path only). The bin's `--selftest` mode calls
// `selftest()` and prints the VERBATIM OK / FAIL line.
// ---------------------------------------------------------------------

/// The committed oracle fixture (the selftest's one-frame encode
/// input — the template frame of the 10-frame synthetic oracle).
const FIXTURE_REL: &str = "ci/oracle10/src/FPTEST_012_20000101_000001.DNG";

/// The committed camera profile (the explicit-profile-file seam — the
/// `FRAMEPRISM_PROFILES` env: the deterministic test surface; the
/// encode refuses without a resolvable profile set).
const PROFILE_REL: &str = "profiles/a001-sigma-fp.profile";

/// The checkout root from this crate's manifest dir (the lib test's
/// cwd is the gui/ package dir; the gate's cwd is the repo root).
fn checkout_root() -> Option<PathBuf> {
    Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("..").to_path_buf())
}

/// The committed fixture's path (two lookup roots: the repo root
/// under the cwd — the gate's run shape — and the checkout root from
/// the manifest dir — the cargo-test run shape). `None` = the named
/// refusal (the selftest never runs without the committed fixture).
pub(crate) fn committed_fixture() -> Option<PathBuf> {
    let via_cwd = std::env::current_dir().ok()?.join(FIXTURE_REL);
    if via_cwd.is_file() {
        return Some(via_cwd);
    }
    let via_checkout = checkout_root()?.join(FIXTURE_REL);
    if via_checkout.is_file() {
        return Some(via_checkout);
    }
    None
}

/// The poll (the job-state reader — the UI's snapshot of the shared
/// state; the per-job worker thread owns the writes).
pub fn poll(state: &Arc<Mutex<JobState>>) -> JobState {
    state.lock().unwrap().clone()
}

/// Poll to `finished` (the bounded wait — a named refusal at the
/// deadline, never a silent hang).
pub(crate) fn wait_finished(state: &Arc<Mutex<JobState>>, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if poll(state).finished {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// A fresh /tmp scratch dir (the unique suffix — the process id + the
/// nanos since the epoch).
pub(crate) fn scratch_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("fp-gui-{tag}-{}-{nanos}", std::process::id()))
}

// ---------------------------------------------------------------------
// The selftest's stdout guard (the exact-stdout contract).
//
// The core's live-metrics per-frame lines ride STDOUT (the core's
// contract: stdout is NOT a byte contract — the verdict/total lines
// keep their shape). The selftest's stdout contract is the single
// VERBATIM OK line (one line, stdout), so the job's window redirects
// the process stdout to /dev/null (the Drop restores it before the OK
// line prints). The no-new-crates rule: raw FFI via `extern "C"` +
// std only (the core's live.rs pattern).
// ---------------------------------------------------------------------

#[cfg(unix)]
mod stdout_guard_unix {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

    extern "C" {
        fn dup(fd: i32) -> i32;
        fn dup2(oldfd: i32, newfd: i32) -> i32;
    }

    /// The guard (the Drop restores fd 1 to the pre-job state).
    pub struct Guard {
        saved: OwnedFd,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            // fd 1 rode /dev/null for the job's window — restore the
            // saved copy (the OK line prints on the original fd).
            let _ = unsafe { dup2(self.saved.as_raw_fd(), 1) };
        }
    }

    pub fn start() -> Result<Guard, String> {
        // A writable /dev/null (the job's stdout sink — the core's
        // per-frame live lines + the run lines land here, never on
        // the selftest's stdout).
        let devnull = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .map_err(|err| format!("the /dev/null open failed: {err}"))?;
        let dn = unsafe { OwnedFd::from_raw_fd(devnull.into_raw_fd()) };
        let saved_raw = unsafe { dup(1) };
        if saved_raw < 0 {
            drop(dn);
            return Err("the stdout save (dup) failed".to_string());
        }
        let saved = unsafe { OwnedFd::from_raw_fd(saved_raw) };
        if unsafe { dup2(dn.as_raw_fd(), 1) } < 0 {
            drop(dn);
            return Err("the stdout redirect (dup2) failed".to_string());
        }
        drop(dn); // the dup2 copied the fd — our copy is done (the close)
        Ok(Guard { saved })
    }
}

/// The stdout guard (the unix job-window redirect — the named refusal
/// on the non-unix targets: the core's live-metrics lines would ride
/// the selftest's stdout, and a false OK line is never printed).
pub(crate) enum StdoutGuard {
    /// The unix redirect (the guard acts by Drop — the field is never
    /// READ, only dropped: the saved fd 1 copy is restored in the
    /// Drop; the dead-code allow is the RAII reason, documented).
    #[allow(dead_code)]
    #[cfg(unix)]
    Unix(stdout_guard_unix::Guard),
    #[cfg(not(unix))]
    None,
}

pub(crate) fn start_stdout_guard() -> Result<StdoutGuard, String> {
    #[cfg(unix)]
    {
        Ok(StdoutGuard::Unix(stdout_guard_unix::start()?))
    }
    #[cfg(not(unix))]
    {
        Err(
            "the stdout guard is unavailable on this platform (the core's live-metrics per-frame lines would ride the selftest's stdout — the exact-stdout contract is the unix gate/dev surface)"
                .to_string(),
        )
    }
}

/// The headless selftest (the steps: a fresh /tmp scratch dir → copy
/// the committed fixture into `<scratch>/src/SELFTEST_CLIP/` →
/// `clips(src)` asserts exactly one row (the `SELFTEST_CLIP` key) →
/// `start_encode` (lossless, the clip selected) → poll to `finished`
/// → the VERBATIM verdict + the output DNG exists + is non-empty →
/// the scratch dir deleted). Runs on a CLEAN CHECKOUT (the committed
/// fixture only — no corpus, no external tool, no network). The
/// LIGHT fence class (one frame). `Err` = the named reason (the
/// bin's FAIL line).
pub fn selftest() -> Result<(), String> {
    // The deterministic profile seam (the explicit profile FILE —
    // the encode refuses without a resolvable profile set; the
    // committed file is checkout-root-relative).
    let profile = checkout_root()
        .and_then(|root| {
            let p = root.join(PROFILE_REL);
            p.is_file().then_some(p)
        })
        .ok_or_else(|| {
            format!(
                "the committed profile is missing ({PROFILE_REL} under the checkout root)"
            )
        })?;
    std::env::set_var("FRAMEPRISM_PROFILES", &profile);

    let fixture =
        committed_fixture().ok_or_else(|| {
            format!(
                "the committed fixture is missing ({FIXTURE_REL} under the repo root)"
            )
        })?;

    // (1) the fresh /tmp scratch dir (the unique suffix). The R4
    // layout: the source root = `<scratch>/src`; the fixture rides
    // `<scratch>/src/SELFTEST_CLIP/` (the key space is the
    // source-root-relative — the scan + the job join the key onto the
    // root).
    let scratch = scratch_dir("selftest");
    let src = scratch.join("src");
    let clip = src.join("SELFTEST_CLIP");
    let dest = scratch.join("dest");
    std::fs::create_dir_all(&clip).map_err(|err| {
        format!("the scratch dir cannot be created ({}): {err}", clip.display())
    })?;

    // (2) copy the committed fixture into the SELFTEST_CLIP dir.
    std::fs::copy(&fixture, clip.join(fixture.file_name().unwrap_or_default()))
        .map_err(|err| format!("copying the committed fixture failed: {err}"))?;

    // (3) the scan: exactly one row (the SELFTEST_CLIP key).
    let rows = clips(&src)
        .map_err(|err| format!("the clip scan failed: {err}"))?;
    if rows.len() != 1 || rows[0].key != "SELFTEST_CLIP" {
        return Err(format!(
            "the clip scan returned {} row(s) (keys: {}), expected exactly one (the SELFTEST_CLIP key)",
            rows.len(),
            rows.iter().map(|r| r.key.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }

    // (4) the encode job (lossless, the clip selected) → poll to
    // finished (the bounded wait). The job's window rides the stdout
    // guard (the core's per-frame live lines are /dev/null-bound; the
    // selftest's stdout stays the single OK line).
    let mode = arbiter("lossless").map_err(|err| err.to_string())?;
    let guard = start_stdout_guard()?;
    let state = Arc::new(Mutex::new(JobState::default()));
    start_encode(&src, &dest, mode, &["SELFTEST_CLIP".to_string()], state.clone())
        .map_err(|err| err.to_string())?;
    if !wait_finished(&state, std::time::Duration::from_secs(120)) {
        return Err("the encode job did not finish within the 120 s timeout".to_string());
    }
    drop(guard);

    // (5) the VERBATIM verdict + the output DNG exists + non-empty.
    let snap = poll(&state);
    if snap.verdict.as_deref() != Some("rc=0 (all clips clean)") {
        return Err(format!(
            "the verdict is {:?}, expected 'rc=0 (all clips clean)'",
            snap.verdict
        ));
    }
    let out = dest
        .join("SELFTEST_CLIP")
        .join(fixture.file_name().unwrap_or_default());
    let len = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    if len == 0 {
        return Err(format!("the output DNG is missing or empty ({})", out.display()));
    }

    // (6) the scratch dir deleted (best effort — the leak is a
    // named residual, never silent).
    if let Err(err) = std::fs::remove_dir_all(&scratch) {
        return Err(format!(
            "the scratch dir could not be deleted ({}): {err}",
            scratch.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // The four named lib tests (the pinned-wording surface — the
    // suite prediction's N = 4).
    use super::*;

    // The process-global env seam (the `FRAMEPRISM_PROFILES` set by
    // the encode test): the tool's own suite holds a process-wide
    // env lock for exactly this class — here the encode test is the
    // sole reader + writer of the seam within this binary (the other
    // three tests touch no env), so the lock documents + guards the
    // isolation.
    static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn scratch(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("fp-gui-test-{tag}-{}-{nanos}", std::process::id()))
    }

    #[test]
    fn arbiter_maps_and_refuses() {
        assert_eq!(
            arbiter("lossless").unwrap(),
            frameprism::worker::Mode::Lossless
        );
        assert_eq!(
            arbiter("log10").unwrap(),
            frameprism::worker::Mode::Log10
        );
        let err = arbiter("vbr-hq").unwrap_err();
        assert_eq!(
            err,
            "unsupported mode 'vbr-hq' — the gui encode surface offers: lossless, log10"
        );
    }

    #[test]
    fn in_place_guard() {
        let src = scratch("in-place-src");
        std::fs::create_dir_all(&src).unwrap();
        // dest == source → the VERBATIM refusal.
        assert_eq!(
            in_place_refusal(&src, &src),
            Some(
                "refusal: the destination is inside the source (an in-place encode is refused — the source would be written over)"
                    .to_string()
            )
        );
        // dest = source/"inner" (the existing inner dir) → the
        // VERBATIM refusal.
        let inner = src.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        assert_eq!(
            in_place_refusal(&src, &inner),
            Some(
                "refusal: the destination is inside the source (an in-place encode is refused — the source would be written over)"
                    .to_string()
            )
        );
        // dest = sibling → None (the NOT-inside case).
        let sibling = scratch("in-place-sib");
        std::fs::create_dir_all(&sibling).unwrap();
        assert_eq!(in_place_refusal(&src, &sibling), None);
        // a missing dest = the NOT-inside case (the encode creates
        // it) → None.
        assert_eq!(in_place_refusal(&src, &src.join("absent-dest")), None);
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&sibling);
    }

    #[test]
    fn selftest_encode_headless() {
        let _env = TEST_ENV_LOCK.lock().unwrap();
        // The deterministic profile seam (the explicit profile FILE —
        // the encode refuses without a resolvable profile set).
        let profile = checkout_root().unwrap().join(PROFILE_REL);
        assert!(profile.is_file(), "the committed profile is missing");
        std::env::set_var("FRAMEPRISM_PROFILES", &profile);

        let fixture = committed_fixture().expect("the committed fixture");
        // The R4 layout: the source root = <scratch>/src; the fixture
        // rides <scratch>/src/SELFTEST_CLIP/ (the key space is the
        // source-root-relative — start_encode joins the key onto the
        // root it is given).
        let scratch = scratch("selftest");
        let root = scratch.join("src");
        let clip = root.join("SELFTEST_CLIP");
        let dest = scratch.join("dest");
        std::fs::create_dir_all(&clip).unwrap();
        std::fs::copy(&fixture, clip.join(fixture.file_name().unwrap())).unwrap();

        let mode = arbiter("lossless").unwrap();
        let state = Arc::new(Mutex::new(JobState::default()));
        start_encode(&root, &dest, mode, &["SELFTEST_CLIP".to_string()], state.clone()).unwrap();
        assert!(
            wait_finished(&state, std::time::Duration::from_secs(120)),
            "the encode job did not finish within the 120 s timeout"
        );

        let snap = poll(&state);
        assert_eq!(snap.verdict.as_deref(), Some("rc=0 (all clips clean)"));
        assert_eq!(snap.done, 1);
        assert_eq!(snap.total, 1);
        assert!(!snap.last_error.is_some());

        let out = dest
            .join("SELFTEST_CLIP")
            .join(fixture.file_name().unwrap());
        assert!(out.is_file(), "the output DNG is missing ({out:?})");
        assert!(std::fs::metadata(&out).unwrap().len() > 0);

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn job_state_transitions() {
        // A fresh JobState (the default fields) — the R3.1
        // transitions, exactly: pre-clip / clip-Ok / clip-Err /
        // post-loop.
        let mut s = JobState::default();
        job_begin(&mut s, 2);
        // pre-clip (clip 1): the baseline + the current key.
        assert_eq!((s.total, s.done, s.current.as_deref(), s.last_error.is_some(), s.finished, s.verdict.is_some()),
            (2, 0, None, false, false, false));
        clip_begin(&mut s, "clip-a");
        assert_eq!(s.current.as_deref(), Some("clip-a"));
        // clip-a Ok: done increments.
        clip_result(&mut s, true, None);
        assert_eq!((s.done, s.last_error.is_some()), (1, false));
        // clip-b: the current key moves; the clip FAILS —
        // last_error is set, done NOT incremented (the job continues).
        clip_begin(&mut s, "clip-b");
        assert_eq!(s.current.as_deref(), Some("clip-b"));
        clip_result(&mut s, false, Some("FAIL clip-b: the named core line".to_string()));
        assert_eq!((s.done, s.last_error.as_deref()), (1, Some("FAIL clip-b: the named core line")));
        // post-loop: finished + the VERBATIM mixed-case verdict.
        job_finish(&mut s);
        assert!(s.finished);
        assert_eq!(s.verdict.as_deref(), Some("rc=1 (1 of 2 clips failed)"));
        // the clean-case verdict (the same surface).
        let mut t = JobState::default();
        job_begin(&mut t, 1);
        clip_begin(&mut t, "clip-a");
        clip_result(&mut t, true, None);
        job_finish(&mut t);
        assert_eq!(t.verdict.as_deref(), Some("rc=0 (all clips clean)"));
    }
}
