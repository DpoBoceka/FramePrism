//! The headless job runner (the GUI's in-process core surface — NO
//! window or GPU import anywhere in this path: the selftest + the
//! suite run it without a display).
//!
//! The GUI consumes the core IN-PROCESS (the path dependency — no
//! FFI, no facade crate): a job is a list of LEGS (the Process
//! ruling — one job composer replaces Encode + Archive + Export):
//! each leg = a mode (Encode / Mirror / Derive / Decode) + a dest +
//! the per-mode options, run IN LEG ORDER on a single job thread over
//! the ONE session source (one source tree — no per-leg source
//! override). The Encode leg is the v1 per-clip `process_dir` loop
//! (the machinery refactored into the leg runner); the Mirror leg is
//! the offload's single-source Legacy form; the Derive / Decode legs
//! are the core verbs' `run` (read-only over the source).
//!
//! Each leg runs under the per-leg STREAM CAPTURE: both fd 1 and fd 2
//! redirected to a per-leg capture file (the unix-only contract —
//! the v1 stdout-guard pattern generalized; the fds are restored on
//! drop). The core's stream output is NOT a byte contract — the
//! capture is for the user's reading (it mirrors what the equivalent
//! CLI run prints to the terminal — both streams), never parsed for
//! semantics, except the per-leg summary's LAST NON-EMPTY line (the
//! core's own summary line, verbatim).
//!
//! The process-wide statics are set EXPLICITLY at each leg start +
//! reset (false) at the job end (the corpus-KAT pattern — the job
//! owns the statics during the run). No cancel (the job runs to
//! completion — an honest absence, not a hidden one; the core
//! exposes no cancel handle).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------
// The leg model (the R3.2 surface — the lib model, not the UI).
// ---------------------------------------------------------------------

/// The leg's mode (the four offered by the mode select).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegMode {
    /// The v1 encode surface (the per-clip `process_dir` loop).
    Encode,
    /// The standalone offload (the single-source Legacy form — the
    /// verified copy + the per-clip manifests; copies ANY tree).
    Mirror,
    /// The 12→8/10 derived working tier (read-only over the source).
    Derive,
    /// The decode (the encoded clip dir → per-frame 16-bit PAM).
    Decode,
}

impl LegMode {
    /// The per-leg report line's lowercase mode slot (the R4.3 pin).
    pub fn line(self) -> &'static str {
        match self {
            LegMode::Encode => "encode",
            LegMode::Mirror => "mirror",
            LegMode::Derive => "derive",
            LegMode::Decode => "decode",
        }
    }

    /// The UI select label.
    pub fn label(self) -> &'static str {
        match self {
            LegMode::Encode => "Encode",
            LegMode::Mirror => "Mirror",
            LegMode::Derive => "Derive",
            LegMode::Decode => "Decode",
        }
    }
}

/// The Derive leg's depth slot (the pinned v>>4 / v>>2 mapping).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeriveBits {
    /// 12→8: v >> 4 (the default).
    Eight,
    /// 12→10: v >> 2.
    Ten,
}

impl DeriveBits {
    /// The 1:1 core mapping (the core's variant names are `B8` / `B10`).
    pub fn as_bits(self) -> frameprism::derived::Bits {
        match self {
            DeriveBits::Eight => frameprism::derived::Bits::B8,
            DeriveBits::Ten => frameprism::derived::Bits::B10,
        }
    }

    /// The UI select label (the mockup's slot wording).
    pub fn label(self) -> &'static str {
        match self {
            DeriveBits::Eight => "8-bit (v>>4)",
            DeriveBits::Ten => "10-bit (v>>2)",
        }
    }
}

/// The leg row's status (the NAMED lines are the contract — the GUI's
/// arbiter lines are pinned verbatim; the core's named lines ride
/// `Failed` / the post-Run `Clean` summary).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LegStatus {
    /// The pre-Run idle token (the UI renders `—`).
    Idle,
    /// The pre-Run ready token (the Mirror leg, the UNIDENTIFIED
    /// contrast ONLY — the offload never gates on identity).
    Ready,
    /// The leg is running on the job thread.
    Running,
    /// The leg completed rc=0.
    Clean,
    /// The leg's core call returned rc≠0 (the core's NAMED line — the
    /// last non-empty captured line, verbatim).
    Failed { line: String },
    /// The pre-Run refusal (the identity refusal / the in-place
    /// guard — the core is NEVER called for the leg; `note` = the
    /// composing second named line (the in-place guard) when it
    /// also applies — the evaluation order names the identity
    /// refusal FIRST).
    Refused { line: String, note: Option<String> },
}

/// One composer leg (the R3.2 record): the mode + the DEST side
/// (path + the per-mode options) + the run state. There is NO
/// per-leg source (the session source is the only source input —
/// the Decode leg's input = the session source, the ruling's named
/// exception: the session must point at an encoded tree, enforced as
/// the core's NAMED refusal, not a GUI guess).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leg {
    pub mode: LegMode,
    pub dest: PathBuf,
    /// The Encode leg's verify toggle (default OFF — the set-up
    /// default; the NEW CAMERA strip state locks it ON — the core's
    /// unpinned contract: verify-on, no temporal acceptance). The
    /// Mirror leg's verify is inherent (the offload contract — there
    /// is no off switch).
    pub verify: bool,
    /// The Derive leg's depth slot.
    pub bits: DeriveBits,
    pub status: LegStatus,
    /// The per-leg summary line (the R4.3 report content).
    pub summary: String,
    /// The per-leg raw log (the captured stream output, verbatim —
    /// the non-unix honesty line where the capture is unavailable).
    pub log: String,
}

impl Leg {
    /// The `+ add leg` default (dest empty, mode Encode, verify OFF,
    /// 8-bit, idle).
    pub fn default_leg() -> Self {
        Self {
            mode: LegMode::Encode,
            dest: PathBuf::new(),
            verify: false,
            bits: DeriveBits::Eight,
            status: LegStatus::Idle,
            summary: String::new(),
            log: String::new(),
        }
    }
}

impl Default for Leg {
    fn default() -> Self {
        Self::default_leg()
    }
}

// ---------------------------------------------------------------------
// The session scan + the identity strip (the 3 scan-derived states).
// ---------------------------------------------------------------------

/// The session scan (the offload detection scan + the resolved
/// profile set — the strip's inputs). The scan walks the SAME
/// collect discipline as the offload copy (the offload key space by
/// construction); it is READ-ONLY + pre-copy — the detection NEVER
/// gates (identity never refuses the offload).
#[derive(Clone, Debug)]
pub struct Scan {
    /// One row per file-bearing clip key (the sorted clip key order;
    /// `""` = the source root).
    pub clips: Vec<frameprism::camera::ClipDetection>,
    /// The scan's `profiles:` line (the ABSENT honesty line when no
    /// set resolves — the UI displays it verbatim, no re-derivation).
    pub profiles_line: String,
    /// The resolved profile set (the strip's sub-line source) —
    /// `None` when no set resolves.
    pub set: Option<frameprism::camera::ProfileSet>,
}

/// The session scan (the core's `offload_detections` + the
/// `resolve_profiles` set — the env seam is the CALLER'S contract:
/// the `FRAMEPRISM_PROFILES` env must carry the seam's effective
/// value before this call).
pub fn scan(source: &Path) -> Result<Scan, String> {
    let det = frameprism::camera::offload_detections(source)?;
    let set = frameprism::camera::resolve_profiles().ok();
    Ok(Scan {
        clips: det.clips,
        profiles_line: det.profiles_line,
        set,
    })
}

impl Scan {
    /// The clip keys in scan order (the sorted clip key order — the
    /// deterministic job order; the Encode leg consumes the WHOLE
    /// source tree: per-clip selection is retired).
    pub fn clip_keys(&self) -> Vec<String> {
        self.clips.iter().map(|c| c.key.clone()).collect()
    }

    /// The strip state derived from the per-clip detection classes.
    pub fn strip_state(&self) -> StripState {
        strip_state_of(&self.clips)
    }
}

/// The strip's 3 scan-derived states (the SETUP MISMATCH state is
/// NOT a strip state — the core's 3-class detection contract
/// collapses the mismatch into `Unprofiled` at scan level; it
/// surfaces at RUN time on the leg as the core's named refusal, and
/// the details panel's legend names it as the run-time state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StripState {
    /// Every file-bearing clip is profiled (a measured setup matches).
    SetUp,
    /// Every file-bearing clip self-describes unprofiled (the frames
    /// self-describe; running verified, no temporal acceptance).
    NewCamera,
    /// No identity (a non-DNG clip / a no-value identity / no clips).
    Unidentified,
}

/// The strip state derivation from the per-clip `DetectionClass` (the
/// total function): UNIDENTIFIED first (the no-clips rule: an empty
/// scan, any `NonDng` clip, any `unprofiled camera - -` clip), then
/// SET UP (every clip `Profiled`), then NEW CAMERA (the remainder:
/// every clip self-describes unprofiled — incl. the mixed
/// `Profiled` + `Unprofiled` trees, the mismatch class's honest
/// state: a mismatched frame is classified `Unprofiled` by the core's
/// 3-class contract, indistinguishable from a true new camera at
/// scan level).
pub fn strip_state_of(clips: &[frameprism::camera::ClipDetection]) -> StripState {
    use frameprism::camera::DetectionClass as D;
    if clips.is_empty() {
        return StripState::Unidentified;
    }
    for c in clips {
        match &c.class {
            D::NonDng => return StripState::Unidentified,
            D::Unprofiled { make, model } if make == "-" && model == "-" => {
                return StripState::Unidentified
            }
            _ => {}
        }
    }
    if clips.iter().all(|c| matches!(c.class, D::Profiled { .. })) {
        StripState::SetUp
    } else {
        StripState::NewCamera
    }
}

/// The UNIDENTIFIED strip line (the R2.3 pin).
pub const UNIDENTIFIED_LINE: &str = "no camera identity in the frames";
/// The UNIDENTIFIED strip sub-line (the R2.3 pin).
pub const UNIDENTIFIED_SUBLINE: &str =
    "no setup resolves for this tree — the Encode leg is refused; the Mirror leg still runs (offload copies any tree)";
/// The NEW CAMERA strip sub-line (the R2.2 pin).
pub const NEW_CAMERA_SUBLINE: &str = "running verified · the setup is not measured yet";

/// The strip's camera line + sub-line (the class fields, the GUI's
/// own formatting — no frame reads; the version text is OMITTED —
/// the base exposes no tool-version seam, the named honesty: the gui
/// crate version is NOT the tool version).
pub fn strip_lines(
    state: StripState,
    clips: &[frameprism::camera::ClipDetection],
    set: &Option<frameprism::camera::ProfileSet>,
) -> (String, String) {
    match state {
        StripState::SetUp => {
            let line = clips
                .iter()
                .find_map(|c| match &c.class {
                    frameprism::camera::DetectionClass::Profiled {
                        camera,
                        profile_version,
                    } => Some(format!("{camera} (profile v{profile_version})")),
                    _ => None,
                })
                .unwrap_or_else(|| UNIDENTIFIED_LINE.to_string());
            let sub = set
                .as_ref()
                .map(|s| format!("setup: {}", s.source))
                .unwrap_or_else(|| UNIDENTIFIED_SUBLINE.to_string());
            (line, sub)
        }
        StripState::NewCamera => {
            let line = clips
                .iter()
                .find_map(|c| match &c.class {
                    frameprism::camera::DetectionClass::Unprofiled { make, model }
                        if make != "-" =>
                    {
                        Some(format!("{make} {model}"))
                    }
                    _ => None,
                })
                .unwrap_or_else(|| UNIDENTIFIED_LINE.to_string());
            (line, NEW_CAMERA_SUBLINE.to_string())
        }
        StripState::Unidentified => {
            (UNIDENTIFIED_LINE.to_string(), UNIDENTIFIED_SUBLINE.to_string())
        }
    }
}

/// The details panel's resolution line: `setup: <ProfileSet.source> ·
/// <the scan's profiles_line>` (the version omitted — no seam; the
/// `profiles_line` carries the ABSENT honesty line when no set
/// resolves — the GUI displays it verbatim, no re-derivation).
pub fn resolution_line(set: &Option<frameprism::camera::ProfileSet>, profiles_line: &str) -> String {
    match set {
        Some(s) => format!("setup: {} · {profiles_line}", s.source),
        None => profiles_line.to_string(),
    }
}

/// The 4-state legend (the details panel — the mockup's off-surface
/// "why" moved into the app disclosure; the strip surface stays
/// copy-only). SETUP MISMATCH is named as the run-time state (the
/// 3-class collapse — the strip itself shows the 3 scan-derived
/// states).
pub const LEGEND: [&str; 4] = [
    "SET UP — a measured setup matches",
    "NEW CAMERA — the frames self-describe; running verified, no temporal acceptance",
    "UNIDENTIFIED — no identity, no setup (the Encode leg is refused)",
    "SETUP MISMATCH — the setup disagrees with the frames (the named refusal at run time)",
];

// ---------------------------------------------------------------------
// The v1 surface (the pinned-wording core — UNCHANGED).
// ---------------------------------------------------------------------

/// One clip row of the scan (the offload key space — the SAME walk as
/// the copy, by construction). `class` = the detection's class as the
/// core's own stable display string (`profiled <camera> (profile
/// v<n>)` / `unprofiled camera <make> <model>` / `non-DNG media`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClipRow {
    pub key: String,
    pub class: String,
}

/// The scan: one row per file-bearing clip key (the sorted clip key
/// order). An empty scan = an EMPTY vec (the UI renders the honest
/// state — never a silent empty list). The error is the core's own
/// named line (the walk failure, the unresolvable tree).
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
/// semantics): the Advanced `mode` slot offers exactly the two modes.
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
/// the leg. Both sides are canonicalized (a missing dest = the
/// NOT-inside case — the leg creates it; the guard cannot refuse
/// what does not exist). `Some` = the NAMED refusal line (the leg
/// does not run, 0 files written); `None` = the dest is outside.
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

/// The profile env seam (the R2 semantics, the pure testable half):
/// the trimmed `field` when non-empty, ELSE the trimmed `launch_env`
/// when non-empty, ELSE `None` (= nothing to write to the env — the
/// core's own probe order, `<cwd>/profiles` → `<exe-dir>/profiles`,
/// stands untouched). The GUI process is the SOLE owner of the env
/// seam (the v1 precedent — the process-global `set_var` before the
/// core calls that read it: the scan + the legs + the maintenance).
pub fn profile_env_seam(field: &str, launch_env: &str) -> Option<String> {
    let field = field.trim();
    if !field.is_empty() {
        return Some(field.to_string());
    }
    let launch_env = launch_env.trim();
    if launch_env.is_empty() {
        None
    } else {
        Some(launch_env.to_string())
    }
}

// ---------------------------------------------------------------------
// The pre-Run arbiter (the leg-level NAMED refusals).
// ---------------------------------------------------------------------

/// The VERBATIM identity refusal line (the mockup's wording — the
/// Encode leg at the UNIDENTIFIED strip state; the core is never
/// called for the refused leg). The core's own undetermined refusal
/// (the rc=2 named line, zero frames touched) REMAINS the final gate:
/// if the state changed between the scan and the leg, the core's
/// named line rides the leg status verbatim — the GUI's arbiter is
/// the honesty layer, the core is the contract.
pub const REFUSED_NO_SETUP: &str =
    "refused — no setup for this camera, the frames do not self-describe (rc=2)";

/// The VERBATIM ready line (the Mirror leg at the UNIDENTIFIED strip
/// state — the offload never gates on identity: it copies any tree).
pub const READY_WILL_RUN: &str = "ready — will run";

/// The pre-Run arbiter (the leg-level refusals — pure: the mode + the
/// last scan's strip state + the source/dest paths; NO core call).
/// Evaluation order (named in the tests): the identity refusal FIRST,
/// then the in-place guard (a composing in-place line rides the
/// `note`), then the ready contrast. Every other leg = the idle
/// token.
pub fn pre_job_status(mode: LegMode, strip: StripState, source: &Path, dest: &Path) -> LegStatus {
    let in_place = in_place_refusal(source, dest);
    if mode == LegMode::Encode && strip == StripState::Unidentified {
        return LegStatus::Refused {
            line: REFUSED_NO_SETUP.to_string(),
            note: in_place,
        };
    }
    if let Some(line) = in_place {
        return LegStatus::Refused {
            line,
            note: None,
        };
    }
    if mode == LegMode::Mirror && strip == StripState::Unidentified {
        return LegStatus::Ready;
    }
    LegStatus::Idle
}

// ---------------------------------------------------------------------
// The run knobs + the per-leg core calls (the R4.1 surface — the M0
// re-read signatures; the pure construction half is field-by-field
// testable).
// ---------------------------------------------------------------------

/// The per-run options (the Advanced row's knobs — each mapped to the
/// exact core surface). `jobs` = 0 (the default pool — the numeric
/// field is a follow-up; the surface shows `auto`). `carry` is NOT a
/// GUI knob (the (T) transcode default — `set_carry_flag(false)`
/// explicit, the `--carry` opt-in stays CLI-only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunKnobs {
    /// The Encode leg's `Mode` arg (the arbiter's output).
    pub encode_mode: frameprism::worker::Mode,
    /// The strict posture (`camera::set_pinned_only` — explicit
    /// per-job set/reset).
    pub strict: bool,
    /// The trial flag (`worker::set_trial_flag` — explicit
    /// per-job set/reset).
    pub trial: bool,
    /// The `force` arg (Encode) / the `force` flag (Derive/Decode).
    pub force: bool,
    /// The `fast` arg (`process_dir`).
    pub fast: bool,
    /// The `downscale` arg (the `downscale2x` slot).
    pub downscale: bool,
    /// The `checksums` arg.
    pub checksums: bool,
    /// The `jobs` arg (0 = the default pool).
    pub jobs: usize,
}

impl Default for RunKnobs {
    fn default() -> Self {
        Self {
            encode_mode: frameprism::worker::Mode::Lossless,
            strict: false,
            trial: false,
            force: false,
            fast: false,
            downscale: false,
            checksums: false,
            jobs: 0,
        }
    }
}

/// The Encode leg's per-clip call (the v1 CLI default surface — the
/// verify slot = the leg's verify; every other slot = the Advanced
/// knobs / the CLI default). Key `""` = the source root (the
/// `process_dir` semantics — no special case).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodeCall {
    pub input: PathBuf,
    pub output: PathBuf,
    pub verify: bool,
    pub force: bool,
    pub jobs: usize,
    pub mode: frameprism::worker::Mode,
    pub downscale: bool,
    pub fast: bool,
    pub checksums: bool,
}

/// The Encode leg's per-clip call construction (the field-by-field
/// testable half).
pub fn encode_call(
    source: &Path,
    dest: &Path,
    key: &str,
    verify: bool,
    knobs: &RunKnobs,
) -> EncodeCall {
    EncodeCall {
        input: source.join(key),
        output: dest.join(key),
        verify,
        force: knobs.force,
        jobs: knobs.jobs,
        mode: knobs.encode_mode,
        downscale: knobs.downscale,
        fast: knobs.fast,
        checksums: knobs.checksums,
    }
}

/// The Mirror leg's core call (the single-source Legacy form — the
/// positional input + the positional dest; the core's own pre-write
/// bands fire named + rc=2 BEFORE any copy: self-mirror, duplicate
/// dest, writability — the GUI surfaces the core's lines).
pub fn mirror_args(source: &Path, dest: &Path) -> frameprism::offload::Args {
    frameprism::offload::Args {
        input: Some(source.to_path_buf()),
        source: vec![],
        dest: vec![],
        to: vec![dest.to_path_buf()],
    }
}

/// The Derive leg's core call (read-only over the source — the
/// ruling: Derive/Decode read the source read-only).
pub fn derive_args(
    source: &Path,
    dest: &Path,
    bits: DeriveBits,
    force: bool,
) -> frameprism::derived::Args {
    frameprism::derived::Args {
        input: source.to_path_buf(),
        output: dest.to_path_buf(),
        bits: bits.as_bits(),
        force,
    }
}

/// The Decode leg's core call (the default binary resolution — the
/// core's named line if the pinned binaries don't resolve; the frame
/// slot = `all` — the one-frame pick is a follow-up).
pub fn decode_args(source: &Path, dest: &Path, force: bool) -> frameprism::decode::Args {
    frameprism::decode::Args {
        input: source.to_path_buf(),
        output: dest.to_path_buf(),
        codec: frameprism::decode::Codec::J92,
        frame: None,
        jobs: 0,
        force,
        cjxl_bin: PathBuf::from("cjxl"),
        djxl_bin: PathBuf::from("djxl"),
    }
}

// ---------------------------------------------------------------------
// The shared job state (the per-job `Arc<Mutex<JobState>>` — the
// std-only shared surface the UI polls at ~4 Hz; the per-job worker
// thread owns the writes). The legs are tracked IN LEG ORDER: the
// per-leg status/summary/log fill in as they complete; the clip
// progress (the Encode leg's per-clip rows) rides the current leg.
// ---------------------------------------------------------------------

/// One leg's shared progress (the per-leg slot of the job state).
#[derive(Clone, Debug)]
pub struct LegProgress {
    pub status: LegStatus,
    /// The per-leg summary (filled at the leg's completion).
    pub summary: String,
    /// The per-leg raw log (the captured stream output — filled at
    /// the leg's completion).
    pub log: String,
    /// The last per-clip error (the Encode leg — the core's display
    /// line; a failed clip increments NOTHING, the job CONTINUES).
    pub last_error: Option<String>,
    /// The clip key the leg is on (the Encode leg — set before each
    /// clip).
    pub clip_current: Option<String>,
    pub clip_done: usize,
    pub clip_total: usize,
}

impl Default for LegProgress {
    fn default() -> Self {
        Self {
            status: LegStatus::Idle,
            summary: String::new(),
            log: String::new(),
            last_error: None,
            clip_current: None,
            clip_done: 0,
            clip_total: 0,
        }
    }
}

/// The shared job state (the leg model — the v1 clip-level fields
/// re-aimed to the leg: the per-leg status/summary/log + the
/// per-clip progress of the current leg).
#[derive(Clone, Debug, Default)]
pub struct JobState {
    /// The per-leg progress (in leg order — the job's legs at start).
    pub legs: Vec<LegProgress>,
    /// The leg the job is on (set before each leg; `None` at rest).
    pub current_leg: Option<usize>,
    pub finished: bool,
    /// The run verdict (the R4.5 line — set once, at the loop's end).
    pub verdict: Option<String>,
}

/// The job's start transition (the worker thread's first step): the
/// per-leg baseline = the caller's pre-Run arbiter output (a
/// REFUSED leg is recorded as-is — the core is never called for it).
pub(crate) fn job_begin(state: &mut JobState, pre_run: &[LegStatus]) {
    state.legs = pre_run
        .iter()
        .map(|status| LegProgress {
            status: status.clone(),
            ..LegProgress::default()
        })
        .collect();
    state.current_leg = None;
    state.finished = false;
    state.verdict = None;
}

/// The pre-leg transition: the leg's status → Running (the clip
/// baseline for the Encode leg — `clip_total` = the scan's clip
/// count; 0 for the single-call legs).
pub(crate) fn leg_begin(state: &mut JobState, i: usize, clip_total: usize) {
    state.current_leg = Some(i);
    state.legs[i].status = LegStatus::Running;
    state.legs[i].clip_total = clip_total;
    state.legs[i].clip_done = 0;
    state.legs[i].clip_current = None;
    state.legs[i].last_error = None;
}

/// The pre-clip transition (the Encode leg): `clip_current` names
/// the clip BEFORE the encode starts.
pub(crate) fn clip_begin(state: &mut JobState, key: &str) {
    let Some(i) = state.current_leg else {
        return;
    };
    state.legs[i].clip_current = Some(key.to_string());
}

/// The post-clip transition (the Encode leg): a clean clip
/// increments `clip_done`; a failed clip sets `last_error` (the
/// core's display line) and increments NOTHING — the leg CONTINUES
/// (the verdict aggregates).
pub(crate) fn clip_result(state: &mut JobState, ok: bool, error: Option<String>) {
    let Some(i) = state.current_leg else {
        return;
    };
    if ok {
        state.legs[i].clip_done += 1;
    } else if let Some(err) = error {
        state.legs[i].last_error = Some(err);
    }
}

/// The post-leg transition: the leg's final status + summary + log
/// (filled as the legs complete — the run-report panel renders them
/// in leg order).
pub(crate) fn leg_result(
    state: &mut JobState,
    i: usize,
    status: LegStatus,
    summary: String,
    log: String,
) {
    state.legs[i].status = status;
    state.legs[i].summary = summary;
    state.legs[i].log = log;
    state.current_leg = None;
}

/// The post-loop transition: `finished` + `verdict`, set once.
pub(crate) fn job_finish(state: &mut JobState) {
    state.finished = true;
    state.current_leg = None;
    let not_clean = state
        .legs
        .iter()
        .filter(|l| matches!(l.status, LegStatus::Failed { .. } | LegStatus::Refused { .. }))
        .count();
    state.verdict = Some(run_verdict_line(state.legs.len(), not_clean));
}

/// The VERBATIM run verdict line (the R4.5 pin): `rc=0 (all legs
/// clean)` when every leg completed clean, else `rc=1 (<k> of <n>
/// legs refused or failed)` (`<k>` = the refused-or-failed count — a
/// pre-Run REFUSED leg counts: it was not clean).
pub(crate) fn run_verdict_line(total: usize, not_clean: usize) -> String {
    if not_clean == 0 {
        "rc=0 (all legs clean)".to_string()
    } else {
        format!("rc=1 ({not_clean} of {total} legs refused or failed)")
    }
}

/// The v1 VERBATIM clips verdict line (the Encode leg's aggregate —
/// the v1 lines stand verbatim): `rc=0 (all clips clean)` when every
/// clip completed clean, else `rc=1 (<k> of <n> clips failed)`.
pub(crate) fn clips_verdict_line(total: usize, done: usize) -> String {
    if done == total {
        "rc=0 (all clips clean)".to_string()
    } else {
        format!("rc=1 ({} of {} clips failed)", total - done, total)
    }
}

/// The Encode leg's summary line (the R4.3 pin): `<done>/<total>
/// clips · <the v1 verdict line>`.
pub(crate) fn encode_leg_summary(done: usize, total: usize) -> String {
    format!("{done}/{total} clips · {}", clips_verdict_line(total, done))
}

/// The LAST NON-EMPTY line of the captured leg output (both streams,
/// arrival order — the core's own summary line is emitted after the
/// work, so the last line IS the summary; verbatim, no parsing, no
/// re-derivation). An empty capture = an empty string (the honest
/// absence — the GUI never invents a line).
pub(crate) fn last_non_empty_line(text: &str) -> String {
    text.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_default()
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
// The `Mirror this output →` affordance (the R5.2 pure function —
// the "second session" is a pure GUI state operation: no core
// involvement; the user's next Run is the second session).
// ---------------------------------------------------------------------

/// The VERBATIM note line (the R5.2 pin).
pub const PREFILL_NOTE: &str =
    "second session — source: the encode leg's output · the shelves you pick";

/// The prefilled second-session composer state (a pure value — the
/// UI applies it to the composer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessPrefill {
    /// The Source field's new value (the Encode leg's dest path).
    pub source: PathBuf,
    /// The leg list reset to a SINGLE Mirror leg (dest empty — the
    /// user picks the shelf).
    pub legs: Vec<Leg>,
    /// The note line (the verbatim pin).
    pub note: String,
}

/// The prefill (the R5.2 pure function): `(legs, verdict) ->
/// Option<ProcessPrefill>` — the legs = the finished run's legs
/// (the final statuses), the verdict = the run's verdict (`Some` =
/// the run finished). `None` when no CLEAN Encode leg exists (the
/// honest disable). Idempotent by construction: the pure function
/// over the run's (legs, verdict) re-applies to the identical fresh
/// prefill — a prefill over a prefilled composer is a fresh prefill,
/// not a stack (the prefilled composer carries no clean Encode leg).
pub fn prefill_mirror_session(
    legs: &[Leg],
    verdict: &Option<String>,
) -> Option<ProcessPrefill> {
    if verdict.is_none() {
        return None;
    }
    let encode = legs
        .iter()
        .find(|l| l.mode == LegMode::Encode && l.status == LegStatus::Clean)?;
    Some(ProcessPrefill {
        source: encode.dest.clone(),
        legs: vec![Leg {
            mode: LegMode::Mirror,
            ..Leg::default_leg()
        }],
        note: PREFILL_NOTE.to_string(),
    })
}

// ---------------------------------------------------------------------
// The per-leg stream capture (the R4.2 surface — both fd 1 and fd 2
// redirected to the per-leg capture file; the unix-only contract;
// the v1 stdout-guard pattern generalized, the no-new-crates rule:
// raw FFI via `extern "C"` + std only).
// ---------------------------------------------------------------------

/// The non-unix honesty line (the verbatim pin — the capture is the
/// unix-only contract; the leg's raw log shows this line where the
/// capture is unavailable).
pub(crate) const CAPTURE_UNAVAILABLE: &str =
    "the raw log is unavailable on this platform (the unix-only stream capture)";

#[cfg(unix)]
mod stream_guard_unix {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
    use std::path::Path;

    extern "C" {
        fn dup(fd: i32) -> i32;
        fn dup2(oldfd: i32, newfd: i32) -> i32;
    }

    /// The guard (the Drop restores fds 1 + 2 to the pre-leg state).
    pub struct Guard {
        saved1: OwnedFd,
        saved2: OwnedFd,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            // fds 1 + 2 rode the capture file for the leg's window —
            // restore the saved copies (the UI / the selftest print
            // on the original fds after the leg).
            let _ = unsafe { dup2(self.saved2.as_raw_fd(), 2) };
            let _ = unsafe { dup2(self.saved1.as_raw_fd(), 1) };
        }
    }

    /// Both streams → the capture file (the v1 /dev/null redirect
    /// generalized to the per-leg capture file — the file must
    /// exist: the job's pre-job step creates it).
    pub fn start(path: &Path) -> Result<Guard, String> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|err| format!("the capture file open failed ({}): {err}", path.display()))?;
        let cap = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
        let saved1_raw = unsafe { dup(1) };
        if saved1_raw < 0 {
            return Err("the stdout save (dup) failed".to_string());
        }
        let saved1 = unsafe { OwnedFd::from_raw_fd(saved1_raw) };
        let saved2_raw = unsafe { dup(2) };
        if saved2_raw < 0 {
            return Err("the stderr save (dup) failed".to_string());
        }
        let saved2 = unsafe { OwnedFd::from_raw_fd(saved2_raw) };
        if unsafe { dup2(cap.as_raw_fd(), 1) } < 0 {
            return Err("the stdout redirect (dup2) failed".to_string());
        }
        if unsafe { dup2(cap.as_raw_fd(), 2) } < 0 {
            return Err("the stderr redirect (dup2) failed".to_string());
        }
        drop(cap); // the dup2 copied the fd — our copy is done (the close)
        Ok(Guard { saved1, saved2 })
    }
}

/// The per-leg stream capture guard (the unix both-fds redirect —
/// the non-unix target: the capture is unavailable, the leg runs
/// WITHOUT the window + the raw log shows the verbatim honesty line).
pub(crate) enum StreamGuard {
    /// The unix redirect (the guard acts by Drop — the saved fd
    /// copies are restored in the Drop; the payload is held, never
    /// read: the RAII reason for the allow).
    #[allow(dead_code)]
    #[cfg(unix)]
    Unix(stream_guard_unix::Guard),
    #[cfg(not(unix))]
    None,
}

pub(crate) fn start_stream_capture(path: &Path) -> Result<StreamGuard, String> {
    #[cfg(unix)]
    {
        Ok(StreamGuard::Unix(stream_guard_unix::start(path)?))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(StreamGuard::None)
    }
}

// ---------------------------------------------------------------------
// The Run (the R4 model — the legs, in order, on the job thread).
// ---------------------------------------------------------------------

/// The Run: a SINGLE job thread (the v1 pattern — no new threading),
/// the legs IN LEG ORDER. One job at a time (the v1 model).
///
/// The pre-job checks (each failure = the NAMED line — the job does
/// not start, 0 files written): (1) the source exists + is a dir
/// (the v1 verbatim line) · (2) the leg list is non-empty · (3) the
/// per-leg capture scratch + the capture files are created. The
/// caller's contract: the profile env seam applied (process-wide)
/// before the call + the legs' `status` = the pre-Run arbiter's
/// output (a REFUSED leg is recorded on the row, the core is never
/// called for it, the run CONTINUES with the next leg).
pub fn start_job(
    source: &Path,
    legs: Vec<Leg>,
    scan: Scan,
    knobs: RunKnobs,
    state: Arc<Mutex<JobState>>,
) -> Result<(), String> {
    if !source.is_dir() {
        return Err(format!(
            "refusal: the source dir is missing or not a directory ({})",
            source.display()
        ));
    }
    if legs.is_empty() {
        return Err("refusal: no legs (the leg list is empty)".to_string());
    }
    // The per-leg capture files (the temp dir — the selftest's
    // scratch pattern; deleted at job end; a creation failure = the
    // NAMED refusal — the job does not start, 0 files written).
    // One per EXECUTING leg — a pre-Run REFUSED leg never runs the
    // core (no window, no file).
    let scratch = scratch_dir("job");
    std::fs::create_dir_all(&scratch).map_err(|err| {
        format!(
            "the job scratch dir cannot be created ({}): {err}",
            scratch.display()
        )
    })?;
    let captures: Vec<Option<PathBuf>> = legs
        .iter()
        .enumerate()
        .map(|(i, leg)| {
            (!matches!(leg.status, LegStatus::Refused { .. }))
                .then(|| scratch.join(format!("leg-{i}.log")))
        })
        .collect();
    for path in captures.iter().flatten() {
        std::fs::File::create(path).map_err(|err| {
            format!(
                "the capture file cannot be created ({}): {err}",
                path.display()
            )
        })?;
    }
    let source = source.to_path_buf();
    let keys = scan.clip_keys();
    let pre_run: Vec<LegStatus> = legs.iter().map(|l| l.status.clone()).collect();
    std::thread::spawn(move || {
        {
            let mut s = state.lock().unwrap();
            job_begin(&mut s, &pre_run);
        }
        let mut aborted = false;
        for (i, leg) in legs.iter().enumerate() {
            if aborted {
                continue;
            }
            if let LegStatus::Refused { line, .. } = &leg.status {
                // The pre-Run refusal: the core is NEVER called for
                // the leg — the named line rides the row + the run
                // continues with the next leg.
                let mut s = state.lock().unwrap();
                leg_result(&mut s, i, leg.status.clone(), line.clone(), String::new());
                continue;
            }
            {
                let mut s = state.lock().unwrap();
                let clip_total = if leg.mode == LegMode::Encode {
                    keys.len()
                } else {
                    0
                };
                leg_begin(&mut s, i, clip_total);
            }
            // The process-wide statics (EXPLICIT at the leg start —
            // the corpus-KAT pattern; the job owns the statics
            // during the run — reset (false) at the job end below).
            frameprism::worker::set_carry_flag(false);
            frameprism::worker::set_trial_flag(knobs.trial);
            frameprism::camera::set_pinned_only(knobs.strict);
            // The per-leg capture window (BOTH streams → the
            // capture file; the non-unix target: no window, the raw
            // log shows the verbatim honesty line).
            let guard = match &captures[i] {
                Some(path) => match start_stream_capture(path) {
                    Ok(g) => Some(g),
                    Err(e) => {
                        // The named abort (the capture contract is
                        // the unix gate/dev surface): the leg is
                        // failed, the core is never called, the job
                        // ends (the remaining legs are not run).
                        let mut s = state.lock().unwrap();
                        leg_result(
                            &mut s,
                            i,
                            LegStatus::Failed { line: e.clone() },
                            e,
                            String::new(),
                        );
                        aborted = true;
                        None
                    }
                },
                None => None,
            };
            if aborted {
                continue;
            }
            let outcome = run_leg_core(leg, &source, &keys, &knobs, &state);
            let raw = match guard {
                Some(guard) => {
                    drop(guard);
                    std::fs::read_to_string(captures[i].as_ref().expect("the executing leg has a capture file"))
                        .unwrap_or_default()
                }
                None => CAPTURE_UNAVAILABLE.to_string(),
            };
            let (status, summary) = match outcome {
                LegOutcome::Encode { clean, summary } => {
                    // The Encode leg's summary is GUI-computed (the
                    // v1 verdict line — the capture never parsed).
                    let status = if clean {
                        LegStatus::Clean
                    } else {
                        LegStatus::Failed { line: summary.clone() }
                    };
                    (status, summary)
                }
                LegOutcome::Single { clean } => {
                    // The core's own summary line (the last
                    // non-empty captured line — verbatim, no
                    // parsing, no re-derivation).
                    let last = last_non_empty_line(&raw);
                    let status = if clean {
                        LegStatus::Clean
                    } else {
                        LegStatus::Failed { line: last.clone() }
                    };
                    (status, last)
                }
            };
            let mut s = state.lock().unwrap();
            leg_result(&mut s, i, status, summary, raw);
        }
        // The statics RESET (false) at the job end.
        frameprism::worker::set_carry_flag(false);
        frameprism::worker::set_trial_flag(false);
        frameprism::camera::set_pinned_only(false);
        let mut s = state.lock().unwrap();
        job_finish(&mut s);
        // The scratch cleanup (best effort — the leak is a named
        // residual, never silent).
        let _ = std::fs::remove_dir_all(&scratch);
    });
    Ok(())
}

/// The per-leg core outcome (the runner's return — the summary half
/// is resolved AFTER the capture window closes: the single-call
/// legs' summary rides the captured output's last line).
enum LegOutcome {
    /// The Encode leg (the summary GUI-computed — the v1 clips
    /// verdict line).
    Encode { clean: bool, summary: String },
    /// The single-call legs (Mirror / Derive / Decode): the summary
    /// and the failure line = the core's last non-empty captured
    /// line.
    Single { clean: bool },
}

/// The per-leg core call (the R4.1 exact surface — the M0 re-read
/// signatures; runs INSIDE the capture window — the core's streams
/// land in the capture file).
fn run_leg_core(
    leg: &Leg,
    source: &Path,
    keys: &[String],
    knobs: &RunKnobs,
    state: &Arc<Mutex<JobState>>,
) -> LegOutcome {
    match leg.mode {
        LegMode::Encode => {
            // The v1 per-clip loop (the `start_encode` machinery
            // refactored into the leg runner — the behavior
            // preserved: the per-clip progress, the
            // continuation-on-failure, the v1 verdict lines). The
            // leg consumes the WHOLE source tree (per-clip
            // selection is retired).
            let total = keys.len();
            if total == 0 {
                // The defensive named line (the empty scan never
                // reaches the runner — the Encode leg is refused
                // pre-Run at the UNIDENTIFIED state).
                return LegOutcome::Encode {
                    clean: false,
                    summary: "refusal: no clips in the source tree (the scan is empty)"
                        .to_string(),
                };
            }
            let mut done = 0usize;
            for key in keys {
                {
                    let mut s = state.lock().unwrap();
                    clip_begin(&mut s, key);
                }
                let call = encode_call(source, &leg.dest, key, leg.verify, knobs);
                let res = frameprism::worker::process_dir(
                    &call.input,
                    &call.output,
                    call.verify, // verify — the leg's verify (the NEW CAMERA lock rides the UI)
                    call.force, // force — the Advanced knob
                    call.jobs, // jobs — the Advanced knob (0 = the default pool)
                    call.mode, // the arbiter's output (the Advanced `mode` slot)
                    call.downscale, // downscale — the Advanced knob
                    call.fast, // fast — the Advanced knob
                    call.checksums, // checksums — the Advanced knob
                    frameprism::worker::LossyFormat::ReferenceDct, // the CLI default
                    &frameprism::worker::ReferenceDctOpts {
                        reference_ref: None,
                        reference_mae_tsv: None,
                        reference_structure_tsv: None,
                    }, // the CLI default construction
                    None, // to — the CLI default
                    false, // qc_gate — the CLI default
                );
                let ok = res.is_ok();
                {
                    let mut s = state.lock().unwrap();
                    clip_result(&mut s, ok, res.err().map(|e| e.to_string()));
                }
                if ok {
                    done += 1;
                }
            }
            LegOutcome::Encode {
                clean: done == total,
                summary: encode_leg_summary(done, total),
            }
        }
        LegMode::Mirror => {
            // The single-source Legacy form (the core's own
            // pre-write bands fire named + rc=2 BEFORE any copy).
            let rc = frameprism::offload::run(&mirror_args(source, &leg.dest));
            LegOutcome::Single { clean: rc == std::process::ExitCode::SUCCESS }
        }
        LegMode::Derive => {
            // Read-only over the source (the ruling).
            let rc = frameprism::derived::run(&derive_args(source, &leg.dest, leg.bits, knobs.force));
            LegOutcome::Single { clean: rc == std::process::ExitCode::SUCCESS }
        }
        LegMode::Decode => {
            // The default binary resolution (the core's named line
            // if the pinned binaries don't resolve).
            let rc = frameprism::decode::run(&decode_args(source, &leg.dest, knobs.force));
            LegOutcome::Single { clean: rc == std::process::ExitCode::SUCCESS }
        }
    }
}

// ---------------------------------------------------------------------
// The archive maintenance (the R6 surface — per shelved dest; the
// audit / restore ride the job thread's single-job model: a
// maintenance run blocks the Run button, the v1 pattern).
// ---------------------------------------------------------------------

/// The maintenance operation kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaintenanceKind {
    /// The read-only sidecar re-verify (the core contract).
    Audit,
    /// The restore from the pristine master (the session source).
    Restore,
}

/// The shared maintenance state (the per-operation
/// `Arc<Mutex<MaintenanceState>>` — the UI polls at the job's ~4 Hz
/// cadence).
#[derive(Clone, Debug, Default)]
pub struct MaintenanceState {
    pub kind: Option<MaintenanceKind>,
    /// The operated dest (the row key).
    pub dest: String,
    pub finished: bool,
    /// The operation's rc=0.
    pub ok: bool,
    /// The core's LAST non-empty captured line (the R4.3 rule,
    /// verbatim — no parsing, no offender counting in the GUI).
    pub line: String,
}

/// The maintenance run (the `audit` / `restore` core verbs at the
/// CLI defaults — `jobs: 0`, `source: None`, `eject: false` /
/// `frame: None`, `force: false` — the caller's contract: the
/// profile env seam applied before the call; the operation rides a
/// std thread + the per-leg capture window (both streams → the
/// capture file; the non-unix honesty line where unavailable)).
pub fn start_maintenance(
    kind: MaintenanceKind,
    dest: &Path,
    from: Option<&Path>,
    state: Arc<Mutex<MaintenanceState>>,
) -> Result<(), String> {
    if !dest.is_dir() {
        return Err(format!(
            "refusal: the archive dir is missing or not a directory ({})",
            dest.display()
        ));
    }
    if kind == MaintenanceKind::Restore {
        let Some(from) = from else {
            return Err("refusal: the restore master is absent (the session source must name the pristine master)".to_string());
        };
        if !from.is_dir() {
            return Err(format!(
                "refusal: the restore master is missing or not a directory ({})",
                from.display()
            ));
        }
    }
    let scratch = scratch_dir("maint");
    std::fs::create_dir_all(&scratch).map_err(|err| {
        format!(
            "the maintenance scratch dir cannot be created ({}): {err}",
            scratch.display()
        )
    })?;
    let capture = scratch.join("maint.log");
    std::fs::File::create(&capture).map_err(|err| {
        format!(
            "the capture file cannot be created ({}): {err}",
            capture.display()
        )
    })?;
    let dest = dest.to_path_buf();
    let from = from.map(|p| p.to_path_buf());
    std::thread::spawn(move || {
        {
            let mut s = state.lock().unwrap();
            s.kind = Some(kind);
            s.dest = dest.display().to_string();
        }
        let guard = match start_stream_capture(&capture) {
            Ok(g) => g,
            Err(e) => {
                let mut s = state.lock().unwrap();
                s.line = e;
                s.finished = true;
                let _ = std::fs::remove_dir_all(&scratch);
                return;
            }
        };
        let rc = match kind {
            MaintenanceKind::Audit => {
                frameprism::audit::run_audit(&frameprism::audit::AuditArgs {
                    input: dest.clone(),
                    jobs: 0, // the CLI default
                    source: None, // the CLI default
                    eject: false, // the CLI default
                })
            }
            MaintenanceKind::Restore => frameprism::audit::run_restore(
                &frameprism::audit::RestoreArgs {
                    input: dest.clone(),
                    from: from.expect("the Restore pre-job check names the master"),
                    frame: None, // the CLI default
                    jobs: 0, // the CLI default
                    force: false, // the CLI default
                },
            ),
        };
        drop(guard);
        let raw = std::fs::read_to_string(&capture).unwrap_or_default();
        let line = last_non_empty_line(&raw);
        let mut s = state.lock().unwrap();
        s.ok = rc == std::process::ExitCode::SUCCESS;
        s.line = if std::env::consts::OS == "unix" {
            line
        } else {
            CAPTURE_UNAVAILABLE.to_string()
        };
        s.finished = true;
        let _ = std::fs::remove_dir_all(&scratch);
    });
    Ok(())
}

// ---------------------------------------------------------------------
// The headless selftest (the R8 surface — the Process surface; the
// gate's teeth; NO window, NO GPU — the lib path only). The bin's
// `--selftest` mode calls `selftest()` and prints the VERBATIM OK /
// FAIL line.
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

/// The headless selftest (the R8 steps — the Process surface; the
/// v1 steps 1–2 preserved as sub-steps; the scratch = a temp dir,
/// deleted; LIGHT — one frame). The steps: (1) the fixture → a
/// scratch source clip · (2) the scan: one row, the class line
/// verbatim · (3) the 3-leg flow — session 1 `Encode` → dest A (the
/// v1 verdict line verbatim + the output DNG), then the
/// second-session shape (the source := dest A): `Mirror` → dest B
/// (the offload of the encoded tree — the mirrored frame file + the
/// offload manifest sidecar) + `Decode` → dest C (the PAM
/// round-trip) · (4) the `Derive` leg (session 3 — source = the RAW
/// scratch source, the 12-bit master; AMENDMENT #3) → dest D (the
/// derived DNG + the derive manifest sidecar at
/// `<destD>/<input-basename>.derive-manifest.tsv`) · (5) the refusal
/// step — a second scratch source = a NON-DNG file (the `NonDng`
/// class → the UNIDENTIFIED state): the Process job [Encode, Mirror]
/// → the Encode leg refused with the VERBATIM R3.3 line (the core
/// never called for it — the dest stays absent) + the Mirror leg
/// runs to rc=0 (the offload copies any tree) + the run verdict =
/// the verbatim R4.5 line · (6) the scratch cleanup. Runs on a CLEAN
/// CHECKOUT (the committed fixture only — no corpus, no external
/// tool, no network). `Err` = the named reason (the bin's FAIL
/// line).
pub fn selftest() -> Result<(), String> {
    #[cfg(not(unix))]
    {
        return Err(
            "the selftest is unix-only (the per-leg stream capture is the unix gate/dev surface)"
                .to_string(),
        );
    }
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
    let fixture_name = fixture
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    // (1) the fresh /tmp scratch dir + the source clip (the v1
    // step 1). The R4 layout: the source root = `<scratch>/src`;
    // the fixture rides `<scratch>/src/SELFTEST_CLIP/` (the key
    // space is the source-root-relative).
    let scratch = scratch_dir("selftest");
    let src = scratch.join("src");
    let clip = src.join("SELFTEST_CLIP");
    std::fs::create_dir_all(&clip).map_err(|err| {
        format!("the scratch dir cannot be created ({}): {err}", clip.display())
    })?;
    std::fs::copy(&fixture, clip.join(fixture_name.as_str())).map_err(|err| {
        format!("copying the committed fixture failed: {err}")
    })?;

    // (2) the scan: exactly one row (the SELFTEST_CLIP key) + the
    // class line VERBATIM (the v1 step 2).
    let rows = clips(&src).map_err(|err| format!("the clip scan failed: {err}"))?;
    if rows.len() != 1 || rows[0].key != "SELFTEST_CLIP" {
        return Err(format!(
            "the clip scan returned {} row(s) (keys: {}), expected exactly one (the SELFTEST_CLIP key)",
            rows.len(),
            rows.iter().map(|r| r.key.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    if rows[0].class != "profiled a001-sigma-fp (profile v1)" {
        return Err(format!(
            "the clip class line is {:?}, expected 'profiled a001-sigma-fp (profile v1)'",
            rows[0].class
        ));
    }
    let scan_a = scan(&src).map_err(|err| format!("the session scan failed: {err}"))?;
    if scan_a.strip_state() != StripState::SetUp {
        return Err(
            "the session strip state is not SET UP (the committed profile must classify the fixture clip)"
                .to_string(),
        );
    }

    let knobs = RunKnobs::default();
    let timeout = std::time::Duration::from_secs(120);

    // (3a) session 1 — the Encode leg (leg 1 of the 3).
    let dest_a = scratch.join("destA");
    let mut legs = vec![Leg {
        mode: LegMode::Encode,
        dest: dest_a.clone(),
        ..Leg::default_leg()
    }];
    for leg in legs.iter_mut() {
        leg.status = pre_job_status(leg.mode, scan_a.strip_state(), &src, &leg.dest);
    }
    let state1 = Arc::new(Mutex::new(JobState::default()));
    start_job(&src, legs, scan_a, knobs.clone(), state1.clone())
        .map_err(|err| format!("session 1 (the Encode leg) did not start: {err}"))?;
    if !wait_finished(&state1, timeout) {
        return Err(
            "session 1 (the Encode leg) did not finish within the 120 s timeout".to_string(),
        );
    }
    let snap1 = poll(&state1);
    if !snap1.finished {
        return Err("session 1 did not finish".to_string());
    }
    if snap1.verdict.as_deref() != Some("rc=0 (all legs clean)") {
        return Err(format!(
            "session 1 verdict is {:?}, expected 'rc=0 (all legs clean)'",
            snap1.verdict
        ));
    }
    if snap1.legs[0].status != LegStatus::Clean {
        return Err(format!(
            "the Encode leg is {:?}, expected clean",
            snap1.legs[0].status
        ));
    }
    if snap1.legs[0].summary != "1/1 clips · rc=0 (all clips clean)" {
        return Err(format!(
            "the Encode leg summary is {:?}, expected '1/1 clips · rc=0 (all clips clean)'",
            snap1.legs[0].summary
        ));
    }
    let out_a = dest_a.join("SELFTEST_CLIP").join(fixture_name.as_str());
    if !out_a.is_file() || std::fs::metadata(&out_a).map(|m| m.len()).unwrap_or(0) == 0 {
        return Err(format!("the output DNG is missing or empty ({})", out_a.display()));
    }

    // (3b) session 2 — the second-session flow (the R5.2 shape): the
    // source := the Encode leg's dest; the Mirror leg + the Decode
    // leg (legs 2–3 of the 3).
    let scan_b = scan(&dest_a).map_err(|err| format!("the session-2 scan failed: {err}"))?;
    let dest_b = scratch.join("destB");
    let dest_c = scratch.join("destC");
    let mut legs = vec![
        Leg {
            mode: LegMode::Mirror,
            dest: dest_b.clone(),
            ..Leg::default_leg()
        },
        Leg {
            mode: LegMode::Decode,
            dest: dest_c.clone(),
            ..Leg::default_leg()
        },
    ];
    for leg in legs.iter_mut() {
        leg.status = pre_job_status(leg.mode, scan_b.strip_state(), &dest_a, &leg.dest);
    }
    let state2 = Arc::new(Mutex::new(JobState::default()));
    start_job(&dest_a, legs, scan_b, knobs.clone(), state2.clone())
        .map_err(|err| format!("session 2 (the Mirror + Decode legs) did not start: {err}"))?;
    if !wait_finished(&state2, timeout) {
        return Err(
            "session 2 (the Mirror + Decode legs) did not finish within the 120 s timeout"
                .to_string(),
        );
    }
    let snap2 = poll(&state2);
    if snap2.verdict.as_deref() != Some("rc=0 (all legs clean)") {
        return Err(format!(
            "session 2 verdict is {:?}, expected 'rc=0 (all legs clean)'",
            snap2.verdict
        ));
    }
    if snap2.legs[0].status != LegStatus::Clean || snap2.legs[1].status != LegStatus::Clean {
        return Err(format!(
            "the Mirror/Decode legs are {:?} / {:?}, expected clean",
            snap2.legs[0].status, snap2.legs[1].status
        ));
    }
    // The Mirror leg's contract surfaces (the GUI asserts
    // existence, never re-verifies: the offload's own verified-copy
    // contract + the re-scan): the mirrored frame file + the
    // offload manifest sidecar at the mirrored clip root.
    let mirrored = dest_b.join("SELFTEST_CLIP").join(fixture_name.as_str());
    if !mirrored.is_file() {
        return Err(format!(
            "the mirrored frame file is missing ({})",
            mirrored.display()
        ));
    }
    let manifest_b = dest_b.join("SELFTEST_CLIP").join("SELFTEST_CLIP.offload-manifest.tsv");
    if !manifest_b.is_file() {
        return Err(format!(
            "the offload manifest sidecar is missing ({})",
            manifest_b.display()
        ));
    }
    // The Decode leg's round-trip: the PAM output exists + is
    // non-empty.
    let stem = fixture_name
        .strip_suffix(".DNG")
        .unwrap_or(fixture_name.as_str());
    let pam = dest_c.join("SELFTEST_CLIP").join(format!("{stem}.pam"));
    if !pam.is_file() || std::fs::metadata(&pam).map(|m| m.len()).unwrap_or(0) == 0 {
        return Err(format!("the PAM output is missing or empty ({})", pam.display()));
    }

    // (4) the Derive leg (session 3; source = the RAW scratch
    // source — the 12-bit master; AMENDMENT #3: the derive's input
    // contract is the tileless 12-bit MASTER tree — the encoded
    // output (dest A) is tile-based by construction (tags 322/323),
    // and the core's named refusal `tile-based input not supported
    // (tag 322/323 present)` would ride the leg) → dest D.
    let scan_d = scan(&src).map_err(|err| format!("the derive scan failed: {err}"))?;
    let dest_d = scratch.join("destD");
    let mut legs = vec![Leg {
        mode: LegMode::Derive,
        dest: dest_d.clone(),
        ..Leg::default_leg()
    }];
    for leg in legs.iter_mut() {
        leg.status = pre_job_status(leg.mode, scan_d.strip_state(), &src, &leg.dest);
    }
    let state4 = Arc::new(Mutex::new(JobState::default()));
    start_job(&src, legs, scan_d, knobs.clone(), state4.clone())
        .map_err(|err| format!("the Derive leg did not start: {err}"))?;
    if !wait_finished(&state4, timeout) {
        return Err("the Derive leg did not finish within the 120 s timeout".to_string());
    }
    let snap4 = poll(&state4);
    if snap4.verdict.as_deref() != Some("rc=0 (all legs clean)") {
        return Err(format!(
            "the Derive leg verdict is {:?}, expected 'rc=0 (all legs clean)'",
            snap4.verdict
        ));
    }
    let derived = dest_d.join("SELFTEST_CLIP").join(fixture_name.as_str());
    if !derived.is_file() || std::fs::metadata(&derived).map(|m| m.len()).unwrap_or(0) == 0 {
        return Err(format!(
            "the derived DNG is missing or empty ({})",
            derived.display()
        ));
    }
    // The derive manifest sidecar (the CLIP name =
    // `checksums::clip_name` of the INPUT — the input's basename —
    // written at the OUTPUT root; `derived.rs`).
    let input_base = src
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let manifest_d = dest_d.join(format!("{input_base}.derive-manifest.tsv"));
    if !manifest_d.is_file() {
        return Err(format!(
            "the derive manifest sidecar is missing ({})",
            manifest_d.display()
        ));
    }

    // (5) the refusal step — a second scratch source = a NON-DNG
    // file (the `NonDng` class → the UNIDENTIFIED state): the
    // Process job [Encode leg, Mirror leg] → the Encode leg refused
    // with the VERBATIM R3.3 line (the core never called for it) +
    // the Mirror leg runs to rc=0 (the offload copies any tree) +
    // the run verdict = the verbatim R4.5 line.
    let src2 = scratch.join("src2");
    std::fs::create_dir_all(src2.join("BATCH")).map_err(|err| {
        format!("the refusal scratch dir cannot be created: {err}")
    })?;
    std::fs::write(src2.join("BATCH/notes.bin"), b"not a DNG").map_err(|err| {
        format!("the refusal source file cannot be written: {err}")
    })?;
    let scan_2 = scan(&src2).map_err(|err| format!("the refusal scan failed: {err}"))?;
    if scan_2.strip_state() != StripState::Unidentified {
        return Err(
            "the refusal source strip state is not UNIDENTIFIED (the non-DNG file must classify NonDng)"
                .to_string(),
        );
    }
    let dest_e = scratch.join("destE");
    let dest_f = scratch.join("destF");
    let mut legs = vec![
        Leg {
            mode: LegMode::Encode,
            dest: dest_e.clone(),
            ..Leg::default_leg()
        },
        Leg {
            mode: LegMode::Mirror,
            dest: dest_f.clone(),
            ..Leg::default_leg()
        },
    ];
    for leg in legs.iter_mut() {
        leg.status = pre_job_status(leg.mode, scan_2.strip_state(), &src2, &leg.dest);
    }
    let state5 = Arc::new(Mutex::new(JobState::default()));
    start_job(&src2, legs, scan_2, knobs, state5.clone())
        .map_err(|err| format!("the refusal run did not start: {err}"))?;
    if !wait_finished(&state5, timeout) {
        return Err("the refusal run did not finish within the 120 s timeout".to_string());
    }
    let snap5 = poll(&state5);
    if snap5.verdict.as_deref() != Some("rc=1 (1 of 2 legs refused or failed)") {
        return Err(format!(
            "the refusal run verdict is {:?}, expected 'rc=1 (1 of 2 legs refused or failed)'",
            snap5.verdict
        ));
    }
    match &snap5.legs[0].status {
        LegStatus::Refused { line, .. } if line == REFUSED_NO_SETUP => {}
        other => {
            return Err(format!(
                "the Encode leg status is {other:?}, expected the VERBATIM R3.3 refusal line"
            ))
        }
    }
    if dest_e.exists() {
        return Err(format!(
            "the Encode leg's core was called (the dest exists: {}) — the refused leg must never run the core",
            dest_e.display()
        ));
    }
    if snap5.legs[1].status != LegStatus::Clean {
        return Err(format!(
            "the Mirror leg is {:?}, expected clean (the offload copies any tree)",
            snap5.legs[1].status
        ));
    }

    // (6) the scratch cleanup (the v1 cleanup step — best effort,
    // the leak is a named residual, never silent).
    if let Err(err) = std::fs::remove_dir_all(&scratch) {
        return Err(format!(
            "the scratch dir could not be deleted ({}): {err}",
            scratch.display()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// The named lib tests (the R9 surface — the v1 5, one replaced,
/// three new, one re-aimed; the suite prediction's N = 8).
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // The process-global env seam (the `FRAMEPRISM_PROFILES` set by
    // the selftest): the tool's own suite holds a process-wide env
    // lock for exactly this class — here the selftest is the sole
    // reader + writer of the seam within this binary (the other
    // seven tests touch no env), so the lock documents + guards the
    // isolation.
    static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn scratch(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("fp-gui-test-{tag}-{}-{nanos}", std::process::id()))
    }

    fn det_clip(key: &str, class: frameprism::camera::DetectionClass) -> frameprism::camera::ClipDetection {
        frameprism::camera::ClipDetection {
            key: key.to_string(),
            class,
        }
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
        // a missing dest = the NOT-inside case (the leg creates
        // it) → None.
        assert_eq!(in_place_refusal(&src, &src.join("absent-dest")), None);
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&sibling);
    }

    #[test]
    fn profile_seam_semantics() {
        // The field wins over the launch env (the trim included).
        assert_eq!(
            profile_env_seam("  /x/profiles/a001.profile ", "/y/p.profile"),
            Some("/x/profiles/a001.profile".to_string())
        );
        // The launch env falls through when the field is empty
        // (the trim included).
        assert_eq!(
            profile_env_seam("", " /y/p.profile "),
            Some("/y/p.profile".to_string())
        );
        // Both empty = None (the core's own probe order stands
        // untouched).
        assert_eq!(profile_env_seam("", ""), None);
        // A whitespace-only field = empty: it falls through to the
        // launch env, and whitespace-only on both sides = None.
        assert_eq!(
            profile_env_seam("   ", "/y/p.profile"),
            Some("/y/p.profile".to_string())
        );
        assert_eq!(profile_env_seam("   ", "  "), None);
    }

    #[test]
    fn selftest_process_headless() {
        let _env = TEST_ENV_LOCK.lock().unwrap();
        // The extended R8 selftest (the v1 steps 1–2 preserved as
        // sub-steps; the v1's assertions ride inside the new one —
        // the 1-for-1 replacement of `selftest_encode_headless` is
        // named).
        selftest().expect("the process selftest failed (the named reason is the failure)");
    }

    #[test]
    fn process_job_transitions() {
        // The re-aim of the v1 `job_state_transitions` (the same
        // transition assertions, re-stated for the leg model: the
        // leg begin/result/finish + the R4.5 verdict lines verbatim
        // — the 1-for-1 re-aim is named).
        let mut s = JobState::default();
        job_begin(&mut s, &[LegStatus::Idle, LegStatus::Idle]);
        assert_eq!(
            (s.legs.len(), s.current_leg, s.finished, s.verdict.is_some()),
            (2, None, false, false)
        );
        // Leg 0 (the Encode leg, 2 clips) — the v1 pre-clip /
        // clip-Ok / clip-Err assertions re-stated at the leg level.
        leg_begin(&mut s, 0, 2);
        assert_eq!(s.legs[0].status, LegStatus::Running);
        assert_eq!((s.legs[0].clip_done, s.legs[0].clip_total), (0, 2));
        clip_begin(&mut s, "clip-a");
        assert_eq!(s.legs[0].clip_current.as_deref(), Some("clip-a"));
        clip_result(&mut s, true, None);
        assert_eq!((s.legs[0].clip_done, s.legs[0].last_error.is_some()), (1, false));
        // clip-b: the current key moves; the clip FAILS —
        // last_error is set, clip_done NOT incremented (the job
        // continues).
        clip_begin(&mut s, "clip-b");
        assert_eq!(s.legs[0].clip_current.as_deref(), Some("clip-b"));
        clip_result(&mut s, false, Some("FAIL clip-b: the named core line".to_string()));
        assert_eq!(
            (s.legs[0].clip_done, s.legs[0].last_error.as_deref()),
            (1, Some("FAIL clip-b: the named core line"))
        );
        leg_result(
            &mut s,
            0,
            LegStatus::Failed {
                line: "rc=1 (1 of 2 clips failed)".to_string(),
            },
            "1/2 clips · rc=1 (1 of 2 clips failed)".to_string(),
            String::new(),
        );
        // Leg 1 — a pre-Run refusal (the identity line).
        leg_begin(&mut s, 1, 0);
        leg_result(
            &mut s,
            1,
            LegStatus::Refused {
                line: REFUSED_NO_SETUP.to_string(),
                note: None,
            },
            REFUSED_NO_SETUP.to_string(),
            String::new(),
        );
        // post-loop: finished + the VERBATIM mixed-case run verdict.
        job_finish(&mut s);
        assert!(s.finished);
        assert_eq!(s.verdict.as_deref(), Some("rc=1 (2 of 2 legs refused or failed)"));
        // the clean-case run verdict (the same surface).
        let mut t = JobState::default();
        job_begin(&mut t, &[LegStatus::Idle]);
        leg_begin(&mut t, 0, 1);
        clip_begin(&mut t, "clip-a");
        clip_result(&mut t, true, None);
        leg_result(
            &mut t,
            0,
            LegStatus::Clean,
            "1/1 clips · rc=0 (all clips clean)".to_string(),
            String::new(),
        );
        job_finish(&mut t);
        assert!(t.finished);
        assert_eq!(t.verdict.as_deref(), Some("rc=0 (all legs clean)"));
        // The verdict line families (the R4.5 legs line + the v1
        // clips lines the Encode leg summary rides — both pinned).
        assert_eq!(
            run_verdict_line(2, 1),
            "rc=1 (1 of 2 legs refused or failed)"
        );
        assert_eq!(encode_leg_summary(1, 2), "1/2 clips · rc=1 (1 of 2 clips failed)");
        assert_eq!(encode_leg_summary(1, 1), "1/1 clips · rc=0 (all clips clean)");
    }

    #[test]
    fn leg_arbiter_modes() {
        // The 4-mode leg arbiter: the mode → core-call mapping is
        // correct (the per-mode Args construction of R4.1, the
        // field-by-field assertion) + the R3.3 verbatim
        // leg-refusal lines over the derived strip states.
        let src = scratch("leg-arbiter-src");
        std::fs::create_dir_all(&src).unwrap();
        let dest = scratch("leg-arbiter-dest");
        std::fs::create_dir_all(&dest).unwrap();

        // The per-mode Args construction (R4.1 — field by field).
        let knobs = RunKnobs {
            encode_mode: frameprism::worker::Mode::Log10,
            strict: true,
            trial: true,
            force: true,
            fast: true,
            downscale: true,
            checksums: true,
            jobs: 3,
        };
        let call = encode_call(&src, &dest, "CLIP", true, &knobs);
        assert_eq!(call.input, src.join("CLIP"));
        assert_eq!(call.output, dest.join("CLIP"));
        assert_eq!(call.verify, true);
        assert_eq!(
            (call.force, call.jobs, call.downscale, call.fast, call.checksums),
            (true, 3, true, true, true)
        );
        assert_eq!(call.mode, frameprism::worker::Mode::Log10);
        // Key `""` = the source root (the `process_dir` semantics —
        // no special case).
        let root_call = encode_call(&src, &dest, "", false, &knobs);
        assert_eq!(root_call.input, src);
        assert_eq!(root_call.output, dest);

        let m = mirror_args(&src, &dest);
        assert_eq!(m.input, Some(src.clone()));
        assert!(m.source.is_empty());
        assert!(m.dest.is_empty());
        assert_eq!(m.to, vec![dest.clone()]);

        let d8 = derive_args(&src, &dest, DeriveBits::Eight, true);
        assert_eq!(d8.input, src);
        assert_eq!(d8.output, dest);
        assert_eq!(d8.bits, frameprism::derived::Bits::B8);
        assert_eq!(d8.force, true);
        let d10 = derive_args(&src, &dest, DeriveBits::Ten, false);
        assert_eq!(d10.bits, frameprism::derived::Bits::B10);
        assert_eq!(d10.force, false);

        let dc = decode_args(&src, &dest, true);
        assert_eq!(dc.input, src);
        assert_eq!(dc.output, dest);
        assert_eq!(dc.codec, frameprism::decode::Codec::J92);
        assert_eq!(dc.frame, None);
        assert_eq!(dc.jobs, 0);
        assert_eq!(dc.force, true);
        assert_eq!(dc.cjxl_bin, PathBuf::from("cjxl"));
        assert_eq!(dc.djxl_bin, PathBuf::from("djxl"));

        // The R3.3 verbatim leg-refusal lines over the derived strip
        // states.
        use frameprism::camera::DetectionClass as D;
        let profiled = [det_clip(
            "A",
            D::Profiled {
                camera: "a001-sigma-fp".to_string(),
                profile_version: 1,
            },
        )];
        let newcam = [det_clip(
            "A",
            D::Unprofiled {
                make: "SIGMA".to_string(),
                model: "SIGMA fp".to_string(),
            },
        )];
        let nondng = [det_clip("A", D::NonDng)];
        let no_id = [det_clip(
            "A",
            D::Unprofiled {
                make: "-".to_string(),
                model: "-".to_string(),
            },
        )];
        // The derived states (the total function: UNIDENTIFIED first
        // — the no-clips rule — then SET UP, then NEW CAMERA).
        assert_eq!(strip_state_of(&profiled), StripState::SetUp);
        assert_eq!(strip_state_of(&newcam), StripState::NewCamera);
        assert_eq!(strip_state_of(&nondng), StripState::Unidentified);
        assert_eq!(strip_state_of(&no_id), StripState::Unidentified);
        assert_eq!(strip_state_of(&[]), StripState::Unidentified);
        // The per-state leg statuses (the verbatim lines — the
        // identity refusal / the ready contrast / the idle token).
        assert_eq!(
            pre_job_status(LegMode::Encode, StripState::Unidentified, &src, &dest),
            LegStatus::Refused {
                line: REFUSED_NO_SETUP.to_string(),
                note: None
            }
        );
        assert_eq!(
            pre_job_status(LegMode::Mirror, StripState::Unidentified, &src, &dest),
            LegStatus::Ready
        );
        for mode in [LegMode::Encode, LegMode::Mirror, LegMode::Derive, LegMode::Decode] {
            assert_eq!(
                pre_job_status(mode, StripState::SetUp, &src, &dest),
                LegStatus::Idle
            );
            assert_eq!(
                pre_job_status(mode, StripState::NewCamera, &src, &dest),
                LegStatus::Idle
            );
        }
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn pre_job_refusals() {
        // The pre-Run arbiter over the scan states: UNIDENTIFIED →
        // the Encode leg refused (the verbatim line, the core never
        // called) + the Mirror leg ready (the verbatim line) + SET
        // UP / NEW CAMERA → no pre-job refusal (the arbiter passes)
        // + the in-place guard composes (a refused-by-identity leg
        // AND an in-place dest → the identity refusal is named
        // FIRST, the in-place line still stands — the evaluation
        // order is named in this test).
        let src = scratch("pre-job-src");
        std::fs::create_dir_all(&src).unwrap();
        let dest = scratch("pre-job-dest");
        std::fs::create_dir_all(&dest).unwrap();
        let inner = src.join("inner");
        std::fs::create_dir_all(&inner).unwrap();

        // UNIDENTIFIED: the Encode leg refused (the verbatim line —
        // the core never called) + the Mirror leg ready (the
        // verbatim contrast line).
        assert_eq!(
            pre_job_status(LegMode::Encode, StripState::Unidentified, &src, &dest),
            LegStatus::Refused {
                line: REFUSED_NO_SETUP.to_string(),
                note: None
            }
        );
        assert_eq!(
            pre_job_status(LegMode::Mirror, StripState::Unidentified, &src, &dest),
            LegStatus::Ready
        );
        // SET UP / NEW CAMERA: no pre-job refusal (the arbiter
        // passes — the idle token for every mode).
        for strip in [StripState::SetUp, StripState::NewCamera] {
            for mode in [LegMode::Encode, LegMode::Mirror, LegMode::Derive, LegMode::Decode] {
                assert_eq!(pre_job_status(mode, strip, &src, &dest), LegStatus::Idle);
            }
        }
        // The in-place guard composes — the EVALUATION ORDER (named
        // here): the identity refusal is named FIRST (the `line`
        // field); the in-place line STILL STANDS (the `note` field).
        // A non-identity leg with an in-place dest → the in-place
        // line alone.
        match pre_job_status(LegMode::Encode, StripState::Unidentified, &src, &inner) {
            LegStatus::Refused { line, note } => {
                assert_eq!(line, REFUSED_NO_SETUP);
                assert_eq!(
                    note.as_deref(),
                    Some(
                        "refusal: the destination is inside the source (an in-place encode is refused — the source would be written over)"
                    )
                );
            }
            other => panic!("the identity refusal must stand first: {other:?}"),
        }
        for mode in [LegMode::Mirror, LegMode::Derive, LegMode::Decode] {
            assert_eq!(
                pre_job_status(mode, StripState::Unidentified, &src, &inner),
                LegStatus::Refused {
                    line: "refusal: the destination is inside the source (an in-place encode is refused — the source would be written over)"
                        .to_string(),
                    note: None
                }
            );
        }
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn prefill_mirror_session() {
        // The R5.2 pure function: the prefill (source = the Encode
        // leg's dest, the single Mirror leg, the verbatim note line)
        // + the `None` case (no clean Encode leg — the honest
        // disable) + the idempotence (a prefill over a prefilled
        // composer is a fresh prefill, not a stack).
        let dest_a = PathBuf::from("/shelves/encoded");
        let dest_b = PathBuf::from("/shelves/mirror");
        let encode = Leg {
            mode: LegMode::Encode,
            dest: dest_a.clone(),
            status: LegStatus::Clean,
            ..Leg::default_leg()
        };
        let mirror = Leg {
            mode: LegMode::Mirror,
            dest: dest_b,
            status: LegStatus::Clean,
            ..Leg::default_leg()
        };
        let verdict = Some("rc=0 (all legs clean)".to_string());
        // The prefill.
        let prefill = super::prefill_mirror_session(&[encode.clone(), mirror.clone()], &verdict)
            .expect("a clean Encode leg must prefill the second session");
        assert_eq!(prefill.source, dest_a);
        assert_eq!(prefill.legs.len(), 1);
        assert_eq!(prefill.legs[0].mode, LegMode::Mirror);
        assert!(prefill.legs[0].dest.as_os_str().is_empty());
        assert_eq!(
            prefill.note,
            "second session — source: the encode leg's output · the shelves you pick"
        );
        // The `None` case (no clean Encode leg — the honest
        // disable): a failed Encode + a finished run.
        let encode_failed = Leg {
            mode: LegMode::Encode,
            dest: dest_a.clone(),
            status: LegStatus::Failed {
                line: "rc=1 (1 of 1 clips failed)".to_string(),
            },
            ..Leg::default_leg()
        };
        assert_eq!(
            super::prefill_mirror_session(&[encode_failed, mirror.clone()], &verdict),
            None
        );
        // The `None` case (the run did not finish — the verdict is
        // absent).
        assert_eq!(
            super::prefill_mirror_session(&[encode.clone(), mirror.clone()], &None),
            None
        );
        // The idempotence: the pure function over the run's
        // (legs, verdict) re-applies to the identical fresh prefill
        // (not a stack); the prefilled composer itself carries no
        // clean Encode leg (the honest disable — no stack).
        let again = super::prefill_mirror_session(&[encode, mirror], &verdict).unwrap();
        assert_eq!(again, prefill);
        assert_eq!(super::prefill_mirror_session(&prefill.legs, &verdict), None);
    }
}
