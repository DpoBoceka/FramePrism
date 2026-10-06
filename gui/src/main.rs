//! The eframe shell (the windowed GUI — the 3-pane app: Process /
//! New camera / Compare). `--selftest` is handled FIRST (before any
//! eframe/window/GPU import executes — the headless selftest, the
//! lib path only: no window, no GPU; the R8 Process surface).
//!
//! The Process pane is the job composer (the first-citizen GUI
//! wave): one source tree + a list of legs (each leg = the mode
//! select + the options slot + the dest + the per-leg status) + the
//! Advanced row + the Run button + the run-report panel + the
//! archive maintenance. The identity strip is the scan-derived 3
//! states (SET UP / NEW CAMERA / UNIDENTIFIED — the details
//! disclosure names the SETUP MISMATCH state as the run-time state).
//! The New camera + Compare panes are honest placeholders (the pane
//! set is FINAL per the ruling; the contents are the next wave's
//! lanes). No cancel (the job runs to completion — an honest
//! absence, not a hidden one). The path fields are text-editable +
//! the native pickers (the `Browse…` buttons — the `rfd` sync pick:
//! a pick REPLACES the field text, a cancel leaves it UNCHANGED).
//! The profile field is the camera-identity seam (the
//! `FRAMEPRISM_PROFILES` env — the probe order: the field → the
//! launch env → the core's own `<cwd>/profiles` → `<exe-dir>/profiles`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use frameprism_gui::{
    arbiter, prefill_mirror_session, pre_job_status, profile_env_seam, scan, start_job,
    start_maintenance, poll, DeriveBits, JobState, Leg, LegMode, LegStatus, MaintenanceKind,
    MaintenanceState, PREFILL_NOTE, READY_WILL_RUN, RunKnobs, Scan, StripState,
    UNIDENTIFIED_LINE, UNIDENTIFIED_SUBLINE,
};

const WINDOW_TITLE: &str = "FramePrism";
/// The v1 honesty note (the pinned surface — the sidebar footer).
const HONESTY_NOTE: &str = "the job runs to completion — no cancel in v1";
/// The poll cadence (the v1 ~4 Hz).
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// The New camera pane placeholder (the verbatim pin — the pane set
/// is FINAL; the content is the next wave's lane).
const PLACEHOLDER_NEW_CAMERA: &str =
    "the New camera pane — the measure → review → set up loop (not yet available in this build)";
/// The Compare pane placeholder (the verbatim pin).
const PLACEHOLDER_COMPARE: &str =
    "the Compare pane — the per-frame pixel comparison of two encodes (not yet available in this build)";
const MODE_LOSSLESS: &str = "Lossless";
const MODE_LOG10: &str = "Log10";
/// The archive-maintenance row's not-yet-audited slot (the R6 pin).
const NOT_AUDITED: &str = "not audited";

/// The pane set (FINAL per the ruling — the 3 tabs; the placeholder
/// contents are the next wave's lanes).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Process,
    NewCamera,
    Compare,
}

/// The scan surface (the session scan + the honest scan-refusal
/// state — never a silent empty list).
#[derive(Clone, Debug)]
enum ScanState {
    /// No scan yet.
    None,
    /// The scan (the strip + the resolution line ride this).
    Ok(Scan),
    /// The scan refused (the core's named line — displayed verbatim).
    Err(String),
}

/// The eframe app: the 3-pane shell + the job state + the scan + the
/// composer + the run report + the archive maintenance.
struct App {
    tab: Tab,
    // The identity strip (the session scan + the details disclosure).
    scan_state: ScanState,
    details_open: bool,
    // The composer (the one session source + the leg list).
    source: String,
    profile: String,
    launch_env: String,
    legs: Vec<Leg>,
    // The Advanced row (the collapsed disclosure — the GUI default).
    advanced_open: bool,
    strict: bool,
    trial: bool,
    force: bool,
    fast: bool,
    downscale: bool,
    checksums: bool,
    mode_label: String,
    // The job (the v1 pattern: the shared state the UI polls at the
    // ~4 Hz cadence; the per-job worker thread owns the writes).
    job: Option<Arc<Mutex<JobState>>>,
    snapshot: Option<JobState>,
    running: bool,
    last_poll: Instant,
    // The last finished run (the run-report panel's content —
    // independent of the composer: the prefill resets the composer,
    // the report shows the run).
    run_legs: Option<Vec<Leg>>,
    run_source: Option<String>,
    run_verdict: Option<String>,
    // The archive maintenance (the R6 rows — per shelved dest).
    maint: Option<Arc<Mutex<MaintenanceState>>>,
    maint_running: bool,
    maint_lines: HashMap<String, String>,
    // The status line + the scan-error / refusal lines (the core's
    // NAMED lines — never hidden).
    status: String,
}

impl App {
    fn new() -> Self {
        Self {
            tab: Tab::Process,
            scan_state: ScanState::None,
            details_open: false,
            source: String::new(),
            profile: String::new(),
            launch_env: std::env::var("FRAMEPRISM_PROFILES").unwrap_or_default(),
            legs: vec![Leg::default_leg()],
            advanced_open: false,
            strict: false,
            trial: false,
            force: false,
            fast: false,
            downscale: false,
            checksums: false,
            mode_label: MODE_LOSSLESS.to_string(),
            job: None,
            snapshot: None,
            running: false,
            last_poll: Instant::now(),
            run_legs: None,
            run_source: None,
            run_verdict: None,
            maint: None,
            maint_running: false,
            maint_lines: HashMap::new(),
            status: "the Process surface: the source tree → the legs → Run".to_string(),
        }
    }

    fn any_running(&self) -> bool {
        self.running || self.maint_running
    }

    /// The profile env seam (the GUI process is the SOLE owner — the
    /// v1 invariant: the env AFTER the seam is EXACTLY the seam's
    /// effective value or absent).
    fn apply_seam(&self) {
        match profile_env_seam(&self.profile, &self.launch_env) {
            Some(p) => std::env::set_var("FRAMEPRISM_PROFILES", p),
            None => std::env::remove_var("FRAMEPRISM_PROFILES"),
        }
    }

    /// The session scan (the fresh scan at the Run — the arbiter's
    /// "last scan"; the explicit Scan button rides it too).
    fn do_scan(&mut self) {
        self.apply_seam();
        let src = Path::new(&self.source);
        match scan(src) {
            Ok(s) => {
                self.scan_state = ScanState::Ok(s.clone());
                self.status = format!("scanned: {} clip(s)", s.clips.len());
            }
            Err(err) => {
                self.scan_state = ScanState::Err(err.clone());
                self.status = "the scan refused (the named line in the details)".to_string();
            }
        }
    }

    fn strip_state(&self) -> StripState {
        match &self.scan_state {
            ScanState::Ok(s) => s.strip_state(),
            // No scan yet / the scan refused = the no-clips rule.
            _ => StripState::Unidentified,
        }
    }

    /// The native folder pick (the `rfd` sync pick — the v1
    /// precedent; a pick REPLACES the field text, a cancel leaves it
    /// UNCHANGED — a cancel is not an error, no status line).
    fn do_browse_pick() -> Option<PathBuf> {
        rfd::FileDialog::new().pick_folder()
    }

    /// The Run (the R4 model — the pre-job checks + the pre-Run
    /// arbiter + the job thread).
    fn do_run(&mut self) {
        // The mode arbiter (the v1 verbatim refusal lines stand for
        // the parked modes).
        let mode = match arbiter(self.mode_label.to_lowercase().as_str()) {
            Ok(mode) => mode,
            Err(err) => {
                self.status = err;
                return;
            }
        };
        // The profile pre-job refusal (the fast honest path — the
        // v1 verbatim refusal).
        let profile = self.profile.trim();
        if !profile.is_empty() && !Path::new(profile).is_file() {
            self.status = format!(
                "refusal: the profile is not a file (the core's env seam accepts an explicit profile file only): {profile}"
            );
            return;
        }
        self.apply_seam();
        let src = Path::new(&self.source);
        // The fresh scan (the run's scan — the strip re-derives).
        let scan = match scan(src) {
            Ok(s) => {
                self.scan_state = ScanState::Ok(s.clone());
                s
            }
            Err(err) => {
                self.scan_state = ScanState::Err(err.clone());
                self.status = err;
                return;
            }
        };
        let strip = scan.strip_state();
        // The pre-Run arbiter (the leg-level NAMED refusals — the
        // core is never called for a refused leg).
        let mut legs = self.legs.clone();
        for leg in legs.iter_mut() {
            leg.status = pre_job_status(leg.mode, strip, src, &leg.dest);
        }
        // The NEW CAMERA lock (the core's unpinned contract —
        // verify-on; the toggle is locked ON in the UI, the runner
        // rides the leg's verify).
        if strip == StripState::NewCamera {
            for leg in legs.iter_mut() {
                if leg.mode == LegMode::Encode {
                    leg.verify = true;
                }
            }
        }
        let knobs = RunKnobs {
            encode_mode: mode,
            strict: self.strict,
            trial: self.trial,
            force: self.force,
            fast: self.fast,
            downscale: self.downscale,
            checksums: self.checksums,
            jobs: 0, // the default pool (the numeric field is a follow-up)
        };
        let state = Arc::new(Mutex::new(JobState::default()));
        match start_job(src, legs, scan, knobs, state.clone()) {
            Ok(()) => {
                self.job = Some(state);
                self.snapshot = None;
                self.running = true;
                self.last_poll = Instant::now();
                self.status = "job started".to_string();
            }
            Err(err) => {
                self.status = err;
            }
        }
    }

    /// The maintenance run (the audit / restore — the per-operation
    /// shared state the UI polls at the job's cadence).
    fn start_maint(&mut self, kind: MaintenanceKind, dest: &Path, from: Option<&Path>) {
        self.apply_seam(); // the audit's camera line resolves the profile set (the env seam)
        let state = Arc::new(Mutex::new(MaintenanceState::default()));
        match start_maintenance(kind, dest, from, state.clone()) {
            Ok(()) => {
                self.maint = Some(state);
                self.maint_running = true;
                self.last_poll = Instant::now();
                self.status = format!("{kind:?} started");
            }
            Err(err) => {
                self.status = err;
            }
        }
    }

    /// The poll (the v1 pattern: the shared state is polled at the
    /// ~4 Hz cadence; the per-job worker thread owns the writes; the
    /// live snapshot rides every poll — the per-clip progress).
    fn poll_job(&mut self) {
        if let Some(job) = &self.job {
            let snap = poll(job);
            self.snapshot = Some(snap.clone()); // the live progress (the v1 pattern)
            if snap.finished {
                self.running = false;
                self.job = None;
                // Sync the composer's legs (the run's statuses /
                // summaries / logs — the index correspondence: the
                // composer is frozen while a job runs).
                for (i, leg) in self.legs.iter_mut().enumerate() {
                    if let Some(p) = snap.legs.get(i) {
                        leg.status = p.status.clone();
                        leg.summary = p.summary.clone();
                        leg.log = p.log.clone();
                    }
                }
                // The run report (the run's legs — the prefill
                // resets the composer, the report shows the run).
                self.run_legs = Some(self.legs.clone());
                self.run_source = Some(self.source.clone());
                self.run_verdict = snap.verdict.clone();
                self.snapshot = Some(snap);
            }
        }
        if let Some(m) = &self.maint {
            let snap = m.lock().unwrap().clone();
            if snap.finished {
                self.maint = None;
                self.maint_running = false;
                self.maint_lines.insert(snap.dest.clone(), snap.line.clone());
                self.status = snap.line.clone(); // the core's named line — never hidden
            }
        }
    }

    /// The `Mirror this output →` affordance (the R5.2 pure
    /// function — the "second session" is a pure GUI state
    /// operation: no core involvement; the user's next Run is the
    /// second session).
    fn do_prefill(&mut self) {
        let Some(legs) = &self.run_legs else {
            return;
        };
        if let Some(prefill) = prefill_mirror_session(legs, &self.run_verdict) {
            self.source = prefill.source.to_string_lossy().into_owned();
            self.legs = prefill.legs;
            self.scan_state = ScanState::None;
            self.status = prefill.note.clone(); // the note line (the verbatim pin)
        }
    }

    fn prefill_enabled(&self) -> bool {
        self.run_legs
            .as_ref()
            .is_some_and(|legs| prefill_mirror_session(legs, &self.run_verdict).is_some())
    }

    /// The leg row's live line while a job runs (the current leg's
    /// progress — the `…` token for the pending legs; empty string
    /// when no job runs — the row shows its status instead).
    fn live_leg_line(&self, i: usize) -> String {
        if !self.running {
            return String::new();
        }
        if self.snapshot.as_ref().and_then(|s| s.current_leg) != Some(i) {
            return "…".to_string();
        }
        match self.snapshot.as_ref().and_then(|s| s.legs.get(i)) {
            Some(p) if p.clip_total > 0 => match &p.clip_current {
                Some(key) => format!("running — {key} ({}/{})", p.clip_done, p.clip_total),
                None => format!("running ({}/{})", p.clip_done, p.clip_total),
            },
            Some(_) => "running".to_string(),
            None => "…".to_string(),
        }
    }

    // -----------------------------------------------------------------
    // The panes.
    // -----------------------------------------------------------------

    fn ui(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("sidebar")
            .resizable(false)
            .default_size(170.0)
            .min_size(140.0)
            .show(ui, |ui| {
                self.sidebar_ui(ui);
            });
        egui::Panel::top("identity").show(ui, |ui| {
            self.strip_ui(ui);
        });
        egui::CentralPanel::default().show(ui, |ui| {
            match self.tab {
                Tab::Process => self.process_ui(ui),
                Tab::NewCamera => Self::placeholder_ui(ui, PLACEHOLDER_NEW_CAMERA),
                Tab::Compare => Self::placeholder_ui(ui, PLACEHOLDER_COMPARE),
            }
        });
    }

    fn sidebar_ui(&mut self, ui: &mut egui::Ui) {
        ui.selectable_value(&mut self.tab, Tab::Process, "Process");
        ui.selectable_value(&mut self.tab, Tab::NewCamera, "New camera");
        ui.selectable_value(&mut self.tab, Tab::Compare, "Compare");
        ui.separator();
        // The footer (the v1 honesty note — the pinned surface — at
        // the bottom of the sidebar; the eframe 0.36 egui has no
        // bottom-down layout, so the band is placed explicitly).
        let rest = ui.available_rect_before_wrap();
        let line_h = 16.0;
        ui.put(
            egui::Rect::from_min_max(egui::pos2(rest.min.x, rest.max.y - 2.0 * line_h), rest.max),
            egui::Label::new(egui::RichText::new("About").weak()),
        );
        ui.put(
            egui::Rect::from_min_max(egui::pos2(rest.min.x, rest.max.y - line_h), rest.max),
            egui::Label::new(egui::RichText::new(HONESTY_NOTE).weak()),
        );
    }

    fn placeholder_ui(ui: &mut egui::Ui, line: &str) {
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.weak(line);
        });
    }

    /// The identity strip (the 3 scan-derived states + the details
    /// disclosure: the resolution line + the 4-state legend).
    fn strip_ui(&mut self, ui: &mut egui::Ui) {
        let (state, line, subline) = match &self.scan_state {
            ScanState::Ok(s) => {
                let st = s.strip_state();
                let (l, sub) = frameprism_gui::strip_lines(st, &s.clips, &s.set);
                (st, l, sub)
            }
            // No scan yet / the scan refused = the no-clips rule.
            _ => (
                StripState::Unidentified,
                UNIDENTIFIED_LINE.to_string(),
                UNIDENTIFIED_SUBLINE.to_string(),
            ),
        };
        let any = self.any_running();
        ui.horizontal(|ui| {
            let (chip, color) = match state {
                StripState::SetUp => ("SET UP", egui::Color32::from_rgb(70, 150, 70)),
                StripState::NewCamera => ("NEW CAMERA", egui::Color32::from_rgb(190, 150, 30)),
                StripState::Unidentified => ("UNIDENTIFIED", egui::Color32::from_rgb(180, 60, 60)),
            };
            ui.colored_label(color, chip);
            ui.vertical(|ui| {
                ui.strong(&line);
                ui.weak(&subline);
            });
            // The CTA (the mockup's New camera jump — the
            // UNIDENTIFIED sub-line is the affordance; the NEW
            // CAMERA state is the same: the set-up loop is the New
            // camera pane).
            if matches!(state, StripState::NewCamera | StripState::Unidentified)
                && ui.add_enabled(!any, egui::Button::new("Set up this camera")).clicked()
            {
                self.tab = Tab::NewCamera;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(if self.details_open { "details ▴" } else { "details ▾" })
                    .clicked()
                {
                    self.details_open = !self.details_open;
                }
            });
        });
        if self.details_open {
            ui.add_space(4.0);
            match &self.scan_state {
                ScanState::Ok(s) => {
                    // The resolution line (the ABSENT honesty line
                    // when no set resolves — the core's line
                    // verbatim, no re-derivation).
                    ui.monospace(frameprism_gui::resolution_line(&s.set, &s.profiles_line));
                }
                ScanState::Err(err) => {
                    ui.colored_label(egui::Color32::from_rgb(180, 60, 60), err);
                }
                ScanState::None => {}
            }
            // The 4-state legend (the mockup's off-surface "why"
            // moved into the app disclosure; the strip surface stays
            // copy-only).
            for legend in frameprism_gui::LEGEND {
                ui.weak(legend);
            }
        }
    }

    /// The Process pane (the job composer).
    fn process_ui(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            let any = self.any_running();
            // The Source row (the v1 surface: the text field + the
            // Scan + the Browse).
            ui.horizontal(|ui| {
                ui.label("Source");
                ui.add_enabled(
                    !any,
                    egui::TextEdit::singleline(&mut self.source)
                        .hint_text("/path/to/card")
                        .desired_width(420.0),
                );
                if ui.add_enabled(!any, egui::Button::new("Scan")).clicked() {
                    self.do_scan();
                }
                if ui.add_enabled(!any, egui::Button::new("Browse…")).clicked() {
                    if let Some(p) = Self::do_browse_pick() {
                        self.source = p.to_string_lossy().into_owned();
                    }
                }
            });
            ui.add_space(8.0);
            // The Legs box (the mockup's surface: one row per leg —
            // the mode select + the options slot + the dest + the
            // per-leg status; `+ add leg` appends the default).
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.weak("Legs");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add_enabled(!any, egui::Button::new("+ add leg")).clicked() {
                            self.legs.push(Leg::default_leg());
                        }
                    });
                });
                // The per-row data (computed BEFORE the
                // `iter_mut` — the row renderer is an associated
                // function, no `self` inside the loop).
                let strip = self.strip_state();
                let live: Vec<String> = (0..self.legs.len())
                    .map(|i| self.live_leg_line(i))
                    .collect();
                for (i, leg) in self.legs.iter_mut().enumerate() {
                    Self::leg_row(ui, leg, any, strip, live[i].clone());
                    ui.separator();
                }
            });
            ui.add_space(8.0);
            // The Advanced row (the collapsed disclosure — the GUI
            // default; the v1 slots; the `jobs` field = the
            // `auto` label).
            egui::CollapsingHeader::new("Advanced (defaults)")
                .default_open(self.advanced_open)
                .show(ui, |ui| {
                    self.advanced_ui(ui, any);
                });
            ui.add_space(8.0);
            // The Run button (right-aligned; disabled while a job /
            // maintenance runs — the v1 pattern).
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(!any, egui::Button::new("Run")).clicked() {
                        self.do_run();
                    }
                });
            });
            ui.add_space(8.0);
            // The archive maintenance (the R6 rows — one row per
            // shelved dest: the Mirror + the Encode leg dests).
            self.maintenance_ui(ui, any);
            // The run-report panel (after the first finished run —
            // the v1 status block, extended).
            if self.run_legs.is_some() {
                ui.add_space(8.0);
                self.report_ui(ui);
            }
            ui.add_space(8.0);
            ui.monospace(&self.status);
            ui.weak(HONESTY_NOTE);
        });
    }

    /// One leg row (the mockup's surface — the mode select + the
    /// options slot + the dest field + the per-leg status; the
    /// status = the pre-Run arbiter line (before the first run) or
    /// the live progress (while the leg runs) or the run state /
    /// summary (after)). An associated function (no `self`): the
    /// row loop borrows `self.legs` mutably, so the renderer takes
    /// its data as parameters.
    fn leg_row(
        ui: &mut egui::Ui,
        leg: &mut Leg,
        any: bool,
        strip: StripState,
        live: String,
    ) {
        ui.horizontal(|ui| {
            // The mode select.
            egui::ComboBox::from_label("")
                .selected_text(leg.mode.label())
                .show_ui(ui, |ui| {
                    for m in [
                        LegMode::Encode,
                        LegMode::Mirror,
                        LegMode::Derive,
                        LegMode::Decode,
                    ] {
                        ui.selectable_value(&mut leg.mode, m, m.label());
                    }
                });
            // The options slot (the mockup's per-mode slot).
            match leg.mode {
                LegMode::Encode => {
                    let locked = strip == StripState::NewCamera;
                    let mut verify = leg.verify || locked;
                    if locked {
                        // The NEW CAMERA lock (the core's unpinned
                        // contract — verify-on; the toggle is
                        // locked ON + the slot text is named).
                        ui.add_enabled(false, egui::Checkbox::new(&mut verify, ""));
                        ui.weak("on (the new-camera guard)");
                        leg.verify = true;
                    } else {
                        ui.checkbox(&mut verify, "");
                        leg.verify = verify;
                    }
                }
                LegMode::Mirror => {
                    // The offload's verify is inherent (the offload
                    // contract — there is no off switch).
                    ui.weak("on");
                    leg.verify = true;
                }
                LegMode::Derive => {
                    egui::ComboBox::from_label("")
                        .selected_text(leg.bits.label())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut leg.bits,
                                DeriveBits::Eight,
                                "8-bit (v>>4)",
                            );
                            ui.selectable_value(
                                &mut leg.bits,
                                DeriveBits::Ten,
                                "10-bit (v>>2)",
                            );
                        });
                }
                LegMode::Decode => {
                    // The frame slot (the v1 `all` — the one-frame
                    // pick is a follow-up).
                    ui.weak("all");
                }
            }
            // The dest field (the text-editable + the native pick).
            let mut dest_text = leg.dest.to_string_lossy().into_owned();
            let dest_res = ui
                .add_enabled(
                    !any,
                    egui::TextEdit::singleline(&mut dest_text)
                        .hint_text("/path/to/dest")
                        .desired_width(360.0),
                )
                .changed();
            if dest_res {
                leg.dest = PathBuf::from(dest_text.trim());
            }
            if ui.add_enabled(!any, egui::Button::new("Browse…")).clicked() {
                if let Some(p) = Self::do_browse_pick() {
                    leg.dest = p;
                }
            }
            // The per-leg status (right-aligned, monospace).
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (status, color) = if !live.is_empty() {
                    (
                        live.clone(),
                        if live == "…" {
                            ui.visuals().weak_text_color()
                        } else {
                            egui::Color32::from_rgb(90, 130, 180)
                        },
                    )
                } else {
                    let color = match &leg.status {
                        LegStatus::Clean => egui::Color32::from_rgb(70, 150, 70),
                        LegStatus::Failed { .. } | LegStatus::Refused { .. } => {
                            egui::Color32::from_rgb(180, 60, 60)
                        }
                        LegStatus::Ready => egui::Color32::from_rgb(190, 150, 30),
                        LegStatus::Running => egui::Color32::from_rgb(90, 130, 180),
                        LegStatus::Idle => ui.visuals().weak_text_color(),
                    };
                    let status = match &leg.status {
                        LegStatus::Idle => "—".to_string(),
                        LegStatus::Ready => READY_WILL_RUN.to_string(),
                        LegStatus::Refused { line, .. } => line.clone(),
                        LegStatus::Clean if !leg.summary.is_empty() => leg.summary.clone(),
                        LegStatus::Clean => "clean".to_string(),
                        LegStatus::Failed { line } => line.clone(),
                        LegStatus::Running => "running".to_string(),
                    };
                    (status, color)
                };
                ui.colored_label(color, status.as_str());
            });
        });
        // The pre-Run refusal's composing note (the in-place line
        // that still stands — the evaluation order names the
        // identity refusal FIRST).
        if let LegStatus::Refused {
            note: Some(note), ..
        } = &leg.status
        {
            ui.colored_label(egui::Color32::from_rgb(180, 60, 60), note);
        }
    }

    /// The Advanced row (the v1 slots — the `jobs` field = the
    /// `auto` label; the `profile` seam's field; the mode select's
    /// offered modes).
    fn advanced_ui(&mut self, ui: &mut egui::Ui, any: bool) {
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.strict, "strict");
            ui.checkbox(&mut self.trial, "trial");
            ui.checkbox(&mut self.force, "force");
            ui.checkbox(&mut self.fast, "fast");
            ui.checkbox(&mut self.downscale, "downscale2x");
            ui.checkbox(&mut self.checksums, "checksums");
            egui::ComboBox::from_label("mode")
                .selected_text(&self.mode_label)
                .show_ui(ui, |ui| {
                    for label in [MODE_LOSSLESS, MODE_LOG10] {
                        ui.selectable_value(&mut self.mode_label, label.to_string(), label);
                    }
                });
            // The `jobs` field (the v1 `auto` label — the numeric
            // field is a follow-up).
            ui.label("jobs");
            ui.weak("auto");
        });
        ui.horizontal(|ui| {
            ui.label("profile");
            ui.add_enabled(
                !any,
                egui::TextEdit::singleline(&mut self.profile)
                    .hint_text("/path/to/profile (empty = the env / the checkout profiles)")
                    .desired_width(420.0),
            );
        });
    }

    /// The archive maintenance (the R6 rows — one row per shelved
    /// dest, in leg order, deduped; the line = the core's last
    /// non-empty captured line after the operation, else the
    /// `not audited` slot).
    fn maintenance_ui(&mut self, ui: &mut egui::Ui, any: bool) {
        let mut dests: Vec<PathBuf> = Vec::new();
        for leg in &self.legs {
            if matches!(leg.mode, LegMode::Mirror | LegMode::Encode)
                && !leg.dest.as_os_str().is_empty()
                && !dests.iter().any(|d| d == &leg.dest)
            {
                dests.push(leg.dest.clone());
            }
        }
        if dests.is_empty() {
            return;
        }
        ui.strong("ARCHIVE MAINTENANCE");
        // The session source (the restore's pristine master) as a
        // local (the row loop below mutates `self` — the borrow must
        // not overlap).
        let source_for_restore = self.source.clone();
        for dest in &dests {
            let base = dest
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| dest.display().to_string());
            let key = dest.display().to_string();
            let line = self
                .maint_lines
                .get(&key)
                .cloned()
                .unwrap_or_else(|| NOT_AUDITED.to_string());
            ui.horizontal(|ui| {
                ui.monospace(format!("{base}: {line}"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(!any, egui::Button::new("Audit now")).clicked() {
                        self.start_maint(MaintenanceKind::Audit, dest, None);
                    }
                    // The restore from the pristine master (the
                    // session source — the R6 pin).
                    if ui.add_enabled(!any, egui::Button::new("Restore")).clicked() {
                        self.start_maint(
                            MaintenanceKind::Restore,
                            dest,
                            Some(Path::new(source_for_restore.as_str())),
                        );
                    }
                });
            });
        }
    }

    /// The run-report panel (the R4.5 surface — the report header +
    /// the per-leg lines filled in as they complete + the current
    /// leg's live status + the raw log per leg (the disclosure) +
    /// the `Mirror this output →` affordance).
    fn report_ui(&mut self, ui: &mut egui::Ui) {
        // The run's data as locals (the prefill below mutates
        // `self` — no borrow of `self.run_legs` may outlive it).
        let legs: Vec<Leg> = self.run_legs.clone().unwrap_or_default();
        let verdict = self.run_verdict.clone().unwrap_or_default();
        let source_base = self
            .run_source
            .clone()
            .map(PathBuf::from)
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
            .or_else(|| self.run_source.clone())
            .unwrap_or_default();
        let n = legs.len();
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.strong(format!("run report — {source_base} · {n} legs · {verdict}"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // The `Mirror this output →` affordance (the
                    // R5.2 prefill — the honest disable without a
                    // clean Encode leg).
                    if ui
                        .add_enabled(self.prefill_enabled(), egui::Button::new("Mirror this output →"))
                        .clicked()
                    {
                        self.do_prefill();
                    }
                });
            });
            for (i, leg) in legs.iter().enumerate() {
                let base = leg
                    .dest
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| leg.dest.display().to_string());
                // The per-leg report line (the R4.3 pin — the
                // summary filled at the leg's completion; the live
                // status while running; the pending `…` for the
                // not-yet-started legs).
                let slot = if self.running {
                    match self.snapshot.as_ref().and_then(|s| s.legs.get(i)) {
                        Some(p)
                            if !matches!(
                                p.status,
                                LegStatus::Running | LegStatus::Idle
                            )
                            && !p.summary.is_empty() =>
                        {
                            p.summary.clone()
                        }
                        Some(p) if self.snapshot.as_ref().and_then(|s| s.current_leg) == Some(i) => {
                            if p.clip_total > 0 {
                                format!("running ({}/{})", p.clip_done, p.clip_total)
                            } else {
                                "running".to_string()
                            }
                        }
                        _ => "…".to_string(),
                    }
                } else if !leg.summary.is_empty() {
                    leg.summary.clone()
                } else {
                    "—".to_string()
                };
                ui.monospace(format!(
                    "leg {} · {} → {}: {}",
                    i + 1,
                    leg.mode.line(),
                    base,
                    slot
                ));
                // The raw log per leg (the disclosure — the
                // captured stream output, verbatim; the non-unix
                // honesty line where the capture is unavailable).
                if !leg.log.is_empty() {
                    egui::CollapsingHeader::new(format!(
                        "raw log — leg {} ({})",
                        i + 1,
                        leg.mode.line()
                    ))
                    .default_open(false)
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(200.0)
                            .show(ui, |ui| {
                                ui.monospace(&leg.log);
                            });
                    });
                }
            }
            // The note line (the verbatim pin — the enabled
            // affordance's companion copy).
            if self.prefill_enabled() {
                ui.weak(PREFILL_NOTE);
            }
        });
    }
}

impl eframe::App for App {
    /// The pre-ui logic (the no-painting phase — the job poll at the
    /// ~4 Hz cadence + the continuous repaint while a job runs; the
    /// v1 pattern).
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.any_running() {
            if Instant::now().duration_since(self.last_poll) >= POLL_INTERVAL {
                self.last_poll = Instant::now();
                self.poll_job();
            }
            // The continuous repaint at the poll cadence (the job's
            // progress + verdict land at ~4 Hz while it runs).
            ctx.request_repaint_after(POLL_INTERVAL);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            self.ui(ui);
        });
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--selftest") {
        // The headless selftest (the lib path only — no window, no
        // GPU; the R8 Process surface). The VERBATIM OK line (the
        // R8 pin; the gate's check rides it); the FAIL line = the
        // named reason.
        match frameprism_gui::selftest() {
            Ok(()) => {
                println!("gui selftest: OK (3 legs rc=0, derive 1/1, refusal named, 1 frame)");
                std::process::exit(0);
            }
            Err(reason) => {
                println!("gui selftest: FAIL — {reason}");
                std::process::exit(1);
            }
        }
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(WINDOW_TITLE)
            .with_inner_size([1000.0, 700.0]),
        ..Default::default()
    };
    let res = eframe::run_native(
        WINDOW_TITLE,
        options,
        Box::new(|_cc| Ok(Box::new(App::new()))),
    );
    if let Err(err) = res {
        eprintln!("frameprism-gui: the window failed to start: {err}");
        std::process::exit(1);
    }
}
