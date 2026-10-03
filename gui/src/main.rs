//! The eframe shell (the windowed GUI — the utility shape). `--selftest`
//! is handled FIRST (before any eframe/window/GPU import executes — the
//! headless selftest, the lib path only: no window, no GPU).
//!
//! The v1 surface is the encode: the source dir → the clip list (the
//! offload detection scan) → the encode job with per-clip progress
//! (the core exposes no live frame-level progress — the honest unit is
//! the clip). No cancel (the job runs to completion — an honest
//! absence, not a hidden one), no offload/verify/wipe verbs. The path
//! fields are text-only (no native dialog).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;

const WINDOW_TITLE: &str = "FramePrism — encode";
const NO_CLIPS: &str = "no clips detected";
const MODE_LOSSLESS: &str = "Lossless";
const MODE_LOG10: &str = "Log10";
const HONESTY_NOTE: &str = "the job runs to completion — no cancel in v1";
/// The job-state poll cadence (~4 Hz — the UI's snapshot of the
/// per-job worker thread's shared state).
const POLL_INTERVAL: Duration = Duration::from_millis(250);

struct App {
    source: String,
    dest: String,
    mode_label: String,
    rows: Vec<frameprism_gui::ClipRow>,
    checked: Vec<bool>,
    job: Option<Arc<Mutex<frameprism_gui::JobState>>>,
    snapshot: Option<frameprism_gui::JobState>,
    running: bool,
    last_poll: Instant,
    status: String,
    done_line: Option<String>,
}

impl App {
    fn new() -> Self {
        Self {
            source: String::new(),
            dest: String::new(),
            mode_label: MODE_LOSSLESS.to_string(),
            rows: Vec::new(),
            checked: Vec::new(),
            job: None,
            snapshot: None,
            running: false,
            last_poll: Instant::now(),
            status: "the v1 surface: the source dir → Scan → the clip list → Start encode"
                .to_string(),
            done_line: None,
        }
    }

    /// The on-demand re-scan (the clip list refresh — the core's own
    /// named line on failure, the EMPTY vec on an empty scan — the
    /// UI renders the honest `no clips detected` line, never a silent
    /// empty list).
    fn do_scan(&mut self) {
        let src = std::path::Path::new(&self.source);
        match frameprism_gui::clips(src) {
            Ok(rows) => {
                self.checked = vec![true; rows.len()]; // default all-on
                self.status = format!("scanned: {} clip(s)", rows.len());
                self.rows = rows;
            }
            Err(err) => {
                self.rows = Vec::new();
                self.checked = Vec::new();
                self.status = err; // the named line — never hidden
            }
        }
    }

    /// The encode job start (the pre-job refusals render as the NAMED
    /// line in the status row — never hidden; a started job owns the
    /// shared `JobState` the UI polls at ~4 Hz).
    fn do_start(&mut self) {
        let mode = match frameprism_gui::arbiter(self.mode_label.to_lowercase().as_str()) {
            Ok(mode) => mode,
            Err(err) => {
                self.status = err;
                return;
            }
        };
        let keys: Vec<String> = self
            .rows
            .iter()
            .enumerate()
            .filter(|(i, _)| self.checked.get(*i).copied().unwrap_or(false))
            .map(|(_, row)| row.key.clone())
            .collect();
        let src = std::path::Path::new(&self.source);
        let dst = std::path::Path::new(&self.dest);
        let state = Arc::new(Mutex::new(frameprism_gui::JobState::default()));
        match frameprism_gui::start_encode(src, dst, mode, &keys, state.clone()) {
            Ok(()) => {
                self.job = Some(state);
                self.snapshot = None;
                self.done_line = None;
                self.running = true;
                self.last_poll = Instant::now();
                self.status = "job started".to_string();
            }
            Err(err) => {
                self.status = err; // the named line — never hidden
            }
        }
    }

    /// The ~4 Hz poll (the job-state snapshot — the UI never holds the
    /// shared lock for more than the snapshot read; the per-job
    /// worker thread owns the writes).
    fn poll_job(&mut self) {
        let Some(job) = &self.job else {
            return;
        };
        let snap = frameprism_gui::poll(job);
        if snap.finished {
            self.running = false;
            self.job = None;
            if let Some(verdict) = snap.verdict.clone() {
                // The VERBATIM verdict line + the dest path on
                // completion.
                self.done_line = Some(format!("{verdict} — dest: {}", self.dest));
            }
        }
        self.snapshot = Some(snap);
    }
}

impl eframe::App for App {
    /// The pre-ui logic (the no-painting phase — the job poll at the
    /// ~4 Hz cadence + the continuous repaint while a job runs).
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.running {
            if Instant::now().duration_since(self.last_poll) >= POLL_INTERVAL {
                self.last_poll = Instant::now();
                self.poll_job();
            }
            // The continuous repaint at the poll cadence (the job's
            // progress + verdict land at ~4 Hz while it runs).
            ctx.request_repaint_after(POLL_INTERVAL);
        }
    }

    /// The UI (the utility shape — the six surface elements).
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            // (1) the source dir + the on-demand scan.
            ui.horizontal(|ui| {
                ui.label("Source dir");
                ui.add(
                    egui::TextEdit::singleline(&mut self.source)
                        .hint_text("/path/to/card")
                        .desired_width(420.0),
                );
                if ui.button("Scan").clicked() {
                    self.do_scan();
                }
            });
            ui.separator();

            // The clip list (one row per clip — the checkbox (default
            // all-on) + the key + the class; an empty scan renders the
            // honest line).
            if self.rows.is_empty() {
                ui.weak(NO_CLIPS);
            } else {
                egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                    for (i, row) in self.rows.iter().enumerate() {
                        let mut on = self.checked.get(i).copied().unwrap_or(false);
                        ui.checkbox(&mut on, format!("{} — {}", row.key, row.class));
                        self.checked[i] = on;
                    }
                });
            }
            ui.separator();

            // (2) the mode (the combo — Lossless default / Log10).
            ui.horizontal(|ui| {
                ui.label("Mode");
                egui::ComboBox::from_label("")
                    .selected_text(self.mode_label.clone())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.mode_label,
                            MODE_LOSSLESS.to_string(),
                            MODE_LOSSLESS,
                        );
                        ui.selectable_value(
                            &mut self.mode_label,
                            MODE_LOG10.to_string(),
                            MODE_LOG10,
                        );
                    });
            });

            // (3) the dest dir (text-only — the v1 path fields).
            ui.horizontal(|ui| {
                ui.label("Dest dir");
                ui.add(
                    egui::TextEdit::singleline(&mut self.dest)
                        .hint_text("/path/to/encoded")
                        .desired_width(420.0),
                );
            });

            // (4) the start (disabled while a job runs — the pre-job
            // refusals land in the status row as the named line).
            ui.horizontal(|ui| {
                let response = ui.add_enabled(!self.running, egui::Button::new("Start encode"));
                if response.clicked() {
                    self.do_start();
                }
            });
            ui.separator();

            // (5) the progress (the bar + the current clip key + the
            // running line; the verdict line + the dest path on
            // completion).
            if self.running {
                if let Some(snap) = &self.snapshot {
                    let frac = if snap.total == 0 {
                        0.0
                    } else {
                        snap.done as f32 / snap.total as f32
                    };
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .text(format!("{}/{}", snap.done, snap.total)),
                    );
                    if let Some(current) = &snap.current {
                        ui.label(format!("current clip: {current}"));
                    }
                    ui.label(format!(
                        "job running — {}/{}",
                        snap.done, snap.total
                    ));
                    if let Some(err) = &snap.last_error {
                        ui.colored_label(egui::Color32::RED, err.as_str());
                    }
                }
            }
            if let Some(line) = &self.done_line {
                ui.strong(line.as_str());
            }
            // The status row (the refusals + the scan results — never
            // hidden).
            ui.monospace(&self.status);
            ui.separator();

            // (6) the static honesty note (the honest absence — there
            // is NO cancel button; the core exposes no cancel handle).
            ui.weak(HONESTY_NOTE);
        });
    }
}

fn main() {
    // `--selftest` is handled FIRST (before any eframe/window/GPU
    // import executes — the headless selftest, the lib path only):
    // the VERBATIM OK line (one line, stdout) + exit 0, or the named
    // FAIL line + exit 1.
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--selftest") {
        match frameprism_gui::selftest() {
            Ok(()) => {
                println!("gui selftest: OK (1/1 clips, rc=0, lossless)");
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
            .with_inner_size([760.0, 520.0]),
        ..Default::default()
    };
    let res =
        eframe::run_native(WINDOW_TITLE, options, Box::new(|_cc| Ok(Box::new(App::new()))));
    if let Err(err) = res {
        eprintln!("frameprism-gui: the window failed to start: {err}");
        std::process::exit(1);
    }
}
