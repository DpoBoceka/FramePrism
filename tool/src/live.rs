//! Live encode metrics (the predict-then-measure arc, second
//! half): the real-encode + dry-run surfaces — the disk I/O utilisation
//! (the card read rate is the headline number — the card is the design
//! bottleneck), the CPU utilisation (multi-core — the % can exceed 100,
//! that is the load), the frames left, and the running ETA.
//!
//! Implementation (the no-new-crates rule): raw FFI via
//! `extern "C"` + `std` only. macOS primary (the machine the gates run
//! on), Linux the named fallback (CPU measured, disk I/O the named
//! `n/a`). UNMEASURABLE = the named `n/a` — never a silent 0.
//!
//! FFI (probed on-machine — the layouts are NOT from
//! memory):
//! - macOS disk I/O: `proc_pid_rusage(pid, RUSAGE_INFO_V4, &ru)`
//!   (libproc.h) — `ri_diskio_bytesread` @144 / `ri_diskio_byteswritten`
//!   @152 of the 296-byte `rusage_info_v4`. BACKING-STORE I/O ONLY: a
//!   page-cache hit does not count (an in-process 300 MB write+fsync →
//!   the written counter moved exactly 300 MB; a read-back of the fresh
//!   file moved the read counter by 0). Process-level: the card reads +
//!   the dest writes of THIS process (the j92 in-process encode + the
//!   dry run; the jxl tier's cjxl subprocess I/O is invisible — the
//!   named non-scope, the report renders it).
//! - macOS CPU: `task_info(mach_task_self(), TASK_ABSOLUTETIME_INFO=1)`
//!   — the LIVE process-wide `total_user + total_system` in mach
//!   absolute-time ticks, converted via `mach_timebase_info` (the
//!   probed 125/3 on this host) to µs / wall → the cpu% (multi-core
//!   aware). `mach_task_self()` is the C macro for the EXTERN VARIABLE
//!   `mach_task_self_` (an `S` data symbol in libsystem_kernel — the
//!   real task port, NOT the literal 0 on this macOS; `task_info(0, …)`
//!   fails with KERN_INVALID_ADDRESS and the variable-as-function form
//!   SIGBUSes — all probed on-machine). The
//!   `TASK_BASIC_INFO` / `TASK_THREAD_TIMES_INFO` counters are stale /
//!   suspend-only on this macOS (probed: they read 0 under load while
//!   `time(1)` shows the real user time); `task_threads` (target 0 =
//!   MACH_PORT_NULL) segfaults — the absolutetime counter is the live
//!   primitive (it tracks the `time(1)` user time to the ms).
//! - Linux CPU: `clock_gettime(CLOCK_PROCESS_CPUTIME_ID)`; disk I/O:
//!   the named `n/a` (the block-granular `ru_inblock×512` variant is the
//!   named follow-up).
//!
//! Surfaces (the contract boundary): the STDOUT per-frame line is
//! EXTENDED (` · read <X> MB/s · cpu <Y>% · left <M> · ETA <m:s>` —
//! stdout is NOT a byte contract; the verdict/total lines keep their
//! existing shape byte-stable) and the MARKDOWN run report gains the
//! additive `## live` section (the final totals — the non-pinned
//! region). The TSV/sidecar machine contracts are UNTOUCHED (no
//! trailing columns — the ms/MB-s data is stdout + markdown only).
//!
//! Process-wide state (the pins.rs / selection.rs / resume.rs OnceLock
//! convention — the CLI has one encode run per process; a second set is
//! a replacement, the both-dispatch's jxl tier never begins — it runs
//! its subprocess tier without the in-process sampling).

use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// A per-frame sampling snapshot (the process-level counters + the wall).
struct Snapshot {
    /// (diskio_bytesread, diskio_byteswritten) — None = the named n/a
    /// (the FFI failed — never a silent 0).
    disk: Option<(u64, u64)>,
    /// The sum of the threads' user+system time (µs) — None = the named
    /// n/a.
    cpu_us: Option<u64>,
    wall: Instant,
}

/// The live run's in-flight state (one per process_dir encode — the j92
/// path; the dry run drives the same surface over its sequential sample
/// loop).
struct Live {
    /// The run's frame total (the `left` arithmetic: N − i).
    total_frames: usize,
    /// The frames processed so far (Done + Skipped + Failed — every
    /// frame consumes a `left` slot; the line is printed for Done only).
    processed: usize,
    /// The previous snapshot (the per-frame delta = now − prev — the
    /// card read rate is the headline number).
    prev: Snapshot,
    /// The Done frames' encode+verify wall ms (the running-ETA input:
    /// the p95 over ALL observed frames so far, recomputed per line —
    /// deterministic given the observed ms, no exponential smoothing).
    obs_ms: Vec<f64>,
    /// The per-frame cpu% (the final `cpu% mean` input).
    cpu_pcts: Vec<f64>,
    /// The per-frame read / write MB/s peaks (the final totals).
    peak_read_mbs: f64,
    peak_write_mbs: f64,
}

/// The final totals (the report's `## live` section — the non-pinned
/// region). Every Option-None field renders the named `n/a`.
#[derive(Clone)]
pub struct LiveTotals {
    pub frames_total: usize,
    pub frames_done: usize,
    pub wall_s: f64,
    /// The process's total backing-store reads over the encode window
    /// (the read-once design at the disk level — a page-cache hit does
    /// not count: a warm source shows the smaller number, the named
    /// environment property, never a silent 0).
    pub read_total: Option<u64>,
    pub read_mean_mbs: Option<f64>,
    pub read_peak_mbs: Option<f64>,
    pub write_total: Option<u64>,
    pub write_mean_mbs: Option<f64>,
    /// The mean of the per-frame cpu% (multi-core — can exceed 100).
    pub cpu_mean_pct: Option<f64>,
    pub fps: f64,
}

static CURRENT: OnceLock<Mutex<Option<Live>>> = OnceLock::new();

fn cell() -> &'static Mutex<Option<Live>> {
    CURRENT.get_or_init(|| Mutex::new(None))
}

fn snapshot() -> Snapshot {
    Snapshot {
        disk: ffi::diskio(),
        cpu_us: ffi::cpu_time_us(),
        wall: Instant::now(),
    }
}

/// Begin the live sampling for a run of `total_frames` (the process_dir
/// start / the dry-run sample loop start). Parks the begin anchors (the
/// window's start: wall + the disk counters — the final totals are the
/// begin→finish deltas) and a second begin in the same process REPLACES
/// the in-flight state (the both dispatch: the j92 tier's begin runs
/// first, the jxl tier never begins).
pub fn begin(total_frames: usize) {
    let snap = snapshot();
    *BEGIN_INSTANT.get_or_init(|| Mutex::new(None)).lock().unwrap() = Some(snap.wall);
    *BEGIN_DISK.get_or_init(|| Mutex::new(None)).lock().unwrap() = snap.disk;
    *cell().lock().unwrap() = Some(Live {
        total_frames,
        processed: 0,
        prev: snap,
        obs_ms: Vec::new(),
        cpu_pcts: Vec::new(),
        peak_read_mbs: 0.0,
        peak_write_mbs: 0.0,
    });
}

/// A Done frame: print the extended per-frame stdout line + record the
/// observation (the running-ETA + the final totals). No-op when no live
/// run is in flight (the jxl tier — the named non-scope).
pub fn note_done(file: &str, in_bytes: u64, out_bytes: u64, ratio: f64, ms: f64) {
    let mut guard = cell().lock().unwrap();
    let Some(live) = guard.as_mut() else {
        return;
    };
    let now = snapshot();
    let (read_mbs, cpu_pct) = {
        let wall_s = now.wall.duration_since(live.prev.wall).as_secs_f64();
        let read_mbs: Option<f64> = match (live.prev.disk, now.disk) {
            (Some((pr, _)), Some((nr, _))) if wall_s > 0.0 => {
                let delta = nr.saturating_sub(pr) as f64;
                Some(delta / wall_s / 1_048_576.0)
            }
            _ => None,
        };
        let cpu_pct: Option<f64> = match (live.prev.cpu_us, now.cpu_us) {
            (Some(pc), Some(nc)) if wall_s > 0.0 => {
                let delta = nc.saturating_sub(pc) as f64 / 1_000_000.0;
                Some(delta / wall_s * 100.0)
            }
            _ => None,
        };
        (read_mbs, cpu_pct)
    };
    let write_mbs = match (live.prev.disk, now.disk) {
        (Some((_, pw)), Some((_, nw))) => {
            let wall_s = now.wall.duration_since(live.prev.wall).as_secs_f64();
            if wall_s > 0.0 {
                Some(nw.saturating_sub(pw) as f64 / wall_s / 1_048_576.0)
            } else {
                None
            }
        }
        _ => None,
    };
    live.processed += 1;
    let left = live.total_frames.saturating_sub(live.processed);
    // The running ETA: frames left × the p95 over ALL observed frames
    // so far (nearest-rank, recomputed per line — deterministic given
    // the observed ms; cheap at these N).
    let eta_ms: Option<f64> = {
        live.obs_ms.push(ms);
        crate::dryrun::percentile_nearest_rank_sorted(&sorted_copy(&live.obs_ms), 0.95)
            .map(|p| left as f64 * p)
    };
    if let Some(r) = read_mbs {
        live.peak_read_mbs = live.peak_read_mbs.max(r);
    }
    if let Some(w) = write_mbs {
        live.peak_write_mbs = live.peak_write_mbs.max(w);
    }
    if let Some(c) = cpu_pct {
        live.cpu_pcts.push(c);
    }
    // The EXTENDED per-frame stdout line (the existing
    // `<name> <src B> <enc B> <ratio> <ms>` shape + the live fields —
    // stdout is not a byte contract; the verdict/total lines keep their
    // shape byte-stable).
    println!(
        "{:<32} {:>10} {:>10} {:>6.2}:1 {:>8.0} · read {} MB/s · cpu {}% · left {} · ETA {}",
        file,
        in_bytes,
        out_bytes,
        ratio,
        ms,
        fmt_mbs(read_mbs),
        fmt_pct(cpu_pct),
        left,
        fmt_mss(eta_ms),
    );
    live.prev = now;
}

/// A Skipped / Failed frame: no line (nothing was encoded this run),
/// but the frame counts for `left` + the delta window advances (the
/// next Done frame's rate is measured against THIS frame's completion,
/// not across the skip).
pub fn note_skipped() {
    let mut guard = cell().lock().unwrap();
    if let Some(live) = guard.as_mut() {
        live.processed += 1;
        live.prev = snapshot();
    }
}

/// Finish the live run: the final snapshot + the totals (the report's
/// `## live` section reads `last()`). The window = the parked begin
/// snapshot → now (the per-frame delta windows telescope to the same
/// span). No-op when nothing is in flight.
pub fn finish() {
    let mut guard = cell().lock().unwrap();
    let Some(live) = guard.take() else {
        return;
    };
    let now = snapshot();
    let begin_wall = *BEGIN_INSTANT.get_or_init(|| Mutex::new(None)).lock().unwrap();
    let begin_disk = *BEGIN_DISK.get_or_init(|| Mutex::new(None)).lock().unwrap();
    let wall_s = begin_wall
        .map(|b| now.wall.duration_since(b).as_secs_f64())
        .unwrap_or_else(|| now.wall.duration_since(live.prev.wall).as_secs_f64());
    let read_total = match (begin_disk, now.disk) {
        (Some((pr, _)), Some((nr, _))) => Some(nr.saturating_sub(pr)),
        _ => None,
    };
    let write_total = match (begin_disk, now.disk) {
        (Some((_, pw)), Some((_, nw))) => Some(nw.saturating_sub(pw)),
        _ => None,
    };
    let totals = LiveTotals {
        frames_total: live.total_frames,
        frames_done: live.obs_ms.len(),
        wall_s,
        read_total,
        read_mean_mbs: read_total.and_then(|t| (wall_s > 0.0).then(|| t as f64 / wall_s / 1_048_576.0)),
        read_peak_mbs: (live.peak_read_mbs > 0.0).then_some(live.peak_read_mbs),
        write_total,
        write_mean_mbs: write_total.and_then(|t| (wall_s > 0.0).then(|| t as f64 / wall_s / 1_048_576.0)),
        cpu_mean_pct: (!live.cpu_pcts.is_empty()).then(|| {
            live.cpu_pcts.iter().sum::<f64>() / live.cpu_pcts.len() as f64
        }),
        fps: if wall_s > 0.0 {
            live.obs_ms.len() as f64 / wall_s
        } else {
            0.0
        },
    };
    *last_cell().lock().unwrap() = Some(totals);
    *guard = None;
}

static LAST: OnceLock<Mutex<Option<LiveTotals>>> = OnceLock::new();

fn last_cell() -> &'static Mutex<Option<LiveTotals>> {
    LAST.get_or_init(|| Mutex::new(None))
}

/// The most recent finished run's totals (the report's `## live` input).
/// None = no live run finished in this process (the jxl tier — the
/// report renders the named non-scope line).
pub fn last() -> Option<LiveTotals> {
    last_cell().lock().unwrap().clone()
}

fn fmt_mbs(v: Option<f64>) -> String {
    v.map_or_else(|| "n/a".into(), |x| format!("{x:.2}"))
}

fn fmt_pct(v: Option<f64>) -> String {
    v.map_or_else(|| "n/a".into(), |x| format!("{x:.1}"))
}

/// The ETA / wall display form `m:ss` (n/a = the named fallback).
pub fn fmt_mss(ms: Option<f64>) -> String {
    match ms {
        None => "n/a".into(),
        Some(ms) => {
            let total_s = (ms / 1000.0).round() as u64;
            format!("{}:{:02}", total_s / 60, total_s % 60)
        }
    }
}

fn sorted_copy(v: &[f64]) -> Vec<f64> {
    let mut s: Vec<f64> = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    s
}

// The begin-window anchors (parked by `begin`, consumed by `finish`):
// the final totals are the begin→finish deltas (the per-frame windows
// telescope to the same span; the begin snapshot is NOT kept in
// `Live.prev` — that advances per frame).
static BEGIN_INSTANT: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
static BEGIN_DISK: OnceLock<Mutex<Option<(u64, u64)>>> = OnceLock::new();

#[cfg(test)]
mod tests {
    use super::*;

    /// The FFI is live on this machine (macOS): a busy loop moves the
    /// cpu time forward (the user+system sum is real — the probe's 58 ms
    /// delta class). The black_box keeps the release build from
    /// collapsing the loop (an affine recurrence would otherwise be a
    /// closed form — the delta would be ~0, the measurement fake).
    #[test]
    fn cpu_time_advances_under_load() {
        let a = ffi::cpu_time_us().expect("the CPU FFI must be available on this machine");
        let mut x = 0u64;
        for i in 0..100_000_000u64 {
            x = std::hint::black_box(x).wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(i);
        }
        let b = ffi::cpu_time_us().expect("the CPU FFI must be available on this machine");
        std::hint::black_box(x);
        assert!(
            b >= a,
            "the cpu time is monotonic: a={a} b={b} (x={x})"
        );
        // A ~100 ms+ burn must show in µs (the absolutetime ticks → µs
        // conversion via the mach timebase is correct).
        assert!(b.saturating_sub(a) > 50_000, "delta={:?} µs (x={x})", b.saturating_sub(a));
    }

    /// The disk I/O FFI is live: the read/write counters are available
    /// (the values may be 0 on a cache-warm machine — the backing-store
    /// semantics; the counters exist + advance on real I/O).
    #[test]
    fn diskio_counters_are_available() {
        let (r, w) = ffi::diskio().expect("the disk I/O FFI must be available on this machine");
        let _ = (r, w);
    }

    /// `fmt_mss` display + the n/a rule.
    #[test]
    fn fmt_mss_shape() {
        assert_eq!(fmt_mss(None), "n/a");
        assert_eq!(fmt_mss(Some(42_000.0)), "0:42");
        assert_eq!(fmt_mss(Some(754_000.0)), "12:34");
        // Rounding: 59.6 s → 1:00.
        assert_eq!(fmt_mss(Some(59_600.0)), "1:00");
    }
}

// =====================================================================
// The platform FFI (zero new crates — std only; macOS primary, Linux
// the named fallback).
// =====================================================================

#[cfg(target_os = "macos")]
mod ffi {
    use std::os::raw::{c_int, c_uint};

    /// The macOS `struct rusage_info_v4` (SDK sys/resource.h — 296 B;
    /// the diskio fields @144/@152; probed on-machine).
    /// `#[repr(C)]` matches the C layout exactly (all u64 after the
    /// 16-byte uuid prefix — 8-aligned, no padding surprises).
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct RusageInfoV4 {
        pub ri_uuid: [u8; 16],
        pub ri_user_time: u64,
        pub ri_system_time: u64,
        pub ri_pkg_idle_wkups: u64,
        pub ri_interrupt_wkups: u64,
        pub ri_pageins: u64,
        pub ri_wired_size: u64,
        pub ri_resident_size: u64,
        pub ri_phys_footprint: u64,
        pub ri_proc_start_abstime: u64,
        pub ri_proc_exit_abstime: u64,
        pub ri_child_user_time: u64,
        pub ri_child_system_time: u64,
        pub ri_child_pkg_idle_wkups: u64,
        pub ri_child_interrupt_wkups: u64,
        pub ri_child_pageins: u64,
        pub ri_child_elapsed_abstime: u64,
        pub ri_diskio_bytesread: u64,
        pub ri_diskio_byteswritten: u64,
        pub ri_cpu_time_qos_default: u64,
        pub ri_cpu_time_qos_maintenance: u64,
        pub ri_cpu_time_qos_background: u64,
        pub ri_cpu_time_qos_utility: u64,
        pub ri_cpu_time_qos_legacy: u64,
        pub ri_cpu_time_qos_user_initiated: u64,
        pub ri_cpu_time_qos_user_interactive: u64,
        pub ri_billed_system_time: u64,
        pub ri_serviced_system_time: u64,
        pub ri_logical_writes: u64,
        pub ri_lifetime_max_phys_footprint: u64,
        pub ri_instructions: u64,
        pub ri_cycles: u64,
        pub ri_billed_energy: u64,
        pub ri_serviced_energy: u64,
        pub ri_interval_max_phys_footprint: u64,
        pub ri_runnable_time: u64,
    }

    const RUSAGE_INFO_V4: c_int = 4;

    /// `struct task_absolutetime_info` (SDK mach/task_info.h — 32 B,
    /// four u64s; TASK_ABSOLUTETIME_INFO=1, COUNT=8; probed on-machine:
    /// the live process-wide total_user + total_system in mach
    /// absolute-time ticks).
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct TaskAbsolutetimeInfo {
        pub total_user: u64,
        pub total_system: u64,
        pub threads_user: u64,
        pub threads_system: u64,
    }

    /// `mach_timebase_info_data_t` (SDK mach/mach_time.h — { u32
    /// numer, u32 denom }; ticks → ns = ticks * numer / denom; probed
    /// on-machine: 125/3 on this host).
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct MachTimebaseInfo {
        pub numer: u32,
        pub denom: u32,
    }

    const TASK_ABSOLUTETIME_INFO: c_int = 1;
    const TASK_ABSOLUTETIME_INFO_COUNT: u32 = 8; // 32 B / 4

    extern "C" {
        // libproc.h: `int proc_pid_rusage(int pid, int flavor, rusage_info_t *buffer)`
        // (rusage_info_t = void *; the buffer is the struct's address).
        fn proc_pid_rusage(pid: i32, flavor: c_int, buffer: *mut c_uint) -> c_int;
        // mach/task_info.h: `kern_return_t task_info(task_name_t target_task, task_flavor_t flavor, task_info_t info, mach_msg_type_number_t *info_cnt)`
        // (task_info_t = natural_t* = u32*; the info struct is cast to it).
        fn task_info(target_task: u32, flavor: c_int, info: *mut c_uint, info_cnt: *mut u32) -> c_int;
        // mach/mach_time.h: `kern_return_t mach_timebase_info(mach_timebase_info_t timebase_info)`
        fn mach_timebase_info(tp: *mut MachTimebaseInfo) -> c_int;
        // mach/mach_init.h: `#define mach_task_self() mach_task_self_` — the
        // process's TASK PORT is an EXTERN VARIABLE (an `S` data symbol in
        // libsystem_kernel — NOT a function; treating it as one SIGBUSes —
        // probed on-machine). A real port name (the literal 0 fails
        // task_info with KERN_INVALID_ADDRESS — the 0-constant form is the
        // legacy shape). Read volatile (the kernel writes it at process
        // bring-up; the value is stable thereafter).
        static mach_task_self_: u32;
    }

    /// The process's (ri_diskio_bytesread, ri_diskio_byteswritten) —
    /// None = the named n/a (the FFI failed; never a silent 0).
    pub fn diskio() -> Option<(u64, u64)> {
        let mut ru: RusageInfoV4 = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            proc_pid_rusage(
                std::process::id() as i32,
                RUSAGE_INFO_V4,
                &mut ru as *mut RusageInfoV4 as *mut c_uint,
            )
        };
        if rc != 0 {
            return None;
        }
        Some((ru.ri_diskio_bytesread, ru.ri_diskio_byteswritten))
    }

    /// The process's total user+system CPU time (µs) — the cpu%
    /// numerator (multi-core: the total spans the cores, the % can
    /// exceed 100 — that is the load). `task_info(TASK_ABSOLUTETIME_INFO)`
    /// is the LIVE process-wide counter (the other task flavors are
    /// stale / suspend-only on this macOS — the probe evidence is in the
    /// module docs). None = the named n/a (the FFI failed — never a
    /// silent 0).
    pub fn cpu_time_us() -> Option<u64> {
        let mut ti: TaskAbsolutetimeInfo = unsafe { std::mem::zeroed() };
        let mut cnt = TASK_ABSOLUTETIME_INFO_COUNT;
        let kr = unsafe {
            task_info(
                std::ptr::read_volatile(&mach_task_self_),
                TASK_ABSOLUTETIME_INFO,
                &mut ti as *mut TaskAbsolutetimeInfo as *mut c_uint,
                &mut cnt,
            )
        };
        if kr != 0 {
            return None;
        }
        let ticks = ti.total_user.saturating_add(ti.total_system);
        let mut tb: MachTimebaseInfo = unsafe { std::mem::zeroed() };
        if unsafe { mach_timebase_info(&mut tb) } != 0 || tb.denom == 0 {
            return None;
        }
        // ticks → µs: ticks * numer / (denom * 1000) — the u128 form
        // keeps the division exact (no float rounding in the numerator).
        let us = (ticks as u128 * tb.numer as u128) / (tb.denom as u128 * 1000);
        Some(us as u64)
    }
}

#[cfg(target_os = "linux")]
mod ffi {
    use std::os::raw::c_int;

    const CLOCK_PROCESS_CPUTIME_ID: c_int = 3;

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }

    extern "C" {
        fn clock_gettime(clockid: c_int, tp: *mut Timespec) -> c_int;
    }

    /// The Linux disk I/O metric is the named `n/a` (the block-granular
    /// `ru_inblock×512` variant is the named follow-up — not measured,
    /// never a silent 0).
    pub fn diskio() -> Option<(u64, u64)> {
        None
    }

    /// The process CPU time (user+system, CLOCK_PROCESS_CPUTIME_ID) —
    /// the Linux CPU path. None = the named n/a.
    pub fn cpu_time_us() -> Option<u64> {
        let mut ts: Timespec = unsafe { std::mem::zeroed() };
        if unsafe { clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut ts) } != 0 {
            return None;
        }
        Some(ts.tv_sec.max(0) as u64 * 1_000_000 + ts.tv_nsec.max(0) as u64 / 1_000)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod ffi {
    /// Unsupported platform: both metrics the named `n/a` (never a
    /// silent 0).
    pub fn diskio() -> Option<(u64, u64)> {
        None
    }
    pub fn cpu_time_us() -> Option<u64> {
        None
    }
}
