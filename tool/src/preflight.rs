//! Pre-flight space + ETA guard (the 260 MB-free
//! mid-run incident's named refusal class).
//!
//! Gate position: BEFORE the first frame/byte of output (the
//! ingest-gate refusal pattern — a refusal writes nothing: the guard
//! runs in the CLI before the encoder's `process_dir`, so not even the
//! ingest manifest leaks into a refused output dir). It runs on the
//! legacy encode (BOTH codecs); bake is NOT gated (its inputs
//! are already-archived bytes — the size is known exactly and the
//! bake disk gate covers it).
//!
//! The estimate is CONSERVATIVE (a LOWER bound on expected output —
//! the measured corpus is 1.88–2.66:1): `est = input_bytes / bound ×
//! margin` with `bound` = 2.0 (j92) / 2.2 (jxl) and `margin` = 1.25
//! default. The ONLY override is the `FRAMEPRISM_PREFLIGHT_MULT` env
//! (float — a test sets it to 1e6 to force the refusal without filling
//! a disk; a parse failure is the NAMED refusal, not a default). There
//! is NO env for bypassing the check itself.
//!
//! The free-space probe REUSES the df-based mechanism of the jxl disk
//! gate (`crate::jxl::free_bytes` — the PAM pre-write gate): no
//! second free-space measurement is invented.
//!
//! The ETA is printed at start (the total, stderr) and per clip / in
//! the run report (the `report.rs` surface): measured corpus
//! rates — j92 ~405 ms/frame @14 jobs, jxl e7 ~306 ms/frame @14 jobs
//! (the a001-001 numbers; the jxl rate is at the `--jxl-parallel`
//! default) — and the label `measured corpus rate, not a guarantee`
//! is the contract.

use std::path::{Path, PathBuf};

/// Measured corpus rates (the a001-001 numbers, @14 jobs) — the ETA
/// estimate inputs, never a guarantee (the label is the contract).
pub const J92_MS_PER_FRAME: f64 = 405.0;
pub const JXL_MS_PER_FRAME: f64 = 306.0;
/// The conservative ratio LOWER bounds (the measured corpus is
/// 1.88–2.66:1): est = input / bound × margin.
pub const J92_RATIO_BOUND: f64 = 2.0;
pub const JXL_RATIO_BOUND: f64 = 2.2;
/// The default margin (the estimate is a lower bound; the margin
/// buys the incident).
pub const DEFAULT_MARGIN: f64 = 1.25;
/// The ONLY env (the margin override; a test sets 1e6 to force the
/// refusal without filling a disk). A parse failure is the named
/// refusal, not a default.
pub const MARGIN_ENV: &str = "FRAMEPRISM_PREFLIGHT_MULT";

pub fn ms_per_frame(codec: &str) -> f64 {
    if codec.eq_ignore_ascii_case("jxl") {
        JXL_MS_PER_FRAME
    } else {
        J92_MS_PER_FRAME
    }
}

pub fn ratio_bound(codec: &str) -> f64 {
    if codec.eq_ignore_ascii_case("jxl") {
        JXL_RATIO_BOUND
    } else {
        J92_RATIO_BOUND
    }
}

/// The margin: `FRAMEPRISM_PREFLIGHT_MULT` (float) or the 1.25 default.
/// `Err(s)` = the env value as given (the caller turns it into the
/// named refusal — a parse failure is NOT a default).
pub fn margin() -> Result<f64, String> {
    match std::env::var(MARGIN_ENV).ok() {
        None => Ok(DEFAULT_MARGIN),
        Some(s) => s
            .trim()
            .parse::<f64>()
            .map_err(|_| format!("{MARGIN_ENV}={s:?}"))
            .and_then(|v| {
                if v.is_finite() && v > 0.0 {
                    Ok(v)
                } else {
                    Err(format!("{MARGIN_ENV}={s:?}"))
                }
            }),
    }
}

/// The estimated output bytes (the conservative lower bound × margin).
pub fn estimate(codec: &str, input_bytes: u64, mult: f64) -> u64 {
    ((input_bytes as f64 / ratio_bound(codec)) * mult).ceil() as u64
}

/// The ETA minutes at the measured corpus rate.
pub fn eta_minutes(codec: &str, frames: usize) -> f64 {
    frames as f64 * ms_per_frame(codec) / 60_000.0
}

/// The ETA body (the reports' format — the per-clip + run
/// lines prefix `eta: `). The label `measured corpus rate, not a
/// guarantee` is the contract — it MUST be carried.
pub fn eta_report_line(codec: &str, frames: usize) -> String {
    format!(
        "~ {:.1} min for {} frame(s) at {:.0} ms/frame (measured corpus rate, not a guarantee)",
        eta_minutes(codec, frames),
        frames,
        ms_per_frame(codec)
    )
}

/// The ETA line (stderr, at start — the guard prints it).
pub fn eta_line(codec: &str, frames: usize) -> String {
    format!("ETA {}", eta_report_line(codec, frames))
}

/// The combined (both) ETA line: ONE line carrying the
/// combined total + the per-tier breakdown + the existing contract
/// label. Both rates are measured corpus numbers (j92 405 ms/frame;
/// jxl e7 306 ms/frame at the `--jxl-parallel` default — the a001-001
/// numbers), so no "unmeasured" naming is needed (do NOT invent
/// a rate — there is none to invent here).
pub fn eta_both_line(frames: usize) -> String {
    let total_min = frames as f64 * (J92_MS_PER_FRAME + JXL_MS_PER_FRAME) / 60_000.0;
    format!(
        "ETA ~ {:.1} min for {} frame(s), both tiers (j92 ~ {:.1} min @ {:.0} ms/frame + jxl ~ {:.1} min @ {:.0} ms/frame; measured corpus rate, not a guarantee)",
        total_min,
        frames,
        eta_minutes("j92", frames),
        J92_MS_PER_FRAME,
        eta_minutes("jxl", frames),
        JXL_MS_PER_FRAME,
    )
}

/// The `-jxl` sibling of a path: the literal `-jxl` suffix
/// on the path's final component, a trailing slash normalized first.
/// The both-dispatch naming core (the jxl tier's output root =
/// `jxl_sibling(output)`; the `--to` dest + `--report` siblings share
/// the rule). Co-located with the combined guard (the both
/// machinery's module) so the lib-level suite gates the rule (the
/// owned files are main.rs + preflight.rs; the suite pin is
/// `--lib`-only, so a main.rs helper would be untestable).
pub fn jxl_sibling(path: &Path) -> PathBuf {
    let lossy = path.to_string_lossy();
    let s = lossy.trim_end_matches('/');
    PathBuf::from(format!("{s}-jxl"))
}

/// The margin parse-failure refusal (the shared named shape — a
/// parse failure is the NAMED refusal, not a default). `s` is the env
/// value as given (`FRAMEPRISM_PREFLIGHT_MULT=<value>`). Extracted pure
/// so both `guard` and `guard_both` share the EXACT line, and the
/// lib-level suite can test the shape without a process-global env
/// window.
pub fn margin_parse_refusal(s: &str) -> Refusal {
    Refusal {
        class: "REFUSED_SPACE",
        line: format!(
            "FAIL preflight-space: {s} is not a positive float — refusing (the margin has no default; unset {MARGIN_ENV} or set a valid multiplier)"
        ),
    }
}

/// `(frame count, total source bytes)` over the input root (the A2
/// estimate inputs — the source .DNGs). The SAME walk discipline as
/// the worker's collection: symlinked entries are SKIPPED (the worker
/// refuses to encode them — counting them would over-estimate) and
/// every descended-into dir is tracked by (dev, ino) (a symlink cycle
/// cannot recurse unboundedly).
#[cfg(unix)]
pub fn scan_source(input: &Path) -> std::io::Result<(usize, u64)> {
    let mut visited = std::collections::HashSet::new();
    let mut frames = 0usize;
    let mut bytes = 0u64;
    scan_rec(input, &mut visited, &mut frames, &mut bytes)?;
    Ok((frames, bytes))
}

#[cfg(unix)]
fn scan_rec(
    dir: &Path,
    visited: &mut std::collections::HashSet<(u64, u64)>,
    frames: &mut usize,
    bytes: &mut u64,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(dir)?;
    if !visited.insert((meta.dev(), meta.ino())) {
        return Ok(()); // already visited — a symlink cycle (or hard-link fan-in): do not recurse again.
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue; // the worker's collect skips symlinked entries
        }
        // (the named bounded-discretion extension — the preflight
        // source scan is the source-tree half of the worker's `collect`
        // boundary: a `._*.DNG` shadow would otherwise be counted as a
        // frame — the inflated ETA + estimate on a shadowed source,
        // the same class, the same one-line skip.
        if entry.file_name().to_str().is_some_and(crate::is_apple_double) {
            continue;
        }
        if p.is_dir() {
            scan_rec(&p, visited, frames, bytes)?;
        } else if p.is_file() {
            let is_dng = p
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("dng"))
                .unwrap_or(false);
            if is_dng {
                *frames += 1;
                *bytes += std::fs::metadata(&p)?.len();
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn scan_source(_input: &Path) -> std::io::Result<(usize, u64)> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the preflight source scan is unix-only (the (dev, ino) cycle guard)",
    ))
}

/// The named refusal (the exact line shape). `class` is
/// the ledger verdict class (`REFUSED_<class>`).
#[derive(Clone, Debug)]
pub struct Refusal {
    pub class: &'static str,
    pub line: String,
}

/// The probe target for the free-space measurement: the guard runs
/// BEFORE the output dir exists (the gate position — a refusal writes
/// 0 files), so `df` is pointed at the NEAREST EXISTING ANCESTOR —
/// the volume the output will be created on. `pub`: the
/// dry-run fit-check reuses this exact probe (no second volume
/// resolver).
pub fn probe_target(output: &Path) -> PathBuf {
    let mut p = output.to_path_buf();
    loop {
        if p.exists() {
            return p;
        }
        match p.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => p = parent.to_path_buf(),
            _ => return PathBuf::from("/"),
        }
    }
}

/// The xattr-less volume family (the note set: the
/// AppleDouble trigger). ntfs / HFS / HFS+ / APFS / anything else →
/// NO note.
pub const XATTR_LESS_FSTYPES: &[&str] = &["exfat", "msdos", "vfat"];

/// Whether the volume's fstypename is in the note set (the
/// note is emitted ONLY for the xattr-less family).
pub fn is_xattr_less_volume(fstype: &str) -> bool {
    XATTR_LESS_FSTYPES.contains(&fstype)
}

/// The exact exFAT destination note line (byte-stable; the
/// fixtures assert it verbatim). Emitted on STDOUT during preflight
/// (before the first write) AND pinned in the run report (encode) /
/// the estimate report (dry-run). `dest` is the resolved output path
/// as the user passed it (the display form). The line is INFORMATION
/// — it names the operator's removal command, it NEVER auto-deletes
/// shadows.
pub fn apple_double_note(fstype: &str, dest: &Path) -> String {
    format!(
        "note: destination volume {fstype} — no xattr support; macOS creates `._*` AppleDouble shadow twins, which frameprism discovery skips (safe to remove: find {} -name '._*' -delete)",
        dest.display()
    )
}

/// The destination-volume fs-type probe (the exFAT note's
/// detection): the volume's fstypename (`Some("exfat")` /
/// `Some("apfs")` / ...). macOS (primary): the raw BSD `statfs` (the
/// live.rs precedent — raw FFI + std only, ZERO new dependencies: no
/// libc crate). Linux: the best-effort `/proc/self/mountinfo` (the
/// field after the `-` separator is the fs type; the longest prefix
/// mount covering the path wins). Unparseable → `None`. A probe
/// failure returns `None` — the note is ADVISORY and a probe failure
/// must never fail a run (the probe tolerates unreadable targets, per
/// `probe_target`'s contract).
pub fn volume_fstype(path: &Path) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        volume_fstype_macos(path)
    }
    #[cfg(target_os = "linux")]
    {
        volume_fstype_linux(path)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = path;
        None // the named non-target (the gates run on macOS)
    }
}

/// The raw BSD `statfs` (the live.rs precedent: raw FFI +
/// std only, ZERO new dependencies — no libc crate). The hand-written
/// struct matches the SDK's `sys/mount.h` EXACTLY — the 64-bit
/// `__DARWIN_STRUCT_STATFS64` variant (the `struct statfs` alias under
/// `__DARWIN_64_BIT_INO_T` — arm64/x86_64), THROUGH the final
/// `f_reserved[7]` (the struct end — the C call writes the full size,
/// 2168 B; a shorter struct overflows). Note the 64-bit variant's
/// order: `f_fstypename` → `f_mntonname` → `f_mntfromname` (NOT the
/// legacy variant's order) — a field-order slip reads the mount point
/// as the fstypename (caught in the G3
/// vector).
#[cfg(target_os = "macos")]
mod statfs_ffi {
    use std::os::raw::c_char;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct statfs {
        pub f_bsize: u32,
        pub f_iosize: i32,
        pub f_blocks: u64,
        pub f_bfree: u64,
        pub f_bavail: i64,
        pub f_files: u64,
        pub f_ffree: u64,
        /// `fsid_t` — `struct { int32_t val[2]; }` (8 B).
        pub f_fsid: [i32; 2],
        /// `uid_t`.
        pub f_owner: u32,
        pub f_type: u32,
        pub f_flags: u32,
        pub f_fssubtype: u32,
        /// `MFSTYPENAMELEN` (16, NUL-terminated).
        pub f_fstypename: [c_char; 16],
        /// `MAXPATHLEN` (1024).
        pub f_mntonname: [c_char; 1024],
        /// `MAXPATHLEN` (1024).
        pub f_mntfromname: [c_char; 1024],
        pub f_flags_ext: u32,
        pub f_reserved: [u32; 7],
    }

    extern "C" {
        pub fn statfs(path: *const c_char, buf: *mut statfs) -> i32;
    }
}

#[cfg(target_os = "macos")]
fn volume_fstype_macos(path: &Path) -> Option<String> {
    use std::ffi::{CStr, CString};
    let cpath = CString::new(path.to_string_lossy().into_owned()).ok()?;
    let mut buf: statfs_ffi::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { statfs_ffi::statfs(cpath.as_ptr(), &mut buf) };
    if rc != 0 {
        return None; // the advisory probe never fails a run
    }
    let fstype = unsafe { CStr::from_ptr(buf.f_fstypename.as_ptr()) };
    Some(fstype.to_string_lossy().into_owned())
}

#[cfg(target_os = "linux")]
fn volume_fstype_linux(path: &Path) -> Option<String> {
    // /proc/self/mountinfo: <mount_id> <parent> <maj:min> <root>
    // <mount_point> <options> ... - <fstype> <source> <super_options>
    // (the named fallback — best-effort, unparseable = None).
    let text = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut best: Option<(usize, &str)> = None; // (mount_point len, fstype)
    for line in text.lines() {
        let Some(dash) = line.rfind(" - ") else {
            continue;
        };
        let before = &line[..dash];
        let after = &line[dash + 3..];
        let fstype = after.split(' ').next()?;
        if fstype.is_empty() {
            continue;
        }
        let mount_point = before.split(' ').nth(4)?;
        if mount_point.is_empty() {
            continue;
        }
        if path == mount_point || path.starts_with(mount_point) {
            let len = mount_point.len();
            if best.map(|(l, _)| len > l).unwrap_or(true) {
                best = Some((len, fstype));
            }
        }
    }
    best.map(|(_, fstype)| fstype.to_string())
}

/// The guard with an explicit margin (the testable core — the public
/// `guard` parses the env and delegates). `frames` feeds the ETA line.
pub fn guard_with_mult(
    codec: &str,
    frames: usize,
    input_bytes: u64,
    output: &Path,
    mult: f64,
) -> Result<(), Refusal> {
    let bound = ratio_bound(codec);
    let est = estimate(codec, input_bytes, mult);
    let free = crate::jxl::free_bytes(&probe_target(output))
        .map_err(|err| Refusal {
            class: "REFUSED_SPACE",
            line: format!(
                "FAIL preflight-space: the free-space probe (df) failed: {err:#} — refusing (no measurement, no run)"
            ),
        })?;
    if free < est {
        return Err(Refusal {
            class: "REFUSED_SPACE",
            line: format!(
                "FAIL preflight-space: output volume free {free} B, estimated need {est} (input {input_bytes} B, ratio bound 1/{bound}, margin {mult})"
            ),
        });
    }
    eprintln!(
        "PASS preflight-space: output volume free {free} B >= estimated need {est} (input {input_bytes} B, ratio bound 1/{bound}, margin {mult})"
    );
    eprintln!("{}", eta_line(codec, frames));
    //: the exFAT destination note — the
    // NAMED information line: name the state,
    // never fail silent): the destination volume is in the xattr-less
    // family (the AppleDouble trigger) → emit on STDOUT before the
    // first write (the guard's gate position — the note rides only a
    // run that PASSES the guard and will actually write; a refused
    // run never reaches this line). Never auto-delete shadows.
    // Advisory: the probe's `None` (unreadable volume / parse
    // failure) = no note, never a run failure.
    if let Some(fstype) = volume_fstype(&probe_target(output)) {
        if is_xattr_less_volume(&fstype) {
            println!("{}", apple_double_note(&fstype, output));
        }
    }
    Ok(())
}

/// The guard (the CLI entry — parses `FRAMEPRISM_PREFLIGHT_MULT`; a parse
/// failure is the named refusal, not a default).
pub fn guard(codec: &str, frames: usize, input_bytes: u64, output: &Path) -> Result<(), Refusal> {
    let mult = match margin() {
        Ok(m) => m,
        Err(s) => return Err(margin_parse_refusal(&s)),
    };
    guard_with_mult(codec, frames, input_bytes, output, mult)
}

/// The combined (both) guard with an explicit margin (the
/// testable core): ONE reservation = the SUM of the per-tier estimates
/// (each tier's own ratio bound, the SAME margin). A j92-only
/// reservation would approve a run that fills the disk 3/4 through the
/// jxl tier. The probe target is unchanged (OUT and OUT-jxl are
/// siblings = the same volume — the nearest existing ancestor).
pub fn guard_both_with_mult(
    frames: usize,
    input_bytes: u64,
    output: &Path,
    mult: f64,
) -> Result<(), Refusal> {
    let est_j92 = estimate("j92", input_bytes, mult);
    let est_jxl = estimate("jxl", input_bytes, mult);
    let est = est_j92.saturating_add(est_jxl);
    let free = crate::jxl::free_bytes(&probe_target(output))
        .map_err(|err| Refusal {
            class: "REFUSED_SPACE",
            line: format!(
                "FAIL preflight-space: the free-space probe (df) failed: {err:#} — refusing (no measurement, no run)"
            ),
        })?;
    if free < est {
        return Err(Refusal {
            class: "REFUSED_SPACE",
            line: format!(
                "FAIL preflight-space: output volume free {free} B, estimated combined need {est} (j92 {est_j92} B @ 1/{J92_RATIO_BOUND} + jxl {est_jxl} B @ 1/{JXL_RATIO_BOUND}; input {input_bytes} B, margin {mult})"
            ),
        });
    }
    eprintln!(
        "PASS preflight-space: output volume free {free} B >= estimated combined need {est} (j92 {est_j92} B @ 1/{J92_RATIO_BOUND} + jxl {est_jxl} B @ 1/{JXL_RATIO_BOUND}; input {input_bytes} B, margin {mult})"
    );
    eprintln!("{}", eta_both_line(frames));
    //: the exFAT destination note — the both-tier guard emits
    // it ONCE for the shared volume (OUT and OUT-jxl are siblings —
    // the probe target is the same; see the single-codec `guard`'s
    // note, above).
    if let Some(fstype) = volume_fstype(&probe_target(output)) {
        if is_xattr_less_volume(&fstype) {
            println!("{}", apple_double_note(&fstype, output));
        }
    }
    Ok(())
}

/// The combined (both) guard (the CLI entry — the margin env parse
/// shares the single-codec `guard`'s exact refusal shape).
pub fn guard_both(
    frames: usize,
    input_bytes: u64,
    output: &Path,
) -> Result<(), Refusal> {
    let mult = match margin() {
        Ok(m) => m,
        Err(s) => return Err(margin_parse_refusal(&s)),
    };
    guard_both_with_mult(frames, input_bytes, output, mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_is_the_lower_bound_times_margin() {
        // 2.0 / 2.2 / 1.25 — the pinned numbers.
        assert_eq!(estimate("j92", 4_000_000, 1.25), 2_500_000);
        assert_eq!(estimate("jxl", 4_400_000, 1.25), 2_500_000);
        // A test-sized margin (the 1e6 shape) always dominates.
        assert!(estimate("j92", 100, 1_000_000.0) > 100);
        // Conservative = a LOWER bound on expected output: the j92
        // bound (1/2.0) is the LARGER estimate of the two (a smaller
        // denominator = a worse, more conservative bound).
        assert!(estimate("j92", 10_000, 1.0) > estimate("jxl", 10_000, 1.0));
        // j92: 10_000/2.0 = 5_000; jxl: 10_000/2.2 ≈ 4_545 — the strict
        // inequality holds.
    }

    #[test]
    fn eta_line_carries_the_contract_label() {
        let line = eta_line("j92", 3);
        assert!(
            line.contains("measured corpus rate, not a guarantee"),
            "{line:?}"
        );
        assert!(line.starts_with("ETA ~ "), "{line:?}");
        // 3 frames @ 405 ms = 1.215 s → 0.0 min (the run prints the
        // line even when the total is under a minute).
        assert!(line.starts_with("ETA ~ 0.0 min"), "{line:?}");
        // 1000 frames @ 405 ms = 6.75 min.
        let line = eta_line("j92", 1000);
        assert!(line.starts_with("ETA ~ 6.8 min"), "{line:?}");
        // The jxl rate is the a001-001 e7 number (306 ms/frame).
        let line = eta_line("jxl", 1000);
        assert!(line.contains("306 ms/frame"), "{line:?}");
    }

    #[test]
    fn scan_source_counts_only_the_worker_frames() {
        let tmp = std::env::temp_dir().join("frameprism_preflight_scan_test");
        let _ = std::fs::remove_dir_all(&tmp);
        let clip = tmp.join("A001_001");
        std::fs::create_dir_all(&clip).unwrap();
        std::fs::write(clip.join("A001_001_0001.DNG"), [0u8; 100]).unwrap();
        std::fs::write(clip.join("A001_001_0002.dng"), [0u8; 50]).unwrap();
        std::fs::write(clip.join("A001_001.jxl-checksums.tsv"), "sidecar").unwrap();
        // A symlinked dir + a symlinked file: the worker's collect
        // skips both — the scan must too (no double count, no escape).
        std::os::unix::fs::symlink(&clip, tmp.join("link-dir")).unwrap();
        std::os::unix::fs::symlink(
            clip.join("A001_001_0001.DNG"),
            tmp.join("link.DNG"),
        )
        .unwrap();
        let (frames, bytes) = scan_source(&tmp).unwrap();
        assert_eq!(frames, 2, "the symlinked copies are not worker frames");
        assert_eq!(bytes, 150);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn probe_target_is_the_nearest_existing_ancestor() {
        // The guard runs before the output dir exists: the probe
        // target is the nearest existing ancestor (the volume the
        // output will be created on).
        let tmp = std::env::temp_dir();
        let nested = tmp.join("frameprism-never-created-a").join("b").join("out");
        assert!(!nested.exists());
        // /tmp exists (on this host) — the walk must stop no higher
        // than an existing dir and never panic.
        let target = probe_target(&nested);
        assert!(target.exists(), "{target:?}");
        assert_eq!(target, std::env::temp_dir());
        // An existing dir is its own target (no unnecessary walk).
        assert_eq!(probe_target(&tmp), tmp);
    }

    #[test]
    fn guard_refuses_named_when_space_is_short() {
        // A 1e15 margin: est = input/2.0 × 1e15 = 500 PB — far above
        // ANY real free space, so the refusal is deterministic without
        // filling a disk (volume-independent).
        let tmp = std::env::temp_dir();
        let err = guard_with_mult("j92", 3, 1_000, &tmp, 1e15)
            .expect_err("a 1e15 margin must refuse on any real volume");
        assert_eq!(err.class, "REFUSED_SPACE");
        // The exact line shape + BOTH numbers.
        assert!(
            err.line.starts_with("FAIL preflight-space: output volume free "),
            "{err:?}"
        );
        assert!(err.line.contains(", estimated need "), "{err:?}");
        assert!(err.line.contains("input 1000 B"), "{err:?}");
        assert!(err.line.contains("ratio bound 1/2"), "{err:?}");
    }

    #[test]
    fn guard_passes_when_space_is_enough() {
        let tmp = std::env::temp_dir();
        // mult 1.0, 1 byte input → est < 1 B (ceil(0.5) = 1) — never
        // above a real free space.
        assert!(
            guard_with_mult("j92", 1, 1, &tmp, 1.0).is_ok(),
            "a 1-byte estimate must pass on any healthy volume"
        );
    }

    /// The env parse failure is the named refusal (not a
    /// default). Sets/removes `FRAMEPRISM_PREFLIGHT_MULT` around the
    /// call (no other test in the suite reads that env — the volume-
    /// dependent guards use `guard_with_mult` directly, so this test's
    /// env window can never misdirect another test).
    #[test]
    fn guard_env_parse_failure_refuses_named() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        std::env::set_var(MARGIN_ENV, "not-a-float");
        let err = guard("j92", 1, 100, &std::env::temp_dir())
            .expect_err("a malformed margin env must refuse");
        std::env::remove_var(MARGIN_ENV);
        assert_eq!(err.class, "REFUSED_SPACE");
        assert!(err.line.contains("FRAMEPRISM_PREFLIGHT_MULT"), "{err:?}");
        assert!(err.line.starts_with("FAIL preflight-space: "), "{err:?}");
        // A valid env value is honored (the margin reaches the line;
        // 1e15 → 50 PB estimate → the refusal is volume-independent).
        // Rust's f64 Display prints 1e15 as 1000000000000000.
        std::env::set_var(MARGIN_ENV, "1e15");
        let err = guard("j92", 1, 100, &std::env::temp_dir())
            .expect_err("a huge valid margin must refuse");
        std::env::remove_var(MARGIN_ENV);
        assert!(err.line.contains("margin 1000000000000000"), "{err:?}");
    }

    // ---- additive tests ----

    #[test]
    fn jxl_sibling_is_the_literal_suffix_with_trailing_slash_normalized() {
        assert_eq!(jxl_sibling(Path::new("/tmp/x/out")), PathBuf::from("/tmp/x/out-jxl"));
        assert_eq!(jxl_sibling(Path::new("/tmp/x/out/")), PathBuf::from("/tmp/x/out-jxl"));
        assert_eq!(jxl_sibling(Path::new("out")), PathBuf::from("out-jxl"));
        // The rule applies to any component (dest / report paths
        // share it).
        assert_eq!(jxl_sibling(Path::new("/d/off")), PathBuf::from("/d/off-jxl"));
        assert_eq!(
            jxl_sibling(Path::new("/r/report.tsv")),
            PathBuf::from("/r/report.tsv-jxl")
        );
    }

    #[test]
    fn guard_both_reservation_is_the_sum_of_the_tier_estimates() {
        // 4_400_000 B input, mult 1.25: j92 = 4_400_000/2.0×1.25 =
        // 2_750_000; jxl = 4_400_000/2.2×1.25 = 2_500_000; combined
        // 5_250_000 — the exact arithmetic (each tier's own ratio
        // bound, the same margin).
        let e92 = estimate("j92", 4_400_000, 1.25);
        let exl = estimate("jxl", 4_400_000, 1.25);
        assert_eq!(e92, 2_750_000);
        assert_eq!(exl, 2_500_000);
        assert_eq!(e92.saturating_add(exl), 5_250_000);
        // A j92-only reservation (2_750_000) is LOOSER than the
        // combined one (5_250_000) — the incident class: a volume
        // with 3.5 GB free passes the j92-only check but must be
        // refused for both.
        assert!(estimate("j92", 4_400_000, 1.25) < e92.saturating_add(exl));
    }

    #[test]
    fn guard_both_refuses_named_with_the_per_tier_breakdown() {
        // A 1e15 margin: est_j92 = 5_000×1e15 = 5e18; est_jxl =
        // (10_000/2.2)×1e15 ≈ 4.55e18; combined ≈ 9.55e18 — all far
        // below u64::MAX (1.84e19, no saturation: the per-tier numbers
        // in the line are exact) and far above ANY real free space,
        // so the refusal is deterministic without filling a disk
        // (volume-independent).
        let input = 10_000u64;
        let tmp = std::env::temp_dir();
        let err = guard_both_with_mult(3, input, &tmp, 1e15)
            .expect_err("a 1e15 margin must refuse on any real volume");
        assert_eq!(err.class, "REFUSED_SPACE");
        // The line shape: the combined need + the per-tier breakdown
        // (the G1e4 evidence — both numbers must be present).
        assert!(
            err.line.starts_with("FAIL preflight-space: output volume free "),
            "{err:?}"
        );
        let e92 = estimate("j92", input, 1e15);
        let exl = estimate("jxl", input, 1e15);
        assert!(e92 < u64::MAX / 2, "the test input must not saturate");
        assert!(
            err.line.contains(&format!("estimated combined need {} ", e92 + exl)),
            "{err:?}"
        );
        assert!(err.line.contains(&format!("j92 {e92} B")), "{err:?}");
        assert!(err.line.contains(&format!("jxl {exl} B")), "{err:?}");
        assert!(err.line.contains("1/2"), "the j92 ratio bound: {err:?}");
        assert!(err.line.contains("1/2.2"), "the jxl ratio bound: {err:?}");
    }

    #[test]
    fn guard_both_passes_when_space_is_enough() {
        let tmp = std::env::temp_dir();
        // mult 1.0, 4_000 B input → combined est = 2_000 + 1_819 =
        // 3_819 B — never above a real free space.
        assert!(
            guard_both_with_mult(1, 4_000, &tmp, 1.0).is_ok(),
            "a tiny combined estimate must pass on any healthy volume"
        );
    }

    #[test]
    fn guard_both_env_parse_failure_refuses_named() {
        // The shared pure helper (ENV-FREE — the suite's one
        // transient flake was an env-window test; no second
        // process-global env window is added): the exact line shape
        // `guard` produces for a malformed margin.
        let r = margin_parse_refusal("FRAMEPRISM_PREFLIGHT_MULT=\"not-a-float\"");
        assert_eq!(r.class, "REFUSED_SPACE");
        assert!(r.line.contains("is not a positive float"), "{r:?}");
        assert!(r.line.contains(MARGIN_ENV), "{r:?}");
        assert!(r.line.starts_with("FAIL preflight-space: "), "{r:?}");
    }

    #[test]
    fn eta_both_line_carries_the_contract_label_and_the_breakdown() {
        let line = eta_both_line(1000);
        assert!(
            line.contains("measured corpus rate, not a guarantee"),
            "{line:?}"
        );
        assert!(line.starts_with("ETA ~ "), "{line:?}");
        assert!(line.contains("1000 frame(s)"), "{line:?}");
        // The per-tier breakdown at the measured corpus rates (the
        // j92 6.75 → "6.8" rounding matches the single-codec
        // `eta_line` test's established behavior).
        assert!(line.contains("j92 ~ 6.8 min @ 405 ms/frame"), "{line:?}");
        assert!(line.contains("jxl ~ 5.1 min @ 306 ms/frame"), "{line:?}");
        // Combined total = the same float arithmetic the function uses
        // (mirrored here — 11.85 is not exact in binary, so the
        // expectation is computed, not hardcoded).
        let total_min = 1000.0_f64 * (J92_MS_PER_FRAME + JXL_MS_PER_FRAME) / 60_000.0;
        assert!(
            line.starts_with(&format!("ETA ~ {:.1} min", total_min)),
            "{line:?}"
        );
    }

    #[test]
    fn probe_target_sibling_outputs_are_the_same_volume() {
        //: OUT and OUT-jxl are siblings — the combined guard
        // probes the volume ONCE (the nearest existing ancestor of
        // OUT), and OUT-jxl resolves to the same one.
        let tmp = std::env::temp_dir();
        let out = tmp.join("frameprism-both-never-created").join("out");
        assert!(!out.exists());
        assert_eq!(probe_target(&out), probe_target(&jxl_sibling(&out)));
        assert_eq!(probe_target(&out), tmp);
    }

    // -------------------------------------------------------------------
    //: the exFAT destination note (the user-notification
 // decision — the named information line; detection = the raw BSD
    // statfs fstypename; the note set = the xattr-less family).
    // -------------------------------------------------------------------

    /// The exact note line (byte-stable — the template, an
    /// independent copy of the bytes; the `find … -name '._*' -delete`
    /// tail included).
    #[test]
    fn apple_double_note_line_is_byte_stable() {
        let line = apple_double_note("exfat", Path::new("/Volumes/remote"));
        assert_eq!(
            line,
            "note: destination volume exfat — no xattr support; macOS creates `._*` AppleDouble shadow twins, which frameprism discovery skips (safe to remove: find /Volumes/remote -name '._*' -delete)"
        );
    }

    /// The note set (the xattr-less family — the AppleDouble trigger).
    /// ntfs / HFS / HFS+ / APFS / anything else → NO note.
    #[test]
    fn xattr_less_note_set_is_the_apple_double_family() {
        assert!(is_xattr_less_volume("exfat"));
        assert!(is_xattr_less_volume("msdos"));
        assert!(is_xattr_less_volume("vfat"));
        assert!(!is_xattr_less_volume("apfs"));
        assert!(!is_xattr_less_volume("hfs"));
        assert!(!is_xattr_less_volume("hfs+"));
        assert!(!is_xattr_less_volume("ntfs"));
        assert!(!is_xattr_less_volume("ufs"));
    }

    /// The APFS half of G3: the suite's tmp volume is NOT in the note
    /// set → the note is ABSENT (the report stays byte-identical to
    /// the pre-note shape — the existing pinned report tests + the
    /// explicit report.rs absence assertion cover the report half).
    /// Volume-type independent (no hard APFS equality — a container's
    /// tmpfs would not break the property being asserted: the note
    /// must not fire on the gate host's tmp volume).
    #[test]
    fn volume_fstype_tmp_volume_carries_no_note() {
        let fstype = volume_fstype(&std::env::temp_dir())
            .expect("the tmp volume must probe on the gate host (the advisory probe never fails a test here: a failure means the host cannot run the gates)");
        assert!(
            !is_xattr_less_volume(&fstype),
            "the tmp volume's fstype {fstype:?} must not be in the note set (the note is ABSENT on APFS)"
        );
    }

    /// G3 — the exFAT hdiutil vector (the G4-space-test precedent):
    /// a ~200 MB EXFAT image, mounted → `volume_fstype(mount)` =
    /// `Some("exfat")` + the note line renders verbatim. The fixture's
    /// Drop = unmount + remove on the happy AND error paths (a panic
    /// unwinds through the Drop — the G4 cleanup discipline).
    #[cfg(target_os = "macos")]
    #[test]
    fn volume_fstype_exfat_hdiutil_vector() {
        use std::process::Command;

        let base = std::env::temp_dir().join(format!("frameprism-spec7-g3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let img = base.join("exfat.dmg");
        let mount = base.join("mnt");
        std::fs::create_dir_all(&mount).unwrap();

        // The fixture guard: unmount + remove on the happy AND error
        // paths (the Drop runs on normal completion AND on the panic
        // unwind — the G4 cleanup discipline).
        struct Fixture {
            base: PathBuf,
            mount: PathBuf,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = Command::new("hdiutil")
                    .args(["detach", "-quiet"])
                    .arg(&self.mount)
                    .status();
                let _ = std::fs::remove_dir_all(&self.base);
            }
        }
        let fixture = Fixture { base: base.clone(), mount: mount.clone() };

        let created = Command::new("hdiutil")
            .args(["create", "-quiet", "-size", "200m", "-fs", "EXFAT", "-volname", "frameprism-g3"])
            .arg("-o")
            .arg(&img)
            .status()
            .expect("hdiutil absent — the G3 gate runs on macOS (the named platform)");
        if !created.success() {
            // The environment refuses exFAT image creation (the
            // macOS TCC restriction — `hdiutil create -fs EXFAT` →
            // "Operation not permitted" while HFS+/MS-DOS images
            // create fine in the same environment).
            // The named graceful skip (the established probe-skip
            // pattern — no #[ignore], no environment-dependent
            // count). The fixture's Drop still cleans up.
            eprintln!("SKIP preflight G3 exFAT hdiutil vector: the environment's hdiutil refuses EXFAT image creation (macOS TCC) — the test skips gracefully (the established corpus-dependent-test pattern)");
            return;
        }
        let attached = Command::new("hdiutil")
            .args(["attach", "-quiet", "-nobrowse", "-mountpoint"])
            .arg(&mount)
            .arg(&img)
            .status()
            .expect("hdiutil attach failed to launch");
        assert!(attached.success(), "hdiutil attach failed");

        // The detection: the BSD statfs f_fstypename of the mounted
        // image.
        let fstype = volume_fstype(&mount)
            .expect("the mounted exFAT volume must probe (the note is advisory for a RUN, but the G3 gate asserts the detection)");
        assert_eq!(fstype, "exfat", "the mounted image's fstypename");

        // The note line renders verbatim (the exact bytes,
        // including the `find … -name '._*' -delete` tail):
        let note = apple_double_note(&fstype, &mount);
        assert_eq!(
            note,
            format!(
                "note: destination volume exfat — no xattr support; macOS creates `._*` AppleDouble shadow twins, which frameprism discovery skips (safe to remove: find {} -name '._*' -delete)",
                mount.display()
            )
        );

        // The fixture is released here (the happy path) — the Drop
        // unmounts + removes; the asserts below are the cleanup proof
        // (the G4 cleanup discipline).
        drop(fixture);
        assert!(!mount.exists(), "the fixture must unmount + remove its mountpoint");
        assert!(!img.exists(), "the fixture must remove the image");
    }
}
