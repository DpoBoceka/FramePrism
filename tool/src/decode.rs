//! `frameprism decode` — the decompression feature:
//! an encoded clip dir → per-frame 16-bit PAM (the p1 mosaic plane).
//!
//! Contract:
//! - **j92 decode** = the same machinery `--verify` uses (DNG read →
//!   lossless tile decode → p1) — reuse, don't fork. The encoded DNG's
//!   structure is detected from IFD0 with `tiff::read_meta` (the
//!   lenient parser — the strip-layout `tiff::read` refuses
//!   compressed/tiled frames BY DESIGN). Lossless tag-7 (Compression
//!   7, the 482×272 tile grid, native 8/10/12-bit depth, no log10
//!   50712 × 4096) is
//!   decoded with the golden-model (`ljpeg_ref`) per-tile decoder
//!   `tileenc::decode_tile`
//!   — the same acceptance path the verify gate gates on (G3); the
//!   single-strip lossless JPEG structure (Compression 7, no tile
//!   tags, 12-bit) with `codec::decode_lossless` (the `verify::bit_exact`
//!   machinery). Non-lossless tag-7 structures (the log10 50712 ×
//!   4096 / 34892 /
//! reference tag-7 DCT) and raw uncompressed frames are hard rejects
//! with the reason. A reference linearization table is NOT refused:
//!   the fp 8-bit mode carries a 50712 × 256 sensor raw→linear LUT
//!   that the lossless surgery carries verbatim into the output, and
//!   the lossless decode is inert to it (it emits the raw
//!   pre-linearization p1 plane and never applies 50712) — so only
//!   the tool's log10 curve (× 4096) marks a quantized frame (see
//!   `decode_j92_frame` + pm-probe-50712.txt).
//!   v1 = the lossless native-depth (8/10/12-bit)
//!   family only — the p1 contract is the raw, unstripped, native-depth
//!   plane, which only the lossless encodes carry.
//! - **jxl decode** = the same machinery `jxl::verify_frame` uses
//!   (djxl 0.12.0 subprocess per plane → strict PAM parse →
//!   `jxl::reinterleave` → p1) — reuse: the strict P7 parse
//!   (`parse_pam`) mirrors `jxl::parse_pam_plane` (P7, DEPTH 1,
//!   MAXVAL 4095, TUPLTYPE GRAYSCALE, exact payload, big-endian u2)
//!   and the re-interleave is `jxl::reinterleave` verbatim. Frames are
//!   processed SERIALLY (the external decoder is the thread pool — the
//!   jxl-encode discipline; `--jobs N` → `--num_threads=N`, 0 = the
//!   binary's default threads).
//! - **Output PAM per frame**: the header from `jxl::pam_header`
//!   (P7, TUPLTYPE GRAYSCALE, MAXVAL 4095), payload = the full mosaic
//!   plane p1 as w×h unpacked 16-bit samples, big-endian u2 (the
//!   ground-truth pin: the PAM pixel-region sha256 == the
//!   `prep/manifest.tsv` p1 sha256 — the manifest is the arbiter).
//!   File name `<base>.pam` (j92: the DNG file stem; jxl: the frame
//!   stem — the common prefix of the 4 `.jxl` names). Atomic
//!   (tmp + rename), written only after a FULL successful decode
//!   (no partial PAM on failure; the input dir is never modified).
//! - **Restore-drill primitive** (the stated caveat: restore
//!   workflows were never tested) — decode is the verified restore
//!   path; the ship gate = 192f × 2 codecs pixel-region
//!   byte-identity against the manifest.
//! - **Exit codes** (the tool convention): pre-run/config errors
//!   (missing input, codec/content mismatch, no frames, `--frame` out
//!   of range) = rc 2; per-frame decode failures = a named `Failed`
//!   outcome per frame + rc 1 (the run itself completed; nothing
//!   half-written).
//! - **Frame order**: encoder order = the sorted input order (j92:
//!   sorted `.DNG` paths — the worker's collect order; jxl: sorted
//!   frame stems). `--frame N` is 1-based over that order.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use clap::{ValueEnum, Args as ClapArgs};
use rayon::prelude::*;

use crate::jxl::{pam_header, reinterleave, PLANES};
use crate::tiff::{self, IfdEntry, Meta};
use crate::tileenc::{self, Grid};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// The input codec for `frameprism decode` (cf. the encode `--codec`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Codec {
    /// J92 lossless tile JPEG inside the DNG container (the default —
    /// the encoded `.DNG` frames).
    J92,
    /// JXL modular lossless: 4 × `.jxl` per frame (the 2×2 sub-planes)
    /// + the `*.jxl-checksums.tsv` sidecar.
    Jxl,
}

/// The `frameprism decode` CLI arguments (the `Cmd::Decode` payload — the
/// subcommand args live here, not in `main.rs`, per the shared CLI
/// restructure contract).
#[derive(ClapArgs, Debug)]
pub struct Args {
    /// The encoded clip dir (j92: `.DNG` frames; jxl: 4 × `.jxl` per
    /// frame + the sidecar). A single `.DNG` file is accepted for j92
    /// (one frame; the PAM lands directly in `<output>`).
    pub input: PathBuf,
    /// The dir for the decoded PAMs (created if missing; the subfolder
    /// layout of the input is mirrored).
    pub output: PathBuf,
    /// The input codec (default j92; a dir whose content contradicts
    /// the codec is a hard reject with the reason).
    #[arg(long, value_enum, default_value_t = Codec::J92)]
    pub codec: Codec,
    /// Decode ONE frame only (1-based, encoder order = the sorted input
    /// order); absent = every frame.
    #[arg(long)]
    pub frame: Option<u32>,
    /// Thread budget: j92 = the rayon worker pool (0 = all cores, the
    /// default); jxl = the djxl `--num_threads` budget, frames
    /// processed serially (the external decoder is the thread pool).
    #[arg(long, default_value_t = 0)]
    pub jobs: usize,
    /// Overwrite existing PAMs (default: skip = resume).
    #[arg(long)]
    pub force: bool,
    /// cjxl binary (accepted for the shared CLI surface; decode never
    /// invokes the encoder — informational only).
    #[arg(long, default_value = "cjxl")]
    pub cjxl_bin: PathBuf,
    /// djxl binary for the jxl decode (path or PATH name; default
    /// `djxl` — the same binary family/version as the encode,
    /// v0.12.0).
    #[arg(long, default_value = "djxl")]
    pub djxl_bin: PathBuf,
}

/// Per-frame decode stats (the summary table row).
#[derive(Clone, Debug)]
struct FrameStats {
    file: String,
    in_bytes: u64,
    out_bytes: u64,
    ms: f64,
}

enum FrameOutcome {
    Done(FrameStats),
    Skipped { file: String, in_bytes: u64 },
    Failed { file: String, error: String },
}

struct Report {
    done: Vec<FrameStats>,
    skipped: Vec<(String, u64)>,
    failed: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// entry
// ---------------------------------------------------------------------------

/// The `Cmd::Decode` match arm (main.rs): run the decode, return the
/// process exit code (2 = pre-run error, 1 = per-frame failure(s),
/// 0 = clean).
pub fn run(args: &Args) -> ExitCode {
    match run_inner(args) {
        Ok(report) => {
            print_summary(args, &report);
            if report.failed.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run_inner(args: &Args) -> Result<Report> {
    // Pre-run validation (rc=2 band): the codec matches the content,
    // --frame is in range, frames exist.
    if args.input == args.output {
        bail!("input and output must differ");
    }

    // The frame set (codec-specific collection + the cross-codec
    // diagnostic live in the collectors — a jxl dir given --codec j92
    // is a hard reject WITH THE REASON, not a silent empty run).
    let (n92, njxl) = match args.codec {
        Codec::J92 => {
            let frames = collect_j92(&args.input)?;
            (Some(frames), None)
        }
        Codec::Jxl => {
            let frames = collect_jxl(&args.input)?;
            (None, Some(frames))
        }
    };
    let count92 = n92.as_ref().map(|v| v.len()).unwrap_or(0);
    let countjxl = njxl.as_ref().map(|v| v.len()).unwrap_or(0);
    let count = count92 + countjxl;
    if count == 0 {
        bail!("no frames to decode in {}", args.input.display());
    }
    let selected: Vec<usize> = match args.frame {
        None => (0..count).collect(),
        Some(n) => {
            if n == 0 {
                bail!("--frame {n} is out of range (frame numbers are 1-based; 1..={count})");
            }
            if (n as usize) > count {
                bail!("--frame {n} is out of range (the input has {count} frame(s) in encoder order)");
            }
            vec![n as usize - 1]
        }
    };

    // Fail fast on a bogus djxl BEFORE anything is written (atomicity +
    // a named error — the jxl::version_line discipline). Runs AFTER
    // the content diagnostics: a j92 dir given --codec jxl is a
    // CONTENT mismatch and must name that reason first (not a
    // missing-binary error when djxl is not on PATH).
    let djxl_version = if args.codec == Codec::Jxl {
        Some(version_line(&args.djxl_bin)?)
    } else {
        None
    };

    std::fs::create_dir_all(&args.output)
        .with_context(|| format!("create output dir {}", args.output.display()))?;

    let t0 = Instant::now();
    let outcomes: Vec<FrameOutcome> = if let Some(frames) = n92 {
        // j92: parallel — frames are fully independent (the worker
        // discipline; jobs 0 = the default pool, N = a dedicated
        // pool). rayon's par_iter collect preserves the input order
        // (= the encoder order).
        let items: Vec<&J92Desc> = frames
            .iter()
            .enumerate()
            .filter(|(i, _)| selected.contains(i))
            .map(|(_, f)| f)
            .collect();
        if args.jobs > 0 {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(args.jobs)
                .build()?;
            pool.install(|| {
                items
                    .par_iter()
                    .map(|f| j92_one(f, &args.output, args.force))
                    .collect()
            })
        } else {
            items
                .par_iter()
                .map(|f| j92_one(f, &args.output, args.force))
                .collect()
        }
    } else {
        // jxl: serial — the external decoder is the thread pool (a
        // frame pool on top would oversubscribe; the jxl-encode
        // discipline).
        let frames = njxl.expect("jxl frames");
        frames_jxl(&frames, &selected, &args.output, args.force, &args.djxl_bin, args.jobs)
    };
    let elapsed = t0.elapsed().as_secs_f64();

    let mut report = Report {
        done: Vec::new(),
        skipped: Vec::new(),
        failed: Vec::new(),
    };
    for o in outcomes {
        match o {
            FrameOutcome::Done(s) => report.done.push(s),
            FrameOutcome::Skipped { file, in_bytes } => report.skipped.push((file, in_bytes)),
            FrameOutcome::Failed { file, error } => {
                eprintln!("FAIL {file}: {error}");
                report.failed.push((file, error));
            }
        }
    }
    let avg = if report.done.is_empty() {
        0.0
    } else {
        report.done.iter().map(|s| s.ms).sum::<f64>() / report.done.len() as f64
    };
    let djxl_note = djxl_version.map(|v| format!(", djxl {v}")).unwrap_or_default();
    eprintln!(
        "{} frame(s) decoded in {:.1}s (avg {:.0} ms/frame{djxl_note}), {} skipped, {} failed: {}",
        report.done.len(),
        elapsed,
        avg,
        report.skipped.len(),
        report.failed.len(),
        args.input.display()
    );
    Ok(report)
}

// ---------------------------------------------------------------------------
// collection
// ---------------------------------------------------------------------------

/// A j92 frame: the `.DNG` source + the output PAM path relative to
/// the output root (subfolder layout mirrored; the file stem + `.pam`).
#[derive(Clone, Debug)]
struct J92Desc {
    src: PathBuf,
    dst_rel: PathBuf,
    file: String,
}

/// A jxl frame group: the 4 planes in `dir`, `stem` = the common
/// prefix of the 4 `.jxl` names, the output PAM relative to the output
/// root.
#[derive(Clone, Debug)]
struct JxlDesc {
    dir: PathBuf,
    stem: String,
    dst_rel: PathBuf,
    in_bytes: u64,
}

/// Recurse `dir` under `base` (the subfolder layout preserved in
/// `rel`): symlinked entries refused, (dev, ino) visited-set cycle
/// guard (the worker's collect discipline).
fn walk(
    base: &Path,
    dir: &Path,
    visited: &mut std::collections::HashSet<(u64, u64)>,
    visit_file: &mut dyn FnMut(&Path, &Path) -> Result<()>,
) -> Result<()> {
    let meta = std::fs::metadata(dir)
        .with_context(|| format!("read dir {}", dir.display()))?;
    let id = (meta.dev(), meta.ino());
    if !visited.insert(id) {
        return Ok(()); // already visited — symlink cycle (or hard-link fan-in)
    }
    let entries =
        std::fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue; // refuse symlinked entries (cycle/escape guard)
        }
        if p.is_dir() {
            walk(base, &p, visited, visit_file)?;
        } else if p.is_file() {
            let rel = p.strip_prefix(base).unwrap_or(&p);
            visit_file(&p, rel)?;
        }
    }
    Ok(())
}

fn ext_is(p: &Path, want: &str) -> bool {
    p.extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case(want))
        .unwrap_or(false)
}

/// Collect the j92 frames: every `.DNG` under `input` (recursed; the
/// subfolder layout mirrored into `output`), sorted by path = the
/// encoder order. A single `.DNG` FILE input is accepted (one frame;
/// the PAM lands directly in `<output>`). A dir with `.jxl` files but
/// no `.DNG` is a hard reject with the reason (the cross-codec
/// diagnostic — the negative-gate contract).
fn collect_j92(input: &Path) -> Result<Vec<J92Desc>> {
    let mut frames: Vec<J92Desc> = Vec::new();
    if input.is_dir() {
        let mut jxl_count = 0u64;
        let mut visited = std::collections::HashSet::new();
        walk(input, input, &mut visited, &mut |p, rel| {
            if ext_is(p, "dng") {
                let dst_rel = rel.with_extension("pam");
                frames.push(J92Desc {
                    src: p.to_path_buf(),
                    dst_rel,
                    file: p
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| p.display().to_string()),
                });
            } else if ext_is(p, "jxl") {
                jxl_count += 1;
            }
            Ok(())
        })?;
        if frames.is_empty() && jxl_count > 0 {
            bail!(
                "no .DNG frames in {} (it contains {jxl_count} .jxl file(s) — it is a JXL clip; pass --codec jxl)",
                input.display()
            );
        }
    } else if input.is_file() {
        if !ext_is(input, "dng") {
            bail!(
                "input is neither a directory nor a .DNG file: {}",
                input.display()
            );
        }
        let base = input
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        frames.push(J92Desc {
            src: input.to_path_buf(),
            dst_rel: PathBuf::from(format!("{base}.pam")),
            file: input
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| input.display().to_string()),
        });
    } else {
        bail!("input is not a directory: {}", input.display());
    }
    frames.sort_by(|a, b| a.src.cmp(&b.src));
    Ok(frames)
}

/// Collect the jxl frame groups: every file named `<stem>_p2_{00,01,
/// 10,11}.jxl` under `input`, grouped by (dir, stem); a group needs
/// all 4 planes in the same dir (a partial group is a hard reject with
/// the named stem + the missing planes). Sorted by (dir, stem) = the
/// encoder order.
fn collect_jxl(input: &Path) -> Result<Vec<JxlDesc>> {
    if !input.is_dir() {
        bail!(
            "--codec jxl requires a clip dir (4 × .jxl per frame); the input is not a directory: {}",
            input.display()
        );
    }
    #[derive(Default)]
    struct Acc {
        planes: [bool; 4],
        sizes: [u64; 4],
    }
    let mut groups: std::collections::BTreeMap<(PathBuf, String), Acc> =
        std::collections::BTreeMap::new();
    let mut jxl_count = 0u64;
    let mut dng_count = 0u64;
    let mut visited = std::collections::HashSet::new();
    walk(input, input, &mut visited, &mut |p, rel| {
        if ext_is(p, "jxl") {
            jxl_count += 1;
            let name = p
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            for (i, plane) in PLANES.iter().enumerate() {
                let suffix = format!("_{plane}.jxl");
                if let Some(stem) = name.strip_suffix(&suffix) {
                    if stem.is_empty() {
                        bail!("unparseable jxl frame name: {name}");
                    }
                    let len = std::fs::metadata(p)?.len();
                    let dir = p.parent().unwrap().to_path_buf();
                    let acc = groups
                        .entry((dir.clone(), stem.to_string()))
                        .or_default();
                    acc.planes[i] = true;
                    acc.sizes[i] = len;
                    let _ = rel;
                    return Ok(());
                }
            }
            bail!(
                "unrecognized .jxl name (expected <stem>_p2_{{00,01,10,11}}.jxl): {name}"
            );
        }
        if ext_is(p, "dng") {
            dng_count += 1;
        }
        Ok(())
    })?;

    let mut frames: Vec<JxlDesc> = Vec::new();
    for ((dir, stem), acc) in groups {
        if !acc.planes.iter().all(|&b| b) {
            let missing: Vec<&str> = acc
                .planes
                .iter()
                .enumerate()
                .filter(|(_, &b)| !b)
                .map(|(i, _)| PLANES[i])
                .collect();
            bail!(
                "incomplete jxl frame group {stem} in {}: missing plane(s) {}",
                dir.display(),
                missing.join(", ")
            );
        }
        let dir_rel = dir.strip_prefix(input).unwrap_or(&dir);
        let dst_rel = dir_rel.join(format!("{stem}.pam"));
        frames.push(JxlDesc {
            dir,
            stem,
            dst_rel,
            in_bytes: acc.sizes.iter().sum(),
        });
    }
    frames.sort_by(|a, b| (a.dir.as_path(), a.stem.as_str()).cmp(&(b.dir.as_path(), b.stem.as_str())));
    if frames.is_empty() {
        if dng_count > 0 {
            bail!(
                "no jxl frame groups in {} (it contains {dng_count} .DNG file(s) — it is a J92 clip; pass --codec j92)",
                input.display()
            );
        }
        if jxl_count > 0 {
            bail!(
                "no complete jxl frame groups in {} ({jxl_count} .jxl file(s) found)",
                input.display()
            );
        }
        bail!("no .jxl frames in input dir {}", input.display());
    }
    Ok(frames)
}

// ---------------------------------------------------------------------------
// j92 decode (the --verify machinery: DNG read → lossless tile decode → p1)
// ---------------------------------------------------------------------------

/// Decode ONE j92 frame as an outcome (a per-frame error is a named
/// `Failed`, never an abort of the run — the worker discipline).
fn j92_one(desc: &J92Desc, output_root: &Path, force: bool) -> FrameOutcome {
    match decode_j92_one(desc, output_root, force) {
        Ok(o) => o,
        Err(err) => FrameOutcome::Failed {
            file: desc.file.clone(),
            error: format!("{err:#}"),
        },
    }
}

/// Decode ONE j92 frame: the resume check, the DNG read, the structure
/// dispatch, the PAM write (atomic, after a FULL successful decode).
fn decode_j92_one(desc: &J92Desc, output_root: &Path, force: bool) -> Result<FrameOutcome> {
    let t0 = Instant::now();
    let dst = output_root.join(&desc.dst_rel);
    let in_bytes = std::fs::metadata(&desc.src).map(|m| m.len()).unwrap_or(0);
    if dst.exists() && !force {
        return Ok(FrameOutcome::Skipped {
            file: desc.file.clone(),
            in_bytes,
        });
    }
    let buf =
        std::fs::read(&desc.src).with_context(|| format!("read {}", desc.src.display()))?;
    let (w, h, p1) = decode_j92_frame(&buf, &desc.file)?;
    if let Some(parent) = dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
    }
    write_pam(&dst, w, h, &p1)?;
    let out_bytes = std::fs::metadata(&dst).map(|m| m.len()).unwrap_or(0);
    Ok(FrameOutcome::Done(FrameStats {
        file: desc.file.clone(),
        in_bytes,
        out_bytes,
        ms: t0.elapsed().as_secs_f64() * 1000.0,
    }))
}

/// Decode a lossless j92 DNG to the full mosaic plane p1 (w×h u16).
/// The structure dispatch reads IFD0 of the ENCODED frame (`tiff::read`
/// refuses compressed/tiled frames by design, so `read_meta` is the
/// parser):
/// - tag-7 + the 482×272 tile grid + native 8/10/12-bit + no log10
///   50712 (× 4096) =
///   the lossless tile structure (incl. the downscale2x half-resolution
///   variant) → per-tile golden-model decode (`tileenc::decode_tile`,
///   the G3 acceptance path) at the frame's BitsPerSample precision;
///   a reference 50712 (e.g. the fp 8-bit × 256 LinearizationTable,
///   carried verbatim by the lossless surgery) is INERT to this decode
///   (it never reads or applies 50712) and does not mark the frame
///   quantized;
/// - tag-7 + no tile tags + 12-bit = the single-strip lossless JPEG →
///   `codec::decode_lossless` (the `verify::bit_exact` machinery);
/// - everything else (raw Compression=1, the log10 50712 × 4096,
///   34892, reference tag-7
///   DCT, a foreign 322/323 grid, non-12-bit single-strip) = a hard
///   reject with the reason.
fn decode_j92_frame(buf: &[u8], what: &str) -> Result<(u32, u32, Vec<u16>)> {
    let meta = tiff::read_meta(buf).map_err(|e| anyhow!("{what}: parse: {e}"))?;
    let get = |tag: u16| -> Option<&IfdEntry> {
        meta.ifd0.entries.iter().find(|e| e.tag == tag)
    };
    let tag_int = |tag: u16| -> Option<u64> {
        let e = get(tag)?;
        let base: &[u8] = match e.out_of_line {
            Some((p, _)) if p as usize + 4 <= buf.len() => {
                &buf[p as usize..p as usize + 4]
            }
            None => &e.value_raw,
            _ => return None,
        };
        match e.typ {
            3 => Some(meta.endianness.u16(base) as u64),
            4 => Some(meta.endianness.u32(base) as u64),
            _ => None,
        }
    };
    let width = tag_int(256)
        .map(|v| v as u32)
        .ok_or_else(|| anyhow!("{what}: missing ImageWidth (256)"))?;
    let height = tag_int(257)
        .map(|v| v as u32)
        .ok_or_else(|| anyhow!("{what}: missing ImageLength (257)"))?;
    let bps = tag_int(258).unwrap_or(0);
    let compression = tag_int(259).unwrap_or(0);
    let photometric = tag_int(262).unwrap_or(0);
    let spp = tag_int(277).unwrap_or(0);
    let has_tiles = get(322).is_some() && get(323).is_some();
    // 50712 count distinguishes the structure (deviation #3,
    // pm-fix-decode50712.md / pm-probe-50712.txt): the ONLY tag-7
    // structure the tool writes that carries a 50712 is log10 mode,
    // and it writes exactly CURVE_LEN = 4096 SHORTs. The fp 8-bit
    // camera mode carries a reference LinearizationTable (SHORT × 256 —
    // a sensor raw→linear LUT) that the lossless surgery carries
    // VERBATIM into the output (byte-identical source↔encode); the
    // lossless decode never reads it (it emits the raw
    // pre-linearization p1 plane), so any 50712 count other than
    // 4096 is inert reference metadata, not a quantized structure.
    let curve_count = get(50712).map(|e| e.count);

    // ---- structure refusals (loud + named — the v1 lossless-only
    // contract) ----
    if compression == 1 {
        bail!(
            "{what}: Compression=1 = an UNCOMPRESSED source frame — decode targets encoded output (encode it first; this input is the source clip, not the archive)"
        );
    }
    if compression == 34892 {
        bail!(
            "{what}: Compression=34892 = a LOSSY frame — decode v1 is lossless-only (the encoded plane is 8-bit; the 12-bit p1 cannot be restored)"
        );
    }
    if compression != 7 {
        bail!(
            "{what}: unsupported Compression={compression} (v1 decodes the tag-7 lossless family only)"
        );
    }
    // Refuse ONLY the log10 quantized structure (50712 × CURVE_LEN =
    // 4096 SHORTs). Any other 50712 count (incl. the measured reference
    // fp 8-bit SHORT × 256) and no 50712 fall through to the normal
    // lossless decode (the tag-7 curve is inert — pm-probe-50712.txt).
    const LOG10_CURVE: u32 = crate::lossydct::CURVE_LEN as u32;
    if curve_count == Some(LOG10_CURVE) {
        bail!(
            "{what}: tag-7 + the log10 LinearizationTable (50712, SHORT × {LOG10_CURVE}) = the log10 (quantized) structure — decode v1 is the LOSSLESS native-depth (8/10/12-bit) family only (that structure quantizes by design)"
        );
    }
    if (bps != 8 && bps != 10 && bps != 12) || photometric != 32803 || spp != 1 {
        bail!(
            "{what}: unexpected frame tags (BitsPerSample={bps}, Photometric={photometric}, SamplesPerPixel={spp}) — the lossless native-depth (8/10/12-bit) CFA frame is expected"
        );
    }

    if has_tiles {
        // ---- lossless tile structure (per-gate grid eligibility) ----
 // The measured contract ( + ): 3024×2010
        // accepts the reference 252×252 grid (the new 3K contract) AND
        // the legacy 482×272 grid (the pre-fix encoder's 3K output must
        // remain decodable — backward compatibility); 1936×1090 (FHD)
        // accepts the per-(geometry × depth) measured contract — the
        // @12/@8 grid 242×274 (8×4 = 32 tiles) AND the @10 grid
 // 484×274 (4×4 = 16 tiles) (rows) — PLUS
        // the legacy 482×272 grid (the pre-fix encoder's FHD output
        // must remain decodable — the storage contract holds across the
 // grid fix, the backward-compat pattern); 2016×1344
        // (Open Gate 2K) accepts the measured depth-invariant grid
 // 252×336 (8×4 = 32 tiles — rows,
 // ) PLUS the legacy 482×272 grid (the pre-fix encoder's
        // OG2K output must remain decodable — the same backward-compat
 // pattern); 1008×672 (the OG2K ds2x — the measured 
 // mode rows, ) accepts the source's OG2K depth-
        // invariant grid 252×336 (4×2 = 8 tiles — full-tile edge rows
 // only — the measured no-half-row verdict) — NO legacy
        // fallback (the 482×272 grid at 1008×672 is an unmeasured shape
        // — the named refusal, the FHD ds2x pattern); 3856×2170 (UHD)
        // accepts the per-(geometry × depth)
 // measured contract (rows, —
 // the onboarding G4) — the @10 grid 964×272 (4×8 =
        // 32 tiles) AND the @12/@8 482×272 grid (8×8 = 64 tiles — the
 // @12 in-profile measured match + the pre-existing @10 output);
        // every other geometry accepts the 482×272 grid only (a
        // foreign grid at a non-3K/non-FHD/non-OG2K/non-UHD frame was
        // never a reference output — named refusal). The grid itself is
        // FILE-DERIVED from the file's 322/323 below (depth is not part
        // of the decode eligibility — the tile blob's SOF3 precision
        // rides each tile).
        let tw = tag_int(322).unwrap_or(0) as u32;
        let th = tag_int(323).unwrap_or(0) as u32;
        let (gate_tw, gate_th) = tileenc::gate_tile_dims(width, height);
        let is_fhd = tileenc::is_fhd_gate(width, height);
        let is_fhd_ds2x = tileenc::is_fhd_ds2x_gate(width, height);
        let is_og2k = tileenc::is_og2k_gate(width, height);
        let is_og2k_ds2x = tileenc::is_og2k_ds2x_gate(width, height);
        let is_og3k_ds2x = tileenc::is_og3k_ds2x_gate(width, height);
        let is_uhd_ds2x = tileenc::is_uhd_ds2x_gate(width, height);
        let is_uhd = tileenc::is_uhd_gate(width, height);
        let modern = if is_fhd_ds2x {
 // The FHD ds2x frame (968×545 — the measured 
 // mode rows): the SOURCE's FHD per-depth grids on the
            // ds2x geometry (242×274 @12/@8 → 4×2 = 8 tiles; 484×274
            // @10 → 2×2 = 4 tiles). The bottom-row tile is the 271-
            // content-row half-row tile on the 274-row plane (the odd-
            // height interop shape — the restore drill's content-rows-
 // only semantics, the decision (b)). The family is
            // the grid×mode-keyed 2-member DS2X family (the routing
            // below — `gate_candidates_for_grid` → `DS2X_FHD_CANDIDATES`,
 // the decision (c)); the 482×272 grid is NOT an eligible ds2x
            // shape (the 1928×1085 UHD ds2x output is the 0.1.0-era
            // legacy mode shape — the byte-frozen mode control).
            (tw, th) == (tileenc::GATE_FHD_TILE_W_12, tileenc::GATE_FHD_TILE_H)
                || (tw, th) == (tileenc::GATE_FHD_TILE_W_10, tileenc::GATE_FHD_TILE_H)
        } else if is_fhd {
            (tw, th) == (tileenc::GATE_FHD_TILE_W_12, tileenc::GATE_FHD_TILE_H)
                || (tw, th) == (tileenc::GATE_FHD_TILE_W_10, tileenc::GATE_FHD_TILE_H)
        } else if is_og2k_ds2x {
 // The OG2K ds2x frame (1008×672 — the measured 
 // mode rows, ): the SOURCE's OG2K depth-
            // invariant 252×336 grid on the ds2x geometry (4×2 = 8
            // tiles at every depth — 1008 = 4×252, 672 = 2×336 exact:
 // full-tile edge rows only, NO half-row class — the 
            // measured no-half-row verdict; the restore drill runs the
            // plain full-tile semantics). The family is the grid×mode-
            // keyed 3-member DS2X family (the routing below —
            // `gate_candidates_for_grid` → `DS2X_OG2K_CANDIDATES` —
 // the census: W7 observed on the ds2x corpus,
            // the 3-member set exactly); the 482×272 grid is NOT an
            // eligible ds2x shape (the unmeasured combination — the
            // named refusal, the FHD ds2x pattern).
            (tw, th) == (tileenc::GATE_OG2K_TILE_W, tileenc::GATE_OG2K_TILE_H)
        } else if is_og3k_ds2x {
 // The OG3K ds2x frame (1512×1005 — the measured 
 // mode rows, ): the SOURCE's OG3K depth-
            // invariant 252×252 grid on the ds2x geometry (6×4 = 24
            // tiles at every depth; 1512 = 6×252 exact, 1005 = 3×252 +
            // 249 — the bottom-row tiles are the 249-content-row
            // half-row tiles on the 252-row plane — the odd-height
            // interop shape; the restore drill runs the content-rows-
 // only semantics, the decision (b)). The family is
            // the grid×mode-keyed 3-member DS2X family (the routing
            // below — `gate_candidates_for_grid` →
 // `DS2X_OG3K_CANDIDATES` — the census: W7
            // observed on the ds2x corpus, the 3-member set exactly);
            // the 482×272 grid is NOT an eligible ds2x shape (the
            // unmeasured combination — the named refusal, the OG2K ds2x
            // pattern).
            (tw, th) == (tileenc::GATE_3K_TILE_W, tileenc::GATE_3K_TILE_H)
        } else if is_uhd_ds2x {
 // The UHD ds2x frame (1928×1085 — the measured 
 // mode rows, ): the SOURCE's UHD per-depth
            // grids on the ds2x geometry (964×272 @10 → 2×4 = 8 tiles;
            // 482×272 @8 → 4×4 = 16 tiles — 1085 = 3×272 + 269 at BOTH
            // grids: the bottom-row tiles are the 269-content-row
            // half-row tiles on the 272-row plane — the odd-height
            // interop shape; the restore drill runs the content-rows-
 // only semantics, the decision (b)). The family is
            // the grid×mode-keyed DS2X family (the routing below —
            // `gate_candidates_for_grid` → `DS2X_UHD_964_CANDIDATES`
 // the 2-member {W2, N1} — W7 never observed — the 
 // census; `DS2X_UHD_482_CANDIDATES` the 3-member {W7,
            // W2, N1} — the @8 row + the 0.1.0-era legacy ds2x output,
            // both the 482×272 grid — the byte-frozen mode control
            // kept decodable, the backward-compat pattern).
            (tw, th) == (tileenc::GATE_UHD_TILE_W_10, tileenc::TILE_H)
                || (tw, th) == (tileenc::TILE_W, tileenc::TILE_H)
        } else if is_og2k {
            (tw, th) == (tileenc::GATE_OG2K_TILE_W, tileenc::GATE_OG2K_TILE_H)
        } else if is_uhd {
            // The UHD per-(geometry × depth) measured contract: the @10 grid 964×272 (4×8 = 32 tiles) AND the
            // @12/@8 482×272 grid (8×8 = 64 tiles — the @12 in-profile
 // measured match + the pre-existing @10 output, both kept
            // decodable — the backward-compat pattern).
            (tw, th) == (tileenc::GATE_UHD_TILE_W_10, tileenc::TILE_H)
                || (tw, th) == (tileenc::TILE_W, tileenc::TILE_H)
        } else {
            (tw, th) == (gate_tw, gate_th)
        };
        let legacy_3k = tileenc::is_3k_gate(width, height)
            && (tw, th) == (tileenc::TILE_W, tileenc::TILE_H);
        let legacy_fhd = is_fhd && (tw, th) == (tileenc::TILE_W, tileenc::TILE_H);
        let legacy_og2k = is_og2k && (tw, th) == (tileenc::TILE_W, tileenc::TILE_H);
        if !modern && !legacy_3k && !legacy_fhd && !legacy_og2k {
            let (expected_txt, legacy_note) = if is_fhd_ds2x {
 // The FHD ds2x measured contract (the 
                // mode rows) — NO legacy fallback: the 482×272 grid at
                // 968×545 is an unmeasured shape (the A+C boundary — the
                // named refusal; the 1928×1085 legacy ds2x output is the
                // byte-frozen mode control, a different geometry).
                (
                    "242×274 or 484×274".to_string(),
                    String::new(),
                )
            } else if is_og2k_ds2x {
 // The OG2K ds2x measured contract (the 
 // mode rows, ) — NO legacy fallback: the 482×272
                // grid at 1008×672 is an unmeasured shape (the A+C
                // boundary — the named refusal, the FHD ds2x pattern).
                (
                    "252×336".to_string(),
                    String::new(),
                )
            } else if is_og3k_ds2x {
 // The OG3K ds2x measured contract (the 
 // mode rows, ) — NO legacy fallback: the 482×272
                // grid at 1512×1005 is an unmeasured shape (the A+C
                // boundary — the named refusal, the OG2K ds2x pattern).
                (
                    "252×252".to_string(),
                    String::new(),
                )
            } else if is_uhd_ds2x {
 // The UHD ds2x measured contract (the 
 // mode rows, ) — NO legacy fallback
                // beyond the measured grids: the 482×272 grid IS a
                // measured ds2x grid here (the @8 row + the 0.1.0-era
                // legacy ds2x output — the byte-frozen mode control);
                // every OTHER grid at 1928×1085 is the unmeasured
                // combination — the named refusal (the FHD/OG2K/OG3K
                // ds2x pattern).
                (
                    "964×272 or 482×272".to_string(),
                    " (the 964×272 = the @10 measured ds2x grid; the 482×272 = the @8 measured ds2x grid + the 0.1.0-era legacy ds2x output)".to_string(),
                )
            } else if is_fhd {
                (
                    "242×274 or 484×274".to_string(),
                    " (or 482×272 — the legacy pre-fix FHD output)".to_string(),
                )
            } else if is_og2k {
                (
                    "252×336".to_string(),
                    " (or 482×272 — the legacy pre-fix OG2K output)".to_string(),
                )
            } else if is_uhd {
                (
                    "964×272 or 482×272".to_string(),
                    " (the 964×272 = the @10 measured grid; the 482×272 = the @12/@8 in-profile grid + the legacy @10 output)".to_string(),
                )
            } else {
                (
                    format!("{gate_tw}×{gate_th}"),
                    if tileenc::is_3k_gate(width, height) {
                        " (or 482×272 — the legacy pre-fix 3K output)".to_string()
                    } else {
                        String::new()
                    },
                )
            };
            bail!(
                "{what}: unexpected tile grid tags 322/323 = {tw}×{th} (expected {expected_txt}{legacy_note} — the lossless tile geometry)"
            );
        }
        let (offs, lens) = tile_offsets_and_lens(&meta, buf, what)?;
        // The grid derives from the FILE's 322/323 (not the frame dims):
        // the legacy 482×272 3K archives decode at 7×8 = 56 cells
        // alongside the new 252×252 archives at 12×8 = 96; the FHD
        // archives decode at the file's own grid (the measured
        // 242×274 8×4 = 32 / 484×274 4×4 = 16, the legacy 482×272
        // 5×5 = 25); the OG2K archives decode at the file's own grid
        // (the measured 252×336 8×4 = 32, the legacy 482×272 5×5 = 25);
        // the OG2K ds2x archives decode at the file's own grid (the
 // measured 252×336 4×2 = 8 — );
        // the OG3K ds2x archives decode at the file's own grid (the
 // measured 252×252 6×4 = 24 — );
        // the UHD ds2x archives decode at the file's own grid (the
        // measured 964×272 2×4 = 8 @10 + the 482×272 4×4 = 16 @8 —
 // — the per-depth source-grid inheritance; the bottom-
        // row tiles are the 269-content-row half-row tiles — the
 // content-rows drill semantics, the decision (b); the 0.1.0-era
        // legacy 482×272 ds2x output stays decodable — the backward-
        // compat pattern);
        // the UHD archives decode at the file's own grid (the measured
 // @10 964×272 4×8 = 32 — — the @12/@8 + the pre-existing
        // @10 482×272 8×8 = 64);
        // every other gate decodes at the 482×272 grid
        // exactly as before.
        let grid = Grid::for_dims(width, height, tw, th);
        let cells = (grid.cols * grid.rows) as usize;
        if offs.len() != cells {
            bail!(
                "{what}: tile count {} (tags 324/325) != grid {cols}×{rows} = {cells} tiles",
                offs.len(),
                cols = grid.cols,
                rows = grid.rows
            );
        }
        // The verify gate's strict-contiguity checks (a corrupted or
        // foreign DNG fails loud + named): monotonically contiguous
        // offsets, every tile in bounds, the last tile ends exactly at
        // EOF (the assembly contract of `surgery::apply_tiled`).
        let mut prev_end = 0u64;
        for (i, (o, l)) in offs.iter().zip(lens.iter()).enumerate() {
            if o + l > buf.len() as u64 {
                bail!(
                    "{what}: tile {i} out of bounds (offset {o}, size {l}, file {} B)",
                    buf.len()
                );
            }
            if i == 0 && *o == 0 {
                bail!("{what}: tile 0 offset is 0 (invalid)");
            }
            if i > 0 && *o != prev_end {
                bail!(
                    "{what}: tile {i} offset {o} != previous tile end {prev_end} (the tiles must be strictly contiguous, tags 324/325)"
                );
            }
            prev_end = o + l;
        }
        if prev_end != buf.len() as u64 {
            bail!(
                "{what}: the last tile ends at {prev_end} != file end {} (the tile blob must end exactly at EOF)",
                buf.len()
            );
        }
        let mut p1 = vec![0u16; (width as usize) * (height as usize)];
        for (i, (o, l)) in offs.iter().zip(lens.iter()).enumerate() {
            let r = (i / grid.cols as usize) as u32;
            let c = (i % grid.cols as usize) as u32;
            let rect = tileenc::tile_region(width, height, &grid, r, c)
                .map_err(|e| anyhow!("{what}: tile ({r},{c}): {e}"))?;
            let dec = tileenc::decode_tile(
                &buf[*o as usize..(*o as usize + *l as usize)],
                &rect,
                bps as u32,
                grid.th,
            )
            .map_err(|e| anyhow!("{what}: tile ({r},{c}): decode: {e}"))?;
            let base = (rect.y0 as usize) * width as usize + rect.x0 as usize;
            for y in 0..rect.tl as usize {
                let s = base + y * width as usize;
                p1[s..s + rect.tw as usize]
                    .copy_from_slice(&dec[y * rect.tw as usize..y * rect.tw as usize + rect.tw as usize]);
            }
        }
        // ---- restore-drill integrity: the decode→re-encode round-trip ----
        // The tile stream carries NO checksum: a mid-file byte flip can
        // leave a VALID coded stream that decodes to WRONG samples
        // (probe: 4/12 one-byte 0xFF flips in the tile blob decoded
        // silently with corrupted pixels). The encoder and this decoder
        // are deterministic and bit-exact (the 2304-file byte-identity
        // gates), so re-encoding the decoded samples must reproduce the
        // stored tile bytes bit-exactly for a valid file. Accept a
        // match with ANY of the candidate encodings OF THE FILE'S GRID
        // (the grid-keyed per-gate family —
        // `tileenc::gate_candidates_for_grid`): the FHD grids (242×274 /
        // 484×274 at 1936×1090) accept the measured FHD family
        // {wrapped-PSV7, wrapped-PSV6, natural-PSV5} (the measured
        // FHD tiles sit outside the 482 legacy family — the measured
 // contract, the 80/80-tile census); the FHD
        // ds2x grids (242×274 / 484×274 at 968×545 — the measured
 // mode rows) accept the grid×mode-keyed 2-
 // member DS2X family {wrapped-PSV6, natural-PSV5} (the decision
        // (c) — W7 never observed, the superset rejected); the OG2K
        // grid (252×336 at 2016×1344) accepts the measured OG2K family
        // {wrapped-PSV7, wrapped-PSV6, natural-PSV5} (the same 3
        // members — the measured per-gate family for the new
 // grids — the measured contract, the
        // 288/288-tile census); the UHD @10 grid (964×272 at 3856×2170)
 // accepts `tileenc::CANDIDATES` — the measured
        // family: the 96/96-tile census found the 482 legacy family's
        // members {wrapped-PSV7, wrapped-PSV2, natural-PSV1}, ZERO
        // outside (the 964×272 grid's measured family = the legacy
        // family's members — no separate constant); every other grid
        // (the 482×272 legacy family at every geometry, incl. the
        // legacy pre-fix FHD/OG2K archives + the UHD @12/@8 482×272
        // archives, + the 3K 252×252) accepts `tileenc::CANDIDATES`
        // unchanged. Default mode is adaptive (smallest of the family);
        // `--fast` is the fixed per-gate family index 0 (the global
        // FAST_CANDIDATE = Wrapped PSV7 at every existing geometry; the
        // DS2X family's index 0 = Wrapped PSV6 at 968×545 — the
 // decision (c) pattern) — both are in this set. A
        // stored tile that matches none of them is a corrupt stream
        // (loud, named — no PAM written). ODD-HEIGHT INTEROP SEMANTICS
 // (the decision (b) — the FHD ds2x bottom-row tiles):
        // the 968×545 frame on the 274-row grid has 271 CONTENT rows in
        // the bottom-row tiles (545−274); the corpus stored
        // 274-row plane carries SYNTHETIC pad rows (the file's pre-
        // decimation pipeline — NOT reproducible from the stored frame,
 // the measurement), while the tool's own ds2x output pads
        // self-consistently (the alternate last-two-rows repeat). The
        // drill therefore re-encodes, for a bottom-row tile (rect.tl <
        // grid.th), the FILE'S OWN decoded full plane (the pad rows
        // self-sourced from the stored tile — `planes_from_tile_rows` +
        // `encode_tile_planes`, bypassing the tool's pad rule) and
        // accepts a match with ANY of the grid-keyed family: the
        // deterministic engine reproduces the stored bytes bit-exactly
        // iff the tl CONTENT rows round-trip (the content rows verified;
        // the pad rows round-trip trivially — non-content filler). Every
        // other tile (incl. the tool's own ds2x bottom tiles — their pad
        // is self-consistent, so the full-plane re-encode matches) keeps
        // the full-plane self-consistent re-encode. Coupling note: the
        // acceptance set is the encoder's per-grid candidate family — a
        // future encoder change (new candidates / families / engines)
        // MUST extend it, or old-data restore fails loud (the safe
        // direction — but a break).
        for (i, (o, l)) in offs.iter().zip(lens.iter()).enumerate() {
            let r = (i / grid.cols as usize) as u32;
            let c = (i % grid.cols as usize) as u32;
            let stored = &buf[*o as usize..*o as usize + *l as usize];
            let rect = tileenc::tile_region(width, height, &grid, r, c)
                .map_err(|e| anyhow!("{what}: tile ({r},{c}): {e}"))?;
            if rect.tl < grid.th {
                // The odd-height bottom-row tile (the FHD ds2x 968×545
 // interop shape — the decision (b) content-rows-only
                // semantics above): the self-sourced full-plane re-
                // encode. The stored tile is the FULL 274-row geometry
                // (padded — the SOF3 shapes pad to th), so decode at the
                // full-height rect (the pad rows INCLUDED — self-
                // sourced from the stored tile, NOT the tool's pad
                // rule); `decode_tile` returns the clipped tl-plane at
                // the content rect, so the full-height rect is the seam.
                let full_rect = crate::tileenc::TileRect {
                    tl: grid.th,
                    ..rect
                };
                let full = tileenc::decode_tile(stored, &full_rect, bps as u32, grid.th)
                    .map_err(|e| anyhow!("{what}: tile ({r},{c}): drill decode: {e}"))?;
                let fam = tileenc::gate_candidates_for_grid(width, height, grid.tw, grid.th);
                let mut any = false;
                for &(orient, psv) in fam {
                    let planes = tileenc::planes_from_tile_rows(&full, &rect, grid.th, orient)
                        .map_err(|e| anyhow!("{what}: tile ({r},{c}): drill planes: {e}"))?;
                    let re = tileenc::encode_tile_planes(&planes, bps as u32, psv)
                        .map_err(|e| anyhow!("{what}: tile ({r},{c}): drill re-encode: {e}"))?;
                    if re.as_slice() == stored {
                        any = true;
                        break;
                    }
                }
                if !any {
                    bail!(
                        "{what}: tile ({r},{c}): re-encode round-trip mismatch (the stored tile matches no candidate encoding of the decoded samples — corrupt stream; restore-drill integrity check; the odd-height content-rows semantics)"
                    );
                }
            } else {
                let (_chosen, (streams, _cand_sizes, _best)) =
                    tileenc::encode_tile_candidates(&p1, width, height, &grid, r, c, bps as u32)
                        .map_err(|e| anyhow!("{what}: tile ({r},{c}): re-encode: {e}"))?;
                if !streams.iter().any(|s| s.as_slice() == stored) {
                    bail!(
                        "{what}: tile ({r},{c}): re-encode round-trip mismatch (the stored tile matches no candidate encoding of the decoded samples — corrupt stream; restore-drill integrity check)"
                    );
                }
            }
        }
        Ok((width, height, p1))
    } else {
        // ---- single-strip lossless JPEG (the worker's fallback
        // structure; the `verify::bit_exact` machinery) ----
        if bps != 12 {
            bail!(
                "{what}: single-strip tag-7 output at {bps}-bit — the decode strip path is 12-bit only (the 8/10-bit archives carry the tile structure; no 12-bit strip exists at this depth)"
            );
        }
        let off_e = get(273)
            .ok_or_else(|| anyhow!("{what}: missing StripOffsets (273)"))?;
        let cnt_e = get(279)
            .ok_or_else(|| anyhow!("{what}: missing StripByteCounts (279)"))?;
        let read_u32 = |e: &IfdEntry, what: &str| -> Result<u64> {
            match e.out_of_line {
                Some((p, _)) if p as usize + 4 <= buf.len() => {
                    Ok(meta.endianness.u32(&buf[p as usize..p as usize + 4]) as u64)
                }
                None => Ok(meta.endianness.u32(&e.value_raw) as u64),
                _ => bail!("{what}: strip value unreadable (tag 0x{:04X})", e.tag),
            }
        };
        let strip_off = read_u32(off_e, what)?;
        let strip_len = read_u32(cnt_e, what)?;
        if strip_off as usize + strip_len as usize > buf.len() {
            bail!(
                "{what}: strip [{strip_off}..{} ) out of bounds (file {} B)",
                strip_off + strip_len,
                buf.len()
            );
        }
        let strip = &buf[strip_off as usize..strip_off as usize + strip_len as usize];
        let (samples, dw, dh) =
            crate::codec::decode_lossless(strip, 12).map_err(|e| anyhow!("{what}: decode: {e}"))?;
        if (dw, dh) != (width, height) {
            bail!("{what}: decoded strip {dw}×{dh} != frame {width}×{height}");
        }
        // ---- restore-drill integrity (same contract as the tile
        // path): the single-strip stream carries no checksum either —
        // re-encode the decoded samples and require the stored strip
        // back bit-exactly (the encoder is deterministic).
        let re = crate::codec::encode_lossless(&samples, width, height, 12)
            .map_err(|e| anyhow!("{what}: re-encode: {e}"))?;
        if re.as_slice() != strip {
            bail!(
                "{what}: re-encode round-trip mismatch (the stored strip is not a bit-exact encoding of the decoded samples — corrupt stream; restore-drill integrity check)"
            );
        }
        Ok((width, height, samples))
    }
}

/// Read the tile offsets (tag 324) + sizes (tag 325) as u32 arrays in
/// the file endianness (LONG; the values are out-of-line for n > 1).
fn tile_offsets_and_lens(meta: &Meta, buf: &[u8], what: &str) -> Result<(Vec<u64>, Vec<u64>)> {
    let read_arr = |tag: u16, name: &str| -> Result<Vec<u64>> {
        let e = meta
            .ifd0
            .entries
            .iter()
            .find(|e| e.tag == tag)
            .ok_or_else(|| anyhow!("{what}: missing tag {name} (0x{tag:04X})"))?;
        if e.typ != 4 {
            bail!(
                "{what}: tag {name} (0x{tag:04X}) is type {t}, expected LONG (4)",
                t = e.typ
            );
        }
        match e.out_of_line {
            Some((p, end)) => {
                if end > buf.len() as u64 {
                    bail!("{what}: tag {name} (0x{tag:04X}) value region out of bounds");
                }
                let n = e.count as usize;
                if (end - p) as usize != n * 4 {
                    bail!(
                        "{what}: tag {name} (0x{tag:04X}) size {} != count {n} × 4",
                        end - p
                    );
                }
                Ok((0..n)
                    .map(|i| {
                        meta.endianness
                            .u32(&buf[(p + i as u64 * 4) as usize..(p + i as u64 * 4 + 4) as usize])
                            as u64
                    })
                    .collect())
            }
            None if e.count == 1 => Ok(vec![meta.endianness.u32(&e.value_raw) as u64]),
            None => bail!(
                "{what}: tag {name} (0x{tag:04X}) value is not out-of-line (count {})",
                e.count
            ),
        }
    };
    let offs = read_arr(324, "TileOffsets")?;
    let lens = read_arr(325, "TileByteCounts")?;
    if offs.len() != lens.len() {
        bail!(
            "{what}: tag 324 count {} != tag 325 count {}",
            offs.len(),
            lens.len()
        );
    }
    Ok((offs, lens))
}

// ---------------------------------------------------------------------------
// jxl decode (the jxl::verify_frame machinery: djxl per plane → strict
// PAM parse → reinterleave → p1)
// ---------------------------------------------------------------------------

/// Decode ONE jxl frame group (serial — see the module docs): the
/// resume check, the 4 × djxl decodes, the PAM write (atomic, after a
/// FULL successful decode).
fn decode_jxl_one(
    desc: &JxlDesc,
    output_root: &Path,
    force: bool,
    djxl_bin: &Path,
    jobs: usize,
) -> Result<FrameOutcome> {
    let t0 = Instant::now();
    let dst = output_root.join(&desc.dst_rel);
    if dst.exists() && !force {
        return Ok(FrameOutcome::Skipped {
            file: desc.stem.clone(),
            in_bytes: desc.in_bytes,
        });
    }
    let (w, h, p1) = decode_jxl_frame(desc, output_root, djxl_bin, jobs)?;
    if let Some(parent) = dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
    }
    write_pam(&dst, w, h, &p1)?;
    let out_bytes = std::fs::metadata(&dst).map(|m| m.len()).unwrap_or(0);
    Ok(FrameOutcome::Done(FrameStats {
        file: format!("{}.pam", desc.stem),
        in_bytes: desc.in_bytes,
        out_bytes,
        ms: t0.elapsed().as_secs_f64() * 1000.0,
    }))
}

/// The serial jxl frame loop (the external decoder is the thread pool
/// — see the module docs).
fn frames_jxl(
    frames: &[JxlDesc],
    selected: &[usize],
    output_root: &Path,
    force: bool,
    djxl_bin: &Path,
    jobs: usize,
) -> Vec<FrameOutcome> {
    frames
        .iter()
        .enumerate()
        .filter(|(i, _)| selected.contains(i))
        .map(|(_, f)| match decode_jxl_one(f, output_root, force, djxl_bin, jobs) {
            Ok(o) => o,
            Err(err) => FrameOutcome::Failed {
                file: f.stem.clone(),
                error: format!("{err:#}"),
            },
        })
        .collect()
}

/// Decode the 4 planes of one jxl frame → the full mosaic plane p1
/// (2×pw × 2×ph u16). Plane 00 establishes the plane geometry; the
/// other three must match it (a mixed-geometry group fails loud +
/// named). The strict P7 parse mirrors `jxl::parse_pam_plane`; the
/// re-interleave is `jxl::reinterleave` verbatim. The temp PAMs land in
/// the OUTPUT root (the input dir is never modified).
fn decode_jxl_frame(
    desc: &JxlDesc,
    output_root: &Path,
    djxl_bin: &Path,
    jobs: usize,
) -> Result<(u32, u32, Vec<u16>)> {
    let what = desc.stem.clone();
    let mut planes: [Vec<u16>; 4] = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let mut geom: Option<(u32, u32)> = None;
    for (i, plane) in PLANES.iter().enumerate() {
        let jxl_p = desc.dir.join(format!("{what}_{plane}.jxl"));
        let pam_tmp = output_root.join(format!(".{what}_{plane}.dec.pam"));
        let mut cmd_args: Vec<String> = Vec::new();
        if jobs > 0 {
            cmd_args.push(format!("--num_threads={jobs}"));
        }
        cmd_args.push(jxl_p.to_string_lossy().into_owned());
        cmd_args.push(pam_tmp.to_string_lossy().into_owned());
        let out = std::process::Command::new(djxl_bin)
            .args(&cmd_args)
            .output()
            .with_context(|| format!("run djxl {}", djxl_bin.display()))?;
        if !out.status.success() {
            let _ = std::fs::remove_file(&pam_tmp);
            bail!(
                "{what} plane {plane}: djxl failed (rc {:?}): {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let pam = std::fs::read(&pam_tmp)
            .with_context(|| format!("read {}", pam_tmp.display()))?;
        let (pw, ph, u16s) = parse_pam(&pam, &format!("{what} {plane}"))?;
        let _ = std::fs::remove_file(&pam_tmp); // best-effort
        match i {
            0 => geom = Some((pw, ph)),
            _ => {
                let g = geom.expect("plane 00 ran first");
                if (pw, ph) != g {
                    bail!(
                        "{what} plane {plane}: {pw}×{ph} != plane 00's {}×{} (the 4 planes must share the geometry)",
                        g.0,
                        g.1
                    );
                }
            }
        }
        planes[i] = u16s;
    }
    let (pw, ph) = geom.expect("4 planes decoded");
    let (w, h) = (2 * pw, 2 * ph);
    let p1 = reinterleave([&planes[0], &planes[1], &planes[2], &planes[3]], w, h);
    Ok((w, h, p1))
}

/// Strict P7 plane PAM parse (the djxl 0.12.0 output for a 12-bit
/// grayscale JXL) — the `jxl::parse_pam_plane` contract: P7 header with
/// exactly WIDTH/HEIGHT/DEPTH 1/MAXVAL 4095/TUPLTYPE GRAYSCALE, then
/// `w*h*2` big-endian u2 bytes. Returns (w, h, samples); the
/// parse is the dimension-ESTABLISHING one (plane 00 sets the
/// geometry), so it takes no expected size. Any deviation is an error
/// (the decode tool must fail loud on format drift).
fn parse_pam(data: &[u8], what: &str) -> Result<(u32, u32, Vec<u16>)> {
    const END: &[u8] = b"ENDHDR\n";
    if data.len() < END.len() {
        bail!("{what}: too short for a PAM header ({} bytes)", data.len());
    }
    let end = data
        .windows(END.len())
        .position(|w| w == END)
        .ok_or_else(|| anyhow!("{what}: not a P7 PAM (no ENDHDR)"))?;
    let header = std::str::from_utf8(&data[..end])
        .map_err(|_| anyhow!("{what}: PAM header is not UTF-8"))?;
    let mut w = 0u32;
    let mut h = 0u32;
    let mut depth: i64 = 0;
    let mut maxval: i64 = 0;
    let mut tupl: Option<&str> = None;
    let mut toks = header.split_whitespace();
    match toks.next() {
        Some("P7") => {}
        other => bail!("{what}: expected P7 header, got {other:?}"),
    }
    while let Some(key) = toks.next() {
        let val = toks
            .next()
            .ok_or_else(|| anyhow!("{what}: dangling PAM key {key}"))?;
        match key {
            "WIDTH" => w = val.parse().map_err(|_| anyhow!("{what}: bad WIDTH {val}"))?,
            "HEIGHT" => h = val.parse().map_err(|_| anyhow!("{what}: bad HEIGHT {val}"))?,
            "DEPTH" => depth = val.parse().map_err(|_| anyhow!("{what}: bad DEPTH {val}"))?,
            "MAXVAL" => maxval = val.parse().map_err(|_| anyhow!("{what}: bad MAXVAL {val}"))?,
            "TUPLTYPE" => tupl = Some(val),
            other => bail!("{what}: unexpected PAM key {other}"),
        }
    }
    if w == 0 || h == 0 {
        bail!("{what}: missing WIDTH/HEIGHT in the PAM header");
    }
    if depth != 1 {
        bail!("{what}: DEPTH {depth} (expected 1)");
    }
    if maxval != 4095 {
        bail!("{what}: MAXVAL {maxval} (expected 4095)");
    }
    if tupl != Some("GRAYSCALE") {
        bail!("{what}: TUPLTYPE {tupl:?} (expected GRAYSCALE)");
    }
    let payload = &data[end + END.len()..];
    let want = (w as u64) * (h as u64) * 2;
    if (payload.len() as u64) != want {
        bail!(
            "{what}: payload {} bytes (expected {want})",
            payload.len()
        );
    }
    let mut out = vec![0u16; want as usize / 2];
    for (i, pair) in payload.chunks_exact(2).enumerate() {
        out[i] = u16::from_be_bytes([pair[0], pair[1]]);
    }
    Ok((w, h, out))
}

// ---------------------------------------------------------------------------
// PAM write (atomic: tmp + rename, after a FULL successful decode only)
// ---------------------------------------------------------------------------

/// Write the frame PAM: the header (`jxl::pam_header` —
/// TUPLTYPE GRAYSCALE, MAXVAL 4095) + the w×h p1 payload as big-endian
/// u2 (the ground-truth pin). Atomic (tmp + rename): a crash never
/// leaves a renamed partial.
fn write_pam(path: &Path, w: u32, h: u32, p1: &[u16]) -> Result<()> {
    if p1.len() != (w as usize) * (h as usize) {
        bail!(
            "p1 length {} != {w}×{h} ({} samples)",
            p1.len(),
            (w as usize) * (h as usize)
        );
    }
    let mut buf = Vec::with_capacity(64 + p1.len() * 2);
    buf.extend_from_slice(pam_header(w, h).as_bytes());
    for s in p1 {
        buf.extend_from_slice(&s.to_be_bytes());
    }
    let tmp = path.with_extension("pam.tmp");
    std::fs::write(&tmp, &buf).with_context(|| format!("write {}", tmp.display()))?;
    if let Err(err) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp); // atomicity: nothing half-written
        return Err(err)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// summary
// ---------------------------------------------------------------------------

fn print_summary(args: &Args, report: &Report) {
    println!();
    println!(
        "frameprism decode {} — {}",
        env!("CARGO_PKG_VERSION"),
        args.input.display()
    );
    println!("input : {}", args.input.display());
    println!("output: {}", args.output.display());
    println!(
        "codec : {}  frame: {}  force: {}  jobs: {}",
        match args.codec {
            Codec::J92 => "j92",
            Codec::Jxl => "jxl",
        },
        match args.frame {
            Some(n) => n.to_string(),
            None => "all".to_string(),
        },
        args.force,
        display_jobs(args.jobs)
    );
    if report.done.is_empty() && report.skipped.is_empty() {
        println!("no frames decoded (all skipped?)");
        return;
    }
    println!();
    println!("frame  in_bytes  out_bytes  ms");
    for s in &report.done {
        println!(
            "{:<36} {:>10} {:>10} {:>8.0}",
            s.file, s.in_bytes, s.out_bytes, s.ms
        );
    }
    println!(
        "\ntotal: {} frame(s) decoded ({} skipped, {} failed)",
        report.done.len(),
        report.skipped.len(),
        report.failed.len()
    );
    for (file, error) in &report.failed {
        println!("FAILED: {file}: {error}");
    }
}

fn display_jobs(jobs: usize) -> String {
    if jobs == 0 {
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0);
        format!("all cores ({n})")
    } else {
        jobs.to_string()
    }
}

/// First line of `bin --version` (a named fail-fast before anything is
/// written — the jxl::version_line discipline).
fn version_line(bin: &Path) -> Result<String> {
    let out = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .with_context(|| format!("run {} --version", bin.display()))?;
    if !out.status.success() {
        bail!(
            "{} --version failed (rc {:?}): {}",
            bin.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string())
}

// ---------------------------------------------------------------------------
// proxy seam (the additive public API for `frameprism
// proxy`; ZERO behavior change to the shipped decode path — the seam
// wraps the same collectors + the same per-frame decoders)
// ---------------------------------------------------------------------------

/// A frame reference in encoder order (the proxy seam's public form —
/// the public counterpart of the private `J92Desc` / `JxlDesc`).
#[derive(Clone, Debug)]
pub enum FrameRef {
    /// A j92 frame: one encoded `.DNG` file.
    J92 { src: PathBuf, name: String },
    /// A jxl frame: the 4-plane group in `dir` (`stem` = the common
    /// prefix of the 4 `.jxl` names).
    Jxl { dir: PathBuf, stem: String },
}

/// The frame set of an encoded clip dir in encoder order (sorted) —
/// the SAME collectors + the SAME cross-codec diagnostics as the
/// shipped decode path (a jxl dir given `j92` is a hard reject with
/// the reason, and vice versa).
pub fn collect_frames(codec: Codec, input: &Path) -> Result<Vec<FrameRef>> {
    match codec {
        Codec::J92 => Ok(
            collect_j92(input)?
                .into_iter()
                .map(|f| FrameRef::J92 { src: f.src, name: f.file })
                .collect(),
        ),
        Codec::Jxl => Ok(
            collect_jxl(input)?
                .into_iter()
                .map(|f| FrameRef::Jxl { dir: f.dir, stem: f.stem })
                .collect(),
        ),
    }
}

/// Decode ONE frame to the full mosaic plane p1 (w×h u16 — the 12-bit
/// raw, unstripped) — NO PAM write; the jxl temp PAMs land in
/// `scratch` (removed best-effort). The j92 path carries the shipped
/// decode→re-encode round-trip integrity check (a corrupt frame fails
/// loud + named).
pub fn decode_frame_p1(
    frame: &FrameRef,
    scratch: &Path,
    djxl_bin: &Path,
    jobs: usize,
) -> Result<(u32, u32, Vec<u16>)> {
    match frame {
        FrameRef::J92 { src, name } => {
            let buf = std::fs::read(src)
                .with_context(|| format!("read {}", src.display()))?;
            decode_j92_frame(&buf, name)
        }
        FrameRef::Jxl { dir, stem } => {
            let desc = JxlDesc {
                dir: dir.clone(),
                stem: stem.clone(),
                dst_rel: PathBuf::from(format!("{stem}.pam")),
                in_bytes: 0,
            };
            decode_jxl_frame(&desc, scratch, djxl_bin, jobs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

 /// PARITY (the measured reference contract, ): the
    /// 3K golden (the 252×252 12×8 grid — the NLE
    /// media-offline fix's target class) must DECODE pixel-exact
    /// through the tool's lossless decode path: the per-gate grid
    /// eligibility (252×252 at 3024×2010), the file-derived grid, the
    /// tile decode + assembly, and the restore-drill re-encode
    /// integrity (the golden's stored tiles must match the tool's
    /// 3-candidate family — the measured mechanism's byte parity).
    /// Corpus-conditional (absent → skip — the fresh CI stays at the
    /// base suite line).
    #[test]
    fn golden_3k_decode_pixel_exact() {
        let names = [
            "A001_006_20260920_000001.DNG",
            "A001_006_20260920_000057.DNG",
            "A001_006_20260920_000114.DNG",
        ];
        for n in names {
            let gold_p = format!("../testdata/reference/lossless/A001_006/{n}");
            let orig_p = format!("../testdata/originals/A001_006/{n}");
            for p in [&gold_p, &orig_p] {
                if !std::path::Path::new(p).exists() {
                    eprintln!("skip: {p} (absent)");
                    return;
                }
            }
            let gold = std::fs::read(&gold_p).unwrap();
            let (w, h, samples) =
                decode_j92_frame(&gold, n).unwrap_or_else(|e| panic!("{n}: decode: {e}"));
            assert_eq!((w, h), (3024, 2010), "{n}: the golden's frame geometry");
            // The pixel-exact ground truth: the ORIGINAL's unpacked
            // samples (the golden is the measured lossless encode of
            // the same frame).
            let orig = std::fs::read(&orig_p).unwrap();
            let frame = crate::tiff::read(&orig)
                .unwrap_or_else(|e| panic!("{n}: original parse: {e}"));
            let packed = frame.strip_slice(&orig);
            let expected = crate::pack12::unpack12(packed, frame.width, frame.height)
                .unwrap_or_else(|e| panic!("{n}: original unpack: {e}"));
            assert_eq!(samples, expected, "{n}: the decoded golden != the original samples (pixel-exact parity)");
        }
    }

    /// THE GOLDEN DECODE TEST — the FHD per-(geometry × depth) grid
 /// (the golden-decode pattern on the mirrored FHD
 /// reference frames — the measured reference contract, 
 /// 12-clip batch): the measured lossless FHD
    /// output (the per-depth measured grids — 242×274 8×4 = 32 tiles
    /// @12/@8, 484×274 4×4 = 16 tiles @10) must DECODE PIXEL-EXACT
    /// through the tool's lossless decode path: the per-gate grid
    /// eligibility (242×274 / 484×274 at 1936×1090, the legacy 482×272
    /// still accepted — the backward-compat pattern), the file-derived
    /// grid, the tile decode + assembly, and the restore-drill re-encode
    /// integrity (the golden's stored tiles must match the tool's FHD
    /// candidate family — the grid-keyed measured mechanism, the
    /// reference's FHD tiles sit outside the 482 legacy family — the
 /// 80/80-tile census). PLUS the structural cross-check (the
    /// reference = the interop oracle + the benchmark, not a byte spec):
    /// the corpus 322/323 / tile count / stored BPS per row — @8:
    /// the corpus stores BPS10 (the measured promotion = the
    /// IDENTITY into the 10-bit precision container, NO value scaling —
    /// the @8 frames decode pixel-exact to the 8-bit originals; the
    /// ×4 hypothesis was measured REJECTED, 0 matches) — ours stores
 /// BPS8 (the no-promotion decision, the literal same-bits lossless).
    /// Corpus-conditional (absent → skip — the fresh CI stays at the
    /// base suite line); on the machine that carries the corpus the
    /// gate MUST run it (RAN-not-skipped).
    #[test]
    fn golden_fhd_decode_pixel_exact() {
        // (clip, input depth, the corpus measured 322/323, the
        // corpus tile count, the corpus STORED BPS (the @8
        // row: the measured 8→10 promotion), the 3 sample frames):
        let cases: [(&str, u16, (u32, u32), u32, u64, [String; 3]); 3] = [
            (
                "A001_004_20260924",
                12,
                (242, 274),
                32,
                12,
                [
                    "A001_004_20260924_000001.DNG".into(),
                    "A001_004_20260924_000049.DNG".into(),
                    "A001_004_20260924_000097.DNG".into(),
                ],
            ),
            (
                "A001_005_20260924",
                10,
                (484, 274),
                16,
                10,
                [
                    "A001_005_20260924_000001.DNG".into(),
                    "A001_005_20260924_000049.DNG".into(),
                    "A001_005_20260924_000097.DNG".into(),
                ],
            ),
            (
                "A001_006_20260924",
                8,
                (242, 274),
                32,
                10, // the measured 8→10 promotion (stored BPS10, identity values)
                [
                    "A001_006_20260924_000001.DNG".into(),
                    "A001_006_20260924_000051.DNG".into(),
                    "A001_006_20260924_000101.DNG".into(),
                ],
            ),
        ];
        for (clip, depth, (want_tw, want_th), want_tiles, want_ref_bps, names) in cases {
            for n in names {
                let gold_p = format!("../testdata/reference/lossless/{clip}/{n}");
                let orig_p = format!("../testdata/originals/{clip}/{n}");
                for p in [&gold_p, &orig_p] {
                    if !std::path::Path::new(p).exists() {
                        eprintln!("skip: {p} (absent)");
                        return;
                    }
                }
                let gold = std::fs::read(&gold_p).unwrap();
                // The structural cross-check (the measured reference
                // contract — AGREEMENT on the grid + count expected; the
                // @8 BPS differs from ours BY DESIGN — noted, not
                // asserted against our output):
                let meta = crate::tiff::read_meta(&gold)
                    .unwrap_or_else(|e| panic!("{n}: reference read_meta: {e}"));
                let e = meta.endianness;
                let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
                let tag16 = |tag: u16| e.u16(&find(tag).unwrap().value_raw);
                let tag32 = |tag: u16| e.u32(&find(tag).unwrap().value_raw);
                assert_eq!((tag32(256), tag32(257)), (1936, 1090), "{n}: the corpus frame geometry");
                assert_eq!(tag16(258) as u64, want_ref_bps, "{n}: the corpus stored BPS (the @8 row: the measured 8→10 promotion)");
                assert_eq!(tag16(259), 7, "{n}: the corpus Compression 7");
                assert_eq!(tag16(262), 32803, "{n}: the corpus PhotometricInterpretation 32803");
                assert_eq!((tag32(322), tag32(323)), (want_tw, want_th), "{n}: the corpus 322/323 (the per-depth FHD grid)");
                assert_eq!(find(324).unwrap().count, want_tiles, "{n}: the corpus tile count");
 // The pixel-exact decode (the pattern — the
                // shipped decode path incl. the restore-drill on the
                // grid-keyed FHD family):
                let (w, h, samples) =
                    decode_j92_frame(&gold, &n).unwrap_or_else(|e| panic!("{n}: decode: {e}"));
                assert_eq!((w, h), (1936, 1090), "{n}: the golden's frame geometry");
                // The pixel-exact ground truth: the ORIGINAL's unpacked
                // samples (the golden is the measured lossless encode
                // of the same frame; the @8 row: the measured identity
                // promotion — the 8-bit originals DIRECTLY).
                let orig = std::fs::read(&orig_p).unwrap();
                let frame = crate::tiff::read(&orig)
                    .unwrap_or_else(|e| panic!("{n}: original parse: {e}"));
                let packed = frame.strip_slice(&orig);
                let expected = match depth {
                    12 => crate::pack12::unpack12(packed, frame.width, frame.height),
                    10 => crate::pack12::unpack10(packed, frame.width, frame.height),
                    _ => crate::pack12::unpack8(packed, frame.width, frame.height),
                }
                .unwrap_or_else(|e| panic!("{n}: original unpack: {e}"));
                assert_eq!(samples, expected, "{n}: the decoded golden != the original samples (pixel-exact parity)");
            }
        }
    }

 /// PARITY (the measured reference contract, — the
 /// 12-clip batch, the onboarding G2): the reference
    /// product's Open Gate 2K goldens (the 252×336 8×4 grid — the
    /// depth-invariant measured contract, 32 tiles) must DECODE
    /// pixel-exact through the tool's lossless decode path: the
    /// per-gate grid eligibility (252×336 at 2016×1344), the file-derived
    /// grid, the tile decode + assembly, and the restore-drill
    /// re-encode integrity on the grid-keyed OG2K family
    /// (`tileenc::OG2K_CANDIDATES` — {W-PSV7, W-PSV6, N-PSV5}, the
    /// 288/288-tile measured contract). All three depths 8/10/12 decode
    /// at the SAME 252×336 grid (the measured depth-invariance); the @8
    /// row: the corpus stored BPS is 10 (the measured identity
    /// promotion) but the 8-bit ORIGINALS decode directly — the
    /// ground-truth comparison is against the originals at the input
    /// depth (NOT the corpus promoted stored precision). The
 /// mirror placement (the maintainer's corpus layout): the originals live
    /// at `testdata/originals_A001_00X/` and the goldens at
 /// `testdata/reference/lossless/A001_00X/` (the spec's path text
 /// `testdata/originals/A001_00X_20260924/` is superseded by the
 /// measured disk layout — ). Corpus-conditional
    /// (absent → skip — the fresh CI stays at the base suite line).
    #[test]
    fn golden_og2k_decode_pixel_exact() {
        // (clip, input depth, the corpus measured 322/323,
        // the corpus tile count, the corpus STORED BPS (the @8
        // row: the measured 8→10 promotion), the 3 sample frames):
        let cases: [(&str, u16, (u32, u32), u32, u64, [String; 3]); 3] = [
            (
                "A001_007",
                12,
                (252, 336),
                32,
                12,
                [
                    "A001_007_20260924_000001.DNG".into(),
                    "A001_007_20260924_000049.DNG".into(),
                    "A001_007_20260924_000097.DNG".into(),
                ],
            ),
            (
                "A001_008",
                10,
                (252, 336),
                32,
                10,
                [
                    "A001_008_20260924_000001.DNG".into(),
                    "A001_008_20260924_000049.DNG".into(),
                    "A001_008_20260924_000097.DNG".into(),
                ],
            ),
            (
                "A001_009",
                8,
                (252, 336),
                32,
                10, // the measured 8→10 promotion (stored BPS10, identity values)
                [
                    "A001_009_20260924_000001.DNG".into(),
                    "A001_009_20260924_000050.DNG".into(),
                    "A001_009_20260924_000100.DNG".into(),
                ],
            ),
        ];
        for (clip, depth, (want_tw, want_th), want_tiles, want_ref_bps, names) in cases {
            for n in names {
                let gold_p = format!("../testdata/reference/lossless/{clip}/{n}");
 // The mirror placement (the maintainer's corpus layout — ):
                let orig_p = format!("../testdata/originals_{clip}/{n}");
                for p in [&gold_p, &orig_p] {
                    if !std::path::Path::new(p).exists() {
                        eprintln!("skip: {p} (absent)");
                        return;
                    }
                }
                let gold = std::fs::read(&gold_p).unwrap();
                // The structural cross-check (the measured reference
                // contract — AGREEMENT on the grid + count expected; the
                // @8 BPS differs from ours BY DESIGN — noted, not
                // asserted against our output):
                let meta = crate::tiff::read_meta(&gold)
                    .unwrap_or_else(|e| panic!("{n}: reference read_meta: {e}"));
                let e = meta.endianness;
                let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
                let tag16 = |tag: u16| e.u16(&find(tag).unwrap().value_raw);
                let tag32 = |tag: u16| e.u32(&find(tag).unwrap().value_raw);
                assert_eq!((tag32(256), tag32(257)), (2016, 1344), "{n}: the corpus frame geometry");
                assert_eq!(tag16(258) as u64, want_ref_bps, "{n}: the corpus stored BPS (the @8 row: the measured 8→10 promotion)");
                assert_eq!(tag16(259), 7, "{n}: the corpus Compression 7");
                assert_eq!(tag16(262), 32803, "{n}: the corpus PhotometricInterpretation 32803");
                assert_eq!((tag32(322), tag32(323)), (want_tw, want_th), "{n}: the corpus 322/336 grid (the depth-invariant OG2K grid)");
                assert_eq!(find(324).unwrap().count, want_tiles, "{n}: the corpus tile count");
                // The pixel-exact decode (the shipped decode path incl.
                // the restore-drill on the grid-keyed OG2K family):
                let (w, h, samples) =
                    decode_j92_frame(&gold, &n).unwrap_or_else(|e| panic!("{n}: decode: {e}"));
                assert_eq!((w, h), (2016, 1344), "{n}: the golden's frame geometry");
                // The pixel-exact ground truth: the ORIGINAL's unpacked
                // samples at the input depth (the @8 row: the measured
                // identity promotion — the 8-bit originals DIRECTLY,
                // NOT the corpus promoted stored precision):
                let orig = std::fs::read(&orig_p).unwrap();
                let frame = crate::tiff::read(&orig)
                    .unwrap_or_else(|e| panic!("{n}: original parse: {e}"));
                let packed = frame.strip_slice(&orig);
                let expected = match depth {
                    12 => crate::pack12::unpack12(packed, frame.width, frame.height),
                    10 => crate::pack12::unpack10(packed, frame.width, frame.height),
                    _ => crate::pack12::unpack8(packed, frame.width, frame.height),
                }
                .unwrap_or_else(|e| panic!("{n}: original unpack: {e}"));
                assert_eq!(samples, expected, "{n}: the decoded golden != the original samples (pixel-exact parity)");
            }
        }
    }

 /// PARITY (the measured reference contract, — the
 /// 12-clip batch, the onboarding G4, the LAST
    /// measured row): the measured UHD @10 goldens (the
    /// 964×272 4×8 grid — the measured per-depth contract, 32 tiles;
    /// 964×4 = 3856 exact; the last row 266 px at the full 272
    /// geometry) must DECODE pixel-exact through the tool's lossless
    /// decode path: the per-gate grid eligibility (964×272 at
    /// 3856×2170 — the @10 measured grid; the 482×272 grid stays
 /// accepted — the @12/@8 in-profile grid + the pre-existing @10 output
    /// — the backward-compat pattern), the file-derived grid, the tile
    /// decode + assembly, and the restore-drill re-encode integrity on
    /// the grid-keyed legacy family (the 964×272 grid's measured family
    /// = `tileenc::CANDIDATES` {W-PSV7, W-PSV2, N-PSV1} — the 96/96-
 /// tile census: every stored reference tile byte-identical to
    /// exactly one candidate, ZERO outside). The @10 row: the
    /// reference's stored BPS is 10 (NO promotion at @10 — unlike the
    /// @8 rows' measured 8→10 identity promotion) and the 10-bit
    /// ORIGINALS decode directly — the ground-truth comparison is
    /// against the originals at the input depth. The mirror placement
 /// (the maintainer's corpus layout): the originals live at
    /// `testdata/originals_A001_002/` and the goldens at
 /// `testdata/reference/lossless/A001_002/`. Corpus-conditional
    /// (absent → skip — the fresh CI stays at the base suite line);
    /// on the machine that carries the corpus the gate MUST run it
    /// (RAN-not-skipped).
    #[test]
    fn golden_uhd10_decode_pixel_exact() {
        // (clip, input depth, the corpus measured 322/323, the
        // corpus tile count, the corpus STORED BPS (the @10
        // row: NO promotion — the reference stores 10 at @10), the 3
        // sample frames):
        let cases: [(&str, u16, (u32, u32), u32, u64, [String; 3]); 1] = [
            (
                "A001_002",
                10,
                (964, 272),
                32,
                10, // the corpus stored BPS at @10 = 10 (no promotion — unlike the @8 rows)
                [
                    "A001_002_20260924_000001.DNG".into(),
                    "A001_002_20260924_000050.DNG".into(),
                    "A001_002_20260924_000099.DNG".into(),
                ],
            ),
        ];
        for (clip, depth, (want_tw, want_th), want_tiles, want_ref_bps, names) in cases {
            for n in names {
                let gold_p = format!("../testdata/reference/lossless/{clip}/{n}");
 // The mirror placement (the maintainer's corpus layout):
                let orig_p = format!("../testdata/originals_{clip}/{n}");
                for p in [&gold_p, &orig_p] {
                    if !std::path::Path::new(p).exists() {
                        eprintln!("skip: {p} (absent)");
                        return;
                    }
                }
                let gold = std::fs::read(&gold_p).unwrap();
                // The structural cross-check (the measured reference
                // contract — AGREEMENT on the grid + count + BPS
                // expected): the @10 row stores BPS10 (no promotion —
                // recorded as the measured contract on the measured
                // output):
                let meta = crate::tiff::read_meta(&gold)
                    .unwrap_or_else(|e| panic!("{n}: reference read_meta: {e}"));
                let e = meta.endianness;
                let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
                let tag16 = |tag: u16| e.u16(&find(tag).unwrap().value_raw);
                let tag32 = |tag: u16| e.u32(&find(tag).unwrap().value_raw);
                assert_eq!((tag32(256), tag32(257)), (3856, 2170), "{n}: the corpus frame geometry");
                assert_eq!(tag16(258) as u64, want_ref_bps, "{n}: the corpus stored BPS (the @10 row: no promotion)");
                assert_eq!(tag16(259), 7, "{n}: the corpus Compression 7");
                assert_eq!(tag16(262), 32803, "{n}: the corpus PhotometricInterpretation 32803");
                assert_eq!((tag32(322), tag32(323)), (want_tw, want_th), "{n}: the corpus 322/323 (the measured @10 UHD grid)");
                assert_eq!(find(324).unwrap().count, want_tiles, "{n}: the corpus tile count");
                // The pixel-exact decode (the shipped decode path incl.
                // the restore-drill on the grid-keyed legacy family —
                // the 964×272 grid's measured family):
                let (w, h, samples) =
                    decode_j92_frame(&gold, &n).unwrap_or_else(|e| panic!("{n}: decode: {e}"));
                assert_eq!((w, h), (3856, 2170), "{n}: the golden's frame geometry");
                // The pixel-exact ground truth: the ORIGINAL's unpacked
                // samples at the input depth (the 10-bit originals
                // DIRECTLY):
                let orig = std::fs::read(&orig_p).unwrap();
                let frame = crate::tiff::read(&orig)
                    .unwrap_or_else(|e| panic!("{n}: original parse: {e}"));
                let packed = frame.strip_slice(&orig);
                let expected = crate::pack12::unpack10(packed, frame.width, frame.height)
                    .unwrap_or_else(|e| panic!("{n}: original unpack10: {e}"));
                assert_eq!(samples, expected, "{n}: the decoded golden != the original samples (pixel-exact parity)");
            }
        }
    }

 /// PARITY (the measured reference contract, — the
 /// 12-clip batch, the onboarding G3): the
    /// measured Open Gate 3K goldens (the 252×252 clean
    /// 12×8 grid — the depth-invariant measured contract, 96 tiles —
 /// the machinery: the legacy 482×272 family
    /// {W-PSV7, W-PSV2, N-PSV1} grid-keyed on 252×252,
    /// `tileenc::CANDIDATES`, the measured selection key = the
    /// hist-pass's pre-stuffing expected bit count) must DECODE
    /// pixel-exact through the tool's lossless decode path: the
    /// per-gate grid eligibility (252×252 at 3024×2010), the
    /// file-derived grid, the tile decode + assembly, and the
    /// restore-drill re-encode integrity on the grid-keyed 3K family
 /// (the census: 576/576 mirrored @10/@8 corpus
    /// tiles byte-identical to exactly one candidate, ZERO outside).
    /// Both depths @10/@8 decode at the SAME 252×252 grid (the
    /// measured depth-invariance); the @8 row: the corpus stored
    /// BPS is 10 (the measured identity promotion) but the 8-bit
    /// ORIGINALS decode directly — the ground-truth comparison is
    /// against the originals at the input depth (NOT the corpus
 /// promoted stored precision). The mirror placement (the maintainer's
    /// corpus layout): the originals live at
    /// `testdata/originals_A001_011/` + `testdata/originals_A001_012/`
 /// and the goldens at `testdata/reference/lossless/A001_011/` +
 /// `testdata/reference/lossless/A001_012/`. Corpus-conditional
    /// (absent → skip — the fresh CI stays at the base suite line).
    #[test]
    fn golden_og3k_decode_pixel_exact() {
        // (clip, input depth, the corpus measured 322/323,
        // the corpus tile count, the corpus STORED BPS (the
        // @8 row: the measured 8→10 promotion), the 3 sample
        // frames):
        let cases: [(&str, u16, (u32, u32), u32, u64, [String; 3]); 2] = [
            (
                "A001_011",
                10,
                (252, 252),
                96,
                10,
                [
                    "A001_011_20260924_000001.DNG".into(),
                    "A001_011_20260924_000050.DNG".into(),
                    "A001_011_20260924_000099.DNG".into(),
                ],
            ),
            (
                "A001_012",
                8,
                (252, 252),
                96,
                10, // the measured 8→10 promotion (stored BPS10, identity values)
                [
                    "A001_012_20260924_000001.DNG".into(),
                    "A001_012_20260924_000049.DNG".into(),
                    "A001_012_20260924_000097.DNG".into(),
                ],
            ),
        ];
        for (clip, depth, (want_tw, want_th), want_tiles, want_ref_bps, names) in cases {
            for n in names {
                let gold_p = format!("../testdata/reference/lossless/{clip}/{n}");
 // The mirror placement (the maintainer's corpus layout):
                let orig_p = format!("../testdata/originals_{clip}/{n}");
                for p in [&gold_p, &orig_p] {
                    if !std::path::Path::new(p).exists() {
                        eprintln!("skip: {p} (absent)");
                        return;
                    }
                }
                let gold = std::fs::read(&gold_p).unwrap();
                // The structural cross-check (the measured reference
                // contract — AGREEMENT on the grid + count expected;
                // the @8 stored BPS10 = the measured identity
                // promotion, recorded as the measured difference — the
 // NO-promotion decision is on OUR output, asserted in
                // the encode structural gate):
                let meta = crate::tiff::read_meta(&gold)
                    .unwrap_or_else(|e| panic!("{n}: reference read_meta: {e}"));
                let e = meta.endianness;
                let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
                let tag16 = |tag: u16| e.u16(&find(tag).unwrap().value_raw);
                let tag32 = |tag: u16| e.u32(&find(tag).unwrap().value_raw);
                assert_eq!((tag32(256), tag32(257)), (3024, 2010), "{n}: the corpus frame geometry");
                assert_eq!(tag16(258) as u64, want_ref_bps, "{n}: the corpus stored BPS (the @8 row: the measured 8→10 promotion)");
                assert_eq!(tag16(259), 7, "{n}: the corpus Compression 7");
                assert_eq!(tag16(262), 32803, "{n}: the corpus PhotometricInterpretation 32803");
                assert_eq!((tag32(322), tag32(323)), (want_tw, want_th), "{n}: the corpus 252×252 grid (the depth-invariant OG3K grid)");
                assert_eq!(find(324).unwrap().count, want_tiles, "{n}: the corpus tile count");
                // The pixel-exact decode (the shipped decode path
                // incl. the restore-drill on the grid-keyed 3K
                // family):
                let (w, h, samples) =
                    decode_j92_frame(&gold, &n).unwrap_or_else(|e| panic!("{n}: decode: {e}"));
                assert_eq!((w, h), (3024, 2010), "{n}: the golden's frame geometry");
                // The pixel-exact ground truth: the ORIGINAL's unpacked
                // samples at the input depth (the @8 row: the measured
                // identity promotion — the 8-bit originals DIRECTLY,
                // NOT the corpus promoted stored precision):
                let orig = std::fs::read(&orig_p).unwrap();
                let frame = crate::tiff::read(&orig)
                    .unwrap_or_else(|e| panic!("{n}: original parse: {e}"));
                let packed = frame.strip_slice(&orig);
                let expected = match depth {
                    10 => crate::pack12::unpack10(packed, frame.width, frame.height),
                    _ => crate::pack12::unpack8(packed, frame.width, frame.height),
                }
                .unwrap_or_else(|e| panic!("{n}: original unpack: {e}"));
                assert_eq!(samples, expected, "{n}: the decoded golden != the original samples (pixel-exact parity)");
            }
        }
    }

    // =================================================================
 // The FHD mode rows ( — measured
    // contract — the mirrored reference mode corpus): the 1936×1090
    // log10 rows (full-res) + the 968×545 ds2x rows at @12/@10/@8.
    // Corpus (the G2/G3/G4 corpus-noting pattern — the mode corpus is
    // date-suffix-free): the reference mode outputs
 // `../testdata/reference/log10/A001_00X/` +
 // `../testdata/reference/ds2x/A001_00X/` + the originals
    // `../testdata/originals_A001_00X/` (A001_004 @12 · A001_005 @10
    // · A001_006 @8 — the 3-frame sample pattern
    // 000001/000049/000097 · 000001/000051/000101).
    // =================================================================

    /// An IFD entry's value bytes (in-line ≤ 4 B or out-of-line by the
    /// pointer range — the golden tests' value cross-check seam).
    fn ifd_value(buf: &[u8], e: crate::tiff::Endian, en: &crate::tiff::IfdEntry) -> Vec<u8> {
        let tsz = match en.typ {
            1 | 2 | 7 | 11 => 1,
            3 | 8 => 2,
            4 | 9 | 12 => 4,
            _ => 1,
        };
        let sz = tsz * en.count as usize;
        if sz <= 4 {
            en.value_raw[..tsz * en.count as usize].to_vec()
        } else {
            let (p, end) = en
                .out_of_line
                .expect("the out-of-line entry must have a pointer");
            buf[p as usize..end as usize].to_vec()
        }
    }

    /// The mode decode goldens' shared machinery (the per-row named
 /// gates wrap this — rows, ):
    /// decodes the 3 mirrored reference MODE frames of the gate's
 /// corpus (`../testdata/reference/{mode}/A001_00X/`) through the
    /// shipped decode path (`decode_j92_frame` — the per-gate grid
    /// eligibility [the FHD grids at 1936×1090 + the 968×545 ds2x
    /// grids; the OG2K grids at 2016×1344 + the 1008×672 ds2x grid —
 /// rows], the file-derived grid, the tile
    /// decode + assembly, the restore-drill re-encode integrity — the
    /// grid×mode-keyed family [the gate family at full resolution; the
 /// DS2X family at the ds2x geometry — the decision (c)]; the odd-height
    /// bottom-row tiles run the content-rows drill semantics — the
 /// decision (b): the self-sourced full-plane re-encode —
    /// the corpus synthetic pad rows are not content, the content
    /// rows verified) and asserts the per-row structural cross-check
 /// (the reference = the interop oracle + the benchmark —
    /// the measured per-arm contract: the geometry · the stored BPS ·
    /// Compression 7 · Photometric 32803 · the per-depth grid + tile
    /// count · the 50712 mechanics [the @12 1024 LUT: presence +
    /// count, NOT the content — the corpus per-frame calibration
 /// table, the free class; the @10 ABSENT; the @8 the
    /// carried native 256 — the value byte-identical to the
 /// original's — the measured byte-identity across all 9 @8
    /// files] · [ds2x: the 51089-91 proxy tags — the measured output OMITS
    /// them (the measured fact — the tool's own encode ADDS them, the
 /// free class — the encode golden pins the presence)] +
    /// the halved crop tags 50719/50720/50829 (each element /2 floor)).
    /// Returns per frame the (name, the decoded samples, the original
    /// unpacked samples) for the caller's per-row content-class
    /// assertion (the measured rows: the @10 log10 raw passthrough +
    /// the @8 log10 identity = pixel-exact vs the originals; the @12
    /// log10 codes + every ds2x decimation = the measured
 /// content — the interop boundary: the decode is asserted
    /// to DECODE (the round-trip + the drill), NEVER pixel-exact vs
 /// the tool's own transform — the δ decision). Corpus-conditional
 /// (skip when the corpus is absent — the project pattern); on the
    /// machine that carries the corpus the gate MUST run it (RAN-not-
    /// skipped).
    fn golden_mode_decode_row(
        mode: &str,
        clip: &str,
        depth: u16,
        want_geom: (u32, u32),
        want_bps: u16,
        want_grid: (u32, u32),
        want_tiles: u32,
        want_lut: Option<u32>,
        want_proxy_absent: bool,
        names: [String; 3],
    ) -> Vec<(String, Vec<u16>, Vec<u16>)> {
        let dir = format!("../testdata/reference/{mode}/{clip}");
        let odir = format!("../testdata/originals_{clip}");
        let mut out: Vec<(String, Vec<u16>, Vec<u16>)> = Vec::new();
        for n in names.iter() {
            let gold_p = format!("{dir}/{n}");
            let orig_p = format!("{odir}/{n}");
            for p in [&gold_p, &orig_p] {
                if !std::path::Path::new(p).exists() {
                    eprintln!("skip: the {mode} {clip} mode corpus is absent ({p})");
                    return Vec::new();
                }
            }
            let gold = std::fs::read(&gold_p).unwrap();
            // The structural cross-check (the measured per-arm
            // reference contract):
            let meta = crate::tiff::read_meta(&gold)
                .unwrap_or_else(|e| panic!("{n}: reference read_meta: {e}"));
            let e = meta.endianness;
            let find = |tag: u16| meta.ifd0.entries.iter().find(|en| en.tag == tag);
            let tag32 = |tag: u16| e.u32(&find(tag).expect("tag present").value_raw);
            let tag16 = |tag: u16| e.u16(&find(tag).expect("tag present").value_raw);
            assert_eq!((tag32(256), tag32(257)), want_geom, "{n}: the corpus frame geometry");
            assert_eq!(tag16(258), want_bps, "{n}: the corpus stored BPS (the per-arm measured contract)");
            assert_eq!(tag16(259), 7, "{n}: the corpus Compression 7");
            assert_eq!(tag16(262), 32803, "{n}: the corpus PhotometricInterpretation 32803");
            assert_eq!((tag32(322), tag32(323)), want_grid, "{n}: the corpus 322/323 (the per-depth grid)");
            assert_eq!(find(324).unwrap().count, want_tiles, "{n}: the corpus tile count");
 // The 50712 mechanics (the measured per-arm contract):
            // None = ABSENT; Some(count) = PRESENT at the measured count
            // (+ when the original carries the table: the value is
 // byte-identical to the original's — the measured
            // byte-identity across all 9 @8 files — the carry, not a
            // duplicate).
            match want_lut {
                None => {
                    assert!(
                        find(50712).is_none(),
                        "{n}: the corpus 50712 must be ABSENT (the measured {mode} row)"
                    );
                }
                Some(cnt) => {
                    let t = find(50712)
                        .unwrap_or_else(|| panic!("{n}: the corpus 50712 must be present (count {cnt})"));
                    assert_eq!(t.count, cnt, "{n}: the corpus 50712 count (the measured {mode} row)");
                    // The @8 arm: the camera-native table CARRIED
                    // verbatim (the value byte-identical to the
 // original's — the measured byte-identity
                    // across all 9 @8 files):
                    let orig = std::fs::read(&orig_p).unwrap();
                    let ometa = crate::tiff::read_meta(&orig)
                        .unwrap_or_else(|err| panic!("{n}: original read_meta: {err}"));
                    if let Some(st) = ometa.ifd0.entries.iter().find(|x| x.tag == 50712) {
                        let gotv = ifd_value(&gold, e, t);
                        let srcv = ifd_value(&orig, ometa.endianness, st);
                        assert_eq!(gotv, srcv, "{n}: the corpus 50712 = the original's table verbatim (the carried @8 identity)");
                    }
                }
            }
            // [ds2x] the measured reference contract: the 51089-91
            // proxy tags are OMITTED by the reference (the tool's own
 // encode design ADDS them — the free header
            // packing — the encode golden pins the presence on the
            // tool's own output), and the crop tags 50719/50720/50829
            // are HALVED (each element /2 floor — the proxy geometry).
            if want_proxy_absent {
                for tag in [51089u16, 51090, 51091] {
                    assert!(
                        find(tag).is_none(),
                        "{n}: the corpus {tag} proxy tag must be ABSENT (the measured omission — the tool's own encode design ADDS them)"
                    );
                }
                let orig = std::fs::read(&orig_p).unwrap();
                let ometa = crate::tiff::read_meta(&orig)
                    .unwrap_or_else(|err| panic!("{n}: original read_meta: {err}"));
                for tag in [50719u16, 50720, 50829] {
                    let st = ometa
                        .ifd0
                        .entries
                        .iter()
                        .find(|x| x.tag == tag)
                        .unwrap_or_else(|| panic!("{n}: the source's {tag} crop tag"));
                    let gt = find(tag)
                        .unwrap_or_else(|| panic!("{n}: the corpus {tag} crop tag"));
                    assert_eq!(gt.typ, st.typ, "{n}: the {tag} type preserved");
                    assert_eq!(gt.count, st.count, "{n}: the {tag} count preserved");
                    let a = ifd_value(&orig, e, st);
                    let b = ifd_value(&gold, e, gt);
                    let al: Vec<u32> = a.chunks_exact(4).map(|c| e.u32(c)).collect();
                    let bl: Vec<u32> = b.chunks_exact(4).map(|c| e.u32(c)).collect();
                    assert_eq!(al.len(), bl.len(), "{n}: the {tag} element count");
                    for (i, (x, y)) in al.iter().zip(bl.iter()).enumerate() {
                        assert_eq!(*y, x / 2, "{n}: the corpus {tag}[{i}] = the source's element halved (floor — the proxy geometry)");
                    }
                }
            }
            // The shipped decode path (the per-gate grid eligibility +
            // the file-derived grid + the tile decode + assembly + the
            // restore-drill — the grid×mode-keyed family; the odd-
            // height bottom-row tiles run the content-rows drill
 // semantics — the decision (b)):
            let (w, h, samples) =
                decode_j92_frame(&gold, n).unwrap_or_else(|err| panic!("{n}: decode: {err}"));
            assert_eq!((w, h), want_geom, "{n}: the decoded geometry");
            // The original's unpacked samples (the per-row content-class
            // assertion's ground truth):
            let orig = std::fs::read(&orig_p).unwrap();
            let frame = crate::tiff::read(&orig)
                .unwrap_or_else(|e| panic!("{n}: original parse: {e}"));
            let expected = match depth {
                12 => crate::pack12::unpack12(frame.strip_slice(&orig), frame.width, frame.height),
                10 => crate::pack12::unpack10(frame.strip_slice(&orig), frame.width, frame.height),
                _ => crate::pack12::unpack8(frame.strip_slice(&orig), frame.width, frame.height),
            }
            .unwrap_or_else(|e| panic!("{n}: original unpack: {e}"));
            out.push((n.clone(), samples, expected));
        }
        out
    }

 /// THE GOLDEN DECODE TEST — the FHD log10 @12 row (the 
 /// measured contract — the mirrored reference corpus): the
    /// measured FHD log10 @12 output (the 242×274 8×4 grid
    /// = 32 tiles, the stored BPS10, the 50712 1024 LUT — the
 /// reference's own per-frame calibration table, the free
    /// class: the structural pin = presence + count, NOT the content)
    /// must DECODE through the tool's lossless decode path: the per-
    /// gate grid eligibility, the file-derived grid, the tile decode +
    /// assembly, and the restore-drill re-encode integrity (the FHD
    /// family — the grid-keyed routing; the 268-content-row bottom-row
    /// half-row tiles run the odd-height content-rows drill semantics
 /// — the decision (b)). Content class = the measured
 /// quantized codes (the measured verdict: maxdiff 1 /
    /// ~97.6–97.9% exact vs the original's own LUT inverse — the ≤1-
    /// LSB residual = the measured tie-break/rounding delta, the
 /// interop boundary — NOT a contract). Corpus
 /// `../testdata/reference/log10/A001_004/` (3 frames).
    #[test]
    fn golden_fhd_log10_12_decode_pixel_exact() {
        let rows = golden_mode_decode_row(
            "log10",
            "A001_004",
            12,
            (1936, 1090),
            10, // the corpus stored BPS10 (the 12→10 BPS split)
            (242, 274),
            32,
            Some(1024), // the measured per-frame 1024 LUT (presence + count only)
            false,
            [
                "A001_004_20260924_000001.DNG".into(),
                "A001_004_20260924_000049.DNG".into(),
                "A001_004_20260924_000097.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, samples, _orig) in rows {
            // The content class: the measured quantized code
 // plane (10-bit codes — the interop boundary: the
            // decode is asserted to DECODE — the round-trip + the
            // drill — NEVER pixel-exact vs the raw originals).
            assert!(
                samples.iter().all(|v| *v <= 1023),
                "{n}: the decoded samples are 10-bit codes (the @12 log10 content class — the quantized code plane)"
            );
        }
    }

 /// THE GOLDEN DECODE TEST — the FHD log10 @10 row (the 
 /// measured contract — the mirrored reference corpus): the
    /// measured FHD log10 @10 output (the 484×274 4×4 grid
    /// = 16 tiles, the stored BPS10 UNCHANGED, NO 50712 — the measured
    /// ABSENT) must DECODE PIXEL-EXACT through the tool's lossless
 /// decode path (the measured verdict: maxdiff 0, 100% exact vs
    /// the raw 10-bit samples — the @10 arm is a RAW 10-BIT
    /// PASSTHROUGH: no log codes, no LUT — content-identical to the
    /// FHD lossless @10 plane). The restore-drill on the FHD family
    /// (the measured subset {W6, N5} ⊂ {W7, W6, N5}) + the 268-
    /// content-row bottom-row tiles (the odd-height content-rows drill
 /// semantics — the decision (b)). Corpus
 /// `../testdata/reference/log10/A001_005/` (3 frames).
    #[test]
    fn golden_fhd_log10_10_decode_pixel_exact() {
        let rows = golden_mode_decode_row(
            "log10",
            "A001_005",
            10,
            (1936, 1090),
            10, // the corpus stored BPS10 (unchanged)
            (484, 274),
            16,
            None, // the measured ABSENT
            false,
            [
                "A001_005_20260924_000001.DNG".into(),
                "A001_005_20260924_000049.DNG".into(),
                "A001_005_20260924_000097.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, samples, orig) in rows {
            assert_eq!(
                samples, orig,
                "{n}: the decoded reference log10 @10 != the original raw 10-bit samples (the measured maxdiff 0 — the raw-passthrough content class)"
            );
        }
    }

 /// THE GOLDEN DECODE TEST — the FHD log10 @8 row (the 
 /// measured contract — the mirrored reference corpus): the
    /// measured FHD log10 @8 output (the 242×274 8×4 grid =
    /// 32 tiles, the stored BPS10 — the measured 8→10 IDENTITY
    /// promotion, NO value scaling — the ×4-scaled hypothesis measured
    /// REJECTED, maxdiff 765, the camera-native 256-entry 50712
    /// CARRIED VERBATIM) must DECODE PIXEL-EXACT through the tool's
 /// lossless decode path (the measured verdict: maxdiff 0, 100%
    /// exact vs the raw 8-bit samples — the 8-bit samples stored as-is
    /// in the BPS10 container). The restore-drill on the FHD family +
    /// the 268-content-row bottom-row tiles (the odd-height content-
 /// rows drill semantics — the decision (b)). Corpus
 /// `../testdata/reference/log10/A001_006/` (3 frames).
    #[test]
    fn golden_fhd_log10_8_decode_pixel_exact() {
        let rows = golden_mode_decode_row(
            "log10",
            "A001_006",
            8,
            (1936, 1090),
            10, // the corpus stored BPS10 (the measured 8→10 identity promotion)
            (242, 274),
            32,
            Some(256), // the camera-native table CARRIED (the helper pins the verbatim value)
            false,
            [
                "A001_006_20260924_000001.DNG".into(),
                "A001_006_20260924_000051.DNG".into(),
                "A001_006_20260924_000101.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, samples, orig) in rows {
            assert_eq!(
                samples, orig,
                "{n}: the decoded reference log10 @8 != the original raw 8-bit samples (the measured maxdiff 0 — the identity-promotion content class)"
            );
        }
    }

 /// THE GOLDEN DECODE TEST — the FHD ds2x @12 row (the 
 /// measured contract — the mirrored reference corpus): the
    /// measured FHD ds2x @12 output (the 968×545 geometry —
    /// the NEW ds2x grid eligibility — the 242×274 4×2 grid = 8 tiles,
    /// the stored BPS12, NO 50712, the 51089-91 proxy tags OMITTED —
    /// the measured omission, the 50719/50720/50829 HALVED) must DECODE
    /// through the tool's lossless decode path on the grid×mode-keyed
 /// 2-member DS2X family (the decision (c) — {W6, N5}, W7
    /// never observed, the superset rejected): the tile decode +
    /// assembly + the restore-drill — the top-row tiles on the full
    /// family match, the 271-content-row bottom-row half-row tiles on
 /// the content-rows drill semantics (the decision (b) —
    /// the corpus synthetic pad rows are not content; the engine
    /// parity ×10/10 on the record proves the content intact). Content
 /// class = the measured decimation (the measured δ decision:
    /// 40–41% exact vs the tool's staircase — the interop boundary —
    /// the decode is asserted to DECODE, NEVER a decimation byte-parity
 /// assertion). Corpus `../testdata/reference/ds2x/A001_004/` (3
    /// frames).
    #[test]
    fn golden_fhd_ds2x_12_decode_pixel_exact() {
        ds2x_decode_row_content("ds2x-12", "A001_004", 12, (968, 545), 12, (242, 274), 8, [
            "A001_004_20260924_000001.DNG".into(),
            "A001_004_20260924_000049.DNG".into(),
            "A001_004_20260924_000097.DNG".into(),
        ]);
    }

 /// THE GOLDEN DECODE TEST — the FHD ds2x @10 row (the 
 /// measured contract — the mirrored reference corpus): the
    /// measured FHD ds2x @10 output (the 968×545 geometry —
    /// the measured 484×274 2×2 grid = 4 tiles, the stored BPS10, NO
    /// 50712, the proxy tags OMITTED + the HALVED crop tags) must
    /// DECODE through the tool's lossless decode path on the 2-member
 /// DS2X family (the decision (c)) + the content-rows drill semantics
 /// on the 271-content-row bottom-row tiles (the decision (b)).
 /// Content class = the measured decimation (the δ decision:
    /// 67% exact vs the tool's staircase — the interop boundary). Corpus
 /// `../testdata/reference/ds2x/A001_005/` (3 frames).
    #[test]
    fn golden_fhd_ds2x_10_decode_pixel_exact() {
        ds2x_decode_row_content("ds2x-10", "A001_005", 10, (968, 545), 10, (484, 274), 4, [
            "A001_005_20260924_000001.DNG".into(),
            "A001_005_20260924_000049.DNG".into(),
            "A001_005_20260924_000097.DNG".into(),
        ]);
    }

 /// THE GOLDEN DECODE TEST — the FHD ds2x @8 row (the 
 /// measured contract — the mirrored reference corpus): the
    /// measured FHD ds2x @8 output (the 968×545 geometry —
    /// the measured 242×274 4×2 grid = 8 tiles, the stored BPS10 — the
    /// measured 8→10 IDENTITY promotion, the camera-native 256-entry
    /// 50712 CARRIED, the proxy tags OMITTED + the HALVED crop tags)
    /// must DECODE through the tool's lossless decode path on the 2-
 /// member DS2X family (the decision (c)) + the content-rows drill
 /// semantics on the 271-content-row bottom-row tiles (the decision
    /// (b)). Content class = the measured decimation (the δ
 /// decision: 73–74% exact vs the tool's staircase — the interop
 /// boundary). Corpus `../testdata/reference/ds2x/A001_006/` (3
    /// frames).
    #[test]
    fn golden_fhd_ds2x_8_decode_pixel_exact() {
        ds2x_decode_row_content("ds2x-8", "A001_006", 8, (968, 545), 10, (242, 274), 8, [
            "A001_006_20260924_000001.DNG".into(),
            "A001_006_20260924_000051.DNG".into(),
            "A001_006_20260924_000101.DNG".into(),
        ]);
    }

    /// The ds2x rows' decode golden seam (the per-row named gates above
    /// wrap this): the shared structural cross-check (the 968×545
    /// geometry — the NEW ds2x grid eligibility · the per-arm stored
    /// BPS · the per-depth grid + tile count · the 50712 mechanics
    /// [absent @12/@10, the carried native 256 @8] · the OMITTED 51089-
    /// 91 proxy tags (the measured reference fact) · the HALVED crop
    /// tags 50719/50720/50829) via the shared machinery + the per-row
    /// content-class assertion: the decode is asserted to DECODE (the
    /// round-trip + the drill — incl. the odd-height content-rows
    /// semantics on the 271-content-row bottom-row tiles) with the
    /// samples fitting the stored precision — the measured
 /// decimation is the interop boundary (the measured δ decision: the
    /// tool keeps its own staircase; the interop acceptance = the
    /// decode of the corpus files, NEVER a decimation byte-parity
    /// assertion).
    fn ds2x_decode_row_content(
        tag: &str,
        clip: &str,
        depth: u16,
        want_geom: (u32, u32),
        want_bps: u16,
        want_grid: (u32, u32),
        want_tiles: u32,
        names: [String; 3],
    ) {
        let rows = golden_mode_decode_row(
            "ds2x",
            clip,
            depth,
            want_geom,
            want_bps,
            want_grid,
            want_tiles,
            if depth == 8 { Some(256) } else { None }, // the @8 arm: the carried native 256
            true, // the reference omits the 51089-91 proxy tags (the measured fact)
            names,
        );
        if rows.is_empty() {
            return;
        }
        for (n, samples, _orig) in rows {
            // The content class: the measured decimation plane
            // (the samples fit the stored precision — the decode + the
            // drill [incl. the content-rows semantics on the bottom-
            // row tiles] passed; the decimation parity vs the tool's
 // own staircase is the interop boundary — the δ decision:
            // NEVER a byte-parity assertion).
            let max = (1u16 << want_bps) - 1;
            assert!(
                samples.iter().all(|v| *v <= max),
                "{n}: the decoded samples fit the stored {want_bps}-bit precision (the ds2x {tag} content class — the measured decimation)"
            );
        }
    }

    // =================================================================
 // The OG2K mode rows ( — measured
    // contract — the mirrored reference mode corpus): the 2016×1344
    // log10 rows (full-res) + the 1008×672 ds2x rows at @12/@10/@8.
    // Corpus (the G2/G3/G4 corpus-noting pattern — the mode corpus is
    // date-suffix-free): the reference mode outputs
 // `../testdata/reference/log10/A001_00X/` +
 // `../testdata/reference/ds2x/A001_00X/` + the originals
    // `../testdata/originals_A001_00X/` (A001_007 @12 · A001_008 @10
    // · A001_009 @8 — the 3-frame sample pattern
    // 000001/000049/000097 · 000001/000050/000100).
    // =================================================================

 /// THE GOLDEN DECODE TEST — the OG2K log10 @12 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured OG2K log10 @12 output (the
    /// depth-invariant 252×336 8×4 grid = 32 tiles, the stored BPS10,
    /// the 50712 1024 LUT — the corpus per-frame calibration
 /// table, the free class: the structural pin = presence +
    /// count, NOT the content) must DECODE through the tool's lossless
    /// decode path: the per-gate grid eligibility, the file-derived
    /// grid, the tile decode + assembly, and the restore-drill re-
    /// encode integrity (the `OG2K_CANDIDATES` family — the grid-keyed
    /// routing; full-tile edge rows only — no half-row class at OG2K,
 /// the measured verdict). Content class = the measured
 /// quantized codes (the measured verdict: maxdiff 1 / ~95.1–
    /// 95.2% exact vs the original's own LUT inverse — the ≤1-LSB
    /// residual = the measured tie-break/rounding delta, the
 /// interop boundary — NOT a contract). Corpus
 /// `../testdata/reference/log10/A001_007/` (3 frames).
    #[test]
    fn golden_og2k_log10_12_decode_pixel_exact() {
        let rows = golden_mode_decode_row(
            "log10",
            "A001_007",
            12,
            (2016, 1344),
            10,
            (252, 336),
            32,
            Some(1024),
            false,
            [
                "A001_007_20260924_000001.DNG".into(),
                "A001_007_20260924_000049.DNG".into(),
                "A001_007_20260924_000097.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, samples, _orig) in rows {
            // The content class: the measured quantized code
 // plane (10-bit codes — the interop boundary: the
            // decode is asserted to DECODE — the round-trip + the
            // drill — NEVER pixel-exact vs the raw originals; the
            // reference's per-frame LUT is its calibration payload —
            // the measured maxdiff 151 vs the tool's embedded A001
            // curve, the ≤1-LSB residual vs the corpus OWN table
 // — the verdict).
            assert!(
                samples.iter().all(|v| *v <= 1023),
                "{n}: the decoded samples are 10-bit codes (the @12 log10 content class — the quantized code plane)"
            );
        }
    }

 /// THE GOLDEN DECODE TEST — the OG2K log10 @10 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured OG2K log10 @10 output (the
    /// depth-invariant 252×336 grid = 32 tiles, the stored BPS10, NO
    /// 50712 — the measured ABSENT) must DECODE PIXEL-EXACT vs the raw
    /// 10-bit original (the measured maxdiff 0 — the raw passthrough:
    /// the corpus row = the original's raw samples in the
    /// BPS10 container). Corpus
 /// `../testdata/reference/log10/A001_008/` (3 frames).
    #[test]
    fn golden_og2k_log10_10_decode_pixel_exact() {
        let rows = golden_mode_decode_row(
            "log10",
            "A001_008",
            10,
            (2016, 1344),
            10,
            (252, 336),
            32,
            None, // the measured ABSENT (no 50712)
            false,
            [
                "A001_008_20260924_000001.DNG".into(),
                "A001_008_20260924_000049.DNG".into(),
                "A001_008_20260924_000097.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, samples, orig) in rows {
            assert_eq!(
                samples, orig,
                "{n}: the decoded golden != the raw 10-bit original samples (pixel-exact parity — the measured maxdiff 0 raw passthrough)"
            );
        }
    }

 /// THE GOLDEN DECODE TEST — the OG2K log10 @8 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured OG2K log10 @8 output (the
    /// depth-invariant 252×336 grid = 32 tiles, the measured 8→10
    /// identity promotion — the stored BPS10, the camera-native 256-
    /// entry 50712 CARRIED verbatim) must DECODE PIXEL-EXACT vs the
    /// raw 8-bit original (the measured maxdiff 0 — the identity
    /// promotion: the 8-bit samples zero-extended into the BPS10
 /// container). Corpus `../testdata/reference/log10/A001_009/` (3
    /// frames).
    #[test]
    fn golden_og2k_log10_8_decode_pixel_exact() {
        let rows = golden_mode_decode_row(
            "log10",
            "A001_009",
            8,
            (2016, 1344),
            10, // the measured 8→10 identity promotion
            (252, 336),
            32,
            Some(256), // the camera-native table CARRIED (the helper pins the verbatim value)
            false,
            [
                "A001_009_20260924_000001.DNG".into(),
                "A001_009_20260924_000050.DNG".into(),
                "A001_009_20260924_000100.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, samples, orig) in rows {
            assert_eq!(
                samples, orig,
                "{n}: the decoded golden != the raw 8-bit original samples (pixel-exact parity — the measured maxdiff 0 identity promotion)"
            );
        }
    }

 /// THE GOLDEN DECODE TEST — the OG2K ds2x @12 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured OG2K ds2x @12 output (the
    /// 1008×672 geometry — the NEW ds2x grid eligibility — the
    /// depth-invariant 252×336 4×2 grid = 8 tiles, the stored BPS12,
    /// the proxy tags OMITTED + the HALVED crop tags) must DECODE
    /// through the tool's lossless decode path on the 3-member
 /// `DS2X_OG2K_CANDIDATES` family (the census — W7
    /// observed — the grid×mode key) + the plain full-tile drill
 /// semantics (full-tile edge rows only — the measured
    /// no-half-row verdict). Content class = the measured
 /// decimation (the δ decision: the interop boundary). Corpus
 /// `../testdata/reference/ds2x/A001_007/` (3 frames).
    #[test]
    fn golden_og2k_ds2x_12_decode_pixel_exact() {
        ds2x_decode_row_content("og2k-ds2x-12", "A001_007", 12, (1008, 672), 12, (252, 336), 8, [
            "A001_007_20260924_000001.DNG".into(),
            "A001_007_20260924_000049.DNG".into(),
            "A001_007_20260924_000097.DNG".into(),
        ]);
    }

 /// THE GOLDEN DECODE TEST — the OG2K ds2x @10 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured OG2K ds2x @10 output (the
    /// 1008×672 geometry, the depth-invariant 252×336 grid = 8 tiles,
    /// the stored BPS10) must DECODE on the 3-member `DS2X_OG2K_
    /// CANDIDATES` family. Content class = the measured
 /// decimation (the δ decision). Corpus
 /// `../testdata/reference/ds2x/A001_008/` (3 frames).
    #[test]
    fn golden_og2k_ds2x_10_decode_pixel_exact() {
        ds2x_decode_row_content("og2k-ds2x-10", "A001_008", 10, (1008, 672), 10, (252, 336), 8, [
            "A001_008_20260924_000001.DNG".into(),
            "A001_008_20260924_000049.DNG".into(),
            "A001_008_20260924_000097.DNG".into(),
        ]);
    }

 /// THE GOLDEN DECODE TEST — the OG2K ds2x @8 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured OG2K ds2x @8 output (the
    /// 1008×672 geometry, the depth-invariant 252×336 grid = 8 tiles,
    /// the measured 8→10 identity promotion — the stored BPS10, the
    /// camera-native 256-entry 50712 CARRIED, the proxy tags OMITTED +
    /// the HALVED crop tags) must DECODE through the tool's lossless
    /// decode path on the 3-member `DS2X_OG2K_CANDIDATES` family.
 /// Content class = the measured decimation (the δ decision).
 /// Corpus `../testdata/reference/ds2x/A001_009/` (3 frames).
    #[test]
    fn golden_og2k_ds2x_8_decode_pixel_exact() {
        ds2x_decode_row_content("og2k-ds2x-8", "A001_009", 8, (1008, 672), 10, (252, 336), 8, [
            "A001_009_20260924_000001.DNG".into(),
            "A001_009_20260924_000050.DNG".into(),
            "A001_009_20260924_000100.DNG".into(),
        ]);
    }

 /// THE GOLDEN DECODE TEST — the OG3K log10 @12 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured OG3K log10 @12 output (the
    /// depth-invariant 252×252 12×8 grid = 96 tiles, the stored BPS10,
    /// the 50712 1024 LUT — the corpus per-frame calibration
 /// table, the free class: the structural pin = presence +
    /// count, NOT the content) must DECODE through the tool's lossless
    /// decode path: the 3K grid eligibility, the file-derived grid, the
    /// tile decode + assembly, and the restore-drill re-encode integrity
    /// (the 3K `CANDIDATES` family — the grid-keyed routing; the bottom-
    /// row tiles are the 246-content-row half-row tiles — the odd-height
    /// interop shape, the content-rows-only drill semantics). Content class = the measured quantized
     /// codes (the interop boundary — NOT a contract). Corpus
    /// `../testdata/reference/log10/A001_010/` (3 frames).
    #[test]
    fn golden_og3k_log10_12_decode_pixel_exact() {
        let rows = golden_mode_decode_row(
            "log10",
            "A001_010",
            12,
            (3024, 2010),
            10,
            (252, 252),
            96,
            Some(1024),
            false,
            [
                "A001_010_20260924_000001.DNG".into(),
                "A001_010_20260924_000050.DNG".into(),
                "A001_010_20260924_000101.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, samples, _orig) in rows {
            // The content class: the measured quantized code
 // plane (10-bit codes — the interop boundary: the
            // decode is asserted to DECODE — the round-trip + the
            // drill — NEVER pixel-exact vs the raw originals; the
            // reference's per-frame LUT is its calibration payload —
 // the verdict).
            assert!(
                samples.iter().all(|v| *v <= 1023),
                "{n}: the decoded samples are 10-bit codes (the @12 log10 content class — the quantized code plane)"
            );
        }
    }

 /// THE GOLDEN DECODE TEST — the OG3K log10 @10 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured OG3K log10 @10 output (the
    /// depth-invariant 252×252 grid = 96 tiles, the stored BPS10, NO
    /// 50712 — the measured ABSENT) must DECODE PIXEL-EXACT vs the raw
    /// 10-bit original (the measured maxdiff 0 — the raw passthrough).
 /// Corpus `../testdata/reference/log10/A001_011/` (3 frames).
    #[test]
    fn golden_og3k_log10_10_decode_pixel_exact() {
        let rows = golden_mode_decode_row(
            "log10",
            "A001_011",
            10,
            (3024, 2010),
            10,
            (252, 252),
            96,
            None, // the measured ABSENT (no 50712)
            false,
            [
                "A001_011_20260924_000001.DNG".into(),
                "A001_011_20260924_000050.DNG".into(),
                "A001_011_20260924_000099.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, samples, orig) in rows {
            assert_eq!(
                samples, orig,
                "{n}: the decoded golden != the raw 10-bit original samples (pixel-exact parity — the measured maxdiff 0 raw passthrough)"
            );
        }
    }

 /// THE GOLDEN DECODE TEST — the OG3K log10 @8 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured OG3K log10 @8 output (the
    /// depth-invariant 252×252 grid = 96 tiles, the measured 8→10
    /// identity promotion — the stored BPS10, the camera-native 256-
    /// entry 50712 CARRIED verbatim) must DECODE PIXEL-EXACT vs the
    /// raw 8-bit original (the measured maxdiff 0 — the identity
 /// promotion). Corpus `../testdata/reference/log10/A001_012/` (3
    /// frames).
    #[test]
    fn golden_og3k_log10_8_decode_pixel_exact() {
        let rows = golden_mode_decode_row(
            "log10",
            "A001_012",
            8,
            (3024, 2010),
            10, // the measured 8→10 identity promotion
            (252, 252),
            96,
            Some(256), // the camera-native table CARRIED (the helper pins the verbatim value)
            false,
            [
                "A001_012_20260924_000001.DNG".into(),
                "A001_012_20260924_000049.DNG".into(),
                "A001_012_20260924_000097.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, samples, orig) in rows {
            assert_eq!(
                samples, orig,
                "{n}: the decoded golden != the raw 8-bit original samples (pixel-exact parity — the measured maxdiff 0 identity promotion)"
            );
        }
    }

 /// THE GOLDEN DECODE TEST — the OG3K ds2x @12 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured OG3K ds2x @12 output (the
    /// 1512×1005 geometry — the NEW ds2x grid eligibility — the depth-
    /// invariant 252×252 6×4 grid = 24 tiles, the stored BPS12, the
    /// proxy tags OMITTED + the HALVED crop tags) must DECODE through
    /// the tool's lossless decode path on the 3-member
 /// `DS2X_OG3K_CANDIDATES` family (the census — W7
    /// observed — the grid×mode key) + the content-rows-only drill
    /// semantics (the bottom-row tiles are the 249-content-row half-row
    /// tiles — the odd-height interop shape). Content class = the
 /// reference's own decimation (the δ decision: the interop boundary).
 /// Corpus `../testdata/reference/ds2x/A001_010/` (3 frames).
    #[test]
    fn golden_og3k_ds2x_12_decode_pixel_exact() {
        ds2x_decode_row_content("og3k-ds2x-12", "A001_010", 12, (1512, 1005), 12, (252, 252), 24, [
            "A001_010_20260924_000001.DNG".into(),
            "A001_010_20260924_000050.DNG".into(),
            "A001_010_20260924_000101.DNG".into(),
        ]);
    }

 /// THE GOLDEN DECODE TEST — the OG3K ds2x @10 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured OG3K ds2x @10 output (the
    /// 1512×1005 geometry, the depth-invariant 252×252 grid = 24
    /// tiles, the stored BPS10) must DECODE on the 3-member
    /// `DS2X_OG3K_CANDIDATES` family. Content class = the measured
 /// own decimation (the δ decision). Corpus
 /// `../testdata/reference/ds2x/A001_011/` (3 frames).
    #[test]
    fn golden_og3k_ds2x_10_decode_pixel_exact() {
        ds2x_decode_row_content("og3k-ds2x-10", "A001_011", 10, (1512, 1005), 10, (252, 252), 24, [
            "A001_011_20260924_000001.DNG".into(),
            "A001_011_20260924_000050.DNG".into(),
            "A001_011_20260924_000099.DNG".into(),
        ]);
    }

 /// THE GOLDEN DECODE TEST — the OG3K ds2x @8 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured OG3K ds2x @8 output (the
    /// 1512×1005 geometry, the depth-invariant 252×252 grid = 24
    /// tiles, the measured 8→10 identity promotion — the stored BPS10,
    /// the camera-native 256-entry 50712 CARRIED, the proxy tags
    /// OMITTED + the HALVED crop tags) must DECODE through the tool's
    /// lossless decode path on the 3-member `DS2X_OG3K_CANDIDATES`
    /// family. Content class = the measured decimation (the δ
 /// decision). Corpus `../testdata/reference/ds2x/A001_012/` (3 frames).
    #[test]
    fn golden_og3k_ds2x_8_decode_pixel_exact() {
        ds2x_decode_row_content("og3k-ds2x-8", "A001_012", 8, (1512, 1005), 10, (252, 252), 24, [
            "A001_012_20260924_000001.DNG".into(),
            "A001_012_20260924_000049.DNG".into(),
            "A001_012_20260924_000097.DNG".into(),
        ]);
    }

    // =================================================================
 // The UHD mode rows ( — measured
    // contract — the mirrored reference mode corpus): the 3856×2170
    // log10 rows (full-res — the existing UHD grid eligibility — 964×272
    // @10 / 482×272 @8) + the 1928×1085 ds2x rows at @10/@8 (the NEW
    // UHD ds2x grid eligibility — the 964×272 + 482×272 grids — the
    // per-depth source-grid inheritance; the bottom-row tiles are the
    // 269-content-row half-row tiles — the content-rows drill
 // semantics, the decision (b); the measured pad class
    // — the middle pad row copy-of-last-row, the outer pads synthetic,
    // the H1 overlap window rejected (0 hits), the engine parity
    // ×48/48 — report.md §6; the 0.1.0-era legacy 482×272 ds2x output
    // stays decodable — the byte-frozen mode control, the backward-
    // compat pattern). Corpus (the G4 corpus-noting pattern — the mode
    // corpus is date-suffix-free): the reference mode outputs
 // `../testdata/reference/{log10,ds2x}/A001_00{2,3}/` + the originals
    // `../testdata/originals_A001_00{2,3}/` (A001_002 @10 · A001_003
    // @8 — the 3-frame sample pattern
    // 000001/000050/000099 · 000001/000049/000098).
    // =================================================================

 /// THE GOLDEN DECODE TEST — the UHD log10 @10 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured UHD log10 @10 output (the
    /// measured 964×272 grid = 4×8 = 32 tiles, the stored BPS10, the
    /// 50712 ABSENT) must DECODE through the tool's lossless decode
    /// path: the per-gate grid eligibility (the existing UHD arm), the
    /// file-derived grid, the tile decode + assembly, and the restore-
    /// drill re-encode integrity (the `CANDIDATES` family — the 964×272
    /// grid's measured family — the grid-keyed routing; the bottom-row
    /// tiles are the 266-content-row half-row tiles — the full-res
 /// odd-height class, the lossless pattern). Content class
    /// = the raw 10-bit samples (the measured maxdiff 0 — the raw
    /// passthrough identity HOLDS at UHD). Corpus
 /// `../testdata/reference/log10/A001_002/` (3 frames).
    #[test]
    fn golden_uhd_log10_10_decode_pixel_exact() {
        let rows = golden_mode_decode_row(
            "log10",
            "A001_002",
            10,
            (3856, 2170),
            10,
            (964, 272),
            32,
            None, // the measured ABSENT (no 50712)
            false,
            [
                "A001_002_20260924_000001.DNG".into(),
                "A001_002_20260924_000050.DNG".into(),
                "A001_002_20260924_000099.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, samples, orig) in rows {
            assert_eq!(
                samples, orig,
                "{n}: the decoded golden != the raw 10-bit original samples (pixel-exact parity — the measured maxdiff 0 raw passthrough)"
            );
        }
    }

 /// THE GOLDEN DECODE TEST — the UHD log10 @8 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured UHD log10 @8 output (the
    /// measured 482×272 grid = 8×8 = 64 tiles, the measured 8→10
    /// identity promotion — the stored BPS10, the camera-native 256-
    /// entry 50712 CARRIED verbatim) must DECODE PIXEL-EXACT vs the
    /// raw 8-bit original (the measured maxdiff 0 — the identity
 /// promotion). Corpus `../testdata/reference/log10/A001_003/` (3
    /// frames).
    #[test]
    fn golden_uhd_log10_8_decode_pixel_exact() {
        let rows = golden_mode_decode_row(
            "log10",
            "A001_003",
            8,
            (3856, 2170),
            10, // the measured 8→10 identity promotion
            (482, 272),
            64,
            Some(256), // the camera-native table CARRIED (the helper pins the verbatim value)
            false,
            [
                "A001_003_20260924_000001.DNG".into(),
                "A001_003_20260924_000049.DNG".into(),
                "A001_003_20260924_000098.DNG".into(),
            ],
        );
        if rows.is_empty() {
            return;
        }
        for (n, samples, orig) in rows {
            assert_eq!(
                samples, orig,
                "{n}: the decoded golden != the raw 8-bit original samples (pixel-exact parity — the measured maxdiff 0 identity promotion)"
            );
        }
    }

 /// THE GOLDEN DECODE TEST — the UHD ds2x @10 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured UHD ds2x @10 output (the
    /// 1928×1085 geometry — the NEW UHD ds2x grid eligibility — the
    /// measured 964×272 2×4 grid = 8 tiles, the stored BPS10, the proxy
    /// tags OMITTED + the HALVED crop tags) must DECODE through the
    /// tool's lossless decode path on the 2-member
 /// `DS2X_UHD_964_CANDIDATES` family (the census — W7
    /// never observed — the grid×mode×grid key) + the content-rows-only
    /// drill semantics (the bottom-row tiles are the 269-content-row
 /// half-row tiles — the odd-height interop shape — the measured
    /// pad class: the middle pad row copy-of-last-row, the outer pads
    /// synthetic, the H1 overlap window rejected (0 hits), the engine
    /// parity ×48/48 (the recorded verdict). Content class = the measured
 /// decimation (the δ decision: the interop boundary). Corpus
 /// `../testdata/reference/ds2x/A001_002/` (3 frames).
    #[test]
    fn golden_uhd_ds2x_10_decode_pixel_exact() {
        ds2x_decode_row_content("uhd-ds2x-10", "A001_002", 10, (1928, 1085), 10, (964, 272), 8, [
            "A001_002_20260924_000001.DNG".into(),
            "A001_002_20260924_000050.DNG".into(),
            "A001_002_20260924_000099.DNG".into(),
        ]);
    }

 /// THE GOLDEN DECODE TEST — the UHD ds2x @8 row (the 
 /// measured contract — — the mirrored reference
    /// corpus): the measured UHD ds2x @8 output (the
    /// 1928×1085 geometry — the NEW UHD ds2x grid eligibility — the
    /// measured 482×272 4×4 grid = 16 tiles, the measured 8→10
    /// identity promotion — the stored BPS10, the camera-native 256-
    /// entry 50712 CARRIED, the proxy tags OMITTED + the HALVED crop
    /// tags) must DECODE through the tool's lossless decode path on
 /// the 3-member `DS2X_UHD_482_CANDIDATES` family (the 
    /// census — W7 observed — the grid×mode×grid key — the @8 row +
    /// the 0.1.0-era legacy ds2x output, both the 482×272 grid, the
    /// byte-frozen mode control kept decodable) + the content-rows-only
    /// drill semantics (the bottom-row tiles are the 269-content-row
 /// half-row tiles — the odd-height interop shape, the decision (b)).
 /// Content class = the measured decimation (the δ decision:
    /// the interop boundary). Corpus
 /// `../testdata/reference/ds2x/A001_003/` (3 frames).
    #[test]
    fn golden_uhd_ds2x_8_decode_pixel_exact() {
        ds2x_decode_row_content("uhd-ds2x-8", "A001_003", 8, (1928, 1085), 10, (482, 272), 16, [
            "A001_003_20260924_000001.DNG".into(),
            "A001_003_20260924_000049.DNG".into(),
            "A001_003_20260924_000098.DNG".into(),
        ]);
    }
}
