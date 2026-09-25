//! `frameprism derive` — the
//! 12→8/10 DERIVED WORKING TIER: genuine CinemaDNG files derived from the
//! 12-bit masters, the space-saving working/edit copy ("stay in realms of
//! CinemaDNG").
//!
//! PIXEL MAPPING (PINNED — no rounding, no dithering):
//!   12→8  = v >> 4
//!   12→10 = v >> 2
//! The pinned formula string is recorded in the sidecar + the run summary
//! (`Bits::formula`, one literal — the recorded decision).
//!
//! CONTAINER: a genuine UNCOMPRESSED CFA DNG at the derived depth — the
//! camera-native shape (the same shape the archive-layout gate reads):
//!   - tag 258 BitsPerSample 12 → 8|10 (in-line SHORT patch);
//!   - tag 279 StripByteCounts → the packed derived strip length (the
//!     the depth rule: 8-bit 1 B/sample, 10-bit per-row 4-per-5-bytes,
//!     zero pad, the ≤64 pad tolerance the parser allows);
//!   - tag 273 StripOffsets UNCHANGED (the strip lands at the same file
//!     offset — no pointer anywhere moves) and tag 259 Compression stays
//!     1 (uncompressed);
//!   - tag 278 RowsPerStrip UNCHANGED (W×H single strip, same geometry);
//!   - every other header byte verbatim (TimeCodes 51043, ExifIFD, the
//!     SIGMA blob, all DNG tags — the lossless-surgery pattern; see
//!     `surgery::apply_derive_strip`).
//! The derived frame is a lossless re-encode input for the EXISTING
//! archive paths (j92 tile at the derived SOF3 precision + jxl e7, both
//! at the derived depth) and `frameprism decode` round-trips it. The
//! derivation is irreversible wrt the master (low bits gone) — the
//! sidecar records `bits_in → bits_out` + the formula (positioning rule:
//! the archive master stays at source depth).
//!
//! INPUT/OUTPUT: `<in-dir>` = a dir of 12-bit master .DNGs (any archive
//! layout — the walk mirrors `worker::collect`: subfolders mirrored,
//! non-DNG sidecars copied through). `<in>` is READ-ONLY (the master is
//! never rewritten — positioning rule, non-negotiable); derive writes
//! only to `<out>` (created if missing). Non-12-bit frames and
//! non-archive-geometry frames are NAMED REFUSALS (rc=1 per frame), not
//! silent skips.
//!
//! SIDE CAR (mandatory, always written on a clean run):
//! `<OUT_DIR>/<CLIP>.derive-manifest.tsv` — v1, header block (bits_in,
//! bits_out, the pinned formula, the tool version, the frame count) +
//! one row per derived frame (file, size, whole-file sha256; rows sorted
//! by path). Deterministic: no wall-clock field (the recorded decision — the
//! bake-manifest `created`-field pattern, pinned rather than clocked),
//! same inputs → byte-identical tsv.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::{Args as ClapArgs, ValueEnum};
use std::os::unix::fs::MetadataExt;
use anyhow::{bail, Context, Result};
use rayon::prelude::*;

/// The derived depth (the pinned 12→8 / 12→10 mapping).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Bits {
    /// 12→8: v >> 4.
    #[value(name = "8")]
    B8,
    /// 12→10: v >> 2.
    #[value(name = "10")]
    B10,
}

impl Bits {
    /// The new BitsPerSample (tag 258) value.
    pub fn as_u16(self) -> u16 {
        match self {
            Bits::B8 => 8,
            Bits::B10 => 10,
        }
    }
    /// The right shift of the pinned linear mapping (no rounding, no
    /// dithering).
    pub fn shift(self) -> u32 {
        match self {
            Bits::B8 => 4,
            Bits::B10 => 2,
        }
    }
 /// The pinned formula string (the recorded decision) — the exact literal
    /// recorded in the sidecar and the run summary.
    pub fn formula(self) -> &'static str {
        match self {
            Bits::B8 => "12->8: v>>4 (no rounding, no dithering)",
            Bits::B10 => "12->10: v>>2 (no rounding, no dithering)",
        }
    }
}

/// The `frameprism derive` CLI arguments (the `Cmd::Derive` payload — the
/// subcommand args live here, not in `main.rs`, per the shared CLI
/// restructure contract).
#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Directory of 12-bit master .DNG frames (any archive layout).
    /// READ-ONLY — the master is never rewritten.
    pub input: PathBuf,
    /// Output dir for the derived .DNGs (same base names) + the
    /// mandatory <CLIP>.derive-manifest.tsv sidecar (created if missing).
    pub output: PathBuf,
    /// Derived depth: 8 (v>>4) or 10 (v>>2) — the pinned mapping.
    #[arg(long, value_enum)]
    pub bits: Bits,
    /// Overwrite existing outputs (default: skip = resume).
    #[arg(long)]
    pub force: bool,
}

/// One frame's derive outcome.
enum Outcome {
    Done {
        file: String,
        in_bytes: u64,
        out_bytes: u64,
    },
    Skipped {
        file: String,
    },
    Failed {
        file: String,
        error: String,
    },
}

/// The `Cmd::Derive` match arm (main.rs): run the derivation, return the
/// process exit code (0 = clean + sidecar written; 1 = per-frame
/// failure(s), NO sidecar; 2 = pre-run error).
pub fn run(args: &Args) -> ExitCode {
    match run_inner(args) {
        Ok((report, manifest)) => {
            print_summary(args, &report, manifest.as_deref());
            ExitCode::SUCCESS
        }
        Err(ErrShape::PreRun(err)) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
        Err(ErrShape::Run(report)) => {
            print_summary(args, &report, None);
            ExitCode::from(1)
        }
    }
}

/// run_inner error shape: PreRun = usage (rc=2); Run = the run finished
/// with per-frame failures (rc=1, the report is printed).
enum ErrShape {
    PreRun(anyhow::Error),
    Run(Report),
}

impl From<anyhow::Error> for ErrShape {
    fn from(e: anyhow::Error) -> Self {
        ErrShape::PreRun(e)
    }
}

struct Report {
    outcomes: Vec<Outcome>,
    sidecars_copied: Vec<String>,
    elapsed_s: f64,
}

fn run_inner(args: &Args) -> Result<(Report, Option<PathBuf>), ErrShape> {
    let t0 = Instant::now();
    // Pre-run validation (rc=2 band — ErrShape::PreRun).
    if !args.input.is_dir() {
        return Err(ErrShape::PreRun(anyhow::anyhow!(
            "input is not a directory: {}",
            args.input.display()
        )));
    }
    if args.input == args.output {
        return Err(ErrShape::PreRun(anyhow::anyhow!(
            "input and output must differ (the master dir is read-only)"
        )));
    }
    std::fs::create_dir_all(&args.output)
        .with_context(|| format!("create output dir {}", args.output.display()))?;

    let mut frames: Vec<(PathBuf, PathBuf)> = Vec::new(); // (in, out)
    let mut sidecars: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut visited = HashSet::new();
    collect(
        &args.input,
        &args.input,
        &args.output,
        &mut frames,
        &mut sidecars,
        &mut visited,
    )?;
    frames.sort_by(|a, b| a.0.cmp(&b.0));
    sidecars.sort_by(|a, b| a.0.cmp(&b.0));
    if frames.is_empty() {
        return Err(ErrShape::PreRun(anyhow::anyhow!(
            "no .DNG master frames in input dir {}",
            args.input.display()
        )));
    }

    let mut sidecars_copied = Vec::new();
    for (src, dst) in &sidecars {
        if dst.exists() && !args.force {
            continue; // resume: the sidecar is already derived
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
        // Atomic sidecar copy (tmp + rename) — the worker's pattern.
        let tmp = dst.with_extension("sidecar.tmp");
        std::fs::copy(src, &tmp)
            .and_then(|_| std::fs::rename(&tmp, dst))
            .with_context(|| {
                format!("copy sidecar {} -> {}", src.display(), dst.display())
            })?;
        sidecars_copied.push(
            src.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        );
    }

    let outcomes: Vec<Outcome> = frames
        .par_iter()
        .map(|(src, dst)| {
            let file = src
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| src.display().to_string());
            if dst.exists() && !args.force {
                return Outcome::Skipped { file };
            }
            match derive_one(src, dst, args.bits) {
                Ok((in_bytes, out_bytes)) => Outcome::Done {
                    file,
                    in_bytes,
                    out_bytes,
                },
                Err(err) => {
                    eprintln!("FAIL {file}: {err:#}");
                    Outcome::Failed {
                        file,
                        error: format!("{err:#}"),
                    }
                }
            }
        })
        .collect();

    let failed = outcomes
        .iter()
        .filter(|o| matches!(o, Outcome::Failed { .. }))
        .count();
    let report = Report {
        outcomes,
        sidecars_copied,
        elapsed_s: t0.elapsed().as_secs_f64(),
    };

    // The mandatory sidecar (only on a clean run — a failed frame would
    // leave a manifest that names files that do not exist). A failed run
    // is ErrShape::Run (rc=1, the report is printed, no sidecar).
    if failed > 0 {
        eprintln!(
            "skipping the derive-manifest sidecar: {failed} frame(s) failed"
        );
        return Err(ErrShape::Run(report));
    }
    let clip = crate::checksums::clip_name(&args.input)?;
    let manifest = Some(write_manifest(&args.output, &clip, args.bits, &frames)?);

    Ok((report, manifest))
}

/// Recursively collect the .DNG master frames + non-DNG sidecars under
/// `base` (mirrors `worker::collect` — the subfolder layout is mirrored
/// into `output_root`, symlinks are refused, the visited set is the
/// symlink-cycle guard).
fn collect(
    base: &Path,
    dir: &Path,
    output_root: &Path,
    frames: &mut Vec<(PathBuf, PathBuf)>,
    sidecars: &mut Vec<(PathBuf, PathBuf)>,
    visited: &mut HashSet<(u64, u64)>,
) -> Result<()> {
    let meta = std::fs::metadata(dir)?;
    let id = (meta.dev(), meta.ino()); // unix: std::os::unix::fs::MetadataExt
    if !visited.insert(id) {
        return Ok(()); // already visited — symlink cycle (or hard-link fan-in)
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue; // refuse symlinked entries (the worker's contract)
        }
        //: the AppleDouble shadow is never a master frame nor a
        // sidecar — skip (the worker's `collect` mirrored, the shared
        // predicate).
        if entry.file_name().to_str().is_some_and(crate::is_apple_double) {
            continue;
        }
        let rel = p.strip_prefix(base).unwrap_or(&p);
        let dst = output_root.join(rel);
        if p.is_dir() {
            collect(base, &p, output_root, frames, sidecars, visited)?;
        } else if p.is_file() {
            let is_dng = p
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("dng"))
                .unwrap_or(false);
            if is_dng {
                frames.push((p, dst));
            } else {
                sidecars.push((p, dst));
            }
        }
    }
    Ok(())
}

/// Per-frame derivation: read the 12-bit master, apply the pinned shift,
/// emit the derived-depth DNG (the strip surgery), gate the round-trip
/// in-run, write atomically.
fn derive_one(src: &Path, dst: &Path, bits: Bits) -> Result<(u64, u64)> {
    let buf = std::fs::read(src).with_context(|| format!("read {}", src.display()))?;
    let frame = crate::tiff::read(&buf)?;
    // Named refusals (the tool pins 12-bit masters at the fp archive
    // geometries — a mix-in is named per frame, not a silent skip):
    // `is_archive_layout` covers the geometry + the bps ∈ {8,10,12} band,
    // the ==12 check pins the master depth.
    if frame.bits_per_sample != 12 {
        anyhow::bail!(
            "derive: master is {}-bit — frameprism derive reads 12-bit masters only (both the 12→8 and the 12→10 mapping start from the 12-bit master)",
            frame.bits_per_sample
        );
    }
    if !crate::worker::is_archive_layout(&frame) {
        anyhow::bail!(
            "derive: {}×{} is not an fp archive geometry (3856×2170 or 1936×1090) — refusing to derive outside the archive layouts",
            frame.width, frame.height
        );
    }
    let packed = frame.strip_slice(&buf);
    let samples = crate::pack12::unpack12(packed, frame.width, frame.height)?;
    // The pinned mapping (no rounding, no dithering): v >> shift.
    let shift = bits.shift();
    let mapped: Vec<u16> = samples.iter().map(|&v| v >> shift).collect();
    let strip = match bits {
        Bits::B8 => crate::pack12::pack8(&mapped)?,
        Bits::B10 => crate::pack12::pack10(&mapped, frame.width)?,
    };
    let out = crate::surgery::apply_derive_strip(&buf, &frame, bits.as_u16(), &strip)
        .map_err(|e| anyhow::anyhow!("derive surgery: {e}"))?;
    // In-run bit-exact round-trip gate (the in-tool structural proof,
    // always on): re-PARSE the derived file (the tiff invariants re-check
    // the rewritten header: BitsPerSample, the W×H single strip, the
    // packed strip length at the depth rule, the zero tail) and
    // re-UNPACK the derived strip — it must equal the pinned mapping
    // bit-exactly.
    let df = crate::tiff::read(&out.bytes)?;
    debug_assert_eq!(df.bits_per_sample, bits.as_u16());
    debug_assert_eq!((df.width, df.height), (frame.width, frame.height));
    let dpacked = df.strip_slice(&out.bytes);
    let back = match bits {
        Bits::B8 => crate::pack12::unpack8(dpacked, df.width, df.height)?,
        Bits::B10 => crate::pack12::unpack10(dpacked, df.width, df.height)?,
    };
    if back != mapped {
        anyhow::bail!(
            "derive round-trip mismatch: the re-parsed {}-bit strip is not the pinned mapping of the master ({} samples) — refusing to write",
            bits.as_u16(),
            back.len()
        );
    }
    // Atomic write (tmp + rename — the worker's contract: nothing
    // half-written on a crash).
    let tmp = dst.with_extension("dng.tmp");
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&tmp, &out.bytes).with_context(|| format!("write {}", tmp.display()))?;
    if let Err(err) = std::fs::rename(&tmp, dst) {
        let _ = std::fs::remove_file(&tmp); // atomicity: nothing half-written
        return Err(err).with_context(|| {
            format!("rename {} -> {}", tmp.display(), dst.display())
        });
    }
    Ok((buf.len() as u64, out.bytes.len() as u64))
}

/// The derive manifest file name for a clip: `<CLIP>.derive-manifest.tsv`
/// (the bake/checksums sidecar naming pattern).
pub fn manifest_name(clip: &str) -> String {
    format!("{clip}.derive-manifest.tsv")
}

/// Write the mandatory `<out_dir>/<clip>.derive-manifest.tsv` (v1): the
/// header block (bits_in → bits_out, the pinned formula, the tool
/// version, the frame count) + one row per derived frame (file, size,
/// whole-file sha256). `frames` = the (in, out) pairs `collect` built for
/// this run (rows = the derived frames' paths RELATIVE to `out_dir`,
/// sorted — the checksums row pattern). Deterministic: NO wall-clock
/// field (the recorded decision).
fn write_manifest(
    out_dir: &Path,
    clip: &str,
    bits: Bits,
    frames: &[(PathBuf, PathBuf)],
) -> Result<PathBuf> {
    if frames.is_empty() {
        bail!("no derived .DNG frames in output dir {}", out_dir.display());
    }
    let mut rows: Vec<(String, u64, String)> = Vec::with_capacity(frames.len());
    for (_src, p) in frames {
        let rel = p.strip_prefix(out_dir).unwrap_or(p);
        let rel_s = rel.to_string_lossy().replace("\\", "/");
        // The bounded reads — the size from the O(1) stat,
        // the sha streamed; the context wording is the pre-existing one.
        let size = std::fs::metadata(p)
            .map(|m| m.len())
            .with_context(|| format!("read {}", p.display()))?;
        let sha = crate::jxl::sha256_stream_path(p)
            .with_context(|| format!("read {}", p.display()))?;
        rows.push((rel_s, size, sha));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut tsv = String::new();
    tsv.push_str("derive-manifest\tv1\n");
    tsv.push_str("bits_in\t12\n");
    tsv.push_str(&format!("bits_out\t{}\n", bits.as_u16()));
    tsv.push_str(&format!("formula\t{}\n", bits.formula()));
    tsv.push_str(&format!("tool\tframeprism {}\n", env!("CARGO_PKG_VERSION")));
    tsv.push_str(&format!("frames\t{}\n", rows.len()));
    tsv.push_str("file\tsize\tsha256\n");
    for (name, size, sha) in &rows {
        tsv.push_str(&format!("{name}\t{size}\t{sha}\n"));
    }
    let path = out_dir.join(manifest_name(clip));
    // Atomic sidecar write (tmp + rename).
    let tmp = out_dir.join(format!(".{clip}.derive-manifest.tsv.tmp"));
    std::fs::write(&tmp, &tsv).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(path)
}

fn print_summary(args: &Args, report: &Report, manifest: Option<&Path>) {
    let done: Vec<&Outcome> = report
        .outcomes
        .iter()
        .filter(|o| matches!(o, Outcome::Done { .. }))
        .collect();
    let skipped = report
        .outcomes
        .iter()
        .filter(|o| matches!(o, Outcome::Skipped { .. }))
        .count();
    let failed = report
        .outcomes
        .iter()
        .filter(|o| matches!(o, Outcome::Failed { .. }))
        .count();
    let total_in: u64 = report
        .outcomes
        .iter()
        .filter_map(|o| match o {
            Outcome::Done { in_bytes, .. } => Some(*in_bytes),
            _ => None,
        })
        .sum();
    let total_out: u64 = report
        .outcomes
        .iter()
        .filter_map(|o| match o {
            Outcome::Done { out_bytes, .. } => Some(*out_bytes),
            _ => None,
        })
        .sum();
    println!();
    println!(
        "frameprism derive {} — {} → {} ({}-bit; {})",
        env!("CARGO_PKG_VERSION"),
        12,
        args.bits.as_u16(),
        args.bits.as_u16(),
        args.bits.formula()
    );
    println!("input : {} (read-only — the master is never rewritten)", args.input.display());
    println!("output: {}", args.output.display());
    if !report.sidecars_copied.is_empty() {
        println!("sidecars copied: {}", report.sidecars_copied.join(", "));
    }
    let skipped_names: Vec<String> = report
        .outcomes
        .iter()
        .filter_map(|o| match o {
            Outcome::Skipped { file } => Some(file.clone()),
            _ => None,
        })
        .collect();
    if !skipped_names.is_empty() {
        println!(
            "skipped (existing, --force to re-derive): {}",
            skipped_names.join(", ")
        );
    }
    if !done.is_empty() {
        println!();
        println!("frame  in_bytes (12b master)  out_bytes ({bits}b derived)  ratio",
            bits = args.bits.as_u16());
        for o in &done {
            if let Outcome::Done { file, in_bytes, out_bytes } = o {
                println!(
                    "{file:<40} {:>14} {:>14} {:>6.2}:1",
                    in_bytes,
                    out_bytes,
                    if *out_bytes > 0 {
                        *in_bytes as f64 / *out_bytes as f64
                    } else {
                        0.0
                    }
                );
            }
        }
    }
    println!(
        "\ntotal: {} frame(s) — {} done, {} skipped, {} failed; {} B (12b raw) → {} B ({}b raw) in {:.1}s",
        report.outcomes.len(),
        done.len(),
        skipped,
        failed,
        total_in,
        total_out,
        args.bits.as_u16(),
        report.elapsed_s
    );
    for o in &report.outcomes {
        if let Outcome::Failed { file, error } = o {
            println!("FAILED: {file}: {error}");
        }
    }
    if let Some(m) = manifest {
        println!("derive-manifest: {}", m.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic 12-bit strip-layout master (the minimal fp-shaped
    /// frame `tiff::read` accepts): IFD0 with exactly the required tags
    /// (all in-line), a packed strip of `samples`, zero tail. The header
    /// layout is fixed (the test asserts against it): IFD0 at 8, 8
    /// entries → the IFD struct spans [8..110), the strip starts at 110.
    /// `w`×`h` pixels (8×4 for the surgery byte tests; the FHD readout
    /// 1936×1090 for the derive_one e2e tests — `derive_one` pins the fp
    /// archive geometries, which `apply_derive_strip` does not).
    const IFD0_OFF: u64 = 8;
    const HEADER_END: usize = 110;
    const FHD_W: u32 = 1936;
    const FHD_H: u32 = 1090;
    /// Entry i starts at IFD0_OFF + 2 + 12*i; its 4-byte value field is
    /// at +8. Entries (tag order): 256 i=0, 257 i=1, 258 i=2, 259 i=3,
    /// 262 i=4, 277 i=5, 273 i=6, 279 i=7.
    const TAG258_VALUE_OFF: usize = 42;
    const TAG259_VALUE_OFF: usize = 54;
    const TAG273_VALUE_OFF: usize = 90;
    const TAG279_VALUE_OFF: usize = 102;

    fn synthetic_master_w(samples: &[u16], w: u32, h: u32, bps: u16) -> Vec<u8> {
        let strip = match bps {
            8 => crate::pack12::pack8(samples).unwrap(),
            10 => crate::pack12::pack10(samples, w).unwrap(),
            _ => crate::pack12::pack12(samples),
        };
        let strip_off = HEADER_END as u64;
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"II*\0");
        buf.extend_from_slice(&(IFD0_OFF as u32).to_le_bytes());
        buf.extend_from_slice(&8u16.to_le_bytes()); // entry count
        let mut push = |tag: u16, typ: u16, count: u32, v: u32| {
            buf.extend_from_slice(&tag.to_le_bytes());
            buf.extend_from_slice(&typ.to_le_bytes());
            buf.extend_from_slice(&count.to_le_bytes());
            buf.extend_from_slice(&v.to_le_bytes());
        };
        push(256, 4, 1, w); // ImageWidth LONG
        push(257, 4, 1, h); // ImageLength LONG
        push(258, 3, 1, bps as u32); // BitsPerSample SHORT
        push(259, 3, 1, 1); // Compression SHORT (none)
        push(262, 3, 1, 32803); // PhotometricInterpretation SHORT (CFA)
        push(277, 3, 1, 1); // SamplesPerPixel SHORT
        push(273, 4, 1, strip_off as u32); // StripOffsets LONG
        push(279, 4, 1, strip.len() as u32); // StripByteCounts LONG
        buf.extend_from_slice(&0u32.to_le_bytes()); // next IFD = 0
        buf.extend_from_slice(&strip);
        buf
    }

    /// The 8×4 test geometry (width a multiple of 4 — the 10-bit rule;
    /// even count — the 12-bit rule).
    fn synthetic_master(samples: &[u16], bps: u16) -> Vec<u8> {
        synthetic_master_w(samples, 8, 4, bps)
    }

    /// The FHD-archive-geometry master (1936×1090 — `derive_one`'s gate
    /// accepts it; 3.17 MB 12-bit strip — cheap enough for a test).
    fn synthetic_master_fhd(bps: u16) -> (Vec<u8>, Vec<u16>) {
        let pixels = ((FHD_W as u64) * (FHD_H as u64)) as usize;
        // Full-range deterministic pattern across the 12-bit domain.
        let samples: Vec<u16> = (0..pixels as u64)
            .map(|i| ((i * 2654435761) % 4096) as u16)
            .collect();
        (synthetic_master_w(&samples, FHD_W, FHD_H, bps), samples)
    }

    fn write_master(dir: &Path, name: &str, buf: &[u8]) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, buf).unwrap();
        p
    }

    #[test]
    fn derive_8b_header_and_pixels() {
        // FHD archive geometry (derive_one pins the fp readouts).
        let (master, s) = synthetic_master_fhd(12);
        let tmp = std::env::temp_dir().join(format!("frameprism_derive_8b_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let src = write_master(&tmp, "m.DNG", &master);
        let dst = tmp.join("out.DNG");
        let (in_b, out_b) = derive_one(&src, &dst, Bits::B8).unwrap();
        let pixels = ((FHD_W as u64) * (FHD_H as u64)) as usize;
        assert_eq!(in_b as usize, master.len());
        assert_eq!(out_b as usize, HEADER_END + pixels);
        let out = std::fs::read(&dst).unwrap();
        // Pixels: exactly v >> 4, 1 B/sample strip (2/3 of the 12-bit).
        let f = crate::tiff::read(&out).unwrap();
        assert_eq!(f.bits_per_sample, 8);
        assert_eq!(f.strip_count, pixels as u64);
        let back = crate::pack12::unpack8(f.strip_slice(&out), f.width, f.height).unwrap();
        assert_eq!(back, s.iter().map(|&v| (v >> 4) as u16).collect::<Vec<_>>());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn derive_10b_header_and_pixels() {
        let (master, s) = synthetic_master_fhd(12);
        let tmp = std::env::temp_dir().join(format!("frameprism_derive_10b_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let src = write_master(&tmp, "m.DNG", &master);
        let dst = tmp.join("out.DNG");
        derive_one(&src, &dst, Bits::B10).unwrap();
        let out = std::fs::read(&dst).unwrap();
        let pixels = ((FHD_W as u64) * (FHD_H as u64)) as usize;
        // Strip: 4-per-5-bytes (5/6 of the 12-bit strip length).
        assert_eq!(out.len(), HEADER_END + pixels * 5 / 4);
        let f = crate::tiff::read(&out).unwrap();
        assert_eq!(f.bits_per_sample, 10);
        assert_eq!(f.strip_count, pixels as u64 * 5 / 4);
        let back = crate::pack12::unpack10(f.strip_slice(&out), f.width, f.height).unwrap();
        assert_eq!(back, s.iter().map(|&v| (v >> 2) as u16).collect::<Vec<_>>());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The surgery byte contract: the header is copied verbatim EXCEPT
    /// exactly tag 258's 2-byte value (12 → bits_out) and tag 279's
    /// 4-byte value (→ the new strip length); the strip lands at the
    /// SAME offset (110), the zero tail is truncated.
    #[test]
    fn surgery_header_diff_is_exactly_258_and_279() {
        let s: Vec<u16> = (0..32u32).map(|i| ((i * 113) % 4096) as u16).collect();
        let master = synthetic_master(&s, 12);
        let frame = crate::tiff::read(&master).unwrap();
        for (bits, strip) in [
            (Bits::B8, crate::pack12::pack8(&s.iter().map(|&v| v >> 4).collect::<Vec<_>>()).unwrap()),
            (Bits::B10, crate::pack12::pack10(&s.iter().map(|&v| v >> 2).collect::<Vec<_>>(), 8).unwrap()),
        ] {
            let out = crate::surgery::apply_derive_strip(&master, &frame, bits.as_u16(), &strip)
                .expect("derive surgery on the synthetic master");
            assert_eq!(out.bytes.len(), HEADER_END + strip.len());
            // The patch offsets (the surgery's own layout arithmetic).
            let patched: std::collections::HashSet<usize> =
                [TAG258_VALUE_OFF, TAG258_VALUE_OFF + 1, TAG279_VALUE_OFF, TAG279_VALUE_OFF + 1,
                 TAG279_VALUE_OFF + 2, TAG279_VALUE_OFF + 3].into_iter().collect();            for i in 0..HEADER_END {
                if patched.contains(&i) {
                    continue;
                }
                assert_eq!(
                    out.bytes[i], master[i],
                    "header byte {i} must be verbatim ({}-bit run)",
                    bits.as_u16()
                );
            }
            assert_eq!(
                out.bytes[TAG258_VALUE_OFF..TAG258_VALUE_OFF + 2],
                bits.as_u16().to_le_bytes()
            );
            assert_eq!(
                u32::from_le_bytes(
                    out.bytes[TAG279_VALUE_OFF..TAG279_VALUE_OFF + 4].try_into().unwrap()
                ),
                strip.len() as u32
            );
            // tag 273 (StripOffsets) UNCHANGED — the strip is at 110 in
            // both files; tag 259 (Compression) stays 1 (uncompressed).
            assert_eq!(
                u32::from_le_bytes(
                    out.bytes[TAG273_VALUE_OFF..TAG273_VALUE_OFF + 4].try_into().unwrap()
                ),
                HEADER_END as u32,
                "StripOffsets must be unchanged (same strip offset)"
            );
            assert_eq!(
                u16::from_le_bytes(out.bytes[TAG259_VALUE_OFF..TAG259_VALUE_OFF + 2].try_into().unwrap()),
                1,
                "Compression must stay 1 (uncompressed)"
            );
        }
    }

    #[test]
    fn derive_refuses_non_12bit_master() {
        let s8: Vec<u16> = (0..32u32).map(|i| ((i * 13) % 256) as u16).collect();
        for bps in [8u16, 10] {
            let master = synthetic_master(&s8, bps);
            // An 8/10-bit master is NOT a derive source (the tool pins
            // 12-bit masters) — the named refusal.
            let frame = crate::tiff::read(&master).unwrap();
            assert_eq!(frame.bits_per_sample, bps);
            assert!(matches!(
                crate::surgery::apply_derive_strip(
                    &master,
                    &frame,
                    Bits::B8.as_u16(),
                    &crate::pack12::pack8(&s8).unwrap()
                ),
                Err(crate::surgery::SurgeryError::DeriveSourceNotTwelveBit(_))
            ));
        }
    }

    #[test]
    fn derive_formula_literals() {
        // The pinned formula strings.
        assert_eq!(Bits::B8.formula(), "12->8: v>>4 (no rounding, no dithering)");
        assert_eq!(
            Bits::B10.formula(),
            "12->10: v>>2 (no rounding, no dithering)"
        );
    }

    /// End-to-end run() on a scratch clip dir: the manifest is written
    /// with the pinned header block (no wall-clock field), deterministic
    /// across two runs into fresh dirs (same inputs → byte-identical
    /// tsv), and a non-12-bit mix-in is a NAMED per-frame refusal (rc=1,
    /// no manifest).
    #[test]
    fn run_e2e_manifest_and_refusals() {
        let (master12, _) = synthetic_master_fhd(12);
        let s8: Vec<u16> = (0..32u32).map(|i| ((i * 7) % 256) as u16).collect();
        let master8 = synthetic_master(&s8, 8);

        let tmp = std::env::temp_dir().join(format!("frameprism_derive_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let in_a = tmp.join("inA");
        let in_b = tmp.join("inB");
        let out1 = tmp.join("out1");
        let out2 = tmp.join("out2");
        let out_bad = tmp.join("out_bad");
        std::fs::create_dir_all(&in_a).unwrap();
        std::fs::create_dir_all(&in_b).unwrap();
        std::fs::write(in_a.join("f1.DNG"), &master12).unwrap();
        std::fs::write(in_b.join("f1.DNG"), &master12).unwrap();
        std::fs::write(in_b.join("f2_8bit.DNG"), &master8).unwrap();
        std::fs::write(in_a.join("side.wav"), b"wav").unwrap();

        let args = Args {
            input: in_a.clone(),
            output: out1.clone(),
            bits: Bits::B8,
            force: false,
        };
        let code = run(&args);
        assert_eq!(code, ExitCode::SUCCESS, "clean run must be rc=0");
        let m1 = out1.join("inA.derive-manifest.tsv");
        assert!(m1.exists(), "the derive-manifest must be written");
        let c1 = std::fs::read_to_string(&m1).unwrap();
        assert!(c1.starts_with(
            "derive-manifest\tv1\nbits_in\t12\nbits_out\t8\nformula\t12->8: v>>4 (no rounding, no dithering)\n"
        ));
        assert!(c1.contains(&format!("tool\tframeprism {}\n", env!("CARGO_PKG_VERSION"))));
        assert!(c1.contains("frames\t1\n"));
        // The derived frame + the copied sidecar are in the output dir.
        assert!(out1.join("f1.DNG").exists());
        assert!(out1.join("side.wav").exists());

        // Determinism: a second run over the identical input into a
        // fresh dir must yield a byte-identical manifest + a
        // byte-identical derived frame.
        let args2 = Args {
            input: in_a.clone(),
            output: out2.clone(),
            bits: Bits::B8,
            force: false,
        };
        assert_eq!(run(&args2), ExitCode::SUCCESS);
        let m2 = out2.join("inA.derive-manifest.tsv");
        let c2 = std::fs::read_to_string(&m2).unwrap();
        assert_eq!(c1, c2, "the manifest must be deterministic (no wall clock)");
        let d1 = std::fs::read(out1.join("f1.DNG")).unwrap();
        let d2 = std::fs::read(out2.join("f1.DNG")).unwrap();
        assert_eq!(d1, d2, "the derived frame must be deterministic");

        // The named refusal: the 8-bit mix-in frame fails named, rc=1,
        // and NO manifest is written.
        let args3 = Args {
            input: in_b,
            output: out_bad.clone(),
            bits: Bits::B8,
            force: false,
        };
        assert_eq!(run(&args3), ExitCode::from(1), "mix-in must be rc=1");
        assert!(!out_bad.join("inB.derive-manifest.tsv").exists());
        assert!(out_bad.join("f1.DNG").exists(), "the 12-bit frame still derives");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    //: the AppleDouble `._*` shadow robustness (the derived-tree
    // mirror collect — the same class as the encode source walker for
    // the derived surface: a `._*.DNG` shadow would be a phantom master
    // frame; the other `._*` shadows mirrored as sidecars).

    /// G2-10: the derived `collect` — the same shape as G2-7 for the
    /// derived surface (one real master + a `._<frame>.DNG` garbage
    /// shadow + a non-DNG `._*` shadow → ONLY the real master; no
    /// `._*` sidecar).
    #[test]
    fn spec7_g2_derived_collect_skips_the_apple_double_shadows() {
        let tmp = std::env::temp_dir().join(format!("frameprism-spec7-g2-derived-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("A001_20260101_000001.DNG"), b"master-bytes").unwrap();
        std::fs::write(tmp.join("._A001_20260101_000001.DNG"), vec![0xFFu8, 0xFE, 0xFF]).unwrap();
        std::fs::write(tmp.join("._notes.txt"), b"shadow-bytes").unwrap();
        let out_root = tmp.join("out");
        let mut frames: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut sidecars: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut visited = std::collections::HashSet::new();
        collect(&tmp, &tmp, &out_root, &mut frames, &mut sidecars, &mut visited).unwrap();
        assert_eq!(frames.len(), 1, "only the real master is a frame: {frames:?}");
        assert_eq!(frames[0].0, tmp.join("A001_20260101_000001.DNG"), "{frames:?}");
        assert!(sidecars.is_empty(), "no `._*` sidecar in the mirror: {sidecars:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
