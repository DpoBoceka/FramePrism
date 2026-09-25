//! CRC-32C checksums (reference parity: "Generate checksums" + "Run a
//! verification pass").
//!
//! CRC-32C (Castagnoli), as used by iSCSI / IEEE 802.3 (Ethernet FCS):
//!   poly 0x1EDC6F41, init 0xFFFFFFFF, refin TRUE, refout TRUE,
//!   xorout 0xFFFFFFFF.
//!
//! Table-driven: a 256-entry reflected table (table[i] = the CRC of the
//! single byte i) is built once at compile time in a `const fn`; the
//! digest walks the table per byte. Two independent implementations agree
//! on the test vectors (unit tests below): this Rust table implementation
//! and the standalone Python table reference `/tmp/crc32c_ref.py`
//! (reproducible: `.venv/bin/python /tmp/crc32c_ref.py`), cross-checked
//! against the `crc32c` C package (pip) in the project venv —
//! all three agree on every vector. Do NOT "correct" the vectors from
//! memory: the CRC-32 (CCITT) and CRC-32C check values are easy to mix up.
//!
//! TSV format (`<OUT_DIR>/<CLIP>.checksums.tsv`), one row per output
//! FRAME (the .DNG files this tool wrote; sidecars are copied through and
//! covered by the same byte-identical-copy guarantee, not by the tsv):
//!
//! v2 — the byte contract for v2 FILES:
//!
//!     file<TAB>size<TAB>crc32c<TAB>sha256
//!     A001_001_20260701_000001.DNG<TAB>2438040<TAB>01234567<TAB>9f86d0...
//!
//! (the 4th column is the whole-file sha256 — the out-of-band integrity
//! digest previously flagged as missing. `--verify-checksums` is UNCHANGED
//! externally: it parses the first three fields and TOLERATES the 4th;
//! `audit` (tool/src/audit/) is the sha256 consumer and refuses
//! 3-column sidecars.)
//!
//! v3 (-cart pull-in — additive): the
//! `--checksums` output now carries the versioned bake-manifest-v2
//! header (the magic line + `version: 3` + the additive `key: value`
//! headers) + the SAME 4 contract columns UNCHANGED in place and order,
//! with the per-frame camera-metadata columns from the DNG header
//! APPENDED:
//!
//!     # frameprism checksums sidecar
//!     version: 3
//!     tool_version: 0.4.0
//!     file size crc32c sha256 timecode framerate iso exposure
//!     A001_001_...000001.DNG 2438040 01234567 9f86d0... 22:22:36:13 24000/1000 100 
//!
//! (the columns are TAB-separated in the file — the sample above
//! is space-compressed; timecode = tag 51043 decoded HH:MM:SS:FF — the BCD layout;
//! framerate = tag 51044 as the rational "24000/1000"; iso = ExifIFD
//! 34855; exposure = ExifIFD 34853 — ABSENT on the fp, measured
//! (measured): a fixed EMPTY column, never an invented value). Old v2
//! sidecars stay auditable: `verify_checksums` + `audit` accept v2 AND
//! v3 (the v2 parse path is byte-untouched). v3 is written by NEW
//! `--checksums` runs only — no v2 file is ever rewritten. The J92
//! sidecar is in NO oracle (oracle10 = DNGs only) and v3 is
//! deterministic (no wall clock — the byte-identity contract on re-
//! runs holds).
//!
//! v4 content (the decision): the
//! per-frame QC/exposure columns ride the additive `<CLIP>.qc.tsv`
//! record next to this file (see the qc module) — this file stays v3
//! byte-identical (the byte contract: the read-only strict parsers
//! accept exactly these columns).
//!
//! `file` = the output frame's path RELATIVE to `out_dir` (POSIX separators;
//! a top-level frame is just its basename — byte-identical to the
//! pre-recursion tsv, so existing files stay valid), `size` = file size in
//! bytes, `crc32c` = lowercase 8-hex digest of the whole file. The walk
//! recurses into clip subfolders, mirroring the worker's `collect()`
//! (review: nested frames were silently uncovered before). Rows are
//! sorted by path. Deterministic: same inputs → byte-identical tsv.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Reflected (LSB-first) CRC-32C table: table[i] = digest of byte i.
/// Built at compile time; `REFLECTED_POLY` is the bit-reversal of
/// 0x1EDC6F41 (the "reversed" polynomial used with refin/refout=true).
const REFLECTED_POLY: u32 = 0x82_F6_3B_78;

const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        // 8 iterations: one per bit of the byte (reflected = LSB first).
        let mut k = 0;
        while k < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ REFLECTED_POLY
            } else {
                crc >> 1
            };
            k += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// pub(crate): the combined streaming digest
/// (jxl.rs `digest_stream_path`) reuses the table — the single
/// home for the CRC-32C algorithm stays in this module.
pub(crate) const TABLE: [u32; 256] = build_table();

/// CRC-32C of `data` (init 0xFFFFFFFF, xorout 0xFFFFFFFF).
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = (crc >> 8) ^ TABLE[((crc ^ b as u32) & 0xFF) as usize];
    }
    crc ^ 0xFFFF_FFFF
}

/// CRC-32C of a file, streaming (the bounded read:
/// `SHA256_CHUNK`-sized reads into a re-used buffer, never the
/// whole file in a `Vec` ). Returns
/// the byte count + the CRC. The io error propagates RAW — the
/// caller wraps it with the site's existing context wording.
pub fn crc32c_stream_path(path: &Path) -> std::io::Result<(u64, u32)> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut crc = 0xFFFF_FFFFu32;
    let mut total = 0u64;
    let mut buf = vec![0u8; crate::jxl::SHA256_CHUNK];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for &b in &buf[..n] {
            crc = (crc >> 8) ^ TABLE[((crc ^ b as u32) & 0xFF) as usize];
        }
        total += n as u64;
    }
    Ok((total, crc ^ 0xFFFF_FFFF))
}

/// CRC-32C of a whole file (the streaming form — the
/// `read {}` context wording is byte-identical to the pre-existing
/// one-shot read).
pub fn crc32c_file(path: &Path) -> Result<(u64, u32)> {
    let (size, crc) =
        crc32c_stream_path(path).with_context(|| format!("read {}", path.display()))?;
    Ok((size, crc))
}

/// The checksum file name for a clip: `<CLIP>.checksums.tsv`.
pub fn checksums_name(clip: &str) -> String {
    format!("{clip}.checksums.tsv")
}

/// The v3 sidecar magic line (the bake-manifest-v2
/// pattern; `audit` routes on it: v2 files never start with it, so the
/// v2 parse path is byte-untouched).
pub const V3_MAGIC: &str = "# frameprism checksums sidecar";

/// The v3 column line: the 4 v2 contract columns UNCHANGED in place
/// and order + the per-frame camera-metadata columns APPENDED
/// (additive; a future v4 appends further columns, never
/// reorders the 4).
pub const V3_COLUMNS: &str =
    "file\tsize\tcrc32c\tsha256\ttimecode\tframerate\tiso\texposure";

/// The clip name for the checksum tsv, from the input/output directory
/// (review: ONE shared helper for `--checksums` and
/// `--verify-checksums` — a trailing-slash input used to derive "" in the
/// verify pass and "clip" in the worker, so the two looked for different
/// tsv files. Empty names are refused.)
pub fn clip_name(dir: &Path) -> Result<String> {
    dir.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot derive a clip name from directory {} (trailing slash or empty path)",
                dir.display()
            )
        })
}

/// Recursively collect the .DNG frames under `dir` (mirroring the worker's
/// `collect()` — review: the top-level-only walk silently missed
/// frames in clip subfolders). Symlinked entries are skipped (no cycles,
/// no escapes). Returns (relative path with POSIX separators, absolute
/// path) pairs; a top-level frame's relative path is its basename, so a
/// flat output dir yields rows byte-identical to the pre-recursion tsv.
/// Recurse `out_dir` collecting the `.DNG` frames as (rel, path) pairs
/// (POSIX rel, the collect() symlink discipline — the sidecar's walk,
/// pub for the final-sidecar union: the sidecar covers EVERY
/// output frame, run frames or not).
pub fn walk_dng(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))? {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue; // refuse symlinked entries (cycle/escape guard)
        }
        //: the AppleDouble shadow is never a frame — skip (the
        // `--checksums` walk would otherwise emit phantom sidecar rows
        // on a shadowed tree).
        if entry.file_name().to_str().is_some_and(crate::is_apple_double) {
            continue;
        }
        if p.is_dir() {
            walk_dng(&p, root, out)?;
        } else if p.is_file() {
            let is_dng = p
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("dng"))
                .unwrap_or(false);
            if is_dng {
                let rel = p.strip_prefix(root).unwrap_or(&p);
                let rel_s = rel.to_string_lossy().replace("\\", "/");
                out.push((rel_s, p));
            }
        }
    }
    Ok(())
}

/// The v3 metadata columns of one row, pre-formatted (timecode /
/// framerate / iso / exposure — the absent-tag shape is the fixed
/// EMPTY string, the write_checksums contract). One formatter for
/// BOTH writers (the end-of-run `write_checksums` walk + the 
/// incremental per-frame append) — the byte parity is structural.
pub fn meta_columns(meta: &crate::worker::FrameMetadata) -> [String; 4] {
    [
        meta.timecode.map(|t| t.display()).unwrap_or_default(),
        meta
            .framerate
            .map(|(n, d)| format!("{n}/{d}"))
            .unwrap_or_default(),
        meta.iso.clone().unwrap_or_default(),
        meta
            .exposure
            .map(|(n, d)| format!("{n}/{d}"))
            .unwrap_or_default(),
    ]
}

/// One v3 sidecar row as its on-disk line (the 4 contract columns +
/// the 4 pre-formatted metadata columns, `\n`-terminated). The single
/// row-shape source for the incremental append (worker.rs) and the
/// final canonical write (the byte parity is structural).
pub fn row_line(
    file: &str,
    size: u64,
    crc: u32,
    sha: &str,
    meta: &[String; 4],
) -> String {
    format!(
        "{file}\t{size}\t{crc:08x}\t{sha}\t{}\t{}\t{}\t{}\n",
        meta[0], meta[1], meta[2], meta[3]
    )
}

/// Write the v3 sidecar file from pre-FORMATTED rows (the
/// versioned header + the rows SORTED BY REL (the deterministic byte
/// order — same inputs → byte-identical tsv, the write_checksums
/// contract). The incremental writer's final canonical rewrite and the
/// end-of-run walk share this byte source.
pub fn write_sidecar(
    out_dir: &Path,
    clip: &str,
    rows: &[(String, u64, u32, String, [String; 4])],
) -> Result<PathBuf> {
    let mut rows: Vec<_> = rows.to_vec();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut tsv = String::new();
    tsv.push_str(V3_MAGIC);
    tsv.push('\n');
    tsv.push_str(&format!("version: 3\ntool_version: {}\n", env!("CARGO_PKG_VERSION")));
    tsv.push_str(V3_COLUMNS);
    tsv.push('\n');
    for (name, size, crc, sha, meta) in &rows {
        tsv.push_str(&row_line(name, *size, *crc, sha, meta));
    }
    let path = out_dir.join(checksums_name(clip));
    // (/): the canonical final write is temp + rename — a
    // kill mid-write leaves the previous complete sidecar in place
    // (the rename never completed), never a torn final file. The tmp
    // is a named hidden pattern (resume::is_temp_name) — a leftover
    // from a killed rewrite is cleaned up + named on the next resume.
    let tmp = out_dir.join(format!(".{}.checksums.tsv.tmp", clip));
    std::fs::write(&tmp, tsv).with_context(|| format!("write {}", tmp.display()))?;
    if let Err(err) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err).with_context(|| {
            format!("rename {} -> {}", tmp.display(), path.display())
        });
    }
    Ok(path)
}

/// Write `<out_dir>/<clip>.checksums.tsv` covering every `.DNG` frame in
/// `out_dir` and its subfolders (review: recursive, rows = relative
/// paths, sorted; flat dirs stay byte-identical to the old tsv). v3
/// the versioned header + the 4 v2 contract
/// columns (one read per file — crc32c + sha256 over the same buffer)
/// and the additive per-frame camera-metadata columns (the DNG header —
/// `worker::read_frame_metadata`: timecode / framerate / iso /
/// exposure; an absent tag is a fixed EMPTY column, a corrupt header
/// is a named hard error — the audit philosophy). Returns the tsv
/// path.
pub fn write_checksums(out_dir: &Path, clip: &str) -> Result<PathBuf> {
    let mut found: Vec<(String, PathBuf)> = Vec::new();
    walk_dng(out_dir, out_dir, &mut found)?;
    if found.is_empty() {
        bail!("no .DNG frames in output dir {}", out_dir.display());
    }
    let mut rows: Vec<(String, u64, u32, String, crate::worker::FrameMetadata)> =
        Vec::with_capacity(found.len());
    for (rel, p) in &found {
        // The streaming triple (size + crc + sha in one
        // bounded pass — never the whole frame in a `Vec`); the
        // `read {}` context is the pre-existing one.
        let (size, sha, crc) = crate::jxl::digest_stream_path(p)
            .with_context(|| format!("read {}", p.display()))?;
        // v3: the per-frame camera metadata from the OUTPUT frame's
        // header (the lossless surgery keeps the header bytes
        // verbatim — the source's tags, re-read from what this tool
        // wrote; a corrupt header is a named hard error — the audit
        // philosophy; the read_frame_metadata error is already fully
        // path-qualified).
        let meta = crate::worker::read_frame_metadata(p)
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        rows.push((rel.clone(), size, crc, sha, meta));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let formatted: Vec<(String, u64, u32, String, [String; 4])> = rows
        .iter()
        .map(|(rel, size, crc, sha, meta)| {
            (
                rel.clone(),
                *size,
                *crc,
                sha.clone(),
                meta_columns(meta),
            )
        })
        .collect();
    write_sidecar(out_dir, clip, &formatted)
}

/// One row of the verification result.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckRow {
    pub file: String,
    pub size: u64,
    pub crc: u32,
    pub ok: bool,
    pub problem: Option<String>,
}

/// Verification pass (reference's "Run a verification pass"): re-read every
/// row of `<out_dir>/<clip>.checksums.tsv`, recompute size + CRC-32C of
/// the on-disk file, and report per-row results. Missing files, size
/// mismatches and CRC mismatches all count as failures (the caller exits
/// non-zero on any failure). Accepts the v2 AND v3 sidecars (v3 =
/// the magic + the header block + the 4 v2 columns + the appended
/// metadata columns — the verify pass parses the first three row fields
/// and TOLERATES the rest; the v2 file format stays byte-identical and
/// parses through the SAME permissive rule set).
pub fn verify_checksums(out_dir: &Path, clip: &str) -> Result<Vec<CheckRow>> {
    let tsv_path = out_dir.join(checksums_name(clip));
    let tsv = std::fs::read_to_string(&tsv_path)
        .with_context(|| format!("read checksums file {}", tsv_path.display()))?;
    let mut rows = Vec::new();
    for (i, line) in tsv.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        // The header block: the v2 column line + the v3 magic/version/
        // tool_version lines + the v3 column line — every non-row line
        // either starts with `file\t` (a column line) or carries no tab
        // (the v3 magic + `key: value` headers). Rows always carry tabs.
        if line.starts_with("file\t") || !line.contains('\t') {
            continue;
        }
        let mut parts = line.split('\t');
        let file = parts.next().unwrap_or("").to_string();
        let size: u64 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("bad size field in line {}: {line:?}", i + 1))?;
        let crc = u32::from_str_radix(
            parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("bad crc field in line {}: {line:?}", i + 1))?,
            16,
        )
        .map_err(|_| anyhow::anyhow!("bad crc field in line {}: {line:?}", i + 1))?;
        let path = out_dir.join(&file); // relative rows (nested clips) + basenames (flat)
        let (ok, problem) = if !path.exists() {
            (false, Some("file missing".to_string()))
        } else {
            let (size2, crc2) =
                crc32c_file(&path).with_context(|| format!("re-read {}", path.display()))?;
            if size2 != size {
                (
                    false,
                    Some(format!("size mismatch: tsv {size}, disk {size2}")),
                )
            } else if crc2 != crc {
                (
                    false,
                    Some(format!("crc32c mismatch: tsv {crc:08x}, disk {crc2:08x}")),
                )
            } else {
                (true, None)
            }
        };
        rows.push(CheckRow {
            file,
            size,
            crc,
            ok,
            problem,
        });
    }
    if rows.is_empty() {
        bail!("no rows in {}", tsv_path.display());
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The HH:MM:SS:FF shape check (the timecode column; std-only — no
    /// regex crate: the std-only posture).
    fn is_hmsf(s: &str) -> bool {
        let parts: Vec<&str> = s.split(':').collect();
        parts.len() == 4
            && parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_digit()))
            && (parts[3].parse::<u8>().map(|f| f < 24).unwrap_or(false))
            && (parts[2].parse::<u8>().map(|v| v < 60).unwrap_or(false))
            && (parts[1].parse::<u8>().map(|v| v < 60).unwrap_or(false))
            && (parts[0].parse::<u8>().map(|v| v < 24).unwrap_or(false))
    }

    /// Test vectors from TWO independent implementations:
    /// (1) the standalone Python table reference /tmp/crc32c_ref.py — a
    /// separately written table-driven implementation, and
    /// (2) the `crc32c` C package (pip) installed in the project venv.
    /// All three agree on every value below; the Rust implementation is
    /// what is asserted.
    #[test]
    fn crc32c_independent_vectors() {
        assert_eq!(crc32c(b"123456789"), 0xE3_06_92_83, "CRC-32C check value");
        assert_eq!(crc32c(b""), 0x00_00_00_00);
        assert_eq!(crc32c(b"ibm370"), 0x52_9F_25_10);
        assert_eq!(crc32c(b"\x00\x00\x00\x00"), 0x48_67_4B_C7);
        assert_eq!(crc32c(b"\xff\xff\xff\xff"), 0xFF_FF_FF_FF);
    }

    #[test]
    fn crc32c_longer_vector() {
        // 4 KiB of 0..255 repeating: a non-trivial stream length that
        // exercises the per-byte loop well beyond the table index range.
        let data: Vec<u8> = (0..4096u32).map(|i| (i & 0xFF) as u8).collect();
        // Vector from the Python reference (same input): 0x9c71fe32
        // (re-checked against the pip `crc32c` package — both agree).
        assert_eq!(crc32c(&data), 0x9C_71_FE_32);
    }

    #[test]
    fn checksums_roundtrip_real_file() {
        // Real-file roundtrip: checksum a real A001 ORIGINAL (read-only),
        // write the tsv to a temp dir next to a copy... the original is
        // immutable — checksum it IN PLACE (reads only) and verify against
        // the on-disk file.
        let p = Path::new("../testdata/originals/A001_001/A001_001_20260701_000001.DNG");
        if !p.exists() {
            eprintln!("skip: no testdata corpus");
            return;
        }
        let (size, crc) = crc32c_file(p).unwrap();
        assert_eq!(size, 12_630_528, "A001 f1 size drifted");
        // The tsv machinery: build a scratch dir with a copy of the file
        // (never touching the original), write + verify + tamper + verify.
        let tmp = std::env::temp_dir().join("frameprism_checksums_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let name = p.file_name().unwrap().to_os_string();
        std::fs::copy(p, tmp.join(&name)).unwrap();
        // write_checksums expects the output dir + clip name; use the
        // scratch dir as "out_dir" and the file's own name row.
        let tsv = write_checksums(&tmp, "scratch").unwrap();
        let content = std::fs::read_to_string(&tsv).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // v3: the magic + version + tool_version headers +
        // the 8-column line + one row.
        assert_eq!(lines[0], V3_MAGIC, "the v3 magic line: {content:?}");
        assert_eq!(lines[1], "version: 3");
        assert!(lines[2].starts_with("tool_version: "), "the additive tool_version header: {content:?}");
        assert_eq!(lines[3], V3_COLUMNS, "the v3 column line");
        assert_eq!(lines.len(), 5, "headers + one row: {content:?}");
        let row = lines[4].split('\t').collect::<Vec<_>>();
        assert_eq!(row.len(), 8, "the 8 v3 columns: {content:?}");
        assert_eq!(row[0], name.to_string_lossy());
        assert_eq!(row[1], size.to_string());
        assert_eq!(row[2], format!("{crc:08x}"));
        assert_eq!(row[2].len(), 8, "crc must be 8-hex");
        // The additive metadata columns: the fp's f1 carries
        // tag 51043 (the fp always has it) — the timecode
        // column is HH:MM:SS:FF; the others are absent-or-well-formed
        // (never invented values).
        assert!(
            row[4].is_empty() || is_hmsf(row[4]),
            "the timecode column is HH:MM:SS:FF or empty (absent tag): {content:?}"
        );
        assert!(
            row[5].is_empty() || row[5].contains('/'),
            "the framerate column is NUM/DEN or empty: {content:?}"
        );
        assert!(row[6].chars().all(|c| c.is_ascii_digit() || c == ','), "iso column: {content:?}");
        assert!(row[7].is_empty() || row[7].contains('/'), "exposure column: {content:?}");
        // Verification pass: clean.
        let rows = verify_checksums(&tmp, "scratch").unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].ok, "clean file must verify: {:?}", rows[0].problem);
        assert_eq!(rows[0].crc, crc);
        // Tamper (scratch copy only): flip one byte → CRC mismatch.
        let f = tmp.join(&name);
        let mut buf = std::fs::read(&f).unwrap();
        buf[100_000] ^= 0x01;
        std::fs::write(&f, buf).unwrap();
        let rows = verify_checksums(&tmp, "scratch").unwrap();
        assert!(!rows[0].ok, "tampered file must fail");
        assert!(rows[0]
            .problem
            .as_deref()
            .unwrap_or("")
            .contains("crc32c mismatch"));
        // Missing file → fail.
        std::fs::remove_file(&f).unwrap();
        let rows = verify_checksums(&tmp, "scratch").unwrap();
        assert!(!rows[0].ok);
        assert_eq!(rows[0].problem.as_deref(), Some("file missing"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// nested clip subfolders are covered. The tsv rows are
    /// relative paths (POSIX separators), verification resolves them
    /// against the output dir, and a flat dir stays basename-only.
    /// (the frames are MINIMAL SYNTHETIC TIFFs — write_checksums
    /// v3 reads each frame's header for the metadata columns; the
    /// flat-dir expected content is the v3 format.)
    #[test]
    fn checksums_nested_subfolders() {
        use crate::worker::synth_tiff;
        let tmp = std::env::temp_dir().join("frameprism_checksums_nested_test");
        let _ = std::fs::remove_dir_all(&tmp);
        let clip = tmp.join("A001_001");
        std::fs::create_dir_all(clip.join("sub/deep")).unwrap();
        // One top-level frame (full metadata), one one-level-deep + one
        // two-levels-deep (TC only — the fixed-empty columns), plus a
        // non-DNG file that must NOT appear.
        std::fs::write(
            clip.join("f1.DNG"),
            synth_tiff((1, 7, 3, 22), Some((24000, 1000)), Some(100), Some((1, 125))),
        )
        .unwrap();
        std::fs::write(clip.join("sub/f2.DNG"), synth_tiff((2, 0, 0, 0), None, None, None)).unwrap();
        std::fs::write(clip.join("sub/deep/f3.DNG"), synth_tiff((3, 0, 0, 0), None, None, None)).unwrap();
        std::fs::write(clip.join("sidecar.wav"), b"wav").unwrap();

        let tsv = write_checksums(&clip, "A001_001").unwrap();
        let content = std::fs::read_to_string(&tsv).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines[0], V3_MAGIC);
        assert_eq!(lines.len(), 7, "4 header lines + 3 nested rows: {content:?}");
        // Sorted relative paths (lexicographic: "sub/deep/..." < "sub/f2"),
        // POSIX separators.
        let r1: Vec<&str> = lines[4].split('\t').collect();
        let r2: Vec<&str> = lines[5].split('\t').collect();
        let r3: Vec<&str> = lines[6].split('\t').collect();
        assert_eq!(r1[0], "f1.DNG");
        assert_eq!(r2[0], "sub/deep/f3.DNG");
        assert_eq!(r3[0], "sub/f2.DNG");
        // The additive v3 columns: f1's full metadata is
        // decoded; the TC-only frames carry the fixed-empty columns.
        assert_eq!(r1[4], "22:03:07:01", "the decoded timecode (BCD): {content:?}");
        assert_eq!(r1[5], "24000/1000");
        assert_eq!(r1[6], "100");
        assert_eq!(r1[7], "1/125");
        assert_eq!(r2[4], "00:00:00:03");
        assert!(r2[5..8].iter().all(|c| c.is_empty()), "absent tags = empty columns");
        assert_eq!(r3[4], "00:00:00:02");
        assert!(
            !content.contains("sidecar.wav"),
            "non-DNG files are not rows"
        );

        // Verification pass resolves relative rows: clean.
        let rows = verify_checksums(&clip, "A001_001").unwrap();
        assert_eq!(rows.len(), 3);
        assert!(
            rows.iter().all(|r| r.ok),
            "clean tree must verify: {content:?}"
        );

        // Tamper a NESTED file → that row fails.
        let mut buf = std::fs::read(clip.join("sub/f2.DNG")).unwrap();
        buf[0] ^= 0x01;
        std::fs::write(clip.join("sub/f2.DNG"), buf).unwrap();
        let rows = verify_checksums(&clip, "A001_001").unwrap();
        let bad: Vec<&CheckRow> = rows.iter().filter(|r| !r.ok).collect();
        assert_eq!(bad.len(), 1, "only the tampered nested row fails");
        assert_eq!(bad[0].file, "sub/f2.DNG");

        // Flat-dir format: a dir with only top-level frames yields
        // basename-only rows (the pre-recursion row shape), in the v3
        // envelope (the metadata columns for the two frames).
        use crate::worker::synth_tiff as st;
        let flat = std::env::temp_dir().join("frameprism_checksums_flat_test");
        let _ = std::fs::remove_dir_all(&flat);
        std::fs::create_dir_all(&flat).unwrap();
        std::fs::write(flat.join("a.DNG"), st((0, 0, 0, 0), None, None, None)).unwrap();
        std::fs::write(flat.join("b.DNG"), st((1, 0, 0, 0), Some((24000, 1000)), Some(100), None)).unwrap();
        let tsv = write_checksums(&flat, "flat").unwrap();
        let content = std::fs::read_to_string(&tsv).unwrap();
        let fa = st((0, 0, 0, 0), None, None, None);
        let fb = st((1, 0, 0, 0), Some((24000, 1000)), Some(100), None);
        let sa = crate::jxl::sha256_hex(&fa);
        let sb = crate::jxl::sha256_hex(&fb);
        let expected = format!(
            "{V3_MAGIC}\nversion: 3\ntool_version: {ver}\n{V3_COLUMNS}\na.DNG\t{alen}\t{a:08x}\t{sa}\t00:00:00:00\t\t\t\nb.DNG\t{blen}\t{b:08x}\t{sb}\t00:00:00:01\t24000/1000\t100\t\n",
            ver = env!("CARGO_PKG_VERSION"),
            alen = fa.len(),
            a = crc32c(&fa),
            blen = fb.len(),
            b = crc32c(&fb),
        );
        assert_eq!(
            content, expected,
            "flat dir rows are basename-only with the v3 columns"
        );
        let _ = std::fs::remove_dir_all(&flat);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// `--verify-checksums` accepts the OLD v2 sidecars
    /// (byte-identical, no magic, 4 columns) AND the new v3 ones — the
    /// old files stay auditable; the row parse is the first-3-fields
    /// contract either way (the v3 row's extra columns are tolerated).
    #[test]
    fn verify_accepts_v2_and_v3_sidecars() {
        use crate::worker::synth_tiff;
        let tmp = std::env::temp_dir().join("frameprism_checksums_v2v3_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let frame = synth_tiff((4, 0, 0, 0), Some((24000, 1000)), Some(100), None);
        std::fs::write(tmp.join("f.DNG"), &frame).unwrap();
        // The v3 sidecar via the writer: verify reads it.
        write_checksums(&tmp, "clip").unwrap();
        let rows = verify_checksums(&tmp, "clip").unwrap();
        assert_eq!(rows.len(), 1, "the v3 sidecar parses (1 row)");
        assert!(rows[0].ok, "the v3 row verifies: {:?}", rows[0].problem);
        // A hand-written v2 sidecar (the legacy byte shape): the
        // SAME verify pass parses it (the legacy-auditable proof at the
        // unit level; E3c's `audit` run is the end-to-end one).
        let tmp2 = std::env::temp_dir().join("frameprism_checksums_v2_legacy_test");
        let _ = std::fs::remove_dir_all(&tmp2);
        std::fs::create_dir_all(&tmp2).unwrap();
        std::fs::write(tmp2.join("f.DNG"), &frame).unwrap();
        let size = frame.len();
        let crc = crc32c(&frame);
        let sha = crate::jxl::sha256_hex(&frame);
        std::fs::write(
            tmp2.join("clip.checksums.tsv"),
            format!("file\tsize\tcrc32c\tsha256\nf.DNG\t{size}\t{crc:08x}\t{sha}\n"),
        )
        .unwrap();
        let rows = verify_checksums(&tmp2, "clip").unwrap();
        assert_eq!(rows.len(), 1, "the v2 sidecar parses (1 row)");
        assert!(rows[0].ok, "the v2 row verifies: {:?}", rows[0].problem);
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&tmp2);
    }

    /// the clip name helper — shared by `--checksums` and
    /// `--verify-checksums`; refuses empty/trailing-slash inputs.
    #[test]
    fn clip_name_helper() {
        assert_eq!(clip_name(Path::new("/in/A001_001")).unwrap(), "A001_001");
        assert_eq!(clip_name(Path::new("out/A001_001/")).unwrap(), "A001_001");
        assert!(clip_name(Path::new("/")).is_err(), "root has no clip name");
        assert!(
            clip_name(Path::new("")).is_err(),
            "empty path has no clip name"
        );
    }

    /// (/, G4): the canonical final sidecar write is temp +
    /// rename — a reader racing the write observes ONLY the old bytes
    /// or the complete new bytes (never a torn final file), and the
    /// hidden tmp is gone after success.
    #[test]
    fn write_sidecar_is_temp_plus_rename_atomic() {
        let base =
            std::env::temp_dir().join(format!("frameprism_sidecar_atomic_{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let clip = "clip";
        let path = base.join(checksums_name(clip));
        // A big sidecar so the write spans multiple page writes.
        let mk_rows = |i: u32| -> (String, u64, u32, String, [String; 4]) {
            let name = format!("A001_001_{:08x}.DNG", i);
            let sha: String = std::iter::repeat('a').take(64).collect();
            (
                name,
                12_000_000,
                i as u32,
                sha,
                [String::new(), String::new(), String::new(), String::new()],
            )
        };
        let old_rows: Vec<_> = (0..20_000).map(mk_rows).collect();
        write_sidecar(&base, clip, &old_rows).unwrap();
        let old = std::fs::read(&path).unwrap();
        let new_rows: Vec<_> = (0..20_000).map(|i| {
            let mut r = mk_rows(i);
            r.1 = 9_999_999; // a visible change in every row
            r
        }).collect();
        // The racer: poll the file; every observation is either the old
        // bytes or (after the rename) the complete new bytes.
        let (tx, rx) = std::sync::mpsc::channel::<Vec<Vec<u8>>>();
        let path_clone = path.clone();
        let reader = std::thread::spawn(move || {
            let mut observed: Vec<Vec<u8>> = Vec::new();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                if let Ok(b) = std::fs::read(&path_clone) {
                    observed.push(b);
                }
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
            tx.send(observed).unwrap();
        });
        std::thread::sleep(std::time::Duration::from_millis(30));
        let new_bytes = {
            let mut tsv = String::new();
            tsv.push_str(V3_MAGIC);
            tsv.push('\n');
            tsv.push_str(&format!("version: 3\ntool_version: {}\n", env!("CARGO_PKG_VERSION")));
            tsv.push_str(V3_COLUMNS);
            tsv.push('\n');
            for r in &new_rows {
                tsv.push_str(&row_line(&r.0, r.1, r.2, &r.3, &r.4));
            }
            tsv.into_bytes()
        };
        write_sidecar(&base, clip, &new_rows).unwrap();
        drop(reader);
        let observed = rx.recv().unwrap();
        assert!(
            observed.len() > 3,
            "the reader sampled the file (got {} observations)",
            observed.len()
        );
        for obs in &observed {
            assert!(
                *obs == old || *obs == new_bytes,
                "a torn final file was observed ({} bytes — neither the old {} nor the new {})",
                obs.len(),
                old.len(),
                new_bytes.len()
            );
        }
        // Success: the hidden tmp is gone.
        assert!(!base.join(format!(".{}.checksums.tsv.tmp", clip)).exists());
        assert_eq!(std::fs::read(&path).unwrap(), new_bytes);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// (/, G4): a write that fails (a simulated kill before
    /// the bytes land) leaves NO final file — the previous complete
    /// sidecar stays in place.
    #[test]
    fn write_sidecar_failure_leaves_no_final_file() {
        let base = std::env::temp_dir().
            join(format!("frameprism_sidecar_fail_{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let clip = "clip";
        let path = base.join(checksums_name(clip));
        let rows: Vec<(String, u64, u32, String, [String; 4])> = vec![(
            "a.DNG".to_string(),
            4,
            0x1234_5678,
            std::iter::repeat('b').take(64).collect(),
            [String::new(), String::new(), String::new(), String::new()],
        )];
        write_sidecar(&base, clip, &rows).unwrap();
        let before = std::fs::read(&path).unwrap();
        // The failure: a non-existent output dir (the write never lands).
        let missing = base.join("no-such-dir").join(checksums_name(clip));
        let err = write_sidecar(&base.join("no-such-dir"), clip, &rows).unwrap_err();
        assert!(err.to_string().contains("no-such-dir"), "{}", err);
        assert!(!missing.exists(), "no final file on failure");
        assert!(!base.join("no-such-dir").join(format!(".{}.checksums.tsv.tmp", clip)).exists());
        // The previous complete sidecar is untouched.
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let _ = std::fs::remove_dir_all(&base);
    }

    //: the AppleDouble `._*` shadow robustness (the end-of-run
    // `--checksums` sidecar walk — a `._*.DNG` shadow would be a
    // phantom sidecar row on a shadowed tree).

    /// G2-9: the `--checksums` walk — real frame + `._` shadow → 1 row
    /// (the real one).
    #[test]
    fn spec7_g2_walk_dng_skips_the_shadow() {
        let tmp = std::env::temp_dir().join(format!("frameprism-spec7-g2-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("A001_20260101_000001.DNG"), b"frame-bytes").unwrap();
        std::fs::write(tmp.join("._A001_20260101_000001.DNG"), vec![0xFFu8, 0xFE, 0xFF]).unwrap();
        let mut out: Vec<(String, PathBuf)> = Vec::new();
        walk_dng(&tmp, &tmp, &mut out).unwrap();
        assert_eq!(out.len(), 1, "real frame + shadow → 1 row: {out:?}");
        assert_eq!(out[0].0, "A001_20260101_000001.DNG", "the top-level rel is the basename: {out:?}");
        assert_eq!(out[0].1, tmp.join("A001_20260101_000001.DNG"), "{out:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
    // The streaming CRC-32C VALUE identity: the chunked
    // digest equals the one-shot digest at the chunk-boundary sizes
    // (the position-dependent fixture — an offset/chunk-boundary
    // bug flips the crc).
    #[test]
    fn crc32c_stream_value_identity() {
        use crate::jxl::SHA256_CHUNK;
        let base = std::env::temp_dir().join(format!(
            "frameprism_crc_stream_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let make = |len: usize| {
            let mut b = vec![0u8; len];
            for (i, x) in b.iter_mut().enumerate() {
                *x = ((i % 251) as u8) ^ ((i / 256) as u8);
            }
            b
        };
        for (label, len) in [
            ("empty", 0usize),
            ("one", 1),
            ("127", 127),
            ("128", 128),
            ("129", 129),
            ("255", 255),
            ("small", 1000),
            ("chunk", SHA256_CHUNK),
            ("chunk+1", SHA256_CHUNK + 1),
        ] {
            let fixture = base.join(format!("fixture-{label}.bin"));
            let bytes = make(len);
            std::fs::write(&fixture, &bytes).unwrap();
            let (size, crc) = crc32c_stream_path(&fixture).unwrap();
            assert_eq!(
                (size, crc),
                (len as u64, crc32c(&bytes)),
                "the streaming crc must equal the one-shot crc ({label}, {len} B)"
            );
            // The anyhow wrapper (the `crc32c_file` shape)
            // agrees.
            assert_eq!(crc32c_file(&fixture).unwrap(), (len as u64, crc32c(&bytes)));
        }
        let _ = std::fs::remove_dir_all(&base);
    }
