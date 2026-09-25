//! `frameprism bake` — reel bundling: one tool pass that
//! packs an ENCODED clip dir into the archival container + the mandatory
//! per-file sha256 manifest.
//!
//! The verdicts drive the
//! defaults: J92 output −4.4…−13.8% (granularity > codec level), JXL
//! incompressible (0% in all 10 containers), tail truncation: zip/7z
//! 0/225 vs tar family 224/225 (graceful), and store-tar is the only
//! SILENT corruption path (rc=0 + corrupted file) — hence the mandatory
//! manifest: the container archives, the manifest is the verification
//! layer (a sweep over it makes silent corruption loud).
//!
//! Container default = detection (an explicit `--zstd` always wins):
//! - ≥1 `.DNG` and no `.jxl` → codec `j92` → default `--zstd 19` →
//!   `<clip>.tar.zst`.
//! - ≥1 `.jxl` and no `.DNG` → codec `jxl` → default `--zstd none`
//!   (plain tar — zero compression time) → `<clip>.tar`.
//! - mixed `.DNG` + `.jxl`, or no codec files (empty/foreign dir) → hard
//!   reject rc=2, loud + named.
//!
//! The mandatory `<clip>.bake-manifest.tsv` (always written; no opt-out)
//! = header block (clip, created, tool_version, codec, container,
//! zstd_level, file_count, tar_version, zstd_version, host — the v2
//! version headers; the first 7 fields are the v1 format unchanged)
//! + one row per file IN the archive (sorted by relative path):
//! relpath, size, sha256. sha256 = the hand-rolled FIPS 180-4 from
//! `crate::jxl` (no new crate).
//!
//! AppleDouble hygiene (v2 — the finding disclosed
//! in the pre-fix commit): bsdtar 3.5.3 on macOS writes `._*` sidecar members
//! into the tar for files carrying xattrs (com.apple.provenance) — hidden
//! from `tar -tf` listings, dropped on macOS extraction, junk on
//! Linux/Windows extraction + ~0.3–0.5% overhead. The in-process
//! container builder (the `tar` + `zstd` crates — no system-tool
//! subprocess) is structurally immune: it reads the file bytes only and
//! never touches xattrs, so no `._*` member can be written on any
//! platform (the legacy system-tar containers' `._*` members, if an
//! un-suppressed one exists, stay auditable — the reader's member map
//! takes what the archive lists). Extraction-side verification: 7-Zip
//! covered here (the cross-platform extractor present locally);
//! built-in Linux/Windows tar extraction is a documented follow-up
//! (not covered here).
//!
//! Sealed-tier reel image (`--iso`):
//! `bake --iso <reel-dir> <image.iso>` stages the SAME per-clip archives
//! + v2 manifests a flat clip dir gets today (grouped by the DNG name
//! prefix — `A001_001_20260701_000001.DNG` → clip `A001_001`) into a
//! temp dir, then images them with the pinned fstool (the in-process
//! ISO writer — `=0.4.33`, no external binary) + the pin-times pass
//! (the post-build overwrite of every directory record's 7-byte date
//! field with the pinned epoch — the maintainer's "epoch" decision: the
//! stored instant is machine-independent) as a hybrid
//! ISO9660+Joliet+Rock Ridge disk image: natively mountable on
//! macOS/Windows/Linux with zero tooling; **mounting is the audit
//! surface** — the embedded per-file sha256 manifest is the
//! verification layer: `frameprism audit <mount>` lists the per-clip
//! archive parts (`tar -tf`) and sha-sweeps every member against the
//! manifest rows (the bake-manifest-aware audit path —
//! the `*.checksums.tsv` sidecars are absent on the mount by
//! design; the manifest IS the sealed-tier sidecar). NO UDF layer: the pinned fstool
//! 0.4.33 writer does not produce UDF (the writer surface has no UDF
//! output — verified in the pinned crate source), and the 9660 layer is
//! the mount guarantee on macOS 26 (native UDF mounting dropped there).
//! Scaling: ISO9660's practical per-file boundary is ~2 GB — a
//! per-clip archive whose RAW members exceed the part target (default
//! 1.5 GiB; the `FRAMEPRISM_ISO_PART_MAX` env var overrides target+max
//! for synthetic tests) is split into contiguous
//! `<clip>.partNN.<container>` parts (each part's raw ≤ target < 2 GB;
//! the manifest's additive `archive:` field lists the parts — present
//! ONLY when parts > 1, single-part manifests stay byte-identical;
//! a single file above the part max is a named hard reject). Whole-
//! image size is not a 9660 concern (volumes run to BD size).
//!
//! Streaming, no temp full-copy of the archive — the exact command is
//! printed to stdout (and lands in the run log):
//! - zstd: `tar -cf - -C <in> <files…> | zstd -19 -q -T0 -o <tmp>`
//! - store: `tar -cf <tmp> -C <in> <files…>`
//! `-T0` = all cores — the measurement convention (the refs
//! ≈14.7 s/GB zstd-19 / ≈0.36 s/GB zstd-9 are `-T0` numbers). The
//! archive is written to a hidden tmp file in the output dir and renamed
//! into place (atomic — a crash never leaves a renamed partial); the
//! manifest is written only after the archive rename, also atomic.
//! `--force` is required to overwrite an existing archive (else rc=2).
//! The input dir is read-only input — never modified.
//!
//! v1 scope: the top-level regular files of the clip dir only (the
//! encoded clip is flat: `.DNG`s, or 4× `.jxl` per frame + the
//! `*.jxl-checksums.tsv` sidecar, which is archived + manifest-covered
//! like any other file). Subdirectories and symlinked entries are hard
//! rejections (loud + named) — never silently skipped.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use fstool::block::FileBackend;
use fstool::fs::iso9660::{FormatOpts, Iso9660};
use fstool::fs::{FileMeta, FileSource, Filesystem};

use crate::jxl::sha256_hex;

/// One archived file: size + sha256 (from the SOURCE — the same bytes
/// that go into the tar stream) + its manifest relpath.
struct FileRow {
    rel: String,
    size: u64,
    sha: String,
}

/// The run's ledger facts: the detected codec +
/// the archived member count (run: the clip's files; run_iso: the
/// reel's frames). The CLI carries them into the ops-ledger row.
#[derive(Clone, Debug)]
pub struct BakeOutcome {
    pub codec: String,
    pub frames: u64,
}

/// The per-clip bake facts (the B5 reel-manifest input): the clip key,
/// the codec, the archive part names (the single-part path = one
/// entry), the per-clip bake manifest name, and the reel-manifest
/// `frames` column (j92 = the .DNG frame count; jxl = the distinct
/// frame stems — the 4-plane convention).
#[derive(Clone, Debug)]
pub struct ClipBakeResult {
    pub clip: String,
    pub codec: &'static str,
    pub part_names: Vec<String>,
    pub manifest_name: String,
    pub frames: u64,
    pub members: usize,
}

/// The named pre-run usage refusals (the ledger
/// semantics): these bails fire BEFORE any run starts (a bad input,
/// an existing archive without `--force`, a mixed/foreign clip) — a
/// run that never started appends NO ledger row (the `REFUSED_*`
/// classes are reserved for the safety gates: PIN / SPACE / INGEST).
/// A mid-run failure (the archive work itself) is a `FAIL` row.
/// The prefixes are the in-tree bail messages of this module — if a
/// NEW pre-run bail is added, add its prefix here (the worst case
/// without it is a spurious FAIL row, never a lost one).
pub const USAGE_REFUSAL_PREFIXES: &[&str] = &[
    "bake: input is not a directory",
    "bake: input and output must be disjoint",
    "bake: --iso input is not a directory",
    "bake: --iso image path",
    "bake: --iso image",
    "bake: refusing to overwrite",
    "bake: --iso no files",
    "bake: --iso no clip folders",
    "bake: --iso the selection names no clip group",
    "bake: --iso reel input must be",
    "bake: --iso clip",
    "bake: --zstd level must be",
    "bake: mixed .DNG + .jxl",
    "bake: no .DNG or .jxl files",
    "bake: no clip folders with frames",
    "bake: the selection names no clip folder",
    "bake: refusing symlinked entry",
    "bake: refusing subdirectory",
    "bake: frame file at the tree root",
    "bake: clip",
    // -G4 (the sealed-tier .sig ride): the `--reel-out` sealing
    // refusals — the flag on the non-iso path (a run that never
    // starts) + the keyless seal-gate checks (a refusal creates no
    // image path).
    "bake: --reel-out",
    "bake: --iso --reel-out",
];

/// The `--reel-out` usage refusal (-G4, the seal gate's check 6):
/// the flag on the non-iso bake path. The provenance bundle is sealed
/// INTO the image — the working-tier bake does not stage it. The
/// message is the usage-refusal prefix class (the CLI refuses rc=2
/// before the first byte — no status line, no ledger row).
pub fn reel_out_non_iso_refusal(reel_out: &Path) -> String {
    format!(
        "bake: --reel-out {} is an --iso flag — the provenance bundle is sealed into the ISO image (the usage is `bake --iso <out> <image> --reel-out <reel-dir>`); the working-tier bake does not stage it",
        reel_out.display()
    )
}

/// `true` when `msg` is one of the named pre-run usage refusals above
/// (the CLI: no ledger row; everything else that errors is a run that
/// started and failed → the FAIL row).
pub fn is_usage_refusal(msg: &str) -> bool {
    USAGE_REFUSAL_PREFIXES.iter().any(|p| msg.starts_with(p))
}

/// The archive-object sha sidecar: the
/// sha256sum-compatible line `<sha256>  <basename>` (TWO spaces, no
/// directory component — `sha256sum -c` must run in the object dir)
/// next to each object the bake produces: the per-part archives
/// (`<clip>.<container>` / `<clip>.partNN.<container>`) and the sealed
/// image (`<reel.iso>`). The sidecars are SEPARATE files — the
/// archive/manifest/ISO bytes are unchanged (the byte-invariance pattern:
/// a re-baked existing reel is sha-IDENTICAL to before). Atomic
/// tmp+rename like the rest of the module.
///: the B6 object sha sidecar VERIFIES — re-hash the
/// object and compare against the sidecar's sha256sum line (the
/// `<sha>  <basename>` shape — the first field). The resume
/// completion marker's check (never trust the sidecar alone).
fn verify_object_sidecar(object: &Path, sidecar: &Path) -> Result<bool, String> {
    let text = std::fs::read_to_string(sidecar)
        .map_err(|e| format!("read the sidecar {}: {e}", sidecar.display()))?;
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| format!("the sidecar {} is empty", sidecar.display()))?;
    let sha = line.split("  ").next().unwrap().trim();
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "the sidecar's sha field is malformed ({} — want 64 hex)",
            sha.chars().take(12).collect::<String>()
        ));
    }
    // The streaming sha (the verify is hash-only); the
    // refusal wording is the pre-existing one.
    let disk =
        crate::jxl::sha256_stream_path(object).map_err(|e| format!("read the object {}: {e}", object.display()))?;
    Ok(disk == sha.to_ascii_lowercase())
}

///: the bake completion marker (the single-archive case):
/// the archive object + the manifest + the verifying `.sha256` sidecar
/// and the manifest's `file_count` matching the current scan. Ok(()) =
/// verified complete (the named skip); Err(reason) = interrupted or
/// stale (the named redo + the stale object/sidecar removal).
fn verify_bake_completion(
    object: &Path,
    manifest: &Path,
    sidecar: &Path,
    current_rows: usize,
) -> Result<(), String> {
    if !object.exists() {
        return Err("the archive object is missing".into());
    }
    if !sidecar.exists() {
        return Err(
            "the .sha256 object sidecar is missing (the completion marker — the archive is interrupted)".into(),
        );
    }
    if !manifest.exists() {
        return Err("the bake manifest is missing (the completion set is incomplete)".into());
    }
    match verify_object_sidecar(object, sidecar) {
        Ok(true) => {}
        Ok(false) => {
            return Err(
                "the .sha256 sidecar does not verify over the on-disk object (re-hashed)".into(),
            );
        }
        Err(e) => return Err(e),
    }
    let m = std::fs::read_to_string(manifest)
        .map_err(|e| format!("read the manifest {}: {e}", manifest.display()))?;
    let fc = m
        .lines()
        .find(|l| l.starts_with("file_count:"))
        .and_then(|l| l.trim_start_matches("file_count:").trim().parse::<usize>().ok());
    match fc {
        Some(n) if n == current_rows => Ok(()),
        Some(n) => Err(format!(
            "the manifest file_count {n} != the current file count {current_rows} (the input changed — the completion is stale)"
        )),
        None => Err("the manifest has no readable file_count header".into()),
    }
}

///: the interrupted bake's leftover temps in the output
/// tree (recursive): the `.bake-tmp` archive temps + the hidden
/// manifest/sidecar temp names. Best-effort (a removal failure is a
/// named note, never an error); returns the removed names (sorted).
fn clean_bake_temps(output: &Path) -> Vec<String> {
    fn is_bake_temp(name: &str) -> bool {
        name.ends_with(".bake-tmp")
            || (name.starts_with('.')
                && (name.ends_with(".bake-manifest.tsv.tmp")
                    || name.ends_with(".sha256.tmp")
                    || name.ends_with(".reel-manifest.tsv.tmp")))
    }
    fn walk(output: &Path, dir: &Path, removed: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().map(|f| f.is_dir()).unwrap_or(false);
            if is_dir {
                walk(output, &p, removed);
                continue;
            }
            if is_bake_temp(&name) {
                match std::fs::remove_file(&p) {
                    Ok(()) => {
                        let rel = p
                            .strip_prefix(output)
                            .unwrap_or(&p)
                            .to_string_lossy()
                            .replace('\\', "/");
                        removed.push(rel);
                    }
                    Err(_) => eprintln!(
                        "bake: resume: note: cannot remove leftover temp {} — left in place",
                        p.display()
                    ),
                }
            }
        }
    }
    let mut removed = Vec::new();
    walk(output, output, &mut removed);
    removed.sort();
    removed
}

fn write_object_sha_sidecar(object: &Path, sha: &str) -> Result<PathBuf> {
    let name = object
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .ok_or_else(|| anyhow!("bake: cannot read the object name of {}", object.display()))?;
    let sidecar = object.with_file_name(format!("{name}.sha256"));
    let tmp = object.with_file_name(format!(".{name}.sha256.tmp"));
    std::fs::write(&tmp, format!("{sha}  {name}\n"))
        .with_context(|| format!("bake: write {}", tmp.display()))?;
    if let Err(err) = std::fs::rename(&tmp, &sidecar) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err).with_context(|| {
            format!("bake: rename {} -> {}", tmp.display(), sidecar.display())
        });
    }
    Ok(sidecar)
}

/// The -G4 provenance-bundle staging: copy one bundle file into
/// `staging/provenance/` — read the source, write a hidden tmp in the
/// same dir, atomic rename (the established crash-safety pattern: a
/// crash never leaves a renamed partial; the tmp is removed on a
/// rename failure).
fn stage_provenance_file(staging: &Path, name: &str, src: &Path) -> Result<PathBuf> {
    let dir = staging.join("provenance");
    std::fs::create_dir_all(&dir).with_context(|| {
        format!(
            "bake: --iso --reel-out create the provenance dir {}",
            dir.display()
        )
    })?;
    let dst = dir.join(name);
    let tmp = dir.join(format!(".{name}.tmp"));
    // The bounded streaming copy (never the whole bundle in
    // a `Vec` — the offload/transfer.rs `File::open` + `io::copy` pattern; no
    // new sync — the pre-existing `fs::write` carried none either). The
    // read/write context wordings are the pre-existing ones.
    let mut src_file = std::fs::File::open(src).with_context(|| {
        format!(
            "bake: --iso --reel-out read the bundle source {}",
            src.display()
        )
    })?;
    let mut dst_file = std::fs::File::create(&tmp)
        .with_context(|| format!("bake: --iso --reel-out write the bundle tmp {}", tmp.display()))?;
    std::io::copy(&mut src_file, &mut dst_file)
        .with_context(|| format!("bake: --iso --reel-out write the bundle tmp {}", tmp.display()))?;
    drop(dst_file);
    if let Err(err) = std::fs::rename(&tmp, &dst) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err).with_context(|| {
            format!(
                "bake: --iso --reel-out rename {} -> {}",
                tmp.display(),
                dst.display()
            )
        });
    }
    Ok(dst)
}

/// The per-clip part split bounds (ISO9660's
/// practical per-file boundary is ~2 GB): the clip's RAW member bytes
/// above `target` split the archive into contiguous parts; `max` is
/// the hard bound on a single-member part (a file above it cannot be
/// part-archived — a named hard reject). Default: 1.5 GiB / 2 GiB —
/// a part's archive is at most its raw size + the tar framing, so
/// every part stays <2 GB. The `FRAMEPRISM_ISO_PART_MAX` env var
/// (undocumented in --help) sets BOTH target and max to <bytes> for
/// synthetic tests.
fn part_bounds() -> Result<(u64, u64)> {
    const DEFAULT_TARGET: u64 = 1_610_612_736; // 1.5 GiB raw
    const DEFAULT_MAX: u64 = 2_147_483_648; // 2 GiB raw
    match std::env::var("FRAMEPRISM_ISO_PART_MAX") {
        Err(_) => Ok((DEFAULT_TARGET, DEFAULT_MAX)),
        Ok(s) => {
            let v: u64 = s
                .trim()
                .parse()
                .map_err(|_| anyhow!("bake: FRAMEPRISM_ISO_PART_MAX is not a valid byte count: {s:?}"))?;
            if v == 0 {
                bail!("bake: FRAMEPRISM_ISO_PART_MAX must be > 0 bytes (got 0)");
            }
            Ok((v, v))
        }
    }
}

/// Greedy contiguous partition of the clip files (sorted order) into
/// parts whose raw bytes stay ≤ `target` (the part target). A single
/// file above `target` takes a part to itself (allowed up to `max`,
/// above = a named hard reject — ISO9660's per-file boundary). The
/// partition is a pure function of (file order, sizes, target, max) —
/// the sealed tier's determinism extends to the part layout.
fn partition_files(
    files: &[(String, PathBuf)],
    sizes: &[u64],
    target: u64,
    max: u64,
    clip: &str,
) -> Result<Vec<Vec<usize>>> {
    let mut parts: Vec<Vec<usize>> = vec![Vec::new()];
    let mut cur = 0u64;
    for (i, size) in sizes.iter().enumerate() {
        if *size > max {
            bail!(
                "bake: clip {clip} member {} is {size} B — above the part max ({max} B); a single-member part cannot exceed ISO9660's practical per-file boundary (the clip needs a different object granularity)",
                files[i].0
            );
        }
        if !parts.last().unwrap().is_empty() && cur + size > target {
            parts.push(Vec::new());
            cur = 0;
        }
        parts.last_mut().unwrap().push(i);
        cur += size;
    }
    Ok(parts)
}

/// Build ONE archive part from `part_files` (in-process tar, optional
/// in-process zstd — the `tar` + `zstd` crates replace the system-tool
/// subprocess: the container bytes are a pure function of (the file
/// set, the contents, the mtimes, the modes, the crate/lib versions)
/// — byte-identical across machines and runs, no platform
/// bsdtar-vs-gnutar drift, no builder uid/gid leak). The byte contract
/// (the D3 decision): the files ONLY (NO directory entries — the explicit
/// file-list writes none; NO `._*` AppleDouble members — structurally,
/// the in-process path never sees xattrs), the entry order = the
/// manifest row order (sorted by relative path), USTAR headers
/// (mtime = the source mtime, mode = the source permission bits,
/// uid = gid = 0, uname/gname = empty, atime/ctime = 0 — the crate's
/// deterministic defaults), and the compressed path = the
/// SINGLE-THREAD zstd encoder (the multi-thread mode's output varies
/// with the core count — that would break the cross-machine
/// determinism this builder exists to give), no frame checksum, the
/// requested level (9/19); level-none = the raw tar alone. The hidden
/// tmp file + atomic rename into `archive` (a crash never leaves a
/// renamed partial). The in-process form is printed to stderr (the
/// truthful run log — the tool, the level, the target). Returns the
/// archive size in bytes.
fn build_archive(
    part_files: &[&(String, PathBuf)],
    zstd_level: Option<u32>,
    tmp: &Path,
    archive: &Path,
) -> Result<u64> {
    let command = match zstd_level {
        Some(level) => format!(
            "bake: in-process container (tar {} + zstd -{level}) → {}",
            env!("FRAMEPRISM_TAR_CRATE_VERSION"),
            tmp.display()
        ),
        None => format!(
            "bake: in-process container (tar {} + zstd none) → {}",
            env!("FRAMEPRISM_TAR_CRATE_VERSION"),
            tmp.display()
        ),
    };
    eprintln!("{command}");

    let res: std::io::Result<()> = match zstd_level {
        Some(level) => {
            // in-process tar → the single-thread zstd encoder (level 9/19,
            // no frame checksum) → the hidden tmp file.
            let file = std::fs::File::create(tmp)
                .map_err(std::io::Error::other)?;
            let enc = zstd::stream::Encoder::new(file, level as i32)
                .map_err(std::io::Error::other)?;
            write_tar_stream(enc, part_files)
                .and_then(|enc| enc.finish().map(|_| ()))
        }
        None => {
            // level-none = the raw tar alone (the store container).
            let file = std::fs::File::create(tmp)
                .map_err(std::io::Error::other)?;
            write_tar_stream(file, part_files).map(|_| ())
        }
    };
    if let Err(err) = res {
        let _ = std::fs::remove_file(tmp); // nothing half-written
        return Err(err).with_context(|| {
            format!("bake: write the archive part {}", tmp.display())
        });
    }
    if let Err(err) = std::fs::rename(tmp, archive) {
        let _ = std::fs::remove_file(tmp); // atomicity: nothing half-written
        return Err(err).with_context(|| {
            format!("bake: rename {} -> {}", tmp.display(), archive.display())
        });
    }
    let archive_bytes = std::fs::metadata(archive)
        .with_context(|| format!("bake: stat {}", archive.display()))?
        .len();
    Ok(archive_bytes)
}

/// Write the tar stream for `part_files` into `w` (the in-process
/// writer, the D3 contract): one entry per file (files only — no
/// directory entries, no `._*` members: this path reads the file bytes
/// only and never touches xattrs), in the given order (the manifest
/// row order), USTAR headers with the source mtime + the source
/// permission bits, uid = gid = 0, empty uname/gname (atime/ctime stay
/// the header's zero defaults — deterministic by construction).
fn write_tar_stream<W: std::io::Write>(
    w: W,
    part_files: &[&(String, PathBuf)],
) -> std::io::Result<W> {
    let mut builder = tar::Builder::new(w);
    for (rel, p) in part_files {
        let md = std::fs::metadata(p)?;
        let mtime = md
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_secs();
        let mut header = tar::Header::new_ustar();
        header.set_size(md.len());
        header.set_mtime(mtime);
        header.set_mode(source_mode_bits(&md));
        header.set_uid(0);
        header.set_gid(0);
        header.set_username("")?;
        header.set_groupname("")?;
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        let mut src = std::fs::File::open(p)?;
        builder.append_data(&mut header, rel, &mut src)?;
    }
    builder.into_inner()
}

/// The source file's permission bits for the USTAR mode field (the D3
/// contract): the full octal mode on unix (the primary platform — the
/// committed byte contract); the read-only flag derived mode on other
/// targets (the source-portability fallback — the std-only `Permissions`
/// surface exposes only that bit; the byte contract is the unix one).
fn source_mode_bits(md: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        // The std-only surface: the read-only flag is the only mode
        // bit the portable Permissions exposes.
        if md.permissions().readonly() {
            0o444
        } else {
            0o666
        }
    }
}

/// `frameprism bake <input-clip-dir> <output> [--zstd …] [--force]`
/// — or, with `--iso`, `frameprism bake --iso <reel-dir> <image.iso>
/// […]` (the sealed-tier reel image — `run_iso`).
///
/// `zstd`: None = detection (j92 → 19, jxl → none); Some(0) = plain tar
/// (store); Some(9 | 19) = explicit level — an explicit `--zstd` always
/// wins over detection.
pub fn run(
    input: &Path,
    output: &Path,
    zstd: Option<u32>,
    force: bool,
    resume: bool,
) -> Result<BakeOutcome> {
    if !input.is_dir() {
        bail!("bake: input is not a directory: {}", input.display());
    }
    let in_abs = std::fs::canonicalize(input)?;
    // Pre-create guard (lexical): never create the output dir INSIDE the
    // read-only input. The canonical check after creation catches the
    // `..`/symlink cases.
    if output
        .to_string_lossy()
        .as_ref()
        .starts_with(in_abs.to_string_lossy().as_ref())
    {
        bail!(
            "bake: input and output must be disjoint directories (input {} / output {})",
            in_abs.display(),
            output.display()
        );
    }
    // The output dir is created (if missing) before canonicalize — the
    // archive names live inside it.
    std::fs::create_dir_all(output)
        .with_context(|| format!("bake: create output dir {}", output.display()))?;
    let out_abs = std::fs::canonicalize(output)?;
    if in_abs == out_abs || out_abs.starts_with(&in_abs) || in_abs.starts_with(&out_abs) {
        bail!(
            "bake: input and output must be disjoint directories (input {} / output {})",
            in_abs.display(),
            out_abs.display()
        );
    }
    // Tree mode: ≥1 clip folder at the root
    // → the per-clip archives + the reel manifest (B5). The flat path
    // below is unchanged (R-INV).
    if is_tree_mode(input) {
        return run_tree(input, output, zstd, force, resume);
    }
    let clip = crate::checksums::clip_name(input)
        .with_context(|| format!("bake: derive clip name from {}", input.display()))?;

    // --- collect the clip files (top-level regular files only) ----------
    let files = collect_files(input)?;

    // --- codec detection (mixed / empty → hard reject) -------------------
    let n_dng = files
        .iter()
        .filter(|(n, _)| ext_is(n, "dng"))
        .count();
    let n_jxl = files.iter().filter(|(n, _)| ext_is(n, "jxl")).count();
    let codec: &'static str = if n_dng > 0 && n_jxl > 0 {
        bail!(
            "bake: mixed .DNG + .jxl input ({n_dng} .DNG, {n_jxl} .jxl in {}) — one codec per clip dir",
            input.display()
        )
    } else if n_dng > 0 {
        "j92"
    } else if n_jxl > 0 {
        "jxl"
    } else {
        bail!(
            "bake: no .DNG or .jxl files in {} ({} file(s) present) — empty or foreign clip dir",
            input.display(),
            files.len()
        )
    };

    // --- container: explicit --zstd always wins, else detection ---------
    let (zstd_level, detected): (Option<u32>, bool) = match zstd {
        Some(l) => {
            if l != 0 && l != 9 && l != 19 {
                bail!("bake: --zstd level must be 0 (none), 9 or 19 (got {l})");
            }
            (if l == 0 { None } else { Some(l) }, false)
        }
        None => (if codec == "j92" { Some(19) } else { None }, true),
    };
    let container: &'static str = if zstd_level.is_some() { "tar.zst" } else { "tar" };

    // --- the per-clip core (archive + manifest + summary) ----------------
    bake_clip(
        &clip,
        &files,
        codec,
        container,
        zstd_level,
        output,
        force,
        detected,
        None,
        // The non-iso path splits only above the default target (all
        // current corpora are below it — the single-archive bytes are
        // unchanged; a >1.5 GiB raw clip gets the part layout + the
        // additive `archive:` manifest field, ).
        Some(part_bounds()?),
        // The B6 object sha sidecars: the plain bake output dir gets
        // one per archive object (the `<clip>.tar.zst.sha256` +
        // the .partNN sidecars for split parts).
        true,
        resume,
    )?;
    Ok(BakeOutcome {
        codec: codec.to_string(),
        frames: files.len() as u64,
    })
}


/// The tree-mode bake: the per-clip
/// archives (the shared `bake_clip` core — byte-identical to the
/// flat per-clip bytes) + the B5 reel manifest when >1 clip archive
/// is staged. The design-decision refusals + skips + the root-level
/// notes are in `collect_tree`; the selection filters the clip
/// set AFTER the refusals (a mixed-up tree is refused regardless of
/// the selection).
fn run_tree(
    input: &Path,
    output: &Path,
    zstd: Option<u32>,
    force: bool,
    resume: bool,
) -> Result<BakeOutcome> {
    let (clips, root_notes) = collect_tree(input)?;
    for note in &root_notes {
        eprintln!("{note}");
    }
    if clips.is_empty() {
        bail!(
            "bake: no clip folders with frames in {} — nothing to bake (the empty folders are the named skips above)",
            input.display()
        );
    }
    // The active selection filters the clip set
    // (absent = the full set — the byte-identity path).
    let clips: Vec<&TreeClip> = match crate::selection::current() {
        Some(a) => clips.iter().filter(|c| a.selected.contains(&c.key)).collect(),
        None => clips.iter().collect(),
    };
    if clips.is_empty() {
        bail!(
            "bake: the selection names no clip folder(s) in {} — nothing to bake",
            input.display()
        );
    }
    // Container: explicit --zstd always wins (all clips), else
    // per-clip detection (the flat convention per codec).
    let explicit: Option<u32> = match zstd {
        Some(l) => {
            if l != 0 && l != 9 && l != 19 {
                bail!("bake: --zstd level must be 0 (none), 9 or 19 (got {l})");
            }
            Some(l)
        }
        None => None,
    };
    let split = part_bounds()?;
    let mut results: Vec<ClipBakeResult> = Vec::new();
    let mut total_files = 0usize;
    let mut codecs: std::collections::BTreeSet<&'static str> =
        std::collections::BTreeSet::new();
    for c in &clips {
        // The clip folder's existence validation (the named error path
        // — the in-process writer opens the files' own paths, no `-C`).
        let _ = std::fs::canonicalize(input.join(&c.key))
            .with_context(|| format!("bake: canonicalize clip folder {}", c.key))?;
        let (zstd_level, detected) = match explicit {
            Some(l) => (if l == 0 { None } else { Some(l) }, false),
            None => if c.codec == "j92" { (Some(19), true) } else { (None, true) },
        };
        let container: &'static str = if zstd_level.is_some() { "tar.zst" } else { "tar" };
        results.push(bake_clip(
            &c.key,
            &c.files,
            c.codec,
            container,
            zstd_level,
            output,
            force,
            detected,
            None,
            Some(split),
            // The B6 object sha sidecars: the plain bake output dir
            // gets one per archive object.
            true,
            resume,
        )?);
        total_files += c.files.len();
        codecs.insert(c.codec);
    }
    // The B5 reel manifest: present when >1 clip archive is staged
    // (the single-clip bake keeps the existing output shape — R-INV).
    // created = the wall clock (the non-iso convention).
    if results.len() > 1 {
        let mut rows: Vec<crate::reel::ReelRow> = Vec::new();
        for r in &results {
            let mb = std::fs::read(output.join(&r.manifest_name))
                .with_context(|| format!("bake: read the manifest {}", r.manifest_name))?;
            rows.push(crate::reel::ReelRow {
                clip: r.clip.clone(),
                codec: r.codec.to_string(),
                archives: r.part_names.clone(),
                archive_shas: reel_row_shas(output, r, "")?,
                manifest: r.manifest_name.clone(),
                manifest_sha: sha256_hex(&mb),
                frames: r.frames,
            });
        }
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let tsv = crate::reel::render(created, &rows);
        let path = output.join(crate::reel::REEL_MANIFEST_NAME);
        std::fs::write(&path, tsv)
            .with_context(|| format!("bake: write the reel manifest {}", path.display()))?;
        println!(
            "  reel      : {} ({} clip(s), {} frame(s) — the reel manifest, B5)",
            path.display(),
            rows.len(),
            rows.iter().map(|r| r.frames).sum::<u64>()
        );
    }
    // The selection line (stdout — the bake summary carries the same
    // line; the tree mode always records it).
    println!(
        "  selection : {}",
        crate::selection::report_line(crate::selection::current(), results.len())
    );
    // The ledger facts: the distinct clip codecs ('+'-joined) + the
    // archived member count.
    let codec: String =
        codecs.iter().map(|s| s.to_string()).collect::<Vec<_>>().join("+");
    Ok(BakeOutcome {
        codec,
        frames: total_files as u64,
    })
}

/// The B5 reel manifest's per-part archive sha256s (the reel.rs row
/// convention — the multi-part clip lists the comma-joined part names
/// and the ALIGNED per-part shas; each part's object bytes are read +
/// hashed).
fn reel_row_shas(
    base: &Path,
    result: &ClipBakeResult,
    ctx: &str,
) -> Result<Vec<String>> {
    let mut shas = Vec::with_capacity(result.part_names.len());
    for pn in &result.part_names {
        // The streaming sha (the re-verify is hash-only);
        // the context wording is the pre-existing one.
        shas.push(
            crate::jxl::sha256_stream_path(&base.join(pn))
                .with_context(|| format!("bake: {ctx} read the archive part {pn}"))?,
        );
    }
    Ok(shas)
}

/// Top-level regular files of a flat clip dir (name + path), sorted by
/// name. Symlinked and subdirectory entries are hard rejects (loud +
/// named — never silently skipped); fifo/socket/device entries are not
/// clip files and are skipped. Shared by `run` (one clip) and `run_iso`
/// (a reel: the same files, grouped by clip prefix).
fn collect_files(input: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    for entry in
        std::fs::read_dir(input).with_context(|| format!("bake: read dir {}", input.display()))?
    {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            bail!(
                "bake: refusing symlinked entry (archive integrity requires plain files): {}",
                p.display()
            );
        }
        if p.is_dir() {
            bail!(
                "bake: refusing subdirectory (v1 bakes the flat clip dir only): {}",
                p.display()
            );
        }
        if !p.is_file() {
            continue; // fifo/socket/device — not a clip file
        }
        files.push((entry.file_name().to_string_lossy().into_owned(), p));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

/// Tree-mode detection: the input has ≥1
/// non-symlink subdirectory at the root = the clip-folder tree (the
/// per-clip archive + the reel manifest). A symlinked subdir is NOT a
/// clip folder (the symlink refusal fires in the collection) — the
/// flat path sees it the same way.
pub fn is_tree_mode(input: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(input) else {
        return false;
    };
    for entry in rd.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() && !ft.is_symlink() {
            return true;
        }
    }
    false
}

/// One clip folder of the tree-mode collection:
/// the folder name (the clip key) + every member file
/// (frames + the sidecars — the tree mode is the sidecar tree; the
/// flat mode's frames-only rule does not apply INSIDE a clip folder),
/// sorted by file name.
pub struct TreeClip {
    pub key: String,
    pub files: Vec<(String, PathBuf)>,
    pub codec: &'static str,
}

/// The tree-mode collection: the per-clip
/// folder groups + the root-level run-level notes. The design
/// decisions: symlinks are refused (the
/// existing class); a subdirectory inside a clip folder is refused
/// (v1 tree = exactly one level deep); a frame file at the tree root
/// is refused (the mixed flat+tree shape); a zero-frame folder with
/// ANY other file is refused (the stray-artifact class — the
/// A001_007-proxy shape); an empty folder is the NAMED SKIP (never
/// silent); non-frame root files are the run-level records (named
/// note, never archived); a frame whose name prefix differs from its
/// folder is refused (the folder/prefix mismatch); mixed codecs
/// inside a clip folder are refused (the flat class).
fn collect_tree(input: &Path) -> Result<(Vec<TreeClip>, Vec<String>)> {
    let mut clips: Vec<TreeClip> = Vec::new();
    let mut root_notes: Vec<String> = Vec::new();
    for entry in
        std::fs::read_dir(input).with_context(|| format!("bake: read dir {}", input.display()))?
    {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if ft.is_symlink() {
            bail!(
                "bake: refusing symlinked entry (archive integrity requires plain files): {}",
                p.display()
            );
        }
        if p.is_dir() {
            // A clip folder: exactly one level deep, plain files only.
            let mut files: Vec<(String, PathBuf)> = Vec::new();
            for sub in
                std::fs::read_dir(&p)
                    .with_context(|| format!("bake: read clip folder {}", p.display()))?
            {
                let sub = sub?;
                let sp = sub.path();
                let sft = sub.file_type()?;
                if sft.is_symlink() {
                    bail!(
                        "bake: refusing symlinked entry (archive integrity requires plain files): {}",
                        sp.display()
                    );
                }
                if sp.is_dir() {
                    bail!(
                        "bake: clip folder {name} contains a subdirectory (v1 tree = exactly one level deep): {}",
                        sp.display()
                    );
                }
                if !sp.is_file() {
                    continue; // fifo/socket/device — not a clip file
                }
                files.push((sub.file_name().to_string_lossy().into_owned(), sp));
            }
            files.sort_by(|a, b| a.0.cmp(&b.0));
            let n_dng = files.iter().filter(|(n, _)| ext_is(n, "dng")).count();
            let n_jxl = files.iter().filter(|(n, _)| ext_is(n, "jxl")).count();
            if n_dng > 0 && n_jxl > 0 {
                bail!(
                    "bake: clip folder {name} mixes .DNG + .jxl frames ({n_dng} .DNG, {n_jxl} .jxl) — one codec per clip folder"
                );
            }
            let codec: &'static str = if n_dng > 0 {
                "j92"
            } else if n_jxl > 0 {
                "jxl"
            } else if files.is_empty() {
                // The empty folder: the NAMED SKIP (never silent).
                eprintln!(
                    "bake: clip folder {name} is empty — skipped (a zero-frame folder is a named skip, never a silent one)"
                );
                continue;
            } else {
                // A zero-frame folder with ANY other file: the
                // stray-artifact class (the A001_007-proxy shape) —
                // a named refusal, never a silent skip.
                bail!(
                    "bake: clip folder {name} has zero frames and {} non-frame file(s) ({}) — the stray-artifact class is a named refusal (the A001_007-proxy shape: a .mov/.proxy-manifest in a clip folder means the folder is not a clip)",
                    files.len(),
                    files
                        .iter()
                        .map(|(n, _)| n.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            };
            // The folder/prefix mismatch (a frame whose name prefix
            // differs from its folder): a named refusal.
            for (n, _) in &files {
                if ext_is(n, "dng") || ext_is(n, "jxl") {
                    let prefix = clip_prefix(n)?;
                    if prefix != name {
                        bail!(
                            "bake: clip folder {name} contains a frame with a different clip prefix {prefix} ({n}) — the folder/prefix mismatch is a named refusal (move the frame to its own clip folder, or rename the folder)"
                        );
                    }
                }
            }
            clips.push(TreeClip {
                key: name,
                files,
                codec,
            });
            continue;
        }
        if !p.is_file() {
            continue; // fifo/socket/device — not a clip file
        }
        // A root-level regular file.
        if ext_is(&name, "dng") || ext_is(&name, "jxl") {
            bail!(
                "bake: frame file at the tree root ({name} in {}) — the mixed flat+tree shape is a named refusal (move it into a clip folder)",
                input.display()
            );
        }
        root_notes.push(format!(
            "bake: root-level non-frame file {name} — skipped (the run-level record: manifest/sidecar/report; never archived)"
        ));
    }
    clips.sort_by(|a, b| a.key.cmp(&b.key));
    Ok((clips, root_notes))
}

/// The reel-manifest `frames` column for a clip's file set: j92 =
/// the .DNG frame count; jxl = the DISTINCT frame stems (the 4-plane
/// convention: `<stem>_p2_NN.jxl` — 4 plane files per frame; the
/// sidecar rows are members, never frames).
fn clip_frame_count(files: &[(String, PathBuf)], codec: &'static str) -> u64 {
    if codec == "j92" {
        files.iter().filter(|(n, _)| ext_is(n, "dng")).count() as u64
    } else {
        let mut stems: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (n, _) in files {
            if !ext_is(n, "jxl") {
                continue;
            }
            let stem = Path::new(n)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            // The plane suffix `_p2_NN` (the last component) — the
            // distinct frame stem is what precedes it.
            if let Some(idx) = stem.rfind("_p2_") {
                stems.insert(stem[..idx].to_string());
            } else {
                stems.insert(stem.to_string());
            }
        }
        stems.len() as u64
    }
}

/// The selection universe for a bake (the clip key space):
/// tree input = the clip folder names (the folders with ≥1 frame —
/// the empty-folder SKIPs and the stray-artifact folders are NOT
/// clips; the bake's own collection applies the named refusals
/// regardless of the selection); flat --iso = the frame name prefix
/// groups; flat non-iso = the single clip (the dir basename).
pub fn selection_universe(input: &Path, iso: bool) -> Result<std::collections::BTreeSet<String>> {
    let mut uni: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if is_tree_mode(input) {
        for entry in
            std::fs::read_dir(input)
                .with_context(|| format!("bake: read dir {}", input.display()))?
        {
            let entry = entry?;
            let p = entry.path();
            let ft = entry.file_type()?;
            if !(ft.is_dir() && !ft.is_symlink()) {
                continue;
            }
            let key = entry.file_name().to_string_lossy().into_owned();
            if key.is_empty() {
                continue;
            }
            let n_frames = std::fs::read_dir(&p)
                .map(|rd| {
                    rd.filter_map(|e| e.ok()).filter(|e| {
                        let n = e.file_name().to_string_lossy().into_owned();
                        e.path().is_file() && (ext_is(&n, "dng") || ext_is(&n, "jxl"))
                    }).count()
                })
                .unwrap_or(0);
            if n_frames > 0 {
                uni.insert(key);
            }
        }
    } else if iso {
        for (rel, _) in collect_files(input)? {
            if ext_is(&rel, "dng") || ext_is(&rel, "jxl") {
                uni.insert(clip_prefix(&rel)?);
            }
        }
    } else {
        uni.insert(crate::checksums::clip_name(input)?);
    }
    Ok(uni)
}

/// The per-clip bake core: build `<clip>.<container>` (in-process,
/// hidden tmp + atomic rename) + the mandatory `<clip>.bake-manifest.tsv`
/// into `output`, for the clip's `files` (the absolute paths — the
/// in-process writer opens them directly, no `-C`). Shared by `run`
/// (the single-clip dir) and `run_iso` (one call per clip prefix, into
/// the reel's staging dir) — so the iso staging is byte-identical to
/// the non-iso path by construction. The in-process container form is
/// printed (the truthful run log).
fn bake_clip(
    clip: &str,
    files: &[(String, PathBuf)],
    codec: &'static str,
    container: &'static str,
    zstd_level: Option<u32>,
    output: &Path,
    force: bool,
    detected: bool,
    // The manifest's `created` epoch: None = wall clock (the non-iso
    // path — byte-unchanged); Some = the pinned --iso epoch (the staged
    // content must be deterministic for the sealed image to be).
    created_epoch: Option<u64>,
    // The per-clip part split: None = no split
    // (the single-archive path — byte-unchanged); Some((target, max))
    // = split the clip's raw members into contiguous parts above the
    // target. The single-part path (raw ≤ target) emits today's exact
    // archive + manifest bytes (the G1 regression gate).
    split: Option<(u64, u64)>,
    // The B6 object sha sidecars (`<object>.sha256` next to each
    // archive object): true = the plain bake output dir; false = the
    // --iso STAGING dir (the ISO/tar BYTES must not change
    // — the sidecars are separate files; the --iso image gets its
    // sidecar NEXT TO THE IMAGE, written by run_iso after the image
    // build —
    // a part sidecar staged here would become an image member and
    // move the image bytes).
    sha_sidecars: bool,
    //: the resumable bake — the B6 object sha sidecar is
    // the completion marker (a verified object + manifest + sidecar =
    // the named skip, no re-bake; else the leftover temps are cleaned
    // up + named and the stale objects are removed for the redo).
    resume: bool,
) -> Result<ClipBakeResult> {
    let t0 = Instant::now();

    // --- output names (the per-part overwrite guard lives with the
    // --- part build; the manifest path is fixed for both layouts)
    let manifest = output.join(format!("{clip}.bake-manifest.tsv"));

    // --- manifest rows: size + sha256 per file, from the SOURCE ----------
    let mut rows: Vec<FileRow> = Vec::with_capacity(files.len());
    let mut raw_bytes = 0u64;
    for (rel, p) in files {
        // The bounded reads — the size from the O(1) stat,
        // the sha streamed; the context wording is the pre-existing one.
        let size = std::fs::metadata(p)
            .map(|m| m.len())
            .with_context(|| format!("bake: read {}", p.display()))?;
        let sha = crate::jxl::sha256_stream_path(p)
            .with_context(|| format!("bake: read {}", p.display()))?;
        raw_bytes += size;
        rows.push(FileRow {
            rel: rel.clone(),
            size,
            sha,
        });
    }

    // --- in-process container versions (logged + manifest header) ----
 // The D5 value form: the in-process library versions — the tar
    // crate version (embedded at build time from the committed
    // Cargo.lock) + the bundled libzstd version (the runtime
    // `zstd::ZSTD_versionString()`); the `(in-process)` marker is the
    // byte-contract statement (no system-tool subprocess — the
    // container bytes are a pure function of the file set/contents/
    // mtimes/modes + the crate/lib versions). Legacy system-tar
    // containers keep their old values; the audit reader accepts the
    // field without validating the value.
    let tar_version = format!("tar {} (in-process)", env!("FRAMEPRISM_TAR_CRATE_VERSION"));
    let zstd_version = format!(
        "zstd {} (in-process)",
        zstd::zstd_safe::version_string()
    );

    // --- part partition (the single-part path = today's bytes) ----------
    let row_sizes: Vec<u64> = rows.iter().map(|r| r.size).collect();
    let all: Vec<usize> = (0..files.len()).collect();
    let part_indexes: Vec<Vec<usize>> = match split {
        None => vec![all],
        Some((target, _max)) if raw_bytes <= target => vec![all],
        Some((target, max)) => partition_files(files, &row_sizes, target, max, clip)?,
    };
    let part_names: Vec<String> = if part_indexes.len() > 1 {
        part_indexes
            .iter()
            .enumerate()
            .map(|(i, _)| format!("{clip}.part{:02}.{container}", i + 1))
            .collect()
    } else {
        Vec::new()
    };

    // ---: the --resume completion marker (before any
    // --- archive byte) -----------------------------------------------
    // The B6 object sha sidecar is the completion marker: the final
    // archive object(s) + the manifest + the verifying sidecar(s) =
    // done → the named skip (no re-bake); else interrupted/stale →
    // the leftover temps are cleaned up + named and the stale
    // objects/sidecars are removed for the redo (the part-split
    // layout re-bakes — the completion marker covers the single-
    // archive case, the named note).
    if resume {
        let cleaned = clean_bake_temps(output);
        if !cleaned.is_empty() {
            eprintln!(
                "bake: resume: cleaned {} leftover temp file(s) from an interrupted run ({})",
                cleaned.len(),
                cleaned.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                    + if cleaned.len() > 5 { " …" } else { "" }
            );
        }
        let object_names: Vec<String> = if part_names.is_empty() {
            vec![format!("{clip}.{container}")]
        } else {
            part_names.clone()
        };
        if part_names.is_empty() {
            // The single-archive layout: the completion marker check
            // (object + manifest + the verifying sidecar + the
            // matching file_count).
            let opath = output.join(&object_names[0]);
            let osidecar = output.join(format!("{}.sha256", object_names[0]));
            match verify_bake_completion(&opath, &manifest, &osidecar, rows.len()) {
                Ok(()) => {
                    eprintln!(
                        "bake: resume: {} verified complete (the object sha256 sidecar matches + the manifest file_count matches the current scan) — skipped, no re-bake",
                        object_names[0]
                    );
                    println!(
                        "bake: resume: {} — verified complete, no re-bake (the completion marker holds)",
                        object_names[0]
                    );
                    return Ok(ClipBakeResult {
                        clip: clip.to_string(),
                        codec,
                        part_names: object_names,
                        manifest_name: format!("{clip}.bake-manifest.tsv"),
                        frames: clip_frame_count(files, codec),
                        members: rows.len(),
                    });
                }
                Err(why) => {
                    eprintln!(
                        "bake: resume: {} is not verified complete ({why}) — removing the stale object + sidecar and re-baking",
                        object_names[0]
                    );
                    if opath.exists() {
                        let _ = std::fs::remove_file(&opath);
                    }
                    if osidecar.exists() {
                        let _ = std::fs::remove_file(&osidecar);
                    }
                }
            }
        } else {
            // The part-split layout: the completion marker covers the
            // single-archive case — the named note + the stale parts
            // removed for the redo.
            eprintln!(
                "bake: resume: {clip} is the part-split layout — the completion marker covers the single-archive case; re-baking all parts"
            );
            for oname in &object_names {
                let opath = output.join(oname);
                let osidecar = output.join(format!("{oname}.sha256"));
                if opath.exists() {
                    let _ = std::fs::remove_file(&opath);
                }
                if osidecar.exists() {
                    let _ = std::fs::remove_file(&osidecar);
                }
            }
        }
    }

    // --- build the archive part(s) (streaming, tmp + atomic rename each) -
    let mut part_bytes: Vec<u64> = Vec::with_capacity(part_indexes.len());
    for (pi, idx) in part_indexes.iter().enumerate() {
        let (archive, tmp) = if part_names.is_empty() {
            (
                output.join(format!("{clip}.{container}")),
                output.join(format!(".{clip}.{container}.bake-tmp")),
            )
        } else {
            let n = &part_names[pi];
            (output.join(n), output.join(format!(".{n}.bake-tmp")))
        };
        if archive.exists() && !force {
            bail!(
                "bake: refusing to overwrite existing archive {} (use --force)",
                archive.display()
            );
        }
        let part_files: Vec<&(String, PathBuf)> = idx.iter().map(|&i| &files[i]).collect();
        part_bytes.push(build_archive(
            &part_files,
            zstd_level,
            &tmp,
            &archive,
        )?);
    }
    let archive_bytes: u64 = part_bytes.iter().sum();

    // --- the mandatory manifest (only after the archive is in place) -----
    let created = match created_epoch {
        Some(pinned) => pinned,
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let level_str = zstd_level.map(|l| l.to_string()).unwrap_or_else(|| "none".into());
    let host = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    // The additive `archive:` header field: the
    // explicit part list, PRESENT ONLY WHEN parts > 1 — the single-part
    // manifest stays byte-identical to the unsplit bytes (the G1
    // regression gate). Placement: after `file_count`, before
    // `tar_version` (the contract's mandated slot).
    let archive_field = if part_names.is_empty() {
        String::new()
    } else {
        format!("archive: {}\n", part_names.join(", "))
    };
    let mut tsv = format!(
        "# frameprism bake manifest\n\
         clip: {clip}\n\
         created: {created} (unix seconds, UTC)\n\
         tool_version: {}\n\
         codec: {codec}\n\
         container: {container}\n\
         zstd_level: {level_str}\n\
         file_count: {}\n\
         {archive_field}tar_version: {tar_version}\n\
         zstd_version: {zstd_version}\n\
         host: {host}\n\
         relpath\tsize\tsha256\n",
        env!("CARGO_PKG_VERSION"),
        rows.len()
    );
    for r in &rows {
        tsv.push_str(&format!("{}\t{}\t{}\n", r.rel, r.size, r.sha));
    }
    let mtmp = output.join(format!(".{clip}.bake-manifest.tsv.tmp"));
    std::fs::write(&mtmp, tsv).with_context(|| format!("bake: write {}", mtmp.display()))?;
    if let Err(err) = std::fs::rename(&mtmp, &manifest) {
        let _ = std::fs::remove_file(&mtmp);
        return Err(err).with_context(|| {
            format!("bake: rename {} -> {}", mtmp.display(), manifest.display())
        });
    }

    // --- the B6 object sha sidecars (one per archive part) -----------------
    // AFTER the archive object(s) + the manifest, BEFORE the summary:
    // `<object>.sha256` next to each object — the one-liner verify after
    // any move/copy (the missing seam for "the ISO moved to another
    // disk"). The object bytes are untouched (the G1 pattern). The
    // --iso staging path skips this (the image bytes must not gain a
    // member — see the `sha_sidecars` parameter).
    let mut sidecar_lines = Vec::new();
    if sha_sidecars {
        let object_names: Vec<String> = if part_names.is_empty() {
            vec![format!("{clip}.{container}")]
        } else {
            part_names.clone()
        };
        for oname in &object_names {
            let opath = output.join(oname);
            // The streaming sha (the object is the multi-GB
            // B6 class — never in a `Vec`); the context wording is
            // the pre-existing one.
            let osha = crate::jxl::sha256_stream_path(&opath)
                .with_context(|| format!("bake: read the object {}", opath.display()))?;
            let sidecar = write_object_sha_sidecar(&opath, &osha)?;
            sidecar_lines.push(format!(
                "  sidecar   : {} (object sha256 — the B6 one-liner verify)",
                sidecar.display()
            ));
        }
    }

    // --- summary (stdout → the run log) ------------------------------------
    println!(
        "bake: clip {clip} — codec {codec} ({})",
        if detected { "detected" } else { "explicit --zstd" }
    );
    println!("  container : {container} (zstd level: {level_str})");
    println!("  files     : {}   raw: {raw_bytes} B", rows.len());
    if part_names.is_empty() {
        let delta_pct = (archive_bytes as f64 / raw_bytes as f64 - 1.0) * 100.0;
        println!(
            "  archive   : {} ({} B, {delta_pct:+.2}% vs raw)   wall {:.1}s",
            output.join(format!("{clip}.{container}")).display(),
            archive_bytes,
            t0.elapsed().as_secs_f64()
        );
    } else {
        for (i, n) in part_names.iter().enumerate() {
            let part_raw: u64 = part_indexes[i].iter().map(|&k| row_sizes[k]).sum();
            let delta_pct = (part_bytes[i] as f64 / part_raw as f64 - 1.0) * 100.0;
            println!(
                "  archive   : {n} ({} B, {delta_pct:+.2}% vs part raw, {} members)",
                part_bytes[i],
                part_indexes[i].len()
            );
        }
        println!(
            "  parts     : {} (split: raw {} B > target {} B)   wall {:.1}s",
            part_names.len(),
            raw_bytes,
            split.map(|(t, _)| t).unwrap_or(0),
            t0.elapsed().as_secs_f64()
        );
    }
    println!("  manifest  : {} ({} rows)", manifest.display(), rows.len());
    for line in &sidecar_lines {
        println!("{line}");
    }
    println!("  tar       : {tar_version}");
    println!("  zstd      : {zstd_version}");
    // The reel-manifest facts (B5): the part names (the single-part
    // path = the single archive) + the manifest name + the frames
    // column (j92 = .DNG count, jxl = the distinct frame stems).
    Ok(ClipBakeResult {
        clip: clip.to_string(),
        codec,
        part_names: if part_names.is_empty() {
            vec![format!("{clip}.{container}")]
        } else {
            part_names.clone()
        },
        manifest_name: format!("{clip}.bake-manifest.tsv"),
        frames: clip_frame_count(files, codec),
        members: rows.len(),
    })
}

/// `frameprism bake --iso <reel-dir> <image.iso> [--zstd …] [--force]`
/// — the sealed-tier reel image .
///
/// `<reel-dir>` = a flat dir of .DNG and/or .jxl frames (one or more
/// clip groups — the clip is derived from the frame name prefix: the
/// first two underscore-separated tokens of the stem,
/// `A001_001_20260701_000001.DNG` → clip `A001_001`; a same-named clip
/// with both codecs is a hard reject — the clean disambiguation rule,
/// the staged `<clip>.bake-manifest.tsv` names would otherwise
/// collide). Every (clip, codec) group gets the SAME per-clip archive
/// and v2 manifest that `run` writes (staging byte-identical by
/// construction — `bake_clip` is the shared core), with per-group
/// container detection (j92 → tar.zst-19, jxl → the store tar)
/// unless an explicit `--zstd` wins for all. A per-clip archive whose
/// raw members exceed the part target bakes the
/// `<clip>.partNN.<container>` parts . The staged
/// members are imaged into `<image.iso>` as a hybrid
/// ISO9660+Joliet+Rock Ridge disk image (the pinned fstool 0.4.33,
/// in-process + the pin-times pass — the epoch-pinned record dates):
/// natively mountable on macOS/Windows/Linux with zero tooling — the
/// mount is the audit surface: `frameprism audit
/// <mount>` lists the per-clip archive parts (`tar -tf`) and sha-
/// sweeps every member against the embedded manifest rows (the bake-
/// manifest-aware audit path — the `*.checksums.tsv` sidecars are
/// absent on the mount by design; the manifest IS the sealed-tier
/// sidecar).
/// No UDF layer: the pinned fstool 0.4.33 writer does not produce UDF
/// (verified in the pinned crate source), and the 9660 layer is the
/// mount guarantee on macOS 26 (native UDF mounting dropped there).
///
/// `<image.iso>` = a FILE path (not a dir; the parent dir is created
/// if missing; an existing image requires `--force`). The reel input
/// is .DNG and/or .jxl frames only (frames-only convention — no
/// sidecars, no foreign files; a JXL reel bakes the store-tar parts).
/// Scaling: ISO9660's practical per-file boundary is ~2 GB — a
/// per-clip archive whose raw members exceed the part target (default
/// 1.5 GiB; the `FRAMEPRISM_ISO_PART_MAX` env var overrides target+max
/// for tests) is split into contiguous parts (each part's raw ≤
/// target < 2 GB); whole-image size is not a 9660 concern (volumes
/// run to BD size).
pub fn run_iso(
    input: &Path,
    image: &Path,
    zstd: Option<u32>,
    force: bool,
    resume: bool,
    // -G4 (the sealed-tier .sig ride): the WORKING-TIER reel dir —
    // the dir the reel manifest + its `.sig` live in (the `bake
    // <out> <reel-dir>` output dir, AFTER `frameprism sign` ran on its
    // reel manifest). Some = the ISO stages the SIGNED manifest + the
    // `.sig` as the `provenance/` bundle at the image root (the
    // keyless seal-gate checks refuse named before the image path is
    // created); None = the existing image shape (byte-identical).
    reel_out: Option<&Path>,
) -> Result<BakeOutcome> {
    let t0 = Instant::now();

    if !input.is_dir() {
        bail!("bake: --iso input is not a directory: {}", input.display());
    }
    let in_abs = std::fs::canonicalize(input)
        .with_context(|| format!("bake: --iso canonicalize {}", input.display()))?;

    // --- image path guards (a file path, disjoint from the input) ------
    if image.is_dir() {
        bail!(
            "bake: --iso image path {} is a directory (expected a file path like reel.iso)",
            image.display()
        );
    }
    let image_parent = image
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&image_parent).with_context(|| {
        format!("bake: --iso create image parent {}", image_parent.display())
    })?;
    let image_parent_abs = std::fs::canonicalize(&image_parent)
        .with_context(|| format!("bake: --iso canonicalize {}", image_parent.display()))?;
    if image_parent_abs == in_abs || image_parent_abs.starts_with(&in_abs) {
        bail!(
            "bake: --iso image {} must not live inside the input dir {}",
            image.display(),
            in_abs.display()
        );
    }
    if image.exists() && !force {
        if resume {
            //: the resume semantics subsume the overwrite
            // guard — the completion check below decides the named
            // skip vs the named redo (the stale image is removed, not
            // "overwritten without asking").
        } else {
            bail!(
                "bake: refusing to overwrite existing image {} (use --force)",
                image.display()
            );
        }
    }

    // --- collect + group the reel frames by (clip, codec) prefix -------
    // The sealed-tier reel payload is the J92 (.DNG) and/or the JXL
    // (.jxl) frames — frames only (no sidecars, no foreign files).
    // Tree mode: the clip folders are the groups —
    // frames + the clip-folder sidecars (the tree mode is the sidecar
    // tree; the frames-only rule is the FLAT path's convention).
    let (mut groups, is_tree) = if is_tree_mode(input) {
        let (clips, root_notes) = collect_tree(input)?;
        for note in &root_notes {
            eprintln!("{note}");
        }
        // The active selection filters the clip
        // set (absent = the full set — the byte-identity path).
        let clips: Vec<&TreeClip> = match crate::selection::current() {
            Some(a) => clips.iter().filter(|c| a.selected.contains(&c.key)).collect(),
            None => clips.iter().collect(),
        };
        if clips.is_empty() {
            bail!(
                "bake: --iso no clip folders with frames in {} — nothing to image (the selection, when active, named no clip folder)",
                input.display()
            );
        }
        let mut g: std::collections::BTreeMap<(String, &'static str), Vec<(String, PathBuf)>> =
            std::collections::BTreeMap::new();
        for c in &clips {
            g.insert((c.key.clone(), c.codec), c.files.clone());
        }
        (g, true)
    } else {
        let files = collect_files(input)?;
        if files.is_empty() {
            bail!("bake: --iso no files in {} — empty reel dir", input.display());
        }
        let mut g: std::collections::BTreeMap<(String, &'static str), Vec<(String, PathBuf)>> =
            std::collections::BTreeMap::new();
        for (rel, p) in &files {
            let codec: &'static str = if ext_is(rel, "dng") {
                "j92"
            } else if ext_is(rel, "jxl") {
                "jxl"
            } else {
                bail!(
                    "bake: --iso reel input must be .DNG and/or .jxl frames only (got {rel} in {}) — the sealed-tier reel payload is the J92 and/or JXL frames (no sidecars, no foreign files)",
                    input.display()
                );
            };
            let clip = clip_prefix(rel)?;
            g.entry((clip.clone(), codec)).or_default().push((rel.clone(), p.clone()));
        }
        (g, false)
    };
    // One codec per clip (a same-named clip with both codecs would
    // collide on the staged <clip>.bake-manifest.tsv name — a hard
    // reject, the clean disambiguation rule).
    {
        let mut seen: std::collections::BTreeMap<&str, &'static str> =
            std::collections::BTreeMap::new();
        for (clip, codec) in groups.keys() {
            if let Some(prev) = seen.get(clip.as_str()) {
                if *prev != *codec {
                    bail!(
                        "bake: --iso clip {clip} has both .DNG and .jxl frames — one codec per clip in a reel (split the frames into separate reel dirs)"
                    );
                }
            }
            seen.insert(clip.as_str(), codec);
        }
    }
    // The selection on the flat path: the active selection
    // filters the clip PREFIX groups (the tree path filtered at the
    // collection; absent = the full set — the byte-identity path).
    if let Some(a) = crate::selection::current() {
        groups.retain(|(clip, _), _| a.selected.contains(clip));
        if groups.is_empty() {
            bail!(
                "bake: --iso the selection names no clip group(s) in {} — nothing to image",
                input.display()
            );
        }
    }
    let total_files: usize = groups.values().map(|f| f.len()).sum();

    // ---: the --resume completion marker (before any
    // --- staging byte) ----------------------------------------------
    // The B6 image sha sidecar is the completion marker: the image +
    // the verifying `<image>.sha256` (re-hashed) = done → the named
    // skip (no re-image, no staging); else the stale image + sidecar
    // are removed (named) and the reel rebuilds from zero. (The
    // unique-per-run $TMPDIR staging dirs of SIGTERM'd runs are left
    // alone — a concurrent run's scratch is never touched; they are
    // unique-named + the manual cleanup is trivial.)
    if resume {
        let image_sidecar = image.with_file_name(format!(
            "{}.sha256",
            image
                .file_name()
                .map(|s| s.to_string_lossy())
                .unwrap_or_default()
        ));
        if image.exists() && image_sidecar.exists() {
            match verify_object_sidecar(image, &image_sidecar) {
                Ok(true) => {
                    eprintln!(
                        "bake: --iso resume: {} verified complete (the image sha256 sidecar matches) — skipped, no re-image",
                        image.display()
                    );
                    println!(
                        "bake: --iso resume: {} + {} — verified complete, no re-image (the completion marker holds)",
                        image.display(),
                        image_sidecar.display()
                    );
                    let mut uniq: Vec<&'static str> =
                        groups.keys().map(|(_, k)| *k).collect();
                    uniq.sort();
                    uniq.dedup();
                    return Ok(BakeOutcome {
                        codec: uniq.join("+"),
                        frames: total_files as u64,
                    });
                }
                Ok(false) => eprintln!(
                    "bake: --iso resume: the sidecar does not verify over the on-disk image — removing the stale image + sidecar and re-imaging"
                ),
                Err(e) => eprintln!(
                    "bake: --iso resume: the sidecar is unreadable ({e}) — removing the stale image + sidecar and re-imaging"
                ),
            }
            let _ = std::fs::remove_file(image);
            let _ = std::fs::remove_file(&image_sidecar);
        } else if image.exists() {
            eprintln!(
                "bake: --iso resume: the image exists without its .sha256 sidecar (the completion marker is missing — an interrupted image) — removing the stale image and re-imaging",
            );
            let _ = std::fs::remove_file(image);
            let _ = std::fs::remove_file(&image_sidecar);
        }
    }

    // --- container: explicit --zstd always wins (all groups), else
    // per-group detection (j92 → 19, jxl → none = the JXL store tar)
    let explicit: Option<u32> = match zstd {
        Some(l) => {
            if l != 0 && l != 9 && l != 19 {
                bail!("bake: --zstd level must be 0 (none), 9 or 19 (got {l})");
            }
            Some(l)
        }
        None => None,
    };

    // --- the per-clip part split ----------------------
    let split = part_bounds()?;

    // --- stage the per-clip archives (byte-identical to the non-iso path)
    // the {seq} suffix is the in-process uniqueness guarantee — the wall-clock field is cross-process only
    let seq = ISO_STAGING_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let staging = std::env::temp_dir().join(format!(
        "frameprism-iso-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        seq
    ));
    std::fs::create_dir_all(&staging)
        .with_context(|| format!("bake: --iso create staging dir {}", staging.display()))?;
    let _staging_guard = StagingGuard { dir: staging.clone() };

    let mut containers: Vec<String> = Vec::with_capacity(groups.len());
    let mut results: Vec<ClipBakeResult> = Vec::new();
    for ((clip, codec), clip_files) in &groups {
        let (zstd_level, detected) = match explicit {
            Some(l) => (if l == 0 { None } else { Some(l) }, false),
            None => {
                if *codec == "j92" {
                    (Some(19), true)
                } else {
                    (None, true) // the JXL container: the store tar
                }
            }
        };
        let container: &'static str = if zstd_level.is_some() { "tar.zst" } else { "tar" };
        containers.push(format!(
            "{codec}: {container} (zstd {})",
            zstd_level.map(|l| l.to_string()).unwrap_or_else(|| "none".into())
        ));
        // The clip group's existence validation (the named error path
        // — the in-process writer opens the files' own paths, no `-C`;
        // the member names are the frame basenames — the FLAT reel
        // root (already canonicalized above as `in_abs`) and the TREE
        // clip folder both carry them directly).
        if is_tree {
            std::fs::canonicalize(input.join(clip))
                .with_context(|| format!("bake: --iso canonicalize clip folder {clip}"))?;
        }
        let res = bake_clip(
            clip,
            clip_files,
            codec,
            container,
            zstd_level,
            &staging,
            force,
            detected,
            Some(PINNED_EPOCH),
            Some(split),
            // The B6 sidecars are NOT staged: the image bytes must
            // not change (the sidecar is a separate file — the
            // `<image>.sha256` is written by run_iso next to the
            // image after the image build).
            false,
            // The staging path NEVER runs the resume completion
            // check (the staging dir is scratch — the marker
            // lives next to the final objects: the out dir for the
            // flat bake, the image for --iso).
            false,
        )?;
        results.push(res);
    }
    // The B5 reel manifest: staged at the image root when >1 clip
    // archive is staged (the single-clip reel keeps the existing image
    // shape — R-INV). created = the pinned epoch + the mtime pinned by
    // the loop below (the image determinism).
    if results.len() > 1 {
        let mut rows: Vec<crate::reel::ReelRow> = Vec::new();
        for r in &results {
            let mb = std::fs::read(staging.join(&r.manifest_name))
                .with_context(|| format!("bake: --iso read the manifest {}", r.manifest_name))?;
            rows.push(crate::reel::ReelRow {
                clip: r.clip.clone(),
                codec: r.codec.to_string(),
                archives: r.part_names.clone(),
                archive_shas: reel_row_shas(&staging, r, "--iso")?,
                manifest: r.manifest_name.clone(),
                manifest_sha: sha256_hex(&mb),
                frames: r.frames,
            });
        }
        let tsv = crate::reel::render(PINNED_EPOCH, &rows);
        let path = staging.join(crate::reel::REEL_MANIFEST_NAME);
        std::fs::write(&path, tsv)
            .with_context(|| format!("bake: --iso write the reel manifest {}", path.display()))?;
    }

    // --- (the sealed-tier .sig ride): the provenance bundle ----
    // The SIGNED working-tier reel manifest + its `.sig` stage as the
    // `provenance/` bundle at the image root: a reader decades from now extracts
    // `provenance/` and runs `frameprism verify
    // provenance/reel.reel-manifest.tsv --key <pubkey>` → the full
    // VERIFY OK from the sealed artifact alone. The ISO's OWN
    // pinned-epoch manifest (the image root) is UNCHANGED — the bundle
    // rides alongside it, under its own name. The staging-time KEYLESS
    // checks (the seal gate — all named rc=2 refusals, zero partial
    // files: the image path is NOT created on a refusal; the staging
    // dir is scratch, the guard removes it): 7 (the shape gate first —
    // a single-clip ISO stages no reel manifest, so the content-row
    // binding has nothing to bind), then 1 the reel-out reel manifest
    // exists; 2 the adjacent `.sig` exists (sign it first — the sealed
    // ISO will not carry a dead reference); 3 the envelope is
    // WELL-FORMED (the existing parser — the same wording class as the
    // audit line); 4 the envelope's `manifest_sha256` == the sha256 of
    // the reel-out manifest bytes (the envelope binds the presented
    // manifest); 5 THE CONTENT-ROW BINDING (the reel-A-into-reel-B
    // attack): both manifests are PARSED with the strict reel parser
    // (a parse failure on either side = the named refusal) and every
    // parsed field must match except the epoch-derived free variables
 // — exactly two (the recorded decision, the approved widening:
    // the original "modulo the created: line" spec was factually
    // insufficient because the per-row manifest_sha256 column also
    // encodes the epoch — it hashes the per-clip manifest, whose only
    // free variable is its own created: line): the `created:` epoch
    // line and the per-row `manifest_sha256` column. The content rows
    // remain bound by clip / codec / archive / archive_sha256 /
    // manifest-name / frames — a signature for a different reel is
    // refused the seal.
    let mut bundle_staged = false;
    if let Some(reel_out) = reel_out {
        let ro_manifest = reel_out.join(crate::reel::REEL_MANIFEST_NAME);
        let ro_sig =
            ro_manifest.with_file_name(format!("{}.sig", crate::reel::REEL_MANIFEST_NAME));
        if results.len() < 2 {
            bail!(
                "bake: --iso --reel-out: the reel is a single clip — the single-clip ISO carries no reel manifest (use the multi-clip reel — the provenance bundle rides the multi-clip ISO)"
            );
        }
        if !ro_manifest.is_file() {
            bail!(
                "bake: --iso --reel-out: the reel manifest is absent from the --reel-out dir {} (expected {}/reel.reel-manifest.tsv — the working-tier bake's reel manifest)",
                reel_out.display(),
                reel_out.display()
            );
        }
        if !ro_sig.is_file() {
            bail!(
                "bake: --iso --reel-out: the reel manifest carries no .sig — sign it first (frameprism sign {}/reel.reel-manifest.tsv --key <private key file>); the sealed ISO will not carry a dead reference",
                reel_out.display()
            );
        }
        let ro_manifest_bytes = std::fs::read(&ro_manifest).with_context(|| {
            format!(
                "bake: --iso --reel-out read the reel manifest {}",
                ro_manifest.display()
            )
        })?;
        let env = match crate::provenance::parse_envelope(&ro_sig) {
            Ok(e) => e,
            Err(e) => bail!(
                "bake: --iso --reel-out: malformed envelope {}: {e} (the provenance claim does not parse — refused the seal)",
                ro_sig.display()
            ),
        };
        if !crate::provenance::envelope_binds_manifest(&env, &ro_manifest_bytes) {
            bail!(
                "bake: --iso --reel-out: the envelope does not bind the presented manifest (the envelope manifest_sha256 {} != the reel-out manifest's sha256 {} — a broken provenance claim is refused the seal)",
                env.manifest_sha256,
                sha256_hex(&ro_manifest_bytes)
            );
        }
        let ro_parsed = match crate::reel::parse(&ro_manifest) {
            Ok(m) => m,
            Err(e) => bail!(
                "bake: --iso --reel-out: malformed reel manifest {} ({e}) — the signed reel manifest does not parse (refused the seal)",
                ro_manifest.display()
            ),
        };
        let staged_manifest_path = staging.join(crate::reel::REEL_MANIFEST_NAME);
        let staged_parsed = match crate::reel::parse(&staged_manifest_path) {
            Ok(m) => m,
            Err(e) => bail!(
                "bake: --iso --reel-out: malformed reel manifest (the staged reel manifest in {}): {e} — the sealed reel's manifest does not parse (refused the seal)",
                staging.display()
            ),
        };
        if !crate::provenance::content_rows_identical(&ro_parsed, &staged_parsed) {
            bail!(
                "bake: --iso --reel-out: the signed manifest's content rows differ from the sealed reel's manifest — a signature for a different reel is refused the seal (the content rows must match on clip / codec / archive / archive_sha256 / manifest name / frames; the only free variables are the created: epoch line and the per-row manifest_sha256 column — it hashes the per-clip manifest, whose only free variable is its own created: epoch line)"
            );
        }
        stage_provenance_file(&staging, crate::reel::REEL_MANIFEST_NAME, &ro_manifest)?;
        stage_provenance_file(
            &staging,
            &format!("{}.sig", crate::reel::REEL_MANIFEST_NAME),
            &ro_sig,
        )?;
        bundle_staged = true;
    }
    let staged_count = std::fs::read_dir(&staging).map(|rd| rd.count()).unwrap_or(0);

    // --- determinism: pin the mtimes of the staged tree ------------------
 // The staged host mtimes are pinned to the epoch. (Pre- the
    // pinned xorriso carried them into the image via the Rock Ridge TF;
    // the in-process writer takes the entry times from the FileMeta we
    // pass and the image's record-date fields from the pin-times pass —
    // the host mtimes no longer reach the image bytes, but the pin
    // STAYS: it keeps the staged tree a deterministic input, and the
    // writer's FileMeta fields are already plumbed at 0.4.33 — a future
    // writer release that carries them gets a pinned input by
    // construction.)
    let mk_pinned_times = || {
        let t = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(PINNED_EPOCH);
        std::fs::FileTimes::new().set_accessed(t).set_modified(t)
    };
    for entry in std::fs::read_dir(&staging)
        .with_context(|| format!("bake: --iso read staging dir {}", staging.display()))?
    {
        let entry = entry.with_context(|| "bake: --iso read staging entry".to_string())?;
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        std::fs::File::open(&p)
            .with_context(|| format!("bake: --iso open staged member {}", p.display()))?
            .set_times(mk_pinned_times())
            .with_context(|| format!("bake: --iso pin mtime of staged member {}", p.display()))?;
    }
    std::fs::File::open(&staging)
        .with_context(|| format!("bake: --iso open staging dir {}", staging.display()))?
        .set_times(mk_pinned_times())
        .with_context(|| format!("bake: --iso pin mtime of staging dir {}", staging.display()))?;
    // -G4: the provenance/ bundle subdir (when staged) — the same
    // mtime coverage as the top-level members (the image's byte-
    // identity anchor rides the pin-times pass + the writer's FileMeta
    // now; the host pin stays the deterministic input — see above;
    // the bundle files themselves are deterministic for a fixed
    // signed_at — the same signed manifest + the same .sig bytes).
    let provenance_dir = staging.join("provenance");
    if provenance_dir.is_dir() {
        for entry in std::fs::read_dir(&provenance_dir)
            .with_context(|| format!("bake: --iso read the provenance dir {}", provenance_dir.display()))?
        {
            let entry = entry.with_context(|| "bake: --iso read the provenance entry".to_string())?;
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            std::fs::File::open(&p)
                .with_context(|| format!("bake: --iso open the staged bundle file {}", p.display()))?
                .set_times(mk_pinned_times())
                .with_context(|| format!("bake: --iso pin mtime of the staged bundle file {}", p.display()))?;
        }
        std::fs::File::open(&provenance_dir)
            .with_context(|| format!("bake: --iso open the provenance dir {}", provenance_dir.display()))?
            .set_times(mk_pinned_times())
            .with_context(|| format!("bake: --iso pin mtime of the provenance dir {}", provenance_dir.display()))?;
    }

    // --- the volume label (the reel name = the in-dir basename) ---------
    let label_full = in_abs
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "reel".into());
    let label: String = if label_full.chars().count() > 32 {
        let t: String = label_full.chars().take(32).collect();
        eprintln!(
            "bake: --iso reel label '{label_full}' exceeds the 9660 volume-label limit — truncated to '{t}' (32 chars)"
        );
        t
    } else {
        label_full
    };

    // --- image (the in-process writer + the pin-times pass) ------------
    // The pinned fstool (the in-process ISO9660+Joliet+Rock Ridge
    // writer — no external binary; the no-RAM-ceiling design: the
    // payload streams through a bounded scratch straight to the
    // device) + the pin-times pass (the post-build overwrite of every
 // directory record's 7-byte date field with the project pin — the
 // maintainer's "epoch" decision: the stored instant is machine-
    // independent, so the image bytes are the same on every build
    // machine, in every TZ). The image bytes are a pure function of
    // (staged content, label, PINNED_EPOCH) — the sealed tier joins
    // the byte-identity culture on the patched output.
    let fstool_version = env!("FRAMEPRISM_FSTOOL_CRATE_VERSION");
    eprintln!(
        "bake: --iso image: fstool {fstool_version} (in-process) + the pin-times pass (epoch {PINNED_EPOCH}) — {} → {}",
        staging.display(),
        image.display()
    );
    // The device (the sparse headroom file) + the in-process build +
    // the pin-times pass (the production seam — the R7 tests drive the
    // same function with a synthetic staging tree):
    build_iso_image(&staging, image, &label)?;
    let image_bytes = std::fs::metadata(image)
        .with_context(|| format!("bake: --iso stat {}", image.display()))?
        .len();

    // --- the B6 image sha sidecar (after the image write, before the
    // --- summary): `<reel.iso>.sha256` next to the image — the
    // one-liner verify after the sealed ISO moves to another disk.
    // The STREAMING sha (the bounded-
    // read discipline: the multi-GB reel image is never loaded whole
    // into RAM — the `SHA256_CHUNK`-buffered `sha256_stream_path`,
    // byte-identical to the one-shot by construction; the one-shot
    // `fs::read(image)` is gone — the whole-file-read RSS class on a
    // named user action is closed). The sidecar bytes are the same
    // (the same sha, the sidecar format — the named test pins it).
    let image_sha = crate::jxl::sha256_stream_path(image)
        .with_context(|| format!("bake: --iso read {}", image.display()))?;
    let image_sidecar = write_object_sha_sidecar(image, &image_sha)?;

    // --- summary (stdout → the run log) ---------------------------------
    let clip_summary: Vec<String> = groups
        .iter()
        .map(|((c, k), f)| {
            let unit = if is_tree {
                "member(s)"
            } else if *k == "j92" {
                ".DNG frame(s)"
            } else {
                ".jxl plane(s)"
            };
            format!("{c} [{k}] ({} {unit})", f.len())
        })
        .collect();
    let unit_word = if is_tree { "member(s)" } else { "frame(s)" };
    println!(
        "bake: reel {label} — {} clip group(s), {total_files} {unit_word} → sealed-tier ISO9660+Joliet+RockRidge image ({})",
        groups.len(),
        if explicit.is_some() { "explicit --zstd" } else { "detected per codec" }
    );
    println!("  clips     : {}", clip_summary.join(" + "));
    println!("  container : {}", containers.join(" + "));
    println!(
        "  image     : {} ({} B)   wall {:.1}s",
        image.display(),
        image_bytes,
        t0.elapsed().as_secs_f64()
    );
    println!(
        "  sidecar   : {} (object sha256 — the B6 one-liner verify)",
        image_sidecar.display()
    );
    println!(
        "  staged    : {} ({} member file(s) — per-clip archive/part + v2 manifest{})",
        staging.display(),
        staged_count,
        if results.len() > 1 {
            ", + the reel manifest"
        } else {
            ""
        }
    );
    if results.len() > 1 {
        println!(
            "  reel      : reel.reel-manifest.tsv staged at the image root ({} clip(s) — the reel manifest, B5)",
            results.len()
        );
    }
    if bundle_staged {
        println!(
            "  provenance: provenance/reel.reel-manifest.tsv + provenance/reel.reel-manifest.tsv.sig staged at the image root (the provenance bundle — the signed working-tier reel manifest + its .sig; a reader decades from now extracts provenance/ and runs `frameprism verify provenance/reel.reel-manifest.tsv --key <pubkey>` for the full VERIFY OK from the sealed artifact)"
        );
    }
    // The selection line (stdout — the bake summary carries the same
    // line; the tree mode always records it, a selection-filtered flat
    // reel records it, the unselected flat reel keeps its existing
    // summary shape — R-INV).
    if is_tree || crate::selection::current().is_some() {
        println!(
            "  selection : {}",
            crate::selection::report_line(crate::selection::current(), results.len())
        );
    }
    println!("  fstool    : {fstool_version} (in-process — the ISO writer + the pin-times pass)");
    println!(
        "  pinned    : epoch {PINNED_EPOCH} (the image's record-date fields + the PVD/SVD dates + the staged manifests' created field — the \"epoch\" mode: the stored instant is machine-independent)"
    );
    // The ledger facts (A3): the distinct group codecs (the reel may
    // mix j92 + jxl clip groups — `+`-joined) + the reel's frame count.
    let mut uniq: Vec<&'static str> = groups.keys().map(|(_, k)| *k).collect();
    uniq.sort();
    uniq.dedup();
    Ok(BakeOutcome {
        codec: uniq.join("+"),
        frames: total_files as u64,
    })
}

/// The in-process ISO image build (the pinned fstool writer + the
/// pin-times pass): `staging` (the flat staged members + the optional
/// `provenance/` subdir) → `image`. The device is the sparse headroom
/// file (the payload size + 16 MiB — the writer places the metadata
/// after the data area, inside image_len; the headroom tail is pure
/// set_len slack, truncated after flush); the sizing is bounded
/// (metadata() per staged file — never the content). The staged tree →
/// the image root (dirs first, then files; the in-image paths are
/// absolute — the writer's normalize requires it; the FileMeta times
/// carry the pin explicitly even though the pinned writer's encoder
/// ignores them at 0.4.33 (dead code — passed for honest intent +
/// future-proofing, NOT relied upon: the record-date fields ride the
/// pin-times pass)). The pin-times pass runs before the return — the
/// image on disk is the patched image (the sidecar sha's the patched
/// bytes). The image bytes are a pure function of (staged content,
/// label, PINNED_EPOCH).
fn build_iso_image(staging: &Path, image: &Path, label: &str) -> Result<()> {
    let provenance_dir = staging.join("provenance");
    const ISO_DEVICE_HEADROOM: u64 = 16 * 1024 * 1024;
    let payload_bytes = staged_payload_bytes(staging, &provenance_dir)?;
    let mut dev =
        FileBackend::create(image, payload_bytes + ISO_DEVICE_HEADROOM)
            .with_context(|| format!("bake: --iso create the image device {}", image.display()))?;
    let opts = FormatOpts {
        volume_id: label.to_string(),
        publisher_id: String::new(),
        data_preparer_id: String::new(),
        application_id: String::new(),
        joliet: true,
        rock_ridge: true,
        el_torito: None,
        create_date: PINNED_EPOCH as u32,
    };
    let mut iso = Iso9660::format(&mut dev, &opts)
        .with_context(|| "bake: --iso format the image (the pinned fstool)".to_string())?;
    let meta = FileMeta {
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: PINNED_EPOCH as u32,
        atime: PINNED_EPOCH as u32,
        ctime: PINNED_EPOCH as u32,
    };
    if provenance_dir.is_dir() {
        iso
            .create_dir(&mut dev, Path::new("/provenance"), meta)
            .with_context(|| "bake: --iso create the provenance/ dir (fstool)".to_string())?;
        for entry in std::fs::read_dir(&provenance_dir)
            .with_context(|| {
                format!("bake: --iso read the provenance dir {}", provenance_dir.display())
            })?
        {
            let entry = entry.with_context(|| "bake: --iso read the provenance entry".to_string())?;
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let name = p
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            iso
                .create_file(
                    &mut dev,
                    Path::new(&format!("/provenance/{name}")),
                    FileSource::HostPath(p.clone()),
                    meta,
                )
                .with_context(|| {
                    format!("bake: --iso add the staged bundle file {} (fstool)", p.display())
                })?;
        }
    }
    for entry in std::fs::read_dir(staging)
        .with_context(|| format!("bake: --iso read staging dir {}", staging.display()))?
    {
        let entry = entry.with_context(|| "bake: --iso read staging entry".to_string())?;
        let p = entry.path();
        if !p.is_file() {
            continue; // the provenance/ dir (created above)
        }
        let name = p
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        iso
            .create_file(
                &mut dev,
                Path::new(&format!("/{name}")),
                FileSource::HostPath(p.clone()),
                meta,
            )
            .with_context(|| format!("bake: --iso add the staged member {} (fstool)", p.display()))?;
    }
    iso.flush(&mut dev)
        .with_context(|| "bake: --iso flush the image (fstool)".to_string())?;
    // The image length (the writer's own number — the device was
    // provisioned with headroom; truncate to the exact length).
    let image_len = match iso.image_len() {
        Some(len) => len,
        None => bail!(
            "bake: --iso the writer reported no image length after flush (fstool drift — re-pin)"
        ),
    };
    let image_file = std::fs::OpenOptions::new()
        .write(true)
        .open(image)
        .with_context(|| format!("bake: --iso open the image for the truncate {}", image.display()))?;
    image_file
        .set_len(image_len)
        .with_context(|| format!("bake: --iso truncate the image to {image_len} B"))?;
    // The pin-times pass (after the build + truncate — the image on
    // disk is the patched image; the caller's sidecar sha's the
    // patched bytes):
    crate::iso_times::pin_record_dates(image, PINNED_EPOCH as u32)
        .with_context(|| format!("bake: --iso the pin-times pass on {}", image.display()))?;
    Ok(())
}

/// The staged tree's total payload byte count (the top-level members plus
/// the provenance/ bundle files when present) — the device headroom
/// sizing input. `metadata().len()` per file (bounded — the content is
/// never read).
fn staged_payload_bytes(staging: &Path, provenance_dir: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in std::fs::read_dir(staging)
        .with_context(|| format!("bake: --iso read staging dir {}", staging.display()))?
    {
        let entry = entry.with_context(|| "bake: --iso read staging entry".to_string())?;
        let p = entry.path();
        if p.is_file() {
            total += std::fs::metadata(&p)
                .with_context(|| format!("bake: --iso stat the staged member {}", p.display()))?
                .len();
        }
    }
    if provenance_dir.is_dir() {
        for entry in std::fs::read_dir(provenance_dir)
            .with_context(|| {
                format!("bake: --iso read the provenance dir {}", provenance_dir.display())
            })?
        {
            let entry = entry.with_context(|| "bake: --iso read the provenance entry".to_string())?;
            let p = entry.path();
            if p.is_file() {
                total += std::fs::metadata(&p)
                    .with_context(|| {
                        format!("bake: --iso stat the staged bundle file {}", p.display())
                    })?
                    .len();
            }
        }
    }
    Ok(total)
}

/// The clip prefix of a DNG frame name: the first two underscore-separated
/// tokens of the stem (`A001_001_20260701_000001.DNG` → `A001_001`). The
/// reel groups frames by this prefix into per-clip archives.
fn clip_prefix(name: &str) -> Result<String> {
    let stem = Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("bake: --iso cannot read the stem of {name}"))?;
    let mut parts = stem.splitn(3, '_');
    let a = parts.next().unwrap_or("");
    let b = parts.next().unwrap_or("");
    if a.is_empty() || b.is_empty() {
        bail!(
            "bake: --iso cannot derive a clip prefix from DNG name {name} (expected <CLIP_ID>_<…>.DNG, e.g. A001_001_20260701_000001.DNG)"
        );
    }
    Ok(format!("{a}_{b}"))
}

/// The pinned --iso epoch (verified: `date -u -r 1789344000`). The
/// contract's original constant (1757798400) does not encode the
/// pinned date; corrected here (disclosed deviation). SINGLE SOURCE
/// OF TRUTH for the pin: the image's record-date fields (the
/// pin-times pass) + the PVD/SVD dates (the writer's create_date) +
/// the summary line AND the staged manifests' `created` field (incl.
/// the staged reel manifest — pinned so the staged content, and thus
/// the image, is deterministic).
const PINNED_EPOCH: u64 = 1789344000;

/// The ISO staging-dir per-process uniqueness counter: the staging name is
/// `frameprism-iso-{pid}-{nanos}-{seq}`. The platform wall clock is coarse (µs
/// quantization — ~24k distinct values over 200k `time_ns()` calls), so the
/// nanos field is NOT unique per call under parallel load: two concurrent
/// `run_iso` calls in one process can land on the same name and share one
/// staging dir. The counter is the in-process uniqueness guarantee (the wall-clock field stays for
/// cross-process uniqueness, the existing behavior). Deterministic — no
/// randomness (the program's determinism posture).
static ISO_STAGING_SEQ: std::sync::atomic::AtomicU64 = AtomicU64::new(1);

/// Removes the reel's temp staging dir on scope exit (success or error) —
/// the staging dir is scratch, never a product output.
struct StagingGuard {
    dir: PathBuf,
}
impl Drop for StagingGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Case-insensitive file extension test (the tool's `.DNG`/`.jxl`
/// convention — see `crate::jxl::collect`).
fn ext_is(name: &str, ext: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case(ext))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// -G4 (the seal gate's check 6): the `--reel-out` usage
    /// refusal is the usage-refusal prefix class (the CLI returns
    /// rc=2 with no ledger row — a run that never started appends no
    /// row).
    #[test]
    fn reel_out_non_iso_refusal_is_usage_class() {
        let msg = reel_out_non_iso_refusal(Path::new("reel"));
        assert!(
            msg.starts_with("bake: --reel-out"),
            "the refusal carries the usage-refusal prefix: {msg}"
        );
        assert!(is_usage_refusal(&msg), "the refusal classifies as a usage refusal");
        assert!(
            msg.contains("--iso flag"),
            "the refusal names the flag's --iso-only scope: {msg}"
        );
    }

    /// -G4 (the zero-partial-files property): a `--reel-out` seal
    /// refusal creates NO image path (the staging dir is scratch —
    /// the guard removes it; the image is written only after the seal
    /// gate passes). The fixture: a flat 2-clip reel dir (tiny
    // synthetic frames — the bake is a pure container: no DNG parse)
    // + an EMPTY reel-out dir (check 1 — the reel manifest is
    // absent). The refusal fires before any archive work — no
    // toolchain needed (the in-process container + ISO components
    // have no PATH resolution).
    #[test]
    fn reel_out_refusal_creates_no_image() {
        let base =
            std::env::temp_dir().join(format!("frameprism_bake_reelout_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let input = base.join("reel-in");
        std::fs::create_dir_all(&input).unwrap();
        std::fs::write(input.join("A001_001_20260914_000001.DNG"), vec![0u8; 256]).unwrap();
        std::fs::write(input.join("A001_002_20260914_000001.DNG"), vec![1u8; 256]).unwrap();
        let reel_out = base.join("reel-out");
        std::fs::create_dir_all(&reel_out).unwrap();
        let image = base.join("image.iso");
        let err = run_iso(
            &input,
            &image,
            None,
            false,
            false,
            Some(&reel_out),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("the reel manifest is absent from the --reel-out dir"),
            "the named check-1 refusal must fire: {msg}"
        );
        assert!(is_usage_refusal(&msg), "the refusal classifies as a usage refusal: {msg}");
        assert!(!image.exists(), "the zero-partial-files property: the image path is NOT created on a refusal");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// -G4 (the content-row binding's parse-failure class): a
    /// MALFORMED reel-out manifest that carries a valid envelope
    /// (checks 1–4 pass — the envelope's sha binds the garbage bytes;
    /// `sign` hashes the manifest bytes, it does not parse them) is
    /// refused at the PARSE step with the named rc=2, and no image
    /// path is created.
    #[test]
    fn reel_out_malformed_manifest_refusal_creates_no_image() {
        let base =
            std::env::temp_dir().join(format!("frameprism_bake_reelout_malformed_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let input = base.join("reel-in");
        std::fs::create_dir_all(&input).unwrap();
        std::fs::write(input.join("A001_001_20260914_000001.DNG"), vec![0u8; 256]).unwrap();
        std::fs::write(input.join("A001_002_20260914_000001.DNG"), vec![1u8; 256]).unwrap();
        let reel_out = base.join("reel-out");
        std::fs::create_dir_all(&reel_out).unwrap();
        let garbage = b"this is not a reel manifest\n";
        let manifest_path = reel_out.join(crate::reel::REEL_MANIFEST_NAME);
        std::fs::write(&manifest_path, garbage).unwrap();
        let seed: [u8; 32] = [0x2a; 32];
        let public = crate::provenance::public_from_seed(&seed);
        let key = crate::provenance::KeyFile {
            kind: crate::provenance::KeyKind::Private,
            fingerprint: crate::jxl::sha256(&public),
            public,
            seed: Some(seed),
        };
        let env = crate::provenance::sign_manifest(
            garbage,
            crate::reel::REEL_MANIFEST_NAME,
            &key,
            1_790_000_000,
            "tool=0.6.0",
        )
        .unwrap();
        crate::provenance::write_envelope(
            &env,
            &manifest_path.with_file_name(format!("{}.sig", crate::reel::REEL_MANIFEST_NAME)),
        )
        .unwrap();
        let image = base.join("image.iso");
        let err = run_iso(
            &input,
            &image,
            None,
            false,
            false,
            Some(&reel_out),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("malformed reel manifest"),
            "the named parse-failure refusal must fire: {msg}"
        );
        assert!(is_usage_refusal(&msg), "the refusal classifies as a usage refusal: {msg}");
        assert!(!image.exists(), "the zero-partial-files property: the image path is NOT created on a refusal");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The bake completion marker's sidecar check —
    /// no sidecar → the redo path; a verifying sidecar → the skip path;
    /// a stale/malformed sidecar → the redo path (never a false skip).
    #[test]
    fn object_sidecar_completion_marker() {
        let base = std::env::temp_dir().join(format!("frameprism_bake_sidecar_{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let object = base.join("A001_001.tar.zst");
        let sidecar = base.join("A001_001.tar.zst.sha256");
        std::fs::write(&object, b"archive-bytes").unwrap();
        let sha = sha256_hex(b"archive-bytes");
        // No sidecar → Err (the completion marker is missing → redo).
        assert!(
            verify_object_sidecar(&object, &sidecar).is_err(),
            "a missing sidecar must be the redo path"
        );
        // The verifying sidecar → Ok(true) (the skip path).
        std::fs::write(&sidecar, format!("{sha}  A001_001.tar.zst\n")).unwrap();
        assert_eq!(
            verify_object_sidecar(&object, &sidecar).unwrap(),
            true,
            "the verifying sidecar is the completion marker"
        );
        // A stale sha → Ok(false) (the marker does NOT hold → redo).
        let stale: String = std::iter::repeat('0').take(64).collect();
        if stale == sha {
            let stale: String = std::iter::repeat('1').take(64).collect();
            std::fs::write(&sidecar, format!("{stale}  A001_001.tar.zst\n")).unwrap();
            assert_eq!(
                verify_object_sidecar(&object, &sidecar).unwrap(),
                false,
                "a stale sha must not verify"
            );
        } else {
            std::fs::write(&sidecar, format!("{stale}  A001_001.tar.zst\n")).unwrap();
            assert_eq!(
                verify_object_sidecar(&object, &sidecar).unwrap(),
                false,
                "a stale sha must not verify"
            );
        }
        // A malformed sha field → Err (named, never a silent skip).
        std::fs::write(&sidecar, "nothex  A001_001.tar.zst\n").unwrap();
        let err = verify_object_sidecar(&object, &sidecar).unwrap_err();
        assert!(err.contains("malformed"), "{err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The `--iso` sidecar's byte-identity (the named
 /// byte-invariance): the streaming sha of a file
    /// equals the one-shot sha of the SAME bytes (SHA-256 is
    /// Merkle–Damgård — one update == the chunked updates; the
    /// primitive is the `Sha256State`, the hex is the shared
    /// `sha256_hex_of`), and `write_object_sha_sidecar` over the
    /// streaming sha produces the sidecar bytes IDENTICAL to the
    /// one-shot sha's sidecar (the sidecar format `{sha}  {name}\n`
    /// unchanged). The fixture sizes straddle the `SHA256_CHUNK`
    /// (1 MiB) read boundary (small / exactly one chunk /
    /// one-chunk-plus-one = the partial-tail path).
    #[test]
    fn iso_sidecar_streaming_sha_byte_identity() {
        let base = std::env::temp_dir().join(format!(
            "frameprism_bake_iso_sidecar_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
 // Deterministic fixture bytes (the suite is a byte-invariance,
        // not a sampling): a position-dependent pattern so an
        // offset/chunk-boundary bug flips the digest.
        let make = |len: usize| {
            let mut b = vec![0u8; len];
            for (i, x) in b.iter_mut().enumerate() {
                *x = ((i % 251) as u8) ^ ((i / 256) as u8);
            }
            b
        };
        for (label, len) in [
            ("small", 1000usize),
            ("chunk", crate::jxl::SHA256_CHUNK),
            ("chunk+1", crate::jxl::SHA256_CHUNK + 1),
        ] {
            let fixture = base.join(format!("fixture-{label}.bin"));
            let bytes = make(len);
            std::fs::write(&fixture, &bytes).unwrap();
            let streamed = crate::jxl::sha256_stream_path(&fixture).unwrap();
            let oneshot = sha256_hex(&std::fs::read(&fixture).unwrap());
            assert_eq!(
                streamed, oneshot,
                "the streaming sha must equal the one-shot sha ({label}, {len} B)"
            );
        }
        // The sidecar byte-identity: the sidecar format (unchanged) over
        // the streaming sha == the one-shot sha's sidecar, byte for
        // byte (the sidecar is frozen).
        let object = base.join("A001_001.iso");
        let object_bytes = make(4096);
        std::fs::write(&object, &object_bytes).unwrap();
        let stream_sha = crate::jxl::sha256_stream_path(&object).unwrap();
        let oneshot_sha = sha256_hex(&object_bytes);
        assert_eq!(stream_sha, oneshot_sha);
        let sidecar = write_object_sha_sidecar(&object, &stream_sha).unwrap();
        let sidecar_bytes = std::fs::read(&sidecar).unwrap();
        assert_eq!(
            sidecar_bytes,
            format!("{oneshot_sha}  A001_001.iso\n").into_bytes(),
            "the sidecar bytes are the one-shot sha's (the sidecar format is unchanged)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    // =====================================================================
 // The in-process ISO writer (the named tests)
    // =====================================================================

 /// R7.3 : the reader readback of the fstool image — a
    /// real (small, temp-dir) fstool build of the synthetic staging
 /// tree (the project part/manifest/provenance shape, seeded, pinned
    /// mtimes) through the production seam → read back THROUGH THE
    /// CRATE'S READER (same pinned crate, the `iso9660` feature — the
 /// reader-check idiom): the volume id as-is + Joliet SVD
    /// present (the raw SVD check: the PVD+1 sector's CD001 magic +
    /// the Supplementary type byte + the Joliet escape sequence) +
    /// Rock Ridge on the primary tree (the RR SP marker in the root
    /// directory record's system-use area — the same check the
    /// crate's open() runs internally) + EVERY file by exact path
    /// sha256-identical to the staged source.
    #[test]
    fn iso_image_reader_readback_full_sha_sweep() {
        let base = std::env::temp_dir().join(format!("frameprism_iso_r73_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let staging = base.join("staging");
        let prov = staging.join("provenance");
        std::fs::create_dir_all(&prov).unwrap();
        let flat: Vec<(&str, &[u8])> = vec![
            ("A001_001.tar.zst", b"seeded-archive-bytes-A001"),
            ("A001_001.bake-manifest.tsv", b"rel\tsize\tsha256\nA001_001.tar.zst\t22\t00\n"),
            ("A002_001.part01.tar.zst", b"seeded-part-bytes-A002-01"),
            ("A002_001.part02.tar.zst", b"seeded-part-bytes-A002-02"),
            ("reel.reel-manifest.tsv", b"clip\tarchive\tcreated\nA001_001\tA001_001.tar.zst\t1789344000\n"),
        ];
        let bundle: Vec<(&str, &[u8])> = vec![
            ("reel.reel-manifest.tsv", b"clip\tarchive\tcreated\nA001_001\tA001_001.tar.zst\t1789344000\n"),
            ("reel.reel-manifest.tsv.sig", b"sealed-sig-bytes"),
        ];
        for (n, b) in &flat {
            std::fs::write(staging.join(n), b).unwrap();
        }
        for (n, b) in &bundle {
            std::fs::write(prov.join(n), b).unwrap();
        }
 // The project shape: the staged mtimes pinned to the epoch (the
        // deterministic input).
        let t = std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(PINNED_EPOCH);
        let pin = |p: &std::path::Path| {
            std::fs::File::open(p)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t))
                .unwrap();
        };
        for entry in std::fs::read_dir(&staging).unwrap().chain(std::fs::read_dir(&prov).unwrap()) {
            pin(&entry.unwrap().path());
        }
        pin(&staging);
        pin(&prov);

        let image = base.join("reel.iso");
        build_iso_image(&staging, &image, "iso-r73").unwrap();
        // --- read back THROUGH THE CRATE'S READER (the same pinned
 // --- crate — the reader-check idiom) --------------
        let mut dev = FileBackend::open_read_only(&image).unwrap();
        let iso = Iso9660::open(&mut dev).unwrap();
        // The volume id as-is (the Joliet-preferred read path).
        assert_eq!(iso.volume_id(), "iso-r73");
 // Bounded block reads (the project read discipline — one 2048 B
        // logical block at a time, never the whole image; the crate's
        // ISO9660 logical block size is 2048 — the writer's PVD
        // logical_block_size field).
        let read_block = |lba: u64| -> [u8; 2048] {
            let mut f = std::fs::File::open(&image).unwrap();
            std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(lba * 2048)).unwrap();
            let mut b = [0u8; 2048];
            std::io::Read::read_exact(&mut f, &mut b).unwrap();
            b
        };
        // The Joliet SVD present (the raw SVD check — the PVD+1 block):
        // the CD001 magic + the SupplementaryVD type byte + the Joliet
        // escape sequence at the system-escape field.
        let svd = read_block(17);
        assert_eq!(svd[0], 2, "the SVD type byte (SupplementaryVD)");
        assert_eq!(&svd[1..6], b"CD001", "the SVD magic");
        assert_eq!(&svd[88..91], b"%/E", "the Joliet escape sequence");
        // Rock Ridge on the primary tree (the RR SP marker in the
        // root directory record's system-use area — the same check
        // the crate's open() runs internally: the PVD's
        // descriptor-embedded root extent → the first record's SUA).
        let pvd = read_block(16);
        let root_lba =
            u32::from_le_bytes(pvd[158..162].try_into().unwrap()) as u64;
        let root_sec = read_block(root_lba);
        let len_dr = root_sec[0] as usize;
        assert!((34..=512).contains(&len_dr), "the '.' record length: {len_dr}");
        let name_len = root_sec[29] as usize;
        let sua = &root_sec[30 + name_len..len_dr];
        assert!(
            sua.windows(7)
                .any(|w| &w[..2] == b"SP" && w[2] >= 7 && w[4] == 0xBE && w[5] == 0xEF),
            "the RR SP marker in the root record's SUA (Rock Ridge on the primary tree)"
        );
        // EVERY file by exact path sha256-identical to the staged
        // source (the full sha sweep — the reader's bytes ARE the
        // staged bytes).
        let files: Vec<(String, Vec<u8>)> = flat
            .iter()
            .map(|(n, b)| (format!("/{n}"), b.to_vec()))
            .chain(
                bundle
                    .iter()
                    .map(|(n, b)| (format!("/provenance/{n}"), b.to_vec())),
            )
            .collect();
        for (path, expected) in &files {
            let mut rd = iso.open_file_reader(&mut dev, path).unwrap();
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut rd, &mut buf).unwrap();
            assert_eq!(buf, *expected, "the member bytes by exact path {path}");
        }
        // The directory listings (the root + the provenance/ subdir —
 // the listing agreement).
        let root_list: Vec<String> = iso
            .list_path(&mut dev, "/")
            .unwrap()
            .iter()
            .map(|e| e.name.clone())
            .collect();
        for (n, _) in flat {
            assert!(root_list.contains(&n.to_string()), "the root listing carries {n}: {root_list:?}");
        }
        assert!(root_list.contains(&"provenance".to_string()), "the root listing carries provenance/: {root_list:?}");
        let prov_list: Vec<String> = iso
            .list_path(&mut dev, "/provenance")
            .unwrap()
            .iter()
            .map(|e| e.name.clone())
            .collect();
        for (n, _) in bundle {
            assert!(prov_list.contains(&n.to_string()), "the provenance/ listing carries {n}: {prov_list:?}");
        }
        let _ = std::fs::remove_dir_all(&base);
    }

 /// R7.4 : the project `--iso` ×2 culture, in-process: the
    /// same staging tree built TWICE (fresh temp dirs, the same pins)
    /// → the two images BYTE-IDENTICAL (full byte compare, the sizes
    /// equal). The image bytes are a pure function of (staged
    /// content, label, PINNED_EPOCH) — the sealed tier's byte-identity
    /// culture on the patched output (no cross-version ISO oracle
 /// exists — the identity is within-writer, the project's culture).
    #[test]
    fn iso_double_build_byte_identity() {
        let base = std::env::temp_dir().join(format!("frameprism_iso_r74_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        // Two identical staging trees (fresh temp dirs — the ×2
        // culture's shape).
        let staging = |i: u8| -> std::path::PathBuf {
            let s = base.join(format!("staging-{i}"));
            let prov = s.join("provenance");
            std::fs::create_dir_all(&prov).unwrap();
            for (n, b) in vec![
                ("A001_001.tar.zst", b"seeded-archive-bytes-A001" as &[u8]),
                ("A001_001.bake-manifest.tsv", b"rel\tsize\tsha256\nA001_001.tar.zst\t22\t00\n" as &[u8]),
                ("reel.reel-manifest.tsv", b"clip\tarchive\tcreated\nA001_001\tA001_001.tar.zst\t1789344000\n" as &[u8]),
            ] {
                std::fs::write(s.join(n), b).unwrap();
            }
            std::fs::write(
                prov.join("reel.reel-manifest.tsv"),
                b"clip\tarchive\tcreated\nA001_001\tA001_001.tar.zst\t1789344000\n",
            )
            .unwrap();
            std::fs::write(prov.join("reel.reel-manifest.tsv.sig"), b"sealed-sig-bytes").unwrap();
            s
        };
        let s1 = staging(1);
        let s2 = staging(2);
        let i1 = base.join("image-1.iso");
        let i2 = base.join("image-2.iso");
        build_iso_image(&s1, &i1, "double").unwrap();
        build_iso_image(&s2, &i2, "double").unwrap();
        let b1 = std::fs::read(&i1).unwrap();
        let b2 = std::fs::read(&i2).unwrap();
        assert_eq!(b1.len(), b2.len(), "the image sizes equal");
        assert_eq!(b1, b2, "the two images are BYTE-IDENTICAL (the ×2 culture)");
        let _ = std::fs::remove_dir_all(&base);
    }

 /// R7.5 : the mounted-mtime audit — the project's G3
    /// hdiutil idiom (the preflight.rs pattern: mount → assert →
    /// unmount + remove on the happy AND error paths — a panic cannot
    /// leak a mount): the built image mounted → EVERY entry (files +
    /// dirs + THE ROOT) has mtime epoch == PINNED_EPOCH exactly (the
    /// TZ-independent assertion — `metadata().modified()` →
    /// `duration_since(UNIX_EPOCH)`, NOT a wall-clock string compare)
    /// → unmount + remove. `#[cfg(target_os = "macos")]` (the gate
    /// runs macos-latest + locally; the Linux/Windows jobs are
    /// `cargo check --locked` only — same scope as the existing
    /// hdiutil tests).
    #[cfg(target_os = "macos")]
    #[test]
    fn iso_mounted_mtime_is_the_pinned_epoch() {
        use std::process::Command;

        let base = std::env::temp_dir().join(format!("frameprism_iso_r75_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let staging = base.join("staging");
        let prov = staging.join("provenance");
        std::fs::create_dir_all(&prov).unwrap();
        for (n, b) in vec![
            ("A001_001.tar.zst", b"seeded-archive-bytes-A001" as &[u8]),
            ("reel.reel-manifest.tsv", b"clip\tarchive\tcreated\nA001_001\tA001_001.tar.zst\t1789344000\n" as &[u8]),
        ] {
            std::fs::write(staging.join(n), b).unwrap();
        }
        std::fs::write(prov.join("reel.reel-manifest.tsv"), b"clip\tarchive\tcreated\nA001_001\tA001_001.tar.zst\t1789344000\n").unwrap();
        std::fs::write(prov.join("reel.reel-manifest.tsv.sig"), b"sealed-sig-bytes").unwrap();

        // The fixture guard: unmount + remove on the happy AND error
        // paths (the Drop runs on normal completion AND on the panic
        // unwind — the G4 cleanup discipline).
        struct Fixture {
            base: std::path::PathBuf,
            mount: std::path::PathBuf,
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
        let mount = base.join("mnt");
        std::fs::create_dir_all(&mount).unwrap();
        let _fixture = Fixture { base: base.clone(), mount: mount.clone() };

        let image = base.join("reel.iso");
        build_iso_image(&staging, &image, "iso-r75").unwrap();
        let attached = Command::new("hdiutil")
            .args(["attach", "-quiet", "-nobrowse", "-mountpoint"])
            .arg(&mount)
            .arg(&image)
            .status()
            .expect("hdiutil attach failed to launch");
        assert!(attached.success(), "hdiutil attach failed");

        // EVERY entry (files + dirs + THE ROOT) has mtime epoch ==
        // PINNED_EPOCH exactly (the TZ-independent assertion).
        fn mounted_mtimes(dir: &std::path::Path) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let p = entry.unwrap().path();
                let secs = std::fs::metadata(&p)
                    .unwrap()
                    .modified()
                    .unwrap()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                assert_eq!(secs, PINNED_EPOCH, "the mounted mtime of {}", p.display());
                if p.is_dir() {
                    mounted_mtimes(&p);
                }
            }
        }
        let root_secs = std::fs::metadata(&mount)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(root_secs, PINNED_EPOCH, "the mounted mtime of THE ROOT");
        mounted_mtimes(&mount);
        // The fixture's Drop (scope end) unmounts + removes — the G4
        // cleanup discipline (the panic path is covered by the same
        // Drop).
    }

    // =====================================================================
 // The in-process container (the D3 writer contract)
    // =====================================================================

 /// T1 : the in-process container is DETERMINISTIC — the
    /// same synthetic input baked twice (fresh temp dirs, the pinned
    /// mtime + mode) produces BYTE-IDENTICAL containers at both zstd
    /// levels (9 + 19) and on the level-none path (the raw-tar part).
    /// The container bytes are a pure function of the input files +
 /// the crate/libzstd versions (the D3 writer contract — no
    /// timestamp beyond the source mtime, no hostname, no tool
    /// surface — the system-tool pipeline's non-determinism classes
    /// are structurally absent).
    #[test]
    fn container_double_bake_is_byte_identical() {
        fn mk_clip(base: &std::path::Path, ext: &str, bytes: &[u8; 2]) {
            std::fs::create_dir_all(base).unwrap();
            for (i, c) in [bytes[0], bytes[1]].into_iter().enumerate() {
                let p = base.join(format!("X001_{i:03}_20260914_000001.{ext}"));
                std::fs::write(&p, vec![c; 2048]).unwrap();
                // The pinned mtime + mode (the only per-run inputs the
                // container carries — the USTAR header fields).
                let f = std::fs::File::options()
                    .read(true)
                    .write(true)
                    .open(&p)
                    .unwrap();
                f.set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(8_640_000))
                    .unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    f.set_permissions(std::fs::Permissions::from_mode(0o644)).unwrap();
                }
            }
        }
        fn sha_of(p: &std::path::Path) -> String {
            crate::jxl::sha256_hex(&std::fs::read(p).unwrap())
        }
        let base =
            std::env::temp_dir().join(format!("frameprism-dblbake-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        // The DNG clip (j92-detect): the zstd levels 9 + 19, each baked
        // twice into a fresh pair of dirs.
        for level in [9u32, 19u32] {
            for tag in ["a", "b"] {
                let in_dir = base.join(format!("in-{level}-{tag}"));
                mk_clip(&in_dir, "DNG", &[1, 2]);
                crate::bake::run(
                    &in_dir,
                    &base.join(format!("out-{level}-{tag}")),
                    Some(level),
                    false,
                    false,
                )
                .expect("the in-process bake");
            }
            // The archive name carries the clip name (the input dir
            // name — the `clip_name` derivation).
            assert_eq!(
                sha_of(&base.join(format!("out-{level}-a/in-{level}-a.tar.zst"))),
                sha_of(&base.join(format!("out-{level}-b/in-{level}-b.tar.zst"))),
                "level {level}: the double-bake containers must be byte-identical"
            );
        }
        // The level-none path (the jxl-detect clip → the raw tar part).
        for tag in ["a", "b"] {
            let in_dir = base.join(format!("in-none-{tag}"));
            mk_clip(&in_dir, "jxl", &[3, 4]);
            crate::bake::run(
                &in_dir,
                &base.join(format!("out-none-{tag}")),
                None,
                false,
                false,
            )
            .expect("the level-none bake (jxl-detect → raw tar)");
        }
        assert_eq!(
            sha_of(&base.join("out-none-a/in-none-a.tar")),
            sha_of(&base.join("out-none-b/in-none-b.tar")),
            "level none: the double-bake raw-tar containers must be byte-identical"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

 /// T3 (D5): the container version fields are the
    /// IN-PROCESS values — the bake manifest's `tar_version` /
    /// `zstd_version` lines carry the `tar <crate-ver> (in-process)` /
    /// `zstd <libzstd-ver> (in-process)` form, built from the
    /// binary-embedded sources (the build.rs value read from the
    /// committed lock for the tar crate; the runtime bundled libzstd's
    /// own version string) — no `--version` probe, no system-tool
 /// surface (the D5 decision).
    #[test]
    fn container_version_fields_are_the_in_process_values() {
        let base =
            std::env::temp_dir().join(format!("frameprism-verfields-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let in_dir = base.join("in");
        std::fs::create_dir_all(&in_dir).unwrap();
        std::fs::write(in_dir.join("X001_001_20260914_000001.DNG"), vec![1u8; 1024]).unwrap();
        let out = base.join("out");
        crate::bake::run(&in_dir, &out, Some(9), false, false).expect("the in-process bake");
        let tsv = std::fs::read_to_string(out.join("in.bake-manifest.tsv")).unwrap();
        let want_tar = format!(
            "tar_version: tar {} (in-process)",
            env!("FRAMEPRISM_TAR_CRATE_VERSION")
        );
        let want_zstd = format!(
            "zstd_version: zstd {} (in-process)",
            zstd::zstd_safe::version_string()
        );
        assert!(
            tsv.lines().any(|l| l == want_tar.as_str()),
            "the manifest carries the embedded tar crate version line: {want_tar:?}\n{tsv}"
        );
        assert!(
            tsv.lines().any(|l| l == want_zstd.as_str()),
            "the manifest carries the runtime libzstd version line: {want_zstd:?}\n{tsv}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
