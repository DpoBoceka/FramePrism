//! The offload's traversal + source inventory: the tree walk + the
//! row collection, the root-boundary guards (the write-path root
//! invariant — a write path that escapes its root is refused before
//! any write) + the canonicalize/prefix helpers, the stale-temp
//! cleanup (the phase-0 residue removal, the named note line), the
//! writability checks.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// The `--to` startup probe: the dest must exist
/// (created) and be WRITABLE before any frame — a named refusal (the
/// caller turns the `Err` into rc=2, before the gate + the encode).
pub fn check_dest_writable(dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)
        .with_context(|| format!("create the --to dest dir {}", dest.display()))?;
    let probe = dest.join(".frameprism-write-probe");
    std::fs::write(&probe, [])
        .with_context(|| format!("write-probe the --to dest dir {}", dest.display()))?;
    let _ = std::fs::remove_file(&probe); // best-effort cleanup
    Ok(())
}


/// Collect EVERY file under `root` (frames + sidecars — the
/// first-class-member rule), mirroring the worker `collect`
/// discipline: symlinked entries are refused (cycle/escape guard) and
/// the (dev, ino) visited set makes a hard-link fan-in / cycle a
/// no-op. Returns (relative POSIX path, absolute path) pairs, sorted by
/// the relative path (the deterministic row order). `pub(crate)` —
/// the camera module's offload detection scan walks the SAME files
/// (the detection key space = the offload row key space by
/// construction).
pub(crate) fn collect_all_files(root: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    let mut visited = std::collections::HashSet::new();
    collect_all_walk(root, root, &mut out, &mut visited)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}


fn collect_all_walk(
    base: &Path,
    dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
    visited: &mut std::collections::HashSet<(u64, u64)>,
) -> Result<()> {
    let meta = std::fs::metadata(dir)
        .with_context(|| format!("read dir {}", dir.display()))?;
    let id = (meta.dev(), meta.ino()); // unix: std::os::unix::fs::MetadataExt
    if !visited.insert(id) {
        return Ok(()); // already visited — symlink cycle (or hard-link fan-in)
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))? {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue; // refuse symlinked entries (cycle/escape guard)
        }
        if p.is_dir() {
            collect_all_walk(base, &p, out, visited)?;
        } else if p.is_file() {
            let rel = p.strip_prefix(base).unwrap_or(&p);
            let rel_s = rel.to_string_lossy().replace("\\", "/");
            out.push((rel_s, p));
        }
    }
    Ok(())
}


/// The stale-temp exact-name double rule: the prefix + the
/// suffix — the atomic-copy seam's temp convention
/// (`._frameprism-offload-<job:08x>.<dst file name>.tmp`). The
/// cleanup deletes ONLY files matching both (the junk temps, never
/// media — a media name a user would not name deliberately cannot
/// match the double rule).
pub(crate) const STALE_TEMP_PREFIX: &str = "._frameprism-offload-";

pub(crate) const STALE_TEMP_SUFFIX: &str = ".tmp";


/// The per-process job id (the atomic-copy seam's temp
/// name): the epoch nanosecond count (the process-start instant) XOR
/// the process id, derived ONCE per process (the `OnceLock` — every file of a job shares the id; a
/// concurrent job = a different process + instant = a different id
/// — a collision at the same tmp path is the named refusal, never an
/// overwrite). NOT on the wire: the temp name is never in a report /
/// manifest (the `._*` ascmhl ignore + the stale cleanup), so its
/// non-determinism is by design.
static JOB_ID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();


pub(crate) fn job_id() -> u32 {
    *JOB_ID.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        (nanos ^ std::process::id() as u128) as u32
    })
}


/// The atomic-copy seam's temp path: the dst's dir (the
/// SAME filesystem = the `rename` is atomic) +
/// `._frameprism-offload-<job:08x>.<dst file name>.tmp`. The `._*`
/// prefix rides the ascmhl manifest's PRE-EXISTING ignore pattern
/// (the zero-manifest-byte-change fact — the temp is invisible to the
/// history without touching the ignore list; a new ignore pattern
/// would have changed the rendered `.mhl` bytes).
pub(crate) fn offload_temp_path(dst: &Path) -> PathBuf {
    let file_name = dst
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    dst.parent()
        .unwrap_or(Path::new("."))
        .join(format!("{STALE_TEMP_PREFIX}{job:08x}.{file_name}{STALE_TEMP_SUFFIX}", job = job_id()))
}


/// The in-flight temp registry (the concurrent-source
/// race closure): the fan-out + the `copy_atomic` seam register their
/// temp paths WHILE THE TEMPS EXIST — the multi-source phase-1 runs
/// one thread per source against the SAME dest roots, and a
/// same-process concurrent writer's temp is NOT stale (the per-core
/// phase-0 cleanup would otherwise delete its sibling's in-flight
/// temp — the pre-existing narrow race the fan-out's longer temp
/// lifetime made live). The registration PRECEDES the temp's
/// existence (register → create), so at any instant an EXISTING
/// unregistered stale-named file belongs to another process (a truly
/// prior interrupted job) = deletable. A crash drops the registry
/// with the process — the on-disk residue becomes stale to the next
/// run (the contract, unchanged).
static ACTIVE_TEMPS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<PathBuf>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));


/// The registry guard (the temp's lifetime scope — `Drop` releases
/// the registration; the fan-out holds the guard for the call, the
/// rename/deletion ends the temp's existence first).
pub(crate) struct ActiveTempGuard(PathBuf);


impl ActiveTempGuard {
    pub(crate) fn register(p: PathBuf) -> Self {
        ACTIVE_TEMPS.lock().unwrap().insert(p.clone());
        ActiveTempGuard(p)
    }
}


impl Drop for ActiveTempGuard {
    fn drop(&mut self) {
        ACTIVE_TEMPS.lock().unwrap().remove(&self.0);
    }
}


/// The stale-temp cleanup (stage 0, after the dest probes,
/// before the first source read): walk `root` (recursive — the
/// mirrored clip tree) and delete the files whose name starts
/// `STALE_TEMP_PREFIX` AND ends `STALE_TEMP_SUFFIX` (the atomic-copy
/// seam's temp convention — a prior interrupted job's residue). The
/// zero-partial-write contract is preserved: no media write; the
/// deletions are the named, logged side effect (the note line is the
/// caller's, per dest root). Returns the count deleted.
pub(crate) fn stale_temp_cleanup(root: &Path) -> Result<u64> {
    let mut n = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("read dir {}", dir.display()))?
        {
            let entry = entry?;
            let p = entry.path();
            let ft = entry.file_type()?;
            if ft.is_symlink() {
                continue; // refuse symlinked entries (the collect discipline)
            }
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                    if name.starts_with(STALE_TEMP_PREFIX) && name.ends_with(STALE_TEMP_SUFFIX) {
                        // The in-flight registry check: a
                        // same-process concurrent writer's temp (the
                        // multi-source phase-1's sibling source
                        // thread) is NOT stale — never delete it (an
                        // unregistered existing temp = another
                        // process's residue = deletable).
                        if !ACTIVE_TEMPS.lock().unwrap().contains(&p) {
                            std::fs::remove_file(&p)
                                .with_context(|| format!("remove the stale offload temp {}", p.display()))?;
                            n += 1;
                        }
                    }
                }
            }
        }
    }
    Ok(n)
}


/// The proper path-component prefix (the nested-source refusal's
/// check, the (source, dest) nesting bands' check):
/// `a` is a prefix of `b` when `b` descends INTO `a` — the
/// component boundary (the `/` separator) decides: `/a/b` prefixes
/// `/a/b/c` but NOT `/a/bc`. Equal paths are NOT nested (the
/// cross-source collision refusal covers the duplicate source;
/// the identity refusals cover the equal paths). `pub(crate)` —
/// the encode `--to` band (`check_to_band`) reads it from the
/// worker/jxl encode paths (the minimal visibility
/// change — the nested-source refusal's existing use is
/// unchanged).
pub(crate) fn is_path_prefix(a: &Path, b: &Path) -> bool {
    let (mut a_comps, mut b_comps) = (a.components(), b.components());
    loop {
        match (a_comps.next(), b_comps.next()) {
            (Some(x), Some(y)) if x == y => {}
            (None, Some(_)) => return true,
            _ => return false,
        }
    }
}


/// The band's canonical form: a
/// canonical path for a path that may not exist YET — walk up to
/// the nearest EXISTING ancestor, canonicalize it, re-join the
/// missing tail verbatim. The bands fire BEFORE the probe's dir
/// creation (the zero-residue refusal), so a missing dest must
/// still resolve to a comparable canonical form — the existing
/// guards' `canonicalize(dest).ok()` skips the missing-dest
/// topologies entirely (the probe then creates the dir INSIDE the
/// source/product tree — the hole the bands close). The tail
/// components are NOT symlink-resolved (they do not exist — the
/// dangling-tail class falls into the writability-probe band, the
/// existing idiom). None on a canonicalize failure (the
/// symlink-loop class) — the probe band names it there.
pub(crate) fn canonicalize_path(p: &Path) -> Option<PathBuf> {
    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = p;
    while !cur.exists() {
        let parent = cur.parent()?;
        missing.push(cur.file_name()?.to_os_string());
        cur = parent;
    }
    let base = std::fs::canonicalize(cur).ok()?;
    let mut out = base;
    for name in missing.into_iter().rev() {
        out.push(name);
    }
    Some(out)
}


/// The write-path root-boundary invariant (the named
/// residual — the hostile INTERMEDIATE-DIR symlink class): a single
/// write-path containment check. A hostile intermediate-dir symlink
/// planted BETWEEN RUNS (the threat model — the inter-run
/// planted state; the guards defend exactly this class) at a
/// DIRECTORY component between a user-designated root `root` and the
/// tool's write path `write_path` would otherwise redirect the write
/// (the tmp+rename) INTO the outside dir the link points to — the
/// final-component guards do not see it (the leaf is a regular file
/// the tool creates, so a planted link at an intermediate DIR is
/// invisible to a leaf lstat). The invariant: `write_path` must be
/// INSIDE `root`'s canonical form — the containment check on the
/// canonical forms (`root_c == path_c || is_path_prefix(root_c,
/// path_c)` via `canonicalize_path` + `is_path_prefix`).
/// Consequences (the volume-alias correctness — the over-refusal
/// lesson): (a) a SYMLINKED VOLUME ALIAS in the root's OWN path
/// components is ACCEPTED — the root + the write path resolve the
/// alias IDENTICALLY under `canonicalize_path` (a legitimate config
/// is never refused; the VOLUME-ALIAS-ACCEPTED pin is a required
/// test) · (b) a PLANTED LINK at an intermediate component BELOW the
/// root is the named refusal (pre-write, zero-partial) · (c) the
/// root's OWN final component being a link is OUT OF REACH (the user
/// designated that path explicitly — standard path semantics; the
/// final-component guards cover the tool-owned LEAF names). `root`
/// = the command's root argument AS GIVEN (NOT pre-canonicalized —
/// the canonicalization inside the guard makes the legitimate alias
/// resolve identically on both sides). The `canonicalize_path` `None`
/// case (the symlink-loop class): the `ok()`-SKIP idiom —
/// a loop cannot redirect to an OUTSIDE dir (it fails with `ELOOP`),
/// so the downstream write error names it; refusing on a loop would
/// be a new refusal class for a non-threat.
pub(crate) fn check_root_bound(write_path: &Path, root: &Path) -> Result<()> {
    let (root_c, path_c) = match (canonicalize_path(root), canonicalize_path(write_path)) {
        (Some(r), Some(p)) => (r, p),
        // The symlink-loop class — the ok()-skip idiom (a
        // loop fails with ELOOP, it cannot land the write in an
        // outside dir; the downstream write error names it).
        _ => return Ok(()),
    };
    if !(root_c == path_c || is_path_prefix(&root_c, &path_c)) {
        bail!(
            "the write path {} escapes its root {} (a symlinked directory component below the root points outside the root's canonical form — the write would land in an outside dir; the write-through is refused): remove the planted symlink / check the mount, then re-run",
            write_path.display(),
            root.display()
        );
    }
    Ok(())
}


/// The write-path root-boundary invariant, the BATCH form (the
/// offload entry): assert that every EXISTING directory under
/// `root` is contained in `root`'s canonical form. The offload's
/// write paths are all `root.join(rel)` (the source-relative paths) —
/// the ONLY way one escapes is a PLANTED (existing) dir link below the
/// root (a dir the tool CREATES is real, never a link). So a single
/// read-only walk of the EXISTING tree, run BEFORE any write (the
/// zero-partial property — it fires before the stale-temp cleanup's
/// descent + the source reads + the copy loop), subsumes every
/// per-write-path check for the offload surface (the media mirror +
/// the per-clip manifest + the reports). Read-only (readdir +
/// canonicalize — no media fixtures, the LIGHT fence class). A real
/// subdir is descended into; a SYMLINK is the check target, NOT a
/// tree to walk (the tool writes THROUGH a link, it never follows one
/// to enumerate) — so a planted link is checked (its canonical form
/// escapes the root → the named refusal) but never descended (no
/// walk into the outside dir).
pub(crate) fn check_root_bound_tree(root: &Path) -> Result<()> {
    let root_c = canonicalize_path(root)
        .ok_or_else(|| anyhow::anyhow!("canonicalize the offload root {}", root.display()))?;
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let meta = std::fs::symlink_metadata(&d)
            .with_context(|| format!("stat the root-boundary dir {}", d.display()))?;
        let ft = meta.file_type();
        // A real dir or a symlink-to-dir: the containment check target.
        // (A symlink to a dir is the planted-link class; a symlink to a
        // FILE cannot carry a write-through dir, but the check is
        // harmless — its canonical form is a file path, still asserted
        // contained.)
        if ft.is_symlink() || meta.is_dir() {
            let d_c = canonicalize_path(&d)
                .ok_or_else(|| anyhow::anyhow!("canonicalize the root-boundary dir {}", d.display()))?;
            if !(root_c == d_c || is_path_prefix(&root_c, &d_c)) {
                bail!(
                    "the write path {} escapes its root {} (a symlinked directory component below the root points outside the root's canonical form — the write would land in an outside dir; the write-through is refused): remove the planted symlink / check the mount, then re-run",
                    d.display(),
                    root.display()
                );
            }
        }
        // Descend into REAL dirs only (a symlink is the check target,
        // not a tree — the tool never follows a link to enumerate).
        if meta.is_dir() && !ft.is_symlink() {
            for entry in std::fs::read_dir(&d)
                .with_context(|| format!("read the root-boundary dir {}", d.display()))?
            {
                let entry = entry?;
                stack.push(entry.path());
            }
        }
    }
    Ok(())
}


/// The source's DEPTH-1 entry names (the top-level entries — files
/// AND dirs; the cross-source collision's read-only check, before
/// the core's full walk). The collect's symlink discipline: symlinked
/// entries are skipped (they are not mirrored — they cannot collide).
pub(crate) fn top_level_names(source: &Path) -> Result<std::collections::BTreeSet<String>> {
    let mut names = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(source)
        .with_context(|| format!("read the offload source {}", source.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            continue; // the collect discipline — never mirrored
        }
        names.insert(entry.file_name().to_string_lossy().into_owned());
    }
    Ok(names)
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::process::ExitCode;

    use super::super::{offload_core_multi, run_offload_multi};

    use crate::offload::testutil::*;
    #[test]
    fn check_dest_writable_refuses_a_path_under_a_file() {
        let base = std::env::temp_dir().join("frameprism_offload_probe_test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("blocker"), b"file").unwrap();
        let err = check_dest_writable(&base.join("blocker/dest")).unwrap_err();
        assert!(
            err.to_string().contains("create the --to dest dir"),
            "the named startup refusal: {err}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


    #[test]
    fn offload_stale_temp_cleanup() {
        // (d) seed 2 stale temps (at two depths) in the dest tree
        // before a clean offload → the run converges rc=0 + both
        // temps DELETED + the media rows OK.
        let (base, input, dest) = setup("staletmp");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let deep = dest.join("A001_001");
        std::fs::create_dir_all(&deep).unwrap();
        let root_temp = dest.join(format!("{STALE_TEMP_PREFIX}deadbeef.manifest.tsv{STALE_TEMP_SUFFIX}"));
        let deep_temp = deep.join(format!("{STALE_TEMP_PREFIX}deadbeef.f1.DNG{STALE_TEMP_SUFFIX}"));
        std::fs::write(&root_temp, b"stale-root").unwrap();
        std::fs::write(&deep_temp, b"stale-deep").unwrap();
        let rc = run_offload_multi(&input_c, &[dest.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "the run converges rc=0 (the cleanup is pre-copy)");
        assert!(!root_temp.exists(), "the root temp deleted");
        assert!(!deep_temp.exists(), "the deep temp deleted");
        let f1 = dest.join("A001_001/f1.DNG");
        assert_eq!(
            std::fs::read(&f1).unwrap(),
            b"frame-one-payload",
            "the media row OK (the cleanup touched no media)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The write-path root-boundary invariant (the named
    /// residual — the intermediate-dir symlink class): the
    /// structural source pin — the guard call sits BEFORE the write
    /// at each guarded seam (the additive lettered sections).
    /// A DISTINCT class from the durability pin
    /// (the fsync-before-rename) — a separate named pin fn keeps the
    /// two structural contracts separate + additive (the existing
    /// durability pin's sections (a)–(h) are UNMOVED). (The split
    /// note: the offload seam surface moved to the part files — the
    /// include targets are the part files; the anchors are unchanged.)
    /// (The split note: the audit restore seam's include target
    /// moved to the part file that receives `run_restore`
    /// (`audit/entries.rs`) — the signature-to-EOF anchors are
    /// unchanged.)
    #[test]
    fn offload_root_boundary_seams_pinned() {
        let transfer = include_str!("transfer.rs");
        let repair = include_str!("../repair.rs");
        let audit = include_str!("../audit/entries.rs");

        // The fn slice: from the fn signature line to (not incl.)
        // the next column-0 fn-definition line (the `fn ` / `pub fn `
        // / `pub(crate) fn ` forms — the ordering pin, not a parse).
        // Nested fn bodies are indented — never column 0.
        fn slice_fn<'a>(src: &'a str, sig: &str) -> &'a str {
            let start = src
                .find(sig)
                .unwrap_or_else(|| panic!("the fn signature {sig:?} is not in the source"));
            let rest = &src[start..];
            let mut offset = 0usize;
            for line in rest.split_inclusive('\n').skip(1) {
                offset += line.len();
                if line.starts_with("fn ")
                    || line.starts_with("pub fn ")
                    || line.starts_with("pub(crate) fn ")
                {
                    return &rest[..offset];
                }
            }
            panic!("no next column-0 fn-definition line after {sig:?}");
        }

        // (a) offload_core_multi: the batch tree-walk guard call
        // (`check_root_bound_tree`) sits BEFORE the stale-temp
        // cleanup's descent (`stale_temp_cleanup`) — the cleanup
        // WALKS the dest tree + deletes the named temps (it would
        // descend through a planted link), so the guard must fire
        // first (the zero-partial property: before ANY write under
        // the dest, including the cleanup's descent).
        let core = slice_fn(transfer, "pub fn offload_core_multi(");
        let i_guard = core
            .find("check_root_bound_tree")
            .expect("offload_core_multi carries the root-boundary tree-walk guard");
        let i_cleanup = core
            .find("stale_temp_cleanup")
            .expect("offload_core_multi's stale-temp cleanup call");
        assert!(
            i_guard < i_cleanup,
            "the root-boundary tree-walk guard sits BEFORE the stale-temp cleanup's descent in offload_core_multi"
        );

        // (b) recopy_and_reverify (repair): the `check_root_bound`
        // call sits BEFORE the lstat guard's `symlink_metadata`
        // AND before the `fs::copy` (the write) — both guards are
        // pre-write (zero-partial for the row); the root-boundary
        // guard (the directory-level class) fires first, the leaf
        // guard (the final-component class) second.
        let recopy = slice_fn(repair, "fn recopy_and_reverify(");
        let i_guard = recopy
            .find("check_root_bound")
            .expect("recopy_and_reverify carries the root-boundary guard");
        let i_62 = recopy
            .find("symlink_metadata")
            .expect("recopy_and_reverify's 62 lstat guard");
        let i_write = recopy
            .find("fs::copy")
            .expect("recopy_and_reverify's fs::copy write");
        assert!(
            i_guard < i_62 && i_guard < i_write,
            "the root-boundary guard sits BEFORE the lstat guard + the fs::copy in recopy_and_reverify"
        );

        // (c) run_restore (audit): the `check_root_bound` call sits
        // BEFORE the swap's `File::create(&tmp)` (the write). The
        // slice is signature-to-EOF (NOT `slice_fn`): `run_restore`
        // is the LAST column-0 fn in entries.rs (the part's test
        // module's fns are indented), so `slice_fn`'s next-fn terminator is absent
        // (the precedent). The exact-string search
        // sidesteps any later occurrence: the guard + the swap's
        // `File::create(&tmp)` are both in the fn body (before the
        // test module), the first occurrence of each.
        let i_sig = audit
            .find("pub fn run_restore(")
            .expect("the run_restore signature");
        let restore = &audit[i_sig..];
        let i_guard = restore
            .find("check_root_bound(parent, input)")
            .expect("run_restore carries the root-boundary guard");
        let i_write = restore
            .find("File::create(&tmp)")
            .expect("run_restore's swap File::create write");
        assert!(
            i_guard < i_write,
            "the root-boundary guard sits BEFORE the swap's File::create in run_restore"
        );
    }


    /// The planted intermediate-dir symlink REFUSED (the
    /// headline — the byte-identity proof): `dest/<clip>`
    /// is a planted link to an outside dir → the offload's tree walk
    /// refuses BEFORE any write (the named class) + the OUTSIDE
    /// TARGET BYTES UNCHANGED + the dest tree unmodified (the
    /// zero-partial property: no tmp created anywhere) + the planted
    /// link stands (never followed for a write). The guard's home is
    /// `offload_core_multi` (the funnel for every offload form —
    /// the per-command wiring is proven by the existing offload
    /// batteries).
    #[test]
    fn offload_planted_intermediate_dir_symlink_refused() {
        let base = std::env::temp_dir().join(format!(
            "frameprism_offload_symlink_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let source = base.join("source");
        let dest = base.join("dest");
        let outside = base.join("outside");
        // The source: 1 clip + 1 frame.
        std::fs::create_dir_all(source.join("A001_001")).unwrap();
        std::fs::write(source.join("A001_001/f1.DNG"), b"frame-payload").unwrap();
        // The dest root (a real dir) + the outside target (the planted
        // link's destination — with a sentinel byte string).
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let sentinel = outside.join("sentinel.bin");
        std::fs::write(&sentinel, b"outside-bytes").unwrap();
        let sentinel_before = std::fs::read(&sentinel).unwrap();
        // The planted intermediate link: dest/A001_001 -> outside
        // (a hostile plants it BETWEEN RUNS — the threat model).
        std::os::unix::fs::symlink(&outside, dest.join("A001_001")).unwrap();
        // The offload: the tree walk refuses BEFORE any write.
        let res = offload_core_multi(&source, &[dest.clone()], &[]);
        let err = match res {
            Err(e) => e,
            Ok(_) => panic!("the planted intermediate-dir symlink must be refused"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("escapes its root"),
            "the named refusal names the class: {msg}"
        );
        assert!(msg.contains("symlinked directory component"), "the class is named: {msg}");
        // The OUTSIDE TARGET BYTES UNCHANGED (the byte-identity proof).
        let sentinel_after = std::fs::read(&sentinel).unwrap();
        assert_eq!(sentinel_before, sentinel_after, "the outside target's bytes are unchanged");
        // NO tmp / mirror file was created in the outside dir (the
        // zero-partial property: the write was refused before it
        // landed anywhere).
        let outside_entries: Vec<String> = std::fs::read_dir(&outside)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            outside_entries, vec!["sentinel.bin"],
            "no tmp/file was created in the outside dir: {outside_entries:?}"
        );
        // The planted link STAYS (never followed for a write; the
        // dest tree is unmodified).
        let link_meta = std::fs::symlink_metadata(dest.join("A001_001")).unwrap();
        assert!(
            link_meta.file_type().is_symlink(),
            "the planted link stands (the dest tree is unmodified)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The VOLUME-ALIAS-ACCEPTED pin (REQUIRED — the over-refusal
    /// lesson: a legitimate config must not be
    /// refused): a SYMLINKED VOLUME ALIAS in the root's own path
    /// components is ACCEPTED — the root + the write path resolve the
    /// alias IDENTICALLY under `canonicalize_path` (the containment
    /// holds). The offload with the LINK path as the root SUCCEEDS +
    /// the bytes land at the real target (the original behavior — the
    /// acceptance proof). The alias is self-contained (the test
    /// creates its own link — the macOS `/tmp` → `/private/tmp`
    /// class is environment-dependent).
    #[test]
    fn offload_volume_alias_accepted() {
        let base = std::env::temp_dir().join(format!(
            "frameprism_volume_alias_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let source = base.join("source");
        let real = base.join("real"); // the real dest target
        let alias = base.join("alias"); // the link (the alias in the root's path)
        std::fs::create_dir_all(source.join("A001_001")).unwrap();
        std::fs::write(source.join("A001_001/f1.DNG"), b"frame-payload").unwrap();
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        // The offload with the LINK path as the root: the legitimate
        // alias resolves identically on both sides (accepted).
        let res = offload_core_multi(&source, &[alias.clone()], &[]);
        assert!(
            res.is_ok(),
            "the legitimate volume alias must be ACCEPTED (the over-refusal lesson)"
        );
        // The bytes land at the REAL target (the alias resolves to it),
        // byte-identical to the source (the original behavior).
        let mirrored = real.join("A001_001/f1.DNG");
        assert!(mirrored.is_file(), "the mirror landed at the real target");
        assert_eq!(
            std::fs::read(&mirrored).unwrap(),
            b"frame-payload",
            "byte-identical to the source (the acceptance proof)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


}
