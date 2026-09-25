//! The offload's fan-out transfer engine: the copy + the
//! multi-dest fan-out (each source file's bytes read ONCE and written
//! to EVERY dest — the card read is the bottleneck; N dests cost one
//! card pass), the durability seams (the sync-before-rename ordering
//! in the copy + the record writers), the mtime discipline, the skip
//! logic (the already-identical dest file is verified, not
//! re-copied — the mtime + the temp surface stay untouched).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::manifests::write_offload_manifest;
use super::traversal::{
    ActiveTempGuard, check_root_bound_tree, collect_all_files, offload_temp_path,
    stale_temp_cleanup,
};
use super::{ClipBlock, OffloadReport, OffloadRow, Verdict, clip_key_of_rel};

// `fanout_source`'s per-dest re-hash row (dest_sha, verdict, detail, window ms).
type PerDestRow = (String, Verdict, String, u64);


/// The 1-dest core (the encode path's `--to` step + the standalone
/// surface's single-dest call — the byte-identical copy loop):
/// `offload_core_multi` over a single dest. The encode coupling stays
/// at the call site: `offload_to` (the encode path) writes the run's
/// single whole-tree manifest at the encode `output` dir; the
/// standalone offload writes one manifest per clip key at the
/// mirrored clip root under `dest_dir` (the placement is the call
/// site's concern — the FORMAT is the shared writer, the wire
/// contract).
pub fn offload_core(
    source_tree: &Path,
    dest_dir: &Path,
    clip_keys: &[String],
) -> Result<OffloadCore> {
    let dest = dest_dir.to_path_buf();
    let outcome = offload_core_multi(source_tree, std::slice::from_ref(&dest), clip_keys)?;
    Ok(OffloadCore {
        report: outcome
            .reports
            .into_iter()
            .next()
            .expect("the 1-dest core carries one report"),
        per_clip: outcome
            .per_clip
            .into_iter()
            .next()
            .expect("the 1-dest core carries one slice set"),
    })
}


/// The core's outcome: the whole-tree report + the per-clip slices.
pub struct OffloadCore {
    /// The whole-tree report (all rows + the per-clip blocks in the
    /// BTreeMap clip-key order — the encode manifest's block order).
    pub report: OffloadReport,
    /// The per-clip slices, one per `clip_keys` entry (the given
    /// order): the clip's rows (the whole-tree row order) + the
    /// clip's block numbers (0/0 for a key with no files).
    pub per_clip: Vec<ClipSlice>,
}


/// The N-dest core's outcome: one whole-tree report per dest (the
/// given order — each report's `dest` is that dest's canonical
/// path) + the per-dest per-clip slices + the per-(file, dest)
/// copy+verify durations.
pub struct OffloadCoreMulti {
    /// The whole-tree reports, one per dest (the given order; all
    /// carry the same rows' files + sizes + source sha256 — the
    /// dest sha256 / verdict / detail columns are per-dest).
    pub reports: Vec<OffloadReport>,
    /// The per-clip slices per dest (`per_clip[i]` = the slices for
    /// `reports[i]`, one per `clip_keys` entry, the given order).
    pub per_clip: Vec<Vec<ClipSlice>>,
    /// The per-(file, dest) copy+verify durations in ms (the
    /// measurement: `copied_ms[i][j]` = the j-th row's
    /// write + dest-side verify window at dest i — the row order is
    /// the source-walk order shared by every dest; the read-once
    /// source side is amortized across the dests — not a pure I/O
    /// throughput number). A SKIPPED row's window (the
    /// duplicate detection) = the verify-only duration (the pre-check
    /// stat + read + hash; NO write). Rides ONLY in the standalone
    /// offload's job report (R-INV-A: the manifests / the run report
    /// / the stderr surface never render it).
    pub copied_ms: Vec<Vec<u64>>,
    /// The per-(file, dest) skip facts (the duplicate
    /// detection: `skipped[i][j]` = true when the j-th row at dest i
    /// was already present with matching content (size + sha256) and
    /// was verified ONLY, NOT re-copied — the row is `Ok` (the dest
    /// content WAS verified against the source); the row struct is
    /// UNTOUCHED — the skip is a RUN fact, not a row fact: the
    /// manifests / the verdict lines / the stderr formats are frozen
    /// (R-INV-M). Rides in the run report's `## skipped` section +
    /// the job report's `skipped` column only).
    pub skipped: Vec<Vec<bool>>,
}

// ---------------------------------------------------------------------------
// The atomic-copy seam (the interruption safety + the
// convergent resume)
// ---------------------------------------------------------------------------


/// The atomic-copy seam (the interruption safety): the
/// copy lands via the TEMP file + `rename` (the tmp+rename
/// pattern — the manifest writer's), so the FINAL path holds ONLY
/// complete, verified files — an interrupted job (SIGKILL / crash /
/// power) leaves the temp, never a partial at the final media path.
/// A pre-existing temp at the helper's tmp path = the NAMED
/// concurrent-job refusal (never overwrite — `fs::copy` would
/// truncate it silently). A failed copy deletes its own temp (the
/// litter the direct-write era left). The mtime is set on the temp
/// BEFORE the rename (rename carries it — the observable mtime on
/// the final path is the pre-existing behavior; the note names the DST —
/// the wire-visible path, never the temp).
fn copy_atomic(src: &Path, dst: &Path, mtime: std::time::SystemTime) -> Result<()> {
    let tmp = offload_temp_path(dst);
    if tmp.exists() {
        bail!(
            "the offload temp file {} already exists (a concurrent job writes this dest — run the offload jobs against a dest root sequentially)",
            tmp.display()
        );
    }
    // The in-flight registration (BEFORE the temp exists —
    // the sibling source thread's phase-0 cleanup must not delete
    // this temp mid-copy; the guard releases at the seam's end).
    let _guard = ActiveTempGuard::register(tmp.clone());
    let copy_res = std::fs::File::open(src)
        .and_then(|mut src_file| {
            let mut dst_file = std::fs::File::create(&tmp)?;
            std::io::copy(&mut src_file, &mut dst_file)?;
            // The durability seam: the copy's bytes are
            // filesystem-synchronized BEFORE the rename (the sync
            // rides `copy_res` — a failure takes the EXISTING
            // failure path: the temp deleted, the named error
            // propagated, the row CopyFail with the detail). The
            // named error is the io::Error's message (the closure's
            // error boundary is std::io — the copy's context shape
            // `sync {src} -> {dst}` + the underlying io error).
            dst_file
                .sync_all()
                .map_err(|err| {
                    std::io::Error::new(
                        err.kind(),
                        format!("sync {} -> {}: {}", src.display(), dst.display(), err),
                    )
                })?;
            Ok(())
        })
        .with_context(|| format!("copy {} -> {}", src.display(), dst.display()));
    if copy_res.is_err() {
        // The failed copy leaves ONLY the temp — delete it (the final
        // path is never partial; best-effort: the temp may not exist
        // when the copy failed before creating it).
        let _ = std::fs::remove_file(&tmp);
        return copy_res.map(|_| ());
    }
    // The mtime preserved on the TEMP before the rename (best-effort —
    // the pre-existing note wording, naming the DST).
    if let Err(err) = std::fs::File::open(&tmp).and_then(|f| f.set_modified(mtime)) {
        eprintln!(
            "note: the offload mtime set on {} failed ({err}) — the content copy stands",
            dst.display()
        );
    }
    let rename_res = std::fs::rename(&tmp, dst)
        .with_context(|| format!("rename {} -> {}", tmp.display(), dst.display()));
    if rename_res.is_err() {
        // The rename failed — delete the temp (the final path is
        // never partial).
        let _ = std::fs::remove_file(&tmp);
        return rename_res.map(|_| ());
    }
    // The durability seam: the best-effort dir sync of the
    // landed entry (the rename's dir-entry update — the pinned note
    // on failure, the content copy stands).
    if let Some(parent) = dst.parent() {
        crate::durability::sync_dir_best_effort(parent);
    }
    Ok(())
}


/// The streaming fan-out (the fast path): open the
/// source ONCE; stream `SHA256_CHUNK`-sized chunks; update the shared
/// source sha state INLINE + write each chunk to every HEALTHY dest's
/// temp (the convention — `offload_temp_path` + the `.tmp`
/// double rule + the pinned concurrent-job refusal per temp). A dest
/// whose temp open or chunk write fails is marked DIRTY (excluded
/// from the subsequent chunks, its temp deleted best-effort — the
/// others continue: the failed-dest-continues property). Per healthy
/// dest: the mtime on the temp BEFORE the rename (the note
/// wording on failure, naming the DST) + the rename; then the
/// INDEPENDENT streaming re-hash of each dest (the verdicts — the
/// fanned dests get the normal OK / SizeMismatch / ShaMismatch rows
/// with the EXACT conservative-path wordings). The source is read
/// EXACTLY ONCE — the advertised read-once/write-N card pass (the
/// DIT fresh-offload scenario). Returns the source sha (the shared
/// row column) + per-dest (dest_sha, verdict, detail, window ms)
/// in dest order (the window opens at the fan-out entry and closes
/// after that dest's re-hash / failure decision — the conservative
/// path's per-dest window placement, the write + verify window).
fn fanout_source(
    src: &Path,
    rel: &str,
    size: u64,
    mtime: std::time::SystemTime,
    dest_abs: &[PathBuf],
) -> Result<(String, Vec<PerDestRow>)> {
    use std::io::{Read, Write};
    let n = dest_abs.len();
    let windows: Vec<std::time::Instant> = (0..n).map(|_| std::time::Instant::now()).collect();
    // The source open FIRST (the refusal-before-any-dest-write order:
    // the conservative path read the source before the per-dest loop
    // — an unreadable source refuses with NO dest side effect, the
    // test-pinned "the failure is before any copy").
    let mut src_file = std::fs::File::open(src)
        .with_context(|| format!("re-scan the offload source {}", src.display()))?;
    // The per-dest prep: the mirrored subdir + the temp open. A
    // failure here marks THAT dest dirty (the others continue — the
    // conservative path's create_dir_all would have bailed the job;
    // the fan-out's failed-dest-continues property is the pinned
    // behavior). The source's content is not read yet (the O(1) prep
    // first).
    let mut tmps: Vec<Option<PathBuf>> = (0..n).map(|_| None).collect();
    let mut files: Vec<Option<std::fs::File>> = (0..n).map(|_| None).collect();
    let mut guards: Vec<Option<ActiveTempGuard>> = (0..n).map(|_| None).collect();
    let mut results: Vec<Option<(String, Verdict, String)>> = (0..n).map(|_| None).collect();
    for i in 0..n {
        let dst = dest_abs[i].join(rel);
        if let Some(parent) = dst.parent() {
            if let Err(err) = std::fs::create_dir_all(parent)
                .with_context(|| format!("create the offload dest subdir {}", parent.display()))
            {
                results[i] = Some(("-".to_string(), Verdict::CopyFail, format!("{err:#}")));
                continue;
            }
        }
        let tmp = offload_temp_path(&dst);
        if tmp.exists() {
            results[i] = Some((
                "-".to_string(),
                Verdict::CopyFail,
                format!(
                    "the offload temp file {} already exists (a concurrent job writes this dest — run the offload jobs against a dest root sequentially)",
                    tmp.display()
                ),
            ));
            continue;
        }
        // The in-flight registration (BEFORE the temp
        // exists — the sibling source thread's phase-0 cleanup must
        // not delete this temp mid-fan-out; the guard is held for
        // the call and releases at its end).
        let guard = ActiveTempGuard::register(tmp.clone());
        match std::fs::File::create(&tmp)
            .with_context(|| format!("open the offload fan-out temp {}", tmp.display()))
        {
            Ok(f) => {
                tmps[i] = Some(tmp);
                files[i] = Some(f);
                guards[i] = Some(guard);
            }
            Err(err) => {
                results[i] = Some(("-".to_string(), Verdict::CopyFail, format!("{err:#}")));
            }
        }
    }
    // The content read (ONCE) + the chunked fan-out.
    let mut s = crate::jxl::Sha256State::new();
    let mut buf = vec![0u8; crate::jxl::SHA256_CHUNK];
    loop {
        let chunk_read = match src_file
            .read(&mut buf)
            .with_context(|| format!("re-scan the offload source {}", src.display()))
        {
            Ok(n) => n,
            Err(err) => {
                // The source failed MID-STREAM: the healthy dests' temps are
                // PARTIAL — delete them (the litter rule: the final
                // path is never partial; a residue the next run's phase-0
                // cleanup would also collect) + bail the job (the
                // conservative path's source-read error semantics).
                for t in tmps.iter().flatten() {
                    let _ = std::fs::remove_file(t);
                }
                return Err(err);
            }
        };
        if chunk_read == 0 {
            break;
        }
        let chunk = &buf[..chunk_read];
        s.update(chunk);
        for i in 0..n {
            let Some(f) = files[i].as_mut() else { continue; };
            if let Err(err) = f
                .write_all(chunk)
                .with_context(|| format!("write the offload fan-out {} -> {}", src.display(), dest_abs[i].join(rel).display()))
            {
                // The failed dest: marked dirty, excluded from the
                // subsequent chunks, its temp deleted best-effort (the
                // failed-copy litter rule — the final path is
                // never partial). The other dests continue.
                let tmp = tmps[i].clone().unwrap_or_default();
                let _ = std::fs::remove_file(&tmp);
                files[i] = None;
                tmps[i] = None;
                results[i] = Some(("-".to_string(), Verdict::CopyFail, format!("{err:#}")));
            }
        }
    }
    let source_sha = crate::jxl::sha256_hex_of(s.finalize());
    // Per healthy dest: the mtime on the temp + the rename (the
    // the seam's observable behavior — rename carries the mtime)
    // + the independent streaming re-hash (the verdicts).
    let mut out: Vec<PerDestRow> = Vec::with_capacity(n);
    for i in 0..n {
        if let Some(r) = results[i].take() {
            out.push((r.0, r.1, r.2, windows[i].elapsed().as_millis() as u64));
            continue;
        }
        let dst = dest_abs[i].join(rel);
        let tmp = tmps[i].clone().unwrap_or_default();
        let close = |window: std::time::Instant| window.elapsed().as_millis() as u64;
        // The durability seam: the dest's bytes are
        // filesystem-synchronized on the STILL-OPEN handle BEFORE
        // the rename (a sync failure = that dest marked DIRTY in the
        // fan-out's EXISTING per-dest failure class — the temp
        // deleted best-effort, the other dests continue: the
        // failed-dest-continues property held).
        let Some(f) = files[i].as_ref() else {
            // Unreachable: a failed dest's `results[i]` is Some and
            // was taken above (the failure is already recorded).
            out.push((
                "-".to_string(),
                Verdict::CopyFail,
                "the fan-out dest handle is already closed (the failure is already recorded)".to_string(),
                close(windows[i]),
            ));
            continue;
        };
        if let Err(err) = f
            .sync_all()
            .with_context(|| format!("sync the offload fan-out temp for {}", dst.display()))
        {
            let _ = std::fs::remove_file(&tmp);
            out.push(("-".to_string(), Verdict::CopyFail, format!("{err:#}"), close(windows[i])));
            continue;
        }
        if let Err(err) = std::fs::File::open(&tmp).and_then(|f| f.set_modified(mtime)) {
            eprintln!(
                "note: the offload mtime set on {} failed ({err}) — the content copy stands",
                dst.display()
            );
        }
        let rename_res = std::fs::rename(&tmp, &dst)
            .with_context(|| format!("rename {} -> {}", tmp.display(), dst.display()));
        if let Err(err) = rename_res {
            // The rename failed — delete the temp (the final path is
            // never partial) + the named CopyFail (the others stand).
            let _ = std::fs::remove_file(&tmp);
            out.push(("-".to_string(), Verdict::CopyFail, format!("{err:#}"), close(windows[i])));
            continue;
        }
        // The durability seam: the best-effort dir sync of
        // the landed entry (the rename's dir-entry update — the
        // pinned note on failure, the content copy stands).
        if let Some(parent) = dst.parent() {
            crate::durability::sync_dir_best_effort(parent);
        }
        // The independent re-hash (the both-sides verification — the
        // written bytes, not the source's memory). The re-scan error
        // bails the job (the conservative path's re-scan semantics —
        // the other healthy dests are already renamed + complete).
        let disk_size = std::fs::metadata(&dst)
            .map(|m| m.len())
            .with_context(|| format!("re-scan the offload copy {}", dst.display()))?;
        let dest_sha = crate::jxl::sha256_stream_path(&dst)
            .with_context(|| format!("re-scan the offload copy {}", dst.display()))?;
        let verdict = if disk_size != size {
            (
                Verdict::SizeMismatch,
                format!(
                    "source {} B, dest {} B after the copy (filesystem anomaly)",
                    size, disk_size
                ),
            )
        } else if dest_sha != source_sha {
            (
                Verdict::ShaMismatch,
                "sha256 of the copy differs from the source (row columns source_sha256 / dest_sha256)".into(),
            )
        } else {
            (Verdict::Ok, String::new())
        };
        out.push((dest_sha, verdict.0, verdict.1, close(windows[i])));
    }
    Ok((source_sha, out))
}


/// The extracted N-dest core (the standalone offload surface's
/// engine — the multi-destination fan-out): the copy+verify body of
/// the `--to` step generalized over `dest_dirs` — re-scan + mirror +
/// mtime + re-scan + the verdict over EVERY file of `source_tree` at
/// EVERY dest. The read-once/write-N contract: each source file's
/// bytes are read ONCE + its sha256 computed ONCE (the card read is
/// the bottleneck — N dests cost one card pass); the source sha256
/// is shared by every dest's rows (the `source_sha256` column is
/// identical across the N manifests); each dest file is hashed
/// AFTER its write (the both-sides verification, N× on the dest
/// side). The per-clip aggregation (the BTreeMap clip-key order —
/// the encode manifest's block order) + the per-clip slices over
/// `clip_keys` (the ingest key space — "" = the source root; a key
/// with no files slices 0/0 — the caller's key space is
/// authoritative) are per-dest. The 1-dest observable behavior
/// (rows, order, verdicts, hashes, manifests, reports) is
/// UNCHANGED by the generalization.
pub fn offload_core_multi(
    source_tree: &Path,
    dest_dirs: &[PathBuf],
    clip_keys: &[String],
) -> Result<OffloadCoreMulti> {
    if dest_dirs.is_empty() {
        bail!("the offload needs at least one dest (frameprism offload <in> <to> [<to> ...])");
    }
    // The N dest dirs (created + canonicalized BEFORE the first
    // source read — the probe ordering: the N dest probes complete
    // before the first source read).
    let mut dest_abs: Vec<PathBuf> = Vec::with_capacity(dest_dirs.len());
    for dest in dest_dirs {
        std::fs::create_dir_all(dest)
            .with_context(|| format!("create the offload dest dir {}", dest.display()))?;
        let abs = std::fs::canonicalize(dest)
            .with_context(|| format!("canonicalize the offload dest dir {}", dest.display()))?;
        dest_abs.push(abs);
    }
    // The write-path root-boundary invariant (the named
    // residual — the intermediate-dir symlink class): BEFORE
    // the stale-temp cleanup's descent (the cleanup WALKS the dest
    // tree + deletes the named temps — a planted intermediate link
    // would redirect that descent into an outside dir) + before the
    // first source read + the copy loop, assert that every EXISTING
    // dir under each dest is contained in the dest's canonical form
    // (a planted symlinked DIR component below the dest would
    // otherwise redirect the offload's tmp+rename — the media mirror
    // + the per-clip manifest — into an outside dir). The legitimate
    // volume-alias class (a symlink in the dest's own path) resolves
    // identically on both sides (accepted — the over-refusal
    // lesson). The root = the dest AS GIVEN. Zero-partial: it fires
    // before ANY write under the dest.
    for dest in dest_dirs {
        check_root_bound_tree(dest)?;
    }
 // The stale-temp cleanup (stage 0: after the dest
    // probes, BEFORE the first source read — the zero-partial-write
    // contract: no media write, the deletions are the named, logged
    // side effect). A prior interrupted job (SIGKILL / crash /
    // power) can leave the atomic-copy seam's temp files at the dest
    // tree — the exact-name double rule (the prefix + the suffix)
    // deletes the JUNK temps only, never media (a media name a user
    // would not name deliberately cannot match the double rule). A
    // re-run of the same job converges: the cleaned dest tree + the
    // skip predicate = verified files stay put, the rest
    // re-copies.
    for root in &dest_abs {
        let n = stale_temp_cleanup(root)?;
        if n > 0 {
            eprintln!(
                "note: removed {} stale offload temp file(s) from a prior interrupted job at {}",
                n,
                root.display()
            );
        }
    }
    let files = collect_all_files(source_tree)?;
    let mut rows: Vec<Vec<OffloadRow>> = vec![Vec::with_capacity(files.len()); dest_abs.len()];
    let mut copied_ms: Vec<Vec<u64>> = vec![Vec::with_capacity(files.len()); dest_abs.len()];
    let mut skipped: Vec<Vec<bool>> = vec![Vec::with_capacity(files.len()); dest_abs.len()];
    for (rel, src) in &files {
        let src_meta = std::fs::metadata(src)
            .with_context(|| format!("stat the offload source {}", src.display()))?;
        let size = src_meta.len();
        let mtime = src_meta
            .modified()
            .with_context(|| format!("stat the source mtime {}", src.display()))?;
        // The hybrid's eligibility check (per-dest `stat`
        // + the size compare — O(1), BEFORE any read): a "skip
        // candidate" = an existing dest regular file of the SAME size.
        // NO candidate at any dest → the FAN-OUT fast path (the source
        // read EXACTLY ONCE — the read-once/write-N card pass:
        // fresh-offload scenario the README claim is about). A
        // candidate at ANY dest → the CONSERVATIVE path (the streaming
        // source sha + the skip check per candidate + the
        // copy_atomic per non-candidate — the skip decision
        // needs the COMPLETE source sha BEFORE any write, so the
        // verify-only semantics stay byte-frozen).
        let mut skip_candidate = vec![false; dest_abs.len()];
        for (i, dst_root) in dest_abs.iter().enumerate() {
            if let Ok(m) = std::fs::metadata(dst_root.join(rel)) {
                skip_candidate[i] = m.is_file() && m.len() == size;
            }
        }
        if !skip_candidate.iter().any(|c| *c) {
            // The fan-out fast path (the streaming
            // read-once/write-N — the O(file) heap never materializes;
            // the per-dest windows ride the fan-out's per-dest
            // write + verify window).
            let (source_sha, fan) = fanout_source(src, rel, size, mtime, &dest_abs)?;
            for (i, (dest_sha, verdict, detail, ms)) in fan.into_iter().enumerate() {
                rows[i].push(OffloadRow {
                    file: rel.clone(),
                    size,
                    source_sha: source_sha.clone(),
                    dest_sha,
                    verdict,
                    detail,
                });
                copied_ms[i].push(ms);
                skipped[i].push(false);
            }
            continue;
        }
        // The conservative path's source sha (the STREAMING
        // pass: `SHA256_CHUNK`-sized reads, never the whole file in a
        // `Vec` — the O(file) heap was the machine incident's root).
        // The source is read ONCE (streamed) — the shared value.
        let source_sha = crate::jxl::sha256_stream_path(src)
            .with_context(|| format!("re-scan the offload source {}", src.display()))?;
        for (i, dst_root) in dest_abs.iter().enumerate() {
            let dst = dst_root.join(rel);
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create the offload dest subdir {}", parent.display()))?;
            }
            // The per-(file, dest) copy+verify window (the
            // measurement: the write + the dest-side verify for
            // that dest; the read-once source side is amortized
            // across the dests — NOT a pure I/O throughput number;
            // it rides ONLY in the job report — R-INV-A). A SKIPPED
            // row's window opens at the same instant and
            // closes after the dest hash — the verify-only duration
            // (the pre-check stat + read + hash; NO write).
            let window = std::time::Instant::now();
            // The duplicate detection ("copy just
            // what's new"): the skip predicate (the exact
            // placement: inside the per-dest loop, BEFORE the copy).
            // A dest file that already exists with the SAME content
            // (size + sha256 both matching the source) is verified
            // ONLY (the read + hash the run performs anyway) and NOT
            // re-copied: no copy, no mtime set_modified, verdict Ok
            // (the dest content WAS verified against the source —
            // sha256 equal is exactly the OK definition — the skip
            // is NOT dirty), skipped = true. The source sha is
            // the once-computed shared value (zero added source
            // reads); the skipped file is read ONCE (the verify
            // re-read); a non-skipped existing file is read twice as
            // today (pre-check + post-copy verify). On a size or sha
            // mismatch the pre-check falls through to the copy path
            // (the copy OVERWRITES — a re-run stays idempotent +
            // re-verified). Automatic — no flag.
            let mut skip = false;
            if let Ok(meta) = std::fs::metadata(&dst) {
                if meta.is_file() && meta.len() == size {
                    // The streaming dest read (the bounded
                    // verify pass — the one-shot `fs::read` is gone).
                    if let Ok(dst_pre) = crate::jxl::sha256_stream_path(&dst) {
                        if dst_pre == source_sha {
                            skip = true;
                        }
                    }
                }
            }
            let (dest_sha, verdict, detail) = if skip {
                // The verified-only path: the dest's sha256 WAS
                // computed (the pre-read) and equals the source's —
                // the row's dest column carries it (the manifest row
                // renders exactly as a fresh-copy row — the skip fact
                // is off the wire, R-INV-M). The row's detail stays
                // EMPTY (an Ok row's detail is unused — the skip note
                // rides the `skipped` vector + the report surfaces
                // )
                (source_sha.clone(), Verdict::Ok, String::new())
            } else {
                // The atomic-copy seam (the interruption
                // safety): the copy lands via a temp file + `rename`
                // (the final path holds ONLY complete, verified files
                // — an interrupted job leaves the temp, never a
                // partial at the final path); the mtime is set on the
                // temp BEFORE the rename (rename carries it — the
                // observable mtime on the final path is the pre-existing
                // behavior); a failed copy deletes its own temp (the
                // direct-write era's litter, removed); a pre-existing
                // temp at the helper's tmp path = the named
                // concurrent-job refusal (the row's CopyFail detail
                // carries it — the rc=1 class, the sweep).
                let copy_res = copy_atomic(src, &dst, mtime);
                match copy_res {
                    Ok(()) => {
                        // The streaming dest re-scan (the
                        // O(1) size stat + the bounded streaming sha —
                        // the one-shot `fs::read` is gone).
                        let disk_size = std::fs::metadata(&dst)
                            .map(|m| m.len())
                            .with_context(|| format!("re-scan the offload copy {}", dst.display()))?;
                        let dest_sha = crate::jxl::sha256_stream_path(&dst)
                            .with_context(|| format!("re-scan the offload copy {}", dst.display()))?;
                        if disk_size != size {
                            (
                                dest_sha,
                                Verdict::SizeMismatch,
                                format!(
                                    "source {} B, dest {} B after the copy (filesystem anomaly)",
                                    size,
                                    disk_size
                                ),
                            )
                        } else if dest_sha != source_sha {
                            (
                                dest_sha,
                                Verdict::ShaMismatch,
                                "sha256 of the copy differs from the source (row columns source_sha256 / dest_sha256)".into(),
                            )
                        } else {
                            (dest_sha, Verdict::Ok, String::new())
                        }
                    }
                    Err(err) => ("-".to_string(), Verdict::CopyFail, format!("{err:#}")),
                }
            };
            rows[i].push(OffloadRow {
                file: rel.clone(),
                size,
                source_sha: source_sha.clone(),
                dest_sha,
                verdict,
                detail,
            });
            copied_ms[i].push(window.elapsed().as_millis() as u64);
            skipped[i].push(skip);
        }
    }
    let mut reports: Vec<OffloadReport> = Vec::with_capacity(dest_abs.len());
    let mut per_clip: Vec<Vec<ClipSlice>> = Vec::with_capacity(dest_abs.len());
    for (i, dst_root) in dest_abs.iter().enumerate() {
        // The per-clip verdict blocks (the ingest-manifest key space
        // — the relpath's parent dir; "" = the source root).
        let mut by_clip: std::collections::BTreeMap<String, (u64, u64)> =
            std::collections::BTreeMap::new();
        for r in &rows[i] {
            let entry = by_clip.entry(clip_key_of_rel(&r.file)).or_default();
            entry.0 += 1;
            if r.verdict == Verdict::Ok {
                entry.1 += 1;
            }
        }
        let clips: Vec<ClipBlock> = by_clip
            .into_iter()
            .map(|(clip_key, (total, ok))| ClipBlock {
                clip: clip_key,
                total,
                ok,
            })
            .collect();
        let report = OffloadReport {
            input: source_tree.to_path_buf(),
            dest: dst_root.clone(),
            rows: rows[i].clone(),
            clips,
        };
        // The per-clip slices (the given `clip_keys` order — the
        // standalone surface's per-clip manifest + report input).
        let slices: Vec<ClipSlice> = clip_keys
            .iter()
            .map(|key| {
                let rows: Vec<OffloadRow> = report
                    .rows
                    .iter()
                    .filter(|r| clip_key_of_rel(&r.file) == *key)
                    .cloned()
                    .collect();
                ClipSlice {
                    key: key.clone(),
                    total: rows.len() as u64,
                    ok: rows.iter().filter(|r| r.verdict == Verdict::Ok).count() as u64,
                    rows,
                }
            })
            .collect();
        reports.push(report);
        per_clip.push(slices);
    }
    Ok(OffloadCoreMulti { reports, per_clip, copied_ms, skipped })
}


/// One clip's slice of the offload (the per-clip manifest's content +
/// the run report's per-clip copy numbers).
pub struct ClipSlice {
    /// The clip key (the ingest key space; "" = the source root).
    pub key: String,
    /// The clip's rows (the whole-tree row order).
    pub rows: Vec<OffloadRow>,
    /// The clip's file count (all verdicts).
    pub total: u64,
    /// The clip's OK row count.
    pub ok: u64,
}


/// The verified offload (the encode path's `--to` step — the worker
/// call site is unchanged — the byte-frozen proof): a thin wrapper
/// over `offload_core` (the copy+verify core) + the encode coupling —
/// ONE whole-tree manifest at the encode `output` dir (named by the
/// input's clip — the wire contract, byte-identical to the
/// pre-extraction shape: the same rows, the same per-clip blocks,
/// the same verdict).
pub fn offload_to(input: &Path, output: &Path, dest: &Path) -> Result<OffloadReport> {
    let clip = crate::checksums::clip_name(input)?;
    // The core does the walk + the byte-identical copy loop; the
    // encode call site needs no per-clip slices (the whole-tree
    // manifest below covers every row — the per-clip slices are the
    // standalone surface's).
    let outcome = offload_core(input, dest, &[])?;
    write_offload_manifest(output, &clip, &outcome.report)?;
    Ok(outcome.report)
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::process::ExitCode;

    use super::super::manifests::{MANIFEST_MAGIC, offload_manifest_name, parse_manifest};
    use super::super::report::{fanout_stderr_lines, run_offload, run_offload_multi};
    use super::super::reverify::reverify;
    use super::super::traversal::{job_id, STALE_TEMP_PREFIX, STALE_TEMP_SUFFIX};
    use super::super::{Args, run};

    use crate::offload::testutil::*;
    #[test]
    fn offload_clean_run_mirror_mtime_and_manifest() {
        let (base, input, dest) = setup("clean");
        let report = offload_to(&input, &base.join("out"), &dest).unwrap();
        assert_eq!(report.rows.len(), 6, "every file rides a row");
        assert!(
            report.rows.iter().all(|r| r.verdict == Verdict::Ok),
            "clean tree: all rows OK: {:?}",
            report.rows.iter().map(|r| (r.file.clone(), r.detail.clone())).collect::<Vec<_>>()
        );
        assert_eq!(report.dirty_count(), 0);
        assert_eq!(
            report.verdict_line(),
            format!("offload: VERIFIED 6/6 (dest {})", report.dest.display()),
            "the canonical dest path in the line"
        );
        // The clip blocks: the ingest-manifest key space.
        let clips: std::collections::BTreeMap<&str, (u64, u64)> =
            report.clips.iter().map(|c| (c.clip.as_str(), (c.total, c.ok))).collect();
        assert_eq!(clips.get("A001_001"), Some(&(4, 4)));
        assert_eq!(clips.get(""), Some(&(2, 2)));
        // Mirror subpaths + mtime preservation.
        let dst_f1 = dest.join("A001_001/f1.DNG");
        assert!(dst_f1.is_file(), "mirrored subpath");
        let m1 = std::fs::metadata(input.join("A001_001/f1.DNG")).unwrap();
        let m2 = std::fs::metadata(&dst_f1).unwrap();
        assert_eq!(
            m1.modified().unwrap(),
            m2.modified().unwrap(),
            "mtime preserved"
        );
        assert_eq!(m1.len(), m2.len());
        // The manifest: magic + version + clip/dest headers + the
        // column line + 6 rows + the per-clip blocks + the verdict.
        let clip = crate::checksums::clip_name(&input).unwrap();
        let path = base.join("out").join(offload_manifest_name(&clip));
        assert!(path.is_file());
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], MANIFEST_MAGIC);
        assert!(lines.contains(&"version: 1"));
        assert!(lines.iter().any(|l| l.starts_with("dest: ")));
        assert!(lines.contains(&"file\tsize\tsource_sha256\tdest_sha256\tverdict"));
        assert!(text.contains("A001_001/f1.DNG\t17\t"), "row: relpath + size");
        assert!(text.contains("clip: A001_001 files: 4 ok: 4 dirty: 0"));
        assert!(text.contains("verdict: VERIFIED 6/6"));
        // Re-parse + re-verify: clean.
        let m = parse_manifest(&path).unwrap();
        assert_eq!(m.rows.len(), 6);
        let (lines, bad) = reverify(&m);
        assert_eq!(bad, 0, "clean re-verify: {lines:?}");
        let _ = std::fs::remove_dir_all(&base);
    }


    #[test]
    fn offload_rerun_is_idempotent_overwrite() {
        let (base, input, dest) = setup("rerun");
        let r1 = offload_to(&input, &base.join("out"), &dest).unwrap();
        // Tamper the dest copy between runs: the re-run OVERWRITES it
        // (a re-run is idempotent + re-verified).
        std::fs::write(dest.join("A001_001/f1.DNG"), b"corrupted-by-hand").unwrap();
        let r2 = offload_to(&input, &base.join("out"), &dest).unwrap();
        assert_eq!(r2.dirty_count(), 0, "the re-run re-copies clean");
        assert!(r2.rows.iter().all(|r| {
            r.source_sha == r.dest_sha
        }));
        assert_eq!(
            std::fs::read(dest.join("A001_001/f1.DNG")).unwrap(),
            b"frame-one-payload"
        );
        let _ = std::fs::remove_dir_all(&base);
        let _ = r1;
    }


    #[test]
    fn standalone_non_dng_tree_mirror_manifests_report_verdict() {
        profile_override_a001();
        let (base, input) = standalone_tree("nondng");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let dest = base.join("to");
        // The non-DNG tree: strip the DNG frames (the sidecar-only
        // card — the pass-through's native material).
        std::fs::remove_file(input.join("A001_001/f1.DNG")).unwrap();
        std::fs::remove_file(input.join("B002_002/f1.DNG")).unwrap();
        std::fs::remove_dir_all(input.join("B002_002")).unwrap();
        let rc = run_offload(&input_c, &dest).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "every row OK");
        // The byte mirror (the dest bytes == the source bytes — the
        // pass-through; every file rides the tree).
        for rel in [
            "A001_001/clip.wav",
            "A001_001/SPP_metadata.xmp",
            "C003_003/clip.wav",
            "root.wav",
            "manifest.tsv",
        ] {
            let src = std::fs::read(input.join(rel)).unwrap();
            let dst = std::fs::read(dest.join(rel)).unwrap();
            assert_eq!(src, dst, "byte mirror: {rel}");
        }
        // mtime preserved (the mirror's clock contract).
        let m1 = std::fs::metadata(input.join("A001_001/clip.wav")).unwrap();
        let m2 = std::fs::metadata(dest.join("A001_001/clip.wav")).unwrap();
        assert_eq!(m1.modified().unwrap(), m2.modified().unwrap(), "mtime preserved");
        // The per-clip manifests: the mirrored clip roots + the dest
        // root (the "" clip — the input's name), each re-verifying
        // clean (the wire contract — the reverify read side).
        let m1 = crate::offload::parse_manifest(&dest.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
        assert_eq!(m1.rows.len(), 2, "the clip's own rows");
        let (_, bad1) = crate::offload::reverify(&m1);
        assert_eq!(bad1, 0, "the clip manifest re-verifies clean");
        let m2 = crate::offload::parse_manifest(&dest.join("C003_003/C003_003.offload-manifest.tsv")).unwrap();
        assert_eq!(m2.rows.len(), 1);
        let m3 = crate::offload::parse_manifest(&dest.join("in.offload-manifest.tsv")).unwrap();
        assert_eq!(m3.rows.len(), 2, "the source-root files (the input's clip name)");
        for m in [&m1, &m2, &m3] {
            let (_, bad) = crate::offload::reverify(m);
            assert_eq!(bad, 0, "{} re-verifies clean", m.name);
        }
        // The run report (the dest root — the pattern: exactly ONE
        // created: line; the detection + copy + verdict sections).
        let tr = read_report(&dest);
        assert_eq!(
            tr.lines().filter(|l| l.starts_with("created:")).count(),
            1,
            "exactly one created: line:\n{tr}"
        );
        assert!(tr.starts_with("# frameprism offload run report — in\n"), "{tr}");
        assert!(tr.contains("## detection"), "{tr}");
        assert!(tr.contains(".: non-DNG media"), "the root clip line: {tr}");
        assert!(tr.contains("A001_001: non-DNG media"), "the sidecar-only clip: {tr}");
        assert!(tr.contains("C003_003: non-DNG media"), "{tr}");
        assert!(tr.contains("## copy"), "{tr}");
        assert!(tr.contains("totals: 5 file(s)"), "{tr}");
        let dest_c = std::fs::canonicalize(&dest).unwrap();
        assert!(
            tr.contains(&format!("\noffload: VERIFIED 5/5 (dest {})\n", dest_c.display())),
            "the verdict line (the existing format — the canonical dest): {tr}"
        );
        assert!(!tr.contains("## failures"), "clean run: no failures section: {tr}");
        let _ = std::fs::remove_dir_all(&base);
    }


    #[test]
    fn standalone_unprofiled_and_profiled_dng_trees_never_transform() {
        profile_override_a001();
        let (base, input) = standalone_tree("dng");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let dest = base.join("to");
        let rc = run_offload(&input_c, &dest).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS);
        // offload NEVER transforms: the dest DNG bytes == the
        // source bytes (NEVER decoded, never re-encoded — the
        // profiled clip's frames are copied as bytes too).
        for clip in ["A001_001", "B002_002"] {
            let src = std::fs::read(input.join(format!("{clip}/f1.DNG"))).unwrap();
            let dst = std::fs::read(dest.join(format!("{clip}/f1.DNG"))).unwrap();
            assert_eq!(src, dst, "no transform: {clip}/f1.DNG");
        }
        // The detection lines (the classes — the report, not a
        // gate: the unprofiled camera's clip is STILL offloaded
        // clean, rc=0).
        let tr = read_report(&dest);
        assert!(tr.contains("A001_001: profiled a001-sigma-fp (profile v1)"), "{tr}");
        assert!(tr.contains("B002_002: unprofiled camera TEST MAKE TEST MODEL"), "{tr}");
        assert!(tr.contains("C003_003: non-DNG media"), "{tr}");
        assert!(tr.contains(".: non-DNG media"), "{tr}");
        // The profiles line names the resolution's source (the
        // honesty context — the test's override file).
        assert!(tr.lines().any(|l| l.starts_with("profiles: the profile file ")), "{tr}");
        // The unprofiled clip's manifest still rides the mirrored clip
        // root + re-verifies clean (the pass-through's record —
        // identity never gates the copy).
        let m = crate::offload::parse_manifest(&dest.join("B002_002/B002_002.offload-manifest.tsv")).unwrap();
        let (_, bad) = crate::offload::reverify(&m);
        assert_eq!(bad, 0, "the unprofiled clip's manifest re-verifies clean");
        let _ = std::fs::remove_dir_all(&base);
    }


    #[test]
    fn standalone_overwrite_pre_corrupted_dest_rerun_clean() {
        profile_override_a001();
        let (base, input) = standalone_tree("overwrite");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let dest = base.join("to");
        // First run (the clean mirror + the manifests + the report).
        let rc1 = run_offload(&input_c, &dest).unwrap();
        assert_eq!(rc1, ExitCode::SUCCESS);
        // Pre-corrupt a dest file between runs: the re-run
        // OVERWRITES it (the re-run is idempotent + re-verified — the
        // standalone surface's repair primitive; `repair` rides the
        // same manifest later).
        std::fs::write(dest.join("A001_001/clip.wav"), b"corrupted-by-hand").unwrap();
        let rc2 = run_offload(&input_c, &dest).unwrap();
        assert_eq!(rc2, ExitCode::SUCCESS, "the re-run re-copies clean");
        assert_eq!(
            std::fs::read(dest.join("A001_001/clip.wav")).unwrap(),
            b"RIFF-wave"
        );
        let m = crate::offload::parse_manifest(&dest.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
        let (_, bad) = crate::offload::reverify(&m);
        assert_eq!(bad, 0, "the re-run's manifest re-verifies clean");
        let tr = read_report(&dest);
        assert!(tr.contains("offload: VERIFIED 7/7 (dest "), "{tr}");
        let _ = std::fs::remove_dir_all(&base);
    }


    #[test]
    fn standalone_copy_fail_named_row_rc1_and_failures_section() {
        profile_override_a001();
        let (base, input) = standalone_tree("copyfail");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let dest = base.join("to");
        // The pre-write band passes (the probe creates + probes the
        // dest root) …
        std::fs::create_dir_all(&dest).unwrap();
        // … then a dest file occupies a source file's mirror path
        // (a DIR at the file's path — the copy itself fails NAMED, the
        // row is COPY_FAIL, the other rows run to completion — the
        // verdict is carried, the run is not killed mid-copy).
        std::fs::create_dir_all(dest.join("A001_001/f1.DNG")).unwrap();
        let rc = run_offload(&input_c, &dest).unwrap();
        assert_eq!(rc, ExitCode::from(1), "the dirty row(s) → rc=1 AFTER the run");
        // The clean rows stand (the mirror of the other 6 files).
        assert_eq!(
            std::fs::read(dest.join("A001_001/clip.wav")).unwrap(),
            b"RIFF-wave"
        );
        // The run report: the `## failures` section (the EXISTING
        // FAIL-line formats — the named row) + the REFUSE verdict
        // line (the existing format).
        let tr = read_report(&dest);
        assert!(tr.contains("## failures"), "{tr}");
        assert!(
            tr.contains("FAIL COPY_FAIL clip=A001_001: A001_001/f1.DNG"),
            "the named FAIL line (the existing format): {tr}"
        );
        let dest_c = std::fs::canonicalize(&dest).unwrap();
        assert!(
            tr.contains(&format!("\noffload: REFUSE 1 named row(s) (dest {})\n", dest_c.display())),
            "the REFUSE verdict line: {tr}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


    #[test]
    fn standalone_pre_write_refusals_rc2() {
        profile_override_a001();
        let base = std::env::temp_dir().join(format!(
            "frameprism_offload_refusal_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        // The nonexistent input (the named refusal — the rc=2 band,
        // before any write).
        let rc = run_offload(&base.join("nope"), &base.join("dest")).unwrap_err();
        assert!(rc.to_string().contains("is not a directory"), "{rc}");
        // The input is a FILE (not a dir).
        std::fs::write(base.join("afile"), b"not a tree").unwrap();
        let rc = run_offload(&base.join("afile"), &base.join("dest")).unwrap_err();
        assert!(rc.to_string().contains("is not a directory"), "{rc}");
        // The dest under a FILE (the probe's named refusal — create +
        // the write-probe, before any row).
        std::fs::create_dir_all(base.join("in")).unwrap();
        let rc = run_offload(&base.join("in"), &base.join("afile/dest")).unwrap_err();
        assert!(rc.to_string().contains("the --to dest dir"), "the probe's existing named line: {rc}");
        assert!(!base.join("afile/dest").exists(), "zero partial writes");
        // The self-mirror guard (the input == the dest — the mirror
        // would copy every file onto itself — the named refusal, zero
        // partial writes).
        std::fs::write(base.join("in/f.wav"), b"x").unwrap();
        let rc = run_offload(&base.join("in"), &base.join("in")).unwrap_err();
        assert!(rc.to_string().contains("are the same dir"), "{rc}");
        let _ = std::fs::remove_dir_all(&base);
    }


    #[test]
    fn core_slices_per_clip_key_space() {
        let base = std::env::temp_dir().join(format!(
            "frameprism_offload_core_slices_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        std::fs::create_dir_all(input.join("b")).unwrap();
        // No source-root files (the "" key = the 0-file key — the
        // empty root's slice; the report's blocks carry "b" only).
        std::fs::write(input.join("b/f1.DNG"), b"frame").unwrap();
        std::fs::write(input.join("b/clip.wav"), b"b-sidecar").unwrap();
        let dest = base.join("to");
        // The caller's key space is authoritative: a key with no
        // files slices 0/0 (the empty clip dir the caller's scan can
        // name); the given order is the slices' order.
        let outcome = offload_core(&input, &dest, &["".to_string(), "b".to_string()]).unwrap();
        assert_eq!(outcome.per_clip.len(), 2);
        assert_eq!(outcome.per_clip[0].key, "");
        assert_eq!((outcome.per_clip[0].total, outcome.per_clip[0].ok), (0, 0),
            "the 0-file key: the 0/0 slice");
        assert_eq!(outcome.per_clip[1].key, "b");
        assert_eq!((outcome.per_clip[1].total, outcome.per_clip[1].ok), (2, 2));
        // The whole-tree report: every row + the BTreeMap clip-key
        // block order (the encode manifest's byte contract — the
        // blocks are NOT re-ordered by the given key space; the
        // 0-file key carries no block — today's by_clip semantics).
        assert_eq!(outcome.report.rows.len(), 2);
        let blocks: Vec<(&str, (u64, u64))> = outcome
            .report
            .clips
            .iter()
            .map(|c| (c.clip.as_str(), (c.total, c.ok)))
            .collect();
        assert_eq!(blocks, vec![("b", (2, 2))]);
        // The slices carry the whole-tree row order (the sorted
        // relpath order).
        let files: Vec<&str> = outcome.per_clip[1]
            .rows
            .iter()
            .map(|r| r.file.as_str())
            .collect();
        assert_eq!(files, vec!["b/clip.wav", "b/f1.DNG"]);
        let _ = std::fs::remove_dir_all(&base);
    }

    // =================================================================
    // The multi-destination fan-out (N dests in one pass — the
    // read-once/write-N core, the all-N pre-write refusals, the
    // per-dest artifacts + status)
    // =================================================================


    /// The 2-dest clean run (the minimum set, test 1): rc=0;
    /// BOTH dests the full mirror + the per-clip manifests (the
    /// `dest` header = ITS dest) + the run report (one `created:`
    /// line each, the detection block ONCE, the per-dest VERIFIED
    /// lines); the source sha256 shared across the N manifests.
    #[test]
    fn fanout_two_dest_clean_rc0_per_dest_artifacts() {
        profile_override_a001();
        let (base, input) = standalone_tree("fanout2clean");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        let rc = run_offload_multi(&input_c, &[d1.clone(), d2.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "every row OK at every dest");
        let d1c = std::fs::canonicalize(&d1).unwrap();
        let d2c = std::fs::canonicalize(&d2).unwrap();
        // BOTH dests: the full byte mirror (the pass-through — every
        // file rides both trees; the 1-dest observables unchanged).
        for rel in [
            "A001_001/f1.DNG",
            "A001_001/clip.wav",
            "A001_001/SPP_metadata.xmp",
            "B002_002/f1.DNG",
            "C003_003/clip.wav",
            "root.wav",
            "manifest.tsv",
        ] {
            let src = std::fs::read(input.join(rel)).unwrap();
            for d in [&d1c, &d2c] {
                assert_eq!(
                    src,
                    std::fs::read(d.join(rel)).unwrap(),
                    "byte mirror: {:?}/{rel}",
                    d
                );
            }
        }
        // The per-clip manifests: each dest's own mirrored clip roots;
        // the `dest` header row = ITS dest (the wire contract — the
        // the path-independent reverify inherits them unchanged).
        for (d, dc) in [(d1c.clone(), d1c.clone()), (d2c.clone(), d2c.clone())] {
            let m1 = crate::offload::parse_manifest(&d.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
            assert_eq!(m1.rows.len(), 3, "the clip's own rows: {:?}", d);
            assert_eq!(m1.dest, dc, "the manifest's dest header = ITS dest");
            let (_, bad) = crate::offload::reverify(&m1);
            assert_eq!(bad, 0, "{d:?}: the clip manifest re-verifies clean");
            let m2 = crate::offload::parse_manifest(&d.join("in.offload-manifest.tsv")).unwrap();
            assert_eq!(m2.rows.len(), 2, "the source-root files: {:?}", d);
            assert_eq!(m2.dest, dc, "the root manifest's dest header = ITS dest");
            let (_, bad) = crate::offload::reverify(&m2);
            assert_eq!(bad, 0, "{d:?}: the root manifest re-verifies clean");
        }
        // the source sha256 is computed ONCE and shared by every
        // dest's rows: the source_sha256 column is identical across
        // the two manifests (the dest sha256 columns are per-dest —
        // equal to the source on a clean run).
        let a1 = crate::offload::parse_manifest(&d1c.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
        let a2 = crate::offload::parse_manifest(&d2c.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
        for ((_, _, s1, d1s), (_, _, s2, d2s)) in a1.rows.iter().zip(a2.rows.iter()) {
            assert_eq!(s1, s2, "the source sha256 shared across the dests");
            assert_eq!(s1, d1s, "the dest sha = the source sha (clean run)");
            assert_eq!(s1, d2s, "the dest sha = the source sha (clean run)");
        }
        // The run report at BOTH dest roots (each carries the WHOLE
        // run): one `created:` line each; the detection block ONCE;
        // one per-dest section per dest + each dest's VERIFIED line
        // verbatim (the existing format — the stderr surface prints
        // the same lines, the per-dest blocks).
        for (d, dc, other) in [(&d1c, &d1c, &d2c), (&d2c, &d2c, &d1c)] {
            let tr = read_report(d);
            assert_eq!(
                tr.lines().filter(|l| l.starts_with("created:")).count(),
                1,
                "exactly one created: line:\n{tr}"
            );
            assert_eq!(tr.matches("## detection").count(), 1, "the detection block ONCE:\n{tr}");
            assert_eq!(tr.matches("### destination: ").count(), 2, "one section per dest:\n{tr}");
            assert!(tr.contains(&format!("### destination: {}", dc.display())), "the dest's own section header:\n{tr}");
            assert!(
                tr.contains(&format!("\noffload: VERIFIED 7/7 (dest {})\n", dc.display())),
                "the dest's own verdict line verbatim:\n{tr}"
            );
            assert!(
                tr.contains(&format!("\noffload: VERIFIED 7/7 (dest {})\n", other.display())),
                "the other dest's section (the report carries the whole run):\n{tr}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The 2-dest, one dirty (the minimum set, test 3): the rc=1
    /// band — dest1's rows all OK, dest2's named FAIL line (the
    /// EXISTING format — no dest slot in the line itself) + the
    /// per-dest verdict lines (dest1 VERIFIED + dest2 REFUSE, the
    /// count named); the post-run corruption is named via the
    /// reverify surface; the stderr composition pinned (the N>1
    /// per-dest blocks + the N=1 wording byte-unchanged).
    #[test]
    fn fanout_two_dest_one_dirty_rc1_per_dest_status() {
        profile_override_a001();
        let (base, input) = standalone_tree("fanout2dirty");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        // Both pre-write bands pass (the probes create + probe the
        // dest roots) …
        std::fs::create_dir_all(&d1).unwrap();
        std::fs::create_dir_all(&d2).unwrap();
        // … then d2's f1.DNG mirror path is occupied by a DIR (the
        // existing in-run COPY_FAIL idiom): d1's rows all OK, d2's
        // named row COPY_FAIL — the rc=1 band (ANY dirty dest).
        std::fs::create_dir_all(d2.join("A001_001/f1.DNG")).unwrap();
        let rc = run_offload_multi(&input_c, &[d1.clone(), d2.clone()]).unwrap();
        assert_eq!(rc, ExitCode::from(1), "any dirty dest = rc=1 AFTER the run");
        let d1c = std::fs::canonicalize(&d1).unwrap();
        let d2c = std::fs::canonicalize(&d2).unwrap();
        // dest1: every row OK (the clean half of the fan-out stands).
        let m1 = crate::offload::parse_manifest(&d1c.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
        let (l1, bad1) = crate::offload::reverify(&m1);
        assert_eq!(bad1, 0, "dest1's rows all OK: {l1:?}");
        // dest2: the named row (the reverify surface — the existing
        // format; the run is not killed mid-copy, the other 6 rows
        // stand).
        let m2 = crate::offload::parse_manifest(&d2c.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
        let (l2, bad2) = crate::offload::reverify(&m2);
        assert_eq!(bad2, 1, "exactly the named row: {l2:?}");
        assert!(
            l2.iter().any(|l| l.starts_with("FAIL offload A001_001/f1.DNG")),
            "the named row (the existing reverify format): {l2:?}"
        );
        assert_eq!(
            std::fs::read(d2c.join("A001_001/clip.wav")).unwrap(),
            b"RIFF-wave",
            "the clean rows stand at d2"
        );
        // The run reports (each carries the whole run): dest1's
        // section VERIFIED, dest2's section the failures + the
        // REFUSE verdict (the count named) + the named FAIL line
        // (the EXISTING format — no dest slot in the line itself).
        let tr1 = read_report(&d1);
        assert!(
            tr1.contains(&format!("\noffload: VERIFIED 7/7 (dest {})\n", d1c.display())),
            "dest1 VERIFIED (every dest named):\n{tr1}"
        );
        assert!(
            tr1.contains("FAIL COPY_FAIL clip=A001_001: A001_001/f1.DNG"),
            "dest2's named FAIL line (the existing format):\n{tr1}"
        );
        assert!(
            tr1.contains(&format!("\noffload: REFUSE 1 named row(s) (dest {})\n", d2c.display())),
            "dest2 REFUSE (the count named):\n{tr1}"
        );
        assert!(tr1.contains("## failures"), "the failures section under d2's section:\n{tr1}");
        // Post-run corruption on dest2 (the reverify surface names it
        // — the flip-one-byte idiom; the existing reverify format).
        let victim = d2c.join("A001_001/clip.wav");
        let mut buf = std::fs::read(&victim).unwrap();
        buf[0] ^= 0x01;
        std::fs::write(&victim, buf).unwrap();
        let (l2b, bad2b) = crate::offload::reverify(&m2);
        assert_eq!(bad2b, 2, "the named row + the corrupted row: {l2b:?}");
        assert!(
            l2b.iter().any(|l| l.starts_with("FAIL offload A001_001/clip.wav") && l.contains("SHA_MISMATCH: source sha256")),
            "the post-run corruption named (the existing format): {l2b:?}"
        );
        // The stderr surface (the per-dest blocks — the EXISTING line
        // formats composed; the N=1 wording byte-unchanged at N=1):
        // dest1's VERIFIED line, then dest2's FAIL line + the
        // per-dest OFFLOAD FAIL line (the all-N phrasing), the dest
        // order.
        let clean = OffloadReport {
            input: PathBuf::from("/in"),
            dest: PathBuf::from("/d1"),
            rows: vec![OffloadRow {
                file: "x.DNG".into(),
                size: 1,
                source_sha: "s".into(),
                dest_sha: "s".into(),
                verdict: Verdict::Ok,
                detail: String::new(),
            }],
            clips: vec![],
        };
        let dirty = OffloadReport {
            input: PathBuf::from("/in"),
            dest: PathBuf::from("/d2"),
            rows: vec![OffloadRow {
                file: "x.DNG".into(),
                size: 1,
                source_sha: "s".into(),
                dest_sha: "-".into(),
                verdict: Verdict::CopyFail,
                detail: "no space left".into(),
            }],
            clips: vec![],
        };
        let lines = fanout_stderr_lines(&[clean.clone(), dirty.clone()]);
        assert_eq!(
            lines,
            vec![
                "offload: VERIFIED 1/1 (dest /d1)".to_string(),
                "FAIL COPY_FAIL clip=.: x.DNG: no space left".to_string(),
                "OFFLOAD FAIL — 1 dirty row(s) (dest /d2): the named FAIL lines above (the verify-before-wipe gate holds: the source tree is reusable only after all 2 dests verify clean)".to_string(),
            ],
            "the N>1 per-dest blocks (the existing formats only)"
        );
        // The N=1 composition (the R-INV-1 wording — byte-identical
        // to the pre-fan-out stream).
        let lines1 = fanout_stderr_lines(&[dirty]);
        assert_eq!(
            lines1,
            vec![
                "FAIL COPY_FAIL clip=.: x.DNG: no space left".to_string(),
                "OFFLOAD FAIL — 1 dirty row(s) (dest /d2): the named FAIL lines above (the verify-before-wipe gate holds: the source tree is reusable only after the dest verifies clean)".to_string(),
            ],
            "the N=1 stream (the existing wording, unchanged)"
        );
        let _ = clean;
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The pre-write all-N proof (the minimum set, test 4): dest2
    /// unwritable (the existing probe-failure idiom) → the NAMED
    /// refusal + ZERO files written to dest1 (the probe ordering: the
    /// N probes complete before the first source read).
    #[test]
    fn fanout_pre_write_all_n_zero_partial_writes() {
        profile_override_a001();
        let (base, input) = standalone_tree("fanout2refusal");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d1 = base.join("to1");
        // d2's path is unwritable (a FILE where the dir must be — the
        // existing `check_dest_writable` failure idiom).
        std::fs::write(base.join("blocker"), b"file").unwrap();
        let d2 = base.join("blocker/dest");
        let err = run_offload_multi(&input_c, &[d1.clone(), d2.clone()]).unwrap_err();
        assert!(
            err.to_string().contains("the --to dest dir"),
            "the named probe refusal for d2 (the rc=2 band): {err}"
        );
        // The pre-write proof: d1's own probe passed (the dir exists)
        // but NO source file was written to it — no mirror, no
        // manifests, no run report (the N probes complete before the
        // first source read).
        assert!(!d1.join("A001_001").exists(), "no mirrored tree at d1");
        assert!(!d1.join("in.offload-manifest.tsv").exists(), "no manifest at d1");
        assert!(!d1.join(crate::report::RUN_REPORT_NAME).exists(), "no run report at d1");
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The duplicate-dest refusal (the minimum set, test 5):
    /// `to1 == to2` → rc=2 named, zero writes (the fan-out refuses
    /// the duplicate — it does not silently dedupe it); the
    /// canonicalized-path equality catches the symlinked alias too.
    #[cfg(unix)]
    #[test]
    fn fanout_duplicate_dest_refused_zero_writes() {
        profile_override_a001();
        let (base, input) = standalone_tree("fanout2dup");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        // The identical dest string (fresh — the refusal fires
        // BEFORE the probe: nothing is created).
        let err = run_offload_multi(&input_c, &[d.clone(), d.clone()]).unwrap_err();
        assert!(
            err.to_string().contains("duplicate dest"),
            "the named duplicate refusal (the rc=2 band): {err}"
        );
        assert!(!d.exists(), "zero writes (before any probe)");
        // The symlinked alias (the canonicalized-path equality — the
        // second arg symlinks to the first's dir).
        std::fs::create_dir_all(&d).unwrap();
        std::os::unix::fs::symlink(&d, base.join("to-alias")).unwrap();
        let d_alias = base.join("to-alias");
        let err = run_offload_multi(&input_c, &[d.clone(), d_alias.clone()]).unwrap_err();
        assert!(
            err.to_string().contains("duplicate dest"),
            "the symlinked alias is the named duplicate: {err}"
        );
        assert!(!d.join("in.offload-manifest.tsv").exists(), "zero writes (the alias case)");
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The self-mirror guard per dest (the minimum set, test 6):
    /// `in == to2`, to1 clean → rc=2 named, zero writes (the guard
    /// covers EVERY dest — the refusal fires before any probe).
    #[test]
    fn fanout_self_mirror_per_dest() {
        profile_override_a001();
        let (base, input) = standalone_tree("fanout2mirror");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d1 = base.join("to");
        // The clean to1 first, the self-mirror to2 second: the guard
        // fires on to2, before any probe — zero writes anywhere.
        let err = run_offload_multi(&input_c, &[d1.clone(), input_c.clone()]).unwrap_err();
        assert!(
            err.to_string().contains("are the same dir"),
            "the named self-mirror refusal (the rc=2 band): {err}"
        );
        assert!(!d1.exists(), "zero writes (the clean to1 was never probed)");
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The audit inheritance (the minimum set — the
    /// integration): a 2-dest clean run → every fan-out dest
    /// is a re-verifiable standalone mirror (the audit's re-verify
    /// surface per dest: rc=0 + the OK verdict line, the
    /// inheritance claim PROVEN in the suite).
    #[test]
    fn fanout_dest_audit_inheritance() {
        profile_override_a001();
        let (base, input) = standalone_tree("fanout2audit");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        let rc = run_offload_multi(&input_c, &[d1.clone(), d2.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "every row OK at every dest");
        // The pure surface half, per dest: 4 manifests (2 clip roots
        // + C003 + the source-root manifest), 7 rows, zero
        // offenders, the OK verdict line (the format
        // verbatim — the path as passed).
        for d in [&d1, &d2] {
            let res = crate::audit::audit_offload_manifests(d, true)
                .unwrap()
                .expect("the dest's records were discovered");
            assert_eq!(res.bad, 0, "{d:?}: every row re-verifies clean: {res:?}");
            assert!(
                res.lines.iter().all(|l| !l.starts_with("FAIL ")),
                "zero FAIL lines: {res:?}"
            );
            assert_eq!(
                res.lines.last().map(String::as_str),
                Some(
                    format!("audit: offload re-verify {}: 4 manifest(s), 7 row(s) OK", d.display())
                        .as_str()
                ),
                "the OK verdict line (the per-dest re-verify surface): {res:?}"
            );
        }
        // The surface's rc half (the ops ledger redirected to the
        // test's file — the audit-verb test idiom).
        let _guard = crate::ENV_LOCK.lock().expect("env lock");
        let ledger = base.join(".ledger-test.tsv");
        let _ = std::fs::remove_file(&ledger);
        std::env::set_var("FRAMEPRISM_LEDGER", &ledger);
        let rc = crate::audit::run_audit(&crate::audit::AuditArgs {
            input: d1.clone(),
            jobs: 1,
            source: None,
        });
        std::env::remove_var("FRAMEPRISM_LEDGER");
        assert_eq!(rc, ExitCode::SUCCESS, "the audit's rc on a fan-out dest = 0");
        let _ = std::fs::remove_dir_all(&base);
    }


    /// Test 1 — the clean skip: the dest pre-seeded with the
    /// identical bytes → every row skipped + Ok (rc=0, the VERIFIED
    /// verdict line), the dest files' mtimes UNCHANGED (the skip
    /// never touches them), the per-clip manifests byte-identical to
    /// a fresh-copy run's manifests (modulo the `created:` + `dest:`
    /// free lines — the skip fact is off the wire, R-INV-M).
    #[test]
    fn offload_skip_clean() {
        profile_override_a001();
        let (base, input) = standalone_tree("skipclean");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        seed_mirror(&d, &input, None, None, None);
        // The dest files' mtimes recorded pre-run (the skip performs
        // no write + no mtime set — asserted post-run).
        let pre_mt = |rel: &str| std::fs::metadata(d.join(rel)).unwrap().modified().unwrap();
        let pre_f1 = pre_mt("A001_001/f1.DNG");
        let pre_root = pre_mt("root.wav");
        // The full surface run (the records: the per-clip manifests
        // + the run report + the job report + the ascmhl) — the rc is
        // the run's rc (a skipped row is OK — the skip is NOT dirty).
        let rc = run_offload_multi(&input_c, &[d.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "every row verified OK (the skip is NOT dirty)");
        let dc = std::fs::canonicalize(&d).unwrap();
        // The verdict line VERIFIED (the run report's per-dest
        // verdict — the existing format verbatim).
        let tr = read_report(&d);
        assert!(
            tr.contains(&format!("offload: VERIFIED 7/7 (dest {})\n", dc.display())),
            "the VERIFIED verdict line verbatim:\n{tr}"
        );
        // The skip facts (the core's `skipped` vector — the
        // pre-seeded dest: every (file, dest) row skipped) + every
        // row Ok (the dest content WAS verified — sha256 equal is
        // exactly the OK definition).
        let core = offload_core_multi(&input_c, &[d.clone()], &clip_keys_of(&input)).unwrap();
        assert_eq!(core.skipped[0].len(), 7, "one skip fact per row");
        assert!(
            core.skipped[0].iter().all(|s| *s),
            "every row skipped: {:?}",
            core.skipped[0]
        );
        assert!(
            core.reports[0].rows.iter().all(|r| r.verdict == Verdict::Ok),
            "every skipped row is Ok: {:?}",
            core.reports[0].rows.iter().map(|r| (r.file.clone(), r.verdict)).collect::<Vec<_>>()
        );
        // The dest files' mtimes UNCHANGED (the seeded mtimes stand
        // — the skip never touches them).
        assert_eq!(pre_mt("A001_001/f1.DNG"), pre_f1, "the skipped file's mtime untouched");
        assert_eq!(pre_mt("root.wav"), pre_root, "the skipped file's mtime untouched");
        // The per-clip manifests byte-identical to a FRESH-copy
        // run's (a fresh dest: zero skips — the copy path), modulo
        // the `created:` + `dest:` free lines (the skip fact is off
        // the wire, R-INV-M).
        let d2 = base.join("fresh");
        let rc2 = run_offload_multi(&input_c, &[d2.clone()]).unwrap();
        assert_eq!(rc2, ExitCode::SUCCESS, "the fresh-copy baseline run");
        for name in [
            "in.offload-manifest.tsv",
            "A001_001/A001_001.offload-manifest.tsv",
            "B002_002/B002_002.offload-manifest.tsv",
            "C003_003/C003_003.offload-manifest.tsv",
        ] {
            assert_eq!(
                manifest_masked(&d.join(name)),
                manifest_masked(&d2.join(name)),
                "the per-clip manifest {name} is byte-identical (modulo the free lines)"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }


    /// Test 2 — the mixed skip: one pre-seeded identical file
    /// (skipped + Ok) + one pre-seeded FLIPPED file (one-byte XOR —
    /// the size-match/sha-mismatch fall-through: the copy path ran,
    /// the copy OVERWRITES, the row is Ok after the re-verify); the
    /// `## skipped` section lists the clip; rc=0 (the skip is NOT
    /// dirty — the flipped file re-copies clean).
    #[test]
    fn offload_skip_mixed_dirty() {
        profile_override_a001();
        let (base, input) = standalone_tree("skippmixed");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        let d2 = base.join("core");
        // The pre-seed (both dests the same shape — ONLY the two
        // A001_001 files: the identical A001_001/f1.DNG (the skip) +
        // the FLIPPED A001_001/clip.wav (one byte XOR — the fall-
        // through); the rest NOT pre-seeded — the fresh copy).
        seed_mirror(
            &d,
            &input,
            Some(&["A001_001/f1.DNG", "A001_001/clip.wav"]),
            Some("A001_001/clip.wav"),
            None,
        );
        seed_mirror(
            &d2,
            &input,
            Some(&["A001_001/f1.DNG", "A001_001/clip.wav"]),
            Some("A001_001/clip.wav"),
            None,
        );
        // The surface run (the records + the rc + the run report's
        // `## skipped` section).
        let rc = run_offload_multi(&input_c, &[d.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "the skip + the re-copy are both OK (the skip is NOT dirty)");
        let dc = std::fs::canonicalize(&d).unwrap();
        assert!(
            read_report(&d).contains(&format!("offload: VERIFIED 7/7 (dest {})\n", dc.display())),
            "the VERIFIED verdict line verbatim\n"
        );
        // The `## skipped` section lists the clip (the clip's total
        // files + the clip's skipped count — one), the pinned
        // rendering).
        let tr = read_report(&d);
        assert!(
            tr.contains("## skipped\n\nclip\tfiles\tskipped\nA001_001\t3\t1\ntotals: 1 file(s) skipped (already present, sha256-verified — not re-copied)\n"),
            "the pinned `## skipped` section (one line for the clip WITH ≥1 skip):\n{tr}"
        );
        // The skip facts (the core pass over the twin pre-seed — the
        // first pass: the flipped file is still flipped): the
        // seeded-identical row skipped + Ok, the flipped row copied
        // + Ok (the copy overwrote the flipped bytes — the re-run
        // stays idempotent + re-verified).
        let core = offload_core_multi(&input_c, &[d2.clone()], &clip_keys_of(&input)).unwrap();
        let j_f1 = core.reports[0].rows.iter().position(|r| r.file == "A001_001/f1.DNG").unwrap();
        let j_wav = core.reports[0].rows.iter().position(|r| r.file == "A001_001/clip.wav").unwrap();
        assert!(core.skipped[0][j_f1], "the seeded-identical row is skipped");
        assert!(!core.skipped[0][j_wav], "the flipped row is NOT skipped (the sha pre-check fails — the copy path ran)");
        assert_eq!(core.reports[0].rows[j_f1].verdict, Verdict::Ok, "the skipped row is Ok");
        assert_eq!(core.reports[0].rows[j_wav].verdict, Verdict::Ok, "the re-copied row is Ok (the copy overwrites)");
        let src_wav = std::fs::read(input.join("A001_001/clip.wav")).unwrap();
        assert_eq!(
            std::fs::read(d2.join("A001_001/clip.wav")).unwrap(),
            src_wav,
            "the copy OVERWROTE the flipped file (the dest now carries the source's bytes)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


    /// Test 3 — the size-mismatch fall-through: the dest
    /// pre-seeded with the WRONG SIZE (the content differs) → NOT
    /// skipped (the size shortcut's negative case), copied +
    /// verified Ok (the copy overwrites — the row re-verifies
    /// against the source after the re-scan).
    #[test]
    fn offload_skip_size_mismatch_falls_through() {
        profile_override_a001();
        let (base, input) = standalone_tree("skipsize");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        seed_mirror(&d, &input, None, None, Some("A001_001/f1.DNG"));
        let core = offload_core_multi(&input_c, &[d.clone()], &clip_keys_of(&input)).unwrap();
        let j = core.reports[0].rows.iter().position(|r| r.file == "A001_001/f1.DNG").unwrap();
        assert!(!core.skipped[0][j], "the wrong-size pre-seed is NOT skipped (the size shortcut's negative case)");
        assert_eq!(core.reports[0].rows[j].verdict, Verdict::Ok, "copied + verified Ok");
        let src = std::fs::read(input.join("A001_001/f1.DNG")).unwrap();
        assert_eq!(
            std::fs::read(d.join("A001_001/f1.DNG")).unwrap(),
            src,
            "the copy overwrote the wrong-size file"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


    /// Test 4 — the fresh dest (the suite anchor): zero
    /// skips, the run report has NO `## skipped` substring (the
    /// section is ABSENT — the zero-skip run renders byte-identically
    /// to the pre-existing shape), the CSV header = the new pinned header
    /// (the pin move) + every data row's `skipped` cell =
    /// `0`.
    #[test]
    fn offload_skip_absent_on_fresh() {
        profile_override_a001();
        let (base, input) = standalone_tree("skipfresh");
        let input_c = std::fs::canonicalize(&input).unwrap();
        // The zero-skip core facts (a fresh dest — the predicate's
        // input is absent for every (file, dest)).
        let d3 = base.join("core");
        let core = offload_core_multi(&input_c, &[d3.clone()], &clip_keys_of(&input)).unwrap();
        assert!(core.skipped[0].iter().all(|s| !*s), "a fresh dest: zero skips: {:?}", core.skipped[0]);
        // The surface run (the fresh dest — the records' rendering).
        let d = base.join("to");
        let rc = run_offload_multi(&input_c, &[d.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS);
        // The run report: NO `## skipped` substring (byte-level
        // absence — the zero-skip rendering is byte-identical to the
        // pre-existing shape).
        let tr = read_report(&d);
        assert!(!tr.contains("## skipped"), "the `## skipped` section is ABSENT:\n{tr}");
        // The job report's CSV: the new pinned header + every data
        // row's `skipped` cell = `0` (the column = immediately before
        // copied_ms — the last position before the wall clock).
        let (_md, csv, _html) = job_report_files(&d);
        let cl: Vec<&str> = csv.lines().collect();
        assert_eq!(
            cl[0],
            "clip,file,size_bytes,source_sha256,dest_sha256,verdict,skipped,copied_ms",
            "the new pinned header (the pin move):\n{csv}"
        );
        for line in &cl[1..] {
            let f: Vec<&str> = line.split(',').collect();
            assert_eq!(f[6], "0", "every fresh row's `skipped` cell = 0: {line:?}");
        }
        let _ = std::fs::remove_dir_all(&base);
    }


    /// Test 6 — the pinned `## skipped` bytes: the 2-clip tree
    /// (C1 fully skipped — both files pre-seeded; C2 partial — one
    /// file pre-seeded + one fresh) → the EXACT pinned section
    /// (the tab-separated table, one line per clip WITH ≥1
    /// skip, the detection clip order, the totals line; the pinned
    /// placement — after the copy block's `totals:` line, before the
    /// verdict line); the section ABSENT when zero skips (the
    /// byte-level absence — the fresh-dest twin).
    #[test]
    fn offload_skip_run_report_section() {
        profile_override_a001();
        let base = std::env::temp_dir().join(format!("frameprism_offload_skip_section_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        std::fs::create_dir_all(input.join("C1")).unwrap();
        std::fs::create_dir_all(input.join("C2")).unwrap();
        std::fs::write(input.join("C1/a.DNG"), b"payload-a").unwrap();
        std::fs::write(input.join("C1/b.wav"), b"payload-b").unwrap();
        std::fs::write(input.join("C2/c.DNG"), b"payload-c").unwrap();
        std::fs::write(input.join("C2/d.wav"), b"payload-d").unwrap();
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        // Pre-seed: C1 fully (a.DNG + b.wav) + C2 partial (c.DNG —
        // d.wav stays fresh).
        for rel in ["C1/a.DNG", "C1/b.wav", "C2/c.DNG"] {
            let bytes = std::fs::read(input.join(rel)).unwrap();
            let p = d.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, bytes).unwrap();
        }
        let rc = run_offload_multi(&input_c, &[d.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS);
        // The EXACT pinned `## skipped` bytes — C1 fully
        // skipped (2 of 2), C2 partial (1 of 2), the totals line.
        let tr = read_report(&d);
        assert!(
            tr.contains(
                "## skipped\n\nclip\tfiles\tskipped\nC1\t2\t2\nC2\t2\t1\ntotals: 3 file(s) skipped (already present, sha256-verified — not re-copied)\n"
            ),
            "the pinned `## skipped` section (the EXACT bytes):\n{tr}"
        );
        // The pinned placement (after the copy block's `totals:`
        // line, before the verdict line).
        let i_totals = tr.find("totals: 4 file(s)").expect("the copy block's totals line:\n{tr}");
        let i_skip = tr.find("## skipped").expect("the `## skipped` section:\n{tr}");
        let i_verdict = tr.find("offload: VERIFIED 4/4").expect("the verdict line:\n{tr}");
        assert!(i_totals < i_skip && i_skip < i_verdict, "the pinned placement:\n{tr}");
        // The section ABSENT when zero skips (the byte-level
        // absence — the fresh-dest twin: no `## skipped` substring
        // anywhere in the report text).
        let d2 = base.join("fresh");
        let rc2 = run_offload_multi(&input_c, &[d2.clone()]).unwrap();
        assert_eq!(rc2, ExitCode::SUCCESS);
        let tr2 = read_report(&d2);
        assert!(!tr2.contains("## skipped"), "zero skips: the section is ABSENT (byte level):\n{tr2}");
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The audit inheritance (the reverify fact): a
    /// mirror written with skips (the dest pre-seeded — the run
    /// skips every file) → the audit's re-verify surface over the
    /// mirror passes unchanged (zero offenders, the OK verdict line
    /// — the rc=0 band: the manifest is frozen — the skip history is
    /// not a mirror fact).
    #[test]
    fn offload_skip_audit_inheritance() {
        profile_override_a001();
        let (base, input) = standalone_tree("skippaudit");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        seed_mirror(&d, &input, None, None, None);
        // The skip run (the mirror written with skips — the full
        // surface: the per-clip manifests + the run report + the job
        // report + the ascmhl).
        let rc = run_offload_multi(&input_c, &[d.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "the all-skipped run stays rc=0");
        // The audit's re-verify surface over the mirror (the
        // reverify pass — `frameprism audit <mirror>`'s pure core):
        // zero offenders + the OK verdict line (the re-verify
        // passes UNCHANGED — the manifest is frozen).
        let res = crate::audit::audit_offload_manifests(&d, true)
            .unwrap()
            .expect("the mirror's records were discovered");
        assert_eq!(res.bad, 0, "every row re-verifies clean (the audit inherits the skip-written mirror unchanged): {res:?}");
        assert!(res.lines.iter().all(|l| !l.starts_with("FAIL ")), "zero FAIL lines: {res:?}");
        assert!(
            res.lines.iter().any(|l| l.starts_with("audit: offload re-verify") && l.contains("OK")),
            "the OK verdict line (the rc=0 band): {res:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


    /// Test 8 — the 2-dest fan-out (dest1 pre-seeded — skips,
    /// dest2 fresh — copies): the per-dest `## skipped` sections
    /// correct (the dest1 section PRESENT, the dest2 section ABSENT
    /// — the section is per-dest), the per-dest manifests
    /// byte-identical across the two dests (modulo the `dest:` +
    /// `created:` free lines), rc=0.
    #[test]
    fn offload_skip_2dest_partial() {
        profile_override_a001();
        let (base, input) = standalone_tree("skipp2d");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        seed_mirror(&d1, &input, None, None, None);
        let rc = run_offload_multi(&input_c, &[d1.clone(), d2.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "dest1 skips + dest2 copies — every row OK at every dest");
        let d1c = std::fs::canonicalize(&d1).unwrap();
        let d2c = std::fs::canonicalize(&d2).unwrap();
        // The per-dest `## skipped` sections (the N>1 shape: the
        // dest1 section carries the section, the dest2 section does
        // NOT — the section is per-dest; exactly ONE `## skipped`
        // in the whole-run report).
        let tr = read_report(&d1);
        assert_eq!(tr.matches("## skipped").count(), 1, "exactly one `## skipped` section (the dest1's):\n{tr}");
        let s1 = format!("### destination: {}\n\n## copy\n", d1c.display());
        let s2 = format!("### destination: {}\n\n## copy\n", d2c.display());
        let i1 = tr.find(&s1).expect("the dest-1 section header:\n{tr}");
        let i2 = tr.find(&s2).expect("the dest-2 section header:\n{tr}");
        assert!(i1 < i2, "the dest order: the sections ride the named order");
        let sec1 = &tr[i1..i2];
        let sec2 = &tr[i2..];
        assert!(
            sec1.contains("## skipped\n\nclip\tfiles\tskipped\n"),
            "the dest1 section carries the `## skipped` section:\n{sec1}"
        );
        assert!(
            sec1.contains("totals: 7 file(s) skipped (already present, sha256-verified — not re-copied)\n"),
            "the dest1 section's totals (every file skipped):\n{sec1}"
        );
        assert!(!sec2.contains("## skipped"), "the dest2 section (the fresh dest) is ABSENT:\n{sec2}");
        // The per-dest manifests byte-identical (modulo the `dest:`
        // + `created:` free lines — the skip fact is off the wire).
        for name in [
            "in.offload-manifest.tsv",
            "A001_001/A001_001.offload-manifest.tsv",
            "B002_002/B002_002.offload-manifest.tsv",
            "C003_003/C003_003.offload-manifest.tsv",
        ] {
            assert_eq!(
                manifest_masked(&d1.join(name)),
                manifest_masked(&d2.join(name)),
                "the per-dest manifest {name} is byte-identical across the dests (modulo the free lines)"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }


    /// Test 9 — the ascmhl unchanged (the ignore set + the
    /// c4 fact): a run with skips writes the ascmhl as usual — the
    /// skipped files' c4 == the fresh-copy run's c4 for the same
    /// content (the dest bytes are the same — the skip never writes
    /// different bytes), the generation appends (the re-run onto the
    /// seeded dest: the 0002 record, the 0001 record
    /// byte-preserved), rc=0, the ascmhl SILENT on success (the
    /// stderr surface carries no ascmhl line — the records carry no
    /// ascmhl content, the R-INV-A artifact proof).
    #[test]
    fn offload_skip_ascmhl_unchanged() {
        profile_override_a001();
        let (base, input) = standalone_tree("skippmhl");
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        // Generation 1 (the fresh run — every file copied: the
        // ascmhl's c4 set for the content).
        let rc = run_offload_multi(&input_c, &[d.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "the fresh run stays rc=0");
        let ascmhl_dir = d.join("ascmhl");
        let mut names: Vec<String> = std::fs::read_dir(&ascmhl_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let g1 = names
            .iter()
            .find(|n| n.ends_with(".mhl") && n.starts_with("0001_"))
            .expect("the generation-1 manifest");
        let g1 = g1.clone();
        let g1_bytes = std::fs::read(ascmhl_dir.join(&g1)).unwrap();
        // The file-hash c4 set (the rel → c4 map — the dest bytes'
        // content hashes; the managed set = the media only).
        let file_c4 = |root: &crate::ascmhl::XmlEl| -> Vec<(String, String)> {
            root.children[2]
                .children
                .iter()
                .filter(|e| e.name == "hash")
                .map(|e| (e.children[0].text.clone(), e.children[1].text.clone()))
                .collect()
        };
        let g1_root = crate::ascmhl::parse_lite(&String::from_utf8(g1_bytes.clone()).unwrap()).unwrap();
        let g1_c4 = file_c4(&g1_root);
        assert_eq!(g1_c4.len(), 7, "the 7 media files' c4s (the managed set): {g1_c4:?}");
        // Generation 2 (the RE-OFFLOAD onto the same dest — every
        // file already present + identical → every row skipped):
        // the generation APPENDS (the 0002 manifest + the chain
        // record; the 0001 record byte-preserved).
        let rc2 = run_offload_multi(&input_c, &[d.clone()]).unwrap();
        assert_eq!(rc2, ExitCode::SUCCESS, "the all-skipped re-run stays rc=0");
        names.clear();
        names = std::fs::read_dir(&ascmhl_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let g2 = names
            .iter()
            .find(|n| n.ends_with(".mhl") && n.starts_with("0002_"))
            .expect("the generation-2 manifest (the append)");
        let g2 = g2.clone();
        assert_eq!(
            std::fs::read(ascmhl_dir.join(&g1)).unwrap(),
            g1_bytes,
            "the 0001 record is byte-preserved (the append-only re-run model)"
        );
        let chain = std::fs::read_to_string(ascmhl_dir.join("ascmhl_chain.xml")).unwrap();
        let recs = crate::ascmhl::read_chain(&chain).expect("the chain's records");
        assert_eq!(recs.len(), 2, "the chain appends the generation-2 record (two generations)");
        // The c4 set: the skipped files' c4 == the fresh-copy
        // run's c4 for the same content (the dest bytes are the
        // same — the skip never writes different bytes).
        let g2_root = crate::ascmhl::parse_lite(&std::fs::read_to_string(ascmhl_dir.join(&g2)).unwrap()).unwrap();
        assert_eq!(g1_c4, file_c4(&g2_root), "the file-hash c4 set is unchanged across generations (the skipped files' c4 == the fresh-copy c4)");
        // The ascmhl SILENT on success: the stderr surface (the
        // single source — the fan-out's line composer) carries no
        // ascmhl line; the records carry no ascmhl content (the
        // R-INV-A artifact proof).
        let core = offload_core_multi(&input_c, &[d.clone()], &clip_keys_of(&input)).unwrap();
        for line in fanout_stderr_lines(&core.reports) {
            assert!(!line.to_lowercase().contains("ascmhl"), "the stderr surface carries no ascmhl line: {line}");
        }
        for artifact in [
            d.join("in.offload-manifest.tsv"),
            d.join("A001_001/A001_001.offload-manifest.tsv"),
            d.join(crate::report::RUN_REPORT_NAME),
            d.join(crate::jobreport::MD_NAME),
            d.join(crate::jobreport::CSV_NAME),
            d.join(crate::jobreport::HTML_NAME),
        ] {
            let body = std::fs::read_to_string(&artifact).unwrap();
            assert!(!body.contains("ascmhl"), "no ascmhl content in {}", artifact.display());
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    // -----------------------------------------------------------------------
    // The atomic-copy seam (the interruption safety + the
    // convergent resume)
    // -----------------------------------------------------------------------


    #[test]
    fn offload_atomic_copy_clean() {
        // (a) the helper: the final bytes + mtime match, NO temp
        // remains.
        let base = std::env::temp_dir().join(format!("frameprism_offload_atomic_clean_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("out")).unwrap();
        let src = base.join("src.txt");
        std::fs::write(&src, b"the-atomic-payload").unwrap();
        let src_mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        {
            let f = std::fs::File::options().write(true).open(&src).unwrap();
            f.set_modified(src_mtime).unwrap();
        }
        let dst = base.join("out/dst.txt");
        copy_atomic(&src, &dst, src_mtime).unwrap();
        assert_eq!(
            std::fs::read(&dst).unwrap(),
            b"the-atomic-payload",
            "the final bytes match"
        );
        let m = std::fs::metadata(&dst).unwrap();
        assert_eq!(
            m.modified().unwrap(),
            src_mtime,
            "the mtime preserved on the final path (the temp-before-rename carry)"
        );
        let leftover: Vec<String> = std::fs::read_dir(base.join("out"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(leftover, vec!["dst.txt".to_string()], "NO temp remains: {leftover:?}");
        let _ = std::fs::remove_dir_all(&base);
    }


    #[test]
    fn offload_atomic_copy_failure_cleanup() {
        // (b) the helper with a failing src (a DIRECTORY as the src —
        // `fs::copy` errors deterministically): the temp deleted, the
        // final path ABSENT, the named error propagated.
        let base = std::env::temp_dir().join(format!("frameprism_offload_atomic_fail_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("srcdir")).unwrap();
        std::fs::create_dir_all(base.join("out")).unwrap();
        let err = copy_atomic(&base.join("srcdir"), &base.join("out/dst.txt"), std::time::UNIX_EPOCH).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("copy "), "the named context propagated: {msg}");
        assert!(!base.join("out/dst.txt").exists(), "the final path ABSENT (never partial)");
        let leftover: Vec<String> = std::fs::read_dir(base.join("out"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(leftover.is_empty(), "the failed copy deleted its own temp: {leftover:?}");
        let _ = std::fs::remove_dir_all(&base);
    }


    #[test]
    fn offload_atomic_copy_concurrent_refusal() {
        // (c) a pre-existing temp at the helper's tmp path → the
        // named refusal, the pre-existing temp BYTE-UNTOUCHED.
        let base = std::env::temp_dir().join(format!("frameprism_offload_atomic_conc_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("out")).unwrap();
        let src = base.join("src.txt");
        std::fs::write(&src, b"payload").unwrap();
        let dst = base.join("out/dst.txt");
        let tmp = offload_temp_path(&dst);
        std::fs::write(&tmp, b"concurrent-job-partial").unwrap();
        let tmp_before = std::fs::read(&tmp).unwrap();
        let err = copy_atomic(&src, &dst, std::time::UNIX_EPOCH).unwrap_err();
        let msg = format!("{err:#}");
        // The PINNED refusal wording (the named surface —
        // exact, with the tmp path interpolated).
        let pinned = format!(
            "the offload temp file {} already exists (a concurrent job writes this dest — run the offload jobs against a dest root sequentially)",
            tmp.display()
        );
        assert!(msg.contains(&pinned), "the pinned concurrent-job refusal wording: {msg}");
        assert!(!dst.exists(), "the final path absent (the refusal fires before any write)");
        assert_eq!(
            std::fs::read(&tmp).unwrap(),
            tmp_before,
            "the pre-existing temp BYTE-UNTOUCHED (never overwritten — fs::copy would truncate it)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


    #[test]
    fn offload_partial_final_converge() {
        // (e) a PARTIAL file (half the bytes) at the final dst path
        // (simulating the direct-write era's interruption residue) →
        // the offload re-copies + verifies, the row OK (the
        // convergence proof: the skip predicate's size check fails on
        // the partial → the copy path → the atomic overwrite).
        let (base, input, dest) = setup("partialconv");
        let input_c = std::fs::canonicalize(&input).unwrap();
        std::fs::create_dir_all(dest.join("A001_001")).unwrap();
        let full = std::fs::read(input.join("A001_001/f1.DNG")).unwrap();
        std::fs::write(dest.join("A001_001/f1.DNG"), &full[..full.len() / 2]).unwrap();
        let rc = run_offload_multi(&input_c, &[dest.clone()]).unwrap();
        assert_eq!(rc, ExitCode::SUCCESS, "the re-run converges rc=0 (the partial re-copied)");
        assert_eq!(
            std::fs::read(dest.join("A001_001/f1.DNG")).unwrap(),
            full,
            "the partial re-copied + verified, the row OK"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    // -----------------------------------------------------------------
    // The streaming fan-out (named tests c/d/e — a/b
    // in jxl.rs, f in audit.rs)
    // -----------------------------------------------------------------


    /// The fresh 3-dest fan-out's byte identity: a
    /// 2-file tree (a 1 MiB + 4096 B file — the pinned 1 MiB chunk
    /// buffer's MULTI-CHUNK path runs; the ">4 KiB" predates
    /// the pinned chunk size: the intent = a file spanning multiple
    /// chunks), the legacy positional form, 3 fresh dests. rc=0; every
    /// dest file BYTE-identical to the source; the per-clip manifest
    /// rows VALUE-identical (the row fields re-derived with the
    /// module's one-shot sha); the run report's `## copy` block EXACT
    /// + exactly one `created:` line + the VERIFIED verdict; NO temp
    /// residue; the dest mtimes preserved = the single-site
    /// invariant (the write reaches the
    /// final path ONLY via temp + rename — a direct final-path write
    /// would carry the run's mtime, never the source's). The
 /// clean-stderr byte-invariance rides the live gate (the
    /// in-process eprintln is the shared stderr).
    #[test]
    fn fanout_fresh_n_dest_byte_identity() {
        profile_override_a001();
        let base = std::env::temp_dir().join("frameprism_offload_fanout3_3dest");
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        std::fs::create_dir_all(input.join("A001_001")).unwrap();
        let big_n = 1024 * 1024 + 4096;
        let big = fanout_content(big_n);
        let small = b"frame-two-payload".to_vec();
        let t = fanout_mtime();
        for (name, bytes) in [("A001_001/f1.DNG", &big), ("A001_001/f2.DNG", &small)] {
            std::fs::write(input.join(name), bytes).unwrap();
            std::fs::File::options()
                .write(true)
                .open(input.join(name))
                .unwrap()
                .set_modified(t)
                .unwrap();
        }
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        let d3 = base.join("to3");
        let rc = run(&Args {
            input: Some(input_c.clone()),
            to: vec![d1.clone(), d2.clone(), d3.clone()],
            source: vec![],
            dest: vec![],
        });
        assert_eq!(rc, ExitCode::SUCCESS, "the fresh 3-dest fan-out = rc 0");
        let dc: Vec<PathBuf> = [d1, d2, d3]
            .iter()
            .map(|p| std::fs::canonicalize(p).unwrap())
            .collect();
        let src_sha_big = crate::jxl::sha256_hex(&big);
        let src_sha_small = crate::jxl::sha256_hex(&small);
        for d in &dc {
            assert_eq!(
                std::fs::read(d.join("A001_001/f1.DNG")).unwrap(),
                big,
                "the byte mirror f1: {d:?}"
            );
            assert_eq!(
                std::fs::read(d.join("A001_001/f2.DNG")).unwrap(),
                small,
                "the byte mirror f2: {d:?}"
            );
            // The single-site restatement: the dest mtime = the
            // source's — only temp + rename carries it (a direct
            // final-path write would set the run's mtime).
            for name in ["A001_001/f1.DNG", "A001_001/f2.DNG"] {
                assert_eq!(
                    std::fs::metadata(d.join(name)).unwrap().modified().unwrap(),
                    t,
                    "the dest mtime = the source's (temp + rename only): {d:?} {name}"
                );
            }
            // NO temp residue.
            for p in fanout_files(d) {
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                assert!(
                    !name.starts_with(STALE_TEMP_PREFIX),
                    "no temp residue: {p:?}"
                );
            }
            // The per-clip manifest rows VALUE-identical.
            let m = parse_manifest(&d.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
            assert_eq!(m.rows.len(), 2, "the manifest rows: {d:?}");
            assert_eq!(m.rows[0].0, "A001_001/f1.DNG");
            assert_eq!(m.rows[0].1, big_n as u64);
            assert_eq!(m.rows[0].2, src_sha_big, "the source sha column: {d:?}");
            assert_eq!(m.rows[0].3, src_sha_big, "the dest sha column: {d:?}");
            assert_eq!(m.rows[1].0, "A001_001/f2.DNG");
            assert_eq!(m.rows[1].1, small.len() as u64);
            assert_eq!(m.rows[1].2, src_sha_small);
            assert_eq!(m.rows[1].3, src_sha_small);
            // The run report: the EXACT `## copy` block + one
            // `created:` line + the VERIFIED verdict.
            let tr = read_report(d);
            assert_eq!(
                tr.lines().filter(|l| l.starts_with("created: ")).count(),
                1,
                "exactly one created: line: {tr}"
            );
            let tot = big_n as u64 + small.len() as u64;
            let copy = format!(
                "## copy\n\nclip\tfiles\tsource B\nA001_001\t2\t{tot}\ntotals: 2 file(s) — {tot} B"
            );
            assert!(tr.contains(&copy), "the exact ## copy block: {tr}");
            assert!(
                tr.contains("offload: VERIFIED 2/2 (dest"),
                "the VERIFIED verdict: {tr}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The failed dest, the others continue: one
    /// dest where the fan-out temp ALREADY EXISTS at the exact
    /// `offload_temp_path` (the deterministic equivalent of the
    /// "temp path cannot be created" fixture — the literal
    /// "dest parent is a file" is INFEASIBLE: the per-clip manifest
    /// is placed AT that same parent (the clip key = the file's full
    /// parent dir), so a broken parent fails the artifact write at
    /// the job level first — an rc + healthy-manifests contradiction
    /// of the pinned expectations. The pre-existing temp is
    /// computed by the test via the module's `job_id()` +
    /// `offload_temp_path` (same process = the same job id)) → the
    /// pinned concurrent-job refusal: the rows FAIL (named), the
    /// other dests complete OK, the run rc=1 (the dirty dest named),
    /// NO failed temp (the pre-existing sentinels stay
    /// BYTE-UNTOUCHED — the refusal never overwrites), the healthy
    /// dests' manifests written.
    #[test]
    fn fanout_failed_dest_others_continue() {
        profile_override_a001();
        let base = std::env::temp_dir().join("frameprism_offload_fanout3_faildest");
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        std::fs::create_dir_all(input.join("A001_001")).unwrap();
        let big = fanout_content(8 * 1024);
        let small = b"frame-two-payload".to_vec();
        let t = fanout_mtime();
        for (name, bytes) in [("A001_001/f1.DNG", &big), ("A001_001/f2.DNG", &small)] {
            std::fs::write(input.join(name), bytes).unwrap();
            std::fs::File::options()
                .write(true)
                .open(input.join(name))
                .unwrap()
                .set_modified(t)
                .unwrap();
        }
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d1 = base.join("to1");
        let d2 = base.join("to2");
        let d3 = base.join("to3");
        std::fs::create_dir_all(&d3).unwrap();
        std::fs::create_dir_all(d3.join("A001_001")).unwrap();
        let d3c = std::fs::canonicalize(&d3).unwrap();
        // The named concurrent job's IN-FLIGHT temps at d3: the
        // literal "temp path cannot be created" fixture (the
        // "dest parent is a file") is INFEASIBLE — the per-clip
        // manifest is placed AT that same parent (the clip key = the
        // file's full parent dir), so a broken parent fails the
        // artifact write at the job level first (an rc + healthy-
        // manifests contradiction of the pinned expectations),
        // and a bare pre-existing temp is NOT the hazard either —
        // the phase-0 stale cleanup collects it (the
        // convergence). The hazard = a CONCURRENT job's in-flight
        // temp: present on disk + registered in the in-flight
        // registry (the sibling-thread semantics — the phase-0
        // cleanup must NOT collect it; the fan-out's exists-check
        // then fires the pinned refusal). The registry + the exact
        // temp paths are computed by the test via the module's
        // `job_id()` + `offload_temp_path` (same process = the same
        // job id). → the rows FAIL (named), the other dests complete
        // OK, the run rc=1 (the dirty dest named), NO failed temp
        // (the sentinels stay BYTE-UNTOUCHED — the refusal never
        // overwrites), the healthy dests' manifests written.
        let sentinel = b"concurrent-job-sentinel";
        let mut sentinels = Vec::new();
        for name in ["A001_001/f1.DNG", "A001_001/f2.DNG"] {
            let tmp = offload_temp_path(&d3c.join(name));
            std::fs::write(&tmp, sentinel).unwrap();
            sentinels.push(tmp);
        }
        let _g1 = ActiveTempGuard::register(sentinels[0].clone());
        let _g2 = ActiveTempGuard::register(sentinels[1].clone());
        let rc = run(&Args {
            input: Some(input_c.clone()),
            to: vec![d1.clone(), d2.clone(), d3.clone()],
            source: vec![],
            dest: vec![],
        });
        assert_eq!(rc, ExitCode::from(1), "the named dirty dest = rc 1");
        let d1c = std::fs::canonicalize(&d1).unwrap();
        let d2c = std::fs::canonicalize(&d2).unwrap();
        // The healthy dests complete OK (bytes + the manifests).
        for d in [&d1c, &d2c] {
            assert_eq!(std::fs::read(d.join("A001_001/f1.DNG")).unwrap(), big, "healthy dest: {d:?}");
            assert_eq!(std::fs::read(d.join("A001_001/f2.DNG")).unwrap(), small);
            let mtext = std::fs::read_to_string(d.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
            assert!(mtext.contains("verdict: VERIFIED 2/2"), "the healthy manifest: {d:?}\n{mtext}");
            for p in fanout_files(d) {
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                assert!(!name.starts_with(STALE_TEMP_PREFIX), "no residue: {p:?}");
            }
        }
        // The dirty dest's named FAIL lines (the pinned refusal
        // wording) + the REFUSE manifest verdict.
        let tr3 = read_report(&d3c);
        for name in ["A001_001/f1.DNG", "A001_001/f2.DNG"] {
            assert!(
                tr3.contains(&format!("FAIL COPY_FAIL clip=A001_001: {name}: the offload temp file")),
                "the named FAIL line: {name}\n{tr3}"
            );
        }
        assert!(
            tr3.contains("already exists (a concurrent job writes this dest — run the offload jobs against a dest root sequentially)"),
            "the pinned refusal wording: {tr3}"
        );
        let m3text = std::fs::read_to_string(d3c.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
        assert!(m3text.contains("verdict: REFUSE 2 named row(s)"), "the REFUSE manifest: {m3text}");
        // The sentinels stay BYTE-UNTOUCHED (the refusal never
        // overwrites) — and are the ONLY stale-named files at d3
        // (no failed temp litter of this run).
        for tmp in &sentinels {
            assert_eq!(std::fs::read(tmp).unwrap(), sentinel, "untouched sentinel: {tmp:?}");
        }
        let stale: Vec<_> = fanout_files(&d3c)
            .into_iter()
            .filter(|p| p.file_name().and_then(|s| s.to_str()).unwrap_or("").starts_with(STALE_TEMP_PREFIX))
            .collect();
        assert_eq!(stale.len(), 2, "only the pre-existing sentinels at d3: {stale:?}");
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The skip semantics, streaming, frozen: the
    /// re-run on the identical dest = the skip surface
    /// byte-frozen through the streaming conversion: the `## skipped`
    /// section + the pinned totals line, the CSV `skipped` column =
    /// 1, the dest mtimes UNTOUCHED (the verify-only skip — no write
    /// at all), and NO `._frameprism-offload-*` temp ever created at
    /// the dest (asserted by the dest listing after the run — the
    /// conservative path creates no temp for a skipped file). The
    /// first run (the fresh fan-out) carries NO `## skipped` section
    /// (the zero-skip shape stays byte-frozen).
    #[test]
    fn skip_semantics_streaming_frozen() {
        profile_override_a001();
        let base = std::env::temp_dir().join("frameprism_offload_fanout3_skip");
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        std::fs::create_dir_all(input.join("A001_001")).unwrap();
        let big = fanout_content(1024 * 1024 + 1);
        let small = b"frame-two-payload".to_vec();
        let t = fanout_mtime();
        for (name, bytes) in [("A001_001/f1.DNG", &big), ("A001_001/f2.DNG", &small)] {
            std::fs::write(input.join(name), bytes).unwrap();
            std::fs::File::options()
                .write(true)
                .open(input.join(name))
                .unwrap()
                .set_modified(t)
                .unwrap();
        }
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d1 = base.join("to1");
        let args = || Args {
            input: Some(input_c.clone()),
            to: vec![d1.clone()],
            source: vec![],
            dest: vec![],
        };
        // Run 1 — the fresh fan-out (NO `## skipped` section — the
 // zero-skip shape's byte-invariance).
        let rc1 = run(&args());
        assert_eq!(rc1, ExitCode::SUCCESS, "the fresh run = rc 0");
        let d1c = std::fs::canonicalize(&d1).unwrap();
        let tr1 = read_report(&d1c);
        assert!(!tr1.contains("## skipped"), "the zero-skip run: the section absent: {tr1}");
        let mtime_of = |name: &str| std::fs::metadata(d1c.join(name)).unwrap().modified().unwrap();
        let mt1 = mtime_of("A001_001/f1.DNG");
        let mt2 = mtime_of("A001_001/f2.DNG");
        // Run 2 — the identical re-run (the skip path).
        let rc2 = run(&args());
        assert_eq!(rc2, ExitCode::SUCCESS, "the skip re-run = rc 0");
        let tr2 = read_report(&d1c);
        let clip = crate::worker::display_clip("A001_001");
        let skipped = format!(
            "\n## skipped\n\nclip\tfiles\tskipped\n{clip}\t2\t2\ntotals: 2 file(s) skipped (already present, sha256-verified — not re-copied)"
        );
        assert!(tr2.contains(&skipped), "the pinned ## skipped section: {tr2}");
        // The CSV `skipped` column = 1 (every row).
        let csv = std::fs::read_to_string(d1c.join(crate::jobreport::CSV_NAME)).unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "clip,file,size_bytes,source_sha256,dest_sha256,verdict,skipped,copied_ms",
            "the CSV header pin: {lines:?}"
        );
        assert_eq!(lines.len(), 3, "the 2 data rows: {lines:?}");
        for l in &lines[1..] {
            assert_eq!(l.split(',').nth(6).unwrap(), "1", "the CSV skipped column: {l}");
        }
        // The dest mtimes UNTOUCHED (the verify-only skip — no write).
        assert_eq!(mtime_of("A001_001/f1.DNG"), mt1, "mtime untouched f1");
        assert_eq!(mtime_of("A001_001/f2.DNG"), mt2, "mtime untouched f2");
        // NO temp ever created at the dest (the listing after the run).
        for p in fanout_files(&d1c) {
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            assert!(!name.starts_with(STALE_TEMP_PREFIX), "no temp at the dest: {p:?}");
        }
        // The bytes still identical (the skip verified, not re-copied).
        assert_eq!(std::fs::read(d1c.join("A001_001/f1.DNG")).unwrap(), big);
        assert_eq!(std::fs::read(d1c.join("A001_001/f2.DNG")).unwrap(), small);
        let _ = std::fs::remove_dir_all(&base);
    }


    /// The structural source pin (the
    /// single-site-pin idiom, the deterministic no-env form): the
    /// `include_str!` of the four seam files; the fn-slice extraction
    /// (from the fn signature to the next column-0 `fn ` line) — the
    /// pin is the ORDERING (the sync sits in the error-propagating
    /// path BEFORE the rename / immediately after the write), not a
    /// parse. (a) `copy_atomic`: `sync_all` before the fn's first
    /// `std::fs::rename`; (b) `fanout_source`: the per-dest
    /// `sync_all` (the named context on the open handle) before that
    /// fn's `rename`; (c) `write_offload_manifest`: the
    /// `sync_file(&tmp, ...)` after the write, before the rename;
    /// (d) the run-report / job-report / ascmhl writer fns: the
    /// `sync_file` call after each `fs::write` (the ordering in the
    /// fn slice); (e) the exact note wordings (the pinned prefix +
    /// suffix); (f) the exact sync-error suffix. (The split note:
    /// the offload seam surface moved to the part files — the include
    /// targets are the part files; the anchors are unchanged.) (The
    /// split note: the audit restore seam's include target moved to
    /// the part file that receives `run_restore`
    /// (`audit/entries.rs`) — the signature-to-EOF anchors are
    /// unchanged.)
    #[test]
    fn offload_durability_seams_pinned() {
        let transfer = include_str!("transfer.rs");
        let manifests = include_str!("manifests.rs");
        let report = include_str!("report.rs");
        let ascmhl = include_str!("../ascmhl.rs");
        let jobreport = include_str!("../jobreport.rs");
        let durability = include_str!("../durability.rs");

        // The fn slice: from the fn signature line to (not incl.)
        // the next column-0 fn-definition line (the `fn ` / `pub fn
        // ` / `pub(crate) fn ` forms — the ordering pin, not a
        // parse). Nested fn bodies are indented — never column 0.
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
            panic!("no next column-0 fn-definition line after {sig:?}")
        }

        // (a) copy_atomic: the sync_all BEFORE the fn's first
        // std::fs::rename (the sync rides the copy's
        // error-propagating path).
        let copy_atomic = slice_fn(transfer, "fn copy_atomic(");
        let i_sync = copy_atomic
            .find("sync_all")
            .expect("copy_atomic carries the sync_all seam");
        let i_rename = copy_atomic
            .find("std::fs::rename")
            .expect("copy_atomic's std::fs::rename");
        assert!(
            i_sync < i_rename,
            "the sync_all sits BEFORE the rename in copy_atomic"
        );

        // (b) fanout_source: the per-dest sync_all (the named
        // context on the still-open handle) BEFORE that fn's
        // rename.
        let fanout = slice_fn(transfer, "fn fanout_source(");
        let i_sync_ctx = fanout
            .find("sync the offload fan-out temp for")
            .expect("fanout_source carries the per-dest sync's named context");
        let i_sync = fanout
            .find("sync_all")
            .expect("fanout_source carries the per-dest sync_all");
        let i_rename = fanout
            .find("std::fs::rename")
            .expect("fanout_source's std::fs::rename");
        assert!(
            i_sync < i_rename && i_sync_ctx < i_rename,
            "the per-dest sync_all sits BEFORE the rename in fanout_source"
        );

        // (c) write_offload_manifest: the write < sync_file(&tmp) <
        // the rename (the ordering in the fn slice).
        let manifest = slice_fn(manifests, "fn write_offload_manifest(");
        let i_write = manifest
            .find("std::fs::write(&tmp, tsv)")
            .expect("the manifest's fs::write");
        let i_sync = manifest
            .find("sync_file(&tmp, \"offload manifest\")")
            .expect("the manifest's sync_file(&tmp)");
        let i_rename = manifest
            .find("std::fs::rename")
            .expect("the manifest's rename");
        assert!(
            i_write < i_sync && i_sync < i_rename,
            "the manifest's sync_file sits after the write + before the rename"
        );

        // (d) the run-report writers (BOTH shapes: the
        // write_offload_run_reports_at loop + the multi-shape's
        // per-dest write in run_offload_multi_sources): the
        // sync_file after each fs::write (the ordering in the fn
        // slice).
        let run_reports = slice_fn(report, "fn write_offload_run_reports_at(");
        let i_write = run_reports
            .find("std::fs::write(&path, &md)")
            .expect("the run report's fs::write");
        let i_sync = run_reports
            .find("sync_file(&path, \"offload run report\")")
            .expect("the run report's sync_file");
        assert!(
            i_write < i_sync,
            "the run report's sync_file sits after its fs::write"
        );
        let multi_sources = slice_fn(report, "fn run_offload_multi_sources(");
        let i_write = multi_sources
            .find("std::fs::write(&path, &run_md)")
            .expect("the multi-shape run report's fs::write");
        let i_sync = multi_sources
            .find("sync_file(&path, \"offload run report\")")
            .expect("the multi-shape run report's sync_file");
        assert!(
            i_write < i_sync,
            "the multi-shape run report's sync_file sits after its fs::write"
        );

        // (d) the job-report writers (legacy `write` + `write_multi`):
        // the sync_file after each fs::write.
        let jr_write = slice_fn(jobreport, "pub fn write(dest_root: &Path");
        let i_write = jr_write
            .find("std::fs::write(&path, body)")
            .expect("the job report's fs::write");
        let i_sync = jr_write
            .find("sync_file(&path, \"job report file\")")
            .expect("the job report's sync_file");
        assert!(
            i_write < i_sync,
            "the job report's sync_file sits after its fs::write"
        );
        let jr_write_multi = slice_fn(jobreport, "pub fn write_multi(dest_root: &Path");
        let i_write = jr_write_multi
            .find("std::fs::write(&path, body)")
            .expect("the multi job report's fs::write");
        let i_sync = jr_write_multi
            .find("sync_file(&path, \"job report file\")")
            .expect("the multi job report's sync_file");
        assert!(
            i_write < i_sync,
            "the multi job report's sync_file sits after its fs::write"
        );

        // (d) the ascmhl writer (write_history): the sync_file after
        // the manifest write + after the chain write; the dir sync
        // after the chain sync.
        let wh = slice_fn(ascmhl, "pub fn write_history(");
        let i_mwrite = wh
            .find("std::fs::write(&manifest_path, xml.as_bytes())")
            .expect("the ascmhl manifest's fs::write");
        let i_msync = wh
            .find("sync_file(&manifest_path, \"ascmhl manifest\")")
            .expect("the ascmhl manifest's sync_file");
        let i_cwrite = wh
            .find("std::fs::write(&chain_path, chain.as_bytes())")
            .expect("the ascmhl chain's fs::write");
        let i_csync = wh
            .find("sync_file(&chain_path, \"ascmhl chain\")")
            .expect("the ascmhl chain's sync_file");
        let i_dir = wh
            .find("sync_dir_best_effort(&ascmhl_dir)")
            .expect("the ascmhl dir's best-effort sync");
        assert!(
            i_mwrite < i_msync
                && i_msync < i_cwrite
                && i_cwrite < i_csync
                && i_csync < i_dir,
            "the ascmhl writer's sync ordering: manifest write < manifest sync < chain write < chain sync < dir sync"
        );

        // (e) the exact note wordings (the pinned prefix +
        // suffix) + (f) the exact sync-error suffix.
        assert!(
            durability.contains("note: the offload durability dir sync on"),
            "the pinned note prefix is in durability.rs"
        );
        assert!(
            durability.contains("— the content copy stands"),
            "the pinned note suffix is in durability.rs"
        );
        assert!(
            durability.contains("(durability — the bytes may not have reached stable storage)"),
            "the pinned sync-error suffix is in durability.rs"
        );

        // (g) the audit restore seam
        // (run_restore): the sync_all BEFORE the seam's rename (the
        // exact-string search: the fn's EARLIER rename is the
        // .pre-restore backup MOVE — `rename(target, &pre)`, the
        // reversed args — a metadata move of the existing target, no
        // bytes written, out of the sync class; the seam's rename is
        // `rename(&tmp, target)`, unique in the slice). The slice is
        // signature-to-EOF (not `slice_fn`): `run_restore` is the
        // LAST column-0 fn in entries.rs (the part's test module's fns are
        // indented), so `slice_fn`'s next-fn terminator is absent;
        // the search strings are unique in the suffix (the test
        // module carries neither at the base).
        let audit = include_str!("../audit/entries.rs");
        let i_sig = audit
            .find("pub fn run_restore(")
            .expect("the run_restore signature");
        let restore = &audit[i_sig..];
        let i_sync = restore
            .find("dst.sync_all()")
            .expect("the restore seam carries the sync_all");
        let i_rename = restore
            .find("std::fs::rename(&tmp, target)")
            .expect("the restore seam's std::fs::rename");
        assert!(
            i_sync < i_rename,
            "the restore seam's sync_all sits BEFORE its rename"
        );

        // (h) the repair manifest seam
        // (rewrite_manifest): the write_all < sync_all < rename
        // ordering in the fn slice (the explicit-File
        // shape; the lstat guard sits above the seam and carries
        // no write/sync/rename string).
        let repair = include_str!("../repair.rs");
        let rmanifest = slice_fn(repair, "pub fn rewrite_manifest(");
        let i_write = rmanifest
            .find("write_all(tsv.as_bytes())")
            .expect("the repair manifest's write_all");
        let i_sync = rmanifest
            .find(".sync_all()")
            .expect("the repair manifest's sync_all");
        let i_rename = rmanifest
            .find("std::fs::rename(&tmp, original)")
            .expect("the repair manifest's rename");
        assert!(
            i_write < i_sync && i_sync < i_rename,
            "the repair manifest's write_all < sync_all < rename"
        );
    }


    /// The functional R-INV (the
    /// `fanout_fresh_n_dest_byte_identity` pattern, lean): the
    /// 1-dest legacy form over a 2-file tree (a 1 MiB + 4096 B file —
    /// the multi-chunk fan-out path — + a small file). rc=0; every
    /// dest file BYTE-identical to the source; the dest mtimes = the
    /// source's (the temp+rename carry — the write still reaches the
    /// final path only via temp + rename); NO temp residue; the
    /// per-clip manifest rows VALUE-identical (the pinned row
    /// fields); the run report's `## copy` block + exactly one
    /// `created:` line + the EXACT `offload: VERIFIED 2/2 (dest ...)`
    /// verdict line. THEN the re-run on the identical dest: rc=0, the
    /// `## skipped` section + the pinned totals line (the surface
    /// intact through the durability seam), the dest mtimes
    /// UNTOUCHED (the verify-only skip). The clean-stderr
 /// byte-invariance rides the live gate (the in-process eprintln is
    /// the shared stderr).
    #[test]
    fn offload_durability_clean_run_frozen() {
        profile_override_a001();
        let base = std::env::temp_dir().join("frameprism_offload_durability_frozen");
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        std::fs::create_dir_all(input.join("A001_001")).unwrap();
        let big_n = 1024 * 1024 + 4096;
        let big = fanout_content(big_n);
        let small = b"frame-two-payload".to_vec();
        let t = fanout_mtime();
        for (name, bytes) in [("A001_001/f1.DNG", &big), ("A001_001/f2.DNG", &small)] {
            std::fs::write(input.join(name), bytes).unwrap();
            std::fs::File::options()
                .write(true)
                .open(input.join(name))
                .unwrap()
                .set_modified(t)
                .unwrap();
        }
        let input_c = std::fs::canonicalize(&input).unwrap();
        let d = base.join("to");
        let rc = run(&Args {
            input: Some(input_c.clone()),
            to: vec![d.clone()],
            source: vec![],
            dest: vec![],
        });
        assert_eq!(
            rc,
            ExitCode::SUCCESS,
            "the 1-dest legacy run = rc 0 (the durability seam is invisible on the clean path)"
        );
        let dc = std::fs::canonicalize(&d).unwrap();
        // Every dest file BYTE-identical to the source.
        assert_eq!(std::fs::read(dc.join("A001_001/f1.DNG")).unwrap(), big, "the byte mirror f1");
        assert_eq!(
            std::fs::read(dc.join("A001_001/f2.DNG")).unwrap(),
            small,
            "the byte mirror f2"
        );
        // The dest mtimes = the source's (the temp+rename carry — a
        // direct final-path write would carry the run's mtime).
        for name in ["A001_001/f1.DNG", "A001_001/f2.DNG"] {
            assert_eq!(
                std::fs::metadata(dc.join(name)).unwrap().modified().unwrap(),
                t,
                "the dest mtime = the source's (temp + rename only): {name}"
            );
        }
        // NO temp residue.
        for p in fanout_files(&dc) {
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            assert!(
                !name.starts_with(STALE_TEMP_PREFIX),
                "no temp residue: {p:?}"
            );
        }
        // The per-clip manifest rows VALUE-identical (the pinned row
        // fields — the re-derived source shas).
        let src_sha_big = crate::jxl::sha256_hex(&big);
        let src_sha_small = crate::jxl::sha256_hex(&small);
        let m = parse_manifest(&dc.join("A001_001/A001_001.offload-manifest.tsv")).unwrap();
        assert_eq!(m.rows.len(), 2, "the manifest rows");
        assert_eq!(m.rows[0].0, "A001_001/f1.DNG");
        assert_eq!(m.rows[0].1, big_n as u64);
        assert_eq!(m.rows[0].2, src_sha_big, "the source sha column");
        assert_eq!(m.rows[0].3, src_sha_big, "the dest sha column");
        assert_eq!(m.rows[1].0, "A001_001/f2.DNG");
        assert_eq!(m.rows[1].1, small.len() as u64);
        assert_eq!(m.rows[1].2, src_sha_small);
        assert_eq!(m.rows[1].3, src_sha_small);
        // The run report: the EXACT `## copy` block + exactly one
        // `created:` line + the EXACT `offload: VERIFIED 2/2 (dest
        // ...)` verdict line.
        let tr = read_report(&dc);
        assert_eq!(
            tr.lines().filter(|l| l.starts_with("created: ")).count(),
            1,
            "exactly one created: line: {tr}"
        );
        let tot = big_n as u64 + small.len() as u64;
        let copy = format!(
            "## copy\n\nclip\tfiles\tsource B\nA001_001\t2\t{tot}\ntotals: 2 file(s) — {tot} B"
        );
        assert!(tr.contains(&copy), "the exact ## copy block: {tr}");
        assert!(
            tr.contains(&format!("offload: VERIFIED 2/2 (dest {})\n", dc.display())),
            "the EXACT VERIFIED verdict line: {tr}"
        );
        // THE RE-RUN on the identical dest: rc=0, the `## skipped`
        // section + the pinned totals line (the surface intact
        // through the durability seam), the dest mtimes UNTOUCHED
        // (the verify-only skip — the seam adds no write).
        let pre_f1 = std::fs::metadata(dc.join("A001_001/f1.DNG")).unwrap().modified().unwrap();
        let pre_f2 = std::fs::metadata(dc.join("A001_001/f2.DNG")).unwrap().modified().unwrap();
        let rc2 = run(&Args {
            input: Some(input_c.clone()),
            to: vec![d.clone()],
            source: vec![],
            dest: vec![],
        });
        assert_eq!(rc2, ExitCode::SUCCESS, "the skip re-run = rc 0");
        let tr2 = read_report(&dc);
        assert!(
            tr2.contains(
                "## skipped\n\nclip\tfiles\tskipped\nA001_001\t2\t2\ntotals: 2 file(s) skipped (already present, sha256-verified — not re-copied)\n"
            ),
            "the pinned `## skipped` section (the EXACT bytes):\n{tr2}"
        );
        assert!(
            tr2.contains(&format!("offload: VERIFIED 2/2 (dest {})\n", dc.display())),
            "the VERIFIED verdict stands on the re-run: {tr2}"
        );
        assert_eq!(
            std::fs::metadata(dc.join("A001_001/f1.DNG")).unwrap().modified().unwrap(),
            pre_f1,
            "the dest mtime untouched (the verify-only skip)"
        );
        assert_eq!(
            std::fs::metadata(dc.join("A001_001/f2.DNG")).unwrap().modified().unwrap(),
            pre_f2,
            "the dest mtime untouched (the verify-only skip)"
        );
        // NO temp residue after the re-run either.
        for p in fanout_files(&dc) {
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            assert!(
                !name.starts_with(STALE_TEMP_PREFIX),
                "no temp residue after the re-run: {p:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

}
