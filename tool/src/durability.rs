//! The durability seam: the filesystem
//! synchronization of the offload's write paths. The read-after-write
//! hash proves the bytes are readable THROUGH the filesystem at that
//! moment — not that they reached stable storage: on a drive/card with
//! a volatile write cache, a file whose page-cache bytes never flush
//! is still "sha-verified". This module makes the filesystem
//! synchronization part of the write contract.
//!
//! What the seam guarantees: every file the offload job writes is
//! filesystem-synchronized (`sync_all` — the process's write buffer
//! pushed to the filesystem) BEFORE it stands at its final path — the
//! media: the sync sits in the copy's error-propagating path BEFORE
//! the atomic rename (the atomic-copy seam's `io::copy` closure; the
//! fan-out's per-dest open handle); the records: the mandatory
//! `sync_file` in the writer's named hard-error band — + a
//! BEST-EFFORT directory sync after the successful rename / record
//! write (`sync_dir_best_effort` — the rename's dir-entry update is
//! the thing a crash can lose; its failure is the pinned note, the
//! content copy stands — the mtime-note precedent).
//!
//! What the seam does NOT claim: physical durability. The drive/card
//! write-cache behavior is platform-specific — a volatile cache can
//! still drop bytes the filesystem has not been asked to flush, and
//! `sync_all` reaches the filesystem, not necessarily the platter.
//! The tool's guarantee stops at the filesystem synchronization. A
//! sync failure is a NAMED error, never a silent durability claim:
//! the media seams fail the dest row via the existing failure
//! machinery (the row FAILs — the sweep continues); the record
//! writers fail the job via their existing named hard-error bands.
//!
//! std-only (no new crates — the std-only posture).

use std::path::Path;

use anyhow::{Context, Result};

/// The MANDATORY file sync (the media seams + the record writers):
/// open the file + `sync_all` — the bytes the tool wrote are pushed
/// to the filesystem before the file stands at its final path (media:
/// BEFORE the rename; records: in the writer's named hard-error band
/// — a failure propagates as the named error, the job fails exactly
/// as a write failure does). `what` = the named record/file class the
/// error line carries.
pub(crate) fn sync_file(path: &Path, what: &str) -> Result<()> {
    std::fs::File::open(path)
        .and_then(|f| f.sync_all())
        .with_context(|| {
            format!(
                "sync the {what} {} (durability — the bytes may not have reached stable storage)",
                path.display()
            )
        })
}

/// The BEST-EFFORT directory sync (both media seams after the
/// successful rename + the record writers): open the dir + `sync_all`
/// — the rename's dir-entry update is the thing a crash can lose. On
/// failure: the pinned note (the mtime-note precedent — best-effort +
/// named note, the content copy stands) — NEVER an Err: the dir sync
/// is a durability improvement, not a correctness gate.
pub(crate) fn sync_dir_best_effort(dir: &Path) {
    if let Err(err) = std::fs::File::open(dir).and_then(|f| f.sync_all()) {
        eprintln!(
            "note: the offload durability dir sync on {} failed ({err}) — the content copy stands",
            dir.display()
        );
    }
}
