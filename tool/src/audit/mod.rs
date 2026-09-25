//! `frameprism audit` / `frameprism restore` (the audit/restore arc).
//!
//! The encoders are deterministic (the 2304-file byte-identity gates),
//! so "one file corrupted → check the master → fix" = re-verify
//! against the sidecar, and repair = swap in the master's bytes after
//! they pass the SAME sidecar row.
//!
//! `frameprism audit <input> [--jobs N]` — the fast integrity pass
//! (FILE-LEVEL, NO DECODE — `--verify` stays the decode round-trip):
//!
//! - Sidecar discovery by GLOB in `<input>` (top level): every
//!   `*.jxl-checksums.tsv` (the JXL sidecar) and every other
//!   `*.checksums.tsv` (the J92 sidecar); zero sidecars → rc=2 (the
//!   record-only carve-outs: a dir carrying an ingest or offload
//!   record — the named notes, the bullets below).
//! - Bake-manifest discovery (the sealed-tier audit surface): every
//!   `*.bake-manifest.tsv` in `<input>` is audited too — the per-clip
//!   archive part(s) (the manifest's `archive:` field when present,
//!   else the single derived `<clip>.<container>` archive) are listed
//!   in-process (the `tar -tf` parity — the member map takes what the
//!   archive lists), every row's member is streamed in-process (the
//!   `tar -xO` parity — no scratch), and size + sha256 are recomputed
//!   against the row. The container read accepts BOTH the in-process-
//!   written containers and the legacy system-tar containers (the
//!   format is sniffed from the zstd frame magic — the bsdtar
//!   auto-decompress parity).
//!   A dir with no sidecar of ANY kind still fails rc=2 (the
//!   no-sidecar message, unchanged). `restore` does NOT audit bake
//!   manifests (the repair semantics are loose-file — a bake-only dir
//!   is the unchanged no-sidecar rc=2).
//! - J92 v2 rows: `file\tsize\tcrc32c\tsha256`. A 3-column row is a
//!   HARD rc=2 — regenerate with `--checksums` on a fresh encode;
//!   never a silent downgrade.
//! - JXL rows: `file\tsize\tsha256\tcrc32c\tplane\t…` (the first five
//!   columns are used; the JXL sha256 column is index 2, the J92 v2
//!   one is index 3 — per-format parsing, never positional guesses).
//! - Per row: recompute size + sha256 + crc32c (where the column
//!   exists) of `<input>/<file>`; the first mismatch is the named
//!   problem. Output: one `FAIL <file> — <problem>` line per offender +
//!   `audit: N/M file(s) OK (<sidecar>)` per sidecar. rc=0 clean,
//!   rc=1 offenders, rc=2 usage.
//! - Ingest-continuity surface: every `*.ingest-manifest.tsv` record
//!   in `<input>` (the ingest safety gate's recorded verdict — written
//!   by the worker's ingest pass, see `worker::write_ingest_manifest`)
//!   is audited too: the recorded verdict is printed (per-clip rows),
//!   and the SAME gate is re-derived via `worker::ingest_gate` from
//!   the .DNG frames present in `<input>` (the encoded outputs carry
//!   tag 51043 verbatim — the surgery's metadata-preserved gate
//!   guarantees it). A re-derived FAIL or a recorded-vs-re-derived
//!   disagreement = named FAIL lines (rc=1, the existing convention);
//!   no DNGs present = the recorded verdict + the named note (re-
//!   derivation not run). A dir with an ingest manifest but NO
//!   archive sidecar of any kind is audited for the ingest record
//!   only (the named note, rc from the re-derivation). `restore` does
//!   NOT audit ingest manifests (its repair semantics are loose-file
//!   — a manifest-only dir is the unchanged no-sidecar rc=2).
//! - Offload re-verify surface: a dir carrying
//!   `*.offload-manifest.tsv` records (top level AND the one-level
//!   clip roots — the standalone `offload` mirror's shape) but NO
//!   archive sidecar of any kind is audited for the offload records
//!   only (the named note — the ingest-record carve-out's exact
//!   shape, the offload phrasing). Every row of every record is
//!   re-verified against the recorded size + the canonical source
//!   sha256 (the `offload::reverify` primitive — the dest bytes as
//!   they sit NOW; its line formats are the contract, verbatim).
//!   rc=0 every row clean, rc=1 any dirty row (ALL records swept —
//!   never stops at the first offender — every dirty row named, the
//!   surface verdict line carries the count), rc=2 the usage
//!   contract (a bad record = the named hard refusal). `restore` does
//!   NOT audit offload manifests (the mirror's repair primitive = the
//!   offload re-run — idempotent + re-verified).
//! - MHL re-verify surface: a dir carrying the `ascmhl/` history dir
//!   (the `ascmhl` module's write-side placement — the scope's top
//!   level) is re-verified against its LATEST manifest (the
//!   `ascmhl_chain.xml`'s last record — every record's c4 verified
//!   against its manifest's bytes; NO chain: exactly one `.mhl` = that
//!   one; ≥2 manifests without a chain = the named ambiguity refusal;
//!   a chain record at a missing / mismatched manifest = the named
//!   corrupt-record refusal — the record is untrustable, rc=2, the B5
//!   posture). The re-verify: every recorded file is re-read + its
//!   C4ID (SHA-512 base58 — the format's one algorithm) is recomputed
//!   against the recorded c4 (the size pre-filter; the row vocabulary
//!   `OK` / `MISSING` / `SIZE_MISMATCH` / `C4_MISMATCH`, the offload
//!   row convention) + the roothash (the content + structure over the
//!   WHOLE scope with the MANIFEST'S OWN ignore patterns — the import
//!   fact: a foreign tool's conformant v2.0 hashlist verifies against
//!   its own values; the namespace + version check is the conformant
//!   refusal). An unrecorded ADDED file keeps the file sweep clean
//!   and breaks the roothash (the seal check). rc=0 every row clean +
//!   the roothash match (the summary line names the latest manifest);
//!   rc=1 any offender (every dirty row named + the roothash verdict
//!   named — `OK` / `MISMATCH: content` / `MISMATCH: structure` /
//!   `MISMATCH: both`); rc=2 the malformed record (the parse + the
//!   selection's corrupt classes). A dir WITHOUT `ascmhl/` audits
//!   byte-identical to pre-existing (the arm is inert). A dir with
//!   `ascmhl/` but NO sidecar of any kind is audited for the MHL
//!   record only (the named note — the offload-carve-out's exact
//!   shape: `note: no archive sidecar in <dir> — auditing the MHL
//!   re-verify record only`). The re-verify is PATH-INDEPENDENT: the
//!   rows are scope-relative + the manifest sits at the scope root —
//!   a MOVE of the whole tree keeps it verifiable.
//!
//! `frameprism restore <input> --from <master> [--frame N] [--jobs N]
//! [--force]` — repair the offenders from a pristine master clip dir:
//!
//! - The arbiter is `<input>`'s sidecar, never the master's. Per
//!   offender (sorted sidecar order): the master candidate
//!   (`<master>/<file column>`) must itself pass the sidecar row (size
//!   + sha256) or it is refused named — a corrupt master is never
//!   swapped in. Swap = rename the corrupt original to
//!   `<file>.pre-restore` (evidence kept) + write the candidate bytes
//!   to `<file>.restore-tmp` + rename over the target (atomic; the
//!   master is never modified).
//! - `--frame N` (1-based over the sorted distinct frame stems = the
//!   decode convention) restricts the offender set to one frame's
//!   files (j92: one row per frame; jxl: the 4 plane rows sharing the
//!   stem).
//! - The FINAL full audit pass over `<input>` must be clean. rc=0 all
//!   restored + final audit clean, rc=1 any unrestorable (each named)
//!   or the final audit not clean, rc=2 usage.
//!
//! The safety seams (pinned): the restore swap is root-boundary-
//! guarded (`offload::check_root_bound` sits BEFORE the swap's write)
//! + filesystem-synchronized BEFORE the seam's rename (the durability
//! seam). A COMPLETED audit appends the ops-
//! ledger row (command=audit, verdict OK/FAIL — the rotation report's
//! input); the usage-class rc=2s append nothing (no run completed).
//!
//! The part layout (the four named conceptual parts — each a `pub mod`
//! below; the cross-module surface is re-exported at this root, so the
//! external `crate::audit::` paths are unchanged): the arg + row/report
//! model (`model`) · the sidecar integrity engine (`sidecars`) · the
//! record audit — the ingest + offload record surfaces (`records`) ·
//! the run entry points — the `run_audit` / `run_restore` dispatch
//! targets (`entries`). The shared test helpers (the cfg(test) surface)
//! ride in `testutil`.

pub mod entries;
pub mod model;
pub mod records;
pub mod sidecars;

#[cfg(test)]
pub(crate) mod testutil;

pub use self::entries::{run_audit, run_restore};
pub use self::model::{AuditArgs, RestoreArgs};
pub use self::records::{
    IngestAuditResult, OffloadAuditResult, audit_ingest_manifests,
    audit_offload_manifests,
};
