//! frameprism library: the DNG/TIFF parse, packing, encode, surgery, verify
//! and worker modules. The binary (`src/main.rs`) is the CLI; the
//! cargo-fuzz target (`fuzz/fuzz_targets/tiff_parse.rs`) exercises
//! `frameprism::tiff::{read, read_meta}` directly.

// The FFI surface (ljpeg_ffi, codec) is hand-written: reject any
// non-C-representable type (Rust enums, arrays by value, ...) in an
// `extern "C"` signature at compile time — a typo that would otherwise be
// silent ABI UB .
#![deny(improper_ctypes)]

/// The ASC MHL media-hash-list history (the
/// industry provenance standard's manifest, the `urn:ASC:MHL:v2.0`
/// lineage — the "v2.0 of the industry provenance standard"): the
/// WRITING side — at EVERY standalone-offload dest root, ONE
/// generation per run: the `ascmhl/` directory + the
/// `NNNN_<dest-basename>_YYYY-MM-DD_HHMMSSZ.mhl` manifest (the
/// generation-1 `transfer` process + the `original` actions, the
/// c4/C4ID hashes — the hand-rolled SHA-512 + base58, std-only,
/// zero new crates; the roothash + the per-file + per-directory
/// content/structure hashes, the pinned ignore set) + the
/// `ascmhl_chain.xml` (the C4ID of each generation's manifest
/// bytes, the append-only re-run model — a re-run appends a NEW
/// generation, the old records preserved byte-for-byte); automatic
/// (no flag — the wiring in `offload::run_offload_multi`), written
/// LAST (after the per-clip manifests + the run report + the job
/// report — the records stand first), silent on success (R-INV-A);
/// the MHL VERIFY pass + the encode surface's `--to` ascmhl = the
/// named follow-ups (see the module docs).
pub mod ascmhl;
/// `frameprism audit` / `frameprism restore` (the
/// audit/restore arc): full-integrity sidecar re-verify (named
/// offenders) + restore from a pristine master (see the module docs).
pub mod audit;
/// `frameprism bake`: reel bundling — per-clip tar|zstd
/// container (detection: j92 → zstd-19, jxl → store) + the mandatory
/// per-file sha256 manifest (see the module docs).
pub mod bake;
/// The camera profiles (OPTION
/// (a)): the per-camera pinned config as a versioned,
/// machine-readable profile (the records pattern — the `# frameprism
/// camera profile` magic + `version:` + `tool_version:` + the
/// deterministic identity/geometry rows, written FROM the
/// measurement). The identity-vs-routing split: the resolver is the
/// IDENTITY layer (the frame's Make/Model + readout/depth/CFA against
/// the pinned set — the four named mismatch classes); the worker's
/// predicates stay the ROUTING layer (the A001 profile = the embedded
/// constants — the encode output for A001 frames stays byte-identical).
/// The encode refuses a non-profiled frame NAMED (rc=2, zero output —
/// the FROZEN posture); the audit gains the additive deterministic
/// camera line (MATCH / MISMATCH rc=1 / ABSENT — optional for the
/// PASS); the profile-set resolution mirrors the pins pattern (the
/// `FRAMEPRISM_PROFILES` env file → `<cwd>/profiles` → `<exe_dir>/
/// profiles` — unresolvable = the named refusal). See the module
/// docs + docs/camera-profiles.md.
pub mod camera;
pub mod checksums;
pub mod codec;
/// `frameprism decode` — the decompression feature:
/// an encoded clip dir → per-frame 16-bit PAM (the p1 mosaic plane; the
/// restore-drill primitive — see the module docs).
pub mod decode;
/// Two-scan 12-bit baseline-DCT decoder for tag-7 (Compression 7)
/// lossy format — the lossy path's acceptance pixel gate .
pub mod dct2s;
/// The `--dry-run` estimate (the predict-then-measure arc,
/// first half): the pinned-random sample encode in RAM (verify always
/// on), the measured ratio band + the projected archive/offload sizes
/// + the space fit-check + the ETA — creates nothing, no ledger row
/// (see the module docs).
pub mod dryrun;
pub mod downscale;
/// `frameprism derive`: the 12→8/10 derived
/// working tier — genuine uncompressed CFA DNGs derived from the 12-bit
/// masters (the pinned v>>4 / v>>2 mapping, the rewritten container
/// header, the <CLIP>.derive-manifest.tsv sidecar; see the module docs).
pub mod derived;
/// `frameprism diff`: the frame-level
/// pixel comparator over two encodes of the same source (the
/// decoded-pixel compare of the two trees — the auto-detected codec
/// pair, the per-frame IDENTICAL/DELTA/MISSING/FAILED + the |Δ|
/// histograms, the deterministic no-wall-clock report, the one
/// ledger row; see the module docs).
pub mod diff;
/// The durability seam: the filesystem
/// synchronization of the offload's write paths — the MANDATORY
/// `sync_file` (a sync failure is a NAMED error — the media's dest
/// row FAILs via the existing failure machinery / the record
/// writer's named hard-error band — never a silent durability claim)
/// + the BEST-EFFORT `sync_dir_best_effort` (the rename's dir-entry
/// update — the pinned note on failure, the content copy stands).
/// NOT a physical-durability claim: the drive/card write-cache
/// behavior is platform-specific — the guarantee stops at the
/// filesystem synchronization (see the module docs).
pub mod durability;
pub mod fastenc;
pub mod iso_times;
/// JXL flag path (`--codec jxl`, effort `--jxl-effort {4|7|9}` with
/// default e7): 4 × 2×2 sub-plane modular lossless JXL per frame
/// (cjxl/djxl 0.12.0 subprocess) + the mandatory jxl-checksums sidecar
/// (see the module docs).
pub mod jxl;
/// The offload job report (the
/// the structured job-report baseline (b): the documented 2024.2 field
/// sets): at EVERY standalone-offload dest root at the run's end
/// (the save-with-job placement), automatic (no flag) —
/// `.frameprism-job-report.md` (the markdown — the manual's
/// "Text" class) + `.frameprism-job-report.csv` (the plain flat
/// form — the pinned header row, the RFC-4180-minimal quoting, NO
/// comment magic — the named deliberate deviation from the manifest
/// TSV idiom) + `.frameprism-job-report.html` (the self-contained
/// styled form — the inline style only, the text escaped); the
/// session + summary blocks + the per-clip blocks (the detection
/// lines verbatim — the pass-through media-details boundary on the
/// record: the DNG payload is NOT parsed); the per-file copy+verify
/// durations (the write+verify window) + the run duration ride ONLY
/// here — the manifests / run report / stderr are untouched by the
/// timing (R-INV-A); the record, not the gate (the rc semantics
/// unchanged — the encode surface's `--to` gets no job report in
/// v1); see the module docs.
pub mod jobreport;
/// The append-only ops ledger (the run journal,
/// A3): one TSV row per completed run in `~/.frameprism/ledger.tsv`
/// (the `FRAMEPRISM_LEDGER` override) + the read-only `frameprism ledger`
/// subcommand with the verification-rotation report (see the module
/// docs).
pub mod ledger;
pub mod ljpeg_ffi;
pub mod ljpeg_ref;
/// The live encode metrics (the predict-then-measure arc):
/// the process-level disk I/O + the CPU + the frames left + the running
/// ETA — the raw-FFI implementation (zero new crates; macOS primary,
/// Linux the named fallback; unmeasurable = the named n/a — see the
/// module docs).
pub mod live;
pub mod log10;
pub mod lossy;
pub mod lossydct;
/// Two-destination ingest — the verified offload (the
/// -cart pull-in): `--to <dir>` re-scans every file
/// in the source tree, copies it to the dest (mirrored subpaths,
/// mtime-preserving), re-scans the copy, and writes the per-file
/// verdict manifest `<CLIP>.offload-manifest.tsv` (see the module
/// docs). + the standalone `frameprism offload <in> <to>` subcommand
/// (the pass-through raw-copy + verify engine — any camera / any
/// format: the copy+verify core extracted from the `--to` step,
/// `offload_to` a thin wrapper over it; the per-clip camera/format
/// detection as report, not gate; the offload run report + the
/// verdict line; the per-clip manifests at the mirrored clip roots).
pub mod offload;
/// Tool-side pin self-check at startup (the
/// Risks-row mitigation): parse `ci/pins.tsv`, probe the version rows
/// with the tool's runtime resolution, refuse NAMED (rc=2, zero
/// output) on a drift/missing binary before the first frame/byte; the
/// resolved state lands in the run report's tool/versions block (see
/// the module docs).
pub mod pins;
/// Pre-flight space + ETA guard: the
/// conservative output estimate (input / 2.0 j92 · / 2.2 jxl × the
/// 1.25 margin) vs the output volume's free space (the jxl disk gate's
/// df probe reused) — a short volume is the NAMED refusal before the
/// first frame/byte; the ETA at the measured corpus rates (see the
/// module docs).
pub mod preflight;
pub mod pack12;
/// The signed manifest — the provenance signature:
/// an ed25519 signature over the reel manifest —
/// sha256 proves the content is intact; the signature proves *this
/// archive was produced by frameprism vX on date D with pin set P*
/// (the key fingerprint lands in the envelope). The documented key
/// file (the tool verifies, it does NOT mint — the external openssl
/// keygen recipe), the `sign` / `verify` verbs (the deterministic
/// envelope — re-sign same `--date` = byte-identical .sig), the
/// audit's keyless signature line (VALID-CONTENT / INVALID-CONTENT /
/// ABSENT — the signature is OPTIONAL for the audit PASS); see the
/// module docs.
pub mod provenance;
/// per-clip QC — the deterministic class (the
/// split): (a) black/blank frames
/// (the pinned range/variance floor on the decoded planes), (b)
/// file-level duplicate (the sidecar sha rows — no decode), (c) the
/// exposure stats (the additive `<CLIP>.qc.tsv` per-frame record + the
/// clip-level moments in the run report — never a gate); the
/// `--qc-gate` verdict mode (rc=2 named rows, the run completes); see
/// the module docs (incl. the v4 placement decision + the union
/// contract).
pub mod qc;
/// The reel manifest (the multi-clip reel's
/// byte contract): `<dir>/reel.reel-manifest.tsv`, one row per clip
/// archive (clip, codec, archive part + sha256, the per-clip bake
/// manifest + sha256, frames) — written only when a bake stages more
/// than one clip archive; the audit's reel verdict reads it (see the
/// module docs).
pub mod reel;
/// `frameprism repair` (the re-copy
/// delta): the repair loop AFTER the two-destination offload 
/// — a mismatch/missing row does NOT re-run the clip; the repair NAMES
/// the row, re-transfers ONLY those files (source → the `--to` dest +
/// the workspace member copy), re-verifies the sha256 (fresh), and
/// re-emits the run report with the updated verdict. Operates from
/// the EXISTING offload manifest + the source tree (no re-encode,
/// no rescan-and-recopy of the whole clip); the disk verdict flips
/// VERIFIED only when the FULL set is clean in BOTH destinations (see
/// the module docs).
pub mod repair;
/// per-clip + run offload reports:
/// `<OUT_DIR>/<CLIP>.frameprism-report.md` per clip
/// (deterministic — no wall clock) + ONE
/// `<OUT_DIR>/.frameprism-run-report.md` (exactly one `created:` line;
/// see the module docs).
pub mod report;
/// `--resume`: the verified-skip plan (the
///: a MANIFEST DIFF, never a process-state machine — the
/// per-frame skip decision (output exists + the sidecar row's sha256
/// verifies over the on-disk output + the source-sha manifest
/// match, when the input carries one) + the torn-row rules + the
/// interrupted-run temp cleanup (see the module docs).
pub mod resume;
/// The clip selection (`--clips` / `--skip`):
/// the encode + bake operate on the selected clip subset (the encode
/// universe = the frame clip keys; a selected run copies only the
/// selected clips' sidecars). Absent flags = the full set = the
/// byte-identity path. The process-wide current selection follows the
/// pins.rs OnceLock convention (see the module docs).
pub mod selection;
/// The source-sha anchor (the direct
/// card archive — verify-before-unmount): the per-clip
/// `<CLIP>.sources.tsv` encode-input record (every source file of the
/// clip — frames + members — with the clip-relative path, size, and
/// sha256 as read at encode) + the verify-against-source surface
/// (`audit --source`: the row classification against the live source,
/// the CARD UNLOCKED/REFUSED/UNVERIFIABLE verdict, the decode-site
/// source-sha registry — the read-site hash, no second full-file
/// read). See the module docs.
pub mod sourcecheck;
/// The machine-readable progress surface (the
///: the append-only JSONL at `~/.frameprism/status.jsonl` (the
/// `FRAMEPRISM_STATUS` override), truncated at run start — one compact
/// one-line JSON event per record; the file is NEVER inside the input
/// or output tree (see the module docs).
pub mod status;
pub mod surgery;
pub mod tiff;
pub mod tileenc;
pub mod verify;
pub mod worker;

/// The process-wide env-var test lock. `cargo test --lib` runs tests on
/// parallel threads in ONE process and `std::env::set_var` is
/// process-global, so every test that (a) sets/removes one of the
/// process env vars the production code reads, OR (b) runs production
/// code that reads one (the lossy erasure path, the ledger path) must
/// hold this lock for the duration of the test. See the SPEC-14 record
/// (the internal SPEC-14 record — the PUB-1b gate flake).
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The AppleDouble shadow predicate (the field
/// incident): macOS writes a binary
/// `._<name>` shadow twin for every file written to an xattr-less
/// volume (the exFAT / msdos / vfat family), because the tool's writes
/// carry default xattrs (`com.apple.provenance`). No frameprism content
/// name starts with `._` (the tool's own sidecars are
/// `.frameprism-run-report.md` / `.members.tsv` — the dot is NOT `._`; the
/// frame/sidecar patterns are `<clip>_<date>_NNNN.DNG` / `*.WAV` /
/// `*.xmp` / `*.tsv` / `*.sha256` / `*.jxl`), so the prefix is a safe,
/// total rule. EVERY glob-driven discovery boundary that walks a user
/// tree skips a matching entry (skip, never error, never log) — one
/// rule, every boundary (the 10-site table + the preflight
/// source scan, named in the suite's pins).
pub fn is_apple_double(name: &str) -> bool {
    name.starts_with("._")
}

/// The directory identity of the cycle-guard visited sets — the
/// platform-typed key (`Eq + Hash`; one variant per platform):
/// - unix: `(dev, ino)` — the strong identity (the same values the
///   pre-existing (dev, ino) pair emitted — the unix behavior is
///   invariant).
/// - windows: the canonical path — the exact identity (symlinks /
///   junctions resolve; two distinct directories can never share a
///   canonical path within a walk — the rename mid-walk is the only
///   theoretical edge, out of class).
/// - other: `(mtime nanos, size)` — the weak fallback, confined to
///   the platforms where neither stable identity is available (none
///   of the three CI targets).
///
/// Forward: the stable-std pair `MetadataExt::{volume_serial_number,
/// file_index}` is feature-gated (`windows_by_handle`) on the pinned
/// 1.98 (E0658 on the record) — when it stabilizes, the windows arm's
/// swap to it is a one-branch change.
#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum DirId {
    /// unix: the (device, inode) pair — the strong identity.
    #[cfg(unix)]
    DevIno(u64, u64),
    /// windows: the canonical path — the exact identity.
    #[cfg(windows)]
    Canonical(std::path::PathBuf),
    /// other: the (mtime nanos, size) pair — the weak fallback
    /// (confined — none of the three CI targets).
    #[cfg(not(any(unix, windows)))]
    MtimeLen(u64, u64),
}

/// The directory identity for the `visited` cycle guard (the platform
/// arm above): the metadata is taken internally — the caller passes
/// the path. The error is the stat's (unix / other) or the
/// canonicalize's (windows) — the site's pre-existing error wording
/// carries it (the `with_context` / `map_err` at the call site).
pub(crate) fn dir_id(path: &std::path::Path) -> std::io::Result<DirId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        Ok(DirId::DevIno(meta.dev(), meta.ino()))
    }
    #[cfg(windows)]
    {
        Ok(DirId::Canonical(path.canonicalize()?))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let meta = std::fs::metadata(path)?;
        let nanos = meta
            .modified()
            .map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    as u64
            })
            .unwrap_or(0);
        Ok(DirId::MtimeLen(nanos, meta.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::is_apple_double;

    /// The predicate unit (G2): the exact vectors
    /// + the tool's own sidecar names (the safety argument) + the
    /// field's shadow names.
    #[test]
    fn apple_double_predicate_is_the_prefix_rule() {
        assert!(is_apple_double("._x"));
        assert!(is_apple_double("._"));
        assert!(!is_apple_double(".members.tsv"));
        assert!(!is_apple_double("..DNG"));
        assert!(!is_apple_double("A001.DNG"));
        // The tool's own sidecars (the dot is NOT `._`):
        assert!(!is_apple_double(".frameprism-run-report.md"));
        assert!(!is_apple_double(".members.tsv"));
        // The field's shadow names (the fp inventory):
        assert!(is_apple_double("._CINEMA.ingest-manifest.tsv"));
        assert!(is_apple_double("._A001_001.members.tsv"));
        assert!(is_apple_double("._A001_001.part01.tar.zst.sha256"));
    }

    /// The cycle-guard identity property (the collision class): two
    /// DISTINCT directories forced to identical (mtime, size) — the
    /// same instant (std-only `File::set_modified`) + the same shape
    /// (one empty file each — the same directory size on the mount)
    /// — must carry DIFFERENT identities. The pre-existing non-unix
    /// (mtime, size) key returns the SAME value here (the collision);
    /// the platform identity (the unix dev/ino, the windows canonical
    /// path) cannot.
    #[test]
    fn cycle_guard_identity_rejects_the_forced_mtime_size_collision() {
        let root = std::env::temp_dir()
            .join(format!("frameprism-cycle-guard-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let d_a = root.join("a");
        let d_b = root.join("b");
        std::fs::create_dir_all(&d_a).unwrap();
        std::fs::create_dir_all(&d_b).unwrap();
        // The same shape: one empty file each (the size half of the
        // forced pair — the same directory size on the mount).
        std::fs::write(d_a.join("x.bin"), b"").unwrap();
        std::fs::write(d_b.join("x.bin"), b"").unwrap();
        // The mtime half: the same instant on both dirs (std-only).
        let instant = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        for d in [&d_a, &d_b] {
            std::fs::OpenOptions::new()
                .read(true)
                .open(d)
                .unwrap()
                .set_modified(instant)
                .unwrap();
        }
        let m_a = std::fs::metadata(&d_a).unwrap();
        let m_b = std::fs::metadata(&d_b).unwrap();
        // The premise (the collision is real on this mount): the
        // exact pair the pre-existing weak key keyed on is identical.
        assert_eq!(
            m_a.modified().unwrap(),
            m_b.modified().unwrap(),
            "the forced mtimes are identical on this mount"
        );
        assert_eq!(
            m_a.len(),
            m_b.len(),
            "the same-shape dirs share the directory size on this mount"
        );
        // The identity: DIFFERENT (the collision class is dead).
        assert_ne!(
            crate::dir_id(&d_a).unwrap(),
            crate::dir_id(&d_b).unwrap(),
            "two distinct dirs sharing the forced (mtime, size) must not share an identity (the false-skip class)"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The cycle-guard walker behavior (the skip / false-cycle
    /// class): the temp tree — the root + two subdirs forced to the
    /// same (mtime, size) + the symlink cycle back into the root
    /// (best-effort — the host's symlink policy decides; the
    /// assertion holds either way) — walked by the actual
    /// cycle-guard walker (`offload::traversal::collect_all_files`):
    /// every real directory is visited exactly once (each file
    /// appears exactly once — a skipped dir drops its files, a
    /// double visit duplicates them), the cycle terminates, nothing
    /// is skipped.
    #[test]
    fn cycle_guard_walker_visits_each_real_dir_once() {
        let root = std::env::temp_dir()
            .join(format!("frameprism-cycle-guard-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let a = root.join("a");
        let b = root.join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("a1.bin"), b"x").unwrap();
        std::fs::write(b.join("b1.bin"), b"y").unwrap();
        // Force the collision on both subdirs (the same instant, the
        // same one-file shape).
        let instant = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        for d in [&a, &b] {
            std::fs::OpenOptions::new()
                .read(true)
                .open(d)
                .unwrap()
                .set_modified(instant)
                .unwrap();
        }
        // The cycle: a symlink back into the root (best-effort — the
        // host's symlink policy; the walker's symlink refusal + the
        // visited set make the walk correct either way).
        let cycle = root.join("cycle");
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(&root, &cycle);
        }
        #[cfg(windows)]
        {
            let _ = std::os::windows::fs::symlink_dir(&root, &cycle);
        }
        let files = crate::offload::traversal::collect_all_files(&root).unwrap();
        let mut rels: Vec<String> = files.iter().map(|(r, _)| r.clone()).collect();
        rels.sort();
        assert_eq!(
            rels,
            vec!["a/a1.bin", "b/b1.bin"],
            "every real dir visited exactly once, the cycle terminates, nothing is skipped (the forced collision must not false-skip a dir)"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// The env-surface + media-read structural tests (the `FRAMEPRISM_*`
/// vars are the test + gate hook: the `set_var`/`remove_var` pair in a
/// test is a transient window — no process-global env state survives
/// a test).
#[cfg(test)]
mod env_compat_tests {
    // The media-reads-bounded invariant (the STRUCTURAL
    // PIN): the per-module count of
    // `std::fs::read(` in the PRODUCTION region (before the first
    // `#[cfg(test)]`) equals the recorded keep set — (C) the small
    // RECORD-file reads (the manifests / the sidecar records / the
    // exe's own sha), (D) the TRANSFORM-class encode/decode reads
    // (the encode/decode consumes the frame in RAM — the documented
    // out-of-scope sibling). Every other production site is a
    // bounded read (the detection prefix / the `SHA256_CHUNK`-
    // buffered streaming helpers / the 512 KiB header-window
    // pattern). A NEW whole-file read in production code moves a
    // count → the pin FAILs (the invariant is gateable from this
    // suite on). The keep-anchors + the wording pins below prove the
    // composition (the counts match on the recorded sites, not
    // elsewhere) and that not one byte of the converted sites'
    // error wording moved. (The split
    // note: the worker surface moved to the part files — the
    // include targets are the part files; the anchors + the
    // keep count + the wordings are unchanged.)
    // (The split note: the main surface moved to the part
    // files — the main.rs row stays (the crate root); the two
    // part rows join the table; the anchors + the counts + the
    // wordings are unchanged.)
    // (The split note: the audit surface moved to the part
    // files — the audit.rs row is replaced by the four part rows
    // (the keep count 0 each); the anchors + the counts + the
    // wordings are unchanged.)
    #[test]
    fn media_reads_bounded_invariant_pinned() {
        let surfaces: [(&str, usize); 58] = [
            (include_str!("ascmhl.rs"), 0),
            (include_str!("audit/entries.rs"), 0),
            (include_str!("audit/model.rs"), 0),
            (include_str!("audit/records.rs"), 0),
            (include_str!("audit/sidecars.rs"), 0),
            (include_str!("bake.rs"), 3),
            (include_str!("camera.rs"), 0),
            (include_str!("checksums.rs"), 0),
            (include_str!("cli_model.rs"), 0),
            (include_str!("codec.rs"), 0),
            (include_str!("dct2s.rs"), 0),
            (include_str!("decode.rs"), 3),
            (include_str!("derived.rs"), 1),
            (include_str!("dispatch.rs"), 0),
            (include_str!("diff.rs"), 0),
            (include_str!("downscale.rs"), 0),
            (include_str!("dryrun.rs"), 1),
            (include_str!("durability.rs"), 0),
            (include_str!("fastenc.rs"), 0),
            (include_str!("jobreport.rs"), 0),
            (include_str!("jxl.rs"), 4),
            (include_str!("ledger.rs"), 0),
            (include_str!("lib.rs"), 0),
            (include_str!("live.rs"), 0),
            (include_str!("ljpeg_ffi.rs"), 0),
            (include_str!("ljpeg_ref.rs"), 0),
            (include_str!("log10.rs"), 0),
            (include_str!("lossy.rs"), 0),
            (include_str!("lossydct.rs"), 0),
            (include_str!("main.rs"), 0),
            (include_str!("offload/forms.rs"), 0),
            (include_str!("offload/manifests.rs"), 0),
            (include_str!("offload/mod.rs"), 0),
            (include_str!("offload/reverify.rs"), 0),
            (include_str!("offload/report.rs"), 0),
            (include_str!("offload/traversal.rs"), 0),
            (include_str!("offload/transfer.rs"), 0),
            (include_str!("pack12.rs"), 0),
            (include_str!("pins.rs"), 0),
            (include_str!("preflight.rs"), 0),
            (include_str!("provenance.rs"), 3),
            (include_str!("qc.rs"), 0),
            (include_str!("reel.rs"), 1),
            (include_str!("repair.rs"), 0),
            (include_str!("report.rs"), 0),
            (include_str!("resume.rs"), 0),
            (include_str!("selection.rs"), 0),
            (include_str!("sourcecheck.rs"), 0),
            (include_str!("status.rs"), 0),
            (include_str!("surgery.rs"), 0),
            (include_str!("tiff.rs"), 0),
            (include_str!("tileenc.rs"), 0),
            (include_str!("verify.rs"), 0),
            (include_str!("worker/checksums.rs"), 0),
            (include_str!("worker/encode.rs"), 1),
            (include_str!("worker/ingest.rs"), 0),
            (include_str!("worker/report.rs"), 0),
            (include_str!("worker/sidecar.rs"), 0),
        ];
        // The PRODUCTION region = before the column-0 test-module
        // marker (the mid-file `#[cfg(test)]` override slots —
        // camera / the fastenc + lib + worker test seams — are test-
        // only and carry no `fs::read`; the no-mod-tests files are
        // whole-file production).
        fn prod_of(module: &str) -> &str {
            match module.find("#[cfg(test)]\nmod tests {") {
                Some(i) => &module[..i],
                None => module,
            }
        }
        for (module, want) in surfaces {
            let n = prod_of(module).matches("std::fs::read(").count();
            assert_eq!(
                n, want,
                "the production-region std::fs::read count moved (a new whole-file media read?) — the bounded-read invariant is the gate"
            );
        }
        // The keep-anchors: the 17 recorded keep sites (the C/D/
        // exe-self-sha class) are in place.
        let anchors: [(&str, &str); 17] = [
            (include_str!("bake.rs"), "std::fs::read(output.join(&r.manifest_name))"),
            (include_str!("bake.rs"), "std::fs::read(staging.join(&r.manifest_name))"),
            (include_str!("bake.rs"), "std::fs::read(&ro_manifest).with_context(|| {"),
            (include_str!("decode.rs"), "std::fs::read(&desc.src).with_context(|| format!(\"read {}\", desc.src.display()))?;"),
            (include_str!("decode.rs"), "std::fs::read(&pam_tmp)"),
            (include_str!("decode.rs"), "std::fs::read(src)"),
            (include_str!("derived.rs"), "std::fs::read(src).with_context(|| format!(\"read {}\", src.display()))?;"),
            (include_str!("dryrun.rs"), "std::fs::read(&p).ok())"),
            (include_str!("jxl.rs"), "std::fs::read(src).with_context(|| format!(\"read {}\", src.display()))?;"),
            (include_str!("jxl.rs"), "std::fs::read(src) {"),
            (include_str!("jxl.rs"), "std::fs::read(&pam_tmp)"),
            (include_str!("provenance.rs"), "std::fs::read(manifest)"),
            (include_str!("provenance.rs"), "std::fs::read(reel_manifest) {"),
            (include_str!("provenance.rs"), "std::fs::read(&args.manifest) {"),
            (include_str!("reel.rs"), "std::fs::read(&p) {"),
            (include_str!("worker/encode.rs"), "std::fs::read(src).with_context(|| format!(\"read {}\", src.display()))?;"),
            (include_str!("jxl.rs"), "std::fs::read(src).with_context(|| format!(\"read {}\", src.display()))?;"),
        ];
        for (module, anchor) in anchors {
            assert!(
                module.contains(anchor),
                "a recorded keep site moved (the keep-set anchor is gone): {anchor}"
            );
        }
        // The wording pins (the converted
        // sites' error wordings are byte-identical to the pre-existing
        // ones).
        let wordings: [(&str, &str); 20] = [
            (include_str!("camera.rs"), "the offload detection sample {} is unreadable ({err})"),
            (include_str!("camera.rs"), "the offload detection sample {} does not parse ({err})"),
            (include_str!("camera.rs"), "cannot read the sample frame {}: {err}"),
            (include_str!("camera.rs"), "the sample frame {} does not parse ({err})"),
            (include_str!("worker/report.rs"), "FAIL {file}: camera identity: read {}: {err}"),
            (include_str!("worker/sidecar.rs"), "read the output frame {} for the sidecar row: {err}"),
            (include_str!("sourcecheck.rs"), "read the card file: {e}"),
            (include_str!("resume.rs"), "resume: read the output frame {} for the sha verify: {err}"),
            (include_str!("resume.rs"), "resume: read the source frame {} for the source-sha check: {err}"),
            (include_str!("report.rs"), "SRC_UNREADABLE ({err}) — the row is named, not invented"),
            (include_str!("repair.rs"), "re-scan the source {}: {err}"),
            (include_str!("repair.rs"), "re-verify: re-scan the source {}: {err}"),
            (include_str!("repair.rs"), "re-verify: read the repaired copy {}: {err}"),
            (include_str!("repair.rs"), "read the source: {err}"),
            (include_str!("bake.rs"), "bake: {ctx} read the archive part {pn}"),
            (include_str!("bake.rs"), "bake: read the object {}"),
            (include_str!("bake.rs"), "bake: --iso --reel-out read the bundle source {}"),
            (include_str!("bake.rs"), "read the object {}: {e}"),
            (include_str!("reel.rs"), "unreadable archive {a}: {err}"),
            (include_str!("checksums.rs"), "\"read {}\", path.display())"),
        ];
        for (module, wording) in wordings {
            assert!(
                prod_of(module).contains(wording),
                "a converted site's error wording moved (the wording discipline): {wording}"
            );
        }
    }
}
