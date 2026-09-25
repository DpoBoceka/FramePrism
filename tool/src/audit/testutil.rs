//! The audit tests' shared helpers (the BCD / timecode
//! builders + the synthetic DNG + the fixture dirs + the
//! ledger-redirecting run wrappers + the offload fixtures —
//! shared across the part test modules; no duplication).

use super::*;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::worker;

    /// Build a BCD payload from a worker::Smpte12m (the fp's field order
    /// [FF, SS, MM, HH] + 4 NUL padding).
    pub(crate)fn bcd_of(v: u8) -> u8 {
        ((v / 10) << 4) | (v % 10)
    }
    pub(crate)fn tc_of(hh: u8, mm: u8, ss: u8, ff: u8) -> worker::Smpte12m {
        worker::Smpte12m { hh, mm, ss, ff }
    }
    pub(crate)fn tc_payload(t: &worker::Smpte12m) -> [u8; 8] {
        [bcd_of(t.ff), bcd_of(t.ss), bcd_of(t.mm), bcd_of(t.hh), 0, 0, 0, 0]
    }

    /// A minimal little-endian TIFF "DNG": IFD0 carries ONE out-of-line
    /// entry — the TimeCodes tag 51043 (type 1, count 8) when `tc` is
    /// Some, or an unrelated in-line tag (256) when None (the TC_MISSING
    /// case). `payload` overrides the 51043 value bytes (the TC_MALFORMED
    /// case). Mirrors the worker's test builder.
    pub(crate)fn synthetic_dng(tc: Option<[u8; 8]>) -> Vec<u8> {
        const IFD_OFF: u32 = 8;
        const N: u16 = 1;
        let struct_len = IFD_OFF as u64 + 2 + (N as u64) * 12 + 4;
        let off = struct_len;
        let mut buf = vec![0u8; off as usize + 8];
        buf[0..4].copy_from_slice(b"II*\0");
        buf[4..8].copy_from_slice(&IFD_OFF.to_le_bytes());
        buf[8..10].copy_from_slice(&N.to_le_bytes());
        let et = 10;
        let (tag, t, c) = match tc {
            Some(_) => (51043u16, 1u16, 8u32),
            None => (256u16, 3u16, 1u32),
        };
        buf[et..et + 2].copy_from_slice(&tag.to_le_bytes());
        buf[et + 2..et + 4].copy_from_slice(&t.to_le_bytes());
        buf[et + 4..et + 8].copy_from_slice(&c.to_le_bytes());
        if let Some(p) = tc {
            buf[et + 8..et + 12].copy_from_slice(&(off as u32).to_le_bytes());
            buf[off as usize..off as usize + 8].copy_from_slice(&p);
        }
        buf[10 + (N as usize) * 12..10 + (N as usize) * 12 + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        buf
    }

    /// Build a two-destination-style audit dir: the per-clip .DNG frames
    /// + the ingest manifest (recorded via the SAME worker functions the
    /// ingest pass uses — the honest round-trip). `record_frames` is the
    /// per-clip frame count the recorded manifest claims (a mismatch
    /// against disk exercises the recorded-vs-re-derived check).
    pub(crate)fn mk_audit_dir(
        tmp: &Path,
        clips: &[(&str, Vec<(&str, worker::Smpte12m)>)],
        record_frames: Option<&[(&str, u64)]>,
    ) {
        let _ = std::fs::remove_dir_all(tmp);
        std::fs::create_dir_all(tmp).unwrap();
        for (dir, frames) in clips {
            let d = tmp.join(dir);
            std::fs::create_dir_all(&d).unwrap();
            for (name, tc) in frames {
                std::fs::write(d.join(name), synthetic_dng(Some(tc_payload(&tc)))).unwrap();
            }
        }
        // The gate over the on-disk frames → the recorded manifest.
        let disk_frames = worker::collect_dng_frames(tmp).unwrap();
        let gate = worker::ingest_gate(tmp, &disk_frames);
        assert!(gate.is_pass(), "the fixture must pass its own gate: {:?}", gate.failures());
        let mut recorded = gate.clone();
        if let Some(rows) = record_frames {
            for (clip, n) in rows {
                if let Some(v) = recorded.clips.iter_mut().find(|v| &v.clip == clip) {
                    v.frames_found = *n;
                }
            }
        }
        // The recorded manifest lands in the SAME dir (the two-dest shape:
        // source DNGs + the copied record; no archive sidecar).
        let p = worker::write_ingest_manifest(tmp, tmp, &recorded).unwrap();
        assert!(p.is_file());
    }

    pub(crate)fn run(input: &Path) -> ExitCode {
        // The A3 ledger row: redirect to THIS test's temp (the suite
        // must not append to the user's journal — `~/.frameprism/ledger
        // .tsv` is user state, never test state). Per-test file + set/
        // remove around the call: a concurrent test swapping the env
        // can only misdirect a row into another temp file (no
        // assertion reads the ledger; the user state is never touched).
        //: the env swap + the run + the ledger-file read are
        // serialized on a static lock (the `--source` tests assert the
        // row's verdict column — a mid-swap env would misdirect the
        // row and skew the read; the lock makes the critical section
        // atomic).
        run_locked(input, None).0
    }

    /// The `--source` variant of `run` (the verify-against-
    /// source surface — the same ledger redirection convention).
    pub(crate)fn run_source(input: &Path, source: &Path) -> ExitCode {
        run_locked(input, Some(source)).0
    }

    /// The critical section (set env → run → read the ledger row's
    /// verdict → remove env), serialized on the process-wide
    /// `crate::ENV_LOCK` (the shared env-var test lock — the module-
    /// private `LEDGER_LOCK` is deleted: the shared lock subsumes it):
    /// every audit-verb test that redirects the ledger env holds the
    /// lock across the whole section, so the row always lands in — and
    /// is always read from — this test's file.

    pub(crate)fn run_locked(input: &Path, source: Option<&Path>) -> (ExitCode, Option<String>) {
        let _guard = crate::ENV_LOCK.lock().expect("env lock");
        let p = input.join(".ledger-test.tsv");
        let _ = std::fs::remove_file(&p); // a torn prior row would skew the last-row read
        std::env::set_var("FRAMEPRISM_LEDGER", &p);
        let rc = run_audit(&AuditArgs {
            input: input.to_path_buf(),
            jobs: 1,
            source: source.map(|s| s.to_path_buf()),
        });
        std::env::remove_var("FRAMEPRISM_LEDGER");
        (rc, ledger_verdict(input))
    }

    /// The ledger row's verdict column of the `run`/`run_source`
    /// helper's redirected file (the last row — the audit appends
    /// exactly one row per completed run; the v2 11-column shape: the
    /// verdict is column 7).
    pub(crate)fn ledger_verdict(input: &Path) -> Option<String> {
        let text = std::fs::read_to_string(input.join(".ledger-test.tsv")).ok()?;
        let line = text.lines().last()?;
        Some(line.split('\t').nth(7)?.to_string())
    }

    ///: the source-verify fixture — a flat encoded-style
    /// archive (the J92 v2 sidecar + the encoded .DNG at the root —
    /// the sweep's surface) + the `<CLIP>.sources.tsv` record (the
    /// flat clip key "") + the live card (the flat clip dir holding
    /// the SOURCE bytes). Returns (archive, card, the sources
    /// record's path).
    pub(crate)fn mk_source_audit_dir(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("frameprism_audit_source_{tag}"));
        let _ = std::fs::remove_dir_all(&base);
        let archive = base.join("out");
        let card = base.join("card");
        std::fs::create_dir_all(&archive).unwrap();
        std::fs::create_dir_all(&card).unwrap();
        let frame = b"encoded-frame-bytes";
        std::fs::write(archive.join("f1.DNG"), frame).unwrap();
        std::fs::write(card.join("f1.DNG"), frame).unwrap();
        let member = b"RIFF-wave";
        std::fs::write(card.join("a.wav"), member).unwrap();
        // The v2 checksums sidecar (the sweep's surface — 4 columns).
        let crc = crate::checksums::crc32c(frame);
        let sha = crate::jxl::sha256_hex(frame);
        std::fs::write(
            archive.join("CLIP.checksums.tsv"),
            format!(
                "file\tsize\tcrc32c\tsha256\nf1.DNG\t{}\t{crc:08x}\t{sha}\n",
                frame.len()
            ),
        )
        .unwrap();
        // The sources record (the flat clip key "" — the dotfile
        // `.sources.tsv`): the frame + the member, the card's bytes.
        let p = crate::sourcecheck::write_sources_record(
            &archive,
            "",
            &[
                ("a.wav".to_string(), member.len() as u64, crate::jxl::sha256_hex(member)),
                ("f1.DNG".to_string(), frame.len() as u64, sha.clone()),
            ],
        )
        .unwrap();
        (archive, card, p)
    }

    /// A B6 object + its sha256sum-compatible sidecar (`<sha>  <name>`,
    /// two spaces).
    pub(crate)fn mk_object_sha(tmp: &Path, name: &str, content: &[u8]) -> String {
        std::fs::write(tmp.join(name), content).unwrap();
        let sha = crate::jxl::sha256_hex(content);
        std::fs::write(tmp.join(format!("{name}.sha256")), format!("{sha}  {name}\n")).unwrap();
        sha
    }

    /// The standalone mirror fixture (the 14a shape — built by the
    /// SAME `offload::run_offload` the surface ships, the honest
    /// round-trip): a 2-clip non-DNG tree (the pass-through's native
    /// material — no profiles, no DNG parsing) mirrored to
    /// `mirror/`: the per-clip manifests at the mirrored clip roots
    /// + the source-root manifest at the mirror root + the run
    /// report. NO archive sidecar, NO ingest manifest, NO reel
    /// manifest (the standalone branch's shape). Returns (base,
    /// mirror root) — 3 manifests, 4 rows.
    pub(crate)fn mk_offload_mirror(tag: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "frameprism_mirror_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        std::fs::create_dir_all(input.join("A001_001")).unwrap();
        std::fs::create_dir_all(input.join("B002_002")).unwrap();
        std::fs::write(input.join("A001_001/f1.wav"), b"wave-one").unwrap();
        std::fs::write(input.join("A001_001/f2.xmp"), b"<?xmp-1?>").unwrap();
        std::fs::write(input.join("B002_002/g1.wav"), b"wave-two").unwrap();
        std::fs::write(input.join("root.wav"), b"root-wave").unwrap();
        let input_c = std::fs::canonicalize(&input).unwrap();
        let mirror = base.join("mirror");
        let rc = crate::offload::run_offload(&input_c, &mirror).unwrap();
        assert_eq!(
            rc,
            ExitCode::SUCCESS,
            "the fixture mirror must verify clean at copy time"
        );
        (base, mirror)
    }

    /// A hand-built valid offload manifest (the wire-contract format
    /// the `offload::parse_manifest` reader pins: the magic, the
    /// clip/dest headers, the column line, the rows).
    pub(crate)fn mk_offload_manifest(path: &Path, clip: &str, dest: &Path, rows: &[(&str, &[u8])]) {
        let mut t = String::new();
        t.push_str(crate::offload::MANIFEST_MAGIC);
        t.push('\n');
        t.push_str("version: 1\n");
        t.push_str(&format!("clip: {clip}\n"));
        t.push_str(&format!("dest: {}\n", dest.display()));
        t.push_str("file\tsize\tsource_sha256\tdest_sha256\tverdict\n");
        for (file, bytes) in rows {
            let sha = crate::jxl::sha256_hex(bytes);
            t.push_str(&format!("{file}\t{}\t{sha}\t{sha}\tOK\n", bytes.len()));
        }
        std::fs::write(path, t).unwrap();
    }
