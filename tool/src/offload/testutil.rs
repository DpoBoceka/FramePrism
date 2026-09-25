//! The offload tests' shared helpers (the per-test /tmp tree
//! setups + the report/manifest readers + the row builders —
//! shared across the part test modules; no duplication).

use super::*;
    use std::path::{Path, PathBuf};

    /// The 14a standalone tree's file relpaths (the deterministic
    /// seed order — the tree's whole content).
    const STANDALONE_RELS: [&str; 7] = [
        "A001_001/SPP_metadata.xmp",
        "A001_001/clip.wav",
        "A001_001/f1.DNG",
        "B002_002/f1.DNG",
        "C003_003/clip.wav",
        "manifest.tsv",
        "root.wav",
    ];

    /// Set up a /tmp source tree: 2 DNG-ish frames in a clip subdir,
    /// a WAV + an XMP at the root + one in the clip (the first-class
    /// members), a nested sidecar — and pin explicit mtimes. `tag`
    /// = a per-test dir suffix (the parallel tests must not share a
    /// base — a sibling's remove_dir_all would race the dest).
    pub(crate) fn setup(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("frameprism_offload_test_{tag}"));
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        let output = base.join("out");
        let dest = base.join("dest");
        std::fs::create_dir_all(input.join("A001_001")).unwrap();
        std::fs::create_dir_all(&output).unwrap();
        let mk = |p: &Path, body: &[u8]| {
            std::fs::write(p, body).unwrap();
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
            let f = std::fs::File::options().write(true).open(p).unwrap();
            f.set_modified(t).unwrap();
        };
        mk(&input.join("A001_001/f1.DNG"), b"frame-one-payload");
        mk(&input.join("A001_001/f2.DNG"), b"frame-two-payload");
        mk(&input.join("A001_001/clip.wav"), b"RIFF-wave");
        mk(&input.join("A001_001/SPP_metadata.xmp"), b"<?xmp?>");
        mk(&input.join("root.wav"), b"RIFF-root-wave");
        mk(&input.join("manifest.tsv"), b"relpath\tsize\tsha256\n");
        (base, input, dest)
    }


    /// Force the in-process profile set for the standalone-offload
    /// tests (the worker-test pattern — the thread-safe stand-in for
    /// the profiles resolution: the repo's A001 profile written to a
    /// per-process temp file + the camera override; the content is
    /// the SAME for every caller — concurrent sets cannot skew each
    /// other).
    pub(crate) fn profile_override_a001() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let p = Path::new("../profiles/a001-sigma-fp.profile");
            let text = std::fs::read_to_string(p).unwrap_or_else(|err| {
                panic!("the A001 profile file must exist for the offload tests: {p:?}: {err}")
            });
            let dir = std::env::temp_dir().join(format!(
                "frameprism-offload-camera-profile-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let f = dir.join("a001-sigma-fp.profile");
            std::fs::write(&f, text).unwrap();
            crate::camera::set_profile_override(Some(&f));
        });
    }


    /// The mixed-card fixture: the profiled clip (the A001 identity),
    /// the unprofiled clip (an unknown Make/Model), the sidecar-only
    /// clip, the source-root files (the "" clip key).
    pub(crate) fn standalone_tree(tag: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "frameprism_offload_standalone_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        std::fs::create_dir_all(input.join("A001_001")).unwrap();
        std::fs::create_dir_all(input.join("B002_002")).unwrap();
        std::fs::create_dir_all(input.join("C003_003")).unwrap();
        std::fs::write(
            input.join("A001_001/f1.DNG"),
            crate::camera::synth_dng_frame("SIGMA", "SIGMA fp", 3856, 2170, 12, 32803, None),
        )
        .unwrap();
        std::fs::write(
            input.join("A001_001/clip.wav"),
            b"RIFF-wave",
        )
        .unwrap();
        std::fs::write(
            input.join("A001_001/SPP_metadata.xmp"),
            b"<?xmp?>",
        )
        .unwrap();
        std::fs::write(
            input.join("B002_002/f1.DNG"),
            crate::camera::synth_dng_frame("TEST MAKE", "TEST MODEL", 1920, 1080, 12, 32803, None),
        )
        .unwrap();
        std::fs::write(input.join("C003_003/clip.wav"), b"RIFF-sidecar").unwrap();
        std::fs::write(input.join("root.wav"), b"RIFF-root-wave").unwrap();
        std::fs::write(input.join("manifest.tsv"), b"relpath\tsize\tsha256\n").unwrap();
        (base, input)
    }


    pub(crate) fn read_report(dest: &Path) -> String {
        let path = dest.join(crate::report::RUN_REPORT_NAME);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("the run report {path:?}: {err}"))
    }


    /// The job report's three files at a dest root (the exact pinned
    /// names — the dest-root report pattern).
    pub(crate) fn job_report_files(dest: &Path) -> (String, String, String) {
        let md = std::fs::read_to_string(dest.join(crate::jobreport::MD_NAME))
            .unwrap_or_else(|err| panic!("the job report md at {dest:?}: {err}"));
        let csv = std::fs::read_to_string(dest.join(crate::jobreport::CSV_NAME))
            .unwrap_or_else(|err| panic!("the job report csv at {dest:?}: {err}"));
        let html = std::fs::read_to_string(dest.join(crate::jobreport::HTML_NAME))
            .unwrap_or_else(|err| panic!("the job report html at {dest:?}: {err}"));
        (md, csv, html)
    }


    /// One `## <heading>` section of the job report's md (the text
    /// between the heading and the next `## ` heading or EOF).
    pub(crate) fn md_section<'a>(md: &'a str, heading: &str) -> &'a str {
        let start_pat = format!("\n## {heading}\n");
        let start = md
            .find(&start_pat)
            .unwrap_or_else(|| panic!("the section ## {heading} in the job report:\n{md}"));
        let rest = &md[start + start_pat.len()..];
        match rest.find("\n## ") {
            Some(end) => &rest[..end],
            None => rest,
        }
    }


    /// The per-file md table row's contract (the code-span file name,
    /// the size/shas/verdict/skipped EXACT, the copied_ms by FORMAT
    /// class only — the wall clock).
    pub(crate) fn md_row_verdict(sec: &str, rel: &str, size: usize, src_sha: &str, dest_sha: &str, verdict: &str, skipped: &str) {
        let prefix = format!("| `{rel}` | {size} | {src_sha} | {dest_sha} | {verdict} | {skipped} | ");
        let line = sec
            .lines()
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("the per-file row for {rel} in the section:\n{sec}"));
        let tail = line
            .strip_prefix(&prefix)
            .unwrap()
            .strip_suffix(" |")
            .unwrap_or_else(|| panic!("the row closes: {line:?}"));
        assert!(
            !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()),
            "copied_ms by FORMAT class (never by value): {tail:?}"
        );
    }


    /// The per-clip `duration:` line's format class (`\d+ ms` — the
    /// value is NOT pinned — the wall clock).
    pub(crate) fn duration_ms_line(line: &str) -> bool {
        let rest = match line.strip_prefix("duration: ") {
            Some(r) => r,
            None => return false,
        };
        let n = match rest.strip_suffix(" ms") {
            Some(n) => n,
            None => return false,
        };
        !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
    }


    /// The summary's run `duration:` line's format class (`\d+\.\d
    /// s` — the value is NOT pinned — the wall clock).
    pub(crate) fn duration_s_line(line: &str) -> bool {
        let rest = match line.strip_prefix("duration: ") {
            Some(r) => r,
            None => return false,
        };
        let n = match rest.strip_suffix(" s") {
            Some(n) => n,
            None => return false,
        };
        n.contains('.') && n.parse::<f64>().is_ok()
    }


    /// The job identifier's UTC timestamp format class
    /// (`YYYY-MM-DDTHH:MM:SSZ` — the value is NOT pinned — the wall
    /// clock).
    pub(crate) fn utc_format(s: &str) -> bool {
        let b = s.as_bytes();
        if b.len() != 20 {
            return false;
        }
        for (i, c) in [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':'), (19, b'Z')] {
            if b[i] != c {
                return false;
            }
        }
        for (i, c) in b.iter().enumerate() {
            if ![4, 7, 10, 13, 16, 19].contains(&i) && !c.is_ascii_digit() {
                return false;
            }
        }
        true
    }


    /// The minimal RFC-4180 line parser (the comma-row round-trip —
    /// the quoting undone; the test's half of the CSV's quoting
    /// contract).
    pub(crate) fn parse_csv_line(line: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut quoted = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if quoted {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        cur.push('"');
                    } else {
                        quoted = false;
                    }
                } else {
                    cur.push(c);
                }
            } else if c == '"' {
                quoted = true;
            } else if c == ',' {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.push(c);
            }
        }
        out.push(cur);
        out
    }


    /// The CSV data row's contract (the clip cell + the file/size/
    /// shas/verdict/skipped EXACT, the copied_ms by FORMAT class
    /// only).
    pub(crate) fn csv_row_verdict(
        lines: &[&str],
        i: usize,
        clip: &str,
        rel: &str,
        size: usize,
        sha: &str,
        dest_sha: &str,
        verdict: &str,
        skipped: &str,
    ) {
        let prefix = format!("{clip},{rel},{size},{sha},{dest_sha},{verdict},{skipped},");
        let line = lines.get(i).unwrap_or_else(|| panic!("the csv row {i}: {lines:?}"));
        assert!(
            line.starts_with(&prefix),
            "the csv row's deterministic values (row order + the exact columns): want prefix {prefix:?} in {line:?}"
        );
        let tail = line.strip_prefix(&prefix).unwrap();
        assert!(
            !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()),
            "copied_ms by FORMAT class (never by value): {tail:?}"
        );
    }


    /// The multi tests' two source trees (2 clips each; the top-level
    /// entry names disjoint across the sources — the
    /// collision-free shape; the basenames cardA/cardB distinct;
    /// NO root files — the "" key is absent from
    /// both scans): cardA = the profiled source (the SIGMA fp DNGs —
    /// the profile override) + the sidecar-only clip; cardB = the
    /// unprofiled source (the TESTM/TEST CAM DNG) + the sidecar-only
    /// clip.
    pub(crate) fn multi_trees(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "frameprism_offload_multi_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let card_a = base.join("cardA");
        let card_b = base.join("cardB");
        std::fs::create_dir_all(card_a.join("A001_001")).unwrap();
        std::fs::create_dir_all(card_a.join("S001_001")).unwrap();
        std::fs::create_dir_all(card_b.join("B002_002")).unwrap();
        std::fs::create_dir_all(card_b.join("T001_001")).unwrap();
        std::fs::write(
            card_a.join("A001_001/f1.DNG"),
            crate::camera::synth_dng_frame("SIGMA", "SIGMA fp", 3856, 2170, 12, 32803, None),
        )
        .unwrap();
        std::fs::write(
            card_a.join("A001_001/f2.DNG"),
            crate::camera::synth_dng_frame("SIGMA", "SIGMA fp", 3856, 2170, 12, 32804, None),
        )
        .unwrap();
        std::fs::write(card_a.join("S001_001/clip.wav"), b"RIFF-wave").unwrap();
        std::fs::write(
            card_b.join("B002_002/f1.DNG"),
            crate::camera::synth_dng_frame("TEST MAKE", "TEST MODEL", 1920, 1080, 12, 32803, None),
        )
        .unwrap();
        std::fs::write(card_b.join("T001_001/clip.wav"), b"RIFF-sidecar").unwrap();
        (base, card_a, card_b)
    }


    /// The multi pipeline's Args (the CLI's form — the flags only, no
    /// positionals — the invocation shape: `offload --source
    /// <treeA> <treeB> --dest <d1> <d2>`).
    pub(crate) fn multi_args(sources: Vec<PathBuf>, dests: Vec<PathBuf>) -> Args {
        Args {
            input: None,
            source: sources,
            dest: dests,
            to: vec![],
        }
    }


    /// A clean synthetic offload row (the pure-composition
    /// assertions' fixture — the idiom).
    pub(crate) fn row_ok(file: &str) -> OffloadRow {
        OffloadRow {
            file: file.into(),
            size: 1,
            source_sha: "s".into(),
            dest_sha: "s".into(),
            verdict: Verdict::Ok,
            detail: String::new(),
        }
    }


    /// A dirty synthetic offload row (the COPY_FAIL band's fixture).
    pub(crate) fn row_fail(file: &str) -> OffloadRow {
        OffloadRow {
            file: file.into(),
            size: 1,
            source_sha: "s".into(),
            dest_sha: "-".into(),
            verdict: Verdict::CopyFail,
            detail: "no space left".into(),
        }
    }


    /// Pre-seed the dest mirror with the source tree's bytes (the
    /// skip predicate's input): the named source files' bytes
    /// written to the dest's mirrored relpaths (`which` = None →
    /// every standalone-tree file). `flip` = the relpath to flip one
    /// byte (the size-match/sha-mismatch fall-through seed);
    /// `wrong_size` = the relpath to seed with a different-size
    /// payload (the size shortcut's negative seed).
    pub(crate) fn seed_mirror(dest: &Path, input: &Path, which: Option<&[&str]>, flip: Option<&str>, wrong_size: Option<&str>) {
        for rel in STANDALONE_RELS.iter().filter(|r| which.map_or(true, |w| w.contains(r))) {
            let src = std::fs::read(input.join(rel)).unwrap();
            let out: Vec<u8> = if let Some(f) = flip {
                if f == *rel {
                    let mut b = src;
                    b[0] ^= 0x01;
                    b
                } else {
                    src
                }
            } else if wrong_size == Some(*rel) {
                b"WRONG-SIZE-PRESEED-0123456789".to_vec()
            } else {
                src
            };
            let p = dest.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, out).unwrap();
        }
    }


    /// The detection's clip key space (`run_offload_multi`'s own
    /// derivation — the tests' core calls ride the same keys).
    pub(crate) fn clip_keys_of(input: &Path) -> Vec<String> {
        crate::camera::offload_detections(input)
            .unwrap()
            .clips
            .iter()
            .map(|c| c.key.clone())
            .collect()
    }


    /// The manifest's bytes modulo the free lines (the skip run's
    /// manifest vs the fresh-copy run's manifest: the `created:` +
    /// `dest:` header lines are the documented free lines — the wire
    /// contract otherwise byte-frozen, R-INV-M).
    pub(crate) fn manifest_masked(path: &Path) -> String {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("created:") && !l.starts_with("dest:"))
            .collect::<Vec<_>>()
            .join("\n")
    }


    /// The deterministic fan-out fixture content.
    pub(crate) fn fanout_content(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i.wrapping_mul(2654435761)) % 251) as u8).collect()
    }


    /// The pinned fixture mtime (the setup() pattern).
    pub(crate) fn fanout_mtime() -> std::time::SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)
    }


    /// Recurse `dir` collecting the file paths (the temp-residue
    /// walks' helper).
    pub(crate) fn fanout_files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let e = e.unwrap();
                let p = e.path();
                if e.file_type().unwrap().is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
        out
    }
