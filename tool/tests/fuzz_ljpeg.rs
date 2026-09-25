//! Fuzz corpus harness — the C-boundary pinned-outcome regression lock
//! (the 0.8.0 security work, ).
//!
//! Runs `frameprism decode <entry> <fresh outdir>` over every fixture in the
//! committed corpus (ci/fuzz-corpus/, env FUZZ_CORPUS overrides the dir),
//! classifies the observed outcome, and asserts it against the committed
//! pin (ci/fuzz-corpus/expected.tsv). Std only — no new dependencies.
//!
//! Run: cargo test --release --test fuzz_ljpeg
//! (OUTSIDE the `--lib` suite scope — the 350/0/1 suite pin is untouched.)
//!
//! Crash policy (docs/security.md): a crash on garbage is ACCEPTED and
//! pinned as a named class; a CORRUPTED WRITE (output where the pin says
//! none, or output bytes != the pin) or an INPUT MUTATION is the hard
//! gate — automatic FAIL, never pinnable. A timeout is a FAIL.
//!
//! The report is deterministic: sorted entry order, one line per entry
//! (`fuzz <name>: <class>`), then the summary line that check-fuzz.sh
//! pins (ci/pins.tsv `fuzz-outcome`).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Bounded wait per entry (the watchdog budget; a timeout is a FAIL).
const MAX_WAIT_SECS: u64 = 120;

enum Class {
    Ok,
    Refused,
    Crash,
    CorruptedWrite,
    InputMutated,
    Timeout,
}

impl Class {
    fn name(&self) -> &'static str {
        match self {
            Class::Ok => "ok",
            Class::Refused => "refused",
            Class::Crash => "crash",
            Class::CorruptedWrite => "corrupted-write",
            Class::InputMutated => "input-mutated",
            Class::Timeout => "timeout",
        }
    }
}

struct Pin {
    name: String,
    class: String,
    bytes: Option<u64>,
}

fn corpus_dir() -> PathBuf {
    match std::env::var("FUZZ_CORPUS") {
        Ok(p) => PathBuf::from(p),
        Err(_) => Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("ci")
            .join("fuzz-corpus")
            .to_path_buf(),
    }
}

fn profiles_env() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("profiles")
        .join("a001-sigma-fp.profile")
        .to_path_buf()
}

fn load_pins(corpus: &Path) -> Vec<Pin> {
    let tsv = corpus.join("expected.tsv");
    let text = fs::read_to_string(&tsv)
        .unwrap_or_else(|e| panic!("fuzz: cannot read {tsv:?}: {e}"));
    let mut pins = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut it = line.split('\t');
        let name = it.next().unwrap_or("").to_string();
        let class = it.next().unwrap_or("").to_string();
        let bytes = it.next().map(|b| b.parse::<u64>()).transpose();
        match &bytes {
            Ok(_) => {}
            Err(e) => panic!("fuzz: bad bytes pin in expected.tsv line {line:?}: {e}"),
        }
        if !matches!(class.as_str(), "ok" | "refused") {
            panic!("fuzz: unknown pin class {class:?} in expected.tsv (name {name:?})");
        }
        pins.push(Pin { name, class, bytes: bytes.unwrap() });
    }
    pins
}

/// Map a fixture file stem to its pin: exact match, or the pin name is a
/// prefix of the stem followed by `-` (the c5-be-magic-le row pins the
/// c5-be-magic-le-ifd fixture).
fn match_pin<'a>(pins: &'a [Pin], stem: &str) -> Option<&'a Pin> {
    let exact = pins.iter().find(|p| p.name == stem);
    if exact.is_some() {
        return exact;
    }
    let prefix: Vec<&Pin> = pins
        .iter()
        .filter(|p| stem.starts_with(&p.name) && stem[p.name.len()..].starts_with('-'))
        .collect();
    if prefix.len() == 1 {
        Some(prefix[0])
    } else {
        None // 0 or ambiguous -> the caller FAILs by name
    }
}

/// Run one entry and classify the observed outcome.
fn run_entry(bin: &Path, input: &Path, stem: &str, pin: &Pin) -> (Class, u64) {
    let in_bytes = fs::read(input)
        .unwrap_or_else(|e| panic!("fuzz: cannot read input {input:?}: {e}"));
    let outdir = std::env::temp_dir().join(format!("frameprism-fuzz-{stem}"));
    let _ = fs::remove_dir_all(&outdir); // removed first (stale-run safety)
    fs::create_dir_all(&outdir)
        .unwrap_or_else(|e| panic!("fuzz: cannot create outdir {outdir:?}: {e}"));

    let mut child: Child = Command::new(bin)
        .arg("decode")
        .arg(input)
        .arg(&outdir)
        .env(
            "FRAMEPRISM_PROFILES",
            profiles_env().to_string_lossy().as_ref(),
        )
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("fuzz: cannot spawn {bin:?} decode: {e}"));

    // Bounded wait — a std watchdog loop (try_wait every 1 s, max budget).
    let deadline = Instant::now() + Duration::from_secs(MAX_WAIT_SECS);
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    let s = child.wait();
                    match s {
                        Ok(s) => break s,
                        Err(e) => panic!("fuzz: cannot reap {stem} after kill: {e}"),
                    }
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(e) => panic!("fuzz: try_wait {stem}: {e}"),
        }
    };
    // Drain the pipes (the child is dead — the reads terminate).
    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut so) = child.stdout.take() {
        let _ = so.read_to_string(&mut out);
    }
    if let Some(mut se) = child.stderr.take() {
        let _ = se.read_to_string(&mut err);
    }
    let _ = (out, err); // captured for diagnostics; the report is deterministic

    // rc model: Some(code) as-is; a signal death (no code) is rc < 0.
    let rc: i32 = match status.code() {
        Some(c) => c,
        None => -1,
    };

    // Input integrity (re-read after the run).
    let input_intact = fs::read(input).map(|b| b == in_bytes).unwrap_or(false);

    // Output inventory.
    let mut out_files: u64 = 0;
    let mut out_bytes: u64 = 0;
    for ent in fs::read_dir(&outdir)
        .unwrap_or_else(|e| panic!("fuzz: cannot read outdir {outdir:?}: {e}"))
    {
        let ent = ent.unwrap();
        if let Ok(md) = ent.metadata() {
            if md.is_file() {
                out_files += 1;
                out_bytes += md.len();
            }
        }
    }
    let has_out = out_files > 0;

    // Classification (deterministic; the spec's classes).
    let class = if timed_out {
        Class::Timeout
    } else if !input_intact {
        Class::InputMutated
    } else if rc < 0 || rc == 101 {
        // signal death or panic; a partial output on an abnormal exit is a
        // corrupted write, not a crash.
        if has_out {
            Class::CorruptedWrite
        } else {
            Class::Crash
        }
    } else if rc == 0 {
        if !has_out {
            // claimed success, wrote nothing — a corrupted write.
            Class::CorruptedWrite
        } else if pin.class == "ok" {
            match pin.bytes {
                Some(b) if b == out_bytes => Class::Ok,
                _ => Class::CorruptedWrite,
            }
        } else {
            // any output where the pin says none.
            Class::CorruptedWrite
        }
    } else if rc == 1 || rc == 2 {
        if has_out {
            Class::CorruptedWrite
        } else {
            Class::Refused
        }
    } else {
        // any other nonzero exit: abnormal.
        if has_out {
            Class::CorruptedWrite
        } else {
            Class::Crash
        }
    };

    (class, out_bytes)
}

#[test]
fn fuzz_corpus_pinned_outcomes() {
    let corpus = corpus_dir();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_frameprism"));
    let pins = load_pins(&corpus);

    // The fixture set (sorted by filename — deterministic order).
    let mut entries: Vec<String> = Vec::new();
    for ent in fs::read_dir(&corpus)
        .unwrap_or_else(|e| panic!("fuzz: cannot read corpus dir {corpus:?}: {e}"))
    {
        let name = ent.unwrap().file_name().to_string_lossy().into_owned();
        if name.ends_with(".DNG") {
            entries.push(name);
        }
    }
    entries.sort();

    if entries.len() != 25 {
        panic!(
            "fuzz: expected 25 corpus entries, found {} ({corpus:?})",
            entries.len()
        );
    }

    let mut counts: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();

    for name in &entries {
        let stem = name.strip_suffix(".DNG").unwrap();
        let pin = match match_pin(&pins, stem) {
            Some(p) => p,
            None => {
                failures.push(format!(
                    "{name}: no expected.tsv row matches the fixture stem {stem:?} \
                    (exact or name+\"-\")"
                ));
                continue;
            }
        };
        let (class, out_bytes) = run_entry(&bin, &corpus.join(name), stem, pin);
        *counts.entry(class.name()).or_insert(0) += 1;
        // the report line uses the PIN name (the expected.tsv identity —
        // c5-be-magic-le pins the c5-be-magic-le-ifd fixture).
        println!("fuzz {}: {}", pin.name, class.name());
        if class.name() != pin.class {
            failures.push(format!(
                "{name}: observed class {} != pinned class {} for pin {stem:?} (bytes {out_bytes})",
                class.name(),
                pin.class
            ));
        }
    }

    // Every pin used exactly once (no orphan rows, no double matches).
    let mut used = vec![false; pins.len()];
    for name in &entries {
        let stem = name.strip_suffix(".DNG").unwrap();
        if let Some(p) = match_pin(&pins, stem) {
            if let Some(i) = pins.iter().position(|q| std::ptr::eq(q, p)) {
                used[i] = true;
            }
        }
    }
    for (i, u) in used.iter().enumerate() {
        if !u {
            failures.push(format!("expected.tsv row {} never matched a fixture", pins[i].name));
        }
    }

    // The hard gates: the never-pinnable classes must be zero.
    for bad in ["corrupted-write", "input-mutated", "timeout"] {
        if let Some(n) = counts.get(bad) {
            if *n > 0 {
                failures.push(format!("{bad}: {n} (hard gate — never pinnable)"));
            }
        }
    }

    let n = entries.len();
    let get = |k: &str| counts.get(k).copied().unwrap_or(0);
    println!(
        "fuzz: {n} entries, {} refused, {} ok, {} crash, {} corrupted-write, {} input-mutated",
        get("refused"),
        get("ok"),
        get("crash"),
        get("corrupted-write"),
        get("input-mutated")
    );

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("fuzz FAIL: {f}");
        }
        panic!("fuzz: {} pinned-outcome violation(s)", failures.len());
    }
}
