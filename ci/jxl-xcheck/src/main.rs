//! xcheck — the JXL independent-decoder cross-check.
//!
//! Decodes the committed JXL oracle108 gold (ci/oracle108/gold/{f10,f8} —
//! 4 × .jxl planes per frame, 8 total) with jxl-oxide — an INDEPENDENT
//! pure-Rust JXL decoder, a separate implementation from the pinned
//! libjxl cjxl/djxl build the tool's existing `--verify` round-trip
//! uses (a bug shared by that pair would not be caught there) — and
//! proves the decoded pixels are byte-exact against the source-frame
//! planes derived from the committed source DNGs:
//!
//!   frameprism <src> <tmp-enc> --codec j92 --verify --jobs 1
//!       (the j92 archive; --verify self-certifies archive == source
//!        pixels — the check-108.sh pattern; no libjxl anywhere)
//!   → frameprism decode --codec j92 <tmp-enc> <tmp-out>
//!       (the pure-Rust DNG path — the golden-model tile decode;
//!        no libjxl anywhere in it)
//!   → strict PAM parse (mirrors the strictness of
//!        frameprism::jxl::parse_pam_plane — the project header shape
//!        from jxl::pam_header)
//!   → frameprism::jxl::deinterleave(&p1, w, h)
//!       (the 4 expected planes, the pub fn — reuse, don't fork)
//!
//! The geometry is COMPUTED from the PAM (w×h full mosaic → w/2 × h/2
//! plane geometry), never hardcoded. The bit depth is read from the
//! JXL frame header per file; all 8 files must agree on ONE depth
//! (expected 12 — the PAM MAXVAL 4095 contract).
//!
//! Output contract (project style): named lines, no silent skips,
//! rc=0 ALL PASS / rc=1 named FAIL. The committed Cargo.lock pin
//! (name = "jxl-oxide" + version = "0.12.6") is asserted BEFORE any
//! decode; a drift is a named FAIL.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{anyhow, bail, Context, Result};
use jxl_oxide::image::BitDepth;
use jxl_oxide::JxlImage;

/// The pinned independent-decoder version (the lock must carry exactly
/// this — it is the latest release AND carries the
/// integer-overflow fixes: GHSA-5pmv-rx8r-wmv5 jxl-grid,
/// GHSA-2v8p-fqpx-2q3w jxl-modular, + the framebuffer soundness fix).
const JXL_OXIDE_PIN: &str = "0.12.6";

/// The oracle108 frame dirs (the two committed 10/8-bit source frames).
const FRAMES: [&str; 2] = ["f10", "f8"];

/// The 4 sub-plane names; index order = frameprism::jxl::deinterleave
/// (plane i = p1[y][x] with y%2==i/2, x%2==i%2 — the jxl::PLANES order).
const PLANES: [&str; 4] = ["p2_00", "p2_01", "p2_10", "p2_11"];

/// Expected bit depth: the PAM MAXVAL 4095 contract (the source planes
/// live in 0..=4095; all 8 gold files must declare it).
const EXPECTED_BITS: u32 = 12;

const PLANE_TOTAL: usize = FRAMES.len() * PLANES.len();

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            println!("xcheck FAIL: {e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo = manifest
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow!("unresolvable repo root from {}", manifest.display()))?
        .to_path_buf();
    let lock = manifest.join("Cargo.lock");
    let gold = repo.join("ci").join("oracle108").join("gold");
    let src = repo.join("ci").join("oracle108").join("src");
    let tool_bin = tool_bin()?;

    // --- the pin assertion (BEFORE any decode) ----------------------------
    // The committed Cargo.lock must carry name = "jxl-oxide" +
    // version = "0.12.6" (the =0.12.6 pin in Cargo.toml); a drift is a
    // named FAIL before any decode.
    let pin = lock_jxl_oxide_version(&lock)?;
    if pin != JXL_OXIDE_PIN {
        bail!(
            "lock pin drift: {} carries jxl-oxide {pin} (expected {JXL_OXIDE_PIN} — the =0.12.6 pin in {}/Cargo.toml)",
            lock.display(),
            manifest.display()
        );
    }
    println!("xcheck: jxl-oxide {pin} (the independent decoder — the committed Cargo.lock pin holds)");

    let tool_version = tool_version_line(&tool_bin)?;

    let mut common_bits: Option<u32> = None;

    for frame in FRAMES {
        let frame_src = src.join(frame);
        let frame_gold = gold.join(frame);
        let sidecar = frame_gold.join(format!("{frame}.jxl-checksums.tsv"));

        // The committed source dir carries exactly one .DNG.
        let dng = sole_dng(&frame_src, frame)?;
        let stem = dng
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .ok_or_else(|| anyhow!("xcheck {frame}: no file stem on {}", dng.display()))?;

        // --- step 0: the source-frame fingerprint the sidecar records ----
        let dng_bytes = std::fs::read(&dng)
            .with_context(|| format!("xcheck {frame}: read the source DNG {}", dng.display()))?;
        let dng_sha = frameprism::jxl::sha256_hex(&dng_bytes);
        let dng_name = dng
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .ok_or_else(|| anyhow!("xcheck {frame}: no file name on {}", dng.display()))?;
        let sidecar_sha = sidecar_src_sha256(&sidecar, frame, &dng_name)?;
        if dng_sha != sidecar_sha {
            bail!(
                "xcheck {frame}: src sha256 mismatch — {} is {dng_sha}, the sidecar src_frame_sha256 is {sidecar_sha}",
                dng_name
            );
        }
        println!("xcheck {frame}: src sha256 OK (matches the sidecar src_frame_sha256)");

        // --- the 2-step j92 source-side pipeline (spec step 1 corrected
        //     after the committed
        //     tool's rc=1 named refusal — decode targets encoded
        //     output; the source clips are raw Compression=1):
        //     encode --verify (the encode self-certifies archive ==
        //     source pixels — the check-108.sh pattern) → decode (the
        //     pure-Rust golden-model tile path). Zero libjxl anywhere.
        let tmp = std::env::temp_dir().join(format!("xcheck-{frame}-{}", std::process::id()));
        let tmp_enc = tmp.join("enc");
        let tmp_out = tmp.join("out");
        std::fs::create_dir_all(&tmp).with_context(|| format!("xcheck {frame}: create {}", tmp.display()))?;
        let enc_args = vec![
            frame_src.to_string_lossy().to_string(),
            tmp_enc.to_string_lossy().to_string(),
            "--codec".into(),
            "j92".into(),
            "--verify".into(),
            "--jobs".into(),
            "1".into(),
        ];
        tool_step(&tool_bin, &enc_args, &format!("xcheck {frame}: j92 encode --verify"))?;
        let dec_args = vec![
            "decode".into(),
            "--codec".into(),
            "j92".into(),
            tmp_enc.to_string_lossy().to_string(),
            tmp_out.to_string_lossy().to_string(),
        ];
        tool_step(&tool_bin, &dec_args, &format!("xcheck {frame}: j92 decode"))?;
        println!("xcheck {frame}: j92 round-trip OK (encode --verify rc=0, decode rc=0)");

        // --- the expected planes (the source-side truth) -------------------
        let pam_path = tmp_out.join(format!("{stem}.pam"));
        let pam = std::fs::read(&pam_path)
            .with_context(|| format!("xcheck {frame}: read the decoded PAM {}", pam_path.display()))?;
        let (w, h, p1) = strict_pam_parse(
            &pam,
            &format!("xcheck {frame}: the PAM {}", pam_path.display()),
        )?;
        if w % 2 != 0 || h % 2 != 0 {
            bail!(
                "xcheck {frame}: the PAM carries odd mosaic geometry {w}x{h} (the 2×2 sub-plane geometry requires even width + height)"
            );
        }
        let (pw, ph) = (w / 2, h / 2);
        let expected = frameprism::jxl::deinterleave(&p1, w, h);

        for i in 0..PLANES.len() {
            let plane = PLANES[i];
            let jxl = frame_gold.join(format!("{stem}_{plane}.jxl"));
            check_plane(&jxl, frame, &expected[i], pw, ph, &mut common_bits)?;
        }

        let _ = std::fs::remove_dir_all(&tmp); // best-effort; the log is the evidence
    }

    // --- the bit-depth contract: ONE depth across all 8 files, == 12 ------
    match common_bits {
        Some(b) if b == EXPECTED_BITS => {}
        Some(b) => bail!(
            "xcheck: bit-depth contract — the gold files agree on {b}-bit (expected {EXPECTED_BITS} — the PAM MAXVAL 4095 contract)"
        ),
        None => bail!("xcheck: no gold file was decoded (no bit depth recorded)"),
    }

    println!(
        "xcheck: {PLANE_TOTAL}/{PLANE_TOTAL} planes byte-exact (independent decoder jxl-oxide {JXL_OXIDE_PIN} vs source-derived planes)"
    );
    println!(
        "xcheck: version facts — jxl-oxide {JXL_OXIDE_PIN} (the committed lock pin: the integer-overflow fixes GHSA-5pmv-rx8r-wmv5 / GHSA-2v8p-fqpx-2q3w), {tool_version} (the source-side j92 pipeline)"
    );
    Ok(())
}

/// One gold plane file: the assert set (BEFORE comparing), the exact
/// integer recovery, the byte-exact compare.
fn check_plane(
    jxl: &Path,
    frame: &str,
    exp: &[u16],
    pw: u32,
    ph: u32,
    common_bits: &mut Option<u32>,
) -> Result<()> {
    let what = format!("xcheck {}/{}", frame, jxl.file_name().unwrap().to_string_lossy());
    let image = JxlImage::builder()
        .open(jxl)
        .map_err(|e| anyhow!("{what}: jxl-oxide {JXL_OXIDE_PIN} open: {e}"))?;

    // --- the asserts (before comparing) -----------------------------------
    let nk = image.num_loaded_keyframes();
    if nk != 1 {
        bail!("{what}: num_loaded_keyframes {nk} (expected 1)");
    }
    let fh = image
        .frame_header(0)
        .ok_or_else(|| anyhow!("{what}: no frame header for keyframe 0"))?;
    let bits = match fh.bit_depth {
        BitDepth::IntegerSample { bits_per_sample } => bits_per_sample,
        BitDepth::FloatSample { .. } => bail!(
            "{what}: the frame bit depth is a FloatSample (expected the integer Modular depth — the PAM MAXVAL 4095 contract)"
        ),
    };
    match *common_bits {
        Some(b) if b != bits => bail!(
            "{what}: bit depth {bits} (the other gold files declare {b} — the 8 files must agree on one depth)"
        ),
        _ => *common_bits = Some(bits),
    }
    if !(1..=24).contains(&bits) {
        bail!(
            "{what}: bit depth {bits} is outside 1..=24 — the exact-integer recovery (f32, 2^bits - 1) is not exact there; the PAM MAXVAL 4095 contract is 12-bit"
        );
    }
    let render = image
        .render_frame(0)
        .map_err(|e| anyhow!("{what}: render_frame(0): {e}"))?;
    if render.orientation() != 1 {
        bail!(
            "{what}: orientation {} (expected 1 — no orientation transform; the plane is compared in file order, no un-rotate)",
            render.orientation()
        );
    }
    let fb = render.image_all_channels();
    if fb.channels() != 1 {
        bail!(
            "{what}: {} channels (expected 1 — the oracle108 gold planes are single-channel grayscale)",
            fb.channels()
        );
    }
    if (fb.width(), fb.height()) != (pw as usize, ph as usize) {
        bail!(
            "{what}: {}x{} (expected {}x{} — the source-derived plane geometry)",
            fb.width(),
            fb.height(),
            pw,
            ph
        );
    }

    // --- the exact integer recovery ---------------------------------------
    // The frame buffer is normalized sample/(2^bits - 1) (jxl-image
    // BitDepth::parse_integer_sample — the same BitDepth value the
    // frame header carries). v = round(s * (2^bits - 1)) is EXACT for
    // every v <= 2^bits - 1: the f32 relative error (<= 2^-24 per
    // round) keeps the rounding interval width << 0.5.
    let max = (1u32 << bits) - 1;
    let maxf = max as f32;
    // A sample outside [0,1] (the decoder does not clamp) saturates in
    // the `as u16` cast (0 / 65535) and therefore mismatches — named,
    // never silent.
    let dec: Vec<u16> = fb.buf().iter().map(|s| (*s * maxf).round() as u16).collect();
    if dec.len() != exp.len() {
        bail!("{what}: {} decoded samples (expected {})", dec.len(), exp.len());
    }

    // --- the byte-exact compare (the first_diff idiom from jxl.rs) --------
    match first_diff(&dec, exp) {
        None => {
            println!("{what}: OK ({}x{} @ {bits}-bit, {} samples byte-exact)", pw, ph, exp.len());
        }
        Some(idx) => {
            // The named-failure evidence: the first 10 mismatches
            // (index + both values) + the min/max of both sides.
            let mut mism: Vec<(usize, u16, u16)> = Vec::new();
            for (i, (d, e)) in dec.iter().zip(exp.iter()).enumerate() {
                if d != e {
                    mism.push((i, *d, *e));
                    if mism.len() == 10 {
                        break;
                    }
                }
            }
            let list: Vec<String> = mism
                .iter()
                .map(|(i, d, e)| format!("idx {i}: decoded {d}, expected {e}"))
                .collect();
            let (dmin, dmax) = (*dec.iter().min().unwrap(), *dec.iter().max().unwrap());
            let (emin, emax) = (*exp.iter().min().unwrap(), *exp.iter().max().unwrap());
            bail!(
                "{what}: NOT byte-exact — first mismatch at index {idx} (decoded {}, expected {}); first {}: {}; decoded min/max {dmin}..={dmax}, expected min/max {emin}..={emax} ({} samples)",
                dec[idx],
                exp[idx],
                mism.len(),
                list.join("; "),
                dec.len()
            );
        }
    }
    Ok(())
}

/// The committed source dir carries exactly one .DNG (else a named FAIL).
fn sole_dng(dir: &Path, frame: &str) -> Result<PathBuf> {
    let mut dngs: Vec<PathBuf> = Vec::new();
    for e in std::fs::read_dir(dir)
        .with_context(|| format!("xcheck {frame}: read the src dir {}", dir.display()))?
    {
        let e = e.with_context(|| format!("xcheck {frame}: read dir entry in {}", dir.display()))?;
        let p = e.path();
        if p.is_file()
            && p.extension()
                .and_then(|x| x.to_str())
                .map(|x| x.eq_ignore_ascii_case("dng"))
                .unwrap_or(false)
        {
            dngs.push(p);
        }
    }
    dngs.sort();
    if dngs.len() != 1 {
        bail!(
            "xcheck {frame}: the src dir {} carries {} .DNG files (expected exactly 1)",
            dir.display(),
            dngs.len()
        );
    }
    Ok(dngs.pop().unwrap())
}

/// The sidecar's `src_frame_sha256` column (the source-frame fingerprint
/// the sidecar already records): the TSV header names the columns; every
/// data row must name the committed source DNG and carry the same value
/// (fixture/sidecar integrity — a drift is a named FAIL).
fn sidecar_src_sha256(sidecar: &Path, frame: &str, dng_name: &str) -> Result<String> {
    let text = std::fs::read_to_string(sidecar)
        .with_context(|| format!("xcheck {frame}: read the sidecar {}", sidecar.display()))?;
    let lines: Vec<&str> = text.lines().collect();
    let header = lines
        .first()
        .copied()
        .ok_or_else(|| anyhow!("xcheck {frame}: the sidecar {} is empty", sidecar.display()))?;
    let cols: Vec<&str> = header.split('\t').collect();
    let col = |name: &str| {
        cols.iter()
            .position(|c| *c == name)
            .ok_or_else(|| anyhow!("xcheck {frame}: the sidecar {} has no {name} column", sidecar.display()))
    };
    let ci_sha = col("src_frame_sha256")?;
    let ci_src = col("src_frame")?;
    let mut sha: Option<String> = None;
    for (rowno, row) in lines.iter().enumerate().skip(1) {
        let f: Vec<&str> = row.split('\t').collect();
        if f.len() != cols.len() {
            bail!(
                "xcheck {frame}: the sidecar row {} has {} columns (expected {})",
                rowno + 1,
                f.len(),
                cols.len()
            );
        }
        if f[ci_src] != dng_name {
            bail!(
                "xcheck {frame}: the sidecar row {} names src_frame {} (expected {dng_name} — the committed source DNG)",
                rowno + 1,
                f[ci_src]
            );
        }
        match &sha {
            None => sha = Some(f[ci_sha].to_string()),
            Some(s) if *s != f[ci_sha] => bail!(
                "xcheck {frame}: the sidecar src_frame_sha256 disagrees across rows ({s} vs {})",
                f[ci_sha]
            ),
            Some(_) => {}
        }
    }
    sha.ok_or_else(|| anyhow!("xcheck {frame}: the sidecar {} has no data rows", sidecar.display()))
}

/// The strict P7 plane-PAM parse — mirrors the strictness of
/// `frameprism::jxl::parse_pam_plane` (tool/src/jxl.rs; that fn is
/// private, so the harness carries the mirrored parser — same rules:
/// P7 + exactly the WIDTH/HEIGHT/DEPTH/MAXVAL/TUPLTYPE keys, DEPTH 1,
/// MAXVAL 4095, TUPLTYPE GRAYSCALE, then w*h*2 big-endian u2 bytes; any
/// deviation is an error — a verify tool must fail loud on format
/// drift). The project header shape: `jxl::pam_header` (P7\nWIDTH w\n
/// HEIGHT h\nDEPTH 1\nMAXVAL 4095\nTUPLTYPE GRAYSCALE\nENDHDR\n).
/// Here the header's w×h is the geometry source of truth (the full p1
/// mosaic; the plane geometry is w/2 × h/2 — computed, never hardcoded).
fn strict_pam_parse(data: &[u8], what: &str) -> Result<(u32, u32, Vec<u16>)> {
    const END: &[u8] = b"ENDHDR\n";
    if data.len() < END.len() {
        bail!("{what}: too short for a PAM header ({} bytes)", data.len());
    }
    let end = data
        .windows(END.len())
        .position(|w| w == END)
        .ok_or_else(|| anyhow!("{what}: not a P7 PAM (no ENDHDR)"))?;
    let header = std::str::from_utf8(&data[..end])
        .map_err(|_| anyhow!("{what}: PAM header is not UTF-8"))?;
    let mut w = 0u32;
    let mut h = 0u32;
    let mut depth: i64 = 0;
    let mut maxval: i64 = 0;
    let mut tupl: Option<&str> = None;
    let mut toks = header.split_whitespace();
    match toks.next() {
        Some("P7") => {}
        other => bail!("{what}: expected P7 header, got {other:?}"),
    }
    while let Some(key) = toks.next() {
        let val = toks
            .next()
            .ok_or_else(|| anyhow!("{what}: dangling PAM key {key}"))?;
        match key {
            "WIDTH" => w = val
                .parse()
                .map_err(|_| anyhow!("{what}: bad WIDTH {val}"))?,
            "HEIGHT" => h = val
                .parse()
                .map_err(|_| anyhow!("{what}: bad HEIGHT {val}"))?,
            "DEPTH" => depth = val
                .parse()
                .map_err(|_| anyhow!("{what}: bad DEPTH {val}"))?,
            "MAXVAL" => maxval = val
                .parse()
                .map_err(|_| anyhow!("{what}: bad MAXVAL {val}"))?,
            "TUPLTYPE" => tupl = Some(val),
            other => bail!("{what}: unexpected PAM key {other}"),
        }
    }
    if depth != 1 {
        bail!("{what}: DEPTH {depth} (expected 1)");
    }
    if maxval != 4095 {
        bail!("{what}: MAXVAL {maxval} (expected 4095)");
    }
    if tupl != Some("GRAYSCALE") {
        bail!("{what}: TUPLTYPE {tupl:?} (expected GRAYSCALE)");
    }
    if w == 0 || h == 0 {
        bail!("{what}: zero geometry {w}x{h}");
    }
    let payload = &data[end + END.len()..];
    let want = (w as usize) * (h as usize) * 2;
    if payload.len() != want {
        bail!("{what}: payload {} bytes (expected {want})", payload.len());
    }
    let mut out = vec![0u16; want / 2];
    for (i, pair) in payload.chunks_exact(2).enumerate() {
        out[i] = u16::from_be_bytes([pair[0], pair[1]]);
    }
    Ok((w, h, out))
}

/// First index where the two planes differ (None = identical) — the
/// first_diff idiom from tool/src/jxl.rs (the fn there is private;
/// mirrored here).
fn first_diff(a: &[u16], b: &[u16]) -> Option<usize> {
    a.iter().zip(b.iter()).position(|(x, y)| x != y)
}

/// The lock pin assertion: the committed Cargo.lock must carry
/// `name = "jxl-oxide"` + the adjacent `version = "..."` line.
fn lock_jxl_oxide_version(lock: &Path) -> Result<String> {
    let text = std::fs::read_to_string(lock)
        .with_context(|| format!("read the committed lock {}", lock.display()))?;
    let lines: Vec<&str> = text.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.trim() == r#"name = "jxl-oxide""#)
        .ok_or_else(|| anyhow!("the committed lock {} has no `name = \"jxl-oxide\"` entry", lock.display()))?;
    for l in lines.iter().skip(start + 1) {
        let t = l.trim();
        if t == "[[package]]" {
            bail!(
                "the committed lock {}: no version line follows the jxl-oxide name (malformed entry)",
                lock.display()
            );
        }
        if let Some(rest) = t.strip_prefix("version = ") {
            return Ok(rest.trim_matches('"').to_string());
        }
    }
    bail!(
        "the committed lock {}: no version line follows the jxl-oxide name",
        lock.display()
    );
}

/// The frameprism release binary — a sibling of this harness's exe
/// (the shared CARGO_TARGET_DIR/release dir; check-xcheck.sh ensures it
/// is current before the harness runs).
fn tool_bin() -> Result<PathBuf> {
    let exe = std::env::current_exe().with_context(|| "locate the harness binary")?;
    let bin = exe.with_file_name("frameprism");
    if !bin.is_file() {
        bail!(
            "the frameprism release binary is missing: {} (run `cargo build --release` in tool/ with the shared CARGO_TARGET_DIR)",
            bin.display()
        );
    }
    Ok(bin)
}

/// The tool's version fact line (first line of `frameprism --version`).
fn tool_version_line(bin: &Path) -> Result<String> {
    let out = Command::new(bin)
        .arg("--version")
        .output()
        .with_context(|| format!("run {} --version", bin.display()))?;
    if !out.status.success() {
        bail!(
            "{} --version failed (rc {:?})",
            bin.display(),
            out.status.code()
        );
    }
    let line = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if line.is_empty() {
        bail!("{} --version printed no line", bin.display());
    }
    Ok(line)
}

/// Run a tool CLI step (named `what`); a non-zero rc is a named FAIL
/// carrying the rc + the last 5 log lines (the failure evidence).
fn tool_step(bin: &Path, args: &[String], what: &str) -> Result<()> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("{what}: spawn {}", bin.display()))?;
    if !out.status.success() {
        let mut log = String::from_utf8_lossy(&out.stdout).to_string();
        let err = String::from_utf8_lossy(&out.stderr);
        if !err.is_empty() {
            if !log.is_empty() {
                log.push('\n');
            }
            log.push_str(&err);
        }
        let tail: Vec<&str> = log.lines().rev().take(5).collect::<Vec<_>>().into_iter().rev().collect();
        bail!("{what}: rc={} — {}", out.status.code().unwrap_or(-1), tail.join(" | "));
    }
    Ok(())
}
