//! JXL flag path (`--codec jxl` + `--jxl-effort {4|7|9}`, default e7):
//! per-frame 4-plane 2×2 modular lossless JXL.
//!
//! Contract:
//! - lossless only, effort = the ladder via `--jxl-effort`
//!   (4|7|9 only — unmeasured efforts are rejected by clap; default
//! behavior = 7, the decision "e7 default + effort flag": e7
//!   4.6× faster encode than e9 for +1.3…2.7% size; e4 10.9× for
//!   +1.9…10.1%).
//! - Per-frame output unit = 4 × `.jxl`: the 2×2 sub-planes
//!   `p2_rc` = p1 rows%2==r, cols%2==c (each w/2 × h/2; bit-depth is
//!   carried natively — 10/8-bit values flow through the same
//!   MAXVAL 4095 container). The
//!   p1-mosaic file is not a tool output (p1 always loses; the
//!   4-plane sum is the shippable unit and the size-claim basis).
//! - Eligibility: the SAME
//!   predicate as the j92 default path (`worker::is_archive_layout`):
//!   geometry ∈ {3856×2170, 1936×1090} × bits ∈ {8,10,12} — the v1
//!   12-bit-only named refusal is lifted. The 2×2 sub-plane pipeline
//!   is bit-depth-agnostic: the PAM stays MAXVAL 4095 u16 (bit-depth-
//!   invariant — probed on the pinned cjxl/djxl: byte-exact
//!   round-trip with the MAXVAL preserved), so the strict verify
//!   parser is untouched and the 12-bit byte-identity contract holds.
//! - Encoder = `cjxl 0.12.0` subprocess (version parity with the
//! measured sizes), decoder = `djxl 0.12.0` subprocess (decision:
//!   v1 = subprocess for version parity + zero new dependencies; the
//!   `jxl` Rust crate v0.7.3, decoder-only, is the documented v2
//!   swap-in — NOT added here).
//! - PAM writer (fixed, byte-exact format): P7, TUPLTYPE
//!   GRAYSCALE, MAXVAL 4095, big-endian u2 payload. MAXVAL 4095 is
//!   the container's 12-bit ceiling — 10-bit (≤1023) and 8-bit (≤255)
//!   sources archive under the same header and sidecar (no per-depth
//!   format work; the sidecar is UNCHANGED).
//! - Mandatory sidecar `<OUT>/<CLIP>.jxl-checksums.tsv` (per file: file,
//!   size, sha256, crc32c, plane, src_frame, src_frame_sha256,
//!   jxl_version, effort) — per-file sha256 is mandatory
//!   regardless of container (JXL bundles are incompressible → plain
//!   tar + this sidecar).
//! - Atomic writes: cjxl encodes to a temp name; the final `.jxl` name
//!   is taken only on rc=0 (a crash never leaves a renamed partial).
//! - `--verify`: sidecar sha256 re-check first (fast failure — only when
//!   the sidecar exists, i.e. a verification pass over existing
//!   output), then djxl decode of all 4 planes → strict PAM parse →
//! re-interleave → p1 vs the PER-DEPTH source unpack, byte-exact
//! (the tool's analog of the measured per-plane rtcheck; the mandatory
//!   gate at all depths). At 12-bit a second gate re-packs p1' with
//!   pack12 against the source strip prefix (the prep file-level
//!   oracle); at 10/8-bit that strip-prefix form is OFF (there is no
//!   pack10/pack8 — a NAMED FOLLOW-UP), so gate (3) alone is the gate.
//! - Threading: the encode is a
//!   REEL-WIDE plane pool (not per-frame — a frame has only 4
//!   planes, and the measured best shape W14_T1 needs reel-wide
//!   W=14). `parallel` (from `--jxl-parallel`): 0 = auto = all cores,
//!   1 = the serial 0.3.0 flow (the escape hatch), >= 2 = W
//!   concurrent `cjxl` processes over the flattened reel planes
//!   (std::thread + std::sync — no new crates). `threads` (from
//!   `--jobs`) is unchanged: the per-cjxl budget (0 = the binary's
//!   default threads, all cores — the `j14` flag; N = `--num_threads=N`,
//! the `j1` mechanism). The grid measured
//!   the (W,T) shapes — W14_T1 16.131 s vs the serial W1_T14 23.793 s
//!   (32.2%) — and the output bytes are invariant at every (W,T)
//!   (75/75 rows sha-identical to the baseline): the per-plane cjxl
//!   args are the 0.3.0 args byte-for-byte, so the CI oracle stays the
//!   byte-identity arbiter at every setting.
//! - PAM temps (the proven grid-driver approach): the full PAM set
//!   (4 temps per encode frame, 1.2 GB for the 72f UHD reel) is
//!   pre-written BEFORE the pool runs; the disk gate (free <
//!   max(2 GB, PAM set + 800 MB margin) — a named loud refusal) fires
//!   before the first PAM byte; the PAMs are removed on both the
//!   success and the failure paths.
//! - Failure: the first failed plane stops new dispatch (the
//!   completed planes stay on disk); the named FAIL carries the frame,
//!   plane, cjxl rc + stderr tail; the run exits non-zero and the
//!   sidecar is NOT written (success-only, as before).
//! - sha256 is hand-rolled (FIPS 180-4) — no new crate; the style
//!   is self-contained digests (cf. `checksums.rs` crc32c). Correctness
//!   gate: the suite recomputes every sidecar sha256 with Python `hashlib`
//!   (independent implementation) + `shasum -a 256` spot checks.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};

use crate::pack12::{pack12, unpack8, unpack10, unpack12};
use crate::worker::{FrameStats, Outcome, Report};

/// The 4 output planes per frame (the 2×2 split of p1; `p2_rc` =
/// rows%2==r, cols%2==c — `prep/prep.py` convention). Plane index
/// r*2+c: p2_00=0, p2_01=1, p2_10=2, p2_11=3.
pub const PLANES: [&str; 4] = ["p2_00", "p2_01", "p2_10", "p2_11"];

/// JXL run options (cf. `worker::ReferenceDctOpts`).
#[derive(Clone, Debug)]
pub struct JxlOpts {
    /// cjxl binary (path or PATH name; default `cjxl`).
    pub cjxl_bin: PathBuf,
    /// djxl binary (path or PATH name; default `djxl`).
    pub djxl_bin: PathBuf,
    /// Encoder/decoder thread budget (from `--jobs`): 0 = the binary's
    /// default (all cores); N > 0 = `--num_threads=N` (the j1 mechanism).
    pub threads: usize,
    /// Encoder effort (from `--jxl-effort`, default 7 — the 
    /// measured ladder 4|7|9 only; see the module docs). Flows into
    /// the cjxl `-e` invocation and the sidecar `effort` column.
    pub effort: u32,
    /// Encode parallelism (from `--jxl-parallel`): the number of
    /// concurrent cjxl processes — the planes in
    /// flight across the WHOLE reel. 0 = auto = all cores; 1 = the
    /// serial 0.3.0 flow (the escape hatch); >= 2 = the W-deep pool
    /// (std::thread + std::sync — no new crates). The per-cjxl
    /// thread budget is `threads` (the T dimension) — unchanged. The
    /// output bytes are invariant at every (parallel, threads)
    /// setting (the grid: 75/75 rows sha-identical).
    pub parallel: usize,
}

/// The mandatory sidecar file name for a clip (cf.
/// `checksums::checksums_name`).
pub fn sidecar_name(clip: &str) -> String {
    format!("{clip}.jxl-checksums.tsv")
}

// ---------------------------------------------------------------------------
// sha256 (FIPS 180-4, self-contained — see the module docs)
// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
];

/// The pinned read buffer for the streaming sha256 sites (the
/// bounded-memory contract: the per-file working set is this
/// buffer, never the file).
pub const SHA256_CHUNK: usize = 1024 * 1024;

/// One FIPS 180-4 compression over a 64-byte block (the one-shot
/// sha256's inner loop, extracted — the SAME constants, the SAME
/// compression: byte-identical by construction; the property test
/// `sha256_streaming_property` proves it).
fn compress_block(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// The incremental SHA-256 state (the streaming helper):
/// the one-shot body split into `update` (buffers the partial block,
/// compresses full 64-byte blocks) + `finalize` (the FIPS 180-4
/// padding — 0x80 + zeros + the 8-byte big-endian BIT count, the
/// overflow-safe wrapping bit count, as the one-shot). Any chunking
/// of `update` yields the same digest (the property test proves it
/// across chunk sizes 1…1 MiB).
pub struct Sha256State {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: u8,
    total: u64,
}

impl Sha256State {
    pub fn new() -> Self {
        Sha256State {
            h: SHA256_H0,
            buf: [0u8; 64],
            buf_len: 0,
            total: 0,
        }
    }
}

impl Default for Sha256State {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256State {
    /// Feed a chunk (any size; the partial block is buffered).
    pub fn update(&mut self, data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        let mut off = 0usize;
        if self.buf_len > 0 {
            let take = (64 - self.buf_len as usize).min(data.len());
            self.buf[self.buf_len as usize..self.buf_len as usize + take]
                .copy_from_slice(&data[..take]);
            self.buf_len += take as u8;
            off = take;
            if self.buf_len == 64 {
                compress_block(&mut self.h, &self.buf);
                self.buf_len = 0;
            }
        }
        while off + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[off..off + 64]);
            compress_block(&mut self.h, &block);
            off += 64;
        }
        if off < data.len() {
            let take = data.len() - off;
            self.buf[..take].copy_from_slice(&data[off..]);
            self.buf_len = take as u8;
        }
    }

    /// The FIPS 180-4 padding + the digest (consumes the state).
    pub fn finalize(self) -> [u8; 32] {
        let mut h = self.h;
        let bit_len = self.total.wrapping_mul(8);
        let mut rem = self.buf;
        let mut rem_len = self.buf_len as usize;
        rem[rem_len] = 0x80;
        rem_len += 1;
        if rem_len > 56 {
            while rem_len < 64 {
                rem[rem_len] = 0;
                rem_len += 1;
            }
            compress_block(&mut h, &rem);
            rem_len = 0;
        }
        while rem_len < 56 {
            rem[rem_len] = 0;
            rem_len += 1;
        }
        rem[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress_block(&mut h, &rem);
        sha256_bytes(h)
    }
}

fn sha256_bytes(h: [u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// SHA-256 digest (FIPS 180-4) — the one-shot, re-implemented over
/// the incremental state (one `update` + `finalize`:
/// every existing call site keeps its exact output; the oracles
/// byte-frozen is the proof).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut s = Sha256State::new();
    s.update(data);
    s.finalize()
}

/// SHA-256 lowercase hex of a digest (the one format — the one-shot
/// hex + the streaming sites share it).
pub fn sha256_hex_of(digest: [u8; 32]) -> String {
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// SHA-256 lowercase hex digest.
pub fn sha256_hex(data: &[u8]) -> String {
    sha256_hex_of(sha256(data))
}

/// The streaming file sha256 (the bounded-memory read:
/// `SHA256_CHUNK`-sized reads into a re-used buffer, never the whole
/// file in a `Vec`). The io error propagates RAW — the caller wraps
/// it with the site's existing context wording (the "re-scan" /
/// "unreadable" wordings are unchanged per site).
pub fn sha256_stream_path(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut s = Sha256State::new();
    let mut buf = vec![0u8; SHA256_CHUNK];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        s.update(&buf[..n]);
    }
    Ok(sha256_hex_of(s.finalize()))
}

/// The streaming file digest triple (the bounded read:
/// size + sha256 + crc32c in ONE `SHA256_CHUNK`-buffered pass,
/// never the whole file in a `Vec` — the audit module's re-verify
/// single-pass shape). The io error propagates RAW — the caller
/// wraps it with the site's existing context wording.
pub fn digest_stream_path(path: &Path) -> std::io::Result<(u64, String, u32)> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut sha = Sha256State::new();
    let mut crc = 0xFFFF_FFFFu32;
    let mut total = 0u64;
    let mut buf = vec![0u8; SHA256_CHUNK];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
        for &b in &buf[..n] {
            crc = (crc >> 8) ^ crate::checksums::TABLE[((crc ^ b as u32) & 0xFF) as usize];
        }
        total += n as u64;
    }
    Ok((
        total,
        sha256_hex_of(sha.finalize()),
        crc ^ 0xFFFF_FFFF,
    ))
}

// ---------------------------------------------------------------------------
// PAM (fixed, byte-exact format) + strict decode-side parse
// ---------------------------------------------------------------------------

/// The exact PAM header the writer emits for every encode (P7, TUPLTYPE
/// GRAYSCALE, MAXVAL 4095) — do not reformat: byte-identity of the cjxl
/// input is part of the byte-identity gate.
pub fn pam_header(w: u32, h: u32) -> String {
    format!("P7\nWIDTH {w}\nHEIGHT {h}\nDEPTH 1\nMAXVAL 4095\nTUPLTYPE GRAYSCALE\nENDHDR\n")
}

/// Parse a strict P7 plane PAM (the djxl 0.12.0 output for a 12-bit
/// grayscale JXL): P7 header with exactly WIDTH/HEIGHT/DEPTH 1/MAXVAL
/// 4095/TUPLTYPE GRAYSCALE, then `w*h*2` big-endian u2 bytes. Any
/// deviation is an error (a verify tool must fail loud on format drift).
fn parse_pam_plane(data: &[u8], what: &str, want_w: u32, want_h: u32) -> Result<Vec<u16>> {
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
    if w != want_w || h != want_h {
        bail!("{what}: {w}x{h} (expected {want_w}x{want_h})");
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
    Ok(out)
}

/// Per-depth source unpack: the same
/// dispatch as the j92 default path (worker.rs) — 8 → `unpack8`,
/// 10 → `unpack10` (the DNG-SDK per-row 4-samples/5-byte bitstream;
/// both archive geometries satisfy width%4==0), 12 → `unpack12`.
/// Any other depth is refused loudly — the primary gate is the
/// `is_archive_layout` eligibility predicate (which already bounds the
/// depth to {8,10,12}); this is the loud fallback behind it.
fn unpack_for_depth(
    packed: &[u8],
    bps: u16,
    width: u32,
    height: u32,
) -> Result<Vec<u16>> {
    Ok(match bps {
        8 => unpack8(packed, width, height)?,
        10 => unpack10(packed, width, height)?,
        12 => unpack12(packed, width, height)?,
        other => bail!("unsupported bit depth {other} (the archive layouts are 8/10/12-bit)"),
    })
}

// ---------------------------------------------------------------------------
// 2×2 de-interleave / re-interleave (the p1 <-> p2_XX transform)
// ---------------------------------------------------------------------------

/// Split p1 (w×h row-major u16, w/h even) into the 4 sub-planes
/// (w/2 × h/2 each, row-major). Plane i = r*2+c holds p1[y][x] with
/// y%2==r, x%2==c — the `prep/prep.py` convention.
pub fn deinterleave(p1: &[u16], w: u32, h: u32) -> [Vec<u16>; 4] {
    debug_assert_eq!(w % 2, 0);
    debug_assert_eq!(h % 2, 0);
    let (pw, ph) = ((w / 2) as usize, (h / 2) as usize);
    let plane_len = pw * ph;
    let mut planes: [Vec<u16>; 4] = [
        vec![0u16; plane_len],
        vec![0u16; plane_len],
        vec![0u16; plane_len],
        vec![0u16; plane_len],
    ];
    let (w, h) = (w as usize, h as usize);
    for y in 0..h {
        let row = y * w;
        for x in 0..w {
            let plane = (y & 1) * 2 + (x & 1);
            planes[plane][(y / 2) * pw + x / 2] = p1[row + x];
        }
    }
    planes
}

/// Inverse of [`deinterleave`]: the 4 sub-planes → p1 (w×h row-major).
pub fn reinterleave(planes: [&[u16]; 4], w: u32, h: u32) -> Vec<u16> {
    debug_assert_eq!(w % 2, 0);
    debug_assert_eq!(h % 2, 0);
    let pw = (w / 2) as usize;
    let (w, h) = (w as usize, h as usize);
    let mut out = vec![0u16; w * h];
    for y in 0..h {
        let row = y * w;
        for x in 0..w {
            out[row + x] = planes[(y & 1) * 2 + (x & 1)][(y / 2) * pw + x / 2];
        }
    }
    out
}

// ---------------------------------------------------------------------------
// subprocess plumbing
// ---------------------------------------------------------------------------

/// First line of `bin --version` (the sidecar `jxl_version` column).
/// Fails fast (named) when the binary is missing or errors — so a bogus
/// `--cjxl-bin` exits non-zero BEFORE anything is written (atomicity).
fn version_line(bin: &Path) -> Result<String> {
    let out = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .with_context(|| format!("run {} --version", bin.display()))?;
    if !out.status.success() {
        bail!(
            "{} --version failed (rc {:?}): {}",
            bin.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string())
}

/// `cjxl` argument prefix: `-e <effort> -d 0` (+ the j1 mechanism
/// `--num_threads=N` when a thread budget is set; 0 = the binary's
/// default threads).
fn cjxl_args(threads: usize, effort: u32) -> Vec<String> {
    let mut args =
        vec!["-e".to_string(), effort.to_string(), "-d".to_string(), "0".to_string()];
    if threads > 0 {
        args.push(format!("--num_threads={threads}"));
    }
    args
}

/// `djxl` argument prefix: no effort/distance flags (decode-only tool);
/// `--num_threads=N` only when a thread budget is set (0.12.0 accepts
/// it; 0 = the binary's default threads). The decode is byte-invariant
/// to the thread count (verified here: j1 == default-thread
/// output byte-identical).
fn djxl_args(threads: usize) -> Vec<String> {
    let mut args = Vec::new();
    if threads > 0 {
        args.push(format!("--num_threads={threads}"));
    }
    args
}

/// Resolve the plane-pool width (`--jxl-parallel`): 0 = auto = all
/// cores; N > 0 = exactly N concurrent cjxl processes (no hard
/// cap — the grid showed the oversubscription penalty is mild,
/// +2.3–3.3%, not a cliff).
pub fn resolve_parallel(w: usize) -> usize {
    if w == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        w
    }
}

/// The `--jxl-parallel` scope guard (mirrors the `--jxl-effort`
/// guard in main.rs): the flag is meaningful only with `--codec jxl`.
/// `Some(msg)` = the named refusal (main.rs bails with it → rc=2);
/// `None` = no refusal (the flag is absent, or the codec is jxl).
pub fn parallel_scope_refusal(codec: &str, flag_given: bool) -> Option<String> {
    if flag_given && !codec.eq_ignore_ascii_case("jxl") {
        Some(format!(
            "--jxl-parallel requires --codec jxl (got --codec {codec})"
        ))
    } else {
        None
    }
}

/// The disk-gate floor before the pam-set pre-write: the 2 GB
/// gate (the A001_001 1.2 GB PAM set + the 800 MB stop-rule
/// margin) generalized to any reel — for a bigger PAM set the floor
/// rises to the estimate + the 800 MB margin (never looser than the
/// 2 GB gate).
pub fn disk_gate_required(pam_estimate: u64) -> u64 {
    const TWO_GB: u64 = 2 * 1024 * 1024 * 1024;
    const MARGIN_800_MB: u64 = 800 * 1024 * 1024;
    TWO_GB.max(pam_estimate.saturating_add(MARGIN_800_MB))
}

/// Free bytes on the volume containing `dir` (POSIX `df -k`, the last
/// line's Avail column in 1K blocks — macOS and GNU df agree on the
/// column position). Err (named) when the probe cannot be run or
/// parsed — the disk gate then refuses loudly (it never proceeds
/// without the measurement). `pub`: the
/// preflight space guard reuses this exact df probe (REUSE
/// the mechanism, do not invent a second one) — the only jxl.rs
/// change here.
pub fn free_bytes(dir: &Path) -> Result<u64> {
    let out = std::process::Command::new("df")
        .arg("-k")
        .arg(dir)
        .output()
        .with_context(|| "run df -k (the disk gate needs a free-space measurement)")?;
    if !out.status.success() {
        bail!(
            "df -k {} failed (rc {:?}): {}",
            dir.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let last = text
        .lines()
        .next_back()
        .ok_or_else(|| anyhow!("df -k produced no output"))?;
    let avail = last
        .split_whitespace()
        .nth(3)
        .ok_or_else(|| anyhow!("df -k: cannot parse the Avail column: {last:?}"))?;
    let kb: u64 = avail
        .parse()
        .map_err(|_| anyhow!("df -k: bad Avail value {avail:?}"))?;
    Ok(kb.saturating_mul(1024))
}

/// The exact PAM bytes for one plane (the header — do not
/// reformat — + the big-endian u2 payload; the byte-identity of the
/// cjxl input is part of the byte-identity gate).
fn plane_pam_bytes(pw: u32, ph: u32, plane: &[u16]) -> Vec<u8> {
    let mut pam = Vec::with_capacity(pam_header(pw, ph).len() + plane.len() * 2);
    pam.extend_from_slice(pam_header(pw, ph).as_bytes());
    for s in plane {
        pam.extend_from_slice(&s.to_be_bytes());
    }
    pam
}

/// The full per-plane `cjxl` argument list — the single source for
/// the W=1 serial path and the pool workers (byte-identical to
/// the 0.3.0 per-plane args at the same (threads, effort)).
fn encode_cmd_args(threads: usize, effort: u32, pam: &str, out: &str) -> Vec<String> {
    let mut args = cjxl_args(threads, effort);
    args.push(pam.to_string());
    args.push(out.to_string());
    args
}

/// The loud refusals of the encode path (the 0.3.0 named messages,
/// verbatim): parse → eligibility (`is_archive_layout`, the same
/// predicate as the j92 default path) → even width/height (the 2×2
/// de-interleave). → (the parsed frame, the plane geometry w/2 ×
/// h/2).
fn frame_geometry(buf: &[u8]) -> Result<(crate::tiff::Frame, u32, u32)> {
    let frame = crate::tiff::read(buf)?;
    if !crate::worker::is_archive_layout(&frame) {
        bail!(
            "--codec jxl accepts the archive layouts only: 3856×2170 or 1936×1090 at 8/10/12-bit (the same eligibility as the j92 default codec); got {w}×{h} at {bps}-bit",
            w = frame.width,
            h = frame.height,
            bps = frame.bits_per_sample
        );
    }
    if frame.width % 2 != 0 || frame.height % 2 != 0 {
        bail!(
            "--codec jxl requires even width/height (2×2 de-interleave); got {}x{}",
            frame.width,
            frame.height
        );
    }
    let (w, h) = (frame.width, frame.height);
    Ok((frame, w / 2, h / 2))
}

/// Phase A2: read the source, apply the loud refusals (the loud
/// fallback — a source swapped between the A1 and A2 passes fails
/// here, named), unpack (the per-depth dispatch), deinterleave, and
/// pre-write the frame's 4 PAM temps (the PAM set the pool then runs
/// over). The PAM bytes are the 0.3.0 bytes.
fn write_frame_pams(
    src: &Path,
    out_dir: &Path,
    base: &str,
    pw: u32,
    ph: u32,
) -> Result<[PathBuf; 4]> {
    let buf = std::fs::read(src).with_context(|| format!("read {}", src.display()))?;
    let (frame, pw2, ph2) = frame_geometry(&buf)?;
    debug_assert_eq!((pw, ph), (pw2, ph2));
    let packed = frame.strip_slice(&buf);
    let p1 =
        unpack_for_depth(packed, frame.bits_per_sample, frame.width, frame.height)?;
    let planes = deinterleave(&p1, frame.width, frame.height);
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("create output dir {}", out_dir.display()))?;
    let mut paths = [
        PathBuf::new(),
        PathBuf::new(),
        PathBuf::new(),
        PathBuf::new(),
    ];
    for (i, plane) in PLANES.iter().enumerate() {
        let pam_tmp = out_dir.join(format!(".{base}_{plane}.pam"));
        std::fs::write(&pam_tmp, plane_pam_bytes(pw, ph, &planes[i]))
            .with_context(|| format!("write {}", pam_tmp.display()))?;
        paths[i] = pam_tmp;
    }
    Ok(paths)
}

/// One plane encode (shared by the W=1 serial path and the pool
/// workers): `cjxl` over the pre-written PAM → rename on rc=0
/// (atomicity: a crash never leaves a renamed partial) → size. The
/// PAM is removed on BOTH outcomes (cleanup); the `.jxl.tmp` is
/// removed on failure. The named message is the 0.3.0 message,
/// verbatim (the frame, plane, cjxl rc + stderr tail).
fn run_plane(
    opts: &JxlOpts,
    pam_tmp: &Path,
    final_p: &Path,
    src_rel: &str,
    plane: &str,
) -> Result<u64> {
    let tmp_p = final_p.with_extension("jxl.tmp");
    let cmd_args = encode_cmd_args(
        opts.threads,
        opts.effort,
        &pam_tmp.to_string_lossy(),
        &tmp_p.to_string_lossy(),
    );
    let out = std::process::Command::new(&opts.cjxl_bin)
        .args(&cmd_args)
        .output()
        .with_context(|| format!("run cjxl {}", opts.cjxl_bin.display()))?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&tmp_p);
        let _ = std::fs::remove_file(pam_tmp);
        bail!(
            "cjxl failed (rc {:?}) for {src_rel} plane {plane}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    if let Err(err) = std::fs::rename(&tmp_p, final_p) {
        let _ = std::fs::remove_file(&tmp_p); // atomicity: nothing half-written
        let _ = std::fs::remove_file(pam_tmp);
        return Err(err).with_context(|| {
            format!("rename {} -> {}", tmp_p.display(), final_p.display())
        });
    }
    // The SIZE is the only consumer — the O(1) stat
    // (the whole-file read is gone; the `read {}` context wording
    // is byte-identical, firing only on a stat failure after the
    // rename just completed).
    let size = std::fs::metadata(final_p)
        .map(|m| m.len())
        .with_context(|| format!("read {}", final_p.display()))?;
    let _ = std::fs::remove_file(pam_tmp);
    Ok(size)
}

/// First index where the two planes differ (None = identical).
fn first_diff(a: &[u16], b: &[u16]) -> Option<usize> {
    a.iter().zip(b.iter()).position(|(x, y)| x != y)
}

/// size + sha256 + crc32c of a file (the bounded
/// streaming pass — the `read {}` context wording byte-identical
/// to the pre-existing one-shot read).
fn file_digest(path: &Path) -> Result<(u64, String, u32)> {
    digest_stream_path(path).with_context(|| format!("read {}", path.display()))
}

/// One sidecar row (version + effort are per-run constants, not rows).
struct SidecarRow {
    file: String,
    size: u64,
    sha: String,
    crc: u32,
    plane: &'static str,
    src_frame: String,
    src_sha: String,
}

// ---------------------------------------------------------------------------
// frame collection (mirrors worker::collect: subfolder mirroring, symlink
// refusal, (dev,ino) cycle guard, non-DNG sidecars)
// ---------------------------------------------------------------------------

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

fn collect(
    base: &Path,
    dir: &Path,
    output_root: &Path,
    frames: &mut Vec<(PathBuf, PathBuf)>,
    sidecars: &mut Vec<(PathBuf, PathBuf)>,
    visited: &mut HashSet<(u64, u64)>,
) -> Result<()> {
    let meta = std::fs::metadata(dir)?;
    let id = (meta.dev(), meta.ino());
    if !visited.insert(id) {
        return Ok(()); // already visited — symlink cycle (or hard-link fan-in)
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue; // refuse symlinked entries (cycle/escape guard)
        }
        let rel = p.strip_prefix(base).unwrap_or(&p);
        let dst = output_root.join(rel);
        if p.is_dir() {
            collect(base, &p, output_root, frames, sidecars, visited)?;
        } else if p.is_file() {
            let is_dng = p
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("dng"))
                .unwrap_or(false);
            if is_dng {
                frames.push((p, dst));
            } else {
                sidecars.push((p, dst));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// the JXL path
// ---------------------------------------------------------------------------

/// The per-frame verify gate result.
enum VerifyGate {
    /// All 4 planes decoded + re-interleaved + packed byte-exact.
    Pass,
    /// Named failure; `planes_ok` = how many planes decoded cleanly
    /// before it (0..3; 4 = the p1/p0 compare step failed after all 4
    /// decodes).
    Fail { problem: String, planes_ok: usize },
}

/// Process every `.DNG` under `input` into 4 × `.jxl` per frame under
/// `output` (subfolder layout mirrored), with the mandatory
/// `<CLIP>.jxl-checksums.tsv` sidecar. The encode is a reel-wide plane
/// pool (see the module docs): Phase A
/// (serial) reads + shas the frames, applies the loud refusals and
/// pre-writes the full PAM set (the disk gate fires before the
/// first PAM byte); Phase B runs the pool over the flattened reel
/// planes (`opts.parallel`: 0 = auto = all cores, 1 = the serial
/// 0.3.0 flow, >= 2 = W concurrent cjxl; the per-plane cjxl args are
/// the 0.3.0 args byte-for-byte, so the output bytes are (W,T)-
/// invariant); Phase C (serial, frame order) builds the sidecar rows
/// and runs the optional `verify` gate — which runs for encoded frames
/// AND for skipped (existing) frames (a `--verify` pass over existing
/// output re-verifies without re-encoding; the sidecar sha256 re-check
/// applies when the sidecar exists). The first failed plane stops new
/// dispatch; the completed planes stay on disk. Exit-code
/// semantics follow `worker::process_dir`: per-frame failure = named
/// `Failed` outcome + non-zero exit; the sidecar is written only when
/// no frame failed. The ingest gate (residual G: the JXL path
/// joins the J92 path's ingest-gate contract) + the `--to` offload +
/// the per-clip/run reports ride this path identically
/// to the j92 path.
pub fn process_dir(
    input: &Path,
    output: &Path,
    verify: bool,
    force: bool,
    opts: &JxlOpts,
    to: Option<&Path>,
) -> Result<Report> {
    std::fs::create_dir_all(output)
        .with_context(|| format!("create output dir {}", output.display()))?;

    let mut frames: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut sidecars: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut visited = HashSet::new();
    collect(input, input, output, &mut frames, &mut sidecars, &mut visited)?;
    frames.sort_by(|a, b| a.0.cmp(&b.0));
    sidecars.sort_by(|a, b| a.0.cmp(&b.0));
    if frames.is_empty() {
        bail!("no .DNG frames in input dir {}", input.display());
    }

    // The ingest gate (residual G): the JXL path
    // joins the J92 path's ingest-gate contract. SAME shared predicate
    // (`worker::ingest_gate` — the order-independence is proven there,
    // test residual_g_gate_is_order_independent), SAME recorded manifest, SAME rc=2
    // semantics: a gate FAIL refuses the input with ZERO frames +
    // ZERO files written (before the PAM set, before the sidecar, before
    // the reports). The fp's own cards pass (the gate ran PASS on
    // A001_007's 72 frames, no manifest.tsv). The `--subset`
    // NAMED opt-in is honored IDENTICALLY here (the four-continuity-
    // class waiver + the SUBSET_MARKER line — the flag is not a j92-
    // only surface).
    let src_frames: Vec<PathBuf> = frames.iter().map(|(s, _)| s.clone()).collect();
    let gate = if crate::worker::subset_flag() {
        crate::worker::ingest_gate_subset(input, &src_frames)
    } else {
        crate::worker::ingest_gate(input, &src_frames)
    };
    if !gate.is_pass() {
        let failures = gate.failures();
        eprintln!(
            "INGEST GATE FAIL — refusing to encode ({} clip(s), {} frame(s) scanned):",
            gate.clips.len(),
            gate.frames_total
        );
        for f in &failures {
            eprintln!("  {f}");
        }
        return Err(anyhow!(
            "the ingest gate refused the input (contract: a corrupt clip is a named FAIL, not a silent encode)"
        ));
    }
    crate::worker::write_ingest_manifest(output, input, &gate)
        .with_context(|| "write the ingest manifest")?;

    // --to: the self-referential + nesting band (the
    // jxl entry point — the audit cited the j92 path only; this
    // path mirrors the RAW input to the dest identically after the
    // encode): the dest
    // must be DISJOINT from the input AND the output. The named
    // rc=2 BEFORE any frame + before the cjxl/djxl version probes
    // (the refusal tests need no pinned binaries). The shared
    // helper is the single code path (the j92 path's band is the
    // same call). NAMED RESIDUAL (pre-existing, recorded not moved — the band site
    // pinned here): the ingest manifest above is written before this band
    // on the jxl path — a refused jxl `--to` leaves that record
    // file (never a frame, never a dest write). Then the dest must
    // exist + be WRITABLE (the named rc=2 startup refusal — see the
    // j92 path).
    if let Some(dest) = to {
        crate::offload::check_to_band(input, output, dest)?;
        crate::offload::check_dest_writable(dest)
            .with_context(|| format!("the --to dest {} (the two-destination offload target)", dest.display()))?;
    }

    // Fail fast on a bogus binary BEFORE anything is written (atomicity:
    // no partial/renamed output on encoder failure).
    let cjxl_version = version_line(&opts.cjxl_bin)?;
    version_line(&opts.djxl_bin).with_context(|| {
        "djxl --version (the verify pass needs the same binary family as cjxl)"
    })?;

    // Sidecars copied through (same atomic tmp+rename discipline as the
    // J92 worker).
    let mut copied = Vec::new();
    for (src, dst) in &sidecars {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if dst.exists() && !force {
            continue;
        }
        let tmp = dst.with_extension("sidecar.tmp");
        if let Err(err) = std::fs::copy(src, &tmp).and_then(|_| std::fs::rename(&tmp, dst)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(err)
                .with_context(|| format!("copy sidecar {} -> {}", src.display(), dst.display()));
        }
        copied.push(
            src.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        );
    }

    // Sidecar re-check source (fast failure BEFORE the decodes): only
    // when `--verify` and the sidecar already exists (a verification
    // pass over existing output). Maps rel file → (size, sha256,
    // src_frame_sha256 — columns 2/3/7 of the sidecar).
    let clip = crate::checksums::clip_name(input)?;
    let sidecar_path = output.join(sidecar_name(&clip));
    let mut sidecar_rows: HashMap<String, (u64, String, String)> = HashMap::new();
    let sidecar_present = verify && sidecar_path.is_file();
    if sidecar_present {
        let text = std::fs::read_to_string(&sidecar_path)
            .with_context(|| format!("read sidecar {}", sidecar_path.display()))?;
        for (i, line) in text.lines().enumerate().skip(1) {
            if line.trim().is_empty() {
                continue;
            }
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 9 {
                bail!(
                    "sidecar {}: bad row (line {}): {line:?}",
                    sidecar_path.display(),
                    i + 1
                );
            }
            let size: u64 = cols[1].parse().map_err(|_| {
                anyhow!(
                    "sidecar {}: bad size (line {})",
                    sidecar_path.display(),
                    i + 1
                )
            })?;
            sidecar_rows.insert(
                cols[0].to_string(),
                (size, cols[2].to_string(), cols[6].to_string()),
            );
        }
    }

    let t0 = Instant::now();

    // ------------------------------------------------------------------
    // Phase A1 — serial prep: read + sha + the loud refusals; the
    // encode frames' pam-set estimate for the disk gate. Skip frames
    // (all 4 planes exist, !force) need no PAM — Phase C does their
    // sidecar rows + the optional verify (the 0.3.0 skip path).
    // ------------------------------------------------------------------
    struct FrameMeta {
        src_rel: String,
        base: String,
        frame_name: String,
        out_dir: PathBuf,
        rel_prefix: String,
        buf_len: u64,
        src_sha: String,
        skip: bool,
        pw: u32,
        ph: u32,
        prep_start: Instant,
        prep_error: Option<String>,
    }

    let mut metas: Vec<FrameMeta> = Vec::with_capacity(frames.len());
    let mut pam_estimate: u64 = 0;
    for (src, dst) in &frames {
        let src_rel = src
            .strip_prefix(input)
            .unwrap_or(src)
            .to_string_lossy()
            .replace("\\", "/");
        let base = dst
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| dst.display().to_string());
        let frame_name = dst
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let out_dir: &Path = dst.parent().unwrap_or(Path::new("."));
        // The frame's output subfolder relative to the output root
        // ("" for a flat layout) — the sidecar `file` keys are
        // output-root-relative.
        let rel_prefix = out_dir
            .strip_prefix(output)
            .map(|p| p.to_string_lossy().replace("\\", "/"))
            .unwrap_or_default();
        let prep_start = Instant::now();
        let buf =
            std::fs::read(src).with_context(|| format!("read {}", src.display()))?;
        let src_sha = sha256_hex(&buf);
        let all_exist = PLANES
            .iter()
            .all(|p| out_dir.join(format!("{base}_{p}.jxl")).is_file());
        if all_exist && !force {
            metas.push(FrameMeta {
                src_rel,
                base,
                frame_name,
                out_dir: out_dir.to_path_buf(),
                rel_prefix,
                buf_len: buf.len() as u64,
                src_sha,
                skip: true,
                pw: 0,
                ph: 0,
                prep_start,
                prep_error: None,
            });
            continue;
        }
        // Encode path: the loud refusals (the 0.3.0 named messages,
        // verbatim) + the plane geometry for the pam-set estimate.
        match frame_geometry(&buf) {
            Ok((_, pw, ph)) => {
                // The frame's pam-set bytes (estimate: 4 temps,
                // each header + big-endian u2 payload).
                let plane_bytes = (pw as u64) * (ph as u64) * 2;
                pam_estimate += 4 * (pam_header(pw, ph).len() as u64 + plane_bytes);
                metas.push(FrameMeta {
                    src_rel,
                    base,
                    frame_name,
                    out_dir: out_dir.to_path_buf(),
                    rel_prefix,
                    buf_len: buf.len() as u64,
                    src_sha,
                    skip: false,
                    pw,
                    ph,
                    prep_start,
                    prep_error: None,
                });
            }
            Err(err) => {
                metas.push(FrameMeta {
                    src_rel,
                    base,
                    frame_name,
                    out_dir: out_dir.to_path_buf(),
                    rel_prefix,
                    buf_len: buf.len() as u64,
                    src_sha,
                    skip: false,
                    pw: 0,
                    ph: 0,
                    prep_start,
                    prep_error: Some(format!("{err:#}")),
                });
            }
        }
    }

    // The disk gate — BEFORE the first PAM byte (the PAM set is
    // pre-written; the floor = the 2 GB disk gate generalized, see
    // disk_gate_required). A named loud refusal — never proceed.
    if pam_estimate > 0 {
        let required = disk_gate_required(pam_estimate);
        let free = free_bytes(output).with_context(|| {
            "the disk gate's free-space probe failed — refusing to pre-write the PAM set without a measurement"
        })?;
        if free < required {
            bail!(
                "disk gate: free {} B < required {} B for the PAM-set pre-write ({} B estimated) — refusing; free up space and re-run (nothing was written)",
                free, required, pam_estimate
            );
        }
    }

    // ------------------------------------------------------------------
    // Phase A2 — pre-write the full PAM set (the proven grid-
    // driver approach): 4 PAM temps per encode frame BEFORE the pool
    // runs. Unpack/deinterleave are the 0.3.0 code (per-depth
    // dispatch, MAXVAL-4095 bytes).
    // ------------------------------------------------------------------
    let mut pams: Vec<[PathBuf; 4]> = {
        let empty: [PathBuf; 4] = [
            PathBuf::new(),
            PathBuf::new(),
            PathBuf::new(),
            PathBuf::new(),
        ];
        vec![empty; frames.len()]
    };
    for (i, (src, _)) in frames.iter().enumerate() {
        let m = &metas[i];
        if m.skip || m.prep_error.is_some() {
            continue;
        }
        match write_frame_pams(src, &m.out_dir, &m.base, m.pw, m.ph) {
            Ok(paths) => pams[i] = paths,
            Err(err) => metas[i].prep_error = Some(format!("{err:#}")),
        }
    }

    // ------------------------------------------------------------------
    // Phase B — the reel-wide plane pool. W = resolve_parallel
    // (0 = auto = all cores; 1 = the 0.3.0 serial flow; >= 2 = the
    // pool). The per-plane cjxl args are the 0.3.0 args byte-for-byte;
    // the first plane failure stops new dispatch — the
    // completed planes stay on disk.
    // ------------------------------------------------------------------
    let n = frames.len();
    let w = resolve_parallel(opts.parallel);
    let mut enc_pos: Vec<Option<usize>> = vec![None; n]; // frame → pool position
    let mut jobs: Vec<(usize, usize)> = Vec::new(); // (frame, plane)
    for (i, m) in metas.iter().enumerate() {
        if m.skip || m.prep_error.is_some() {
            continue;
        }
        let pos = jobs.len() / 4;
        enc_pos[i] = Some(pos);
        for p in 0..4 {
            jobs.push((i, p));
        }
    }
    let enc_count = jobs.len() / 4;
    let sizes: Arc<Mutex<Vec<[u64; 4]>>> =
        Arc::new(Mutex::new(vec![[0u64; 4]; enc_count]));
    #[derive(Clone)]
    struct PlaneInfo {
        src_rel: String,
        base: String,
        out_dir: PathBuf,
    }
    let mut infos: Vec<PlaneInfo> = Vec::with_capacity(enc_count);
    for m in metas.iter() {
        if m.skip || m.prep_error.is_some() {
            continue;
        }
        infos.push(PlaneInfo {
            src_rel: m.src_rel.clone(),
            base: m.base.clone(),
            out_dir: m.out_dir.clone(),
        });
    }
    struct PoolState {
        queue: VecDeque<(usize, usize)>,
        /// (pool position, the named cjxl error) of the first failure.
        failed: Option<(usize, String)>,
    }
    let state: Arc<Mutex<PoolState>> = Arc::new(Mutex::new(PoolState {
        queue: jobs.iter().copied().collect(),
        failed: None,
    }));

    if w == 1 {
        // The 0.3.0 serial flow (the escape hatch): the canonical
        // (frame, plane) order, the same per-plane path as the pool.
        for (fi, p) in &jobs {
            if state.lock().unwrap().failed.is_some() {
                break; // the first failure stops new dispatch
            }
            let pos = enc_pos[*fi].unwrap();
            let info = &infos[pos];
            let final_p = info.out_dir.join(format!("{}_{}.jxl", info.base, PLANES[*p]));
            match run_plane(opts, &pams[*fi][*p], &final_p, &info.src_rel, PLANES[*p]) {
                Ok(size) => {
                    sizes.lock().unwrap()[pos][*p] = size;
                }
                Err(msg) => {
                    state.lock().unwrap().failed = Some((pos, format!("{msg:#}")));
                }
            }
        }
    } else {
        let mut workers = Vec::with_capacity(w);
        for _ in 0..w {
            let state = Arc::clone(&state);
            let sizes = Arc::clone(&sizes);
            let infos = infos.clone();
            let pams = pams.clone();
            let enc_pos = enc_pos.clone();
            let opts = opts.clone();
            workers.push(std::thread::spawn(move || loop {
                let job = {
                    let mut st = state.lock().unwrap();
                    if st.failed.is_some() {
                        None
                    } else {
                        st.queue.pop_front()
                    }
                };
                let Some((fi, p)) = job else {
                    break;
                };
                let pos = enc_pos[fi].unwrap();
                let info = &infos[pos];
                let final_p = info.out_dir.join(format!("{}_{}.jxl", info.base, PLANES[p]));
                match run_plane(&opts, &pams[fi][p], &final_p, &info.src_rel, PLANES[p]) {
                    Ok(size) => {
                        sizes.lock().unwrap()[pos][p] = size;
                    }
                    Err(msg) => {
                        let mut st = state.lock().unwrap();
                        if st.failed.is_none() {
                            st.failed = Some((pos, format!("{msg:#}")));
                        }
                    }
                }
            }));
        }
        for t in workers {
            t.join().expect("a jxl plane worker panicked");
        }
    }
    let pool_failed = state.lock().unwrap().failed.clone();

    // Cleanup: remove the PAM temps the pool did not consume (the
    // per-plane deletes covered the executed jobs; the un-dispatched
    // ones — a stopped pool or a Phase A failure — go here). Reached
    // on BOTH the success and the failure paths (the sidecar is
    // written after it, success-only).
    for (i, m) in metas.iter().enumerate() {
        if m.skip {
            continue;
        }
        for path in &pams[i] {
            if path.as_os_str().is_empty() {
                continue;
            }
            let _ = std::fs::remove_file(path);
        }
    }

    // ------------------------------------------------------------------
    // Phase C — serial post-processing in FRAME order (the outcomes
    // and the sidecar rows keep the 0.3.0 frame order regardless of
    // the pool completion order). Skip frames = the 0.3.0 skip
    // path; successful encode frames = rows + the optional verify;
    // failed/not-attempted frames = named Failed outcomes (the
    // sidecar is skipped — success-only, as before).
    // ------------------------------------------------------------------
    let mut outcomes: Vec<Outcome> = Vec::with_capacity(n);
    let mut rows: Vec<SidecarRow> = Vec::new();
    let mut verify_pass = 0usize;
    let mut verify_fail = 0usize;

    for (i, (src, _)) in frames.iter().enumerate() {
        let m = &metas[i];
        let key_for = |plane: &str| -> String {
            if m.rel_prefix.is_empty() {
                format!("{}_{}.jxl", m.base, plane)
            } else {
                format!("{}/{}_{}.jxl", m.rel_prefix, m.base, plane)
            }
        };
        // 1. Phase A refusal/failure (the 0.3.0 named message,
        //    verbatim — parse / eligibility / even / unpack / PAM
        //    write): a named Failed outcome.
        if let Some(prep_err) = &m.prep_error {
            verify_fail += 1;
            eprintln!("FAIL {}: {prep_err}", m.frame_name);
            outcomes.push(Outcome::Failed {
                file: m.frame_name.clone(),
                error: prep_err.clone(),
            });
            continue;
        }
        // 2. A plane failed in the pool (this frame or an earlier one
        //    — a failure stopped new dispatch). The first frame carries the
        //    0.3.0 cjxl message verbatim; the not-attempted frames
        //    are named (the completed planes stay on disk; the
        //    sidecar is skipped). An encode frame that COMPLETED
        //    before the pool stopped (all 4 planes on disk) falls
        //    through to the success path — the 0.3.0 semantics (it
        //    was Done; its verify still ran).
        if !m.skip {
            if let Some((fpos, fmsg)) = &pool_failed {
                let pos = enc_pos[i].unwrap();
                let complete = sizes.lock().unwrap()[pos].iter().all(|&s| s > 0);
                if !complete {
                    let msg = if &pos == fpos {
                        fmsg.clone() // the 0.3.0 message, verbatim
                    } else {
                        format!("not attempted: a previous plane failed (first: {fmsg})")
                    };
                    verify_fail += 1;
                    eprintln!("FAIL {}: {msg}", m.frame_name);
                    outcomes.push(Outcome::Failed {
                        file: m.frame_name.clone(),
                        error: msg,
                    });
                    continue;
                }
            }
        }
        // 3. Success path (a skip frame or a completed encode frame):
        //    the sidecar rows from disk + the optional verify.
        let frame_rows = match rows_from_files(
            &m.out_dir,
            &m.base,
            &m.src_rel,
            &m.src_sha,
            &key_for,
        ) {
            Ok(r) => r,
            Err(err) => {
                eprintln!("FAIL {}: {err:#}", m.frame_name);
                verify_fail += 1;
                outcomes.push(Outcome::Failed {
                    file: m.frame_name.clone(),
                    error: format!("{err:#}"),
                });
                continue;
            }
        };
        let mut gate_ok = true;
        if verify {
            match std::fs::read(src) {
                Ok(buf) => {
                    match verify_frame(
                        &buf,
                        &m.out_dir,
                        &m.base,
                        opts,
                        &sidecar_rows,
                        sidecar_present,
                        &m.src_rel,
                        &m.src_sha,
                        &key_for,
                    ) {
                        Ok(VerifyGate::Pass) => {
                            verify_pass += 1;
                        }
                        Ok(VerifyGate::Fail { problem, planes_ok }) => {
                            verify_fail += 1;
                            let msg = format!(
                                "verify {}: {problem} ({planes_ok}/4 planes decoded cleanly)",
                                m.src_rel
                            );
                            eprintln!("FAIL {}: {msg}", m.frame_name);
                            outcomes.push(Outcome::Failed {
                                file: m.frame_name.clone(),
                                error: msg,
                            });
                            gate_ok = false;
                        }
                        Err(err) => {
                            verify_fail += 1;
                            eprintln!("FAIL {}: {err:#}", m.frame_name);
                            outcomes.push(Outcome::Failed {
                                file: m.frame_name.clone(),
                                error: format!("{err:#}"),
                            });
                            gate_ok = false;
                        }
                    }
                }
                Err(err) => {
                    verify_fail += 1;
                    let msg = format!("read {}: {err}", m.src_rel);
                    eprintln!("FAIL {}: {msg}", m.frame_name);
                    outcomes.push(Outcome::Failed {
                        file: m.frame_name.clone(),
                        error: msg,
                    });
                    gate_ok = false;
                }
            }
        }
        if gate_ok {
            if m.skip {
                outcomes.push(Outcome::Skipped {
                    file: m.frame_name.clone(),
                    in_bytes: m.buf_len,
                });
            } else {
                let pos = enc_pos[i].unwrap();
                let out_bytes: u64 = sizes.lock().unwrap()[pos].iter().sum();
                outcomes.push(Outcome::Done(FrameStats {
                    file: m.frame_name.clone(),
                    in_bytes: m.buf_len,
                    out_bytes,
                    ratio: if out_bytes > 0 {
                        m.buf_len as f64 / out_bytes as f64
                    } else {
                        0.0
                    },
                    ms: m.prep_start.elapsed().as_secs_f64() * 1000.0,
                    log10: None,
                    lossy: None,
                    quality: None,
                    reference_dct: None,
                }));
            }
            rows.extend(frame_rows);
        }
    }

    let done = outcomes.iter().filter(|o| matches!(o, Outcome::Done(_))).count();
    let skipped = outcomes.iter().filter(|o| matches!(o, Outcome::Skipped { .. })).count();
    let failed = outcomes.iter().filter(|o| matches!(o, Outcome::Failed { .. })).count();
    let total_in: u64 = outcomes
        .iter()
        .map(|o| match o {
            Outcome::Done(s) => s.in_bytes,
            Outcome::Skipped { in_bytes, .. } => *in_bytes,
            Outcome::Failed { .. } => 0,
        })
        .sum();
    let total_out: u64 = outcomes
        .iter()
        .filter_map(|o| match o {
            Outcome::Done(s) => Some(s.out_bytes),
            _ => None,
        })
        .sum();
    let elapsed = t0.elapsed().as_secs_f64();
    let avg = if done > 0 {
        outcomes
            .iter()
            .filter_map(|o| match o {
                Outcome::Done(s) => Some(s.ms),
                _ => None,
            })
            .sum::<f64>()
            / done as f64
    } else {
        0.0
    };
    eprintln!(
        "{done} frame(s) jxl-encoded in {elapsed:.1}s (avg {avg:.0} ms/frame, cjxl {cjxl_version}), \
         {skipped} skipped, {failed} failed: {total_in} B -> {total_out} B",
    );
    if verify {
        eprintln!(
            "jxl verify: {verify_pass}/{} frame(s) PASS ({} planes byte-exact), {verify_fail} failed",
            verify_pass + verify_fail,
            verify_pass * 4,
        );
    }

    let checksums_path = if failed > 0 {
        eprintln!("skipping the jxl sidecar: {failed} frame(s) failed");
        None
    } else {
        Some(write_sidecar(output, &clip, &rows, &cjxl_version, opts.effort)?)
    };

    // --to + the per-clip/run reports: the same
    // wiring as the j92 path (after the encode + sidecar; the camera
    // metadata for the jxl path lands in the REPORTS: the
    // oracle-pinned JXL sidecar is byte-frozen and carries none).
    let offload_report = if let Some(dest) = to {
        let r = crate::offload::offload_to(input, output, dest)
            .with_context(|| format!("the --to offload to {}", dest.display()))?;
        if r.dirty_count() > 0 {
            for line in r.fail_lines() {
                eprintln!("{line}");
            }
            eprintln!(
                "OFFLOAD FAIL — {} dirty row(s) (dest {}): the named FAIL lines above (the verify-before-wipe gate holds: the camera disk is reusable only after BOTH destinations verify clean)",
                r.dirty_count(),
                dest.display()
            );
        } else {
            eprintln!("{}", r.verdict_line());
        }
        Some(r)
    } else {
        None
    };

    let _reports = crate::report::write_reports(
        output,
        input,
        "jxl",
        &cjxl_version,
        &gate,
        &frames,
        &outcomes,
        offload_report.as_ref(),
        checksums_path.as_ref(),
    )
    .with_context(|| "write the offload reports")?;

    Ok(Report {
        outcomes,
        copied_sidecars: copied,
        checksums: checksums_path,
        offload_dirty_rows: offload_report.as_ref().map(|r| r.dirty_count()),
    })
}

/// Sidecar rows for a frame from the on-disk `.jxl` files (encoded OR
/// skipped — the sidecar must cover the whole clip). `key_for(plane)`
/// maps a plane to its output-root-relative sidecar key.
fn rows_from_files(
    out_dir: &Path,
    base: &str,
    src_rel: &str,
    src_sha: &str,
    key_for: &dyn Fn(&str) -> String,
) -> Result<Vec<SidecarRow>> {
    let mut rows = Vec::with_capacity(4);
    for plane in PLANES {
        let p = out_dir.join(format!("{base}_{plane}.jxl"));
        let (size, sha, crc) = file_digest(&p)?;
        rows.push(SidecarRow {
            file: key_for(plane),
            size,
            sha,
            crc,
            plane,
            src_frame: src_rel.to_string(),
            src_sha: src_sha.to_string(),
        });
    }
    Ok(rows)
}

/// The per-frame verify gate (called only when `verify` is on).
///
/// Order (fast failure first):
/// 1. sidecar re-check (only when the sidecar is present): per-file
///    size + sha256, then the source frame's sha256 against the row —
///    a bit-rotted `.jxl` or a swapped source fails here, before any
///    decode;
/// 2. djxl decode of all 4 planes → strict PAM parse → u16 (big-endian);
/// 3. re-interleave → p1' vs the source unpack (byte-exact, named first
///    diff);
/// 4. pack12(p1') → p0 vs the source strip prefix (byte-exact — the
///    strip may carry trailing padding; the first 3·w·h/2 bytes are the
///    packed plane, the prep file-level oracle).
fn verify_frame(
    buf: &[u8],
    out_dir: &Path,
    base: &str,
    opts: &JxlOpts,
    sidecar_rows: &HashMap<String, (u64, String, String)>,
    sidecar_present: bool,
    src_rel: &str,
    src_sha: &str,
    key_for: &dyn Fn(&str) -> String,
) -> Result<VerifyGate> {
    let frame = crate::tiff::read(buf).map_err(|e| anyhow!("parse source: {e}"))?;
    // Eligibility (the encode path's named refusal, mirrored —
    // the v1 12-bit-only scope is lifted to the archive layouts,
    // identical to the j92 path): a frame outside them would
    // mis-decode silently, so refuse loud.
    if !crate::worker::is_archive_layout(&frame) {
        return Ok(VerifyGate::Fail {
            problem: format!(
                "source frame is {w}×{h} at {bps}-bit — --codec jxl accepts the archive layouts only (3856×2170 or 1936×1090 at 8/10/12-bit)",
                w = frame.width,
                h = frame.height,
                bps = frame.bits_per_sample
            ),
            planes_ok: 0,
        });
    }
    let (pw, ph) = (frame.width / 2, frame.height / 2);
    if pw == 0 || ph == 0 {
        return Ok(VerifyGate::Fail {
            problem: "frame too small for the 2×2 plane split".to_string(),
            planes_ok: 0,
        });
    }

    // (1) sidecar re-check — fast failure before any decode. A missing
    // file fails at the digest step (named); size/sha mismatch fails
    // here before any decode is spent.
    if sidecar_present {
        for plane in PLANES {
            let key = key_for(plane);
            let (want_size, want_sha, want_src) = match sidecar_rows.get(&key) {
                Some(v) => v,
                None => {
                    return Ok(VerifyGate::Fail {
                        problem: format!(
                            "sidecar has no row for {key} (the sidecar does not cover this frame)"
                        ),
                        planes_ok: 0,
                    });
                }
            };
            let p = out_dir.join(format!("{base}_{plane}.jxl"));
            let (size, sha, _crc) = match file_digest(&p) {
                Ok(d) => d,
                Err(err) => {
                    return Ok(VerifyGate::Fail {
                        problem: format!("cannot read {key}: {err:#}"),
                        planes_ok: 0,
                    });
                }
            };
            if size != *want_size {
                return Ok(VerifyGate::Fail {
                    problem: format!(
                        "size mismatch for {key}: sidecar {want_size}, disk {size}"
                    ),
                    planes_ok: 0,
                });
            }
            if sha != *want_sha {
                return Ok(VerifyGate::Fail {
                    problem: format!(
                        "sha256 mismatch for {key}: sidecar {want_sha}, disk {sha}"
                    ),
                    planes_ok: 0,
                });
            }
            // The source frame must be the one the sidecar pinned (a
            // swapped source would make the decode compare
            // meaningless). All 4 rows of the frame carry the same
            // src_frame_sha256; one check suffices.
            if plane == PLANES[0] && src_sha != *want_src {
                return Ok(VerifyGate::Fail {
                    problem: format!(
                        "source frame {src_rel} sha256 differs from the sidecar (src_frame_sha256)"
                    ),
                    planes_ok: 0,
                });
            }
        }
    }

    // (2) djxl decode of all 4 planes → strict PAM parse → u16.
    let mut decoded: [Vec<u16>; 4] = [
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ];
    for (i, plane) in PLANES.iter().enumerate() {
        let jxl_p = out_dir.join(format!("{base}_{plane}.jxl"));
        let pam_tmp = out_dir.join(format!(".{base}_{plane}.dec.pam"));
        let mut cmd_args = djxl_args(opts.threads);
        cmd_args.push(jxl_p.to_string_lossy().into_owned());
        cmd_args.push(pam_tmp.to_string_lossy().into_owned());
        let out = std::process::Command::new(&opts.djxl_bin)
            .args(&cmd_args)
            .output()
            .with_context(|| format!("run djxl {}", opts.djxl_bin.display()))?;
        if !out.status.success() {
            let _ = std::fs::remove_file(&pam_tmp);
            return Ok(VerifyGate::Fail {
                problem: format!(
                    "djxl failed (rc {:?}) for {src_rel} plane {plane}: {}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
                planes_ok: i,
            });
        }
        let pam = std::fs::read(&pam_tmp)
            .with_context(|| format!("read {}", pam_tmp.display()))?;
        let what = format!("{src_rel} {plane}");
        let plane_u16 =
            parse_pam_plane(&pam, &what, pw, ph).map_err(|e| anyhow!("{e}"))?;
        let _ = std::fs::remove_file(&pam_tmp);
        decoded[i] = plane_u16;
    }

    // (3) re-interleave → p1' vs the PER-DEPTH source unpack (the
    // mandatory gate at all depths).
    let p1r = reinterleave(
        [
            &decoded[0],
            &decoded[1],
            &decoded[2],
            &decoded[3],
        ],
        frame.width,
        frame.height,
    );
    let packed = frame.strip_slice(buf);
    let p1 = unpack_for_depth(packed, frame.bits_per_sample, frame.width, frame.height)?;
    if let Some(idx) = first_diff(&p1r, &p1) {
        return Ok(VerifyGate::Fail {
            problem: format!(
                "re-interleaved p1 differs from the source unpack at sample {idx} of {} (byte-exact gate failed)",
                p1.len()
            ),
            planes_ok: 4,
        });
    }

    // (4) 12-bit only: pack12(p1') → p0 vs the source strip prefix (the
    // strip may carry trailing padding — the first 3·w·h/2 bytes are the
    // packed plane; the prep file-level oracle). 10/8-bit clips gate on
    // (3) alone: there is no pack10/pack8 (the inverse packers are a
    // NAMED FOLLOW-UP — the strip-prefix form needs them; gate (3) has
    // the identical pixel strength).
    if frame.bits_per_sample == 12 {
        let p0 = pack12(&p1r);
        if packed.len() < p0.len() || packed[..p0.len()] != p0[..] {
            let n = packed.len().min(p0.len());
            let diff = (0..n).find(|&i| packed[i] != p0[i]).unwrap_or(n);
            return Ok(VerifyGate::Fail {
                problem: format!(
                    "packed p0 differs from the source strip at byte {diff} of {} (byte-exact gate failed; strip {} B, packed {} B)",
                    n,
                    packed.len(),
                    p0.len()
                ),
                planes_ok: 4,
            });
        }
    }
    Ok(VerifyGate::Pass)
}

/// Write the sidecar atomically (tmp + rename), rows sorted by file.
fn write_sidecar(
    out_dir: &Path,
    clip: &str,
    rows: &[SidecarRow],
    version: &str,
    effort: u32,
) -> Result<PathBuf> {
    let mut sorted: Vec<&SidecarRow> = rows.iter().collect();
    sorted.sort_by(|a, b| a.file.cmp(&b.file));
    let mut tsv = String::from(
        "file\tsize\tsha256\tcrc32c\tplane\tsrc_frame\tsrc_frame_sha256\tjxl_version\teffort\n",
    );
    for r in &sorted {
        tsv.push_str(&format!(
            "{}\t{}\t{}\t{:08x}\t{}\t{}\t{}\t{}\t{effort}\n",
            r.file, r.size, r.sha, r.crc, r.plane, r.src_frame, r.src_sha, version
        ));
    }
    let path = out_dir.join(sidecar_name(clip));
    let tmp = out_dir.join(format!(".{clip}.jxl-checksums.tsv.tmp"));
    std::fs::write(&tmp, tsv).with_context(|| format!("write {}", tmp.display()))?;
    if let Err(err) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("rename {} -> {}", tmp.display(), path.display()));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 10-bit (the pixel path at 10-bit): a synthetic
    /// strip (4-per-5-byte MSB-first groups, the DNG-SDK rule) through
    /// unpack10 → deinterleave → reinterleave is the identity. 8×8,
    /// width%4==0 (both archive geometries satisfy the constraint).
    #[test]
    fn depth10_deinterleave_identity() {
        let (w, h) = (8u32, 8u32);
        let n = (w * h) as usize;
        let s: Vec<u16> = (0..n as u32).map(|i| ((i * 8887) % 1024) as u16).collect();
        let mut packed = vec![0u8; n * 5 / 4];
        for (i, chunk) in s.chunks(4).enumerate() {
            let word = ((chunk[0] as u64) << 30)
                | ((chunk[1] as u64) << 20)
                | ((chunk[2] as u64) << 10)
                | chunk[3] as u64;
            packed[i * 5..i * 5 + 5].copy_from_slice(&word.to_be_bytes()[3..]);
        }
        let p1 = crate::pack12::unpack10(&packed, w, h).unwrap();
        assert_eq!(p1, s);
        let planes = deinterleave(&p1, w, h);
        let back = reinterleave(
            [&planes[0], &planes[1], &planes[2], &planes[3]],
            w,
            h,
        );
        assert_eq!(back, s, "10-bit p1 -> 4 planes -> p1 is not the identity");
        // every value fits the MAXVAL 4095 PAM unchanged
        assert!(back.iter().all(|&v| v <= 1023));
    }

    /// 8-bit: the same identity through unpack8 (1 byte per sample).
    #[test]
    fn depth8_deinterleave_identity() {
        let (w, h) = (8u32, 8u32);
        let n = (w * h) as usize;
        let s: Vec<u16> = (0..n as u32).map(|i| ((i * 521) % 256) as u16).collect();
        let packed: Vec<u8> = s.iter().map(|&v| v as u8).collect();
        let p1 = crate::pack12::unpack8(&packed, w, h).unwrap();
        assert_eq!(p1, s);
        let planes = deinterleave(&p1, w, h);
        let back = reinterleave(
            [&planes[0], &planes[1], &planes[2], &planes[3]],
            w,
            h,
        );
        assert_eq!(back, s, "8-bit p1 -> 4 planes -> p1 is not the identity");
        assert!(back.iter().all(|&v| v <= 255));
    }

    /// The depth dispatch: 8/10/12 reach the right unpacker (known
    /// vectors from pack12's tests); any other depth is refused loudly
    /// (the fallback behind the is_archive_layout eligibility gate).
    #[test]
    fn unpack_for_depth_dispatch() {
        // 12-bit known group: [0x12, 0x34, 0x56] = [0x123, 0x456]
        assert_eq!(
            unpack_for_depth(&[0x12, 0x34, 0x56], 12, 2, 1).unwrap(),
            vec![0x123, 0x456]
        );
        // 10-bit known group (pack12's test vector): 48 c4 51 e0 ab
        assert_eq!(
            unpack_for_depth(&[0x48, 0xC4, 0x51, 0xE0, 0xAB], 10, 4, 1).unwrap(),
            vec![0x123, 0x45, 0x78, 0xAB]
        );
        // 8-bit: 1 byte per sample
        assert_eq!(
            unpack_for_depth(&[1, 2, 3], 8, 3, 1).unwrap(),
            vec![1, 2, 3]
        );
        // 16-bit: refused loudly (the is_archive_layout gate is primary)
        assert!(unpack_for_depth(&[0u8; 8], 16, 2, 1).is_err());
    }

    /// The `--jxl-parallel` scope guard (mirrors the effort guard):
    /// the flag is meaningful only with `--codec jxl`; an explicit flag
    /// on another codec is a named refusal (rc=2). Absent flag = no
    /// refusal (the auto default applies).
    #[test]
    fn jxl_parallel_scope_refusal() {
        assert!(
            parallel_scope_refusal("j92", false).is_none(),
            "absent flag: no refusal (the auto default applies)"
        );
        assert!(
            parallel_scope_refusal("jxl", true).is_none(),
            "the jxl path accepts the flag"
        );
        let r = parallel_scope_refusal("j92", true).unwrap();
        assert!(
            r.starts_with("--jxl-parallel requires --codec jxl") && r.contains("j92"),
            "the named refusal names the offending codec: {r}"
        );
    }

    /// The pool-width resolution: 0 = auto = all cores; N > 0 =
    /// exactly N (1 = the serial 0.3.0 escape hatch).
    #[test]
    fn jxl_parallel_resolution() {
        let auto = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        assert!(auto >= 1);
        assert_eq!(resolve_parallel(0), auto, "0 = auto = all cores");
        assert_eq!(resolve_parallel(1), 1, "1 = the serial escape hatch");
        assert_eq!(resolve_parallel(14), 14);
    }

    /// The per-plane cjxl args are the 0.3.0 args byte-for-byte at
    /// every (threads, effort) — the pool workers and the serial path
    /// share the single source (encode_cmd_args), so the output bytes
    /// are (W,T)-invariant.
    #[test]
    fn jxl_encode_args_match_legacy_serial() {
        for (threads, effort) in [(0, 4u32), (0, 7), (14, 7), (1, 9)] {
            let mut legacy = cjxl_args(threads, effort);
            legacy.push("in.pam".to_string());
            legacy.push("out.jxl".to_string());
            assert_eq!(
                encode_cmd_args(threads, effort, "in.pam", "out.jxl"),
                legacy,
                "threads={threads} effort={effort}"
            );
        }
        // The serial shape's args (0 = the binary's default threads):
        assert_eq!(
            cjxl_args(0, 7),
            vec![
                "-e".to_string(),
                "7".to_string(),
                "-d".to_string(),
                "0".to_string()
            ]
        );
        // The j1 mechanism: an explicit budget is the hidden flag.
        assert_eq!(cjxl_args(14, 7).last().unwrap(), "--num_threads=14");
    }

    /// The PAM bytes are the legacy header bytes (the do-not-reformat header +
    /// the big-endian u2 payload) — the cjxl input's byte-identity is
    /// part of the gate.
    #[test]
    fn jxl_pam_bytes_match_legacy_header() {
        let plane = vec![1u16, 4095, 7, 0];
        let got = plane_pam_bytes(2, 2, &plane);
        let mut want = pam_header(2, 2).into_bytes();
        for s in &plane {
            want.extend_from_slice(&s.to_be_bytes());
        }
        assert_eq!(got, want);
        assert!(got.starts_with(
            b"P7\nWIDTH 2\nHEIGHT 2\nDEPTH 1\nMAXVAL 4095\nTUPLTYPE GRAYSCALE\nENDHDR\n"
        ));
    }

    /// The sidecar file is byte-identical regardless of the pool
    /// completion order (write_sidecar sorts by file; the Phase C
    /// assembly keeps the frame order) — the sidecar is the byte
    /// contract the CI pins.
    #[test]
    fn jxl_sidecar_rows_invariant_under_shuffled_completion() {
        let mk = |fi: u64, pi: usize| SidecarRow {
            file: format!("f{fi}_{}.jxl", PLANES[pi]),
            size: 100 + fi * 1000 + pi as u64,
            sha: format!("{:064x}", fi.wrapping_mul(0x9E37_79B9_7F4A_7C15)),
            crc: (fi * 100 + pi as u64) as u32,
            plane: PLANES[pi],
            src_frame: format!("f{fi}.DNG"),
            src_sha: format!("{:064x}", fi.wrapping_add(1)),
        };
        // 2 frames × 4 planes, canonical (frame, plane) order …
        let canonical: Vec<SidecarRow> = (0..2u64)
            .flat_map(|fi| (0..4).map(move |pi| mk(fi, pi)))
            .collect();
        // … and the same rows in a shuffled (pool-completion-like)
        // order.
        let shuffled: Vec<SidecarRow> = (0..2u64)
            .flat_map(|fi| (1..5).map(move |pi| mk(fi, pi - 1)))
            .collect();
        let tmp = std::env::temp_dir().join(format!(
            "frameprism_jxl_sidecar_order_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let version = "cjxl v0.12.0 1cad73c [_NEON_] {test}";
        let p1 = write_sidecar(&tmp, "clipA", &canonical, version, 7).unwrap();
        let c1 = std::fs::read(&p1).unwrap();
        let p2 = write_sidecar(&tmp, "clipA", &shuffled, version, 7).unwrap();
        let c2 = std::fs::read(&p2).unwrap();
        assert_eq!(c1, c2, "the sidecar must not depend on the completion order");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The disk-gate floor — the 2 GB gate for the reference reel
    /// (the 1.2 GB PAM set), rising to estimate + the 800 MB margin
    /// for bigger reels (never looser than 2 GB).
    #[test]
    fn jxl_disk_gate_floor() {
        let two_gb = 2u64 * 1024 * 1024 * 1024;
        let margin = 800u64 * 1024 * 1024;
        // The reference reel (the A001_001 1.2 GB PAM set): the 2 GB
        // floor (1.2 GB + the 800 MB margin is still below it).
        assert_eq!(disk_gate_required(1200 * 1024 * 1024), two_gb);
        // A small reel (the oracle frames): the 2 GB floor still
        // applies.
        assert_eq!(disk_gate_required(8 * 1024 * 1024), two_gb);
        // A big reel: the floor rises to the estimate + margin.
        assert_eq!(
            disk_gate_required(17 * 1024 * 1024 * 1024),
            17 * 1024 * 1024 * 1024 + margin
        );
    }

    // -----------------------------------------------------------------------
    // The streaming sha256 (the refactor's byte-identity proof)
    // -----------------------------------------------------------------------

    /// (a) the property: for the pinned size ladder × the pinned chunk-
    /// size ladder, the chunked `Sha256State` digest == the one-shot
    /// `sha256()` on the same bytes (the one-shot is re-implemented
    /// over the state — this pins BOTH the refactor and the chunking).
    #[test]
    fn sha256_streaming_property() {
        let sizes = [0usize, 1, 63, 64, 65, 127, 128, 1000, 4096, 1024 * 1024, 1024 * 1024 + 1];
        let chunks = [1usize, 7, 63, 64, 1000, 1024 * 1024];
        for &n in &sizes {
            // Deterministic pseudo-content (no
            // fixture file needed for the property).
            let data: Vec<u8> = (0..n).map(|i| ((i.wrapping_mul(31)) % 251) as u8).collect();
            let once = sha256(&data);
            for &c in &chunks {
                let mut s = Sha256State::new();
                for chunk in data.chunks(c) {
                    s.update(chunk);
                }
                assert_eq!(s.finalize(), once, "size {n} chunked by {c}");
            }
        }
    }

    /// (b) the FIPS 180-4 known-answer vectors, fed in ODD chunk
    /// sizes (1 / 3 / 63-byte chunks — the padding corner cases at
    /// 55/56/64-byte message lengths are exercised by (a)'s ladder;
    /// this pins the published digests themselves, streamed).
    #[test]
    fn sha256_streaming_fips_vectors() {
        let vectors: [(&[u8], &str); 3] = [
            (b"" as &[u8], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc" as &[u8],
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (([b'a'; 448 / 8]).as_slice() as &[u8],
             "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"),
        ];
        for (data, hex) in &vectors {
            for c in [1usize, 3, 63] {
                let mut s = Sha256State::new();
                for chunk in data.iter().as_slice().chunks(c) {
                    s.update(chunk);
                }
                assert_eq!(&sha256_hex_of(s.finalize()), hex, "chunked by {c}");
            }
        }
    }

    /// The A001 profile override (the worker/offload test idiom —
    /// the thread-safe stand-in for the profiles resolution: the
    /// repo's A001 profile written to a per-process temp file + the
    /// camera override; the content is the SAME for every caller —
    /// concurrent sets cannot skew each other).
    fn a001_profile_override() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let p = std::path::Path::new("../profiles/a001-sigma-fp.profile");
            let text = std::fs::read_to_string(p)
                .unwrap_or_else(|err| panic!("the A001 profile file must exist for the jxl tests: {p:?}: {err}"));
            let dir =
                std::env::temp_dir().join(format!("frameprism-jxl-camera-profile-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let f = dir.join("a001-sigma-fp.profile");
            std::fs::write(&f, text).unwrap();
            crate::camera::set_profile_override(Some(&f));
        });
    }

    /// The jxl entry point's `--to` band wiring (the audit
    /// cited the j92 path only — this path mirrors the RAW
    /// input to the dest identically after the encode). The shared
    /// helper is the
    /// single code path (the topology table + the exact lines are
    /// unit-pinned in offload/forms.rs
    /// `to_band_six_topologies_refuse_named`); this battery
    /// proves the JXL wiring: the band fires BEFORE the cjxl/djxl
    /// version probes (the bogus binary paths are never probed —
    /// the refusal needs no pinned binaries — a regression that
    /// moves the band after the probes fails with the version-probe
    /// error, not the band's named line) + the zero-FRAME-writes
    /// proof. The input must PASS the ingest gate (the gate
    /// precedes the band on the jxl path): the synthetic A001-
    /// identity frame + the profile override. NAMED RESIDUAL
    /// (pre-existing, recorded, not
    /// moved): the ingest manifest is written before the band site
    /// — the assertion is frame-free, not dir-empty.
    #[test]
    fn jxl_to_band_refuses_before_any_frame() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        a001_profile_override();
        let bytes = crate::camera::synth_dng_frame(
            "SIGMA", "SIGMA fp", 1936, 1090, 10, 32803, Some([0u8; 8]),
        );
        let name = "A001_001_20260701_000001.DNG";
        let base = std::env::temp_dir().join(format!(
            "frameprism-jxl-to-band-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        // The bogus binary paths: the band fires before the version
        // probes — they are never probed (the named refusal needs
        // no pinned binaries).
        let opts = JxlOpts {
            cjxl_bin: std::path::PathBuf::from("/nonexistent/cjxl"),
            djxl_bin: std::path::PathBuf::from("/nonexistent/djxl"),
            threads: 1,
            effort: 7,
            parallel: 1,
        };
        let top_files = |p: &Path| {
            std::fs::read_dir(p)
                .map(|rd| rd.flatten().filter(|e| e.path().is_file()).count())
                .unwrap_or(0)
        };
        let frame_free = |p: &Path, tag: &str| {
            if let Ok(rd) = std::fs::read_dir(p) {
                for e in rd.flatten() {
                    let n = e.file_name().to_string_lossy().into_owned();
                    assert!(
                        !n.ends_with(".DNG") && !n.ends_with(".jxl"),
                        "{tag}: no frame writes at {p:?}: {n}"
                    );
                }
            }
        };
        let refuse = |tag: &str, input: &Path, output: &Path, to: &Path, phrase: &str| {
            std::fs::create_dir_all(input).unwrap();
            std::fs::write(input.join(name), &bytes).unwrap();
            let err = process_dir(input, output, false, false, &opts, Some(to)).unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains(phrase), "{tag}: the named refusal — {msg}");
        };
        // (1) identity output — the headline case.
        let in1 = base.join("1").join("in");
        let out1 = base.join("1").join("out");
        refuse("1 identity-output", &in1, &out1, &out1, "is the encode output");
        frame_free(&out1, "1");
        // (2) the dest nested in the output.
        let in2 = base.join("2").join("in");
        let out2 = base.join("2").join("out");
        let to2 = out2.join("sub");
        refuse("2 nested-in-output", &in2, &out2, &to2, "is inside the encode output");
        assert!(!to2.exists(), "2: the dest was never created (the band precedes the probe)");
        frame_free(&out2, "2");
        // (3) the output nested in the dest.
        let in3 = base.join("3").join("in");
        let outer3 = base.join("3").join("outer");
        let out3 = outer3.join("out");
        refuse("3 output-nested-in-to", &in3, &out3, &outer3, "contains the encode output");
        assert_eq!(top_files(&outer3), 0, "3: the dest root holds no file (only the output dir)");
        // (4) identity input — the verify-only no-op (refused,
        // not documented).
        let in4 = base.join("4").join("in");
        let out4 = base.join("4").join("out");
        refuse("4 identity-input", &in4, &out4, &in4, "is the encode input");
        frame_free(&out4, "4");
        // (5) the dest nested in the input (the card-surface class).
        let in5 = base.join("5").join("in");
        let out5 = base.join("5").join("out");
        let to5 = in5.join("sub");
        refuse("5 nested-in-input", &in5, &out5, &to5, "is inside the encode input");
        assert!(!to5.exists(), "5: the dest was never created (the band precedes the probe)");
        frame_free(&out5, "5");
        // (6) the input nested in the dest.
        let outer6 = base.join("6").join("outer2");
        let in6 = outer6.join("in");
        let out6 = base.join("6").join("out");
        refuse("6 input-nested-in-to", &in6, &out6, &outer6, "contains the encode input");
        assert_eq!(top_files(&outer6), 0, "6: the dest root holds no file (only the input dir)");
        let _ = std::fs::remove_dir_all(&base);
    }
}
    // The streaming digest-triple VALUE identity: the
    // single-pass size + sha + crc equals the one-shot values at
    // the chunk-boundary sizes (the position-dependent fixture).
    #[test]
    fn digest_stream_value_identity() {
        use crate::checksums::crc32c;
        let base = std::env::temp_dir().join(format!(
            "frameprism_digest_stream_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let make = |len: usize| {
            let mut b = vec![0u8; len];
            for (i, x) in b.iter_mut().enumerate() {
                *x = ((i % 251) as u8) ^ ((i / 256) as u8);
            }
            b
        };
        for (label, len) in [
            ("empty", 0usize),
            ("one", 1),
            ("127", 127),
            ("128", 128),
            ("129", 129),
            ("255", 255),
            ("small", 1000),
            ("chunk", SHA256_CHUNK),
            ("chunk+1", SHA256_CHUNK + 1),
        ] {
            let fixture = base.join(format!("fixture-{label}.bin"));
            let bytes = make(len);
            std::fs::write(&fixture, &bytes).unwrap();
            let (size, sha, crc) = digest_stream_path(&fixture).unwrap();
            assert_eq!(
                (size, sha, crc),
                (len as u64, sha256_hex(&bytes), crc32c(&bytes)),
                "the streaming triple must equal the one-shot values ({label}, {len} B)"
            );
            // The private `file_digest` (the helper shape)
            // agrees.
            assert_eq!(file_digest(&fixture).unwrap(), (len as u64, sha256_hex(&bytes), crc32c(&bytes)));
        }
        let _ = std::fs::remove_dir_all(&base);
    }
