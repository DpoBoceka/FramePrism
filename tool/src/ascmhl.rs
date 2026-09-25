//! The ASC MHL media-hash-list history (the
//! industry provenance standard's manifest, the `urn:ASC:MHL:v2.0`
//! lineage — the "v2.0 of the industry provenance standard" the
//! namespace carries literally; the old MHL 1.1 (2009, the
//! MD5/SHA1-era format) is a different, strictly weaker generation —
//! this module writes the NEW one).
//!
//! The WRITE side (the named scope): at EVERY standalone-offload
//! dest root, ONE generation per run:
//!   - `ascmhl/` — the history's directory at the dest (scope) root
//!     (the spec's 5.3.1 placement: the history lives in a directory
//!     named `ascmhl` at the TOP LEVEL of the media directory);
//!   - `NNNN_<dest-basename>_YYYY-MM-DD_HHMMSSZ.mhl` — the manifest
//!     (a "hashlist", the spec's 6.3 naming: the 4-digit generation
//!     from 0001, the scope folder's name, the run's creation
//!     instant — UTC; the file name's `HHMMSSZ` = the Zulu form of
//!     the SAME instant as the manifest's `creationdate`);
//!   - `ascmhl_chain.xml` — the chain (the namespace
//!     `urn:ASC:MHL:DIRECTORY:v2.0`): one `<hashlist sequencenr="N">`
//!     record per generation (the manifest's file name + the C4ID of
//!     that manifest file's bytes — the chain MANDATES c4);
//!   - The durability seam: the manifest's + the chain's
//!     bytes are filesystem-synchronized (`sync_file`) after their
//!     writes (a sync failure = the named hard-error band — the
//!     run's rc becomes the error rc) + the `ascmhl/` dir's
//!     best-effort sync after (the pinned note on failure — the
//!     content stands).
//!
//! The generation-1 semantics: the process is `transfer` (the
//! manifest is created as the data is copied — the offload case);
//! every hash element carries `action="original"` (the initial
//! hashes within the history — the `verified`/`failed` actions
//! belong to the VERIFY operation's generations, the follow-up). The
//! `creationdate` + every `hashdate` = the run's creation instant
//! (the run report's `created` unix seconds → UTC — the decision:
//! one run instant). `hostname` = the code's existing host source
//! (the run report's `host:` line — OS + ARCH). `tool` =
//! `frameprism` + the `version` attribute (the tool's version).
//!
//! THE RE-RUN CASE (append, never clobber): a run onto a dest
//! that already carries an `ascmhl` history reads the existing chain
//! (the max `sequencenr` + 1 — the existing manifest file names'
//! `NNNN` prefixes included, so a broken history can never clobber a
//! generation), writes the NEW generation's manifest, and APPENDS the
//! new chain record — the existing records are preserved
//! byte-for-byte (the chain is append-only: the writer splices the
//! new record before the closing tag of the existing file; a
//! corrupted or foreign chain that does not end with the closing tag
//! is the NAMED refusal, never a clobber).
//!
//! THE IGNORE SET (pinned): the history covers the MEDIA, not
//! frameprism's records. The `<ignore>` patterns = the spec's
//! mandatory defaults (`.DS_Store` + `ascmhl` — the history's own
//! files can never be records in themselves) + the `._*` AppleDouble
//! shadow prefix (the tool's `is_apple_double` convention — the
//! manifest must not record shadows) + the frameprism artifact
//! names (the exact post-17 tree's names: the offload manifest, the
//! ingest/reel/bake/derive manifests, the members record, the
//! checksum sidecars (both flavors), the source record, the QC
//! sidecar, the clip report (both renames), the run report (both
//! renames), the job report's three names —
//! referenced, never renamed — + the signature sidecar). The
//! matching semantics (the v1 simple rules — NO deep glob engine):
//! a bare name = any file/directory with that name at any depth;
//! `*.ext` = any entry ending in that suffix at any depth; `._*` =
//! the prefix rule at any depth. A matching DIRECTORY is skipped
//! with its whole subtree (the spec's ignore semantics).
//!
//! THE HASHES (c4 (C4ID) ONLY, every record): the C4ID (SMPTE
//! ST 2114 / the spec's Appendix D) = SHA-512 of the data, encoded
//! base58 over the C4ID character set (no 0/O/I/l; the leading zeros
//! padded with `1`), prefixed `c4` → exactly 90 chars. The per-FILE
//! record = the C4ID of the DEST file's bytes (the copy — the
//! provenance record is of the copy; the source sha rides the
//! offload manifest, the complementary per-file source→dest sha256
//! verification record — sha256 is NOT in the MHL format, the two
//! records complement each other). The per-DIRECTORY + the ROOT
//! records = the content/structure pair (the spec's Appendix G +
//! the reference implementation's `DirectoryHashContext` semantics —
//! the tie-breaker):
//!   - the CONTENT hash of a directory = the hash-of-hashes over the
//!     children's CONTENT hashes (a child directory contributes its
//!     content hash);
//!   - the STRUCTURE hash: per child, the fresh single-shot C4ID of
//!     `basename_utf8 + the mixed digest's octets` — a child FILE
//!     mixes its CONTENT digest, a child DIRECTORY mixes its
//!     STRUCTURE digest (a child directory's content hash is NOT
//!     mixed into the parent's structure — the structure-vs-content
//!     distinction, pinned by the test vectors); the directory's
//!     structure = the hash-of-hashes over those child values;
//!   - the HASH-OF-HASHES (Appendix G): sort the hash value STRINGS
//!     lexicographically, decode each to its Appendix D byte
//!     representation (for c4: the 64 SHA-512 octets — the digest,
//!     NOT the base58 string), write the octet stream to a fresh
//!     generator, digest, decode;
//!   - the ROOT hash = the same two computations at the scope root.
//! The manifest's `<hashes>` entries render in post-order (a
//! directory's children — sorted lexicographically, files and
//! directories merged by name — come BEFORE the directory's own
//! `<directoryhash>` entry; the reference's `post_order_lexicographic`
//! order, the worked examples' order). The scope root itself is NOT
//! a `<directoryhash>` entry (its hashes = the `roothash`).
//!
//! THE MANIFEST SHAPE (the v1 element set — the exact XSD sequence,
//! the deterministic rendering pinned in the tests: the two-space
//! indent, the attribute order per the spec's examples — the
//! `path`'s `size` before `lastmodificationdate`, the hash
//! elements' `action` before `hashdate`; NO `metadata` /
//! `references` / `previousPath` / `author` / `README.txt` in v1):
//! `hashlist@version="2.0"@xmlns="urn:ASC:MHL:v2.0"` →
//! `creatorinfo` (creationdate / hostname / tool@version) →
//! `processinfo` (process / roothash (content + structure
//! containers, each one `<c4 hashdate="…">`) / ignore (one
//! `<pattern>` per ignore pattern)) → `hashes` (one `<hash>` per managed
//! file — the dest-relative path + the size + the dest file's mtime
//! + the `<c4 action="original" hashdate="…">`; one `<directoryhash>`
//! per managed non-root directory — the path + the mtime + the
//! content/structure containers). The `lastmodificationdate` = the
//! DEST file/directory's mtime (the mirror preserves the source
//! mtime; the recorded value is the dest's, as the spec's example
//! records).
//!
//! THE FAILURE BAND: a write failure (the ascmhl dir's
//! creation, the manifest write, the chain read/append/write) is the
//! named hard-error band (the `.with_context` class — the error
//! surfaces, the run's rc becomes the error rc — the records are
//! already standing: the ascmhl is written LAST, after the per-clip
//! manifests + the run report + the job report — the provenance
//! record comes after the verification records). Silent on success
//! (R-INV-A: the stderr surface gains NO line).
//!
//! THE BOUNDARY : the standalone `offload` subcommand's
//! N-dest runner ONLY (the wiring in `offload::run_offload_multi` —
//! automatic, no flag, like the job report); the encode output (the
//! archive) gets NO ascmhl (it is the original encode, not a copy),
//! and the encode surface's `--to` dest = the named follow-up (the
//! same named follow-up as the encode-surface job report); the MHL
//! VERIFY pass = the `audit` verb's re-verify surface (the
//! the read side below: the recompute of every recorded c4 + the
//! roothash seal check, the conformant v2.0 import); the
//! `verified`/`failed` action generations = the named follow-up;
//! the flatten operation + nested histories = v1
//! N/A (the dest trees never carry a nested scope); manifest IMPORT
//! (reading other tools' ascmhl histories) = the read side (SHIPPED):
//! the `parse_hashlist` strict parser (the v1 element set
//! + the named refusal classes — every one names the manifest + the
//! offending value) + the `verify_scope` scope re-verify (the
//! per-file c4 recompute — the size pre-filter, the offload row
//! vocabulary `OK`/`MISSING`/`SIZE_MISMATCH`/`C4_MISMATCH` — + the
//! roothash seal over the WHOLE scope with the MANIFEST'S OWN ignore
//! patterns — the import fact: a foreign tool's conformant v2.0
//! hashlist verifies against its own values) + the `select_manifest`
//! latest-record selection (the chain's last record, the per-record
//! c4 verification, the single-manifest no-chain carve-out, the
//! named ambiguity + corrupt-record refusals) + the `audit_mhl`
//! seam the `audit` verb's detection-driven arm calls (a dir without
//! `ascmhl/` audits byte-identical to pre-existing — R-INV); the
//! conformant v2.0 hashlist is the import scope — the 2009 MHL 1.1
//! / JSON lineage is out of scope, the namespace + version check is
//! the conformant refusal; the `verified`/`failed` action
//! generations = the named follow-up.
//!
//! std-only (no new crates): the SHA-512 is hand-rolled (the
//! `jxl::sha256` idiom — FIPS 180-4, the constants are the
//! FIPS data, the vectors are the contract — the `sha512_vectors`
//! test pins the core against hashlib; the C4ID vectors pin the
//! base58 over it), the base58 divmod is ~20 lines, the XML is
//! hand-rolled strings + the minimal `parse_lite` structural parser
//! (the self-parse pattern — the chain reader + the in-suite
//! well-formedness/structure check).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// The history's directory name (the spec's 5.3.1: the `ascmhl`
/// directory at the scope's top level — the mandatory ignore default
/// #2).
pub const ASCMHL_DIR_NAME: &str = "ascmhl";

/// The chain file's name (inside the ascmhl dir).
pub const CHAIN_NAME: &str = "ascmhl_chain.xml";

/// The ignore set (the EXACT pinned patterns — the order is the
/// `<ignore>` element's order + the matcher's order): the mandatory
/// defaults, the shadow prefix, then the frameprism artifact names
/// (the exact post-rename tree's names — the encode sidecar list from
/// the code + the offload / run / job report names; the job report's
/// three names are the contract — referenced, never
/// renamed).
pub const IGNORE_PATTERNS: &[&str] = &[
    // the mandatory defaults (the spec's 5.6.1.2):
    ".DS_Store",
    "ascmhl",
    // the AppleDouble shadow prefix (the tool's `is_apple_double`
    // convention — the manifest must not record shadows):
    "._*",
    // the frameprism artifacts (the exact names as of the post-17
    // tree — the encode sidecar list from the code + the offload /
    // run / job report names):
    "*.offload-manifest.tsv",
    "*.ingest-manifest.tsv",
    "*.reel-manifest.tsv",
    "*.bake-manifest.tsv",
    "*.derive-manifest.tsv",
    "*.members.tsv",
    "*.checksums.tsv",
    "*.jxl-checksums.tsv",
    "*.sources.tsv",
    "*.qc.tsv",
    "*.frameprism-report.md",
    ".frameprism-run-report.md",
    ".frameprism-job-report.md",
    ".frameprism-job-report.csv",
    ".frameprism-job-report.html",
    "*.sig",
];

// ---------------------------------------------------------------------------
// The SHA-512 (FIPS 180-4 — the hand-rolled idiom,
// `jxl::sha256`'s 64-bit twin: the 128-byte blocks, the 80-round
// compression) + the C4ID (the spec's Appendix D) + the hash-of-hashes
// (Appendix G)
// ---------------------------------------------------------------------------

/// The FIPS 180-4 SHA-512 initial hash values (the first 64
/// fractional bits of the SQUARE roots of the first 8 primes — the
/// spec's DATA, not a derivation; the vectors are the contract).
const SHA512_H0: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// The FIPS 180-4 SHA-512 round constants (the first 64 fractional
/// bits of the CUBE roots of the first 80 primes — the spec's DATA;
/// the table matches RFC 6234 §SHA-512 verbatim). The contract:
/// the `sha512_vectors` test (the hashlib vectors — a transcription
/// error in any constant fails it) + the pinned C4ID vectors (the
/// base58 over this core).
const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// One SHA-512 compression block (FIPS 180-4 section 8.1): the 16-word
/// message-schedule expansion to 80 words + the 80-round compression
/// of `h` (extracted from the one-shot's inner loop: the
/// SAME SHA512_K / SHA512_H0 constants, the SAME schedule +
/// compression — byte-identical by construction; the streaming
/// property test + the KATs prove it).
fn compress_block512(h: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = u64::from_be_bytes([
            block[8 * i],
            block[8 * i + 1],
            block[8 * i + 2],
            block[8 * i + 3],
            block[8 * i + 4],
            block[8 * i + 5],
            block[8 * i + 6],
            block[8 * i + 7],
        ]);
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) = (
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
    );
    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA512_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
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

/// The incremental SHA-512 state (the streaming helper,
/// the `Sha256State` precedent): the one-shot body split into
/// `update` (buffers the partial 128-byte block, compresses full
/// blocks) + `finalize` (the FIPS 180-4 / ISO 10118 padding — 0x80
/// and zeros + the 16-byte big-endian BIT count, the overflow-safe
/// `wrapping_mul(8)` bit count, as the one-shot). Any chunking of
/// `update` yields the same digest (the property test proves it
/// across chunk sizes 1…1 MiB).
pub struct Sha512State {
    h: [u64; 8],
    buf: [u8; 128],
    buf_len: u16,
    total: u128,
}

impl Sha512State {
    pub fn new() -> Self {
        Sha512State {
            h: SHA512_H0,
            buf: [0u8; 128],
            buf_len: 0,
            total: 0,
        }
    }
}

impl Default for Sha512State {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512State {
    /// Feed a chunk (any size; the partial block is buffered).
    pub fn update(&mut self, data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u128);
        let mut off = 0usize;
        if self.buf_len > 0 {
            let take = (128 - self.buf_len as usize).min(data.len());
            self.buf[self.buf_len as usize..self.buf_len as usize + take]
                .copy_from_slice(&data[..take]);
            self.buf_len += take as u16;
            off = take;
            if self.buf_len == 128 {
                compress_block512(&mut self.h, &self.buf);
                self.buf_len = 0;
            }
        }
        while off + 128 <= data.len() {
            let mut block = [0u8; 128];
            block.copy_from_slice(&data[off..off + 128]);
            compress_block512(&mut self.h, &block);
            off += 128;
        }
        if off < data.len() {
            let take = data.len() - off;
            self.buf[..take].copy_from_slice(&data[off..]);
            self.buf_len = take as u16;
        }
    }

    /// The FIPS 180-4 / ISO 10118 padding + the digest (consumes the
    /// state).
    pub fn finalize(self) -> [u8; 64] {
        let mut h = self.h;
        let bit_len = self.total.wrapping_mul(8);
        let mut rem = self.buf;
        let mut rem_len = self.buf_len as usize;
        rem[rem_len] = 0x80;
        rem_len += 1;
        if rem_len > 112 {
            while rem_len < 128 {
                rem[rem_len] = 0;
                rem_len += 1;
            }
            compress_block512(&mut h, &rem);
            rem_len = 0;
        }
        while rem_len < 112 {
            rem[rem_len] = 0;
            rem_len += 1;
        }
        rem[112..128].copy_from_slice(&bit_len.to_be_bytes());
        compress_block512(&mut h, &rem);
        let mut out = [0u8; 64];
        for (i, word) in h.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// The SHA-512 digest (FIPS 180-4) — the one-shot, re-implemented
/// over the incremental state (one `update` + `finalize`:
/// every existing call site keeps its exact output; the KATs + the
/// one-pass proof are the byte-invariance net).
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut s = Sha512State::new();
    s.update(data);
    s.finalize()
}

/// The C4ID character set (SMPTE ST 2114 / the spec's Appendix D —
/// no `0`, `O`, `I`, `l`; `1` is the zero-pad digit).
const C4_CHARSET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The C4ID over a digest (the spec's Appendix D; the reference
/// implementation's `C4.string_digest` algorithm): the SHA-512
/// digest read as a big-endian integer, repeated divmod by 58 over
/// the C4ID character set (most-significant first), the leading
/// zeros padded with `1`, prefixed `c4` → exactly 90 chars. (Extracted from the one-shot `c4`: the divmod the one-shot
/// carried, byte-identical by construction.)
pub fn c4_of_digest(digest: [u8; 64]) -> String {
    let mut buf = digest;
    let mut digits: Vec<u8> = Vec::new();
    while buf.iter().any(|b| *b != 0) {
        // One divmod-58 step over the 64-octet big-endian integer
        // (the remainder fits: the carry < 58, so carry*256+255 < 2^16).
        let mut rem: u64 = 0;
        for b in buf.iter_mut() {
            let cur = (rem << 8) | (*b as u64);
            *b = (cur / 58) as u8;
            rem = cur % 58;
        }
        digits.push(C4_CHARSET[rem as usize]);
    }
    digits.reverse();
    let s: String = digits.iter().map(|b| *b as char).collect();
    let pad = 88usize.saturating_sub(s.len());
    format!("c4{}{}", "1".repeat(pad), s)
}

/// The C4ID (the spec's Appendix D): the SHA-512 of the data + the
/// Appendix D decode — `sha512` + `c4_of_digest` (the
/// one-shot the body was split from — the byte-identity by
/// construction; the KATs pass unmodified).
pub fn c4(data: &[u8]) -> String {
    c4_of_digest(sha512(data))
}

/// The streaming C4ID over a file (the bounded-memory
/// read: `SHA256_CHUNK`-sized reads into a re-used buffer (
/// ONE chunk size for every streaming site; the
/// read-only reuse, jxl.rs untouched), never the whole file in a
/// `Vec`). The io error propagates RAW — the caller wraps it with
/// the site's existing context wording (the "hash the ascmhl file
/// …" / "hash the mhl re-verify file …" / "read the ascmhl manifest
/// …" wordings are unchanged per site).
pub fn c4_stream_path(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut s = Sha512State::new();
    let mut buf = vec![0u8; crate::jxl::SHA256_CHUNK];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        s.update(&buf[..n]);
    }
    Ok(c4_of_digest(s.finalize()))
}

/// The C4ID's decode to the digest's octets (the reference
/// `C4.bytes_from_string_digest`; the Appendix G "encode the hash
/// value into its appropriate byte representation" — for c4: the 64
/// SHA-512 octets, NOT the base58 string): the 88-char body read
/// base58 as a big-endian integer into the 64-octet buffer. A valid
/// C4ID (one this module produced, or one from the format) decodes
/// to < 2^512 — the buffer is the width by construction (a
/// malformed overlong input would overflow the carry, which the
/// 64-octet buffer drops; the decode is only fed valid C4IDs).
pub fn c4_bytes(c4id: &str) -> [u8; 64] {
    let body = c4id.strip_prefix("c4").unwrap_or(c4id);
    let mut acc: [u8; 64] = [0; 64];
    for ch in body.bytes() {
        let digit = C4_CHARSET.iter().position(|c| *c == ch).unwrap_or(0) as u64;
        let mut carry = digit;
        for b in acc.iter_mut().rev() {
            let cur = (*b as u64).wrapping_mul(58).wrapping_add(carry);
            *b = cur as u8;
            carry = cur >> 8;
        }
    }
    acc
}

/// The hash-of-hashes (the spec's Appendix G; the reference
/// `Hasher.hash_of_hash_list`): sort the hash value STRINGS
/// lexicographically, decode each to its Appendix D byte
/// representation (the c4: the digest's octets), write the octet
/// stream to a fresh generator (the concatenation — Merkle–Damgård:
/// equivalent to the incremental updates), digest, decode. The empty
/// list = the digest of the empty input (the reference's empty-list
/// rule). All the children's hashes are c4 (the one algorithm,
/// so Appendix G's same-algorithm requirement holds trivially).
pub fn hash_of_hash_list(list: &[&str]) -> String {
    let mut sorted: Vec<&str> = list.to_vec();
    sorted.sort_unstable();
    let mut buf: Vec<u8> = Vec::with_capacity(sorted.len() * 64);
    for s in &sorted {
        buf.extend_from_slice(&c4_bytes(s));
    }
    c4(&buf)
}

/// The parent structure's per-child mix (the reference
/// `DirectoryHashContext`: the child FILE mixes its CONTENT digest,
/// the child DIRECTORY its STRUCTURE digest — the child
/// directory's content hash is NOT mixed into the structure): the
/// fresh single-shot C4ID of `basename_utf8 + the mixed digest's
/// octets` (the child's NAME, not its full path).
pub fn structure_child_c4(basename: &str, mixed_c4: &str) -> String {
    let mut buf = basename.as_bytes().to_vec();
    buf.extend_from_slice(&c4_bytes(mixed_c4));
    c4(&buf)
}

// ---------------------------------------------------------------------------
// The ignore matching (the simple rules — the name-level matcher)
// ---------------------------------------------------------------------------

/// One ignore pattern over an entry's NAME (the v1 simple rules — NO
/// deep glob engine): a `*.ext` pattern = the suffix rule (any entry
/// ending in the suffix, at any depth); a `prefix*` pattern = the
/// prefix rule (any entry starting with the prefix, at any depth —
/// the `._*` shadow rule); a bare name = the exact-name rule (any
/// file/directory with that name, at any depth).
fn pattern_matches(pattern: &str, name: &str) -> bool {
    if let Some(stripped) = pattern.strip_prefix('*') {
        name.ends_with(stripped)
    } else if let Some(stripped) = pattern.strip_suffix('*') {
        name.starts_with(stripped)
    } else {
        name == pattern
    }
}

/// The ignore decision over an entry's name (a matching entry is
/// skipped — a matching DIRECTORY with its whole subtree: the spec's
/// ignore semantics).
pub fn is_ignored(name: &str) -> bool {
    IGNORE_PATTERNS.iter().any(|p| pattern_matches(p, name))
}

// ---------------------------------------------------------------------------
// The UTC stamps (the std-only arithmetic —
// `jobreport::utc_timestamp`'s civil-from-days, the `+00:00` form)
// ---------------------------------------------------------------------------

/// The XSD `dateTime` UTC form (examples:
/// `T09:15:00+00:00` — the `+00:00` offset, the
/// `lastmodificationdate` / `creationdate` / `hashdate` attributes):
/// `jobreport::utc_timestamp` civil arithmetic + the
/// offset suffix.
fn utc_iso(unix: u64) -> String {
    let z = crate::jobreport::utc_timestamp(unix);
    format!("{}+00:00", &z[..z.len() - 1])
}

/// The manifest file name's date/time stamp (the spec's 6.3: the
/// `YYYY-MM-DD` + the `HHMMSSZ` — the Zulu form of the SAME instant
/// as the manifest's `creationdate` — NO colons in the time slot).
fn utc_filename_stamp(unix: u64) -> String {
    let ts = crate::jobreport::utc_timestamp(unix); // YYYY-MM-DDTHH:MM:SSZ
    format!("{}_{}Z", &ts[..10], ts[11..ts.len() - 1].replace(':', ""))
}

// ---------------------------------------------------------------------------
// The XML (the deterministic hand-rolled rendering + the minimal
// `parse_lite` structural parser — the self-parse pattern)
// ---------------------------------------------------------------------------

/// The XML text/attribute escaping (the five standard entities).
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A minimal XML element (the `parse_lite` node — the
/// well-formedness + structure check: no namespace validation, no
/// DTD, the entity-decoded text).
#[derive(Clone, Debug)]
pub struct XmlEl {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<XmlEl>,
    /// The direct text (entity-decoded; the whitespace-only runs are
    /// dropped — the element's content is either elements or text,
    /// not mixed — the parser-lite's surface).
    pub text: String,
}

/// The total-safety nesting bound:
/// `parse_element`'s recursion was UNBOUNDED — a hostile
/// depth-50,000 nesting input (350,000 B — the foreign-manifest
/// import surface, where `parse_hashlist` calls
/// `parse_lite` FIRST) = a stack overflow → SIGABRT (exit 134 — not
/// a typed error, not a Rust panic; measured: 10,000 levels OK,
/// 50,000 aborts). The guard bails when the depth EXCEEDS
/// `MAX_ELEMENT_DEPTH` — 2,000x the conformant v2.0 element set's max
/// nesting depth of 5 (the `hashlist` → `processinfo` → `roothash` →
/// `content` → `c4` chain) — a conformant document NEVER triggers:
/// zero behavior change on conformant input, the byte-frozen contract
/// holds. The bound rides the guard's wording (the
/// expected value rides the wording — a bound change is a conscious
/// wording change).
pub(crate) const MAX_ELEMENT_DEPTH: usize = 10_000;

/// The minimal XML parser: the well-formedness
/// (the balanced tag stack, the quoted attributes) + the structure
/// (the elements, the attributes, the entity-decoded text). The
/// supported surface = the ascmhl manifests + the chain (the XML
/// declaration, the elements, the attributes, the five standard
/// entities, the comments — anything else is a NAMED error, never a
/// silent pass).
pub fn parse_lite(src: &str) -> Result<XmlEl> {
    let b = src.as_bytes();
    let mut i = 0usize;
    skip_ws(b, &mut i);
    if b[i..].starts_with(b"<?xml") {
        let end = b[i..]
            .windows(2)
            .position(|w| w == b"?>")
            .ok_or_else(|| anyhow::anyhow!("the XML declaration is unterminated"))?
            + i;
        i = end + 2;
        skip_ws(b, &mut i);
    }
    let (root, mut j) = parse_element(b, i, 1)?;
    skip_ws(b, &mut j);
    if j != b.len() {
        bail!("trailing content after the root element at byte {j}");
    }
    Ok(root)
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && b[*i].is_ascii_whitespace() {
        *i += 1;
    }
}

/// The five standard entities (the parser-lite's surface — an
/// unknown entity / a bare `&` = the named error).
fn decode_entities(s: &str) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < s.len() {
        if s[i..].starts_with('&') {
            let end = s[i..]
                .find(';')
                .ok_or_else(|| anyhow::anyhow!("an unterminated entity at byte {i}"))?
                + i;
            match &s[i + 1..end] {
                "amp" => out.push('&'),
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                other => bail!(
                    "an unknown entity &{other}; (the parser-lite's surface: the five standard entities)"
                ),
            }
            i = end + 1;
        } else {
            let c = s[i..].chars().next().expect("a valid char at a byte boundary");
            out.push(c);
            i += c.len_utf8();
        }
    }
    Ok(out)
}

/// One element + the cursor past its close (the recursive shape).
/// `depth` = the nesting level (1 at the root, +1 per child — the
/// total-safety bound: the guard below bails when it
/// EXCEEDS `MAX_ELEMENT_DEPTH` — the unbounded recursion's
/// stack-overflow surface, the named refusal instead of the SIGABRT).
fn parse_element(b: &[u8], start: usize, depth: usize) -> Result<(XmlEl, usize)> {
    if depth > MAX_ELEMENT_DEPTH {
        bail!(
            "an excessive element nesting depth {depth} (the parse_lite nesting bound is {MAX_ELEMENT_DEPTH} — the malformed record — the record is untrustable)"
        );
    }
    let mut i = start;
    if i >= b.len() || b[i] != b'<' {
        bail!(
            "expected an element start, got {:?} at byte {i}",
            b.get(i).copied()
        );
    }
    i += 1;
    let name_start = i;
    while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' && b[i] != b'/' {
        i += 1;
    }
    let name = std::str::from_utf8(&b[name_start..i])
        .map_err(|_| anyhow::anyhow!("a non-UTF-8 element name at byte {name_start}"))?;
    if name.is_empty() {
        bail!("an empty element name at byte {name_start}");
    }
    let mut el = XmlEl {
        name: name.to_string(),
        attrs: Vec::new(),
        children: Vec::new(),
        text: String::new(),
    };
    // The attributes (until the bare `>` or the `/>` self-close).
    loop {
        skip_ws(b, &mut i);
        if i >= b.len() {
            bail!("an unterminated element start for <{}>", el.name);
        }
        if b[i] == b'/' {
            if i + 1 < b.len() && b[i + 1] == b'>' {
                return Ok((el, i + 2));
            }
            bail!("a malformed self-close for <{}>", el.name);
        }
        if b[i] == b'>' {
            i += 1;
            break;
        }
        let an_start = i;
        while i < b.len()
            && !b[i].is_ascii_whitespace()
            && b[i] != b'='
            && b[i] != b'>'
            && b[i] != b'/'
        {
            i += 1;
        }
        let an = std::str::from_utf8(&b[an_start..i])
            .map_err(|_| anyhow::anyhow!("a non-UTF-8 attribute name at byte {an_start}"))?;
        if an.is_empty() {
            bail!("an empty attribute name in <{}>", el.name);
        }
        skip_ws(b, &mut i);
        if i >= b.len() || b[i] != b'=' {
            bail!("the attribute {an:?} of <{}> has no value", el.name);
        }
        i += 1;
        skip_ws(b, &mut i);
        if i >= b.len() || (b[i] != b'"' && b[i] != b'\'') {
            bail!(
                "the attribute {an:?} of <{}> has an unquoted value",
                el.name
            );
        }
        let q = b[i];
        i += 1;
        let v_start = i;
        while i < b.len() && b[i] != q {
            i += 1;
        }
        if i >= b.len() {
            bail!(
                "the attribute {an:?} of <{}> has an unterminated value",
                el.name
            );
        }
        let v = std::str::from_utf8(&b[v_start..i])
            .map_err(|_| anyhow::anyhow!("a non-UTF-8 attribute value for {an:?}"))?;
        i += 1;
        el.attrs.push((an.to_string(), decode_entities(v)?));
    }
    // The children + the text (until the matching `</name>`).
    loop {
        if i >= b.len() {
            bail!("the element <{}> is unclosed", el.name);
        }
        if b[i] == b'<' {
            if i + 1 < b.len() && b[i + 1] == b'!' {
                if i + 4 <= b.len() && &b[i..i + 4] == b"<!--" {
                    let end = b[i..]
                        .windows(3)
                        .position(|w| w == b"-->")
                        .ok_or_else(|| anyhow::anyhow!("an unterminated comment at byte {i}"))?
                        + i;
                    i = end + 3;
                    continue;
                }
                bail!("unsupported markup at byte {i}");
            }
            if i + 1 < b.len() && b[i + 1] == b'/' {
                i += 2;
                let cs = i;
                while i < b.len() && b[i] != b'>' {
                    i += 1;
                }
                if i >= b.len() {
                    bail!("an unterminated close tag for <{}>", el.name);
                }
                let close = std::str::from_utf8(&b[cs..i])
                    .map_err(|_| anyhow::anyhow!("a non-UTF-8 close tag at byte {cs}"))?;
                if close != el.name {
                    bail!(
                        "a mismatched close: expected </{}>, got </{}>",
                        el.name,
                        close
                    );
                }
                return Ok((el, i + 1));
            }
            let (child, j) = parse_element(b, i, depth + 1)?;
            el.children.push(child);
            i = j;
        } else {
            let ts = i;
            while i < b.len() && b[i] != b'<' {
                i += 1;
            }
            let t = std::str::from_utf8(&b[ts..i])
                .map_err(|_| anyhow::anyhow!("a non-UTF-8 text run at byte {ts}"))?;
            let t = decode_entities(t)?;
            if !t.trim().is_empty() {
                if !el.text.is_empty() {
                    bail!(
                        "mixed content in <{}> (the parser-lite's surface: elements or text, not both)",
                        el.name
                    );
                }
                el.text = t;
            }
        }
    }
}

/// An element attribute lookup (the `parse_lite` consumer's helper —
/// `None` when absent).
pub fn attr<'a>(el: &'a XmlEl, name: &str) -> Option<&'a str> {
    el.attrs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

// ---------------------------------------------------------------------------
// The manifest (the data + the deterministic rendering)
// ---------------------------------------------------------------------------

/// One manifest entry (the `<hash>` / `<directoryhash>` row — the
/// render order is the POST-ORDER: a directory's children come
/// before the directory's own entry).
#[derive(Clone, Debug)]
pub enum Entry {
    /// A managed file (the dest-relative path, the size, the dest
    /// file's mtime — unix seconds — the C4ID of the dest file's
    /// bytes).
    File {
        path: String,
        size: u64,
        mtime: u64,
        c4: String,
    },
    /// A managed non-root directory (the dest-relative path, the
    /// mtime, the content + structure C4IDs).
    Dir {
        path: String,
        mtime: u64,
        content: String,
        structure: String,
    },
}

/// The manifest's data (the pure renderer's input — the wall-clock
/// capture happens in the writer, the rendering is deterministic).
#[derive(Clone, Debug)]
pub struct ManifestData {
    /// The scope folder's name (the dest dir's basename — the file
    /// name's slot).
    pub folder: String,
    /// The run's creation instant (unix seconds, UTC — the
    /// `creationdate` + every `hashdate` + the file name's stamp).
    pub created: u64,
    /// The machine's hostname (the code's existing host source — the
    /// run report's `host:` line).
    pub hostname: String,
    /// The tool's version (the `tool`'s `version` attribute).
    pub tool_version: String,
    /// The scope root's content + structure C4IDs (the `roothash`).
    pub root_content: String,
    pub root_structure: String,
    /// The managed entries (the post-order render order).
    pub entries: Vec<Entry>,
}

/// The manifest's file name (the spec's 6.3): `NNNN_<foldername>_
/// YYYY-MM-DD_HHMMSSZ.mhl` — the 4-digit generation (from 0001), the
/// scope folder's name, the run's creation instant (UTC).
pub fn manifest_name(folder: &str, created: u64, generation: u32) -> String {
    format!("{:04}_{}_{}.mhl", generation, folder, utc_filename_stamp(created))
}

/// The manifest's EXACT rendering (the v1 element set — the XSD
/// sequence: `hashlist` → `creatorinfo` → `processinfo` → `hashes`;
/// NO `metadata` / `references` in v1; the two-space indent, the
/// attribute order per the spec's examples — the byte-stable
/// rendering pinned in the tests). An empty managed set omits the
/// `<hashes>` element (the XSD's `minOccurs="0"` — the roothash over
/// the empty scope stands).
pub fn render_manifest(m: &ManifestData) -> String {
    let iso = utc_iso(m.created);
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    s.push_str("<hashlist version=\"2.0\" xmlns=\"urn:ASC:MHL:v2.0\">\n");
    s.push_str("  <creatorinfo>\n");
    s.push_str(&format!("    <creationdate>{iso}</creationdate>\n"));
    s.push_str(&format!("    <hostname>{}</hostname>\n", xml_escape(&m.hostname)));
    s.push_str(&format!(
        "    <tool version=\"{}\">frameprism</tool>\n",
        xml_escape(&m.tool_version)
    ));
    s.push_str("  </creatorinfo>\n");
    s.push_str("  <processinfo>\n");
    s.push_str("    <process>transfer</process>\n");
    s.push_str("    <roothash>\n");
    s.push_str("      <content>\n");
    s.push_str(&format!(
        "        <c4 hashdate=\"{iso}\">{}</c4>\n",
        xml_escape(&m.root_content)
    ));
    s.push_str("      </content>\n");
    s.push_str("      <structure>\n");
    s.push_str(&format!(
        "        <c4 hashdate=\"{iso}\">{}</c4>\n",
        xml_escape(&m.root_structure)
    ));
    s.push_str("      </structure>\n");
    s.push_str("    </roothash>\n");
    s.push_str("    <ignore>\n");
    for p in IGNORE_PATTERNS {
        s.push_str(&format!("      <pattern>{}</pattern>\n", xml_escape(p)));
    }
    s.push_str("    </ignore>\n");
    s.push_str("  </processinfo>\n");
    if !m.entries.is_empty() {
        s.push_str("  <hashes>\n");
        for e in &m.entries {
            match e {
                Entry::File {
                    path,
                    size,
                    mtime,
                    c4,
                } => {
                    s.push_str("    <hash>\n");
                    s.push_str(&format!(
                        "      <path size=\"{size}\" lastmodificationdate=\"{}\">{}</path>\n",
                        xml_escape(&utc_iso(*mtime)),
                        xml_escape(path)
                    ));
                    s.push_str(&format!(
                        "      <c4 action=\"original\" hashdate=\"{iso}\">{}</c4>\n",
                        xml_escape(c4)
                    ));
                    s.push_str("    </hash>\n");
                }
                Entry::Dir {
                    path,
                    mtime,
                    content,
                    structure,
                } => {
                    s.push_str("    <directoryhash>\n");
                    s.push_str(&format!(
                        "      <path lastmodificationdate=\"{}\">{}</path>\n",
                        xml_escape(&utc_iso(*mtime)),
                        xml_escape(path)
                    ));
                    s.push_str("      <content>\n");
                    s.push_str(&format!(
                        "        <c4 hashdate=\"{iso}\">{}</c4>\n",
                        xml_escape(content)
                    ));
                    s.push_str("      </content>\n");
                    s.push_str("      <structure>\n");
                    s.push_str(&format!(
                        "        <c4 hashdate=\"{iso}\">{}</c4>\n",
                        xml_escape(structure)
                    ));
                    s.push_str("      </structure>\n");
                    s.push_str("    </directoryhash>\n");
                }
            }
        }
        s.push_str("  </hashes>\n");
    }
    s.push_str("</hashlist>\n");
    s
}

// ---------------------------------------------------------------------------
// The chain (the append-only model)
// ---------------------------------------------------------------------------

const CHAIN_HEADER: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ascmhldirectory xmlns=\"urn:ASC:MHL:DIRECTORY:v2.0\">\n";
const CHAIN_FOOTER: &str = "</ascmhldirectory>\n";

/// One chain record's rendering (the worked examples' shape: the
/// `sequencenr` attribute, the `path` (the manifest's file name),
/// the `c4` (the C4ID of that manifest file's bytes — NO attributes:
/// the chain's c4 is the reference hash of the generation, not an
/// action-bearing hash entry)).
pub fn chain_record(sequencenr: u32, manifest_name: &str, manifest_c4: &str) -> String {
    format!(
        "  <hashlist sequencenr=\"{sequencenr}\">\n    <path>{}</path>\n    <c4>{}</c4>\n  </hashlist>\n",
        xml_escape(manifest_name),
        xml_escape(manifest_c4)
    )
}

/// The chain file over `existing` (the append model): a fresh
/// history = the header + the record + the close; a re-run = the
/// existing bytes preserved byte-for-byte, the new record spliced
/// before the closing tag. A corrupted or foreign chain (no
/// closing-tag ending) = the NAMED refusal (never a clobber).
pub fn render_chain(
    existing: &str,
    sequencenr: u32,
    manifest_name: &str,
    manifest_c4: &str,
) -> Result<String> {
    if existing.is_empty() {
        return Ok(CHAIN_HEADER.to_string()
            + &chain_record(sequencenr, manifest_name, manifest_c4)
            + CHAIN_FOOTER);
    }
    let body = existing.strip_suffix(CHAIN_FOOTER).ok_or_else(|| {
        anyhow::anyhow!(
            "the ascmhl chain does not end with the closing tag (a corrupted or foreign chain — the append is refused, never a clobber)"
        )
    })?;
    Ok(body.to_string()
        + &chain_record(sequencenr, manifest_name, manifest_c4)
        + CHAIN_FOOTER)
}

/// The chain's existing records (the `parse_lite` read: the
/// `<hashlist sequencenr="N">` elements' `sequencenr` + `path` +
/// `c4` text).
pub fn read_chain(existing: &str) -> Result<Vec<(u32, String, String)>> {
    let root = parse_lite(existing)?;
    if root.name != "ascmhldirectory" {
        bail!("the ascmhl chain's root is <{}>, expected <ascmhldirectory>", root.name);
    }
    let mut out = Vec::new();
    for el in &root.children {
        if el.name != "hashlist" {
            bail!("an unexpected <{}> element in the ascmhl chain", el.name);
        }
        let nr = attr(el, "sequencenr")
            .and_then(|v| v.parse::<u32>().ok())
            .ok_or_else(|| anyhow::anyhow!("the ascmhl chain's <hashlist> is missing a numeric sequencenr"))?;
        let mut path = None;
        let mut c4 = None;
        for child in &el.children {
            match child.name.as_str() {
                "path" => path = Some(child.text.clone()),
                "c4" => c4 = Some(child.text.clone()),
                other => bail!("an unexpected <{other}> element in the ascmhl chain's <hashlist>"),
            }
        }
        let (Some(path), Some(c4)) = (path, c4) else {
            bail!("the ascmhl chain's <hashlist> is missing its <path> / <c4>");
        };
        out.push((nr, path, c4));
    }
    Ok(out)
}

/// The next generation number: the max of (the existing
/// chain's `sequencenr`s, the existing manifest file names' `NNNN`
/// prefixes) + 1 — a fresh history (no ascmhl dir) = 1.
pub fn next_generation(ascmhl_dir: &Path) -> Result<u32> {
    if !ascmhl_dir.is_dir() {
        return Ok(1);
    }
    let mut max: u32 = 0;
    let chain_path = ascmhl_dir.join(CHAIN_NAME);
    match std::fs::read_to_string(&chain_path) {
        Ok(existing) => {
            if let Ok(records) = read_chain(&existing) {
                for (nr, _, _) in records {
                    max = max.max(nr);
                }
            }
            // An unparseable chain is NOT a reason to clobber a
            // generation: the manifest file names' NNNNs still set
            // the floor (below) — the chain's read error surfaces at
            // the append (the closing-tag refusal).
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("read the ascmhl chain {}", chain_path.display())),
    }
    for entry in std::fs::read_dir(ascmhl_dir)
        .with_context(|| format!("read the ascmhl dir {}", ascmhl_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".mhl") {
            let head: String = name.chars().take(4).collect();
            if head.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(g) = head.parse::<u32>() {
                    max = max.max(g);
                }
            }
        }
    }
    Ok(max + 1)
}

// ---------------------------------------------------------------------------
// The scope walk + the directory-hash computation (the reference
// `DirectoryHashContext` + `post_order_lexicographic`)
// ---------------------------------------------------------------------------

struct FileNode {
    name: String,
    size: u64,
    mtime: u64,
    c4: String,
}

struct DirNode {
    name: String,
    mtime: u64,
    files: Vec<FileNode>,
    dirs: Vec<DirNode>,
}

fn mtime_unix(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The scope walk (the built-in ignore set — the write side's
/// walk): the `walk_with` body with `is_ignored`.
fn walk(dir: &Path, visited: &mut HashSet<(u64, u64)>) -> Result<DirNode> {
    walk_with(dir, visited, &is_ignored)
}

/// The scope walk with a caller-supplied ignore predicate (the read
/// side passes the MANIFEST'S OWN ignore patterns — the import fact;
/// the write side passes the built-in `is_ignored`, so the write
/// behavior is the pre-existing walk's, byte-identical). The
/// ignore applies at the entry level — a matching directory skips its whole
/// subtree; the mirror's guards: symlinked entries skipped, the
/// (dev, ino) cycle guard. Every managed file's bytes are hashed (the
/// read side's roothash recompute hashes the scope's CURRENT bytes —
/// the re-verify surface).
fn walk_with(
    dir: &Path,
    visited: &mut HashSet<(u64, u64)>,
    ignored: &dyn Fn(&str) -> bool,
) -> Result<DirNode> {
    let meta = std::fs::metadata(dir)
        .with_context(|| format!("stat the ascmhl scope {}", dir.display()))?;
    let id = (meta.dev(), meta.ino()); // unix: std::os::unix::fs::MetadataExt
    if !visited.insert(id) {
        bail!("the ascmhl scope walk hit a directory cycle at {}", dir.display());
    }
    let mut names: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("read the ascmhl scope dir {}", dir.display()))?
    {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue; // the mirror's symlink refusal idiom (cycle/escape guard)
        }
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    for name in names {
        if ignored(&name) {
            continue; // the ignore set: the file, or the directory + its subtree
        }
        let p = dir.join(&name);
        if p.is_dir() {
            dirs.push(walk_with(&p, visited, ignored)?);
        } else if p.is_file() {
            let m = std::fs::metadata(&p)
                .with_context(|| format!("stat the ascmhl file {}", p.display()))?;
            files.push(FileNode {
                name: name.clone(),
                size: m.len(),
                mtime: mtime_unix(&m),
                c4: c4_stream_path(&p)
                    .with_context(|| format!("hash the ascmhl file {}", p.display()))?,
            });
        }
    }
    Ok(DirNode {
        name: dir
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        mtime: mtime_unix(&meta),
        files,
        dirs,
    })
}

/// A directory's (content, structure) C4IDs over its children (the
/// reference `DirectoryHashContext`): the
/// content = the hash-of-hashes over the children's content C4IDs
/// (a child directory contributes its CONTENT hash); the structure
/// = the hash-of-hashes over the per-child mixes (a child FILE: its
/// content digest; a child DIRECTORY: its STRUCTURE digest — the
/// child directory's content digest is NOT mixed). The empty
/// children = the empty-input digest (both).
fn dir_hashes(d: &DirNode) -> (String, String) {
    let mut contents: Vec<String> = Vec::new();
    let mut structures: Vec<String> = Vec::new();
    for f in &d.files {
        contents.push(f.c4.clone());
        structures.push(structure_child_c4(&f.name, &f.c4));
    }
    for c in &d.dirs {
        let (cc, sc) = dir_hashes(c);
        contents.push(cc);
        structures.push(structure_child_c4(&c.name, &sc));
    }
    let cs: Vec<&str> = contents.iter().map(|s| s.as_str()).collect();
    let ss: Vec<&str> = structures.iter().map(|s| s.as_str()).collect();
    (hash_of_hash_list(&cs), hash_of_hash_list(&ss))
}

/// The post-order entry list (a directory's children — files and
/// directories merged, sorted lexicographically by name — come
/// before the directory's own `<directoryhash>` entry; the scope
/// root itself is NOT an entry — its hashes = the `roothash`).
fn push_entries(d: &DirNode, prefix: &str, out: &mut Vec<Entry>) {
    let mut items: Vec<&str> = Vec::new();
    for f in &d.files {
        items.push(f.name.as_str());
    }
    for c in &d.dirs {
        items.push(c.name.as_str());
    }
    items.sort_unstable();
    for name in items {
        if let Some(f) = d.files.iter().find(|f| f.name == name) {
            let rel = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}/{name}")
            };
            out.push(Entry::File {
                path: rel,
                size: f.size,
                mtime: f.mtime,
                c4: f.c4.clone(),
            });
        } else {
            let c = d.dirs.iter().find(|c| c.name == name).unwrap();
            let rel = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}/{name}")
            };
            push_entries(c, &rel, out);
            let (cc, sc) = dir_hashes(c);
            out.push(Entry::Dir {
                path: rel,
                mtime: c.mtime,
                content: cc,
                structure: sc,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// The writer (the FS orchestration — the failure band)
// ---------------------------------------------------------------------------

/// Write ONE generation of the ascmhl history at the dest (scope)
/// root (the write position: LAST — after the per-clip manifests
/// and the run report + the job report — the records stand first; a
/// failure here is the named hard-error band, the run's rc becomes
/// the error rc). `created` = the run's creation instant (unix
/// seconds, UTC — the run report's `created` line: the manifest's
/// `creationdate` + the file name's stamp + every `hashdate` are
/// this instant). Returns the manifest's path.
pub fn write_history(dest_root: &Path, created: u64) -> Result<PathBuf> {
    let ascmhl_dir = dest_root.join(ASCMHL_DIR_NAME);
    let generation = next_generation(&ascmhl_dir)?;
    let mut visited = HashSet::new();
    let root = walk(dest_root, &mut visited)?;
    let (root_content, root_structure) = dir_hashes(&root);
    let mut entries = Vec::new();
    push_entries(&root, "", &mut entries);
    let folder = dest_root
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "root".to_string());
    let data = ManifestData {
        folder: folder.clone(),
        created,
        // The code's existing host source (the run report's `host:`
        // line — the same source).
        hostname: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        root_content,
        root_structure,
        entries,
    };
    let xml = render_manifest(&data);
    let name = manifest_name(&folder, created, generation);
    std::fs::create_dir_all(&ascmhl_dir)
        .with_context(|| format!("create the ascmhl dir {}", ascmhl_dir.display()))?;
    let manifest_path = ascmhl_dir.join(&name);
    std::fs::write(&manifest_path, xml.as_bytes())
        .with_context(|| format!("write the ascmhl manifest {}", manifest_path.display()))?;
    // The durability seam: the manifest's bytes are
    // filesystem-synchronized (a sync failure = the named hard-error
    // band — the run's rc becomes the error rc).
    crate::durability::sync_file(&manifest_path, "ascmhl manifest")?;
    let manifest_c4 = c4(xml.as_bytes());
    let chain_path = ascmhl_dir.join(CHAIN_NAME);
    let existing = match std::fs::read_to_string(&chain_path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("read the ascmhl chain {}", chain_path.display()))
        }
    };
    let chain = render_chain(&existing, generation, &name, &manifest_c4)
        .with_context(|| format!("append the ascmhl chain {}", chain_path.display()))?;
    std::fs::write(&chain_path, chain.as_bytes())
        .with_context(|| format!("write the ascmhl chain {}", chain_path.display()))?;
    // The durability seam: the chain's bytes are
    // filesystem-synchronized (the named hard-error band) + the
    // best-effort dir sync of the ascmhl history dir (the pinned note
    // on failure — the content stands).
    crate::durability::sync_file(&chain_path, "ascmhl chain")?;
    crate::durability::sync_dir_best_effort(&ascmhl_dir);
    Ok(manifest_path)
}

// ---------------------------------------------------------------------------
// The read side (the MHL import + the sealed-archive re-verify)
// ---------------------------------------------------------------------------

/// One parsed hashlist file entry (the `<hash>` row — the manifest's
/// order is preserved; the size + the mtime are recorded values —
/// the mtime is stored, NEVER verified: the C4ID is the content
/// record).
#[derive(Clone, Debug)]
pub struct HashFile {
    pub path: String,
    pub size: u64,
    pub mtime: String,
    pub c4: String,
}

/// One parsed hashlist directory entry (the `<directoryhash>` row).
#[derive(Clone, Debug)]
pub struct HashDir {
    pub path: String,
    pub mtime: String,
    pub content: String,
    pub structure: String,
}

/// The parsed hashlist — the strict read-side mirror of the v1
/// element set the write side renders + the conformant-import
/// surface (the foreign tool's name + the foreign ignore list ride
/// through, unverified).
#[derive(Clone, Debug)]
pub struct Hashlist {
    pub creationdate: String,
    pub hostname: String,
    /// The tool's name (the `frameprism` string on self-written
    /// manifests; the foreign tool's name on imports — the import
    /// fact).
    pub tool: String,
    pub tool_version: String,
    pub process: String,
    pub root_content: String,
    pub root_structure: String,
    /// The manifest's OWN ignore patterns (the import fact: the
    /// roothash recompute is governed by THIS list, not the
    /// built-in `IGNORE_PATTERNS`).
    pub ignore: Vec<String>,
    /// The file entries (the manifest's order).
    pub files: Vec<HashFile>,
    /// The directory entries (the manifest's order).
    pub dirs: Vec<HashDir>,
}

/// The C4ID shape check (the named refusal class — the malformed c4
/// value): `c4` + exactly 88 C4ID-alphabet characters (the 512-bit
/// digest's fixed base58 form over `C4_CHARSET`).
fn check_c4(value: &str, manifest: &str, where_: &str) -> Result<()> {
    let body = value.strip_prefix("c4").ok_or_else(|| {
        anyhow::anyhow!(
            "the mhl manifest {manifest} has a {where_} c4 value {value:?} that does not start with the algorithm prefix `c4` (the malformed c4 value — the C4ID = SHA-512, base58 over the C4ID character set)"
        )
    })?;
    if body.len() != 88 {
        bail!(
            "the mhl manifest {manifest} has a {where_} c4 value of {total} total characters (expected `c4` + exactly 88 character-set characters — the C4ID's fixed 512-bit form — the malformed c4 value)",
            total = value.len()
        );
    }
    for ch in body.bytes() {
        if !C4_CHARSET.contains(&ch) {
            bail!(
                "the mhl manifest {manifest} has a {where_} c4 value {value:?} carrying a character outside the C4ID character set (the malformed c4 value)"
            );
        }
    }
    Ok(())
}

/// The path-in-scope check (the named refusal class — the path
/// escaping the scope): not empty, not absolute, no `..` component.
fn check_in_scope(path: &str, manifest: &str) -> Result<()> {
    if path.is_empty() {
        bail!(
            "the mhl manifest {manifest} has an empty <path> in its hashes section (a path escaping the scope — the record is untrustable)"
        );
    }
    if path.starts_with('/') {
        bail!(
            "the mhl manifest {manifest} has an absolute <path> {path:?} in its hashes section (a path escaping the scope — the record is untrustable)"
        );
    }
    for comp in path.split('/') {
        if comp == ".." {
            bail!(
                "the mhl manifest {manifest} has a <path> {path:?} with a `..` component in its hashes section (a path escaping the scope — the record is untrustable)"
            );
        }
    }
    Ok(())
}

/// One `<c4>` slot of a `content`/`structure` container (the
/// roothash's + the directoryhash's): exactly ONE `<c4>` child with
/// a present `hashdate` attribute + a well-formed C4ID value.
fn slot_c4(slot: &XmlEl, what: &str, manifest: &str) -> Result<String> {
    if slot.children.len() != 1 || slot.children[0].name != "c4" {
        bail!(
            "the mhl manifest {manifest} {what} is malformed (expected exactly one <c4> child — the record is untrustable)"
        );
    }
    let c4el = &slot.children[0];
    let hashdate = attr(c4el, "hashdate").unwrap_or("");
    if hashdate.is_empty() {
        bail!(
            "the mhl manifest {manifest} {what} <c4> is missing its hashdate attribute (the record is untrustable)"
        );
    }
    let v = c4el.text.trim().to_string();
    check_c4(&v, manifest, what)?;
    Ok(v)
}

/// The STRICT read-side parse of a conformant v2.0 hashlist (the
/// import seam): the v1 element set the write side renders —
/// `hashlist`@version=2.0@xmlns=urn:ASC:MHL:v2.0 → `creatorinfo`
/// (creationdate / hostname / tool@version + the documented
/// optionals author / location / comment — accepted, content
/// unverified) → `processinfo` (process / roothash / ignore) →
/// `hashes` (the `<hash>` + `<directoryhash>` rows). Every named
/// refusal class names the manifest + the offending value: the
/// malformed XML; the non-`hashlist` root; the non-2.0 version;
/// the non-conformant namespace (the conformant refusal — the 2009
/// MHL 1.1 / JSON lineage is out of scope, not a parser); the
/// missing creatorinfo / processinfo / roothash / ignore block; the
/// unknown element in the pinned positions; the malformed c4; the
/// duplicate `<path>`; the path escaping the scope; the empty
/// hashes section (a manifest covering nothing is not a record);
/// the non-enum `<c4>` action (the XSD's ActionAttributeType:
/// original / verified / failed); the directoryhash's path
/// carrying a size attribute (the v1 shape: NO size — the XSD's
/// DirectoryHashType + the pinned wire format).
/// The `manifest` label = the manifest file's name (every refusal
/// names it). The XSD conformance note: the full XSD permits a
/// broader wire surface (the per-row `md5`/`sha1`/`xxh*` siblings,
/// `previousPath`, the per-row + top-level `metadata`, the top-
/// level `references`) — the v1 subset rejects every one of them as
/// the named unknown-element class (the reader is a strict importer
/// of the v1 subset —
/// not a general XSD validator; the acceptance widening = the named
/// follow-up). The XSD makes roothash + ignore OPTIONAL in
/// processinfo — the re-verify surface REQUIRES both (the spec's
/// pinned refusal classes: a record without the seal or the ignore
/// list is not a re-verify record).
pub fn parse_hashlist(src: &str, manifest: &str) -> Result<Hashlist> {
    let root = parse_lite(src).with_context(|| format!("parse the mhl manifest {manifest}"))?;
    if root.name != "hashlist" {
        bail!(
            "the mhl manifest {manifest} root is <{}>, expected <hashlist> (the malformed record — the record is untrustable)",
            root.name
        );
    }
    let version = attr(&root, "version").unwrap_or("");
    if version != "2.0" {
        bail!(
            "the mhl manifest {manifest} version is {version:?}, expected \"2.0\" (the v2.0 lineage — the conformant import scope; the 2009 MHL 1.1 lineage is out of scope, not a parser)"
        );
    }
    let xmlns = attr(&root, "xmlns").unwrap_or("");
    if xmlns != "urn:ASC:MHL:v2.0" {
        bail!(
            "the mhl manifest {manifest} namespace is {xmlns:?}, expected \"urn:ASC:MHL:v2.0\" (the conformant import scope — a non-conformant format is the named refusal, not a parser)"
        );
    }
    // The top-level multiset: exactly one creatorinfo + one
    // processinfo, at most one hashes (the empty managed set omits
    // it — the writer's XSD minOccurs=0 shape), nothing else (no
    // metadata / references in v1).
    for ch in &root.children {
        if !matches!(ch.name.as_str(), "creatorinfo" | "processinfo" | "hashes") {
            bail!(
                "the mhl manifest {manifest} has an unexpected top-level element <{}> (the v1 element set: creatorinfo, processinfo, hashes — no metadata / references in v1 — the record is untrustable)",
                ch.name
            );
        }
    }
    let count = |n: &str| root.children.iter().filter(|c| c.name == n).count();
    if count("creatorinfo") != 1 {
        bail!("the mhl manifest {manifest} is missing the required <creatorinfo> element (or carries more than one — the record is untrustable)");
    }
    if count("processinfo") != 1 {
        bail!("the mhl manifest {manifest} is missing the required <processinfo> element (or carries more than one — the record is untrustable)");
    }
    if count("hashes") > 1 {
        bail!("the mhl manifest {manifest} carries more than one <hashes> element (the record is untrustable)");
    }
    let creator = root.children.iter().find(|c| c.name == "creatorinfo").unwrap();
    let process = root.children.iter().find(|c| c.name == "processinfo").unwrap();
    let hashes = root.children.iter().find(|c| c.name == "hashes");
    // The creatorinfo: creationdate + hostname + tool (each exactly
    // once) + the documented optionals (accepted, content
    // unverified).
    let mut creationdate: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut tool_el: Option<&XmlEl> = None;
    for ch in &creator.children {
        match ch.name.as_str() {
            "creationdate" => {
                if creationdate.is_some() {
                    bail!("the mhl manifest {manifest} creatorinfo carries more than one <creationdate> (the record is untrustable)");
                }
                creationdate = Some(ch.text.trim().to_string());
            }
            "hostname" => {
                if hostname.is_some() {
                    bail!("the mhl manifest {manifest} creatorinfo carries more than one <hostname> (the record is untrustable)");
                }
                hostname = Some(ch.text.trim().to_string());
            }
            "tool" => {
                if tool_el.is_some() {
                    bail!("the mhl manifest {manifest} creatorinfo carries more than one <tool> (the record is untrustable)");
                }
                tool_el = Some(ch);
            }
            "author" | "location" | "comment" => {
                // The documented optionals (the wire
                // example) — accepted, content unverified.
            }
            other => {
                bail!(
                    "the mhl manifest {manifest} creatorinfo has an unexpected element <{other}> (the v1 set: creationdate, hostname, tool + the optionals author / location / comment — the record is untrustable)"
                );
            }
        }
    }
    let tool_el = tool_el.ok_or_else(|| {
        anyhow::anyhow!("the mhl manifest {manifest} creatorinfo is missing the required <tool> element (the record is untrustable)")
    })?;
    let tool_version = attr(tool_el, "version").unwrap_or("");
    if tool_version.is_empty() {
        bail!("the mhl manifest {manifest} <tool> is missing its version attribute (the record is untrustable)");
    }
    let tool = tool_el.text.trim().to_string();
    if tool.is_empty() {
        bail!("the mhl manifest {manifest} <tool> element is empty (the record is untrustable)");
    }
    if creationdate.as_deref().map(str::is_empty).unwrap_or(true) {
        bail!("the mhl manifest {manifest} creatorinfo is missing its <creationdate> (or the value is empty — the record is untrustable)");
    }
    if hostname.as_deref().map(str::is_empty).unwrap_or(true) {
        bail!("the mhl manifest {manifest} creatorinfo is missing its <hostname> (or the value is empty — the record is untrustable)");
    }
    // The processinfo: process + roothash + ignore (each exactly
    // once).
    let mut process_el: Option<&XmlEl> = None;
    let mut roothash: Option<&XmlEl> = None;
    let mut ignore_el: Option<&XmlEl> = None;
    for ch in &process.children {
        match ch.name.as_str() {
            "process" => {
                if process_el.is_some() {
                    bail!("the mhl manifest {manifest} processinfo carries more than one <process> (the record is untrustable)");
                }
                process_el = Some(ch);
            }
            "roothash" => {
                if roothash.is_some() {
                    bail!("the mhl manifest {manifest} processinfo carries more than one <roothash> (the record is untrustable)");
                }
                roothash = Some(ch);
            }
            "ignore" => {
                if ignore_el.is_some() {
                    bail!("the mhl manifest {manifest} processinfo carries more than one <ignore> (the record is untrustable)");
                }
                ignore_el = Some(ch);
            }
            other => {
                bail!(
                    "the mhl manifest {manifest} processinfo has an unexpected element <{other}> (the v1 set: process, roothash, ignore — the record is untrustable)"
                );
            }
        }
    }
    let process_el = process_el.ok_or_else(|| {
        anyhow::anyhow!("the mhl manifest {manifest} processinfo is missing the required <process> element (the record is untrustable)")
    })?;
    let roothash = roothash.ok_or_else(|| {
        anyhow::anyhow!("the mhl manifest {manifest} processinfo is missing the required <roothash> element (the record is untrustable)")
    })?;
    let ignore_el = ignore_el.ok_or_else(|| {
        anyhow::anyhow!("the mhl manifest {manifest} processinfo is missing the required <ignore> block (the record is untrustable)")
    })?;
    let process_name = process_el.text.trim().to_string();
    if process_name.is_empty() {
        bail!("the mhl manifest {manifest} <process> element is empty (the record is untrustable)");
    }
    // The roothash: exactly <content> + <structure> (in order), each
    // one <c4> child.
    if roothash.children.len() != 2
        || roothash.children[0].name != "content"
        || roothash.children[1].name != "structure"
    {
        bail!(
            "the mhl manifest {manifest} <roothash> is malformed (expected exactly <content> + <structure>, each with one <c4> child — the record is untrustable)"
        );
    }
    let root_content = slot_c4(&roothash.children[0], "roothash <content>", manifest)?;
    let root_structure = slot_c4(&roothash.children[1], "roothash <structure>", manifest)?;
    // The ignore block: one or more <pattern> children (the
    // manifest's OWN list — the import fact).
    let mut ignore: Vec<String> = Vec::new();
    for ch in &ignore_el.children {
        if ch.name != "pattern" {
            bail!(
                "the mhl manifest {manifest} <ignore> block has an unexpected element <{}> (the v1 set: <pattern> — the record is untrustable)",
                ch.name
            );
        }
        let p = ch.text.trim().to_string();
        if p.is_empty() {
            bail!("the mhl manifest {manifest} <ignore> block has an empty <pattern> (the record is untrustable)");
        }
        ignore.push(p);
    }
    if ignore.is_empty() {
        bail!("the mhl manifest {manifest} <ignore> block has no patterns (the missing ignore block — the record is untrustable)");
    }
    // The hashes section: the <hash> + <directoryhash> rows (the
    // manifest's order preserved). The absent <hashes> (the writer's
    // empty-set shape) + the empty section = the empty-hashes
    // refusal (a manifest covering nothing is not a record).
    let mut files: Vec<HashFile> = Vec::new();
    let mut dirs: Vec<HashDir> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    if let Some(h) = hashes {
        for row in &h.children {
            match row.name.as_str() {
                "hash" => {
                    if row.children.len() != 2
                        || row.children[0].name != "path"
                        || row.children[1].name != "c4"
                    {
                        bail!("the mhl manifest {manifest} has a malformed <hash> row (expected exactly <path> then <c4> — the record is untrustable)");
                    }
                    let path_el = &row.children[0];
                    let path = path_el.text.trim().to_string();
                    check_in_scope(&path, manifest)?;
                    if !seen.insert(path.clone()) {
                        bail!("the mhl manifest {manifest} hashes section has a duplicate <path> {path:?} (the record is untrustable)");
                    }
                    let size_s = attr(path_el, "size").unwrap_or("");
                    if size_s.is_empty() {
                        bail!("the mhl manifest {manifest} <hash> path {path:?} is missing its size attribute (the record is untrustable)");
                    }
                    let size: u64 = size_s.parse().map_err(|_| {
                        anyhow::anyhow!("the mhl manifest {manifest} <hash> path {path:?} has a non-numeric size attribute {size_s:?} (the record is untrustable)")
                    })?;
                    let mtime = attr(path_el, "lastmodificationdate").unwrap_or("");
                    if mtime.is_empty() {
                        bail!("the mhl manifest {manifest} <hash> path {path:?} is missing its lastmodificationdate attribute (the record is untrustable)");
                    }
                    let c4_el = &row.children[1];
                    let action = attr(c4_el, "action").unwrap_or("");
                    if !matches!(action, "original" | "verified" | "failed") {
                        bail!(
                            "the mhl manifest {manifest} <hash> path {path:?} <c4> action is {action:?}, expected one of the format's enum values (original / verified / failed — the XSD's ActionAttributeType) (the record is untrustable)"
                        );
                    }
                    let hashdate = attr(c4_el, "hashdate").unwrap_or("");
                    if hashdate.is_empty() {
                        bail!("the mhl manifest {manifest} <hash> path {path:?} <c4> is missing its hashdate attribute (the record is untrustable)");
                    }
                    let c4v = c4_el.text.trim().to_string();
                    check_c4(&c4v, manifest, &format!("hash c4 for path {path:?}"))?;
                    files.push(HashFile {
                        path,
                        size,
                        mtime: mtime.to_string(),
                        c4: c4v,
                    });
                }
                "directoryhash" => {
                    if row.children.len() != 3
                        || row.children[0].name != "path"
                        || row.children[1].name != "content"
                        || row.children[2].name != "structure"
                    {
                        bail!("the mhl manifest {manifest} has a malformed <directoryhash> row (expected exactly <path> + <content> + <structure> — the record is untrustable)");
                    }
                    let path_el = &row.children[0];
                    let path = path_el.text.trim().to_string();
                    check_in_scope(&path, manifest)?;
                    if !seen.insert(path.clone()) {
                        bail!("the mhl manifest {manifest} hashes section has a duplicate <path> {path:?} (the record is untrustable)");
                    }
                    let mtime = attr(path_el, "lastmodificationdate").unwrap_or("");
                    if mtime.is_empty() {
                        bail!("the mhl manifest {manifest} <directoryhash> path {path:?} is missing its lastmodificationdate attribute (the record is untrustable)");
                    }
                    if attr(path_el, "size").is_some() {
                        bail!(
                            "the mhl manifest {manifest} <directoryhash> path {path:?} carries a size attribute (the v1 shape: the directoryhash's path has NO size — the XSD's DirectoryHashType + the pinned wire format) (the record is untrustable)"
                        );
                    }
                    let content = slot_c4(&row.children[1], &format!("directoryhash <content> for path {path:?}"), manifest)?;
                    let structure = slot_c4(&row.children[2], &format!("directoryhash <structure> for path {path:?}"), manifest)?;
                    dirs.push(HashDir {
                        path,
                        mtime: mtime.to_string(),
                        content,
                        structure,
                    });
                }
                other => {
                    bail!(
                        "the mhl manifest {manifest} hashes section has an unexpected element <{other}> (the v1 set: <hash> + <directoryhash> — the record is untrustable)"
                    );
                }
            }
        }
    }
    if files.is_empty() && dirs.is_empty() {
        bail!("the mhl manifest {manifest} hashes section is empty (a manifest covering nothing is not a record — the record is untrustable)");
    }
    Ok(Hashlist {
        creationdate: creationdate.unwrap(),
        hostname: hostname.unwrap(),
        tool,
        tool_version: tool_version.to_string(),
        process: process_name,
        root_content,
        root_structure,
        ignore,
        files,
        dirs,
    })
}

/// The MHL re-verify's manifest selection: the CHAIN'S LAST record
/// (the chain is parseable + EVERY record's c4 verifies against its
/// manifest's bytes — a missing manifest or a mismatched c4 = the
/// named corrupt-record refusal) → the last record's manifest (the
/// latest generation). NO chain: exactly ONE `.mhl` = that one (the
/// single-manifest carve-out); ZERO = the named refusal; ≥2 = the
/// named ambiguity refusal (the spec's exact wording).
pub fn select_manifest(ascmhl_dir: &Path) -> Result<PathBuf> {
    let chain_path = ascmhl_dir.join(CHAIN_NAME);
    if chain_path.is_file() {
        let existing = std::fs::read_to_string(&chain_path)
            .with_context(|| format!("read the ascmhl chain {}", chain_path.display()))?;
        let records = read_chain(&existing)
            .with_context(|| format!("parse the ascmhl chain {}", chain_path.display()))?;
        if records.is_empty() {
            bail!(
                "the ascmhl chain at {} is parseable but carries no records (the corrupt-record class — the record is untrustable)",
                chain_path.display()
            );
        }
        for (nr, name, recorded_c4) in &records {
            let mpath = ascmhl_dir.join(name);
            if !mpath.is_file() {
                bail!(
                    "the ascmhl chain's record {nr} points at a missing manifest ({name} in {}) — the corrupt-record class: the record is untrustable",
                    ascmhl_dir.display()
                );
            }
            let actual = c4_stream_path(&mpath)
                .with_context(|| format!("read the ascmhl manifest {}", mpath.display()))?;
            if actual != *recorded_c4 {
                bail!(
                    "the ascmhl chain's record {nr} c4 does not match the manifest bytes ({name} records {recorded_c4}; the file hashes {actual}) — the corrupt-record class: the record is untrustable"
                );
            }
        }
        let (_, name, _) = records.last().unwrap().clone();
        Ok(ascmhl_dir.join(name))
    } else {
        let mut manifests: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(ascmhl_dir)
            .with_context(|| format!("read the ascmhl dir {}", ascmhl_dir.display()))?
        {
            let entry =
                entry.with_context(|| format!("read an entry of {}", ascmhl_dir.display()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".mhl") {
                manifests.push(name);
            }
        }
        manifests.sort();
        if manifests.is_empty() {
            bail!(
                "the ascmhl dir at {} carries no .mhl manifest — there is no record to verify",
                ascmhl_dir.display()
            );
        }
        if manifests.len() > 1 {
            bail!(
                "{} carries {} manifests without a chain (ascmhl_chain.xml) — the history is ambiguous; the record is untrustable (add the chain or verify a single-manifest scope)",
                ascmhl_dir.display(),
                manifests.len()
            );
        }
        Ok(ascmhl_dir.join(&manifests[0]))
    }
}

/// One MHL re-verify file row (the manifest's order — the offload
/// row vocabulary).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MhlRowVerdict {
    /// The recorded size + c4 match the file's current bytes.
    Ok,
    /// The recorded file is absent from the scope.
    Missing,
    /// The file's size differs from the recorded size.
    SizeMismatch,
    /// The file's c4 differs from the recorded c4.
    C4Mismatch,
}

/// One MHL re-verify row (the per-file surface — a recorded file's
/// verdict + the named detail).
#[derive(Clone, Debug)]
pub struct MhlRow {
    pub path: String,
    pub verdict: MhlRowVerdict,
    /// The named detail (the FAIL line's parenthetical — the record
    /// vs the disk's fact).
    pub detail: String,
}

/// The roothash verdict (the seal check — each side's match).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MhlRootVerdict {
    pub content_match: bool,
    pub structure_match: bool,
}

/// The MHL scope re-verify's result (the per-file rows in the
/// manifest's order + the roothash verdict).
#[derive(Clone, Debug)]
pub struct MhlVerifyResult {
    /// The per-file rows (the manifest's order — the RECORDED files
    /// only: an ADDED file never appears here; the roothash is its
    /// named catch).
    pub rows: Vec<MhlRow>,
    pub root: MhlRootVerdict,
}

/// The MHL scope re-verify: the per-file c4 recompute (the
/// manifest's order; the size pre-filter; the parallel file-read
/// pool — the audit's `jobs` arg, 0 = all cores) + the roothash recompute over the WHOLE scope with the
/// MANIFEST'S OWN ignore patterns (the import fact — a foreign
/// record verifies against its own values). A VANISHED recorded file
/// = the `Missing` row (the offload row vocabulary — the audit's
/// named offender); a recorded file that EXISTS but cannot be stat-
/// ted or read = the named hard error (the no-silent-skip posture —
/// the pre-B6 sweep-error default), not an offender row (the row
/// vocabulary is fixed).
pub fn verify_scope(scope: &Path, hl: &Hashlist, jobs: usize) -> Result<MhlVerifyResult> {
    let check_one = |f: &HashFile| -> Result<MhlRow> {
        let p = scope.join(&f.path);
        // A vanished recorded file = the MISSING row (the offload
        // row vocabulary — the audit's named-offender class); a
        // STAT failure on a present entry (or a read failure below)
        // = the named hard error (the no-silent-skip posture — the
        // pre-B6 sweep-error default), never a silent skip.
        let meta = match std::fs::metadata(&p) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(MhlRow {
                    path: f.path.clone(),
                    verdict: MhlRowVerdict::Missing,
                    detail: format!(
                        "the manifest records {} — the file is absent from the scope",
                        f.c4
                    ),
                });
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("stat the mhl re-verify file {}", p.display()))
            }
        };
        if !meta.is_file() {
            return Ok(MhlRow {
                path: f.path.clone(),
                verdict: MhlRowVerdict::Missing,
                detail: format!(
                    "the manifest records {} — the file is absent from the scope (a non-file entry stands in its place)",
                    f.c4
                ),
            });
        }
        if meta.len() != f.size {
            return Ok(MhlRow {
                path: f.path.clone(),
                verdict: MhlRowVerdict::SizeMismatch,
                detail: format!("the manifest records {} B; the file is {} B", f.size, meta.len()),
            });
        }
        let actual = c4_stream_path(&p)
            .with_context(|| format!("hash the mhl re-verify file {}", p.display()))?;
        if actual != f.c4 {
            return Ok(MhlRow {
                path: f.path.clone(),
                verdict: MhlRowVerdict::C4Mismatch,
                detail: format!("the manifest records {}; the file hashes {actual}", f.c4),
            });
        }
        Ok(MhlRow {
            path: f.path.clone(),
            verdict: MhlRowVerdict::Ok,
            detail: String::new(),
        })
    };
    let want = if jobs == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    } else {
        jobs
    };
    let n = want.max(1).min(hl.files.len().max(1));
    let mut rows: Vec<MhlRow> = Vec::new();
    if n == 1 {
        for f in &hl.files {
            rows.push(check_one(f)?);
        }
    } else {
        let mut results: Vec<Option<Result<MhlRow>>> = (0..hl.files.len()).map(|_| None).collect();
        std::thread::scope(|s| {
            let chunk = hl.files.len().div_ceil(n);
            let mut handles = Vec::new();
            for (ci, c) in hl.files.chunks(chunk).enumerate() {
                let start = ci * chunk;
                let files: Vec<HashFile> = c.to_vec();
                handles.push(s.spawn(move || {
                    files
                        .iter()
                        .enumerate()
                        .map(|(i, f)| (start + i, check_one(f)))
                        .collect::<Vec<_>>()
                }));
            }
            for h in handles {
                for (i, res) in h.join().expect("mhl re-verify thread panicked") {
                    results[i] = Some(res);
                }
            }
        });
        for r in results.into_iter() {
            rows.push(r.expect("every row was computed")?);
        }
    }
    // The roothash recompute (the scope's CURRENT bytes; the
    // manifest's OWN ignore patterns — the import fact).
    let mut visited = HashSet::new();
    let ignore = &hl.ignore;
    let root = walk_with(
        scope,
        &mut visited,
        &|name: &str| ignore.iter().any(|p| pattern_matches(p, name)),
    )?;
    let (rc, rs) = dir_hashes(&root);
    Ok(MhlVerifyResult {
        rows,
        root: MhlRootVerdict {
            content_match: rc == hl.root_content,
            structure_match: rs == hl.root_structure,
        },
    })
}

/// The audit verb's MHL re-verify surface output (the arm's seam):
/// the per-offender FAIL lines (the manifest's order) + the summary
/// line (the spec's pinned shapes) + the offender count.
#[derive(Clone, Debug)]
pub struct MhlAuditOut {
    pub offenders: usize,
    pub lines: Vec<String>,
    pub summary: String,
}

/// The MHL re-verify surface (the audit dispatch): select the
/// latest manifest (the chain's last record / the single-manifest
/// carve-out / the named refusals), parse it strictly, re-verify the
/// scope. Every error here = the named hard-refusal class (the B5
/// posture — the record is untrustable: the audit's rc=2).
pub fn audit_mhl(input: &Path, jobs: usize) -> Result<MhlAuditOut> {
    let ascmhl_dir = input.join(ASCMHL_DIR_NAME);
    let manifest_path = select_manifest(&ascmhl_dir)?;
    let manifest_name = manifest_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| manifest_path.display().to_string());
    let xml = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("read the mhl manifest {}", manifest_path.display()))?;
    let hl = parse_hashlist(&xml, &manifest_name)?;
    let res = verify_scope(input, &hl, jobs)?;
    let mut lines = Vec::new();
    let mut offenders = 0usize;
    for row in &res.rows {
        if row.verdict == MhlRowVerdict::Ok {
            continue;
        }
        offenders += 1;
        let class = match row.verdict {
            MhlRowVerdict::Missing => "MISSING",
            MhlRowVerdict::SizeMismatch => "SIZE_MISMATCH",
            MhlRowVerdict::C4Mismatch => "C4_MISMATCH",
            MhlRowVerdict::Ok => unreachable!("the Ok rows are skipped above"),
        };
        lines.push(format!("FAIL {}: {} ({})", row.path, class, row.detail));
    }
    let roothash = if res.root.content_match && res.root.structure_match {
        "OK".to_string()
    } else if res.root.structure_match {
        "MISMATCH: content".to_string()
    } else if res.root.content_match {
        "MISMATCH: structure".to_string()
    } else {
        "MISMATCH: both".to_string()
    };
    let summary = if offenders == 0 {
        format!(
            "audit: mhl re-verify {}: {} file(s) verified, roothash OK (the latest manifest {})",
            input.display(),
            res.rows.len(),
            manifest_name
        )
    } else {
        format!(
            "audit: mhl re-verify {}: FAIL {} offender(s) — roothash {} (the named lines above) (the latest manifest {})",
            input.display(),
            offenders,
            roothash,
            manifest_name
        )
    };
    Ok(MhlAuditOut { offenders, lines, summary })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vectors: generated by a stdlib-only python transcription
    /// of the reference algorithm (the C4 class + `hash_of_hash_list`
    /// + `DirectoryHashContext`), self-verified against the reference
    /// suite's pinned c4 vector + cross-checked against the LIVE
    /// reference implementation (`ascmhl create -v -h c4`).

    /// The C4ID vectors (test 1 — the exact 90-char strings, the
    /// `c4` prefix, the charset membership).
    #[test]
    fn c4id_vectors() {
        let vectors: Vec<(&[u8], &str)> = vec![
            (
                b"",
                "c459dsjfscH38cYeXXYogktxf4Cd9ibshE3BHUo6a58hBXmRQdZrAkZzsWcbWtDg5oQstpDuni4Hirj75GEmTc1sFT",
            ),
            (
                b"a",
                "c41dF3bGD8iqVcrJJQpS6fEsVgg9iKeNHGCCEhK2C2cGYRm2dx8xeFU1wKbkBsCWdefaz82KeyfbBf8Pfkpm4C56cc",
            ),
            (
                b"abc",
                "c45S4rnaTNWonxss1u8LzsaJdEph1AJhWUF4sh2waXKMsutyfAxg4ybUeuXVWS9HdNcEypmeXn8FZGonD4w1rj9DZp",
            ),
            (
                b"frameprism",
                "c43AxymLNJnJmqy3j9En4AmugTiSL6V3YY1Ds6VvejuS3wmXN1AFLfLtssL15HrfvR6RmuycPhwViZGrPr5AMQ8jTf",
            ),
            // the reference suite's pinned vector (tests/test_hasher.py):
            (
                b"media-hash-list",
                "c456LycWwpMMS7VDZEKvYv2L1uJS6s4qAFnaJdnQiy5JVbBFZMA8aLDS6SPaJjLqxXH4qZdnbuktopMt9frtC2qL1R",
            ),
        ];
        let charset = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for (input, expected) in &vectors {
            let got = c4(input);
            assert_eq!(&got, expected, "the C4ID of {input:?}");
            assert_eq!(got.len(), 90, "the 90-char C4ID");
            assert!(got.starts_with("c4"), "the c4 prefix");
            assert!(
                got[2..].chars().all(|ch| charset.contains(ch)),
                "the charset membership (no 0/O/I/l): {got}"
            );
            assert!(!got[2..].contains('0') && !got[2..].contains('O') && !got[2..].contains('I') && !got[2..].contains('l'), "the excluded digits");
            // the round-trip: the decode returns the digest's octets
            // (the Appendix D byte representation — NOT the base58
            // string).
            assert_eq!(c4_bytes(&got), sha512(input), "the c4_bytes round-trip over {input:?}");
        }
    }

    /// The SHA-512 core vectors (the hand-rolled core's contract — a transcription error in any
    /// FIPS 180-4 constant fails this test). The hashlib vectors —
    /// the message formula for the 55/56/111/112/1000-byte cases:
    /// `msg[i] = (i*i*31 + i*7 + 11) % 256` (deterministic — the
    /// pad boundary + the two-block boundary + the multi-block path).
    #[test]
    fn sha512_vectors() {
        fn formula(n: usize) -> Vec<u8> {
            (0..n).map(|i| (((i as u64) * (i as u64) * 31 + (i as u64) * 7 + 11) % 256) as u8).collect()
        }
        let hex = |d: [u8; 64]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (b"".to_vec(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
            (b"abc".to_vec(), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            (formula(55), "b0ef420cf8d4288fae50101f234366d5c461aa0342543a7b9af49fab31e19d02bcc73f797e0cc98e9422613b43f9c3faf85d275f65676a1ebb6333addecfd831"),
            (formula(56), "8cd1ea2b40322eaea3d7cc1cffbb27d84304763edd956863f3fc53b77c96311f29a180e44db3afe9cfe9e46e1be2ff6ad937591691f541322de7cc6f13d39782"),
            (formula(111), "3b5fbcb7c413a94658bd8b7097185e9945f513d5a7acaff7db3e8e68dc7d49eea4e86df35a147a10d357f2e3f5e6c43d7c11cf8189668d96111700e213e74d77"),
            (formula(112), "cfa2ba1be532497cb786f0255b2f07f51f05b540b98723f0ed69324be02b82c68c8c52f4a4b8efe0e5fb5b664e6248f5835bdb9cf12d654c40b628c1e8c0f183"),
            (formula(1000), "3c18ad41cf3f8eb46aba82b49229edad64485b203aefc021807e626f2c36fc5352539a2bbeadd680c2794c2feff6d22b8a7692e7a94a8863bd59185919f323f7"),
        ];
        for (msg, expected) in &cases {
            assert_eq!(
                &hex(sha512(msg)),
                expected,
                "the SHA-512 of the {}-byte message",
                msg.len()
            );
        }
    }

    /// The hash-of-hashes vector (test 2 — Appendix G: the
    /// lexicographic sort proven by the vector choice: the input
    /// order != the sorted order; the empty list = the empty-input
    /// digest).
    #[test]
    fn hash_of_hashes_vector() {
        let c_a = c4(b"a");
        let c_abc = c4(b"abc");
        let c_fp = c4(b"frameprism");
        let c_empty = c4(b"");
        // The deliberately unsorted input order (the vector choice
        // proves the lexicographic sort: the input order != the
        // sorted order).
        let input: Vec<&str> = vec![c_abc.as_str(), c_empty.as_str(), c_a.as_str(), c_fp.as_str()];
        let mut sorted = input.clone();
        sorted.sort();
        assert_ne!(input, sorted, "the vector choice must prove the sort (input order != sorted order)");
        let expected =
            "c456kQaJttnqvzYi8KpE7SUh1pwWxiJsrL1FgrUBp2CeYfxGhCg3mK3GuRAv9c59gW8Xt9kDU2CKzCgakBrHihvnZh";
        assert_eq!(hash_of_hash_list(&input), expected, "the unsorted input");
        // The same values in the reversed order → the same parent
        // (the sort is the semantics).
        let reversed: Vec<&str> = input.iter().rev().cloned().collect();
        assert_eq!(
            hash_of_hash_list(&reversed),
            expected,
            "the reversed input (the sort is applied)"
        );
        // The empty list = the empty-input digest.
        assert_eq!(hash_of_hash_list(&[]), c_empty, "the empty list");
    }

    /// The structure-hash semantics (test 3: the
    /// child DIRECTORY mixes its STRUCTURE hash, the child FILE its
    /// content hash — the vector choice PROVES the distinction: the
    /// pinned WRONG content-mix value must differ).
    #[test]
    fn structure_hash_semantics() {
        // The mini-tree (the dest-relative paths):
        //   note.txt     "root note\n"       (a root file)
        //   Clips/a.DNG  "frame-one-bytes"   (a subdir child file)
        //   Clips/b.wav  "frame-two-bytes"   (a subdir child file)
        let note = c4(b"root note\n");
        let a_dng = c4(b"frame-one-bytes");
        let b_wav = c4(b"frame-two-bytes");
        assert_eq!(
            note,
            "c45KpA5Ki6wvDMg8YjtWmNQGnDjMMoZ3ko5ephTYcT12LT8CrCjxXLLGc4jkMQcAtb2VwwtnjBHZDVGk8brg1h7YDG"
        );
        assert_eq!(
            a_dng,
            "c43HoBNNNaYEeer5RnstBxWLS9CaXGt8skYGyyVoXrCDHYLpQenZjs8v2FZztvhcqauQe6oAyT6cRJLhQTVQCUkByj"
        );
        assert_eq!(
            b_wav,
            "c42iJhByL5RpZjP2pmUgLC2Sg3jBgyATvm5V4TPwmfaiw4Q2okaK8hHjzHC2DxfoFzAu9pneqiaJAFT2YF1Jha1xVZ"
        );
        // The Clips directory (the two file children).
        let clips_content = hash_of_hash_list(&[a_dng.as_str(), b_wav.as_str()]);
        assert_eq!(
            clips_content,
            "c43HiRFT6uENFyfMQ7hUmEYCQJNSdmVyC9CdQHgUFm4RyUfNL7bZnYcUKyoxdCe56PG7Wo5dhipYYHKQv7oxYeeWt2"
        );
        let sc_a = structure_child_c4("a.DNG", &a_dng);
        let sc_b = structure_child_c4("b.wav", &b_wav);
        let clips_structure = hash_of_hash_list(&[sc_a.as_str(), sc_b.as_str()]);
        assert_eq!(
            clips_structure,
            "c45KR37ocDot2fRe6j7hwxjqZd2otVVmvTunUX3fjcbLWu6gXj3kih8UPbVtzaz78vdLA6iRAZbeTcfeaSPghuRazt"
        );
        // The root (the Clips DIR child + the note file child): the
        // dir child contributes its CONTENT to the root content, its
        // STRUCTURE to the root structure.
        let root_content = hash_of_hash_list(&[clips_content.as_str(), note.as_str()]);
        assert_eq!(
            root_content,
            "c42YtCKURp6dvZWUdTWt6unwLErGX2Ps9mCLEUteHu22bPnJ7UkcrfcNLbHCjJ4aQhJSZRpydMksjaCY6bbmYcFoDD"
        );
        let sc_clips = structure_child_c4("Clips", &clips_structure);
        let sc_note = structure_child_c4("note.txt", &note);
        let root_structure = hash_of_hash_list(&[sc_clips.as_str(), sc_note.as_str()]);
        assert_eq!(
            root_structure,
            "c45oMbBqTRJz9sBPpAXrPY2FwtVyRFRQESXsYtvAUi935Z142FCYrVudi7HXA7dKgaD4tecRLjSrW3wN14PmL6h5Gf"
        );
        // The DISTINCTION proof: the WRONG mix (the child
        // directory's CONTENT hash into the parent's structure) must
        // differ from the pinned root structure.
        let sc_wrong = structure_child_c4("Clips", &clips_content);
        let sc_note2 = structure_child_c4("note.txt", &note);
        let wrong = hash_of_hash_list(&[sc_wrong.as_str(), sc_note2.as_str()]);
        assert_eq!(
            wrong,
            "c4257Kou9AC1GGUbgDHR6AJdxQhiQ5hVCCYFCVQXDxhRKjnHXidQPq3avrdjrbNrk37qppqtkjudwn9BcNhwr7uMhq"
        );
        assert_ne!(
            wrong, root_structure,
            "the content-mix and the structure-mix differ (the structure-vs-content distinction)"
        );
    }

    /// The fixture manifest (the pinned-bytes input; the stamps: created
 /// 1758000000 = T05:20:00Z, the mtime 1757900000 =
 /// T01:33:20Z).
    fn fixture() -> ManifestData {
        ManifestData {
            folder: "DestA".into(),
            created: 1_758_000_000,
            hostname: "macos aarch64".into(),
            tool_version: "0.12.0".into(),
            root_content: "c41Z89KjzexSrn2DEuug5dqRHcPYZSo12bm6WRiqhu2QGEmx63kfxmBFvVmMfxZSHvFo1h23aMkYrjnBr6wb7s1xVK"
                .into(),
            root_structure: "c41id5PaHtzietiron6sVSoh7BkCW6LbgvKNV3cFbH4MArm6xc6sX71ztaNsH3jePXJj4xzLtoAP6G7DaB3C9kVPyY"
                .into(),
            entries: vec![
                Entry::File {
                    path: "clips/a.DNG".into(),
                    size: 10,
                    mtime: 1_757_900_000,
                    c4: "c42GL5p3g2d81SYxs1B3bQ6M3v14rp63PqeARim8G7E9RgeMaEQcBDQj27BhHDpwQCbWvp1TNdxugSSVaLwsV1uuyj"
                        .into(),
                },
                Entry::Dir {
                    path: "clips".into(),
                    mtime: 1_757_900_000,
                    content: "c41ezJP1haSq3Dcqvwr6sJ4FEfGBtePD9WEF3ktERgJigAWpUcayGiDEAKwC3yZQHx1PX2evZ3pSrN9go7PQXtEA2B"
                        .into(),
                    structure: "c42ViDxGz1YbrkCbt87KHr2AQ95MAypeMb1ShcMt4CwA86rH8yTCB38NQzmdoMw5QfLLL3SjJBLSdVpqabCstCMUgG"
                        .into(),
                },
            ],
        }
    }

    /// The XML rendering (test 4 — the EXACT expected bytes: the
    /// element order per the XSD sequence, the attribute order per
    /// the spec's examples, the two-space indent, the `version` +
    /// the namespace, the `action`/`hashdate` attrs; the chain's
    /// rendering + the append splice).
    #[test]
    fn xml_rendering_pinned_bytes() {
        let m = fixture();
        let got = render_manifest(&m);
        let expected = "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<hashlist version=\"2.0\" xmlns=\"urn:ASC:MHL:v2.0\">
  <creatorinfo>
    <creationdate>2025-09-16T05:20:00+00:00</creationdate>
    <hostname>macos aarch64</hostname>
    <tool version=\"0.12.0\">frameprism</tool>
  </creatorinfo>
  <processinfo>
    <process>transfer</process>
    <roothash>
      <content>
        <c4 hashdate=\"2025-09-16T05:20:00+00:00\">c41Z89KjzexSrn2DEuug5dqRHcPYZSo12bm6WRiqhu2QGEmx63kfxmBFvVmMfxZSHvFo1h23aMkYrjnBr6wb7s1xVK</c4>
      </content>
      <structure>
        <c4 hashdate=\"2025-09-16T05:20:00+00:00\">c41id5PaHtzietiron6sVSoh7BkCW6LbgvKNV3cFbH4MArm6xc6sX71ztaNsH3jePXJj4xzLtoAP6G7DaB3C9kVPyY</c4>
      </structure>
    </roothash>
    <ignore>
      <pattern>.DS_Store</pattern>
      <pattern>ascmhl</pattern>
      <pattern>._*</pattern>
      <pattern>*.offload-manifest.tsv</pattern>
      <pattern>*.ingest-manifest.tsv</pattern>
      <pattern>*.reel-manifest.tsv</pattern>
      <pattern>*.bake-manifest.tsv</pattern>
      <pattern>*.derive-manifest.tsv</pattern>
      <pattern>*.members.tsv</pattern>
      <pattern>*.checksums.tsv</pattern>
      <pattern>*.jxl-checksums.tsv</pattern>
      <pattern>*.sources.tsv</pattern>
      <pattern>*.qc.tsv</pattern>
      <pattern>*.frameprism-report.md</pattern>
      <pattern>.frameprism-run-report.md</pattern>
      <pattern>.frameprism-job-report.md</pattern>
      <pattern>.frameprism-job-report.csv</pattern>
      <pattern>.frameprism-job-report.html</pattern>
      <pattern>*.sig</pattern>
    </ignore>
  </processinfo>
  <hashes>
    <hash>
      <path size=\"10\" lastmodificationdate=\"2025-09-15T01:33:20+00:00\">clips/a.DNG</path>
      <c4 action=\"original\" hashdate=\"2025-09-16T05:20:00+00:00\">c42GL5p3g2d81SYxs1B3bQ6M3v14rp63PqeARim8G7E9RgeMaEQcBDQj27BhHDpwQCbWvp1TNdxugSSVaLwsV1uuyj</c4>
    </hash>
    <directoryhash>
      <path lastmodificationdate=\"2025-09-15T01:33:20+00:00\">clips</path>
      <content>
        <c4 hashdate=\"2025-09-16T05:20:00+00:00\">c41ezJP1haSq3Dcqvwr6sJ4FEfGBtePD9WEF3ktERgJigAWpUcayGiDEAKwC3yZQHx1PX2evZ3pSrN9go7PQXtEA2B</c4>
      </content>
      <structure>
        <c4 hashdate=\"2025-09-16T05:20:00+00:00\">c42ViDxGz1YbrkCbt87KHr2AQ95MAypeMb1ShcMt4CwA86rH8yTCB38NQzmdoMw5QfLLL3SjJBLSdVpqabCstCMUgG</c4>
      </structure>
    </directoryhash>
  </hashes>
</hashlist>
";
        assert_eq!(got, expected, "the exact manifest bytes (the byte-stable rendering)");
        // Byte-stability: a second render of the same data.
        assert_eq!(render_manifest(&m), got, "the re-render is byte-identical");
        // The file name's shape (the spec's 6.3).
        assert_eq!(
            manifest_name("DestA", 1_758_000_000, 1),
            "0001_DestA_2025-09-16_052000Z.mhl"
        );
        assert_eq!(
            manifest_name("DestA", 1_758_000_000, 27),
            "0027_DestA_2025-09-16_052000Z.mhl"
        );
        // The chain (the fresh-history rendering — the sequencenr +
        // the path + the c4 of the manifest's bytes).
        let chain_c4 = c4(got.as_bytes());
        let chain = render_chain("", 1, "0001_DestA_2025-09-16_052000Z.mhl", &chain_c4).unwrap();
        let expected_chain = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ascmhldirectory xmlns=\"urn:ASC:MHL:DIRECTORY:v2.0\">\n  <hashlist sequencenr=\"1\">\n    <path>0001_DestA_2025-09-16_052000Z.mhl</path>\n    <c4>{chain_c4}</c4>\n  </hashlist>\n</ascmhldirectory>\n"
        );
        assert_eq!(chain, expected_chain, "the fresh chain's exact bytes");
        // The append (the existing bytes preserved, the record
        // spliced before the close).
        let chain2 = render_chain(&chain, 2, "0002_DestA_2025-09-17_052000Z.mhl", "c4NEW").unwrap();
        assert!(
            chain2.starts_with(&chain[..chain.len() - CHAIN_FOOTER.len()]),
            "the existing records preserved byte-for-byte"
        );
        assert!(
            chain2.contains("  <hashlist sequencenr=\"2\">\n    <path>0002_DestA_2025-09-17_052000Z.mhl</path>\n    <c4>c4NEW</c4>\n  </hashlist>\n"),
            "the appended record\n{chain2}"
        );
        assert!(chain2.ends_with(CHAIN_FOOTER), "the single closing tag");
        // A corrupted / foreign chain = the named refusal (never a
        // clobber).
        assert!(
            render_chain("not a chain at all", 2, "x.mhl", "c4X").is_err(),
            "the corrupted chain is refused"
        );
    }

    /// The self-parse (test 5 — the in-suite structural check: the
    /// generated manifest + the chain round-trip through
    /// `parse_lite` — the well-formedness + the element/attribute
    /// structure; the reference-parser validation is out-of-suite).
    #[test]
    fn self_parse_the_generated_manifest() {
        let m = fixture();
        let xml = render_manifest(&m);
        let root = parse_lite(&xml).expect("the manifest is well-formed");
        assert_eq!(root.name, "hashlist", "the root element");
        assert_eq!(attr(&root, "version"), Some("2.0"), "the version attribute");
        assert_eq!(
            attr(&root, "xmlns"),
            Some("urn:ASC:MHL:v2.0"),
            "the namespace"
        );
        // The XSD sequence: creatorinfo, processinfo, hashes.
        let names: Vec<&str> = root.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["creatorinfo", "processinfo", "hashes"], "the element order");
        let creator = &root.children[0];
        assert_eq!(
            creator.children.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["creationdate", "hostname", "tool"],
            "the creatorinfo's child order"
        );
        assert_eq!(creator.children[0].text, "2025-09-16T05:20:00+00:00");
        assert_eq!(creator.children[1].text, "macos aarch64");
        assert_eq!(attr(&creator.children[2], "version"), Some("0.12.0"), "the tool's version");
        assert_eq!(creator.children[2].text, "frameprism", "the OSS tool name");
        let process = &root.children[1];
        assert_eq!(
            process.children.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["process", "roothash", "ignore"],
            "the processinfo's child order"
        );
        assert_eq!(process.children[0].text, "transfer", "the process");
        let roothash = &process.children[1];
        assert_eq!(
            roothash.children.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["content", "structure"],
            "the roothash's containers"
        );
        for container in &roothash.children {
            assert_eq!(container.children.len(), 1, "one c4 per container");
            let c4el = &container.children[0];
            assert_eq!(c4el.name, "c4");
            assert_eq!(attr(c4el, "hashdate"), Some("2025-09-16T05:20:00+00:00"), "the hashdate");
            assert_eq!(attr(c4el, "action"), None, "the roothash c4 carries no action");
            assert_eq!(c4el.text.len(), 90, "the 90-char c4 text");
        }
        let ignore = &process.children[2];
        let patterns: Vec<&str> = ignore.children.iter().map(|c| c.text.as_str()).collect();
        assert_eq!(patterns, IGNORE_PATTERNS, "the pinned ignore set, the exact order");
        // The hashes (the fixture's post-order: the file, then the
        // dir).
        let hashes = &root.children[2];
        assert_eq!(
            hashes.children.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["hash", "directoryhash"],
            "the entries' kinds, the post-order"
        );
        let hash = &hashes.children[0];
        let path = &hash.children[0];
        assert_eq!(path.name, "path");
        assert_eq!(attr(path, "size"), Some("10"), "the size attr");
        assert_eq!(
            attr(path, "lastmodificationdate"),
            Some("2025-09-15T01:33:20+00:00"),
            "the mtime attr"
        );
        assert_eq!(path.text, "clips/a.DNG");
        let file_c4 = &hash.children[1];
        assert_eq!(file_c4.name, "c4");
        assert_eq!(attr(file_c4, "action"), Some("original"), "the generation-1 action");
        assert_eq!(attr(file_c4, "hashdate"), Some("2025-09-16T05:20:00+00:00"));
        let dirhash = &hashes.children[1];
        let dirpath = &dirhash.children[0];
        assert_eq!(attr(dirpath, "size"), None, "the directoryhash's path carries no size");
        assert_eq!(dirpath.text, "clips");
        assert_eq!(
            dirhash.children[1..].iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["content", "structure"],
            "the dir's containers"
        );
        // NO metadata / references (the v1 element set).
        assert!(!names.contains(&"metadata"), "no metadata in v1");
        assert!(!names.contains(&"references"), "no references in v1");
        // The chain (the same structural surface).
        let chain = render_chain("", 1, "0001_DestA_2025-09-16_052000Z.mhl", c4(xml.as_bytes()).as_str()).unwrap();
        let croot = parse_lite(&chain).expect("the chain is well-formed");
        assert_eq!(croot.name, "ascmhldirectory");
        assert_eq!(
            attr(&croot, "xmlns"),
            Some("urn:ASC:MHL:DIRECTORY:v2.0"),
            "the chain's namespace"
        );
        let recs = read_chain(&chain).expect("the chain's records");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0], (1, "0001_DestA_2025-09-16_052000Z.mhl".to_string(), c4(xml.as_bytes())));
        // The well-formedness negative (the parser-lite refuses a
        // mismatched close — never a silent pass).
        assert!(
            parse_lite("<hashlist><a></b></hashlist>").is_err(),
            "the mismatched close is refused"
        );
        assert!(
            parse_lite("<hashlist><a attr=unquoted></a></hashlist>").is_err(),
            "the unquoted attribute is refused"
        );
    }

    /// The ignore matcher (test 6 — the exact set: the tree with
    /// a media file + every artifact name → the managed set = the
    /// media only; the patterns pinned by the test's exact
    /// input/output).
    #[test]
    fn ignore_matcher_the_r5_set() {
        // The exact pinned pattern list (the order — the `<ignore>`
        // element's order).
        assert_eq!(
            IGNORE_PATTERNS,
            &[
                ".DS_Store",
                "ascmhl",
                "._*",
                "*.offload-manifest.tsv",
                "*.ingest-manifest.tsv",
                "*.reel-manifest.tsv",
                "*.bake-manifest.tsv",
                "*.derive-manifest.tsv",
                "*.members.tsv",
                "*.checksums.tsv",
                "*.jxl-checksums.tsv",
                "*.sources.tsv",
                "*.qc.tsv",
                "*.frameprism-report.md",
                ".frameprism-run-report.md",
                ".frameprism-job-report.md",
                ".frameprism-job-report.csv",
                ".frameprism-job-report.html",
                "*.sig",
            ]
        );
        // The managed names (the media — never ignored):
        for name in [
            "clip.DNG",
            "sidecar.wav",
            "notes.txt",
            "x",
            "x.DNG",
            "x.checksums", // the suffix WITHOUT the .tsv — not a pattern
            "x.jxl-checksums.tsvx", // a longer suffix — not a pattern
        ] {
            assert!(!is_ignored(name), "the media name {name} is managed");
        }
        // The ignored names (each artifact, at ANY depth — the
        // name-level rule):
        for name in [
            ".DS_Store",
            "ascmhl",
            "._shadow",
            "._.DS_Store",
            "A001.offload-manifest.tsv",
            ".offload-manifest.tsv",
            "A001.ingest-manifest.tsv",
            "reel.reel-manifest.tsv",
            "A001.bake-manifest.tsv",
            "A001.derive-manifest.tsv",
            "A001.members.tsv",
            ".members.tsv",
            "A001.checksums.tsv",
            "A001.jxl-checksums.tsv",
            "A001.sources.tsv",
            "A001.qc.tsv",
            "A001.frameprism-report.md",
            ".frameprism-run-report.md",
            ".frameprism-job-report.md",
            ".frameprism-job-report.csv",
            ".frameprism-job-report.html",
            "reel.reel-manifest.sig",
            "x.sig",
        ] {
            assert!(is_ignored(name), "the artifact {name} is ignored");
        }
    }

    /// The re-run append (test 7 — generation 1, then a new
    /// instant → generation 2: the chain has two records (the first
    /// record's bytes preserved), the new manifest's NNNN = 0002,
    /// the chain's c4 = the C4ID of the new manifest's bytes).
    #[test]
    fn re_run_appends_a_generation_never_clobbers() {
        let base = std::env::temp_dir().join("frameprism_ascmhl_test_rerun");
        let _ = std::fs::remove_dir_all(&base);
        let dest = base.join("DestR");
        std::fs::create_dir_all(dest.join("clips")).unwrap();
        std::fs::write(dest.join("clips/a.DNG"), b"frame-one-bytes").unwrap();
        std::fs::write(dest.join("note.txt"), b"root note\n").unwrap();
        // Generation 1.
        let gen1 = write_history(&dest, 1_758_000_000).expect("generation 1");
        let name1 = gen1.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name1.starts_with("0001_DestR_"), "the 0001 numbering: {name1}");
        assert_eq!(next_generation(&base.join("DestR/ascmhl")).unwrap(), 2);
        let chain1 = std::fs::read_to_string(base.join("DestR/ascmhl/ascmhl_chain.xml")).unwrap();
        let manifest1 = std::fs::read(&gen1).unwrap();
        // Generation 2 (a re-run — the new instant).
        let gen2 = write_history(&dest, 1_758_086_400).expect("generation 2");
        let name2 = gen2.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name2.starts_with("0002_DestR_"), "the 0002 numbering: {name2}");
        assert_ne!(name1, name2, "the new manifest is a NEW file (never a clobber)");
        let manifest2 = std::fs::read(&gen2).unwrap();
        let chain2 = std::fs::read_to_string(base.join("DestR/ascmhl/ascmhl_chain.xml")).unwrap();
        // The first record's bytes preserved byte-for-byte (the
        // append-only model — chain1 minus its close is a prefix of
        // chain2).
        let close1 = chain1.rfind("</ascmhldirectory>").unwrap();
        assert!(
            chain2.starts_with(&chain1[..close1]),
            "the generation-1 record's bytes preserved:\n{chain1}\n---\n{chain2}"
        );
        // The two records, in order, with the correct c4s (the
        // C4ID of each manifest's bytes).
        let recs = read_chain(&chain2).expect("the two chain records");
        assert_eq!(recs.len(), 2, "two generations in the chain");
        assert_eq!(recs[0], (1, name1.clone(), c4(&manifest1)));
        assert_eq!(recs[1], (2, name2.clone(), c4(&manifest2)));
        // Generation 3 (the numbering keeps climbing).
        let gen3 = write_history(&dest, 1_758_172_800).expect("generation 3");
        assert!(
            gen3.file_name().unwrap().to_string_lossy().starts_with("0003_DestR_"),
            "the 0003 numbering"
        );
        assert_eq!(read_chain(&std::fs::read_to_string(base.join("DestR/ascmhl/ascmhl_chain.xml")).unwrap()).unwrap().len(), 3);
        // The failure band (the ascmhl dir pre-created as a FILE —
        // the writer's create fails NAMED).
        let dest2 = base.join("DestF");
        std::fs::create_dir_all(&dest2).unwrap();
        std::fs::write(dest2.join("f.DNG"), b"media").unwrap();
        std::fs::write(dest2.join(ASCMHL_DIR_NAME), b"the blocker").unwrap();
        let err = write_history(&dest2, 1_758_000_000).expect_err("the create fails");
        assert!(
            format!("{err:#}").contains("create the ascmhl dir"),
            "the named refusal: {err:#}"
        );
        assert!(dest2.join(ASCMHL_DIR_NAME).is_file(), "the blocker stands (never clobbered)");
        let _ = std::fs::remove_dir_all(&base);
    }

    // -------------------------------------------------------------------
    // The read side (the MHL import + the sealed-archive
    // re-verify): the strict parser + the scope re-verify + the
    // latest-manifest selection.
    // -------------------------------------------------------------------

    /// A 2-file + 1-directory scope (the MHL read-side fixture — the
    /// `ScopeA` fixture's shape).
    fn mk_scope(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("frameprism_ascmhl_read_{tag}"));
        let _ = std::fs::remove_dir_all(&base);
        let scope = base.join("ScopeA");
        std::fs::create_dir_all(scope.join("clips")).unwrap();
        std::fs::write(scope.join("note.txt"), b"root note\n").unwrap();
        std::fs::write(scope.join("clips/a.DNG"), b"frame-one-bytes").unwrap();
        scope
    }

    /// Read + strictly parse the written manifest of `scope` (the
    /// self-written round-trip).
    fn parse_written(scope: &Path) -> (crate::ascmhl::Hashlist, String) {
        let mpath = scope
            .join(ASCMHL_DIR_NAME)
            .read_dir()
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().map(|e| e == "mhl").unwrap_or(false))
            .last()
            .expect("a written manifest stands");
        let name = mpath.file_name().unwrap().to_string_lossy().into_owned();
        let xml = std::fs::read_to_string(&mpath).unwrap();
        (parse_hashlist(&xml, &name).expect("the self-written manifest parses strictly"), name)
    }

    #[test]
    fn mhl_parse_hashlist_ok() {
        // (a) The write side's EXACT rendering parses strictly: the
        // 2-file + 1-directory scope → 2 file entries (the manifest's
        // order — the post-order: the subdirectory's file first) + 1
        // directory entry; the roothash round-trips (the 90-char
        // C4IDs); the ignore list + the tool identity + the process
        // ride through.
        let scope = mk_scope("parse_ok");
        write_history(&scope, 1_758_000_000).expect("the history stands");
        let (hl, name) = parse_written(&scope);
        assert_eq!(hl.files.len(), 2);
        assert_eq!(hl.files[0].path, "clips/a.DNG");
        assert_eq!(hl.files[0].c4, c4(b"frame-one-bytes"));
        assert_eq!(hl.files[0].size, 15);
        assert_eq!(hl.files[1].path, "note.txt");
        assert_eq!(hl.files[1].c4, c4(b"root note\n"));
        assert_eq!(hl.dirs.len(), 1);
        assert_eq!(hl.dirs[0].path, "clips");
        assert!(hl.dirs[0].content.starts_with("c4"));
        assert!(hl.dirs[0].structure.starts_with("c4"));
        assert_eq!(hl.root_content.len(), 90);
        assert_eq!(hl.root_structure.len(), 90);
        assert_eq!(
            hl.ignore,
            IGNORE_PATTERNS.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
        assert_eq!(hl.tool, "frameprism");
        assert_eq!(hl.tool_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(hl.process, "transfer");
        assert!(
            hl.creationdate.ends_with("+00:00"),
            "the creationdate is the writer's UTC form: {}",
            hl.creationdate
        );
        let _ = name;
    }

    #[test]
    fn mhl_parse_refusals() {
        // (b) The named refusal classes: the malformed XML, the
        // non-hashlist root, the non-2.0 version, the non-conformant
        // namespace (the 2009 MHL 1.1 lineage's out-of-scope
        // refusal), the malformed c4 (short / long / off-alphabet),
        // the duplicate <path>, the scope-escaping paths (a `..`
        // component / absolute), the missing roothash, the missing
        // ignore block, the empty hashes section — EVERY one names
        // the manifest + the offending value.
        let scope = mk_scope("parse_refusals");
        write_history(&scope, 1_758_000_000).expect("the history stands");
        let mpath = scope
            .join(ASCMHL_DIR_NAME)
            .read_dir()
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().map(|e| e == "mhl").unwrap_or(false))
            .next()
            .expect("a written manifest stands");
        let xml = std::fs::read_to_string(&mpath).unwrap();
        let name = "fixture.mhl";
        let file_c4 = c4(b"frame-one-bytes");
        // The roothash block's exact span (the surgical removals).
        let rs = xml.find("    <roothash>").expect("the roothash block");
        let re = rs + xml[rs..].find("    </roothash>").expect("the roothash close") + "    </roothash>".len();
        let is = xml.find("    <ignore>").expect("the ignore block");
        let ie = is + xml[is..].find("    </ignore>").expect("the ignore close") + "    </ignore>".len();
        // The a.DNG <hash> block's span (the duplicate surgery).
        let hs = xml.find("    <hash>").expect("the hash block");
        let he = hs + xml[hs..].find("    </hash>").expect("the hash close") + "    </hash>".len();
        let hash_block = xml[hs..he].to_string();
        let md = crate::ascmhl::ManifestData {
            folder: "ScopeA".into(),
            created: 1_758_000_000,
            hostname: "h".into(),
            tool_version: "t".into(),
            root_content: file_c4.clone(),
            root_structure: file_c4.clone(),
            entries: vec![],
        };
        let empty_hashes = crate::ascmhl::render_manifest(&md);
        let cases: Vec<(&str, String, &str)> = vec![
            ("malformed XML", xml.replacen("</hashlist>", "", 1), "parse the mhl manifest"),
            (
                "the non-hashlist root",
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mediahashlist version=\"2.0\" xmlns=\"urn:ASC:MHL:v2.0\">\n  <creatorinfo>\n    <creationdate>2025-09-16T00:00:00Z</creationdate>\n    <hostname>h</hostname>\n    <tool version=\"t\">x</tool>\n  </creatorinfo>\n</mediahashlist>\n"
                    .to_string(),
                "expected <hashlist>",
            ),
            (
                "the non-2.0 version",
                xml.replace("version=\"2.0\"", "version=\"1.9\""),
                "expected \"2.0\"",
            ),
            (
                "the non-conformant namespace",
                xml.replace("xmlns=\"urn:ASC:MHL:v2.0\"", "xmlns=\"urn:ASC:MHL:DIRECTORY:v2.0\""),
                "expected \"urn:ASC:MHL:v2.0\"",
            ),
            (
                "the malformed c4 (87 body chars)",
                xml.replacen(&file_c4, &format!("c4{}", "1".repeat(87)), 1),
                "exactly 88",
            ),
            (
                "the malformed c4 (89 body chars)",
                xml.replacen(&file_c4, &format!("c4{}", "1".repeat(89)), 1),
                "exactly 88",
            ),
            (
                "the malformed c4 (off-alphabet char)",
                xml.replacen(&file_c4, &format!("c4{}0", "1".repeat(87)), 1),
                "outside the C4ID character set",
            ),
            (
                "the duplicate <path>",
                xml.replacen(&hash_block, &format!("{hash_block}\n{hash_block}"), 1),
                "duplicate <path>",
            ),
            ("the scope-escaping path (..)", xml.replacen("clips/a.DNG", "../x", 1), "a `..` component"),
            (
                "the scope-escaping path (absolute)",
                xml.replacen(">note.txt<", ">/abs<", 1),
                "absolute <path>",
            ),
            (
                "the missing roothash",
                format!("{}{}", &xml[..rs], &xml[re..]),
                "missing the required <roothash>",
            ),
            (
                "the missing ignore block",
                format!("{}{}", &xml[..is], &xml[ie..]),
                "missing the required <ignore>",
            ),
            ("the empty hashes section", empty_hashes, "hashes section is empty"),
            (
                "the non-enum <c4> action",
                xml.replacen("action=\"original\"", "action=\"bogus\"", 1),
                "expected one of the format's enum values",
            ),
            (
                "the directoryhash path's size attribute",
                xml.replacen(
                    "<path lastmodificationdate=",
                    "<path size=\"99\" lastmodificationdate=",
                    1
                ),
                "carries a size attribute",
            ),
        ];
        for (label, bad, needle) in &cases {
            let err = match parse_hashlist(bad, name) {
                Err(e) => e,
                Ok(_) => panic!("{label}: the refusal was not raised"),
            };
            assert!(
                format!("{err:#}").contains(needle),
                "{label}: the named refusal is missing its class wording: {err:#}"
            );
            assert!(
                format!("{err:#}").contains(name),
                "{label}: the named refusal names the manifest: {err:#}"
            );
        }
    }

    #[test]
    fn mhl_verify_clean() {
        // (c) The clean re-verify: every row OK (the manifest's
        // order) + the roothash match — the parallel pool (jobs=0 =
        // all cores) on the 2-file scope.
        let scope = mk_scope("verify_clean");
        write_history(&scope, 1_758_000_001).expect("the history stands");
        let (hl, _) = parse_written(&scope);
        let res = verify_scope(&scope, &hl, 0).expect("the re-verify runs");
        assert_eq!(res.rows.len(), 2);
        assert!(
            res.rows.iter().all(|r| r.verdict == MhlRowVerdict::Ok),
            "every recorded file verifies: {res:?}"
        );
        assert_eq!(res.rows[0].path, "clips/a.DNG");
        assert_eq!(res.rows[1].path, "note.txt");
        assert!(
            res.root.content_match && res.root.structure_match,
            "the roothash seal holds on the unmodified scope: {res:?}"
        );
    }

    #[test]
    fn mhl_verify_tampered() {
        // (d) The byte-flip AFTER the manifest: the C4_MISMATCH row
        // (the size pre-filter passes — the flip keeps the length)
        // + the roothash mismatch (the seal check).
        let scope = mk_scope("verify_tampered");
        write_history(&scope, 1_758_000_002).expect("the history stands");
        let (hl, _) = parse_written(&scope);
        std::fs::write(scope.join("note.txt"), b"root notx\n").unwrap();
        let res = verify_scope(&scope, &hl, 1).expect("the re-verify runs");
        let bad = res.rows.iter().find(|r| r.path == "note.txt").expect("the row stands");
        assert_eq!(bad.verdict, MhlRowVerdict::C4Mismatch, "the flipped byte is named: {bad:?}");
        assert!(
            bad.detail.contains("the file hashes"),
            "the detail names the disk's fact: {bad:?}"
        );
        assert!(
            res.rows.iter().find(|r| r.path == "clips/a.DNG").unwrap().verdict == MhlRowVerdict::Ok,
            "the untouched file verifies"
        );
        assert!(!res.root.content_match, "the content seal breaks: {res:?}");
        assert!(!res.root.structure_match, "the structure seal breaks: {res:?}");
    }

    #[test]
    fn mhl_verify_missing() {
        // (e) The recorded file DELETED after the manifest: the
        // MISSING row + the roothash mismatch (the walk no longer
        // sees the file).
        let scope = mk_scope("verify_missing");
        write_history(&scope, 1_758_000_003).expect("the history stands");
        let (hl, _) = parse_written(&scope);
        std::fs::remove_file(scope.join("note.txt")).unwrap();
        let res = verify_scope(&scope, &hl, 1).expect("the re-verify runs");
        let bad = res.rows.iter().find(|r| r.path == "note.txt").expect("the row stands");
        assert_eq!(bad.verdict, MhlRowVerdict::Missing, "the vanished file is named: {bad:?}");
        assert!(!res.root.content_match, "the content seal breaks: {res:?}");
    }

    #[test]
    fn mhl_verify_added_file() {
        // (f) The LOAD-BEARING sealed-archive property: the
        // UNRECORDED ADDED file keeps the file sweep clean (every
        // recorded row OK — the sweep never sees unrecorded files)
        // and breaks the roothash (the seal check is its named
        // catch).
        let scope = mk_scope("verify_added");
        write_history(&scope, 1_758_000_004).expect("the history stands");
        let (hl, _) = parse_written(&scope);
        std::fs::write(scope.join("extra.txt"), b"unrecorded bytes\n").unwrap();
        let res = verify_scope(&scope, &hl, 1).expect("the re-verify runs");
        assert!(
            res.rows.iter().all(|r| r.verdict == MhlRowVerdict::Ok),
            "the file sweep is clean (the added file is not a recorded row): {res:?}"
        );
        assert_eq!(res.rows.len(), 2);
        assert!(!res.root.content_match, "the content seal breaks on the addition: {res:?}");
        assert!(!res.root.structure_match, "the structure seal breaks on the addition: {res:?}");
    }

    #[test]
    fn mhl_chain_selection() {
        // (g) The latest-manifest selection: the 2-manifest chain
        // selects the LATEST (0002) + the verify is clean against its
        // values (the 0001 selection would C4-mismatch the flipped
        // note.txt); the corrupt chain (a record's c4 ≠ the
        // manifest's bytes) = the named corrupt-record refusal; the
        // 2-manifest no-chain dir = the named ambiguity refusal (the
        // spec's exact wording); the single-manifest no-chain dir =
        // that manifest (the carve-out).
        let scope = mk_scope("chain");
        write_history(&scope, 1_758_000_010).expect("generation 1 stands");
        std::fs::write(scope.join("note.txt"), b"root notx\n").unwrap();
        write_history(&scope, 1_758_000_011).expect("generation 2 stands");
        let ascmhl_dir = scope.join(ASCMHL_DIR_NAME);
        let sel = select_manifest(&ascmhl_dir).expect("the chain selects the latest");
        let sel_name = sel.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            sel_name.starts_with("0002_"),
            "the latest generation is selected: {sel_name}"
        );
        let xml = std::fs::read_to_string(&sel).unwrap();
        let hl = parse_hashlist(&xml, &sel_name).expect("the latest manifest parses");
        let res = verify_scope(&scope, &hl, 1).expect("the re-verify runs");
        assert!(
            res.rows.iter().all(|r| r.verdict == MhlRowVerdict::Ok),
            "the latest manifest's values verify (the 0001 selection would fail): {res:?}"
        );
        assert!(
            res.root.content_match && res.root.structure_match,
            "the roothash seal holds against the latest values: {res:?}"
        );
        // The corrupt chain: flip one C4ID body character of the
        // FIRST record's c4 (the value's first char — the `>c4`
        // anchor skips the element name).
        let chain_path = ascmhl_dir.join(CHAIN_NAME);
        let chain = std::fs::read_to_string(&chain_path).unwrap();
        let pos = chain.find(">c4").expect("the chain carries the record c4");
        let body_start = pos + 1 + 2; // past the `>` + the `c4` prefix
        let orig = chain.as_bytes()[body_start];
        let flip = if orig == b'1' { '2' } else { '1' };
        let mut tampered = chain.clone();
        tampered.replace_range(body_start..body_start + 1, &flip.to_string());
        std::fs::write(&chain_path, tampered).unwrap();
        let err = select_manifest(&ascmhl_dir)
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("does not match the manifest bytes"),
            "the corrupt-record class is named: {err:#}"
        );
        // The 2-manifest no-chain dir: the named ambiguity refusal
        // (the spec's exact wording).
        std::fs::write(&chain_path, chain).unwrap(); // restore the good chain
        std::fs::remove_file(&chain_path).unwrap();
        let err = select_manifest(&ascmhl_dir).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("carries 2 manifests without a chain"), "the ambiguity refusal: {msg}");
        assert!(msg.contains("the history is ambiguous"), "the ambiguity refusal: {msg}");
        assert!(
            msg.contains("the record is untrustable"),
            "the ambiguity refusal: {msg}"
        );
        // The single-manifest no-chain dir: the carve-out.
        let scope2 = mk_scope("chain_single");
        write_history(&scope2, 1_758_000_012).expect("the generation stands");
        let ascmhl2 = scope2.join(ASCMHL_DIR_NAME);
        std::fs::remove_file(ascmhl2.join(CHAIN_NAME)).unwrap();
        let sel = select_manifest(&ascmhl2).expect("the single manifest is selected");
        assert!(
            sel.file_name().unwrap().to_string_lossy().starts_with("0001_"),
            "the single manifest is the selection"
        );
    }

    // -----------------------------------------------------------------------
    // The streaming sha512 (the refactor's byte-identity proof)
    // -----------------------------------------------------------------------

    /// (a) the property: for the pinned size ladder × the pinned chunk-
    /// size ladder, the chunked `Sha512State` digest == the one-shot
    /// `sha512()` on the same bytes (the one-shot is re-implemented
    /// over the state — this pins BOTH the refactor and the chunking).
    #[test]
    fn sha512_streaming_property() {
        let sizes = [0usize, 1, 127, 128, 129, 255, 1000, 4096, 1024 * 1024, 1024 * 1024 + 1];
        let chunks = [1usize, 3, 127, 128, 1000, 1024 * 1024];
        for &n in &sizes {
            // Deterministic pseudo-content (no fixture file needed for the property).
            let data: Vec<u8> = (0..n).map(|i| ((i.wrapping_mul(31)) % 251) as u8).collect();
            let once = sha512(&data);
            for &c in &chunks {
                let mut s = Sha512State::new();
                for chunk in data.chunks(c) {
                    s.update(chunk);
                }
                assert_eq!(s.finalize(), once, "size {n} chunked by {c}");
            }
        }
    }

    /// (b) the KAT cases of the existing `sha512_vectors` (the empty,
    /// "abc", the formula 55/56/111/112/1000 cases), fed in ODD chunk
    /// sizes (1 / 3 / 127-byte chunks — the padding corner cases at the
    /// 127/128/129/255-byte message lengths are exercised by (a)'s
    /// ladder; this pins the published digests themselves, streamed).
    #[test]
    fn sha512_streaming_fips_vectors() {
        fn formula(n: usize) -> Vec<u8> {
            (0..n).map(|i| (((i as u64) * (i as u64) * 31 + (i as u64) * 7 + 11) % 256) as u8).collect()
        }
        let hex = |d: [u8; 64]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (b"".to_vec(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
            (b"abc".to_vec(), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            (formula(55), "b0ef420cf8d4288fae50101f234366d5c461aa0342543a7b9af49fab31e19d02bcc73f797e0cc98e9422613b43f9c3faf85d275f65676a1ebb6333addecfd831"),
            (formula(56), "8cd1ea2b40322eaea3d7cc1cffbb27d84304763edd956863f3fc53b77c96311f29a180e44db3afe9cfe9e46e1be2ff6ad937591691f541322de7cc6f13d39782"),
            (formula(111), "3b5fbcb7c413a94658bd8b7097185e9945f513d5a7acaff7db3e8e68dc7d49eea4e86df35a147a10d357f2e3f5e6c43d7c11cf8189668d96111700e213e74d77"),
            (formula(112), "cfa2ba1be532497cb786f0255b2f07f51f05b540b98723f0ed69324be02b82c68c8c52f4a4b8efe0e5fb5b664e6248f5835bdb9cf12d654c40b628c1e8c0f183"),
            (formula(1000), "3c18ad41cf3f8eb46aba82b49229edad64485b203aefc021807e626f2c36fc5352539a2bbeadd680c2794c2feff6d22b8a7692e7a94a8863bd59185919f323f7"),
        ];
        for (msg, expected) in &cases {
            for &c in &[1usize, 3, 127] {
                let mut s = Sha512State::new();
                for chunk in msg.chunks(c) {
                    s.update(chunk);
                }
                assert_eq!(
                    &hex(s.finalize()),
                    expected,
                    "the SHA-512 of the {}-byte message chunked by {c}",
                    msg.len()
                );
            }
        }
    }
    /// 55a (a) — the malformed-XML SYNTAX edges (the per-bail! sites
    /// of `parse_lite` / `parse_element` — the byte-offset arithmetic's
    /// named-refusal pin: every adversarial input = a TYPED refusal with
    /// the existing class wording — ZERO new wordings — or a benign
    /// parse. The truncated-at-every-byte sweep pins the total-safety at
    /// the byte level (the test COMPLETING = no panic / no abort — the
    /// clean result, now standing in the suite).
    #[test]
    fn xml_syntax_edges() {
        fn refused(doc: &str) -> String {
            match parse_lite(doc) {
                Ok(_) => panic!("{doc:?}: the refusal was not raised"),
                Err(e) => e.to_string(),
            }
        }
        // (a.1) The per-site syntax edges (the `misc` sweep —
        // the expected outcome per input).
        let e = refused("");
        assert!(e.contains("expected an element start"), "the empty document: {e}");
        let e = refused("   \n\t  ");
        assert!(e.contains("expected an element start"), "the whitespace-only document: {e}");
        let e = refused("<?xml version=\"1.0\"?>");
        assert!(e.contains("expected an element start"), "the declaration-only document: {e}");
        let e = refused("<?xml version=\"1.0\"");
        assert!(
            e.contains("the XML declaration is unterminated"),
            "the truncated declaration: {e}"
        );
        // The comment-like / DOCTYPE byte sequences: the parser-lite
        // reads them as element starts — WEIRD but typed + total (the
        // behavior pin: not a crash class).
        let e = refused("<!-- x -->");
        assert!(e.contains("has no value"), "the comment-only document: {e}");
        let e = refused("<!DOCTYPE hashlist>");
        assert!(
            e.contains("the attribute \"hashlist\" of <!DOCTYPE> has no value"),
            "the DOCTYPE document: {e}"
        );
        let e = refused("<");
        assert!(e.contains("an empty element name at byte 1"), "the lone <: {e}");
        let e = refused("</a>");
        assert!(
            e.contains("an empty element name at byte 1"),
            "the close-at-root (the name scan hits / immediately): {e}"
        );
        let e = refused("<a");
        assert!(e.contains("an unterminated element start for <a>"), "the truncated start: {e}");
        let e = refused("<a>");
        assert!(e.contains("the element <a> is unclosed"), "the unclosed element: {e}");
        assert!(parse_lite("<a/>").is_ok(), "the self-close is well-formed (benign)");
        let e = refused("<a /");
        assert!(e.contains("a malformed self-close for <a>"), "the truncated self-close: {e}");
        let e = refused("<a b");
        assert!(e.contains("the attribute \"b\" of <a> has no value"), "the value-less attr: {e}");
        let e = refused("<a b=");
        assert!(e.contains("has an unquoted value"), "the eq-truncated attr: {e}");
        let e = refused("<a b=\"");
        assert!(e.contains("has an unterminated value"), "the unterminated attr value: {e}");
        let e = refused("<a b=1>");
        assert!(e.contains("has an unquoted value"), "the unquoted attr value: {e}");
        let e = refused("<a =\"1\">");
        assert!(e.contains("an empty attribute name in <a>"), "the empty attr name: {e}");
        let e = refused("<a></b");
        assert!(e.contains("an unterminated close tag for <a>"), "the truncated close: {e}");
        let e = refused("<a><b></a></b>");
        assert!(
            e.contains("a mismatched close: expected </b>, got </a>"),
            "the nested mismatch: {e}"
        );
        let e = refused("<a><![CDATA[x]]></a>");
        assert!(e.contains("unsupported markup at byte"), "the CDATA-ish markup: {e}");
        let e = refused("<a><?x?></a>");
        assert!(
            e.contains("a mismatched close"),
            "the PI is parsed as a close tag named ?x? (typed): {e}"
        );
        // The comment surface (benign pins): skipped, the text stands.
        let el = parse_lite("<a><!-- c -->x</a>").expect("the comment skips (benign)");
        assert_eq!(el.text, "x");
        assert!(parse_lite("<a><!-- --></a>").is_ok(), "the empty comment (benign)");
        // The mixed-content surface (the class-23 behavior note): a
        // SINGLE text run adjacent to elements is OK; a SECOND
        // non-whitespace text run = the bail.
        assert!(parse_lite("<a>x<b/></a>").is_ok(), "the single text run (benign)");
        let e = refused("<a>x<b/>y</a>");
        assert!(e.contains("mixed content in <a>"), "the two text runs: {e}");
        // (a.2) The truncated-at-every-byte sweep (the clean
        // result, standing in the suite: every prefix = a typed result —
        // the test completing = no panic / no abort; only the final
        // prefixes — the full document + the trailing-newline variant —
        // are well-formed).
        let m = render_manifest(&fixture());
        for n in 0..=m.len() {
            let _ = parse_lite(&m[..n]); // a typed Ok or Err — never a panic
        }
        let oks: Vec<usize> = (0..=m.len())
            .filter(|n| parse_lite(&m[..*n]).is_ok())
            .collect();
        assert!(
            oks.iter().all(|n| *n >= m.len() - 1),
            "only the final prefixes are well-formed: {oks:?}"
        );
        let mid = parse_lite(&m[..1]).expect_err("the single-byte prefix refuses");
        assert!(
            mid.to_string().contains("an empty element name"),
            "the truncated root start: {mid:?}"
        );
    }

    /// 55a (b) — the ESCAPING edges (decode_entities — the attribute
    /// + the text positions, both probed: the 5 standard entities decode
    /// (benign), the unknown / bare / unterminated / empty-reference /
    /// doubled / case-mismatched forms = the existing named classes —
    /// ZERO new wordings).
    #[test]
    fn escaping_edges() {
        // (b.1) The 5 standard entities: benign, decoded — attribute +
        // text position.
        for (ent, ch) in [("amp", "&"), ("lt", "<"), ("gt", ">"), ("quot", "\""), ("apos", "'")] {
            let el = parse_lite(&format!("<root a=\"&{ent};\"></root>"))
                .unwrap_or_else(|e| panic!("the entity &{ent}; in the attribute: {e}"));
            assert_eq!(attr(&el, "a").unwrap_or(""), ch, "the attribute entity &{ent};");
            let el = parse_lite(&format!("<root>&{ent};</root>"))
                .unwrap_or_else(|e| panic!("the entity &{ent}; in the text: {e}"));
            assert_eq!(el.text, ch, "the text entity &{ent};");
        }
        // (b.2) The unknown entity: the named class (attribute + text).
        for doc in ["<root a=\"&zeta;\"></root>", "<root>&zeta;</root>"] {
            let e = match parse_lite(doc) {
                Ok(_) => panic!("{doc}: the refusal was not raised"),
                Err(e) => e.to_string(),
            };
            assert!(
                e.contains("an unknown entity &zeta; (the parser-lite's surface: the five standard entities)"),
                "the unknown entity: {e}"
            );
        }
        // (b.3) The bare & / the & at the end / the missing semicolon:
        // the unterminated-entity class (attribute + text).
        for doc in [
            "<root a=\"&x\"></root>",
            "<root a=\"x&\"></root>",
            "<root>&</root>",
            "<root a=\"&am\"></root>",
        ] {
            let e = match parse_lite(doc) {
                Ok(_) => panic!("{doc}: the refusal was not raised"),
                Err(e) => e.to_string(),
            };
            assert!(
                e.contains("an unterminated entity at byte"),
                "the bare / trailing / semicolon-less &: {e}"
            );
        }
        // (b.4) The empty reference / the doubled / the
        // case-mismatched: the unknown-entity class (the `other` is the
        // offending value in the wording).
        for doc in ["<root a=\"&;\"></root>", "<root a=\"&&amp;\"></root>", "<root a=\"&AMP;\"></root>"] {
            let e = match parse_lite(doc) {
                Ok(_) => panic!("{doc}: the refusal was not raised"),
                Err(e) => e.to_string(),
            };
            assert!(
                e.contains("an unknown entity"),
                "the empty-reference / doubled / case entity: {e}"
            );
        }
        // (b.5) The entity mid-value + the double-escape (benign pins):
        // the surrounding text stands + the entities decode.
        let el = parse_lite("<root a=\"x&amp;y\"></root>").expect("the mid-value entity (benign)");
        assert_eq!(attr(&el, "a").unwrap_or(""), "x&y");
        let el = parse_lite("<root a=\"&amp;amp;\"></root>")
            .expect("the double-escaped entity (benign — the legal `&amp;amp;`)");
        assert_eq!(attr(&el, "a").unwrap_or(""), "&amp;");
    }

    /// 55a (c) — the UNICODE edges (the multi-byte char-boundary
    /// safety of the byte-offset arithmetic: name / attribute name /
    /// value / text, the parse positions — benign + round-tripping) +
    /// the FILE SEAM (the non-UTF-8 bytes question: `select_manifest`
    /// reads the chain via `read_to_string` → the TYPED io error — not a
    /// panic, not a new class; the same primitive at every file-read
    /// site in the chain / verify layer).
    #[test]
    fn unicode_edges() {
        // (c.1) The multi-byte char-boundary edges (benign, probed).
        let el = parse_lite("<А x=\"1\"></А>")
            .expect("the multi-byte element name (benign)");
        assert_eq!(el.name, "А");
        let el = parse_lite("<root А=\"1\"></root>")
            .expect("the multi-byte attribute name (benign)");
        assert_eq!(attr(&el, "А").unwrap_or(""), "1");
        let el = parse_lite("<root>😀</root>")
            .expect("the multi-byte text (benign)");
        assert_eq!(el.text, "😀");
        let el = parse_lite("<root a=\"А😀\"></root>")
            .expect("the multi-byte attribute value (benign)");
        assert_eq!(
            attr(&el, "a").unwrap_or(""),
            "А😀",
            "the multi-byte value round-trips byte-identical"
        );
        // The multi-byte at the parse positions (the name start after
        // <, the attribute boundary): the from_utf8 sub-slices of a
        // valid-UTF-8 &str always land on char boundaries (the
        // defensive non-UTF-8 bails are therefore unreachable
        // via the &str surface).
        assert!(
            parse_lite("<А А=\"А\"></А>").is_ok(),
            "the multi-byte at every parse position (benign)"
        );
        // (c.2) The FILE SEAM: the non-UTF-8 chain file = the typed io
        // error (the InvalidData class — not a panic: the test
        // completing is the proof; not a new class: the existing
        // `read the ascmhl chain` context + the io's own wording).
        let base = std::env::temp_dir().join(format!(
            "frameprism_ascmhl_55a_utf8_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let ascmhl = base.join("ascmhl");
        std::fs::create_dir_all(&ascmhl).unwrap();
        std::fs::write(
            ascmhl.join("ascmhl_chain.xml"),
            b"<ascmhldirectory>\xff\xfe</ascmhldirectory>",
        )
        .unwrap();
        let e = select_manifest(&ascmhl).expect_err("the non-UTF-8 chain file refuses");
        assert!(
            e.to_string().contains("read the ascmhl chain"),
            "the existing context names the seam: {e:?}"
        );
        assert!(
            e.downcast_ref::<std::io::Error>().is_some(),
            "the non-UTF-8 bytes = the typed io error (the InvalidData class): {e:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The NAMESPACE / VERSION edges (the surgical
    /// substitutions over the rendered manifest — the conformant-
    /// refusal class: every one names the manifest + the offending
    /// value; the extra-attr / duplicate-attr
    /// benign pins: the behavior is the pin — they are NOT refusal
    /// classes, ZERO new wordings).
    #[test]
    fn namespace_version_edges() {
        const NAME: &str = "probe55a.mhl";
        let base = render_manifest(&fixture());
        fn refused(base: &str, from: &str, to: &str, label: &str, expect: &str) {
            let bad = base.replacen(from, to, 1);
            assert_ne!(bad, base, "the substitution applied: {label}");
            let e = match parse_hashlist(&bad, NAME) {
                Ok(_) => panic!("{label}: the refusal was not raised"),
                Err(e) => e.to_string(),
            };
            assert!(e.contains(NAME), "{label}: the manifest is named: {e}");
            assert!(e.contains(expect), "{label}: the class wording: {e}");
        }
        // (d.1) The namespace edges (the v1-lineage out-of-scope refusal
        // included).
        refused(
            &base,
            "xmlns=\"urn:ASC:MHL:v2.0\"",
            "",
            "the xmlns missing",
            "namespace is \"\", expected \"urn:ASC:MHL:v2.0\"",
        );
        refused(
            &base,
            "xmlns=\"urn:ASC:MHL:v2.0\"",
            "xmlns=\"URN:ASC:MHL:v2.0\"",
            "the xmlns wrong case",
            "namespace is \"URN:ASC:MHL:v2.0\"",
        );
        refused(
            &base,
            "xmlns=\"urn:ASC:MHL:v2.0\"",
            "xmlns=\"urn:ASC:MHL:v1.1\"",
            "the v1 lineage",
            "namespace is \"urn:ASC:MHL:v1.1\"",
        );
        // (d.2) The version edges (the root's attr only — a version
        // moved onto a child leaves the root's empty → the same class).
        refused(
            &base,
            "version=\"2.0\"",
            "version=\"2.1\"",
            "the version 2.1",
            "version is \"2.1\", expected \"2.0\"",
        );
        refused(
            &base,
            "version=\"2.0\"",
            "",
            "the version missing",
            "version is \"\", expected \"2.0\"",
        );
        refused(
            &base,
            "version=\"2.0\"",
            "version=\"V2.0\"",
            "the version wrong case",
            "version is \"V2.0\"",
        );
        let moved = base
            .replacen("version=\"2.0\" ", "", 1)
            .replacen("<creatorinfo>", "<creatorinfo version=\"2.0\">", 1);
        let e = match parse_hashlist(&moved, NAME) {
            Ok(_) => panic!("the version-on-child: the refusal was not raised"),
            Err(e) => e.to_string(),
        };
        assert!(
            e.contains("version is \"\", expected \"2.0\""),
            "the version moved off the root (the root's attr is empty): {e}"
        );
        // (d.3) The benign pins (the behavior is the pin — NOT refusal
        // classes): the extra root attr + the duplicate version attr
        // parse OK (the XML layer ignores unknown attrs; `attr()` takes
        // the FIRST match).
        let extra = base.replacen("<hashlist ", "<hashlist extra=\"1\" ", 1);
        assert!(
            parse_hashlist(&extra, NAME).is_ok(),
            "the extra root attr parses (benign — the behavior pin)"
        );
        let dup = base.replacen("version=\"2.0\"", "version=\"2.0\" version=\"2.0\"", 1);
        assert!(
            parse_hashlist(&dup, NAME).is_ok(),
            "the duplicate version attr parses (benign — the first match wins)"
        );
    }

    /// 55a (e) — the PATH edges (`check_in_scope` — the BEHAVIOR IS
    /// THE PIN, NOT A FIX: the check is LITERAL — `split('/')` +
    /// `comp == ".."`, NO normalization: `a/b/../c` is refused even
    /// though it normalizes to the in-scope `a/c`; the `.` / the empty
    /// / the Unicode / the backslash components pass; the path is
    /// TRIMMED at extraction — the whitespace-only path = the empty
    /// class. Every refusal names the manifest + the path value.)
    #[test]
    fn path_edges() {
        const NAME: &str = "probe55a.mhl";
        let base = render_manifest(&fixture());
        let with_path = |path: &str| {
            let bad = base.replace(">clips/a.DNG</path>", &format!(">{path}</path>"));
            assert_ne!(bad, base, "the path substitution applied: {path:?}");
            bad
        };
        // (e.1) The `..`-component class (the literal-component pin —
        // the normalizing-in-scope `a/b/../c` is refused too).
        for p in ["../x", "a/b/../c", "a/../../b", "a/../..", "a/..", ".."] {
            let e = match parse_hashlist(&with_path(p), NAME) {
                Ok(_) => panic!("the path {p:?}: the refusal was not raised"),
                Err(e) => e.to_string(),
            };
            assert!(e.contains(NAME), "the path {p:?}: the manifest is named: {e}");
            assert!(
                e.contains("with a `..` component"),
                "the path {p:?}: the ..-component class: {e}"
            );
        }
        // (e.2) The absolute class.
        let e = match parse_hashlist(&with_path("/abs"), NAME) {
            Ok(_) => panic!("the absolute path: the refusal was not raised"),
            Err(e) => e.to_string(),
        };
        assert!(e.contains("an absolute <path> \"/abs\""), "the absolute path: {e}");
        // (e.3) The empty class (the trim pin: the whitespace-only path
        // trims to empty at extraction — `path_el.text.trim()`).
        for p in ["", "   "] {
            let e = match parse_hashlist(&with_path(p), NAME) {
                Ok(_) => panic!("the path {p:?}: the refusal was not raised"),
                Err(e) => e.to_string(),
            };
            assert!(
                e.contains("an empty <path> in its hashes section"),
                "the path {p:?}: the empty class (the whitespace-only trim pin): {e}"
            );
        }
        // (e.4) The benign components (the literal-match pin: only the
        // exact `..` component refuses — `..x` / `...` / `.` / the
        // empty / the backslash / the Unicode all pass).
        for p in ["a/b/", "./a", "a/./b", "a\\b", "clips/А.DNG", "a/..x", "a/...", "a//b"] {
            assert!(
                parse_hashlist(&with_path(p), NAME).is_ok(),
                "the path {p:?} is in scope (the behavior pin)"
            );
        }
    }

    /// The TOTAL-SAFETY DEPTH FINDING:
    /// `parse_element`'s
    /// unbounded recursion over the depth-50,000 input (350,000 B — the
    /// foreign-manifest import surface) was a stack overflow →
    /// SIGABRT (exit 134 — not a typed error); the `MAX_ELEMENT_DEPTH`
    /// guard (bails when the depth EXCEEDS the bound) converts it to
    /// the named typed refusal. THE BOUNDARY: the guard trips at the
    /// element whose depth EXCEEDS the bound — the maximal accepted nesting = depth 10,000 (= the bound), the
    /// minimal refused = depth 10,001 (the first depth > the bound) —
    /// the trip point pinned at both sides. STACK NOTE (the measured
    /// constraint): the boundary inputs live at ~10,001 live recursion
    /// frames, which do NOT fit the 2 MB libtest thread (measured:
    /// SIGABRT at 2 MB, clean at 8 MB) — so the
    /// parse runs on an explicit 8 MB worker thread (the default
    /// process main-thread stack size); the test thread only orchestrates. The 350,000 B
    /// crash input + the import-surface form (the manifest named by
    /// the EXISTING `parse the mhl manifest {manifest}` context) ride the same worker.
    #[test]
    fn nesting_depth_bound() {
        assert_eq!(
            MAX_ELEMENT_DEPTH, 10_000,
            "the bound is pinned (a bound change = a conscious wording change)"
        );
        /// One parse on the explicit 8 MB worker thread (the stack note
        /// above): `kind` = 0 the standalone `parse_lite`, 1 the import
        /// surface `parse_hashlist` (the manifest context). The Err side
        /// returns the CHAIN rendering (`{:?}` — the Display of a
        /// context-wrapped anyhow error is the outermost context alone:
        /// the class wording rides the chain, the form
        /// `parse the mhl manifest {manifest}: <class wording>`).
        fn run_depth(n: usize, kind: u8) -> Result<String, String> {
            let h = std::thread::Builder::new()
                .name("depth-probe".into())
                .stack_size(8 * 1024 * 1024)
                .spawn(move || {
                    let mut s = String::with_capacity(n * 6);
                    for _ in 0..n {
                        s.push_str("<a>");
                    }
                    for _ in 0..n {
                        s.push_str("</a>");
                    }
                    match kind {
                        0 => parse_lite(&s)
                            .map(|_| "ok".to_string())
                            .map_err(|e| format!("{e:?}")),
                        _ => parse_hashlist(&s, "probe55a.mhl")
                            .map(|_| "ok".to_string())
                            .map_err(|e| format!("{e:?}")),
                    }
                })
                .expect("the 8 MB worker thread spawns");
            h.join()
                .expect("the worker completes (an abort = a stack overflow despite the bound)")
        }
        // (f.1) The crash input (the 350,000 B depth-50,000 minimal
        // SIGABRT repro): now a TYPED refusal — the proof is the typed
        // Err (that is only true if the process did not SIGABRT).
        let e = run_depth(50_000, 0).expect_err("the crash input is refused");
        assert!(
            e.contains("an excessive element nesting depth 10001"),
            "the class wording names the offending value: {e}"
        );
        assert!(
            e.contains("the parse_lite nesting bound is 10000"),
            "the bound rides the wording: {e}"
        );
        assert!(
            e.contains("the malformed record — the record is untrustable"),
            "the class's tail: {e}"
        );
        // The IMPORT surface (the manifest +
        // the offending value named): the existing `parse the mhl
        // manifest {manifest}` context wraps the guard.
        let e = run_depth(50_000, 1).expect_err("the crash input is refused at the import surface");
        assert!(
            e.contains("parse the mhl manifest probe55a.mhl"),
            "the manifest is named by the existing context: {e}"
        );
        assert!(
            e.contains("an excessive element nesting depth 10001"),
            "the class wording at the import surface: {e}"
        );
        // (f.3) The BOUNDARY (the trip point pinned at both sides):
        // depth exactly the bound = the maximal accepted nesting
        // (well-formed, parses); depth bound+1 = the minimal refused
        // nesting (the first depth EXCEEDING the bound).
        assert!(
            run_depth(10_000, 0).is_ok(),
            "the depth-10,000 nesting parses (the maximal accepted nesting)"
        );
        let e =
            run_depth(10_001, 0).expect_err("the depth-10,001 nesting is refused (the trip point)");
        assert!(
            e.contains("an excessive element nesting depth 10001"),
            "the trip point's wording: {e}"
        );
    }
}
