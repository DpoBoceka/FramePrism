//! The signed manifest — the provenance signature (the
//! sign/verify surface over the reel manifest; the tool
//! verifies, it does NOT mint).
//!
//! sha256 proves the content is intact; the signature proves *this
//! archive was produced by frameprism vX on date D with pin set P*. The
//! 50-year-archive angle — a reader decades from now can tell "produced by the
//! trusted toolchain" from "the bytes match something."
//!
//! The signing target: the reel manifest `<dir>/reel.reel-manifest.tsv`
//! (the bake's reel-granularity record — `crate::reel::REEL_MANIFEST_NAME`);
//! `sign` / `verify` take the MANIFEST PATH as their first argument, so
//! they work on whatever the bake produced. The manifest bytes are
//! NEVER touched by the signature: the envelope is a NEW file
//! `<manifest>.sig` (the header-block record pattern — the magic line,
//! the `version:` / `tool_version:` fields, the named fields, the
//! `note:` line, the atomic tmp+rename write; the wall clock lives in
//! the ENVELOPE only — `signed_at` — never in the manifest).
//!
//! The signature (ed25519-dalek, RFC 8032 — DETERMINISTIC: the same
//! manifest + the same key + the same inputs → the same signature
//! bytes) covers the CANONICAL STRING (the pinned v1 shape — a future
//! reader re-derives it from the envelope alone + the manifest):
//!
//!     frameprism-reel-sig-v1
//!     manifest_sha256=<64 hex>
//!     tool_version=<v>
//!     signed_at=<unix seconds>
//!     key_fingerprint=<64 hex>
//!     pin_set=<the one-line canonical pin-set string>
//!
//! (the five `key=value` lines in that order, `\n`-joined, with the
//! leading `frameprism-reel-sig-v1\n` magic line; no trailing newline).
//! Re-sign with the same `--date` = byte-identical envelope bytes.
//!
//! The KEY FILE — the documented external format (the tool verifies,
//! it does NOT mint — the same posture as the pins: the tool checks
//! what it is given; key generation is the documented openssl +
//! coreutils recipe in docs/provenance.md, a separate surface):
//!
//!     # frameprism key file
//!     version: 1
//!     type: private            # or: public
//!     fingerprint: <64 hex — the sha256 of the 32-byte RAW public key>
//!     public: <64 hex — the 32-byte public key>
//!     seed: <64 hex — the 32-byte ed25519 seed>        # private files ONLY
//!
//! `sign` requires `type: private` (a public-only key = the named
//! rc=2 refusal — the tool never mints, and a verify key is never a
//! signing key by accident). `verify` accepts `type: public` OR
//! `type: private` (it uses the `public:` field — a private key file
//! may verify its own signatures). A corrupt key file (bad magic / bad
//! hex / wrong lengths / a missing field / `type: public` with a
//! `seed:` line / a `fingerprint:` that does not equal the sha256 of
//! the raw public key) = the named corrupt-key refusal (rc=2, zero
//! partial operations — a key file that lies about its own identity is
//! a records-class refusal, not a signature finding).
//!
//! The audit integration (`crate::audit::run_audit`): the keyless
//! CONTENT CLAIM — the envelope well-formedness + the manifest
//! `manifest_sha256` re-hash (the signature itself is `verify`'s
//! surface, which takes the key):
//! - `audit: signature VALID-CONTENT (...)` — the audit verdict is
//!   UNAFFECTED (a valid signature is provenance, not an archive check);
//! - `audit: signature INVALID-CONTENT (malformed envelope | manifest
//!   mismatch)` — the audit FAILS (rc=1, the offender class —
//!   the audit-side findings ride rc=1; a broken
//!   provenance claim is worse than its absence — the envelope lies);
//! - `audit: signature ABSENT (...)` — the honesty line (every audit
//!   names the reel manifest's signature state; the signature is
//!   OPTIONAL for the audit PASS — pre-signing archives stay valid).
//!
//! The VERB rc convention matches the audit's: a signature FINDING
//! (verify's mismatch/invalid classes) rides rc=1 (the documented
//! offender class); a malformed REFUSAL (corrupt envelope / corrupt
//! key / missing manifest or .sig / public-only sign) rides rc=2.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args as ClapArgs;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::jxl::sha256_hex;

/// The `.sig` path for a manifest path (`<manifest path>.sig` — the
/// envelope's default placement, next to the manifest it covers).
fn sig_path_of(manifest: &Path) -> PathBuf {
    let mut s = manifest.as_os_str().to_os_string();
    s.push(".sig");
    PathBuf::from(s)
}

/// The reel signature envelope's magic line.
pub const SIG_MAGIC: &str = "# frameprism reel signature";

/// The key file's magic line.
pub const KEY_MAGIC: &str = "# frameprism key file";

/// The canonical-string magic (line 1 of the signature input).
pub const CANONICAL_MAGIC: &str = "frameprism-reel-sig-v1";

/// One 64-hex field (a 32-byte digest / key material, lowercase).
fn parse_hex64(field: &str, value: &str) -> Result<[u8; 32], String> {
    let v = value.trim();
    if v.len() != 64 || !v.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "bad hex in field {field:?}: {v:?} (want 64 lowercase hex digits)"
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&v[2 * i..2 * i + 2], 16)
            .map_err(|_| format!("bad hex in field {field:?}: {v:?}"))?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// The key file (the documented format — the tool verifies, it does NOT mint)
// ---------------------------------------------------------------------------

/// The key file's class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// A signing key (carries the `seed:` line).
    Private,
    /// A verify key (no `seed:` line).
    Public,
}

/// The parsed key file (the strict shape — every field is checked; a
/// field that lies (the fingerprint vs the raw public key) is a named
/// corrupt-key error, not a tolerant skip).
#[derive(Clone, Debug)]
pub struct KeyFile {
    pub kind: KeyKind,
    /// The key file's `fingerprint:` field (== sha256(raw public key) —
    /// checked at parse).
    pub fingerprint: [u8; 32],
    /// The raw 32-byte ed25519 public key.
    pub public: [u8; 32],
    /// The raw 32-byte ed25519 seed (private files only).
    pub seed: Option<[u8; 32]>,
}

impl KeyFile {
    /// The fingerprint as 64 lowercase hex (the envelope / the verdict
    /// lines' field).
    pub fn fingerprint_hex(&self) -> String {
        hex(&self.fingerprint)
    }

    /// The ed25519 signing key (private files only).
    pub fn signing_key(&self) -> Result<SigningKey, String> {
        match self.seed {
            Some(seed) => Ok(SigningKey::from_bytes(&seed)),
            None => Err(
                "the key file has no seed: line (type: public — a verify key can never sign)"
                    .into(),
            ),
        }
    }

    /// The ed25519 verifying key (both classes — the `public:` field).
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.public)
            .expect("the public: field is a 32-byte key (checked at parse)")
    }
}

/// The raw 32-byte public key DERIVED from the seed (the keygen
/// recipe's cross-check — the sha256 of these bytes is the
/// fingerprint).
pub fn public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Parse the key file (the strict shape). A bad magic, an unsupported
/// version, a bad/missing/duplicate field, a bad `type:`, a
/// `type: public` with a `seed:` line, or a `fingerprint:` that does
/// not equal the sha256 of the raw public key = a named corrupt-key
/// error (the rc=2 records-class refusal — zero partial operations).
/// Unknown `key: value` fields are skipped (the additive header
/// convention — new key-file fields never invalidate old keys).
pub fn parse_key_file(path: &Path) -> Result<KeyFile, String> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("unreadable key file {path:?}: {e}"))?;
    let mut lines = text.lines().enumerate();
    let (_, magic) = lines
        .next()
        .ok_or_else(|| format!("empty key file {name}"))?;
    if magic != KEY_MAGIC {
        return Err(format!(
            "corrupt key file {name}: the magic line is {magic:?}, want {KEY_MAGIC:?}"
        ));
    }
    let mut version: Option<&str> = None;
    let mut kind: Option<KeyKind> = None;
    let mut fingerprint: Option<[u8; 32]> = None;
    let mut public: Option<[u8; 32]> = None;
    let mut seed: Option<[u8; 32]> = None;
    for (i, line) in lines {
        let lineno = i + 1;
        if line.trim().is_empty() {
            continue;
        }
        let (key, value) = match line.split_once(':') {
            Some(kv) => kv,
            None => {
                return Err(format!(
                    "corrupt key file {name}: line {lineno} is not a field: {line:?}"
                ))
            }
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "version" => {
                if version.is_some() {
                    return Err(format!("corrupt key file {name}: duplicate field {key:?}"));
                }
                version = Some(value);
            }
            "type" => {
                if kind.is_some() {
                    return Err(format!("corrupt key file {name}: duplicate field {key:?}"));
                }
                kind = Some(match value {
                    "private" => KeyKind::Private,
                    "public" => KeyKind::Public,
                    other => {
                        return Err(format!(
                            "corrupt key file {name}: bad type {other:?} (want private or public)"
                        ))
                    }
                });
            }
            "fingerprint" => {
                if fingerprint.is_some() {
                    return Err(format!("corrupt key file {name}: duplicate field {key:?}"));
                }
                fingerprint = Some(parse_hex64(key, value)?);
            }
            "public" => {
                if public.is_some() {
                    return Err(format!("corrupt key file {name}: duplicate field {key:?}"));
                }
                public = Some(parse_hex64(key, value)?);
            }
            "seed" => {
                if seed.is_some() {
                    return Err(format!("corrupt key file {name}: duplicate field {key:?}"));
                }
                seed = Some(parse_hex64(key, value)?);
            }
            _ => {} // future fields (the header is additive)
        }
    }
    let version = version
        .ok_or_else(|| format!("corrupt key file {name}: missing field \"version\""))?;
    if version != "1" {
        return Err(format!(
            "corrupt key file {name}: unsupported version {version:?} (want 1)"
        ));
    }
    let kind = kind
        .ok_or_else(|| format!("corrupt key file {name}: missing field \"type\""))?;
    let fingerprint = fingerprint
        .ok_or_else(|| format!("corrupt key file {name}: missing field \"fingerprint\""))?;
    let public = public
        .ok_or_else(|| format!("corrupt key file {name}: missing field \"public\""))?;
    // The identity check: the fingerprint MUST equal the sha256 of the
    // raw public key (a key file that lies about its own identity is a
    // records-class refusal).
    let calc = crate::jxl::sha256(&public);
    if fingerprint != calc {
        return Err(format!(
            "corrupt key file {name}: fingerprint {} does not equal the sha256 of the raw public key {} (the key file does not match its own identity)",
            hex(&fingerprint),
            hex(&calc)
        ));
    }
    // The class/seed consistency: a public file must not carry a seed
    // (a verify key is never a signing key); a private file MUST carry
    // the seed (the private file is the signing key's record — a
    // private file without its seed is a records-class refusal).
    if kind == KeyKind::Public && seed.is_some() {
        return Err(format!(
            "corrupt key file {name}: type: public must not carry a seed: line (a verify key is never a signing key)"
        ));
    }
    if kind == KeyKind::Private && seed.is_none() {
        return Err(format!(
            "corrupt key file {name}: missing field \"seed\" (a type: private key file must carry its seed — the private file is the signing key's record)"
        ));
    }
    Ok(KeyFile {
        kind,
        fingerprint,
        public,
        seed,
    })
}

/// Render the key file bytes (the documented format; the tests'
/// round-trip helper). `seed = None` = the public-only (verify) key.
pub fn render_key_file(kind: KeyKind, public: &[u8; 32], seed: Option<&[u8; 32]>) -> String {
    let mut text = format!("{KEY_MAGIC}\nversion: 1\n");
    text.push_str(&format!("type: {}\n", if kind == KeyKind::Private { "private" } else { "public" }));
    text.push_str(&format!("fingerprint: {}\n", sha256_hex(public)));
    text.push_str(&format!("public: {}\n", hex(public)));
    if let Some(s) = seed {
        text.push_str(&format!("seed: {}\n", hex(s)));
    }
    text
}

// ---------------------------------------------------------------------------
// The signature envelope (<manifest>.sig — the header-block record)
// ---------------------------------------------------------------------------

/// The parsed signature envelope (the strict shape — every field is
/// checked; a malformed envelope = the named rc=2 refusal at the verb
/// surface / the INVALID-CONTENT class at the audit surface).
#[derive(Clone, Debug)]
pub struct Envelope {
    pub tool_version: String,
    /// The signature date (unix seconds, UTC — the wall clock lives in
    /// the envelope only, never in the manifest).
    pub signed_at: u64,
    /// The manifest file NAME (the basename — the envelope is the
    /// manifest's next-to record).
    pub manifest: String,
    /// The manifest's sha256 as read at sign (lowercase 64-hex).
    pub manifest_sha256: String,
    /// The manifest's size in bytes as read at sign.
    pub manifest_bytes: u64,
    /// The signing key's fingerprint (lowercase 64-hex — the sha256 of
    /// the raw public key).
    pub key_fingerprint: String,
    /// The canonical pin-set string (one line — the components +
    /// version strings as resolved by the pins machinery at sign time).
    pub pin_set: String,
    /// The ed25519 signature over the canonical string (64 bytes).
    pub signature: [u8; 64],
}

impl Envelope {
    /// The canonical string this envelope's signature covers (the
    /// signature input — re-derived from the envelope fields alone +
    /// the manifest's sha256).
    pub fn canonical_string(&self) -> String {
        canonical_string_with_magic(
            CANONICAL_MAGIC,
            &self.manifest_sha256,
            &self.tool_version,
            self.signed_at,
            &self.key_fingerprint,
            &self.pin_set,
        )
    }

    /// The envelope file bytes (the deterministic render — a re-sign
    /// with the same `--date` reproduces these bytes).
    pub fn render(&self) -> String {
        format!(
            "{SIG_MAGIC}\n\
             version: 1\n\
             tool_version: {}\n\
             signed_at: {} (unix seconds, UTC)\n\
             manifest: {}\n\
             manifest_sha256: {}\n\
             manifest_bytes: {}\n\
             key_fingerprint: {}\n\
             pin_set: {}\n\
             signature: {}\n\
             note: the signature covers the canonical string (deterministic — re-sign with the same --date reproduces byte-identical envelope bytes; the tool verifies, it does not mint)\n",
            self.tool_version,
            self.signed_at,
            self.manifest,
            self.manifest_sha256,
            self.manifest_bytes,
            self.key_fingerprint,
            self.pin_set,
            hex(&self.signature)
        )
    }
}

/// The canonical string (the signature input — the pinned v1 shape):
/// the leading `frameprism-reel-sig-v1\n` magic line + the five
/// `key=value` lines in this order, `\n`-joined, NO trailing newline.
/// A future reader re-derives it from the envelope alone + the
/// manifest (the `manifest_sha256` field is the manifest's bytes).
pub fn canonical_string_with_magic(
    magic: &str,
    manifest_sha256: &str,
    tool_version: &str,
    signed_at: u64,
    key_fingerprint: &str,
    pin_set: &str,
) -> String {
    format!(
        "{magic}\n\
         manifest_sha256={manifest_sha256}\n\
         tool_version={tool_version}\n\
         signed_at={signed_at}\n\
         key_fingerprint={key_fingerprint}\n\
         pin_set={pin_set}"
    )
}

/// The canonical string with the current magic (the sign path).
pub fn canonical_string(
    manifest_sha256: &str,
    tool_version: &str,
    signed_at: u64,
    key_fingerprint: &str,
    pin_set: &str,
) -> String {
    canonical_string_with_magic(
        CANONICAL_MAGIC,
        manifest_sha256,
        tool_version,
        signed_at,
        key_fingerprint,
        pin_set,
    )
}

/// Parse the envelope (the strict shape): the magic line, the
/// `version: 1` header, every named field present + well-formed (the
/// 64-hex / 128-hex fields, the numeric fields). Any deviation = a
/// named malformed-envelope error.
pub fn parse_envelope(path: &Path) -> Result<Envelope, String> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("unreadable envelope {path:?}: {e}"))?;
    let mut lines = text.lines().enumerate();
    let (_, magic) = lines
        .next()
        .ok_or_else(|| format!("empty signature envelope {name}"))?;
    if magic != SIG_MAGIC {
        return Err(format!(
            "malformed envelope {name}: the magic line is {magic:?}, want {SIG_MAGIC:?}"
        ));
    }
    let mut version: Option<&str> = None;
    let mut tool_version: Option<&str> = None;
    let mut signed_at: Option<u64> = None;
    let mut manifest: Option<&str> = None;
    let mut manifest_sha256: Option<&str> = None;
    let mut manifest_bytes: Option<u64> = None;
    let mut key_fingerprint: Option<&str> = None;
    let mut pin_set: Option<&str> = None;
    let mut signature: Option<[u8; 64]> = None;
    let mut note_seen = false;
    for (i, line) in lines {
        let lineno = i + 1;
        if line.trim().is_empty() {
            continue;
        }
        let (key, value) = match line.split_once(':') {
            Some(kv) => kv,
            None => {
                return Err(format!(
                    "malformed envelope {name}: line {lineno} is not a field: {line:?}"
                ))
            }
        };
        let key = key.trim();
        let value = value.trim();
        let dup = |seen: bool| {
            if seen {
                Some(format!("malformed envelope {name}: duplicate field {key:?}"))
            } else {
                None
            }
        };
        match key {
            "version" => {
                if let Some(e) = dup(version.is_some()) {
                    return Err(e);
                }
                version = Some(value);
            }
            "tool_version" => {
                if let Some(e) = dup(tool_version.is_some()) {
                    return Err(e);
                }
                tool_version = Some(value);
            }
            "signed_at" => {
                if let Some(e) = dup(signed_at.is_some()) {
                    return Err(e);
                }
                // `signed_at: <epoch> (unix seconds, UTC)` — the epoch
                // field (the same convention as the manifests'
                // `created:` lines).
                let epoch = value.split(' ').next().unwrap_or(value);
                signed_at = Some(
                    epoch
                        .parse::<u64>()
                        .map_err(|_| format!("malformed envelope {name}: bad signed_at field {value:?}"))?,
                );
            }
            "manifest" => {
                if let Some(e) = dup(manifest.is_some()) {
                    return Err(e);
                }
                manifest = Some(value);
            }
            "manifest_sha256" => {
                if let Some(e) = dup(manifest_sha256.is_some()) {
                    return Err(e);
                }
                if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(format!(
                        "malformed envelope {name}: bad manifest_sha256 field {value:?} (want 64 hex digits)"
                    ));
                }
                manifest_sha256 = Some(value);
            }
            "manifest_bytes" => {
                if let Some(e) = dup(manifest_bytes.is_some()) {
                    return Err(e);
                }
                manifest_bytes = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| format!("malformed envelope {name}: bad manifest_bytes field {value:?}"))?,
                );
            }
            "key_fingerprint" => {
                if let Some(e) = dup(key_fingerprint.is_some()) {
                    return Err(e);
                }
                if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(format!(
                        "malformed envelope {name}: bad key_fingerprint field {value:?} (want 64 hex digits)"
                    ));
                }
                key_fingerprint = Some(value);
            }
            "pin_set" => {
                if let Some(e) = dup(pin_set.is_some()) {
                    return Err(e);
                }
                pin_set = Some(value);
            }
            "signature" => {
                if let Some(e) = dup(signature.is_some()) {
                    return Err(e);
                }
                if value.len() != 128 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(format!(
                        "malformed envelope {name}: bad signature field {value:?} (want 128 hex digits)"
                    ));
                }
                let mut sig = [0u8; 64];
                for i in 0..64 {
                    sig[i] = u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap();
                }
                signature = Some(sig);
            }
            "note" => note_seen = true,
            _ => {} // future fields (the header is additive)
        }
    }
    let version = version.ok_or_else(|| format!("malformed envelope {name}: missing field \"version\""))?;
    if version != "1" {
        return Err(format!(
            "malformed envelope {name}: unsupported version {version:?} (want 1)"
        ));
    }
    let _ = note_seen; // the note line is informational (tolerated, not required at parse)
    Ok(Envelope {
        tool_version: tool_version
            .ok_or_else(|| format!("malformed envelope {name}: missing field \"tool_version\""))?
            .to_string(),
        signed_at: signed_at
            .ok_or_else(|| format!("malformed envelope {name}: missing field \"signed_at\""))?,
        manifest: manifest
            .ok_or_else(|| format!("malformed envelope {name}: missing field \"manifest\""))?
            .to_string(),
        manifest_sha256: manifest_sha256
            .ok_or_else(|| format!("malformed envelope {name}: missing field \"manifest_sha256\""))?
            .to_string(),
        manifest_bytes: manifest_bytes
            .ok_or_else(|| format!("malformed envelope {name}: missing field \"manifest_bytes\""))?,
        key_fingerprint: key_fingerprint
            .ok_or_else(|| format!("malformed envelope {name}: missing field \"key_fingerprint\""))?
            .to_string(),
        pin_set: pin_set
            .ok_or_else(|| format!("malformed envelope {name}: missing field \"pin_set\""))?
            .to_string(),
        signature: signature
            .ok_or_else(|| format!("malformed envelope {name}: missing field \"signature\""))?,
    })
}

// ---------------------------------------------------------------------------
// sign / verify (the verbs' core — the CLI wrappers map to ExitCodes)
// ---------------------------------------------------------------------------

/// Sign the manifest (the core — the deterministic part): read the
/// manifest bytes, hash them, build the canonical string over the
/// (manifest sha, tool version, date, key fingerprint, pin set), and
/// sign it with the private key (RFC 8032 — deterministic). Returns
/// the envelope (the caller renders it to disk atomically).
pub fn sign_manifest(
    manifest_bytes: &[u8],
    manifest_name: &str,
    key: &KeyFile,
    date: u64,
    pin_set: &str,
) -> Result<Envelope, String> {
    let sk = key.signing_key()?;
    let msha = sha256_hex(manifest_bytes);
    let tool = env!("CARGO_PKG_VERSION");
    let fp = key.fingerprint_hex();
    let canonical = canonical_string(&msha, tool, date, &fp, pin_set);
    let sig: Signature = sk.sign(canonical.as_bytes());
    Ok(Envelope {
        tool_version: tool.to_string(),
        signed_at: date,
        manifest: manifest_name.to_string(),
        manifest_sha256: msha,
        manifest_bytes: manifest_bytes.len() as u64,
        key_fingerprint: fp,
        pin_set: pin_set.to_string(),
        signature: sig.to_bytes(),
    })
}

/// Write the envelope atomically (tmp + rename;
/// a re-sign OVERWRITES, with the same `--date` the bytes
/// are identical). Returns the final path.
pub fn write_envelope(env: &Envelope, out: &Path) -> std::io::Result<PathBuf> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let name = out
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = out.with_file_name(format!(".{name}.tmp"));
    std::fs::write(&tmp, env.render())?;
    std::fs::rename(&tmp, out)?;
    Ok(out.to_path_buf())
}

/// One verify finding (the rc=1 class — the documented offender).
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyFinding {
    /// `VERIFY OK (the signature is valid — key fingerprint <fp>; the
    /// archive was produced by frameprism <tool_version> on <date> with
    /// the recorded pin set)`.
    Ok {
        fingerprint: String,
        tool_version: String,
        date: u64,
    },
    /// `VERIFY FAIL: manifest mismatch (the manifest on disk does not
    /// match the signed manifest_sha256 — the content is NOT the
    /// signed content)`.
    ManifestMismatch,
    /// `VERIFY FAIL: signature invalid (the signature does not verify
    /// against the presented key — the provenance claim does not
    /// hold)`.
    SignatureInvalid,
    /// `VERIFY FAIL: key fingerprint mismatch (the envelope names key
    /// <fp1>; the presented key is <fp2> — the signature was made by a
    /// different key)`.
    FingerprintMismatch {
        envelope_fp: String,
        key_fp: String,
    },
}

/// The verify re-derivation (the core): (1) re-hash the on-disk
/// manifest (the intactness claim — the same sha256 the sidecars use)
/// and compare to the envelope's `manifest_sha256`; (2) check the
/// envelope's `key_fingerprint` against the presented key file's
/// fingerprint (the different-key attack is NAMED before the
/// signature check — verifying a signature against a key the
/// envelope does not name is meaningless); (3) re-derive the
/// canonical string from the envelope fields and verify the ed25519
/// signature against the key's public key (the provenance claim —
/// O(1) in the manifest). `Err` = the rc=2 class (the missing
/// manifest / the missing or corrupt envelope).
pub fn verify_manifest(manifest: &Path, key: &KeyFile, sig: &Path) -> Result<VerifyFinding, String> {
    let env = match parse_envelope(sig) {
        Ok(e) => e,
        Err(e) => {
            return Err(format!("corrupt envelope {}: {e}", sig.display()));
        }
    };
    let bytes = std::fs::read(manifest)
        .map_err(|e| format!("the manifest is not found: {} ({e})", manifest.display()))?;
    // (1) the content claim (the manifest's bytes on disk vs the
    // signed sha256 — O(n), the intactness check).
    let disk = sha256_hex(&bytes);
    if disk != env.manifest_sha256 {
        return Ok(VerifyFinding::ManifestMismatch);
    }
    // (2) the key-identity check (envelope vs the presented key — a
    // signature from a DIFFERENT key than the one presented is a
    // named finding).
    let key_fp = key.fingerprint_hex();
    if env.key_fingerprint != key_fp {
        return Ok(VerifyFinding::FingerprintMismatch {
            envelope_fp: env.key_fingerprint.clone(),
            key_fp,
        });
    }
    // (3) the provenance claim (the ed25519 signature over the
    // re-derived canonical string — O(1) in the manifest).
    let canonical = env.canonical_string();
    match key.verifying_key().verify(canonical.as_bytes(), &Signature::from_bytes(&env.signature)) {
        Ok(()) => Ok(VerifyFinding::Ok {
            fingerprint: env.key_fingerprint,
            tool_version: env.tool_version,
            date: env.signed_at,
        }),
        Err(_) => Ok(VerifyFinding::SignatureInvalid),
    }
}

/// The verify finding's named line (the stdout verdict — the exact
/// v1 shapes, unit-tested verbatim).
pub fn verify_line(f: &VerifyFinding) -> String {
    match f {
        VerifyFinding::Ok {
            fingerprint,
            tool_version,
            date,
        } => format!(
            "VERIFY OK (the signature is valid — key fingerprint {fingerprint}; the archive was produced by frameprism {tool_version} on {date} with the recorded pin set)"
        ),
        VerifyFinding::ManifestMismatch => {
            "VERIFY FAIL: manifest mismatch (the manifest on disk does not match the signed manifest_sha256 — the content is NOT the signed content)".into()
        }
        VerifyFinding::SignatureInvalid => {
            "VERIFY FAIL: signature invalid (the signature does not verify against the presented key — the provenance claim does not hold)".into()
        }
        VerifyFinding::FingerprintMismatch {
            envelope_fp,
            key_fp,
        } => format!(
            "VERIFY FAIL: key fingerprint mismatch (the envelope names key {envelope_fp}; the presented key is {key_fp} — the signature was made by a different key)"
        ),
    }
}

// ---------------------------------------------------------------------------
// The sealing checks (-G4 — the sealed-tier .sig ride)
// ---------------------------------------------------------------------------
//
// `bake --iso --reel-out <dir>` stages the SIGNED working-tier reel
// manifest + its `.sig` as the `provenance/` bundle at the ISO image
// root. The bundle's checks are KEYLESS (the signature itself is the
// reader's `verify` surface — the key is never a bake input):
// the envelope well-formedness, the manifest-sha binding, and the
// content-row binding below. The pure predicates live here (unit-
// tested); the file presence + the orchestration + the named rc=2
// refusal wording live in `crate::bake` (the sealing site).

/// The manifest-sha binding (the -G4 seal gate's check 4): the
/// envelope's `manifest_sha256` field equals the sha256 of the
/// presented manifest bytes. A mismatch = the envelope does not bind
/// the presented manifest — a broken provenance claim.
pub fn envelope_binds_manifest(env: &Envelope, manifest_bytes: &[u8]) -> bool {
    sha256_hex(manifest_bytes) == env.manifest_sha256
}

/// The content-row binding (the -G4 seal gate's check 5 — the
/// reel-A-into-reel-B attack): two PARSED reel manifests attest the
/// SAME content iff every parsed field matches EXCEPT the
/// epoch-derived free variables — exactly two (the recorded decision
/// — the approved widening of the original "modulo the
/// created: line" spec, which was factually insufficient):
/// (1) the `created:` epoch line (the working tier renders the wall
/// clock, the ISO re-renders the pinned epoch) and (2) each row's
/// `manifest_sha` column (the per-clip manifest's sha256 — a pure
/// function of (per-clip content rows + the per-clip manifest's own
/// `created:` line), so it varies with the epoch by construction).
/// The content rows remain bound by clip / codec / archive /
/// archive_sha256 / manifest-name / frames — a signature for a
/// different reel's manifest is refused the seal. Safety argument:
/// the excluded column is a pure function of the
/// per-clip content rows + the per-clip epoch line; the per-clip
/// content rows are a pure function of the archive content; the
/// archive content is bound by `archive_sha256` (+`frames`) — so
/// excluding `manifest_sha` loses no binding the reel row does not
/// already carry; the reader's `verify` still binds the bundle
/// manifest byte-for-byte.
pub fn content_rows_identical(a: &crate::reel::ReelManifest, b: &crate::reel::ReelManifest) -> bool {
    // Every parsed field is bound except the two free variables above:
    // `created` (excluded per row's manifest — the header epoch line)
    // and `rows[i].manifest_sha` (excluded — the epoch-derived column).
    a.name == b.name
        && a.version == b.version
        && a.tool_version == b.tool_version
        && a.clips == b.clips
        && a.frames == b.frames
        && a.rows.len() == b.rows.len()
        && a.rows.iter().zip(b.rows.iter()).all(|(x, y)| {
            x.clip == y.clip
                && x.codec == y.codec
                && x.archives == y.archives
                && x.archive_shas == y.archive_shas
                && x.manifest == y.manifest
                && x.frames == y.frames
        })
}

/// The audit's keyless signature line (the CONTENT CLAIM — the
/// envelope well-formedness + the manifest `manifest_sha256` re-hash;
/// the signature itself is `frameprism verify --key <pubkey>`'s
/// surface). Returns (the named line, bad): `bad = true` is the
/// INVALID-CONTENT class (the audit's rc=1 offender — a broken
/// provenance claim is worse than its absence — the envelope lies).
/// The ABSENT line is the universal honesty line (every audit names
/// the reel manifest's signature state — the signature is OPTIONAL for
/// the audit PASS; pre-signing archives stay valid).
pub fn audit_signature_line(reel_manifest: &Path) -> (String, bool) {
    let name = reel_manifest
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let sig_path = sig_path_of(reel_manifest);
    if !sig_path.is_file() {
        return (
            format!(
                "audit: signature ABSENT ({name} carries no .sig — the archive predates signing or was never signed; the archive audit is unaffected)"
            ),
            false,
        );
    }
    let env = match parse_envelope(&sig_path) {
        Ok(e) => e,
        Err(e) => {
            return (
                format!(
                    "audit: signature INVALID-CONTENT ({name}.sig — malformed envelope: {e})"
                ),
                true,
            );
        }
    };
    match std::fs::read(reel_manifest) {
        Err(e) => (
            format!(
                "audit: signature INVALID-CONTENT ({name}.sig — manifest mismatch: the on-disk reel manifest is unreadable ({e}) — the signed content is not the sealed content)"
            ),
            true,
        ),
        Ok(bytes) => {
            let disk = sha256_hex(&bytes);
            if disk != env.manifest_sha256 {
                (
                    format!(
                        "audit: signature INVALID-CONTENT ({name}.sig — manifest mismatch: the manifest on disk does not match the signed manifest_sha256 — the content is NOT the signed content)"
                    ),
                    true,
                )
            } else {
                (
                    format!(
                        "audit: signature VALID-CONTENT ({name}.sig — envelope well-formed + the manifest matches the signed sha256; the signature itself is verified by frameprism verify --key <pubkey>)"
                    ),
                    false,
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The CLI surface (the verbs' rc conventions: finding rc=1, refusal
// rc=2)
// ---------------------------------------------------------------------------

/// The `frameprism sign` CLI arguments.
#[derive(ClapArgs, Debug)]
pub struct SignArgs {
    /// The reel manifest to sign (the bake's
    /// reel.reel-manifest.tsv — or any manifest path the bake
    /// produced). The manifest bytes are NEVER touched: the signature
    /// is a NEW file <manifest>.sig (the header-block envelope — the
    /// manifest sha256 + the key fingerprint + the tool version + the
    /// pin set + the date + the ed25519 signature over the canonical
    /// string).
    pub manifest: PathBuf,

    /// The key file (type: private REQUIRED — the tool verifies, it
    /// does not mint; key generation is the documented external
    /// openssl recipe, not a tool subcommand). A corrupt key file or a
    /// type: public key = the named rc=2 refusal (zero partial
    /// operations).
    #[arg(long)]
    pub key: PathBuf,

    /// The signature date (unix seconds, UTC; default: now). The wall
    /// clock lives in the envelope ONLY (never in the manifest) —
    /// re-sign with the same --date = byte-identical .sig (the ed25519
    /// RFC 8032 determinism).
    #[arg(long)]
    pub date: Option<u64>,

    /// The .sig output path (default: <manifest path>.sig). A
    /// re-sign overwrites atomically (tmp + rename).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// Run `frameprism sign` (the rc convention: rc=0 signed, rc=2 the named
/// refusal — the manifest/key/pins re-derivations fail BEFORE the
/// envelope is written, so a refusal leaves zero partial files).
pub fn run_sign(args: &SignArgs) -> ExitCode {
    // The key (the records-class refusal — the tool verifies, it does
    // not mint).
    let key = match parse_key_file(&args.key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: sign: {e}");
            return ExitCode::from(2);
        }
    };
    if key.kind != KeyKind::Private {
        eprintln!(
            "error: sign: the key file {} is type: public — sign requires type: private (the tool verifies, it does not mint — a verify key is never a signing key by accident)",
            args.key.display()
        );
        return ExitCode::from(2);
    }
    // The manifest (the sign input — read-only, never touched).
    let bytes = match std::fs::read(&args.manifest) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "error: sign: the manifest is not found: {} ({e}) — run the bake first (the reel manifest is the signing target)",
                args.manifest.display()
            );
            return ExitCode::from(2);
        }
    };
    // The pin set (the envelope's provenance binding — the components
    // + version strings as resolved by the existing pins machinery,
    // the same source ci/check-pins.sh asserts; not found = the named
    // records-class refusal — the pin set is the envelope's content).
    let pin_set = match crate::pins::resolved_pin_set(None) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "error: sign: the pin set cannot be resolved: {e} — the pin set is the envelope's provenance binding (the resolution: the FRAMEPRISM_PINS env, <cwd>/ci/pins.tsv, <exe_dir>/../ci/pins.tsv)"
            );
            return ExitCode::from(2);
        }
    };
    let date = args
        .date
        .unwrap_or_else(crate::ledger::now_secs);
    let manifest_name = args
        .manifest
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let env = match sign_manifest(&bytes, &manifest_name, &key, date, &pin_set) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: sign: {e}");
            return ExitCode::from(2);
        }
    };
    let out = args
        .out
        .clone()
        .unwrap_or_else(|| sig_path_of(&args.manifest));
    if let Err(e) = write_envelope(&env, &out) {
        eprintln!(
            "error: sign: cannot write the envelope {}: {e}",
            out.display()
        );
        return ExitCode::from(2);
    }
    println!(
        "sign: {} (manifest {} {} B; key fingerprint {}; date {})",
        out.display(),
        manifest_name,
        env.manifest_bytes,
        env.key_fingerprint,
        env.signed_at
    );
    ExitCode::SUCCESS
}

/// The `frameprism verify` CLI arguments.
#[derive(ClapArgs, Debug)]
pub struct VerifyArgs {
    /// The reel manifest whose .sig is verified (the same manifest
    /// path the sign ran over).
    pub manifest: PathBuf,

    /// The key file (type: public OR private — the verify uses the
    /// public: field; a private key file may verify its own
    /// signatures). A corrupt key file = the named rc=2 refusal.
    #[arg(long)]
    pub key: PathBuf,

    /// The .sig path (default: <manifest path>.sig). A missing .sig =
    /// the named rc=2 usage refusal (distinct from the audit's ABSENT
    /// honesty line — the audit names it, the verb refuses it).
    #[arg(long)]
    pub sig: Option<PathBuf>,
}

/// Run `frameprism verify` (the rc convention: rc=0 the signature is
/// valid; rc=1 a signature FINDING (the documented offender class —
/// the mismatch/invalid lines); rc=2 a malformed REFUSAL (the missing
/// manifest / the missing or corrupt envelope / the corrupt key —
/// zero partial verdicts)).
pub fn run_verify(args: &VerifyArgs) -> ExitCode {
    let key = match parse_key_file(&args.key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: verify: {e}");
            return ExitCode::from(2);
        }
    };
    let sig = args
        .sig
        .clone()
        .unwrap_or_else(|| sig_path_of(&args.manifest));
    if !sig.is_file() {
        eprintln!(
            "error: verify: the signature envelope is absent: {} (the archive was never signed — run frameprism sign {} --key <private key file>; the audit's ABSENT line is the honesty surface, this verb's missing-.sig is the usage refusal)",
            sig.display(),
            args.manifest.display()
        );
        return ExitCode::from(2);
    }
    match verify_manifest(&args.manifest, &key, &sig) {
        Ok(f) => {
            println!("{}", verify_line(&f));
            match f {
                VerifyFinding::Ok { .. } => ExitCode::SUCCESS,
                _ => ExitCode::from(1),
            }
        }
        Err(e) => {
            eprintln!("error: verify: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed test seed (hardcoded — the deterministic sign/verify
    /// fixtures; NOT key material for production, a test constant).
    const TEST_SEED: [u8; 32] = [
        0xa1, 0x5c, 0x3e, 0x77, 0x02, 0x9b, 0xd4, 0x48, 0xf6, 0x1e, 0xab, 0xc0, 0x39, 0x5d,
        0xe2, 0x8a, 0x44, 0x71, 0xbf, 0x23, 0x06, 0xd9, 0x58, 0xc7, 0x1f, 0x8e, 0xa3, 0x65,
        0x0b, 0xf2, 0x4d, 0x97,
    ];
    const TEST_DATE: u64 = 1_790_000_000;
    const PIN_SET: &str = "cjxl=v0.12.0 1cad73c; djxl=v0.12.0 1cad73c; tar=bsdtar 3.5.3; tool=0.6.0; xorriso=1.5.8.pl02; zstd=1.5.7";

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("frameprism-provenance-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn private_key() -> KeyFile {
        let public = public_from_seed(&TEST_SEED);
        KeyFile {
            kind: KeyKind::Private,
            fingerprint: crate::jxl::sha256(&public),
            public,
            seed: Some(TEST_SEED),
        }
    }

    fn second_key() -> KeyFile {
        let seed: [u8; 32] = [0x5b; 32];
        let public = public_from_seed(&seed);
        KeyFile {
            kind: KeyKind::Private,
            fingerprint: crate::jxl::sha256(&public),
            public,
            seed: Some(seed),
        }
    }

    fn write_manifest(d: &Path) -> PathBuf {
        let p = d.join("reel.reel-manifest.tsv");
        std::fs::write(
            &p,
            "# frameprism reel manifest\nversion: 1\ncreated: 1790000000 (unix seconds, UTC)\ntool_version: 0.6.0\nclips: 2\nframes: 174\nclip\tcodec\tarchive\tarchive_sha256\tmanifest\tmanifest_sha256\tframes\nA001_005\tj92\tA001_005.tar.zst\t0000000000000000000000000000000000000000000000000000000000000000\tA001_005.bake-manifest.tsv\t0000000000000000000000000000000000000000000000000000000000000000\t94\nA001_007\tj92\tA001_007.tar.zst\t0000000000000000000000000000000000000000000000000000000000000000\tA001_007.bake-manifest.tsv\t0000000000000000000000000000000000000000000000000000000000000000\t80\n",
        )
        .unwrap();
        p
    }

    fn sign_fixtures(d: &Path, key: &KeyFile, date: u64) -> (PathBuf, PathBuf) {
        let m = write_manifest(d);
        let bytes = std::fs::read(&m).unwrap();
        let env = sign_manifest(&bytes, "reel.reel-manifest.tsv", key, date, PIN_SET).unwrap();
        let sig = d.join("reel.reel-manifest.tsv.sig");
        write_envelope(&env, &sig).unwrap();
        (m, sig)
    }

    // -- the key file (the round-trip + the corrupt classes) ------------

    #[test]
    fn key_file_roundtrip_private_public() {
        let d = tmp("key-rt");
        let k = private_key();
        for (kind, seed, p) in [
            (KeyKind::Private, Some(TEST_SEED), d.join("private.key")),
            (KeyKind::Public, None, d.join("public.key")),
        ] {
            let text = render_key_file(kind, &k.public, seed.as_ref());
            std::fs::write(&p, text).unwrap();
            let parsed = parse_key_file(&p).unwrap();
            assert_eq!(parsed.kind, kind, "{p:?}");
            assert_eq!(parsed.public, k.public);
            assert_eq!(parsed.seed, seed);
            // The fingerprint = the sha256 of the raw public key (the
            // parse enforces it — the identity check).
            assert_eq!(parsed.fingerprint_hex(), sha256_hex(&k.public));
        }
        // A private key file may verify its own signatures (the
        // verify uses the public: field — both classes).
        let (m, s) = sign_fixtures(&d, &k, TEST_DATE);
        let priv_parsed = parse_key_file(&d.join("private.key")).unwrap();
        let pub_parsed = parse_key_file(&d.join("public.key")).unwrap();
        for parsed in [priv_parsed, pub_parsed] {
            assert_eq!(
                verify_manifest(&m, &parsed, &s).unwrap(),
                VerifyFinding::Ok {
                    fingerprint: k.fingerprint_hex(),
                    tool_version: env!("CARGO_PKG_VERSION").into(),
                    date: TEST_DATE,
                }
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The openssl ed25519 capability probe (the G0 environment fix,
    /// — the named exception to the "no existing test
    /// modified" rule): runs the REAL keygen operation and classifies
    /// the environment. Ok(der) = the openssl supports ed25519 keygen
    /// (the PKCS8 DER on stdout — the DER-tail cross-check proceeds);
    /// Err(excerpt) = the operation failed (e.g. Apple's LibreSSL
    /// 3.3.6 — `genpkey -algorithm ed25519` → "Algorithm ed25519 not
    /// found", rc=1 — the ci fresh-shell PATH resolves /usr/bin/openssl;
    /// or the openssl is absent from PATH) → the caller prints the
    /// named SKIP line and the test passes (the established
    /// corpus-dependent-test pattern — no #[ignore], no
    /// environment-dependent count).
    fn openssl_ed25519_probe(bin: &str) -> std::result::Result<Vec<u8>, String> {
        match std::process::Command::new(bin)
            .args(["genpkey", "-algorithm", "ed25519", "-outform", "DER"])
            .output()
        {
            Ok(o) if o.status.success() => Ok(o.stdout),
            Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
            Err(e) => Err(format!(
                "openssl is not runnable in this environment ({e})"
            )),
        }
    }

    #[test]
    fn openssl_probe_classifies_the_failed_operation() {
        // The helper's CLASSIFICATION, not the environment: a fake
        // openssl that fails with the LibreSSL-class stderr → Err with
        // the stderr excerpt; a fake that succeeds (a >32-byte DER on
        // stdout) → Ok(der).
        let d = tmp("probe-classify");
        let der_file = d.join("der48");
        std::fs::write(&der_file, std::iter::repeat(0x42u8).take(48).collect::<Vec<u8>>())
            .unwrap();
        let failing = d.join("openssl-fail");
        std::fs::write(
            &failing,
            "#!/bin/sh\necho 'Algorithm ed25519 not found' >&2\nexit 1\n",
        )
        .unwrap();
        let succeeding = d.join("openssl-ok");
        std::fs::write(
            &succeeding,
            format!("#!/bin/sh\ncat {}\n", der_file.display()),
        )
        .unwrap();
        for bin in [&failing, &succeeding] {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(bin).unwrap().permissions();
            p.set_mode(0o755);
            std::fs::set_permissions(bin, p).unwrap();
        }
        let r = openssl_ed25519_probe(failing.to_str().unwrap());
        match r {
            Ok(_) => panic!("a failed probe operation must classify as the skip case"),
            Err(excerpt) => assert!(
                excerpt.contains("not found"),
                "the stderr excerpt must carry the failure: {excerpt}"
            ),
        }
        let r = openssl_ed25519_probe(succeeding.to_str().unwrap());
        match r {
            Ok(der) => assert_eq!(der.len(), 48, "the successful probe returns the DER"),
            Err(e) => panic!("a successful probe must classify as Ok: {e}"),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn key_file_fingerprint_is_sha256_of_raw_public() {
        // The fingerprint field = the in-tree sha256 of the 32-byte
        // raw public key (the independent-of-the-tool cross-check is
        // the G5 gate — the openssl recipe's own sha256).
        let public = public_from_seed(&TEST_SEED);
        assert_eq!(sha256_hex(&public), hex(&private_key().fingerprint));
        // The keygen recipe's DER-tail cross-check (the documented
        // external path — the PKCS8 tail 32 bytes = the seed, the
        // SPKI tail 32 bytes = the raw public key). The probe gates
        // the cross-check on the environment's openssl capability:
        // an openssl without ed25519 keygen (e.g. Apple's LibreSSL
        // 3.3.6 — the ci fresh-shell PATH resolves /usr/bin/openssl)
        // is the named graceful skip (the established
        // corpus-dependent-test pattern — no #[ignore], no
        // environment-dependent count).
        match openssl_ed25519_probe("openssl") {
            Ok(der) => {
                assert!(der.len() > 32, "the PKCS8 DER is shorter than the 32-byte seed");
                let seed_vec = der[der.len() - 32..].to_vec();
                let seed: [u8; 32] = seed_vec.try_into().unwrap();
                let mut c = std::process::Command::new("openssl")
                    .args(["pkey", "-pubout", "-outform", "DER"])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .expect("spawn openssl pkey");
                {
                    use std::io::Write;
                    c.stdin.take().unwrap().write_all(&der).unwrap();
                }
                let pubout = c.wait_with_output().unwrap();
                assert!(
                    pubout.status.success(),
                    "openssl pkey failed: {}",
                    String::from_utf8_lossy(&pubout.stderr)
                );
                let spki = &pubout.stdout;
                assert!(
                    spki.len() > 32,
                    "the SPKI DER is shorter than the 32-byte public key"
                );
                let raw_public = spki[spki.len() - 32..].to_vec();
                let derived = public_from_seed(&seed);
                assert_eq!(
                    &raw_public[..],
                    &derived[..],
                    "the SPKI tail != the seed-derived public key"
                );
            }
            Err(excerpt) => {
                eprintln!(
                    "SKIP provenance key-fingerprint cross-check: the environment's openssl lacks ed25519 ({excerpt}); cross-check requires OpenSSL 1.1.1+ — the test skips gracefully (the established corpus-dependent-test pattern)"
                );
            }
        }
    }

    /// A parsed 2-clip reel manifest fixture with a controlled
    /// `created` epoch + the A001_007 row's frame count + the
    /// A001_007 row's archive sha (the -G4 seal-gate fixtures —
    /// the content-row binding's test shapes; the per-row
    /// `manifest_sha` columns are the fixed 0x00/0x11 digests unless
    /// a case mutates them).
    fn reel_fixture(created: u64, a007_frames: u64, a007_archive_sha: &str) -> crate::reel::ReelManifest {
        let z0: String = std::iter::repeat('0').take(64).collect();
        let z1: String = std::iter::repeat('1').take(64).collect();
        crate::reel::ReelManifest {
            name: "reel.reel-manifest.tsv".into(),
            version: "1".into(),
            created,
            tool_version: "0.6.0".into(),
            clips: Some(2),
            frames: Some(94 + a007_frames),
            rows: vec![
                crate::reel::ReelRow {
                    clip: "A001_005".into(),
                    codec: "j92".into(),
                    archives: vec!["A001_005.tar.zst".into()],
                    archive_shas: vec![z1.clone()],
                    manifest: "A001_005.bake-manifest.tsv".into(),
                    manifest_sha: z0.clone(),
                    frames: 94,
                },
                crate::reel::ReelRow {
                    clip: "A001_007".into(),
                    codec: "j92".into(),
                    archives: vec!["A001_007.tar.zst".into()],
                    archive_shas: vec![a007_archive_sha.into()],
                    manifest: "A001_007.bake-manifest.tsv".into(),
                    manifest_sha: z0,
                    frames: a007_frames,
                },
            ],
        }
    }

    #[test]
    fn content_rows_identical_classes() {
        let z1: String = std::iter::repeat('1').take(64).collect();
        let z2: String = std::iter::repeat('2').take(64).collect();
        // (a) the LEGITIMATE case (the working-tier vs the staged
        // pinned-epoch renders): differs ONLY in `created` + the
        // per-row `manifest_sha` (the two epoch-derived free
        // variables) → PASSES.
        let working = reel_fixture(1_790_000_000, 80, &z1);
        let pinned = {
            let mut m = reel_fixture(1_789_344_000, 80, &z1);
            m.rows[0].manifest_sha = z2.clone();
            m.rows[1].manifest_sha = z2.clone();
            m
        };
        assert!(
            content_rows_identical(&working, &pinned),
            "the created-line + per-row manifest_sha difference (the epoch-derived free variables) must pass"
        );
        // A single-row manifest_sha-only difference still passes (the
        // excluded column is the ONLY difference).
        let sha_only = {
            let mut m = pinned.clone();
            m.rows[0].manifest_sha = z1.clone();
            m
        };
        assert!(
            content_rows_identical(&pinned, &sha_only),
            "a manifest_sha-only difference must pass (the excluded column)"
        );
        // Identical parses pass trivially.
        assert!(content_rows_identical(&pinned, &pinned));
        // (b) frames differ → refuses (a different reel state — the
        // doctored/1-frame-prefix class).
        let other_frames = reel_fixture(1_789_344_000, 10, &z1);
        assert!(
            !content_rows_identical(&pinned, &other_frames),
            "a differing frames field must refuse (a signature for a different reel)"
        );
        // (c) archive_sha256 differs (the reel-A/reel-B core) → refuses.
        let other_archive = {
            let mut m = reel_fixture(1_789_344_000, 80, &z1);
            m.rows[1].archive_shas = vec![z2.clone()];
            m
        };
        assert!(
            !content_rows_identical(&pinned, &other_archive),
            "a differing archive_sha256 must refuse (the reel-A-into-reel-B core)"
        );
        // (d) clip differs → refuses.
        let other_clip = {
            let mut m = reel_fixture(1_789_344_000, 80, &z1);
            m.rows[1].clip = "B001_007".into();
            m
        };
        assert!(
            !content_rows_identical(&pinned, &other_clip),
            "a differing clip must refuse (a signature for a different reel)"
        );
        // A differing row COUNT refuses (the row-length gate).
        let one_row = {
            let mut m = pinned.clone();
            m.rows.truncate(1);
            m.clips = Some(1);
            m
        };
        let two_rows = pinned.clone();
        assert!(
            !content_rows_identical(&one_row, &two_rows),
            "a differing row count must refuse"
        );
    }

    #[test]
    fn envelope_binds_manifest_classes() {
        let bytes = b"the manifest bytes";
        let sha = sha256_hex(bytes);
        let env = Envelope {
            tool_version: "0.6.0".into(),
            signed_at: TEST_DATE,
            manifest: "reel.reel-manifest.tsv".into(),
            manifest_sha256: sha.clone(),
            manifest_bytes: bytes.len() as u64,
            key_fingerprint: hex(&crate::jxl::sha256(&public_from_seed(&TEST_SEED))),
            pin_set: PIN_SET.into(),
            signature: [0u8; 64],
        };
        assert!(
            envelope_binds_manifest(&env, bytes),
            "a matching manifest_sha256 binds the presented manifest"
        );
        assert!(
            !envelope_binds_manifest(&env, b"tampered manifest bytes"),
            "a mismatched manifest_sha256 does not bind (the envelope is for other bytes)"
        );
    }

    #[test]
    fn key_file_corrupt_classes() {
        let d = tmp("key-corrupt");
        let k = private_key();
        let base = render_key_file(KeyKind::Private, &k.public, Some(&TEST_SEED));
        // Bad magic.
        let p = d.join("bad-magic.key");
        std::fs::write(&p, base.replace(KEY_MAGIC, "# nope")).unwrap();
        assert!(parse_key_file(&p).unwrap_err().contains("magic line"));
        // Bad hex (a 63-char fingerprint).
        let p = d.join("bad-hex.key");
        std::fs::write(
            &p,
            base.replace(&format!("fingerprint: {}", k.fingerprint_hex()), "fingerprint: abc"),
        )
        .unwrap();
        assert!(parse_key_file(&p).unwrap_err().contains("bad hex"));
        // Missing seed (a private file without it = the missing-field
        // class; the sign refusal is the public-only class below).
        let p = d.join("missing-seed.key");
        let mut lines: Vec<&str> =
            base.lines().filter(|l| !l.starts_with("seed:")).collect();
        let mut text = lines.join("\n");
        text.push('\n');
        std::fs::write(&p, text).unwrap();
        assert!(parse_key_file(&p).unwrap_err().contains("missing field"));
        // Public with a seed line = the named corrupt class.
        let p = d.join("public-seed.key");
        std::fs::write(
            &p,
            base.replace("type: private", "type: public"),
        )
        .unwrap();
        assert!(parse_key_file(&p)
            .unwrap_err()
            .contains("must not carry a seed"));
        // A fingerprint that lies (flip one hex digit of the field).
        let p = d.join("lying-fp.key");
        let fp = k.fingerprint_hex();
        let mut flipped = fp.clone();
        let i = if flipped.starts_with('0') { 1 } else { 0 };
        flipped.replace_range(
            i..i + 1,
            if flipped.as_bytes()[i] == b'0' { "1" } else { "0" },
        );
        std::fs::write(&p, base.replace(&format!("fingerprint: {fp}"), &format!("fingerprint: {flipped}"))).unwrap();
        assert!(parse_key_file(&p)
            .unwrap_err()
            .contains("does not equal the sha256 of the raw public key"));
        // A duplicate field.
        let p = d.join("dup.key");
        std::fs::write(&p, format!("{base}public: {}\n", hex(&k.public))).unwrap();
        assert!(parse_key_file(&p).unwrap_err().contains("duplicate field"));
        // An unsupported version.
        let p = d.join("v2.key");
        std::fs::write(&p, base.replace("version: 1", "version: 2")).unwrap();
        assert!(parse_key_file(&p).unwrap_err().contains("unsupported version"));
        let _ = std::fs::remove_dir_all(&d);
    }

    // -- the canonical string (the exact bytes) --------------------------

    #[test]
    fn canonical_string_exact_bytes() {
        // The hand-computed fixture (the pinned v1 shape — a future
        // reader re-derives it from the envelope alone + the
        // manifest): the magic line + the five key=value lines in
        // order, \n-joined, NO trailing newline.
        let s = canonical_string(
            "aa".repeat(32).as_str(),
            "0.6.0",
            1_790_000_000,
            &"bb".repeat(32),
            PIN_SET,
        );
        let want = format!(
            "frameprism-reel-sig-v1\n\
             manifest_sha256={}\n\
             tool_version=0.6.0\n\
             signed_at=1790000000\n\
             key_fingerprint={}\n\
             pin_set={PIN_SET}",
            "aa".repeat(32),
            "bb".repeat(32)
        );
        assert_eq!(s, want);
        assert!(!s.ends_with('\n'), "no trailing newline (the \n-join)");
        assert_eq!(s.lines().count(), 6);
    }

    // -- the sign/verify round-trip + the determinism ---------------------

    #[test]
    fn sign_verify_roundtrip_deterministic() {
        let d = tmp("roundtrip");
        let k = private_key();
        let (m, s) = sign_fixtures(&d, &k, TEST_DATE);
        let parsed = parse_key_file(&d.join("k.key")).unwrap_or_else(|_| {
            std::fs::write(d.join("k.key"), render_key_file(KeyKind::Private, &k.public, Some(&TEST_SEED))).unwrap();
            parse_key_file(&d.join("k.key")).unwrap()
        });
        let f = verify_manifest(&m, &parsed, &s).unwrap();
        assert!(
            matches!(f, VerifyFinding::Ok { .. }),
            "{f:?} (line: {})",
            verify_line(&f)
        );
        // The determinism: a re-sign with the same date = byte-
        // identical envelope bytes (the RFC 8032 determinism).
        let sig2 = d.join("reel.reel-manifest.tsv.sig2");
        let bytes = std::fs::read(&m).unwrap();
        let env2 = sign_manifest(&bytes, "reel.reel-manifest.tsv", &k, TEST_DATE, PIN_SET).unwrap();
        write_envelope(&env2, &sig2).unwrap();
        assert_eq!(
            std::fs::read(&s).unwrap(),
            std::fs::read(&sig2).unwrap(),
            "same date => byte-identical .sig"
        );
        // A different date: only the signed_at + signature lines
        // differ (the date is in the canonical string).
        let sig3 = d.join("reel.reel-manifest.tsv.sig3");
        let env3 = sign_manifest(&bytes, "reel.reel-manifest.tsv", &k, TEST_DATE + 1, PIN_SET)
            .unwrap();
        write_envelope(&env3, &sig3).unwrap();
        let t1 = std::fs::read_to_string(&s).unwrap();
        let t3 = std::fs::read_to_string(&sig3).unwrap();
        let l1: Vec<&str> = t1.lines().collect();
        let l3: Vec<&str> = t3.lines().collect();
        assert_eq!(l1.len(), l3.len());
        let diffs: Vec<usize> = l1
            .iter()
            .zip(&l3)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        // The signed_at line + the signature line (nothing else).
        assert_eq!(diffs.len(), 2, "{l1:?} vs {l3:?}");
        assert!(l1[diffs[0]].starts_with("signed_at: "), "{l1:?}");
        assert!(l1[diffs[1]].starts_with("signature: "), "{l1:?}");
        // The re-verify of the second envelope holds (rc=0 class).
        const TEST_DATE_2: u64 = TEST_DATE + 1;
        let f3 = verify_manifest(&m, &parsed, &sig3).unwrap();
        assert!(matches!(f3, VerifyFinding::Ok { date: TEST_DATE_2, .. }), "{f3:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    // -- the verify findings (the named lines — the G3 classes) ----------

    #[test]
    fn verify_finding_classes() {
        let d = tmp("findings");
        let k = private_key();
        let k2 = second_key();
        // (b) the manifest tamper (a 1-byte flip AFTER the sign) =
        // the manifest-mismatch finding.
        let (m, s) = sign_fixtures(&d, &k, TEST_DATE);
        let mut bytes = std::fs::read(&m).unwrap();
        bytes[0] ^= 0x01;
        std::fs::write(&m, &bytes).unwrap();
        let f = verify_manifest(&m, &k, &s).unwrap();
        assert_eq!(f, VerifyFinding::ManifestMismatch);
        assert_eq!(
            verify_line(&f),
            "VERIFY FAIL: manifest mismatch (the manifest on disk does not match the signed manifest_sha256 — the content is NOT the signed content)"
        );
        // (c) the tampered signature (a hex flip of the signature
        // field, the presented key = the signing key) = the
        // signature-invalid finding (the pure provenance break — the
        // envelope's key identity is intact). A fresh fixture (the
        // previous block's manifest is still tampered).
        let (m, s) = sign_fixtures(&d, &k, TEST_DATE);
        let env_text = std::fs::read_to_string(&s).unwrap();
        let sig_line = env_text.lines().find(|l| l.starts_with("signature: ")).unwrap();
        let hexbody = sig_line.trim_start_matches("signature: ");
        let mut flipped = hexbody.to_string();
        let i = if flipped.starts_with('0') { 1 } else { 0 };
        flipped.replace_range(i..i + 1, if flipped.as_bytes()[i] == b'0' { "1" } else { "0" });
        let tampered = env_text.replace(hexbody, &flipped);
        std::fs::write(&s, tampered).unwrap();
        let f = verify_manifest(&m, &k, &s).unwrap();
        assert_eq!(f, VerifyFinding::SignatureInvalid);
        assert_eq!(
            verify_line(&f),
            "VERIFY FAIL: signature invalid (the signature does not verify against the presented key — the provenance claim does not hold)"
        );
        // (d) the key-fingerprint attack (sign with key A, present the
        // .sig to verify --key B) = the fingerprint-mismatch finding
        // (the check order: the key identity is named BEFORE the
        // signature check — a verify against a key the envelope does
        // not name is meaningless).
        let (m, s) = sign_fixtures(&d, &k, TEST_DATE);
        let f = verify_manifest(&m, &k2, &s).unwrap();
        assert_eq!(
            f,
            VerifyFinding::FingerprintMismatch {
                envelope_fp: k.fingerprint_hex(),
                key_fp: k2.fingerprint_hex(),
            }
        );
        let line = verify_line(&f);
        assert!(line.starts_with("VERIFY FAIL: key fingerprint mismatch (the envelope names key "), "{line}");
        assert!(line.ends_with("— the signature was made by a different key)"), "{line}");
        // The OK line (the exact shape — the G1 gate's verbatim).
        let f = verify_manifest(&m, &k, &s).unwrap();
        assert_eq!(
            verify_line(&f),
            format!(
                "VERIFY OK (the signature is valid — key fingerprint {}; the archive was produced by frameprism {} on {TEST_DATE} with the recorded pin set)",
                k.fingerprint_hex(),
                env!("CARGO_PKG_VERSION")
            )
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    // -- the rc=2 classes (the refusals) ----------------------------------

    #[test]
    fn refusal_classes() {
        let d = tmp("refusals");
        let k = private_key();
        let (m, s) = sign_fixtures(&d, &k, TEST_DATE);
        // The corrupt envelope (the signature hex truncated — the
        // named malformed-envelope class, rc=2 at the verb surface).
        let env_text = std::fs::read_to_string(&s).unwrap();
        let sig_line = env_text.lines().find(|l| l.starts_with("signature: ")).unwrap();
        let truncated = format!("signature: {}", &sig_line.trim_start_matches("signature: ")[..64]);
        let corrupt = env_text.replacen(sig_line, &truncated, 1);
        let sc = d.join("corrupt.sig");
        std::fs::write(&sc, corrupt).unwrap();
        let e = verify_manifest(&m, &k, &sc).unwrap_err();
        assert!(e.contains("corrupt envelope"), "{e}");
        assert!(e.contains("want 128 hex digits"), "{e}");
        // The missing .sig (the verify usage refusal — distinct from
        // the audit's ABSENT honesty line).
        let missing = d.join("nope.sig");
        let e = verify_manifest(&m, &k, &missing).unwrap_err();
        assert!(e.contains("corrupt envelope"), "{e}");
        // The missing manifest.
        let e = verify_manifest(&d.join("nope.reel-manifest.tsv"), &k, &s).unwrap_err();
        assert!(e.contains("the manifest is not found"), "{e}");
        // The public-only sign (a verify key is never a signing key —
        // the sign refusal; the run_sign wrapper names it).
        let pubk = KeyFile {
            kind: KeyKind::Public,
            fingerprint: k.fingerprint,
            public: k.public,
            seed: None,
        };
        let e = sign_manifest(b"x", "x", &pubk, TEST_DATE, PIN_SET).unwrap_err();
        assert!(e.contains("type: public — a verify key can never sign"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    // -- the audit line (the three classes — the verdict table) ----------

    #[test]
    fn audit_line_classes() {
        let d = tmp("audit-line");
        let k = private_key();
        let (m, s) = sign_fixtures(&d, &k, TEST_DATE);
        // VALID-CONTENT (the content claim holds — the verdict is
        // unaffected: bad = false). The .sig must be next to the
        // manifest (the default sign placement).
        let (line, bad) = audit_signature_line(&m);
        assert!(!bad, "{line}");
        assert_eq!(
            line,
            "audit: signature VALID-CONTENT (reel.reel-manifest.tsv.sig — envelope well-formed + the manifest matches the signed sha256; the signature itself is verified by frameprism verify --key <pubkey>)"
        );
        // INVALID-CONTENT (the manifest tamper — the rc=1 offender
        // class: bad = true).
        let mut bytes = std::fs::read(&m).unwrap();
        bytes[0] ^= 0x01;
        std::fs::write(&m, &bytes).unwrap();
        let (line, bad) = audit_signature_line(&m);
        assert!(bad, "{line}");
        assert!(line.starts_with("audit: signature INVALID-CONTENT (reel.reel-manifest.tsv.sig — manifest mismatch: "), "{line}");
        // INVALID-CONTENT (the malformed envelope — the rc=1 offender
        // class): a manifest whose .sig is not a well-formed envelope.
        let m3 = d.join("bad.reel-manifest.tsv");
        std::fs::write(&m3, b"# frameprism reel manifest\n").unwrap();
        let s3 = m3.with_file_name(format!("{}.sig", m3.file_name().unwrap().to_string_lossy()));
        std::fs::write(&s3, "not an envelope\n").unwrap();
        let (line, bad) = audit_signature_line(&m3);
        assert!(bad, "{line}");
        assert!(line.starts_with("audit: signature INVALID-CONTENT (bad.reel-manifest.tsv.sig — malformed envelope: "), "{line}");
        // A reel manifest WITHOUT its .sig = the ABSENT honesty line
        // (the verdict is unaffected: bad = false). The ABSENT line
        // is the universal honesty line: EVERY audit names the reel
        // manifest's signature state (G6 — the single-clip
        // archive's audit carries the ABSENT line too; the baseline
        // audit has no line at all — the additive surface).
        let m2 = d.join("other.reel-manifest.tsv");
        std::fs::write(&m2, b"# frameprism reel manifest\n").unwrap();
        let (line, bad) = audit_signature_line(&m2);
        assert!(!bad, "{line}");
        assert_eq!(
            line,
            "audit: signature ABSENT (other.reel-manifest.tsv carries no .sig — the archive predates signing or was never signed; the archive audit is unaffected)"
        );
        let _ = std::fs::remove_file(&s);
        let _ = std::fs::remove_dir_all(&d);
    }

    // -- the pins accessor (the canonical pin-set string) -----------------

    #[test]
    fn pin_set_canonical_shape() {
        use crate::pins::PinRow;
        let rows = vec![
            PinRow { component: "suite".into(), expected: "304 passed; 0 failed; 1 ignored".into(), probe: "probed-by-check.sh".into(), note: String::new() },
            PinRow { component: "cjxl/djxl".into(), expected: "v0.12.0 1cad73c".into(), probe: "version-contains --version".into(), note: String::new() },
            PinRow { component: "cjxl-sha256".into(), expected: "ab".into(), probe: "sha256-equal".into(), note: String::new() },
            PinRow { component: "zstd".into(), expected: "1.5.7".into(), probe: "lock-grep zstd-sys".into(), note: String::new() },
            PinRow { component: "tar".into(), expected: "0.4.46".into(), probe: "lock-grep tar".into(), note: String::new() },
            PinRow { component: "fstool".into(), expected: "0.4.33".into(), probe: "lock-grep fstool".into(), note: String::new() },
            PinRow { component: "tool".into(), expected: "0.6.0".into(), probe: "toml-grep".into(), note: String::new() },
        ];
        let s = crate::pins::pin_set_canonical(&rows);
        // The version rows' expected strings (the contract — the same
        // source ci/check-pins.sh asserts), sorted by component, the
        // cjxl/djxl row split into its two components, the tool row =
        // the running version; the sha256-equal + CI rows excluded.
        let want = format!(
            "cjxl=v0.12.0 1cad73c; djxl=v0.12.0 1cad73c; fstool=0.4.33; tar=0.4.46; tool={}; zstd=1.5.7",
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(s, want, "{s}");
    }
}
