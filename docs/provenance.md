# Provenance — the signed reel manifest

The reel manifest's `sha256` proves the *content* is intact. The
provenance signature proves the *provenance claim*: **this archive was
produced by frameprism vX on date D with pin set P** — by a key that the
verifier has out-of-band. The signature is an addition over the
manifest (a new `<manifest>.sig` file); the manifest bytes are never
touched, and an unsigned archive remains fully auditable (the
signature is OPTIONAL for the audit PASS).

## What the signature covers

`sign` computes an ed25519 signature (RFC 8032 — deterministic, same
key + same message = same signature) over a CANONICAL STRING — the
pinned v1 shape, re-derivable from the envelope + the manifest alone:

```
frameprism-reel-sig-v1
manifest_sha256=<64 hex>
tool_version=<the running frameprism version>
signed_at=<unix seconds, UTC>
key_fingerprint=<64 hex>
pin_set=<the one-line canonical pin-set string>
```

(the five `key=value` lines in that order, `\n`-joined, NO trailing
newline). The `pin_set` is the pin file's EXPECTED version strings
(the contract, not the live probe state — deterministic for a given
pins file): the version rows as `component=version` (the `cjxl/djxl`
row contributes `cjxl=…` + `djxl=…`), the tool row as
`tool=<version>`, sorted, `; `-joined; the byte pins + the
CI-probed rows carry no component version and are excluded. Same
source `ci/check-pins.sh` asserts.

## The key file (documented format — the tool verifies, it does NOT mint)

The key file is a small text record. frameprism PARSES and VERIFIES it;
it never generates one (the same posture as the pins: the tool checks
what it is given). Key generation is the external openssl + coreutils
recipe below — a separate surface, run by the human:

```
# frameprism key file
version: 1
type: private            # or: public
fingerprint: <64 hex — the sha256 of the 32-byte RAW public key>
public: <64 hex — the 32-byte public key>
seed: <64 hex — the 32-byte ed25519 seed>        # private files ONLY
```

Strict parse: bad magic / bad hex / wrong lengths / a missing field /
a duplicate field / `type: public` carrying a `seed:` line / `type:
private` WITHOUT a `seed:` line / a `fingerprint:` that does not equal
the sha256 of the raw public key = the named corrupt-key refusal
(rc=2, zero partial operations — a key file that lies about its own
identity is a records-class refusal, not a signature finding).
Unknown fields are skipped (the header is additive).

### Key generation (the documented external recipe — openssl + coreutils)

```sh
# 1. Generate the ed25519 key (PKCS8 DER on stdout).
openssl genpkey -algorithm ed25519 -outform DER > pkcs8.der

# 2. The seed = the PKCS8's trailing 32 bytes (the ed25519 layout:
#    the PrivateKey OCTET STRING wraps the raw 32-byte seed).
SEED=$(tail -c 32 pkcs8.der | shasum -a 256 >/dev/null && tail -c 32 pkcs8.der | od -An -vtx1 | tr -d ' \n')

# 3. The public key = the SPKI DER's trailing 32 bytes (the BIT STRING
#    wraps the raw 32-byte public key).
openssl pkey -in pkcs8.der -pubout -outform DER > spki.der
PUB=$(tail -c 32 spki.der | od -An -vtx1 | tr -d ' \n')

# 4. The fingerprint = the sha256 of the RAW public key (the in-tree
#    cross-check — the tool re-derives it from the public: field and
#    refuses the file if it does not match).
FP=$(tail -c 32 spki.der | shasum -a 256 | cut -d' ' -f1)

# 5. Assemble the key file (private keeps the seed; the verify key
#    file is the same minus the seed line, type: public).
{ echo "# frameprism key file"; echo "version: 1"; echo "type: private"; \
  echo "fingerprint: $FP"; echo "public: $PUB"; echo "seed: $SEED"; } > signing.key
```

(Any equivalent derivation is fine — the contract is the three fields:
`fingerprint` = sha256(raw public), `public` = the 32-byte public key,
`seed` = the 32-byte seed. The unit test
`key_file_fingerprint_is_sha256_of_raw_public` pins the DER-tail
property against the openssl binary itself.)

**Environment note**: the recipe requires an OpenSSL with ed25519
support (OpenSSL 1.1.1+); on macOS `/usr/bin/openssl` is Apple's
LibreSSL and lacks ed25519 key generation — use the Homebrew OpenSSL
(`/opt/homebrew/bin/openssl`) or an equivalent.

**Storage**: the private key file is a SECRET (whoever holds it can
sign). Keep it out of the repo; the public key file is the shareable
artifact (publish it with the archive so third parties can `verify`).

## The envelope (`<manifest>.sig`)

The signature record — written by `sign` NEXT TO the manifest (the
default; `--out` relocates it), atomic (tmp + rename), deterministic
(re-sign with the same `--date` = byte-identical envelope bytes):

```
# frameprism signature envelope
version: 1
tool_version: <v>
signed_at: <unix seconds, UTC>
manifest: <the manifest's file name>
manifest_sha256: <64 hex — the manifest bytes as read at sign>
manifest_bytes: <the manifest's byte length>
key_fingerprint: <64 hex — the signing key's identity>
pin_set: <the one-line canonical pin-set string>
signature: <128 hex — the ed25519 signature over the canonical string>
note: the signature covers the canonical string (...)
```

## The verbs

```
frameprism sign   --key <private.key> [--date <unix>] [--out <path>] <manifest>
frameprism verify --key <public-or-private.key> [--sig <path>] <manifest>
```

- `sign` — writes the envelope. Requires `type: private` (a
  public-only key = the named rc=2 refusal — a verify key is never a
  signing key by accident). The manifest, key, and pin set are all
  re-derived BEFORE any write — a refusal leaves zero partial files.
- `verify` — re-derives (1) the manifest's sha256 on disk (the
  intactness claim), (2) the key identity (the envelope's
  `key_fingerprint` vs the presented key — checked BEFORE the
  signature: a verify against a key the envelope does not name is
  meaningless), (3) the signature over the re-derived canonical
  string. rc=0 valid; rc=1 a signature FINDING (`manifest mismatch` /
  `signature invalid` / `key fingerprint mismatch` lines); rc=2 a
  malformed REFUSAL (missing manifest / missing or corrupt envelope /
  corrupt key — the audit's ABSENT line is the audit's honesty
  surface; the verb's missing-`.sig` is the usage refusal).

## The audit signature line (keyless)

Every audit names the reel manifest's signature state (the `audit
report` surface — the keyless CONTENT CLAIM: the envelope
well-formedness + the `manifest_sha256` re-hash; the signature itself
is `verify`'s surface, which takes the key):

- `audit: signature VALID-CONTENT (…)` — the content claim holds; the
  audit verdict is UNAFFECTED (a valid signature is provenance, not
  an archive check);
- `audit: signature INVALID-CONTENT (malformed envelope | manifest
  mismatch)` — the audit FAILS (rc=1, the offender class — a broken
  provenance claim is worse than its absence: the envelope lies);
- `audit: signature ABSENT (…)` — the honesty line (the archive
  predates signing or was never signed; the archive audit is
  unaffected).

## The sealed tier — the `.sig` ride into the ISO (the provenance bundle)

A sealed ISO is a transport: a future reader who mounts (or extracts)
the disk gets the full `VERIFY OK` from the sealed artifact alone.
`bake --iso` carries that as the **provenance bundle** — staged at the
image root as the `provenance/` subdirectory, ALONGSIDE the image's
own pinned-epoch `reel.reel-manifest.tsv` (the ISO's own manifest is
UNCHANGED — the bundle rides alongside it, under its own name):

```
bake --iso <encoded reel dir> <image> --reel-out <reel dir>
```

- `<reel dir>` = the WORKING-TIER reel dir — the `bake <out>
  <reel-dir>` output dir, AFTER `frameprism sign <reel dir>/
  reel.reel-manifest.tsv --key <private key file>` was run on its
  reel manifest.
- What rides: `provenance/reel.reel-manifest.tsv` (the SIGNED
  working-tier reel manifest — the bytes untouched) +
  `provenance/reel.reel-manifest.tsv.sig` (its envelope).

Why a bundle (not a `.sig` copied next to the image-root manifest):
`bake --iso` re-renders the reel manifest at the image root with the
PINNED epoch (the image determinism), while the working-tier manifest
was rendered with the WALL-CLOCK `created` epoch — a working-tier
`.sig` can therefore never match the ISO's own manifest bytes. The
bundle instead rides the SIGNED working-tier manifest alongside; the
ISO's own manifest stays exactly what it was.

### The sealing-time checks (keyless — the seal gate)

The seal is checked WITHOUT the key (the signature itself is the
reader's `verify` surface). Every failing check = a named rc=2
refusal with zero partial files (the image path is NOT created):

1. `<reel dir>/reel.reel-manifest.tsv` exists;
2. the adjacent `.sig` exists (sign it first — the sealed ISO will
   not carry a dead reference);
3. the envelope is well-formed (the existing envelope parser — the
   same wording class as the audit line);
4. the envelope's `manifest_sha256` == the sha256 of the reel-out
   manifest's bytes (the envelope must bind the presented manifest —
   a broken provenance claim is refused the seal);
5. **the content-row binding**: the signed manifest and the sealed
   reel's manifest must match on every parsed field except the
   epoch-derived free variables — exactly two: the `created:` epoch
   line (working tier = the wall clock, the ISO = the pinned epoch)
   and the per-row `manifest_sha256` column — that column hashes the
   per-clip manifest, whose only free variable is its own `created:`
   epoch line, so it is excluded with the header epoch; the content
   rows remain bound by clip / codec / archive / archive_sha256 /
   manifest-name / frames. A signature for a different reel is
   refused (the reel-A-into-reel-B attack); a malformed manifest on
   either side is the named refusal too.

`--reel-out` on the non-`--iso` bake = the named usage refusal (the
flag is `--iso`-only — it seals into the image; the working-tier bake
does not stage it); a single-clip ISO carries no reel manifest, so
`--reel-out` on a single-clip ISO = the named refusal too.

### The reader path (extract + verify)

```sh
# Extract the provenance/ bundle from the sealed ISO (either route):
bsdtar -xf reel.iso -C scratch provenance/
hdiutil convert reel.iso -imageformat UDFTO9664 -o reel.udf  # + hdiutil attach

# The full verification from the sealed artifact alone:
frameprism verify scratch/provenance/reel.reel-manifest.tsv --key <public key file>
# → VERIFY OK (…)
```

(the envelope's `manifest:` basename matches the extracted name → the
default `.sig` path resolves; the manifest bytes survive the ISO
round-trip → the content claim holds; the signature is the provenance
claim.)

### Determinism

The bundle is deterministic for a fixed `signed_at` (the same signed
manifest + the same `.sig` bytes), and the staged bundle's mtimes are
pinned with the rest of the staged tree — the ISO d1/d2 byte-identity
anchor holds WITH the bundle staged (two `bake --iso --reel-out` runs
from the same signed state produce byte-identical images).

Absent `--reel-out`, `bake --iso` is UNCHANGED (the flag is purely
additive — the plain `bake` / `bake --iso` outputs for existing
invocations are byte-identical to the pre-bundle binary).
