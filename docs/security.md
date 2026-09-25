# Security — the standing CI security posture

The posture in one line: **determinism-first** — verification inputs are
committed and pinned (the pinned-binary pattern of `ci/pins.tsv`), and the
two standing security jobs (the dependency
audit + the C-boundary fuzz corpus) are wired into `ci/check.sh` like
the byte-identity oracles: a drift is a named FAIL, never a silent
skip.

## 1. Posture

- **Self-contained project gates.** The project verification inputs, audit
  data, codec binaries, and fixtures are committed; the scripts in
  `ci/check.sh` do not fetch them. GitHub Actions checkout, toolchain setup,
  Cargo dependency setup, and cache operations can use the network.
- **Pinned externals.** `ci/pins.tsv` carries the full pin set: the
  cjxl/djxl byte pins, the toolchain pins (zstd/tar/fstool), the
  suite pin, the oracles, and — as part of this posture — the `cargo-audit`
  version+sha pins, the `advisory-db` / `fuzz-corpus` tree-sha256
  pins, and the `fuzz-outcome` pin.
- **Crash policy (the hard gate).** A crash on garbage input is
  ACCEPTED and pinned as a named class (the harness classifies it). A
  **corrupted write** (output where the pin says none, or output bytes
  ≠ the pin) or an **input mutation** is the hard gate — the harness
  fails automatically; these classes are never pinnable.

## 2. Dependency audit (standing job: `ci/check-audit.sh`)

- **Pinned binary:** rustsec/`cargo-audit` **v0.22.2**, aarch64-
  apple-darwin, committed at `deps/pinned-binaries/cargo-audit`
  (version + sha256 pins; env override `CI_CARGO_AUDIT_BIN`).
- **Pinned advisory DB:** a snapshot of rustsec/advisory-db at
  **`e2e640471715167f73e22eaf761f2e547adafeec`**,
  committed at `deps/rustsec-advisory-db/` (1265 content files, the
  `.git` dir stripped at commit; tree-sha256 pin `advisory-db`).
- **Offline invocation:**
  `cargo-audit audit --db deps/rustsec-advisory-db --no-fetch --file
  tool/Cargo.lock` — the output is pinned on its two stable fragments
  (`Loaded 1246 security advisories` + `124 crate dependencies`);
  `--no-fetch` is the no-network guarantee.
- **Current result: 0 vulnerabilities across 124 crate dependencies**
  — the tree includes the provenance-signature `ed25519-dalek` v2 chain.
- **Refresh procedure** (a maintainer step, never from CI): clone the
  advisory DB at a new commit, stage the binary + DB under `deps/`
  (stripping `.git`), re-pin (the `advisory-db` tree hash + the
  advisory/dep counts pinned in `ci/check-audit.sh`), and land the updated pins and artifacts together.

## 3. C boundary (standing job: `ci/check-fuzz.sh`)

**The map.** `tool/src/codec.rs` (the turbojpeg `tj3` C API) is the
ONLY externally-reachable C path: a single-strip tag-7 J92 frame
reaches `codec::decode_lossless` via `frameprism decode` on external
input. Real fp frames are tiled and take the golden-model Rust decode
path (no C). `ljpeg_ffi` / `ljpeg_shim.c` (raw libjpeg) decodes only
the tool's OWN encoded output — internal, not an external-input
surface.

**The corpus** (`ci/fuzz-corpus/`, 25 committed fixtures, 3 classes,
regenerable byte-identical by `generate_corpus.py` against the
committed `base-frame.dng`):

| class | entries | surface | pinned outcome |
|---|---|---|---|
| A — synthetic single-strip J92 (tag-7, no tile tags, 12-bit CFA) | a1–a12 | the turbojpeg C boundary (`decode_lossless`) | 12 × `refused` |
| B — synthetic tiled-base mutations (bitflip/truncation/tile-grid/PRNG/bad-magic/IFD-cut) | b1–b8 | the golden-model Rust decode path | 1 × `ok` (b1: a decodable corruption → the complete 16,735,112 B PAM — lossless JPEG has NO in-band integrity; the audit/sidecar layer is the integrity mechanism) + 7 × `refused` |
| C — synthetic garbage TIFF (random bytes/IFD-past-EOF/count-huge/unknown-type/BE-magic-LE-IFD) | c1–c5 | the `read_meta` Rust parse | 5 × `refused` |

Per-entry class pins: `ci/fuzz-corpus/expected.tsv` (the `bytes`
column pins the exact output size for `ok` entries). The outcome
report is pinned wholesale (the `fuzz-outcome` pin row; the exact
summary line `fuzz: 25 entries, 24 refused, 1 ok, 0 crash, 0
corrupted-write, 0 input-mutated`).

**The decode input.** The class-A/B outcomes involve the DECODE of the
committed pinned prefix — the fuzz runs the repo binary, which links
`deps/.jpeg-prefix` (the `turbojpeg` / `turbojpeg-prefix` pins in
ci/pins.tsv); an unpinned Homebrew decode is NOT in the contract path
(the Homebrew formula is unpatched — see deps/README.md). Upgrade
posture per §5, risk 1.

**Finding a5.** A 2-byte SOI-only strip makes
`tj3DecompressHeader` "succeed" with garbage dimensions (≈ u32::MAX);
the allocation `vec![0u16; (width*height)]` in `decode_lossless` then
**panicked** (`capacity overflow`, rc=101). No files were written,
but the tool's discipline is NAMED refusals. Fix (the only production
change): a dimension-magnitude guard at the allocation
site — `width*height > u64::MAX/4` is refused named (`implausible
JPEG dimensions … refusing to allocate`), keeping `samples*2 <
usize::MAX` with margin (a real frame is ≈ 8.4e6 samples).
Regression-locked by corpus entry a5 (the harness also FAILs on any
crash class, so the guard's absence would be a gate failure).

## 4. Subprocess surface (review note)

- **13 `Command::new` sites** (the cjxl/djxl contract engine for the
  `bake`/`decode`/`diff` paths + their version probes, the `df`
  free-space probe, `openssl` for the sign/verify, the `hdiutil`
  macOS test vectors, and the pins self-check probe). The `bake`
  container + image paths are in-process (no system-tool subprocess —
  the zstd/tar containers and the ISO image are built by the pinned
  crates). **Zero `shell(true)`, zero string-built argv** —
  every argument is an owned `String`/path from operator input or a
  constant; no attacker-controlled data reaches any argv beyond
  operator-supplied paths.
- **Child env = inherited** (CI uses the minimal fresh-shell PATH).
- **Standing rule:** a new subprocess requires maintainer review + a note
  update here.

## 5. Known residual risks

1. **libjpeg-turbo (the byte-contract build input): PINNED.** The
   contract never links the Homebrew build —
   the Homebrew jpeg-turbo formula is UNPATCHED (it cannot emit the
   SoC-compatible per-component lossless DHT tables; see
   deps/README.md) and survives only as (a) an EXPLICIT
   `JPEG_TURBO_PREFIX=/opt/homebrew/opt/jpeg-turbo` opt-in — named in
   the report's build-fact line, so a non-contract encode is visible per
   report (the old "dev fallback when `JPEG_TURBO_PREFIX` is unset"
   clause is gone: a bare build links the committed pinned prefix, and a
   missing prefix is a named build refusal at build time). The
   separately version-pinned tools are no longer Homebrew-supplied: the
   in-process zstd/tar/fstool components ride the committed Cargo.lock,
   and the cjxl/djxl + cargo-audit binaries are committed in
   `deps/pinned-binaries/`. The
   contract links the COMMITTED patched prefix
   `deps/.jpeg-prefix/{lib,include}` (tj 3.2.1; source
   `d9b5af99e53591c0b51ba82bea3a0874b78c4c20` + the
   committed `libjpeg-percomp-lossless.patch`, both pinned in
   `deps/fetch.sh`) — pinned by version (the `turbojpeg` pc-grep pin,
   the same first-`Version:`-line of the same .pc that `tool/build.rs`
   embeds in every report's build-fact line) + tree sha256 (the
   `turbojpeg-prefix` pin over the 13 committed files): a source or
   toolchain drift is a NAMED REFUSAL at the pin step, before any
   encode; the oracles + the fuzz corpus remain the behavioral
   backstop. Surviving residual: the prefix bytes are a build of
   AppleClang 21.0.0.21000334 — the committed bytes are the contract,
   the recipe is provenance (the cjxl/djxl posture); a prefix upgrade
   is a deliberate named migration (rebuild → re-pin → re-verify the
   oracles). Separately noted (pre-existing, unchanged by the pin): the
   oracle gold is anchored to the canonical working tree (the
   build-fact line embeds the ABSOLUTE prefix path; the records embed
   source mtimes) — a fresh machine verifies pins/suite/audit/fuzz +
   encode self-contained, but the oracle byte gates re-anchor on the
   canonical tree.
2. **The advisory DB is a point-in-time snapshot** — the refresh
   procedure above is the only update path.
3. **The fuzz is a pinned-corpus regression lock, NOT a
   coverage-guided fuzzer** — it locks the reconciled behavior; it
   does not search for new classes.
4. **No minting** (maintainer posture): the tool verifies,
   never generates keys — keygen is the external openssl+coreutils
   recipe in `docs/provenance.md`.
