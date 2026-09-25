# FramePrism

FramePrism compresses uncompressed CinemaDNG RAW frame sequences, losslessly, for the edit
pipeline. The default output is **j92** — a DNG container carrying lossless JPEG tiles
(ITU-T T.81, JPEG 92): bit-exact on the round-trip, and it imports into DaVinci Resolve 21
(the 21.1-generation measurement). Two working modes ride the same contract: `--mode log10` (10-bit log codes)
and `--downscale2x` (a 2× downscale — ~10:1 for proxies).

What 0.1.1 ships:

- **The j92 working tier** — lossless, NLE-compatible (the output plays in DaVinci Resolve 21.1).
- **The modes** — `log10` + `downscale2x`, at the measured camera gates.
- **The jxl archival tier** — `--codec jxl`: 4 sub-plane `.jxl` files per frame + the checksum sidecar (the archival format — not an NLE container).
- **`--fast`** — bit-exact single-candidate selection, ~3–4.6× faster than the adaptive 3-candidate selection.
- **The card workflow** — `offload` (mirror + verify any card tree, N×M fan-out), `audit`, `restore`, `repair`, `ledger` (the verify-before-wipe verdict — docs/card-workflow.md).
- **The verification chain** — sha256/crc32c checksum sidecars, the `--verify` round-trip, the byte-identity oracles re-encoded + byte-compared on every gate run.
- **Subcommands** — `bake` (tar/ISO + manifest), `decode` (16-bit PAM frames), `derive` (8/10-bit working DNGs), `diff`, `sign`/`verify` (the signed reel manifest — docs/provenance.md).

Known limits (0.1.1): the distribution is the source + the release-page binaries (the
Downloads — the Quick start builds the source); the contract build is macOS Apple Silicon
(the gate toolchain); the MHL manifest's writer/parser is tested against the adversarial
suite, round-trip with a third-party implementation not yet exercised; the card `wipe`
verb and the auto-eject after a verified offload are not yet implemented.

## Quick start

From the repository root:

macOS (the gate toolchain — the committed prefix is the mac host's):

```sh
cargo build --release --manifest-path tool/Cargo.toml  # build.rs links the committed deps/.jpeg-prefix
./tool/target/release/frameprism --version             # frameprism 0.1.1

# encode a clip (frames in → frames out; the run prints the summary:
# the frame count, the bytes in/out, the ratio, the wall time):
./tool/target/release/frameprism originals/ clips/

# decode back (the round-trip is bit-exact):
./tool/target/release/frameprism decode clips/ decoded/
```

Linux / Windows (Git Bash — the host prefix first — the committed one is a Darwin build):

```sh
deps/fetch.sh && deps/build-libjpeg.sh   # → deps/.jpeg-prefix (the host build)
JPEG_TURBO_PREFIX=$PWD/deps/.jpeg-prefix cargo build --release --manifest-path tool/Cargo.toml
```

The full prefix contract (the opt-in paths, the named refusals): `CONTRIBUTING.md` (the Build section).

No footage? The self-contained smoke gate + the committed 10-frame fixture:

```sh
bash ci/check.sh                                             # the whole gate (the CI job — zero external setup)
./tool/target/release/frameprism ci/oracle10/src /tmp/frameprism-demo --jobs 1
```

Reference numbers (the committed 12-bit fixture, 225 frames): lossless 5.00:1 · log10 6.93:1 ·
downscale2x 17.12:1.

## Platforms and cameras

- **Platform:** the contract build is macOS Apple Silicon (the gate toolchain: rustc 1.98.1 / clippy 0.1.98; MSRV 1.80); the prebuilt binaries also cover Linux (x86_64) + Windows (x86_64) (the Downloads); the source build works on all three platforms with the host-prefix setup (the Quick start).
- **Cameras:** the Sigma fp (A001) is profiled and measured at 8/10/12-bit. FramePrism encodes only the measured camera × mode combinations — the unmeasured ones are a named refusal, not a guess (docs/camera-profiles.md).
- **Distribution:** the source (this repository) + the prebuilt release binaries (the Downloads). No `cargo install`, crates.io package, or Homebrew package.

## Downloads

Prebuilt binaries for macOS (arm64), Linux (x86_64) and Windows (x86_64) are on the release page (https://github.com/DpoBoceka/FramePrism/releases).
Verify the download against the `SHA256SUMS` in the release assets (`sha256sum -c` / the certutil equivalent).
The Linux build targets the ubuntu-24.04 runner (glibc 2.39+); the source build (the Quick start) works on all three platforms with the host-prefix setup.

## CLI

`frameprism --help` is the single source of truth for the flag semantics (the design notes
live in `docs/cli.md`). The current surface, straight from the binary:

<!-- frameprism-help-commands:begin — regenerate from the built binary's frameprism --help; the ci/check.sh drift gate byte-diffs this block; do not edit by hand -->
```
Commands:
  bake     Package an encoded clip dir into a tar[.zst] archive + a per-file sha256 manifest. --iso: write a mountable ISO image instead; --reel-out: ride the signed reel manifest + its .sig on the image
  decode   Decode an encoded clip dir to 16-bit PAM frames
  offload  Offload (mirror + verify) a source tree to one or more destinations — no encode: every file (the frames + the sidecars — any camera, any format) is re-scanned (sha256 — the source's bytes are read ONCE per file), copied to EVERY destination (mirrored subpaths, mtime preserved), re-scanned after each write, and rowed into the per-clip offload manifests at each destination (the `dest` header row is that dest) + the run report at each destination root (the report carries the whole run — every dest's status). The two forms: the single-source form — the positional `in` (the source) + the positional `to` dests (the legacy shape, byte-identical) — and the multi-source form — `--source <SOURCE>...` (the sources) + `--dest <DEST>...` (the dests; every source fanned to every dest in one job; the per-source work runs concurrently — one std::thread per source, the sources do not wait on each other; the per-dest-root artifacts ride the serialized tail after all sources join — one ascmhl generation per dest per job). The positionals are the single-source form's: the mixed-form/all-absent refusals are the named rc=2 bands. The camera/format detection is a report, never a gate (the offload copies + verifies any tree). Per-destination verification + status: rc=0 every row OK at every dest; rc=1 any dirty row at any dest (the named FAIL lines, after the run — every dest named); rc=2 the pre-write refusals (the self-mirror guard per dest, the duplicate-dest refusal, the per-dest writability probe — before any copy)
  audit    Verify every file the sidecars list (size + sha256, + crc32c where present). rc=0 clean, rc=1 offenders named, rc=2 usage
  restore  Re-copy audit offenders from a pristine master (the master must itself verify; the original is kept as <file>.pre-restore)
  derive   Derive 8/10-bit working DNGs from 12-bit masters (pinned v>>4 / v>>2)
  diff     Per-frame pixel comparison of two encodes; deterministic --report; --strict = exit 1 on any delta
  repair   Re-copy + re-verify the dirty rows of an offload manifest from the source tree
  ledger   Show the ops ledger + the rotation report (last audit older than N days)
  sign     Sign the reel manifest (ed25519, deterministic; the manifest bytes are never touched)
  verify   Verify a signed reel manifest (sha256 + key identity + signature)
  help     Print this message or the help of the given subcommand(s)
```
<!-- frameprism-help-commands:end -->

## Build contract (the short version)

On macOS (the gate toolchain), a bare `cargo build` IS the contract build — build.rs links
the committed patched `deps/.jpeg-prefix` (libjpeg-turbo 3.2.1, source-pinned); a missing or
unresolvable prefix is a NAMED build refusal before any encode — never a silent fallback.
`JPEG_TURBO_PREFIX` is the explicit opt-in to a different prefix (the unpatched Homebrew
formula is the NAMED non-contract path: it silently emits conforming-but-NLE-incompatible
output). The default lossless encoder is the native Rust T.81 (SOF3) entropy encoder
(byte-identical to the libjpeg FFI path); `FRAMEPRISM_ENGINE=ffi|libjpeg|legacy` restores the
FFI engine — the engines are byte-identical, so a mis-set var cannot change output bytes.
To rebuild the committed prefix from the pinned source: `deps/fetch.sh` +
`deps/build-libjpeg.sh`. Full contract: `CONTRIBUTING.md`.

## Layout

```
tool/            Rust CLI + codec (src/: tiff, pack12, tileenc, surgery,
                 lossydct, dct2s, ljpeg_shim.c, worker, verify; the
                 cargo-fuzz target in tool/fuzz/)
ci/              the CI gate + the byte-identity oracles (check.sh +
                 the check-*.sh legs, pins.tsv, fuzz-corpus/, oracle10/,
                 oracle108/)
tools/           the documented research scripts (the eight, pure
                 stdlib — see CONTRIBUTING.md for the inventory)
deps/            the committed pin set: the patched static prefix
                 (.jpeg-prefix), the pinned cjxl/djxl + cargo-audit
                 (pinned-binaries/), the advisory-db snapshot — see
                 deps/README.md
docs/            the user-facing engineering docs (the 11 docs + the
                 index — see the Docs table)
profiles/        the camera profiles (the encode contract's default
                 lookup: <cwd>/profiles — docs/camera-profiles.md)
testdata/        the corpus registry (clips.tsv + manifest.tsv; footage
                 not committed — the registry only — see
                 testdata/README.md)
CHANGELOG.md     release history
CONTRIBUTING.md  build contract, CI gate, corpus
LICENSE          MIT license
```

## Docs

| doc | what it is |
|---|---|
| `docs/README.md` | the docs index |
| `docs/architecture.md` | pipeline, format contract, verification, code layout |
| `docs/cli.md` | the CLI design notes — where the `--help` narrative lives |
| `docs/compatibility.md` | the NLE/reader compatibility matrix |
| `docs/format-dct12.md` | the dct12 format — the non-default lossy tier's format doc |
| `docs/jxl-tier.md` | the shipped JXL archival tier + the evaluated-codecs table |
| `docs/provenance.md` | the signed reel manifest — the `sign`/`verify` verbs, the key-file format, the no-mint posture, the sealed-tier `--reel-out` bundle |
| `docs/card-workflow.md` | the direct card archive — the verify-before-unmount gate, the CARD UNLOCKED/REFUSED/UNVERIFIABLE verdict |
| `docs/camera-profiles.md` | the per-camera pinned config — the profile format, the identity-vs-routing split, the named mismatch classes, the `FRAMEPRISM_PROFILES` resolution |
| `docs/glossary.md` | terminology |
| `docs/security.md` | the security posture + the vulnerability handling |
| `docs/third-party.md` | third-party attribution |
| `CONTRIBUTING.md` | build contract, CI gate, corpus |

## License

MIT (`LICENSE` at the repo root). Third-party attribution: `docs/third-party.md`.
