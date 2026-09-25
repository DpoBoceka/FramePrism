# deps — bundled dependency source (reference)

`fetch.sh` clones `tinydng/` + `libjpeg-turbo/` only — `dng_sdk_1_7_1/`,
`LibRaw/`, `libtiff/` were bundled manually (see the per-entry notes
below). The bundled sources are gitignored (large, re-fetchable) and
are reference material — EXCEPT the committed patched turbojpeg prefix
at `deps/.jpeg-prefix/{lib,include}` (the byte contract's build input —
see the link section below), which is NOT reference material: it is the
contract.

**libjpeg-turbo link (build contract):** the DEFAULT build (no
`JPEG_TURBO_PREFIX`) links the COMMITTED patched prefix at
`deps/.jpeg-prefix/{lib,include}` — `tool/build.rs` resolves it from
the manifest dir (`<tool>/../deps/.jpeg-prefix`, identical on every
platform), so a bare `cargo build` IS the contract build (zero setup).
A missing or unresolvable prefix (no `lib/` + `include/`, or the
`libturbojpeg.a`/`libjpeg.a` static libs absent) is a **NAMED build
refusal** at build time — build.rs never silently falls back to another
location. Homebrew is **NO LONGER the dev fallback** — it is the
EXPLICIT `JPEG_TURBO_PREFIX=/opt/homebrew/opt/jpeg-turbo` opt-in only,
and the formula is UNPATCHED: it cannot emit the
SoC/Resolve-compatible per-component lossless tiles (an unpatched
libjpeg silently emits the legacy merged-DHT output — conforming, but
NOT SoC-compatible; the mechanism is documented in
build-libjpeg.sh + the patch) —
the named non-contract path, visible in the report's build-fact line
(the linked prefix is named). The COMMITTED prefix is libjpeg-turbo
**3.2.1**, built from the pinned source
`d9b5af99e53591c0b51ba82bea3a0874b78c4c20` + the committed
`libjpeg-percomp-lossless.patch`; AppleClang 21.0.0.21000334):
`deps/fetch.sh` pins the source commit (and patch-checks the committed
patch against it); `ci/pins.tsv` pins the prefix — the `turbojpeg`
row (the same first-`Version:`-line of the same .pc that `tool/build.rs`
embeds in every report's build-fact line) + the `turbojpeg-prefix`
tree-sha256 row (the 13 committed files). A rebuild from a different
source/toolchain changes the pin → a **named FAIL** at the pin step,
before any encode — the same posture as the cjxl/djxl pins: the
COMMITTED BYTES ARE the contract, the recipe (`build-libjpeg.sh`) is
provenance. A prefix upgrade is a deliberate, named migration:
rebuild → re-pin → re-verify the oracles.

- `tinydng/` — header-only C++11 DNG load/write; lossless-JPEG DNG
  reader/writer; no lossy cDNG. Parser reference material.
- `libjpeg-turbo/` — codec source. Read `src/turbojpeg.h` +
  `doc/libjpeg.txt` for the exact `tj3*` lossless API
  (`TJPARAM_LOSSLESS`, `TJPARAM_PRECISION` 2–16 for lossless).
- `dng_sdk_1_7_1/` — Adobe DNG SDK 1.7.1 (2023). Bundled manually (not
  fetched by `fetch.sh`). Includes
  `DNG_Spec_1_7_1_0.pdf` (the current DNG spec — supersedes the 2009
  CinemaDNG v1.0 copy for DNG-container details),
  plus bundled libjpeg / libjxl / XMP. Reference for DNG tag semantics +
  lossless-JPEG-in-DNG conventions.
- `LibRaw/` — libraw (open-source RAW decoder). Bundled manually (not
  fetched by `fetch.sh`). Cross-check decoder for
  `verify`: decode both the input unpacked plane and the output JPEG,
  compare. (The fp packs its 12-bit samples in standard DNG order —
  verified pixel-exact vs LibRaw — so LibRaw is the cross-check,
  not the primary path.)
- `libtiff/` — libtiff. Bundled manually (not fetched by `fetch.sh`).
  Low-level TIFF read/write reference; informs the
  `tiff.rs` IFD parser. Not linked by the tool (we do byte surgery, not a
  TIFF library rewrite).
- `pinned-binaries/` — the pinned cjxl/djxl encoder pair (v0.12.0
  `1cad73c`, the local NEON build of libjxl). COMMITTED (un-ignored, like
  the oracle goldens — the same class of byte-contract artifact:
  these encoders PRODUCED the committed JXL goldens) — the jxl
  byte-identity contract. `ci/pins.tsv` pins BOTH the version
  (self-report) and the sha256 of these exact bytes, so the pin is
  self-contained. Update only via a deliberate, named pin migration:
  rebuild → re-pin the shas → re-record the oracle goldens (a
  version drift silently changes archive bytes).
**libjxl dylib (the cjxl/djxl runtime contract):** the pinned
`pinned-binaries/{cjxl,djxl}` binaries (entry above) reference three
`@rpath` dylibs — `libjxl.0.12.dylib`, `libjxl_threads.0.12.dylib`,
`libjxl_cms.0.12.dylib` — and carry a baked `LC_RPATH` pointing at the original local build dir;
that dir no longer exists. The committed dylibs are the recovered
rebuild of upstream libjxl @ v0.12.0
(tag `a7a9c787`) with the machine toolchain (AppleClang
21.0.0.21000334, CMake Release, `BUILD_SHARED_LIBS=ON`, library
targets only — no tools) — the recipe: `build-libjxl.sh` (the named
brotli-STATIC step there keeps the committed set exactly the 3
referenced dylibs, self-contained). The recovered dylibs are COMMITTED
at `.jxl-libs/` (un-ignored, like the pinned binaries — the same
class of byte-contract artifact) and pinned by the `jxl-libs`
tree-sha256 row in `ci/pins.tsv`. The `1cad73c` in the binaries'
`--version` line is a LOCAL-build stamp of the original
local checkout — baked into the committed binaries; it is NOT reproducible
from upstream and needs NO reproduction (the binaries are never
rebuilt, so their `--version` output is fixed regardless of which
dylibs load). THE COMMITTED DYLIB BYTES ARE THE CONTRACT (the self-contained
posture, the turbojpeg-prefix pattern): running `build-libjxl.sh` is a
DELIBERATE NAMED MIGRATION (rebuild → re-pin the `jxl-libs` row →
re-verify `ci/check-108.sh` first), never a silent refresh. Runtime
wiring: the baked `LC_RPATH` is dead by design now — the resolution
path is `DYLD_FALLBACK_LIBRARY_PATH=deps/.jxl-libs` (dyld's last
resort for `@rpath` lookups), exported by the named line in every
`ci/*.sh` that spawns a cjxl/djxl process (`check-pins.sh`,
`check-108.sh`; the export propagates to the tool's cjxl/djxl
subprocesses). The behavioral canary that proves the swap is
byte-transparent: `ci/check-108.sh` (oracle108 10/10 @ 2,380,943 B
byte-identical — the jxl byte contract RESTORED, not approximated).
Upgrade path: a future cjxl/djxl re-pin (a binary-level migration) is
the point to consider `install_name_tool` rpath surgery on the
binaries — named future work, not now.
