#!/usr/bin/env bash
# Rebuild the three libjxl 0.12 runtime dylibs into deps/.jxl-libs/:
# libjxl.0.12.dylib, libjxl_threads.0.12.dylib, libjxl_cms.0.12.dylib —
# the runtime dependency of the pinned cjxl/djxl binaries
# (deps/pinned-binaries/, the jxl byte-identity contract).
#
# THE COMMITTED DYLIB BYTES ARE THE CONTRACT (the self-contained posture — the
# turbojpeg-prefix pattern). This recipe is PROVENANCE, not a routine
# step: running it is a DELIBERATE NAMED MIGRATION (rebuild → re-pin the
# `jxl-libs` tree-sha256 row in ci/pins.tsv → re-verify the oracles —
# `ci/check-108.sh` first). NEVER a silent refresh: a rebuild from a
# different source/toolchain changes the pin = a named FAIL at the pin
# step, before any encode.
#
# Provenance of the committed bytes:
#   - the pinned binaries' baked LC_RPATH points at the original local
#     build dir; that dir no longer exists — the committed dylibs are
#     the recovered rebuild of the same source
#   - source anchor: upstream libjxl @ v0.12.0, tag a7a9c787
#     (git rev-parse of the build checkout) — the same version the
#     pinned binaries' `--version` line "v0.12.0 1cad73c" reports.
#     NOTE: `1cad73c` is a LOCAL commit of the original
#     checkout (not in upstream libjxl nor google/highway — checked);
#     it is a provenance stamp BAKED INTO THE COMMITTED BINARIES. It is
#     NOT reproducible from upstream and needs NO reproduction: the
#     binaries are never rebuilt, so their `--version` output is fixed
#     regardless of which dylibs load. No JPEGXL_VERSION stamping is
#     done in this build (the tools aren't built — it is a tool-build
#     artifact).
#   - toolchain: AppleClang 21.0.0.21000334 (CMake Release, arm64) —
#     the same major toolchain as the original build (the binaries'
#     own version line says so)
#   - bundled deps at libjxl's pinned submodule SHAs (via ./deps.sh):
#     brotli 028fb5a2 (v1.2.0), highway 457c8917 (v1.2.0), skcms
#     96d9171c (2025_09_16) — absorbed into the dylibs (highway is
#     forced static by libjxl itself: HWY_FORCE_STATIC_LIBS; brotli is
#     forced static by the patch below)
#   - the committed set stays EXACTLY the three @rpath names the
#     binaries reference — self-contained (no fourth dylib): that is
#     why the brotli patch exists (see step 2b)
#   - behavioral canary: ci/check-108.sh (oracle108 10/10 @ 2,380,943 B
#     byte-identical) — a rebuilt set is accepted IFF cjxl/djxl
#     encode/decode over it reproduces the gold byte-exactly (lossless
#     JXL is exact arithmetic; same source + toolchain → same bytes)
#
# The build tree lives in /tmp (NOT the repo). Only the three dylibs
# (deps/.jxl-libs/) enter the repo. The pinned binaries
# (deps/pinned-binaries/{cjxl,djxl}) are NEVER touched by this recipe.
#
# Runtime wiring (why the dylibs' install names stay @rpath and no
# install_name_tool surgery is done): the pinned binaries resolve
# @rpath/libjxl* via DYLD_FALLBACK_LIBRARY_PATH=deps/.jxl-libs
# (dyld's last resort for @rpath lookups — the dead baked rpath is
# tried first and misses), exported by the named line in
# ci/check-pins.sh + ci/check-108.sh.
#
# Usage: bash deps/build-libjxl.sh   (≈ 20–40 min on a 14-core arm64
#       Mac)
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(cd .. && pwd)"

SRC=/tmp/libjxl-0.12.0
BUILD="$SRC/build"
LIBS="$PWD/.jxl-libs"
DYLIBS="libjxl.0.12.dylib libjxl_threads.0.12.dylib libjxl_cms.0.12.dylib"

# 1. the source anchor: upstream libjxl @ v0.12.0 (tag a7a9c787)
rm -rf "$SRC"
git clone --depth 1 --branch v0.12.0 https://github.com/libjxl/libjxl "$SRC"
( cd "$SRC" && git log -1 --format='libjxl source anchor: %H (%d)' )

# 2. third-party deps at libjxl's pinned submodule versions
#    (brotli/highway/skcms — the rest of the fetch is inert for a
#    library-only build)
( cd "$SRC" && ./deps.sh )

# 2b. the NAMED deviation from the stock configure: force the bundled
#     brotli targets STATIC. The stock BUILD_SHARED_LIBS=ON also makes
#     brotlicommon/brotlidec/brotlienc shared dylibs, which would give
#     libjxl.0.12.dylib three MORE @rpath references (libbrotli*.dylib)
#     that have no committed file to resolve to — breaking the
#     self-contained 3-dylib contract. Forcing STATIC absorbs the
#     brotli objects into libjxl.0.12.dylib (brotli sets
#     POSITION_INDEPENDENT_CODE TRUE on non-emscripten, so the
#     absorption is PIC-safe; the hwy precedent is the same posture —
#     libjxl itself sets HWY_FORCE_STATIC_LIBS ON). The JXL bytes are
#     UNAFFECTED: same brotli source (pinned SHA), same encoder — the
#     static-vs-shared linkage is not a byte-contract input; G3
#     (check-108) is the acceptance proof.
sed -i.bak \
  -e 's/^add_library(brotlicommon \${BROTLI_COMMON_SOURCES})/add_library(brotlicommon STATIC ${BROTLI_COMMON_SOURCES})/' \
  -e 's/^add_library(brotlidec \${BROTLI_DEC_SOURCES})/add_library(brotlidec STATIC ${BROTLI_DEC_SOURCES})/' \
  -e 's/^add_library(brotlienc \${BROTLI_ENC_SOURCES})/add_library(brotlienc STATIC ${BROTLI_ENC_SOURCES})/' \
  "$SRC/third_party/brotli/CMakeLists.txt"
grep -n 'add_library(brotli' "$SRC/third_party/brotli/CMakeLists.txt" | head -3

# 3. configure: Release, shared libs, library targets ONLY
#    (no tools — the pinned binaries ARE the tools; no examples/tests/
#    benchmarks/docs; JPEGXL_ENABLE_SKCMS stays ON — libjxl_cms is the
#    skcms-backed color-management dylib the binaries reference)
cmake -S "$SRC" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DBUILD_TESTING=OFF \
  -DJPEGXL_ENABLE_TOOLS=OFF \
  -DJPEGXL_ENABLE_DEVTOOLS=OFF \
  -DJPEGXL_ENABLE_EXAMPLES=OFF \
  -DJPEGXL_ENABLE_BENCHMARK=OFF \
  -DJPEGXL_ENABLE_DOXYGEN=OFF \
  -DJPEGXL_ENABLE_MANPAGES=OFF \
  -DJPEGXL_ENABLE_VIEWERS=OFF \
  -DJPEGXL_ENABLE_PLUGINS=OFF \
  -DJPEGXL_ENABLE_SJPEG=OFF \
  -DJPEGXL_ENABLE_JNI=OFF \
  -DJPEGXL_ENABLE_OPENEXR=OFF \
  -DJPEGXL_ENABLE_TCMALLOC=OFF \
  -DJPEGXL_ENABLE_FUZZERS=OFF

# 4. build (the long pole)
cmake --build "$BUILD" -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"

# 5. the exact referenced SONAMEs — otool -D each (the install names
#    must be @rpath/<name>: the binaries' dead baked LC_RPATH is
#    resolved via DYLD_FALLBACK_LIBRARY_PATH, step 9)
for d in $DYLIBS; do otool -D "$BUILD/lib/$d" | tail -1; done

# 5b. the self-containment check: libjxl.0.12.dylib must reference ONLY
#     the sibling jxl dylibs + system libs (NO @rpath/libbrotli* — the
#     step-2b patch's proof)
otool -L "$BUILD/lib/libjxl.0.12.dylib" | grep '@rpath' | grep -v 'libjxl' \
  && { echo "FAIL: libjxl references an unexpected @rpath dylib — self-contained 3-dylib layout broken" >&2; exit 1; } \
  || echo "self-contained: no unexpected @rpath refs"

# 6. cross-check against the pinned binaries' @rpath references (every
#    @rpath/libjxl* ref in BOTH binaries must match a built dylib's
#    exact name + install name)
for b in "$PWD/pinned-binaries/cjxl" "$PWD/pinned-binaries/djxl"; do
  otool -L "$b" | grep '@rpath/libjxl' || { echo "no @rpath/libjxl refs in $b?" >&2; exit 1; }
done

# 7. the dylib home (ONLY the three dylibs enter the repo; the build
#    tree's libjxl.0.12.dylib entries are symlinks to .0.12.0.dylib —
#    copy the real files, dereferenced, under the exact referenced
#    names)
rm -rf "$LIBS"
mkdir -p "$LIBS"
for d in $DYLIBS; do cp -L "$BUILD/lib/$d" "$LIBS/"; done
ls -l "$LIBS"

# 8. the jxl-libs tree-sha256 (the ci/pins.tsv `jxl-libs` row — the
#    same canonical tree hash ci/check-pins.sh computes: sorted file
#    list, per-file sha256, sha256 of the concatenated listing). After
#    a NAMED migration, update the row's expected column to this hash.
( cd "$LIBS" && find . -type f | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256 | awk '{print "jxl-libs tree-sha256: " $1}' )

# 9. re-verify: the version pins (18/18, incl. the recovered cjxl/djxl
#    pair + the jxl-libs row) and the BEHAVIORAL canary (oracle108 MUST
#    stay 10/10 @ 2,380,943 B byte-identical — otherwise the migration
#    FAILED: restore the previous dylibs + pin, investigate)
bash "$REPO/ci/check-pins.sh"
bash "$REPO/ci/check-108.sh"
