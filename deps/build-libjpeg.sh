#!/usr/bin/env bash
# Build the bundled libjpeg-turbo with the per-component lossless table
# patch (libjpeg-percomp-lossless.patch) into a local prefix, static libs
# (libjpeg.a + libturbojpeg.a). The frameprism tool needs the patched
# compressor: the measured corpus tiles carry two per-component lossless DC tables
# (comp 0 -> table 0, comp 1 -> table 1, SOS selectors (0,0),(1,0)), and
# unpatched libjpeg (a) resets dc_tbl_no in jpeg_default_colorspace()
# during jpeg_start_compress (jcmaster.c) and (b) forces the SOS DC
# selector to 0 when Ss != 0 (jcmarker.c emit_sos) — so unpatched builds
# can only emit the single merged DHT.
#
# The bundled source tree under deps/libjpeg-turbo is kept CLEAN (the
# patch is applied to a throwaway copy in deps/.build/). Output prefix:
#   deps/.jpeg-prefix   (gitignored; not part of the reference copy)
#
# Build the tool against it with:
#   JPEG_TURBO_PREFIX=$PWD/deps/.jpeg-prefix cargo build --release
set -euo pipefail
cd "$(dirname "$0")"

TREE=libjpeg-turbo
BUILD=.build/libjpeg-turbo
PREFIX=.jpeg-prefix
PATCH=libjpeg-percomp-lossless.patch

[ -f "$PATCH" ] || { echo "missing $PATCH" >&2; exit 1; }

# Fresh throwaway copy of the reference tree + patch
rm -rf .build
mkdir -p .build
cp -R "$TREE" "$BUILD"
( cd "$BUILD" && git apply --check "$OLDPWD/$PATCH" )
( cd "$BUILD" && git apply "$OLDPWD/$PATCH" )

cmake -S "$BUILD" -B "$BUILD/cmbuild" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_STATIC_LIBS=ON \
  -DENABLE_SHARED=OFF \
  -DCMAKE_INSTALL_PREFIX="$PWD/$PREFIX" \
  -DCMAKE_C_FLAGS="-O2"
cmake --build "$BUILD/cmbuild" -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
cmake --install "$BUILD/cmbuild"

echo
echo "installed into $PWD/$PREFIX:"
ls -1 "$PREFIX/lib" 2>/dev/null | sed 's/^/  /'
echo
echo "build the tool with:"
echo "  JPEG_TURBO_PREFIX=$PWD/$PREFIX cargo build --release"