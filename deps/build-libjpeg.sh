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
#
# Host-portable (the CI build hosts: the mac + linux unix hosts and the
# windows-latest runner's Git Bash — MSYS/MINGW). The pinned source
# commit, the patch, and the prefix layout never move; only the
# generator/flags are host-selected below. On MSVC the static lib
# names are jpeg-static.lib / turbojpeg-static.lib (the CMake
# OUTPUT_NAME rename to libjpeg/libturbojpeg is unix-only) —
# tool/build.rs links them per-platform.
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

# --- host-portable configure (the unix hosts keep the byte-invariant
# default-generator invocation; the windows host gets the MSVC
# selection). The pin/patch/prefix never move.
#   - `--config Release` + `-j` below: silently ignored on the unix
#     single-config generator (verified), required to select the
#     Release config on the windows multi-config generator.
#   - MSVC: the install prefix is passed in the native (C:\...) form —
#     Git Bash's msys-style $PWD is not what the Windows cmake wants
#     (cygpath -m: the msys->windows conversion, a Git Bash builtin).
#   - MSVC: -DWITH_CRT_DLL=ON matches Rust's MSVC default (the dynamic
#     CRT, /MD — libjpeg-turbo's own default is the /MT static CRT; the
#     runtime-library choice, not a source change). Plain (unquoted,
#     empty-or-single-word) expansion: no bash arrays — the mac /bin/bash
#     3.2 + `set -u` rejects the empty-array expansion.
INSTALL_PREFIX="$PWD/$PREFIX"
EXTRA_CMAKE_ARGS=""
case "$(uname -s 2>/dev/null)" in
  Linux|Darwin) ;;  # the unix hosts: the default generator, the msys-style prefix (unchanged)
  *)
    INSTALL_PREFIX="$(cygpath -m "$PWD/$PREFIX")"
    EXTRA_CMAKE_ARGS="-DWITH_CRT_DLL=ON"
    ;;
esac

cmake -S "$BUILD" -B "$BUILD/cmbuild" \
  $EXTRA_CMAKE_ARGS \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_STATIC_LIBS=ON \
  -DENABLE_SHARED=OFF \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
  -DCMAKE_C_FLAGS="-O2"
cmake --build "$BUILD/cmbuild" -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" --config Release
cmake --install "$BUILD/cmbuild" --config Release

echo
echo "installed into $PWD/$PREFIX:"
ls -1 "$PREFIX/lib" 2>/dev/null | sed 's/^/  /'
echo
echo "build the tool with:"
echo "  JPEG_TURBO_PREFIX=$PWD/$PREFIX cargo build --release"