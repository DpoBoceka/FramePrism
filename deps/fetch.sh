#!/usr/bin/env bash
# Fetch dependency source. The byte contract links the COMMITTED patched
# libjpeg-turbo prefix (deps/.jpeg-prefix/{lib,include} — pinned in
# ci/pins.tsv, `turbojpeg` + `turbojpeg-prefix`); this script pins the
# SOURCE that prefix was built from. Homebrew is a dev fallback only
# (tool/build.rs with no JPEG_TURBO_PREFIX) — the Homebrew formula is
# UNPATCHED and cannot emit the SoC-compatible per-component lossless
# tiles (see deps/build-libjpeg.sh's header for the mechanism).
set -euo pipefail
cd "$(dirname "$0")"

# --- tinydng: reference material, not a link target — HEAD is fine ----
if [ -d tinydng ]; then
  echo "deps/tinydng: already present"
else
  git clone --depth 1 https://github.com/palszasz/tinydng tinydng
fi

# --- libjpeg-turbo: PINNED to the commit the committed prefix was
# built from (the byte contract's source input — a source-side drift
# that breaks the patch is a named FAIL at fetch time, not a
# mysterious build failure later) -------------------------------------
LT_JPEG_TURBO_COMMIT=d9b5af99e53591c0b51ba82bea3a0874b78c4c20
PATCH=libjpeg-percomp-lossless.patch

if [ -d libjpeg-turbo/.git ]; then
  HEAD="$(git -C libjpeg-turbo rev-parse HEAD)"
  if [ "$HEAD" != "$LT_JPEG_TURBO_COMMIT" ]; then
    echo "deps/libjpeg-turbo: FAIL — HEAD is $HEAD, the pin is $LT_JPEG_TURBO_COMMIT (remove the dir and re-fetch — the pin is $LT_JPEG_TURBO_COMMIT)" >&2
    exit 1
  fi
  echo "deps/libjpeg-turbo: already present at the pinned commit $LT_JPEG_TURBO_COMMIT"
else
  git clone https://github.com/libjpeg-turbo/libjpeg-turbo libjpeg-turbo
  git -C libjpeg-turbo checkout --detach "$LT_JPEG_TURBO_COMMIT"
  echo "deps/libjpeg-turbo: cloned + detached at the pinned commit $LT_JPEG_TURBO_COMMIT"
fi

# The byte contract's source input must be patchable (the committed
# per-component lossless DHT patch applies cleanly to the pinned
# commit). $PWD is the deps dir (the script cd's there) — the patch
# lives one level up from the clone, so use the absolute path (the
# same $OLDPWD pattern build-libjpeg.sh uses).
if ! git -C libjpeg-turbo apply --check "$PWD/$PATCH"; then
  echo "deps/libjpeg-turbo: FAIL — $PATCH does not apply to $LT_JPEG_TURBO_COMMIT (source-side drift — check the pin)" >&2
  exit 1
fi
echo "deps/libjpeg-turbo: $PATCH applies cleanly (patch-check OK)"

echo "done: $(ls -1d */ 2>/dev/null | tr '\n' ' ')"
