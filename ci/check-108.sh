#!/usr/bin/env bash
# check-108.sh — the 10/8-bit JXL oracle.
#
# What this is: the byte-identity gate for `--codec jxl` at 10/8-bit.
# Two deterministic synthetic source frames (ci/oracle108/src/: f10 =
# UHD 3856×2170 10-bit; f8 = FHD 1936×1090 8-bit — the two
# depths the 12-bit oracle10 lacks) are re-encoded with the committed
# binary at e7 into a temp dir and every output byte-compared against
# the committed gold (8 .jxl planes + the 2 sidecars; the sidecar
# carries no host-dependent fields, so it is deterministic for the
# pinned cjxl). The cjxl/djxl version pin is re-asserted here because
# the JXL bytes are that build's output — a drift silently changes the
# archive bytes (same contract as check-pins.sh; if this script is
# wired into check.sh's flow the shared pins step already covers it).
# Any failure is a named FAIL + rc=1 — no silent skips.
#
# CLI: check-108.sh [--repo <path>]
#   --repo   repo root (default: this script's grandparent)
# Env:  JPEG_TURBO_PREFIX (default <repo>/deps/.jpeg-prefix),
#       CARGO_TARGET_DIR (default <repo>/target), CI_CJXL_BIN /
#       CI_DJXL_BIN (pin overrides — the same defaults as check-pins.sh).
# Exit: 0 ALL PASS, 1 any named FAIL.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    *) echo "check-108: unknown argument: $1" >&2; exit 2 ;;
  esac
done

export JPEG_TURBO_PREFIX="${JPEG_TURBO_PREFIX:-$REPO/deps/.jpeg-prefix}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO/target}"
# The libjxl 0.12 runtime dylib home (deps/.jxl-libs/ — the committed pin,
# see deps/README.md): the pinned cjxl/djxl binaries carry a dead baked
# LC_RPATH (the rawcodecs build dir, since pruned), so dyld resolves their
# @rpath/libjxl* references
# through this last-resort fallback; the export also propagates to the
# tool's cjxl/djxl subprocesses (the oracle encode/decode). Appended to
# any existing value (bash 3.2-portable).
export DYLD_FALLBACK_LIBRARY_PATH="$REPO/deps/.jxl-libs${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
CJXL_BIN="${CI_CJXL_BIN:-$REPO/deps/pinned-binaries/cjxl}"
DJXL_BIN="${CI_DJXL_BIN:-$REPO/deps/pinned-binaries/djxl}"
JXL_PIN="v0.12.0 1cad73c"
GOLD="$SCRIPT_DIR/oracle108/gold"
SRC="$SCRIPT_DIR/oracle108/src"
EXPECTED_TOTAL=2380943   # sum of the 8 gold .jxl (byte-identity contract)

echo "=== ci check-108: $(date '+%Y-%m-%d %H:%M:%S') repo=$REPO ==="

# --- step 1: cjxl/djxl version pin (the JXL bytes are that build's output)
for pair in "cjxl:$CJXL_BIN" "djxl:$DJXL_BIN"; do
  label="${pair%%:*}"; bin="${pair#*:}"
  if [ ! -x "$bin" ]; then
    echo "FAIL check-108: $label pin — missing binary ($bin)"
    exit 1
  fi
  line1="$("$bin" --version 2>&1 | head -1)"
  case "$line1" in
    *"$JXL_PIN"*) echo "PIN OK $label :: $line1" ;;
    *) echo "FAIL check-108: $label pin — expected $JXL_PIN, got $line1"; exit 1 ;;
  esac
done

# --- step 2: release build (no-op when current) --------------------------------
echo "--- build (release) ---"
if ! (cd "$REPO/tool" && cargo build --release); then
  echo "FAIL check-108: cargo build --release failed"
  exit 1
fi
BIN="$CARGO_TARGET_DIR/release/frameprism"
[ -x "$BIN" ] || { echo "FAIL check-108: tool binary missing: $BIN"; exit 1; }

# --- step 3: the two-frame oracle (byte-identity vs gold) -----------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ok=0; miss=0; tot=0
for d in f10 f8; do
  echo "--- oracle108/$d (encode $SRC/$d → byte-identity vs $GOLD/$d) ---"
  "$BIN" "$SRC/$d" "$TMP/$d" --codec jxl --jxl-effort 7 --jobs 1 \
    --cjxl-bin "$CJXL_BIN" --djxl-bin "$DJXL_BIN" --verify \
    > "$TMP/$d.log" 2>&1
  enc_rc=$?
  if [ $enc_rc -ne 0 ]; then
    echo "FAIL check-108: $d encode failed (rc=$enc_rc, log tail below)"
    tail -5 "$TMP/$d.log"
    exit 1
  fi
  # the 4 planes + the sidecar, byte-for-byte
  for f in "$GOLD/$d"/*; do
    b="$(basename "$f")"
    if [ ! -f "$TMP/$d/$b" ]; then
      echo "FAIL check-108: $d output missing: $b"
      miss=$((miss+1)); continue
    fi
    if cmp -s "$f" "$TMP/$d/$b"; then
      ok=$((ok+1))
    else
      echo "FAIL check-108: $d mismatch: $b"
      miss=$((miss+1))
    fi
  done
  for f in "$TMP/$d"/*.jxl; do
    s=$(stat -f%z "$f"); tot=$((tot+s))
  done
done
if [ "$ok" -ne 10 ] || [ "$miss" -ne 0 ] || [ "$tot" -ne "$EXPECTED_TOTAL" ]; then
  echo "FAIL check-108: oracle $ok/10 identical, total $tot B (expected 10/10, $EXPECTED_TOTAL B)"
  exit 1
fi
echo "oracle108: $ok/10 byte-identical (8 .jxl + 2 sidecars), total $tot B"
echo "ci check-108: ALL PASS (cjxl/djxl pinned, oracle108 10/10 @ $EXPECTED_TOTAL B)"
exit 0
