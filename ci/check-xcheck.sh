#!/usr/bin/env bash
# check-xcheck.sh — the JXL independent-decoder cross-check.
#
# What this is: the independent-decoder gate for the committed JXL
# oracle108 gold (the "named residual" closed — the JXL tier's
# integrity check, cf. docs/jxl-tier.md). The existing `--verify`
# round-trips the JXL bytes with djxl — the SAME libjxl build as
# cjxl — so a bug shared by that pair would not be caught. This gate
# decodes the 8 gold planes (ci/oracle108/gold/{f10,f8}, 4 × .jxl per
# frame) with jxl-oxide — a pure-Rust JXL decoder, a SEPARATE
# implementation from the pinned libjxl pair — and proves the decoded
# pixels are byte-exact against the source-frame planes derived from
# the committed source DNGs (the j92 round-trip: encode --verify →
# the pure-Rust golden-model tile decode; no libjxl anywhere in the
# source-side path). The harness (ci/jxl-xcheck/ — a SEPARATE crate,
# so the tool's dep tree + the audit baseline are untouched; the path
# dependency flows harness→tool only) also asserts the lock pin
# (name = "jxl-oxide" + version = "0.12.6" in the COMMITTED
# ci/jxl-xcheck/Cargo.lock) BEFORE any decode — 0.12.6 = the latest
# release, carrying the integer-overflow fixes
# (GHSA-5pmv-rx8r-wmv5 jxl-grid, GHSA-2v8p-fqpx-2q3w jxl-modular, +
# the framebuffer soundness fix). The harness prints the named lines
# (per-frame src sha256 + j92 round-trip, per-plane OK, the 8/8 line,
# the version facts); a non-zero harness rc is a named FAIL here.
# Any failure is a named FAIL + rc=1 — no silent skips.
#
# CLI: check-xcheck.sh [--repo <path>]
#   --repo   repo root (default: this script's grandparent)
# Env:  JPEG_TURBO_PREFIX (default <repo>/deps/.jpeg-prefix),
#       CARGO_TARGET_DIR (default <repo>/target) — the shared dir;
#       the tool's deps are already built there (a check.sh run).
# Exit: 0 ALL PASS, 1 any named FAIL.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    *) echo "check-xcheck: unknown argument: $1" >&2; exit 2 ;;
  esac
done

export JPEG_TURBO_PREFIX="${JPEG_TURBO_PREFIX:-$REPO/deps/.jpeg-prefix}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO/target}"

echo "=== ci check-xcheck: $(date '+%Y-%m-%d %H:%M:%S') repo=$REPO ==="

# --- step 1: build the harness (release; the lock pin is committed) ---
echo "--- build the harness (release) ---"
if ! cargo build --release --manifest-path "$SCRIPT_DIR/jxl-xcheck/Cargo.toml"; then
  echo "FAIL check-xcheck: cargo build --release (ci/jxl-xcheck) failed"
  exit 1
fi
HARNESS="$CARGO_TARGET_DIR/release/jxl-xcheck"
[ -x "$HARNESS" ] || { echo "FAIL check-xcheck: harness binary missing: $HARNESS"; exit 1; }

# --- step 2: the frameprism release binary is current (the check-108.sh
# step-2 pattern — no-op when check.sh's step 2 already built it) ---
echo "--- build the tool (release; no-op when current) ---"
if ! (cd "$REPO/tool" && cargo build --release); then
  echo "FAIL check-xcheck: cargo build --release (tool) failed"
  exit 1
fi
BIN="$CARGO_TARGET_DIR/release/frameprism"
[ -x "$BIN" ] || { echo "FAIL check-xcheck: tool binary missing: $BIN"; exit 1; }

# --- step 3: the cross-check (the harness prints the named lines) -------
if ! "$HARNESS"; then
  echo "FAIL check-xcheck: the xcheck harness failed (the named xcheck FAIL is above)"
  exit 1
fi
echo "ci check-xcheck: ALL PASS (jxl-oxide 0.12.6 vs the source-derived planes, 8/8 byte-exact)"
exit 0
