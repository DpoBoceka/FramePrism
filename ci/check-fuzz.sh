#!/usr/bin/env bash
# check-fuzz.sh — the C-boundary fuzz corpus job.
#
# What this is: the pinned-outcome regression lock over the committed
# 25-fixture corpus (ci/fuzz-corpus/ — class A synthetic single-strip
# J92 = the turbojpeg C boundary, class B synthetic tiled-base mutations =
# the golden-model Rust decode path, class C synthetic garbage TIFF =
# the read_meta parse). The harness (tool/tests/fuzz_ljpeg.rs, std
# only) runs `frameprism decode <entry> <fresh outdir>` per fixture and
# asserts the observed class against ci/fuzz-corpus/expected.tsv; a
# corrupted write or an input mutation is an automatic FAIL (never
# pinnable). This script pins the harness's deterministic summary line
# (the ci/pins.tsv `fuzz-outcome` row) — drift is a named FAIL.
# The job is outside the `--lib` suite scope (the 350/0/1 pin is
# untouched). No silent skips.
#
# CLI: check-fuzz.sh [--repo <path>]
#   --repo   repo root (default: this script's grandparent)
# Env:  JPEG_TURBO_PREFIX (default <repo>/deps/.jpeg-prefix),
#       CARGO_TARGET_DIR (default <repo>/target) — when invoked from
#       check.sh, step 2 already built the release bin (the build below
#       is a no-op); standalone runs build first (the check-108.sh
#       pattern). FUZZ_CORPUS (default <repo>/ci/fuzz-corpus).
# Exit: 0 PASS, 1 any named FAIL.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    *) echo "check-fuzz: unknown argument: $1" >&2; exit 2 ;;
  esac
done

export JPEG_TURBO_PREFIX="${JPEG_TURBO_PREFIX:-$REPO/deps/.jpeg-prefix}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO/target}"
CORPUS="${FUZZ_CORPUS:-$REPO/ci/fuzz-corpus}"
PIN_LINE="fuzz: 25 entries, 24 refused, 1 ok, 0 crash, 0 corrupted-write, 0 input-mutated"

echo "=== ci check-fuzz: $(date '+%Y-%m-%d %H:%M:%S') repo=$REPO ==="

[ -f "$CORPUS/expected.tsv" ] || { echo "FAIL fuzz: missing corpus pin ($CORPUS/expected.tsv)"; exit 1; }

# --- build (release; no-op when check.sh's step 2 already built) ---
echo "--- build (release) ---"
if ! (cd "$REPO/tool" && cargo build --release); then
  echo "FAIL fuzz: cargo build --release failed"
  exit 1
fi

out="$(cd "$REPO/tool" && FUZZ_CORPUS="$CORPUS" cargo test --release --test fuzz_ljpeg -- --nocapture 2>&1)"
rc=$?
if [ $rc -ne 0 ]; then
  echo "FAIL fuzz: harness rc=$rc (per-entry report + failures below)"
  printf '%s\n' "$out" | tail -30
  exit 1
fi
case "$out" in
  *"$PIN_LINE"*) ;;
  *)
    echo "FAIL fuzz: pinned outcome line missing — expected: $PIN_LINE"
    printf '%s\n' "$out" | grep -E '^(fuzz |fuzz:)' | tail -27
    exit 1 ;;
esac
echo "fuzz: PASS (25/25 class-pinned, 0 crash, 0 corrupted-write, 0 input-mutated)"
exit 0
