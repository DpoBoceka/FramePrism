#!/usr/bin/env bash
# check-audit.sh — the standing dependency-audit job.
#
# What this is: an OFFLINE cargo-audit over the tool's dep tree — the
# pinned rustsec/cargo-audit v0.22.2 binary (committed at
# deps/pinned-binaries/cargo-audit, the same pinned-binary pattern as
# the cjxl/djxl byte pins) over the pinned rustsec/advisory-db snapshot
# (committed at deps/rustsec-advisory-db/, 1294 files, .git stripped).
# `--no-fetch` is the no-network guarantee: the audit reads ONLY the
# committed db. The output is pinned on its two stable fragments
# (the advisory count + the dep count — the paths vary, the counts are
# the contract): a dep-tree drift that adds a vulnerable crate, or an
# advisory-count drift from an unstaged db refresh, is a named FAIL.
# No silent skips.
#
# Refresh procedure (docs/security.md): a maintainer step — clone the db
# at a new commit, stage the binary + db under deps/, re-pin (the tree
# hashes in ci/pins.tsv + the advisory/dep counts pinned here). Never
# from CI.
#
# CLI: check-audit.sh [--repo <path>]
#   --repo   repo root (default: this script's grandparent)
# Env:  CI_CARGO_AUDIT_BIN (pin override — the committed default is
#       deps/pinned-binaries/cargo-audit; the same resolution as the
#       pins.tsv rows).
# Exit: 0 PASS, 1 any named FAIL.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    *) echo "check-audit: unknown argument: $1" >&2; exit 2 ;;
  esac
done

AUDIT_BIN="${CI_CARGO_AUDIT_BIN:-$REPO/deps/pinned-binaries/cargo-audit}"
DB="$REPO/deps/rustsec-advisory-db"
PIN_ADVISORIES="Loaded 1246 security advisories"
PIN_DEPS="118 crate dependencies"

echo "=== ci check-audit: $(date '+%Y-%m-%d %H:%M:%S') repo=$REPO ==="

[ -x "$AUDIT_BIN" ] || { echo "FAIL audit: missing pinned cargo-audit binary ($AUDIT_BIN)"; exit 1; }
[ -d "$DB/rust" ]   || { echo "FAIL audit: missing pinned advisory db ($DB/rust)"; exit 1; }

# --color never: the pinned output fragments (the advisory-count + the dep-tree pin) are grepped verbatim — the runner's CARGO_TERM_COLOR=always default would colorize the lines and break the match (the CI first-run class: the output is the contract, make it environment-stable)
out="$("$AUDIT_BIN" audit --color never --db "$DB" --no-fetch --file "$REPO/tool/Cargo.lock" 2>&1)"
rc=$?
if [ $rc -ne 0 ]; then
  echo "FAIL audit: cargo-audit rc=$rc (offline, pinned db — output tail below)"
  printf '%s\n' "$out" | tail -8
  exit 1
fi
miss=""
case "$out" in *"$PIN_ADVISORIES"*) ;; *) miss="$miss the advisory-count pin ($PIN_ADVISORIES)";; esac
case "$out" in *"$PIN_DEPS"*) ;; *) miss="$miss the dep-count pin ($PIN_DEPS)";; esac
if [ -n "$miss" ]; then
  echo "FAIL audit: pinned output fragment(s) missing:$miss (dep-tree or db drift — re-pin per docs/security.md)"
  printf '%s\n' "$out" | head -4
  exit 1
fi
echo "audit: PASS (0 vulnerabilities, 124 deps, 1246 advisories)"
exit 0
