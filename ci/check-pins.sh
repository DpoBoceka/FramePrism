#!/usr/bin/env bash
# check-pins.sh — version-pin assertions (the byte-identity contracts).
#
# Reads pins.tsv (same dir) and probes each row:
#   - version-contains <flag>: run <bin> <flag>, the FIRST line must
#     CONTAIN the expected string (a version+commit is the contract —
#     a version drift would silently change archive bytes).
#   - lock-grep <crate>: the expected version must live in
#     tool/Cargo.lock's entry for <crate> (the IN-PROCESS component
#     pins — the bake container is built by the tar/zstd crates, not
#     system tools, so the pin source is the lock, not a
#     `--version` probe). The crate-name→version read is an awk pass
#     over the lock's `[[[package]]]` blocks (name line → the next
#     version line, exact equality). The zstd-sys row is special:
#     the sys-crate version carries the bundled libzstd version as a
#     `+zstd.<libzstd>` suffix (the zstd-sys convention; the libzstd
#     source is the `zstd-sys` crate's vendored C tree at exactly that
#     version) — the expected is asserted against the SUFFIX, so the
#     row pins the libzstd (the bytes' actual producer), not the
#     sys-crate wrapper. Missing lock / missing entry / mismatch = a
#     named FAIL (no silent skip).
#   - sha256-equal: the expected column IS the sha256 hex — the
#     BYTE-IDENTITY pin. The probed file resolves exactly like the
#     cjxl/djxl version row does (env override > the committed
#     default at deps/pinned-binaries/) so the sha pin covers the
#     SAME binary the version pin checks. Portable hashing (shasum
#     -a 256, sha256sum fallback); neither tool present = a named
#     FAIL (no silent skip).
#   - toml-grep: the repo tool/Cargo.toml must carry the expected
#     version line.
#   - pc-grep <repo-relative .pc path>: the FIRST `Version:` line of
#     the pkgconfig file, prefix-stripped + trimmed, must EQUAL the
#     expected version — the same read tool/build.rs does for the
#     reports' build-time fact line (the pin and the report line read
#     the same fact; the two surfaces cannot drift independently). The
#     row: turbojpeg (deps/.jpeg-prefix — the committed patched prefix
#     the byte contract links). Missing file / no Version: line /
#     mismatch = a named FAIL.
#   - tree-sha256: the expected column IS the sha256 hex of the
#     CANONICAL TREE HASH of a committed directory (find -type f |
#     LC_ALL=C sort | per-file sha256 | sha256 of that listing —
#     deterministic; xargs may split into several hash invocations
#     but the concatenated per-file lines stay in sorted order).
#     The rows: advisory-db (deps/rustsec-advisory-db, the pinned
#     rustsec/advisory-db snapshot), fuzz-corpus (ci/fuzz-corpus, the
#     committed fuzz fixtures + base + generator), turbojpeg-prefix
#     (deps/.jpeg-prefix/{lib,include} — the byte contract's build
#     input, the TWO committed dirs; the pin is the sha256 of the two
#     single-dir canonical tree hashes), jxl-libs (deps/.jxl-libs — the
#     pinned cjxl/djxl binaries' runtime dylib home: the 3 committed
#     libjxl 0.12 dylibs; the binaries' dead baked LC_RPATH is resolved
#     via DYLD_FALLBACK_LIBRARY_PATH=deps/.jxl-libs, the named export
#     line in this script + check-108.sh). A drift (an unstaged db
#     refresh, a changed fixture, a rebuilt prefix) is a named FAIL.
#   - probed-by-check.sh: recorded expectation, asserted by check.sh
#     itself (the suite gate line / the oracle total / the pinned fuzz
#     outcome line) — OK by record, never a silent skip.
# A missing binary is a named FAIL (the pin cannot be verified).
# No network. Exit: 0 all OK, 1 any FAIL (every FAIL named).
#
# CLI: check-pins.sh [--repo <path>]
#   --repo       repo root (default: this script's grandparent — ci/
#                sits at the repo root of the frameprism project)
# Env: CI_CJXL_BIN / CI_DJXL_BIN override the libjxl tool paths
#      (the committed defaults: deps/pinned-binaries/{cjxl,djxl} —
#      the pinned v0.12.0 1cad73c build; the byte-identity shas are
#      pinned alongside the version rows in pins.tsv);
#      CI_CARGO_AUDIT_BIN overrides the cargo-audit binary (the
#      committed default: deps/pinned-binaries/cargo-audit).

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
PINS="$SCRIPT_DIR/pins.tsv"

# The libjxl 0.12 runtime dylib home (deps/.jxl-libs/ — the committed pin,
# see deps/README.md): the pinned cjxl/djxl binaries carry a dead baked
# LC_RPATH (the rawcodecs build dir, since pruned), so dyld resolves their
# @rpath/libjxl* references
# through this last-resort fallback. Appended to any existing value
# (bash 3.2-portable).
export DYLD_FALLBACK_LIBRARY_PATH="$REPO/deps/.jxl-libs${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    *) echo "check-pins: unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -f "$PINS" ] || { echo "check-pins: pins file not found: $PINS" >&2; exit 1; }

ok=0; fail=0; n=0
check_one() {  # $1 = label, $2 = bin (resolved path), $3 = flag; $component/$expected from the loop (dynamic scope)
  local label="$1" bin="$2" flag="$3" line1
  if [ ! -x "$bin" ]; then
    echo "PIN FAIL $component :: expected $expected, got missing binary ($label: ${bin:-unresolved})"
    return 1
  fi
  line1="$("$bin" "$flag" 2>&1 | head -1)"
  case "$line1" in
    *"$expected"*) echo "PIN OK $component :: $line1"; return 0 ;;
    *) echo "PIN FAIL $component :: expected $expected, got ($label) $line1"; return 1 ;;
  esac
}
while IFS=$'\t' read -r component expected probe note; do
  [ "$component" = "component" ] && continue
  n=$((n+1))
  probe_type="${probe%% *}"
  probe_flag="${probe#* }"

  if [ "$probe_type" = "version-contains" ]; then
    row_ok=1
    case "$component" in
      cjxl/djxl)
        CJXL_BIN="${CI_CJXL_BIN:-$REPO/deps/pinned-binaries/cjxl}"
        DJXL_BIN="${CI_DJXL_BIN:-$REPO/deps/pinned-binaries/djxl}"
        check_one cjxl "$CJXL_BIN" "$probe_flag" || row_ok=0
        check_one djxl "$DJXL_BIN" "$probe_flag" || row_ok=0
        ;;
      cargo-audit)
        AUDIT_BIN="${CI_CARGO_AUDIT_BIN:-$REPO/deps/pinned-binaries/cargo-audit}"
        check_one cargo-audit "$AUDIT_BIN" "$probe_flag" || row_ok=0
        ;;
      python3)
        PYTHON3_BIN="$(command -v python3 || true)"
        check_one python3 "$PYTHON3_BIN" "$probe_flag" || row_ok=0 ;;
      *) echo "PIN FAIL $component :: unsupported probe for a version row: $probe" >&2; row_ok=0 ;;
    esac
    if [ "$row_ok" = "1" ]; then ok=$((ok+1)); else fail=$((fail+1)); fi
    continue
  fi

  if [ "$probe_type" = "lock-grep" ]; then
    # The in-process component pin: the version must
    # live in tool/Cargo.lock's entry for the named crate (the
    # container bytes are a pure function of the crate/lib versions —
    # no system tool in the loop; the fstool row pins the
    # bake --iso writer crate — the image's record layout is a pure
    # function of the crate version, the record-date fields riding the
    # pin-times pass's epoch constant). The lock's package block format:
    #   name = "<crate>"
    #   version = "<ver>"
    # (name line → the next version line). The zstd-sys row pins the
    # LIBZSTD (the `+zstd.<libzstd>` suffix — the sys-crate version
    # carries the bundled libzstd's version; the libzstd source is
    # the zstd-sys crate's vendored C tree at exactly that version).
    lock_name="$probe_flag"
    LOCK="$REPO/tool/Cargo.lock"
    if [ ! -f "$LOCK" ]; then
      echo "PIN FAIL $component :: expected $expected, got missing lock ($LOCK)"
      fail=$((fail+1)); continue
    fi
    ver="$(awk -v c="\"$lock_name\"" '$1=="name" && $3==c { getline; if ($1=="version") { v=$3; gsub(/\"/,"",v); print v; exit } }' "$LOCK")"
    if [ -z "$ver" ]; then
      echo "PIN FAIL $component :: expected $expected, got no $lock_name entry in $LOCK"
      fail=$((fail+1)); continue
    fi
    actual="$ver"
    if [ "$lock_name" = "zstd-sys" ]; then
      actual="${ver#*+zstd.}"
    fi
    case "$actual" in
      "$expected")
        if [ "$lock_name" = "zstd-sys" ]; then
          echo "PIN OK $component :: zstd-sys $ver (tool/Cargo.lock — the bundled libzstd $actual)"
        else
          echo "PIN OK $component :: $lock_name $actual (tool/Cargo.lock)"
        fi
        ok=$((ok+1)) ;;
      *)
        echo "PIN FAIL $component :: expected $expected, got ($LOCK $lock_name) $actual"
        fail=$((fail+1)) ;;
    esac
    continue
  fi

  if [ "$probe_type" = "sha256-equal" ]; then
    # the BYTE-IDENTITY pin: expected = the sha256 hex; the file
    # resolves exactly like the version row (env override > the
    # committed default) — the sha pin covers the SAME binary.
    case "$component" in
      cjxl-sha256) SHA_PROBE_BIN="${CI_CJXL_BIN:-$REPO/deps/pinned-binaries/cjxl}" ;;
      djxl-sha256) SHA_PROBE_BIN="${CI_DJXL_BIN:-$REPO/deps/pinned-binaries/djxl}" ;;
      cargo-audit-sha256) SHA_PROBE_BIN="${CI_CARGO_AUDIT_BIN:-$REPO/deps/pinned-binaries/cargo-audit}" ;;
      *) echo "PIN FAIL $component :: unsupported component for a sha256-equal row: $probe"; fail=$((fail+1)); continue ;;
    esac
    if [ ! -f "$SHA_PROBE_BIN" ]; then
      echo "PIN FAIL $component :: expected $expected, got missing file ($SHA_PROBE_BIN)"
      fail=$((fail+1)); continue
    fi
    SHA_TOOL=""
    if command -v shasum >/dev/null 2>&1; then
      SHA_TOOL="shasum -a 256"
    elif command -v sha256sum >/dev/null 2>&1; then
      SHA_TOOL="sha256sum"
    fi
    if [ -z "$SHA_TOOL" ]; then
      echo "PIN FAIL $component :: expected $expected, got no hash tool (shasum and sha256sum both missing)"
      fail=$((fail+1)); continue
    fi
    actual="$( $SHA_TOOL "$SHA_PROBE_BIN" 2>/dev/null | head -1 | awk '{print $1}' )"
    case "$actual" in
      "$expected")
        echo "PIN OK $component :: $actual ($SHA_PROBE_BIN)"; ok=$((ok+1)) ;;
      *)
        echo "PIN FAIL $component :: expected $expected, got $actual ($SHA_PROBE_BIN)"; fail=$((fail+1)) ;;
    esac
    continue
  fi

  if [ "$probe_type" = "toml-grep" ]; then
    tfile="$REPO/tool/Cargo.toml"
    hit="$(grep -m1 "version = \"$expected\"" "$tfile" 2>/dev/null || true)"
    if [ -n "$hit" ]; then
      echo "PIN OK $component :: $hit ($tfile)"
      ok=$((ok+1))
    else
      echo "PIN FAIL $component :: expected $expected, got no match in $tfile"
      fail=$((fail+1))
    fi
    continue
  fi

  if [ "$probe_type" = "pc-grep" ]; then
    # the version fact the byte contract links: the FIRST `Version:`
    # line of the .pc at probe_flag (repo-relative), prefix-stripped +
    # trimmed — the same read tool/build.rs does for the reports'
    # build-time fact line (the pin and the report cannot drift
    # independently). Missing file / no Version: line / mismatch = a
    # named FAIL.
    pcfile="$REPO/$probe_flag"
    if [ ! -f "$pcfile" ]; then
      echo "PIN FAIL $component :: expected $expected, got missing file ($pcfile)"
      fail=$((fail+1)); continue
    fi
    actual="$(awk '/^Version:/ {sub(/^Version:/, ""); gsub(/^[ \t]+|[ \t]+$/, ""); print; exit}' "$pcfile")"
    case "$actual" in
      "$expected")
        echo "PIN OK $component :: Version: $actual ($pcfile)"; ok=$((ok+1)) ;;
      *)
        echo "PIN FAIL $component :: expected $expected, got ${actual:-'(no Version: line)'} ($pcfile)"
        fail=$((fail+1)) ;;
    esac
    continue
  fi

  if [ "$probe_type" = "tree-sha256" ]; then
    # the CANONICAL TREE HASH of a committed directory (deterministic:
    # sorted file list, per-file sha256, sha256 of the concatenated
    # listing). Missing dir / missing hash tool = a named FAIL.
    TREE_TOOL=""
    if command -v shasum >/dev/null 2>&1; then
      TREE_TOOL="shasum -a 256"
    elif command -v sha256sum >/dev/null 2>&1; then
      TREE_TOOL="sha256sum"
    fi
    if [ -z "$TREE_TOOL" ]; then
      echo "PIN FAIL $component :: expected $expected, got no hash tool (shasum and sha256sum both missing)"
      fail=$((fail+1)); continue
    fi
    if [ "$component" = "turbojpeg-prefix" ]; then
      # the byte contract's build input = the TWO committed dirs
      # (lib/ + include/ — bin/ + share/ are build install outputs,
      # deliberately out of the pin so a local rebuild that only ADDS
      # them cannot move it). The pin = sha256 of the two single-dir
      # canonical tree hashes.
      TJ_LIB="$REPO/deps/.jpeg-prefix/lib"
      TJ_INC="$REPO/deps/.jpeg-prefix/include"
      if [ ! -d "$TJ_LIB" ] || [ ! -d "$TJ_INC" ]; then
        echo "PIN FAIL $component :: expected $expected, got missing dir ($TJ_LIB + $TJ_INC)"
        fail=$((fail+1)); continue
      fi
      H1="$(cd "$TJ_LIB" && find . -type f | LC_ALL=C sort | xargs $TREE_TOOL | $TREE_TOOL | awk '{print $1}')"
      H2="$(cd "$TJ_INC" && find . -type f | LC_ALL=C sort | xargs $TREE_TOOL | $TREE_TOOL | awk '{print $1}')"
      actual="$(printf '%s\n%s\n' "$H1" "$H2" | $TREE_TOOL | awk '{print $1}')"
      case "$actual" in
        "$expected")
          echo "PIN OK $component :: $actual ($TJ_LIB + $TJ_INC)"; ok=$((ok+1)) ;;
        *)
          echo "PIN FAIL $component :: expected $expected, got $actual ($TJ_LIB + $TJ_INC)"; fail=$((fail+1)) ;;
      esac
      continue
    fi
    case "$component" in
      advisory-db) TREE_DIR="$REPO/deps/rustsec-advisory-db" ;;
      fuzz-corpus) TREE_DIR="$REPO/ci/fuzz-corpus" ;;
      jxl-libs)    TREE_DIR="$REPO/deps/.jxl-libs" ;;
      *) echo "PIN FAIL $component :: unsupported component for a tree-sha256 row: $probe"; fail=$((fail+1)); continue ;;
    esac
    if [ ! -d "$TREE_DIR" ]; then
      echo "PIN FAIL $component :: expected $expected, got missing dir ($TREE_DIR)"
      fail=$((fail+1)); continue
    fi
    actual="$(cd "$TREE_DIR" && find . -type f | LC_ALL=C sort | xargs $TREE_TOOL | $TREE_TOOL | awk '{print $1}')"
    case "$actual" in
      "$expected")
        echo "PIN OK $component :: $actual ($TREE_DIR)"; ok=$((ok+1)) ;;
      *)
        echo "PIN FAIL $component :: expected $expected, got $actual ($TREE_DIR)"; fail=$((fail+1)) ;;
    esac
    continue
  fi

  if [ "$probe_type" = "probed-by-check.sh" ]; then
    echo "PIN OK $component :: recorded — probed by check.sh ($note)"
    ok=$((ok+1))
    continue
  fi

  echo "PIN FAIL $component :: unknown probe type: $probe_type"
  fail=$((fail+1))
done < "$PINS"

echo "pins: $ok/$n OK"
[ "$fail" = "0" ] && exit 0 || exit 1
