#!/usr/bin/env bash
# check-oss-clean.sh — the OSS-clean grep gate (the token-family scan).
#
# What this is: the re-runnable grep gate that re-asserts the OSS-clean
# invariant at every gate run — the public tree carries no
# internal-project state. It scans the FULL tree (.git + target + the
# vendored deps subdirectories EXCLUDED — the vendored third-party
# byte-contract inputs; the first-party deps files — the *.sh, README.md,
# *.patch, fetch.sh — are SCANNED) for the token family:
# the item numbers, the M0 census token, the ADDENDUM marker, the ADR
# IDs (the dashed + bare forms), the owner/PM/ruling vocabulary, the
# house-lane sense of "lane", the G1–G4 gate-vocabulary hits (allowed
# only as the lossydct structural-gate class), the byte-freeze +
# re-onboard + A/B + tree-ops chronology tokens, the internal dates (the
# dashed form + the 8-digit compact form — the compact form is
# boundary-guarded so it cannot fire inside a longer hex/numeric run),
# the reference product name (slimraw), the old product name (cdngzip),
# the F-\d defect ids, the house/plateau/2076 / ROADMAP / Phase-\d /
# task-\d vocabulary, the internal run paths (runs/20\d\d-...), the
# machine home paths (~/), the internal 7-hex commit-sha class, and the
# item-109 fix family: the product-pointer prose (the space + hyphen
# forms), the reference provenance, the old reference-dct wire-format
# name (guards the rename), the internal knowledge-sheet paths, the era
# refs (the 09-NN idiom), the v1 plan refs (the narrow forms — a bare
# "v1" is a version token, not a leak), the internal-structure
# voice (the narrow form — a bare "worker" is the tool's own module
# name, not a leak), and the provenance-pointer class (the internal-
# records pointer + the available-on-request clause — the final-pass
# standing invariant).
#
# Named exception classes (ALLOWED — counted + named in the gate output,
# never a FAIL). Each class is a functional public surface, not a leak:
#   E1  the FPTEST fixture names' pinned fictional capture date
#       (20000101 compact / 2000-01-01 dashed — the camera naming
#       contract; any OTHER 8-digit / dashed date is a hit)
#   E2  the legitimate 7-hex public identifiers: the pinned cjxl build
#       id (1cad73c — functional version-pin data) + the ed25519 curve
#       name (the provenance module's signature curve + the dependency
#       package names) + the committed libjpeg patch's index-line blob
#       shas (functional patch metadata — public upstream libjpeg-turbo
#       blob ids)
#   E3  the H1 blocklist's functional literals — the gate's OWN guard
#       data: the quoted-literal array entries in
#       tool/src/main.rs + tool/src/cli_model.rs (the internal-token
#       vocabulary the rendered-surface blocklist guards against; the
#       reference product name is NOT among them — if it re-appears it
#       is a hit)
#   E4  the lossydct structural gates G1–G4 — the codebase's OWN
#       documented guarantee vocabulary (docs/architecture.md + the
#       tool sources that name the gates they enforce): the gate name
#       is not a leak, the re-onboarding narrative sense is
#   E5  the plateau_snap DCT-transform vocabulary — the codebase's own
#       documented algorithm term (tool/src/lossydct.rs + the
#       vdct_probe research bin that documents it); the H1 blocklist
#       keeps the term off the rendered help surface
#   E6  the numeric literal 2076 on a PURE-NUMERIC line (the DCT curve
#       table data — not the internal token)
#   E7  the class-A/B decode-refusal taxonomy in docs/security.md +
#       the fuzz-corpus pin note in ci/pins.tsv (the codebase's own
#       documented refusal-class names; the ops A/B-test sense is the
#       leak)
#   E8  NOTICE.md — verbatim third-party license text (legal boilerplate
#       that cannot be edited; the rendered-surface tripwire already
#       encodes this tolerance)
#   E9  the GitHub Actions runner cache paths (~/.cargo/*) in
#       .github/workflows/ci.yml — the runner's home, not a machine
#       home
#   E10 the gate's own pattern table (ci/check-oss-clean.sh — the
#       scanner's family literals are the gate, not tree content)
#   E11 the camera-named DNG capture dates in fixture/corpus file names
#       (the A001_\d{3}_YYYYMMDD + A_YYYYMMDD + FPTEST_\d{3}_YYYYMMDD
#       naming contract — the pinned corpus' camera naming + the
#       synthetic test fixtures' names)
#   E12 the product's documented user-home state paths (~/.frameprism/
#       ledger/status + the documented Resolve log path — product
#       behavior on the user's own machine, a generic home, not a
#       machine-specific leak)
#   E13 the lossy encoder's D1-D5 defect/decision taxonomy (the
#       codebase's own domain vocabulary in the tool sources — the D1
#       CFA-band defect, the D2 pre-domain transform, the D3 seam, the
#       D4 legacy container, the D5 container version fields; the ADR
#       form D-NN-N stays a hit)
#   E14 the documented pinned epoch constant in tool/src/iso_times.rs
#       (1789344000 = 2026-09-14 00:00:00 UTC — the MHL record-date
#       epoch; a functional product constant, not internal chronology)
#   E15 the MHL reference-implementation context (the MHL module's refs
#       to the spec's reference implementation — a third-party public
#       tool, the owner's ruling — + the offload MHL report's c4-shape
#       refs; file-scoped to tool/src/ascmhl.rs +
#       tool/src/offload/report.rs, the possessive form only)
#
# The scan is python3 stdlib-only (the runner-preinstalled interpreter —
# the same dependency posture as the fixture-provenance step). The scan
# is read-only against the tree.
#
# CLI: check-oss-clean.sh [--repo <path>] [--report]
#   --repo    repo root (default: this script's parent)
#   --report  the scan mode: print the full per-file/per-line hit table
#             + the per-class exception table, NEVER fail (the R1/R4
#             scan surface; the gate mode is the default)
# Exit: 0 clean (every hit inside the exception classes), 1 any hit
#       outside them, 2 usage error.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --report) REPORT=1; shift ;;
    *) echo "check-oss-clean: unknown argument: $1" >&2; exit 2 ;;
  esac
done

python3 - "$REPO" "$REPORT" <<'PYEOF'
import os
import re
import sys

repo = os.path.abspath(sys.argv[1])
report_mode = sys.argv[2] == "1"

EXCLUDE_DIRS = {".git", "target"}
# The vendored deps subdirectories (the third-party byte-contract inputs —
# the committed pinned binaries, the built jpeg prefix, the jxl dylibs, the
# advisory-DB snapshot; the spec-named deps/libjpeg-turbo + deps/dng_sdk_1_7_1
# are fetched by deps/fetch.sh in the dev tree — not committed here — and
# stay excluded if present). Everything else under deps/ is FIRST-PARTY
# (the build/fetch scripts, the patch, the README) and stays SCANNED — the
# wholesale deps/ exclusion is what let deps/build-libjpeg.sh's product
# pointer ride through every gate run.
DEPS_VENDORED = {
    "deps/.jpeg-prefix",
    "deps/.jxl-libs",
    "deps/pinned-binaries",
    "deps/rustsec-advisory-db",
    "deps/libjpeg-turbo",
    "deps/dng_sdk_1_7_1",
}

# The token family (the R1 spec family; the item pattern carries the
# documented "items" plural extension — the pins-suite-line "items 7-106"
# + the build.rs "items131415" surface the audit table names).
#
# date-compact is boundary-guarded: an 8-digit run is only a date when
# it stands alone — inside a longer hex run (a sha256 checksum) or a
# longer numeric run (a 16-digit ISO datetime) it is data, not a date.
FAMILY = [
    ("item-number", re.compile(r"item[s]?[ _-]?\d+", re.I)),
    ("M0", re.compile(r"\bM0\b")),
    ("ADDENDUM", re.compile(r"ADDENDUM")),
    ("adr-dashed", re.compile(r"\bD-\d+-\d+")),
    ("adr-bare", re.compile(r"\bD\d+[a-z]?\b")),
    ('owner', re.compile(r"\bowner(?:'s)?\b", re.I)),
    ("ruling", re.compile(r"\bruling", re.I)),
    ("PM", re.compile(r"\bPM\b")),
    ("lane", re.compile(r"\blanes?\b", re.I)),
    ("G1-4", re.compile(r"\bG[1-4]\b")),
    ("byte-freeze", re.compile(r"byte[- ]freeze", re.I)),
    ("re-onboard", re.compile(r"re[- ]?onboard", re.I)),
    ("A/B", re.compile(r"\bA/B\b")),
    ("date-dashed", re.compile(r"202[6-9]-\d{2}-\d{2}")),
    ("slimraw", re.compile(r"slimraw", re.I)),
    ("v1.10.0", re.compile(r"v1\.10\.0")),
    ("cdngzip", re.compile(r"cdngzip", re.I)),
    ("F-dash", re.compile(r"\bF-\d")),
    ("house", re.compile(r"\bhouse", re.I)),
    ("plateau", re.compile(r"plateau", re.I)),
    ("2076", re.compile(r"\b2076\b")),
    ("ROADMAP", re.compile(r"\bROADMAP\b", re.I)),
    ("Phase-N", re.compile(r"\bPhase \d", re.I)),
    ("task-N", re.compile(r"\btask \d", re.I)),
    ("tree-ops", re.compile(r"tree[- ]ops", re.I)),
    ("runs-path", re.compile(r"runs/20\d{2}")),
    ("home-path", re.compile(r"~/")),
    ("date-compact", re.compile(r"(?<![0-9a-zA-Z])202[6-9]\d{4}(?![0-9a-zA-Z])")),
    # date-dashed / date-compact are scoped to the project era (2026+):
    # pre-2026 dates (the MHL test-vector timeline 2025-09-16, the FPTEST
    # fictional capture date 2000-01-01) are fixture data, not internal
    # chronology.
    # sha7 requires at least one a-f letter: a bare 7-digit number (an
    # oracle byte count) is data, not a commit sha.
    ("sha7", re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{7}\b")),
    # The item-109 fix family (the PM-gate-caught residual classes — the
    # product-pointer prose, the old wire-format name, the internal-file
    # refs, the era refs, the v1 plan refs, the internal-structure voice).
    ("reference-product", re.compile(r"reference[- ]product", re.I)),
    ("reference-possessive", re.compile(r"the reference's", re.I)),
    ("reference-provenance", re.compile(r"reference provenance", re.I)),
    ("reference-dct", re.compile(r"reference-dct")),
    ("knowledge-path", re.compile(r"knowledge/[a-z0-9]")),
    ("era-ref", re.compile(r"\b09-\d{2} era")),
    ("v1-target", re.compile(r"v1 target")),
    ("for-v1", re.compile(r"for v1\b")),
    ("workers-embedded", re.compile(r"the worker's embedded")),
    # The provenance-pointer class (the item-109 final-pass invariant — the
    # class the external publication-readiness review + the PM's de-wrapped
    # scan both caught; it survived every earlier gate run because the
    # family never carried it): the internal-records pointer + the
    # available-on-request clause.
    ("internal-records", re.compile(r"internal records", re.I)),
    ("available-on-request", re.compile(r"available on request", re.I)),
]

# E1 — the FPTEST fixture names' pinned fictional capture date (2000-01-01 /
# 20000101) — outside the 2026+ date scope; the exception is retained for the
# fixture-name idiom (the camera-named DNG idiom shares the guard).
E1_DASHED = "2000-01-01"
E1_COMPACT = "20000101"
# E2 — the legitimate 7-hex public identifiers (anywhere). The last four:
# the committed libjpeg patch's index-line blob shas (functional patch
# metadata — public upstream libjpeg-turbo blob ids; the patch is a
# committed byte-contract input and stays byte-untouched).
E2_SHA = {"1cad73c", "ed25519", "a064d4d", "120ff75", "ca156fb", "0bb0e41"}
# E3 — the H1 blocklist's functional literals (the gate's own guard
# data — the quoted-literal array entries). The reference product name
# is NOT in this set (ruling (a): it is a hit wherever it appears).
E3_FILES = {"tool/src/main.rs", "tool/src/cli_model.rs"}
E3_LITERAL = re.compile(
    r'^\s*"(ROADMAP|vendor|lane-P|bake-lane|owner-boarded|owner|plateau|'
    r"2076|D-21|D13|DIT|Phase 1|item 1|task 1)",
)
# E4 — the lossydct structural gates G1–G4 (the codebase's own
# documented gate vocabulary).
E4_G = re.compile(r"\bG[1-4]\b")
# E5 — the plateau_snap DCT-transform vocabulary (the algorithm's own
# term — lossydct + the probe bin that documents it + the worker
# encode path that names the clamp it inherits).
E5_FILES = {"tool/src/lossydct.rs", "tool/src/bin/vdct_probe.rs",
            "tool/src/worker/encode.rs"}
# E6 — the numeric literal 2076 on a pure-numeric line (the curve
# table — data, not the internal token).
E6_LINE = re.compile(r"^[\s\d,;()\[\].+\-/]+$")
# E7 — the class-A/B decode-refusal taxonomy (security.md + the
# fuzz-corpus pin note).
E7_FILES = {"docs/security.md", "ci/pins.tsv"}
# E8 — NOTICE.md (verbatim third-party license text).
E8_FILE = "NOTICE.md"
# E9 — the GitHub Actions runner cache paths.
E9_FILE = ".github/workflows/ci.yml"
# E10 — the gate's own pattern table.
E10_FILE = "ci/check-oss-clean.sh"
# E11 — the camera-named DNG capture dates (the corpus/fixture file-name
# naming contract).
# E11 — the camera-named fixture/corpus file-name idiom: an uppercase
# camera token (+ optional frame number or placeholder) directly
# preceding a compact capture date (the A001_001_20260701_000001.DNG
# corpus names, the synthetic B_/C_/X001_/FPTEST_ test fixtures, the
# clip-registry shot ids). A date in prose without the camera prefix
# still hits.
E11_CAM = re.compile(r"(?<![A-Z0-9])[A-Z][A-Z0-9]{0,3}_(?:(?:\d{3}|00X|\{i:03\})_)?(202[6-9]\d{4})(?![0-9])")
# E12 — the product's documented user-home state paths.
E12_HOME = re.compile(r"~/(?:\.frameprism/|Library/)")
# E13 — the lossy encoder's defect/decision taxonomy D1-D5 (the codebase's
# own domain vocabulary — the D1 CFA-band defect, the D2 pre-domain
# transform, the D3 seam, the D4 legacy container, the D5 container
# version fields; tool/ source only).
E13_D = {"D1", "D2", "D3", "D4", "D5"}
# E14 — the documented pinned epoch constant in tool/src/iso_times.rs
# (1789344000 = 2026-09-14 00:00:00 UTC — the MHL record-date epoch;
# a functional product constant, not internal chronology).
E14_FILE = "tool/src/iso_times.rs"
# E15 — the MHL reference-implementation context (file-scoped, the
# possessive form only — the MHL spec's reference implementation is a
# third-party public tool, the owner's ruling).
E15_FILES = {"tool/src/ascmhl.rs", "tool/src/offload/report.rs"}

e_names = {
    "E1": "the FPTEST pinned fictional capture date",
    "E2": "the legitimate 7-hex public identifiers (the cjxl build id + the ed25519 curve name + the libjpeg patch's index-line blob shas)",
    "E3": "the H1 blocklist functional literals (the gate's own guard data)",
    "E4": "the lossydct G1-G4 structural gate vocabulary",
    "E5": "the plateau_snap DCT-transform vocabulary",
    "E6": "the numeric literal 2076 (the DCT curve table data)",
    "E7": "the class-A/B decode-refusal taxonomy (docs/security.md)",
    "E8": "NOTICE.md (verbatim third-party license text)",
    "E9": "the GitHub Actions runner cache paths",
    "E10": "the gate's own pattern table",
    "E11": "the camera-named DNG capture dates (corpus/fixture file names)",
    "E12": "the product's documented user-home state paths",
    "E13": "the lossy encoder's D1-D5 defect/decision taxonomy (domain vocabulary)",
    "E14": "the documented pinned epoch constant (iso_times.rs, 1789344000 = 2026-09-14 UTC)",
    "E15": "the MHL reference-implementation context (the third-party public tool, the owner's ruling)",
}

hits = []           # (relpath, lineno, pattern, line)
e_counts = {k: 0 for k in e_names}
e_rows = {k: [] for k in e_names}   # (relpath, lineno, pattern) — the exception evidence
skipped_binary = 0

for dirpath, dirnames, filenames in os.walk(repo):
    rel_d = os.path.relpath(dirpath, repo).replace(os.sep, "/")
    dirnames[:] = sorted(d for d in dirnames
                         if d not in EXCLUDE_DIRS
                         and (rel_d + "/" + d) not in DEPS_VENDORED)
    for fn in sorted(filenames):
        full = os.path.join(dirpath, fn)
        rel = os.path.relpath(full, repo).replace(os.sep, "/")
        try:
            with open(full, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (UnicodeDecodeError, OSError):
            skipped_binary += 1
            continue
        # Wrap-dates: the line-based scan misses a dashed date split
        # across a line break ("... 2026-" / "/// 09-24 ...").
        for i in range(len(lines) - 1):
            if re.search(r"202[6-9]-$\s*$", lines[i]) and re.match(r"\s*[/#*]*\s*0\d-\d\d\b", lines[i + 1]):
                hits.append((rel, i + 1, "date-wrap", lines[i].rstrip("\n")))
                continue
        for i, line in enumerate(lines, 1):
            for pname, rx in FAMILY:
                for m in rx.finditer(line):
                    # JPEG marker hex (FF D8 / FF D9) — not an ADR id.
                    if pname == "adr-bare" and m.group(0) in ("D8", "D9"):
                        continue
                    e = None
                    # E8 / E10: whole-file exception classes.
                    if rel == E8_FILE:
                        e = "E8"
                    elif rel == E10_FILE:
                        e = "E10"
                    elif m.group(0) in (E1_DASHED, E1_COMPACT):
                        e = "E1"
                    elif pname == "sha7" and (m.group(0) in E2_SHA or re.fullmatch(r"f[0-9]{6}", m.group(0))):
                        e = "E2"
                    elif rel in E3_FILES and E3_LITERAL.match(line):
                        e = "E3"
                    elif E4_G.fullmatch(m.group(0)):
                        e = "E4"
                    elif pname == "plateau" and rel in E5_FILES:
                        e = "E5"
                    elif pname == "2076" and E6_LINE.match(line):
                        e = "E6"
                    elif pname == "A/B" and rel in E7_FILES and "class" in line.lower():
                        e = "E7"
                    elif pname == "home-path" and rel == E9_FILE and "~/." in line:
                        e = "E9" if re.search(r"~/\.cargo", line) else None
                    elif pname == "home-path" and E12_HOME.search(line):
                        e = "E12"
                    elif (pname == "adr-bare" and m.group(0) in E13_D
                          and rel.startswith("tool/")):
                        e = "E13"
                    elif (rel == E14_FILE
                          and pname in ("date-dashed", "date-compact")
                          and "epoch" in line.lower()):
                        e = "E14"
                    elif pname == "reference-possessive" and rel in E15_FILES:
                        e = "E15"
                    elif pname == "date-compact" and any(
                            c.group(1) == m.group(0)
                            for c in E11_CAM.finditer(line)):
                        e = "E11"
                    if e:
                        e_counts[e] += 1
                        e_rows[e].append((rel, i, pname))
                        continue
                    hits.append((rel, i, pname, line.rstrip("\n")))

if report_mode:
    print(f"# oss-clean scan (report mode) — repo={repo}")
    print(f"# files scanned: all text files, the vendored deps subdirs + .git + target/ excluded; binary files skipped: {skipped_binary}")
    for k in sorted(e_counts):
        print(f"# {k}={e_counts[k]} {e_names[k]}")
    print(f"# non-exception hits: {len(hits)}")
    by_file = {}
    for rel, lineno, pname, line in hits:
        by_file.setdefault(rel, []).append((lineno, pname, line))
    for rel in sorted(by_file):
        rows = by_file[rel]
        print(f"\n## {rel} — {len(rows)} hit line(s)")
        for lineno, pname, line in rows:
            print(f"  L{lineno} [{pname}] {line[:200]}")
    print("\n# exception evidence (per class):")
    for k in sorted(e_rows):
        if not e_rows[k]:
            continue
        print(f"\n# {k} ({e_counts[k]}): {e_names[k]}")
        for rel, lineno, pname in e_rows[k]:
            print(f"  {rel}:{lineno} [{pname}]")
    sys.exit(0)

if hits:
    print(f"FAIL oss-clean gate: {len(hits)} hit line(s) outside the named exception classes:")
    for rel, lineno, pname, line in hits:
        print(f"  {rel}:{lineno} [{pname}] {line[:160]}")
    summary = ", ".join(f"{k}={e_counts[k]}" for k in sorted(e_counts))
    print(f"(exception classes allowed: {summary})")
    sys.exit(1)

summary = ", ".join(f"{k}={e_counts[k]}" for k in sorted(e_counts) if e_counts[k])
print(
    f"oss-clean gate: PASS — 0 hits outside the exception classes "
    f"({summary or 'no exception hits'})"
)
sys.exit(0)
PYEOF
