# The JXL archival tier (`--codec jxl`)

The shipped surface is `--codec jxl` (10/8-bit support) plus the
`--jxl-parallel` W-deep pool. The public claims below are limited to the
committed gates and documented behavior.

## What it is

- `--codec {j92|jxl|both}` — default `j92` = the unchanged DNG path
  (byte-identical: the 10-frame synthetic oracle lands at
  67,762,584 B; the suite gate is pinned in `ci/check.sh`). `both` = the
  two-tier single-command archive: j92 → `OUT` + jxl → `OUT-jxl`.
- v1 = **lossless only**: `--codec jxl` + a lossy `--mode`, or
  `--downscale2x`, or `--fast` → hard reject (rc=2, clear message).
- **Per-frame output unit = 4 × `.jxl`**: the 2×2 sub-planes
  p2_00/p2_01/p2_10/p2_11 at 1928×1085 u16 (modular lossless JXL). The size
  claims rest on exactly these 4 files' sum.
- **Effort: `--jxl-effort {4|7|9}`, default e7** — restricted to the
  measured ladder (unmeasured efforts rejected by clap; explicit
  `--jxl-effort` + `--codec j92` → rc=2 hard reject). Measured: e7 = 4.6×
  faster encode than e9 for +1.3…2.7% size; e4 = 10.9× for +1.9…10.1%;
  e9 = the size anchor (the pre-flag fixed effort, kept for sealed
  masters). Decode / `--verify` is effort-invariant (identical at all
  three).
- **Parallelism: `--jxl-parallel <W>`** — W-deep concurrent cjxl processes
  across the reel (0 = auto = all cores; 1 = the serial escape hatch;
  j92 + flag = rc=2 named refusal). `--jobs N` is the per-cjxl thread
  dimension (0 = default 14).
- **Encoder: cjxl 0.12.0 subprocess** (`--cjxl-bin`, default `cjxl` on
  PATH; the committed pinned copy: `deps/pinned-binaries/cjxl` — the
  byte-identity location pinned by `ci/pins.tsv` on version + sha256).
  PAM input = TUPLTYPE GRAYSCALE, MAXVAL 4095, big-endian u2.
- **Mandatory per-file sidecar** `<CLIP>-src.jxl-checksums.tsv` (file, size,
  sha256, crc32c, plane, src_frame, src_frame_sha256, jxl_version, effort) —
  JXL bundles incompressible in containers → plain tar + this sidecar.
- **`--verify`**: sidecar sha256 re-check first (fast failure, named
  frame/file) → djxl 0.12.0 subprocess decode (strict PAM parse) →
  re-interleave → p1 byte-exact + p0 strip-prefix byte-exact (the 12-bit
  pack12 gate). Byte-exact is the gate.
- **Independent-decoder cross-check**:
  `--verify` round-trips with djxl, the SAME libjxl build as cjxl, so a bug
  shared by that pair would not be caught. `ci/check-xcheck.sh` (wired into
  `ci/check.sh` after the oracle108 step) decodes the committed oracle108 gold
  (8 planes) with **jxl-oxide 0.12.6** — a pure-Rust decoder, a SEPARATE
  implementation; the version pinned in `ci/jxl-xcheck/Cargo.lock` (the
  `jxl-oxide` row in `ci/pins.tsv`) — and asserts the planes byte-exact
  against the source-derived planes (the j92 round-trip: encode `--verify` →
  the pure-Rust golden-model decode; no libjxl in the source-side path).
  The gate: 8/8 planes byte-exact, rc=0.
- Atomic writes (temp + rename); named-frame failures → nonzero; bogus
  `--cjxl-bin` → rc=2 with ZERO files written.

## 10/8-bit scope

`--codec jxl` covers the same scope as the j92 path: the shared
`is_archive_layout` predicate (UHD|FHD × {8, 10, 12}-bit) — the refusal
stays a loud named message. The PAM stays MAXVAL 4095 u16 big-endian,
bit-depth-invariant; per-depth unpack dispatch (unpack8/10/12 from
pack12) in encode + verify; the verify gate = the re-interleaved p1
byte-exact at all depths. Named follow-up: the 10/8-bit strip-prefix gate
(pack10/pack8 don't exist yet).

## Size claim (shipped)

On the measured set, JXL e7 beats the J92 same-window by **−20.9%**
(bright A001_010) to **−27.2%** (dark A001_001); on the full measured
corpus (1514 frames) JXL wins on every frame. The corpus contains no
genuinely bright content, so J92 stays the default. Archival by
construction — the accepted trade: **NLE off the table** (no NLE decodes
`.jxl`; by design, not a gap).

## Disambiguation: JXL-in-DNG (tag 52546) ≠ the `--codec jxl` sidecar tier

Two different JXL stories, measured separately:

- **JXL-in-DNG** (Compression tag 52546, DNG ≥ 1.7): JXL bytes INSIDE the
  DNG container. Verdict **NO (measured across 15 cells)** — the JXL
  lossless is larger than our tag-7 on all cells; details in
  `docs/compatibility.md` (format row: JXL-DNG).
- **The shipped `--codec jxl` sidecar tier**: plain `.jxl` files + the
  checksum sidecar, no DNG container. That is this doc — the archival size
  tier (e7).

## Evaluated codecs (the one table)

| codec | tier | verdict | one-line why |
|---|---|---|---|
| J92 (T.81 in DNG) | default, NLE-openable | **SHIPPED** — the default | the only DNG-carriable lossless; the measured-parity contract (64 SOF3 tiles) |
| JXL sidecar (`--codec jxl`) | archival | **SHIPPED** (e7) | −20…−27% vs J92 on the measured set; NLE off the table by design |
| JPEG LS | archival | **REJECTED** (maintainer decision) | only the bit-exact mode, and it loses to J92 everywhere; and a DNG can't carry it — the DNG Compression tag is {1, 7} |
| JPEG 2000 | — | **NOT ADOPTED** (measured) | between J92 and JXL on size, no NLE reader, no tier to own |
| JXL-in-DNG (tag 52546) | archival | **NO** (measured across 15 cells) | larger than tag-7 on all cells (`docs/compatibility.md`) |

**Evaluated and rejected — J92→JXL re-wrap:** the pinned libjxl JBRD
jpeg-data-reader path is 8-bit-only at source (`PRECISION` gate;
source-verified) — the JXL tier encodes from the unpacked plane, not by
re-wrapping J92 tiles.
