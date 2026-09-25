# Camera profiles (option (a))

The per-camera pinned config as a **versioned, machine-readable profile**
— the "camera-agnostic given DNGs" claim made concrete and falsifiable
per camera (option (a): the
profile is the **identity record**, not the routing config).

## The identity-vs-routing split

The profile is the **identity layer**: *does this frame's camera exist
in the pinned set, and is THIS readout/depth/CFA measured for it?* The
worker's predicates (`is_tile_layout` / `is_archive_layout` / the
native-depth paths) remain the **routing layer**: a profiled frame is
routed exactly as the embedded constants routed it. The A001 profile
**equals** the embedded constants (`tool/src/worker/` — the
tile-layout + archive-layout predicates, the 8/10/12 native depths,
the CFA photometric 32803), so the encode output for A001 frames stays
**byte-identical** to the pre-existing behavior (the G1/G3 gates). The gate sits AHEAD
of the routing; it never rewrites it.

The FROZEN posture stays the default: an **unknown camera is a named
refusal** (rc=2 at the encode surface — the tool does not encode
without its camera identity resolved). The profile is an explicit
identity, not an opt-in to new behavior. A new camera is a **new
profile file + the measurement**, not a code change.

The split gains its **third class** with the `offload` subcommand
(the **PASS-THROUGH** dispatch): any camera, any format — the
offload mirrors + verifies the bytes, it never decodes or re-
encodes, so the copy's correctness does not depend on the camera's
measurement. There the identity is a **REPORT, not a gate**: the
per-clip detection line names the class (`profiled <camera>
(profile v<n>)` / `unprofiled camera <Make> <Model>` / `non-DNG
media`), and identity NEVER refuses the copy. The FROZEN unknown-
camera refusal sits ahead of the TRANSFORM routing only (the encode
keeps the named rc=2 — the transform's byte-frozen correctness
depends on the measurement; the copy's does not). The A001
profile's meaning is unchanged (the transform's identity record —
the pass-through never consumes it).

## The profile file (the records pattern)

`profiles/<camera>.profile` — the `# frameprism camera profile` magic
line first, then the `version:` + `tool_version:` header (the pinned
record, like the pins), then the deterministic `key: value` rows:

| key | meaning |
| --- | --- |
| `version` | the profile format version (1 — a different version is the named `bad version` refusal) |
| `tool_version` | informational (the pinned-record marker — never enforced) |
| `camera` | the deterministic camera id (one token) |
| `make` / `model` | the DNG Make/Model tag values — the **primary identity** (exact match) |
| `photometric` | the profiled CFA PhotometricInterpretation (A001: `32803`) |
| `naming` | the measured file-naming convention (informational — the resolver never matches on file names) |
| `geometry` (repeatable) | `<width> <height> <bits> <predicates>` — one measured readout/depth row; `<predicates>` is the canonical-order class list (`tile,archive` / `archive`) naming which SHIPPED predicates accept the row (the routing layer's input — the worker routes unchanged) |

The reference example (the A001 — written from the measurement):

```text
# frameprism camera profile
version: 1
tool_version: 0.1.0
camera: a001-sigma-fp
make: SIGMA
model: SIGMA fp
photometric: 32803
naming: <CLIP>_<YYYYMMDD>_<NNNNNN>.DNG
geometry: 3856 2170 12 tile,archive
geometry: 3856 2170 10 archive
geometry: 3856 2170 8 archive
geometry: 1936 1090 12 archive
geometry: 1936 1090 10 archive
geometry: 1936 1090 8 archive
geometry: 2016 1344 12 archive
geometry: 2016 1344 10 archive
geometry: 2016 1344 8 archive
geometry: 3024 2010 12 archive
geometry: 3024 2010 10 archive
geometry: 3024 2010 8 archive
```

The parser is **strict** (the named refusal classes, never a silent
fallback): bad magic · bad version · unknown key · bad row shape ·
duplicate row (header key or geometry triple) · non-numeric field ·
missing required key · no geometry rows. Cross-file invariants: the
camera ids are UNIQUE and no two profiles claim the same Make/Model
(an ambiguous primary identity is a named refusal, not a guess).

## Resolution (the pins pattern)

The profile SET resolves like the pins
(`tool/src/pins.rs::resolve_pins_path`): the `FRAMEPRISM_PROFILES` env
(an explicit profile FILE path — the deterministic test surface; a
named env that does not resolve is a named refusal, NOT a silent
fall-through) → the `profiles/` dir under the cwd → the `profiles/`
dir next to the executable. **Unresolvable = the named refusal**:
`camera profile set unresolvable (probed: …) — the tool does not
encode without its camera identity` (rc=2, the encode refuses before
any frame — the same posture as the pins). A corrupt profile file is
the same named refusal (the file name + the parse error class).

The encode resolves the set **once per run** (not per frame) and
resolves **every frame of the selected set BEFORE any write** (the
pre-write identity check — the gate reads the header only,
`tiff::read_meta`; the encode's own `tiff::read` in the per-frame run
is the full parse, and the per-frame layer re-resolves the
already-parsed frame against the same loaded set — no second parse —
so a file changed between the gate and the encode is still refused
named). A 0-frame run has nothing to identify (no load, no refusal —
the legacy behavior stands).

## The four mismatch classes (the falsifiability point)

Ordered Make/Model → geometry → bits → photometric; a frame failing
two checks names the FIRST in that order. The per-frame named line:
`FAIL {file}: camera mismatch: …`; the run summary:
`CAMERA GATE FAIL — {n} frame(s) refused, 0 compressed (the named
FAIL lines above)`; the refusal: `camera gate: {n} named FAIL line(s)
— refusing to compress (see the FAIL lines above)` (rc=2, zero output —
nothing is written to the output dir; the gate fires before any
compressed write).

| class | line (the offending values in the message) |
| --- | --- |
| 1 — unknown camera | `camera mismatch: no profile matches Make/Model <make> <model>` (the M1 row is a new profile file, not a code change) |
| 2 — unmeasured geometry | `camera mismatch: profile <id> Make/Model match but geometry <w>x<h> is not in the profile's geometry rows` (a known camera, an unmeasured readout — a config row addition when measured) |
| 3 — unmeasured depth | `camera mismatch: profile <id> geometry <w>x<h> matches but bits_per_sample <b> is not a profiled depth for that geometry` |
| 4 — CFA photometric | `camera mismatch: profile <id> geometry/depth match but photometric interpretation <p> != the profile's CFA photometric <pp>` |

A frame whose identity tags are unreadable (missing Make/Model,
wrong type, out-of-bounds value) is its own named refusal
(`camera identity: …` — the tool does not encode what it cannot
identify).

## The audit camera line (additive)

The audit (`tool/src/audit/` — the ingest-continuity surface) gains
one line per `--audit` run, appended after the ingest-continuity
section:

```text
audit: camera MATCH (a001-sigma-fp, profile v1)
```

```text
FAIL audit: camera MISMATCH — <sample frame>: camera mismatch: …   (rc=1 — the named offender)
```

```text
audit: camera ABSENT — <reason> (the camera identity was not checked — the line is optional for the PASS)
```

The keyless claim: the audit needs nothing but the profile set + the
DNG frames — no archive bytes, no key (the audit does not need to
decompress a pixel to verify the camera identity). The **sample** is
the first frame of the dir (deterministic — the sorted frame order;
the v1 sample — a full per-frame audit resolution is a later
candidate; the encode already resolved every frame at encode time).
The ABSENT class is the honesty line (the profile set unresolvable /
no frames / the sample unreadable) — the line is OPTIONAL for the
PASS, exactly like the signature ABSENT line (it leaves the verdict
untouched); a MISMATCH is the named offender and rides the audit rc=1
(the encode path keeps rc=2).

## What the profile does NOT do

- It does not change the routing: the A001 profile = the embedded
  constants; the encode output for A001 frames is byte-identical
  (G1: the fixture encode + the MATCH line; G3: the audit delta vs
  the baseline binary = exactly the one MATCH line).
- It does not match on file names (the `naming` row is informational
  — the identity is the header, the file name is the camera's
  business).
- It does not widen the accepted set: the 8/10/12 native depths, the
  tile/archive layouts, the CFA photometric — a frame outside the
  profiled rows is refused NAMED (the falsifiability point).
- It does not touch the bake/repair/ledger/diff paths (the encode
  identity gate + the audit line only; the main.rs CLI surface is
  unchanged — `FRAMEPRISM_PROFILES` is the only new knob, the pins
  pattern).

## The CI fixture (the synthetic foreign-DNG class)

`tool/src/camera.rs::synth_dng_frame` (the shared `#[cfg(test)]`
builder — the worker's `synthetic_dng` TC-helper pattern extended
with the camera identity tags) builds the minimal valid
little-endian single-strip TIFF/DNG container (the identity tags +
the geometry/depth/CFA header + a valid TimeCodes tag + a real
zero-filled strip) for the four foreign variants:

- (a) `ACME ACME-1` 1024×768 @12 CFA → **class 1** (and
  `tiff::read`-parseable — the identity gate fires after the parse);
- (b) `SIGMA SIGMA fp` 4000×3000 @12 CFA → **class 2** (a known
  camera, an unmeasured readout);
- (c) `SIGMA SIGMA fp` 3856×2170 @14 CFA → **class 3** (the depth is
  not 8/10/12 — `tiff::read` would refuse it by its OWN named class,
  `UnsupportedBps(14)`; the run gate names class 3 first);
- (d) `SIGMA SIGMA fp` 3856×2170 @12 photometric 1 → **class 4**
  (`tiff::read`'s own `NotCfa(1)` refusal never fires — the gate
  precedes the encode parse).

The end-to-end `process_dir` tests (the `p8d11_gate_*` in
`tool/src/worker/`) run all four through the refusal (the named Err + zero
output) plus the A001-identity FHD-10 container end to end (the gate
is a no-op for a profiled frame).

## Provenance

- The public profile records the supported DNG structure facts: Make/Model,
  measured readouts and depths, CFA photometric value, and naming convention.
  Private camera footage and footage-derived measurement artifacts are not
  distributed.
- The identity tags ride the ALREADY-PARSED header (the `tiff::read`
  Frame's verbatim IFD0 / the `tiff::read_meta` header) — the
  resolution never re-parses a frame for them; `tiff.rs` is
  unchanged (the identity tags are plain IFD0 entries — the
  `read_meta`/`read` surface already carries them verbatim).
- The resolution + refusal posture: the pins pattern
  (`tool/src/pins.rs`) + the FROZEN posture (the unknown camera is
  the named refusal, like the unknown clip in the ingest gate).
- The audit line: the ingest-continuity surface's additive-line
  pattern (the signature line — optional for the PASS).

## The per-gate byte contract (the measured set)

The profile rows are the IDENTITY; the per-gate BYTE CONTRACT is what
each geometry's encode/decode machinery pins. The per-gate grids (the 3K grid, the FHD grid, the OG2K grid, the
OG3K 10/8 rows, the UHD @10 grid): the A001 set is:

| geometry (readout) | grid | tile selection | NLE (DaVinci Resolve 21.1) |
| --- | --- | --- | --- |
| 3856×2170 @12 (UHD) | 482×272 (the legacy contract) | the size-min | ✅ the maintainer's Resolve check (the tested clip's grid class — the NLE's playable class) |
| 3856×2170 @10 (UHD) | 964×272 (4×8 = 32 tiles — the measured per-depth grid — 964×4 = 3856 exact; the last row 266 px at the full 272 geometry) | the size-min over the measured per-gate family {W-PSV7, W-PSV2, N-PSV1} (the 96/96-tile census: the 964×272 grid's measured family = the 482 legacy family's members — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| 3856×2170 @8 (UHD) | 482×272 (the measured choice at @8) | the size-min | ✅ the maintainer's Resolve check (the full-clip import plays) |
| 1936×1090 @12 (FHD) | 242×274 (8×4 = 32 tiles — the measured per-depth grid) | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| 1936×1090 @10 (FHD) | 484×274 (4×4 = 16 tiles — the measured per-depth grid) | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| 1936×1090 @8 (FHD) | 242×274 (8×4 = 32 tiles — the measured fold: the @8 row folds to the @12 grid) | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| 2016×1344 @12 (Open Gate 2K) | 252×336 (8×4 = 32 tiles — the measured per-gate grid) | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| 2016×1344 @10 (Open Gate 2K) | 252×336 (8×4 = 32 tiles — the measured depth-invariant grid) | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| 2016×1344 @8 (Open Gate 2K) | 252×336 (8×4 = 32 tiles — the measured depth-invariant grid) | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| 3024×2010 @12 (Open Gate 3K) | 252×252 clean 12×8 (the measured current output — byte-identical on the 3-frame golden gate) | the measured pre-stuffing bit-count key (per-gate) | ✅ the maintainer's Resolve check (the pre-fix 482×272 3K class was the measured NLE refusal — the four-sample table + the grid-class register entry, `docs/compatibility.md`) |
| 3024×2010 @10 (Open Gate 3K) | 252×252 clean 12×8 (the measured depth-invariant grid) | the measured pre-stuffing bit-count key (per-gate) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| 3024×2010 @8 (Open Gate 3K) | 252×252 clean 12×8 (the measured depth-invariant grid) | the measured pre-stuffing bit-count key (per-gate) | ✅ the maintainer's Resolve check (the full-clip import plays) |

**The @8 boundary (the no-promotion boundary — the measurement):** the measured @8 output promotes the 8-bit FHD and OG2K
frames to a BPS10 container — the measured promotion is the IDENTITY
into the 10-bit precision container (NO value scaling: the mirrored
@8 frames decode pixel-exact to the 8-bit originals at both gates —
FHD: the measurement; OG2K: 0/2,709,504 samples × 3 frames;
the ×4 hypothesis was measured and rejected — 0 matches). This tool
does NOT replicate that: the @8 output stores the literal 8-bit
samples (BPS8 — the same-bits lossless, the 3K/2K/UHD @8 precedent).
The measured @8 row is the interop oracle + the benchmark only (the
decode golden tests assert the mirrored @8 frames pixel-exact vs the
8-bit originals and record the stored BPS10 as the measured
difference, not an assertion on our output). At the UHD gate the @8 measured output ALSO runs the 482×272 grid (the measured choice — the grid UNCHANGED by the UHD @10 row) with the
measured 8→10 identity promotion (stored BPS10); our @8 output keeps
the 482×272 grid at BPS8 (the no-promotion boundary above — the per-gate
boundary note in the @8 row).

**The 3K re-layout's tag-set variants (the measurement):** the 8-bit OG3K originals carry the
camera-native 50712 LinearizationTable (SHORT × 256 = 512 B out-of-
line — present ONLY on the 8-bit OG3K originals; the @12/@10 OG3K
originals have no 50712). The 3K re-layout template is therefore
variant per tag set — the discriminator is the frame's MEASURED TAG
SET (the 50712 presence, not the depth label): the 50712-less set (the
@12 + @10 OG3K originals — the 58-entry IFD0) → the original 59-entry
template (the measured values — UNCHANGED); the 50712-
carrying set (the @8 OG3K originals — the 59-entry IFD0) → the 60-
entry variant (the measured values: uniform +12 on every
region with tag < 50712, the 512 B 50712 region at 0xdf2c in tag
order, +524 after the insertion point, the variant-specific 51041/
51043 slot constant; the 47 ExifIFD entries + the 570 B ExifIFD body +
the 96 tiles + the 57 SI7MA in-blob pointers are tag-set-invariant).
A tag set matching NEITHER variant is refused LOUD with the named
`SurgeryError::ThreeKTemplateTag` BEFORE any write (the named
refusal — the former panic site — never a silent layout or a panic;
the pinned test `d103_1_planted_out_of_template_tag_loud_refusal`
plants an out-of-template tag on the mirrored originals, both
variants). The @8 output keeps the 50712 entry in the re-laid output
(the tag surface preserved) at BPS8 (the no-promotion boundary above).

**The measurement provenance:** the FHD contract (the per-depth grid + the
candidate family + the fold + the promotion) and the OG2K contract (the
depth-invariant 252×336 grid + the measured per-gate family + the
no-promotion @8) and the UHD @10 contract (the measured 964×272 grid —
4×8 = 32 tiles; 964×4 = 3856 exact; the last row 266 px at the full 272
geometry; the 96/96-tile census: the 964×272 grid's measured family =
the 482 legacy family's members {W-PSV7, W-PSV2, N-PSV1}, ZERO
outside; the @12/@8 482×272 grids UNCHANGED; the strip-geometry record
— the @10 originals' StripByteCounts = W×H×bps/8 + 12 — the 10-bit
packing's measured +12) are measured on the pinned test corpus (the 12-clip A001 batch) —
7 clips mirrored for the golden (A001_004 @12 · A001_005 @10 · A001_006
@8 (FHD) + A001_007 @12 · A001_008 @10 · A001_009 @8 (OG2K) + A001_002
@10 (UHD) — 688 frames; the 9-frame golden sample per clip:
000001 / 000049 / 000097 at the FHD @12/@10 and OG2K @12/@10 clips,
000001 / 000051 / 000101 at the FHD @8 clip, 000001 / 000050 / 000100
at the OG2K @8 clip, 000001 / 000050 / 000099 at the UHD @10 clip
(A001_002, 99 frames), 6 clips
structural-only (A001_001..003, 010..012), 0 lossy-only. The G3
onboarding mirrors the OG3K clips A001_011 @10 +
A001_012 @8 for the golden in addition (3 sample frames each —
000001 / 000050 / 000099 and 000001 / 000049 / 000097; the 576/576-
tile census + the per-tag measurements behind the 3K re-layout's
tag-set variants above).

**The candidate family is GRID-KEYED (the per-gate scoping
discipline):** the FHD grids {242×274, 484×274} at 1936×1090 run on
the measured FHD family {W-PSV7, W-PSV6, N-PSV5} (the 80/80-tile
census over the mirrored corpus: every stored FHD reference tile is
byte-identical to exactly one re-encode from this family, ZERO tiles
outside); the OG2K grid {252×336} at 2016×1344 runs on the measured
OG2K family {W-PSV7, W-PSV6, N-PSV5} (the 288/288-tile census over the
mirrored corpus: every stored OG2K reference tile is byte-identical to
exactly one re-encode from this family, ZERO tiles outside — the same
3 members as the FHD family: the measured per-gate family
for the NEW grids); the UHD 964×272 grid (the @10 measured row) runs on the 482 legacy family {W-PSV7, W-PSV2, N-PSV1} — the
96/96-tile census over the mirrored A001_002 @10 corpus measured the
964×272 grid's family to be EXACTLY these 3 members (every stored
reference tile byte-identical to exactly one re-encode, ZERO outside —
the legacy family's members ARE the 964×272 grid's measured family, so
no separate family constant); every other (geometry × grid) combination
runs on the 482 legacy family {W-PSV7, W-PSV2, N-PSV1} UNCHANGED —
including the legacy pre-fix 482×272 FHD/OG2K archives (the decode-side
backward-compat acceptance) + the UHD @12/@8 482×272 archives + the
legacy @10 482×272 archives (the decode-side backward-compat
acceptance of the pre-fix UHD@10 output) and the 3K gate (the
handling). `--fast`'s FHD/OG2K candidate = the family's index 0
(W-PSV7) = the same stream as every other gate's index 0 (the `--fast`
byte contract is unchanged); the `--fast` UHD@10 candidate = the
measured family's index 0 (W-PSV7) = the same stream (the census).

The per-gate DNG LAYOUT (the third contract dimension): the 482×272
gates keep the 0.1.0 layout; the 3K gate emits the MEASURED per-tag
re-layout (the size-guarded offset templates + the 37500 pointer rebase
— per tag-set variant: the 50712-less @12/@10 originals on the original
template, the 50712-carrying @8 originals on the measured 50712 variant
— a tag set outside the selected variant or a size drift fails LOUD +
named, never silently; see the tag-set-variants paragraph above); the
FHD gate (1936×1090) + the OG2K gate (2016×1344) + the UHD gate's @10
grid (964×272 at 3856×2170 — the UHD @10 row) emit
the surgical `apply_tiled` layout at their measured grids (the
grid-generic machinery — the grids ride `gate_tile_dims_depth`: the
tile plan carries the grid + the tile count, the per-tile StripByteCounts
+ the header bookkeeping + the strip-at-EOF layout are
grid-generic — the mode-contract measurements changed only the TilePlan grids +
families, NO surgery.rs change): the
@8 boundary — the header packing is FREE. The OG2K header packing (measured on the pinned test corpus (the 12-clip A001 batch): a
NON-uniform per-tag re-layout — the ExifIFD 34665 0x4124 → 0x4e2,
the 324/325 arrays at header offsets 0x3a2/0x422, the 32 tiles from
0x134b0) is NOT replicated — the same posture as every other gate
(incl. UHD, whose surgical layout ships NLE-playable since 0.1.0, and
the FHD precedent — the maintainer's NLE-verified surgical grid output);
the 3K re-layout was demanded by the measured NLE refusal (the
discriminator = the grid class, now measured + emitted for OG2K).

**The boundary:** the pixel path (the tile encode/decode, the padding,
the verify) is GENERIC over the grid — every gate runs the same
machinery on its own tile size. What is NOT generic is the
MEASURED-PARITY CONTRACT: the grid choice, the candidate family, the
selection key (the 3K gate's measured bit-count key; the FHD gate's
size-min over its measured family — the free packing frees the byte
choice), and the DNG layout are the measured replicas of the corpus output, per geometry. A geometry outside the measured set is
the named refusal (mismatch classes 2/3 above) — the tool does not
encode what it has not measured; there is no silent fallback and no
best-effort output class.

**Onboarding a new geometry** = measurement, not a code change (the
per-gate version of the new-camera principle above): the inputs are
(a) a clip at the new geometry from the camera, (b) the measured output of the same clip (the golden source), (c) one measurement
pass that derives the contract from the golden bytes (the grid, the
per-tile geometry, the selection key, the DNG layout) and implements
it per-gate with the byte-identity golden test as the gate. Private footage
and footage-derived onboarding measurements are not distributed.

## The FHD + OG2K mode byte contract (the log10 + downscale2x measured rows)

The per-gate table above is the LOSSLESS tier. The FHD gate
(1936×1090) additionally carries the two MEASURED MODE rows — the
10-bit log codes (`--mode log10`) and the 2× downscale
(`--downscale2x`) — at @12/@10/@8, measured on the 12-clip A001 batch (A001_004 @12 · A001_005 @10 ·
A001_006 @8, the 3-frame golden samples 000001/000049/000097 and
000001/000051/000101). The mode rows share the lossless tier's per-
depth grids (the mode's grid = the per-depth lossless grid: 242×274
@12/@8 + 484×274 @10 at the full-res 1936×1090; the 968×545 ds2x
output inherits the source's per-depth grid) — the tile plan carries
the grid + the BPS + the LUT mechanics per mode × depth arm (the
measured per-arm plans; the lossless tier's plans are UNCHANGED at
every geometry/mode — the per-gate scoping discipline). The family is
keyed on (geometry × grid × mode): the log10 rows ride the measured
FHD family {W-PSV7, W-PSV6, N-PSV5} (the 32/32 + 16/16 + 32/32-tile
census — ZERO outside, the @10 row the subset {W-PSV6, N-PSV5}); the
ds2x rows ride a NEW measured 2-member family {W-PSV6, N-PSV5} for
the 968×545 gate (W-PSV7 never observed on the ds2x corpus — the
superset rejected: an unmeasured member is an unmeasured stream class,
the same boundary posture as the unmeasured-geometry refusal; the
SAME 242/484×274 grids keep the 3-member FHD family on the
lossless/log10 rows — the mode is part of the family key, never a
grid-only key). `--fast` at the ds2x geometry = the measured family's
index-0 stream (W-PSV6); the FHD fast stream stays the global W-PSV7
at every other geometry (the `--fast` byte contract UNCHANGED).

| mode | depth | geometry | stored BPS (the measured note) | grid (tiles) | the 50712 mechanics | tile selection | NLE (DaVinci Resolve 21.1) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| log10 | @12 | 1936×1090 | 12→10 (the 10-bit log codes — the mode's 10bit_log container) | 242×274 (8×4 = 32) | the 1024-entry LUT ADDED (the tool's own built-in A001 curve — the measured per-frame table is its calibration payload, the free class: the structural pin = presence + count, NOT the content — the 2 measured reference variants [656-entry delta] prove the table is frame-dependent) | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| log10 | @10 | 1936×1090 | 10 (unchanged — the RAW 10-BIT PASSTHROUGH: no codes, no LUT — content-identical to the FHD lossless @10 plane; the tool's log10 @10 output is byte-identical to its lossless @10 output) | 484×274 (4×4 = 16) | ABSENT | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (no reference-matching key — ; the census observed the subset {W-PSV6, N-PSV5}) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| log10 | @8 | 1936×1090 | 8→10 (the MEASURED mode-tier promotion: the 8-bit samples identity-promoted into the 10-bit domain — the values unchanged, the ×4-scaled hypothesis measured and rejected — unlike the lossless tier's no-promotion boundary, which is scoped to the lossless tier's camera-native storage) | 242×274 (8×4 = 32) | the camera-native 256-entry table CARRIED VERBATIM (byte-identical across all 9 @8 files — the carry, not a duplicate: a second 50712 = the measured gap) | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| downscale2x | @12 | 968×545 | 12 (unchanged) | 242×274 (4×2 = 8 — the bottom-row tiles = the 271-content-row half-row tiles on the 274-row plane) | ABSENT | the size-min over the measured per-gate family {W-PSV6, N-PSV5} (the 2-member set EXACTLY — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| downscale2x | @10 | 968×545 | 10 (unchanged) | 484×274 (2×2 = 4) | ABSENT | the size-min over the measured per-gate family {W-PSV6, N-PSV5} (the 2-member set EXACTLY — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| downscale2x | @8 | 968×545 | 8→10 (the MEASURED mode-tier promotion — the 258 = the structure of the measured mode shape; the lossless tier's no-promotion boundary is scoped to the lossless tier) | 242×274 (4×2 = 8) | the camera-native 256-entry table CARRIED VERBATIM | the size-min over the measured per-gate family {W-PSV6, N-PSV5} (the 2-member set EXACTLY — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |

**The content classes (the measured verdicts):** log10 @12 = the
quantized 10-bit code plane (the measured per-frame LUT — the
≤1-LSB residual vs the original's own LUT inverse is the measured
interop boundary, maxdiff 1 / ~97.6–97.9% exact — NOT a contract);
log10 @10 = the raw 10-bit samples (maxdiff 0, 100% exact ×3 frames);
log10 @8 = the 8-bit samples identity-promoted (maxdiff 0, 100%
exact); the ds2x rows = the tool's own staircase decimation plane
(bit-exact by construction) — the measured decimation differs
(the measured δ: 40–41% exact @12 / 67% @10 / 73–74% @8 vs
the tool's staircase, maxdiff up to 1156 — the interop boundary: the
interop acceptance = the DECODE of the corpus files, never a
decimation byte-parity assertion). The ds2x rows' crop tags
(50719/50720/50829) are the source's tags HALVED (the proxy geometry)
+ the 51089-91 proxy tags OMITTED in the measured ds2x output (the tool's own
ds2x design adds them — the free header packing).

**The restore-drill on the odd-height bottom-row tiles (the measured
interop shape):** the 968×545 frame on the 274-row grid leaves a
271-content-row bottom row (ODD) — the measured bottom-row tiles
store a FULL 274-row plane (271 content + 3 pad rows; the pad rows
are synthetic — one an exact copy of the last real row, two identical
values absent from ANY real row — NOT reproducible from the stored
frame). The tool's engine reproduces EVERY reference bottom tile
BYTE-EXACTLY from the stored components (the engine parity —
roundtrip-byte-match ×10/10, both orientations) — the only mismatch
is the pad-ROW CONTENT. The drill's acceptance for these interop
tiles therefore compares the FULL tile bytes for the even-height
tiles and the CONTENT ROWS ONLY for the odd-height half-row tiles
(the pad rows are non-content filler; the tool's OWN ds2x output
keeps the full byte-match — its pad is self-consistent). The FHD
full-res bottom row (268 content rows on the 274-row plane) carries
the same odd-height shape on the log10 rows.

**The OG2K mode rows (the 2016×1344 gate — the second of the mode-onboarding stream):** the OG2K gate additionally carries the
two MEASURED MODE rows — log10 + downscale2x — at @12/@10/@8, measured
on the same 12-clip A001 batch (A001_007 @12 · A001_008 @10 ·
A001_009 @8, the 3-frame golden samples 000001/000049/000097 and
000001/000050/000100). Unlike the FHD's per-depth grids, the OG2K mode
rows are DEPTH-INVARIANT: the log10 rows ride the lossless tier's
252×336 grid (8×4 = 32) at every depth, and the 1008×672 ds2x output
(2016/2 × 1344/2) inherits it (4×2 = 8 tiles). The edge tiles are
FULL-tile rows only (1008 = 4×252, 672 = 2×336 exact — the measured
no-half-row verdict; the FHD ds2x's 271-content-row half-row class does
NOT occur at OG2K — the decode drill runs the plain full-tile
semantics). The log10 rows ride the measured `OG2K_CANDIDATES` family
{W-PSV7, W-PSV6, N-PSV5} (the 3× 32/32-tile census — ZERO outside);
the ds2x rows ride a NEW measured 3-member family {W-PSV7, W-PSV6,
N-PSV5} for the 1008×672 gate (the 24/24-tile census: W-PSV7 IS
observed — 1 tile in 4 frames — so the 3-member set is the measured
family EXACTLY (the unmeasured member = the unmeasured stream class); contrast the FHD ds2x's 2-member set where
W7 was never observed). `--fast` at the 1008×672 geometry = the family's
index-0 stream = W-PSV7 = the global `FAST_CANDIDATE` (the global fast
path is byte-identical to the family's index-0 stream at this geometry
— the `--fast` byte contract UNCHANGED). The 252×336 grids keep the
3-member OG2K family on the 2016×1344 lossless/log10 rows — the mode
is part of the family key, never a grid-only key.

| mode | depth | geometry | stored BPS (the measured note) | grid (tiles) | the 50712 mechanics | tile selection | NLE (DaVinci Resolve 21.1) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| log10 | @12 | 2016×1344 | 12→10 (the 10-bit log codes — the mode's 10bit_log container) | 252×336 (8×4 = 32 — depth-invariant) | the 1024-entry LUT ADDED (the tool's own built-in A001 curve — the measured per-frame table is its calibration payload, the free class: the structural pin = presence + count, NOT the content — the measured reference table [sha16 28dc1bce…] is frame-stable across the 3 A001_007 frames, NOT byte-identical to the tool's embedded curve) | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| log10 | @10 | 2016×1344 | 10 (unchanged — the RAW 10-BIT PASSTHROUGH: no codes, no LUT — content-identical to the OG2K lossless @10 plane; the tool's log10 @10 output is byte-identical to its lossless @10 output) | 252×336 (8×4 = 32 — depth-invariant) | ABSENT | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| log10 | @8 | 2016×1344 | 8→10 (the MEASURED mode-tier promotion: the 8-bit samples identity-promoted into the 10-bit domain — the values unchanged, the ×4-scaled hypothesis measured and rejected — unlike the lossless tier's no-promotion boundary, which is scoped to the lossless tier's camera-native storage) | 252×336 (8×4 = 32 — depth-invariant) | the camera-native 256-entry table CARRIED VERBATIM (byte-identical across all 9 @8 files — the carry, not a duplicate) | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| downscale2x | @12 | 1008×672 | 12 (unchanged) | 252×336 (4×2 = 8 — full-tile edge rows only, the measured no-half-row verdict) | ABSENT | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (the 3-member set EXACTLY — W7 observed on the ds2x corpus — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| downscale2x | @10 | 1008×672 | 10 (unchanged) | 252×336 (4×2 = 8 — full-tile edge rows only) | ABSENT | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (the 3-member set EXACTLY — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| downscale2x | @8 | 1008×672 | 8→10 (the MEASURED mode-tier promotion — the 258 = the structure of the measured mode shape; the lossless tier's no-promotion boundary is scoped to the lossless tier) | 252×336 (4×2 = 8 — full-tile edge rows only) | the camera-native 256-entry table CARRIED VERBATIM | the size-min over the measured per-gate family {W-PSV7, W-PSV6, N-PSV5} (the 3-member set EXACTLY — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |

**The OG2K content classes (the measured verdicts):** log10 @12 = the
quantized 10-bit code plane (the measured per-frame LUT — the
≤1-LSB residual vs the original's own LUT inverse is the measured
interop boundary, maxdiff 1 / ~95.1–95.2% exact — NOT a contract);
log10 @10 = the raw 10-bit samples (maxdiff 0, 100% exact ×3 frames);
log10 @8 = the 8-bit samples identity-promoted (maxdiff 0, 100%
exact); the ds2x rows = the tool's own staircase decimation plane
(bit-exact by construction) — the measured decimation differs
(the measured δ: ~37% exact @12 / ~70% @10 / ~74% @8 vs the
tool's staircase — the interop boundary: the interop acceptance = the
DECODE of the corpus files, never a decimation byte-parity
assertion). The ds2x rows' crop tags (50719/50720/50829) are the
source's tags HALVED (the proxy geometry) + the 51089-91 proxy tags
OMITTED in the measured ds2x output (the tool's own ds2x design adds them — the
free header packing). The IFD0 tag-surface deltas (source →
tool): log10 @12 +2 / @10 +1 / @8 +1; ds2x @12/@10 +4 (−3 strip +4
tile +3 proxy) / @8 +4 (the @8 source's 59 → 63).

**The OG3K mode rows (the 3024×2010 gate — the third of the mode-
onboarding stream):** the OG3K gate additionally carries the
two MEASURED MODE rows — log10 + downscale2x — at @12/@10/@8, measured
on the pinned test corpus (the 12-clip A001 batch) (A001_010 @12 · A001_011 @10 ·
A001_012 @8, the 3-frame golden samples 000001/000050/000101 ·
000001/000050/000099 · 000001/000049/000097). Like the OG2K rows, the
OG3K mode rows are DEPTH-INVARIANT: the log10 rows ride the lossless
tier's 252×252 grid (12×8 = 96) at every depth, and the 1512×1005
ds2x output (3024/2 × 2010/2) inherits it (6×4 = 24 tiles). Unlike
OG2K's full-tile-only edge rows, the OG3K rows carry the ODD-HEIGHT
HALF-ROW class: 2010 = 7×252 + 246 leaves a 246-content-row bottom row
at full resolution (and 1005 = 3×252 + 249 leaves a 249-content-row
bottom row at ds2x) — the decode drill runs the content-rows-only
semantics on those half-row tiles (the content-rows-only drill; the
even-height full tiles keep the full byte-match). The log10 rows ride
the measured `CANDIDATES` family {W-PSV7, W-PSV2, N-PSV1} (the 864/
864-tile census — the SAME members as the 3K lossless family, the
separate lossless/log10 provenance); the ds2x rows ride the measured
`DS2X_OG3K_CANDIDATES` family {W-PSV7, W-PSV2, N-PSV1} for the
1512×1005 gate (the 24/24-tile census — the SAME members as the 3K
lossless family, the separate ds2x provenance). `--fast` at the
1512×1005 geometry = the family's index-0 stream = W-PSV7 = the global
`FAST_CANDIDATE` (the global fast path is byte-identical to the
family's index-0 stream at this geometry — the `--fast` byte contract
UNCHANGED). The 252×252 grids keep the 3K family on the 3024×2010
lossless/log10 rows — the mode is part of the family key, never a
grid-only key.

The OG3K mode rows close the parameterization gap: the shipped 3K
surgery was the LOSSLESS-ONLY fixed template (two region maps, 96
tiles hardcoded, the BPS unchanged, no LUT add, no crop halving, no
proxy). The mode arms ride a PARAMETERIZED 3K re-layout the fixed
templates cannot express — the measured packing rule (the 2-byte-
aligned out-of-line walk; the fixed templates are its E∈{59,60} × N=96
× 50712∈{absent,512 B} instances) applied to the per-arm OUTPUT tag-set
parameters (the effective-output discriminator: the ds2x arms
ADD the 51089-91 proxy tags — the tool's own ds2x design, the
free header packing — so the tool's ds2x IFD0 is 62/63 entries vs the
measured 59/60; the 34665 pointer = the COMPUTED ExifIFD offset of
the output's own tag-set parameters, never a hand constant — the
free-packing decision). The ds2x arm carries the DNG
BackwardVersion ≥ 1.4.0.0 guard (the fp frame is already at 0x01040000
— the no-op; the guard + the verify arm are the contract).

| mode | depth | geometry | stored BPS (the measured note) | grid (tiles) | the 50712 mechanics | tile selection | NLE (DaVinci Resolve 21.1) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| log10 | @12 | 3024×2010 | 12→10 (the 10-bit log codes — the mode's 10bit_log container) | 252×252 (12×8 = 96 — depth-invariant; the bottom row = the 246-content-row half-row tiles) | the 1024-entry LUT ADDED (the tool's own built-in A001 curve — the measured per-frame table is its calibration payload, the free class: the structural pin = presence + count, NOT the content — the measured reference table [sha16 28dc1bce…] is frame-stable, the SAME A001 batch table as the OG2K @12 rows) | the size-min over the measured per-gate family {W-PSV7, W-PSV2, N-PSV1} (the 3K gate's measured pre-stuffing bit-count key — the geometry-keyed in-tree machinery) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| log10 | @10 | 3024×2010 | 10 (unchanged — the RAW 10-BIT PASSTHROUGH: no codes, no LUT — content-identical to the OG3K lossless @10 plane; the tool's log10 @10 output is byte-identical to its lossless @10 output) | 252×252 (12×8 = 96 — depth-invariant) | ABSENT | the 3K gate's measured pre-stuffing bit-count key (the geometry-keyed in-tree machinery) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| log10 | @8 | 3024×2010 | 8→10 (the MEASURED mode-tier promotion: the 8-bit samples identity-promoted into the 10-bit domain — the values unchanged, the ×4-scaled hypothesis measured and rejected — unlike the lossless tier's no-promotion boundary, which is scoped to the lossless tier's camera-native storage) | 252×252 (12×8 = 96 — depth-invariant) | the camera-native 256-entry table CARRIED VERBATIM (the carry, not a duplicate) | the 3K gate's measured pre-stuffing bit-count key (the geometry-keyed in-tree machinery) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| downscale2x | @12 | 1512×1005 | 12 (unchanged) | 252×252 (6×4 = 24 — the bottom row = the 249-content-row half-row tiles) | ABSENT | the size-min over the measured per-gate family {W-PSV7, W-PSV2, N-PSV1} (the 3-member set EXACTLY — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| downscale2x | @10 | 1512×1005 | 10 (unchanged) | 252×252 (6×4 = 24 — the bottom row = the 249-content-row half-row tiles) | ABSENT | the size-min over the measured per-gate family {W-PSV7, W-PSV2, N-PSV1} (the 3-member set EXACTLY — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| downscale2x | @8 | 1512×1005 | 8→10 (the MEASURED mode-tier promotion — the 258 = the structure of the measured mode shape; the lossless tier's no-promotion boundary is scoped to the lossless tier) | 252×252 (6×4 = 24 — the bottom row = the 249-content-row half-row tiles) | the camera-native 256-entry table CARRIED VERBATIM | the size-min over the measured per-gate family {W-PSV7, W-PSV2, N-PSV1} (the 3-member set EXACTLY — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |

**The UHD mode rows (the 3856×2170 gate — the fourth of the
mode-onboarding stream):** the UHD gate additionally carries the two
MEASURED MODE rows — log10 + downscale2x — at @10/@8 (the @12 mode
rows are the frozen 0.1.0-era outputs — the mode controls, not the
measured rows), measured on the pinned test corpus (the 12-clip A001 batch)
batch (A001_002 @10 · A001_003 @8, the 3-frame golden samples
000001/000050/000099 · 000001/000049/000098). Like the FHD rows, the
UHD mode rows are PER-DEPTH (the OG2K/OG3K depth-invariance does not
apply at UHD): the log10 rows ride the lossless tier's measured per-
depth grids at the full-res 3856×2170 (964×272 @10 = 4×8 = 32;
482×272 @8 = 8×8 = 64), and the 1928×1085 ds2x output (3856/2 ×
2170/2) inherits the source's per-depth grid (964×272 @10 = 2×4 = 8;
482×272 @8 = 4×4 = 16). The ds2x geometry carries the odd-height
half-row class at BOTH grids: 1085 = 3×272 + 269 leaves a 269-
content-row bottom row (the bottom-row tiles are the 269-content-row
half-row tiles on the 272-row plane — the decode drill runs the
content-rows-only semantics on them). The
log10 rows ride the gate's measured family {W-PSV7, W-PSV2, N-PSV1}
(the 96/96 + 192/192-tile censuses — W-PSV6/N-PSV5 never observed);
the ds2x rows ride TWO NEW measured families — the FIRST ds2x
geometry with TWO measured grids (the per-depth inheritance): the
964×272 grid carries the 2-member {W-PSV2, N-PSV1} (W-PSV7 never
observed on the ds2x-@10 corpus — the 24/24-tile census — the
superset rejected (the unmeasured member = the unmeasured stream class)); the 482×272 grid carries the 3-member
{W-PSV7, W-PSV2, N-PSV1} (W-PSV7 IS observed on the ds2x-@8 corpus —
the 48/48-tile census — the SAME members as the legacy 482 family,
the separate ds2x provenance). `--fast` at the 964×272 grid on
1928×1085 = the family's index-0 stream W-PSV2 (the ONLY ds2x
geometry where the `--fast` stream ≠ the global W-PSV7 — the byte
contract at that geometry×grid); the 482×272 grid keeps the global
W-PSV7 (the family's index-0 = the global candidate — the `--fast`
byte contract UNCHANGED there).

| mode | depth | geometry | stored BPS (the measured note) | grid (tiles) | the 50712 mechanics | tile selection | NLE (DaVinci Resolve 21.1) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| log10 | @10 | 3856×2170 | 10 (unchanged — the RAW 10-BIT PASSTHROUGH: no codes, no LUT — content-identical to the UHD lossless @10 plane; the tool's log10 @10 output is byte-identical to its lossless @10 output — the measured content identity; the measured log10 @10 on-disk size = the tool's size, 2610614 B at f000001) | 964×272 (4×8 = 32 — per-depth; the bottom row = the 266-content-row half-row tiles) | ABSENT | the size-min over the gate's measured family {W-PSV7, W-PSV2, N-PSV1} (the 96/96-tile census — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| log10 | @8 | 3856×2170 | 8→10 (the MEASURED mode-tier promotion: the 8-bit samples identity-promoted into the 10-bit domain — the values unchanged — unlike the lossless tier's no-promotion boundary, which is scoped to the lossless tier's camera-native storage) | 482×272 (8×8 = 64 — per-depth; the bottom row = the 266-content-row half-row tiles) | the camera-native 256-entry table CARRIED VERBATIM (the carry, not a duplicate) | the size-min over the gate's measured family {W-PSV7, W-PSV2, N-PSV1} (the 192/192-tile census — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| downscale2x | @10 | 1928×1085 | 10 (unchanged) | 964×272 (2×4 = 8 — the per-depth inheritance; the bottom row = the 269-content-row half-row tiles) | ABSENT | the size-min over the measured 2-member family {W-PSV2, N-PSV1} (the 2-member set EXACTLY — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |
| downscale2x | @8 | 1928×1085 | 8→10 (the MEASURED mode-tier promotion — the 258 = the structure of the measured mode shape; the lossless tier's no-promotion boundary is scoped to the lossless tier) | 482×272 (4×4 = 16 — the per-depth inheritance; the bottom row = the 269-content-row half-row tiles) | the camera-native 256-entry table CARRIED VERBATIM | the size-min over the measured 3-member family {W-PSV7, W-PSV2, N-PSV1} (the 3-member set EXACTLY — no reference-matching key — the free class) | ✅ the maintainer's Resolve check (the full-clip import plays) |

**The UHD content classes (the measured verdicts):** log10 @10 = the
raw 10-bit samples (maxdiff 0, 100% exact ×3 frames — the @10 raw-
passthrough identity HOLDS at UHD); log10 @8 = the 8-bit samples
identity-promoted (maxdiff 0, 100% exact); the ds2x rows = the tool's
own staircase decimation plane (bit-exact by construction) — the
measured decimation differs (the measured δ: 74.8–75.0%
exact @10 / 76.5–79.3% @8 vs the tool's staircase, maxdiff 241/245/
247 @10 · 38/43/44 @8 — the interop boundary: the interop acceptance
= the DECODE of the corpus files, never a decimation byte-parity
assertion). The ds2x rows' crop tags (50719/50720/50829) are the
source's tags HALVED (each element /2 floor — the proxy geometry) +
the 51089-91 proxy tags OMITTED in the measured ds2x output (the tool's own ds2x
design adds them — the free header packing — the tool's ds2x
IFD0 = 62/63 entries vs the measured 59/60). The IFD0 tag-surface
deltas (source → tool): log10 @10 +1 / @8 +1; ds2x @10 +4 / @8 +4
(−3 strip +4 tile +3 proxy; the @8 source's 59 → 63).

**The restore-drill on the UHD ds2x odd-height bottom-row tiles (the
measured interop shape):** the 1928×1085 geometry on the 272-row
grids leaves a 269-content-row bottom row at BOTH measured grids
(1085 = 3×272 + 269 — 1928 = 2×964 exact @10, 4×482 exact @8) — the
measured bottom-row tiles store a FULL 272-row plane (269 content
rows + 3 pad rows; the pad-row content: the MIDDLE pad row = a byte-
exact copy of the last content row, the OUTER pad rows = the engine's
synthetic filler — NOT zero, NOT equal to each other, NOT equal to
ANY row of the frame; the H1 bottom-anchored overlap-window hypothesis
MEASURED AND REJECTED — 0 hits across all 48 dissected tiles — the
pad rows are NOT reproducible from the stored frame). The tool's
engine reproduces EVERY reference bottom tile BYTE-EXACTLY from the
stored components (the engine parity — roundtrip-byte-match ×48/48).
The drill's acceptance compares the FULL tile bytes for the full-tile
rows and the CONTENT ROWS ONLY for the half-row bottom-row tiles (the
pad rows are non-content filler; the tool's OWN ds2x output keeps the
full byte-match — its pad is self-consistent). The 0.1.0-era legacy
ds2x output (1928×1085 on the 482×272 grid — the byte-frozen mode
control) stays decodable on the 3-member 482-grid family (the
backward-compat pattern).

**The OG3K content classes (the measured verdicts):** log10 @12 = the
quantized 10-bit code plane (the measured per-frame LUT —
maxdiff 151 vs the tool's embedded A001 curve, the ≤1-LSB residual vs
the original's own LUT inverse is the measured interop boundary —
NOT a contract); log10 @10 = the raw 10-bit samples (maxdiff 0, 100%
exact); log10 @8 = the 8-bit samples identity-promoted (maxdiff 0,
100% exact — the ×4 hypothesis REJECTED, maxdiff 765); the ds2x rows =
the tool's own staircase decimation plane (bit-exact by construction)
— the measured decimation differs (the measured δ: 45–82%
exact, maxdiff 46–1499 vs the tool's staircase — the interop boundary:
the interop acceptance = the DECODE of the corpus files, never a
decimation byte-parity assertion). The ds2x rows' crop tags
(50719/50720/50829) are the source's tags HALVED (the proxy geometry)
+ the 51089-91 proxy tags OMITTED in the measured ds2x output (the tool's own
ds2x design adds them — the free header packing — the tool's
ds2x IFD0 = 62/63 entries vs the measured 59/60). The IFD0 tag-
surface deltas (source → tool): log10 @12 +2 / @10 +1 / @8 +1; ds2x
@12 +4 / @10 +4 / @8 +4.

**The remaining unmeasured combinations (the A+C boundary):** the
measured set = the UHD-12 log10 + the UHD-12 ds2x (the 0.1.0-era
mode controls) + the four UHD @10/@8 rows above + the six FHD rows
above + the six OG2K rows above + the six OG3K rows above. Every
other mode combination — the FHD log10 + downscale2x COMBINATION, the
OG2K log10 + downscale2x COMBINATION, the UHD log10 + downscale2x
COMBINATION, the non-archive layouts — REMAINS the named refusal
(the refusal text names the measured set). No silent fallback, no
best-effort output class.
