# NLE / reader compatibility matrix

Every cell is sourced to a shipped document or identified as a maintainer
measurement. Private camera footage and footage-derived measurement artifacts
are not distributed. "Measured" = maintainer-verified from disk unless noted.
v1 scope = Resolve-only NLE target (maintainer decision;
the broader reader research is carried in the matrix rows themselves). The
version-drift protocol re-checks the NLE deviation register below on
the NLE 21.1 → 22.

## Tool / reader matrix

| tool / reader | license | reads OUR lossless (tag-7 tile JPEG) | reads dct12 2-scan (our lossy family) | reads JXL-DNG (52546) | writes | NLE behavior | source (public record) |
|---|---|---|---|---|---|---|---|
| **the NLE (21.1 generation)** | proprietary | ✅ **maintainer oracle PASS** ("lossless clips look good"; both sequences; bit-exact RAW) — **annotated:** the PASS covered the tested clip's grid class (the 3856×2170 UHD on the 482×272 grid — the NLE's playable class); the four-sample measurement (log-sourced, both encode routes) shows the NLE 21.1 generation **rejects** the 3024×2010 3K frame on the 482×272 grid (the ragged 132px edge column — the per-frame pixel-decode failures) and **plays** the 252×252 clean 12×8 grid (the SoC's current 3K output) — the cell's over-generalization corrected, the historical PASS preserved (the deviation register below) | ⚠️ maintainer's session: our vbr-hq output visually broken on ALL clips ("all of them"); reference goldens = 0 decode failures in the oracle → **ingest-defect-vs-visual-quality diagnostic OPEN** (reference goldens = same-format-class control) | ✗ (no JXL in the NLE) | n/a (NLE) | the NLE acceptance oracle | maintainer measurement |
| **rawpy 0.27.1 / LibRaw 2.25** (venv) | LibRaw dual (MIT/GPL) | ✅ **bit-exact** (8/8 max=0 vs canonical `frame_pixels`; the roundtrip half of the 0.1.0 contract) | ⚠️ **silent partial decode** — first-scan-only (even-rows-only) with no error (the measured discrepancy; a compat fact, not a defect) | ✗ for our rawpy wheel — needs the Adobe DNG SDK; the 0.27.1 wheel links no SDK (otool-verified) → rejects 52546 | n/a (decoder) | library (our measurement path) | maintainer measurement |
| **the independent C decoder library** (darktable lineage) | LGPL 2.1-or-later (+ one Novell BSD exception) | ✗ **hard reject, PSV=7** — PSV rides the Ah byte (Ss=00, Ah=07); identical reject on the SoC's own lossless goldens = **first reader that can't open the SoC's lossless files** (compat-class fact) | ✗ **FAILS LOUD** — DQT → "Not a valid RAW file." hard error (`AbstractLJpegDecoder.cpp:110`); second SOS + SOF1 unparsed; source + empirical on real f088 bytes | ✗ (zero code path) | n/a (decoder-only; zero encoder code) | library (darktable) | — |
| **the independent Rust DNG CLI** (0.8.0; its Rust raw reader library) | LGPL 2.1 | ✅ **bit-exact** (the `convert` verb decodes our lossless; re-confirmed on both clips) | ⏸ not tested (out of scope; its reader accepts tag-7 DC-only per-component DHTs, predictors 1–7, SOF3 prec 10–16, DQT→error) | ✅ **decompress only** — `decompressors/jpegxl.rs`, dispatch 1/7/8/34892/52546; the first non-Adobe "reads JXL-DNG" row | lossless only (256²×144 tiles edge-padded, pred 1–7, 2×2 row-merge on pred 4–7; **no lossy writer** — the JXL half is decompress) | **output: the NLE (21.1 generation) opens OK** (maintainer playback; the CLI build/flags/source clip unrecorded — see row note); reader side n/a (CLI/GUI tool) | maintainer playback |
| **Adobe DNG SDK 1.7.1** (reference; the fetched `deps/dng_sdk_1_7_1/` copy — gitignored, re-fetchable with `deps/fetch.sh`) | proprietary (Adobe) | ✅ (standard tag-7) | ⏸ not tested (out of scope) | ✅ **reference writer + reader** — `use_case_LosslessMosaic` writes a lossless JXL main IFD (Interleave2D + 50975/52547) | tag-7 lossless + JXL-DNG lossless (reference implementation) | n/a (SDK) | — |
| **PyAV 18.1.0 / ffmpeg stack** (venv; no ffmpeg binary on this machine) | BSD/GPL (ffmpeg) | ⚠️ `av.open` OK, **avcodec decode FAILS** — the ffmpeg-stack row (the silent-fallback footgun family; measure on a real ffmpeg binary if the row is ever load-bearing) | ✗ (research finding: FFmpeg ✗ for the BMD lossy family) | n/a | n/a (encoder for ProRes-class video only — no ProRes proxy tier in this tool: the tier is not part of the current product; private footage-derived measurements are not distributed) | library (video codecs) | — |
| **Premiere / FCP / Lightroom** | proprietary | ⏸ not tested (the Resolve-only decision) | ✗ (research finding: Premiere ✗) | ✗ (no JXL in any of them) | n/a | out of scope — revisit on drift-protocol data or a maintainer request | — |
| **OCTOPUS RAW Player** (MIT) | MIT | ⏸ not tested | ✅ verified decoder of the BMD lossy family (libjpeg `data_precision == 12\|16` detection, stock UNPATCHED libjpeg-turbo 3.0.3 — the third verified decoder; mechanism note: cross-check our `deps/.jpeg-prefix` DNL patch target before the next libjpeg bump) | ✗ | n/a (player) | a member of the 3-decoder oracle | — |
| **MLV-App** (C++/Qt app, in-repo DNG codec) | **GPLv3** | ⏸ not tested (out of scope = pattern recon, not decode testing) | ⏸ not tested | ✗ (MLV3 = J2K/OpenJPH, not JXL) | MLV2 lossless (DNG packing + LJ92) + MLV3 (J2K); **code reuse NO (GPLv3)**; patterns reusable: class-split-before-coder (validates the DNG 1.7.1 subimage path for the 2-px grid) + log-domain-before-lossy (validates the log10 family) | no native NLE path (Premiere via Influx; Resolve/FCP via cDNG export) | — |
| **the SoC writer** (the format's origin) | proprietary (SoC firmware) | n/a (writer-only: can't retro-encode) | n/a (writes the format contract our family reproduces; the SoC's goldens = the reference) | n/a | the BMD-compatible cDNG family (lossless + lossy) | the camera-side writer | maintainer measurement |

## Row note — the loud-vs-silent asymmetry (the independent C decoder library vs LibRaw)

The two major open-source RAW stacks handle our lossy 2-scan files **oppositely**:
LibRaw (rawpy) **silently partial-decodes** (first scan only — even rows, no error;
the measured behavior), while the independent C decoder library **fails loud** with a hard error at
the DQT. Same input bytes, opposite failure modes. This is a **compat fact, not a
defect** (our format matches the SoC's, which both stacks handle the way they
do — the independent C decoder library's PSV=7 reject also hits the SoC's own lossless goldens). It
matters for any future "which reader will open our files" answer: the loud one is
the honest one.

## Row note — the independent Rust DNG CLI's lossless output plays in the NLE (maintainer)

Maintainer playback: the independent Rust DNG CLI's **lossless output** opens in the NLE (21.1 generation) (OK; flags / source clip / the CLI build unrecorded). First maintainer-verified NLE point for a third-party lossless tag-7 layout — the CLI's writer (144×256² edge-padded tiles, its own predictor choice; neither the SoC's layout nor ours) reads fine. Confirms the model: lossless-tier NLE readability requires **standard tag-7 structure, not byte parity with the SoC's output** (consistent with the lossless tier's zero-deviation status and the fact that the independent C decoder library rejects the SoC's *own* goldens — PSV=7 is the compat-class boundary, and anything inside it passes). Consequences: (a) frameprism's 3-candidate trial-encode is the measured 2.67× workload factor, and its product is the **byte-identity with the SoC's current output (the interop record), not an NLE-compat requirement** (NLE readability is the standard tag-7 structure); (b) a single-candidate `--fast` mode (still standard tag-7) is NLE-safe — the compatibility side of the `--fast` decision is de-risked by maintainer evidence; (c) the independent Rust DNG CLI (70–105 fps — the speed measurement is not part of the public gate) is now a maintainer-verified fast bulk lossless encoder alternative — without the integrity bundle (no per-frame verify / checksums / pinned reproducibility).

## Format row — JXL-DNG (tag 52546, DNG ≥ 1.7)

- **Verdict for the archival tier: NO (measured across 15 cells).** JXL lossless
  (libjxl 0.11.2, the Adobe-bundled copy, distance 0) is **LARGER than our tag-7
  on all 15 cells** — best −3.01% (dark, four-CFA-class subimage split, the
  1.7.1 Row/ColumnInterleaveFactor path), worst −62% (bright clipped-flat).
  The JXL→Compression=7 conversion is proven bit-exact; the write path exists
  (Adobe SDK reference writer); the bytes simply lose to the tuned per-tile
  lossless Huffman on this content.
- **Spec mechanics** (for the record): tag 52546 (0xCD42), 8≤N≤16 integer, 1 or
  3 planes, photometric whitelist excludes CFA 32803 → the designed Bayer path =
  1.7.1.0 InterleaveFactor (52547) four-monochrome-subimage split; JXLDistance
  52553 (0.0 = lossless) / JXLEffort 52554 / JXLDecodeSpeed 52555. Real-world
  adoption (Adobe 2023 / DxO / Samsung) is **lossy proxies**, not archival.
- **Readers today:** Adobe SDK ✓ (reference writer too) · LibRaw w/ SDK ✓ ·
  the independent Rust DNG CLI ✓ (decompress only — the first non-Adobe row) · the independent C decoder library ✗ · the NLE /
  FCP / Premiere ✗ (no JXL at all).
- **Revisit triggers:** (a) a better 12-bit-integer JXL lossless coder; (b) an NLE
  ships JXL decoding. Neither is on a current watch item.

## NLE deviation register (what makes our DNGs non-stock — the drift watch list)

The tolerance surface Resolve tolerates today (the register the
version-drift protocol re-checks on 21.1 → 22): non-standard per-component DHT
class 2/4 (DC-only) · SOS `3F 00` (3-scan PSV=7 layout for the lossy family) ·
50719 DefaultCropOrigin (4,2) truncation · no 51111 tile-bytes tag. Lossless
tier: standard tag-7 (no deviation — the wide-compat class).

**A001 3K (3024×2010) grid class:** the 482×272 grid (the
measured-era layout — the ragged 132px edge column) → the NLE 21.1 generation
pixel-decode FAIL (the four log-sourced sessions across both encode routes —
the GUI incident encode's three sessions + the CLI control; the per-frame
decode-failure class in the NLE's own log; the playing controls = the camera
originals uncompressed + the SoC's 252×252 output). The 252×252 clean
12×8 grid (the SoC's current 3K output) → PASS (0 IO errors).
Mechanism suspect = the ragged edge column (the 132px vs 482px non-uniform
tile width); the uniform-grid hypothesis (the UHD @12 archive 8×8 clean grid)
UNTESTED. The core's decode side refused the new grid pre-fix (the named
refusal: `unexpected tile grid tags 322/323 = 252×252 (expected 482×272 — the
lossless tile geometry)`). **Fix (this
change):** the per-gate grid — the 3K gate now emits the NLE-readable 252×252
class (byte-identical to the SoC's current output); the other
gates keep the 482×272 contract unchanged.

**A001 UHD (3856×2170) @10 — the 964×272 grid class:** the 964×272 (4×8 = 32-tile) grid on the @10 readout → the NLE 21.1 generation opens it (the maintainer's full-clip Resolve check — the 99-frame A001_002 @10 clip plays; default + fast encodes). Structure: uniform column width (964×4 = 3856 exact — no ragged column) + the 266-px last row (the same edge-row class as the NLE-verified @12 482×272 grid — the oracle clip). The pre-fix @10 output (the 482×272/64 grid) = the measured drift from the SoC's @10 shape — the tool now emits the measured grid. The same check covers the @8 row (the 482×272 grid at BPS8 — plays). The same full-corpus double-check (the 12-clip batch × every j92 mode/effort combination — 28 encoded clip variants): all open. The jxl tier (4 × .jxl sub-plane files + the checksum sidecar per frame — the archival tier): the NLE does not open it — the tier's designation (not a DNG container; the j92 tier is the NLE working tier).

*Maintainer measurements that depend on private footage are not distributed;
the committed synthetic gates cover the public byte-identity claims.*
