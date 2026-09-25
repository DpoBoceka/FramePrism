# Architecture

The tool is a single Rust binary (`tool/`) + a C shim for the libjpeg
boundary. The core property: **byte surgery, not a TIFF rewrite** — the
header bytes are kept identical, the compressed stream is written at the
existing strip offset, and the tail is truncated. The supported camera
profiles and committed verification fixtures constrain the measured layouts
on which that operation is accepted.

## Pipeline

```
input .dng (uncompressed, compression 1, 12-bit, 3856×2170, CFA 32803)
  │
  ├─ tiff.rs        IFD0/ExifIFD/sub-IFD parse (read-only understanding;
  │                 the writer does offset bookkeeping, not IFD re-derive)
  ├─ pack12.rs      unpack the standard-DNG 12-bit packing → u16 plane
  │
  ├─ mode path ────────────────────────────────────────────────────────────
  │  lossless (default):
  │    64 tiles on a fixed 8×8 row-major grid (482×272; last row 266 →
  │    padded to 272 by the measured alternating-row rule)
  │    per tile: even/odd COLUMN split → 2 component planes
  │    3-candidate trial-encode (the candidate set is profile/grid-specific)
  │    (entropy engine: native Rust T.81, byte-identical to the libjpeg FFI
  │     path; FRAMEPRISM_ENGINE=ffi restores it. Stream
  │     structure per the patched libjpeg: SOF3, per-component DC DHTs —
  │     see Build contract) · --fast: single fixed candidate (wrap-PSV7)
  │    smallest post-pad wins; even-byte tile padding (0x00 after FFD9
  │    when odd)
  │  log10:          the log LUT (identity 0..255, compresses 256..4095)
  │                 embedded via 50712, BPS 10, then the lossless path
  │  --downscale2x:  the measured staircase decimation
  │                 (phase-preserving; the plain 2×2 average produces
  │                 the magenta cast) + 50719 (4,2) signal + ExifIFD re-emit fix
  │  dct12 (DEFERRED): the tag-7 lossy format; docs/format-dct12.md
  │    carries the public identity + status
  │  34892 archive (DEFERRED): 12→8 1-component baseline DCT tiles under
  │    PhotometricInterpretation 34892
  │
  ├─ surgery.rs     tag diff: drop 273/278/279; insert 322/323/324/325
  │                 (+ 50712 for the lossy/log10 paths); compression 1→7;
  │                 IFD + sub-IFD re-emit at the shifted positions; no
  │                 digest recompute (the reader-compat contract)
  │
  └─ output .dng    atomic per-frame write (temp + rename); TimeCodes /
                   FrameRate / TStop / CFA / ColorMatrix byte-preserved
```

The format contracts the encoder replicates (measured, byte-for-byte):
- **Lossless tiles:** the encoder structure uses the measured adaptive
  per-tile PSV×orientation, last-row padding rule, and even-byte invariant.
  Public verification uses the committed synthetic byte-identity fixtures.
- **Lossy tiles (the dct12 format — parked):** `docs/format-dct12.md`
  carries the public format identity and parked status.

## Verification (the `--verify` gate families)

- **G1 structure:** per-tile marker/tag check vs the format contract
  (byte-level; the lossless path additionally md5s against local lossless
  goldens when present). Real footage and footage-derived goldens are not
  distributed.
- **G2/G3 pixels:** decode the output (lossless: `ljpeg_ref`-style decode;
  lossy: the both-scan `dct2s` decoder — rawpy is NOT the lossy pixel gate,
  it decodes even rows only) and compare against the original: bit-exact
  (lossless) or the per-frame catastrophe/anchor gates (lossy).
- **Independent decoders:** rawpy (LibRaw) + the independent Rust DNG CLI
  (LGPL 2.1) bit-exact on the lossless tier (`docs/compatibility.md`);
  the fixed NLE decode oracle
  + maintainer UI playback for NLE acceptance (the maintainer step is
  mandatory — it caught an oracle false negative).
- **Metadata:** the expected-diff table (only the tag plan may differ);
  TimeCodes/FrameRate byte-identical.
- **Checksums:** CRC-32C over the unpacked 16-bit plane
  (`--checksums` / `--verify-checksums`).

The suite gate is pinned in `ci/check.sh` (the 1 ignored test is the
real-file roundtrip anchor — gated on footage presence). `cargo test` is
green only with the patched libjpeg prefix (see below).

## Build contract

- `tool/build.rs` links libjpeg-turbo from the committed
  `deps/.jpeg-prefix` by default. `JPEG_TURBO_PREFIX` is the explicit
  override; there is no Homebrew fallback. **Compatible lossless tiles
  require the patched static prefix** — `deps/build-libjpeg.sh` builds
  `deps/.jpeg-prefix` from the fetched reference source
  (gitignored, re-fetchable with `deps/fetch.sh`) + `deps/libjpeg-percomp-lossless.patch`
  (2 hunks: `jcmaster.c` save/restore of per-component `dc_tbl_no` across
  the lossless re-default; `jcmarker.c` `emit_sos` honoring `dc_tbl_no` in
  lossless mode). An unpatched lib silently falls back to the legacy
  merged-DHT output — conforming JPEG, not SoC-compatible.
  The fail-fast guard is shipped: a resolved prefix that does not exist —
  or lacks the link surface (`lib/` + `include/` + the two static libs) —
  is the named `cargo:error` refusal (the resolved prefix + the remedy
  named) and `build.rs` never falls back to another location: the
  unpatched-lib silent-fallback class is structurally unreachable.
- The C shim (`tool/ljpeg_shim.c`) wraps the raw libjpeg C API for the
  paths the tj3 API doesn't expose (multi-component lossless, raw
  coefficients, 16-bit DQT tables).

## Code layout (`tool/src/`)

| module | responsibility |
|---|---|
| `main.rs` / `worker/` | CLI (clap), frame fan-out (parallel), resume/`--force`, report.tsv |
| `tiff.rs` | IFD parse (read-only), tag bookkeeping |
| `pack12.rs` | 12-bit standard-DNG pack/unpack |
| `tileenc.rs` | the lossless tile encoder (tile plan, even/odd split, 3-candidate trial-encode, padding) |
| `ljpeg_shim.c` + `lib.rs` FFI | the libjpeg C boundary (bindgen-verified signatures) |
| `surgery.rs` | the byte-surgery writer (tag plan, offset shift, atomic write) |
| `lossydct.rs` | the dct12 encoder (DEFERRED family) + the env-gated cast levers (`FRAMEPRISM_ERASURE`, `FRAMEPRISM_DCDC_CONSTS` — off by default) |
| `dct2s.rs` | the both-scan DCT reference decoder (the lossy pixel gate) + `dct2s` CLI (`probe` / `quality`) |
| `checksums.rs` | CRC-32C over the unpacked plane |
| `verify.rs` | the `--verify` gate families |
| `bin/` | diagnostics (`vdct_probe`, `cbr_probe`, `dcprobe`, `d1emp`, `d2probe`, `render_dng`) |
| `fuzz/` (sibling) | cargo-fuzz target (DNG parse + tile decode) |

## Test data

The tracked registry files (`testdata/README.md`, `testdata/clips.tsv`, and
`testdata/manifest.tsv`) carry the public clip list and manifest rows. Real
camera footage, reference outputs, and footage-derived measurement artifacts
are not distributed. Public verification uses committed synthetic fixtures,
registries, scripts, and gate outputs.
