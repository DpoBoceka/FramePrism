# Changelog

All notable changes to frameprism.

## 0.1.1

- The Windows source-portability fix (the portable file identity + the cfg-gated permission branches) — the source compiles and the binary links on all three platforms, proven by CI.
- The 3-OS release binaries: every PR and main push builds them as Actions artifacts; a `v*` tag publishes them (with `SHA256SUMS`) to the GitHub Release.
- The release workflow's least-privilege permissions.
- The README Downloads section.

## 0.1.0 — the initial release

The initial release of the public tree. The pinned test corpus (the
measured 12-clip A001 batch + the 3-frame golden samples —
`testdata/manifest.tsv`) + the byte contract 67,762,584 B / 2,380,943 B
(the version-independent contract). The distribution stays source-only
(build from the repository on Apple Silicon macOS).

- **The encode surface** — `--mode lossless` (default) / `log10` (10-bit)
  / `--downscale2x` + the per-depth mode arms over the measured camera
  profiles (the per-gate grid geometry + the candidate families —
  `docs/camera-profiles.md`); the lossy 34892 DCT format (`--lossy-format
  {34892|dct12}` — the non-default tier, `docs/format-dct12.md`);
  the native Rust lossless default engine (byte-identical to the libjpeg
  FFI path) + the `--fast` single-candidate mode; the `--jxl-parallel`
  reel-wide plane-parallel JXL encode (a speed-only knob — the bytes are
  invariant).
- **The two-tier archive** — `--codec both`: one source read, the j92
  working tier → `OUT`, then the jxl archival tier → `OUT-jxl`; a `both`
  run is byte-identical to the two standalone runs. The JXL archival
  tier: the pinned cjxl/djxl, 10/8-bit support, the strict `--verify`,
  `--jxl-effort {4|7|9}` (default e7).
- **The archival system** — `frameprism decode` (archive → per-frame
  16-bit PAM, the round-trip check ON always), `audit` (the full sidecar
  re-verify), `restore` (the master-restore drill), `bake` (per-clip
  container + the mandatory bake manifest), `bake --iso` (the
  deterministic sealed ISO reel image — a pure function of the staged
  content, label, and pinned date; the in-process `fstool` 0.4.33 writer
  + the post-build pin-times pass — every directory record's 7-byte date
  field overwritten with the pinned epoch, so the image bytes are
  identical on every build machine, in every TZ). The bake container
  builder is in-process (the Rust `tar` + `zstd` crates — no
  system-tool prerequisite); the container/image bytes are a pure
  function of the input files + the pinned crate/library versions.
- **The safe-offload workflow** — the `offload` subcommand (the
  pass-through copy + verify of any card tree — any camera / any format,
  N×M multi-source/multi-destination fan-out, the verify-before-wipe
  verdict, automatic duplicate detection, temp-file + atomic-rename copy
  safety, the filesystem-sync-before-rename contract); `--resume`
  (kill-resumable: the manifest diff — the resumed final state is
  byte-identical to the uninterrupted run); the `frameprism repair` loop
  (the dirty-row re-transfer, mtime-preserving); the reel
  timecode-continuity gate (the `REEL_OVERLAP` refusal); the ingest
  safety gates (the frame-number-gap + timecode-continuity refusals
  before the first encode); the tree-aware bake / audit / selection (a
  card root → one reel archive + the reel manifest; `--clips` / `--skip`);
  the frame-level `diff` (per-frame IDENTICAL / DELTA / MISSING / FAILED
  + the run-level delta histogram; `--strict`); `frameprism derive` (the
  derived working tier).
- **Provenance** — the sealed-manifest pin-set line; `frameprism sign` /
  `frameprism verify` over the reel manifest (the tool verifies, never
  mints — no key generation in the binary); the signed manifest + its
  signature ride the sealed ISO tier as the `provenance/` bundle.
- **Security posture** — the write path refuses a planted symlink or a
  self-referential / nested destination before any write (zero partial
  writes), and no write may escape the destination root; the committed
  dependency-audit step runs with no network (the pinned audit binary
  over the committed advisory-db snapshot); the fixture provenance
  authority committed to the tree (the deterministic regeneration
  generator + the committed sha256 manifest — the fixtures' provenance
  re-proven on every CI run).
- **The camera-profile gate** — the camera Make/Model resolves to the
  encode geometry (the encode gate fires before any write), selected by
  the `FRAMEPRISM_PROFILES` env var; the `FRAMEPRISM_*` names are the
  only interface.
- **The deterministic per-clip QC class** (report-only by default) —
  black/blank-frame, duplicate-frame, and exposure-stat checks;
  `--qc-gate` opts the first two into exit-code gates.
