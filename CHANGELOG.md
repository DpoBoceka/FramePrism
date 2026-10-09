# Changelog

All notable changes to frameprism.

## gui 0.1.0

- The desktop GUI (the encode surface) — `frameprism-gui`: the in-process
  encode job over the core (the same `process_dir` path the CLI dispatches
  — the encode bytes are the CLI's), in the egui/eframe window: the source
  scan (the clip rows + the detection class), the lossless / log10 mode
  (any other mode is the named refusal), the destination + the in-place
  refusal, the run-to-completion job (no cancel) + the CLI verdict lines.
  The prebuilt `frameprism-gui-*` binaries ship per OS on the release
  page.
- The Profile row (the camera-identity seam) — the optional profile
  field + the native file pick (the rfd sync pick): the GUI process is
  the sole owner of the `FRAMEPRISM_PROFILES` env (the field wins over
  the launch env; both empty = the core's own `<cwd>/profiles` →
  `<exe-dir>/profiles` probe order stands untouched); a non-file field
  is the named pre-job refusal (the core's env seam accepts an
  explicit profile file only — the job does not start).
- The workspace root — the `Cargo.toml` + the `Cargo.lock` ride the
  repository root (the tool's lock moved; the tool's `--help` surface, the
  suite counts, and the oracle byte contracts stand unmodified under the
  move).
- The gate — the gui step joins the check gate (the gui release build +
  the 5-test lib suite + the headless selftest — the `gui selftest: OK
  (1/1 clips, rc=0, lossless)` line); the offline audit rides the
  workspace lock.
- The release — the release workflow builds + publishes the
  `frameprism-gui-*` binaries per OS (the SHA256SUMS now covers the six
  files); the per-PR CI builds the gui binary for the compile signal +
  the source-portability check jobs are workspace-scoped.

## 0.3.0

- The mixed-compression input — a clip may now mix raw (uncompressed) frames and fp-camera lossless frames in one encode: the frame classifier dispatches each frame to its own path (the raw frames to the archive's raw path, the fp-camera lossless frames to the transcode path through the archive's encode); `--carry` lets the eligible fp frames ride carried (untranscoded) instead, with the per-frame provenance in the report; a mixed clip's dry-run carries the both-estimates line (carried vs transcoded, size). The whole-body-divergent fp tile is accepted when its decoded plane matches the decoded same-class fp neighbor's same-tile plane within the pinned temporal bound (the temporal oracle — it adds acceptance only; every existing refusal stands unchanged otherwise).
- The transcode-path profiler — `FRAMEPRISM_PROFILE=1` writes the per-phase sidecar `<dest>/.frameprism-profile.tsv` (the 8-phase contract per frame: read / fp-input-decode / fp-input-drill / source-synth / archive-encode / archive-drill / fidelity-decode / fidelity-compare); the gate absent or other = the byte-frozen default (no sidecar, no output change).
- The Stage-1 fast default — the 482 grid's selection default flips to the fixed single W7 candidate (today's `--fast` behavior): the clip-scale archive encode ≈ 2.7× faster at size parity with the measured per-frame band; the old size-minimum trial stands byte-frozen on the new `--trial` flag; `--fast` stays accepted (a no-op on that grid — its behavior IS the new default; every other grid's selection is untouched); `--fast` + `--trial` is the unconditional named refusal (rc=2).
- The native fast golden-model decode — the fp-camera input-tile decode + the restore-drill decode leg ride the table-driven Rust T.81 SOF3 decoder (the `ljpeg_ref` golden-model contract: the identical accept/reject verdict, planes, and refusal wording — the reference model stays the acceptance authority, the equivalence is KAT-pinned over the corpus + a synthetic corruption battery) instead of the bit-sequential reference decoder; the re-encode leg was already the native fast encoder (the drill's classification contract is unchanged).
- The 10-frame synthetic byte-identity oracle total re-pins at 72,325,126 B under the new default (the JXL oracle's 2,380,943 B stands unmodified).
- The self-describing encode — the camera profile is now the promotion to the pinned contract, not the gate: with no profile resolvable, frames that self-describe (a readable camera identity) and whose structure the shipped layout predicates confirm against the frame's own data still encode — the run announces the unpinned mode at start (the named line: `unpinned encode: MAKE MODEL WxH @B-bit (self-described; no pin — verify-on, no temporal acceptance; to pin this camera: the measured profile file)`), verifies every frame on the round-trip (the unpinned output's only falsifiability — the guard is not escapable), and the temporal acceptance is unavailable (it is pinned to the frozen oracle class — the whole-body-divergent tile keeps its existing named refusal). Frames the tool cannot identify or confirm are the named refusal (rc=2 before any frame, nothing written). The pinned path is byte-identical (the oracles' totals stand). `--pinned-only` = the strict posture (default off): with the flag, the no-profile run is the named refusal instead of the unpinned encode. The honest limits, on the record: an unpinned archive has no frozen oracle (it is falsifiable per-frame at encode time; it is not byte-pinned across tool versions — the promotion exists), and the verify cost is real (the forced round-trip is measured ≈ 2× the wall on the 723-frame mixed clip).
- The profile-measure verb — the measure → review → pin onboarding: `frameprism profile-measure <SOURCE>... --out <FILE>` scans one or more trees of the camera's clips read-only (the bounded-read pass — the sources are never modified; a camera batch can span dirs — the per-source measurements merge as a pure census: the per-readout counts summed, the class census merged, the bound over the batch's merged divergent-tile census) and measures the structural constants (the readout×depth rows + the layout predicates) + the temporal bound (4× the batch's measured worst whole-body-divergent-tile delta — the zero-divergent batch omits the bound, the named line stands), then writes the candidate profile to the explicit `--out` path only (REQUIRED — the candidate is a reviewed artifact: an absent `--out` is the named usage refusal, a missing parent dir is the named refusal with no partial write, and the write is the atomic temp+rename). The report (the coverage census per readout + the class census + the divergent-tile census — or the named zero-case line) is the stdout surface (the measure's output IS the report). The honest limits, on the record: the bound is batch-relative (measure over a representative batch — a narrow batch yields a tight bound), the candidate is user-reviewed (the tool measures; the user decides), and the structural rows are the footage's (over the A001 footage the measured candidate reproduces the committed pin's twelve geometry rows byte-identically — the pin is a function of the footage).

## 0.2.0

- The card auto-eject — `frameprism audit <archive> --source <card-root> --eject`: the verify-before-unmount release gate completes the card workflow. The eject runs only on `CARD UNLOCKED` (the named `CARD EJECTED` line — the card's volume is unmounted after the verified audit; the eject is an unmount only — the tool still never wipes the card); `CARD REFUSED` / `CARD UNVERIFIABLE` are the named `EJECT REFUSED` lines (the audit's rc unchanged); the eject command's failure is the named `EJECT FAIL` line + rc 1; Windows is the named platform refusal (the std-only boundary — the `CARD UNLOCKED` release stands). The ops-ledger verdict column carries the eject outcome when `--eject` is given. The env override `FP_EJECT_CMD` is the documented test seam (the CI_CARGO_AUDIT_BIN precedent).
- The README Known-limits fix — the stale "card `wipe` verb" line is gone (the no-wipe property is a design — `docs/card-workflow.md` — not a limit; the auto-eject is implemented, no longer a limit).
- The dependency freshness — the dalek-3 signing stack, the 3-OS actions, the grouped dependabot.
- The JXL platform posture — the absent/unspawnable cjxl/djxl binary is the named rc=2 refusal before the first byte (zero residuals — no output dir, no ingest manifest, no ledger row) + the per-OS posture docs (the committed pin on macOS, the host's 0.12.0 binaries on Linux/Windows — `docs/jxl-tier.md`) + the Windows capability disclosure (the encode path is the unix-only named refusal at the preflight; the check/audit/decode verbs are unaffected).
- The oracle re-anchor — the docs + the test doc comments carry the acceptance model explicitly: per-row acceptance = the bit-exact round-trip + the per-gate structural pins + the NLE spot-check; the format-origin reference product's outputs are the interop evidence + the benchmark, never the byte spec (the `ci/` synthetic oracles + the round-trip are the anchors).

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
