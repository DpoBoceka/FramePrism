# testdata — real-footage reference set

The public `testdata/` directory tracks only the corpus registries
(`README.md`, `clips.tsv`, and `manifest.tsv`). Real camera footage,
footage-derived reference outputs, and encode outputs are not distributed.
The committed synthetic fixtures under `ci/` provide the clone-ready gate
inputs; `ci/oracle10/src/` contains the 10-frame sample.

## Layout

    testdata/
    ├── originals/<CLIP>/                    # unmodified camera output — NEVER process in place
    ├── reference/<PRESET>/<CLIP>/          # the SoC's outputs (golden reference);
    │                                        #   each <CLIP> dir = 225 DNG + the vendor's
    │                                        #   own WAV + SPP_metadata.xmp (227 entries)
    ├── frameprism/<MODE>/<CLIP>/           # frameprism lossless-family outputs
    │                                        #   (lossless, log10, downscale2x,
    │                                        #   log10-downscale2x — the composable
    │                                        #   log10 + --downscale2x mode)
    ├── frameprism/dct12/<PRESET>/<CLIP>/ # frameprism lossy outputs — the production
    │                                        #   lossy family (--lossy-format
    │                                        #   vendor-dct); the extra <PRESET>
    │                                        #   level mirrors the reference/ tree
    ├── clips.tsv                            # clip registry — canonical clip list (tracked)
    └── manifest.tsv                         # encode results: clip × preset × tool (tracked)

Canonical clip ID = the `originals/` dir name. The camera's inner file prefix
(e.g. A001_002's files are named `A001_009_*`) is a recorded FIELD in
clips.tsv, never the org key.

## Clip naming

    <camera>-<res><bits>-<fps>p-<subject>
    e.g. fp-4K12-24p-cards   Sigma fp, 3856×2170 (the UHD crop 3840×2160 lives
                             inside it), 12-bit cDNG, 24.00p, color cards

Useful test subjects: color cards (color/metadata sanity), skin tones
(quality), dark/low-light (noise = lossless-ratio worst case),
high-detail (ratio stress).

## Preset naming (mirrors the SoC's UI)

    lossless | log10 | vbr-hq | vbr-lt | cbr3 | cbr4 | cbr5 | cbr7 | downscale2x

## Why we keep these

1. **the SoC's lossless output = golden reference for tag layout**: exact
   `Compression` value, 513/514 handling, sub-IFD retention, filename
   preservation. Diff frameprism output against it tag-by-tag.
2. **log10** shows how 10-bit + log encoding is signaled in cDNG
   (Linearization opcodes, spec §9.2) — reference for our `log10` mode.
3. **Lossy outputs**: real compression ratios on fp footage + NLE
   compatibility checks (Resolve; Premiere is the interesting case).
4. **downscale2x**: reference for the half-res working-file mode.

## Rules

- `originals/` is immutable: no in-place edits, no re-sort, no deleting
  without re-shoot.
- Every run: input = `originals/<CLIP>`, output into the preset dir.
- After each run, append to `manifest.tsv` (header already there).

## Clip intake protocol (new clip)

1. Add the clip row to `clips.tsv` (registry = the only source of truth for
   clip IDs, prefixes, frame counts, in_bytes).
2. Source into `originals/<CLIP>/` (dir name = canonical clip ID).
3. The reference goldens into `reference/<PRESET>/<CLIP>/` (one reference run per preset).
4. `frameprism/` outputs per encode + `manifest.tsv` rows per encode.

Never stage testdata payloads into git (gitignored by design — only README.md,
manifest.tsv, clips.tsv are tracked).