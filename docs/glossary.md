# Glossary

Terms used across the docs.

## JPEG / DNG internals

- **PSV** — the predictor selector value: the JPEG lossless (T.81) predictor
  number, carried in the SOS `Ss` field (not in SOF3). libjpeg / DNG-SDK
  Table H.1 numbering: 1=left, 2=up, 3=diag, 4=left+up−diag,
  5=left+(up−diag)/2, 6=up+(left−diag)/2, 7=(left+up)/2; the ISO T.81 spec's
  own Table H.1 numbers 4–7 differently — the two must not be mixed. The
  measured per-tile candidate set (replicated by frameprism) is
  {1, 2, 7}.
- **SOF1** — Start Of Frame, extended sequential DCT class; in this repo it
  carries the 12-bit lossy DCT tiles (data precision 12).
- **SOF3** — Start Of Frame, lossless; the class of every frameprism lossless
  tile (the 2-component even/odd column split).
- **SOS** — Start Of Scan; the scan header. In lossless mode its `Ss` field
  is the PSV.
- **DHT** — Define Huffman Table. The camera's lossless tiles carry
  per-component DC DHTs; the per-component-DHT patch is the build-contract
  keystone; the public mechanism is documented in `CONTRIBUTING.md`.
- **DQT** — Define Quantization Table.

## frameprism tiers

- **j92** — the lossless JPEG tier: ITU-T T.81 Annex H (1992) lossless — the
  tool's default DNG output (`--codec j92`). "92" = 1992, the same name as
  the independent Rust DNG CLI's `ljpeg92` codec class (see `docs/third-party.md`).
- **e7** — JXL encoder effort 7 (cjxl `--effort 7`): the default of the
  `--codec jxl` tier (`--jxl-effort {4|7|9}`; `docs/jxl-tier.md`).

## Verification vocabulary

- **oracle** — a fixed reference decode used as the acceptance /
  byte-identity reference. (a) The CI byte-identity oracles: committed
  fixture frames in `ci/oracle10/` (12-bit) + `ci/oracle108/` (10/8-bit
  JXL), re-encoded and byte-compared by `ci/check.sh` on every gate run.
  (b) The NLE decode oracle: the fixed NLE Scripting-API
  import/decode of an encoded clip (`tools/nle_decode_oracle.py`),
  whose error strings are the NLE acceptance signal.
- **goldens** — the reference encode outputs a byte-identity check targets:
  footage-derived reference outputs (not distributed), and the committed CI
  oracle goldens under `ci/oracle10/` + `ci/oracle108/`.
- **32-set** — the 32-frame reference set (24 bright + 8 dark) that the
  deferred lossy family's M1 gate is scored on.
- **M1 gate** — the cast-conjunction verdict on the 32-set: the acceptance
  gate for the deferred lossy family's residual chroma cast.

## Deferred lossy family

The family is parked (hidden from the
default surface, still parseable — the CLI surface is in `docs/cli.md`).
Private footage-derived measurements for this deferred family are not
distributed.

## Process vocabulary

- **maintainer** — the person who runs the project (the footage, the NLE
  acceptance, the decisions); the historical records' personal attributions
  are voiced as "maintainer-verified" here.
