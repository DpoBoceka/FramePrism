# Third-party attribution

The per-component redistribution audit lives in `NOTICE.md` (the repo root).
That file reproduces license texts in full where stated and incorporates
other terms by pinned upstream reference where stated; this file is the
per-component narrative.

## libjpeg-turbo (the dual IJG + Modified BSD license)

The codec source for the lossless path. The build contract uses a locally
built static prefix from the fetched reference source
(`deps/libjpeg-turbo/` — gitignored, re-fetchable with `deps/fetch.sh`)
with the per-component lossless DHT patch
(`deps/libjpeg-percomp-lossless.patch`, 2 hunks) applied — built by
`deps/build-libjpeg.sh` → `deps/.jpeg-prefix`. The patch mechanism and why the prefix is load-bearing are documented in
the build contract in `CONTRIBUTING.md`.

License: the dual BSD-style pair — the IJG License (the libjpeg API
library + the inherited code) + the Modified (3-clause) BSD License
(the TurboJPEG API). `NOTICE.md` reproduces the applicable IJG legal
terms and Modified BSD text and incorporates the remaining terms by
pinned upstream reference where stated.

## libjxl v0.12.0 pinned binaries (cjxl + djxl)

`deps/pinned-binaries/cjxl` + `deps/pinned-binaries/djxl` — the local
NEON build of libjxl v0.12.0 (the local build stamp `1cad73c`; the
provenance note in
`deps/README.md`), committed because they are the byte-identity
contract of the JXL tier:
`ci/pins.tsv` pins both the version and the sha256 of the exact committed
bytes. Provenance is recorded in `deps/README.md`. Update only via a
deliberate named pin migration (rebuild → re-pin the shas → re-record the
oracle goldens).

The v0.12.0 build bundles three components statically: brotli (MIT),
highway (Apache-2.0), and skcms (BSD-3-Clause) — verified from the
committed dylibs (the NOTICE.md highway block carries the license
text). libjxl's own license: BSD-3-Clause (the JPEG XL Project). The
full texts are in `NOTICE.md`.

## Historical ljpeg92 reference (not distributed)

A parked lossless-speed port of the 1992 T.81 Annex H encoder (the
independent Rust DNG CLI's (LGPL 2.1) 0.8.0 Rust port of Baldwin's
`lj92.c`) exists only in the project's measurement-evidence archive;
this repository does not distribute
`tool/src/ljpeg92.rs`. Its internal copy preserves the original MIT header
and license review record. It is not shipped because the speed gate is
unreachable under the measured-parity 3-candidate contract.

## tool/src/fastenc.rs (the default entropy engine)

A clean-room reimplementation of the T.81 lossless entropy encoder
(measured line-similarity 0.009 vs `ljpeg92.rs`); byte-identical to the
libjpeg FFI path on every gate. It uses the IJG public-domain Annex K.2
Huffman table-generation algorithm (the `jpeg_gen_optimal_table`
semantics: pseudo-symbol, two-smallest merge, canonical codes) and cites
the independent Rust DNG CLI (LGPL 2.1) only as a speed reference.

## Oracle fixture frames (ci/oracle10, ci/oracle108)

Deterministic synthetic CFA content in sanitized Sigma fp container
templates, committed as the byte-identity CI proof:
`ci/oracle10/` (12-bit, 10 frames → the 67,762,584 B oracle) and
`ci/oracle108/` (10/8-bit JXL, 2 source frames → the 2,380,943 B oracle).
They are re-encoded and byte-compared by `ci/check.sh` on every gate run.
The source fixtures are deterministically regenerable by the committed
generator (`ci/fixture-templates/generate_fixtures.py`), authenticated by
the committed sha256 manifest
(`ci/fixture-templates/fixture-manifest.sha256`); the gate re-proves the
12/12 byte identity on every run.
