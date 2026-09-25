# Docs index

| doc | what it is |
|---|---|
| `docs/README.md` | this index |
| `docs/architecture.md` | pipeline, format contract, verification, code layout |
| `docs/cli.md` | the CLI design notes — where the `--help` narrative lives |
| `docs/compatibility.md` | the NLE/reader compatibility matrix |
| `docs/format-dct12.md` | the dct12 lossy format — parked (deferred); public format identity and status |
| `docs/jxl-tier.md` | the shipped JXL archival tier + the evaluated-codecs table |
| `docs/provenance.md` | the signed reel manifest — the `sign`/`verify` verbs, the key-file format, the no-mint posture, the sealed-tier `--reel-out` bundle |
| `docs/card-workflow.md` | the direct card archive — the verify-before-unmount gate, the CARD UNLOCKED/REFUSED/UNVERIFIABLE verdict |
| `docs/camera-profiles.md` | the per-camera pinned config — the profile format, the identity-vs-routing split, the named mismatch classes, the `FRAMEPRISM_PROFILES` resolution |
| `docs/security.md` | the standing CI security posture — pinned-component determinism, the dependency audit + the C-boundary fuzz corpus wired into the gate |
| `docs/glossary.md` | terminology — read this first if the jargon is new |
| `docs/third-party.md` | third-party attribution |
| `CONTRIBUTING.md` | build contract, CI gate, corpus |

**Build contract:** `CONTRIBUTING.md` — the patched libjpeg prefix, the CI
gate (`ci/check.sh`), and what a contributor can verify without the footage.

Private camera footage and footage-derived measurement artifacts are not
distributed. Public reproducibility rests on committed synthetic fixtures,
registries, scripts, and gate outputs.
