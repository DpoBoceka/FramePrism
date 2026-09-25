# dct12 — 12-bit DCT parity tiles (the idiomatic format name)

`dct12` is the idiomatic name for the 12-bit DCT parity-tile lossy
format — the specific combination of 12-bit precision + DCT parity
tiles + the DNG tag-7 mechanism. It is the format the tool's
`--lossy-format` wire-format selection refers to (the default of the
lossy tier, `dct12`).

**Status:** parked / deferred. Not part
of the default surface — the lossy flags are hidden from --help but
remain parseable; `docs/cli.md` carries the CLI surface.

Private footage-derived measurements for this parked format are not
distributed. No reproducibility claim is made for the deferred tier.
