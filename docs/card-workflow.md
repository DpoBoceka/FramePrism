# Card workflow — the direct card archive (verify-before-unmount)

The card archive workflow: encode straight from the mounted camera card
onto the archive drive, verify the archive against the LIVE source
before the card leaves, and only then release the card for reuse.
The tool never wipes the card — the format is the operator's action,
and the tool's verdict is the release gate's claim.

## The four steps

1. **Encode from the card.** The card is the input; the archive drive
   takes the compressed archive and the raw offload:

   ```
   frameprism <card-root> <archive-drive>/out --to <archive-drive>/raw
   ```

   `<card-root>` is the mounted card — a single clip dir or the
   multi-clip tree (the clip key = the folder name). During the encode
   every source file is read exactly once, and the encode's read hashes
   the source bytes (no second full-file read — the card I/O is the
   bottleneck, and the ETA line estimates from it). The run writes the
   source-sha anchor (below) for every clip into `<archive-drive>/out`,
   and the `--to` raw offload lands on the archive drive (the
   verify-before-wipe offload gate runs against the raw mirror).

2. **Verify against the live source — before the card is unmounted.**

   ```
   frameprism audit <archive-drive>/out --source <card-root>
   ```

   The archive's own audit runs first (ingest continuity, offload
   re-verify, the members records, the report echo — the pre-existing
   surfaces, unchanged), and then every row of every per-clip source
   record is re-read from the card and re-hashed. The per-row verdicts
   use the named classes:

   - `OK` — size + sha256 match the record's row;
   - `MISSING` — the file is absent from the card;
   - `SIZE_MISMATCH` — the size differs from the record's row;
   - `SHA_MISMATCH` — the size matches, the sha256 does not.

   A dirty row prints a named line (`FAIL source <CLASS> clip=<clip>:
   <file> (<detail>)`) — loud, named, no silent skip. The run ends with
   the CARD verdict:

   - `CARD UNLOCKED (N source row(s) verified against the live source
     + the archive audit clean — the verify-before-wipe gate is clean;
     the card is reusable)` — **rc 0**. The card is released: it may be
     reused, and formatting it is the operator's decision, not the
     tool's.
   - `CARD REFUSED (N named source row(s) dirty — the named rows above;
     the card must NOT be formatted/wiped)` — **rc 1**. The archive
     audit is clean but at least one source row is dirty: the card's
     content does not match what the archive claims to have come from.
     Do not format the card; re-run the audit after the cause is
     found. (The full-set claim runs both ways: a clean card + a dirty
     archive also refuses — the UNLOCKED line requires the archive
     audit clean too.)
   - `CARD UNVERIFIABLE (…)` — the named honesty line when the
     verification cannot run: the card root is absent (unmounted) or
     the source record is absent (an archive made before this feature).
     The source rows are NOT verified; the archive audit is unaffected.
     The rc follows the archive audit result (a clean archive stays
     rc 0; a dirty archive stays rc 1) — an unmounted card is not a
     failure of the archive.
   - A corrupt source record (bad magic, a bad row) or a clip-key
     mismatch (the record's clip key vs the card tree's folder names)
     is a hard **rc 2** with a named error and zero partial verdicts —
     the usage-class semantics (no ledger row, no CARD line).

   The ops ledger row's verdict column carries the CARD outcome when
   `--source` is given (`CARD_OK` / `CARD_REFUSED` /
   `CARD_UNVERIFIABLE`); an audit without `--source` keeps the
   pre-existing `OK`/`FAIL` verdicts, unchanged.

   **The `--eject` form (the auto-eject after a verified audit — the
   release gate's additive action):**

   ```
   frameprism audit <archive-drive>/out --source <card-root> --eject
   ```

   The eject runs ONLY after the CARD verdict has printed (the
   verdict's own words stand — the eject is an UNMOUNT only: the tool
   still never wipes the card; the format remains the operator's
   action). The gate (the safety property): only `CARD UNLOCKED`
   sanctions the eject.

   - `CARD UNLOCKED` + `--eject` → the volume is ejected:
     `CARD EJECTED (<mount-point> — the verify-before-wipe gate is
     clean; the card is released + ejected)` — **rc 0** (the audit's
     verdict is unchanged).
   - `CARD REFUSED` + `--eject` → the named `EJECT REFUSED (the CARD
     verdict is REFUSED — the card must stay as evidence; no eject)`
     line — the audit's rc is UNCHANGED (1).
   - `CARD UNVERIFIABLE` + `--eject` → the named `EJECT REFUSED (the
     CARD verdict is UNVERIFIABLE — the source rows could not be
     verified; no eject)` line — the rc follows the archive audit
     (UNCHANGED by the flag).
   - The eject command's failure (device busy, not a volume, missing
     binary) → the named `EJECT FAIL (the eject command failed: …)`
     line + **rc 1** (the requested action did not happen — the
     operator must know; the verdict line above already printed).
   - Windows: the named platform refusal (`EJECT REFUSED (the
     auto-eject is not yet supported on this platform — …)`) — the
     std-only boundary (a specific-volume eject has no clean std
     mechanism; the Shell API needs FFI). `CARD UNLOCKED` + rc 0
     stand: the release is not refused, only the auto-eject — the
     operator's own unmount proceeds.

   The platform eject (the std-only spawn): macOS =
   `diskutil eject <mount-point>`; Linux = the `/proc/mounts`
   longest-prefix match of the source path → `eject <device>`.
   The env override `FP_EJECT_CMD` replaces the spawned eject command
   (the documented test seam — the CI_CARGO_AUDIT_BIN precedent;
   unset = the platform command). `--eject` without `--source` is the
   named **rc 2** (a CARD verdict does not exist without a source —
   the eject gate IS the verdict).

   With `--eject`, the ops ledger row's verdict column carries the
   eject outcome (`CARD_OK_EJECTED` / `CARD_OK_EJECT_REFUSED` /
   `CARD_OK_EJECT_FAIL` / `CARD_REFUSED_EJECT_REFUSED` /
   `CARD_UNVERIFIABLE_EJECT_REFUSED`); without `--eject` the CARD_*
   verdicts above stand.

3. **Bake the archive.** With the card released, the archive dir
   becomes the working archive; the reel container is baked from it:

   ```
   frameprism bake <archive-drive>/out <archive-drive>/reel
   ```

   (With `--iso`, the reel's per-clip archives + manifests are imaged
   as a natively mountable ISO9660 disk image — run it twice into two
   paths and compare the sha256: the images are byte-identical, the
   determinism check.)

4. **The archive-only audit, after the card is gone.** Once the card is
   unmounted (or gone entirely), the archive is verified on its own:

   ```
   frameprism audit <archive-drive>/out            # the archive-integrity pass (unchanged)
   frameprism audit <archive-drive>/out --source <card-root>
   ```

   The second form, pointed at the card's (now absent) mount point,
   prints the `CARD UNVERIFIABLE` honesty line and the archive audit's
   own verdict stands — the source rows are not re-verifiable, and that
   is named, not silent. (The source records still sit in
   `<archive-drive>/out`: a later re-mount of the same card can be
   verified against them at any time.)

## The source-sha anchor

Every encode run writes, per clip, the additive next-to record
`<CLIP>.sources.tsv` in the archive dir (flat single-clip run: the
dotfile `.sources.tsv`):

```
# frameprism source record
version: 1
tool_version: <tool version>
clip: <clip key>
note: the source-sha anchor (…)
file	size	sha256
<clip-relative file>	<size>	<sha256 of the source bytes as read at encode>
```

The rows cover EVERY source file of the clip — the DNG frames and the
non-frame members (WAV/XMP/…) — clip-relative, sorted by file name,
deterministic (no wall clock: two encodes of the same source write
byte-identical records). The sha256 is the source's as read at encode
(one read, one hash, at the encode's read site; the `--to` offload's
source rows carry the same values). The per-clip report carries the
deterministic `## sources` reference section (the record's name + row
count). The audit's `--source` surface re-hashes the card against these
rows — that comparison is the verify-before-unmount gate.

## Caveats

- **The tool never wipes the card.** There is no erase flag and no
  format path. The workflow's safety property is the ordering: encode →
  verify → release. `CARD UNLOCKED` is the only state in which
  reusing (or formatting) the card is sanctioned; everything else
  keeps the card as evidence. The `--eject` flag's auto-eject is an
  UNMOUNT only (the verify-before-unmount release) — not a wipe: it
  reinforces the ordering, never weakens it.
- **Card I/O is the bottleneck.** The encode reads every frame once
  (the ETA line estimates from that), and the `--source` audit
  re-reads + re-hashes the entire card. On a slow USB card both steps
  are I/O-bound; the wall time is dominated by the card's throughput,
  not the encode/audit compute.
- **The record is the archive's claim, made at encode time.** It
  anchors the source bytes AS READ — if the card changes after the
  encode (a re-shoot, a partial format, a rewrite), the `--source`
  audit will say so, per row, by name. That is the workflow working,
  not a defect.
- **Archives made before this feature** carry no source records: the
  `--source` audit names them `CARD UNVERIFIABLE` (the archive audit
  itself is unaffected). Re-encode from the (still mounted) card to
  gain the anchor for a given set of source files.

## The synthetic dry run — the session runbook

A synthetic-card dry run exercises this chain end to end: 30 DNGs from each
of two test clips plus one synthetic WAV+XMP member pair per clip (64 source
rows, 695 MB). This section is the public runbook; real footage and
footage-derived run artifacts are not distributed.

**The four commands (the chain above, verbatim shape):**

1. `frameprism <card-root> <archive-drive>/out --to <archive-drive>/raw`
2. `frameprism audit <archive-drive>/out --source <card-root>` — BEFORE the
   card is unmounted
3. `frameprism bake <archive-drive>/out <archive-drive>/reel` — and
   `bake … reel.iso --iso` twice → sha-compare for the sealed tier
4. `frameprism audit <archive-drive>/out` — AFTER the card is gone

**Expected verdict lines (verbatim, as measured on the dry run):**

- step 1: per-clip `<CLIP>.sources.tsv` in `<out>` (one row per source
  file, clip-relative, sorted) + the per-clip report's `## sources`
  section + the ingest/offload manifests + the raw offload in `<raw>`;
  the encode's `total: N frames (0 skipped, 0 failed) — … wall …` line.
- step 2: `CARD UNLOCKED (N source row(s) verified against the live
  source + the archive audit clean — the verify-before-wipe gate is
  clean; the card is reusable)` — **rc 0**. N = every row of every
  per-clip source record (64 in this 2×30 fixture; for the full A001
  set = every file of both clips). The per-clip OK surface prints as
  `audit: sources K/K file(s) OK (<CLIP>.sources.tsv, clip <clip>, card
  <card-path>)` per clip. **This is the only state in which
  reusing/formatting the card is sanctioned.**
- step 3: bake prints the per-clip `archive: …tar.zst (… B, …% vs raw)`
  + manifest + sidecar lines; the `--iso` run prints `image: <path>
  (… B) wall …` + the fstool/pinned-epoch lines. Two `--iso` runs into
  two paths must sha256-compare equal (measured: `0dea8f30…` ×2).
- step 4: the archive verdict stands alone (`audit: …` lines, `run OK`,
  no CARD line). Re-pointing `audit <out> --source <absent-card-path>`
  prints the honesty line `CARD UNVERIFIABLE (the source at <path> is
  absent — the source rows are NOT verified; the archive audit is
  unaffected)` — rc follows the archive audit (clean → 0). The source
  records stay in `<out>`: a later re-mount of the same card is
  verifiable against them at any time.

**Named-negative expectations (what a dirty card prints, per row, by
name — measured in this dry run):**

- tampered file (size intact, bytes changed): `FAIL source SHA_MISMATCH
  clip=<clip>: <file> (record sha256 <record>, card <actual>)` →
  `CARD REFUSED (N named source row(s) dirty — the named rows above; the
  card must NOT be formatted/wiped)`, **rc 1**.
- missing file: `FAIL source MISSING clip=<clip>: <file> (the file is
  absent from the card (<path>))` → `CARD REFUSED …`, **rc 1**.
- card absent/unmounted: `CARD UNVERIFIABLE (the source at <path> is
  absent — the source rows are NOT verified; the archive audit is
  unaffected)` — **rc follows the archive audit** (clean → 0); the
  archive audit stands.

**Wall-time budget on this machine (internal SSD; measured on the 60-frame / 695 MB synthetic card — the card-I/O steps scale ~linearly in card bytes; the full A001 2-clip set is 238 frames / ~2.5 GB ≈ 3.7×):**

| step | 60-frame synthetic (measured) | full A001 set (budget) |
|---|---|---|
| encode (cold) | 4.2 s | ~15 s |
| `audit --source` (the card re-hash) | 3.1 s | ~11 s |
| `bake` (default) | 13.1 s | ~45 s |
| `bake --iso` (each) | 13.8 / 15.0 s | ~50 s each |
| archive-only audit | 1.6 s | ~2 s |

On the real USB card, expect the card-I/O steps (encode, `audit
--source`) to be I/O-bound and scale with the card's throughput —
budget several times the numbers above and read the encode's `eta:`
line, which estimates from the same card read.

**Known free variables (not defects; what may differ run-to-run):**

1. The `created:` unix-epoch line — in `card.ingest-manifest.tsv`,
   `card.offload-manifest.tsv`, and the run-level
   `.frameprism-run-report.md` (wall clock by design; excluded from the
   determinism checks). The per-clip reports and the
   `<CLIP>.sources.tsv` records carry **no** epoch.
2. The ISO staging name — a per-run random `$TMPDIR/frameprism-iso-<pid>-…`
   staging dir; **never in the archive bytes** (the image is pinned:
   `--modification-date=2026091400000000` +
   `SOURCE_DATE_EPOCH=1789344000`); the image sha is byte-stable
   (verified across two runs).
