# frameprism CLI — design notes (the relocated `--help` narrative)

The `--help` output is the user surface (facts only, no narrative); the
design narrative — the why + the rc semantics + the honesty lines + the
design decisions per command/flag, referencing the exact flag/command
names — is documented here.

## Commands

### `bake`

The archival container + the mandatory `<clip>.bake-manifest.tsv`
(per-file sha256 sidecar — R4: the container archives, the manifest
verifies; the sweep over it closes the store-tar silent-corruption
path). Container detection (measured): J92 output −4.4…−13.8% under zstd
(granularity > codec level); JXL incompressible (0% in all 10
containers) — detection therefore defaults j92 → tar|zstd-19 and
jxl → plain tar; an explicit `--zstd` always wins.

`--iso`: `<output>` is an IMAGE PATH — the reel's per-clip archives +
manifests are staged and imaged as a natively mountable
ISO9660+Joliet+RockRidge disk image (the pinned in-process fstool 0.4.33
writer + the pin-times pass — the epoch-pinned mtimes, no external
binary); the mount is the audit surface (extract the per-clip tars +
sha-sweep every member against the embedded sha256 manifest).

`--reel-out` (the sealed-tier ride, `--iso` only): the signed
working-tier reel manifest + its `.sig` ride the image as the
`provenance/` bundle at the image root — the reader extracts
`provenance/` and runs `frameprism verify
provenance/reel.reel-manifest.tsv --key <pubkey>`; see
docs/provenance.md. The keyless sealing checks refuse named (rc=2,
zero partial files): the manifest + `.sig` present, the envelope
well-formed, the envelope's `manifest_sha256` binding the manifest
bytes, and the content-row binding (every parsed field must match
except the epoch-derived free variables — the `created:` epoch line
and the per-row `manifest_sha256` column, which hashes the per-clip
manifest, whose only free variable is its own `created:` line — a
signature for a different reel is refused the seal). On the non-iso
path = the named usage refusal. Absent = the existing image shape
(byte-identical).

`--resume`: the object sha sidecar is the completion
marker — the final archive object WITH a verifying `.sha256` sidecar
(re-hashed) + the manifest = done → the named skip, no re-bake;
without it (or a stale file_count) = interrupted → the leftover temps
are cleaned up + named and the bake redoes from zero. Absent = the
the legacy behavior (an existing archive is refused without --force).

`--clips` / `--skip`: comma separated clip keys to BAKE / LEAVE
OUT (tree: the clip folder names; flat --iso: the frame name prefixes;
flat: the single clip name). Unknown name / conflict / empty effective
set = the named rc=2 before any file. Absent = the full set
(byte-identity). The selection is journaled (the ledger's `selection`
column) + the bake summary carries the `selection:` line.

### `decode`

The decompression / restore-drill primitive: decode
an encoded clip dir to per-frame 16-bit PAMs.

### `offload`

The standalone pass-through mirror + verify
(`offload <in> <to> [<to> ...]` — N destinations in one pass,
the multi-destination fan-out) — no encode: the WHOLE tree (the
frames + every non-DNG sidecar — WAV/XMP are first-class
members, any camera, any format) is re-scanned (sha256 — the
source's bytes are read ONCE per file and written to EVERY
dest: the card read is the bottleneck, N dests cost one card
pass), copied to every destination (mirrored subpaths,
mtime-preserving), re-scanned per destination (each dest file
is hashed after its write), and rowed into the per-clip
offload manifests at each dest's mirrored clip roots (the
wire-contract format — the manifest's `dest` header row is ITS
dest — `restore` / the `audit` reverify read it unchanged) +
ONE run report at EVERY dest root (the
`.frameprism-run-report.md` pattern, one `created:` line each:
the per-clip detection lines ONCE — the detection is
source-side, run once — + one per-dest section per dest (a
`### destination: <dir>` header + the copy summary + the named
FAIL lines + that dest's verdict line); each report carries the
whole run — every dest's status). The read-once/write-N claim
is a STREAMING implementation: the fresh multi-dest
form opens the source ONCE and streams 1 MiB chunks to every
dest's temp while hashing inline — the per-file working set is
the 1 MiB chunk buffer, NOT the file (the bounded memory; the
one-shot whole-file read's O(file) heap is gone), and the
re-verify paths — the offload's per-dest re-scan, the `audit`
reverify, the `restore` master verify — read with the same
bounded streaming pass.

The offload never transforms: it mirrors. Even a profiled camera's
frames ride as bytes (never decoded, never re-encoded) — the
destination holds a MIRROR of the card, verifiable against the
source; the transform (the DNG profile's encode) stays on the
encode path. Mixing the two would break the source-mirror
verification.

Duplicate detection (copy just what's new — automatic, no flag):
a dest file that already exists with the SAME content (the
pre-check: the file exists, its size matches the source's, and
its sha256 matches the source's sha256) is verified ONLY — the
read + hash the run performs anyway — and NOT re-copied (no
copy, no mtime set; the skip never touches the dest file's mtime).
Re-runs of an offload copy just what's new. The skip is NOT
dirty: a skipped row is `OK` (the dest content WAS verified
against the source — sha256 equal is exactly the OK definition);
the per-clip counts, the verdict line (`VERIFIED` / `REFUSE`),
the rc (0/1/2), and the wire contracts (the per-clip manifests —
byte-frozen, the skip fact never rides on the wire — and the
`audit`'s re-verify) are unchanged: a mirror written with skips
re-verifies at any later time exactly as today (the skip history
is not a mirror fact). A size- or sha-mismatch pre-check falls
through to the copy path (the copy OVERWRITES — a re-run stays
idempotent + re-verified). The skip fact rides in the run
report's new `## skipped` section (PRESENT ONLY WHEN ≥1 row was
skipped at that dest: the per-clip rows — one line per clip WITH
≥1 skip — + the `totals: <N> file(s) skipped (already present,
sha256-verified — not re-copied)` line) + the job report's new
`skipped` column (md/HTML `yes`/`no`, CSV `1`/`0` — the CSV
header pin moves to `clip,file,size_bytes,source_sha256,dest_
sha256,verdict,skipped,copied_ms`). The `copied_ms` of a skipped
row = the verify-only window (the pre-check stat + read + hash;
NO write — the duration semantics: skipped rows carry the verify-
only window (no write); the non-skipped rows' window is
unchanged). The escape hatch (force the re-copy of an already-
present identical file) is a future `--force-copy`-class flag —
a named follow-up, not shipped.

The job report at EVERY dest root (automatic — no flag — the
save-with-job placement: the record of the offload job, the
the structured job-report format): `.frameprism-job-report.md` (the project
markdown — the report's idiom), `.frameprism-job-report.csv`
(the plain flat form — spreadsheet-compatible: the first line is
the column header row `clip,file,size_bytes,source_sha256,
dest_sha256,verdict,skipped,copied_ms`, one row per file, RFC-4180-minimal
quoting — the named deliberate deviation from the manifest TSV
idiom: NO comment magic, a `#` line would break spreadsheet
loading), `.frameprism-job-report.html` (the self-contained styled
form — the inline style only, zero external resources, zero
JavaScript, zero images, the text escaped). Written at the run's
end, AFTER the per-clip manifests + the run report (the records
stand first). The content (the manual's Detailed + Summary levels
in ONE report — the project idiom): the session block (the input
path as given, the dest path, the report's own `created:` stamp —
separate from the run report's created line, the tool + version
line, the job identifier — the run's UTC timestamp), the summary
block (the file count + total size + the run duration — seconds,
1-decimal — + that dest's verdict line verbatim), the per-clip
blocks (the detection line verbatim — the three classes; the
clip's file count + size + copy+verify duration in ms; the
per-file table: the relpath, the size, the source + dest sha256,
the verdict, the skipped column (the duplicate
detection: `yes`/`no` in the md/HTML, `1`/`0` in the CSV), the
per-file copied_ms). The media details are the
detection identity + the file counts/sizes/durations/verdicts:
the standalone offload is pass-through — the DNG payload is NOT
parsed (the detection reads the Make/Model headers only); the
frame/TC details are the encode path's ingest gate. The
durations are the per-file copy+verify window (the write + the
dest-side re-scan + hash for that dest — the read-once source
side is amortized across the dests — not a pure I/O throughput
number); skipped rows carry the verify-only window (no write —
the duplicate detection's verify-only pass: the pre-check stat +
read + hash, never a write); they ride ONLY in the job report — the
manifests, the
run report, and the stderr surface are unchanged by the timing
(the wire contract is untouched). The job report is the RECORD,
not the gate: the rc semantics above are unchanged (it renders
the run's verification results — it never re-verifies or
re-hashes); a job-report write failure is a named hard error
AFTER the records stand (the manifests + the run report are
already written). The encode surface's `--to` path gets no job
report (v1 — the named follow-up).

The ASC MHL history at EVERY dest root (automatic — no flag — the
industry provenance standard's media-hash-list record, the ASC
MHL, the `urn:ASC:MHL:v2.0` lineage — the provenance record
written beside every offload copy): the `ascmhl/` directory at
the dest's top level (the spec's placement) + ONE manifest per
run (`NNNN_<dest-basename>_YYYY-MM-DD_HHMMSSZ.mhl` — the 4-digit
generation from 0001, the dest's folder name, the run's creation
instant in UTC) + the `ascmhl_chain.xml` (one
`<hashlist sequencenr="N">` record per generation: the manifest
file's name + its C4ID — the C4ID = SHA-512, base58-encoded
over the C4ID character set (the spec's Appendix D — the
format's one hash algorithm, `c4`) — the chain mandates it). The
generation-1 semantics: the `transfer` process, every file hash
`action="original"` (the `verified`/`failed` actions belong to
the MHL verify pass — the named follow-up), the `creationdate`
+ every `hashdate` + the file name's date/time = the run's
creation instant (the run report's `created:` unix seconds —
one run instant), `hostname` = the tool's host source, `tool`
= `frameprism` + the version. The hashes: every managed file's
C4ID (the DEST copy's bytes — the provenance record is of the
copy; the per-file source→dest sha256 verification rides the
offload manifest — the two records complement each other, sha256
is not in the MHL format) + the scope root's + every
subdirectory's content/structure pair (the spec's Appendix G
hash-of-hashes: the content = the hash-of-hashes over the
children's content hashes, the structure over the per-child
mixes — a child directory mixes its STRUCTURE hash into the
parent's structure). The `<ignore>` set (pinned): the history
covers the MEDIA, not frameprism's records — the mandatory
defaults (`.DS_Store`, `ascmhl` — the history's own files), the
`._*` shadow prefix, and the frameprism artifact names (the
offload / ingest / reel / bake / derive manifests, the members
record, the checksum sidecars (both flavors), the source
record, the QC sidecar, the clip reports (both renames), the run
report (both renames), the job report's three names, the
signature sidecars). The re-run model (append-only, never a
clobber): a run onto a dest that already carries an `ascmhl`
history reads the chain (the next generation = the max
`sequencenr` / manifest `NNNN` prefix + 1), writes the NEW
generation's manifest, and APPENDS the chain record — the
existing records are preserved byte-for-byte (a corrupted or
foreign chain that lacks the closing tag is a named refusal,
never a clobber). Written LAST — after the per-clip manifests +
the run report + the job report (the records stand first — a
write failure is a named hard error, the records already stand);
silent on success (the stderr surface gains no line). The durability
seam: the manifest's + the chain's bytes are
filesystem-synchronized (`sync_file`) after their writes (a sync
failure = the named hard error — the run's rc becomes the error rc)
+ the `ascmhl/` dir's best-effort sync after (the pinned note on
failure — the content stands). The writing
side: the encode surface's `--to` ascmhl is the named follow-up.
Interoperability scope: FramePrism's writer/parser, adversarial suite,
C4ID/roothash vectors, and re-verification path are tested. Round-trip
interoperability with an independent third-party ASC MHL implementation has
not yet been exercised.

The MHL VERIFY pass is the `audit` verb's re-verify surface (the
MHL read side — the recompute of every recorded c4 + the
roothash seal check over the conformant v2.0 hashlist — see the
`audit` section); the `verified`/`failed` action generations
remain the named follow-up.

The per-clip camera/format detection is a REPORT, not a gate: each
clip's line names one of the three classes — `profiled <camera>
(profile v<n>)` / `unprofiled camera <Make> <Model>` / `non-DNG
media` — and identity NEVER refuses the copy (any tree is copyable
and verifiable). The encode surface's FROZEN unknown-camera
refusal is untouched (the transform's byte-frozen correctness
depends on the measurement; the copy's does not). A new camera is
still a new profile file + the measurement, never a heuristic.

The pre-write refusals cover EVERY dest before any copy (zero
partial writes anywhere): the input exists + is a dir (checked
once), the self-mirror guard per dest (`in` == `to_i` — the
mirror would copy every file onto itself), a duplicate dest is
refused named (`to_i` == `to_j` — the fan-out refuses the
duplicate, it does not silently dedupe it), the dest probe per
dest (exists + writable — the N probes complete before the
first source read).

rc: 0 every row OK at every dest; 1 ANY dirty dest (the
per-dest named FAIL lines + the per-dest `OFFLOAD FAIL` lines
AFTER the run — the clean dests still print their `VERIFIED`
lines, every dest named; the verdict is carried, the run is
not killed mid-copy); 2 the pre-write refusals (above). The
VERIFY-BEFORE-WIPE rule is the contract: the card is reusable
only after EVERY dest's verdict line says `VERIFIED` (`offload:
VERIFIED <n>/<n> (dest <dir>)` per dest; `REFUSE <k> named
row(s)` otherwise) — the re-run on verified dests is idempotent
+ re-verifies (the existing dest files with matching content are
verified in place — NOT re-copied — and the different-content ones
are overwritten + re-scanned). After the run, at any later time,
`frameprism audit <dest>` re-verifies every row of each dest
against the recorded source sha256 + size (the dest bytes as
they sit NOW — a fan-out dest is a standalone mirror: the
audit's re-verify surface per dest — the named FAIL lines + the
rc carry the verdict: a backup is re-trusted only after the
audit says OK — see the `audit` section).

Honest residuals: a nested `in`/`to` is unguarded beyond the
self-mirror guard; no eject/wipe — the verdict is the safety line,
the wipe is the card's, not the tool's.

The multi-source form (`--source <tree>... --dest <dir>...` — the
sources named by flag, the dests by flag, NO positionals: the
usage line is `frameprism offload [in] <to>... [--source <SOURCE>...
--dest <DEST>...]`): N sources fanned to ALL M dests in ONE job
(the N×M pair set — every source mirrored to every dest).
The per-source work runs CONCURRENTLY (one `std::thread` per
source, scoped; each source's work is disjoint — its own dest
subtrees: the sources' mirrored entries are distinct top-level
names, so the concurrent writes never share a path). The
detection is per-source (run once per source, source-side —
the same report-not-gate semantics); the copy + verify is
per-source × per-dest. The per-dest-root artifacts are written
in the SERIALIZED tail (one `std::thread` at a time — the
records are the shared surface): the run report (the
multi-shape: the `# frameprism offload run report — <M> source(s)`
title, the `input:` line PER SOURCE in the given order, the
per-source `### source: <in>` detection sections, and the
per-source × per-dest `## copy — source: <in>` blocks (the
copy summary + the `## skipped` section (the pinned
format, PRESENT ONLY WHEN ≥1 row of that pair was skipped) +
the named FAIL lines + the PAIR verdict line
`offload: VERIFIED <n>/<n> (source <in>, dest <dir>)` /
`offload: REFUSE <k> named row(s) (source <in>, dest <dir>)`)) +
the job report (the multi-shape: the session's `input:` line
per source, the CSV's `source` column after `verdict` + the
`skipped` column (the duplicate detection — the same
column the legacy CSV's pin carries) — the header
`clip,file,size_bytes,source_sha256,dest_sha256,verdict,
source,skipped,copied_ms` — the md/html tables' `source`
column after `file` + the `skipped` column at its
shipped position (after `verdict`)) + the ascmhl history (ONE manifest per dest per run —
the merged hash set: every source's entries under the ONE scope
root). After the per-pair lines, the JOB-LEVEL line
(uniform — rendered for every multi-shape job): `offload:
VERIFIED <total-ok>/<total-files> (<M> source(s) × <N> dest(s))`
/ `offload: REFUSE <total-dirty> named row(s) (<M> source(s) ×
<N> dest(s))` (the totals across pairs). rc: 0 every pair
CLEAN; 1 ANY pair dirty (all pairs named — the sweep) or a
SOURCE-THREAD failure (the named line `OFFLOAD FAIL — source
<in>: <err>` — the other sources' pairs still complete, their
records stand); 2 the pre-write refusals. The form bands
(named, rc=2, before ANY write): the sources are named ONCE —
the positional input (the single-source form) or `--source`
(the multi-source form), not both; the dests are named ONCE —
the positional dests (the single-source form) or `--dest` (the
multi-source form), not both; `--source` without `--dest` is
refused named (the multi-source form names its dests with
`--dest`); `--dest` without `--source` is refused named; neither
is refused named (the offload needs a source). The phase-0
bands (the multi-source generalizations of the existing guards,
all rc=2, before ANY write): a NESTED pair of sources (one
source inside the other — the mirror semantics are undefined),
a CROSS-SOURCE top-level name collision (a clip dir/file
present in two sources — the offload refuses to merge two
sources' entries under one name), the PER-PAIR self-mirror
guard (any source == any dest — the existing guard, the pair
named), the duplicate dest (the existing refusal, unchanged),
and the SHARED SOURCE BASENAME (two sources whose canonicalized
basenames are exact-equal — the source-root manifests would
collide at the dest roots; name the source dirs distinctly).
The legacy positional form (`offload <in> <to>...`) is
BYTE-IDENTICAL to its pre-multi-source rendering — the
multi-source form is the `--source`/`--dest` flag form; the
positional invocation is the single-source form's.

Interruption safety + convergent resume (automatic — no flag — the
copy path's interruption story): the copy lands via a TEMP file +
atomic `rename` (the manifest writer's tmp+rename pattern,
generalized to the media files) — the temp is written in the dest
clip dir (the SAME filesystem as the final path = the rename is
atomic), named `._frameprism-offload-<job:08x>.<dst file name>.tmp`
(the per-process 8-hex job id — the name is non-deterministic by
design and never rides on the wire — reports/manifests carry no
temp name; the `._*` prefix rides the ascmhl manifest's
PRE-EXISTING ignore pattern — the zero-manifest-byte-change fact),
so the FINAL media path holds ONLY complete, verified files: an
interrupted job (Ctrl-C, SIGKILL, crash, power) leaves the temp —
never a partial at the final path (a FAILED copy deletes its own
temp; a pre-existing temp at the helper's tmp path is the NAMED
concurrent-job refusal — `error: the offload temp file <tmp>
already exists (a concurrent job writes this dest — run the
offload jobs against a dest root sequentially)` — never
overwritten: `fs::copy` would truncate it silently). A RE-RUN of
the same job CONVERGES: the skip predicate (the duplicate
detection above) verifies the already-present files, the
missing/partial/changed files re-copy (the atomic rename replaces
— a partial at the final path from the direct-write era is
overwritten + re-verified), and the phase-0 STALE-TEMP CLEANUP
(after the dest probes, before the first source read) deletes the
prior interrupted job's temps — the files whose name starts
`._frameprism-offload-` AND ends `.tmp` (the exact-name double
rule — the junk temps only, never media) — with the named note
line `note: removed <n> stale offload temp file(s) from a prior
interrupted job at <dest>` (per dest root; the clean-path stderr
stays byte-frozen — the note fires ONLY when a cleanup actually
happens or an mtime set fails). PAUSE semantics: no SIGINT handler
(the std-only posture admits no signal crate) — "pause" = stop the
job by any means; the convergent re-run above is the resume
guarantee (the feature).

Durability (the honest vocabulary — what `VERIFIED` proves): the
verdict's content claim is the comparison (size + sha256, both
sides — the source re-scanned fresh + the dest re-scanned after its
write), and the storage claim is pinned now too: every file the
offload job writes is filesystem-synchronized (`sync_all` — the
process's write buffer pushed to the filesystem) BEFORE it stands at
its final path — the media files: the sync sits in the copy's
error-propagating path BEFORE the atomic rename (the atomic-copy
seam's `io::copy` closure; the fan-out's per-dest open handle — a
sync failure = a NAMED error: the dest row FAILs via the existing
failure machinery — the named error + the row `COPY_FAIL` detail, the
sweep continues); the records (the per-clip manifests, the run
report, the job report, the ascmhl manifest + chain): the mandatory
file sync in the writer's named hard-error band (a sync failure =
the named error — the job fails exactly as a write failure does) —
+ a BEST-EFFORT directory sync after the successful rename / record
write (the rename's dir-entry update is the thing a crash can lose;
its failure is the pinned note `note: the offload durability dir
sync on <dir> failed (<error>) — the content copy stands` — the
mtime-note precedent: best-effort + named note, the content copy
stands; the clean-path stderr gains no line on a healthy
filesystem). What the tool does NOT claim: physical durability. The
drive/card write-cache behavior is platform-specific — a volatile
write cache can still drop bytes the filesystem has not been asked
to flush; the tool's guarantee stops at the filesystem
synchronization. The `VERIFIED` / `REFUSE` verdict lines themselves
are byte-frozen (no wire change — the semantics ride these docs, not
the lines).

### `audit`

Full-integrity sidecar audit (the audit/restore
arc): re-read every file the sidecar lists and recompute size + sha256
(+ crc32c where the column exists); every offender reported named.
rc=0 clean, rc=1 offenders named, rc=2 usage. The sidecars: J92
`<CLIP>.checksums.tsv` (4-column v2 with the sha256 column) or the JXL
`<CLIP>.jxl-checksums.tsv` (always sha256); a 3-column legacy J92
sidecar is a hard reject (regenerate with --checksums).

The standalone offload mirror is a valid audit surface (the
re-verify-a-backup-later pass): a dir carrying `*.offload-manifest.
tsv` records (top level or the clip subdirs — the standalone
`offload` mirror's shape) but no archive sidecar is audited for the
offload records only (the named note `no archive sidecar in <dir> —
auditing the offload re-verify record only`): every row of every
record is re-verified against the recorded source sha256 + size (the
dest bytes as they sit NOW — the named FAIL lines: `file missing in
the offload dest`, `SIZE_MISMATCH`, `SHA_MISMATCH`,
`OFFLOAD_DEST_MISSING`). rc=0 every row clean; rc=1 any dirty row
(all records swept — never stops at the first offender — every dirty
row named, the verdict line `audit: offload re-verify <dir>: N
manifest(s), M row(s) OK` / `… FAIL (K named offender(s))` carries
the count); rc=2 a corrupt record (the named hard refusal) — a
genuinely record-less dir keeps the no-sidecar rc=2, unchanged.
`restore` on such a tree = the unchanged no-sidecar rc=2 (the
mirror's repair primitive = the offload re-run — idempotent +
re-verified).

The MHL re-verify surface (the ascmhl read side; the
write side's `ascmhl/` history, above): a dir carrying an
`ascmhl/` history dir (the write side's placement — the scope's
top level) is re-verified against its LATEST manifest (the
`ascmhl_chain.xml`'s last record — every record's c4 verified
against its manifest's bytes; NO chain: exactly one `.mhl` is that
one; ≥2 manifests without a chain = the named ambiguity refusal —
`the <ascmhl dir> carries N manifests without a chain
(ascmhl_chain.xml) — the history is ambiguous; the record is
untrustable (add the chain or verify a single-manifest scope)`;
a chain record at a missing / mismatched manifest = the named
corrupt-record refusal — the record is untrustable, rc=2, the B5
posture). The re-verify: every recorded file is re-read + its C4ID
(SHA-512 base58 — the format's one algorithm) is recomputed
against the recorded c4 (the size pre-filter; the row vocabulary
`OK` / `MISSING` / `SIZE_MISMATCH` / `C4_MISMATCH`, the offload row
convention — the named `FAIL <path>: <class> (<detail>)` lines)
+ the roothash (the content + structure over the WHOLE scope with
the MANIFEST'S OWN ignore patterns — the import fact: a foreign
tool's conformant v2.0 hashlist verifies against its own values;
the namespace + version check is the conformant refusal — the 2009
MHL 1.1 / JSON lineage is out of scope, not a parser). An
unrecorded ADDED file keeps the file sweep clean and breaks the
roothash (the seal check — the load-bearing sealed-archive
property). rc=0 every row clean + the roothash match (the summary
line `audit: mhl re-verify <dir>: N file(s) verified, roothash OK
(the latest manifest <name>)`); rc=1 any offender (every dirty row
named + the roothash verdict named — `OK` / `MISMATCH: content` /
`MISMATCH: structure` / `MISMATCH: both` — the summary line
`audit: mhl re-verify <dir>: FAIL K offender(s) — roothash
<verdict> (the named lines above) (the latest manifest <name>)`);
rc=2 the malformed record (the parse + the selection's corrupt
classes). A dir WITHOUT `ascmhl/` audits byte-identical to
legacy (the arm is inert); a dir with `ascmhl/` but NO archive
sidecar of any kind is audited for the MHL record only (the named
note `no archive sidecar in <dir> — auditing the MHL re-verify
record only` — the offload carve-out's exact shape: a foreign
tool's scope may carry ONLY its ascmhl history); a dir with NEITHER
keeps the legacy no-sidecar rc=2, unchanged. The re-verify is PATH-INDEPENDENT: the
rows are scope-relative + the manifest sits at the scope root — a
MOVE of the whole tree keeps it verifiable (the relocation proof).
`restore` does NOT repair MHL offenders (the repair primitive =
the offload re-run, as above).

### `restore`

Per offender — the master candidate must itself pass
the sidecar row (size + sha256) or it is refused named (a corrupt
master is never swapped in); the corrupt original is kept as
`<file>.pre-restore`; the final audit pass must be clean. rc=0 all
restored, rc=1 any unrestorable (named), rc=2 usage.

### `derive`

The 12→8/10 derived working tier: derive genuine uncompressed CFA DNGs
from a dir of 12-bit master .DNGs. The pinned pixel mapping: 12→8 =
v>>4 (the primary space question), 12→10 = v>>2 — no rounding, no
dithering — + the rewritten container header (BitsPerSample 8/10 + the
per-depth strip expectations; every other header byte
verbatim). The input is READ-ONLY (the master is never rewritten); the
output is a dir of derived .DNGs (same base names) + the mandatory
`<CLIP>.derive-manifest.tsv` (bits_in → bits_out, the pinned formula,
the tool version, per-frame sha256). Non-12-bit frames are named
refusals (rc=1 per frame). The derived frames flow the existing encode
paths (j92 / jxl at the derived depth) and the decode round-trip.

### `diff`

Frame-level pixel comparator over two encodes of (hopefully) the same
source. The codec is AUTO-DETECTED
per input (the j92 .DNG layout / the jxl 4-plane layout; a plain file /
empty / ambiguous / contradictory dir = a named rc=2 refusal before
any decode). The comparison is ALWAYS at the decoded-pixel level (both
sides through the shipped p1 plane — the containers differ across
tiers): per frame IDENTICAL / DELTA (px_diff + delta_min/max + lsb_k +
the |Δ|-histogram) / MISSING (named, which side) / FAILED (named).
Same-codec pairs = the 3-candidate / tool-version-migration use case;
cross-codec pairs prove the cross-tier lossless contract (the `both`
run's OUT + OUT-jxl). `--report` is DETERMINISTIC (no wall clock, no
absolute paths — the same inputs are byte-identical across runs).
rc=0 when the comparison completed (a delta is a FINDING), rc=1 on any
MISSING/FAILED, rc=2 usage; `--strict` exits 1 on any DELTA. ONE
ledger row per completed run (verdict diff-IDENTICAL / diff-DELTA /
diff-FAIL); no status lines (v1 — the audit/decode posture).
READ-ONLY on the inputs.

### `repair`

The re-copy delta — the repair loop: after the
two-destination offload a mismatch/missing row does NOT re-run the clip. Operates from the EXISTING offload manifest
+ the source tree: the manifest-row diff per destination (missing /
size-mismatch / sha-mismatch / clean; the fresh source hash is the
canonical reference), the selective re-copy of the dirty rows only
(mtime-preserving, `--rows <csv>` to scope them), the re-verify (both
sides re-hashed fresh), the manifest rewrite (the repaired rows'
verdicts flip; the header stands verbatim) + the run-report re-emit (the updated verdict line + the named `offload dirty:` rows —
deterministic, no new wall clock). The disk verdict (any destination:
the `--to` full mirror + the workspace member copies) flips VERIFIED
only when the FULL set is clean (a clean delta never unlocks the
camera disk while any row is still dirty). rc=0 the full set clean,
rc=1 rows still dirty (named), rc=2 usage (a missing/corrupt offload
record, a dest/input that does not match the recorded record, an
unknown --rows name).

### `ledger`

The append-only ops ledger (the run journal): list the rows (newest last, the file order) + the ROTATION REPORT —
every distinct output with a completed bake/bake-iso row whose most
recent audit row is older than N days (default 90; `--since N` also
lists only the last N days and is the rotation window) is listed
`ROTATE <output>: last audit <age> days ago` (never audited →
`last audit never`). Read-only over the journal (the writer is the run
paths; the file is user state, never a byte contract); a malformed row
is a named skip + continue. rc=0 always (the reader is never fatal —
its damage is named, on stderr). `--json`: one JSON object per row
(lines); the rotation report + the warnings land on stderr (stdout
stays the pure JSON stream).

### `sign` / `verify`

The provenance signature. `sign`:
an ed25519 signature (RFC 8032 — deterministic) over the CANONICAL
STRING (the manifest sha256 + the tool version + the date + the key
fingerprint + the pin set, the pinned v1 shape) — the NEW envelope
file `<manifest>.sig` (the manifest bytes are NEVER touched; the wall
clock lives in the envelope only — the `signed_at` field; re-sign with
the same `--date` = byte-identical .sig). The key file is the
documented external format (type: private REQUIRED — the tool
verifies, it does not mint: key generation is the documented openssl
recipe, not a tool subcommand; a corrupt key / a type: public key / a
missing manifest / an unresolvable pin set = the named rc=2 refusal,
zero partial files). The pin set = the components + version strings as
resolved by the existing pins machinery (the same source
ci/check-pins.sh asserts).

`verify`: re-derive (1) the manifest's sha256 on disk (the intactness
claim), (2) the key identity (the envelope's `key_fingerprint` vs the
presented key file — a different-key presentation is the named
fingerprint-mismatch finding), and (3) the ed25519 signature over the
re-derived canonical string (the integrity + key-identity claim — the
canonical string [the manifest sha256 + tool version + date + key
fingerprint + pin set] was signed by the key whose fingerprint the
envelope records; NOT a process claim — it does not prove the archive
was produced by frameprism). The key file is
type: public OR private (the verify uses the `public:` field — a
private key file may verify its own signatures). rc=0 the signature is
valid; rc=1 a signature FINDING (the documented offender class — the
manifest mismatch / the signature invalid / the key fingerprint
mismatch lines); rc=2 a malformed REFUSAL (the missing manifest / the
missing or corrupt envelope / the corrupt key file — zero partial
verdicts; the audit's ABSENT line is the audit's honesty surface, the
verify's missing-.sig is the usage refusal).

## Legacy encode surface (the positional `input` / `output`)

### The positionals

`Option` at the clap level ONLY for the clap 4.6.6 positional-subcommand
quirk — the legacy surface still requires both (the explicit check in
`main()` errors rc=2 when absent).

### `--mode` — and the parked lossy tier

`lossless` (12-bit, default) / `log10` (10-bit log: same lossless tile
structure at data precision 10 + LinearizationTable 50712).

The six lossy presets (`vbr-hq`, `vbr-lt`, `cbr3`, `cbr4`, `cbr5`,
`cbr7`) target EITHER lossy wire format (`--lossy-format`):
`dct12` (the default — the **dct12** format,
docs/format-dct12.md) or `34892` (experimental/archive,
NLE-unreadable; parked — the "34892 archive family").

**Parked + hidden:** the family
is DEFERRED (maintainer visual rejection). The OSS help
surface therefore hides the six lossy `--mode` values, `--lossy-format`,
and the three `--reference-*` flags (`hide = true` — invisible in
`--help` / `-h`), while they STAY PARSEABLE (the escape hatch; no
logic change, no re-enum, no default change — the parse-path refusal
messages `--reference-* requires a lossy --mode…` are unchanged).
Private footage-derived measurements for this parked format are not
distributed.

`--reference-ref`: the reference DNG (any preset/frame of the clip) for
`--lossy-format dct12` (default: the embedded curve constant).
`--reference-mae-tsv`: the measured per-frame MAE TSV
for `--lossy-format dct12 --verify` — the G2 pixel gate then also
requires our MAE within [0.5×, 1.5×] of the measured
same-frame MAE (default: the p99-only gate).
`--reference-structure-tsv`: the measured per-frame
structure TSV (tab-separated: frame, v_ratio, h_ratio, dem2_wg,
dem2_gr, dem2_wr) for `--lossy-format dct12 --verify` — the
structure gates then use the per-frame measured-anchored
bands (default: the independent floors only — informational
demosaic line).

### `--downscale2x`

2×2 CFA-phase-correct 2× decimation (the fp's symmetric W G / G R
pattern — `downscale::decimation_rule`; no filter; the old even/even
rule was a single-phase plane with a color cast and was superseded),
re-encoded in the same tile structure + DNG proxy
signalling (51089/51090/51091 = the original crop size). Composable
with `--mode`. `in_bytes` in the stats stays the full-resolution input
size (the ratio is against what the camera wrote).

### `--fast`

Skip the 3-candidate per-tile trial encode and always use the reference
product's
Wrapped PSV 7 (the fixed-candidate choice for both
precisions, per the per-tile probe;
price vs adaptive selection +1.4% (dark) to +4.3%
(bright) tile bytes — bit-exact lossless, verify unaffected). Composes
with `--downscale2x` and the FRAMEPRISM_ENGINE=native engine seam.

### `--resume`

The per-frame skip decision is a
MANIFEST DIFF — a frame skips ONLY if its output exists AND the
sidecar row's sha256 verifies over the on-disk output AND (when the
input carries the source-sha manifest) the source sha matches
the row; anything else re-encodes (the repair path — a missing frame,
a corrupted output, a source that changed). The sidecar is written
incrementally (header at run start, a row per completed frame,
the canonical sorted rewrite at completion — a killed run's partial
file is the resume's evidence + the torn-tail row is the named
discard). v1 scope: j92 only — `--codec jxl` + `--resume` is the
named rc=2 (the jxl sidecar is plane-based; the follow-up). The
interrupted run's leftover temps are cleaned up + named. Absent
= the legacy behavior (the naive existence-skip, the end-of-run
sidecar).

### `--subset`

The NAMED subset opt-in (the 60-frame
random-subset gate): the ingest safety gate runs
with EXACTLY the four within-clip continuity classes waived (FRAME_GAP
/ FRAME_DUP / TC_GAP / TC_OVERLAP — a sparse subset is legal by
construction). EVERY other class stays a hard refusal under the flag:
FRAME_BADNAME, TC_MISSING, TC_MALFORMED, COUNT_MISMATCH, MANIFEST_BAD,
the cross-clip REEL_OVERLAP (the double-capture disk-lock class — a
distinct purpose, never waived), and the upstream profile-resolution
refusals (unknown camera / unmeasured geometry / unmeasured
readout-depth-CFA). The waiver is recorded NAMED in every output
artifact (the honesty property): the per-clip report carries the line
`ingest-gate: subset (continuity waived — re-verify)` and the
ledger row carries the same marker in its `context` column. Absent (the
default) = the unconditional hard gate (the R3 no-escape-flag posture
— the byte-identity path; this is the NAMED door, not an escape
hatch). Both encode paths (j92 + jxl) honor it identically.

### `--dry-run` / `--dry-run-frames`

Predict-then-measure: estimate the compression rate + the ETA
on real footage BEFORE the run — encode the pinned-random sample (the
pinned LCG seed, the clamp default K = min(N, min(max(20,
ceil(N/10)), 60)) or the explicit `--dry-run-frames K`) IN MEMORY
(never written — the buffer seam, the verify pass always on: the
honesty anchor) and report the measured ratio band + the projected
archive/offload sizes + the space fit against <dest> + the ETA.
CREATES NOTHING (no files/dirs under <dest>, no sidecars/manifests, NO
ledger row — the `--report FILE` markdown is the record). The
in-memory seam is the in-process j92 encode: `--codec jxl/both` +
`--dry-run` is the named rc=2 (the cjxl subprocess tier writes by
design). The corpus-rate preflight is replaced by the MEASURED
fit-check (no fixed corpus rate — the line names the measured number).
The live metrics drive the same surface over the sequential sample
loop (the per-frame line + the `## live` section of the report).

`--dry-run-frames K`: the explicit sample size (1 ≤ K ≤ N; K=N = the
full-clip measurement, legal + named). Absent = the default clamp rule
(10%, floored at 20, capped at 60). K=0 or K>N = the named
usage refusal (rc=2, before the gate).

### `--codec`

`j92` (the default, byte-identical under the committed oracle)
/ `jxl` (JXL modular lossless, effort via `--jxl-effort` default e7,
4 × `.jxl` per frame (the 2×2 sub-planes p2_00/p2_01/p2_10/11) + the
mandatory jxl-checksums sidecar; `--jobs` sets the cjxl/djxl thread
budget (0 = all cores; N = `--num_threads=N` — cjxl 0.12.0's hidden
flag)) / `both`: sequential j92 (the
working tier → `output`) THEN jxl (the archival tier → `output-jxl`,
the literal `-jxl` suffix), each tier running its existing standalone
path unchanged (the composition contract — the both run's trees are
byte-identical to the two standalone runs). The space guard reserves
BOTH tiers' estimates (the combined preflight); the status file
carries the j92 block only (the jxl path emits no status lines); the
run report + ledger are per-tier (two rows, the codec column
canonical). v1 scope — the named rc=2 refusals (no tier-spanning
resume: the jxl tier's recovery is the standalone `--force` re-run; no
`--clips`/`--skip`: the jxl path has no selection in v1; no
`--verify-checksums`: the pass is ambiguous).

`--jxl-effort`: the measured ladder 4 | 7 | 9 (default 7;
unmeasured efforts are rejected). Measured 192-frame ladder (p2×4):
e7 4.6× faster encode than e9 for +1.3…2.7% size; e4 10.9× for
+1.9…10.1%. Flows into the cjxl `-e` invocation and the sidecar
`effort` column. Explicit `--jxl-effort` + `--codec j92` is rejected
(rc=2: "--jxl-effort requires --codec jxl").

`--jxl-parallel`: the number of
concurrent `cjxl` processes — the planes in flight across the WHOLE
reel. 0 (the default) = auto = all cores (on 14 cores: W14_T14, in the
grid's flat 16.1–16.9 s region — ~32% faster than the serial shape,
byte-identical at every setting); 1 = the serial escape hatch; >= 2 = the
W-deep pool. `--jobs` is unchanged (the
per-cjxl thread budget, the T dimension). Explicit `--jxl-parallel` +
`--codec j92` is rejected (rc=2: "--jxl-parallel requires --codec jxl").

`--cjxl-bin` / `--djxl-bin`: the cjxl/djxl binaries for `--codec jxl`
(path or PATH name). Version parity with the measured size data is the
contract (v1: cjxl 0.12.0).

### `--checksums` / `--verify-checksums`

`--checksums`: after the run, write `<OUT_DIR>/<CLIP>.checksums.tsv`
(file, size, crc32c — CRC-32C Castagnoli) over every output frame —
the "generate checksums" surface (the help names it idiomatically).
`--verify-checksums`: run ONLY the checksum verification pass —
re-read `<OUT_DIR>/<CLIP>.checksums.tsv` and every listed file,
recompute size + CRC-32C; nonzero exit on any mismatch or missing file
(no frames are encoded in this mode).

### `--qc-gate`

The deterministic class — (a)
black/blank (the pinned range/variance floor on the decoded planes) +
(b) file-level duplicate (the sidecar sha rows — no decode) become
GATES: any hit → the run COMPLETES (no data loss — the files are
written) and exits rc=2 with the named rows (the
named-negative convention — the gate is a verdict, not a preflight
refusal). Absent (the default) = REPORT ONLY: the (c) exposure stats +
the (a)/(b) candidates are always named in the run report (the
additive `<CLIP>.qc.tsv` per-frame record + the clip-level moments);
the run never gates. (c) is never a gate (a "−2 EV" reading is a
number, never a verdict); (d) focus is out of scope. j92 decode site
only: `--codec jxl` + `--qc-gate` = the named no-op note (v1). Implies
the sidecar pass (the (b) check rides the sidecar sha rows; the
per-frame record lands in `<CLIP>.qc.tsv` — `<CLIP>.checksums.tsv`
stays v3 byte-identical, the v4 content rides the additive record —
the byte contract over the literal in-file placement).

### `--to`

Two-destination ingest: after the encode, re-scan + copy EVERY file in `<in>` (the
frames + the non-DNG sidecars — WAV/XMP are first-class members) to
the dest (mirrored subpaths, mtime-preserving), re-scan the copies,
and write `<OUT_DIR>/<CLIP>.offload-manifest.tsv` (per-file verdict
rows + the per-clip verdict blocks) — the verify-before-unmount gate.
Dirty rows = named FAIL lines + rc=1 AFTER the encode (the
verify-before-wipe line lands in the run report). The dest is
probed at startup (exists + writable); unwritable = rc=2 before any
frame. Both the j92 and the jxl paths. The run + per-clip reports
carry the offload section (the verdict line + the named FAIL lines +
the per-clip detection lines) — additive: without `--to` the reports
are byte-identical.

### `--pins`

The pin self-check (the risks-row mitigation): the
byte-identity contracts probed BEFORE the first frame/byte (a
drift/missing binary = the named refusal rc=2, zero output). The flag
opts the check IN (absent = the legacy behavior, no pin gate); the
optional VALUE is an explicit pins file, and without one the default
resolution is the `FRAMEPRISM_PINS` env → `<cwd>/ci/pins.tsv`
(repo checkouts) → `<exe_dir>/../ci/pins.tsv`; not found = a named skip
line (never a refusal — installed-from-brew users have no repo; the CI
entrypoint remains the enforcement surface). NO escape flag (the
`--allow-unpinned` maintainer decision is PARKED).

### `--clips` / `--skip`

Comma separated clip keys to ENCODE /
LEAVE OUT (the input's clip key space — the frame parent dirs relative
to the input root: the tree folder names, the flat prefix convention
for a single-clip dir). The encode universe = the distinct clip keys
of the input's .DNG frames. Every name must exist (unknown = the named
rc=2 BEFORE any frame; `--clips` + `--skip` naming the same clip =
named rc=2; the effective set empty = named rc=2; an empty name
between commas = the named rc=2). Absent = the full set = the
byte-identity path (the ingest gate + the encode + the sidecar copy +
the run-sidecar operate on the selected set; a selected run copies only
the selected clips' sidecars — the input-root manifest.tsv is NOT
mirrored into a partial output). `--codec jxl` + a selection = the
named rc=2 refusal in v1 (the jxl path's frame collection is a
separate path). The selection is journaled (the ledger's `selection`
column) + the run report carries the `selection:` line.

### The short flags

`--verify`: bit-exact verify per frame (lossless: decode out == unpack
in; log10: LUT-inverted reconstruction within the curve bound + the
mode's metadata expected-diff set). `--force`: overwrite/skip-over
existing outputs (default: skip = resume). `--report`: also write a
TSV report to this path (manifest-compatible columns). `--jobs`:
worker thread count (0 = all cores, the default).
