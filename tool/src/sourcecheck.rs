//! The source-sha anchor (the direct
//! card archive — verify-before-unmount).
//!
//! `<CLIP>.sources.tsv` — the per-clip encode-input provenance record:
//! EVERY source file of the clip (the DNG frames AND the non-frame
//! members — WAV/XMP) with the clip-relative path, the size, and the
//! sha256 **as read at encode** (the card bytes at ingest — the
//! offload `source_sha256` column pattern applied to the encode input).
//! Written at ENCODE time for every encode run (the j92 AND the jxl
//! paths — `report::write_reports` is the single write site), with or
//! without `--to` (a `--to` run reuses the offload manifest's source
//! shas — zero extra reads). The record is a NEW FILE: no existing
//! record's bytes change (the byte contract — G6).
//!
//! The record is the ANCHOR for the verify-before-wipe gate:
//! `frameprism audit <archive> --source <card-root>` re-reads the SOURCE
//! tree and re-hashes every row of every discovered
//! `<CLIP>.sources.tsv` against the live source (the card): the
//! offload row vocabulary (OK / MISSING / SIZE_MISMATCH / SHA_MISMATCH,
//! + the named READ_ERROR class for an unreadable card file) per row —
//! loud, named, no silent skip. A row that no longer matches means the
//! card content moved AFTER the encode — the card is suspect, not the
//! archive. The tool NEVER wipes the card: `CARD UNLOCKED` is the
//! human's release (the operator formats only after seeing it).
//!
//! Determinism (the contract): NO wall clock — the same source
//! state produces the same bytes; the rows are sorted by path.
//!
//! The decode-site registry (the pins/selection/qc OnceLock pattern):
//! `worker::run` notes the source buffer's sha256 DURING the encode
//! read (one read, one hash — no second full-file read; the card I/O
//! is the bottleneck). `report::write_reports` claims it per frame
//! (the sidecar row key); frames this run did not read (the
//! resume-skip, the jxl path, the failed frame) fall back to the
//! write-site read in report.rs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// The magic line of the source record `<CLIP>.sources.tsv` (the
/// additive next-to pattern — the members record / the offload
/// manifest ride the same name space).
pub const SOURCES_MAGIC: &str = "# frameprism source record";

/// The source record file name suffix (`<CLIP>` + the suffix; the flat
/// key "" → the dotfile `.sources.tsv` — the per-clip record's
/// convention).
pub const SOURCES_SUFFIX: &str = ".sources.tsv";

/// The source record column line: one row per source file of the clip
/// (the clip-relative POSIX path — path-independent, the record
/// survives a move of the tree), the size in bytes, the sha256
/// (lowercase 64-hex — the canonical digest the re-verify checks
/// against; "-" = the named absence: the source was unreadable at
/// encode, the row can never verify — the card is REFUSED on it).
pub const SOURCES_COLUMNS: &str = "file\tsize\tsha256";

/// The source record file name for a clip: `<CLIP>.sources.tsv`.
pub fn sources_name(clip: &str) -> String {
    format!("{clip}{SOURCES_SUFFIX}")
}

/// One source record row (the three data columns).
#[derive(Clone, Debug, PartialEq)]
pub struct SourcesRow {
    /// The clip-relative path (POSIX; a top-level file is its
    /// basename).
    pub file: String,
    pub size: u64,
    /// The source file's sha256 as read at encode ("-" = unreadable at
    /// encode — the named absence).
    pub sha: String,
}

/// The parsed source record (the audit's parse surface — the strict
/// shape, the offload-manifest convention).
#[derive(Clone, Debug)]
pub struct SourcesRecord {
    /// The record's file name (`<CLIP>.sources.tsv`).
    pub name: String,
    /// The clip key ("" = the flat clip — the input root).
    pub clip: String,
    pub rows: Vec<SourcesRow>,
}

// ---------------------------------------------------------------------------
// The decode-site source-sha registry (the read-site hash)
// ---------------------------------------------------------------------------

/// The source-sha registry (the pins/selection/qc OnceLock pattern — a
/// process-wide static; one run per process, no reset needed).
static SOURCE_SHAS: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();

fn registry() -> &'static Mutex<BTreeMap<String, String>> {
    SOURCE_SHAS.get_or_init(Default::default)
}

/// Note one frame's source sha at the encode read site (worker::run,
/// right after the source buffer read — ONE read, ONE hash; the buffer
/// is already in memory for the decode). Keyed by the sidecar row key
/// (the output-relative frame path, POSIX — the worker `process`
/// closure's `rel`); absent key = a non-encode caller.
pub fn note_source_sha(rel: &str, sha: &str) {
    registry().lock().expect("source-sha registry poisoned").insert(rel.to_string(), sha.to_string());
}

/// Claim one frame's source sha (the report's record write site).
/// `None` = the run did not read this frame's source (the resume-skip /
/// the jxl path / the failed frame) — the caller's write-site fallback.
pub fn claim_source_sha(rel: &str) -> Option<String> {
    registry().lock().expect("source-sha registry poisoned").get(rel).cloned()
}

// ---------------------------------------------------------------------------
// The record write + parse (the strict shape)
// ---------------------------------------------------------------------------

/// Write the source record `<CLIP>.sources.tsv` (temp + rename — the
/// atomic-write convention: a kill mid-write leaves the previous
/// complete record in place, never a torn final file). Deterministic
/// bytes (no wall clock — the contract): the same source state →
/// the same record. `rows` = (file, size, sha) — the caller sorts by
/// file (the record is the anchor: the row ORDER is the contract).
pub fn write_sources_record(
    output: &Path,
    clip: &str,
    rows: &[(String, u64, String)],
) -> std::io::Result<PathBuf> {
    let mut tsv = String::new();
    tsv.push_str(SOURCES_MAGIC);
    tsv.push('\n');
    tsv.push_str("version: 1\n");
    tsv.push_str(&format!("tool_version: {}\n", env!("CARGO_PKG_VERSION")));
    tsv.push_str(&format!("clip: {clip}\n"));
    tsv.push_str("note: the source-sha anchor (the verify-before-wipe gate — the source bytes as read at encode; the audit --source re-hash compares against these rows; the tool never wipes the card — CARD UNLOCKED is the human's release)\n");
    tsv.push_str(SOURCES_COLUMNS);
    tsv.push('\n');
    for (file, size, sha) in rows {
        tsv.push_str(&format!("{file}\t{size}\t{sha}\n"));
    }
    let path = output.join(sources_name(clip));
    let tmp = output.join(format!(".{clip}{SOURCES_SUFFIX}.tmp"));
    std::fs::write(&tmp, tsv)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Parse a source record (this module's writer — the strict shape):
/// the magic line, the `key: value` header lines (`clip` required;
/// `version` / `tool_version` / `note` skipped — the additive
/// convention), the exact column line, the 3-column data rows. A bad
/// magic, a missing clip field, a bad size field, or a non-3-column
/// row is a hard named error (the audit turns it into the named hard
/// rc=2 — the offload-manifest convention; never a silent skip).
pub fn parse_sources_record(path: &Path) -> Result<SourcesRecord, String> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("read the source record {name}: {err}"))?;
    let lines: Vec<&str> = text.lines().collect();
    let first = lines
        .first()
        .ok_or_else(|| format!("empty source record {name}"))?;
    if *first != SOURCES_MAGIC {
        return Err(format!(
            "{name} is not a frameprism source record (first line {first:?}, want {SOURCES_MAGIC:?})"
        ));
    }
    let mut clip: Option<String> = None;
    let mut rows: Vec<SourcesRow> = Vec::new();
    let mut in_data = false;
    for (idx, line) in lines.iter().enumerate().skip(1) {
        let lineno = idx + 1;
        if !in_data {
            if *line == SOURCES_COLUMNS {
                in_data = true;
            } else if let Some(v) = line.strip_prefix("clip: ") {
                clip = Some(v.to_string());
            }
            // the other header keys (version / tool_version / note) —
            // additive by convention.
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if !line.contains('\t') {
            return Err(format!(
                "bad row in {name} line {lineno} (want 3 tab-separated columns: file, size, sha256): {line:?}"
            ));
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 3 {
            return Err(format!(
                "bad row in {name} line {lineno}: {} columns (want 3: file, size, sha256)",
                f.len()
            ));
        }
        let size: u64 = f[1]
            .parse()
            .map_err(|_| format!("bad size column {:?} in {name} line {lineno}", f[1]))?;
        rows.push(SourcesRow {
            file: f[0].to_string(),
            size,
            sha: f[2].to_string(),
        });
    }
    let clip = clip
        .ok_or_else(|| format!("no clip field in {name}"))?;
    if !in_data {
        return Err(format!("no column line in {name} (want {SOURCES_COLUMNS:?})"));
    }
    Ok(SourcesRecord {
        name,
        clip,
        rows,
    })
}

// ---------------------------------------------------------------------------
// The verify-against-source classification (the audit --source surface)
// ---------------------------------------------------------------------------

/// The source row's verdict (the offload row vocabulary — the named
/// classes — + the named READ_ERROR class for an unreadable card
/// file, the offload COPY_FAIL's extension): a dirty row
/// keeps the card locked (the gate is a full-set claim).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceClass {
    Ok,
    Missing,
    SizeMismatch,
    ShaMismatch,
    ReadError,
}

impl SourceClass {
    /// The named class word (the FAIL line's column).
    pub fn as_str(self) -> &'static str {
        match self {
            SourceClass::Ok => "OK",
            SourceClass::Missing => "MISSING",
            SourceClass::SizeMismatch => "SIZE_MISMATCH",
            SourceClass::ShaMismatch => "SHA_MISMATCH",
            SourceClass::ReadError => "READ_ERROR",
        }
    }
}

/// Classify ONE record row against the live card file. `target` = the
/// card file the row names; `card_label` = the named display of the
/// checked source (the record's clip dir — the FAIL line names it).
/// The FIRST mismatch is the named problem (size → sha256 — the
/// offload row-vocabulary order); a stat/read failure is named too
/// (loud, not silent). `None` = OK.
pub fn classify_source_row(target: &Path, row: &SourcesRow, card_label: &Path) -> Option<(SourceClass, String)> {
    let meta = match std::fs::metadata(target) {
        Ok(m) if m.is_file() => m,
        Ok(_) => {
            return Some((
                SourceClass::Missing,
                format!(
                    "the file is absent from the card ({}) — not a regular file",
                    card_label.display()
                ),
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Some((
                SourceClass::Missing,
                format!("the file is absent from the card ({})", card_label.display()),
            ))
        }
        Err(e) => {
            return Some((
                SourceClass::ReadError,
                format!("stat the card file: {e}"),
            ))
        }
    };
    let size = meta.len();
    if size != row.size {
        return Some((
            SourceClass::SizeMismatch,
            format!("record {} B, card {} B", row.size, size),
        ));
    }
    // A zero-byte card file against a zero-byte record row: the sha
    // check still stands (the sha256 of no bytes is an honest digest —
    // never invent an OK over an empty source).
    // The streaming sha (the size came from the caller's
    // metadata stat above); the ReadError wording is the pre-existing
    // one.
    let sha = match crate::jxl::sha256_stream_path(target) {
        Ok(s) => s,
        Err(e) => {
            return Some((
                SourceClass::ReadError,
                format!("read the card file: {e}"),
            ))
        }
    };
    if sha != row.sha {
        Some((
            SourceClass::ShaMismatch,
            format!("record sha256 {}, card {}", row.sha, sha),
        ))
    } else {
        None
    }
}

/// Re-verify ONE parsed record against its clip source dir: the row
/// classification in ROW order (deterministic) + the per-record
/// summary line (the offload summary's shape). Returns (the dirty rows
/// [(file, class, detail)], the summary line).
pub fn reverify_record(rec: &SourcesRecord, clip_dir: &Path, card_root: &Path) -> (Vec<(String, SourceClass, String)>, String) {
    let mut dirty: Vec<(String, SourceClass, String)> = Vec::new();
    for row in &rec.rows {
        let target = clip_dir.join(&row.file);
        if let Some((class, detail)) = classify_source_row(&target, row, &target) {
            dirty.push((row.file.clone(), class, detail));
        }
    }
    let summary = format!(
        "audit: sources {}/{} file(s) OK ({}, clip {}, card {})",
        rec.rows.len() - dirty.len(),
        rec.rows.len(),
        rec.name,
        crate::worker::display_clip(&rec.clip),
        card_root.display()
    );
    (dirty, summary)
}

/// Discover the `*.sources.tsv` records in `input` (top level, sorted
/// by path — the same discovery convention as the members records).
pub fn discover_sources_records(input: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(input) {
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            if name == ".sources.tsv" || name.ends_with(".sources.tsv") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The tree-aware resolution of a record's clip key against the card
/// root (convention: the clip key = the folder name,
/// matching the record's `clip:` key — the same tree-root detection as
/// `bake::is_tree_mode`). A mismatch is a NAMED hard error (the audit
/// turns it into the rc=2 refusal — zero partial verdicts):
/// - the flat key "" + a tree root = the record cannot be resolved
///   (pass the clip dir itself);
/// - a clip key absent from a tree root = the folder does not exist;
/// - a clip key against a flat (single-clip) root must equal the
///   root's folder name.
fn resolve_clip_dir(card_root: &Path, tree_root: bool, clip: &str) -> Result<PathBuf, String> {
    if clip.is_empty() {
        if tree_root {
            return Err(format!(
                "clip key mismatch: the source record's clip key is the flat root (\"\"), but the card root {} is a multi-clip tree — pass the clip dir itself (zero partial verdicts)",
                card_root.display()
            ));
        }
        return Ok(card_root.to_path_buf());
    }
    if tree_root {
        let d = card_root.join(clip);
        if !d.is_dir() {
            return Err(format!(
                "clip key mismatch: the source record names clip {clip}, but the folder is absent from the card tree {} (the clip key = the folder name — zero partial verdicts)",
                card_root.display()
            ));
        }
        return Ok(d);
    }
    let base = card_root
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if base != clip {
        return Err(format!(
            "clip key mismatch: the source record names clip {clip}, but the single-clip card root {} is named {base:?} (the clip key = the folder name — zero partial verdicts)",
            card_root.display()
        ));
    }
    Ok(card_root.to_path_buf())
}

/// The source-verify result over the archive's discovered records:
/// the per-row FAIL lines + the per-record summary lines (in record
/// order, row order), the dirty row count, and the verified row count.
#[derive(Debug)]
pub struct SourceVerify {
    pub lines: Vec<String>,
    pub dirty: usize,
    pub verified: usize,
}

/// The CARD verdict's outcome (the pure mapping the audit caller
/// renders — unit-testable without the CLI): the class + the exact
/// verdict line. The UNVERIFIABLE line is built by the caller (it
/// names the absent path / record — the input-dependent wording).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardClass {
    /// Every source row OK + the archive audit clean (the rc=0 class).
    Unlocked,
    /// Named source rows dirty — the card must NOT be formatted/wiped.
    Refused,
    /// The source is not verified (absent card / absent record) — the
    /// rc follows the archive audit result.
    Unverifiable,
}

impl CardClass {
    /// The ledger's verdict column (the QC_GATE-style additive verdict
    /// — the audit WITHOUT --source keeps the existing OK/FAIL
    /// verdicts, unchanged).
    pub fn ledger_verdict(self) -> &'static str {
        match self {
            CardClass::Unlocked => "CARD_OK",
            CardClass::Refused => "CARD_REFUSED",
            CardClass::Unverifiable => "CARD_UNVERIFIABLE",
        }
    }

 /// The rc (the decision: the audit-side re-derived violations
    /// ride rc=1; UNVERIFIABLE follows the archive audit result — an
    /// unmounted card is NOT a failure of the archive).
    pub fn rc(self, archive_bad: usize) -> u8 {
        match self {
            CardClass::Unlocked => 0,
            CardClass::Refused => 1,
            CardClass::Unverifiable => if archive_bad == 0 { 0 } else { 1 },
        }
    }
}

/// The CARD verdict line (the exact wordings) + the class, from
/// the verified/dirty row counts + the archive audit's offender count.
/// UNLOCKED is printed ONLY when every source row is OK AND the
/// archive audit is clean; any dirty source row keeps the card locked
/// (the full-set claim); a clean card + a dirty archive is REFUSED too
/// (the gate is a full-set claim — the card is reusable only after the
/// archive is verified clean as well).
pub fn card_verdict(verified: usize, dirty: usize, archive_bad: usize) -> (CardClass, String) {
    if dirty == 0 && archive_bad == 0 {
        (
            CardClass::Unlocked,
            format!(
                "CARD UNLOCKED ({verified} source row(s) verified against the live source + the archive audit clean — the verify-before-wipe gate is clean; the card is reusable)"
            ),
        )
    } else if dirty > 0 {
        (
            CardClass::Refused,
            format!(
                "CARD REFUSED ({dirty} named source row(s) dirty — the named rows above; the card must NOT be formatted/wiped)"
            ),
        )
    } else {
        (
            CardClass::Refused,
            format!(
                "CARD REFUSED (0 named source row(s) dirty — the archive audit is not clean ({archive_bad} named offender(s) above); the card must NOT be formatted/wiped)"
            ),
        )
    }
}

/// The verify-against-source surface: discover the archive's
/// `<CLIP>.sources.tsv` records, resolve each against the card root
/// (the tree-aware clip-key convention), and re-verify every row
/// against the live source. Returns:
/// - `Ok(None)` — the UNVERIFIABLE class (the named line: the card
///   root is absent, or the archive carries no source record — the
///   source rows are NOT verified; the archive audit is unaffected,
///   the rc follows it);
/// - `Ok(Some(SourceVerify))` — the classified rows (dirty + verified
///   counts + the lines);
/// - `Err(named)` — the hard refusal class (a corrupt record / a
///   clip-key mismatch — the audit's named rc=2, ZERO partial
///   verdicts).
pub fn audit_sources(archive: &Path, card_root: &Path) -> Result<Option<SourceVerify>, String> {
    if !card_root.is_dir() {
        return Ok(None);
    }
    let records = discover_sources_records(archive);
    if records.is_empty() {
        return Ok(None);
    }
    //: parse + resolve EVERY record before any row is
    // classified (zero partial verdicts — a corrupt record or a
    // clip-key mismatch refuses the whole surface, named, rc=2).
    let tree_root = crate::bake::is_tree_mode(card_root);
    let mut resolved: Vec<(SourcesRecord, PathBuf)> = Vec::new();
    for p in &records {
        let rec = parse_sources_record(p)?;
        let dir = resolve_clip_dir(card_root, tree_root, &rec.clip)?;
        resolved.push((rec, dir));
    }
    //: the row classification (record order, row order).
    let mut lines: Vec<String> = Vec::new();
    let mut dirty = 0usize;
    let mut verified = 0usize;
    for (rec, dir) in &resolved {
        let (dirty_rows, summary) = reverify_record(rec, dir, card_root);
        for (file, class, detail) in &dirty_rows {
            lines.push(format!(
                "FAIL source {} clip={}: {} ({})",
                class.as_str(),
                crate::worker::display_clip(&rec.clip),
                file,
                detail
            ));
        }
        lines.push(summary);
        dirty += dirty_rows.len();
        verified += rec.rows.len() - dirty_rows.len();
    }
    Ok(Some(SourceVerify {
        lines,
        dirty,
        verified,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha_of(data: &[u8]) -> String {
        crate::jxl::sha256_hex(data)
    }

    fn mk_outcome(tmp: &Path, dir: &str) -> (PathBuf, PathBuf) {
        let base = tmp.join(dir);
        let _ = std::fs::remove_dir_all(&base);
        let archive = base.join("archive");
        let card = base.join("card");
        std::fs::create_dir_all(&archive).unwrap();
        std::fs::create_dir_all(&card).unwrap();
        (archive, card)
    }

    #[test]
    fn sources_record_write_parse_roundtrip_deterministic_sorted() {
        let tmp = std::env::temp_dir().join("frameprism_sourcecheck_roundtrip");
        let (archive, _card) = mk_outcome(&tmp, "roundtrip");
        // The rows UNsorted on input — the record is the anchor: the
        // sorted order is the contract (the caller sorts; here the
        // write site's job is proven by the bytes).
        let rows: Vec<(String, u64, String)> = vec![
            ("b.DNG".into(), 4u64, sha_of(b"bbbb")),
            ("a.wav".into(), 3, sha_of(b"wav")),
            ("a.DNG".into(), 3, sha_of(b"abc")),
        ];
        let mut sorted = rows.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let p1 = write_sources_record(&archive, "A001_005", &sorted).unwrap();
        let p2 = write_sources_record(&archive, "A001_005", &sorted).unwrap();
        assert!(p1 == p2 && p1.is_file());
        assert_eq!(std::fs::read(&p1).unwrap(), std::fs::read(&p2).unwrap(), "deterministic bytes (no wall clock)");
        let text = std::fs::read_to_string(&p1).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], SOURCES_MAGIC);
        assert!(lines.contains(&"version: 1"));
        assert!(lines.iter().any(|l| l.starts_with("tool_version: ")));
        assert!(lines.contains(&"clip: A001_005"));
        assert!(lines.iter().any(|l| l.starts_with("note: the source-sha anchor")));
        assert_eq!(lines[5], SOURCES_COLUMNS);
        // The rows: sorted by path (a.DNG < a.wav < b.DNG — the byte order).
        assert_eq!(lines[6], format!("a.DNG\t3\t{}", sha_of(b"abc")));
        assert_eq!(lines[7], format!("a.wav\t3\t{}", sha_of(b"wav")));
        assert_eq!(lines[8], format!("b.DNG\t4\t{}", sha_of(b"bbbb")));
        // The round-trip parse.
        let rec = parse_sources_record(&p1).unwrap();
        assert_eq!(rec.clip, "A001_005");
        assert_eq!(
            rec.rows,
            vec![
                SourcesRow { file: "a.DNG".into(), size: 3, sha: sha_of(b"abc") },
                SourcesRow { file: "a.wav".into(), size: 3, sha: sha_of(b"wav") },
                SourcesRow { file: "b.DNG".into(), size: 4, sha: sha_of(b"bbbb") },
            ]
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn sources_record_flat_key_is_the_dotfile() {
        let tmp = std::env::temp_dir().join("frameprism_sourcecheck_flat");
        let (archive, _card) = mk_outcome(&tmp, "flat");
        let rows = vec![("f1.DNG".to_string(), 1, sha_of(b"x"))];
        let p = write_sources_record(&archive, "", &rows).unwrap();
        assert_eq!(p.file_name().unwrap().to_str().unwrap(), ".sources.tsv");
        let rec = parse_sources_record(&p).unwrap();
        assert_eq!(rec.clip, "");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn sources_record_corrupt_classes_are_named_errors() {
        let tmp = std::env::temp_dir().join("frameprism_sourcecheck_corrupt");
        let (archive, _card) = mk_outcome(&tmp, "corrupt");
        let rows = vec![("f1.DNG".to_string(), 1, sha_of(b"x"))];
        let p = write_sources_record(&archive, "CLIP", &rows).unwrap();
        let good = std::fs::read_to_string(&p).unwrap();
        // Bad magic.
        std::fs::write(&p, format!("# wrong magic\n{good}")).unwrap();
        let e = parse_sources_record(&p).unwrap_err();
        assert!(e.contains("is not a frameprism source record"), "{e:?}");
        // Bad column count (2 columns).
        std::fs::write(
            &p,
            format!("{SOURCES_MAGIC}\nversion: 1\nclip: CLIP\n{SOURCES_COLUMNS}\nf1.DNG\t1\n"),
        )
        .unwrap();
        let e = parse_sources_record(&p).unwrap_err();
        assert!(e.contains("2 columns (want 3: file, size, sha256)"), "{e:?}");
        // Bad column count (4 columns).
        std::fs::write(
            &p,
            format!("{SOURCES_MAGIC}\nclip: CLIP\n{SOURCES_COLUMNS}\nf1.DNG\t1\t{sha}\textra\n", sha = sha_of(b"x")),
        )
        .unwrap();
        let e = parse_sources_record(&p).unwrap_err();
        assert!(e.contains("4 columns (want 3: file, size, sha256)"), "{e:?}");
        // Bad size field.
        std::fs::write(
            &p,
            format!("{SOURCES_MAGIC}\nclip: CLIP\n{SOURCES_COLUMNS}\nf1.DNG\tbig\t{sha}\n", sha = sha_of(b"x")),
        )
        .unwrap();
        let e = parse_sources_record(&p).unwrap_err();
        assert!(e.contains("bad size column"), "{e:?}");
        // Missing clip field.
        std::fs::write(&p, format!("{SOURCES_MAGIC}\n{SOURCES_COLUMNS}\nf1.DNG\t1\t{sha}\n", sha = sha_of(b"x")))
            .unwrap();
        let e = parse_sources_record(&p).unwrap_err();
        assert!(e.contains("no clip field"), "{e:?}");
        // Empty record.
        std::fs::write(&p, "").unwrap();
        let e = parse_sources_record(&p).unwrap_err();
        assert!(e.contains("empty source record"), "{e:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn sources_classify_ok_missing_size_sha_read() {
        let tmp = std::env::temp_dir().join("frameprism_sourcecheck_classify");
        let (_archive, card) = mk_outcome(&tmp, "classify");
        std::fs::write(card.join("ok.DNG"), b"the-bytes").unwrap();
        std::fs::write(card.join("size.DNG"), b"shor").unwrap(); // 4 B vs recorded 6
        std::fs::write(card.join("sha.DNG"), b"others").unwrap(); // 6 B, wrong sha
        std::fs::create_dir_all(card.join("dir.DNG")).unwrap(); // a dir where a file is recorded
        // missing.DNG is simply absent.
        let rec = SourcesRecord {
            name: "A001_005.sources.tsv".into(),
            clip: "A001_005".into(),
            rows: vec![
                SourcesRow { file: "ok.DNG".into(), size: 9, sha: sha_of(b"the-bytes") },
                SourcesRow { file: "missing.DNG".into(), size: 5, sha: sha_of(b"nope") },
                SourcesRow { file: "size.DNG".into(), size: 6, sha: sha_of(b"shorxx") },
                SourcesRow { file: "sha.DNG".into(), size: 6, sha: sha_of(b"recorded") },
                SourcesRow { file: "dir.DNG".into(), size: 1, sha: sha_of(b"z") },
            ],
        };
        let (dirty, summary) = reverify_record(&rec, &card, &card);
        let classes: BTreeMap<&str, SourceClass> = dirty
            .iter()
            .map(|(f, c, _)| (f.as_str(), *c))
            .collect();
        assert_eq!(classes.get("ok.DNG"), None, "the OK row is not dirty: {dirty:?}");
        assert_eq!(classes.get("missing.DNG"), Some(&SourceClass::Missing));
        assert_eq!(classes.get("size.DNG"), Some(&SourceClass::SizeMismatch));
        assert_eq!(classes.get("sha.DNG"), Some(&SourceClass::ShaMismatch));
        assert_eq!(classes.get("dir.DNG"), Some(&SourceClass::Missing));
        assert_eq!(dirty.len(), 4);
        // The named details (the figures are the evidence).
        let size_detail = dirty.iter().find(|(f, _, _)| f == "size.DNG").unwrap().2.clone();
        assert_eq!(size_detail, "record 6 B, card 4 B");
        assert!(summary.contains("audit: sources 1/5 file(s) OK"), "{summary:?}");
        assert!(summary.contains("clip A001_005"), "{summary:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn sources_audit_end_to_end_tree_and_flat_and_mismatches() {
        let tmp = std::env::temp_dir().join("frameprism_sourcecheck_e2e");
        let base = tmp.join("base");
        let _ = std::fs::remove_dir_all(&base);
        // The card tree: two clips (the tree-root shape).
        let card = base.join("card");
        let c5 = card.join("A001_005");
        let c7 = card.join("A001_007");
        std::fs::create_dir_all(&c5).unwrap();
        std::fs::create_dir_all(&c7).unwrap();
        std::fs::write(c5.join("f1.DNG"), b"frame-five").unwrap();
        std::fs::write(c5.join("a.wav"), b"wave").unwrap();
        std::fs::write(c7.join("g1.DNG"), b"frame-seven").unwrap();
        // The archive: the two records (tree clip keys).
        let archive = base.join("archive");
        std::fs::create_dir_all(&archive).unwrap();
        write_sources_record(
            &archive,
            "A001_005",
            &vec![
                ("a.wav".to_string(), 4, sha_of(b"wave")),
                ("f1.DNG".to_string(), 10, sha_of(b"frame-five")),
            ],
        )
        .unwrap();
        write_sources_record(
            &archive,
            "A001_007",
            &[("g1.DNG".to_string(), 11, sha_of(b"frame-seven"))],
        )
        .unwrap();
        // The clean tree: verified, 3 rows, 0 dirty.
        let v = audit_sources(&archive, &card).unwrap().unwrap();
        assert_eq!(v.verified, 3);
        assert_eq!(v.dirty, 0);
        assert!(
            v.lines.iter().all(|l| l.starts_with("audit: sources ")),
            "{:?}",
            v.lines
        );
        // The card root absent: the UNVERIFIABLE class (None).
        assert!(audit_sources(&archive, &base.join("absent")).unwrap().is_none());
        // The archive with no record: the UNVERIFIABLE class (None).
        let empty = base.join("archive-empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(audit_sources(&empty, &card).unwrap().is_none());
        // The clip-key mismatches (the named hard refusals — the rc=2
        // class, zero partial verdicts).
        // (a) a tree root + a flat record (clip "") = the named refusal.
        let flat_archive = base.join("flat-archive");
        std::fs::create_dir_all(&flat_archive).unwrap();
        write_sources_record(
            &flat_archive,
            "",
            &[("f1.DNG".to_string(), 10, sha_of(b"frame-five"))],
        )
        .unwrap();
        let e = audit_sources(&flat_archive, &card).unwrap_err();
        assert!(
            e.contains("clip key mismatch") && e.contains("multi-clip tree"),
            "{e:?}"
        );
        // (b) a tree root missing the clip folder.
        let missing_archive = base.join("missing-archive");
        std::fs::create_dir_all(&missing_archive).unwrap();
        write_sources_record(
            &missing_archive,
            "A001_009",
            &[("x.DNG".to_string(), 1, sha_of(b"y"))],
        )
        .unwrap();
        let e = audit_sources(&missing_archive, &card).unwrap_err();
        assert!(e.contains("clip key mismatch") && e.contains("A001_009"), "{e:?}");
        // (c) a flat (single-clip) card root: the folder name must
        // match the record's clip key.
        let fc = base.join("flat").join("A001_005");
        std::fs::create_dir_all(&fc).unwrap();
        let e = audit_sources(&missing_archive, &fc).unwrap_err();
        assert!(
            e.contains("clip key mismatch") && e.contains("named \"A001_005\""),
            "{e:?}"
        );
        // The matching single-clip root verifies.
        let ok_flat = base.join("ok-flat-archive");
        std::fs::create_dir_all(&ok_flat).unwrap();
        write_sources_record(
            &ok_flat,
            "A001_005",
            &[("f1.DNG".to_string(), 10, sha_of(b"frame-five"))],
        )
        .unwrap();
        std::fs::write(fc.join("f1.DNG"), b"frame-five").unwrap();
        let v = audit_sources(&ok_flat, &fc).unwrap().unwrap();
        assert_eq!(v.verified, 1);
        assert_eq!(v.dirty, 0);
        // The tamper negatives (G3's classes, per clip): flip a byte
        // (SHA_MISMATCH — equal size, one byte changed), delete a
        // member (MISSING); the other clip's rows stay clean (the
        // per-clip scoping).
        std::fs::write(c7.join("g1.DNG"), b"frame-seveX").unwrap();
        let v = audit_sources(&archive, &card).unwrap().unwrap();
        assert_eq!(v.dirty, 1);
        assert_eq!(v.verified, 2);
        assert!(
            v.lines
                .iter()
                .any(|l| l.starts_with("FAIL source SHA_MISMATCH clip=A001_007: g1.DNG")),
            "{:?}",
            v.lines
        );
        let _ = std::fs::remove_file(c5.join("a.wav"));
        let v = audit_sources(&archive, &card).unwrap().unwrap();
        assert_eq!(v.dirty, 2);
        assert!(
            v.lines
                .iter()
                .any(|l| l.starts_with("FAIL source MISSING clip=A001_005: a.wav")),
            "{:?}",
            v.lines
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn sources_registry_note_claim() {
        // The read-site registry: note at the encode read, claim at the
        // record write (the sidecar rel key).
        let key = "A001_005/A001_005_20260914_000001.DNG";
        note_source_sha(key, "abc123");
        assert_eq!(claim_source_sha(key).as_deref(), Some("abc123"));
        assert_eq!(claim_source_sha("A001_005/absent.DNG"), None);
    }

    #[test]
    fn sources_card_verdict_transitions() {
        // All clean + archive clean → UNLOCKED rc=0 (the ledger's CARD_OK).
        let (c, line) = card_verdict(12, 0, 0);
        assert!(matches!(c, CardClass::Unlocked));
        assert_eq!(
            line,
            "CARD UNLOCKED (12 source row(s) verified against the live source + the archive audit clean — the verify-before-wipe gate is clean; the card is reusable)"
        );
        assert_eq!(c.rc(0), 0);
        assert_eq!(c.ledger_verdict(), "CARD_OK");
        // Any dirty row → REFUSED rc=1 (even with a clean archive).
        let (c, line) = card_verdict(11, 1, 0);
        assert!(matches!(c, CardClass::Refused));
        assert_eq!(
            line,
            "CARD REFUSED (1 named source row(s) dirty — the named rows above; the card must NOT be formatted/wiped)"
        );
        assert_eq!(c.rc(0), 1);
        assert_eq!(c.ledger_verdict(), "CARD_REFUSED");
        // Dirty rows + a dirty archive: the source rows are named; the
        // line carries the source-row count (the archive's named rows
        // are above).
        let (c, line) = card_verdict(9, 3, 2);
        assert!(matches!(c, CardClass::Refused));
        assert!(line.starts_with("CARD REFUSED (3 named source row(s) dirty"), "{line:?}");
        assert_eq!(c.rc(2), 1);
        // A clean card + a dirty archive → REFUSED rc=1 (the gate is a
        // full-set claim — the card is not released on a dirty archive).
        let (c, line) = card_verdict(12, 0, 2);
        assert!(matches!(c, CardClass::Refused));
        assert!(line.starts_with("CARD REFUSED (0 named source row(s) dirty — the archive audit is not clean"), "{line:?}");
        assert_eq!(c.rc(2), 1);
        // UNVERIFIABLE: the rc FOLLOWS the archive audit result (an
        // unmounted card is not a failure of the archive).
        let u = CardClass::Unverifiable;
        assert_eq!(u.rc(0), 0);
        assert_eq!(u.rc(3), 1);
        assert_eq!(u.ledger_verdict(), "CARD_UNVERIFIABLE");
    }
}
