//! Camera profiles (OPTION (a)): the per-camera pinned config as a versioned,
//!
//! machine-readable profile (the "camera-agnostic given DNGs" claim made
//! concrete and falsifiable per camera).
//!
//! A profile file (`profiles/<camera>.profile`, the records pattern —
//! the `# frameprism camera profile` magic + `version:` + `tool_version:`
//! + deterministic `key: value` rows) pins, written FROM the
//! measurement for A001:
//!   - the camera identity (the DNG Make/Model tag values — the primary
//!     identity),
//!   - the measured readout geometries + depths + which of the SHIPPED
//!     predicates apply per readout/depth (`tile` =
//!     `worker::is_tile_layout`, `archive` = `worker::is_archive_layout`),
//!   - the CFA PhotometricInterpretation,
//!   - the file-naming convention (informational),
//!   - `tool_version` (the profile is a pinned record like the pins).
//!
//! The identity-vs-routing split: this module is the IDENTITY layer
//! (does this frame's camera exist in the pinned set, and is THIS
//! readout/depth/CFA measured for it?). The predicates remain the
//! ROUTING layer (the worker routes a profiled frame exactly as the
//! embedded constants did — the A001 profile = the embedded constants;
//! the encode output for A001 frames stays byte-identical). The gate
//! sits AHEAD of the routing; it never rewrites it.
//!
//! The FROZEN posture stays the default: an unknown camera = the named
//! refusal (rc=2 at the encode surface — the tool does not encode
//! without its camera identity resolved; the profile is an explicit
//! identity, not an opt-in to new behavior).
//!
//! Resolution (the pins pattern — `crate::pins::resolve_pins_path`):
//! the `FRAMEPRISM_PROFILES` env (an explicit profile FILE path, the
//! deterministic test surface) → the `profiles/` dir under cwd → the
//! `profiles/` dir next to the executable. Unresolvable = the named
//! refusal (the encode refuses rc=2 before any frame; the audit side
//! degrades to the honest ABSENT line — the audit is read-only).
//!
//! Mismatch classes (the falsifiability point — each distinct + named,
//! ordered Make/Model → geometry → bits → photometric; a frame failing
//! two checks names the FIRST in that order):
//!   1. `camera mismatch: no profile matches Make/Model <make> <model>`
//!      (the unknown camera — a new profile file, not a
//!      code change);
//!   2. `camera mismatch: profile <id> Make/Model match but geometry
//!      <w>x<h> is not in the profile's geometry rows` (a known camera,
//!      an unmeasured readout — a config row addition when measured);
//!   3. `camera mismatch: profile <id> geometry <w>x<h> matches but
//!      bits_per_sample <b> is not a profiled depth for that geometry`;
//!   4. `camera mismatch: profile <id> geometry/depth match but
//!      photometric interpretation <p> != the profile's CFA
//!      photometric <pp>`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The profile file's magic line (the records pattern).
pub const PROFILE_MAGIC: &str = "# frameprism camera profile";


/// The detection prefix bound (the bounded read): the
/// camera identity lives in the IFD0 identity tags (Make/Model
/// strings, the 50712 curve value) and the tiff module bounds-checks
/// every IFD structure + out-of-line value offset against the buffer
/// it is given — so the parse's REACH is a property of the file
/// layout, not the file size. Measured (a standalone
/// binary-search probe over the 37 committed DNG fixtures: the
/// oracle10/108 real A001 footage + the fuzz-corpus adversarial set):
/// the `read_meta` + `identity_from_ifd0` reach is at most 79,280 B
/// (the IFD chain + the identity tag values; the oracle108 f8 frame
/// carries the maximum). 1 MiB = 12.7× the measured maximum, the
/// header-window class (the worker's 512 KiB metadata windows)
/// with headroom for larger-sensor IFD regions — and 8 orders of
/// magnitude below the multi-GB hostile-input class the bound
/// defends against. An IFD offset past the prefix = the tiff
/// module's existing named out-of-bounds error class → the existing
/// note path (the clip rides the `unprofiled camera - -` line).
pub(crate) const DETECTION_PREFIX_BOUND: usize = 1024 * 1024;/// The only known profile format version (a different version is the
/// named `bad version` refusal — never a silent fallback).
pub const PROFILE_VERSION: u32 = 1;

/// The shipped predicate classes a geometry row can pin (the names the
/// profile uses for `worker::is_tile_layout` / `worker::is_archive_layout`
/// — the routing layer the identity gate stands ahead of).
pub const PRED_TILE: &str = "tile";
pub const PRED_ARCHIVE: &str = "archive";

/// One measured readout/depth row: the geometry + the profiled depth +
/// which shipped predicates accept it (the canonical order
/// `tile,archive` — a row never lists a predicate twice).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeometryRow {
    pub width: u32,
    pub height: u32,
    pub bits: u16,
    pub predicates: Vec<&'static str>,
}

/// One parsed camera profile (the pinned per-camera config).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub version: u32,
    /// Informational (the pinned-record marker — like the sidecar's
    /// `tool_version:`; never enforced).
    pub tool_version: String,
    /// The deterministic camera id (recorded in the file + the docs).
    pub camera: String,
    /// The Make/Model tag values (the primary identity — exact match).
    pub make: String,
    pub model: String,
    /// The profiled CFA PhotometricInterpretation (the CFA tag check).
    pub photometric: u16,
    /// The measured file-naming convention (informational — the
    /// resolver never matches on file names).
    pub naming: String,
    /// The measured readouts (the resolver's geometry/depth rows).
    pub geometries: Vec<GeometryRow>,
}

/// The loaded profile set (the pins set of the camera identity).
#[derive(Clone, Debug)]
pub struct ProfileSet {
    /// The profiles, sorted by camera id (deterministic).
    pub profiles: Vec<Profile>,
    /// The resolved source (the refusal/MATCH lines name it).
    pub source: String,
}

/// The frame-header fields the resolver needs (the DNG IFD0 identity
/// tags — extracted from the ALREADY-PARSED header; the resolution
/// never re-parses the frame for them).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameIdentity {
    pub make: String,
    pub model: String,
    pub width: u32,
    pub height: u32,
    pub bits_per_sample: u16,
    pub photometric: u16,
}

/// The resolver's verdict for one frame.
#[derive(Debug)]
pub enum Resolution {
    /// The camera is pinned + this readout/depth/CFA is measured: the
    /// camera id + the profile version + the predicate class(es) for
    /// this geometry/depth (the routing layer's input — the worker
    /// routes unchanged).
    Match {
        camera: String,
        profile_version: u32,
        predicates: Vec<&'static str>,
    },
    /// A NAMED mismatch (class 1..4 — see the module docs; the message
    /// is the full deterministic named line, no wall clock).
    Mismatch(Mismatch),
}

/// One named mismatch class (the falsifiability point).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    /// The class number (1 = unknown camera, 2 = unmeasured geometry,
    /// 3 = unmeasured depth, 4 = photometric).
    pub class: u8,
    /// The full deterministic named line (the `camera mismatch: ...`
    /// wording — the offending values in the message).
    pub message: String,
}

impl Mismatch {
    /// The named line as the per-frame FAIL suffix
    /// (`FAIL {file}: {named_line}`).
    pub fn named_line(&self) -> &str {
        &self.message
    }
}

// =====================================================================
// The strict parser (the records pattern)
// =====================================================================

/// Parse one profile file's text (STRICT — the named refusal classes:
/// bad magic / bad version / unknown key / bad row shape / duplicate
/// row / non-numeric field / missing required key). A corrupt profile
/// is a named refusal, never a silent fallback.
pub fn parse_profile(text: &str) -> Result<Profile, String> {
    let mut lines = text.lines().enumerate();
    let (_, first) = lines.next().ok_or_else(|| {
        "bad magic: empty profile file (the # frameprism camera profile magic line must be first)"
            .to_string()
    })?;
    if first != PROFILE_MAGIC {
        return Err(format!(
            "bad magic: first line is {first:?}, want {PROFILE_MAGIC:?}"
        ));
    }
    let mut version: Option<u32> = None;
    let mut tool_version: Option<String> = None;
    let mut camera: Option<String> = None;
    let mut make: Option<String> = None;
    let mut model: Option<String> = None;
    let mut photometric: Option<u16> = None;
    let mut naming: Option<String> = None;
    let mut geometries: Vec<GeometryRow> = Vec::new();
    let mut seen_keys: BTreeSet<&str> = BTreeSet::new();
    let mut seen_geometry: BTreeSet<(u32, u32, u16)> = BTreeSet::new();

    for (i, line) in lines {
        let lineno = i + 1; // the magic line is line 1 (already consumed)
        if line.trim().is_empty() || line.starts_with('#') {
            continue; // blank + comment lines (the header provenance)
        }
        let (key, value) = match line.split_once(':') {
            Some(kv) => kv,
            None => {
                return Err(format!(
                    "bad row shape: line {lineno} is not a `key: value` row: {line:?}"
                ))
            }
        };
        let key = key.trim();
        let value = value.trim();
        let dup = |what: &str| -> Result<(), String> {
            if seen_keys.contains(what) {
                Err(format!("duplicate row: {what} (line {lineno})"))
            } else {
                Ok(())
            }
        };
        match key {
            "version" => dup("version")?,
            "tool_version" => dup("tool_version")?,
            "camera" => dup("camera")?,
            "make" => dup("make")?,
            "model" => dup("model")?,
            "photometric" => dup("photometric")?,
            "naming" => dup("naming")?,
            "geometry" => {} // the geometry rows may repeat (one per readout/depth)
            other => {
                return Err(format!("unknown key: {other} (line {lineno})"))
            }
        }
        seen_keys.insert(key);
        match key {
            "version" => {
                let v: u32 = value
                    .parse()
                    .map_err(|_| format!("non-numeric field: version = {value} (line {lineno})"))?;
                if v != PROFILE_VERSION {
                    return Err(format!(
                        "bad version: version: {v} (want version: {PROFILE_VERSION} — the only known profile format)"
                    ));
                }
                version = Some(v);
            }
            "tool_version" => {
                if value.is_empty() {
                    return Err(format!("bad row shape: line {lineno}: empty value for tool_version"));
                }
                tool_version = Some(value.to_string());
            }
            "camera" => {
                if value.is_empty() || value.contains(char::is_whitespace) {
                    return Err(format!(
                        "bad row shape: line {lineno}: the camera id is one token (no whitespace): {value:?}"
                    ));
                }
                camera = Some(value.to_string());
            }
            "make" => {
                if value.is_empty() {
                    return Err(format!("bad row shape: line {lineno}: empty value for make"));
                }
                make = Some(value.to_string());
            }
            "model" => {
                if value.is_empty() {
                    return Err(format!("bad row shape: line {lineno}: empty value for model"));
                }
                model = Some(value.to_string());
            }
            "photometric" => {
                let p: u16 = value.parse().map_err(|_| {
                    format!("non-numeric field: photometric = {value} (line {lineno})")
                })?;
                photometric = Some(p);
            }
            "naming" => {
                if value.is_empty() {
                    return Err(format!("bad row shape: line {lineno}: empty value for naming"));
                }
                naming = Some(value.to_string());
            }
            "geometry" => {
                let fields: Vec<&str> = value.split_whitespace().collect();
                if fields.len() != 4 {
                    return Err(format!(
                        "bad row shape: line {lineno}: a geometry row is `geometry: <width> <height> <bits> <predicates>` (4 fields): {value:?}"
                    ));
                }
                let width: u32 = fields[0].parse().map_err(|_| {
                    format!("non-numeric field: geometry width = {} (line {lineno})", fields[0])
                })?;
                let height: u32 = fields[1].parse().map_err(|_| {
                    format!("non-numeric field: geometry height = {} (line {lineno})", fields[1])
                })?;
                let bits: u16 = fields[2].parse().map_err(|_| {
                    format!("non-numeric field: geometry bits = {} (line {lineno})", fields[2])
                })?;
                if width == 0 || height == 0 || bits == 0 {
                    return Err(format!(
                        "bad row shape: line {lineno}: width/height/bits must be > 0: {value:?}"
                    ));
                }
                let mut preds: Vec<&'static str> = Vec::new();
                for tok in fields[3].split(',') {
                    let p = match tok {
                        PRED_TILE => PRED_TILE,
                        PRED_ARCHIVE => PRED_ARCHIVE,
                        other => {
                            return Err(format!(
                                "bad row shape: line {lineno}: unknown predicate {other:?} (want `tile` and/or `archive`)"
                            ))
                        }
                    };
                    if preds.iter().any(|q| q == &p) {
                        return Err(format!(
                            "bad row shape: line {lineno}: predicate {tok:?} is listed twice: {value:?}"
                        ));
                    }
                    preds.push(p);
                }
                if preds.is_empty() {
                    return Err(format!(
                        "bad row shape: line {lineno}: no predicates named: {value:?}"
                    ));
                }
                // The canonical order (tile,archive) — deterministic.
                preds.sort_by_key(|p| if *p == PRED_TILE { 0 } else { 1 });
                if !seen_geometry.insert((width, height, bits)) {
                    return Err(format!(
                        "duplicate row: geometry {width} {height} {bits} (line {lineno})"
                    ));
                }
                geometries.push(GeometryRow {
                    width,
                    height,
                    bits,
                    predicates: preds,
                });
            }
            _ => unreachable!("the match above names every key"),
        }
    }

    let missing = |key: &str| -> Option<String> {
        match (key, &version, &tool_version, &camera, &make, &model, &photometric, &naming) {
            ("version", None, _, _, _, _, _, _) => Some(key.into()),
            ("tool_version", _, None, _, _, _, _, _) => Some(key.into()),
            ("camera", _, _, None, _, _, _, _) => Some(key.into()),
            ("make", _, _, _, None, _, _, _) => Some(key.into()),
            ("model", _, _, _, _, None, _, _) => Some(key.into()),
            ("photometric", _, _, _, _, _, None, _) => Some(key.into()),
            ("naming", _, _, _, _, _, _, None) => Some(key.into()),
            _ => None,
        }
    };
    for key in ["version", "tool_version", "camera", "make", "model", "photometric", "naming"] {
        if let Some(k) = missing(key) {
            return Err(format!("missing required key: {k}"));
        }
    }
    if geometries.is_empty() {
        return Err(
            "no geometry rows (a profile must pin at least one measured readout/depth)"
                .into(),
        );
    }
    Ok(Profile {
        version: version.unwrap(),
        tool_version: tool_version.unwrap(),
        camera: camera.unwrap(),
        make: make.unwrap(),
        model: model.unwrap(),
        photometric: photometric.unwrap(),
        naming: naming.unwrap(),
        geometries,
    })
}

/// Load one profile file (the named refusal carries the file name).
fn load_profile_file(path: &Path) -> Result<Profile, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("camera profile {}: unreadable: {err}", path.display()))?;
    parse_profile(&text)
        .map_err(|err| format!("camera profile {}: {err}", path.display()))
}

/// Load every `*.profile` file in a profiles/ dir (sorted by file name
/// — the deterministic set order). Cross-file identity invariants: the
/// camera ids are UNIQUE and no two profiles claim the same Make/Model
/// (an ambiguous primary identity is a named refusal, not a guess).
fn load_profile_dir(dir: &Path) -> Result<Vec<Profile>, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)
        .map_err(|err| format!("camera profiles dir {}: unreadable: {err}", dir.display()))?
    {
        let entry = entry.map_err(|err| format!("camera profiles dir {}: {err}", dir.display()))?;
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("profile") && p.is_file() {
            files.push(p);
        }
    }
    files.sort();
    let mut profiles = Vec::new();
    for f in &files {
        profiles.push(load_profile_file(f)?);
    }
    // The cross-file invariants (the set must be a function of the
    // primary identity).
    let mut by_camera: BTreeMap<&str, &Path> = BTreeMap::new();
    for (i, p) in profiles.iter().enumerate() {
        if let Some(first) = by_camera.get(p.camera.as_str()) {
            return Err(format!(
                "duplicate camera id {} ({} and the profiles/ dir already claimed it via {})",
                p.camera, files[i].display(), first.display()
            ));
        }
        by_camera.insert(&p.camera, &files[i]);
    }
    let mut by_make_model: BTreeMap<(&str, &str), &str> = BTreeMap::new();
    for (i, p) in profiles.iter().enumerate() {
        let key = (p.make.as_str(), p.model.as_str());
        if let Some(other) = by_make_model.get(&key) {
            return Err(format!(
                "conflicting profiles for Make/Model {make} {model} ({other} and {file} — the primary identity is ambiguous)",
                make = p.make,
                model = p.model,
                file = files[i].display()
            ));
        }
        by_make_model.insert(key, &p.camera);
    }
    Ok(profiles)
}

// =====================================================================
// The profile-set resolution (the pins pattern)
// =====================================================================

/// The probe candidates, in resolution order (the named refusal line
/// lists them — the pins `probed:` shape).
pub fn candidates() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(env) = std::env::var("FRAMEPRISM_PROFILES") {
        out.push(format!("FRAMEPRISM_PROFILES={env} (explicit profile file)"));
    }
    if let Ok(cwd) = std::env::current_dir() {
        out.push(format!("{} (cwd)", cwd.join("profiles").display()));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(format!("{} (exe-dir)", dir.join("profiles").display()));
        }
    }
    out
}

/// The pure resolution core (the testable half — `resolve_profiles`
/// feeds it the live env/cwd/exe-dir): the `env` file (an explicit
/// profile FILE — the deterministic test surface; a named env that does
/// not resolve is a named refusal, NOT a silent fall-through) → the
/// `cwd` profiles/ dir → the `exe_dir` profiles/ dir → the named
/// unresolvable refusal.
pub fn resolve_core(env: Option<&Path>, cwd: &Path, exe_dir: &Path) -> Result<ProfileSet, String> {
    if let Some(p) = env {
        if !p.is_file() {
            return Err(format!(
                "camera profile set unresolvable: the FRAMEPRISM_PROFILES file is not a file: {} (the named refusal — the tool does not encode without its camera identity)",
                p.display()
            ));
        }
        let profile = load_profile_file(p)?;
        return Ok(ProfileSet {
            profiles: vec![profile],
            source: format!("the FRAMEPRISM_PROFILES file {}", p.display()),
        });
    }
    let cwd_dir = cwd.join("profiles");
    if cwd_dir.is_dir() {
        let profiles = load_profile_dir(&cwd_dir)?;
        return Ok(ProfileSet {
            profiles,
            source: format!("the profiles dir {} (cwd)", cwd_dir.display()),
        });
    }
    let exe_dir_profiles = exe_dir.join("profiles");
    if exe_dir_profiles.is_dir() {
        let profiles = load_profile_dir(&exe_dir_profiles)?;
        return Ok(ProfileSet {
            profiles,
            source: format!("the profiles dir {} (exe-dir)", exe_dir_profiles.display()),
        });
    }
    Err(format!(
        "camera profile set unresolvable (probed: {}) — the tool does not encode without its camera identity (the named rc=2 — the pins-pattern resolution)",
        candidates().join("; ")
    ))
}

/// Resolve the profile set for a run: the `FRAMEPRISM_PROFILES` env file →
/// `<cwd>/profiles` → `<exe_dir>/profiles`. Unresolvable / a corrupt
/// profile = the named refusal (the encode refuses rc=2 before any
/// frame; the audit side degrades to the honest ABSENT line).
pub fn resolve_profiles() -> Result<ProfileSet, String> {
    #[cfg(test)]
    {
        // The in-process equivalent of FRAMEPRISM_PROFILES (process-global
        // env is racy across parallel cargo tests; this slot compiles
        // out of the production build — the production path below is
        // the whole surface).
        if let Some(p) = OVERRIDDEN.lock().unwrap().clone() {
            return if p.is_dir() {
                Ok(ProfileSet {
                    profiles: load_profile_dir(&p)?,
                    source: format!("the profiles dir {}", p.display()),
                })
            } else {
                let profile = load_profile_file(&p)?;
                Ok(ProfileSet {
                    profiles: vec![profile],
                    source: format!("the profile file {}", p.display()),
                })
            };
        }
    }
    let env = std::env::var("FRAMEPRISM_PROFILES")
        .ok()
        .map(PathBuf::from);
    let cwd = std::env::current_dir().unwrap_or_default();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_default();
    resolve_core(env.as_deref(), &cwd, &exe_dir)
}

#[cfg(test)]
static OVERRIDDEN: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// Test-only: force the resolved profile source (a `.profile` file or a
/// `profiles/` dir) — the thread-safe in-process equivalent of
/// `FRAMEPRISM_PROFILES` (the production build never compiles this slot
/// into `resolve_profiles`). `None` clears the override.
#[cfg(test)]
pub fn set_profile_override(path: Option<&Path>) {
    *OVERRIDDEN.lock().unwrap() = path.map(PathBuf::from);
}

// =====================================================================
// The frame identity (the IFD0 identity tags — no re-parse)
// =====================================================================

/// The TIFF base type sizes (the tiff.rs map — the extractor only needs
/// the value bytes of the identity tags).
fn tiff_type_size(typ: u16) -> Option<u32> {
    Some(match typ {
        1 | 2 | 6 | 7 => 1,    // BYTE, ASCII, SBYTE, UNDEFINED
        3 | 8 => 2,            // SHORT, SSHORT
        4 | 9 | 11 | 12 => 4,  // LONG, SLONG, (11 unused), IFD
        5 | 10 | 13 | 14 | 15 | 16 | 17 => 8, // RATIONAL, SRATIONAL, IFD8, SLOFFSET, DOUBLE, LONG8, SLONG8
        18 => 16,              // RATIONAL8
        _ => return None,
    })
}

/// The value bytes of one IFD entry (in-line: the first `type_size *
/// count` bytes of the 4-byte value field — by construction ≤ 4;
/// out-of-line: the file range). `None` = out of the buffer bounds.
fn entry_value_bytes<'a>(en: &'a crate::tiff::IfdEntry, bytes: &'a [u8]) -> Option<&'a [u8]> {
    if let Some((s, e)) = en.out_of_line {
        if e > bytes.len() as u64 {
            return None;
        }
        return Some(&bytes[s as usize..e as usize]);
    }
    let sz = tiff_type_size(en.typ)? as u64;
    let n = (sz * en.count as u64).min(4);
    Some(&en.value_raw[..n as usize])
}

/// The first element of an integer identity tag (256/257/258/262 —
/// SHORT or LONG, count ≥ 1), little-endian. The named error is
/// deterministic (the tag name + id + the observed type/count).
fn ifd0_int(ifd0: &crate::tiff::IfdTable, bytes: &[u8], tag: u16, name: &str) -> Result<u32, String> {
    let en = ifd0
        .entries
        .iter()
        .find(|e| e.tag == tag)
        .ok_or_else(|| format!("no {name} tag ({tag}) in IFD0"))?;
    if !matches!(en.typ, 3 | 4) {
        return Err(format!(
            "{name} tag ({tag}) is type {} (want SHORT 3 or LONG 4)",
            en.typ
        ));
    }
    if en.count < 1 {
        return Err(format!("{name} tag ({tag}) has count 0"));
    }
    let v = entry_value_bytes(en, bytes)
        .ok_or_else(|| format!("{name} tag ({tag}) value is out of the buffer bounds"))?;
    let word = match en.typ {
        3 => u16::from_le_bytes([v[0], v[1]]) as u32,
        _ => u32::from_le_bytes([v[0], v[1], v[2], v[3]]),
    };
    Ok(word)
}

/// The first element of an ASCII identity tag (271/272), NUL-trimmed.
fn ifd0_ascii(ifd0: &crate::tiff::IfdTable, bytes: &[u8], tag: u16, name: &str) -> Result<String, String> {
    let en = ifd0
        .entries
        .iter()
        .find(|e| e.tag == tag)
        .ok_or_else(|| format!("no {name} tag ({tag}) in IFD0"))?;
    if en.typ != 2 {
        return Err(format!("{name} tag ({tag}) is type {} (want ASCII 2)", en.typ));
    }
    let v = entry_value_bytes(en, bytes)
        .ok_or_else(|| format!("{name} tag ({tag}) value is out of the buffer bounds"))?;
    if v.is_empty() {
        return Err(format!("{name} tag ({tag}) has an empty value"));
    }
    let s = std::str::from_utf8(v)
        .map_err(|_| format!("{name} tag ({tag}) is not UTF-8"))?;
    Ok(s.trim_end_matches('\0').to_string())
}

/// Extract the frame's identity from an ALREADY-PARSED IFD0 (the
/// `tiff::read` Frame's verbatim table or the `tiff::read_meta`
/// header's) — the resolution NEVER re-parses the frame for these.
/// The named error (a frame without a readable identity tag) is its
/// own class — the gate refuses it named (the tool does not encode
/// what it cannot identify).
pub fn identity_from_ifd0(
    ifd0: &crate::tiff::IfdTable,
    bytes: &[u8],
) -> Result<FrameIdentity, String> {
    Ok(FrameIdentity {
        make: ifd0_ascii(ifd0, bytes, 271, "Make")?,
        model: ifd0_ascii(ifd0, bytes, 272, "Model")?,
        width: ifd0_int(ifd0, bytes, 256, "ImageWidth")?,
        height: ifd0_int(ifd0, bytes, 257, "ImageLength")?,
        bits_per_sample: ifd0_int(ifd0, bytes, 258, "BitsPerSample")? as u16,
        photometric: ifd0_int(ifd0, bytes, 262, "PhotometricInterpretation")? as u16,
    })
}

// =====================================================================
// The resolver (the core)
// =====================================================================

/// Resolve one frame's identity against the profile set. The class
/// order is Make/Model → geometry → bits → photometric: a frame failing
/// two checks names the FIRST in that order (deterministic wording, no
/// wall clock — the offending values in the message).
pub fn resolve(set: &ProfileSet, id: &FrameIdentity) -> Resolution {
    let matched: Vec<&Profile> = set
        .profiles
        .iter()
        .filter(|p| p.make == id.make && p.model == id.model)
        .collect();
    let [p] = matched.as_slice() else {
        // The set loader refuses Make/Model conflicts — >1 here is
        // unreachable; the empty case is class 1 (the unknown camera).
        return Resolution::Mismatch(Mismatch {
            class: 1,
            message: format!(
                "camera mismatch: no profile matches Make/Model {} {}",
                id.make, id.model
            ),
        });
    };
    let geom: Vec<&GeometryRow> = p
        .geometries
        .iter()
        .filter(|g| g.width == id.width && g.height == id.height)
        .collect();
    if geom.is_empty() {
        return Resolution::Mismatch(Mismatch {
            class: 2,
            message: format!(
                "camera mismatch: profile {} Make/Model match but geometry {}x{} is not in the profile's geometry rows",
                p.camera, id.width, id.height
            ),
        });
    }
    let depth: Vec<&GeometryRow> = geom.iter().filter(|g| g.bits == id.bits_per_sample).copied().collect();
    if depth.is_empty() {
        return Resolution::Mismatch(Mismatch {
            class: 3,
            message: format!(
                "camera mismatch: profile {} geometry {}x{} matches but bits_per_sample {} is not a profiled depth for that geometry",
                p.camera, id.width, id.height, id.bits_per_sample
            ),
        });
    }
    if id.photometric != p.photometric {
        return Resolution::Mismatch(Mismatch {
            class: 4,
            message: format!(
                "camera mismatch: profile {} geometry/depth match but photometric interpretation {} != the profile's CFA photometric {}",
                p.camera, id.photometric, p.photometric
            ),
        });
    }
    Resolution::Match {
        camera: p.camera.clone(),
        profile_version: p.version,
        predicates: depth[0].predicates.clone(),
    }
}

// =====================================================================
// The audit camera line (the additive identity surface)
// =====================================================================

/// The audit's camera line (the keyless identity claim — the audit
/// needs nothing but the profile set + the DNG frames; no archive
/// bytes, no key). The SAMPLE is the first frame of the dir
/// (deterministic — the sorted `collect_dng_frames` order; the v1
/// sample — a full per-frame audit resolution is a
/// candidate, the encode already resolved every frame at encode time).
/// Returns (the line, the bad flag — MISMATCH is the named offender,
/// the audit-side re-derived violation class, rc=1; the ABSENT class
/// is the honesty line — the line is OPTIONAL for the PASS, the rc
/// follows the rest of the audit, exactly like the signature ABSENT
/// line).
pub fn audit_camera_line(input: &Path, frames: &[PathBuf]) -> (String, bool) {
    let absent = |reason: String| {
        (
            format!(
                "audit: camera ABSENT — {reason} (the camera identity was not checked — the line is optional for the PASS)"
            ),
            false,
        )
    };
    let sample = match frames.first() {
        Some(p) => p,
        None => {
            return absent(format!(
                "no DNG frames in {}",
                input.display()
            ))
        }
    };
    let set = match crate::camera::resolve_profiles() {
        Ok(s) => s,
        Err(err) => return absent(err),
    };
    // The bounded prefix read (the audit is the detection
    // class — the identity's measured reach is 79,280 B over the
    // committed fixtures); the ABSENT wordings below are the
    // pre-existing ones.
    let buf = match read_detection_prefix(sample) {
        Ok(b) => b,
        Err(err) => {
            return absent(format!(
                "cannot read the sample frame {}: {err}",
                sample.display()
            ))
        }
    };
    let meta = match crate::tiff::read_meta(&buf) {
        Ok(m) => m,
        Err(err) => {
            return absent(format!(
                "the sample frame {} does not parse ({err})",
                sample.display()
            ))
        }
    };
    let ident = match identity_from_ifd0(&meta.ifd0, &buf) {
        Ok(i) => i,
        Err(err) => {
            return absent(format!(
                "the sample frame {} has no readable camera identity ({err})",
                sample.display()
            ))
        }
    };
    match resolve(&set, &ident) {
        Resolution::Match {
            camera,
            profile_version,
            ..
        } => (
            format!("audit: camera MATCH ({camera}, profile v{profile_version})"),
            false,
        ),
        Resolution::Mismatch(m) => (
            format!(
                "FAIL audit: camera MISMATCH — {}: {}",
                sample.display(),
                m.named_line()
            ),
            true,
        ),
    }
}

// =====================================================================
// The per-clip offload detection (the offload surface's camera/format
// report — the detection is a REPORT, not a gate: the offload copies
// + verifies ANY tree, on ANY camera, ANY format; identity never
// refuses here — the encode surface keeps its FROZEN gate)
// =====================================================================

/// One clip's camera/format detection (the offload surface's report
/// line — the deterministic named class, the surface's contract):
///   - `profiled <camera> (profile v<n>)` — a `Resolution::Match` on
///     the clip's sample frame's identity;
///   - `unprofiled camera <Make> <Model>` — no `Resolution::Match`
///     (the class-1 unknown camera, or a class-2..4 unmeasured
///     readout — the pass-through needs no measurement; a sample
///     with no readable identity carries the no-value token `-`);
///   - `non-DNG media` — no DNG frames in the clip (the sidecar-only
///     / non-DNG camera material).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DetectionClass {
    /// `profiled <camera> (profile v<n>)`.
    Profiled {
        camera: String,
        profile_version: u32,
    },
    /// `unprofiled camera <make> <model>` (a no-identity sample
    /// carries `-`/`-` — the manifest's no-value token).
    Unprofiled {
        make: String,
        model: String,
    },
    /// `non-DNG media`.
    NonDng,
}

impl DetectionClass {
    /// The deterministic named line (the report surface's contract —
    /// the three classes above, no wall clock).
    pub fn line(&self) -> String {
        match self {
            DetectionClass::Profiled {
                camera,
                profile_version,
            } => format!("profiled {camera} (profile v{profile_version})"),
            DetectionClass::Unprofiled { make, model } => {
                format!("unprofiled camera {make} {model}")
            }
            DetectionClass::NonDng => "non-DNG media".to_string(),
        }
    }
}

/// One clip's detection row (the clip key = the ingest key space —
/// the file relpath's parent dir, "" = the source root — the SAME
/// key space as the offload rows + the per-clip manifests).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClipDetection {
    pub key: String,
    pub class: DetectionClass,
}

/// The profile set's state for the detection scan (the report's
/// `profiles:` context line + the `profiled` line's reachability —
/// the audit ABSENT precedent: an unresolvable set degrades to the
/// honest line, it never refuses the offload).
#[derive(Debug)]
pub enum ProfileSetState {
    /// A resolved set (the pins-pattern source is the report line).
    Resolved(ProfileSet),
    /// No set (the named resolution refusal — the ABSENT honesty
    /// line; no `profiled` line is reachable).
    Absent(String),
}

/// The detection scan's outcome: the per-clip lines (the sorted clip
/// key order — the deterministic report order) + the `profiles:`
/// context line.
#[derive(Debug)]
pub struct OffloadDetectionScan {
    /// One row per file-bearing clip key (the sorted order; "" = the
    /// source root).
    pub clips: Vec<ClipDetection>,
    /// The run report's `profiles:` line (the set's source, or the
    /// ABSENT honesty line naming the resolution refusal).
    pub profiles_line: String,
}

/// The offload surface's per-clip detection scan (a report, not a
/// gate). Walks `source_tree` (the offload collect discipline — the
/// SAME walk as the copy, so the detection key space is the offload
/// row key space by construction), groups the files by the ingest
/// clip key, and classifies each clip's DNG frames against the
/// profile set. The v1 sample (the `audit_camera_line` precedent):
/// the clip's first DNG frame (the sorted order). Read-only,
/// pre-copy — identity NEVER refuses here (the offload copies +
/// verifies any tree; the encode surface keeps its FROZEN gate).
pub fn offload_detections(source_tree: &Path) -> Result<OffloadDetectionScan, String> {
    let state = match resolve_profiles() {
        Ok(s) => ProfileSetState::Resolved(s),
        Err(reason) => ProfileSetState::Absent(reason),
    };
    offload_detections_with(source_tree, state)
}

/// The pure scan core (the testable half — `offload_detections`
/// feeds it the live pins-pattern resolution): `state` = the profile
/// set's state (Resolved / Absent + the named refusal). Same walk +
/// same key space + same v1 sample; deterministic over the tree +
/// the set (no wall clock).
pub fn offload_detections_with(
    source_tree: &Path,
    state: ProfileSetState,
) -> Result<OffloadDetectionScan, String> {
    let files = crate::offload::collect_all_files(source_tree)
        .map_err(|err| format!("walk the offload source tree {}: {err:#}", source_tree.display()))?;
    // The per-clip grouping (the ingest key space — the relpath's
    // parent dir; "" = the source root). The files are sorted by the
    // relpath, so a clip's first DNG frame is the sample (the sorted
    // order — the audit's v1 sample).
    let mut by_clip: BTreeMap<String, ClipDetection> = BTreeMap::new();
    for (rel, abs) in &files {
        let key = crate::offload::clip_key_of_rel(rel);
        let entry = by_clip
            .entry(key.clone())
            .or_insert_with(|| ClipDetection {
                key: key.clone(),
                class: DetectionClass::NonDng,
            });
        let name = abs
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let is_dng = !crate::is_apple_double(&name)
            && abs
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("dng"));
        if is_dng && entry.class == DetectionClass::NonDng {
            // The v1 sample: the FIRST DNG frame of the clip (the
            // sorted order) — a later frame never re-classifies
            // (deterministic; the full per-frame resolution is the
            // encode's, at encode time).
            entry.class = classify_detection_sample(abs, &state);
        }
    }
    let profiles_line = match &state {
        ProfileSetState::Resolved(s) => format!("profiles: {}", s.source),
        ProfileSetState::Absent(reason) => format!(
            "profiles: ABSENT — {reason} (the camera identity check degrades — the DNG clips ride the `unprofiled camera` line; the offload copies + verifies regardless)"
        ),
    };
    Ok(OffloadDetectionScan {
        clips: by_clip.into_values().collect(),
        profiles_line,
    })
}

/// Classify one clip's sample DNG frame against the profile set (the
/// class order: Match → `profiled`; no Match → `unprofiled camera
/// <Make> <Model>`; no readable identity → the no-value token `- -`
/// and the honest stderr note — the line stays in the three forms, the
/// report's determinism holds; the copy + verify is never affected
/// — the detection is a report, not a gate).
/// Read AT MOST `DETECTION_PREFIX_BOUND` bytes (the detection class):
/// a file shorter than the bound reads in full; a longer
/// file reads the prefix (the memory is bounded by the const, never
/// the file size). The io error propagates RAW — the callers keep
/// their existing note wordings.
pub(crate) fn read_detection_prefix(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let mut buf = Vec::with_capacity(DETECTION_PREFIX_BOUND);
    f.take(DETECTION_PREFIX_BOUND as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

fn classify_detection_sample(sample: &Path, state: &ProfileSetState) -> DetectionClass {
    let unidentifiable = || DetectionClass::Unprofiled {
        make: "-".into(),
        model: "-".into(),
    };
    // The bounded prefix read (the identity's measured
    // reach is 79,280 B over the committed fixtures — the bound is
    // 1 MiB); the note wordings below are the pre-existing ones.
    let buf = match read_detection_prefix(sample) {
        Ok(b) => b,
        Err(err) => {
            eprintln!(
                "note: the offload detection sample {} is unreadable ({err}) — the clip rides the `unprofiled camera - -` line (the copy + verify is unaffected)",
                sample.display()
            );
            return unidentifiable();
        }
    };
    let meta = match crate::tiff::read_meta(&buf) {
        Ok(m) => m,
        Err(err) => {
            eprintln!(
                "note: the offload detection sample {} does not parse ({err}) — the clip rides the `unprofiled camera - -` line (the copy + verify is unaffected)",
                sample.display()
            );
            return unidentifiable();
        }
    };
    let ident = match identity_from_ifd0(&meta.ifd0, &buf) {
        Ok(i) => i,
        Err(err) => {
            eprintln!(
                "note: the offload detection sample {} has no readable camera identity ({err}) — the clip rides the `unprofiled camera - -` line (the copy + verify is unaffected)",
                sample.display()
            );
            return unidentifiable();
        }
    };
    let set = match state {
        ProfileSetState::Resolved(s) => s,
        ProfileSetState::Absent(_) => {
            // No set — no Match is reachable (the honest line; the
            // refusal is named in the scan's `profiles:` line).
            return DetectionClass::Unprofiled {
                make: ident.make,
                model: ident.model,
            };
        }
    };
    match resolve(set, &ident) {
        Resolution::Match { camera, profile_version, .. } => DetectionClass::Profiled {
            camera,
            profile_version,
        },
        Resolution::Mismatch(_) => DetectionClass::Unprofiled {
            make: ident.make,
            model: ident.model,
        },
    }
}

// =====================================================================
// The synthetic foreign-DNG fixture (the OPTION (a) CI gate — the
// shared test builder, the worker's `synthetic_dng` TC-helper pattern
// extended with the camera identity tags)
// =====================================================================

/// The synthetic foreign-DNG fixture (the OPTION (a) CI gate): a
/// minimal valid little-endian single-strip TIFF/DNG container — the
/// camera identity tags (Make/Model) + the geometry/depth/CFA header
/// + an optional TimeCodes tag (51043) + a real (zero-filled) single
/// strip, so `tiff::read` + `strip_slice` succeed for the CFA variants
/// (the identity gate fires AFTER the parse; the strip content is
/// trivial). The non-CFA / non-8-10-12 variants are `read_meta`-
/// parseable (the run gate's surface) and are refused by `tiff::read`
/// 's own named classes had they ever reached the encode.
/// `#[cfg(test)] pub`: the camera + the worker tests both build the
/// fixture classes through this (the bcd16 shared-helper pattern).
#[cfg(test)]
pub fn synth_dng_frame(
    make: &str,
    model: &str,
    w: u32,
    h: u32,
    bps: u16,
    photo: u16,
    tc: Option<[u8; 8]>,
) -> Vec<u8> {
    const IFD_OFF: u32 = 8;
    // The IFD0 entries: 256, 257, 258, 259, 262, 277 (in-line SHORTs),
    // 271 + 272 (ASCII out-of-line), 278, 273, 279 (+ 51043 when tc).
    let n_entries: u16 = if tc.is_some() { 12 } else { 11 };
    let struct_len = IFD_OFF as u64 + 2 + (n_entries as u64) * 12 + 4;
    // The out-of-line values: Make, Model, [TC], then the strip.
    let make_bytes = format!("{make}\0").into_bytes();
    let model_bytes = format!("{model}\0").into_bytes();
    let make_off = struct_len;
    let model_off = make_off + make_bytes.len() as u64;
    let tc_off = model_off + model_bytes.len() as u64;
    let strip_off = if tc.is_some() {
        tc_off + 8
    } else {
        tc_off
    };
    // The strip length (the DNG nominal packing per precision —
    // zero-filled; the parser's pad tolerance admits exact fits).
    let pixels = (w as u64) * (h as u64);
    let strip_len = match bps {
        8 => pixels,
        10 => pixels * 5 / 4,
        _ => pixels * 3 / 2, // 12 (and the synthetic 14-bit case)
    };
    let total = strip_off + strip_len;
    let mut buf = vec![0u8; total as usize];
    buf[0..4].copy_from_slice(b"II*\0");
    buf[4..8].copy_from_slice(&IFD_OFF.to_le_bytes());
    buf[8..10].copy_from_slice(&n_entries.to_le_bytes());
    // (sorted by tag id — the encode's tile surgery refuses to re-emit
    // an unsorted IFD0; the real A001 DNGs are sorted).
    let mut entries: Vec<(u16, u16, u32, Option<u32>)> = vec![
        (256, 3, 1, None), // ImageWidth
        (257, 3, 1, None), // ImageLength
        (258, 3, 1, None), // BitsPerSample
        (259, 3, 1, None), // Compression = 1
        (262, 3, 1, None), // PhotometricInterpretation
        (271, 2, make_bytes.len() as u32, Some(make_off as u32)),
        (272, 2, model_bytes.len() as u32, Some(model_off as u32)),
        (273, 4, 1, Some(strip_off as u32)), // StripOffsets
        (277, 3, 1, None), // SamplesPerPixel = 1
        (278, 3, 1, None), // RowsPerStrip = height
        (279, 4, 1, Some(strip_len as u32)), // StripByteCounts
    ];
    if let Some(_) = tc {
        entries.push((51043, 1, 8, Some(tc_off as u32)));
    }
    for (i, (tag, typ, count, ptr)) in entries.iter().enumerate() {
        let t = (IFD_OFF as u64 + 2 + (i as u64) * 12) as usize;
        buf[t..t + 2].copy_from_slice(&tag.to_le_bytes());
        buf[t + 2..t + 4].copy_from_slice(&typ.to_le_bytes());
        buf[t + 4..t + 8].copy_from_slice(&count.to_le_bytes());
        match ptr {
            Some(p) => buf[t + 8..t + 12].copy_from_slice(&p.to_le_bytes()),
            None => {
                // In-line value (the first 2 bytes of the value field
                // carry the SHORT).
                let v: u32 = match tag {
                    256 => w as u32,
                    257 => h as u32,
                    258 => bps as u32,
                    259 => 1,
                    262 => photo as u32,
                    277 => 1,
                    278 => h as u32,
                    _ => unreachable!("in-line entry without a value"),
                };
                buf[t + 8..t + 10].copy_from_slice(&(v as u16).to_le_bytes());
            }
        }
    }
    buf[make_off as usize..make_off as usize + make_bytes.len()]
        .copy_from_slice(&make_bytes);
    buf[model_off as usize..model_off as usize + model_bytes.len()]
        .copy_from_slice(&model_bytes);
    if let Some(tc) = tc {
        buf[tc_off as usize..tc_off as usize + 8].copy_from_slice(&tc);
    }
    // The next-IFD pointer (0).
    let tail = (IFD_OFF as usize) + 2 + (n_entries as usize) * 12;
    buf[tail..tail + 4].copy_from_slice(&0u32.to_le_bytes());
    buf
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The A001 profile's exact contents (the reference example —
    /// written as a deterministic function of the profile identity). The on-disk file is
    /// asserted against this (the file IS the record).
    const A001_PROFILE: &str = "# frameprism camera profile
version: 1
tool_version: 0.1.0
camera: a001-sigma-fp
make: SIGMA
model: SIGMA fp
photometric: 32803
naming: <CLIP>_<YYYYMMDD>_<NNNNNN>.DNG
geometry: 3856 2170 12 tile,archive
geometry: 3856 2170 10 archive
geometry: 3856 2170 8 archive
geometry: 1936 1090 12 archive
geometry: 1936 1090 10 archive
geometry: 1936 1090 8 archive
geometry: 2016 1344 12 archive
geometry: 2016 1344 10 archive
geometry: 2016 1344 8 archive
geometry: 3024 2010 12 archive
geometry: 3024 2010 10 archive
geometry: 3024 2010 8 archive
";

    fn a001_profile() -> Profile {
        parse_profile(A001_PROFILE).expect("the A001 profile must parse")
    }

    fn a001_set() -> ProfileSet {
        ProfileSet {
            profiles: vec![a001_profile()],
            source: "the test set".into(),
        }
    }

    fn ident(make: &str, model: &str, w: u32, h: u32, bps: u16, photo: u16) -> FrameIdentity {
        FrameIdentity {
            make: make.into(),
            model: model.into(),
            width: w,
            height: h,
            bits_per_sample: bps,
            photometric: photo,
        }
    }

    // ---- the parser (valid + every named class) -----------------------

    #[test]
    fn parse_a001_profile_valid() {
        let p = a001_profile();
        assert_eq!(p.version, 1);
        assert_eq!(p.tool_version, "0.1.0");
        assert_eq!(p.camera, "a001-sigma-fp");
        assert_eq!(p.make, "SIGMA");
        assert_eq!(p.model, "SIGMA fp");
        assert_eq!(p.photometric, 32803);
        assert_eq!(p.naming, "<CLIP>_<YYYYMMDD>_<NNNNNN>.DNG");
        assert_eq!(p.geometries.len(), 12);
        assert_eq!(
            p.geometries[0],
            GeometryRow {
                width: 3856,
                height: 2170,
                bits: 12,
                predicates: vec![PRED_TILE, PRED_ARCHIVE],
            }
        );
        assert_eq!(
            p.geometries[1],
            GeometryRow {
                width: 3856,
                height: 2170,
                bits: 10,
                predicates: vec![PRED_ARCHIVE],
            }
        );
        // The Open Gate 2K rows (measured — the modified firmware 5.02's
        // third readout): archive-only, the measured depth rows 12/10/8
 // (the 12-bit row — the measurement; the 10/8-bit rows
 // — measurement, the onboarding
 // G2 — the depth-match decision landed: the identity layer pins
        // what was measured).
        assert_eq!(
            p.geometries[6],
            GeometryRow {
                width: 2016,
                height: 1344,
                bits: 12,
                predicates: vec![PRED_ARCHIVE],
            }
        );
        assert_eq!(
            p.geometries[7],
            GeometryRow {
                width: 2016,
                height: 1344,
                bits: 10,
                predicates: vec![PRED_ARCHIVE],
            }
        );
        assert_eq!(
            p.geometries[8],
            GeometryRow {
                width: 2016,
                height: 1344,
                bits: 8,
                predicates: vec![PRED_ARCHIVE],
            }
        );
        // The Open Gate 3K rows (measured — the modified
        // firmware 5.02 line's fourth readout, the UNOFFICIAL mode 98):
        // archive-only, the measured depth rows 12/10/8 (the 12-bit row
 // — the measurement; the 10/8-bit rows — the
 // measurement, the onboarding G3 —
 // the depth-match decision landed: the identity layer pins what
        // was measured).
        assert_eq!(
            p.geometries[9],
            GeometryRow {
                width: 3024,
                height: 2010,
                bits: 12,
                predicates: vec![PRED_ARCHIVE],
            }
        );
        assert_eq!(
            p.geometries[10],
            GeometryRow {
                width: 3024,
                height: 2010,
                bits: 10,
                predicates: vec![PRED_ARCHIVE],
            }
        );
        assert_eq!(
            p.geometries[11],
            GeometryRow {
                width: 3024,
                height: 2010,
                bits: 8,
                predicates: vec![PRED_ARCHIVE],
            }
        );
        // The on-disk profile (when the repo layout is around) must be
        // the reference example, comment lines excluded (the parser
        // skips them — the record is the data rows).
        let disk = Path::new("../profiles/a001-sigma-fp.profile");
        if disk.is_file() {
            let text = std::fs::read_to_string(disk).unwrap();
            let disk_profile = parse_profile(&text).expect("the on-disk profile must parse");
            assert_eq!(
                disk_profile,
                a001_profile(),
                "the on-disk A001 profile must equal the reference example"
            );
        }
    }

    #[test]
    fn parse_bad_magic() {
        let mut text = A001_PROFILE.to_string();
        let fixed = text.replace(
            "# frameprism camera profile",
            "# frameprism other profile",
        );
        let err = parse_profile(&fixed).unwrap_err();
        assert!(err.starts_with("bad magic:"), "{err}");
        assert!(parse_profile("").unwrap_err().starts_with("bad magic:"));
    }

    #[test]
    fn parse_bad_version() {
        let text = A001_PROFILE.replace("version: 1", "version: 2");
        let err = parse_profile(&text).unwrap_err();
        assert!(err.starts_with("bad version:"), "{err}");
    }

    #[test]
    fn parse_unknown_key() {
        // The foreign key lands on line 2 (after the magic line — the
        // first line must stay the magic).
        let text = format!("{PROFILE_MAGIC}\nsensitivity: 800\n{A001_PROFILE}");
        let err = parse_profile(&text).unwrap_err();
        assert!(err == "unknown key: sensitivity (line 2)", "{err}");
    }

    #[test]
    fn parse_bad_row_shape() {
        // A geometry row with 3 fields.
        let text = A001_PROFILE.replace(
            "geometry: 1936 1090 8 archive",
            "geometry: 1936 1090 8",
        );
        assert!(parse_profile(&text).unwrap_err().starts_with("bad row shape:"));
        // An unknown predicate token.
        let text = A001_PROFILE.replace(
            "geometry: 3856 2170 10 archive",
            "geometry: 3856 2170 10 mosaic",
        );
        let err = parse_profile(&text).unwrap_err();
        assert!(err.contains("unknown predicate"), "{err}");
        // A row with no `key: value` split (after the magic line).
        let text = format!("{PROFILE_MAGIC}\njust a line\n{A001_PROFILE}");
        assert!(parse_profile(&text).unwrap_err().starts_with("bad row shape:"));
        // An empty make value.
        let text = A001_PROFILE.replace("make: SIGMA", "make: ");
        assert!(parse_profile(&text).unwrap_err().starts_with("bad row shape:"));
        // Zero width.
        let text = A001_PROFILE.replace(
            "geometry: 3856 2170 10 archive",
            "geometry: 0 2170 10 archive",
        );
        assert!(parse_profile(&text).unwrap_err().starts_with("bad row shape:"));
    }

    #[test]
    fn parse_duplicate_row() {
        // A repeated header key (the second `camera:` lands on line 5 —
        // magic 1, the injected row 2, version 3, tool_version 4,
        // camera 5).
        let mut lines: Vec<&str> = A001_PROFILE.lines().collect();
        lines.insert(1, "camera: other-id");
        let text = lines.join("\n") + "\n";
        let err = parse_profile(&text).unwrap_err();
        assert!(err == "duplicate row: camera (line 5)", "{err}");
        // A repeated geometry (width, height, bits) — the appended row
 // is line 21 (the A001_PROFILE body is 20 lines — the 
        // const rows: the body grew 18 → 20 with the two OG3K 10/8 rows
 // (16 → 18 with the two OG2K 10/8 rows)).
        let text = format!("{A001_PROFILE}geometry: 3856 2170 8 archive\n");
        let err = parse_profile(&text).unwrap_err();
        assert!(
            err == "duplicate row: geometry 3856 2170 8 (line 21)",
            "{err}"
        );
    }

    #[test]
    fn parse_non_numeric_field() {
        for (key, value) in [
            ("version", "v1"),
            ("photometric", "CFA"),
        ] {
            let text = A001_PROFILE
                .replace(&format!("{key}: 1"), &format!("{key}: {value}"))
                .replace(&format!("{key}: 32803"), &format!("{key}: {value}"));
            let err = parse_profile(&text).unwrap_err();
            assert!(
                err.starts_with("non-numeric field:"),
                "{key}: {err}"
            );
        }
        let text = A001_PROFILE.replace(
            "geometry: 3856 2170 10 archive",
            "geometry: 3856 2170 ten archive",
        );
        let err = parse_profile(&text).unwrap_err();
        assert!(err.starts_with("non-numeric field:"), "{err}");
    }

    #[test]
    fn parse_missing_required_key() {
        for key in [
            "version",
            "tool_version",
            "camera",
            "make",
            "model",
            "photometric",
            "naming",
        ] {
            let mut lines = A001_PROFILE
                .lines()
                .filter(|l| !l.starts_with(&format!("{key}:")))
                .collect::<Vec<_>>()
                .join("\n");
            lines.push('\n');
            let err = parse_profile(&lines).unwrap_err();
            assert!(err == format!("missing required key: {key}"), "{err}");
        }
    }

    #[test]
    fn parse_no_geometry_rows() {
        let text = A001_PROFILE
            .lines()
            .filter(|l| !l.starts_with("geometry:"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let err = parse_profile(&text).unwrap_err();
        assert!(err.starts_with("no geometry rows"), "{err}");
    }

    // ---- the resolver matrix (the A001 match + the four classes + the
    //      ordering) ------------------------------------------------------

    #[test]
    fn resolve_a001_match_all_geometries_and_depths() {
        let set = a001_set();
        for (w, h) in [(3856u32, 2170u32), (1936, 1090)] {
            for bits in [8u16, 10, 12] {
                match resolve(
                    &set,
                    &ident("SIGMA", "SIGMA fp", w, h, bits, 32803),
                ) {
                    Resolution::Match {
                        camera,
                        profile_version,
                        predicates,
                    } => {
                        assert_eq!(camera, "a001-sigma-fp");
                        assert_eq!(profile_version, 1);
                        if (w, h, bits) == (3856, 2170, 12) {
                            // The tile layout row (is_tile_layout AND
                            // is_archive_layout — the shipped pair).
                            assert_eq!(predicates, vec![PRED_TILE, PRED_ARCHIVE]);
                        } else {
                            assert_eq!(predicates, vec![PRED_ARCHIVE]);
                        }
                    }
                    Resolution::Mismatch(m) => {
                        panic!("A001 {w}x{h} @{bits} must MATCH: {}", m.message)
                    }
                }
            }
        }
    }

    #[test]
    fn resolve_open_gate_2k_all_depths_match_archive() {
 // The depth-match decision (landed — the 
 // measurement, the onboarding G2): the profile now
        // carries the measured Open Gate 2K depth rows 12/10/8 (the
        // identity layer pins what was measured — the 10/8 rows this
        // test formerly guarded as the frozen posture's class-3
        // refusal have landed with the measurement). All three depths
        // MATCH with the archive-only predicates (the row/depth matrix
        // — mirroring `resolve_a001_match_all_geometries_and_depths`).
        // The class-3 unmeasured-depth refusal wording STAYS for
        // genuinely unprofiled (geometry × depth) combinations (the
        // UHD @14 pin — the other refusal tests pass unmodified; the
 // 3K gate's 10/8 rows LANDED at —
        // `camera_resolver_3k_all_profiled_depths_match_archive`).
        for bits in [8u16, 10, 12] {
            match resolve(
                &a001_set(),
                &ident("SIGMA", "SIGMA fp", 2016, 1344, bits, 32803),
            ) {
                Resolution::Match {
                    camera,
                    profile_version,
                    predicates,
                } => {
                    assert_eq!(camera, "a001-sigma-fp");
                    assert_eq!(profile_version, 1);
                    assert_eq!(predicates, vec![PRED_ARCHIVE]);
                }
                Resolution::Mismatch(m) => {
                    panic!("A001 2016x1344 @{bits} must MATCH: {}", m.message)
                }
            }
        }
    }

    #[test]
    fn camera_resolver_3k_all_profiled_depths_match_archive() {
 // The depth-match decision (extended —, the G3
 // onboarding): the profile carries the MEASURED Open Gate 3K
        // depth rows 12/10/8 (the identity layer pins what was measured
 // — the 12-bit row: the measurement, the UNOFFICIAL
 // mode 98; the 10/8-bit rows: the 
        // measurement — this test formerly guarded the 10/8 rows as the
        // frozen posture's class-3 refusal; they landed with the
        // measurement). All three depths MATCH with the archive-only
        // predicates (the row/depth matrix — mirroring
        // `resolve_a001_match_all_geometries_and_depths`). The class-3
        // unmeasured-depth refusal wording STAYS for genuinely
        // unprofiled (geometry × depth) combinations (the UHD @14 pin:
        // the other refusal tests pass unmodified).
        for bits in [8u16, 10, 12] {
            match resolve(
                &a001_set(),
                &ident("SIGMA", "SIGMA fp", 3024, 2010, bits, 32803),
            ) {
                Resolution::Match {
                    camera,
                    profile_version,
                    predicates,
                } => {
                    assert_eq!(camera, "a001-sigma-fp");
                    assert_eq!(profile_version, 1);
                    assert_eq!(predicates, vec![PRED_ARCHIVE]);
                }
                Resolution::Mismatch(m) => {
                    panic!("A001 3024x2010 @{bits} must MATCH: {}", m.message)
                }
            }
        }
    }

    #[test]
    fn resolve_class1_unknown_camera() {
        // The foreign camera (a new profile file, not a code change).
        match resolve(
            &a001_set(),
            &ident("ACME", "ACME-1", 1024, 768, 12, 32803),
        ) {
            Resolution::Mismatch(m) => {
                assert_eq!(m.class, 1);
                assert_eq!(
                    m.message,
                    "camera mismatch: no profile matches Make/Model ACME ACME-1"
                );
            }
            other => panic!("must be class 1, got {other:?}"),
        }
    }

    #[test]
    fn resolve_class2_unmeasured_geometry() {
        match resolve(
            &a001_set(),
            &ident("SIGMA", "SIGMA fp", 4000, 3000, 12, 32803),
        ) {
            Resolution::Mismatch(m) => {
                assert_eq!(m.class, 2);
                assert_eq!(
                    m.message,
                    "camera mismatch: profile a001-sigma-fp Make/Model match but geometry 4000x3000 is not in the profile's geometry rows"
                );
            }
            other => panic!("must be class 2, got {other:?}"),
        }
    }

    #[test]
    fn resolve_class3_unmeasured_depth() {
        match resolve(
            &a001_set(),
            &ident("SIGMA", "SIGMA fp", 3856, 2170, 14, 32803),
        ) {
            Resolution::Mismatch(m) => {
                assert_eq!(m.class, 3);
                assert_eq!(
                    m.message,
                    "camera mismatch: profile a001-sigma-fp geometry 3856x2170 matches but bits_per_sample 14 is not a profiled depth for that geometry"
                );
            }
            other => panic!("must be class 3, got {other:?}"),
        }
    }

    #[test]
    fn resolve_class4_photometric() {
        match resolve(
            &a001_set(),
            &ident("SIGMA", "SIGMA fp", 3856, 2170, 12, 1),
        ) {
            Resolution::Mismatch(m) => {
                assert_eq!(m.class, 4);
                assert_eq!(
                    m.message,
                    "camera mismatch: profile a001-sigma-fp geometry/depth match but photometric interpretation 1 != the profile's CFA photometric 32803"
                );
            }
            other => panic!("must be class 4, got {other:?}"),
        }
    }

    #[test]
    fn resolve_class_ordering_first_failing_wins() {
        // A frame failing Make/Model AND geometry names class 1 (the
        // first in the order).
        match resolve(
            &a001_set(),
            &ident("ACME", "ACME-1", 4000, 3000, 12, 32803),
        ) {
            Resolution::Mismatch(m) => assert_eq!(m.class, 1, "{}", m.message),
            other => panic!("must mismatch, got {other:?}"),
        }
        // A frame failing depth AND photometric names class 3.
        match resolve(
            &a001_set(),
            &ident("SIGMA", "SIGMA fp", 3856, 2170, 14, 1),
        ) {
            Resolution::Mismatch(m) => assert_eq!(m.class, 3, "{}", m.message),
            other => panic!("must mismatch, got {other:?}"),
        }
    }

    // ---- the profile-set resolution (the pins pattern) -----------------

    fn write_profile_file(dir: &Path, name: &str, text: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn resolve_core_env_file_precedence() {
        let tmp = std::env::temp_dir().join("frameprism_camera_env_file_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let env_file = write_profile_file(&tmp, "a001-sigma-fp.profile", A001_PROFILE);
        // The cwd + exe dirs both carry a DIFFERENT profile: the env
        // file wins (the precedence).
        let cwd = tmp.join("cwd");
        let exe = tmp.join("exe");
        std::fs::create_dir_all(cwd.join("profiles")).unwrap();
        std::fs::create_dir_all(exe.join("profiles")).unwrap();
        let other = A001_PROFILE.replace(
            "camera: a001-sigma-fp",
            "camera: other-id",
        );
        write_profile_file(&cwd.join("profiles"), "other.profile", &other);
        write_profile_file(&exe.join("profiles"), "other2.profile", &other);
        let set = resolve_core(Some(&env_file), &cwd, &exe).unwrap();
        assert_eq!(set.profiles.len(), 1);
        assert_eq!(set.profiles[0].camera, "a001-sigma-fp");
        assert!(set.source.contains("FRAMEPRISM_PROFILES"), "{}", set.source);
        // The env file missing = the named refusal (NOT a silent
        // fall-through to the dirs).
        let err = resolve_core(Some(&tmp.join("nope.profile")), &cwd, &exe).unwrap_err();
        assert!(err.starts_with("camera profile set unresolvable:"), "{err}");
        assert!(err.contains("not a file"), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_core_cwd_then_exe_then_unresolvable() {
        let tmp = std::env::temp_dir().join("frameprism_camera_dirs_test");
        let _ = std::fs::remove_dir_all(&tmp);
        let cwd = tmp.join("cwd");
        let exe = tmp.join("exe");
        std::fs::create_dir_all(cwd.join("profiles")).unwrap();
        std::fs::create_dir_all(exe.join("profiles")).unwrap();
        write_profile_file(&cwd.join("profiles"), "a.profile", A001_PROFILE);
        // cwd wins over exe.
        let set = resolve_core(None, &cwd, &exe).unwrap();
        assert_eq!(set.profiles.len(), 1);
        assert!(set.source.contains("cwd"), "{}", set.source);
        // No cwd dir → the exe dir.
        let cwd2 = tmp.join("cwd2");
        std::fs::create_dir_all(&cwd2).unwrap();
        let set = resolve_core(None, &cwd2, &exe).unwrap();
        assert!(set.source.contains("exe-dir"), "{}", set.source);
        // Neither → the named unresolvable refusal.
        let exe2 = tmp.join("exe2");
        std::fs::create_dir_all(&exe2).unwrap();
        let err = resolve_core(None, &cwd2, &exe2).unwrap_err();
        assert!(
            err.starts_with("camera profile set unresolvable (probed:"),
            "{err}"
        );
        assert!(err.contains("the tool does not encode"), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_core_malformed_profile_named() {
        let tmp = std::env::temp_dir().join("frameprism_camera_malformed_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let cwd = tmp.join("cwd");
        std::fs::create_dir_all(cwd.join("profiles")).unwrap();
        let exe = tmp.join("exe");
        std::fs::create_dir_all(&exe).unwrap();
        // A truncated profile (the magic + one row only).
        let truncated = write_profile_file(
            &cwd.join("profiles"),
            "a001-sigma-fp.profile",
            "# frameprism camera profile\nversion: 1\n",
        );
        let err = resolve_core(None, &cwd, &exe).unwrap_err();
        assert!(
            err.starts_with(&format!("camera profile {}: ", truncated.display())),
            "{err}"
        );
        assert!(err.contains("missing required key:"), "{err}");
        // A bad-magic profile.
        std::fs::write(
            &truncated,
            "# frameprism other profile\nversion: 1\n",
        )
        .unwrap();
        let err = resolve_core(None, &cwd, &exe).unwrap_err();
        assert!(err.contains("bad magic:"), "{err}");
        // A cross-file duplicate camera id.
        std::fs::write(&truncated, A001_PROFILE).unwrap();
        write_profile_file(
            &cwd.join("profiles"),
            "z-dup.profile",
            A001_PROFILE,
        );
        let err = resolve_core(None, &cwd, &exe).unwrap_err();
        assert!(err.contains("duplicate camera id a001-sigma-fp"), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ---- the identity extraction (from a parsed header) -----------------

    /// A minimal little-endian TIFF/DNG header carrying the identity
    /// tags (the `read_meta`-parseable half of the foreign-DNG fixture
    /// — see the fixture builder above for the full single-strip
    /// container).
    fn synth_identity_header(
        make: &str,
        model: &str,
        w: u32,
        h: u32,
        bps: u16,
        photo: u16,
    ) -> Vec<u8> {
        crate::camera::synth_dng_frame(make, model, w, h, bps, photo, None)
    }

    #[test]
    fn identity_from_synthetic_header() {
        for (make, model, w, h, bps, photo) in [
            ("SIGMA", "SIGMA fp", 3856u32, 2170u32, 12u16, 32803u16),
            ("ACME", "ACME-1", 1024, 768, 12, 32803),
            ("SIGMA", "SIGMA fp", 3856, 2170, 12, 1),
        ] {
            let buf = synth_identity_header(make, model, w, h, bps, photo);
            let meta = crate::tiff::read_meta(&buf).unwrap_or_else(|e| {
                panic!("synthetic {make} {model} {w}x{h} @ {bps} photo {photo} must read_meta: {e}")
            });
            let id = identity_from_ifd0(&meta.ifd0, &buf).unwrap();
            assert_eq!(
                id,
                FrameIdentity {
                    make: make.into(),
                    model: model.into(),
                    width: w,
                    height: h,
                    bits_per_sample: bps,
                    photometric: photo,
                }
            );
        }
    }

    /// A valid 8-byte TimeCodes payload (the fp's BCD layout — all
    /// zeros: HH=MM=SS=FF=0, a legal SMPTE 12M field). The fixture
    /// frames carry it so a foreign frame is ingest-eligible (the
    /// camera gate — not the TC gate — is the refusal under test).
    const TC_VALID: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

    #[test]
    fn identity_missing_make_tag_named() {
        // The audit tests' single-entry synthetic (256 only): no Make.
        let n_entries: u16 = 1;
        let struct_len = 8u64 + 2 + 12 + 4;
        let mut buf = vec![0u8; struct_len as usize + 8];
        buf[0..4].copy_from_slice(b"II*\0");
        buf[4..8].copy_from_slice(&8u32.to_le_bytes());
        buf[8..10].copy_from_slice(&n_entries.to_le_bytes());
        buf[10..12].copy_from_slice(&256u16.to_le_bytes()); // tag
        buf[12..14].copy_from_slice(&3u16.to_le_bytes()); // SHORT
        buf[14..18].copy_from_slice(&1u32.to_le_bytes()); // count 1
        buf[18..20].copy_from_slice(&3856u16.to_le_bytes());
        let meta = crate::tiff::read_meta(&buf).unwrap();
        let err = identity_from_ifd0(&meta.ifd0, &buf).unwrap_err();
        assert_eq!(err, "no Make tag (271) in IFD0");
    }

    // ---- the fixture classes end to end (the four variants + the A001
    //      container parses) ---------------------------------------------

    #[test]
    fn fixture_variant_a_class1_and_parses() {
        // (a) ACME ACME-1, 1024x768 @12, CFA: tiff::read OK + class 1.
        let buf = synth_dng_frame("ACME", "ACME-1", 1024, 768, 12, 32803, Some(TC_VALID));
        let frame = crate::tiff::read(&buf)
            .expect("variant (a) must be a fully parseable single-strip DNG");
        let packed = frame.strip_slice(&buf);
        assert_eq!(packed.len(), (1024 * 768 * 3 / 2) as usize);
        let id = identity_from_ifd0(&frame.ifd0, &buf).unwrap();
        match resolve(&a001_set(), &id) {
            Resolution::Mismatch(m) => {
                assert_eq!(m.class, 1);
                assert_eq!(
                    m.message,
                    "camera mismatch: no profile matches Make/Model ACME ACME-1"
                );
            }
            other => panic!("must be class 1: {other:?}"),
        }
    }

    #[test]
    fn fixture_variant_b_class2_and_parses() {
        // (b) SIGMA SIGMA fp, 4000x3000 @12, CFA: tiff::read OK +
        // class 2 (a known camera, an unmeasured readout).
        let buf = synth_dng_frame("SIGMA", "SIGMA fp", 4000, 3000, 12, 32803, Some(TC_VALID));
        let frame = crate::tiff::read(&buf)
            .expect("variant (b) must be a fully parseable single-strip DNG");
        let id = identity_from_ifd0(&frame.ifd0, &buf).unwrap();
        match resolve(&a001_set(), &id) {
            Resolution::Mismatch(m) => {
                assert_eq!(m.class, 2);
                assert!(m.message.contains("geometry 4000x3000 is not in the profile's geometry rows"), "{}", m.message);
            }
            other => panic!("must be class 2: {other:?}"),
        }
    }

    #[test]
    fn fixture_variant_c_class3_read_meta() {
        // (c) SIGMA SIGMA fp, 3856x2170 @14, CFA: the depth is not
        // 8/10/12, so tiff::read refuses it by its OWN named class
        // (UnsupportedBps) — the run gate (read_meta) names class 3
        // BEFORE the encode ever parses it.
        let buf = synth_dng_frame("SIGMA", "SIGMA fp", 3856, 2170, 14, 32803, Some(TC_VALID));
        assert!(
            matches!(crate::tiff::read(&buf), Err(crate::tiff::ParseError::UnsupportedBps(14))),
            "the 14-bit container is the parser's own named refusal (the gate precedes it)"
        );
        let meta = crate::tiff::read_meta(&buf).unwrap();
        let id = identity_from_ifd0(&meta.ifd0, &buf).unwrap();
        match resolve(&a001_set(), &id) {
            Resolution::Mismatch(m) => {
                assert_eq!(m.class, 3);
                assert!(m.message.contains("bits_per_sample 14 is not a profiled depth"), "{}", m.message);
            }
            other => panic!("must be class 3: {other:?}"),
        }
    }

    #[test]
    fn fixture_variant_d_class4_read_meta() {
        // (d) SIGMA SIGMA fp, 3856x2170 @12, photometric 1 (RGB, not
        // CFA): tiff::read refuses it by its OWN named class (NotCfa)
        // — the run gate (read_meta) names class 4 before the encode
        // ever parses it.
        let buf = synth_dng_frame("SIGMA", "SIGMA fp", 3856, 2170, 12, 1, Some(TC_VALID));
        assert!(
            matches!(crate::tiff::read(&buf), Err(crate::tiff::ParseError::NotCfa(1))),
            "the non-CFA container is the parser's own named refusal (the gate precedes it)"
        );
        let meta = crate::tiff::read_meta(&buf).unwrap();
        let id = identity_from_ifd0(&meta.ifd0, &buf).unwrap();
        match resolve(&a001_set(), &id) {
            Resolution::Mismatch(m) => {
                assert_eq!(m.class, 4);
                assert!(
                    m.message
                        .contains("photometric interpretation 1 != the profile's CFA photometric 32803"),
                    "{}",
                    m.message
                );
            }
            other => panic!("must be class 4: {other:?}"),
        }
    }

    #[test]
    fn fixture_a001_identity_container_parses_and_matches() {
        // The A001-identity synthetic (the FHD 1936x1090 @10 readout):
        // tiff::read OK + MATCH (the gate passes a profiled frame).
        let buf = synth_dng_frame("SIGMA", "SIGMA fp", 1936, 1090, 10, 32803, Some(TC_VALID));
        let frame = crate::tiff::read(&buf)
            .expect("the A001-identity FHD-10 container must parse");
        let id = identity_from_ifd0(&frame.ifd0, &buf).unwrap();
        match resolve(&a001_set(), &id) {
            Resolution::Match { camera, profile_version, predicates } => {
                assert_eq!(camera, "a001-sigma-fp");
                assert_eq!(profile_version, 1);
                assert_eq!(predicates, vec![PRED_ARCHIVE]);
            }
            other => panic!("must MATCH: {other:?}"),
        }
    }

    // ---- the audit camera line classes ----------------------------------

    fn mk_audit_camera_dir(tag: &str, dng: Option<&[u8]>) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("frameprism_camera_audit_{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(bytes) = dng {
            std::fs::write(dir.join("A001_001_20260701_000001.DNG"), bytes).unwrap();
        }
        dir
    }

    /// Save/restore the process-wide profile override (the test-only
    /// slot): every test override carries the SAME A001 profile
    /// content, so a concurrent set/restore interleaving cannot skew a
    /// resolution — but the previous value is restored (never a blind
    /// clear) so a concurrent worker-encode test keeps its set.
    fn override_around<T>(path: &Path, f: impl FnOnce() -> T) -> T {
        let mut guard = OVERRIDDEN.lock().unwrap();
        let prev = guard.take();
        *guard = Some(path.to_path_buf());
        drop(guard);
        let out = f();
        *OVERRIDDEN.lock().unwrap() = prev;
        out
    }

    #[test]
    fn audit_camera_line_match() {
        let tmp = std::env::temp_dir().join("frameprism_camera_audit_match_profile");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let profile_file = write_profile_file(&tmp, "a001-sigma-fp.profile", A001_PROFILE);
        let dir = mk_audit_camera_dir(
            "match",
            Some(&synth_dng_frame("SIGMA", "SIGMA fp", 3856, 2170, 12, 32803, None)),
        );
        let frames = vec![dir.join("A001_001_20260701_000001.DNG")];
        let (line, bad) = override_around(&profile_file, || {
            audit_camera_line(&dir, &frames)
        });
        assert!(!bad, "{line}");
        assert_eq!(line, "audit: camera MATCH (a001-sigma-fp, profile v1)");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_camera_line_mismatch_is_a_named_offender() {
        let tmp = std::env::temp_dir().join("frameprism_camera_audit_mm_profile");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let profile_file = write_profile_file(&tmp, "a001-sigma-fp.profile", A001_PROFILE);
        let dir = mk_audit_camera_dir(
            "mismatch",
            Some(&synth_dng_frame("ACME", "ACME-1", 1024, 768, 12, 32803, None)),
        );
        let frames = vec![dir.join("A001_001_20260701_000001.DNG")];
        let (line, bad) = override_around(&profile_file, || {
            audit_camera_line(&dir, &frames)
        });
        assert!(bad, "{line}");
        assert!(line.starts_with("FAIL audit: camera MISMATCH — "), "{line}");
        assert!(
            line.contains("camera mismatch: no profile matches Make/Model ACME ACME-1"),
            "{line}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_camera_line_absent_no_frames() {
        let dir = mk_audit_camera_dir("absent-noframes", None);
        let (line, bad) = audit_camera_line(&dir, &[]);
        assert!(!bad, "{line}");
        assert!(line.starts_with("audit: camera ABSENT — no DNG frames in "), "{line}");
        assert!(line.contains("optional for the PASS"), "{line}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // =================================================================
    // The per-clip offload detection (the offload surface's report —
    // a report, not a gate; the pure `offload_detections_with` core —
    // no process-global profile override, deterministic over the
    // tree + the set)
    // =================================================================

    /// The test's resolved profile set (the A001 profile — the
    /// camera.rs reference contents, parsed in-process).
    fn a001_profile_set() -> ProfileSet {
        ProfileSet {
            profiles: vec![a001_profile()],
            source: "the test profile set (the camera.rs detection tests)".into(),
        }
    }

    /// The detection fixture tree: the profiled clip (the A001
    /// identity — the Match class), the unprofiled clip (an unknown
    /// Make/Model — the class-1 Mismatch), the non-DNG clip
    /// (sidecar-only), the unparseable-DNG clip (the no-readable-
    /// identity class), the source-root files (the "" clip key).
    fn detection_tree(tag: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "frameprism_offload_detect_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let input = base.join("in");
        std::fs::create_dir_all(input.join("A001_001")).unwrap();
        std::fs::create_dir_all(input.join("B002_002")).unwrap();
        std::fs::create_dir_all(input.join("C003_003")).unwrap();
        std::fs::create_dir_all(input.join("D004_004")).unwrap();
        // The profiled clip (the A001 identity — the 3856x2170 12-bit
        // readout the profile pins).
        std::fs::write(
            input.join("A001_001/f1.DNG"),
            synth_dng_frame("SIGMA", "SIGMA fp", 3856, 2170, 12, 32803, None),
        )
        .unwrap();
        // The unprofiled clip (an unknown Make/Model — the class-1
        // Mismatch: no profile matches).
        std::fs::write(
            input.join("B002_002/f1.DNG"),
            synth_dng_frame("TEST MAKE", "TEST MODEL", 1920, 1080, 12, 32803, None),
        )
        .unwrap();
        // The non-DNG clip (the sidecar-only material).
        std::fs::write(input.join("C003_003/clip.wav"), b"RIFF-wave").unwrap();
        // The unparseable DNG (a .DNG-named non-TIFF — the sample has
        // no readable identity: the `- -` no-value token).
        std::fs::write(input.join("D004_004/junk.DNG"), b"not-a-tiff").unwrap();
        // The source-root file (the "" clip key — the non-DNG class).
        std::fs::write(input.join("root.wav"), b"RIFF-root-wave").unwrap();
        (base, input)
    }

    #[test]
    fn offload_detections_name_the_three_classes() {
        let (base, input) = detection_tree("classes");
        let scan =
            offload_detections_with(&input, ProfileSetState::Resolved(a001_profile_set())).unwrap();
        // One row per file-bearing clip key, the sorted clip key order
        // (the deterministic report order).
        let keys: Vec<&str> = scan.clips.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, vec!["", "A001_001", "B002_002", "C003_003", "D004_004"],
            "{:?}", scan.clips);
        let by_key: std::collections::BTreeMap<&str, DetectionClass> = scan
            .clips
            .iter()
            .map(|c| (c.key.as_str(), c.class.clone()))
            .collect();
        assert_eq!(
            by_key.get("A001_001"),
            Some(&DetectionClass::Profiled {
                camera: "a001-sigma-fp".into(),
                profile_version: 1,
            }),
            "the Match class: the camera id + the profile version"
        );
        assert_eq!(
            by_key.get("B002_002"),
            Some(&DetectionClass::Unprofiled {
                make: "TEST MAKE".into(),
                model: "TEST MODEL".into(),
            }),
            "the class-1 Mismatch: the frame's own Make/Model"
        );
        assert_eq!(by_key.get("C003_003"), Some(&DetectionClass::NonDng));
        assert_eq!(
            by_key.get("D004_004"),
            Some(&DetectionClass::Unprofiled {
                make: "-".into(),
                model: "-".into(),
            }),
            "the unreadable sample: the no-value token"
        );
        assert_eq!(by_key.get(""), Some(&DetectionClass::NonDng));
        // The deterministic named lines (the surface's contract — the
        // exact formats).
        let lines: std::collections::BTreeMap<&str, String> = scan
            .clips
            .iter()
            .map(|c| (c.key.as_str(), c.class.line()))
            .collect();
        assert_eq!(
            lines.get("A001_001").map(String::as_str),
            Some("profiled a001-sigma-fp (profile v1)")
        );
        assert_eq!(
            lines.get("B002_002").map(String::as_str),
            Some("unprofiled camera TEST MAKE TEST MODEL")
        );
        assert_eq!(lines.get("C003_003").map(String::as_str), Some("non-DNG media"));
        assert_eq!(lines.get("D004_004").map(String::as_str), Some("unprofiled camera - -"));
        assert_eq!(lines.get("").map(String::as_str), Some("non-DNG media"));
        assert!(scan.profiles_line.starts_with("profiles: the test profile set"),
            "{}", scan.profiles_line);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn offload_detections_absent_set_rides_the_honest_lines() {
        let (base, input) = detection_tree("absent");
        let scan = offload_detections_with(
            &input,
            ProfileSetState::Absent(
                "camera profile set unresolvable (the test's named refusal)".into(),
            ),
        )
        .unwrap();
        // No set → no Match is reachable: the DNG clips ride
        // `unprofiled camera` with the readable identity (the A001
        // clip is NOT profiled without its profile), the non-DNG
        // clips + the `- -` class are unchanged (the report, not a
        // gate: nothing refuses).
        let by_key: std::collections::BTreeMap<&str, DetectionClass> = scan
            .clips
            .iter()
            .map(|c| (c.key.as_str(), c.class.clone()))
            .collect();
        assert_eq!(
            by_key.get("A001_001"),
            Some(&DetectionClass::Unprofiled {
                make: "SIGMA".into(),
                model: "SIGMA fp".into(),
            }),
            "the identity is still named (the readable sample)"
        );
        assert_eq!(
            by_key.get("B002_002"),
            Some(&DetectionClass::Unprofiled {
                make: "TEST MAKE".into(),
                model: "TEST MODEL".into(),
            })
        );
        assert_eq!(by_key.get("C003_003"), Some(&DetectionClass::NonDng));
        assert_eq!(
            by_key.get("D004_004"),
            Some(&DetectionClass::Unprofiled {
                make: "-".into(),
                model: "-".into(),
            })
        );
        assert_eq!(by_key.get(""), Some(&DetectionClass::NonDng));
        // The ABSENT honesty line (the refusal named — the audit
        // ABSENT precedent).
        assert!(
            scan.profiles_line.starts_with("profiles: ABSENT — camera profile set unresolvable (the test's named refusal)"),
            "{}",
            scan.profiles_line
        );
        assert!(scan.profiles_line.contains("the offload copies + verifies regardless"),
            "{}",
            scan.profiles_line);
        let _ = std::fs::remove_dir_all(&base);
    }

    // The detection prefix bound (the bounded read): a
    // file LARGER than the bound with the identity in the first
    // page classifies IDENTICALLY through the prefix read and the
    // full buffer (the behavior-neutrality proof). The synthetic
    // frame is 1024x1024 x 16-bit = 1,572,864 B of strip + the
    // header (1.5 MiB > the 1 MiB bound).
    #[test]
    fn detection_prefix_property_over_the_bound() {
        let full = synth_dng_frame("TestMake", "TestModel", 1024, 1024, 16, 5, None);
        assert!(
            full.len() > DETECTION_PREFIX_BOUND,
            "the fixture must exceed the bound ({} B > {} B)",
            full.len(),
            DETECTION_PREFIX_BOUND
        );
        let base = std::env::temp_dir().join(format!(
            "frameprism_cam_detect_prefix_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join("A001_001_20260101_000001.DNG");
        std::fs::write(&path, &full).unwrap();

        // The prefix read is capped at the bound (AT MOST the bound).
        let prefix = read_detection_prefix(&path).unwrap();
        assert_eq!(prefix.len(), DETECTION_PREFIX_BOUND);

        // The identity + the classification are IDENTICAL through
        // the prefix and the full buffer (the measured reach of the
        // committed fixtures is 79,280 B — the identity sits in the
        // first page).
        let ident_full = crate::tiff::read_meta(&full).unwrap();
        let ident_prefix = crate::tiff::read_meta(&prefix).unwrap();
        let f = identity_from_ifd0(&ident_full.ifd0, &full).unwrap();
        let pfx = identity_from_ifd0(&ident_prefix.ifd0, &prefix).unwrap();
        assert_eq!(pfx, f);

        // The classification rides the parsed identity (the Absent
        // set — no Match is reachable; the Unprofiled row carries
        // the identity, exactly the pre-existing full-read outcome).
        let cls = classify_detection_sample(&path, &ProfileSetState::Absent("test".to_string()));
        assert_eq!(
            cls,
            DetectionClass::Unprofiled {
                make: "TestMake".into(),
                model: "TestModel".into(),
            }
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    // The truncated-prefix behavior PIN: an identity value
    // stored BEYOND the bound (a value pointer at 2 MiB — the
    // hostile-input class) is the tiff module's named
    // RegionOutOfBounds class on the prefix read → the EXISTING note
    // path → the clip rides the `unprofiled camera - -` line (the
    // same refusal/note semantics — no new class, no new wording).
    #[test]
    fn detection_prefix_truncation_rides_the_unprofiled_line() {
        // A minimal TIFF (LE) with the Make/Model values at offsets
        // BEYOND the 1 MiB bound: the IFD structure is in the first
        // page, the identity strings at 2 MiB.
        const VALUE_OFF: u32 = 2 * 1024 * 1024;
        let make = b"FarMake\0";
        let model = b"FarModel\0";
        // (the IFD0 structure: 8 + 2 + 6*12 + 4 = 88 B — in the
        // first page by construction)
        let mut buf = vec![0u8; VALUE_OFF as usize + make.len() + model.len() + 64];
        buf[0..4].copy_from_slice(b"II*\0");
        buf[4..8].copy_from_slice(&8u32.to_le_bytes());
        buf[8..10].copy_from_slice(&6u16.to_le_bytes());
        let entries: [(u16, u16, u32, u32); 6] = [
            // (tag, typ, count, in-line value or out-of-line offset)
            (256, 3, 1, 1024),          // ImageWidth (in-line)
            (257, 3, 1, 1024),          // ImageLength (in-line)
            (258, 3, 1, 16),            // BitsPerSample (in-line)
            (262, 3, 1, 5),             // PhotometricInterpretation (in-line)
            (271, 2, make.len() as u32, VALUE_OFF),                    // Make (out-of-line, beyond the bound)
            (272, 2, model.len() as u32, VALUE_OFF + make.len() as u32), // Model (out-of-line, beyond the bound)
        ];
        for (i, (tag, typ, count, val)) in entries.iter().enumerate() {
            let t = 8 + 2 + i * 12;
            buf[t..t + 2].copy_from_slice(&tag.to_le_bytes());
            buf[t + 2..t + 4].copy_from_slice(&typ.to_le_bytes());
            buf[t + 4..t + 8].copy_from_slice(&count.to_le_bytes());
            buf[t + 8..t + 12].copy_from_slice(&val.to_le_bytes());
        }
        // The next-IFD pointer (0) — already zero.
        let model_off = VALUE_OFF as usize + make.len();
        buf[VALUE_OFF as usize..model_off].copy_from_slice(make);
        buf[model_off..model_off + model.len()].copy_from_slice(model);

        // The FULL buffer parses + carries the identity (the sanity
        // side — the full-read path WOULD resolve it).
        let full_meta = crate::tiff::read_meta(&buf).unwrap();
        let full_ident = identity_from_ifd0(&full_meta.ifd0, &buf).unwrap();
        assert_eq!(full_ident.make, "FarMake");

        // The PREFIX read: the out-of-line value offset is past the
        // prefix → the tiff module's named RegionOutOfBounds class
        // (the parse REFUSES — it never panics).
        let prefix = buf[..DETECTION_PREFIX_BOUND].to_vec();
        let err = crate::tiff::read_meta(&prefix).unwrap_err();
        assert!(
            matches!(err, crate::tiff::ParseError::RegionOutOfBounds { .. }),
            "the truncated prefix is the named RegionOutOfBounds class: {err:?}"
        );

        // The classification rides the EXISTING note path → the
        // unidentifiable `unprofiled camera - -` line.
        let base = std::env::temp_dir().join(format!(
            "frameprism_cam_detect_trunc_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join("A001_001_20260101_000001.DNG");
        std::fs::write(&path, &buf).unwrap();
        let cls = classify_detection_sample(&path, &ProfileSetState::Absent("test".to_string()));
        assert_eq!(
            cls,
            DetectionClass::Unprofiled {
                make: "-".into(),
                model: "-".into(),
            }
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
