//! The checksums — the frame-metadata reads.
//!
//! The timecode cluster: `Smpte12m` (the SMPTE 12m BCD timecode — the
//! camera's TimeCodes tag parse) + the parse surface
//! (`parse_timecodes_field` / `bcd_byte` / `resolve_tc` /
//! `read_timecodes_tag` — the bounded window read, the fallback
//! discipline) + the tag constants (`TC_TAG` / `TC_TAG_COUNT` /
//! `TC_FRAME_RATE`). The frame-metadata cluster: `FrameMetadata` (the
//! 4 camera-metadata columns — the timecode / the frame rate / the ISO
//! / the exposure) + the EXIF/IFD walk (`walk_ifd` / `IfdEntry` /
//! `IfdWalk` / `tiff_type_size` / `parse_rational_pair` /
//! `resolve_frame_metadata` — the bounds discipline: every pointer is
//! range-checked against the file len) + `read_frame_metadata` (the
//! bounded window read) + `frame_number_from_stem` (the clip-stem
//! frame number). The consumers: the crate `checksums` module (the
//! --checksums sidecar's camera-metadata columns) + the crate `report`
//! module + the ingest gate (the `ingest` part).

use std::io::{Read as _, Seek as _};
use std::path::Path;

use anyhow::Result;

/// The CinemaDNG TimeCodes tag (the per-frame SMPTE 12M; the 8-byte
/// value field = 4 BCD field bytes + 4 NUL padding).
pub const TC_TAG: u16 = 51043;

/// The expected TimeCodes value count (the fp's 8-byte cDNG
/// metadata field).
pub const TC_TAG_COUNT: u32 = 8;

/// The frame rate the TC continuity contract is pinned to (tag 51044 =
/// 24000/1000, verified on every batch clip): consecutive frames
/// advance exactly one frame.
pub const TC_FRAME_RATE: u64 = 24;

/// One SMPTE 12M non-drop timecode (24 fps), parsed from the tag's
/// 4-byte BCD payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Smpte12m {
    pub hh: u8,
    pub mm: u8,
    pub ss: u8,
    pub ff: u8,
}

impl Smpte12m {
    /// The absolute frame count (24 fps non-drop) — the continuity
    /// arithmetic domain.
    pub fn total_frames(self) -> u64 {
        (((self.hh as u64) * 60 + self.mm as u64) * 60 + self.ss as u64)
            * TC_FRAME_RATE
            + self.ff as u64
    }
    /// The SMPTE 12M display form `HH:MM:SS:FF`.
    pub fn display(self) -> String {
        format!(
            "{:02}:{:02}:{:02}:{:02}",
            self.hh, self.mm, self.ss, self.ff
        )
    }
}

/// One BCD byte (tens digit in the high nibble; both nibbles ≤ 9).
fn bcd_byte(b: u8) -> Option<u8> {
    if (b & 0x0F) > 9 {
        return None;
    }
    Some((b >> 4) * 10 + (b & 0x0F))
}

/// Parse the tag 51043 8-byte value field as a 24 fps non-drop SMPTE
/// 12M timecode: byte [0]=FF, [1]=SS, [2]=MM, [3]=HH (BCD — the fp's
/// field order, least-significant field first; the trailing 4 padding
/// bytes are ignored). `Err` names the malformed payload (never a
/// silent skip).
pub fn parse_timecodes_field(bytes: &[u8]) -> Result<Smpte12m, String> {
    if bytes.len() < 4 {
        return Err(format!(
            "TimeCodes (51043) payload is {} byte(s), want 4+ (the 4 BCD field bytes)",
            bytes.len()
        ));
    }
    let ff = bcd_byte(bytes[0]).ok_or_else(|| {
        format!("TimeCodes (51043) frame byte 0x{:02X} is not BCD", bytes[0])
    })?;
    let ss = bcd_byte(bytes[1]).ok_or_else(|| {
        format!(
            "TimeCodes (51043) seconds byte 0x{:02X} is not BCD",
            bytes[1]
        )
    })?;
    let mm = bcd_byte(bytes[2]).ok_or_else(|| {
        format!(
            "TimeCodes (51043) minutes byte 0x{:02X} is not BCD",
            bytes[2]
        )
    })?;
    let hh = bcd_byte(bytes[3]).ok_or_else(|| {
        format!("TimeCodes (51043) hours byte 0x{:02X} is not BCD", bytes[3])
    })?;
    if hh > 23 {
        return Err(format!("TimeCodes (51043) hour field {hh:02} > 23 (SMPTE 12M)"));
    }
    if ff > 23 {
        return Err(format!(
            "TimeCodes (51043) frame field {ff:02} > 23 (24 fps non-drop — tag 51044 = 24000/1000)"
        ));
    }
    if ss > 59 {
        return Err(format!("TimeCodes (51043) seconds field {ss:02} > 59 (SMPTE 12M)"));
    }
    if mm > 59 {
        return Err(format!("TimeCodes (51043) minutes field {mm:02} > 59 (SMPTE 12M)"));
    }
    Ok(Smpte12m { hh, mm, ss, ff })
}

/// The result of resolving tag 51043 out of a (possibly windowed) read
/// of a DNG's header.
enum TcResolve {
    /// The tag is present and parseable.
    Found(Smpte12m),
    /// The IFD0 was walked completely; the tag is absent.
    Absent,
    /// The header is corrupt, or the tag is present but malformed —
    /// `reason` is the named detail (the TC_MALFORMED class).
    Malformed(String),
    /// The IFD0 structure or the tag's value pointer extends beyond the
    /// buffer read — the caller falls back to the full-file read
    /// (named, not a silent skip).
    OutOfWindow,
}

/// Walk the little-endian IFD0 of the (possibly windowed) header buffer
/// and resolve tag 51043. Every offset is bounds-checked against BOTH
/// the buffer (a window) and the full file length — the two bounds are
/// what separate `Malformed` (corrupt) from `OutOfWindow` (re-read
/// needed).
fn resolve_tc(buf: &[u8], file_len: u64) -> TcResolve {
    if buf.len() < 8 || file_len < 8 {
        return TcResolve::Malformed(format!(
            "file is {} byte(s) — too small to be a TIFF (want 8+)",
            file_len.min(buf.len() as u64)
        ));
    }
    if &buf[0..4] != b"II*\0" {
        return TcResolve::Malformed(
            "not a little-endian TIFF (want the II*\\0 magic at offset 0) — the fp's cDNG is little-endian".into(),
        );
    }
    let ifd_off = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as u64;
    if ifd_off + 2 > buf.len() as u64 {
        return if ifd_off + 2 > file_len {
            TcResolve::Malformed(format!(
                "IFD0 offset {ifd_off} is out of the file bounds ({} B)",
                file_len
            ))
        } else {
            TcResolve::OutOfWindow
        };
    }
    let n = u16::from_le_bytes(buf[ifd_off as usize..(ifd_off + 2) as usize].try_into().unwrap())
        as u64;
    if n == 0 {
        return TcResolve::Malformed("IFD0 entry count is 0".into());
    }
    let ifd_end = match ifd_off.checked_add(2).and_then(|a| a.checked_add(n * 12)).and_then(|a| a.checked_add(4)) {
        Some(v) => v,
        None => {
            return TcResolve::Malformed("IFD0 entry count is implausible (offset overflow)".into())
        }
    };
    if ifd_end > buf.len() as u64 {
        return if ifd_end > file_len {
            TcResolve::Malformed(format!(
                "IFD0 structure ({n} entries) is out of the file bounds ({} B)",
                file_len
            ))
        } else {
            TcResolve::OutOfWindow
        };
    }
    for i in 0..n {
        let t = ifd_off + 2 + i * 12;
        let tag = u16::from_le_bytes(buf[t as usize..(t + 2) as usize].try_into().unwrap());
        if tag != TC_TAG {
            continue;
        }
        let typ = u16::from_le_bytes(buf[(t + 2) as usize..(t + 4) as usize].try_into().unwrap());
        let cnt = u32::from_le_bytes(buf[(t + 4) as usize..(t + 8) as usize].try_into().unwrap());
        // Byte-sized types (BYTE 1 / ASCII 2 / UNDEFINED 7,11) are the
        // only legal carriers of the 8-byte BCD payload; anything else
        // (or a wrong count) is a named malformed-tag FAIL.
        let tsz: u64 = match typ {
            1 | 2 | 7 | 11 => 1,
            3 | 8 => 2,
            4 | 9 => 4,
            _ => 0,
        };
        if tsz == 0 || tsz * cnt as u64 != TC_TAG_COUNT as u64 {
            return TcResolve::Malformed(format!(
                "TimeCodes (51043) is type {typ} count {cnt} — want a byte type with count {TC_TAG_COUNT}"
            ));
        }
        let value_off = t + 8;
        let size = TC_TAG_COUNT as u64; // 8
        let value: &[u8] = if size <= 4 {
            // In-line (unreachable at count 8 — kept for completeness;
            // the IFD bounds above guarantee value_off..+4 is in buf).
            &buf[value_off as usize..(value_off + size) as usize]
        } else {
            if value_off + 4 > buf.len() as u64 {
                return if value_off + 4 > file_len {
                    TcResolve::Malformed(format!(
                        "TimeCodes (51043) value field at {value_off} is out of the file bounds ({} B)",
                        file_len
                    ))
                } else {
                    TcResolve::OutOfWindow
                };
            }
            let p = u32::from_le_bytes(
                buf[value_off as usize..(value_off + 4) as usize].try_into().unwrap(),
            ) as u64;
            if p + size > file_len {
                return TcResolve::Malformed(format!(
                    "TimeCodes (51043) out-of-line pointer {p} + {size} B is out of the file bounds ({} B)",
                    file_len
                ));
            }
            if p + size > buf.len() as u64 {
                return TcResolve::OutOfWindow;
            }
            &buf[p as usize..(p + size) as usize]
        };
        return match parse_timecodes_field(value) {
            Ok(tc) => TcResolve::Found(tc),
            Err(reason) => TcResolve::Malformed(reason),
        };
    }
    TcResolve::Absent
}

/// Read the per-frame TimeCodes (tag 51043) from a DNG frame file.
/// `Ok(Some(tc))` = present + parseable · `Ok(None)` = the tag is
/// absent from IFD0 (the TC_MISSING class — the fp always carries it,
/// so absence is an ingest anomaly) · `Err(reason)` = a corrupt header
/// or a malformed payload (the TC_MALFORMED class — a corrupt header
/// is named, never passed).
///
/// Reads a 512 KiB header window first (the fp's IFD0 + every
/// out-of-line value ends < 79 KiB); the
/// full file is read ONLY when the value pointer falls outside the
/// window (the named fallback — never a silent skip).
pub fn read_timecodes_tag(path: &Path) -> Result<Option<Smpte12m>, String> {
    const WINDOW: u64 = 512 * 1024;
    let file_len = std::fs::metadata(path)
        .map_err(|err| format!("{}: metadata: {err}", path.display()))?
        .len();
    let mut file = std::fs::File::open(path)
        .map_err(|err| format!("{}: open: {err}", path.display()))?;
    let mut buf = vec![0u8; WINDOW.min(file_len) as usize];
    file.read_exact(&mut buf)
        .map_err(|err| format!("{}: read the header window: {err}", path.display()))?;
    match resolve_tc(&buf, file_len) {
        TcResolve::Found(tc) => Ok(Some(tc)),
        TcResolve::Absent => Ok(None),
        TcResolve::Malformed(reason) => Err(format!("{}: {reason}", path.display())),
        TcResolve::OutOfWindow => {
            // Named fallback: the tag's value pointer lies beyond the
            // header window — read the rest of the file and re-resolve.
            eprintln!(
                "note: {} — TimeCodes (51043) value pointer beyond the 512 KiB header window; reading the full file",
                path.display()
            );
            file.seek(std::io::SeekFrom::Start(WINDOW.min(file_len)))
                .map_err(|err| format!("{}: seek: {err}", path.display()))?;
            file.read_to_end(&mut buf)
                .map_err(|err| format!("{}: read the full file: {err}", path.display()))?;
            match resolve_tc(&buf, file_len) {
                TcResolve::Found(tc) => Ok(Some(tc)),
                TcResolve::Absent => Ok(None),
                TcResolve::Malformed(reason) => Err(format!("{}: {reason}", path.display())),
                TcResolve::OutOfWindow => Err(format!(
                    "{}: TimeCodes (51043) is out of bounds even after the full-file read (corrupt header?)",
                    path.display()
                )),
            }
        }
    }
}

// =====================================================================
// per-frame camera metadata (the
// pull-in — the sidecar v3 columns). The tags + shapes MEASURED on
// the CINEMA batch (tag census; all 7 clips probed):
// 51043 TimeCodes IFD0 BYTE n=8 (the BCD layout
// b0=FF b1=SS b2=MM b3=HH)
// 51044 FrameRate IFD0 SRATIONAL n=1 = 24000/1000 (every frame)
// 34855 ISOSpeedRatings ExifIFD (via IFD0 0x8769) SHORT n=1 = 100
// 34853 ExposureTime ExifIFD — ABSENT on the fp (the fixed empty
// column; no invented values)
// =====================================================================

/// The ExifIFD pointer tag (IFD0 0x8769, TIFF-EXIF) — the fp's
/// 34855/34853 live in the Exif sub-IFD, not IFD0 (tag census).
///
pub const EXIF_IFD_TAG: u16 = 0x8769;

/// The FrameRate tag (DNG; SRATIONAL n=1 on the fp — 24000/1000).
pub const FRAME_RATE_TAG: u16 = 51044;

/// The ISOSpeedRatings tag (EXIF; in the ExifIFD on the fp — SHORT n=1).
pub const ISO_TAG: u16 = 34855;

/// The ExposureTime tag (EXIF; in the ExifIFD on the fp — ABSENT there,
/// the fixed empty sidecar column).
pub const EXPOSURE_TAG: u16 = 34853;

/// Per-frame camera metadata from the DNG header (the sidecar v3
/// columns,). `None` per field = the tag is absent
/// (the fixed empty column — never an invented value); the reader's
/// `Err` = a corrupt header or a present-but-malformed tag (named —
/// never a silent skip, the audit philosophy).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FrameMetadata {
    /// Tag 51043 (IFD0) — the BCD decode.
    pub timecode: Option<Smpte12m>,
    /// Tag 51044 (IFD0) — (num, den); the fp = (24000, 1000).
    pub framerate: Option<(u32, u32)>,
    /// Tag 34855 (ExifIFD) — decimal, comma-joined for count > 1
    /// (the fp = "100", count 1).
    pub iso: Option<String>,
    /// Tag 34853 (ExifIFD) — (num, den) seconds. ABSENT on the fp
    /// (measured) → the fixed empty column.
    pub exposure: Option<(u32, u32)>,
}

/// One resolved IFD entry (the value bytes, inlined or pointer-
/// resolved against BOTH the window and the file bounds — the resolve_
/// tc bounds discipline).
struct IfdEntry {
    tag: u16,
    typ: u16,
    count: u32,
    value: Vec<u8>,
}

enum IfdWalk {
    Entries(Vec<IfdEntry>),
    Malformed(String),
    OutOfWindow,
}

/// The size per value element of a TIFF type (0 = unknown type).
fn tiff_type_size(typ: u16) -> u64 {
    match typ {
        1 | 2 | 6 | 7 => 1,   // BYTE / ASCII / SBYTE / UNDEFINED
        3 | 8 => 2,           // SHORT / SSHORT
        4 | 9 | 11 => 4,      // LONG / SLONG / FLOAT
        5 | 10 | 12 => 8,     // RATIONAL / SRATIONAL / DOUBLE
        _ => 0,
    }
}

/// Walk one little-endian IFD at `ifd_off` within the (possibly
/// windowed) header buffer `buf`, with `file_len` = the full file
/// length. Every offset is bounds-checked against BOTH bounds — the
/// two bounds are what separate `Malformed` (corrupt) from
/// `OutOfWindow` (a window re-read is needed), the resolve_tc
/// convention.
fn walk_ifd(buf: &[u8], file_len: u64, ifd_off: u64) -> IfdWalk {
    if ifd_off + 2 > buf.len() as u64 {
        return if ifd_off + 2 > file_len {
            IfdWalk::Malformed(format!(
                "IFD offset {ifd_off} is out of the file bounds ({} B)",
                file_len
            ))
        } else {
            IfdWalk::OutOfWindow
        };
    }
    let n =
        u16::from_le_bytes(buf[ifd_off as usize..(ifd_off + 2) as usize].try_into().unwrap()) as u64;
    if n == 0 {
        return IfdWalk::Malformed("IFD entry count is 0".into());
    }
    let ifd_end = match ifd_off
        .checked_add(2)
        .and_then(|a| a.checked_add(n * 12))
        .and_then(|a| a.checked_add(4))
    {
        Some(v) => v,
        None => {
            return IfdWalk::Malformed("IFD entry count is implausible (offset overflow)".into())
        }
    };
    if ifd_end > buf.len() as u64 {
        return if ifd_end > file_len {
            IfdWalk::Malformed(format!(
                "IFD structure ({n} entries) is out of the file bounds ({} B)",
                file_len
            ))
        } else {
            IfdWalk::OutOfWindow
        };
    }
    let mut entries = Vec::with_capacity(n as usize);
    for i in 0..n {
        let t = ifd_off + 2 + i * 12;
        let tag = u16::from_le_bytes(buf[t as usize..(t + 2) as usize].try_into().unwrap());
        let typ = u16::from_le_bytes(buf[(t + 2) as usize..(t + 4) as usize].try_into().unwrap());
        let count = u32::from_le_bytes(buf[(t + 4) as usize..(t + 8) as usize].try_into().unwrap());
        let tsz = tiff_type_size(typ);
        if tsz == 0 {
            return IfdWalk::Malformed(format!(
                "tag {tag} has unknown TIFF type {typ}"
            ));
        }
        let size = match tsz.checked_mul(count as u64) {
            Some(s) => s,
            None => {
                return IfdWalk::Malformed(format!(
                    "tag {tag} value size is implausible (type {typ} count {count})"
                ))
            }
        };
        let value = if size <= 4 {
            // In-line (the IFD bounds above guarantee value_off..+4).
            buf[(t + 8) as usize..((t + 8) + size) as usize].to_vec()
        } else {
            if (t + 8) + 4 > buf.len() as u64 {
                return if (t + 8) + 4 > file_len {
                    IfdWalk::Malformed(format!(
                        "tag {tag} value field at {} is out of the file bounds ({} B)",
                        t + 8,
                        file_len
                    ))
                } else {
                    IfdWalk::OutOfWindow
                };
            }
            let p = u32::from_le_bytes(
                buf[(t + 8) as usize..(t + 12) as usize].try_into().unwrap(),
            ) as u64;
            if p + size > file_len {
                return IfdWalk::Malformed(format!(
                    "tag {tag} out-of-line pointer {p} + {size} B is out of the file bounds ({} B)",
                    file_len
                ));
            }
            if p + size > buf.len() as u64 {
                return IfdWalk::OutOfWindow;
            }
            buf[p as usize..(p + size) as usize].to_vec()
        };
        entries.push(IfdEntry { tag, typ, count, value });
    }
    IfdWalk::Entries(entries)
}

/// Read a (num, den) rational out of an 8-byte RATIONAL/SRATIONAL
/// value (two little-endian int32s). Names the corrupt/nonsense shape.
fn parse_rational_pair(value: &[u8], what: &str) -> Result<(u32, u32), String> {
    if value.len() != 8 {
        return Err(format!(
            "{what} value is {} byte(s), want 8 (a rational pair)",
            value.len()
        ));
    }
    let num = i32::from_le_bytes(value[0..4].try_into().unwrap());
    let den = i32::from_le_bytes(value[4..8].try_into().unwrap());
    if den <= 0 {
        return Err(format!("{what} is {num}/{den} — want a positive denominator"));
    }
    if num < 0 {
        return Err(format!("{what} is {num}/{den} — want a non-negative numerator"));
    }
    Ok((num as u32, den as u32))
}

enum MetaResolve {
    Found(FrameMetadata),
    Malformed(String),
    OutOfWindow,
}

/// Resolve the per-frame camera metadata out of the (possibly
/// windowed) header buffer: the IFD0 TimeCodes (51043 — the
/// BCD decode) + FrameRate (51044) + the ExifIFD (via 0x8769) ISO
/// speed ratings (34855) + exposure time (34853). The bounds
/// discipline is walk_ifd's (Malformed = corrupt, OutOfWindow = a full-
/// file re-read is needed); a present-but-wrong-shaped tag is a named
/// Malformed (a corrupt header is named, never passed).
fn resolve_frame_metadata(buf: &[u8], file_len: u64) -> MetaResolve {
    if buf.len() < 8 || file_len < 8 {
        return MetaResolve::Malformed(format!(
            "file is {} byte(s) — too small to be a TIFF (want 8+)",
            file_len.min(buf.len() as u64)
        ));
    }
    if &buf[0..4] != b"II*\0" {
        return MetaResolve::Malformed(
            "not a little-endian TIFF (want the II*\\0 magic at offset 0) — the fp's cDNG is little-endian".into(),
        );
    }
    let ifd0 = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as u64;
    let entries = match walk_ifd(buf, file_len, ifd0) {
        IfdWalk::Entries(e) => e,
        IfdWalk::Malformed(r) => return MetaResolve::Malformed(r),
        IfdWalk::OutOfWindow => return MetaResolve::OutOfWindow,
    };
    let mut meta = FrameMetadata::default();
    let mut exif: Option<Vec<IfdEntry>> = None;
    for e in &entries {
        match e.tag {
            TC_TAG => {
                // The contract: a byte type with count 8.
                if e.typ != 1 && e.typ != 2 && e.typ != 7 && e.typ != 11 {
                    return MetaResolve::Malformed(format!(
                        "TimeCodes (51043) is type {} count {} — want a byte type with count {TC_TAG_COUNT}",
                        e.typ, e.count
                    ));
                }
                if e.count != TC_TAG_COUNT {
                    return MetaResolve::Malformed(format!(
                        "TimeCodes (51043) is type {} count {} — want a byte type with count {TC_TAG_COUNT}",
                        e.typ, e.count
                    ));
                }
                meta.timecode = match parse_timecodes_field(&e.value) {
                    Ok(tc) => Some(tc),
                    Err(reason) => return MetaResolve::Malformed(reason),
                };
            }
            FRAME_RATE_TAG => {
                if e.typ != 5 && e.typ != 10 || e.count != 1 {
                    return MetaResolve::Malformed(format!(
                        "FrameRate (51044) is type {} count {} — want a rational with count 1",
                        e.typ, e.count
                    ));
                }
                match parse_rational_pair(&e.value, "FrameRate (51044)") {
                    Ok(r) => meta.framerate = Some(r),
                    Err(reason) => return MetaResolve::Malformed(reason),
                }
            }
            EXIF_IFD_TAG => {
                if e.typ != 4 || e.count != 1 {
                    return MetaResolve::Malformed(format!(
                        "ExifIFD pointer (0x8769) is type {} count {} — want a LONG with count 1",
                        e.typ, e.count
                    ));
                }
                let p = u32::from_le_bytes(e.value.as_slice().try_into().unwrap()) as u64;
                match walk_ifd(buf, file_len, p) {
                    IfdWalk::Entries(e2) => exif = Some(e2),
                    IfdWalk::Malformed(r) => {
                        return MetaResolve::Malformed(format!("ExifIFD (0x8769): {r}"))
                    }
                    IfdWalk::OutOfWindow => return MetaResolve::OutOfWindow,
                }
            }
            _ => {}
        }
    }
    if let Some(ex) = exif {
        for e in &ex {
            match e.tag {
                ISO_TAG => {
                    // The EXIF spec carriers: SHORT / SSHORT / LONG /
                    // SLONG (the fp: SHORT n=1). Rendered decimal,
                    // comma-joined for count > 1 (never a re-interpretation).
                    let mut vals: Vec<String> = Vec::with_capacity(e.count as usize);
                    match e.typ {
                        3 => {
                            for i in 0..e.count as usize {
                                vals.push(
                                    u16::from_le_bytes(e.value[i * 2..i * 2 + 2].try_into().unwrap())
                                        .to_string(),
                                );
                            }
                        }
                        8 => {
                            for i in 0..e.count as usize {
                                vals.push(
                                    i16::from_le_bytes(e.value[i * 2..i * 2 + 2].try_into().unwrap())
                                        .to_string(),
                                );
                            }
                        }
                        4 => {
                            for i in 0..e.count as usize {
                                vals.push(
                                    u32::from_le_bytes(e.value[i * 4..i * 4 + 4].try_into().unwrap())
                                        .to_string(),
                                );
                            }
                        }
                        9 => {
                            for i in 0..e.count as usize {
                                vals.push(
                                    i32::from_le_bytes(e.value[i * 4..i * 4 + 4].try_into().unwrap())
                                        .to_string(),
                                );
                            }
                        }
                        _ => {
                            return MetaResolve::Malformed(format!(
                                "ISOSpeedRatings (34855) is type {typ} count {count} — want SHORT/SSHORT/LONG/SLONG",
                                typ = e.typ, count = e.count
                            ))
                        }
                    }
                    if vals.is_empty() {
                        return MetaResolve::Malformed(
                            "ISOSpeedRatings (34855) has count 0".into(),
                        );
                    }
                    meta.iso = Some(vals.join(","));
                }
                EXPOSURE_TAG => {
                    if e.typ != 5 && e.typ != 10 || e.count != 1 {
                        return MetaResolve::Malformed(format!(
                            "ExposureTime (34853) is type {} count {} — want a rational with count 1",
                            e.typ, e.count
                        ));
                    }
                    match parse_rational_pair(&e.value, "ExposureTime (34853)") {
                        Ok(r) => meta.exposure = Some(r),
                        Err(reason) => return MetaResolve::Malformed(reason),
                    }
                }
                _ => {}
            }
        }
    }
    MetaResolve::Found(meta)
}

/// Read the per-frame camera metadata (tag 51043 TimeCodes, tag 51044
/// FrameRate, ExifIFD 34855 ISO / 34853 exposure time) from a DNG frame
/// file — the sidecar v3 columns . `Ok(meta)` = the
/// resolved metadata (an absent tag is a `None` field — the fixed
/// empty column, not an error); `Err(reason)` = a corrupt header or a
/// present-but-malformed tag (named — never a silent skip).
///
/// Reads a 512 KiB header window first (the fp's IFD0 + ExifIFD + every
/// out-of-line value ends < 79 KiB);
/// the full file is read ONLY when a value pointer falls outside the
/// window (the named fallback — never a silent skip). The window size
/// + fallback mirror `read_timecodes_tag` exactly.
pub fn read_frame_metadata(path: &Path) -> Result<FrameMetadata, String> {
    const WINDOW: u64 = 512 * 1024;
    let file_len = std::fs::metadata(path)
        .map_err(|err| format!("{}: metadata: {err}", path.display()))?
        .len();
    let mut file = std::fs::File::open(path)
        .map_err(|err| format!("{}: open: {err}", path.display()))?;
    let mut buf = vec![0u8; WINDOW.min(file_len) as usize];
    file.read_exact(&mut buf)
        .map_err(|err| format!("{}: read the header window: {err}", path.display()))?;
    match resolve_frame_metadata(&buf, file_len) {
        MetaResolve::Found(m) => Ok(m),
        MetaResolve::Malformed(reason) => Err(format!("{}: {reason}", path.display())),
        MetaResolve::OutOfWindow => {
            // Named fallback: a tag's value pointer lies beyond the
            // header window — read the rest of the file and re-resolve.
            eprintln!(
                "note: {} — a metadata value pointer beyond the 512 KiB header window; reading the full file",
                path.display()
            );
            file.seek(std::io::SeekFrom::Start(WINDOW.min(file_len)))
                .map_err(|err| format!("{}: seek: {err}", path.display()))?;
            file.read_to_end(&mut buf)
                .map_err(|err| format!("{}: read the full file: {err}", path.display()))?;
            match resolve_frame_metadata(&buf, file_len) {
                MetaResolve::Found(m) => Ok(m),
                MetaResolve::Malformed(reason) => Err(format!("{}: {reason}", path.display())),
                MetaResolve::OutOfWindow => Err(format!(
                    "{}: a metadata value is out of bounds even after the full-file read (corrupt header?)",
                    path.display()
                )),
            }
        }
    }
}

/// The frame number = the last `_`-separated field of the DNG file
/// stem, when that field is all digits (the fp naming pattern
/// `A001_001_20260701_000001.DNG` -> 1 — verified on the CINEMA batch).
/// `None` = not the fp pattern (the FRAME_BADNAME class — named, never
/// silently dropped).
pub fn frame_number_from_stem(stem: &str) -> Option<u64> {
    let field = stem.rsplit('_').next()?;
    if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    field.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::testutil::*;
    #[test]
    fn tc_parse_valid_and_malformed() {
        // The real A001_001 f1 value (FF 13, SS 51, MM 53, HH 22).
        let tc = parse_timecodes_field(&[0x13, 0x51, 0x53, 0x22, 0, 0, 0, 0]).unwrap();
        assert_eq!(tc, Smpte12m { hh: 22, mm: 53, ss: 51, ff: 13 });
        assert_eq!(tc.display(), "22:53:51:13");
        let tc2 = parse_timecodes_field(&[0x14, 0x51, 0x53, 0x22, 0, 0, 0, 0]).unwrap();
        assert_eq!(tc2.total_frames() - tc.total_frames(), 1); // the +1 step
        let wrap = parse_timecodes_field(&[0x00, 0x13, 0x00, 0x00, 0, 0, 0, 0]).unwrap();
        let pre = parse_timecodes_field(&[0x23, 0x12, 0x00, 0x00, 0, 0, 0, 0]).unwrap();
        assert_eq!(wrap.total_frames() - pre.total_frames(), 1); // 00:00:12:23 -> 00:00:13:00
        // Malformed: a non-BCD nibble / out-of-range fields / a short payload.
        assert!(parse_timecodes_field(&[0x5A, 0x51, 0x53, 0x22, 0, 0, 0, 0]).is_err()); // lo nibble 10
        assert!(parse_timecodes_field(&[0x25, 0x51, 0x53, 0x22, 0, 0, 0, 0]).is_err()); // ff 25 > 23
        assert!(parse_timecodes_field(&[0x13, 0x51, 0x53, 0x24, 0, 0, 0, 0]).is_err()); // hh 24 > 23
        assert!(parse_timecodes_field(&[0x13, 0x1F, 0x53, 0x22, 0, 0, 0, 0]).is_err()); // ss lo nibble 15
        assert!(parse_timecodes_field(&[0x13, 0x51]).is_err()); // short
    }

    #[test]
    fn frame_number_from_stem_named() {
        assert_eq!(frame_number_from_stem("A001_001_20260701_000001"), Some(1));
        assert_eq!(frame_number_from_stem("A001_007_20260914_000080"), Some(80));
        assert_eq!(frame_number_from_stem("x_000007"), Some(7));
        assert_eq!(frame_number_from_stem("A001_001_20260701_000000"), Some(0));
        assert_eq!(frame_number_from_stem("reference"), None);
        assert_eq!(frame_number_from_stem("A001_ref"), None);
        assert_eq!(frame_number_from_stem("A001_"), None);
    }

    #[test]
    fn read_timecodes_window_and_fallback() {
        let tmp = std::env::temp_dir().join(format!("frameprism-tc-window-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let tc = Smpte12m { hh: 1, mm: 2, ss: 3, ff: 4 };
        // The normal case: the value sits right after the IFD (in the window).
        let p1 = tmp.join("ok.DNG");
        std::fs::write(&p1, synthetic_dng(Some(&tc_payload(&tc)), 1, 8, None)).unwrap();
        assert_eq!(read_timecodes_tag(&p1).unwrap(), Some(tc));
        // The ABSENT case: an IFD with no 51043 entry.
        let p2 = tmp.join("absent.DNG");
        std::fs::write(&p2, synthetic_dng(None, 1, 8, None)).unwrap();
        assert_eq!(read_timecodes_tag(&p2).unwrap(), None);
        // The window-fallback case: the value pointer sits PAST the 512 KiB
        // window (a sparse zero file with the payload at 600 KiB).
        let p3 = tmp.join("far.DNG");
        std::fs::write(&p3, synthetic_dng(Some(&tc_payload(&tc)), 1, 8, Some(600 * 1024))).unwrap();
        assert_eq!(read_timecodes_tag(&p3).unwrap(), Some(tc));
        // The malformed cases: a wrong value size (LONG×1 = 4 B ≠ 8 B) +
        // a bad BCD payload. (LONG×2 is a LEGAL 8-byte carrier — not a
        // malformed case.)
        let p4 = tmp.join("badtype.DNG");
        std::fs::write(&p4, synthetic_dng(Some(&tc_payload(&tc)), 4, 1, None)).unwrap();
        assert!(matches!(read_timecodes_tag(&p4), Err(_)));
        let p5 = tmp.join("badbcd.DNG");
        std::fs::write(&p5, synthetic_dng(Some(&[0x5A, 0x51, 0x53, 0x22, 0, 0, 0, 0]), 1, 8, None)).unwrap();
        assert!(matches!(read_timecodes_tag(&p5), Err(_)));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn frame_metadata_full_absent_and_malformed() {
        let base = std::env::temp_dir().join(format!("frameprism-frame-meta-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        // Full: TC + FR + ExifIFD(ISO + exposure).
        let full = synth_tiff((2, 7, 3, 16), Some((24000, 1000)), Some(100), Some((1, 125)));
        let p1 = base.join("full.DNG");
        std::fs::write(&p1, full).unwrap();
        let m = read_frame_metadata(&p1).unwrap();
        assert_eq!(m.timecode, Some(Smpte12m { hh: 16, mm: 3, ss: 7, ff: 2 }));
        assert_eq!(m.framerate, Some((24000, 1000)));
        assert_eq!(m.iso, Some("100".into()));
        assert_eq!(m.exposure, Some((1, 125)));
        // Absent: TC only — the fixed-empty columns (never invented).
        let tc_only = synth_tiff((0, 0, 0, 0), None, None, None);
        let p2 = base.join("tconly.DNG");
        std::fs::write(&p2, tc_only).unwrap();
        let m = read_frame_metadata(&p2).unwrap();
        assert_eq!(m.timecode, Some(Smpte12m { hh: 0, mm: 0, ss: 0, ff: 0 }));
        assert!(m.framerate.is_none(), "absent tag = empty column");
        assert!(m.iso.is_none());
        assert!(m.exposure.is_none());
        // Malformed: the TC tag present with the wrong count → named.
        let bad = synthetic_dng(Some(&t4(0, 0, 0, 0)), 1, 4, None); // count 4, want 8
        let p3 = base.join("badcount.DNG");
        std::fs::write(&p3, bad).unwrap();
        let err = read_frame_metadata(&p3).unwrap_err();
        assert!(
            err.contains("TimeCodes (51043) is type 1 count 4") && err.contains("want a byte type with count 8"),
            "the named malformed reason: {err:?}"
        );
        // Malformed: not a TIFF at all → named.
        let p4 = base.join("notiff.DNG");
        std::fs::write(&p4, b"nope-nope-nope").unwrap();
        assert!(
            read_frame_metadata(&p4).unwrap_err().contains("not a little-endian TIFF"),
            "the named refusal: {:?}",
            read_frame_metadata(&p4).unwrap_err()
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn metadata_full_file_fallback_named() {
        // The 512 KiB window fallback: the TC value pointer lies beyond
        // the header window (a file > 512 KiB) — the reader names the
        // re-read and resolves from the full file (the resolve_tc
        // fallback, mirrored).
        let base = std::env::temp_dir().join(format!("frameprism-frame-meta-fallback-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let win: u64 = 512 * 1024;
        let val_off = win + 4096; // beyond the window, inside the file
        // header(8) + IFD0(count 2 + 1 entry 12 + next 4) = 26 bytes of
        // structure; zero-fill to val_off; the 8-byte TC value there.
        let mut b = vec![0u8; (val_off + 8) as usize];
        b[0..4].copy_from_slice(b"II*\0");
        b[4..8].copy_from_slice(&8u32.to_le_bytes());
        b[8..10].copy_from_slice(&1u16.to_le_bytes());
        b[10..12].copy_from_slice(&51043u16.to_le_bytes());
        b[12..14].copy_from_slice(&1u16.to_le_bytes()); // BYTE
        b[14..18].copy_from_slice(&8u32.to_le_bytes()); // n=8
        b[18..22].copy_from_slice(&(val_off as u32).to_le_bytes());
        b[22..26].copy_from_slice(&0u32.to_le_bytes());
        b[val_off as usize..(val_off + 8) as usize].copy_from_slice(&t4(5, 9, 1, 8));
        let p = base.join("far.DNG");
        std::fs::write(&p, b).unwrap();
        let m = read_frame_metadata(&p).unwrap(); // the named fallback path
        assert_eq!(m.timecode, Some(Smpte12m { hh: 5, mm: 9, ss: 1, ff: 8 }));
        assert!(m.framerate.is_none());
        let _ = std::fs::remove_dir_all(&base);
    }
}
