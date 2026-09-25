//! Minimal DNG/TIFF IFD parser over an immutable byte slice.
//!
//! Parses the Sigma fp uncompressed cDNG layout (verified on clip
//! A001_001 — see the project
//!   [0 .. strip_start)    header: IFD0 (58 tags) + ExifIFD + all metadata
//!   [strip_start .. end)  single uncompressed 12-bit packed strip
//!   [end .. file end)     zero tail (optional)
//!
//! The parser ALSO enforces the surgery invariant (see `surgery.rs`):
//! single strip, every out-of-line region (recursing into ExifIFD/GPSIFD/
//! InteropIFD) ends before the strip start, no SubIFD, zero tail. A frame
//! that violates the invariant is REFUSED, not processed.
//!
//! Design notes:
//! - Total-safe on untrusted input: every read bounds-checked, typed errors,
//!   no panics. `read`/`read_meta` are the cargo-fuzz target
//!   (`tool/fuzz/fuzz_targets/tiff_parse.rs`).
//! - `read` (the frame-accepting parser) is little-endian-only by design:
//!   the surgery emitters write LE, so MM (big-endian) frames are refused at
//!   parse time (`NotLittleEndian`) rather than re-emitted mixed-endian.
//! - Writing lives in `surgery` (byte replacement), not here.
//! - The raw strip is 12-bit packed (big-endian word, MSB-first — see
//!   `pack12.rs`); this module passes the packed bytes through untouched.

use std::ops::Range;

use thiserror::Error;

/// TIFF field sizes for known types.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum ParseError {
    #[error("not a TIFF file (bad magic; first 4 bytes: {0:?})")]
    NotTiff(Vec<u8>),
    #[error("big-endian (MM) TIFF: not supported — the surgery emitters are little-endian; convert to II (little-endian) first")]
    NotLittleEndian,
    #[error("IFD at offset {0} out of bounds (file {1} bytes)")]
    BadIfdOffset(u64, u64),
    #[error("implausible IFD tag count {0} at offset {1}")]
    ImplausibleCount(u32, u64),
    #[error("IFD structure at offset {0} out of bounds")]
    IfdStructureOutOfBounds(u64),
    #[error("unknown TIFF field type {0} for tag {1}")]
    UnknownFieldType(u16, u16),
    #[error("out-of-bounds value region for tag {tag} (0x{tag:04X}): [{start}..{end}) in file of {file_size} bytes")]
    RegionOutOfBounds {
        tag: u16,
        start: u64,
        end: u64,
        file_size: u64,
    },
    #[error("missing required tag {tag} (0x{tag:04X}, {name})")]
    MissingTag { tag: u16, name: &'static str },
    #[error("input must be uncompressed (Compression={0})")]
    NotUncompressed(u16),
    #[error("unsupported PhotometricInterpretation {0} (need 32803 = CFA)")]
    NotCfa(u16),
    #[error("unsupported SamplesPerPixel {0} (need 1)")]
    NotSingleSample(u16),
    #[error("unsupported BitsPerSample {0} (8/10/12 supported)")]
    UnsupportedBps(u16),
    #[error("tile-based input not supported (tag 322/323 present)")]
    TiledInput,
    #[error("multiple strips (count={0}); MVP supports single-strip frames")]
    MultiStrip(u32),
    #[error("DNG SubIFD (51328) present; unsupported in MVP")]
    SubIfdPresent,
    #[error("RowsPerStrip {0} != image height {1} (multi-strip)")]
    RowsPerStripMismatch(u32, u32),
    #[error("odd pixel count {0}; 12-bit packing requires even width*height")]
    OddPixelCount(u64),
    #[error("10-bit input with width {0} (not a multiple of 4): the DNG per-row 10-bit bitstream must end on a byte boundary (width*10 bits must be a multiple of 8)")]
    Bps10WidthMisaligned(u32),
    #[error("strip length {actual} B inconsistent with {w}x{h} 12-bit packed (expected {expected} B + small padding)")]
    StripLenMismatch {
        w: u32,
        h: u32,
        expected: u64,
        actual: u64,
    },
    #[error("strip [{start}..{end}) out of bounds (file {file_size} bytes)")]
    StripOutOfBounds {
        start: u64,
        end: u64,
        file_size: u64,
    },
    #[error("out-of-line value for tag {tag} (0x{tag:04X}) ends at {end}, at/past strip start {strip_start}")]
    MetadataOverlapsStrip {
        tag: u16,
        end: u64,
        strip_start: u64,
    },
    #[error("non-zero tail: {0} bytes after strip must be zero")]
    NonZeroTail(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    pub fn u16(self, b: &[u8]) -> u16 {
        let a = b;
        match self {
            Endian::Little => u16::from_le_bytes([a[0], a[1]]),
            Endian::Big => u16::from_be_bytes([a[0], a[1]]),
        }
    }
    pub fn u32(self, b: &[u8]) -> u32 {
        match self {
            Endian::Little => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            Endian::Big => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        }
    }
    /// Write a 16-bit value at `off` (used by surgery; file-absolute offset).
    pub fn put_u16(self, buf: &mut [u8], off: u64, v: u16) {
        let b = match self {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        buf[off as usize..off as usize + 2].copy_from_slice(&b);
    }
    /// Write a 32-bit value at `off` (used by surgery; file-absolute offset).
    pub fn put_u32(self, buf: &mut [u8], off: u64, v: u32) {
        let b = match self {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        buf[off as usize..off as usize + 4].copy_from_slice(&b);
    }
}

/// One out-of-line tag value region (or an IFD structure) inside the header.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    /// Tag id; 0 marks an IFD structure (sub-IFD tables), not a tag value.
    pub tag: u16,
    pub start: u64,
    pub end: u64,
}

/// One IFD entry as stored in the file (value field verbatim).
/// Used by the tile surgery (`surgery::apply_tiled`), which re-emits IFD
/// tables with shifted pointers, and by `read_meta` (metadata comparison
/// of output files, which the strip-layout `read` refuses by design).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IfdEntry {
    pub tag: u16,
    pub typ: u16,
    pub count: u32,
    /// The raw 4-byte value field (inline value bytes, or a file pointer
    /// when the value is out-of-line).
    pub value_raw: [u8; 4],
    /// Out-of-line value range (ptr, end); None = inline (<= 4 bytes).
    pub out_of_line: Option<(u64, u64)>,
}

/// A full IFD table (entry count, entries, next-IFD pointer) at a known
/// file offset.
#[derive(Clone, Debug)]
pub struct IfdTable {
    /// File offset of the 16-bit entry-count word.
    pub off: u64,
    /// Byte range of the IFD structure (count + entries + next pointer).
    pub struct_range: Range<u64>,
    pub entries: Vec<IfdEntry>,
    pub next_ifd: u32,
}

/// Generic frame metadata (IFD0 + sub-IFDs) without the strip-layout
/// invariants — used to verify the TILE-mode output, whose IFD table grew
/// by one entry (273/278/279 out, 322-325 in) and whose out-of-line data
/// shifted by 12 bytes; position-independent content comparison.
#[derive(Clone, Debug)]
pub struct Meta {
    pub endianness: Endian,
    pub ifd0: IfdTable,
    /// Sub-IFD tables (ExifIFD 34665, GPSIFD 34853, InteropIFD 40095),
    /// in pointer order.
    pub sub_ifds: Vec<IfdTable>,
}

/// Tags whose value is a file offset into a sub-IFD (ExifIFD 34665,
/// GPSInfo 34853, InteropIFD 40095, SubIFDs 330) in the TIFF types the
/// corpus carries them in: LONG (4), IFD (12), IFD8 (13) or SLOFFSET (14).
/// The Sigma fp file carries ExifIFD as **type 4 count 1, not type 12** —
/// a type-12-only check missed the fp Exif sub-IFD entirely (stale 34665
/// in every tile-mode output; discovered via the LibRaw open
/// failure on the log10+downscale2x frame, whose garbage-sub-IFD walk hit
/// the LIBRAW_IOSPACE_CHECK EOF guard). 14 (SLOFFSET, TIFF C14) is a legal
/// 8-byte offset type for the same tags.
pub fn is_ifd_pointer(typ: u16, tag: u16) -> bool {
    matches!(typ, 4 | 12 | 13 | 14) && matches!(tag, 330 | 34665 | 34853 | 40095)
}

/// A parsed fp cDNG frame, ready for surgery.
pub struct Frame {
    pub endianness: Endian,
    pub width: u32,
    pub height: u32,
    pub bits_per_sample: u16,
    pub compression: u16,
    /// File offset of the single raw strip.
    pub strip_offset: u64,
    /// Byte count of the single raw strip.
    pub strip_count: u64,
    pub strip_range: Range<u64>,
    /// Every out-of-line region (recursive over Exif/GPS/Interop IFDs) plus
    /// IFD structures. All end before `strip_offset` (checked).
    pub regions: Vec<Region>,
    /// File offset of the in-line 2-byte value of tag 259 (Compression).
    pub compression_value_offset: u64,
    /// File offset of the in-line 4-byte value of tag 279 (StripByteCounts).
    pub strip_count_value_offset: u64,
    /// Full IFD0 table (verbatim entries) — needed by the tile surgery to
    /// re-emit the table with shifted pointers.
    pub ifd0: IfdTable,
    /// Sub-IFD tables (Exif/GPS/Interop), in pointer order.
    pub sub_ifds: Vec<IfdTable>,
    /// End (exclusive) of the last out-of-line region in the header — the
    /// data blob the tile surgery shifts as one piece.
    pub data_end: u64,
    pub file_size: u64,
}

impl Frame {
    /// The 12-bit packed strip as a byte slice of the source buffer.
    pub fn strip_slice<'a>(&self, src: &'a [u8]) -> &'a [u8] {
        &src[self.strip_range.start as usize..self.strip_range.end as usize]
    }
}

struct Entry {
    tag: u16,
    typ: u16,
    count: u32,
    /// File offset of the 4-byte value field (t+8).
    value_offset: u64,
    /// Data location: None = in-line (in the value field), Some = out-of-line.
    data: Option<(u64, u64)>,
}

/// TIFF base type sizes (TIFF C14 numbering, per LibRaw's tiff.cpp):
/// 12 IFD = 4 (a LONG), 13 IFD8 / 14 SLOFFSET / 15 DOUBLE / 16 LONG8 /
/// 17 SLONG8 = 8, 18 RATIONAL8 = 16. (The pre-C14 map had 12→8 and
/// 14→4, which would mis-size IFD8/SLOFFSET entries and misclassify a
/// count-1 IFD entry as out-of-line.)
fn type_size(typ: u16) -> Result<u32, ParseError> {
    Ok(match typ {
        1 | 2 | 6 | 7 => 1,                   // BYTE, ASCII, SBYTE, UNDEFINED
        3 | 8 => 2,                           // SHORT, SSHORT
        4 | 9 | 11 | 12 => 4,                 // LONG, SLONG, (11 unused), IFD
        5 | 10 | 13 | 14 | 15 | 16 | 17 => 8, // RATIONAL, SRATIONAL, IFD8, SLOFFSET, DOUBLE, LONG8, SLONG8
        18 => 16,                             // RATIONAL8
        _ => return Err(ParseError::UnknownFieldType(typ, 0)),
    })
}

/// Read one IFD; returns its entries + the IFD structure's byte range.
fn read_ifd(bytes: &[u8], off: u64, e: Endian) -> Result<(Vec<Entry>, Range<u64>), ParseError> {
    let len = bytes.len() as u64;
    if off + 2 > len {
        return Err(ParseError::BadIfdOffset(off, len));
    }
    let n = e.u16(&bytes[off as usize..off as usize + 2]) as u64;
    if n == 0 || n > 512 {
        return Err(ParseError::ImplausibleCount(n as u32, off));
    }
    let struct_start = off;
    let struct_end = off + 2 + n * 12 + 4;
    if struct_end > len {
        return Err(ParseError::IfdStructureOutOfBounds(off));
    }
    let mut entries = Vec::with_capacity(n as usize);
    for i in 0..n {
        let t = off + 2 + i * 12;
        let tag = e.u16(&bytes[t as usize..t as usize + 2]);
        let typ = e.u16(&bytes[t as usize + 2..t as usize + 4]);
        let count = e.u32(&bytes[t as usize + 4..t as usize + 8]);
        let value_offset = t + 8;
        let tsz = type_size(typ).map_err(|_| ParseError::UnknownFieldType(typ, tag))? as u64;
        let sz = tsz
            .checked_mul(count as u64)
            .ok_or(ParseError::ImplausibleCount(count, off))?;
        let data = if sz <= 4 {
            None // in-line
        } else {
            let p = e.u32(&bytes[value_offset as usize..value_offset as usize + 4]) as u64;
            if p + sz > len {
                return Err(ParseError::RegionOutOfBounds {
                    tag,
                    start: p,
                    end: p + sz,
                    file_size: len,
                });
            }
            Some((p, p + sz))
        };
        entries.push(Entry {
            tag,
            typ,
            count,
            value_offset,
            data,
        });
    }
    Ok((entries, struct_start..struct_end))
}

/// Map a parsed entry list to the verbatim `IfdTable` form (value fields as
/// stored, plus the next-IFD pointer after the entry array).
fn to_ifd_table(
    bytes: &[u8],
    off: u64,
    e: Endian,
    entries: &[Entry],
    struct_range: Range<u64>,
) -> IfdTable {
    let entries = entries
        .iter()
        .map(|en| IfdEntry {
            tag: en.tag,
            typ: en.typ,
            count: en.count,
            value_raw: bytes[en.value_offset as usize..en.value_offset as usize + 4]
                .try_into()
                .unwrap(),
            out_of_line: en.data,
        })
        .collect();
    let next_ifd = e.u32(&bytes[(struct_range.end - 4) as usize..struct_range.end as usize]);
    IfdTable {
        off,
        struct_range,
        entries,
        next_ifd,
    }
}

pub fn read(bytes: &[u8]) -> Result<Frame, ParseError> {
    let len = bytes.len() as u64;
    if len < 8 {
        return Err(ParseError::NotTiff(bytes[..len.min(4) as usize].to_vec()));
    }
    let e = match &bytes[0..4] {
        b"II*\0" => Endian::Little,
        b"MM\0*" => {
            // Refuse big-endian at parse time (review: the surgery /
            // log10 / lossy / verify emitters are little-endian, so an MM
            // frame parsed here would be re-emitted with a mixed-endian IFD.
            // `read_meta` (output comparison only) stays lenient).
            return Err(ParseError::NotLittleEndian);
        }
        other => return Err(ParseError::NotTiff(other[..4].to_vec())),
    };
    let ifd0_off = e.u32(&bytes[4..8]) as u64;
    let (entries, ifd0_struct) = read_ifd(bytes, ifd0_off, e)?;
    let ifd0 = to_ifd_table(bytes, ifd0_off, e, &entries, ifd0_struct.clone());

    // --- collect out-of-line regions, recursing into IFD pointers ----------
    let mut regions: Vec<Region> = Vec::new();
    regions.push(Region {
        tag: 0,
        start: ifd0_struct.start,
        end: ifd0_struct.end,
    });
    let mut sub_ifds: Vec<IfdTable> = Vec::new();
    let mut stack: Vec<u64> = Vec::new();
    for en in &entries {
        if let Some((s, e2)) = en.data {
            regions.push(Region {
                tag: en.tag,
                start: s,
                end: e2,
            });
        }
        if is_ifd_pointer(en.typ, en.tag) {
            // IFD pointers (Exif / GPS / Interop / SubIFDs): queue each target.
            let base = match en.data {
                Some((p, _)) => p,
                None => en.value_offset,
            };
            for j in 0..en.count as u64 {
                let po = e.u32(&bytes[(base + j * 4) as usize..(base + j * 4 + 4) as usize]) as u64;
                if po > 0 {
                    stack.push(po);
                }
            }
        }
    }
    while let Some(off) = stack.pop() {
        let (sub_entries, sub_struct) = read_ifd(bytes, off, e)?;
        regions.push(Region {
            tag: 0,
            start: sub_struct.start,
            end: sub_struct.end,
        });
        sub_ifds.push(to_ifd_table(bytes, off, e, &sub_entries, sub_struct));
        for en in &sub_entries {
            if let Some((s, e2)) = en.data {
                regions.push(Region {
                    tag: en.tag,
                    start: s,
                    end: e2,
                });
            }
            if is_ifd_pointer(en.typ, en.tag) {
                let base = match en.data {
                    Some((p, _)) => p,
                    None => en.value_offset,
                };
                for j in 0..en.count as u64 {
                    let po =
                        e.u32(&bytes[(base + j * 4) as usize..(base + j * 4 + 4) as usize]) as u64;
                    if po > 0 {
                        stack.push(po);
                    }
                }
            }
        }
    }

    // --- structural refusals (cheap, specific errors) ----------------------
    for en in &entries {
        if en.tag == 51328 {
            return Err(ParseError::SubIfdPresent);
        }
        if en.tag == 322 || en.tag == 323 {
            return Err(ParseError::TiledInput);
        }
    }

    // --- required tags -----------------------------------------------------
    fn tag_int(entries: &[Entry], tag: u16, e: Endian, bytes: &[u8]) -> Option<u64> {
        let en = entries.iter().find(|en| en.tag == tag)?;
        match en.typ {
            3 => {
                let base = en.data.map(|(p, _)| p).unwrap_or(en.value_offset);
                Some(e.u16(&bytes[base as usize..base as usize + 2]) as u64)
            }
            4 => {
                let base = en.data.map(|(p, _)| p).unwrap_or(en.value_offset);
                Some(e.u32(&bytes[base as usize..base as usize + 4]) as u64)
            }
            _ => None,
        }
    }
    macro_rules! need {
        ($tag:expr, $name:expr) => {
            tag_int(&entries, $tag, e, bytes).ok_or(ParseError::MissingTag {
                tag: $tag,
                name: $name,
            })?
        };
    }
    let width = need!(256, "ImageWidth") as u32;
    let height = need!(257, "ImageLength") as u32;
    let bps = need!(258, "BitsPerSample") as u16;
    let compression = need!(259, "Compression") as u16;
    let photometric = need!(262, "PhotometricInterpretation") as u16;
    let spp = need!(277, "SamplesPerPixel") as u16;
    let strip_offsets = need!(273, "StripOffsets");
    let strip_counts = need!(279, "StripByteCounts");

    let comp_entry = entries.iter().find(|en| en.tag == 259).unwrap();
    let count_entry = entries.iter().find(|en| en.tag == 279).unwrap();
    let comp_count = comp_entry.count;
    let cnt_count = count_entry.count;

    // RowsPerStrip (optional) must equal the full height for a single strip.
    if let Some(rps) = tag_int(&entries, 278, e, bytes) {
        if rps as u32 != height {
            return Err(ParseError::RowsPerStripMismatch(rps as u32, height));
        }
    }

    // --- value checks ------------------------------------------------------
    if compression != 1 {
        return Err(ParseError::NotUncompressed(compression));
    }
    if photometric != 32803 {
        return Err(ParseError::NotCfa(photometric));
    }
    if spp != 1 {
        return Err(ParseError::NotSingleSample(spp));
    }
    if bps != 8 && bps != 10 && bps != 12 {
        return Err(ParseError::UnsupportedBps(bps));
    }
    if comp_count != 1 || cnt_count != 1 {
        return Err(ParseError::MultiStrip(comp_count.max(cnt_count)));
    }

    // --- strip geometry ----------------------------------------------------
    // Packing per precision (DNG-standard; 12-bit verified pixel-exact
    // against LibRaw — pack12.rs; 10-bit per the DNG SDK
    // dng_read_image::ReadUncompressed generic case — pack12.rs):
    //   12-bit: 2 samples per 3 bytes (1.5 B/px), big-endian word,
    //           MSB-first — even pixel count required (2-sample packing)
    //   10-bit: per-row big-endian bitstream, samples MSB-first
    //           (1.25 B/px = 4 samples per 5 bytes; the row ends on a
    //           byte boundary when width is a multiple of 4 — both of
    //           the fp's readouts: 3856, 1936)
    //   8-bit:  1 B per sample — any pixel count
    let pixels = (width as u64) * (height as u64);
    if bps == 12 && pixels % 2 != 0 {
        return Err(ParseError::OddPixelCount(pixels));
    }
    if bps == 10 && width % 4 != 0 {
        return Err(ParseError::Bps10WidthMisaligned(width));
    }
    let expected = match bps {
        8 => pixels,
        10 => pixels * 5 / 4,
        _ => pixels * 3 / 2, // 12
    };
    let strip_offset = strip_offsets;
    let strip_count = strip_counts;
    // Pad tolerance: the camera emits a small end-of-strip pad (measured
    // on the CINEMA batch, fp firmware Ver.5.02.0.V91): +12 B
    // on 10- and 12-bit (both geometries), +8 B on 8-bit. The 12-bit rule
    // ADDITIONALLY requires the pad to be a whole number of 3-byte groups
    // (%3) — byte-identical to the original contract. NOTE: the 10/8-bit
    // pads are NOT group-aligned (the 10-bit row is a bitstream: 12 B =
    // 3 samples + 4 bits of the next row's first byte… in practice the
    // pad is camera-side alignment, not a packing artifact), so NO mod
    // constraint is applied to them — do NOT port one by analogy. The
    // bit-exact round-trip gate (verify) is the real mis-parse
    // protection; the <= 64 B tolerance catches structural drift. A
    // stricter 10/8-bit pad rule can be added when more camera data
    // exists.
    let pad_ok = match bps {
        12 => (strip_count - expected) % 3 == 0,
        _ => true, // 8/10-bit: the measured pads are not group-multiple
    };
    if strip_count < expected || strip_count - expected > 64 || !pad_ok {
        return Err(ParseError::StripLenMismatch {
            w: width,
            h: height,
            expected,
            actual: strip_count,
        });
    }
    let strip_end = strip_offset + strip_count;
    if strip_end > len {
        return Err(ParseError::StripOutOfBounds {
            start: strip_offset,
            end: strip_end,
            file_size: len,
        });
    }

    // --- surgery invariant: all header regions end before the strip -------
    for r in &regions {
        if r.end > strip_offset {
            return Err(ParseError::MetadataOverlapsStrip {
                tag: r.tag,
                end: r.end,
                strip_start: strip_offset,
            });
        }
    }

    // --- zero tail ----------------------------------------------------------
    for &b in &bytes[strip_end as usize..] {
        if b != 0 {
            return Err(ParseError::NonZeroTail(len - strip_end));
        }
    }

    Ok(Frame {
        endianness: e,
        width,
        height,
        bits_per_sample: bps,
        compression,
        strip_offset,
        strip_count,
        strip_range: strip_offset..strip_end,
        regions: regions.clone(),
        compression_value_offset: comp_entry.value_offset,
        strip_count_value_offset: count_entry.value_offset,
        ifd0,
        sub_ifds,
        data_end: regions
            .iter()
            .map(|r| r.end)
            .max()
            .unwrap_or(ifd0_struct.end),
        file_size: len,
    })
}

/// Generic metadata parse (IFD0 + Exif/GPS/Interop sub-IFDs) WITHOUT the
/// strip-layout invariants of `read`: no Compression/strip/tile checks.
/// This is what `verify::metadata_preserved_tiled` uses to compare the
/// tile-mode output (whose IFD table legitimately differs) against the
/// source, tag by tag.
pub fn read_meta(bytes: &[u8]) -> Result<Meta, ParseError> {
    let len = bytes.len() as u64;
    if len < 8 {
        return Err(ParseError::NotTiff(bytes[..len.min(4) as usize].to_vec()));
    }
    let e = match &bytes[0..4] {
        b"II*\0" => Endian::Little,
        b"MM\0*" => Endian::Big,
        other => return Err(ParseError::NotTiff(other[..4].to_vec())),
    };
    let ifd0_off = e.u32(&bytes[4..8]) as u64;
    let (entries, ifd0_struct) = read_ifd(bytes, ifd0_off, e)?;
    let ifd0 = to_ifd_table(bytes, ifd0_off, e, &entries, ifd0_struct);

    let mut sub_ifds: Vec<IfdTable> = Vec::new();
    let mut stack: Vec<u64> = Vec::new();
    for en in &entries {
        if is_ifd_pointer(en.typ, en.tag) {
            let base = match en.data {
                Some((p, _)) => p,
                None => en.value_offset,
            };
            for j in 0..en.count as u64 {
                let po = e.u32(&bytes[(base + j * 4) as usize..(base + j * 4 + 4) as usize]) as u64;
                if po > 0 {
                    stack.push(po);
                }
            }
        }
    }
    while let Some(off) = stack.pop() {
        let (sub_entries, sub_struct) = read_ifd(bytes, off, e)?;
        sub_ifds.push(to_ifd_table(bytes, off, e, &sub_entries, sub_struct));
        for en in &sub_entries {
            if is_ifd_pointer(en.typ, en.tag) {
                let base = match en.data {
                    Some((p, _)) => p,
                    None => en.value_offset,
                };
                for j in 0..en.count as u64 {
                    let po =
                        e.u32(&bytes[(base + j * 4) as usize..(base + j * 4 + 4) as usize]) as u64;
                    if po > 0 {
                        stack.push(po);
                    }
                }
            }
        }
    }

    Ok(Meta {
        endianness: e,
        ifd0,
        sub_ifds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Load a real A001 frame from testdata (skip if the corpus is absent).
    fn testdata_frame(name: &str) -> Option<(Vec<u8>, u32, u32)> {
        let p = format!("../testdata/originals/A001_001/A001_001_20260701_{name}.DNG");
        match std::fs::read(&p) {
            Ok(b) => Some((b, 3856, 2170)),
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                None
            }
        }
    }

    #[test]
    fn real_a001_frame1_parses() {
        let (buf, w, h) = match testdata_frame("000001") {
            Some(x) => x,
            None => return,
        };
        let f = read(&buf).expect("frame 1 must parse");
        assert_eq!((f.width, f.height), (w, h));
        assert_eq!(f.bits_per_sample, 12);
        assert_eq!(f.compression, 1);
        assert_eq!(f.strip_offset, 78_848);
        assert_eq!(f.strip_count, 12_551_292);
        assert_eq!(f.file_size, 12_630_528);
        assert_eq!(f.strip_range, 78_848..12_630_140);
        assert!(f.compression_value_offset < f.strip_offset);
        assert!(f.strip_count_value_offset < f.strip_offset);
        // invariant: all regions before the strip
        assert!(f.regions.iter().all(|r| r.end <= f.strip_offset));
        assert!(!f.regions.is_empty());
    }

    #[test]
    fn real_a001_all_frames_parse() {
        let dir = std::path::Path::new("../testdata/originals/A001_001");
        if !dir.is_dir() {
            eprintln!("skip: no testdata corpus");
            return;
        }
        let mut n = 0u32;
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().and_then(|s| s.to_str()) != Some("DNG") {
                continue;
            }
            let buf = std::fs::read(&p).unwrap();
            let f = read(&buf).unwrap_or_else(|err| panic!("{} must parse: {err}", p.display()));
            assert_eq!(
                f.strip_offset,
                78_848,
                "{}: strip offset drift",
                p.display()
            );
            n += 1;
        }
        assert_eq!(n, 225, "expected 225 frames in A001_001");
    }

    #[test]
    fn rejects_truncated_header() {
        let (buf, _, _) = match testdata_frame("000001") {
            Some(x) => x,
            None => return,
        };
        let short = &buf[..100]; // mid-IFD
        assert!(matches!(
            read(short),
            Err(ParseError::IfdStructureOutOfBounds(_))
        ));
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(matches!(read(b"XXXX"), Err(ParseError::NotTiff(_))));
        assert!(matches!(read(&[]), Err(ParseError::NotTiff(_))));
    }

    #[test]
    fn rejects_big_endian() {
        // MM magic must be refused at parse time (review: the emitters
        // are little-endian, so accepting MM here would produce mixed-
        // endian IFDs. read_meta stays lenient (output comparison only)).
        let mm = [0x4D, 0x4D, 0x00, 0x2A, 0x08, 0x00, 0x00, 0x00];
        assert!(matches!(read(&mm), Err(ParseError::NotLittleEndian)));
        // read_meta accepts both endiannesses (output comparison only): the
        // 8-byte MM header above passes the magic check and fails only at
        // the IFD read — NOT as NotTiff/NotLittleEndian.
        assert!(matches!(read_meta(&mm), Err(ParseError::BadIfdOffset(..))));
    }

    #[test]
    fn type_sizes_c14() {
        // the pre-C14 map had 12→8 and 14→4; correct sizes:
        // 12 IFD = 4, 13 IFD8 / 14 SLOFFSET / 15 DOUBLE / 16 LONG8 /
        // 17 SLONG8 = 8, 18 RATIONAL8 = 16.
        for (typ, size) in [
            (1u16, 1u32),
            (2, 1),
            (3, 2),
            (4, 4),
            (5, 8),
            (6, 1),
            (7, 1),
            (8, 2),
            (9, 4),
            (11, 4),
            (12, 4),
            (13, 8),
            (14, 8),
            (15, 8),
            (16, 8),
            (17, 8),
            (18, 16),
        ] {
            assert_eq!(type_size(typ).unwrap(), size, "type {typ}");
        }
        assert!(type_size(19).is_err());
        // IFD-pointer recognition includes C14's SLOFFSET (14).
        assert!(is_ifd_pointer(14, 330));
        assert!(is_ifd_pointer(4, 34665));
        assert!(!is_ifd_pointer(5, 34665));
    }

    /// Truncated/garbage-input smoke (mini-fuzz; the real harness is
    /// `tool/fuzz/fuzz_targets/tiff_parse.rs` — cargo-fuzz + nightly).
    /// Neither parser may panic on any prefix of a real frame or on
    /// adversarial small inputs.
    #[test]
    fn fuzz_smoke_no_panic() {
        let garbage: Vec<u8> = vec![
            0u8, 1, 2, 3, 0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x49, 0x2A, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        for input in [
            &garbage[..],
            b"II*\0",
            b"II*\0\x00\x00\x00",
            b"MM\0*\x08\x00\x00\x00",
        ] {
            let _ = read(input);
            let _ = read_meta(input);
        }
        let (buf, _, _) = match testdata_frame("000001") {
            Some(x) => x,
            None => return, // corpus absent: garbage smoke above still ran
        };
        // Every truncation boundary of a real frame must be a typed error or
        // a parse, never a panic.
        for cut in [
            8usize,
            9,
            10,
            100,
            4096,
            78_847,
            78_848,
            78_849,
            1_000_000,
            buf.len() - 1,
        ] {
            if cut >= buf.len() {
                continue;
            }
            let _ = read(&buf[..cut]);
            let _ = read_meta(&buf[..cut]);
        }
        // A real full frame still parses.
        assert!(read(&buf).is_ok());
        assert!(read_meta(&buf).is_ok());
    }

    /// make the corpus dependency visible. A clean clone
    /// (testdata/ is gitignored) still passes `cargo test`, but the corpus
    /// tests are INERT there — this test prints that state so the gate's
    /// teeth are visible in the test output.
    #[test]
    fn corpus_presence_report() {
        let dir = std::path::Path::new("../testdata/originals/A001_001");
        if dir.is_dir() {
            let n = std::fs::read_dir(dir)
                .map(|it| {
                    it.filter_map(|e| e.ok())
                        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("DNG"))
                        .count()
                })
                .unwrap_or(0);
            eprintln!("[corpus] A001_001 present ({n} frames) — real_a001_* tests ACTIVE");
            assert!(n > 0, "corpus dir present but empty?");
        } else {
            eprintln!("[corpus] A001_001 MISSING — all real_a001_* corpus tests are SKIPPED (inert); cargo test is green without the corpus by design");
        }
    }

    #[test]
    fn rejects_nonzero_tail() {
        let (mut buf, _, _) = match testdata_frame("000001") {
            Some(x) => x,
            None => return,
        };
        *buf.last_mut().unwrap() = 0xFF; // corrupt the zero tail
        assert!(matches!(read(&buf), Err(ParseError::NonZeroTail(_))));
    }

    #[test]
    fn rejects_compressed_input() {
        let (mut buf, _, _) = match testdata_frame("000001") {
            Some(x) => x,
            None => return,
        };
        // Flip Compression (tag 259) from 1 to 7 in the in-line value.
        // Locate the IFD entry: walk IFD0 to find tag 259's value offset.
        let off = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        let n = u16::from_le_bytes([buf[off], buf[off + 1]]) as usize;
        let mut found = false;
        for i in 0..n {
            let t = off + 2 + i * 12;
            let tag = u16::from_le_bytes([buf[t], buf[t + 1]]);
            if tag == 259 {
                buf[t + 8] = 7;
                buf[t + 9] = 0;
                found = true;
                break;
            }
        }
        assert!(found);
        assert!(matches!(read(&buf), Err(ParseError::NotUncompressed(7))));
    }
}
