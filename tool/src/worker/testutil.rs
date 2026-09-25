//! The shared test helpers (the cfg(test) surface — the split's
//! test infrastructure).
//!
//! `bcd16` (the BCD nibble — the timecode field encoding) + `synth_tiff`
//! (the minimal synthetic LE TIFF — the camera-metadata fixtures) — the
//! cross-module test consumers (the crate `report` + `checksums` test
//! modules) reach them at `crate::worker::` (the mod.rs
//! `#[cfg(test)] pub use` re-exports — the external paths unchanged).
//! The in-module helpers (the camera-gate / the synthetic-DNG / the
//! synth-root / the clip fixtures) serve the part test modules (the
//! `use crate::worker::testutil::*;` idiom).

use std::path::{Path, PathBuf};

use super::checksums::Smpte12m;
use super::ingest::collect_dng_frames;
use super::report::ClipVerdict;

/// BCD-encode a 0..=99 value into a single byte (the TC layout:
/// the 51043 value bytes are BCD — hi nibble = tens, lo nibble = ones).
/// `#[cfg(test)]` + `pub`: the shared synth-TIFF helper (above) and the
/// report tests both build 51043 value bytes through this.
#[cfg(test)]
pub fn bcd16(v: u8) -> u8 {
    ((v / 10) << 4) | (v % 10)
}

/// The ExifIFD pointer tag (TIFF-EXIF; in the EXIF spec the tag is
/// 0x8769 "ExifImageDirectory" — the fp's 34855/34853 live in that
/// sub-IFD, not IFD0 (tag census)).
#[cfg(test)]
pub fn synth_tiff(
    tc: (u8, u8, u8, u8), // (ff, ss, mm, hh) — the BCD layout
    framerate: Option<(u32, u32)>, // (num, den)
    iso: Option<u16>,
    exposure: Option<(u32, u32)>, // (num, den)
) -> Vec<u8> {
    // Minimal LE TIFF for the v3 tests: IFD0 = [51043 (BYTE n=8)] +
    // optionally 51044 (SRATIONAL n=1) + optionally 0x8769 (inline
    // pointer) → ExifIFD = [34855 (SHORT n=1)] + optionally 34853
    // (SRATIONAL n=1). Values > 4 bytes are out-of-line (the parser's
    // bounds discipline exercised the same way either way).
    struct SynEntry {
        tag: u16,
        typ: u16,
        cnt: u32,
        val: Vec<u8>,
        ptr: u32,
    }
    let mut ifd0: Vec<SynEntry> = vec![SynEntry {
        tag: 51043,
        typ: 1,
        cnt: 8,
        val: {
            let (ff, ss, mm, hh) = tc;
            vec![bcd16(ff), bcd16(ss), bcd16(mm), bcd16(hh), 0, 0, 0, 0]
        },
        ptr: 0,
    }];
    if let Some((n, d)) = framerate {
        let mut v = Vec::new();
        v.extend_from_slice(&n.to_le_bytes());
        v.extend_from_slice(&d.to_le_bytes());
        ifd0.push(SynEntry { tag: 51044, typ: 10, cnt: 1, val: v, ptr: 0 });
    }
    let mut exif: Vec<SynEntry> = Vec::new();
    if let Some(v) = iso {
        exif.push(SynEntry { tag: 34855, typ: 3, cnt: 1, val: v.to_le_bytes().to_vec(), ptr: 0 });
    }
    if let Some((n, d)) = exposure {
        let mut v = Vec::new();
        v.extend_from_slice(&n.to_le_bytes());
        v.extend_from_slice(&d.to_le_bytes());
        exif.push(SynEntry { tag: 34853, typ: 5, cnt: 1, val: v, ptr: 0 });
    }
    let ifd0_off: u32 = 8;
    let ifd0_size = if exif.is_empty() {
        2 + ifd0.len() * 12 + 4
    } else {
        2 + (ifd0.len() + 1) * 12 + 4 // + the 0x8769 pointer entry
    };
    let exif_off: u32 = if exif.is_empty() { 0 } else { ifd0_off + ifd0_size as u32 };
    let exif_size = if exif.is_empty() { 0 } else { 2 + exif.len() * 12 + 4 };
    let area_start = ifd0_off + ifd0_size as u32 + exif_size as u32;
    let mut area = area_start;
    let mut assign = |e: &mut SynEntry| {
        if e.val.len() > 4 {
            e.ptr = area;
            area += e.val.len() as u32;
        }
    };
    for e in ifd0.iter_mut() {
        assign(e);
    }
    if !exif.is_empty() {
        ifd0.push(SynEntry {
            tag: 0x8769,
            typ: 4,
            cnt: 1,
            val: exif_off.to_le_bytes().to_vec(), // inline (4 bytes)
            ptr: 0,
        });
    }
    for e in exif.iter_mut() {
        assign(e);
    }
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"II*\0");
    b.extend_from_slice(&ifd0_off.to_le_bytes());
    b.extend_from_slice(&(ifd0.len() as u16).to_le_bytes());
    for e in &ifd0 {
        b.extend_from_slice(&e.tag.to_le_bytes());
        b.extend_from_slice(&e.typ.to_le_bytes());
        b.extend_from_slice(&e.cnt.to_le_bytes());
        if e.val.len() <= 4 {
            b.extend_from_slice(&e.val);
            b.extend_from_slice(&vec![0u8; 4 - e.val.len()]);
        } else {
            b.extend_from_slice(&e.ptr.to_le_bytes());
        }
    }
    b.extend_from_slice(&0u32.to_le_bytes());
    if !exif.is_empty() {
        b.extend_from_slice(&(exif.len() as u16).to_le_bytes());
        for e in &exif {
            b.extend_from_slice(&e.tag.to_le_bytes());
            b.extend_from_slice(&e.typ.to_le_bytes());
            b.extend_from_slice(&e.cnt.to_le_bytes());
            if e.val.len() <= 4 {
                b.extend_from_slice(&e.val);
                b.extend_from_slice(&vec![0u8; 4 - e.val.len()]);
            } else {
                b.extend_from_slice(&e.ptr.to_le_bytes());
            }
        }
        b.extend_from_slice(&0u32.to_le_bytes());
    }
    for e in ifd0.iter().chain(exif.iter()) {
        if e.val.len() > 4 {
            b.extend_from_slice(&e.val);
        }
    }
    b
}

    /// A fresh scratch input dir holding ONE synthetic DNG frame
    /// (the OPTION (a) fixture class — the camera.rs shared builder) +
    /// a sibling output dir. Returns (input, output, the base dir for
    /// the cleanup).
    pub fn camera_gate_fixture(tag: &str, name: &str, bytes: &[u8]) -> (PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("frameprism-camera-gate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let input = base.join("in");
        std::fs::create_dir_all(&input).unwrap();
        std::fs::write(input.join(name), bytes).unwrap();
        (input, base.join("out"), base)
    }

    ///: force the in-process profile set for the encode tests
    /// (the thread-safe stand-in for FRAMEPRISM_PROFILES — the process-
    /// global env is racy across parallel cargo tests; the production
    /// build never compiles the slot into the resolution). Writes the
    /// repo's A001 profile to a per-process temp file and sets the
    /// camera override (the content is the SAME for every caller —
    /// concurrent sets cannot skew each other).
    pub fn camera_profile_override() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let p = Path::new("../profiles/a001-sigma-fp.profile");
            let text = std::fs::read_to_string(p)
                .unwrap_or_else(|err| panic!("the A001 profile file must exist for the encode tests: {p:?}: {err}"));
            let dir = std::env::temp_dir().join(format!("frameprism-worker-camera-profile-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let f = dir.join("a001-sigma-fp.profile");
            std::fs::write(&f, text).unwrap();
            crate::camera::set_profile_override(Some(&f));
        });
    }

    /// Build a BCD payload from a Smpte12m (the fp's field order
    /// [FF, SS, MM, HH] + 4 NUL padding).
    pub fn bcd_of(v: u8) -> u8 {
        ((v / 10) << 4) | (v % 10)
    }
    pub fn tc_payload(t: &Smpte12m) -> [u8; 8] {
        [bcd_of(t.ff), bcd_of(t.ss), bcd_of(t.mm), bcd_of(t.hh), 0, 0, 0, 0]
    }

    /// Build a minimal little-endian TIFF "DNG" whose IFD0 carries ONE
    /// out-of-line entry. `tc = Some(payload)` → the entry is the
    /// TimeCodes tag 51043 (type 1, count 8); `None` → the entry is an
    /// unrelated tag (256, SHORT×1 in-line) so 51043 is ABSENT. `typ`/
    /// `count` override the TimeCodes entry's type/count (the
    /// TC_MALFORMED cases); `payload_off` moves the out-of-line value to
    /// a non-default file offset (the window-fallback case).
    pub fn synthetic_dng(tc: Option<&[u8; 8]>, typ: u16, count: u32, payload_off: Option<u64>) -> Vec<u8> {
        const IFD_OFF: u32 = 8;
        const N: u16 = 1;
        let struct_len = IFD_OFF as u64 + 2 + (N as u64) * 12 + 4;
        let def_off = struct_len;
        let off = payload_off.unwrap_or(def_off);
        let mut buf = vec![0u8; off.max(struct_len) as usize + 8];
        buf[0..4].copy_from_slice(b"II*\0");
        buf[4..8].copy_from_slice(&IFD_OFF.to_le_bytes());
        buf[8..10].copy_from_slice(&N.to_le_bytes());
        let et = 10; // the first entry at IFD_OFF + 2
        let (tag, t, c) = match tc {
            Some(_) => (51043u16, typ, count),
            None => (256u16, 3, 1), // an unrelated in-line tag
        };
        buf[et..et + 2].copy_from_slice(&tag.to_le_bytes());
        buf[et + 2..et + 4].copy_from_slice(&t.to_le_bytes());
        buf[et + 4..et + 8].copy_from_slice(&c.to_le_bytes());
        if tc.is_some() {
            buf[et + 8..et + 12].copy_from_slice(&(off as u32).to_le_bytes());
            buf[off as usize..off as usize + 8].copy_from_slice(tc.unwrap());
        }
        // next-IFD pointer (0).
        buf[10 + (N as usize) * 12..10 + (N as usize) * 12 + 4].copy_from_slice(&0u32.to_le_bytes());
        buf
    }

    /// A synthetic ingest root with the given per-clip frame plan. Each
    /// clip spec: (dir name, a list of (file-name, TC or None)); `None` =
    /// the 51043 tag absent. Returns the frame paths.
    pub fn synth_root(
        tmp: &Path,
        clips: &[(&str, Vec<(&str, Option<Smpte12m>)>)],
        manifest: Option<&str>,
    ) -> Vec<PathBuf> {
        let _ = std::fs::remove_dir_all(tmp);
        for (dir, frames) in clips {
            let d = tmp.join(dir);
            std::fs::create_dir_all(&d).unwrap();
            for (name, tc) in frames {
                let payload = tc.map(|t| tc_payload(&t));
                let bytes = match payload {
                    Some(p) => synthetic_dng(Some(&p), 1, 8, None),
                    None => synthetic_dng(None, 1, 8, None),
                };
                std::fs::write(d.join(name), bytes).unwrap();
            }
        }
        if let Some(m) = manifest {
            std::fs::write(tmp.join("manifest.tsv"), m).unwrap();
        }
        collect_dng_frames(tmp).unwrap()
    }

    pub fn t(t: u8, m: u8, s: u8, f: u8) -> Smpte12m {
        Smpte12m { hh: t, mm: m, ss: s, ff: f }
    }

    pub fn t4(hh: u8, mm: u8, ss: u8, ff: u8) -> [u8; 8] {
        [ff, ss, mm, hh, 0, 0, 0, 0]
    }

    /// A synthetic ClipVerdict for the pure reel_check tests.
    pub fn synth_clip(clip: &str, tc_first: Option<(u8, u8, u8, u8)>, tc_last: Option<(u8, u8, u8, u8)>) -> ClipVerdict {
        let abs = |t: (u8, u8, u8, u8)| Smpte12m { hh: t.0, mm: t.1, ss: t.2, ff: t.3 }.total_frames();
        let disp = |t: (u8, u8, u8, u8)| Smpte12m { hh: t.0, mm: t.1, ss: t.2, ff: t.3 }.display();
        ClipVerdict {
            clip: clip.into(),
            frames_found: 2,
            manifest_declared: None,
            frame_range: Some((1, 2)),
            tc_start: tc_first.map(disp),
            tc_end: tc_last.map(disp),
            tc_first_frames: tc_first.map(abs),
            tc_last_frames: tc_last.map(abs),
            failures: Vec::new(),
        }
    }
