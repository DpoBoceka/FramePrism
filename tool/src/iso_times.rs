//! The pin-times pass : the post-build overwrite of the
//! 7-byte ECMA-119 record-date fields with the project pin.
//!
//! The in-process ISO writer (the pinned fstool `=0.4.33`) emits every
//! directory record's 7-byte date field (record offset 18) as hard
//! all-zeros and carries no Rock Ridge `TF` entries, so a raw build
//! mounts with 1970-01-01 on every entry (the measured gap — ).
//! This pass walks the on-disk directory records — the PVD + the Joliet
//! SVD descriptor-embedded root records (descriptor offset 156) + the
//! BFS over the directory extents — and overwrites each record's date
//! field IN PLACE with the pin's epoch in the pinned UTC encoding
//! (the maintainer's "epoch" decision: the stored instant is
//! machine-independent — the same patched bytes on every build machine,
//! in every TZ; the mounter renders the instant in its own local TZ).
//!
//! In-place fixed 7-byte overwrites only — no record moves, no extent
//! size changes, no path tables touched — the image bytes stay a pure
//! function of (staged content, label, the pinned epoch), so the project
//! `--iso` ×2 byte-identity culture holds on the patched output.
//!
//! The walk is ECMA-119 standard layout facts (stable since 1988 — a
//! property of the standard, not of the crate's internals). The only
//! crate-coupled assumption — "the date field is all-zeros" (the
//! pinned writer's current behavior) — is LOUD-ASSERTED: a non-zero
//! field is a hard stop with the pinned refusal (the writer changed —
//! re-pin before release), never a silent mispatch, never a skipped
//! field. A refusal writes NOTHING (all verification is a read phase;
//! the write phase runs only after every field verified).
//!
//! Bounded reads only (the 53 media-reads-bounded invariant): the pass
//! reads the two descriptor sectors + each directory extent (metadata,
//! KB-scale) via seek + read_exact — NEVER the whole image (a 4 GiB
//! image must not enter RAM — the hadris 2×-payload OOM class is the
//! class this swap exists to remove). No `std::fs::read` site.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::Context;

const SECTOR: u64 = 2048;
const PVD_LBA: u64 = 16;
const SVD_LBA: u64 = 17;
/// The descriptor-embedded root directory record's offset within the
/// PVD / the Joliet SVD (ECMA-119 §6.9 / the Joliet supplement — the
/// same 156 layout in both descriptors).
const DESC_ROOT_OFFSET: u64 = 156;
/// The record's 7-byte date field: record start + 18 (ECMA-119 §6.9 —
/// bytes 18..24, 7 bytes).
const DATE_OFFSET: u64 = 18;
const DATE_LEN: u64 = 7;
/// The record flags byte (record start + 25); 0x02 = the directory bit.
const DIR_FLAG: u8 = 0x02;
/// A record's length byte (record start + 0); 0 = the record extends
/// to the end of its sector.
///
/// A record never straddles a 2048 B sector boundary: a standard-
/// conforming writer pushes it to the next sector (the gap counting
/// against the extent), so a scan that honors the 4-byte minimum
/// record space (length byte + at least 3) walks the layout exactly.
///
/// The sector-rounding tail: the pinned writer sizes a directory
/// extent to WHOLE sectors (the records' sum, rounded up — its
/// `align_records_to_sector`), so the tail after the last
/// explicit-length record is all-zero padding inside the extent. The
/// scan's rule for a zero length byte at `pos`: if everything from
/// `pos` to the extent's end is zero, the record stream ENDS there
/// (the padding is not a record — no patch, no bail); otherwise a
/// real variable-length record is present (patch + continue at the
/// next sector, the standard's rule).
const LENGTH_BYTE: u64 = 0;

/// The 7-byte ECMA-119 record-date encoding of `epoch` (in UTC):
/// one binary byte each — `(year−1900, month, day, hour, minute,
/// second, 1/100 s)` — the encoding pinned from the project writer's own
/// bytes (/98 forensics). `epoch` 1789344000 (
/// 00:00:00 UTC) → exactly `7e 09 0e 00 00 00 00` (the named test
/// pins the literal against the computed value).
pub fn encode_record_date(epoch: u32) -> [u8; 7] {
    let days = (epoch / 86400) as i64;
    let secs = epoch % 86400;
    let (year, month, day) = civil_from_days(days);
    [
        (year - 1900) as u8,
        month as u8,
        day as u8,
        (secs / 3600) as u8,
        ((secs / 60) % 60) as u8,
        (secs % 60) as u8,
        0,
    ]
}

/// The civil calendar date of `days` since 1970-01-01 (the Howard
/// Hinnant civil_from_days algorithm — std-only, no datetime dep).
/// Returns (year, month 1..=12, day 1..=31).
fn civil_from_days(z0: i64) -> (i64, u32, u32) {
    let z = z0 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of era [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month index [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe as i64 + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// The inverse of [`encode_record_date`] (the test's round-trip
/// guard): the epoch the 7 bytes encode (the pure integer civil math
/// — no wall clock anywhere in the pass).
pub fn decode_record_date(bytes: &[u8; 7]) -> u32 {
    // The days-from-civil (the civil_from_days inverse — Hinnant):
    // the days since 1970-01-01 of (year, month, day).
    let y = i64::from(bytes[0]) + 1900;
    let yy = if bytes[1] <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = (yy - era * 400) as u64;
    let mp = if bytes[1] > 2 {
        (bytes[1] - 3) as u64
    } else {
        (bytes[1] + 9) as u64
    };
    let doy = (153 * mp + 2) / 5 + (bytes[2] as u64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    let secs = days * 86_400
        + (bytes[3] as i64) * 3600
        + (bytes[4] as i64) * 60
        + (bytes[5] as i64);
    secs as u32
}

fn read_at(file: &std::fs::File, offset: u64, len: u64) -> anyhow::Result<Vec<u8>> {
    let mut f = file.try_clone()?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len as usize];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// The descriptor (PVD or the Joliet SVD) at `lba`: verify the `CD001`
/// descriptor type (bytes 1..6), verify the descriptor-embedded root
/// record's date field is all-zeros (offset 156 + 18), and return the
/// root extent (lba, size). `Ok(None)` = the descriptor slot carries no
/// `CD001` (the Joliet SVD is absent — legitimate: the pass patches the
/// PVD only). The actual overwrite happens in the write phase (after
/// every field is verified).
fn patch_descriptor_root(
    file: &std::fs::File,
    lba: u64,
    sites: &mut Vec<u64>,
) -> anyhow::Result<Option<(u32, u32)>> {
    let sector = read_at(file, lba * SECTOR, SECTOR)?;
    if &sector[1..6] != b"CD001" {
        return Ok(None);
    }
    let rec = DESC_ROOT_OFFSET;
    let rec_len = u64::from(sector[rec as usize]);
    if rec_len < DATE_OFFSET + DATE_LEN {
        anyhow::bail!(
            "iso: pin-times pass: the {lba}-LBA descriptor's root record (offset {rec}) is {rec_len} B — too short for the 7-byte date field: the image is not the writer's output; re-pin"
        );
    }
    verify_zero_field(file, lba * SECTOR + rec + DATE_OFFSET)?;
    sites.push(lba * SECTOR + rec + DATE_OFFSET);
    let extent_lba = u32::from_le_bytes([
        sector[rec as usize + 2],
        sector[rec as usize + 3],
        sector[rec as usize + 4],
        sector[rec as usize + 5],
    ]);
    let extent_size = u32::from_le_bytes([
        sector[rec as usize + 10],
        sector[rec as usize + 11],
        sector[rec as usize + 12],
        sector[rec as usize + 13],
    ]);
    if extent_size == 0 {
        anyhow::bail!(
            "iso: pin-times pass: the root directory extent (the {lba}-LBA descriptor) has size 0: the image is not the writer's output; re-pin"
        );
    }
    Ok(Some((extent_lba, extent_size)))
}

/// The loud assert (the only crate-coupled assumption): the 7 bytes at
/// `offset` are ALL-ZERO (the pinned writer's current behavior) — a
/// non-zero field = the pinned VERBATIM refusal (a hard `Err`, never a
/// silent mispatch, never a skipped field).
fn verify_zero_field(file: &std::fs::File, offset: u64) -> anyhow::Result<()> {
    let field = read_at(file, offset, DATE_LEN)?;
    if field.iter().any(|b| *b != 0) {
        anyhow::bail!(
            "iso: pin-times pass: record date field not all-zeros at offset {offset} — the writer changed; re-pin before release"
        );
    }
    Ok(())
}

/// The BFS over one directory extent: patch every record's date field
/// (files + dirs + the dot records — the mounter reads every entry's
/// mtime from its directory record's base field when no RR `TF` is
/// present) and enqueue the sub-directory extents. EVERY directory
/// record is descended, dot records included: the dot records' extents
/// are themselves/parents, and the caller's visited set (consulted at
/// POP time) dedupes them — no name inspection. A name-based dot test
/// is unreliable here: the Joliet UCS-2 names carry the same leading
/// 0x00 byte as the single-byte dot forms (measured — it
/// misclassified every ASCII Joliet directory and left the Joliet
/// sub-tree unpatched).
fn patch_extent(
    file: &std::fs::File,
    extent_lba: u32,
    extent_size: u32,
    sites: &mut Vec<u64>,
    queue: &mut Vec<(u32, u32)>,
) -> anyhow::Result<()> {
    let base = extent_lba as u64 * SECTOR;
    let end = base + extent_size as u64;
    let mut pos = base;
    while pos < end {
        let sector_start = (pos / SECTOR) * SECTOR;
        // The 4-byte minimum record space: less than 4 bytes left in
        // the sector → the record (if any) starts at the next sector.
        if sector_start + SECTOR - pos < 4 {
            pos = sector_start + SECTOR;
            continue;
        }
        let sector = read_at(file, sector_start, SECTOR)?;
        let off = (pos - sector_start) as usize;
        let rec_len = u64::from(sector[off + LENGTH_BYTE as usize]);
        let eff = if rec_len == 0 {
            SECTOR - (pos - sector_start) // the variable-length record extends to the sector end
        } else {
            rec_len
        };
        if rec_len > 0 && eff > SECTOR - (pos - sector_start) {
            anyhow::bail!(
                "iso: pin-times pass: a record at offset {pos} straddles a sector boundary ({rec_len} B in {remaining} B left in the sector): the layout is not the writer's; re-pin",
                remaining = SECTOR - (pos - sector_start)
            );
        }
        if rec_len == 0 {
            // The zero-tail rule (the module doc): everything from `pos`
            // to the extent's end all zero → the record stream ENDS
            // (the writer's whole-sector padding is not a record — no
            // patch, no bail); otherwise a real variable-length record
            // (patch + continue at the next sector, the standard's rule).
            // Bounded, sector by sector (the extent is KB-scale
            // metadata — never the whole image).
            let mut all_zero = sector[off..].iter().all(|&b| b == 0);
            let mut p = sector_start + SECTOR;
            while all_zero && p < end {
                let n = SECTOR.min(end - p);
                let rest = read_at(file, p, n)?;
                all_zero = rest.iter().all(|&b| b == 0);
                p += n;
            }
            if all_zero {
                break;
            }
        }
        if eff >= DATE_OFFSET + DATE_LEN {
            verify_zero_field(file, pos + DATE_OFFSET)?;
            sites.push(pos + DATE_OFFSET);
        } else {
            anyhow::bail!(
                "iso: pin-times pass: a record at offset {pos} is {eff} B — too short for the 7-byte date field: the layout is not the writer's; re-pin"
            );
        }
        // The descent: the directory flag (record start + 25) — the
        // record's extent fields (lba at +2, size at +10). Every
        // directory record is enqueued (the doc above: the dot records
        // dedupe at pop time; no name inspection — the Joliet UCS-2
        // leading-0x00 byte collides with the dot forms).
        if eff > 33 && sector[off + 25] & DIR_FLAG != 0 {
            let lba = u32::from_le_bytes([
                sector[off + 2],
                sector[off + 3],
                sector[off + 4],
                sector[off + 5],
            ]);
            let size = u32::from_le_bytes([
                sector[off + 10],
                sector[off + 11],
                sector[off + 12],
                sector[off + 13],
            ]);
            // The visited set is consulted at POP time (the caller's
            // loop) — an enqueued extent is walked exactly once no
            // matter how many records point at it (incl. the dot
            // records' self/parent extents).
            queue.push((lba, size));
        }
        if rec_len == 0 {
            pos = sector_start + SECTOR;
        } else {
            pos += rec_len;
        }
    }
    Ok(())
}

/// The pass: after the fstool build + truncate, before the sidecar —
/// overwrite every directory record's 7-byte date field with the
/// `epoch` pin (the computed encoding — the named test pins the
/// literal against it). Returns the patched field count (the 2
/// descriptor-embedded roots + every on-disk record incl. the dot
/// records). See the module docs for the layout facts + the loud
/// assert + the bounded-read discipline.
pub fn pin_record_dates(image: &Path, epoch: u32) -> anyhow::Result<u32> {
    let patch = encode_record_date(epoch);
    let file = std::fs::File::open(image)
        .with_context(|| format!("iso: pin-times pass: open the image {}", image.display()))?;
    // The read phase (all verification — a refusal writes NOTHING):
    let mut sites: Vec<u64> = Vec::new();
    let root = patch_descriptor_root(&file, PVD_LBA, &mut sites)?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "iso: pin-times pass: no CD001 primary volume descriptor at LBA {PVD_LBA} ({}): the image is not the writer's output; re-pin",
                image.display()
            )
        })?;
    // The Joliet SVD (LBA 17) when present (the same 156 root-record
    // layout; absent = the PVD-only walk — the descriptor slot
    // carries the VDST instead). The SVD-embedded root record is
    // patched here, and its extent is the Joliet tree's OWN root
    // directory extent — a SEPARATE on-disk directory tree (the
    // supplement re-describes the layout with Joliet names; the
    // mounter prefers the Joliet tree when the SVD is present — the
    // mounted mtimes come from the Joliet records, so a PVD-only
    // walk leaves every mounted entry at 1970). Both extents seed
    // the BFS; the visited set walks each extent exactly once (the
    // writer's trees are disjoint; a shared extent — the handcrafted
    // fixture's case — dedupes to one walk).
    let svd_root = patch_descriptor_root(&file, SVD_LBA, &mut sites)?;
    let mut queue: Vec<(u32, u32)> = vec![root];
    if let Some(svd) = svd_root {
        queue.push(svd);
    }
    let mut visited: std::collections::HashSet<u32> = std::collections::HashSet::new();
    while let Some((lba, size)) = queue.pop() {
        if !visited.insert(lba) {
            continue; // already walked (the seed or a descent re-enqueued it)
        }
        patch_extent(&file, lba, size, &mut sites, &mut queue)?;
    }
    // The write phase (only after every field verified all-zeros):
    let mut out = std::fs::OpenOptions::new().write(true).open(image).with_context(|| {
        format!("iso: pin-times pass: open the image for writing {}", image.display())
    })?;
    for &site in &sites {
        out.seek(SeekFrom::Start(site))?;
        out.write_all(&patch)?;
    }
    Ok(sites.len() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The computed encoding == the pinned literal (guards the
    /// encoding itself — a civil-calendar or unit bug flips a byte
    /// here, not in the pass).
    #[test]
    fn record_date_encoding_matches_the_pinned_literal() {
        assert_eq!(encode_record_date(1_789_344_000), [0x7e, 0x09, 0x0e, 0, 0, 0, 0]);
        // The 1970 anchor: 0 → 1970-01-01 00:00:00 (year-1900 = 70).
        assert_eq!(encode_record_date(0), [70, 1, 1, 0, 0, 0, 0]);
        // The round-trip (the decode is the inverse — the pass's own
        // constant is the authority, the decode is the test's guard).
        for epoch in [0u32, 86_400, 1_789_344_000, 2_000_000_000] {
            assert_eq!(
                decode_record_date(&encode_record_date(epoch)),
                epoch,
                "the round-trip at {epoch}"
            );
        }
    }

    /// A minimal on-disk image the pass can walk: the PVD (LBA 16, the
    /// CD001 type + the root record at 156 with a known extent) + one
    /// directory sector (the root extent: the dot records + one file
    /// record) + one directory extent (the sub dir: the dot records +
    /// one file record) + a Joliet SVD (LBA 17, the same 156 root
    /// record — the writer always emits it when joliet is on). All
    /// date fields start ALL-ZERO (the writer's behavior the pass
    /// loud-asserts). The layout = the ECMA-119 standard facts the
    /// walk implements (a property of the standard, not of the
    /// writer): this fixture is the fixture, the writer's images are
    /// the production input (the bake-side named tests cover those).
    fn dir_record(extent_lba: u32, extent_size: u32, name: &[u8]) -> Vec<u8> {
        // The full 33-byte prefix + the name (+ even padding) — the
        // standard's minimum real record. The date field (18..25)
        // stays ZERO (the writer's all-zeros behavior).
        let padded = if name.len() % 2 == 0 { name.len() + 1 } else { name.len() };
        let mut rec = vec![0u8; 33 + padded];
        rec[0] = (33 + padded) as u8;
        rec[2..6].copy_from_slice(&extent_lba.to_le_bytes());
        rec[10..14].copy_from_slice(&extent_size.to_le_bytes());
        rec[25] = 0x02; // the directory flag
        rec[32] = name.len() as u8;
        rec[33..33 + name.len()].copy_from_slice(name);
        rec
    }
    fn file_record(extent_lba: u32, extent_size: u32, name: &[u8]) -> Vec<u8> {
        let padded = if name.len() % 2 == 0 { name.len() + 1 } else { name.len() };
        let mut rec = vec![0u8; 33 + padded];
        rec[0] = (33 + padded) as u8;
        rec[2..6].copy_from_slice(&extent_lba.to_le_bytes());
        rec[10..14].copy_from_slice(&extent_size.to_le_bytes());
        rec[25] = 0x00; // regular file
        rec[32] = name.len() as u8;
        rec[33..33 + name.len()].copy_from_slice(name);
        rec
    }
    fn sector_with(records: &[Vec<u8>]) -> Vec<u8> {
        let mut s = vec![0u8; SECTOR as usize];
        let mut pos = 0usize;
        for r in records {
            s[pos..pos + r.len()].copy_from_slice(r);
            // The 4-byte-minimum alignment the scan mirrors (the
            // writer's placement rule).
            pos += r.len();
            if SECTOR as usize - pos < 4 {
                pos = SECTOR as usize;
            }
        }
        s
    }
    /// Builds the minimal image (LBA 16 = the PVD · LBA 17 = the
    /// Joliet SVD · LBA 3 = the root dir extent · LBA 4 = the sub dir
    /// extent). Returns (the image path, the expected site offsets).
    /// The root extent (LBA 3): the dot records (names 0x00/0x01 —
    /// the root-extent form) + the `sub` dir record (→ LBA 4) + the
    /// `f1` file record. The sub extent (LBA 4): the dot records
    /// (names `.`/`..` — the non-root form) + the `f2` file record.
    /// Record lengths (the 33-byte prefix + the name + the even
    /// padding — 33 is odd, so the total is even): name 1 B → 34 ·
    /// 2 B → 36 · 3 B → 36.
    fn minimal_image(base: &Path) -> (std::path::PathBuf, Vec<u64>) {
        let pvd = {
            let mut s = vec![0u8; SECTOR as usize];
            s[1..6].copy_from_slice(b"CD001"); // the descriptor type
            let root = dir_record(3, SECTOR as u32, &[0x00]);
            s[156..156 + root.len()].copy_from_slice(&root);
            s
        };
        let svd = {
            let mut s = vec![0u8; SECTOR as usize];
            s[1..6].copy_from_slice(b"CD001"); // the Joliet SVD type
            let root = dir_record(3, SECTOR as u32, &[0x00]);
            s[156..156 + root.len()].copy_from_slice(&root);
            s
        };
        let root_extent = sector_with(&[
            dir_record(3, SECTOR as u32, &[0x00]), // the `.` (root form)
            dir_record(3, SECTOR as u32, &[0x01]), // the `..` (root form)
            dir_record(4, SECTOR as u32, b"sub"),
            file_record(10, 16, b"f1"),
        ]);
        let sub_extent = sector_with(&[
            dir_record(4, SECTOR as u32, b"."),
            dir_record(4, SECTOR as u32, b".."),
            file_record(11, 16, b"f2"),
        ]);
        let mut img = vec![0u8; 20 * SECTOR as usize]; // LBA 0..19 (the PVD/SVD at 16/17)
        img[(3 * SECTOR as usize)..(4 * SECTOR as usize)].copy_from_slice(&root_extent);
        img[(4 * SECTOR as usize)..(5 * SECTOR as usize)].copy_from_slice(&sub_extent);
        img[(16 * SECTOR as usize)..(17 * SECTOR as usize)].copy_from_slice(&pvd);
        img[(17 * SECTOR as usize)..(18 * SECTOR as usize)].copy_from_slice(&svd);
        let p = base.join("minimal.iso");
        std::fs::write(&p, &img).unwrap();
        // The expected site offsets: the PVD root field (16*2048+156+18)
        // + the SVD root field (17*2048+156+18) + the root extent's
        // records (4 @ the sector start + the accumulated offsets)
        // + the sub extent's records (3).
        let root_sector = 3 * SECTOR;
        let sub_sector = 4 * SECTOR;
        let mut sites = vec![
            16 * SECTOR + DESC_ROOT_OFFSET + DATE_OFFSET,
            17 * SECTOR + DESC_ROOT_OFFSET + DATE_OFFSET,
        ];
        let mut pos = 0usize;
        for l in ROOT_LENS {
            sites.push(root_sector + pos as u64 + DATE_OFFSET);
            pos += l;
        }
        pos = 0;
        for l in SUB_LENS {
            sites.push(sub_sector + pos as u64 + DATE_OFFSET);
            pos += l;
        }
        (p, sites)
    }

    /// The R7.1/R7.2 fixture record lengths (see the doc above):
    /// root extent = [34, 34, 36, 36] (the 0x00/0x01 dots · `sub` ·
    /// `f1`) · sub extent = [34, 36, 36] (the `.`/`..` dots · `f2`).
    const ROOT_LENS: [usize; 4] = [34, 34, 36, 36];
    const SUB_LENS: [usize; 3] = [34, 36, 36];

    /// R7.1 — the pass patches every walked record's date field with
    /// the EXACT pin bytes, the file size UNCHANGED, the descriptor-
    /// embedded roots patched, and the untouched bytes untouched (a
    /// 7-byte in-place overwrite — the footprint is exactly
    /// N×7 changed bytes).
    #[test]
    fn iso_times_pass_patches_the_record_date_fields() {
        let base =
            std::env::temp_dir().join(format!("frameprism_iso_times_patch_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let (p, sites) = minimal_image(&base);
        let before = std::fs::read(&p).unwrap();
        let len = before.len() as u64;
        let n = pin_record_dates(&p, 1_789_344_000).unwrap();
        assert_eq!(n, sites.len() as u32, "the patched field count (the 2 descriptor roots + every on-disk record incl. the dots)");
        let after = std::fs::read(&p).unwrap();
        assert_eq!(after.len() as u64, len, "the file size UNCHANGED (in-place only)");
        // The EXACT bytes at every walked field == the pin literal:
        for &s in &sites {
            assert_eq!(
                &after[s as usize..(s + DATE_LEN) as usize],
                &[0x7e, 0x09, 0x0e, 0, 0, 0, 0],
                "the field at {s} is the pinned epoch bytes (2026-09-14 00:00:00 UTC)"
            );
        }
        // The footprint: EXACTLY the patch's non-zero bytes changed
        // (N×3 — the rest of each field was already zero; no other
        // byte moved — the in-place 7-byte-overwrite class).
        let patch = [0x7e, 0x09, 0x0e, 0, 0, 0, 0];
        let changed_set: std::collections::BTreeSet<usize> = before
            .iter()
            .zip(after.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        let want_set: std::collections::BTreeSet<usize> = sites
            .iter()
            .flat_map(|&s| (0..DATE_LEN).filter(|o| patch[*o as usize] != 0).map(move |o| (s + o) as usize))
            .collect();
        assert_eq!(
            changed_set.len(),
            sites.len() * 3,
            "the changed-byte count (N×3 non-zero bytes — the rest already zero)"
        );
        assert!(changed_set == want_set, "the changed bytes are EXACTLY the patch's non-zero bytes (the footprint is the pass itself)");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// R7.2 — the HARD-STOP arm: a non-zero date field BEFORE the pass
    /// (the writer changed) → the pinned VERBATIM refusal (the `{n}`
    /// = the planted offset) + the image bytes UNCHANGED (a refusal
    /// never writes — the read phase verifies before the write phase
    /// runs).
    #[test]
    fn iso_times_pass_refuses_a_nonzero_date_field() {
        let base = std::env::temp_dir().join(format!(
            "frameprism_iso_times_refuse_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let (p, sites) = minimal_image(&base);
        // Plant a non-zero second in the PVD root record's date field
        // (the writer-changed simulation).
        let planted = sites[0];
        let mut corrupt = std::fs::read(&p).unwrap();
        corrupt[(planted + 5) as usize] = 0x07; // the second byte
        std::fs::write(&p, &corrupt).unwrap();
        let before = std::fs::read(&p).unwrap();
        let err = pin_record_dates(&p, 1_789_344_000).unwrap_err();
        let msg = format!("{err:#}");
        assert_eq!(
            msg,
            format!(
                "iso: pin-times pass: record date field not all-zeros at offset {planted} — the writer changed; re-pin before release"
            ),
            "the pinned VERBATIM wording (the {{n}} = the planted offset): {msg}"
        );
        assert_eq!(
            std::fs::read(&p).unwrap(),
            before,
            "a refusal NEVER writes (the image bytes are unchanged)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
