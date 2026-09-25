//! The offload's re-verify audit surface: `frameprism audit` on a
//! dir carrying the offload manifest re-verifies the DEST against the
//! recorded rows (the re-scan + the verdict lines; a post-run dest
//! corruption is named here, rc=1).

use super::manifests::Manifest;

/// The re-audit/verify path (; the `audit` verb's
/// offload section): re-read every row's DEST file (the dest recorded
/// in the manifest) and recompute size + sha256 against the row
/// (size + the canonical source_sha256). Missing dest dir / missing
/// file / size mismatch / sha mismatch = the named problem on that
/// row (the audit philosophy — loud, named, no silent skip). Returns
/// (the lines for the caller to print, in order; the bad count — the
/// rc contribution: rc=1 when any row is dirty).
pub fn reverify(m: &Manifest) -> (Vec<String>, usize) {
    let mut lines = Vec::new();
    let mut bad = 0usize;
    if !m.dest.is_dir() {
        lines.push(format!(
            "FAIL OFFLOAD_DEST_MISSING: the offload dest {} is absent — {} row(s) unverifiable ({})",
            m.dest.display(),
            m.rows.len(),
            m.name
        ));
        return (lines, m.rows.len());
    }
    for (file, size, src_sha, _dst_sha) in &m.rows {
        let target = m.dest.join(file);
        // The streaming re-verify (the bounded read):
        // the O(1) size stat + the `SHA256_CHUNK`-buffered sha — the
        // one-shot `fs::read` of the whole dest file is gone (the
        // reverify's O(file) heap was the machine incident's root).
        // The per-site wordings are UNCHANGED (the pinned lines
        // byte-identical).
        let problem = if !target.is_file() {
            Some(format!("file missing in the offload dest {}", m.dest.display()))
        } else {
            match std::fs::metadata(&target).map(|mt| mt.len()) {
                Err(err) => Some(format!("read the offload dest file: {err}")),
                Ok(disk_size) => {
                    if disk_size != *size {
                        Some(format!(
                            "SIZE_MISMATCH: manifest {size} B, disk {disk_size} B"
                        ))
                    } else {
                        match crate::jxl::sha256_stream_path(&target) {
                            Err(err) => Some(format!("read the offload dest file: {err}")),
                            Ok(sha) => {
                                if sha != *src_sha {
                                    Some(format!(
                                        "SHA_MISMATCH: source sha256 {src_sha}, disk {sha}"
                                    ))
                                } else {
                                    None
                                }
                            }
                        }
                    }
                }
            }
        };
        if let Some(problem) = problem {
            bad += 1;
            lines.push(format!("FAIL offload {file}: {problem}", file = file));
        }
    }
    lines.push(format!(
        "audit: offload {}/{} file(s) OK ({}, dest {})",
        m.rows.len() - bad,
        m.rows.len(),
        m.name,
        m.dest.display()
    ));
    (lines, bad)
}


#[cfg(test)]
mod tests {
    use super::*;

    use super::super::{offload_manifest_name, offload_to, parse_manifest};

    use crate::offload::testutil::*;
    #[test]
    fn reverify_names_sha_mismatch_after_post_run_corruption() {
        let (base, input, dest) = setup("shamismatch");
        offload_to(&input, &base.join("out"), &dest).unwrap();
        let clip = crate::checksums::clip_name(&input).unwrap();
        let path = base.join("out").join(offload_manifest_name(&clip));
        let m = parse_manifest(&path).unwrap();
        // Post-run corruption (the E3a shape): flip one dest byte AFTER
        // the run — the re-audit/verify path must NAME it.
        let victim = dest.join("A001_001/f1.DNG");
        let mut buf = std::fs::read(&victim).unwrap();
        buf[0] ^= 0x01;
        std::fs::write(&victim, buf).unwrap();
        let (lines, bad) = reverify(&m);
        assert_eq!(bad, 1, "exactly the corrupted row: {lines:?}");
        let fail = lines
            .iter()
            .find(|l| l.starts_with("FAIL offload A001_001/f1.DNG"))
            .expect("the corrupted row is named");
        assert!(fail.contains("SHA_MISMATCH"), "{fail}");
        assert!(lines.last().unwrap().contains("audit: offload 5/6"));
        let _ = std::fs::remove_dir_all(&base);
    }


    #[test]
    fn reverify_names_size_mismatch_and_missing_file_and_missing_dest() {
        let (base, input, dest) = setup("sizemissing");
        offload_to(&input, &base.join("out"), &dest).unwrap();
        let clip = crate::checksums::clip_name(&input).unwrap();
        let path = base.join("out").join(offload_manifest_name(&clip));
        let m = parse_manifest(&path).unwrap();
        // Truncate one dest file (a size mismatch with a sha mismatch
        // underneath — the SIZE check fires first, named).
        std::fs::write(dest.join("A001_001/f2.DNG"), b"short").unwrap();
        // Remove one dest file.
        std::fs::remove_file(dest.join("root.wav")).unwrap();
        let (lines, bad) = reverify(&m);
        assert_eq!(bad, 2, "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("f2.DNG") && l.contains("SIZE_MISMATCH")));
        assert!(lines.iter().any(|l| l.contains("root.wav") && l.contains("missing")));
        // The whole dest dir vanishes: every row is unverifiable, named.
        let (lines, bad) = reverify(&Manifest {
            name: m.name.clone(),
            clip: m.clip.clone(),
            dest: base.join("vanished"),
            rows: m.rows.clone(),
        });
        assert_eq!(bad, 6);
        assert!(lines[0].contains("OFFLOAD_DEST_MISSING"));
        let _ = std::fs::remove_dir_all(&base);
    }


}
