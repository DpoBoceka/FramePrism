// m1gate: native-encoder byte-identity gate (speed program).
//
// For each frame, per tile: (a) all 3 reference candidates encoded natively
// (fastenc::encode_planes_native) must be BYTE-IDENTICAL to the libjpeg
// streams (tileenc::encode_tile_candidates — the 0.1.0 engine), and
// (b) in golden mode the native winner must equal the golden tile bytes
// (the 0.1.0 adaptive output). Nonzero exit on any mismatch.
//
// CLI:
//   m1gate --orig <frame.dng> --golden <frame.dng> [--prec 12]
//   m1gate --orig <frame.dng> [--prec 12|10]           (libjpeg mode)
//   m1gate --origdir <DIR> --goldendir <DIR> [--limit N] [--prec 12]
//   m1gate --origdir <DIR> [--limit N] [--prec 12|10]  (libjpeg mode)
//
// The candidate set is the measured one (tileenc::CANDIDATES order):
// 0 = wrapped PSV7, 1 = wrapped PSV2, 2 = natural PSV1.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use frameprism::{fastenc, pack12, tiff, tileenc};
use tileenc::{Grid, Orient};

const CANDS: [(Orient, i32); 3] = [
    (Orient::Wrapped, 7),
    (Orient::Wrapped, 2),
    (Orient::Natural, 1),
];

fn get<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let mut i = args.iter().position(|a| a == flag)?;
    i += 1;
    args.get(i).map(|s| s.as_str())
}

fn frame_mosaic(path: &Path) -> Result<(Vec<u16>, u32, u32), String> {
    let buf = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let frame = tiff::read(&buf).map_err(|e| format!("tiff parse: {e}"))?;
    let (w, h) = (frame.width, frame.height);
    let mosaic = pack12::unpack12(frame.strip_slice(&buf), w, h)
        .map_err(|e| format!("unpack12: {e}"))?;
    Ok((mosaic, w, h))
}

fn golden_tiles(buf: &[u8], count: usize) -> Result<Vec<&[u8]>, String> {
    let meta = tiff::read_meta(buf).map_err(|e| format!("golden meta: {e}"))?;
    let e = meta.endianness;
    let mut offs = Vec::new();
    let mut cnts = Vec::new();
    for en in &meta.ifd0.entries {
        match (en.tag, en.typ, en.count) {
            (324, 4, c) if c == count as u32 => {
                let (start, _) = en.out_of_line.ok_or("324 out-of-line")?;
                let start = start as usize;
                offs = (0..count)
                    .map(|i| e.u32(&buf[start + i * 4..start + i * 4 + 4]) as usize)
                    .collect();
            }
            (325, 4, c) if c == count as u32 => {
                let (start, _) = en.out_of_line.ok_or("325 out-of-line")?;
                let start = start as usize;
                cnts = (0..count)
                    .map(|i| e.u32(&buf[start + i * 4..start + i * 4 + 4]) as usize)
                    .collect();
            }
            _ => {}
        }
    }
    if offs.len() != count || cnts.len() != count {
        return Err(format!(
            "golden must have {count} tile offsets/counts (got {}/{})",
            offs.len(),
            cnts.len()
        ));
    }
    Ok(offs
        .into_iter()
        .zip(cnts)
        .map(|(o, c)| &buf[o..o + c])
        .collect())
}

/// Reference even-size invariant (encode_tile_candidates: FFD9 + 0x00 pad).
fn pad(mut s: Vec<u8>) -> Vec<u8> {
    if s.len() % 2 == 1 {
        s.push(0);
    }
    s
}

fn gate_frame(
    label: &str,
    orig: &Path,
    golden: Option<&Path>,
    prec: u32,
) -> Result<(usize, usize, bool), String> {
    let (mosaic, w, h) = frame_mosaic(orig)?;
    let g = Grid::new(w, h);
    let ntile = (g.cols * g.rows) as usize;
    let gbuf = match golden {
        Some(gp) => Some(
            std::fs::read(gp)
                .map_err(|e| format!("read {}: {e}", gp.display()))?,
        ),
        None => None,
    };
    let gtiles = gbuf.as_ref().map(|buf| golden_tiles(buf, ntile).unwrap());
    let mut ok = true;
    let mut cand_mismatches = 0usize;
    let mut winner_mismatches = 0usize;
    for r in 0..g.rows {
        for c in 0..g.cols {
            let i = (r * g.cols + c) as usize;
            let (_chosen, (streams, _sizes, best)) =
                tileenc::encode_tile_candidates(&mosaic, w, h, &g, r, c, prec)
                    .map_err(|e| format!("{label} tile {r},{c}: {e}"))?;
            for (k, &(orient, psv)) in CANDS.iter().enumerate() {
                let p = tileenc::planes_from_tile(&mosaic, w, h, &g, r, c, orient)
                    .map_err(|e| format!("{label} tile {r},{c}: {e}"))?;
                let native =
                    fastenc::encode_planes_native(&p, prec, psv)
                        .map_err(|e| format!("{label} tile {r},{c} cand {k}: {e}"))?;
                let native = pad(native);
                if native != streams[k] {
                    ok = false;
                    cand_mismatches += 1;
                    let first = native
                        .iter()
                        .zip(streams[k].iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(native.len().min(streams[k].len()));
                    eprintln!(
                        "{label} tile {r},{c} cand {k} ({orient:?} psv {psv}): native {} B vs libjpeg {} B, first diff at byte {first}",
                        native.len(),
                        streams[k].len()
                    );
                    static mut DUMPED: bool = false;
                    let mut dump = false;
                    unsafe {
                        if !DUMPED {
                            dump = true;
                            DUMPED = true;
                        }
                    }
                    if dump {
                        let n = 16.min(native.len());
                        let m = 16.min(streams[k].len());
                        eprintln!(
                            "  tail native: {}",
                            native[native.len() - n..].iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
                        );
                        eprintln!(
                            "  tail lib:    {}",
                            streams[k][streams[k].len() - m..].iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
                        );
                    }
                }
            }
            if let Some(gtiles) = &gtiles {
                let p_best = CANDS[best];
                let p = tileenc::planes_from_tile(&mosaic, w, h, &g, r, c, p_best.0)
                    .map_err(|e| format!("{label} tile {r},{c}: {e}"))?;
                let native = fastenc::encode_planes_native(&p, prec, p_best.1)
                    .map_err(|e| format!("{label} tile {r},{c} winner: {e}"))?;
                let native = pad(native);
                if native != gtiles[i] {
                    ok = false;
                    winner_mismatches += 1;
                    let first = native
                        .iter()
                        .zip(gtiles[i].iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(native.len().min(gtiles[i].len()));
                    eprintln!(
                        "{label} tile {r},{c} WINNER (idx {best}): native {} B vs golden {} B, first diff at byte {first}",
                        native.len(),
                        gtiles[i].len()
                    );
                }
            }
        }
    }
    println!(
        "{label}: {} tiles, cand mismatches {cand_mismatches}, winner mismatches {winner_mismatches} → {}",
        ntile,
        if ok { "PASS" } else { "FAIL" }
    );
    Ok((cand_mismatches + winner_mismatches, ntile, ok))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let orig = get(&args, "--orig").map(PathBuf::from);
    let golden = get(&args, "--golden").map(PathBuf::from);
    let origdir = get(&args, "--origdir").map(PathBuf::from);
    let goldendir = get(&args, "--goldendir").map(PathBuf::from);
    let limit = get(&args, "--limit").and_then(|s| s.parse().ok());
    let prec: u32 = get(&args, "--prec").and_then(|s| s.parse().ok()).unwrap_or(12);

    let mut pairs: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
    match (orig, golden, origdir, goldendir) {
        (Some(o), Some(gp), None, None) => pairs.push((o, Some(gp))),
        (Some(o), None, None, None) => pairs.push((o, None)),
        (None, _, Some(od), Some(gd)) => {
            let mut fo: Vec<PathBuf> = std::fs::read_dir(&od)
                .expect("origdir")
                .map(|e| e.unwrap().path())
                .filter(|p| p.extension().map(|x| x == "DNG").unwrap_or(false))
                .collect();
            fo.sort();
            let mut fg: Vec<PathBuf> = std::fs::read_dir(&gd)
                .expect("goldendir")
                .map(|e| e.unwrap().path())
                .filter(|p| p.extension().map(|x| x == "DNG").unwrap_or(false))
                .collect();
            fg.sort();
            for (k, p) in fo.into_iter().enumerate() {
                if limit.map(|n| k >= n).unwrap_or(false) {
                    break;
                }
                let name = p.file_name().unwrap().to_owned();
                let gp = fg
                    .iter()
                    .find(|q| q.file_name() == Some(name.as_os_str()))
                    .cloned();
                pairs.push((p, gp));
            }
        }
        (None, _, Some(od), None) => {
            let mut fo: Vec<PathBuf> = std::fs::read_dir(&od)
                .expect("origdir")
                .map(|e| e.unwrap().path())
                .filter(|p| p.extension().map(|x| x == "DNG").unwrap_or(false))
                .collect();
            fo.sort();
            for (k, p) in fo.into_iter().enumerate() {
                if limit.map(|n| k >= n).unwrap_or(false) {
                    break;
                }
                pairs.push((p, None));
            }
        }
        _ => {
            eprintln!("usage: see m1gate header");
            return ExitCode::FAILURE;
        }
    }

    let mut total_fail = 0usize;
    let mut total_tiles = 0usize;
    for (o, g) in &pairs {
        let label = o
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        match gate_frame(&label, o, g.as_ref().map(|p| p.as_path()), prec) {
            Ok((fails, ntile, _ok)) => {
                total_fail += fails;
                total_tiles += ntile;
            }
            Err(e) => {
                eprintln!("{label}: ERROR {e}");
                total_fail += 1;
            }
        }
    }
    println!("TOTAL: {total_tiles} tiles, {total_fail} failures");
    if total_fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
