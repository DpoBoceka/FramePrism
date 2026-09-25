//! dct2s — probe + quality tool for tag-7 (two-scan 12-bit
//! DCT) lossy cDNG format .
//!
//! Subcommands:
//! probe <reference.dng> [--tile T] [--scan S] [--blocks N] [--print M]
//!       Decode tiles/scans and print per-scan vpred + plane stats and the
//!       first M blocks (index, vpred, mean/min/max) — the single-tile
//!       debugging probe.
//! quality <reference_dir> <orig_dir> [--frames N] [--tsv PATH]
//!       Per-frame TRUE full-image quality (both scans, 4 tiles) vs the
//!       original, plus the "ab-lossy" masked values (the 7.94 artifact)
//!       side by side. Writes the TSV report when requested.

use std::path::PathBuf;
use std::time::Instant;

use frameprism::dct2s;
use frameprism::pack12;
use frameprism::tiff;

fn entry_bytes<'a>(entry: &'a tiff::IfdEntry, src: &'a [u8]) -> Option<&'a [u8]> {
    match entry.out_of_line {
        Some((s, e)) => Some(&src[s as usize..e as usize]),
        None => {
            let n = match entry.typ {
                1 | 2 | 6 | 7 => 1,
                3 | 8 => 2,
                4 | 9 | 11 | 12 => 4,
                5 | 10 => 8,
                _ => return None,
            } * entry.count as usize;
            if n <= 4 {
                Some(&entry.value_raw[..n])
            } else {
                None
            }
        }
    }
}

fn tag_long(meta: &tiff::Meta, src: &[u8], tag: u16) -> Option<Vec<u32>> {
    let e = meta.ifd0.entries.iter().find(|e| e.tag == tag)?;
    let b = entry_bytes(e, src)?;
    (0..e.count as usize)
        .map(|i| Some(meta.endianness.u32(&b[4 * i..4 * i + 4])))
        .collect()
}

fn tag_short(meta: &tiff::Meta, src: &[u8], tag: u16) -> Option<Vec<u16>> {
    let e = meta.ifd0.entries.iter().find(|e| e.tag == tag)?;
    let b = entry_bytes(e, src)?;
    (0..e.count as usize)
        .map(|i| Some(meta.endianness.u16(&b[2 * i..2 * i + 2])))
        .collect()
}

struct ReferenceFrame {
    width: u32,
    height: u32,
    tw: u32,
    tl: u32,
    tiles: Vec<(usize, usize)>,
    curve: Vec<u16>,
}

fn reference_frame(vb: &[u8]) -> Result<ReferenceFrame, String> {
    let meta = tiff::read_meta(vb).map_err(|e| e.to_string())?;
    let width = tag_long(&meta, vb, 256)
        .and_then(|v| v.into_iter().next())
        .ok_or("no 256")?;
    let height = tag_long(&meta, vb, 257)
        .and_then(|v| v.into_iter().next())
        .ok_or("no 257")?;
    let tw = tag_long(&meta, vb, 322)
        .and_then(|v| v.into_iter().next())
        .ok_or("no 322")?;
    let tl = tag_long(&meta, vb, 323)
        .and_then(|v| v.into_iter().next())
        .ok_or("no 323")?;
    let offs = tag_long(&meta, vb, 324).ok_or("no 324")?;
    let cnts = tag_long(&meta, vb, 325).ok_or("no 325")?;
    if offs.len() != cnts.len() || offs.is_empty() {
        return Err("324/325 mismatch".into());
    }
    let tiles: Vec<(usize, usize)> = offs
        .iter()
        .zip(cnts.iter())
        .map(|(&o, &c)| (o as usize, c as usize))
        .collect();
    let curve = tag_short(&meta, vb, 0xC618);
    let curve = dct2s::linearization_curve(curve.as_deref());
    Ok(ReferenceFrame {
        width,
        height,
        tw,
        tl,
        tiles,
        curve,
    })
}

fn list_dngs(dir: &std::path::Path) -> Result<Vec<PathBuf>, String> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .map(|x| x.eq_ignore_ascii_case("dng"))
                    .unwrap_or(false)
        })
        .collect();
    v.sort();
    Ok(v)
}

fn cmd_probe(
    path: &std::path::Path,
    tile: usize,
    scan: Option<usize>,
    blocks: usize,
    print: usize,
) -> Result<(), String> {
    let vb = std::fs::read(path).map_err(|e| e.to_string())?;
    let vf = reference_frame(&vb)?;
    println!(
        "{}: {}x{} tile {}x{} {} tiles; curve deviations from identity: {}",
        path.display(),
        vf.width,
        vf.height,
        vf.tw,
        vf.tl,
        vf.tiles.len(),
        (0..65536usize).filter(|&i| vf.curve[i] != i as u16).count(),
    );
    let ti = tile.min(vf.tiles.len() - 1);
    let (o, c) = vf.tiles[ti];
    let tileb = &vb[o..o + c];
    let info = dct2s::parse_tile(tileb).map_err(|e| e.to_string())?;
    let scans: Vec<usize> = match scan {
        Some(s) => vec![s],
        None => (0..info.sos.len()).collect(),
    };
    for si in scans {
        if si >= info.sos.len() {
            continue;
        }
        let t0 = Instant::now();
        let (plane, vpreds) =
            dct2s::decode_scan_plane(tileb, &info, si, &vf.curve).map_err(|e| e.to_string())?;
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        let n = blocks.min(dct2s::NB);
        let vmin = vpreds.iter().take(n).min().copied().unwrap_or(0);
        let vmax = vpreds.iter().take(n).max().copied().unwrap_or(0);
        let pmin = plane.iter().copied().min().unwrap_or(0);
        let pmax = plane.iter().copied().max().unwrap_or(0);
        let pmean: f64 = plane.iter().map(|&v| v as f64).sum::<f64>() / plane.len() as f64;
        println!(
            "tile {ti} scan {si}: {n} blocks {ms:.0} ms | vpred {vmin}..{vmax} | plane min {pmin} max {pmax} mean {pmean:.2}",
        );
        // `bi` is a VALUE here (band/col split), not just an index
        // (clippy allow).
        #[allow(clippy::needless_range_loop)]
        for bi in 0..print.min(n) {
            let w = dct2s::NBLK_W * 8;
            let band = bi / dct2s::NBLK_W;
            let col = bi % dct2s::NBLK_W;
            let mut sum = 0f64;
            let mut mn = u16::MAX;
            let mut mx = 0u16;
            for r in 0..8 {
                let row = &plane[(band * 8 + r) * w + col * 8..(band * 8 + r) * w + col * 8 + 8];
                for &v in row {
                    sum += v as f64;
                    mn = mn.min(v);
                    mx = mx.max(v);
                }
            }
            println!(
                "  blk {bi} ({band},{col}): vpred {:6} mean {:7.2} min {:5} max {:5}",
                vpreds[bi],
                sum / 64.0,
                mn,
                mx,
            );
        }
    }
    Ok(())
}

fn cmd_quality(
    reference_dir: &std::path::Path,
    orig_dir: &std::path::Path,
    frames: usize,
    tsv: Option<&PathBuf>,
) -> Result<(), String> {
    let vfiles = list_dngs(reference_dir)?;
    let ofiles = list_dngs(orig_dir)?;
    if vfiles.is_empty() {
        return Err(format!("no .dng in {}", reference_dir.display()));
    }
    let n = frames.min(vfiles.len());
    let mut out = String::from(
        "frame\tmae\texact_pct\tle1_pct\tmax_abs\tmae_even\tmae_odd\tab_style_mae\tab_style_exact_pct\tms\n",
    );
    for (k, vf) in vfiles.iter().take(n).enumerate() {
        let of = ofiles
            .iter()
            .find(|p| p.file_name() == vf.file_name())
            .ok_or_else(|| format!("original missing for {}", vf.display()))?;
        let t0 = Instant::now();
        let vb = std::fs::read(vf).map_err(|e| e.to_string())?;
        let ob = std::fs::read(of).map_err(|e| e.to_string())?;
        let vframe = reference_frame(&vb)?;
        let tile_slices: Vec<&[u8]> = vframe.tiles.iter().map(|&(o, c)| &vb[o..o + c]).collect();
        let frame = dct2s::assemble_frame(
            &tile_slices,
            vframe.tw,
            vframe.tl,
            vframe.width,
            vframe.height,
            &vframe.curve,
        )
        .map_err(|e| e.to_string())?;
        let ometa = tiff::read(&ob).map_err(|e| e.to_string())?;
        let original = pack12::unpack12(ometa.strip_slice(&ob), ometa.width, ometa.height)
            .map_err(|e| e.to_string())?;
        if frame.len() != original.len() {
            return Err(format!(
                "{}: size mismatch {} vs {}",
                vf.display(),
                frame.len(),
                original.len()
            ));
        }
        let q = dct2s::quality_metrics(&frame, &original, vframe.width, vframe.height);
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        let row = format!(
            "{}\t{:.4}\t{:.2}\t{:.2}\t{}\t{:.4}\t{:.4}\t{:.4}\t{:.2}\t{:.0}",
            vf.file_name().unwrap().to_string_lossy(),
            q.mae,
            q.exact_pct,
            q.le1_pct,
            q.max_abs,
            q.mae_even,
            q.mae_odd,
            q.ab_style_mae,
            q.ab_style_exact_pct,
            ms,
        );
        println!("{row}");
        out.push_str(&row);
        out.push('\n');
        if k % 25 == 0 {
            println!("  progress {k}/{n}");
        }
    }
    if let Some(p) = tsv {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(p, out).map_err(|e| e.to_string())?;
        println!("tsv written to {}", p.display());
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: dct2s <probe|quality> ... (see tool/src/bin/dct2s.rs)");
        std::process::exit(2);
    }
    let res = match args[1].as_str() {
        "probe" => {
            let mut tile = 0usize;
            let mut scan: Option<usize> = None;
            let mut blocks = dct2s::NB;
            let mut print = 8usize;
            let mut path: Option<PathBuf> = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--tile" => {
                        i += 1;
                        tile = args[i].parse().unwrap();
                    }
                    "--scan" => {
                        i += 1;
                        scan = Some(args[i].parse().unwrap());
                    }
                    "--blocks" => {
                        i += 1;
                        blocks = args[i].parse().unwrap();
                    }
                    "--print" => {
                        i += 1;
                        print = args[i].parse().unwrap();
                    }
                    other => path = Some(PathBuf::from(other)),
                }
                i += 1;
            }
            let path = path.expect("reference .dng path required");
            cmd_probe(&path, tile, scan, blocks, print)
        }
        "quality" => {
            let mut frames = usize::MAX;
            let mut tsv: Option<PathBuf> = None;
            let mut dirs: Vec<PathBuf> = Vec::new();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--frames" => {
                        i += 1;
                        frames = args[i].parse().unwrap();
                    }
                    "--tsv" => {
                        i += 1;
                        tsv = Some(PathBuf::from(args[i].clone()));
                    }
                    other => dirs.push(PathBuf::from(other)),
                }
                i += 1;
            }
            if dirs.len() != 2 {
                eprintln!("usage: dct2s quality <ref_dir> <orig_dir> [--frames N] [--tsv PATH]");
                std::process::exit(2);
            }
            cmd_quality(&dirs[0], &dirs[1], frames, tsv.as_ref())
        }
        other => {
            eprintln!("unknown subcommand {other}");
            std::process::exit(2);
        }
    };
    if let Err(e) = res {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
