//! render_dng — decode one cDNG frame to a 16-bit PGM (strictly read-only
//! on the input file; the PGM is written to the user-specified output path).
//!
//! Supported wire formats (auto-detected from tag 259 / 324):
//! - Compression 7 + tiles (324/325): reference/reference two-scan 12-bit DCT
//!   (the vbr-*/cbr* lossy family) — via `dct2s::assemble_frame`
//!   - Compression 1: uncompressed 12-bit packed strip — via `pack12::unpack12`
//!
//! Usage:
//!   render_dng <frame.dng> <out.pgm>

use frameprism::{dct2s, pack12, tiff};

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

fn first(v: Option<Vec<u32>>) -> Result<u32, String> {
    v.and_then(|mut v| v.pop())
        .ok_or_else(|| "missing tag".to_string())
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: render_dng <frame.dng> <out.pgm> (input is read-only)".into());
    }
    let src = std::fs::read(&args[1]).map_err(|e| e.to_string())?;
    let meta = tiff::read_meta(&src).map_err(|e| e.to_string())?;
    let comp = tag_short(&meta, &src, 259)
        .and_then(|v| v.into_iter().next())
        .ok_or("no 259")?;
    let width = first(tag_long(&meta, &src, 256))?;
    let height = first(tag_long(&meta, &src, 257))?;

    let frame: Vec<u16> = if comp == 7 {
        // reference DCT: 4 tiles, 2x2 grid, both scans
        let tw = first(tag_long(&meta, &src, 322))?;
        let tl = first(tag_long(&meta, &src, 323))?;
        let offs = tag_long(&meta, &src, 324).ok_or("no 324")?;
        let cnts = tag_long(&meta, &src, 325).ok_or("no 325")?;
        if offs.len() != cnts.len() || offs.is_empty() {
            return Err("324/325 mismatch".into());
        }
        let tiles: Vec<(usize, usize)> = offs
            .iter()
            .zip(cnts.iter())
            .map(|(&o, &c)| (o as usize, c as usize))
            .collect();
        let curve = tag_short(&meta, &src, 0xC618);
        let curve = dct2s::linearization_curve(curve.as_deref());
        let tile_slices: Vec<&[u8]> = tiles.iter().map(|&(o, c)| &src[o..o + c]).collect();
        dct2s::assemble_frame(&tile_slices, tw, tl, width, height, &curve)
            .map_err(|e| e.to_string())?
    } else if comp == 1 {
        let f = tiff::read(&src).map_err(|e| e.to_string())?;
        pack12::unpack12(f.strip_slice(&src), f.width, f.height).map_err(|e| e.to_string())?
    } else {
        return Err(format!("unsupported compression {comp}"));
    };

    if (width * height) as usize != frame.len() {
        return Err(format!(
            "frame size mismatch: {width}x{height} vs {}",
            frame.len()
        ));
    }
    let mut out = Vec::with_capacity(frame.len() * 2 + 32);
    out.extend_from_slice(format!("P5\n{width} {height}\n65535\n").as_bytes());
    for &v in &frame {
        out.extend_from_slice(&v.to_be_bytes());
    }
    std::fs::write(&args[2], &out).map_err(|e| e.to_string())?;
    println!(
        "wrote {} ({}x{}, comp {comp}, {} samples)",
        args[2],
        width,
        height,
        frame.len()
    );
    Ok(())
}
