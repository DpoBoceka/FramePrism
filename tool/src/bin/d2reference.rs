//! b diagnostic — measured per-class mean error + MAE, one or all
//! frames. Decodes the corpus DNG with the Rust reference
//! decoder (bit-exact to rawpy/LibRaw — see dct2s smoke anchor), the REAL
//! per-frame curve (tag 0xC618), and compares per-CFA-class against the
//! ORIGINAL 12-bit samples. Identical class mapping to the 20a FATAL gate
//! (`gate_class_means`): phase from 50719 DefaultCropOrigin [8,5] (A001
//! corpus constant), pattern [W G / G R], W=(0,0), G=(0,1)|(1,0), R=(1,1),
//! post-curve 12-bit domain.
//!
//! Usage: d2reference <reference.dng|dir> [original.dng|dir]
//! (dirs: pairs by filename stem; default reference dir = ../testdata/reference/vbr-hq,
//!    original dir = ../testdata/originals/A001_001)

use frameprism::{dct2s, lossydct, pack12, tiff};

/// minimal LE IFD walk for tags 256/257/324/325/0xC618 (same convention as
/// the dct2s real-file smoke anchor)
fn ifd(vb: &[u8]) -> (u32, u32, Vec<u32>, Vec<u32>, Vec<u16>) {
    let u16le = |o: usize| u16::from_le_bytes([vb[o], vb[o + 1]]);
    let ifd_off = u32::from_le_bytes([vb[4], vb[5], vb[6], vb[7]]) as usize;
    let n = u16le(ifd_off) as usize;
    let mut w = 0u32;
    let mut h = 0u32;
    let mut offs: Vec<u32> = Vec::new();
    let mut cnts: Vec<u32> = Vec::new();
    let mut curve: Vec<u16> = Vec::new();
    for k in 0..n {
        let e = ifd_off + 2 + k * 12;
        let tag = u16le(e);
        let cnt = u32::from_le_bytes([vb[e + 4], vb[e + 5], vb[e + 6], vb[e + 7]]);
        let vo = e + 8;
        let po = |size: usize| {
            if size as u64 * cnt as u64 <= 4 {
                vo
            } else {
                u32::from_le_bytes([vb[vo], vb[vo + 1], vb[vo + 2], vb[vo + 3]]) as usize
            }
        };
        match tag {
            256 => w = u32::from_le_bytes([vb[vo], vb[vo + 1], vb[vo + 2], vb[vo + 3]]),
            257 => h = u32::from_le_bytes([vb[vo], vb[vo + 1], vb[vo + 2], vb[vo + 3]]),
            324 => {
                let po = po(4);
                for i in 0..cnt as usize {
                    offs.push(u32::from_le_bytes([
                        vb[po + 4 * i],
                        vb[po + 4 * i + 1],
                        vb[po + 4 * i + 2],
                        vb[po + 4 * i + 3],
                    ]));
                }
            }
            325 => {
                let po = po(4);
                for i in 0..cnt as usize {
                    cnts.push(u32::from_le_bytes([
                        vb[po + 4 * i],
                        vb[po + 4 * i + 1],
                        vb[po + 4 * i + 2],
                        vb[po + 4 * i + 3],
                    ]));
                }
            }
            0xC618 => {
                let po = po(2);
                for i in 0..cnt as usize {
                    curve.push(u16::from_le_bytes([vb[po + 2 * i], vb[po + 2 * i + 1]]));
                }
            }
            _ => {}
        }
    }
    (w, h, offs, cnts, curve)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let reference_src = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("../testdata/reference/vbr-hq");
    let orig_dir = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("../testdata/originals/A001_001");
    if std::path::Path::new(reference_src).is_dir() {
        // all frames in the dir, paired by name
        let entries: Vec<String> = std::fs::read_dir(reference_src)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".DNG"))
            .collect();
        for name in &entries {
            run_frame(
                &std::path::Path::new(reference_src).join(name),
                &std::path::Path::new(orig_dir).join(name),
            );
        }
    } else {
        // single reference file: original paired by name in the orig dir
        let name = std::path::Path::new(reference_src)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        run_frame(
            std::path::Path::new(reference_src),
            &std::path::Path::new(orig_dir).join(name),
        );
    }
}

fn run_frame(vp: &std::path::Path, op: &std::path::Path) {
    let name = vp.file_name().unwrap().to_string_lossy().to_string();
    let vb = std::fs::read(vp).unwrap_or_else(|e| panic!("{vp:?}: {e}"));
    let ob = std::fs::read(op).unwrap_or_else(|e| panic!("{op:?}: {e}"));
    let (w, h, offs, cnts, curve) = ifd(&vb);
    let curve = dct2s::linearization_curve(Some(&curve));
    let oframe = tiff::read(&ob).unwrap();
    let (ow, oh) = (oframe.width, oframe.height);
    assert_eq!((w, h), (ow, oh), "{name}: size mismatch");
    let samples = pack12::unpack12(oframe.strip_slice(&ob), ow, oh).unwrap();
    let mut decoded = vec![0u16; (w * h) as usize];
    let plane_w = lossydct::PLANE_W;
    let plane_h = lossydct::PLANE_H;
    for (t, (off, cnt)) in offs.iter().zip(cnts.iter()).enumerate() {
        let tx = (t % 2) * plane_w;
        let ty = (t / 2) * (plane_h * 2);
        let tile = &vb[*off as usize..(*off + *cnt) as usize];
        let info = dct2s::parse_tile(tile).unwrap();
        for si in 0..2usize {
            let (recon, _) = dct2s::decode_scan_plane(tile, &info, si, &curve).unwrap();
            for p in 0..plane_h {
                let fr = ty + 2 * p + si;
                if fr >= h as usize {
                    break;
                }
                let row = &mut decoded[fr * (w as usize) + tx..fr * (w as usize) + tx + plane_w];
                row.copy_from_slice(&recon[p * plane_w..(p + 1) * plane_w]);
            }
        }
    }
    // per-class, EXACT gate mapping (50719 [8,5], [W G / G R])
    let (cleft, ctop) = (8i64, 5);
    let mut sum = [0i64; 3];
    let mut cnt = [0u64; 3];
    let mut mae = 0.0f64;
    for (i, (&d, &s)) in decoded.iter().zip(samples.iter()).enumerate() {
        let y = (i / w as usize) as i64;
        let x = (i % w as usize) as i64;
        let rp = (y - ctop).rem_euclid(2) as usize;
        let cp = (x - cleft).rem_euclid(2) as usize;
        let cls = match (rp, cp) {
            (0, 0) => 0,
            (1, 1) => 2,
            _ => 1,
        };
        sum[cls] += i64::from(d) - i64::from(s);
        cnt[cls] += 1;
        mae += (i64::from(d) - i64::from(s)).abs() as f64;
    }
    mae /= (w * h) as f64;
    let (mw, mg, mr) = (
        sum[0] as f64 / cnt[0] as f64,
        sum[1] as f64 / cnt[1] as f64,
        sum[2] as f64 / cnt[2] as f64,
    );
    let max_abs = mw.abs().max(mg.abs()).max(mr.abs());
    println!("{name}: MAE {mae:.3} | W {mw:+.3} G {mg:+.3} R {mr:+.3} | max|mean| {max_abs:.3}");
}
