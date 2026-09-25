//! prep diagnostic — spatial cast/seam measurement for ONE frame.
//! Decodes the DNG with the corpus-verified Rust decoder (dct2s, real curve)
//! and reports vs the original 12-bit samples:
//!   * per-class W/G/R mean error: whole frame / bright (source>3500) / rest
//!   * seam steps: col 1927->1928 (tile seam) vs ref cols 1000, 1915;
//!     row 1087->1088 (tile seam) vs ref row 500 — mean/std/%|d|>2
//!   * error 2x2 CFA-parity matrix (per rp,cp mean) — 2-period structure
//!
//! Phase from 50719 [8,5], pattern [W G / G R] (identical to the gates).
//!
//! Usage: d2diag <frame.dng> <original.dng>

// W/H/BW/BH/NBW/NBH are the DCT/image-domain convention in this scratch
// diagnostic (rustc non_snake_case allow for the whole file).
#![allow(non_snake_case)]

use frameprism::{dct2s, lossydct, pack12, tiff};

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

fn step_stats(d: &[i64]) -> (f64, f64, f64) {
    let n = d.len() as f64;
    let mean = d.iter().map(|v| (*v) as f64).sum::<f64>() / n;
    let std = (d.iter().map(|v| ((*v as f64) - mean).powi(2)).sum::<f64>() / n).sqrt();
    let gt2 = d.iter().filter(|v| v.abs() > 2).count() as f64 / n;
    (mean, std, gt2)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: d2diag <frame.dng> <original.dng>");
        std::process::exit(2);
    }
    let vb = std::fs::read(&args[1]).unwrap();
    let ob = std::fs::read(&args[2]).unwrap();
    let name = args[1].rsplit('/').next().unwrap().to_string();
    let (w, h, offs, cnts, curve) = ifd(&vb);
    let curve = dct2s::linearization_curve(Some(&curve));
    let oframe = tiff::read(&ob).unwrap();
    let samples = pack12::unpack12(oframe.strip_slice(&ob), w, h).unwrap();
    let (W, H) = (w as usize, h as usize);
    let mut decoded = vec![0u16; W * H];
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
                if fr >= H {
                    break;
                }
                decoded[fr * W + tx..fr * W + tx + plane_w]
                    .copy_from_slice(&recon[p * plane_w..(p + 1) * plane_w]);
            }
        }
    }
    // per-class + parity, whole / bright / rest
    let (cleft, ctop) = (8i64, 5);
    let mut sum = [[0i64; 3]; 4]; // [region][class] 0=whole 1=bright 2=rest 3=mid
    let mut cnt = [[0u64; 3]; 4];
    let mut par = [[0i64; 2]; 2]; // [rp][cp]
    let mut parc = [[0u64; 2]; 2];
    let mut mae = 0.0f64;
    let mut n_bright = 0u64;
    for y in 0..H {
        let y64 = y as i64;
        let rp = (y64 - ctop).rem_euclid(2) as usize;
        for x in 0..W {
            let x64 = x as i64;
            let cp = (x64 - cleft).rem_euclid(2) as usize;
            let cls = match (rp, cp) {
                (0, 0) => 0,
                (1, 1) => 2,
                _ => 1,
            };
            let i = y * W + x;
            let e = decoded[i] as i64 - samples[i] as i64;
            par[rp][cp] += e;
            parc[rp][cp] += 1;
            mae += e.abs() as f64;
            let sv = samples[i] as i64;
            let mid = (512..2048).contains(&sv);
            if sv > 3500 {
                n_bright += 1;
            }
            let ri = if sv > 3500 { 1 } else { 2 };
            for ri_ in [0usize, ri, 3usize] {
                if ri_ != 3 || mid {
                    sum[ri_][cls] += e;
                    cnt[ri_][cls] += 1;
                }
            }
        }
    }
    let px = (W * H) as f64;
    mae /= px;
    let fmt3 = |s: &[i64; 3], c: &[u64; 3]| {
        format!(
            "{:+8.3} / {:+8.3} / {:+8.3}",
            s[0] as f64 / c[0] as f64,
            s[1] as f64 / c[1] as f64,
            s[2] as f64 / c[2] as f64
        )
    };
    println!(
        "{name}: MAE {mae:.3} (whole) | bright-px share {}%",
        100.0 * n_bright as f64 / px
    );
    println!("  per-class W/G/R whole: {}", fmt3(&sum[0], &cnt[0]));
    println!("  per-class W/G/R bright: {}", fmt3(&sum[1], &cnt[1]));
    println!("  per-class W/G/R rest  : {}", fmt3(&sum[2], &cnt[2]));
    println!(
        "  per-class W/G/R mid(512-2047): {}",
        fmt3(&sum[3], &cnt[3])
    );
    let p = |i: usize, j: usize| par[i][j] as f64 / parc[i][j] as f64;
    println!(
        "  err 2x2 parity [rp][cp]: r0: {:+.} {:+.} | r1: {:+.} {:+.}",
        p(0, 0),
        p(0, 1),
        p(1, 0),
        p(1, 1)
    );
    // seam steps (post-curve domain)
    let col = |xa: usize, xb: usize| -> Vec<i64> {
        (0..H)
            .map(|y| decoded[y * W + xb] as i64 - decoded[y * W + xa] as i64)
            .collect()
    };
    let row = |ya: usize, yb: usize| -> Vec<i64> {
        (0..W)
            .map(|x| decoded[yb * W + x] as i64 - decoded[ya * W + x] as i64)
            .collect()
    };
    let rep = |lbl: &str, d: &[i64]| {
        let (m, s, g) = step_stats(d);
        println!("  seam {lbl:<14} mean {m:+} std {s} %|d|>2 {g:.4}");
    };
    // error-domain seam steps (removes scene content: a seam artifact is a
    // systematic shift in the ERROR at the seam column/row)
    let ecol = |xa: usize, xb: usize| -> Vec<i64> {
        (0..H)
            .map(|y| {
                let i1 = y * W + xb;
                let i0 = y * W + xa;
                (decoded[i1] as i64 - samples[i1] as i64)
                    - (decoded[i0] as i64 - samples[i0] as i64)
            })
            .collect()
    };
    let erow = |ya: usize, yb: usize| -> Vec<i64> {
        (0..W)
            .map(|x| {
                let i1 = yb * W + x;
                let i0 = ya * W + x;
                (decoded[i1] as i64 - samples[i1] as i64)
                    - (decoded[i0] as i64 - samples[i0] as i64)
            })
            .collect()
    };
    rep("ERR col1927->1928*", &ecol(1927, 1928));
    rep("ERR col1000->1001", &ecol(1000, 1001));
    rep("ERR col1915->1916", &ecol(1915, 1916));
    rep("ERR row1087->1088*", &erow(1087, 1088));
    rep("ERR row500->501", &erow(500, 501));
    rep("col1927->1928*", &col(1927, 1928));
    rep("col1000->1001", &col(1000, 1001));
    rep("col1915->1916", &col(1915, 1916));
    rep("row1087->1088*", &row(1087, 1088));
    rep("row500->501", &row(500, 501));
    // full-frame RAW 2-period step: horizontal pixel step std over ALL pixels
    // (source vs decoded) — does the decoded Bayer retain the CFA pattern?
    let mut ss: Vec<f64> = Vec::new();
    let mut ds: Vec<f64> = Vec::new();
    for y in 0..H {
        for x in 0..W - 1 {
            let i = y * W + x;
            ss.push(samples[i + 1] as i64 as f64 - samples[i] as i64 as f64);
            ds.push(decoded[i + 1] as i64 as f64 - decoded[i] as i64 as f64);
        }
    }
    let m = |v: &[f64]| -> (f64, f64) {
        let mu = v.iter().sum::<f64>() / v.len() as f64;
        let sd = (v.iter().map(|x| (x - mu).powi(2)).sum::<f64>() / v.len() as f64).sqrt();
        (mu, sd)
    };
    let (smu, ssd) = m(&ss);
    let (dmu, dsd) = m(&ds);
    println!("  RAW 2period h-step: source mean {smu:+.} std {ssd:.} | decoded mean {dmu:+.} std {dsd:.} (ratio decoded/source {ratio:.3})", ratio = dsd / ssd);
    // vertical too
    let mut svv: Vec<f64> = Vec::new();
    let mut dvv: Vec<f64> = Vec::new();
    for y in 0..H - 1 {
        for x in 0..W {
            let i = y * W + x;
            svv.push(samples[i + W] as i64 as f64 - samples[i] as i64 as f64);
            dvv.push(decoded[i + W] as i64 as f64 - decoded[i] as i64 as f64);
        }
    }
    let (smuv, ssdv) = m(&svv);
    let (dmuv, dsdv) = m(&dvv);
    println!("  RAW 2period v-step: source mean {smuv:+.} std {ssdv:.} | decoded mean {dmuv:+.} std {dsdv:.} (ratio decoded/source {ratiov:.3})", ratiov = dsdv / ssdv);
    // 2-period error structure (orange/cyan CFA-pattern cast test):
    // in mid-tone pixels, anti-correlation of the ERROR between adjacent
    // pixels = residual 2-period CFA structure in the decoded domain
    let mut hstep: Vec<i64> = Vec::new();
    let mut vstep: Vec<i64> = Vec::new();
    let mut hprod: Vec<f64> = Vec::new();
    for y in 0..H - 1 {
        for x in 0..W - 1 {
            let i = y * W + x;
            let sv = samples[i] as i64;
            if (512..2048).contains(&sv) {
                let e0 = decoded[i] as i64 - samples[i] as i64;
                let e1 = decoded[i + 1] as i64 - samples[i + 1] as i64;
                hstep.push(e0 - e1);
                hprod.push(e0 as f64 * e1 as f64);
                let i2 = i + W;
                let e2 = decoded[i2] as i64 - samples[i2] as i64;
                vstep.push(e0 - e2);
            }
        }
    }
    let hmean: f64 = hstep.iter().map(|v| (*v) as f64).sum::<f64>() / hstep.len() as f64;
    let hstd: f64 = (hstep
        .iter()
        .map(|v| ((*v) as f64 - hmean).powi(2))
        .sum::<f64>()
        / hstep.len() as f64)
        .sqrt();
    let hprod_mean: f64 = hprod.iter().sum::<f64>() / hprod.len() as f64;
    let vmean: f64 = vstep.iter().map(|v| (*v) as f64).sum::<f64>() / vstep.len() as f64;
    let vstd: f64 = (vstep
        .iter()
        .map(|v| ((*v) as f64 - vmean).powi(2))
        .sum::<f64>()
        / vstep.len() as f64)
        .sqrt();
    println!("  2period ERR mid: h-step mean {hmean:+.} std {hstd:.} h-corr(mean prod) {hprod_mean:+.} | v-step mean {vmean:+.} std {vstd:.}");
    // per-block (64x64) per-class error: spatial variability of the cast
    let (BW, BH) = (64, 64);
    let (NBW, NBH) = (W / BW, H / BH);
    let mut bsum = [vec![[0i64; 3]; NBW * NBH]];
    let mut bcnt = [vec![[0u64; 3]; NBW * NBH]];
    for y in 0..NBH * BH {
        for x in 0..NBW * BW {
            let i = y * W + x;
            let cls = match (y % 2, x % 2) {
                (0, 0) => 0,
                (1, 1) => 2,
                _ => 1,
            };
            let b = (y / BH) * NBW + x / BW;
            bsum[0][b][cls] += decoded[i] as i64 - samples[i] as i64;
            bcnt[0][b][cls] += 1;
        }
    }
    for ci in 0..3 {
        let name = ['W', 'G', 'R'][ci];
        let vals: Vec<f64> = (0..NBW * NBH)
            .map(|b| {
                if bcnt[0][b][ci] > 0 {
                    bsum[0][b][ci] as f64 / bcnt[0][b][ci] as f64
                } else {
                    f64::NAN
                }
            })
            .filter(|v| v.is_finite())
            .collect();
        let mean = vals.iter().sum::<f64>() / vals.len() as f64;
        let std = (vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / vals.len() as f64).sqrt();
        let lo = vals.iter().cloned().fold(f64::MAX, f64::min);
        let hi = vals.iter().cloned().fold(f64::MIN, f64::max);
        println!(
            "  BLOCK64 {name}: blocks {} mean {mean:+.} std {std:.} min {lo:+.} max {hi:+.}",
            vals.len()
        );
    }
    // flat-region seam: decoded step on rows/cols where the source is flat
    // (|src step| < 8) — the perceptual condition for a visible seam line
    let flat_col = |xa: usize, xb: usize| {
        let mut ds: Vec<i64> = Vec::new();
        for y in 0..H {
            let sstep = samples[y * W + xb] as i64 - samples[y * W + xa] as i64;
            if sstep.abs() < 8 {
                ds.push(decoded[y * W + xb] as i64 - decoded[y * W + xa] as i64);
            }
        }
        ds
    };
    let flat_row = |ya: usize, yb: usize| {
        let mut ds: Vec<i64> = Vec::new();
        for x in 0..W {
            let sstep = samples[yb * W + x] as i64 - samples[ya * W + x] as i64;
            if sstep.abs() < 8 {
                ds.push(decoded[yb * W + x] as i64 - decoded[ya * W + x] as i64);
            }
        }
        ds
    };
    let frep = |lbl: &str, d: &[i64]| {
        if d.is_empty() {
            println!("  FLAT {lbl}: no flat rows");
        } else {
            let (m, s, g) = step_stats(d);
            let gt1 = d.iter().filter(|v| v.abs() > 1).count() as f64 / d.len() as f64;
            let n = d.len();
            println!("  FLAT {lbl}: n {n} mean {m:+} std {s} %|d|>1 {gt1:.4} %|d|>2 {g:.4}");
        }
    };
    // block-boundary FLAT scan: for every 8-block boundary pair (x=8k+7 -> 8k+8),
    // the FLAT-masked decoded step — distinguishes a general DCT block-grid
    // effect (all boundaries hot) from a tile-boundary effect (only the
    // 1927->1928 / 1087->1088 boundaries hot)
    let nbound_x = W / 8; // 482 block cols -> 481 interior boundaries
    let mut per_b: Vec<(f64, usize)> = Vec::new(); // (mean, boundary idx)
    let mut allb: Vec<i64> = Vec::new();
    for k in 0..nbound_x - 1 {
        let xa = 8 * k + 7;
        let xb = 8 * (k + 1);
        if xb >= W {
            break;
        }
        let d = flat_col(xa, xb);
        if d.len() > 32 {
            let (m, _, _) = step_stats(&d);
            per_b.push((m, k));
            allb.extend(d);
        }
    }
    if !allb.is_empty() {
        let (m, s, g) = step_stats(&allb);
        let nn = allb.len();
        let bb = per_b.len();
        println!("  FLATALL block-col boundaries: n {nn} boundaries {bb} mean {m:+.} std {s:.} %|d|>2 {g:.4}");
    }
    per_b.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    println!("  FLATALL top-8 block-col boundaries (mean, k):");
    for (m, k) in per_b.iter().take(8) {
        println!("    k {k} (x {}->{}): {m:+.}", 8 * k + 7, 8 * (k + 1));
    }
    let nbound_y = H / 8;
    let mut per_b_y: Vec<(f64, usize)> = Vec::new();
    let mut allby: Vec<i64> = Vec::new();
    for k in 0..nbound_y - 1 {
        let ya = 8 * k + 7;
        let yb = 8 * (k + 1);
        if yb >= H {
            break;
        }
        let d = flat_row(ya, yb);
        if d.len() > 32 {
            let (m, _, _) = step_stats(&d);
            per_b_y.push((m, k));
            allby.extend(d);
        }
    }
    if !allby.is_empty() {
        let (m, s, g) = step_stats(&allby);
        let nn = allby.len();
        let bb = per_b_y.len();
        println!("  FLATALL block-row boundaries: n {nn} boundaries {bb} mean {m:+.} std {s:.} %|d|>2 {g:.4}");
    }
    per_b_y.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    println!("  FLATALL top-8 block-row boundaries (mean, k):");
    for (m, k) in per_b_y.iter().take(8) {
        println!("    k {k} (y {}->{}): {m:+.}", 8 * k + 7, 8 * (k + 1));
    }
    frep("col1927->1928*", &flat_col(1927, 1928));
    frep("col1000->1001", &flat_col(1000, 1001));
    frep("col1915->1916", &flat_col(1915, 1916));
    frep("row1087->1088*", &flat_row(1087, 1088));
    frep("row500->501", &flat_row(500, 501));
    // source-side reference (what the seam looks like BEFORE encoding):
    let scol = |xa: usize, xb: usize| -> Vec<i64> {
        (0..H)
            .map(|y| samples[y * W + xb] as i64 - samples[y * W + xa] as i64)
            .collect()
    };
    let srow = |ya: usize, yb: usize| -> Vec<i64> {
        (0..W)
            .map(|x| samples[yb * W + x] as i64 - samples[ya * W + x] as i64)
            .collect()
    };
    rep("SRC col1927->1928", &scol(1927, 1928));
    rep("SRC row1087->1088", &srow(1087, 1088));
}
