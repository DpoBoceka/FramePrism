//! diagnostic — demosaic proxy: what does an NLE demosaic see in
//! each decoded Bayer? Simple per-class demosaic (own-class pixel = own
//! value; other classes = mean of the 4 same-class pixels at ±2 in x/y),
//! then per-pixel chroma stats (W-G, G-R, W-R mean/std) + colorfulness
//! (mean per-pixel channel range). Compare source vs decoded.
//!
// W/H are the DCT/image-domain convention in this scratch diagnostic
// (rustc non_snake_case allow for the whole file).
#![allow(non_snake_case)]

//! Usage: d2demo <frame.dng> <original.dng>

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

/// class at (x,y) with phase rp=(y-5)%2, cp=(x-8)%2: 0=W 1=G 2=R
fn cls(x: usize, y: usize) -> usize {
    let rp = (y + 1) % 2; // (y-5)%2
    let cp = x % 2; // (x-8)%2
    match (rp, cp) {
        (0, 0) => 0,
        (1, 1) => 2,
        _ => 1,
    }
}

fn report(name: &str, img: &[u16], w: usize, h: usize) {
    let W = w;
    let H = h;
    // demosaic: channel[c][i]
    let mut ch: [Vec<f64>; 3] = [vec![0f64; W * H], vec![0f64; W * H], vec![0f64; W * H]];
    for y in 0..H {
        for x in 0..W {
            let i = y * W + x;
            let c0 = cls(x, y);
            ch[c0][i] = img[i] as f64;
            // `c` is a VALUE (== c0, the class lookup), not just an index
            // (clippy allow).
            #[allow(clippy::needless_range_loop)]
            for c in 0..3usize {
                if c == c0 {
                    continue;
                }
                let mut s = 0f64;
                let mut n = 0f64;
                for (xx, yy) in [
                    (x.saturating_sub(2), y),
                    ((x + 2).min(W - 1), y),
                    (x, y.saturating_sub(2)),
                    (x, (y + 2).min(H - 1)),
                ] {
                    if cls(xx, yy) == c {
                        s += img[yy * W + xx] as f64;
                        n += 1.0;
                    }
                }
                ch[c][i] = if n > 0.0 { s / n } else { img[i] as f64 };
            }
        }
    }
    // per-pixel chroma stats
    let mut wg = 0f64;
    let mut gr = 0f64;
    let mut wr = 0f64;
    let mut wg2 = 0f64;
    let mut gr2 = 0f64;
    let mut wr2 = 0f64;
    let mut range = 0f64;
    let n = (W * H) as f64;
    // `i` only indexes the three equal-length `ch` channels (clippy
    // allow — the measurement loop keeps its direct index form).
    #[allow(clippy::needless_range_loop)]
    for i in 0..W * H {
        let (a, b, r) = (ch[0][i], ch[1][i], ch[2][i]);
        let d1 = a - b;
        let d2 = b - r;
        let d3 = a - r;
        wg += d1;
        gr += d2;
        wr += d3;
        wg2 += d1 * d1;
        gr2 += d2 * d2;
        wr2 += d3 * d3;
        range += a.max(b).max(r) - a.min(b).min(r);
    }
    let mean = |s: f64| s / n;
    let std = |s: f64, m: f64| (s / n - m * m).max(0.0).sqrt();
    let mw = mean(wg);
    let mg = mean(gr);
    let mwr = mean(wr);
    println!(
        "{name}: W-G mean {mw:+.} std {:.2} | G-R mean {mg:+.} std {:.2} | W-R mean {mwr:+.} std {:.2} | colorfulness (mean range) {:.2}",
        std(wg2, mw),
        std(gr2, mg),
        std(wr2, mwr),
        mean(range)
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: d2demo <frame.dng> <original.dng>");
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
    // per-class levels
    let report_cls = |lbl: &str, img: &[u16]| {
        let mut sum = [0.0f64; 3];
        let mut sum2 = [0.0f64; 3];
        let mut cnt = [0.0f64; 3];
        for y in 0..H {
            for x in 0..W {
                let c = cls(x, y);
                let v = img[y * W + x] as f64;
                sum[c] += v;
                sum2[c] += v * v;
                cnt[c] += 1.0;
            }
        }
        for c in 0..3 {
            let name = ['W', 'G', 'R'][c];
            let m = sum[c] / cnt[c];
            let sd = (sum2[c] / cnt[c] - m * m).max(0.0).sqrt();
            println!(
                "{lbl} class {name}: mean {m:.} std {sd:.} (n {n:.0})",
                n = cnt[c]
            );
        }
    };
    report_cls(&format!("SRC {name}"), &samples);
    report_cls(&format!("DEC {name}"), &decoded);
    report(&format!("SRC {name}"), &samples, W, H);
    report(&format!("DEC {name}"), &decoded, W, H);
}
