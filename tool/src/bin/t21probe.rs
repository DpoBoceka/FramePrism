//! Phase-1 PROBE (frameprism lossy v2).
//!
//! Subcommands:
//!   stages <original.dng> <ref_frame.dng>
//!     Run the PRODUCTION encoder stages on the original (curve + tiles from
//!     the ref DNG) and report, per stage, the d2diag-protocol signature:
//!     MAE, per-class W/G/R error, h/v 2-period ratios, d2demo demosaic
//!     chroma stds, FLAT seam steps, per-(row-parity,class) offset mean/std.
//!     Stages: source / 2tap (cfa_lowpass_h) / pre0 (invLUT) / box3 /
//!     snap (full_frame_planes) / dct (quantize_plane + dct2s::idct_block,
//!     DC uncentered 16384 + c0*q0) / file (real decode of the ref DNG).
//!
//! reference <ref_frame.dng> <original.dng>
//! Decode the ref DNG (reference golden or ours) and print the full
//!     class-structure characterization: per-(rp,class) offset mean/std,
//!     per-class LEVEL offset (class-mean decoded - class-mean source),
//!     h-step per class pair (W-row G-W, G-row R-G), v-step per column
//!     parity (even-x G-W, odd-x R-G), h/v ratios, demosaic (d2demo +
//!     fixed +/-1 4-neighbor), FLAT seam lines.
//!
//!   cand <name> <original.dng> <ref_frame.dng>
//!     Run a candidate CFA transform (source space, full frame, before the
//!     tile cut — the cfa_lowpass_h slot) through the REAL encoder chain
//!     (full_frame_planes -> encode_tiles BASE_TABLE -> assemble_frame) and
//!     print the one-line signature.
//!     Names: baseline | identity | box3src | hbox5 | v2tap | hv2tap | u7notch | notch3
//!
//!   dqt <ref_frame.dng>
//!     Print the file's DQT as an 8x8 (i,j) grid (i = vertical frequency =
//!     plane-row direction, j = horizontal frequency = frame-x direction)
//!     next to BASE_TABLE, for the CFA-band comparison.
//!
//! decomp <original.dng> <reference.dng> <ours.dng>
//! Per-component DCT decomposition (the decisive experiment):
//! for each frame (source: invLUT planes; reference/ours: identity-curve
//!     decode planes = exact file pre-domain content) compute the MSQ per
//!     DCT coefficient (i,j) over all 8x8 blocks of the 8 parity planes
//!     (i = vertical frequency, j = horizontal frequency), plus the MSQ of
//!     the inter-plane difference D = odd-plane - even-plane (the v-step
//! structure lives there). Reports ratios reference/source and ours/source.
//!
//! steps2 <original.dng> <reference.dng> <ours.dng>
//!     SIGNAL-DOMAIN 2-period decomposition per 12-bit frame: row-parity
//!     (frame-x (−1)^x) and column-parity (frame-y (−1)^y) amplitudes,
//!     h/v step 2-period vs texture split, per-class W/G/R means,
//!     per-class-pair adjacent steps (d2diag HP/VP protocol).
//!
//!   dctcand <spec> <original.dng> <ref_frame.dng>
//!     DCT-domain candidate: the production chain with the
//!     cfa_lowpass_h slot optional (spec prefix "2tap+"), and a FIXED
//!     per-(i,j) coefficient scale applied to the encoder's X_orth BEFORE
//!     quantization: spec terms `name=value` (comma separated), name ∈
//!     dc | hnq | vnq | c77 | low | mid | rest | hnqe | hnqo | vne | vno
//!     | alle | allee | allo | ij=<i>,<j> | dcmix=<G>.
//!     `dcmix=<G>` / `dcmixg=<G>,dcmixk=<K>` = the cross-plane DC mixing
//! (the measured inter-row-class-difference gain): per tile,
//!     per 8x8 block position, with L = (DC_odd + DC_even)/2 and
//!     D = DC_odd − DC_even (centered pre-domain units): DC_odd' = L +
//!     D'/2, DC_even' = L − D'/2 (the block-pair mean L preserved).
//!     k = 0: D' = G·D (the plain per-block gain). k > 0: the band-limited
//!     gain D' = G·(D − box(D)) + box(D) = G·D − (G−1)·box(2k+1)(D) (the
//!     box on the 241x68 block grid, edge-clipped): the fine-scale
//!     inter-row difference amplified G×, the coarse-scale (column) part
//! preserved ~1× — the measured scale-dependent gain
//!     (per-block D 7-10×, column D ~1×).
//!
//! Protocols are byte-identical to tool/src/bin/d2diag.rs + d2demo.rs so
//! numbers compare against the reference and vendor measurement tables {our,ven}_f1_f86_full.tsv.
//! NOTE (measured, probe): the d2demo +/-2 neighbor search never
//! finds a different class (this CFA's classes sit at +/-1 of each other),
//! so d2demo's chroma stds are an EDGE-BAND statistic (the saturated
//! 2-column/2-row border, where the clamped neighbor flips parity) scaled
//! by sqrt(~0.0019). Kept verbatim for comparability with the spec
//! numbers; the `fixed` +/-1 4-neighbor demosaic is the full-frame
//! reference (reported alongside as `dem_fixed`).
// W/H are the DCT/image-domain convention in this scratch probe (the
// rustc non_snake_case allow for the whole file).
#![allow(non_snake_case)]

use frameprism::{dct2s, lossydct, pack12, tiff};

const CLEFT: i64 = 8;
const CTOP: i64 = 5;

fn cls_of(x: usize, y: usize) -> usize {
    let rp = ((y as i64) - CTOP).rem_euclid(2) as usize;
    let cp = ((x as i64) - CLEFT).rem_euclid(2) as usize;
    match (rp, cp) {
        (0, 0) => 0, // W
        (1, 1) => 2, // R
        _ => 1,      // G
    }
}

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

/// Decode a DNG (any of reference/ours) into the post-curve 12-bit frame,
/// exactly the d2diag scaffold.
fn decode_frame(
    vb: &[u8],
    w: u32,
    h: u32,
    offs: &[u32],
    cnts: &[u32],
    curve65536: &[u16],
) -> Vec<u16> {
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
            let (recon, _) = dct2s::decode_scan_plane(tile, &info, si, curve65536).unwrap();
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
    decoded
}

fn std_of(v: &[f64]) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    let n = v.len() as f64;
    let m = v.iter().sum::<f64>() / n;
    (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / n).sqrt()
}

fn mean_of(v: &[f64]) -> f64 {
    if v.is_empty() {
        f64::NAN
    } else {
        v.iter().sum::<f64>() / v.len() as f64
    }
}

/// The d2demo-protocol demosaic (verbatim: +/-2 neighbors, same-class
/// fallback) — edge-band statistic (see module docs).
fn demosaic_d2demo(img: &[u16], W: usize, H: usize) -> [f64; 3] {
    let mut ch: [Vec<f64>; 3] = [vec![0f64; W * H], vec![0f64; W * H], vec![0f64; W * H]];
    for y in 0..H {
        for x in 0..W {
            let i = y * W + x;
            let c0 = cls_of(x, y);
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
                    if cls_of(xx, yy) == c {
                        s += img[yy * W + xx] as f64;
                        n += 1.0;
                    }
                }
                ch[c][i] = if n > 0.0 { s / n } else { img[i] as f64 };
            }
        }
    }
    let mut wg: Vec<f64> = Vec::new();
    let mut gr: Vec<f64> = Vec::new();
    let mut wr: Vec<f64> = Vec::new();
    // `i` only indexes the three equal-length `ch` channels (clippy
    // allow — the measurement loop keeps its direct index form).
    #[allow(clippy::needless_range_loop)]
    for i in 0..W * H {
        wg.push(ch[0][i] - ch[1][i]);
        gr.push(ch[1][i] - ch[2][i]);
        wr.push(ch[0][i] - ch[2][i]);
    }
    [std_of(&wg), std_of(&gr), std_of(&wr)]
}

/// Fixed full-frame demosaic: other channels = mean of the 4 same-class
/// +/-1 neighbors (this CFA's same-class pixels sit at +/-1 in the
/// other channels' parities). The honest "what a demosaic sees" metric.
fn demosaic_fixed(img: &[u16], W: usize, H: usize) -> [f64; 3] {
    // class grid: per (x,y) the class; same-class neighbors of class c at
    // (x+dx, y+dy): the 4 offsets that hit class c (computed per pixel).
    let mut ch: [Vec<f64>; 3] = [vec![0f64; W * H], vec![0f64; W * H], vec![0f64; W * H]];
    for y in 0..H {
        for x in 0..W {
            let i = y * W + x;
            let c0 = cls_of(x, y);
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
                for dy in -1i32..=1 {
                    for dx in -1i32..=1 {
                        if dx == 0 && dy == 0 {
                            continue;
                        }
                        let xx = (x as i32 + dx) as usize;
                        let yy = (y as i32 + dy) as usize;
                        if xx >= W || yy >= H {
                            continue;
                        }
                        if cls_of(xx, yy) == c {
                            s += img[yy * W + xx] as f64;
                            n += 1.0;
                        }
                    }
                }
                ch[c][i] = if n > 0.0 { s / n } else { img[i] as f64 };
            }
        }
    }
    let mut wg: Vec<f64> = Vec::new();
    let mut gr: Vec<f64> = Vec::new();
    let mut wr: Vec<f64> = Vec::new();
    // `i` only indexes the three equal-length `ch` channels (clippy
    // allow — the measurement loop keeps its direct index form).
    #[allow(clippy::needless_range_loop)]
    for i in 0..W * H {
        wg.push(ch[0][i] - ch[1][i]);
        gr.push(ch[1][i] - ch[2][i]);
        wr.push(ch[0][i] - ch[2][i]);
    }
    [std_of(&wg), std_of(&gr), std_of(&wr)]
}

/// d2diag-protocol signature of `img` vs `src` (both post-curve 12-bit).
/// One TSV line (tab-separated).
fn signature_line(label: &str, img: &[u16], src: &[u16], W: usize, H: usize) -> String {
    // MAE + per-class error
    let mut mae = 0.0f64;
    let mut csum = [0i64; 3];
    let mut ccnt = [0u64; 3];
    // h/v 2-period steps
    let mut sh: Vec<f64> = Vec::new();
    let mut dh: Vec<f64> = Vec::new();
    let mut sv: Vec<f64> = Vec::new();
    let mut dv: Vec<f64> = Vec::new();
    // per (rp, class) offset sums
    let mut psum = [[0i64; 3]; 2];
    let mut psum2 = [[0f64; 3]; 2];
    let mut pcnt = [[0u64; 3]; 2];
    // class level: per-class sum of img and src
    let mut cimg = [0i64; 3];
    let mut csrc = [0i64; 3];
    // h-step per class pair: W-row (rp0): G-W at even cp step; G-row (rp1): R-G
    // v-step per column parity: even-x (W column... x even, cp = (x-8)%2 = 0):
    // v-step = row+1 (rp1, cp0 = G) - row (rp0, cp0 = W) = G - W; odd x: R - G.
    let mut hp_wrow: Vec<f64> = Vec::new();
    let mut hp_grow: Vec<f64> = Vec::new();
    let mut vp_even: Vec<f64> = Vec::new();
    let mut vp_odd: Vec<f64> = Vec::new();
    // FLAT seam (d2diag protocol)
    let mut flat_col_seam: Vec<i64> = Vec::new();
    let mut flat_col_r1: Vec<i64> = Vec::new();
    let mut flat_col_r2: Vec<i64> = Vec::new();
    let mut flat_row_seam: Vec<i64> = Vec::new();
    let mut flat_row_r: Vec<i64> = Vec::new();
    for y in 0..H {
        let rp = ((y as i64) - CTOP).rem_euclid(2) as usize;
        for x in 0..W {
            let cp = ((x as i64) - CLEFT).rem_euclid(2) as usize;
            let c = match (rp, cp) {
                (0, 0) => 0,
                (1, 1) => 2,
                _ => 1,
            };
            let i = y * W + x;
            let d = img[i] as i64 - src[i] as i64;
            mae += d.abs() as f64;
            csum[c] += d;
            ccnt[c] += 1;
            cimg[c] += img[i] as i64;
            csrc[c] += src[i] as i64;
            psum[rp][c] += d;
            psum2[rp][c] += (d as f64).powi(2);
            pcnt[rp][c] += 1;
            if x < W - 1 {
                sh.push(src[i + 1] as i64 as f64 - src[i] as i64 as f64);
                dh.push(img[i + 1] as i64 as f64 - img[i] as i64 as f64);
            }
        }
        if y < H - 1 {
            for x in 0..W {
                let i = y * W + x;
                sv.push(src[i + W] as i64 as f64 - src[i] as i64 as f64);
                dv.push(img[i + W] as i64 as f64 - img[i] as i64 as f64);
            }
        }
    }
    let shstd = std_of(&sh);
    let dhstd = std_of(&dh);
    let svstd = std_of(&sv);
    let dvstd = std_of(&dv);
    let h_ratio = if shstd > 0.0 { dhstd / shstd } else { f64::NAN };
    let v_ratio = if svstd > 0.0 { dvstd / svstd } else { f64::NAN };
    // class-pair h-steps (img): step x -> x+1 within row y
    for y in 0..H {
        let rp = ((y as i64) - CTOP).rem_euclid(2) as usize;
        for x in 0..W - 1 {
            let cp = ((x as i64) - CLEFT).rem_euclid(2) as usize;
            let d = (img[y * W + x + 1] as i64 - img[y * W + x] as i64) as f64;
            // cp even (x even): class -> class: rp0: W->G (G-W); rp1: G->R (R-G)
            // cp odd (x odd): W row: G->W; G row: R->G (sign-flipped; we want
            // the pair magnitude with sign convention "2nd class - 1st class
            // in x order": collect even-x steps only (G-W / R-G convention).
            if cp == 0 {
                if rp == 0 {
                    hp_wrow.push(d);
                } else {
                    hp_grow.push(d);
                }
            }
        }
        if y < H - 1 {
            for x in 0..W {
                let cp = ((x as i64) - CLEFT).rem_euclid(2) as usize;
                let d = (img[(y + 1) * W + x] as i64 - img[y * W + x] as i64) as f64;
                if cp == 0 {
                    vp_even.push(d);
                } else {
                    vp_odd.push(d);
                }
            }
        }
    }
    let hp_wrow_m = mean_of(&hp_wrow);
    let hp_grow_m = mean_of(&hp_grow);
    let vp_even_m = mean_of(&vp_even);
    let vp_odd_m = mean_of(&vp_odd);
    let hp_wrow = std_of(&hp_wrow);
    let hp_grow = std_of(&hp_grow);
    let vp_even = std_of(&vp_even);
    let vp_odd = std_of(&vp_odd);
    // FLATALL block-boundary aggregates (the boundary-scan protocol,
    // whole-frame 8px grid: boundaries x=8k+7->8k+8 / y=8k+7->8k+8)
    let mut flatall_bc: Vec<i64> = Vec::new();
    let mut flatall_br: Vec<i64> = Vec::new();
    // tile-col seam splits: row parity (even-y = R->G step, odd-y = G->W)
    // and source brightness band (curve slope varies with level)
    let mut seamc_even: Vec<i64> = Vec::new();
    let mut seamc_odd: Vec<i64> = Vec::new();
    let mut seamc_dark: Vec<i64> = Vec::new(); // src[1927] < 256
    let mut seamc_mid: Vec<i64> = Vec::new(); // 256..=1023
    let mut seamc_bright: Vec<i64> = Vec::new(); // > 1023
    for y in 0..H {
        for (xa, xb, dst) in [
            (1927usize, 1928, &mut flat_col_seam),
            (1000, 1001, &mut flat_col_r1),
            (1915, 1916, &mut flat_col_r2),
        ] {
            let sstep = src[y * W + xb] as i64 - src[y * W + xa] as i64;
            if sstep.abs() < 8 {
                let d = img[y * W + xb] as i64 - img[y * W + xa] as i64;
                dst.push(d);
                if xa == 1927 {
                    if y % 2 == 0 {
                        seamc_even.push(d);
                    } else {
                        seamc_odd.push(d);
                    }
                    let sv = src[y * W + xa] as i64;
                    if sv < 256 {
                        seamc_dark.push(d);
                    } else if sv <= 1023 {
                        seamc_mid.push(d);
                    } else {
                        seamc_bright.push(d);
                    }
                }
            }
        }
    }
    for k in 0..W / 8 - 1 {
        let xa = 8 * k + 7;
        let xb = 8 * (k + 1);
        for y in 0..H {
            let sstep = src[y * W + xb] as i64 - src[y * W + xa] as i64;
            if sstep.abs() < 8 {
                flatall_bc.push(img[y * W + xb] as i64 - img[y * W + xa] as i64);
            }
        }
    }
    for k in 0..H / 8 - 1 {
        let ya = 8 * k + 7;
        let yb = 8 * (k + 1);
        for x in 0..W {
            let sstep = src[yb * W + x] as i64 - src[ya * W + x] as i64;
            if sstep.abs() < 8 {
                flatall_br.push(img[yb * W + x] as i64 - img[ya * W + x] as i64);
            }
        }
    }
    for (ya, yb, dst) in [
        (1087usize, 1088, &mut flat_row_seam),
        (500, 501, &mut flat_row_r),
    ] {
        for x in 0..W {
            let sstep = src[yb * W + x] as i64 - src[ya * W + x] as i64;
            if sstep.abs() < 8 {
                dst.push(img[yb * W + x] as i64 - img[ya * W + x] as i64);
            }
        }
    }
    let fm = |v: &[i64]| {
        if v.is_empty() {
            f64::NAN
        } else {
            v.iter().map(|x| *x as f64).sum::<f64>() / v.len() as f64
        }
    };
    let dem2 = demosaic_d2demo(img, W, H);
    let demf = demosaic_fixed(img, W, H);
    // per-(rp,class) offset mean/std
    let pofs = |rp: usize, c: usize| -> (f64, f64) {
        let n = pcnt[rp][c] as f64;
        if n == 0.0 {
            return (f64::NAN, f64::NAN);
        }
        let m = psum[rp][c] as f64 / n;
        (m, (psum2[rp][c] / n - m * m).max(0.0).sqrt())
    };
    let cm = |c: usize| (cimg[c] as f64 / ccnt[c] as f64) - (csrc[c] as f64 / ccnt[c] as f64);
    let cls3 = |c: usize| format!("{:+.3}", csum[c] as f64 / ccnt[c] as f64);
    let mut s = format!(
        "{label}\tMAE {mae:.3}\tW {wc} G {gc} R {rc}\th_ratio {hr:.3}\tv_ratio {vr:.3}\tdem2 {d2a:.2}/{d2b:.2}/{d2c:.2}\tdemf {df1:.2}/{df2:.2}/{df3:.2}\tFLAT_c* {fc:.3}\tFLAT_r* {fr:.3}\tFLAT_c1 {f1:.3}\tFLAT_c2 {f2:.3}\tFLAT_r {f0:.3}\tFALL_bc {fabc:.3}\tFALL_br {fabr:.3}\tSEAMC_e {sce:.3}\tSEAMC_o {sco:.3}\tSEAMC_d {scd:.3}\tSEAMC_m {scm:.3}\tSEAMC_b {scb:.3}\tHP_wm {hwm:.2}/sd {hws:.2}\tHP_gm {hgm:.2}/sd {hgs:.2}\tVP_e {vpe:.2}/sd {vps:.2}\tVP_o {vpo:.2}/sd {vps2:.2}\tLW {lw:.2}\tLG {lg:.2}\tLR {lr:.2}",
        mae = mae / (W * H) as f64,
        wc = cls3(0),
        gc = cls3(1),
        rc = cls3(2),
        hr = h_ratio,
        vr = v_ratio,
        d2a = dem2[0], d2b = dem2[1], d2c = dem2[2],
        df1 = demf[0], df2 = demf[1], df3 = demf[2],
        fc = fm(&flat_col_seam),
        fr = fm(&flat_row_seam),
        f1 = fm(&flat_col_r1),
        f2 = fm(&flat_col_r2),
        f0 = fm(&flat_row_r),
        fabc = fm(&flatall_bc),
        fabr = fm(&flatall_br),
        sce = fm(&seamc_even),
        sco = fm(&seamc_odd),
        scd = fm(&seamc_dark),
        scm = fm(&seamc_mid),
        scb = fm(&seamc_bright),
        hwm = hp_wrow_m,
        hws = hp_wrow,
        hgm = hp_grow_m,
        hgs = hp_grow,
        vpe = vp_even_m,
        vps = vp_even,
        vpo = vp_odd_m,
        vps2 = vp_odd,
        lw = cm(0),
        lg = cm(1),
        lr = cm(2),
    );
    // per-(rp,class) mean/std appended as p00m/p00s ... (rp 0..2, cls WGR)
    for rp in 0..2usize {
        for c in 0..3usize {
            let (m, sd) = pofs(rp, c);
            s.push_str(&format!("\tp{rp}{c}m {m:+.3}\tp{rp}{c}s {sd:.3}"));
        }
    }
    s
}

/// Run one full-frame stage: map a per-parity full-frame plane pair
/// (plane row p <-> frame row 2p + plane_idx) back to the source domain
/// via the 65536 curve, into a full W x H frame.
fn planes_to_frame(pre0: &[Vec<u16>], curve65536: &[u16], W: usize, H: usize) -> Vec<u16> {
    let fw = W;
    let mut out = vec![0u16; W * H];
    for (plane_idx, plane) in pre0.iter().enumerate() {
        let n = plane.len() / fw;
        for p in 0..n {
            let fr = 2 * p + plane_idx;
            if fr >= H {
                continue;
            }
            for x in 0..fw {
                out[fr * fw + x] = curve65536[plane[p * fw + x] as usize];
            }
        }
    }
    out
}

// ------------------------------------------------- DCT-domain helpers

/// Orthonormal DCT-II matrix (identical to lossydct::dct_matrix).
fn dmat() -> [f64; 64] {
    let mut m = [0f64; 64];
    for u in 0..8usize {
        let a = if u == 0 {
            (1.0f64 / 2.0).sqrt() / 2.0
        } else {
            0.5
        };
        for i in 0..8usize {
            let ang = (2 * i + 1) as f64 * u as f64 * core::f64::consts::PI / 16.0;
            m[u * 8 + i] = a * ang.cos();
        }
    }
    m
}

/// X_orth = A·X·Aᵀ on a centered 8x8 block (identical to
/// lossydct::block_xorth: DC slot = 8 × (block mean − 2048)). Index k = i*8+j
/// with i = vertical frequency (plane-row direction), j = horizontal
/// frequency (frame-x direction).
fn block_xorth_local(plane: &[u16], pw: usize, bx: usize, by: usize) -> [f64; 64] {
    let a = dmat();
    let mut x = [[0f64; 8]; 8];
    for i in 0..8 {
        let row = &plane[(by * 8 + i) * pw + bx * 8..(by * 8 + i) * pw + bx * 8 + 8];
        for j in 0..8 {
            x[i][j] = f64::from(row[j]) - 2048.0;
        }
    }
    let mut y = [[0f64; 8]; 8];
    for u in 0..8 {
        for k in 0..8 {
            let mut acc = 0f64;
            for l in 0..8 {
                acc += a[u * 8 + l] * x[l][k];
            }
            y[u][k] = acc;
        }
    }
    let mut out = [0f64; 64];
    for u in 0..8 {
        for v in 0..8 {
            let mut acc = 0f64;
            for k in 0..8 {
                acc += y[u][k] * a[v * 8 + k];
            }
            out[u * 8 + v] = acc;
        }
    }
    out
}

/// Natural (i*8+j) index → FILE (zigzag/DQT) position (lossydct::nat2file).
fn n2file_arr() -> [usize; 64] {
    let mut t = [0usize; 64];
    for (p, &nn) in dct2s::ZIGZAG.iter().take(64).enumerate() {
        t[nn as usize] = p;
    }
    t
}

/// The 8 parity planes (4 tiles × even/odd frame row) of a full frame
/// (12-bit or pre-domain u16) — geometry + padding identical to
/// lossydct::build_planes (plane row p ↔ frame row tile_y + 2p + si;
/// bottom-tile padding rows repeat the plane's last real row).
fn build_planes8(frame: &[u16], w: u32, h: u32) -> [Vec<u16>; 8] {
    let pw = lossydct::PLANE_W;
    let ph = lossydct::PLANE_H;
    let (W, H) = (w as usize, h as usize);
    let mut out: [Vec<u16>; 8] = [0usize; 8].map(|_| vec![0u16; pw * ph]);
    let last_real = lossydct::PLANE_H_REAL - 1;
    for tr in 0..2u32 {
        for tc in 0..2u32 {
            let ti = (tr as usize) * 2 + tc as usize;
            let fy0 = tr * lossydct::TILE_H;
            let fx0 = tc * lossydct::TILE_W;
            for si in 0..2usize {
                let plane = &mut out[ti * 2 + si];
                for p in 0..ph {
                    let fr = fy0 + 2 * p as u32 + si as u32;
                    let row_off = p * pw;
                    if (fr as usize) < H {
                        let srow = (fr as usize) * W + fx0 as usize;
                        plane[row_off..row_off + pw].copy_from_slice(&frame[srow..srow + pw]);
                    } else {
                        let lrow = last_real * pw;
                        let tmp: Vec<u16> = plane[lrow..lrow + pw].to_vec();
                        plane[row_off..row_off + pw].copy_from_slice(&tmp);
                    }
                }
            }
        }
    }
    out
}

/// Decode the 8 file parity planes (pre-domain, identity curve — the exact
/// file content; the DCT of this is the dequantized coefficient set).
fn planes_of(vb: &[u8], offs: &[u32], cnts: &[u32]) -> [Vec<u16>; 8] {
    let id = dct2s::linearization_curve(None);
    let mut out: [Vec<u16>; 8] = [0usize; 8].map(|_| Vec::new());
    for (t, (off, cnt)) in offs.iter().zip(cnts.iter()).enumerate() {
        let tile = &vb[*off as usize..(*off + *cnt) as usize];
        let info = dct2s::parse_tile(tile).unwrap();
        for si in 0..2usize {
            let (recon, _) = dct2s::decode_scan_plane(tile, &info, si, &id).unwrap();
            out[t * 2 + si] = recon;
        }
    }
    out
}

/// MSQ per (i,j) (natural order, k = i*8+j): pooled over the 8 planes,
/// plus the even/odd-parity split.
fn msq_decomp(planes: &[Vec<u16>; 8]) -> (Vec<f64>, Vec<f64>, Vec<f64>) {
    let mut tot = vec![0f64; 64];
    let mut par = vec![0f64; 128];
    let pw = lossydct::PLANE_W;
    let ph = lossydct::PLANE_H;
    let nbw = pw / 8;
    let nbh = ph / 8;
    for (pi, plane) in planes.iter().enumerate() {
        let si = pi % 2;
        for by in 0..nbh {
            for bx in 0..nbw {
                let x = block_xorth_local(plane, pw, bx, by);
                for k in 0..64 {
                    let v = x[k] * x[k];
                    tot[k] += v;
                    par[si * 64 + k] += v;
                }
            }
        }
    }
    (tot, par[0..64].to_vec(), par[64..128].to_vec())
}

/// MSQ per (i,j) of the inter-plane difference D = odd-plane − even-plane
/// (per tile, same 8x8 grid). The v-step (frame-y step at fixed x) equals
/// D exactly; its (−1)^x part is the j=7 column of this DCT.
fn msq_decomp_diff(planes: &[Vec<u16>; 8]) -> Vec<f64> {
    let pw = lossydct::PLANE_W;
    let ph = lossydct::PLANE_H;
    let nbw = pw / 8;
    let nbh = ph / 8;
    let mut tot = vec![0f64; 64];
    for t in 0..4usize {
        let even = &planes[t * 2];
        let odd = &planes[t * 2 + 1];
        let mut d = vec![0i32; pw * ph];
        for (i, &e) in even.iter().enumerate() {
            d[i] = odd[i] as i32 - e as i32;
        }
        // DCT needs u16 (centered by −2048 internally): shift into range
        let mut d16 = vec![0u16; pw * ph];
        for (i, &v) in d.iter().enumerate() {
            d16[i] = (v + 2048).clamp(0, 4095) as u16;
        }
        for by in 0..nbh {
            for bx in 0..nbw {
                // the −2048 centering inside block_xorth cancels the shift
                let x = block_xorth_local(&d16, pw, bx, by);
                // re-centering: block_xorth subtracted 2048 from (D+2048)
                // = D exactly. (DC slot = 8×mean(D) ✓)
                for k in 0..64 {
                    tot[k] += x[k] * x[k];
                }
            }
        }
    }
    tot
}

/// One band summary line: name + MSQ trio + ratios.
fn band_line(label: &str, idx: &[usize], s: &[f64], v: &[f64], o: &[f64]) -> String {
    let m = |a: &[f64]| idx.iter().map(|&k| a[k]).sum::<f64>();
    let (ms, mv, mo) = (m(s), m(v), m(o));
    format!(
        "band {label:<6}\tsrc {ms:.1}\tven {mv:.1}\tours {mo:.1}\tven/src {rv:.3}\tours/src {ro:.3}",
        rv = if ms > 0.0 { mv / ms } else { f64::NAN },
        ro = if ms > 0.0 { mo / ms } else { f64::NAN }
    )
}

use frameprism::ljpeg_ffi::{
    ljpeg_comp_error, ljpeg_comp_free, ljpeg_comp_new, ljpeg_encode_coeff12, ljpeg_free_buffer,
}; // the ljpeg raw-coefficient shim symbols (single home in the lib)

/// libjpeg 12-bit quantize (identical to lossydct::quantize_index):
/// (t + q/2)/q, C truncation toward zero.
fn quant_local(t: f64, q: i64) -> i64 {
    ((t + (q as f64) * 0.5) / (q as f64)).trunc() as i64
}

/// Encode pre-quantized qcodes (natural order, 241×68 blocks × 64) into the
/// 1-component 12-bit stream (mirror of lossydct::encode_coeffs_plane).
fn encode_coeffs_local(coeffs: &[i16], table: &[u16; 64]) -> Vec<u8> {
    let h = unsafe { ljpeg_comp_new() };
    if h.is_null() {
        panic!("ljpeg_comp_new returned null");
    }
    let mut outbuf: *mut u8 = std::ptr::null_mut();
    let mut outsize: core::ffi::c_ulong = 0;
    let rc = unsafe {
        ljpeg_encode_coeff12(
            h,
            coeffs.as_ptr(),
            lossydct::PLANE_W as core::ffi::c_int,
            lossydct::PLANE_H as core::ffi::c_int,
            table.as_ptr(),
            &mut outbuf,
            &mut outsize,
        )
    };
    if rc != 0 {
        let msg = unsafe { std::ffi::CStr::from_ptr(ljpeg_comp_error(h)) }
            .to_string_lossy()
            .into_owned();
        unsafe {
            ljpeg_comp_free(h);
        };
        panic!("ljpeg_encode_coeff12: {msg}");
    }
    let jpeg = unsafe { std::slice::from_raw_parts(outbuf, outsize as usize) }.to_vec();
    unsafe {
        ljpeg_free_buffer(outbuf as *mut core::ffi::c_void);
        ljpeg_comp_free(h);
    };
    jpeg
}

/// `parse_dctcand_spec` result: (use_2tap, base_scale[64],
/// parity_scale[2][64] (-1 = unset), then the remaining scale/flag
/// fields) — named type for clippy type_complexity .
type DctcandSpec = (bool, [f64; 64], [[f64; 64]; 2], f64, usize, f64, bool, bool);

/// Parse a dctcand spec: optional "2tap+" prefix, then `name=value` terms.
/// Returns (use_2tap, base_scale[64], parity_scale[2][64] (-1 = unset)).
fn parse_dctcand_spec(spec: &str) -> DctcandSpec {
    let (use_2tap, terms) = match spec.strip_prefix("2tap+") {
        Some(t) => (true, t),
        None => (false, spec),
    };
    let mut dcmix_g = 0.0f64; // inter-plane DC (D = odd − even) gain; 0 = off
    let mut idpre = false; // identity pre-domain: raw invLUT, no box3/snap
    let mut dcmix_k = 0usize; // box half-size on the block grid (dcmix2)
    let mut d12_g = 0.0f64; // 12-bit source-space inter-row D gain; 0 = off
    let mut notch12 = false; // 12-bit per-row (−1)^x notch
    let mut base = [1.0f64; 64];
    let mut par = [[-1.0f64; 64]; 2];
    let set = |arr: &mut [f64; 64], i: usize, j: usize, v: f64| arr[i * 8 + j] = v;
    let set_set = |arr: &mut [f64; 64], pts: &[(usize, usize)], v: f64| {
        for &(i, j) in pts {
            set(arr, i, j, v);
        }
    };
    for term in terms.split(',').map(|t| t.trim()).filter(|t| !t.is_empty()) {
        let (name, vs) = term
            .split_once('=')
            .unwrap_or_else(|| panic!("dctcand spec term without '=': {term}"));
        let v: f64 = vs
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("bad scale {vs}"));
        let name = name.trim();
        match name {
            "dc" => set(&mut base, 0, 0, v),
            "hnq" => {
                let pts: Vec<(usize, usize)> = (0..8).map(|i| (i, 7)).collect();
                set_set(&mut base, &pts, v);
            }
            "vnq" => {
                let pts: Vec<(usize, usize)> = (0..7).map(|j| (7, j)).collect();
                set_set(&mut base, &pts, v);
            }
            "c77" => set(&mut base, 7, 7, v),
            "low" => {
                for i in 0..=2usize {
                    for j in 0..=2usize {
                        if (i, j) != (0, 0) {
                            set(&mut base, i, j, v);
                        }
                    }
                }
            }
            "mid" => {
                for i in 0..8usize {
                    for j in 0..8usize {
                        if (i.max(j) <= 4) && (i.max(j) >= 1) && !(i <= 2 && j <= 2) {
                            set(&mut base, i, j, v);
                        }
                    }
                }
            }
            "rest" => {
                for i in 0..8usize {
                    for j in 0..8usize {
                        if i.max(j) >= 5 && (i, j) != (7, 7) {
                            set(&mut base, i, j, v);
                        }
                    }
                }
            }
            "hnqe" => {
                for i in 0..8 {
                    set(&mut par[0], i, 7, v);
                }
            }
            "hnqo" => {
                for i in 0..8 {
                    set(&mut par[1], i, 7, v);
                }
            }
            "vne" => {
                for j in 0..7 {
                    set(&mut par[0], 7, j, v);
                }
            }
            "vno" => {
                for j in 0..7 {
                    set(&mut par[1], 7, j, v);
                }
            }
            "alle" => {
                par[0].fill(v);
            }
            "allo" => {
                par[1].fill(v);
            }
            "dcmix" => {
                dcmix_g = v;
            }
            "dcmixg" => {
                dcmix_g = v;
            }
            "dcmixk" => {
                dcmix_k = v as usize;
            }
            "d12" => {
                d12_g = v;
            }
            "notch12" => {
                notch12 = true;
            }
            "i0j35" => {
                set(&mut base, 0, 3, v);
                set(&mut base, 0, 5, v);
            }
            "idpre" => {
                idpre = true;
            }
            "i0j356" => {
                set(&mut base, 0, 3, v);
                set(&mut base, 0, 5, v);
                set(&mut base, 0, 6, v);
            }
            "i0hi" => {
                for j in 3..=6usize {
                    set(&mut base, 0, j, v);
                }
            }
            _ => {
                if let Some(r) = name.strip_prefix("ij=") {
                    let (ri, rj) = r.split_once(',').unwrap_or_else(|| panic!("bad ij {r}"));
                    let i: usize = ri.trim().parse().unwrap();
                    let j: usize = rj.trim().parse().unwrap();
                    set(&mut base, i, j, v);
                } else {
                    panic!("unknown dctcand spec name {name}");
                }
            }
        }
    }
    (use_2tap, base, par, dcmix_g, dcmix_k, d12_g, notch12, idpre)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: t21probe <stages|reference|cand> ...");
        std::process::exit(2);
    }
    match args[1].as_str() {
        "stages" => {
            if args.len() != 4 {
                eprintln!("usage: t21probe stages <original.dng> <ref_frame.dng>");
                std::process::exit(2);
            }
            let ob = std::fs::read(&args[2]).unwrap();
            let vb = std::fs::read(&args[3]).unwrap();
            let (w, h, _offs, _cnts, curve) = ifd(&vb);
            let oframe = tiff::read(&ob).unwrap();
            let src = pack12::unpack12(oframe.strip_slice(&ob), w, h).unwrap();
            let (W, H) = (w as usize, h as usize);
            let curve_arr: [u16; lossydct::CURVE_LEN] = {
                let mut a = [0u16; lossydct::CURVE_LEN];
                a.copy_from_slice(&curve);
                a
            };
            let curve65536 = dct2s::linearization_curve(Some(&curve));
            let inv = lossydct::inv_lut(&curve_arr);
            // header
            println!(
                "stage\tMAE\tW\tG\tR\th_ratio\tv_ratio\tdem2\tdemf\tFLAT_c*\tFLAT_r*\tFLAT_c1\tFLAT_c2\tFLAT_r\tHP_wm\thp_wsd\thp_gm\thp_gsd\tvp_e\tvp_esd\tvp_o\tvp_osd\tLW\tLG\tLR\tper(rp,cls) mean/std"
            );
            // 0: source
            println!("{}", signature_line("source", &src, &src, W, H));
            // 1: after cfa_lowpass_h
            let s2 = lossydct::cfa_lowpass_h(&src, w, h);
            println!("{}", signature_line("2tap", &s2, &src, W, H));
            // 2: after invLUT (pre0, full-frame parity planes)
            let fw = W;
            let n_rows = [h.div_ceil(2) as usize, (h / 2) as usize];
            let mut pre0 = vec![Vec::new(); 2];
            for si in 0..2usize {
                let n = n_rows[si];
                let mut pre = vec![0u16; fw * n];
                for p in 0..n {
                    let fr = 2 * p + si;
                    for x in 0..fw {
                        pre[p * fw + x] = inv[s2[fr * fw + x] as usize];
                    }
                }
                pre0[si] = pre;
            }
            let pre0f = planes_to_frame(&pre0, &curve65536, W, H);
            println!("{}", signature_line("pre0", &pre0f, &src, W, H));
            // 3: after box3 (full-frame planes)
            let prior0 = lossydct::box3_smooth_wh(&pre0[0], fw, n_rows[0]);
            let prior1 = lossydct::box3_smooth_wh(&pre0[1], fw, n_rows[1]);
            let box3f = planes_to_frame(&[prior0.clone(), prior1.clone()], &curve65536, W, H);
            println!("{}", signature_line("box3", &box3f, &src, W, H));
            // 4: after snap + tile cut (full_frame_planes)
            let planes = lossydct::full_frame_planes(&s2, w, h, &inv, &curve_arr).unwrap();
            let mut snapf = vec![0u16; W * H];
            {
                let plane_w = lossydct::PLANE_W;
                for (t, tp) in planes.iter().enumerate() {
                    let tx = (t % 2) * plane_w;
                    let ty = (t / 2) * (lossydct::PLANE_H * 2);
                    for (si, plane) in [tp.even.as_slice(), tp.odd.as_slice()].iter().enumerate() {
                        for p in 0..lossydct::PLANE_H {
                            let fr = ty + 2 * p + si;
                            if fr >= H {
                                break;
                            }
                            let row = &plane[p * plane_w..(p + 1) * plane_w];
                            for x in 0..plane_w {
                                snapf[fr * W + tx + x] = curve65536[row[x] as usize];
                            }
                        }
                    }
                }
            }
            println!("{}", signature_line("snap", &snapf, &src, W, H));
            // 5: after DCT + quantize (pre-domain recon via idct_block; DC
            // uncentered exactly as the decoder's vpred chain: 16384 + c0*q0)
            let table = lossydct::BASE_TABLE;
            let mut n2f = [0usize; 64];
            for (p, &nn) in dct2s::ZIGZAG.iter().take(64).enumerate() {
                n2f[nn as usize] = p;
            }
            let mut dctf = vec![0u16; W * H];
            for (t, tp) in planes.iter().enumerate() {
                let tx = (t % 2) * lossydct::PLANE_W;
                let ty = (t / 2) * (lossydct::PLANE_H * 2);
                for si in 0..2usize {
                    let plane = if si == 0 {
                        tp.even.as_slice()
                    } else {
                        tp.odd.as_slice()
                    };
                    let qcodes = lossydct::quantize_plane(plane, &table);
                    let nbw = lossydct::PLANE_W / 8;
                    for (b, q) in qcodes.chunks_exact(64).enumerate() {
                        let by = b / nbw;
                        let bx = b % nbw;
                        let mut x = [0i32; 64];
                        x[0] = dct2s::VPRED0 + q[0] as i32 * table[0] as i32;
                        for k in 1..64usize {
                            x[k] = q[k] as i32 * table[n2f[k]] as i32;
                        }
                        let px = dct2s::idct_block(&x);
                        let y0 = ty + by * 16; // plane row p = by*8+rr -> frame row ty + 2p + si
                        for rr in 0..8usize {
                            let fr = y0 + rr * 2 + si;
                            if fr >= H {
                                continue;
                            }
                            for cc in 0..8usize {
                                let xx = tx + bx * 8 + cc;
                                dctf[fr * W + xx] = curve65536[px[rr * 8 + cc] as usize];
                            }
                        }
                    }
                }
            }
            println!("{}", signature_line("dct", &dctf, &src, W, H));
            // 6: the real file decode of the ref DNG
            let (w2, h2, offs, cnts, curve2) = ifd(&vb);
            let curve2_65536 = dct2s::linearization_curve(Some(&curve2));
            let filedec = decode_frame(&vb, w2, h2, &offs, &cnts, &curve2_65536);
            println!("{}", signature_line("file", &filedec, &src, W, H));
        }
        "reference" => {
            if args.len() != 4 {
                eprintln!("usage: t21probe reference <ref_frame.dng> <original.dng>");
                std::process::exit(2);
            }
            let vb = std::fs::read(&args[2]).unwrap();
            let ob = std::fs::read(&args[3]).unwrap();
            let (w, h, offs, cnts, curve) = ifd(&vb);
            let curve65536 = dct2s::linearization_curve(Some(&curve));
            let oframe = tiff::read(&ob).unwrap();
            let src = pack12::unpack12(oframe.strip_slice(&ob), w, h).unwrap();
            let decoded = decode_frame(&vb, w, h, &offs, &cnts, &curve65536);
            let (W, H) = (w as usize, h as usize);
            println!("{}", signature_line("ref", &decoded, &src, W, H));
        }
        "cand" => {
            if args.len() != 5 {
                eprintln!("usage: t21probe cand <name> <original.dng> <ref_frame.dng>");
                std::process::exit(2);
            }
            let name = args[2].as_str();
            let ob = std::fs::read(&args[3]).unwrap();
            let vb = std::fs::read(&args[4]).unwrap();
            let (w, h, _offs, _cnts, curve) = ifd(&vb);
            let oframe = tiff::read(&ob).unwrap();
            let src = pack12::unpack12(oframe.strip_slice(&ob), w, h).unwrap();
            let (W, H) = (w as usize, h as usize);
            let curve_arr: [u16; lossydct::CURVE_LEN] = {
                let mut a = [0u16; lossydct::CURVE_LEN];
                a.copy_from_slice(&curve);
                a
            };
            let curve65536 = dct2s::linearization_curve(Some(&curve));
            let inv = lossydct::inv_lut(&curve_arr);
            // candidate transform (source space, full frame)
            let n = src.len();
            let s2: Vec<u16> = match name {
                "baseline" => lossydct::cfa_lowpass_h(&src, w, h),
                "identity" => src.clone(),
                "box3src" => {
                    let mut out = vec![0u16; n];
                    for y in 0..H {
                        for x in 0..W {
                            let mut s = 0u32;
                            let mut c = 0u32;
                            for dy in -1i32..=1 {
                                for dx in -1i32..=1 {
                                    let xx = (x as i32 + dx) as usize;
                                    let yy = (y as i32 + dy) as usize;
                                    if xx >= W || yy >= H {
                                        continue;
                                    }
                                    s += src[yy * W + xx] as u32;
                                    c += 1;
                                }
                            }
                            out[y * W + x] = (s / c) as u16;
                        }
                    }
                    out
                }
                "hbox5" => {
                    let mut out = vec![0u16; n];
                    for y in 0..H {
                        let ro = y * W;
                        for x in 0..W {
                            // symmetric 5-tap box, edge-replicate (x-2 .. x+2)
                            let xs: [i32; 5] = [
                                (x as i32 - 2).clamp(0, W as i32 - 1),
                                (x as i32 - 1).clamp(0, W as i32 - 1),
                                x as i32,
                                (x as i32 + 1).clamp(0, W as i32 - 1),
                                (x as i32 + 2).clamp(0, W as i32 - 1),
                            ];
                            let mut s = 0u32;
                            for &xx in xs.iter() {
                                s += src[ro + xx as usize] as u32;
                            }
                            out[ro + x] = (s / 5) as u16;
                        }
                    }
                    out
                }
                "v2tap" => {
                    let mut out = vec![0u16; n];
                    for y in 0..H {
                        let yb = (y + 1).min(H - 1);
                        for x in 0..W {
                            out[y * W + x] =
                                ((src[y * W + x] as u32 + src[yb * W + x] as u32) / 2) as u16;
                        }
                    }
                    out
                }
                "hv2tap" => {
                    let h2 = lossydct::cfa_lowpass_h(&src, w, h);
                    let mut out = vec![0u16; n];
                    for y in 0..H {
                        let yb = (y + 1).min(H - 1);
                        for x in 0..W {
                            out[y * W + x] =
                                ((h2[y * W + x] as u32 + h2[yb * W + x] as u32) / 2) as u16;
                        }
                    }
                    out
                }
                // u7notch + horizontal 3-tap box (reference h-crushing variant):
                // notch first (removes the exact x-2-period), then a 3-tap
                // h-average that crushes the u3/u5 x-harmonics (the thin-stripe
                // h-texture) while preserving slow h-gradients at 60%.
                "notch3" => {
                    let notched = {
                        let mut out = vec![0u16; n];
                        for y in 0..H {
                            let ro = y * W;
                            let (mut se, mut ne) = (0i64, 0i64);
                            let (mut so, mut no) = (0i64, 0i64);
                            for x in 0..W {
                                let v = src[ro + x] as i64;
                                if x % 2 == 0 {
                                    se += v;
                                    ne += 1;
                                } else {
                                    so += v;
                                    no += 1;
                                }
                            }
                            let a = (se / ne - so / no) / 2;
                            for x in 0..W {
                                let v = src[ro + x] as i64;
                                let v = v - if x % 2 == 0 { a } else { -a };
                                out[ro + x] = v.clamp(0, 4095) as u16;
                            }
                        }
                        out
                    };
                    let mut out = vec![0u16; n];
                    for y in 0..H {
                        let ro = y * W;
                        for x in 0..W {
                            let l = if x > 0 {
                                notched[ro + x - 1]
                            } else {
                                notched[ro]
                            };
                            let r = if x + 1 < W {
                                notched[ro + x + 1]
                            } else {
                                notched[ro]
                            };
                            out[ro + x] =
                                ((l as u32 + 2 * notched[ro + x] as u32 + r as u32) / 4) as u16;
                        }
                    }
                    out
                }
                // Reference-mechanism candidate (probe): the per-row
                // x-2-period (u=7) notch. out = s - a[y]·(−1)^x with a[y] =
                // (row even-x mean − row odd-x mean)/2. Removes each row's
                // 2-period (class) component exactly, preserves all other
                // per-pixel structure (v-texture, per-pixel class fluctuation,
                // wide-band h-texture). Derived from the measured
                // per-(rp,class) offsets = exact 2-tap class signature with
                // full per-pixel texture retention (see probe-report).
                "u7notch" => {
                    let mut out = vec![0u16; n];
                    for y in 0..H {
                        let ro = y * W;
                        let (mut se, mut ne) = (0i64, 0i64);
                        let (mut so, mut no) = (0i64, 0i64);
                        for x in 0..W {
                            let v = src[ro + x] as i64;
                            if x % 2 == 0 {
                                se += v;
                                ne += 1;
                            } else {
                                so += v;
                                no += 1;
                            }
                        }
                        let a = (se / ne - so / no) / 2;
                        for x in 0..W {
                            let v = src[ro + x] as i64;
                            let v = v - if x % 2 == 0 { a } else { -a };
                            out[ro + x] = v.clamp(0, 4095) as u16;
                        }
                    }
                    out
                }
                other => {
                    eprintln!("unknown candidate {other}");
                    std::process::exit(2);
                }
            };
            let planes = lossydct::full_frame_planes(&s2, w, h, &inv, &curve_arr).unwrap();
            let tiles = lossydct::encode_tiles(&planes, &lossydct::BASE_TABLE).unwrap();
            let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
            let decoded =
                dct2s::assemble_frame(&refs, lossydct::TILE_W, lossydct::TILE_H, w, h, &curve65536)
                    .unwrap();
            println!("{name}\t{}", signature_line(name, &decoded, &src, W, H));
        }
        "flatrows" => {
            // d2diag FLAT row-step protocol for a list of row pairs:
            // FLAT step mean (|src step| < 8 mask) of decode[y+1] - decode[y].
            // Usage: t21probe flatrows <ref.dng> <original.dng> y0 y1
            if args.len() != 6 {
                eprintln!("usage: t21probe flatrows <ref.dng> <original.dng> <y0> <y1>");
                std::process::exit(2);
            }
            let y0: usize = args[4].parse().unwrap();
            let y1: usize = args[5].parse().unwrap();
            let vb = std::fs::read(&args[2]).unwrap();
            let ob = std::fs::read(&args[3]).unwrap();
            let (w, h, offs, cnts, curve) = ifd(&vb);
            let curve65536 = dct2s::linearization_curve(Some(&curve));
            let oframe = tiff::read(&ob).unwrap();
            let src = pack12::unpack12(oframe.strip_slice(&ob), w, h).unwrap();
            let decoded = decode_frame(&vb, w, h, &offs, &cnts, &curve65536);
            let (W, H) = (w as usize, h as usize);
            for y in y0.min(H - 1)..y1.min(H - 1) {
                let mut ds: Vec<i64> = Vec::new();
                for x in 0..W {
                    let sstep = src[(y + 1) * W + x] as i64 - src[y * W + x] as i64;
                    if sstep.abs() < 8 {
                        ds.push(decoded[(y + 1) * W + x] as i64 - decoded[y * W + x] as i64);
                    }
                }
                if ds.is_empty() {
                    continue;
                }
                let m = ds.iter().map(|v| *v as f64).sum::<f64>() / ds.len() as f64;
                let sd = (ds.iter().map(|v| ((*v as f64) - m).powi(2)).sum::<f64>()
                    / ds.len() as f64)
                    .sqrt();
                // parity split (FLAT-masked): even-x vs odd-x decoded row step
                let mut de: Vec<i64> = Vec::new();
                let mut do_: Vec<i64> = Vec::new();
                for x in 0..W {
                    let sstep = src[(y + 1) * W + x] as i64 - src[y * W + x] as i64;
                    if sstep.abs() < 8 {
                        if x % 2 == 0 {
                            de.push(decoded[(y + 1) * W + x] as i64 - decoded[y * W + x] as i64);
                        } else {
                            do_.push(decoded[(y + 1) * W + x] as i64 - decoded[y * W + x] as i64);
                        }
                    }
                }
                let pm = |v: &[i64]| {
                    if v.is_empty() {
                        f64::NAN
                    } else {
                        v.iter().map(|x| *x as f64).sum::<f64>() / v.len() as f64
                    }
                };
                println!("rowpair {y:>5} n {len} flatstep mean {m:+.3} std {sd:.3} | even-x {me:+.3} (n {ne}) odd-x {mo:+.3} (n {no_})", len = ds.len(), me = pm(&de), ne = de.len(), mo = pm(&do_), no_ = do_.len());
            }
        }
        "rows" => {
            // Per-row (decode - source) mean profile: localizes row-parity /
            // block-row DC structure in the ref decode (reference or ours).
            // Usage: t21probe rows <ref.dng> <original.dng> <y0> <y1>
            if args.len() != 6 {
                eprintln!("usage: t21probe rows <ref_frame.dng> <original.dng> <y0> <y1>");
                std::process::exit(2);
            }
            let y0: usize = args[4].parse().unwrap();
            let y1: usize = args[5].parse().unwrap();
            let vb = std::fs::read(&args[2]).unwrap();
            let ob = std::fs::read(&args[3]).unwrap();
            let (w, h, offs, cnts, curve) = ifd(&vb);
            let curve65536 = dct2s::linearization_curve(Some(&curve));
            let oframe = tiff::read(&ob).unwrap();
            let src = pack12::unpack12(oframe.strip_slice(&ob), w, h).unwrap();
            let decoded = decode_frame(&vb, w, h, &offs, &cnts, &curve65536);
            let (W, H) = (w as usize, h as usize);
            for y in y0.min(H)..y1.min(H) {
                let d: Vec<f64> = (0..W)
                    .map(|x| decoded[y * W + x] as f64 - src[y * W + x] as f64)
                    .collect();
                let m = d.iter().sum::<f64>() / d.len() as f64;
                let mut m2 = 0f64;
                for v in d.iter() {
                    m2 += (v - m).powi(2);
                }
                let sd = (m2 / d.len() as f64).sqrt();
                // block row: which 8x8 block row contains frame row y (tile-local)
                let ty = y % 1088;
                let br = ty / 8;
                println!("row {y:>5} blkrow {br:>3} mean {m:+.3} std {sd:.3}");
            }
        }
        "dqt" => {
            if args.len() != 3 {
                eprintln!("usage: t21probe dqt <ref_frame.dng>");
                std::process::exit(2);
            }
            let vb = std::fs::read(&args[2]).unwrap();
            let (_w, _h, offs, _cnts, _curve) = ifd(&vb);
            let tile = &vb[offs[0] as usize..(offs[0] + _cnts[0]) as usize];
            let info = dct2s::parse_tile(tile).unwrap();
            let dqt = *info.dqt.get(&0).expect("DQT tq0");
            let n2f = n2file_arr();
            let grid = |t: &[u16; 64]| {
                let mut g = vec![];
                for i in 0..8 {
                    let mut row = vec![];
                    for j in 0..8 {
                        row.push(t[n2f[i * 8 + j]] as usize);
                    }
                    g.push(
                        row.iter()
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join("\t"),
                    );
                }
                g.join("\n")
            };
            println!(
                "DQT of {} as (i,j) grid (i = vertical freq / plane-row dir, j = horizontal freq / frame-x dir; CFA h-2period = j=7 column):",
                args[2].rsplit('/').next().unwrap()
            );
            println!("{}", grid(&dqt));
            println!("BASE_TABLE (ours vbr-hq) same grid:");
            println!("{}", grid(&lossydct::BASE_TABLE));
        }
        "decomp" => {
            if args.len() != 5 {
                eprintln!("usage: t21probe decomp <original.dng> <ref.dng> <ours.dng>");
                std::process::exit(2);
            }
            let ob = std::fs::read(&args[2]).unwrap();
            let vv = std::fs::read(&args[3]).unwrap();
            let uv = std::fs::read(&args[4]).unwrap();
            let (w, h, _offs, _cnts, curve) = ifd(&vv);
            let curve_arr: [u16; lossydct::CURVE_LEN] = {
                let mut a = [0u16; lossydct::CURVE_LEN];
                a.copy_from_slice(&curve);
                a
            };
            let oframe = tiff::read(&ob).unwrap();
            let src = pack12::unpack12(oframe.strip_slice(&ob), w, h).unwrap();
            let inv = lossydct::inv_lut(&curve_arr);
            // source pre-domain planes (invLUT, no pre-transform — the
            // available content); reference/ours: exact file pre-domain content
            let src_pre: Vec<u16> = src.iter().map(|&v| inv[v as usize]).collect();
            let sp = build_planes8(&src_pre, w, h);
            let (s_tot, s_e, s_o) = msq_decomp(&sp);
            let s_d = msq_decomp_diff(&sp);
            let (w2, h2, offs, cnts, _c2) = ifd(&vv);
            let vp = planes_of(&vv, &offs, &cnts);
            let (v_tot, v_e, v_o) = msq_decomp(&vp);
            let v_d = msq_decomp_diff(&vp);
            let (u2, h3, offs3, cnts3, _c3) = ifd(&uv);
            let op = planes_of(&uv, &offs3, &cnts3);
            let (o_tot, _o_e, _o_o) = msq_decomp(&op);
            let o_d = msq_decomp_diff(&op);
            let _ = (w2, h2, u2, h3);
            let mut out = String::new();
            out.push_str("=== per-plane MSQ (pooled over 4 tiles) (i = vertical freq, j = horizontal freq) ===\n");
            out.push_str(
                "(i,j)\tMSQ_src\tMSQ_ven\tMSQ_ours\tven/src\tours/src\tvenE/srcE\tvenO/srcO\n",
            );
            for i in 0..8usize {
                for j in 0..8usize {
                    let k = i * 8 + j;
                    let rv = if s_tot[k] > 0.0 {
                        v_tot[k] / s_tot[k]
                    } else {
                        f64::NAN
                    };
                    let ro = if s_tot[k] > 0.0 {
                        o_tot[k] / s_tot[k]
                    } else {
                        f64::NAN
                    };
                    let re = if s_e[k] > 0.0 {
                        v_e[k] / s_e[k]
                    } else {
                        f64::NAN
                    };
                    let ror = if s_o[k] > 0.0 {
                        v_o[k] / s_o[k]
                    } else {
                        f64::NAN
                    };
                    out.push_str(&format!(
                        "({i},{j})\t{s:.0}\t{v:.0}\t{o:.0}\t{rv:.3}\t{ro:.3}\t{re:.3}\t{ror:.3}\n",
                        s = s_tot[k],
                        v = v_tot[k],
                        o = o_tot[k],
                        rv = rv,
                        ro = ro,
                        re = re,
                        ror = ror
                    ));
                }
            }
            out.push_str("BANDS (per-plane pooled):\n");
            let bands: [(&str, Vec<usize>); 7] = [
                ("DC", vec![0]),
                (
                    "low",
                    (0..=2usize)
                        .flat_map(|_i| 0..=2)
                        .filter(|k| *k != 0)
                        .collect(),
                ),
                (
                    "mid",
                    (0..8)
                        .flat_map(|_i| 0..8)
                        .filter(|&k| {
                            let i = k / 8;
                            let j = k % 8;
                            i.max(j) <= 4 && i.max(j) >= 1 && !(i <= 2 && j <= 2)
                        })
                        .collect(),
                ),
                (
                    "rest",
                    (0..8)
                        .flat_map(|_i| 0..8)
                        .filter(|&k| {
                            let i = k / 8;
                            let j = k % 8;
                            i.max(j) >= 5 && (i, j) != (7, 7)
                        })
                        .collect(),
                ),
                ("hnq", (0..8).map(|i| i * 8 + 7).collect()),
                ("vnq", (0..7).map(|j| 7 * 8 + j).collect()),
                ("c77", vec![7 * 8 + 7]),
            ];
            for (label, idx) in bands.iter() {
                out.push_str(&band_line(label, idx, &s_tot, &v_tot, &o_tot));
                out.push('\n');
            }
            out.push_str("\n=== INTER-PLANE DIFFERENCE D = odd − even (per tile; the v-step structure) ===\n");
            out.push_str("band\tMSQ_src\tMSQ_ven\tMSQ_ours\tven/src\tours/src\n");
            for (label, idx) in bands.iter() {
                out.push_str(&band_line(label, idx, &s_d, &v_d, &o_d));
                out.push('\n');
            }
            out.push_str(
                "(D: low/DC = the v-step SMOOTH part; hnq (j=7) = the v-step (−1)^x part)\n",
            );
            print!("{out}");
        }
        "steps2" => {
            if args.len() != 5 {
                eprintln!("usage: t21probe steps2 <original.dng> <ref.dng> <ours.dng>");
                std::process::exit(2);
            }
            let ob = std::fs::read(&args[2]).unwrap();
            let vv = std::fs::read(&args[3]).unwrap();
            let uv = std::fs::read(&args[4]).unwrap();
            let (w, h, offs, cnts, curve) = ifd(&vv);
            let curve65536 = dct2s::linearization_curve(Some(&curve));
            let oframe = tiff::read(&ob).unwrap();
            let src = pack12::unpack12(oframe.strip_slice(&ob), w, h).unwrap();
            let vdec = decode_frame(&vv, w, h, &offs, &cnts, &curve65536);
            let (w2, h2, offs3, cnts3, curve3) = ifd(&uv);
            let curve3_65536 = dct2s::linearization_curve(Some(&curve3));
            let odec = decode_frame(&uv, w2, h2, &offs3, &cnts3, &curve3_65536);
            let (W, H) = (w as usize, h as usize);
            let frames: [(&str, &Vec<u16>); 3] = [("src", &src), ("ven", &vdec), ("ours", &odec)];
            for (lbl, img) in frames.iter() {
                // class means (50719 phase [8,5])
                let mut cm = [0i64; 3];
                let mut cc = [0u64; 3];
                for y in 0..H {
                    let rp = ((y as i64) - CTOP).rem_euclid(2) as usize;
                    for x in 0..W {
                        let cp = ((x as i64) - CLEFT).rem_euclid(2) as usize;
                        let c = match (rp, cp) {
                            (0, 0) => 0,
                            (1, 1) => 2,
                            _ => 1,
                        };
                        cm[c] += img[y * W + x] as i64;
                        cc[c] += 1;
                    }
                }
                let m3 = |c: usize| cm[c] as f64 / cc[c] as f64;
                // row-parity amplitude c_h(y) = (even-x mean − odd-x mean)/2
                let mut ch: Vec<f64> = Vec::with_capacity(H);
                for y in 0..H {
                    let ro = y * W;
                    let (mut se, mut ne) = (0i64, 0i64);
                    let (mut so, mut no) = (0i64, 0i64);
                    for x in 0..W {
                        let v = img[ro + x] as i64;
                        if x % 2 == 0 {
                            se += v;
                            ne += 1;
                        } else {
                            so += v;
                            no += 1;
                        }
                    }
                    ch.push((se / ne - so / no) as f64 / 2.0);
                }
                let rms =
                    |v: &[f64]| (v.iter().map(|x| x * x).sum::<f64>() / v.len() as f64).sqrt();
                let h2p = 2.0 * rms(&ch);
                // column-parity amplitude c_v(x)
                let mut cv: Vec<f64> = Vec::with_capacity(W);
                for x in 0..W {
                    let (mut se, mut ne) = (0i64, 0i64);
                    let (mut so, mut no) = (0i64, 0i64);
                    for y in 0..H {
                        let v = img[y * W + x] as i64;
                        if y % 2 == 0 {
                            se += v;
                            ne += 1;
                        } else {
                            so += v;
                            no += 1;
                        }
                    }
                    cv.push((se / ne - so / no) as f64 / 2.0);
                }
                let v2p = 2.0 * rms(&cv);
                // total h/v step stds (d2diag protocol)
                let mut hs: Vec<f64> = Vec::new();
                let mut vs: Vec<f64> = Vec::new();
                for y in 0..H {
                    for x in 0..W - 1 {
                        hs.push(img[y * W + x + 1] as i64 as f64 - img[y * W + x] as i64 as f64);
                    }
                }
                for y in 0..H - 1 {
                    for x in 0..W {
                        vs.push(img[(y + 1) * W + x] as i64 as f64 - img[y * W + x] as i64 as f64);
                    }
                }
                let ht = std_of(&hs);
                let vt = std_of(&vs);
                let tex_h = (ht * ht - h2p * h2p).max(0.0).sqrt();
                let tex_v = (vt * vt - v2p * v2p).max(0.0).sqrt();
                // class-pair adjacent steps (d2diag HP/VP protocol)
                let mut hpw: Vec<f64> = Vec::new();
                let mut hpg: Vec<f64> = Vec::new();
                let mut vpe: Vec<f64> = Vec::new();
                let mut vpo: Vec<f64> = Vec::new();
                for y in 0..H {
                    let rp = ((y as i64) - CTOP).rem_euclid(2) as usize;
                    for x in 0..W - 1 {
                        let cp = ((x as i64) - CLEFT).rem_euclid(2) as usize;
                        if cp == 0 {
                            let d = (img[y * W + x + 1] as i64 - img[y * W + x] as i64) as f64;
                            if rp == 0 {
                                hpw.push(d);
                            } else {
                                hpg.push(d);
                            }
                        }
                    }
                    if y < H - 1 {
                        for x in 0..W {
                            let cp = ((x as i64) - CLEFT).rem_euclid(2) as usize;
                            let d = (img[(y + 1) * W + x] as i64 - img[y * W + x] as i64) as f64;
                            if cp == 0 {
                                vpe.push(d);
                            } else {
                                vpo.push(d);
                            }
                        }
                    }
                }
                println!(
                    "{lbl}: classMeans W {mw:.1} G {mg:.1} R {mr:.1} | h-step {ht:.2} (2period {h2p:.2} tex {tex_h:.2}) | v-step {vt:.2} (2period {v2p:.2} tex {tex_v:.2}) | HPw {hpw:.2}/HPg {hpg:.2} VPe {vpe:.2}/VPo {vpo:.2}",
                    mw = m3(0), mg = m3(1), mr = m3(2),
                    ht = ht, h2p = h2p, tex_h = tex_h,
                    vt = vt, v2p = v2p, tex_v = tex_v,
                    hpw = std_of(&hpw), hpg = std_of(&hpg), vpe = std_of(&vpe), vpo = std_of(&vpo),
                );
            }
        }
        "dctcand" => {
            if args.len() != 5 {
                eprintln!("usage: t21probe dctcand <spec> <original.dng> <ref_frame.dng>");
                eprintln!("  spec: [2tap+]name=value[,...] — see module docs");
                std::process::exit(2);
            }
            let spec = args[2].as_str();
            let (use_2tap, base, par, dcmix_g, dcmix_k, d12_g, notch12, idpre) =
                parse_dctcand_spec(spec);
            let ob = std::fs::read(&args[3]).unwrap();
            let vb = std::fs::read(&args[4]).unwrap();
            let (w, h, _offs, _cnts, curve) = ifd(&vb);
            let curve_arr: [u16; lossydct::CURVE_LEN] = {
                let mut a = [0u16; lossydct::CURVE_LEN];
                a.copy_from_slice(&curve);
                a
            };
            let curve65536 = dct2s::linearization_curve(Some(&curve));
            let oframe = tiff::read(&ob).unwrap();
            let src = pack12::unpack12(oframe.strip_slice(&ob), w, h).unwrap();
            let (W, H) = (w as usize, h as usize);
            let inv = lossydct::inv_lut(&curve_arr);
            let mut s2: Vec<u16> = if use_2tap {
                lossydct::cfa_lowpass_h(&src, w, h)
            } else {
                src.clone()
            };
            // 12-bit source-space inter-row (class) D gain: per (even-row,
            // odd-row) pair at each column: D = odd − even (the per-pixel
            // class difference, 12-bit), D' = G·D, even' = even − D'/2,
            // odd' = odd + D'/2 (the row-pair mean preserved; the curve
            // slope cancels — a brightness-independent 12-bit gain, the
            // the measured ~7-10× pre-domain D gain expressed post-curve).
            if d12_g != 0.0 {
                let mut out = vec![0u16; W * H];
                let mut y = 0usize;
                while y + 1 < H {
                    for x in 0..W {
                        let a = src[y * W + x] as f64;
                        let b = src[(y + 1) * W + x] as f64;
                        let d = (b - a) * d12_g;
                        out[y * W + x] = (a - d / 2.0).clamp(0.0, 4095.0) as u16;
                        out[(y + 1) * W + x] = (b + d / 2.0).clamp(0.0, 4095.0) as u16;
                    }
                    y += 2;
                }
                s2 = out;
            }
            // 12-bit per-row (−1)^x notch: removes each row's even-x/odd-x
            // alternation exactly (the within-row CFA class offset — the
            // (−1)^x 2-period that causes the banding).
            if notch12 {
                for y in 0..H {
                    let ro = y * W;
                    let (mut se, mut ne) = (0f64, 0.0);
                    let (mut so, mut no) = (0f64, 0.0);
                    for x in 0..W {
                        let v = s2[ro + x] as f64;
                        if x % 2 == 0 {
                            se += v;
                            ne += 1.0;
                        } else {
                            so += v;
                            no += 1.0;
                        }
                    }
                    let c = (se / ne - so / no) / 2.0;
                    for x in 0..W {
                        let v = s2[ro + x] as f64 - if x % 2 == 0 { c } else { -c };
                        s2[ro + x] = v.clamp(0.0, 4095.0) as u16;
                    }
                }
            }
            let planes: [lossydct::TilePlanes; 4] = if idpre {
                // identity pre-domain: raw invLUT of the source, no box3, no
                // snap (same tile geometry + padding via build_planes8)
                let pre_frame: Vec<u16> = s2.iter().map(|&v| inv[v as usize]).collect();
                let p8 = build_planes8(&pre_frame, w, h);
                [
                    lossydct::TilePlanes {
                        even: p8[0].to_vec(),
                        odd: p8[1].to_vec(),
                    },
                    lossydct::TilePlanes {
                        even: p8[2].to_vec(),
                        odd: p8[3].to_vec(),
                    },
                    lossydct::TilePlanes {
                        even: p8[4].to_vec(),
                        odd: p8[5].to_vec(),
                    },
                    lossydct::TilePlanes {
                        even: p8[6].to_vec(),
                        odd: p8[7].to_vec(),
                    },
                ]
            } else {
                lossydct::full_frame_planes(&s2, w, h, &inv, &curve_arr).unwrap()
            };
            let table = lossydct::BASE_TABLE;
            let n2f = n2file_arr();
            let q: [i64; 64] = core::array::from_fn(|p| i64::from(table[p]));
            let pw = lossydct::PLANE_W;
            let ph = lossydct::PLANE_H;
            let nbw = pw / 8;
            let nbh = ph / 8;
            let mut refs: Vec<Vec<u8>> = Vec::new();
            for tp in planes.iter() {
                let mut xs: [Vec<[f64; 64]>; 2] =
                    [vec![[0f64; 64]; nbw * nbh], vec![[0f64; 64]; nbw * nbh]];
                for (si, plane) in [tp.even.as_slice(), tp.odd.as_slice()].iter().enumerate() {
                    let mut b = 0usize;
                    for by in 0..nbh {
                        for bx in 0..nbw {
                            xs[si][b] = block_xorth_local(plane, pw, bx, by);
                            b += 1;
                        }
                    }
                }
                // cross-plane DC mixing (the measured D gain), same block grid.
                // k = 0: plain per-block gain. k > 0: band-limited gain
                // D' = G·D − (G−1)·box(2k+1)(D) on the block grid (the
                // fine-scale inter-row difference amplified G×, the
                // coarse-scale (column) part preserved ~1× — the measured
                // scale-dependent gain).
                if dcmix_g != 0.0 {
                    let nd: Vec<f64> = (0..nbw * nbh).map(|b| xs[1][b][0] - xs[0][b][0]).collect();
                    let dsm: Option<Vec<f64>> = if dcmix_k == 0 {
                        None // plain per-block gain D' = G·D
                    } else {
                        let mut out = vec![0f64; nbw * nbh];
                        for by in 0..nbh {
                            for bx in 0..nbw {
                                let (mut s, mut n) = (0f64, 0.0);
                                for ky in by.saturating_sub(dcmix_k)..=(by + dcmix_k).min(nbh - 1) {
                                    for kx in
                                        bx.saturating_sub(dcmix_k)..=(bx + dcmix_k).min(nbw - 1)
                                    {
                                        s += nd[ky * nbw + kx];
                                        n += 1.0;
                                    }
                                }
                                out[by * nbw + bx] = s / n;
                            }
                        }
                        Some(out)
                    };
                    for b in 0..nbw * nbh {
                        let o = xs[1][b][0];
                        let e = xs[0][b][0];
                        let l = (o + e) / 2.0;
                        let d = nd[b];
                        let d2 = match &dsm {
                            None => dcmix_g * d,
                            Some(sm) => dcmix_g * d - (dcmix_g - 1.0) * sm[b],
                        };
                        xs[1][b][0] = l + d2 / 2.0;
                        xs[0][b][0] = l - d2 / 2.0;
                    }
                }
                let mut jpegs: Vec<Vec<u8>> = Vec::new();
                for si in 0..2usize {
                    let mut qcodes = vec![0i16; nbw * nbh * 64];
                    let mut o = 0usize;
                    for (b, x) in xs[si].iter().enumerate() {
                        for (k, &xo) in x.iter().enumerate() {
                            let sv = if par[si][k] >= 0.0 {
                                par[si][k]
                            } else {
                                base[k]
                            };
                            let c = quant_local(xo * sv, q[n2f[k]]);
                            qcodes[o + k] = c.clamp(i16::MIN as i64, i16::MAX as i64) as i16;
                        }
                        o += 64;
                        let _ = b;
                    }
                    jpegs.push(encode_coeffs_local(&qcodes, &table));
                }
                let stitched = lossydct::stitch_tile(&jpegs[0], &jpegs[1], &table).unwrap();
                refs.push(stitched);
            }
            let decoded = dct2s::assemble_frame(
                &refs.iter().map(|r| r.as_slice()).collect::<Vec<_>>(),
                lossydct::TILE_W,
                lossydct::TILE_H,
                w,
                h,
                &curve65536,
            )
            .unwrap();
            println!("{spec}\t{}", signature_line(spec, &decoded, &src, W, H));
        }
        other => {
            eprintln!("unknown subcommand {other}");
            std::process::exit(2);
        }
    }
}
