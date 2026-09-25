//! Phase-3 diagnostic: production encode_tiles_t21 vs the probe
//! dctcand harness, tile bytes + decoded MAE for one frame. Scratch
//! diagnostic (untracked; delete after use).
//!
//! Usage: t21cmp <original.dng> <ref_frame.dng>

use frameprism::ljpeg_ffi::{
    ljpeg_comp_free, ljpeg_comp_new, ljpeg_encode_coeff12, ljpeg_free_buffer,
};
use frameprism::{dct2s, lossydct, pack12, tiff}; // the ljpeg raw-coefficient shim symbols (single home in the lib)

fn ifd(vb: &[u8]) -> (u32, u32, Vec<u16>) {
    let u16le = |o: usize| u16::from_le_bytes([vb[o], vb[o + 1]]);
    let ifd_off = u32::from_le_bytes([vb[4], vb[5], vb[6], vb[7]]) as usize;
    let n = u16le(ifd_off) as usize;
    let mut w = 0u32;
    let mut h = 0u32;
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
            0xC618 => {
                let po = po(2);
                for i in 0..cnt as usize {
                    curve.push(u16::from_le_bytes([vb[po + 2 * i], vb[po + 2 * i + 1]]));
                }
            }
            _ => {}
        }
    }
    (w, h, curve)
}

fn mae(a: &[u16], b: &[u16]) -> f64 {
    let s: i64 = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| ((*x) as i64 - (*y) as i64).abs())
        .sum();
    s as f64 / a.len() as f64
}

// ---- probe-local DCT / quant (verbatim from t21probe.rs) ----
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

fn quant_local(t: f64, q: i64) -> i64 {
    ((t + (q as f64) * 0.5) / (q as f64)).trunc() as i64
}

fn n2file_arr() -> [usize; 64] {
    let mut t = [0usize; 64];
    for (p, &nn) in dct2s::ZIGZAG.iter().take(64).enumerate() {
        t[nn as usize] = p;
    }
    t
}

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
            lossydct::PLANE_W as std::ffi::c_int,
            lossydct::PLANE_H as std::ffi::c_int,
            table.as_ptr(),
            &mut outbuf,
            &mut outsize,
        )
    };
    if rc != 0 {
        panic!("ljpeg_encode_coeff12 failed rc={rc}");
    }
    let jpeg = unsafe { std::slice::from_raw_parts(outbuf, outsize as usize) }.to_vec();
    unsafe {
        ljpeg_free_buffer(outbuf as *mut std::ffi::c_void);
        ljpeg_comp_free(h);
    };
    jpeg
}

/// The probe dctcand pipeline (hnq=0, dcmixg=8 dcmixk=T21_DC_MIX_K —
/// the band-limited mix via the same lib function as the
/// production path, i0j35=0.2) on the given planes — verbatim logic from
/// t21probe.rs.
fn probe_tiles(planes: &[lossydct::TilePlanes; 4]) -> Vec<Vec<u8>> {
    let table = lossydct::BASE_TABLE;
    let q: [i64; 64] = core::array::from_fn(|p| i64::from(table[p]));
    let n2f = n2file_arr();
    let pw = lossydct::PLANE_W;
    let ph = lossydct::PLANE_H;
    let nbw = pw / 8;
    let nbh = ph / 8;
    // spec scales: hnq=0 -> j=7 column 0; i0j35=0.2 -> (0,3),(0,5) x0.2
    // (const indices = the intended DCT bin coordinates, i=0 row j=3/5,
    // not an arithmetic mistake — clippy erasing_op fix)
    let base: [f64; 64] = {
        let mut b = [1.0f64; 64];
        for i in 0..8 {
            b[i * 8 + 7] = 0.0;
        }
        b[3] = 0.2;
        b[5] = 0.2;
        b
    };
    let mut out = Vec::new();
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
        // cross-scan DC mix — the production band-limited form:
        // D' = G·D − (G−1)·box(2K+1)(D) on the tile's block-DC grid,
        // K = T21_DC_MIX_K — the SAME lib function as encode_tiles_t21
        // (the probe-parity contract: this bin re-verifies production ≡
        // probe tile bytes after any change to either side).
        let nd: Vec<f64> = (0..nbw * nbh).map(|b| xs[1][b][0] - xs[0][b][0]).collect();
        let d2 = lossydct::t21_dc_mix_bandlimited(&nd, nbw, nbh);
        for b in 0..nbw * nbh {
            let o = xs[1][b][0];
            let e = xs[0][b][0];
            let l = (o + e) / 2.0;
            xs[1][b][0] = l + d2[b] / 2.0;
            xs[0][b][0] = l - d2[b] / 2.0;
        }
        let mut jpegs: Vec<Vec<u8>> = Vec::new();
        for plane_blocks in xs.iter() {
            let mut qcodes = vec![0i16; nbw * nbh * 64];
            let mut o = 0usize;
            for (b, x) in plane_blocks.iter().enumerate() {
                for (k, &xo) in x.iter().enumerate() {
                    let sv = base[k];
                    let c = quant_local(xo * sv, q[n2f[k]]);
                    qcodes[o + k] = c.clamp(i16::MIN as i64, i16::MAX as i64) as i16;
                }
                o += 64;
                let _ = b;
            }
            jpegs.push(encode_coeffs_local(&qcodes, &table));
        }
        out.push(lossydct::stitch_tile(&jpegs[0], &jpegs[1], &table).unwrap());
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: t21cmp <original.dng> <ref_frame.dng>");
        std::process::exit(2);
    }
    let ob = std::fs::read(&args[2 - 1]).unwrap(); // original
    let vb = std::fs::read(&args[2]).unwrap(); // ref
    let (w, h, curve) = ifd(&vb);
    let curve_arr: [u16; lossydct::CURVE_LEN] = {
        let mut a = [0u16; lossydct::CURVE_LEN];
        a.copy_from_slice(&curve);
        a
    };
    let embedded = lossydct::REFERENCE_CURVE;
    let same_curve = curve_arr == embedded;
    println!("curve: ref-file == embedded REFERENCE_CURVE: {same_curve}");
    if !same_curve {
        let diff: Vec<usize> = curve_arr
            .iter()
            .zip(embedded.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        println!(
            "  curve diffs at {} positions; first 12: {:?}",
            diff.len(),
            &diff[..12.min(diff.len())]
        );
    }
    let oframe = tiff::read(&ob).unwrap();
    let src = pack12::unpack12(oframe.strip_slice(&ob), w, h).unwrap();
    let inv = lossydct::inv_lut(&curve_arr);
    let planes = lossydct::full_frame_planes(&src, w, h, &inv, &curve_arr).unwrap();

    // production path
    let ta = lossydct::encode_tiles_t21(&planes, &lossydct::BASE_TABLE).unwrap();
    // probe path
    let tb = probe_tiles(&planes);

    let mut any_diff = false;
    for t in 0..4 {
        if ta[t] == tb[t] {
            println!("tile {t}: BYTES IDENTICAL ({} bytes)", ta[t].len());
        } else {
            any_diff = true;
            let n = ta[t].len().min(tb[t].len());
            let d = (0..n).find(|i| ta[t][*i] != tb[t][*i]);
            println!(
                "tile {t}: DIFFER (prod {} bytes, probe {} bytes) first diff @ {d:?}",
                ta[t].len(),
                tb[t].len()
            );
        }
    }

    let curve65536 = dct2s::linearization_curve(Some(&curve_arr));
    let curve65536_emb = dct2s::linearization_curve(Some(&embedded));
    let dec_a_refcurve = dct2s::assemble_frame(
        &ta.iter().map(|t| t.as_slice()).collect::<Vec<_>>(),
        lossydct::TILE_W,
        lossydct::TILE_H,
        w,
        h,
        &curve65536,
    )
    .unwrap();
    let dec_a_embcurve = dct2s::assemble_frame(
        &ta.iter().map(|t| t.as_slice()).collect::<Vec<_>>(),
        lossydct::TILE_W,
        lossydct::TILE_H,
        w,
        h,
        &curve65536_emb,
    )
    .unwrap();
    let dec_b_refcurve = dct2s::assemble_frame(
        &tb.iter().map(|t| t.as_slice()).collect::<Vec<_>>(),
        lossydct::TILE_W,
        lossydct::TILE_H,
        w,
        h,
        &curve65536,
    )
    .unwrap();
    println!(
        "MAE prod-tiles + ref-curve : {:.4}",
        mae(&dec_a_refcurve, &src)
    );
    println!(
        "MAE prod-tiles + emb-curve : {:.4}",
        mae(&dec_a_embcurve, &src)
    );
    println!(
        "MAE probe-tiles + ref-curve: {:.4}",
        mae(&dec_b_refcurve, &src)
    );
    if !any_diff {
        println!("NOTE: tiles identical — divergence (if any) is decode/curve-side only");
    }
}
