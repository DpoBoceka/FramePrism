// d2probe: — measure the CFA-erasing pre-domain transform (D2).
// Per frame (f1 dark / f86 bright / f113 mid):
//   * source CFA contrast (LSB, full frame; and pre-units via invLUT)
//   * src2 = cfa_lowpass_h(source): CFA contrast (LSB) — the erasure
// * pipeline output (full_frame_planes on src2 — chain):
//     tile0 scan0 H contrast (pre-units) — what the DCT encodes
//   * forward model: |curve(out) − source| and |curve(out) − src2|
//     (MAE / max, source 12-bit LSB) on the tile0 scan0 region — the snap
//     window now applies to src2, so the |· − src2| bound is the hard one
//     (~1.5 LSB worst case) and |· − source| includes the documented
//     ≤ adjacent-diff/2 erasure deviation.
//
// Usage: d2probe [f1 f86 f113]   (defaults: 000001 000086 000113)

use frameprism::{lossydct, pack12, tiff};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let names: Vec<String> = if args.len() > 1 {
        args[1..].to_vec()
    } else {
        vec!["000001".into(), "000086".into(), "000113".into()]
    };
    for n in &names {
        let path = format!("../testdata/originals/A001_001/A001_001_20260701_{n}.DNG");
        let srcb = std::fs::read(&path).unwrap();
        let frame = tiff::read(&srcb).unwrap();
        let (w, h) = (frame.width, frame.height);
        let samples = pack12::unpack12(frame.strip_slice(&srcb), w, h).unwrap();

        // source CFA contrast on the tile0 scan0 region (frame even rows,
        // cols 0..1928) — the full-frame even/odd mix cancels the CFA
        // signal (row classes 0/1 contribute opposite signs).
        let (mut se, mut so, mut ne, mut no) = (0f64, 0f64, 0f64, 0f64);
        for p in 0..lossydct::PLANE_H {
            for x in 0..lossydct::PLANE_W {
                let v = samples[2 * p * (w as usize) + x] as f64;
                if x % 2 == 0 {
                    se += v;
                    ne += 1.0;
                } else {
                    so += v;
                    no += 1.0;
                }
            }
        }
        let c_src_lsb = (so / no - se / ne).abs();
        let inv = lossydct::inv_lut(&lossydct::REFERENCE_CURVE);
        let (mut pe, mut po, mut pne, mut pno) = (0f64, 0f64, 0f64, 0f64);
        for p in 0..lossydct::PLANE_H {
            for x in 0..lossydct::PLANE_W {
                let s = samples[2 * p * (w as usize) + x];
                let v = inv[s as usize] as f64;
                if x % 2 == 0 {
                    pe += v;
                    pne += 1.0;
                } else {
                    po += v;
                    pno += 1.0;
                }
            }
        }
        let c_src_pre = (po / pno - pe / pne).abs();

        let src2 = lossydct::cfa_lowpass_h(&samples, w, h);
        // src2 contrast on the same region (LSB)
        let (mut s2e, mut s2o, mut s2ne, mut s2no) = (0f64, 0f64, 0f64, 0f64);
        for p in 0..lossydct::PLANE_H {
            for x in 0..lossydct::PLANE_W {
                let v = src2[2 * p * (w as usize) + x] as f64;
                if x % 2 == 0 {
                    s2e += v;
                    s2ne += 1.0;
                } else {
                    s2o += v;
                    s2no += 1.0;
                }
            }
        }
        let c_src2_lsb = (s2o / s2no - s2e / s2ne).abs();

        let planes =
            lossydct::full_frame_planes(&src2, w, h, &inv, &lossydct::REFERENCE_CURVE).unwrap();
        let out = &planes[0].even; // tile0 scan0 (pre-units)
        let c_out_pre = lossydct::cfa_contrast_cols(out);

        // tile0 scan0 region: frame row 2p, col x
        let mut fwd_src = 0i64;
        let mut fwd_src2 = 0i64;
        let mut mx_src = 0u32;
        let mut mx_src2 = 0u32;
        for (i, &o) in out.iter().enumerate() {
            let p = i / lossydct::PLANE_W;
            let x = i % lossydct::PLANE_W;
            let s = samples[2 * p * (w as usize) + x];
            let s2 = src2[2 * p * (w as usize) + x];
            let cv = lossydct::REFERENCE_CURVE[o as usize] as i64;
            let e1 = (cv - s as i64).abs();
            let e2 = (cv - s2 as i64).abs();
            fwd_src += e1;
            fwd_src2 += e2;
            if e1 as u32 > mx_src {
                mx_src = e1 as u32;
            }
            if e2 as u32 > mx_src2 {
                mx_src2 = e2 as u32;
            }
        }
        let nn = out.len() as f64;
        println!("f{n}:");
        println!(
            "  source CFA contrast (tile0 scan0): {c_src_lsb:.3} LSB / {c_src_pre:.2} pre-units"
        );
        println!(
            "  src2 (2-tap H) CFA contrast: {c_src2_lsb:.4} LSB  (erasure: {:.2}% of source)",
            100.0 * c_src2_lsb / c_src_lsb
        );
        println!("  pipeline out (tile0 scan0) H contrast: {c_out_pre:.4} pre-units  ({:.2}% of source pre)", 100.0 * c_out_pre / c_src_pre);
        println!(
            "  forward model: vs source MAE {:.4} max {mx_src} LSB | vs src2 MAE {:.4} max {mx_src2} LSB (snap window)",
            fwd_src as f64 / nn, fwd_src2 as f64 / nn
        );
    }
}
