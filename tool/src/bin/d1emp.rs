// d1emp: empirical D1/D2/D3-fix measurement on a real re-encoded frame
// (re-scoped, chained).
//
// Mirrors the FATAL gate's exact quantities on one frame:
//   cin[t] = cfa_contrast_cols of the ENCODED scan0 parity plane (the
//            gate's input pre-domain — same full_frame_planes chain the
// worker runs (full-frame box3 before the tile cut),
//   cr[t]  = cfa_contrast_cols of the tile's scan 0 decoded with the
//            IDENTITY curve (pre-curve IDCT — the measurement
//            convention),
//   (1) ratio[t] = cr / cin — required in [0, 2.0] only where the input
//       carries meaningful CFA energy (cin >= 1.0; after the 20b CFA
//       erasure cin is the erasure residual and the recon carries odd-u
//       quantization leakage — the ratio form misfires near the floor),
//   (2) source-referenced backstop: cr <= 2.0 × the ORIGINAL source's
//       CFA contrast (pre-units) — the anti-amplification invariant in
// the erased-input world (; pre-fix D1 measured 4.005×).
// Plus the per-CFA-class mean error (W/G/R, phase from 50719 [8,5]) and the
// full-frame MAE vs source (gate limit 31 LSB/class, 20b reference-recalibrated; pre-fix f1 vbr-hq:
// ours 14.46 / reference 14.36, per-class +32.6/-20.4/+28.4).
//
// Usage: d1emp <original.dng> [table_scale]   (scale 1.0 = vbr-hq BASE_TABLE;
// for CBR presets pass the 'scale' column of the encode report)

use frameprism::{dct2s, lossydct, pack12, tiff};

fn cfa_class_means(
    decoded: &[u16],
    source: &[u16],
    w: u32,
    origin: [u32; 2],
) -> ([f64; 3], f64, u32) {
    let (cleft, ctop) = (origin[0] as i64, origin[1] as i64);
    let mut sum = [0i64; 3];
    let mut cnt = [0u64; 3];
    let mut tot = 0i64;
    let mut max_e = 0u32;
    for (i, (&d, &s)) in decoded.iter().zip(source.iter()).enumerate() {
        let y = (i as u32) / w;
        let x = (i as u32) % w;
        let rp = (y as i64 - ctop).rem_euclid(2);
        let cp = (x as i64 - cleft).rem_euclid(2);
        // pattern [W G / G R]: (0,0)=W (0,1)=G (1,0)=G (1,1)=R
        let cls = match (rp, cp) {
            (0, 0) => 0,
            (0, 1) | (1, 0) => 1,
            _ => 2,
        };
        let e = d as i64 - s as i64;
        sum[cls] += e;
        cnt[cls] += 1;
        tot += e.abs();
        let ae = e.unsigned_abs(); // bounded 12-bit deltas; compare in the u64 domain
        if ae > max_e as u64 {
            max_e = ae as u32;
        }
    }
    let means = [
        sum[0] as f64 / cnt[0] as f64,
        sum[1] as f64 / cnt[1] as f64,
        sum[2] as f64 / cnt[2] as f64,
    ];
    (means, tot as f64 / decoded.len() as f64, max_e)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        eprintln!("usage: d1emp <original.dng> [table_scale]");
        std::process::exit(2);
    }
    let scale = args
        .get(2)
        .map(|s| s.parse::<f64>())
        .transpose()
        .expect("bad table_scale")
        .unwrap_or(1.0);
    let srcb = std::fs::read(&args[1]).unwrap();
    let frame = tiff::read(&srcb).unwrap();
    let packed = frame.strip_slice(&srcb);
    let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
    let (w, h) = (frame.width, frame.height);

    // Input pre-domain: the exact worker chain (CFA-erased
    // source first — the transform must precede the invLUT remap).
    let curve = lossydct::REFERENCE_CURVE;
    let inv = lossydct::inv_lut(&curve);
    let src2 = lossydct::cfa_lowpass_h(&samples, w, h);
    let planes = lossydct::full_frame_planes(&src2, w, h, &inv, &curve).unwrap();

    // Tiles at the given table scale — deterministic, same as the worker wrote.
    let table = lossydct::scale_table(scale);
    let tiles = lossydct::encode_tiles(&planes, &table).unwrap();

    let id = dct2s::linearization_curve(None); // identity
                                               // Source-referenced backstop inputs (re-scope): the ORIGINAL
                                               // (un-erased) source's CFA contrast per tile, pre-units.
    let src_orig_planes = lossydct::build_source_planes(&samples, w, h).unwrap();
    println!("tile  cin     cr      ratio   srcCFA  backstop(2x)");
    let mut all_ok = true;
    for (t, tile) in tiles.iter().enumerate() {
        let info = dct2s::parse_tile(tile).unwrap();
        let (recon, _) = dct2s::decode_scan_plane(tile, &info, 0, &id).unwrap();
        let cin = lossydct::cfa_contrast_cols(&planes[t].even);
        let cr = lossydct::cfa_contrast_cols(&recon);
        // (1) ratio form — only where the input carries meaningful CFA energy
        let ratio = if cin >= 1.0 { cr / cin } else { f64::NAN };
        let ratio_ok = cin < 1.0 || ratio <= 2.0;
        // (2) source-referenced backstop
        let src_pre: Vec<u16> = src_orig_planes[t]
            .even
            .iter()
            .map(|&s| inv[s as usize])
            .collect();
        let cin_src = lossydct::cfa_contrast_cols(&src_pre);
        let backstop_ok = cr <= 2.0 * cin_src;
        all_ok &= ratio_ok && backstop_ok;
        let backstop_str = if backstop_ok { "ok" } else { "FAIL" };
        let backstop_limit = 2.0 * cin_src;
        println!(
            "{t:<4} {cin:<8.4} {cr:<8.4} {ratio:.4}  {cin_src:<8.4} {backstop_limit:.4} ({backstop_str})"
        );
    }
    println!(
        "cfa-contrast gate (20b re-scoped: ratio in [0,2.0] where cin >= 1.0, + recon <= 2x source): {}",
        if all_ok { "PASS" } else { "FAIL" }
    );

    // Full-frame decode (real curve) → per-class means + MAE.
    let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
    let cp = dct2s::linearization_curve(Some(&curve));
    let decoded =
        dct2s::assemble_frame(&refs, lossydct::TILE_W, lossydct::TILE_H, w, h, &cp).unwrap();
    let (means, mae, max_e) = cfa_class_means(&decoded, &samples, w, [8, 5]);
    println!(
        "per-class mean err (W/G/R): {:+.3} / {:+.3} / {:+.3} LSB (gate: |mean| < 31 each, reference-anchored)",
        means[0], means[1], means[2]
    );
    println!(
        "full-frame MAE {mae:.3} max {max_e} LSB (pre-fix f1 vbr-hq: ours 14.46 / reference 14.36)"
    );
}
