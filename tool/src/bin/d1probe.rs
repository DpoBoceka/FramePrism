// d1probe: localize the D1 defect (the 4.00× CFA-band amplification).
//
// Encodes a synthetic 1928×544 plane carrying ONLY the 2-column-period
// pattern (the Sigma CFA R/G band) through the real encoder path
// (lossydct::encode_plane → ljpeg_encode_dct12 / libjpeg islow DCT), stitches
// a reference tile, then:
//   (1) decodes the plane with the project decoder (dct2s, identity curve)
//       and measures the reconstructed 2-period contrast vs the input;
//   (2) extracts the DEQUANTIZED coefficients actually written into the
//       bitstream (dct2s::decode_scan) for block (0,0) and compares them
//       against an independent reference DCT-II (float64, written inline)
//       quantized with the same table.
//
// If (2) shows the file coefficients ≈ the reference → the encoder DCT is
// correct and the amplification (if any) is in the decoder IDCT. If the file
// coefficients are ≈ 4× the reference on the 2-period band → the encoder
// wrote wrong coefficients (encoder-side DCT/normalization bug).

use frameprism::{dct2s, lossydct};

/// Independent reference DCT-II (float64, O(n^2)) of one 8-sample row:
/// X(u) = 2/8 * sum_x x(x) * cos(pi/8 * (2x+1) * u).
fn ref_dct1d(x: &[f64; 8]) -> [f64; 8] {
    let mut out = [0f64; 8];
    // `u` is the DCT output index AND a value input (the cos argument), so
    // the range loop is the direct form (clippy allow).
    #[allow(clippy::needless_range_loop)]
    for u in 0..8 {
        let mut s = 0.0;
        for (xi, v) in x.iter().enumerate() {
            s += v * (((2 * xi + 1) * u) as f64 * std::f64::consts::PI / 8.0).cos();
        }
        out[u] = (2.0 / 8.0) * s;
    }
    out
}

fn contrast(plane: &[u16], w: usize) -> f64 {
    // |mean(odd cols) - mean(even cols)| over the whole plane.
    let (mut se, mut oe, mut ne, mut no) = (0f64, 0f64, 0f64, 0f64);
    for y in 0..plane.len() / w {
        for x in 0..w {
            let v = plane[y * w + x] as f64;
            if x % 2 == 0 {
                se += v;
                ne += 1.0;
            } else {
                oe += v;
                no += 1.0;
            }
        }
    }
    (oe / no - se / ne).abs()
}

fn main() {
    let w = lossydct::PLANE_W;
    let h = lossydct::PLANE_H;

    // Pattern 1: pure 2-column-period (the CFA band): 2048 ± 100.
    let mut even = vec![0u16; w * h];
    let mut odd = vec![0u16; w * h];
    for y in 0..h {
        for x in 0..w {
            let v = 2048i32 + if x % 2 == 0 { 100 } else { -100 };
            even[y * w + x] = v as u16;
            odd[y * w + x] = v as u16;
        }
    }
    println!("=== pattern: 2-column-period (CFA band), 2048±100 ===");
    println!("input contrast:  {:.1}", contrast(&even, w));

    let ej = lossydct::encode_plane(&even, &lossydct::BASE_TABLE).unwrap();
    let oj = lossydct::encode_plane(&odd, &lossydct::BASE_TABLE).unwrap();
    let tile = lossydct::stitch_tile(&ej, &oj, &lossydct::BASE_TABLE).unwrap();
    let info = dct2s::parse_tile(&tile).unwrap();
    let ident = dct2s::linearization_curve(None);

    let (plane, _) = dct2s::decode_scan_plane(&tile, &info, 0, &ident).unwrap();
    let dc = contrast(&plane, w);
    println!(
        "decoded contrast: {:.1}  (recon/input = {:.3})",
        dc,
        dc / 200.0
    );
    // a few decoded rows for a visual check
    for r in 0..3usize {
        println!("  row {r}: {:?}", &plane[r * w..r * w + 16]);
    }

    // Extract the file's DEQUANTIZED coefficients for block (0,0) (band 0,
    // col 0 → raster index 0) via the project's bitstream reader.
    let quant = *info.dqt.get(&0).unwrap();
    let td = info.dht.get(&0x00).unwrap();
    let ta = info.dht.get(&0x10).unwrap();
    let h_dc = dct2s::make_decoder_ref(&td.counts16, &td.syms).unwrap();
    let h_ac = dct2s::make_decoder_ref(&ta.counts16, &ta.syms).unwrap();
    let (_, ds, de) = info.sos[0];
    let (vpreds, coeffs) =
        dct2s::decode_scan(&tile[ds..de], &h_dc, &h_ac, &quant, dct2s::NB).unwrap();
    let c = &coeffs[0];
    println!("block(0,0) file coefficients (natural order):");
    println!(
        "  DC (vpred)  = {} (expect ≈ 16384 + 8*0 = 16384; pattern mean 2048 → centered 0)",
        vpreds[0]
    );
    // 2-period (−1)^x pattern: energy at v=7 (and v=3) in the COLUMN dir;
    // rows identical → u=0 only. Natural (0,3)=3, (0,7)=7.
    for v in [0usize, 1, 2, 3, 4, 5, 6, 7] {
        let zz = v; // natural (0,v) index = v
        let file_pos = dct2s::ZIGZAG
            .iter()
            .position(|&z| (z as usize) == zz)
            .unwrap();
        println!(
            "  (0,{v}) file={:>7} q[zz{file_pos}]={}",
            c[zz], quant[file_pos]
        );
    }

    // Reference DCT of the 8×8 block (all rows = [2148,1948,...]).
    let block: [f64; 8] = [
        2148.0, 1948.0, 2148.0, 1948.0, 2148.0, 1948.0, 2148.0, 1948.0,
    ];
    let xr = ref_dct1d(&block);
    println!("reference DCT-II (row 0, column frequencies):");
    for u in 0..8 {
        let file_pos = dct2s::ZIGZAG
            .iter()
            .position(|&z| (z as usize) == u)
            .unwrap();
        let q = quant[file_pos] as f64;
        let deq = (xr[u] / q).round() * q;
        let file_c = c[u] as f64;
        let refv = xr[u];
        let ratio = if deq.abs() > 1.0 {
            file_c / deq
        } else {
            f64::NAN
        };
        println!("  (0,{u}) ref={refv:>12.4}  ref_dequant={deq:>10.1}  file={file_c:>10.1}  ratio={ratio:.4}");
    }

    // DC: reference X(0) = mean·8? For orthonormal DCT-II X(0) = 2/8 * sum
    // = mean = 2048 (centered 0 → X(0) = 0 in centered domain). The file's
    // vpred is the dequantized DC coefficient = 8 * centered mean (IDCT
    // divides by 8). So expect vpred ≈ 16384 + 8*(2048-2048) = 16384.
    println!();
    println!();
    // Pattern 2: 4-column-period (1,1,−1,−1)·100 → energy at v=6 (u=0).
    let mut even2 = vec![0u16; w * h];
    for y in 0..h {
        for x in 0..w {
            let v = 2048i32 + if x % 4 < 2 { 100 } else { -100 };
            even2[y * w + x] = v as u16;
        }
    }
    println!("=== pattern: 4-column-period (1,1,-1,-1)*100 ===");
    println!("input contrast (odd-even): {:.1}", contrast(&even2, w));
    let ej2 = lossydct::encode_plane(&even2, &lossydct::BASE_TABLE).unwrap();
    let tile2 = lossydct::stitch_tile(&ej2, &oj, &lossydct::BASE_TABLE).unwrap();
    let info2 = dct2s::parse_tile(&tile2).unwrap();
    let (plane2, _) = dct2s::decode_scan_plane(&tile2, &info2, 0, &ident).unwrap();
    println!("decoded contrast (odd-even): {:.1}", contrast(&plane2, w));
    let td2 = info2.dht.get(&0x00).unwrap();
    let ta2 = info2.dht.get(&0x10).unwrap();
    let h_dc2 = dct2s::make_decoder_ref(&td2.counts16, &td2.syms).unwrap();
    let h_ac2 = dct2s::make_decoder_ref(&ta2.counts16, &ta2.syms).unwrap();
    let (_, ds2, de2) = info2.sos[0];
    let (_vpreds2, coeffs2) =
        dct2s::decode_scan(&tile2[ds2..de2], &h_dc2, &h_ac2, &quant, dct2s::NB).unwrap();
    let c2 = &coeffs2[0];
    let block2: [f64; 8] = [
        2148.0, 2148.0, 1948.0, 1948.0, 2148.0, 2148.0, 1948.0, 1948.0,
    ];
    let xr2 = ref_dct1d(&block2);
    println!("block(0,0):");
    for u in 0..8 {
        let file_pos = dct2s::ZIGZAG
            .iter()
            .position(|&z| (z as usize) == u)
            .unwrap();
        let q = quant[file_pos] as f64;
        let deq = (xr2[u] / q).round() * q;
        let file_c = c2[u] as f64;
        let refv = xr2[u];
        let ratio = if deq.abs() > 1.0 {
            file_c / deq
        } else {
            f64::NAN
        };
        println!("  (0,{u}) ref={refv:>12.4}  ref_dequant={deq:>10.1}  file={file_c:>10.1}  ratio={ratio:.4}");
    }
}
