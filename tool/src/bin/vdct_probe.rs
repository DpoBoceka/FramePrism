// scratch: f1 dct12 pipeline — dump tile0 decode stats for comparison
// against the measured reference anchor (vpred0 block0 = 4394, plane means
// ~287.9 even / ~287.3 odd, post-curve).
use frameprism::{dct2s, lossydct, pack12, tiff};

fn main() {
    let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
    let src = std::fs::read(p).unwrap();
    let frame = tiff::read(&src).unwrap();
    let packed = frame.strip_slice(&src);
    let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
    let curve = lossydct::REFERENCE_CURVE;
    let inv = lossydct::inv_lut(&curve);
    let planes = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
    let tiles = lossydct::encode_tiles(&planes, &lossydct::BASE_TABLE).unwrap();
    println!(
        "tile sizes: {:?}",
        tiles.iter().map(|t| t.len()).collect::<Vec<_>>()
    );
    for (ti, tile) in tiles.iter().enumerate() {
        let info = dct2s::parse_tile(tile).unwrap();
        let curve_padded = dct2s::linearization_curve(Some(&curve));
        for scan in 0..2usize {
            let (plane, vpreds) =
                dct2s::decode_scan_plane(tile, &info, scan, &curve_padded).unwrap();
            let n = plane.len();
            let sum: u64 = plane.iter().map(|&v| v as u64).sum();
            let mn = plane.iter().min().unwrap();
            let mx = plane.iter().max().unwrap();
            println!("tile{ti} scan{scan}: mean={:.2} min={mn} max={mx} vpred0={} vpred1={} vpred_last={}",
                sum as f64 / n as f64, vpreds[0], vpreds[1], vpreds[n / 64 - 1]);
        }
    }
    // pre-domain plane stats (tile0) for comparison with the source
    for (name, pl) in [("even", &planes[0].even), ("odd", &planes[0].odd)] {
        let sum: u64 = pl.iter().map(|&v| v as u64).sum();
        println!(
            "tile0 pre {name}: mean={:.2} min={} max={}",
            sum as f64 / pl.len() as f64,
            pl.iter().min().unwrap(),
            pl.iter().max().unwrap()
        );
    }
    // source stats (frame rows 0..1087, cols 0..1927 — tile0 region)
    let mut sum = 0u64;
    let mut n = 0usize;
    for y in 0..1088u32 {
        for x in 0..1928u32 {
            sum += samples[(y as usize) * 3856 + x as usize] as u64;
            n += 1;
        }
    }
    println!("tile0 source: mean={:.2}", sum as f64 / n as f64);
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn block0_dc_check() {
        let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let src = std::fs::read(p).unwrap();
        let frame = tiff::read(&src).unwrap();
        let packed = frame.strip_slice(&src);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = lossydct::REFERENCE_CURVE;
        let inv = lossydct::inv_lut(&curve);
        let planes = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
        // block0 of tile0 even plane: rows 0-7, cols 0-7
        let even = &planes[0].even;
        let mut sum = 0i64;
        for r in 0..8 {
            for c in 0..8 {
                sum += even[r * 1928 + c] as i64;
            }
        }
        let m = sum as f64 / 64.0;
        let expected_vpred = 16384 + (8.0 * (m - 2048.0) / 5.0).round() as i32 * 5;
        println!("block0 pre-mean={m:.2} expected vpred0={expected_vpred}");
        // flat-constant check: encode a flat 1024 plane, decode, print
        let flat = vec![1024u16; 1928 * 544];
        let fj = lossydct::encode_plane(&flat, &lossydct::BASE_TABLE).unwrap();
        let odd_flat = vec![2048u16; 1928 * 544];
        let oj = lossydct::encode_plane(&odd_flat, &lossydct::BASE_TABLE).unwrap();
        let tile = lossydct::stitch_tile(&fj, &oj, &lossydct::BASE_TABLE).unwrap();
        let info = dct2s::parse_tile(&tile).unwrap();
        let cp = dct2s::linearization_curve(Some(&curve.to_vec()));
        let (plane, vpreds) = dct2s::decode_scan_plane(&tile, &info, 0, &cp).unwrap();
        println!(
            "flat 1024: decoded[0..4]={:?} vpred0={} (expect pre-domain 1024 → curve(1024)=1024)",
            plane[0..4].to_vec(),
            vpreds[0]
        );
        let (plane1, vpreds1) = dct2s::decode_scan_plane(&tile, &info, 1, &cp).unwrap();
        println!(
            "flat 2048: decoded[0..4]={:?} vpred0={}",
            plane1[0..4].to_vec(),
            vpreds1[0]
        );
    }
}

#[cfg(test)]
mod t2 {
    use super::*;
    #[test]
    fn dht_dump() {
        let flat = vec![1024u16; 1928 * 544];
        let fj = lossydct::encode_plane(&flat, &lossydct::BASE_TABLE).unwrap();
        // find the DHT markers in the plane stream
        let mut i = 0;
        while i + 4 < fj.len() {
            if fj[i] == 0xFF && fj[i + 1] == 0xC4 {
                let ls = u16::from_be_bytes([fj[i + 2], fj[i + 3]]) as usize;
                let tctq = fj[i + 4];
                let counts: Vec<u8> = fj[i + 5..i + 5 + 16].to_vec();
                let nsym: usize = counts.iter().map(|&c| c as usize).sum();
                let syms: Vec<u8> = fj[i + 5 + 16..i + 5 + 16 + nsym].to_vec();
                println!(
                    "plane DHT {tctq:02x}: Ls={} counts={:?} first_syms={:?}",
                    ls,
                    counts,
                    &syms[..8.min(syms.len())]
                );
                i += 2 + ls;
            } else {
                i += 1;
            }
        }
        let oj = lossydct::encode_plane(&vec![2048u16; 1928 * 544], &lossydct::BASE_TABLE).unwrap();
        let tile = lossydct::stitch_tile(&fj, &oj, &lossydct::BASE_TABLE).unwrap();
        let info = dct2s::parse_tile(&tile).unwrap();
        for (tctq, dt) in &info.dht {
            println!(
                "tile  DHT {tctq:02x}: counts={:?} first_syms={:?}",
                dt.counts16,
                &dt.syms[..8.min(dt.syms.len())]
            );
        }
    }
}

#[cfg(test)]
mod t3 {
    use super::*;
    #[test]
    fn dqt_dump() {
        let flat = vec![1024u16; 1928 * 544];
        let fj = lossydct::encode_plane(&flat, &lossydct::BASE_TABLE).unwrap();
        let mut i = 0;
        while i + 4 < fj.len() {
            if fj[i] == 0xFF && fj[i + 1] == 0xDB {
                let ls = u16::from_be_bytes([fj[i + 2], fj[i + 3]]) as usize;
                let first = fj[i + 4];
                let v0 = u16::from_be_bytes([fj[i + 5], fj[i + 6]]);
                let v1 = u16::from_be_bytes([fj[i + 7], fj[i + 8]]);
                let v7 = u16::from_be_bytes([fj[i + 5 + 14], fj[i + 6 + 14]]);
                println!(
                    "plane DQT: Ls={} first_byte=0x{:02x} v0={} v1={} v7={} (BASE 5 6 7 10...)",
                    ls, first, v0, v1, v7
                );
                i += 2 + ls;
            } else {
                i += 1;
            }
        }
        let sofi = fj
            .iter()
            .position(|&b| b == 0xFF)
            .and_then(|p| (fj[p + 1] == 0xC1).then(|| p));
        if let Some(p) = sofi {
            let prec = fj[p + 5];
            let h = u16::from_be_bytes([fj[p + 6], fj[p + 7]]);
            let w = u16::from_be_bytes([fj[p + 8], fj[p + 9]]);
            println!("plane SOF1: prec={} {}x{}", prec, w, h);
        }
    }
}

#[cfg(test)]
mod t4 {
    use super::*;
    use frameprism::dct2s;
    // Decode BOTH my f1 tile and the measured f1 vbr-hq tile, compare
    // pre-domain (before curve) and post-domain (after curve) vs source.
    #[test]
    fn compare_reference_vs_ours() {
        let op = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let vp = "../testdata/reference/vbr-hq/A001_001/A001_001_20260701_000001.DNG";
        let src = std::fs::read(op).unwrap();
        let frame = tiff::read(&src).unwrap();
        let packed = frame.strip_slice(&src);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = lossydct::REFERENCE_CURVE;
        let inv = lossydct::inv_lut(&curve);

        // --- my tiles ---
        let planes = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
        let mtiles = lossydct::encode_tiles(&planes, &lossydct::BASE_TABLE).unwrap();

        // --- reference tiles (extract the 4 tile streams from the DNG) ---
        let vbuf = std::fs::read(vp).unwrap();
        let vmeta = tiff::read_meta(&vbuf).unwrap();
        let e = vmeta.endianness;
        // read 324 (TileOffsets LONG x4) + 325 (TileByteCounts LONG x4)
        let (toffs, tcnts) = {
            let mo = vmeta.ifd0.entries.iter().find(|x| x.tag == 324).unwrap();
            let mc = vmeta.ifd0.entries.iter().find(|x| x.tag == 325).unwrap();
            let (op0, _) = mo.out_of_line.unwrap();
            let (oc0, _) = mc.out_of_line.unwrap();
            let offs: Vec<u64> = (0..4)
                .map(|i| e.u32(&vbuf[(op0 as usize) + i * 4..(op0 as usize) + i * 4 + 4]) as u64)
                .collect();
            let cnts: Vec<u64> = (0..4)
                .map(|i| e.u32(&vbuf[(oc0 as usize) + i * 4..(oc0 as usize) + i * 4 + 4]) as u64)
                .collect();
            (offs, cnts)
        };
        let cp = dct2s::linearization_curve(Some(&curve.to_vec()));

        // assemble both (post-domain)
        let mut vtiles: Vec<Vec<u8>> = Vec::new();
        for i in 0..4 {
            let a = toffs[i] as usize;
            let b = (toffs[i] + tcnts[i]) as usize;
            vtiles.push(vbuf[a..b].to_vec());
        }
        let vrefs: Vec<&[u8]> = vtiles.iter().map(|t| t.as_slice()).collect();
        let vpost =
            dct2s::assemble_frame(&vrefs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        let mrefs: Vec<&[u8]> = mtiles.iter().map(|t| t.as_slice()).collect();
        let mpost =
            dct2s::assemble_frame(&mrefs, 1928, 1088, frame.width, frame.height, &cp).unwrap();

        let mae = |a: &[u16], b: &[u16]| -> f64 {
            a.iter()
                .zip(b)
                .map(|(x, y)| (*x as i64 - *y as i64).unsigned_abs() as f64)
                .sum::<f64>()
                / a.len() as f64
        };
        println!(
            "MAE(reference_post, source) = {:.3}   (TSV says 14.36)",
            mae(&vpost, &samples)
        );
        println!("MAE(our_post,     source) = {:.3}", mae(&mpost, &samples));
        println!("MAE(our_post, reference_post) = {:.3}", mae(&mpost, &vpost));

        // pre-domain: decode scan0 of tile0 for both, before curve.
        // (decode_scan_plane applies the curve; to get pre-domain, use an identity curve)
        let ident = dct2s::linearization_curve(None); // identity
        let mi = dct2s::parse_tile(&mtiles[0]).unwrap();
        let (mpre, _) = dct2s::decode_scan_plane(&mtiles[0], &mi, 0, &ident).unwrap();
        let vi = dct2s::parse_tile(&vtiles[0]).unwrap();
        let (vpre, _) = dct2s::decode_scan_plane(&vtiles[0], &vi, 0, &ident).unwrap();
        // my invLUT pre-domain for tile0 even (same geometry)
        let myinv_pre: Vec<u16> = planes[0].even.clone();
        println!(
            "MAE(reference_pre, our_decoded_pre) = {:.3}  (tile0 scan0)",
            mae(&vpre, &mpre)
        );
        println!(
            "MAE(reference_pre, invLUT_source)   = {:.3}  (tile0 scan0)",
            mae(&vpre, &myinv_pre)
        );
        // how much of the post-domain gap is flat-band? sample a few
        let n = mpre.len();
        let mut flat_gap = 0.0;
        let mut flat_n = 0;
        for i in 0..n {
            let s = samples[((i / 1928) * 2) * 3856 + (i % 1928)]; // tile0 even: frame row 2p, col c
            if s < 400 {
                flat_gap +=
                    (mpost[(i / 1928) * 3856 + (i % 1928)] as i64 - s as i64).unsigned_abs() as f64;
                flat_n += 1;
            }
        }
        if flat_n > 0 {
            println!(
                "flat-band(s<400) MAE ours = {:.3} over {} px",
                flat_gap / flat_n as f64,
                flat_n
            );
        }
    }
}

#[cfg(test)]
mod t5 {
    use super::*;
    use frameprism::dct2s;
    // Achievable-floor test: reconstruct the measured pre-domain (decode
    // reference tiles with identity curve), re-encode it with OUR encoder
    // (BASE_TABLE), decode with the real curve, measure MAE vs source.
    // If this lands near 14.36, the gap is purely pre-domain
    // reconstruction (invLUT noise) and we need a smoother pre-domain.
    #[test]
    fn floor_with_reference_predomain() {
        let op = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let vp = "../testdata/reference/vbr-hq/A001_001/A001_001_20260701_000001.DNG";
        let src = std::fs::read(op).unwrap();
        let frame = tiff::read(&src).unwrap();
        let packed = frame.strip_slice(&src);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = lossydct::REFERENCE_CURVE;
        let vbuf = std::fs::read(vp).unwrap();
        let vmeta = tiff::read_meta(&vbuf).unwrap();
        let e = vmeta.endianness;
        let mo = vmeta.ifd0.entries.iter().find(|x| x.tag == 324).unwrap();
        let mc = vmeta.ifd0.entries.iter().find(|x| x.tag == 325).unwrap();
        let (op0, _) = mo.out_of_line.unwrap();
        let (oc0, _) = mc.out_of_line.unwrap();
        let toffs: Vec<u64> = (0..4)
            .map(|i| e.u32(&vbuf[(op0 as usize) + i * 4..(op0 as usize) + i * 4 + 4]) as u64)
            .collect();
        let tcnts: Vec<u64> = (0..4)
            .map(|i| e.u32(&vbuf[(oc0 as usize) + i * 4..(oc0 as usize) + i * 4 + 4]) as u64)
            .collect();
        let vtiles: Vec<Vec<u8>> = (0..4)
            .map(|i| vbuf[toffs[i] as usize..(toffs[i] + tcnts[i]) as usize].to_vec())
            .collect();

        let ident = dct2s::linearization_curve(None);
        // full-frame pre-domain from the corpus tiles (identity curve)
        let w = frame.width as usize;
        let h = frame.height as usize;
        let mut pre = vec![0u16; w * h];
        for ti in 0..4 {
            let info = dct2s::parse_tile(&vtiles[ti]).unwrap();
            let (tr, tc) = (ti / 2, ti % 2);
            let ty0 = tr * 1088;
            let tx0 = tc * 1928;
            for scan in 0..2usize {
                let (plane, _) =
                    dct2s::decode_scan_plane(&vtiles[ti], &info, scan, &ident).unwrap();
                for p in 0..dct2s::NBLK_H * 8 {
                    let y = ty0 + 2 * p + scan;
                    if y >= h {
                        continue;
                    }
                    for c in 0..dct2s::NBLK_W * 8 {
                        pre[y * w + tx0 + c] = plane[p * dct2s::NBLK_W * 8 + c];
                    }
                }
            }
        }
        // split into per-tile even/odd pre-planes (no invLUT), pad last rows
        let mut tiles = Vec::new();
        for tr in 0..2usize {
            for tc in 0..2usize {
                let ty0 = tr * 1088;
                let tx0 = tc * 1928;
                let (mut even, mut odd) = (vec![0u16; 1928 * 544], vec![0u16; 1928 * 544]);
                for p in 0..544 {
                    for c in 0..1928 {
                        let ye = ty0 + 2 * p;
                        let yo = ty0 + 2 * p + 1;
                        even[p * 1928 + c] = if ye < h {
                            pre[ye * w + tx0 + c]
                        } else {
                            even[(540) * 1928 + c]
                        };
                        odd[p * 1928 + c] = if yo < h {
                            pre[yo * w + tx0 + c]
                        } else {
                            odd[(540) * 1928 + c]
                        };
                    }
                }
                let ej = lossydct::encode_plane(&even, &lossydct::BASE_TABLE).unwrap();
                let oj = lossydct::encode_plane(&odd, &lossydct::BASE_TABLE).unwrap();
                tiles.push(lossydct::stitch_tile(&ej, &oj, &lossydct::BASE_TABLE).unwrap());
            }
        }
        let cp = dct2s::linearization_curve(Some(&curve.to_vec()));
        let vrefs: Vec<&[u8]> = vtiles.iter().map(|t| t.as_slice()).collect();
        let vpost =
            dct2s::assemble_frame(&vrefs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
        let post =
            dct2s::assemble_frame(&refs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        let mae = |a: &[u16], b: &[u16]| {
            a.iter()
                .zip(b)
                .map(|(x, y)| (*x as i64 - *y as i64).unsigned_abs() as f64)
                .sum::<f64>()
                / a.len() as f64
        };
        println!(
            "MAE(encode(reference_pre), source) = {:.3}   (reference itself = 14.36)",
            mae(&post, &samples)
        );
        println!(
            "MAE(encode(reference_pre), reference_post) = {:.3}",
            mae(&post, &vpost)
        );
    }
}

#[cfg(test)]
mod t6 {
    use super::*;
    use frameprism::dct2s;
    // HF-content analysis: is the invLUT-vs-reference pre-domain difference
    // smooth (low-freq offset, fixable by smoothing) or noisy (per-pixel
    // tie-break HF that the DCT quantizes)? Measure first-difference
    // energy (HF proxy) of reference_pre, invLUT_pre, and their difference.
    #[test]
    fn hf_analysis() {
        let op = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let vp = "../testdata/reference/vbr-hq/A001_001/A001_001_20260701_000001.DNG";
        let src = std::fs::read(op).unwrap();
        let frame = tiff::read(&src).unwrap();
        let packed = frame.strip_slice(&src);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = lossydct::REFERENCE_CURVE;
        let inv = lossydct::inv_lut(&curve);
        let vbuf = std::fs::read(vp).unwrap();
        let vmeta = tiff::read_meta(&vbuf).unwrap();
        let e = vmeta.endianness;
        let mo = vmeta.ifd0.entries.iter().find(|x| x.tag == 324).unwrap();
        let mc = vmeta.ifd0.entries.iter().find(|x| x.tag == 325).unwrap();
        let (op0, _) = mo.out_of_line.unwrap();
        let (oc0, _) = mc.out_of_line.unwrap();
        let toffs: Vec<u64> = (0..4)
            .map(|i| e.u32(&vbuf[(op0 as usize) + i * 4..(op0 as usize) + i * 4 + 4]) as u64)
            .collect();
        let tcnts: Vec<u64> = (0..4)
            .map(|i| e.u32(&vbuf[(oc0 as usize) + i * 4..(oc0 as usize) + i * 4 + 4]) as u64)
            .collect();
        let vtiles: Vec<Vec<u8>> = (0..4)
            .map(|i| vbuf[toffs[i] as usize..(toffs[i] + tcnts[i]) as usize].to_vec())
            .collect();
        let ident = dct2s::linearization_curve(None);

        // tile0 scan0 pre-domain: reference vs invLUT (same 1928x544 geometry)
        let info = dct2s::parse_tile(&vtiles[0]).unwrap();
        let (vpre, _) = dct2s::decode_scan_plane(&vtiles[0], &info, 0, &ident).unwrap();
        let planes = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
        let ipre = planes[0].even.clone();
        let W = 1928;
        let H = 544;
        let n = W * H;

        // first-difference energy (horizontal + vertical) as an HF proxy
        let fd = |a: &[u16]| -> f64 {
            let mut s = 0.0;
            let mut cnt = 0;
            for y in 0..H {
                for x in 0..W {
                    let i = y * W + x;
                    if x + 1 < W {
                        s += (a[i] as i64 - a[i + 1] as i64).abs() as f64;
                        cnt += 1;
                    }
                    if y + 1 < H {
                        s += (a[i] as i64 - a[i + W] as i64).abs() as f64;
                        cnt += 1;
                    }
                }
            }
            s / cnt as f64
        };
        println!(
            "first-diff (HF proxy): reference_pre={:.2}  invLUT_pre={:.2}",
            fd(&vpre),
            fd(&ipre)
        );

        // difference d = reference - invLUT: is it smooth?
        let d: Vec<i64> = vpre
            .iter()
            .zip(&ipre)
            .map(|(v, i)| *v as i64 - *i as i64)
            .collect();
        let d_abs_mae: f64 = d.iter().map(|x| x.abs() as f64).sum::<f64>() / n as f64;
        // d first-diff (HF of the difference)
        let dfd: f64 = {
            let mut s = 0.0;
            let mut cnt = 0;
            for y in 0..H {
                for x in 0..W {
                    let i = y * W + x;
                    if x + 1 < W {
                        s += (d[i] - d[i + 1]).abs() as f64;
                        cnt += 1;
                    }
                    if y + 1 < H {
                        s += (d[i] - d[i + W]).abs() as f64;
                        cnt += 1;
                    }
                }
            }
            s / cnt as f64
        };
        println!(
            "diff MAE = {:.2}  diff first-diff (HF of diff) = {:.2}",
            d_abs_mae, dfd
        );
        // If diff is smooth, diff first-diff << diff MAE. If noisy, ~equal.

        // Per-post-value: for a fixed source value s in the flat band, what
        // pre values do reference and invLUT use? Show the spread.
        // (pick s=300, a flat-band post value)
        let mut vsum = 0.0;
        let mut vcnt = 0;
        let mut isum = 0.0;
        let mut icnt = 0;
        for y in 0..H {
            for x in 0..W {
                let i = y * W + x;
                // source value at tile0 even pixel (frame row 2y, col x)
                let s = samples[(2 * y) as usize * 3856 + x as usize];
                if s == 300 {
                    vsum += vpre[i] as f64;
                    vcnt += 1;
                    isum += ipre[i] as f64;
                    icnt += 1;
                }
            }
        }
        if vcnt > 0 {
            println!(
                "s=300: reference pre mean={:.1} (n={})  invLUT pre={}",
                vsum / vcnt as f64,
                vcnt,
                inv[300]
            );
        }
    }
}

#[cfg(test)]
mod t7 {
    use super::*;
    use frameprism::dct2s;
    // Smoothing sweep: apply a box blur of radius r to the pre-domain,
    // re-encode, decode, measure MAE vs source AND base error
    // (MAE(curve[smooth_pre], source)). Goal: MAE < 21.54 (1.5x reference)
    // with small base error.
    #[test]
    fn smoothing_sweep() {
        let op = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let src = std::fs::read(op).unwrap();
        let frame = tiff::read(&src).unwrap();
        let packed = frame.strip_slice(&src);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = lossydct::REFERENCE_CURVE;
        let inv = lossydct::inv_lut(&curve);
        let cp = dct2s::linearization_curve(Some(&curve.to_vec()));
        let mae = |a: &[u16], b: &[u16]| {
            a.iter()
                .zip(b)
                .map(|(x, y)| (*x as i64 - *y as i64).unsigned_abs() as f64)
                .sum::<f64>()
                / a.len() as f64
        };

        // base pre-domain planes (invLUT), per tile even/odd
        let base_planes =
            lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();

        // box-blur a plane (edge-clamp), radius r
        let blur = |pl: &[u16], r: usize| -> Vec<u16> {
            let W = 1928;
            let H = 544;
            let g = |x: isize, y: isize| -> usize {
                let x = x.clamp(0, W as isize - 1) as usize;
                let y = y.clamp(0, H as isize - 1) as usize;
                y * W + x
            };
            let rr = r as isize;
            let mut out = vec![0u16; W * H];
            for y in 0..H {
                for x in 0..W {
                    let mut s = 0u32;
                    let mut c = 0u32;
                    for dy in -rr..=rr {
                        for dx in -rr..=rr {
                            s += pl[g(x as isize + dx, y as isize + dy)] as u32;
                            c += 1;
                        }
                    }
                    out[y * W + x] = (s / c) as u16;
                }
            }
            out
        };

        for &r in &[0usize, 1, 2, 3] {
            let mut tiles = Vec::new();
            for t in 0..4 {
                let even = if r == 0 {
                    base_planes[t].even.clone()
                } else {
                    blur(&base_planes[t].even, r)
                };
                let odd = if r == 0 {
                    base_planes[t].odd.clone()
                } else {
                    blur(&base_planes[t].odd, r)
                };
                let ej = lossydct::encode_plane(&even, &lossydct::BASE_TABLE).unwrap();
                let oj = lossydct::encode_plane(&odd, &lossydct::BASE_TABLE).unwrap();
                tiles.push(lossydct::stitch_tile(&ej, &oj, &lossydct::BASE_TABLE).unwrap());
            }
            let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
            let post =
                dct2s::assemble_frame(&refs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
            let full_mae = mae(&post, &samples);
            // base error: curve of the (un-encoded) smoothed pre vs source
            let mut base = 0.0;
            let mut bc = 0;
            for t in 0..4 {
                let ty0 = (t / 2) * 1088;
                let tx0 = (t % 2) * 1928;
                for scan in 0..2 {
                    let pl = if scan == 0 {
                        if r == 0 {
                            base_planes[t].even.clone()
                        } else {
                            blur(&base_planes[t].even, r)
                        }
                    } else {
                        if r == 0 {
                            base_planes[t].odd.clone()
                        } else {
                            blur(&base_planes[t].odd, r)
                        }
                    };
                    for p in 0..544 {
                        let y = ty0 + 2 * p + scan;
                        if y as usize >= frame.height as usize {
                            continue;
                        }
                        for c2 in 0..1928 {
                            let pre = pl[p * 1928 + c2] as usize;
                            let postv = curve[pre.min(4095)] as i64;
                            let sv = samples[y as usize * 3856 + tx0 as usize + c2] as i64;
                            base += (postv - sv).unsigned_abs() as f64;
                            bc += 1;
                        }
                    }
                }
            }
            println!("r={r}: full MAE={full_mae:.3}  base MAE(curve[smooth_pre],src)={:.3}  (need full<21.54)", base/bc as f64);
        }
    }
}

#[cfg(test)]
mod sweep {
    use super::*;
    use frameprism::dct2s;

    // 3x3 box blur (edge-clamp)
    fn box3(pl: &[u16]) -> Vec<u16> {
        let W = 1928;
        let H = 544;
        let g = |x: isize, y: isize| -> usize {
            let x = x.clamp(0, W as isize - 1) as usize;
            let y = y.clamp(0, H as isize - 1) as usize;
            y * W + x
        };
        let mut out = vec![0u16; W * H];
        for y in 0..H {
            for x in 0..W {
                let mut s = 0u32;
                for dy in -1..=1 {
                    for dx in -1..=1 {
                        s += pl[g(x as isize + dx, y as isize + dy)] as u32;
                    }
                }
                out[y * W + x] = (s / 9) as u16;
            }
        }
        out
    }
    // center-weighted soft blur [0 1 0;1 4 1;0 1 0]/8 (lighter than box3)
    fn soft3(pl: &[u16]) -> Vec<u16> {
        let W = 1928;
        let H = 544;
        let g = |x: isize, y: isize| -> usize {
            let x = x.clamp(0, W as isize - 1) as usize;
            let y = y.clamp(0, H as isize - 1) as usize;
            y * W + x
        };
        let mut out = vec![0u16; W * H];
        for y in 0..H {
            for x in 0..W {
                let c = pl[g(x as isize, y as isize)] as u32;
                let l = pl[g(x as isize - 1, y as isize)] as u32;
                let r = pl[g(x as isize + 1, y as isize)] as u32;
                let t = pl[g(x as isize, y as isize - 1)] as u32;
                let b = pl[g(x as isize, y as isize + 1)] as u32;
                out[y * W + x] = ((4 * c + l + r + t + b) / 8) as u16;
            }
        }
        out
    }

    // For one frame + smoother id, build planes, encode 4 tiles, decode, MAE.
    fn mae_for(src_path: &str, smoother: &str) -> f64 {
        let srcb = std::fs::read(src_path).unwrap();
        let frame = tiff::read(&srcb).unwrap();
        let packed = frame.strip_slice(&srcb);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = lossydct::REFERENCE_CURVE;
        let inv = lossydct::inv_lut(&curve);
        let cp = dct2s::linearization_curve(Some(&curve.to_vec()));
        let planes = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
        let apply = |pl: &[u16]| -> Vec<u16> {
            match smoother {
                "raw" => pl.to_vec(),
                "box3" => box3(pl),
                "soft3" => soft3(pl),
                _ => pl.to_vec(),
            }
        };
        let mut tiles = Vec::new();
        for t in 0..4 {
            let even = apply(&planes[t].even);
            let odd = apply(&planes[t].odd);
            let ej = lossydct::encode_plane(&even, &lossydct::BASE_TABLE).unwrap();
            let oj = lossydct::encode_plane(&odd, &lossydct::BASE_TABLE).unwrap();
            tiles.push(lossydct::stitch_tile(&ej, &oj, &lossydct::BASE_TABLE).unwrap());
        }
        let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
        let post =
            dct2s::assemble_frame(&refs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        post.iter()
            .zip(&samples)
            .map(|(a, b)| (*a as i64 - *b as i64).unsigned_abs() as f64)
            .sum::<f64>()
            / post.len() as f64
    }

    #[test]
    fn sweep_frames() {
        let base = "../testdata/originals/A001_001/";
        let frames = [
            ("000149", 2.2581),
            ("000180", 6.1438),
            ("000001", 14.3600),
            ("000113", 19.9209),
            ("000060", 40.5188),
            ("000087", 59.8531),
        ];
        let smoothers = ["raw", "soft3", "box3"];
        println!("frame      reference raw     soft3   box3   (ratios vs reference in parens)");
        for (fnum, vend) in frames {
            let path = format!("{}A001_001_20260701_{}.DNG", base, fnum);
            let mut line = format!("{}  {:6.2}  ", fnum, vend);
            for sm in smoothers {
                let m = mae_for(&path, sm);
                line = format!("{}{:7.2}({:4.2}x)  ", line, m, m / vend);
            }
            println!("{line}");
        }
    }
}

#[cfg(test)]
mod grid {
    use super::*;
    use frameprism::dct2s;

    // 3x3 Gaussian [1 2 1; 2 4 2; 1 2 1]/16 (sigma ~ 1)
    fn gauss3(pl: &[u16]) -> Vec<u16> {
        let W = 1928;
        let H = 544;
        let g = |x: isize, y: isize| {
            let x = x.clamp(0, W as isize - 1) as usize;
            let y = y.clamp(0, H as isize - 1) as usize;
            y * W + x
        };
        let mut out = vec![0u16; W * H];
        for y in 0..H {
            for x in 0..W {
                let mut s = 0u32;
                let (X, Y) = (x as isize, y as isize);
                s += pl[g(X - 1, Y - 1)] as u32
                    + 2 * pl[g(X, Y - 1)] as u32
                    + pl[g(X + 1, Y - 1)] as u32
                    + 2 * pl[g(X - 1, Y)] as u32
                    + 4 * pl[g(X, Y)] as u32
                    + 2 * pl[g(X + 1, Y)] as u32
                    + pl[g(X - 1, Y + 1)] as u32
                    + 2 * pl[g(X, Y + 1)] as u32
                    + pl[g(X + 1, Y + 1)] as u32;
                out[y * W + x] = (s / 16) as u16;
            }
        }
        out
    }
    fn box3(pl: &[u16]) -> Vec<u16> {
        let W = 1928;
        let H = 544;
        let g = |x: isize, y: isize| {
            let x = x.clamp(0, W as isize - 1) as usize;
            let y = y.clamp(0, H as isize - 1) as usize;
            y * W + x
        };
        let mut out = vec![0u16; W * H];
        for y in 0..H {
            for x in 0..W {
                let mut s = 0u32;
                let (X, Y) = (x as isize, y as isize);
                for dy in -1..=1 {
                    for dx in -1..=1 {
                        s += pl[g(X + dx, Y + dy)] as u32;
                    }
                }
                out[y * W + x] = (s / 9) as u16;
            }
        }
        out
    }
    // leaky blend: a*raw + (1-a)*box3
    fn blend(pl: &[u16], a: u32) -> Vec<u16> {
        let b = box3(pl);
        let W = 1928;
        let H = 544;
        (0..W * H)
            .map(|i| ((a * pl[i] as u32 + (100 - a) * b[i] as u32) / 100) as u16)
            .collect()
    }
    fn mae_for(src_path: &str, smoother: &dyn Fn(&[u16]) -> Vec<u16>) -> f64 {
        let srcb = std::fs::read(src_path).unwrap();
        let frame = tiff::read(&srcb).unwrap();
        let packed = frame.strip_slice(&srcb);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = lossydct::REFERENCE_CURVE;
        let inv = lossydct::inv_lut(&curve);
        let cp = dct2s::linearization_curve(Some(&curve.to_vec()));
        let planes = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
        let mut tiles = Vec::new();
        for t in 0..4 {
            let even = smoother(&planes[t].even);
            let odd = smoother(&planes[t].odd);
            let ej = lossydct::encode_plane(&even, &lossydct::BASE_TABLE).unwrap();
            let oj = lossydct::encode_plane(&odd, &lossydct::BASE_TABLE).unwrap();
            tiles.push(lossydct::stitch_tile(&ej, &oj, &lossydct::BASE_TABLE).unwrap());
        }
        let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
        let post =
            dct2s::assemble_frame(&refs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        post.iter()
            .zip(&samples)
            .map(|(a, b)| (*a as i64 - *b as i64).unsigned_abs() as f64)
            .sum::<f64>()
            / post.len() as f64
    }
    #[test]
    fn grid() {
        let base = "../testdata/originals/A001_001/";
        let frames = [
            ("000151", 2.20),
            ("000149", 2.2581),
            ("000188", 6.1438),
            ("000001", 14.36),
            ("000113", 19.9209),
            ("000087", 59.8531),
        ];
        type Sm = Box<dyn Fn(&[u16]) -> Vec<u16>>;
        let smoothers: Vec<(&str, Sm)> = vec![
            ("raw", Box::new(|p: &[u16]| p.to_vec())),
            ("bl25", Box::new(|p: &[u16]| blend(p, 75))), // 0.75 raw
            ("bl50", Box::new(|p: &[u16]| blend(p, 50))), // 0.50 raw
            ("gauss3", Box::new(gauss3)),
            ("box3", Box::new(box3)),
        ];
        let hdr: String = smoothers.iter().map(|(n, _)| format!("{n:>15}")).collect();
        println!("frame   vend | {hdr}");
        for (fnum, vend) in frames {
            let path = format!("{}A001_001_20260701_{}.DNG", base, fnum);
            let mut line = format!("{fnum} {vend:5.2} | ");
            for (_n, f) in &smoothers {
                let m = mae_for(&path, f.as_ref());
                let r = m / vend;
                line = format!("{line}{m:7.2} ({r:5.2}x) | ");
            }
            println!("{line}");
        }
    }
}

#[cfg(test)]
mod plateaustrength {
    use super::*;
    use frameprism::dct2s;
    use frameprism::lossydct;
    // plateau-snap with a box3 applied `n` times as the prior (n=1 current, n=2 stronger)
    fn pmae(src_path: &str, n: u32) -> f64 {
        let srcb = std::fs::read(src_path).unwrap();
        let frame = tiff::read(&srcb).unwrap();
        let packed = frame.strip_slice(&srcb);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = lossydct::REFERENCE_CURVE;
        let inv = lossydct::inv_lut(&curve);
        let _ = lossydct::plateau_range(&curve);
        let cp = dct2s::linearization_curve(Some(&curve.to_vec()));
        let pre0 = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
        let srcp = lossydct::build_source_planes(&samples, frame.width, frame.height).unwrap();
        // pre-blur pre0 with box3 (n-1) extra times so the plateau-snap's own
        // box3 prior gives box3^n overall.
        let mut pp = [0; 4].map(|_| lossydct::TilePlanes {
            even: vec![],
            odd: vec![],
        });
        for t in 0..4 {
            let mut e = pre0[t].even.clone();
            let mut o = pre0[t].odd.clone();
            for _ in 0..n.saturating_sub(1) {
                e = lossydct::box3_smooth(&e);
                o = lossydct::box3_smooth(&o);
            }
            pp[t] = lossydct::TilePlanes { even: e, odd: o };
        }
        let planes = lossydct::smooth_planes(&pp, &srcp, &curve);
        let tiles = lossydct::encode_tiles(&planes, &lossydct::BASE_TABLE).unwrap();
        let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
        let post =
            dct2s::assemble_frame(&refs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        post.iter()
            .zip(&samples)
            .map(|(a, b)| (*a as i64 - *b as i64).unsigned_abs() as f64)
            .sum::<f64>()
            / post.len() as f64
    }
    #[test]
    fn strength() {
        let base = "../testdata/originals/A001_001/";
        let frames = [
            ("000151", 2.20),
            ("000189", 6.14),
            ("000225", 6.34),
            ("000001", 14.36),
            ("000113", 19.92),
            ("000103", 32.72),
            ("000087", 59.85),
        ];
        println!("frame  vend |  n1(box3)   n2(box3x2)   n3(box3x3)");
        for (fnum, vend) in frames {
            let path = format!("{}A001_001_20260701_{}.DNG", base, fnum);
            let m1 = pmae(&path, 1);
            let m2 = pmae(&path, 2);
            let m3 = pmae(&path, 3);
            let (r1, r2, r3) = (m1 / vend, m2 / vend, m3 / vend);
            println!("{fnum} {vend:5.2} | {m1:7.2} ({r1:5.2}x) {m2:7.2} ({r2:5.2}x) {m3:7.2} ({r3:5.2}x)");
        }
    }
}

#[cfg(test)]
mod box2 {
    use super::*;
    use frameprism::dct2s;
    use frameprism::lossydct;
    fn box2(pl: &[u16]) -> Vec<u16> {
        let W = 1928;
        let H = 544;
        let g = |x: isize, y: isize| {
            let x = x.clamp(0, W as isize - 1) as usize;
            let y = y.clamp(0, H as isize - 1) as usize;
            y * W + x
        };
        let mut out = vec![0u16; W * H];
        for y in 0..H {
            for x in 0..W {
                let (X, Y) = (x as isize, y as isize);
                let s = pl[g(X, Y)] as u32
                    + pl[g(X + 1, Y)] as u32
                    + pl[g(X, Y + 1)] as u32
                    + pl[g(X + 1, Y + 1)] as u32;
                out[y * W + x] = (s / 4) as u16;
            }
        }
        out
    }
    fn pmae(src_path: &str, which: &str) -> f64 {
        let srcb = std::fs::read(src_path).unwrap();
        let frame = tiff::read(&srcb).unwrap();
        let packed = frame.strip_slice(&srcb);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = lossydct::REFERENCE_CURVE;
        let inv = lossydct::inv_lut(&curve);
        let cp = dct2s::linearization_curve(Some(&curve.to_vec()));
        let pre0 = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
        let srcp = lossydct::build_source_planes(&samples, frame.width, frame.height).unwrap();
        let planes: [lossydct::TilePlanes; 4] = if which == "box2" {
            // plain 2x2 average on the pre0 planes
            [
                lossydct::TilePlanes {
                    even: box2(&pre0[0].even),
                    odd: box2(&pre0[0].odd),
                },
                lossydct::TilePlanes {
                    even: box2(&pre0[1].even),
                    odd: box2(&pre0[1].odd),
                },
                lossydct::TilePlanes {
                    even: box2(&pre0[2].even),
                    odd: box2(&pre0[2].odd),
                },
                lossydct::TilePlanes {
                    even: box2(&pre0[3].even),
                    odd: box2(&pre0[3].odd),
                },
            ]
        } else {
            lossydct::smooth_planes(&pre0, &srcp, &curve) // plateau-snap (box3 prior)
        };
        let tiles = lossydct::encode_tiles(&planes, &lossydct::BASE_TABLE).unwrap();
        let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
        let post =
            dct2s::assemble_frame(&refs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        post.iter()
            .zip(&samples)
            .map(|(a, b)| (*a as i64 - *b as i64).unsigned_abs() as f64)
            .sum::<f64>()
            / post.len() as f64
    }
    #[test]
    fn b2() {
        let base = "../testdata/originals/A001_001/";
        let frames = [
            ("000151", 2.20),
            ("000189", 6.14),
            ("000225", 6.34),
            ("000001", 14.36),
            ("000113", 19.92),
            ("000103", 32.72),
            ("000087", 59.85),
        ];
        println!("frame  vend |  plateau(box3prior)  box2(plain)");
        for (fnum, vend) in frames {
            let path = format!("{}A001_001_20260701_{}.DNG", base, fnum);
            let m1 = pmae(&path, "plateau");
            let m2 = pmae(&path, "box2");
            let (r1, r2) = (m1 / vend, m2 / vend);
            println!("{fnum} {vend:5.2} | {m1:7.2} ({r1:5.2}x) {m2:7.2} ({r2:5.2}x)");
        }
    }
}

#[cfg(test)]
mod full225 {
    use super::*;
    use frameprism::dct2s;
    use frameprism::lossydct;
    fn pmae(src_path: &str) -> f64 {
        let srcb = std::fs::read(src_path).unwrap();
        let frame = tiff::read(&srcb).unwrap();
        let packed = frame.strip_slice(&srcb);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = lossydct::REFERENCE_CURVE;
        let inv = lossydct::inv_lut(&curve);
        let cp = dct2s::linearization_curve(Some(&curve.to_vec()));
        let pre0 = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
        let srcp = lossydct::build_source_planes(&samples, frame.width, frame.height).unwrap();
        let planes = lossydct::smooth_planes(&pre0, &srcp, &curve);
        let tiles = lossydct::encode_tiles(&planes, &lossydct::BASE_TABLE).unwrap();
        let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
        let post =
            dct2s::assemble_frame(&refs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        post.iter()
            .zip(&samples)
            .map(|(a, b)| (*a as i64 - *b as i64).unsigned_abs() as f64)
            .sum::<f64>()
            / post.len() as f64
    }
    #[test]
    fn all() {
        let base = "../testdata/originals/A001_001/";
        let mut vend = std::collections::HashMap::new();
        for line in std::fs::read_to_string("../../../quality_vbr-hq.tsv")
            .unwrap()
            .lines()
            .skip(1)
        {
            let f: Vec<&str> = line.split('\t').collect();
            vend.insert(f[0].to_string(), f[1].parse::<f64>().unwrap());
        }
        let dir = std::path::Path::new(base);
        let files: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .map(|x| x.eq_ignore_ascii_case("dng"))
                    .unwrap_or(false)
            })
            .collect();
        let mut ratios = Vec::new();
        let mut our_maes = Vec::new();
        let mut vend_maes = Vec::new();
        let mut below = 0;
        let mut above = 0;
        let mut over_p99 = 0;
        for p in &files {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            let m = pmae(p.to_str().unwrap());
            let v = vend.get(&name).copied().unwrap_or(0.0);
            let r = m / v;
            if r < 0.5 {
                below += 1;
            }
            if r > 1.5 {
                above += 1;
            }
            if m > 59.682 {
                over_p99 += 1;
            }
            ratios.push(r);
            our_maes.push(m);
            vend_maes.push(v);
        }
        ratios.sort_by(|a, b| a.partial_cmp(b).unwrap());
        our_maes.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = ratios.len();
        let p99_our = our_maes[((0.99 * n as f64) as usize).min(n - 1)];
        let med = ratios[n / 2];
        eprintln!("n={} ratio min={:.3} med={:.3} max={:.3} | below0.5={} above1.5={} over_p99={} | our_p99={:.3}",
            n, ratios[0], med, ratios[n-1], below, above, over_p99, p99_our);
        // print the frames with ratio > 1.5 (the band violations)
        let mut hi: Vec<(usize, f64, f64)> = vec![];
        for (i, r) in ratios.iter().enumerate() {
            if *r > 1.5 {
                hi.push((i, *r, 0.0));
            }
        }
        hi.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        for (i, r, _) in hi.iter().take(15) {
            let v = vend_maes[*i];
            eprintln!("  hi frame idx={} reference={:.2} ratio={:.3}", *i, v, r);
        }
    }
}

#[cfg(test)]
mod blend225 {
    use super::*;
    use frameprism::dct2s;
    use frameprism::lossydct;
    fn box3f(pl: &[u16]) -> Vec<u16> {
        lossydct::box3_smooth(pl)
    }
    fn pmae(src_path: &str, a_plateau: u32) -> f64 {
        let srcb = std::fs::read(src_path).unwrap();
        let frame = tiff::read(&srcb).unwrap();
        let packed = frame.strip_slice(&srcb);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = lossydct::REFERENCE_CURVE;
        let inv = lossydct::inv_lut(&curve);
        let cp = dct2s::linearization_curve(Some(&curve.to_vec()));
        let pre0 = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
        let srcp = lossydct::build_source_planes(&samples, frame.width, frame.height).unwrap();
        let pl = lossydct::smooth_planes(&pre0, &srcp, &curve);
        // blend a*flat step + (1-a)*box3 in the pixel domain
        let be = [
            box3f(&pl[0].even),
            box3f(&pl[1].even),
            box3f(&pl[2].even),
            box3f(&pl[3].even),
        ];
        let bo = [
            box3f(&pl[0].odd),
            box3f(&pl[1].odd),
            box3f(&pl[2].odd),
            box3f(&pl[3].odd),
        ];
        let mk = |t: usize| {
            let mut e = vec![0u16; pl[t].even.len()];
            let mut o = vec![0u16; pl[t].odd.len()];
            for i in 0..pl[t].even.len() {
                e[i] = ((a_plateau * pl[t].even[i] as u32 + (100 - a_plateau) * be[t][i] as u32)
                    / 100) as u16;
                o[i] = ((a_plateau * pl[t].odd[i] as u32 + (100 - a_plateau) * bo[t][i] as u32)
                    / 100) as u16;
            }
            lossydct::TilePlanes { even: e, odd: o }
        };
        let planes = [mk(0), mk(1), mk(2), mk(3)];
        let tiles = lossydct::encode_tiles(&planes, &lossydct::BASE_TABLE).unwrap();
        let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
        let post =
            dct2s::assemble_frame(&refs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        post.iter()
            .zip(&samples)
            .map(|(a, b)| (*a as i64 - *b as i64).unsigned_abs() as f64)
            .sum::<f64>()
            / post.len() as f64
    }
    #[test]
    fn all() {
        let base = "../testdata/originals/A001_001/";
        let mut vend = std::collections::HashMap::new();
        for line in std::fs::read_to_string("../../../quality_vbr-hq.tsv")
            .unwrap()
            .lines()
            .skip(1)
        {
            let f: Vec<&str> = line.split('\t').collect();
            vend.insert(f[0].to_string(), f[1].parse::<f64>().unwrap());
        }
        let files: Vec<_> = std::fs::read_dir(base)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .map(|x| x.eq_ignore_ascii_case("dng"))
                    .unwrap_or(false)
            })
            .collect();
        for a in [100, 70, 50] {
            let mut ratios = Vec::new();
            let mut below = 0;
            let mut above = 0;
            for p in &files {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                let m = pmae(p.to_str().unwrap(), a);
                let v = vend.get(&name).copied().unwrap_or(1.0);
                let r = m / v;
                if r < 0.5 {
                    below += 1;
                }
                if r > 1.5 {
                    above += 1;
                }
                ratios.push(r);
            }
            ratios.sort_by(|x, y| x.partial_cmp(y).unwrap());
            let n = ratios.len();
            eprintln!(
                "a={} ratio min={:.3} med={:.3} max={:.3} | below0.5={} above1.5={}",
                a,
                ratios[0],
                ratios[n / 2],
                ratios[n - 1],
                below,
                above
            );
        }
    }
}

#[cfg(test)]
mod margin225 {
    use super::*;
    use frameprism::dct2s;
    use frameprism::lossydct;
    // plateau-snap with a margin m: clamp(prior, lo-m, hi+m); box3 prior computed once
    fn snap_m(pre0: &[u16], se: &[u16], lo: &[i32; 4096], hi: &[i32; 4096], m: i32) -> Vec<u16> {
        let prior = lossydct::box3_smooth(pre0);
        (0..pre0.len())
            .map(|i| {
                let (l, h) = (lo[se[i] as usize] - m, hi[se[i] as usize] + m);
                let p = prior[i] as i32;
                (if p < l {
                    l
                } else if p > h {
                    h
                } else {
                    p
                }) as u16
            })
            .collect()
    }
    fn pmae_m(src_path: &str, m: i32) -> f64 {
        let srcb = std::fs::read(src_path).unwrap();
        let frame = tiff::read(&srcb).unwrap();
        let packed = frame.strip_slice(&srcb);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = lossydct::REFERENCE_CURVE;
        let inv = lossydct::inv_lut(&curve);
        let (lo, hi) = lossydct::plateau_range(&curve);
        let cp = dct2s::linearization_curve(Some(&curve.to_vec()));
        let pre0 = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
        let srcp = lossydct::build_source_planes(&samples, frame.width, frame.height).unwrap();
        let planes = [
            lossydct::TilePlanes {
                even: snap_m(&pre0[0].even, &srcp[0].even, &lo, &hi, m),
                odd: snap_m(&pre0[0].odd, &srcp[0].odd, &lo, &hi, m),
            },
            lossydct::TilePlanes {
                even: snap_m(&pre0[1].even, &srcp[1].even, &lo, &hi, m),
                odd: snap_m(&pre0[1].odd, &srcp[1].odd, &lo, &hi, m),
            },
            lossydct::TilePlanes {
                even: snap_m(&pre0[2].even, &srcp[2].even, &lo, &hi, m),
                odd: snap_m(&pre0[2].odd, &srcp[2].odd, &lo, &hi, m),
            },
            lossydct::TilePlanes {
                even: snap_m(&pre0[3].even, &srcp[3].even, &lo, &hi, m),
                odd: snap_m(&pre0[3].odd, &srcp[3].odd, &lo, &hi, m),
            },
        ];
        let tiles = lossydct::encode_tiles(&planes, &lossydct::BASE_TABLE).unwrap();
        let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
        let post =
            dct2s::assemble_frame(&refs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        post.iter()
            .zip(&samples)
            .map(|(a, b)| (*a as i64 - *b as i64).unsigned_abs() as f64)
            .sum::<f64>()
            / post.len() as f64
    }
    #[test]
    fn all() {
        let base = "../testdata/originals/A001_001/";
        let mut vend = std::collections::HashMap::new();
        for line in std::fs::read_to_string("../../../quality_vbr-hq.tsv")
            .unwrap()
            .lines()
            .skip(1)
        {
            let f: Vec<&str> = line.split('\t').collect();
            vend.insert(f[0].to_string(), f[1].parse::<f64>().unwrap());
        }
        let files: Vec<_> = std::fs::read_dir(base)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .map(|x| x.eq_ignore_ascii_case("dng"))
                    .unwrap_or(false)
            })
            .collect();
        for m in [0, 3, 6, 12, 24] {
            let mut ratios = Vec::new();
            let mut below = 0;
            let mut above = 0;
            for p in &files {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                let mm = pmae_m(p.to_str().unwrap(), m);
                let v = vend.get(&name).copied().unwrap_or(1.0);
                let r = mm / v;
                if r < 0.5 {
                    below += 1;
                }
                if r > 1.5 {
                    above += 1;
                }
                ratios.push(r);
            }
            ratios.sort_by(|x, y| x.partial_cmp(y).unwrap());
            let n = ratios.len();
            eprintln!(
                "m={m} ratio min={:.3} med={:.3} max={:.3} | below0.5={} above1.5={}",
                ratios[0],
                ratios[n / 2],
                ratios[n - 1],
                below,
                above
            );
        }
    }
}

#[cfg(test)]
mod adaptm {
    use super::*;
    use frameprism::dct2s;
    use frameprism::lossydct;
    // content-adaptive margin: m_i = k / flat_width(i); the steep band
    // (narrow flat step) gets more smoothing than the flat band (wide flat step).
    fn snap_a(pre0: &[u16], se: &[u16], lo: &[i32; 4096], hi: &[i32; 4096], k: i32) -> Vec<u16> {
        let prior = lossydct::box3_smooth(pre0);
        (0..pre0.len())
            .map(|i| {
                let (l0, h0) = (lo[se[i] as usize], hi[se[i] as usize]);
                let w = (h0 - l0 + 1).max(1);
                let m = k / w; // margin scales inversely with flat-region width
                let (l, h) = (l0 - m, h0 + m);
                let p = prior[i] as i32;
                (if p < l {
                    l
                } else if p > h {
                    h
                } else {
                    p
                }) as u16
            })
            .collect()
    }
    fn pmae_a(src_path: &str, k: i32) -> f64 {
        let srcb = std::fs::read(src_path).unwrap();
        let frame = tiff::read(&srcb).unwrap();
        let packed = frame.strip_slice(&srcb);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = lossydct::REFERENCE_CURVE;
        let inv = lossydct::inv_lut(&curve);
        let (lo, hi) = lossydct::plateau_range(&curve);
        let cp = dct2s::linearization_curve(Some(&curve.to_vec()));
        let pre0 = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
        let srcp = lossydct::build_source_planes(&samples, frame.width, frame.height).unwrap();
        let planes = [
            lossydct::TilePlanes {
                even: snap_a(&pre0[0].even, &srcp[0].even, &lo, &hi, k),
                odd: snap_a(&pre0[0].odd, &srcp[0].odd, &lo, &hi, k),
            },
            lossydct::TilePlanes {
                even: snap_a(&pre0[1].even, &srcp[1].even, &lo, &hi, k),
                odd: snap_a(&pre0[1].odd, &srcp[1].odd, &lo, &hi, k),
            },
            lossydct::TilePlanes {
                even: snap_a(&pre0[2].even, &srcp[2].even, &lo, &hi, k),
                odd: snap_a(&pre0[2].odd, &srcp[2].odd, &lo, &hi, k),
            },
            lossydct::TilePlanes {
                even: snap_a(&pre0[3].even, &srcp[3].even, &lo, &hi, k),
                odd: snap_a(&pre0[3].odd, &srcp[3].odd, &lo, &hi, k),
            },
        ];
        let tiles = lossydct::encode_tiles(&planes, &lossydct::BASE_TABLE).unwrap();
        let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
        let post =
            dct2s::assemble_frame(&refs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        post.iter()
            .zip(&samples)
            .map(|(a, b)| (*a as i64 - *b as i64).unsigned_abs() as f64)
            .sum::<f64>()
            / post.len() as f64
    }
    #[test]
    fn all() {
        let base = "../testdata/originals/A001_001/";
        let mut vend = std::collections::HashMap::new();
        for line in std::fs::read_to_string("../../../quality_vbr-hq.tsv")
            .unwrap()
            .lines()
            .skip(1)
        {
            let f: Vec<&str> = line.split('\t').collect();
            vend.insert(f[0].to_string(), f[1].parse::<f64>().unwrap());
        }
        let files: Vec<_> = std::fs::read_dir(base)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .map(|x| x.eq_ignore_ascii_case("dng"))
                    .unwrap_or(false)
            })
            .collect();
        for k in [4, 8, 12, 16] {
            let mut ratios = Vec::new();
            let mut below = 0;
            let mut above = 0;
            for p in &files {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                let mm = pmae_a(p.to_str().unwrap(), k);
                let v = vend.get(&name).copied().unwrap_or(1.0);
                let r = mm / v;
                if r < 0.5 {
                    below += 1;
                }
                if r > 1.5 {
                    above += 1;
                }
                ratios.push(r);
            }
            ratios.sort_by(|x, y| x.partial_cmp(y).unwrap());
            let n = ratios.len();
            eprintln!(
                "k={k} ratio min={:.3} med={:.3} max={:.3} | below0.5={} above1.5={}",
                ratios[0],
                ratios[n / 2],
                ratios[n - 1],
                below,
                above
            );
        }
    }
}
