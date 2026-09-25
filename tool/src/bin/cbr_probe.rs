use frameprism::{dct2s, lossydct, pack12, surgery, tiff};
// Replicate the worker's CBR path for a frame: find the scale search_scale
// picks for a given k, print the chosen scale, file size, and MAE. Also
// print the vbr-hq (s=1.0) file size + MAE for reference.
fn run(path: &str, _frame_w: u32, _frame_h: u32, k: Option<u32>) {
    let b = std::fs::read(path).unwrap();
    let frame = tiff::read(&b).unwrap();
    let packed = frame.strip_slice(&b);
    let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
    let curve = lossydct::REFERENCE_CURVE;
    let inv = lossydct::inv_lut(&curve);
    let pre0 = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
    let srcp = lossydct::build_source_planes(&samples, frame.width, frame.height).unwrap();
    let planes = lossydct::smooth_planes(&pre0, &srcp, &curve);
    let curve_bytes = lossydct::curve_bytes(&curve);
    let cp = dct2s::linearization_curve(Some(&curve));
    let in_bytes = b.len() as u64;
    // vbr-hq reference (s=1.0, BASE)
    let base_tiles = lossydct::encode_tiles(&planes, &lossydct::BASE_TABLE).unwrap();
    let base_out = surgery::apply_tiled_reference_dct(&b, &frame, &base_tiles, &curve_bytes).unwrap();
    let prefix = base_out.bytes_out as u64 - base_tiles.iter().map(|t| t.len() as u64).sum::<u64>();
    let base_mae = {
        let refs: Vec<&[u8]> = base_tiles.iter().map(|t| t.as_slice()).collect();
        let post =
            dct2s::assemble_frame(&refs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        post.iter()
            .zip(&samples)
            .map(|(a, b)| (*a as i64 - *b as i64).unsigned_abs() as f64)
            .sum::<f64>()
            / post.len() as f64
    };
    eprintln!(
        "  vbr-hq(s=1.0): file={file} mae={mae:.3}",
        file = base_out.bytes_out,
        mae = base_mae
    );
    if let Some(k) = k {
        let limit = in_bytes / k as u64 * 105 / 100;
        let cache: std::cell::RefCell<std::collections::HashMap<u64, Vec<Vec<u8>>>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
        cache
            .borrow_mut()
            .insert(1.0f64.to_bits(), base_tiles.clone());
        let total_fn = |s: f64| -> u64 {
            let t = {
                let mut c = cache.borrow_mut();
                match c.get(&s.to_bits()) {
                    Some(t) => t.clone(),
                    None => {
                        let t = lossydct::encode_tiles(&planes, &lossydct::scale_table(s))
                            .expect("encode");
                        c.insert(s.to_bits(), t.clone());
                        t
                    }
                }
            };
            prefix + t.iter().map(|x| x.len() as u64).sum::<u64>()
        };
        let s = lossydct::search_scale(limit, &total_fn);
        let tiles = cache.borrow().get(&s.to_bits()).cloned().unwrap();
        let out = surgery::apply_tiled_reference_dct(&b, &frame, &tiles, &curve_bytes).unwrap();
        let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
        let post =
            dct2s::assemble_frame(&refs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        let mae: f64 = post
            .iter()
            .zip(&samples)
            .map(|(a, b)| (*a as i64 - *b as i64).unsigned_abs() as f64)
            .sum::<f64>()
            / post.len() as f64;
        let nominal = in_bytes / k as u64;
        let dev = (out.bytes_out as f64 / nominal as f64 - 1.0) * 100.0;
        let file = out.bytes_out;
        eprintln!("  cbr{k}(nominal {nominal}, limit {limit}): s={s:.4} file={file} ({dev:+.1}% of nominal) mae={mae:.3}");
    }
}
fn main() {
    let base = "../testdata/originals/A001_001/";
    for (n, ks) in [(127, vec![3, 4, 7]), (57, vec![7]), (141, vec![3])] {
        let p = format!("{base}A001_001_20260701_{:06}.DNG", n);
        eprintln!("frame {n}:");
        for k in ks {
            run(&p, 3856, 2170, Some(k));
        }
        run(&p, 3856, 2170, None);
    }
    // Direct MAE-vs-scale sweep for f127 (the contradiction frame).
    let p = format!("{base}A001_001_20260701_0127.DNG");
    let b = std::fs::read(&p).unwrap();
    let frame = tiff::read(&b).unwrap();
    let packed = frame.strip_slice(&b);
    let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
    let curve = lossydct::REFERENCE_CURVE;
    let inv = lossydct::inv_lut(&curve);
    let pre0 = lossydct::build_planes(&samples, frame.width, frame.height, &inv).unwrap();
    let srcp = lossydct::build_source_planes(&samples, frame.width, frame.height).unwrap();
    let planes = lossydct::smooth_planes(&pre0, &srcp, &curve);
    let cp = dct2s::linearization_curve(Some(&curve));
    eprintln!("f127 MAE-vs-scale sweep:");
    for &s in &[0.05f64, 0.1, 0.1923, 0.3757, 0.5, 1.0, 1.393, 2.0, 4.0] {
        let table = lossydct::scale_table(s);
        let tiles = lossydct::encode_tiles(&planes, &table).unwrap();
        let size: u64 = tiles.iter().map(|t| t.len() as u64).sum();
        let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
        let post =
            dct2s::assemble_frame(&refs, 1928, 1088, frame.width, frame.height, &cp).unwrap();
        let mae: f64 = post
            .iter()
            .zip(&samples)
            .map(|(a, b)| (*a as i64 - *b as i64).unsigned_abs() as f64)
            .sum::<f64>()
            / post.len() as f64;
        let min1 = table.iter().filter(|&&v| v == 1).count();
        eprintln!("  s={s:.4} tiles={size} mae={mae:.3} (table ones={min1}/64)");
    }
}
