use frameprism::{pack12, tiff};
// DC-only scan1: odd rows decode to their overall DC mean -> odd MAE = odd
// rows' abs-deviation from the mean (the DCT error a DC-only scan1 gives).
fn main() {
    let base = "../testdata/originals/A001_001/";
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
    let mut worst = 0.0f64;
    let mut wname = String::new();
    let mut vals: Vec<(f64, String)> = Vec::new();
    for p in &files {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let b = std::fs::read(p).unwrap();
        let frame = tiff::read(&b).unwrap();
        let packed = frame.strip_slice(&b);
        let samples = pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let w = frame.width as usize;
        let h = frame.height as usize;
        let mut o_sum = 0.0;
        let mut n = 0.0;
        for y in 1..h {
            let base = y * w;
            for x in 0..w {
                o_sum += samples[base + x] as f64;
                n += 1.0;
            }
        }
        let o_mean = o_sum / n;
        let mut o_dev = 0.0;
        for y in 1..h {
            let base = y * w;
            for x in 0..w {
                o_dev += (samples[base + x] as f64 - o_mean).abs();
            }
        }
        let odd_mae = o_dev / n;
        vals.push((odd_mae, name.clone()));
        if odd_mae > worst {
            worst = odd_mae;
            wname = name.clone();
        }
    }
    vals.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    eprintln!("DC-only scan1 odd-row MAE (= odd rows abs-dev from mean): n={} worst={worst:.1} ({wname}) | top5:", vals.len());
    for (v, n) in vals.iter().take(5) {
        eprintln!("  {n} {v:.1}");
    }
    let above50 = vals.iter().filter(|(v, _)| *v > 50.0).count();
    let above20 = vals.iter().filter(|(v, _)| *v > 20.0).count();
    eprintln!("odd_mae>50: {above50} | >20: {above20} of {}", vals.len());
}
