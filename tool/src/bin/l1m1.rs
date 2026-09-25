// l1m1: per-candidate stage decomposition on REAL tiles.
//
// Goal: measure the five stages of the current per-candidate
// cost on ≥256 real tiles (A001_001 f001–f004 × 64, 3856×2170), prec 12
// (12-bit plane) and prec 10 (10-bit log CODES via log10::inv — the
// worker's mapping):
//   t1 planes_from_tile         (per candidate, as encode_candidate pays it)
//   t2 fastenc::native_hist     (diff/nbits histogram, both components)
//   t3 fastenc::native_tables   (IJG K.2 table derivation, both components)
//   t4 encode_planes_native     (FULL encode — black box incl. its own hist+table)
//   t5 encode_planes_native_size (size-only — exact post-pad length)
//
// Emission fraction = (t4 − t5) / (t1 + t4): the share of the current
// per-candidate cost that the size-only pass SKIPS (the byte stores;
// hist+table+emit arithmetic remain in both). STOP condition:
// if emission < 20% of candidate cost, the lever is not worth it.
// Expected lever gain: the two losing candidates drop from (t1+t4) to
// (t1+t5) each, i.e. ≈ 2×(t4−t5) saved per tile (splits are per-
// candidate today; the lever can additionally share the wrapped split).
//
// Cross-check (free real-data gate): on every measured tile,
// t5 must equal the t4 stream's post-even-pad length. Any mismatch →
// nonzero exit + printed evidence.
//
// CLI: l1m1 --origdir DIR [--limit N (default 4)] [--passes K (default 5)]
//        [--prec 12|10|both (default both)]
// Output: per-pass lines on stderr; final min/mean table + verdict on
// stdout.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use frameprism::{fastenc, log10, pack12, tiff, tileenc};
use tileenc::Grid;

/// Reference candidate order (tileenc::CANDIDATES is private; m1gate keeps
/// its own copy — same pattern).
const CANDS: [(tileenc::Orient, i32); 3] = [
    (tileenc::Orient::Wrapped, 7),
    (tileenc::Orient::Wrapped, 2),
    (tileenc::Orient::Natural, 1),
];

fn get<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let mut i = args.iter().position(|a| a == flag)?;
    i += 1;
    args.get(i).map(|s| s.as_str())
}

struct Frame {
    name: String,
    mosaic12: Vec<u16>,
    mosaic10: Vec<u16>,
    w: u32,
    h: u32,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let origdir = match get(&args, "--origdir").map(PathBuf::from) {
        Some(p) => p,
        None => {
            eprintln!("usage: l1m1 --origdir DIR [--limit N] [--passes K] [--prec 12|10|both]");
            return ExitCode::FAILURE;
        }
    };
    let limit: usize = get(&args, "--limit").and_then(|s| s.parse().ok()).unwrap_or(4);
    let passes: usize = get(&args, "--passes").and_then(|s| s.parse().ok()).unwrap_or(5);
    let precs: Vec<u32> = match get(&args, "--prec").map(|s| s.to_string()).as_deref() {
        Some("12") => vec![12],
        Some("10") => vec![10],
        Some("both") | None => vec![12, 10],
        Some(s) => {
            eprintln!("--prec must be 12, 10 or both, got {s}");
            return ExitCode::FAILURE;
        }
    };

    // Frame list: sorted DNG names, first `limit` (f001..f00N by name).
    let mut frames: Vec<PathBuf> = std::fs::read_dir(&origdir)
        .expect("origdir")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|x| x == "DNG").unwrap_or(false))
        .collect();
    frames.sort();
    frames.truncate(limit);
    if frames.is_empty() {
        eprintln!("no DNG frames in {origdir:?}");
        return ExitCode::FAILURE;
    }

    // Load once (I/O + unpack outside the timed region).
    let mut loaded: Vec<Frame> = Vec::with_capacity(frames.len());
    for f in &frames {
        let buf = std::fs::read(f).unwrap();
        let frame = tiff::read(&buf).unwrap();
        let (w, h) = (frame.width, frame.height);
        let mosaic12 = pack12::unpack12(frame.strip_slice(&buf), w, h).unwrap();
        let inv = log10::inv();
        let mosaic10 = mosaic12.iter().map(|v| inv[*v as usize]).collect();
        eprintln!(
            "loaded {}: {}x{} ({} frames total in dir)",
            f.file_name().unwrap().to_string_lossy(),
            w,
            h,
            frames.len()
        );
        loaded.push(Frame {
            name: f.file_name().unwrap().to_string_lossy().into_owned(),
            mosaic12,
            mosaic10,
            w,
            h,
        });
    }

    // Per (precision, pass): [t1..t5] in seconds, summed over all tiles×cands.
    let mut results: Vec<(u32, Vec<[f64; 5]>)> = Vec::new();
    let mut total_mismatch = 0usize;

    for &prec in &precs {
        let mut pass_acc: Vec<[f64; 5]> = Vec::with_capacity(passes);
        for pass in 0..passes {
            let mut acc = [0.0f64; 5];
            let mut ncand = 0usize;
            for fr in &loaded {
                let plane: &[u16] = if prec == 12 { &fr.mosaic12 } else { &fr.mosaic10 };
                let g = Grid::new(fr.w, fr.h);
                for r in 0..g.rows {
                    for c in 0..g.cols {
                        for &(orient, psv) in CANDS.iter() {
                            let s0 = Instant::now();
                            let p =
                                tileenc::planes_from_tile(plane, fr.w, fr.h, &g, r, c, orient)
                                    .unwrap();
                            acc[0] += s0.elapsed().as_secs_f64();

                            let s1 = Instant::now();
                            let (c0, c1) = fastenc::native_hist(&p, prec, psv).unwrap();
                            acc[1] += s1.elapsed().as_secs_f64();

                            let s2 = Instant::now();
                            let (_t0, _t1) = fastenc::native_tables(&c0, &c1);
                            acc[2] += s2.elapsed().as_secs_f64();

                            let s3 = Instant::now();
                            let full =
                                fastenc::encode_planes_native(&p, prec, psv).unwrap();
                            acc[3] += s3.elapsed().as_secs_f64();

                            let s4 = Instant::now();
                            let sz =
                                fastenc::encode_planes_native_size(&p, prec, psv).unwrap();
                            acc[4] += s4.elapsed().as_secs_f64();

                            ncand += 1;
                            if sz != full.len() + full.len() % 2 {
                                total_mismatch += 1;
                                eprintln!(
                                    "SIZE MISMATCH {prec}b {pass}: {} tile ({r},{c}) cand {orient:?} psv {psv}: size-only {sz} vs full post-pad {}",
                                    fr.name,
                                    full.len() + full.len() % 2
                                );
                            }
                        }
                    }
                }
            }
            // Per-pass line: stage totals (ms) + emission fraction.
            let n = (loaded.len()
                * (loaded[0].w.div_ceil(482) as usize)
                * (loaded[0].h.div_ceil(272) as usize)
                * 3) as f64;
            let cand_cost = (acc[0] + acc[3]) / n; // s per tile-candidate
            let emission = (acc[3] - acc[4]).max(0.0) / n;
            eprintln!(
                "{prec}b pass {pass}: n={ncand} (expect {n:.0}) | split {:.2} ms | hist {:.2} ms | table {:.2} ms | full {:.2} ms | size {:.2} ms | emit_share {:.1}% (cand cost {:.3} ms/tile-cand)",
                acc[0] * 1e3,
                acc[1] * 1e3,
                acc[2] * 1e3,
                acc[3] * 1e3,
                acc[4] * 1e3,
                if cand_cost > 0.0 {
                    emission / cand_cost * 100.0
                } else {
                    0.0
                },
                cand_cost * 1e3
            );
            pass_acc.push(acc);
        }
        results.push((prec, pass_acc));
    }

    // Final table: min/mean per stage across passes + verdict.
    println!("# stage decomposition — A001_001 {}f × 64 tiles × 3 cands, {} passes",
        loaded.len(), passes);
    println!("stage | per precision: min_ms mean_ms | (n = tiles × cands per pass)");
    let n = (loaded.len()
        * (loaded[0].w.div_ceil(482) as usize)
        * (loaded[0].h.div_ceil(272) as usize)
        * 3) as f64;
    let stage_names = ["split", "hist", "table", "full", "size"];
    for (prec, pass_acc) in &results {
        println!("prec {prec}:");
        for (si, name) in stage_names.iter().enumerate() {
            let vals: Vec<f64> = pass_acc.iter().map(|a| a[si] * 1e3).collect();
            let mn = vals.iter().cloned().fold(f64::MAX, f64::min);
            let mean = vals.iter().sum::<f64>() / vals.len() as f64;
            println!("  {name:5}  min {mn:8.2} ms   mean {mean:8.2} ms   (over {n:.0} tile-cands)");
        }
        let fmn: Vec<f64> = pass_acc.iter().map(|a| a[3] * 1e3).collect();
        let smn: Vec<f64> = pass_acc.iter().map(|a| a[4] * 1e3).collect();
        let cmin = pass_acc.iter().map(|a| (a[0] + a[3]) * 1e3).fold(f64::MAX, f64::min);
        let cmean = pass_acc.iter().map(|a| (a[0] + a[3]) * 1e3).sum::<f64>() / pass_acc.len() as f64;
        let e_min = fmn.iter().zip(&smn).map(|(f, s)| (f - s).max(0.0)).fold(f64::MAX, f64::min);
        let e_mean = (pass_acc.iter().map(|a| (a[3] - a[4]).max(0.0)).sum::<f64>() / pass_acc.len() as f64) * 1e3;
        println!(
            "  EMISSION (full − size): min {e_min:.2} ms  mean {e_mean:.2} ms  of candidate cost → share min {:.1}%  mean {:.1}%",
            if cmin > 0.0 { e_min / cmin * 100.0 } else { 0.0 },
            if cmean > 0.0 { e_mean / cmean * 100.0 } else { 0.0 }
        );
        let tiles_per_pass = n / 3.0;
        // e_min/e_mean are summed over ALL 3 candidates per tile; the lever
        // replaces only the 2 LOSERS with size-only, so the saving is
        // (2/3) of the per-tile total, not 2× it.
        let tiles_per_frame =
            (loaded[0].w.div_ceil(482) * loaded[0].h.div_ceil(272)) as f64;
        println!(
            "  expected A-lever saving (2 losing cands → size-only): min {:.3} ms/tile ({:.2} ms/frame), mean {:.3} ms/tile ({:.2} ms/frame) — plus the shareable wrapped split",
            (2.0 / 3.0) * e_min / tiles_per_pass,
            (2.0 / 3.0) * e_min / tiles_per_pass * tiles_per_frame,
            (2.0 / 3.0) * e_mean / tiles_per_pass,
            (2.0 / 3.0) * e_mean / tiles_per_pass * tiles_per_frame
        );
    }
    println!("size_mismatches_vs_full: {total_mismatch}");
    if total_mismatch > 0 {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
