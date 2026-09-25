// cand_probe: per-tile 3-candidate size probe (speed program).
//
// Measurement only — no shared-code change. For every .DNG in the input
// directory (sorted by name), parses the frame exactly the way the
// lossless path does (tiff::read → strip_slice → pack12::unpack12), builds
// the log10 code plane, and trial-encodes the measured 3 candidates
// ({wrapped-PSV7, wrapped-PSV2, natural-PSV1} — tileenc::CANDIDATES order,
// indices 0/1/2) at BOTH precisions via the same pub fn the worker uses
// (tileenc::encode_tile_candidates). The reported sizes are the even-padded
// post-PAD sizes — the values that go into TileByteCounts.
//
// CLI: cand_probe <INPUT_DIR> <OUT.tsv> [--frames N]
//   (--frames N: probe the first N .DNG only, in sorted order — sanity runs)
//
// Output: one TSV row per tile (row-major (r,c), the worker's push order):
//   file \t r \t c \t s12_0 \t s12_1 \t s12_2 \t best12 \t
//                  s10_0 \t s10_1 \t s10_2 \t best10
// with a header row. `bestNN` = index of the chosen candidate (smallest
// post-pad size; strict `<`, ties → earlier candidate — the 0.1.0 rule).
//
// Failures: a per-frame error is eprintln'd, counted, and makes the final
// exit code nonzero (no silent skips); the TSV holds rows for
// the successful frames only. Frame-level parallelism: rayon (order
// preserved; output deterministic).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use frameprism::{log10, pack12, tiff, tileenc};
use rayon::prelude::*;

fn frame_rows(path: &Path) -> Result<Vec<String>, String> {
    let buf = std::fs::read(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let frame = tiff::read(&buf).map_err(|e| format!("tiff parse: {e}"))?;
    let (pw, ph) = (frame.width, frame.height);
    let samples =
        pack12::unpack12(frame.strip_slice(&buf), pw, ph)
            .map_err(|e| format!("unpack12: {e}"))?;
    let codes10: Vec<u16> = {
        let inv = log10::inv();
        samples.iter().map(|v| inv[*v as usize]).collect()
    };
    let grid = tileenc::Grid::new(pw, ph);
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut rows = Vec::with_capacity((grid.rows * grid.cols) as usize);
    for r in 0..grid.rows {
        for c in 0..grid.cols {
            let (_, (streams12, sizes12, best12)) =
                tileenc::encode_tile_candidates(&samples, pw, ph, &grid, r, c, 12)
                    .map_err(|e| format!("tile ({r},{c}) prec12: {e}"))?;
            let (_, (streams10, sizes10, best10)) =
                tileenc::encode_tile_candidates(&codes10, pw, ph, &grid, r, c, 10)
                    .map_err(|e| format!("tile ({r},{c}) prec10: {e}"))?;
            // Only the sizes are needed; the candidate streams (the
            // worker's output) are dropped here — this probe measures
            // selection economics, not bytes.
            let _ = (streams12, streams10);
            rows.push(format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                name,
                r,
                c,
                sizes12[0],
                sizes12[1],
                sizes12[2],
                best12,
                sizes10[0],
                sizes10[1],
                sizes10[2],
                best10
            ));
        }
    }
    Ok(rows)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut input_dir: Option<PathBuf> = None;
    let mut out_tsv: Option<PathBuf> = None;
    let mut frames_n: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--frames" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--frames needs a value");
                    return ExitCode::from(2);
                }
                frames_n = Some(
                    args[i]
                        .parse::<usize>()
                        .unwrap_or_else(|_| {
                            eprintln!("--frames: not a usize: {}", args[i]);
                            std::process::exit(2);
                        }),
                );
            }
            a if a.starts_with("--") => {
                eprintln!("unknown flag: {a}");
                return ExitCode::from(2);
            }
            positional => {
                if input_dir.is_none() {
                    input_dir = Some(PathBuf::from(positional));
                } else if out_tsv.is_none() {
                    out_tsv = Some(PathBuf::from(positional));
                } else {
                    eprintln!("unexpected positional: {positional}");
                    return ExitCode::from(2);
                }
            }
        }
        i += 1;
    }
    let (input_dir, out_tsv) = match (input_dir, out_tsv) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            eprintln!("usage: cand_probe <INPUT_DIR> <OUT.tsv> [--frames N]");
            return ExitCode::from(2);
        }
    };

    let mut files: Vec<PathBuf> = match std::fs::read_dir(&input_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.extension()
                        .map(|x| x.to_string_lossy().eq_ignore_ascii_case("dng"))
                        .unwrap_or(false)
            })
            .collect(),
        Err(e) => {
            eprintln!("read_dir {}: {e}", input_dir.display());
            return ExitCode::from(1);
        }
    };
    files.sort();
    let total = files.len();
    if let Some(n) = frames_n {
        files.truncate(n);
    }
    eprintln!(
        "cand_probe: {} of {} .DNG frames in {}",
        files.len(),
        total,
        input_dir.display()
    );

    // Frame-level rayon; par_iter().collect() preserves input order, so the
    // TSV is deterministic (file-sorted, per-tile row-major).
    let t0 = std::time::Instant::now();
    let results: Vec<Result<Vec<String>, String>> = files
        .par_iter()
        .map(|p| frame_rows(p))
        .collect();
    let elapsed = t0.elapsed();

    let mut failures = Vec::new();
    let mut rows: Vec<String> = Vec::new();
    for (p, res) in files.iter().zip(results.iter()) {
        match res {
            Ok(rs) => rows.extend(rs.iter().cloned()),
            Err(e) => {
                eprintln!("FAIL {}: {e}", p.display());
                failures.push(p.display().to_string());
            }
        }
    }

    let header = "file\tr\tc\ts12_0\ts12_1\ts12_2\tbest12\ts10_0\ts10_1\ts10_2\tbest10\n";
    if let Some(parent) = out_tsv.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let mut out = match std::fs::File::create(&out_tsv) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("create {}: {e}", out_tsv.display());
            return ExitCode::from(1);
        }
    };
    let mut w = std::io::BufWriter::new(&mut out);
    if w.write_all(header.as_bytes()).is_err() || w.write_all(rows.join("\n").as_bytes()).is_err()
    {
        eprintln!("write {}: io error", out_tsv.display());
        return ExitCode::from(1);
    }
    if w.write_all(b"\n").is_err() {
        eprintln!("write {}: io error", out_tsv.display());
        return ExitCode::from(1);
    }
    drop(w);
    drop(out);

    eprintln!(
        "cand_probe: {} rows from {} frames in {:.1}s ({} ok, {} failed) → {}",
        rows.len(),
        files.len(),
        elapsed.as_secs_f64(),
        files.len() - failures.len(),
        failures.len(),
        out_tsv.display()
    );
    if failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
