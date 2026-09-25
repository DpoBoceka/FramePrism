//! Criterion bench: the speed criterion (50–150 ms/frame/core,
//! M-series) for the lossless tile encoder — 64 × 2-component (even/odd
//! column-plane) lossless JPEG, PSV 7, per 3856×2170 12-bit frame.
//!
//! Uses the real A001 f1 when the corpus is present, a deterministic
//! synthetic plane otherwise (clean clones). Single-threaded per
//! iteration — this is the per-CORE number the targets.

use criterion::{criterion_group, criterion_main, Criterion};

fn real_or_synthetic_frame() -> (Vec<u16>, u32, u32) {
    let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
    if let Ok(src) = std::fs::read(p) {
        if let Ok(frame) = frameprism::tiff::read(&src) {
            let packed = frame.strip_slice(&src);
            if let Ok(samples) = frameprism::pack12::unpack12(packed, frame.width, frame.height) {
                eprintln!("bench: real A001 f1 ({:?}x{:?})", frame.width, frame.height);
                return (samples, frame.width, frame.height);
            }
        }
    }
    // Deterministic synthetic 3856×2170 12-bit plane (LCG).
    eprintln!("bench: corpus absent — synthetic frame");
    let (w, h) = (3856u32, 2170u32);
    let mut state = 0x1234_5678_9ABC_DEF0u64;
    let mut v = vec![0u16; (w * h) as usize];
    for s in v.iter_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *s = ((state >> 20) & 0x0FFF) as u16;
    }
    (v, w, h)
}

fn bench_encode(c: &mut Criterion) {
    let (samples, w, h) = real_or_synthetic_frame();
    let grid = frameprism::tileenc::Grid::new(w, h);
    let mut group = c.benchmark_group("encode_frame");
    group.bench_function("lossless_tiles_12bit", |b| {
        b.iter(|| {
            let mut tiles = Vec::with_capacity((grid.cols * grid.rows) as usize);
            for r in 0..grid.rows {
                for col in 0..grid.cols {
                    tiles.push(
                        frameprism::tileenc::encode_tile(&samples, w, h, &grid, r, col, 12)
                            .expect("tile encode"),
                    );
                }
            }
            std::hint::black_box(tiles);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_encode);
criterion_main!(benches);
