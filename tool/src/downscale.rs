//! downscale2x: CFA-phase-correct 2× decimation of the unpacked
//! raw plane — the half-resolution working-file mode.
//!
//! RULE (measured parity): the "staircase/pinwheel"
//! decimation, measured from the corpus
//! (fit against the measured decoded plane: 74–84%
//! pixel-exact, MAE 0.17–0.31 LSB, residual = the measured encoder's own
//! unidentifiable ±1–2 LSB δ):
//!
//!     P[y, x] = o[2y + (x&1),  2x + (y&1)]
//!
//! **Phase correctness.** For the 2×2 pattern the file declares, anchored
//! at (0,0), the source phase of output (x, y) is (y&1, x&1) — the
//! *transposed* position. A 2×2 pattern whose two off-diagonal classes are
//! equal (all standard Bayers: the two greens sit off-diagonal; the fp:
//! 33422 = (0,1,1,2) = W G / G R — off-diagonals both green, 1 == 1) is
//! symmetric, so the transposed class equals the declared class at every
//! position → the decimated plane is a legal CFA image and the CFA tags
//! stay VALID, preserved byte-identical (see surgery.rs). The two
//! diagonal phases pass through unchanged; the two off-diagonal phases
//! are swapped but carry the same class.
//!
//! **Fallback: phase-exact.** For an asymmetric 2×2 pattern (off-diagonals
//! differ — e.g. GBRG/GRBG families) or a non-zero CFAPlaneLeft/Top
//! anchor (50969/50970), the staircase would put the wrong class in the
//! off-diagonal positions (a color cast). The phase-exact mapping
//!
//!     P[y, x] = o[2y + ((y−t)&1), 2x + ((x−l)&1)]
//!
//! takes the source pixel whose phase equals the output's declared phase
//! at every position — correct for ANY 2×2 pattern. `decimation_rule`
//! picks between the two from the frame's CFA tags.
//!
//! **Superseded (user playback test): even/even decimation.**
//! The old rule `P[y,x] = o[2y, 2x]` kept ONLY the (0,0) phase — for a
//! 2×2 pattern every output pixel has the input's top-left class, so the
//! plane is single-phase. Declared as a 2×2 CFA image it demosaics in NLEs
//! with a strong color cast (A001 ds2x rendered magenta in Resolve; the
//! raw-level checks missed it: the clip is dark — signal 253–574 — so the
//! raw-plane MAE vs the measured encoder was only 1.9–6.5 LSB, and `--verify`
//! compares against our own decimation). The module's old "single-phase
//! proxy plane is acceptable as a working file" note is retracted: a
//! single-phase plane is NOT a working raw file, it is a color-cast
//! artifact. No box/area filter either — averaging different CFA phases
//! into one pixel destroys the phase information the same way (it just
//! hides it better).
//!
//! Geometry: W×H → (W/2)×(H/2) (W even is required by the 12-bit packing
//! check; H even on A001 = 2170 → 1928×1085; odd H floors — the max
//! source index 2·(H/2−1)+1 = H−2 ≤ H−1 is in bounds either way). The tile
//! grid is recomputed for the half size (3856×2170 → 1928×1085 → 4×4
//! tiles; last-row tiles 482×269 → padded to full-272 geometry, see
//! tileenc::padded_tl).

use crate::tiff::Frame;

/// Which 2× decimation mapping to use for a frame (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Reference staircase `P[y,x] = o[2y+(x&1), 2x+(y&1)]` — only selected
    /// when the declared 2×2 pattern is symmetric (off-diagonals equal)
    /// and the CFA anchor is (0,0).
    Staircase,
    /// Phase-exact `P[y,x] = o[2y+((y−t)&1), 2x+((x−l)&1)]` — phase-correct
    /// for any 2×2 pattern, with the CFAPlaneLeft/Top anchor (l, t).
    PhaseExact { cl: u32, ct: u32 },
}

/// Choose the decimation rule from the frame's CFA tags. Infallible on
/// purpose: any tag anomaly (missing pattern, unexpected type, >2×2)
/// falls back to the phase-exact rule with the anchor read or (0,0) —
/// the always-phase-correct mapping, never the color-casting one.
pub fn decimation_rule(src: &[u8], frame: &Frame) -> Rule {
    // CFA pattern: 50967 (DNG) preferred, else 33422 (legacy; the fp).
    // (A MISSING tag is Ok(None) — fall through to the legacy tag; only
    // malformed tags (Err) also fall through, since the other tag may be
    // the file's pattern.)
    let mut pat_v: Option<Vec<u8>> = crate::surgery::ifd_tag_bytes_opt(src, frame, 50967)
        .ok()
        .flatten();
    if pat_v.is_none() {
        pat_v = crate::surgery::ifd_tag_bytes_opt(src, frame, 33422)
            .ok()
            .flatten();
    }
    let pat: Option<[u8; 4]> = match pat_v {
        Some(v) if v.len() == 4 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(&v[..4]);
            Some(a)
        }
        _ => None,
    };
    let mut dims_v: Option<Vec<u32>> = crate::surgery::ifd_tag_u32s_opt(src, frame, 50966)
        .ok()
        .flatten();
    if dims_v.is_none() {
        dims_v = crate::surgery::ifd_tag_u32s_opt(src, frame, 33421)
            .ok()
            .flatten();
    }
    let dims: Option<(u32, u32)> = match dims_v {
        Some(v) if v.len() == 2 => Some((v[0], v[1])),
        _ => None,
    };
    let cl = crate::surgery::ifd_tag_u32s_opt(src, frame, 50969)
        .ok()
        .flatten()
        .filter(|v| v.len() == 1)
        .map(|v| v[0])
        .unwrap_or(0);
    let ct = crate::surgery::ifd_tag_u32s_opt(src, frame, 50970)
        .ok()
        .flatten()
        .filter(|v| v.len() == 1)
        .map(|v| v[0])
        .unwrap_or(0);
    match (pat, dims) {
        (Some(p), Some((2, 2))) if cl == 0 && ct == 0 && p[1] == p[2] => Rule::Staircase,
        _ => Rule::PhaseExact { cl, ct },
    }
}

/// Decimate `mosaic` (row-major, `w`×`h`) 2× per `rule`; returns
/// (plane, out_w, out_h). Pure pixel selection — no filtering.
pub fn decimate2x(mosaic: &[u16], w: u32, h: u32, rule: Rule) -> (Vec<u16>, u32, u32) {
    debug_assert_eq!(
        mosaic.len(),
        (w as usize) * (h as usize),
        "mosaic length must be w*h"
    );
    let hw = (w / 2) as usize;
    let hh = (h / 2) as usize;
    let w = w as usize;
    let mut out = vec![0u16; hw * hh];
    for y in 0..hh {
        let y32 = y as u32;
        for x in 0..hw {
            let (dy, dx): (usize, usize) = match rule {
                Rule::Staircase => (x & 1, y & 1),
                Rule::PhaseExact { cl, ct } => (
                    (y32.wrapping_sub(ct) & 1) as usize,
                    ((x as u32).wrapping_sub(cl) & 1) as usize,
                ),
            };
            out[y * hw + x] = mosaic[(2 * y + dy) * w + (2 * x + dx)];
        }
    }
    (out, hw as u32, hh as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CFA-phase marker mosaic for a 2×2 pattern `pat` (row-major [p00,p10,
    /// p01,p11] with distinct values per class): pixel (y,x) = the class
    /// value at (x%2, y%2) + a small position marker (x + 100*w... no —
    /// the position must stay inside the class block; use a separate
    /// function for position checks).
    fn cfa_mosaic(w: usize, h: usize, pat: [u16; 4]) -> Vec<u16> {
        (0..(w * h))
            .map(|i| {
                let x = (i % w) as u32;
                let y = (i / w) as u32;
                pat[(y % 2) as usize * 2 + (x % 2) as usize]
            })
            .collect()
    }

    /// Position-exact marker mosaic (catches any mapping that is not
    /// exactly the documented index rule).
    fn pos_mosaic(w: usize, h: usize) -> Vec<u16> {
        (0..(w * h)).map(|i| (i as u16) % 60000).collect()
    }

    /// THE regression test (the magenta bug): the decimated plane
    /// must carry the declared CFA class at every position — for the fp's
    /// symmetric pattern (W G / G R, codes [3,1,1,2]) the Staircase rule
    /// must output the SAME class value at each (x%2, y%2) position.
    #[test]
    fn staircase_is_phase_correct_on_symmetric_pattern() {
        let (w, h) = (8usize, 8);
        let pat: [u16; 4] = [3000, 1000, 1000, 2000]; // W G / G R (fp classes)
        let m = cfa_mosaic(w, h, pat);
        let (out, ow, oh) = decimate2x(&m, w as u32, h as u32, Rule::Staircase);
        let (ow, oh) = (ow as usize, oh as usize);
        assert_eq!((ow, oh), (4, 4));
        for y in 0..oh as usize {
            for x in 0..ow as usize {
                assert_eq!(
                    out[y * ow + x],
                    pat[(y % 2) * 2 + (x % 2)],
                    "phase class wrong at ({x},{y})"
                );
            }
        }
    }

    /// Same check for the PhaseExact rule (correct for ANY pattern) — and
    /// the staircase is PROVEN to fail it on an asymmetric pattern (G B /
    /// R G), which is why decimation_rule refuses it there.
    #[test]
    fn phase_exact_is_phase_correct_on_asymmetric_pattern() {
        let (w, h) = (8usize, 8);
        let pat: [u16; 4] = [3000, 2000, 4000, 1000]; // G B / R G (asymmetric)
        let m = cfa_mosaic(w, h, pat);
        let (out, ow, oh) = decimate2x(&m, w as u32, h as u32, Rule::PhaseExact { cl: 0, ct: 0 });
        let (ow, oh) = (ow as usize, oh as usize);
        for y in 0..oh {
            for x in 0..ow {
                assert_eq!(out[y * ow + x], pat[(y % 2) * 2 + (x % 2)]);
            }
        }
        // The staircase swaps the off-diagonal classes here (B vs R) →
        // 50% of positions wrong. Document the refusal empirically.
        let (bad, _, _) = decimate2x(&m, w as u32, h as u32, Rule::Staircase);
        let wrong = (0..ow * oh)
            .filter(|&i| bad[i] != pat[(i % ow % 2) + ((i / ow) % 2) * 2])
            .count();
        assert_eq!(
            wrong,
            ow * oh / 2,
            "staircase must be wrong on exactly the off-diagonals for an asymmetric pattern"
        );
    }

    /// Phase-exact honors a non-zero CFA anchor: with cl=1, ct=0 the
    /// declared class of (x,y) is pattern[(x−1)%2, y%2] — the source pixel
    /// must sit on that class.
    #[test]
    fn phase_exact_honors_cfa_anchor() {
        let (w, h) = (8usize, 8);
        let pat: [u16; 4] = [3000, 2000, 4000, 1000];
        let m = cfa_mosaic(w, h, pat); // mosaic phase = (x%2, y%2) anchored at (0,0)
        let (out, ow, oh) = decimate2x(&m, w as u32, h as u32, Rule::PhaseExact { cl: 1, ct: 0 });
        let (ow, oh) = (ow as usize, oh as usize);
        for y in 0..oh {
            for x in 0..ow {
                let decl = ((x as u32).wrapping_sub(1) % 2) as usize + (y % 2) * 2;
                assert_eq!(
                    out[y * ow + x],
                    pat[decl],
                    "anchor (1,0) mishandled at ({x},{y})"
                );
            }
        }
    }

    /// Index-rule checks for both mappings (position markers).
    #[test]
    fn mappings_match_documented_index_rule() {
        let (w, h) = (8usize, 6);
        let m = pos_mosaic(w, h);
        // Staircase: out[y,x] = m[(2y+(x&1))*w + (2x+(y&1))]
        let (out, ow, oh) = decimate2x(&m, w as u32, h as u32, Rule::Staircase);
        let (ow, oh) = (ow as usize, oh as usize);
        assert_eq!((ow, oh), (4, 3));
        for y in 0..oh {
            for x in 0..ow {
                let sy = 2 * y + (x & 1);
                let sx = 2 * x + (y & 1);
                assert_eq!(out[y * ow + x], m[sy * w + sx]);
            }
        }
        // PhaseExact (0,0): out[y,x] = m[(2y+(y&1))*w + (2x+(x&1))]
        let (out, ow, oh) = decimate2x(&m, w as u32, h as u32, Rule::PhaseExact { cl: 0, ct: 0 });
        let (ow, oh) = (ow as usize, oh as usize);
        for y in 0..oh {
            for x in 0..ow {
                let sy = 2 * y + (y & 1);
                let sx = 2 * x + (x & 1);
                assert_eq!(out[y * ow + x], m[sy * w + sx]);
            }
        }
    }

    #[test]
    fn odd_height_floors() {
        // Odd H: 7 rows -> 3 rows; max source row 2*2+1 = 5 ≤ 6.
        let (w, h) = (4usize, 7);
        let m = pos_mosaic(w, h);
        for rule in [Rule::Staircase, Rule::PhaseExact { cl: 0, ct: 0 }] {
            let (out, ow, oh) = decimate2x(&m, w as u32, h as u32, rule);
            let (ow, oh) = (ow as usize, oh as usize);
            assert_eq!((ow, oh), (2, 3));
            for y in 0..3 {
                for x in 0..2 {
                    let (dy, dx) = match rule {
                        Rule::Staircase => (x & 1, y & 1),
                        _ => (y & 1, x & 1),
                    };
                    assert_eq!(out[y * 2 + x], m[(2 * y + dy) * w + (2 * x + dx)]);
                }
            }
        }
    }

    /// decimation_rule on the real fp file: 33422 = (0,1,1,2) (W G / G R,
    /// symmetric), no 50969/50970 → Staircase. (Guard for the magenta fix:
    /// if the rule ever flips to PhaseExact on this frame the ds2x content
    /// still demosaics correctly — but the measured-parity fit degrades from
    /// ~77% to ~76% exact, so the canary below pins the choice.)
    #[test]
    fn real_a001_frame1_rule_is_staircase() {
        let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let src = match std::fs::read(p) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                return;
            }
        };
        let f = crate::tiff::read(&src).unwrap();
        assert_eq!(decimation_rule(&src, &f), Rule::Staircase);
    }

    /// A001 f1 canary for the staircase decimation (measured):
    /// the decimated plane is now a full 4-phase mosaic — min 254, max 877
    /// (the bright spot 881 at (411,744) → 877 = its /2 −1, inside the
    /// measured ±1–2 δ band; the measured encoder's own recon reads 255/878 — the 1
    /// LSB difference is the measured encoder's unidentifiable per-pixel δ), mean 271.49. The OLD even/even canary
    /// (253/574/267) pinned the single-phase sub-lattice — deleted with
    /// the bug.
    #[test]
    fn real_a001_frame1_staircase_canary() {
        let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let src = match std::fs::read(p) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                return;
            }
        };
        let f = crate::tiff::read(&src).unwrap();
        let packed = f.strip_slice(&src);
        let samples = crate::pack12::unpack12(packed, f.width, f.height).unwrap();
        let rule = decimation_rule(&src, &f);
        assert_eq!(rule, Rule::Staircase);
        let (half, hw, hh) = decimate2x(&samples, f.width, f.height, rule);
        assert_eq!((hw, hh), (1928, 1085), "3856x2170 -> 1928x1085");
        assert_eq!(half.len(), (1928 * 1085) as usize);
        let (hw, hh) = (hw as usize, hh as usize);
        let min = half.iter().min().copied().unwrap_or(0) as i64;
        let max = half.iter().max().copied().unwrap_or(0) as i64;
        let mean = half.iter().map(|v| *v as i64).sum::<i64>() / (hw * hh) as i64;
        eprintln!(
            "decimated f1 (staircase): {}x{} min={} max={} mean={}",
            hw, hh, min, max, mean
        );
        assert_eq!(min, 254, "f1 decimated min drifted");
        assert_eq!(max, 877, "f1 decimated max drifted (full 4-phase mosaic)");
        assert!(
            (270..273).contains(&mean),
            "f1 decimated mean {} drifted (measured 271)",
            mean
        );
        // 4-phase check: the four sub-lattices must carry DIFFERENT class
        // means (a single-phase plane — the old bug — has ~equal ones).
        let mean_at = |dy: usize, dx: usize| -> f64 {
            let mut s = 0i64;
            let mut c = 0;
            for y in (dy..hh as usize).step_by(2) {
                for x in (dx..hw as usize).step_by(2) {
                    s += half[y * hw + x] as i64;
                    c += 1;
                }
            }
            s as f64 / c as f64
        };
        let m00 = mean_at(0, 0);
        let m10 = mean_at(0, 1);
        let m01 = mean_at(1, 0);
        let m11 = mean_at(1, 1);
        eprintln!("  class means: W(0,0)={m00:.2} G(1,0)={m10:.2} G(0,1)={m01:.2} R(1,1)={m11:.2}");
        // fp classes on this clip: W≈267.1, G≈266.4, G≈266.4, R≈276.3
        // (rawpy original class means over the (8,5) crop) — the R class
        // must stand clearly above the greens (spread ≥ 8 LSB). The old
        // single-phase plane had all four ≈ 267 (spread < 2).
        let spread = [m00, m10, m01, m11]
            .iter()
            .cloned()
            .fold(0.0f64, |a, b| a.max(b))
            - [m00, m10, m01, m11]
                .iter()
                .cloned()
                .fold(f64::MAX, |a, b| a.min(b));
        assert!(
            spread >= 8.0,
            "class spread {spread:.2} too small — single-phase plane?"
        );
    }
}
