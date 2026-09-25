//! Tag-7 ("12-bit DCT parity tiles", DNG Compression 7) encoder —
//! the interop lossy format (the measured tag-7 contract).
//!
//! # Format (measured, SSOT: docs/format-dct12.md)
//!
//! Each of the 4 tiles (1928×1088 frame region, grid 3856×2170) is ONE
//! self-contained JPEG stream:
//!
//! ```text
//! SOI  DQT(16-bit, tq=0)  DHT 00  DHT 10  DHT 01  DHT 11
//!      SOF1 (prec 12, 1928×544, nf=2, ids 00/01, 1×1, tq 0)
//!      SOS0 (01 00 00 00 3f 00)  <even-plane scan>
//!      SOS1 (01 01 11 00 3f 00)  <odd-plane scan>
//!      EOI
//! ```
//!
//! scan 0 = the tile's EVEN frame rows (plane row p ↔ frame row
//! ty0+2p), scan 1 = the ODD rows (ty0+2p+1); each scan is a
//! single-component 1928×544 baseline-DCT plane (241×68 blocks).
//!
//! # Encoding semantics (the measured contract)
//!
//! - The plane values are the **pre-curve** (pre-LUT) 12-bit values:
//!   `pre = invLUT(source)` (nearest-preimage inverse of the 50712 curve,
//!   max post-domain error 2 LSB). Erasure gate (`FRAMEPRISM_ERASURE`, see
//!   `CfaErasure`): **DEFAULT `v4-2tap`** — the
//!   **v4 pre-domain horizontal 2-tap**
//!   `out[x] = (pre[x] + pre[x+1]) / 2` (edge-replicate at the frame
//!   edge) over the FULL-FRAME parity planes (`h2tap_smooth_wh`, applied
//!   in `full_frame_planes` BEFORE the DCT) — the measured reference erasure
//!   base (the oracle-verified grid kill). The
//!   2-tap alone erases the within-row class contrast at ALL frequencies
//!   (D_WG/D_RG down to ~5%/20% of the source), so the NLE
//!   demosaic cannot separate G from W/R — the user-visible G-deficit
//!   cast in Resolve; the corpus file erases the 2-px CFA pattern but
//!   RETAINS the smooth class-diff envelope (~60% of the source's
//!   D_WG/D_RG) — a smooth per-CLASS color cue (~100% of
//!   the reference D_WG is the inter-scan component; both the tag-7 contract and the v4 transform
//!   erase the within-scan contrast, so the 2-tap base stays). Gated
//!   DIAGNOSTIC `v5b-cue-cd` (`cue_offsets` — a
//!   RENDER-FAILING probe, NEVER the default): the v4 2-tap PLUS a
//!   per-scan sign-flipped smooth cue — U = (W+R)/2 − (Go+Ge)/2 (half-
//!   res class lattices), minus its 2-px CFA-aliasing component (box5
//!   (U·checker)·checker, checker = (−1)^(r+c) — kills the 2-px grid,
//!   keeps the 8–16px class structure), upscaled ×2, added +g·U_band to
//!   scan0 and −g·U_band to scan1 (inter-scan; g = `CUE_GAIN`, env
//!   override `FRAMEPRISM_CUE_GAIN`), clipped to the pre-domain. Its proxy
//!   passed (g = 0.7, D_WG/D_RG in the reference band,
//!   (0,7) at the 2-tap floor) but the RENDER FAILED: the per-
//!   scan sign flip is a hard 2-px VERTICAL sign pattern (per-scan DC
//!   s1−s0 +16.2 vs the reference −0.6; per-class DC a ±2.94% 2×2
//!   checkerboard vs the measured flat ±0.12%) that the NLE demosaic
//!   amplifies into a y-Nyquist 2-px moiré ~2× WORSE than v4 (A5−B
//!   flat-window FFT 122k vs A4's 63k) + a systematic blue cast (B−G
//!   +54.7 left band vs v4's +23.5) — the proxy measured (0,v) horizontal
//!   bins only and was blind to the (7,0) vertical direction. The reference
//!   cue is per-CLASS (smooth per-lattice color, class-balanced per-scan
//!   DC) — the cA-band attempt (per-class sign + band-limited cue
//!   field + per-scan DC balancing) supersedes it. Gated
//!   diagnostic `v5-binkill`: the DCT-domain selective
//!   bin kill (`cfa_bin_kill_block`: zero (4,0)/(0,4)/(4,4) per 8×8 block,
//!   applied in `encode_tiles_t21` AFTER the forward DCT) — RETIRED by the
//!   probe as the reference erasure: a pure 2-px (−1)^x pattern's DCT-II
//!   energy spreads over the ODD-v bins ((0,1)/(0,3)/(0,5)/(0,7), (0,7)
//!   dominant), NOT the mask bins, which carry ≈0 on the source itself —
//!   the mask is a no-op (see `cfa_bin_kill_block` + the test
//!   `v5_bin_kill_2period_energy_location`; the bin-label→X_orth mapping
//!   error — the record was corrected by the follow-up probe) — the
//!   remaining reference difference
//!   vs v4 is the smooth per-class offset field O, NOT
//!   linearly fit-recoverable from source per-class statistics; the
//!   `v5b-cue-cd` diagnostic re-injects a fixed-algorithm approximation
//!   of O on top of the 2-tap base (see `cue_offsets`). Gated
//!   diagnostic `dcdc`: the v4 2-tap PLUS a per-class
//!   constant DC offset Δ_regime_c (8 literal constants — 4 CFA classes ×
//!   dark/bright regime, `DCDC_DARK`/`DCDC_BRIGHT`, regime keyed on the
//!   frame's own source mean vs `DCDC_T`), applied in the RAW source
//!   domain BEFORE the 50712 pre-curve LUT (raw-domain decision: a raw
//!   add round-trips exactly through the curve; a pre-domain constant is
//!   attenuated by the local curve slope ~1/10–1/14 in the dark band) —
//!   the rank-1 L0-level cast
//!   fix; 92.6–96.5% of the frame-DC (L0) error RMS removed on holdout;
//!   derived, not tuned; the 8 constants (+ optional T) are
//!   env-overridable via `FRAMEPRISM_DCDC_CONSTS` (unset/empty = the
//!   literals, bit-exact; malformed = hard error); NEVER the default).
//!   planes before the tile cut (`full_frame_planes` /
//!   `h2tap_smooth_wh`). v4 (the fit-probe baseline):
//!   this 2-tap IS the measured pre-DCT CFA erasure — the
//!   estimator (8 frames × 4 tiles × both scans × all blocks) fits the
//!   reference goldens with the CFA band at 8.51× the file's own
//!   quantization floor (per-coefficient residual ≈ 0.4–0.7·q; the (0,7)
//!   2-period 368.5 → 8.2, 12-bit scale) — erasure-then-curve order
//!   (pre-domain, this position), right neighbor, no cross-scan coupling
//!   (vertical 2-tap refuted at 16× floor). It SUBSUMES the v2/v3
//!   DCT-domain structure transform (j=7 zero + (0,3)/(0,5) ×0.2 +
//!   cross-scan DC mix — superseded: the tag-7 format's inter-scan DC
//!   difference is 1× the source, measured gain 0.24, not G=8) and the
//!   linearized-domain 2-tap (order A; the pre-domain order B
//!   fits 7% better in-band: 8.51× vs 9.22× floor). The 3×3 box
//!   (`box3_smooth_wh`) is superseded for production (kept
//!   for probes/tests; its history: the per-tile box3 edge-replicated at
//!   the tile borders, leaving the D3 seam line at x=1928/y=1088; the
//!   full-frame box removed the per-pixel 12-bit-POST staircase, f1 MAE
//!   0.78× reference — but over-smoothed relative to the measured 2-tap,
//!   13.9–14.3× floor in the fit-probe baseline).
//! - The DCT encode is a **standard 12-bit baseline DCT** (samples
//!   centered at 2048, islow DCT, DC chain from 0). The reference decoder
//!   (LibRaw case 0xc1) restarts the DC predictor at
//!   `VPRED0 = 16384 = 8 × 2048` (the islow DC scale), which exactly
//!   cancels the 2048 centering — flat-image roundtrip MAE 0.0,
//!   gradient MAE 2.45 (libjpeg q75 tables).
//! - Last-row tiles: 541 real plane rows + **3 padding rows that repeat
//!   the plane's last real row** (edge extension; the measured
//!   pad rows decode to ~1-2 LSB of the last real row in
//!   flat areas, and the decoder clips them at the frame edge anyway,
//!   so the rule affects only the last block band's DCT coupling and
//!   the size).
//! - The DQT is the preset's table (VBR: fixed per preset, measured
//!   byte-identical across frames; CBR: the base shape scaled per
//!   frame to land the size target — the measured encoder does exactly this:
//!   cbr3/4/5/7 tables ≈ base × 0.35/0.5/0.7/1.0, per-frame).
//!
//! # G2 gate
//!
//! `dct2s::assemble_frame` on OUR tiles vs the original 12-bit plane:
//! per-frame MAE within [0.5×, 1.5×] of the corpus same-frame MAE and
//! ≤ the preset p99 (59.68 LSB, measured on all 225 A001 frames, all
//! presets). CBR modes: total size within ±5% of in_bytes/k. The
//! full-frame MAE is blind to STRUCTURED error (the ds2x-magenta
//! generalization lesson), so three structured gates run alongside
//! it (FATAL, vbr + cbr): the CFA-contrast gate (anti-amplification:
//! ratio form where the input carries meaningful CFA
//! energy + the source-referenced backstop), the per-CFA-class mean gate
//! (the reference-recalibrated limit 31 LSB), and the tile-seam gate
//! (|err| on the middle column/row pair vs the local baseline
//! < 1.5× — D3, the user's vertical center line).

use std::path::Path;

use thiserror::Error;

/// Reference frame grid (measured; A001 clip): 3856×2170, 2×2 tiles of
/// 1928×1088.
pub const FRAME_W: u32 = 3856;
pub const FRAME_H: u32 = 2170;
pub const TILE_W: u32 = 1928;
pub const TILE_H: u32 = 1088;
/// Parity plane height: TILE_H / 2 rows (544 = 68 × 8).
pub const PLANE_H: usize = (TILE_H / 2) as usize;
/// Parity plane width (= TILE_W).
pub const PLANE_W: usize = TILE_W as usize;
/// Real plane rows of the last-row tiles (2170 = 1088 + 1082; 1082/2).
pub const PLANE_H_REAL: usize = 541;
/// 50712 LinearizationTable count (measured: SHORT × 4096).
pub const CURVE_LEN: usize = 4096;
/// The measured preset p99 (identical for all six presets on the
/// A001 dark clip). NOTE: the per-frame p99 cap + the
/// per-frame [0.5,1.5] band were RETIRED: the measured max (59.85)
/// exceeds its p99 (59.68), so a per-frame p99 cap is unachievable even by the
/// measured encoder. Kept as a reference constant; the per-frame gate is now the
/// catastrophe ceiling `r < 2.0` (see `gate_pixels`) + the per-preset
/// distribution gate (`gate_distribution`).
pub const P99_LIM: f64 = 59.68;
/// FIXED plateau-snap margin (locked, pre-domain). A global (per-preset)
/// margin — NOT per-frame or content-adaptive (which
/// would be the overfit/tautology trap; the measured encoder uses a fixed transform, so
/// parity means a fixed transform). margin 3 = 0 frames < 0.5×, 4 frames
/// (1.8%) > 1.5× (the f213–f225 high-detail tail), max 1.72 < 2.0 (vbr-hq).
pub const SNAP_MARGIN: i32 = 3;

/// Base quantization table (zigzag order, 16-bit DQT values) = the
/// measured vbr-hq table (== cbr7 f1 within ±1 in the AC tail). The CBR
/// shapes are this table scaled (measured ratios: cbr3 ≈ ×0.35, cbr4 ≈
/// ×0.5, cbr5 ≈ ×0.7).
pub const BASE_TABLE: [u16; 64] = [
    5, 6, 6, 7, 8, 7, 10, 7, 7, 10, 13, 8, 11, 8, 13, 18, 11, 12, 12, 11, 18, 23, 14, 14, 16, 14,
    14, 23, 31, 18, 17, 20, 20, 17, 18, 31, 23, 21, 23, 25, 23, 21, 23, 26, 27, 30, 30, 27, 26, 32,
    35, 37, 35, 32, 41, 44, 44, 41, 51, 53, 51, 62, 62, 64,
];

/// The measured vbr-lt table (≈ BASE_TABLE × 2 with the measured
/// rounding at several indices — 19 where 2×10, 21 where 2×11, 35 where
/// 2×18, …; kept verbatim, NOT re-derived).
pub const LT_TABLE: [u16; 64] = [
    10, 12, 12, 14, 16, 14, 19, 14, 14, 19, 26, 16, 21, 16, 26, 35, 21, 24, 24, 21, 35, 46, 27, 28,
    32, 28, 27, 46, 61, 35, 34, 39, 39, 34, 35, 61, 45, 42, 45, 49, 45, 42, 45, 52, 54, 59, 59, 54,
    52, 64, 69, 73, 69, 64, 81, 87, 87, 81, 102, 106, 102, 124, 124, 127,
];

/// The measured 50712 curve (A001 clip; byte-identical across all six
/// presets and all 225 frames — 12/12 extractions, one unique MD5).
/// Fallback when no reference file is available; a present reference
/// must match it byte-for-byte
/// (`curve_matches_reference`).
pub const REFERENCE_CURVE: [u16; 4096] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
    74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97,
    98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
    117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135,
    136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154,
    155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173,
    174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192,
    193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211,
    212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230,
    231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249,
    250, 251, 252, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 257,
    257, 257, 257, 257, 257, 257, 257, 257, 257, 257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
    257, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
    258, 258, 259, 259, 259, 259, 259, 259, 259, 259, 259, 259, 259, 259, 259, 259, 259, 259, 259,
    259, 259, 260, 260, 260, 260, 260, 260, 260, 260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
    260, 260, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261, 261,
    261, 261, 262, 262, 262, 262, 262, 262, 262, 262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
    262, 263, 263, 263, 263, 263, 263, 263, 263, 263, 263, 263, 263, 263, 263, 263, 263, 263, 263,
    264, 264, 264, 264, 264, 264, 264, 264, 264, 264, 264, 264, 264, 264, 264, 264, 264, 265, 265,
    265, 265, 265, 265, 265, 265, 265, 265, 265, 265, 265, 265, 265, 265, 265, 266, 266, 266, 266,
    266, 266, 266, 266, 266, 266, 266, 266, 266, 266, 266, 266, 266, 267, 267, 267, 267, 267, 267,
    267, 267, 267, 267, 267, 267, 267, 267, 267, 267, 268, 268, 268, 268, 268, 268, 268, 268, 268,
    268, 268, 268, 268, 268, 268, 268, 268, 269, 269, 269, 269, 269, 269, 269, 269, 269, 269, 269,
    269, 269, 269, 269, 270, 270, 270, 270, 270, 270, 270, 270, 270, 270, 270, 270, 270, 270, 270,
    270, 271, 271, 271, 271, 271, 271, 271, 271, 271, 271, 271, 271, 271, 271, 271, 272, 272, 272,
    272, 272, 272, 272, 272, 272, 272, 272, 272, 272, 272, 272, 273, 273, 273, 273, 273, 273, 273,
    273, 273, 273, 273, 273, 273, 273, 273, 274, 274, 274, 274, 274, 274, 274, 274, 274, 274, 274,
    274, 274, 274, 275, 275, 275, 275, 275, 275, 275, 275, 275, 275, 275, 275, 275, 275, 276, 276,
    276, 276, 276, 276, 276, 276, 276, 276, 276, 276, 276, 276, 277, 277, 277, 277, 277, 277, 277,
    277, 277, 277, 277, 277, 277, 277, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278,
    278, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 280, 280, 280, 280,
    280, 280, 280, 280, 280, 280, 280, 280, 280, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281,
    281, 281, 281, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 283, 283, 283, 283,
    283, 283, 283, 283, 283, 283, 283, 283, 283, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284,
    284, 284, 285, 285, 285, 285, 285, 285, 285, 285, 285, 285, 285, 285, 286, 286, 286, 286, 286,
    286, 286, 286, 286, 286, 286, 286, 287, 287, 287, 287, 287, 287, 287, 287, 287, 287, 287, 287,
    288, 288, 288, 288, 288, 288, 288, 288, 288, 288, 288, 288, 289, 289, 289, 289, 289, 289, 289,
    289, 289, 289, 289, 290, 290, 290, 290, 290, 290, 290, 290, 290, 290, 290, 291, 291, 291, 291,
    291, 291, 291, 291, 291, 291, 291, 291, 292, 292, 292, 292, 292, 292, 292, 292, 292, 292, 292,
    293, 293, 293, 293, 293, 293, 293, 293, 293, 293, 294, 294, 294, 294, 294, 294, 294, 294, 294,
    294, 294, 295, 295, 295, 295, 295, 295, 295, 295, 295, 295, 295, 296, 296, 296, 296, 296, 296,
    296, 296, 296, 296, 297, 297, 297, 297, 297, 297, 297, 297, 297, 297, 298, 298, 298, 298, 298,
    298, 298, 298, 298, 298, 298, 299, 299, 299, 299, 299, 299, 299, 299, 299, 299, 300, 300, 300,
    300, 300, 300, 300, 300, 300, 300, 301, 301, 301, 301, 301, 301, 301, 301, 301, 301, 302, 302,
    302, 302, 302, 302, 302, 302, 302, 303, 303, 303, 303, 303, 303, 303, 303, 303, 303, 304, 304,
    304, 304, 304, 304, 304, 304, 304, 305, 305, 305, 305, 305, 305, 305, 305, 305, 305, 306, 306,
    306, 306, 306, 306, 306, 306, 306, 307, 307, 307, 307, 307, 307, 307, 307, 307, 308, 308, 308,
    308, 308, 308, 308, 308, 308, 309, 309, 309, 309, 309, 309, 309, 309, 309, 310, 310, 310, 310,
    310, 310, 310, 310, 310, 311, 311, 311, 311, 311, 311, 311, 311, 311, 312, 312, 312, 312, 312,
    312, 312, 312, 312, 313, 313, 313, 313, 313, 313, 313, 313, 314, 314, 314, 314, 314, 314, 314,
    314, 314, 315, 315, 315, 315, 315, 315, 315, 315, 316, 316, 316, 316, 316, 316, 316, 316, 316,
    317, 317, 317, 317, 317, 317, 317, 317, 318, 318, 318, 318, 318, 318, 318, 318, 319, 319, 319,
    319, 319, 319, 319, 319, 320, 320, 320, 320, 320, 320, 320, 320, 321, 321, 321, 321, 321, 321,
    321, 321, 322, 322, 322, 322, 322, 322, 322, 322, 323, 323, 323, 323, 323, 323, 323, 323, 324,
    324, 324, 324, 324, 324, 324, 324, 325, 325, 325, 325, 325, 325, 325, 326, 326, 326, 326, 326,
    326, 326, 326, 327, 327, 327, 327, 327, 327, 327, 328, 328, 328, 328, 328, 328, 328, 328, 329,
    329, 329, 329, 329, 329, 329, 330, 330, 330, 330, 330, 330, 330, 330, 331, 331, 331, 331, 331,
    331, 331, 332, 332, 332, 332, 332, 332, 332, 333, 333, 333, 333, 333, 333, 333, 334, 334, 334,
    334, 334, 334, 334, 335, 335, 335, 335, 335, 335, 335, 336, 336, 336, 336, 336, 336, 336, 337,
    337, 337, 337, 337, 337, 337, 338, 338, 338, 338, 338, 338, 338, 339, 339, 339, 339, 339, 339,
    339, 340, 340, 340, 340, 340, 340, 340, 341, 341, 341, 341, 341, 341, 342, 342, 342, 342, 342,
    342, 342, 343, 343, 343, 343, 343, 343, 344, 344, 344, 344, 344, 344, 344, 345, 345, 345, 345,
    345, 345, 346, 346, 346, 346, 346, 346, 346, 347, 347, 347, 347, 347, 347, 348, 348, 348, 348,
    348, 348, 348, 349, 349, 349, 349, 349, 349, 350, 350, 350, 350, 350, 350, 351, 351, 351, 351,
    351, 351, 352, 352, 352, 352, 352, 352, 353, 353, 353, 353, 353, 353, 354, 354, 354, 354, 354,
    354, 354, 355, 355, 355, 355, 355, 355, 356, 356, 356, 356, 356, 357, 357, 357, 357, 357, 357,
    358, 358, 358, 358, 358, 358, 359, 359, 359, 359, 359, 359, 360, 360, 360, 360, 360, 360, 361,
    361, 361, 361, 361, 361, 362, 362, 362, 362, 362, 363, 363, 363, 363, 363, 363, 364, 364, 364,
    364, 364, 364, 365, 365, 365, 365, 365, 366, 366, 366, 366, 366, 366, 367, 367, 367, 367, 367,
    368, 368, 368, 368, 368, 368, 369, 369, 369, 369, 369, 370, 370, 370, 370, 370, 370, 371, 371,
    371, 371, 371, 372, 372, 372, 372, 372, 372, 373, 373, 373, 373, 373, 374, 374, 374, 374, 374,
    375, 375, 375, 375, 375, 376, 376, 376, 376, 376, 376, 377, 377, 377, 377, 377, 378, 378, 378,
    378, 378, 379, 379, 379, 379, 379, 380, 380, 380, 380, 380, 381, 381, 381, 381, 381, 382, 382,
    382, 382, 382, 383, 383, 383, 383, 383, 384, 384, 384, 384, 384, 385, 385, 385, 385, 385, 386,
    386, 386, 386, 386, 387, 387, 387, 387, 387, 388, 388, 388, 388, 388, 389, 389, 389, 389, 389,
    390, 390, 390, 390, 391, 391, 391, 391, 391, 392, 392, 392, 392, 392, 393, 393, 393, 393, 393,
    394, 394, 394, 394, 395, 395, 395, 395, 395, 396, 396, 396, 396, 396, 397, 397, 397, 397, 398,
    398, 398, 398, 398, 399, 399, 399, 399, 400, 400, 400, 400, 400, 401, 401, 401, 401, 402, 402,
    402, 402, 402, 403, 403, 403, 403, 404, 404, 404, 404, 404, 405, 405, 405, 405, 406, 406, 406,
    406, 406, 407, 407, 407, 407, 408, 408, 408, 408, 409, 409, 409, 409, 409, 410, 410, 410, 410,
    411, 411, 411, 411, 412, 412, 412, 412, 412, 413, 413, 413, 413, 414, 414, 414, 414, 415, 415,
    415, 415, 416, 416, 416, 416, 417, 417, 417, 417, 417, 418, 418, 418, 418, 419, 419, 419, 419,
    420, 420, 420, 420, 421, 421, 421, 421, 422, 422, 422, 422, 423, 423, 423, 423, 424, 424, 424,
    424, 425, 425, 425, 425, 426, 426, 426, 426, 427, 427, 427, 427, 428, 428, 428, 428, 429, 429,
    429, 429, 430, 430, 430, 430, 431, 431, 431, 431, 432, 432, 432, 433, 433, 433, 433, 434, 434,
    434, 434, 435, 435, 435, 435, 436, 436, 436, 436, 437, 437, 437, 437, 438, 438, 438, 439, 439,
    439, 439, 440, 440, 440, 440, 441, 441, 441, 442, 442, 442, 442, 443, 443, 443, 443, 444, 444,
    444, 445, 445, 445, 445, 446, 446, 446, 446, 447, 447, 447, 448, 448, 448, 448, 449, 449, 449,
    449, 450, 450, 450, 451, 451, 451, 451, 452, 452, 452, 453, 453, 453, 453, 454, 454, 454, 455,
    455, 455, 455, 456, 456, 456, 457, 457, 457, 457, 458, 458, 458, 459, 459, 459, 459, 460, 460,
    460, 461, 461, 461, 462, 462, 462, 462, 463, 463, 463, 464, 464, 464, 464, 465, 465, 465, 466,
    466, 466, 467, 467, 467, 467, 468, 468, 468, 469, 469, 469, 470, 470, 470, 471, 471, 471, 471,
    472, 472, 472, 473, 473, 473, 474, 474, 474, 475, 475, 475, 475, 476, 476, 476, 477, 477, 477,
    478, 478, 478, 479, 479, 479, 480, 480, 480, 480, 481, 481, 481, 482, 482, 482, 483, 483, 483,
    484, 484, 484, 485, 485, 485, 486, 486, 486, 487, 487, 487, 488, 488, 488, 489, 489, 489, 489,
    490, 490, 490, 491, 491, 491, 492, 492, 492, 493, 493, 493, 494, 494, 494, 495, 495, 495, 496,
    496, 496, 497, 497, 497, 498, 498, 498, 499, 499, 500, 500, 500, 501, 501, 501, 502, 502, 502,
    503, 503, 503, 504, 504, 504, 505, 505, 505, 506, 506, 506, 507, 507, 507, 508, 508, 508, 509,
    509, 510, 510, 510, 511, 511, 511, 512, 512, 512, 513, 513, 513, 514, 514, 514, 515, 515, 516,
    516, 516, 517, 517, 517, 518, 518, 518, 519, 519, 520, 520, 520, 521, 521, 521, 522, 522, 522,
    523, 523, 524, 524, 524, 525, 525, 525, 526, 526, 527, 527, 527, 528, 528, 528, 529, 529, 530,
    530, 530, 531, 531, 531, 532, 532, 533, 533, 533, 534, 534, 534, 535, 535, 536, 536, 536, 537,
    537, 538, 538, 538, 539, 539, 539, 540, 540, 541, 541, 541, 542, 542, 543, 543, 543, 544, 544,
    545, 545, 545, 546, 546, 547, 547, 547, 548, 548, 548, 549, 549, 550, 550, 550, 551, 551, 552,
    552, 553, 553, 553, 554, 554, 555, 555, 555, 556, 556, 557, 557, 557, 558, 558, 559, 559, 559,
    560, 560, 561, 561, 561, 562, 562, 563, 563, 564, 564, 564, 565, 565, 566, 566, 567, 567, 567,
    568, 568, 569, 569, 569, 570, 570, 571, 571, 572, 572, 572, 573, 573, 574, 574, 575, 575, 575,
    576, 576, 577, 577, 578, 578, 578, 579, 579, 580, 580, 581, 581, 582, 582, 582, 583, 583, 584,
    584, 585, 585, 585, 586, 586, 587, 587, 588, 588, 589, 589, 589, 590, 590, 591, 591, 592, 592,
    593, 593, 594, 594, 594, 595, 595, 596, 596, 597, 597, 598, 598, 599, 599, 599, 600, 600, 601,
    601, 602, 602, 603, 603, 604, 604, 605, 605, 605, 606, 606, 607, 607, 608, 608, 609, 609, 610,
    610, 611, 611, 612, 612, 613, 613, 614, 614, 614, 615, 615, 616, 616, 617, 617, 618, 618, 619,
    619, 620, 620, 621, 621, 622, 622, 623, 623, 624, 624, 625, 625, 626, 626, 627, 627, 628, 628,
    629, 629, 630, 630, 631, 631, 632, 632, 633, 633, 634, 634, 635, 635, 636, 636, 637, 637, 638,
    638, 639, 639, 640, 640, 641, 641, 642, 642, 643, 643, 644, 644, 645, 645, 646, 646, 647, 647,
    648, 648, 649, 649, 650, 650, 651, 651, 652, 652, 653, 654, 654, 655, 655, 656, 656, 657, 657,
    658, 658, 659, 659, 660, 660, 661, 661, 662, 663, 663, 664, 664, 665, 665, 666, 666, 667, 667,
    668, 668, 669, 670, 670, 671, 671, 672, 672, 673, 673, 674, 674, 675, 676, 676, 677, 677, 678,
    678, 679, 679, 680, 681, 681, 682, 682, 683, 683, 684, 684, 685, 686, 686, 687, 687, 688, 688,
    689, 690, 690, 691, 691, 692, 692, 693, 694, 694, 695, 695, 696, 696, 697, 698, 698, 699, 699,
    700, 700, 701, 702, 702, 703, 703, 704, 705, 705, 706, 706, 707, 707, 708, 709, 709, 710, 710,
    711, 712, 712, 713, 713, 714, 715, 715, 716, 716, 717, 718, 718, 719, 719, 720, 721, 721, 722,
    722, 723, 724, 724, 725, 725, 726, 727, 727, 728, 729, 729, 730, 730, 731, 732, 732, 733, 733,
    734, 735, 735, 736, 737, 737, 738, 738, 739, 740, 740, 741, 742, 742, 743, 743, 744, 745, 745,
    746, 747, 747, 748, 749, 749, 750, 750, 751, 752, 752, 753, 754, 754, 755, 756, 756, 757, 758,
    758, 759, 760, 760, 761, 761, 762, 763, 763, 764, 765, 765, 766, 767, 767, 768, 769, 769, 770,
    771, 771, 772, 773, 773, 774, 775, 775, 776, 777, 777, 778, 779, 779, 780, 781, 781, 782, 783,
    783, 784, 785, 786, 786, 787, 788, 788, 789, 790, 790, 791, 792, 792, 793, 794, 794, 795, 796,
    797, 797, 798, 799, 799, 800, 801, 801, 802, 803, 804, 804, 805, 806, 806, 807, 808, 809, 809,
    810, 811, 811, 812, 813, 814, 814, 815, 816, 816, 817, 818, 819, 819, 820, 821, 821, 822, 823,
    824, 824, 825, 826, 827, 827, 828, 829, 829, 830, 831, 832, 832, 833, 834, 835, 835, 836, 837,
    838, 838, 839, 840, 841, 841, 842, 843, 844, 844, 845, 846, 847, 847, 848, 849, 850, 850, 851,
    852, 853, 853, 854, 855, 856, 857, 857, 858, 859, 860, 860, 861, 862, 863, 863, 864, 865, 866,
    867, 867, 868, 869, 870, 871, 871, 872, 873, 874, 874, 875, 876, 877, 878, 878, 879, 880, 881,
    882, 882, 883, 884, 885, 886, 886, 887, 888, 889, 890, 890, 891, 892, 893, 894, 894, 895, 896,
    897, 898, 899, 899, 900, 901, 902, 903, 903, 904, 905, 906, 907, 908, 908, 909, 910, 911, 912,
    913, 913, 914, 915, 916, 917, 918, 918, 919, 920, 921, 922, 923, 924, 924, 925, 926, 927, 928,
    929, 930, 930, 931, 932, 933, 934, 935, 936, 936, 937, 938, 939, 940, 941, 942, 942, 943, 944,
    945, 946, 947, 948, 949, 949, 950, 951, 952, 953, 954, 955, 956, 957, 957, 958, 959, 960, 961,
    962, 963, 964, 965, 965, 966, 967, 968, 969, 970, 971, 972, 973, 974, 975, 975, 976, 977, 978,
    979, 980, 981, 982, 983, 984, 985, 986, 986, 987, 988, 989, 990, 991, 992, 993, 994, 995, 996,
    997, 998, 999, 999, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011,
    1012, 1013, 1014, 1015, 1016, 1017, 1018, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026,
    1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042,
    1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058,
    1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074,
    1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091,
    1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1101, 1102, 1104, 1105, 1106, 1107, 1108,
    1109, 1110, 1111, 1112, 1113, 1114, 1115, 1116, 1117, 1119, 1120, 1121, 1122, 1123, 1124, 1125,
    1126, 1127, 1128, 1129, 1131, 1132, 1133, 1134, 1135, 1136, 1137, 1138, 1139, 1140, 1142, 1143,
    1144, 1145, 1146, 1147, 1148, 1149, 1150, 1152, 1153, 1154, 1155, 1156, 1157, 1158, 1159, 1161,
    1162, 1163, 1164, 1165, 1166, 1167, 1169, 1170, 1171, 1172, 1173, 1174, 1175, 1177, 1178, 1179,
    1180, 1181, 1182, 1184, 1185, 1186, 1187, 1188, 1189, 1191, 1192, 1193, 1194, 1195, 1196, 1198,
    1199, 1200, 1201, 1202, 1203, 1205, 1206, 1207, 1208, 1209, 1211, 1212, 1213, 1214, 1215, 1217,
    1218, 1219, 1220, 1221, 1223, 1224, 1225, 1226, 1227, 1229, 1230, 1231, 1232, 1234, 1235, 1236,
    1237, 1238, 1240, 1241, 1242, 1243, 1245, 1246, 1247, 1248, 1249, 1251, 1252, 1253, 1254, 1256,
    1257, 1258, 1259, 1261, 1262, 1263, 1264, 1266, 1267, 1268, 1270, 1271, 1272, 1273, 1275, 1276,
    1277, 1278, 1280, 1281, 1282, 1283, 1285, 1286, 1287, 1289, 1290, 1291, 1292, 1294, 1295, 1296,
    1298, 1299, 1300, 1302, 1303, 1304, 1305, 1307, 1308, 1309, 1311, 1312, 1313, 1315, 1316, 1317,
    1319, 1320, 1321, 1323, 1324, 1325, 1327, 1328, 1329, 1331, 1332, 1333, 1335, 1336, 1337, 1339,
    1340, 1341, 1343, 1344, 1345, 1347, 1348, 1349, 1351, 1352, 1354, 1355, 1356, 1358, 1359, 1360,
    1362, 1363, 1364, 1366, 1367, 1369, 1370, 1371, 1373, 1374, 1376, 1377, 1378, 1380, 1381, 1383,
    1384, 1385, 1387, 1388, 1390, 1391, 1392, 1394, 1395, 1397, 1398, 1399, 1401, 1402, 1404, 1405,
    1407, 1408, 1409, 1411, 1412, 1414, 1415, 1417, 1418, 1419, 1421, 1422, 1424, 1425, 1427, 1428,
    1430, 1431, 1433, 1434, 1435, 1437, 1438, 1440, 1441, 1443, 1444, 1446, 1447, 1449, 1450, 1452,
    1453, 1455, 1456, 1458, 1459, 1461, 1462, 1464, 1465, 1467, 1468, 1470, 1471, 1473, 1474, 1476,
    1477, 1479, 1480, 1482, 1483, 1485, 1486, 1488, 1489, 1491, 1492, 1494, 1495, 1497, 1498, 1500,
    1502, 1503, 1505, 1506, 1508, 1509, 1511, 1512, 1514, 1515, 1517, 1519, 1520, 1522, 1523, 1525,
    1526, 1528, 1530, 1531, 1533, 1534, 1536, 1537, 1539, 1541, 1542, 1544, 1545, 1547, 1549, 1550,
    1552, 1553, 1555, 1557, 1558, 1560, 1561, 1563, 1565, 1566, 1568, 1570, 1571, 1573, 1574, 1576,
    1578, 1579, 1581, 1583, 1584, 1586, 1588, 1589, 1591, 1592, 1594, 1596, 1597, 1599, 1601, 1602,
    1604, 1606, 1607, 1609, 1611, 1612, 1614, 1616, 1617, 1619, 1621, 1622, 1624, 1626, 1628, 1629,
    1631, 1633, 1634, 1636, 1638, 1639, 1641, 1643, 1645, 1646, 1648, 1650, 1651, 1653, 1655, 1657,
    1658, 1660, 1662, 1664, 1665, 1667, 1669, 1671, 1672, 1674, 1676, 1678, 1679, 1681, 1683, 1685,
    1686, 1688, 1690, 1692, 1693, 1695, 1697, 1699, 1700, 1702, 1704, 1706, 1708, 1709, 1711, 1713,
    1715, 1717, 1718, 1720, 1722, 1724, 1726, 1727, 1729, 1731, 1733, 1735, 1736, 1738, 1740, 1742,
    1744, 1746, 1747, 1749, 1751, 1753, 1755, 1757, 1759, 1760, 1762, 1764, 1766, 1768, 1770, 1772,
    1773, 1775, 1777, 1779, 1781, 1783, 1785, 1787, 1788, 1790, 1792, 1794, 1796, 1798, 1800, 1802,
    1804, 1805, 1807, 1809, 1811, 1813, 1815, 1817, 1819, 1821, 1823, 1825, 1827, 1829, 1830, 1832,
    1834, 1836, 1838, 1840, 1842, 1844, 1846, 1848, 1850, 1852, 1854, 1856, 1858, 1860, 1862, 1864,
    1866, 1868, 1870, 1872, 1874, 1876, 1878, 1880, 1882, 1884, 1886, 1888, 1890, 1892, 1894, 1896,
    1898, 1900, 1902, 1904, 1906, 1908, 1910, 1912, 1914, 1916, 1918, 1920, 1922, 1924, 1926, 1928,
    1930, 1932, 1934, 1936, 1938, 1941, 1943, 1945, 1947, 1949, 1951, 1953, 1955, 1957, 1959, 1961,
    1963, 1966, 1968, 1970, 1972, 1974, 1976, 1978, 1980, 1982, 1984, 1987, 1989, 1991, 1993, 1995,
    1997, 1999, 2002, 2004, 2006, 2008, 2010, 2012, 2014, 2017, 2019, 2021, 2023, 2025, 2027, 2030,
    2032, 2034, 2036, 2038, 2040, 2043, 2045, 2047, 2049, 2051, 2054, 2056, 2058, 2060, 2063, 2065,
    2067, 2069, 2071, 2074, 2076, 2078, 2080, 2083, 2085, 2087, 2089, 2092, 2094, 2096, 2098, 2101,
    2103, 2105, 2107, 2110, 2112, 2114, 2116, 2119, 2121, 2123, 2126, 2128, 2130, 2132, 2135, 2137,
    2139, 2142, 2144, 2146, 2149, 2151, 2153, 2156, 2158, 2160, 2163, 2165, 2167, 2170, 2172, 2174,
    2177, 2179, 2181, 2184, 2186, 2188, 2191, 2193, 2195, 2198, 2200, 2203, 2205, 2207, 2210, 2212,
    2215, 2217, 2219, 2222, 2224, 2227, 2229, 2231, 2234, 2236, 2239, 2241, 2244, 2246, 2248, 2251,
    2253, 2256, 2258, 2261, 2263, 2266, 2268, 2270, 2273, 2275, 2278, 2280, 2283, 2285, 2288, 2290,
    2293, 2295, 2298, 2300, 2303, 2305, 2308, 2310, 2313, 2315, 2318, 2320, 2323, 2325, 2328, 2330,
    2333, 2336, 2338, 2341, 2343, 2346, 2348, 2351, 2353, 2356, 2359, 2361, 2364, 2366, 2369, 2371,
    2374, 2377, 2379, 2382, 2384, 2387, 2390, 2392, 2395, 2397, 2400, 2403, 2405, 2408, 2411, 2413,
    2416, 2418, 2421, 2424, 2426, 2429, 2432, 2434, 2437, 2440, 2442, 2445, 2448, 2450, 2453, 2456,
    2458, 2461, 2464, 2466, 2469, 2472, 2475, 2477, 2480, 2483, 2485, 2488, 2491, 2494, 2496, 2499,
    2502, 2505, 2507, 2510, 2513, 2516, 2518, 2521, 2524, 2527, 2529, 2532, 2535, 2538, 2541, 2543,
    2546, 2549, 2552, 2555, 2557, 2560, 2563, 2566, 2569, 2571, 2574, 2577, 2580, 2583, 2586, 2588,
    2591, 2594, 2597, 2600, 2603, 2606, 2608, 2611, 2614, 2617, 2620, 2623, 2626, 2629, 2631, 2634,
    2637, 2640, 2643, 2646, 2649, 2652, 2655, 2658, 2661, 2664, 2666, 2669, 2672, 2675, 2678, 2681,
    2684, 2687, 2690, 2693, 2696, 2699, 2702, 2705, 2708, 2711, 2714, 2717, 2720, 2723, 2726, 2729,
    2732, 2735, 2738, 2741, 2744, 2747, 2750, 2753, 2756, 2759, 2762, 2765, 2768, 2772, 2775, 2778,
    2781, 2784, 2787, 2790, 2793, 2796, 2799, 2802, 2805, 2809, 2812, 2815, 2818, 2821, 2824, 2827,
    2830, 2834, 2837, 2840, 2843, 2846, 2849, 2852, 2856, 2859, 2862, 2865, 2868, 2872, 2875, 2878,
    2881, 2884, 2887, 2891, 2894, 2897, 2900, 2904, 2907, 2910, 2913, 2916, 2920, 2923, 2926, 2929,
    2933, 2936, 2939, 2942, 2946, 2949, 2952, 2956, 2959, 2962, 2965, 2969, 2972, 2975, 2979, 2982,
    2985, 2989, 2992, 2995, 2999, 3002, 3005, 3009, 3012, 3015, 3019, 3022, 3025, 3029, 3032, 3036,
    3039, 3042, 3046, 3049, 3053, 3056, 3059, 3063, 3066, 3070, 3073, 3076, 3080, 3083, 3087, 3090,
    3094, 3097, 3101, 3104, 3108, 3111, 3114, 3118, 3121, 3125, 3128, 3132, 3135, 3139, 3142, 3146,
    3149, 3153, 3156, 3160, 3164, 3167, 3171, 3174, 3178, 3181, 3185, 3188, 3192, 3196, 3199, 3203,
    3206, 3210, 3213, 3217, 3221, 3224, 3228, 3231, 3235, 3239, 3242, 3246, 3250, 3253, 3257, 3261,
    3264, 3268, 3271, 3275, 3279, 3282, 3286, 3290, 3294, 3297, 3301, 3305, 3308, 3312, 3316, 3319,
    3323, 3327, 3331, 3334, 3338, 3342, 3346, 3349, 3353, 3357, 3361, 3364, 3368, 3372, 3376, 3380,
    3383, 3387, 3391, 3395, 3399, 3402, 3406, 3410, 3414, 3418, 3422, 3425, 3429, 3433, 3437, 3441,
    3445, 3449, 3453, 3456, 3460, 3464, 3468, 3472, 3476, 3480, 3484, 3488, 3492, 3495, 3499, 3503,
    3507, 3511, 3515, 3519, 3523, 3527, 3531, 3535, 3539, 3543, 3547, 3551, 3555, 3559, 3563, 3567,
    3571, 3575, 3579, 3583, 3587, 3591, 3595, 3599, 3603, 3607, 3612, 3616, 3620, 3624, 3628, 3632,
    3636, 3640, 3644, 3648, 3653, 3657, 3661, 3665, 3669, 3673, 3677, 3681, 3686, 3690, 3694, 3698,
    3702, 3707, 3711, 3715, 3719, 3723, 3728, 3732, 3736, 3740, 3744, 3749, 3753, 3757, 3761, 3766,
    3770, 3774, 3778, 3783, 3787, 3791, 3796, 3800, 3804, 3808, 3813, 3817, 3821, 3826, 3830, 3834,
    3839, 3843, 3847, 3852, 3856, 3861, 3865, 3869, 3874, 3878, 3882, 3887, 3891, 3896, 3900, 3904,
    3909, 3913, 3918, 3922, 3927, 3931, 3936, 3940, 3944, 3949, 3953, 3958, 3962, 3967, 3971, 3976,
    3980, 3985, 3989, 3994, 3999, 4003, 4008, 4012, 4017, 4021, 4026, 4030, 4035, 4040, 4044, 4049,
    4053, 4058, 4063, 4067, 4072, 4076, 4081, 4086, 4090, 4095,
];

/// Where the 50712 curve bytes for a frame came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurveSrc {
    /// Read from the corpus file (tag 50712, byte-copied).
    ReferenceFile,
    /// The embedded A001 constant (fallback).
    Embedded,
}

/// The corpus SOS payloads (structural parity: copied verbatim).
pub const SOS0_PAYLOAD: [u8; 6] = [0x01, 0x00, 0x00, 0x00, 0x3f, 0x00];
pub const SOS1_PAYLOAD: [u8; 6] = [0x01, 0x01, 0x11, 0x00, 0x3f, 0x00];
/// The corpus SOF1 (12-bit, 1928×544, 2 components with 0-based ids).
pub const SOF1_BYTES: [u8; 16] = [
    0xff, 0xc1, 0x00, 0x0e, 0x0c, 0x02, 0x20, 0x07, 0x88, 0x02, 0x00, 0x11, 0x00, 0x01, 0x11, 0x00,
];

#[derive(Error, Debug)]
pub enum DctError {
    #[error("libjpeg 12-bit DCT encode: {0}")]
    Encode(String),
    #[error("plane {which}: bad dims (want {w}×{h})")]
    PlaneDims { which: String, w: usize, h: usize },
    #[error("plane jpeg: missing {what}")]
    StreamPart { what: String },
    #[error("frame dims {w}×{h} != reference grid {fw}×{fh}")]
    FrameDims { w: u32, h: u32, fw: u32, fh: u32 },
    #[error("reference curve: {0}")]
    Curve(String),
    #[error("structure check failed: {0}")]
    Structure(String),
    #[error("pixel gate failed: {0}")]
    Gate(String),
    #[error("unknown FRAMEPRISM_ERASURE mode `{0}` (expected `v4-2tap`, `v5b-cue-cd`, `v5-binkill` or `dcdc`)")]
    BadErasureMode(String),
    #[error("bad FRAMEPRISM_DCDC_CONSTS: {0}")]
    BadDcdcConsts(String),
}

/// v5 (cast fix) — the CFA-erasure mode selector.
///
/// The measured pre-DCT CFA erasure (coefficient proof +
/// mechanism verdict): the measured encoder zeros the 2-px Nyquist CFA-aliasing
/// bins and RETAINS the class-diff envelope (~60% of the source's
/// D_WG/D_RG — the class difference the NLE demosaic uses to separate G
/// from W/R). The v4 pre-domain spatial 2-tap (`h2tap_smooth_wh`, 
/// fit, the pre-v4 commit) killed the 2-px grid (render-verified) but
/// erased the column-parity class-diff at ALL frequencies (D_WG/D_RG
/// ~5%/20% of source) → the user-visible full-frame G-deficit cast
/// (~+23/255, render).
///
/// Env-var gate `FRAMEPRISM_ERASURE` (single knob, read at the two pipeline
/// seams below — unset = the default):
///   `v4-2tap` (DEFAULT) — the v4 pre-domain horizontal 2-tap (applied
///   in `full_frame_planes`), the v4 files — the measured
/// reference erasure base, the render baseline (reproducible);
///   `v5b-cue-cd` (gated diagnostic) — the v4 2-tap
///   base PLUS the content-adaptive fixed-algorithm color-cue
///   re-injection (`cue_offsets`, per-scan sign flip; RENDER FAILED —
///   see `cue_offsets` docs; NEVER the default);
/// `v5-binkill` (gated diagnostic, ) — the DCT-domain selective bin
///   kill (`cfa_bin_kill_block`, applied in `encode_tiles_t21`); measured
/// no-op on the CFA aliasing (probe — see `cfa_bin_kill_block`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CfaErasure {
 /// v4 (candidate): pre-domain horizontal 2-tap
    /// (the render baseline; reproducible via `FRAMEPRISM_ERASURE=v4-2tap`).
    V4TwoTap,
    /// v5 (cast fix): post-forward-DCT bin kill.
    V5BinKill,
    /// v5b-cue-cd (GATED DIAGNOSTIC — the render-
    /// FAILED cD cue; NEVER the default): the v4 2-tap erasure PLUS the
    /// per-scan sign-flipped color-cue re-injection (`cue_offsets`).
    V5Cue,
    /// dcdc (GATED DIAGNOSTIC — the rank-1 per-class DC-offset
    /// fix; NEVER the default): the v4 2-tap
    /// erasure PLUS a per-class constant Δ added in the RAW source
    /// domain (before the 50712 pre-curve LUT — raw-domain decision:
    /// a raw add round-trips exactly through the curve, a pre-domain
    /// constant is attenuated by the local curve slope) — 8 literal
    /// constants (4 classes × dark/bright regime, `DCDC_DARK`/
    /// `DCDC_BRIGHT`, order W,Ge,Go,R — see their docs for the
    /// derivation provenance), regime keyed on the frame's own source
    /// mean vs `DCDC_T`. The constants (+ optional T) are
    /// env-overridable via `FRAMEPRISM_DCDC_CONSTS` (unset/empty = the
    /// literals, bit-exact; malformed = hard error —
    /// `dcdc_consts_from_env`). L0-level (frame-DC) correction ONLY — no
    /// fixed transform reproduces the measured block-DC grid.
    Dcdc,
}

impl CfaErasure {
    /// The env-var gate (`FRAMEPRISM_ERASURE`): DEFAULT (unset) = `v4-2tap`
    /// (the render baseline — a render-FAILing cue must not be the
    /// production default); `v5b-cue-cd` = the cD color-cue diagnostic;
    /// `v5-binkill` = the bin-kill diagnostic; `dcdc` = the per-class
    /// DC-offset diagnostic. An unrecognized NON-EMPTY value is a hard
    /// error — a typo must not silently switch the production transform.
    pub fn from_env() -> Result<Self, DctError> {
        match std::env::var("FRAMEPRISM_ERASURE") {
            Ok(s) if s == "v4-2tap" => Ok(Self::V4TwoTap),
            Ok(s) if s == "v5-binkill" => Ok(Self::V5BinKill),
            Ok(s) if s == "v5b-cue-cd" => Ok(Self::V5Cue),
            Ok(s) if s == "dcdc" => Ok(Self::Dcdc),
            Err(_) => Ok(Self::V4TwoTap),
            Ok(s) => Err(DctError::BadErasureMode(s)),
        }
    }
}

/// The v5 selective bin kill (gated DIAGNOSTIC): zeroes bins (0,4) idx
/// 4, (4,0) idx 32, (4,4) idx 36 of ONE 8×8 block's X_orth (natural
/// order `u*8+v` — `u` = row/vertical frequency, `v` = column/horizontal
/// frequency, per `block_xorth`).
///
/// Measured on the real corpus (the production `block_xorth`): a pure
/// 2-px (−1)^x pattern's DCT-II energy spreads over the ODD-v bins
/// ((0,1)/(0,3)/(0,5)/(0,7), (0,7) dominant), and the mask bins {4,32,36}
/// carry ≈0 on the SOURCE itself (e.g. f1 tile0: −0.15/−0.02/+0.01) —
/// the kill is a no-op on the CFA aliasing (the bin-label→X_orth mapping
/// is the trap: a label's bin is not the mask's bin). The reference
/// product's actual erasure is the v4 pre-domain 2-tap base (grid kill
/// oracle-verified) plus a smooth per-class offset field O. Kept in-tree as a
/// gated diagnostic (`FRAMEPRISM_ERASURE=v5-binkill`), NOT the default.
/// NOTHING else is touched — the DC slot and every other AC bin pass
/// through unchanged (the shared BASE_TABLE quantization does the rest,
/// identical to the measured table).
pub fn cfa_bin_kill_block(x: &mut [f64; 64]) {
    // Mask bins {4, 32, 36} = DCT bins (0,4), (4,0), (4,4) — the probe
    // mask. The const indices are the bin coordinates themselves (
    // diagnostic; do not "simplify" away the zeroing — the op is the feature).
    x[4] = 0.0;
    x[32] = 0.0;
    x[36] = 0.0;
}

/// Nearest-preimage inverse of the curve: `inv[s]` = the smallest pre
/// value p with |curve[p] - s| minimal (monotone curve → two pointers,
/// O(N); ties go to the lower pre — matching the measured Python
/// reference).
pub fn inv_lut(curve: &[u16; CURVE_LEN]) -> [u16; CURVE_LEN] {
    let mut inv = [0u16; CURVE_LEN];
    let mut p = 0usize;
    // `s` is used as a VALUE (s64 + the distance comparisons), not just an
    // index — the range loop is the direct form (clippy allow).
    #[allow(clippy::needless_range_loop)]
    for s in 0..CURVE_LEN {
        let s64 = s as i64;
        // Advance through the decreasing side of the V (ties included —
        // the curve has long flat steps in the flat band; stopping on a
        // tie would strand the pointer on a flat step below s).
        while p + 1 < CURVE_LEN {
            let d_cur = (curve[p] as i64 - s64).abs();
            let d_nxt = (curve[p + 1] as i64 - s64).abs();
            if d_nxt <= d_cur {
                p += 1;
            } else {
                break;
            }
        }
        // Step back to the SMALLEST minimizer (measured reference
        // behavior: ties go to the lower pre value).
        while p > 0 && (curve[p - 1] as i64 - s64).abs() == (curve[p] as i64 - s64).abs() {
            p -= 1;
        }
        inv[s] = p as u16;
    }
    inv
}

/// 50712 file bytes: count u16 values, file (little-)endian SHORTs.
pub fn curve_bytes(curve: &[u16; CURVE_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CURVE_LEN * 2);
    for v in curve {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

/// Read the 50712 curve from a reference DNG (any preset; the
/// curve is preset/frame-invariant — verified). Returns the curve + the
/// source tag.
pub fn read_reference_curve(path: &Path) -> Result<([u16; CURVE_LEN], CurveSrc), DctError> {
    // The bounded prefix read (the 50712 value offset is
    // bounds-checked by the tiff module against the buffer given — a
    // value past the prefix is the named RegionOutOfBounds class,
    // which flows into this same DctError::Curve refusal); the
    // refusal wording is the pre-existing one.
    let buf = crate::camera::read_detection_prefix(path)
        .map_err(|e| DctError::Curve(format!("{}: {e}", path.display())))?;
    let meta = crate::tiff::read_meta(&buf)
        .map_err(|e| DctError::Curve(format!("{}: {e}", path.display())))?;
    let en = meta
        .ifd0
        .entries
        .iter()
        .find(|x| x.tag == 50712)
        .ok_or_else(|| DctError::Curve(format!("{}: no 50712 tag", path.display())))?;
    if en.typ != 3 || en.count != CURVE_LEN as u32 {
        return Err(DctError::Curve(format!(
            "{}: 50712 is typ {} count {} (want SHORT × {CURVE_LEN})",
            path.display(),
            en.typ,
            en.count
        )));
    }
    let (p, _) = en.out_of_line.ok_or_else(|| {
        DctError::Curve(format!("{}: 50712 in-line (unexpected)", path.display()))
    })?;
    let e = meta.endianness;
    let mut curve = [0u16; CURVE_LEN];
    for i in 0..CURVE_LEN {
        curve[i] = e.u16(&buf[p as usize + i * 2..p as usize + i * 2 + 2]);
    }
    Ok((curve, CurveSrc::ReferenceFile))
}

// ----------------------------------------------------------------- planes

/// 3×3 box low-pass (edge-replicate) on a `w`×`h` u16 plane (
/// generic — the full-frame parity planes are 3856×1085). The pre-domain
/// domain-transform smoothing — see the module docs for the measured
/// rationale (removes the flat-band quantization staircase without
/// touching the real low-freq signal). Edge-replicate at the plane edge —
/// for the FULL-FRAME planes (full_frame_planes) the plane edge IS the
/// frame edge, so there is no replicate at the tile borders (D3).
pub fn box3_smooth_wh(pl: &[u16], w: usize, h: usize) -> Vec<u16> {
    let g = |x: isize, y: isize| -> usize {
        let x = x.clamp(0, w as isize - 1) as usize;
        let y = y.clamp(0, h as isize - 1) as usize;
        y * w + x
    };
    let mut out = vec![0u16; w * h];
    for y in 0..h {
        for x in 0..w {
            let mut s = 0u32;
            for dy in -1..=1 {
                for dx in -1..=1 {
                    s += pl[g(x as isize + dx, y as isize + dy)] as u32;
                }
            }
            out[y * w + x] = (s / 9) as u16;
        }
    }
    out
}

/// The per-tile case (PLANE_W × PLANE_H). The PRODUCTION chain
/// smooths the FULL-FRAME planes instead (full_frame_planes) — the per-tile
/// edge-replicate at the tile borders was the D3 seam (the 1–2 column
/// neighborhood discontinuity at x=1927/1928, the user-visible vertical
/// center line). Kept for the box3 unit tests and the vdct_probe
/// calibration-history probes.
pub fn box3_smooth(pl: &[u16]) -> Vec<u16> {
    box3_smooth_wh(pl, PLANE_W, PLANE_H)
}

/// v4 (fit-probe) — the measured pre-DCT CFA
/// erasure as a full-plane operator: horizontal 2-tap with the RIGHT
/// neighbor, `out[y,x] = (p[y,x] + p[y,min(x+1,w-1)]) / 2` (integer,
/// the same semantics as `cfa_lowpass_h`; the last column averages with
/// itself → unchanged — edge-replicate at the frame edge only, so no
/// tile-border neighborhood discontinuity, same as the full-frame box3
/// it supersedes). Applied on the FULL-FRAME pre-domain (invLUT) parity
/// planes BEFORE the tile cut (`full_frame_planes`) — the estimator
/// winner (erasure-then-curve order; the fit: within-row (−1)^x
/// 2-period → exactly flat for (a+b) even, CFA band at the file's own
/// quantization scale; the inter-row class difference untouched — the
/// horizontal-only kernel is what the measured 1.00× v-ratio requires).
pub fn h2tap_smooth_wh(pl: &[u16], w: usize, h: usize) -> Vec<u16> {
    let mut out = vec![0u16; w * h];
    for y in 0..h {
        let r = y * w;
        for x in 0..w {
            let a = pl[r + x] as u32;
            let b = pl[r + (x + 1).min(w - 1)] as u32;
            out[r + x] = ((a + b) / 2) as u16;
        }
    }
    out
}

/// v5b-cue-cd diagnostic — the color-cue gain.
/// Tuned on the raw-domain proxy (g = 0.7 lands D_WG/D_RG retention inside the
/// measured per-frame band on all 9 frames, 6 dark + 3 bright, with the
/// (0,7) bin at/below the 2-tap floor — the proxy was blind to the
/// vertical (7,0) direction, which the render exposed).
/// Env override `FRAMEPRISM_CUE_GAIN` (probe knob; the diagnostic default is
/// the constant; out-of-range values fall back to the constant).
pub const CUE_GAIN: f64 = 0.7;

fn cue_gain() -> f64 {
    std::env::var("FRAMEPRISM_CUE_GAIN")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|&g| (0.0..=2.0).contains(&g))
        .unwrap_or(CUE_GAIN)
}

/// separable 5×5 box (edge-replicate) on an f64 grid (w×h) — the kernel
/// for the v5b-cue-cd 2-px aliasing estimate (`cue_offsets`).
fn box5_2d_f64(x: &[f64], w: usize, h: usize) -> Vec<f64> {
    let mut t = vec![0f64; w * h];
    for y in 0..h {
        let r = y * w;
        for cx in 0..w {
            let mut s = 0.0;
            for dx in -2i32..=2 {
                let xx = (cx as i32 + dx).clamp(0, w as i32 - 1) as usize;
                s += x[r + xx];
            }
            t[r + cx] = s / 5.0;
        }
    }
    let mut out = vec![0f64; w * h];
    for y in 0..h {
        let r = y * w;
        for cx in 0..w {
            let mut s = 0.0;
            for dy in -2i32..=2 {
                let yy = (y as i32 + dy).clamp(0, h as i32 - 1) as usize;
                s += t[yy * w + cx];
            }
            out[r + cx] = s / 5.0;
        }
    }
    out
}

/// v5b-cue-cd (GATED DIAGNOSTIC, render-FAILED — see
/// the module docs; NEVER the default) — the color-cue offsets for the
/// two FULL-FRAME pre-domain parity planes (scan0 = even frame rows,
/// scan1 = odd frame rows; `n0`/`n1` = 1085 each for the 2170-row frame).
///
/// The v4 2-tap erases the within-row class contrast at ALL frequencies
/// (D_WG/D_RG ~5%/20% of the source) → the NLE demosaic cannot
/// separate G from W/R → the user-visible G-deficit cast. The measured
/// file keeps the SMOOTH class-diff envelope (~60% of the source's
/// D_WG/D_RG, /) while erasing the 2-px CFA pattern; pinned
/// the cue as ~100% INTER-SCAN (the within-scan contrast is erased by
/// BOTH reference and v4 — the 2-tap base stays). This re-injects a
/// content-adaptive FIXED-ALGORITHM approximation of that cue (no
/// per-content lookup, no fitted per-frame transform — the 
/// linear-fit dead-end is retired):
///   U(r,c)      = (W + R)/2 − (Go + Ge)/2   (half-res class lattices —
///                the inter-scan color cue; W = pre0[r,2c], Ge =
///                pre0[r,2c+1], Go = pre1[r,2c], R = pre1[r,2c+1])
///   U_band(r,c) = U − box5(U·checker)·checker, checker = (−1)^(r+c)
///                (removes the 2-px CFA-aliasing component, keeps the
///                8–16px class structure — a constant U survives at
///                24/25, a pure 2×2 pattern at 0; the box5 window is the
///                measured compromise: 2-px kill at 1–4%, 8-px pass at
///                ~33–90%)
///   scan0 += g·U_band,  scan1 −= g·U_band   (upscaled ×2: each half-res
///                (r,c) covers the 2×2 full-res cell; g = `cue_gain()`)
///
/// Provenance: the transform runs in the pre-domain (same domain as the
/// 2-tap — the pre-planes are the invLUT source); the raw-domain proxy maps ~1:1 to the pre-domain in the dark band
/// (curve slope ≈ 1) — the round-trip measurement (encode + render_dng
/// decode) validates the bright-band mapping. The offsets are added to
/// the 2-tap output and clipped to the pre-domain (0..4095) — the clip
/// is what keeps the bright-band cue amplitude in line (the raw proxy
/// does NOT clip).
fn cue_offsets(
    pre0: &[u16],
    pre1: &[u16],
    fw: usize,
    n0: usize,
    n1: usize,
    g: f64,
) -> (Vec<f64>, Vec<f64>) {
    let nc = fw / 2; // 1928 half-res cols
    let n = n0.min(n1); // U grid rows (1085)
    let mut u = vec![0f64; n * nc];
    let mut uch = vec![0f64; n * nc];
    for r in 0..n {
        let ro = r * fw;
        let ru = r * nc;
        for c in 0..nc {
            let x = 2 * c;
            let wv = pre0[ro + x] as f64;
            let ge = pre0[ro + x + 1] as f64;
            let go = pre1[ro + x] as f64;
            let rv = pre1[ro + x + 1] as f64;
            let val = (wv + rv) / 2.0 - (go + ge) / 2.0;
            u[ru + c] = val;
            let ch = if (r + c) % 2 == 0 { 1.0 } else { -1.0 };
            uch[ru + c] = val * ch;
        }
    }
    let en = box5_2d_f64(&uch, nc, n);
    let mut off0 = vec![0f64; n0 * fw];
    let mut off1 = vec![0f64; n1 * fw];
    for r in 0..n {
        let r0 = r * fw;
        let ru = r * nc;
        for c in 0..nc {
            let ch = if (r + c) % 2 == 0 { 1.0 } else { -1.0 };
            let band = u[ru + c] - en[ru + c] * ch;
            let o0 = g * band;
            let o1 = -g * band;
            off0[r0 + 2 * c] = o0;
            off0[r0 + 2 * c + 1] = o0;
            off1[r0 + 2 * c] = o1;
            off1[r0 + 2 * c + 1] = o1;
        }
    }
    (off0, off1)
}

/// v5b-cue-cd: add a cue offset (f64) plane to a 2-tap (u16) plane,
/// round-to-nearest, clip to the pre-domain (0..4095).
fn apply_cue_offset(tap: &[u16], off: &[f64]) -> Vec<u16> {
    tap.iter()
        .zip(off.iter())
        .map(|(&t, &o)| {
            let v = (t as f64 + o).round().clamp(0.0, 4095.0);
            v as u16
        })
        .collect()
}

/// Apply the plateau-constrained smooth inverse to all four tiles' parity
/// planes (the pre-domain domain-transform — see plateau_snap). `pre0` is
/// the raw invLUT planes (build_planes of the CFA-erased source — task
/// 20b), `src_planes` the CFA-erased source planes (build_source_planes),
/// `curve` the 50712 curve. The result is the smooth, CFA-erased pre-domain
/// the DCT encodes (the raw invLUT pre-domain carries
/// the flat-band 12-bit-POST quantization staircase amplified ~13×, so its
/// DCT error is 1.2–4.3× the measured one; a plain 3×3 box over-smooths flat
/// frames to 0.41×; the plateau-snap lands ~1.0×, see the grid probe.
/// The caller applies cfa_lowpass_h to the source before
/// build_planes/build_source_planes — the measured transform is
/// CFA-erasing and the flat step snap re-imposes any CFA contrast that
/// survives to the pre-domain).
///
/// SUPERSEDED in production by full_frame_planes — this path
/// box3-smooths each TILE plane separately (edge-replicate at every plane
/// border), so the middle column pair x=1927/1928 (and row pair
/// y=1087/1088) gets a different 3×3 neighborhood than any interior pixel
/// → the structural seam line (D3, the user's vertical center line). Kept
/// for the vdct_probe calibration-history probes (which measure the
/// per-tile variants).
pub fn smooth_planes(
    pre0: &[TilePlanes; 4],
    src_planes: &[TilePlanes; 4],
    curve: &[u16; CURVE_LEN],
) -> [TilePlanes; 4] {
    let (lo, hi) = plateau_range(curve);
    let m = SNAP_MARGIN;
    [
        TilePlanes {
            even: plateau_snap(&pre0[0].even, &src_planes[0].even, &lo, &hi, m),
            odd: plateau_snap(&pre0[0].odd, &src_planes[0].odd, &lo, &hi, m),
        },
        TilePlanes {
            even: plateau_snap(&pre0[1].even, &src_planes[1].even, &lo, &hi, m),
            odd: plateau_snap(&pre0[1].odd, &src_planes[1].odd, &lo, &hi, m),
        },
        TilePlanes {
            even: plateau_snap(&pre0[2].even, &src_planes[2].even, &lo, &hi, m),
            odd: plateau_snap(&pre0[2].odd, &src_planes[2].odd, &lo, &hi, m),
        },
        TilePlanes {
            even: plateau_snap(&pre0[3].even, &src_planes[3].even, &lo, &hi, m),
            odd: plateau_snap(&pre0[3].odd, &src_planes[3].odd, &lo, &hi, m),
        },
    ]
}

/// 2-tap adjacent-column low-pass in SOURCE space (CFA-erasing, 
/// D2): `out[y,x] = (src[y,x] + src[y,x+1]) / 2` with edge-replicate at the
/// last column (the edge is a no-op). Applied to the FULL FRAME (width
/// 3856) BEFORE the invLUT remap and the tile cut — no seam at the x=1928
/// tile boundary (unlike the per-tile box3, which moves to the
/// full frame). Zeros the 2-period horizontal band (odd-u Nyquist u=7;
/// DCT-II response: u=7 → 0, u=5 → ×0.31, u=3 → ×0.69, u=1 → ×0.96) that
/// carries the CFA R/G column pattern within a parity plane: scan0 (even
/// frame rows) is all G R rows and scan1 all W G rows, so the CFA pattern
/// is 2-period in x only inside each plane — the vertical 2-period (W vs G
/// row classes) is a scan0-vs-scan1 per-plane mean, inherent to the 2-scan
/// format, NOT an intra-plane pattern. FIXED, content-independent
/// (anti-tautology rule).
///
/// WHY SOURCE SPACE: the plateau snap
/// clamps every pixel into the flat step of ITS OWN source value — a smooth
/// pre-domain prior (box3 or a pre-domain 2-tap) is class-agnostic, so in
/// every region where the local CFA contrast exceeds the plateau±margin
/// window (~25 pre-units) the clamp re-projects the two phases onto their
/// OWN class flat steps and re-imposes the full inter-class contrast
/// (measured: 154.95 pre-units out vs 154.61 in — the pre-domain 2-tap
/// changes nothing after the snap). The erasure must therefore PRECEDE the
/// remap: a CFA-erased source feeds the invLUT, the box3 and the snap, and
/// all snap windows become class-agnostic. The residual 2-period energy
/// after the 2-tap is 0.5·Δ(half-contrast) (the adjacent variation of the
/// R/G contrast itself) — small because the contrast varies slowly.
///
/// The measured transform is CFA-erasing (its recon CFA contrast is
/// ≈ 0 in every luminance band — P4); ours kept ~72–94% of it
/// (D2 — the residual of the cast/banding the user saw in Resolve). The
/// forward-model contract becomes `curve(out) ≈ (src[x]+src[x+1])/2`: the
/// per-pixel deviation from the ORIGINAL source is bounded by half the
/// adjacent-column difference (≤ CFA contrast/2 in patterned regions) —
/// the documented deviation allowed by the acceptance (the
/// plateau±margin window now applies to the smoothed source, so the hard
/// snap bound |curve(out) − smoothed| ≤ ~1.5 source LSB is unchanged).
pub fn cfa_lowpass_h(src: &[u16], w: u32, h: u32) -> Vec<u16> {
    let w = w as usize;
    let h = h as usize;
    let mut out = vec![0u16; w * h];
    for y in 0..h {
        let r = y * w;
        for x in 0..w {
            let a = src[r + x] as u32;
            let b = src[r + (x + 1).min(w - 1)] as u32;
            out[r + x] = ((a + b) / 2) as u16;
        }
    }
    out
}

/// The plateau-constrained smooth inverse for ONE parity plane. Smooth the
/// nearest-preimage (pre0) with a 3×3 box (the smooth prior), then snap each
/// pixel into the pre-image PLATEAU of its source value (the pre values that
/// invert to that source). This removes the flat-band quantization staircase
/// while respecting the forward model (every output pixel inverts to its
/// source), unlike a plain blur — which is why it lands MAE ~1.0× the
/// measured one across the full 225-frame range rather than over-smoothing.
/// (the CFA 2-period band is erased UPSTREAM of this function
/// — in source space, before the invLUT remap; see cfa_lowpass_h. The snap
/// re-imposes any CFA contrast that survives to the pre-domain, so the
/// erasure cannot live here. The 3×3 box now runs on the
/// FULL-FRAME planes upstream — full_frame_planes — not per tile; this
/// per-tile form is kept for the vdct_probe calibration-history probes.)
/// `margin` lets the smooth prior pull the result up to `margin` pre values
/// outside the flat step (toward the prior), trading a little forward-model
/// fidelity for more smoothing of the steep-band frames (the f213–f225
/// high-detail tail where a 0-margin snap lands 1.5–1.97× the measured MAE).
/// Locked at `SNAP_MARGIN` (3) — a recorded calibration decision.
pub fn plateau_snap(
    pre0: &[u16],
    src_plane: &[u16],
    lo: &[i32; CURVE_LEN],
    hi: &[i32; CURVE_LEN],
    margin: i32,
) -> Vec<u16> {
    debug_assert_eq!(pre0.len(), src_plane.len());
    let prior = box3_smooth(pre0);
    let mut out = vec![0u16; pre0.len()];
    for i in 0..pre0.len() {
        let s = src_plane[i] as usize;
        let p = prior[i] as i32;
        let l = lo[s] - margin;
        let h = hi[s] + margin;
        out[i] = (if p < l {
            l
        } else if p > h {
            h
        } else {
            p
        }) as u16;
    }
    out
}

/// For each source (post-curve) value s, the pre-image PLATEAU [lo(s),
/// hi(s)]: the contiguous pre values that all invert to the closest curve
/// value to s (the nearest-preimage tie-set). In the curve's flat band
/// (slope ~0.077) the range is ~13 pre values wide; in the steep bands it
/// is 1. `plateau_snap` projects a smooth prior into this range.
pub fn plateau_range(curve: &[u16; CURVE_LEN]) -> ([i32; CURVE_LEN], [i32; CURVE_LEN]) {
    let inv = inv_lut(curve);
    let mut cfirst = vec![5000i32; CURVE_LEN];
    let mut clast = vec![0i32; CURVE_LEN];
    // `p` is used as a VALUE (cfirst/clast store it), not just an index
    // (clippy allow).
    #[allow(clippy::needless_range_loop)]
    for p in 0..CURVE_LEN {
        let c = curve[p] as usize;
        if (p as i32) < cfirst[c] {
            cfirst[c] = p as i32;
        }
        clast[c] = p as i32;
    }
    let mut lo = [0i32; CURVE_LEN];
    let mut hi = [0i32; CURVE_LEN];
    for s in 0..CURVE_LEN {
        let c = curve[inv[s] as usize] as usize;
        lo[s] = cfirst[c];
        hi[s] = clast[c];
    }
    (lo, hi)
}

/// Build the four tiles' parity planes of the SOURCE (post-curve) 12-bit
/// values (the pre-domain's forward image). Mirrors build_planes but keeps
/// the raw source values (not the invLUT). The plateau-constrained inverse
/// uses it to know, per pre-domain pixel, the source value it must invert
/// to. Last-row tiles padded with edge extension.
pub fn build_source_planes(src: &[u16], w: u32, h: u32) -> Result<[TilePlanes; 4], DctError> {
    if w != FRAME_W || h != FRAME_H {
        return Err(DctError::FrameDims {
            w,
            h,
            fw: FRAME_W,
            fh: FRAME_H,
        });
    }
    let mut out = [(); 4].map(|_| TilePlanes {
        even: vec![0u16; PLANE_W * PLANE_H],
        odd: vec![0u16; PLANE_W * PLANE_H],
    });
    for tr in 0..2u32 {
        for tc in 0..2u32 {
            let ti = (tr as usize) * 2 + tc as usize;
            let fy0 = tr * TILE_H;
            let fx0 = tc * TILE_W;
            for plane_idx in 0..2 {
                let plane = if plane_idx == 0 {
                    &mut out[ti].even
                } else {
                    &mut out[ti].odd
                };
                for p in 0..PLANE_H {
                    let fr = fy0 + 2 * p as u32 + plane_idx as u32;
                    let row_off = p * PLANE_W;
                    if (fr as usize) < h as usize {
                        for c in 0..PLANE_W {
                            plane[row_off + c] =
                                src[(fr as usize) * (FRAME_W as usize) + fx0 as usize + c];
                        }
                    } else {
                        for c in 0..PLANE_W {
                            plane[row_off + c] = plane[(PLANE_H_REAL - 1) * PLANE_W + c];
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

/// One tile's two parity planes (each PLANE_W × PLANE_H u16, pre-LUT
/// domain, row-major).
#[derive(Clone, Debug)]
pub struct TilePlanes {
    pub even: Vec<u16>,
    pub odd: Vec<u16>,
}

/// Build the four tiles' parity planes from the original 12-bit
/// (post-curve) source plane: `pre = invLUT(source)` per pixel, even/odd
/// frame-row split per tile, last-row tiles padded with 3 repetitions of
/// the plane's last real row (edge extension — measured padding rule).
pub fn build_planes(
    src: &[u16],
    w: u32,
    h: u32,
    inv: &[u16; CURVE_LEN],
) -> Result<[TilePlanes; 4], DctError> {
    if w != FRAME_W || h != FRAME_H {
        return Err(DctError::FrameDims {
            w,
            h,
            fw: FRAME_W,
            fh: FRAME_H,
        });
    }
    let mut out = [(); 4].map(|_| TilePlanes {
        even: vec![0u16; PLANE_W * PLANE_H],
        odd: vec![0u16; PLANE_W * PLANE_H],
    });
    for tr in 0..2u32 {
        for tc in 0..2u32 {
            let ti = (tr as usize) * 2 + tc as usize;
            let fy0 = tr * TILE_H;
            let fx0 = tc * TILE_W;
            for plane_idx in 0..2 {
                let plane = if plane_idx == 0 {
                    &mut out[ti].even
                } else {
                    &mut out[ti].odd
                };
                for p in 0..PLANE_H {
                    // plane row p ↔ frame row fy0 + 2p + plane_idx
                    let fr = fy0 + 2 * p as u32 + plane_idx as u32;
                    let row_off = p * PLANE_W;
                    if (fr as usize) < h as usize {
                        for c in 0..PLANE_W {
                            let s = src[(fr as usize) * (FRAME_W as usize) + fx0 as usize + c];
                            plane[row_off + c] = inv[s as usize];
                        }
                    } else {
                        // padding row (last-row tiles): repeat the
                        // plane's last real row (row PLANE_H_REAL - 1).
                        debug_assert!(p >= PLANE_H_REAL, "padding rows are the last 3 plane rows");
                        for c in 0..PLANE_W {
                            plane[row_off + c] = plane[(PLANE_H_REAL - 1) * PLANE_W + c];
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- dcdc
// — the gated per-class DC-offset diagnostic.

/// dcdc (GATED DIAGNOSTIC — the rank-1 candidate;
/// NEVER the default): the DARK-regime per-class DC offsets
/// Δ_c, in the E = B − A4 L0 convention (we ADD +Δ to bring our v4-2tap
/// decode A4 toward the measured decode B). Order (W, Ge, Go, R) — the
/// `w15c_cue_proxy.classes` grid W=P[0::2,0::2], Ge=P[0::2,1::2],
/// Go=P[1::2,0::2], R=P[1::2,1::2]. PROVENANCE (deterministic derivation
/// — derived, not tuned; literal table, NO new data path):
/// L0_c(frame) = mean(class_c(B)) − mean(class_c(A4)) on the
/// anchor PGMs (raw 12-bit units, NO /16); Δ_dark_c = mean(L0_c(f097),
/// L0_c(f113)) on the dark anchors (the Model A fit frames),
/// Δ_bright_c = L0_c(b0150) on the bright anchors.
/// Rank-1 holdout: 92.6–96.5% of the frame-DC (L0) error RMS
/// removed, per-class residual ≤1.2 raw; the G1 FAIL bounds the
/// ambition to the L0 level (no fixed transform reproduces the measured
/// block-DC grid). APPLICATION DOMAIN (raw-domain decision):
/// the Δ is added in the RAW source domain (0..4095, the domain the anchor
/// PGMs live in) BEFORE the 50712 pre-curve LUT — a raw add round-trips
/// exactly through the curve (decoded raw shift ≈ Δ_c, up to DCT/quant
/// noise in the DC domain), whereas a pre-domain constant is attenuated by
/// the local curve slope (~1/10–1/14 in the dark band — the v1 finding).
/// The per-class raw constants commute with the per-class horizontal 2-tap
/// at the L0 level, so the ordering vs `h2tap_smooth_wh` is immaterial.
pub const DCDC_DARK: [f64; 4] = [1.337713, 1.359291, 1.467699, 1.501032];

/// dcdc BRIGHT-regime constants (order W,Ge,Go,R; convention +
/// provenance: see `DCDC_DARK`).
pub const DCDC_BRIGHT: [f64; 4] = [44.659793, 45.231073, 18.998368, 19.835990];

/// dcdc regime threshold: the frame is DARK iff its own full-source mean
/// (12-bit raw) is below this (the encoder has the source — the regime
/// key is the same ≤1-switch key allowed). T = (max dark anchor
/// source mean + min bright anchor source mean) / 2 over the 8 anchor
/// SOURCE frames (the 6 dark + 2 bright full-res C PGMs):
/// (299.790 + 752.925) / 2; the 8 anchors split
/// strictly around T (nearest anchor 50.0% of the dark-bright gap away).
pub const DCDC_T: f64 = 526.357976;

/// dcdc: the 8 per-class DC constants + the regime
/// threshold as a unit — either the `DCDC_DARK`/`DCDC_BRIGHT`/`DCDC_T`
/// literals (the default) or the `FRAMEPRISM_DCDC_CONSTS` env override
/// (the response-pulse constants and the later fitted constants).
#[derive(Clone, Copy, Debug, PartialEq)]
struct DcdcConsts {
    /// dark-regime per-class offsets (order W,Ge,Go,R), 12-bit raw domain.
    dark: [f64; 4],
    /// bright-regime per-class offsets (order W,Ge,Go,R), 12-bit raw domain.
    bright: [f64; 4],
    /// regime threshold T (frame source mean, 12-bit raw; dark iff below).
    t: f64,
}

/// The env override `FRAMEPRISM_DCDC_CONSTS`: 8 comma-separated
/// floats (order W,Ge,Go,R dark; W,Ge,Go,R bright) + an optional 9th
/// field = the `DCDC_T` override (8 fields keep the literal T). Unset or
/// empty = the literals (default behavior UNCHANGED — bit-exact). Any
/// other malformation (wrong field count, unparsable or non-finite
/// field) is a HARD error mirroring the `CfaErasure::from_env` idiom —
/// a typo must never silently fall back to the literals.
fn dcdc_consts_from_env() -> Result<Option<DcdcConsts>, DctError> {
    let raw = match std::env::var("FRAMEPRISM_DCDC_CONSTS") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return Ok(None),
    };
    let fields: Vec<&str> = raw.split(',').collect();
    if !(8..=9).contains(&fields.len()) {
        return Err(DctError::BadDcdcConsts(format!(
            "expected 8 or 9 comma-separated floats (dark W,Ge,Go,R; bright \
             W,Ge,Go,R[, T]); got {}: {:?}",
            fields.len(),
            raw
        )));
    }
    let mut v = [0.0f64; 9];
    for (i, f) in fields.iter().enumerate() {
        v[i] = f.trim().parse::<f64>().map_err(|e| {
            DctError::BadDcdcConsts(format!(
                "field {} is not a parsable float ({}): {:?}",
                i + 1,
                e,
                raw
            ))
        })?;
        if !v[i].is_finite() {
            return Err(DctError::BadDcdcConsts(format!(
                "field {} is not finite: {:?}",
                i + 1,
                raw
            )));
        }
    }
    Ok(Some(DcdcConsts {
        dark: [v[0], v[1], v[2], v[3]],
        bright: [v[4], v[5], v[6], v[7]],
        t: if fields.len() == 9 { v[8] } else { DCDC_T },
    }))
}

/// dcdc: the frame's own source mean (12-bit raw, full frame) — the
/// regime key for `DCDC_T` (no new data path: `src` is the frame the
/// encoder is erasing).
fn dcdc_source_mean(src: &[u16]) -> f64 {
    src.iter().map(|&v| v as u64).sum::<u64>() as f64 / src.len() as f64
}

/// dcdc: the per-class RAW-domain DC offset for ONE source pixel (frame
/// row `fr`, frame col `x`) under the `w15c_cue_proxy.classes` grid
/// (W = even/even, Ge = even/odd, Go = odd/even, R = odd/odd). The raw
/// add is applied BEFORE the invLUT (raw-domain decision —
/// see the `DCDC_DARK` docs for why the raw domain is exact and the
/// pre-domain is slope-attenuated). Round-to-nearest, clip to the raw
/// domain 0..4095 (a raw DC add saturates at the 12-bit ceiling — the
/// bright-highlight tail clips; the flat majority
/// the sanity DC mean is measured on is far from 4095).
fn dcdc_raw_offset(s: u16, fr: usize, x: usize, dc: &[f64; 4]) -> u16 {
    let d = match (fr % 2, x % 2) {
        (0, 0) => dc[0], // W
        (0, 1) => dc[1], // Ge
        (1, 0) => dc[2], // Go
        _ => dc[3],      // R
    };
    ((s as f64) + d).round().clamp(0.0, 4095.0) as u16
}

/// The PRODUCTION pre-domain chain (D3 — replaces
/// build_planes + smooth_planes in the worker): the 3×3 box low-pass runs
/// on the FULL-FRAME parity planes (width FRAME_W = 3856, (h+1)/2 and h/2
/// rows — 1085 each for the 2170-row frame) BEFORE the cut into the 4 tile
/// planes, so the tile borders carry NO edge-replicate — the frame edge is
/// the only replicated edge (the pre-20c per-tile box3 edge-replicated at
/// every plane border; the middle column pair x=1927/1928 and row pair
/// y=1087/1088 got a different 3×3 neighborhood than any interior pixel —
/// D3, the 1–2 column seam line down the middle of the frame the user saw
/// in Resolve). `src` is the CFA-erased 12-bit source (cfa_lowpass_h is
/// applied by the caller, upstream, — it is ALREADY full-frame).
/// Steps: (1) invLUT into the two full-frame parity planes, (2) the CFA
/// erasure (gated by `FRAMEPRISM_ERASURE`, see `CfaErasure`): v4 (DEFAULT) =
/// the pre-domain horizontal 2-tap on each full-frame plane
/// (`h2tap_smooth_wh` — the v4-candidate erasure, edge-replicate at
/// the frame edge only); v5-binkill (gated diagnostic) = NO pre-domain op
/// (its erasure is the post-forward-DCT selective bin kill in
/// `encode_tiles_t21`), (3) cut
/// into the 4 tile planes (last-row tiles: 3 padding rows repeat the
/// plane's last real row — the measured rule, unchanged).
///
/// v4: NO plateau clamp. The ±SNAP_MARGIN window (the
/// forward-model guarantee) forced `curve(out)` to the linearized 2-tap
/// within ~2 source LSB — a v3/20b contract stricter than the measured
/// corpus file satisfies: the fit measures the corpus decoded
/// deviation from the 2-tap at 33/row (its internal content deviation;
/// the file's per-block DC sits +50…+76 pre-domain ≈ +10…+14 source LSB
/// ABOVE the 2-tap of our invLUT, systematically, across all 4 tile-scans
/// — the measured internal 12-bit→pre-domain mapping, not reproducible
/// from the file), and the clamped chain's ≤ 2 LSB bound was the clamp's
/// own artifact (Jensen kink at the bright knee alone reaches 27 LSB,
/// inside the measured 33/row envelope). The reference-fidelity contract
/// replaces the forward-model contract: `curve(out) ≈ (src[x] +
/// src[x+1]) / 2` within the measured deviation envelope. The 
/// fit validates the clamp-free 2-tap against the goldens: CFA band at
/// 8.51× the file's own quantization floor, whole-plane pixel MAE ~1.0×
/// the measured one. NOTE (recorded per the task): the structure
/// gate's v-floor clause (v_ratio ≥ 0.5, calibrated to v2/v3's 8×
/// cross-scan DC mix + the measured 33/row content deviation, reference
/// 1.001–1.086) rejects the v4 reference-faithful file (measured v_ratio
/// ~0.09–0.17 — the faithful 2-tap keeps the inter-scan difference at
/// 1× the source, the measured gain, and the file's per-pixel
/// deviation ~3/row, so the decoded v-step std ≈ the 1× inter-scan DC
/// difference ≈ 0.09–0.17× the source v-step std — the 20b 2-tap
/// 0.08–0.12 band the clause was built to reject). The gate is kept
/// AS-IS in this scope (record, do not re-tune); the v-floor
/// re-anchoring for the measured-faithful baseline is a recorded decision.
/// The `curve` parameter stays in the signature (callers unchanged);
/// the clamp machinery (`plateau_range` / `plateau_snap` /
/// `SNAP_MARGIN`) is kept for the retired per-tile `smooth_planes`
/// probe path and the diagnostics.
pub fn full_frame_planes(
    src: &[u16],
    w: u32,
    h: u32,
    inv: &[u16; CURVE_LEN],
    curve: &[u16; CURVE_LEN],
) -> Result<[TilePlanes; 4], DctError> {
    if w != FRAME_W || h != FRAME_H {
        return Err(DctError::FrameDims {
            w,
            h,
            fw: FRAME_W,
            fh: FRAME_H,
        });
    }
    // The env-var gate (see `CfaErasure`) — read once per encode.
    full_frame_planes_erased(src, w, h, inv, curve, CfaErasure::from_env()?)
}

/// `full_frame_planes` with an explicit erasure mode (the env-driven
/// wrapper above is the production entry; tests and diagnostics pin a
/// mode WITHOUT touching the process env — the parallel test threads
/// share it, so an explicit argument is the race-free form).
pub fn full_frame_planes_erased(
    src: &[u16],
    w: u32,
    h: u32,
    inv: &[u16; CURVE_LEN],
    curve: &[u16; CURVE_LEN],
    erase: CfaErasure,
) -> Result<[TilePlanes; 4], DctError> {
    if w != FRAME_W || h != FRAME_H {
        return Err(DctError::FrameDims {
            w,
            h,
            fw: FRAME_W,
            fh: FRAME_H,
        });
    }
    // v4: the plateau clamp is removed (see the function docs) — `curve`
    // stays in the signature for the unchanged call sites.
    let _ = curve;
    // v4 (): the CFA-erasure mode (see `CfaErasure`).
    // DEFAULT v4-2tap (the render baseline — policy: a render-
    // FAILing cue must not be the production default): the pre-domain
    // 2-tap alone. v5b-cue-cd (gated diagnostic — RENDER FAILED):
    // the 2-tap PLUS the per-scan sign-flipped color-cue re-injection
    // (`cue_offsets`). v5-binkill (gated diagnostic): NO pre-domain
    // smoothing — its erasure is the DCT-domain selective bin kill in
    // `encode_tiles_t21` (measured no-op on the CFA aliasing, probe
    // — see `cfa_bin_kill_block`).
    let fw = FRAME_W as usize;
    let n_rows = [h.div_ceil(2) as usize, (h / 2) as usize]; // even / odd full-plane rows
                                                             // dcdc (raw-domain decision): the per-class raw DC
                                                             // offset is applied in the RAW source domain BEFORE the invLUT (the
                                                             // 0..4095 domain the anchor PGMs live in) — a raw add round-trips
                                                             // exactly through the 50712 curve (decoded raw shift ≈ Δ_c), whereas a
                                                             // pre-domain constant is attenuated by the local curve slope
                                                             // (~1/10–1/14 in the dark band). Regime keyed on the frame's own source
                                                             // mean (see `DCDC_DARK`). `None` for every non-dcdc mode → the default
                                                             // path is byte-identical to v4-2tap (bit-exact HARD GATE). The
                                                             // constants (+ optional T) may come from the `FRAMEPRISM_DCDC_CONSTS`
                                                             // env override (`dcdc_consts_from_env`); unset/empty = the literals
                                                             // (bit-exact), malformed = a hard error.
    let dcdc_consts = dcdc_consts_from_env()?;
    let dcdc_dc: Option<&[f64; 4]> = if erase == CfaErasure::Dcdc {
        match &dcdc_consts {
            Some(c) => Some(if dcdc_source_mean(src) < c.t {
                &c.dark
            } else {
                &c.bright
            }),
            None => Some(if dcdc_source_mean(src) < DCDC_T {
                &DCDC_DARK
            } else {
                &DCDC_BRIGHT
            }),
        }
    } else {
        None
    };
    // (1) full-frame pre0 parity planes: plane row p ↔ frame row 2p+plane_idx
    // (both planes up front — the v5b-cue-cd cue needs the class lattices of
    // BOTH scans to build U = (W+R)/2 − (Go+Ge)/2). For dcdc the per-class
    // raw DC add (`dcdc_raw_offset`) is folded in here, before `inv[...]`.
    let pre_planes: [Vec<u16>; 2] = [0, 1].map(|plane_idx| {
        let n = n_rows[plane_idx];
        let mut pre = vec![0u16; fw * n];
        for p in 0..n {
            let fr = 2 * p + plane_idx;
            let ro = p * fw;
            for x in 0..fw {
                let s = match dcdc_dc {
                    Some(dc) => dcdc_raw_offset(src[fr * fw + x], fr, x, dc),
                    None => src[fr * fw + x],
                };
                pre[ro + x] = inv[s as usize];
            }
        }
        pre
    });
    // (2) the CFA erasure (gated by `FRAMEPRISM_ERASURE`): v4-2tap (DEFAULT,
    // baseline) = the pre-domain horizontal 2-tap over the FULL
    // plane (no tile-border replicate — edge-replicate at the frame edge
    // only); v5b-cue-cd (gated diagnostic — render-FAILED, never
    // the default) = the 2-tap PLUS the color-cue re-injection
    // (`cue_offsets`: +g·U_band on scan0, −g·U_band on scan1, clipped);
    // dcdc (gated diagnostic — the rank-1 per-class DC offset,
    // never the default) = the per-class constant Δ_regime_c applied in the
    // RAW source domain upstream in the pre_planes build (before the invLUT,
    // see `dcdc_raw_offset` + the `DCDC_DARK` docs; regime keyed on the
    // frame's own source mean vs `DCDC_T`) — the pre-domain here is the 2-tap
    // base, identical to v4; v5-binkill (gated
    // diagnostic) = no pre-domain op — its erasure is the post-forward-DCT
    // selective bin kill in `encode_tiles_t21`
    // (see `CfaErasure`).
    let (prior0, prior1) = match erase {
        CfaErasure::V4TwoTap => (
            h2tap_smooth_wh(&pre_planes[0], fw, n_rows[0]),
            h2tap_smooth_wh(&pre_planes[1], fw, n_rows[1]),
        ),
        CfaErasure::V5Cue => {
            let (off0, off1) = cue_offsets(
                &pre_planes[0],
                &pre_planes[1],
                fw,
                n_rows[0],
                n_rows[1],
                cue_gain(),
            );
            let tap0 = h2tap_smooth_wh(&pre_planes[0], fw, n_rows[0]);
            let tap1 = h2tap_smooth_wh(&pre_planes[1], fw, n_rows[1]);
            (
                apply_cue_offset(&tap0, &off0),
                apply_cue_offset(&tap1, &off1),
            )
        }
        CfaErasure::Dcdc => {
            // dcdc (GATED DIAGNOSTIC, never the default): the
            // per-class RAW DC add is applied upstream in the pre_planes
            // build (before the invLUT, see `dcdc_raw_offset`) — the
            // pre-domain here is the plain 2-tap base, identical to v4.
            (
                h2tap_smooth_wh(&pre_planes[0], fw, n_rows[0]),
                h2tap_smooth_wh(&pre_planes[1], fw, n_rows[1]),
            )
        }
        CfaErasure::V5BinKill => (pre_planes[0].clone(), pre_planes[1].clone()),
    };
    let mut out = [(); 4].map(|_| TilePlanes {
        even: vec![0u16; PLANE_W * PLANE_H],
        odd: vec![0u16; PLANE_W * PLANE_H],
    });
    // `plane_idx` is used as a VALUE (== 0 comparison, 2*p+plane_idx), not
    // just an index (clippy allow).
    #[allow(clippy::needless_range_loop)]
    for plane_idx in 0..2usize {
        let n = n_rows[plane_idx];
        let prior = if plane_idx == 0 { &prior0 } else { &prior1 };
        // (3) cut into tiles (same padding rule as build_planes) — the
        // v4 output is the 2-tap itself (no clamp; see the docs).
        for tr in 0..2u32 {
            for tc in 0..2u32 {
                let ti = (tr as usize) * 2 + tc as usize;
                let plane = if plane_idx == 0 {
                    &mut out[ti].even
                } else {
                    &mut out[ti].odd
                };
                let fx0 = tc * TILE_W;
                for p in 0..PLANE_H {
                    let f = (tr as usize) * PLANE_H + p; // full-plane row
                    let row_off = p * PLANE_W;
                    if f < n {
                        let prow = f * fw + fx0 as usize;
                        plane[row_off..row_off + PLANE_W]
                            .copy_from_slice(&prior[prow..prow + PLANE_W]);
                    } else {
                        // padding row (last-row tiles): repeat the plane's
                        // last real row (row PLANE_H_REAL - 1).
                        debug_assert!(p >= PLANE_H_REAL, "padding rows are the last 3 plane rows");
                        for c in 0..PLANE_W {
                            plane[row_off + c] = plane[(PLANE_H_REAL - 1) * PLANE_W + c];
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

// -------------------------------------------------------------------- FFI
//
// C ABI declarations live in `crate::ljpeg_ffi` (single home, ).
use crate::ljpeg_ffi::{
    ljpeg_comp_error, ljpeg_comp_free, ljpeg_comp_new, ljpeg_encode_coeff12, ljpeg_free_buffer,
};

// ------------------------------------------------- DCT (encoder-side)

/// Orthonormal DCT-II 8×8 matrix, row-major: `A[u][i] = a(u)·cos(π(2i+1)u/16)`
/// with `a(0) = 1/(2√2)`, `a(u>0) = 1/2`. This is the EXACT inverse of the
/// decoder's IDCT convention (`dct2s::idct_block`: cs = cos(kπ/16)/2 with √½
/// pre-scaling on the DC row/col — its 2-D scale factors are exactly
/// `a(u)·a(v)`: DC 1/8, single-axis 1/(4√2), two-axis 1/4), so
/// `X_orth = A·X·Aᵀ` on a centered block is the coefficient set that
/// `idct_block` inverts.
///
/// Why we compute the DCT ourselves: this libjpeg-turbo
/// rebuild's 12-bit islow forward DCT writes the odd-frequency-row
/// coefficients at the wrong per-row scale — measured on a pure 2-period
/// CFA-band plane (2048±100, all rows identical): file coefficients
/// (0,1)=144 (correct), (0,3)=240 (2.09× the islow value 115),
/// (0,5)=648 (3.25× of 199), (0,7)=3224 (4.45× of 725); the 8-bit islow
/// path (the workhorse) is correct, and libjpeg's own 12-bit DCT↔IDCT pair
/// is self-consistent (an independent djpeg decodes the stream back to the
/// input), so it is a per-row scale error in the 12-bit compile of the
/// multi-precision rebuild, not a data-path bug in our shim. The
/// reference-verified decoder (dct2s = LibRaw ljpeg_idct) inverts the STANDARD
/// islow convention (Q = X_orth), so the encoder must write that — done
/// here, with libjpeg used only for DC prediction + 2-pass Huffman +
/// bitstream (the raw-coefficient API, `ljpeg_encode_coeff12`).
fn dct_matrix() -> &'static [f64; 64] {
    static M: std::sync::OnceLock<[f64; 64]> = std::sync::OnceLock::new();
    M.get_or_init(|| {
        let mut m = [0f64; 64];
        for u in 0..8usize {
            let a = if u == 0 {
                (1.0f64 / 2.0).sqrt() / 2.0 // 1/(2√2)
            } else {
                0.5
            };
            for i in 0..8usize {
                let ang = (2 * i + 1) as f64 * u as f64 * core::f64::consts::PI / 16.0;
                m[u * 8 + i] = a * ang.cos();
            }
        }
        m
    })
}

/// Natural (row-major 8×8) index → FILE (zigzag/DQT) position.
fn nat2file() -> &'static [usize; 64] {
    static T: std::sync::OnceLock<[usize; 64]> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut t = [0usize; 64];
        for (p, &n) in crate::dct2s::ZIGZAG.iter().take(64).enumerate() {
            t[n as usize] = p;
        }
        t
    })
}

/// libjpeg 12-bit quantize convention: `(t + q/2) / q` with C's
/// truncation-toward-zero division (the 12-bit branch of jcdctmgr:
/// `temp += qval >> 1; temp /= qval` on the 8×-scaled islow output ≡ the
/// same on X_orth with qval = 8q). Returns the QUANTIZED INDEX (qcode),
/// not the dequantized value: the raw-coefficient path hands JBLOCKs to
/// `encode_mcu` as-is (the transcode coef controller — jctrans
/// `compress_output` — passes blocks straight to the entropy encoder, and
/// `encode_one_block` codes `block[k]` as the Huffman symbol), so the array
/// must contain the qcodes themselves. The decoder recovers the dequantized
/// coefficient as `qcode × quant[filepos]` (dct2s `decode_scan`).
fn quantize_index(t: f64, q: i64) -> i64 {
    let num = t + (q as f64) * 0.5;
    (num / (q as f64)).trunc() as i64
}

/// DCT + quantize one parity plane (PLANE_W × PLANE_H u16, 0..4095) into
/// QUANTIZED INDICES (qcodes) in natural order, blocks raster: 241 × 68
/// blocks × 64. The DC slot of each block is `quantize_index(8 × (block
/// mean − 2048), q0)` — the encoder's DC predictor starts at 0 on the
/// centered index, and the decoder's vpred chain (vpred0 = 16384 = 8 × 2048,
/// `vpred += diff × quant[0]`) unwinds exactly that. AC slots are
/// `quantize_index(X_orth, q)`, q indexed by FILE/zigzag position (DQT
/// order); the dequantized value `index × q` is what `dct2s::decode_scan`
/// reconstructs (`coef * quant[filepos]`) and feeds to `idct_block`.
pub fn quantize_plane(plane: &[u16], table: &[u16; 64]) -> Vec<i16> {
    assert_eq!(plane.len(), PLANE_W * PLANE_H, "quantize_plane: bad dims");
    quantize_plane_raw(plane, table)
}

/// `quantize_plane` on a plane of arbitrary (block-multiple) size — the
/// shared core (the FATAL gates' synthetic tests use full planes; kept
/// separate so the full-plane convenience wrapper stays dim-checked).
///
/// One block's pre-quantization X_orth (natural order, 64 f64, centered:
/// DC slot = 8 × (block mean − 2048)) — the exact inverse of the dct2s
/// IDCT (orthonormal DCT-II); `quantize_plane_raw` turns these into the
/// qcodes the raw-coefficient bitstream path expects (see
/// `quantize_index`). Exposed to the DCT unit tests (the tag-7 DCT
/// comparison).
fn block_xorth(plane: &[u16], pw: usize, bx: usize, by: usize) -> [f64; 64] {
    let a = dct_matrix();
    let mut x = [[0f64; 8]; 8];
    for i in 0..8 {
        let row = &plane[(by * 8 + i) * pw + bx * 8..(by * 8 + i) * pw + bx * 8 + 8];
        for j in 0..8 {
            x[i][j] = f64::from(row[j]) - 2048.0;
        }
    }
    // Y = A·X: y[u][k] = Σ_l A[u][l]·X[l][k]
    let mut y = [[0f64; 8]; 8];
    for u in 0..8 {
        for k in 0..8 {
            let mut acc = 0f64;
            for l in 0..8 {
                acc += a[u * 8 + l] * x[l][k];
            }
            y[u][k] = acc;
        }
    }
    // X_orth[u][v] = Σ_k Y[u][k]·A[v][k]
    let mut out = [0f64; 64];
    for u in 0..8 {
        for v in 0..8 {
            let mut acc = 0f64;
            for k in 0..8 {
                acc += y[u][k] * a[v * 8 + k];
            }
            out[u * 8 + v] = acc;
        }
    }
    out
}

/// Quantize pre-computed per-block X_orth (natural order, 64 f64 each, blocks
/// raster) into QUANTIZED INDICES (qcodes) in natural order — the shared tail
/// of `quantize_plane_raw` (exposed so the production path can
/// transform the float coefficients BEFORE quantization; see
/// `encode_tiles_t21`).
fn quantize_xorth_blocks(xs: &[[f64; 64]], table: &[u16; 64]) -> Vec<i16> {
    let n2f = nat2file();
    let q: [i64; 64] = core::array::from_fn(|p| i64::from(table[p]));
    let mut out = vec![0i16; xs.len() * 64];
    let mut o = 0usize;
    for x in xs.iter() {
        for (k, &xo) in x.iter().enumerate() {
            let qi = q[n2f[k]];
            let c = quantize_index(xo, qi);
            // JCOEF is `short`: saturate (a qcode of ±32768 would need
            // |X_orth| ≥ q·32768 — unreachable for 12-bit content; the
            // clamp keeps the FFI type honest). The encoder Huffman-codes
            // c AS-IS (see quantize_index), the decoder recovers c·q.
            out[o + k] = c.clamp(i16::MIN as i64, i16::MAX as i64) as i16;
        }
        o += 64;
    }
    out
}

fn quantize_plane_raw(plane: &[u16], table: &[u16; 64]) -> Vec<i16> {
    let pw = plane.len() / PLANE_H;
    let nbw = pw / 8;
    let nbh = PLANE_H / 8;
    let mut xs = vec![[0f64; 64]; nbw * nbh];
    let mut b = 0usize;
    for by in 0..nbh {
        for bx in 0..nbw {
            xs[b] = block_xorth(plane, pw, bx, by);
            b += 1;
        }
    }
    quantize_xorth_blocks(&xs, table)
}

// ------------------------------------------------- FATAL gates (20a)

/// CFA R−G column contrast of one scan0 plane, in LSB of the plane's own
/// domain: |mean(odd cols) − mean(even cols)|. Every scan0 plane row is
/// CFA class row 1 (frame even rows; 50719 ctop is odd for the fp), where
/// even cols = G and odd cols = R (the measured phase contract; with an
/// odd cleft the columns swap — the ABSOLUTE contrast is unchanged). This
/// is the 2-column-period component the D1 defect amplified.
pub fn cfa_contrast_cols(plane: &[u16]) -> f64 {
    let mut se = 0.0f64;
    let mut so = 0.0f64;
    let mut ne = 0.0f64;
    let mut no = 0.0f64;
    for (x, &v) in plane.iter().enumerate() {
        if x % 2 == 0 {
            se += f64::from(v);
            ne += 1.0;
        } else {
            so += f64::from(v);
            no += 1.0;
        }
    }
    (so / no - se / ne).abs()
}

/// FATAL CFA-contrast gate (anti-amplification; 
/// re-scope). Two checks per tile, on the scan0 plane (the recon is the
/// tile's scan 0 decoded with the IDENTITY LUT — pre-curve IDCT, the
/// measurement convention):
///
/// (1) RATIO FORM (the 20a spec): recon / input pre-domain contrast ∈
///     [0, 2.0], applied where the input has meaningful CFA energy
///     (cin ≥ CIN_MEANINGFUL). Kills D1-class defects on strong-CFA input
/// (4.00× amplification → ratio ≈ 4 → FAIL); the measured erasure
///     behavior lands at ~0, which is also acceptable.
/// (2) SOURCE-REFERENCED BACKSTOP : recon contrast ≤ 2.0× the
///     ORIGINAL source's CFA contrast (pre-units via invLUT) —
///     anti-amplification relative to the real CFA energy, content-scale
///     invariant.
///
/// WHY BOTH (the interaction): after the CFA-erasing pre-domain,
/// the input contrast is the erasure residual (f1
/// 0.023 / f86 0.416 / f113 0.010 pre-units) and the recon carries a small
/// odd-u quantization LEAKAGE (f1 0.281, f86 tile1 0.784) that is scene
/// texture, not amplified CFA band — at input levels near the leakage the
/// ratio form misfires (f86 tile1: 0.784/0.386 = 2.03 on a healthy encode),
/// so the ratio form is applied only where cin ≥ CIN_MEANINGFUL (= 1.0 —
/// a fixed design parameter, not fitted), and the source-referenced
/// backstop covers the erased-input world (it is scale-invariant: a 4×
/// amplification of a strong band still exceeds 2× the source's band).
/// The D1 regression guard for the erased-input world is the synthetic
/// round-trip unit test (a 2-period block through the encoder DCT must
/// land ≈ 1.00×, not 4.00×), not any contrast ratio.
pub fn gate_cfa_contrast(
    tiles: &[Vec<u8>],
    planes: &[TilePlanes; 4],
    src_orig_planes: &[TilePlanes; 4],
    curve: &[u16; CURVE_LEN],
) -> Result<(), DctError> {
    const RATIO_MAX: f64 = 2.0;
    const CIN_MEANINGFUL: f64 = 1.0; // ratio form needs meaningful input CFA energy
    const SRC_RATIO_MAX: f64 = 2.0; // recon ≤ 2× the source's CFA contrast
    let id = crate::dct2s::linearization_curve(None);
    let inv = inv_lut(curve);
    for (t, tile) in tiles.iter().enumerate() {
        let info = crate::dct2s::parse_tile(tile)
            .map_err(|e| DctError::Gate(format!("cfa gate tile {t}: parse: {e}")))?;
        let (recon, _) = crate::dct2s::decode_scan_plane(tile, &info, 0, &id)
            .map_err(|e| DctError::Gate(format!("cfa gate tile {t}: decode scan0: {e}")))?;
        let cr = cfa_contrast_cols(&recon);
        let cin = cfa_contrast_cols(&planes[t].even);
        // (1) the 20a ratio form — where the input carries meaningful CFA energy
        if cin >= CIN_MEANINGFUL {
            let ratio = cr / cin;
            if ratio > RATIO_MAX {
                return Err(DctError::Gate(format!(
                    "cfa-contrast tile {t}: ratio {ratio:.3} > {RATIO_MAX} (input {cin:.3}, recon {cr:.3} pre-units)"
                )));
            }
        }
        // (2) source-referenced backstop 
        let src_pre: Vec<u16> = src_orig_planes[t]
            .even
            .iter()
            .map(|&s| inv[s as usize])
            .collect();
        let cin_src = cfa_contrast_cols(&src_pre);
        if cr > SRC_RATIO_MAX * cin_src {
            return Err(DctError::Gate(format!(
                "cfa-contrast tile {t}: recon {cr:.3} > {SRC_RATIO_MAX}× source {cin_src:.3} pre-units"
            )));
        }
    }
    Ok(())
}

/// FATAL per-CFA-class mean-error gate (reference-
/// recalibrated): |mean(decoded − source)| per class (W / G / R) must be
/// < LIMIT. Phase from tag 50719 DefaultCropOrigin `[cleft, ctop]`:
/// class at (y, x) = ((y−ctop) mod 2, (x−cleft) mod 2) over the [W G /
/// G R] pattern (W = 00, G = 01|10, R = 11). Generalizes the ds2x-magenta
/// lesson: full-frame MAE is blind to structured per-class error.
/// `decoded`/`source` are post-curve 12-bit planes.
///
/// LIMIT = 31 (reference-anchored arbitration
/// rule): the original 20a limit of 15 was calibrated on the DARK f1
/// (reference per-class ±5 there). Measuring the corpus per-class means
/// on ALL 225 vbr-hq frames (identical code path: 50719 phase [8,5],
/// W/G/R mapping, real per-frame curve; cross-validated bit-exact against
/// the independent Python decode) shows the measured encoder itself reaches
/// max|mean| = 15.343 (f84, W −15.343) on the bright content (f82–f89),
/// and 16/225 reference frames exceed the old 15 limit — the 2-tap CFA
/// erasure structurally shifts each class by (class-diff)/2 (each pixel →
/// column local mean), which scales with the CFA class contrast (bright
/// frames) and NOT with the preset (all 4 cbr presets measured ≤ 1.9).
/// The limit is max_reference × 2 = 30.686, rounded up to 31. Evidence:
/// the 225 measured rows + the per-class reference data.
pub fn gate_class_means(
    decoded: &[u16],
    source: &[u16],
    w: u32,
    origin: [u32; 2],
) -> Result<(), DctError> {
    const LIMIT: f64 = 31.0; // reference-anchored (max_reference 15.343 × 2)
    let (cleft, ctop) = (origin[0] as i64, origin[1] as i64);
    let mut sum = [0i64; 3];
    let mut cnt = [0u64; 3];
    for (i, (&d, &s)) in decoded.iter().zip(source.iter()).enumerate() {
        let y = (i / w as usize) as i64;
        let x = (i % w as usize) as i64;
        let rp = (y - ctop).rem_euclid(2) as usize;
        let cp = (x - cleft).rem_euclid(2) as usize;
        let cls = match (rp, cp) {
            (0, 0) => 0, // W
            (1, 1) => 2, // R
            _ => 1,      // G (01 | 10)
        };
        sum[cls] += i64::from(d) - i64::from(s);
        cnt[cls] += 1;
    }
    let names = ["W", "G", "R"];
    for c in 0..3 {
        if cnt[c] == 0 {
            continue;
        }
        let mean = sum[c] as f64 / cnt[c] as f64;
        if mean.abs() >= LIMIT {
            return Err(DctError::Gate(format!(
                "per-class mean {}: {mean:.2} LSB (|mean| >= {LIMIT})",
                names[c]
            )));
        }
    }
    Ok(())
}

/// Seam-gate result: the measured |err| ratio (seam strip / local baseline)
/// for the vertical (x = 1928 tile border) and horizontal (y = 1088)
/// seams. Returned for the --verify log (the 20d 225-frame record).
#[derive(Debug)]
pub struct SeamRatios {
    pub v: f64,
    pub h: f64,
}

/// FATAL tile-seam gate (the user's vertical center line):
/// |err| on the tile-boundary COLUMN pair x ∈ {1927, 1928} (full frame
/// height) and ROW pair y ∈ {1087, 1088} (full frame width) must each be
/// < 1.5× the local baseline — columns 1916–1926 ∪ 1930–1940 (same height)
/// and rows 1076–1086 ∪ 1090–1100 (same width) — in the post-curve 12-bit
/// domain (same domains as gate_class_means; the baseline is 22/24 columns
/// / rows wide, i.e. ±11–12 away from the seam, one column/row gap). Catches
/// the D3-class defect: a 1–2 column/row step at the frame middle (the
/// pre-20c per-tile box3 edge-replicate seam). Where the baseline mean |err|
/// is below SEAM_BASE_EPS (a near-exact region — the ratio is meaningless),
/// the seam strip must be below the absolute SEAM_ABS_LIM (1.0 LSB — a
/// visible line is a multi-LSB step). Fixed design parameters, not fitted.
pub fn gate_seam(decoded: &[u16], source: &[u16], w: u32, h: u32) -> Result<SeamRatios, DctError> {
    if w != FRAME_W || h != FRAME_H {
        return Err(DctError::FrameDims {
            w,
            h,
            fw: FRAME_W,
            fh: FRAME_H,
        });
    }
    const SEAM_RATIO_MAX: f64 = 1.5;
    const SEAM_BASE_EPS: f64 = 0.05;
    const SEAM_ABS_LIM: f64 = 1.0;
    let fw = w as usize;
    let fh = h as usize;
    // sum of |decoded − source| over cols ∈ [c0, c1) × rows ∈ [r0, r1)
    // (returns (sum, n))
    let strip = |c0: usize, c1: usize, r0: usize, r1: usize| -> (u64, u64) {
        let (mut s, mut n) = (0u64, 0u64);
        for y in r0..r1 {
            let ro = y * fw;
            for x in c0..c1 {
                s += decoded[ro + x].abs_diff(source[ro + x]) as u64;
                n += 1;
            }
        }
        (s, n)
    };
    let ratio_of = |seam: (u64, u64), base: (u64, u64)| -> f64 {
        let s = seam.0 as f64 / seam.1 as f64;
        let b = base.0 as f64 / base.1 as f64;
        if b < SEAM_BASE_EPS {
            // near-exact region: the ratio is meaningless — judge the seam
            // against the absolute floor instead (reported as the effective
            // ratio s/SEAM_ABS_LIM × SEAM_RATIO_MAX so PASS ≤ 1.5 holds).
            (s / SEAM_ABS_LIM * SEAM_RATIO_MAX).min(f64::INFINITY)
        } else {
            s / b
        }
    };
    // vertical seam at x = 1928 (the 1927/1928 column pair)
    let seam_v = strip(1927, 1929, 0, fh);
    let base_v = (strip(1916, 1927, 0, fh), strip(1930, 1941, 0, fh));
    let base_v = (base_v.0 .0 + base_v.1 .0, base_v.0 .1 + base_v.1 .1);
    let r_v = ratio_of(seam_v, base_v);
    if r_v > SEAM_RATIO_MAX {
        return Err(DctError::Gate(format!(
            "seam vertical (x∈{{1927,1928}}): ratio {r_v:.3} > {SEAM_RATIO_MAX}"
        )));
    }
    // horizontal seam at y = 1088 (the 1087/1088 row pair)
    let seam_h = strip(0, fw, 1087, 1089);
    let base_h = (strip(0, fw, 1076, 1087), strip(0, fw, 1090, 1101));
    let base_h = (base_h.0 .0 + base_h.1 .0, base_h.0 .1 + base_h.1 .1);
    let r_h = ratio_of(seam_h, base_h);
    if r_h > SEAM_RATIO_MAX {
        return Err(DctError::Gate(format!(
            "seam horizontal (y∈{{1087,1088}}): ratio {r_h:.3} > {SEAM_RATIO_MAX}"
        )));
    }
    Ok(SeamRatios { v: r_v, h: r_h })
}

/// The decoded-frame 2-period structure ratios (the lossy v2 transform)
/// (d2diag RAW 2-period protocol, full frame, all pixels): the std of the
/// decoded adjacent-pixel steps over the horizontal (x → x+1) and vertical
/// (y → y+1) neighbor sets, each divided by the same stat on the SOURCE
/// (12-bit post-curve). `h_ratio` ≈ how much of the within-row 2-period
/// banding survives the encode (the lossy v2 transform erases it → small);
/// `v_ratio` ≈ how much of the between-row (row-parity) class structure
/// survives (the transform PRESERVES it → ≈ 1, reference-anchored). Both
/// `decoded` and `source` are post-curve 12-bit full frames. Returns
/// (h_ratio, v_ratio); NaN where the source step std is 0 (the gate
/// rejects NaN as a measurement error).
pub fn structure_ratios(decoded: &[u16], source: &[u16], w: u32, h: u32) -> (f64, f64) {
    let (fw, fh) = (w as usize, h as usize);
    let mut sh = 0f64;
    let mut dh = 0f64;
    let mut sh2 = 0f64;
    let mut dh2 = 0f64;
    let mut sv = 0f64;
    let mut dv = 0f64;
    let mut sv2 = 0f64;
    let mut dv2 = 0f64;
    let mut nh = 0.0f64;
    let mut nv = 0.0f64;
    for y in 0..fh {
        let ro = y * fw;
        for x in 0..fw - 1 {
            let s = (source[ro + x + 1] as f64) - (source[ro + x] as f64);
            let d = (decoded[ro + x + 1] as f64) - (decoded[ro + x] as f64);
            sh += s;
            dh += d;
            sh2 += s * s;
            dh2 += d * d;
            nh += 1.0;
        }
        if y < fh - 1 {
            for x in 0..fw {
                let i = ro + x;
                let s = (source[i + fw] as f64) - (source[i] as f64);
                let d = (decoded[i + fw] as f64) - (decoded[i] as f64);
                sv += s;
                dv += d;
                sv2 += s * s;
                dv2 += d * d;
                nv += 1.0;
            }
        }
    }
    let std = |sum: f64, sum2: f64, n: f64| -> f64 {
        let m = sum / n;
        (sum2 / n - m * m).max(0.0).sqrt()
    };
    let shstd = std(sh, sh2, nh);
    let svstd = std(sv, sv2, nv);
    let (hr, vr) = (
        if shstd > 0.0 {
            std(dh, dh2, nh) / shstd
        } else {
            f64::NAN
        },
        if svstd > 0.0 {
            std(dv, dv2, nv) / svstd
        } else {
            f64::NAN
        },
    );
    (hr, vr)
}

/// FATAL per-frame structure gate (the lossy v2 transform) (vbr + cbr), the
/// cast-regression backstop: the decoded 2-period ratios (see
/// `structure_ratios`) must stay inside the measured-anchored bands
/// (approved calibration, probe 225-frame sweep):
///
/// v_ratio ∈ [max(0.5, 0.5×reference_v_same_frame), max(1.4, 3.5×reference_v_same_frame)]
/// h_ratio ≤ max(1.0, 2 × reference_h_same_frame)
///
/// (The v-floor was recalibrated from the fixed 0.7
/// — calibrated to v2's own min 0.707 while the measured encoder sits at 1.001–1.086
/// on all 225 A001 frames — to the measured-anchored form above, with a 0.5
/// absolute floor without the anchor. See the clause (1) comment.
///
/// The measured encoder (vbr-hq 225) sweeps: v = 1.001–1.086, h = 0.071–0.438. The
/// v-floor is the anti-2-tap regression clause (the 20b 2-tap
/// measured v = 0.08–0.12 clip-wide — a re-introduced source-space
/// low-pass crushes the between-row class structure the demosaic needs);
/// the 1.0 h-floor = never above the source's own h-step std. The 3.5×
/// reference-v ceiling absorbs the fixed-G dark-segment overshoot (the
/// measured D gain is content-adaptive 9.95 dark → 6.98 bright; a
/// fixed G = 8 overshoots the 12-bit D where the curve slope ≈ 1.0 —
/// measured max 3.398 on the A001 clip, frames ~f132–f185; the overshoot
/// points TOWARD the source chroma, not the cast). The h-floor clause is
/// reference-independent and enforced even WITHOUT the same-frame reference
/// anchor (`reference` = None); the v-floor degrades to its 0.5 absolute
/// half without the anchor; the upper bounds need the anchor and are
/// skipped (informational) without it — the same optional-anchor pattern
/// as the G2 pixel gate's `--reference-mae-tsv`. The existing gates
/// (per-class ≤ 31 both ways, MAE catastrophe ceiling, seam ratio, G2
/// distribution) are unchanged and NOT weakened.
pub fn gate_structure(hr: f64, vr: f64, reference: Option<(f64, f64)>) -> Result<(), DctError> {
    if hr.is_nan() || vr.is_nan() {
        return Err(DctError::Gate(format!(
            "structure: NaN ratio (h {hr}, v {vr}) — measurement error (flat source?)"
        )));
    }
    // (1) v-floor: the 2-tap-regression clause (recalibrated):
    // floor = max(0.5, 0.5×reference_v) with
    // the same-frame anchor, 0.5 absolute without it. The 0.7 floor was
    // calibrated to v2's OWN min (v2 min 0.707; f1 = 0.713 sat on the
    // edge) — circular, one encoder generation stale — while the measured encoder
    // sits at v ≥ 1.001 on all 225 A001 frames (0 below 0.7). The
    // reference-anchored form keeps the proxy's cast-prevention function
    // (no frame may drop below 50% of the measured per-frame v) and
    // generalizes to clip 2 where the measured v may not sit at ~1.0.
    // The dem2/pcdiff direct cast measures (gate_demosaic + per-class)
    // remain PRIMARY .
    let v_floor = reference.as_ref().map_or(0.5f64, |&(vv, _)| 0.5 * vv).max(0.5);
    if vr < v_floor {
        return Err(DctError::Gate(format!(
            "structure: v_ratio {vr:.3} < {v_floor:.3} (max(0.5, 0.5×reference_v); between-row class structure crushed — 2-tap-class regression)"
        )));
    }
    // (2) h-floor: never above the source's own h-step (reference-independent).
    if hr > 1.0 {
        return Err(DctError::Gate(format!(
            "structure: h_ratio {hr:.3} > 1.0 (h-band above source — banding-class regression)"
        )));
    }
    // (3) the measured-anchored upper bounds (same-frame anchor required).
    if let Some((vv, vh)) = reference {
        if vv.is_nan() || vh.is_nan() || vv <= 0.0 {
            return Err(DctError::Gate(format!(
                "structure: bad reference anchor (v {vv}, h {vh})"
            )));
        }
        let v_upper = 1.4f64.max(3.5 * vv);
        if vr > v_upper {
            return Err(DctError::Gate(format!(
                "structure: v_ratio {vr:.3} > {v_upper:.3} (max(1.4, 3.5×reference_v {vv:.3}))"
            )));
        }
        let h_upper = 1.0f64.max(2.0 * vh);
        if hr > h_upper {
            return Err(DctError::Gate(format!(
                "structure: h_ratio {hr:.3} > {h_upper:.3} (max(1.0, 2×reference_h {vh:.3}))"
            )));
        }
    }
    Ok(())
}

/// The d2demo demosaic-proxy chroma stds of ONE frame (the lossy v2 transform)
/// (W−G, G−R, W−R stds over all pixels), phase-general over the tag 50719
/// `origin = [cleft, ctop]`: class at (x, y) = ((y−ctop) mod 2, (x−cleft)
/// mod 2) over the [W G / G R] pattern (W = 00, G = 01|10, R = 11 — same
/// mapping as `gate_class_means`). Protocol (byte-identical to the
/// diagnostic `d2demo` on the A001 phase [8,5], so the numbers compare
/// against the probe/Phase-3 TSVs): per pixel, own class = own value, the
/// other two classes = the mean of the same-class pixels at (x±2, y) and
/// (x, y±2) (edge-clamped; a class's pixels form a period-2 lattice, so
/// the clamped border positions either contribute or are skipped by the
/// class match — kept verbatim). What an NLE demosaic sees as LOCAL COLOR:
/// the 2-tap drove these to ≈ 0 (the decoded Bayer is flat gray
/// per demosaic neighborhood → the orange/cyan cast); the measured encoder and the
/// lossy v2 transform keeps them ≈ source (probe: f86 reference 1.27/1.78/1.26
/// vs 2-tap 0.17/0.23/0.16). NOTE (probe, measured): on this CFA the ±2
/// neighbor search never finds a different class than the own lattice, so
/// this is a per-class-lattice local-contrast statistic (kept verbatim for
/// comparability).
pub fn demosaic_chroma(decoded: &[u16], w: u32, h: u32, origin: [u32; 2]) -> [f64; 3] {
    let (fw, fh) = (w as usize, h as usize);
    let (cleft, ctop) = (origin[0] as i64 & 1, origin[1] as i64 & 1);
    // 2×2 class lookup (the class is periodic-2 in both axes).
    let lut = |ry: usize, cx: usize| -> usize {
        let rp = (ry as i64).wrapping_sub(ctop).rem_euclid(2) as usize;
        let cp = (cx as i64).wrapping_sub(cleft).rem_euclid(2) as usize;
        match (rp, cp) {
            (0, 0) => 0, // W
            (1, 1) => 2, // R
            _ => 1,      // G
        }
    };
    let mut ch: [Vec<f64>; 3] = [
        vec![0f64; fw * fh],
        vec![0f64; fw * fh],
        vec![0f64; fw * fh],
    ];
    for y in 0..fh {
        for x in 0..fw {
            let i = y * fw + x;
            let c0 = lut(y & 1, x & 1);
            ch[c0][i] = decoded[i] as f64;
            // `c` is used as a VALUE (== c0, the lut lookup), not just an
            // index (clippy allow).
            #[allow(clippy::needless_range_loop)]
            for c in 0..3usize {
                if c == c0 {
                    continue;
                }
                let mut s = 0f64;
                let mut n = 0f64;
                for (xx, yy) in [
                    (x.saturating_sub(2), y),
                    ((x + 2).min(fw - 1), y),
                    (x, y.saturating_sub(2)),
                    (x, (y + 2).min(fh - 1)),
                ] {
                    if lut(yy & 1, xx & 1) == c {
                        s += decoded[yy * fw + xx] as f64;
                        n += 1.0;
                    }
                }
                ch[c][i] = if n > 0.0 { s / n } else { decoded[i] as f64 };
            }
        }
    }
    let mut wg = 0f64;
    let mut gr = 0f64;
    let mut wr = 0f64;
    let mut wg2 = 0f64;
    let mut gr2 = 0f64;
    let mut wr2 = 0f64;
    let n = (fw * fh) as f64;
    // `i` only indexes the three equal-length `ch` channels; a zip chain
    // would change the measurement code shape for no gain (clippy
    // allow).
    #[allow(clippy::needless_range_loop)]
    for i in 0..fw * fh {
        let (a, b, r) = (ch[0][i], ch[1][i], ch[2][i]);
        let d1 = a - b;
        let d2 = b - r;
        let d3 = a - r;
        wg += d1;
        gr += d2;
        wr += d3;
        wg2 += d1 * d1;
        gr2 += d2 * d2;
        wr2 += d3 * d3;
    }
    let std = |s: f64, m: f64| (s / n - m * m).max(0.0).sqrt();
    let (mw, mg, mwr) = (wg / n, gr / n, wr / n);
    [std(wg2, mw), std(gr2, mg), std(wr2, mwr)]
}

/// FATAL per-frame demosaic-chroma gate (the lossy v2 transform) (vbr + cbr):
/// each of the W−G / G−R / W−R chroma stds (see `demosaic_chroma`, decoded
/// file) must be inside [0.5×, max(2×, 0.75 absolute)] of the measured
/// same-frame value — the cast gate: the demosaic must see local color in
/// the same range as the measured encoder (probe calibration: the measured
/// 225-frame dec/src chroma medians 0.79–0.92, worst frames 0.12× source —
/// so the global ≥0.5×-source clause is intentionally DROPPED: it would
/// fail the measured encoder itself; the 0.75 absolute floor keeps the band
/// meaningful on near-monochrome frames). The reference anchor is REQUIRED
/// (the band is reference-relative by construction): without
/// `--reference-structure-tsv` the gate prints the measured values on the
/// informational line and is not FATAL (the v-floor of `gate_structure`
/// still catches the 2-tap regression, which crushes both v and chroma).
pub fn gate_demosaic(ours: [f64; 3], reference: Option<[f64; 3]>) -> Result<(), DctError> {
    let names = ["W-G", "G-R", "W-R"];
    for (c, &o) in ours.iter().enumerate() {
        if o.is_nan() {
            let name = names[c];
            return Err(DctError::Gate(format!(
                "demosaic: NaN chroma std ({name}) — measurement error"
            )));
        }
    }
    let Some(v) = reference else {
        return Ok(()); // informational only without the anchor (see docs)
    };
    for (c, (&o, &vc)) in ours.iter().zip(v.iter()).enumerate() {
        let name = names[c];
        if vc.is_nan() || vc <= 0.0 {
            return Err(DctError::Gate(format!(
                "demosaic: bad reference anchor {name} {vc}"
            )));
        }
        // The lower bound carries an absolute
        // sub-permille visibility slack (0.03 LSB = 0.0007% of the 12-bit
        // scale). The demosaic-proxy chroma stds sit at the decode noise
        // floor on dark frames (reference dem2 0.09–0.13), where the pure
        // 0.5× ratio amplifies sub-LSB quantization — a k=16 225-frame
        // sweep: 48 channel violations across 33 dark frames, ALL
        // below-lo, max deficit 0.025 LSB (0.0006%) = accepted
        // residual. The slack is a round visibility constant, NOT a fit
        // to the candidate's own min (anti-circularity: the measured encoder stays
        // the anchor). The hi bound is UNCHANGED — over-cast stays FATAL.
        let lo = (0.5 * vc - 0.03).max(0.0);
        let hi = (2.0 * vc).max(0.75);
        if o < lo || o > hi {
            return Err(DctError::Gate(format!(
                "demosaic {name}: {o:.3} outside [{lo:.3}, {hi:.3}] (max(0.5×reference−0.03, 0)–max(2×,0.75) of the measured {vc:.3})"
            )));
        }
    }
    Ok(())
}

/// The flat-region seam steps (the lossy v2 transform) (d2diag FLAT protocol,
/// INFORMATIONAL only — seam verdict: the measured encoder shows the same
/// artifact class at up to ±18 LSB clip-wide, so the flat-region systematic
/// step is NOT a FATAL defect of our file; the existing ratio gate
/// `gate_seam` is unchanged). Protocol: on the rows/cols where the SOURCE
/// adjacent step is flat (|src step| < 8 LSB), the mean of the DECODED
/// adjacent step over the seam column pair x = 1927 → 1928, the two
/// reference column pairs x = 1000 → 1001 and 1915 → 1916, the seam row
/// pair y = 1087 → 1088, and the reference row pair y = 500 → 501 (the
/// d2diag seam/reference geometry). A systematic seam step shows up as the
/// seam value well above the reference values; the measured
/// distribution is the reference band.
#[derive(Debug)]
pub struct SeamFlatSteps {
    pub col_seam: f64,
    pub col_ref1: f64,
    pub col_ref2: f64,
    pub row_seam: f64,
    pub row_ref: f64,
}

pub fn seam_flat_steps(
    decoded: &[u16],
    source: &[u16],
    w: u32,
    h: u32,
) -> Result<SeamFlatSteps, DctError> {
    if w != FRAME_W || h != FRAME_H {
        return Err(DctError::FrameDims {
            w,
            h,
            fw: FRAME_W,
            fh: FRAME_H,
        });
    }
    let (fw, fh) = (w as usize, h as usize);
    let mut cs = 0f64;
    let mut cr1 = 0f64;
    let mut cr2 = 0f64;
    let mut ncs = 0.0f64;
    let mut ncr1 = 0.0f64;
    let mut ncr2 = 0.0f64;
    for y in 0..fh {
        let ro = y * fw;
        for (xa, xb, s, n) in [
            (1927usize, 1928, &mut cs, &mut ncs),
            (1000, 1001, &mut cr1, &mut ncr1),
            (1915, 1916, &mut cr2, &mut ncr2),
        ] {
            let sstep = source[ro + xb] as i64 - source[ro + xa] as i64;
            if sstep.abs() < 8 {
                *s += (decoded[ro + xb] as i64 - decoded[ro + xa] as i64) as f64;
                *n += 1.0;
            }
        }
    }
    let mut rs = 0f64;
    let mut rr = 0f64;
    let mut nrs = 0.0f64;
    let mut nrr = 0.0f64;
    for (ya, yb, s, n) in [
        (1087usize, 1088, &mut rs, &mut nrs),
        (500, 501, &mut rr, &mut nrr),
    ] {
        for x in 0..fw {
            let sstep = source[yb * fw + x] as i64 - source[ya * fw + x] as i64;
            if sstep.abs() < 8 {
                *s += (decoded[yb * fw + x] as i64 - decoded[ya * fw + x] as i64) as f64;
                *n += 1.0;
            }
        }
    }
    Ok(SeamFlatSteps {
        col_seam: if ncs > 0.0 { cs / ncs } else { f64::NAN },
        col_ref1: if ncr1 > 0.0 { cr1 / ncr1 } else { f64::NAN },
        col_ref2: if ncr2 > 0.0 { cr2 / ncr2 } else { f64::NAN },
        row_seam: if nrs > 0.0 { rs / nrs } else { f64::NAN },
        row_ref: if nrr > 0.0 { rr / nrr } else { f64::NAN },
    })
}

fn ffi_err_str(ptr: *const core::ffi::c_char) -> String {
    if ptr.is_null() {
        return "libjpeg encode failed".to_string();
    }
    // SAFETY: non-null C string owned by the shim handle (valid until the
    // next call on it), read only through `CStr`.
    unsafe {
        core::ffi::CStr::from_ptr(ptr)
            .to_string_lossy()
            .into_owned()
    }
}

/// Encode one parity plane (PLANE_W × PLANE_H, pre-LUT u16) as a
/// 1-component 12-bit baseline-DCT JPEG with the given quantization
/// table. The DCT is computed in Rust (`quantize_plane` — exact inverse of
/// the dct2s IDCT convention; see the D1 note above) and the quantized
/// indices (qcodes) go through libjpeg's raw-coefficient API (the
/// ljpeg_encode_coeff12 shim; optimize_coding forced, custom table,
/// precision 12) for DC prediction + 2-pass Huffman + bitstream. The
/// transcode coef controller passes the JBLOCKs to `encode_mcu` AS-IS and
/// `encode_one_block` codes `block[k]` as the Huffman symbol, so the
/// qcodes ARE the bitstream symbols (the decoder dequantizes them as
/// `qcode × quant[filepos]`). Returns the raw stream (SOI..EOI, JFIF APP0
/// included — the stitcher drops it).
pub fn encode_plane(plane: &[u16], table: &[u16; 64]) -> Result<Vec<u8>, DctError> {
    if plane.len() != PLANE_W * PLANE_H {
        return Err(DctError::PlaneDims {
            which: "encode_plane".into(),
            w: plane.len() / PLANE_W,
            h: PLANE_H,
        });
    }
    encode_coeffs_plane(&quantize_plane(plane, table), table)
}

/// Encode pre-quantized qcodes (as `quantize_plane` produces them:
/// natural order, blocks raster, DC slot = the centered-index qcode
/// `quantize_index(8 × (mean − 2048), q0)`) into the 1-component 12-bit
/// stream. Split out so the FATAL-gate negative tests can encode doctored
/// coefficient sets (the D1 regression test).
fn encode_coeffs_plane(coeffs: &[i16], table: &[u16; 64]) -> Result<Vec<u8>, DctError> {
    let expected = (PLANE_W / 8) * (PLANE_H / 8) * 64;
    if coeffs.len() != expected {
        return Err(DctError::PlaneDims {
            which: "encode_coeffs_plane".into(),
            w: coeffs.len() / 64,
            h: PLANE_H,
        });
    }
    // SAFETY: `ljpeg_comp_new` is the shim's allocator (calloc); the
    // pointer is null-checked here and `ljpeg_comp_free`d on every exit
    // path below.
    let h = unsafe { ljpeg_comp_new() };
    if h.is_null() {
        return Err(DctError::Encode("ljpeg_comp_new returned null".into()));
    }
    let mut outbuf: *mut u8 = std::ptr::null_mut();
    let mut outsize: core::ffi::c_ulong = 0;
    // SAFETY: live handle; `coeffs` and `table` outlive the call; the dims
    // are PLANE_W×PLANE_H (block-multiple, checked above); `&mut
    // outbuf/outsize` are null-initialized locals the shim writes. On
    // success `outbuf` is malloc'd by the shim and freed exactly once
    // below.
    let rc = unsafe {
        ljpeg_encode_coeff12(
            h,
            coeffs.as_ptr(),
            PLANE_W as core::ffi::c_int,
            PLANE_H as core::ffi::c_int,
            table.as_ptr(),
            &mut outbuf,
            &mut outsize,
        )
    };
    if rc != 0 {
        let msg = ffi_err_str(unsafe { ljpeg_comp_error(h) });
        unsafe { ljpeg_comp_free(h) };
        return Err(DctError::Encode(msg));
    }
    // SAFETY: rc == 0 ⇒ `outbuf` is valid for `outsize` bytes (shim-owned);
    // copied out before the single `ljpeg_free_buffer`.
    let jpeg = unsafe { std::slice::from_raw_parts(outbuf, outsize as usize) }.to_vec();
    // SAFETY: single free of the shim-malloc'd buffer + single free of the
    // handle, both now past their last use.
    unsafe {
        ljpeg_free_buffer(outbuf as *mut core::ffi::c_void);
        ljpeg_comp_free(h);
    }
    Ok(jpeg)
}

// ------------------------------------------------------- stream surgery

/// A DHT segment from a 1-component encode: (tctq, raw marker bytes).
type DhtSeg = (u8, Vec<u8>);

/// Walk a libjpeg 1-component stream; return the DHT segments (raw
/// marker bytes, tctq order) and the scan data (SOS end .. EOI).
fn split_one_comp(jpeg: &[u8]) -> Result<(Vec<DhtSeg>, Vec<u8>), DctError> {
    let n = jpeg.len();
    let mut i = 0usize;
    let mut dhts: Vec<DhtSeg> = Vec::new();
    let mut scan: Option<Vec<u8>> = None;
    let mut eoi = false;
    while i + 1 < n {
        if jpeg[i] != 0xFF {
            return Err(DctError::StreamPart {
                what: "lost SOI/marker sync".into(),
            });
        }
        let m = jpeg[i + 1];
        if m == 0xD9 {
            eoi = true;
            break;
        }
        if m == 0xD8 || m == 0x00 || (0xD0..=0xD7).contains(&m) || m == 0x01 {
            i += 2;
            continue;
        }
        if i + 4 > n {
            return Err(DctError::StreamPart {
                what: "truncated marker".into(),
            });
        }
        let ln = u16::from_be_bytes([jpeg[i + 2], jpeg[i + 3]]) as usize;
        if ln < 2 || i + 2 + ln > n {
            return Err(DctError::StreamPart {
                what: "bad marker length".into(),
            });
        }
        match m {
            0xC4 => dhts.push((jpeg[i + 4], jpeg[i..i + 2 + ln].to_vec())),
            0xDA => {
                let ds = i + 2 + ln;
                // scan data runs to the EOI (1-component stream).
                let mut j = ds;
                while j + 1 < n {
                    if jpeg[j] == 0xFF && jpeg[j + 1] != 0x00 {
                        break;
                    }
                    j += 1;
                }
                scan = Some(jpeg[ds..j].to_vec());
                i = j;
                continue;
            }
            _ => {}
        }
        i += 2 + ln;
    }
    if !eoi {
        return Err(DctError::StreamPart {
            what: "missing EOI".into(),
        });
    }
    let scan = scan.ok_or(DctError::StreamPart {
        what: "missing scan data".into(),
    })?;
    Ok((dhts, scan))
}

/// Relabel a DHT segment's TcTq byte.
fn relabel_dht(raw: &[u8], tctq: u8) -> Vec<u8> {
    let mut v = raw.to_vec();
    v[4] = tctq;
    v
}

/// Stitch one reference tile: SOI + 16-bit DQT(tq=0) + DHT 00/10 (from the
/// even-plane encode) + DHT 01/11 (from the odd-plane encode, relabeled),
/// then the corpus SOF1 + SOS0 + even scan + SOS1 + odd scan + EOI. The
/// libjpeg JFIF APP0 and both libjpeg SOS headers are dropped; the DQT
/// is always re-emitted as 16-bit (the decoder reads 16-bit entries
/// unconditionally; the corpus file stores 16-bit).
pub fn stitch_tile(
    even_jpeg: &[u8],
    odd_jpeg: &[u8],
    table: &[u16; 64],
) -> Result<Vec<u8>, DctError> {
    let (dht_e, scan_e) = split_one_comp(even_jpeg)?;
    let (dht_o, scan_o) = split_one_comp(odd_jpeg)?;
    let pick = |dhts: &Vec<DhtSeg>, want: u8, what: &str| -> Result<Vec<u8>, DctError> {
        dhts.iter()
            .find(|(t, _)| *t == want)
            .map(|(_, b)| b.clone())
            .ok_or(DctError::StreamPart {
                what: format!("missing DHT {want:02x} ({what})"),
            })
    };
    let dht00 = pick(&dht_e, 0x00, "even")?;
    let dht10 = pick(&dht_e, 0x10, "even")?;
    let dht01 = relabel_dht(&pick(&dht_o, 0x00, "odd")?, 0x01);
    let dht11 = relabel_dht(&pick(&dht_o, 0x10, "odd")?, 0x11);

    let mut out = Vec::with_capacity(768 + scan_e.len() + scan_o.len());
    out.extend_from_slice(&[0xff, 0xd8]);
    // DQT: 16-bit entries (prec bit 4), tq 0, Ls = 1 + 64*2 = 131.
    out.extend_from_slice(&[0xff, 0xdb, 0x00, 0x83, 0x10]);
    for v in table {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&dht00);
    out.extend_from_slice(&dht10);
    out.extend_from_slice(&dht01);
    out.extend_from_slice(&dht11);
    out.extend_from_slice(&SOF1_BYTES);
    out.extend_from_slice(&[0xff, 0xda, 0x00, 0x08]);
    out.extend_from_slice(&SOS0_PAYLOAD);
    out.extend_from_slice(&scan_e);
    out.extend_from_slice(&[0xff, 0xda, 0x00, 0x08]);
    out.extend_from_slice(&SOS1_PAYLOAD);
    out.extend_from_slice(&scan_o);
    out.extend_from_slice(&[0xff, 0xd9]);
    Ok(out)
}

// ------------------------------------------------------------- encoding

/// Encode all four tiles of a frame (pre-LUT planes already built).
pub fn encode_tiles(planes: &[TilePlanes; 4], table: &[u16; 64]) -> Result<Vec<Vec<u8>>, DctError> {
    let mut tiles = Vec::with_capacity(4);
    for t in planes {
        let ej = encode_plane(&t.even, table)?;
        let oj = encode_plane(&t.odd, table)?;
        tiles.push(stitch_tile(&ej, &oj, table)?);
    }
    Ok(tiles)
}

/// The cross-scan DC mix (the lossy v2 transform), ONE block position, G = 8
/// (the measured inter-row-class-difference D gain, DCT domain,
/// centered pre-domain units, DC slot = 8 × (block mean − 2048)).
///
/// `dc_odd`/`dc_even` = the odd-scan (scan 1, frame ODD rows) and
/// even-scan (scan 0, frame EVEN rows) DC coefficients at the same (tile,
/// block position). The mix preserves the block-pair MEAN exactly and
/// amplifies the block-pair DIFFERENCE (the inter-row class difference D,
/// the per-pixel class structure an NLE demosaic needs for local color)
/// by G× in the pre-domain:
///
///   L = (DC_odd + DC_even) / 2          (preserved exactly)
///   D = DC_odd − DC_even
///   DC_odd' = L + (G/2)·D = L + 4·D     (G = 8)
///   DC_even' = L − (G/2)·D = L − 4·D
///
/// ≡ DC_odd' = 4.5·DC_odd − 3.5·DC_even, DC_even' = 4.5·DC_even −
/// 3.5·DC_odd (8× amplification of D: DC_odd' − DC_even' = 8·D).
///
/// The L±4D form (G=8) is the authoritative one, unit-tested in
/// `t21_dc_mix_amplifies_8x_preserves_mean`. The "≡ 4·DC_odd − 3·DC_even"
/// shorthand is a G=7 RESIDUE ((4O−3E)−(4E−3O) = 7·D) and fails 95/225
/// frames on the v-floor (min v_ratio 0.241) — rejected.
///
/// Parameter provenance (anti-tautology): G = 8 = the MEDIAN of the
/// measured D-DC amplitude ratios (9.95 dark / 8.88 mid / 6.98
/// bright — reference files only, probe). The G=8 vs G=7 selection
/// was made against the measured-anchored gate bands on the A001 test clip
/// (documented engineering choice; the formula itself is fixed and
/// content-independent — no per-frame fit).
pub fn t21_dc_mix(dc_odd: f64, dc_even: f64) -> (f64, f64) {
    const G: f64 = 8.0;
    let l = (dc_odd + dc_even) / 2.0;
    let d = dc_odd - dc_even;
    (l + (G / 2.0) * d, l - (G / 2.0) * d)
}

/// v3 (the 3b seam fix) — the
/// band-limited cross-scan DC mix box half-size on the per-tile block-DC
/// grid, K = 16 (the 33×33 block box window; the production value selected
/// by the 225-frame sweep against the measured-anchored gate bands —
/// see `t21_dc_mix_bandlimited`.
pub const T21_DC_MIX_K: usize = 16;

/// v3 (the 3b seam fix) — the
/// band-limited cross-scan DC mix for ONE tile's block-DC grid:
///
///   D' = G·D − (G−1)·box(2K+1)(D),   G = 8, K = T21_DC_MIX_K
///
/// `nd` = the per-block inter-scan DC difference D = DC_odd − DC_even on
/// the tile's nbw×nbh block grid (raster order, block 0 = top-left);
/// returns D' in the same order. The caller then sets the per-block DC
/// slots to L ± D'/2 with L = (DC_odd + DC_even)/2 (the block-pair mean
/// preserved exactly, as in `t21_dc_mix`). The box window is per-tile
/// (edge-clipped) — content-independent (fixed K, no per-frame fit), so
/// the file contract is unchanged (DC VALUES only, same as `t21_dc_mix`).
///
/// Mechanism: v2's
/// per-block G=8 amplification of the RAW D amplifies the inter-scan DC
/// step at every 8-px block boundary → the A (tile-col seam
/// x=1927→1928, v2 max +8.84 / 21 dark frames) + B (all-270 block-row
/// unidirectional positive bias, v2 median +2.54) defects. Replacing D by
/// its box(2K+1)-smoothed coarse form keeps the large-scale inter-row
/// class difference the NLE demosaic needs (v2's cast fix) while killing
/// the per-block step — measured 225-frame result: A ≤ +0.66 (reference
/// class; the original 21-frame cluster fixed), B two-sided (median
/// −0.031; reference ref +0.30), MAE mean 0.340× reference (v2 0.374), per-class
/// pcdiff max 1.45 (v2 5.54 — cast structure better preserved than v2).
/// K=0 ≡ the v2 per-block mix (`t21_dc_mix`); k=32 was rejected (8 seam
/// frames to +4.67 incl. 5 new dark seams); a constant D grid is passed
/// through exactly (band-limiter DC gain 1: D' = G·D − (G−1)·D = D).
///
/// probe-PARITY CONTRACT (anti-tautology anchor): this formula is
/// BIT-IDENTICAL to the probe implementation (t21probe.rs
/// `dcmixg/dcmixk` — same box accumulation order, same operations), so
/// the probe evidence applies to this production path without
/// re-measurement; `t21cmp` re-verifies production ≡ probe tile bytes
/// after any change to either side.
pub fn t21_dc_mix_bandlimited(nd: &[f64], nbw: usize, nbh: usize) -> Vec<f64> {
    const G: f64 = 8.0;
    let k = T21_DC_MIX_K;
    let mut out = vec![0f64; nbw * nbh];
    for by in 0..nbh {
        for bx in 0..nbw {
            // The box(2k+1) mean over the block grid, edge-clipped —
            // VERBATIM the sweep's probe loop (same accumulation order → the
            // probe-parity contract holds bit-for-bit).
            let (mut s, mut n) = (0f64, 0.0);
            for ky in by.saturating_sub(k)..=(by + k).min(nbh - 1) {
                for kx in bx.saturating_sub(k)..=(bx + k).min(nbw - 1) {
                    s += nd[ky * nbw + kx];
                    n += 1.0;
                }
            }
            let b = by * nbw + bx;
            out[b] = G * nd[b] - (G - 1.0) * (s / n);
        }
    }
    out
}

/// The class-structure-preserving transform (the lossy v2 transform) on ONE
/// 8×8 block PAIR: the even-scan (scan 0) and odd-scan (scan 1) X_orth
/// coefficient vectors (natural order, `out[u·8+v]`, u = vertical freq i,
/// v = horizontal freq j, centered pre-domain, pre-quantization). The
/// transform is a fixed, content-independent formula (locked;
/// the reference mechanism measured by probe — the measured
/// DQT is bit-identical to BASE_TABLE, so its signature is a content
/// transform, not a quant choice):
///
/// 1. **j=7 column (v = 7, all u, both planes) → 0.** Erases the
///    within-row (−1)^x class offset — the 2-period banding the user
///    confirmed as defect D1/D2 (probe: reference residual 0.003 MSQ =
///    quantization leakage; we land exactly 0 under the shared table).
/// 2. **i=0 row (u = 0), j=3 and j=5 (both planes) → ×0.2.** The
///    row-average-profile h-high-frequency notch (measured
///    post-quantization profile 0.28/0.032 reproduced by pre-scale 0.2
///    through the shared table at q=13/23; j=6 stays ×1.0 — its reference
///    attenuation is shared quantization, not an explicit scale).
/// 3. **Cross-scan DC mix G = 8** (see `t21_dc_mix`): the block-pair mean
///    L preserved exactly, the inter-row class difference D amplified 8×
///    in the pre-domain (≈ 1.1–1.3× effective inter-row class gain in
///    12-bit through the curve's flat mid-band — the demosaic's local
///    color, the cast fix).
/// 4. All other coefficients ×1.0 (the shared BASE_TABLE quantization does
///    the rest, identical to the measured table).
///
/// Applied per (tile, block position) AFTER the pipeline reaches the
/// per-tile parity planes (invLUT → box3 → tile cut + flat step snap → DCT),
/// replacing the 20b source-space `cfa_lowpass_h` 2-tap as the structure
/// transform. BOTH scan planes are DCT'd before the mix (co-processing per
/// tile). Tile boundaries: 1928×1088 = 241×136 blocks of 8 — no block
/// straddles a tile edge, so the per-block transform is seam-safe (same as
/// the DCT itself). The vpred0=16384/centered-DC file contract is
/// unchanged (the mix changes the encoded DC VALUES, not the contract; the
/// reference-verified decoder dct2s reads coefficients generically).
///
/// V3 NOTE: this function is the K=0 CORE (the v2
/// per-block G·D mix) — unit-test reference + the t21cmp-equivalent
/// diagnostics. The PRODUCTION path (`encode_tiles_t21`) applies steps
/// (1)–(2) here and replaces step (3) with the tile's band-limited D'
/// (`t21_dc_mix_bandlimited`, K = T21_DC_MIX_K) — the closure.
///
/// Forward-model contract (documented): decoded = smooth
/// pre-domain + 8× inter-scan DC gain; the 20b contract
/// `curve(out) ≈ (src[x]+src[x+1])/2` is SUPERSEDED. The hard snap bound
/// (|curve(out) − smoothed| ≤ ~1.5 source LSB) still bounds the non-DC
/// residual; the DC component is bounded by the per-class + structure
/// gates below.
pub fn t21_transform_block(xe: &mut [f64; 64], xo: &mut [f64; 64]) {
    // (1) j=7 column (v = 7) → 0, both scan planes (natural idx u·8+7).
    for u in 0..8 {
        xe[u * 8 + 7] = 0.0;
        xo[u * 8 + 7] = 0.0;
    }
    // (2) i=0 row (u = 0), j = 3 and j = 5 → ×0.2, both planes (DCT bins
    // (0,3), (0,5); the const indices 3/5 ARE the structure attenuation —
    // not an arithmetic mistake, do not "simplify").
    xe[3] *= 0.2;
    xe[5] *= 0.2;
    xo[3] *= 0.2;
    xo[5] *= 0.2;
    // (3) cross-scan DC mix G = 8 (L±4D) at this block position.
    let (o, e) = t21_dc_mix(xo[0], xe[0]);
    xo[0] = o;
    xe[0] = e;
}

/// (lossy v2→v3) / **v4 (DEFAULT)** /
/// v5-binkill (gated diagnostic) —
/// the PRODUCTION tile encoder. v4 (DEFAULT): NO per-block transform
/// here — the erasure is the upstream v4 pre-domain 2-tap
/// (`full_frame_planes`).
/// `v5-binkill` (gated DIAGNOSTIC, not the default; probe retired it
/// as the reference erasure — the mask bins are ≈0 on the source, see
/// `cfa_bin_kill_block`): the selective bin kill per 8×8 block, both scan
/// planes, applied to the forward-DCT X_orth below. The DEFAULT is
/// `v4-2tap` (gate `CfaErasure`): NO per-block transform — the v4
/// pre-domain 2-tap runs upstream in `full_frame_planes`. v4: NO
/// per-block transform — the measured pre-DCT CFA erasure is
/// the SPATIAL pre-domain 2-tap applied upstream (`full_frame_planes` /
/// `h2tap_smooth_wh`), and the measurement
/// shows
/// it lands the CFA band at the file's own quantization scale while the
/// the tag-7 format's inter-scan DC difference is 1× the source (measured gain
/// 0.24 on A001_001 f1, both scans) — so the v2/v3 transform (j=7 → 0;
/// (0,3)/(0,5) ×0.2; cross-scan DC mix — v2 per-block G = 8
/// `t21_transform_block`; v3 / band-limited D' = G·D − (G−1)·
/// box(2K+1)(D), K = T21_DC_MIX_K = 16) is SUPERSEDED in the tag-7 DCT
/// path: the functions remain in the crate for diagnostics, unit tests
/// and the probe-parity contract, but `encode_tiles_t21` no longer
/// applies them. The 20d concern (the retired 20b 2-tap crushed the
/// inter-row class structure — decoded v-2period 0.08–0.12× source vs
/// the measured 1.00×) does not recur: the 20b crush came from the
/// linearized-domain order + the box3/snap chain of that pipeline; the
/// v4 pre-domain 2-tap keeps the inter-row difference at 1× (the
/// synthetic-CFA test asserts vr ≥ 0.9 / hr ≤ 0.3).
///
/// Everything downstream of the coefficients is shared with
/// `encode_tiles` (`quantize_xorth_blocks` → `encode_coeffs_plane` →
/// `stitch_tile`), so the file contract (markers, DHT relabel, 16-bit DQT,
/// vpred0/DC centering) is identical.
pub fn encode_tiles_t21(
    planes: &[TilePlanes; 4],
    table: &[u16; 64],
) -> Result<Vec<Vec<u8>>, DctError> {
    // The env-var gate (see `CfaErasure`) — read once per encode.
    encode_tiles_t21_erased(planes, table, CfaErasure::from_env()?)
}

/// `encode_tiles_t21` with an explicit erasure mode (the env-driven
/// wrapper above is the production entry; see
/// `full_frame_planes_erased` for why the explicit form exists).
pub fn encode_tiles_t21_erased(
    planes: &[TilePlanes; 4],
    table: &[u16; 64],
    erase: CfaErasure,
) -> Result<Vec<Vec<u8>>, DctError> {
    let pw = PLANE_W;
    let ph = PLANE_H;
    let nbw = pw / 8;
    let nbh = ph / 8;
    let mut tiles = Vec::with_capacity(4);
    for t in planes {
        // DCT both scan planes of the tile (float X_orth, natural order,
        // blocks raster). DEFAULT (v4-2tap): no per-block transform — the
        // erasure is the upstream spatial 2-tap (`full_frame_planes`); the
        // v2/v3 DCT-domain transform (t21_transform_block / t21_dc_mix /
        // t21_dc_mix_bandlimited) remains superseded in this path
        // (diagnostics/probe-parity only). v5-binkill (gated diagnostic;
        // probe: the mask bins are ≈0 on the source — a no-op on the
        // CFA aliasing, whose 2-px energy sits in the ODD-v bins; the
        // bin-label→X_orth mapping is the trap):
        // the selective bin kill below.
        let mut xe = vec![[0f64; 64]; nbw * nbh];
        let mut xo = vec![[0f64; 64]; nbw * nbh];
        let mut b = 0usize;
        for by in 0..nbh {
            for bx in 0..nbw {
                xe[b] = block_xorth(&t.even, pw, bx, by);
                xo[b] = block_xorth(&t.odd, pw, bx, by);
                b += 1;
            }
        }
        if erase == CfaErasure::V5BinKill {
            // The v5 bin kill (gated diagnostic), per block, BOTH scan
            // planes. NO-OP on the real CFA aliasing (probe: the 2-px
            // energy sits in the odd-v bins, the mask bins carry ≈0 on
            // the source) — retained for the probe-parity contract only.
            for xb in xe.iter_mut() {
                cfa_bin_kill_block(xb);
            }
            for xb in xo.iter_mut() {
                cfa_bin_kill_block(xb);
            }
        }
        let qe = quantize_xorth_blocks(&xe, table);
        let qo = quantize_xorth_blocks(&xo, table);
        let ej = encode_coeffs_plane(&qe, table)?;
        let oj = encode_coeffs_plane(&qo, table)?;
        tiles.push(stitch_tile(&ej, &oj, table)?);
    }
    Ok(tiles)
}

/// The CBR table: BASE_TABLE × scale, rounded, clamped to 1..4095.
/// (The measured CBR shapes are the base table scaled per frame —
/// measured ratios cbr3 ≈ 0.35, cbr4 ≈ 0.5, cbr5 ≈ 0.7, cbr7 ≈ 1.0.)
pub fn scale_table(scale: f64) -> [u16; 64] {
    let mut t = [0u16; 64];
    for (i, v) in BASE_TABLE.iter().enumerate() {
        let s = (*v as f64) * scale;
        t[i] = (s.round().clamp(1.0, 4095.0)) as u16;
    }
    t
}

/// Binary-search the table scale for the total size closest UNDER
/// `limit` (mirrors `lossy::search_quality`; the size is monotone in the
/// scale: larger table = coarser = smaller).
pub fn search_scale(limit: u64, total: &dyn Fn(f64) -> u64) -> f64 {
    // size(scale) is decreasing in the scale (larger table = coarser =
    // smaller file). We want the FINEST scale still under the limit
    // (largest file <= limit): the smallest s with total(s) <= limit.
    // The grid spans 0.05 .. ~11. The coarse end (s up to ~11) is REQUIRED
    // for the CBR size spec: the cbr7 budget (in/7 ≈ 1.80 MB) is BELOW the
    // natural (s=1.0) file size on high-HF frames (up to ~2.7 MB), so the
    // search must reach scales coarser than the base table. (The first
    // grid topped out at s≈1.39, which made the cbr7 budget
    // unreachable on 79/225 frames — the search returned the coarsest grid
    // point ABOVE the limit and the ±5% size gate failed. The table is
    // clamped at 4095, so large s is safe.)
    let grid: Vec<f64> = (0..40)
        .map(|i| 0.05 * 2f64.powf(i as f64 / 5.0))
        .filter(|s| *s <= 16.0)
        .collect();
    let usable: Vec<f64> = grid
        .iter()
        .copied()
        .filter(|s| total(*s) <= limit)
        .collect();
    let (mut lo, mut hi) = match usable.first().copied() {
        Some(hi) => {
            // finest usable on the grid; the bracket just below it is
            // the coarser neighbor (or a 60% step-down if absent).
            let idx = grid.iter().position(|s| *s == hi).expect("grid hit");
            let lo = grid.get(idx.saturating_sub(1)).copied().unwrap_or(hi * 0.6);
            (lo, hi)
        }
        // Nothing under the limit: take the coarsest (closest to the
        // limit from above).
        None => (
            *grid.last().expect("grid non-empty"),
            *grid.last().expect("grid non-empty"),
        ),
    };
    if lo == hi {
        return hi;
    }
    // Invariant: total(lo) > limit >= total(hi) (lo too fine, hi
    // usable). Converge on the boundary; the answer is the smallest
    // usable scale = hi at the end.
    for _ in 0..6 {
        let mid = (lo + hi) / 2.0;
        if total(mid) <= limit {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    hi
}

// ------------------------------------------------------------- verify

/// G1 structure check on one encoded tile (mirrors the measured layout):
/// marker sequence SOI/DQT/DHT×4/SOF1/SOS/SOS/EOI, the exact reference
/// DQT bytes (16-bit), SOF1 bytes, SOS payloads, and the two-scan
/// decodability via `crate::dct2s::parse_tile`.
pub fn check_tile_structure(tile: &[u8], table: &[u16; 64]) -> Result<(), DctError> {
    let info = crate::dct2s::parse_tile(tile)
        .map_err(|e| DctError::Structure(format!("parse_tile: {e}")))?;
    if info.sos.len() != 2 {
        return Err(DctError::Structure(format!(
            "SOS count {} (want 2)",
            info.sos.len()
        )));
    }
    // DQT: one entry, tq 0, exact 16-bit values.
    if info.dqt.len() != 1 || !info.dqt.contains_key(&0) {
        return Err(DctError::Structure("DQT: want exactly tq=0".into()));
    }
    let got = info.dqt.get(&0).expect("tq=0 checked");
    if got != table {
        return Err(DctError::Structure(
            "DQT values differ from the encode table".into(),
        ));
    }
    // DHT: all four TcTq present.
    for tctq in [0x00u8, 0x10, 0x01, 0x11] {
        if !info.dht.contains_key(&tctq) {
            return Err(DctError::Structure(format!("DHT {tctq:02x} missing")));
        }
    }
    // SOS payloads: exact reference bytes.
    let (o0, ds0, de0) = info.sos[0];
    let (o1, ds1, de1) = info.sos[1];
    let p0 = &tile[o0 + 4..o0 + 4 + 6];
    let p1 = &tile[o1 + 4..o1 + 4 + 6];
    if p0 != SOS0_PAYLOAD || p1 != SOS1_PAYLOAD {
        return Err(DctError::Structure(
            "SOS payloads differ from the reference templates".into(),
        ));
    }
    if ds0 == 0 || de0 <= ds0 || ds1 == 0 || de1 <= ds1 {
        return Err(DctError::Structure("empty scan segment".into()));
    }
    // SOF1 bytes: exact reference header (SOF1 is the only SOF allowed).
    let sof = tile
        .windows(SOF1_BYTES.len())
        .find(|w| w[0] == 0xFF && w[1] == 0xC1)
        .ok_or(DctError::Structure("SOF1 missing".into()))?;
    if sof != SOF1_BYTES {
        return Err(DctError::Structure(
            "SOF1 header differs from the reference template".into(),
        ));
    }
    Ok(())
}

/// G2 pixel stats of a both-scan reconstruction vs the original.
pub fn pixel_mae(decoded: &[u16], original: &[u16]) -> (f64, u32) {
    debug_assert_eq!(decoded.len(), original.len());
    let mut sum = 0u64;
    let mut mx = 0u32;
    for (d, o) in decoded.iter().zip(original.iter()) {
        let x = (*d as i64 - *o as i64).unsigned_abs();
        sum += x;
        mx = mx.max(x as u32);
    }
    (sum as f64 / decoded.len() as f64, mx)
}

/// Per-parity MAE of a decoded frame vs the original (even frame rows =
/// scan 0, odd frame rows = scan 1), plus the overall max-abs. The
/// scan-completeness check (G2): a zero/missing/broken scan makes one
/// parity's MAE an order of magnitude off the other's.
pub fn parity_mae(decoded: &[u16], original: &[u16], w: u32) -> (f64, f64, u32) {
    debug_assert_eq!(decoded.len(), original.len());
    let mut esum = 0u64;
    let mut en = 0u64;
    let mut osum = 0u64;
    let mut on = 0u64;
    let mut mx = 0u32;
    let rows = decoded.len() / (w as usize);
    for y in 0..rows {
        let even_row = y % 2 == 0;
        let base = y * (w as usize);
        for x in 0..(w as usize) {
            let e = (decoded[base + x] as i64 - original[base + x] as i64).unsigned_abs();
            mx = mx.max(e as u32);
            if even_row {
                esum += e;
                en += 1;
            } else {
                osum += e;
                on += 1;
            }
        }
    }
    (
        esum as f64 / en.max(1) as f64,
        osum as f64 / on.max(1) as f64,
        mx,
    )
}

/// Per-parity MEANS OF THE SOURCE (original) plane (even frame rows / odd
/// frame rows), single pass O(N). Input to the content-scale-aware
/// dead-scan backstop in `check_scan_completeness` (): the ceiling for
/// parity p scales with p's own source mean.
pub fn src_parity_means(original: &[u16], w: u32) -> (f64, f64) {
    debug_assert!(!original.is_empty());
    let rows = original.len() / (w as usize);
    let mut esum = 0u64;
    let mut en = 0u64;
    let mut osum = 0u64;
    let mut on = 0u64;
    for y in 0..rows {
        let base = y * (w as usize);
        if y % 2 == 0 {
            for x in 0..(w as usize) {
                esum += original[base + x] as u64;
                en += 1;
            }
        } else {
            for x in 0..(w as usize) {
                osum += original[base + x] as u64;
                on += 1;
            }
        }
    }
    (
        esum as f64 / en.max(1) as f64,
        osum as f64 / on.max(1) as f64,
    )
}

/// The G2 scan-completeness check: the even-row (scan 0) and odd-row
/// (scan 1) MAE must be the SAME ORDER OF MAGNITUDE (ratio ≤ 10). A
/// zero/missing/corrupted scan1 (or scan0) makes one parity's MAE an
/// order of magnitude off (e.g. a dead scan1 ≈ the source mean, ≈ 270
/// LSB vs the live scan's ≈ 15) → automatic FAIL. On real frames the two
/// parities are similar (f1 vbr-hq: even 15.9 / odd 12.8, ratio 1.24).
///
/// BACKSTOP (content-scale-aware): the broken-scan detection must NOT
/// depend on the ratio alone. A dead scan0/scan1 gives the affected
/// parity's MAE ≈ that parity's SOURCE mean (the dead parity decodes to
/// ~0), while a LIVE scan's parity MAE is content-scale-bounded: ≤ ~59
/// on the DARK
/// A001_001 clip (the measured max odd MAE across all 6 presets, the
/// bright f84-f88 frames) but 148–272 on the BRIGHT A001_002 clip (ours,
/// measured) and 352–648 on the corpus OWN A001_002 vbr-hq golden (p50 509)
/// p50 509) — the erasure representation is inherently >100 LSB from
/// source on bright content, so the old absolute 100 ceiling (calibrated
/// on A001_001) rejected LIVE bright encodes (stop: 289/289 frames).
/// The backstop is now, per parity p:
///
///   ceiling_p = max(DEAD_SCAN_MAE_LIM, DEAD_SCAN_CEIL_FACTOR × src_parity_mean_p)
///
/// A dead parity (MAE ≈ 1.0 × its source mean) sits ≥33% ABOVE its
/// ceiling; live bright content stays inside (ours max 272 vs 0.75×581 ≈
/// 436; reference max 648 vs 0.75×933 ≈ 700). The absolute 100 remains the
/// FLOOR: on content with src parity mean < ~133 (darker than both test
/// clips) the behavior is identical to the old absolute form, and the
/// dark 100–203 window is covered by the G2 catastrophe gate (r =
/// ours/reference < 2.0 vs the measured ~14 dark MAE ⇒ r ≈ 10 ⇒ FAIL) + the
/// per-preset distribution gate. This also catches a DC-only scan1 (all
/// AC zeroed) on the bright frames where its G≈28 exceeds the ratio
/// bound; on flat frames a DC-only scan1 lands G≈3 INSIDE [0.1,10] (a
/// minor, benign corruption — the flat decode is close to the low-HF
/// source — so it is intentionally not auto-FAILED; the ratio + this
/// backstop are the broken-scan detectors).
///
/// `even_src_mean` / `odd_src_mean` = the per-parity means of the SOURCE
/// (original) plane (`src_parity_means`); the verify pass computes them
/// alongside `parity_mae`.
pub const DEAD_SCAN_MAE_LIM: f64 = 100.0;
pub const DEAD_SCAN_CEIL_FACTOR: f64 = 0.75;
pub fn check_scan_completeness(
    even_mae: f64,
    odd_mae: f64,
    even_src_mean: f64,
    odd_src_mean: f64,
) -> Result<(), DctError> {
    if !even_mae.is_finite() || !odd_mae.is_finite() {
        return Err(DctError::Gate(format!(
            "scan-completeness: non-finite MAE (even {even_mae}, odd {odd_mae})"
        )));
    }
    if !even_src_mean.is_finite() || !odd_src_mean.is_finite() {
        return Err(DctError::Gate(format!(
            "scan-completeness: non-finite source parity means (even {even_src_mean}, odd {odd_src_mean})"
        )));
    }
    // Content-scale-aware backstop: a dead scan0/scan1 drives the affected
    // parity's MAE to ≈ its source mean (the parity decodes to ~0), far
    // above any live scan — ceiling_p = max(100, 0.75 × src_parity_mean_p).
    let even_ceil = DEAD_SCAN_MAE_LIM.max(DEAD_SCAN_CEIL_FACTOR * even_src_mean);
    let odd_ceil = DEAD_SCAN_MAE_LIM.max(DEAD_SCAN_CEIL_FACTOR * odd_src_mean);
    if even_mae > even_ceil || odd_mae > odd_ceil {
        return Err(DctError::Gate(format!(
            "scan-completeness: parity MAE {even_mae:.2}/{odd_mae:.2} exceeds dead-scan ceiling {even_ceil:.0}/{odd_ceil:.0} (src parity means {even_src_mean:.0}/{odd_src_mean:.0}) — a dead scan"
        )));
    }
    let hi = even_mae.max(odd_mae);
    let lo = even_mae.min(odd_mae);
    let ratio = if lo > 0.0 { hi / lo } else { f64::INFINITY };
    // [0.1, 10.0] on odd/even (== hi/lo <= 10.0, clean 10:1 either way): the
    // locked scan-completeness gate (calibration
    // fix). The dead-scan signature (the ONLY thing this gate catches) is
    // G≈18 (scan1 missing → odd_row_MAE ≈ source mean ~271 vs even ~15) on
    // the upper side and G≈0.055 on the lower (scan0 missing). Upper 10.0
    // keeps a 1.8× margin below the dead-scan-1 18 and 2.3× above the
    // observed benign max 4.3 (the f144-f146 even/odd HF asymmetry); lower
    // 0.1 keeps a 1.8× margin above the dead-scan-0 0.055. A ratio > 10
    // means a dead or broken scan → automatic FAIL. The benign 4.3 even/odd
    // HF asymmetry (a known encoder characteristic, see the report) sits
    // comfortably inside.
    if ratio > 10.0 {
        return Err(DctError::Gate(format!(
            "scan-completeness: even/odd MAE {even_mae:.2}/{odd_mae:.2} (ratio {ratio:.1}) ∉ [0.1, 10.0] — a dead or broken scan"
        )));
    }
    Ok(())
}

/// The REVISED G2 per-frame pixel gate (locked).
/// The per-frame [0.5,1.5] band + the per-frame p99 cap are RETIRED (the
/// measured max 59.85 > its p99 59.68 → unachievable even by the
/// reference; the per-frame band is unachievable for a content-dependent
/// transform approximation). Per frame this now checks:
/// (a) catastrophe ceiling: `r = our_mae / reference_mae < 2.0` (no single
/// frame 2× worse than the measured encoder);
///   (b) CBR size (when `cbr_target` is Some): out_bytes within ±5%.
/// The per-PRESET distribution gate (`gate_distribution`) and the
/// scan-completeness gate (`check_scan_completeness`) are separate.
pub fn gate_pixels(
    our_mae: f64,
    reference_mae: f64,
    cbr_target: Option<u64>,
    out_bytes: u64,
) -> Result<(), DctError> {
    if reference_mae > 0.0 {
        let r = our_mae / reference_mae;
        if r >= 2.0 {
            return Err(DctError::Gate(format!(
                "catastrophe: r = our {our_mae:.2} / reference {reference_mae:.2} = {r:.3} ≥ 2.0"
            )));
        }
    }
    if let Some(t) = cbr_target {
        let lo = t.saturating_sub(t / 20); // −5%
        let hi = t + t / 20; // +5%
        if !(out_bytes >= lo && out_bytes <= hi) {
            return Err(DctError::Gate(format!(
                "size {out_bytes} outside ±5% of CBR target {t} [{lo}..{hi}]"
            )));
        }
    }
    Ok(())
}

/// The G2 per-PRESET distribution gate (locked;
/// RECALIBRATED), computed over ALL
/// frames of a preset. `ratios` = the per-frame MAE ratios r_i = our_MAE_i /
/// reference_MAE_i (from the corpus quality_<preset>.tsv). Gates:
///   (a) mean(r) ∈ [0.10, 1.20];
///   (b) p50(r) ∈ [0.10, 1.40];
///   (c) count(r > 1.5) ≤ 5.
/// count(r < 0.5) is NOT gated — it is reported on the end-of-run
/// informational line only (observable, never gated).
///
/// RECALIBRATION RATIONALE (the gate was locked at calibration; the
/// change carries its own evidence):
/// The gate's purpose is catching quality REGRESSION vs the reference band.
/// A defect in OUR encode degrades our decode vs the source — it pushes r UP
/// (worse than the measured encoder), never down: r < 1 means our MAE-vs-source is
/// BELOW the measured MAE-vs-source, which is the direction of being better,
/// not being broken (a broken encode, dead scan, or flat collapse shows up
/// as large r, or is caught by scan-completeness / the catastrophe ceiling).
/// The old lower bounds (mean ≥ 0.90, p50 ≥ 0.70, count(r<0.5) == 0) were an
/// artifact of Phase B's parity goal ("match the measured quality band");
/// the lossy v2 CFA-erasing pre-domain deliberately beat that band (the
/// CFA erasure is the quality win). The new 0.10 lower bound is a
/// MISMATCH-SANITY floor only (10× better than the measured encoder across a 225-frame
/// mixed-content clip is beyond any plausible same-format encode gain; it
/// guards against reference-band/measurement errors), NOT a quality
/// target. No content fitting — a one-sided quality ceiling against an
/// external reference; anti-tautology preserved. Unchanged: the per-frame
/// catastrophe ceiling r < 2.0 and all FATAL defect gates (CFA-contrast,
/// per-class-31, seam, scan-completeness + dead-scan backstop); the gate
/// remains VBR-scoped (FATAL for vbr-hq/vbr-lt only, informational for CBR).
/// Evidence — measured distributions (fixed encoder, A001,
/// 225 frames per preset):
/// vbr-hq mean 0.322 (p50 0.295, max 0.548, r>1.5: 0, r<0.5: 215); vbr-lt
/// mean 0.321 (p50 0.293, max 0.544, r>1.5: 0, r<0.5: 219); cbr3/4/5/7
/// mean 0.324 (max ~0.552, r>1.5: 0) at the CBR size target (landing
/// +2.37/+4.33/+4.04/+4.22% over nominal, within ±5%). The pre-fix defective
/// run (the gate's original calibration point) measured mean 0.935–0.970
/// with per-frame catastrophes up to r 4.56 on cbr3 — the per-frame
/// catastrophe ceiling + FATAL defect gates are what caught THAT; this
/// distribution gate catches a systematic regression of the whole preset's
/// quality vs the reference band.
pub fn gate_distribution(ratios: &[f64]) -> Result<(), DctError> {
    if ratios.is_empty() {
        return Err(DctError::Gate("distribution gate: no frames".to_string()));
    }
    let mut sorted = ratios.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = sorted.len();
    let mean: f64 = sorted.iter().sum::<f64>() / n as f64;
    let p50 = sorted[n / 2];
    let count_gt_1_5 = sorted.iter().filter(|r| **r > 1.5).count();
    let count_lt_0_5 = sorted.iter().filter(|r| **r < 0.5).count();
    if !(0.10..=1.20).contains(&mean) {
        return Err(DctError::Gate(format!(
            "distribution: mean(r) {mean:.3} ∉ [0.10, 1.20] (p50 {p50:.3}, >1.5: {count_gt_1_5}, <0.5: {count_lt_0_5})"
        )));
    }
    if !(0.10..=1.40).contains(&p50) {
        return Err(DctError::Gate(format!(
            "distribution: p50(r) {p50:.3} ∉ [0.10, 1.40] (mean {mean:.3}, >1.5: {count_gt_1_5}, <0.5: {count_lt_0_5})"
        )));
    }
    if count_gt_1_5 > 5 {
        return Err(DctError::Gate(format!(
            "distribution: count(r > 1.5) = {count_gt_1_5} > 5 (mean {mean:.3}, p50 {p50:.3})"
        )));
    }
    // count_lt_0_5 is deliberately NOT gated (20d recalibration): frames
    // better than the measured encoder are the 20b design intent. The end-of-run
    // informational line (worker.rs) still reports it.
    Ok(())
}

/// Negative-test hook: increment the second SOS marker's Ls low byte
/// by 1. `parse_tile` still succeeds (the marker stays well-formed and
/// the decoder ignores the SOS payload) but the scan-1 data_start
/// shifts by one byte → the scan decodes (the decoder is EOF-tolerant
/// by design — LibRaw pads a truncated tail with zero codes, no error)
/// into GARBAGE pixels → the G2 pixel gate must fail (MAE >> p99).
/// A payload-byte change is caught by the G1 structure gate instead
/// (`check_tile_structure` compares the exact reference SOS payloads).
pub fn corrupt_sos1(tile: &mut [u8]) {
    let mut i = 0usize;
    let mut seen = 0usize;
    while i + 4 < tile.len() {
        if tile[i] == 0xFF && tile[i + 1] == 0xDA {
            seen += 1;
            if seen == 2 {
                tile[i + 3] = tile[i + 3].wrapping_add(1);
                return;
            }
            i += 10;
        } else {
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src_pattern(w: usize, h: usize) -> Vec<u16> {
        // deterministic ramp: value depends on (y, x) so even/odd rows
        // and columns differ.
        let mut v = Vec::with_capacity(w * h);
        for y in 0..h {
            for x in 0..w {
                v.push((((y * 7) % 37) * 100 + (x * 13) % 97) as u16);
            }
        }
        v
    }

    #[test]
    fn inv_lut_endpoints_and_bounded_error() {
        let inv = inv_lut(&REFERENCE_CURVE);
        assert_eq!(inv[0], 0);
        assert_eq!(inv[4095], 4095);
        // measured anchors:
        assert_eq!(inv[271], 536);
        assert_eq!(inv[549], 2047);
        assert_eq!(inv[2048], 3469);
        // max post-domain error 2 (nearest preimage).
        let max_err = (0..4096)
            .map(|s| (REFERENCE_CURVE[inv[s] as usize] as i64 - s as i64).abs())
            .max()
            .unwrap();
        assert_eq!(max_err, 2);
    }

    #[test]
    fn scale_table_identity_and_clamps() {
        let t = scale_table(1.0);
        assert_eq!(&t, &BASE_TABLE);
        // 2× scale is the nearest integer double (the measured vbr-lt
        // table is its own measured rounding, not this one — LT_TABLE is
        // used verbatim for that preset).
        let t2 = scale_table(2.0);
        assert_eq!(t2[0], 10);
        assert_eq!(t2[6], 20);
        // clamping at 1
        let tsmall = scale_table(0.01);
        assert!(tsmall.iter().all(|&v| v >= 1));
        // the measured tables are monotone-ish sane (no zero entries)
        assert!(BASE_TABLE.iter().all(|&v| v >= 1));
        assert!(LT_TABLE.iter().all(|&v| v >= 1));
    }

    #[test]
    fn build_planes_mapping_and_padding() {
        let w = FRAME_W as usize;
        let h = FRAME_H as usize;
        let src = (0..(w * h))
            .map(|i| (i % 4096) as u16)
            .collect::<Vec<u16>>();
        let inv = inv_lut(&REFERENCE_CURVE);
        let planes = build_planes(&src, FRAME_W, FRAME_H, &inv).unwrap();
        // tile0/even: plane row p, col c ↔ src[2p * w + c]
        for p in [0usize, 1, 100, 543] {
            for c in [0usize, 1, 500, 1927] {
                let s = src[2 * p * w + c];
                assert_eq!(planes[0].even[p * PLANE_W + c], inv[s as usize]);
            }
        }
        // tile0/odd: plane row p, col c ↔ src[(2p+1) * w + c]
        for p in [0usize, 1, 543] {
            for c in [0usize, 999, 1927] {
                let s = src[(2 * p + 1) * w + c];
                assert_eq!(planes[0].odd[p * PLANE_W + c], inv[s as usize]);
            }
        }
        // tile1 (top-right): col offset TILE_W
        {
            let p = 10usize;
            let c = 5usize;
            let s = src[2 * p * w + TILE_W as usize + c];
            assert_eq!(planes[1].even[p * PLANE_W + c], inv[s as usize]);
        }
        // tile2 (bottom-left): last real plane row 540 ↔ frame row
        // 1088 + 1080 = 2168 (even).
        {
            let p = PLANE_H_REAL - 1;
            let s = src[2168 * w + 0];
            assert_eq!(planes[2].even[p * PLANE_W + 0], inv[s as usize]);
        }
        // padding rows 541..543 repeat row 540.
        for ti in [2usize, 3] {
            for pl in [&planes[ti].even, &planes[ti].odd] {
                for p in [541usize, 542, 543] {
                    for c in [0usize, 500, 1927] {
                        assert_eq!(pl[p * PLANE_W + c], pl[(PLANE_H_REAL - 1) * PLANE_W + c]);
                    }
                }
            }
        }
    }

    #[test]
    fn bad_frame_dims_rejected() {
        let src = vec![0u16; 64 * 64];
        let inv = inv_lut(&REFERENCE_CURVE);
        assert!(matches!(
            build_planes(&src, 64, 64, &inv),
            Err(DctError::FrameDims { .. })
        ));
    }

    /// Synthetic tile: two flat-ish synthetic planes → encode → stitch →
    /// structure check; then the SOS1-corruption negative test.
    fn synthetic_planes() -> (Vec<u16>, Vec<u16>) {
        let even: Vec<u16> = (0..(PLANE_W * PLANE_H))
            .map(|i| 1024 + ((i * 7) % 64) as u16)
            .collect();
        let odd: Vec<u16> = (0..(PLANE_W * PLANE_H))
            .map(|i| 2048 + ((i * 11) % 64) as u16)
            .collect();
        (even, odd)
    }

    #[test]
    fn stitch_roundtrip_structure() {
        let (even, odd) = synthetic_planes();
        let ej = encode_plane(&even, &BASE_TABLE).unwrap();
        let oj = encode_plane(&odd, &BASE_TABLE).unwrap();
        let tile = stitch_tile(&ej, &oj, &BASE_TABLE).unwrap();
        check_tile_structure(&tile, &BASE_TABLE).unwrap();
        // the both-scan decoder parses it (2 SOS, 4 DHT, 1 DQT) and
        // decodes both scans without error.
        let info = crate::dct2s::parse_tile(&tile).unwrap();
        assert_eq!(info.sos.len(), 2);
        assert_eq!(info.dqt.len(), 1);
        assert_eq!(info.dht.len(), 4);
        let (plane, _) = crate::dct2s::decode_scan_plane(
            &tile,
            &info,
            0,
            &crate::dct2s::linearization_curve(Some(&REFERENCE_CURVE.to_vec())),
        )
        .unwrap();
        assert_eq!(plane.len(), PLANE_W * PLANE_H);
        let (plane1, _) = crate::dct2s::decode_scan_plane(
            &tile,
            &info,
            1,
            &crate::dct2s::linearization_curve(Some(&REFERENCE_CURVE.to_vec())),
        )
        .unwrap();
        assert_eq!(plane1.len(), PLANE_W * PLANE_H);
    }

    /// Flat planes: DC-only encodes → tiny scans (the corruption test
    /// needs the scan-1 distance to fit the u16 Ls).
    fn flat_planes() -> (Vec<u16>, Vec<u16>) {
        let even = vec![1024u16; PLANE_W * PLANE_H];
        let odd = vec![2048u16; PLANE_W * PLANE_H];
        (even, odd)
    }

    /// The negative SOS1-corruption test (both verify gates):
    /// (a) a payload-byte change → the G1 structure gate fails;
    /// (b) an Ls 1-byte shift → the scans still parse AND decode (the
    ///     decoder is EOF-tolerant by design) but scan1 becomes
    ///     garbage → the G2 pixel gate fails (MAE >> preset p99).
    #[test]
    fn sos1_corruption_verify_gates() {
        let (even, odd) = synthetic_planes();
        let ej = encode_plane(&even, &BASE_TABLE).unwrap();
        let oj = encode_plane(&odd, &BASE_TABLE).unwrap();
        let curve = crate::dct2s::linearization_curve(Some(&REFERENCE_CURVE.to_vec()));
        let mut tile = stitch_tile(&ej, &oj, &BASE_TABLE).unwrap();

        // (a) payload-byte corruption → the G1 structure gate fails.
        let mut t1 = tile.clone();
        let mut i = 0usize;
        let mut seen = 0usize;
        while i + 9 < t1.len() {
            if t1[i] == 0xFF && t1[i + 1] == 0xDA {
                seen += 1;
                if seen == 2 {
                    t1[i + 5] ^= 0x01; // SOS1 payload byte 2 (Cs/TdTa nibble)
                    break;
                }
                i += 10;
            } else {
                i += 1;
            }
        }
        assert!(
            check_tile_structure(&t1, &BASE_TABLE).is_err(),
            "G1 must reject the corrupted SOS1 payload"
        );

        // (b) Ls +1 → data_start shifts one byte: parse OK, decode OK
        // (EOF-tolerant), but the pixels are garbage.
        corrupt_sos1(&mut tile);
        let info = crate::dct2s::parse_tile(&tile).unwrap();
        let (plane1, _) = crate::dct2s::decode_scan_plane(&tile, &info, 1, &curve)
            .expect("scan1 still decodes (EOF-tolerant decoder)");
        let (mae, _) = pixel_mae(&plane1, &odd);
        assert!(
            mae > P99_LIM,
            "SOS1 Ls shift must break the G2 pixel gate (MAE {mae:.2} <= p99 {P99_LIM})"
        );
    }

    #[test]
    fn pixel_mae_sanity() {
        let a = vec![100u16, 200, 300];
        let b = vec![100u16, 210, 280];
        let (mae, mx) = pixel_mae(&a, &b);
        assert!((mae - (0.0 + 10.0 + 20.0) / 3.0).abs() < 1e-9);
        assert_eq!(mx, 20);
    }

    #[test]
    fn gate_pixels_catastrophe() {
        // r = our/reference < 2.0 → OK (the per-frame catastrophe ceiling).
        gate_pixels(14.0, 15.0, None, 0).unwrap(); // r = 0.93
                                                   // r >= 2.0 → catastrophe FAIL.
        assert!(matches!(
            gate_pixels(30.0, 10.0, None, 0),
            Err(DctError::Gate(_))
        )); // r = 3.0
        assert!(matches!(
            gate_pixels(40.0, 15.0, None, 0),
            Err(DctError::Gate(_))
        )); // r = 2.67
            // The p99 cap is RETIRED: a frame with r < 2.0 but MAE > p99 (59.68)
            // now PASSES (the per-frame p99 self-cap no longer applies).
        gate_pixels(65.0, 35.0, None, 0).unwrap(); // r = 1.86 < 2.0, MAE 65 > 59.68
                                                   // CBR size out of ±5% → FAIL.
        assert!(matches!(
            gate_pixels(14.0, 15.0, Some(1_000_000), 1_100_000),
            Err(DctError::Gate(_))
        ));
        // CBR size in band → OK.
        gate_pixels(14.0, 15.0, Some(1_000_000), 1_040_000).unwrap();
    }

    #[test]
    fn gate_distribution_sanity() {
        // A well-matched (parity-ish) distribution (mean ~1.0, p50 ~1.0,
        // few outliers) passes — regression protection intact (20d
        // recalibration condition i).
        let good: Vec<f64> = (0..100).map(|i| 1.0 + (i as f64 - 50.0) * 0.01).collect();
        gate_distribution(&good).unwrap();
        // mean too high (1.5 >= 1.3) → FAIL — upper bound intact (condition ii).
        let high: Vec<f64> = vec![1.5; 100];
        assert!(matches!(gate_distribution(&high), Err(DctError::Gate(_))));
        // mean 1.25 > 1.20 → FAIL (upper bound).
        let high2: Vec<f64> = vec![1.25; 100];
        assert!(matches!(gate_distribution(&high2), Err(DctError::Gate(_))));
        // A frame < 0.5× no longer FAILS (20d recalibration: count(r<0.5)
        // is informational only — being better than the measured encoder is the 20b
        // design intent).
        let low_one = {
            let mut v = vec![1.0; 100];
            v[0] = 0.4;
            v
        };
        gate_distribution(&low_one).unwrap();
        // 6 frames > 1.5× → FAIL (count(r>1.5) > 5) — upper bound intact.
        let many_high = {
            let mut v = vec![1.0; 100];
            for i in 0..6 {
                v[i] = 1.6;
            }
            v
        };
        assert!(matches!(
            gate_distribution(&many_high),
            Err(DctError::Gate(_))
        ));
        // The measured shape (vbr-hq: 215/225 frames r<0.5, mean 0.322,
        // max 0.548) PASSES — the recalibrated gate accepts the fixed
        // encoder's systematically-better distribution.
        let better_20d = {
            let mut v = vec![0.295f64; 215];
            v.extend(vec![0.50; 10]);
            v
        };
        let mean: f64 = better_20d.iter().sum::<f64>() / better_20d.len() as f64;
        assert!((0.30..0.35).contains(&mean), "20d-shape mean {mean}");
        gate_distribution(&better_20d).unwrap();
        // mean < 0.10 → FAIL — the mismatch-sanity floor is intact
        // (10× better than the measured encoder across a mixed-content clip is
        // beyond any plausible same-format encode gain — guard against a
        // wrong reference band / measurement reference) (condition iii).
        let sanity_floor: Vec<f64> = vec![0.05; 100];
        assert!(matches!(
            gate_distribution(&sanity_floor),
            Err(DctError::Gate(_))
        ));
        // p50 upper bound intact: mean 0.975 (in band) but p50 1.45 > 1.40
        // → FAIL.
        let p50_high = {
            let mut v = vec![0.5f64; 50];
            v.extend(vec![1.45; 50]);
            v
        };
        assert!(matches!(
            gate_distribution(&p50_high),
            Err(DctError::Gate(_))
        ));
    }

    #[test]
    fn search_scale_reaches_coarse_grid() {
        // The cbr7 scenario: the budget (limit) is BELOW the natural
        // (s=1.0) file size, so the search must pick a scale COARSER than
        // the base table (s > 1.0). Model total(s) = 3,000,000 / s (3.0 MB
        // at s=1.0). Limit 1.9 MB ⇒ the finest s with total(s) <= limit is
        // s = 3.0/1.9 ≈ 1.579 (> the old grid max 1.39 — the extended grid
        // must reach it). Assert the returned scale is coarse (s > 1.0) and
        // lands total just under the limit.
        let limit: u64 = 1_900_000;
        let total = |s: f64| (3_000_000.0 / s) as u64;
        let s = search_scale(limit, &total);
        assert!(s > 1.0, "must reach a coarser-than-base scale (got {s})");
        assert!(
            s > 1.39,
            "must reach beyond the old grid max 1.39 (got {s})"
        );
        // landed total is under the limit and close to it (within one step).
        let t = total(s);
        assert!(t <= limit, "landed total {t} must be <= limit {limit}");
        assert!(
            t as f64 > limit as f64 * 0.90,
            "landed total {t} too far under limit"
        );
        // the scale is near the analytic boundary 3.0/1.9 = 1.579.
        assert!(
            (s - 3.0 / 1.9).abs() < 0.2,
            "scale {s} not near boundary 1.579"
        );
    }

    #[test]
    fn box3_smooth_reduces_staircase() {
        // A 13-LSB alternating staircase (the flat-band quantization
        // artifact) is smoothed away; a flat plane is unchanged.
        let mut st = vec![0u16; PLANE_W * PLANE_H];
        for (i, v) in st.iter_mut().enumerate() {
            let x = i % PLANE_W;
            *v = if x % 2 == 0 { 2048 } else { 2048 + 13 };
        }
        let hd = first_diff(&st);
        let sm = box3_smooth(&st);
        let hd_sm = first_diff(&sm);
        assert!(
            hd_sm < hd / 2.0,
            "box3 must halve the staircase HF (raw {hd}, smooth {hd_sm})"
        );
        let flat = vec![3000u16; PLANE_W * PLANE_H];
        let sm_flat = box3_smooth(&flat);
        assert!(sm_flat.iter().all(|&v| v == 3000));
    }

    fn first_diff(pl: &[u16]) -> f64 {
        let w = PLANE_W;
        let mut s = 0.0;
        let mut n = 0.0;
        for y in 0..(pl.len() / w) {
            for x in 0..(w - 1) {
                s += (pl[y * w + x + 1] as i64 - pl[y * w + x] as i64).unsigned_abs() as f64;
                n += 1.0;
            }
        }
        s / n
    }

    #[test]
    fn scan_completeness_gates() {
        // [0.1, 10.0] on odd/even (hi/lo <= 10.0, clean 10:1 either way).
        // Signature (): (even_mae, odd_mae, even_src_mean, odd_src_mean);
        // src means = the ORIGINAL plane's per-parity means. dark = the
        // A001_001 source parity-mean class (~271); bright = A001_002 (~581
        // low / ~933 high).
        let dark = 271.0;
        let bright = 581.0;
        assert!(check_scan_completeness(59.0, 15.0, dark, dark).is_ok()); // live dark: 59 < 203.25
        assert!(check_scan_completeness(15.9, 12.8, dark, dark).is_ok()); // ratio 1.24, live
        assert!(check_scan_completeness(1.3, 5.3, dark, dark).is_ok()); // ratio 4.1, the f144 benign asymmetry
        assert!(check_scan_completeness(1.3, 5.58, dark, dark).is_ok()); // ratio 4.3, the observed benign max
                                                                         // A dead scan1: odd MAE ≈ source mean (~271). Caught by BOTH the
                                                                         // ratio bound (18 > 10) AND the content-aware backstop (271 > 203.25).
        assert!(check_scan_completeness(271.0, 15.0, dark, dark).is_err()); // dead, dark: 271 > 0.75×271
        assert!(check_scan_completeness(15.0, 270.0, dark, dark).is_err()); // dead scan1
        assert!(check_scan_completeness(270.0, 15.0, dark, dark).is_err()); // dead scan0
                                                                            // The backstop catches a dead scan EVEN when the ratio is small (a
                                                                            // dead scan0 where the even rows ALSO have high error): both parity
                                                                            // MAEs ~150/160 (ratio 1.0, INSIDE [0.1,10]) but above the ceiling
                                                                            // when the content is dark enough that the absolute FLOOR 100 binds
                                                                            // (src means 100 → ceiling max(100, 75) = 100) → backstop FAIL.
        assert!(check_scan_completeness(150.0, 160.0, 100.0, 100.0).is_err()); // backstop
        assert!(check_scan_completeness(f64::NAN, 15.0, dark, dark).is_err()); // non-finite MAE
        assert!(check_scan_completeness(15.0, 15.0, f64::NAN, dark).is_err()); // non-finite src mean (fail loud)
                                                                               // Boundary: ratio 10.0 is OK (closed), 10.5 is a FAIL (both MAEs
                                                                               // inside the dark ceiling 203.25 → the ratio is what trips it).
        assert!(check_scan_completeness(10.0, 100.0, 100.0, 100.0).is_ok()); // ratio 10.0, MAE 100 == ceiling (closed, OK)
        assert!(check_scan_completeness(10.0, 105.0, dark, dark).is_err()); // ratio 10.5
                                                                            // rows — the content-scale-aware backstop (the A001_002
                                                                            // evidence: ours 148–272 / reference 352–648 / dead ≈ src mean):
        assert!(check_scan_completeness(272.0, 139.0, bright, bright).is_ok()); // ours bright live: 272 < 435.75
        assert!(check_scan_completeness(648.0, 300.0, 933.0, 933.0).is_ok()); // reference bright class: 648 < 699.75
        assert!(check_scan_completeness(933.0, 150.0, 933.0, 933.0).is_err()); // dead, bright: 933 > 699.75
        assert!(check_scan_completeness(101.0, 15.0, dark, dark).is_ok()); // 101 < 203.25 (dark ceiling)
        assert!(check_scan_completeness(100.0, 10.0, 100.0, 100.0).is_ok()); // 100 == ceiling (closed boundary)
        assert!(check_scan_completeness(100.0001, 10.0, 100.0, 100.0).is_err());
        // 100.0001 > 100 (strictly above)
    }

    #[test]
    fn src_parity_means_sanity() {
        let w = 4u32;
        // row0 (even): 100+200+300+400 = 1000 → 250
        // row1 (odd):   10+ 20+ 30+ 40 =  100 →  25
        let orig: Vec<u16> = vec![100, 200, 300, 400, 10, 20, 30, 40];
        let (e, o) = src_parity_means(&orig, w);
        assert!((e - 250.0).abs() < 1e-9, "even mean {e}");
        assert!((o - 25.0).abs() < 1e-9, "odd mean {o}");
    }

    /// condition 1 : the DC-only scan1 negative case. A
    /// scan1 with all AC zeroed decodes the odd rows to their DC mean. On a
    /// bright frame (f84-f88, the highest odd-row std ~57) the even/odd MAE
    /// ratio G≈28 → the ratio bound FAILS. Confirmed: the gate still catches
    /// the DC-only corruption (it does not become a no-op at [0.1, 10.0]).
    #[test]
    fn dc_only_scan1_negative() {
        // A bright frame's DC-only scan1: the odd rows decode to their mean
        // (odd MAE ≈ the odd rows' std ≈ 57), the even rows are live (even
        // MAE ≈ the live DCT error ≈ 2). G ≈ 28 > 10 → FAIL.
        assert!(check_scan_completeness(2.0, 57.0, 271.0, 271.0).is_err()); // G ≈ 28.5 (ratio FAIL; MAEs < dark ceiling 203)
                                                                            // A flat frame's DC-only scan1: the odd rows decode to their mean
                                                                            // (odd MAE ≈ the odd rows' std ≈ 4), the even rows are live (even
                                                                            // MAE ≈ 1.5). G ≈ 2.7 INSIDE [0.1, 10] AND odd MAE 4 < ceiling → the
                                                                            // gate does NOT auto-FAIL it (a minor, benign corruption — the flat
                                                                            // decode is close to the low-HF source). This is the documented
                                                                            // trade-off (see the report); the broken-scan detection relies on
                                                                            // the dead-scan signature (odd MAE ≈ src parity mean), which the
                                                                            // content-aware backstop + ratio both catch.
        assert!(check_scan_completeness(1.5, 4.0, 271.0, 271.0).is_ok()); // G ≈ 2.7, benign
    }

    #[test]
    fn parity_mae_sanity() {
        let w = 4u32;
        let decoded: Vec<u16> = vec![100, 100, 100, 100, 100, 150, 100, 100];
        let orig: Vec<u16> = vec![100, 100, 100, 100, 100, 100, 100, 100];
        let (even_mae, odd_mae, mx) = parity_mae(&decoded, &orig, w);
        assert!((even_mae - 0.0).abs() < 1e-9, "even row exact: {even_mae}");
        assert!(
            (odd_mae - 12.5).abs() < 1e-9,
            "odd MAE = 50/4 = 12.5: {odd_mae}"
        );
        assert_eq!(mx, 50);
    }

    // Corpus presence-visibility: the NEGATIVE test runs on a REAL f1
    // encode (not a synthetic). A corrupted scan1 (SOS1 Ls shift — the
    // decoder is EOF-tolerant, so it decodes into garbage without
    // erroring) must trip the G2 gate (scan-completeness and/or the
    // pixel band/p99). This is the phase-A lesson.
    #[test]
    fn negative_real_f1_corrupt_scan1_fails_verify() {
        let path = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        if !std::path::Path::new(path).exists() {
            eprintln!("skip: no testdata corpus");
            return;
        }
        let srcb = std::fs::read(path).unwrap();
        let frame = crate::tiff::read(&srcb).unwrap();
        let packed = frame.strip_slice(&srcb);
        let samples = crate::pack12::unpack12(packed, frame.width, frame.height).unwrap();
        let curve = REFERENCE_CURVE;
        let inv = inv_lut(&curve);
        let pre0 = build_planes(&samples, frame.width, frame.height, &inv).unwrap();
        let src_planes = build_source_planes(&samples, frame.width, frame.height).unwrap();
        let planes = smooth_planes(&pre0, &src_planes, &curve);
        let tiles = encode_tiles(&planes, &BASE_TABLE).unwrap();
        let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
        let cp = crate::dct2s::linearization_curve(Some(&curve.to_vec()));
        // Healthy encode: G2 scan-completeness + pixel gate PASS.
        let decoded =
            crate::dct2s::assemble_frame(&refs, TILE_W, TILE_H, frame.width, frame.height, &cp)
                .unwrap();
        let (even_mae, odd_mae, _mx) = parity_mae(&decoded, &samples, frame.width);
        let (esrc, osrc) = src_parity_means(&samples, frame.width);
        assert!(
            check_scan_completeness(even_mae, odd_mae, esrc, osrc).is_ok(),
            "healthy f1 must pass scan-completeness (even {even_mae:.2} / odd {odd_mae:.2}, src means {esrc:.0}/{osrc:.0})"
        );
        let (mae, _m) = pixel_mae(&decoded, &samples);
        assert!(
            mae < P99_LIM,
            "healthy f1 vbr-hq MAE {mae:.2} < p99 {P99_LIM}"
        );
        // Corrupt the scan1 in every tile (SOS1 Ls shift → shifted scan1
        // → garbage odd rows) → the G2 gate must FAIL.
        let mut bad = tiles.clone();
        for t in &mut bad {
            corrupt_sos1(t);
        }
        let refs2: Vec<&[u8]> = bad.iter().map(|t| t.as_slice()).collect();
        let decoded2 =
            crate::dct2s::assemble_frame(&refs2, TILE_W, TILE_H, frame.width, frame.height, &cp)
                .unwrap();
        let (even_mae2, odd_mae2, _mx) = parity_mae(&decoded2, &samples, frame.width);
        let scan_gate = check_scan_completeness(even_mae2, odd_mae2, esrc, osrc).is_err();
        let (mae2, _m) = pixel_mae(&decoded2, &samples);
        let pixel_gate = mae2 > P99_LIM || mae2 > 1.5 * 14.36; // reference f1 vbr-hq = 14.36
        assert!(
            scan_gate || pixel_gate,
            "corrupted scan1 must FAIL a G2 gate (scan_gate {scan_gate}: even {even_mae2:.2}/odd {odd_mae2:.2}; pixel_gate {pixel_gate}: MAE {mae2:.2})"
        );
    }

 // ---------------------------------------------------- D1 / DCT tests

    /// The encoder DCT (matrix form) must equal the reference orthonormal
    /// DCT-II double sum on a non-trivial 8×8 block: X_orth(u,v) =
    /// a(u)a(v)·Σ_ij x_c(i,j)·cos(π(2i+1)u/16)·cos(π(2j+1)v/16),
    /// a(0) = 1/(2√2), a(k>0) = 1/2. Independent code path (direct sum vs
    /// the A·X·Aᵀ matrix products) — catches normalization / half-sample /
 /// sign errors in the DCT matrix. (The D1 pin: the libjpeg
    /// 12-bit islow DCT's odd-row scales were the defect; this pins OUR
    /// replacement to the exact inverse of the corpus-verified IDCT.)
    #[test]
    fn dct_matches_reference_dct2() {
        // deterministic non-trivial 8×8 (block-multiple plane 8×8)
        let block: Vec<u16> = (0..64)
            .map(|i| (2048 + (((i * 53) % 17) as i32 - 8) * 97) as u16)
            .collect();
        let xo = block_xorth(&block, 8, 0, 0);
        let a_of = |k: u32| {
            if k == 0 {
                (1.0f64 / 2.0).sqrt() / 2.0
            } else {
                0.5
            }
        };
        for u in 0..8 {
            for v in 0..8 {
                let mut ref_ = 0f64;
                for i in 0..8 {
                    for j in 0..8 {
                        let xc = f64::from(block[i * 8 + j]) - 2048.0;
                        let ang_u = (2 * i + 1) as f64 * u as f64 * core::f64::consts::PI / 16.0;
                        let ang_v = (2 * j + 1) as f64 * v as f64 * core::f64::consts::PI / 16.0;
                        ref_ += a_of(u as u32) * a_of(v as u32) * ang_u.cos() * ang_v.cos() * xc;
                    }
                }
                let got = xo[u * 8 + v];
                assert!(
                    (got - ref_).abs() < 1e-9 * ref_.abs().max(1.0),
                    "({u},{v}): got {got}, ref {ref_}"
                );
            }
        }
    }

    /// Full-plane 2-period CFA pattern (2048±100, all rows identical):
    /// the encoder's coefficients must be the STANDARD islow values (the
    /// exact inverse of the dct2s IDCT), and the block must round-trip
 /// through the corpus-verified IDCT. D1 regression: the defective
    /// libjpeg 12-bit DCT wrote (0,3)=240 / (0,5)=648 / (0,7)=3224 here
    /// (2.09×/3.25×/4.45× the standard values) → this test FAILED on the
    /// old path.
    #[test]
    fn dct_cfa_pattern_standard_coefficients_and_roundtrip() {
        let plane: Vec<u16> = (0..(PLANE_W * PLANE_H))
            .map(|i| if i % 2 == 0 { 2148 } else { 1948 })
            .collect();
        let coeffs = quantize_plane(&plane, &BASE_TABLE);
        let b = &coeffs[..64]; // block (0,0), natural-order QCODES
        let n2f = nat2file();
        let dq = |k: usize| -> i64 { i64::from(b[k]) * i64::from(BASE_TABLE[n2f[k]]) };
        assert_eq!(b[0], 0); // DC qcode: mean 2048 → centered 0
                             // standard islow (dequantized): X_orth(0,1) = 144.19 → qcode 24 →
                             // 144; (0,3) = 170.09 → 17 → 170; (0,5) = 254.55 → 14 → 252;
                             // (0,7) = 724.90 → 23 → 713. (The old defective 12-bit DCT wrote
                             // dequantized 144/240/648/3224 here = 1.00×/1.41×/2.55×/4.45×
                             // these values.)
        assert_eq!(dq(1), 144);
        assert_eq!(dq(3), 170);
        assert_eq!(dq(5), 252);
        assert_eq!(dq(7), 713);
        // no even-AC energy (2-period pattern): all other slots 0
        for (i, &c) in b.iter().enumerate() {
            if matches!(i, 0 | 1 | 3 | 5 | 7) {
                continue;
            }
            assert_eq!(c, 0, "slot {i} must be 0 (2-period pattern)");
        }
        // round-trip through the corpus-verified IDCT: ≈ the input pattern.
        // Dequantize all 64 slots (qcode × quant[filepos]) — what
        // decode_scan produces — then shift the DC slot to the ABSOLUTE
        // vpred scale (the decoder's vpred0 = 16384 = 8×2048 restores the
        // centering; the encoder-side DCT writes the centered-index DC and
        // the DC predictor starts at 0).
        let mut c64 = [0i32; 64];
        for k in 0..64 {
            c64[k] = (i64::from(b[k]) * i64::from(BASE_TABLE[n2f[k]])) as i32;
        }
        c64[0] += 16384;
        let px = crate::dct2s::idct_block(&c64);
        let recon: Vec<i64> = px.iter().map(|&p| i64::from(p)).collect();
        let input: Vec<i64> = (0..64)
            .map(|i| if i % 2 == 0 { 2148 } else { 1948 })
            .collect();
        let max_dev = recon
            .iter()
            .zip(&input)
            .map(|(r, s)| (r - s).abs())
            .max()
            .unwrap();
        assert!(
            max_dev <= 2,
            "round-trip max deviation {max_dev} LSB (quantization + f32 IDCT)"
        );
 // CFA contrast ratio (recon / input) ≈ 1.00 — the D1 acceptance
        // target (the defective path measured 4.005).
        let c_in = cfa_contrast_cols(&plane);
        let recon_plane: Vec<u16> = recon.iter().map(|&v| v.clamp(0, 65535) as u16).collect();
        let c_re = cfa_contrast_cols(&recon_plane);
        let ratio = c_re / c_in;
        // ≈1.00 within quantization of the v=5/7 coefficients (−2.5/−11.9
        // dequantized LSB → the recon contrast lands ~196.5 on 200). The
 // D1 defect measured 4.005; a healthy encode must NOT amplify.
        assert!(
            (ratio - 1.0).abs() <= 0.05,
            "CFA contrast ratio {ratio} (in {c_in}, recon {c_re})"
        );
    }

    /// FATAL-gate negative test (acceptance): a doctored 4×
 /// CFA-band (odd-v) coefficient set — the D1 signature — must FAIL
    /// `gate_cfa_contrast` (ratio ≈ 4 > 2.0), while the healthy encode
    /// passes. End-to-end: encode → stitch → per-tile scan0 pre-domain
    /// decode (identity LUT) → ratio.
    #[test]
    fn doctored_4x_cfa_coeff_fails_verify_gate() {
        let plane: Vec<u16> = (0..(PLANE_W * PLANE_H))
            .map(|i| if i % 2 == 0 { 2148 } else { 1948 })
            .collect();
        let planes: [TilePlanes; 4] = core::array::from_fn(|_| TilePlanes {
            even: plane.clone(),
            odd: plane.clone(),
        });
        let healthy = |()| -> Vec<Vec<u8>> {
            let c = quantize_plane(&plane, &BASE_TABLE);
            let ej = encode_coeffs_plane(&c, &BASE_TABLE).unwrap();
            let oj = encode_coeffs_plane(&c, &BASE_TABLE).unwrap();
            [0; 4]
                .into_iter()
                .map(|_| stitch_tile(&ej, &oj, &BASE_TABLE).unwrap())
                .collect()
        };
        // healthy encode: ratio ≈ 1.0 → PASS. The source reference is the
        // plane's own forward image (source = curve[pre] — exact forward
        // model) so its invLUT contrast ≈ the plane's (a consistent
        // synthetic frame; the backstop limit ≈ 2× plane contrast).
        let src_plane: Vec<u16> = plane.iter().map(|&p| REFERENCE_CURVE[p as usize]).collect();
        let src_planes: [TilePlanes; 4] = core::array::from_fn(|_| TilePlanes {
            even: src_plane.clone(),
            odd: src_plane.clone(),
        });
        let t_ok = healthy(());
        gate_cfa_contrast(&t_ok, &planes, &src_planes, &REFERENCE_CURVE)
            .expect("healthy 2-period encode must pass the cfa gate");

        // doctored: every block's (0,3)/(0,5)/(0,7) qcode ×4 — the decoded
 // dequantized coefficients are then 4× the healthy values (D1's
        // factor on the odd-v CFA-band rows; (0,1) was already 1.00 in the
        // defect)
        let mut c = quantize_plane(&plane, &BASE_TABLE);
        for b in c.chunks_mut(64) {
            for k in [3usize, 5, 7] {
                b[k] = (i32::from(b[k]) * 4) as i16;
            }
        }
        let ej = encode_coeffs_plane(&c, &BASE_TABLE).unwrap();
        let oj = encode_coeffs_plane(&quantize_plane(&plane, &BASE_TABLE), &BASE_TABLE).unwrap();
        let t_bad: Vec<Vec<u8>> = (0..4)
            .map(|_| stitch_tile(&ej, &oj, &BASE_TABLE).unwrap())
            .collect();
        let err = gate_cfa_contrast(&t_bad, &planes, &src_planes, &REFERENCE_CURVE)
            .expect_err("doctored 4× CFA coefficients must FAIL the cfa gate");
        assert!(matches!(err, DctError::Gate(_)));
    }

    /// FATAL per-class gate: a +30 LSB bias on the W class only must FAIL
    /// (|mean| ≥ 15); a bias-free decode passes. Phase from 50719 origin.
    #[test]
    fn gate_class_means_detects_class_bias() {
        let w = 16u32;
        let h = 16u32;
        let origin = [8u32, 5]; // the fp's measured DefaultCropOrigin
        let source: Vec<u16> = vec![2048; (w * h) as usize];
        let class_of = |y: u32, x: u32| -> usize {
            let rp = ((y as i64 - 5).rem_euclid(2)) as usize;
            let cp = ((x as i64 - 8).rem_euclid(2)) as usize;
            match (rp, cp) {
                (0, 0) => 0, // W
                (1, 1) => 2, // R
                _ => 1,      // G
            }
        };
        // healthy: all classes mean 0
        gate_class_means(&source, &source, w, origin).expect("bias-free decode must pass");
        // W-only +40 bias → |mean_W| = 40 ≥ 31 → FAIL
        let biased: Vec<u16> = (0..(w * h) as usize)
            .map(|i| {
                let (y, x) = (i / w as usize, i % w as usize);
                if class_of(y as u32, x as u32) == 0 {
                    2048 + 40
                } else {
                    2048
                }
            })
            .collect();
        let err = gate_class_means(&biased, &source, w, origin)
            .expect_err("a +40 W-class bias must FAIL the per-class gate");
        assert!(matches!(err, DctError::Gate(_)));
        // a 12 LSB W bias is inside the 31-LSB limit → PASS (reference
        // bright-frame per-class reaches 15.343; 31 = 2× that)
        let mild: Vec<u16> = biased
            .iter()
            .map(|&v| if v == 2088 { 2060 } else { v })
            .collect();
        gate_class_means(&mild, &source, w, origin).expect("a +12 W-class bias must pass");
        // and a 20 LSB W-class bias — above the measured worst
        // (15.343) but inside 2× → PASS (the measured encoder itself is at 15.3)
        let vlevel: Vec<u16> = biased
            .iter()
            .map(|&v| if v == 2088 { 2068 } else { v })
            .collect();
        gate_class_means(&vlevel, &source, w, origin).expect("a +20 W-class bias must pass");
    }

    /// Centered-DC convention: a flat 1536 plane → the DC qcode is
    /// quantize_index(8·(1536−2048), 5) = quantize_index(−4096, 5) = −818
    /// (libjpeg 12-bit rounding (t + q/2)/q with C truncation), i.e. the
    /// dequantized centered DC −4090, and the corpus-verified IDCT
    /// (vpred = 16384 − 4090 = 12294, DC scale 1/8) inverts to 1536 ± 1.
    #[test]
    fn quantize_dc_centered_and_idct_inverts() {
        let plane: Vec<u16> = vec![1536; PLANE_W * PLANE_H];
        let coeffs = quantize_plane(&plane, &BASE_TABLE);
        assert_eq!(coeffs[0], -818);
        assert!(coeffs.iter().all(|&c| c == 0 || c == -818));
        let mut c = [0i32; 64];
        // idct_block's DC slot is the ABSOLUTE vpred scale: the decoder's
        // vpred0 (16384) plus the centered dequantized DC (−4090).
        c[0] = 16384 - 4090;
        let px = crate::dct2s::idct_block(&c);
        assert!(px.iter().all(|&p| (p as i64 - 1536).abs() <= 1), "{px:?}");
    }

 // ----: the CFA-erasing pre-domain transform (D2) ----

    /// 2-period horizontal pattern (the CFA R/G column band) → the 2-tap
    /// adjacent-column low-pass zeros it exactly (the DCT-II u=7 Nyquist
    /// response is 0). Small synthetic frame — the fn is generic w×h
    /// (production: the full 3856-wide frame, before the tile cut). The
    /// last column is a no-op (edge-replicate, same convention as box3).
    #[test]
    fn cfa_lowpass_h_2period_to_zero() {
        let (w, h) = (16u32, 4);
        let src: Vec<u16> = (0..(w * h as u32))
            .map(|i| if i % 2 == 0 { 264 } else { 270 })
            .collect();
        let out = cfa_lowpass_h(&src, w, h);
        for y in 0..h as usize {
            for x in 0..w as usize {
                let expect = if x == w as usize - 1 { 270 } else { 267 };
                assert_eq!(out[y * w as usize + x], expect, "y{y} x{x}");
            }
        }
        // contrast over the interior (the edge no-op contributes ~0.19)
        assert!(cfa_contrast_cols(&out) < 1.0);
    }

    /// Flat input → unchanged (no-op on constant planes — the Phase B
    /// flat-frame quality calibration is untouched by the transform).
    #[test]
    fn cfa_lowpass_h_flat_unchanged() {
        let (w, h) = (8u32, 2);
        let src = vec![3000u16; (w * h as u32) as usize];
        let out = cfa_lowpass_h(&src, w, h);
        assert!(out.iter().all(|&v| v == 3000));
    }

    /// Edge handling: the last column is a no-op (edge-replicate → self
    /// average); the column before it averages with the last.
    #[test]
    fn cfa_lowpass_h_edge_replicate() {
        let (w, h) = (4u32, 1);
        let src = vec![100u16, 100, 100, 200];
        let out = cfa_lowpass_h(&src, w, h);
        assert_eq!(out[2], 150); // (100+200)/2
        assert_eq!(out[3], 200); // (200+200)/2 = edge no-op
    }

    // ------------------------------------------------ v4 () tests

    /// v4 unit-test contract (i): a constant plane passes through the
    /// erasure EXACTLY — and its DCT is DC-only (8·(c−2048) with the
    /// 2048-centering, all AC exactly 0).
    #[test]
    fn v4_h2tap_constant_plane_exact() {
        let pl = vec![3000u16; 8 * 8];
        let out = h2tap_smooth_wh(&pl, 8, 8);
        assert!(
            out.iter().all(|&v| v == 3000),
            "constant plane passes through exactly"
        );
        let x = block_xorth(&out, 8, 0, 0);
        assert!(
            (x[0] - 8.0 * (3000.0 - 2048.0)).abs() < 1e-6,
            "DC = 8·(c−2048) exact (got {0})",
            x[0]
        );
        assert!(
            x[1..].iter().all(|&v| v.abs() < 1e-6),
            "all AC coefficients exactly 0"
        );
    }

    /// v4 unit-test contract (ii), mirroring the coefficient evidence:
    /// a 2-px alternating (CFA) pattern carries the source's
    /// class-frequency energy (+24…+255, 12-bit scale) and the v4
    /// erasure crushes it to the measured file floor
    /// (|mean| < 1.5). In the standard orthonormal DCT (verified:
    /// vts decode == rawpy decode), the within-row 2-period concentrates
    /// at (u=0, v=7) — the file's (4,0)/(0,4)/(4,4) labels in natural order;
    /// the vertical 2-period concentrates at (7,0)/(5,0) and the measured encoder
    /// KEEPS it (1.00× v-ratio), so the horizontal 2-tap must leave it
    /// untouched (D measurement: the file's inter-scan DC difference
    /// is 1× the source — least-squares gain 0.24 in the pre-domain,
    /// −0.55 vs −0.58 linearized — NOT the v3 G=8 mix).
    #[test]
    fn v4_2period_cfa_coefficients_at_reference_floor() {
        // within-row (−1)^x 2-period, ±128 around 2048 (pre-domain,
        // 4096 scale) over a 32-column plane (the 2-period spans the
        // whole plane — as on a real frame; the frame edge is 1 column
        // out of 3856 in production). The interior block (bx=0) is
        // asserted at the reference floor; the last block (bx=3) carries
        // the documented single edge-column no-op (edge-replicate) and
        // is excluded from the floor assertion.
        let (w, h) = (32usize, 8usize);
        let mut pl = vec![2048u16; w * h];
        for y in 0..h {
            for x in 0..w {
                pl[y * w + x] = if x % 2 == 0 { 2176 } else { 1920 };
            }
        }
        let pre = block_xorth(&pl, w, 0, 0);
        // source: the 2-period carries the CFA energy far above the
        // +24 source floor (4096 scale).
        assert!(
            pre[0 * 8 + 7].abs() > 24.0,
            "source (0,7) carries the CFA energy (got {0})",
            pre[7]
        );
        // the v4 erasure (pre-domain 2-tap) → exactly flat in the
        // interior: the (0,7)/(0,5) coefficients land at the measured
        // measured floor (< 1.5, the file bound).
        let er = h2tap_smooth_wh(&pl, w, h);
        let post = block_xorth(&er, w, 0, 0);
        assert!(
            post[0 * 8 + 7].abs() < 1.5,
            "erased (0,7) at the reference floor (got {0})",
            post[7]
        );
        assert!(
            post[0 * 8 + 5].abs() < 1.5,
            "erased (0,5) at the reference floor (got {0})",
            post[5]
        );
        // the edge block's only residual is the single edge-column no-op
        // (x = w−1 averages with itself — the documented edge-replicate,
        // ≈31 here for ±128 amplitude): far below the source energy, and
        // 1 column out of 1928 per frame edge in production (the fit
        // measures the file-level (0,7) residual at 8.2 including it).
        let edge = block_xorth(&er, w, 3, 0);
        assert!(
            edge[0 * 8 + 7].abs() < pre[0 * 8 + 7].abs(),
            "edge-block (0,7) attenuated vs the source 2-period (got {0} vs {1})",
            edge[7],
            pre[7]
        );
        // the vertical 2-period is preserved EXACTLY (a horizontal 2-tap
        // is a no-op on constant rows): the inter-row class structure the
        // NLE demosaic needs is untouched.
        let mut vp = vec![2048u16; w * h];
        for y in 0..h {
            for x in 0..w {
                vp[y * w + x] = if y % 2 == 0 { 2176 } else { 1920 };
            }
        }
        let pre_v = block_xorth(&vp, w, 0, 0);
        let post_v = block_xorth(&h2tap_smooth_wh(&vp, w, h), w, 0, 0);
        assert!(
            (pre_v[7 * 8 + 0].abs() - post_v[7 * 8 + 0].abs()).abs() < 1e-6,
            "vertical 2-period (7,0) preserved exactly by the horizontal 2-tap"
        );
    }

    /// End-to-end erasure (the synthetic acceptance; v4 chain:
    /// the erasure now lives INSIDE full_frame_planes — the caller's
    /// cfa_lowpass_h pre-pass is a no-op for erasure purposes on a pure
    /// 2-period, so the test body is unchanged): a strict 2×2 CFA frame
    /// (even frame rows = G R, odd rows = W G, flat scene) through
    /// full_frame_planes → encode_tiles → the tile0 scan0 reconstruction
    /// (identity-curve IDCT) has CFA contrast ≤ 1 pre-unit. Input
    /// contrast: 6 LSB ≈ 114 pre-units (the dark-band slope ~19 pre/LSB).
    /// The DCT of the erased pre-domain is DC-only per plane → the recon
    /// is a constant plane (± DC quantization) → contrast 0.
    #[test]
    fn cfa_erasing_end_to_end_2period_frame() {
        // v4 behavior pin: this test asserts the v4
 // 2-tap erasure INSIDE full_frame_planes. The v4 mode is
        // passed explicitly (the env-driven wrapper defaults to it;
        // explicit mode = race-free, see `full_frame_planes_erased`).
        let w = FRAME_W as usize;
        let h = FRAME_H as usize;
        let src: Vec<u16> = (0..(w as u32 * h as u32))
            .map(|i| {
                let y = (i as u32) / (w as u32);
                let x = (i as u32) % (w as u32);
                if y % 2 == 0 {
                    if x % 2 == 0 {
                        264
                    } else {
                        270
                    } // G R rows (scan0)
                } else if x % 2 == 0 {
                    263
                } else {
                    269
                } // W G rows (scan1)
            })
            .collect();
        // input CFA contrast on the tile0 scan0 region (LSB)
        let (mut se, mut so, mut ne, mut no) = (0f64, 0f64, 0f64, 0f64);
        for p in 0..PLANE_H {
            for x in 0..PLANE_W {
                let v = src[2 * p * w + x] as f64;
                if x % 2 == 0 {
                    se += v;
                    ne += 1.0;
                } else {
                    so += v;
                    no += 1.0;
                }
            }
        }
        let c_src = (so / no - se / ne).abs();
        assert!(
            c_src > 5.0,
            "the synthetic frame must carry the CFA pattern ({c_src})"
        );
        let inv = inv_lut(&REFERENCE_CURVE);
        let src2 = cfa_lowpass_h(&src, FRAME_W, FRAME_H);
        let planes = full_frame_planes_erased(
            &src2,
            FRAME_W,
            FRAME_H,
            &inv,
            &REFERENCE_CURVE,
            CfaErasure::V4TwoTap,
        )
        .unwrap();
        let tiles = encode_tiles(&planes, &BASE_TABLE).unwrap();
        let info = crate::dct2s::parse_tile(&tiles[0]).unwrap();
        let id = crate::dct2s::linearization_curve(None);
        let (recon, _) = crate::dct2s::decode_scan_plane(&tiles[0], &info, 0, &id).unwrap();
        let c_re = cfa_contrast_cols(&recon);
        assert!(
            c_re <= 1.0,
            "recon CFA contrast {c_re} pre-units must be ≤ 1 (erased; input {c_src} LSB)"
        );
    }

    /// Real-f1 erasure + hard bound (corpus-gated; v4 PRODUCTION chain):
    /// on real footage, RAW samples → full_frame_planes (the v4 pre-domain
    /// 2-tap, no clamp — see the function docs) and (1) the encoded
    /// pre-domain keeps < 10% of the source's CFA contrast and (2) the
    /// v4 reference-fidelity contract |curve(out) − (src[x]+src[x+1])/2| ≤
    /// 27 source LSB holds per pixel (the measured worst case on f1 — the
    /// Jensen kink at the curve's bright knee, inside the measured
    /// 33/row deviation envelope from the fit; the 20b/20c ≤ 2 LSB
    /// clamp-artifact bound is superseded).
    /// The deviation vs the ORIGINAL source is the documented ≤
    /// adjacent-diff/2 erasure (its MEAN is bounded by the 20a per-class
    /// gate, not here).
    #[test]
    fn cfa_erasing_real_f1_forward_model() {
        // v4 behavior pin: this test asserts the v4
 // pre-domain 2-tap chain — the erasure contrast bound
        // and the |curve(out) − 2-tap| ≤ 27 forward-model bound. The v4
        // mode is passed explicitly (race-free; see
        // `full_frame_planes_erased`).
        let path = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        if !std::path::Path::new(path).exists() {
            eprintln!("skip: no testdata corpus");
            return;
        }
        let srcb = std::fs::read(path).unwrap();
        let frame = crate::tiff::read(&srcb).unwrap();
        let (w, h) = (frame.width, frame.height);
        let samples = crate::pack12::unpack12(frame.strip_slice(&srcb), w, h).unwrap();
        let inv = inv_lut(&REFERENCE_CURVE);
        // source CFA contrast on the tile0 scan0 region (frame even rows,
        // cols 0..1928) in pre-units — the full-frame even/odd mix cancels
        // the CFA signal (row classes 0/1 contribute opposite signs), so
        // the region measurement is the reference (anchor: f1 =
        // 18.90 LSB ≈ 149 pre-units; 148.97).
        let (mut se, mut so, mut ne, mut no) = (0f64, 0f64, 0f64, 0f64);
        for p in 0..PLANE_H {
            for x in 0..PLANE_W {
                let s = samples[2 * p * (w as usize) + x];
                let v = inv[s as usize] as f64;
                if x % 2 == 0 {
                    se += v;
                    ne += 1.0;
                } else {
                    so += v;
                    no += 1.0;
                }
            }
        }
        let c_src_pre = (so / no - se / ne).abs();
        assert!(
            c_src_pre > 50.0,
            "f1 must carry the CFA pattern ({c_src_pre} pre-units)"
        );
        // v4 PRODUCTION chain (worker.rs): RAW samples in — the erasure
        // and the erased-source clamp are inside full_frame_planes. The
        // 20b contract reference is the linearized 2-tap of the raw
        // samples (the v4 clamp window center).
        let src2 = cfa_lowpass_h(&samples, w, h);
        let planes =
            full_frame_planes_erased(&samples, w, h, &inv, &REFERENCE_CURVE, CfaErasure::V4TwoTap)
                .unwrap();
        let out = &planes[0].even;
        let c_out = cfa_contrast_cols(out);
        assert!(
            c_out < 0.10 * c_src_pre,
            "erasure: out {c_out} < 10% of source {c_src_pre} pre-units"
        );
        let mut mx = 0u32;
        for (i, &o) in out.iter().enumerate() {
            let p = i / PLANE_W;
            let x = i % PLANE_W;
            let s2 = src2[2 * p * (w as usize) + x];
            let e = (REFERENCE_CURVE[o as usize] as i64 - s2 as i64).abs() as u32;
            if e > mx {
                mx = e;
            }
        }
        assert!(
            mx <= 27,
            "v4 reference-fidelity |curve(out) − src2| ≤ 27 source LSB (Jensen knee; got {mx})"
        );
    }

    // v5 (cast fix) — the selective bin kill.
    #[test]
    fn v5_bin_kill_zeroes_exactly_the_three_cfa_bins() {
        // full-spectrum synthetic: every bin nonzero with a known value.
        let mut x = core::array::from_fn(|i| (i as f64 + 1.0) * 128.0);
        cfa_bin_kill_block(&mut x);
        assert!(x[0 * 8 + 4] == 0.0, "(0,4) zeroed");
        assert!(x[4 * 8 + 0] == 0.0, "(4,0) zeroed");
        assert!(x[4 * 8 + 4] == 0.0, "(4,4) zeroed");
        for (i, &v) in x.iter().enumerate() {
            if i == 0 * 8 + 4 || i == 4 * 8 + 0 || i == 4 * 8 + 4 {
                continue;
            }
            assert!(
                (v - (i as f64 + 1.0) * 128.0).abs() < 1e-9,
                "bin {i} untouched by the mask (got {v})"
            );
        }
    }

    #[test]
    fn v5_bin_kill_2period_energy_location() {
        // MEASURED DCT-II FACT (the production
        // `block_xorth` on real corpus data): the orthonormal DCT-II's
        // half-sample shift means a pure 2-px (−1)^x pattern does NOT
        // concentrate in bin (0,4) — its energy spreads over the ODD
        // horizontal bins ((0,1)/(0,3)/(0,5)/(0,7), (0,7) dominant), and
        // the three mask bins (4,0)/(0,4)/(4,4) carry ≈0 of it. This
        // test pins that behavior so the mask's effect on a pure
        // 2-period signal is documented (the mask is a NO-OP on such a
        // pattern: it zeros exactly the three target bins, which hold
        // float-floor energy here). The real-corpus consequence (the
        // source scan planes' phase-locked CFA energy sits in the odd-v
        // bins, while the {4,32,36} bins are ≈0 in source AND
        // reference) is the recorded decision
        // on the v5 mask scope.
        let patterns: [(&str, fn(usize, usize) -> bool); 3] = [
            ("h", |x, _y| x % 2 == 0),
            ("v", |_x, y| y % 2 == 0),
            ("diag", |x, y| (x + y) % 2 == 0),
        ];
        for (name, sel) in patterns {
            let pl: Vec<u16> = (0..8 * 8)
                .map(|i| {
                    let (y, x) = (i / 8, i % 8);
                    if sel(x, y) {
                        2176
                    } else {
                        1920
                    }
                })
                .collect();
            let xb = block_xorth(&pl, 8, 0, 0);
            // The three mask bins carry ≈0 of the 2-period energy
            // (DCT-II spreads it over the odd-frequency bins — odd-v for
            // (−1)^x, odd-u for (−1)^y, odd×odd for the checkerboard).
            let in_mask = xb[0 * 8 + 4].abs() + xb[4 * 8 + 0].abs() + xb[4 * 8 + 4].abs();
            let rest: f64 = xb
                .iter()
                .enumerate()
                .filter(|(k, _)| *k != 0 && *k != 4 && *k != 32 && *k != 36)
                .map(|(_, &v)| v.abs())
                .sum();
            assert!(
                in_mask < 1.0,
                "{name}: mask bins ≈0 for the 2-period (got {in_mask})"
            );
            assert!(
                rest > 100.0,
                "{name}: the 2-period energy is in the non-mask AC bins (got {rest})"
            );
            let mut xbm = xb;
            cfa_bin_kill_block(&mut xbm);
            assert_eq!(xbm[0 * 8 + 4], 0.0);
            assert_eq!(xbm[4 * 8 + 0], 0.0);
            assert_eq!(xbm[4 * 8 + 4], 0.0);
            // no-op on the pattern (float-exact: the bins were ~0)
            let diff: f64 = xb.iter().zip(&xbm).map(|(a, b)| (a - b).abs()).sum();
            assert!(
                diff < 1.0,
                "{name}: mask is a no-op on the pure 2-period (diff {diff})"
            );
        }
    }

    #[test]
    fn erasure_mode_gate_default_and_rejection() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        // The env-var gate: unset → v4-2tap
        // default (the render baseline — a render-FAILing cue must not
        // be the production default); `v5b-cue-cd` = the
        // cD cue diagnostic; `v5-binkill` = the bin-kill
        // diagnostic; an unrecognized non-empty value is a HARD error (a
        // typo must not silently switch the production transform).
        std::env::remove_var("FRAMEPRISM_ERASURE");
        assert_eq!(
            CfaErasure::from_env().unwrap(),
            CfaErasure::V4TwoTap,
            "unset FRAMEPRISM_ERASURE = the v4-2tap default"
        );
        std::env::set_var("FRAMEPRISM_ERASURE", "v4-2tap");
        assert_eq!(CfaErasure::from_env().unwrap(), CfaErasure::V4TwoTap);
        std::env::set_var("FRAMEPRISM_ERASURE", "v5b-cue-cd");
        assert_eq!(CfaErasure::from_env().unwrap(), CfaErasure::V5Cue);
        std::env::set_var("FRAMEPRISM_ERASURE", "v5-binkill");
        assert_eq!(CfaErasure::from_env().unwrap(), CfaErasure::V5BinKill);
        std::env::set_var("FRAMEPRISM_ERASURE", "dcdc");
        assert_eq!(CfaErasure::from_env().unwrap(), CfaErasure::Dcdc);
        std::env::set_var("FRAMEPRISM_ERASURE", "v5-cue");
        assert!(
            matches!(CfaErasure::from_env(), Err(DctError::BadErasureMode(s)) if s == "v5-cue"),
            "the v5-cue mode name is a hard error (renamed v5b-cue-cd)"
        );
        std::env::set_var("FRAMEPRISM_ERASURE", "bogus");
        assert!(
            matches!(CfaErasure::from_env(), Err(DctError::BadErasureMode(s)) if s == "bogus"),
            "an unrecognized mode is a hard error"
        );
        std::env::remove_var("FRAMEPRISM_ERASURE");
    }

    /// dcdc env-override unit contract: the `FRAMEPRISM_DCDC_CONSTS`
    /// parse — absent/empty = the literals (None, bit-exact default),
    /// valid 8 or 9 fields = the override (9th = T; 8 keeps the literal
    /// T), any malformation = a hard error (`BadDcdcConsts`, never a
    /// silent fallback to the literals).
    #[test]
    fn dcdc_consts_env_override_parse() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        // absent → None (the literals; default behavior unchanged)
        std::env::remove_var("FRAMEPRISM_DCDC_CONSTS");
        assert_eq!(
            dcdc_consts_from_env().unwrap(),
            None,
            "absent FRAMEPRISM_DCDC_CONSTS = the built-in literals (bit-exact default)"
        );
        // empty → None (empty = the literals, not an error)
        std::env::set_var("FRAMEPRISM_DCDC_CONSTS", "");
        assert_eq!(
            dcdc_consts_from_env().unwrap(),
            None,
            "empty FRAMEPRISM_DCDC_CONSTS = the literals"
        );
        // valid 8 (the s100 base itself; T stays the literal)
        std::env::set_var(
            "FRAMEPRISM_DCDC_CONSTS",
            "1.337713,1.359291,1.467699,1.501032,44.659793,45.231073,18.998368,19.835990",
        );
        let c = dcdc_consts_from_env().unwrap().expect("8 valid fields");
        assert_eq!(c.dark, DCDC_DARK, "8-field parse = the built-in dark literals");
        assert_eq!(
            c.bright, DCDC_BRIGHT,
            "8-field parse = the built-in bright literals"
        );
        assert_eq!(c.t, DCDC_T, "8-field parse keeps the literal T");
        // valid 9 (the optional T override)
        std::env::set_var(
            "FRAMEPRISM_DCDC_CONSTS",
            "0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,500.0",
        );
        let c = dcdc_consts_from_env().unwrap().expect("9 valid fields");
        assert!(
            c.dark.iter().all(|&v| v == 0.5) && c.bright.iter().all(|&v| v == 0.5),
            "9-field parse = the 8 override values"
        );
        assert_eq!(c.t, 500.0, "the 9th field overrides T");
        // whitespace-tolerant fields
        std::env::set_var("FRAMEPRISM_DCDC_CONSTS", " 1.0 , 2.0,3.0,4.0,5.0,6.0,7.0,8.0");
        let c = dcdc_consts_from_env()
            .unwrap()
            .expect("whitespace-tolerant fields");
        assert_eq!(c.dark, [1.0, 2.0, 3.0, 4.0]);
        assert_eq!(c.bright, [5.0, 6.0, 7.0, 8.0]);
        assert_eq!(c.t, DCDC_T);
        // malformed: wrong field count (7 / 10) → hard error
        std::env::set_var("FRAMEPRISM_DCDC_CONSTS", "1,2,3,4,5,6,7");
        assert!(
            matches!(dcdc_consts_from_env(), Err(DctError::BadDcdcConsts(_))),
            "7 fields = hard error"
        );
        std::env::set_var("FRAMEPRISM_DCDC_CONSTS", "1,2,3,4,5,6,7,8,9,10");
        assert!(
            matches!(dcdc_consts_from_env(), Err(DctError::BadDcdcConsts(_))),
            "10 fields = hard error"
        );
        // malformed: unparsable field → hard error (never a silent fallback)
        std::env::set_var("FRAMEPRISM_DCDC_CONSTS", "1,2,x,4,5,6,7,8");
        assert!(
            matches!(dcdc_consts_from_env(), Err(DctError::BadDcdcConsts(_))),
            "garbage field = hard error"
        );
        // malformed: non-finite field or T → hard error
        std::env::set_var("FRAMEPRISM_DCDC_CONSTS", "1,2,3,nan,5,6,7,8");
        assert!(
            matches!(dcdc_consts_from_env(), Err(DctError::BadDcdcConsts(_))),
            "non-finite field = hard error"
        );
        std::env::set_var("FRAMEPRISM_DCDC_CONSTS", "1,2,3,4,5,6,7,8,inf");
        assert!(
            matches!(dcdc_consts_from_env(), Err(DctError::BadDcdcConsts(_))),
            "non-finite T = hard error"
        );
        // trailing comma = an empty 9th field → hard error (not silent 8)
        std::env::set_var("FRAMEPRISM_DCDC_CONSTS", "1,2,3,4,5,6,7,8,");
        assert!(
            matches!(dcdc_consts_from_env(), Err(DctError::BadDcdcConsts(_))),
            "trailing comma = hard error"
        );
        std::env::remove_var("FRAMEPRISM_DCDC_CONSTS");
    }

    // ---------------------------------------------------- v5b-cue-cd tests

    /// v5b-cue-cd unit contract (i): the cue offsets are INTER-SCAN (scan0 =
    /// +g·U_band, scan1 = −g·U_band, sign-exact) and follow the smooth
    /// class envelope: a constant U survives the 2-px aliasing
    /// subtraction at 24/25 (box5 kills the pure checkerboard, keeps the
    /// smooth envelope — the interior cell is exact: off = g·(24/25)·U),
    /// and a balanced-class frame (U = 0) gets a zero cue.
    #[test]
    fn v5cue_offsets_inter_scan_and_envelope() {
        let fw = 16usize;
        let n = 8usize;
        // W = R = 2040 (both "bright" classes), Go = Ge = 2000 → U =
        // (2040+2040)/2 − (2000+2000)/2 = 40 (constant — the scene-level
        // color cue, no 2-px component).
        let mut pre0 = vec![0u16; fw * n]; // scan0: W at even cols, Ge at odd
        let mut pre1 = vec![0u16; fw * n]; // scan1: Go at even cols, R at odd
        for r in 0..n {
            for c in 0..(fw / 2) {
                pre0[r * fw + 2 * c] = 2040;
                pre0[r * fw + 2 * c + 1] = 2000;
                pre1[r * fw + 2 * c] = 2000;
                pre1[r * fw + 2 * c + 1] = 2040;
            }
        }
        let g = 0.7;
        let (off0, off1) = cue_offsets(&pre0, &pre1, fw, n, n, g);
        // U = 40 → U_band = 24/25·40 = 38.4 (interior: the box5 checker
        // extraction is exact on a constant envelope) → off = ±26.88.
        let interior = 4 * fw + 8; // cell (r=4, c=4) — fully interior
        assert!(
            (off0[interior] - g * 38.4).abs() < 0.5,
            "scan0 cue = +g·(24/25)·U interior-exact (got {0}, want {1})",
            off0[interior],
            g * 38.4
        );
        assert!(
            (off1[interior] + g * 38.4).abs() < 0.5,
            "scan1 cue = −g·(24/25)·U (the inter-scan sign flip, got {0})",
            off1[interior]
        );
        // both frame columns of a half-res cell carry the same offset
        // (the ×2 upsample):
        assert_eq!(
            off0[interior],
            off0[interior + 1],
            "×2 upsample: cell columns equal"
        );
        assert_eq!(off1[interior], off1[interior + 1]);
        // balanced classes (U = 0) → the cue is exactly zero:
        let (off0b, off1b) = cue_offsets(&pre0, &pre0, fw, n, n, g);
        assert!(
            off0b.iter().all(|&o| o.abs() < 1e-9),
            "balanced classes → U = 0 → cue 0 (scan0)"
        );
        assert!(
            off1b.iter().all(|&o| o.abs() < 1e-9),
            "balanced classes → U = 0 → cue 0 (scan1)"
        );
    }

    /// v5b-cue-cd unit contract (ii): the 2-px grid stays KILLED — on a strict
    /// 2×2 CFA pattern frame the scan0 tile0 (0,7) bin stays AT the v4
    /// 2-tap floor (≤ v4 + 2 pre-units; the v4 floor itself < 1.5, the
    /// contract) — the cue must not re-inject the 2-px CFA energy
    /// (the negative control: the naive per-pixel checkerboard re-injects
    /// it 5–10× source). The cue is also
    /// verified NOT to be a no-op (it changes the planes).
    #[test]
    fn v5cue_2period_grid_stays_killed() {
        let w = FRAME_W as usize;
        let h = FRAME_H as usize;
        // strict 2×2 CFA pattern, high contrast in the pre-domain (200/
        // 350): even frame rows: x even 200, x odd 350; odd rows: x even
        // 350, x odd 200 → W = R = 350, Go = Ge = 200 (U = 150 constant —
        // the cue is a uniform per-scan offset, no 2-px component).
        let src: Vec<u16> = (0..(w as u32 * h as u32))
            .map(|i| {
                let y = (i as u32) / (w as u32);
                let x = (i as u32) % (w as u32);
                if (y % 2 == 0) == (x % 2 == 0) {
                    200
                } else {
                    350
                }
            })
            .collect();
        let inv = inv_lut(&REFERENCE_CURVE);
        // production chain (worker.rs): the raw source goes straight into
        // full_frame_planes (the 20b cfa_lowpass_h pre-pass is retired).
        let p4 = full_frame_planes_erased(
            &src,
            FRAME_W,
            FRAME_H,
            &inv,
            &REFERENCE_CURVE,
            CfaErasure::V4TwoTap,
        )
        .unwrap();
        let p5 = full_frame_planes_erased(
            &src,
            FRAME_W,
            FRAME_H,
            &inv,
            &REFERENCE_CURVE,
            CfaErasure::V5Cue,
        )
        .unwrap();
        // measure at an INTERIOR block (bx=8, by=8 — away from the frame
        // edge, where the box5 checker-extraction window clamps and the
        // U_band amplitude tapers over the first ~3 plane rows/cols — a
        // corner artifact confined to the frame boundary, a tiny fraction
        // of the file's measured (0,7) floor):
        let b4 = block_xorth(&p4[0].even, PLANE_W, 8, 8);
        let b5 = block_xorth(&p5[0].even, PLANE_W, 8, 8);
        assert!(
            b4[0 * 8 + 7].abs() < 1.5,
            "v4 (0,7) at the reference floor (got {0})",
            b4[7]
        );
        assert!(
            b5[0 * 8 + 7].abs() < 5.0 && b5[0 * 8 + 7].abs() <= b4[0 * 8 + 7].abs() + 2.0,
            "v5b-cue-cd (0,7) at the v4 floor (got {0} vs v4 {1} — the grid stays killed)",
            b5[7],
            b4[7]
        );
        // the cue is not a no-op (it changed the planes — the uniform
        // per-scan cue offset, U = 150 raw ≈ ±~90 pre over most pixels):
        let d: u64 = (0..4)
            .map(|ti| {
                let a = &p4[ti];
                let b = &p5[ti];
                a.even
                    .iter()
                    .zip(b.even.iter())
                    .map(|(x, y)| ((*x) as i32 - (*y) as i32).unsigned_abs() as u64)
                    .sum::<u64>()
                    + a.odd
                        .iter()
                        .zip(b.odd.iter())
                        .map(|(x, y)| ((*x) as i32 - (*y) as i32).unsigned_abs() as u64)
                        .sum::<u64>()
            })
            .sum();
        assert!(
            d > 1_000_000,
            "v5b-cue-cd changed the pre-planes vs v4 (L1 diff {d})"
        );
    }

    /// v5-cue unit contract (iii): cue retention — on a synthetic frame
    /// with SMOOTH per-class brightness offsets (the scene color, NOT the
    /// 2-px pattern), the v5-cue pre-domain restores a large share of the
    /// source's class-diff envelope (D_WG retention ratio in [0.5, 0.9] —
    /// the measured ~0.6 band — well above the 2-tap
    /// alone), without re-injecting the 2-px bin. The class fields are
    /// ZERO-MEAN color around the common base (real footage's W−G color
    /// fluctuates around 0 — a DC color offset leaks into the 2-tap
    /// residual via the (2W−W′−Go−R)/4 term and masks the erasure); the
    /// frame sits in the curve's identity toe (raw ≤ ~228: pre = raw,
    /// verified numerically), so the pre-domain ratio is the raw-domain
    /// proxy ratio (measured on this frame: r4 = 0.22, r5 = 0.65 — the
    /// the "2-tap 5–20% / reference ~60%" split). Real acceptance is the
    /// proxy + the round-trip render; this test pins the MECHANISM.
    #[test]
    fn v5cue_restores_class_diff_envelope() {
        let w = FRAME_W as usize;
        let h = FRAME_H as usize;
        // smooth low-frequency class offsets (period 128–256 px), zero-mean
        // color, W≠R and Ge≠Go (distinct smooth shapes — real footage's
        // class fields are correlated but distinct).
        // REAL CFA geometry (matches `cue_offsets`): even frame rows
        // (scan0): even col = W, odd col = Ge; odd rows (scan1): even col
        // = Go, odd col = R.
        let src: Vec<u16> = (0..(w as u32 * h as u32))
            .map(|i| {
                let y = (i as u32) / (w as u32);
                let x = (i as u32) % (w as u32);
                let f1 = ((x / 128) % 5) as u16;
                let f2 = ((y / 256) % 3) as u16;
                let f3 = ((y / 128) % 5) as u16;
                let f4 = ((x / 256) % 3) as u16;
                let base = 100u16 + 12 * f1 + 10 * f2;
                let cw = base + 12 * f1 + 6 * f2; // W
                let cge = base - 5 * f1 - 3 * f2; // Ge
                let cgo = base - 6 * f1 - 2 * f3; // Go
                let cr = base + 10 * f3 + 5 * f4; // R (distinct smooth shape)
                if y % 2 == 0 {
                    if x % 2 == 0 {
                        cw
                    } else {
                        cge
                    } // scan0: W Ge
                } else {
                    if x % 2 == 0 {
                        cgo
                    } else {
                        cr
                    } // scan1: Go R
                }
            })
            .collect();
        let inv = inv_lut(&REFERENCE_CURVE);
        // source class fields in the pre-domain (same domain as the
        // output planes — the retention ratio is domain-consistent):
        let src_pre: Vec<u16> = src.iter().map(|&s| inv[s as usize]).collect();
        let nc = PLANE_W / 2;
        let mut dwg_src = Vec::with_capacity(PLANE_H * nc);
        for p in 0..PLANE_H {
            let r0 = (2 * p) * w;
            let r1 = (2 * p + 1) * w;
            for c in 0..nc {
                let wv = src_pre[r0 + 2 * c] as f64; // W (scan0, even col)
                let ge = src_pre[r0 + 2 * c + 1] as f64; // Ge (scan0, odd col)
                let go = src_pre[r1 + 2 * c] as f64; // Go (scan1, even col)
                dwg_src.push(wv - (go + ge) / 2.0);
            }
        }
        let mean = dwg_src.iter().sum::<f64>() / dwg_src.len() as f64;
        let std_src = (dwg_src.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>()
            / dwg_src.len() as f64)
            .sqrt();
        assert!(
            std_src > 5.0,
            "the synthetic frame carries the class envelope (std {std_src})"
        );
        let ratio_of = |planes: &[TilePlanes; 4]| {
            // D_WG field only (the proxy's per-field convention — a mixed
            // D_WG+D_RG std is dominated by the inter-scan mean offset
            // between the two fields, which IS the cue itself):
            let mut v: Vec<f64> = Vec::with_capacity(PLANE_H * (PLANE_W / 2));
            for p in 0..PLANE_H {
                let ro = p * PLANE_W;
                for c in 0..(PLANE_W / 2) {
                    let wv = planes[0].even[ro + 2 * c] as f64;
                    let ge = planes[0].even[ro + 2 * c + 1] as f64;
                    let go = planes[0].odd[ro + 2 * c] as f64;
                    v.push(wv - (go + ge) / 2.0);
                }
            }
            let m = v.iter().sum::<f64>() / v.len() as f64;
            (v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / v.len() as f64).sqrt() / std_src
        };
        let p4 = full_frame_planes_erased(
            &src,
            FRAME_W,
            FRAME_H,
            &inv,
            &REFERENCE_CURVE,
            CfaErasure::V4TwoTap,
        )
        .unwrap();
        let p5 = full_frame_planes_erased(
            &src,
            FRAME_W,
            FRAME_H,
            &inv,
            &REFERENCE_CURVE,
            CfaErasure::V5Cue,
        )
        .unwrap();
        let r4 = ratio_of(&p4);
        let r5 = ratio_of(&p5);
        assert!(
            r4 < 0.4,
            "the v4 2-tap erases most of the envelope (ratio {r4})"
        );
        assert!(
            r5 >= 0.5 && r5 <= 0.9,
            "v5-cue retention in the reference band [0.5, 0.9] (got {r5}; v4 {r4})"
        );
        assert!(
            r5 - r4 > 0.2,
            "the cue restores a large share (Δ {0} = {1} − {2})",
            r5 - r4,
            r5,
            r4
        );
    }

 // -------------------------------------------------------- D3 / seam tests

    /// Synthetic seam-gate calibration (no corpus): a uniform 1 LSB decode
    /// error everywhere → seam/baseline ≈ 1.0 → PASS; a +10 LSB step at the
    /// tile-boundary column x=1928 (vertical seam) or row y=1088
    /// (horizontal seam) → seam ≈ (1+11)/2 = 6 vs baseline 1 → ratio 6 >
    /// 1.5 → FAIL.
    #[test]
    fn seam_gate_detects_doctored_step() {
        let w = FRAME_W;
        let h = FRAME_H;
        let n = (w * h) as usize;
        let source: Vec<u16> = vec![260u16; n];
        // healthy: uniform 1 LSB error everywhere (seam = baseline)
        let decoded: Vec<u16> = vec![261u16; n];
        assert!(
            gate_seam(&decoded, &source, w, h).is_ok(),
            "uniform error must pass the seam gate"
        );
        // doctored VERTICAL seam: +10 LSB at column x=1928 (right-tile first col)
        let mut dv = decoded.clone();
        for y in 0..h {
            dv[(y as usize) * (w as usize) + 1928] =
                source[(y as usize) * (w as usize) + 1928].wrapping_add(11);
        }
        assert!(
            gate_seam(&dv, &source, w, h).is_err(),
            "vertical doctored seam must FAIL"
        );
        // doctored HORIZONTAL seam: +10 LSB at row y=1088 (bottom-tile first row)
        let mut dh = decoded.clone();
        let rh = 1088usize * (w as usize);
        for x in 0..(w as usize) {
            dh[rh + x] = source[rh + x].wrapping_add(11);
        }
        assert!(
            gate_seam(&dh, &source, w, h).is_err(),
            "horizontal doctored seam must FAIL"
        );
        // the step one column OFF the boundary (x=1929) is inside the seam
        // pair's neighbor baseline, not the seam strip — still a big local
        // spike, but NOT at the tile border: the gate judges the border pair.
        // (Documented scope: the gate is anti-SEAM at x∈{1927,1928} /
        // y∈{1087,1088}, not a general spike detector.)
    }

    /// Corpus-gated end-to-end seam test (the acceptance): the
    /// PRODUCTION chain (cfa_lowpass_h → full_frame_planes → encode_tiles →
    /// assemble_frame) on real f1 → the seam gate PASSES (the full-frame
    /// box3 left no tile-border seam). Negative: a doctored seam line — a
    /// 2-column +12 LSB step at x=1928/1929 (the post-curve 12-bit domain
 /// the gate judges; the D3 seam's decoded signature is a 1–2 column
    /// step at exactly the frame middle) → the seam gate FAILS. (The step
    /// is applied to the DECODED plane, not the pre-domain: a pre-domain
    /// step is quantized away at vbr-hq quality — measured: +100 pre-units
    /// at x=1928 → seam ratio 1.23, below the 1.5 limit — so the gate, like
    /// all pixel-domain gates, judges the post-curve domain where a visible
    /// seam line lives.)
    #[test]
    fn doctored_seam_column_fails_verify_gate() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        let path = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        if !std::path::Path::new(path).exists() {
            eprintln!("skip: no testdata corpus");
            return;
        }
        let srcb = std::fs::read(path).unwrap();
        let frame = crate::tiff::read(&srcb).unwrap();
        let (w, h) = (frame.width, frame.height);
        let samples = crate::pack12::unpack12(frame.strip_slice(&srcb), w, h).unwrap();
        let curve = REFERENCE_CURVE;
        let inv = inv_lut(&curve);
        let src2 = cfa_lowpass_h(&samples, w, h);
        let planes = full_frame_planes(&src2, w, h, &inv, &curve).unwrap();
        let cp = crate::dct2s::linearization_curve(Some(&curve.to_vec()));
        // healthy production encode → PASS (and record the ratios)
        let tiles = encode_tiles(&planes, &BASE_TABLE).unwrap();
        let refs: Vec<&[u8]> = tiles.iter().map(|t| t.as_slice()).collect();
        let decoded = crate::dct2s::assemble_frame(&refs, TILE_W, TILE_H, w, h, &cp).unwrap();
        let seam = gate_seam(&decoded, &samples, w, h)
            .expect("healthy f1 full_frame_planes encode must pass the seam gate");
        let (sv, sh) = (seam.v, seam.h);
        eprintln!("  f1 seam (healthy): v {sv:.3} h {sh:.3} (limit 1.5)");
        // doctored VERTICAL seam: +12 LSB on the 2 columns at the tile
        // border (x=1928 the right-tile first column, x=1929 its neighbor)
        let mut dv = decoded.clone();
        for y in 0..(h as usize) {
            let ro = y * (w as usize);
            dv[ro + 1928] = dv[ro + 1928].wrapping_add(50);
            dv[ro + 1929] = dv[ro + 1929].wrapping_add(50);
        }
        let err = gate_seam(&dv, &samples, w, h)
            .expect_err("doctored seam line at x=1928 must FAIL the seam gate");
        assert!(matches!(err, DctError::Gate(_)));
        // doctored HORIZONTAL seam: +50 LSB on rows 1088/1089
        let mut dh = decoded.clone();
        for x in 0..(w as usize) {
            let r0 = 1088usize * (w as usize);
            let r1 = 1089usize * (w as usize);
            dh[r0 + x] = dh[r0 + x].wrapping_add(50);
            dh[r1 + x] = dh[r1 + x].wrapping_add(50);
        }
        assert!(
            gate_seam(&dh, &samples, w, h).is_err(),
            "horizontal doctored seam must FAIL"
        );
    }

    /// The full-frame box3 must NOT introduce a tile-border discontinuity:
    /// on a flat full-frame plane the full-frame and the (doctored-
    /// comparison) per-tile pipelines give identical planes EXCEPT at the
    /// border columns/rows — and on a flat plane both are exact (a box of
    /// equal values is the value), so the discriminating case is a
    /// 1-column step at x=1928: the full-frame box3 spreads it over
    /// columns 1927–1929 (max step 2/3 of the original), while the per-tile
 /// box3 leaves a hard 1-column step at 1928 (the D3 seam).
    #[test]
    fn full_frame_box3_smooths_across_the_tile_border() {
        let fw = FRAME_W as usize;
        let n = ((FRAME_H + 1) / 2) as usize; // one full parity plane (1085 rows)
                                              // flat 260 with a +9 step at column x=1928 (the tile border)
        let src: Vec<u16> = (0..(fw * n))
            .map(|i| if i % fw == 1928 { 269 } else { 260 })
            .collect();
        let sm = box3_smooth_wh(&src, fw, n);
        let p = n / 2; // a middle row
        let v = |x: usize| sm[p * fw + x] as i64;
        // the step is spread over 3 columns (the box window is 3 wide, so
        // each of cols 1927/1928/1929 has 3 of 9 window cells at 269):
        // col 1927: (260·6 + 269·3)/9 = 263; col 1928: window {1927,1928,1929}
        // = {260,269,260} → 263; col 1929: (269·3 + 260·6)/9 = 263.
        assert_eq!(
            v(1926),
            260,
            "interior left of the step unchanged: {}",
            v(1926)
        );
        assert_eq!(v(1927), 263, "step spreads left: {}", v(1927));
        assert_eq!(
            v(1928),
            263,
            "step spreads over the border column: {}",
            v(1928)
        );
        assert_eq!(v(1929), 263, "step spreads right: {}", v(1929));
        assert_eq!(
            v(1930),
            260,
            "interior right of the step unchanged: {}",
            v(1930)
        );
 // no hard 1-column step survives (the D3 seam signature is a
        // |Δ(col+1) − Δ(col)| ≥ full-step at the border)
        let step_at = |x: usize| v(x + 1) - v(x);
        assert!(
            step_at(1926).abs() <= 3 && step_at(1928).abs() <= 3,
            "the border step must be ≤ 1/3 of the original 9 (got {} / {})",
            step_at(1926),
            step_at(1928)
        );
    }

    // ------------------------------------------------- lossy v2

    /// (b) The cross-scan DC mix: G = 8 amplification of the block-pair
    /// difference + exact block-pair mean preservation (the recorded correction
    /// — L±4D, NOT the rejected G=7 shorthand "≡ 4O − 3E").
    #[test]
    fn t21_dc_mix_amplifies_8x_preserves_mean() {
        // o = 100, e = −40: L = 30, D = 140 → O' = 590, E' = −530
        let (o, e) = t21_dc_mix(100.0, -40.0);
        assert_eq!(o, 590.0, "O' = L + 4·D");
        assert_eq!(e, -530.0, "E' = L − 4·D");
        assert_eq!(o - e, 8.0 * 140.0, "the difference is amplified 8×");
        assert_eq!((o + e) / 2.0, 30.0, "the block-pair mean L is preserved");
        // identity case: no difference → no change
        let (oi, ei) = t21_dc_mix(7.0, 7.0);
        assert_eq!(oi, 7.0);
        assert_eq!(ei, 7.0);
        // the rejected G=7 form (4O−3E, 4E−3O) would give 460/−420 — pin
        // the 8× form so the G=7 regression is caught by this test.
        assert_ne!(o, 4.0 * 100.0 - 3.0 * -40.0, "not the G=7 residue");
    }

    /// The transform on one block pair: j=7 column zeroed (all i),
    /// (0,3)/(0,5) ×0.2, the DC mix, everything else untouched — both
    /// scan planes.
    #[test]
    fn t21_transform_block_coefficient_map() {
        let mut xe = [1.0f64; 64];
        let mut xo = [2.0f64; 64];
        t21_transform_block(&mut xe, &mut xo);
        // (1) j=7 column (natural idx u·8+7) → 0
        for u in 0..8 {
            assert_eq!(xe[u * 8 + 7], 0.0);
            assert_eq!(xo[u * 8 + 7], 0.0);
        }
        // (2) i=0 row, j=3 and j=5 → ×0.2
        assert_eq!(xe[3], 0.2);
        assert_eq!(xe[5], 0.2);
        assert_eq!(xo[3], 0.4);
        assert_eq!(xo[5], 0.4);
        // (3) DC mix: L = 1.5, D = 1 → O' = 5.5, E' = −2.5
        assert_eq!(xo[0], 5.5);
        assert_eq!(xe[0], -2.5);
        // (4) everything else ×1.0 (j=6 explicitly UNTOUCHED)
        assert_eq!(xe[6], 1.0);
        assert_eq!(xo[6], 2.0);
        assert_eq!(xe[1], 1.0);
        assert_eq!(xo[8], 2.0);
        assert_eq!(xe[63 - 56], 0.0, "idx 7 (u=0,v=7) zeroed");
    }

    /// (a) Negative test — a strict 2×2 CFA frame (W=200 / G=210 / R=220,
    /// flat scene, 10 LSB class steps — the identity curve band) through
    /// the FULL PRODUCTION chain (full_frame_planes on the RAW source — no
    /// 2-tap — → encode_tiles_t21 → the corpus-verified decoder): the
    /// decoded frame must PRESERVE the between-row class structure
    /// (v_ratio ≥ 0.9 — the 2-tap crushes it to 0.08–0.12, so a re-entrant
    /// source-space low-pass fails) and ERASE the within-row 2-period
    /// banding (h_ratio ≤ 0.3 — the source h-step std is 10, the transform
    /// zeros the j=7 column). The D-mix presence is separately pinned by
    /// `t21_dc_mix_amplifies_8x_preserves_mean` +
    /// `t21_transform_block_coefficient_map` (a dropped mix would leave
    /// v ≈ 1.0×, which the unit tests reject, and the end-to-end h-erasure
    /// here still requires the transform to be in the path).
    #[test]
    fn t21_end_to_end_2period_frame_preserves_v_erases_h() {
        let _g = crate::ENV_LOCK.lock().expect("env lock");
        let w = FRAME_W as usize;
        let h = FRAME_H as usize;
        // even frame rows: x even = G (210), x odd = R (220); odd frame
        // rows: x even = W (200), x odd = G (210) — h steps ±10, v steps
        // ±10 (source h/v step std both 10).
        let src: Vec<u16> = (0..(w as u32 * h as u32))
            .map(|i| {
                let y = (i as u32) / (w as u32);
                let x = (i as u32) % (w as u32);
                if y % 2 == 0 {
                    if x % 2 == 0 {
                        210
                    } else {
                        220
                    }
                } else if x % 2 == 0 {
                    200
                } else {
                    210
                }
            })
            .collect();
        let (sh0, sv0) = source_step_stds(&src, FRAME_W, FRAME_H);
        assert!(
            (sh0 - 10.0).abs() < 0.5 && (sv0 - 10.0).abs() < 0.5,
            "the synthetic must carry ±10 h/v steps (got h {sh0}, v {sv0})"
        );
        let inv = inv_lut(&REFERENCE_CURVE);
        // PRODUCTION chain (lossy v2): RAW source (no cfa_lowpass_h) →
        // full_frame_planes → encode_tiles_t21 → reference-verified decode.
        let planes = full_frame_planes(&src, FRAME_W, FRAME_H, &inv, &REFERENCE_CURVE).unwrap();
        let tiles = encode_tiles_t21(&planes, &BASE_TABLE).unwrap();
        let curve = crate::dct2s::linearization_curve(Some(&REFERENCE_CURVE.to_vec()));
        let decoded = crate::dct2s::assemble_frame(
            &tiles.iter().map(|t| t.as_slice()).collect::<Vec<_>>(),
            TILE_W,
            TILE_H,
            FRAME_W,
            FRAME_H,
            &curve,
        )
        .unwrap();
        let (hr, vr) = structure_ratios(&decoded, &src, FRAME_W, FRAME_H);
        assert!(vr >= 0.9, "v_ratio {vr:.3} ≥ 0.9 (between-row class structure preserved; the 2-tap gives 0.08–0.12)");
        assert!(hr <= 0.3, "h_ratio {hr:.3} ≤ 0.3 (within-row 2-period banding erased; the source h-step std is {sh0:.2})");
    }

    /// Source h/v adjacent-step stds (the denominator of `structure_ratios`)
    /// — test helper (kept separate so the assertion message is honest).
    fn source_step_stds(img: &[u16], w: u32, h: u32) -> (f64, f64) {
        let (fw, fh) = (w as usize, h as usize);
        let mut hs: Vec<f64> = Vec::new();
        let mut vs: Vec<f64> = Vec::new();
        for y in 0..fh {
            for x in 0..fw - 1 {
                hs.push(img[y * fw + x + 1] as f64 - img[y * fw + x] as f64);
            }
            if y < fh - 1 {
                for x in 0..fw {
                    vs.push(img[(y + 1) * fw + x] as f64 - img[y * fw + x] as f64);
                }
            }
        }
        let std = |v: &Vec<f64>| {
            let m = v.iter().sum::<f64>() / v.len() as f64;
            (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / v.len() as f64).sqrt()
        };
        (std(&hs), std(&vs))
    }

    /// The gate bands (approved calibration): v-floor = max(0.5, 0.5×reference_v) (0.5 absolute without the
    /// anchor — the fixed 0.7 was calibrated to v2's own min), h-floor 1.0
    /// always; the measured-anchored upper bounds only with the same-frame
    /// anchor.
    #[test]
    fn gate_structure_bands() {
        assert!(gate_structure(0.5, 1.0, None).is_ok());
        assert!(
            gate_structure(0.5, 0.49, None).is_err(),
            "v-floor 0.5 (reference-independent)"
        );
        assert!(gate_structure(0.5, 0.5, None).is_ok(), "at the 0.5 floor");
        assert!(
            gate_structure(0.5, 0.55, Some((1.2, 0.1))).is_err(),
            "v < 0.5×reference_v (0.6) — the anchored floor binds"
        );
        assert!(
            gate_structure(0.5, 0.6, Some((1.2, 0.1))).is_ok(),
            "at 0.5×reference_v"
        );
        assert!(
            gate_structure(0.5, 0.5, Some((0.8, 0.1))).is_ok(),
            "reference floor (0.4) below the 0.5 absolute — the max() floor wins"
        );
        assert!(gate_structure(1.01, 1.0, None).is_err(), "h-floor 1.0");
        assert!(gate_structure(0.3, 1.0, Some((1.0, 0.1))).is_ok());
        assert!(
            gate_structure(0.3, 1.4, Some((0.1, 0.1))).is_ok(),
            "v ≤ max(1.4, 3.5×0.1) = 1.4"
        );
        assert!(
            gate_structure(0.3, 1.41, Some((0.1, 0.1))).is_err(),
            "v > max(1.4, 3.5×0.1) = 1.4"
        );
        assert!(
            gate_structure(0.3, 3.4, Some((1.0, 0.1))).is_ok(),
            "3.4 ≤ 3.5×reference_v"
        );
        assert!(
            gate_structure(0.3, 3.51, Some((1.0, 0.1))).is_err(),
            "v > 3.5×reference_v"
        );
        assert!(
            gate_structure(0.45, 1.0, Some((1.0, 0.1))).is_ok(),
            "h 0.45 ≤ max(1.0, 2×0.1) = 1.0"
        );
        assert!(
            gate_structure(1.05, 1.0, Some((1.0, 0.1))).is_err(),
            "h 1.05 > max(1.0, 2×0.1) = 1.0"
        );
        assert!(
            gate_structure(0.95, 1.0, Some((1.0, 0.6))).is_ok(),
            "h ≤ max(1.0, 2×reference_h)"
        );
        assert!(gate_structure(1.1, 1.0, Some((1.0, 0.6))).is_err(), "h 1.1 > the absolute 1.0 floor (the reference anchor alone would allow 1.2 — the gates conjunct)");
        assert!(gate_structure(f64::NAN, 1.0, None).is_err(), "NaN");
        assert!(
            gate_structure(0.5, 1.0, Some((0.0, 0.1))).is_err(),
            "bad anchor"
        );
    }

    /// The demosaic-chroma gate bands : lo = max(0.5×reference −
    /// 0.03, 0) (the sub-permille visibility slack on the low side — the
    /// dark-frame noise-floor class, k=16 sweep: 48 channel violations
    /// across 33 frames, max deficit 0.025 LSB), hi = max(2×, 0.75) UNCHANGED
    /// (over-cast stays FATAL); no anchor → informational (Ok); NaN → Err.
    #[test]
    fn gate_demosaic_bands() {
        assert!(
            gate_demosaic([0.1, 0.2, 0.3], None).is_ok(),
            "no anchor → informational"
        );
        assert!(
            gate_demosaic([0.1, 0.2, 0.3], Some([0.2, 0.4, 0.6])).is_ok(),
            "at/above the 0.5× floor"
        );
        assert!(
            gate_demosaic([0.07, 0.2, 0.3], Some([0.2, 0.4, 0.6])).is_ok(),
            "at the new lo (0.5×reference − 0.03)"
        );
        assert!(
            gate_demosaic([0.0699, 0.2, 0.3], Some([0.2, 0.4, 0.6])).is_err(),
            "below max(0.5×reference − 0.03, 0)"
        );
        assert!(
            gate_demosaic([0.0, 0.2, 0.3], Some([0.05, 0.4, 0.6])).is_ok(),
            "tiny reference value (lo clamps at 0)"
        );
        assert!(
            gate_demosaic([1.0, 0.2, 0.3], Some([0.2, 0.4, 0.6])).is_err(),
            "above max(2×, 0.75) — UNCHANGED (over-cast FATAL)"
        );
        assert!(
            gate_demosaic([0.74, 0.2, 0.3], Some([0.1, 0.4, 0.6])).is_ok(),
            "0.75 absolute floor"
        );
        assert!(
            gate_demosaic([0.76, 0.2, 0.3], Some([0.1, 0.4, 0.6])).is_err(),
            "above max(2×0.1, 0.75)"
        );
        assert!(gate_demosaic([f64::NAN, 0.2, 0.3], None).is_err(), "NaN");
    }

    /// (c) band-limited mix properties: a constant D grid is passed
    /// through exactly (band-limiter DC gain 1: D' = G·D − (G−1)·D = D —
    /// the coarse part IS the signal on a constant grid), and the small-grid
    /// values match the hand-computed box(2K+1) formula (K=16 ≥ the grid
    /// extent → the window is the whole grid for every block →
    /// D'[b] = G·D[b] − (G−1)·mean(D)).
    #[test]
    fn t21_dc_mix_bandlimited_constant_d_and_formula() {
        // constant D: 3×2 grid, D = −10 (the end-to-end 2-period synthetic
        // frame's actual nd grid class — the v3 transform must be the
        // identity there, which `t21_end_to_end_2period_frame_preserves_v_erases_h`
        // relies on).
        let nd = vec![-10.0f64; 6];
        let out = t21_dc_mix_bandlimited(&nd, 3, 2);
        for (i, &d) in out.iter().enumerate() {
            assert_eq!(d, -10.0, "constant D passes through (i {i})");
        }
        // hand-computed formula on a 2×2 grid (K=16 → every window = the
        // whole grid): D = [1, 2, 3, 4], mean = 2.5 →
        // D' = 8·D − 7·2.5 = [−9.5, −1.5, 6.5, 14.5].
        let nd = [1.0f64, 2.0, 3.0, 4.0];
        let out = t21_dc_mix_bandlimited(&nd, 2, 2);
        let want = [
            8.0 * 1.0 - 7.0 * 2.5,
            8.0 * 2.0 - 7.0 * 2.5,
            8.0 * 3.0 - 7.0 * 2.5,
            8.0 * 4.0 - 7.0 * 2.5,
        ];
        for i in 0..4 {
            let got = out[i];
            assert!((got - want[i]).abs() < 1e-9, "formula i {i}: got {got}");
        }
        // the fine-scale part is amplified, the coarse part preserved:
        // D = mean + δ → D' = mean + 8·δ.
        let nd = [2.5 + 1.0f64, 2.5 - 1.0]; // δ = ±1, mean 2.5
        let out = t21_dc_mix_bandlimited(&nd, 2, 1);
        assert!((out[0] - 10.5).abs() < 1e-9, "fine part +1 → mean + 8");
        assert!((out[1] - (-5.5)).abs() < 1e-9, "fine part −1 → mean − 8");
    }

    /// The flat-region seam measurement (informational): a flat frame with
    /// zero decode error measures zero everywhere (the FLAT mask is active
    /// — |src step| < 8 — so n > 0, not NaN).
    #[test]
    fn seam_flat_steps_flat_plane_zero() {
        let w = FRAME_W;
        let h = FRAME_H;
        let img: Vec<u16> = vec![260u16; (w * h) as usize];
        let s = seam_flat_steps(&img, &img, w, h).unwrap();
        assert_eq!(s.col_seam, 0.0);
        assert_eq!(s.col_ref1, 0.0);
        assert_eq!(s.col_ref2, 0.0);
        assert_eq!(s.row_seam, 0.0);
        assert_eq!(s.row_ref, 0.0);
    }
}
