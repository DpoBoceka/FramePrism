//! Reference-structure lossless tile encoder (the 5:1 compression goal).
//!
//! Structure (single source of truth: pixel-exact
//! reversed from the reference golden):
//!
//! - The 3856×2170 mosaic is tiled row-major into a grid of
//!   `ceil(W/482) × ceil(H/272)` tiles of 482×272 (last row/col clipped):
//!   A001 → 8×8 = 64 tiles, last row 266 tall.
//! - Each tile is ONE lossless (SOF3) JPEG stream, 2 components (1×1
//!   sampling), data precision 12 (lossless mode) or 10 (log10 mode —
//!   10-bit log codes, LUT signalled by DNG tag 50712), Pt=0, **Ss (PSV)
//!   = 7** — the libjpeg / DNG-SDK Table H.1 numbering (7 = (left+up)/2).
//! - Component 0 = the tile's EVEN columns, row-major; component 1 = the
//!   tile's ODD columns, row-major. Splitting even/odd puts same-CFA-phase
//!   pixels in one plane; in the wrapped orientation the up-neighbor is 2
//!   mosaic rows up = same phase → diffs cluster at 0 → per-tile Huffman
//!   crushes it (this structure, not a better encoder, buys the 5:1).
//! - Each parity plane (tileH × 241 samples for a 482-wide tile) is stored
//!   oriented to a FULL tile height (reference contract, measured
//!   across all 225 frames × 3 presets): the tile's mosaic is padded to
//!   `padded_tl` rows (next multiple of 272) by repeating the last two
//!   real rows alternately (pad row y = row tl−2+(y−tl)%2), THEN oriented:
//!   wrapped = (padded_tl/2) rows of tw (272 → 136×482, last-row 266/269 →
//!   136×482 padded), natural = padded_tl rows of tw/2 (272×241). The DNG
//!   decoder clips the decode to the tile area, so the pad rows are
//!   discarded on read. (The pre-measurement inference "last row 482×133"
//!   was wrong — every last-row reference tile is full-272 geometry.)
//! - per-tile adaptive orientation + PSV (the 3 candidates, measured
//!   on all 32,400 lossless tiles of A001 — the ONLY combos observed):
//!   {wrapped PSV7, wrapped PSV2, natural PSV1}; Ss=1 ⇔ natural in every
//!   frame. The encoder trial-encodes the three and picks per the
//!   per-gate selection key — the 3K gate (3024×2010): the lowest
//!   expected pre-stuffing bit count (the histogram pass's
//!   Σ freq × (code_len + nbits); measured ); the other gates:
//!   the 0.1.0 smallest post-pad stream (the byte-invariance pin; see
//!   `encode_tile_candidates`) — see `encode_tile`.
//! - Per-tile (per-stream) Huffman tables: libjpeg lossless mode forces
//!   `optimize_coding=TRUE` (2-pass encode, tables fit to the stream) —
//!   the DNG "per-tile tables" property, for free.
//!
//! FFI: raw libjpeg C API via the opaque-handle shim `ljpeg_shim.c`
//! (the jpeg_compress_struct layout is internal; Homebrew does not
//! install jpegint.h). Key API facts (libjpeg-turbo 3.2.0, 8-bit JSAMPLE
//! build — the measured facts):
//! - `in_color_space = JCS_UNKNOWN` + `input_components = 2` keeps
//!   num_components=2 through `jpeg_set_defaults` and the lossless
//!   re-default in `jinit_compress_master` (JCS_GRAYSCALE/RGB would force
//!   1/3 components).
//! - 12-bit precision lossless I/O MUST use `jpeg12_write_scanlines` /
//!   `jpeg12_read_scanlines` (J12SAMPLE = `short`); the plain
//!   `jpeg_write_scanlines` rejects data_precision>8 in an 8-bit build.
//! - `jpeg_enable_lossless(cinfo, 7, 0)` sets master->lossless + Ss/Se/Ah/Al.
//! - `jpeg_mem_dest` / `jpeg_mem_src` (public API) for in-memory streams.
//! - **CRITICAL (the pixel-order fix):** for multi-component raw
//!   input the scanline rows MUST be **per-pixel interleaved**
//!   `[c0(x=0), c1(x=0), c0(x=1), c1(x=1), ...]` — libjpeg's `null_convert`
//!   (JCS_UNKNOWN, nc=2, jccolor.c) de-interleaves exactly that layout
//!   (`comp[ci][x] = row[x*nc + ci]`). Passing component-BLOCK rows
//!   `[c0 row | c1 row]` (the pre-fix bug) makes libjpeg silently encode
//!   de-interleaved planes: the bitstream is still standard T.81 and
//!   libjpeg's own decode cancels the error (self-roundtrip "passes"),
//!   but every standard decoder (LibRaw/DNG-SDK/Resolve, this module's
//!   `ljpeg_ref`) reads wrong pixels (78% mismatch on A001 f1).
//!
//! Decode: the ACCEPTANCE path is `ljpeg_ref::decode` — the Rust port of
//! `tools/ljpeg_decode.py`, the PRD's canonical T.81-order reference
//! decoder (guardrail G3: libjpeg self-roundtrip is never the acceptance
//! gate). The libjpeg FFI decode (`decode_tile_ljpeg`) is kept as a fast
//! pre-check only (it is standard-order, so post-fix it agrees with
//! `ljpeg_ref` on our streams).

use thiserror::Error;

pub const TILE_W: u32 = 482;
pub const TILE_H: u32 = 272;

/// Open Gate 3K frame dimensions (the UNOFFICIAL mode 98 of the modified
/// firmware 5.02 line; measured on clip A001_006, 114 frames, 24 fps).
pub const GATE_3K_W: u32 = 3024;
pub const GATE_3K_H: u32 = 2010;

/// The 3K gate's tile geometry (the measured reference contract,
/// — the A001_006 golden: a 12×8 grid, 3024 = 12×252 exact
/// with one 246 px edge row encoded at the FULL 252 geometry, the
/// even/odd COLUMN split, the same 3-candidate adaptive mechanism).
pub const GATE_3K_TILE_W: u32 = 252;
pub const GATE_3K_TILE_H: u32 = 252;

/// FHD frame dimensions (the fp's 1936×1090 readout; the profile rows
/// `1936 1090 12/10/8 archive` — the native depths 8/10/12).
pub const GATE_FHD_W: u32 = 1936;
pub const GATE_FHD_H: u32 = 1090;

/// Open Gate 2K frame dimensions (the 2016×1344 readout of the modified
/// firmware 5.02 line — the Open Gate 2K geometry; the profile rows
/// `2016 1344 12/10/8 archive`, the @10/@8 rows added at the 
/// measurement — 's onboarding).
pub const GATE_OG2K_W: u32 = 2016;
pub const GATE_OG2K_H: u32 = 1344;

/// The FHD gate's tile geometry (the measured reference contract,
/// 12-clip batch — the per-(geometry ×
/// input depth) grid rule: the FHD grid VARIES WITH DEPTH within the
/// geometry). The @12 grid: 242×274 (242×8 = 1936 exact; the last row
/// 1090 − 3×274 = 268 encoded at the FULL 274 geometry — the generic
/// edge-tile padding rule). The @8 input FOLDS to the @12 grid (the
/// measured fold rule — the measured @8 row stores the @12 grid at
/// BPS10; ours stores BPS8, no promotion — ). The @10 grid:
/// 484×274 (484×4 = 1936 exact; same 268 edge row). The 8→10 promotion
/// the reference applies to its @8 output is NOT replicated (the
/// per-gate boundary note in `docs/camera-profiles.md`).
pub const GATE_FHD_TILE_W_12: u32 = 242;
pub const GATE_FHD_TILE_W_10: u32 = 484;
pub const GATE_FHD_TILE_H: u32 = 274;

/// The FHD ds2x gate's geometry — the 1936×1090 gate's measured
/// downscale2x output (1936/2 × 1090/2 = 968×545, the 
/// FHD mode rows): the per-depth grids ride the SOURCE's FHD
/// per-depth grid (`gate_tile_dims_depth` on 1936×1090: 242×274 @12/@8,
/// 484×274 @10), the measured family is `DS2X_FHD_CANDIDATES` (the
/// grid×mode-keyed 2-member family — the ds2x geometry IS the mode key),
/// and the bottom-row tiles are the 271-content-row half-row tiles on
/// the 274-row plane (the odd-height interop shape — the decode drill's
/// content-rows-only semantics, the decision (b)).
pub const GATE_FHD_DS2X_W: u32 = 968;
pub const GATE_FHD_DS2X_H: u32 = 545;

/// The OG2K ds2x gate's geometry — the 2016×1344 gate's measured
/// downscale2x output (2016/2 × 1344/2 = 1008×672, the 
/// OG2K mode rows, ): the grids ride the SOURCE's OG2K
/// depth-invariant 252×336 grid (`gate_tile_dims_depth` on 2016×1344 —
/// 4×2 = 8 tiles at every depth), the measured family is
/// `DS2X_OG2K_CANDIDATES` (the grid×mode-keyed 3-member family — the ds2x
/// geometry IS the mode key; unlike the FHD ds2x's 2-member family, W7
/// IS observed on the OG2K ds2x corpus — the census), and
/// the edge tiles are FULL-tile rows only (1008 = 4×252, 672 = 2×336
/// exact — the measured no-half-row verdict; the decode drill runs
/// the plain full-tile semantics).
pub const GATE_OG2K_DS2X_W: u32 = 1008;
pub const GATE_OG2K_DS2X_H: u32 = 672;

/// The OG3K ds2x gate's geometry — the 3024×2010 gate's measured
/// downscale2x output (3024/2 × 2010/2 = 1512×1005, the 
/// OG3K mode rows): the grids ride the SOURCE's OG3K depth-
/// invariant 252×252 grid (`gate_tile_dims_depth` on 3024×2010 — 6×4 =
/// 24 tiles at every depth: 1512 = 6×252 exact, 1005 = 3×252 + 249),
/// the measured family is `DS2X_OG3K_CANDIDATES` (the grid×mode-keyed
/// 3-member family — the ds2x geometry IS the mode key; the census:
/// W7 observed on the ds2x corpus — 5–6 tiles/frame — the 3-member set
/// EXACTLY), and the bottom-row tiles are the 249-content-row half-row
/// tiles on the 252-row plane (the odd-height interop shape — the
/// decode drill's content-rows-only semantics, the decision
/// (b) by analogy: the measured the pad mechanism — the middle pad
/// row copy-of-last-row, the outer pads synthetic, the engine parity
/// ×54/54 — report.md §6).
pub const GATE_OG3K_DS2X_W: u32 = 1512;
pub const GATE_OG3K_DS2X_H: u32 = 1005;

/// The UHD ds2x gate's geometry — the 3856×2170 gate's measured
/// downscale2x output (3856/2 × 2170/2 = 1928×1085, the 
/// UHD mode rows, ): the grids ride the SOURCE's UHD
/// per-depth grid (`gate_tile_dims_depth` on 3856×2170 — 964×272 @10,
/// 482×272 @8 — the per-depth inheritance): 1928 = 2×964 exact @10 /
/// 4×482 exact @8; 1085 = 3×272 + 269 at BOTH grids — the bottom-row
/// tiles are the 269-content-row half-row tiles on the 272-row plane
/// (the odd-height interop shape — the decode drill's content-rows-
/// only semantics, the decision (b) — the measured the
/// pad class: the middle pad row copy-of-last-row, the outer pads
/// synthetic, the H1 overlap window rejected (0 hits), the engine
/// parity ×48/48 — report.md §6). The measured families are GRID-
/// KEYED (the first ds2x geometry with TWO measured grids — the per-
/// depth inheritance): the 964×272 grid → `DS2X_UHD_964_CANDIDATES`
/// (the 2-member {W2, N1} — W7 never observed on the ds2x-@10 corpus
/// — the census); the 482×272 grid → `DS2X_UHD_482_CANDIDATES`
/// (the 3-member {W7, W2, N1} — the @8 row + the 0.1.0-era legacy
/// ds2x output, both the 482×272 grid — the byte-frozen mode control
/// kept decodable, the backward-compat pattern).
pub const GATE_UHD_DS2X_W: u32 = 1928;
pub const GATE_UHD_DS2X_H: u32 = 1085;

/// The Open Gate 2K gate's tile geometry (the measured reference
/// contract, 12-clip batch — the per-gate
/// grid, the onboarding G2): 252×336 (252×8 = 2016 exact,
/// 336×4 = 1344 exact — a clean 8×4 = 32-tile grid with NO partial
/// tiles). The grid is DEPTH-INVARIANT for this gate (the measured
/// rule — all three depths 8/10/12 = 252×336; unlike the FHD's
/// per-depth grids). The 8→10 promotion the reference applies to its
/// @8 output is NOT replicated (our @8 output stores BPS8 —,
/// the per-gate boundary note in `docs/camera-profiles.md`).
pub const GATE_OG2K_TILE_W: u32 = 252;
pub const GATE_OG2K_TILE_H: u32 = 336;

/// UHD frame dimensions (the 3856×2170 readout — the shipped pair; the
/// profile rows `3856 2170 12/10/8 archive`).
pub const GATE_UHD_W: u32 = 3856;
pub const GATE_UHD_H: u32 = 2170;

/// The UHD gate's tile geometry (the measured reference contract,
/// 12-clip batch — the per-(geometry ×
/// input depth) grid rule, the onboarding G4, the LAST
/// measured row): the @10 grid 964×272 (964×4 = 3856 EXACT — no edge
/// column; 2170 = 7×272 + 266 — the LAST ROW 266 px encoded at the
/// FULL 272 geometry — the generic edge-tile padding rule; 4×8 = 32
/// tiles). The @12 + @8 grids KEEP the 482×272 default UNCHANGED (the
/// @12 = the in-profile measured match — the 0.1.0-era A001_001
/// measurement + the re-verification; the @8 = the
/// reference's OWN measured 482×272 choice at @8 — its @8 output also
/// runs 482×272, storing BPS10 via the measured identity promotion;
/// ours stores BPS8 — the no-promotion). The 964×272 grid's
/// measured candidate family = the 482 legacy family's members
/// {W-PSV7, W-PSV2, N-PSV1} — the 96/96-tile census over the mirrored
/// A001_002 @10 corpus: every stored reference tile byte-identical to
/// exactly one re-encode from `CANDIDATES`, ZERO outside (
/// ; `gate_candidates` / `gate_candidates_for_grid` route the
/// 964×272 grid to `CANDIDATES` — no separate family constant).
pub const GATE_UHD_TILE_W_10: u32 = 964;

/// Per-gate tile geometry (the measured reference contract): the
/// 3024×2010 Open Gate 3K frame uses the 252×252 grid; every other
/// geometry keeps the 482×272 grid (the byte-invariance contract).
///
/// The GEOMETRY-ONLY (legacy/default) contract: the FHD gate's
/// per-depth grid (242×274 @12/8, 484×274 @10 — the measured 
/// contract) + the OG2K gate's depth-invariant grid (252×336
/// — the measured row) + the UHD gate's per-depth grid
/// (964×272 @10 — the measured row; 482×272 @12/@8) live in
/// `gate_tile_dims_depth`; this function returns the FHD's + OG2K's
/// PRE-MEASUREMENT 482×272 default (the legacy grid — the decode-side
/// backward-compat acceptance of the pre-fix FHD/OG2K archives + every
/// other geometry's unchanged contract). The production encode path
/// uses `Grid::for_depth` (the depth-aware seam); this function +
/// `Grid::new` keep their byte-invariant behavior for the remaining
/// callers.
pub fn gate_tile_dims(frame_w: u32, frame_h: u32) -> (u32, u32) {
    if frame_w == GATE_3K_W && frame_h == GATE_3K_H {
        (GATE_3K_TILE_W, GATE_3K_TILE_H)
    } else {
        (TILE_W, TILE_H)
    }
}

/// Per-(geometry × depth) tile geometry (the canonical measured
/// reference contract): the grid VARIES WITH DEPTH within the FHD
/// geometry (the measured rule): 1936×1090 @12 →
/// 242×274 (8×4 = 32 tiles), @10 → 484×274 (4×4 = 16 tiles), @8 →
/// 242×274 (the 8-bit input folds to the 12-bit grid — the measured
/// fold rule; our @8 output stores BPS8, the reference stores BPS10 —
/// , the promotion is NOT replicated). The UHD geometry varies
/// at @10 ONLY (the measured rule — the 
/// onboarding G4): 3856×2170 @10 → 964×272 (4×8 = 32 tiles; 964×4
/// = 3856 exact; the last row 266 px at the full 272 geometry), @12/
/// @8 → 482×272 UNCHANGED (the @12 in-profile measured match; the @8
/// the measured 482×272 choice). The other measured
/// rows are depth-invariant: 3024×2010 → 252×252 (the row)
/// and 2016×1344 → 252×336 (the row — all depths, the
/// measured depth-invariance); every other geometry (incl. the FHD/
/// UHD depths outside the measured arms — UNREACHABLE in the encode
/// path: the tool unpacks 8/10/12 only) → the 482×272 default.
/// `depth` = the ENCODED frame's BitsPerSample (the native-depth
/// path: the source BPS — `TilePlan bps_patch = None`).
pub fn gate_tile_dims_depth(frame_w: u32, frame_h: u32, depth: u32) -> (u32, u32) {
    if frame_w == GATE_3K_W && frame_h == GATE_3K_H {
        (GATE_3K_TILE_W, GATE_3K_TILE_H)
    } else if frame_w == GATE_FHD_W && frame_h == GATE_FHD_H {
        match depth {
            10 => (GATE_FHD_TILE_W_10, GATE_FHD_TILE_H),
            8 | 12 => (GATE_FHD_TILE_W_12, GATE_FHD_TILE_H),
            _ => (TILE_W, TILE_H),
        }
    } else if frame_w == GATE_OG2K_W && frame_h == GATE_OG2K_H {
        // The OG2K grid is depth-invariant (the measured rule — all
        // three depths = 252×336; the `depth` argument is part of the
        // canonical signature, not a selector here).
        (GATE_OG2K_TILE_W, GATE_OG2K_TILE_H)
    } else if frame_w == GATE_UHD_W && frame_h == GATE_UHD_H {
 // The UHD grid varies at @10 ONLY (the measured rule —
 // the onboarding G4): @10 → the 964×272 grid (4×8 =
        // 32 tiles); @12/@8 → the 482×272 default UNCHANGED (the @12
        // in-profile measured match — the 0.1.0-era measurement + the
 // re-verification; the @8 the
        // measured 482×272 choice; the other depths are UNREACHABLE in
        // the encode path: the tool unpacks 8/10/12 only).
        match depth {
            10 => (GATE_UHD_TILE_W_10, TILE_H),
            _ => (TILE_W, TILE_H),
        }
    } else {
        (TILE_W, TILE_H)
    }
}

/// The Open Gate 3K gate (the per-gate grid + the measured header
/// re-layout contract in `surgery::apply_tiled_3k`).
pub fn is_3k_gate(frame_w: u32, frame_h: u32) -> bool {
    frame_w == GATE_3K_W && frame_h == GATE_3K_H
}

/// The FHD gate (the per-(geometry × depth) grid — the measured
/// contract: 242×274 @12/8, 484×274 @10; the
/// surgical `apply_tiled` layout, NOT the 3K re-layout).
pub fn is_fhd_gate(frame_w: u32, frame_h: u32) -> bool {
    frame_w == GATE_FHD_W && frame_h == GATE_FHD_H
}

/// The FHD ds2x gate (the measured 968×545 downscale2x output of the
/// FHD gate — see `GATE_FHD_DS2X_W`/`GATE_FHD_DS2X_H`): the decode-side
/// grid eligibility (the per-depth grids 242×274 / 484×274) + the
/// grid×mode-keyed family routing (`gate_candidates_for_grid` →
/// `DS2X_FHD_CANDIDATES`).
pub fn is_fhd_ds2x_gate(frame_w: u32, frame_h: u32) -> bool {
    frame_w == GATE_FHD_DS2X_W && frame_h == GATE_FHD_DS2X_H
}

/// The OG2K ds2x gate (the measured 1008×672 downscale2x output of the
/// OG2K gate — see `GATE_OG2K_DS2X_W`/`GATE_OG2K_DS2X_H`): the decode-
/// side grid eligibility (the depth-invariant 252×336 grid) + the
/// grid×mode-keyed family routing (`gate_candidates_for_grid` →
/// `DS2X_OG2K_CANDIDATES`).
pub fn is_og2k_ds2x_gate(frame_w: u32, frame_h: u32) -> bool {
    frame_w == GATE_OG2K_DS2X_W && frame_h == GATE_OG2K_DS2X_H
}

/// The OG3K ds2x gate (the measured 1512×1005 downscale2x output of the
/// OG3K gate — see `GATE_OG3K_DS2X_W`/`GATE_OG3K_DS2X_H`): the decode-
/// side grid eligibility (the depth-invariant 252×252 grid — 6×4 = 24
/// tiles) + the grid×mode-keyed family routing
/// (`gate_candidates_for_grid` → `DS2X_OG3K_CANDIDATES`).
pub fn is_og3k_ds2x_gate(frame_w: u32, frame_h: u32) -> bool {
    frame_w == GATE_OG3K_DS2X_W && frame_h == GATE_OG3K_DS2X_H
}

/// The UHD ds2x gate (the measured 1928×1085 downscale2x output of the
/// UHD gate — see `GATE_UHD_DS2X_W`/`GATE_UHD_DS2X_H`): the decode-
/// side grid eligibility (the per-depth grids 964×272 @10 / 482×272
/// @8 — the per-depth inheritance — + the 0.1.0-era legacy 482×272
/// mode output) + the grid-keyed family routing
/// (`gate_candidates_for_grid` → `DS2X_UHD_964_CANDIDATES` /
/// `DS2X_UHD_482_CANDIDATES` — the first ds2x geometry with two
/// measured grids: the grid IS the family key here — the ds2x mode
/// plus the per-depth source grid).
pub fn is_uhd_ds2x_gate(frame_w: u32, frame_h: u32) -> bool {
    frame_w == GATE_UHD_DS2X_W && frame_h == GATE_UHD_DS2X_H
}

/// The Open Gate 2K gate (the per-gate grid — the measured 
/// contract: 252×336 depth-invariant; the surgical `apply_tiled`
/// layout — the boundary: the header packing is free, the
/// reference's own non-uniform OG2K packing is NOT replicated — the
/// FHD precedent, the maintainer's NLE-verified surgical grid output).
pub fn is_og2k_gate(frame_w: u32, frame_h: u32) -> bool {
    frame_w == GATE_OG2K_W && frame_h == GATE_OG2K_H
}

/// The UHD gate (the 3856×2170 shipped pair — the per-(geometry ×
/// depth) grid — the measured contract: 964×272
/// @10, 482×272 @12/@8 UNCHANGED; the surgical `apply_tiled` layout —
/// the byte-surgery design, grid-generic via the TilePlan).
pub fn is_uhd_gate(frame_w: u32, frame_h: u32) -> bool {
    frame_w == GATE_UHD_W && frame_h == GATE_UHD_H
}

/// The tile height the plane is padded to before orientation (reference
/// contract, measured): last-row tiles (tl=266/269) are
/// encoded with FULL tile geometry (136×482 wrapped / 272×241 natural);
/// the pad rows repeat the last two real rows alternately (CFA-phase
/// preserving). Full tiles (tl=272) are unchanged.
pub fn padded_tl(tl: u32) -> u32 {
    padded_tl_for(tl, TILE_H)
}

/// `padded_tl` for an explicit tile height (the per-gate grids — the
/// 482 contract keeps `padded_tl`; the 3K gate's 246 px edge row pads
/// to the full 252 geometry the same way the 482 gate's ragged rows
/// pad to 272).
pub fn padded_tl_for(tl: u32, th: u32) -> u32 {
    tl.div_ceil(th) * th
}

/// Plane orientation of the two parity components.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Orient {
    /// Two tile rows per plane row (same-CFA-phase up-neighbor in the
    /// wrapped pair); plane = (padded_tl/2) × tw.
    Wrapped,
    /// One tile row per plane row; plane = padded_tl × tw/2.
    Natural,
}

#[derive(Error, Debug, Clone, PartialEq)]
pub enum TileError {
    #[error("odd tile width {0}; even/odd column planes need an even width")]
    OddTileWidth(u32),
    #[error("tile ({r},{c}) out of range for grid {gcols}x{grow}")]
    TileOutOfRange {
        r: u32,
        c: u32,
        gcols: u32,
        grow: u32,
    },
    #[error("libjpeg encode failed: {0}")]
    Encode(String),
    #[error("libjpeg decode failed: {0}")]
    Decode(String),
    #[error("decoded tile {rows}x{cols} does not match expected plane geometry {eh}x{ew} (wrapped) or {nh}x{nw} (natural)")]
    GeometryMismatch {
        rows: u32,
        cols: u32,
        ew: u32,
        eh: u32,
        nw: u32,
        nh: u32,
    },
}

/// Tile grid for a frame: `ceil(w/tw)` columns × `ceil(h/th)` rows, where
/// (tw, th) = `gate_tile_dims` (the per-gate geometry: 482×272 for every
/// geometry EXCEPT the 3024×2010 Open Gate 3K gate — 252×252, 12×8 =
/// 96 tiles). A001 3856×2170 → 8×8 (64 tiles); 1928×1085 (future
/// downscale2x) → 4×4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grid {
    pub cols: u32,
    pub rows: u32,
    /// The tile width/height of this grid (the per-gate geometry — the
    /// 482×272 contract or the 3K gate's 252×252).
    pub tw: u32,
    pub th: u32,
}

impl Grid {
    pub fn new(frame_w: u32, frame_h: u32) -> Grid {
        let (tw, th) = gate_tile_dims(frame_w, frame_h);
        Grid::for_dims(frame_w, frame_h, tw, th)
    }

    /// A grid at the per-(geometry × depth) contract (the production
    /// encode path — the FHD gate's depth-varying grid: 242×274 @12/8,
    /// 484×274 @10; the OG2K gate's depth-invariant grid 252×336 at all
 /// depths — the measured rows; every other
    /// (geometry × depth) combination the unchanged contract — the
    /// byte-invariance pin).
    pub fn for_depth(frame_w: u32, frame_h: u32, depth: u32) -> Grid {
        let (tw, th) = gate_tile_dims_depth(frame_w, frame_h, depth);
        Grid::for_dims(frame_w, frame_h, tw, th)
    }

    /// A grid for EXPLICIT tile dimensions: the decode side derives the
    /// grid from the FILE's 322/323 values (the legacy 482×272 3K
    /// archives decode alongside the new 252×252 ones — 7×8 vs 12×8
    /// over the same frame).
    pub fn for_dims(frame_w: u32, frame_h: u32, tw: u32, th: u32) -> Grid {
        Grid {
            cols: frame_w.div_ceil(tw),
            rows: frame_h.div_ceil(th),
            tw,
            th,
        }
    }
}

/// The mosaic region covered by tile (r, c): row-major grid, last row/col
/// clipped to the frame edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TileRect {
    pub x0: u32,
    pub y0: u32,
    pub tw: u32,
    pub tl: u32,
}

pub fn tile_region(
    frame_w: u32,
    frame_h: u32,
    g: &Grid,
    r: u32,
    c: u32,
) -> Result<TileRect, TileError> {
    if r >= g.rows || c >= g.cols {
        return Err(TileError::TileOutOfRange {
            r,
            c,
            gcols: g.cols,
            grow: g.rows,
        });
    }
    let tw = g.tw.min(frame_w - c * g.tw);
    let tl = g.th.min(frame_h - r * g.th);
    Ok(TileRect {
        x0: c * g.tw,
        y0: r * g.th,
        tw,
        tl,
    })
}

/// SOF3 geometry of each parity plane for a tile of `tw`×`tl` mosaic
/// pixels, BEFORE the measured-contract padding (the historical
/// divisible-or-natural rule; kept for reference/tests — the encode path
/// uses `planes_from_tile` with an explicit `Orient` + padding).
pub fn plane_orient(tw: u32, tl: u32) -> (u32, u32) {
    debug_assert!(tw % 2 == 0, "even tile width required");
    if tl % 2 == 0 && tl * (tw / 2) % tw == 0 {
        (tl / 2, tw) // wrapped: tl/2 rows of tw (= two tile rows per plane row)
    } else {
        (tl, tw / 2) // natural orientation
    }
}

/// The divisible-or-natural rule PLUS the LibRaw decoder-safety override
/// (measured on downscale2x): LibRaw's `lossless_dng_load_raw`
/// (dng.cpp, the SOF3 branch) takes a special path when
/// `tiff_samples==1 && jh.clrs>1 && jh.clrs*jwide == raw_width` — with
/// jwide = SOF_width×clrs (clrs=2) that is `4×SOF_width == raw_width`.
/// In that path each SOF row is mapped to FOUR mosaic rows (row/col state
/// persists across SOF rows) and reads stale row-buffer samples → ~85%
/// wrong pixels (rows 2+ zero). For the wrapped orientation SOF_width =
/// tw, so a frame with `4×tw == frame_w` (A001 downscale: 4×482 = 1928)
/// hits it on every wrapped tile — full-resolution 3856 does NOT (4×482 =
/// 1928 ≠ 3856), which is why the MVP passed rawpy 0/8,367,520 while the
/// downscale output failed with 65% mismatch. The natural orientation
/// (SOF_width = tw/2) hits the branch when `2×tw == frame_w`. Rule: if the
/// auto choice's SOF width would hit the branch and the other orientation
/// is available, use the other one (both can never hit at once: 4tw == fw
/// and 2tw == fw ⇒ tw = 0). The standard else-branch (per-SOF-row raster
/// fill) decodes both orientations pixel-exactly (proven: full-res pass +
/// reference golden's 6 natural tiles + the downscale last-row natural tiles
/// at 0.00% rawpy mismatch).
///
/// SUPERSEDED for the encode path (Resolve media-offline): reference
/// parity wins — the measured encoder WRAPS the ds2x tiles too
/// (and Resolve accepts them; the LibRaw rawpy canary fails on the
/// measured wrapped ds2x tiles as well, so BMD ≠ LibRaw). The encode
/// path now trial-encodes the measured 3 candidates (see `encode_tile`).
/// Kept for reference (and `--verify` of pre-parity files).
pub fn plane_orient_libraw_safe(tw: u32, tl: u32, frame_w: u32) -> (u32, u32) {
    debug_assert!(tw % 2 == 0, "even tile width required");
    let (rows, cols) = plane_orient(tw, tl);
    let auto_hits = 4 * cols == frame_w; // the branch condition on SOF width
    if !auto_hits {
        return (rows, cols);
    }
    if cols == tw {
        (tl, tw / 2) // forced natural (always available: tw even)
    } else if tl % 2 == 0 && tl * (tw / 2) % tw == 0 {
        (tl / 2, tw) // forced wrapped (the safe alternative)
    } else {
        (tl, tw / 2) // no safe alternative; accept (not in the corpus)
    }
}

/// The tile's even/odd column planes in SOF3 orientation.
#[derive(Clone, Debug)]
pub struct Planes {
    /// Tile mosaic size (tw × tl pixels).
    pub rect: TileRect,
    /// SOF3 image size per component (rows × cols).
    pub rows: u32,
    pub cols: u32,
    /// The gate's tile height for this grid (the per-gate geometry —
    /// 272 on the 482×272 grids, 252 on the 3K gate's 252×252 grid);
    /// the full-geometry padding reference for `tile_from_planes`.
    pub th: u32,
    /// Component 0: even columns, row-major in SOF3 orientation (rows*cols).
    pub even: Vec<u16>,
    /// Component 1: odd columns, row-major in SOF3 orientation (rows*cols).
    pub odd: Vec<u16>,
}

/// Extract tile (r, c) from the frame mosaic, pad it to the measured full
/// tile height, and split it into oriented even/odd column planes.
/// `mosaic` is the full frame, row-major, `frame_w` × `frame_h` samples.
///
/// Padding (reference contract, measured, pixel-exact on the
/// full-resolution presets and structurally confirmed on ds2x): tile rows
/// tl..padded_tl−1 repeat the last two real rows alternately — pad row y =
/// row tl−2+(y−tl)%2 (CFA-phase preserving). With `Orient::Wrapped` the
/// pad lands as repeated plane rows; with `Orient::Natural` as repeated
/// mosaic rows. `tl < 2` (not in the corpus) degenerates to repeating row
/// 0. DNG decoders clip the plane to the tile area, so the pad rows never
/// reach the pixel data.
pub fn planes_from_tile(
    mosaic: &[u16],
    frame_w: u32,
    frame_h: u32,
    g: &Grid,
    r: u32,
    c: u32,
    oriented: Orient,
) -> Result<Planes, TileError> {
    let rect = tile_region(frame_w, frame_h, g, r, c)?;
    if rect.tw % 2 != 0 {
        return Err(TileError::OddTileWidth(rect.tw));
    }
    let pad_tl = padded_tl_for(rect.tl, g.th);
    let (rows, cols) = match oriented {
        Orient::Wrapped => (pad_tl / 2, rect.tw),
        Orient::Natural => (pad_tl, rect.tw / 2),
    };
    let (rows, cols, half) = (rows as usize, cols as usize, (rect.tw / 2) as usize);
    let n = rows * cols;
    let mut even = vec![0u16; n];
    let mut odd = vec![0u16; n];
    let base = (rect.y0 as usize) * (frame_w as usize) + rect.x0 as usize;
    let tw = rect.tw as usize;
    let tl = rect.tl as usize;
    let wrapped = oriented == Orient::Wrapped;
    for y in 0..pad_tl as usize {
        // Reference pad rule: alternate repeats of the last two real rows
        // (tl=266 → rows 264,265,264,265,264,265; tl=269 → 267,268,267).
        let src_y = if y < tl {
            y
        } else if tl >= 2 {
            (tl - 2) + (y - tl) % 2
        } else {
            y % tl.max(1)
        };
        let row =
            &mosaic[base + src_y * (frame_w as usize)..base + src_y * (frame_w as usize) + tw];
        // Oriented row index: wrapped → y/2 (two tile rows per plane row),
        // natural → y. Wrapped: first tile-row samples go to the first half
        // of the oriented row, second tile-row samples to the second half.
        let (oy, ox0) = if wrapped {
            (y / 2, (y % 2) * half)
        } else {
            (y, 0)
        };
        for x in 0..half {
            even[oy * cols + ox0 + x] = row[2 * x];
            odd[oy * cols + ox0 + x] = row[2 * x + 1];
        }
    }
    Ok(Planes {
        rect,
        rows: rows as u32,
        cols: cols as u32,
        th: g.th,
        even,
        odd,
    })
}

/// Inverse of `planes_from_tile`: reassemble the tile mosaic (tw × tl,
/// row-major) from oriented even/odd planes. Orientation is inferred from
/// (rows, cols, tw, tl): wrapped when `cols == tw` and rows × 2 is the
/// padded tile height (or the legacy unpadded tl for even tl), natural
/// when `cols == tw/2` and rows is the padded tile height (or the legacy
/// unpadded tl). Both candidates are checked so adaptive-orientation files
/// (the measured natural tiles, the measured padded last-row tiles — all 64
/// f1 tiles) reassemble correctly. Pad rows (rows ≥ tl) are discarded: the
/// output is exactly tw × tl.
pub fn tile_from_planes(p: &Planes) -> Result<Vec<u16>, TileError> {
    let TileRect { tw, tl, .. } = p.rect;
    if tw % 2 != 0 {
        return Err(TileError::OddTileWidth(tw));
    }
    let half = (tw / 2) as usize;
    let (rows, cols) = (p.rows, p.cols);
    let cols_u = cols as usize;
    let h = rows;
    let pad = padded_tl_for(tl, p.th);
    let wrapped = cols == tw && (h * 2 == pad || (tl % 2 == 0 && h * 2 == tl));
    let natural = (cols as usize) == half && (h == pad || h == tl);
    if !wrapped && !natural {
        // Expected plane geometry: wrapped = (padded_tl/2 × tw) [legacy
        // (tl/2 × tw) for even tl]; natural = (padded_tl × tw/2) [legacy
        // (tl × tw/2)].
        let (ew, eh) = plane_orient(tw, tl);
        return Err(TileError::GeometryMismatch {
            rows,
            cols,
            ew,
            eh,
            nw: half as u32,
            nh: tl,
        });
    }
    let mut out = vec![0u16; (tw * tl) as usize];
    if wrapped {
        for y in 0..tl as usize {
            let oy = y / 2;
            let ox0 = (y % 2) * half;
            for x in 0..half {
                // plane row oy holds tile rows 2oy (samples ox0..ox0+half)
                // and 2oy+1 (samples half..half+half)
                let s_even0 = p.even[oy * cols_u + ox0 + x];
                let s_odd0 = p.odd[oy * cols_u + ox0 + x];
                out[y * tw as usize + 2 * x] = s_even0;
                out[y * tw as usize + 2 * x + 1] = s_odd0;
                if y + 1 < tl as usize {
                    let s_even1 = p.even[oy * cols_u + half + x];
                    let s_odd1 = p.odd[oy * cols_u + half + x];
                    out[(y + 1) * tw as usize + 2 * x] = s_even1;
                    out[(y + 1) * tw as usize + 2 * x + 1] = s_odd1;
                }
            }
        }
    } else {
        for y in 0..tl as usize {
            for x in 0..half {
                out[y * tw as usize + 2 * x] = p.even[y * cols_u + x];
                out[y * tw as usize + 2 * x + 1] = p.odd[y * cols_u + x];
            }
        }
    }
    Ok(out)
}

// --------------------------------------------------------------------- FFI

// C ABI declarations live in `crate::ljpeg_ffi` (single home, ).
use crate::ljpeg_ffi::{
    ljpeg_comp_error, ljpeg_comp_free, ljpeg_comp_new, ljpeg_decode_lossless, ljpeg_decomp_error,
    ljpeg_decomp_free, ljpeg_decomp_new, ljpeg_encode_lossless2, ljpeg_free_buffer,
};

fn err_str(ptr: *const core::ffi::c_char, default: &str) -> String {
    if ptr.is_null() {
        return default.to_string();
    }
    // SAFETY: non-null C string owned by the shim handle (valid until the
    // next call on it), read only through `CStr`.
    unsafe {
        core::ffi::CStr::from_ptr(ptr)
            .to_string_lossy()
            .into_owned()
    }
}

/// Encode one tile (from `planes`, produced by `planes_from_tile`) as a
/// 2-component lossless SOF3 JPEG stream of `precision` bits per sample
/// (12 = lossless mode, 10 = log10 mode, 8 = native 8-bit lossless;
/// `psv` = predictor selection value, libjpeg/DNG-SDK Table H.1 numbering
/// 1..7; per-tile Huffman via libjpeg's 2-pass optimization). The stream
/// is in STANDARD T.81 order (per-MCU symbols, per-component predictors)
/// — decodable pixel-exactly by `ljpeg_ref` (and LibRaw/DNG-SDK/Resolve).
/// See the module docs for the per-pixel input layout requirement (the
/// pixel-order fix).
pub fn encode_planes(p: &Planes, precision: u32, psv: i32) -> Result<Vec<u8>, TileError> {
    if precision != 8 && precision != 10 && precision != 12 {
        return Err(TileError::Encode(format!(
            "unsupported precision {precision} (need 8, 10 or 12)"
        )));
    }
    if !(1..=7).contains(&psv) {
        return Err(TileError::Encode(format!(
            "unsupported PSV {psv} (need 1..7)"
        )));
    }
    // SAFETY: `ljpeg_comp_new` is the shim's allocator (calloc); the
    // pointer is null-checked here and `ljpeg_comp_free`d on every exit
    // path below.
    let h = unsafe { ljpeg_comp_new() };
    if h.is_null() {
        return Err(TileError::Encode("ljpeg_comp_new returned null".into()));
    }
    // One per-PIXEL interleaved row buffer: rows × (2*cols) shorts,
    // row y = [even(y,0), odd(y,0), even(y,1), odd(y,1), ...].
    // libjpeg's null_convert de-interleaves this layout into the two
    // component planes; component-BLOCK rows would silently encode the
    // wrong (de-interleaved) planes — see the module docs.
    let n = (p.rows * p.cols * 2) as usize;
    let mut rowbuf = vec![0i16; n];
    for y in 0..p.rows as usize {
        let s = y * p.cols as usize;
        let d = y * 2 * p.cols as usize;
        for x in 0..p.cols as usize {
            rowbuf[d + 2 * x] = p.even[s + x] as i16;
            rowbuf[d + 2 * x + 1] = p.odd[s + x] as i16;
        }
    }
    let mut outbuf: *mut u8 = std::ptr::null_mut();
    let mut outsize: core::ffi::c_ulong = 0;
    // SAFETY: live handle; `rowbuf` (per-pixel interleaved, the layout the
    // shim documents) outlives the call; `psv`/`precision` range-checked
    // above; `&mut outbuf/outsize` are null-initialized locals the shim
    // writes. On success `outbuf` is malloc'd by the shim and freed
    // exactly once below.
    let rc = unsafe {
        ljpeg_encode_lossless2(
            h,
            rowbuf.as_ptr(),
            p.cols as core::ffi::c_int,
            p.rows as core::ffi::c_int,
            psv,
            precision as core::ffi::c_int,
            &mut outbuf,
            &mut outsize,
        )
    };
    if rc != 0 {
        let msg = err_str(unsafe { ljpeg_comp_error(h) }, "encode failed");
        unsafe { ljpeg_comp_free(h) };
        return Err(TileError::Encode(msg));
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

/// Decode one tile stream with the CANONICAL T.81-order reference decoder
/// (`ljpeg_ref`, Rust port of tools/ljpeg_decode.py) and reassemble the
/// tile mosaic (tw × tl, row-major). This is the acceptance path (G3).
/// The expected tile geometry (`rect`) disambiguates the plane
/// orientation; both wrapped (cols==tw) and natural (cols==tw/2) layouts
/// are accepted. `expected_precision` must be 10 (log10 codes) or 12
/// (lossless 12-bit samples).
pub fn decode_tile(
    jpeg: &[u8],
    rect: &TileRect,
    expected_precision: u32,
    th: u32,
) -> Result<Vec<u16>, TileError> {
    let (info, comps) = crate::ljpeg_ref::decode(jpeg)
        .map_err(|e| TileError::Decode(format!("golden-model (ljpeg_ref) decode: {e}")))?;
    if info.nf != 2 {
        return Err(TileError::Decode(format!(
            "expected 2 components, got {}",
            info.nf
        )));
    }
    if info.precision != expected_precision {
        return Err(TileError::Decode(format!(
            "expected {expected_precision}-bit precision, got {}",
            info.precision
        )));
    }
    let planes = Planes {
        rect: *rect,
        rows: info.height,
        cols: info.width,
        th,
        even: comps[0].clone(),
        odd: comps[1].clone(),
    };
    tile_from_planes(&planes)
}

/// Decode one tile stream with libjpeg's own lossless decoder — FAST
/// pre-CHECK ONLY, never the acceptance gate (G3). Post the pixel-order
/// fix our streams are standard T.81, so this agrees with `decode_tile`;
/// the pre-fix streams only decoded correctly here (shared
/// mis-interpretation), which is exactly why self-roundtrip cannot gate.
pub fn decode_tile_ljpeg(
    jpeg: &[u8],
    rect: &TileRect,
    expected_precision: u32,
    th: u32,
) -> Result<Vec<u16>, TileError> {
    // SAFETY: `ljpeg_decomp_new` is the shim's allocator (calloc); the
    // pointer is null-checked here and `ljpeg_decomp_free`d on every exit
    // path below.
    let h = unsafe { ljpeg_decomp_new() };
    if h.is_null() {
        return Err(TileError::Decode("ljpeg_decomp_new returned null".into()));
    }
    let mut out: *mut i16 = std::ptr::null_mut();
    let mut w: core::ffi::c_int = 0;
    let mut ht: core::ffi::c_int = 0;
    let mut nc: core::ffi::c_int = 0;
    // SAFETY: live handle; `jpeg` is a `&[u8]` borrow outliving the call,
    // `jpeg.len()` its exact length; the four `&mut` out-params are
    // initialized locals the shim writes. On success `out` is malloc'd by
    // the shim (ht × nc × w shorts) and freed exactly once below.
    let rc = unsafe {
        ljpeg_decode_lossless(
            h,
            jpeg.as_ptr(),
            jpeg.len() as core::ffi::c_long,
            &mut out,
            &mut w,
            &mut ht,
            &mut nc,
            expected_precision as core::ffi::c_int,
        )
    };
    if rc != 0 {
        let msg = err_str(unsafe { ljpeg_decomp_error(h) }, "decode failed");
        unsafe { ljpeg_decomp_free(h) };
        return Err(TileError::Decode(msg));
    }
    let (rows, cols) = (ht as u32, w as u32);
    if nc != 2 {
        unsafe {
            ljpeg_free_buffer(out as *mut core::ffi::c_void);
            ljpeg_decomp_free(h);
        }
        return Err(TileError::Decode(format!(
            "expected 2 components, got {nc}"
        )));
    }
    let total = (rows * cols * 2) as usize;
    // SAFETY: rc == 0 and nc == 2 (checked above) ⇒ `out` holds exactly
    // rows × cols × 2 shorts (the shim's ht × nc × w allocation), read
    // into owned Vecs before the single `ljpeg_free_buffer`.
    let samples = unsafe { std::slice::from_raw_parts(out, total) };
    let mut even = vec![0u16; (rows * cols) as usize];
    let mut odd = vec![0u16; (rows * cols) as usize];
    // libjpeg's multi-component output is per-PIXEL interleaved:
    // row y = [c0(x=0), c1(x=0), c0(x=1), c1(x=1), ...].
    for (y, chunk) in samples.chunks_exact((cols * 2) as usize).enumerate() {
        let s = y * cols as usize;
        for x in 0..cols as usize {
            even[s + x] = chunk[2 * x] as u16;
            odd[s + x] = chunk[2 * x + 1] as u16;
        }
    }
    unsafe {
        ljpeg_free_buffer(out as *mut core::ffi::c_void);
        ljpeg_decomp_free(h);
    }
    let planes = Planes {
        rect: *rect,
        rows,
        cols,
        th,
        even,
        odd,
    };
    tile_from_planes(&planes)
}

/// The 482 legacy per-tile candidate set (measured across ALL 225
/// frames × 3 lossless presets — 32,400 tiles, the ONLY combos
/// observed): wrapped PSV7, wrapped PSV2, natural PSV1. Ss=1 ⇔ natural
/// in every frame. (orient, psv) in trial order. GRID-KEYED scoping
/// (the per-gate discipline): every geometry on the 482×272 grid
/// (UHD/2K + the legacy pre-fix FHD/OG2K archives) AND the 3K gate
/// (252×252 — the handling) AND the UHD @10 grid (964×272 —
/// the measured family: the 96/96-tile census over the
/// mirrored A001_002 @10 corpus found exactly these 3 members, ZERO
/// outside — the 482 legacy family's members ARE the 964×272 grid's
/// measured family, so no separate constant) run on this family; the
/// FHD gate's measured per-gate family  is
/// `FHD_CANDIDATES` (the FHD grids 242×274/484×274 — `gate_candidates`
/// / `gate_candidates_for_grid`) and the OG2K gate's is
/// `OG2K_CANDIDATES` (the 252×336 grid — the measured
/// family, same 3 members as the FHD's).
pub const CANDIDATES: [(Orient, i32); 3] = [
    (Orient::Wrapped, 7),
    (Orient::Wrapped, 2),
    (Orient::Natural, 1),
];

/// The FHD gate's per-tile candidate family (the measured reference
/// contract — 12-clip batch; the 80/80-tile
/// census over the mirrored corpus: every FHD reference tile is
/// byte-identical to exactly one of these 3 re-encodes, the observed
/// combos ONLY wrapped-PSV6 (dominant) / natural-PSV5 / wrapped-PSV7,
/// ZERO tiles outside). GRID-KEYED on the FHD grids {242×274, 484×274}
/// — never global: the 482×272 grid (every geometry, incl. the legacy
/// 482×272 FHD archives) keeps `CANDIDATES` unchanged. Index 0 =
/// Wrapped PSV7 = the global `FAST_CANDIDATE` (the `--fast` FHD byte
/// contract is the same stream as the other gates' index 0). Selection
/// over the family = the existing project selection (size-min — :
/// no new per-gate reference-matching key; the byte choice is free,
/// the round-trip + structure + NLE carry the acceptance).
pub const FHD_CANDIDATES: [(Orient, i32); 3] = [
    (Orient::Wrapped, 7),
    (Orient::Wrapped, 6),
    (Orient::Natural, 5),
];

/// The Open Gate 2K gate's per-tile candidate family (the measured
/// reference contract — 12-clip batch;
/// the 288/288-tile census over the mirrored corpus: every OG2K
/// reference tile is byte-identical to exactly one of these 3
/// re-encodes, the observed combos ONLY wrapped-PSV6 (dominant,
/// 12–19/frame) / wrapped-PSV7 (4–10/frame) / natural-PSV5
/// (9–13/frame), ZERO tiles outside). The same 3 members as the FHD
/// measured family — the measured per-gate family for the
/// NEW grids (252×336 / 242×274 / 484×274) — but the per-gate
/// PROVENANCE is separate (the 9-frame 288-tile OG2K census vs the
/// 9-frame 80-tile FHD census). GRID-KEYED on the OG2K grid 252×336 —
/// never global: the 482×272 grid (every geometry, incl. the legacy
/// pre-fix OG2K archives) keeps `CANDIDATES` unchanged. Index 0 =
/// Wrapped PSV7 = the global `FAST_CANDIDATE` (the `--fast` OG2K byte
/// contract is the same stream as the other gates' index 0). Selection
/// over the family = the existing project selection (size-min — :
/// no new per-gate reference-matching key; the byte choice is free,
/// the round-trip + structure + NLE carry the acceptance).
pub const OG2K_CANDIDATES: [(Orient, i32); 3] = [
    (Orient::Wrapped, 7),
    (Orient::Wrapped, 6),
    (Orient::Natural, 5),
];

/// The FHD ds2x gate's (968×545) per-tile candidate family (the measured
/// reference contract — the census over the mirrored FHD ds2x corpus,
/// ): the top-row tiles match {W-PSV6, N-PSV5} ONLY —
/// W-PSV7 is NEVER observed, so the measured family is this 2-member set
/// EXACTLY (the decision (c): the superset is REJECTED — an
/// unmeasured member is an unmeasured stream class; the A+C boundary —
/// the tool does not decode/encode what it has not measured). The
/// bottom-row tiles (the odd-height half-row tiles — 271 content rows on
/// the 274-row plane) run the decode drill's content-rows-only semantics
/// (the decision (b) — the file's pad rows are synthetic / pre-
/// decimation-derived, NOT reproducible from the stored frame; the engine
/// parity — byte-exact re-encode from the stored components ×10/10 —
/// proves the content is intact). GRID×MODE-keyed: the 242/484×274 grids
/// carry `FHD_CANDIDATES` on the 1936×1090 lossless/log10 rows AND this
/// 2-member family on the 968×545 ds2x rows — the mode is part of the
/// family key (NEVER a grid-only key; the ds2x geometry IS the mode key).
/// Index 0 = Wrapped PSV6 = the measured family's index-0 stream = the
/// `--fast` FHD ds2x stream (the per-gate pattern). Selection over the
/// family = the existing project selection (size-min — : no reference-
/// matching key).
pub const DS2X_FHD_CANDIDATES: [(Orient, i32); 2] = [
    (Orient::Wrapped, 6),
    (Orient::Natural, 5),
];

/// The OG2K ds2x gate's (1008×672) per-tile candidate family (the
/// measured reference contract — the census over the
/// mirrored OG2K ds2x corpus, ): the 24/24-tile
/// census found the observed combos wrapped-PSV6 (3–6/frame) /
/// natural-PSV5 (2–4/frame) / wrapped-PSV7 (1 tile in 4 frames —
/// A001_007@12 f000001, A001_008@10 f000001 + f000097, A001_009@8
/// f000050), ZERO tiles outside. Unlike the FHD ds2x family (where W7
/// was never observed → the 2-member set), W7 IS observed here, so the
/// measured family is the 3-member {W7, W6, N5} set EXACTLY (the
/// decision (c) — family = exactly the measured set; all 3
/// members observed). The same 3 members as `OG2K_CANDIDATES` (the
/// full-resolution rows) — but the per-gate provenance is separate (the
/// ds2x 24/24-tile census vs the lossless 288/288-tile + log10
/// 288/288-tile censuses). GRID×MODE-keyed: the 252×336 grids carry
/// `OG2K_CANDIDATES` on the 2016×1344 lossless/log10 rows AND this
/// family on the 1008×672 ds2x rows — the mode is part of the family
/// key (NEVER a grid-only key; the ds2x geometry IS the mode key). Index
/// 0 = Wrapped PSV7 = the global `FAST_CANDIDATE` = the `--fast` OG2K
/// ds2x stream (the global fast path is the family's index-0 stream at
/// this geometry — the byte contract). Selection over the family = the
/// existing project selection (size-min — : no reference-matching
/// key).
pub const DS2X_OG2K_CANDIDATES: [(Orient, i32); 3] = [
    (Orient::Wrapped, 7),
    (Orient::Wrapped, 6),
    (Orient::Natural, 5),
];

/// The OG3K ds2x gate's (1512×1005) per-tile candidate family (the
/// measured reference contract — the census over the mirrored OG3K
/// ds2x corpus, ): the 24/24-tile census found the
/// observed combos wrapped-PSV2 / wrapped-PSV7 (5–6 tiles/frame) /
/// natural-PSV1, ZERO tiles outside — the measured family is the
/// 3-member {W7, W2, N1} set EXACTLY (the decision (c); the
/// same members as the 3K lossless family `CANDIDATES` — the 252×252
/// grid's measured family — but the per-gate provenance is separate:
/// the ds2x 24/24-tile census vs the lossless 576/576-tile + log10
/// 864/864-tile censuses). The same family EXACTLY is the measured
/// contract for the OG3K LOG10 rows (3024×2010 on the 252×252 grid —
/// the 864/864-tile census: {W7, W2, N1}, W6/N5 never observed — the
/// full-resolution mode rows ride the gate's existing family routing
/// (`CANDIDATES` — the measured members) as the FHD/OG2K pattern). GRID×
/// MODE-keyed: the 252×252 grids carry the 3K family on the 3024×2010
/// lossless/log10 rows AND this family on the 1512×1005 ds2x rows — the
/// mode is part of the family key (NEVER a grid-only key; the ds2x
/// geometry IS the mode key). Index 0 = Wrapped PSV7 = the global
/// `FAST_CANDIDATE` = the `--fast` OG3K ds2x stream (the global fast
/// path is the family's index-0 stream at this geometry — the byte
/// contract, the OG2K ds2x pattern). Selection over the family = the
/// existing project selection (the 1512×1005 geometry is NOT the 3K gate
/// → the 0.1.0 size-min contract; the 3024×2010 log10 rows keep the
/// 3K gate's measured expected-bit-count key — the geometry-keyed
/// in-tree machinery, unchanged).
pub const DS2X_OG3K_CANDIDATES: [(Orient, i32); 3] = [
    (Orient::Wrapped, 7),
    (Orient::Wrapped, 2),
    (Orient::Natural, 1),
];

/// The UHD ds2x gate's (1928×1085) 964×272-grid per-tile candidate
/// family (the measured reference contract — the census
/// over the mirrored UHD ds2x @10 corpus, ): the
/// 24/24-tile census found the observed combos wrapped-PSV2 (5/frame)
/// / natural-PSV1 (3/frame), ZERO tiles outside — the measured family
/// is the 2-member {W2, N1} set EXACTLY (the decision (c):
/// the superset is REJECTED — W-PSV7 is NEVER observed on the ds2x-
/// @10 corpus; the A+C boundary — the tool does not encode/decode
/// what it has not measured). The ds2x @10 row rides the 964×272 grid
/// on 1928×1085 (1928 = 2×964 exact; 1085 = 3×272 + 269 — the bottom-
/// row tiles are the 269-content-row half-row tiles on the 272-row
/// plane — the odd-height interop shape, the decode drill's content-
/// rows-only semantics, the decision (b)). GRID×MODE-keyed with the
/// GRID IN THE KEY (the first ds2x geometry with TWO measured grids —
/// the per-depth source-grid inheritance): the 964×272 grid at
/// 1928×1085 carries THIS family on the ds2x row; the SAME 964×272
/// tile dimensions at the 3856×2170 full-res rows ride `CANDIDATES`
/// (the family is NEVER keyed on the grid or the geometry alone). Index
/// 0 = Wrapped PSV2 = the measured family's index-0 stream = the
/// `--fast` UHD ds2x @10 stream (the FHD ds2x W6 pattern —
/// the ONLY ds2x geometry where the `--fast` stream ≠ the global W7;
/// `encode_tile_fast` routes this geometry×grid to it). Selection over
/// the family = the existing project selection (size-min — : no
/// reference-matching key).
pub const DS2X_UHD_964_CANDIDATES: [(Orient, i32); 2] = [
    (Orient::Wrapped, 2),
    (Orient::Natural, 1),
];

/// The UHD ds2x gate's (1928×1085) 482×272-grid per-tile candidate
/// family (the measured reference contract — the census
/// over the mirrored UHD ds2x @8 corpus, ): the
/// 48/48-tile census found the observed combos wrapped-PSV7 (2–3/
/// frame) / wrapped-PSV2 (7–8/frame) / natural-PSV1 (6–7/frame), ZERO
/// tiles outside — the measured family is the 3-member {W7, W2, N1}
/// set EXACTLY (the decision (c); the same members as the
/// legacy 482 family `CANDIDATES` — but the per-gate provenance is
/// separate: the ds2x-@8 48/48-tile census vs the legacy lossless
/// censuses — the pattern). The ds2x @8 row rides the 482×272
/// grid on 1928×1085 (1928 = 4×482 exact; 1085 = 3×272 + 269 — the
/// bottom-row tiles are the 269-content-row half-row tiles on the
/// 272-row plane — the odd-height interop shape, the decode drill's
/// content-rows-only semantics, the decision (b)). The 0.1.0-era legacy
/// ds2x output (1928×1085 @ 482×272 — the byte-frozen mode control)
/// shares this grid and family (kept decodable — the backward-compat
/// pattern). GRID×MODE-keyed with the GRID IN THE KEY: the 482×272
/// grid at 1928×1085 carries THIS family on the ds2x rows; the SAME
/// 482×272 tile dimensions at every other geometry ride `CANDIDATES`
/// (the family is NEVER keyed on the grid or the geometry alone). Index
/// 0 = Wrapped PSV7 = the global `FAST_CANDIDATE` = the `--fast` UHD
/// ds2x @8 stream (the global fast path is the family's index-0
/// stream at this geometry — the byte contract, the OG2K/OG3K ds2x
/// pattern). Selection over the family = the existing project selection
/// (size-min — : no reference-matching key).
pub const DS2X_UHD_482_CANDIDATES: [(Orient, i32); 3] = [
    (Orient::Wrapped, 7),
    (Orient::Wrapped, 2),
    (Orient::Natural, 1),
];

/// The per-gate candidate family, ENCODE-side keyed on the frame's
/// gate geometry: the FHD ds2x gate (968×545) → `DS2X_FHD_CANDIDATES`
/// (the measured 2-member family — the decision (c); the ds2x
/// geometry IS the mode key); the OG2K ds2x gate (1008×672) →
/// `DS2X_OG2K_CANDIDATES` (the measured 3-member family — the 
/// census; the same grid×mode key); the FHD gate (1936×1090) →
/// `FHD_CANDIDATES` (the measured per-(geometry × depth) grid is
/// encoded on the FHD grids, so the geometry key IS the grid key here);
/// the OG2K gate (2016×1344) → `OG2K_CANDIDATES` (the depth-invariant
/// measured grid is encoded on the 252×336 grid); the UHD gate
/// (3856×2170) + every other gate → `CANDIDATES` (the 482 legacy family
/// — the byte-invariance pin; for the UHD gate the geometry key covers
/// BOTH of its grids: the @12/@8 482×272 grid + the @10 964×272 grid,
/// whose measured family = the same 3 members — the 96/96-
/// tile census). The UHD ds2x geometry (1928×1085) is GRID-KEYED (two
/// measured ds2x grids — the per-depth source-grid inheritance) — the grid-keyed `gate_candidates_for_grid` is the routing seam
/// for its rows; this geometry-only accessor's 1928×1085 fallback =
/// `CANDIDATES` (the same members as `DS2X_UHD_482_CANDIDATES` — the
/// 482-grid ds2x family; the production encode path routes by grid via
/// `gate_candidates_for_grid` / `encode_tile_fast`).
pub fn gate_candidates(frame_w: u32, frame_h: u32) -> &'static [(Orient, i32)] {
    if is_fhd_ds2x_gate(frame_w, frame_h) {
        &DS2X_FHD_CANDIDATES
    } else if is_og2k_ds2x_gate(frame_w, frame_h) {
        &DS2X_OG2K_CANDIDATES
    } else if is_og3k_ds2x_gate(frame_w, frame_h) {
        // The OG3K ds2x geometry (1512×1005) = the measured 3-member
        // DS2X family (the grid×mode key — the ds2x geometry IS the
        // mode key; the 3024×2010 lossless/log10 rows keep `CANDIDATES`
        // — the same measured members, the separate lossless provenance).
        &DS2X_OG3K_CANDIDATES
    } else if is_fhd_gate(frame_w, frame_h) {
        &FHD_CANDIDATES
    } else if is_og2k_gate(frame_w, frame_h) {
        &OG2K_CANDIDATES
    } else {
        &CANDIDATES
    }
}

/// The per-gate candidate family, DECODE-side keyed on the FILE's grid
/// (the file-derived 322/323 — the backward-compat shape): a 968×545
/// frame on the FHD ds2x grids {242×274, 484×274} → `DS2X_FHD_CANDIDATES`
/// (the measured 2-member family — the grid×mode key: the SAME tile
/// dimensions on the 1936×1090 frames ride `FHD_CANDIDATES`, the
/// decision (c)); a 1008×672 frame on the 252×336 grid →
/// `DS2X_OG2K_CANDIDATES` (the measured 3-member family — the SAME
/// 252×336 tile dimensions on the 2016×1344 frames ride
/// `OG2K_CANDIDATES` — the grid×mode key, ); the UHD ds2x gate
/// (1928×1085, — the FIRST ds2x geometry with TWO measured
/// grids — the per-depth source-grid inheritance): on the 964×272 grid
/// → `DS2X_UHD_964_CANDIDATES` (the measured 2-member family), on the
/// 482×272 grid → `DS2X_UHD_482_CANDIDATES` (the measured 3-member
/// family — the @8 row + the 0.1.0-era legacy ds2x output, both the
/// 482×272 grid — the byte-frozen mode control); a 1936×1090 frame on
/// the FHD grids {242×274, 484×274} → `FHD_CANDIDATES`; a 2016×1344
/// frame on the 252×336 grid → `OG2K_CANDIDATES`; every other
/// (geometry × grid) combination → `CANDIDATES` UNCHANGED (the 482×272
/// grid at every other geometry — incl. the legacy pre-fix FHD/OG2K
/// archives — and the 3K gate's 252×252 and its legacy 482×272 shape,
/// and the UHD 964×272 grid (the measured family: the
/// 96/96-tile census found the 482 legacy family's members {W-PSV7,
/// W-PSV2, N-PSV1}, ZERO outside).
pub fn gate_candidates_for_grid(
    frame_w: u32,
    frame_h: u32,
    tw: u32,
    th: u32,
) -> &'static [(Orient, i32)] {
    // The FHD ds2x gate (968×545) on its measured per-depth grids:
    // the 2-member DS2X family (grid×mode-keyed — the ds2x geometry IS
    // the mode key; the SAME tile dimensions on the 1936×1090 lossless/
    // log10 rows ride `FHD_CANDIDATES` — the family is NEVER keyed on
 // the grid alone). The decision (c): the measured family
    // exactly (no W7 superset).
    if is_fhd_ds2x_gate(frame_w, frame_h)
        && ((tw, th) == (GATE_FHD_TILE_W_12, GATE_FHD_TILE_H)
            || (tw, th) == (GATE_FHD_TILE_W_10, GATE_FHD_TILE_H))
    {
        &DS2X_FHD_CANDIDATES
    } else if is_og2k_ds2x_gate(frame_w, frame_h)
        && (tw, th) == (GATE_OG2K_TILE_W, GATE_OG2K_TILE_H)
    {
        // The OG2K ds2x grid×mode key: the 1008×672 geometry on the
 // 252×336 grid = the measured 3-member DS2X family (
 // — W7 observed; the SAME 252×336 tile dimensions on the
        // 2016×1344 lossless/log10 rows ride `OG2K_CANDIDATES`).
        &DS2X_OG2K_CANDIDATES
    } else if is_og3k_ds2x_gate(frame_w, frame_h)
        && (tw, th) == (GATE_3K_TILE_W, GATE_3K_TILE_H)
    {
        // The OG3K ds2x grid×mode key: the 1512×1005 geometry on the
 // 252×252 grid = the measured 3-member DS2X family (the 
        // census — W7 observed on the ds2x corpus; the SAME 252×252
        // tile dimensions on the 3024×2010 lossless/log10 rows ride
        // `CANDIDATES` — the separate lossless/log10 provenance).
        &DS2X_OG3K_CANDIDATES
    } else if is_uhd_ds2x_gate(frame_w, frame_h) {
 // The UHD ds2x grid×mode×GRID key ( — the first ds2x
        // geometry with TWO measured grids — the per-depth source-grid
        // inheritance): 1928×1085 on the 964×272 grid = the measured
        // 2-member {W2, N1} family (W7 never observed on the ds2x-@10
 // corpus — the census); on the 482×272 grid = the measured
        // 3-member {W7, W2, N1} family (the @8 row + the 0.1.0-era
        // legacy ds2x output — the byte-frozen mode control). The SAME
        // 964/482×272 tile dimensions at the 3856×2170 full-res rows
        // ride `CANDIDATES` (the family is NEVER keyed on the grid or
        // the geometry alone).
        if (tw, th) == (GATE_UHD_TILE_W_10, TILE_H) {
            &DS2X_UHD_964_CANDIDATES
        } else if (tw, th) == (TILE_W, TILE_H) {
            &DS2X_UHD_482_CANDIDATES
        } else {
            &CANDIDATES
        }
    } else if is_fhd_gate(frame_w, frame_h)
        && ((tw, th) == (GATE_FHD_TILE_W_12, GATE_FHD_TILE_H)
            || (tw, th) == (GATE_FHD_TILE_W_10, GATE_FHD_TILE_H))
    {
        &FHD_CANDIDATES
    } else if is_og2k_gate(frame_w, frame_h) && (tw, th) == (GATE_OG2K_TILE_W, GATE_OG2K_TILE_H) {
        &OG2K_CANDIDATES
    } else {
        &CANDIDATES
    }
}

/// The single fixed candidate for `--fast`: Wrapped PSV 7 — the
/// measured default predictor orientation, and the probe's
/// fixed-candidate recommendation for BOTH precisions (10 and 12):
/// price vs adaptive selection +1.42% (dark A001_001) to +4.27%
/// (bright A001_010) tile bytes, in exchange for skipping the 2 extra
/// trial encodes per tile. FHD/OG2K: the per-gate families' index 0 is
/// the SAME stream (Wrapped PSV7) — the `--fast` byte contract at those
/// grids is the same stream as the other gates' index 0. UHD @10:
/// the measured 964×272 family's index 0 is the SAME stream (Wrapped
/// PSV7 — the census) — the `--fast` UHD@10 byte contract
/// is the same stream as the other gates' index 0. FHD ds2x (968×545):
/// the measured 2-member family's index-0 stream (Wrapped PSV6 —
/// `DS2X_FHD_CANDIDATES[0]`, the decision (c) pattern —
/// `encode_tile_fast` routes the ds2x geometry to it; every OTHER
/// geometry keeps this global W7 — the byte-invariance pin).
pub const FAST_CANDIDATE: (Orient, i32) = (Orient::Wrapped, 7);

/// The two lossless entropy engines. Both produce BYTE-IDENTICAL
/// streams (255 frames / 16,320 tiles / 48,960 candidate
/// streams, precisions 10+12, both reference clips, 0 failures;
/// golden re-run 2/2 per engine) — engine choice is a performance /
/// provenance knob, never a correctness knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// Native Rust T.81 (SOF3) encoder (`fastenc::encode_planes_native`).
    /// Shipped default since 0.2.0.
    Native,
    /// The 0.1.0 audited libjpeg-turbo FFI path (`encode_planes`).
    Ffi,
}

/// Pure engine-selection mapping (unit-tested without touching process
/// env). Native is the shipped default; `ffi`/`libjpeg`/`legacy`
/// restore the 0.1.0 FFI path. Any other value (incl. a typo) is
/// native — safe because the engines are byte-identical.
pub fn engine_from(v: Option<&str>) -> Engine {
    match v.map(|s| s.trim().to_ascii_lowercase()).as_deref().unwrap_or("") {
        "ffi" | "libjpeg" | "legacy" => Engine::Ffi,
        _ => Engine::Native,
    }
}

/// Engine selection seam (seam; 0.2.0 default flip):
/// `FRAMEPRISM_ENGINE` env var — native by default;
/// `FRAMEPRISM_ENGINE=ffi|libjpeg|legacy` selects the audited 0.1.0
/// libjpeg FFI path.
fn native_engine() -> bool {
    engine_from(std::env::var("FRAMEPRISM_ENGINE").ok().as_deref())
        == Engine::Native
}

/// Encode one (orient, psv) candidate stream for one tile, even-padded
/// (reference invariant). Shared by the 3-candidate adaptive path and the
/// single-candidate `--fast` path, so both apply the engine seam and
/// the pad at exactly one place.
fn encode_candidate(
    mosaic: &[u16],
    frame_w: u32,
    frame_h: u32,
    g: &Grid,
    r: u32,
    c: u32,
    precision: u32,
    orient: Orient,
    psv: i32,
) -> Result<Vec<u8>, TileError> {
    let p = planes_from_tile(mosaic, frame_w, frame_h, g, r, c, orient)?;
    encode_planes_padded(&p, precision, psv)
}

/// Encode one oriented plane set through the engine seam + the reference
/// even-size pad (shared by the adaptive and fast paths).
fn encode_planes_padded(p: &Planes, precision: u32, psv: i32) -> Result<Vec<u8>, TileError> {
    let mut s = if native_engine() {
        crate::fastenc::encode_planes_native(p, precision, psv)?
    } else {
        encode_planes(p, precision, psv)?
    };
    if s.len() % 2 == 1 {
        s.push(0); // reference even-size invariant (FFD9 + 0x00)
    }
    Ok(s)
}

/// One encoded candidate stream + its even-padded size — VARIABLE-
/// LENGTH over the gate's measured family (the 3-member families at
/// every existing grid — the byte-invariance pin; the 2-member FHD ds2x
/// family at 968×545 — the decision (c) variable-length
/// accommodation, the mechanical representation change: fixed `[; 3]`
/// arrays → Vecs, the caller-facing tuple shape unchanged).
pub type CandidateSet = (Vec<Vec<u8>>, Vec<usize>, usize);

/// Trial-encode the measured 3 candidates for one tile and
/// return all streams (each even-padded, reference invariant) + sizes +
/// the index of the chosen stream. The selection key is PER-GATE (the
/// byte-invariance contract — the other gates' outputs are frozen to the
/// 0.1.0 size-min behavior) and the CANDIDATE FAMILY is PER-GRID (the
/// grid-keyed per-gate discipline — `gate_candidates_for_grid`, keyed on
/// the ACTUAL grid `g` being encoded so the decode drill's file-derived
/// grid selects the right family: the legacy 482×272 FHD archives stay
/// on `CANDIDATES`, the FHD grids on `FHD_CANDIDATES`):
/// - **the 3K gate (3024×2010)**: the histogram pass's pre-stuffing
///   expected bit count per candidate (`fastenc::expected_bits`), ties →
///   the earlier candidate. Measured on the 114-frame corpus
///   (10,944 tiles, the winner streams byte-identical to the corpus in
///   all of them): it reproduces 10,943 of 10,944 of the corpus file's
///   stored selections (the one residual is a 7-bit boundary tile where
///   the corpus file's trial stream is believed to diverge from ours on the
///   losing candidate). The final byte size is NOT the key: on 41 corpus
///   tiles the measured encoder keeps the LARGER stream.
/// - **the other gates**: the 0.1.0 size-min contract (the smallest
///   post-pad stream, ties → the earlier candidate) — unchanged by this
///   feature (the oracle10/108 byte pins); the FHD gate (1936×1090)
///   is size-min over its measured `FHD_CANDIDATES` family and the
///   OG2K gate (2016×1344) over its measured `OG2K_CANDIDATES` family
///   (no new per-gate reference-matching key).
pub fn encode_tile_candidates(
    mosaic: &[u16],
    frame_w: u32,
    frame_h: u32,
    g: &Grid,
    r: u32,
    c: u32,
    precision: u32,
) -> Result<(Vec<u8>, CandidateSet), TileError> {
    let fam = gate_candidates_for_grid(frame_w, frame_h, g.tw, g.th);
    let mut streams: Vec<Vec<u8>> = Vec::with_capacity(fam.len());
    let mut sizes: Vec<usize> = Vec::with_capacity(fam.len());
    let mut keys: Vec<u64> = vec![u64::MAX; fam.len()];
    let mut best: usize = 0;
    // The 3K gate (3024×2010) uses the measured bit-count selection key;
    // the other gates keep the 0.1.0 size-min contract (the byte-invariance
    // pin — the oracle10/108 sizes; the 482 selection is
    // unmeasured and is kept exactly as shipped). The candidate FAMILY is
    // keyed on the actual grid (the per-gate discipline): the FHD grids
    // select `FHD_CANDIDATES`, the OG2K 252×336 grid selects
    // `OG2K_CANDIDATES`, the FHD ds2x 968×545 grids select the 2-member
 // `DS2X_FHD_CANDIDATES` family (the decision (c)), every
    // other grid (482×272 + 252×252) selects `CANDIDATES`.
    let three_k = is_3k_gate(frame_w, frame_h);
    for (i, &(orient, psv)) in fam.iter().enumerate() {
        let p = planes_from_tile(mosaic, frame_w, frame_h, g, r, c, orient)?;
        let s = encode_planes_padded(&p, precision, psv)?;
        sizes.push(s.len());
        if three_k {
 // The 3K gate's measured comparison key (the
            // 114-frame corpus — 10,943 of 10,944 of the corpus file's
            // stored selections; the final byte size does NOT reproduce
            // them — 41 tiles where the measured encoder keeps the larger
            // stream). Strict < keeps the earlier candidate on a tie.
            let k = crate::fastenc::expected_bits(&p, precision, psv)?;
            keys[i] = k;
            if k < keys[best] {
                best = i;
            }
        } else if i == 0 || s.len() < sizes[best] {
            // The 0.1.0 contract: the smallest post-pad stream; strict <
            // keeps the earlier candidate on a tie.
            best = i;
        }
        streams.push(s);
    }
    let chosen = streams[best].clone();
    Ok((chosen, (streams, sizes, best)))
}

/// Convenience: encode one tile directly from the frame mosaic, adaptively
/// (reference parity — the NLE media-offline root cause was the fixed
/// PSV7 + fixed-orientation + merged-DHT structure; the measured encoder trial-
/// encodes the 3 candidates per tile and picks per the per-gate
/// selection key (the 3K gate: the measured expected-bit-count key; the
/// other gates: the 0.1.0 size-min contract — see
/// `encode_tile_candidates`), so we do the same). `precision` 12 = lossless (the mosaic is 12-bit samples), 10 =
/// log10 (the mosaic is 10-bit log codes, i.e. `crate::log10::inv()`-
/// mapped 12-bit samples). Cost: 3× the single-candidate encode.
pub fn encode_tile(
    mosaic: &[u16],
    frame_w: u32,
    frame_h: u32,
    g: &Grid,
    r: u32,
    c: u32,
    precision: u32,
) -> Result<Vec<u8>, TileError> {
    let (tile, _cands) = encode_tile_candidates(mosaic, frame_w, frame_h, g, r, c, precision)?;
    Ok(tile)
}

/// `--fast`: single-candidate encode — no trial encode, just the gate's
/// measured family's INDEX-0 candidate through the same engine +
/// even-pad seam as the adaptive path. Every existing geometry's family
/// index 0 is the global FAST_CANDIDATE (Wrapped PSV 7 — the byte-
/// invariance pin); the FHD ds2x gate (968×545) rides its measured 2-
/// member family's index 0 (Wrapped PSV 6 — the decision (c)
/// pattern: the `--fast` stream is the measured family's index-0
/// stream). Output is bit-exact lossless (verify passes); per-tile size
/// may be larger than the adaptive choice (the price band), and equals
/// it exactly on the tiles where candidate 0 wins the adaptive
/// comparison.
pub fn encode_tile_fast(
    mosaic: &[u16],
    frame_w: u32,
    frame_h: u32,
    g: &Grid,
    r: u32,
    c: u32,
    precision: u32,
) -> Result<Vec<u8>, TileError> {
    let (orient, psv) = if is_fhd_ds2x_gate(frame_w, frame_h) {
        DS2X_FHD_CANDIDATES[0]
    } else if is_uhd_ds2x_gate(frame_w, frame_h)
        && (g.tw, g.th) == (GATE_UHD_TILE_W_10, TILE_H)
    {
        // The UHD ds2x @10 row (the 964×272 grid on 1928×1085): the measured 2-member family's index-0 stream (Wrapped
 // PSV2 — the FHD ds2x W6 pattern — the ONLY ds2x
        // geometry where the `--fast` stream ≠ the global W7). The
        // 482×272 grid at 1928×1085 keeps the global W7 (the
        // `DS2X_UHD_482_CANDIDATES` index 0 = the global candidate —
        // the byte contract, the OG2K/OG3K ds2x pattern).
        DS2X_UHD_964_CANDIDATES[0]
    } else {
        FAST_CANDIDATE
    };
    encode_candidate(mosaic, frame_w, frame_h, g, r, c, precision, orient, psv)
}

/// The inverse of `tile_from_planes`: split a FULL tile-height row-major
/// tile plane (tw × th — a decoded tile's full plane, the pad rows
/// INCLUDED) into the oriented even/odd column planes (the same oriented
/// layout `planes_from_tile` writes, minus the mosaic extraction + the
/// reference pad rule — the caller owns the plane rows, pad rows
/// included). The odd-height interop restore-drill's re-encode input
/// (the decision (b)): the drill re-encodes the FILE'S OWN
/// decoded plane (the pad rows self-sourced from the stored tile, NOT
/// the tool's pad rule), so the deterministic engine reproduces the
/// stored tile bytes bit-exactly iff the tl CONTENT rows round-trip —
/// the content-rows-only semantics for the 968×545 ds2x bottom-row
/// tiles (the file's pad rows are synthetic / pre-decimation-
/// derived — the measured fact; the engine parity ×10/10 on the record).
pub fn planes_from_tile_rows(
    plane: &[u16],
    rect: &TileRect,
    th: u32,
    oriented: Orient,
) -> Result<Planes, TileError> {
    let TileRect { tw, .. } = *rect;
    if tw % 2 != 0 {
        return Err(TileError::OddTileWidth(tw));
    }
    let tw_us = tw as usize;
    if plane.len() != tw_us * (th as usize) {
        return Err(TileError::GeometryMismatch {
            rows: (plane.len() / tw_us.max(1)) as u32,
            cols: tw,
            ew: tw,
            eh: th / 2,
            nw: tw / 2,
            nh: th,
        });
    }
    let half = (tw / 2) as usize;
    let (rows, cols) = match oriented {
        Orient::Wrapped => (th / 2, tw),
        Orient::Natural => (th, tw / 2),
    };
    let (rows, cols) = (rows as usize, cols as usize);
    let n = rows * cols;
    let mut even = vec![0u16; n];
    let mut odd = vec![0u16; n];
    for y in 0..th as usize {
        // The mirror of `planes_from_tile`'s write loop at `src_y = y`
        // (no pad — the plane is full-height): wrapped → y/2 (two tile
        // rows per plane row), natural → y.
        let (oy, ox0) = match oriented {
            Orient::Wrapped => (y / 2, (y % 2) * half),
            Orient::Natural => (y, 0),
        };
        for x in 0..half {
            even[oy * cols + ox0 + x] = plane[y * tw_us + 2 * x];
            odd[oy * cols + ox0 + x] = plane[y * tw_us + 2 * x + 1];
        }
    }
    Ok(Planes {
        rect: TileRect {
            x0: rect.x0,
            y0: rect.y0,
            tw,
            tl: th,
        },
        rows: rows as u32,
        cols: cols as u32,
        th,
        even,
        odd,
    })
}

/// Encode an EXPLICIT tile plane set (the caller owns the full plane —
/// `planes_from_tile_rows` / a self-sourced decoded plane, the pad rows
/// included — bypassing the mosaic extraction + the reference pad rule)
/// through the engine seam + the reference even-size pad. The odd-height
/// interop restore-drill's per-candidate re-encode path (the 
/// decision (b)): the deterministic engine reproduces the stored tile bytes
/// bit-exactly from the file's own decoded plane iff the content rows
/// round-trip.
pub fn encode_tile_planes(p: &Planes, precision: u32, psv: i32) -> Result<Vec<u8>, TileError> {
    encode_planes_padded(p, precision, psv)
}

// ------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic 12-bit plane: phase-stratified like a Bayer mosaic
    /// (even/odd columns near-constant per row parity) + per-pixel jitter.
    fn test_mosaic(w: u32, h: u32) -> Vec<u16> {
        (0..(w * h) as usize)
            .map(|i| {
                let x = i % w as usize;
                let y = i / w as usize;
                let phase = if y % 2 == 0 {
                    if x % 2 == 0 {
                        293
                    } else {
                        326
                    }
                } else {
                    if x % 2 == 0 {
                        326
                    } else {
                        293
                    }
                };
                let jitter = ((x * 7 + y * 13) % 47) as u16;
                (phase as u16).wrapping_add(jitter) % 4096
            })
            .collect()
    }

    fn full_roundtrip(frame_w: u32, frame_h: u32, precision: u32, as_log10_codes: bool) {
        let g = Grid::new(frame_w, frame_h);
        let mosaic12 = test_mosaic(frame_w, frame_h);
        let mosaic: Vec<u16> = if as_log10_codes {
            let inv = crate::log10::inv();
            mosaic12.iter().map(|v| inv[*v as usize]).collect()
        } else {
            mosaic12
        };
        // Both reference orientations (wrapped PSV7, natural PSV1) must
        // roundtrip bit-exact, including the padded last-row tiles.
        for (orient, psv) in [(Orient::Wrapped, 7i32), (Orient::Natural, 1)] {
            for r in 0..g.rows {
                for c in 0..g.cols {
                    let rect = tile_region(frame_w, frame_h, &g, r, c).unwrap();
                    let p = planes_from_tile(&mosaic, frame_w, frame_h, &g, r, c, orient).unwrap();
                    let jpeg = encode_planes(&p, precision, psv).unwrap();
                    let back = decode_tile(&jpeg, &rect, precision, g.th).unwrap();
                    let base = (rect.y0 as usize) * frame_w as usize + rect.x0 as usize;
                    let src: Vec<u16> = (0..rect.tl)
                        .flat_map(|y| {
                            mosaic[base + y as usize * frame_w as usize
                                ..base + y as usize * frame_w as usize + rect.tw as usize]
                                .iter()
                                .copied()
                        })
                        .collect();
                    assert_eq!(back, src, "tile ({r},{c}) {tw}x{tl} must roundtrip bit-exact (precision {precision}, log10 codes {as_log10_codes}, orient {:?}, psv {psv})", orient, tw = rect.tw, tl = rect.tl);
                }
            }
        }
    }

    #[test]
    fn grid_geometry_3856x2170() {
        let g = Grid::new(3856, 2170);
        assert_eq!((g.cols, g.rows), (8, 8), "A001 must be 8x8 = 64 tiles");
        let r00 = tile_region(3856, 2170, &g, 0, 0).unwrap();
        assert_eq!((r00.x0, r00.y0, r00.tw, r00.tl), (0, 0, 482, 272));
        let r77 = tile_region(3856, 2170, &g, 7, 7).unwrap();
        assert_eq!((r77.x0, r77.y0, r77.tw, r77.tl), (3374, 1904, 482, 266));
        // 7*272 + 266 = 2170
        assert_eq!(7 * TILE_H + r77.tl, 2170);
        assert!(tile_region(3856, 2170, &g, 8, 0).is_err());
        // Last-row tile plane (legacy helper, pre-padding rule):
        // 266*241 = 133*482 → wrapped 482x133; full tile 272 → 482x136.
        assert_eq!(plane_orient(482, 266), (133, 482));
        assert_eq!(plane_orient(482, 272), (136, 482));
        // Reference-contract padding: the ENCODE path pads
        // last-row tiles to the full 272 tile height (136×482 wrapped /
        // 272×241 natural); pad rows repeat the last two real rows.
        assert_eq!(padded_tl(266), 272);
        assert_eq!(padded_tl(269), 272);
        assert_eq!(padded_tl(272), 272);
        // Full-frame synthetic mosaic (distinct values per pixel so the pad
        // rule is checkable).
        let mosaic: Vec<u16> = (0..(3856 * 2170) as usize)
            .map(|i| (i % 4096) as u16)
            .collect();
        let pw = planes_from_tile(&mosaic, 3856, 2170, &g, 7, 0, Orient::Wrapped).unwrap();
        assert_eq!(
            (pw.rows, pw.cols),
            (136, 482),
            "last-row wrapped plane is padded 136x482"
        );
        let pn = planes_from_tile(&mosaic, 3856, 2170, &g, 7, 0, Orient::Natural).unwrap();
        assert_eq!(
            (pn.rows, pn.cols),
            (272, 241),
            "last-row natural plane is padded 272x241"
        );
        // Pad rule: pad row y = row tl-2+(y-tl)%2 → for tl=266 the last 6
        // natural-plane rows alternate row 264 / row 265 content.
        let base = (1904 * 3856) as usize;
        for dy in 0..6 {
            let src_row = 264 + dy % 2;
            let plane_row = 266 + dy;
            for x in 0..241 {
                assert_eq!(
                    pn.even[plane_row * 241 + x],
                    mosaic[base + src_row * 3856 + 2 * x],
                    "pad row {plane_row} must repeat tile row {src_row} (even cols)"
                );
            }
        }
    }

    #[test]
    fn grid_geometry_1928x1085() {
        // downscale2x: half of 3856x2170.
        let g = Grid::new(1928, 1085);
        assert_eq!((g.cols, g.rows), (4, 4));
        let r00 = tile_region(1928, 1085, &g, 0, 0).unwrap();
        assert_eq!((r00.tw, r00.tl), (482, 272));
        let r33 = tile_region(1928, 1085, &g, 3, 3).unwrap();
        // 3*272 = 816; 1085 - 816 = 269 (odd) → natural orientation.
        assert_eq!((r33.tw, r33.tl), (482, 269));
        assert_eq!(
            plane_orient(482, 269),
            (269, 241),
            "odd tile height → natural 241x269"
        );
        // LibRaw decoder-safety override (downscale2x): 4×482 =
        // 1928 == frame width → the wrapped SOF width (482) would hit
        // LibRaw's clrs*jwide == raw_width branch (measured: 65% pixel
        // mismatch) → force natural 241×tl for every tile. Full-resolution
        // 3856 is UNCHANGED (4×482 = 1928 ≠ 3856 → wrapped, as before).
        assert_eq!(
            plane_orient_libraw_safe(482, 272, 1928),
            (272, 241),
            "1928-wide: forced natural"
        );
        assert_eq!(
            plane_orient_libraw_safe(482, 269, 1928),
            (269, 241),
            "1928-wide last row: natural (auto)"
        );
        assert_eq!(
            plane_orient_libraw_safe(482, 272, 3856),
            (136, 482),
            "3856-wide: wrapped (unchanged)"
        );
        assert_eq!(
            plane_orient_libraw_safe(482, 266, 3856),
            (133, 482),
            "3856-wide last row: wrapped (unchanged)"
        );
    }

    #[test]
    fn grid_geometry_clipped_last_column() {
        // Width not a multiple of 482: last column clipped (tw=18, even).
        let g = Grid::new(982, 300);
        assert_eq!((g.cols, g.rows), (3, 2));
        let r02 = tile_region(982, 300, &g, 0, 2).unwrap();
        assert_eq!((r02.x0, r02.tw), (964, 18));
        let r10 = tile_region(982, 300, &g, 1, 0).unwrap();
        assert_eq!((r10.y0, r10.tl), (272, 28));
        assert_eq!(plane_orient(18, 28), (14, 18));
    }

    #[test]
    fn planes_roundtrip_pure() {
        // Both reference orientations, full + last-row (padded) tiles.
        for (tw, tl) in [(482u32, 272), (482, 266), (482, 269), (18, 28)] {
            let m = test_mosaic(tw, tl);
            let g = Grid::new(tw, tl); // 1x1 grid
            for orient in [Orient::Wrapped, Orient::Natural] {
                let pad = padded_tl(tl);
                let (rows, cols) = match orient {
                    Orient::Wrapped => (pad / 2, tw),
                    Orient::Natural => (pad, tw / 2),
                };
                let p = planes_from_tile(&m, tw, tl, &g, 0, 0, orient).unwrap();
                assert_eq!((p.rows, p.cols), (rows, cols));
                assert_eq!(
                    p.even.len(),
                    p.odd.len(),
                    "plane sizes differ for {tw}x{tl}"
                );
                let back = tile_from_planes(&p).unwrap();
                assert_eq!(
                    back, m,
                    "pure roundtrip must be exact for {tw}x{tl} ({orient:?}, pad to {pad})"
                );
            }
        }
    }

    #[test]
    fn synthetic_tile_roundtrip_wrapped() {
        // 482x272 tile: plane 65,552 samples = 136 rows of 482 (divisible).
        full_roundtrip(482, 272, 12, false);
    }

    #[test]
    fn synthetic_tile_roundtrip_natural() {
        // 482x273 tile: plane 273*241 = 65,793 samples — NOT divisible by
        // 482 → natural 241x273 orientation path.
        full_roundtrip(482, 273, 12, false);
    }

    #[test]
    fn synthetic_tile_multi() {
        // A small frame exercising mixed full/clipped tiles.
        full_roundtrip(982, 300, 12, false);
    }

    #[test]
    fn synthetic_frame_1928x1085_downscale2x() {
        // The downscale2x frame geometry: 4×4 grid, last row 482×269
        // (odd → natural 241×269 planes), all 16 tiles roundtrip bit-exact
        // through libjpeg + the golden-model decoder.
        full_roundtrip(1928, 1085, 12, false);
        full_roundtrip(1928, 1085, 10, true); // log10 codes, same geometry
    }

    #[test]
    fn log10_10bit_tile_roundtrip_bit_exact() {
        // 10-bit log codes through the SAME tile structure (SOF3 precision
        // 10, PSV 7, 2 parity components) must roundtrip BIT-EXACT — the
        // log10 losslessness claim is at the code level (the 12-bit
        // reconstruction error is the LUT quantization, gated separately).
        full_roundtrip(482, 272, 10, true); // wrapped orientation
        full_roundtrip(482, 273, 10, true); // natural orientation
        full_roundtrip(982, 300, 10, true); // mixed full/clipped tiles
    }

    #[test]
    fn real_a001_frame1_tiled_roundtrip() {
        let p = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let buf = match std::fs::read(p) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {p} ({err})");
                return;
            }
        };
        let f = crate::tiff::read(&buf).unwrap();
        let packed = f.strip_slice(&buf);
        let s = crate::pack12::unpack12(packed, f.width, f.height).unwrap();
        let g = Grid::new(f.width, f.height);
        assert_eq!((g.cols, g.rows), (8, 8));
        let mut total = 0usize;
        for r in 0..g.rows {
            for c in 0..g.cols {
                let jpeg = encode_tile(&s, f.width, f.height, &g, r, c, 12).unwrap();
                let rect = tile_region(f.width, f.height, &g, r, c).unwrap();
                let back = decode_tile(&jpeg, &rect, 12, g.th).unwrap();
                let base = (rect.y0 as usize) * f.width as usize + rect.x0 as usize;
                for y in 0..rect.tl as usize {
                    let src: Vec<u16> = s[base + y * f.width as usize
                        ..base + y * f.width as usize + rect.tw as usize]
                        .to_vec();
                    assert_eq!(
                        &back[y * rect.tw as usize..y * rect.tw as usize + rect.tw as usize],
                        &src,
                        "tile ({r},{c}) row {y} mismatch"
                    );
                }
                total += jpeg.len();
            }
        }
        eprintln!(
            "tiled frame 1: 64 tiles, JPEG total {} B vs packed {} B ({:.2}:1 over packed strip)",
            total,
            packed.len(),
            packed.len() as f64 / total as f64
        );
    }

    #[test]
    fn real_a001_frame1_tiled_vs_golden() {
        let op = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let gp = "../testdata/reference/lossless/A001_001/A001_001_20260701_000001.DNG";
        let obuf = match std::fs::read(op) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {op} ({err})");
                return;
            }
        };
        let gbuf = match std::fs::read(gp) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {gp} ({err})");
                return;
            }
        };
        let f = crate::tiff::read(&obuf).unwrap();
        let s = crate::pack12::unpack12(f.strip_slice(&obuf), f.width, f.height).unwrap();
        let g = Grid::new(f.width, f.height);
        let mut ours: Vec<usize> = Vec::new();
        for r in 0..g.rows {
            for c in 0..g.cols {
                ours.push(
                    encode_tile(&s, f.width, f.height, &g, r, c, 12)
                        .unwrap()
                        .len(),
                );
            }
        }

        // Golden per-tile sizes: parse 325 (TileByteCounts) — LONG count 64.
        let e = f.endianness;
        let mut golden: Vec<u32> = Vec::new();
        let meta = crate::tiff::read_meta(&gbuf).expect("golden must parse");
        for en in &meta.ifd0.entries {
            if en.tag == 325 && en.typ == 4 && en.count == 64 {
                let (start, _) = en.out_of_line.expect("325 out-of-line");
                for i in 0..64 {
                    let o = (start + i * 4) as usize;
                    golden.push(e.u32(&gbuf[o..o + 4]));
                }
            }
        }
        assert_eq!(golden.len(), 64, "golden must have 64 tile byte counts");
        let gout: Vec<usize> = golden.iter().map(|v| *v as usize).collect();

        eprintln!("tile  ours    golden  delta%");
        for (i, (o, gsz)) in ours.iter().zip(gout.iter()).enumerate() {
            let d = if *gsz == 0 {
                0.0
            } else {
                (*o as f64 / *gsz as f64 - 1.0) * 100.0
            };
            eprintln!("{i:4}  {o:7}  {gsz:7}  {d:+6.2}%");
        }
        let sum_o: usize = ours.iter().sum();
        let sum_g: usize = gout.iter().sum();
        let drift = (sum_o as f64 / sum_g as f64 - 1.0) * 100.0;
        eprintln!("total ours={sum_o} golden={sum_g} drift={drift:+.2}%");
        assert!(
            drift.abs() < 10.0,
            "total size must be within 10% of the reference golden, got {drift:+.2}%"
        );
    }

    /// Extract the per-tile byte streams of a tiled DNG from the 324
    /// (TileOffsets) / 325 (TileByteCounts) LONG arrays.
    fn golden_tiles(gbuf: &[u8], count: usize) -> Vec<Vec<u8>> {
        let meta = crate::tiff::read_meta(gbuf).expect("golden must parse");
        let e = meta.endianness;
        let (mut offs, mut cnts) = (Vec::new(), Vec::new());
        for en in &meta.ifd0.entries {
            match (en.tag, en.typ, en.count) {
                (324, 4, c) if c == count as u32 => {
                    let (start, _) = en.out_of_line.expect("324 out-of-line");
                    let start = start as usize;
                    offs = (0..count)
                        .map(|i| e.u32(&gbuf[start + i * 4..start + i * 4 + 4]) as usize)
                        .collect();
                }
                (325, 4, c) if c == count as u32 => {
                    let (start, _) = en.out_of_line.expect("325 out-of-line");
                    let start = start as usize;
                    cnts = (0..count)
                        .map(|i| e.u32(&gbuf[start + i * 4..start + i * 4 + 4]) as usize)
                        .collect();
                }
                _ => {}
            }
        }
        assert_eq!(offs.len(), count, "golden must have {count} tile offsets");
        assert_eq!(cnts.len(), count, "golden must have {count} tile counts");
        offs.into_iter()
            .zip(cnts)
            .map(|(o, c)| gbuf[o..o + c].to_vec())
            .collect()
    }

    /// Reference-parity acceptance: the adaptive encoder
    /// (3 candidates {wrapped PSV7, wrapped PSV2, natural PSV1}, the
    /// histogram-pass expected-bit-count key wins, see
    /// `encode_tile_candidates`) must reproduce the reference golden tiles
    /// BYTE-IDENTICALLY on sample frames — f1 (the 64/64 measurement),
    /// f113 (middle) and f225 (last). A byte-identical tile implies the
    /// same (Ss, orientation) choice, the same per-component Huffman fits
    /// AND the same tie-break, so this gates the whole reference contract.
    #[test]
    fn real_a001_sample_frames_tiled_byte_identical_to_golden() {
        let gdir = "../testdata/reference/lossless";
        let odir = "../testdata/originals/A001_001";
        for fi in [1usize, 113, 225] {
            let name = format!("A001_001_20260701_{fi:06}.DNG");
            let op = format!("{odir}/{name}");
            let gp = format!("{gdir}/{name}");
            let obuf = match std::fs::read(&op) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("skip: {op} ({err})");
                    return;
                }
            };
            let gbuf = match std::fs::read(&gp) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("skip: {gp} ({err})");
                    return;
                }
            };
            let f = crate::tiff::read(&obuf).unwrap();
            let s = crate::pack12::unpack12(f.strip_slice(&obuf), f.width, f.height).unwrap();
            let g = Grid::new(f.width, f.height);
            let gtiles = golden_tiles(&gbuf, (g.cols * g.rows) as usize);
            let mut ident = 0usize;
            let mut sum_o = 0usize;
            let mut sum_g = 0usize;
            for r in 0..g.rows {
                for c in 0..g.cols {
                    let i = (r * g.cols + c) as usize;
                    let ours = encode_tile(&s, f.width, f.height, &g, r, c, 12).unwrap();
                    sum_o += ours.len();
                    sum_g += gtiles[i].len();
                    if ours == gtiles[i] {
                        ident += 1;
                    } else {
                        panic!(
                            "frame {fi} tile {i}: {} B vs golden {} B — not byte-identical",
                            ours.len(),
                            gtiles[i].len()
                        );
                    }
                }
            }
            assert_eq!(
                sum_o, sum_g,
                "frame {fi}: tile totals must match the golden exactly"
            );
            eprintln!(
                "frame {fi}: {ident}/{} tiles byte-identical to golden, total {sum_o} B",
                g.cols * g.rows
            );
        }
    }

    /// G1 re-verification (in Rust): the reference golden tile 0 must decode
    /// PIXEL-EXACT with the standard T.81-order golden-model decoder —
    /// confirms the golden-structure facts AND that
    /// `ljpeg_ref` matches the Python reference decoder.
    #[test]
    fn golden_model_decodes_reference_golden_tile0_pixel_exact() {
        let gp = "../testdata/reference/lossless/A001_001/A001_001_20260701_000001.DNG";
        let op = "../testdata/originals/A001_001/A001_001_20260701_000001.DNG";
        let gbuf = match std::fs::read(gp) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {gp} ({err})");
                return;
            }
        };
        let obuf = match std::fs::read(op) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("skip: {op} ({err})");
                return;
            }
        };
        let f = crate::tiff::read(&obuf).unwrap();
        let mosaic = crate::pack12::unpack12(f.strip_slice(&obuf), f.width, f.height).unwrap();
        let base = 0usize;
        let meta = crate::tiff::read_meta(&gbuf).expect("golden must parse");
        let e = meta.endianness;
        // Golden tile 0: 324[0]..324[0]+325[0]
        let mut off: u32 = 0;
        let mut cnt: u32 = 0;
        for en in &meta.ifd0.entries {
            if en.tag == 324 && en.count == 64 {
                let (p, _) = en.out_of_line.unwrap();
                off = e.u32(&gbuf[p as usize..p as usize + 4]);
            }
            if en.tag == 325 && en.count == 64 {
                let (p, _) = en.out_of_line.unwrap();
                cnt = e.u32(&gbuf[p as usize..p as usize + 4]);
            }
        }
        let tile = &gbuf[off as usize..off as usize + cnt as usize];
        let (info, comps) = crate::ljpeg_ref::decode(tile).unwrap();
        assert_eq!(
            (info.width, info.height, info.nf, info.precision, info.psv),
            (482, 136, 2, 12, 7),
            "golden tile 0 must be 482x136 2-comp 12-bit PSV7"
        );
        // Wrapped planes: plane row oy = tile rows 2oy (first 241 cols) +
        // 2oy+1 (last 241 cols) of that parity. Tile 0 sits at frame (0,0),
        // so frame col = tile col = 2x + ci.
        let mut ok = 0usize;
        for oy in 0..136usize {
            for x in 0..241usize {
                for ty in 0..2usize {
                    let row = oy * 2 + ty;
                    let plane_col = if ty == 0 { x } else { 241 + x };
                    for ci in 0..2usize {
                        let want = comps[ci][oy * 482 + plane_col];
                        let px = base + row * f.width as usize + 2 * x + ci;
                        if want == mosaic[px] {
                            ok += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(
            ok, 131_104,
            "golden tile 0 must be pixel-exact in standard T.81 order (131,104/131,104)"
        );
    }

    /// Acceptance (4): a STANDARD T.81-order decode of OUR stream is
    /// pixel-exact (synthetic tile, wrapped orientation) — and the fast
    /// libjpeg pre-check agrees with the golden model.
    #[test]
    fn our_stream_standard_t81_order_decode_is_pixel_exact() {
        let (fw, fh) = (482u32, 272u32);
        let g = Grid::new(fw, fh);
        let mosaic = test_mosaic(fw, fh);
        let rect = tile_region(fw, fh, &g, 0, 0).unwrap();
        let jpeg = encode_tile(&mosaic, fw, fh, &g, 0, 0, 12).unwrap();
        // Golden-model (standard T.81 per-MCU order) decode — the gate.
        let back = decode_tile(&jpeg, &rect, 12, g.th).unwrap();
        let src: Vec<u16> = mosaic[..(fw * fh) as usize].to_vec();
        assert_eq!(
            back, src,
            "standard-order decode of our stream must be pixel-exact"
        );
        // Fast libjpeg pre-check must agree (post pixel-order fix both are
        // standard-order decoders of the same stream).
        let pre = decode_tile_ljpeg(&jpeg, &rect, 12, g.th).unwrap();
        assert_eq!(
            pre, back,
            "libjpeg pre-check must agree with the golden model"
        );
    }

    // --fast is exactly the adaptive candidate 0 (Wrapped PSV 7)
    // stream — same engine seam + even pad — and is bit-exact lossless.
    #[test]
    fn fast_equals_candidate_zero_and_roundtrips() {
        assert_eq!(FAST_CANDIDATE, CANDIDATES[0]);
        let (fw, fh) = (482u32, 272u32); // 1x1 grid, exact fill (no padding)
        let g = Grid::new(fw, fh);
        let mosaic = test_mosaic(fw, fh);
        for prec in [10u32, 12] {
            let (chosen, cands) =
                encode_tile_candidates(&mosaic, fw, fh, &g, 0, 0, prec).unwrap();
            let fast = encode_tile_fast(&mosaic, fw, fh, &g, 0, 0, prec).unwrap();
            assert_eq!(
                fast, cands.0[0],
                "prec {prec}: fast stream != candidate 0 (Wrapped PSV 7)"
            );
            // --fast is candidate 0; the adaptive choice is the min over
            // all 3, so the fast tile is always >= the adaptive tile
            // (equality exactly where candidate 0 wins). Measured
            // that price: +1.42% (dark) .. +4.27% (bright) at frame level.
            assert!(fast.len() >= chosen.len());
            // Bit-exact roundtrip of the fast tile (the decode side is
            // orientation-agnostic — verify needs no fast-mode change):
            let rect = tile_region(fw, fh, &g, 0, 0).unwrap();
            let back = decode_tile(&fast, &rect, prec, g.th).unwrap();
            assert_eq!(
                back, mosaic,
                "prec {prec}: fast tile must decode pixel-exact"
            );
        }
    }

    /// 0.2.0 engine default: native is shipped; the FFI escape hatch
    /// matches its three documented values, case-insensitive; anything
    /// else (incl. typos) is native — the engines are byte-identical,
    /// so a mis-set var can never change the output bytes.
    #[test]
    fn engine_from_selection() {
        assert_eq!(engine_from(None), Engine::Native, "env-absent default");
        assert_eq!(engine_from(Some("")), Engine::Native);
        assert_eq!(engine_from(Some("native")), Engine::Native);
        assert_eq!(engine_from(Some("nativ")), Engine::Native, "typo → native");
        assert_eq!(engine_from(Some("ffi")), Engine::Ffi);
        assert_eq!(engine_from(Some("FFI")), Engine::Ffi, "case-insensitive");
        assert_eq!(engine_from(Some("libjpeg")), Engine::Ffi);
        assert_eq!(engine_from(Some("legacy")), Engine::Ffi);
    }
}
