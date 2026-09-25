//! Two-scan 12-bit baseline-DCT decoder for tag-7 (Compression 7,
//! "lossless") lossy cDNG format — the acceptance pixel gate for the lossy
//! path .
//!
//! THE BOTH-SCANS DECODER: rawpy/LibRaw reconstructs only scan 0 (even tile
//! rows; odd rows = 0) for this format, so the tag-7 format's true full-image
//! quality is only measurable with this module. Semantics are a faithful
//! port of the research script `tools/dct12_tile_scan.py`, which is
//! bit-exact against rawpy 0.27.1 (LibRaw commit b860248a — the same source
//! the tag-7 corpus file is decoded with):
//! 99.998–99.9996 % exact, max ±1 LSB (float32-vs-float64 IDCT rounding
//! class).
//!
//! Per-tile dct12 structure (docs/format-dct12.md §2):
//! SOI → DQT (16-bit, tq=0 shared) → 4 DHT (TcTq 00/01/10/11, non-standard
//! class bytes) → SOF1 (precision 12, 544×1928, 2 components 1×1) →
//! SOS0 + scan 0 → SOS1 + scan 1 → EOI. Each scan = one single-component
//! 1928×544 DCT plane = 241×68 8×8 blocks in raster order. scan 0 → even
//! tile rows, scan 1 → odd tile rows (LibRaw case 0xc1 mapping; the SOS
//! Ss/Se bytes carry the parity marker 00 00 / 01 11). Last-row tiles
//! (1082 real rows) carry 3 padded plane rows, clipped at assembly.
//!
//! DECODE SEMANTICS (LibRaw `ljpeg_idct` + `adobe_copy_pixel`, verified):
//! * Huffman: `make_decoder_ref` builds the fully expanded table
//!   (huff[0] = maxlen; each len-bit code occupies 2^(max-len) consecutive
//!   entries; over-subscription tolerated — the write stops at 2^max and the
//!   remaining slots stay 0 = (len 0, sym 0)). `getbithuff` reads the top
//!   `maxlen` bits of a 32-bit MSB-first buffer and consumes only the stored
//!   code length. Bit stuffing: FF 00 → the FF byte's 8 bits ARE in the
//!   stream, the 0x00 is dropped; FF xx≠0 → both bytes consumed, reader
//!   enters reset mode (no more refills).
//! * DC: `vpred` restarts at 16384 per tile/scan (hardcoded for case 0xc1);
//!   `vpred += diff * quant[0]` (vpred is the dequantized DC coefficient);
//!   DC symbol length 16 → diff = -32768 (DNG ≥ 1.1 rule; this format is
//!   always DNG 1.4).
//! * AC: `for (i = 1; i < 64; i++)` — FILE position 1; `i += skip` then the
//!   FOR-LOOP `i++` (advance per coefficient = skip + 1); EOB (len 0,
//!   skip < 15) ends the block; ZRL (15,0) writes a 0 coefficient; the
//!   coefficient is dequantized as `work[zigzag[i]] = coef * quant[i]` —
//!   quant indexed by FILE position (DQT order), NOT natural order.
//! * IDCT: orthonormal (cs table = cos(kπ/16)/2 with √½ pre-scaling on the
//!   DC row/col → DC-only blocks give X00/8); float32 in LibRaw's
//!   operation order.
//! * Rounding/clip: `idct[c] = LIM((int)(P + 0.5), 0, 65535)` — C cast
//!   truncates toward zero (NOT round-half-even, NOT floor); NOT clipped to
//!   4095 here.
//! * LinearizationTable (tag 50712 / 0xC618, SHORT×4096): the decoded pixel
//!   is passed through `curve[]` (`adobe_copy_pixel`: RAW = curve[**rp]);
//!   `linear_table` takes the tag values verbatim and pads the tail with the
//!   last value. THIS FORMAT'S CURVE IS NOT THE IDENTITY (identity on
//!   0..255, compressing 256..4095 — e.g. curve[549]=271,
//! curve[2048]=549): it is the tag-7 format's highlight-range compaction that
//!   shrinks DCT AC energy. (The ab-lossy report's "identity LUT"
//!   claim was a measurement error — raw IFD bytes + a rawpy probe DNG
//! disprove it)

use std::collections::BTreeMap;

use thiserror::Error;

/// 8×8 zigzag order (file position → natural index). Entries 64..79 pad to
/// 63, exactly as LibRaw's 80-entry table (only reachable with i ≥ 64,
/// where the coefficient is always 0 — see `decode_scan`).
pub const ZIGZAG: [u8; 80] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63,
    63, 63, 63, 63, 63, 63,
];

/// DC prediction start (LibRaw case 0xc1 hardcodes 16384 per tile/scan).
pub const VPRED0: i32 = 16384;

/// Blocks per scan plane: 241 × 68 (1928/8 × 544/8).
pub const NBLK_W: usize = 241;
pub const NBLK_H: usize = 68;
pub const NB: usize = NBLK_W * NBLK_H;

#[derive(Error, Debug, PartialEq)]
pub enum Dct2sError {
    #[error("no DHT {0:02x} in tile")]
    TableMissing(u8),
    #[error("no tq=0 DQT in tile")]
    NoDqt,
    #[error("EOI not found in tile")]
    NoEoi,
    #[error("Huffman table empty (no codes)")]
    EmptyTable,
    #[error("Huffman: more counts than symbols")]
    MoreCountsThanSymbols,
    #[error("bit underflow at byte {0} (lost sync?)")]
    BitUnderflow(usize),
    #[error("truncated scan data at byte {0}")]
    Truncated(usize),
    #[error("DNG 50712 (LinearizationTable) has {0} entries (need ≥ 1)")]
    BadCurve(usize),
    #[error("tile geometry: need 4 tiles, got {0}")]
    BadTileCount(usize),
}

// ---------------------------------------------------------------------------
// Huffman tables
// ---------------------------------------------------------------------------

/// Exact port of LibRaw `make_decoder_ref`.
///
/// Returns the fully expanded table `huff` of length 1 + 2^maxlen with
/// `huff[0] = maxlen` and `huff[c+1] = (len << 8) | sym` for the code whose
/// top-`maxlen`-bit value is `c`. Each len-bit symbol occupies
/// `2^(maxlen - len)` consecutive slots; once the array is full
/// (over-subscription) writes stop but the symbols are still consumed —
/// matching the C `if (h <= 1 << max)` guard.
pub fn make_decoder_ref(counts16: &[u8], syms: &[u8]) -> Result<Vec<u16>, Dct2sError> {
    if counts16.len() != 16 {
        return Err(Dct2sError::EmptyTable);
    }
    let mut maxl = 16;
    while maxl > 0 && counts16[maxl - 1] == 0 {
        maxl -= 1;
    }
    if maxl == 0 {
        return Err(Dct2sError::EmptyTable);
    }
    let nslots = 1usize << maxl;
    let mut huff = vec![0u16; 1 + nslots];
    huff[0] = maxl as u16;
    let mut h: usize = 1;
    let mut si = 0usize;
    for ln in 1..=maxl {
        for _ in 0..counts16[ln - 1] {
            if si >= syms.len() {
                return Err(Dct2sError::MoreCountsThanSymbols);
            }
            let s = syms[si];
            si += 1;
            for _ in 0..(1usize << (maxl - ln)) {
                if h <= nslots {
                    huff[h] = ((ln as u16) << 8) | s as u16;
                    h += 1;
                }
            }
        }
    }
    Ok(huff)
}

// ---------------------------------------------------------------------------
// Bit reader (exact LibRaw getbithuff/getbits semantics)
// ---------------------------------------------------------------------------

/// 32-bit MSB-first bit reader with JPEG bit stuffing, exactly as LibRaw's
/// `getbithuff` (zero_after_ff path): FF 00 → FF's bits in stream, 0x00
/// dropped; FF xx≠0 → both consumed, `reset` (no more refills); a table read
/// (huff = Some) consumes only the stored code length, a raw read consumes
/// `nbits`.
#[derive(Debug)]
pub struct BitReader<'a> {
    data: &'a [u8],
    pub i: usize,
    bitbuf: u32,
    vbits: i32,
    reset: bool,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            i: 0,
            bitbuf: 0,
            vbits: 0,
            reset: false,
        }
    }

    /// LibRaw getbithuff. `huff` = Some(&huff[1..]) for a table read
    /// (nbits = huff[0] = maxlen, returns the symbol and consumes the
    /// stored length) or None for a raw n-bit read.
    // The explicit 32-bit masks below document the bit width even though
    // `<<` on a u32 already truncates (clippy identity_op allow).
    #[allow(clippy::identity_op)]
    fn getbithuff(&mut self, nbits: u32, huff: Option<&[u16]>) -> Result<u32, Dct2sError> {
        if nbits > 25 {
            return Ok(0);
        }
        if nbits == 0 || self.vbits < 0 {
            return Ok(0);
        }
        while !self.reset && self.vbits < nbits as i32 {
            // EOF mid-refill: return c = 0 with NO state change (exact
            // Python-reference / LibRaw behavior — the final block's codes
            // may end mid-byte and rely on this).
            if self.i >= self.data.len() {
                return Ok(0);
            }
            let c = self.data[self.i];
            self.i += 1;
            if c == 0xFF {
                if self.i >= self.data.len() {
                    break; // FF at EOF: byte discarded, stop refilling
                }
                let nxt = self.data[self.i];
                self.i += 1;
                if nxt == 0x00 {
                    // stuffing: the FF byte's 8 bits ARE part of the stream;
                    // only the 0x00 is discarded (LibRaw: reset stays 0, the
                    // loop body adds the FF byte).
                    self.bitbuf = ((self.bitbuf << 8) | 0xFF) & 0xFFFF_FFFF;
                    self.vbits += 8;
                    continue;
                }
                self.reset = true; // marker: stop (both bytes consumed)
                break;
            }
            self.bitbuf = ((self.bitbuf << 8) | u32::from(c)) & 0xFFFF_FFFF;
            self.vbits += 8;
        }
        let c: u32 = if self.vbits == 0 {
            0
        } else {
            (self.bitbuf << (32 - self.vbits as u32)) >> (32 - nbits)
        };
        if let Some(huff) = huff {
            let e = huff[c as usize];
            self.vbits -= i32::from(e >> 8);
            if self.vbits < 0 {
                return Err(Dct2sError::BitUnderflow(self.i));
            }
            return Ok(u32::from(e & 0xFF));
        }
        self.vbits -= nbits as i32;
        if self.vbits < 0 {
            return Err(Dct2sError::BitUnderflow(self.i));
        }
        Ok(c)
    }

    /// LibRaw getbits(n): raw n-bit read.
    pub fn getbits(&mut self, n: u32) -> Result<u32, Dct2sError> {
        self.getbithuff(n, None)
    }

    /// LibRaw getbits(-1): full reset (bitbuf = vbits = reset = 0).
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn reset_bits(&mut self) {
        self.bitbuf = 0;
        self.vbits = 0;
        self.reset = false;
    }
}

// ---------------------------------------------------------------------------
// Scan decode
// ---------------------------------------------------------------------------

/// Decode `nblocks` 8×8 blocks (raster order) from one scan bitstream.
///
/// Returns `(vpreds, coeffs)`: per-block dequantized DC prediction value
/// (== the DC coefficient, `vpred += diff * quant[0]`) and the 64 natural-
/// order dequantized coefficients (ACs already multiplied by `quant[i]` in
/// FILE/zigzag order; slot 0 = the DC value, for convenience).
pub fn decode_scan(
    data: &[u8],
    h_dc: &[u16],
    h_ac: &[u16],
    quant: &[u16],
    nblocks: usize,
) -> Result<(Vec<i32>, Vec<[i32; 64]>), Dct2sError> {
    if quant.len() != 64 {
        return Err(Dct2sError::NoDqt);
    }
    let mut br = BitReader::new(data);
    let mut vpred = VPRED0;
    let q0 = i32::from(quant[0]);
    let q: Vec<i32> = quant.iter().map(|&v| i32::from(v)).collect();
    let mut vpreds = Vec::with_capacity(nblocks);
    let mut coeffs: Vec<[i32; 64]> = Vec::with_capacity(nblocks);
    for _ in 0..nblocks {
        // DC (LibRaw ljpeg_diff): symbol = diff bit length; length 16 →
        // -32768 (DNG >= 1.1 rule; this format is always DNG 1.4).
        let ln = br.getbithuff(u32::from(h_dc[0]), Some(&h_dc[1..]))? as usize;
        let diff = if ln == 16 {
            -32768
        } else {
            let d = br.getbits(ln as u32)? as i32;
            if ln > 0 && (d & (1 << (ln - 1))) == 0 {
                d - ((1 << ln) - 1)
            } else {
                d
            }
        };
        vpred += diff * q0;
        vpreds.push(vpred);

        let mut cs = [0i32; 64];
        cs[0] = vpred;
        // LibRaw ljpeg_idct AC loop: for (i = 1; i < 64; i++) { len =
        // gethuff(); i += skip = len >> 4; if EOB break; coef = getbits(len);
        // work[zigzag[i]] = coef * quant[i]; } — the for-loop i++ after each
        // non-EOB coefficient (advance = skip + 1: skip zeros BETWEEN).
        let mut i = 1usize;
        while i < 64 {
            let sym = br.getbithuff(u32::from(h_ac[0]), Some(&h_ac[1..]))?;
            let skip = (sym >> 4) as usize;
            i += skip;
            let ln = (sym & 15) as usize;
            if ln == 0 && skip < 15 {
                break; // EOB
            }
            let d = br.getbits(ln as u32)? as i32;
            let d = if ln > 0 && (d & (1 << (ln - 1))) == 0 {
                d - ((1 << ln) - 1)
            } else {
                d
            };
            if i < 64 {
                // C writes work[zigzag[i]] = coef * quant[i] unconditionally;
                // for i >= 64 the coefficient is always 0 (ZRL: len 0 →
                // getbits(0) = 0), so 0*quant == 0 == skipping. A valid DCT
                // block has at most 63 AC coefficients, so i never reaches
                // 64 with a non-zero coefficient.
                cs[ZIGZAG[i] as usize] = d * q[i];
            }
            i += 1; // the for-loop increment (skipped on the EOB break)
        }
        coeffs.push(cs);
    }
    Ok((vpreds, coeffs))
}

// ---------------------------------------------------------------------------
// IDCT
// ---------------------------------------------------------------------------

const SQRT_HALF_F32: f32 = 0.707_106_77f32;

/// LibRaw's cs table: cs[c] = float(cos((c & 31) * M_PI / 16) / 2), 106
/// entries (max index (2*7+1)*7 = 105).
fn cs_table() -> [f32; 106] {
    let mut cs = [0f32; 106];
    for (c, slot) in cs.iter_mut().enumerate() {
        *slot = (((c & 31) as f32) * std::f32::consts::PI / 16.0).cos() / 2.0;
    }
    cs
}

/// LibRaw `CLIP(x)`: LIM((int)(x), 0, 65535) — C cast truncates toward zero.
fn round_clip(p: f32) -> u16 {
    let v = (p + 0.5) as i32; // truncation toward zero (NOT floor)
    v.clamp(0, 65535) as u16
}

/// Orthonormal IDCT of one block in LibRaw's exact operation order
/// (float32, cs table, √½ pre-scaling on the DC row/col, two 1-D passes
/// with sequential accumulation), then `(int)(P + 0.5)` rounding + clip
/// 0..65535. `coeffs` = natural-order dequantized coefficients with slot 0
/// = the DC prediction value. Returns 64 pixels (row-major 8×8), BEFORE the
/// LinearizationTable LUT.
pub fn idct_block(coeffs: &[i32; 64]) -> [u16; 64] {
    let cs = cs_table();
    let mut w = [[0f32; 8]; 8];
    for i in 0..8 {
        for j in 0..8 {
            w[i][j] = coeffs[i * 8 + j] as f32;
        }
    }
    // FORC(8) work[0][0][c] *= sqrt(1/2); FORC(8) work[0][c][0] *= sqrt(1/2)
    // `c` indexes BOTH dimensions (w[0][c] and w[c][0]) — a range loop, not
    // an iterator (clippy allow).
    #[allow(clippy::needless_range_loop)]
    for c in 0..8 {
        w[0][c] *= SQRT_HALF_F32;
        w[c][0] *= SQRT_HALF_F32;
    }
    // work[1][i][j] = sum_c work[0][i][c] * cs[(2j+1)c]
    let mut w1 = [[0f32; 8]; 8];
    for i in 0..8 {
        for j in 0..8 {
            let mut s = 0f32;
            for c in 0..8 {
                s += w[i][c] * cs[(2 * j + 1) * c];
            }
            w1[i][j] = s;
        }
    }
    // work[2][i][j] = sum_c work[1][c][j] * cs[(2i+1)c]
    let mut out = [0u16; 64];
    for i in 0..8 {
        for j in 0..8 {
            let mut s = 0f32;
            for c in 0..8 {
                s += w1[c][j] * cs[(2 * i + 1) * c];
            }
            out[i * 8 + j] = round_clip(s);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// LinearizationTable (tag 50712 / 0xC618)
// ---------------------------------------------------------------------------

/// LibRaw `linear_table`: tag u16 values verbatim into curve[0..n), tail
/// padded with the last value to 65536. Absent or empty tag → identity
/// (LibRaw: `if (len < 1) return;` leaves the identity curve in place).
pub fn linearization_curve(entries: Option<&[u16]>) -> Vec<u16> {
    match entries {
        None => (0..=65535u32).map(|i| i as u16).collect(),
        Some([]) => (0..=65535u32).map(|i| i as u16).collect(),
        Some(v) => {
            let mut curve = vec![v[v.len() - 1]; 65536];
            curve[..v.len()].copy_from_slice(v);
            curve
        }
    }
}

/// Apply the curve LUT to decoded (pre-curve) pixels.
pub fn apply_curve(curve: &[u16], pix: &mut [u16]) {
    for p in pix.iter_mut() {
        *p = curve[*p as usize];
    }
}

// ---------------------------------------------------------------------------
// Tile / frame level
// ---------------------------------------------------------------------------

/// One DHT table as stored in the marker.
#[derive(Debug, Clone)]
pub struct DhtTable {
    pub counts16: [u8; 16],
    pub syms: Vec<u8>,
}

/// Parsed tile markers (SOI..EOI).
#[derive(Debug)]
pub struct TileInfo {
    pub dht: BTreeMap<u8, DhtTable>,
    pub dqt: BTreeMap<u8, [u16; 64]>,
    /// (sos_marker_off, data_start, data_end) per SOS, in file order.
    pub sos: Vec<(usize, usize, usize)>,
}

/// Walk a tile's JPEG marker stream. Port of the verified Python
/// `parse_tile_markers`: DHT by TcTq, DQT by Tq (16-bit entries, precision
/// nibble ignored — LibRaw reads 16 bits per entry unconditionally), SOS
/// data = [marker + 2 + Ls, next marker) with FF 00 skipped in the walk
/// (the BitReader re-handles stuffing in place on the raw bytes).
pub fn parse_tile(tile: &[u8]) -> Result<TileInfo, Dct2sError> {
    let mut dht: BTreeMap<u8, DhtTable> = BTreeMap::new();
    let mut dqt: BTreeMap<u8, [u16; 64]> = BTreeMap::new();
    let mut sos: Vec<(usize, usize, usize)> = Vec::new();
    let n = tile.len();
    let mut i = 2usize;
    let mut eoi = false;
    while i + 1 < n && tile[i] == 0xFF {
        let m = tile[i + 1];
        if m == 0xD9 {
            eoi = true;
            break;
        }
        if m == 0xD8 || (0xD0..=0xD7).contains(&m) || m == 0x01 {
            i += 2;
            continue;
        }
        if i + 4 > n {
            break;
        }
        let ln = u16::from_be_bytes([tile[i + 2], tile[i + 3]]) as usize;
        if m == 0xC4 {
            let base = i + 4;
            let mut j = base;
            while j + 17 <= i + 2 + ln {
                let tctq = tile[j];
                let mut counts16 = [0u8; 16];
                counts16.copy_from_slice(&tile[j + 1..j + 17]);
                let nsym: usize = counts16.iter().map(|&c| c as usize).sum();
                if j + 17 + nsym > i + 2 + ln {
                    break;
                }
                let syms = tile[j + 17..j + 17 + nsym].to_vec();
                dht.insert(tctq, DhtTable { counts16, syms });
                j += 17 + nsym;
            }
        } else if m == 0xDB {
            let mut j = i + 4;
            let end = i + 2 + ln;
            while j < end && j + 129 <= n {
                let tq = tile[j] & 0x0F;
                let mut q = [0u16; 64];
                for t in 0..64 {
                    q[t] = u16::from_be_bytes([tile[j + 1 + 2 * t], tile[j + 2 + 2 * t]]);
                }
                dqt.insert(tq, q);
                j += 129;
            }
        } else if m == 0xDA {
            let data_start = i + 2 + ln;
            let mut j = data_start;
            while j + 1 < n {
                if tile[j] == 0xFF && tile[j + 1] != 0x00 {
                    break;
                }
                j += 1;
            }
            sos.push((i, data_start, j));
            i = j;
            continue;
        }
        i += 2 + ln;
    }
    if !eoi {
        return Err(Dct2sError::NoEoi);
    }
    Ok(TileInfo { dht, dqt, sos })
}

/// Decode one scan plane of one tile → (NBLK_H*8, NBLK_W*8) u16 pixels
/// (curve applied), block index = band*NBLK_W + col, plane row p = band*8 +
/// row-in-block.
pub fn decode_scan_plane(
    tile: &[u8],
    tile_info: &TileInfo,
    scan: usize,
    curve: &[u16],
) -> Result<(Vec<u16>, Vec<i32>), Dct2sError> {
    if scan >= tile_info.sos.len() {
        return Err(Dct2sError::NoEoi);
    }
    // per-scan table set: scan k → TcTq (k, 0x10 + k)
    let t = scan as u8;
    let tctq_dc = t;
    let tctq_ac = 0x10 + t;
    let td = tile_info
        .dht
        .get(&tctq_dc)
        .ok_or(Dct2sError::TableMissing(tctq_dc))?;
    let ta = tile_info
        .dht
        .get(&tctq_ac)
        .ok_or(Dct2sError::TableMissing(tctq_ac))?;
    let h_dc = make_decoder_ref(&td.counts16, &td.syms)?;
    let h_ac = make_decoder_ref(&ta.counts16, &ta.syms)?;
    let quant = tile_info.dqt.get(&0).ok_or(Dct2sError::NoDqt)?;
    let (_, ds, de) = tile_info.sos[scan];
    let (vpreds, coeffs) = decode_scan(&tile[ds..de], &h_dc, &h_ac, quant, NB)?;
    let mut plane = vec![0u16; NBLK_H * 8 * NBLK_W * 8];
    for (bi, c) in coeffs.iter().enumerate() {
        let (band, col) = (bi / NBLK_W, bi % NBLK_W);
        let px = idct_block(c);
        for r in 0..8 {
            let base = (band * 8 + r) * (NBLK_W * 8) + col * 8;
            for k in 0..8 {
                plane[base + k] = curve[px[r * 8 + k] as usize];
            }
        }
    }
    Ok((plane, vpreds))
}

/// Full-frame both-scan assembly (4 tiles, 2×2 grid): plane row p of tile
/// (tr, tc) → frame row tr*tl + 2p + scan, frame col tc*tw + …; rows beyond
/// `height` (last-row tiles: 1082 real of 1088) are clipped.
pub fn assemble_frame(
    tiles: &[&[u8]],
    tw: u32,
    tl: u32,
    width: u32,
    height: u32,
    curve: &[u16],
) -> Result<Vec<u16>, Dct2sError> {
    if tiles.len() != 4 {
        return Err(Dct2sError::BadTileCount(tiles.len()));
    }
    let mut frame = vec![0u16; (width * height) as usize];
    for (ti, tile) in tiles.iter().enumerate() {
        let info = parse_tile(tile)?;
        let (tr, tc) = (ti / 2, ti % 2);
        let ty0 = tr as u32 * tl;
        let tx0 = tc as u32 * tw;
        for scan in 0..2usize {
            let (plane, _) = decode_scan_plane(tile, &info, scan, curve)?;
            for p in 0..(NBLK_H * 8) {
                let y = ty0 + 2 * p as u32 + scan as u32;
                if y >= height {
                    continue;
                }
                let row =
                    &mut frame[(y as usize) * width as usize..(y as usize + 1) * width as usize];
                row[tx0 as usize..tx0 as usize + NBLK_W * 8]
                    .copy_from_slice(&plane[p * NBLK_W * 8..(p + 1) * NBLK_W * 8]);
            }
        }
    }
    Ok(frame)
}

// ---------------------------------------------------------------------------
// Quality metrics
// ---------------------------------------------------------------------------

/// Full-frame quality vs the original (both-scan reconstruction).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Quality {
    pub mae: f64,
    pub exact_pct: f64,
    pub le1_pct: f64,
    pub max_abs: u32,
    pub mae_even: f64,
    pub mae_odd: f64,
    /// The "ab-lossy" artifact, reproduced for comparison:
    /// even-row |d| summed, divided by TOTAL pixel count (== mae_even / 2),
    /// odd-row diff masked to 0.
    pub ab_style_mae: f64,
    /// Same masking for the exact count: (N_odd + exact_even) / N_total.
    pub ab_style_exact_pct: f64,
}

pub fn quality_metrics(decoded: &[u16], original: &[u16], width: u32, height: u32) -> Quality {
    debug_assert_eq!(decoded.len(), original.len());
    let n = decoded.len();
    let w = width as usize;
    let _ = height;
    let mut sum = 0u64;
    let mut sum_even = 0u64;
    let mut sum_odd = 0u64;
    let mut exact = 0u64;
    let mut exact_even = 0u64;
    let mut le1 = 0u64;
    let mut max_abs = 0u32;
    for i in 0..n {
        let p = decoded[i];
        let o = original[i];
        let d = (p as i64 - o as i64).unsigned_abs();
        sum += d;
        if i / w % 2 == 0 {
            // frame-row parity (row y = i / w)
            sum_even += d;
            if d == 0 {
                exact_even += 1;
            }
        } else {
            sum_odd += d;
        }
        if d == 0 {
            exact += 1;
        }
        if d <= 1 {
            le1 += 1;
        }
        max_abs = max_abs.max(d as u32);
    }
    let n_even = (n as f64 / 2.0).round();
    Quality {
        mae: sum as f64 / n as f64,
        exact_pct: 100.0 * exact as f64 / n as f64,
        le1_pct: 100.0 * le1 as f64 / n as f64,
        max_abs,
        mae_even: sum_even as f64 / n_even,
        mae_odd: sum_odd as f64 / n_even,
        ab_style_mae: sum_even as f64 / n as f64,
        ab_style_exact_pct: 100.0 * ((n / 2) as f64 + exact_even as f64) / n as f64,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The LibRaw source's own make_decoder_ref doc example (comment in
    /// decoders_dcraw.cpp): counts (1×len1, 4×len2, 2×len3, 3×len4, 1×len5,
    /// 1×len6, 1×len7), syms 04 03 05 06 02 07 01 08 09 00 0a 0b ff.
    /// This table is OVER-SUBSCRIBED at max = 7: len1 fills 64 slots (c0-63)
    /// and len2 needs 128 more (c64-191) but only 128 slots exist (c0-127):
    /// writes stop once h > 128 while the remaining symbols are still
    /// consumed (the C `if (h <= 1 << max)` guard) — no error.
    /// Hand-computed: c0-63 → (1, 0x04); c64-95 → (2, 0x03); c96-127 →
    /// (2, 0x05); nothing written beyond slot 128 (sym 0x06 onward never
    /// lands; h[128] = 0).
    #[test]
    fn make_decoder_ref_doc_example() {
        let counts: [u8; 16] = [1, 4, 2, 3, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let syms: [u8; 13] = [
            0x04, 0x03, 0x05, 0x06, 0x02, 0x07, 0x01, 0x08, 0x09, 0x00, 0x0a, 0x0b, 0xff,
        ];
        let h = make_decoder_ref(&counts, &syms).unwrap();
        assert_eq!(h.len(), 1 + 128);
        assert_eq!(h[0], 7); // maxlen
                             // code 0000000 (c=0 → slot 1): (len 1, sym 0x04)
        assert_eq!(h[1], (1u16 << 8) | 0x04);
        // code 0100000 (c=32 → slot 33): still len1 sym 0x04
        assert_eq!(h[33], (1u16 << 8) | 0x04);
        // code 1000000 (c=64 → slot 65): (len 2, sym 0x03)
        assert_eq!(h[65], (2u16 << 8) | 0x03);
        // code 1100000 (c=96 → slot 97): (len 2, sym 0x05)
        assert_eq!(h[97], (2u16 << 8) | 0x05);
        // Over-subscription: c=120 (slot 121) is still in sym 0x05's 32-slot
        // range — sym 0x06 was consumed but never written.
        assert_eq!(h[121], (2u16 << 8) | 0x05);
        // c=127 (slot 128): last writable slot, still (2, 0x05); c=128.. don't
        // exist (array length 129).
        assert_eq!(h[128], (2u16 << 8) | 0x05);
    }

    /// Over-subscription: 3 one-bit symbols in a max=1 table can only fill
    /// 2 slots; the third is consumed but not written (C guard).
    #[test]
    fn make_decoder_ref_over_subscription() {
        let counts: [u8; 16] = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let syms = [7u8, 8, 9];
        let h = make_decoder_ref(&counts, &syms).unwrap();
        assert_eq!(h[0], 1);
        assert_eq!(h[1], (1u16 << 8) | 7); // code 0
        assert_eq!(h[2], (1u16 << 8) | 8); // code 1
                                           // sym 9 was consumed but the table is full — no slot for it.
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn bitreader_ff00_keeps_ff_drops_zero() {
        // FF 00 55: the FF byte's bits ARE in the stream; the 0x00 is
        // dropped → 16-bit read = 0xFF55.
        let data: &[u8] = &[0xFF, 0x00, 0x55];
        let mut br = BitReader::new(data);
        assert_eq!(br.getbits(16).unwrap(), 0xFF55);
        assert_eq!(br.i, 3);
    }

    #[test]
    fn bitreader_ff_nonzero_resets() {
        // FF 10: marker — both bytes consumed, reader resets with no bits:
        // the read returns c = 0 and the bit counter goes negative →
        // LibRaw derrors; here: BitUnderflow.
        let data: &[u8] = &[0xFF, 0x10];
        let mut br = BitReader::new(data);
        assert!(matches!(br.getbits(8), Err(Dct2sError::BitUnderflow(_))));
        assert!(br.reset);
    }

    /// A table read must consume only the STORED code length (3 here), not
    /// the maxlen window (4): the leftover window bit belongs to the next
    /// read. Table (max 4): len3 syms 7, 8 → codes 0000/0001, 0010/0011;
    /// len4 sym 9 → 0100.
    #[test]
    fn bitreader_table_read_consumes_stored_length_only() {
        let counts: [u8; 16] = [0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let h = make_decoder_ref(&counts, &[7u8, 8, 9]).unwrap();
        assert_eq!(h[0], 4);
        // stream bits: 000 (table code 0000/0001 → sym 7, stored len 3) 0111
        // (raw 4) 0 → 0000 0111 0
        let data: &[u8] = &[0x0E];
        let mut br = BitReader::new(data);
        assert_eq!(br.getbithuff(4, Some(&h[1..])).unwrap(), 7);
        // If the read had consumed the 4-bit window, this would be 14
        // (1110); stored-length consumption leaves 0111 = 7.
        assert_eq!(br.getbits(4).unwrap(), 7);
        assert_eq!(br.getbits(1).unwrap(), 0);
        assert_eq!(br.i, 1);
    }

    /// Synthetic scan: 3 blocks with a hand-computed bitstream (the bits
    /// were traced by hand against the reader step by step).
    ///
    /// DC table (max 4): counts len3: 2 (syms 0, 2), len4: 2 (syms 1, 9).
    ///   canonical: len3 codes 000/001 → sym0/sym2; len4 codes 0100/0101 →
    ///   sym1/sym9. Expansion (16 slots): c0,1 → (3,0); c2,3 → (3,2);
    ///   c4 → (4,1); c5 → (4,9); c6..15 → 0.
    /// AC table (max 4): counts len3: 1 (sym 0 = EOB), len4: 1 (sym 4 =
    ///   (skip0, len4)). canonical: 000 → EOB; 0010 → sym4. Expansion:
    ///   c0,1 → (3,0); c2,3 → (4,4); c4..15 → 0.
    ///
    /// Stream (30 bits):
    ///   B0: 0100 (DC sym1) + 1 (diff +1, MSB set) + 000 (EOB)
    ///   B1: 001 (DC sym2) + 01 (diff: 1-3 = -2) + 000 (EOB)
    ///   B2: 000 (DC sym0) + 0010 (AC (0,4)) + 1001 (coef +9) + 000 (EOB)
    ///   = 01001000 00101000 00000001 01001000
    ///   (bit layout traced by hand AND cross-checked against the verified
    ///   Python reference reader)
    #[test]
    fn decode_scan_synthetic_chain() {
        let dc_counts: [u8; 16] = [0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let dc_syms = [0u8, 2, 1, 9];
        let h_dc = make_decoder_ref(&dc_counts, &dc_syms).unwrap();
        assert_eq!(h_dc[0], 4);
        let ac_counts: [u8; 16] = [0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let ac_syms = [0u8, 4];
        let h_ac = make_decoder_ref(&ac_counts, &ac_syms).unwrap();
        assert_eq!(h_ac[0], 4);
        let data: &[u8] = &[0x48, 0x28, 0x05, 0x20];
        let quant = vec![3u16; 64]; // q0 = 3
        let (vpreds, coeffs) = decode_scan(data, &h_dc, &h_ac, &quant, 3).unwrap();
        // B0: vpred = 16384 + 1*3; B1: - 2*3; B2: unchanged.
        assert_eq!(vpreds, vec![16384 + 3, 16384 + 3 - 6, 16384 + 3 - 6]);
        // B2: file pos 1 → ZIGZAG[1] = 1 → natural (0,1): 9 * quant[1] = 27.
        // DC slot 0 = vpred.
        assert_eq!(coeffs[2][0], vpreds[2]);
        assert_eq!(coeffs[2][1], 27);
        assert!(coeffs[2][2..].iter().all(|&c| c == 0));
        assert!(coeffs[0][1..].iter().all(|&c| c == 0));
    }

    /// ZRL (15,0) writes a zero at the advanced position and the advance is
    /// skip + 1: after a ZRL from position 1, i = 1 + 15 = 16, the for-loop
    /// i++ → 17, so the NEXT coefficient lands at file position 17.
    #[test]
    fn decode_scan_zrl_advance() {
        // DC: as the synthetic test (max 4: 0000/0001 → (3,0); 0010/0011 →
        // (3,2); 0100 → (4,1); 0101 → (4,9)).
        let dc_counts: [u8; 16] = [0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let dc_syms = [0u8, 2, 1, 9];
        let h_dc = make_decoder_ref(&dc_counts, &dc_syms).unwrap();
        // AC: len3: 1 sym (240 = ZRL) → code 000 (slots c0,1); len4: 2 syms
        // (0 = EOB → 0010/c2, 1 = (0,1) → 0011/c3).
        let ac_counts: [u8; 16] = [0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let ac_syms = [240u8, 0, 1];
        let h_ac = make_decoder_ref(&ac_counts, &ac_syms).unwrap();
        // Stream (15 bits):
        //   000 (DC sym0) 000 (ZRL) 0011 1 ((0,1) coef +1) 0010 (EOB)
        //   = 00000000 11100100
        let data: &[u8] = &[0x00, 0xE4];
        let quant = vec![2u16; 64];
        let (vpreds, coeffs) = decode_scan(data, &h_dc, &h_ac, &quant, 1).unwrap();
        assert_eq!(vpreds, vec![VPRED0]);
        let c = &coeffs[0];
        assert_eq!(c[ZIGZAG[16] as usize], 0); // ZRL wrote a 0 (natural 32)
        assert_eq!(c[ZIGZAG[17] as usize], 1 * 2); // (0,1) @ pos 17 (natural 33)
        assert_eq!(c[ZIGZAG[18] as usize], 0); // nothing at the next position
    }
    /// DC-only IDCT: P = X00/8 exactly (orthonormal scaling), then
    /// (int)(P + 0.5) trunc + clip.
    #[test]
    fn idct_dc_only_scaling_and_rounding() {
        let mut c = [0i32; 64];
        c[0] = 4394; // real-file block 0 vpred
        let p = idct_block(&c);
        // (int)(4394/8 + 0.5) = (int)(549.75) = 549
        assert!(p.iter().all(|&v| v == 549), "{p:?}");
        c[0] = 16384;
        let p = idct_block(&c);
        assert!(p.iter().all(|&v| v == 2048)); // 16384/8 = 2048.0
        c[0] = 16004;
        let p = idct_block(&c);
        assert!(p.iter().all(|&v| v == 2001)); // (int)(2000.5 + 0.5) = 2001
        c[0] = -8;
        let p = idct_block(&c);
        // P = -1.0 → (int)(-0.5) = 0 → all 0 (trunc toward zero, then clip)
        assert!(p.iter().all(|&v| v == 0));
        c[0] = -12;
        let p = idct_block(&c);
        // P = -1.5 → (int)(-1.0) = -1 → clip 0
        assert!(p.iter().all(|&v| v == 0));
        c[0] = 65536 * 8; // over the 16-bit range (not reachable in-file,
                          // but the clip must hold)
        let p = idct_block(&c);
        assert!(p.iter().all(|&v| v == 65535));
    }

    /// Single AC coefficient (0,1) = 50: hand-computed orthonormal IDCT.
    /// P[i][c] = 50 * (1/sqrt(8)) * 0.5 * cos((2c+1)π/16); the (i) axis is
    /// flat (u = 0). Row 0, f64 reference, (int)(P+0.5):
    ///   c0: 50·0.353553·0.5·0.980785 = 8.6813 → 9
    ///   c1: 50·0.353553·0.5·0.831470 = 7.3432 → 7
    ///   c2: 50·0.353553·0.5·0.555570 = 4.9034 → 5
    ///   c3: 50·0.353553·0.5·0.195090 = 1.7270 → 2
    ///   c4: 50·0.353553·0.5·(-0.195090) = -1.7270 → (int)(-1.227) = -1
    ///   c5: -4.9034 → (int)(-4.4034) = -4
    ///   c6: -7.3432 → (int)(-6.8432) = -6
    ///   c7: -8.6813 → (int)(-8.1813) = -8
    #[test]
    fn idct_single_ac_hand_computed() {
        let mut c = [0i32; 64];
        c[1] = 50; // natural (0,1)
        let p = idct_block(&c);
        let row: [i32; 8] = [
            p[0] as i32,
            p[1] as i32,
            p[2] as i32,
            p[3] as i32,
            p[4] as i32,
            p[5] as i32,
            p[6] as i32,
            p[7] as i32,
        ];
        assert_eq!(row, [9, 7, 5, 2, 0, 0, 0, 0]); // negatives clip to 0
                                                   // all 8 rows identical (u = 0 → no row dependence)
        for r in 0..8 {
            let row: [i32; 8] = [
                p[r * 8] as i32,
                p[r * 8 + 1] as i32,
                p[r * 8 + 2] as i32,
                p[r * 8 + 3] as i32,
                p[r * 8 + 4] as i32,
                p[r * 8 + 5] as i32,
                p[r * 8 + 6] as i32,
                p[r * 8 + 7] as i32,
            ];
            assert_eq!(row, [9, 7, 5, 2, 0, 0, 0, 0], "row {r}");
        }
    }

    /// round_clip: (int)(P + 0.5) then clamp 0..65535. (Truncation toward
    /// zero vs floor is not observable after the clip: any negative
    /// intermediate clamps to 0 either way — what is pinned is the
    /// round-half-UP of P+0.5, not round-half-even.)
    #[test]
    fn round_clip_trunc_semantics() {
        assert_eq!(round_clip(2.4f32), 2);
        assert_eq!(round_clip(2.5f32), 3); // +0.5 then trunc
        assert_eq!(round_clip(3.5f32), 4);
        assert_eq!(round_clip(-1.2f32), 0); // negative intermediate → clip 0
        assert_eq!(round_clip(-17.864f32), 0);
        assert_eq!(round_clip(-5.0f32), 0); // clip
        assert_eq!(round_clip(70_000.0f32), 65535); // clip
    }

    /// linear_table: values verbatim, tail padded with the last value;
    /// absent tag → identity.
    #[test]
    fn linearization_curve_padding() {
        let entries: Vec<u16> = (0..=100u16).map(|i| i * 2).collect(); // 101 entries
        let curve = linearization_curve(Some(&entries));
        assert_eq!(curve.len(), 65536);
        assert_eq!(curve[0], 0);
        assert_eq!(curve[50], 100);
        assert_eq!(curve[100], 200);
        assert_eq!(curve[101], 200); // padded with the last value
        assert_eq!(curve[65535], 200);
        let id = linearization_curve(None);
        assert_eq!(id[1234], 1234);
        assert_eq!(id[65535], 65535);
    }

    /// apply_curve on the real vbr-hq f1 curve points (measured from the
    /// file's 50712 tag): curve[549] = 271, curve[2048] = 549.
    #[test]
    fn apply_curve_real_points() {
        // A curve matching the real file at the probe points.
        let mut curve = vec![0u16; 65536];
        for i in 0..65536usize {
            curve[i] = i as u16;
        }
        curve[549] = 271;
        curve[2048] = 549;
        let mut pix = vec![549u16, 2048, 777];
        apply_curve(&curve, &mut pix);
        assert_eq!(pix, vec![271, 549, 777]);
    }

    /// Marker walk: a minimal synthetic tile shaped like the real reference
    /// markers (DQT Ls = 131 = 1 + 128; SOF1 Ls = 14 with 2 parity-plane
    /// components; SOS Ls = 8: Nf=1 + comp id/hv + SsSe 3F 00), DHT by
    /// TcTq, EOI-terminated. (Measured from the tag-7 corpus file.)
    #[test]
    fn parse_tile_markers_synthetic() {
 // FF D8 | FF DB 00 83 00 q0 q1 … (64×16-bit, tq 0) |
        // FF C4 00 13 00 c0..c15 s0 s1 |
        // FF C1 00 0E 0C H H W W 2 comp1 comp2 | (SOF1 prec 12)
        // FF DA 00 08 01 00 00 00 3F 00 | data 4 B |
 // FF DA 00 08 01 01 11 00 3F 00 | data 2 B | FF D9
        let mut t: Vec<u8> = vec![0xFF, 0xD8];
        t.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x83, 0x00]);
        for k in 0..64 {
            t.extend_from_slice(&[(k as u8) as u8, 0x01u8]); // q[k] = k
        }
        t.extend_from_slice(&[0xFF, 0xC4, 0x00, 0x15, 0x00]);
        let counts: [u8; 16] = [0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        t.extend_from_slice(&counts);
        t.extend_from_slice(&[0u8, 4]);
        t.extend_from_slice(&[
            0xFF, 0xC1, 0x00, 0x0E, 0x0C, 0x02, 0x20, 0x07, 0x88, 0x02, 0x00, 0x11, 0x00, 0x01,
            0x11, 0x00,
        ]);
        t.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x3F, 0x00]);
        t.extend_from_slice(&[0x11, 0xFF, 0x00, 0x22]); // scan0: FF00 stuffed
        t.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x11, 0x00, 0x3F, 0x00]);
        t.extend_from_slice(&[0x33, 0x44]); // scan1
        t.extend_from_slice(&[0xFF, 0xD9]);
        let info = parse_tile(&t).unwrap();
        assert!(info.dht.contains_key(&0x00));
        let q = info.dqt.get(&0).unwrap();
        assert_eq!(q[0], 1);
        assert_eq!(q[5], 0x0501);
        assert_eq!(q[63], 0x3F01);
        assert_eq!(info.sos.len(), 2);
        let (_, s0, e0) = info.sos[0];
        assert_eq!(&t[s0..e0], &[0x11, 0xFF, 0x00, 0x22]); // FF00 kept in range
        let (_, s1, e1) = info.sos[1];
        assert_eq!(&t[s1..e1], &[0x33, 0x44]);
    }

    /// Real-file smoke anchor (run with `cargo test -- --ignored` with the
    /// testdata tree present): tile 0 scan 0 of vbr-hq f1 must reproduce the
    /// rawpy/LibRaw ground truth block 0 EXACTLY (64 pixels, measured) and
    /// the vpred chain start (4394 = 16384 − 2398·5).
    #[test]
    #[ignore]
    fn real_file_tile0_block0_matches_rawpy_gt() {
        let path = "../testdata/reference/vbr-hq/A001_001/A001_001_20260701_000001.DNG";
        let vb = std::fs::read(path).expect("reference file");
        // minimal LE IFD walk for tags 256/257/324/325/0xC618
        let u16le = |o: usize| u16::from_le_bytes([vb[o], vb[o + 1]]);
        let ifd_off = u32::from_le_bytes([vb[4], vb[5], vb[6], vb[7]]) as usize; // "II*\0" + u32 offset
        let n = u16le(ifd_off) as usize;
        let mut offs: Vec<u32> = Vec::new();
        let mut cnts: Vec<u32> = Vec::new();
        let mut curve: Option<Vec<u16>> = None;
        for k in 0..n {
            let e = ifd_off + 2 + k * 12;
            let tag = u16le(e);
            let cnt = u32::from_le_bytes([vb[e + 4], vb[e + 5], vb[e + 6], vb[e + 7]]);
            let vo = e + 8;
            let po = |size: usize| {
                if size as u64 * cnt as u64 <= 4 {
                    vo
                } else {
                    u32::from_le_bytes([vb[vo], vb[vo + 1], vb[vo + 2], vb[vo + 3]]) as usize
                }
            };
            match tag {
                324 => {
                    let po = po(4);
                    for i in 0..cnt as usize {
                        offs.push(u32::from_le_bytes([
                            vb[po + 4 * i],
                            vb[po + 4 * i + 1],
                            vb[po + 4 * i + 2],
                            vb[po + 4 * i + 3],
                        ]));
                    }
                }
                325 => {
                    let po = po(4);
                    for i in 0..cnt as usize {
                        cnts.push(u32::from_le_bytes([
                            vb[po + 4 * i],
                            vb[po + 4 * i + 1],
                            vb[po + 4 * i + 2],
                            vb[po + 4 * i + 3],
                        ]));
                    }
                }
                0xC618 => {
                    let po = po(2);
                    let mut v = Vec::with_capacity(cnt as usize);
                    for i in 0..cnt as usize {
                        v.push(u16::from_le_bytes([vb[po + 2 * i], vb[po + 2 * i + 1]]));
                    }
                    curve = Some(v);
                }
                _ => {}
            }
        }
        let tile = &vb[offs[0] as usize..(offs[0] + cnts[0]) as usize];
        let info = parse_tile(tile).unwrap();
        let curve = linearization_curve(curve.as_deref());
        let (plane, vpreds) = decode_scan_plane(tile, &info, 0, &curve).unwrap();
        assert_eq!(vpreds[0], 4394); // 16384 - 2398*5 (DC code 0xFE, sym 12)
                                     // rawpy GT block 0 (measured, bit-exact target):
        let gt: [[u16; 8]; 8] = [
            [274, 276, 275, 275, 275, 273, 274, 276],
            [275, 274, 276, 274, 274, 276, 275, 276],
            [274, 273, 274, 275, 275, 276, 277, 275],
            [273, 273, 273, 277, 277, 275, 277, 276],
            [270, 269, 272, 273, 274, 274, 274, 275],
            [266, 268, 269, 270, 272, 273, 273, 274],
            [262, 264, 265, 266, 268, 268, 270, 269],
            [261, 261, 262, 263, 264, 265, 265, 266],
        ];
        let w = NBLK_W * 8;
        for r in 0..8 {
            let row: Vec<u16> = (0..8).map(|c| plane[r * w + c]).collect();
            eprintln!("DECODED row {r}: {row:?}");
        }
        for r in 0..8 {
            for c in 0..8 {
                assert_eq!(plane[r * w + c], gt[r][c], "pixel ({r},{c})");
            }
        }
    }

    #[test]
    fn quality_metrics_row_parity_not_column_parity() {
        // 4x2 frame, row-major: row 0 diffs [0,2,4,6], row 1 diffs [8,10,12,14].
        // Row parity (i / w) must drive the even/odd split — pixel/column
        // parity (i % 2) gives a different partition when w is even.
        let decoded: Vec<u16> = vec![10, 12, 14, 16, 18, 20, 22, 24];
        let original: Vec<u16> = vec![10, 10, 10, 10, 10, 10, 10, 10];
        let q = quality_metrics(&decoded, &original, 4, 2);
        assert_eq!(q.mae_even, 12.0 / 4.0); // row 0 only
        assert_eq!(q.mae_odd, 44.0 / 4.0); // row 1 only
        assert_eq!(q.ab_style_mae, 12.0 / 8.0);
        assert_eq!(q.mae, 56.0 / 8.0);
    }
}
