#!/usr/bin/env python3
"""Two-scan baseline-DCT reference decoder for the tag-7 lossy (12-bit)
format (pixel gate). THE BOTH-SCANS decoder: rawpy/LibRaw
reconstructs only scan0 (even rows; odd rows = 0), so the corpus
true full-image quality was UNKNOWN without this tool.

The tag-7 per-tile structure (measured, format-dct12.md §2):
  SOI → one 16-bit DQT (tq=0, shared) → 4 DHT (TcTq 00/10/01/11)
  → SOF1 (precision 12, 1928×544, 2 components 1×1, both tq=0)
  → SOS0 + scan0 → SOS1 + scan1 → EOI
Row-parity split (CONFIRMED by this tool): each scan = a single-component
1928×544 DCT plane (68×241 8×8 blocks, raster order). scan0 → even tile rows,
scan1 → odd tile rows (plane row p → tile rows 2p / 2p+1, written with the
LibRaw case-0xc1 even-row mapping). Last-row tiles (1082 real rows) carry 3
padded plane rows that are clipped at assembly.

DECODE SEMANTICS — a faithful port of LibRaw's lenient path (deps/LibRaw
src/decoders/decoders_dcraw.cpp + src/dng.cpp; the decoder byte-identical to
what rawpy 0.27.1 compiles — verified by diffing LibRaw commit
b860248a against deps/LibRaw):

* **Huffman tables are valid canonical tables** and `make_decoder_ref` +
  `getbithuff` decode them exactly canonically: the table is the fully
  expanded form (each len-bit code occupies 2^(max-len) consecutive entries,
  huff[0] = maxlen, code c = top maxlen bits of the buffer indexes
  huff[c+1] = (len, sym); the read consumes only the stored len bits). The
  earlier "off-by-one" narrative was a mischaracterization of the huff[c+1]
  indexing on the expanded array.
* **getbithuff**: 32-bit bit buffer (MSB-first); FF 0x00: the FF byte's 8
  bits ARE in the stream, the 0x00 is dropped; FF xx!=0: both bytes consumed,
  reader enters reset mode (no more refills).
* **DC prediction** restarts at **vpred = 16384** per tile/scan (LibRaw
  hardcodes it for case 0xc1); `vpred += diff * quant[0]`; DC symbol len 16
  → diff = -32768 (DNG >= 1.1); work[0][0][0] = vpred.
* **AC**: loop `for (i = 1; i < 64; i++)` (file position 1); `skip = sym>>4;
  i += skip;` EOB (len 0, skip < 15) ends the block; ZRL (15,0) writes a 0
  coefficient at the advanced position; coefficient d is dequantized as
  `work[zigzag[i]] = d * quant[i]` — **quant indexed by FILE position i**
  (the DQT order, zigzag), NOT natural order.
* **DQT**: the single tq=0 table (positional, shared by both scans).
* **IDCT**: orthonormal (LibRaw's cs-table = cos(kπ/16)/2 with √½ pre-scaling
  on the DC row/col → DC-only blocks give X00/8); this tool uses exact
  float64 math (LibRaw is float32 — ±1 on ~0.01% of pixels at most).
* **Rounding/clip**: `idct[c] = LIM((int)(P + 0.5), 0, 65535)` — C trunc
  toward zero, NOT round-half-even, NOT clipped to 4095 here.
* **LinearizationTable (tag 0xC618, 4096 u16)**: the decoded pixel is passed
  through `curve[]` (`adobe_copy_pixel: RAW = curve[**rp]`, linear_table:
  tag values verbatim, tail padded with the last value). THIS FILE's curve
  is identity on 0..255 and compresses 256..4095 (curve[549]=271,
  curve[2048]=549) — it is NOT the identity; this is the tag-7 format's
  highlight-range compaction that shrinks DCT AC energy. Skipping this LUT
  is the dominant source of the earlier MAE ~696 "decoder bug" report.
* **SOS payload** `Ns Ss Se Cs Ah Al` (Ls=8): Ss/Se are non-standard (00 00 /
  01 11) and IGNORED (like LibRaw); the scan bitstream starts at
  sos_off + 2 + Ls = sos_off + 10, and is exactly 16388 blocks (68×241).
* **Per-scan table selection**: scan k uses the TcTq (k, 16+k) DHTs —
  scan0 → 00/10, scan1 → 01/11. (The SOS component selector is 00 in both
  scans; the standard multi-scan rule is per-component tables, and the
  reference's 4-DHT layout only makes sense that way. `--ac-tables 00` forces
  the shared-tables reading for scan1 to compare.)
* **rawpy/LibRaw GT = scan0 ONLY**: `lossless_dng_load_raw` case 0xc1 decodes
  one 68×241 block stream per tile (the even plane) and NEVER decodes SOS1 —
  rawpy's raw_image odd rows are 0. Both-scan assembly (this tool) is the
  reference's TRUE full-image reconstruction.

Verification: `--rawpy-check` compares the scan0 plane against rawpy's
raw_image even rows (the known LibRaw ground truth — expect near bit-exact,
any ±1 pixels = the float32-vs-float64 IDCT rounding class).

Usage:
  dct12_tile_scan.py <dct12.dng> <orig.dng> [--tile 0,1,2,3] [--scan 0,1]
      [--blocks N]         # smoke: decode only the first N blocks/scan
      [--rawpy-check]      # scan0 vs rawpy even rows (needs rawpy)
      [--ac-tables {00,01}]# scan1 AC/DC table set (default 01)
Prints per-tile/scan parity diagnostics + full-frame MAE vs the original
(when all 4 tiles × both scans decoded). Stdlib + numpy (+ rawpy optional).
"""
import argparse
import sys
import time

import numpy as np

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from dct12_dng_probe import read_ifd  # noqa: E402

ZIG = np.array([0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33,
                40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50,
                43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46,
                53, 60, 61, 54, 47, 55, 62, 63], dtype=np.intp)
NBLK_W, NBLK_H = 241, 68          # 1928/8, 544/8
N = 8                             # block side
NB = NBLK_W * NBLK_H              # 16388 blocks per scan
VPRED0 = 16384                    # LibRaw case 0xc1 DC prediction start
CURVE_TAG = 0xC618                # DNG LinearizationTable (50712)

# exact orthonormal IDCT matrix (float64): x = D @ X @ D.T
D8 = np.zeros((8, 8))
for _r in range(8):
    for _c in range(8):
        D8[_r, _c] = (1 / np.sqrt(8) if _c == 0 else 0.5) * np.cos((2 * _r + 1) * _c * np.pi / 16)


class DecodeError(Exception):
    pass


def make_decoder_ref(counts16, syms):
    """Exact port of LibRaw make_decoder_ref.
    → (huff: list of (len<<8)|sym, huff[0]=maxlen), with the over-subscription
    behavior (writes stop once the 2^maxlen array is full; symbols still
    consumed from the table)."""
    count = [0] + list(counts16)          # count[len] = counts16[len-1]
    maxl = 16
    while maxl and not count[maxl]:
        maxl -= 1
    if maxl == 0:
        raise DecodeError("empty Huffman table")
    huff = [0] * (1 + (1 << maxl))
    huff[0] = maxl
    h = 1
    src = iter(syms)
    for ln in range(1, maxl + 1):
        for _ in range(count[ln]):
            try:
                s = next(src)
            except StopIteration:
                raise DecodeError("Huffman: more counts than symbols")
            for _ in range(1 << (maxl - ln)):
                if h <= (1 << maxl):
                    huff[h] = (ln << 8) | s
                    h += 1
    return huff, maxl


class BitReader:
    """Exact port of LibRaw getbithuff (32-bit buffer, FF00 reset, the
    stored-length-only advance for table reads). The +1 array offset of
    `gethuff(h) = getbithuff(*h, h+1)` is applied by the caller passing
    `huff[1:]`."""
    M = 0xFFFFFFFF

    def __init__(self, data):
        self.data = data
        self.i = 0
        self.bitbuf = 0
        self.vbits = 0
        self.reset = False

    def getbithuff(self, nbits, huff):
        if nbits > 25:
            return 0
        if nbits < 0:
            self.bitbuf = self.vbits = 0
            self.reset = False
            return 0
        if nbits == 0 or self.vbits < 0:
            return 0
        while (not self.reset) and self.vbits < nbits:
            if self.i >= len(self.data):
                return 0
            c = self.data[self.i]
            self.i += 1
            if c == 0xFF:
                if self.i >= len(self.data):
                    break
                nxt = self.data[self.i]
                self.i += 1
                if nxt == 0x00:
                    # stuffing (exact LibRaw semantics): the FF byte's 8 bits
                    # ARE part of the bitstream; only the 0x00 is discarded.
                    self.bitbuf = ((self.bitbuf << 8) + 0xFF) & self.M
                    self.vbits += 8
                    continue
                self.reset = True     # marker: stop (byte consumed)
                break
            self.bitbuf = ((self.bitbuf << 8) + c) & self.M
            self.vbits += 8
        if self.vbits == 0:
            c = 0
        else:
            c = (((self.bitbuf << (32 - self.vbits)) & self.M) >> (32 - nbits))
        if huff is not None:
            self.vbits -= huff[c] >> 8
            c = huff[c] & 0xFF
        else:
            self.vbits -= nbits
        if self.vbits < 0:
            raise DecodeError(f"bit underflow (vbits={self.vbits}) at byte {self.i}")
        return c

    def getbits(self, n):
        return self.getbithuff(n, None)


def ljpeg_diff(br, h_dc):
    ln = br.getbithuff(h_dc[0], h_dc[1:])
    if ln == 16:
        return -32768
    d = br.getbits(ln)
    if ln and (d & (1 << (ln - 1))) == 0:
        d -= (1 << ln) - 1
    return d


def linearization_curve(vb, tags):
    """curve[] exactly as LibRaw linear_table(): tag 0xC618 u16 values
    verbatim into [0..n-1], tail padded with the last value to 65536;
    absent tag → identity."""
    if CURVE_TAG in tags:
        vals = np.asarray(tags[CURVE_TAG]["val"], dtype=np.int64)
        curve = np.full(65536, vals[-1], dtype=np.int64)
        curve[:len(vals)] = vals
        return curve
    return np.arange(65536, dtype=np.int64)


def decode_plane(data, h_dc, h_ac, quant, curve, nblocks=NB):
    """Decode `nblocks` 8×8 blocks (raster order) → (nblocks,8,8) uint16
    plane pixels: IDCT → (int)(+0.5) trunc → clip 0..65535 → curve LUT.
    DC prediction restarts at 16384; AC dequantizes with quant[i] in FILE
    (zigzag/DQT) order starting at position 1, like LibRaw ljpeg_idct."""
    br = BitReader(data)
    vpred = VPRED0
    q0 = quant[0]
    Q = np.asarray(quant, dtype=np.float64)
    cs_all = np.zeros((nblocks, 64), dtype=np.float64)
    vpreds = np.zeros(nblocks, dtype=np.float64)
    for bi in range(nblocks):
        vpred += ljpeg_diff(br, h_dc) * q0
        vpreds[bi] = vpred
        cs = cs_all[bi]
        # LibRaw: for (i = 1; i < 64; i++) { len = gethuff(); i += skip = len >> 4;
        # if EOB break; coef = getbits(len); work[zigzag[i]] = coef * quant[i]; }
        # — note the FOR-LOOP i++ after each (non-EOB) coefficient: the advance
        # per coefficient is skip + 1 (skip = zeros BETWEEN coefficients).
        i = 1
        while i < 64:
            ln = br.getbithuff(h_ac[0], h_ac[1:])
            skip = ln >> 4
            i += skip
            ln &= 15
            if ln == 0 and skip < 15:
                break
            d = br.getbits(ln)
            if ln and (d & (1 << (ln - 1))) == 0:
                d -= (1 << ln) - 1
            # LibRaw: ((float*)work)[zigzag[i]] = coef * quant[i] — quant in
            # FILE order; i may reach >= 64 via ZRL chains (zigzag[64..79] pad
            # to 63, and coef is 0 there, so 0*quant == 0 == skip).
            if i < 64:
                cs[ZIG[i]] = d * Q[i]
            i += 1  # the for-loop increment (skipped on the EOB break)
    # DC: work[0][0][0] = vpred (already scaled by quant[0] in the +=).
    F = cs_all
    F[:, 0] = vpreds
    X = F.reshape(nblocks, 8, 8)
    P = np.matmul(np.matmul(D8, X), D8.T)
    # C (int) cast truncates toward zero; np.trunc matches (after the +0.5,
    # values are >= -0.5 where trunc==floor anyway; clip removes the rest).
    return curve[np.clip(np.trunc(P + 0.5), 0, 65535).astype(np.int64)]


def plane_from_blocks(blocks):
    """Assemble decode_plane's (nblocks,8,8) output into the (NBLK_H*8,
    NBLK_W*8) plane: block bi = band*NBLK_W + col (raster), plane row p =
    band*8 + r, plane col = col*8 + k. THIS IS THE ONLY CORRECT ASSEMBLY —
    an ad-hoc consumer once reshaped (NBLK_H, 8, NBLK_W, 8) instead (the
    fixture): that scrambles the (band, col, r, k) axes and, on
    dark content, mimics a "content-dependent, both-scans" decode bug. The
    production Rust port (dct2s::decode_scan_plane) uses the same layout.
    """
    return (blocks.reshape(NBLK_H, NBLK_W, N, N)
            .transpose(0, 2, 1, 3)
            .reshape(NBLK_H * N, NBLK_W * N))


def parse_tile_markers(tile):
    """Walk SOI..EOI → (dht {tctq: (counts16, syms)}, dqt {tq: [64]},
    [(sos_off, data_start, data_end)])."""
    dht, dqt, sos = {}, {}, []
    i = 2
    n = len(tile)
    eoi = None
    while i < n - 1 and tile[i] == 0xFF:
        m = tile[i + 1]
        if m == 0xD9:
            eoi = i
            break
        if m == 0xD8:
            i += 2
            continue
        ln = (tile[i + 2] << 8) | tile[i + 3]
        if m == 0xC4:
            counts = list(tile[i + 5:i + 21])
            dht[tile[i + 4]] = (counts, list(tile[i + 21:i + 21 + sum(counts)]))
        elif m == 0xDB:
            j = i + 4
            while j < i + 2 + ln:
                tq = tile[j] & 0x0F
                dqt[tq] = [int.from_bytes(tile[j + 1 + 2 * t:j + 3 + 2 * t], "big")
                           for t in range(64)]
                j += 1 + 128
        elif m == 0xDA:
            data_start = i + 2 + ln
            j = data_start
            while j < n - 1:
                if tile[j] == 0xFF and tile[j + 1] != 0x00:
                    break
                j += 1
            sos.append((i, data_start, j))
            i = j
            continue
        i += 2 + ln
    if eoi is None:
        raise DecodeError("EOI not found")
    return dht, dqt, sos


def frame_pixels(orig_bytes, width, height):
    """Unpack the DNG 12-bit standard-order packed strip → uint16 (h,w)."""
    to = read_ifd(orig_bytes, 8, "<")
    off, cnt = to[273]["val"][0], to[279]["val"][0]
    packed = orig_bytes[off:off + cnt]
    n = width * height
    bits = np.unpackbits(np.frombuffer(packed, dtype=np.uint8))
    vals = bits[:n * 12].reshape(n, 12)
    wts = (1 << np.arange(11, -1, -1))
    return (vals @ wts).reshape(height, width).astype(np.uint16)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("reference")
    ap.add_argument("orig")
    ap.add_argument("--tile", default="0,1,2,3")
    ap.add_argument("--scan", default="0,1")
    ap.add_argument("--blocks", type=int, default=NB,
                    help="smoke: decode only the first N blocks of each scan")
    ap.add_argument("--rawpy-check", action="store_true",
                    help="compare scan0 planes against rawpy's even rows")
    ap.add_argument("--ac-tables", choices=["00", "01"], default="01",
                    help="table set for scan1 (default 01 = per-scan DHTs)")
    a = ap.parse_args()
    tiles = [int(x) for x in a.tile.split(",")]
    scans = [int(x) for x in a.scan.split(",")]

    t0 = time.time()
    vb = open(a.reference, "rb").read()
    tags = read_ifd(vb, 8, "<")
    tw, tl = tags[322]["val"][0], tags[323]["val"][0]
    offs, cnts = tags[324]["val"], tags[325]["val"]
    fw, fh = tags[256]["val"][0], tags[257]["val"][0]
    curve = linearization_curve(vb, tags)
    if CURVE_TAG in tags:
        cv = curve[:min(4096, len(curve))]
        dev = int((cv != np.arange(len(cv))).sum())
        print(f"LinearizationTable (0xC618): {len(cv)} entries, {dev} deviate from identity, "
              f"curve[549]={cv[549]}, curve[2048]={cv[2048]}, curve[4095]={cv[4095]}")
    ob = open(a.orig, "rb").read()
    frame = frame_pixels(ob, fw, fh)

    # 2×2 grid: tile (tr,tc) at (tc*tw, tr*tl); last row clipped to fh
    x0 = [0, tw] if fw > tw else [0]
    y0 = [0, tl] if fh > tl else [0]

    decoded = {}
    for ti in tiles:
        tile = vb[offs[ti]:offs[ti] + cnts[ti]]
        dht, dqt, sos = parse_tile_markers(tile)
        if 0 not in dqt:
            raise DecodeError(f"tile {ti}: no tq=0 DQT")
        quant = dqt[0]
        for si in scans:
            if si >= len(sos):
                print(f"tile {ti} scan {si}: SOS missing", file=sys.stderr)
                continue
            _, data_start, data_end = sos[si]
            # RAW scan bytes — NO pre-destuffing: the BitReader's FF00 logic
            # (the exact LibRaw zero_after_ff path) handles stuffing in place.
            data = tile[data_start:data_end]
            # per-scan table set: scan0 → 00/10; scan1 → 01/11 (or 00/10 forced)
            t = si if a.ac_tables == "01" or si == 0 else 0
            tctq_dc, tctq_ac = t, 0x10 + t
            if tctq_dc not in dht or tctq_ac not in dht:
                raise DecodeError(f"tile {ti} scan {si}: DHT {tctq_dc:02x}/{tctq_ac:02x} missing")
            h_dc, _ = make_decoder_ref(*dht[tctq_dc])
            h_ac, _ = make_decoder_ref(*dht[tctq_ac])
            ts = time.time()
            blocks = decode_plane(data, h_dc, h_ac, quant, curve, a.blocks)
            ms = time.time() - ts
            if a.blocks == NB:
                plane = plane_from_blocks(blocks)
                tr, tc = ti // 2, ti % 2
                ty0, tx0 = y0[tr], x0[tc]
                # plane row p ↔ tile row 2p+si; real plane rows clipped at fh
                real_plane_rows = max(0, min((fh - 1 - ty0 - si) // 2 + 1, plane.shape[0]))
                if si == 0:
                    rows_hyp = np.array([ty0 + 2 * p for p in range(real_plane_rows)])
                    rows_alt = np.array([ty0 + 2 * p + 1 for p in range(real_plane_rows)])
                else:
                    rows_hyp = np.array([ty0 + 2 * p + 1 for p in range(real_plane_rows)])
                    rows_alt = np.array([ty0 + 2 * p for p in range(real_plane_rows)])
                    rows_alt = rows_alt[rows_alt < fh]
                    rows_hyp = rows_hyp[rows_hyp < fh]
                mae_hyp = np.abs(plane[:len(rows_hyp)].astype(np.int32)
                                 - frame[rows_hyp, tx0:tx0 + plane.shape[1]].astype(np.int32)).mean()
                mae_alt = np.abs(plane[:len(rows_alt)].astype(np.int32)
                                 - frame[rows_alt, tx0:tx0 + plane.shape[1]].astype(np.int32)).mean()
                decoded[(ti, si)] = plane
                print(f"tile {ti} (grid {tr},{tc} @{tx0},{ty0}) scan {si} [{a.blocks} blocks, "
                      f"{ms:.2f}s]: min {plane.min():5d} max {plane.max():5d} mean {plane.mean():8.2f} | "
                      f"MAE parity={si}: {mae_hyp:7.3f}  parity={1 - si}: {mae_alt:7.3f}  → "
                      f"{'parity=' + str(si) if mae_hyp < mae_alt else 'parity=' + str(1 - si) + ' (UNEXPECTED)'}")
            else:
                print(f"tile {ti} scan {si}: {a.blocks} smoke blocks, {ms:.2f}s, "
                      f"mean {blocks.reshape(-1, 64).mean():.1f}")
                decoded[(ti, si)] = None

    if a.rawpy_check and 0 in [s for s in scans] and all(v is not None for v in decoded.values()):
        import rawpy
        with rawpy.imread(a.reference) as raw:
            rp = raw.raw_image
        for ti in sorted({t for t, s in decoded if s == 0}):
            tr, tc = ti // 2, ti % 2
            ty0, tx0 = y0[tr], x0[tc]
            n = min(NBLK_H * N, (fh - ty0 + 1) // 2)
            mine = decoded[(ti, 0)][:n]
            theirs = rp[ty0:ty0 + 2 * n:2, tx0:tx0 + mine.shape[1]]
            d = np.abs(mine.astype(np.int32) - theirs.astype(np.int32))
            exact = (d == 0).mean() * 100
            print(f"RAWPY-CHECK tile {ti} scan0 vs rawpy even rows ({n}×{mine.shape[1]}): "
                  f"exact {exact:.4f}% | max {d.max()} | MAE {d.mean():.5f} "
                  f"({'PASS' if exact > 99.0 else 'FAIL — decoder mismatch'})")

    if set(decoded) == {(t, s) for t in range(4) for s in (0, 1)} and \
            all(v is not None for v in decoded.values()):
        full = np.zeros((fh, fw), dtype=np.float64)
        for (ti, si), plane in decoded.items():
            tr, tc = ti // 2, ti % 2
            ty0, tx0 = y0[tr], x0[tc]
            for p in range(NBLK_H * N):
                y = ty0 + 2 * p + si
                if y < fh:
                    full[y, tx0:tx0 + plane.shape[1]] = plane[p]
        d = np.abs(full - frame.astype(np.float64))
        exact = (np.rint(full).astype(np.int32) == frame.astype(np.int32)).mean() * 100
        print(f"\nFULL-FRAME (both scans, 4 tiles) vs original: MAE {d.mean():.4f} | "
              f"max {d.max():.0f} | exact {exact:.2f}% | ≤1 LSB {(d <= 1).mean() * 100:.2f}%")
        print(f"   even-rows MAE {d[0::2].mean():.4f} | odd-rows MAE {d[1::2].mean():.4f}")
    else:
        print(f"\n(full-frame MAE needs all 4 tiles × 2 scans; decoded "
              f"{sum(1 for v in decoded.values() if v is not None)} planes)")
    print(f"wall {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()