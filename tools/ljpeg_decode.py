#!/usr/bin/env python3
"""Minimal lossless JPEG (SOF3, ITU-T T.81) decoder — frameprism reference tool.

Purpose: decode a lossless-JPEG tile from a CinemaDNG file and verify it
against the known mosaic (from the original uncompressed strip), which lets
us reverse-engineer the exact structure of a reference encoder:
PSV used, component layout, point transform.

Supports: SOF3 only, 8/12/16-bit precision, Nf up to 3, standard canonical
Huffman (DHT DC tables only — lossless JPEG has no AC blocks), PSV 1..7 with
the T.81 formulas, interleaved per-MCU scan order (one sample per component
per MCU, component order).

Usage:
  ljpeg_decode.py --tile <dng> <tile_index>   decode one tile, dump stats
  ljpeg_decode.py --stream <file>             decode a raw .jpg stream
  ljpeg_decode.py --verify <orig_dng> <slim_dng> <tile_index>
      decode the slim tile and check candidate layouts against the
      original frame's mosaic region (pixel-exact).
"""
import argparse
import struct
import sys
from collections import Counter


# ---------------------------------------------------------------- TIFF/DNG
def read_ifd0_tags(buf):
    e = '<' if buf[:2] == b'II' else '>'
    n = struct.unpack_from(e + 'H', buf, 8)[0]
    tsz = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 11: 4, 12: 4}
    d = {}
    for i in range(n):
        t = 8 + 2 + i * 12
        tag, typ, count = struct.unpack_from(e + 'HHI', buf, t)
        sz = tsz.get(typ, 1) * count
        if sz <= 4:
            d[tag] = buf[t + 8:t + 8 + sz]
        else:
            p = struct.unpack_from(e + 'I', buf, t + 8)[0]
            d[tag] = buf[p:p + sz]
    return e, d


def extract_tile(buf, tile_index=0):
    e, d = read_ifd0_tags(buf)
    w = struct.unpack_from(e + 'I', d[256])[0]
    h = struct.unpack_from(e + 'I', d[257])[0]
    if 324 in d:  # tiled (reference encoder output)
        tlc = d[325]
        cnt = struct.unpack_from(e + '%dI' % (len(tlc) // 4), tlc)
        offs = struct.unpack_from(e + '%dI' % (len(d[324]) // 4), d[324])
        return w, h, buf[offs[tile_index]:offs[tile_index] + cnt[tile_index]]
    so = struct.unpack_from(e + 'I', d[273])[0]
    sc = struct.unpack_from(e + 'I', d[279])[0]
    return w, h, buf[so:so + sc]


def unpack_mosaic(buf):
    """Original frame -> 2-D int32 mosaic (BE word, MSB-first; verified)."""
    e, d = read_ifd0_tags(buf)
    w = struct.unpack_from(e + 'I', d[256])[0]
    h = struct.unpack_from(e + 'I', d[257])[0]
    so = struct.unpack_from(e + 'I', d[273])[0]
    px = w * h
    import numpy as np
    words = np.frombuffer(buf[so:so + px // 2 * 3], dtype=np.uint8).reshape(px // 2, 3)
    wbe = (words[:, 2].astype(np.uint32)
           | (words[:, 1].astype(np.uint32) << 8)
           | (words[:, 0].astype(np.uint32) << 16))
    s = np.stack([wbe >> 12, wbe & 0xFFF], axis=1).ravel().astype(np.int32)
    return w, h, s.reshape(h, w)


# ---------------------------------------------------------------- Huffman
class BitReader:
    def __init__(self, data, start):
        self.data = data
        self.pos = start
        self.acc = 0
        self.nbits = 0

    def bits(self, n):
        while self.nbits < n:
            self.acc = (self.acc << 8) | self.data[self.pos]
            self.pos += 1
            self.nbits += 8
            # JPEG bit stuffing: an 0xFF byte in the entropy data is
            # followed by a stuffed 0x00 that must be discarded.
            if self.data[self.pos - 1] == 0xFF and self.pos < len(self.data) \
                    and self.data[self.pos] == 0x00:
                self.pos += 1
        v = (self.acc >> (self.nbits - n)) & ((1 << n) - 1)
        self.nbits -= n
        return v


def build_huff(payload):
    """DHT payload -> {tc*16+tq: (counts, vals)} (canonical codes implicit)."""
    out = {}
    i = 0
    while i < len(payload):
        tc_tq = payload[i]
        counts = payload[i + 1:i + 17]
        n = sum(counts)
        vals = payload[i + 17:i + 17 + n]
        i += 17 + n
        out[(tc_tq >> 4) * 16 + (tc_tq & 0x0F)] = (list(counts), list(vals))
    return out


def huff_decode(br, counts, vals):
    """Incremental canonical Huffman decode -> symbol value.

    D.1 code assignment: first code of length k = sum_{l<k} c(l)*2^(k-l);
    recurrence first(k+1) = (first(k) + c(k)) * 2, first(1) = 0. The
    accumulated raw bit value v (k bits) matches length k iff
    0 <= v - first(k) < c(k).
    """
    v = 0
    first = 0
    for k in range(1, 17):
        v = (v << 1) | br.bits(1)
        rank = v - first
        if 0 <= rank < counts[k - 1]:
            return vals[sum(counts[:k - 1]) + rank]
        first = (first + counts[k - 1]) * 2
    raise ValueError('huff decode failed (corrupt stream?)')


def dc_value(br, counts, vals):
    cat = huff_decode(br, counts, vals)
    if cat == 0:
        return 0
    v = br.bits(cat)
    if v < (1 << (cat - 1)):
        v -= (1 << cat) - 1
    return v


# ---------------------------------------------------------------- SOF3 scan
def parse_stream(data):
    """Return dict with sof fields, dht tables, sos, scan start offset.

    libjpeg conventions (verified against reference encoder output + libjpeg source,
    jdmarker.c/jcmarker.c/jclossls.c):
      - SOF3 per-component: id, sampling (h<<4|v; must be 1x1 for lossless),
        quant table selector. The byte that T.81 calls "PSV" is used by
        libjpeg for sampling factors (0x11 = 1x1).
      - SOS: standard layout (Ns, per-comp cid+AhAl, then Ss, Se, AhAl);
        for lossless the PREDICTOR lives in Ss (1..7, libjpeg's Table H.1
        numbering — note 4..7 differ from the T.81 spec numbering).
    """
    i = 2
    dht = {}
    sof = None
    sos = None
    while i < len(data) - 4:
        if data[i] != 0xFF:
            raise ValueError(f'lost JPEG sync at {i}')
        m = data[i + 1]
        if m == 0xD9:
            break
        if m == 0x01 or 0xD0 <= m <= 0xD7 or m == 0xD8:
            i += 2
            continue
        ln = struct.unpack('>H', data[i + 2:i + 4])[0]
        payload = data[i + 4:i + 2 + ln]
        if m == 0xC3:
            sof = payload
        elif m == 0xC4:
            dht.update(build_huff(payload))
        elif m == 0xDA:
            sos = payload
            i += 2 + ln
            break
        i += 2 + ln
    if not (sof and sos):
        raise ValueError('missing SOF3 or SOS')
    prec = sof[0]
    y, x = struct.unpack('>HH', sof[1:5])
    nf = sof[5]
    comps = []
    for c in range(nf):
        j = 6 + c * 3
        comps.append((sof[j], (sof[j + 1] >> 4) & 0xF, (sof[j + 1] & 0xF), sof[j + 2]))
    ns = sos[0]
    sos_info = [(sos[1 + c * 2], (sos[2 + c * 2] >> 4) & 0xF,
                 (sos[2 + c * 2] & 0xF)) for c in range(ns)]
    ss, se = sos[1 + 2 * ns], sos[2 + 2 * ns]
    return dict(precision=prec, w=x, h=y, nf=nf, comps=comps,
                dht=dht, sos=sos_info, psv=ss, se=se, scan_start=i)


def t81_pred(psv, a, b, c):
    """Libjpeg lossless predictors (src/jlossls.h Table H.1; Ra=a=left,
    Rb=b=up, Rc=c=diag). NOTE: numbering 4..7 differs from the T.81 spec."""
    if psv == 1:
        return a
    if psv == 2:
        return b
    if psv == 3:
        return c
    if psv == 4:
        return a + b - c
    if psv == 5:
        return a + (b - c) // 2
    if psv == 6:
        return b + (a - c) // 2
    if psv == 7:
        return (a + b) // 2
    raise ValueError(f'bad PSV {psv}')


def decode_stream(data, psv_override=None):
    """Decode a SOF3 stream -> (info, list of per-component (h,w) int32).

    Edge predictor init per DNG SDK (dng_lossless_jpeg_shared.cpp) / T.81:
      - first sample of each component: d + (1 << (precision - Pt - 1))
      - rest of first row: left prediction only (regardless of PSV)
      - first column of later rows: up prediction
      - otherwise: PSV (Ss; libjpeg/DNG numbering)
    Scan order: interleaved per MCU (per row, per col, per comp).
    Each Huffman symbol is the difference from the predictor (the predictor
    state IS the DC predictor — no extra accumulation); category 16 ->
    -32768.
    """
    import numpy as np
    info = parse_stream(data)
    w, h, nf = info['w'], info['h'], info['nf']
    psv = psv_override if psv_override is not None else info['psv']
    edge = 1 << (info['precision'] - 1)  # Pt read as 0 in the SOS last byte
    comp_tables = []
    for idx in range(nf):
        cid = info['comps'][idx][0]
        entry = next((s for s in info['sos'] if s[0] == cid), None)
        if entry is None:
            raise ValueError(f'SOS has no entry for component id {cid} '
                             f'(sos={info["sos"]})')
        _, ah, al = entry
        dc = info['dht'].get(0 * 16 + ah)
        if dc is None:
            raise ValueError(f'no DC table {ah} for component {cid}')
        comp_tables.append((cid, psv, dc))
    br = BitReader(data, info['scan_start'])
    comps = [np.zeros((h, w), dtype=np.int32) for _ in range(nf)]
    for y in range(h):
        for x in range(w):
            for ci in range(nf):
                _, _, (counts, vals) = comp_tables[ci]
                cat = huff_decode(br, counts, vals)
                if cat == 0:
                    d = 0
                elif cat == 16:
                    d = -32768
                else:
                    d = br.bits(cat)
                    if d < (1 << (cat - 1)):
                        d -= (1 << cat) - 1
                if y == 0 and x == 0:
                    pred = edge
                elif y == 0:
                    pred = int(comps[ci][0, x - 1])
                elif x == 0:
                    pred = int(comps[ci][y - 1, 0])
                else:
                    pred = t81_pred(psv, int(comps[ci][y, x - 1]),
                                    int(comps[ci][y - 1, x]),
                                    int(comps[ci][y - 1, x - 1]))
                comps[ci][y, x] = pred + d
    return info, comps


# ------------------------------------------------------------------- verify
def _layout_vertical(c0, c1):
    return _np.vstack([c0, c1])


def _layout_row_interleave(c0, c1):
    out = _np.empty((c0.shape[0] * 2, c0.shape[1]), dtype=c0.dtype)
    out[0::2] = c0
    out[1::2] = c1
    return out


def _layout_col_interleave(c0, c1):
    out = _np.empty((c0.shape[0], c0.shape[1] * 2), dtype=c0.dtype)
    out[:, 0::2] = c0
    out[:, 1::2] = c1
    return out


def _layout_wrap_col(c0, c1):
    """Wrapped even/odd COLUMN planes (reference A001 layout).

    Each parity plane is stored as (tl/2) rows of tw samples; plane row oy
    holds the even columns of tile rows 2*oy (first half) and 2*oy+1
    (second half). Valid when tl*tw/2 % tw == 0 (272->136, 266->133).
    """
    ph, pw = c0.shape
    tl = ph * 2
    out = _np.empty((tl, pw), dtype=c0.dtype)
    half = pw // 2
    for oy in range(ph):
        out[2 * oy, 0::2] = c0[oy, :half]
        out[2 * oy, 1::2] = c1[oy, :half]
        out[2 * oy + 1, 0::2] = c0[oy, half:]
        out[2 * oy + 1, 1::2] = c1[oy, half:]
    return out


LAYOUTS = {
    # how to rebuild a (2h, w) tile mosaic from two (h, w) components
    'vertical-split': _layout_vertical,
    'row-interleave': _layout_row_interleave,
    'col-interleave': _layout_col_interleave,
    'wrap-col': _layout_wrap_col,
}


def main():
    global _np
    import numpy as _np
    ap = argparse.ArgumentParser()
    g = ap.add_subparsers(dest='cmd', required=True)
    t = g.add_parser('tile'); t.add_argument('dng'); t.add_argument('idx', type=int, default=0, nargs='?')
    s = g.add_parser('stream'); s.add_argument('jpg')
    v = g.add_parser('verify')
    v.add_argument('orig'); v.add_argument('slim'); v.add_argument('idx', type=int, default=0, nargs='?')
    args = ap.parse_args()

    if args.cmd == 'stream':
        data = open(args.jpg, 'rb').read()
        info, comps = decode_stream(data)
        for i, c in enumerate(comps):
            print(f'comp{i}: {c.shape[1]}x{c.shape[0]} min={c.min()} max={c.max()} mean={c.mean():.2f}')
        return

    if args.cmd == 'tile':
        w, h, tile = extract_tile(open(args.dng, 'rb').read(), args.idx)
        info, comps = decode_stream(tile)
        print(f'tile {args.idx}: stream {info["w"]}x{info["h"]} nf={info["nf"]} '
              f'prec={info["precision"]} comps={info["comps"]} sos={info["sos"]}')
        for i, c in enumerate(comps):
            print(f'comp{i}: {c.shape[1]}x{c.shape[0]} min={c.min()} max={c.max()} mean={c.mean():.2f}')
        return

    if args.cmd == 'verify':
        ow, oh, mosaic = unpack_mosaic(open(args.orig, 'rb').read())
        _, _, tile = extract_tile(open(args.slim, 'rb').read(), args.idx)
        info = parse_stream(tile)
        print(f'stream {info["w"]}x{info["h"]} nf={info["nf"]} psv(Ss)={info["psv"]} '
              f'comps={info["comps"]} sos={info["sos"]}')
        # tile region of the mosaic: tiles are row-major; tile idx (r,c)
        tw = info['w']
        tl = info['h'] * info['nf']  # full tile = nf*comp-h rows
        tpc = ow // tw  # tiles per row
        r, c = divmod(args.idx, tpc)
        y0, x0 = r * tl, c * tw
        region = mosaic[y0:y0 + tl, x0:x0 + tw]
        if region.shape != (tl, tw):
            print(f'region shape {region.shape} != tile {tl}x{tw}; checking partial only')
        for psv_try in (None,) + tuple(range(1, 8)):
            try:
                _, comps = decode_stream(tile, psv_override=psv_try)
            except Exception as ex:
                print(f'psv={psv_try}: decode failed ({ex!r})')
                continue
            for lname, lfn in LAYOUTS.items():
                rebuilt = lfn(comps[0], comps[1])
                n = min(rebuilt.shape[0], region.shape[0], tl)
                m = min(rebuilt.shape[1], region.shape[1], tw)
                match = int((rebuilt[:n, :m] == region[:n, :m]).sum())
                tot = n * m
                if match == tot:
                    print(f'*** PIXEL-EXACT: psv={psv_try} layout={lname} ({tot} samples)')
                    for ci, cc in enumerate(comps):
                        cnt = Counter(cc.flatten().tolist())
                        print(f'    comp{ci} top5: {cnt.most_common(5)}')
                else:
                    frac = match / tot
                    if frac > 0.5:
                        print(f'psv={psv_try} {lname}: {match}/{tot} ({frac:.2%})')


if __name__ == '__main__':
    main()