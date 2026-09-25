#!/usr/bin/env python3
"""Probe the sample order libjpeg-turbo wrote for 2-comp lossless (SOF3).

Decode /tmp/our_tile0_fresh.jpg three ways and compare each against the
original mosaic's tile-0 region (even/odd column planes, wrapped 482x136):
  A) standard T.81 per-MCU interleave (y, x, comp)   [tools/ljpeg_decode.py]
  B) per-row blocks: [c0 row | c1 row]
  C) per-frame blocks: [all c0 | all c1]  (sanity)
Prints exact-match counts. Also re-runs the G1 check: standard decode of the
Reference golden tile 0 vs the original mosaic (pixel-exact?).
"""
import sys
sys.path.insert(0, 'tools')
import numpy as np
from ljpeg_decode import (parse_stream, build_huff, BitReader, dc_value,
                          t81_pred, unpack_mosaic, extract_tile)


def decode_with_order(data, order):
    info = parse_stream(data)
    w, h, nf = info['w'], info['h'], info['nf']
    psv = info['psv']
    edge = 1 << (info['precision'] - 1)
    tables = []
    for idx in range(nf):
        cid = info['comps'][idx][0]
        entry = next(s for s in info['sos'] if s[0] == cid)
        tables.append(info['dht'].get(0 * 16 + entry[1]))
    br = BitReader(data, info['scan_start'])
    comps = [np.zeros((h, w), dtype=np.int32) for _ in range(nf)]
    pred = [[[0] * w for _ in range(h)] for _ in range(nf)]

    def decode_one(ci, y, x):
        counts, vals = tables[ci]
        cat = 0
        v = 0
        first = 0
        for k in range(1, 17):
            v = (v << 1) | br.bits(1)
            rank = v - first
            if 0 <= rank < counts[k - 1]:
                cat = vals[sum(counts[:k - 1]) + rank]
                break
            first = (first + counts[k - 1]) * 2
        if cat == 0:
            d = 0
        elif cat == 16:
            d = -32768
        else:
            d = br.bits(cat)
            if d < (1 << (cat - 1)):
                d -= (1 << cat) - 1
        if y == 0 and x == 0:
            p = edge
        elif y == 0:
            p = pred[ci][y][x - 1]
        elif x == 0:
            p = pred[ci][y - 1][0]
        else:
            p = t81_pred(psv, pred[ci][y][x - 1], pred[ci][y - 1][x],
                         pred[ci][y - 1][x - 1])
        pred[ci][y][x] = p + d
        return p + d

    if order == 'standard':
        for y in range(h):
            for x in range(w):
                for ci in range(nf):
                    comps[ci][y, x] = decode_one(ci, y, x)
    elif order == 'rowblock':
        for y in range(h):
            for ci in range(nf):
                for x in range(w):
                    comps[ci][y, x] = decode_one(ci, y, x)
    elif order == 'frameblock':
        for ci in range(nf):
            for y in range(h):
                for x in range(w):
                    comps[ci][y, x] = decode_one(ci, y, x)
    return info, comps


def planes_of(mosaic, y0, x0, tw, tl):
    region = mosaic[y0:y0 + tl, x0:x0 + tw]
    even = region[:, 0::2].copy()
    odd = region[:, 1::2].copy()
    # wrapped: plane row oy holds tile rows 2oy (first half) and 2oy+1 (second half)
    ph, pw = tl // 2, tw
    out = np.empty((ph, pw), dtype=even.dtype)
    for oy in range(ph):
        out[oy, :pw // 2] = even[2 * oy, :]
        out[oy, pw // 2:] = even[2 * oy + 1, :]
    oddp = np.empty((ph, pw), dtype=odd.dtype)
    for oy in range(ph):
        oddp[oy, :pw // 2] = odd[2 * oy, :]
        oddp[oy, pw // 2:] = odd[2 * oy + 1, :]
    return out, oddp


def report(name, info, comps, target):
    ok = 0
    for ci in range(2):
        ok += int((comps[ci] == target[ci]).sum())
    tot = comps[0].size * 2
    print(f'{name}: {ok}/{tot} samples exact ({ok / tot:.2%})')
    return ok


orig = 'testdata/originals/A001_001/A001_001_20260701_000001.DNG'
golden = 'testdata/reference/lossless/A001_001/A001_001_20260701_000001.DNG'
ow, oh, mosaic = unpack_mosaic(open(orig, 'rb').read())
tw, tl = 482, 272
tgt_even, tgt_odd = planes_of(mosaic, 0, 0, tw, tl)
target = (tgt_even, tgt_odd)

g_w, g_h, gtile = extract_tile(open(golden, 'rb').read(), 0)
info, comps = decode_with_order(gtile, 'standard')
print(f'G1 golden tile0: stream {info["w"]}x{info["h"]} nf={info["nf"]} psv={info["psv"]}')
report('G1 golden standard   ', info, comps, target)

otile = open('/tmp/our_tile0_fresh.jpg', 'rb').read()
for order in ('standard', 'rowblock', 'frameblock'):
    info, comps = decode_with_order(otile, order)
    report(f'ours   {order:12s} ', info, comps, target)