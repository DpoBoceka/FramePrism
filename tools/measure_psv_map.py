#!/usr/bin/env python3
"""Measure the corpus per-tile (Ss/PSV, orientation) map.

Step 1 of the parity work: confirm/correct the 3-candidate hypothesis
{PSV7-wrap, PSV2-wrap, PSV1-natural} across ALL frames of ALL lossless
presets, and get the ds2x contract (orientation + PSV, incl. last row).

Per tile it reads ONLY the header markers (up to and including SOS):
  - SOF3 (0xC3): data precision, Y (height), X (width), Nf
  - DHT (0xC4): count + TcTh class bytes
  - SOS  (0xDA): Ns, per-comp (cid, TcTh), Ss (PSV), Se, Pt
Orientation: wrapped when SOF X == tile width (two tile rows per plane row,
padded for last-row tiles), natural when SOF X == tile width/2.

Usage:
  measure_psv_map.py PRESET_DIR [FRAME_GLOB ...] [frame-indices csv]
  e.g.
  measure_psv_map.py testdata/reference/lossless 'A001_001_20260701_*.DNG' '0,112,224'
  (frame-indices default: all; tiles: all; prints per-frame maps + global
   distributions; --json OUT writes the full per-tile map)
"""
import struct
import sys
import glob
import json
import os
from collections import Counter

TW = 482  # tile width (all presets)
TH = 272  # tile height (full rows)


def parse_tiles(d: bytes):
    """Return list of tile byte-strings (header+entropy), ordered by 324 offsets."""
    bo = "<" if d[:2] == b"II" else ">"
    off, = struct.unpack_from(bo + "I", d, 4)
    n, = struct.unpack_from(bo + "H", d, off)
    ents = {}
    for i in range(n):
        e = off + 2 + 12 * i
        t, ty, cnt = struct.unpack_from(bo + "HHI", d, e)
        ents[t] = (ty, cnt, struct.unpack_from(bo + "I", d, e + 8)[0])

    def arr(t):
        ty, cnt, vf = ents[t]
        return list(struct.unpack_from(bo + f"{cnt}I", d, vf))

    a324, a325 = arr(324), arr(325)  # 324=TileOffsets, 325=TileByteCounts (TIFF spec)

    def looks_offsets(a):
        step = max(1, len(a) // 8)
        return all(0 < a[i] < len(d) - 2 and d[a[i]] == 0xFF and d[a[i] + 1] == 0xD8
                   for i in range(0, len(a), step))

    if looks_offsets(a324):
        offs, sizes = a324, a325
    else:  # defensive: some scratch tools had the two swapped
        offs, sizes = a325, a324
    return [d[o:o + s] for o, s in zip(offs, sizes)]


def tile_meta(tile: bytes):
    """Walk header markers; return dict(prec, Y, X, nf, tcth, ncomp,
    comp_sels, Ss, Se, Pt) or None if no SOF3+SOS found."""
    i = 0
    sof = None
    dhts = []
    sos = None
    n = len(tile)
    while i < n:
        if tile[i] != 0xFF:
            break
        m = tile[i + 1]
        if m == 0xD8 or 0xD0 <= m <= 0xD7 or m in (0x00, 0x01):
            i += 2
            continue
        if m == 0xD9:
            break
        ln = int.from_bytes(tile[i + 2:i + 4], "big")
        if i + 2 + ln > n:
            break
        body = tile[i + 4:i + 2 + ln]
        if m == 0xC3:
            prec = body[0]
            Y, X = int.from_bytes(body[1:3], "big"), int.from_bytes(body[3:5], "big")
            nf = body[5]
            comps = [(body[6 + 3 * k], body[7 + 3 * k], body[8 + 3 * k]) for k in range(nf)]
            sof = (prec, Y, X, nf, comps)
        elif m == 0xC4:
            dhts.append(body[0])  # TcTh
        elif m == 0xDA:
            nsc = body[0]
            sels = [(body[1 + 2 * k], body[2 + 2 * k]) for k in range(nsc)]
            Ss, Se, Pt = body[-3], body[-2], body[-1]
            sos = (nsc, sels, Ss, Se, Pt)
            break
        i += 2 + ln
    if sof is None or sos is None:
        return None
    prec, Y, X, nf, comps = sof
    nsc, sels, Ss, Se, Pt = sos
    return {"prec": prec, "Y": Y, "X": X, "nf": nf, "comps": comps,
            "dhts": dhts, "nsc": nsc, "sels": sels, "Ss": Ss, "Se": Se, "Pt": Pt}


def classify(tl, meta):
    """orientation for tile of mosaic height tl (last row may be clipped)."""
    if meta is None:
        return "none"
    if meta["X"] == TW:
        return "wrap"
    if meta["X"] == TW // 2:
        return "nat"
    return f"odd-{meta['Y']}x{meta['X']}"


def main():
    args = sys.argv[1:]
    json_out = None
    if "--json" in args:
        k = args.index("--json")
        json_out = args[k + 1]
        del args[k:k + 2]
    if len(args) < 2:
        print(__doc__)
        sys.exit(2)
    preset_dir, pattern = args[0], args[1]
    frames_csv = args[2] if len(args) > 2 else None
    files = sorted(glob.glob(os.path.join(preset_dir, pattern)))
    if not files:
        print(f"no files match {preset_dir}/{pattern}", file=sys.stderr)
        sys.exit(1)
    idxs = None
    if frames_csv:
        idxs = [int(x) for x in frames_csv.split(",") if x.strip() != ""]
        files = [files[i] for i in idxs if 0 <= i < len(files)]

    # frame geometry: read from the first file's IFD (256/257)
    d0 = open(files[0], "rb").read()
    bo = "<"
    off, = struct.unpack_from(bo + "I", d0, 4)
    n, = struct.unpack_from(bo + "H", d0, off)
    W = H = 0
    for i in range(n):
        e = off + 2 + 12 * i
        t, ty, cnt = struct.unpack_from(bo + "HHI", d0, e)
        if t in (256, 257) and cnt == 1:
            v = struct.unpack_from(bo + ("H" if ty == 3 else "I"), d0, e + 8)[0]
            W, H = (v, H) if t == 256 else (W, v)
    gcols, grows = (W + TW - 1) // TW, (H + TH - 1) // TH
    print(f"preset={preset_dir} frames={len(files)} frame={W}x{H} grid={gcols}x{grows} "
          f"last_row_h={H - (grows - 1) * TH}")

    combos = Counter()          # global (Ss, orient) counts
    prec_seen = set()
    dht_patterns = Counter()
    sel_patterns = Counter()
    odd_tiles = 0
    lastrow_metas = Counter()   # (Ss, orient, Y) on the last grid row
    nonstd = []                 # tiles outside the 3-candidate hypothesis
    frame_maps = {}             # frame idx -> {tile idx: (Ss, orient)}
    per_frame_size = Counter()  # (orient) -> total entropy bytes, for context

    for fi, path in enumerate(files):
        d = open(path, "rb").read()
        tiles = parse_tiles(d)
        if len(tiles) != gcols * grows:
            print(f"!! frame {fi}: {len(tiles)} tiles, expected {gcols * grows}")
            continue
        fmap = {}
        for ti in range(len(tiles)):
            tl = min(TH, H - (ti // gcols) * TH)
            meta = tile_meta(tiles[ti])
            if meta is None:
                fmap[ti] = ("?", "?")
                combos[("?", "none")] += 1
                continue
            orient = classify(tl, meta)
            fmap[ti] = (meta["Ss"], orient)
            combos[(meta["Ss"], orient)] += 1
            prec_seen.add(meta["prec"])
            dht_patterns[tuple(meta["dhts"])] += 1
            sel_patterns[tuple(meta["sels"])] += 1
            if len(tiles[ti]) % 2:
                odd_tiles += 1
            r = ti // gcols
            if r == grows - 1:
                lastrow_metas[(meta["Ss"], orient, meta["Y"])] += 1
            if (meta["Ss"], orient) not in {(7, "wrap"), (2, "wrap"), (1, "nat")}:
                nonstd.append((fi, ti, meta["Ss"], orient, meta["Y"], meta["X"]))
        frame_maps[fi] = fmap

    print(f"\n=== (Ss, orientation) combos across {len(files)} frames ===")
    for (ss, o), c in sorted(combos.items()):
        print(f"  Ss={ss} {o:5s} x{c}")
    print(f"\nprecisions: {sorted(prec_seen)}  odd-sized tiles: {odd_tiles}")
    print(f"DHT TcTh patterns: {dict(dht_patterns)}")
    print(f"SOS selector patterns: {dict(sel_patterns)}")
    print(f"\nlast-row (clipped) tiles: {dict(lastrow_metas)}")
    if nonstd:
        print(f"\n!! {len(nonstd)} tiles OUTSIDE {{7-wrap, 2-wrap, 1-nat}} (first 30):")
        for row in nonstd[:30]:
            print(f"   frame {row[0]} tile {row[1]}: Ss={row[2]} {row[3]} SOF {row[4]}x{row[5]}")
    else:
        print("\nall tiles inside the 3-candidate hypothesis {7-wrap, 2-wrap, 1-nat}")

    # Ss==1 coupling with natural orientation, per frame
    s1 = Counter()
    for fi, fmap in frame_maps.items():
        s1_tiles = {ti for ti, (ss, o) in fmap.items() if ss == 1}
        nat_tiles = {ti for ti, (ss, o) in fmap.items() if o == "nat"}
        if s1_tiles != nat_tiles:
            s1["MISMATCH"] += 1
        elif not s1_tiles:
            s1["both empty"] += 1
        else:
            s1["equal+nonempty"] += 1
    print(f"\nSs=1 tiles vs natural tiles per frame: {dict(s1)}")

    # per-frame natural-tile counts (compact anomaly view)
    nat_per_frame = [sum(1 for (_, o) in f.values() if o == "nat") for f in frame_maps.values()]
    ss1_per_frame = [sum(1 for (ss, _) in f.values() if ss == 1) for f in frame_maps.values()]
    print(f"\nnatural/Ss=1 tile counts per frame: min {min(nat_per_frame)} / max {max(nat_per_frame)} "
          f"(both lists equal: {nat_per_frame == ss1_per_frame})")
    print(f"per-frame Ss=7-wrap counts: min {min(sum(1 for (ss, o) in f.values() if (ss, o) == (7, 'wrap')) for f in frame_maps.values())} / "
          f"max {max(sum(1 for (ss, o) in f.values() if (ss, o) == (7, 'wrap')) for f in frame_maps.values())}")

    if json_out:
        out = {"preset": preset_dir, "frame": [W, H], "grid": [gcols, grows],
               "tiles": {str(fi): {str(ti): list(v) for ti, v in m.items()}
                         for fi, m in frame_maps.items()}}
        with open(json_out, "w") as f:
            json.dump(out, f)
        print(f"\njson map -> {json_out}")


if __name__ == "__main__":
    main()