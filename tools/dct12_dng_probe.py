#!/usr/bin/env python3
"""Measure the tag-7 lossy tile structure.

Dumps, per tile of the lossy DNG (Compression 7, 12-bit DCT parity
planes): the full JPEG marker sequence + DQT tables (16-bit), SOF fields,
DHT tables (TcTq byte, counts, symbols), SOS fields (Ns, sel, Ss, Se,
AhAl) — the exact bytes to replicate for reference parity. Also prints the
DNG tag plan (258/259/262/322/323/50707/50712/33421/33422) and the
per-tile byte counts.

Usage:
  dct12_dng_probe.py <file.dng> [--tiles 0,1,2,3] [--full-dht] [--json OUT]

Stdlib only.
"""
import json
import struct
import sys

TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8,
              11: 1, 12: 4, 16: 8}

MARKER_NAMES = {
    0xFFD8: "SOI", 0xFFD9: "EOI", 0xFFDA: "SOS", 0xFFDB: "DQT", 0xFFC0: "SOF0",
    0xFFC1: "SOF1", 0xFFC2: "SOF2", 0xFFC3: "SOF3", 0xFFC4: "DHT", 0xFFDD: "DRI",
    0xFFE0: "APP0", 0xFFE1: "APP1", 0xFFE2: "APP2", 0xFFE3: "APP3", 0xFFE4: "APP4",
    0xFFE5: "APP5", 0xFFE6: "APP6", 0xFFE7: "APP7", 0xFFED: "APP13", 0xFFEE: "APP14",
    0xFFFE: "COM",
}


def read_ifd(buf, off, e):
    n = struct.unpack_from(e + "H", buf, off)[0]
    tags = {}
    base = off + 2
    for i in range(n):
        p = base + i * 12
        tag, typ, cnt = struct.unpack_from(e + "HHI", buf, p)
        sz = TYPE_SIZES[typ] * cnt
        if sz <= 4:
            val_off = p + 8
        else:
            (val_off,) = struct.unpack_from(e + "I", buf, p + 8)
        raw = buf[val_off:val_off + sz] if sz <= 128 or typ in (11, 12) else None
        if typ == 4 and cnt <= 64:
            vals = list(struct.unpack_from(e + f"{cnt}I", buf, val_off))
        elif typ == 3 and cnt <= 4600:
            vals = list(struct.unpack_from(e + f"{cnt}H", buf, val_off))
        else:
            vals = None
        tags[tag] = {"ty": typ, "cnt": cnt, "val": vals, "off": val_off}
    return tags


def walk_markers(tile: bytes, full_dht: bool):
    """Walk a JPEG stream's markers (up to EOI). Returns the report dict."""
    rep = {"markers": [], "dqt": [], "sof": None, "dht": [], "sos": []}
    if tile[:2] != b"\xff\xd8":
        rep["error"] = "not a JPEG (no SOI)"
        return rep
    i = 2
    n = len(tile)
    while i < n - 1:
        if tile[i] != 0xFF:
            rep["error"] = f"expected FF at {i:#x}, got {tile[i]:02x}"
            break
        m = tile[i + 1]
        if m == 0xD8:
            rep["markers"].append(("SOI", i))
            i += 2
            continue
        if m == 0xD9:
            rep["markers"].append(("EOI", i))
            i += 2
            break
        if m in (0x00, 0xFF) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        (ln,) = struct.unpack_from(">H", tile, i + 2)
        name = MARKER_NAMES.get(0xFF00 | m, f"UNK_{m:02X}")
        rep["markers"].append((name, i))
        if m == 0xDB:  # DQT
            prec = tile[i + 4]
            tq = tile[i + 4] & 0x0F
            entries = []
            j = i + 4
            while j < i + 2 + ln:
                tq = tile[j] & 0x0F
                entries = list(struct.unpack_from(">64H", tile, j + 1))
                j += 1 + 128
            rep["dqt"].append({"tq": tq, "prec16": prec == 0x10,
                               "mean": sum(entries) / 64, "first8": entries[:8],
                               "last8": entries[-8:], "all": entries if full_dht else None})
        elif m in (0xC0, 0xC1, 0xC2, 0xC3):  # SOF (baseline/extended/progressive/lossless)
            # payload (from i+4): P(1) Yh Yl Xh Xl Nf(1) [comps 3B each]
            prec, yh, xw, nf = struct.unpack_from(">BHHB", tile, i + 4)
            comps = []
            j = i + 10
            for _ in range(nf):
                cid, hv, tqb = struct.unpack_from(">BBB", tile, j)
                comps.append({"id": cid, "hv": [hv >> 4, hv & 0xF], "tq": tqb})
                j += 3
            rep["sof"] = {"marker": name, "precision": prec, "y": yh, "x": xw,
                          "nf": nf, "comps": comps}
        elif m == 0xC4:  # DHT
            (tctq,) = struct.unpack_from(">B", tile, i + 4)
            tc, tqb = tctq >> 4, tctq & 0xF
            counts = list(struct.unpack_from("16B", tile, i + 5))
            syms = list(tile[i + 21:i + 21 + sum(counts)])
            rep["dht"].append({"tctq": tctq, "tc": tc, "tq": tqb,
                               "len": ln, "counts": counts,
                               "syms": syms if full_dht else None,
                               "nsyms": sum(counts)})
        elif m == 0xDA:  # SOS
            (ns,) = struct.unpack_from(">B", tile, i + 4)
            comps = []
            j = i + 5
            for _ in range(ns):
                sel, ss, se, ahal = struct.unpack_from("4B", tile, j)
                comps.append({"sel": sel, "ss": ss, "se": se, "ah_al": ahal})
                j += 4
            rep["sos"].append({"ns": ns, "comps": comps, "len": ln})
        i += 2 + ln
    return rep


def main():
    argv = sys.argv[1:]
    args, opts = [], {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            if "=" in a:
                k, v = a.split("=", 1)
                opts[k] = v
            else:
                # --flag or --flag value
                if i + 1 < len(argv) and not argv[i + 1].startswith("--") and \
                        argv[i + 1] not in ("--full-dht",):
                    opts[a] = argv[i + 1]
                    i += 1
                else:
                    opts[a] = True
        else:
            args.append(a)
        i += 1
    path = args[0]
    tv = opts.get("--tiles", "0")
    tiles = [int(x) for x in str(tv).split(",")]
    full_dht = bool(opts.get("--full-dht"))
    buf = open(path, "rb").read()
    e = "<" if buf[:2] == b"II" else ">"
    tags = read_ifd(buf, 8, e)

    plan = {}
    for t in (256, 257, 258, 259, 262, 273, 278, 279, 322, 323, 324, 325,
              33421, 33422, 50706, 50707, 50711, 50712, 50713, 50714, 50717,
              50719, 50720, 50721, 50722, 50972, 51111):
        if t in tags:
            v = tags[t]["val"]
            if v is None:
                v = f"<raw @{tags[t]['off']:#x} cnt={tags[t]['cnt']} ty={tags[t]['ty']}>"
            plan[str(t)] = v
    out = {"file": path, "size": len(buf), "tags": plan, "tiles": {}}
    if 324 in tags and 325 in tags:
        offs = tags[324]["val"]
        cnts = tags[325]["val"]
        out["tag322_323"] = [plan.get("322"), plan.get("323")]
        for ti in tiles:
            o, c = offs[ti], cnts[ti]
            tile = buf[o:o + c]
            out["tiles"][str(ti)] = {"off": o, "size": c,
                                     "walk": walk_markers(tile, full_dht)}
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()