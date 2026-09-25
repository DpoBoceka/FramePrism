#!/usr/bin/env python3
"""Fuzz corpus generator — ci/fuzz-corpus/ (the 25 fixtures, fixed seeds).

Regenerates every committed *.DNG fixture from scratch, byte-identical:
  - Class A: synthetic single-strip J92 (tag-7, no tile tags, 12-bit CFA)
    — the codec::decode_lossless turbojpeg C boundary.
  - Class B: mutations of the committed synthetic base-frame.dng (the
    golden-model Rust decode path). The generator READS the committed base —
    it never re-encodes.
  - Class C: synthetic garbage TIFF — the read_meta Rust parse.

The base frame (base-frame.dng, same dir) is a plain encode of the first
committed deterministic synthetic ci/oracle10 source frame (10 frames,
3856x2170, tiled 12-bit J92); its embedded records carry the encoder's
source path + mtime (the known record free variables).

Usage: python3 generate_corpus.py [--check]
  default: (re)write the 25 fixtures next to this script.
  --check: verify every existing fixture matches regeneration
           (exit 1 naming any drift) — writes nothing.
"""
import os, random, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(HERE, "base-frame.dng")

def u32(v): return struct.pack("<I", v)

def build_single_strip(strip, bps=12, w=3856, h=2170, have_off=True, have_cnt=True,
                       cnt_delta=0, magic=b"II*\x00"):
    """Minimal LE TIFF, ALL values in-line (the tool's convention for
    count-1 LONG/SHORT — matches the real J92 frames: 256/257/273/279
    carry their values in the entry's 4-byte value field). Layout:
    magic(4) + ifd_ptr(4) + IFD(2+n*12+4) + strip."""
    n = 6 + (1 if have_off else 0) + (1 if have_cnt else 0)
    ifd_size = 2 + n * 12 + 4
    strip_pos = 8 + ifd_size
    rows = []
    rows.append((256, 4, w))            # ImageWidth (in-line LONG)
    rows.append((257, 4, h))            # ImageLength
    rows.append((258, 3, bps))          # BitsPerSample (short)
    rows.append((259, 3, 7))            # Compression = JPEG
    rows.append((262, 3, 32803))        # Photometric = CFA
    rows.append((277, 3, 1))            # SamplesPerPixel
    if have_off:
        rows.append((273, 4, strip_pos))
    if have_cnt:
        rows.append((279, 4, len(strip) + cnt_delta))
    assert len(rows) == n
    ifd = struct.pack("<H", n)
    for tag, typ, val in rows:
        if typ == 3:
            ifd += struct.pack("<HHII", tag, typ, 1, val)
        else:
            ifd += struct.pack("<HHII", tag, typ, 1, val)  # in-line LONG
    ifd += struct.pack("<I", 0)
    return magic + u32(8) + ifd + strip

def jpeg_sof3(w, h, prec=12):
    """SOF3 (lossless): precision, height, width, 1 component (id 1, no quant)."""
    body = struct.pack(">BHHB", prec, h, w, 1) + struct.pack(">BB", 1, 0)
    return b"\xff\xed" + struct.pack(">H", len(body) + 2) + body

def jpeg_dht_dummy():
    # DHT: Tc=0 Tn=0, 16 count bytes (all 1 -> 1 symbol), 1 symbol byte
    counts = bytes([1] + [0] * 15)
    body = b"\x00" + counts + b"\x00"
    return b"\xff\xc4" + struct.pack(">H", len(body) + 2) + body

def jpeg_sos(w, h):
    body = struct.pack(">BBB", 1, 1, 0) + b"\x00\x3f\x00"  # 1 comp, dc0 ac0, spectable
    return b"\xff\xda" + struct.pack(">H", len(body) + 2) + body

variants = {}

# ---------- Class A: single-strip (the C boundary) ----------
garbage_scan = random.Random(1).randbytes(40000)
sof3 = jpeg_sof3(3856, 2170)
dht = jpeg_dht_dummy()
sos = jpeg_sos(3856, 2170)

# a1: plausible structure, garbage scan, no EOI
variants["a1-sof3-dht-sos-garbage"] = build_single_strip(b"\xff\xd8" + sof3 + dht + sos + garbage_scan)
# a2: 10% truncation of that stream
s = b"\xff\xd8" + sof3 + dht + sos + garbage_scan
variants["a2-trunc10"] = build_single_strip(s[: len(s) // 10])
# a3: all 0xFF strip
variants["a3-all-0xff"] = build_single_strip(b"\xff" * 100000)
# a4: all-zero strip
variants["a4-all-zero"] = build_single_strip(b"\x00" * 100000)
# a5: SOI only (the a5 guard: header parse "succeeds" with garbage dims)
variants["a5-soi-only"] = build_single_strip(b"\xff\xd8")
# a6: zero-length strip
variants["a6-zero-len"] = build_single_strip(b"")
# a7: strip length claims +1000 past EOF
variants["a7-len-past-eof"] = build_single_strip(garbage_scan, cnt_delta=1000)
# a8: strip length claims -1000 (short read into a longer payload)
variants["a8-len-short"] = build_single_strip(b"\xff\xd8" + sof3 + dht + sos + garbage_scan, cnt_delta=-1000)
# a9: huge w/h claim + garbage
variants["a9-huge-wh"] = build_single_strip(b"\xff\xd8" + sof3 + dht + sos + garbage_scan, w=0xFFFFFFFF, h=0xFFFFFFFF)
# a10: bps=10 (strip path is 12-bit only)
variants["a10-bps10"] = build_single_strip(b"\xff\xd8" + sof3 + dht + sos + garbage_scan, bps=10)
# a11: missing StripOffsets
variants["a11-no-273"] = build_single_strip(b"\xff\xd8" + sof3 + garbage_scan, have_off=False)
# a12: missing Photometric (rebuild without tag 262)
def build_no_262(strip):
    entries = [(256, 4, 3856, None), (257, 4, 2170, None), (258, 3, 12, None),
               (259, 3, 7, None), (277, 3, 1, None),
               (273, 4, None, u32(0)), (279, 4, None, u32(len(strip)))]
    n = len(entries)
    ifd = struct.pack("<H", n)
    for i, (tag, typ, val, payload) in enumerate(entries):
        if typ == 3:
            ifd += struct.pack("<HHII", tag, typ, 1, val)
        else:
            ifd += struct.pack("<HHI I", tag, typ, 1, 0)
    ifd += struct.pack("<I", 0)
    off = 8 + 2 + n * 12 + 4
    body = b""
    cur = off
    for i, (tag, typ, val, payload) in enumerate(entries):
        if typ == 4 and payload is not None:
            epos = 2 + i * 12 + 8
            ifd = ifd[:epos] + u32(cur) + ifd[epos + 4:]
            body += payload
            cur += len(payload)
    return b"II*\x00" + u32(8) + ifd + body + strip
variants["a12-no-photometric"] = build_no_262(b"\xff\xd8" + sof3 + garbage_scan)

# ---------- Class B: synthetic tiled base mutations ----------
base = open(BASE, "rb").read()

def find_tag_value(d, tag, want_typ=None):
    ifd = struct.unpack_from("<I", d, 4)[0]
    n = struct.unpack_from("<H", d, ifd)[0]
    for i in range(n):
        e = ifd + 2 + i * 12
        t, typ, cnt = struct.unpack_from("<HHI", d, e)
        if t == tag and (want_typ is None or typ == want_typ):
            return e, typ, cnt
    return None

r = find_tag_value(base, 325)  # TileByteCounts out-of-line
tile_cnt_off = struct.unpack_from("<I", base, r[0] + 8)[0]
tile0_len = struct.unpack_from("<I", base, tile_cnt_off)[0]
r = find_tag_value(base, 324)
tile_off_arr = struct.unpack_from("<I", base, r[0] + 8)[0]
tile0_off = struct.unpack_from("<I", base, tile_off_arr)[0]

variants["b1-tile0-bitflip"] = base[:tile0_off + 200] + bytes([base[tile0_off + 200] ^ 1]) + base[tile0_off + 201:]
variants["b2-trunc95"] = base[: int(len(base) * 0.95)]
variants["b3-trunc10"] = base[: int(len(base) * 0.10)]
b = bytearray(base)
struct.pack_into("<I", b, tile_cnt_off, tile0_len + 1000)
variants["b4-tilelen-plus1000"] = bytes(b)
b = bytearray(base)
r322 = find_tag_value(base, 322)  # TileWidth
if r322[1] == 4:
    struct.pack_into("<I", b, r322[0] + 8, 481)
else:
    struct.pack_into("<H", b, r322[0] + 8, 481)
variants["b5-tilewidth-481"] = bytes(b)
rng = random.Random(42)
variants["b6-tile0-rng"] = base[:tile0_off] + bytes(rng.getrandbits(8) for _ in range(tile0_len)) + base[tile0_off + tile0_len:]
variants["b7-bad-magic"] = b"\xde\xad\xbe\xef" + base[4:]
variants["b8-ifd-truncated"] = base[:80]  # cut inside the 59-entry IFD

# ---------- Class C: synthetic garbage TIFF ----------
variants["c1-random-bytes"] = random.Random(3).randbytes(65536)
variants["c2-ifd-past-eof"] = b"II*\x00" + u32(0xFFFFFFFF) + b"\x00" * 32
variants["c3-ifd-count-huge"] = b"II*\x00" + u32(8) + struct.pack("<H", 0xFFFF) + b"\x00" * 64
# c4: unknown field type (typ=99) in first entry
variants["c4-unknown-type"] = b"II*\x00" + u32(8) + struct.pack("<H", 1) + struct.pack("<HHI", 256, 99, 1) + u32(0) + u32(0) + b"\x00" * 16
variants["c5-be-magic-le-ifd"] = b"MM\x00*" + u32(8) + struct.pack("<H", 1) + struct.pack("<HHI", 256, 4, 1) + u32(0) + u32(0) + b"\x00" * 16

check = "--check" in sys.argv
drift = []
for name in sorted(variants):
    data = variants[name]
    p = os.path.join(HERE, name + ".DNG")
    if check:
        if not os.path.exists(p):
            drift.append((name, "missing"))
        elif open(p, "rb").read() != data:
            drift.append((name, "drift"))
        else:
            print(f"check OK {name} ({len(data)} B)")
    else:
        with open(p, "wb") as f:
            f.write(data)
        print(f"wrote {name}.DNG ({len(data)} B)")
if check:
    if drift:
        for name, why in drift:
            print(f"DRIFT {name}: {why}")
        sys.exit(1)
    print(f"corpus check: {len(variants) - len(drift)}/{len(variants)} byte-identical")
