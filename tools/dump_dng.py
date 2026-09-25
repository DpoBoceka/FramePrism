#!/usr/bin/env python3
"""dng dump — minimal DNG/TIFF frame inspector.

Pure stdlib (numpy optional for stats). Prints per file:
  - endianness, IFD0 tag table (named where known), sub-IFDs
  - raw strip geometry + position in file (strip-at-EOF check)
  - XMP / cDNG tags (TimeCodes 51043, FrameRate 51044, TStop 51058)
  - for uncompressed frames: raw-plane statistics (min/max/mean/percentiles)
  - for JPEG-compressed frames: 513/514 + JPEG stream extent

Usage: dump_dng.py [--stats] file.dng [more.dng ...]
"""
import struct
import sys

TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 4, 16: 8}
TYPE_NAMES = {1: 'BYTE', 2: 'ASCII', 3: 'SHORT', 4: 'LONG', 5: 'RATIONAL', 6: 'SBYTE',
              7: 'UNDEF', 8: 'SSHORT', 9: 'SLONG', 10: 'SRATIONAL', 11: 'UNDEFINED',
              12: 'IFD-PTR', 16: 'FLOAT'}
NAMES = {
    254: 'NewSubfileType', 256: 'ImageWidth', 257: 'ImageLength', 258: 'BitsPerSample',
    259: 'Compression', 262: 'PhotometricInterpretation', 270: 'ImageDescription',
    271: 'Make', 272: 'Model', 273: 'StripOffsets', 274: 'Orientation', 277: 'SamplesPerPixel',
    278: 'RowsPerStrip', 279: 'StripByteCounts', 282: 'XResolution', 283: 'YResolution',
    284: 'PlanarConfig', 305: 'Software', 306: 'DateTime', 315: 'ResolutionUnit',
    339: 'SampleFormat', 513: 'JPEGInterchangeFormat', 514: 'JPEGInterchangeFormatLength',
    34665: 'ExifIFD', 34853: 'GPSIFD', 40095: 'InteropIFD', 700: 'XMP', 33550: 'Copyright',
    33487: 'FocalLenIn35mm', 33489: 'CFARepeatPatternDim', 33490: 'CFAPattern',
    51008: 'CalibrationIlluminant1', 51009: 'ColorMatrix1', 51010: 'ColorMatrix2',
    51018: 'AsShotNeutral', 51021: 'BaselineExposure', 51022: 'OpcodeList3',
    51025: 'AnalogGain', 51040: 'DefaultCrop', 51041: 'NoiseProfile',
    51042: 'DefaultScale', 51043: 'TimeCodes', 51044: 'FrameRate', 51045: 'CameraSerialNumber',
    51046: 'LensInfo', 51050: 'AsShotWhitePoint', 51058: 'TStop',
    51064: 'BlackLevelRepeatDim', 51065: 'BlackLevel', 51066: 'WhiteLevel',
    51067: 'DefaultBlack', 51068: 'DefaultWhite', 51089: 'CFALayout',
    51326: 'DNGVersion', 51327: 'DNGPrivateData', 51328: 'SubIFD',
    51336: 'UniqueCameraModel', 51337: 'LensModel', 51340: 'BodySerialNumber',
    51346: 'ActiveArea', 51347: 'MaskedArea', 51352: 'CameraSerialNumber',
}
COMPRESSION_NAMES = {1: 'none', 2: 'CCITT', 3: 'T4', 4: 'T6', 5: 'LZW', 6: 'JPEG',
                     7: 'JPEG-lossless', 8: 'JPEG2000', 32946: 'Deflate', 34712: 'LD-JPEG'}
# Sigma-private tags observed in SIGMA fp cDNG (names inferred from values)
SIGMA_NAMES = {
    0xC61D: 'Sigma:sensorMax(WhiteLevel?)', 0xC620: 'Sigma:ActiveArea3840x2160?',
    0xC621: 'Sigma:ColorMatrixA?', 0xC622: 'Sigma:ColorMatrixB?', 0xC62F: 'Sigma:Serial?',
    0xC634: 'Sigma:SIGMA_EXTH_SPPA block', 0xC68D: 'Sigma:CropRect(0,0,H,W)?',
    0xC6F9: 'Sigma:?', 0xC6FA: 'Sigma:calibA(216f32)?', 0xC6FB: 'Sigma:calibB(216f32)?',
    0xC6FC: 'Sigma:calibGrid(256f32)?',
}
PHOTOMETRIC_NAMES = {1: 'WhiteIsZero', 2: 'BlackIsZero', 3: 'RGB', 4: 'CMYK', 5: 'YCbCr',
                     6: 'CIELab', 8: 'LogLuv', 32803: 'CFA', 34892: 'LinearRaw'}


def read_ifd(buf, off, e):
    n = struct.unpack_from(e + 'H', buf, off)[0]
    if n > 500:
        raise ValueError(f'implausible tag count {n} at {off}')
    base = off + 2
    tags = []
    for i in range(n):
        t = base + i * 12
        tag, typ, count = struct.unpack_from(e + 'HHI', buf, t)
        raw = buf[t + 8:t + 12]
        tags.append((tag, typ, count, raw))
    nxt = struct.unpack_from(e + 'I', buf, base + n * 12)[0] if base + n * 12 + 4 <= len(buf) else 0
    return tags, nxt


def val_bytes(buf, tag, typ, count, raw, e):
    sz = TYPE_SIZES.get(typ, 1) * count
    if sz <= 4:
        return raw[:sz]
    ptr = struct.unpack_from(e + 'I', raw)[0]
    if ptr + sz > len(buf):
        return b''
    return buf[ptr:ptr + sz]


def _nums(vb, e, count, signed):
    fmt = ('i' if signed else 'I') * count
    try:
        return struct.unpack_from(e + fmt, vb)
    except struct.error:
        return ()


def fmt_val(tag, typ, count, vb, e):
    if not vb:
        return '<missing>'
    if tag == 259 and typ in (3, 4) and count == 1:
        c = struct.unpack_from(e + ('H' if typ == 3 else 'I'), vb)[0]
        return f'{c} ({COMPRESSION_NAMES.get(c, "?")})'
    if tag == 262 and typ in (3, 4) and count == 1:
        c = struct.unpack_from(e + ('H' if typ == 3 else 'I'), vb)[0]
        return f'{c} ({PHOTOMETRIC_NAMES.get(c, "?")})'
    if typ == 2:
        return repr(vb.rstrip(b'\x00')[:110])
    if typ in (1, 3, 4, 6, 8, 9) and count <= 12:
        vals = _nums(vb, e, count, typ in (6, 8, 9))
        if not vals:
            return '<short>'
        if typ in (1, 6):
            return ' '.join(str(v) for v in vals)
        if tag in (273, 279):
            return ' '.join(f'{v} (0x{v:x})' for v in vals)
        return ' '.join(str(v) for v in vals)
    if typ in (5, 10) and count <= 12:
        n = _nums(vb, e, count * 2, typ == 10)
        if not n:
            return '<short>'
        return ' '.join(f'{n[i]}/{n[i + count]}' for i in range(count))
    if typ == 16 and count <= 16:
        try:
            return ' '.join(f'{v:.4g}' for v in struct.unpack_from(e + f'{count}f', vb))
        except struct.error:
            return '<short>'
    if tag == 51043 and typ == 1:
        out = []
        for i in range(count):
            b = vb[i * 8:i * 8 + 8]
            if len(b) < 8:
                break
            u = bool(b[0] & 0x01)
            df = bool(b[0] & 0x02)
            fr = b[0] & 0x78
            out.append(f"{'19' if u else '20'}{b[1]:02d}:{b[2]:02d}:{b[3]:02d}:{b[4]:02d}"
                       f"{',' if df else ''}{fr:02d}")
        return ' '.join(out) + f'  [raw {vb.hex()[:40]}]'
    if len(vb) <= 48:
        return ' '.join(f'{b:02x}' for b in vb)
    return f'{len(vb)}B: ' + ' '.join(f'{b:02x}' for b in vb[:48]) + ' …'


def raw_stats(raw, e, bits):
    try:
        import numpy as np
        a = np.frombuffer(raw, dtype='<u2' if e == '<' else '>u2')
        p = np.percentile(a, [0, 1, 50, 99, 100]).astype(int)
        nz = np.count_nonzero(a)
        print(f'    raw stats (u16, n={a.size}): min={a.min()} p1={p[1]} p50={p[2]} '
              f'p99={p[3]} max={a.max()} mean={a.mean():.1f} std={a.std():.1f} '
              f'zero_frac={1 - nz / a.size:.5f}')
        m = int(a.max())
        if m <= 4095:
            print(f'    → values fit {m.bit_length()}-bit (sensorMax ~{4095 if m > 1023 else 1023})')
        else:
            print(f'    → {m} max')
    except ImportError:
        import array
        arr = array.array('H')
        arr.frombytes(raw)
        print(f'    raw stats (u16, n={len(arr)}): min={min(arr)} max={max(arr)} '
              f'mean={sum(arr) / len(arr):.1f} (no numpy)')


def main():
    args = [a for a in sys.argv[1:] if a != '--stats']
    with_stats = '--stats' in sys.argv
    for path in args:
        buf = open(path, 'rb').read()
        size = len(buf)
        bo = buf[:2]
        e = '<' if bo == b'II' else '>' if bo == b'MM' else None
        if e is None:
            print(f'!! {path}: not a TIFF (first 2 bytes: {bo!r})')
            continue
        off0 = struct.unpack_from(e + 'I', buf, 4)[0]  # IFD offset is at byte 4
        ifd0, nxt = read_ifd(buf, off0, e)
        tags = {t: (ty, c, raw) for t, ty, c, raw in ifd0}
        print(f'== {path}')
        print(f'   file={size:,} B ({size / 2**20:.2f} MiB), endianness={"little" if e == "<" else "big"}')
        for t, ty, c, raw in ifd0:
            name = NAMES.get(t) or SIGMA_NAMES.get(t) or f'0x{t:04X}'
            try:
                vb = val_bytes(buf, t, ty, c, raw, e)
                s = fmt_val(t, ty, c, vb, e)
            except Exception as ex:
                s = f'<decode err: {ex}>'
            print(f'   {t:5d} 0x{t:04X} {TYPE_NAMES.get(ty, ty):9s} n={c:<6d} {name:30s} {s[:104]}')
        # geometry + strip position (type-aware)
        def num(tag):
            if tag not in tags:
                return None
            ty, c, raw = tags[tag]
            vb = val_bytes(buf, tag, ty, c, raw, e)
            fmt = ('i' if ty in (8, 9, 10) else 'I' if ty in (3, 4, 5) else 'B')
            try:
                return struct.unpack_from(e + fmt, vb)[0]
            except struct.error:
                return None

        w, h = num(256), num(257)
        bps = num(258) or 16
        spp = num(277) or 1
        comp = num(259) or 1
        soffs, scnts = (num(273),) if 273 in tags else (None,), (num(279),) if 279 in tags else (None,)
        if w and h and soffs[0] is not None:
            exp = w * h * spp * ((bps + 7) // 8) if bps in (8, 16, 32) else w * h * spp * (bps // 8)
            tot = scnts[0] if scnts[0] else 0
            start, end = soffs[0], soffs[0] + tot
            print(f'   geometry: {w}x{h} spp={spp} bps={bps} comp={comp} '
                  f'({COMPRESSION_NAMES.get(comp, "?")})')
            print(f'   strip=[{start:,} .. {end:,}) count={tot:,} expected12bit={exp:,} '
                  f'strip_at_eof={end == size} gap_to_eof={size - end:,} B '
                  f'header={start:,} B')
        # sub-IFDs
        if 51328 in tags:
            ty, c, raw = tags[51328]
            vb = val_bytes(buf, 51328, ty, c, raw, e)
            for o in struct.unpack_from(e + f'{c}I', vb):
                sub, _ = read_ifd(buf, o, e)
                print(f'   SubIFD @ {o:,} ({o / 2**20:.2f} MiB): {len(sub)} tags '
                      f'[{", ".join(str(t) for t, *_ in sub[:40])}]')
        if 700 in tags:
            ty, c, raw = tags[700]
            xmp = val_bytes(buf, 700, ty, c, raw, e)
            print(f'   XMP: {len(xmp)} B, head: {xmp[:80]!r}')
        if comp == 1 and soffs[0] is not None and scnts[0]:
            raw_strip = buf[soffs[0]:soffs[0] + min(scnts[0], size - soffs[0])]
            if with_stats:
                print(f'    (reading {len(raw_strip):,} B strip for stats)')
                raw_stats(raw_strip, e, bps)
        if comp in (6, 7):
            j513 = num(513)
            eoi = buf.find(b'\xff\xd9', soffs[0]) if soffs[0] is not None else -1
            print(f'   JPEG: 513={j513} 514={num(514)} strip=[{soffs[0]:,}..{soffs[0] + scnts[0]:,}) '
                  f'EOI@{eoi:,}')
        print()


if __name__ == '__main__':
    main()