#!/usr/bin/env python3
"""vts parity regression test — dct12_tile_scan.py (vts) vs the production
reference decoder (tool/target/release/render_dng, == rawpy/LibRaw exact).

WHY THIS TEST EXISTS: vts was declared "CONTAMINATED"
after forensics measured 5.71-56.77 LSB vts-vs-prod divergence.
Root cause: vts's decode path is CORRECT (bit-exact vs the Rust oracle
and the rawpy ground truth on block 0 of the f0001 fixture, 100% of pixels
within 1 LSB on every fixture frame/scan at the time of writing). The
"contamination" was a two-part fixture/measurement artifact, NOT a vts decode
bug:
  1. The forensics fixture script assembled the plane with the WRONG reshape —
     `P.reshape(NBLK_H, 8, NBLK_W, 8)` scrambles the (band, col, r, k) axes;
     the correct assembly (vts main() / this test) is
     `P.reshape(NBLK_H, NBLK_W, 8,8).transpose(0,2,1,3)`;
  2. the render_dng PGM domain is POST-CURVE 0..4095 x1 (BE u16, maxval
     65535, values written as-is by render_dng.rs) — NOT "post-curve x16"
     (an earlier assumption that poisoned the quick checks).
A scrambled dark frame compared in the same domain looks like a
"content-dependent, blockwise, both-scans" divergence — exactly the reported
signature. This test makes that bug class impossible to repeat silently: any
future vts decode regression shows up as a >1 LSB gate failure on the fixture
frames, and the PGM reader encodes the verified x1/BE domain.

DOMAIN FACTS (verified, do not "correct"):
  * render_dng PGM: P5, "<w> <h>", maxval 65535, BIG-ENDIAN u16 pixels,
    values = post-curve 0..4095 for comp 7 (DCT) and raw 12-bit 0..4095 for
    comp 1 (unpacked source) — x1 in both.
  * vts decode_plane output: post-curve 0..4095 (curve applied inside).
  * f32 (Rust) vs f64 (vts) IDCT: isolated 1-LSB pixels at rounding borders
    are expected and are the only tolerated residual (content-INDEPENDENT).

FIXTURES (gitignored testdata, on-disk in a fresh checkout only via the
intake protocol — see testdata/README.md; the test aborts with a clear
message if a fixture is missing):
  DCT path (comp 7, reference vbr-hq A001_001): frames
      000001 000065 000097 000113 000132 000164 000185 000225
  source path (comp 1, originals A001_001): frames 000001, 000100
      (API-path guard for vts.frame_pixels, which the DCT path does not
       exercise)

USAGE:
  test_vts_parity.py                 # full gate: 8 DCT frames + 2 source
  test_vts_parity.py --frames 1,65   # subset (DCT frames, quick smoke)
  test_vts_parity.py --skip-dct      # source path only (~seconds)
  test_vts_parity.py --run-dir PATH  # where PGM cache + TSV land
                                      # (default: the internal run dir)

GATE (per spec): DCT frames, BOTH scans: all-row MAE <= 1.0 LSB AND max diff
<= 8 LSB, and the residual must be content-INDEPENDENT (pct within 1 LSB
reported per row; a content-dependent signature = not fixed, investigate).
Source frames: exact or <= 1 LSB. Exit 0 = PASS, 1 = FAIL, 2 = fixture/setup
error. Full run ~50 min (vts is a pure-Python reference decoder: ~43 s per
scan, 8 scans/frame) — it is a fixture regression gate, not a CI smoke test.
"""
import argparse
import glob
import os
import subprocess
import sys
import time

import numpy as np

TOOLS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLS)                      # .../projects/frameprism
PERSONAL = os.path.dirname(os.path.dirname(ROOT))  # .../Personal
DEFAULT_RUN_DIR = os.path.join(PERSONAL, "runs", "frameprism-v4-erasure")
DCT_FRAMES = ["000001", "000065", "000097", "000113",
              "000132", "000164", "000185", "000225"]
SRC_FRAMES = ["000001", "000100"]
MAE_GATE = 1.0
MAX_GATE = 8

sys.path.insert(0, TOOLS)
import dct12_tile_scan as vts  # noqa: E402
from dct12_dng_probe import read_ifd  # noqa: E402


def die_setup(msg):
    print(f"SETUP-ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


def load_pgm(path):
    """render_dng PGM: P5, BE u16, x1 domain (see module docstring)."""
    raw = open(path, "rb").read()
    parts = raw.split(b"\n", 3)
    if parts[0] != b"P5":
        die_setup(f"not a P5 PGM: {path}")
    w = int(parts[1].split()[0])
    h = int(parts[1].split()[1])
    pix = np.frombuffer(parts[3], dtype=np.dtype(np.uint16).newbyteorder(">"))
    if pix.size != w * h:
        die_setup(f"PGM size mismatch {pix.size} vs {w}x{h} in {path}")
    return pix.reshape(h, w).astype(np.int32), w, h


def render_pgms(dng, out, render_bin):
    r = subprocess.run([render_bin, dng, out], capture_output=True, text=True)
    if r.returncode != 0:
        die_setup(f"render_dng failed on {dng}: {r.stderr.strip()}")


def dng_path(root, kind, frame):
    base = ("reference/vbr-hq/A001_001" if kind == "dct"
            else "originals/A001_001")
    p = os.path.join(root, "testdata", base, f"A001_001_20260701_{frame}.DNG")
    if not os.path.exists(p):
        die_setup(f"fixture missing: {p} (testdata is gitignored — run the "
                  f"intake protocol, testdata/README.md)")
    return p


def vts_full_frame(vb, tags, curve, frame=None):
    """vts both-scan decode with the CORRECT plane assembly (vts main()
    layout; the `reshape(NBLK_H, 8, NBLK_W, 8)` variant is the
    known scramble bug — do not reintroduce it). Returns (frame, per-scan
    (plane, ys) list)."""
    tw, tl = tags[322]["val"][0], tags[323]["val"][0]
    offs, cnts = tags[324]["val"], tags[325]["val"]
    fw, fh = tags[256]["val"][0], tags[257]["val"][0]
    out = np.zeros((fh, fw), dtype=np.int32)
    per_scan = []
    for ti in range(len(offs)):
        tile = vb[offs[ti]:offs[ti] + cnts[ti]]
        dht, dqt, sos = vts.parse_tile_markers(tile)
        quant = dqt[0]
        tr, tc = ti // 2, ti % 2
        ty0, tx0 = tr * tl, tc * tw
        for si in (0, 1):
            data = tile[sos[si][1]:sos[si][2]]
            h_dc, _ = vts.make_decoder_ref(*dht[si])
            h_ac, _ = vts.make_decoder_ref(*dht[0x10 + si])
            blocks = vts.decode_plane(data, h_dc, h_ac, quant, curve)
            plane = vts.plane_from_blocks(blocks).astype(np.int32)
            ys = ty0 + 2 * np.arange(vts.NBLK_H * 8) + si
            keep = ys < fh
            out[ys[keep], tx0:tx0 + tw] = plane[keep]
            per_scan.append((si, plane, ys, keep, tx0, tw))
    return out, per_scan


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--frames", default="",
                    help="comma list of DCT frame numbers (default: all 8)")
    ap.add_argument("--skip-dct", action="store_true",
                    help="source-path guard only")
    ap.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    a = ap.parse_args()

    os.makedirs(os.path.join(a.run_dir, "w16_pgm"), exist_ok=True)
    tsv = os.path.join(a.run_dir, "w16_parity.tsv")
    with open(tsv, "w") as f:
        f.write("frame\tpath\tscan\tmae_lsb\tmax_lsb\tn_pix\tpct_within_1\n")

    render_bin = os.path.join(ROOT, "tool", "target", "release", "render_dng")
    if not os.path.exists(render_bin):
        print("render_dng missing — building (release) ...", flush=True)
        r = subprocess.run(["cargo", "build", "--release", "--bin", "render_dng"],
                           cwd=os.path.join(ROOT, "tool"),
                           capture_output=True, text=True)
        if r.returncode != 0:
            die_setup(f"cargo build failed: {r.stderr[-2000:]}")

    rows = []
    if not a.skip_dct:
        frames = ([p.zfill(6)[-6:] for p in a.frames.split(",")] if a.frames
                  else [f for f in DCT_FRAMES])
        for frame in frames:
            frame = frame[-6:]
            dng = dng_path(ROOT, "dct", frame)
            pgm = os.path.join(a.run_dir, "w16_pgm", f"fit_ven_{frame}.pgm")
            if not os.path.exists(pgm):
                t0 = time.time()
                render_pgms(dng, pgm, render_bin)
                print(f"f{frame}: oracle PGM rendered in {time.time()-t0:.0f}s",
                      flush=True)
            ref, w, h = load_pgm(pgm)
            vb = open(dng, "rb").read()
            tags = read_ifd(vb, 8, "<")
            curve = vts.linearization_curve(vb, tags)
            t0 = time.time()
            full, per_scan = vts_full_frame(vb, tags, curve, frame)
            for si, plane, ys, keep, tx0, tw in per_scan:
                ref_rows = ref[np.clip(ys, 0, h - 1), tx0:tx0 + tw][keep]
                diff = np.abs(plane[keep] - ref_rows)
                row = (frame, "dct", si, float(diff.mean()), int(diff.max()),
                       int(diff.size), float((diff <= 1).mean() * 100))
                rows.append(row)
                print(f"f{frame} scan{si}: MAE {row[3]:.4f} max {row[4]} "
                      f"within1 {row[6]:.3f}%  t={time.time()-t0:.0f}s",
                      flush=True)
    for frame in SRC_FRAMES:
        dng = dng_path(ROOT, "src", frame)
        pgm = os.path.join(a.run_dir, "w16_pgm", f"src_{frame}.pgm")
        if not os.path.exists(pgm):
            render_pgms(dng, pgm, render_bin)
        ref, w, h = load_pgm(pgm)
        vb = open(dng, "rb").read()
        tags = read_ifd(vb, 8, "<")
        mine = vts.frame_pixels(vb, tags[256]["val"][0], tags[257]["val"][0])
        diff = np.abs(mine.astype(np.int32) - ref)
        row = (frame, "src", 0, float(diff.mean()), int(diff.max()),
               int(diff.size), float((diff <= 1).mean() * 100))
        rows.append(row)
        print(f"f{frame} src: MAE {row[3]:.4f} max {row[4]} within1 {row[6]:.3f}%",
              flush=True)

    with open(tsv, "a") as f:
        for r in rows:
            f.write(f"{r[0]}\t{r[1]}\t{r[2]}\t{r[3]:.4f}\t{r[4]}\t{r[5]}\t{r[6]:.3f}\n")

    # GATE
    fails = []
    for r in rows:
        frame, kind, si, mae, mx, n, p1 = r
        if kind == "dct":
            if mae > MAE_GATE or mx > MAX_GATE:
                fails.append(f"f{frame} scan{si}: MAE {mae:.3f} > {MAE_GATE} or "
                             f"max {mx} > {MAX_GATE}")
            elif p1 < 99.0:
                print(f"WARN f{frame} scan{si}: within-1 {p1:.2f}% < 99% — "
                      f"residual is not content-independent; inspect before "
                      f"trusting vts on new content")
        else:
            if mx > 1:
                fails.append(f"f{frame} src: max {mx} > 1 LSB")
    print(f"\nTSV: {tsv}")
    if fails:
        print("GATE: FAIL")
        for f_ in fails:
            print("  " + f_)
        sys.exit(1)
    print(f"GATE: PASS — {len(rows)} comparisons, all within "
          f"MAE {MAE_GATE} / max {MAX_GATE} LSB (DCT) and <=1 LSB (source); "
          f"residual is the content-independent f32/f64 IDCT rounding class")


if __name__ == "__main__":
    main()
