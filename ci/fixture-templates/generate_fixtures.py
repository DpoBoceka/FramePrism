#!/usr/bin/env python3
"""Regenerate the committed deterministic synthetic CFA fixtures.

The committed oracle source fixtures (ci/oracle10/src/, ci/oracle108/src/)
are deterministic synthetic CFA content in sanitized Sigma fp container
templates. This script is their provenance authority: it authenticates
every committed fixture against the committed sha256 manifest
(fixture-manifest.sha256), regenerates all 12 from the tree's own
committed template fixtures (the self-template mode: each set's template
IS its committed first frame), and byte-compares the regeneration
against the committed bytes.

Self-template mode: the templates are the tree's own committed
fixtures (already sanitized — the synthetic serial, the synthetic
epoch, the synthetic software string). The byte-generation core is the
authority: the container is kept, the metadata identity fields are
written to their fixed synthetic values (a no-op for the template frame,
a per-frame write for the derived frames), and the pixel strip is
replaced with the deterministic packed plane for the frame's seed.

`--verify` (the gate entrypoint) is read-only against the tree: it
writes only to a temp dir, removed on every path. `--out` regenerates
the full set into a fresh scratch dir (parity with the reference
implementation; restores deleted fixtures from the tree).

python3 stdlib only. Integer-only byte math (no floats in any
byte-affecting path, no platform PRNG, no locale) — the determinism
invariants of the reference implementation are preserved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import struct
import sys
import tempfile

SERIAL_REPLACEMENT = b"FPTEST01"
DATE = "2000:01:01 00:00:00"
SOFTWARE = "FramePrism Test Fixture"
TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2,
             9: 4, 10: 8, 11: 4, 12: 8, 13: 4, 16: 8, 17: 8, 18: 8}

# The fixture sets, in deterministic order. Each set: (out_dir = the
# committed dir the set's fixtures live in, name_prefix = the fixture
# name prefix, the bit depth, the frame count). The template is the
# committed first frame of the set: f"{out_dir}/{name_prefix}_000001.DNG"
# (the self-template); the output of frame N is
# f"{out_dir}/{name_prefix}_{N:06}.DNG" — for N = 1 that IS the
# template's own path.
FIXTURE_SETS = [
    ("ci/oracle10/src", "FPTEST_012_20000101", 12, 10),
    ("ci/oracle108/src/f10", "FPTEST_010_20000101", 10, 1),
    ("ci/oracle108/src/f8", "FPTEST_008_20000101", 8, 1),
]

MANIFEST_REL = "ci/fixture-templates/fixture-manifest.sha256"
TOTAL_FIXTURES = 12


class FixtureProvenanceError(Exception):
    """A named structural failure (the message names the offending path)."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ifd_entries(buf: bytes | bytearray, offset: int, endian: str):
    count = struct.unpack_from(endian + "H", buf, offset)[0]
    for index in range(count):
        pos = offset + 2 + index * 12
        tag, typ, item_count = struct.unpack_from(endian + "HHI", buf, pos)
        yield tag, typ, item_count, pos


def value_location(buf: bytes | bytearray, typ: int, count: int, pos: int, endian: str):
    size = TYPE_SIZE[typ] * count
    offset = pos + 8 if size <= 4 else struct.unpack_from(endian + "I", buf, pos + 8)[0]
    return offset, size


def numeric_value(buf: bytes | bytearray, typ: int, offset: int, endian: str) -> int:
    return struct.unpack_from(endian + ("H" if typ == 3 else "I"), buf, offset)[0]


def patch_ascii(buf: bytearray, typ: int, count: int, pos: int, endian: str, value: str):
    offset, size = value_location(buf, typ, count, pos, endian)
    encoded = value.encode("ascii")
    if len(encoded) >= size:
        raise ValueError(f"replacement {value!r} does not fit in {size} bytes")
    buf[offset:offset + size] = encoded + b"\0" * (size - len(encoded))


def bcd(value: int) -> int:
    return (value // 10) * 16 + value % 10


def timecode(frame_index: int) -> bytes:
    # Fixed synthetic epoch, one valid 24 fps non-drop step per frame.
    ff = (frame_index - 1) % 24
    seconds = (frame_index - 1) // 24
    return bytes((bcd(ff), bcd(seconds % 60), bcd((seconds // 60) % 60),
                  bcd((seconds // 3600) % 24), 0, 0, 0, 0))


def correlated_noise(x: int, y: int, seed: int) -> int:
    # A fixed 4x4-correlated integer field; no platform PRNG is involved.
    xx, yy = x >> 2, y >> 2
    z = (xx * 0x1F123BB5) ^ (yy * 0x5F356495) ^ (seed * 0x9E3779B1)
    z ^= z >> 16
    z = (z * 0x45D9F3B) & 0xFFFFFFFF
    z ^= z >> 16
    return (z & 255) - 128


def sample(x: int, y: int, width: int, height: int, bits: int, seed: int) -> int:
    maximum = (1 << bits) - 1
    tx, ty = min(7, x * 8 // width), min(5, y * 6 // height)
    lx = (x * 8) % width
    ly = (y * 6) % height
    tile_w = max(1, width // 8)
    tile_h = max(1, height // 6)
    u = min(1023, lx * 1024 // tile_w)
    v = min(1023, ly * 1024 // tile_h)
    kind = (tx + 3 * ty + seed) % 8
    if kind == 0:       # shadow flat
        level = 75
    elif kind == 1:     # horizontal ramp
        level = 100 + 800 * u // 1023
    elif kind == 2:     # vertical ramp
        level = 100 + 800 * v // 1023
    elif kind == 3:     # diagonal ramp
        level = 80 + 850 * (u + v) // 2046
    elif kind == 4:     # hard vertical and horizontal edges
        level = 160 if (u < 512) ^ (v < 512) else 820
    elif kind == 5:     # highlight field with a clipped patch
        level = 1000 if (u - 512) ** 2 + (v - 512) ** 2 < 115000 else 700
    elif kind == 6:     # coarse CFA-color patches
        patch = ((u // 256) + 4 * (v // 256) + seed) % 3
        cfa = 0 if not (y & 1) and not (x & 1) else (2 if (y & 1) and (x & 1) else 1)
        level = 820 if cfa == patch else 180
    else:               # seeded correlated texture
        level = 500 + correlated_noise(x, y, seed) * 3
    cfa = 0 if not (y & 1) and not (x & 1) else (2 if (y & 1) and (x & 1) else 1)
    level = level * (108, 100, 90)[cfa] // 100
    # Fine deterministic sensor-like grain plus a frame-specific offset.
    fine = (((x * 73 + y * 151 + seed * 199) ^ (x * y)) & 31) - 16
    value = level * maximum // 1023 + fine * max(1, maximum // 4095)
    return max(0, min(maximum, value))


def packed_plane(width: int, height: int, bits: int, seed: int) -> tuple[bytes, dict]:
    output = bytearray()
    minimum = (1 << bits) - 1
    maximum = 0
    sums = [0, 0, 0]
    counts = [0, 0, 0]
    for y in range(height):
        row = [sample(x, y, width, height, bits, seed) for x in range(width)]
        minimum = min(minimum, min(row)); maximum = max(maximum, max(row))
        for x, value in enumerate(row):
            cfa = 0 if not (y & 1) and not (x & 1) else (2 if (y & 1) and (x & 1) else 1)
            sums[cfa] += value; counts[cfa] += 1
        if bits == 8:
            output.extend(row)
        elif bits == 12:
            for x in range(0, width, 2):
                a, b = row[x:x + 2]
                output.extend((a >> 4, ((a & 15) << 4) | (b >> 8), b & 255))
        elif bits == 10:
            for x in range(0, width, 4):
                a, b, c, d = row[x:x + 4]
                output.extend(((a << 30) | (b << 20) | (c << 10) | d).to_bytes(5, "big"))
        else:
            raise ValueError(bits)
    stats = {"min": minimum, "max": maximum,
             "cfa_means": [round(sums[i] / counts[i], 3) for i in range(3)],
             "pattern_classes": ["shadow-flat", "horizontal-ramp", "vertical-ramp",
                                 "diagonal-ramp", "hard-edges", "highlights",
                                 "cfa-patches", "correlated-texture"]}
    return bytes(output), stats


def regenerate(original: bytes, name: str, bits: int, frame_index: int):
    """Regenerate one fixture from the self-template (the committed
    first frame of its set). Returns (original, regenerated, facts)."""
    buf = bytearray(original)
    endian = "<" if buf[:2] == b"II" else ">"
    root = struct.unpack_from(endian + "I", buf, 4)[0]
    todo = [root]
    seen = set()
    serials = []
    tags = {}
    while todo:
        ifd = todo.pop()
        if ifd in seen:
            continue
        seen.add(ifd)
        entries = list(ifd_entries(buf, ifd, endian))
        for tag, typ, count, pos in entries:
            offset, size = value_location(buf, typ, count, pos, endian)
            tags.setdefault(tag, (typ, count, offset, size, pos))
            if tag in (330, 34665, 34853) and typ in (3, 4) and count == 1:
                todo.append(numeric_value(buf, typ, offset, endian))
            if tag in (50735, 42033):
                serials.append(bytes(buf[offset:offset + size]).rstrip(b"\0"))
            if tag in (306, 36867, 36868):
                patch_ascii(buf, typ, count, pos, endian, DATE)
            elif tag in (50735, 42033):
                patch_ascii(buf, typ, count, pos, endian, SERIAL_REPLACEMENT.decode())
            elif tag == 42016:
                patch_ascii(buf, typ, count, pos, endian, sha256(name.encode())[:32])
            elif tag == 305:
                patch_ascii(buf, typ, count, pos, endian, SOFTWARE)
            elif tag == 51043:
                if size != 8:
                    raise ValueError(f"unexpected TimeCodes width {size}")
                buf[offset:offset + size] = timecode(frame_index)
    # Self-template serial invariant (the re-based R1.4): the template is
    # ALREADY sanitized. Every serial field found by the IFD walk (the
    # 50735 + 42033 SerialNumber tags — both patched above, a no-op for
    # the identity value) must carry exactly the synthetic serial, and
    # exactly ONE residual copy sits in the private maker-note data —
    # the reference implementation's residual==1 invariant re-based for
    # the self-template mode (its residual was the maker-note copy left
    # after the fields were written). Total occurrences = the serial-
    # field count + 1. The equal-width no-op replace preserves all
    # offsets; any other structure is a named failure.
    if not serials or any(s != SERIAL_REPLACEMENT for s in serials):
        raise FixtureProvenanceError(
            f"serial field(s) are not the synthetic serial "
            f"{SERIAL_REPLACEMENT!r}, got {serials!r} ({name})")
    occurrences = bytes(buf).count(SERIAL_REPLACEMENT)
    if occurrences != len(serials) + 1:
        raise FixtureProvenanceError(
            f"expected {len(serials) + 1} occurrences of the synthetic serial "
            f"({len(serials)} serial field(s) + the one maker-note copy), "
            f"got {occurrences} ({name})")
    buf[:] = bytes(buf).replace(SERIAL_REPLACEMENT, SERIAL_REPLACEMENT)
    if bytes(buf).count(SERIAL_REPLACEMENT) != occurrences:
        raise FixtureProvenanceError(
            f"serial occurrence count changed during the no-op replace ({name})")

    def number(tag: int) -> int:
        typ, _count, offset, _size, _pos = tags[tag]
        return numeric_value(buf, typ, offset, endian)

    width, height = number(256), number(257)
    actual_bits, strip_offset, strip_count = number(258), number(273), number(279)
    if actual_bits != bits:
        raise ValueError((actual_bits, bits))
    plane, stats = packed_plane(width, height, bits, frame_index)
    padding = strip_count - len(plane)
    if padding not in (8, 12):
        raise ValueError(f"unexpected strip padding {padding}")
    buf[strip_offset:strip_offset + strip_count] = plane + bytes(padding)
    if len(buf) != len(original):
        raise ValueError("container size changed")
    return original, bytes(buf), {
        "width": width, "height": height, "bits": bits,
        "strip_offset": strip_offset, "strip_count": strip_count,
        "strip_padding": padding, "timecode": f"00:00:00:{frame_index - 1:02}",
        **stats,
    }


def load_manifest(repo: pathlib.Path) -> dict:
    """Parse the committed sha256 manifest (the sha256sum convention:
    '<hex>  <repo-root-relative path>'). Every committed fixture must
    have exactly one row; the file must have exactly 12 rows."""
    manifest_path = repo / MANIFEST_REL
    if not manifest_path.is_file():
        raise FixtureProvenanceError(f"manifest missing: {MANIFEST_REL}")
    expected_paths = {
        f"{out_dir}/{name_prefix}_{frame:06}.DNG"
        for out_dir, name_prefix, _bits, count in FIXTURE_SETS
        for frame in range(1, count + 1)
    }
    rows = {}
    for line_no, line in enumerate(manifest_path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split("  ", 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            raise FixtureProvenanceError(
                f"malformed manifest row {line_no}: {line!r}")
        digest, rel = parts
        if rel in rows:
            raise FixtureProvenanceError(f"duplicate manifest row for {rel}")
        rows[rel] = digest
    if set(rows) != expected_paths:
        missing = sorted(expected_paths - set(rows))
        extra = sorted(set(rows) - expected_paths)
        raise FixtureProvenanceError(
            f"manifest path set mismatch (missing: {missing}; extra: {extra})")
    if len(rows) != TOTAL_FIXTURES:
        raise FixtureProvenanceError(
            f"expected {TOTAL_FIXTURES} manifest rows, got {len(rows)}")
    return rows


def authenticate(repo: pathlib.Path, manifest: dict) -> None:
    """Verify every committed fixture's sha256 against the manifest
    BEFORE any regeneration output is produced."""
    for rel in sorted(manifest):
        fixture = repo / rel
        if not fixture.is_file():
            raise FixtureProvenanceError(f"committed fixture missing: {rel}")
        actual = sha256(fixture.read_bytes())
        if actual != manifest[rel]:
            raise FixtureProvenanceError(
                f"fixture hash mismatch: {rel} (manifest {manifest[rel]}, "
                f"tree {actual})")


def regenerate_all(repo: pathlib.Path) -> dict:
    """Regenerate all 12 fixtures; return {relpath: regenerated bytes}.
    Structural failures raise FixtureProvenanceError naming the path."""
    outputs = {}
    for out_dir, name_prefix, bits, count in FIXTURE_SETS:
        template_rel = f"{out_dir}/{name_prefix}_000001.DNG"
        template = (repo / template_rel).read_bytes()
        for frame in range(1, count + 1):
            name = f"{name_prefix}_{frame:06}.DNG"
            rel = f"{out_dir}/{name}"
            _before, after, _facts = regenerate(template, name, bits, frame)
            outputs[rel] = after
    return outputs


def verify(repo: pathlib.Path) -> int:
    """The gate entrypoint: read-only against the tree. Authenticate all
    12 committed fixtures against the manifest, regenerate all 12 into a
    temp dir, byte-compare each against the committed file."""
    manifest = load_manifest(repo)
    authenticate(repo, manifest)
    tmp = tempfile.mkdtemp(prefix="fixture-provenance-")
    try:
        outputs = regenerate_all(repo)
        mismatches = []
        for rel in sorted(outputs):
            regenerated = outputs[rel]
            committed = (repo / rel).read_bytes()
            if regenerated != committed:
                mismatches.append(rel)
        for rel in mismatches:
            print(f"fixture provenance FAIL: regenerated bytes differ from "
                  f"committed: {rel}", file=sys.stderr)
        if mismatches:
            return 1
        print(f"fixture provenance: {TOTAL_FIXTURES}/{TOTAL_FIXTURES} "
              f"regenerated byte-identical")
        return 0
    finally:
        shutil.rmtree(tmp)


def generate(repo: pathlib.Path, out: pathlib.Path, manifest_out: pathlib.Path) -> None:
    """The scratch generation mode (parity with the reference): write all
    12 fixtures + a JSON manifest into a fresh, nonexistent scratch dir."""
    manifest = load_manifest(repo)
    authenticate(repo, manifest)
    if out.exists():
        raise FileExistsError(f"refusing to replace existing output: {out}")
    if manifest_out.exists():
        raise FileExistsError(
            f"refusing to replace existing manifest: {manifest_out}")
    out.mkdir(parents=True)
    files = []
    for out_dir, name_prefix, bits, count in FIXTURE_SETS:
        template_rel = f"{out_dir}/{name_prefix}_000001.DNG"
        template = (repo / template_rel).read_bytes()
        for frame in range(1, count + 1):
            name = f"{name_prefix}_{frame:06}.DNG"
            rel = f"{out_dir}/{name}"
            before, after, facts = regenerate(template, name, bits, frame)
            destination = out / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(after)
            destination.chmod(0o644)
            files.append({
                "template": template_rel,
                "template_sha256": manifest[template_rel],
                "output": rel,
                "before_sha256": sha256(before), "after_sha256": sha256(after),
                "before_bytes": len(before), "after_bytes": len(after),
                "mode": "100644", **facts,
            })
            print(f"generated {rel} ({len(after)} bytes)")
    payload = {"schema": 1, "generator": "generate_fixtures.py",
               "mode": "self-template (the tree's own committed fixtures)",
               "fixed_identity": {"datetime": DATE,
                                  "serial": SERIAL_REPLACEMENT.decode(),
                                  "software": SOFTWARE},
               "files": files}
    manifest_out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {manifest_out} ({len(files)} fixtures)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="the committed fixtures' provenance authority "
                    "(deterministic regeneration + byte-comparison)")
    parser.add_argument("--repo", type=pathlib.Path, default=None,
                        help="repo root (default: this script's grandparent, "
                             "resolved from its location)")
    parser.add_argument("--verify", action="store_true",
                        help="read-only gate mode: authenticate + regenerate "
                             "+ byte-compare all 12 (exit 0/1)")
    parser.add_argument("--out", type=pathlib.Path, default=None,
                        help="scratch generation mode: fresh, nonexistent "
                             "output directory (parity mode)")
    parser.add_argument("--manifest", type=pathlib.Path, default=None,
                        help="scratch manifest path (default: "
                             "<out> fixtures-manifest.json, generation mode)")
    args = parser.parse_args()
    repo = (args.repo.resolve() if args.repo else
            pathlib.Path(__file__).resolve().parents[2])
    if not (repo / "ci").is_dir():
        print(f"fixture provenance: repo root not recognized: {repo} "
              f"(no ci/ dir)", file=sys.stderr)
        return 2
    try:
        if args.verify:
            if args.out is not None:
                print("fixture provenance: --verify and --out are mutually "
                      "exclusive", file=sys.stderr)
                return 2
            return verify(repo)
        if args.out is None:
            parser.print_usage(sys.stderr)
            print("fixture provenance: nothing to do (use --verify or --out)",
                  file=sys.stderr)
            return 2
        out = args.out.resolve()
        manifest_out = (args.manifest.resolve() if args.manifest else
                        out.with_name(out.name + "-fixtures-manifest.json"))
        generate(repo, out, manifest_out)
        return 0
    except FixtureProvenanceError as exc:
        print(f"fixture provenance FAIL: {exc}", file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        print(f"fixture provenance FAIL: structural error: {exc}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
