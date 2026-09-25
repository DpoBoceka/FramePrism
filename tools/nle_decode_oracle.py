#!/usr/bin/env python3
"""NLE decode oracle (sequence protocol).

Imports a 225-frame DNG folder as a sequence clip (MediaStorage — the UI
behavior), relinks, builds a UNIQUE timeline, seeks through frames
{1 (burst x3), 60, 113, 165, 225}, then parses the ResolveDebug.txt TAIL
for decode failures whose path is inside the probe folder. Cleans up
timeline + clip afterwards.

Usage: nle_decode_oracle.py <folder> <label>
Prints one JSON line: {..., "decode_failures": N, "verdict": "PASS"/"FAIL"}
Exit 0 iff decode_failures == 0.
Counts ANY frame-read / frame-info / header-read failure for the folder's
files (all BMD error strings — the single-`Failed to decode the video
frame` pattern missed the 34892 "Feature is not implemented" failure
class; oracle11 false negative).

Protocol notes:
- AddItemListToMediaPool with the FOLDER = proper 225-frame sequence clip.
- The clip may sit "OFFLINE - <path>" after import: RelinkClips + settle.
- Delete old oracle-* timelines first (CreateTimelineFromClips fails on
  name collisions).
- **The log marker is taken BEFORE the import (oracle11b fix)**:
  the decisive failure for an unsupported format (e.g. 34892/LinearRaw)
  happens at IMPORT time — `Failed to get frame information from video
  frame <...>, error: <Feature is not implemented.>` — and a clip that
  probes Offline logs NOTHING on timeline seeks. A marker after the
  import (oracle9/10/11 protocol) therefore reports 0 failures for
  exactly the files the UI shows as Media Offline (the oracle11 false
  negative). The per-folder path filter keeps foreign lines out.
- Pool-side thumbnail failures (f1/f145/f218) can bleed into the same
  log lines; the per-frame breakdown in the output distinguishes them
  (pool thumbs hit exactly f1/f145/f218 and appear right after import).
"""
import DaVinciResolveScript as dvr
import json
import os
import re
import sys
import time

LOG = os.path.expanduser(
    "~/Library/Application Support/Blackmagic Design/DaVinci Resolve/Logs/ResolveDebug.txt"
)
PROJ = "frameprism-offline-probe"
FPS = 24  # A001 FrameRate 24000/1000


def log_tail(marker: int) -> str:
    try:
        with open(LOG, "rb") as f:
            f.seek(marker)
            return f.read().decode("utf-8", "replace")
    except FileNotFoundError:
        return ""


def tc(frame: int) -> str:
    t = frame - 1
    return f"01:00:{t // FPS:02d}:{t % FPS:02d}"


def main(folder: str, label: str) -> int:
    folder = os.path.abspath(folder)
    t0 = time.time()
    RESOLVE = dvr.scriptapp("Resolve")
    pm = RESOLVE.GetProjectManager()
    proj = pm.LoadProject(PROJ) or pm.CreateProject(PROJ)
    mp = proj.GetMediaPool()
    ms = RESOLVE.GetMediaStorage()
    out = {"label": label, "folder": folder}

    # Delete old oracle-* timelines (name-collision pitfall).
    try:
        for tl in mp.GetTimelineList() or []:
            if tl.GetName().startswith("oracle-"):
                mp.DeleteTimelines([tl])
        time.sleep(1.0)
    except Exception as e:  # noqa: BLE001
        out["timeline_cleanup_err"] = str(e)

    # MARKER BEFORE THE IMPORT (oracle11b fix): the import-time probe is
    # the decisive signal for unsupported formats — an import that probes
    # Offline logs no per-frame errors on later seeks.
    marker = os.path.getsize(LOG)

    items = ms.AddItemListToMediaPool([{"media": folder}])
    out["import_ok"] = bool(items)
    if not items:
        print(json.dumps(out, default=str))
        return 1
    it = items[0]
    time.sleep(6.0)  # import + metadata settle
    p = it.GetClipProperty() or {}
    out.update(clip=p.get("File Name"), frames=p.get("Frames"), online=p.get("Online Status"))
    if out.get("online") != "Online":
        try:
            mp.RelinkClips([it], None)
            time.sleep(5.0)
            p = it.GetClipProperty() or {}
            out["online_after_relink"] = p.get("Online Status")
        except Exception as e:  # noqa: BLE001
            out["relink_err"] = str(e)

    tl = mp.CreateTimelineFromClips(f"oracle-{label}", [{"mediaPoolItem": it}])
    out["timeline_ok"] = bool(tl)
    if not tl:
        print(json.dumps(out, default=str))
        return 1
    proj.SetCurrentTimeline(tl)
    time.sleep(2.0)

    for s in (1, 1, 1, 60, 113, 165, 225):  # opening burst + spread
        tl.SetCurrentTimecode(tc(s))
        time.sleep(4.0)
    time.sleep(2.0)  # let the log flush

    tail = log_tail(marker)
 # Oracle bugfix (oracle11 false negative): the original
    # pattern matched only `error: <Failed to decode the video frame.>`
    # (the lossless-family failure string). BMD fails UNSUPPORTED formats
    # (e.g. 34892/LinearRaw) with a DIFFERENT string — `error: <Feature is
    # not implemented.>` — on the same "Failed to read frame frame" / "Failed
    # to get frame information" lines. Count any frame-read / frame-info /
    # header-read failure whose path is inside the probe folder, and keep
    # the error strings for the record.
    pat_read = re.compile(
        r"(?:Failed to read frame frame from video frame"
        r"|Failed to get frame information from video frame"
        r") <([^>]+)>, error: <([^>]*)>"
    )
    pat_header = re.compile(
        r"Failed to read header of file '([^']+)'"
    )
    fails = {}
    err_strings = {}
    for m in pat_read.finditer(tail):
        if folder.rstrip("/") in m.group(1):
            base = os.path.basename(m.group(1))
            fails[base] = fails.get(base, 0) + 1
            err_strings[m.group(2)] = err_strings.get(m.group(2), 0) + 1
    for m in pat_header.finditer(tail):
        if folder.rstrip("/") in m.group(1):
            base = os.path.basename(m.group(1))
            fails["hdr:" + base] = fails.get("hdr:" + base, 0) + 1
    total = sum(fails.values())
    out["decode_failures"] = total
    out["decode_fail_frames"] = fails
    out["decode_fail_error_strings"] = err_strings
    out["verdict"] = "PASS" if total == 0 else "FAIL"

    try:
        mp.DeleteTimelines([tl])
    except Exception:
        pass
    try:
        mp.UnlinkClips([it])
    except Exception:
        pass
    out["elapsed"] = round(time.time() - t0, 1)
    print(json.dumps(out, default=str))
    return 0 if total == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: resolve_decode_oracle.py <folder> <label>")
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))