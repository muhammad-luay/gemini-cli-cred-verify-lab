#!/usr/bin/env python3
"""Same-uid /proc/<pid>/environ scan (benign lab collection only).

Reads the environ of every same-uid process and prints selected key=value
lines for processes that carry the lab canary keys. Appends to out_path.
"""
import os
import sys

WATCH_KEYS = {
    "CI",
    "GEMINI_API_KEY",
    "VFY_JOB_SECRET",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_ENV",
    "GITHUB_SHA",
    "GITHUB_ACTIONS",
    "SURFACE",
    "RUNNER_TRACKING_ID",
    "GEMINI_CLI_TRUST_WORKSPACE",
    "VFY_LATE_STEP",
    "VFY_LATE_ENV",
}
NEEDLES = (b"VFY_JOB_SECRET=", b"GITHUB_TOKEN=", b"GEMINI_API_KEY=", b"VFY_LATE_STEP=")


def main(out_path):
    uid = os.getuid()
    lines = []
    for entry in sorted(os.listdir("/proc")):
        if not entry.isdigit():
            continue
        try:
            if os.stat(f"/proc/{entry}").st_uid != uid:
                continue
            with open(f"/proc/{entry}/environ", "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        if not any(needle in raw for needle in NEEDLES):
            continue
        try:
            with open(f"/proc/{entry}/comm") as fh:
                comm = fh.read().strip()
        except OSError:
            comm = "?"
        lines.append(f"-- pid={entry} comm={comm}")
        for kv in raw.split(b"\x00"):
            if not kv:
                continue
            key = kv.split(b"=", 1)[0].decode(errors="replace")
            if key in WATCH_KEYS:
                lines.append(kv.decode(errors="replace"))
    with open(out_path, "a") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
