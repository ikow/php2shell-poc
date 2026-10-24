#!/usr/bin/env python3
"""
OOM reachability estimator for php2shell (CVE-2026-109618 / CVE-2026-109619).

Answers one question before anyone sends a destructive OOM probe: can a
multipart body even exhaust `memory_limit` on this configuration?

Model
-----
During multipart parsing PHP keeps more than one live copy of each field
value. In calibrated lab payloads the steady-state footprint of the request
is approximately:

    footprint ~= 2 * body_size + 1 MiB

where 1 MiB is a conservative floor for the request, the session and the
script. The model is empirical: it was fitted on the calibration points
below and it is a planning aid, not a guarantee.

Calibration points (PHP 8.4.26, one worker, multipart OOM payload):

    memory_limit  post_max_size  body     measured result
    8M            64M            3.7M     OOM (8/8, display_errors=On)
    32M           8M             3.7M     no OOM
    128M          8M             3.7M     no OOM
    512M          512M           12M      no OOM
    512M          512M           480M     OOM

Consequence for stock configurations: with the PHP defaults
(`memory_limit=128M`, `post_max_size=8M`) the largest body a client can
submit is 8 MiB, so the reachable footprint is ~17 MiB, far below 128 MiB.
The OOM primitive that starts the public chains is not reachable without a
configuration change.

Offline: this module sends no traffic. It is used by `check.py` (tiers 3.5
and 4) and can be run standalone:

    python3 scanner/oom_reach.py -m 128M -p 8M

Author: JoshRob (contribution; see PR description)
"""

from __future__ import annotations

import argparse
import json
import sys

MIB = 1024 * 1024
OVERHEAD = 1 * MIB
COPIES = 2

VERDICT_REACHABLE = "REACHABLE"
VERDICT_BORDERLINE = "BORDERLINE"
VERDICT_UNREACHABLE = "UNREACHABLE"


def parse_size(text) -> int:
    """Parse PHP-style sizes: 128M, 8M, 512K, 1G, 1048576, 3.7M."""
    if isinstance(text, int):
        if text < 0:
            raise ValueError("negative size")
        return text
    s = str(text).strip().upper().replace(" ", "")
    factors = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
    if s and s[-1] in factors:
        number, factor = s[:-1], factors[s[-1]]
    else:
        number, factor = s, 1
    value = float(number) * factor
    if value < 0:
        raise ValueError("negative size")
    return int(value)


def fmt(size: int) -> str:
    if size >= 1024 ** 3 and size % (1024 ** 3) == 0:
        return f"{size // (1024 ** 3)}G"
    if size >= MIB:
        return f"{size / MIB:.1f}M".replace(".0M", "M")
    if size >= 1024:
        return f"{size // 1024}K"
    return f"{size}B"


def estimate(memory_limit: int, post_max_size: int,
             body_size: int | None = None,
             upload_max_filesize: int | None = None) -> dict:
    """Estimate whether a multipart body can exhaust memory_limit."""
    cap = post_max_size
    if upload_max_filesize is not None:
        cap = min(cap, upload_max_filesize)
    if body_size is None:
        body = cap
    else:
        body = min(body_size, cap)
    footprint = COPIES * body + OVERHEAD

    if footprint > 1.25 * memory_limit:
        verdict = VERDICT_REACHABLE
    elif footprint > 0.90 * memory_limit:
        verdict = VERDICT_BORDERLINE
    else:
        verdict = VERDICT_UNREACHABLE

    notes = []
    if body_size is None:
        notes.append(f"assuming the full body cap ({fmt(post_max_size)})")
    elif body_size > cap:
        notes.append(f"requested body {fmt(body_size)} exceeds the cap; using {fmt(cap)}")
    if upload_max_filesize is not None and upload_max_filesize < post_max_size:
        notes.append("upload_max_filesize binds the file part; plain fields use post_max_size")
    if verdict == VERDICT_UNREACHABLE:
        notes.append("OOM-driven chains cannot start here; request-level chains are not covered")
    if verdict == VERDICT_BORDERLINE:
        notes.append("borderline: the calibration point at this ratio aborted 8/8, "
                     "but variance is high; confirm only in a disposable replica")

    return {
        "memory_limit": memory_limit,
        "post_max_size": post_max_size,
        "upload_max_filesize": upload_max_filesize,
        "body_used": body,
        "body_cap": cap,
        "model": f"footprint = {COPIES} * body + {fmt(OVERHEAD)}",
        "footprint": footprint,
        "footprint_h": fmt(footprint),
        "memory_limit_h": fmt(memory_limit),
        "ratio": round(footprint / memory_limit, 3) if memory_limit else None,
        "verdict": verdict,
        "notes": notes,
    }


def format_estimate(result: dict) -> list[str]:
    """Human-readable lines for one estimate."""
    lines = [
        f"memory_limit        {result['memory_limit_h']}",
        f"post_max_size       {fmt(result['post_max_size'])}",
    ]
    if result.get("upload_max_filesize") is not None:
        lines.append(f"upload_max_filesize {fmt(result['upload_max_filesize'])}")
    lines.append(f"body used           {fmt(result['body_used'])} (cap {fmt(result['body_cap'])})")
    lines.append(f"model               {result['model']}")
    lines.append(f"footprint           {result['footprint_h']} ({result['ratio']} x memory_limit)")
    lines.append(f"verdict             {result['verdict']}")
    for note in result["notes"]:
        lines.append(f"note                {note}")
    return lines


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Estimate whether a multipart body can exhaust memory_limit "
                    "(offline; sends no traffic).",
    )
    ap.add_argument("-m", "--memory-limit", default=None,
                    help="PHP memory_limit, e.g. 128M (default: 128M)")
    ap.add_argument("--post-max-size", default=None,
                    help="PHP post_max_size, e.g. 8M (default: 8M)")
    ap.add_argument("--upload-max-filesize", default=None,
                    help="PHP upload_max_filesize, e.g. 2M (optional)")
    ap.add_argument("-b", "--body-size", default=None,
                    help="body an attacker can/will send (default: the cap)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    try:
        memory_limit = parse_size(args.memory_limit) if args.memory_limit else 128 * MIB
        post_max_size = parse_size(args.post_max_size) if args.post_max_size else 8 * MIB
        upload = parse_size(args.upload_max_filesize) if args.upload_max_filesize else None
        body = parse_size(args.body_size) if args.body_size else None
    except ValueError as exc:
        ap.error(f"invalid size: {exc}")
        return 3
    if memory_limit == 0:
        ap.error("memory_limit must be > 0")
        return 3

    result = estimate(memory_limit, post_max_size, body, upload)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for line in format_estimate(result):
            print(line)
    return {"REACHABLE": 0, "UNREACHABLE": 1, "BORDERLINE": 2}[result["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
