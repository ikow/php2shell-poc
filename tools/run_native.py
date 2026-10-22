#!/usr/bin/env python3
"""Run the validation image with bounded resources and no network or host writes outside artifacts."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "php2shell-validation:local"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build",
        action="store_true",
        help="Build the pinned image first (requires network)",
    )
    parser.add_argument(
        "--tests",
        action="store_true",
        help="Run all tests, including native integration tests",
    )
    args, forwarded = parser.parse_known_args(argv)
    if args.tests and forwarded:
        parser.error("--tests does not accept validator arguments")
    name = "p2s-validation-" + uuid.uuid4().hex
    started = False
    try:
        if args.build:
            subprocess.run(
                [
                    "docker",
                    "build",
                    "-f",
                    str(ROOT / "tools/native/Dockerfile"),
                    "-t",
                    IMAGE,
                    str(ROOT),
                ],
                check=True,
                timeout=600,
            )
        directory = ROOT / "artifacts"
        directory.mkdir(exist_ok=True)
        cmd = [
            "docker",
            "run",
            "--name",
            name,
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=128",
            "--memory=512m",
            "--cpus=2",
            "--user={}:{}".format(os.getuid(), os.getgid()),
            "--tmpfs=/tmp:rw,noexec,nosuid,size=128m",
            "--mount=type=bind,src={},dst=/work,readonly".format(ROOT),
            "--mount=type=bind,src={},dst=/reports".format(directory),
        ]
        if args.tests:
            cmd += [
                "-e",
                "P2S_NATIVE=1",
                "--entrypoint",
                "python",
                IMAGE,
                "-B",
                "-m",
                "unittest",
                "discover",
                "-v",
            ]
        else:
            cmd += [IMAGE, "--output-dir", "/reports/native"] + forwarded
        started = True
        return subprocess.run(cmd, timeout=300).returncode
    except (OSError, subprocess.SubprocessError) as error:
        print("container validation error: {}".format(error), file=sys.stderr)
        return 2
    finally:
        if started:
            # Remove only this invocation's container, including after a timeout.
            subprocess.run(
                ["docker", "rm", "-f", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
            )


if __name__ == "__main__":
    raise SystemExit(main())
