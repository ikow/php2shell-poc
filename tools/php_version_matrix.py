#!/usr/bin/env python3
"""Compare benign PHP session/configuration behavior in networkless containers."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXED_PATCHES = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
ADVISORIES = [
    "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
]
PROBE = r"""
$keys = ['session.upload_progress.enabled', 'session.use_only_cookies',
         'session.serialize_handler', 'memory_limit', 'post_max_size'];
$config = [];
foreach ($keys as $key) { $config[$key] = ini_get($key); }
if (!session_start()) { exit(2); }
$_SESSION = ['sample' => 'value'];
$encoded = session_encode();
$_SESSION = [];
$ok = session_decode($encoded) && $_SESSION === ['sample' => 'value'];
session_destroy();
echo json_encode(['version' => PHP_VERSION, 'sapi' => PHP_SAPI,
  'configuration' => $config, 'encoded' => $encoded, 'roundtrip' => $ok]);
"""


def advisory_status(version):
    """Version-only classification from PHP advisories reviewed on 2026-10-22."""
    match = re.fullmatch(r"(8\.[2345])\.([0-9]+)", version)
    if not match:
        return "unknown"
    return (
        "below_advisory_fix"
        if int(match[2]) < FIXED_PATCHES[match[1]]
        else "at_or_above_advisory_fix"
    )


def run_matrix(images, versions=None):
    observations = []
    selected = [
        key
        for key in images
        if versions is None
        or any(key == version or key.startswith(version + ".") for version in versions)
    ]
    if not selected:
        raise ValueError("No PHP versions selected")
    for minor in selected:
        if minor not in images or not re.fullmatch(
            r"php:[A-Za-z0-9.-]+@sha256:[a-f0-9]{64}", images[minor]
        ):
            raise ValueError("Expected a known, digest-pinned official PHP image")
        for handler in ("php", "php_serialize"):
            for enabled in (True, False):
                cmd = [
                    "docker",
                    "run",
                    "--rm",
                    "--pull=never",
                    "--network=none",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--user=65532:65532",
                    "--pids-limit=32",
                    "--memory=96m",
                    "--cpus=1",
                    "--tmpfs=/tmp:rw,noexec,nosuid,size=8m",
                    images[minor],
                    "php",
                    "-n",
                    "-d",
                    "session.save_path=/tmp",
                    "-d",
                    "memory_limit=32M",
                    "-d",
                    "session.serialize_handler=" + handler,
                    "-d",
                    "session.upload_progress.enabled=" + ("1" if enabled else "0"),
                    "-r",
                    PROBE,
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode:
                    raise RuntimeError(
                        "PHP probe failed for {}: {}".format(
                            minor, result.stderr[-1000:]
                        )
                    )
                observed = json.loads(result.stdout)
                observed.update(
                    image=images[minor],
                    requested_minor=minor,
                    handler=handler,
                    upload_progress_enabled=enabled,
                    vulnerability_status="not_assessed",
                    advisory_version_status=advisory_status(observed["version"]),
                )
                config = observed["configuration"]
                version_matches = (
                    observed["version"] == minor
                    if minor.count(".") == 2
                    else observed["version"].startswith(minor + ".")
                )
                observed["passed"] = (
                    version_matches
                    and observed["sapi"] == "cli"
                    and observed["roundtrip"] is True
                    and config["session.serialize_handler"] == handler
                    and config["session.upload_progress.enabled"]
                    == ("1" if enabled else "0")
                )
                observations.append(observed)
    return {
        "schema_version": 1,
        "backend": "php-cli-configuration",
        "note": "Benign CLI observations and advisory version comparison only; exploitability and web-SAPI behavior are not assessed.",
        "advisory_snapshot": {
            "reviewed": "2026-10-22",
            "sources": ADVISORIES,
            "fixed_patches": FIXED_PATCHES,
        },
        "passed": all(o["passed"] for o in observations),
        "observations": observations,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--minor", action="append", choices=("8.2", "8.3", "8.4", "8.5")
    )
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/php"))
    args = parser.parse_args(argv)
    try:
        images = json.loads((ROOT / "tools/native/php-images.json").read_text())
        report = run_matrix(images, args.minor)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "php-matrix.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n"
        )
        lines = [
            "# PHP configuration matrix",
            "",
            report["note"],
            "",
            "| PHP | Advisory version status | Handler | Upload progress | Session roundtrip | Result |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for row in report["observations"]:
            lines.append(
                "| {} | {} | {} | {} | {} | {} |".format(
                    row["version"],
                    row["advisory_version_status"],
                    row["handler"],
                    row["upload_progress_enabled"],
                    row["roundtrip"],
                    row["passed"],
                )
            )
        (args.output_dir / "php-matrix.md").write_text("\n".join(lines) + "\n")
        print(
            json.dumps(
                {
                    "passed": report["passed"],
                    "observations": len(report["observations"]),
                }
            )
        )
        return 0 if report["passed"] else 1
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("PHP matrix error: {}".format(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
