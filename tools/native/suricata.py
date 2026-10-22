"""Run the installed Suricata binary against files only."""

import json
import ipaddress
from pathlib import Path
import re
import subprocess
import tempfile


def run_command(argv, timeout=60):
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode:
        # Engine diagnostics are for the local operator; reports omit packet content.
        raise RuntimeError(
            "Engine command failed: {}\n{}".format(
                argv[0], (result.stderr + result.stdout)[-6000:]
            )
        )
    return result.stdout


def inventory(path):
    ids = re.findall(r"\bsid\s*:\s*(\d+)\s*;", Path(path).read_text())
    if not ids or len(ids) != len(set(ids)):
        raise ValueError("Suricata rules must have unique SIDs")
    return ids


def analyze(pcap, rules, syntax_only=False, home_net="192.0.2.0/24"):
    home_net = str(ipaddress.ip_network(home_net, strict=False))
    rules, pcap = Path(rules).resolve(), Path(pcap).resolve()
    with tempfile.TemporaryDirectory(prefix="p2s-suricata-") as directory:
        args = [
            "suricata",
            "-c",
            "/etc/suricata/suricata.yaml",
            "-S",
            str(rules),
            "-l",
            directory,
            "--set",
            "vars.address-groups.HOME_NET=[" + home_net + "]",
            "--set",
            "vars.address-groups.EXTERNAL_NET=any",
            "--set",
            "unix-command.enabled=no",
            "--set",
            "stream.checksum-validation=no",
            "--set",
            "app-layer.protocols.http.libhtp.default-config.request-body-limit=2mb",
            "--set",
            "app-layer.protocols.http.libhtp.default-config.response-body-limit=2mb",
        ]
        run_command(
            args
            + (
                ["-T"]
                if syntax_only
                else ["--runmode=single", "-k", "none", "-r", str(pcap)]
            )
        )
        alerts = []
        eve = Path(directory) / "eve.json"
        if not syntax_only:
            if not eve.exists():
                raise RuntimeError("Suricata did not produce EVE output")
            for line in eve.read_text().splitlines():
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    alerts.append(str(event["alert"]["signature_id"]))
        return sorted(set(alerts))
