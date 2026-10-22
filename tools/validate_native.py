#!/usr/bin/env python3
"""Native, offline Suricata/ModSecurity/Sigma detection validation."""

import argparse
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile

from tools.validate_detection import INDICATORS, check_fixtures, load_fixtures
from tools.native.pcap import inspect_capture, write_capture
from tools.native.reporting import engine_report, write_reports
from tools.native.suricata import analyze, inventory, run_command

ROOT = Path(__file__).resolve().parents[1]


def load_cases(path, engine, rule_ids):
    cases = load_fixtures(path)
    if not isinstance(cases, list) or not cases or len(cases) > 1000:
        raise ValueError(
            "Native fixtures must be a non-empty array of at most 1000 cases"
        )
    seen = set()
    for item in cases:
        fields = {"id", "description", "malicious", "expected"} | (
            {"event", "logsource"}
            if engine == "sigma"
            else {"request", "response", "repeat"}
        )
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("Invalid native fixture fields")
        if (
            not isinstance(item["id"], str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", item["id"])
            or item["id"] in seen
        ):
            raise ValueError("Invalid or duplicate native fixture ID")
        seen.add(item["id"])
        if (
            type(item["malicious"]) is not bool
            or not isinstance(item["description"], str)
            or not item["description"].strip()
        ):
            raise ValueError(
                "Native fixture needs a description and independent boolean traffic label"
            )
        if engine == "sigma":
            if not isinstance(item["event"], dict) or not isinstance(
                item["logsource"], dict
            ):
                raise ValueError("Sigma event and logsource must be objects")
            if set(item["logsource"]) - {"category", "product", "service"}:
                raise ValueError("Unknown Sigma logsource field")
            if any(not isinstance(v, str) or not v for v in item["logsource"].values()):
                raise ValueError("Invalid Sigma logsource values")
            for key, value in item["event"].items():
                if (
                    not isinstance(key, str)
                    or len(key) > 200
                    or type(value) not in (str, int, float, bool, type(None))
                ):
                    raise ValueError("Sigma event fields must contain scalar values")
            expected = item["expected"]
        else:
            check_fixtures(
                [
                    {
                        "id": item["id"],
                        "description": item["description"],
                        "request": item["request"],
                        "malicious": item["malicious"],
                        "expected": dict.fromkeys(INDICATORS, False),
                    }
                ]
            )
            response = item["response"]
            if (
                not isinstance(response, str)
                or len(response.encode()) > 1024 * 1024
                or not re.match(r"HTTP/1\.[01] [1-5][0-9]{2} [^\r\n]*\r\n", response)
                or "\r\n\r\n" not in response
            ):
                raise ValueError("Invalid HTTP response fixture")
            if type(item["repeat"]) is not int or not 1 <= item["repeat"] <= 10:
                raise ValueError("repeat must be an integer between 1 and 10")
            if not isinstance(item["expected"], dict) or set(item["expected"]) != {
                "suricata",
                "modsecurity",
            }:
                raise ValueError("HTTP fixtures must label both native engines")
            expected = item["expected"][engine]
        if (
            not isinstance(expected, list)
            or any(not isinstance(rid, str) for rid in expected)
            or len(expected) != len(set(expected))
            or set(expected) - set(rule_ids)
        ):
            raise ValueError("Expected alerts must be unique, known rule IDs")
    return cases


def run_suite(engines, with_crs=False, fixtures=None, require_coverage=True):
    reports, crs_results = [], []
    for name in engines:
        if name == "suricata":
            rule_path = ROOT / "detection/php2shell.rules"
            ids = inventory(rule_path)
            cases = load_cases(
                fixtures or ROOT / "tests/fixtures/native/http.json", name, ids
            )
            analyze("/tmp/not-used.pcap", rule_path, syntax_only=True)
            version = run_command(["suricata", "-V"]).strip()
            observations = []
            for item in cases:
                with tempfile.TemporaryDirectory() as directory:
                    capture = Path(directory) / "fixture.pcap"
                    write_capture(
                        capture, item["request"], item["response"], item["repeat"]
                    )
                    inspect_capture(capture)
                    observations.append((item, analyze(capture, rule_path)))
        elif name == "modsecurity":
            from tools.native.modsecurity import ModSecurity

            rule_path = ROOT / "detection/modsecurity.conf"
            ids = re.findall(r"\bid:(\d+)", rule_path.read_text())
            if len(ids) != len(set(ids)) or not ids:
                raise ValueError("ModSecurity rules must have unique IDs")
            cases = load_cases(
                fixtures or ROOT / "tests/fixtures/native/http.json", name, ids
            )
            adapter = ModSecurity(rule_path)
            version, observations = adapter.version, []
            try:
                for item in cases:
                    observations.append(
                        (item, adapter.evaluate(item["request"], item["response"]))
                    )
            finally:
                adapter.close()
            if with_crs:
                adapter = ModSecurity(rule_path, with_crs=True)
                try:
                    for item in cases:
                        actual = adapter.evaluate(item["request"], item["response"])
                        project = sorted(set(actual) & set(ids))
                        crs_results.append(
                            {
                                "id": item["id"],
                                "custom_alerts": project,
                                "crs_alerts": sorted(set(actual) - set(ids)),
                                "passed": project == sorted(item["expected"][name]),
                            }
                        )
                finally:
                    adapter.close()
        elif name == "sigma":
            from tools.native.sigma import Sigma

            adapter = Sigma(ROOT / "detection/php2shell.yaml")
            ids = list(adapter.queries)
            cases = load_cases(
                fixtures or ROOT / "tests/fixtures/native/sigma.json", name, ids
            )
            version = adapter.version
            observations = [
                (item, adapter.evaluate(item["event"], item["logsource"]))
                for item in cases
            ]
        else:
            raise ValueError("Unknown engine: " + name)
        report = engine_report(name, version, ids, observations)
        if require_coverage and report["coverage_ratio"] < 1:
            report["passed"] = False
        reports.append(report)
    passed = all(report["passed"] for report in reports) and all(
        case["passed"] for case in crs_results
    )
    return {
        "schema_version": 1,
        "backend": "native",
        "passed": passed,
        "engines": reports,
        "coverage_required": require_coverage,
        "crs": {
            "status": "executed",
            "version": run_command(
                ["dpkg-query", "-W", "-f=${Version}", "modsecurity-crs"]
            ),
            "passed": all(c["passed"] for c in crs_results),
            "cases": crs_results,
        }
        if crs_results
        else None,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--engine", choices=("all", "suricata", "modsecurity", "sigma"), default="all"
    )
    parser.add_argument("--with-crs", action="store_true")
    parser.add_argument("--fixtures", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/native"))
    parser.add_argument("--allow-incomplete-coverage", action="store_true")
    parser.add_argument(
        "--pcap",
        type=Path,
        help="Offline Suricata analysis only; no replay onto a network",
    )
    parser.add_argument(
        "--home-net", default="192.0.2.0/24", help="Protected network for PCAP analysis"
    )
    args = parser.parse_args(argv)
    try:
        if args.pcap:
            if args.engine not in ("all", "suricata") or args.with_crs or args.fixtures:
                raise ValueError(
                    "PCAP mode only supports Suricata and no fixture/CRS options"
                )
            metadata = inspect_capture(args.pcap)
            alerts = analyze(
                args.pcap, ROOT / "detection/php2shell.rules", home_net=args.home_net
            )
            result = {
                "backend": "suricata-pcap",
                "status": "executed",
                "pcap": metadata,
                "rule_ids": alerts,
                "home_net": args.home_net,
                "ground_truth": "not_provided",
                "metrics": None,
            }
            args.output_dir.mkdir(parents=True, exist_ok=True)
            (args.output_dir / "pcap.json").write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n"
            )
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.fixtures and args.engine == "all":
            raise ValueError("Custom fixtures require an explicit engine")
        if args.with_crs and args.engine not in ("all", "modsecurity"):
            raise ValueError("--with-crs requires ModSecurity")
        engines = (
            ["suricata", "modsecurity", "sigma"]
            if args.engine == "all"
            else [args.engine]
        )
        report = run_suite(
            engines, args.with_crs, args.fixtures, not args.allow_incomplete_coverage
        )
        write_reports(report, args.output_dir)
        print(
            json.dumps(
                {
                    "passed": report["passed"],
                    "engines": [
                        {
                            "engine": r["engine"],
                            "coverage": r["coverage_ratio"],
                            "traffic": r["traffic"],
                        }
                        for r in report["engines"]
                    ],
                    "crs_passed": report["crs"]["passed"] if report["crs"] else None,
                },
                indent=2,
            )
        )
        return 0 if report["passed"] else 1
    except (
        OSError,
        ValueError,
        RuntimeError,
        sqlite3.Error,
        subprocess.SubprocessError,
        ImportError,
        RecursionError,
    ) as error:
        print("native validation error: {}".format(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
