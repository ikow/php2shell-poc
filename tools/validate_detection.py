#!/usr/bin/env python3
"""Offline HTTP indicator regression runner; never executes native IDS/WAF rules."""
import argparse
import json
import re
import sys
from pathlib import Path

INDICATORS = {
    "upload_progress": "php_session_upload_progress",
    "session_in_form": 'name="phpsessid"',
    "php_filename": 'filename="<?php',
    "session_path": "/sess_",
}
DEFAULT_FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures/http.json"
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_REQUEST_BYTES = 1024 * 1024
NOTE = "Synthetic substring indicators only; native detection rules were not executed."


def check_fixtures(fixtures):
    """Fail closed before matching: labels must be complete, explicit booleans."""
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError("Fixtures must be a non-empty JSON array")
    seen = set()
    fields = {"id", "description", "request", "malicious", "expected"}
    for index, item in enumerate(fixtures):
        context = "Fixture {}".format(index)
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError(context + ": required fields are " + ", ".join(sorted(fields)))
        for field in ("id", "description", "request"):
            if not isinstance(item[field], str) or not item[field].strip():
                raise ValueError(context + ": " + field + " must be a non-empty string")
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", item["id"]):
            raise ValueError(context + ": invalid id")
        if item["id"] in seen:
            raise ValueError(context + ": duplicate id " + item["id"])
        seen.add(item["id"])
        request = item["request"]
        if len(request.encode("utf-8")) > MAX_REQUEST_BYTES:
            raise ValueError(context + ": request exceeds 1 MiB")
        if "\r\n\r\n" not in request:
            raise ValueError(context + ": missing HTTP header/body separator")
        headers = request.split("\r\n\r\n", 1)[0].split("\r\n")
        if not re.fullmatch(r"[A-Z]+ [^\s]+ HTTP/1\.[01]", headers[0]):
            raise ValueError(context + ": invalid HTTP request line")
        if any(not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[^\r\n]*", h)
               for h in headers[1:]):
            raise ValueError(context + ": invalid HTTP header")
        expected = item["expected"]
        if type(item["malicious"]) is not bool:
            raise ValueError(context + ": malicious must be boolean")
        if not isinstance(expected, dict) or set(expected) != set(INDICATORS):
            raise ValueError(context + ": expected must label every known indicator exactly once")
        if any(type(value) is not bool for value in expected.values()):
            raise ValueError(context + ": expected labels must be booleans")


def load_fixtures(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("Fixture file exceeds 8 MiB")
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_keys)


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def outcome(actual, expected):
    return "tp" if actual and expected else "fp" if actual else "fn" if expected else "tn"


def empty_counts():
    return {key: 0 for key in ("tp", "tn", "fp", "fn")}


def metrics(counts):
    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None
    return dict(counts, precision=ratio(counts["tp"], counts["tp"] + counts["fp"]),
                recall=ratio(counts["tp"], counts["tp"] + counts["fn"]),
                false_positive_rate=ratio(counts["fp"], counts["fp"] + counts["tn"]))


def build_report(fixtures):
    check_fixtures(fixtures)
    counts = {name: empty_counts() for name in INDICATORS}
    traffic = empty_counts()
    cases = []
    for item in fixtures:
        request = item["request"].lower()
        actual = {name: marker in request for name, marker in INDICATORS.items()}
        results = {name: outcome(actual[name], item["expected"][name]) for name in INDICATORS}
        for name, result in results.items():
            counts[name][result] += 1
        classification = outcome(any(actual.values()), item["malicious"])
        traffic[classification] += 1
        cases.append({"id": item["id"], "malicious": item["malicious"],
                      "actual": actual, "expected": item["expected"],
                      "outcomes": results, "traffic_outcome": classification})
    coverage = {}
    for name, count in counts.items():
        positive = count["tp"] + count["fn"]
        negative = count["tn"] + count["fp"]
        coverage[name] = {"positive_cases": positive, "negative_cases": negative,
                          "complete": positive > 0 and negative > 0}
    return {"schema_version": 1, "backend": "synthetic-indicator", "note": NOTE,
            "native_engines": {name: "not_run" for name in ("suricata", "modsecurity", "sigma")},
            "fixture_count": len(fixtures), "signals": {n: metrics(c) for n, c in counts.items()},
            "traffic": metrics(traffic), "coverage": coverage,
            "coverage_ratio": sum(c["complete"] for c in coverage.values()) / len(INDICATORS),
            "cases": cases,
            "passed": not any(c["fp"] or c["fn"] for c in counts.values())
                      and not traffic["fp"] and not traffic["fn"]}


def validate(fixtures):
    """Retain the starter's per-indicator count return shape."""
    report = build_report(fixtures)
    return {name: {key: values[key] for key in empty_counts()}
            for name, values in report["signals"].items()}


def render_markdown(report):
    lines = ["# Detection validation report", "", report["note"], "",
             "Backend: `synthetic-indicator`. Native engines: **not run**.", "",
             "Fixtures: {}. Result: **{}**. Indicator coverage: {:.0%}.".format(
                 report["fixture_count"], "PASS" if report["passed"] else "FAIL", report["coverage_ratio"]),
             "", "| Scope | TP | TN | FP | FN |", "| --- | ---: | ---: | ---: | ---: |"]
    for name, counts in list(report["signals"].items()) + [("Traffic (any indicator)", report["traffic"])]:
        lines.append("| {} | {} | {} | {} | {} |".format(
            name, counts["tp"], counts["tn"], counts["fp"], counts["fn"]))
    lines.extend(["", "## Indicator coverage", "",
                  "| Indicator | Positive cases | Negative cases | Complete |",
                  "| --- | ---: | ---: | --- |"])
    for name, coverage in report["coverage"].items():
        lines.append("| {} | {} | {} | {} |".format(
            name, coverage["positive_cases"], coverage["negative_cases"], coverage["complete"]))
    failures = [case for case in report["cases"]
                if case["traffic_outcome"] in ("fp", "fn")
                or any(value in ("fp", "fn") for value in case["outcomes"].values())]
    lines.extend(["", "## Failing fixtures", ""])
    lines.extend("- `{}`: traffic {}; signals {}".format(
        c["id"], c["traffic_outcome"], ", ".join(n + "=" + v for n, v in c["outcomes"].items()))
                 for c in failures)
    if not failures:
        lines.append("None.")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", type=Path, help="Write report to an existing directory")
    parser.add_argument("--require-coverage", action="store_true",
                        help="Fail unless every indicator has positive and negative cases")
    args = parser.parse_args(argv)
    try:
        if args.output and args.output.resolve() == args.fixtures.resolve():
            raise ValueError("Output must not overwrite fixture input")
        report = build_report(load_fixtures(args.fixtures))
        if args.require_coverage and report["coverage_ratio"] < 1:
            report["passed"] = False
        rendered = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
                    if args.format == "json" else render_markdown(report))
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0 if report["passed"] else 1
    except (OSError, ValueError, RecursionError) as error:
        print("validation error: {}".format(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
