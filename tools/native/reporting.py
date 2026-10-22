"""Native rule metrics and portable, escaped JSON/Markdown/HTML/SARIF output."""

import html
import json
from pathlib import Path

from tools.validate_detection import empty_counts, metrics, outcome


def engine_report(engine, version, rule_ids, observations):
    rules = {rid: empty_counts() for rid in sorted(rule_ids)}
    traffic = empty_counts()
    cases = []
    passed = True
    for item, actual in observations:
        expected = set(
            item["expected"][engine]
            if isinstance(item["expected"], dict)
            else item["expected"]
        )
        actual = set(actual)
        if actual - set(rules):
            raise ValueError("Engine emitted unknown project rule IDs")
        missing, unexpected = sorted(expected - actual), sorted(actual - expected)
        passed = passed and not missing and not unexpected
        for rid, counts in rules.items():
            counts[outcome(rid in actual, rid in expected)] += 1
        classification = outcome(bool(actual), item["malicious"])
        traffic[classification] += 1
        cases.append(
            {
                "id": item["id"],
                "actual": sorted(actual),
                "expected": sorted(expected),
                "missing": missing,
                "unexpected": unexpected,
                "traffic_outcome": classification,
            }
        )
    matrix = {
        rid: dict(
            metrics(counts),
            positive_cases=counts["tp"] + counts["fn"],
            negative_cases=counts["tn"] + counts["fp"],
            covered=bool(counts["tp"] + counts["fn"])
            and bool(counts["tn"] + counts["fp"]),
        )
        for rid, counts in rules.items()
    }
    return {
        "engine": engine,
        "version": version,
        "status": "executed",
        "passed": bool(passed),
        "traffic": metrics(traffic),
        "rules": matrix,
        "cases": cases,
        "coverage_ratio": sum(r["covered"] for r in matrix.values()) / len(matrix),
    }


def markdown(report):
    lines = [
        "# Native detection validation",
        "",
        "Regression result: **{}**.".format("PASS" if report["passed"] else "FAIL"),
        "",
        "Regression status compares reviewed expected rule alerts. Traffic FP/FN values",
        "compare independent malicious/benign labels and remain visible even for known limitations.",
        "",
        "| Engine | Version | Rule coverage | Traffic TP | TN | FP | FN |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for engine in report["engines"]:
        t = engine["traffic"]
        lines.append(
            "| {} | {} | {:.0%} | {} | {} | {} | {} |".format(
                engine["engine"],
                engine["version"],
                engine["coverage_ratio"],
                t["tp"],
                t["tn"],
                t["fp"],
                t["fn"],
            )
        )
    lines += [
        "",
        "## Rule coverage matrix",
        "",
        "| Engine | Rule | TP | TN | FP | FN | Positive | Negative |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for engine in report["engines"]:
        for rid, rule in engine["rules"].items():
            lines.append(
                "| {} | {} | {} | {} | {} | {} | {} | {} |".format(
                    engine["engine"],
                    rid,
                    rule["tp"],
                    rule["tn"],
                    rule["fp"],
                    rule["fn"],
                    rule["positive_cases"],
                    rule["negative_cases"],
                )
            )
    lines += ["", "## Regressions and classification errors", ""]
    for engine in report["engines"]:
        for case in engine["cases"]:
            if (
                case["missing"]
                or case["unexpected"]
                or case["traffic_outcome"] in ("fp", "fn")
            ):
                lines.append(
                    "- {} / {}: missing {}; unexpected {}; traffic {}.".format(
                        engine["engine"],
                        case["id"],
                        ", ".join(case["missing"]) or "none",
                        ", ".join(case["unexpected"]) or "none",
                        case["traffic_outcome"],
                    )
                )
    if report.get("crs"):
        lines += [
            "",
            "## OWASP CRS coexistence",
            "",
            "CRS-enabled transactions executed; custom rule alerts are validated separately.",
            "CRS rule alerts are recorded in JSON and are not labeled as custom-rule detections.",
        ]
    return "\n".join(lines) + "\n"


def sarif(report):
    rules, results = [], []
    for engine in report["engines"]:
        name = engine["engine"]
        for rid in engine["rules"]:
            rules.append(
                {
                    "id": name + "/" + rid,
                    "shortDescription": {"text": name + " rule " + rid},
                }
            )
        fixture = (
            "tests/fixtures/native/sigma.json"
            if name == "sigma"
            else "tests/fixtures/native/http.json"
        )
        for case in engine["cases"]:
            for kind, ids in (
                ("missed expected alert", case["missing"]),
                ("unexpected alert", case["unexpected"]),
            ):
                for rid in ids:
                    results.append(
                        {
                            "ruleId": name + "/" + rid,
                            "level": "error",
                            "message": {
                                "text": "{} in fixture {}".format(kind, case["id"])
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": fixture,
                                            "uriBaseId": "%SRCROOT%",
                                        }
                                    }
                                }
                            ],
                            "properties": {"fixtureId": case["id"], "engine": name},
                        }
                    )
    # Passing detections are not vulnerability findings. Known classification gaps
    # belong in metrics, not fabricated security alerts at exploit source locations.
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "php2shell-detection-validation", "rules": rules}
                },
                "results": results,
                "invocations": [{"executionSuccessful": True}],
                "properties": {"regressionPassed": report["passed"]},
            }
        ],
    }


def write_reports(report, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "native.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    )
    text = markdown(report)
    (directory / "native.md").write_text(text)
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>Detection validation</title><style>body{max-width:1100px;margin:2rem auto;font:16px system-ui}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>Detection validation</h1><pre>'
        + html.escape(text)
        + "</pre></html>"
    )
    (directory / "native.html").write_text(page)
    (directory / "native.sarif").write_text(
        json.dumps(sarif(report), indent=2, sort_keys=True) + "\n"
    )
