#!/usr/bin/env python3
"""Offline sample HTTP indicator validation (not a WAF rules engine)."""
import json
from pathlib import Path

INDICATORS = {
    "upload_progress": "php_session_upload_progress",
    "session_in_form": 'name="phpsessid"',
    "php_filename": 'filename="<?php',
    "session_path": "/sess_",
}

def validate(fixtures):
    report = {name: {"tp": 0, "tn": 0, "fp": 0, "fn": 0} for name in INDICATORS}
    for item in fixtures:
        if not isinstance(item.get("request"), str) or not isinstance(item.get("expected"), dict):
            raise ValueError("Invalid fixture")
        request = item["request"].lower()
        for name, marker in INDICATORS.items():
            expected = item["expected"].get(name)
            if type(expected) is not bool:
                raise ValueError("Missing boolean expected label: " + name)
            actual = marker in request
            label = "tp" if actual and expected else "fp" if actual else "fn" if expected else "tn"
            report[name][label] += 1
    return report

if __name__ == "__main__":
    fixtures = json.loads((Path(__file__).parents[1] / "tests/fixtures/http.json").read_text())
    result = validate(fixtures)
    print(json.dumps({"signals": result, "note": "Only synthetic string indicators; native engine rules not executed."}, indent=2))
    if any(v["fp"] or v["fn"] for v in result.values()):
        raise SystemExit(1)
