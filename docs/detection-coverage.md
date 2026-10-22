# Offline detection coverage

## Run locally

Requires Python 3.9+ and no third-party packages. Run from the repository root:

```sh
python3 -B -m unittest discover -v
python3 -B tools/validate_detection.py --require-coverage
python3 -B tools/validate_detection.py --require-coverage --format markdown
python3 -B tools/validate_detection.py --fixtures tests/fixtures/http.json --output /tmp/detection-report.json
```

The default fixture path also works from another directory. Exit status is 0
for a passing corpus, 1 for a mismatch or required coverage failure, and 2 for
invalid input or an I/O error. Output directories must already exist. JSON is
the default output format. Reports contain no request bodies or timestamps.

## Fixture contract

`tests/fixtures/http.json` is a non-empty JSON array. Each item has exactly:

- `id`: unique ASCII identifier, 1–80 letters, digits, dots, underscores or hyphens.
- `description`: non-empty synthetic description.
- `request`: HTTP/1.0 or HTTP/1.1 request string with CRLF headers and a blank
  line separating headers and body. Validation checks the envelope only, not
  full HTTP framing, multipart structure or content length.
- `malicious`: independent boolean traffic ground truth. Here this means a
  synthetic suspicious scenario, not a working exploit or proof of compromise.
- `expected`: explicit boolean desired alarm for **each** of `upload_progress`,
  `session_in_form`, `php_filename`, and `session_path`.

Missing/unknown fields, duplicate IDs or JSON keys, numeric boolean substitutes,
invalid envelopes, requests over 1 MiB, and files over 8 MiB are rejected before
evaluation. Keep labels manually reviewed and independent of matcher output.
Use only synthetic metadata and requests: these limits are not a redaction tool.

## Measurement semantics

The existing four case-insensitive substring checks are retained. `validate()`
returns the original per-indicator TP/TN/FP/FN count shape; fixtures now require
the stricter contract above. `build_report()` adds metrics and individual results.

For each indicator, TP is expected=true/actual=true, FP is expected=false/actual=true,
FN is expected=true/actual=false, and TN is expected=false/actual=false.
Traffic metrics compare **any** indicator firing against `malicious`. A request
matching several indicators counts once in traffic metrics. Indicator expectations
and traffic ground truth remain independent, so correctly recognizing a marker
in legitimate traffic still records a traffic FP. Either kind of FP/FN fails CI.

Precision = TP/(TP+FP), recall = TP/(TP+FN), and false-positive rate = FP/(FP+TN).
Undefined ratios are JSON null. Coverage is the fraction of the four indicators
having at least one expected-positive and one expected-negative fixture, regardless
of correctness. It is **not** native rule or attack-chain coverage. The default
corpus has 12 examples: six suspicious and six benign. All four indicators have
positive and negative examples. This tiny corpus cannot estimate production FPR.

Tests separately introduce a benign marker collision and an encoded path miss,
asserting FP/FN counts and failure behavior. These limitations are deliberately
retained rather than hidden by relabeling fixtures or suppressing failures.

## Indicator matrix and source references

| Indicator | Positive fixtures | Benign regression examples | Related source rules (not executed) |
| --- | --- | --- | --- |
| upload_progress | progress-marker, mixed-case-progress, combined-markers | ordinary-upload, near-markers | Suricata 2026100; ModSecurity 9900100; Sigma suffix 001 |
| session_in_form | session-field, combined-markers | session-cookie, near-markers | Suricata 2026101; ModSecurity 9900101 |
| php_filename | filename-marker | ordinary-upload, near-markers | Suricata 2026102; ModSecurity 9900102 |
| session_path | session-path | home, login, json-api | Suricata 2026106 |

Every benign fixture is checked against every indicator. These source references
express conceptual relationships only. For example, the filename matcher only
recognizes `filename="<?php` while native rules use different constraints and
parsing. Substrings in unrelated headers/bodies can trigger alarms, and encoding,
whitespace and alternate quoting can evade them. No native rule syntax is linted.

## Native rule inventory: all untested

| Source | Rule IDs | Required future evidence |
| --- | --- | --- |
| Suricata request | 2026100–2026106 | Native rule load, TCP/HTTP parsing, positive/negative PCAPs |
| Suricata response | 2026110–2026112 | HTTP responses and native EVE alerts |
| Suricata recon/inventory | 2026115, 2026116 | Threshold/time series and response headers |
| ModSecurity request | 9900100–9900103, 9900106 | Parsed transactions, configuration, audit logs and actions |
| ModSecurity response | 9900104, 9900105 | Enabled response inspection and phase-4 logs |
| Sigma | IDs ending php2shell001–php2shell005 | Schema validation, backend conversion, web/process/file/application log fixtures |
| OpenResty | check() checks 1–3 | Isolated nginx/OpenResty runtime and request handling |

There are 12 Suricata `alert` declarations in the source despite README wording
of 13. Sigma identifiers and unused selections need native schema/conversion
review. Source rules remain unchanged for a separate, evidence-backed P1 review.

## Deferred work

Native engines and isolated Docker tests (P1), SARIF and native per-rule coverage
(P2), PCAP import/replay, response fixtures, PHP version comparisons, and OWASP CRS
integration are pending. GitHub Actions runs the offline suite on Python 3.9,
3.11 and 3.13 and uploads reports; a remote CI run is not implied by local tests.
