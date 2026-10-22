# P0 local validation results

Validated on Python 3.9.6 on the feature branch
`feat/detection-validation-framework`.

## Baseline

- Initial unittest discovery: zero tests.
- Initial validator: FileNotFoundError because tests/fixtures/http.json was absent.
- Existing exploit and PoC scripts were inspected, not executed.

## Final checks

| Check | Result |
| --- | --- |
| `python3 -B -m unittest discover -v` | 11 tests passed |
| Default validator with `--require-coverage` | Exit 0 |
| JSON and Markdown report generation | Both succeeded |
| Independent traffic confusion matrix | TP 6, TN 6, FP 0, FN 0 |
| Indicator positive/negative coverage | 4 of 4 (100%) |
| Injected benign collision and encoded miss | Correct FP/FN counts and failing status asserted |
| Malformed input / missing file / duplicate labels | Rejected with exit 2 where applicable |
| Incomplete corpus with coverage gate | Exit 1 asserted |
| Deterministic output / arbitrary working directory | Passed |
| Python source compilation (in memory) | tools, tests, poc and exploit passed |
| `git diff --check` | Passed |
| Changes to exploit, poc, lab or detection sources | None |

The tests cover schema validation, strict booleans, duplicate JSON keys, request
and file size limits, all four confusion outcomes, null metric denominators,
traffic labels independent of indicator expectations, output-file behavior,
input overwrite prevention, and subprocess CLI behavior.

Generated local reports: `/private/tmp/php2shell-detection-report.json` and
`/private/tmp/php2shell-detection-report.md`. Reports can be regenerated with the
commands in [coverage documentation](../detection-coverage.md).

## Unverified and deferred

GitHub Actions is configured but has not been run remotely. Python 3.11 and 3.13
are CI targets, not locally verified runtimes. Native Suricata, ModSecurity,
Sigma and OpenResty execution, native rule linting, Docker isolation, PCAP input,
PHP version matrix, CRS integration and SARIF remain pending. No live target
requests or exploit execution were performed.

These results establish the offline framework's behavior on synthetic fixtures.
They do not establish native rule accuracy, vulnerability status, or production
false-positive rates.
