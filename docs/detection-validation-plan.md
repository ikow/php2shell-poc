# Detection Validation Framework — implementation plan

## Goal
Add an offline, deterministic, non-exploit regression suite for PHP2Shell detection rules. Validate malicious-looking fixtures and benign traffic without targeting third-party services. Preserve the existing proof-of-concept as a separate, opt-in lab.

## Current repository baseline
- `detection/`: Suricata/Snort, Sigma, ModSecurity and OpenResty rules.
- `poc/`: verification scripts for PHP session and FPM behavior.
- `exploit/`: separate exploit research scripts.
- `lab/`: containerized reproduction environment.

## Scope (first iteration)
1. Establish `tests/fixtures/http/` with redacted, non-executable, synthetic request samples and expected labels.
2. Build `tools/validate_detection.py` to validate fixture schema and summarize rule coverage. Never issue network requests.
3. Add a small unittest suite validating positive, negative, malformed and ambiguous samples.
4. Add GitHub Actions workflow for Python unit tests and static linting of detection files.
5. Write `docs/detection-coverage.md` mapping every rule to its fixture(s), limitations, and expected outcome.
6. Generate a machine-readable JSON report containing per-rule detections, false positives, false negatives and total coverage. CI must fail on regression.
7. Document that static matching is not a substitute for running Suricata/ModSecurity against representative HTTP transactions; add optional integration tests later.

## Acceptance criteria
- Fully offline CI; no live exploit execution.
- Deterministic tests (same fixtures => same report).
- Explicit detection and legitimate-traffic fixtures for each high-priority rule.
- No real credentials, tokens, domain targets or executable payloads in fixtures.
- Report counts are reproducible and unit-tested.
- No changes to existing exploit behavior.

## Next milestones
- M2: Use isolated Docker-backed tests to validate native engine behavior.
- M3: PCAP/HTTP transcript import with privacy redaction and safe replay in an isolated network.
- M4: JSON/SARIF artifacts and per-rule regression charts.

## Contribution strategy
Make changes on a feature branch and open a draft pull request. Offer the detection validation feature upstream when it passes CI, with clearly documented limitations.
