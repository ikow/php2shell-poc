# Detection validation implementation plan

## Repository assessment

Reviewed README, technical and patch analysis, all detection formats, PoC and
exploit entry points, and lab configuration. These are research assets, not an
automated detection validation suite. Existing PoCs open sockets and the lab
starts vulnerable services; neither belongs in offline CI. The lab also uses
privileged containers and floating image tags, unsuitable for native engine CI.
Repository vulnerability and mitigation claims are inherited research context,
not independently verified by this implementation.

At review time, upstream `ikow/php2shell-poc` main and fork main both resolved to
`5baea61cbea2cfabaed3251aac68c652b164aa89`. The fork feature branch adds
`df56fe8` (plan) and `145630f` (starter validator). The exploit/PoC separation
already exists at the shared main commit; it is not a fork-specific difference.

The initial plan correctly separates offline fixtures from native engines, but
does not define fixture semantics, coverage denominators, input failures, or
regression policy. Its promise of static rule linting needs engine-specific
tooling and must not be represented by simple file-presence checks.

The starter validator has four case-insensitive substring checks and a reusable
`validate(fixtures)` function. It never loads detection rule files. Its default
fixture file is missing, so execution fails with FileNotFoundError. Initial
unittest discovery runs zero tests. Preserve the checks and function interface,
and add a tested validation/reporting layer without claiming engine execution.

## Architecture and small delivery stages

1. **P0 input contract:** JSON array of uniquely identified HTTP fixtures with a
   description, raw request, independent malicious/benign label, and explicit
   expected alarm booleans for all four indicators. Validate the entire corpus
   before evaluation. Reject empty corpora, unknown/missing keys, invalid types,
   duplicate IDs, invalid HTTP request envelopes, and oversized inputs.
2. **P0 runner:** retain the indicator backend and `validate` count interface.
   Produce per-indicator confusion counts, aggregate request-level TP/FP/FN/TN,
   precision, recall, false-positive rate, coverage, and individual outcomes.
   Per-indicator labels express desired alarms; independent traffic labels
   measure whether any alarm classifies the request correctly. Zero denominators
   yield null rather than misleading perfect scores.
3. **P0 regression and delivery:** deterministic JSON and Markdown, failure exit
   codes, unit and subprocess regression tests, fixture corpus, English usage
   documentation, and GitHub Actions across supported Python versions. Require
   positive and negative labels for every indicator in the default CI gate.
4. **P1 adapters (implemented):** native Suricata syntax and PCAP tests; ModSecurity
   transactions and native server-log callbacks; Sigma schema/conversion and representative log
   events. Use pinned, unprivileged Docker environments, internal networks,
   read-only rules, resource limits, timeouts, and no production targets. Native
   adapters must return actual engine rule IDs and execution status.
5. **P2 (implemented):** SARIF semantics, native rule
   coverage matrix, HTML, and optional GitHub code-scanning upload. Offline PCAP input, a
   benign PHP configuration/advisory-version matrix, and OWASP CRS coexistence
   tests are also implemented. See the native validation guide for exact scope.

## Dependencies and test strategy

P0 uses only Python 3.9+ standard library and unittest. It imports no exploit
code, starts no services, and opens no sockets. CI setup/artifact actions require
GitHub connectivity; validator and tests require no network or package install.
Fixtures are synthetic HTTP/1.x request envelopes, not a general HTTP parser or
wire-valid PCAP generator. No response, process, file event, chunk decoding,
URL decoding, multipart parsing, or stateful thresholds are claimed.

Test schema failures, every indicator's positive/negative cases, all four
confusion outcomes, independently labeled benign marker collisions, missed
encoded indicators, undefined metrics, deterministic reports, missing/corrupt
input, CLI exit codes, coverage gates, and running outside repository cwd.
Do not execute existing PoCs or mutate exploit or lab files. Native engine
failures may justify narrowly scoped detection-rule fixes with regression evidence.

## Risks and acceptance criteria

Synthetic indicator coverage does not establish engine accuracy or real-world
exploit coverage. Report the backend and native engine status explicitly. Map
indicators to related source rule IDs only as references, never as verified
coverage. Small balanced fixtures are regression examples, not representative
production false-positive estimates. Never include raw requests in reports;
fixture metadata must also be synthetic and non-sensitive.

P0 is accepted when the bundled corpus passes, each indicator has positive and
negative examples, all unit/CLI regression tests pass locally, reports are
deterministic, malformed input exits 2 without a traceback, regression or
required coverage failure exits 1, and no network/exploit execution occurs.
CI workflow execution on GitHub remains unverified until an actual remote run.
Native engine validation, SARIF, response fixtures and Docker integration were
subsequently implemented and tested. See [native validation](../native-validation.md)
and [validation results](validation-results.md). Full web-SAPI exploitability
validation and universal SIEM/engine-version compatibility are not claimed.
