# Detection toolkit validation results

Branch: `feat/detection-validation-framework`.

## Baseline and P0

Initial discovery found zero tests, and the starter validator failed because its
fixture file was absent. P0 introduced 11 passing tests and 12 indicator fixtures:
traffic TP 6, TN 6, FP 0, FN 0, with positive/negative coverage for all four
indicators. The retained P0 runner remains standard-library-only and offline.

## Native delivery checks

| Check | Local result |
| --- | --- |
| Full suite in isolated Docker with `P2S_NATIVE=1` | 24 tests, zero skips, passed |
| Suricata native syntax/load and offline PCAP execution | Passed, 12/12 rule IDs covered |
| libModSecurity native request/response/logging phases | Passed, 7/7 rule IDs covered |
| Official pySigma conversion and SQLite event evaluation | Passed, 5/5 rule UUIDs covered |
| CRS 3.3.5 coexistence with custom rules | All 21 HTTP fixtures passed |
| PCAP CLI with generated TCP/HTTP capture | Actual Suricata alert observed; no packets transmitted |
| PHP before/at-fix configuration matrix | 32/32 observations passed across 8 digest-pinned images |
| SARIF 2.1.0 schema, passing and failing reports | Passed against vendored OASIS schema |
| JSON, Markdown, escaped HTML and SARIF generation | Passed; deterministic output tested |
| Ruff lint and formatting of new Python modules | Passed |
| Workflow syntax validation | Both workflows passed actionlint 1.7.11 |
| `git diff --check` | Passed |
| Existing exploit, poc and lab sources | Unchanged and not executed |

Native environment: Ubuntu 24.04, Suricata 7.0.3, ModSecurity 3.0.12,
pySigma 1.5.1 / SQLite backend 1.2.4, CRS 3.3.5. Native Python is 3.12;
local Python 3.9 and 3.11 are also checked with optional dependencies reported
as skips where unavailable. A skip in the standard-library suite is not reported
as a successful native integration test.

## Independent classification results

Expected rule behavior passes on all fixtures, with positive/negative coverage
for all 24 rule IDs. Traffic metrics independently expose these limitations:

| Engine | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| Suricata | 14 | 6 | 1 | 0 |
| ModSecurity | 10 | 6 | 1 | 4 |
| Sigma | 5 | 7 | 0 | 0 |

The benign legacy upload-progress feature triggers both HTTP engines. ModSecurity
has no rule for the two session-path scenarios, long session cookies, or PHP
version headers. These counts are explicitly asserted by regression tests; a
regression PASS is not presented as perfect traffic classification.

PHP runtime pairs: 8.2.34/8.2.35, 8.3.35/8.3.36, 8.4.26/8.4.27 and 8.5.11/8.5.12.
Both session handlers and upload-progress settings are tested in each image.
Advisory-version classifications are separate from observed benign CLI behavior;
no exploitability or web-SAPI assessment is inferred.

Reports are generated under ignored `artifacts/native/` and `artifacts/php/`.
Reproduce with the [native guide](../native-validation.md).

## Remote/environment boundaries

GitHub workflows include P0, native engines, CRS, reports and the PHP matrix.
Remote CI status is verified after pushing when GitHub provides a run. Optional
GitHub Security upload requires code scanning and `P2S_UPLOAD_SARIF=true`.
The SARIF exporter and schema validation do not depend on that setting.

The first remote run passed Python 3.11/3.13 but could not install Python 3.9 on
the floating Ubuntu 26.04 runner. Workflows now pin Ubuntu 24.04 so the advertised
Python 3.9 compatibility job uses a supported setup-python platform.

Supported PCAP input is bounded classic Ethernet PCAP. No live-network replay,
TLS decryption, pcapng support, Apache/nginx blocking connector tests, universal
SIEM backend compatibility, or PHP exploitation tests are claimed. OpenResty
runtime testing is outside the three requested native adapters.
