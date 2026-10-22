# Native Detection Validation Toolkit

The P0 substring backend remains available unchanged. The native runner executes
Suricata 7.0.3, libModSecurity 3.0.12, and official pySigma 1.5.1 with its SQLite
backend 1.2.4. It validates all 12 Suricata, 7 ModSecurity, and 5 Sigma rules using
21 HTTP transaction fixtures and 12 log/event fixtures. OWASP CRS 3.3.5 coexistence
is checked separately. These pinned versions define the tested baseline, not a
recommendation for production deployment or a claim of compatibility with every
engine release. OpenResty is outside the three requested native adapters.

## Quick start

Requires Python 3.9+ and a running Docker daemon. Dependency downloads happen
only during image builds/pulls; the actual engines have no network access.

```sh
python3 -B -m tools.run_native --build --with-crs
python3 -B -m tools.run_native --tests
```

The runner mounts the repository read-only, allows writes only to `artifacts/`
and an ephemeral bounded `/tmp`, drops all capabilities, uses the host user's
UID/GID, limits memory/CPU/processes, and removes its container after completion
or a timeout. It publishes no ports, mounts no Docker socket, starts no PHP web
server, and executes no exploit code. Native subprocesses have their own timeouts.

Generate reports for just one engine:

```sh
python3 -B -m tools.run_native --engine suricata
python3 -B -m tools.run_native --engine modsecurity --with-crs
python3 -B -m tools.run_native --engine sigma
```

Reports are `artifacts/native/native.json`, `native.md`, `native.html`, and
`native.sarif`. Exit codes are 0 for expected rule behavior and coverage, 1 for
regressions or missing required coverage, and 2 for input/runtime failures. An
unavailable engine is an error, never a passing skipped integration.

For Python-only development, install pinned dependencies into a virtual environment:

```sh
python3.11 -m venv .venv
.venv/bin/pip install -r requirements-validation.txt
.venv/bin/python -B -m unittest discover -v
.venv/bin/python -B -m tools.validate_native --engine sigma
```

Native engine tests are enabled explicitly by `P2S_NATIVE=1` inside Docker. The
standard-library-only P0 workflow skips tests requiring optional native/Sigma
packages; the native workflow installs them and executes every test.

## What each adapter validates

- **Suricata:** loads the real rules with `-T`; creates deterministic Ethernet,
  IPv4 and TCP handshakes, segmented requests and responses in classic PCAPs;
  performs offline stream processing with `-r`; reads actual EVE signature IDs.
  Repeated-probe fixtures share a source address and timestamp window. Each case
  runs in a new engine process so thresholds cannot leak between fixtures.
- **ModSecurity:** loads the actual rule file through the libModSecurity v3 C
  API, processes connection/request/response/logging phases, and collects rule
  IDs through its native server-log callback. Chunk framing is decoded as a web
  server connector would do. `DetectionOnly` allows observing every matching
  rule; HTTP blocking behavior, nginx/Apache connectors, and ModSecurity v2 are
  not claimed to have been tested.
- **Sigma:** official pySigma parsing validates IDs and syntax, its maintained
  SQLite backend converts each rule, and real SQL queries execute against an
  in-memory event table. Logsource routing is explicit. This tests that backend,
  not every SIEM dialect. `RequestBody`, `Content`, and `Message` require the
  corresponding log enrichment; ordinary access logs do not contain all of them.
- **OWASP CRS:** loads the distribution's setup and complete CRS rule directory
  together with custom ModSecurity rules, then executes every HTTP fixture.
  Custom alerts must remain identical. Additional CRS IDs are recorded separately;
  coexistence is not equivalent to a CRS blocking-policy accuracy assessment.

## Fixtures, metrics, and coverage

HTTP fixtures contain `id`, `description`, independent `malicious` ground truth,
`request`, `response`, `repeat`, and explicit expected alert arrays for both
engines. Sigma fixtures contain metadata, independent `malicious`, `event`,
`logsource`, and an expected UUID array. Unknown expected IDs, duplicate IDs,
invalid types and oversized files fail closed. Fixture requests are synthetic;
there are no real credentials, executable PHP payloads, or live destinations.

Expected rule arrays are reviewed regression baselines. They record the known
behavior of each rule, including known signature collisions. Per-rule TP/TN/FP/FN
compare actual alerts with those arrays. Native traffic TP/TN/FP/FN separately
compare any project rule firing against the independent malicious/benign label.
Known traffic errors remain visible even when expected rule behavior passes.
The tests assert their current counts so they cannot silently disappear.

Each of the 24 rules must have expected-positive and expected-negative cases.
Coverage is labeled-case coverage, not a proof that all evasions are detected.
`--allow-incomplete-coverage` permits focused custom corpora; CI always requires
complete coverage. A custom fixture file requires `--engine`.

The benign `legitimate-progress-feature` fixture intentionally demonstrates a
false positive in both HTTP engines. ModSecurity also has four known misses for
session-path requests, encoded session paths, long session cookies, and exposed
version headers because it has no equivalent rules. A regression PASS does not
mean zero false positives or full attack-chain coverage. The reports preserve
these gaps instead of weakening the ground-truth labels.

## Offline PCAP replay and analysis

Place an authorized capture under the repository (PCAP files are gitignored):

```sh
python3 -B -m tools.run_native --pcap samples/traffic.pcap --home-net 10.0.0.0/8
```

This replays packets **into Suricata's file reader only**; it does not transmit
packets. Input supports bounded classic Ethernet PCAP (maximum 64 MiB and 200,000
packets); malformed/truncated captures and pcapng are rejected. TLS decryption,
HTTP/2 fixture generation and other link types are not implemented. Select the
protected network explicitly for captures from your environment. Output is
`artifacts/native/pcap.json`, containing packet metadata and observed rule IDs.
Without ground truth, TP/FP/FN are null rather than invented. Raw packets,
addresses, URIs and cookies are not included in reports.

## PHP version and configuration matrix

The matrix compares benign CLI observations across digest-pinned official PHP
8.2, 8.3, 8.4 and 8.5 images, immediately before and at each advisory fix. Each runs with `php` and `php_serialize` handlers,
with upload-progress enabled and disabled: 32 isolated observations. It records
the actual runtime version, SAPI, INI configuration, and a benign session
encode/decode roundtrip. A version-only advisory status uses the two official PHP advisories reviewed on
2026-10-22, with sources and fixed-version boundaries embedded in the report. No
memory-exhaustion or deserialization exploit runs.

```sh
python3 - <<'PY'
import json, subprocess
from pathlib import Path
for image in json.loads(Path('tools/native/php-images.json').read_text()).values():
    subprocess.run(['docker', 'pull', image], check=True)
PY
python3 -B -m tools.php_version_matrix
```

Reports: `artifacts/php/php-matrix.json` and `php-matrix.md`. Runtime containers
have no network, capabilities, writable root filesystem or published ports.
These CLI observations do **not** establish web-SAPI behavior or vulnerability
status. The JSON explicitly says `vulnerability_status: not_assessed`; a safe
configuration probe cannot prove exploitability or patch completeness. A
vulnerability reproduction matrix would require separately authorized lab tests
and is not silently substituted by version-string comparisons.

## Reports and CI

Native reports include execution status, actual engine versions, per-rule
coverage, independent traffic classification, and individual missing/unexpected
alerts. Output is deterministic for fixed inputs and engine versions and omits
raw HTTP and log event content. HTML escapes all displayed content.

SARIF 2.1.0 represents missing/unexpected rule alerts as regression findings at
the fixture artifact, not vulnerabilities at exploit source files. Passing
expected detections do not become security findings. Both passing and failing
SARIF are checked offline against the vendored OASIS schema.

GitHub Actions runs the standard-library P0 matrix, the complete native test suite,
CRS coexistence, report generation and all 32 PHP observations on pushes and PRs.
Artifacts are uploaded even after test failures. To enable GitHub Security upload
on pushes, set repository Actions variable `P2S_UPLOAD_SARIF=true` and enable code
scanning. Fork PRs do not receive security-event write access. SARIF artifact
creation/schema validation works independently of that optional GitHub setting.

## Rule corrections backed by native tests

- Suricata 2026115: `bsize` replaces invalid `dsize` mixed with application matching.
- Suricata 2026103: recognize numeric serialization-length prefixes after `|O:`.
- Suricata 2026104: measure the filename, not arbitrary following file contents.
- Suricata 2026112: use the cookie buffer, where Suricata exposes Set-Cookie values.
- ModSecurity: supported severity names; parsed `ARGS_NAMES` for PHPSESSID; remove
  conflicting `noauditlog` on the rule intended to log that signal.
- Sigma: valid stable UUIDs, explicit enriched-event fields, literal PHP question
  mark, and both OOM message fragments required together. Unused selections removed.

Exploit, PoC and vulnerable lab sources remain unchanged.

## Implementation references

- [Suricata command-line options](https://docs.suricata.io/en/suricata-7.0.0/command-line-options.html)
- [ModSecurity C API](https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/headers/modsecurity/transaction.h)
- [Official pySigma SQLite backend](https://github.com/SigmaHQ/pySigma-backend-sqlite)
- [OWASP CRS installation](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/)
- [GitHub SARIF upload](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
- [OASIS SARIF schema](https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json)
