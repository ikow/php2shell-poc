# php2shell Scanner

Fast, non-destructive vulnerability scanner for CVE-2026-109618 / CVE-2026-109619.
Built by the CVE authors — tests the actual attack primitives, not just version numbers.

## Quick Start

```bash
# Single target
python3 scanner/check.py https://example.com

# Multiple targets
python3 scanner/check.py --targets urls.txt

# JSON output for automation
python3 scanner/check.py https://example.com --json
```

## Detection Tiers

| Tier | What | Risk | Traffic |
|------|------|------|---------|
| 1 | Version fingerprint (headers) | None | 1 GET |
| 2 | `upload_progress` reachability | Low | 1-2 POST (~2KB) |
| 3 | Session write verification | Low | 1 POST + 1 GET |
| 4 | OOM differential | **Destructive** | 1 POST (~2MB) |

Tiers 1-3 run by default. Tier 4 requires `--active`.

### Tier 1: Version Fingerprint
Extracts PHP version from `X-Powered-By`, `Server` headers, and error pages. Detects SAPI type (FPM vs mod_php). Compares against patched versions.

### Tier 2: upload_progress Reachability
Sends a minimal multipart POST with `PHP_SESSION_UPLOAD_PROGRESS`. If a session cookie comes back, the rfc1867 handler processed the request — the attack primitive is reachable. Also tests session fixation via POST body (pre-PR#22113).

### Tier 3: Session Write Verification
Injects a harmless marker string in the upload filename and checks if it appears in the session. Confirms the filename injection primitive that enables Chains A/C/E.

### Tier 4: OOM Differential (opt-in)
Sends an oversized multipart to trigger `memory_limit`. Compares the crash behavior to a baseline GET:
- **Unpatched:** empty 500, connection reset, 502 (worker death)
- **Patched:** graceful error (soft OOM) or clean `_exit(137)`

**WARNING:** This WILL crash unpatched PHP workers. Use only on systems you control.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `VULNERABLE` | Confirmed vulnerable |
| `LIKELY_VULNERABLE` | Attack primitive reachable but version hidden |
| `PATCHED` | Running a patched version |
| `UNKNOWN` | Insufficient signals |
| `ERROR` | Connection failure |

## Options

```
positional:
  target                Target URL (http:// or https://)

options:
  --targets FILE, -f    File with one URL per line (- for stdin)
  --path PATH, -p       Override endpoint path
  --active              Enable OOM probe (DESTRUCTIVE)
  --json, -j            JSON output
  --threads N, -t       Concurrent threads (default: 10)
  --timeout SEC         Per-request timeout (default: 10)
  --quiet, -q           Only show vulnerable targets
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | At least one target is vulnerable |
| 1 | All targets are patched |
| 2 | No vulnerable targets found, but at least one target is unknown/error |

## Examples

```bash
# Scan lab targets
python3 scanner/check.py http://127.0.0.1:18082   # PHP 8.2.34 → VULNERABLE
python3 scanner/check.py http://127.0.0.1:18085   # PHP 8.2.35 → PATCHED
python3 scanner/check.py http://127.0.0.1:18056   # PHP 5.6.40 → VULNERABLE

# Batch scan with JSON + parallel
python3 scanner/check.py --targets urls.txt --json --threads 20

# Pipe from stdin
echo "https://example.com" | python3 scanner/check.py --targets -

# Active mode (will crash unpatched workers)
python3 scanner/check.py http://127.0.0.1:18091 --active

# CI integration — distinguish findings, patched targets, and incomplete scans
if python3 scanner/check.py --targets prod-hosts.txt --quiet --json; then
    echo "Vulnerable targets found" >&2
    exit 1
else
    status=$?
    case "$status" in
        1) echo "All targets reported PATCHED" ;;
        *) echo "Scan incomplete or failed (exit $status)" >&2; exit 2 ;;
    esac
fi
```

## Offline Tests

Run from the repository root (Python standard library only):

```bash
python3 -m unittest discover -s tests -v
```

The tests simulate scan results and block socket connections. They cover
single-target and concurrent batch exit codes, including mixed patched and
unknown/error results, vulnerable-result precedence, and JSON/text/quiet output.
Exit code 1 requires every target to report `PATCHED`; a partially inconclusive
batch returns 2 unless a vulnerable target was found (exit code 0).

## How It Compares

| Scanner | Method | Destructive | Accuracy |
|---------|--------|-------------|----------|
| **This tool** | Primitive probe + version | No (default) | High |
| Assetnote | OOM crash + version | Yes (~29MB) | High |
| JoasASantos | Version fingerprint | No | Medium |
| SOCRadar | Passive version check | No | Low |

Our advantage: we test the actual attack primitive (`session.upload_progress` reachability + session fixation) non-destructively, which provides high confidence even when the PHP version is hidden.

## Patched Versions

| Branch | Fixed Version |
|--------|--------------|
| 8.2.x | 8.2.35 |
| 8.3.x | 8.3.36 |
| 8.4.x | 8.4.27 |
| 8.5.x | 8.5.12 |
| 5.x–8.1.x | EOL — no fix |
