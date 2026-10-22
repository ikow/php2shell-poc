# php2shell Detection Rules

Detection and blocking rules for CVE-2026-109618 / CVE-2026-109619.

## Files

| File | Format | Use Case |
|------|--------|----------|
| `php2shell.rules` | Suricata / Snort | Network IDS — 12 rules covering request-side, response-side, and recon |
| `php2shell.yaml` | Sigma | SIEM log detection — web server logs and host-level process/file events |
| `modsecurity.conf` | ModSecurity v2/v3 | WAF — drop-in rules for Apache/Nginx with ModSecurity |
| `php2shell.lua` | OpenResty / Nginx Lua | Reverse proxy — lightweight Lua module for OpenResty |

## Quick Start

**Suricata:**
```bash
cp php2shell.rules /etc/suricata/rules/
echo "  - php2shell.rules" >> /etc/suricata/suricata.yaml  # under rule-files
suricatasc -c reload-rules
```

**ModSecurity:**
```bash
cp modsecurity.conf /etc/modsecurity/conf.d/php2shell.conf
# or: Include /path/to/modsecurity.conf  in your modsecurity config
systemctl reload apache2  # or nginx
```

**OpenResty:**
```nginx
# In your nginx server block:
access_by_lua_block {
    require("php2shell").check()
}
```

## Coverage Matrix

| SID / Rule | What It Detects | Severity |
|-----------|-----------------|----------|
| **Request-side** | | |
| 2026100 | `PHP_SESSION_UPLOAD_PROGRESS` in multipart POST | HIGH |
| 2026101 | `PHPSESSID` as form field (session fixation) | HIGH |
| 2026102 | PHP code in upload filename (`<?php` in filename) | CRITICAL |
| 2026103 | Serialized PHP object in filename (`\|O:` pattern) | CRITICAL |
| 2026104 | Oversized filename (>10KB, session inflation) | MEDIUM |
| 2026105 | Chunked multipart POST (post_max_size bypass) | MEDIUM |
| 2026106 | Session file path in URL (LFI trigger) | HIGH |
| **Response-side** | | |
| 2026110 | PHP OOM "memory exhausted" in response | HIGH |
| 2026111 | "Session object destruction failed" in response | CRITICAL |
| 2026112 | Anomalous PHPSESSID cookie length (heap leak) | CRITICAL |
| **Reconnaissance** | | |
| 2026115 | Small upload progress probes (threshold: 3/60s) | LOW |
| 2026116 | Vulnerable PHP version in response header | INFO |

## Notes

- **SID 2026100 is the single most important rule.** It covers the primary attack vector for both CVEs with near-zero false positives.
- Response-side rules (2026110-2026112) detect exploitation that bypassed request-side defenses. Deploy both layers.
- The 64KB body inspection limit in many WAFs means attackers can pad past your inspection window. PHP-level mitigation (`session.upload_progress.enabled = Off`) is the reliable fix.
- These rules complement, but do not replace, patching PHP to 8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+.

## References

- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
- [Sansec research](https://sansec.io/research/php2shell) — PHPSESSID memory leak discovery
- [Cloudflare WAF blog](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/) — full transaction detection approach
- [Corelight detection](https://github.com/corelight/php2shell-detect) — Zeek + Suricata community rules

## Automated validation

Run `python3 -B -m tools.run_native --build --with-crs` from the repository root.
This executes all 24 Suricata/ModSecurity/Sigma rule IDs with positive and negative
fixtures, using the actual engines and pySigma-to-SQLite conversion. Reports
include known traffic false positives and coverage gaps. See the
[native validation guide](../docs/native-validation.md) for exact versions,
report formats, PCAP analysis, Sigma event-field mappings and limitations.
