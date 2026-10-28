<p align="center">
  <img src="docs/cover.png" alt="php2shell" width="700">
</p>

<h1 align="center">php2shell</h1>
<p align="center">
  <strong>CVE-2026-109618 & CVE-2026-109619 — PHP Pre-Auth RCE Exploit & Detection Toolkit</strong>
</p>
<p align="center">
  <a href="https://github.com/ikow/php2shell-poc/stargazers"><img src="https://img.shields.io/github/stars/ikow/php2shell-poc?style=flat-square" alt="Stars"></a>
  <img src="https://img.shields.io/badge/CVSS-9.2%20Critical-red?style=flat-square" alt="CVSS 9.2">
  <img src="https://img.shields.io/badge/PHP-5.4%E2%80%938.5-orange?style=flat-square" alt="Affected Versions">
  <img src="https://img.shields.io/badge/Fixed-8.2.35%20%7C%208.3.36%20%7C%208.4.27%20%7C%208.5.12-green?style=flat-square" alt="Fixed Versions">
  <img src="https://img.shields.io/badge/Exploits-3%20public%20%7C%202%20paid-blue?style=flat-square" alt="Exploits">
</p>

<p align="center">
  <a href="#exploits">Exploits</a> · <a href="#detection-rules">Detection</a> · <a href="#quick-start">Lab</a> · <a href="docs/EXPLOITATION.md">ITW Tracker</a> · <a href="https://qideng.substack.com/p/php2shell-dissecting-phps-critical">Writeup</a> · <a href="https://qideng.substack.com/p/php2shell-one-week-later-cisa-kev">Week 1 Report</a>
</p>

---

Five independent RCE chains exploiting PHP's `session.upload_progress` and the Zend engine's OOM bailout. **14 years of vulnerable code** — PHP 5.4.0 (2012) through 8.5.11. Pre-auth. No application vulnerability required for some chains.

Impacts **78% of all websites** — including WordPress (43%), Joomla, Drupal, Laravel, Magento, and every default PHP installation.

**Author:** [Qi Deng](https://github.com/ikow) &nbsp;|&nbsp; **Writeup:** [Substack](https://qideng.substack.com/p/php2shell-dissecting-phps-critical) &nbsp;|&nbsp; **Week 1 Report:** [Substack](https://qideng.substack.com/p/php2shell-one-week-later-cisa-kev) &nbsp;|&nbsp; **Date:** 2026-10-21

## CVE Details

| CVE | GHSA | CVSS | Description |
|-----|------|------|-------------|
| CVE-2026-109618 | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | 9.2 | OOM → `longjmp()` leaves Zend engine state invalid → RCE |
| CVE-2026-109619 | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | 9.2 | Stale global state across FPM worker requests → UAF → RCE |

**Patch:** [Commit 3584a98](https://github.com/php/php-src/commit/3584a98bda) — 300 files changed across the Zend engine.

## Attack Chains

| Chain | Vector | Pre-auth | Conditions | SAPI |
|-------|--------|:--------:|------------|------|
| **A** | Session injection + LFI | Yes | App has any LFI sink | All |
| **B** | var_destroy UAF → handler overwrite | No | App calls `unserialize()` | All |
| **C** | Handler mismatch → `__destruct` | Yes | Two dirs with different serialize_handler | FPM |
| **D** | OOM corruption → stale `EG()` | Yes | **None** — any endpoint | mod_php |
| **E** | FPM session OOM → stale `BG()` | Yes | Producer: any `session_start()` endpoint; Consumer: **any** endpoint | FPM |

Chain D is the most critical: **zero-dependency pre-auth RCE** against any Apache mod_php installation.

Chain E is nearly as broad on FPM: the producer needs any endpoint that calls `session_start()` (near-universal — WordPress, Laravel, Joomla, Drupal all do), and the **consumer can be any PHP endpoint** — the `rfc1867` upload_progress handler runs during SAPI startup before application code. Verified: `nosession.php` (no `session_start()` in code) triggers 502 crash when consuming stale `BG(unserialize)` state.

## Exploits

Three RCE exploits (Chains A, B, C) are included in [`exploit/`](exploit/):

| File | Chain | What It Does |
|------|-------|-------------|
| `chain_a_session_lfi.py` | A | Injects PHP code via upload filename → LFI includes session file → RCE |
| `chain_b_uaf_rce.php` | B | var_destroy UAF → discovers `zif_system` via EG() → overwrites `var_dump` handler via `/proc/self/mem` → RCE |
| `chain_c_mismatch_rce.py` | C | Pollutes FPM worker `PS(serializer)` → injects serialized object via filename → `__destruct` fires on decode failure → RCE |

Chains D and E exploits are available to [paid subscribers](https://qideng.substack.com/p/php2shell-dissecting-phps-critical).

```bash
# Chain A: Session injection + LFI → RCE
python3 exploit/chain_a_session_lfi.py --host TARGET --port 80 --command 'id'

# Chain B: var_destroy UAF → RCE (run on target or via uploaded webshell)
php exploit/chain_b_uaf_rce.php

# Chain C: Handler mismatch → __destruct → RCE
python3 exploit/chain_c_mismatch_rce.py --host TARGET --port 80 --command 'id'
```

## Detection Rules

Pre-built IDS / WAF / SIEM rules in [`detection/`](detection/):

| File | Format | Signatures |
|------|--------|-----------|
| `php2shell.rules` | Suricata / Snort | 13 rules — request, response, and recon |
| `php2shell.yaml` | Sigma | 5 rules — web logs, process creation, file events |
| `modsecurity.conf` | ModSecurity v2/v3 | 7 rules — drop-in for Apache/Nginx |
| `php2shell.lua` | OpenResty Lua | Lightweight reverse proxy module |

**Fastest mitigation:** block `PHP_SESSION_UPLOAD_PROGRESS` in multipart POST bodies. Near-zero legitimate use, covers the primary attack vector for both CVEs.

## Quick Start

```bash
git clone https://github.com/ikow/php2shell-poc.git && cd php2shell-poc

# Start the lab (PHP-FPM + nginx + Apache mod_php)
cd lab && docker compose up -d

# Verify each chain
python3 ../poc/verify_session_injection.py --target http://127.0.0.1:18080
python3 ../poc/verify_handler_mismatch.py --target http://127.0.0.1:18080
python3 ../poc/verify_oom_trigger.py --host 127.0.0.1 --port 18081
python3 ../poc/verify_fpm_stale_state.py --target http://127.0.0.1:18080

# Run an exploit
python3 ../exploit/chain_a_session_lfi.py --host 127.0.0.1 --port 18080 --command 'id'
```

## Repository Structure

```
php2shell-poc/
├── exploit/
│   ├── chain_a_session_lfi.py        # RCE: session injection + LFI
│   ├── chain_b_uaf_rce.php           # RCE: var_destroy UAF → handler overwrite
│   └── chain_c_mismatch_rce.py       # RCE: handler mismatch → __destruct
├── detection/
│   ├── php2shell.rules               # Suricata / Snort IDS rules
│   ├── php2shell.yaml                # Sigma SIEM detection rules
│   ├── modsecurity.conf              # ModSecurity WAF rules
│   └── php2shell.lua                 # OpenResty / Nginx Lua WAF module
├── poc/
│   ├── verify_session_injection.py   # Verify Chain A
│   ├── verify_uaf_asan.php           # Verify Chain B (ASAN)
│   ├── verify_handler_mismatch.py    # Verify Chain C
│   ├── verify_oom_trigger.py         # Verify Chain D
│   └── verify_fpm_stale_state.py     # Verify Chain E
├── lab/
│   ├── docker-compose.yml            # PHP-FPM + nginx + Apache mod_php
│   ├── setup.sh                      # One-click lab setup
│   └── php.ini / php-apache.ini      # Vulnerable PHP configs
└── docs/
    ├── ANALYSIS.md                   # Full technical analysis
    ├── EXPLOITATION.md               # ITW exploitation tracker, IOCs, downstream impact
    ├── substack_article.md           # Writeup source (original)
    └── substack_exploitation_article.md  # Week 1 report source
```

## Mitigation

```ini
; Immediate — reduces attack surface
session.upload_progress.enabled = Off
session.use_only_cookies = On
```

> **The only complete fix is patching PHP** to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+. The OOM corruption (Chain D) is in the Zend engine core — no INI setting fixes it.

For legacy / EOL environments (PHP 5.4–8.1) where upstream provides no official security updates, community-maintained backports with deployment automation and verification tooling are available at [Anton-Barinov/php2shell-patches](https://github.com/Anton-Barinov/php2shell-patches).

## Exploitation in the Wild

> **CISA KEV listed** (2026-10-26) &nbsp;|&nbsp; **Confirmed RCE** on honeypot (2026-10-24) &nbsp;|&nbsp; **Millions** of attempts within 24h

Full analysis: **[PHP2Shell One Week Later](https://qideng.substack.com/p/php2shell-one-week-later-cisa-kev)** (Substack) &nbsp;|&nbsp; Live tracker with IOCs: **[docs/EXPLOITATION.md](docs/EXPLOITATION.md)**

Highlights:
- **ASLR bypass PoC** leaked addresses via `Set-Cookie` — works on x86_64 with production config, no debugger needed
- **Potassium** (Mirai fork) delivered via php2shell — ChaCha20-encrypted config, 20 DDoS commands, reverse shell
- **Downstream pre-auth RCE confirmed** on WordPress, Drupal, Joomla, Magento, Roundcube, phpMyAdmin, Nextcloud, Laravel, Symfony, MediaWiki, WooCommerce, Shopware, WHMCS

## Downstream Impact

Wiz has demonstrated pre-auth RCE on stock container images:

| Platform | Vulnerable | Notes |
|----------|:----------:|-------|
| WordPress | Yes | Core doesn't use PHP sessions, but WooCommerce and many plugins do |
| Joomla | Yes | Uses native PHP sessions by default |
| Drupal | Yes | Uses native PHP sessions by default |
| Magento | Yes | Vulnerable even in maintenance mode |
| Laravel | Yes | `PendingBroadcast` is a known `__destruct` gadget |
| Roundcube | Yes | Webmail — credential exposure risk |
| phpMyAdmin | Yes | Direct database access |
| Nextcloud | Yes | File storage system |
| Symfony | Yes | Framework-level exposure |
| MediaWiki | Yes | Wiki platform |
| WooCommerce | Yes | WordPress plugin; payment data at risk |
| Shopware | Yes | E-commerce platform |
| WHMCS | Yes | Hosting control panel |

See **[docs/EXPLOITATION.md](docs/EXPLOITATION.md)** for full details, IOCs, and attacker tooling.

## References

- [PHP Security Advisory](https://www.php.net/archive/2026.php)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
- [Patch commit 3584a98](https://github.com/php/php-src/commit/3584a98bda) — 300 files, Zend engine + extensions
- [Cloudflare WAF coverage](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/)
- [Sansec analysis](https://sansec.io/research/php2shell) — PHPSESSID heap leak discovery
- [Wiz downstream impact](https://www.wiz.io/blog/php2shell-php-rce)
- [Corelight detection](https://github.com/corelight/php2shell-detect) — Zeek + Suricata community rules
- [Wiz exploitation analysis](https://www.wiz.io/blog/php2shell-exploitation-so-far) — Honeypot data, remediation stats
- [ELLIO sensor data](https://ellio.tech/en/blog/php2shell-what-we-observed-and-what-to-do/) — First-seen timeline, payload observations
- [VulnCheck exploit](https://www.vulncheck.com/blog/php2shell-vulnerabilities) — Production-config ASLR bypass
- [Nokia Deepfield Potassium](https://github.com/deepfield/public-research/tree/main/potassium) — Mirai-variant botnet analysis
- [Community EOL Backports (PHP 5.4–8.1)](https://github.com/Anton-Barinov/php2shell-patches) — fleet-validated patches, deploy tooling & verification suite

## Disclaimer

This repository is for **authorized security testing and educational purposes only**. Exploit code for Chains D and E (zero-dependency RCE) is available to [paid subscribers](https://qideng.substack.com/p/php2shell-dissecting-phps-critical) of the writeup.

## License

MIT

---

<p align="center">
  <sub>
    <b>Keywords:</b> php2shell, CVE-2026-109618, CVE-2026-109619, PHP RCE, PHP exploit, session.upload_progress,
    pre-auth RCE, PHP vulnerability, PHP session injection, PHP deserialization, PHP OOM, PHP memory corruption,
    use-after-free, GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp, WordPress RCE, Joomla RCE, Drupal RCE,
    PHP security, WAF rules, Suricata rules, ModSecurity rules, IDS signatures, PHP 8.2.35, PHP 8.4.27,
    session upload progress, PHP session fixation, rfc1867, longjmp, zend_bailout,
    Snort rules, Sigma rules, detection rules, PHP patch, PHP critical vulnerability
  </sub>
</p>
