#!/usr/bin/env python3
"""
Run commands against a running honeypot instance and print the raw output.

Thin wrapper over the test client so that ad-hoc inspection during an audit
uses exactly the same connection path as the conformance suite.

Examples:
    python3 tests/hp_exec.py 'uname -a' 'df -h' 'ps aux | head'
    python3 tests/hp_exec.py --shell 'cd /tmp' 'ls -la'
    python3 tests/hp_exec.py --user deploy --password deploy 'id'
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.cowrie_client import OpenSSHClient  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("commands", nargs="+")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--user", default="deploy")
    ap.add_argument("--password", default="Sunrise-Ledger-1972")
    ap.add_argument("--shell", action="store_true", help="drive an interactive PTY shell instead of exec")
    args = ap.parse_args()

    client = OpenSSHClient(host=args.host, port=args.port, username=args.user, password=args.password)
    if not client.start():
        print(f"FATAL: authentication failed for {args.user}", file=sys.stderr)
        client.close()
        return 2

    try:
        if args.shell:
            print(client.interactive(args.commands))
        else:
            for cmd in args.commands:
                res = client.run(cmd)
                print("=" * 72)
                print(f"$ {cmd}   [exit={res.exit_status} {res.duration_ms}ms]")
                print("-" * 72)
                if res.stdout:
                    print(res.stdout.rstrip("\n"))
                if res.stderr:
                    print("--- stderr ---")
                    print(res.stderr.rstrip("\n"))
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
