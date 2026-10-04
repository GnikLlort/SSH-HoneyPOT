#!/usr/bin/env python3
"""
One-way ingestion: export bundle -> monitoring store.

This is a SEPARATE program from the web dashboard, on purpose.

    * The web process cannot trigger it. There is no endpoint, no button, no
      import. The dashboard imports `store` (read-only) and nothing else.
    * Ingestion runs on the monitoring host, so the honeypot never holds a
      credential for the store and the store never connects to the honeypot.
    * Data flows one way. Nothing here can send a command anywhere: it reads
      files and writes rows.

Run it on a timer:

    python3 ingest.py --store /var/lib/honeypot-store --bundle /var/spool/honeypot-export

Ingestion is idempotent. Every row is keyed on Cowrie's own event uuid, so
re-running over overlapping bundles adds nothing and a failed run can simply be
repeated. Overlap is expected, not exceptional: bundles are packed while the
honeypot is still writing, so the last bundle and the next one always share
events.

Exit codes:
    0  ingested, no problems
    1  ingested with warnings (a corrupt line, a skipped file)
    2  could not ingest at all (missing bundle, unreadable store)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from store import Store, iso  # noqa: E402
from terminal_safety import safe_log_value  # noqa: E402


def log(message: str) -> None:
    """Timestamped, single-line output. Values are sanitised: this can print
    field content that originated from an attacker."""
    print(f"[{iso()}] {safe_log_value(message, 400)}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", required=True, help="monitoring store root")
    ap.add_argument("--bundle", required=True, help="export bundle directory")
    ap.add_argument("--keep", action="store_true",
                    help="keep the bundle after a successful ingest")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    store_root = Path(args.store)
    bundle = Path(args.bundle)

    if not bundle.is_dir():
        log(f"ERROR: bundle directory {bundle} does not exist")
        return 2
    if not (bundle / "cowrie.json").is_file() and not list(bundle.glob("*.jsonl")):
        # An empty bundle is not an error: a honeypot with no traffic yet
        # legitimately produces one, and failing here would page someone at
        # 3am for nothing.
        log(f"note: bundle {bundle} contains no event log; ingesting what is there")

    if not os.access(store_root.parent if store_root.parent.exists() else Path("/"),
                     os.W_OK) and not store_root.exists():
        log(f"ERROR: cannot create store at {store_root} (parent not writable)")
        return 2

    store = Store(store_root)
    try:
        stats = store.ingest_bundle(bundle)
    except Exception as exc:                       # noqa: BLE001 - report, never crash a timer
        log(f"ERROR: ingest failed: {safe_log_value(exc, 300)}")
        return 2

    if not args.quiet:
        log(f"ingested {bundle.name}: "
            f"events +{stats.events_new} (dup {stats.events_dup}), "
            f"recordings +{stats.recordings_new}, "
            f"captures +{stats.quarantine_new}, "
            f"health +{stats.health_new}")

    if stats.errors:
        for err in stats.errors[:10]:
            log(f"  warning: {err}")
        log(f"completed with {len(stats.errors)} warning(s)")
        return 1

    if not args.keep:
        # Remove only the bundle's ingestible data, never the store. A failed
        # ingest returns before this point, so an unreadable bundle is retried
        # rather than silently discarded.
        try:
            for child in bundle.iterdir():
                if child.is_dir():
                    import shutil
                    shutil.rmtree(child)
                else:
                    child.unlink()
        except OSError as exc:
            log(f"  note: could not clear bundle: {safe_log_value(exc, 200)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
