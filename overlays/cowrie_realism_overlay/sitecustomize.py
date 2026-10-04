"""
sitecustomize entry point for the optional realism overlay.

CPython imports ``sitecustomize`` automatically at interpreter startup when it
is importable, so putting this directory on PYTHONPATH is enough to load the
overlay - no files in the installed Cowrie tree are modified.

Loading is gated on COWRIE_REALISM_OVERLAY so that unrelated Python
invocations in the same environment (``cowrie init``, ``fsctl``, an operator's
shell) are unaffected.

The systemd unit shipped with this package sets:

    Environment=PYTHONPATH=<state>/overlay
    Environment=COWRIE_REALISM_OVERLAY=1

Removing those two lines and restarting reverts to stock Cowrie behaviour.
"""

import os
import sys
import traceback

if os.environ.get("COWRIE_REALISM_OVERLAY", "").strip() in ("1", "yes", "true"):
    try:
        from cowrie_realism_overlay import apply

        _status = apply()
        if os.environ.get("COWRIE_REALISM_OVERLAY_VERBOSE", "").strip() in ("1", "yes", "true"):
            print(f"[cowrie-realism-overlay] {_status}", file=sys.stderr)
    except Exception:  # noqa: BLE001
        # Never prevent the honeypot from starting. A honeypot that is down
        # collects nothing, which is worse than an imperfect one that runs.
        print("[cowrie-realism-overlay] disabled after error:", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
