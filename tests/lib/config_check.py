"""
Static checks on config/cowrie.cfg that only a live run could otherwise make.

WHY THIS IS A SEPARATE MODULE
    Two suites need these assertions. `tests/test_conformance.py` runs them
    beside the live-lab checks (the audit recommended exactly that), and
    `tests/test_safety_guards.py` runs them with the unit suites, so a machine
    with no lab still catches a config edit that reopens port forwarding.

    One implementation, both callers. A safety invariant duplicated across two
    test files is an invariant that will eventually be true in one of them.

THE INVARIANT
    config/cowrie.cfg sets `[ssh] forwarding = true` so that Cowrie answers
    forward requests itself with a fake channel instead of refusing them, which
    is what a real build server with `AllowTcpForwarding yes` would look like.
    That behaviour is safe ONLY while `forward_redirect` and `forward_tunnel`
    are both false: with either true, Cowrie opens a real TCP connection to a
    host the visitor names -- the honeypot becomes a proxy into the network it
    is supposed to be isolated from. The config comment says so; nothing
    checked it, so an edit could silently reopen a route out of the boundary.
"""

from __future__ import annotations

import configparser
from pathlib import Path

__all__ = ["isolation_config_problems", "REQUIRED_FALSE"]

# Keys in [ssh] that must be false for the isolation story to hold.
REQUIRED_FALSE = ("forward_redirect", "forward_tunnel")


def isolation_config_problems(path: Path) -> list[str]:
    """Return a list of problems; empty means the config is as validated."""
    path = Path(path)
    parser = configparser.ConfigParser()
    try:
        with path.open(encoding="utf-8") as fh:
            parser.read_file(fh)
    except OSError as exc:
        return [f"cannot read {path}: {exc}"]
    except configparser.Error as exc:
        return [f"{path} is not parseable: {exc}"]

    if not parser.has_section("ssh"):
        return [f"{path} has no [ssh] section"]

    problems: list[str] = []

    if not parser.getboolean("ssh", "forwarding", fallback=False):
        problems.append(
            "[ssh] forwarding is not true, so Cowrie refuses forward requests "
            "outright. That is safe but inconsistent with the emulated host, "
            "which the profile describes as allowing them (docs/04).")

    for key in REQUIRED_FALSE:
        value = parser.getboolean("ssh", key, fallback=None)
        if value is not False:
            problems.append(
                f"[ssh] {key} = {value!r}. It must be false: with it true Cowrie "
                f"opens a real TCP connection to a host named by the visitor, "
                f"which turns the honeypot into a proxy into the network it is "
                f"isolated from (docs/05).")
    return problems
