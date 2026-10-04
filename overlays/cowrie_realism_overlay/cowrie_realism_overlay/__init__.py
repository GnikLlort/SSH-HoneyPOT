"""
Optional realism overlay for Cowrie v3.1.0.

WHY THIS EXISTS
---------------
Four of the defects found during the realism audit cannot be fixed through
configuration, because the affected code paths never consult CowrieConfig:

  1. ``free``                      reads the real host's /proc/meminfo
  2. ``ps aux``                    drops the TIME and COMMAND columns, and
                                   appends rows hardcoded to "Jul22"/"06:30"
                                   regardless of the emulated boot time
  3. ``ps -ef`` / ``ps -e``        returns a two-row list unrelated to the
                                   configured process table
  4. ``service --status-all``      returns a hardcoded Debian-7-era list
                                   (cups, lightdm, open-vm-tools, whoopsie,
                                   mountall.sh) on a host that claims to run
                                   systemd on Debian 12

Each is a fingerprinting signal an operator can see with one command.

HOW IT IS APPLIED
-----------------
Nothing in the installed Cowrie tree is modified. The overlay is loaded
through ``sitecustomize``, which CPython imports automatically at interpreter
startup if it is importable. The systemd unit adds the overlay directory to
PYTHONPATH and sets COWRIE_REALISM_OVERLAY=1.

To revert: remove the two environment lines from the unit and restart. Cowrie
then behaves exactly as the pinned upstream release.

SCOPE AND SAFETY
----------------
The overlay only changes the *rendering* of emulated output. It does not
execute anything, does not touch the network, does not open files outside the
configured honeypot state directory, and cannot be influenced by anything a
visitor sends beyond the command string that Cowrie has already parsed.

It is pinned to Cowrie v3.1.0 (commit 6ec36d0d5d4a1a14bc6e6ddadcb7b8f255e0570b).
``verify_targets()`` checks that the classes and methods being patched still
exist, and refuses to load rather than half-applying against a different
release.
"""

from __future__ import annotations

import os

__all__ = ["apply", "verify_targets", "OVERLAY_VERSION"]

OVERLAY_VERSION = "1.0.0"
PINNED_COWRIE = "3.1.0"


def verify_targets() -> list[str]:
    """
    Confirm the objects we intend to replace still exist.

    Returns a list of problems; an empty list means the overlay can be
    applied safely.
    """
    problems: list[str] = []
    try:
        import cowrie
        from cowrie.commands import base as cmd_base
        from cowrie.commands import free as cmd_free
        from cowrie.commands import service as cmd_service
    except Exception as exc:  # noqa: BLE001
        return [f"cannot import cowrie command modules: {exc}"]

    # cowrie.__version__ is a module (cowrie._version), not a string, so read
    # the installed distribution metadata instead.
    version = None
    try:
        from importlib.metadata import PackageNotFoundError, version as pkg_version

        try:
            version = pkg_version("cowrie")
        except PackageNotFoundError:
            version = None
    except Exception:  # noqa: BLE001
        version = None

    if version is None:
        # Fall back to the module attribute if it happens to be a plain string.
        attr = getattr(cowrie, "__version__", None)
        version = attr if isinstance(attr, str) else None

    if version != PINNED_COWRIE:
        problems.append(f"cowrie version {version!r} is not the pinned {PINNED_COWRIE!r}")

    if not hasattr(cmd_free, "Command_free"):
        problems.append("cowrie.commands.free.Command_free not found")
    elif not hasattr(cmd_free.Command_free, "get_free_stats"):
        problems.append("Command_free.get_free_stats not found")

    if not hasattr(cmd_base, "Command_ps"):
        problems.append("cowrie.commands.base.Command_ps not found")

    if not hasattr(cmd_service, "Command_service"):
        problems.append("cowrie.commands.service.Command_service not found")
    elif not hasattr(cmd_service.Command_service, "status_all"):
        problems.append("Command_service.status_all not found")

    return problems


def apply() -> str:
    """Apply the overlay. Returns a short status string for the log."""
    problems = verify_targets()
    if problems:
        return "overlay NOT applied: " + "; ".join(problems)

    from cowrie_realism_overlay import patches

    patches.install()
    return f"overlay {OVERLAY_VERSION} applied (cowrie {PINNED_COWRIE})"


if os.environ.get("COWRIE_REALISM_OVERLAY", "").strip() in ("1", "yes", "true"):
    # Import-time application. Failures are swallowed deliberately: a broken
    # overlay must never stop the honeypot from starting, because a honeypot
    # that is down collects nothing.
    try:
        _status = apply()
        if os.environ.get("COWRIE_REALISM_OVERLAY_VERBOSE", "").strip() in ("1", "yes", "true"):
            import sys

            print(f"[cowrie-realism-overlay] {_status}", file=sys.stderr)
    except Exception as _exc:  # noqa: BLE001
        import sys

        print(f"[cowrie-realism-overlay] failed to apply: {_exc}", file=sys.stderr)
