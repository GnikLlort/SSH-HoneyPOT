"""
Guards for the destructive operations in this package.

WHY THIS MODULE EXISTS
    Two programs delete a directory tree: the profile builder
    (`realism/build_profile.py --out ...`) and the bundle builder
    (`dashboard/bundle.py --out ...`). A third, `deploy/uninstall.sh`, deletes
    the honeypot state directory in shell. In every case the path arrives as an
    operator-supplied argument, and in two of them the program runs as root
    during installation.

    Neither path was validated. `--out /opt/cowrie` -- a plausible slip for the
    state directory, whose name the operator has just been typing -- would have
    recursively deleted `var/lib/cowrie/tty/`: the session recordings, which
    are evidence. `--out /` is worse. The blast radius of the mistake includes
    material that cannot be regenerated.

    So the rule is inverted: a recursive delete is refused unless the target
    can be shown to be this package's own output. "Cannot be shown" means
    refuse, and an operator who really means it passes an explicit force flag
    (documented at the point of use, never inferred).

WHAT IS REFUSED UNCONDITIONALLY
    Structure, not ownership: `/`, a shared top-level directory, a mount point,
    anything containing a mount point, the current directory or one of its
    ancestors, and a symlink. These are refused even with --force, because
    "I meant it" is not a reason to `rm -rf` a machine, and a flag that can
    authorise that is worse than no flag.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = [
    "MARKER_PROFILE",
    "MARKER_BUNDLE",
    "DEFAULT_STATE_DIR",
    "UnsafePathError",
    "guard_delete_target",
    "looks_like_state_dir",
    "write_marker",
]

# Written into a directory this package has produced. A marker from a previous
# run is the strongest evidence available that the directory is ours to
# replace: it is a positive claim rather than a guess at the shape of a path.
MARKER_PROFILE = ".honeypot-profile"
MARKER_BUNDLE = ".honeypot-bundle"

# The deployment default from deploy/versions.env, which uninstall.sh must be
# allowed to delete even on a host where the layout probe finds nothing (a
# failed install leaves an empty directory). Kept in sync by a test.
DEFAULT_STATE_DIR = "/opt/cowrie"

_SYSTEM_DIRS = frozenset({
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64",
    "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys",
    "/tmp", "/usr", "/var",
})

_SHARED_TOP_LEVEL = frozenset({"/opt", "/usr", "/var", "/etc", "/home"})


class UnsafePathError(ValueError):
    """Raised instead of deleting something that cannot be shown to be ours."""


def _mount_points() -> set[str]:
    """
    Every mount point on this host, resolved.

    `/proc/self/mountinfo` is used rather than `os.path.ismount()` because a
    bind mount has the same device number as its parent, so ismount() cannot
    see it -- and a bind mount is exactly the case where deleting a tree
    deletes something that lives elsewhere.
    """
    points: set[str] = set()
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                fields = line.split()
                # mountinfo: ... <mount point> <options> ... ; the mount point
                # is field 5 (index 4) and spaces are escaped as \040.
                if len(fields) > 4:
                    points.add(os.path.realpath(fields[4].replace("\\040", " ")))
    except OSError:
        pass
    return points


def _mount_problem(path: Path) -> str:
    resolved = os.path.realpath(path)
    for point in _mount_points():
        if point == resolved:
            return f"{path} is a mount point"
        if point.startswith(resolved.rstrip("/") + "/"):
            return f"{path} contains the mount point {point}"
    return ""


def _structural_problems(path: Path) -> list[str]:
    problems: list[str] = []
    resolved = Path(os.path.realpath(path))

    if str(resolved) in _SYSTEM_DIRS:
        problems.append(f"{resolved} is a system directory")
    elif len(resolved.parts) < 2:
        problems.append(f"{resolved} is the filesystem root")
    if str(resolved) in _SHARED_TOP_LEVEL:
        problems.append(f"{resolved} is a shared top-level directory")

    cwd = Path.cwd().resolve()
    if resolved == cwd:
        problems.append(f"{resolved} is the current working directory")
    elif cwd.is_relative_to(resolved):
        problems.append(f"{resolved} is an ancestor of the current working directory")

    if path.is_symlink():
        # resolve() already followed the link for the checks above; deleting
        # through the link deletes the target, which is the surprise to avoid.
        problems.append(f"{path} is a symlink")

    mount = _mount_problem(resolved)
    if mount:
        problems.append(mount)
    return problems


def _has_marker(path: Path, marker: str) -> bool:
    return (path / marker).is_file()


def looks_like_state_dir(path: Path) -> bool:
    """
    Does this look like a honeypot state directory?

    The deployment uses the state directory as the service account's home, so
    its layout is distinctive: the virtualenv, the Cowrie configuration and the
    evidence directories are directly under it. An unrelated directory -- the
    classic case being the operator's home -- does not match, which is the
    answer that matters: the failure mode here is deleting the wrong thing, not
    failing to delete the right one.
    """
    for probe in ("var/lib/cowrie", "var/log/cowrie", "etc/cowrie.cfg", "venv/bin/cowrie"):
        if (path / probe).exists():
            return True
    return False


def write_marker(path: Path, marker: str, note: str) -> None:
    """Record that this directory is this package's output, for the next run."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        (path / marker).write_text(note.rstrip("\n") + "\n", encoding="utf-8")
    except OSError:
        # A read-only or unusual filesystem must not fail the build; the next
        # run simply has one less piece of evidence and may ask for --force.
        pass


def guard_delete_target(path: Path, *, kind: str, allow_force: bool = False) -> Path:
    """
    Return the resolved path to delete, or raise UnsafePathError.

    `kind` is one of:
      profile-output  a generated profile (realism/build_profile.py)
      bundle-output   a staging bundle (dashboard/bundle.py)
      state-dir       the honeypot state directory (deploy/uninstall.sh)

    `allow_force` authorises deleting a directory that does not look like this
    package's output. It does NOT authorise deleting a system directory, a
    mount point or the working directory; those are refused either way.
    """
    if not str(path).strip():
        raise UnsafePathError("refusing to delete an empty path")

    resolved = Path(os.path.realpath(path))
    problems = _structural_problems(path)
    if problems:
        raise UnsafePathError(
            f"refusing to delete {resolved}: " + "; ".join(problems) +
            ". This is refused even with a force flag, because deleting it "
            "would damage the host rather than replace a build artefact.")

    if not resolved.exists():
        return resolved  # nothing to delete yet; the caller recreates it

    if kind == "profile-output":
        recognisable = _has_marker(resolved, MARKER_PROFILE) or "build" in resolved.parts
        what = ("a generated profile directory (no " + MARKER_PROFILE +
                " marker from an earlier run, and it is not under a directory "
                "named 'build')")
    elif kind == "bundle-output":
        try:
            empty = not any(resolved.iterdir())
        except OSError:
            empty = False
        recognisable = (empty or _has_marker(resolved, MARKER_BUNDLE)
                        or (resolved / "BUNDLE.json").is_file()
                        or (resolved / "manifest.json").is_file())
        what = ("a bundle staging directory (not empty, and no BUNDLE.json "
                "or " + MARKER_BUNDLE + " marker from an earlier run)")
    elif kind == "state-dir":
        recognisable = looks_like_state_dir(resolved) or str(resolved) == DEFAULT_STATE_DIR
        what = ("a honeypot state directory (no var/lib/cowrie, etc/cowrie.cfg "
                "or venv/bin/cowrie, and not the default " + DEFAULT_STATE_DIR + ")")
    else:
        raise UnsafePathError(f"unknown guard kind {kind!r}")

    if not recognisable and not allow_force:
        raise UnsafePathError(
            f"refusing to delete {resolved}: it does not look like {what}.\n"
            f"If that path really is this package's output, re-run with the "
            f"force flag; if it is anything else, you have just avoided "
            f"deleting it.")
    return resolved
