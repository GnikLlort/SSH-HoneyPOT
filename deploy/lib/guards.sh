#!/usr/bin/env bash
# shellcheck shell=bash
# =============================================================================
# Delete guards for the deployment scripts.
# =============================================================================
# Sourced by deploy/uninstall.sh. This is the shell half of
# shared/safe_paths.py: the same rules, because the operation they protect is
# the same one -- recursively deleting a directory whose name arrived as an
# argument.
#
# WHY
#   `uninstall.sh --remove` ends in `rm -rf "$STATE_DIR"`. The script checks
#   that it is running as root, and that the operator passed
#   --i-understand-this-destroys-evidence, but nothing checked *what*
#   "$STATE_DIR" named. STATE_DIR is overridable in /etc/cowrie-logship.env,
#   which is sourced earlier, so a typo there turns the documented cleanup into
#   the destruction of whatever that path actually is.
#
# WHAT IS REFUSED UNCONDITIONALLY (even with --force-path)
#   /, a system directory, a one-component path, a symlink, a mount point or a
#   tree containing one, the current working directory or an ancestor of it.
#   A force flag exists to override "this does not look like ours", never to
#   authorise damage to the host.
# =============================================================================

# Keep in step with DEFAULT_STATE_DIR in shared/safe_paths.py and with the
# default in versions.env; tests/test_safety_guards.py asserts all three agree.
: "${DEFAULT_STATE_DIR:=/opt/cowrie}"

_SYSTEM_DIRS=" /bin /boot /dev /etc /home /lib /lib32 /lib64 /media /mnt /opt /proc /root /run /sbin /srv /sys /tmp /usr /var "
_SHARED_TOP_LEVEL=" /opt /usr /var /etc /home "

# Mirror of safe_paths.looks_like_state_dir().
looks_like_state_dir() {
    local dir="$1"
    local probe
    for probe in var/lib/cowrie var/log/cowrie etc/cowrie.cfg venv/bin/cowrie; do
        [[ -e "$dir/$probe" ]] && return 0
    done
    return 1
}

# Refuse if the tree contains a mount point. Deleting through a mount point
# deletes what is mounted there -- which lives somewhere else entirely.
_contains_mount_point() {
    local resolved="$1"
    [[ -r /proc/self/mountinfo ]] || return 1
    awk -v t="$resolved/" 'index($5, t) == 1 { found = 1 } END { exit(found ? 0 : 1) }' \
        /proc/self/mountinfo
}

# guard_delete_target_state_dir <path> <force 0|1>
# Prints the reason and returns 1 when the path must not be deleted.
# Prints the resolved path on success so the caller deletes what was checked,
# not the raw string it passed in.
guard_delete_target_state_dir() {
    local dir="${1:-}" force="${2:-0}"
    local resolved

    if [[ -z "$dir" || "$dir" == " " ]]; then
        echo "refusing to delete an empty path" >&2
        return 1
    fi
    if ! resolved="$(realpath -m -- "$dir" 2>/dev/null)"; then
        echo "refusing to delete $dir: the path cannot be resolved" >&2
        return 1
    fi

    local hard=""
    if [[ "$resolved" == "/" ]]; then
        hard="/ is the filesystem root"
    elif [[ "$_SYSTEM_DIRS" == *" $resolved "* ]]; then
        hard="$resolved is a system directory"
    elif [[ "$_SHARED_TOP_LEVEL" == *" $resolved "* ]]; then
        hard="$resolved is a shared top-level directory"
    elif [[ "$resolved" != /*/* ]]; then
        hard="$resolved is a one-component path"
    elif [[ -L "$dir" ]]; then
        hard="$dir is a symlink; delete the link, not its target"
    elif [[ "$PWD" == "$resolved" ]]; then
        hard="$resolved is the current working directory"
    elif [[ "$PWD" == "$resolved"/* ]]; then
        hard="$resolved is an ancestor of the current working directory"
    elif command -v mountpoint >/dev/null 2>&1 && mountpoint -q -- "$resolved"; then
        hard="$resolved is a mount point"
    elif _contains_mount_point "$resolved"; then
        hard="$resolved contains a mount point"
    fi
    if [[ -n "$hard" ]]; then
        echo "refusing to delete $resolved: $hard." >&2
        echo "This is refused even with --force-path: deleting it would damage" >&2
        echo "the host rather than remove a honeypot deployment." >&2
        return 1
    fi

    if [[ "$resolved" != "$DEFAULT_STATE_DIR" ]] && ! looks_like_state_dir "$resolved"; then
        if [[ "$force" != "1" ]]; then
            echo "refusing to delete $resolved: it does not look like a honeypot" >&2
            echo "state directory (no var/lib/cowrie, etc/cowrie.cfg or" >&2
            echo "venv/bin/cowrie, and not the default $DEFAULT_STATE_DIR)." >&2
            echo "If that path really is this honeypot's state directory, re-run" >&2
            echo "with --force-path; if it is anything else, you have just" >&2
            echo "avoided deleting it." >&2
            return 1
        fi
    fi

    printf '%s\n' "$resolved"
    return 0
}
