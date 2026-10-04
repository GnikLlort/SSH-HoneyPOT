#!/usr/bin/env bash
# Small helpers for driving the local Cowrie lab instance during testing.
#
# Deliberately avoids `pkill -f twistd`: the pattern also matches the shell
# running the command, which kills the test harness itself. We resolve the
# PID from the pidfile instead, and fall back to scanning /proc for a
# twistd process whose cwd is the lab directory.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB_DIR="${LAB_DIR:-$REPO_ROOT/lab}"
VENV="$REPO_ROOT/.venv"

lab_stop() {
    local pid=""
    if [[ -f "$LAB_DIR/var/run/cowrie.pid" ]]; then
        pid="$(cat "$LAB_DIR/var/run/cowrie.pid" 2>/dev/null || true)"
    fi
    if [[ -z "$pid" ]]; then
        # Find a twistd started from this repo without matching our own cmdline.
        for candidate in /proc/[0-9]*; do
            [[ -r "$candidate/cmdline" ]] || continue
            if tr '\0' ' ' < "$candidate/cmdline" 2>/dev/null | grep -q "venv/bin/twistd"; then
                local cwd
                cwd="$(readlink -f "$candidate/cwd" 2>/dev/null || true)"
                if [[ "$cwd" == "$LAB_DIR" ]]; then
                    pid="${candidate#/proc/}"
                    break
                fi
            fi
        done
    fi
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.25
        done
        # A wedged reactor ignores SIGTERM. This is a documented failure mode
        # (see docs/10-assumptions-limitations-detection.md), so force it.
        if kill -0 "$pid" 2>/dev/null; then
            echo "lab_stop: PID $pid ignored SIGTERM (wedged reactor); sending SIGKILL" >&2
            kill -KILL "$pid" 2>/dev/null || true
            sleep 1
        fi
    fi
    rm -f "$LAB_DIR/var/run/cowrie.pid"
}

lab_start() {
    mkdir -p "$LAB_DIR/var/log/cowrie" "$LAB_DIR/var/lib/cowrie/downloads" \
             "$LAB_DIR/var/lib/cowrie/tty" "$LAB_DIR/var/run"
    # PYTHONPATH loads the optional realism overlay via sitecustomize.
    # COWRIE_REALISM_OVERLAY=1 enables it; unset both to run stock Cowrie.
    ( cd "$LAB_DIR" && PATH="$VENV/bin:$PATH" \
        PYTHONPATH="$REPO_ROOT/overlays/cowrie_realism_overlay" \
        COWRIE_REALISM_OVERLAY="${COWRIE_REALISM_OVERLAY:-1}" \
        "$VENV/bin/cowrie" start >/dev/null 2>&1 )
    for _ in $(seq 1 40); do
        if "$VENV/bin/python" - <<'PY' 2>/dev/null
import socket, sys
s = socket.socket(); s.settimeout(0.5)
sys.exit(0 if s.connect_ex(("127.0.0.1", 2222)) == 0 else 1)
PY
        then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

lab_restart() {
    lab_stop
    sleep 0.5
    lab_start
}

"$@"
