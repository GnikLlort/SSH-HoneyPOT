#!/usr/bin/env bash
# Small helpers for driving the local Cowrie lab instance during testing.
#
# Deliberately avoids `pkill -f twistd`: the pattern also matches the shell
# running the command, which kills the test harness itself. We resolve the
# PID from the pidfile instead, and fall back to scanning /proc for a
# twistd process whose cwd is the lab directory.
#
# Commands:
#   lab_init     materialise the lab from build/profile + config/ (idempotent)
#   lab_start    start Cowrie on 127.0.0.1:2222 (initialises the lab if needed)
#   lab_stop     stop it
#   lab_restart  stop, then start
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB_DIR="${LAB_DIR:-$REPO_ROOT/lab}"
VENV="${VENV:-$REPO_ROOT/.venv}"
PROFILE_DIR="${PROFILE_DIR:-$REPO_ROOT/build/profile}"

# ---------------------------------------------------------------------------
# lab_init - build the lab state directory from the generated profile.
# ---------------------------------------------------------------------------
# The lab is a loopback instance of exactly the deployment: the same generated
# filesystem, process table, txtcmd overrides, credential policy and operator
# config, with two deliberate differences - it listens on 127.0.0.1:2222
# instead of 0.0.0.0:22, and it runs as the invoking user rather than the
# `cowrie` service account.
#
# It is idempotent: re-running it refreshes the lab from the current
# build/profile, which is what you want after editing realism/identity.yaml.
lab_init() {
    if [[ ! -x "$VENV/bin/cowrie" ]]; then
        echo "lab_init: no Cowrie in $VENV" >&2
        echo "lab_init: run:  python3 -m venv .venv && .venv/bin/pip install 'cowrie @ git+https://github.com/cowrie/cowrie@6ec36d0d5d4a1a14bc6e6ddadcb7b8f255e0570b'" >&2
        return 1
    fi
    if [[ ! -f "$PROFILE_DIR/fs.pickle" || ! -f "$PROFILE_DIR/expectations.json" ]]; then
        echo "lab_init: no built profile at $PROFILE_DIR" >&2
        echo "lab_init: run:  $VENV/bin/python realism/build_profile.py --identity realism/identity.yaml --out build/profile" >&2
        return 1
    fi

    # Files are swapped underneath a running Cowrie, so stop it first.
    if [[ -f "$LAB_DIR/var/run/cowrie.pid" ]] \
        && kill -0 "$(cat "$LAB_DIR/var/run/cowrie.pid" 2>/dev/null || echo 0)" 2>/dev/null; then
        echo "lab_init: stopping the running lab first"
        lab_stop
    fi

    mkdir -p "$LAB_DIR/etc" "$LAB_DIR/share" "$LAB_DIR/share/synthetic" \
             "$LAB_DIR/var/log/cowrie" "$LAB_DIR/var/lib/cowrie/downloads" \
             "$LAB_DIR/var/lib/cowrie/tty" "$LAB_DIR/var/run"

    # Operator config: the same `<state>` substitution install.sh performs,
    # plus the loopback listener and the lab port.
    sed -e "s|<state>|$LAB_DIR|g" \
        -e 's|^listen_endpoints = .*|listen_endpoints = tcp:2222:interface=127.0.0.1|' \
        "$REPO_ROOT/config/cowrie.cfg" > "$LAB_DIR/etc/cowrie.cfg"

    # Generated profile: the pieces deploy/install.sh stage 7 installs.
    install -m 0644 "$PROFILE_DIR/cowrie-profile.cfg" "$LAB_DIR/etc/profile.cfg"
    install -m 0644 "$REPO_ROOT/config/userdb.txt" "$LAB_DIR/etc/userdb.txt"
    install -m 0644 "$PROFILE_DIR/fs.pickle" "$LAB_DIR/var/lib/cowrie/fs.pickle"
    install -m 0644 "$PROFILE_DIR/cmdoutput.json" "$LAB_DIR/var/lib/cowrie/cmdoutput.json"

    rm -rf "$LAB_DIR/share/txtcmds"
    mkdir -p "$LAB_DIR/share/txtcmds"
    cp -a "$PROFILE_DIR/txtcmds/." "$LAB_DIR/share/txtcmds/"

    # The unit bind-mounts this over /proc/meminfo. The lab cannot mount
    # namespaces without privileges, so here it is only checked in by the
    # realism overlay, which reads the emulated file instead. Copied for
    # parity with the deployment layout.
    install -m 0644 "$PROFILE_DIR/procfs/meminfo" "$LAB_DIR/share/synthetic/meminfo"

    echo "lab_init: $LAB_DIR initialised from $PROFILE_DIR"
}

# ---------------------------------------------------------------------------
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
    # First run: materialise the lab so the documented command sequence
    # (build_profile.py, then lab_restart) works from a clean checkout.
    if [[ ! -f "$LAB_DIR/etc/cowrie.cfg" ]]; then
        echo "lab_start: lab is not initialised; running lab_init" >&2
        lab_init || return 1
    fi

    mkdir -p "$LAB_DIR/var/log/cowrie" "$LAB_DIR/var/lib/cowrie/downloads" \
             "$LAB_DIR/var/lib/cowrie/tty" "$LAB_DIR/var/run"

    local start_log="$LAB_DIR/var/log/cowrie/lab-start.log"
    # PYTHONPATH loads the optional realism overlay via sitecustomize.
    # COWRIE_REALISM_OVERLAY=1 enables it; unset both to run stock Cowrie.
    # Output is kept, not discarded: a failed start must say why.
    ( cd "$LAB_DIR" && PATH="$VENV/bin:$PATH" \
        PYTHONPATH="$REPO_ROOT/overlays/cowrie_realism_overlay" \
        COWRIE_REALISM_OVERLAY="${COWRIE_REALISM_OVERLAY:-1}" \
        "$VENV/bin/cowrie" start >"$start_log" 2>&1 ) || true
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
    echo "lab_start: nothing listening on 127.0.0.1:2222 after 20s" >&2
    if [[ -s "$start_log" ]]; then
        echo "lab_start: last lines of $start_log:" >&2
        tail -n 5 "$start_log" >&2
    fi
    return 1
}

lab_restart() {
    lab_stop
    sleep 0.5
    lab_start
}

"$@"
