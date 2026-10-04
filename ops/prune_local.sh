#!/usr/bin/env bash
# =============================================================================
# Enforce the local retention policy. Installs to /usr/local/sbin/prune_local.sh
# Usage: prune_local.sh [retention_days]
# =============================================================================
# The honeypot host is a staging area, not an archive. This deletes local
# copies that are older than the retention window.
#
# SAFETY: it only ever deletes from inside the honeypot state directory, and it
# refuses to run if that directory looks wrong. A retention script that follows
# a symlink or a bad variable is how an operator deletes something they
# needed.
# =============================================================================
set -euo pipefail

STATE_DIR="${STATE_DIR:-/opt/cowrie}"
RETENTION_DAYS="${1:-${RETENTION_DAYS_LOCAL:-30}}"

case "$STATE_DIR" in
    /opt/cowrie|/srv/cowrie) ;;
    *) echo "refusing to run: STATE_DIR '$STATE_DIR' is not a recognised honeypot directory"; exit 1 ;;
esac
[[ -d "$STATE_DIR" ]] || { echo "STATE_DIR does not exist"; exit 1; }
[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || { echo "retention days must be an integer"; exit 1; }

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] prune: $*"; }

# Captured files age out first; they are already shipped.
for sub in downloads tty; do
    dir="$STATE_DIR/var/lib/cowrie/$sub"
    [[ -d "$dir" ]] || continue
    before=$(find "$dir" -type f 2>/dev/null | wc -l)
    # -xdev stops the walk at a filesystem boundary.
    find "$dir" -xdev -type f -mtime "+$RETENTION_DAYS" -delete 2>/dev/null || true
    after=$(find "$dir" -type f 2>/dev/null | wc -l)
    log "$sub: removed $((before - after)) file(s) older than ${RETENTION_DAYS}d"
done

# Older rotated logs.
find "$STATE_DIR/var/log/cowrie" -xdev -type f -name 'cowrie.log-*' \
     -mtime "+$RETENTION_DAYS" -delete 2>/dev/null || true

log "done"
