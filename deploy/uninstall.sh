#!/usr/bin/env bash
# =============================================================================
# Remove the honeypot from a host.
# =============================================================================
# Two modes, because "roll back" and "destroy everything" are different
# operations and confusing them destroys evidence.
#
#   ./uninstall.sh --stop        Stop and disable the service, keep all data.
#   ./uninstall.sh --remove      Stop, then delete the service account, the
#                                state directory and every captured file.
#
# --remove PRINTS WHAT IT WILL DELETE and requires --i-understand-this-destroys-evidence.
# Before anything is deleted the state directory is checked by
# deploy/lib/guards.sh: it must look like a honeypot state directory, and it
# must not be a system directory, a mount point or a symlink. A STATE_DIR that
# is none of those things is refused; --force-path overrides only that
# ownership check, never the structural one.
#
# Captured files and session recordings are security evidence. Deleting them is
# irreversible. Export first: ops/quarantine_sync.sh
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$REPO_ROOT/deploy/versions.env"
# shellcheck source=/dev/null
source "$REPO_ROOT/deploy/lib/guards.sh"

MODE=""
CONFIRMED=0
FORCE_PATH=0
for arg in "$@"; do
    case "$arg" in
        --stop) MODE="stop" ;;
        --remove) MODE="remove" ;;
        --i-understand-this-destroys-evidence) CONFIRMED=1 ;;
        --force-path) FORCE_PATH=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    esac
done

[[ -n "$MODE" ]] || { echo "specify --stop or --remove"; exit 1; }
[[ "$(id -u)" -eq 0 ]] || { echo "must run as root"; exit 1; }

log() { echo "  $*"; }

echo "=== Stopping the honeypot ==="
# Disabling before deleting means a reboot cannot resurrect a half-removed
# service that then fails in a confusing way.
log "disable and stop the timers and service"
systemctl disable --now cowrie-logship.timer cowrie-healthcheck.timer 2>/dev/null || true
systemctl disable --now cowrie.service 2>/dev/null || true
# Cowrie's reactor can ignore SIGTERM when wedged; give it a moment then force.
log "wait for the process to exit"
for _ in $(seq 1 20); do
    systemctl is-active --quiet cowrie.service || break
    sleep 0.5
done
systemctl stop cowrie.service 2>/dev/null || true
log "service stopped"

if [[ "$MODE" == "stop" ]]; then
    echo
    echo "Service stopped and disabled. Everything under $STATE_DIR is untouched."
    echo "Re-enable with:  systemctl enable --now cowrie.service"
    echo "Captured evidence is still in $STATE_DIR/var/lib/cowrie/downloads"
    exit 0
fi

echo
echo "=== Removing the deployment ==="
echo
echo "This will DELETE:"
du -sh "$STATE_DIR" 2>/dev/null | sed 's/^/  /' || true
echo "  $STATE_DIR/var/lib/cowrie/downloads   (captured files)"
echo "  $STATE_DIR/var/lib/cowrie/tty         (session recordings)"
echo "  $STATE_DIR/var/log/cowrie             (event logs)"
echo "  $STATE_DIR/venv, $STATE_DIR/build     (application)"
echo "and the service account '$HONEYPOT_USER'."
echo
if [[ "$CONFIRMED" -ne 1 ]]; then
    echo "Refusing to continue without --i-understand-this-destroys-evidence"
    echo
    echo "Export the evidence first:"
    echo "  sudo /usr/local/sbin/quarantine_sync.sh"
    exit 1
fi

log "remove the systemd units"
rm -f /etc/systemd/system/cowrie.service \
      /etc/systemd/system/cowrie-healthcheck.service \
      /etc/systemd/system/cowrie-healthcheck.timer \
      /etc/systemd/system/cowrie-logship.service \
      /etc/systemd/system/cowrie-logship.timer
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

log "remove the helper scripts and logrotate policy"
rm -f /usr/local/sbin/healthcheck.sh /usr/local/sbin/quarantine_sync.sh \
      /usr/local/sbin/canary_scan.sh /usr/local/sbin/alert_dispatch.sh \
      /usr/local/sbin/prune_local.sh
rm -f /etc/logrotate.d/cowrie

log "delete the state directory"
# The path is checked before anything is removed, and the check returns the
# resolved path so the delete acts on what was examined -- not on the raw
# string that arrived from versions.env or /etc/cowrie-logship.env.
if ! RESOLVED_STATE_DIR="$(guard_delete_target_state_dir "$STATE_DIR" "$FORCE_PATH")"; then
    echo
    echo "Nothing was deleted. The systemd units and helper scripts were already"
    echo "removed by the steps above; re-run with the path corrected, or pass"
    echo "--force-path if the refusal is wrong."
    exit 1
fi
rm -rf "$RESOLVED_STATE_DIR"

log "remove the service account"
if id -u "$HONEYPOT_USER" >/dev/null 2>&1; then
    userdel "$HONEYPOT_USER" 2>/dev/null || true
fi

echo
echo "Host is clean. Nothing outside $STATE_DIR, /usr/local/sbin and"
echo "/etc/systemd/system was modified by this package."
echo
echo "REVIEW THESE MANUALLY:"
echo "  * AWS Security Group rules opening tcp/$HONEYPOT_PORT"
echo "  * Route table entries you added for the honeypot subnet"
echo "  * The S3 bucket and IAM role used for evidence shipping"
echo "  * The EC2 instance itself"
echo "Nothing above was changed automatically, because deleting cloud"
echo "resources is outside what a script on the host should decide."
