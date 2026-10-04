#!/usr/bin/env bash
# =============================================================================
# Rebuild the honeypot from scratch, preserving evidence.
# =============================================================================
# The documented recovery path when a host is suspected compromised, when a
# version pin changes, or when the profile is edited.
#
# Preserving evidence is the whole point:
#   * Logs and captured files are exported to the evidence store FIRST.
#   * The quarantined originals are never deleted until the export is verified.
#   * The rebuild happens on a NEW instance; the old one is terminated, not
#     reused. A honeypot host that has been interacted with is not trustworthy.
#
# Usage:
#   ./rebuild.sh --export-only            # ship evidence, stop.
#   ./rebuild.sh --export-only --verify   # ship, then verify the export.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$REPO_ROOT/deploy/versions.env"

EXPORT_ONLY=0
VERIFY=0
for arg in "$@"; do
    case "$arg" in
        --export-only) EXPORT_ONLY=1 ;;
        --verify) VERIFY=1 ;;
    esac
done

[[ "$(id -u)" -eq 0 ]] || { echo "must run as root"; exit 1; }

echo "=== Evidence export (always first) ==="
if [[ -x /usr/local/sbin/quarantine_sync.sh ]]; then
    /usr/local/sbin/quarantine_sync.sh || {
        echo "Export failed. DO NOT proceed with the rebuild:"
        echo "deleting the source before the copy is verified destroys evidence."
        exit 1
    }
else
    echo "quarantine_sync.sh not installed; skipping automated export."
    echo "MANUALLY copy $STATE_DIR/var/lib/cowrie and $STATE_DIR/var/log before continuing."
fi

if [[ "$VERIFY" -eq 1 ]]; then
    echo "=== Verifying the export ==="
    # Counts must match on both sides. A partial export is worse than none,
    # because it looks complete.
    local_logs=$(find "$STATE_DIR/var/log/cowrie" -type f 2>/dev/null | wc -l)
    local_files=$(find "$STATE_DIR/var/lib/cowrie/downloads" -type f 2>/dev/null | wc -l)
    echo "  local log files:     $local_logs"
    echo "  local captured files: $local_files"
    echo "  Confirm these counts against the evidence store before continuing."
fi

if [[ "$EXPORT_ONLY" -eq 1 ]]; then
    echo "Export complete. No changes made to this host."
    exit 0
fi

cat <<'NEXT'
=== Rebuild ===
Rebuilding on this host is NOT the supported path. The supported sequence is:

  1. Verify the evidence export above.
  2. Note the pinned commit from versions.env:
       COWRIE_COMMIT
  3. Terminate this instance (AWS console, or:
       aws ec2 terminate-instances --instance-ids <id>)
  4. Launch a NEW Ubuntu LTS instance in the same isolated subnet.
  5. Run the install guide from the top: docs/03-install-ubuntu-ec2.md
  6. Confirm the new instance passes the conformance suite before it receives
     any traffic.

Why a new instance: a honeypot that has been interacted with has had
attacker-controlled input parsed by a network service. Rebuilding on the same
host would carry any compromise forward into the "clean" deployment.
NEXT
