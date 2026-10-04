#!/usr/bin/env bash
# =============================================================================
# Ship honeypot evidence off the host into the encrypted evidence store.
# =============================================================================
# Installs to: /usr/local/sbin/quarantine_sync.sh
# Run by:      cowrie-logship.timer every 5 minutes
#
# WHY THIS RUNS SO OFTEN
# Evidence that only exists on the honeypot is evidence a visitor can destroy.
# Shipping every few minutes bounds how much can be lost to whatever the
# visitor is able to do, without depending on the honeypot being trustworthy.
#
# WHAT IT MOVES
#   * cowrie.json / cowrie.log   - the event record
#   * tty/                       - full session recordings
#   * downloads/                 - files captured from SCP/SFTP uploads
#   * a manifest with SHA-256 of every captured file
#
# HOW IT STORES THEM
# The destination defaults to S3 with:
#   * SSE-KMS encryption (a customer-managed key, not the default)
#   * Object Lock / versioning enabled, so a compromised honeypot cannot
#     overwrite or delete what it already shipped
#   * a bucket policy that denies s3:DeleteObject to the honeypot's role
#
# The script COPIES by default and only prunes locally after the copy is
# verified. Deleting first and copying second is how evidence gets lost.
# =============================================================================
set -euo pipefail

STATE_DIR="${STATE_DIR:-/opt/cowrie}"
# shellcheck source=/dev/null
source "${REPO_ROOT:-/opt/cowrie/share/pkg}/deploy/versions.env" 2>/dev/null || true

: "${EVIDENCE_BUCKET:?EVIDENCE_BUCKET must be set in /etc/cowrie-logship.env}"
: "${EVIDENCE_PREFIX:=honeypot}"

SENSOR="$(hostname -s 2>/dev/null || echo unknown)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="s3://${EVIDENCE_BUCKET}/${EVIDENCE_PREFIX}/${SENSOR}/${STAMP}"

LOG_DIR="$STATE_DIR/var/log/cowrie"
TTY_DIR="$STATE_DIR/var/lib/cowrie/tty"
DL_DIR="$STATE_DIR/var/lib/cowrie/downloads"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# -- 1. Build a manifest of captured files ------------------------------------
# Recording the hash at capture time, on the honeypot, means the hash travels
# with the evidence. Any later mismatch proves tampering in transit or at rest.
MANIFEST="$(mktemp)"
trap 'rm -f "$MANIFEST"' EXIT
{
    echo "# Captured-file manifest"
    echo "# sensor:  $SENSOR"
    echo "# created: $STAMP"
    echo "# sha256  size  first_seen_utc  filename"
} > "$MANIFEST"

file_count=0
if [[ -d "$DL_DIR" ]]; then
    while IFS= read -r -d '' f; do
        sha="$(sha256sum "$f" | awk '{print $1}')"
        size="$(stat -c %s "$f")"
        mtime="$(date -u -d "@$(stat -c %Y "$f")" +%Y-%m-%dT%H:%M:%SZ)"
        # The filename is attacker-controlled. It is written verbatim to the
        # manifest and NEVER passed to a shell or used as a local path.
        printf '%s  %s  %s  %s\n' "$sha" "$size" "$mtime" "$(basename "$f")" >> "$MANIFEST"
        file_count=$((file_count + 1))
    done < <(find "$DL_DIR" -type f -print0 2>/dev/null)
fi

# -- 2. Ship ---------------------------------------------------------------
if ! command -v aws >/dev/null 2>&1; then
    log "ERROR: aws CLI not found. Evidence is NOT being shipped."
    log "       Install it, or configure an alternative destination."
    exit 1
fi

log "shipping to $DEST"

# The manifest goes first: if any later copy fails, the destination still has
# a record of what should have arrived.
aws s3 cp --only-show-errors --sse aws:kms "$MANIFEST" "$DEST/manifest.txt" || {
    log "ERROR: manifest upload failed; nothing else attempted"
    exit 1
}

shipped_ok=1
for pair in "logs:$LOG_DIR" "sessions:$TTY_DIR" "downloads:$DL_DIR"; do
    label="${pair%%:*}"; src="${pair#*:}"
    [[ -d "$src" ]] || continue
    if ! aws s3 sync "$src" "$DEST/$label/" \
            --only-show-errors --sse aws:kms --exclude '*' --include '*' >/dev/null; then
        log "ERROR: failed to ship $label"
        shipped_ok=0
    fi
done

[[ "$shipped_ok" -eq 1 ]] || { log "ship incomplete; local copies retained"; exit 1; }

log "shipped $file_count captured file(s) and the log/session directories"

# -- 3. Prune locally, only after a successful ship ---------------------------
# The honeypot host is a staging area with a small disk; the evidence store is
# the archive. Retention on the host is deliberately short.
RETENTION_DAYS="${RETENTION_DAYS_LOCAL:-30}"
if command -v /usr/local/sbin/prune_local.sh >/dev/null 2>&1; then
    /usr/local/sbin/prune_local.sh "$RETENTION_DAYS" || log "WARNING: prune step failed"
fi

# Never silently succeed when the disk is nearly full - that is how a honeypot
# stops recording without anyone noticing.
avail_pct="$(df --output=pcent "$STATE_DIR" | tail -1 | tr -dc '0-9')"
if [[ -n "$avail_pct" && "$avail_pct" -ge 90 ]]; then
    log "CRITICAL: honeypot filesystem ${avail_pct}% full"
    /usr/local/sbin/alert_dispatch.sh disk_full "filesystem ${avail_pct}% full on $SENSOR" || true
fi

log "done"
