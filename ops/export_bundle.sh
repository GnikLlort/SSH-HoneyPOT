#!/usr/bin/env bash
# =============================================================================
# Build an export bundle from the honeypot's state directory and ship it.
# =============================================================================
# Installs to: /usr/local/sbin/export_bundle.sh
# Run by:      cowrie-bundle-ship.timer (optional, NOT enabled by install.sh)
#
# WHY THIS EXISTS
# The monitoring dashboard (dashboard/) does not read the raw evidence layout
# that quarantine_sync.sh uploads. It ingests bundles: one manifest plus the
# event log, the recordings, and the health log, packed by dashboard/bundle.py.
# Without this step a monitoring host has nothing to ingest, and the dashboard
# is empty no matter how much traffic the honeypot sees.
#
# WHY IT IS NOT ENABLED BY DEFAULT
# It is a second egress path for evidence, and it carries the event log and the
# session recordings -- which contain captured credentials -- into a second
# host. That is the point of an off-host reviewer, but it is a decision the
# operator makes deliberately, not one an installer makes for them:
#
#     sudo systemctl enable --now cowrie-bundle-ship.timer
#
# CAPTURED FILES ARE NOT INCLUDED BY DEFAULT
# `--no-downloads` is the default here, and the bytes are the reason. The
# dashboard shows uploads by metadata and hash and has no code path that opens
# them (docs/15), so shipping the bytes puts captured malware on the reviewer
# host for no functional gain. Metadata still arrives through the event log.
# Pass --with-downloads to include them, on a host you are willing to treat as
# contaminated.
#
# The bundle is uploaded to the SAME evidence bucket as quarantine_sync.sh,
# under .../<sensor>/bundles/<UTC stamp>/, with a .sha256 beside it.
# =============================================================================
set -euo pipefail

STATE_DIR="${STATE_DIR:-/opt/cowrie}"
# shellcheck source=/dev/null
source "${REPO_ROOT:-$STATE_DIR/share/pkg}/deploy/versions.env" 2>/dev/null || true
: "${EVIDENCE_BUCKET:?EVIDENCE_BUCKET must be set in /etc/cowrie-logship.env}"
: "${EVIDENCE_PREFIX:=honeypot}"

PKG_DIR="${PKG_DIR:-$STATE_DIR/share/pkg}"
STAGING="${STAGING:-$STATE_DIR/var/spool/bundle}"
WITH_DOWNLOADS=0
NO_UPLOAD=0
KEEP_BUNDLE=0
for arg in "$@"; do
    case "$arg" in
        --with-downloads) WITH_DOWNLOADS=1 ;;
        --no-upload) NO_UPLOAD=1 ;;
        --keep) KEEP_BUNDLE=1 ;;
        --state) PREV="--state" ;;
        --state=*) STATE_DIR="${arg#--state=}" ;;
        --staging=*) STAGING="${arg#--staging=}" ;;
        -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
        *) if [[ "${PREV:-}" == "--state" ]]; then STATE_DIR="$arg"; fi ;;
    esac
    PREV="$arg"
done

SENSOR="${SENSOR:-$(hostname -s 2>/dev/null || echo unknown)}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$STAGING/$STAMP"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

[[ -d "$STATE_DIR/var/log/cowrie" ]] || {
    log "ERROR: $STATE_DIR/var/log/cowrie not found. Is this the honeypot host?"
    exit 1
}
[[ -f "$PKG_DIR/dashboard/bundle.py" ]] || {
    log "ERROR: $PKG_DIR/dashboard/bundle.py not found."
    log "       install.sh copies the package to $STATE_DIR/share/pkg."
    exit 1
}
# bundle.py is standard library only: it must not depend on the Cowrie
# virtualenv, because the virtualenv is the honeypot's and this runs beside it.
PY="${PY:-$(command -v python3)}"
[[ -n "$PY" ]] || { log "ERROR: python3 not found"; exit 1; }

# -- 1. Build the bundle ------------------------------------------------------
mkdir -p "$OUT" "$STAGING"
BUNDLE_ARGS=(--state "$STATE_DIR" --out "$OUT/bundle")
if [[ "$WITH_DOWNLOADS" -eq 0 ]]; then
    BUNDLE_ARGS+=(--no-downloads)
fi
if ! HONEYPOT_STATE_DIR="$STATE_DIR" "$PY" "$PKG_DIR/dashboard/bundle.py" \
        "${BUNDLE_ARGS[@]}" >"$OUT/bundle.log" 2>&1; then
    log "ERROR: bundle.py failed:"
    sed 's/^/    /' "$OUT/bundle.log"
    exit 1
fi
sed 's/^/    /' "$OUT/bundle.log" | tail -n +2

# -- 2. Tar it, and hash the tarball ------------------------------------------
# The hash is of the archive as shipped. A mismatch at the far end means the
# bytes changed in transit, which is the one thing a monitoring host cannot
# detect for itself.
TARBALL="$OUT/bundle.tar.gz"
tar -czf "$TARBALL" -C "$OUT" bundle
SHA="$(sha256sum "$TARBALL" | awk '{print $1}')"
printf '%s  %s\n' "$SHA" "$(basename "$TARBALL")" > "$TARBALL.sha256"
log "bundle built: $TARBALL ($(du -h "$TARBALL" | awk '{print $1}'), sha256 ${SHA:0:12}...)"

if [[ "$NO_UPLOAD" -eq 1 ]]; then
    log "not uploading (--no-upload). Bundle left at $OUT"
    exit 0
fi

# -- 3. Upload ----------------------------------------------------------------
if ! command -v aws >/dev/null 2>&1; then
    log "ERROR: aws CLI not found. The bundle is at $OUT and has NOT been shipped."
    exit 1
fi
DEST="s3://${EVIDENCE_BUCKET}/${EVIDENCE_PREFIX}/${SENSOR}/bundles/${STAMP}"
aws s3 cp --only-show-errors --sse aws:kms "$TARBALL" "$DEST/bundle.tar.gz" || {
    log "ERROR: upload failed. The bundle is at $OUT and has NOT been shipped."
    exit 1
}
aws s3 cp --only-show-errors --sse aws:kms "$TARBALL.sha256" "$DEST/bundle.tar.gz.sha256" || {
    log "ERROR: the archive uploaded but its hash did not. Do not treat this"
    log "       bundle as verified; re-run, or upload $TARBALL.sha256 by hand."
    exit 1
}
log "shipped: $DEST/bundle.tar.gz"

# -- 4. Clean up --------------------------------------------------------------
# Only after a successful upload, and only the staging copy: the source data
# under var/lib and var/log is what quarantine_sync.sh ships and what the local
# retention policy prunes. This script never touches it.
#
# The shape of $OUT is checked before it is deleted. A recursive delete on a
# path built from variables is the operation deploy/lib/guards.sh exists for
# (its own caller is uninstall.sh); this one is narrow enough to check itself:
# a UTC stamp directly under the staging directory, and nothing else.
case "$OUT" in
    "$STAGING"/20[0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;;
    *) log "ERROR: refusing to remove unexpected path: $OUT"; exit 1 ;;
esac
if [[ "$KEEP_BUNDLE" -eq 0 ]]; then
    rm -rf "$OUT"
    log "staging cleared (use --keep to keep the local copy)"
else
    log "staging kept at $OUT"
fi
