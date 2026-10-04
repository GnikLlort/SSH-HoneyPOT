#!/usr/bin/env bash
# =============================================================================
# Alert dispatch. Installs to /usr/local/sbin/alert_dispatch.sh
# Usage: alert_dispatch.sh <event_key> <message>
# =============================================================================
# Delivers to whatever ALERT_WEBHOOK is configured in
# /etc/cowrie-logship.env. Nothing is sent anywhere by default: an unset
# webhook logs locally and exits, so a misconfigured deployment is silent
# rather than accidentally exfiltrating to an unknown endpoint.
#
# WHAT IS AND IS NOT SENT
# The alert payload contains: the event key, the message, the sensor name and
# a UTC timestamp. It deliberately does NOT contain captured commands,
# credentials or file contents. An alerting channel is usually lower-assurance
# than the evidence store (chat, email, SMS), so evidence stays out of it and
# the alert only tells a human to go and look.
# =============================================================================
set -euo pipefail

EVENT_KEY="${1:-unknown}"
MESSAGE="${2:-}"

# Load webhook configuration if present.
if [[ -f /etc/cowrie-logship.env ]]; then
    # shellcheck source=/dev/null
    set -a; source /etc/cowrie-logship.env; set +a
fi

SENSOR="$(hostname -s 2>/dev/null || echo unknown)"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

SEVERITY="warning"
case "$EVENT_KEY" in
    service_down|disk_critical|isolation_broken|quarantine_critical) SEVERITY="critical" ;;
    session_accepted|file_upload|disk_warn|quarantine_warn) SEVERITY="notice" ;;
esac

payload="$(cat <<JSON
{"source":"cowrie-honeypot","sensor":"$SENSOR","event":"$EVENT_KEY",
 "severity":"$SEVERITY","message":"$MESSAGE","timestamp":"$NOW"}
JSON
)"

echo "[$NOW] $SEVERITY $EVENT_KEY: $MESSAGE" >> /var/log/cowrie-alerts.log

if [[ -z "${ALERT_WEBHOOK:-}" ]]; then
    exit 0
fi

if command -v curl >/dev/null 2>&1; then
    curl --silent --show-error --max-time 10 \
         --header 'Content-Type: application/json' \
         --data "$payload" "$ALERT_WEBHOOK" >/dev/null 2>&1 || {
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] failed to deliver alert via webhook" \
            >> /var/log/cowrie-alerts.log
        exit 1
    }
fi
