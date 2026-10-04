#!/usr/bin/env bash
# =============================================================================
# Honeypot health check. Installs to /usr/local/sbin/healthcheck.sh
# Run by: cowrie-healthcheck.timer every 5 minutes.
# =============================================================================
# Answers one question: "is the honeypot still collecting evidence?"
#
# A honeypot that is up but no longer recording looks identical to a quiet one
# from the outside. These checks detect the failure modes actually observed in
# testing (see docs/09-test-results.md):
#
#   1. Process gone / service failed.
#   2. Listening but not answering the SSH handshake. Observed when the
#      reactor is wedged by a pathological command: the socket accepts the TCP
#      connection and then never sends a banner, so a port check alone passes.
#   3. The event log stopped growing.
#   4. The disk is filling with captured files.
#   5. Unexpected outbound connections (the honeypot should make none while
#      idle, apart from the log shipper).
#   6. The honeypot service account can see real host files.
# =============================================================================
set -uo pipefail

STATE_DIR="${STATE_DIR:-/opt/cowrie}"
PORT="${HONEYPOT_PORT:-22}"
ALERT=/usr/local/sbin/alert_dispatch.sh
STATE_FILE=/run/cowrie-healthcheck.state
LOG_FILE=/var/log/cowrie-healthcheck.log

mkdir -p "$(dirname "$LOG_FILE")"
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG_FILE" >/dev/null; }
alert() { local key="$1" msg="$2"; log "ALERT $key: $msg"; [[ -x "$ALERT" ]] && "$ALERT" "$key" "$msg" || true; }

# De-duplicate: raise each distinct problem at most once per hour, so a
# persistent fault does not generate 288 alerts a day and train everyone to
# ignore them.
should_alert() {
    local key="$1" now last
    now="$(date +%s)"
    last="$(awk -v k="$key" '$1==k {print $2}' "$STATE_FILE" 2>/dev/null)"
    if [[ -n "${last:-}" ]] && (( now - last < 3600 )); then
        return 1
    fi
    touch "$STATE_FILE"
    awk -v k="$key" '$1!=k' "$STATE_FILE" > "${STATE_FILE}.tmp" 2>/dev/null || true
    mv "${STATE_FILE}.tmp" "$STATE_FILE" 2>/dev/null || true
    echo "$key $now" >> "$STATE_FILE"
    return 0
}

failures=0

# -- 1. Service health --------------------------------------------------------
if ! systemctl is-active --quiet cowrie.service; then
    alert service_down "cowrie.service is not active"
    failures=$((failures + 1))
fi

# -- 2. The honeypot actually speaks SSH --------------------------------------
# Reading the banner is the only check that distinguishes "listening" from
# "processing". A wedged reactor accepts connections and then goes silent.
#
# Read ONE LINE, not a fixed byte count. The banner is ~38 bytes and the
# honeypot then waits for the client's identification string, so a
# `head -c 128` style read never reaches its count: it blocks until the
# outer timeout kills it, and its buffered output is lost with it. That made
# this check report "no banner" - and therefore "reactor wedged" - on a
# perfectly healthy honeypot, every time. A line-oriented read returns as soon
# as the CRLF arrives.
read_banner() {
    local port="$1" wait="$2" line=""
    exec 3<>"/dev/tcp/127.0.0.1/$port" 2>/dev/null || return 1
    if ! IFS= read -r -t "$wait" line <&3; then
        exec 3<&- 2>/dev/null || true
        exec 3>&- 2>/dev/null || true
        return 1
    fi
    exec 3<&- 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
    printf '%s' "${line%$'\r'}"
}

banner="$(read_banner "$PORT" 8 2>/dev/null || true)"
if [[ -z "$banner" ]]; then
    if should_alert ssh_no_banner; then
        alert ssh_no_banner "port $PORT accepts TCP but sent no SSH banner within 8s (reactor wedged?)"
    fi
    failures=$((failures + 1))
elif [[ "$banner" != SSH-2.0-* ]]; then
    if should_alert ssh_bad_banner; then
        alert ssh_bad_banner "port $PORT sent an unexpected banner: ${banner:0:80}"
    fi
    failures=$((failures + 1))
fi

# -- 3. The event log is still growing ----------------------------------------
JSON_LOG="$STATE_DIR/var/log/cowrie/cowrie.json"
if [[ -f "$JSON_LOG" ]]; then
    age=$(( $(date +%s) - $(stat -c %Y "$JSON_LOG") ))
    # 24h without a single event on a public honeypot means something is wrong.
    if (( age > 86400 )); then
        if should_alert log_stale; then
            alert log_stale "no events written to cowrie.json for $((age / 3600))h"
        fi
        failures=$((failures + 1))
    fi
    if [[ ! -s "$JSON_LOG" ]]; then
        log "NOTE: cowrie.json exists but is empty (may be a fresh deployment)"
    fi
else
    alert log_missing "cowrie.json not found at $JSON_LOG"
    failures=$((failures + 1))
fi

# -- 4. Disk usage ------------------------------------------------------------
avail_pct="$(df --output=pcent "$STATE_DIR" 2>/dev/null | tail -1 | tr -dc '0-9')"
if [[ -n "$avail_pct" ]]; then
    if (( avail_pct >= 92 )); then
        alert disk_critical "filesystem ${avail_pct}% full"
        failures=$((failures + 1))
    elif (( avail_pct >= 80 )); then
        alert disk_warn "filesystem ${avail_pct}% full"
    fi
fi

DL_MB="$(du -sm "$STATE_DIR/var/lib/cowrie/downloads" 2>/dev/null | awk '{print $1}')"
if [[ -n "${DL_MB:-}" ]]; then
    if (( DL_MB >= ${QUARANTINE_CRITICAL_MB:-4096} )); then
        alert quarantine_critical "captured files total ${DL_MB} MB"
        failures=$((failures + 1))
    elif (( DL_MB >= ${QUARANTINE_WARN_MB:-2048} )); then
        alert quarantine_warn "captured files total ${DL_MB} MB"
    fi
fi

# -- 5. Unexpected outbound traffic -------------------------------------------
# The honeypot should make no outbound connections while idle except to the
# evidence store and the package mirror during updates. Sample two seconds of
# established connections.
if command -v ss >/dev/null 2>&1; then
    outbound="$(ss -tnH state established '( dport = :443 or dport = :22 or dport = :80 )' 2>/dev/null \
        | grep -v '127.0.0.1' | grep -v '::1' || true)"
    if [[ -n "$outbound" ]] && ! systemctl is-active --quiet cowrie-logship.service; then
        if should_alert outbound_unexpected; then
            alert outbound_unexpected "connections observed while idle: $(echo "$outbound" | head -3 | tr '\n' ';')"
        fi
    fi
fi

# -- 6. The service account cannot see host data ------------------------------
# If this ever fires, the isolation has failed and the deployment must be
# treated as compromised.
if id -u cowrie >/dev/null 2>&1; then
    if sudo -u cowrie test -r /etc/shadow 2>/dev/null; then
        alert isolation_broken "the cowrie account can read /etc/shadow"
        failures=$((failures + 1))
    fi
    if sudo -u cowrie test -r /root 2>/dev/null; then
        alert isolation_broken "the cowrie account can read /root"
        failures=$((failures + 1))
    fi
fi

# -- 7. Agent-installed paths must not exist ----------------------------------
for forbidden in /opt/cowrie/honeyfs /opt/cowrie/src; do
    if [[ -e "$forbidden" ]]; then
        log "NOTE: $forbidden exists (expected only in a source checkout)"
    fi
done

if (( failures == 0 )); then
    log "healthy (banner: ${banner:0:40})"
    exit 0
fi
log "unhealthy: $failures check(s) failed"
exit 1
