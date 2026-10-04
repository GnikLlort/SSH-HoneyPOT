#!/usr/bin/env bash
# =============================================================================
# Install the monitoring dashboard on a monitoring host.
# =============================================================================
# READ THIS BEFORE RUNNING.
#
# This is the companion to deploy/install.sh, and it is deliberately a
# different script:
#
#   * install.sh installs the HONEYPOT. It never touches the dashboard, because
#     staging the reviewer on the host under review defeats the separation
#     (docs/15 §1).
#   * this script installs the DASHBOARD, and it refuses to run on a host that
#     looks like a honeypot unless it is told to with --allow-on-honeypot.
#
# What it does, in order: checks the prerequisites, creates a service account
# and the store/spool directories, copies the package, installs and starts the
# systemd units, creates the store if it does not exist, and prints the exact
# commands for the two things it must not do for you -- choosing a password and
# reaching the user interface.
#
# It needs no network, no AWS credentials and no Python packages: the dashboard
# is standard library only.
#
#   ./install-dashboard.sh                      # show the plan (dry run)
#   sudo ./install-dashboard.sh --apply
#   sudo ./install-dashboard.sh --apply --listen 127.0.0.1:8443
#   sudo ./install-dashboard.sh --apply --store /srv/honeypot-store
#
# Re-running it is the update path: the package is re-copied, the units are
# reinstalled, and the store, accounts and evidence are left alone.
#
# THE USER INTERFACE IS NOT EXPOSED. It listens on a UNIX socket by default and
# is reached over a management path (docs/16 §4). A TCP listener is available
# for people who intend to port-forward to it, and it binds to loopback only.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$REPO_ROOT/deploy/versions.env"

MODE="dry-run"
INSTALL_DIR="${INSTALL_DIR:-/opt/honeypot-dashboard}"
STORE="${STORE_DIR:-/var/lib/honeypot-store}"
SPOOL="${SPOOL_DIR:-/var/spool/honeypot-export}"
SVC_USER="${DASHBOARD_USER:-hpmon}"
SVC_GROUP="${DASHBOARD_GROUP:-$SVC_USER}"
LISTEN="${DASHBOARD_LISTEN:-unix:/run/honeypot-dashboard/dashboard.sock}"
ALLOW_ON_HONEYPOT=0
NO_UNITS=0
for arg in "$@"; do
    case "$arg" in
        --apply) MODE="apply" ;;
        --dry-run) MODE="dry-run" ;;
        --allow-on-honeypot) ALLOW_ON_HONEYPOT=1 ;;
        --no-units) NO_UNITS=1 ;;
        --install-dir) PREV="--install-dir" ;;
        --store) PREV="--store" ;;
        --spool) PREV="--spool" ;;
        --user) PREV="--user" ;;
        --listen) PREV="--listen" ;;
        --install-dir=*) INSTALL_DIR="${arg#--install-dir=}" ;;
        --store=*) STORE="${arg#--store=}" ;;
        --spool=*) SPOOL="${arg#--spool=}" ;;
        --user=*) SVC_USER="${arg#--user=}"; SVC_GROUP="$SVC_USER" ;;
        --listen=*) LISTEN="${arg#--listen=}" ;;
        -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
        *)
            case "${PREV:-}" in
                --install-dir) INSTALL_DIR="$arg" ;;
                --store) STORE="$arg" ;;
                --spool) SPOOL="$arg" ;;
                --user) SVC_USER="$arg"; SVC_GROUP="$arg" ;;
                --listen) LISTEN="$arg" ;;
                *) echo "unknown argument: $arg" >&2; exit 2 ;;
            esac
            ;;
    esac
    PREV="$arg"
done

if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GRN=""; YEL=""; RST=""
fi

STAGE_NUM=0
stage() {
    STAGE_NUM=$((STAGE_NUM + 1))
    echo
    echo "${BOLD}=== Stage ${STAGE_NUM}: $1 ===${RST}"
}
act() {
    local why="$1"; shift
    echo "  ${DIM}why: ${why}${RST}"
    echo "  ${BOLD}\$ $*${RST}"
    if [[ "$MODE" == "dry-run" ]]; then
        echo "  ${DIM}(dry run: not executed)${RST}"
        return 0
    fi
    "$@"
}
note() { echo "  ${DIM}$*${RST}"; }
warn() { echo "  ${YEL}warning: $*${RST}"; }
die()  { echo "${RED}error: $*${RST}" >&2; exit 1; }

echo "${BOLD}Monitoring dashboard - installation${RST}"
echo "  mode:          $MODE"
echo "  repository:    $REPO_ROOT"
echo "  install to:    $INSTALL_DIR/pkg"
echo "  store:         $STORE"
echo "  bundle spool:  $SPOOL"
echo "  service user:  $SVC_USER"
echo "  listen:        $LISTEN"
if [[ "$MODE" == "dry-run" ]]; then
    echo
    echo "${YEL}DRY RUN - no changes will be made. Re-run with --apply to execute.${RST}"
fi

# ---------------------------------------------------------------------------
stage "Verify this host is a monitoring host, with a usable Python"
# ---------------------------------------------------------------------------
if [[ "$MODE" == "apply" && "$(id -u)" -ne 0 ]]; then
    die "must run as root in --apply mode"
fi

# The separation is the design (docs/15 §1). Detect the obvious case -- a
# honeypot state directory or a running cowrie unit -- and stop, naming what
# was found.
LOOKS_LIKE_HONEYPOT=""
[[ -d /opt/cowrie/var/lib/cowrie ]] && LOOKS_LIKE_HONEYPOT="/opt/cowrie/var/lib/cowrie"
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files cowrie.service 2>/dev/null | grep -q cowrie; then
    LOOKS_LIKE_HONEYPOT="${LOOKS_LIKE_HONEYPOT:-cowrie.service is installed}"
fi
if [[ -n "$LOOKS_LIKE_HONEYPOT" ]]; then
    if [[ "$ALLOW_ON_HONEYPOT" -eq 1 ]]; then
        warn "$LOOKS_LIKE_HONEYPOT -- installing beside the honeypot anyway (--allow-on-honeypot)"
        warn "this is supported for local evaluation only: the reviewer then lives on the host it reviews"
    else
        die "this looks like the honeypot host ($LOOKS_LIKE_HONEYPOT).
       The dashboard belongs on a separate instance (docs/15 §1). If you are
       evaluating it on one host, re-run with --allow-on-honeypot and accept
       that the separation is gone."
    fi
fi

for tool in python3 rsync; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required.
       On Ubuntu:  sudo apt-get install -y --no-install-recommends $tool"
done

PYBIN="$(command -v python3 || true)"
[[ -n "$PYBIN" ]] || die "python3 not found"
PY_VER="$("$PYBIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
note "python3 version: $PY_VER ($PYBIN)"
if ! "$PYBIN" - <<'PY'
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
then
    die "python3 >= 3.11 is required (found $PY_VER)"
fi
# hash_password() uses hashlib.scrypt. It exists in CPython built against
# OpenSSL 1.1+, but NOT when built against LibreSSL -- and an account that
# cannot be created is a confusing way to discover that.
if ! "$PYBIN" -c 'import hashlib; hashlib.scrypt' 2>/dev/null; then
    die "this Python has no hashlib.scrypt (built against LibreSSL?).
       Account creation would fail later with a less clear message."
fi
note "hashlib.scrypt is available"

if [[ "$LISTEN" == unix:* && -z "${LISTEN#unix:}" ]]; then
    die "--listen unix: needs a path"
fi
case "$LISTEN" in
    unix:*) : ;;
    *)
        hostpart="${LISTEN%%:*}"
        case "$hostpart" in
            127.0.0.1|::1|localhost) : ;;
            *) die "refusing to bind $hostpart. The dashboard shows captured
       credentials. Bind loopback (127.0.0.1:8443), or use the default UNIX
       socket and reach it over SSM or a VPN (docs/16 §4)." ;;
        esac
        ;;
esac

# ---------------------------------------------------------------------------
stage "Create the service account and the directories it owns"
# ---------------------------------------------------------------------------
if id -u "$SVC_USER" >/dev/null 2>&1; then
    note "user $SVC_USER already exists; skipping useradd"
else
    act "create a system account with no login shell, for the dashboard only" \
        useradd --system --no-create-home --shell /usr/sbin/nologin \
                --comment "honeypot monitoring dashboard" "$SVC_USER"
fi
act "create the install, store and bundle directories" \
    install -d -o root -g "$SVC_GROUP" -m 0750 "$INSTALL_DIR" "$INSTALL_DIR/pkg"
# The store is writable by the service account: the admin, session, audit and
# export tables live in it. The evidence tables are additionally opened through
# a read-only SQLite handle, so this is not the only thing protecting them.
act "create the store and the bundle spool, owned by the service account" \
    install -d -o "$SVC_USER" -g "$SVC_GROUP" -m 0750 \
        "$STORE" "$SPOOL" "$INSTALL_DIR/run"

# ---------------------------------------------------------------------------
stage "Copy the package"
# ---------------------------------------------------------------------------
# Self-contained: the dashboard is standard library only, so there is no venv
# and nothing to install from the network. Exclusions skip build output, the
# local test lab and Python bytecode.
act "copy the package into $INSTALL_DIR/pkg" \
    rsync -a --delete \
        --exclude '.git' --exclude '.venv' --exclude 'build' --exclude 'lab' \
        --exclude '__pycache__' --exclude '*.pyc' \
        "$REPO_ROOT/" "$INSTALL_DIR/pkg/"
act "make the installed package read-only to the service account" \
    bash -c "chown -R root:'$SVC_GROUP' '$INSTALL_DIR/pkg' && chmod -R a-w,g+rX,o= '$INSTALL_DIR/pkg'"

# ---------------------------------------------------------------------------
stage "Install the systemd units"
# ---------------------------------------------------------------------------
if [[ "$NO_UNITS" -eq 1 ]]; then
    note "--no-units: skipping unit installation"
else
    UNIT_SRC="$REPO_ROOT/deploy/systemd"
    # The shipped unit is the canonical deployment: UNIX socket, no network
    # address families. The substitutions below move only the values the
    # operator actually asked for, on the INSTALLED copy -- the file in the
    # repository stays the reference configuration.
    act "install the dashboard unit, with the requested paths and listen spec" \
        bash -c "
            sed -e 's|/opt/honeypot-dashboard|$INSTALL_DIR|g' \
                -e 's|/var/lib/honeypot-store|$STORE|g' \
                -e 's|--listen unix:/run/honeypot-dashboard/dashboard.sock|--listen $LISTEN|' \
                -e 's|^User=hpmon\$|User=$SVC_USER|' \
                -e 's|^Group=hpmon\$|Group=$SVC_GROUP|' \
                '$UNIT_SRC/honeypot-dashboard.service' \
                > /etc/systemd/system/honeypot-dashboard.service"
    if [[ "$LISTEN" != unix:* ]]; then
        warn "TCP listen spec: the unit is patched to allow AF_INET as well as AF_UNIX."
        warn "Keep it on loopback, and reach it over a management path (docs/16 §4)."
        act "allow AF_INET in the installed unit (TCP listen spec)" \
            sed -i 's|^RestrictAddressFamilies=AF_UNIX$|RestrictAddressFamilies=AF_UNIX AF_INET|' \
                /etc/systemd/system/honeypot-dashboard.service
    fi
    act "install the ingest unit and timer, with the requested paths" \
        bash -c "
            sed -e 's|/opt/honeypot-dashboard|$INSTALL_DIR|g' \
                -e 's|/var/lib/honeypot-store|$STORE|g' \
                -e 's|/var/spool/honeypot-export|$SPOOL|g' \
                -e 's|^User=hpmon\$|User=$SVC_USER|' \
                -e 's|^Group=hpmon\$|Group=$SVC_GROUP|' \
                '$UNIT_SRC/honeypot-dashboard-ingest.service' \
                > /etc/systemd/system/honeypot-dashboard-ingest.service
            install -o root -g root -m 0644 \
                '$UNIT_SRC/honeypot-dashboard-ingest.timer' \
                /etc/systemd/system/honeypot-dashboard-ingest.timer"
    act "reload systemd and start the dashboard and the ingest timer" \
        systemctl daemon-reload
    act "enable and start the ingest timer" \
        systemctl enable --now honeypot-dashboard-ingest.timer
    act "enable and start the dashboard" \
        systemctl enable --now honeypot-dashboard.service
fi

# ---------------------------------------------------------------------------
stage "Create the store, and ingest anything already waiting"
# ---------------------------------------------------------------------------
DB="$STORE/store.sqlite3"
if [[ "$MODE" == "apply" ]]; then
    if [[ -f "$DB" ]]; then
        note "store already present: $DB"
    else
        act "create an empty store (no bundle has arrived yet)" \
            sudo -u "$SVC_USER" "$PYBIN" "$INSTALL_DIR/pkg/dashboard/manage.py" \
                --store "$STORE" init
    fi
    if [[ -n "$(ls -A "$SPOOL" 2>/dev/null || true)" ]]; then
        note "the bundle spool is not empty; running the ingest unit once"
        systemctl start honeypot-dashboard-ingest.service || \
            warn "the ingest unit returned non-zero; check 'journalctl -u honeypot-dashboard-ingest'"
    fi
else
    note "would create $DB if it does not exist, and ingest anything in $SPOOL"
fi

# ---------------------------------------------------------------------------
echo
if [[ "$MODE" == "dry-run" ]]; then
    echo "${YEL}This was a dry run. Re-run with --apply to make these changes.${RST}"
    exit 0
fi

cat <<NEXT
${GRN}Done.${RST} Two things are deliberately left for you to do by hand:

1. Create the first account. The password is never passed on a command line,
   and the TOTP secret is shown exactly once:

     sudo -u $SVC_USER $PYBIN $INSTALL_DIR/pkg/dashboard/manage.py \\
         --store $STORE adduser --username <you> --role admin

   (No terminal to prompt on? Add --password-stdin and pipe the password in.)

2. Reach the interface. It is listening on:
     $LISTEN

   Over SSM, with the default UNIX socket, bridge and forward:

     # on the monitoring instance
     sudo socat TCP-LISTEN:8443,bind=127.0.0.1,reuseaddr,fork \\
         UNIX-CONNECT:/run/honeypot-dashboard/dashboard.sock
     # on your workstation
     aws ssm start-session --target <monitoring-instance> \\
         --document-name AWS-StartPortForwardingSession \\
         --parameters '{"portNumber":["8443"],"localPortNumber":["8443"]}'

   Then browse to http://127.0.0.1:8443 and sign in with the account above
   plus the code from your authenticator app.

The full walkthrough, including what to do when the dashboard is empty, is in:
  $INSTALL_DIR/pkg/docs/16-dashboard-setup.md
NEXT
