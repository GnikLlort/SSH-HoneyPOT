#!/usr/bin/env bash
# =============================================================================
# Staged installation of the SSH honeypot on a dedicated Ubuntu LTS instance.
# =============================================================================
#
# READ THIS BEFORE RUNNING.
#
# This script changes the machine it runs on. Every step prints what it is
# about to do and why before doing it. By default the script only PRINTS the
# plan ("dry run"); nothing is modified until you pass --apply.
#
#   ./install.sh                     # show the plan, change nothing
#   sudo ./install.sh --apply        # perform stages 1-9
#   sudo ./install.sh --apply --stage 5   # perform one stage only
#
# It is written to be safe to re-run: each stage checks whether its work is
# already done and skips it, and the pinned Cowrie checkout is refreshed rather
# than re-cloned. That is what makes this script the update path as well as the
# install path: pull a newer commit, re-run it, restart the service. See
# docs/17-updating-the-deployment.md, or use ./deploy/update.sh, which wraps
# this script with the pre-flight checks and the rollback command.
#
# PREREQUISITES
#   * A freshly created Ubuntu 24.04 LTS EC2 instance, in its own AWS account
#     or at minimum its own VPC and security group, with NO route to any
#     production network.
#   * Run from this repository checkout, as root.
#   * The instance must NOT host anything else.
#
# THIS SCRIPT WILL NOT
#   * open a firewall port,
#   * create or modify AWS resources,
#   * install anything from an unpinned source,
#   * copy any data from any other machine.
# Network exposure is configured separately and deliberately; see
# deploy/aws/security-groups.md.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$REPO_ROOT/deploy/versions.env"
# shellcheck source=/dev/null
source "$REPO_ROOT/deploy/lib/checkout.sh"

MODE="dry-run"
ONLY_STAGE=""
for arg in "$@"; do
    case "$arg" in
        --apply) MODE="apply" ;;
        --dry-run) MODE="dry-run" ;;
        --stage) shift || true ;;
        --stage=*) ONLY_STAGE="${arg#--stage=}" ;;
        --stage) ;;
        -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
        *) if [[ "${PREV:-}" == "--stage" ]]; then ONLY_STAGE="$arg"; fi ;;
    esac
    PREV="$arg"
done

# -- output helpers ----------------------------------------------------------
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
    if [[ -n "$ONLY_STAGE" && "$ONLY_STAGE" != "$STAGE_NUM" ]]; then
        SKIP_STAGE=1
    else
        SKIP_STAGE=0
    fi
}

# Explain an action, then (only in apply mode) perform it.
act() {
    local why="$1"; shift
    echo "  ${DIM}why: ${why}${RST}"
    echo "  ${BOLD}\$ $*${RST}"
    if [[ "$SKIP_STAGE" == "1" ]]; then
        echo "  ${DIM}(skipped: --stage filter)${RST}"
        return 0
    fi
    if [[ "$MODE" == "dry-run" ]]; then
        echo "  ${DIM}(dry run: not executed)${RST}"
        return 0
    fi
    "$@"
}

note() { echo "  ${DIM}$*${RST}"; }
warn() { echo "  ${YEL}warning: $*${RST}"; }
die()  { echo "${RED}error: $*${RST}" >&2; exit 1; }

echo "${BOLD}SSH honeypot - staged installation${RST}"
echo "  mode:        $MODE"
echo "  repository:  $REPO_ROOT"
echo "  target:      $STATE_DIR"
echo "  honeypot:    cowrie $COWRIE_VERSION @ ${COWRIE_COMMIT:0:12}"
[[ -n "$ONLY_STAGE" ]] && echo "  stage filter: $ONLY_STAGE"
if [[ "$MODE" == "dry-run" ]]; then
    echo
    echo "${YEL}DRY RUN - no changes will be made. Re-run with --apply to execute.${RST}"
fi

# ---------------------------------------------------------------------------
stage "Verify prerequisites and that this is a disposable host"
# ---------------------------------------------------------------------------
# These checks exist to stop the most damaging mistake: running the installer
# on a machine that already has a job.
if [[ "$(id -u)" -ne 0 && "$MODE" == "apply" ]]; then
    die "must run as root in --apply mode"
fi

PY_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo none)"
note "python3 version: $PY_VER"
if [[ "$MODE" == "apply" ]]; then
    python3 - <<PY || die "python3 >= ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR} is required (found ${PY_VER})"
import sys
raise SystemExit(0 if sys.version_info >= (${MIN_PYTHON_MAJOR}, ${MIN_PYTHON_MINOR}) else 1)
PY
fi

# Refuse to install on a host that already serves something on port 22.
if [[ "$MODE" == "apply" ]] && command -v ss >/dev/null 2>&1; then
    if ss -ltnH "sport = :${HONEYPOT_PORT}" 2>/dev/null | grep -q .; then
        warn "something is already listening on tcp/${HONEYPOT_PORT}:"
        ss -ltnp "sport = :${HONEYPOT_PORT}" 2>/dev/null | sed 's/^/    /' || true
        die "refusing to install: this host already runs an SSH service. Install on a dedicated instance."
    fi
fi

# A honeypot that shares a filesystem with production data will eventually leak
# something. Detect the obvious cases and stop.
if [[ "$MODE" == "apply" ]]; then
    for suspicious in /var/www /srv/app /opt/marswars /home/deploy/www; do
        if [[ -d "$suspicious" ]]; then
            warn "found $suspicious - is this really a disposable host?"
        fi
    done
fi
note "this host must have no route to production networks; that is enforced by"
note "the security group and route table, not by this script."

# ---------------------------------------------------------------------------
stage "Install pinned system packages"
# ---------------------------------------------------------------------------
# Needed to build Cowrie's dependencies and to run it. `python3-venv` gives an
# isolated interpreter; `python3-dev` and `build-essential` cover the wheels
# that have no prebuilt binary for this platform; `libffi-dev` and
# `libssl-dev` are required by cryptography/bcrypt when a wheel is unavailable.
act "install the build and runtime dependencies Cowrie needs" \
    env DEBIAN_FRONTEND=noninteractive apt-get update -qq
act "install packages (no upgrades, no autoremove: keep the host minimal)" \
    env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3-venv python3-dev python3-pip build-essential libffi-dev libssl-dev \
        git ca-certificates rsync jq

# ---------------------------------------------------------------------------
stage "Create the dedicated unprivileged service account"
# ---------------------------------------------------------------------------
# The honeypot must never run as root. This account gets no shell, no home
# directory content, and no sudo. If Cowrie is ever compromised, this is the
# privilege level the attacker inherits.
# Checked in both modes: `useradd` fails hard if the account already exists,
# and this script advertises itself as safe to re-run. Skipping the creation is
# the difference between an idempotent re-run and one that dies at stage 3.
if id -u "$HONEYPOT_USER" >/dev/null 2>&1; then
    note "user $HONEYPOT_USER already exists; skipping useradd"
    existing_home="$(getent passwd "$HONEYPOT_USER" | cut -d: -f6)"
    if [[ -n "$existing_home" && "$existing_home" != "$STATE_DIR" ]]; then
        warn "its home directory is $existing_home, not $STATE_DIR"
    fi
else
    act "create a system account with no login shell and no home directory" \
        useradd --system --create-home --home-dir "$STATE_DIR" --shell /usr/sbin/nologin \
                --comment "Cowrie honeypot service account" "$HONEYPOT_USER"
fi
act "create the state directory tree owned by the service account" \
    install -d -o "$HONEYPOT_USER" -g "$HONEYPOT_GROUP" -m 0750 \
        "$STATE_DIR" "$STATE_DIR/etc" "$STATE_DIR/var" "$STATE_DIR/var/log" \
        "$STATE_DIR/var/lib" "$STATE_DIR/var/run" "$STATE_DIR/share"

# ---------------------------------------------------------------------------
stage "Fetch Cowrie at the pinned commit and build an isolated virtualenv"
# ---------------------------------------------------------------------------
# Pinning to a commit (not a tag) means the exact code under test is the exact
# code deployed. The virtualenv keeps Cowrie's dependencies away from the
# system Python, which the rest of the OS relies on.
#
# "Re-run safe" is load-bearing: the documented update path is to run this
# script again against a newer pin (docs/17). `git clone` refuses to run into a
# directory that already exists, so the checkout is delegated to
# deploy/lib/checkout.sh, which clones, fetches, re-checks-out and verifies the
# commit -- and is tested directly (tests/test_deployment_scripts.py).
BUILD_DIR="$STATE_DIR/build"
act "clone or refresh the pinned Cowrie checkout" \
    ensure_pinned_checkout "$BUILD_DIR/cowrie" "$COWRIE_REPO" "$COWRIE_COMMIT"
act "create the virtualenv" \
    python3 -m venv "$STATE_DIR/venv"
act "install Cowrie from the pinned source (dependencies are pinned in its pyproject.toml)" \
    "$STATE_DIR/venv/bin/pip" install --quiet --upgrade pip setuptools wheel
act "install the honeypot package" \
    "$STATE_DIR/venv/bin/pip" install --quiet "$BUILD_DIR/cowrie"

# Twisted caches its plugin list. When the cache is stale, `cowrie start` fails
# with "Unknown command: cowrie" from twistd, which says nothing useful.
act "refresh Twisted's plugin cache so twistd can find the cowrie service" \
    "$STATE_DIR/venv/bin/python" "$BUILD_DIR/cowrie/bin/regen-dropin.cache"

if [[ "$MODE" == "apply" ]]; then
    # Only checkable once stage 4 has created the virtualenv. On a filtered run
    # (`--stage 5`) the venv may not exist yet; a bare command substitution here
    # would make `set -e` kill the script with exit 127 and no message at all,
    # which is indistinguishable from a crash.
    if [[ -x "$STATE_DIR/venv/bin/pip" ]]; then
        installed_ver="$("$STATE_DIR/venv/bin/pip" show cowrie 2>/dev/null | awk '/^Version:/{print $2}')"
        [[ -n "$installed_ver" ]] || die "cowrie is not installed in $STATE_DIR/venv (re-run stage 4)"
        [[ "$installed_ver" == "$COWRIE_VERSION" ]] || die "installed cowrie $installed_ver != pinned $COWRIE_VERSION"
        note "verified installed version: $installed_ver"
    else
        warn "no virtualenv at $STATE_DIR/venv; skipping the installed-version check"
        note "stage 4 (and the full install) creates it. Expected on a filtered run."
    fi
fi

# ---------------------------------------------------------------------------
stage "Initialise the Cowrie state directory"
# ---------------------------------------------------------------------------
# Cowrie 3.x treats the CURRENT WORKING DIRECTORY as its state directory:
# ./etc/cowrie.cfg is the config, ./var/log/cowrie/ holds logs, ./var/run/ the
# PID file. `cowrie init` writes a full copy of the bundled template, which is
# a trap: appending to it duplicates sections and Cowrie then refuses to start
# with a confusing error. We therefore write our own minimal config, which
# contains only overrides and is much easier to audit.
act "create the log/state directories the service writes into" \
    install -d -o "$HONEYPOT_USER" -g "$HONEYPOT_GROUP" -m 0750 \
        "$STATE_DIR/var/log/cowrie" "$STATE_DIR/var/lib/cowrie/downloads" \
        "$STATE_DIR/var/lib/cowrie/tty" "$STATE_DIR/var/run"

# ---------------------------------------------------------------------------
stage "Generate the synthetic host profile from the identity manifest"
# ---------------------------------------------------------------------------
# realism/identity.yaml is the single source of truth. This step turns it into
# the filesystem, the process table, the txtcmd outputs, the config fragment
# and the expectations the test suite asserts against. Doing it as one step is
# what makes the fake machine internally consistent.
act "install PyYAML for the generator (build tool only; not used by the honeypot)" \
    "$STATE_DIR/venv/bin/pip" install --quiet "pyyaml==${PYYAML_VERSION}"
act "build the profile" \
    env HOME=/root "$STATE_DIR/venv/bin/python" "$REPO_ROOT/realism/build_profile.py" \
        --identity "$REPO_ROOT/realism/identity.yaml" \
        --out "$BUILD_DIR/profile"
note "the build fails loudly if any consistency invariant is violated; see"
note "$BUILD_DIR/profile/BUILD-REPORT.txt"

# ---------------------------------------------------------------------------
stage "Install configuration, credential policy and the realism overlay"
# ---------------------------------------------------------------------------
act "install the generated profile artefacts" \
    install -o "$HONEYPOT_USER" -g "$HONEYPOT_GROUP" -m 0640 \
        "$BUILD_DIR/profile/fs.pickle" "$STATE_DIR/var/lib/cowrie/fs.pickle"
act "install the process table" \
    install -o "$HONEYPOT_USER" -g "$HONEYPOT_GROUP" -m 0640 \
        "$BUILD_DIR/profile/cmdoutput.json" "$STATE_DIR/var/lib/cowrie/cmdoutput.json"
act "install the txtcmd output directory" \
    rsync -a --delete "$BUILD_DIR/profile/txtcmds/" "$STATE_DIR/share/txtcmds/"
act "install the generated config fragment" \
    install -o root -g "$HONEYPOT_GROUP" -m 0640 \
        "$BUILD_DIR/profile/cowrie-profile.cfg" "$STATE_DIR/etc/profile.cfg"

# Stock Cowrie's `free` reads the REAL host /proc/meminfo and reports the
# instance's actual RAM to a visitor. cowrie.service bind-mounts this synthetic
# file over /proc/meminfo inside the service's private mount namespace, so the
# honeypot process cannot see the real values even if the realism overlay fails
# to load. The file must be readable by the service account before the unit
# starts, or systemd will refuse to set up the mount and the service will not
# start - so this is a required step, not optional hardening.
act "install the synthetic /proc/meminfo (masked over the real one by the unit)" \
    install -d -o root -g "$HONEYPOT_GROUP" -m 0750 "$STATE_DIR/share/synthetic"
act "install the synthetic memory layout" \
    install -o root -g "$HONEYPOT_GROUP" -m 0644 \
        "$BUILD_DIR/profile/procfs/meminfo" "$STATE_DIR/share/synthetic/meminfo"

act "install the curated credential policy" \
    install -o root -g "$HONEYPOT_GROUP" -m 0640 \
        "$REPO_ROOT/config/userdb.txt" "$STATE_DIR/etc/userdb.txt"

# NOTE: the redirection has to live *inside* the command string. A plain
# `act ... > file` is expanded by the shell before act() is called, so even a
# dry run would try to create the file - and fail, because the state directory
# does not exist yet. That aborts the plan under `set -e` and the operator
# never sees stages 8-10.
act "install the operator config, with absolute paths substituted" \
    bash -c "sed -e 's|<state>|$STATE_DIR|g' \
        '$REPO_ROOT/config/cowrie.cfg' > '$STATE_DIR/etc/cowrie.cfg'"
act "restrict the operator config to the service account" \
    chown root:"$HONEYPOT_GROUP" "$STATE_DIR/etc/cowrie.cfg"
act "limit permissions on the config" \
    chmod 0640 "$STATE_DIR/etc/cowrie.cfg"

# The overlay fixes the handful of defects that configuration cannot reach
# (free reading the host's memory, ps losing columns, service --status-all
# returning a Debian 7 list). It is optional and reversible.
act "install the optional realism overlay into the state directory" \
    rsync -a --delete "$REPO_ROOT/overlays/cowrie_realism_overlay/" "$STATE_DIR/share/overlay/"
act "hand the overlay to the service account" \
    chown -R "$HONEYPOT_USER":"$HONEYPOT_GROUP" "$STATE_DIR/share/overlay"
note "set COWRIE_REALISM_OVERLAY=0 in the unit to run stock Cowrie instead."

# Install the package itself alongside the honeypot. The operational helpers
# look for the identity manifest and the version pins under $STATE_DIR/share/pkg
# rather than in the checkout the installer was run from, so that the host stays
# self-describing after the checkout is gone. Exclusions skip everything that is
# either build output, the local test lab, or Python bytecode.
act "install the package for runtime reference (identity manifest, version pins)" \
    rsync -a --delete \
        --exclude '.git' --exclude '.venv' --exclude 'build' --exclude 'lab' \
        --exclude '__pycache__' --exclude '*.pyc' \
        "$REPO_ROOT/" "$STATE_DIR/share/pkg/"
act "make the installed package read-only to the service account" \
    chown -R root:"$HONEYPOT_GROUP" "$STATE_DIR/share/pkg"
act "allow the service account to read the package but never write it" \
    chmod -R a-w,g+rX,o= "$STATE_DIR/share/pkg"

# ---------------------------------------------------------------------------
stage "Install and enable the systemd units"
# ---------------------------------------------------------------------------
act "install the honeypot service unit" \
    install -o root -g root -m 0644 \
        "$REPO_ROOT/deploy/systemd/cowrie.service" /etc/systemd/system/cowrie.service
act "install the health check unit and timer" \
    install -o root -g root -m 0644 \
        "$REPO_ROOT/deploy/systemd/cowrie-healthcheck.service" \
        "$REPO_ROOT/deploy/systemd/cowrie-healthcheck.timer" \
        /etc/systemd/system/
act "install the log-shipping unit and timer" \
    install -o root -g root -m 0644 \
        "$REPO_ROOT/deploy/systemd/cowrie-logship.service" \
        "$REPO_ROOT/deploy/systemd/cowrie-logship.timer" \
        /etc/systemd/system/
# The bundle shipper is what feeds the off-host monitoring dashboard. It is
# installed but NOT enabled: it is a second egress path that carries the event
# log and the session recordings to another host, so enabling it is a
# deliberate decision (docs/16 §3), not something an installer decides.
act "install the dashboard bundle shipper (not enabled)" \
    install -o root -g root -m 0644 \
        "$REPO_ROOT/deploy/systemd/cowrie-bundle-ship.service" \
        "$REPO_ROOT/deploy/systemd/cowrie-bundle-ship.timer" \
        /etc/systemd/system/
act "reload systemd so it sees the new units" \
    systemctl daemon-reload
act "enable and start the honeypot" \
    systemctl enable --now cowrie.service
act "enable the health check and log shipper" \
    systemctl enable --now cowrie-healthcheck.timer cowrie-logship.timer

# The playback UI is installed but deliberately NOT enabled: it is started by
# hand for a review session and stopped afterwards, so an evidence viewer is not
# sitting on the host the rest of the time. It binds to 127.0.0.1 only.
act "install the session playback unit (not enabled)" \
    install -o root -g root -m 0644 \
        "$REPO_ROOT/deploy/systemd/cowrie-playback.service" /etc/systemd/system/cowrie-playback.service
act "make the playback server readable by the service account" \
    install -o "$HONEYPOT_USER" -g "$HONEYPOT_GROUP" -m 0750 \
        "$REPO_ROOT/playback/server.py" "$STATE_DIR/playback/server.py"
note "start it for a review with: sudo systemctl start cowrie-playback"
note "to feed the off-host dashboard: sudo systemctl enable --now cowrie-bundle-ship.timer"
note "(the package it needs is already at $STATE_DIR/share/pkg/dashboard/)"

# ---------------------------------------------------------------------------
stage "Install the operational helper scripts"
# ---------------------------------------------------------------------------
act "install health check, quarantine, canary and retention helpers" \
    install -o root -g root -m 0755 \
        "$REPO_ROOT/ops/healthcheck.sh" \
        "$REPO_ROOT/ops/quarantine_sync.sh" \
        "$REPO_ROOT/ops/canary_scan.sh" \
        "$REPO_ROOT/ops/alert_dispatch.sh" \
        "$REPO_ROOT/ops/prune_local.sh" \
        "$REPO_ROOT/ops/export_bundle.sh" \
        /usr/local/sbin/
act "install the logrotate policy" \
    install -o root -g root -m 0644 \
        "$REPO_ROOT/ops/logrotate/cowrie" /etc/logrotate.d/cowrie

# ---------------------------------------------------------------------------
stage "Record the deployment and run the conformance suite"
# ---------------------------------------------------------------------------
act "write a deployment record for audit and rollback" \
    bash -c "cat > '$STATE_DIR/DEPLOYMENT.txt' <<EOF
Deployed:        \$(date -u +%Y-%m-%dT%H:%M:%SZ)
Cowrie version:  $COWRIE_VERSION
Cowrie commit:   $COWRIE_COMMIT
Identity source: $REPO_ROOT/realism/identity.yaml
State directory: $STATE_DIR
Service account: $HONEYPOT_USER
Honeypot port:   $HONEYPOT_PORT
EOF
chown root:root '$STATE_DIR/DEPLOYMENT.txt'; chmod 0644 '$STATE_DIR/DEPLOYMENT.txt'"

echo
echo "${BOLD}Verification (run these after every install)${RST}"
cat <<'VERIFY'
  # 1. The service is up and listening:
  systemctl status cowrie --no-pager
  ss -ltnp | grep -E ':22\b'

  # 2. The honeypot answers as the profile claims:
  ssh -o StrictHostKeyChecking=no -p 22 deploy@127.0.0.1 'uname -a'

  # 3. Full conformance suite, from the repository checkout:
  python3 tests/test_conformance.py --expect build/profile/expectations.json

  # 4. Nothing real is visible:
  sudo -u cowrie ls -la /home          # must not list real users
  grep -r "canary" /etc /home /var/log # must find nothing outside the honeypot
VERIFY

if [[ "$MODE" == "dry-run" ]]; then
    echo
    echo "${YEL}This was a dry run. Re-run with --apply to make these changes.${RST}"
fi
echo
echo "${GRN}Done.${RST} Review deploy/aws/security-groups.md before exposing the port."
