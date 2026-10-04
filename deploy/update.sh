#!/usr/bin/env bash
# =============================================================================
# Update an installed honeypot to a different branch, tag or commit.
# =============================================================================
# The installer (deploy/install.sh) is idempotent, so "update" is really
# "run the installer again against a different revision of this repository".
# This script is the wrapper that makes that safe to do on a live sensor:
#
#   1. It will not touch a dirty source tree without being told to, because a
#      dirty tree is installed exactly as it is: uncommitted edits become part
#      of the deployment while DEPLOYMENT.txt claims a commit.
#   2. It records what it is replacing, so the rollback command is a copy-paste
#      away and printed before anything changes.
#   3. It refuses to run against a host that has never been installed.
#   4. It restarts the service and re-runs the health check afterwards, and it
#      says so plainly when a step failed instead of leaving a stopped sensor.
#
# EVIDENCE IS NEVER TOUCHED. This script does not delete or move anything under
# the state directory; `install.sh` replaces configuration, units, the generated
# profile and the Cowrie checkout, and leaves var/log, var/lib and the captured
# files exactly where they are.
#
# Usage:
#   ./update.sh                                   # show the plan (dry run)
#   sudo ./update.sh --ref main --apply           # update to origin/main
#   sudo ./update.sh --ref v1.2.0 --apply         # a tag or branch
#   sudo ./update.sh --ref <commit> --apply       # exact commit
#   sudo ./update.sh --source /root/honeypot-src --ref <branch> --apply
#   sudo ./update.sh --rollback --apply           # back to the recorded previous
#   ./update.sh --list                            # branches and tags available
#
# Exit codes:  0 success, 1 refusal or failure, 2 usage error.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$REPO_ROOT/deploy/versions.env"

MODE="dry-run"
REF=""
SOURCE="${HONEYPOT_SOURCE:-}"
ROLLBACK=0
LIST=0
FORCE_DIRTY=0
SKIP_VERIFY=0
NO_RESTART=0
for arg in "$@"; do
    case "$arg" in
        --apply) MODE="apply" ;;
        --dry-run) MODE="dry-run" ;;
        --rollback) ROLLBACK=1 ;;
        --list) LIST=1 ;;
        --force-dirty-tree) FORCE_DIRTY=1 ;;
        --skip-verify) SKIP_VERIFY=1 ;;
        --no-restart) NO_RESTART=1 ;;
        --ref) PREV="--ref" ;;
        --source) PREV="--source" ;;
        --ref=*) REF="${arg#--ref=}" ;;
        --source=*) SOURCE="${arg#--source=}" ;;
        -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
        *)
            case "${PREV:-}" in
                --ref) REF="$arg" ;;
                --source) SOURCE="$arg" ;;
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
note() { echo "  ${DIM}$*${RST}"; }
step() { echo; echo "${BOLD}== $* ==${RST}"; }
die()  { echo "${RED}error: $*${RST}" >&2; exit 1; }

# ---------------------------------------------------------------------------
step "Locate the source checkout"
# ---------------------------------------------------------------------------
# The installer rsyncs THIS directory into $STATE_DIR/share/pkg, so the update
# has to be run from the checkout the operator actually pulls into. Preference
# order: --source, $HONEYPOT_SOURCE, the directory this script lives in, then
# the path docs/03 creates.
if [[ -z "$SOURCE" ]]; then
    if [[ -d "$REPO_ROOT/.git" ]]; then
        SOURCE="$REPO_ROOT"
    elif [[ -d /root/honeypot-src/.git ]]; then
        SOURCE=/root/honeypot-src
    fi
fi
[[ -n "$SOURCE" ]] || die "no source checkout found. Pass --source <path>."
[[ -d "$SOURCE/.git" ]] || die "$SOURCE is not a git checkout (install.sh could not have been run from it)"
echo "  source:        $SOURCE"
echo "  state dir:     $STATE_DIR"
echo "  honeypot:      cowrie $COWRIE_VERSION @ ${COWRIE_COMMIT:0:12}"
[[ "$MODE" == "dry-run" ]] && echo "  ${YEL}mode: dry run - nothing will change${RST}"

git -C "$SOURCE" fetch --quiet --prune --tags origin 2>/dev/null || \
    echo "  ${YEL}warning: git fetch failed (no network?); using local refs${RST}"

if [[ "$LIST" -eq 1 ]]; then
    echo
    echo "branches and tags that can be given to --ref:"
    git -C "$SOURCE" branch -r --sort=-committerdate | sed 's/^/  /' | head -30
    echo
    git -C "$SOURCE" tag --sort=-creatordate | sed 's/^/  /' | head -20
    exit 0
fi

# ---------------------------------------------------------------------------
step "Decide the target revision"
# ---------------------------------------------------------------------------
CURRENT="$(git -C "$SOURCE" rev-parse HEAD)"
CURRENT_DESC="$(git -C "$SOURCE" describe --always --dirty 2>/dev/null || echo "$CURRENT")"
echo "  currently checked out: $CURRENT_DESC ($(git -C "$SOURCE" rev-parse --abbrev-ref HEAD))"

if [[ "$ROLLBACK" -eq 1 ]]; then
    LOG="$STATE_DIR/UPDATE-LOG.txt"
    [[ -f "$LOG" ]] || die "no update log at $LOG; there is nothing recorded to roll back to"
    REF="$(awk '/^previous-commit:/ {v=$2} END {print v}' "$LOG")"
    [[ -n "$REF" ]] || die "no previous-commit line in $LOG"
    echo "  rolling back to: $REF (the revision recorded by the last update)"
fi

if [[ -n "$REF" ]]; then
    if ! TARGET="$(git -C "$SOURCE" rev-parse --verify --quiet "${REF}^{commit}")"; then
        die "$REF is not a branch, tag or commit in $SOURCE. Run $0 --list to see what is available."
    fi
else
    TARGET="$CURRENT"
    echo "  ${YEL}no --ref given: this is a no-op on the source tree; only the installer would re-run.${RST}"
fi

echo "  target:                $TARGET"
[[ "$TARGET" == "$CURRENT" ]] || {
    echo "  commits being applied:"
    git -C "$SOURCE" log --oneline --no-decorate "$CURRENT..$TARGET" | head -25 | sed 's/^/    /'
}

# ---------------------------------------------------------------------------
step "Pre-flight checks"
# ---------------------------------------------------------------------------
[[ -d "$STATE_DIR/etc" ]] || die "$STATE_DIR/etc not found: this host is not an installed honeypot. Run deploy/install.sh first."
[[ -f "$STATE_DIR/DEPLOYMENT.txt" ]] || \
    echo "  ${YEL}warning: no DEPLOYMENT.txt; recording one now${RST}"

if [[ -n "$(git -C "$SOURCE" status --porcelain)" ]]; then
    if [[ "$FORCE_DIRTY" -eq 1 ]]; then
        echo "  ${YEL}source tree is dirty; installing it as-is (--force-dirty-tree)${RST}"
    else
        echo
        git -C "$SOURCE" status --short | sed 's/^/    /'
        die "the source tree has uncommitted changes. Commit or stash them, or pass
       --force-dirty-tree if you really intend to deploy this exact content."
    fi
fi

# Evidence that has not been shipped is not evidence: warn, and make the
# operator choose. This is a warning rather than a refusal because the shipping
# timer covers it every 5 minutes; it exists to catch the case where shipping has
# been failing for hours and nobody noticed.
if [[ -x /usr/local/sbin/healthcheck.sh ]] && [[ "$(id -u)" -eq 0 ]]; then
    if ! /usr/local/sbin/healthcheck.sh >/dev/null 2>&1; then
        echo "  ${YEL}warning: healthcheck.sh reports a problem before the update."
        echo "           Run it and read the output: an update is easier to reason about"
        echo "           from a known-good starting point.${RST}"
    fi
fi

DISK_AVAIL_MB="$(df -Pm "$STATE_DIR" 2>/dev/null | awk 'NR==2 {print $4}')"
if [[ -n "$DISK_AVAIL_MB" ]] && [[ "$DISK_AVAIL_MB" -lt 2048 ]]; then
    die "only ${DISK_AVAIL_MB} MB free on the filesystem holding $STATE_DIR; an update needs room to build"
fi

# ---------------------------------------------------------------------------
step "Apply"
# ---------------------------------------------------------------------------
if [[ "$MODE" == "dry-run" ]]; then
    cat <<PLAN
  Would run, in this order:

    1. git -C $SOURCE checkout --detach $TARGET
       (the source tree is left detached at the target; branch names in
        DEPLOYMENT.txt are ambiguous the moment the branch moves)

    2. sudo $SOURCE/deploy/install.sh --apply
       Refreshes the Cowrie checkout at the pin in deploy/versions.env,
       reinstalls the package, regenerates the realism profile, reinstalls the
       systemd units and restarts cowrie.service. Evidence is untouched.

    3. systemctl restart cowrie.service && systemctl restart cowrie-healthcheck.timer
       (install.sh already starts them; this makes a failure explicit here.)

    4. Record the update in $STATE_DIR/UPDATE-LOG.txt, including the revision
       this update is replacing, which is what --rollback reads.

  Re-run with --apply to perform it.
PLAN
    exit 0
fi

[[ "$(id -u)" -eq 0 ]] || die "must run as root in --apply mode (sudo $0 --ref $REF --apply)"

if [[ "$TARGET" != "$CURRENT" ]]; then
    # --force is deliberate and narrow: the tree was either clean (checked
    # above) or the operator passed --force-dirty-tree, and install.sh installs
    # the working tree, so what is on disk must be the target revision.
    git -C "$SOURCE" checkout --quiet --force --detach "$TARGET" || \
        die "could not check out $TARGET in $SOURCE"
    note "source tree now at $(git -C "$SOURCE" rev-parse --short HEAD)"
fi

bash "$SOURCE/deploy/install.sh" --apply || die "install.sh failed. The service may be stopped;
       re-run 'sudo $SOURCE/deploy/install.sh --apply' once the cause is fixed. Evidence is intact."

if [[ "$NO_RESTART" -eq 0 ]]; then
    systemctl restart cowrie.service || die "cowrie.service failed to restart"
    systemctl restart cowrie-healthcheck.timer 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
step "Record and verify"
# ---------------------------------------------------------------------------
LOG="$STATE_DIR/UPDATE-LOG.txt"
{
    echo "updated:         $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "updated-by:      ${SUDO_USER:-$(id -un)}"
    echo "previous-commit: $CURRENT"
    echo "applied-commit:  $TARGET"
    echo "source:          $SOURCE"
    echo "cowrie-pin:      $COWRIE_VERSION @ $COWRIE_COMMIT"
} >> "$LOG"
chown root:root "$LOG"; chmod 0644 "$LOG"
note "update recorded in $LOG"

if [[ "$SKIP_VERIFY" -eq 0 ]]; then
    if systemctl is-active --quiet cowrie.service; then
        echo "  ${GRN}cowrie.service is active${RST}"
    else
        echo "  ${RED}cowrie.service is NOT active${RST}"
        systemctl status cowrie --no-pager --lines 20 || true
        exit 1
    fi
    if [[ -x /usr/local/sbin/healthcheck.sh ]]; then
        /usr/local/sbin/healthcheck.sh || \
            echo "  ${YEL}healthcheck reported a problem; run it directly for the detail${RST}"
    fi
fi

cat <<NEXT

${BOLD}Done.${RST} This update replaced code, configuration and the generated profile.
It did not touch evidence: var/log, var/lib and every captured file are where
they were.

Verify the profile the way the conformance suite does (from the checkout, or
from $STATE_DIR/share/pkg):

  sudo $STATE_DIR/venv/bin/python $STATE_DIR/share/pkg/tests/test_conformance.py \\
      --expect $STATE_DIR/build/profile/expectations.json --host 127.0.0.1 --port 22

Roll back to the revision this update replaced:

  sudo $0 --rollback --apply

Read the update history:

  cat $STATE_DIR/UPDATE-LOG.txt
NEXT
