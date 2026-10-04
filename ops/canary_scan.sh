#!/usr/bin/env bash
# =============================================================================
# Canary scan. Installs to /usr/local/sbin/canary_scan.sh
# =============================================================================
# Every canary value in realism/identity.yaml is planted in the EMULATED
# filesystem and must appear NOWHERE ELSE. This script searches the real host
# for them.
#
# A hit means the honeypot's synthetic content has leaked into the host, or the
# host's real content has been copied into the honeypot. Either direction is a
# serious finding: the first reveals the honeypot, the second leaks real data.
#
# Run after every rebuild and after every identity change.
# =============================================================================
set -uo pipefail

IDENTITY="${IDENTITY:-/opt/cowrie/share/pkg/realism/identity.yaml}"
CANARY_DIRS="${CANARY_DIRS:-/etc /home /root /srv /var /usr/local /opt/cowrie/etc}"

if [[ ! -r "$IDENTITY" ]]; then
    echo "cannot read identity manifest at $IDENTITY" >&2
    echo "run from the repository checkout, or set IDENTITY=" >&2
    exit 2
fi

# Extract canary values without a YAML parser so this stays dependency-free.
mapfile -t CANARIES < <(awk '
    /^canaries:/ {in_canaries=1; next}
    in_canaries && /^[a-z_]+:/ {in_canaries=0}
    in_canaries && /value:/ {
        sub(/.*value:[[:space:]]*/, "")
        gsub(/^"|"$/, "")
        print
    }
' "$IDENTITY")

if [[ ${#CANARIES[@]} -eq 0 ]]; then
    echo "no canaries found in $IDENTITY" >&2
    exit 2
fi

echo "Scanning for ${#CANARIES[@]} canary value(s) outside the emulated filesystem"
echo "search roots: $CANARY_DIRS"
echo

hits=0
for value in "${CANARIES[@]}"; do
    [[ -n "$value" ]] || continue
    # Exclude the honeypot's own state, where the profiles legitimately contain
    # canaries, and exclude the identity manifest itself.
    found="$(grep -rIl --exclude-dir=var --exclude-dir=build --exclude-dir=.git \
             -F "$value" $CANARY_DIRS 2>/dev/null \
             | grep -v 'identity.yaml' | grep -v '/opt/cowrie/share/pkg' || true)"
    if [[ -n "$found" ]]; then
        echo "LEAK: canary ${value:0:16}... found in:"
        echo "$found" | sed 's/^/    /'
        hits=$((hits + 1))
    fi
done

echo
if (( hits == 0 )); then
    echo "OK: no canary value found outside the emulated filesystem."
    exit 0
fi
echo "FAIL: $hits canary leak(s). Treat the deployment as compromised:"
echo "  * A honeypot canary on the host means synthetic content escaped."
echo "  * Review docs/11-rollback-and-rebuild.md and rebuild."
exit 1
