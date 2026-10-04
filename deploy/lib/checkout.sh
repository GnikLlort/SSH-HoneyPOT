#!/usr/bin/env bash
# =============================================================================
# Pinned-checkout helpers, sourced by deploy/install.sh and deploy/update.sh.
# =============================================================================
# Sourced, never executed: no shebang semantics are relied on, and nothing here
# may have side effects at source time.
#
# WHY THIS IS A LIBRARY
# The installer claims to be safe to re-run, and the documented update path is
# "re-run it against a newer pin". The command it used for that,
#
#     git clone <repo> /opt/cowrie/build/cowrie
#
# is not idempotent: on the second run git exits 128 with "destination path
# already exists and is not an empty directory", `set -e` aborts the installer
# at stage 4, and nothing after it happens. An update looked like a crash in
# the middle of the build.
#
# The logic is here rather than inline so it can be tested directly against a
# throwaway repository (tests/test_deployment_scripts.py) instead of being
# asserted by reading the script.
# =============================================================================

# ensure_pinned_checkout <dir> <repo-url> <commit> [--force]
#
# Leaves <dir> as a clone of <repo-url> with <commit> checked out, whether or
# not it already existed. Returns 0 on success, non-zero with a message on
# stderr otherwise.
#
# Local modifications in <dir> are discarded: this is a build directory, not a
# working copy, and building from a half-edited tree is how a deployment
# silently differs from the commit it claims to run. A warning is printed when
# something is actually thrown away, so it is never silent.
ensure_pinned_checkout() {
    local dir="$1" repo="$2" commit="$3" force="${4:-}"
    local dirty=""

    if [[ -z "$dir" || -z "$repo" || -z "$commit" ]]; then
        echo "ensure_pinned_checkout: dir, repo and commit are all required" >&2
        return 2
    fi
    if ! command -v git >/dev/null 2>&1; then
        echo "ensure_pinned_checkout: git is not installed" >&2
        return 2
    fi

    if [[ -e "$dir" && ! -d "$dir/.git" ]]; then
        # A directory that is not a clone is never deleted, not even with
        # --force: it may be a hand-placed copy, and "delete this path that
        # arrived in a variable" is the operation deploy/lib/guards.sh exists
        # to prevent. --force moves it aside instead, which is reversible and
        # is named in the output.
        if [[ "$force" == "--force" ]]; then
            local aside="${dir}.replaced-$(date -u +%Y%m%dT%H%M%SZ)"
            mv "$dir" "$aside"
            echo "ensure_pinned_checkout: moved the unrecognised directory aside to $aside" >&2
        else
            echo "ensure_pinned_checkout: $dir exists and is not a git checkout." >&2
            echo "  Refusing to touch it. Move it aside yourself, or pass --force to" >&2
            echo "  have it renamed out of the way (never deleted)." >&2
            return 3
        fi
    fi

    if [[ ! -d "$dir/.git" ]]; then
        mkdir -p "$(dirname "$dir")"
        # --no-single-branch so a pin on a branch that is not `main` is still
        # reachable from a fresh clone.
        if ! git clone --quiet --no-single-branch "$repo" "$dir"; then
            echo "ensure_pinned_checkout: clone from $repo failed" >&2
            return 4
        fi
        echo "  cloned $repo -> $dir"
    else
        # Fetch every branch and tag: the pin may have moved to a commit that
        # this clone has never seen. Failure is not fatal here - the commit
        # might already be present from an earlier fetch.
        git -C "$dir" fetch --quiet --prune origin || \
            echo "  warning: git fetch failed; using what is already in $dir" >&2
    fi

    if ! git -C "$dir" cat-file -e "${commit}^{commit}" 2>/dev/null; then
        # A commit that is not reachable from any ref (an unreviewed pin, or a
        # force-push) still has to be fetched by name. GitHub allows this for
        # reachable objects; if the server does not, the checkout below fails
        # loudly rather than building the wrong code.
        git -C "$dir" fetch --quiet origin "$commit" 2>/dev/null || true
    fi
    if ! git -C "$dir" cat-file -e "${commit}^{commit}" 2>/dev/null; then
        echo "ensure_pinned_checkout: commit $commit is not present in $dir" >&2
        echo "  The pin may be wrong, or the repository may have been rewritten." >&2
        return 5
    fi

    dirty="$(git -C "$dir" status --porcelain 2>/dev/null || true)"
    if [[ -n "$dirty" ]]; then
        echo "  note: discarding local changes in $dir (build directory):" >&2
        printf '    %s\n' "${dirty%%$'\n'*}" >&2
    fi

    if ! git -C "$dir" checkout --quiet --force --detach "$commit"; then
        echo "ensure_pinned_checkout: could not check out $commit" >&2
        return 6
    fi
    git -C "$dir" reset --quiet --hard "$commit" 2>/dev/null || true

    local head
    head="$(git -C "$dir" rev-parse HEAD 2>/dev/null || echo unknown)"
    if [[ "$head" != "$commit" ]]; then
        echo "ensure_pinned_checkout: HEAD is $head, expected $commit" >&2
        return 7
    fi
    return 0
}
