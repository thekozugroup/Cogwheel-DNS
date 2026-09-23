#!/bin/sh
#
# Cogwheel DNS — the gate, in one command.
#
#   sh scripts/verify.sh            run every check CI runs, in CI's order
#   sh scripts/verify.sh --list     print the commands without running them
#
# THIS SCRIPT IS THE CANONICAL LIST. CONTRIBUTING.md, the README and the pull
# request template name this script rather than restating its contents,
# because four copies of a command list is how they end up disagreeing with
# each other and with .github/workflows/ci.yml.
#
# It stops at the first failure, because a red gate is one problem to fix and
# scrolling past it wastes your time. --keep-going runs everything and reports
# at the end, which is what you want just before opening a pull request.
#
# Everything here runs with no Docker daemon, no root and no route to the
# internet, with three exceptions that say so and skip themselves rather than
# failing: cargo-audit and cargo-deny have to be installed once, and
# `docker buildx build --check` needs a daemon CI has and a laptop may not.
# A skip is reported as a skip and never as a pass.
#
# POSIX sh.

set -eu

cd "$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$(printf '\033[0m'); C_BOLD=$(printf '\033[1m')
    C_RED=$(printf '\033[31m'); C_GREEN=$(printf '\033[32m')
    C_DIM=$(printf '\033[2m')
else
    C_RESET=''; C_BOLD=''; C_RED=''; C_GREEN=''; C_DIM=''
fi

usage() {
    cat <<'USAGE'
Cogwheel DNS verification gate — everything CI checks, in CI's order.

Usage:
  verify.sh [--list] [--keep-going] [--no-web]

Options:
  --list        Print the commands this would run, in order, and exit.
  --keep-going  Run every check even after one fails, and report at the end.
  --no-web      Skip the apps/cogwheel-web checks (Rust only).
  -h, --help    This message.

Exit status: 0 everything passed, 1 something failed.

cargo-audit and cargo-deny install once:

  cargo install cargo-audit --locked
  cargo install cargo-deny --locked
USAGE
}

LIST=no
KEEP_GOING=no
WEB=yes
while [ $# -gt 0 ]; do
    case "$1" in
        --list)       LIST=yes; shift ;;
        --keep-going) KEEP_GOING=yes; shift ;;
        --no-web)     WEB=no; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            usage >&2; printf 'error: unknown option: %s\n' "$1" >&2; exit 1 ;;
    esac
done

PASSED=''
FAILED=''
SKIPPED=''
STATUS=0

# --list prints from the same code path that runs, so the printed list cannot
# drift from the executed one.
step() {
    _label=$1
    shift
    if [ "$LIST" = yes ]; then
        printf '%s\n' "$*"
        return 0
    fi
    printf '\n%s──  %s%s%s  %s%s\n' "$C_DIM" "$C_RESET$C_BOLD" "$_label" "$C_RESET" "$C_DIM$*" "$C_RESET"
    if "$@"; then
        PASSED="$PASSED $_label"
    else
        STATUS=1
        FAILED="$FAILED $_label"
        printf '%s%s failed.%s\n' "$C_RED" "$_label" "$C_RESET" >&2
        if [ "$KEEP_GOING" = no ]; then
            finish
        fi
    fi
}

skip() {
    if [ "$LIST" = yes ]; then
        return 0
    fi
    SKIPPED="$SKIPPED $1"
    printf '\n%s──  %s  skipped: %s%s\n' "$C_DIM" "$1" "$2" "$C_RESET"
}

# In --list mode every check is listed whether or not its tool is present,
# because the list is the gate and the gate does not shrink to fit a laptop.
have() {
    if [ "$LIST" = yes ]; then
        return 0
    fi
    command -v "$1" >/dev/null 2>&1
}

finish() {
    if [ "$LIST" = yes ]; then
        exit 0
    fi
    printf '\n'
    if [ -n "$PASSED" ]; then
        printf '%spassed%s  %s\n' "$C_GREEN" "$C_RESET" "${PASSED# }"
    fi
    if [ -n "$SKIPPED" ]; then
        printf '%sskipped %s%s\n' "$C_DIM" "${SKIPPED# }" "$C_RESET"
    fi
    if [ -n "$FAILED" ]; then
        printf '%sfailed%s  %s\n' "$C_RED" "$C_RESET" "${FAILED# }"
    fi
    if [ "$STATUS" -eq 0 ]; then
        printf '\n%sThe gate is green.%s\n' "$C_GREEN$C_BOLD" "$C_RESET"
    fi
    exit "$STATUS"
}

# --- Rust -----------------------------------------------------------------
#
# `-- --check` on fmt: without it `cargo fmt --all` rewrites your files and
# exits 0, having told you nothing.
step fmt    cargo fmt --all -- --check
step clippy cargo clippy --workspace --all-targets --all-features -- -D warnings
step test   cargo test --workspace
# --locked fails rather than quietly resolving a different Cargo.lock. A
# lockfile change should be a commit somebody made on purpose.
step build  cargo build --release --locked -p cogwheel-server

if have cargo-audit; then
    step audit cargo audit
else
    skip audit 'cargo install cargo-audit --locked'
fi

if have cargo-deny; then
    step deny cargo deny check
else
    skip deny 'cargo install cargo-deny --locked'
fi

# --- Web ------------------------------------------------------------------
#
# `npm run build` runs `tsc --noEmit` before Vite, so it is the typecheck as
# well as the build. CI always does a clean `npm ci`; locally that is only
# worth the wait when there is nothing installed yet.
if [ "$WEB" = yes ]; then
    if [ "$LIST" = yes ] || [ ! -d apps/cogwheel-web/node_modules ]; then
        step web-deps npm --prefix apps/cogwheel-web ci
    fi
    step web-lint  npm --prefix apps/cogwheel-web run lint
    step web-build npm --prefix apps/cogwheel-web run build
else
    skip web '--no-web'
fi

# --- The shipped scripts and the Dockerfile -------------------------------
if have shellcheck; then
    # Word splitting is the point here: shellcheck takes one argument per script.
    # shellcheck disable=SC2086
    step shellcheck shellcheck scripts/*.sh
else
    skip shellcheck 'shellcheck is not installed'
fi

# `docker buildx version` only proves the plugin is installed. The check builds,
# so it needs a daemon answering -- which is what `docker info` establishes.
if [ "$LIST" = yes ] || docker info >/dev/null 2>&1; then
    step dockerfile docker buildx build --check .
else
    skip dockerfile 'no Docker daemon is answering'
fi

finish
