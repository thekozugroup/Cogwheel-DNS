#!/bin/sh
#
# Cogwheel DNS — post-install verification.
#
#   sh scripts/verify-install.sh
#   sh scripts/verify-install.sh --host 10.0.0.2
#
# Every check here corresponds to something a user will notice if it is broken.
# It exits non-zero if any check fails, so it is safe to run from a cron job or
# a monitoring script as well as by hand after an install or upgrade.
#
# The persistence check restarts Cogwheel, which causes a few seconds of DNS
# downtime. Pass --skip-restart to leave it out.
#
# POSIX sh. Needs curl (or wget) and dig (or nslookup); it reports SKIP rather
# than inventing a result when a tool is missing.

set -eu

HTTP_HOST=127.0.0.1
DNS_HOST=127.0.0.1
HTTP_PORT="${COGWHEEL_HTTP_PORT:-8080}"
DNS_PORT="${COGWHEEL_DNS_PORT:-53}"
TIMEOUT=5
SKIP_RESTART=no
CONTAINER_NAME="${COGWHEEL_CONTAINER_NAME:-cogwheel}"

# Blocked on a stock install before any list is configured.
BLOCKED_DOMAIN=ads.example.com
# Never on a blocklist, and reserved by RFC 2606 so it cannot be bought.
ALLOWED_DOMAIN=example.com

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$(printf '\033[0m'); C_BOLD=$(printf '\033[1m')
    C_RED=$(printf '\033[31m'); C_YELLOW=$(printf '\033[33m'); C_GREEN=$(printf '\033[32m')
else
    C_RESET=''; C_BOLD=''; C_RED=''; C_YELLOW=''; C_GREEN=''
fi

pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf '  %s[ PASS ]%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf '  %s[ FAIL ]%s %s\n' "$C_RED" "$C_RESET" "$1"
         [ $# -gt 1 ] && printf '           %s\n' "$2"; return 0; }
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); printf '  %s[ SKIP ]%s %s\n' "$C_YELLOW" "$C_RESET" "$1"
         [ $# -gt 1 ] && printf '           %s\n' "$2"; return 0; }
head_() { printf '\n%s%s%s\n' "$C_BOLD" "$1" "$C_RESET"; }

usage() {
    cat <<'USAGE'
Cogwheel DNS post-install verification

Usage:
  verify-install.sh [options]

Options:
  --host HOST         Host for both HTTP and DNS checks (default: 127.0.0.1)
  --http-host HOST    Override just the HTTP host
  --dns-host HOST     Override just the DNS host
  --http-port PORT    Web UI / API port (default: 8080)
  --dns-port PORT     DNS port (default: 53)
  --container NAME    Docker container name for the restart check
                      (default: cogwheel)
  --skip-restart      Do not run the persistence check
  -h, --help          This message

Exit status is 0 only if no check failed.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --host)         HTTP_HOST="${2:?}"; DNS_HOST="$2"; shift 2 ;;
        --http-host)    HTTP_HOST="${2:?}"; shift 2 ;;
        --dns-host)     DNS_HOST="${2:?}"; shift 2 ;;
        --http-port)    HTTP_PORT="${2:?}"; shift 2 ;;
        --dns-port)     DNS_PORT="${2:?}"; shift 2 ;;
        --container)    CONTAINER_NAME="${2:?}"; shift 2 ;;
        --skip-restart) SKIP_RESTART=yes; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              usage >&2; printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done

BASE="http://$HTTP_HOST:$HTTP_PORT"
BODY_FILE=$(mktemp)
trap 'rm -f "$BODY_FILE"' EXIT INT TERM

have() { command -v "$1" >/dev/null 2>&1; }

# GET $1; body lands in $BODY_FILE; echoes the HTTP status code.
http_get() {
    if have curl; then
        curl -s -o "$BODY_FILE" -w '%{http_code}' --max-time "$TIMEOUT" "$BASE$1" 2>/dev/null || printf '000'
    elif have wget; then
        if wget -q -O "$BODY_FILE" -T "$TIMEOUT" "$BASE$1" 2>/dev/null; then printf '200'; else printf '000'; fi
    else
        printf '000'
    fi
}

# POST JSON $2 to $1; body lands in $BODY_FILE; echoes the HTTP status code.
http_post() {
    if have curl; then
        curl -s -o "$BODY_FILE" -w '%{http_code}' --max-time "$TIMEOUT" \
             -X POST -H 'Content-Type: application/json' -d "$2" "$BASE$1" 2>/dev/null || printf '000'
    else
        printf '000'
    fi
}

dns_query() { # dns_query <domain> [extra dig flag]
    if have dig; then
        dig +short +timeout=3 +tries=2 ${2:+"$2"} -p "$DNS_PORT" "@$DNS_HOST" "$1" A 2>/dev/null
    elif have nslookup; then
        nslookup -type=A -port="$DNS_PORT" "$1" "$DNS_HOST" 2>/dev/null |
            sed -n 's/^Address: *//p'
    else
        return 1
    fi
}

printf '%sCogwheel post-install verification%s\n' "$C_BOLD" "$C_RESET"
printf '  Web/API : %s\n' "$BASE"
printf '  DNS     : %s port %s\n' "$DNS_HOST" "$DNS_PORT"

# ==========================================================================
head_ "1. Control plane"
# ==========================================================================

if ! have curl && ! have wget; then
    skip "all HTTP checks" "neither curl nor wget is installed"
else
    code=$(http_get /health/live)
    if [ "$code" = 200 ] && grep -q '"status"[[:space:]]*:[[:space:]]*"ok"' "$BODY_FILE"; then
        pass "liveness   GET /health/live -> 200 {\"data\":{\"status\":\"ok\"}}"
    else
        fail "liveness   GET /health/live" "got HTTP $code; the server is not up on $BASE"
    fi

    # Distinct endpoint from liveness. Note it is currently an unconditional
    # stub on the server: a 200 here means the HTTP listener is answering, not
    # that the database and resolver were probed.
    code=$(http_get /health/ready)
    if [ "$code" = 200 ] && grep -q '"status"[[:space:]]*:[[:space:]]*"ready"' "$BODY_FILE"; then
        pass "readiness  GET /health/ready -> 200 {\"data\":{\"status\":\"ready\"}}"
    else
        fail "readiness  GET /health/ready" "got HTTP $code"
    fi

    code=$(http_get /api/v1/dashboard)
    if [ "$code" = 200 ] && grep -q '"data"' "$BODY_FILE"; then
        pass "api        GET /api/v1/dashboard -> 200 enveloped JSON"
    else
        fail "api        GET /api/v1/dashboard" "got HTTP $code"
    fi

    code=$(http_get /)
    if [ "$code" = 200 ] && grep -qi '<html\|<!doctype html' "$BODY_FILE"; then
        pass "web UI     GET / -> 200 HTML (assets are bundled and served)"
    elif [ "$code" = 404 ]; then
        fail "web UI     GET /" "404 - the server started without web assets. Check COGWHEEL_WEB_DIST_DIR."
    else
        fail "web UI     GET /" "got HTTP $code"
    fi

    code=$(http_get /api/v1/resolver-access)
    if [ "$code" = 200 ]; then
        pass "advertised GET /api/v1/resolver-access -> 200"
        printf '           router should point at: '
        sed -n 's/.*"dns_targets"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p' "$BODY_FILE" | head -1
        printf '\n'
    else
        fail "advertised GET /api/v1/resolver-access" "got HTTP $code"
    fi
fi

# ==========================================================================
head_ "2. Resolver"
# ==========================================================================

if ! have dig && ! have nslookup; then
    skip "all DNS checks" "install dig (apt-get install -y dnsutils) or nslookup, then re-run"
else
    answer=$(dns_query "$ALLOWED_DOMAIN" || true)
    if [ -n "$answer" ] && printf '%s' "$answer" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' &&
       ! printf '%s' "$answer" | grep -qx '0\.0\.0\.0'; then
        pass "allowed    $ALLOWED_DOMAIN -> $(printf '%s' "$answer" | tr '\n' ' ')"
    else
        fail "allowed    $ALLOWED_DOMAIN" "expected a real A record, got: ${answer:-<no answer>}"
    fi

    # A blocked domain must resolve, but to the null address. An NXDOMAIN or a
    # timeout here means filtering is not actually running.
    answer=$(dns_query "$BLOCKED_DOMAIN" || true)
    if printf '%s' "$answer" | grep -qx '0\.0\.0\.0'; then
        pass "blocked    $BLOCKED_DOMAIN -> 0.0.0.0 (null-routed by policy)"
    elif [ -z "$answer" ]; then
        fail "blocked    $BLOCKED_DOMAIN" "no answer at all - the resolver may not be reachable"
    else
        fail "blocked    $BLOCKED_DOMAIN" "expected 0.0.0.0, got: $(printf '%s' "$answer" | tr '\n' ' ')"
    fi

    if have dig; then
        answer=$(dns_query "$ALLOWED_DOMAIN" "+tcp" || true)
        if [ -n "$answer" ]; then
            pass "tcp        $ALLOWED_DOMAIN over TCP/$DNS_PORT answers"
        else
            fail "tcp        $ALLOWED_DOMAIN over TCP/$DNS_PORT" \
                 "UDP works but TCP does not. Large responses and zone transfers will fail; check that both 53/tcp and 53/udp are open."
        fi
    else
        skip "tcp        DNS over TCP" "needs dig"
    fi
fi

# ==========================================================================
head_ "3. Persistence across a restart"
# ==========================================================================

restart_cogwheel() {
    if have docker && docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
        RESTART_METHOD="docker restart $CONTAINER_NAME"
        docker restart "$CONTAINER_NAME" >/dev/null 2>&1
    elif have systemctl && systemctl cat cogwheel.service >/dev/null 2>&1; then
        RESTART_METHOD="systemctl restart cogwheel"
        systemctl restart cogwheel.service >/dev/null 2>&1
    else
        return 1
    fi
}

wait_for_http() {
    _w=0
    while [ "$_w" -lt 90 ]; do
        [ "$(http_get /health/live)" = 200 ] && return 0
        _w=$((_w + 3))
        sleep 3
    done
    return 1
}

if [ "$SKIP_RESTART" = yes ]; then
    skip "persistence" "--skip-restart was given"
elif ! have curl; then
    skip "persistence" "needs curl to write and read back a marker record"
elif [ "$(http_get /health/live)" != 200 ]; then
    skip "persistence" "control plane is not answering; fix section 1 first"
else
    MARKER="verify-$(date +%s)"
    payload="{\"emoji\":\"🔎\",\"name\":\"$MARKER\",\"description\":\"temporary record written by verify-install.sh\",\"blocklists\":[],\"allowlists\":[]}"

    code=$(http_post /api/v1/settings/block-profiles "$payload")
    if [ "$code" != 200 ]; then
        fail "persistence" "could not write the marker record (HTTP $code)"
    else
        printf '           wrote marker "%s"; restarting Cogwheel...\n' "$MARKER"
        RESTART_METHOD=
        if ! restart_cogwheel; then
            skip "persistence" "no '$CONTAINER_NAME' container and no cogwheel.service found; restart it yourself and re-run"
        elif ! wait_for_http; then
            fail "persistence" "Cogwheel did not come back after '$RESTART_METHOD' - this is a serious failure, check the logs"
        else
            code=$(http_get /api/v1/settings)
            if [ "$code" = 200 ] && grep -q "$MARKER" "$BODY_FILE"; then
                pass "persistence  marker survived '$RESTART_METHOD' (the data volume is real)"
            else
                fail "persistence  marker did NOT survive the restart" \
                     "state is being written somewhere ephemeral - check the /app/data volume mount"
            fi
        fi

        # Always clean up, on every path above: a verification script must not
        # leave records behind, least of all when it failed partway through.
        if http_post /api/v1/settings/block-profiles/delete "{\"id\":\"$MARKER\"}" >/dev/null 2>&1; then
            printf '           removed marker "%s"\n' "$MARKER"
        else
            printf '           %scould not remove marker "%s" - delete it in Settings%s\n' \
                   "$C_YELLOW" "$MARKER" "$C_RESET"
        fi
    fi
fi

# ==========================================================================
printf '\n%s%s%s\n' "$C_BOLD" "-----------------------------------------------" "$C_RESET"
printf '  %s%d passed%s' "$C_GREEN" "$PASS_COUNT" "$C_RESET"
[ "$FAIL_COUNT" -gt 0 ] && printf ', %s%d failed%s' "$C_RED" "$FAIL_COUNT" "$C_RESET"
[ "$SKIP_COUNT" -gt 0 ] && printf ', %s%d skipped%s' "$C_YELLOW" "$SKIP_COUNT" "$C_RESET"
printf '\n\n'

if [ "$FAIL_COUNT" -gt 0 ]; then
    printf '  Troubleshooting: DEPLOYMENT.md section 8.\n'
    printf '  Start with port 53 - it is the most common cause.\n\n'
    exit 1
fi

printf '  Cogwheel is working. Point your router at it and you are done.\n\n'
