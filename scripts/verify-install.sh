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
# scripts/install.sh leaves a copy of this file at /etc/cogwheel/verify-install.sh,
# so a host installed with `curl | sudo sh` -- which has no checkout -- can still
# run it after an upgrade:
#
#   sudo /etc/cogwheel/verify-install.sh
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

# A stock install ships no active rules of its own -- the seeded default list
# has to be fetched first, which a runner with no egress never does. Section 2
# installs a household block rule for this name instead of trusting a list, so
# .test (reserved by RFC 2606, like .example) never resolves for real.
BLOCKED_DOMAIN=blocked.test
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

# DELETE $1; body lands in $BODY_FILE; echoes the HTTP status code.
http_delete() {
    if have curl; then
        curl -s -o "$BODY_FILE" -w '%{http_code}' --max-time "$TIMEOUT" -X DELETE "$BASE$1" 2>/dev/null || printf '000'
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

    # Distinct endpoint from liveness, and a stronger claim: the server holds
    # this at 503 until storage is open at schema v1, a policy is installed and
    # both DNS listeners are bound. A 200 here means the appliance can answer
    # queries, which is what a rolling upgrade should gate on.
    code=$(http_get /health/ready)
    if [ "$code" = 200 ] && grep -q '"status"[[:space:]]*:[[:space:]]*"ready"' "$BODY_FILE"; then
        pass "readiness  GET /health/ready -> 200 {\"data\":{\"status\":\"ready\"}}"
    else
        fail "readiness  GET /health/ready" "got HTTP $code"
    fi

    code=$(http_get /api/v1/overview)
    if [ "$code" = 200 ] && grep -q '"data"' "$BODY_FILE"; then
        pass "api        GET /api/v1/overview -> 200 enveloped JSON"
    else
        fail "api        GET /api/v1/overview" "got HTTP $code"
    fi

    code=$(http_get /)
    if [ "$code" = 200 ] && grep -qi '<html\|<!doctype html' "$BODY_FILE"; then
        pass "web UI     GET / -> 200 HTML (assets are bundled and served)"
    elif [ "$code" = 404 ]; then
        fail "web UI     GET /" "404 - the server started without web assets. Check COGWHEEL_WEB_DIST_DIR."
    else
        fail "web UI     GET /" "got HTTP $code"
    fi

    code=$(http_get /api/v1/overview)
    if [ "$code" = 200 ]; then
        pass "advertised GET /api/v1/overview -> connect.targets present"
        printf '           router should point at: '
        sed -n 's/.*"targets"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p' "$BODY_FILE" | head -1
        printf '\n'
    else
        fail "advertised GET /api/v1/overview" "got HTTP $code"
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
    # timeout here means filtering is not actually running. A marker rule
    # (rather than a subscribed list) supplies the block, so this passes even
    # when no list has downloaded yet.
    if ! have curl; then
        skip "blocked    $BLOCKED_DOMAIN" "needs curl to install a marker block rule"
    else
        code=$(http_post /api/v1/rules "{\"domain\":\"$BLOCKED_DOMAIN\",\"action\":\"block\"}")
        RULE_ID=$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$BODY_FILE" | head -1)
        if [ "$code" != 200 ] || [ -z "$RULE_ID" ]; then
            fail "blocked    $BLOCKED_DOMAIN" "could not install the marker block rule (HTTP $code)"
        else
            answer=$(dns_query "$BLOCKED_DOMAIN" || true)
            if printf '%s' "$answer" | grep -qx '0\.0\.0\.0'; then
                pass "blocked    $BLOCKED_DOMAIN -> 0.0.0.0 (null-routed by the marker rule)"
            elif [ -z "$answer" ]; then
                fail "blocked    $BLOCKED_DOMAIN" "no answer at all - the resolver may not be reachable"
            else
                fail "blocked    $BLOCKED_DOMAIN" "expected 0.0.0.0, got: $(printf '%s' "$answer" | tr '\n' ' ')"
            fi
        fi

        # Always remove the marker, on every path above: this script must not
        # leave a household rule behind just because a later check failed.
        if [ -n "$RULE_ID" ]; then
            if http_delete "/api/v1/rules/$RULE_ID" >/dev/null 2>&1; then
                printf '           removed marker rule for %s\n' "$BLOCKED_DOMAIN"
            else
                printf '           %scould not remove the marker rule for %s - delete it in Lists%s\n' \
                       "$C_YELLOW" "$BLOCKED_DOMAIN" "$C_RESET"
            fi
        fi
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
    # TEST-NET-1 (RFC 5737): never a real device's address, so this cannot
    # collide with anything already on the household's network.
    MARKER_IP="192.0.2.$(( ($$ % 250) + 2 ))"
    payload="{\"name\":\"$MARKER\",\"ip_address\":\"$MARKER_IP\"}"

    code=$(http_post /api/v1/devices "$payload")
    DEVICE_ID=$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$BODY_FILE" | head -1)
    if [ "$code" != 200 ] || [ -z "$DEVICE_ID" ]; then
        fail "persistence" "could not write the marker device (HTTP $code)"
    else
        printf '           wrote marker device "%s" (%s); restarting Cogwheel...\n' "$MARKER" "$MARKER_IP"
        RESTART_METHOD=
        if ! restart_cogwheel; then
            skip "persistence" "no '$CONTAINER_NAME' container and no cogwheel.service found; restart it yourself and re-run"
        elif ! wait_for_http; then
            fail "persistence" "Cogwheel did not come back after '$RESTART_METHOD' - this is a serious failure, check the logs"
        else
            code=$(http_get /api/v1/devices)
            if [ "$code" = 200 ] && grep -q "$MARKER" "$BODY_FILE"; then
                pass "persistence  marker survived '$RESTART_METHOD' (the data volume is real)"
            else
                fail "persistence  marker did NOT survive the restart" \
                     "state is being written somewhere ephemeral - check the /app/data volume mount"
            fi
        fi

        # Always clean up, on every path above: a verification script must not
        # leave records behind, least of all when it failed partway through.
        if http_delete "/api/v1/devices/$DEVICE_ID" >/dev/null 2>&1; then
            printf '           removed marker device "%s"\n' "$MARKER"
        else
            printf '           %scould not remove marker device "%s" - delete it in Devices%s\n' \
                   "$C_YELLOW" "$MARKER" "$C_RESET"
        fi
    fi
fi

# ==========================================================================
head_ "4. The update path"
# ==========================================================================
#
# Checking that Cogwheel answers is half the job. The other half is whether the
# next update will reach this host at all, and that is the part nobody notices
# is broken until a security fix has been out for three months. Everything here
# is read-only.

COMPOSE_DIR="${COGWHEEL_CONFIG_DIR:-/etc/cogwheel}"

compose_cmd() {
    if have docker && docker compose version >/dev/null 2>&1; then
        ( cd "$COMPOSE_DIR" && docker compose "$@" )
    elif have docker-compose; then
        ( cd "$COMPOSE_DIR" && docker-compose "$@" )
    else
        return 127
    fi
}

if [ ! -f "$COMPOSE_DIR/docker-compose.yml" ]; then
    skip "update     no Compose project at $COMPOSE_DIR" \
         "this host was not set up by scripts/install.sh; upgrade from wherever its compose file lives"
elif ! have docker; then
    skip "update     docker is not on PATH"
elif ! compose_cmd config -q >/dev/null 2>&1; then
    fail "update     $COMPOSE_DIR/docker-compose.yml does not parse" \
         "run: cd $COMPOSE_DIR && docker compose config"
else
    pass "update     the Compose project at $COMPOSE_DIR is valid"
    printf '           upgrade with: cd %s && sudo docker compose pull && sudo docker compose up -d\n' "$COMPOSE_DIR"

    # Which tag this host follows decides whether an update can ever arrive by
    # itself. Both answers are legitimate; only one of them is a surprise.
    if have docker && docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
        REF=$(docker container inspect --format '{{.Config.Image}}' "$CONTAINER_NAME" 2>/dev/null || printf '')
        case "$REF" in
            *@sha256:*)
                printf '           pinned by digest (%s)\n' "$REF"
                printf '           %sdocker compose pull will never move this host. That is a choice; make sure it was yours.%s\n' "$C_YELLOW" "$C_RESET" ;;
            *:latest)
                printf '           following %s - a pull takes the newest final release\n' "$REF" ;;
            *)
                printf '           pinned to %s\n' "$REF"
                printf '           edit COGWHEEL_IMAGE in %s/.env to follow a moving tag\n' "$COMPOSE_DIR" ;;
        esac

        SCHEMA=$(docker image inspect --format '{{index .Config.Labels "io.cogwheel.schema-version"}}' "$REF" 2>/dev/null || printf '')
        [ -n "$SCHEMA" ] && printf '           database schema v%s (a release that changes this migrates in place)\n' "$SCHEMA"
    fi
fi

# ==========================================================================
printf '\n%s%s%s\n' "$C_BOLD" "-----------------------------------------------" "$C_RESET"
printf '  %s%d passed%s' "$C_GREEN" "$PASS_COUNT" "$C_RESET"
[ "$FAIL_COUNT" -gt 0 ] && printf ', %s%d failed%s' "$C_RED" "$FAIL_COUNT" "$C_RESET"
[ "$SKIP_COUNT" -gt 0 ] && printf ', %s%d skipped%s' "$C_YELLOW" "$SKIP_COUNT" "$C_RESET"
printf '\n\n'

if [ "$FAIL_COUNT" -gt 0 ]; then
    printf '  Troubleshooting: docs/DEPLOYMENT.md section 8.\n'
    printf '  Start with port 53 - it is the most common cause.\n\n'
    exit 1
fi

printf '  Cogwheel is working. Point your router at it and you are done.\n\n'
