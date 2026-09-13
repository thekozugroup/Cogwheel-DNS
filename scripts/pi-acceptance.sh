#!/bin/sh
# Cogwheel acceptance test — run this ON the Raspberry Pi after installing.
#
#   sudo sh scripts/pi-acceptance.sh [--http HOST:PORT] [--dns HOST[:PORT]]
#
# Proves the appliance actually works on the hardware, rather than that it started.
# Every check prints PASS or FAIL and the script exits non-zero if any FAIL.
#
# This differs from scripts/verify-install.sh: that one checks a deployment is wired up
# correctly, this one proves the appliance resolves, filters and survives a restart on the
# real hardware. Run it once per new hardware target.

set -eu

HTTP="127.0.0.1:8080"
DNS="127.0.0.1"
FAILURES=0
PASSES=0

while [ $# -gt 0 ]; do
    case "$1" in
        --http) HTTP="$2"; shift 2 ;;
        --dns) DNS="$2"; shift 2 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

DNS_HOST="${DNS%%:*}"
case "$DNS" in
    *:*) DNS_PORT="${DNS##*:}" ;;
    *)   DNS_PORT="53" ;;
esac

pass() { PASSES=$((PASSES + 1)); printf '  PASS  %s\n' "$1"; }
fail() { FAILURES=$((FAILURES + 1)); printf '  FAIL  %s\n' "$1"; }
info() { printf '        %s\n' "$1"; }
head_() { printf '\n== %s ==\n' "$1"; }

api() { curl -fsS --max-time 10 "http://${HTTP}$1" 2>/dev/null; }

# ---------------------------------------------------------------- host

head_ "Host"
info "$(uname -srm)"
if [ -r /proc/device-tree/model ]; then
    info "$(tr -d '\0' < /proc/device-tree/model)"
fi
info "$(nproc) CPUs, $(awk '/MemTotal/ {printf "%.1f GB RAM", $2/1024/1024}' /proc/meminfo)"
ARCH="$(uname -m)"
case "$ARCH" in
    aarch64|arm64) pass "64-bit ARM userland ($ARCH)" ;;
    x86_64) pass "x86_64 host ($ARCH) — not a Pi, but supported" ;;
    *) fail "unsupported architecture: $ARCH (Cogwheel needs a 64-bit OS)" ;;
esac

# ---------------------------------------------------------------- service

head_ "Service"
if api /health/live >/dev/null; then
    pass "liveness responds at http://${HTTP}/health/live"
else
    fail "liveness did not respond at http://${HTTP}/health/live"
    echo
    echo "Cannot continue without the control plane. Check: docker ps / systemctl status cogwheel"
    exit 1
fi

READY="$(api /health/ready || true)"
if printf '%s' "$READY" | grep -q '"status":"ready"'; then
    pass "readiness reports ready"
else
    fail "readiness is not ready — a subsystem is still starting or failed"
    info "$READY"
fi
printf '%s' "$READY" | tr ',' '\n' | grep -E 'storage|policy|dns_listeners' | sed 's/^/        /' || true

# ---------------------------------------------------------------- dns

head_ "DNS resolution"
if ! command -v dig >/dev/null 2>&1; then
    info "dig not installed; using a built-in query instead"
    DIG=0
else
    DIG=1
fi

query() { # query <name> -> prints answer IPs, empty on failure
    if [ "$DIG" -eq 1 ]; then
        dig +short +timeout=3 +tries=1 "@${DNS_HOST}" -p "${DNS_PORT}" "$1" A 2>/dev/null
    else
        python3 - "$1" "$DNS_HOST" "$DNS_PORT" <<'PY' 2>/dev/null
import socket, struct, sys, random
name, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
tid = random.randint(0, 65535)
pkt = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0) \
    + b''.join(bytes([len(l)]) + l.encode() for l in name.split('.')) + b'\x00' \
    + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(pkt, (host, port))
data, _ = s.recvfrom(4096)
count = struct.unpack('>H', data[6:8])[0]
i = 12
while data[i] != 0:
    i += 1 + data[i]
i += 5
for _ in range(count):
    i += 2
    rtype, _, _, rdlen = struct.unpack('>HHIH', data[i:i+10]); i += 10
    if rtype == 1 and rdlen == 4:
        print('.'.join(str(b) for b in data[i:i+4]))
    i += rdlen
PY
    fi
}

ALLOWED="$(query example.com || true)"
if [ -n "$ALLOWED" ]; then
    pass "resolves example.com -> $(printf '%s' "$ALLOWED" | tr '\n' ' ')"
else
    fail "could not resolve example.com through ${DNS_HOST}:${DNS_PORT}"
fi

BLOCKED="$(query doubleclick.net || true)"
if printf '%s' "$BLOCKED" | grep -q '^0\.0\.0\.0$'; then
    pass "blocks doubleclick.net (returns 0.0.0.0)"
elif [ -z "$BLOCKED" ]; then
    fail "no answer for doubleclick.net"
else
    info "doubleclick.net -> $(printf '%s' "$BLOCKED" | tr '\n' ' ')"
    fail "doubleclick.net still resolved — filtering is not working (on a fresh install the lists may still be downloading: wait for the first refresh, then re-run)"
fi

# ---------------------------------------------------------------- web

head_ "Web control plane"
for route in / /activity /devices /protection /settings; do
    CODE="$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 10 "http://${HTTP}${route}" 2>/dev/null || echo 000)"
    if [ "$CODE" = "200" ]; then
        pass "GET ${route} -> 200"
    else
        fail "GET ${route} -> ${CODE}"
    fi
done
CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${HTTP}/api/v1/definitely-not-real" 2>/dev/null || echo 000)"
if [ "$CODE" = "404" ]; then
    pass "unknown API path -> 404"
else
    fail "unknown API path -> ${CODE} (expected 404)"
fi

# ---------------------------------------------------------------- persistence

head_ "Persistence across restart"
BEFORE="$(api /api/v1/runtime | tr ',' '\n' | sed -n 's/.*"queries_total":\([0-9]*\).*/\1/p' | head -1 || true)"
info "queries_total before restart: ${BEFORE:-unknown}"
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx cogwheel; then
    docker restart cogwheel >/dev/null 2>&1 || true
    RESTARTED=1
elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet cogwheel 2>/dev/null; then
    systemctl restart cogwheel || true
    RESTARTED=1
else
    RESTARTED=0
    info "could not find a cogwheel container or unit to restart; skipping"
fi

if [ "$RESTARTED" -eq 1 ]; then
    i=0
    while [ "$i" -lt 60 ]; do
        api /health/ready >/dev/null 2>&1 && break
        i=$((i + 1)); sleep 1
    done
    if api /health/ready >/dev/null 2>&1; then
        pass "came back ready after a restart in ${i}s"
    else
        fail "did not become ready within 60s of restart"
    fi
    AFTER="$(query example.com || true)"
    if [ -n "$AFTER" ]; then
        pass "still resolving after restart"
    else
        fail "not resolving after restart"
    fi
fi

# ---------------------------------------------------------------- result

head_ "Result"
printf '  %d passed, %d failed\n\n' "$PASSES" "$FAILURES"
if [ "$FAILURES" -gt 0 ]; then
    echo "Acceptance FAILED. Logs:  docker logs cogwheel   |   journalctl -u cogwheel -n 100"
    exit 1
fi
echo "Acceptance PASSED on $(uname -m)."
