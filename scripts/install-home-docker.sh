#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root so it can publish port 53 and adjust local resolver settings." >&2
  exit 1
fi

IMAGE_TAG="${IMAGE_TAG:-cogwheel-server:latest}"
CONTAINER_NAME="${CONTAINER_NAME:-cogwheel}"
DATA_DIR="${DATA_DIR:-/var/lib/cogwheel}"
DNS_HOST_PORT="${DNS_HOST_PORT:-53}"
WEB_HOST_PORT="${WEB_HOST_PORT:-30080}"
INSTALL_TAILSCALE="${INSTALL_TAILSCALE:-0}"
TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY:-}"
ADVERTISED_DNS_TARGETS="${COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "$ADVERTISED_DNS_TARGETS" ]]; then
  HOST_SHORTNAME="$(hostname)"
  IPV4_TARGETS="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' || true)"
  IPV6_TARGETS="$(ip -6 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true)"
  ADVERTISED_DNS_TARGETS="$HOST_SHORTNAME"
  if [[ -n "$IPV4_TARGETS" ]]; then
    while IFS= read -r ip; do
      [[ -n "$ip" ]] && ADVERTISED_DNS_TARGETS+=",$ip"
    done <<< "$IPV4_TARGETS"
  fi
  if [[ -n "$IPV6_TARGETS" ]]; then
    while IFS= read -r ip; do
      [[ -n "$ip" ]] && ADVERTISED_DNS_TARGETS+=",$ip"
    done <<< "$IPV6_TARGETS"
  fi
fi

if [[ "$DNS_HOST_PORT" == "53" ]] && command -v systemctl >/dev/null 2>&1; then
  mkdir -p /etc/systemd/resolved.conf.d
  cat >/etc/systemd/resolved.conf.d/cogwheel.conf <<'EOF'
[Resolve]
DNSStubListener=no
EOF
  systemctl restart systemd-resolved >/dev/null 2>&1 || true
fi

if ss -lntup "( sport = :${DNS_HOST_PORT} )" | grep -q LISTEN; then
  echo "Port ${DNS_HOST_PORT} is still busy. Stop the conflicting DNS service, then rerun this installer." >&2
  exit 1
fi

if [[ "$INSTALL_TAILSCALE" == "1" ]]; then
  curl -fsSL https://tailscale.com/install.sh | sh
  if [[ -n "$TAILSCALE_AUTH_KEY" ]]; then
    tailscale up --auth-key "$TAILSCALE_AUTH_KEY" --advertise-exit-node --accept-dns=false
  else
    echo "Tailscale installed. Complete 'tailscale up --advertise-exit-node --accept-dns=false' after authenticating the node." >&2
  fi

  DNS_HOST_PORT="$DNS_HOST_PORT" "$SCRIPT_DIR/apply-tailscale-dns-intercept.sh"
fi

mkdir -p "$DATA_DIR"
chown -R 10001:10001 "$DATA_DIR"

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

docker run -d \
  --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  -p "${DNS_HOST_PORT}:30053/udp" \
  -p "${DNS_HOST_PORT}:30053/tcp" \
  -p "${WEB_HOST_PORT}:30080" \
  -e COGWHEEL_PROFILE=dev \
  -e COGWHEEL_SERVER__HTTP_BIND_ADDR=0.0.0.0:30080 \
  -e COGWHEEL_SERVER__DNS_UDP_BIND_ADDR=0.0.0.0:30053 \
  -e COGWHEEL_SERVER__DNS_TCP_BIND_ADDR=0.0.0.0:30053 \
  -e COGWHEEL_SERVER__ADVERTISED_DNS_PORT="${DNS_HOST_PORT}" \
  -e COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS="${ADVERTISED_DNS_TARGETS}" \
  -e COGWHEEL_STORAGE__DATABASE_URL=sqlite:///app/data/cogwheel.db \
  -v "$DATA_DIR:/app/data" \
  "$IMAGE_TAG"

echo "Cogwheel is running."
echo "- DNS targets: ${ADVERTISED_DNS_TARGETS}"
echo "- Web UI: http://$(hostname):${WEB_HOST_PORT}"
if [[ "$INSTALL_TAILSCALE" == "1" ]]; then
  echo "- Tailscale exit-node advertising prepared. Toggle it in Settings once the node is authenticated."
  echo "- Tailscale DNS interception is pinned to tailscale0 so exit-node DNS traffic reaches Cogwheel."
fi
