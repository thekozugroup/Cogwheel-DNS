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
  -e COGWHEEL_STORAGE__DATABASE_URL=sqlite:///app/data/cogwheel.db \
  -v "$DATA_DIR:/app/data" \
  "$IMAGE_TAG"

echo "Cogwheel is running."
echo "- DNS target: $(hostname):${DNS_HOST_PORT}"
echo "- Web UI: http://$(hostname):${WEB_HOST_PORT}"
