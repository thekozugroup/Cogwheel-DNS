#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this helper as root so it can install host firewall rules for tailscale0." >&2
  exit 1
fi

DNS_HOST_PORT="${DNS_HOST_PORT:-53}"
TAILSCALE_INTERFACE="${TAILSCALE_INTERFACE:-tailscale0}"

ensure_redirect() {
  local binary="$1"
  local protocol="$2"

  if ! command -v "$binary" >/dev/null 2>&1; then
    echo "Skipping ${binary}; command not found." >&2
    return 0
  fi

  if ! "$binary" -t nat -C PREROUTING -i "$TAILSCALE_INTERFACE" -p "$protocol" --dport 53 -j REDIRECT --to-ports "$DNS_HOST_PORT" >/dev/null 2>&1; then
    "$binary" -t nat -I PREROUTING 1 -i "$TAILSCALE_INTERFACE" -p "$protocol" --dport 53 -j REDIRECT --to-ports "$DNS_HOST_PORT"
  fi
}

ensure_redirect iptables udp
ensure_redirect iptables tcp
ensure_redirect ip6tables udp
ensure_redirect ip6tables tcp

echo "Tailscale DNS interception is active on ${TAILSCALE_INTERFACE} -> local port ${DNS_HOST_PORT}."
