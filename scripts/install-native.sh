#!/bin/sh
#
# Cogwheel DNS — native (non-Docker) install onto a systemd host.
#
#   sudo ./scripts/install-native.sh                    # build from this checkout
#   sudo ./scripts/install-native.sh --tarball FILE     # install a release artifact
#   sudo ./scripts/install-native.sh --uninstall
#
# Use this when you do not want Docker on the box: a bare Raspberry Pi OS
# install, or a host where Docker's networking would get in the way. It is
# strictly more work to maintain than the container install -- you own the
# toolchain and the upgrades -- so prefer scripts/install.sh unless you have a
# reason not to.
#
# Layout it produces:
#   /usr/local/bin/cogwheel-server         binary
#   /usr/local/share/cogwheel/web          web assets
#   /etc/cogwheel/cogwheel.env             configuration (preserved on upgrade)
#   /var/lib/cogwheel                      SQLite database, owned by cogwheel
#   /etc/systemd/system/cogwheel.service   from deploy/cogwheel.service
#
# POSIX sh.

set -eu

INSTALLER_VERSION="1.0.0"

SERVICE_USER=cogwheel
SERVICE_GROUP=cogwheel
BIN_PATH=/usr/local/bin/cogwheel-server
WEB_DIR=/usr/local/share/cogwheel/web
CONFIG_DIR=/etc/cogwheel
ENV_FILE="$CONFIG_DIR/cogwheel.env"
DATA_DIR=/var/lib/cogwheel
UNIT_PATH=/etc/systemd/system/cogwheel.service

DNS_PORT="${COGWHEEL_DNS_PORT:-53}"
HTTP_PORT="${COGWHEEL_HTTP_PORT:-8080}"
# Whether the port came from the command line, as opposed to the default above.
# An upgrade adopts the ports recorded in an existing cogwheel.env, but an
# explicit flag has to win over it -- that is how a port gets changed.
DNS_PORT_EXPLICIT=no
HTTP_PORT_EXPLICIT=no
UPSTREAM_SERVERS="${COGWHEEL_UPSTREAM_SERVERS:-1.1.1.1:53,1.0.0.1:53}"
PROFILE="${COGWHEEL_PROFILE:-home}"

ACTION=install
TARBALL=
FORCE_ENV=no
PURGE=no
SKIP_BUILD=no

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$(printf '\033[0m'); C_BOLD=$(printf '\033[1m')
    C_RED=$(printf '\033[31m'); C_YELLOW=$(printf '\033[33m'); C_GREEN=$(printf '\033[32m')
else
    C_RESET=''; C_BOLD=''; C_RED=''; C_YELLOW=''; C_GREEN=''
fi

log()  { printf '%s==>%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
step() { printf '%s--%s %s\n' "$C_BOLD" "$C_RESET" "$*"; }
warn() { printf '%swarning:%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()  { printf '%serror:%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
    cat <<'USAGE'
Cogwheel DNS native installer

Usage:
  install-native.sh [options]
  install-native.sh --uninstall [--purge]

Options:
  --tarball FILE     Install from a release tarball instead of building.
                     Expects cogwheel-server and web/ inside it.
  --skip-build       Use binaries already present in this checkout
                     (target/release/cogwheel-server, apps/cogwheel-web/dist)
  --dns-port PORT    Port for DNS (default: 53)
  --http-port PORT   Port for the web UI (default: 8080)
  --upstream LIST    Comma-separated upstream resolvers
  --profile NAME     dev | home | smb (default: home)
  --force-env        Overwrite /etc/cogwheel/cogwheel.env
                     (default: an existing file is preserved on upgrade)
  --uninstall        Stop, disable and remove Cogwheel
  --purge            With --uninstall, also delete /var/lib/cogwheel
  -h, --help         This message
USAGE
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --tarball)    TARBALL="${2:?--tarball needs a path}"; shift 2 ;;
            --skip-build) SKIP_BUILD=yes; shift ;;
            --dns-port)   DNS_PORT="${2:?--dns-port needs a value}"; DNS_PORT_EXPLICIT=yes; shift 2 ;;
            --http-port)  HTTP_PORT="${2:?--http-port needs a value}"; HTTP_PORT_EXPLICIT=yes; shift 2 ;;
            --upstream)   UPSTREAM_SERVERS="${2:?--upstream needs a value}"; shift 2 ;;
            --profile)    PROFILE="${2:?--profile needs a value}"; shift 2 ;;
            --force-env)  FORCE_ENV=yes; shift ;;
            --uninstall)  ACTION=uninstall; shift ;;
            --purge)      PURGE=yes; shift ;;
            -h|--help)    usage; exit 0 ;;
            *)            usage >&2; die "unknown option: $1" ;;
        esac
    done
    case "$PROFILE" in
        dev|home|smb) ;;
        *) die "--profile must be dev, home or smb; got '$PROFILE'" ;;
    esac
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "must run as root. Try: sudo $0"
}

require_systemd() {
    command -v systemctl >/dev/null 2>&1 ||
        die "systemctl not found. This installer targets systemd hosts.
     On a non-systemd host, use the container install: scripts/install.sh"
    [ -d /run/systemd/system ] ||
        die "systemd is not running as PID 1 on this host.
     Use the container install instead: scripts/install.sh"
}

ensure_service_user() {
    if getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        step "Group '$SERVICE_GROUP' already exists"
    else
        groupadd --system "$SERVICE_GROUP"
        step "Created group '$SERVICE_GROUP'"
    fi

    if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        step "User '$SERVICE_USER' already exists"
    else
        useradd --system --gid "$SERVICE_GROUP" \
                --home-dir "$DATA_DIR" --no-create-home \
                --shell /usr/sbin/nologin \
                --comment "Cogwheel DNS" "$SERVICE_USER"
        step "Created system user '$SERVICE_USER'"
    fi
}

build_from_source() {
    command -v cargo >/dev/null 2>&1 ||
        die "cargo not found. Install a Rust toolchain (https://rustup.rs), or
     pass --tarball with a release artifact from
     https://github.com/thekozugroup/Cogwheel-DNS/releases"
    command -v npm >/dev/null 2>&1 ||
        die "npm not found. Install Node.js 22+, or pass --tarball instead."

    step "Building the server (this takes a while on a Pi)"
    ( cd "$REPO_ROOT" && cargo build --release --locked -p cogwheel-server )

    step "Building the web control plane"
    ( cd "$REPO_ROOT/apps/cogwheel-web" && npm ci --no-audit --no-fund && npm run build )

    SRC_BIN="$REPO_ROOT/target/release/cogwheel-server"
    SRC_WEB="$REPO_ROOT/apps/cogwheel-web/dist"
}

use_prebuilt() {
    SRC_BIN="$REPO_ROOT/target/release/cogwheel-server"
    SRC_WEB="$REPO_ROOT/apps/cogwheel-web/dist"
    [ -x "$SRC_BIN" ] || die "--skip-build given but $SRC_BIN is missing or not executable"
    [ -f "$SRC_WEB/index.html" ] || die "--skip-build given but $SRC_WEB/index.html is missing"
    step "Using prebuilt artifacts from this checkout"
}

unpack_tarball() {
    [ -f "$TARBALL" ] || die "tarball not found: $TARBALL"
    UNPACK_DIR=$(mktemp -d)
    # Cleaned up by the trap installed in do_install.
    tar -xzf "$TARBALL" -C "$UNPACK_DIR"

    SRC_BIN=$(find "$UNPACK_DIR" -type f -name cogwheel-server -perm -u+x | head -n 1)
    [ -n "$SRC_BIN" ] || die "no executable 'cogwheel-server' inside $TARBALL"

    SRC_WEB=$(dirname "$(find "$UNPACK_DIR" -type f -path '*/web/index.html' | head -n 1)" 2>/dev/null || true)
    if [ -z "$SRC_WEB" ] || [ ! -f "$SRC_WEB/index.html" ]; then
        warn "no web assets in $TARBALL; the API will serve without a UI"
        SRC_WEB=
    fi
    step "Unpacked $TARBALL"
}

install_files() {
    install -Dm0755 "$SRC_BIN" "$BIN_PATH"
    step "Installed $BIN_PATH"

    if [ -n "$SRC_WEB" ]; then
        rm -rf "$WEB_DIR"
        mkdir -p "$WEB_DIR"
        # `cp -R src/.` copies the contents, not the directory itself.
        cp -R "$SRC_WEB/." "$WEB_DIR/"
        chmod -R a+rX "$WEB_DIR"
        step "Installed web assets to $WEB_DIR"
    fi

    # StateDirectory= in the unit also creates and chowns this, but doing it
    # here means an upgrade fixes ownership on a directory that predates the
    # unit (or was created by hand).
    install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "$DATA_DIR"
    step "Data directory $DATA_DIR ready"
}

detect_advertised_targets() {
    if [ -n "${COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS:-}" ]; then
        ADVERTISED_TARGETS=$COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS
        return 0
    fi
    _targets=$(hostname 2>/dev/null || printf 'cogwheel')
    if command -v ip >/dev/null 2>&1; then
        _addrs=$(ip -o addr show scope global 2>/dev/null |
            awk '$2 !~ /^(docker|br-|veth|virbr|cni|flannel)/ {print $4}' | cut -d/ -f1)
        for _a in $_addrs; do
            _targets="$_targets,$_a"
        done
    fi
    ADVERTISED_TARGETS=$_targets
}

# On an upgrade, cogwheel.env -- not this script's defaults -- is what the
# service actually runs with. write_env_file deliberately preserves that file,
# and the header tells operators it is safe to edit, so every later step has to
# agree with its contents rather than with the defaults at the top of this file.
#
# Without this, re-running the installer on a box configured for non-default
# ports went wrong three ways, all silently:
#
#   - fix_port_53 saw DNS_PORT=53 and rewrote the host's resolver config to
#     clear a :53 conflict that does not exist on a machine serving :5353.
#   - the health probe polled :8080 while the service listened elsewhere, so a
#     service that had started perfectly was declared failed.
#   - the closing summary printed ports nothing was listening on.
#
# An explicit --dns-port/--http-port still wins; that is how you change a port.
adopt_ports_from_env_file() {
    [ -r "$ENV_FILE" ] || return 0
    [ "$FORCE_ENV" = no ] || return 0

    _env_http=$(sed -n 's/^COGWHEEL_SERVER__HTTP_BIND_ADDR=.*:\([0-9][0-9]*\)$/\1/p' "$ENV_FILE" | tail -n 1)
    _env_dns=$(sed -n 's/^COGWHEEL_SERVER__DNS_UDP_BIND_ADDR=.*:\([0-9][0-9]*\)$/\1/p' "$ENV_FILE" | tail -n 1)

    if [ "$HTTP_PORT_EXPLICIT" = no ] && [ -n "$_env_http" ] && [ "$_env_http" != "$HTTP_PORT" ]; then
        step "Using HTTP port $_env_http from $ENV_FILE (not the default $HTTP_PORT)"
        HTTP_PORT=$_env_http
    fi
    if [ "$DNS_PORT_EXPLICIT" = no ] && [ -n "$_env_dns" ] && [ "$_env_dns" != "$DNS_PORT" ]; then
        step "Using DNS port $_env_dns from $ENV_FILE (not the default $DNS_PORT)"
        DNS_PORT=$_env_dns
    fi
}

write_env_file() {
    mkdir -p "$CONFIG_DIR"

    if [ -f "$ENV_FILE" ] && [ "$FORCE_ENV" = no ]; then
        step "Keeping existing $ENV_FILE (use --force-env to regenerate)"
        return 0
    fi

    detect_advertised_targets

    cat > "$ENV_FILE" <<EOF
# Cogwheel DNS configuration, read by systemd via EnvironmentFile=.
# Generated by install-native.sh $INSTALLER_VERSION.
# Safe to edit: an upgrade preserves this file unless --force-env is passed.
# Apply changes with: systemctl restart cogwheel
COGWHEEL_PROFILE=$PROFILE
COGWHEEL_SERVER__HTTP_BIND_ADDR=0.0.0.0:$HTTP_PORT
COGWHEEL_SERVER__DNS_UDP_BIND_ADDR=0.0.0.0:$DNS_PORT
COGWHEEL_SERVER__DNS_TCP_BIND_ADDR=0.0.0.0:$DNS_PORT
COGWHEEL_SERVER__ADVERTISED_DNS_PORT=$DNS_PORT
COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS=$ADVERTISED_TARGETS
COGWHEEL_STORAGE__DATABASE_URL=sqlite://$DATA_DIR/cogwheel.db
COGWHEEL_UPSTREAM__SERVERS=$UPSTREAM_SERVERS
COGWHEEL_WEB_DIST_DIR=$WEB_DIR
EOF
    chmod 0644 "$ENV_FILE"
    step "Wrote $ENV_FILE"
}

install_unit() {
    _src="$REPO_ROOT/deploy/cogwheel.service"
    [ -f "$_src" ] || die "unit file not found at $_src"
    install -Dm0644 "$_src" "$UNIT_PATH"
    systemctl daemon-reload
    step "Installed $UNIT_PATH"
}

fix_port_53() {
    if [ "$DNS_PORT" != 53 ]; then
        step "DNS port is $DNS_PORT, not 53 -- no privileged-port conflict to resolve"
        return 0
    fi
    # Single source of truth for the port-53 logic; install.sh owns it.
    if [ -x "$REPO_ROOT/scripts/install.sh" ]; then
        sh "$REPO_ROOT/scripts/install.sh" --fix-port-53 --dns-port "$DNS_PORT"
    else
        warn "scripts/install.sh not found; skipping the port-53 conflict check.
         If the service fails to start, see DEPLOYMENT.md 'Port 53 is already in use'."
    fi
}

start_service() {
    systemctl enable cogwheel.service >/dev/null 2>&1 || true
    systemctl restart cogwheel.service
    step "Started cogwheel.service"

    _waited=0
    while [ "$_waited" -lt 60 ]; do
        if ! systemctl is-active --quiet cogwheel.service; then
            err "cogwheel.service stopped unexpectedly"
            return 1
        fi
        if probe_http; then
            log "HTTP endpoint is answering after ${_waited}s"
            return 0
        fi
        _waited=$((_waited + 3))
        sleep 3
    done
    err "cogwheel.service is running but /health/live did not answer within 60s"
    return 1
}

probe_http() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsS -o /dev/null --max-time 4 "http://127.0.0.1:$HTTP_PORT/health/live" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O /dev/null -T 4 "http://127.0.0.1:$HTTP_PORT/health/live" 2>/dev/null
    else
        # Cannot probe; do not claim success we did not observe.
        return 1
    fi
}

show_failure() {
    err "Install did not come up cleanly. Recent log:"
    journalctl -u cogwheel.service -n 40 --no-pager 2>&1 | sed 's/^/    /' >&2 || true
    printf '\n' >&2
    err "The service is left installed but stopped so you can inspect it:"
    err "    systemctl status cogwheel"
    err "    journalctl -u cogwheel -f"
    err "Roll back with:  sudo $0 --uninstall"
    systemctl stop cogwheel.service >/dev/null 2>&1 || true
    exit 1
}

cleanup_unpack() {
    [ -n "${UNPACK_DIR:-}" ] && [ -d "${UNPACK_DIR:-}" ] && rm -rf "$UNPACK_DIR"
    return 0
}

do_install() {
    require_root
    require_systemd

    trap cleanup_unpack EXIT INT TERM

    if [ -n "$TARBALL" ]; then
        unpack_tarball
    elif [ "$SKIP_BUILD" = yes ]; then
        use_prebuilt
    else
        build_from_source
    fi

    ensure_service_user
    # Before fix_port_53, which branches on DNS_PORT, and before the health
    # probe and summary further down, which both read HTTP_PORT.
    adopt_ports_from_env_file
    fix_port_53
    install_files
    write_env_file
    install_unit

    if ! start_service; then
        show_failure
    fi

    detect_advertised_targets
    # An address, not a name: ADVERTISED_TARGETS leads with the hostname, and a
    # router's DNS field will not take one. Same reasoning as install.sh.
    _primary=$(printf '%s' "$ADVERTISED_TARGETS" | tr ',' '\n' |
        grep -m1 -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9A-Fa-f]*:[0-9A-Fa-f:]*$' || true)
    [ -n "$_primary" ] || _primary=$(printf '%s' "$ADVERTISED_TARGETS" | cut -d, -f1)

    printf '\n'
    printf '%s  Cogwheel is running (native install).%s\n\n' "$C_BOLD$C_GREEN" "$C_RESET"
    printf '  %sWeb UI%s        http://%s:%s\n' "$C_BOLD" "$C_RESET" "$_primary" "$HTTP_PORT"
    printf '  %sDNS server%s    %s port %s\n' "$C_BOLD" "$C_RESET" "$_primary" "$DNS_PORT"
    printf '\n'
    printf '  Status:      systemctl status cogwheel\n'
    printf '  Logs:        journalctl -u cogwheel -f\n'
    printf '  Config:      %s  (systemctl restart cogwheel to apply)\n' "$ENV_FILE"
    printf '  Verify:      sh scripts/verify-install.sh --http-port %s --dns-port %s\n' "$HTTP_PORT" "$DNS_PORT"
    printf '  Upgrade:     git pull && sudo %s\n' "$0"
    printf '  Uninstall:   sudo %s --uninstall\n' "$0"
    printf '\n'
}

do_uninstall() {
    require_root

    if [ -f "$UNIT_PATH" ]; then
        systemctl disable --now cogwheel.service >/dev/null 2>&1 || true
        rm -f "$UNIT_PATH"
        systemctl daemon-reload
        systemctl reset-failed cogwheel.service >/dev/null 2>&1 || true
        step "Removed $UNIT_PATH"
    else
        step "No unit at $UNIT_PATH"
    fi

    rm -f "$BIN_PATH"
    rm -rf "$WEB_DIR"
    rm -f "$ENV_FILE"
    rmdir "$CONFIG_DIR" 2>/dev/null || true
    rmdir /usr/local/share/cogwheel 2>/dev/null || true
    step "Removed binary, web assets and configuration"

    # The resolver stub was disabled by install.sh --fix-port-53, which
    # recorded it in /etc/cogwheel/install-state. Reverse it the same way.
    if [ -x "$REPO_ROOT/scripts/install.sh" ] &&
       [ -e /etc/systemd/resolved.conf.d/10-cogwheel-stub-listener.conf ]; then
        warn "the systemd-resolved stub listener is still disabled by Cogwheel"
        printf '  Restore it with:  sudo %s/scripts/install.sh --uninstall\n' "$REPO_ROOT"
    fi

    if [ "$PURGE" = yes ]; then
        rm -rf "$DATA_DIR"
        step "Deleted $DATA_DIR"
        if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
            userdel "$SERVICE_USER" >/dev/null 2>&1 || true
            step "Removed user '$SERVICE_USER'"
        fi
        log "Cogwheel removed, including all data."
    else
        log "Cogwheel removed. Data kept at $DATA_DIR."
        printf '  Delete it with:  sudo rm -rf %s\n' "$DATA_DIR"
    fi
}

main() {
    parse_args "$@"
    case "$ACTION" in
        install)   do_install ;;
        uninstall) do_uninstall ;;
    esac
}

main "$@"
