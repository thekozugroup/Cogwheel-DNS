#!/bin/sh
#
# Cogwheel DNS — one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/thekozugroup/Cogwheel-DNS/main/scripts/install.sh | sudo sh
#
# or, from a checkout:
#
#   sudo ./scripts/install.sh
#
# What it does, in order:
#   1. Checks it is running on a supported Linux/arch with a working Docker.
#   2. Finds whatever already owns port 53 and deals with it. On the common
#      case -- systemd-resolved's stub listener on 127.0.0.53:53 -- it disables
#      the stub AND repairs /etc/resolv.conf so the host can still resolve.
#      For a real DNS server (dnsmasq, bind, unbound, ...) it stops and tells
#      you, because silently disabling someone's DNS server is not a decision
#      an installer gets to make.
#   3. Pulls the image, writes /etc/cogwheel/cogwheel.env, starts the container.
#   4. Waits for the container to report healthy and then proves the resolver
#      actually answers a query.
#   5. If any of that fails, rolls back: restores the previous container if
#      there was one, otherwise removes what it created and reverts the host
#      DNS changes.
#
# Everything it changes on the host is recorded in /etc/cogwheel/install-state
# so `--uninstall` can reverse exactly those changes and nothing else.
#
# POSIX sh. No bashisms: this runs under dash on Debian/Ubuntu and ash on
# Alpine-based rescue shells.

set -eu

COGWHEEL_INSTALLER_VERSION="1.0.0"

# --------------------------------------------------------------------------
# Defaults. Every one is overridable by flag or environment.
# --------------------------------------------------------------------------
IMAGE="${COGWHEEL_IMAGE:-ghcr.io/thekozugroup/cogwheel-dns:latest}"
CONTAINER_NAME="${COGWHEEL_CONTAINER_NAME:-cogwheel}"
VOLUME_NAME="${COGWHEEL_VOLUME_NAME:-cogwheel-data}"
DNS_PORT="${COGWHEEL_DNS_PORT:-53}"
HTTP_PORT="${COGWHEEL_HTTP_PORT:-8080}"
NETWORK_MODE="${COGWHEEL_NETWORK_MODE:-host}"
UPSTREAM_SERVERS="${COGWHEEL_UPSTREAM_SERVERS:-1.1.1.1:53,1.0.0.1:53}"
PROFILE="${COGWHEEL_PROFILE:-home}"
# How blocked names are answered.
BLOCK_MODE="${COGWHEEL_BLOCK_MODE:-null_ip}"
CPU_LIMIT="${COGWHEEL_CPU_LIMIT:-2.0}"
MEMORY_LIMIT="${COGWHEEL_MEMORY_LIMIT:-1024m}"
MEMORY_RESERVATION="${COGWHEEL_MEMORY_RESERVATION:-192m}"
HEALTH_TIMEOUT="${COGWHEEL_HEALTH_TIMEOUT:-180}"

CONFIG_DIR=/etc/cogwheel
ENV_FILE="$CONFIG_DIR/cogwheel.env"
STATE_FILE="$CONFIG_DIR/install-state"
RESOLVED_DROPIN=/etc/systemd/resolved.conf.d/10-cogwheel-stub-listener.conf
RESOLV_BACKUP="$CONFIG_DIR/resolv.conf.pre-cogwheel"

ACTION=install
PURGE=no
SKIP_START=no

# Populated as we go; consumed by rollback and by the state file.
STATE_RESOLVED_DROPIN=no
STATE_RESOLV_ACTION=none
STATE_RESOLV_PREV_TARGET=
PREVIOUS_IMAGE=
PREVIOUS_IMAGE_REF=
FRESH_INSTALL=yes

# How to tell the operator to run this script again.
#
# NOT "$0". The advertised install is `curl -fsSL ... | sudo sh`, and a script
# read from a pipe has no path: $0 is the shell's own name. Every instruction
# built from it came out as "sh --uninstall", which is not a command -- it is
# `sh` being handed an illegal option. Nothing named install.sh exists on the
# box either, because the installer never copies itself anywhere, so that left
# the one documented way to restore the host's DNS unreachable from the only
# place it was mentioned.
case "$0" in
    */*) SELF_CMD="sudo $0" ;;
    *)   SELF_CMD="curl -fsSL https://raw.githubusercontent.com/thekozugroup/Cogwheel-DNS/main/scripts/install.sh | sudo sh -s --" ;;
esac
# Set when the process holding the DNS port turns out to be Cogwheel itself,
# so the post-fix "is the port free now?" check does not treat an install that
# is about to be replaced as an unresolved conflict.
PORT_HELD_BY_COGWHEEL=no

# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$(printf '\033[0m')
    C_BOLD=$(printf '\033[1m')
    C_RED=$(printf '\033[31m')
    C_YELLOW=$(printf '\033[33m')
    C_GREEN=$(printf '\033[32m')
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
Cogwheel DNS installer

Usage:
  install.sh [options]
  install.sh --uninstall [--purge]
  install.sh --fix-port-53

Options:
  --image REF           Container image to run
                        (default: ghcr.io/thekozugroup/cogwheel-dns:latest)
  --container NAME      Container name (default: cogwheel)
  --volume NAME         Docker volume for /app/data (default: cogwheel-data)
  --dns-port PORT       Host port clients send DNS to (default: 53)
  --http-port PORT      Host port for the web UI (default: 8080)
  --network host|bridge Networking mode (default: host)
                        host   - real client IPs, per-device profiles work
                        bridge - isolated, but client IPs may be rewritten to
                                 the Docker gateway, which breaks per-device
                                 profiles. See DEPLOYMENT.md.
  --upstream LIST       Comma-separated upstream resolvers
                        (default: 1.1.1.1:53,1.0.0.1:53)
  --profile NAME        dev | home | smb (default: home)
  --block-mode MODE     How blocked names are answered (default: null_ip)
                        null_ip  - 0.0.0.0 / ::
                        nxdomain - as if the name did not exist
                        nodata   - NOERROR with no answers
                        refused  - REFUSED
  --no-start            Write configuration but do not start the container
  --fix-port-53         Only resolve the port-53 conflict, then exit
  --uninstall           Remove Cogwheel and revert host DNS changes
  --purge               With --uninstall, also delete the data volume
  --version             Print installer version
  -h, --help            This message

Environment equivalents: COGWHEEL_IMAGE, COGWHEEL_CONTAINER_NAME,
COGWHEEL_VOLUME_NAME, COGWHEEL_DNS_PORT, COGWHEEL_HTTP_PORT,
COGWHEEL_NETWORK_MODE, COGWHEEL_UPSTREAM_SERVERS, COGWHEEL_PROFILE.
USAGE
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --image)      IMAGE="${2:?--image needs a value}"; shift 2 ;;
            --container)  CONTAINER_NAME="${2:?--container needs a value}"; shift 2 ;;
            --volume)     VOLUME_NAME="${2:?--volume needs a value}"; shift 2 ;;
            --dns-port)   DNS_PORT="${2:?--dns-port needs a value}"; shift 2 ;;
            --http-port)  HTTP_PORT="${2:?--http-port needs a value}"; shift 2 ;;
            --network)    NETWORK_MODE="${2:?--network needs a value}"; shift 2 ;;
            --upstream)   UPSTREAM_SERVERS="${2:?--upstream needs a value}"; shift 2 ;;
            --profile)    PROFILE="${2:?--profile needs a value}"; shift 2 ;;
            --block-mode) BLOCK_MODE="${2:?--block-mode needs a value}"; shift 2 ;;
            --no-start)   SKIP_START=yes; shift ;;
            --fix-port-53) ACTION=fix-port-53; shift ;;
            --uninstall)  ACTION=uninstall; shift ;;
            --purge)      PURGE=yes; shift ;;
            --version)    printf 'cogwheel-installer %s\n' "$COGWHEEL_INSTALLER_VERSION"; exit 0 ;;
            -h|--help)    usage; exit 0 ;;
            *)            usage >&2; die "unknown option: $1" ;;
        esac
    done

    case "$NETWORK_MODE" in
        host|bridge) ;;
        *) die "--network must be 'host' or 'bridge', got '$NETWORK_MODE'" ;;
    esac
    case "$PROFILE" in
        dev|home|smb) ;;
        *) die "--profile must be dev, home or smb; got '$PROFILE'" ;;
    esac
    case "$BLOCK_MODE" in
        null_ip|nxdomain|nodata|refused) ;;
        *) die "--block-mode must be null_ip, nxdomain, nodata or refused; got '$BLOCK_MODE'" ;;
    esac
}

# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "must run as root (binding port 53 and editing resolver config both need it).
     Try: $SELF_CMD"
    fi
}

detect_platform() {
    PLATFORM_OS=$(uname -s)
    PLATFORM_ARCH=$(uname -m)

    if [ "$PLATFORM_OS" != "Linux" ]; then
        die "Cogwheel's appliance install is Linux-only (found $PLATFORM_OS).
     Docker Desktop cannot bind host port 53 the way a DNS appliance needs.
     For a Mac or Windows workstation, run the dev profile instead:
     see DEPLOYMENT.md section 'Local development'."
    fi

    case "$PLATFORM_ARCH" in
        x86_64|amd64)  DOCKER_ARCH=amd64 ;;
        aarch64|arm64) DOCKER_ARCH=arm64 ;;
        armv7l|armv6l)
            die "32-bit ARM ($PLATFORM_ARCH) is not a published target.
     Cogwheel publishes linux/amd64 and linux/arm64 only. On a Raspberry Pi,
     install the 64-bit Raspberry Pi OS and re-run this installer." ;;
        *) die "unsupported architecture: $PLATFORM_ARCH (need x86_64 or aarch64)" ;;
    esac

    OS_PRETTY=$PLATFORM_OS
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        OS_PRETTY=$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-${NAME:-Linux}}")
    fi
    step "Host: ${OS_PRETTY} (${PLATFORM_ARCH} -> linux/${DOCKER_ARCH})"
}

require_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        die "docker is not installed.
     Install it first:  curl -fsSL https://get.docker.com | sh
     Then re-run this installer."
    fi
    if ! docker info >/dev/null 2>&1; then
        die "docker is installed but the daemon is not reachable.
     Try:  sudo systemctl enable --now docker
     Then re-run this installer."
    fi
    step "Docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo present)"
}

# $CONFIG_DIR holds the env file, the install state -- and the backup of
# /etc/resolv.conf, which is taken during the port-53 fix, i.e. before either
# of the file writers runs. Every function that writes into the directory calls
# this first, so no writer depends on another having run earlier.
ensure_config_dir() {
    [ -d "$CONFIG_DIR" ] || mkdir -p "$CONFIG_DIR"
    chmod 0755 "$CONFIG_DIR"
}

# --------------------------------------------------------------------------
# Port 53
#
# This is the single most common reason a self-hosted DNS appliance fails to
# start on Linux. systemd-resolved runs a stub resolver on 127.0.0.53:53 on
# Ubuntu, Debian with systemd-resolved enabled, Fedora, and Raspberry Pi OS
# derivatives that have adopted it.
# --------------------------------------------------------------------------

# Which inspection tool this host has. Set once; both helpers below need to
# agree, because each tool formats the owning process differently and picking
# the name out of the wrong format is how "detect systemd-resolved" quietly
# turns into "give up and tell the user to fix it themselves".
PORT_TOOL=
detect_port_tool() {
    if command -v ss >/dev/null 2>&1; then
        PORT_TOOL=ss
    elif command -v netstat >/dev/null 2>&1; then
        PORT_TOOL=netstat
    elif command -v lsof >/dev/null 2>&1; then
        PORT_TOOL=lsof
    else
        PORT_TOOL=none
    fi
}

# One line per listener on the given port, or the literal "unknown" if this
# host has no way to look. Never claim a port is free just because we cannot see.
port_listeners() {
    case "$PORT_TOOL" in
        ss)
            ss -lnptu "( sport = :$1 )" 2>/dev/null | sed '1d' ;;
        netstat)
            netstat -lnptu 2>/dev/null | awk -v p=":$1\$" '$4 ~ p' ;;
        lsof)
            # +c 0 stops lsof truncating the command name to 9 characters,
            # which would turn "systemd-resolve" into "systemd-r".
            { lsof -nP +c 0 -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | sed '1d'
              lsof -nP +c 0 -iUDP:"$1" 2>/dev/null | sed '1d'; } ;;
        *)
            printf 'unknown\n' ;;
    esac
}

# Lowercased name of the most likely owning process, or empty.
#   ss      -> users:(("systemd-resolve",pid=1234,fd=12))
#   netstat -> last column is  1234/systemd-resolve
#   lsof    -> first column is the command name
port_owner() {
    case "$PORT_TOOL" in
        ss)      port_listeners "$1" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -n 1 ;;
        netstat) port_listeners "$1" | awk '{print $NF}' | sed -n 's#^[0-9]*/##p'  | head -n 1 ;;
        lsof)    port_listeners "$1" | awk 'NF {print $1}' | head -n 1 ;;
        *)       printf '' ;;
    esac | tr '[:upper:]' '[:lower:]'
}

systemd_resolved_active() {
    command -v systemctl >/dev/null 2>&1 &&
        systemctl is-active --quiet systemd-resolved 2>/dev/null
}

# Point /etc/resolv.conf somewhere that still works once the stub is gone.
#
# Deliberately NOT pointed at 127.0.0.1 (Cogwheel itself). If the host resolved
# through Cogwheel and Cogwheel failed to start, the box would have no DNS at
# all -- and no DNS means you cannot pull the image to fix it. Pointing at
# systemd-resolved's uplink file keeps the host resolving via the real upstream
# servers no matter what state the container is in.
repair_resolv_conf() {
    _uplink=/run/systemd/resolve/resolv.conf

    if [ -L /etc/resolv.conf ]; then
        _target=$(readlink /etc/resolv.conf)
    else
        _target=""
    fi

    case "$_target" in
        */stub-resolv.conf)
            if [ -e "$_uplink" ]; then
                STATE_RESOLV_PREV_TARGET=$_target
                ln -sf "$_uplink" /etc/resolv.conf
                STATE_RESOLV_ACTION=relinked
                step "Repointed /etc/resolv.conf: stub-resolv.conf -> $_uplink"
            else
                warn "$_uplink does not exist; writing a static /etc/resolv.conf instead"
                write_static_resolv_conf
            fi
            ;;
        */resolv.conf)
            step "/etc/resolv.conf already points at the uplink resolver; leaving it alone"
            ;;
        "")
            # A regular file. If it names the stub address it will break.
            if [ -f /etc/resolv.conf ] && grep -q '^[[:space:]]*nameserver[[:space:]]\+127\.0\.0\.53' /etc/resolv.conf 2>/dev/null; then
                write_static_resolv_conf
            else
                step "/etc/resolv.conf is a static file that does not use the stub; leaving it alone"
            fi
            ;;
        *)
            step "/etc/resolv.conf -> $_target (not the systemd stub); leaving it alone"
            ;;
    esac
}

# True if the backup is there at all. A backup of a symlinked /etc/resolv.conf
# is itself a symlink, and may legitimately dangle, so `-e` alone would report
# a perfectly good backup as missing and throw the original away.
resolv_backup_exists() {
    [ -e "$RESOLV_BACKUP" ] || [ -L "$RESOLV_BACKUP" ]
}

# The upstream list is "ip:port"; resolv.conf takes bare addresses. Emitting
# nothing here would produce a resolv.conf with no nameserver in it, which is
# indistinguishable from having no DNS at all -- so an unusable list falls back
# to public resolvers rather than to silence.
resolv_nameserver_lines() {
    _lines=
    _oldifs=$IFS
    IFS=','
    # Nothing in this loop is IFS-sensitive; IFS is restored immediately after.
    for _srv in $UPSTREAM_SERVERS; do
        [ -n "$_srv" ] || continue
        _ip=$_srv
        # An upstream may be written as tls://ip#certname or
        # https://ip#certname/path. resolv.conf takes a bare address, and
        # feeding it the whole URL produced the line "nameserver tls" -- a
        # resolv.conf with no usable server in it, i.e. a host with no DNS,
        # which is the single worst state this installer can leave behind.
        # Reduce to the address before the port logic below runs.
        #
        # The host resolving in cleartext to the same provider is deliberate:
        # /etc/resolv.conf is how THIS machine resolves when Cogwheel is not
        # running, so it must not depend on Cogwheel, and it cannot speak DoT
        # without a stub resolver that is not being installed here.
        _ip=${_ip#*://}
        _ip=${_ip%%#*}
        _ip=${_ip%%/*}
        case "$_ip" in
            *']:'*) _ip=${_ip%]:*} ;;   # [2606:4700::1111]:53
            *']'*)  _ip=${_ip%]}   ;;   # [2606:4700::1111]
            *:*:*)  :              ;;   # bare IPv6, no port to strip
            *:*)    _ip=${_ip%:*}  ;;   # 1.1.1.1:53
        esac
        _ip=${_ip#"["}
        [ -n "$_ip" ] || continue
        # Only literal addresses reach resolv.conf. A hostname or a typo here
        # becomes a nameserver line the resolver cannot use, and enough of
        # those means the host silently has no DNS. Anything unusable is
        # dropped, and if that leaves nothing the caller falls back to public
        # resolvers rather than writing an empty file.
        case "$_ip" in
            *[!0-9.]*[!0-9A-Fa-f:]*|"") warn "ignoring unusable upstream address '$_srv' when writing resolv.conf"; continue ;;
            *:*) : ;;                                   # IPv6 literal
            *.*.*.*) : ;;                               # IPv4 literal
            *) warn "ignoring unusable upstream address '$_srv' when writing resolv.conf"; continue ;;
        esac
        _lines="${_lines}nameserver ${_ip}
"
    done
    IFS=$_oldifs

    if [ -z "$_lines" ]; then
        warn "no usable address in upstream list '$UPSTREAM_SERVERS'; falling back to public resolvers so this host keeps working DNS"
        _lines='nameserver 1.1.1.1
nameserver 9.9.9.9
'
    fi
    printf '%s' "$_lines"
}

write_static_resolv_conf() {
    # The backup lives in CONFIG_DIR, and this is reached from
    # resolve_port_conflict -- which runs BEFORE write_env_file and
    # write_state_file, the only two functions that used to create that
    # directory. Without this the cp below failed with ENOENT, no backup was
    # ever written, and --uninstall had nothing to restore /etc/resolv.conf
    # from. Create it here rather than relying on a caller that runs later.
    ensure_config_dir

    if ! resolv_backup_exists; then
        # -L as well as -e: on a host where systemd-resolved has never run,
        # /etc/resolv.conf is a symlink to a stub file that does not exist yet.
        # `-e` is false for a dangling symlink, and that symlink is exactly the
        # state uninstall has to put back. `cp -a` copies the link itself.
        if [ ! -e /etc/resolv.conf ] && [ ! -L /etc/resolv.conf ]; then
            warn "/etc/resolv.conf does not exist; there is nothing to back up"
        elif cp -a /etc/resolv.conf "$RESOLV_BACKUP"; then
            step "Backed up /etc/resolv.conf to $RESOLV_BACKUP"
        else
            die "could not back up /etc/resolv.conf to $RESOLV_BACKUP.
     Refusing to replace this host's resolver configuration without a backup --
     --uninstall would have nothing to restore and the host could be left with
     no DNS. Fix the write error above, then re-run."
        fi
    fi

    {
        printf '# Written by the Cogwheel installer.\n'
        printf '# systemd-resolved stub listener disabled so Cogwheel can bind :53.\n'
        printf '# The host resolves via upstream directly, so host DNS survives a\n'
        printf '# Cogwheel outage. Restored by: install.sh --uninstall\n'
        resolv_nameserver_lines
    } > /etc/resolv.conf.cogwheel-new
    mv /etc/resolv.conf.cogwheel-new /etc/resolv.conf
    STATE_RESOLV_ACTION=replaced
    step "Wrote a static /etc/resolv.conf (backup at $RESOLV_BACKUP)"
}

# Last resort for the uninstall/rollback path: leave this host with a
# resolv.conf that actually resolves. "Uninstalled Cogwheel, lost DNS" is the
# worst outcome this script can produce, so a missing backup must never mean
# "do nothing and hope".
write_fallback_resolv_conf() {
    {
        printf '# Written by the Cogwheel installer while removing itself,\n'
        printf '# because no pre-Cogwheel backup of /etc/resolv.conf was found.\n'
        printf '# These are the upstream resolvers Cogwheel was configured with.\n'
        printf '# On a systemd-resolved host you can hand resolution back with:\n'
        printf '#   sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf\n'
        printf '#   sudo systemctl restart systemd-resolved\n'
        resolv_nameserver_lines
    } > /etc/resolv.conf.cogwheel-new
    mv /etc/resolv.conf.cogwheel-new /etc/resolv.conf
    step "Wrote a working /etc/resolv.conf so this host still has DNS"
}

disable_resolved_stub() {
    mkdir -p /etc/systemd/resolved.conf.d
    # Idempotent: same content every time, so re-running changes nothing.
    cat > "$RESOLVED_DROPIN" <<'EOF'
# Installed by the Cogwheel DNS installer.
#
# systemd-resolved's stub listener binds 127.0.0.53:53, which prevents any
# other resolver from binding port 53 on this host. Cogwheel needs :53.
#
# Removing this file and restarting systemd-resolved restores the stub.
# `install.sh --uninstall` does exactly that.
[Resolve]
DNSStubListener=no
EOF
    STATE_RESOLVED_DROPIN=yes
    step "Wrote $RESOLVED_DROPIN (DNSStubListener=no)"

    repair_resolv_conf

    if systemctl restart systemd-resolved 2>/dev/null; then
        step "Restarted systemd-resolved"
    else
        warn "could not restart systemd-resolved; you may need to restart it manually"
    fi

    # Give the socket a moment to actually close.
    _tries=0
    while [ "$_tries" -lt 10 ]; do
        if [ -z "$(port_listeners "$DNS_PORT")" ]; then
            return 0
        fi
        _tries=$((_tries + 1))
        sleep 1
    done
    return 0
}

resolve_port_conflict() {
    detect_port_tool
    step "Checking what owns port $DNS_PORT (via ${PORT_TOOL})"

    _listeners=$(port_listeners "$DNS_PORT" || true)

    if [ "$_listeners" = "unknown" ]; then
        warn "no ss/netstat/lsof available; cannot check port $DNS_PORT.
         If the container fails to start, something else is already bound."
        return 0
    fi

    if [ -z "$_listeners" ]; then
        log "Port $DNS_PORT is free"
        return 0
    fi

    _owner=$(port_owner "$DNS_PORT" || true)

    case "$_owner" in
        systemd-resolve*|resolved)
            log "systemd-resolved's stub listener holds port $DNS_PORT -- disabling it"
            disable_resolved_stub
            ;;
        dnsmasq)
            die "dnsmasq is already serving DNS on port $DNS_PORT.
     Cogwheel replaces it, but stopping it is your call because it may also be
     serving DHCP on this network. When you are ready:
         sudo systemctl disable --now dnsmasq
     then re-run this installer.
     (On OpenWrt/LEDE, reconfigure dnsmasq to port 0 instead of disabling it.)" ;;
        named|bind9)
            die "BIND (named) is already serving DNS on port $DNS_PORT.
     Stop it before installing Cogwheel:
         sudo systemctl disable --now named   # or bind9
     then re-run this installer." ;;
        unbound)
            die "unbound is already serving DNS on port $DNS_PORT.
     Stop it before installing Cogwheel:
         sudo systemctl disable --now unbound
     then re-run this installer." ;;
        pdns_recursor|pdns_server|coredns|knot-resolver|kresd|stubby)
            die "'$_owner' is already serving DNS on port $DNS_PORT.
     Stop or reconfigure it, then re-run this installer." ;;
        cogwheel|cogwheel-*)
            # Cogwheel already holds the port. Two ways that happens, and
            # neither is an error -- re-running this installer is the
            # documented upgrade path:
            #
            #   - the container is running with --network host, so the socket
            #     belongs to the containerised process and `ss` names it
            #     "cogwheel-server" rather than any Docker plumbing;
            #   - a native (systemd) install is running on this host.
            #
            # Without this arm both fall through to the catch-all below, which
            # refuses to touch "a DNS service it did not install" -- i.e. the
            # installer aborts because it detected itself.
            if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
                PORT_HELD_BY_COGWHEEL=yes
                log "Port $DNS_PORT is held by the existing '$CONTAINER_NAME' container -- it will be replaced"
            elif command -v systemctl >/dev/null 2>&1 &&
                 systemctl is-active --quiet cogwheel.service 2>/dev/null; then
                # install-native.sh runs `install.sh --fix-port-53` on every
                # upgrade, while its own service is still bound to :53. That is
                # the same install being upgraded, not a conflict -- the caller
                # restarts the unit immediately afterwards.
                if [ "$ACTION" = fix-port-53 ]; then
                    PORT_HELD_BY_COGWHEEL=yes
                    log "Port $DNS_PORT is held by the native Cogwheel service -- the caller will restart it"
                else
                    die "a native Cogwheel install (systemd unit 'cogwheel') is serving DNS on port $DNS_PORT.
     Upgrade that install with scripts/install-native.sh, or remove it first:
         sudo systemctl disable --now cogwheel
     then re-run this installer."
                fi
            else
                err "Port $DNS_PORT is held by a cogwheel-server process this installer does not manage:"
                printf '%s\n' "$_listeners" >&2
                die "Stop it, then re-run this installer."
            fi
            ;;
        docker-proxy|dockerd|containerd|"")
            # `ss` could not name the process (or named the Docker plumbing).
            # The stub listener is still identifiable by its address, so check
            # that before giving up.
            if printf '%s\n' "$_listeners" | grep -q '127\.0\.0\.53'; then
                log "systemd-resolved's stub listener (127.0.0.53:$DNS_PORT) holds the port -- disabling it"
                disable_resolved_stub
            elif systemd_resolved_active && [ -z "$_owner" ]; then
                log "systemd-resolved is active and port $DNS_PORT is busy -- disabling its stub listener"
                disable_resolved_stub
            elif docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
                log "Port $DNS_PORT is held by the existing '$CONTAINER_NAME' container -- it will be replaced"
            else
                err "Port $DNS_PORT is held by another container or by an unidentified process:"
                printf '%s\n' "$_listeners" >&2
                die "Stop it, then re-run this installer."
            fi
            ;;
        *)
            err "Port $DNS_PORT is held by '$_owner':"
            printf '%s\n' "$_listeners" >&2
            die "Cogwheel will not stop a DNS service it did not install.
     Stop or reconfigure it, then re-run this installer." ;;
    esac

    # systemd-resolved sometimes needs a second to release the socket, and a
    # stale listener here is worth catching now rather than as a cryptic
    # container crash loop. A listener that IS Cogwheel is expected: it is
    # replaced (container) or restarted by the caller (native upgrade).
    _still=$(port_listeners "$DNS_PORT" || true)
    if [ -n "$_still" ] && [ "$_still" != "unknown" ] &&
       [ "$PORT_HELD_BY_COGWHEEL" != yes ] &&
       ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
        err "Port $DNS_PORT is still in use after the conflict fix:"
        printf '%s\n' "$_still" >&2
        die "Resolve it manually and re-run."
    fi
}

# --------------------------------------------------------------------------
# Advertised DNS targets
#
# What the Overview page tells a user to type into their router. Derived from
# the host's own global addresses -- never hardcoded.
# --------------------------------------------------------------------------
detect_advertised_targets() {
    if [ -n "${COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS:-}" ]; then
        ADVERTISED_TARGETS=$COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS
        return 0
    fi

    _targets=$(hostname 2>/dev/null || printf 'cogwheel')

    if command -v ip >/dev/null 2>&1; then
        # Global-scope addresses only, and skip container/bridge interfaces --
        # advertising 172.17.0.1 to a household router helps nobody.
        _addrs=$(ip -o addr show scope global 2>/dev/null |
            awk '$2 !~ /^(docker|br-|veth|virbr|cni|flannel)/ {print $4}' |
            cut -d/ -f1)
        for _a in $_addrs; do
            _targets="$_targets,$_a"
        done
    fi

    ADVERTISED_TARGETS=$_targets
}

# --------------------------------------------------------------------------
# Install
# --------------------------------------------------------------------------
write_env_file() {
    ensure_config_dir

    if [ "$NETWORK_MODE" = host ]; then
        _dns_bind="0.0.0.0:$DNS_PORT"
        _http_bind="0.0.0.0:$HTTP_PORT"
    else
        # Bridge mode: bind unprivileged ports inside the container and let
        # Docker publish them on the privileged host ports.
        _dns_bind="0.0.0.0:5353"
        _http_bind="0.0.0.0:8080"
    fi

    # Written fresh each run: the installer owns this file. Operator edits
    # belong in a docker-compose deployment, not here.
    cat > "$ENV_FILE" <<EOF
# Generated by the Cogwheel installer $COGWHEEL_INSTALLER_VERSION -- do not edit.
# Re-running scripts/install.sh overwrites this file.
COGWHEEL_PROFILE=$PROFILE
COGWHEEL_SERVER__HTTP_BIND_ADDR=$_http_bind
COGWHEEL_SERVER__DNS_UDP_BIND_ADDR=$_dns_bind
COGWHEEL_SERVER__DNS_TCP_BIND_ADDR=$_dns_bind
COGWHEEL_SERVER__ADVERTISED_DNS_PORT=$DNS_PORT
COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS=$ADVERTISED_TARGETS
COGWHEEL_STORAGE__DATABASE_URL=sqlite:///app/data/cogwheel.db
COGWHEEL_UPSTREAM__SERVERS=$UPSTREAM_SERVERS
COGWHEEL_BLOCKING__MODE=$BLOCK_MODE
EOF
    chmod 0644 "$ENV_FILE"
    step "Wrote $ENV_FILE"
}

# Every key is STATE_-prefixed on purpose. This file gets sourced by
# --uninstall, so an unprefixed key like RESOLVED_DROPIN= would silently
# overwrite the same-named path constant above and make uninstall try to
# `rm -f yes`. The prefix keeps the state namespace disjoint from the config
# namespace, and means sourcing can never clobber a value the operator passed
# on the command line.
# Carry forward host changes recorded by an EARLIER run.
#
# The state variables reset to "no"/"none" at the top of every invocation, and
# only resolve_port_conflict sets them. On an upgrade the port conflict was
# already dealt with by run 1, so run 2 legitimately changes nothing -- and then
# wrote those defaults straight over the file, erasing the only record that the
# stub listener had ever been disabled and /etc/resolv.conf rewritten.
#
# The damage surfaced much later, at `--uninstall`: load_state_file SUCCEEDS
# (the file exists, it just says "none"), so the disk-evidence fallback is
# skipped and revert_host_dns does nothing. The host keeps DNSStubListener=no
# and Cogwheel's resolv.conf forever, with the operator's real one orphaned in
# /etc/cogwheel -- while README.md promises uninstall "puts your host DNS back
# exactly".
#
# So this file is a cumulative record, not a snapshot of the current run: a
# recorded change may be upgraded from absent to present, never the reverse.
preserve_prior_host_dns_state() {
    [ -r "$STATE_FILE" ] || return 0

    _prior_dropin=$(sed -n 's/^STATE_RESOLVED_DROPIN=//p' "$STATE_FILE" | tail -n 1)
    _prior_action=$(sed -n 's/^STATE_RESOLV_ACTION=//p' "$STATE_FILE" | tail -n 1)
    _prior_target=$(sed -n 's/^STATE_RESOLV_PREV_TARGET=//p' "$STATE_FILE" | tail -n 1)

    if [ "$STATE_RESOLVED_DROPIN" != yes ] && [ "$_prior_dropin" = yes ]; then
        STATE_RESOLVED_DROPIN=yes
    fi

    if [ "$STATE_RESOLV_ACTION" = none ] && [ -n "$_prior_action" ] &&
       [ "$_prior_action" != none ]; then
        STATE_RESOLV_ACTION=$_prior_action
        STATE_RESOLV_PREV_TARGET=$_prior_target
    fi
}

write_state_file() {
    ensure_config_dir
    preserve_prior_host_dns_state
    cat > "$STATE_FILE" <<EOF
# Written by the Cogwheel installer. Consumed by --uninstall.
# Records only the host changes this installer made, so uninstall reverses
# exactly those and nothing else.
STATE_INSTALLER_VERSION=$COGWHEEL_INSTALLER_VERSION
STATE_CONTAINER_NAME=$CONTAINER_NAME
STATE_VOLUME_NAME=$VOLUME_NAME
STATE_IMAGE=$IMAGE
STATE_NETWORK_MODE=$NETWORK_MODE
STATE_DNS_PORT=$DNS_PORT
STATE_HTTP_PORT=$HTTP_PORT
STATE_RESOLVED_DROPIN=$STATE_RESOLVED_DROPIN
STATE_RESOLV_ACTION=$STATE_RESOLV_ACTION
STATE_RESOLV_PREV_TARGET=$STATE_RESOLV_PREV_TARGET
EOF
    chmod 0644 "$STATE_FILE"
}

load_state_file() {
    [ -r "$STATE_FILE" ] || return 1
    # Only ever written by this script; every value is a bare token.
    # shellcheck disable=SC1090
    . "$STATE_FILE"
    return 0
}

ensure_volume() {
    if docker volume inspect "$VOLUME_NAME" >/dev/null 2>&1; then
        step "Reusing existing data volume '$VOLUME_NAME'"
    else
        docker volume create "$VOLUME_NAME" >/dev/null
        step "Created data volume '$VOLUME_NAME'"
    fi
    # The image creates /app/data owned by uid 10001, and Docker copies that
    # ownership onto a fresh named volume, so there is nothing to chown here.
    # A volume carried over from an older, root-owned install is repaired:
    docker run --rm -v "$VOLUME_NAME:/data" --user 0 --entrypoint /bin/sh \
        "$IMAGE" -c 'chown -R 10001:10001 /data && chmod 0750 /data' >/dev/null 2>&1 ||
        warn "could not normalise ownership on '$VOLUME_NAME'; if the server reports a database permission error, run:
         docker run --rm -v $VOLUME_NAME:/data --user 0 --entrypoint /bin/sh $IMAGE -c 'chown -R 10001:10001 /data'"
}

# Record what is running now, so a failed upgrade can be undone.
#
# `{{.Image}}`, NOT `{{.Config.Image}}`. Config.Image is the reference string the
# container was created from -- for the default install that is the literal
# "ghcr.io/thekozugroup/cogwheel-dns:latest". By the time this runs, `docker
# pull` has ALREADY repointed that tag at the new image, so rolling back to it
# re-runs the exact image that just failed: a second 180s health timeout, then
# "rollback also failed", on a box whose household has no DNS. `{{.Image}}` is
# the resolved sha256 of the image actually in use, which no pull can move.
#
# The tag is still worth capturing, but only to say something legible to the
# operator -- a bare digest in a status line helps nobody.
remember_previous() {
    if docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
        FRESH_INSTALL=no
        PREVIOUS_IMAGE=$(docker container inspect --format '{{.Image}}' "$CONTAINER_NAME" 2>/dev/null || printf '')
        PREVIOUS_IMAGE_REF=$(docker container inspect --format '{{.Config.Image}}' "$CONTAINER_NAME" 2>/dev/null || printf '')
        step "Existing install found (image: ${PREVIOUS_IMAGE_REF:-unknown}) -- upgrading in place"
    fi
}

start_container() {
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

    # Split into a positional set so the two network modes share one run call.
    set -- \
        --name "$CONTAINER_NAME" \
        --detach \
        --restart unless-stopped \
        --env-file "$ENV_FILE" \
        --volume "$VOLUME_NAME:/app/data" \
        --cap-drop ALL \
        --cap-add NET_BIND_SERVICE \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,size=64m \
        --init \
        --stop-timeout 20 \
        --ulimit nofile=65535:65535 \
        --cpus "$CPU_LIMIT" \
        --memory "$MEMORY_LIMIT" \
        --memory-reservation "$MEMORY_RESERVATION" \
        --log-driver json-file \
        --log-opt max-size=10m \
        --log-opt max-file=3 \
        --label io.cogwheel.installed-by="install.sh/$COGWHEEL_INSTALLER_VERSION"

    if [ "$NETWORK_MODE" = host ]; then
        set -- "$@" --network host
    else
        set -- "$@" \
            --publish "$DNS_PORT:5353/udp" \
            --publish "$DNS_PORT:5353/tcp" \
            --publish "$HTTP_PORT:8080/tcp"
    fi

    # `docker run` can be refused by the daemon rather than by Cogwheel -- an
    # unavailable ulimit, a cgroup the host does not support, a name clash, a
    # seccomp/apparmor denial. Under `set -e` an unchecked failure here killed
    # the installer outright: no explanation, and no rollback, even though the
    # port-53 fix had ALREADY edited this host's resolver configuration. That
    # left a box with a rewritten /etc/resolv.conf, no Cogwheel, and a bare
    # exit code. Return instead, so do_install can roll the host back.
    #
    # `2>&1 >/dev/null` in that order: stderr to the capture, stdout to the
    # bin. The reverse would capture the container id and discard the error.
    if ! _run_err=$(docker run "$@" "$IMAGE" 2>&1 >/dev/null); then
        err "the Docker daemon refused to start the container:"
        printf '%s\n' "$_run_err" | sed 's/^/       /' >&2
        return 1
    fi
    step "Started container '$CONTAINER_NAME'"
}

wait_for_health() {
    step "Waiting for '$CONTAINER_NAME' to report healthy (up to ${HEALTH_TIMEOUT}s)"
    _waited=0
    while [ "$_waited" -lt "$HEALTH_TIMEOUT" ]; do
        _status=$(docker container inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
            "$CONTAINER_NAME" 2>/dev/null || printf 'gone')
        _running=$(docker container inspect --format '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || printf 'false')

        case "$_status" in
            healthy)
                log "Container is healthy (after ${_waited}s)"
                return 0 ;;
            unhealthy)
                err "Container reported unhealthy"
                return 1 ;;
            gone)
                err "Container disappeared"
                return 1 ;;
            none)
                # Image has no HEALTHCHECK; fall back to probing HTTP directly.
                if probe_http; then
                    log "HTTP endpoint is answering (image has no healthcheck)"
                    return 0
                fi ;;
        esac

        if [ "$_running" != "true" ]; then
            err "Container exited before becoming healthy"
            return 1
        fi

        _waited=$((_waited + 3))
        sleep 3
    done

    err "Timed out after ${HEALTH_TIMEOUT}s waiting for a healthy container"
    return 1
}

probe_http() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsS -o /dev/null --max-time 4 "http://127.0.0.1:$HTTP_PORT/health/live" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O /dev/null -T 4 "http://127.0.0.1:$HTTP_PORT/health/live" 2>/dev/null
    else
        return 1
    fi
}

# A healthy container only proves the HTTP side is up. This proves the thing
# the product actually exists to do.
probe_dns() {
    step "Probing the resolver with a real query"
    if command -v dig >/dev/null 2>&1; then
        if dig +short +timeout=3 +tries=2 -p "$DNS_PORT" @127.0.0.1 example.com A >/dev/null 2>&1; then
            log "DNS resolution works (dig @127.0.0.1 -p $DNS_PORT example.com)"
            return 0
        fi
        err "dig @127.0.0.1 -p $DNS_PORT example.com returned no answer"
        return 1
    elif command -v nslookup >/dev/null 2>&1; then
        if nslookup -port="$DNS_PORT" example.com 127.0.0.1 >/dev/null 2>&1; then
            log "DNS resolution works (nslookup via 127.0.0.1:$DNS_PORT)"
            return 0
        fi
        err "nslookup against 127.0.0.1:$DNS_PORT failed"
        return 1
    else
        warn "no dig or nslookup on this host; skipping the DNS probe.
         Install one (apt-get install -y dnsutils) and verify manually:
             dig @127.0.0.1 -p $DNS_PORT example.com"
        return 0
    fi
}

rollback() {
    err "Install failed -- rolling back"

    # Only when there is a container to read. If the daemon refused to create
    # one, `docker logs` prints "No such container" -- and printing that under a
    # "last 40 log lines" heading reads as though Cogwheel started and then
    # vanished, sending the operator looking in the wrong place entirely.
    if docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
        printf '\n%s---- last 40 log lines from %s ----%s\n' "$C_BOLD" "$CONTAINER_NAME" "$C_RESET" >&2
        docker logs --tail 40 "$CONTAINER_NAME" 2>&1 | sed 's/^/    /' >&2 || true
        printf '\n' >&2
    else
        printf '\n%sThe container was never created, so there are no logs.%s\n\n' "$C_BOLD" "$C_RESET" >&2
    fi

    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

    # The previous image is addressed by digest, so this is a genuinely
    # different image from the one that just failed. Both conditions are
    # checked rather than assumed: an upgrade between two tags that resolve to
    # the SAME digest (re-running the installer with nothing new published)
    # would otherwise "roll back" onto the identical image and fail twice for
    # no reason, and a digest that has since been pruned from the local store
    # would fail with "No such image" dressed up as a rollback attempt.
    if [ "$FRESH_INSTALL" = no ] && [ -n "$PREVIOUS_IMAGE" ] &&
       [ "$PREVIOUS_IMAGE" != "$IMAGE" ] &&
       docker image inspect "$PREVIOUS_IMAGE" >/dev/null 2>&1; then
        warn "restoring the previous image: ${PREVIOUS_IMAGE_REF:-$PREVIOUS_IMAGE} ($PREVIOUS_IMAGE)"
        _failed_image=$IMAGE
        IMAGE=$PREVIOUS_IMAGE
        if start_container && wait_for_health; then
            IMAGE=$_failed_image
            err "Rolled back to ${PREVIOUS_IMAGE_REF:-$PREVIOUS_IMAGE}, which is healthy. The new image ($_failed_image) did not start."
            err "Your data volume '$VOLUME_NAME' was not touched."
            exit 1
        fi
        IMAGE=$_failed_image
        # Say the true thing. This used to claim "Container removed." while
        # leaving a container behind with --restart unless-stopped, i.e. a
        # crash loop the operator had just been told did not exist.
        docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
        err "Rollback to ${PREVIOUS_IMAGE_REF:-$PREVIOUS_IMAGE} also failed; the container has been removed."
        err "Your data volume '$VOLUME_NAME' is intact; nothing was deleted."
        err "This host is NOT serving DNS. Point your router back at its previous"
        err "resolver, then investigate with:  docker logs $CONTAINER_NAME"
        exit 1
    fi

    if [ "$FRESH_INSTALL" = no ]; then
        # An upgrade with nothing safe to go back to. Do NOT revert the host DNS
        # changes here: they were made by an EARLIER, successful run, not by
        # this one, and undoing them would be this script destroying state it
        # did not create.
        err "The upgrade failed and there is no previous image to restore."
        if [ -n "$PREVIOUS_IMAGE" ]; then
            err "The image this install was running ($PREVIOUS_IMAGE) is no longer in the local store."
        fi
        err "Your data volume '$VOLUME_NAME' is intact; nothing was deleted."
        err "Reinstall a known-good version with:  $SELF_CMD --image <ref>"
        exit 1
    fi

    # Fresh install: undo the host DNS changes too, so the box is left exactly
    # as it was found.
    warn "reverting host DNS changes made by this run"
    revert_host_dns
    err "Cogwheel was not installed. The host is back to its previous state."
    err "Data volume '$VOLUME_NAME' was left in place; remove it with:  docker volume rm $VOLUME_NAME"
    exit 1
}

revert_host_dns() {
    if [ "$STATE_RESOLVED_DROPIN" = yes ] && [ -e "$RESOLVED_DROPIN" ]; then
        rm -f "$RESOLVED_DROPIN"
        step "Removed $RESOLVED_DROPIN"
    fi

    case "$STATE_RESOLV_ACTION" in
        relinked)
            if [ -n "$STATE_RESOLV_PREV_TARGET" ]; then
                ln -sf "$STATE_RESOLV_PREV_TARGET" /etc/resolv.conf
                step "Restored /etc/resolv.conf -> $STATE_RESOLV_PREV_TARGET"
            else
                warn "install state records a relinked /etc/resolv.conf but not what it pointed at"
                write_fallback_resolv_conf
            fi ;;
        replaced)
            if resolv_backup_exists; then
                cp -a "$RESOLV_BACKUP" /etc/resolv.conf
                rm -f "$RESOLV_BACKUP"
                step "Restored /etc/resolv.conf from $RESOLV_BACKUP"
            else
                # Reachable when the backup was taken by a version of this
                # installer that could not create it (CONFIG_DIR did not exist
                # yet), or when it was deleted by hand. Do not leave the host
                # with a resolv.conf pointing at a resolver we are removing.
                warn "no backup at $RESOLV_BACKUP; cannot restore the original /etc/resolv.conf"
                write_fallback_resolv_conf
            fi ;;
        none|*) ;;
    esac

    if command -v systemctl >/dev/null 2>&1 &&
       systemctl cat systemd-resolved.service >/dev/null 2>&1; then
        systemctl restart systemd-resolved >/dev/null 2>&1 ||
            warn "could not restart systemd-resolved"
    fi
}

print_success() {
    # Lead with an ADDRESS, not a name. ADVERTISED_TARGETS begins with the
    # host's name (detect_advertised_targets appends the IPs after it), so the
    # headline used to read "DNS server  raspberrypi  port 53" -- and a router's
    # DNS field takes an address. Following that literally does not work, on the
    # one line the whole install exists to produce.
    _primary=$(printf '%s' "$ADVERTISED_TARGETS" | tr ',' '\n' |
        grep -m1 -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9A-Fa-f]*:[0-9A-Fa-f:]*$' || true)
    # No global address found (an isolated container, or `ip` missing): fall
    # back to the name rather than printing nothing at all.
    [ -n "$_primary" ] || _primary=$(printf '%s' "$ADVERTISED_TARGETS" | cut -d, -f1)

    printf '\n'
    printf '%s  Cogwheel is running.%s\n\n' "$C_BOLD$C_GREEN" "$C_RESET"
    printf '  %sWeb UI%s        http://%s:%s\n' "$C_BOLD" "$C_RESET" "$_primary" "$HTTP_PORT"
    printf '  %sDNS server%s    %s port %s\n' "$C_BOLD" "$C_RESET" "$_primary" "$DNS_PORT"
    printf '\n'
    printf '  Point the DNS setting on your router at one of:\n'
    printf '%s' "$ADVERTISED_TARGETS" | tr ',' '\n' | while IFS= read -r _t; do
        [ -n "$_t" ] && printf '      %s\n' "$_t"
    done
    printf '\n'
    printf '  Set it on the ROUTER (DHCP DNS servers), not on each device, so every\n'
    printf '  client is covered. On a dual-stack network set the IPv6 address too --\n'
    printf '  a client with an IPv6 resolver will bypass an IPv4-only setting.\n'
    printf '\n'
    # Every command here has to work when this script arrived down a pipe, so
    # none of them may be built from $0 or assume a checkout is present.
    printf '  Check it:    curl -fsS http://127.0.0.1:%s/health/ready\n' "$HTTP_PORT"
    printf '  Logs:        docker logs -f %s\n' "$CONTAINER_NAME"
    printf '  Upgrade:     re-run this installer\n'
    printf '  Uninstall:   %s --uninstall\n' "$SELF_CMD"
    printf '\n'
}

do_install() {
    require_root
    detect_platform
    require_docker
    # Before resolve_port_conflict, which is what takes the /etc/resolv.conf
    # backup that --uninstall depends on.
    ensure_config_dir

    resolve_port_conflict
    detect_advertised_targets

    step "Pulling $IMAGE"
    if ! _pull_err=$(docker pull "$IMAGE" 2>&1); then
        printf '%s\n' "$_pull_err" | sed 's/^/       /' >&2
        # "denied"/"unauthorized" from a registry that is reachable does not
        # mean the network is broken, and telling someone to check their network
        # sends them to the wrong place entirely. For ghcr.io it almost always
        # means the package is private -- which is a setting on the publisher's
        # side, not anything this host can fix.
        case "$_pull_err" in
            *denied*|*unauthorized*|*authentication*)
                die "not permitted to pull $IMAGE.
     The image exists but is not public, so this host cannot download it.
     If you are the publisher: make the package public in its GitHub package
     settings. Otherwise log in first:  docker login ghcr.io
     You can also install without Docker -- see DEPLOYMENT.md section 3." ;;
            *"not found"*|*"manifest unknown"*)
                die "$IMAGE does not exist.
     Check the tag, and that it was published for linux/$DOCKER_ARCH.
     Releases: https://github.com/thekozugroup/Cogwheel-DNS/releases" ;;
            *)
                die "could not pull $IMAGE.
     Check network access and that the tag exists for linux/$DOCKER_ARCH." ;;
        esac
    fi

    remember_previous
    ensure_volume
    write_env_file

    if [ "$SKIP_START" = yes ]; then
        write_state_file
        log "Configuration written to $ENV_FILE; not starting (--no-start)"
        return 0
    fi

    if ! start_container; then
        rollback
    fi

    if ! wait_for_health; then
        rollback
    fi

    if ! probe_dns; then
        warn "the container is healthy but DNS did not answer."
        warn "this usually means something is intercepting port $DNS_PORT, or the"
        warn "DNS bind address in $ENV_FILE does not match --network $NETWORK_MODE."
        rollback
    fi

    write_state_file
    print_success
}

do_uninstall() {
    require_root

    if load_state_file; then
        step "Read install state from $STATE_FILE (installed by ${STATE_INSTALLER_VERSION:-unknown})"
        # STATE_RESOLVED_DROPIN / STATE_RESOLV_ACTION / STATE_RESOLV_PREV_TARGET
        # are set directly by sourcing. Container and volume names are NOT
        # adopted from state: if you installed with --container/--volume, pass
        # the same flags to --uninstall.
        :
    else
        warn "no $STATE_FILE found; removing the container and reverting any Cogwheel resolver drop-in that exists"
    fi

    # Disk evidence is consulted whether or not a state file was read, and it
    # can only ever ADD work. Two reasons it cannot be an `else` branch:
    #
    #   - Installers before this fix overwrote the state file on every re-run,
    #     so boxes exist right now whose state file says "none" while the
    #     drop-in and the resolv.conf backup are plainly sitting on disk. A
    #     present-but-stale file used to defeat this recovery entirely.
    #   - The file can be edited or partially restored by hand.
    #
    # Leaving a host on Cogwheel's resolver after it has been uninstalled is the
    # worst outcome this script has, so the check that prevents it should not be
    # gated on the record being trustworthy.
    if [ "$STATE_RESOLVED_DROPIN" != yes ] && [ -e "$RESOLVED_DROPIN" ]; then
        STATE_RESOLVED_DROPIN=yes
        step "Found $RESOLVED_DROPIN on disk; it will be removed"
    fi
    if [ "$STATE_RESOLV_ACTION" = none ]; then
        if resolv_backup_exists; then
            STATE_RESOLV_ACTION=replaced
            step "Found $RESOLV_BACKUP on disk; /etc/resolv.conf will be restored from it"
        elif [ -f /etc/resolv.conf ] &&
             grep -q 'Written by the Cogwheel installer' /etc/resolv.conf 2>/dev/null; then
            STATE_RESOLV_ACTION=replaced
            step "/etc/resolv.conf was written by Cogwheel; it will be replaced"
        fi
    fi

    if docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
        docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
        step "Removed container '$CONTAINER_NAME'"
    else
        step "No container named '$CONTAINER_NAME'"
    fi

    revert_host_dns

    rm -f "$ENV_FILE" "$STATE_FILE"
    rmdir "$CONFIG_DIR" 2>/dev/null || true
    step "Removed installer configuration"

    if [ "$PURGE" = yes ]; then
        if docker volume inspect "$VOLUME_NAME" >/dev/null 2>&1; then
            docker volume rm "$VOLUME_NAME" >/dev/null
            step "Deleted data volume '$VOLUME_NAME'"
        fi
        log "Cogwheel removed, including all data."
    else
        log "Cogwheel removed. Data volume '$VOLUME_NAME' was KEPT."
        printf '  Re-running the installer will pick it up again.\n'
        printf '  To delete it:  docker volume rm %s\n' "$VOLUME_NAME"
    fi

    printf '  Verify host DNS still works:  getent hosts example.com\n'
}

do_fix_port_53() {
    require_root
    ensure_config_dir
    resolve_port_conflict
    # Persist what we changed even in fix-only mode, so uninstall can undo it.
    if [ "$STATE_RESOLVED_DROPIN" = yes ] || [ "$STATE_RESOLV_ACTION" != none ]; then
        detect_advertised_targets
        write_state_file
    fi
    log "Port $DNS_PORT is available."
}

main() {
    parse_args "$@"
    case "$ACTION" in
        install)      do_install ;;
        uninstall)    do_uninstall ;;
        fix-port-53)  do_fix_port_53 ;;
    esac
}

main "$@"
