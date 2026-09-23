#!/bin/sh
#
# Cogwheel DNS — is there a newer image than the one I am running?
#
#   sudo sh /etc/cogwheel/check-update.sh
#   sh scripts/check-update.sh --image ghcr.io/thekozugroup/cogwheel-dns:latest
#
# WHAT LEAVES THIS MACHINE, exactly: between one and four HTTPS requests to
# ghcr.io, the registry this host already pulls its image from. No credentials,
# no identifiers, nothing about DNS. It is the same conversation `docker pull`
# has, minus the download.
#
# Cogwheel itself makes no update check. There is no setting for one and
# nothing in the product phones home, because the first thing a privacy
# appliance should not do is open an unannounced connection on first boot --
# even a harmless one, and even to answer a useful question. This script is the
# same answer as an opt-in: nothing runs it unless you do.
#
# If you want to be told, run it from cron and let the exit status decide:
#
#   0   up to date (or pinned by digest, which can never move)
#   10  a newer image exists for the tag this host follows
#   1   could not find out
#
#   # weekly, Sunday 09:00. --quiet prints nothing at all when there is
#   # nothing to say, so cron mails you only on exit 10.
#   0 9 * * 0 /etc/cogwheel/check-update.sh --quiet
#
# Do not append `|| true` to that line. The exit status is the whole message,
# and swallowing it is the same as not running the check.
#
# It never changes anything, and it will not apply the update for you:
# replacing your own container means stopping yourself mid-request, and a
# failure halfway leaves nothing to diagnose from. The two commands that do
# apply it are printed at the end.
#
# POSIX sh. Needs curl; jq is optional and only buys the schema-version answer.

set -eu

CONFIG_DIR="${COGWHEEL_CONFIG_DIR:-/etc/cogwheel}"
ENV_FILE="$CONFIG_DIR/.env"
CONTAINER_NAME="${COGWHEEL_CONTAINER_NAME:-cogwheel}"
IMAGE_REF="${COGWHEEL_IMAGE:-}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$(printf '\033[0m'); C_BOLD=$(printf '\033[1m')
    C_YELLOW=$(printf '\033[33m'); C_GREEN=$(printf '\033[32m')
else
    C_RESET=''; C_BOLD=''; C_YELLOW=''; C_GREEN=''
fi

say()  { printf '%s\n' "$*"; }
note() { printf '  %s\n' "$*"; }
err()  { printf 'error: %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
    cat <<'USAGE'
Cogwheel DNS update check

Usage:
  check-update.sh [--image REF] [--container NAME] [--quiet]

Options:
  --image REF       Image reference to check. Default: COGWHEEL_IMAGE from
                    /etc/cogwheel/.env, or whatever the running container was
                    started from.
  --container NAME  Container to read the running image from (default: cogwheel)
  --quiet           Print nothing unless an update is available
  -h, --help        This message

Exit status: 0 up to date, 10 update available, 1 could not find out.
USAGE
}

QUIET=no
while [ $# -gt 0 ]; do
    case "$1" in
        --image)     IMAGE_REF="${2:?--image needs a value}"; shift 2 ;;
        --container) CONTAINER_NAME="${2:?--container needs a value}"; shift 2 ;;
        --quiet)     QUIET=yes; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           usage >&2; die "unknown option: $1" ;;
    esac
done

out() { [ "$QUIET" = yes ] || printf '%s\n' "$*"; }

command -v curl >/dev/null 2>&1 || die "curl is needed and was not found."
command -v docker >/dev/null 2>&1 || die "docker is needed and was not found."

# ---------------------------------------------------------------------------
# Which reference does this host follow?
#
# .env first, because that is the file the operator edits and the one Compose
# reads; the running container second, for a host installed some other way.
# ---------------------------------------------------------------------------
if [ -z "$IMAGE_REF" ] && [ -r "$ENV_FILE" ]; then
    IMAGE_REF=$(sed -n 's/^COGWHEEL_IMAGE=//p' "$ENV_FILE" | tail -n 1)
fi
if [ -z "$IMAGE_REF" ]; then
    IMAGE_REF=$(docker container inspect --format '{{.Config.Image}}' "$CONTAINER_NAME" 2>/dev/null || printf '')
fi
[ -n "$IMAGE_REF" ] ||
    die "could not work out which image this host follows.
     Pass one:  $0 --image ghcr.io/thekozugroup/cogwheel-dns:latest"

# A digest reference names exactly one set of bytes. There is nothing to check
# and nothing that can move -- which is the point of pinning, not a fault.
case "$IMAGE_REF" in
    *@sha256:*)
        out "${C_BOLD}Pinned by digest.${C_RESET} $IMAGE_REF"
        out "  Nothing to check: this reference can never move. Follow a tag"
        out "  (for example :latest) in $ENV_FILE if you want updates to arrive."
        exit 0 ;;
esac

REGISTRY=${IMAGE_REF%%/*}
REMAINDER=${IMAGE_REF#*/}
NAME=${REMAINDER%:*}
TAG=${REMAINDER##*:}
[ "$TAG" = "$REMAINDER" ] && TAG=latest

if [ "$REGISTRY" != "ghcr.io" ]; then
    out "${C_YELLOW}This check only speaks to ghcr.io; $IMAGE_REF is somewhere else.${C_RESET}"
    out "  Compare it yourself with:  docker pull $IMAGE_REF"
    exit 0
fi

# ---------------------------------------------------------------------------
# What is on this host, and what is in the registry?
#
# The local side is the repo digest Docker recorded when it pulled. The remote
# side is the digest the registry currently serves for the same tag. Those are
# the two numbers Unraid's update button compares, and the two `docker pull`
# uses to decide whether there is anything to download.
# ---------------------------------------------------------------------------
LOCAL_DIGEST=$(docker image inspect --format '{{range .RepoDigests}}{{.}}
{{end}}' "$IMAGE_REF" 2>/dev/null | sed -n "s|^${REGISTRY}/${NAME}@||p" | head -n 1)

ACCEPT='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'

TOKEN=$(curl -fsSL --max-time 15 \
    "https://ghcr.io/token?scope=repository:${NAME}:pull&service=ghcr.io" 2>/dev/null |
    sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] ||
    die "could not get an anonymous pull token from ghcr.io for ${NAME}.
     Check this host has outbound HTTPS to ghcr.io."

# HEAD, so the digest arrives without the manifest body.
REMOTE_DIGEST=$(curl -fsSI --max-time 15 \
    -H "Authorization: Bearer $TOKEN" -H "Accept: $ACCEPT" \
    "https://ghcr.io/v2/${NAME}/manifests/${TAG}" 2>/dev/null |
    tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest:[[:space:]]*//p' | head -n 1)
[ -n "$REMOTE_DIGEST" ] ||
    die "ghcr.io did not return a digest for ${NAME}:${TAG}.
     The tag may not exist, or the package may not be public."

if [ -z "$LOCAL_DIGEST" ]; then
    out "${C_YELLOW}This host has no pulled copy of ${IMAGE_REF} to compare.${C_RESET}"
    out "  The registry currently serves $REMOTE_DIGEST"
    out "  (an image built locally has no registry digest, which is expected.)"
    exit 0
fi

if [ "$LOCAL_DIGEST" = "$REMOTE_DIGEST" ]; then
    out "${C_GREEN}Up to date.${C_RESET} ${IMAGE_REF} is the image ghcr.io serves."
    out "  $LOCAL_DIGEST"
    exit 0
fi

# ---------------------------------------------------------------------------
# There is something newer. Say what it is, and -- the one fact that decides
# whether this upgrade needs care -- whether it changes the database schema.
# ---------------------------------------------------------------------------
NEW_VERSION=
NEW_SCHEMA=
if command -v jq >/dev/null 2>&1; then
    ARCH=$(docker version --format '{{.Server.Arch}}' 2>/dev/null || printf 'amd64')
    INDEX=$(curl -fsSL --max-time 15 -H "Authorization: Bearer $TOKEN" -H "Accept: $ACCEPT" \
        "https://ghcr.io/v2/${NAME}/manifests/${REMOTE_DIGEST}" 2>/dev/null || printf '')
    # A single-architecture image has no manifest list, so fall back to the
    # digest already in hand rather than reporting nothing.
    CHILD=$(printf '%s' "$INDEX" |
        jq -r --arg a "$ARCH" '.manifests // [] | map(select(.platform.architecture == $a and .platform.os == "linux")) | .[0].digest // empty' 2>/dev/null || printf '')
    [ -n "$CHILD" ] || CHILD=$REMOTE_DIGEST

    CONFIG_DIGEST=$(curl -fsSL --max-time 15 -H "Authorization: Bearer $TOKEN" -H "Accept: $ACCEPT" \
        "https://ghcr.io/v2/${NAME}/manifests/${CHILD}" 2>/dev/null |
        jq -r '.config.digest // empty' 2>/dev/null || printf '')
    if [ -n "$CONFIG_DIGEST" ]; then
        LABELS=$(curl -fsSL --max-time 15 -H "Authorization: Bearer $TOKEN" \
            "https://ghcr.io/v2/${NAME}/blobs/${CONFIG_DIGEST}" 2>/dev/null |
            jq -r '.config.Labels // {}' 2>/dev/null || printf '{}')
        NEW_VERSION=$(printf '%s' "$LABELS" | jq -r '."org.opencontainers.image.version" // empty' 2>/dev/null || printf '')
        NEW_SCHEMA=$(printf '%s' "$LABELS" | jq -r '."io.cogwheel.schema-version" // empty' 2>/dev/null || printf '')
    fi
fi

RUNNING_VERSION=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$IMAGE_REF" 2>/dev/null || printf '')
RUNNING_SCHEMA=$(docker image inspect --format '{{index .Config.Labels "io.cogwheel.schema-version"}}' "$IMAGE_REF" 2>/dev/null || printf '')

say ''
printf '%s  An update is available for %s%s\n' "$C_BOLD$C_YELLOW" "$IMAGE_REF" "$C_RESET"
say ''
note "running   ${RUNNING_VERSION:-unknown}  $LOCAL_DIGEST"
note "available ${NEW_VERSION:-unknown}  $REMOTE_DIGEST"
say ''

if [ -n "$RUNNING_SCHEMA" ] && [ -n "$NEW_SCHEMA" ]; then
    if [ "$RUNNING_SCHEMA" = "$NEW_SCHEMA" ]; then
        note "Database schema is unchanged (v$RUNNING_SCHEMA). This upgrade does not"
        note "migrate anything, so going back is just putting the old tag back."
    else
        printf '  %sThis upgrade migrates the database: schema v%s -> v%s.%s\n' \
            "$C_BOLD" "$RUNNING_SCHEMA" "$NEW_SCHEMA" "$C_RESET"
        note "It happens in place, on first start, and leaves a copy of the old file"
        note "beside it as cogwheel.db.pre-v${NEW_SCHEMA} in the data volume."
        note "Going back afterwards means restoring that copy first, along with"
        note "deleting the -wal beside it: the older build refuses to open a database"
        note "it does not recognise, and 'restart: unless-stopped' turns that refusal"
        note "into a crash loop. The exact command is in docs/DEPLOYMENT.md."
    fi
else
    note "Could not read the schema version of one of the two images, so whether"
    note "this upgrade migrates the database is unknown. Check the release notes."
fi

say ''
note "Release notes: https://github.com/thekozugroup/Cogwheel-DNS/releases"
say ''
note "Apply it:"
note "    cd $CONFIG_DIR"
note "    sudo docker compose pull && sudo docker compose up -d"
say ''
note "Nothing has been changed by this check."
say ''
exit 10
