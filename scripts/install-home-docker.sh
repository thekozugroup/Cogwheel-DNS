#!/bin/sh
#
# DEPRECATED — kept only so existing links and runbooks keep working.
#
# This script used to carry its own copy of the port-53 conflict handling, the
# container run flags and the advertised-target detection. All of that now
# lives in scripts/install.sh, which additionally waits for the container to
# become healthy, proves the resolver answers a real query, rolls back on
# failure, and supports --uninstall.
#
# Use scripts/install.sh directly:
#
#   sudo ./scripts/install.sh
#   sudo ./scripts/install.sh --help
#
# This shim forwards whatever you pass it and will be removed in a future
# release.

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

printf 'scripts/install-home-docker.sh is deprecated; forwarding to scripts/install.sh\n' >&2

# Map the environment variables the old script honoured onto the new flags.
#
# Order matters: the mapped flags are appended first, then the caller's own
# arguments are rotated to the end so an explicit flag always beats a legacy
# environment variable. (`set --` on its own would discard "$@" entirely,
# which would silently turn `install-home-docker.sh --help` into a real
# install.)
argc=$#

if [ -n "${IMAGE_TAG:-}" ]; then      set -- "$@" --image "$IMAGE_TAG"; fi
if [ -n "${CONTAINER_NAME:-}" ]; then set -- "$@" --container "$CONTAINER_NAME"; fi
if [ -n "${DNS_HOST_PORT:-}" ]; then  set -- "$@" --dns-port "$DNS_HOST_PORT"; fi
if [ -n "${WEB_HOST_PORT:-}" ]; then  set -- "$@" --http-port "$WEB_HOST_PORT"; fi

# Rotate the original arguments from the front to the back.
i=0
while [ "$i" -lt "$argc" ]; do
    set -- "$@" "$1"
    shift
    i=$((i + 1))
done

exec sh "$SCRIPT_DIR/install.sh" "$@"
