#!/bin/sh
set -e

# Run the update check on interactive startup only: needs a TTY and an image
# with build metadata baked in (published images). `mscp_check` can be run
# manually inside the container at any time. Set MSCP_SKIP_UPDATE_CHECK=1
# to disable the startup check.
if [ -t 1 ] && [ -z "${MSCP_SKIP_UPDATE_CHECK:-}" ] && [ -n "${MSCP_BUILD_SHA:-}" ] && [ "${MSCP_BUILD_SHA}" != "unknown" ] && [ -n "${MSCP_IMAGE_REPO:-}" ]; then
    if command -v mscp_check >/dev/null 2>&1; then
        mscp_check || true
    elif [ -f "$(dirname "$0")/mscp_check" ]; then
        sh "$(dirname "$0")/mscp_check" || true
    fi
fi

exec "$@"
