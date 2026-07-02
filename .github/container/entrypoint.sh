#!/bin/sh
set -e

# Only run the update check when attached to a TTY (interactive session)
if [ -t 1 ] && [ -n "${MSCP_BUILD_SHA:-}" ] && [ "${MSCP_BUILD_SHA}" != "unknown" ] && [ -n "${MSCP_IMAGE_REPO:-}" ]; then
    latest=$(wget -qO- --timeout=5 \
        --header "Accept: application/vnd.github+json" \
        --header "User-Agent: mscp-container" \
        "https://api.github.com/repos/${MSCP_IMAGE_REPO}/commits/main" 2>/dev/null | \
        python3 -c "import sys, json; print(json.load(sys.stdin).get('sha', ''))" 2>/dev/null) || true

    if [ -n "${latest}" ] && [ "${MSCP_BUILD_SHA}" != "${latest}" ]; then
        owner="${MSCP_IMAGE_REPO%%/*}"
        printf '\n*** A newer version of the mscp container is available. ***\n'
        printf '    docker:    docker pull ghcr.io/%s/mscp_2.0:latest\n' "${owner}"
        printf '    container: container pull ghcr.io/%s/mscp_2.0:latest\n\n' "${owner}"
    fi
fi

exec "$@"
