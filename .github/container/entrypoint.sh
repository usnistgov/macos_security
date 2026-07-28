#!/bin/sh
set -e

# Only run the update check when attached to a TTY (interactive session)
if [ -t 1 ] && [ -n "${MSCP_BUILD_SHA:-}" ] && [ "${MSCP_BUILD_SHA}" != "unknown" ] && [ -n "${MSCP_IMAGE_REPO:-}" ]; then
    remote_sha=$(python3 - 2>/dev/null <<'PYEOF'
import json, os, sys, urllib.request

owner_repo = os.environ.get("MSCP_IMAGE_REPO", "")
owner = owner_repo.split("/")[0] if "/" in owner_repo else ""
image = "mscp_2.0"
tag = os.environ.get("MSCP_IMAGE_TAG") or "latest"

def ghcr_get(path, accept, token=None):
    req = urllib.request.Request(f"https://ghcr.io{path}")
    req.add_header("Accept", accept)
    req.add_header("User-Agent", "mscp-container")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.load(r)
    except Exception:
        return None

if not owner:
    sys.exit(0)

tok = ghcr_get(f"/token?scope=repository:{owner}/{image}:pull&service=ghcr.io", "application/json")
if not tok:
    sys.exit(0)
token = tok.get("token", "")

index = ghcr_get(
    f"/v2/{owner}/{image}/manifests/{tag}",
    "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json",
    token,
)
if not index or not index.get("manifests"):
    sys.exit(0)

plat = ghcr_get(
    f"/v2/{owner}/{image}/manifests/{index['manifests'][0]['digest']}",
    "application/vnd.oci.image.manifest.v1+json",
    token,
)
if not plat:
    sys.exit(0)

cfg_digest = (plat.get("config") or {}).get("digest", "")
if not cfg_digest:
    sys.exit(0)

cfg = ghcr_get(f"/v2/{owner}/{image}/blobs/{cfg_digest}", "application/json", token)
if not cfg:
    sys.exit(0)

labels = (cfg.get("config") or {}).get("Labels") or {}
print(labels.get("org.opencontainers.image.revision", ""))
PYEOF
    ) || true

    if [ -n "${remote_sha}" ] && [ "${MSCP_BUILD_SHA}" != "${remote_sha}" ]; then
        owner="${MSCP_IMAGE_REPO%%/*}"
        tag="${MSCP_IMAGE_TAG:-latest}"
        printf '\n*** A newer version of the mSCP container is available. ***\n'
        printf 'Please update to the latest version to ensure you have the most recent rules and features.\n\n'
        printf 'Exit the container and run the following command to update:\n'
        printf '    container image pull ghcr.io/%s/mscp_2.0:%s\n\n' "${owner}" "${tag}"
    fi
fi

exec "$@"
