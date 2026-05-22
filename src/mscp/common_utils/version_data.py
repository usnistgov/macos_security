# mscp/common_utils/version_data.py
"""Lookup helper for per-OS / per-version metadata.

Exposes `get_version_data`, which resolves the entry for a given
``(os_name, os_version)`` from the ``versions.platforms`` block of the
project metadata loaded in `mscp_data`.
"""

# Standard python modules
from typing import Any

# Local python modules
from .logger_instance import logger

OS_NAME_MAP = {
    "tahoe": "Tahoe",
    "sequoia": "Sequoia",
    "sonoma": "Sonoma",
    "ventura": "Ventura",
    "ios_26": "iOS 26",
    "ios_18": "iOS 18",
    "ios_17": "iOS 17",
    "visionos_26": "VisionOS 26",
}


def get_version_data(
    os_name: str, os_version: float, mscp_data: dict[str, Any]
) -> dict[str, Any]:
    """Return the metadata entry for an OS / version pair.

    Looks up ``mscp_data["versions"]["platforms"][os_name]`` and returns
    the entry whose ``os_version`` matches. Unknown OS names or versions
    raise `ValueError`; other parse errors are logged and yield an empty
    dict so callers can proceed with defaults.

    Args:
        os_name (str): Operating system family (e.g. ``"macOS"``,
            ``"ios"``); compared case-insensitively.
        os_version (float): Version (e.g. ``15.0``).
        mscp_data (dict[str, Any]): Project metadata as produced by
            `get_mscp_data`.

    Returns:
        dict[str, Any]: The matching version entry, or ``{}`` on a
            non-`ValueError` parse failure.

    Raises:
        ValueError: If `os_name` isn't in the platforms dict, or no
            version entry has the requested `os_version`. The message
            includes the valid options.
    """

    # version_file: Path = Path(config["includes_dir"], "version.yaml")
    try:
        platforms: dict = mscp_data.get("versions", {}).get("platforms", {})
        valid_types = sorted(platforms.keys())

        if os_name.lower() not in platforms:
            raise ValueError(
                f"Unknown os_type {os_name!r}. Valid options: {valid_types}"
            )

        valid_versions = [e.get("os_version") for e in platforms[os_name.lower()]]
        match = next(
            (
                e
                for e in platforms[os_name.lower()]
                if e.get("os_version") == os_version
            ),
            None,
        )

        if match is None:
            raise ValueError(
                f"Unknown os_version {os_version!r} for {os_name!r}. "
                f"Valid versions: {valid_versions}"
            )
        else:
            match["compliance_version"] = (
                f"{OS_NAME_MAP.get(match['os_name'].lower(), match['os_name'])} Guidance, Revision {match['revision']}"
            )

        return match

    except ValueError:
        raise
    except Exception as e:
        logger.error("Error parsing mscp_data file: {}", e)
        return {}
