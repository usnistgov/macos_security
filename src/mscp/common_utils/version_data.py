# mscp/generate/checklist.py

# Standard python modules
from typing import Any

# Local python modules
from .logger_instance import logger

# Additional python modules


def get_version_data(
    os_name: str, os_version: float, mscp_data: dict[str, Any]
) -> dict[str, Any]:
    """
    Retrieve version data for a given operating system name and version.

    Args:
        os_name (str): The name of the operating system.
        os_version (int): The version of the operating system.

    Returns:
        dict[str, Any]: A dictionary containing the version data for the specified OS name and version.
                        If no matching version data is found, an empty dictionary is returned.

    Raises:
        FileNotFoundError: If the version file is not found.
        Exception: If there is an error parsing the version file.
    """

    try:
        return next(
            (
                entry
                for entry in mscp_data.get("versions", {})
                .get("platforms", {})
                .get(os_name.lower(), [])
                if entry.get("os_version") == os_version
            ),
            {},
        )

    except FileNotFoundError:
        logger.error("Project not supported for {} version {}", os_name, os_version)
        return {}

    except Exception as e:
        logger.error("Error parsing mscp_data file: {}", e)
        return {}
