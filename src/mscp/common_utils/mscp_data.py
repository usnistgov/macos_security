# mscp/common_utils/mscp_data.py
"""Loader for the mSCP project metadata file.

Exposes `get_mscp_data` (re-readable accessor) and `mscp_data` (a
module-level dict populated at import time from the path configured
under `config["mscp_data"]`). This metadata holds version info,
supported platform lists, and other build constants consumed by the
CLI and generators.
"""

# Standard python modules
from pathlib import Path
from typing import Any

# Local python modules
from .config import config
from .file_handling import open_file
from .logger_instance import logger

# Additional python modules


def get_mscp_data() -> dict[str, Any]:
    """Read and return the project metadata dict from disk.

    The file path is taken from ``config["mscp_data"]``. Errors are
    swallowed and an empty dict is returned (after a logger error) so
    that import-time failure of this module doesn't take the whole CLI
    down.

    Returns:
        dict[str, Any]: Parsed contents of the mSCP metadata file, or
            an empty dict if the file is missing or unable to be parsed.
    """

    mscp_data_file: Path = Path(config["mscp_data"])
    try:
        logger.info("Attempting to open mscp_data file: {}", mscp_data_file)
        mscp_data: dict[str, Any] = open_file(mscp_data_file)

        return mscp_data

    except FileNotFoundError:
        logger.error("mscp_data file not found: {}", mscp_data_file)
        return {}

    except Exception as e:
        logger.error("Error parsing mscp_data file: {}", e)
        return {}


mscp_data = get_mscp_data()
