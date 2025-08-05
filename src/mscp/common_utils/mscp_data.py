# mscp/common_utils/mscp_data.py

# Standard python modules
from pathlib import Path
from typing import Any

# Local python modules
from .config import config
from .file_handling import open_file
from .logger_instance import logger

# Additional python modules


def get_mscp_data() -> dict[str, Any]:
    """
    Retrieve mscp data.

    Args:
        none

    Returns:
        dict[str, Any]: A dictionary containing the mscp data.

    Raises:
        FileNotFoundError: If the mscp_data file is not found.
        Exception: If there is an error parsing the mscp_data file.
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
