# mscp/generate/checklist.py

# Standard python modules
from pathlib import Path
from typing import Optional, List, Dict, Any

# Additional python modules
from loguru import logger

# Local python modules
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml


def get_version_data(os_name: str, os_version: int) -> dict[str, Any]:
    os_version_float: float = float(os_version)
    version_file: Path = Path(config["includes_dir"], "version.yaml")
    try:
        logger.info("Attempting to open version file: {}", version_file)
        version_data: dict = open_yaml(version_file)
        platforms = version_data.get("platforms", {})
        os_entries = platforms.get(os_name, [])

        return next(
            (entry for entry in os_entries if entry.get("os") == os_version_float),
            {}
        )
    except FileNotFoundError:
        logger.error("Version file not found: {}", version_file)
        return {}
    except Exception as e:
        logger.error("Error parsing version file: {}", e)
        return {}
