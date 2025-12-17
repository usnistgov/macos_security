# mscp/common_utils/customization.py

# Standard python modules
from pathlib import Path
from typing import Any

# Local python modules
from .logger_instance import logger
from .file_handling import open_file


def collect_overrides(override_location: Path) -> dict[str, Any]:
    """
    Collects all custom override yaml files from the provided overrides location.

    Args:
        override_location (Path): The path to the folder containing the overrides to process.

    Returns:
        dict[str, Any]: Dictionary of discovered custom overrides data.

    Raises:
        Exception: If there is an error processing the overrides file.
    """

    overrides = {}
    overrides_dir = override_location

    for override_file in overrides_dir.rglob("*.y*ml"):
        try:
            logger.info("Attempting to open custom override file: {}", override_file)
            override_data: dict[str, Any] = open_file(override_file)

            override_id: str = override_data.get("id", "")

            if not override_id:
                logger.warning(
                    "Custom override file does not contain id: field, attempting to fall back to filename as id."
                )
                override_id = override_file.stem

            overrides[override_id] = {}

            for k, v in override_data.items():
                overrides[override_id][k] = v

        except Exception as e:
            logger.error("Failed to load override from file {}: {}", override_file, e)

    return overrides
