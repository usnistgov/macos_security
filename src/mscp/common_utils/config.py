# mscp/common_utils/config.py

# Standard python modules
# from pathlib import Path

# Additional python modules
from loguru import logger

from .constants import CONFIG_PATH

# Local python modules
from .file_handling import open_file

# CONFIG_PATH: Path = Path.cwd() / "config" / "config.yaml"

try:
    logger.info("Attempting to open config file: {}", CONFIG_PATH)
    config = open_file(CONFIG_PATH)
    logger.success("Config file loaded successfully")
except Exception as e:
    logger.error("An error occurred while loading the config file: {}", e)
    raise
