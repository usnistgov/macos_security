# mscp/common_utils/config.py

# Standard python modules
from pathlib import Path

# Local python modules
from .file_handling import open_file
from .logger_instance import logger

# Additional python modules

src_path = Path(__file__).parent.parent.parent
project_path = src_path.parent

CONFIG_PATH: Path = project_path / "config" / "config.yaml"

try:
    logger.info("Attempting to open config file: {}", CONFIG_PATH)
    config = open_file(CONFIG_PATH)
    logger.success("Config file loaded successfully")
except Exception as e:
    logger.error("An error occurred while loading the config file: {}", e)
    raise
