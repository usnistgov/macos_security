# mscp/common_utils/config.py

# Standard python modules
import logging

from pathlib import Path

# Local python modules
from src.mscp.common_utils.file_handling import open_yaml

# Initialize logger
logger = logging.getLogger(__name__)

CONFIG_PATH: Path = Path.cwd() / "config" / "config.yaml"

config = open_yaml(CONFIG_PATH)
