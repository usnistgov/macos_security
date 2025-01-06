# mscp/common_utils/config.py

import logging

from pathlib import Path

from src.mscp.common_utils.file_handling import open_yaml

logger = logging.getLogger(__name__)

CONFIG_PATH: Path = Path.cwd() / "config" / "config.yaml"

config = open_yaml(CONFIG_PATH)
