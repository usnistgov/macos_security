# mscp/generate/checklist.py

# Standard python modules
import logging

from pathlib import Path
from typing import Optional, List, Dict, Any

# Additional python modules

# Local python modules
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml

logger = logging.getLogger(__name__)

def get_version_data(os_name: str, os_version: int) -> Dict[str, Any]:
    os_version_float: float = float(os_version)
    version_file: Path = Path(config["includes_dir"], "version.yaml")
    version_data: dict = open_yaml(version_file)
    current_version_data: dict = next((entry for entry in version_data.get("platforms", {}).get(os_name, []) if entry.get("os") == os_version_float), {})

    return current_version_data
