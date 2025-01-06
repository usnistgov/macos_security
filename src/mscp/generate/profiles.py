# mscp/generate/payload.py

# Standard python modules
import logging

from pathlib import Path
from icecream import ic

# Local python modules
from src.mscp.common_utils.config import config
from src.mscp.classes.baseline import Baseline
from src.mscp.common_utils.file_handling import open_file, open_yaml, make_dir

# Initialize local logger
logger = logging.getLogger(__name__)

def generate_profiles(build_path: Path, baseline_name: str, baseline: Baseline, hash: str = "", signing: bool = False) -> None:
    manifests_file: dict = open_yaml(Path(config.get("includes_dir", ""), "supported_payloads.yaml"))
    ic(manifests_file)
