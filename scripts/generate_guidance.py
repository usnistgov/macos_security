#!/usr/bin/env python
# filename: scripts/generate_guidance.py

# Standard python modules
import sys
from pathlib import Path

# Add the project root to sys.path
sys.path.append(str(Path(__file__).resolve().parents[1]))

# Local python modules
from src.mscp.cli import parse_cli
from src.mscp.common_utils.logger_instance import logger
from src.mscp.common_utils.logging_config import set_logger

logger.enable("mscp")

GLOBAL_ARGS = {"--os_name", "--os_version", "-v", "-q"}

if __name__ == "__main__":
    logger.enable("mscp")
    logger = set_logger()
    logger.info("=== Logging Initialized ===")
    logger.info("LOGGING LEVEL: INFO")

    sys.argv.insert(1, Path(__file__).stem.split("_")[1])
    sys.exit(parse_cli())
