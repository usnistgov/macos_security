#! /usr/bin/env python3
# filename: mscp.py

# Standard python modules
import sys

# Local python modules
from src.mscp.cli import parse_cli
from src.mscp.common_utils.logger_instance import logger
from src.mscp.common_utils.logging_config import set_logger

logger.enable("mscp")
logger = set_logger()
logger.info("=== Logging Initialized ===")
logger.info("LOGGING LEVEL: INFO")


def main() -> None:
    parse_cli()


if __name__ == "__main__":
    sys.exit(main())
