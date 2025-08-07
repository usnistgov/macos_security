# src/mscp/__main__.py

# Standard python modules
import sys

# Local python modules
from .cli import parse_cli
from .common_utils import logger, set_logger


def main() -> None:
    parse_cli()


if __name__ == "__main__":
    logger.enable("mscp")
    logger = set_logger()
    logger.info("=== Logging Initialized ===")
    logger.info("LOGGING LEVEL: INFO")

    sys.exit(main())
