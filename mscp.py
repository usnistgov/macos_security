# ./mscp.py

# Standard python modules
import logging
import logging.config

from pathlib import Path

# Local python modules
from src.mscp.cli import main
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml, remove_file

# TODO Convert to loguru and loguru-config before going to production
#!       This will allow for better log handling and serialization for ingestion into external tools.

# Initialize logger
def setup_logging(environment: str = "development", update_log=False) -> None:
    config_file: Path = Path(config.get("logging_config", ""))
    logging_config = open_yaml(config_file)
    log_file: Path = Path(logging_config.get("handlers", {}).get("file", {}).get("filename", None))

    if log_file.exists() and not update_log:
        remove_file(log_file)

    logging.config.dictConfig(logging_config)

    log_level_str: str = logging_config.get("loggers", {}).get(environment, {}).get("level", None)

    if log_level_str == None:
        raise("Unable to initialize logging")

    logger = logging.getLogger(environment)
    logger.info("=== Logging Initialized ===")
    logger.info(f"LOGGING LEVEL: {log_level_str}")
    logger.info(f"LOGGING ENVIRONMENT: {environment}")


if __name__ == "__main__":
    setup_logging(config.get("environment", ""))
    main()
