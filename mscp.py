#! .venv/bin/python3 mscp.py
# filename: mscp.py

# Standard python modules
import sys
from pathlib import Path

# Additional python modules
from loguru import logger

# Local python modules
from src.mscp import main
from src.mscp.classes import LoguruFormatter
from src.mscp.common_utils import config


# Initialize logger
def setup_logging(environment: str = "development") -> None:
    logger_format: str = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | {name}:{function}:{line} | {function} | {level} | <level>{message}</level>"

    # Set logging level based on environment
    match environment:
        case "development":
            log_level_str = "DEBUG"
        case "production":
            log_level_str = "INFO"
        case "testing":
            log_level_str = "DEBUG"
        case _:
            log_level_str = "DEBUG"

    formatter = LoguruFormatter()
    logger.remove()
    logger.configure(
        handlers=[
            {
                "sink": sys.stderr,
                "level": log_level_str,
                "format": formatter.format_log,
            },
            {
                "sink": Path("logs", f"mscp_{log_level_str}.log"),
                "level": log_level_str,
                "encoding": "utf-8",
                "enqueue": True,
                "serialize": True,
                "rotation": "1 hour",
            },
        ]
    )

    logger.info("=== Logging Initialized ===")
    logger.info("LOGGING LEVEL: {}", log_level_str)
    logger.info("LOGGING ENVIRONMENT: {}", environment)


if __name__ == "__main__":
    setup_logging(config.get("environment", ""))
    main()
