# ./mscp.py

# Standard python modules
import sys

# Additional python modules
from loguru import logger

# Local python modules
from src.mscp.cli import main
from src.mscp.common_utils.config import config


# Initialize logger
def setup_logging(environment: str = "development") -> None:
    logger_format: str = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | {name} | {level} | <level>{message}</level>"

    match environment:
        case "development":
            log_level_str = "DEBUG"
        case "production":
            log_level_str = "INFO"
        case "testing":
            log_level_str = "DEBUG"
        case _:
            log_level_str = "DEBUG"

    logger.remove()
    logger.configure(handlers=[{"sink": sys.stderr, "level": log_level_str, "format": logger_format},{"sink": f"logs/{log_level_str}.log", "level": log_level_str, "format": logger_format, "serialize": True, "rotation": "1 hour"}])

    logger.info("=== Logging Initialized ===")
    logger.info("LOGGING LEVEL: {}", log_level_str)
    logger.info("LOGGING ENVIRONMENT: {}", environment)


if __name__ == "__main__":
    setup_logging(config.get("environment", ""))
    main()
