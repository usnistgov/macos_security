# mscp/common_utils/logging_config.py

# Standard python modules
from __future__ import annotations

import sys
from pathlib import Path

import loguru

# Local python modules
from ..classes.loguruformatter import LoguruFormatter
from .logger_instance import logger


def set_logger(debug: bool = False, verbosity: int = 0) -> loguru.Logger:
    log_level: str = "ERROR"

    if verbosity == 1:
        log_level = "WARNING"
    elif verbosity == 2:
        log_level = "INFO"
    elif verbosity > 2 or debug:
        log_level = "DEBUG"

    formatter = LoguruFormatter()
    logger.remove()

    logger.configure(
        handlers=[
            {
                "sink": sys.stderr,
                "level": log_level,
                "format": formatter.format_log,
                "filter": lambda record: record["level"].name != "SUCCESS",
            },
            {
                "sink": Path("logs", "mscp.log"),
                "level": log_level,
                "encoding": "utf-8",
                "enqueue": True,
                "serialize": True,
                "rotation": "1 hour",
            },
        ]
    )

    return logger
