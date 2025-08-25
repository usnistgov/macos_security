# mscp/common_utils/logging_config.py

# Standard python modules
from __future__ import annotations

import sys
from pathlib import Path

import loguru

# Local python modules
# from ..classes.loguruformatter import LoguruFormatter
from .logger_instance import logger


def set_logger(verbosity: int = 0, quitness: int = 0) -> loguru.Logger:
    log_level: str

    formatter = LoguruFormatter()
    logger.remove()

    level_value: int = verbosity - quitness
    formatter_level = formatter.log_format

    match level_value:
        case lv if lv <= -2:
            log_level = "CRITICAL"
        case -1:
            log_level = "ERROR"
        case 0:
            log_level = "WARNING"
        case 1:
            log_level = "INFO"
        case _:
            log_level = "DEBUG"
            formatter_level = formatter.log_format_debug

    logger.configure(
        handlers=[
            {
                "sink": sys.stderr,
                "level": log_level,
                "format": formatter_level,
            },
            {
                "sink": Path("logs", "mscp.log"),
                "level": log_level,
                "encoding": "utf-8",
                "enqueue": True,
                "serialize": True,
                "rotation": "1 hour",
                "retention": 3,
            },
        ]
    )

    return logger
