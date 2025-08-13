# mscp/common_utils/logging_config.py

# Standard python modules
from __future__ import annotations

import sys
from pathlib import Path

import loguru

# Local python modules
from ..classes.loguruformatter import LoguruFormatter
from .logger_instance import logger


def set_logger(log_level: str = "ERROR") -> loguru.Logger:
    formatter = LoguruFormatter()
    logger.remove()

    logger.configure(
        handlers=[
            {
                "sink": sys.stderr,
                "level": log_level,
                "format": formatter.format_log,
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
