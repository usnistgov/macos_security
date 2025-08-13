# mscp/common_utils/error_handling.py

import csv
import json
import plistlib
from collections.abc import Callable, Iterable
from functools import wraps
from typing import Any

# Additional python modules
import yaml

# Local python modules
from .logger_instance import logger

COMMON_ERRORS = (
    FileNotFoundError,
    PermissionError,
    OSError,
    IOError,
)

YAML_ERRORS = COMMON_ERRORS + (yaml.YAMLError,)

JSON_ERRORS = COMMON_ERRORS + (json.JSONDecodeError,)

PLIST_ERRORS = COMMON_ERRORS + (plistlib.InvalidFileException,)

CSV_ERRORS = COMMON_ERRORS + (csv.Error,)


def handle_expected_errors(
    func: Callable,
    expected_exceptions: Iterable[type[BaseException]],
    *,
    suppress: bool = False,
    context: str = "",
) -> Any:
    try:
        return func()
    except tuple(expected_exceptions) as e:
        logger.error(f"{context}Error: {e}")
        if not suppress:
            raise
    except Exception:
        raise


def log_expected_errors(
    expected_exceptions: Iterable[type[BaseException]],
    *,
    suppress: bool = False,
    context: str = "",
):
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return handle_expected_errors(
                lambda: func(*args, **kwargs),
                expected_exceptions,
                suppress=suppress,
                context=context,
            )

        return wrapper

    return decorator
