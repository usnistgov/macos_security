# mscp/common_utils/error_handling.py

import csv
import json
import plistlib
import subprocess
from collections.abc import Callable, Iterable
from functools import wraps
from typing import Any

# Additional python modules
from ruamel.yaml import YAMLError
from ruamel.yaml.constructor import ConstructorError
from ruamel.yaml.parser import ParserError
from ruamel.yaml.representer import RepresenterError
from ruamel.yaml.scanner import ScannerError

# Local python modules
from .logger_instance import logger

COMMON_ERRORS = (
    FileNotFoundError,
    PermissionError,
    OSError,
    IOError,
)

YAML_ERRORS = COMMON_ERRORS + (
    YAMLError,
    ConstructorError,
    ScannerError,
    ParserError,
    RepresenterError,
)
JSON_ERRORS = COMMON_ERRORS + (json.JSONDecodeError,)
PLIST_ERRORS = COMMON_ERRORS + (plistlib.InvalidFileException,)
CSV_ERRORS = COMMON_ERRORS + (csv.Error,)
COMMAND_ERRORS = COMMON_ERRORS + (subprocess.CalledProcessError,)


def handle_expected_errors(
    func: Callable,
    expected_exceptions: Iterable[type[BaseException]],
    *,
    suppress: bool = False,
    context: str = "",
    fallback: Any = None,
) -> Any:
    try:
        return func()
    except tuple(expected_exceptions) as e:
        if suppress:
            if callable(fallback):
                return fallback(e)
        else:
            logger.error(f"{context}Error: {e}")
            raise
    except Exception:
        raise


def log_expected_errors(
    expected_exceptions: Iterable[type[BaseException]],
    *,
    suppress: bool = False,
    context: str = "",
    fallback: Any = None,
):
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return handle_expected_errors(
                lambda: func(*args, **kwargs),
                expected_exceptions,
                suppress=suppress,
                context=context,
                fallback=fallback,
            )

        return wrapper

    return decorator
