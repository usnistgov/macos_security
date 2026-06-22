# mscp/common_utils/logging_config.py
"""`loguru` configuration for the mSCP CLI.

`set_logger` wires up a stderr sink whose level depends on ``-v`` /
``-vv`` / ``--debug``, plus a rotating file sink under ``logs/mscp.log``.
`function_filter` lets developers narrow stderr output to a single
module via the ``MSCP_DEV_FILTER`` environment variable.
The module-level `verbose_logging` and `suppress_spinner` flags are read by
`spinner_utils.conditional_inject_spinner` to decide whether to show a
spinner.
"""

# Standard python modules
from __future__ import annotations

import os
import sys
from pathlib import Path

import loguru

# Local python modules
from .logger_instance import logger

verbose_logging: bool = False
suppress_spinner: bool = False


def function_filter(record):
    """`loguru` filter limiting output to a developer-selected module.

    Reads the ``MSCP_DEV_FILTER`` environment variable; when set, only
    records whose module name (lowercased) contains the substring pass
    through. When unset, the empty string is "in" every module name, so
    nothing is filtered.

    Example::

        export MSCP_DEV_FILTER=guidance_support

    Args:
        record: A `loguru` record dict, of which only ``module`` is read.

    Returns:
        bool: ``True`` if this record should be emitted to the configured
            sinks, ``False`` to suppress it.
    """
    lvl = record["level"].name

    if lvl == "SUCCESS":
        return False

    filter = os.environ.get("MSCP_DEV_FILTER", "")

    return filter in record["module"].lower()


def set_logger(debug: bool = False, verbosity: int = 0) -> loguru.Logger:
    """Configure the global `loguru` logger and return it.

    Replaces any existing handlers with a stderr sink (level chosen
    from `verbosity` / `debug`) plus a rotating file sink at
    ``logs/mscp.log``. Also updates the module-level `verbose_logging`
    flag so other modules (e.g. `spinner_utils`) can adapt their UI.

    The stderr level mapping is:

    - `verbosity == 0` (default): ``ERROR``
    - `verbosity == 1` (``-v``): ``WARNING``
    - `verbosity == 2` (``-vv``): ``INFO``
    - `verbosity > 2` or `debug=True`: ``DEBUG``

    Args:
        debug (bool): If true, force the stderr sink to ``DEBUG`` level
            regardless of `verbosity`. Defaults to ``False``.
        verbosity (int): Verbosity level from the ``-v`` flag. Defaults
            to ``0`` (errors only).

    Returns:
        loguru.Logger: The reconfigured global logger, ready for use.
    """
    global verbose_logging
    verbose_logging = verbosity > 0 or debug
    log_level: str = "ERROR"

    if verbosity == 1:
        log_level = "WARNING"
    elif verbosity == 2:
        log_level = "INFO"
    elif verbosity > 2 or debug:
        log_level = "DEBUG"

    # formatter = LoguruFormatter()
    logger.remove()

    logger.configure(
        handlers=[
            {
                "sink": sys.stderr,
                "level": log_level,
                "filter": function_filter,
            },
            {
                "sink": Path("logs", "mscp.log"),
                "level": "DEBUG",
                "encoding": "utf-8",
                "enqueue": True,
                "serialize": True,
                "rotation": "1 hour",
                "retention": 5,
            },
        ]
    )

    return logger
