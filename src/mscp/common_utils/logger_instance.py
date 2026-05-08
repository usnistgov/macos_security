# mscp/common_utils/logging_instance.py
"""Singleton `loguru` logger used throughout mSCP.

Imports the global `loguru` logger, removes its default sink (so log
output isn't emitted until `set_logger` is called), and re-exports it
as `logger`.
"""

from __future__ import annotations

import loguru
from loguru import logger as _base_logger

_base_logger.remove()

logger: loguru.Logger = _base_logger
