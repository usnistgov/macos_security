# mscp/common_utils/logging_instance.py

from __future__ import annotations

import loguru
from loguru import logger as _base_logger

logger: loguru.Logger = _base_logger
