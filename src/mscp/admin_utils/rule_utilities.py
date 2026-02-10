# mscp/admin_utils/rule_utilities.py

# Standard python modules
import argparse
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# Local python modules
from ..common_utils import (
    config,
    logger,
    make_dir,
    mscp_data,
    open_file,
    sanitize_input,
)


def add_new_rule(args: argparse.Namespace) -> None:
    """Add a new rule to the MSCP library."""
    logger.info("Building new rule for MSCP...")
