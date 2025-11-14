#!/usr/bin/env python
# filename: scripts/generate_scap.py

# Standard python modules
import sys
from mscp.common_utils import set_logger
from mscp.generate import (
    generate_scap,
    
)
from mscp.cli import Customparser, validate_file

# Add the project root to sys.path
sys.path.append(str(Path(__file__).resolve().parents[1]))

# Local python modules
from src.mscp.cli import parse_cli
from src.mscp.common_utils.logger_instance import logger
from src.mscp.common_utils.logging_config import set_logger

if __name__ == "__main__":
    logger.enable("mscp")
    logger = set_logger()
    logger.info("=== Logging Initialized ===")
    logger.info("LOGGING LEVEL: ERROR")
    
    parser = Customparser(
        description="CLI tool for generating scap content from MSCP.",
    )
    
    parser.set_defaults(func=generate_scap)
    parser.add_argument(
        "-b",
        "--baseline",
        default="all_rules",
        help="Baseline YAML file used to create the guide.",
        type=str
    )
    parser.add_argument(
        "-x",
        "--xccdf",
        default=None,
        help="Generate an xccdf file.",
        action="store_true",
    )
    parser.add_argument(
        "--oval",
        default=None,
        help="Generate an oval file of the checks.",
        action="store_true",
    )
    parser.add_argument(
        "-l",
        "--list_tags",
        default=None,
        help="List the available keyword tags to search for.",
        action="store_true",
    )

    # Platform options
    parser.add_argument(
        "-O", 
        "--os_name",
        type=str,
        choices=["macos", "ios", "visionos"],
        default="macos",
        help="Target operating system for the baseline (default: macOS)."
    )
    parser.add_argument(
        "--list-platforms",
        action="store_true",
        help="List all available platforms and their OS versions."
    )
    parser.add_argument(
        "-o",
        "--os_version",
        default=15.0,
        type=float,
        help="Operating system version (eg: 14.0, 15.0).",
    )

    parser.add_argument(
        "-D",
        "--debug",
        required=False,
        help="Enable debug output.",
        action="store_true",
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to write the baseline file (default: ../build/scap/<platform>)"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        required=False,
        help="Increase verbosity level (e.g., -v, -vv, -vvv)",
        action="count",
        default=0,
    )

    sys.argv.insert(1, Path(__file__).stem.split("_")[1])
    sys.exit(parse_cli())