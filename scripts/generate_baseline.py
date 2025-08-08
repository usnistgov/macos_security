#!/usr/bin/env python
# filename: generate_baseline.py

import argparse
import sys
from mscp.common_utils import set_logger
from mscp.generate import (
    generate_baseline,
)
from mscp.cli import Customparser


def main() -> None:
    logger = set_logger()
    logger.enable("mscp")
    logger.info("=== Logging Initialized ===")
    logger.info("LOGGING LEVEL: ERROR")
    
    parser = Customparser(
        description="CLI tool for generating baselines and benchmarks from MSCP.",
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

    parser.set_defaults(func=generate_baseline)
    parser.add_argument(
        "-c",
        "--controls",
        help="Output the 800-53 controls covered by the rules.",
        action="store_true",
    )
    parser.add_argument(
        "-k",
        "--keyword",
        help="Keyword tag to collect rules containing the tag.",
        action="store",
    )
    parser.add_argument(
        "-l",
        "--list_tags",
        help="List the available keyword tags to search for.",
        action="store_true",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to write the baseline file (default: ../build/baselines/<platform>)"
    )
    parser.add_argument(
        "-t",
        "--tailor",
        help="Customize the baseline to your organizations values.",
        action="store_true",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        required=False,
        help="Increase verbosity level (e.g., -v, -vv, -vvv)",
        action="count",
        default=0,
    )

    try:
        args = parser.parse_args()

    except argparse.ArgumentError as e:
        logger.error("Argument Error: {}", e)
        parser.print_help()
        sys.exit()

    if args.verbose == 1:
        logger = set_logger(verbosity=1)
        logger.info("=== Logging level changed ===")
        logger.info("LOGGING LEVEL: WARNING")
    elif args.verbose == 2:
        logger = set_logger(verbosity=2)
        logger.info("=== Logging level changed ===")
        logger.info("LOGGING LEVEL: INFO")
    elif args.verbose > 2 or args.debug:
        logger = set_logger(debug=True)
        logger.info("=== Logging level changed ===")
        logger.info("LOGGING LEVEL: DEBUG")

    if args.os_name == "ios" and args.os_version < 16:
        logger.warning(
            "iOS/iPadOS 16 and below is not supported, please use mSCP version 1.0."
        )
        sys.exit()

    if args.os_name == "macos" and args.os_version < 13:
        logger.warning(
            "macOS 13 and below is not supported, please use mSCP version 1.0."
        )
        sys.exit()

    args.func(args)

if __name__ == "__main__":
    sys.exit(main())