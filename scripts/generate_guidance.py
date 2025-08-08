#!/usr/bin/env python
# filename: generate_guidance.py

import argparse
import sys

from mscp.common_utils import set_logger
from mscp.generate import (
    generate_guidance,
)
from mscp.cli import Customparser, validate_file


def main() -> None:
    logger = set_logger()
    logger.enable("mscp")
    logger.info("=== Logging Initialized ===")
    logger.info("LOGGING LEVEL: ERROR")

    parser = Customparser(
        description="CLI tool for generating guidance documents from MSCP.",
    )
    parser.add_argument(
        "--os_name",
        choices=["macos", "ios", "visionos"],
        default="macos",
        help="Which operating system being checked.",
        type=str,
    )

    parser.add_argument(
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

    parser.set_defaults(func=generate_guidance)
    
    parser.add_argument(
        "baseline",
        default=None,
        help="Baseline YAML file used to create the guide.",
        type=validate_file,
    )
    parser.add_argument(
        "-c", "--clean", help=argparse.SUPPRESS, action="store_true"
    )
    parser.add_argument(
        "-d",
        "--ddm",
        help="Generate declarative management artifacts for the rules.",
        action="store_true",
    )
    parser.add_argument(
        "-l",
        "--logo",
        default=None,
        help="Full path to logo file to be included in the guide.",
        action="store",
        type=validate_file,
    )
    parser.add_argument(
        "-p",
        "--profiles",
        help="Generate configuration profiles for the rules.",
        action="store_true",
    )
    parser.add_argument(
        "-r",
        "--reference",
        default=None,
        help="Use the reference ID instead of rule ID for identification.",
        action="store",
    )
    parser.add_argument(
        "-s",
        "--script",
        help="Generate the compliance script for the rules.",
        action="store_true",
    )
    # add gary argument to include tags for XCCDF generation, with a nod to Gary the SCAP guru
    parser.add_argument(
        "-g", "--gary", help=argparse.SUPPRESS, action="store_true"
    )
    parser.add_argument(
        "-x",
        "--xlsx",
        help="Generate the excel (xlsx) document for the rules.",
        action="store_true",
    )
    parser.add_argument(
        "-H",
        "--hash",
        default=None,
        help="sign the configuration profiles with subject key ID (hash value without spaces)",
        action="store",
    )
    parser.add_argument(
        "-a",
        "--audit_name",
        default=None,
        help="name of audit plist and log - defaults to baseline name",
        action="store",
    )
    parser.add_argument(
        "-A",
        "--all",
        default=None,
        help="Generate Documentation and all support files",
        action="store_true",
    )
    parser.add_argument(
        "-m",
        "--markdown",
        default=None,
        help="Generate Documentation in markdown format",
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

    if not hasattr(args, "func"):
        logger.error("Functionality for {} is not implemented yet.", args.subcommand)
        parser.print_help()
        sys.exit()

    if args.os_name == "ios" and args.os_version < 16:
        logger.error(
            "iOS/iPadOS 16 and below is not supported, please use mSCP version 1.0."
        )
        sys.exit()

    if args.os_name == "macos" and args.os_version < 13:
        logger.error(
            "macOS 13 and below is not supported, please use mSCP version 1.0."
        )
        sys.exit()

    if args.os_name == "visionos":
        logger.error("visionOS is not supported at this time.")
        sys.exit()

    if args.os_name != "macos" and args.script:
        logger.error(
            "Compliance script generation is only supported for macOS. Please remove the --script flag."
        )
        sys.exit()

    args.func(args)

if __name__ == "__main__":
    sys.exit(main())