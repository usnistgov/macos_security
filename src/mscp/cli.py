# mscp/cli.py

# Standard python modules
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from platform import mac_ver

# Local python modules
from . import __version__
from .common_utils import logger, set_logger, supported_languages, validate_yaml_file
from .generate import (
    generate_baseline,
    generate_checklist,
    generate_guidance,
    generate_language,
    generate_local_report,
    generate_mapping,
)


class Customparser(argparse.ArgumentParser):
    """
    Customparser is a subclass of argparse.ArgumentParser that overrides the error method
    to log an error message, print the help message, and exit the program with a status code of 2.

    Methods:
        error(message: str) -> None:
            Logs an error message, prints the help message, and exits the program with status code 2.
    """

    def error(self, message: str) -> None:
        logger.error(f"Argument Error: {message}")
        self.print_help()
        sys.exit(2)


def get_mac_os_version() -> float:
    """
    Retrieves the macOS version as a float.

    Returns:
        float: The macOS version.
    """
    version_str = mac_ver()[0]
    try:
        major = version_str.split(".")[0]
        return float(major)
    except (ValueError, IndexError):
        logger.error(f"Unable to parse macOS version from string: {version_str}")
        sys.exit()


def validate_file(arg: str) -> Path:
    if (file := Path(arg)).is_file():
        return file
    else:
        logger.error(f"File Not found: {arg}")
        sys.exit()


def parse_cli(program: str | None = "mscp") -> None:
    logger = set_logger()

    parent_parser = Customparser(add_help=False)

    parent_parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase output verbosity (-v, -vv)",
    )

    parent_parser.add_argument(
        "-q",
        "--quiet",
        action="count",
        default=0,
        help="Reduce output verbosity (-q, -qq)",
    )

    benchmark_parser = Customparser(add_help=False)
    benchmark_parser.add_argument(
        "-B",
        "--benchmark",
        default=None,
        help="Benchmark to use for the rules.",
        action="store",
    )

    parser = Customparser(
        description="CLI tool for managing baseline and compliance documents.",
        prog=program,
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
        default=get_mac_os_version(),
        type=float,
        help="Operating system version (eg: 14.0, 15.0).",
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    # Sub Parsers for individual commands
    subparsers = parser.add_subparsers(
        title="Subcommands",
        required=True,
        description="Valid Subcommands",
        dest="subcommand",
    )

    # 'baseline' subcommand
    baseline_parser: argparse.ArgumentParser = subparsers.add_parser(
        "baseline",
        help="Given a keyword tag, generate a generic baseline.yaml file containing rules with the tag.",
        parents=[parent_parser, benchmark_parser],
        add_help=True,
    )
    baseline_parser.set_defaults(func=generate_baseline)
    baseline_parser.add_argument(
        "-c",
        "--controls",
        help="Output the 800-53 controls covered by the rules.",
        action="store_true",
    )
    baseline_parser.add_argument(
        "-k",
        "--keyword",
        help="Keyword tag to collect rules containing the tag.",
        action="store",
    )
    baseline_parser.add_argument(
        "-l",
        "--list_tags",
        help="List the available keyword tags to search for.",
        action="store_true",
    )
    baseline_parser.add_argument(
        "-t",
        "--tailor",
        help="Customize the baseline to your organizations values.",
        action="store_true",
    )

    # 'guidance' subcommand
    guidance_parser: argparse.ArgumentParser = subparsers.add_parser(
        "guidance",
        help="Given a baseline, create guidance documents and files.",
        parents=[parent_parser, benchmark_parser],
        add_help=True,
    )
    guidance_parser.set_defaults(func=generate_guidance)
    guidance_parser.add_argument(
        "baseline",
        default=None,
        help="Baseline YAML file used to create the guide.",
        type=validate_file,
    )
    guidance_parser.add_argument(
        "-c", "--clean", help=argparse.SUPPRESS, action="store_true"
    )
    guidance_parser.add_argument(
        "-d",
        "--ddm",
        help="Generate declarative management artifacts for the rules.",
        action="store_true",
    )
    guidance_parser.add_argument(
        "-l",
        "--logo",
        default=None,
        help="Full path to logo file to be included in the guide.",
        action="store",
        type=validate_file,
    )
    guidance_parser.add_argument(
        "-L",
        "--language",
        default="en",
        help="Generate guidance using a supported language.",
        action="store",
        choices=supported_languages,
    )
    guidance_parser.add_argument(
        "-p",
        "--profiles",
        help="Generate configuration profiles for the rules.",
        action="store_true",
    )
    guidance_parser.add_argument(
        "-r",
        "--reference",
        default=None,
        help="Use the reference ID instead of rule ID for identification.",
        action="store",
    )
    guidance_parser.add_argument(
        "-s",
        "--script",
        help="Generate the compliance script for the rules.",
        action="store_true",
    )
    # add gary argument to include tags for XCCDF generation, with a nod to Gary the SCAP guru
    guidance_parser.add_argument(
        "-g", "--gary", help=argparse.SUPPRESS, action="store_true"
    )
    guidance_parser.add_argument(
        "-x",
        "--xlsx",
        help="Generate the excel (xlsx) document for the rules.",
        action="store_true",
    )
    guidance_parser.add_argument(
        "-H",
        "--hash",
        default=None,
        help="sign the configuration profiles with subject key ID (hash value without spaces)",
        action="store",
    )
    guidance_parser.add_argument(
        "-a",
        "--audit_name",
        default=None,
        help="name of audit plist and log - defaults to baseline name",
        action="store",
    )
    guidance_parser.add_argument(
        "-A",
        "--all",
        default=None,
        help="Generate Documentation and all support files",
        action="store_true",
    )
    guidance_parser.add_argument(
        "-m",
        "--markdown",
        default=None,
        help="Generate Documentation in markdown format",
        action="store_true",
    )

    mapping_parser: argparse.ArgumentParser = subparsers.add_parser(
        "mapping",
        help="Easily generate custom rules from compliance framework mappings",
        parents=[parent_parser],
        add_help=True,
    )
    mapping_parser.set_defaults(func=generate_mapping)
    mapping_parser.add_argument(
        "-c",
        "--csv",
        default=None,
        help="CSV to create custom rule files from a mapping",
        type=validate_file,
    )
    mapping_parser.add_argument(
        "-f",
        "--framework",
        default="800-53r5",
        help="Specify framework for the source. If no framework is specified, the default is 800-53r5.",
        action="store",
    )

    scap_parser: argparse.ArgumentParser = subparsers.add_parser(
        "scap",
        help="Easily generate xccdf, oval, or scap datastream. If no option is defined, it will generate an scap datastream file.",
        parents=[parent_parser],
        add_help=True,
    )
    # scap_parser.set_defaults(func=parser.print_help)
    scap_parser.add_argument(
        "-b",
        "--baseline",
        default=None,
        help="Baseline YAML file used to create the guide.",
        type=validate_file,
        action="store",
    )
    scap_parser.add_argument(
        "-x",
        "--xccdf",
        default=None,
        help="Generate an xccdf file.",
        action="store_true",
    )
    scap_parser.add_argument(
        "-o",
        "--oval",
        default=None,
        help="Generate an oval file of the checks.",
        action="store_true",
    )
    scap_parser.add_argument(
        "-l",
        "--list_tags",
        default=None,
        help="List the available keyword tags to search for.",
        action="store_true",
    )

    local_report_parser: argparse.ArgumentParser = subparsers.add_parser(
        "local_report",
        help="Creates local report in Excel format.",
        parents=[parent_parser],
        add_help=True,
    )
    local_report_parser.set_defaults(func=generate_local_report)
    local_report_parser.add_argument(
        "-p", "--plist", help="Plist input file", type=validate_file, action="store"
    )
    local_report_parser.add_argument(
        "-o",
        "--output",
        help="Location to output report to.",
        type=Path,
        action="store",
    )

    checklist_parser: argparse.ArgumentParser = subparsers.add_parser(
        "stig_checklist",
        help="Creates DISA STIG Checklist",
        parents=[parent_parser],
        add_help=True,
    )
    checklist_parser.set_defaults(func=generate_checklist)
    checklist_parser.add_argument(
        "-p", "--plist", help="Plist input file", type=validate_file, action="store"
    )

    checklist_parser.add_argument(
        "-d", "--disastig", help="DISA STIG File", type=validate_file, action="store"
    )

    checklist_parser.add_argument(
        "-j", "--json", help="Create JSON export", default=None, action="store_true"
    )

    checklist_parser.add_argument(
        "-b",
        "--baseline",
        help="Baseline YAML file used to create the guide.",
        type=validate_file,
        action="store",
    )

    checklist_parser.add_argument(
        "--checklist_version",
        help="STIG Checklist Version",
        default="3",
        action="store",
        choices=["2", "3"],
    )

    validate_parser: argparse.ArgumentParser = subparsers.add_parser(
        "validate",
        help="Validates the YAML files in the rules directory.",
        parents=[parent_parser],
        add_help=True,
    )
    validate_parser.set_defaults(func=validate_yaml_file)

    validate_parser.add_argument(
        "-i",
        "--only_invalid",
        help="Only show invalid files.",
        action="store_true",
    )

    language_parser: argparse.ArgumentParser = subparsers.add_parser(
        "language",
        help="List supported languages for localization.",
        parents=[parent_parser],
        add_help=True,
    )
    language_parser.set_defaults(func=generate_language)

    language_parser.add_argument(
        "baseline",
        default=None,
        help="Baseline YAML file used to create the guide.",
        type=validate_file,
    )
    language_parser.add_argument(
        "-c",
        "--custom",
        action="store_true",
        help="Load custom configurations (passed to Baseline.from_file)",
    )
    language_parser.add_argument(
        "-o",
        "--output",
        default="messages.pot",
        help="Output POT path (default: messages.pot)",
    )
    language_parser.add_argument(
        "-d",
        "--domain",
        default="messages",
        help="gettext domain (default: messages)",
    )

    try:
        args = parser.parse_args()

        logger = set_logger(args.verbose, args.quiet)

    except argparse.ArgumentError as e:
        logger.error("Argument Error: {}", e)
        parser.print_help()
        sys.exit()

    if not hasattr(args, "func"):
        logger.error("Functionality for {} is not implemented yet.", args.subcommand)
        parser.print_help()
        sys.exit()

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

    if args.os_name == "visionos":
        logger.warning("visionOS is not supported at this time.")
        sys.exit()

    if args.subcommand == "guidance":
        if args.os_name != "macos" and args.script:
            logger.error("Compliance script generation is only supported for macOS.")
            args.script = False

    args.func(args)


if __name__ == "__main__":
    logger.enable("mscp")

    raise SystemExit(parse_cli())
    # sys.exit(parse_cli())
