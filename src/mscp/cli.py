# mscp/cli.py

# Standard python modules
import argparse
import sys
from pathlib import Path
from typing import Union

# Additional python modules
from loguru import logger

# Local python modules
from src.mscp.generate import (
    generate_baseline,
    generate_checklist,
    generate_guidance,
    generate_local_report,
    generate_mapping,
)

# from src.mscp.generate.baseline import generate_baseline
# from src.mscp.generate.checklist import generate_checklist
# from src.mscp.generate.guidance import generate_guidance
# from src.mscp.generate.local_report import generate_local_report
# from src.mscp.generate.mapping import generate_mapping
# from src.mscp.generate.scap import generate_scap


class CustomHelpFormatter(argparse.HelpFormatter):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def start_section(self, heading: str) -> None:
        heading = heading.upper()
        super().start_section(heading)

    def format_help(self) -> str:
        help_text = super().format_help()
        return f"\n{help_text}\n"

    def format_usage(self) -> str:
        usage_text = super().format_usage()
        return f"USAGE: {usage_text}"

    def format_description(self, description: str) -> str:
        if description:
            return f"{description}\n\n"
        else:
            return ""

    def format_epilog(self, epilog: str) -> str:
        if epilog:
            return f"\n{epilog}\n"
        else:
            return ""


def validate_file(arg: str) -> Union[Path, None]:
    if (file := Path(arg)).is_file():
        return file
    else:
        logger.error(f"File Not found: {arg}")
        sys.exit()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CLI tool for managing baseline and compliance documents.",
        formatter_class=CustomHelpFormatter,
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
        default=15,
        type=int,
        help="Operating system version (eg: 14, 15).",
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
    )
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
        "guidance", help="Given a baseline, create guidance documents and files."
    )
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
        "-d", "--debug", help=argparse.SUPPRESS, action="store_true"
    )
    guidance_parser.add_argument(
        "-D",
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

    mapping_parser: argparse.ArgumentParser = subparsers.add_parser(
        "mapping",
        help="Easily generate custom rules from compliance framework mappings",
    )
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
    )
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
        "local_report", help="Creates local report in Excel format."
    )
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
        "stig_checklist", help="Creates DISA STIG Checklist"
    )
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
        "-v",
        "--version",
        help="STIG Checklist Version",
        default="3",
        action="store",
        choices=["2", "3"],
    )

    args = parser.parse_args()

    match args.subcommand:
        case "guidance":
            logger.debug("CLI guidance entry")

            generate_guidance(args)
        case "baseline":
            logger.debug("CLI baseline entry")

            generate_baseline(args)
        case "mapping":
            logger.debug("CLI baseline entry")

            generate_mapping(args)
        case "scap":
            logger.debug("CLI SCAP entry")
            logger.error("SCAP generation is not implemented yet.")
            sys.exit()

            # generate_scap(args)
        case "local_report":
            logger.debug("CLI local_report entry")

            generate_local_report(args)
        case "stig_checklist":
            logger.debug("CLI stig_checklist entry")

            generate_checklist(args)
        case _:
            parser.print_help()


if __name__ == "__main__":
    main()
