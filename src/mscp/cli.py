# mscp/cli.py
"""Command-line interface for mSCP.

Defines `parse_cli`, the top-level entry point invoked from
`mscp.__main__`. Builds an `argparse` tree with subcommands
`baseline` / `guidance` / `mapping` / `scap` / `admin` (the
last with its own nested utilities) and dispatches to the matching
function in `mscp.generate` or `mscp.admin_utils`.
"""

# Standard python modules
import argparse
import json
import sys
import platform
from datetime import datetime
from pathlib import Path

# Local python modules
from .admin_utils import (
    build_all_baselines,
    add_new_rule,
    generate_mscp_banners,
    remove_mscp_apple_release,
    update_mscp_apple_release,
    update_mscp_release,
)
from .common_utils import (
    logger,
    set_logger,
    validate_yaml_file,
    get_supported_languages,
    mscp_data,
    config,
    ensure_custom_dirs,
    set_custom_dir,
    validate_rule_folder_structure,
)
from .generate import (
    generate_baseline,
    generate_guidance,
    generate_mapping,
    generate_scap,
    generate_localize_template,
    generate_mo_from_json,
)


class Customparser(argparse.ArgumentParser):
    """`argparse.ArgumentParser` that logs errors via `loguru`.

    Overrides `error` so usage failures are routed through the mSCP logger
    (instead of stderr) before the help text is printed and the process
    exits with status 2.
    """

    def error(self, message: str) -> None:
        """Log `message` via `loguru`, print help, and exit with status 2.

        Args:
            message (str): Error message reported by `argparse`.
        """
        logger.error(f"Argument Error: {message}")
        self.print_help()
        sys.exit(2)


class ListPlatformsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        fmt = "human"
        if "--format" in sys.argv:
            idx = sys.argv.index("--format")
            if idx + 1 < len(sys.argv):
                fmt = sys.argv[idx + 1]

        platforms = mscp_data.get("versions", {}).get("platforms", {})

        if fmt == "json":
            print(
                json.dumps(
                    {
                        name: sorted((e["os_version"] for e in versions), reverse=True)
                        for name, versions in platforms.items()
                    },
                    indent=2,
                )
            )
        else:
            platform_versions = {
                name: sorted((e["os_version"] for e in versions), reverse=True)
                for name, versions in platforms.items()
            }
            col_width = max(len(name) for name in platform_versions) + 4
            max_rows = max(len(v) for v in platform_versions.values())

            print("Supported platforms (--os_name) and versions (--os_version):\n")
            print("  " + "".join(name.ljust(col_width) for name in platform_versions))
            print(
                "  "
                + "".join(
                    ("-" * len(name)).ljust(col_width) for name in platform_versions
                )
            )
            for i in range(max_rows):
                print(
                    "  "
                    + "".join(
                        (str(v[i]) if i < len(v) else "").ljust(col_width)
                        for v in platform_versions.values()
                    )
                )
            print()
        parser.exit()


class SmartFormatter(argparse.HelpFormatter):
    """Help formatter with two minor tweaks for the mSCP CLI.

    - Single-letter / single-form options are indented to align with the
      long-form options for readability.
    - Help strings prefixed with `"R|"` are emitted with their original
      newlines preserved (a common `argparse` recipe for raw text).
    """

    def _format_action_invocation(self, action):
        # Get the default invocation (e.g., "-p PROFILE", "--profile PROFILE")
        invocation = super()._format_action_invocation(action)

        # action.option_strings contains all flag names: ["-p", "--profile"]
        if len(action.option_strings) == 1:
            # Add indentation for single-option flags
            invocation = "    " + invocation

        return invocation

    def _split_lines(self, text, width):
        if text.startswith("R|"):
            return text[2:].strip().splitlines()
        # this is the RawTextHelpFormatter._split_lines
        return argparse.HelpFormatter._split_lines(self, text, width)


def get_macos_version() -> float:
    """Return the running host's major macOS version as a float.

    Used as the default for the `--os_version` flag so the CLI assumes
    the current host's version unless overridden. Falls back to `27.0`
    when `platform.mac_ver` returns an empty string (e.g. when run on a
    non-macOS host).

    Returns:
        float: Major version (e.g. `15.0`), or `27.0` on a non-macOS host.
    """
    version_str, _, _ = platform.mac_ver()
    if version_str:
        major = int(version_str.split(".")[0])
        return float(major)
    else:
        return 27.0


def validate_file(arg: str) -> Path | None:
    """`argparse` type validator: ensure `arg` points at an existing file.

    Used as the `type=` argument on flags that take a path. Logs an
    error and calls `sys.exit` if the path doesn't resolve to a file.

    Args:
        arg (str): Raw command-line argument value.

    Returns:
        Path | None: The validated `Path`, or never returns when the file
            is missing (process exits).
    """
    if (file := Path(arg)).is_file():
        return file
    else:
        logger.error(f"File Not found: {arg}")
        sys.exit()


def valid_date(date_str):
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        return date_str
    except ValueError:
        raise argparse.ArgumentTypeError("Date must be in MM-DD-YYYY format")


def parse_cli() -> None:
    """Build the mSCP argument parser, parse `sys.argv`, and dispatch.

    Constructs the top-level parser plus the `baseline`, `guidance`,
    `mapping`, `scap`, and `admin` subcommands (each with its own
    flags), applies log-verbosity overrides, validates the platform/OS
    arguments (rejects unsupported macOS / iOS versions), and then calls
    the subcommand's bound `func` with the parsed `argparse.Namespace`.

    Note:
        Reads `sys.argv`; configures the global mSCP logger; mutates the
        global `config` dict for `output_dir` / `rules_dir`; may call
        `sys.exit` on validation failure.
    """
    parent_parser = Customparser()
    parent_parser.add_argument(
        "-D",
        "--debug",
        required=False,
        help=argparse.SUPPRESS,
        action="store_true",
    )

    parent_parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase the amount of logging to stdout (-v, -vv)",
    )

    parser = Customparser(
        description="command-line interface for generating baseline and compliance documents for the macOS Security Compliance Project",
        prog="mscp",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        parents=[parent_parser],
        add_help=False,
    )

    _v = mscp_data.get("mscp", {})
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {_v.get('version', 'unknown')} (build {_v.get('build', '?')}, {_v.get('build_date', 'unknown')})",
    )

    parser.add_argument(
        "--list_platforms",
        nargs=0,
        action=ListPlatformsAction,
        help="list all supported platforms and versions",
    )

    parser.add_argument(
        "--format",
        choices=["human", "json"],
        default="human",
        help="output format for --list_platforms",
    )

    parser.add_argument(
        "--os_name",
        choices=mscp_data.get("versions", {}).get("platforms", {}),
        default="macos",
        help="operating system to be referenced when generating guidance",
        type=str,
    )

    parser.add_argument(
        "--os_version",
        default=get_macos_version(),
        type=float,
        help="version of the operating system to be referenced when generating guidance (eg: 14.0, 15.0).",
    )

    parser.add_argument(
        "-C",
        "--custom_dir",
        default=config["custom_dir"],
        type=Path,
        metavar="PATH",
        help="Path to custom directory.",
    )

    parser.add_argument(
        "-R",
        "--rules_dir",
        default=config["rules_dir"],
        type=validate_rule_folder_structure,
        help="Path to directory containing the library of rule files.",
    )

    parser.add_argument(
        "-o",
        "--output_dir",
        default=config["output_dir"],
        type=Path,
        metavar="PATH",
        help="Path to output directory.",
    )

    # Sub Parsers for individual commands
    subparsers = parser.add_subparsers(
        title="Generate commands",
        required=True,
        dest="subcommand",
        metavar="{baseline,guidance,mapping,scap}",
    )

    # 'baseline' subcommand
    baseline_parser: argparse.ArgumentParser = subparsers.add_parser(
        "baseline",
        help="generate a baseline YAML file containing rules associated with the provided keyword/tag",
        parents=[parent_parser],
        add_help=False,
    )
    baseline_parser.set_defaults(func=generate_baseline)

    baseline_parser.add_argument(
        "-b",
        "--baseline",
        type=validate_file,
        help=argparse.SUPPRESS,
        # help="when tailoring, if you provide a baseline.yaml file, it will only prompt for rules not already included",
        action="store",
    )

    baseline_parser.add_argument(
        "-c",
        "--controls",
        help=argparse.SUPPRESS,
        action="store_true",
    )
    baseline_parser.add_argument(
        "-k",
        "--keyword",
        help="keyword to be used to collect associated rules",
        action="store",
    )
    baseline_parser.add_argument(
        "-l",
        "--list_tags",
        help="list the available keywords that can be used to generate a baseline YAML file",
        action="store_true",
    )
    baseline_parser.add_argument(
        "-m",
        "--migrate",
        type=validate_file,
        metavar="LEGACY_BASELINE",
        help="migrate a legacy (pre-2.0) baseline YAML to the current format",
        action="store",
    )
    baseline_parser.add_argument(
        "-t",
        "--tailor",
        help="create a customized baseline that is based on your organization's requirements",
        action="store_true",
    )

    # 'guidance' subcommand
    guidance_parser: argparse.ArgumentParser = subparsers.add_parser(
        "guidance",
        help="given a baseline YAML files, create guidance documents and supporting files",
        parents=[parent_parser],
        formatter_class=SmartFormatter,
        add_help=False,
    )
    guidance_parser.set_defaults(func=generate_guidance)
    guidance_parser.add_argument(
        "baseline",
        default=None,
        help="""R|baseline YAML file used to create the guidance documents
baseline files are generated by the `mscp.py baseline` command""",
        type=validate_file,
    )
    guidance_parser.add_argument(
        "-A",
        "--all",
        default=None,
        help="generate documentation and all support files for the rules in the specified baseline",
        action="store_true",
    )
    guidance_parser.add_argument(
        "-d",
        "--ddm",
        help="generate declarative management artifacts (if applicable) for the rules in the specified baseline",
        action="store_true",
    )
    guidance_parser.add_argument(
        "-l",
        "--logo",
        default=None,
        help="full path to logo file to be included in the PDF and HTML guide",
        action="store",
        type=validate_file,
    )
    guidance_parser.add_argument(
        "-L",
        "--language",
        default="en",
        help="generate guidance using a supported language",
        action="store",
        choices=get_supported_languages(),
    )
    guidance_parser.add_argument(
        "-M",
        "--manifest",
        default=None,
        help="generate a JSON manifest file for the rules in the specified baseline",
        action="store_true",
    )
    guidance_parser.add_argument(
        "-m",
        "--markdown",
        default=None,
        help="generate documentation in markdown format",
        action="store_true",
    )
    guidance_parser.add_argument(
        "--markdown-tree",
        help="""R|generate documentation as a paginated Markdown directory tree
(one page per rule, NN- ordered filenames, index.md per section)
ready to use with Docusaurus, Starlight, MkDocs, or VitePress""",
        action="store_true",
    )
    guidance_parser.add_argument(
        "-p",
        "--profiles",
        help="generate configuration profiles for the rules in the specified baseline",
        action="store_true",
    )
    guidance_parser.add_argument(
        "--consolidated-profile",
        default=False,
        help="include a single consolidated configuration profile when generating profiles",
        action="store_true",
    )
    guidance_parser.add_argument(
        "--granular-profiles",
        default=False,
        help="include granular per-setting configuration profiles when generating profiles",
        action="store_true",
    )
    hash_help = (
        "(macOS ONLY) sign the configuration profiles with subject key ID (hash value without spaces)"
        if sys.platform.startswith("darwin")
        else argparse.SUPPRESS
    )
    guidance_parser.add_argument(
        "-H",
        "--hash",
        default=None,
        help=hash_help,
        action="store",
    )

    guidance_parser.add_argument(
        "-s",
        "--script",
        help="generate the compliance script for the rules in the specified baseline",
        action="store_true",
    )

    guidance_parser.add_argument(
        "--audit_name",
        default=None,
        help="specify the name of audit plist and log (defaults to baseline name)",
        action="store",
    )

    guidance_parser.add_argument(
        "--reference",
        default=None,
        help="""R|use the reference ID instead of rule ID for logging in the generated
compliance script (e.g. disa_stig, cis.benchmark)
        """,
        action="store",
    )
    # add gary argument to include tags for XCCDF generation, with a nod to Gary the SCAP guru
    guidance_parser.add_argument(
        "-g", "--gary", help=argparse.SUPPRESS, action="store_true"
    )
    guidance_parser.add_argument(
        "--dark",
        default=False,
        help=argparse.SUPPRESS,
        action="store_true",
    )

    guidance_parser.add_argument(
        "-x",
        "--xlsx",
        help="generate an excel file for the rules in the specified baseline",
        action="store_true",
    )

    guidance_parser.add_argument(
        "--no-docs",
        dest="no_docs",
        default=False,
        help="skip generating the asciidoctor, PDF, and HTML documents",
        action="store_true",
    )

    mapping_parser: argparse.ArgumentParser = subparsers.add_parser(
        "mapping",
        help="generate custom rules from compliance framework mappings",
        parents=[parent_parser],
        add_help=False,
    )
    mapping_parser.set_defaults(func=generate_mapping)
    mapping_parser.add_argument(
        "-c",
        "--csv",
        default=None,
        required=True,
        help="the source CSV used to create custom rule files from a mapping",
        type=validate_file,
    )
    mapping_parser.add_argument(
        "-f",
        "--framework",
        default="800-53r5",
        help="specify the source framework to map against, value must exist in a column header of the CSV (default is 800-53r5)",
        action="store",
    )
    scap_parser: argparse.ArgumentParser = subparsers.add_parser(
        "scap",
        help="generate xccdf, oval, or scap datastream",
        parents=[parent_parser],
        formatter_class=SmartFormatter,
        add_help=False,
    )
    scap_parser.set_defaults(func=generate_scap)
    scap_parser.add_argument(
        "-b",
        "--baseline",
        default="all_rules",
        help="baseline keyword to generate an SCAP content file for (default: all_rules)",
        action="store",
    )
    scap_parser.add_argument(
        "-x",
        "--xccdf",
        default=None,
        help="generate an xccdf file containing the data from the rules",
        action="store_true",
    )
    scap_parser.add_argument(
        "-o",
        "--oval",
        default=None,
        help="generate an oval file containing the checks used by the rules",
        action="store_true",
    )
    scap_parser.add_argument(
        "-l",
        "--list_tags",
        default=None,
        help="list the available keywords that can be used to generate the SCAP content from",
        action="store_true",
    )
    scap_parser.add_argument(
        "--disa_stig",
        default=None,
        help="supply path DISA STIG XCCDF file to generate an OVAL file replacing the title with SRG and Vuln IDs from the DISA STIG",
        type=validate_file,
    )

    # local_report_parser: argparse.ArgumentParser = subparsers.add_parser(
    #     "local_report",
    #     help="Creates local report in Excel format.",
    #     parents=[parent_parser],
    #     add_help=False,
    # )
    # local_report_parser.set_defaults(func=generate_local_report)
    # local_report_parser.add_argument(
    #     "-p", "--plist", help="Plist input file", type=validate_file, action="store"
    # )
    # local_report_parser.add_argument(
    #     "-o",
    #     "--output",
    #     help="Location to output report to.",
    #     type=Path,
    #     action="store",
    # )

    # checklist_parser: argparse.ArgumentParser = subparsers.add_parser(
    #     "stig_checklist",
    #     help="Creates DISA STIG Checklist",
    #     parents=[parent_parser],
    #     add_help=False,
    # )
    # checklist_parser.set_defaults(func=generate_checklist)
    # checklist_parser.add_argument(
    #     "-p", "--plist", help="Plist input file", type=validate_file, action="store"
    # )

    # checklist_parser.add_argument(
    #     "-d", "--disastig", help="DISA STIG File", type=validate_file, action="store"
    # )

    # checklist_parser.add_argument(
    #     "-j", "--json", help="Create JSON export", default=None, action="store_true"
    # )

    # checklist_parser.add_argument(
    #     "-b",
    #     "--baseline",
    #     help="Baseline YAML file used to create the guide.",
    #     type=validate_file,
    #     action="store",
    # )

    # checklist_parser.add_argument(
    #     "-V",
    #     "--checklist_version",
    #     help="STIG Checklist Version",
    #     default="3",
    #     action="store",
    #     choices=["2", "3"],
    # )

    admin_parser: argparse.ArgumentParser = subparsers.add_parser(
        "admin",
        parents=[parent_parser],
        add_help=False,
    )

    admin_subparsers = admin_parser.add_subparsers(
        title="Admin Utilities",
        required=True,
        dest="admin_command",
    )

    build_all_parser = admin_subparsers.add_parser(
        "baselines",
        parents=[parent_parser],
        help="build all baselines supported in MSCP",
        add_help=False,
    )
    build_all_parser.set_defaults(func=build_all_baselines)

    add_rule_parser = admin_subparsers.add_parser(
        "create",
        parents=[parent_parser],
        help="create a new rule for the MSCP library",
        add_help=False,
    )
    add_rule_parser.set_defaults(func=add_new_rule)

    generate_banners_parser = admin_subparsers.add_parser(
        "banners",
        parents=[parent_parser],
        help="generate MSCP banners with the updated color scheme for use in documentation and other collateral",
        add_help=False,
    )
    generate_banners_parser.set_defaults(func=generate_mscp_banners)

    update_apple_release_parser = admin_subparsers.add_parser(
        "update",
        parents=[parent_parser],
        help="update rule library with platform placeholders for new Apple release",
        add_help=False,
    )
    update_apple_release_parser.set_defaults(func=update_mscp_apple_release)

    update_apple_release_parser.add_argument(
        "--version",
        help="version number of Apple release to add to MSCP",
        type=float,
        required=True,
        action="store",
    )

    update_apple_release_parser.add_argument(
        "--new_name",
        help="name of macOS from Apple release to add to MSCP",
        type=str,
        required=True,
        action="store",
    )

    remove_apple_release_parser = admin_subparsers.add_parser(
        "remove",
        parents=[parent_parser],
        help="remove a platform version from the rule library, mscp_data, and schema",
        add_help=False,
    )
    remove_apple_release_parser.set_defaults(func=remove_mscp_apple_release)

    remove_apple_release_parser.add_argument(
        "--version",
        help="version number of Apple release to remove from MSCP",
        type=float,
        required=True,
        action="store",
    )

    update_mscp_release_parser = admin_subparsers.add_parser(
        "release",
        parents=[parent_parser],
        help="update MSCP for new release",
        add_help=False,
    )
    update_mscp_release_parser.set_defaults(func=update_mscp_release)

    update_mscp_release_parser.add_argument(
        "--release_date",
        help="date to be used for release (YYYY-MM-DD)",
        type=valid_date,
        required=True,
        action="store",
    )
    update_mscp_release_parser.add_argument(
        "--major",
        help="update major version",
        action="store_true",
    )
    update_mscp_release_parser.add_argument(
        "--minor",
        help="update minor version",
        action="store_true",
    )

    validate_parser: argparse.ArgumentParser = admin_subparsers.add_parser(
        "validate",
        help="validates the YAML files against the mscp_rule.json schema found in the rules and custom directories",
        parents=[parent_parser],
        add_help=False,
    )
    validate_parser.set_defaults(func=validate_yaml_file)

    validate_parser.add_argument(
        "--all_validation",
        help="show all validation output",
        action="store_true",
    )
    localize_template_parser: argparse.ArgumentParser = admin_subparsers.add_parser(
        "translation-json",
        help="generate translation template file for localization",
        parents=[parent_parser],
        add_help=False,
    )
    localize_template_parser.set_defaults(func=generate_localize_template)

    localize_template_parser.add_argument(
        "-o",
        "--output",
        default="messages.json",
        help="output JSON path (default: messages.json)",
    )
    localize_template_parser.add_argument(
        "-d",
        "--domain",
        default="messages",
        help="specify the gettext domain (default: messages)",
    )

    mo_from_json_parser: argparse.ArgumentParser = admin_subparsers.add_parser(
        "mo-from-json",
        help="generate a MO file from translated .json for localization",
        parents=[parent_parser],
        add_help=False,
    )
    mo_from_json_parser.set_defaults(func=generate_mo_from_json)

    mo_from_json_parser.add_argument(
        "json_file",
        default=None,
        help="file (.json) containing translations to convert",
        type=validate_file,
    )
    mo_from_json_parser.add_argument(
        "-m",
        "--mo_file",
        default="messages.mo",
        help="output MO file (default: messages.mo)",
    )

    mo_from_json_parser.add_argument(
        "-l",
        "--locale",
        default=None,
        required=True,
        help="Locale of translations in provided .json file.",
    )
    mo_from_json_parser.add_argument(
        "-d",
        "--domain",
        default="messages",
        help="gettext domain (default: messages)",
    )
    mo_from_json_parser.add_argument(
        "-f",
        "--use_fuzzy",
        action="store_true",
        help="Enable the flag for fuzzy matches in translations.",
    )
    _pre, _ = parent_parser.parse_known_args()
    set_logger(
        debug=getattr(_pre, "debug", False), verbosity=getattr(_pre, "verbose", 0)
    )
    try:
        args = parser.parse_args()

        logger = set_logger(verbosity=args.verbose)

        if args.output_dir:
            config["output_dir"] = str(args.output_dir.expanduser().resolve())
        if args.custom_dir:
            set_custom_dir(args.custom_dir.expanduser().resolve())
        ensure_custom_dirs()
    except argparse.ArgumentError as e:
        logger.error("Argument Error: {}", e)
        parser.print_help()
        sys.exit()

    if args.debug:
        logger = set_logger(debug=True)
        logger.info("=== Logging level changed ===")
        logger.info("LOGGING LEVEL: DEBUG")
    else:
        logger.info("=== Logging level changed ===")
        logger.debug("LOGGING LEVEL: CRITICAL")

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

    if not args.rules_dir == config["rules_dir"]:
        config["rules_dir"] = args.rules_dir

    if args.subcommand == "guidance":
        if args.os_name != "macos" and args.script:
            logger.error(
                "Compliance script generation is only supported for macOS. Please remove the --script flag."
            )
            sys.exit()

        # if generating consolidated profile, assume to do all profiles
        if args.consolidated_profile or args.granular_profiles:
            args.profiles = True

    if args.subcommand == "baseline":
        if len(sys.argv) == 2:
            baseline_parser.print_help()
            sys.exit()
        if not args.migrate and not args.keyword and not args.list_tags:
            logger.error("One of --keyword, --list_tags, or --migrate is required.")
            baseline_parser.print_help()
            sys.exit(1)

    args.func(args)
