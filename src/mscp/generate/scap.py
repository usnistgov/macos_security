# mscp/generate/scap.py

# Standard python modules
import logging
import argparse
import sys

from pathlib import Path
from typing import Any
from datetime import datetime
from icecream import ic

# Additional python modules
from jinja2 import Environment, FileSystemLoader
from lxml import etree

# Local python modules
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml, make_dir, open_file, create_file
from src.mscp.common_utils.version_data import get_version_data
from src.mscp.classes.baseline import Baseline
from src.mscp.classes.macsecurityrule import MacSecurityRule
from src.mscp.common_utils.file_handling import open_file


# Initialize local logger
logger = logging.getLogger(__name__)


def set_reference(items: list[str]) -> str:
    """
    Convert a list of strings into a comma-separated string.

    Args:
        items (list[str]): The list of strings to be converted.

    Returns:
        str: A comma-separated string of the list items.
    """
    return ', '.join(items)


def lint_xml_file(file_path: Path) -> None:
    """
    Lint and pretty-print an XML file.
    This function reads an XML file from the given filepath, removes any
    unnecessary blank text, and then writes the pretty-printed XML back to
    the same file.
    Args:
        file_path (Path): The path to the XML file to be linted.
    Raises:
        Exception: If there is an error reading, parsing, or writing the XML file,
                   an exception will be logged.
    """

    try:
        xml_content = open_file(file_path)

        parser = etree.XMLParser(remove_blank_text=True)
        tree = etree.XML(xml_content, parser)
        pretty_xml = etree.tostring(tree, pretty_print=True, encoding='unicode')

        create_file(file_path, pretty_xml)

        logger.info(f"XML file {file_path} has been linted successfully.")
    except Exception as e:
        logger.error(f"Error linting XML file {file_path}: {e}")


def create_scap(output_path: Path, version_info: dict[str, Any], rules: list[MacSecurityRule], baselines: list[str], os_name: str, export_as: str) -> None:
    date_time: str = datetime.now().isoformat(timespec="seconds")
    os_type: str = ""
    env: Environment = Environment(loader=FileSystemLoader(config["defaults"]["scap_templates_dir"]), trim_blocks=True, lstrip_blocks=True)
    env.filters["set_reference"] = set_reference

    main_template = env.get_template('main.xml.jinja')

    match os_name:
        case "ios":
            os_type = "iOS/iPadOS"
        case 'visionos':
            os_type = "visionOS"
        case _:
            os_type = "macOS"

    rule_dict_list: list[dict] = [rule.to_dict() for rule in rules]

    rendered_output = main_template.render(
        date_time=date_time,
        guidance=version_info.get("version", ""),
        os_version=version_info.get("os", ""),
        cpe=version_info.get("cpe", ""),
        os_type=os_type,
        rules=rule_dict_list,
        baselines=baselines
    )


def generate_scap(args: argparse.Namespace) -> None:
    export_as: str = "scap"
    output_file: Path = Path(config["output_dir"])
    all_rules: list[MacSecurityRule] = []
    baselines: list[Baseline] = []
    seen_rules: set[str] = set()

    current_version_data: dict = get_version_data(args.os_name, args.os_version)

    if args.baseline:
        baselines = [Baseline.from_yaml(args.baseline, args.os_name, args.os_version)]
    else:
        baselines = Baseline.load_all_from_folder(Path(config["defaults"]["baseline_dir"]), args.os_name, args.os_version)

    for baseline in baselines:
        for profile in baseline.profile:
            for rule in profile.rules:
                if rule.rule_id not in seen_rules:
                    seen_rules.add(rule.rule_id)
                    all_rules.append(rule)

    all_tags: list[str] = MacSecurityRule.get_tags(all_rules)
    #! TODO remove the replace for production
    # all_baselines: list[str] = [args.baseline.stem.replace('_test', '')] if args.baseline else all_tags

    if args.list_tags:
        for tag in all_tags:
            print(tag)

        sys.exit()

    # all_rules_pruned: list[MacSecurityRule] = [
    #     rule for rule in all_rules if any(baseline in rule.tags for baseline in baselines)
    # ]

    odv_rules: list[MacSecurityRule] = [
        rule for rule in all_rules if rule.odv
    ]

    filenameversion = current_version_data['version'].split(", ", maxsplit=1)[-1].replace(" ", "_")
    base_filename: str = f"{args.os_name}_{current_version_data.get("os", None)}_Security_Compliance_Benchmark-{filenameversion}.xml"

    if args.oval:
        export_as = "oval"
        base_filename = base_filename.replace(".xml", "_oval.xml")

    if args.xccdf:
        export_as = "xccdf"
        base_filename = base_filename.replace(".xml", "_xccdf.xml")

    if ("ios" or "visionos") in args.os_name and args.oval:
        logger.error("OVAL generation is only avalilable for MacOS")
        sys.exit()

    if not (args.oval and args.xccdf) and args.os_name != "macos":
        export_as = "xccdf"
        base_filename = base_filename.replace(".xml", "_xccdf.xml")

        logger.info(f"{args.os_name} will only export as XCCDF")

    output_file = output_file / base_filename

    ic(f"Count of all rules: {len(all_rules)}")
    ic(f"Count of all baselines: {len(baselines)}")
    ic(f"Count of pruned rules: {len(all_rules)}")
    ic(f"Count of rules with ODV: {len(odv_rules)}")
    if len(odv_rules) != 0:
        ic(odv_rules[0].rule_id)
        ic(len(odv_rules[0].odv))
