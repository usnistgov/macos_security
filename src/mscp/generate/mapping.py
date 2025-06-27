# mscp/generate/mapping.py

# Standard python modules
import argparse
import re
import sys
from pathlib import Path
from typing import Any

# Local python modules
from ..classes import Author, Baseline, Macsecurityrule
from ..common_utils import config, get_version_data, make_dir, open_file
from ..common_utils.logger_instance import logger

# Additional python modules


def update_rule_with_custom_controls(
    rule: Macsecurityrule, controls: list[str], header: str
) -> None:
    """
    Update a rule with custom controls and add references.

    Args:
        rule (Macsecurityrule): The rule to update.
        controls (List[str]): The controls to add.
        header (str): The header to map controls against.
    """

    if not rule.references.custom_refs:
        rule.references["custom_refs"] = {}

    rule.references["custom_refs"][header] = controls
    logger.info(f"Updated rule {rule.rule_id} with controls: {controls}")


def generate_mapping(args: argparse.Namespace) -> None:
    current_version_data: dict[str, Any] = get_version_data(
        args.os_name, args.os_version
    )

    rules: list[Macsecurityrule] = Macsecurityrule.collect_all_rules(
        args.os_name, args.os_version
    )
    custom_rules: list[Macsecurityrule] = []

    csv_data: dict[str, Any] = open_file(args.csv)

    if len(csv_data.keys()) < 2:
        logger.error("The CSV File can only contain 2 headers.")
        sys.exit()

    other_header, framework_header = csv_data.keys()

    if args.framework not in framework_header:
        logger.error(f"{args.framework} not found in csv file.")
        sys.exit()

    baseline_name: str = other_header.replace(" ", "_").lower()
    output_dir: Path = Path(config["output_dir"], other_header.lower())
    baseline_file_path: Path = output_dir / "baseline" / f"{baseline_name}.yaml"

    if not output_dir.exists():
        make_dir(output_dir)

    for rule in rules:
        rule_file_path: Path = output_dir / "rules" / f"{rule.rule_id}.yaml"
        control_list: list = []

        if any(tag in rule.tags for tag in ["supplemental", "srg"]):
            continue

        for row in csv_data.values():
            if "N/A" in row.get(args.framework):
                continue

            controls: list[str] = [
                control.strip() for control in row[args.framework].split(",")
            ]
            references: list = []

            match args.framework:
                case var if re.search(r"/", var):
                    framework_main, framework_sub = (
                        args.framework.split("/", 1) + [None][:2]
                    )

                    if rule.customized:
                        references = (
                            rule.references.get("custom_refs", {})
                            .get(framework_main, {})
                            .get(framework_sub, [])
                        )
                    else:
                        references = rule.references.get(framework_main, {}).get(
                            framework_sub, []
                        )
                case _:
                    references = rule.references.get(args.framework, [])

            for control in controls:
                if control in references and control not in control_list:
                    control_list.append(control)
                    row_array = [item.strip() for item in row[other_header].split(",")]

                    for item in row_array:
                        logger.info(
                            f"{rule.rule_id} - {args.framework} {control} maps to {other_header} {item}"
                        )

        if not control_list:
            logger.debug(f"No controls matched for rule {rule.rule_id}")
            continue

        update_rule_with_custom_controls(rule, control_list, other_header)

        if not rule.customized:
            rule.customized = True

        rule.tags.append(other_header)

        rule.to_yaml(rule_file_path)

        custom_rules.append(rule)

    baseline_title: str = (
        f"{args.os_name} {args.os_version}: Security Configuration - {args.framework}"
    )

    Baseline.create_new(
        baseline_file_path,
        custom_rules,
        current_version_data,
        baseline_name,
        [Author(name=None, organization=None)],
        baseline_title,
    )
