# mscp/generate/mapping.py

# Standard python modules
import argparse
import sys
import time
from pathlib import Path
from typing import Any

# Local python modules
from ..classes import Author, Baseline, Macsecurityrule
from ..common_utils import config, make_dir, open_file
from ..common_utils.logger_instance import logger

# Additional python modules
from yaspin import inject_spinner
from yaspin.core import Yaspin
from yaspin.spinners import Spinners


def update_rule_with_custom_references(
    rule: Macsecurityrule, references: list[str], reference_source: str
) -> None:
    """
    Update a rule with custom references.

    Args:
        rule (Macsecurityrule): The rule to update.
        references (List[str]): The references to add.
        reference_source (str): The reference source to map references to.
    """

    rule.references[reference_source] = references

    logger.info(f"Updated rule {rule.rule_id} with references: {references}")


@inject_spinner()
def generate_mapping(sp: Yaspin, args: argparse.Namespace) -> None:
    sp.spinner = Spinners.dots
    sp.text = "Collecting rule files"
    time.sleep(1)
    rules: list[Macsecurityrule] = Macsecurityrule.collect_all_rules(
        args.os_name, args.os_version, tailoring=True
    )

    csv_data: dict[str, Any] = open_file(args.csv)

    if args.framework not in csv_data.keys():
        logger.error(f"{args.framework} not found in csv header row.")
        sys.exit()

    for other_header in csv_data:
        custom_rules: list[Macsecurityrule] = []

        if other_header == args.framework:
            continue

        build_path: Path = Path(config["custom"].get("baseline_dir", ""))

        baseline_name: str = other_header.replace(" ", "_").lower()
        output_dir: Path = Path(config["output_dir"], other_header.lower())
        rules_output_dir: Path = output_dir / "rules"
        baseline_file_path: Path = (
            build_path / f"{baseline_name}_{args.os_name}_{args.os_version}.yaml"
        )

        for dir_path in [output_dir, build_path, rules_output_dir]:
            make_dir(dir_path)

        sp.text = "Mapping references and creating customized rule files"
        time.sleep(1)
        for rule in rules:
            rule_file_path: Path = output_dir / "rules" / f"{rule.rule_id}.yaml"
            control_list: list = []
            mapped_control_list: list = []

            for row, _ in enumerate(csv_data[other_header]):
                if "N/A" in csv_data[args.framework][row]:
                    continue

                if not csv_data[other_header][row]:
                    continue

                controls: list[str] = [
                    control.strip()
                    for control in csv_data[args.framework][row].split(",")
                ]
                references: list = []
                try:
                    references = rule.references.get_ref(args.framework)
                except KeyError as e:
                    logger.error(e)

                for control in controls:
                    if control in references and control not in control_list:
                        control_list.append(control)
                        row_array = [
                            item.strip()
                            for item in csv_data[other_header][row].split(",")
                        ]
                        for item in row_array:
                            logger.info(
                                f"{rule.rule_id} - {args.framework} {control} maps to {other_header} {item}"
                            )
                            if item not in mapped_control_list:
                                mapped_control_list.append(item)

            if not control_list:
                logger.debug(f"No controls matched for rule {rule.rule_id}")
                continue

            update_rule_with_custom_references(rule, mapped_control_list, other_header)

            rule.tags.append(other_header)

            rule.to_yaml(rule_file_path)

            # remove added reference for additional framework processing
            delattr(rule.references, other_header)

            custom_rules.append(rule)

        baseline_title: str = f"{args.os_name} {args.os_version}: Security Configuration - {args.framework}"

        sp.text = "Generating custom baseline for mapped rules"
        time.sleep(1)
        Baseline.create_new(
            output_file=baseline_file_path,
            rules=custom_rules,
            baseline_name=baseline_name,
            benchmark="recommended",
            authors=[Author(name="", organization="")],
            full_title=baseline_title,
            os_type=args.os_name,
            os_version=args.os_version,
            baseline_dict={},
        )

        sp.text = f"DONE!"
        sp.ok("✔")

        print(f"Generated new baseline file: {baseline_file_path}")
        print(f"Generated customized rule files: {rules_output_dir}")
