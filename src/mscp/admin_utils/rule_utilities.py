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
from ..classes import Macsecurityrule


def add_new_rule(args: argparse.Namespace) -> None:
    """Add a new rule to the MSCP library."""
    logger.info("Building new rule for MSCP...")

    build_path: Path = Path(config["custom"].get("rules_dir", ""))

    all_rules: list[Macsecurityrule] = Macsecurityrule.collect_all_rules(
        args.os_name, args.os_version, tailoring=False, parent_values="Default"
    )
    rule_title: str = sanitize_input("Enter a title for the new rule: ")
    rule_id: str = sanitize_input("Enter a unique ID for the new rule: ")

    references = {"nist": {}}

    new_rule_dict = {
        "title": rule_title,
        "rule_id": rule_id,
        "discussion": "discuss all the things",
        "references": references,
        "mechanism": "Configuration Profile",
        "os_name": args.os_name,
        "os_type": args.os_name,
        "section": "auditing",
    }

    new_rule = Macsecurityrule(**new_rule_dict)

    rule_output_file: Path = build_path / f"{rule_id}.yaml"
    new_rule.to_yaml(rule_output_file)
