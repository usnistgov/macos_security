# mscp/admin_utils/rule_utilities.py
"""Interactive helpers for working with rule YAML files.

Currently provides `add_new_rule`, which scaffolds a placeholder rule
file under the configured custom rules directory.
"""

# Standard python modules
import argparse
from pathlib import Path

# Local python modules
from ..common_utils import (
    config,
    logger,
    sanitize_input,
)
from ..classes import Macsecurityrule


def add_new_rule(args: argparse.Namespace) -> None:
    """Scaffold a new placeholder rule YAML in the custom rules directory.

    Prompts for a title and unique rule ID, builds a minimal
    `Macsecurityrule` populated with placeholder values (mechanism
    ``"Configuration Profile"``, section ``"auditing"``, NIST references
    empty), and serialises it to
    ``<custom_rules_dir>/<rule_id>.yaml`` for the user to fill in.

    Args:
        args (argparse.Namespace): Parsed CLI arguments; only `os_name`
            is consumed (used for both `os_name` and `os_type` on the
            scaffolded rule).

    Side Effects:
        Writes a YAML file to disk and prompts on stdin via
        `sanitize_input`.
    """
    logger.info("Building new rule for MSCP...")

    build_path: Path = Path(config["custom"].get("rules_dir", ""))

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
