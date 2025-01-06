# mscp/common_utils/collect_rules.py
import logging

from typing import List, Dict
from pathlib import Path

# from src.mscp.classes.baseline import Baseline
from src.mscp.classes.macsecurityrule import MacSecurityRule, Cis
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml
from src.mscp.common_utils.odv import fill_in_odv

logger = logging.getLogger(__name__)

def collect_all_rules() -> List[MacSecurityRule]:
    """
    Parse YAML files from the 'rules' and/or 'custom' directory and imports them as MacSecurityRule objects.

    Returns:
        List[MacSecurityRule]: List of parsed MacSecurityRule objects.
    """

    rules_list: List[MacSecurityRule] = []
    rules_dirs: List[Path] = [Path(config["defaults"]["rules_dir"]), Path(config["custom"]["rules_dir"])]
    rule_files: List[Path] = [file for rules_dir in rules_dirs
                              for file in rules_dir.rglob("*.y*ml")]

    for rule_file in rule_files:
        rule_yaml = open_yaml(rule_file)

        rules_list.append(
            MacSecurityRule(
                title=rule_yaml.get("title", "missing").replace('|', '\\|'),
                rule_id=rule_yaml.get("id", "missing").replace('|', '\\|'),
                severity=rule_yaml.get("severity", "missing").replace('|', '\\|'),
                discussion=rule_yaml.get("discussion", "missing").replace('|', '\\|'),
                check=rule_yaml.get("check", "missing").replace('|', '\\|'),
                fix=rule_yaml.get("fix", "missing").replace('|', '\\|'),
                cci=rule_yaml.get("references", {}).get("cci", None),
                cce=rule_yaml.get("references", {}).get("cce", None),
                nist_171=rule_yaml.get("references", {}).get("800-171r3", None),
                nist_controls=rule_yaml.get("references", {}).get("800-53r4", None),
                disa_stig=rule_yaml.get("references", {}).get("disa_stig", None),
                srg=rule_yaml.get("references", {}).get("srg", None),
                sfr=rule_yaml.get("references", {}).get("sfr", None),
                cis=rule_yaml.get("references", {}).get("cis", Cis(benchmark=None, controls_v8=None)),
                cmmc=rule_yaml.get("references", {}).get("cmmc", None),
                indigo=rule_yaml.get("references", {}).get("indigo", None),
                custom_refs=rule_yaml.get("custom_refs", None),
                odv=rule_yaml.get("odv", None),
                tags=rule_yaml.get("tags", None),
                result_value=rule_yaml.get("result", "missing"),
                mobileconfig=rule_yaml.get("mobileconfig", False),
                mobileconfig_info=rule_yaml.get("mobileconfig_info", {}),
                customized=rule_yaml.get("references", {}).get("customized", False)
            )
        )

    return rules_list

