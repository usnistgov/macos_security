# macsecurityrule.py

# Standard python modules
import logging
import sys

from dataclasses import dataclass
from typing import List, Dict, Any
from pathlib import Path

# Local python modules
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml
from src.mscp.common_utils.odv import fill_in_odv

# Initialize logger
logger = logging.getLogger(__name__)

@dataclass
class Cis:
    benchmark: List[str] | None
    controls_v8: List[float] | None


@dataclass(slots=True)
class MacSecurityRule:
    title: str
    rule_id: str
    severity: str
    discussion: str
    check: str
    fix: str
    cci: List[str]
    cce: List[str]
    nist_controls: List[str]
    nist_171: List[str]
    disa_stig: List[str]
    srg: List[str]
    sfr: List[str]
    cis: Cis
    cmmc: List[str]
    indigo: List[str]
    custom_refs: List[str]
    odv: List[str]
    tags: List[str]
    result: Any
    result_value: str
    mobileconfig: bool
    mobileconfig_info: dict
    ddm_info: dict
    customized: bool
    mechanism: str = ""
    section: str = ""

    @classmethod
    def load_rules(cls, rule_ids: List[str], os_name: str, os_version: int, parent_values: str, section: str, custom: bool = False) -> List["MacSecurityRule"]:
        """
        Load MacSecurityRule objects from YAML files for the given rule IDs.

        Args:
            rule_ids (List[str]): List of rule IDs to load.
            parent_values (str): Parent values to apply when filling in ODV.
            is_custom (bool): Whether to include custom rules.

        Returns:
            List[MacSecurityRule]: A list of loaded MacSecurityRule objects.
        """

        rules_dir: List[Path] = []
        rules = []

        if custom:
            rules_dirs = [
                Path(config["custom"]["rules_dir"], os_name, f"{os_version}"),
                Path(config["defaults"]["rules_dir"], os_name, f"{os_version}")
            ]
        else:
            rules_dirs = [Path(config["defaults"]["rules_dir"], os_name, f"{os_version}")]

        for rule_id in rule_ids:
            rule_file = next((file for rules_dir in rules_dirs if rules_dir.exists()
                              for file in rules_dir.rglob(f"{rule_id}.y*ml")), None)
            if not rule_file:
                logger.warning(f"Rule file not found for rule: {rule_id}")
                continue

            rule_yaml: dict = open_yaml(rule_file)
            fill_in_odv(rule_yaml, parent_values)

            result = rule_yaml.get("result", "N/A")

            if isinstance(result, dict):
                for result_type in ["integer", "boolean", "string", "base64"]:
                    if result_type in result:
                        result_value = result[result_type]
                        break
                else:
                    result_value = "N/A"
            else:
                result_value = result

            mechanism = "Manual"
            if "[source,bash]" in rule_yaml["fix"]:
                mechanism = "Script"
            if "This is implemented by a Configuration Profile." in rule_yaml["fix"]:
                mechanism = "Configuration Profile"

            match rule_yaml["tags"]:
                case "inherent":
                    mechanism = "The control cannot be configured out of compliance."
                case "permanent":
                    mechanism = "The control is not able to be configured to meet the requirement. It is recommended to implement a third-party solution to meet the control."
                case "not_applicable":
                    mechanism = "The control is not applicable when configuring a macOS system."

            rules.append(cls(
                title=rule_yaml.get("title", "missing").replace('|', '\\|'),
                rule_id=rule_yaml.get("id", "missing").replace('|', '\\|'),
                severity=rule_yaml.get("severity", None),
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
                result=rule_yaml.get("result", {}),
                result_value=result_value,
                mobileconfig=rule_yaml.get("mobileconfig", False),
                mobileconfig_info=rule_yaml.get("mobileconfig_info", {}),
                customized=rule_yaml.get("references", {}).get("customized", False),
                section=section,
                mechanism=mechanism,
                ddm_info=rule_yaml.get("ddm_info", {})
            ))

        return rules

    def get(self, attr, default=None):
        return getattr(self, attr, default)
