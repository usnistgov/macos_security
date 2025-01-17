# mscp/classes/baseline.py

# Standard python modules
import logging
import re

from pathlib import Path
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from collections import OrderedDict, defaultdict

# Additional python modules
import pandas as pd

# Local python modules
from src.mscp.classes.macsecurityrule import MacSecurityRule
from src.mscp.common_utils.file_handling import open_yaml, create_yaml
from src.mscp.common_utils.config import config

# Initialize logger
logger = logging.getLogger(__name__)


class Author(BaseModel):
    name: str
    organization: str


class Profile(BaseModel):
    section: str
    description: str
    rules: List[MacSecurityRule]

    def get(self, attr, default=None):
        return getattr(self, attr, default)


class Baseline(BaseModel):
    authors: List[Author]
    profile: List[Profile]
    name: str
    title: str = Field(default="")
    description: str = Field(default="")
    parent_values: str = ""


    @classmethod
    def from_yaml(cls, file_path: Path, os_name: str, os_version: int, custom: bool = False) -> "Baseline":
        """
        Load a Baseline object from a YAML file, including profiles and associated rules.

        Args:
            file_path (Path): Path to the baseline YAML file.
            custom (bool): Whether to load custom configurations.

        Returns:
            Baseline: A fully populated Baseline instance.
        """

        logger.info(f"Attempting to open Baseline file: {file_path}")

        section_dir: Path = Path(config["defaults"]["sections_dir"], os_name)
        if custom:
            section_dir = Path(config["custom"]["sections_dir"], os_name)

        baseline_data = open_yaml(file_path)
        authors = [Author(**author) for author in baseline_data.get("authors", [])]

        # Parse profiles
        profiles = []
        for prof in baseline_data.get("profile", []):
            section_data = open_yaml(Path(section_dir, f"{prof['section']}.yaml"))
            profiles.append(Profile(
                section=section_data.get("name", "").strip(),
                description=section_data.get("description", "").strip(),
                rules=MacSecurityRule.load_rules(prof.get("rules", []), os_name, os_version, baseline_data.get("parent_values", ""), section_data.get("name", "").strip(), custom)
            ))

        # Instantiate Baseline object
        baseline = cls(
            authors=authors,
            profile=profiles,
            name=file_path.stem,
            title=baseline_data.get("title", ""),
            description=baseline_data.get("description", ""),
            parent_values=baseline_data.get("parent_values", ""),
        )

        return baseline


    @classmethod
    def create_new(cls, output_file: Path, rules: List[MacSecurityRule], version_data: Dict[str, Any], baseline_name: str, benchmark: str, authors: List[Author], full_title: str) -> None:
        """
        Create and save a Baseline object as a YAML file with grouped and sorted rules.

        Args:
            output_file (Path): Path to save the baseline YAML file.
            rules (List[MacSecurityRule]): List of rules to include in the baseline.
            version_data (Dict[str, Any]): Version information, including OS and CPE.
            baseline_name (str): Name of the baseline.
            benchmark (str): Benchmark type (e.g., 'recommended').
            authors (List[Authors]): List of authors.
            full_title (str): Full title for the baseline.
        """
        os_name: str = re.search(r'(macos|ios|visionos)', version_data["cpe"], re.IGNORECASE).group()
        os_version: float = version_data["os"]
        baseline_title: str = f"{os_name} {os_version}: Security Configuration - {full_title} {baseline_name}"
        description: str = f"|\n  This guide describes the actions to take when securing a {os_name} {os_version} system against the {full_title} {baseline_name} security baseline.\n"

        if benchmark == "recommended":
            description += "\n  Information System Security Officers and benchmark creators can use this catalog of settings in order to assist them in security benchmark creation. This list is a catalog, not a checklist or benchmark, and satisfaction of every item is not likely to be possible or sensible in many operational scenarios."

        special_sections: dict = {
            "inherent": "Inherent",
            "permanent": "Permanent",
            "n_a": "Not Applicable",
            "supplemental": "Supplemental",
        }

        grouped_rules = defaultdict(list)
        section_descriptions: dict = {}

        for yaml_file in Path(config["defaults"]["section"]).glob("*.y*ml"):
            section_data: dict = open_yaml(yaml_file)

            section_descriptions[section_data.get("name")] = section_data.get("description", "")

        for rule in rules:
            matched: bool = False
            for tag, section_name in special_sections.items():
                if tag in rule.tags:
                    grouped_rules[section_name].append(rule)
                    matched = True
                    break

            if not matched:
                grouped_rules[rule.section].append(rule)

        for section in grouped_rules:
            grouped_rules[section] = sorted(grouped_rules[section], key=lambda r: r.rule_id)

        profiles = [
            Profile(
                section=section,
                description=section_descriptions.get(section, "No description available"),
                rules=grouped_rules[section],
            )
            for section in grouped_rules
        ]

        baseline = cls(
            authors=authors,
            profile=profiles,
            name=output_file.stem,
            title=baseline_title.strip(),
            description=description.strip(),
            parent_values=benchmark
        )

        baseline.to_yaml(output_path=output_file)

    def to_dataframe(self) -> pd.DataFrame:
        """
        Convert the profiles and rules from the Baseline object into a Pandas DataFrame.

        Returns:
            pd.DataFrame: A DataFrame containing rules with their associated profile sections.
        """

        rules =[]
        for profile in self.profile:
            for rule in profile.rules:
                rule_dict = dict(rule)
                rule_dict["section"] = profile.section
                rules.append(rule_dict)

        return pd.DataFrame(rules)


    def to_yaml(self, output_path: Path) -> None:
        serialized_data = self.model_dump()
        key_order: List[str] = ['title', 'description', 'authors', 'parent_values', 'profile']
        ordered_data = OrderedDict()

        for profile in serialized_data["profile"]:
            profile.pop("description", None)
            profile["rules"] = sorted([rule["rule_id"] for rule in profile["rules"]])

        for key in key_order:
            if key in serialized_data:
                ordered_data[key] = serialized_data[key]

        serialized_data = ordered_data

        create_yaml(output_path, serialized_data)

    def get(self, attr, default=None):
        return getattr(self, attr, default)
