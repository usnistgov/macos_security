# mscp/classes/baseline.py

# Standard python modules
import logging

from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any

# Additional python modules
import pandas as pd

# Local python modules
from src.mscp.classes.macsecurityrule import MacSecurityRule
from src.mscp.common_utils.file_handling import open_yaml
from src.mscp.common_utils.config import config

# Initialize logger
logger = logging.getLogger(__name__)

@dataclass
class Authors:
    name: str
    organization: str

@dataclass
class Profile:
    section: str
    description: str
    rules: List[MacSecurityRule]

@dataclass
class Baseline:
    authors: List[Authors]
    profile: List[Profile]
    name: str
    title: str = field(default="")
    description: str = field(default="")
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
        authors = [Authors(**author) for author in baseline_data.get("authors", [])]

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


    def to_dataframe(self) -> pd.DataFrame:
        """
        Convert the profiles and rules from the Baseline object into a Pandas DataFrame.

        Returns:
            pd.DataFrame: A DataFrame containing rules with their associated profile sections.
        """

        rules =[]
        for profile in self.profile:
            for rule in profile.rules:
                rule_dict = asdict(rule)
                rule_dict["section"] = profile.section
                rules.append(rule_dict)

        return pd.DataFrame(rules)


    def get(self, attr, default=None):
        return getattr(self, attr, default)
