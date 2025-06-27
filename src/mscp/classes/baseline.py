# mscp/classes/baseline.py

# Standard python modules
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import Any

# Additional python modules
import pandas as pd
from pydantic import BaseModel, Field

# Local python modules
from ..common_utils import config, create_yaml, open_file
from ..common_utils.logger_instance import logger
from .macsecurityrule import Macsecurityrule


class BaseModelWithAccessors(BaseModel):
    """
    A base class that provides `get`, `__getitem__`, and `__setitem__` methods
    for all derived classes.
    """

    def get(self, attr: str, default: Any = None) -> Any:
        """
        Get the value of an attribute, or return the default if it doesn't exist.
        """
        return getattr(self, attr, default)

    def __getitem__(self, key: str) -> Any:
        """
        Allow dictionary-like access to attributes.
        """
        if key in self.__class__.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")

    def __setitem__(self, key: str, value: Any) -> None:
        """
        Allow dictionary-like setting of attributes.
        """
        if key in self.__class__.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(
                f"{key} is not a valid attribute of {self.__class__.__name__}"
            )


class Author(BaseModelWithAccessors):
    name: str | None
    organization: str | None


class Profile(BaseModelWithAccessors):
    section: str
    description: str
    rules: list[Macsecurityrule]


class Baseline(BaseModelWithAccessors):
    authors: list[Author]
    profile: list[Profile]
    name: str
    title: str = ""
    description: str = ""
    parent_values: str = ""

    @classmethod
    def from_yaml(
        cls, file_path: Path, os_name: str, os_version: int, custom: bool = False
    ) -> "Baseline":
        """
        Load a Baseline object from a YAML file, including profiles and associated rules.

        Args:
            file_path (Path): Path to the baseline YAML file.
            custom (bool, optional): Whether to load custom configurations. Defaults to False.
            os_version (int): Operating system version.
            custom (bool): Whether to load custom configurations.

        Returns:
            Baseline: A fully populated Baseline instance.
        """

        logger.info(f"Attempting to open Baseline file: {file_path}")

        section_dirs: list[Path] = []

        # section_dir: Path = Path(config["defaults"]["sections_dir"])
        if custom:
            section_dirs = [
                Path(config["custom"]["sections_dir"]),
                Path(config["defaults"]["sections_dir"]),
            ]
        else:
            section_dirs = [Path(config["defaults"]["sections_dir"])]

        baseline_data: dict[str, Any] = open_file(file_path)
        authors = [Author(**author) for author in baseline_data.get("authors", [])]
        baseline_tag = file_path.stem.replace("_test", "")

        # Parse profiles
        profiles: list[Profile] = []
        for prof in baseline_data.get("profile", []):
            logger.debug(f"Section Name: {prof['section']}")

            section_file = next(
                (
                    file
                    for section_dir in section_dirs
                    if section_dir.exists()
                    for file in section_dir.rglob(f"{prof['section']}.y*ml")
                ),
                None,
            )

            if not section_file:
                logger.warning("Rule file not found for rule: {}", prof["section"])
                continue

            section_data: dict[str, str] = open_file(Path(section_file))

            logger.debug(f"Section Data: {section_data}")

            profiles.append(
                Profile(
                    section=section_data.get("name", "").strip(),
                    description=section_data.get("description", "").strip(),
                    rules=Macsecurityrule.load_rules(
                        prof.get("rules", []),
                        os_name,
                        os_version,
                        baseline_data.get("parent_values", ""),
                        section_data.get("name", "").strip(),
                        baseline_tag,
                        custom,
                    ),
                )
            )

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
    def create_new(
        cls,
        output_file: Path,
        rules: list[Macsecurityrule],
        baseline_name: str | None,
        authors: list[Author],
        full_title: str,
        benchmark: str,
        os_type: str,
        os_version: float,
        baseline_dict: dict[str, Any] = Field(default_factory=dict[str, Any]),
    ) -> None:
        """
        Creates a new baseline YAML file based on the provided rules, metadata, and configuration.

        Args:
            output_file (Path): The path where the baseline YAML file will be written.
            rules (list[Macsecurityrule]): A list of security rule objects to include in the baseline.
            baseline_name (str | None): The name of the baseline, or None if not specified.
            authors (list[Author]): A list of authors to attribute to the baseline.
            full_title (str): The full title of the baseline.
            benchmark (str): The benchmark type (e.g., "recommended").
            os_type (str): The operating system type (e.g., "macOS").
            os_version (float): The version of the operating system.
            baseline_dict (dict[str, Any], optional): Additional baseline metadata. Defaults to an empty dict.

        Returns:
            None

        Side Effects:
            - Writes the generated baseline to both the specified output file and a custom output file.
            - Reads section descriptions from YAML files in the configured sections directory.

        Notes:
            - The function groups rules into sections, including special sections such as "Inherent", "Permanent", "Not Applicable", and "Supplemental".
            - Section descriptions are loaded from YAML files in the sections directory.
            - The resulting baseline is serialized to YAML format and saved to disk.
        """

        description: str = ""
        os_type = os_type.replace("os", "OS")
        custom_output_file: Path = Path(
            config["custom"]["baseline_dir"], output_file.name
        )

        if baseline_dict is None:
            baseline_dict["title"] = (
                f"{os_type} {os_version}: Security Configuration - {full_title} {baseline_name}"
            )

            description: str = (
                f"This guide describes the actions to take when securing a {os_type} {os_version} system against the {full_title} {baseline_name} security baseline.\n"
            )

            if benchmark == "recommended":
                description += "\nInformation System Security Officers and benchmark creators can use this catalog of settings in order to assist them in security benchmark creation. This list is a catalog, not a checklist or benchmark, and satisfaction of every item is not likely to be possible or sensible in many operational scenarios."

            baseline_dict["description"] = description.strip()

        special_sections: dict[str, str] = {
            "inherent": "Inherent",
            "permanent": "Permanent",
            "n_a": "Not Applicable",
            "supplemental": "Supplemental",
        }

        grouped_rules = defaultdict(list)
        section_descriptions = {}

        for yaml_file in Path(config["defaults"]["sections_dir"]).glob("*.y*ml"):
            section_data: dict = open_file(yaml_file)

            section_descriptions[section_data.get("name")] = section_data.get(
                "description", ""
            )

        for rule in rules:
            matched: bool = False
            for tag, section_name in special_sections.items():
                if rule.tags is not None and tag in rule.tags:
                    grouped_rules[section_name].append(rule)
                    matched = True
                    break

            if not matched:
                grouped_rules[rule.section].append(rule)

        for section in grouped_rules:
            grouped_rules[section] = sorted(
                grouped_rules[section], key=lambda r: r.rule_id
            )

        profiles = [
            Profile(
                section=section,
                description=section_descriptions.get(
                    section, "No description available"
                ),
                rules=grouped_rules[section],
            )
            for section in grouped_rules
        ]

        baseline = cls(
            **baseline_dict,
            authors=authors,
            profile=profiles,
            name=output_file.stem,
            parent_values=benchmark,
        )

        baseline.to_yaml(output_path=output_file)
        baseline.to_yaml(output_path=custom_output_file)

    def to_dataframe(self) -> pd.DataFrame:
        """
        Convert the profiles and rules from the Baseline object into a Pandas DataFrame.

        Returns:
            pd.DataFrame: A DataFrame containing rules with their associated profile sections.
        """

        rules: list[dict] = []
        for profile in self.profile:
            for rule in profile.rules:
                rule_data = rule.model_dump()
                references = rule_data.pop("references", {})

                for ref_key, ref_value in references.items():
                    rule_data[ref_key] = ref_value

                rules.append(rule_data)

        return pd.DataFrame(rules)

    def to_yaml(self, output_path: Path) -> None:
        """
        Serializes the baseline model to a YAML file with a specific order for keys and profiles.

        Args:
            output_path (Path): The path where the YAML file will be created.

        Returns:
            None

        The method performs the following steps:
        1. Logs the start of the YAML creation process.
        2. Serializes the model data.
        3. Defines the order for the main keys and profile sections.
        4. Removes the "name" key from the serialized data.
        5. Sorts the rules within each profile by their rule IDs.
        6. Orders the profiles based on the predefined profile order.
        7. Constructs an ordered dictionary with the specified key order.
        8. Creates the YAML file using the ordered data.
        9. Logs the completion of the YAML creation process.
        """

        logger.info("Creating baseline yaml")
        serialized_data = self.model_dump()
        key_order: list[str] = [
            "title",
            "description",
            "authors",
            "parent_values",
            "profile",
        ]
        profile_order: list[str] = [
            "Auditing",
            "Authentication",
            "iCloud",
            "Operating System",
            "Password Policy",
            "System Settings",
            "Inherent",
            "Permanent",
            "Not Applicable",
            "Supplemental",
        ]
        ordered_data: OrderedDict = OrderedDict()

        serialized_data.pop("name")
        for profile in serialized_data["profile"]:
            profile.pop("description", None)
            profile["rules"] = sorted([rule["rule_id"] for rule in profile["rules"]])

        ordered_profiles = sorted(
            serialized_data["profile"],
            key=lambda p: (
                profile_order.index(p["section"])
                if p["section"] in profile_order
                else len(profile_order)
            ),
        )

        for key in key_order:
            if key in serialized_data:
                if key == "profile":
                    ordered_data[key] = ordered_profiles
                else:
                    ordered_data[key] = serialized_data[key]

        create_yaml(output_path, ordered_data)
        logger.success("Created baseline yaml: {}", output_path)

    @classmethod
    def load_all_from_folder(
        cls, folder_path: Path, os_name: str, os_version: int, custom: bool = False
    ) -> list["Baseline"]:
        """
        Load all Baseline objects from YAML files in a specified folder.

        Args:
            folder_path (Path): Path to the folder containing baseline YAML files.
            os_name (str): Operating system name.
            os_version (int): Operating system version.
            custom (bool): Whether to load custom configurations.

        Returns:
            list[Baseline]: A list of fully populated Baseline instances.
        """

        logger.debug("=== LOADING ALL BASELINES ===")
        baseline_folder: Path = Path(folder_path, os_name, str(os_version))
        logger.debug(f"Folder: {baseline_folder}")
        baselines: list["Baseline"] = []

        for yaml_file in baseline_folder.glob("*.yaml"):
            logger.debug(f"Loading YAML file: {yaml_file}")
            baseline = cls.from_yaml(yaml_file, os_name, os_version, custom)
            baselines.append(baseline)

        logger.success("Loaded {} baselines", len(baselines))
        return baselines
