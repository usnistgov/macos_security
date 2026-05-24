# mscp/classes/baseline.py
"""Baseline document model.

A *baseline* is a top-level mSCP document that pairs metadata (authors,
title, description, target platform) with a set of `Profile` sections, each
of which groups one or more `Macsecurityrule` objects. This module defines
the `Baseline`, `Profile`, and `Author` Pydantic models, along with class
methods to load baselines from YAML and write them back out.
"""

# Standard python modules
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import Any, Optional

# Additional python modules
import pandas as pd
from pydantic import BaseModel

# Local python modules
from ..common_utils import config, create_yaml, open_file
from ..common_utils.logger_instance import logger
from .macsecurityrule import Macsecurityrule

__all__ = ["Author", "Profile", "Baseline"]


class BaseModelWithAccessors(BaseModel):
    """Pydantic base class with dict-style accessors.

    Adds `get` plus ``__getitem__`` / ``__setitem__`` so subclasses can be
    treated either as Pydantic models or as plain dict-like objects. Item
    access is restricted to declared model fields to keep typos from
    silently creating new attributes.
    """

    def get(self, attr: str, default: Any = None) -> Any:
        """Return the value of `attr`, or `default` if it isn't set.

        Unlike ``__getitem__``, this never raises and is not restricted to
        declared model fields — it just delegates to `getattr`.

        Args:
            attr (str): Attribute name to read.
            default (Any): Value returned when ``attr`` is absent.
                Defaults to ``None``.

        Returns:
            Any: The attribute value, or ``default`` if no such attribute
                exists on the instance.
        """
        return getattr(self, attr, default)

    def __getitem__(self, key: str) -> Any:
        """Dict-style read of a declared model field.

        Raises:
            KeyError: If ``key`` is not a declared field on the class.
        """
        if key in self.__class__.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")

    def __setitem__(self, key: str, value: Any) -> None:
        """Dict-style write to a declared model field.

        Raises:
            KeyError: If ``key`` is not a declared field on the class.
        """
        if key in self.__class__.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(
                f"{key} is not a valid attribute of {self.__class__.__name__}"
            )


class Author(BaseModelWithAccessors):
    """One author or owning organization of a baseline.

    Attributes:
        name (str | None): Personal name of the author, if available.
        organization (str | None): Organization the author represents, if
            applicable.
    """

    name: str | None
    organization: str | None
    additional: Optional[bool] = None

    def is_additional(self) -> bool:
        """Return true if this author is in addition to MSCP contributors.

        This is a simple helper that checks the `additional` field, which
        should be set to true for any author that is not a primary contributor
        to MSCP. This allows generated guidance to flag such authors
        and their contributions for special attention.

        Returns:
            bool: True when `additional` is true, false otherwise.
        """
        return self.additional is True


class Profile(BaseModelWithAccessors):
    """A named section of a baseline grouping related rules.

    Profiles correspond to the top-level groupings rendered in generated
    guidance (``Auditing``, ``Authentication``, ``Operating System``,
    etc.), plus the synthetic special sections (``Inherent``, ``Permanent``,
    ``Not Applicable``, ``Supplemental``).

    Attributes:
        section (str): Display name of the section (e.g. ``"Operating
            System"``).
        description (str): Section description copied from the matching
            section YAML file.
        rules (list[Macsecurityrule]): Rules included in this profile,
            generally sorted by `rule_id`.
    """

    section: str
    description: str
    rules: list[Macsecurityrule]


class Baseline(BaseModelWithAccessors):
    """An mSCP baseline document.

    A baseline pairs metadata about a security guide (title, description,
    authors, target platform) with the `Profile` sections that hold its
    rules. Instances are normally constructed via `from_yaml` (loading an
    existing baseline file) or `create_new` (assembling one from a rule
    set).

    Attributes:
        authors (list[Author]): Authors and/or owning organisations.
        profile (list[Profile]): Section profiles holding the baseline's
            rules.
        name (str): Short identifier, typically derived from the baseline
            filename stem.
        title (str): Human-readable full title of the baseline.
        description (str): Description rendered in generated guidance.
        platform (dict[str, Any]): Target platform metadata, e.g.
            ``{"os": "macOS", "version": 15.0}``.
        parent_values (str): Name of the parent benchmark this baseline
            inherits from (e.g. ``"recommended"``), or empty.
    """

    authors: list[Author]
    profile: list[Profile]
    name: str
    title: str = ""
    description: str = ""
    platform: dict[str, Any] = {}
    parent_values: str = ""

    @classmethod
    def from_yaml(
        cls,
        file_path: Path,
        language: str = "en",
        custom: bool = False,
    ) -> "Baseline":
        """Load a `Baseline` from a YAML file with rules resolved.

        Reads the baseline document, then for each profile entry resolves
        the matching section file (under ``config["sections_dir"]``, plus
        ``config["custom"]["sections_dir"]`` if `custom` is set) and
        loads its rules via `Macsecurityrule.load_rules`.

        Args:
            file_path (Path): Path to the baseline YAML file.
            language (str): Language code passed through to the file
                loader for localised strings. Defaults to ``"en"``.
            custom (bool): If true, also search the configured custom
                sections directory when resolving section files.
                Defaults to ``False``.

        Returns:
            Baseline: A fully populated baseline with all profiles and
                rules resolved. Profiles whose section file cannot be
                found are skipped with a warning.
        """

        logger.info(f"Attempting to open Baseline file: {file_path}")

        section_dirs: list[Path] = []

        # section_dir: Path = Path(config["sections_dir"])
        if custom:
            section_dirs = [
                Path(config["custom"]["sections_dir"]),
                Path(config["sections_dir"]),
            ]
        else:
            section_dirs = [Path(config["sections_dir"])]

        baseline_data: dict[str, Any] = open_file(file_path, language)
        authors = [Author(**author) for author in baseline_data.get("authors", [])]

        platform: dict[str, Any] = baseline_data["platform"]

        # Parse profiles
        profiles: list[Profile] = []
        for prof in baseline_data.get("profile", []):
            logger.debug(f"Section Name: {prof['section']}")
            section_clean: str = prof["section"].replace(" ", "").lower()

            section_file = next(
                (
                    file
                    for section_dir in section_dirs
                    if section_dir.exists()
                    for file in section_dir.rglob(f"{section_clean}.y*ml")
                ),
                None,
            )

            if not section_file:
                logger.warning("Rule file not found for rule: {}", prof["section"])
                continue

            section_data: dict[str, str] = open_file(Path(section_file), language)

            logger.debug(f"Section Data: {section_data}")

            profiles.append(
                Profile(
                    section=section_data.get("name", "").strip(),
                    description=section_data.get("description", "").strip(),
                    rules=Macsecurityrule.load_rules(
                        prof.get("rules", []),
                        platform["os"],
                        platform["version"],
                        baseline_data.get("parent_values", ""),
                        section_data.get("name", "").strip(),
                        tailoring=False,
                        language=language,
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
            platform=platform,
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
        baseline_dict: dict[str, Any],
        language: str = "en",
    ) -> None:
        """Build a new baseline from a rule set and write it to YAML.

        Groups ``rules`` into profiles by their `section` (or by special
        section tags ``inherent``, ``permanent``, ``n_a``, ``supplemental``
        when present), loads section descriptions from
        ``config["sections_dir"]``, and serialises the result via
        `to_yaml`. If ``baseline_dict`` lacks a ``title`` or
        ``description`` they're synthesised from the other arguments.

        Args:
            output_file (Path): Destination YAML file for the new baseline.
            rules (list[Macsecurityrule]): Rules to include.
            baseline_name (str | None): Short identifier folded into the
                synthesised title/description if those aren't supplied.
            authors (list[Author]): Authors attributed to the baseline.
            full_title (str): Long-form title prepended to the synthesised
                ``title`` and ``description`` when set.
            benchmark (str): Benchmark identifier (e.g. ``"recommended"``);
                stored as ``parent_values`` and used to extend the
                synthesised description when equal to ``"recommended"``.
            os_type (str): Operating-system family (e.g. ``"macOS"``).
            os_version (float): Operating-system version (e.g. ``15.0``).
            baseline_dict (dict[str, Any]): Additional baseline metadata
                merged into the constructor; ``title`` and ``description``
                are filled in if absent.
            language (str): Language code for loaded section descriptions.
                Defaults to ``"en"``.

        Side Effects:
            Writes the generated baseline to ``output_file``. Reads every
            ``*.y*ml`` file in ``config["sections_dir"]`` to resolve
            section descriptions.
        """

        description: str = ""
        os_type = os_type.replace("os", "OS")
        # custom_output_file: Path = Path(
        #     config["custom"]["baseline_dir"], output_file.name
        # )

        if "title" not in baseline_dict:
            baseline_dict["title"] = (
                f"{os_type} {os_version}: Security Configuration - {f'{full_title}' if full_title else ''}{f'{baseline_name}' if baseline_name else ''}"
            )

        if "description" not in baseline_dict:
            description: str = f"This guide describes the actions to take when securing a {os_type} {os_version} system against the {f'{full_title}' if full_title else ''}{f'{baseline_name}' if baseline_name else ''} security benchmark.\n"

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

        for yaml_file in Path(config["sections_dir"]).glob("*.y*ml"):
            section_data: dict = open_file(yaml_file, language)

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
            platform={"os": os_type, "version": os_version},
        )

        baseline.to_yaml(output_path=output_file)
        # baseline.to_yaml(output_path=custom_output_file)

    def to_dataframe(self) -> pd.DataFrame:
        """Flatten the baseline's rules into a `pandas.DataFrame`.

        Each rule contributes one row. The nested ``references`` mapping
        is unpacked so each reference namespace (``nist``, ``disa``, etc.)
        becomes its own column.

        Returns:
            pd.DataFrame: One row per rule across all profiles, with rule
                fields and unpacked references as columns.
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
        """Serialise this baseline to YAML in canonical key order.

        The serialised document orders top-level keys as ``title``,
        ``description``, ``authors``, ``parent_values``, ``platform``,
        ``profile`` (any other keys are dropped), and orders profiles by
        a fixed sequence (``Auditing``, ``Authentication``, ``iCloud``,
        ``Operating System``, ``Password Policy``, ``System Settings``,
        followed by the special sections). Within each profile, ``rules``
        is reduced to a sorted list of rule IDs.

        Args:
            output_path (Path): Destination YAML file.
        """

        logger.info("Creating baseline yaml")
        serialized_data = self.model_dump(exclude_none=True)
        key_order: list[str] = [
            "title",
            "description",
            "authors",
            "parent_values",
            "platform",
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
