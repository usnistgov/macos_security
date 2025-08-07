# macsecurityrule.py

# Standard python modules
import base64
from collections import OrderedDict
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

# Additional python modules
from lxml import etree
from pydantic import BaseModel, ConfigDict, Field

# Local python modules
from ..common_utils import (
    config,
    create_yaml,
    get_version_data,
    make_dir,
    mscp_data,
    open_file,
    sanitize_input,
)
from ..common_utils.logger_instance import logger


class Sectionmap(StrEnum):
    AUDIT = "auditing"
    AUTH = "authentication"
    ICLOUD = "icloud"
    INHERENT = "inherent"
    OS = "operatingsystem"
    MANUAL = "manual"
    NOT_APPLICABLE = "notapplicable"
    PWPOLICY = "passwordpolicy"
    PERMANENT = "permanent"
    SRG = "srg"
    SUPPLEMENTAL = "supplemental"
    SYSTEM_SETTINGS = "systemsettings"


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


class NistReferences(BaseModelWithAccessors):
    cce: dict[str, list[str]] | None = None
    nist_800_53r5: list[str] | None = None
    nist_800_171r3: list[str] | None = None

    def __init__(self, **data):
        super().__init__(**data)
        if self.cce:
            self.cce = OrderedDict(sorted(self.cce.items()))
        if self.nist_800_53r5:
            self.nist_800_53r5 = sorted(self.nist_800_53r5)
        if self.nist_800_171r3:
            self.nist_800_171r3 = sorted(self.nist_800_171r3)


class DisaReferences(BaseModelWithAccessors):
    cci: list[str] | None = None
    srg: list[str] | None = None
    disa_stig: list[str] | None = None
    cmmc: list[str] | None = None
    sfr: list[str] | None = None
    severity: str | None = None

    def __init__(self, **data):
        super().__init__(**data)
        if self.cci:
            self.cci = sorted(self.cci)
        if self.srg:
            self.srg = sorted(self.srg)
        if self.sfr:
            self.sfr = sorted(self.sfr)
        if self.disa_stig:
            self.disa_stig = sorted(self.disa_stig)
        if self.cmmc:
            self.cmmc = sorted(self.cmmc)


class CisReferences(BaseModelWithAccessors):
    benchmark: list[str] | None = None
    controls_v8: list[float] | None = None

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if self.benchmark:
            self.benchmark = sorted(self.benchmark)
        if self.controls_v8:
            self.controls_v8 = sorted(self.controls_v8)


class bsiReferences(BaseModelWithAccessors):
    indigo: list[str] | None = None
    severity: str | None = None

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if self.indigo:
            self.indigo = sorted(self.indigo)


class Mobileconfigpayload(BaseModelWithAccessors):
    payload_type: str
    payload_content: list[dict[str, Any]]


class References(BaseModelWithAccessors):
    model_config: ConfigDict = ConfigDict(extra="ignore")

    nist: NistReferences
    disa: DisaReferences | None = None
    cis: CisReferences | None = None
    bsi: bsiReferences | None = None
    custom: list[str] | None = None


class Macsecurityrule(BaseModelWithAccessors):
    """
    Macsecurityrule

    A data model representing a macOS security rule, including its metadata, configuration, and mechanisms for enforcement and customization.

    Attributes:
        title (str): The title of the security rule.
        rule_id (str): Unique identifier for the rule.
        severity (str): Severity level of the rule.
        discussion (str): Detailed discussion or rationale for the rule.
        references (References): Reference information (e.g., NIST, CIS) associated with the rule.
        odv (dict[str, Any] | None): Organizational Defined Values for the rule, if applicable.
        finding (bool): Indicates if the rule is a finding.
        tags (list[str]): List of tags categorizing the rule.
        result_value (Any): The expected result value for compliance.
        mobileconfig (bool): Whether the rule can be enforced via a configuration profile.
        mobileconfig_info (list[Mobileconfigpayload]): Information about the configuration profile payloads.
        ddm_info (dict[str, Any]): Declarative Device Management information.
        customized (bool): Indicates if the rule has been customized.
        mechanism (str): The enforcement mechanism for the rule (e.g., Manual, Script, Configuration Profile).
        section (str | None): The section or category to which the rule belongs.
        uuid (str): Universally unique identifier for the rule instance.
        platforms (dict[str, Platforms]): Platform-specific data for the rule.
        os_name (str): Name of the operating system.
        os_type (str): Type of the operating system.

    Class Methods:
        load_rules: Load Macsecurityrule objects from YAML files for the given rule IDs.
        collect_all_rules: Populate Macsecurityrule objects from YAML files in a folder, mapping folder names to section filenames.
        odv_query: Interactively query the user to include/exclude rules and set Organizational Defined Values (ODVs).
        get_tags: Generate a sorted list of unique tags from the provided rules.

    Instance Methods:
        _format_mobileconfig_fix: Generate a formatted XML-like string for the `mobileconfig_info` field.
        _fill_in_odv: Replace placeholders ('$ODV') in the instance attributes with the appropriate override value.
        format_payload: Format a single payload type and its content as a string.
        _add_payload_content: Add payload content as XML elements to the parent node.
        _create_value_element: Create an XML element based on the type of the provided value.
        write_odv_custom_rule: Write a custom ODV rule to a YAML file.
        remove_odv_custom_rule: Remove the custom rule from the ODV and update the corresponding YAML file.
        to_yaml: Serialize the rule to a YAML file, preserving key order and cleaning references.
        to_dict: Convert the Macsecurityrule instance to a dictionary.
        _clean_references: Clean the references dictionary by removing any keys with values that are None or in ("NA", "N/A").

    Usage:
        This class is used to represent, load, manipulate, and serialize macOS security rules, supporting both standard and custom configurations, and providing mechanisms for user interaction and compliance reporting.
    """

    title: str
    rule_id: str
    discussion: str
    references: References
    odv: dict[str, Any] | None = None
    finding: bool = False
    tags: list[str] | None = None
    result_value: str | int | bool | None = None
    mobileconfig_info: list[Mobileconfigpayload] | None = None
    ddm_info: dict[str, Any] | None = None
    customized: bool = False
    mechanism: str
    section: str | None
    uuid: str = Field(default_factory=lambda: str(uuid4()))
    platforms: dict[str, dict[str, Any]] = Field(default_factory=dict)
    os_name: str
    os_type: str
    os_version: float = Field(default_factory=float)
    check: str | None = None
    fix: str | None = None
    severity: str | None = None

    @classmethod
    def load_rules(
        cls,
        rule_ids: list[str],
        os_type: str,
        os_version: float,
        parent_values: str,
        section: str,
        baseline_tag: str | None = None,
        custom: bool = False,
        generate_baseline: bool = False,
    ) -> list["Macsecurityrule"]:
        """
        Load Macsecurityrule objects from YAML files for the given rule IDs.

        Args:
            rule_ids (list[str]): List of rule IDs to load.
            os_type (str): Operating system name.
            os_version (int): Operating system version.
            parent_values (str): Parent values to apply when filling in ODV.
            section (str): Section name for the rules.
            custom (bool): Whether to include custom rules.
            generate_baseline (bool): Whether to generate a baseline.

        Returns:
            list[Macsecurityrule]: A list of loaded Macsecurityrule objects.
        """

        logger.info("=== LOADING {} RULES ===", section.upper())

        rules: list[Macsecurityrule] = []
        os_version_str: str = str(os_version)
        os_version_int: int = int(os_version)
        current_version_data: dict[str, Any] = get_version_data(
            os_type, os_version, mscp_data
        )
        os_name: str = current_version_data["os_name"]
        os_typeversion: str = f"{os_type}_{os_version_int}".lower()
        os_type = os_type.replace("os", "OS")

        rules_dirs: list[Path] = [
            Path(config["custom"]["rules_dir"]),
            Path(config["defaults"]["rules_dir"]),
        ]

        for rule_id in rule_ids:
            logger.debug("Transforming rule: {}", rule_id)

            result_value: str | int | bool | None = None
            check_value: str | None = None
            fix_value: str | None = None
            mechanism: str = "Manual"
            payloads: list[Mobileconfigpayload] | None = []
            severity: str | None = None

            rule_file = next(
                (
                    file
                    for rules_dir in rules_dirs
                    if rules_dir.exists()
                    for pattern in (f"{rule_id}.y*ml", f"{rule_id}.json")
                    for file in rules_dir.rglob(pattern)
                ),
                None,
            )

            if not rule_file:
                logger.warning("Rule file not found for rule: {}", rule_id)
                continue

            rule_yaml: dict[str, Any] = open_file(rule_file)

            if os_type not in rule_yaml.get("platforms", {}):
                logger.debug(
                    "Rule {} does not support the OS type: {}. Skipping rule.",
                    rule_id,
                    os_type,
                )
                continue

            if os_version_str not in rule_yaml["platforms"][os_type]:
                logger.debug(
                    "Rule {} does not support the OS version: {}. Skipping rule.",
                    rule_id,
                    os_version_str,
                )
                continue

            rule_yaml["rule_id"] = rule_yaml.pop("id")

            if "custom" in rule_file.parts:
                rule_yaml["customized"] = True

            enforcement_info = rule_yaml["platforms"][os_type].get(
                "enforcement_info", {}
            )

            tags = rule_yaml.get("tags", [])

            if enforcement_info and section != "notapplicable":
                check_shell = enforcement_info.get("check", {}).get("shell")
                check_result = enforcement_info.get("check", {}).get("result")
                fix_shell = enforcement_info.get("fix", {}).get("shell")
                additonal_info = enforcement_info.get("fix", {}).get("additional_info")

                if check_result:
                    for k, v in rule_yaml["platforms"][os_type]["enforcement_info"][
                        "check"
                    ]["result"].items():
                        if isinstance(v, (int, bool, str)):
                            result_value = v
                            break
                        elif k == "base64":
                            result_encoded: bytes = base64.b64encode(v.encode("UTF-8"))
                            result_value = result_encoded.decode("utf-8")
                            break

                if check_shell and fix_shell:
                    mechanism = "Script"

                    check_value = check_shell
                    fix_value = fix_shell

                if check_shell:
                    check_value = check_shell

                if (
                    not check_shell
                    or not fix_shell
                    or not check_value
                    and additonal_info
                ):
                    fix_value = None

            if "mobileconfig_info" in rule_yaml:
                mechanism = "Configuration Profile"

                for entry in rule_yaml["mobileconfig_info"]:
                    payload_type: str = str(entry.get("PayloadType", ""))
                    payload_content: list[dict[str, Any]] = entry.get(
                        "PayloadContent", []
                    )

                    payloads.append(
                        Mobileconfigpayload(
                            payload_type=payload_type,
                            payload_content=payload_content,
                        )
                    )

                if check_value and "osascript" in check_value:
                    # Get the first key from the first payload_content dict
                    first_key = list(payloads[0].payload_content[0].keys())[0]
                    check_value = f"/usr/bin/osascript -l JavaScript -e \"$.NSUserDefaults.alloc.initWithSuiteName('{payloads[0].payload_type}').objectForKey('{first_key}').js\""

                rule_yaml.pop("mobileconfig_info", None)
            else:
                payloads = None

            benchmarks: list[dict[str, str]] = rule_yaml["platforms"][os_type][
                os_version_str
            ].get("benchmarks", [])

            if benchmarks and baseline_tag:
                for benchmark in benchmarks:
                    if (
                        benchmark.get("name") == baseline_tag
                        and "severity" in benchmark
                    ):
                        severity = benchmark["severity"]
                        break

            if tags:
                match rule_yaml["tags"]:
                    case "inherent":
                        mechanism = "Inherent"
                        fix_value = (
                            "The control cannot be configured out of compliance."
                        )
                        section = Sectionmap.INHERENT
                    case "permanent":
                        mechanism = "Permanent"
                        fix_value = "The control is not able to be configured to meet the requirement. It is recommended to implement a third-party solution to meet the control."
                        section = Sectionmap.PERMANENT
                    case "not_applicable" | "n_a":
                        mechanism = "N/A"
                        fix_value = "The control is not applicable when configuring a macOS system."
                        section = Sectionmap.NOT_APPLICABLE

            ref: dict[str, Any] = rule_yaml["references"]
            nist: dict[str, Any] = ref.get("nist", {})
            disa: dict[str, Any] = ref.get("disa", {})
            cis: dict[str, Any] = ref.get("cis", {})
            bsi: dict[str, Any] = ref.get("bsi", {})

            # Map NIST references
            nist_map = {
                "800-53r5": "nist_800_53r5",
                "800-171r3": "nist_800_171r3",
                "cce": "cce",
            }

            for src, dst in nist_map.items():
                if src in nist and nist[src] is not None:
                    value = nist.pop(src)
                    if src == "cce" and isinstance(value, dict):
                        value = value.get(os_typeversion)
                        if value is not None and not isinstance(value, dict):
                            # Ensure cce is always a dict[str, list[str]] or None
                            value = None
                    if dst in ("nist_800_53r5", "nist_800_171r3"):
                        if value is not None and not isinstance(value, list):
                            value = [value] if isinstance(value, str) else None
                    nist[dst] = value

            # Map CIS benchmark
            if cis and "benchmark" in cis:
                if isinstance(cis["benchmark"], dict):
                    cis["benchmark"] = cis["benchmark"].get(os_typeversion)
                if cis["benchmark"] is not None and not isinstance(
                    cis["benchmark"], list
                ):
                    cis["benchmark"] = [cis["benchmark"]]

            # Map DISA references
            if disa:
                if "disa_stig" in disa and isinstance(disa["disa_stig"], dict):
                    disa["disa_stig"] = disa["disa_stig"].get(os_typeversion)
                    if disa["disa_stig"] is not None and not isinstance(
                        disa["disa_stig"], list
                    ):
                        disa["disa_stig"] = [disa["disa_stig"]]

            # Map BSI references
            if bsi:
                if "indigo" in bsi and isinstance(bsi["indigo"], dict):
                    bsi["indigo"] = bsi["indigo"].get(os_typeversion)
                    if bsi["indigo"] is not None and not isinstance(
                        bsi["indigo"], list
                    ):
                        bsi["indigo"] = [bsi["indigo"]]

            rule = cls(
                **rule_yaml,
                result_value=result_value,
                mobileconfig_info=payloads,
                mechanism=mechanism,
                section=section,
                os_name=os_name,
                os_type=os_type,
                os_version=os_version,
                check=check_value,
                fix=fix_value,
                severity=severity,
            )

            if rule.mobileconfig_info:
                logger.debug("Formatting mobileconfig_info for rule: {}", rule.rule_id)
                rule._format_mobileconfig_fix()
                logger.success("Formatted mobileconfig_info for rule: {}", rule.rule_id)

            if (
                rule.odv is not None
                and not generate_baseline
                and parent_values is not None
            ):
                rule._fill_in_odv(parent_values)

            logger.success("Transformed rule: {}", rule_id)

            rules.append(rule)

        logger.debug("NUMBER OF {} LOADED RULES: {}", section.upper(), len(rules))
        logger.info("=== RULES {} LOADED ===", section.upper())

        return rules

    @classmethod
    def collect_all_rules(
        cls,
        os_type: str,
        os_version: int,
        generate_baseline: bool = True,
        parent_values: str = "default",
    ) -> list["Macsecurityrule"]:
        """
        Populate Macsecurityrule objects from YAML files in a folder.
        Map folder names to specific section filenames for the `section` attribute.

        Args:
            os_type (str): Operating system name.
            os_version (int): Operating system version.
            parent_values (str): Parent values for rule initialization.

        Returns:
            list[Macsecurityrule]: A list of Macsecurityrule instances.
        """

        logger.info("=== LOADING ALL RULES ===")

        rules: list[Macsecurityrule] = []

        section_dirs: list[Path] = [
            Path(config["custom"]["sections_dir"]),
            Path(config["defaults"]["sections_dir"]),
        ]

        rules_dirs: list[Path] = [
            Path(config["custom"]["rules_dir"]),
            Path(config["defaults"]["rules_dir"]),
        ]

        section_data: dict[str, str] = {
            section_file.stem: open_file(section_file).get("name", "")
            for section_dir in section_dirs
            for section_file in section_dir.glob("*.y*ml")
            if section_file.is_file()
        }

        for rule_dir in rules_dirs:
            if not rule_dir.exists() or not rule_dir.is_dir():
                logger.warning(
                    "Directory does not exist or is not a directory: {}", rule_dir
                )
                continue

            for folder in rule_dir.iterdir():
                if not folder.is_dir():
                    continue

                if folder.name == "sysprefs":
                    continue

                for rule_file in folder.rglob("*.y*ml"):
                    try:
                        rule_name: str = rule_file.stem
                        folder_name: str = rule_file.parent.name
                        logger.debug("{} folder: {}", rule_name, folder_name)
                        section_name: str = section_data.get(
                            Sectionmap[folder_name.upper()], ""
                        )
                        logger.debug("Section Name: {}", section_name)
                        custom: bool = False

                        if "custom" in str(folder).lower():
                            custom = True

                        if not section_name:
                            logger.warning(
                                "Folder '{}' not found in section mapping.", folder_name
                            )
                            continue

                        rules += cls.load_rules(
                            rule_ids=[rule_name],
                            os_type=os_type,
                            os_version=os_version,
                            parent_values=parent_values,
                            section=section_name,
                            custom=custom,
                            generate_baseline=generate_baseline,
                        )

                    except Exception as e:
                        logger.error(
                            "Failed to load rule from file {}: {}", rule_file, e
                        )

        logger.info("=== ALL RULES LOADED ===")

        return rules

    def _format_mobileconfig_fix(self) -> None:
        """
        Generate a formatted XML-like string for the `mobileconfig_info` field.

        Handles special cases such as `com.apple.ManagedClient.preferences`.

        This method updates the `fix` attribute of the instance but does not return anything.
        """
        if not self.mobileconfig_info:
            return

        rulefix = ""

        for payload in self.mobileconfig_info:
            if payload.payload_type == "com.apple.ManagedClient.preferences":
                rulefix += (
                    f"NOTE: The following settings are in the ({payload.payload_type}) payload. "
                    "This payload requires the additional settings to be sub-payloads within, "
                    "containing their defined payload types.\n\n"
                )

                if isinstance(payload.payload_content, list):
                    for item in payload.payload_content:
                        if isinstance(item, dict):
                            for (
                                nested_payload_type,
                                nested_payload_content,
                            ) in item.items():
                                nested_fix = self.format_payload(
                                    nested_payload_type, nested_payload_content
                                )
                                rulefix += nested_fix
                        else:
                            logger.warning(
                                "Unexpected item type in payload_content list: {}",
                                type(item),
                            )

                if isinstance(payload.payload_content, dict):
                    # Recursively process nested payloads
                    for (
                        nested_payload_type,
                        nested_payload_content,
                    ) in payload.payload_content.items():
                        nested_fix = self.format_payload(
                            nested_payload_type, nested_payload_content
                        )
                        rulefix += nested_fix

            rulefix += self.format_payload(
                payload.payload_type, payload.payload_content
            )

        self._update_fix_for_configuration_profile()

    def _update_fix_for_configuration_profile(self) -> None:
        """
        Update the `fix` attribute or the enforcement info for configuration profiles.
        """
        if self.mechanism == "Configuration Profile":
            if (
                not self.platforms.get(self.os_type, {})
                .get("enforcement_info", {})
                .get("fix")
            ):
                if self.mobileconfig_info and len(self.mobileconfig_info) > 0:
                    self.fix = (
                        f"Create a configuration profile containing the following keys in the "
                        f"({self.mobileconfig_info[0].payload_type}) payload type:\n\n"
                        + self.format_payload(
                            self.mobileconfig_info[0].payload_type,
                            self.mobileconfig_info[0].payload_content,
                        )
                    )
            else:
                if self.mobileconfig_info and len(self.mobileconfig_info) > 0:
                    self.platforms[self.os_type]["enforcement_info"]["fix"] = (
                        self.format_payload(
                            self.mobileconfig_info[0].payload_type,
                            self.mobileconfig_info[0].payload_content,
                        )
                    )

    @staticmethod
    def format_payload(
        payload_type: str,
        payload_content: list[dict] | dict,
        jinja_filter: bool = False,
    ) -> str:
        """
        Format a single payload type and its content.

        Args:
            payload_type (str): The type of the payload.
            payload_content (dict): The content of the payload.

        Returns:
            str: A formatted string representing the payload.
        """

        output: str = ""

        if not jinja_filter:
            output = "[source,xml]\n----\n"

        # Generate XML for the payload content
        root = etree.Element("Payload", attrib=None, nsmap=None)
        if isinstance(payload_content, list):
            for payload in payload_content:
                if isinstance(payload, dict):
                    elements = []
                    for key, value in payload.items():
                        # Create a <key> element
                        key_element = etree.Element("key", attrib=None, nsmap=None)
                        key_element.text = key
                        elements.append(key_element)

                        # Create the corresponding value element
                        value_element = Macsecurityrule._create_value_element(value)
                        elements.append(value_element)

                    # Append all elements to the root element
                    for element in elements:
                        root.append(element)

        # Pretty-print the XML content
        output += (
            etree.tostring(root, encoding="unicode", pretty_print=True)
            .strip()
            .replace("<root>", "")
            .replace("</root>", "")
            + "\n"
        )

        if not jinja_filter:
            output += "----\n\n"

        return output

    @staticmethod
    def _add_payload_content(parent: etree.Element, content: dict) -> None:
        """
        Add payload content as XML elements to the parent node.

        Args:
            parent (etree.Element): The parent XML element.
            content (dict): The dictionary of key-value pairs to process.
        """
        for key, value in content.items():
            key_element = etree.SubElement(parent, "key", attrib=None, nsmap=None)
            key_element.text = key

            match value:
                case bool():
                    etree.SubElement(
                        parent, "true" if value else "false", attrib=None, nsmap=None
                    )
                case int():
                    int_element = etree.SubElement(
                        parent, "integer", attrib=None, nsmap=None
                    )
                    int_element.text = str(value)
                case str():
                    str_element = etree.SubElement(
                        parent, "string", attrib=None, nsmap=None
                    )
                    str_element.text = value
                case list():
                    array_element = etree.SubElement(
                        parent, "array", attrib=None, nsmap=None
                    )
                    for item in value:
                        item_element = etree.SubElement(
                            array_element, "string", attrib=None, nsmap=None
                        )
                        item_element.text = item
                case dict():
                    dict_element = etree.SubElement(
                        parent, "dict", attrib=None, nsmap=None
                    )
                    Macsecurityrule._add_payload_content(dict_element, value)
                case _:
                    logger.error(
                        "Unsupported value type: {} for value: {}", type(value), value
                    )
                    raise ValueError(
                        f"Unsupported value type: {type(value)} for key: {key}"
                    )

    @staticmethod
    def _create_value_element(value: Any) -> etree.Element:
        """
        Creates an XML element based on the type of the provided value.

        Args:
            value (Any): The value to be converted into an XML element. Supported types are:
                - bool: Creates an element with tag "true" or "false".
                - int: Creates an element with tag "integer" and the integer value as text.
                - str: Creates an element with tag "string" and the string value as text.
                - list: Creates an element with tag "array" and each item in the list as a "string" sub-element.
                - dict: Creates an element with tag "dict" and adds the dictionary content as sub-elements.

        Returns:
            etree.Element: The created XML element based on the provided value.

        Raises:
            ValueError: If the provided value type is not supported.
        """
        match value:
            case bool():
                return etree.Element(
                    "true" if value else "false", attrib=None, nsmap=None
                )
            case int():
                int_element = etree.Element("integer", attrib=None, nsmap=None)
                int_element.text = str(value)
                return int_element
            case float():
                float_element = etree.Element("real", attrib=None, nsmap=None)
                float_element.text = str(value)
                return float_element
            case str():
                str_element = etree.Element("string", attrib=None, nsmap=None)
                str_element.text = value
                return str_element
            case list():
                array_element = etree.Element("array", attrib=None, nsmap=None)
                for item in value:
                    item_element = etree.SubElement(
                        array_element, "string", attrib=None, nsmap=None
                    )
                    item_element.text = item
                return array_element
            case dict():
                dict_element = etree.Element("dict", attrib=None, nsmap=None)
                Macsecurityrule._add_payload_content(dict_element, value)
                return dict_element
            case _:
                logger.error(
                    "Unsupported value type: {} for value: {}", type(value), value
                )
                raise ValueError(f"Unsupported value type: {type(value)}")

    def _fill_in_odv(self, parent_values: str) -> None:
        """
        Replaces placeholders ('$ODV') in the instance attributes with the appropriate override value
        based on the parent_values key.

        Args:
            parent_values (str): The key to look up in the 'odv' dictionary. Expected format is a string
                                 representing the parent value category, such as 'custom', 'recommended',
                                 or any other specific category defined in the 'odv' dictionary.

        Returns:
            None: Modifies the instance attributes in place.
        """
        if self.odv is None:
            logger.warning("No ODV dictionary found for rule: {}", self.rule_id)
            return

        odv_lookup: dict[str, Any] = self.odv
        odv_value: str | int | bool | None = odv_lookup.get(parent_values)

        # Replace $ODV in text fields
        fields_to_process: tuple[str, ...] = (
            "title",
            "discussion",
            "fix",
        )

        # Helper function to recursively replace $ODV in nested structures
        def replace_odv_in_obj(obj):
            if isinstance(obj, str) and "$ODV" in obj:
                return obj.replace("$ODV", str(odv_value))
            elif isinstance(obj, dict):
                return {k: replace_odv_in_obj(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_odv_in_obj(item) for item in obj]
            else:
                return obj

        for field in fields_to_process:
            value = getattr(self, field, None)
            if value is not None:
                setattr(self, field, replace_odv_in_obj(value))

        # Replace $ODV in mobileconfig_info
        if self.mobileconfig_info is not None:
            for payload in self.mobileconfig_info:
                payload.payload_content = replace_odv_in_obj(payload.payload_content)

        # Replace $ODV in ddm_info
        if self.ddm_info is not None:
            self.ddm_info = replace_odv_in_obj(self.ddm_info)

        if self.platforms is not None:
            self.platforms = replace_odv_in_obj(self.platforms)

    def write_odv_custom_rule(self, odv: Any) -> None:
        """
        Writes a custom ODV (Object Data Value) rule to a YAML file.

        Args:
            odv (Any): The custom ODV data to be written.

        Returns:
            None
        """
        rule_file_path: Path = Path(
            config["custom"]["rules"][self.section], f"{self.rule_id}.yaml"
        )

        make_dir(rule_file_path.parent)

        self["odv"] = {"custom": odv}

        self.to_yaml(rule_file_path)

    def remove_odv_custom_rule(self) -> None:
        """
        Removes the custom rule from the ODV (Object Data Value) and updates the corresponding YAML file.

        This method performs the following steps:
        1. Constructs the file path for the custom rule YAML file based on the configuration and rule ID.
        2. Checks if the rule file exists. If not, logs a warning and exits the method.
        3. If the ODV contains a "custom" key, it removes this key.
        4. Writes the updated ODV to the YAML file.

        Returns:
            None
        """
        rule_file_path: Path = Path(
            config["custom"]["rules"][self.section], f"{self.rule_id}.yaml"
        )

        if not rule_file_path.exists():
            logger.warning("Rule file not found: {}", rule_file_path)
            return

        if self.odv is not None and "custom" in self.odv:
            self.odv.pop("custom")
            self["references"].pop("custom")

        self.to_yaml(rule_file_path)

    @classmethod
    def odv_query(
        cls, rules: list["Macsecurityrule"], benchmark: str
    ) -> list["Macsecurityrule"]:
        """
        Queries the user to include/exclude rules and set Organizational Defined Values (ODVs).

        Args:
            rules (list[Macsecurityrule]): List of rules to process.
            benchmark (str): The benchmark being tailored (e.g., "recommended").

        Returns:
            list[Macsecurityrule]: List of included rules after user input and ODV modifications.
        """
        print(
            "The inclusion of any given rule is a risk-based-decision (RBD). "
            "While each rule is mapped to an 800-53 control, deploying it in your organization "
            "should be part of the decision-making process.\n"
        )

        if benchmark != "recommended":
            print(
                "WARNING: You are tailoring an established benchmark. Excluding rules or modifying ODVs "
                "may result in non-compliance with the benchmark.\n"
            )

        included_rules: list[Macsecurityrule] = []
        queried_rule_ids: list[str] = []
        include_all: bool = False
        _always_include: tuple[str, ...] = ("inherent",)

        for rule in rules:
            get_odv: bool = False

            # Default inclusion logic for certain tags
            if any(tag in rule.tags for tag in _always_include):
                include = "y"
            elif include_all:
                if rule.rule_id not in queried_rule_ids:
                    include = "y"
                    get_odv = True
                    queried_rule_ids.append(rule.rule_id)
                    rule.remove_odv_custom_rule()
            else:
                if rule.rule_id not in queried_rule_ids:
                    include = sanitize_input(
                        f'Would you like to include the rule for "{rule.rule_id}" in your benchmark? [Y/n/all/?]: ',
                        str,
                        range_=("y", "n", "all", "?"),
                        default_="y",
                    )
                    if include == "?":
                        print(f"Rule Details: \n{rule.discussion}")
                        include = sanitize_input(
                            f'Would you like to include the rule for "{rule.rule_id}" in your benchmark? [Y/n/all]: ',
                            str,
                            range_=("y", "n", "all"),
                            default_="y",
                        )
                    queried_rule_ids.append(rule.rule_id)
                    get_odv = True
                    rule.remove_odv_custom_rule()
                    if include.lower() == "all":
                        include_all = True
                        include = "y"

            if include.lower() == "y":
                included_rules.append(rule)
                if rule.odv == "missing":
                    continue
                elif get_odv and rule.odv:
                    odv_hint = rule.odv.get("hint", "")
                    odv_recommended = rule.odv.get("recommended")
                    odv_benchmark = rule.odv.get(benchmark)

                    if benchmark == "recommended":
                        print(f"{odv_hint}")
                        odv = sanitize_input(
                            f'Enter the ODV for "{rule.rule_id}" or press Enter for the recommended value ({odv_recommended}): ',
                            type(odv_recommended),
                            default_=odv_recommended,
                        )
                        if odv != odv_recommended:
                            rule.write_odv_custom_rule(odv)
                    else:
                        print(f"\nODV value: {odv_hint}")
                        odv = sanitize_input(
                            f'Enter the ODV for "{rule.rule_id}" or press Enter for the default value ({odv_benchmark}): ',
                            type(odv_benchmark),
                            default_=odv_benchmark,
                        )
                        if odv != odv_benchmark:
                            rule.write_odv_custom_rule(odv)

        return included_rules

    def to_yaml(self, output_path: Path) -> None:
        key_order: list[str] = [
            "id",
            "title",
            "discussion",
            "references",
            "customized",
            "platforms",
            "tags",
            "odv",
            "mobileconfig",
            "mobileconfig_info",
            "ddm_info",
        ]

        required_keys: tuple[str, ...] = (
            "id",
            "title",
            "discussion",
            "references",
            "platforms",
        )

        rule_file_path: Path = output_path / f"{self.rule_id}.yaml"
        serialized_data: dict[str, Any] = self.model_dump()
        ordered_data = OrderedDict()

        self._clean_references()

        serialized_data["references"]["nist"]["800-53r5"] = serialized_data[
            "references"
        ].pop("nist_800_53r5")
        serialized_data["references"]["nist"]["800-171r3"] = serialized_data[
            "references"
        ].pop("nist_800_171")

        for key in serialized_data["references"]:
            if isinstance(serialized_data["references"][key], list):
                serialized_data["references"][key] = sorted(
                    [
                        item
                        for item in serialized_data["references"][key]
                        if item not in [None, "NA", "N/A"]
                    ]
                )

        for key in key_order:
            if key in serialized_data:
                ordered_data[key] = serialized_data[key]

        clean_dict: dict = {
            key: value
            for key, value in ordered_data.items()
            if value or key in required_keys
        }

        create_yaml(rule_file_path, clean_dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the Macsecurityrule instance to a dictionary.

        Returns:
            dict[str, Any]: A dictionary representation of the Macsecurityrule instance.
        """
        return self.model_dump()

    def _clean_references(self) -> None:
        """
        Clean the references dictionary by removing any keys with values that are None or in ("NA", "N/A").
        """

        def clean_dict(d: dict) -> dict:
            return {
                k: clean_dict(v) if isinstance(v, dict) else v
                for k, v in d.items()
                if v is not None and v not in ("NA", "N/A")
            }

        self.references = References(**clean_dict(self.references.model_dump()))

    @staticmethod
    def mobileconfig_info_to_xml(
        mobileconfig_info: list[dict[str, Any]],
    ) -> str:
        """
        Convert the given mobileconfig_info to an XML string using the format_payload method.

        Args:
            mobileconfig_info (list[Mobileconfigpayload]): List of Mobileconfigpayload objects.

        Returns:
            str: XML string representation of the mobileconfig_info.
        """
        if not mobileconfig_info:
            return ""

        output = ""
        for payload in mobileconfig_info:
            output += Macsecurityrule.format_payload(
                payload["payload_type"],
                payload["payload_content"],
                jinja_filter=True,
            )

        return output

    @staticmethod
    def _create_static_value_element(value: Any) -> etree.Element:
        """
        Static helper to create an XML element based on the type of the provided value.

        Args:
            value (Any): The value to be converted into an XML element.

        Returns:
            etree.Element: The created XML element.
        """
        match value:
            case bool():
                return etree.Element("true" if value else "false")
            case int():
                int_element = etree.Element("integer")
                int_element.text = str(value)
                return int_element
            case str():
                str_element = etree.Element("string")
                str_element.text = value
                return str_element
            case list():
                array_element = etree.Element("array")
                for item in value:
                    item_element = etree.SubElement(array_element, "string")
                    item_element.text = item
                return array_element
            case dict():
                dict_element = etree.Element("dict")
                for k, v in value.items():
                    key_elem = etree.SubElement(dict_element, "key")
                    key_elem.text = k
                    dict_element.append(Macsecurityrule._create_static_value_element(v))
                return dict_element
            case _:
                raise ValueError(f"Unsupported value type: {type(value)}")
