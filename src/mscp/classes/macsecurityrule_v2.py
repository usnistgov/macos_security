# macsecurityrule.py

# Standard python modules
import base64
from collections import OrderedDict
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from loguru import logger

# Additional python modules
from lxml import etree
from pydantic import BaseModel, ConfigDict, Field

# Local python modules
from src.mscp.common_utils import (
    config,
    create_yaml,
    get_version_data,
    make_dir,
    open_yaml,
    sanitize_input,
)


class Sectionmap(Enum):
    AUDIT = "auditing"
    AUTH = "authentication"
    ICLOUD = "icloud"
    INHERENT = "inherent"
    OS = "operatingsystem"
    NOT_APPLICABLE = "not_applicable"
    PWPOLICY = "passwordpolicy"
    PERMANENT = "permanent"
    SRG = "srg"
    SUPPLEMENTAL = "supplemental"
    SYSTEM_SETTINGS = "systemsettings"


class NistReferences(BaseModel):
    cce: dict[str, list[str]] | None = None
    nist_800_53r5: list[str] | None = None
    nist_800_171r3: list[str] | None = None

    def get(self, attr, default=None):
        return getattr(self, attr, default)

    def __getitem__(self, key: str) -> Any:
        if key in self.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(
                f"{key} is not a valid attribute of {self.__class__.__name__}"
            )


class DisaReferences(BaseModel):
    cci: list[str] | None = None
    srg: list[str] | None = None
    disa_stig: dict[str, list[str]] | None = None
    cmmc: list[str] | None = None

    def get(self, attr, default=None):
        return getattr(self, attr, default)

    def __getitem__(self, key: str) -> Any:
        if key in self.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(
                f"{key} is not a valid attribute of {self.__class__.__name__}"
            )


class CisReferences(BaseModel):
    benchmark: dict[str, list[str]] | None = None
    controls_v8: list[str] | None = None

    def get(self, attr, default=None):
        return getattr(self, attr, default)

    def __getitem__(self, key: str) -> Any:
        if key in self.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(
                f"{key} is not a valid attribute of {self.__class__.__name__}"
            )


class bisReferences(BaseModel):
    indigo: list[str] | None = None

    def get(self, attr, default=None):
        return getattr(self, attr, default)

    def __getitem__(self, key: str) -> Any:
        if key in self.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(
                f"{key} is not a valid attribute of {self.__class__.__name__}"
            )


class Mobileconfigpayload(BaseModel):
    payload_type: str
    payload_content: dict[str, Any]

    def get(self, attr, default=None):
        return getattr(self, attr, default)

    def __getitem__(self, key: str) -> Any:
        if key in self.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(
                f"{key} is not a valid attribute of {self.__class__.__name__}"
            )


class References(BaseModel):
    model_config: ConfigDict = ConfigDict(extra="ignore")

    nist: NistReferences
    disa: DisaReferences | None = None
    cis: CisReferences | None = None
    bis: bisReferences | None = None

    def get(self, attr, default=None):
        return getattr(self, attr, default)

    def __getitem__(self, key: str) -> Any:
        if key in self.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(
                f"{key} is not a valid attribute of {self.__class__.__name__}"
            )


class Platformconfig(BaseModel):
    severity: str
    benchmarks: list[str]
    fix: str | None = None


class Platformconfigios(Platformconfig):
    supervised: bool


class Platform(BaseModel):
    model_config: ConfigDict = ConfigDict(extra="ignore")

    check: str
    result: dict[str, Any]
    fix: str
    sequoia: Platformconfig | None = None
    sonoma: Platformconfig | None = None
    ventura: Platformconfig | None = None
    monterey: Platformconfig | None = None
    big_sur: Platformconfig | None = None
    catalina: Platformconfig | None = None
    ios_16: Platformconfigios | None = None
    ios_17: Platformconfigios | None = None
    ios_18: Platformconfigios | None = None

    def get(self, attr, default=None):
        return getattr(self, attr, default)

    def __getitem__(self, key: str) -> Any:
        if key in self.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(
                f"{key} is not a valid attribute of {self.__class__.__name__}"
            )


class Macsecurityrule(BaseModel):
    """
    Represents a security rule for macOS systems.

    Attributes:
        title (str): The title of the security rule.
        rule_id (str): The unique identifier for the rule.
        severity (str): The severity level of the rule.
        discussion (str): A detailed discussion about the rule.
        check (str): Instructions on how to check compliance with the rule.
        fix (str): Instructions on how to fix non-compliance with the rule.
        references (References): References related to the rule.
        odv (dict[str, Any]]): Organizational Defined Values (ODVs) for the rule.
        finding (bool): Indicates if the rule is a finding.
        tags (list[str]): Tags associated with the rule.
        result (dict[str, Any]): The result of the rule check.
        result_value (Any): The value of the result.
        mobileconfig (bool): Indicates if the rule is related to mobile configuration.
        mobileconfig_info (list[Mobileconfigpayload]): Information about mobile configuration payloads.
        ddm_info (dict): Additional information for Device Deployment Management (DDM).
        customized (bool): Indicates if the rule is customized.
        operating_system (list[Operatingsystem]): List of operating systems the rule applies to.
        mechanism (str): The mechanism used to enforce the rule.
        section (str): The section the rule belongs to.
        uuid (str): The unique identifier for the rule instance.

    Methods:
        load_rules: Loads Macsecurityrule objects from YAML files for the given rule IDs.
        collect_all_rules: Populates Macsecurityrule objects from YAML files in a folder.
        format_mobileconfig_fix: Generates a formatted XML-like string for the `mobileconfig_info` field.
        _fill_in_odv: Replaces placeholders ('$ODV') in the instance attributes with the appropriate override value.
        _format_payload: Formats a single payload type and its content.
        encode_base64_result: Encodes the 'base64' key's value in the given dictionary into Base64 format.
        write_odv_custom_rule: Writes a custom ODV value to a rule file.
        remove_odv_custom_rule: Removes a custom ODV value from a rule file.
        odv_query: Queries the user to include/exclude rules and set Organizational Defined Values (ODVs).
        to_yaml: Serializes the Macsecurityrule instance to a YAML file.
        to_dict: Converts the Macsecurityrule instance to a dictionary.
        get_tags: Generates a sorted list of unique tags from the provided rules.
    """

    title: str
    rule_id: str
    severity: str
    discussion: str
    references: References
    odv: dict[str, Any] | None = None
    finding: bool = False
    tags: list[str]
    result_value: Any
    mobileconfig: bool
    mobileconfig_info: list[Mobileconfigpayload]
    ddm_info: dict[str, Any]
    customized: bool
    mechanism: str
    section: str | None
    uuid: str = Field(default_factory=lambda: str(uuid4()))
    platforms: dict[str, Platform]
    os_name: str

    @classmethod
    @logger.catch
    def load_rules(
        cls,
        rule_ids: list[str],
        os_type: str,
        os_version: int,
        parent_values: str,
        section: str,
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

        rules_dirs: list[Path] = []
        rules: list[Macsecurityrule] = []
        mobileconfig_info: list[dict[str, Any]] = []
        mechanism: str = "Manual"
        os_version_str: str = str(os_version)
        current_version_data: dict = get_version_data(os_type, os_version)

        os_name: str = current_version_data["os_name"]

        if custom:
            rules_dirs = [
                Path(config["custom"]["rules_dir"], os_type, os_version_str),
                Path(config["defaults"]["rules_dir"], os_type, os_version_str),
            ]
        else:
            rules_dirs = [
                Path(config["defaults"]["rules_dir"], os_type, os_version_str)
            ]

        for rule_id in rule_ids:
            logger.debug("Transforming rule: {}", rule_id)

            rule_file = next(
                (
                    file
                    for rules_dir in rules_dirs
                    if rules_dir.exists()
                    for file in rules_dir.rglob(f"{rule_id}.y*ml")
                ),
                None,
            )
            if not rule_file:
                logger.warning("Rule file not found for rule: {}", rule_id)
                continue

            rule_yaml: dict = open_yaml(rule_file)
            payloads: list[Mobileconfigpayload] = []

            for k, v in rule_yaml.items():
                if k in ["title", "id", "discussion", "check", "fix"]:
                    rule_yaml[k] = v.replace("|", "\\|")

            rule_yaml["rule_id"] = rule_yaml.pop("id")

            result_value: str | int | bool | None = None

            if not rule_yaml.get("platforms").get(os_name).get("result"):
                rule_yaml["platforms"][os_name]["result"] = (
                    rule_yaml.get("platforms").get(os_name).get("result", None)
                )
            else:
                if isinstance(rule_yaml["result"], dict):
                    for k, v in rule_yaml["result"].items():
                        if isinstance(v, (int, bool, str)):
                            result_value = v
                            break
                        elif k == "base64":
                            result_value = cls._encode_base64_result(v)
                            break

            if rule_yaml["mobileconfig"]:
                mechanism = "Configuration Profile"

                mobileconfig_info = rule_yaml.get("mobileconfig_info", [{}])

                if isinstance(mobileconfig_info, dict):
                    for payload_type, payload_content in mobileconfig_info.items():
                        if isinstance(payload_content, dict):
                            payloads.append(
                                Mobileconfigpayload(
                                    payload_type=payload_type,
                                    payload_content=payload_content,
                                )
                            )
                        else:
                            logger.warning(
                                "Invalid payload content for payload type {}: {}",
                                payload_type,
                                payload_content,
                            )
                elif isinstance(mobileconfig_info, list):
                    for entry in mobileconfig_info:
                        payload_type: str = str(entry.get("PayloadType", ""))
                        payload_content = entry.get("PayloadContent", {})
                        logger.debug(
                            "The payload content type is: {}", type(payload_content)
                        )
                        payloads.append(
                            Mobileconfigpayload(
                                payload_type=payload_type,
                                payload_content=payload_content,
                            )
                        )

                rule_yaml.pop("mobileconfig_info", None)

            if "[source,bash]" in rule_yaml["fix"]:
                mechanism = "Script"

            match rule_yaml["tags"]:
                case "inherent":
                    mechanism = "The control cannot be configured out of compliance."
                case "permanent":
                    mechanism = "The control is not able to be configured to meet the requirement. It is recommended to implement a third-party solution to meet the control."
                case "not_applicable":
                    mechanism = (
                        "The control is not applicable when configuring a macOS system."
                    )

            if rule_yaml["references"]["nist"]["800-53r5"]:
                rule_yaml["references"]["nist"]["nist_800_53r5"] = rule_yaml[
                    "references"
                ]["nist"].pop("800-53r5")

            if rule_yaml["references"]["nist"]["800-171r3"]:
                rule_yaml["references"]["nist"]["nist_800_171r3"] = rule_yaml[
                    "references"
                ]["nist"].pop("800-171r3")

            if not rule_yaml["references"]["cis"]:
                rule_yaml["references"]["cis"] = None
            else:
                if "controls v8" in rule_yaml["references"]["cis"]:
                    rule_yaml["references"]["cis"]["controls_v8"] = rule_yaml[
                        "references"
                    ]["cis"].pop("controls v8")
                    if type(rule_yaml["references"]["cis"]["controls_v8"]) is not float:
                        rule_yaml["references"]["cis"]["controls_v8"] = None

            if not rule_yaml.get("odv", None):
                rule_yaml["odv"] = None

            if not rule_yaml.get("ddm_info", None):
                rule_yaml["ddm_info"] = None

            rule = cls(
                **rule_yaml,
                result_value=result_value,
                mobileconfig_info=payloads,
                mechanism=mechanism,
                section=section,
                os_name=os_name,
            )

            if rule.mobileconfig:
                logger.debug("Formatting mobileconfig_info for rule: {}", rule.rule_id)
                formatted_mobileconfig = rule._format_mobileconfig_fix()
                rule["platforms"][os_name]["fix"] = formatted_mobileconfig
                logger.success("Formatted mobileconfig_info for rule: {}", rule.rule_id)

            if rule.odv is not None and not generate_baseline:
                rule._fill_in_odv(parent_values)

            logger.success("Transformed rule: {}", rule_id)

            rules.append(rule)

        logger.debug("NUMBER OF {} LOADED RULES: {}", section.upper(), len(rules))
        logger.info("=== RULES {} LOADED ===", section.upper())

        return rules

    @classmethod
    @logger.catch
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
        rules: list[Macsecurityrule] = []
        os_version_str: str = str(os_version)
        sub_sections: list[str] = [
            "permanent",
            "inherent",
            "n_a",
            "srg",
            "supplemental",
        ]
        section_dirs: list[Path] = [
            Path(config["custom"]["sections_dir"]),
            Path(config["defaults"]["sections_dir"]),
        ]

        rules_dirs: list[Path] = [
            Path(config["custom"]["rules_dir"], os_type, os_version_str),
            Path(config["defaults"]["rules_dir"], os_type, os_version_str),
        ]

        section_data: dict = {
            section_file.stem: open_yaml(section_file).get("name", "")
            for section_dir in section_dirs
            for section_file in section_dir.glob("*.y*ml")
            if section_file.is_file()
        }

        # Iterate through each folder in the base path
        for rule_dir in rules_dirs:
            if not rule_dir.exists() or not rule_dir.is_dir():
                logger.warning(
                    "Directory does not exist or is not a directory: {}", rule_dir
                )
                continue

            for folder in rule_dir.iterdir():
                if not folder.is_dir():
                    continue

                for yaml_file in folder.rglob("*.y*ml"):
                    try:
                        rule_yaml: dict = open_yaml(yaml_file)
                        folder_name: str = yaml_file.parent.name
                        logger.debug("{} folder: {}", rule_yaml["id"], folder_name)
                        section_name: str = section_data.get(
                            Sectionmap[folder_name.upper()].value, ""
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

                        for tag in rule_yaml.get("tags", []):
                            if tag in sub_sections:
                                section_name = section_data.get(
                                    Sectionmap[tag.upper()].value, ""
                                )

                        rules += cls.load_rules(
                            rule_ids=[rule_yaml.get("id", "")],
                            os_type=os_type,
                            os_version=os_version,
                            parent_values=parent_values,
                            section=section_name,
                            custom=custom,
                            generate_baseline=generate_baseline,
                        )

                    except Exception as e:
                        logger.error(
                            "Failed to load rule from file {}: {}", yaml_file, e
                        )

        return rules

    @logger.catch
    def _format_mobileconfig_fix(self) -> str:
        """
        Generate a formatted XML-like string for the `mobileconfig_info` field.

        Handles special cases such as `com.apple.ManagedClient.preferences`.

        Returns:
            str: A formatted string representing the mobileconfig payloads.
        """
        if not self.mobileconfig_info:
            return "No mobileconfig info available for this rule.\n"

        rulefix = ""

        for payload in self.mobileconfig_info:
            if payload.payload_type == "com.apple.ManagedClient.preferences":
                rulefix += (
                    f"NOTE: The following settings are in the ({payload.payload_type}) payload. "
                    "This payload requires the additional settings to be sub-payloads within, "
                    "containing their defined payload types.\n\n"
                )
                # Recursively process nested payloads
                for (
                    nested_payload_type,
                    nested_payload_content,
                ) in payload.payload_content.items():
                    nested_fix = self._format_payload(
                        nested_payload_type, nested_payload_content
                    )
                    rulefix += nested_fix
            else:
                rulefix += self._format_payload(
                    payload.payload_type, payload.payload_content
                )

        return rulefix

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
        odv_value: str | int | bool | None = None

        if self.odv is None:
            logger.warning("No ODV dictionary found for rule: {}", self.rule_id)
            return

        odv_lookup: dict[str, Any] = self.odv
        odv_value = odv_lookup.get(parent_values)

        # Replace $ODV in text fields
        fields_to_process: tuple[str, ...] = ("title", "discussion", "check", "fix")
        for field in fields_to_process:
            if hasattr(self, field) and "$ODV" in getattr(self, field, ""):
                updated_value = getattr(self, field).replace("$ODV", str(odv_value))
                setattr(self, field, updated_value)

        # Replace $ODV in result
        if isinstance(self["platforms"][self.os_name]["result"], dict):
            for key, value in self["platforms"][self.os_name]["result"].items():
                if isinstance(value, str) and "$ODV" in value:
                    self["platforms"][self.os_name]["result"][key] = value.replace(
                        "$ODV", str(odv_value)
                    )

        # Replace $ODV in mobileconfig_info
        if self.mobileconfig_info is not None:
            for payload in self.mobileconfig_info:
                for key, value in payload.payload_content.items():
                    if isinstance(value, str) and "$ODV" in value:
                        payload.payload_content[key] = value.replace(
                            "$ODV", str(odv_value)
                        )
                    elif isinstance(value, dict):
                        for subkey, subvalue in value.items():
                            if isinstance(subvalue, str) and "$ODV" in subvalue:
                                value[subkey] = subvalue.replace("$ODV", str(odv_value))

        # Replace $ODV in ddm_info
        if self.ddm_info is not None:
            for key, value in self.ddm_info.items():
                if isinstance(value, str) and "$ODV" in value:
                    self.ddm_info[key] = value.replace("$ODV", str(odv_value))
                elif isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        if isinstance(subvalue, str) and "$ODV" in subvalue:
                            value[subkey] = subvalue.replace("$ODV", str(odv_value))

    @logger.catch
    def _format_payload(self, payload_type: str, payload_content: dict) -> str:
        """
        Format a single payload type and its content.

        Args:
            payload_type (str): The type of the payload.
            payload_content (dict): The content of the payload.

        Returns:
            str: A formatted string representing the payload.
        """
        output = f"Create a configuration profile containing the following keys in the ({payload_type}) payload type:\n\n"
        output += "[source,xml]\n----\n"

        # Generate XML for the payload content
        root = etree.Element("Payload", attrib=None, nsmap=None)
        self._add_payload_content(root, payload_content)

        elements = []
        for key, value in payload_content.items():
            # Create a <key> element
            key_element = etree.Element("key", attrib=None, nsmap=None)
            key_element.text = key
            elements.append(key_element)

            # Create the corresponding value element
            value_element = self._create_value_element(value)
            elements.append(value_element)

        # Pretty-print each element individually
        for element in elements:
            output += (
                etree.tostring(element, encoding="unicode", pretty_print=True).strip()
                + "\n"
            )

        output += "----\n\n"
        return output

    @staticmethod
    @logger.catch
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

    @logger.catch
    def _create_value_element(self, value: Any) -> etree.Element:
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
                self._add_payload_content(dict_element, value)
                return dict_element
            case _:
                logger.error(
                    "Unsupported value type: {} for value: {}", type(value), value
                )
                raise ValueError(f"Unsupported value type: {type(value)}")

    @staticmethod
    @logger.catch
    def _encode_base64_result(result: dict[str, Any]) -> str:
        """
        Encodes the 'base64' key's value in the given dictionary into Base64 format,
        updates the dictionary with the encoded value, and returns the encoded string.

        Args:
            result (dict[str, Any]): A dictionary with a 'base64' key containing a string value.

        Returns:
            str: The Base64-encoded string.
        """
        if "base64" in result:
            result_string_bytes: bytes = f"{result['base64']}\n".encode("UTF-8")
            result_encoded: bytes = base64.b64encode(result_string_bytes)
            result["base64"] = result_encoded.decode()
            return result["base64"]

        return ""

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

        self.to_yaml(rule_file_path)

    @classmethod
    @logger.catch
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

    @logger.catch
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

    @logger.catch
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
    @logger.catch
    def get_tags(rules: list["Macsecurityrule"], list_tags: bool = False) -> list[str]:
        """
        Generate a sorted list of unique tags from the provided rules, optionally
        print the tags if list_tags is True.

        Args:
            rules (list[Macsecurityrule]): List of all Macsecurityrule objects.
            list_tags (bool): If True, prints all unique tags.

        Returns:
            list[str]: Sorted list of unique tags, including 'all_rules'.
        """

        all_tags: list[str] = sorted(set(tag for rule in rules for tag in rule.tags))

        if "all_rules" not in all_tags:
            all_tags.append("all_rules")

        all_tags.sort()

        if list_tags:
            for tag in all_tags:
                print(tag)

        return all_tags

    def get(self, attr, default=None):
        return getattr(self, attr, default)

    def __getitem__(self, key: str) -> Any:
        if key in self.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(
                f"{key} is not a valid attribute of {self.__class__.__name__}"
            )
