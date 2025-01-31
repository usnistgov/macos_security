# macsecurityrule.py

# Standard python modules
import logging
import sys
import base64

from typing import Any, Optional, TypeVar, Generic
from pathlib import Path
from collections import OrderedDict, defaultdict
from enum import Enum
from icecream import ic

# Additional python modules
from lxml import etree
from pydantic import BaseModel

# Local python modules
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml, make_dir, create_yaml
from src.mscp.common_utils.sanatize_input import sanitised_input

# Initialize logger
logger = logging.getLogger(__name__)

T = TypeVar("T", str, int, bool, float, None, list, dict)


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


class Cis(BaseModel):
    benchmark: Optional[list[str]] = ["N/A"]
    controls_v8: Optional[list[float]] = []


    def __getitem__(self, key: str) -> Any:
        if key in self.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")


    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")


class Operatingsystem(BaseModel):
    name: str
    version: list[float]


class Mobileconfigpayload(BaseModel, Generic[T]):
    payload_type: str
    payload_content: dict[str, T]


    def __getitem__(self, key: str) -> T:
        if key in self.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")


    def __setitem__(self, key: str, value: T) -> None:
        if key in self.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")


class References(BaseModel, Generic[T]):
    cci: list[str] = ["N/A"]
    cce: list[str] = ["N/A"]
    nist_controls: list[str] = ["N/A"]
    nist_171: list[str] = ["N/A"]
    disa_stig: list[str] = ["N/A"]
    srg: list[str] = ["N/A"]
    cis: Cis
    cmmc: list[str] = ["N/A"]
    sfr: list[str] = ["N/A"]
    indigo: list[str] = ["N/A"]
    custom_refs: Optional[dict[str, T]] = {}

    class Config:
        extra = "ignore"


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
            raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")


class MacSecurityRule(BaseModel, Generic[T]):
    title: str
    rule_id: str
    severity: str
    discussion: str
    check: str
    fix: str
    references: References
    odv: Optional[dict[str, T]] = {}
    tags: list[str]
    result: dict[str, T]
    result_value: T
    mobileconfig: bool
    mobileconfig_info: list[Mobileconfigpayload]
    ddm_info: dict
    customized: bool
    operating_system: list[Operatingsystem]
    mechanism: str = ""
    section: str = ""

    @classmethod
    def load_rules(cls, rule_ids: list[str], os_name: str, os_version: int, parent_values: str, section: str, custom: bool = False, generate_baseline: bool = False) -> list["MacSecurityRule"]:
        """
        Load MacSecurityRule objects from YAML files for the given rule IDs.

        Args:
            rule_ids (list[str]): List of rule IDs to load.
            os_name (str): Operating system name.
            os_version (int): Operating system version.
            parent_values (str): Parent values to apply when filling in ODV.
            section (str): Section name for the rules.
            custom (bool): Whether to include custom rules.
            generate_baseline (bool): Whether to generate a baseline.

        Returns:
            list[MacSecurityRule]: A list of loaded MacSecurityRule objects.
        """

        logger.info(f"=== LOADING {section.upper()} RULES ===")

        rules_dirs: list[Path] = []
        rules: list[MacSecurityRule] = []
        mobileconfig_info: list[dict[str, T]] = []
        mechanism: str = "Manual"
        os_version_str: str = str(os_version)

        if custom:
            rules_dirs = [
                Path(config["custom"]["rules_dir"], os_name, os_version_str),
                Path(config["defaults"]["rules_dir"], os_name, os_version_str)
            ]
        else:
            rules_dirs = [Path(config["defaults"]["rules_dir"], os_name, os_version_str)]

        for rule_id in rule_ids:
            logger.debug(f"Transforming rule: {rule_id}")

            rule_file = next((file for rules_dir in rules_dirs if rules_dir.exists()
                              for file in rules_dir.rglob(f"{rule_id}.y*ml")), None)
            if not rule_file:
                logger.warning(f"Rule file not found for rule: {rule_id}")
                continue

            rule_yaml: dict = open_yaml(rule_file)
            payloads: list[Mobileconfigpayload] = []

            result = rule_yaml.get("result", "N/A")
            mobileconfig = rule_yaml.get("mobileconfig", False)

            if "base64" in result:
                cls.encode_base64_result(result)

            for result_type in ["integer", "boolean", "string", "base64"]:
                if result_type in result:
                    result_value = result[result_type]
                    break
            else:
                result_value = "N/A"

            if mobileconfig:
                mechanism = "Configuration Profile"

                mobileconfig_info = rule_yaml.get("mobileconfig_info", {})

                if isinstance(mobileconfig_info, dict):
                    for payload_type, payload_content in mobileconfig_info.items():
                        if isinstance(payload_content, dict):
                            payloads.append(Mobileconfigpayload(payload_type=payload_type, payload_content=payload_content))
                        else:
                            logger.warning(f"Invalid payload content for payload type {payload_type}: {payload_content}")
                elif isinstance(mobileconfig_info, list):
                    for entry in mobileconfig_info:
                        payload_type: str = str(entry.get("PayloadType", ""))
                        payload_content = entry.get("PayloadContent", {})
                        logger.debug(f"The payload content type is: {type(payload_content)}")
                        payloads.append(Mobileconfigpayload(payload_type=payload_type, payload_content=payload_content))

            if "[source,bash]" in rule_yaml["fix"]:
                mechanism = "Script"

            match rule_yaml["tags"]:
                case "inherent":
                    mechanism = "The control cannot be configured out of compliance."
                case "permanent":
                    mechanism = "The control is not able to be configured to meet the requirement. It is recommended to implement a third-party solution to meet the control."
                case "not_applicable":
                    mechanism = "The control is not applicable when configuring a macOS system."

            if "800-53r5" in rule_yaml["references"]:
                rule_yaml["references"]["nist_controls"] = rule_yaml["references"].pop("800-53r5")

            if rule_yaml.get("references", {}).get("800-171r3"):
                rule_yaml["references"]["nist_171"] = rule_yaml["references"].pop("800-171r3")

            if rule_yaml.get("references", {}).get("cis", None) is None:
                rule_yaml["references"]["cis"] = Cis().model_dump()
            else:
                if "controls v8" in rule_yaml["references"]["cis"]:
                    rule_yaml["references"]["cis"]["controls_v8"] = rule_yaml["references"]["cis"].pop("controls v8")
                    if type(rule_yaml["references"]["cis"]["controls_v8"]) is not float:
                        rule_yaml["references"]["cis"]["controls_v8"] = None

            rule = cls(
                title=rule_yaml.get("title", "missing").replace('|', '\\|'),
                rule_id=rule_yaml.get("id", "missing").replace('|', '\\|'),
                severity=rule_yaml.get("severity", ""),
                discussion=rule_yaml.get("discussion", "missing").replace('|', '\\|'),
                check=rule_yaml.get("check", "missing").replace('|', '\\|'),
                fix=rule_yaml.get("fix", "").replace('|', '\\|'),
                references=References(**rule_yaml["references"]),
                odv=rule_yaml.get("odv", {}),
                tags=rule_yaml.get("tags", []),
                result=rule_yaml.get("result", {}),
                result_value=result_value,
                mobileconfig=rule_yaml.get("mobileconfig", False),
                mobileconfig_info=payloads,
                customized=rule_yaml.get("references", {}).get("customized", False),
                section=section,
                mechanism=mechanism,
                ddm_info=rule_yaml.get("ddm_info", {}),
                operating_system=rule_yaml.get("operating_system", [])
            )

            if mobileconfig:
                logger.debug(f"Formatting mobileconfig_info for rule: {rule.rule_id}")
                formatted_mobileconfig = rule.format_mobileconfig_fix()
                rule.fix = formatted_mobileconfig
                logger.debug(formatted_mobileconfig)

            if not rule.odv == None and not generate_baseline:
                rule._fill_in_odv(parent_values)

            logger.debug(f"Transformed rule: {rule_id}")

            rules.append(rule)

        logger.debug(f"NUMBER OF {section.upper()} LOADED RULES: {len(rules)}")
        logger.info(f"=== RULES {section.upper()} LOADED ===")

        return rules


    @classmethod
    def collect_all_rules(cls, os_name: str, os_version: int, generate_baseline: bool = True, parent_values: str = "default") -> list["MacSecurityRule"]:
        """
        Populate MacSecurityRule objects from YAML files in a folder.
        Map folder names to specific section filenames for the `section` attribute.

        Args:
            os_name (str): Operating system name.
            os_version (int): Operating system version.
            parent_values (str): Parent values for rule initialization.

        Returns:
            list[MacSecurityRule]: A list of MacSecurityRule instances.
        """
        rules: list[MacSecurityRule] = []
        os_version_str: str = str(os_version)
        sub_sections: list[str] = ["permanent", "inherent", "n_a", "srg", "supplemental"]
        section_dirs: list[Path] = [
            Path(config["custom"]["sections_dir"]),
            Path(config["defaults"]["sections_dir"])
        ]

        rules_dirs: list[Path] = [
            Path(config["custom"]["rules_dir"], os_name, os_version_str),
            Path(config["defaults"]["rules_dir"], os_name, os_version_str)
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
                logger.warning(f"Directory does not exist or is not a directory: {rule_dir}")
                continue

            for folder in rule_dir.iterdir():
                if not folder.is_dir():
                    continue

                for yaml_file in folder.rglob("*.y*ml"):
                    try:
                        rule_yaml: dict = open_yaml(yaml_file)
                        folder_name: str = yaml_file.parent.name
                        logger.debug(f"{rule_yaml["id"]} folder: {folder_name}")
                        section_name: str = section_data.get(Sectionmap[folder_name.upper()].value, "")
                        logger.debug(f"Section Name: {section_name}")
                        custom: bool = False

                        if "custom" in str(folder).lower():
                            custom = True

                        if not section_name:
                            logger.warning(f"Folder '{folder_name}' not found in section mapping.")
                            continue

                        for tag in rule_yaml.get("tags", []):
                            if tag in sub_sections:
                                section_name = section_data.get(Sectionmap[tag.upper()].value, "")

                        rules += cls.load_rules(
                            rule_ids=[rule_yaml.get("id", "")],
                            os_name=os_name,
                            os_version=os_version,
                            parent_values=parent_values,
                            section=section_name,
                            custom=custom,
                            generate_baseline=generate_baseline
                        )

                    except Exception as e:
                        logger.error(f"Failed to load rule from file {yaml_file}: {e}")

        return rules


    def format_mobileconfig_fix(self) -> str:
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
                for nested_payload_type, nested_payload_content in payload.payload_content.items():
                    nested_fix = self._format_payload(nested_payload_type, nested_payload_content)
                    rulefix += nested_fix
            else:
                rulefix += self._format_payload(payload.payload_type, payload.payload_content)

        return rulefix


    def _fill_in_odv(self, parent_values: str) -> None:
        """
        Replaces placeholders ('$ODV') in the instance attributes with the appropriate override value
        based on the parent_values key.

        Args:
            parent_values (str): The key to look up in the 'odv' dictionary.

        Returns:
            None: Modifies the instance attributes in place.
        """
        _has_odv = False
        odv_value = None

    # Ensure odv is a dictionary-like structure
        if isinstance(self.odv, dict):
            odv_lookup = self.odv
        elif isinstance(self.odv, list) and all(isinstance(item, str) for item in self.odv):
            odv_lookup = {str(i): v for i, v in enumerate(self.odv)}  # Map indices to values
        else:
            odv_lookup = {}

        # Extract ODV value
        for key in [parent_values, "custom", "recommended"]:
            if key in odv_lookup:
                odv_value = odv_lookup[key]
                odv_value = str(odv_value) if not isinstance(odv_value, int) else odv_value
                _has_odv = True
                break

        if not _has_odv:
            return

        # Replace $ODV in text fields
        fields_to_process = ["title", "discussion", "check", "fix"]
        for field in fields_to_process:
            if hasattr(self, field) and "$ODV" in getattr(self, field, ""):
                updated_value = getattr(self, field).replace("$ODV", str(odv_value))
                setattr(self, field, updated_value)

        # Replace $ODV in result
        if isinstance(self.result, dict):
            for key, value in self.result.items():
                if isinstance(value, str) and "$ODV" in value:
                    self.result[key] = value.replace("$ODV", str(odv_value))

        # Replace $ODV in mobileconfig_info
        for payload in self.mobileconfig_info:
            for key, value in payload.payload_content.items():
                if isinstance(value, str) and "$ODV" in value:
                    payload.payload_content[key] = value.replace("$ODV", str(odv_value))
                elif isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        if isinstance(subvalue, str) and "$ODV" in subvalue:
                            value[subkey] = subvalue.replace("$ODV", str(odv_value))

        # Replace $ODV in ddm_info
        for key, value in self.ddm_info.items():
            if isinstance(value, str) and "$ODV" in value:
                self.ddm_info[key] = value.replace("$ODV", str(odv_value))
            elif isinstance(value, dict):
                for subkey, subvalue in value.items():
                    if isinstance(subvalue, str) and "$ODV" in subvalue:
                        value[subkey] = subvalue.replace("$ODV", str(odv_value))


    def _format_payload(self, payload_type: str, payload_content: dict) -> str:
        """
        Format a single payload type and its content.

        Args:
            payload_type (str): The type of the payload.
            payload_content (dict): The content of the payload.

        Returns:
            str: A formatted string representing the payload.
        """
        output = (
            f"Create a configuration profile containing the following keys in the ({payload_type}) payload type:\n\n"
        )
        output += "[source,xml]\n----\n"

        # Generate XML for the payload content
        root = etree.Element("Payload", attrib={}, nsmap=None)
        self._add_payload_content(root, payload_content)

        elements = []
        for key, value in payload_content.items():
            # Create a <key> element
            key_element = etree.Element("key", attrib={}, nsmap=None)
            key_element.text = key
            elements.append(key_element)

            # Create the corresponding value element
            value_element = self._create_value_element(value)
            elements.append(value_element)

        # Pretty-print each element individually
        for element in elements:
            output += etree.tostring(element, encoding="unicode", pretty_print=True).strip() + "\n"

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
            key_element = etree.SubElement(parent, "key", attrib={}, nsmap=None)
            key_element.text = key

            match value:
                case bool():
                    etree.SubElement(parent, "true" if value else "false", attrib={}, nsmap=None)
                case int():
                    int_element = etree.SubElement(parent, "integer", attrib={}, nsmap=None)
                    int_element.text = str(value)
                case str():
                    str_element = etree.SubElement(parent, "string", attrib={}, nsmap=None)
                    str_element.text = value
                case list():
                    array_element = etree.SubElement(parent, "array", attrib={}, nsmap=None)
                    for item in value:
                        item_element = etree.SubElement(array_element, "string", attrib={}, nsmap=None)
                        item_element.text = item
                case dict():
                    dict_element = etree.SubElement(parent, "dict", attrib={}, nsmap=None)
                    MacSecurityRule._add_payload_content(dict_element, value)
                case _:
                    raise ValueError(f"Unsupported value type: {type(value)} for key: {key}")


    def _create_value_element(self, value):
        """
        Create an XML element for a value based on its type.

        Args:
            value (Any): The value to convert into an XML element.

        Returns:
            etree.Element: The created XML element.
        """
        if isinstance(value, bool):
            return etree.Element("true" if value else "false", attrib={}, nsmap=None)
        elif isinstance(value, int):
            int_element = etree.Element("integer", attrib={}, nsmap=None)
            int_element.text = str(value)
            return int_element
        elif isinstance(value, str):
            str_element = etree.Element("string", attrib={}, nsmap=None)
            str_element.text = value
            return str_element
        elif isinstance(value, list):
            array_element = etree.Element("array", attrib={}, nsmap=None)
            for item in value:
                item_element = etree.SubElement(array_element, "string", attrib={}, nsmap=None)
                item_element.text = item
            return array_element
        elif isinstance(value, dict):
            dict_element = etree.Element("dict", attrib={}, nsmap=None)
            self._add_payload_content(dict_element, value)
            return dict_element
        else:
            raise ValueError(f"Unsupported value type: {type(value)}")


    def get(self, attr, default=None):
        return getattr(self, attr, default)


    @staticmethod
    def encode_base64_result(result: dict[str, Any]) -> str:
        """
        Encodes the 'base64' key's value in the given dictionary into Base64 format,
        updates the dictionary with the encoded value, and returns the encoded string.

        Args:
            result (Dict[str, Any]): A dictionary with a 'base64' key containing a string value.

        Returns:
            str: The Base64-encoded string.
        """
        if "base64" in result:
            result_string_bytes: bytes = f'{result["base64"]}\n'.encode("UTF-8")
            result_encoded: bytes = base64.b64encode(result_string_bytes)
            result["base64"] = result_encoded.decode()
            return result["base64"]

        return ""


    @staticmethod
    def write_odv_custom_rule(rule, odv: Any) -> None:
        rule_file_path: Path = Path(config["custom"]["rules"][rule.section], f"{rule.rule_id}.yaml")

        make_dir(rule_file_path.parent)

        rule['odv'] = {"custom": odv}

        create_yaml(rule_file_path, rule, "rule")


    @staticmethod
    def remove_odv_custom_rule(rule) -> None:
        rule_file_path: Path = Path(config["custom"]["rules"][rule.section], f"{rule.rule_id}.yaml")

        if not rule_file_path.exists():
            return

        if "odv" in rule and "custom" in rule["odv"]:
            del rule["odv"]["custom"]

            create_yaml(rule_file_path, rule, "rule")


    @classmethod
    def odv_query(cls, rules: list["MacSecurityRule"], benchmark: str) -> list["MacSecurityRule"]:
        """
        Queries the user to include/exclude rules and set Organizational Defined Values (ODVs).

        Args:
            rules (list[MacSecurityRule]): List of rules to process.
            benchmark (str): The benchmark being tailored (e.g., "recommended").

        Returns:
            list[MacSecurityRule]: List of included rules after user input and ODV modifications.
        """
        print(
            "The inclusion of any given rule is a risk-based-decision (RBD). "
            "While each rule is mapped to an 800-53 control, deploying it in your organization "
            "should be part of the decision-making process.\n"
        )

        if benchmark != "recommended":
            print(
                f"WARNING: You are tailoring an established benchmark. Excluding rules or modifying ODVs "
                "may result in non-compliance with the benchmark.\n"
            )

        included_rules = []
        queried_rule_ids = []
        include_all = False
        _always_include = ["inherent"]

        for rule in rules:
            get_odv = False

            # Default inclusion logic for certain tags
            if any(tag in rule.tags for tag in _always_include):
                include = "y"
            elif include_all:
                if rule.rule_id not in queried_rule_ids:
                    include = "y"
                    get_odv = True
                    queried_rule_ids.append(rule.rule_id)
                    cls.remove_odv_custom_rule(rule)
            else:
                if rule.rule_id not in queried_rule_ids:
                    include = sanitised_input(
                        f"Would you like to include the rule for \"{rule.rule_id}\" in your benchmark? [Y/n/all/?]: ",
                        str,
                        range_=("y", "n", "all", "?"),
                        default_="y",
                    )
                    if include == "?":
                        print(f"Rule Details: \n{rule.discussion}")
                        include = sanitised_input(
                            f"Would you like to include the rule for \"{rule.rule_id}\" in your benchmark? [Y/n/all]: ",
                            str,
                            range_=("y", "n", "all"),
                            default_="y",
                        )
                    queried_rule_ids.append(rule.rule_id)
                    get_odv = True
                    cls.remove_odv_custom_rule(rule)
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
                        odv = sanitised_input(
                            f'Enter the ODV for "{rule.rule_id}" or press Enter for the recommended value ({odv_recommended}): ',
                            type(odv_recommended),
                            default_=odv_recommended,
                        )
                        if odv != odv_recommended:
                            cls.write_odv_custom_rule(rule, odv)
                    else:
                        print(f"\nODV value: {odv_hint}")
                        odv = sanitised_input(
                            f'Enter the ODV for "{rule.rule_id}" or press Enter for the default value ({odv_benchmark}): ',
                            type(odv_benchmark),
                            default_=odv_benchmark,
                        )
                        if odv != odv_benchmark:
                            cls.write_odv_custom_rule(rule, odv)

        return included_rules


    def to_yaml(self, output_path: Path) -> None:
        key_order: list[str] = ["id", "title", "discussion", "check", "result", "fix", "references", "customized", "operating_system", "tags", "severity", "odv", "mobileconfig", "mobileconfig_info", "ddm_info"]
        required_keys: list[str] = ["id", "title", "discussion", "check", "fix", "operating_system", "references"]
        rule_file_path: Path = output_path / f"{self.rule_id}.yaml"
        serialized_data: dict[str, Any] = self.model_dump()
        ordered_data = OrderedDict()

        serialized_data["references"]["800-53r5"] = serialized_data["references"].pop("nist_controls")
        serialized_data["references"]["800-171r3"] = serialized_data["references"].pop("nist_171")

        for key in serialized_data["references"]:
            serialized_data["references"][key].sort()

        for key in key_order:
            if key in serialized_data:
                ordered_data[key] = serialized_data[key]

        clean_dict: dict = {key:value
                            for key, value in ordered_data.items()
                            if value or key in required_keys}

        create_yaml(rule_file_path, clean_dict, "rule")


    def to_dict(self) -> dict[str, T]:
        """Convert the MacSecurityRule instance to a dictionary"""
        return self.model_dump()


    @staticmethod
    def get_tags(rules: list["MacSecurityRule"], list_tags: bool = False) -> list[str]:
        """
        Generate a sorted list of unique tags from the provided rules, optionally
        print the tags if list_tags is True.

        Args:
            rules (list[MacSecurityRule]): List of all MacSecurityRule objects.
            list_tags (bool): If True, prints all unique tags.

        Returns:
            list[str]: Sorted list of unique tags, including 'all_rules'.
        """

        all_tags = sorted(set(tag for rule in rules for tag in rule.tags))
        if "all_rules" not in all_tags:
            all_tags.append("all_rules")
        all_tags.sort()

        if list_tags:
            for tag in all_tags:
                print(tag)

        return all_tags


    def __getitem__(self, key: str) -> Any:
        if key in self.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")
