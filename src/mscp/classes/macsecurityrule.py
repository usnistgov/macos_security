# macsecurityrule.py

# Standard python modules
import logging
import sys
import base64

from typing import List, Dict, Any, Optional
from pathlib import Path

# Additional python modules
from lxml import etree
from pydantic import BaseModel

# Local python modules
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml, make_dir, create_yaml
from src.mscp.common_utils.sanatize_input import sanitised_input

# Initialize logger
logger = logging.getLogger(__name__)

class Cis(BaseModel):
    benchmark: Optional[List[str]] = []
    controls_v8: Optional[List[float]] = []


class Mobileconfigpayload(BaseModel):
    payload_type: str
    payload_content: Dict[str, Any]


class MacSecurityRule(BaseModel):
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
    odv: Optional[Dict[str, Any]] = {}
    tags: List[str]
    result: Any
    result_value: str | int
    mobileconfig: bool
    mobileconfig_info: List[Mobileconfigpayload]
    ddm_info: dict
    customized: bool
    mechanism: str = ""
    section: str = ""

    @classmethod
    def load_rules(cls, rule_ids: List[str], os_name: str, os_version: int, parent_values: str, section: str, custom: bool = False, generate_baseline: bool = False) -> List["MacSecurityRule"]:
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
        rules: List[MacSecurityRule] = []
        mobileconfig_info: List = []
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
            rule_file = next((file for rules_dir in rules_dirs if rules_dir.exists()
                              for file in rules_dir.rglob(f"{rule_id}.y*ml")), None)
            if not rule_file:
                logger.warning(f"Rule file not found for rule: {rule_id}")
                continue

            rule_yaml: dict = open_yaml(rule_file)
            payloads: List[Mobileconfigpayload] = []

            result = rule_yaml.get("result", "N/A")
            mobileconfig = rule_yaml.get("mobileconfig", False)

            if "base64" in result:
                cls.encode_base64_result(result)  # Apply Base64 encoding
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
                        payloads.append(Mobileconfigpayload(payload_type=payload_type, payload_content=payload_content))
                elif isinstance(mobileconfig_info, list):
                    for entry in mobileconfig_info:
                        payload_type = entry.get("PayloadType")
                        payload_content = entry.get("PayloadContent", {})
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

            rule = cls(
                title=rule_yaml.get("title", "missing").replace('|', '\\|'),
                rule_id=rule_yaml.get("id", "missing").replace('|', '\\|'),
                severity=rule_yaml.get("severity", ""),
                discussion=rule_yaml.get("discussion", "missing").replace('|', '\\|'),
                check=rule_yaml.get("check", "missing").replace('|', '\\|'),
                fix=rule_yaml.get("fix", "").replace('|', '\\|'),
                cci=rule_yaml.get("references", {}).get("cci", []),
                cce=rule_yaml.get("references", {}).get("cce", []),
                nist_171=rule_yaml.get("references", {}).get("800-171r3", []),
                nist_controls=rule_yaml.get("references", {}).get("800-53r4", []),
                disa_stig=rule_yaml.get("references", {}).get("disa_stig", []),
                srg=rule_yaml.get("references", {}).get("srg", []),
                sfr=rule_yaml.get("references", {}).get("sfr", []),
                cis = Cis(**rule_yaml.get("references", {}).get("cis", {})),
                cmmc=rule_yaml.get("references", {}).get("cmmc", []),
                indigo=rule_yaml.get("references", {}).get("indigo", []),
                custom_refs=rule_yaml.get("custom_refs", []),
                odv=rule_yaml.get("odv", {}),
                tags=rule_yaml.get("tags", []),
                result=rule_yaml.get("result", {}),
                result_value=result_value,
                mobileconfig=rule_yaml.get("mobileconfig", False),
                mobileconfig_info=payloads,
                customized=rule_yaml.get("references", {}).get("customized", False),
                section=section,
                mechanism=mechanism,
                ddm_info=rule_yaml.get("ddm_info", {})
            )

            if mobileconfig:
                logger.debug(f"Formatting mobileconfig_info for rule: {rule.rule_id}")
                formatted_mobileconfig = rule.format_mobileconfig_fix()
                rule.fix = formatted_mobileconfig
                logger.debug(formatted_mobileconfig)

            if not rule.odv == None and generate_baseline:
                rule._fill_in_odv(parent_values)

            rules.append(rule)

        return rules


    @classmethod
    def collect_all_rules(cls, os_name: str, os_version: int, parent_values: str) -> List["MacSecurityRule"]:
        """
        Populate MacSecurityRule objects from YAML files in a folder.
        Map folder names to specific section filenames for the `section` attribute.

        Args:
            os_name (str): Operating system name.
            os_version (int): Operating system version.
            parent_values (str): Parent values for rule initialization.

        Returns:
            List[MacSecurityRule]: A list of MacSecurityRule instances.
        """
        rules: List[MacSecurityRule] = []
        os_version_str: str = str(os_version)
        sub_sections: list[str] = ["permanent", "inherent", "n_a", "srg", "supplemental"]
        section_dirs: List[Path] = [
            Path(config["custom"]["sections_dir"]),
            Path(config["defaults"]["sections_dir"])
        ]

        rules_dirs: List[Path] = [
            Path(config["custom"]["rules_dir"], os_name, os_version_str),
            Path(config["defaults"]["rules_dir"], os_name, os_version_str)
        ]

        section_map: dict = {
            "audit": "auditing",
            "auth": "authentication",
            "icloud": "icloud",
            "inherent": "inherent",
            "os": "macos",
            "not_applicable": "not_applicable",
            "pwpolicy": "passwordpolicy",
            "permanent": "permanent",
            "srg": "srg",
            "supplemental": "supplemental",
            "system_settings": "systemsettings"
        }

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
                        section_name: str = section_data.get(section_map.get(folder_name, ""), "")
                        custom: bool = False

                        if "custom" in str(folder).lower():
                            custom = True

                        if not section_name:
                            logger.warning(f"Folder '{folder_name}' not found in section mapping.")
                            continue

                        for tag in rule_yaml.get("tags", []):
                            if tag in sub_sections:
                                section_name = section_data.get(section_map.get(tag, ""), "")

                        rules += cls.load_rules(
                            rule_ids=[rule_yaml.get("id", "")],
                            os_name=os_name,
                            os_version=os_version,
                            parent_values=parent_values,
                            section=section_name,
                            custom=custom,
                            generate_baseline=True
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
        root = etree.Element("Payload")
        self._add_payload_content(root, payload_content)

        elements = []
        for key, value in payload_content.items():
            # Create a <key> element
            key_element = etree.Element("key")
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
            key_element = etree.SubElement(parent, "key")
            key_element.text = key

            match value:
                case bool():
                    etree.SubElement(parent, "true" if value else "false")
                case int():
                    int_element = etree.SubElement(parent, "integer")
                    int_element.text = str(value)
                case str():
                    str_element = etree.SubElement(parent, "string")
                    str_element.text = value
                case list():
                    array_element = etree.SubElement(parent, "array")
                    for item in value:
                        item_element = etree.SubElement(array_element, "string")
                        item_element.text = item
                case dict():
                    dict_element = etree.SubElement(parent, "dict")
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
            return etree.Element("true" if value else "false")
        elif isinstance(value, int):
            int_element = etree.Element("integer")
            int_element.text = str(value)
            return int_element
        elif isinstance(value, str):
            str_element = etree.Element("string")
            str_element.text = value
            return str_element
        elif isinstance(value, list):
            array_element = etree.Element("array")
            for item in value:
                item_element = etree.SubElement(array_element, "string")
                item_element.text = item
            return array_element
        elif isinstance(value, dict):
            dict_element = etree.Element("dict")
            self._add_payload_content(dict_element, value)
            return dict_element
        else:
            raise ValueError(f"Unsupported value type: {type(value)}")


    def get(self, attr, default=None):
        return getattr(self, attr, default)


    @staticmethod
    def encode_base64_result(result: Dict[str, Any]) -> str:
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

        create_yaml(rule_file_path, rule)


    @staticmethod
    def remove_odv_custom_rule(rule) -> None:
        rule_file_path: Path = Path(config["custom"]["rules"][rule.section], f"{rule.rule_id}.yaml")

        if not rule_file_path.exists():
            return

        if "odv" in rule and "custom" in rule["odv"]:
            del rule["odv"]["custom"]

            create_yaml(rule_file_path, rule)


    @classmethod
    def odv_query(cls, rules: List["MacSecurityRule"], benchmark: str) -> List["MacSecurityRule"]:
        """
        Queries the user to include/exclude rules and set Organizational Defined Values (ODVs).

        Args:
            rules (List[MacSecurityRule]): List of rules to process.
            benchmark (str): The benchmark being tailored (e.g., "recommended").

        Returns:
            List[MacSecurityRule]: List of included rules after user input and ODV modifications.
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
                        str.lower,
                        range_=("y", "n", "all", "?"),
                        default_="y",
                    )
                    if include == "?":
                        print(f"Rule Details: \n{rule.discussion}")
                        include = sanitised_input(
                            f"Would you like to include the rule for \"{rule.rule_id}\" in your benchmark? [Y/n/all]: ",
                            str.lower,
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
                elif get_odv:
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
