# macsecurityrule.py

# Standard python modules
import logging
import sys
import base64

from dataclasses import dataclass
from typing import List, Dict, Any
from pathlib import Path
from icecream import ic
from collections import defaultdict

# Additional python modules
from lxml import etree

# Local python modules
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml

# Initialize logger
logger = logging.getLogger(__name__)

@dataclass
class Cis:
    benchmark: List[str] | None
    controls_v8: List[float] | None


@dataclass
class Mobileconfigpayload:
    payload_type: str
    payload_content: Dict[str, Any]


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
    mobileconfig_info: List[Mobileconfigpayload]
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
            # if isinstance(result, dict):
            #     for result_type in ["integer", "boolean", "string", "base64"]:
            #         if result_type in result:
            #             result_value = result[result_type]
            #             break
            #     else:
            #         result_value = "N/A"
            # else:
            #     result_value = result

            if mobileconfig:
                mechanism = "Configuration Profile"

                mobileconfig_info = rule_yaml.get("mobileconfig_info", {})

                if isinstance(mobileconfig_info, dict):
                    for payload_type, payload_content in mobileconfig_info.items():
                        payloads.append(Mobileconfigpayload(payload_type, payload_content))
                elif isinstance(mobileconfig_info, list):
                    for entry in mobileconfig_info:
                        payload_type = entry.get("PayloadType")
                        payload_content = entry.get("PayloadContent", {})
                        payloads.append(Mobileconfigpayload(payload_type, payload_content))

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
                severity=rule_yaml.get("severity", None),
                discussion=rule_yaml.get("discussion", "missing").replace('|', '\\|'),
                check=rule_yaml.get("check", "missing").replace('|', '\\|'),
                fix=rule_yaml.get("fix", "").replace('|', '\\|'),
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

            if not rule.odv == None:
                rule._fill_in_odv(parent_values)

            rules.append(rule)

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
