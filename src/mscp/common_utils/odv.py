# mscp/common_utils/odv.py

# Standard python modules
import logging

from typing import List

# Local python modules
from src.mscp.common_utils.config import config

# Initialize local logger
logger = logging.getLogger(__name__)


def fill_in_odv(resulting_yaml: dict, parent_values: str) -> None:
    """
    Replaces placeholders ('$ODV') in the YAML content with the appropriate override value
    based on the parent_values key.

    Args:
        resulting_yaml (dict): The dictionary representing the YAML content.
        parent_values (str): The key to look up in the 'odv' dictionary.

    Returns:
        None: The function modifies resulting_yaml in place.
    """

    fields_to_process = ["title", "discussion", "check", "fix"]
    _has_odv = False
    odv = None

    if "odv" in resulting_yaml:
        for key in [parent_values, "custom", "recommended"]:
            if key in resulting_yaml["odv"]:
                odv = resulting_yaml["odv"][key]
                odv = str(odv) if not isinstance(odv, int) else odv
                _has_odv = True
                break

    if not _has_odv:
        return

    for field in fields_to_process:
        if field in resulting_yaml and "$ODV" in resulting_yaml[field]:
            resulting_yaml[field] = resulting_yaml[field].replace("$ODV", str(odv))

    if "result" in resulting_yaml:
        for result_value in resulting_yaml["result"]:
            if "$ODV" in str(resulting_yaml["result"][result_value]):
                resulting_yaml["result"][result_value] = odv

    if isinstance(resulting_yaml.get("mobileconfig_info"), dict):
        for mc_type, mc_content in resulting_yaml["mobileconfig_info"].items():
            if isinstance(mc_content, dict):
                for key, value in mc_content.items():
                    if "$ODV" in str(value):
                        if isinstance(value, dict):
                            for k, v in value.items():
                                if v == "$ODV":
                                    value[k] = odv
                        else:
                            mc_content[key] = odv

    if "ddm_info" in resulting_yaml:
        for ddm_type, value in resulting_yaml["ddm_info"].items():
            if isinstance(value, dict):
                for _key, _value in value.items():
                    if "$ODV" in str(_value):
                        resulting_yaml["ddm_info"][ddm_type][_key] = odv
            elif "$ODV" in value:
                resulting_yaml["ddm_info"][ddm_type] = odv


def write_odv_custom_rule() -> None:
    ...


def remove_odv_custom_rule() -> None:
    ...


def query_odv() -> None:
    ...
