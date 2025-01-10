# mscp/common_utils/mobile_config_fix.py

import logging

from typing import List

from src.mscp.classes.macsecurityrule import Mobileconfigpayload

logger = logging.getLogger(__name__)

def format_mobileconfig_fix(mobileconfig: List) -> str:
    """
    Generate a formatted string representing a configuration profile in XML format
    based on the provided mobileconfig dictionary.

    The function recursively processes the mobileconfig dictionary to construct
    XML-like configuration strings. It handles various payload types and ensures
    proper formatting for nested dictionaries, arrays, integers, booleans, and strings.
    Additionally, it accounts for the special "com.apple.ManagedClient.preferences" domain,
    which requires sub-payloads within its payload type.

    Args:
        mobileconfig (List[Mobileconfigprofile]): A list of Mobileconfigprofile instances.
            Keys are domains or payload types, and values are configuration settings,
            which can include nested dictionaries, lists, or scalar values.

    Returns:
        str: A formatted string that can be used to define a configuration profile,
        adhering to the required XML-like structure.

    Example:
        Input:
        {
            "com.example.settings": {
                "ExampleKey": "ExampleValue",
                "NestedDict": {
                    "SubKey": "SubValue"
                },
                "ExampleArray": ["Value1", "Value2"],
                "ExampleBool": True
            }
        }

        Output:
        Create a configuration profile containing the following keys in the (com.example.settings) payload type:

        [source,xml]
        ----
        <key>ExampleKey</key>
        <string>ExampleValue</string>
        <key>NestedDict</key>
        <dict>
            <key>SubKey</key>
            <string>SubValue</string>
        </dict>
        <key>ExampleArray</key>
        <array>
            <string>Value1</string>
            <string>Value2</string>
        </array>
        <key>ExampleBool</key>
        <true/>
        ----
    """

    rulefix = ""

    for profile in mobileconfig:
        payload_type = profile.payload_type
        payload_content = profile.payload_content

        if payload_type == "com.apple.ManagedClient.preferences":
            rulefix += (
                f"NOTE: The following settings are in the ({payload_type}) payload. "
                "This payload requires the additional settings to be sub-payloads within, "
                "containing their defined payload types.\n\n"
            )
            # Recursively handle nested payloads if needed
            nested_fix = format_mobileconfig_fix(
                [Mobileconfigpayload(k, v) for k, v in payload_content.items()]
            )
            rulefix += nested_fix
        else:
            rulefix += (
                f"Create a configuration profile containing the following keys in the ({payload_type}) payload type:\n\n"
            )
            rulefix += "[source,xml]\n----\n"

            for key, value in payload_content.items():
                rulefix += f"<key>{key}</key>\n"

                if isinstance(value, bool):
                    rulefix += f"<{str(value).lower()}/>\n"
                elif isinstance(value, list):
                    rulefix += "<array>\n"
                    for item in value:
                        rulefix += f"    <string>{item}</string>\n"
                    rulefix += "</array>\n"
                elif isinstance(value, int):
                    rulefix += f"<integer>{value}</integer>\n"
                elif isinstance(value, str):
                    rulefix += f"<string>{value}</string>\n"
                elif isinstance(value, dict):
                    rulefix += "<dict>\n"
                    for sub_key, sub_value in value.items():
                        rulefix += f"    <key>{sub_key}</key>\n"
                        if isinstance(sub_value, str):
                            rulefix += f"    <string>{sub_value}</string>\n"
                        elif isinstance(sub_value, bool):
                            rulefix += f"    <{str(sub_value).lower()}/>\n"
                        elif isinstance(sub_value, list):
                            rulefix += "    <array>\n"
                            for sub_item in sub_value:
                                rulefix += f"        <string>{sub_item}</string>\n"
                            rulefix += "    </array>\n"
                        elif isinstance(sub_value, int):
                            rulefix += f"    <integer>{sub_value}</integer>\n"
                    rulefix += "</dict>\n"

            rulefix += "----\n\n"

    return rulefix
