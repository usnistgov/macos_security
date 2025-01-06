# mscp/common_utils/mobile_config_fix.py

import logging

logger = logging.getLogger(__name__)

def format_mobileconfig_fix(mobileconfig: dict) -> str:
    """
    Generate a formatted string representing a configuration profile in XML format
    based on the provided mobileconfig dictionary.

    The function recursively processes the mobileconfig dictionary to construct
    XML-like configuration strings. It handles various payload types and ensures
    proper formatting for nested dictionaries, arrays, integers, booleans, and strings.
    Additionally, it accounts for the special "com.apple.ManagedClient.preferences" domain,
    which requires sub-payloads within its payload type.

    Args:
        mobileconfig (dict): A dictionary representing the configuration settings.
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
    for domain, settings in mobileconfig.items():
        if domain == "com.apple.ManagedClient.preferences":
            rulefix = rulefix + (
                f"NOTE: The following settings are in the ({domain}) payload. This payload requires the additional settings to be sub-payloads within, containing their defined payload types.\n\n"
            )
            rulefix = rulefix + format_mobileconfig_fix(settings)
        else:
            rulefix = rulefix + (
                f"Create a configuration profile containing the following keys in the ({domain}) payload type:\n\n"
            )
            rulefix = rulefix + "[source,xml]\n----\n"
            for item in settings.items():
                rulefix = rulefix + (f"<key>{item[0]}</key>\n")

                if type(item[1]) == bool:
                    rulefix = rulefix + (f"<{str(item[1]).lower()}/>\n")
                elif type(item[1]) == list:
                    rulefix = rulefix + "<array>\n"
                    for setting in item[1]:
                        rulefix = rulefix + (f"    <string>{setting}</string>\n")
                    rulefix = rulefix + "</array>\n"
                elif type(item[1]) == int:
                    rulefix = rulefix + (f"<integer>{item[1]}</integer>\n")
                elif type(item[1]) == str:
                    rulefix = rulefix + (f"<string>{item[1]}</string>\n")
                elif type(item[1]) == dict:
                    rulefix = rulefix + "<dict>\n"
                    for k,v in item[1].items():
                        if type(v) == dict:
                            rulefix = rulefix + \
                                (f"    <key>{k}</key>\n")
                            rulefix = rulefix + \
                                (f"    <dict>\n")
                            for x,y in v.items():
                                rulefix = rulefix + \
                                    (f"      <key>{x}</key>\n")
                                rulefix  = rulefix + \
                                    (f"      <string>{y}</string>\n")
                            rulefix = rulefix + \
                            (f"    </dict>\n")
                            break
                        if isinstance(v, list):
                            rulefix = rulefix + "    <array>\n"
                            for setting in v:
                                rulefix = rulefix + \
                                    (f"        <string>{setting}</string>\n")
                            rulefix = rulefix + "    </array>\n"
                        else:
                            rulefix = rulefix + \
                                    (f"    <key>{k}</key>\n")
                            rulefix = rulefix + \
                                    (f"    <string>{v}</string>\n")
                    rulefix = rulefix + "</dict>\n"


            rulefix = rulefix + "----\n\n"

    return rulefix
