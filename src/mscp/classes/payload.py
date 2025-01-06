# mscp/classes/payload.py

import os
import plistlib
import logging

from uuid import uuid4
from pathlib import Path
from typing import List, Dict, Optional, Union
from dataclasses import dataclass, field

from .macsecurityrule import MacSecurityRule

logger = logging.getLogger(__name__)

class PayloadDict:
    """Class to create and manipulate Configuration Profiles.
    The actual plist content can be accessed as a dictionary via the 'data' attribute.
    """

    def __init__(self, identifier, uuid=False, description='', organization='', displayname=''):
        self.data = {}
        self.data["PayloadVersion"] = 1
        self.data["PayloadOrganization"] = organization
        if uuid:
            self.data["PayloadUUID"] = uuid
        else:
            self.data['PayloadUUID'] = makeNewUUID()
        self.data['PayloadType'] = 'Configuration'
        self.data['PayloadScope'] = 'System'
        self.data['PayloadDescription'] = description
        self.data['PayloadDisplayName'] = displayname
        self.data['PayloadIdentifier'] = identifier
        self.data['ConsentText'] = {"default": "THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM, OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY, CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER."}

        # An empty list for 'sub payloads' that we'll fill later
        self.data["PayloadContent"] = []

    def _updatePayload(self, payload_content_dict, baseline_name):
        """Update the profile with the payload settings. Takes the settings dictionary which will be the
        PayloadContent dict within the payload. Handles the boilerplate, naming and descriptive
        elements.
        """
        # description = "Configuration settings for the {} preference domain.".format(payload_type)
        payload_dict = {}

        # Boilerplate
        payload_dict['PayloadVersion'] = 1
        payload_dict['PayloadUUID'] = makeNewUUID()
        payload_dict['PayloadType'] = payload_content_dict['PayloadType']
        payload_dict['PayloadIdentifier'] = f"alacarte.macOS.{baseline_name}.{payload_dict['PayloadUUID']}"

        payload_dict["PayloadContent"] = payload_content_dict
        # Add the payload to the profile
        self.data.update(payload_dict)

    def _addPayload(self, payload_content_dict, baseline_name):
        """Add a payload to the profile. Takes the settings dictionary which will be the
        PayloadContent dict within the payload. Handles the boilerplate, naming and descriptive
        elements.
        """
        # description = "Configuration settings for the {} preference domain.".format(payload_type)
        payload_dict = {}

        # Boilerplate
        payload_dict['PayloadVersion'] = 1
        payload_dict['PayloadUUID'] = makeNewUUID()
        payload_dict['PayloadType'] = payload_content_dict['PayloadType']
        payload_dict['PayloadIdentifier'] = f"alacarte.macOS.{baseline_name}.{payload_dict['PayloadUUID']}"

        payload_dict["PayloadContent"] = payload_content_dict
        # Add the payload to the profile
        # print payload_dict
        del payload_dict["PayloadContent"]["PayloadType"]
        self.data["PayloadContent"].append(payload_dict)

    def addNewPayload(self, payload_type, settings, baseline_name):
        """Add a payload to the profile. Takes the settings dictionary which will be the
        PayloadContent dict within the payload. Handles the boilerplate, naming and descriptive
        elements.
        """
        # description = "Configuration settings for the {} preference domain.".format(payload_type)
        payload_dict = {}

        # Boilerplate
        payload_dict['PayloadVersion'] = 1
        payload_dict['PayloadUUID'] = makeNewUUID()
        payload_dict['PayloadType'] = payload_type
        payload_dict['PayloadIdentifier'] = f"alacarte.macOS.{baseline_name}.{payload_dict['PayloadUUID']}"

        # Add the settings to the payload
        for setting in settings:
            for k, v in setting.items():
                payload_dict[k] = v

        # Add the payload to the profile
        self.data["PayloadContent"].append(payload_dict)

    def addMCXPayload(self, settings, baseline_name):
        """Add a payload to the profile. Takes the settings dictionary which will be the
        PayloadContent dict within the payload. Handles the boilerplate, naming and descriptive
        elements.
        """
        keys = settings[1]
        plist_dict = {}
        for key in keys.split():
            plist_dict[key] = settings[2]

        # description = "Configuration settings for the {} preference domain.".format(payload_type)
        payload_dict = {}

        state = "Forced"
        domain = settings[0]

        # Boilerplate
        payload_dict[domain] = {}
        payload_dict[domain][state] = []
        payload_dict[domain][state].append({})
        payload_dict[domain][state][0]["mcx_preference_settings"] = plist_dict
        payload_dict["PayloadType"] = "com.apple.ManagedClient.preferences"

        self._addPayload(payload_dict, baseline_name)

    def finalizeAndSave(self, output_path):
        """Perform last modifications and save to configuration profile."""
        plistlib.dump(self.data, output_path)
        print(f"Configuration profile written to {output_path.name}")

    def finalizeAndSavePlist(self, output_path):
        """Perform last modifications and save to an output plist."""
        output_file_path = output_path.name
        preferences_path = os.path.dirname(output_file_path)

        settings_dict = {}
        for i in self.data["PayloadContent"]:
            if i["PayloadType"] == "com.apple.ManagedClient.preferences":
                for key, value in i["PayloadContent"].items():
                    domain = key
                    preferences_output_file = os.path.join(
                        preferences_path, domain + ".plist"
                    )
                    if not os.path.exists(preferences_output_file):
                        with open(preferences_output_file, "w"):
                            pass
                    with open(preferences_output_file, "rb") as fp:
                        try:
                            settings_dict = plistlib.load(fp)
                        except:
                            settings_dict = {}
                    with open(preferences_output_file, "wb") as fp:
                        for setting in value["Forced"]:
                            for key, value in setting[
                                "mcx_preference_settings"
                            ].items():
                                settings_dict[key] = value

                        # preferences_output_path = open(preferences_output_file, 'wb')
                        plistlib.dump(settings_dict, fp)
                        print(f"Settings plist written to {preferences_output_file}")
                    settings_dict.clear()
                    try:
                        os.unlink(output_file_path)
                    except:
                        continue
            else:
                if os.path.exists(output_file_path):
                    with open(output_file_path, "rb") as fp:
                        try:
                            settings_dict = plistlib.load(fp)
                        except:
                            settings_dict = {}
                for key, value in i.items():
                    if not key.startswith("Payload"):
                        settings_dict[key] = value

                plistlib.dump(settings_dict, output_path)
                print(f"Settings plist written to {output_path.name}")

def makeNewUUID() -> str:
    return str(uuid4())

@dataclass
class Payload:
    """
    Class to create and manipulate ConfigurationProfiles.
    The actual plist content can be accessed as a dictionary via the 'data' attribute.
    """

    identifier: str
    uuid: Optional[str] = None
    description: str = ''
    organization: str = ''
    displayname: str = ''
    PayloadVersion: int = 1
    PayloadType: str = 'Configuration'
    PayloadScope: str = 'System'
    data: Dict[str, Union[str, int, Dict[str, str], List[Dict[str, Union[str, int]]]]] = field(init=False)

    def __post_init__(self):
        self.data = {
            "PayloadVersion": self.PayloadVersion,
            "PayloadOrganization": self.organization,
            "PayloadUUID": self.uuid or makeNewUUID(),
            "PayloadType": self.PayloadType,
            "PayloadScope": self.PayloadScope,
            "PayloadDescription": self.description,
            "PayloadDisplayName": self.displayname,
            "PayloadIdentifier": self.identifier,
            "PayloadContent": []
        }
