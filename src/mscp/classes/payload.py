# mscp/classes/payload.py

import os
import plistlib
import logging

from uuid import uuid4
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

# Initialize local logger
logger = logging.getLogger(__name__)


def make_new_uuid() -> str:
    return str(uuid4())


@dataclass
class Payload:
    """Dataclass to create and manipulate Configuration Profiles."""
    identifier: str
    organization: str = ""
    description: str = ""
    displayname: str = ""
    uuid: Optional[str] = field(default_factory=make_new_uuid)
    payload_version: int = 1
    payload_scope: str = "System"
    payload_type: str = "Configuration"
    consent_text: Dict[str, str] = field(default_factory=lambda: {
        "default": (
            "THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, "
            "EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, "
            "ANY WARRANTY THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED "
            "WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM "
            "FROM INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE "
            "SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT SHALL "
            "NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT, INDIRECT, "
            "SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM, OR IN ANY WAY "
            "CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY, CONTRACT, TORT, OR OTHERWISE, "
            "WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS "
            "SUSTAINED FROM, OR AROSE OUT OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER."
        )
    })
    payload_content: List[Dict[str, Any]] = field(default_factory=list)

    def add_payload(self, payload_type: str, settings: Dict[str, Any], baseline_name: str) -> None:
        """Add a payload to the profile."""
        payload = {
            "PayloadVersion": self.payload_version,
            "PayloadUUID": make_new_uuid(),
            "PayloadType": payload_type,
            "PayloadIdentifier": f"alacarte.macOS.{baseline_name}.{make_new_uuid()}",
        }
        # Merge settings directly into the payload dictionary
        payload.update(settings)
        self.payload_content.append(payload)


    def add_mcx_payload(self, settings: List[Any], baseline_name: str) -> None:
        """Add a Managed Client preferences payload."""
        keys = settings[1]
        plist_dict = {key: settings[2] for key in keys.split()}
        uuid = make_new_uuid()

        domain = settings[0]
        payload = {
            "PayloadVersion": self.payload_version,
            "PayloadUUID": uuid,
            "PayloadType": "com.apple.ManagedClient.preferences",
            "PayloadIdentifier": f"alacarte.macOS.{baseline_name}.{uuid}",
            "PayloadContent": {}
        }

        # Add the MCX settings directly to the payload
        payload.get("PayloadContent", {}).update({domain: {"Forced": [{"mcx_preference_settings": plist_dict}]}})
        self.payload_content.append(payload)


    def save_to_plist(self, output_path: Path) -> None:
        """Save the profile to a plist file."""
        data = {
            "PayloadVersion": self.payload_version,
            "PayloadOrganization": self.organization,
            "PayloadUUID": self.uuid,
            "PayloadType": self.payload_type,
            "PayloadScope": self.payload_scope,
            "PayloadDescription": self.description,
            "PayloadDisplayName": self.displayname,
            "PayloadIdentifier": self.identifier,
            "ConsentText": self.consent_text,
            "PayloadContent": self.payload_content
        }

        with output_path.open("wb") as plist_file:
            plistlib.dump(data, plist_file)
        print(f"Configuration profile written to {output_path}")

    def finalize_and_save_plist(self, output_path: Path) -> None:
        """Save a final plist with additional processing for MCX settings."""
        for payload in self.payload_content:
            if payload.get("PayloadType") == "com.apple.ManagedClient.preferences":
                for domain, value in payload["PayloadContent"].items():
                    preferences_file = output_path.parent / f"{domain}.plist"
                    preferences_file.touch(exist_ok=True)
                    with preferences_file.open("rb") as f:
                        try:
                            settings_dict = plistlib.load(f)
                        except Exception:
                            settings_dict = {}
                    with preferences_file.open("wb") as f:
                        for forced_setting in value["Forced"]:
                            settings_dict.update(forced_setting["mcx_preference_settings"])
                        plistlib.dump(settings_dict, f)
                        print(f"Settings plist written to {preferences_file}")

        self.save_to_plist(output_path)
