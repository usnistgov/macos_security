# mscp/classes/payload.py

# Standard python modules
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

# Additional python modules
from loguru import logger
from pydantic import BaseModel, Field

# Local python modules
from src.mscp.common_utils import create_plist, open_plist

# from src.mscp.common_utils.file_handling import create_plist, open_plist


class Payload(BaseModel):
    """
    A class to represent a configuration profile payload.

    Attributes:
        identifier (str): The identifier for the payload.
        organization (str): The organization associated with the payload.
        description (str): A description of the payload.
        displayname (str): The display name of the payload.
        uuid (Optional[str]): The universally unique identifier for the payload.
        payload_version (int): The version of the payload.
        payload_scope (str): The scope of the payload.
        consent_text (Dict[str, str]): The consent text associated with the payload.
        payload_content (List[Dict[str, Any]]): The content of the payload.

    Methods:
        add_payload(payload_type: str, settings: Dict[str, Any], baseline_name: str) -> None:
            Adds a payload to the profile.

        add_mcx_payload(settings: List[Any], baseline_name: str) -> None:
            Adds a Managed Client preferences payload.

        save_to_plist(output_path: Path) -> None:
            Saves the profile to a plist file.

        finalize_and_save_plist(output_path: Path) -> None:
            Saves a final plist with additional processing for MCX settings.
    """

    identifier: str = ""
    organization: str = ""
    description: str = ""
    displayname: str = ""
    uuid: Optional[str] = Field(default_factory=lambda: str(uuid4()))
    payload_version: int = 1
    payload_scope: str = "System"
    payload_type: str = "Configuration"
    consent_text: dict[str, str] = Field(
        default_factory=lambda: {
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
        }
    )
    payload_content: list[dict[str, Any]] = Field(default_factory=list)

    @logger.catch
    def add_payload(
        self, payload_type: str, settings: dict[str, Any], baseline_name: str
    ) -> None:
        """
        Add a payload to the profile.

        Args:
            payload_type (str): The type of the payload.
            settings (Dict[str, Any]): A dictionary of settings to be included in the payload.
            baseline_name (str): The name of the baseline to be used in the payload identifier.

        Returns:
            None
        """
        uuid = self._make_new_uuid()

        payload = {
            "PayloadVersion": self.payload_version,
            "PayloadUUID": uuid,
            "PayloadType": payload_type,
            "PayloadIdentifier": f"alacarte.macOS.{baseline_name}.{uuid}",
        }
        # Merge settings directly into the payload dictionary
        payload.update(settings)
        self.payload_content.append(payload)

    @logger.catch
    def add_mcx_payload(self, settings: list[Any], baseline_name: str) -> None:
        """
        Add a Managed Client preferences payload.

        Args:
            settings (List[Any]): A list containing the domain and keys for the MCX settings.
                - settings[0] (str): The domain for the MCX settings.
                - settings[1] (str): A space-separated string of keys.
                - settings[2] (Any): The value associated with each key.
            baseline_name (str): The name of the baseline to be used in the PayloadIdentifier.

        Returns:
            None
        """
        keys = settings[1]
        plist_dict = {key: settings[2] for key in keys.split()}
        uuid = self._make_new_uuid()

        domain = settings[0]
        payload = {
            "PayloadVersion": self.payload_version,
            "PayloadUUID": uuid,
            "PayloadType": "com.apple.ManagedClient.preferences",
            "PayloadIdentifier": f"alacarte.macOS.{baseline_name}.{uuid}",
            "PayloadContent": {
                domain: {"Forced": [{"mcx_preference_settings": plist_dict}]}
            },
        }

        self.payload_content.append(payload)

    @logger.catch
    def save_to_plist(self, output_path: Path) -> None:
        """
        Save the profile to a plist file.

        Args:
            output_path (Path): The path where the plist file will be saved.

        Returns:
            None
        """
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
            "PayloadContent": self.payload_content,
        }

        create_plist(output_path, data)
        logger.success(f"Configuration profile written to {output_path}")

    @logger.catch
    def finalize_and_save_plist(self, output_path: Path) -> None:
        """
        Save a final plist with additional processing for MCX settings.

        This method iterates through the payload content and processes any payloads
        of type 'com.apple.ManagedClient.preferences'. For each domain in the payload
        content, it creates or updates a plist file with the forced MCX preference settings.

        Args:
            output_path (Path): The path where the final plist will be saved.

        Raises:
            Exception: If there is an error opening an existing plist file.
        """
        for payload in self.payload_content:
            if payload.get("PayloadType") == "com.apple.ManagedClient.preferences":
                self._process_mcx_payload(payload, output_path)

        self.save_to_plist(output_path)

    def _process_mcx_payload(self, payload: dict[str, Any], output_path: Path) -> None:
        """
        Process MCX payload and update plist files.

        Args:
            payload (dict[str, Any]): The MCX payload to process.
            output_path (Path): The path where the final plist will be saved.
        """
        for domain, value in payload["PayloadContent"].items():
            preferences_file = output_path.parent / f"{domain}.plist"
            preferences_file.touch(exist_ok=True)
            settings_dict = self._open_or_create_plist(preferences_file)

            settings_dict.update(
                {
                    k: v
                    for forced_setting in value["Forced"]
                    for k, v in forced_setting["mcx_preference_settings"].items()
                }
            )

            self._save_plist(preferences_file, settings_dict)

    def _open_or_create_plist(self, preferences_file: Path) -> dict[str, Any]:
        """
        Open an existing plist file or create a new one if it doesn't exist.

        Args:
            preferences_file (Path): The path to the plist file.

        Returns:
            dict[str, Any]: The contents of the plist file.
        """
        try:
            logger.info("Opening plist file: {}", preferences_file)
            return open_plist(preferences_file)
        except Exception as e:
            logger.warning(f"Error opening plist file {preferences_file}: {e}")
            return {}

    def _save_plist(
        self, preferences_file: Path, settings_dict: dict[str, Any]
    ) -> None:
        """
        Save the settings dictionary to a plist file.

        Args:
            preferences_file (Path): The path to the plist file.
            settings_dict (dict[str, Any]): The settings to save.
        """
        try:
            create_plist(preferences_file, settings_dict)
            logger.success(f"Settings plist written to {preferences_file}")
        except Exception as e:
            logger.error(f"Error creating plist file {preferences_file}: {e}")

    @logger.catch
    def _make_new_uuid(self) -> str:
        return str(uuid4())
