# mscp/classes/payload.py
"""Configuration profile payload model.

Provides `Payload`, the in-memory representation of a macOS configuration
profile (or a per-domain preference plist). Payloads accumulate sub-payload
dictionaries and can be serialized to ``.mobileconfig`` or ``.plist`` files.
"""

# Standard python modules
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

# Local python modules
from ..common_utils import create_file, open_file
from ..common_utils.logger_instance import logger


class Payload(BaseModel):
    """A macOS configuration profile payload.

    Holds the top-level metadata of a profile (identifier, organization,
    scope, etc.) along with a list of sub-payloads accumulated via
    `add_payload` / `add_mcx_payload`. The whole payload is serialized to
    disk via `save_to_plist` (raw write) or `finalize_and_save_plist`
    (which additionally splits Managed Client preference payloads into
    per-domain plists).

    Attributes:
        identifier (str): The ``PayloadIdentifier`` written to the profile.
        organization (str): Owning organization written as
            ``PayloadOrganization``.
        description (str): Human-readable description written as
            ``PayloadDescription``.
        displayname (str): Display name written as ``PayloadDisplayName``.
        uuid (str | None): The profile UUID. Defaults to a freshly
            generated UUID4 string.
        payload_version (int): Profile schema version. Defaults to ``1``.
        payload_scope (str): Profile scope (``"System"`` or ``"User"``).
            Defaults to ``"System"``.
        payload_type (str): Top-level ``PayloadType``. Defaults to
            ``"Configuration"``.
        consent_text (dict[str, str]): Localized consent strings keyed by
            language code (e.g. ``"default"``, ``"en"``). Defaults to a
            built-in NIST disclaimer under ``"default"``.
        payload_content (list[dict[str, Any]]): Sub-payload dictionaries
            appended by `add_payload` / `add_mcx_payload`.
    """

    identifier: str = ""
    organization: str = ""
    description: str = ""
    displayname: str = ""
    uuid: str | None = Field(default_factory=lambda: str(uuid4()))
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

    def add_payload(self, payload_type: str, settings: dict[str, Any]) -> None:
        """Append a generic sub-payload to `payload_content`.

        Builds a payload dict with a fresh UUID and the standard
        ``PayloadVersion`` / ``PayloadType`` / ``PayloadIdentifier`` keys,
        merges ``settings`` into it, and appends it to `payload_content`.

        Args:
            payload_type (str): The ``PayloadType`` value (e.g.
                ``"com.apple.screensaver"``).
            settings (dict[str, Any]): Profile settings merged verbatim
                into the payload dict.
        """
        uuid = self._make_new_uuid()

        payload: dict[str, int | str] = {
            "PayloadVersion": self.payload_version,
            "PayloadUUID": uuid,
            "PayloadType": payload_type,
            "PayloadIdentifier": f"mscp.{payload_type}.{uuid}",
        }

        payload.update(settings)
        self.payload_content.append(payload)

    def add_mcx_payload(self, domain: str, settings: dict[str, Any]) -> None:
        """Append a Managed Client (MCX) preferences sub-payload.

        Wraps ``settings`` in the MCX
        ``PayloadContent[domain]["Forced"][0]["mcx_preference_settings"]``
        nesting expected by ``com.apple.ManagedClient.preferences`` and
        appends the result to `payload_content`.

        Args:
            domain (str): The preference domain to manage (e.g.
                ``"com.apple.screensaver"``).
            settings (dict[str, Any]): MCX preference settings to enforce
                for ``domain``.
        """

        uuid: str = self._make_new_uuid()

        payload = {
            "PayloadVersion": self.payload_version,
            "PayloadUUID": uuid,
            "PayloadType": "com.apple.ManagedClient.preferences",
            "PayloadIdentifier": f"mscp.{domain}.{uuid}",
            "PayloadContent": {
                domain: {"Forced": [{"mcx_preference_settings": settings}]}
            },
        }

        self.payload_content.append(payload)

    def save_to_plist(self, output_path: Path) -> None:
        """Write the assembled payload to disk.

        Behavior depends on the file extension of ``output_path``:

        - ``.mobileconfig``: writes the full top-level profile dictionary
          (identifier, scope, organization, payload content, etc.).
        - ``.plist``: writes only the merged inner settings, with the
          MDM-only keys (``PayloadVersion``, ``PayloadUUID``,
          ``PayloadType``, ``PayloadIdentifier``) stripped, in *append*
          mode.

        Args:
            output_path (Path): Destination file. The extension determines
                which format is written; other extensions are silently
                skipped.
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

        if output_path.suffix == ".mobileconfig":
            create_file(output_path, data)
            logger.success(f"Configuration profile written to {output_path}")
        elif output_path.suffix == ".plist":
            payload_content = {}
            for payload in self.payload_content:
                filtered_payload = {}
                for k, v in payload.items():
                    if k not in (
                        "PayloadVersion",
                        "PayloadUUID",
                        "PayloadType",
                        "PayloadIdentifier",
                    ):
                        filtered_payload[k] = v

                payload_content.update(filtered_payload)

            create_file(output_path, payload_content, append=True)

            logger.success(f"Preference file written to {output_path}")

    def finalize_and_save_plist(self, output_path: Path) -> None:
        """Write per-domain MCX plists, then save the main payload.

        For each MCX sub-payload in `payload_content`, splits the forced
        preference settings out into a sibling ``<domain>.plist`` next to
        ``output_path`` (creating the file if needed). After all MCX
        payloads have been processed, calls `save_to_plist` to write
        ``output_path`` itself.

        Args:
            output_path (Path): Destination of the main payload. Per-domain
                plists are written alongside it in the same directory.
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
            settings_dict = {
                k: v
                for forced_setting in value["Forced"]
                for k, v in forced_setting["mcx_preference_settings"].items()
            }

            self._save_plist(preferences_file, settings_dict)

    def _open_or_create_plist(self, preferences_file: Path) -> dict[str, Any]:
        """
        Open an existing plist file or create a new one if it doesn't exist.

        Args:
            preferences_file (Path): The path to the plist file.

        Returns:
            dict[str, Any]: The contents of the plist file.
        """

        if not preferences_file.exists():
            return {}

        try:
            logger.info("Opening plist file: {}", preferences_file)
            return open_file(preferences_file)
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
            create_file(preferences_file, settings_dict)
            logger.success(f"Settings plist written to {preferences_file}")
        except Exception as e:
            logger.error(f"Error creating plist file {preferences_file}: {e}")

    def _make_new_uuid(self) -> str:
        return str(uuid4())
