# mscp/generate/payload.py

# Standard python modules
import logging

from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict
from datetime import date


# Local python modules
from src.mscp.common_utils.config import config
from src.mscp.classes.baseline import Baseline
from src.mscp.classes.macsecurityrule import MacSecurityRule
from src.mscp.classes.payload import Payload
from src.mscp.common_utils.file_handling import open_file, open_yaml, make_dir
from src.mscp.common_utils.run_command import run_command


# Initialize local logger
logger = logging.getLogger(__name__)


def get_payload_content_by_type(rules: List[MacSecurityRule]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Group the payload_content of Mobileconfigpayloads by their payload_type across a list of MacSecurityRule objects.

    Args:
        rules (List[MacSecurityRule]): A list of MacSecurityRule objects.

    Returns:
        Dict[str, List[Dict[str, Any]]]: A dictionary where the keys are payload_types and the values
                                         are lists of payload_content dictionaries.
    """
    grouped_content = defaultdict(list)

    for rule in rules:
        if rule.mobileconfig:
            for payload in rule.mobileconfig_info:
                payload_type = payload.payload_type
                payload_content = payload.payload_content

                # Merge settings for the same payload_type if needed
                existing_content = next((item for item in grouped_content[payload_type] if item == payload_content), None)
                if not existing_content:
                    grouped_content[payload_type].append(payload_content)
                else:
                    # Merge list values for the same key
                    for key, value in payload_content.items():
                        if isinstance(value, list):
                            existing_content.setdefault(key, []).extend(value)
                        else:
                            existing_content[key] = value

    return dict(grouped_content)


def sign_config_profile(in_file: Path, out_file: Path, cert_hash: str) -> None:
    """
    Signs the configuration profile using the identity associated with the provided hash

    Args:
        in_file (Path): The file being signed.
        out_file (Path): The file being written to.
        hash (str): The hash string to use for signing.
    """

    cmd = f"security cms -SZ {cert_hash} -i {in_file} -o {out_file}"
    output, error = run_command(cmd)

    if output:
        logger.info(f"Signed Configuration profile written to {out_file}")


def generate_profiles(build_path: Path, baseline_name: str, baseline: Baseline, signing: bool = False, hash: str = "") -> None:
    unsigned_mobileconfig_output_path: Path = Path(build_path, "mobileconfigs", "unsigned")
    signed_mobileconfig_output_path: Path = Path(build_path, "mobileconfigs", "signed")
    settings_plist_output_path: Path = Path(build_path, "mobileconfigs", "preferences")
    create_date: date = date.today()

    manifests_file: dict = open_yaml(Path(config.get("includes_dir", ""), "supported_payloads.yaml"))

    make_dir(unsigned_mobileconfig_output_path)
    make_dir(settings_plist_output_path)

    if signing:
        make_dir(signed_mobileconfig_output_path)

    profile_errors: List = [
        rule for profile in baseline.profile
        for rule in profile.rules
        if rule.mobileconfig and any(
            payload.payload_type not in manifests_file.get("payloads_types", [])
            for payload in rule.mobileconfig_info
        )
    ]

    valid_rules: List = [
        rule for profile in baseline.profile
        for rule in profile.rules
        if rule.mobileconfig and any(
            payload.payload_type in manifests_file.get("payloads_types", [])
            for payload in rule.mobileconfig_info
        )
    ]

    grouped_payloads: dict = get_payload_content_by_type(valid_rules)

    if len(profile_errors) != 0:
        logger.info(f"There were errors found in {len(profile_errors)} rules")
        for error in profile_errors:
            logger.info(f"Correct the following rule: {error.rule_id}")

    for payload_type, settings_list in grouped_payloads.items():
        logger.debug(f"Payload Type: {payload_type}")
        logger.debug(f"Settings List: {settings_list}")
        payload_base_name = f"com.apple{payload_type}" if payload_type.startswith(".") else payload_type
        unsigned_mobileconfig_file_path = unsigned_mobileconfig_output_path / f"{payload_base_name}.mobileconfig"
        settings_plist_file_path = settings_plist_output_path / f"{payload_base_name}.plist"

        if signing:
            signed_mobileconfig_file_path = signed_mobileconfig_output_path / f"{payload_base_name}.mobileconfig"

        identifier = f"{payload_type}.{baseline_name}"
        description = (
            f"Created: {create_date}\n"
            f"Configuration settings for the {payload_type} preference domain."
        )
        organization = "macOS Security Compliance Project"
        displayname = f"[{baseline_name}] {payload_type} settings"

        new_profile = Payload(
            identifier=identifier,
            organization=organization,
            description=description,
            displayname=displayname,
        )

        if payload_type == "com.apple.ManagedClient.preferences":
            for settings in settings_list:
                for domain, payload_content in settings.items():
                    new_profile.add_mcx_payload([domain, "Forced", payload_content], baseline_name)
        else:
            settings: dict = {k: v for d in settings_list for k, v in d.items()}
            new_profile.add_payload(payload_type, settings, baseline_name)

        new_profile.save_to_plist(unsigned_mobileconfig_file_path)

        if signing:
            sign_config_profile(unsigned_mobileconfig_file_path, signed_mobileconfig_file_path, hash)

        new_profile.finalize_and_save_plist(settings_plist_file_path)

    # Final message
    print(
        f"""
        CAUTION: These configuration profiles are intended for evaluation in a TEST
        environment. Certain configuration profiles (Smartcards), when applied could
        leave a system in a state where a user can no longer login with a password.
        Please use caution when applying configuration settings to a system.

        NOTE: If an MDM is already being leveraged, many of these profile settings may
        be available through the vendor.
        """
    )
