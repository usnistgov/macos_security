# mscp/generate/payload.py

# Standard python modules
from collections import defaultdict
from datetime import date
from pathlib import Path
from typing import Any

# Local python modules
from ...classes import Baseline, Macsecurityrule, Payload
from ...common_utils import config, logger, make_dir, open_file, run_command


def get_payload_content_by_type(
    rules: list[Macsecurityrule],
) -> dict[str, list[dict[str, Any]]]:
    """
    Group the payload_content of Mobileconfigpayloads by their payload_type across a list of Macsecurityrule objects.

    Args:
        rules (List[Macsecurityrule]): A list of Macsecurityrule objects.

    Returns:
        Dict[str, List[Dict[str, Any]]]: A dictionary where the keys are payload_types and the values
                                         are lists of payload_content dictionaries.
    """
    grouped_content = defaultdict(list)

    for rule in rules:
        if rule.mobileconfig_info:
            for payload in rule.mobileconfig_info:
                payload_type = payload.payload_type
                payload_content = payload.payload_content

                # Merge settings for the same payload_type if needed
                existing_content = next(
                    (
                        item
                        for item in grouped_content[payload_type]
                        if item == payload_content
                    ),
                    None,
                )
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


@logger.catch
def generate_profiles(
    build_path: Path,
    baseline_name: str,
    baseline: Baseline,
    signing: bool = False,
    hash_value: str = "",
) -> None:
    """
    Generates configuration profiles based on the provided baseline and saves them to the specified build path.

    Args:
        build_path (Path): The path where the generated profiles will be saved.
        baseline_name (str): The name of the baseline being used.
        baseline (Baseline): The baseline object containing profile and rule information.
        signing (bool, optional): Whether to sign the generated profiles. Defaults to False.
        hash_value (str, optional): The hash value used for signing the profiles. Defaults to an empty string.

    Returns:
        None

    Raises:
        None

    Notes:
        - Creates directories for unsigned, signed, and preferences profiles.
        - Validates rules against supported payload types.
        - Logs any errors found in the rules.
        - Groups payloads by type and generates profiles for each type.
        - Saves the generated profiles in plist format.
        - Optionally signs the profiles if signing is enabled.
        - Displays a caution message about the use of the generated profiles in a test environment.
    """

    unsigned_output_path: Path = Path(build_path, "mobileconfigs", "unsigned")
    signed_output_path: Path = Path(build_path, "mobileconfigs", "signed")
    plist_output_path: Path = Path(build_path, "mobileconfigs", "preferences")
    create_date: date = date.today()

    manifests_file: dict = open_file(
        Path(config.get("includes_dir", ""), "supported_payloads.yaml")
    )

    make_dir(unsigned_output_path)
    make_dir(plist_output_path)

    if signing:
        make_dir(signed_output_path)

    profile_errors: list[Macsecurityrule] = [
        rule
        for profile in baseline.profile
        for rule in profile.rules
        if rule.mobileconfig_info
        and any(
            payload.payload_type not in manifests_file.get("payloads_types", [])
            for payload in rule.mobileconfig_info
        )
    ]

    valid_rules: list[Macsecurityrule] = [
        rule
        for profile in baseline.profile
        for rule in profile.rules
        if rule.mobileconfig_info
        and any(
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
        logger.debug("Payload Type: {}", payload_type)
        logger.debug("Settings List: {}", repr(settings_list))

        flat_settings = [s for sublist in settings_list for s in sublist]

        payload_base_name = (
            f"com.apple{payload_type}" if payload_type.startswith(".") else payload_type
        )
        unsigned_mobileconfig_file_path = (
            unsigned_output_path / f"{payload_base_name}.mobileconfig"
        )
        settings_plist_file_path = plist_output_path / f"{payload_base_name}.plist"

        if signing:
            signed_mobileconfig_file_path = (
                signed_output_path / f"{payload_base_name}.mobileconfig"
            )

        sanitized_payload_type = "".join(
            c if c.isalnum() or c in "._-" else "_" for c in payload_type
        )
        identifier = f"{sanitized_payload_type}.{baseline_name}"
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
            for settings in flat_settings:
                for domain, payload_content in settings.items():
                    new_profile.add_mcx_payload(domain, payload_content, baseline_name)
        else:
            settings: dict = {k: v for d in flat_settings for k, v in d.items()}
            new_profile.add_payload(payload_type, settings, baseline_name)

        new_profile.save_to_plist(unsigned_mobileconfig_file_path)

        if signing:
            sign_config_profile(
                unsigned_mobileconfig_file_path,
                signed_mobileconfig_file_path,
                hash_value,
            )

        new_profile.finalize_and_save_plist(settings_plist_file_path)

        logger.info(
            f"Configuration profile for {payload_type} saved to {unsigned_mobileconfig_file_path}"
        )

    managed_client_file: Path = (
        plist_output_path / "com.apple.ManagedClient.preferences.plist"
    )

    if managed_client_file.exists():
        managed_client_file.unlink()

    # Final message
    logger.info(
        """
        CAUTION: These configuration profiles are intended for evaluation in a TEST
        environment. Certain configuration profiles (Smartcards), when applied could
        leave a system in a state where a user can no longer login with a password.
        Please use caution when applying configuration settings to a system.

        NOTE: If an MDM is already being leveraged, many of these profile settings may
        be available through the vendor.
        """
    )
