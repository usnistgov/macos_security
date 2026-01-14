# mscp/generate/payload.py

# Standard python modules
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

# Local python modules
from ...classes import Baseline, Macsecurityrule, Payload
from ...common_utils import logger, make_dir, run_command


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
    consolidated: bool = False,
    granular: bool = False,
) -> None:
    """
    Generates configuration profiles based on the provided baseline and saves them to the specified build path.

    Args:
        build_path (Path): The path where the generated profiles will be saved.
        baseline_name (str): The name of the baseline being used.
        baseline (Baseline): The baseline object containing profile and rule information.
        signing (bool, optional): Whether to sign the generated profiles. Defaults to False.
        hash_value (str, optional): The hash value used for signing the profiles. Defaults to an empty string.
        consolidated (bool, optional): Whether to include a single consolidate profile containing all the settings.
        granular (bool, optional): Whether to build individual profiles for every setting.

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

    def merge_flat_settings(flat_settings: List[Dict[str, Any]]) -> Dict[str, Any]:
        agg: defaultdict[str, List[Any]] = defaultdict(list)
        result: Dict[str, Any] = {}

        for d in flat_settings:
            for k, v in d.items():
                if isinstance(v, list):
                    agg[k].extend(v)  # accumulate list values
                else:
                    result[k] = v  # last non-list value wins

        # move list aggregates into the final result
        for k, vals in agg.items():
            # if a non-list value was already set for k, keep the aggregated list anyway
            result[k] = vals

        return result

    unsigned_output_path: Path = Path(build_path, "mobileconfigs", "unsigned")
    signed_output_path: Path = Path(build_path, "mobileconfigs", "signed")
    plist_output_path: Path = Path(build_path, "mobileconfigs", "preferences")
    granular_output_path: Path = Path(build_path, "mobileconfigs", "granular")
    granular_signed_output_path: Path = Path(build_path, "mobileconfigs", "granular", "signed")

    make_dir(unsigned_output_path)
    make_dir(plist_output_path)

    if granular:
        make_dir(granular_output_path)
        if signing:
            make_dir(granular_signed_output_path)

    if signing:
        make_dir(signed_output_path)

    valid_rules: list[Macsecurityrule] = [
        rule for profile in baseline.profile for rule in profile.rules
    ]

    grouped_payloads: dict = get_payload_content_by_type(valid_rules)

    consolidated_profile = Payload(
        identifier=f"consolidated.{baseline_name}",
        organization="macOS Security Compliance Project",
        displayname=f"{baseline_name} settings",
        description=f"Consolidated configuration settings for {baseline_name}.",
    )

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
        identifier = f"mscp.{sanitized_payload_type}.{baseline_name}"
        description = (
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
                    consolidated_profile.add_mcx_payload(
                        domain, payload_content, baseline_name
                    )
                    # generate individual profiles for each setting
                    if granular:
                        for setting, value in payload_content.items():
                            granular_profile = Payload(
                                identifier=f"mscp.{domain}.{setting}",
                                organization=organization,
                                description=f"Configuration for {domain}:{setting}",
                                displayname=f"[{domain}] - {setting}",
                            )

                            granular_profile.add_mcx_payload(
                                domain, {setting: value}, setting
                            )
                            granular_profile.save_to_plist(
                                granular_output_path / f"{setting}.mobileconfig"
                            )
                            if signing:
                                sign_config_profile(
                                    granular_output_path / f"{setting}.mobileconfig",
                                    granular_signed_output_path / f"{setting}.mobileconfig",
                                    hash_value,
                                )
        else:
            settings = merge_flat_settings(flat_settings)
            new_profile.add_payload(payload_type, settings, baseline_name)
            consolidated_profile.add_payload(payload_type, settings, baseline_name)

            # generate individual profiles for each setting
            if granular:
                for setting, value in settings.items():
                    granular_profile = Payload(
                        identifier=f"mscp.{payload_type}.{setting}",
                        organization=organization,
                        description=f"Configuration for {payload_type}:{setting}",
                        displayname=f"[{payload_type}] - {setting}",
                    )
                    granular_profile.add_payload(
                        payload_type, {setting: value}, setting
                    )
                    granular_profile.save_to_plist(
                        granular_output_path / f"{setting}.mobileconfig"
                    )
                    if signing:
                        sign_config_profile(
                            granular_output_path / f"{setting}.mobileconfig",
                            granular_signed_output_path / f"{setting}.mobileconfig",
                            hash_value,
                        )

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

    # write consolidated profile if enabled
    if consolidated:
        consolidated_profile.save_to_plist(
            unsigned_output_path / f"{baseline_name}.mobileconfig"
        )

        if signing:
            sign_config_profile(
                unsigned_output_path / f"{baseline_name}.mobileconfig",
                signed_output_path / f"{baseline_name}.mobileconfig",
                hash_value,
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
