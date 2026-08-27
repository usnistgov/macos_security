# mscp/generate/ddm.py
"""Declarative Device Management (DDM) artifact generation for mSCP.

Provides `generate_ddm`, which processes ``ddm_info`` fields from baseline
rules and writes DDM JSON configurations, assets, activations, and service
ZIP archives under a ``declarative/`` subdirectory of the build path.

Also provides `ddm_info_to_json`, a Jinja-filter helper that renders a single
rule's ``ddm_info`` as the configuration declaration JSON (mirroring what
`generate_ddm` writes to ``declarative/configurations/``) for inline display
in guidance documents.
"""

# Standard python modules
import hashlib
import json
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

# Local python modules
from ...classes import Baseline, Macsecurityrule
from ...common_utils import (
    append_text,
    logger,
    make_dir,
    mscp_data,
    remove_dir,
    APPLE_OS,
)


def deep_merge(base: Any, incoming: Any) -> Any:
    """Recursively merge *incoming* into *base* and return the combined value.

    - Two dicts are merged key by key (recursing on shared keys).
    - Two lists are concatenated, skipping entries already present in *base*.
    - Any other combination: *incoming* replaces *base* (so a missing *base*,
      passed as ``None``, simply yields *incoming*).

    Used to combine the ``ddm_value`` payloads of multiple rules that target
    the same declaration type and ``ddm_key`` - for example several
    ``com.apple.configuration.app.settings`` rules that each contribute one
    ``DeniedBinaries`` entry under the ``Allowed`` key, which must accumulate
    into a single list rather than overwrite one another.

    Args:
        base (Any): Value accumulated so far (``None`` if nothing yet).
        incoming (Any): Value from the current rule to merge in.

    Returns:
        Any: The merged value.
    """
    if isinstance(base, dict) and isinstance(incoming, dict):
        merged: dict[Any, Any] = dict(base)
        for key, value in incoming.items():
            merged[key] = deep_merge(merged[key], value) if key in merged else value
        return merged

    if isinstance(base, list) and isinstance(incoming, list):
        merged_list: list[Any] = list(base)
        for item in incoming:
            if item not in merged_list:
                merged_list.append(item)
        return merged_list

    return incoming


def ddm_declaration_identifier(baseline_name: str, kind: str, suffix: str) -> str:
    """Build an mSCP DDM declaration identifier.

    Args:
        baseline_name (str): Baseline name embedded in the identifier.
        kind (str): Declaration kind segment (``"config"``, ``"asset"`` or
            ``"activation"``).
        suffix (str): Trailing segment identifying the specific declaration.

    Returns:
        str: Identifier of the form ``org.mscp.<baseline_name>.<kind>.<suffix>``.
    """
    return f"org.mscp.{baseline_name}.{kind}.{suffix}"


def build_ddm_declaration(
    ddm_info: dict[str, Any], baseline_name: str = "baseline"
) -> dict[str, Any]:
    """Build the DDM configuration declaration dict for one rule's ``ddm_info``.

    Mirrors the ``configuration`` declaration that `generate_ddm` writes for a
    rule: a ``com.apple.configuration.services.configuration-files`` payload
    referencing a data asset, or a standard configuration payload built from
    the rule's ``ddm_key`` / ``ddm_value`` pair.

    Args:
        ddm_info (dict[str, Any]): A rule's ``ddm_info`` mapping.
        baseline_name (str): Baseline name used to build the identifiers.

    Returns:
        dict[str, Any]: ``Identifier`` / ``Type`` / ``Payload`` declaration dict.
    """
    declaration_type: str = ddm_info.get("declarationtype", "")

    if declaration_type == "com.apple.configuration.services.configuration-files":
        service: str = ddm_info.get("service", "")
        service_parts: list[str] = service.split(".")
        suffix: str = service_parts[2] if len(service_parts) > 2 else service
        return {
            "Identifier": ddm_declaration_identifier(baseline_name, "config", suffix),
            "Type": declaration_type,
            "Payload": {
                "ServiceType": service,
                "DataAssetReference": ddm_declaration_identifier(
                    baseline_name, "asset", suffix
                ),
            },
        }

    suffix = declaration_type.replace("com.apple.configuration.", "")
    ddm_key: str = ddm_info.get("ddm_key", "")
    ddm_value: Any = ddm_info.get("ddm_value", "")
    return {
        "Identifier": ddm_declaration_identifier(baseline_name, "config", suffix),
        "Type": declaration_type,
        "Payload": {ddm_key: ddm_value} if ddm_key else {},
    }


def ddm_info_to_json(
    ddm_info: dict[str, Any] | None, baseline_name: str = "baseline"
) -> str:
    """Render a rule's ``ddm_info`` as a configuration declaration JSON string.

    Jinja-filter convenience wrapper around `build_ddm_declaration`, analogous
    to ``mobileconfig_info_to_xml`` for configuration profiles.  Callers
    (typically templates) get the indented JSON without any surrounding
    AsciiDoc/Markdown source-block delimiters.

    Args:
        ddm_info (dict[str, Any] | None): A rule's ``ddm_info`` mapping.
        baseline_name (str): Baseline name used to build the identifiers.

    Returns:
        str: Pretty-printed declaration JSON, or ``""`` when *ddm_info* is empty.
    """
    if not ddm_info:
        return ""

    return json.dumps(build_ddm_declaration(ddm_info, baseline_name), indent=4)


def generate_ddm_activation(output_path: Path, identifier: str) -> None:
    """Write a DDM activation JSON file that references a single configuration.

    Derives the activation identifier from *identifier* by replacing
    ``"config"`` and ``"asset"`` with ``"activation"``, then appends the
    JSON payload to *output_path*.

    Args:
        output_path (Path): Destination file path (created or appended to).
        identifier (str): Configuration or asset DDM identifier to activate.
    """
    activation_ddm_identifier: str = identifier.replace("config", "activation").replace(
        "asset", "activation"
    )

    activation_ddm_json: dict = {
        "Identifier": activation_ddm_identifier,
        "Type": "com.apple.activation.simple",
        "Payload": {"StandardConfigurations": [identifier]},
    }

    append_text(output_path, json.dumps(activation_ddm_json, indent=4))


def zip_directory(zip_path: Path, folder_path: Path) -> None:
    """Recursively compress *folder_path* into *zip_path*, preserving relative paths.

    Args:
        zip_path (Path): Destination ZIP file path.
        folder_path (Path): Directory to compress.
    """
    folder_path = Path(folder_path)
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for file_path in folder_path.rglob("*"):
                zipf.write(file_path, arcname=file_path.relative_to(folder_path))
    except IOError as e:
        logger.error(f"Unable to create zip file for {folder_path}. Error: {e}.")
        return


def generate_ddm(build_path: Path, baseline: Baseline, baseline_name: str) -> None:
    """Generate DDM configuration, asset, and activation JSON files for *baseline*.

    Iterates rules with ``ddm_info``, writing service configuration files and
    ZIP archives (``com.apple.configuration.services.configuration-files``) or
    standard declaration JSONs into ``<build_path>/declarative/{configurations,
    assets,activations}/``.  Skips non-Apple platforms and unknown services.

    Args:
        build_path (Path): Root output directory for this baseline's artifacts.
        baseline (Baseline): Baseline whose rules supply ``ddm_info`` payloads.
        baseline_name (str): Baseline name used as part of DDM identifiers.
    """
    if not baseline.platform["os"].lower() in APPLE_OS:
        logger.warning(
            f"Platform {baseline.platform['os']} does not support DDM, skipping generation."
        )
        return

    ddm_output_path: Path = Path(build_path, "declarative")
    activations_output_path: Path = Path(ddm_output_path, "activations")
    assets_output_path: Path = Path(ddm_output_path, "assets")
    configurations_output_path: Path = Path(ddm_output_path, "configurations")
    ddm_dict: dict[str, Any] = defaultdict(dict)

    logger.debug(f"Output Directory name: {ddm_output_path}")

    if not ddm_output_path.exists():
        make_dir(ddm_output_path)
        make_dir(activations_output_path)
        make_dir(assets_output_path)
        make_dir(configurations_output_path)

    ddm_rules: list[Macsecurityrule] = [
        rule for profile in baseline.profile for rule in profile.rules if rule.ddm_info
    ]

    for ddm_rule in ddm_rules:
        ddm_info: dict[str, Any] = ddm_rule["ddm_info"]
        declaration_type = ddm_info.get("declarationtype", "")

        if declaration_type == "com.apple.configuration.services.configuration-files":
            service_name = ddm_info.get("service", "")
            if not mscp_data.get("ddm", {}).get("services", {}).get(service_name):
                logger.error(f"{service_name} service NOT found")
                continue

            logger.debug(f"Service name: {service_name}")
            service_path = (
                mscp_data.get("ddm", {}).get("services", {}).get(service_name, "")
            )
            logger.debug(f"Service path: {service_path}")

            # Handle the configuration directory and file
            service_config_dir: Path = Path(
                ddm_output_path,
                service_name,
                str(mscp_data["ddm"]["services"][service_name]).lstrip("/").rstrip("/"),
            )
            service_config_file: Path = service_config_dir / ddm_info.get(
                "config_file", ""
            )

            logger.debug(f"Configuration Directory: {service_config_dir}")
            logger.debug(f"Configuration File: {service_config_file}")

            if not service_config_dir.exists():
                make_dir(service_config_dir)

            config_key = ddm_info.get("configuration_key", "")
            config_value = ddm_info.get("configuration_value", "")

            if config_key == "file":
                append_text(
                    service_config_file, config_value, encoding="UTF-8", newline="\n"
                )
            else:
                append_text(
                    service_config_file,
                    f"{config_key} {config_value}",
                    encoding="UTF-8",
                    newline="\n",
                )

            ddm_dict[declaration_type].update({})
        else:
            ddm_key = ddm_info.get("ddm_key", "")
            ddm_value = ddm_info.get("ddm_value", "")
            # Merge rather than overwrite so multiple rules sharing a
            # declaration type and key (e.g. app.settings / DeniedBinaries)
            # accumulate their list entries instead of the last rule winning.
            ddm_dict[declaration_type][ddm_key] = deep_merge(
                ddm_dict[declaration_type].get(ddm_key), ddm_value
            )

    sha256_hash = hashlib.sha256()
    for ddm_type in ddm_dict.keys():
        if "files" in ddm_type:
            for service in mscp_data.get("ddm", {}).get("services", {}):
                logger.debug(f"Service Name: {service}")
                for path in ddm_output_path.rglob(service):
                    logger.info(f"Found configuration files for {service}, zipping")
                    logger.debug(f"Folder path: {path}")
                    zip_path: Path = Path(assets_output_path, f"{service}.zip")

                    ddm_identifier: str = (
                        f"org.mscp.{baseline_name}.asset.{service.split('.')[2]}"
                    )
                    activation_ddm_identifier: str = ddm_identifier.replace(
                        "config", "activation"
                    ).replace("asset", "activation")
                    config_ddm_identifier: str = ddm_identifier.replace(
                        "asset", "config"
                    )

                    asset_file_path: Path = Path(
                        assets_output_path, f"{ddm_identifier}.json"
                    )
                    config_file_path: Path = Path(
                        configurations_output_path, f"{config_ddm_identifier}.json"
                    )
                    activation_file_path: Path = Path(
                        activations_output_path, f"{activation_ddm_identifier}.json"
                    )

                    zip_directory(zip_path, path)

                    if zip_path.exists():
                        remove_dir(path)

                    sha256_hash.update(zip_path.read_bytes())
                    zip_sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()

                    asset_ddm_json: dict = {
                        "Identifier": ddm_identifier,
                        "Type": "com.apple.asset.data",
                        "Payload": {
                            "Reference": {
                                "ContentType": "application/zip",
                                "DataURL": f"https://hostname.site.com/{service}.zip",
                                "Hash-SHA-256": str(zip_sha),
                            },
                            "Authentication": {"Type": "MDM"},
                        },
                    }

                    configuration_ddm_json: dict = {
                        "Identifier": config_ddm_identifier,
                        "Type": ddm_type,
                        "Payload": {
                            "ServiceType": service,
                            "DataAssetReference": ddm_identifier,
                        },
                    }

                    append_text(asset_file_path, json.dumps(asset_ddm_json, indent=4))
                    append_text(
                        config_file_path, json.dumps(configuration_ddm_json, indent=4)
                    )

                    generate_ddm_activation(activation_file_path, ddm_identifier)
        else:
            logger.debug(f"Building any declarations for {ddm_type}...")
            ddm_identifier = f"org.mscp.{baseline_name}.config.{ddm_type.replace('com.apple.configuration.', '')}"
            activation_ddm_identifier: str = ddm_identifier.replace(
                "config", "activation"
            ).replace("asset", "activation")
            config_file_path: Path = Path(
                configurations_output_path, f"{ddm_identifier}.json"
            )
            activation_file_path: Path = Path(
                activations_output_path, f"{activation_ddm_identifier}.json"
            )

            ddm_json = {
                "Identifier": ddm_identifier,
                "Type": ddm_type,
                "Payload": ddm_dict.get(ddm_type, {}),
            }

            append_text(config_file_path, json.dumps(ddm_json, indent=4))

            generate_ddm_activation(activation_file_path, ddm_identifier)

    logger.success(f"DDM profiles generated successfully for {baseline_name}.")
