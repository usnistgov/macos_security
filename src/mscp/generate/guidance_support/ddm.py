# mscp/generate/ddm.py

# Standard python modules
import json
import shutil
import hashlib

from pathlib import Path
from typing import List
from collections import defaultdict

# Additional python modules
from loguru import logger

# Local python modules
from src.mscp.classes.baseline import Baseline
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml, make_dir, append_text, remove_dir


def generate_ddm_activation(output_path: Path, identifier: str) -> None:
    activation_ddm_identifier: str = identifier.replace("config", "activation").replace("asset", "activation")

    activation_ddm_json: dict = {
        "Identifier": activation_ddm_identifier,
        "Type": "com.apple.activation.simple",
        "Payload": {
            "StandardConfigurations": [ identifier ]
        }
    }

    append_text(output_path, json.dumps(activation_ddm_json, indent=4))


def generate_ddm(build_path: Path, baseline: Baseline, baseline_name: str) -> None:
    """
    Generate Declarative Device Management (DDM) profiles for a given baseline.

    This function creates and organizes DDM files such as configurations, assets, and activations
    based on the rules in the provided baseline. It processes `ddm_info` from the rules to generate
    JSON files and zip archives required for DDM operations.

    Args:
        build_path (Path): The base directory where DDM output files will be stored.
        baseline (Baseline): The Baseline object containing profiles and rules to process.
        baseline_name (str): The name of the baseline for identifying the output files.

    Returns:
        None

    Raises:
        Various exceptions for file handling, such as IOError for archive creation errors.

    Key Steps:
        1. Parse `ddm_info` from rules in the baseline to identify supported declaration types.
        2. Create required output directories if they don't exist.
        3. Process configuration files (`com.apple.configuration.services.configuration-files`):
            - Generate configuration directories and files.
            - Append configuration settings based on `ddm_info`.
        4. Generate and zip configuration files for supported services.
        5. Create JSON assets, configurations, and activations for each DDM declaration type.

    Notes:
        - The `assets`, `activations`, and `configurations` folders are created in the `declarative`
          directory under the `build_path`.
        - Services not found in `mscp_data` are skipped with a logged error message.
        - Unsupported DDM types are logged as errors and skipped.

    Example:
        generate_ddm(
            build_path=Path("/path/to/build"),
            baseline=my_baseline_object,
            baseline_name="example_baseline"
        )
    """

    mscp_data: dict = open_yaml(Path(config.get("mspc_data", "")))
    ddm_output_path: Path = Path(build_path, "declarative")
    activations_output_path: Path = Path(ddm_output_path, "activations")
    assets_output_path: Path = Path(ddm_output_path, "assets")
    configurations_output_path: Path = Path(ddm_output_path, "configurations")
    ddm_dict:dict = defaultdict(dict)

    logging.debug(f"Output Directory name: {ddm_output_path}")

    if not ddm_output_path.exists():
        make_dir(ddm_output_path)
        make_dir(activations_output_path)
        make_dir(assets_output_path)
        make_dir(configurations_output_path)

    ddm_rules: List = [
        rule for profile in baseline.profile
        for rule in profile.rules
        if rule.ddm_info
    ]

    for ddm_rule in ddm_rules:
        ddm_info = ddm_rule.get("ddm_info", {})
        declaration_type = ddm_info.get("declarationtype", "")

        if declaration_type == "com.apple.configuration.services.configuration-files":
            service_name = ddm_info.get("service", "")
            if not mscp_data.get("ddm", {}).get("services", {}).get(service_name):
                logger.error(f"{service_name} service NOT found")
                continue

            logger.debug(f"Service name: {service_name}")
            service_path = mscp_data.get("ddm", {}).get("services", {}).get(service_name, "")
            logger.debug(f"Service path: {service_path}")

            # Handle the configuration directory and file
            service_config_dir: Path = Path(
                ddm_output_path,
                service_name,
                str(mscp_data["ddm"]["services"][service_name]).lstrip("/")
            )
            service_config_file: Path = service_config_dir / ddm_info.get("config_file", "")

            logger.debug(f"Configuration Directory: {service_config_dir}")
            logger.debug(f"Configuration File: {service_config_file}")

            if not service_config_dir.exists():
                make_dir(service_config_dir)

            config_key = ddm_info.get("configuration_key", "")
            config_value = ddm_info.get("configuration_value", "")

            if config_key == "file":
                append_text(service_config_file, config_value, encoding="UTF-8", newline="\n")
            else:
                append_text(service_config_file, f"{config_key} {config_value}", encoding="UTF-8", newline="\n")

            ddm_dict[declaration_type].update({})
        else:
            ddm_key = ddm_info.get("ddm_key", "")
            ddm_value = ddm_info.get("ddm_value", "")
            ddm_dict[declaration_type][ddm_key] = ddm_value

    for ddm_type in mscp_data.get("ddm", {}).get("supported_types", []):
        if ddm_type not in ddm_dict.keys():
            logger.error(f"Unsupported ddm type: {ddm_type}")
            continue

        if "files" in ddm_type:
            for service in mscp_data.get("ddm", {}).get("services", {}):
                logger.debug(f"Service Name: {service}")
                for path in ddm_output_path.rglob(service):
                    logger.info(f"Found configuration files for {service}, zipping")
                    logger.debug(f"Folder path: {path}")
                    zip_path_str: str = str(f"{assets_output_path}/{service}")

                    ddm_identifier: str = f'org.mscp.{baseline_name}.asset.{service.split(".")[2]}'
                    activation_ddm_identifier: str = ddm_identifier.replace("config", "activation").replace("asset", "activation")
                    config_ddm_identifier: str = ddm_identifier.replace("asset", "config")

                    asset_file_path: Path = Path(assets_output_path, f"{ddm_identifier}.json")
                    config_file_path: Path = Path(configurations_output_path, f"{config_ddm_identifier}.json")
                    activation_file_path: Path = Path(activations_output_path, f"{activation_ddm_identifier}.json")

                    try:
                        shutil.make_archive(zip_path_str, 'zip', base_dir=path, logger=logger)
                    except IOError as e:
                        logger.error(f"Unable to create zip file for {service}. Error: {e}.")

                    if Path(f"{zip_path_str}.zip").exists():
                        remove_dir(path)

                    zip_path: Path = Path(f"{zip_path_str}.zip")
                    sha256_hash = hashlib.sha256()
                    sha256_hash.update(zip_path.read_bytes())
                    zip_sha = sha256_hash.hexdigest()

                    asset_ddm_json: dict = {
                        "Identifier": ddm_identifier,
                        "Type": "com.apple.asset.data",
                        "Payload": {
                            "Reference": {
                                "ContentType": "application/zip",
                                "DataURL": f"https://hostname.site.com/{service}.zip",
                                "Hash-SHA-256": str(zip_sha)
                            },
                            "Authentication": {
                                "Type": "None"
                            }
                        }
                    }

                    configuration_ddm_json: dict = {
                        "Identifier": config_ddm_identifier,
                        "Type": ddm_type,
                        "Payload": {
                            "ServiceType": service,
                            "DataAssetReference": ddm_identifier
                        }
                    }

                    append_text(asset_file_path, json.dumps(asset_ddm_json, indent=4))
                    append_text(config_file_path, json.dumps(configuration_ddm_json, indent=4))

                    generate_ddm_activation(activation_file_path, ddm_identifier)
        else:
            logger.debug(f"Building any declarations for {ddm_type}...")
            ddm_identifier = f'org.mscp.{baseline_name}.config.{ddm_type.replace("com.apple.configuration.", "")}'
            activation_ddm_identifier: str = ddm_identifier.replace("config", "activation").replace("asset", "activation")
            config_file_path: Path = Path(configurations_output_path, f"{ddm_identifier}.json")
            activation_file_path: Path = Path(activations_output_path, f"{activation_ddm_identifier}.json")

            ddm_json = {
                "Identifier": ddm_identifier,
                "Type": ddm_type,
                "Payload": ddm_dict.get(ddm_type, {})
            }

            append_text(config_file_path, json.dumps(ddm_json, indent=4))

            generate_ddm_activation(activation_file_path, ddm_identifier)
