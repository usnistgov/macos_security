# mscp/generate/ddm.py

# Standard python modules
import logging
import json
import shutil
import hashlib

from pathlib import Path
from typing import List

# Local python modules
from src.mscp.classes.baseline import Baseline
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml, make_dir, append_text, remove_dir

# Initialize logger
logger = logging.getLogger(__name__)


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

    mscp_data: dict = open_yaml(Path(config["global"]["mspc_data"]))
    ddm_output_path: Path = Path(build_path, "declarative")
    activations_output_path: Path = Path(ddm_output_path, "activations")
    assets_output_path: Path = Path(ddm_output_path, "assets")
    configurations_output_path: Path = Path(ddm_output_path, "configurations")
    ddm_dict: dict = {}

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
        if ddm_rule.get("ddm_info", {}).get("declarationtype", "") == "com.apple.configuration.services.configuration-files":
            if not mscp_data.get("ddm", {}).get("services", {}).get(ddm_rule.get("ddm_info", {}).get("service")):
                logger.error(f"{ddm_rule.get("ddm_info", {}).get("service", "")} service NOT found")
                continue

            service_name = ddm_rule.get("ddm_info", {}).get("service", "")
            logger.debug(f"Service name: {service_name}")

            service_path = mscp_data.get("ddm", {}).get("services", {}).get(service_name, "")
            logger.debug(f"Service path: {service_path}")

            # ! Need to strip the trailing "/" so that pathlib does not treat it as an absolute path.
            service_config_dir: Path = Path(ddm_output_path, ddm_rule.get("ddm_info", {}).get("service", ""), str(mscp_data["ddm"]["services"][ddm_rule.get("ddm_info", {}).get("service")]).lstrip("/"))
            service_config_file: Path = service_config_dir / ddm_rule.get("ddm_info", {}).get("config_file")

            logging.debug(f"Configuration Directory name: {service_config_dir}")
            logging.debug(f"Configuration File name: {service_config_file}")

            if not service_config_dir.exists():
                make_dir(service_config_dir)

            if ddm_rule.get("ddm_info", {}).get("configuration_key", "") == "file":
                append_text(service_config_file, ddm_rule.get("ddm_info", {}).get("configuration_value", ""), encoding='UTF-8', newline='\n')
            else:
                append_text(service_config_file, f"{ddm_rule.get("ddm_info", {}).get("configuration_key", "")} {ddm_rule.get("ddm_info", {}).get("configuration_value", "")}", encoding='UTF-8', newline='\n')

            ddm_dict.setdefault(ddm_rule.get("ddm_info", {}).get("declarationtype", ""), {}).update({})
        else:
            ddm_dict.setdefault(ddm_rule.get("ddm_info", {}).get("declarationtype", ""), {}).update(
                {ddm_rule.get("ddm_info", {}).get("ddm_key", ""): ddm_rule.get("ddm_info", {}).get("ddm_value", "")}
                )

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
