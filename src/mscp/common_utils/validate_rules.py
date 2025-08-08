# src/mscp/validate_rules.py

# Standard python modules
import argparse
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

# Local python modules
from . import SCHEMA_PATH, config, open_file
from .logger_instance import logger

# Additional python modules


def validate_yaml_file(args: argparse.Namespace) -> None:
    schema: dict = open_file(Path(SCHEMA_PATH))
    validator = Draft202012Validator(schema)

    yaml_files: list = list(Path(config["defaults"]["rules_dir"]).rglob("*.y*ml"))

    if not yaml_files:
        logger.error("No YAML files found in rules directory.")
        return

    logger.info(
        f"Validating {len(yaml_files)} YAML files in '{config['defaults']['rules_dir']}'...\n"
    )

    for yaml in yaml_files:
        data: dict = open_file(yaml)
        try:
            validator.validate(data)
            if not args.only_invalid:
                logger.info(f"✅ VALID:   {yaml}")
        except ValidationError as e:
            logger.warning(f"❌ INVALID: {yaml}")
            logger.warning(f"   → {e.message}")
        except Exception as e:
            logger.error(f"⚠️ ERROR:   {yaml}")
            logger.error(f"   → {e}")
