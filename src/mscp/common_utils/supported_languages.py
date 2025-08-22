# mscp/common_utils/supported_languages.py

# Standard python modules
from pathlib import Path
from typing import Any

# Local python modules
from .config import config
from .file_handling import open_file
from .logger_instance import logger

# Additional python modules


def get_supported_languages() -> list[str]:
    """
    Retrieve supported languages.

    Args:
        none

    Returns:
        list[str]: A list containing the available supported languages for localization.
    """

    localization_path = Path(config["defaults"]["locales_dir"])

    languages: list[str] = ["en"]
    logger.debug(
        f"Enumerating available languages from the localization path: {localization_path}"
    )

    for item in localization_path.iterdir():
        if item.is_dir():
            logger.debug(f"Found possible supported language file: {item}")
            languages.append(item.stem)

    return languages


def get_language_data(
    language: str,
    category: str,
) -> dict[str, Any]:
    language_file = Path(
        config["defaults"]["locales_dir"], language, category
    ).with_suffix(".yaml")

    try:
        logger.info("Attempting to open language file: {}", language_file)
        language_data: dict[str, Any] = open_file(language_file)

        return language_data

    except FileNotFoundError:
        logger.error("language file not found: {}", language_file)
        return {}

    except Exception as e:
        logger.error("Error parsing language file: {}", e)
        return {}


supported_languages = get_supported_languages()
