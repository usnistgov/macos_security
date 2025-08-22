# mscp/common_utils/localization.py

# Standard python modules
import gettext
import yaml
from typing import Optional

# Local python modules
from .config import config
from .logger_instance import logger

# Global variable to store the gettext localization function
_localization_function = gettext.gettext


def setup_gettext_localization(language: str = "en") -> None:
    """
    Configure gettext for localizations.

    Args:
        domain (str): The localization domain (usually "messages")
        localedir (str): Path to the locales directory
        language (str): Language code (e.g., "de", "fr", "es")
    """
    global _localization_function

    domain: str = "messages"
    localedir: str = config["defaults"]["locales_dir"]

    try:
        # Set up the localization
        localization = gettext.translation(
            domain=domain, localedir=localedir, languages=[language], fallback=True
        )
        _localization_function = localization.gettext
        logger.debug(f"Gettext configured for language: {language}, domain: {domain}")

    except Exception as e:
        logger.warning(f"Failed to setup gettext for language {language}: {e}")
        # Fallback to default gettext behavior
        _localization_function = gettext.gettext


def get_localization_function():
    """
    Get the current localization function.

    Returns:
        callable: The current gettext localization function
    """
    return _localization_function


def localize_string(text: str) -> str:
    """
    localize a string using the configured localization function.

    Args:
        text (str): The string to localize

    Returns:
        str: The localized string
    """
    return _localization_function(text)


def localize_constructor(loader, node):
    """
    Custom YAML constructor for !localize tag that uses gettext for localization.

    Args:
        loader: The YAML loader instance
        node: The YAML node containing the localize string

    Returns:
        str: The localized string using the configured gettext function
    """
    value = loader.construct_scalar(node)
    logger.debug(f"attempting to localize with value: {value}")
    return _localization_function(value)


def register_yaml_constructors() -> None:
    """
    Register the !localize YAML constructor with YAML loaders.

    This function should be called once to enable !localize tag support
    in YAML files.
    """
    yaml.add_constructor("!localize", localize_constructor)
    yaml.SafeLoader.add_constructor("!localize", localize_constructor)


def configure_localization_for_yaml(
    language: Optional[str] = None,
) -> None:
    """
    Configure localization and register YAML constructors in one call.

    Args:
        language (str, optional): Language code for localization (e.g., "de", "fr"). If None, uses current gettext config.
        domain (str): localization domain name. Defaults to "messages".
        localedir (str): Path to the locales directory. Defaults to "config/locales".
    """
    logger.debug(f"configure_localization_for_yaml called with language: {language}")
    # Register YAML constructors if not already done
    register_yaml_constructors()

    # Configure gettext if language is specified
    if language:
        logger.debug(f"Setting up gettext for language: {language}")
        setup_gettext_localization(language=language)
    else:
        logger.debug("No language specified, keeping current gettext config")
