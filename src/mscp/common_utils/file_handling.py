# mscp/common_utils/file_handling.py

# Standard python modules
import logging
import yaml
import csv
import plistlib

from pathlib import Path
from typing import Optional, Any
from icecream import ic

# Local python modules

# Initialize logger
logger = logging.getLogger(__name__)


ENCODING = 'utf-8'

def open_file(file_path: Path) -> Optional[Any]:
    """
    Attempts to open a file and read it's contents with error checking and logging

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        Optional[Any]: The content of the file if successful, None if otherwise.
    """

    try:
        logger.debug(f"Attempting to open file: {file_path}")
        return file_path.read_text(encoding=ENCODING)

    except (FileNotFoundError, PermissionError, IOError, Exception) as e:
        logger.error(
            f"An error occurred while opening the file: {file_path}. Error: {e}"
        )
        raise


def open_yaml(file_path: Path) -> dict[str, Any]:
    """
    Attempts to open a yaml file and read it's contents with error checking and logging

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        dict[str, Any]: The content of the file if successful, None if otherwise.
    """

    try:
        logger.debug(f"Attempting to open YAML: {file_path}")

        data = yaml.safe_load(file_path.read_text(encoding=ENCODING))
        return data if isinstance(data, dict) else {}

    except (
        FileNotFoundError,
        PermissionError,
        yaml.YAMLError,
        IOError,
        Exception,
    ) as e:
        logger.error(
            f"An error occurred while opening the file: {file_path}. Error: {e}"
        )
        raise


def open_csv(file_path: Path) -> dict[str, Any]:
    """
    Attempts to open a csv file and read it's contents with error checking and logging

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        dict[str, Any]: The content of the file if successful, None if otherwise.
    """

    try:
        logger.debug(f"Attempting to open CSV: {file_path}")
        data = csv.DictReader(file_path.read_text(encoding='utf-8-sig'), dialect="excel")
        return data if isinstance(data, dict) else {}

    except (FileNotFoundError, PermissionError, csv.Error, IOError, Exception) as e:
        logger.error(
            f"An error occurred while opening the file: {file_path}. Error: {e}"
        )
        raise


def open_plist(file_path: Path) -> dict[str, dict[str, bool]]:
    """
    Attempts to open a plist file and read its contents with error checking and logging

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        Optional[dict[str, Any]]: The content of the file if successful, None if otherwise.
    """
    try:
        logger.debug(f"Attempting to open plist: {file_path}")
        return plistlib.load(file_path.read_bytes())


    except (FileNotFoundError, PermissionError, plistlib.InvalidFileException, IOError, Exception) as e:
        logger.error(
            f"An error occurred while opening the file: {file_path}. Error: {e}"
        )
        raise


def create_yaml(
    file_path: Path, data: dict[str, Any], yaml_type: str, sort_keys: bool = False
) -> None:
    """
    Create YAML file.

    Args:
        file_path (Path): The path to the file that the data will be added to.
        data (dict): The data that will be added to the file.
        yaml_type (str): What type of yaml are you outputting, baseline or rule.
        sort_keys (bool): Sort the keys. Default is False
    Returns:
        None: The function writes directly to the file and does not return a value.
    """
    try:
        yaml_content: str = "---\n"

        match yaml_type:
            case "baseline":
                yaml_content += "# yaml-language-server: $schema=https://raw.githubusercontent.com/snoopy82481/macos_security/main/schemas/baseline.json\n"
            case "rule":
                yaml_content += "# yaml-language-server: $schema=https://raw.githubusercontent.com/snoopy82481/macos_security/main/schemas/rules.json\n"
            case _:
                logger.error("Yaml type has no schema validation yet.")

        with file_path.open("w", encoding=ENCODING) as file:
            file.write(yaml_content)
            yaml.dump(
                dict(data), stream=file, explicit_start=False, sort_keys=sort_keys, indent=2, default_flow_style=False
            )

    except Exception as e:
        logger.error(f"Error processing {file_path}: {e}")
        raise


def create_file(file_path: Path, data: str) -> None:
    """
    Write the supplied data to a file.

    Args:
        file_path (Path): The path to the file to which data will be written.
        data (str): The data to write to the file.

    Returns:
        None: The function writes directly to the file and does not return a value.
    """
    try:
        file_path.write_text(data, encoding=ENCODING)
    except (FileNotFoundError, PermissionError, IOError) as e:
        logger.error(
            f"Error occurred while writing to the file: {file_path}. Error: {e}"
        )
        raise


def create_plist(file_path: Path, data: dict[str, Any]) -> None:
    try:
        plistlib.dump(data, file_path.write_bytes())
    except Exception as e:
        logger.error(f"Error processing {file_path}: {e}")
        raise


def make_dir(folder_path: Path) -> None:
    if not folder_path.exists():
        try:
            folder_path.mkdir(parents=True)
            logger.debug(f"Created folder: {folder_path}")
        except OSError as e:
            logger.error(f"Creation of {folder_path} failed.")
            logger.debug(f"Error message: {str(e)}")
            raise


def append_text(
    file_path: Path, text: str, encoding: str = ENCODING, errors=None, newline=None
) -> None:
    """
    Append text to a file, creating the file if it does not exist.

    Args:
        file_path (Path): The path to the file to which text will be appended.
        text (str): The text to append to the file.
        encoding (str, optional): The encoding used to write the text. Defaults to 'utf-8'.
        errors (str, optional): Specifies how encoding/decoding errors are handled. Defaults to 'strict'.
        newline (str, optional): Specifies how newlines are handled. Defaults to None.

    Returns:
        None: The function writes directly to the file and does not return a value.
    """
    try:
        with file_path.open(
            mode="a", encoding=encoding, errors=errors, newline=newline
        ) as f:
            logger.debug(f"Appending to file: {file_path}")
            f.write(f"{text}\n")

    except Exception as e:
        logger.error(f"Error occurred: {e}")
        raise


def remove_dir(folder_path: Path) -> None:
    if folder_path.exists():
        try:
            for root, dirs, files in folder_path.walk(top_down=False):
                for name in files:
                    (root / name).unlink()
                for name in dirs:
                    (root / name).rmdir()

            folder_path.rmdir()
            logger.debug(f"Removed folder: {folder_path}")

        except OSError as e:
            logger.error(f"Removal of {folder_path} failed.")
            logger.debug(f"Error message: {str(e)}")
            raise


def remove_file(file_path: Path) -> None:
    if file_path.exists():
        try:
            file_path.unlink()
            logger.debug(f"Removed file: {file_path}")
        except FileNotFoundError as e:
            logger.warning(f"File Name not found: {file_path}")

        except OSError as e:
            logger.error(
                f"An error occurred while removing the file: {file_path}. Error: {e}"
            )
            logger.debug(f"Error message: {str(e)}")
            raise
