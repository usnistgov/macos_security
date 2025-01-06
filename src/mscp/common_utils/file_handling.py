# mscp/common_utils/file_handling.py

# Standard python modules
import logging
import yaml

from pathlib import Path
from typing import Optional, Any, List

# Local python modules

# Initialize logger
logger = logging.getLogger(__name__)


def open_file(file_path: Path) -> Optional[Any]:
    """
    Attempts to open a file and read it's contents with error checking and logging

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        Optional[Any]: The content of the file if successful, None if otherwise.
    """

    try:
        logger.info(f"Attempting to open file: {file_path}")

        with file_path.open("r") as file:
            logger.info(f"Successfully read the file {file_path}")
            return file.read()

    except (FileNotFoundError,PermissionError, IOError, Exception) as e:
        logger.error(f"An error occurred while opening the file: {file_path}. Error: {e}")

    return None


def open_yaml(file_path: Path) -> dict[str, Any]:
    """
    Attempts to open a file and read it's contents with error checking and logging

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        Optional[Any]: The content of the file if successful, None if otherwise.
    """

    try:
        logger.info(f"Attempting to open file: {file_path}")

        with file_path.open("r", encoding='utf-8') as file:
            logger.info(f"Successfully read the file {file_path}")
            data = yaml.safe_load(file)
            return data if isinstance(data, dict) else {}

    except (FileNotFoundError,PermissionError,yaml.YAMLError, IOError, Exception) as e:
        logger.error(f"An error occurred while opening the file: {file_path}. Error: {e}")
        return {}


def make_dir(folder_path: Path) -> None:
    if not folder_path.exists():
        try:
            folder_path.mkdir(parents=True)
            logger.info(f"Created folder: {folder_path}")
        except OSError as e:
            logger.error(f"Creation of {folder_path} failed.")
            logging.debug(f"Error message: {str(e)}")


def append_text(path: Path, text: str, encoding: str = "UTF-8", errors=None, newline=None) -> None:
    """
    Append text to a file, creating the file if it does not exist.

    Args:
        path (Path): The path to the file to which text will be appended.
        text (str): The text to append to the file.
        encoding (str, optional): The encoding used to write the text. Defaults to 'utf-8'.
        errors (str, optional): Specifies how encoding/decoding errors are handled. Defaults to 'strict'.
        newline (str, optional): Specifies how newlines are handled. Defaults to None.

    Returns:
        None: The function writes directly to the file and does not return a value.
    """
    try:
        with path.open(mode='a', encoding=encoding, errors=errors, newline=newline) as f:
            logging.info(f"Appending to file: {path}")
            f.write(f"{text}\n")

    except Exception as e:
        logger.error(f"Error occurred: {e}")


def remove_dir(folder_path: Path) -> None:
    if folder_path.exists():
        try:
            for root,dirs,files in folder_path.walk(top_down=False):
                for name in files:
                    (root / name).unlink()
                for name in dirs:
                    (root / name).rmdir()

            folder_path.rmdir()
            logger.info(f"Removed folder: {folder_path}")

        except OSError as e:
            logger.error(f"Removal of {folder_path} failed.")
            logging.debug(f"Error message: {str(e)}")
