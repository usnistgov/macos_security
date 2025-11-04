# mscp/common_utils/file_handling.py

# Standard python modules
import csv
import json
import plistlib
from collections.abc import Callable, MutableMapping
from pathlib import Path
from typing import Any

# Additional python modules
# import yaml
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.scalarstring import LiteralScalarString

from .error_handling import (
    COMMON_ERRORS,
    CSV_ERRORS,
    JSON_ERRORS,
    PLIST_ERRORS,
    YAML_ERRORS,
    log_expected_errors,
)

# Local python modules
from .logger_instance import logger

ENCODING: str = "utf-8"
READ_HANDLERS: dict[str, Callable[[Path], object]] = {}
WRITE_HANDLERS: dict[str, Callable[[Path, Any], None]] = {}

yaml = YAML()
yaml.preserve_quotes = True
yaml.explicit_start = True
yaml.indent(mapping=2, sequence=4, offset=2)
yaml.allow_unicode = True
yaml.width = 4096


def _to_literal_scalars(obj):
    if isinstance(obj, dict):
        return {k: _to_literal_scalars(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_literal_scalars(v) for v in obj]
    if isinstance(obj, str) and "\n" in obj:
        lit = LiteralScalarString(obj)
        # Optional: control trailing newline behavior
        # lit.fa.set_chomp('strip')  # -> |-
        return lit
    return obj


def register_read_handler(*extensions: str):
    def decorator(func: Callable[[Path], object]):
        for ext in extensions:
            READ_HANDLERS[ext.lower()] = func
        return func

    return decorator


def register_write_handler(*suffixes: str):
    def decorator(func: Callable[[Path, Any], None]):
        for suffix in suffixes:
            WRITE_HANDLERS[suffix.lower()] = func
        return func

    return decorator


def open_file(file_path: Path) -> Any:
    handler = READ_HANDLERS.get(file_path.suffix.lower(), open_text)
    return handler(file_path)


def create_file(file_path: Path, data: Any) -> None:
    writer = WRITE_HANDLERS.get(file_path.suffix.lower())
    if writer:
        writer(file_path, data)
    else:
        logger.warning("No writer registered for {}, using fallback", file_path.suffix)
        create_text(file_path, data)


@log_expected_errors(COMMON_ERRORS, context="Reading text file: ")
def open_text(file_path: Path) -> str:
    """
    Attempts to open a text file and read it's contents with error checking and logging

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        str: The content of the file if successful, None if otherwise.
    """

    logger.debug(f"Attempting to open text file: {file_path}")
    return file_path.read_text(encoding=ENCODING)


@register_read_handler(".yaml", ".yml")
@log_expected_errors(YAML_ERRORS, context="Reading YAML file: ")
def open_yaml(file_path: Path) -> CommentedMap | MutableMapping | None:
    """
    Attempts to open a yaml file and read its contents with error checking and logging

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        dict[str, Any]: The content of the file if successful, {} otherwise.
    """
    logger.debug("Attempting to open YAML: {}", file_path)

    with file_path.open("r", encoding=ENCODING) as f:
        data: MutableMapping | None = yaml.load(f)
        if data is None:
            return CommentedMap()
        if not isinstance(data, MutableMapping):
            raise TypeError(f"Unexpected YAML structure in {file_path}")
        return data


@register_read_handler(".csv")
@log_expected_errors(CSV_ERRORS, context="Reading CSV file: ")
def open_csv(file_path: Path) -> dict[str, Any]:
    """
    Attempts to open a csv file and read its contents with error checking and logging

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        dict[str, Any]: The content of the file as a list of dictionaries if successful.
    """

    logger.debug("Attempting to open CSV: {}", file_path)
    data = csv.DictReader(file_path.read_text(encoding="utf-8-sig"), dialect="excel")
    return data if isinstance(data, dict) else {}


@register_read_handler(".plist", ".mobileconfig")
@log_expected_errors(PLIST_ERRORS, context="Reading plist file: ")
def open_plist(file_path: Path) -> dict[str, dict[str, bool]] | None:
    """
    Attempts to open a plist file and read its contents with error checking and logging.

    This function uses the `plistlib` module to parse the contents of a plist file.
    It includes error handling for various exceptions such as invalid file format,
    file not found, permission issues, and other I/O errors. Errors are logged
    appropriately before being raised.

        file_path (Path): The path to the plist file to be opened.

        dict[str, dict[str, bool]] | None: The parsed content of the plist file as a dictionary
        if successful, or None if an error occurs.
    """

    logger.debug("Attempting to open plist: {}", file_path)

    with file_path.open("rb") as file:
        return plistlib.load(file)


@register_read_handler(".json")
@log_expected_errors(JSON_ERRORS, context="Reading JSON file: ")
def open_json(file_path: Path) -> dict[str, Any]:
    """
    Opens a JSON file and returns its contents as a dictionary.

    Args:
        file_path (Path): The path to the JSON file to be opened.

    Returns:
        dict[str, Any]: The contents of the JSON file as a dictionary.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If there is insufficient permission to read the file.
        IOError: If an I/O error occurs while reading the file.
        Exception: For any other exceptions that may occur during file handling.

    Logs:
        Logs debug information when attempting to open the file.
        Logs an error message if an exception occurs during file handling.
    """

    logger.debug("Attempting to open JSON: {}", file_path)

    with file_path.open("r") as file:
        return json.load(file)


@register_write_handler(".yaml", ".yml")
@log_expected_errors(YAML_ERRORS, context="Creating YAML file: ")
def create_yaml(file_path: Path, data: MutableMapping) -> None:
    """
    Create YAML file.

    Args:
        file_path (Path): The path to the file that the data will be added to.
        data (dict): The data that will be added to the file.
        sort_keys (bool): Sort the keys. Default is False
    Returns:
        None: The function writes directly to the file and does not return a value.
    """
    logger.debug("Attempting to create YAML: {}", file_path)

    normalized = _to_literal_scalars(data)
    clean_data: CommentedMap = CommentedMap(normalized)

    if not file_path.exists():
        file_path.touch()

    with file_path.open("w", encoding=ENCODING) as f:
        yaml.dump(clean_data, f)

    logger.success("Created YAML: {}", file_path)


@log_expected_errors(COMMON_ERRORS, context="Creating text file: ")
def create_text(file_path: Path, data: str) -> None:
    """
    Write the supplied data to a file.

    Args:
        file_path (Path): The path to the file to which data will be written.
        data (str): The data to write to the file.

    Returns:
        None: The function writes directly to the file and does not return a value.
    """

    file_path.write_text(data, encoding=ENCODING)


@register_write_handler(".plist", ".mobileconfig")
@log_expected_errors(PLIST_ERRORS, context="Creating plist file: ")
def create_plist(file_path: Path, data: dict[str, Any]) -> None:
    with file_path.open("wb") as file:
        plistlib.dump(data, file)


@register_write_handler(".json")
@log_expected_errors(JSON_ERRORS, context="Creating JSON file: ")
def create_json(file_path: Path, data: dict[str, Any]) -> None:
    """
    Creates a JSON file at the specified file path with the given data.

    Args:
        file_path (Path): The path where the JSON file will be created.
        data (dict[str, Any]): The data to be written to the JSON file.

    Raises:
        Exception: If an error occurs while writing to the file, it logs the error and re-raises the exception.
    """
    file_path.write_text(json.dumps(data, indent=1))


@register_write_handler(".csv")
@log_expected_errors(CSV_ERRORS, context="Creating CSV file: ")
def create_csv(file_path: Path, data: list[dict[str, Any]]) -> None:
    """
    Creates a CSV file at the specified file path with the given data.

    Args:
        file_path (Path): The path where the CSV file will be created.
        data (list[dict[str, Any]]): The data to be written to the CSV file.

    Raises:
        Exception: If an error occurs while writing to the file, it logs the error and re-raises the exception.
    """
    with file_path.open("w", newline="", encoding=ENCODING) as file:
        writer = csv.DictWriter(file, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)


@log_expected_errors(COMMON_ERRORS, context="Creating directory: ")
def make_dir(folder_path: Path) -> None:
    """
    Creates a directory at the specified folder path if it does not already exist.

    Args:
        folder_path (Path): The path of the folder to be created.

    Logs:
        Success message if the directory is created successfully.
    """
    if not folder_path.exists():
        folder_path.mkdir(parents=True)
        logger.success("Created folder: {}", folder_path)


@log_expected_errors(COMMON_ERRORS, context="Appending text to file: ")
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
    logger.debug(f"Appending to file: {file_path}")
    with file_path.open(
        mode="a", encoding=encoding, errors=errors, newline=newline
    ) as f:
        f.write(f"{text}\n")
        logger.success("Appended to file: {}", file_path)


@log_expected_errors(COMMON_ERRORS, context="Removing directory: ")
def remove_dir(folder_path: Path) -> None:
    """
    Remove a directory and all its contents.

    This function removes the specified directory and all its files and subdirectories.
    It logs the process of removal and handles any errors that may occur.

    Args:
        folder_path (Path): The path to the directory to be removed.

    Raises:
        OSError: If an error occurs during the removal process.
    """

    if not folder_path.exists():
        logger.warning("Directory does not exist: {}", folder_path)
        return

    logger.debug("Attempting to remove folder: {}", folder_path)

    for root, dirs, files in folder_path.walk(top_down=False):
        for name in files:
            (root / name).unlink()
        for name in dirs:
            (root / name).rmdir()

    folder_path.rmdir()
    logger.success("Removed folder: {}", folder_path)


@log_expected_errors(COMMON_ERRORS, context="Removing directory contents: ")
def remove_dir_contents(folder_path: Path) -> None:
    """
    Remove the contents of a directory without removing the directory itself.

    This function removes all files and subdirectories within the specified directory.
    It logs the process of removal and handles any errors that may occur.

    Args:
        folder_path (Path): The path to the directory whose contents will be removed.

    Raises:
        OSError: If an error occurs during the removal process.
    """

    if not folder_path.exists():
        logger.warning("Directory does not exist: {}", folder_path)
        return

    logger.debug("Removing contents of folder: {}", folder_path)

    for root, dirs, files in folder_path.walk(top_down=False):
        for name in files:
            (root / name).unlink()
        for name in dirs:
            (root / name).rmdir()

    logger.success("Removed contents of folder: {}", folder_path)


@log_expected_errors(COMMON_ERRORS, context="Removing file: ")
def remove_file(file_path: Path) -> None:
    """
    Remove the specified file if it exists.

    Args:
        file_path (Path): The path to the file to be removed.

    Raises:
        OSError: If an error occurs while removing the file.

    Logs:
        Success: When the file is successfully removed.
        Warning: If the file is not found.
        Error: If an error occurs while removing the file.
    """

    if not file_path.exists():
        logger.warning("File does not exist: {}", file_path)
        return

    logger.debug("Attempting to remove file: {}", file_path)

    file_path.unlink()
    logger.success("Removed file: {}", file_path)
