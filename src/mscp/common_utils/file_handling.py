# mscp/common_utils/file_handling.py

# Standard python modules
import csv
import json
import plistlib
from pathlib import Path
from typing import Any

# Additional python modules
import yaml

# Local python modules
from .logger_instance import logger

ENCODING: str = "utf-8"


def _str_presenter(dumper, data):
    """
    Preserve multiline strings when dumping yaml.
    https://github.com/yaml/pyyaml/issues/240
    """
    if "\n" in data:
        # Remove trailing spaces messing out the output.
        block = "\n".join([line.rstrip() for line in data.splitlines()])
        if data.endswith("\n"):
            block += "\n"
        return dumper.represent_scalar("tag:yaml.org,2002:str", block, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.add_representer(str, _str_presenter)
yaml.representer.SafeRepresenter.add_representer(str, _str_presenter)


def open_file(file_path: Path, language: str = "en") -> Any:
    """
    Attempts to open a file and read its contents with error checking and logging.

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        str: The content of the file if successful.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If there are insufficient permissions to access the file.
        IOError: If an I/O error occurs during file operations.
        Exception: For any other unexpected errors.
    """

    match file_path.suffix:
        case ".yaml" | ".yml":
            return open_yaml(file_path, language=language)
        case ".csv":
            return open_csv(file_path)
        case ".plist" | ".mobileconfig":
            return open_plist(file_path)
        case ".json":
            return open_json(file_path)
        case _:
            return open_text(file_path)


def open_text(file_path: Path) -> str:
    """
    Attempts to open a text file and read it's contents with error checking and logging

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        str: The content of the file if successful, None if otherwise.
    """

    try:
        logger.debug(f"Attempting to open text file: {file_path}")
        return file_path.read_text(encoding=ENCODING)

    except Exception as e:
        logger.error(
            f"An error occurred while opening the file: {file_path}. Error: {e}"
        )
        raise


def open_yaml(
    file_path: Path,
    language: str = None,
) -> dict[str, Any]:
    """
    Attempts to open a yaml file and read its contents with error checking and logging.
    Supports !localize tags for automatic gettext localization.

    Args:
        file_path (Path): The path to the file to be opened.
        language (str, optional): Language code for localization (e.g., "de", "fr"). If None, uses current gettext config.
        domain (str): localization domain name. Defaults to "messages".
        localedir (str): Path to the locales directory. Defaults to "config/locales".

    Returns:
        dict[str, Any]: The content of the file if successful, empty dict otherwise.
    """

    try:
        logger.debug("Attempting to open YAML: {}", file_path)
        # Note: localization should be configured globally before YAML processing
        # configure_localization_for_yaml is now called at the application level

        data = yaml.safe_load(file_path.read_text(encoding=ENCODING))
        return data if isinstance(data, dict) else {}

    except (
        yaml.YAMLError,
        Exception,
    ) as e:
        logger.error(
            "An error occurred while opening the file: {}. Error: {}", file_path, e
        )
        raise


def open_csv(file_path: Path) -> dict[str, Any]:
    """
    Attempts to open a csv file and read its contents with error checking and logging

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        dict[str, Any]: The content of the file as a list of dictionaries if successful.
    """

    try:
        logger.debug("Attempting to open CSV: {}", file_path)
        data = csv.DictReader(
            file_path.read_text(encoding="utf-8-sig"), dialect="excel"
        )
        return data if isinstance(data, dict) else {}

    except (csv.Error, Exception) as e:
        logger.error(
            f"An error occurred while opening the file: {file_path}. Error: {e}"
        )
        raise


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

    Raises:
        plistlib.InvalidFileException: If the file is not a valid plist.
        FileNotFoundError: If the file does not exist.
        PermissionError: If there are insufficient permissions to read the file.
        IOError: If an I/O error occurs while accessing the file.
        Exception: For any other unexpected errors.
    """

    try:
        logger.debug("Attempting to open plist: {}", file_path)

        with file_path.open("rb") as file:
            return plistlib.load(file)
    except plistlib.InvalidFileException as e:
        logger.error(
            "An error occurred while processing the file: {}. Error: {}", file_path, e
        )
        raise

    except Exception as e:
        logger.error(
            "An error occurred while opening the file: {}. Error: {}", file_path, e
        )
        raise


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

    try:
        logger.debug("Attempting to open JSON: {}", file_path)

        with file_path.open("r") as file:
            return json.load(file)

    except Exception as e:
        logger.error(
            "An error occurred while opening the file: {}. Error: {}", file_path, e
        )
        raise


def create_file(file_path: Path, data: Any) -> None:
    """
    Attempts to create a file with error checking and logging.

    Args:
        file_path (Path): The path to the file to be created.

    Returns:
        None: The function writes directly to the file and does not return a value.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If there are insufficient permissions to access the file.
        IOError: If an I/O error occurs during file operations.
        Exception: For any other unexpected errors.
    """

    match file_path.suffix:
        case ".yaml" | ".yml":
            create_yaml(file_path, data)
        case ".csv":
            create_csv(file_path, data)
        case ".plist" | ".mobileconfig":
            create_plist(file_path, data)
        case ".json":
            create_json(file_path, data)
        case _:
            create_text(file_path, data)


def create_yaml(file_path: Path, data: dict[str, Any]) -> None:
    """
    Create YAML file.

    Args:
        file_path (Path): The path to the file that the data will be added to.
        data (dict): The data that will be added to the file.
        sort_keys (bool): Sort the keys. Default is False
    Returns:
        None: The function writes directly to the file and does not return a value.
    """
    try:
        logger.debug("Attempting to create YAML: {}", file_path)

        if not file_path.exists():
            file_path.touch()

        file_path.write_text(
            yaml.dump(
                dict(data),
                default_flow_style=False,
                sort_keys=False,
                explicit_start=True,
                indent=2,
                allow_unicode=True,
            ),
            encoding=ENCODING,
        )

        logger.success("Created YAML: {}", file_path)

    except yaml.YAMLError as e:
        logger.error(
            "An error occurred while processing the file: {}. Error: {}", file_path, e
        )
        raise

    except Exception as e:
        logger.error(
            "An error occurred while opening the file: {}. Error: {}", file_path, e
        )
        raise


def create_text(file_path: Path, data: str) -> None:
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
    except IOError as e:
        logger.error(
            "An error occurred while opening the file: {}. Error: {}", file_path, e
        )
        raise


def create_plist(file_path: Path, data: dict[str, Any]) -> None:
    try:
        with file_path.open("wb") as file:
            plistlib.dump(data, file)
    except Exception as e:
        logger.error(
            "An error occurred while processing the file: {}. Error: {}", file_path, e
        )
        raise


def create_json(file_path: Path, data: dict[str, Any]) -> None:
    """
    Creates a JSON file at the specified file path with the given data.

    Args:
        file_path (Path): The path where the JSON file will be created.
        data (dict[str, Any]): The data to be written to the JSON file.

    Raises:
        Exception: If an error occurs while writing to the file, it logs the error and re-raises the exception.
    """
    try:
        file_path.write_text(json.dumps(data, indent=1))
    except Exception as e:
        logger.error(
            "An error occurred while processing the file: {}. Error: {}", file_path, e
        )
        raise


def create_csv(file_path: Path, data: list[dict[str, Any]]) -> None:
    """
    Creates a CSV file at the specified file path with the given data.

    Args:
        file_path (Path): The path where the CSV file will be created.
        data (list[dict[str, Any]]): The data to be written to the CSV file.

    Raises:
        Exception: If an error occurs while writing to the file, it logs the error and re-raises the exception.
    """
    try:
        with file_path.open("w", newline="", encoding=ENCODING) as file:
            writer = csv.DictWriter(file, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
    except Exception as e:
        logger.error(
            "An error occurred while processing the file: {}. Error: {}", file_path, e
        )
        raise


def make_dir(folder_path: Path) -> None:
    """
    Creates a directory at the specified folder path if it does not already exist.

    Args:
        folder_path (Path): The path of the folder to be created.

    Raises:
        OSError: If the directory creation fails.

    Logs:
        Success message if the directory is created successfully.
        Error message if the directory creation fails.
        Debug message with the error details if the directory creation fails.
    """
    if not folder_path.exists():
        try:
            folder_path.mkdir(parents=True)
            logger.success("Created folder: {}", folder_path)
        except OSError as e:
            logger.error("Creation of {} failed.", folder_path)
            logger.debug("Error message: {}", str(e))
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
        logger.debug(f"Appending to file: {file_path}")
        with file_path.open(
            mode="a", encoding=encoding, errors=errors, newline=newline
        ) as f:
            f.write(f"{text}\n")
            logger.success("Appended to file: {}", file_path)

    except Exception as e:
        logger.error(f"Error occurred: {e}")
        raise


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
    if folder_path.exists():
        try:
            logger.debug("Removing folder: {}", folder_path)
            for root, dirs, files in folder_path.walk(top_down=False):
                for name in files:
                    (root / name).unlink()
                for name in dirs:
                    (root / name).rmdir()

            folder_path.rmdir()
            logger.success("Removed folder: {}", folder_path)

        except OSError as e:
            logger.error("Removal of {} failed.", folder_path)
            logger.debug("Error message: {}", str(e))
            raise


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
    if folder_path.exists():
        try:
            logger.debug("Removing contents of folder: {}", folder_path)
            for root, dirs, files in folder_path.walk(top_down=False):
                for name in files:
                    (root / name).unlink()
                for name in dirs:
                    (root / name).rmdir()

            logger.success("Removed contents of folder: {}", folder_path)

        except OSError as e:
            logger.error("Removal of {} failed.", folder_path)
            logger.debug("Error message: {}", str(e))
            raise


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
    if file_path.exists():
        try:
            file_path.unlink()
            logger.success("Removed file: {}", file_path)

        except FileNotFoundError:
            logger.warning("File Name not found: {}", file_path)

        except OSError as e:
            logger.error(
                "An error occurred while removing the file: {}. Error: {}", file_path, e
            )
            raise
