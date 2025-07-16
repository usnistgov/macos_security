# mscp/classes/filehandler.py

# Standard python modules
import csv
import json
import plistlib
from pathlib import Path
from typing import Any

# Additional python modules
import yaml
from pydantic import BaseModel

from ..common_utils.logger_instance import logger


class FileHandler(BaseModel):
    ENCODING: str = "utf-8"
    file_path: Path

    def __init__(self, file_path: Path):
        """
        Initialize the FileHandler with a file path.
        """
        super().__init__()
        self.setup_yaml()
        self.file_path = file_path

    @staticmethod
    def _str_presenter(dumper, data):
        """
        Preserve multiline strings when dumping YAML.
        """
        if "\n" in data:
            block = "\n".join([line.rstrip() for line in data.splitlines()])
            if data.endswith("\n"):
                block += "\n"
            return dumper.represent_scalar("tag:yaml.org,2002:str", block, style="|")
        return dumper.represent_scalar("tag:yaml.org,2002:str", data)

    @classmethod
    def setup_yaml(cls):
        """
        Configure YAML to use the custom string presenter.
        """
        yaml.add_representer(str, cls._str_presenter)
        yaml.representer.SafeRepresenter.add_representer(str, cls._str_presenter)

    @classmethod
    def open_file(cls, file_path: Path) -> Any:
        """
        Open a file based on its extension and return its contents.
        """
        handlers = {
            ".yaml": cls.open_yaml,
            ".yml": cls.open_yaml,
            ".csv": cls.open_csv,
            ".plist": cls.open_plist,
            ".json": cls.open_json,
        }
        handler = handlers.get(file_path.suffix, cls.open_text)
        return handler(file_path)

    def open_text(self) -> str:
        """
        Open a text file and return its contents.
        """
        try:
            logger.debug(f"Attempting to open text file: {self.file_path}")
            return self.file_path.read_text(encoding=FileHandler.ENCODING)
        except Exception as e:
            logger.error(f"Error opening text file: {self.file_path}. Error: {e}")
            raise

    def open_yaml(self) -> dict[str, Any]:
        """
        Open a YAML file and return its contents as a dictionary.
        """
        try:
            logger.debug(f"Attempting to open YAML file: {self.file_path}")
            data = yaml.safe_load(
                self.file_path.read_text(encoding=FileHandler.ENCODING)
            )
            return data if isinstance(data, dict) else {}
        except Exception as e:
            logger.error(f"Error opening YAML file: {self.file_path}. Error: {e}")
            raise

    def open_csv(self) -> list[dict[str, Any]]:
        """
        Open a CSV file and return its contents as a list of dictionaries.
        """
        try:
            logger.debug(f"Attempting to open CSV file: {self.file_path}")
            with self.file_path.open(encoding=FileHandler.ENCODING) as file:
                return list(csv.DictReader(file))
        except Exception as e:
            logger.error(f"Error opening CSV file: {self.file_path}. Error: {e}")
            raise

    def open_plist(self) -> dict[str, Any]:
        """
        Open a plist file and return its contents as a dictionary.
        """
        try:
            logger.debug(f"Attempting to open plist file: {self.file_path}")
            with self.file_path.open("rb") as file:
                return plistlib.load(file)
        except Exception as e:
            logger.error(f"Error opening plist file: {self.file_path}. Error: {e}")
            raise

    def open_json(self) -> dict[str, Any]:
        """
        Open a JSON file and return its contents as a dictionary.
        """
        try:
            logger.debug(f"Attempting to open JSON file: {self.file_path}")
            with self.file_path.open("r", encoding=FileHandler.ENCODING) as file:
                return json.load(file)
        except Exception as e:
            logger.error(f"Error opening JSON file: {self.file_path}. Error: {e}")
            raise

    def create_yaml(self, data: dict[str, Any]) -> None:
        """
        Create a YAML file with the given data.
        """
        try:
            logger.debug(f"Attempting to create YAML file: {self.file_path}")
            self.file_path.write_text(
                yaml.dump(
                    data,
                    default_flow_style=False,
                    sort_keys=False,
                    explicit_start=True,
                    indent=2,
                    encoding=FileHandler.ENCODING,
                )
            )
            logger.success(f"Created YAML file: {self.file_path}")
        except Exception as e:
            logger.error(f"Error creating YAML file: {self.file_path}. Error: {e}")
            raise

    @classmethod
    def create_file(cls, data: Any) -> None:
        """
        Write the supplied data to a file.
        """
        handlers: dict = {
            ".yaml": cls.create_yaml,  # For YAML files
            ".yml": cls.create_yaml,  # For YAML files
            ".json": cls.create_json,  # For JSON files
            ".csv": cls.create_csv,  # For CSV files
            ".plist": cls.create_plist,  # For plist files, use JSON format
        }
        handler = handlers.get(cls.file_path.suffix, cls.create_text)
        handler(data)

    def create_text(self, data: str) -> None:
        """
        Write the supplied data to a text file at the specified path.
        This method uses the instance's file_path attribute.
        """
        try:
            logger.debug(f"Attempting to create text file: {self.file_path}")
            self.file_path.write_text(data, encoding=self.ENCODING)
            logger.success(f"Created text file: {self.file_path}")
        except Exception as e:
            logger.error(f"Error creating text file: {self.file_path}. Error: {e}")
            raise

    def create_json(self, data: dict[str, Any]) -> None:
        """
        Create a JSON file with the given data.
        """
        try:
            logger.debug(f"Attempting to create JSON file: {self.file_path}")
            self.file_path.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Error creating JSON file: {self.file_path}. Error: {e}")
            raise

    def create_csv(self, data: list[dict[str, Any]]) -> None:
        """
        Create a CSV file with the given data.
        """
        try:
            logger.debug(f"Attempting to create CSV file: {self.file_path}")
            with self.file_path.open(
                "w", newline="", encoding=FileHandler.ENCODING
            ) as file:
                writer = csv.DictWriter(file, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
        except Exception as e:
            logger.error(f"Error creating CSV file: {self.file_path}. Error: {e}")
            raise

    def create_plist(self, data: dict[str, Any]) -> None:
        try:
            with self.file_path.open("wb") as file:
                plistlib.dump(data, file)
        except Exception as e:
            logger.error(
                "An error occurred while processing the file: {}. Error: {}",
                self.file_path,
                e,
            )
            raise
