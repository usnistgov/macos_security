# mscp/classes/basemodel.py

# Standard python modules
from typing import Any

# Additional python modules
from pydantic import BaseModel, ConfigDict


class BaseModelWithAccessors(BaseModel):
    """
    A base class that provides `get`, `__getitem__`, and `__setitem__` methods
    for all derived classes.
    """

    model_config: ConfigDict = ConfigDict(extra="ignore")

    def get(self, attr: str, default: Any = None) -> Any:
        """
        Get the value of an attribute, or return the default if it doesn't exist.
        """
        return getattr(self, attr, default)

    def __getitem__(self, key: str) -> Any:
        """
        Allow dictionary-like access to attributes.
        """
        if key in self.__class__.model_fields:
            return getattr(self, key)
        raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")

    def __setitem__(self, key: str, value: Any) -> None:
        """
        Allow dictionary-like setting of attributes.
        """
        if key in self.__class__.model_fields:
            setattr(self, key, value)
        else:
            raise KeyError(f"{key} is not a valid attribute of {self.__class__.__name__}")
