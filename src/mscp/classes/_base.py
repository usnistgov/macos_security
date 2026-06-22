# mscp/classes/_base.py
"""Shared Pydantic base class with dict-style accessors.

A single definition consumed by both `baseline` and `macsecurityrule` to
avoid duplication and keep behavior consistent.
"""

from typing import Any

from pydantic import BaseModel

__all__ = ["BaseModelWithAccessors"]


class BaseModelWithAccessors(BaseModel):
    """Pydantic base class with dict-style accessors.

    Adds `get` plus ``__getitem__`` / ``__setitem__`` so subclasses can be
    treated either as Pydantic models or as plain dict-like objects.
    Item access delegates to ``getattr`` / ``setattr``, so any attribute
    that exists on the instance (declared field or dynamic) is reachable.
    Unknown keys raise ``KeyError`` rather than silently creating new
    attributes.
    """

    def get(self, attr: str, default: Any = None) -> Any:
        """Return the value of *attr*, or *default* if it is absent.

        Args:
            attr: Attribute name to read.
            default: Value returned when *attr* is absent. Defaults to
                ``None``.

        Returns:
            The attribute value, or *default* if no such attribute exists.
        """
        return getattr(self, attr, default)

    def __getitem__(self, key: str) -> Any:
        """Dict-style read; raises ``KeyError`` if the attribute is missing."""
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key) from None

    def __setitem__(self, key: str, value: Any) -> None:
        """Dict-style write; raises ``KeyError`` if the attribute is forbidden."""
        try:
            setattr(self, key, value)
        except AttributeError:
            raise KeyError(f"{key!r} is not a valid attribute") from None
