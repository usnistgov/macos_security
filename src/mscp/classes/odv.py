"""Organization Defined Value (ODV) models for macOS security rules.

Defines `OdvHint` and `OdvValidation`, which describe the hint metadata
attached to a rule's ``odv`` block.  These models are used for validation
only — the ``odv`` field on `Macsecurityrule` remains a plain dict to
preserve dict-style access patterns used throughout the codebase.
"""

from pydantic import ConfigDict

from ._base import BaseModelWithAccessors


class OdvValidation(BaseModelWithAccessors):
    """Constraints used to validate a user-supplied ODV value.

    All fields are optional; only the constraints relevant to the rule's
    ``datatype`` need to be present.

    Attributes:
        min: Minimum acceptable numeric value.
        max: Maximum acceptable numeric value.
        regex: Regular expression the value must match.
        enumValues: Discrete set of acceptable string values.
    """

    model_config = ConfigDict(extra="forbid")

    min: float | None = None
    max: float | None = None
    regex: str | None = None
    enumValues: list[str] | None = None


class OdvHint(BaseModelWithAccessors):
    """Metadata that describes an ODV and guides user input.

    Attributes:
        datatype: The expected data type for the ODV value (e.g.
            ``"number"``, ``"string"``, ``"enum"``, ``"regex"``).
        description: Human-readable description of the value and its
            purpose, shown during interactive tailoring.
        validation: Optional constraints used to validate the supplied
            value before it is accepted.
    """

    model_config = ConfigDict(extra="forbid")

    datatype: str
    description: str
    validation: OdvValidation | None = None
