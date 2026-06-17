from typing import Optional, Union, Literal
from pydantic import Field, ConfigDict

from ._base import BaseModelWithAccessors

ODV = Literal["$ODV"]


class ResultDef(BaseModelWithAccessors):
    """Expected result definition for a shell-based compliance check.

    Holds the anticipated output value of a check command in exactly one
    of its three typed fields.  Only one field should be populated at a
    time; the others remain ``None``.  Any field may be set to ``"$ODV"``
    as a placeholder when the expected value is organization-defined.

    Attributes:
        string: Expected string output, or ``"$ODV"`` for an ODV placeholder.
        integer: Expected integer output, or ``"$ODV"`` for an ODV placeholder.
        boolean: Expected boolean output, or ``"$ODV"`` for an ODV placeholder.
    """

    model_config = ConfigDict(extra="ignore")

    string: Optional[Union[str, ODV]] = None
    integer: Optional[Union[int, ODV]] = None
    boolean: Optional[Union[bool, ODV]] = None


class ShellCheck(BaseModelWithAccessors):
    """Shell command configuration for evaluating a rule's compliance state.

    Encapsulates the command(s) used to audit whether a macOS configuration
    setting is in the desired state.

    Attributes:
        shell: Shell command(s) to evaluate the state of a configuration.
        result: Expected result indicating a passing/compliant state.
        additional_info: Human-readable notes supplementing the check command.
    """

    model_config = ConfigDict(extra="ignore")

    shell: str = Field(
        "", description="Shell command(s) to evaluate the state of a configuration."
    )
    result: Optional[ResultDef] = None
    additional_info: Optional[str] = ""


class ShellFix(BaseModelWithAccessors):
    """Shell command configuration for remediating a failing compliance check.

    Holds the command(s) used to bring a non-compliant configuration setting
    into the desired state.

    Attributes:
        shell: Shell command(s) to fix the configuration if the check fails.
        additional_info: Human-readable notes supplementing the fix command.
    """

    model_config = ConfigDict(extra="ignore")

    shell: Optional[str] = Field(
        "",
        description="Shell command(s) to fix the configuration if the check command fails.",
    )
    additional_info: Optional[str] = ""


class DefaultStateShell(BaseModelWithAccessors):
    """Shell command configuration for restoring a setting to its factory default.

    Used to document how to undo a rule's enforcement and return the system
    to the out-of-box macOS state.

    Attributes:
        shell: Shell command(s) to restore the system to factory default state.
        note: Human-readable notes supplementing the default-state command.
    """

    model_config = ConfigDict(extra="ignore")

    shell: Optional[str] = Field(
        "",
        description="Shell command(s) to restore the system to a default factory state.",
    )
    note: Optional[str] = ""


class EnforcementInfo(BaseModelWithAccessors):
    """Enforcement details for a macOS security rule.

    Aggregates the check, fix, and default-state shell commands that together
    describe how to audit, remediate, and revert a security configuration.
    Unknown fields are rejected (``extra="forbid"``).

    Attributes:
        check: Shell-based audit command and expected result for the rule.
        fix: Shell-based remediation command applied when the check fails.
        default_state: Shell-based command to restore the system to its
            factory default configuration for this setting.
    """

    model_config = ConfigDict(extra="forbid")

    check: Optional[ShellCheck] = None
    fix: Optional[ShellFix] = None
    default_state: Optional[DefaultStateShell] = None
