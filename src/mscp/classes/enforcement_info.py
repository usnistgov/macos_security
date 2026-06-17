from typing import Optional, Union, Literal
from pydantic import Field, ConfigDict

from ._base import BaseModelWithAccessors


class ResultDef(BaseModelWithAccessors):
    model_config = ConfigDict(extra="ignore")

    string: Optional[str] = None
    integer: Optional[Union[int, Literal["$ODV"]]] = "$ODV"
    boolean: Optional[bool] = None


class ShellCheck(BaseModelWithAccessors):
    model_config = ConfigDict(extra="ignore")

    shell: str = Field(
        "", description="Shell command(s) to evaluate the state of a configuration."
    )
    result: Optional[ResultDef] = None
    additional_info: Optional[str] = ""


class ShellFix(BaseModelWithAccessors):
    model_config = ConfigDict(extra="ignore")

    shell: Optional[str] = Field(
        "",
        description="Shell command(s) to fix the configuration if the check command fails.",
    )
    additional_info: Optional[str] = ""


class DefaultStateShell(BaseModelWithAccessors):
    model_config = ConfigDict(extra="ignore")

    shell: Optional[str] = Field(
        "",
        description="Shell command(s) to restore the system to a default factory state.",
    )
    note: Optional[str] = ""


class EnforcementInfo(BaseModelWithAccessors):
    model_config = ConfigDict(extra="forbid")

    check: Optional[ShellCheck] = None
    fix: Optional[ShellFix] = None
    default_state: Optional[DefaultStateShell] = None
