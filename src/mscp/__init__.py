# outer __init__.py
"""mSCP — macOS Security Compliance Project.

Top-level package for the mSCP toolchain. Re-exports the domain models
(`Baseline`, `Macsecurityrule`, `Payload`, `LoguruFormatter`,
`RuleLibrary`), the command-line entry point `parse_cli`, the generator
entry points (`baseline`, `guidance`, `mapping`, `translation`), and the
file / config helpers used throughout the codebase.

The package's `loguru` logger is disabled by default; callers that want
mSCP log output should enable it (typically via `set_logger`).
"""

from loguru import logger
from .classes.baseline import Baseline

from .classes.loguruformatter import LoguruFormatter
from .classes.macsecurityrule import Macsecurityrule
from .classes.payload import Payload
from .classes.rule_library import RuleLibrary
from .cli import parse_cli
from .common_utils.config import config
from .common_utils.file_handling import (
    append_text,
    create_csv,
    create_plist,
    create_yaml,
    make_dir,
    open_csv,
    open_file,
    open_plist,
    open_yaml,
    remove_dir,
    remove_dir_contents,
    remove_file,
)
from .common_utils.logging_config import set_logger
from .common_utils.run_command import run_command
from .common_utils.validate_rules import validate_yaml_file
from .generate import baseline, guidance, mapping, translation

logger.disable("mscp")

__version__ = "2.0.0"

__all__ = [
    "Baseline",
    "Macsecurityrule",
    "LoguruFormatter",
    "Payload",
    "RuleLibrary",
    "config",
    "append_text",
    "create_csv",
    "create_plist",
    "create_yaml",
    "make_dir",
    "open_csv",
    "open_file",
    "open_plist",
    "open_yaml",
    "remove_dir",
    "remove_dir_contents",
    "remove_file",
    "run_command",
    "baseline",
    "guidance",
    "mapping",
    "parse_cli",
    "validate_yaml_file",
    "set_logger",
    "translation",
]
