# outer __init__.py

from loguru import logger

logger.disable("mscp")

__version__ = "2.0.0"

from .classes.baseline import Baseline
from .classes.loguruformatter import LoguruFormatter
from .classes.macsecurityrule import Macsecurityrule
from .classes.payload import Payload
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
from .common_utils.localization import configure_localization_for_yaml
from .common_utils.logging_config import set_logger
from .common_utils.run_command import run_command
from .common_utils.validate_rules import validate_yaml_file
from .generate import baseline, checklist, guidance, local_report, mapping

logger.disable("mscp")

__version__ = "2.0.0"

__all__ = [
    "__version__",
    "Baseline",
    "Macsecurityrule",
    "LoguruFormatter",
    "Payload",
    "config",
    "append_text",
    "create_csv",
    "create_file",
    "create_plist",
    "create_yaml",
    "create_text",
    "create_json",
    "sanitize_input",
    "run_command",
    "get_version_data",
    "mscp_data",
    "get_mscp_data",
    "make_dir",
    "open_csv",
    "open_file",
    "open_plist",
    "open_text",
    "open_yaml",
    "remove_dir",
    "remove_dir_contents",
    "remove_file",
    "run_command",
    "baseline",
    "checklist",
    "guidance",
    "local_report",
    "mapping",
    "parse_cli",
    "validate_yaml_file",
    "set_logger",
]
