# mscp/common_utils/run_command.py

# Standard python modules
import shlex
import subprocess

from .error_handling import COMMAND_ERRORS, log_expected_errors
from .logger_instance import logger

# Local python modules


def _command_fallback(e: Exception) -> tuple[None, str]:
    """
    Build a structured error return value for run_command().
    Suppresses logging for 'which asciidoctor*' checks.
    """
    cmd = getattr(e, "cmd", None)
    stderr = getattr(e, "stderr", None)

    if isinstance(cmd, (list, tuple)):
        cmd_str = " ".join(cmd)
    else:
        cmd_str = str(cmd) if cmd else ""

    if cmd_str.startswith("which asciidoctor"):
        logger.debug("Expected asciidoctor check failed: %s", stderr or str(e))
        return None, f"Command failed (expected check): {stderr or str(e)}"

    logger.error("Command '%s' failed: %s", cmd_str or "<unknown>", stderr or str(e))
    return None, f"Command failed: {stderr or str(e)}"


@log_expected_errors(
    COMMAND_ERRORS,
    suppress=True,
    fallback=_command_fallback,
)
def run_command(command: str) -> tuple[str | None, str | None]:
    """
    Executes a shell command and returns its output or an error message.

    Returns:
        (stdout, None) on success
        (None, "Command failed: <details>") on failure
    """
    args = shlex.split(command)
    logger.info("Executing command: {}", command)

    result = subprocess.run(args, capture_output=True, text=True, check=True)

    logger.success("Command executed successfully: {}", command)
    logger.debug("Command output: {}", result.stdout.strip())

    return result.stdout.strip(), None
