# mscp/common_utils/run_command.py

# Standard python modules
import shlex
import subprocess

# Local python modules
from .logger_instance import logger


def run_command(command: str) -> tuple[str | None, str | None]:
    """
    Executes a shell command and returns its output or an error message.
        result = subprocess.run(args, capture_output=True, text=True, check=True)
    Parameters:
        command (str): The command to be executed.

    Returns:
        Tuple[Optional[str], Optional[str]]: A tuple containing the command output if successful, or an error message if the command fails.
    """
    args = shlex.split(command)
    try:
        logger.info("Executing command: {}", command)

        result = subprocess.run(args, capture_output=True, text=True, check=True)

        logger.success("Command executed successfully: {}", command)
        logger.debug("Command output: {}", result.stdout.strip())

        return result.stdout.strip(), None

    except subprocess.CalledProcessError as e:
        logger.error(
            "Command '{}' failed with return code {}: {}",
            command,
            e.returncode,
            e.stderr,
        )

        return None, f"Command failed: {e.stderr}"

    except OSError as e:
        logger.error("OS error when running command: {}", command)
        logger.error("OS error when running command: {}, Error: {}", command, str(e))

        return None, f"OS error occurred: {str(e)}"
