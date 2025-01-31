# mscp/common_utils/run_command.py

import logging
import subprocess
import shlex

from typing import Tuple, Optional

# Initialize local logger
logger = logging.getLogger(__name__)

def run_command(command: str) -> Tuple[Optional[str], Optional[str]]:
    args = shlex.split(command)
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=True)
        logger.info(f"Command executed successfully: {command}")
        logger.debug(f"Command output: {result.stdout}")

        return result.stdout.strip(), None

    except subprocess.CalledProcessError as e:
        if e.returncode != 0:
            logger.error(f"Command failed with return code {e.returncode}: {e.stderr}")

        return None, f"Command failed: {e.stderr}"

    except OSError as e:
        logger.error(f"OS error when running command: {command}")
        logger.debug(f"Error message: {str(e)}")

        return None, f"OS error occurred: {str(e)}"
