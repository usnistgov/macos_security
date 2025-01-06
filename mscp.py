# ./mscp.py

import logging
import logging.config

from pathlib import Path

from src.mscp.cli import main
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml

# Initialize logger
logging_config = open_yaml(Path(config.get("logging_config", "")))
logging.config.dictConfig(logging_config)
logger = logging.getLogger('staging')

if __name__ == "__main__":
    main()
