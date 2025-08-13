# mscp/common_utils/config.py

# Standard python modules
from pathlib import Path

# Local python modules
from .file_handling import open_file
from .logger_instance import logger

# Additional python modules


def find_project_root() -> Path:
    """
    Find the project root directory by looking for distinctive files/directories
    that indicate this is the mscp project root.
    
    Searches from the current module's location upwards until it finds markers
    like 'config/config.yaml', 'src/mscp', etc.
    
    Returns:
        Path: Path to the project root directory
        
    Raises:
        FileNotFoundError: If project root cannot be found
    """
    # Start from this module's directory and walk up
    current_path = Path(__file__).resolve().parent
    
    # Look for distinctive project markers
    project_markers = [
        "config/config.yaml",  # Main config file
        "src/mscp",           # Source directory structure
        "pyproject.toml",     # Python project file
        "requirements.txt",   # Dependencies file
    ]
    
    # Walk up the directory tree
    for _ in range(10):  # Limit to prevent infinite loops
        # Check if any of the markers exist
        markers_found = sum(1 for marker in project_markers if (current_path / marker).exists())
        
        # If we find at least 2 markers, this is likely the project root
        if markers_found >= 2:
            return current_path
            
        # Move up one directory
        parent = current_path.parent
        if parent == current_path:  # Reached filesystem root
            break
        current_path = parent
    
    # Fallback: try current working directory if markers are found there
    cwd = Path.cwd()
    markers_found = sum(1 for marker in project_markers if (cwd / marker).exists())
    if markers_found >= 2:
        return cwd
    
    # If all else fails, raise an error with helpful information
    raise FileNotFoundError(
        f"Could not find mscp project root. Searched from {Path(__file__).resolve()} "
        f"up to filesystem root and current working directory {cwd}. "
        f"Please ensure you're running from within the mscp project directory."
    )


# Find project root and construct config path
PROJECT_ROOT: Path = find_project_root()
CONFIG_PATH: Path = PROJECT_ROOT / "config" / "config.yaml"

try:
    logger.info("Attempting to open config file: {}", CONFIG_PATH)
    config = open_file(CONFIG_PATH)
    logger.success("Config file loaded successfully")
except Exception as e:
    logger.error("An error occurred while loading the config file: {}", e)
    raise
