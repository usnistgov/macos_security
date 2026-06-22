# src/mscp/__main__.py
"""Entry point for ``python -m mscp``.

Enables the package logger, ensures the configured custom directories
exist, then delegates to `parse_cli`.
"""

import sys

from .cli import parse_cli
from .common_utils import logger


def main() -> None:
    """Run the mSCP CLI as a module entry point.

    Enables the `mscp` loguru logger then delegates to `parse_cli`, which
    calls `set_custom_dir` (if ``--custom_dir`` was supplied) and
    `ensure_custom_dirs` before dispatching to the appropriate sub-command.
    """
    logger.enable("mscp")
    parse_cli()


if __name__ == "__main__":
    sys.exit(main())
