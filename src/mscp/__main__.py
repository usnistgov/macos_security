# src/mscp/__main__.py
"""Entry point for ``python -m mscp``.

Enables the package logger, ensures the configured custom directories
exist, then delegates to `parse_cli`.
"""

import sys

from .cli import parse_cli
from .common_utils import logger, ensure_custom_dirs


def main() -> None:
    """Run the mSCP CLI as a module entry point.

    Enables the `mscp` loguru logger, calls `ensure_custom_dirs` to create
    the per-user custom directories on first run, then dispatches to
    `parse_cli`.
    """
    logger.enable("mscp")
    ensure_custom_dirs()
    parse_cli()


if __name__ == "__main__":
    sys.exit(main())
