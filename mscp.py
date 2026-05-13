#! /usr/bin/env python
# Direct-run entry point for uninstalled use.
# If the mscp package is installed, run `mscp` instead.
if __name__ != "__main__":
    raise ImportError(
        "the referenced mscp.py is a direct-run script, not a module. "
        "this script is shadowing the installed 'mscp' package. "
        "to resove this, remove or rename mscp.py."
    )

import sys

sys.path.insert(0, "src")

from mscp.cli import parse_cli
from mscp.common_utils import logger, ensure_custom_dirs


def main() -> None:
    logger.enable("mscp")
    ensure_custom_dirs()
    parse_cli()


sys.exit(main())
