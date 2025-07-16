#! .venv/bin/python3
# filename: mscp.py

# Standard python modules
import sys

# Local python modules
from src.mscp.cli import parse_cli


def main() -> None:
    parse_cli()


if __name__ == "__main__":
    sys.exit(main())
