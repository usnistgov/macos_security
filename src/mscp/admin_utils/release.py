# mscp/admin_utils/release.py
"""Admin utility to prepare for release.

Updates information in ``mscp_data.yaml`` and attempts to update
the CHANGELOG.adoc in preparation for release.
"""

# Standard python modules
import argparse
from pathlib import Path

# Local python modules
from ..common_utils import (
    config,
    logger,
    mscp_data,
    create_file,
    conditional_inject_spinner,
)

from yaspin.core import Yaspin
from yaspin.spinners import Spinners


@conditional_inject_spinner()
def update_mscp_release(sp: Yaspin, args: argparse.Namespace) -> None:
    """ """
    sp.spinner = Spinners.dots

    mscp_data_file: Path = Path(config["mscp_data"])
    mscp_data_file_updated = False

    sp.text = f"Updating mscp_data.yaml with information for next release"
    current_mscp_major, current_mscp_minor = mscp_data["mscp"].get("version").split(".")

    if args.major:
        new_major = int(current_mscp_major) + 1
        new_version = f"{new_major}.0"
        mscp_data["mscp"]["version"] = new_version
        mscp_data["mscp"]["release_date"] = args.release_date
        mscp_data_file_updated = True
    if args.minor:
        new_minor = int(current_mscp_minor) + 1
        new_version = f"{current_mscp_major}.{new_minor}"
        mscp_data["mscp"]["version"] = new_version
        mscp_data["mscp"]["release_date"] = args.release_date
        mscp_data_file_updated = True

    if mscp_data_file_updated:
        create_file(mscp_data_file, mscp_data)
        sp.text = f"DONE: mscp_data.yaml has been updated with release information"
        sp.ok("✔")
    else:
        sp.text = f"No updates needed for release."
        sp.ok("✔")

    return
