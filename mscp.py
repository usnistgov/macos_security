#!/usr/bin/env python3
# filename: mscp.py

import sys
import argparse
import logging
import tempfile
import subprocess
import os

from typing import Generic
from pathlib import Path
from dataclasses import dataclass
from base64 import b64encode

# Initialize logger
logger = logging.getLogger(__name__)

# Classes
@dataclass
class MacSecurityRule:
    title = str

# Functions
def parse_args() -> argparse.Namespace:
    """
    Configure the arguments used in the script
    """

    # Parent parser for all types
    parser = argparse.ArgumentParser(
        description="CLI tool for managing baseline and compliance documents."
    )

    parser.add_argument(
        "baseline",
        required=True,
        default=None,
        help="Baseline YAML file used to create the guide.",
        type=Path
    )

    parser.add_argument(
        "--os_name",
        required=True,
        choices=["macos","ios"],
        default="macos",
        help="Which operating system being checked.",
        type=str
    )

    parser.add_argument(
        "--os_version",
        required=True,
        type=int,
        help="Operating system version (eg: 14, 15)."
    )

    parser.add_argument(
        "--generate_type",
        required=True,
        choices=["baseline","guidance","mapping","scap","checklist","local_report"],
        default="guidance",
        help="What is being generated."
    )

    # Sub Parsers for individual commands
    subparsers = parser.add_subparsers(
        title="Subcommands",
        description="Valid Subcommands",
        dest="subcommand"
    )

    # 'baseline' subcommand
    baseline_parser = subparsers.add_parser("baseline", help="Given a keyword tag, generate a generic baseline.yaml file containing rules with the tag.")
    baseline_parser.add_argument(
        "-c",
        "--controls",
        default=None,
        help="Output the 800-53 controls covered by the rules.",
        action="store_true"
    )
    baseline_parser.add_argument(
        "-k",
        "--keyword",
        default=None,
        help="Keyword tag to collect rules containing the tag.",
        action="store"
    )
    baseline_parser.add_argument(
        "-l",
        "--list_tags",
        default=None,
        help="List the available keyword tags to search for.",
        action="store_true"
    )
    baseline_parser.add_argument(
        "-t",
        "--tailor",
        default=None,
        help="Customize the baseline to your organizations values.",
        action="store_true"
    )

    # 'guidance' subcommand
    guidance_parser = subparsers.add_parser("guidance", help="Given a baseline, create guidance documents and files.")
    guidance_parser.add_argument(
        "-c",
        "--clean",
        default=None,
        help=argparse.SUPPRESS,
        action="store_true"
    )
    guidance_parser.add_argument(
        "-d",
        "--debug",
        default=None,
        help=argparse.SUPPRESS,
        action="store_true"
    )
    guidance_parser.add_argument(
        "-D",
        "--ddm",
        default=None,
        help="Generate declarative management artifacts for the rules.",
        action="store_true"
    )
    guidance_parser.add_argument(
        "-l",
        "--logo",
        default=None,
        help="Full path to logo file to be included in the guide.",
        action="store"
    )
    guidance_parser.add_argument(
        "-p",
        "--profiles",
        default=None,
        help="Generate configuration profiles for the rules.",
        action="store_true"
    )
    guidance_parser.add_argument(
        "-r",
        "--reference",
        default=None,
        help="Use the reference ID instead of rule ID for identification."
    )
    guidance_parser.add_argument(
        "-s",
        "--script",
        default=None,
        help="Generate the compliance script for the rules.",
        action="store_true"
    )
    # add gary argument to include tags for XCCDF generation, with a nod to Gary the SCAP guru
    guidance_parser.add_argument(
        "-g",
        "--gary",
        default=None,
        help=argparse.SUPPRESS,
        action="store_true"
    )
    guidance_parser.add_argument(
        "-x",
        "--xlsx",
        default=None,
        help="Generate the excel (xlsx) document for the rules.",
        action="store_true"
    )
    guidance_parser.add_argument(
        "-H",
        "--hash",
        default=None,
        help="sign the configuration profiles with subject key ID (hash value without spaces)"
    )
    guidance_parser.add_argument(
        "-a",
        "--audit_name",
        default=None,
        help="name of audit plist and log - defaults to baseline name"
    )

    return parser.parse_args()


def verify_signing_hash(hash: str) -> bool:
    """
    Attempts to validate the existance of the certificate provided by the hash

    Input: hash
    """

    with tempfile.NamedTemporaryFile(mode="w", delete=True) as in_file:
        unsigned_tmp_file_path = in_file.name
        in_file.write("temporary file for signing")
        in_file.flush()

        cmd = ["security", "cms", "-SZ", hash, "-i", unsigned_tmp_file_path]

        with open(os.devnull, "w") as FNULL:
            result = subprocess.run(cmd, stdout=FNULL, stderr=FNULL)

    return result.returncode == 0


def main() -> None:
    logo: Path = Path("templates/images/mscp_banner.png")
    signing: bool = False

    args = parse_args()

    output_basename: Path = args.baseline.name
    baseline_name: Path = args.baseline.stem
    audit_name: str = str(baseline_name)
    build_path: Path = Path("build", baseline_name)

    if args.audit_name:
        audit_name: str = args.audit_name

    if args.logo:
        logo: Path = args.logo

    if args.hash:
        signing: bool = True
        if not verify_signing_hash(args.hash):
            sys.exit("Cannot use the provided hash to sign.  Please make sure you provide the subject key ID hash from an installed certificate")

    b64logo: bytes = b64encode(logo.read_bytes())

    if not build_path.exists():
        build_path.mkdir()
    else:
        for root, dirs, files in build_path.walk(top_down=False):
            for name in files:
                (root / name).unlink()
            for name in dirs:
                (root / name).rmdir()


    print("The Sky is Blue")


if __name__ == '__main__':
    sys.exit(main())
