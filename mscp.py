#!/usr/bin/env python3
# filename: mscp.py

import sys
import argparse
import logging
import tempfile
import subprocess
import os
import yaml

from typing import Generic, Optional, Any, Dict
from pathlib import Path
from dataclasses import dataclass
from base64 import b64encode

import mscp

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
        default=None,
        help="Baseline YAML file used to create the guide.",
        type=Path
    )

    parser.add_argument(
        "--os_name",
        choices=["macos","ios"],
        default="macos",
        help="Which operating system being checked.",
        type=str
    )

    parser.add_argument(
        "--os_version",
        default=15,
        type=int,
        help="Operating system version (eg: 14, 15)."
    )

    # Sub Parsers for individual commands
    subparsers = parser.add_subparsers(
        title="Subcommands",
        required=True,
        description="Valid Subcommands",
        dest="subcommand"
    )

    # 'baseline' subcommand
    baseline_parser = subparsers.add_parser("baseline", help="Given a keyword tag, generate a generic baseline.yaml file containing rules with the tag.")
    baseline_parser.add_argument(
        "-c",
        "--controls",
        help="Output the 800-53 controls covered by the rules.",
        action="store_true"
    )
    baseline_parser.add_argument(
        "-k",
        "--keyword",
        help="Keyword tag to collect rules containing the tag.",
        action="store"
    )
    baseline_parser.add_argument(
        "-l",
        "--list_tags",
        help="List the available keyword tags to search for.",
        action="store_true"
    )
    baseline_parser.add_argument(
        "-t",
        "--tailor",
        help="Customize the baseline to your organizations values.",
        action="store_true"
    )

    # 'guidance' subcommand
    guidance_parser = subparsers.add_parser("guidance", help="Given a baseline, create guidance documents and files.")
    guidance_parser.add_argument(
        "-c",
        "--clean",
        help=argparse.SUPPRESS,
        action="store_true"
    )
    guidance_parser.add_argument(
        "-d",
        "--debug",
        help=argparse.SUPPRESS,
        action="store_true"
    )
    guidance_parser.add_argument(
        "-D",
        "--ddm",
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
        help="Generate configuration profiles for the rules.",
        action="store_true"
    )
    guidance_parser.add_argument(
        "-r",
        "--reference",
        default=None,
        help="Use the reference ID instead of rule ID for identification.",
        action="store"
    )
    guidance_parser.add_argument(
        "-s",
        "--script",
        help="Generate the compliance script for the rules.",
        action="store_true"
    )
    # add gary argument to include tags for XCCDF generation, with a nod to Gary the SCAP guru
    guidance_parser.add_argument(
        "-g",
        "--gary",
        help=argparse.SUPPRESS,
        action="store_true"
    )
    guidance_parser.add_argument(
        "-x",
        "--xlsx",
        help="Generate the excel (xlsx) document for the rules.",
        action="store_true"
    )
    guidance_parser.add_argument(
        "-H",
        "--hash",
        default=None,
        help="sign the configuration profiles with subject key ID (hash value without spaces)",
        action="store"
    )
    guidance_parser.add_argument(
        "-a",
        "--audit_name",
        default=None,
        help="name of audit plist and log - defaults to baseline name",
        action="store"
    )

    return parser.parse_args()


def verify_signing_hash(hash: str) -> bool:
    """
    Attempts to validate the existance of the certificate provided by the hash

    Args:
        hash (str): The certificate hash.

    Returns:
        bool: If the certificate is valid returns True.
    """

    with tempfile.NamedTemporaryFile(mode="w", delete=True) as in_file:
        unsigned_tmp_file_path = in_file.name
        in_file.write("temporary file for signing")
        in_file.flush()

        cmd = ["security", "cms", "-SZ", hash, "-i", unsigned_tmp_file_path]

        with open(os.devnull, "w") as FNULL:
            result = subprocess.run(cmd, stdout=FNULL, stderr=FNULL)

    return result.returncode == 0


def open_file_with_error_checking(file_path: Path) -> Optional[str]:
    """
    Attempts to open a file and read it's contents with error checking and logging

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        Optional[str]: The content of the file if successful, None if otherwise.
    """

    try:
        logging.info(f"Attempting to open file: {file_path}")

        with file_path.open("r") as file:
            content = file.read()
            logging.info(f"Successfully read the file {file_path}")
            return content

    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
    except PermissionError:
        logging.error(f"Permission denied when trying to open the file: {file_path}")
    except Exception as e:
        logging.error(f"An error occurred while opening the file: {file_path}. Error: {e}")

    return None


def open_yaml_file_with_error_checking(file_path: Path) -> Optional[Any]:
    """
    Attempts to open a file and read it's contents with error checking and logging

    Args:
        file_path (Path): The path to the file to be opened.

    Returns:
        Optional[Any]: The content of the file if successful, None if otherwise.
    """

    try:
        logging.info(f"Attempting to open file: {file_path}")

        with file_path.open("r") as file:
            content = yaml.safe_load(file)
            logging.info(f"Successfully read the file {file_path}")
            return content

    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
    except PermissionError:
        logging.error(f"Permission denied when trying to open the file: {file_path}")
    except yaml.YAMLError as error:
        logging.error(f"An error occurred while opening the file: {file_path}. Error: {error}")
    except Exception as e:
        logging.error(f"An error occurred while opening the file: {file_path}. Error: {e}")

    return None


def main() -> None:
    logging.basicConfig(
        filename="mscp.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    logo: Path = Path("templates/images/mscp_banner.png")
    signing: bool = False
    log_reference: str = "default"
    use_custom_reference: bool = False
    rules: MacSecurityRule = MacSecurityRule()

    args = parse_args()

    output_basename: Path = args.baseline.name
    baseline_name: Path = args.baseline.stem
    audit_name: str = str(baseline_name)
    build_path: Path = Path("build", baseline_name)
    adoc_output_file: Path = Path(build_path, f"{baseline_name}.adoc")
    baseline_yaml = open_yaml_file_with_error_checking(args.baseline)

    if args.audit_name:
        audit_name = args.audit_name

    if args.logo:
        logo = args.logo

    if args.hash:
        signing = True
        if not verify_signing_hash(args.hash):
            sys.exit("Cannot use the provided hash to sign.  Please make sure you provide the subject key ID hash from an installed certificate")

    if args.reference:
        use_custom_reference = True
        log_reference = args.reference

    b64logo: bytes = b64encode(logo.read_bytes())

    if not build_path.exists():
        build_path.mkdir()
    else:
        for root,dirs,files in build_path.walk(top_down=False):
            for name in files:
                (root / name).unlink()
            for name in dirs:
                (root / name).rmdir()

    test = MacSecurityRule_new()
    print(test)


if __name__ == "__main__":
    main()
