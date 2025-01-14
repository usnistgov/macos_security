# mscp/generate/guidance.py

# Standard python modules
import logging
import tempfile
import argparse
import sys

from pathlib import Path
from icecream import ic
from base64 import b64encode

# Additional python modules

# Local python modules
from src.mscp.classes.baseline import Baseline
from src.mscp.common_utils.run_command import run_command
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml, make_dir
from src.mscp.generate.documents import generate_documents
from src.mscp.generate.script import generate_script, generate_audit_plist
from src.mscp.generate.ddm import generate_ddm
from src.mscp.generate.excel import generate_excel
from src.mscp.generate.profiles import generate_profiles


# Initialize local logger
logger = logging.getLogger(__name__)


# Functions
def verify_signing_hash(cert_hash: str) -> bool:
    """
    Attempts to validate the existence of the certificate provided by the hash

    Args:
        cert_hash (str): The certificate hash.

    Returns:
        bool: If the certificate is valid, returns True.
    """

    with tempfile.NamedTemporaryFile(mode="w", delete=True) as in_file:
        unsigned_tmp_file_path = in_file.name
        in_file.write("temporary file for signing")
        in_file.flush()

        cmd: str = f"security cms -SZ {cert_hash} -i {unsigned_tmp_file_path}"

        stdout, error = run_command(cmd)

    if error:
        logger.error(f"Verification failed for hash {cert_hash}. Error: {error}")
        return False

    logger.info(f"Certificate hash {cert_hash} verified successfully.")
    return True


def guidance(args: argparse.Namespace) -> None:
    logo_path: str = f"{config["defaults"]["images_dir"]}/mscp_banner.png"
    signing: bool = False
    log_reference: str = "default"
    use_custom_reference: bool = False
    pdf_theme: str = "mscp-theme.yml"
    custom: bool = not any(Path(config["custom"]["root_dir"]).iterdir())
    show_all_tags: bool = False

    os_version: float = float(args.os_version)
    version_file: Path = Path(config["includes_dir"], "version.yaml")
    version_data: dict = open_yaml(version_file)
    current_version_data = next((entry for entry in version_data.get("platforms", {}).get(args.os_name, []) if entry.get("os") == os_version), {})

    output_basename: str = args.baseline.name
    baseline_name: str = args.baseline.stem
    audit_name: str = str(baseline_name)
    build_path: Path = Path(config.get("output_dir", ""), baseline_name)
    adoc_output_file: Path = Path(build_path, f"{baseline_name}.adoc")
    spreadsheet_output_file: Path = Path(build_path, f"{baseline_name}.xlsx")

    baseline: Baseline = Baseline.from_yaml(args.baseline, args.os_name, args.os_version, custom)

    if args.audit_name:
        audit_name = args.audit_name

    if args.logo:
        logo = args.logo

    if args.hash:
        signing = True
        if not verify_signing_hash(args.hash):
            logger.error("Cannot use the provided hash to sign.  Please make sure you provide the subject key ID hash from an installed certificate")
            sys.exit()

    if args.reference:
        use_custom_reference = True
        log_reference = args.reference

    b64logo: bytes = b64encode(Path(logo_path).read_bytes())

    if not build_path.exists():
        make_dir(build_path)
    else:
        for root,dirs,files in build_path.walk(top_down=False):
            for name in files:
                (root / name).unlink()
            for name in dirs:
                (root / name).rmdir()

    logger.info(f"Profile YAML: {output_basename}")
    logger.info(f"Output path: {adoc_output_file.name}")

    if custom:
        themes = list(Path(config["custom"]["misc_dir"]).glob('*theme*.yml'))

        if len(themes) > 1:
            logger.warning("Found multiple custom themes in directory, only one can exist, using default")
        elif len(themes) == 1:
            logger.info(f"Found custom PDF theme: {themes[0]}")
            pdf_theme = str(themes[0])

    if args.profiles:
        logger.info("Generating configuration profiles...")
        generate_profiles(build_path, baseline_name, baseline)

    if args.ddm:
        logger.info("Generating declarative components...")
        generate_ddm(build_path, baseline, baseline_name)

    if args.script:
        logger.info("Generating compliance script...")
        generate_script(build_path, baseline_name, audit_name, baseline, log_reference)
        generate_audit_plist(build_path, baseline_name, baseline)

    if args.xlsx:
        logger.info("Generating Excel document")
        generate_excel(spreadsheet_output_file, baseline)

    if args.gary:
        show_all_tags = True

    generate_documents(adoc_output_file, baseline, b64logo, pdf_theme, logo_path, args.os_name, current_version_data, show_all_tags, custom)
