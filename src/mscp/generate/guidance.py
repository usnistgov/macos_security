# mscp/generate/guidance.py

# Standard python modules
import argparse
import sys
import tempfile
from base64 import b64encode
from pathlib import Path
from typing import Any

# Local python modules
from ..classes import Baseline
from ..common_utils import (
    config,
    get_version_data,
    logger,
    make_dir,
    mscp_data,
    remove_dir_contents,
    run_command,
)
from ..common_utils.localization import configure_localization_for_yaml
from ..generate.guidance_support import (
    generate_ddm,
    generate_documents,
    generate_excel,
    generate_profiles,
    generate_script,
    generate_restore_script,
)


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


def generate_guidance(args: argparse.Namespace) -> None:
    # Configure localization at the beginning based on the CLI language parameter
    logger.debug(f"Language parameter from CLI: {args.language}")
    configure_localization_for_yaml(language=args.language)

    logo_path: Path = Path(
        config["defaults"]["images_dir"], "mscp_banner.png"
    ).absolute()
    signing: bool = False
    log_reference: str = "default"
    pdf_theme: str = "mscp-theme.yml"
    custom: bool = not any(Path(config["custom"]["root_dir"]).iterdir())
    show_all_tags: bool = False

    output_basename: str = args.baseline.name
    baseline_name: str = args.baseline.stem
    audit_name: str = str(baseline_name)
    build_path: Path = Path(config.get("output_dir", ""), baseline_name)
    adoc_output_file: Path = Path(build_path, f"{baseline_name}_{args.language}.adoc")
    md_output_file: Path = Path(build_path, f"{baseline_name}_{args.language}.md")
    spreadsheet_output_file: Path = Path(
        build_path, f"{baseline_name}_{args.language}.xlsx"
    )

    baseline: Baseline = Baseline.from_yaml(args.baseline, args.language, custom)

    current_version_data: dict[str, Any] = get_version_data(
        baseline.platform["os"], baseline.platform["version"], mscp_data
    )

    if args.audit_name:
        audit_name = args.audit_name

    if args.logo:
        logo_path = args.logo

    if args.hash:
        signing = True
        if not verify_signing_hash(args.hash):
            logger.error(
                "Cannot use the provided hash to sign.  Please make sure you provide the subject key ID hash from an installed certificate"
            )
            sys.exit()

    if args.reference:
        log_reference = args.reference

    b64logo: bytes = b64encode(Path(logo_path).read_bytes())

    if not build_path.exists():
        make_dir(build_path)
    else:
        remove_dir_contents(build_path)

    logger.info(f"Profile YAML: {output_basename}")
    logger.info(f"Output path: {adoc_output_file.name}")

    if custom:
        themes = list(Path(config["custom"]["misc_dir"]).glob("*theme*.yml"))

        if len(themes) > 1:
            logger.warning(
                "Found multiple custom themes in directory, only one can exist, using default"
            )
        elif len(themes) == 1:
            logger.info(f"Found custom PDF theme: {themes[0]}")
            pdf_theme = str(themes[0])

    if args.profiles:
        logger.info("Generating configuration profiles")
        if not signing:
            generate_profiles(
                build_path,
                baseline_name,
                baseline,
                consolidated=args.consolidated_profile,
                granular=args.granular_profiles,
            )
        else:
            generate_profiles(
                build_path,
                baseline_name,
                baseline,
                signing,
                args.hash,
                consolidated=args.consolidated_profile,
                granular=args.granular_profiles,
            )

    if args.ddm:
        logger.info("Generating declarative components")
        generate_ddm(build_path, baseline, baseline_name)

    if args.script and args.os_name == "macos":
        logger.info("Generating compliance script")
        generate_script(build_path, baseline_name, audit_name, baseline, log_reference)
        generate_restore_script(
            build_path, baseline_name, audit_name, baseline, log_reference
        )

    if args.xlsx:
        logger.info("Generating Excel document")
        generate_excel(spreadsheet_output_file, baseline)

    if args.gary:
        show_all_tags = True

    if args.markdown:
        logger.info("Generating markdown documents")
        generate_documents(
            md_output_file,
            baseline,
            b64logo,
            pdf_theme,
            logo_path,
            baseline.platform["os"],
            current_version_data,
            show_all_tags,
            custom,
            output_format="markdown",
            language=args.language,
        )

    if args.all:
        logger.info("Generating all support files")
        logger.info("Generating configuration profiles")
        generate_profiles(
            build_path,
            baseline_name,
            baseline,
            consolidated=args.consolidated_profile,
            granular=args.granular_profiles,
        )

        logger.info("Generating declarative components")
        generate_ddm(build_path, baseline, baseline_name)

        if args.os_name == "macos":
            logger.info("Generating compliance script")
            generate_script(
                build_path,
                baseline_name,
                audit_name,
                baseline,
                log_reference,
                current_version_data,
            )
            generate_restore_script(
                build_path,
                baseline_name,
                audit_name,
                baseline,
                log_reference,
                current_version_data,
            )

        logger.info("Generating Excel document")
        generate_excel(spreadsheet_output_file, baseline)

        logger.info("Generating markdown documents")
        generate_documents(
            md_output_file,
            baseline,
            b64logo,
            pdf_theme,
            logo_path,
            baseline.platform["os"],
            current_version_data,
            show_all_tags,
            custom,
            output_format="markdown",
            language=args.language,
        )

    generate_documents(
        adoc_output_file,
        baseline,
        b64logo,
        pdf_theme,
        logo_path,
        baseline.platform["os"],
        current_version_data,
        show_all_tags,
        custom,
        language=args.language,
    )

    print(
        f"MSCP DOCUMENT GENERATION COMPLETE! All of the documents can be found in this folder: /{build_path}/"
    )
