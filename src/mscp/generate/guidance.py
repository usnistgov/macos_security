# mscp/generate/guidance.py
"""Main guidance document orchestration for the macOS Security Compliance Project.

Provides `generate_guidance`, the top-level entry point that coordinates
profile generation, DDM declarations, compliance scripts, Excel output,
Markdown documents, JSON manifests, and AsciiDoc/PDF/HTML guidance documents
for a given baseline.  `verify_signing_hash` validates a certificate hash
before profile signing.
"""

# Standard python modules
import argparse
import sys
import tempfile
import time
from base64 import b64encode
from pathlib import Path
from typing import Any

# Additional python modules
from ..common_utils import conditional_inject_spinner
from yaspin.core import Yaspin
from yaspin.spinners import Spinners

# Local python modules
from ..classes import Baseline
from ..classes.legacy_baseline import LegacyBaseline
from ..common_utils import (
    config,
    get_version_data,
    logger,
    make_dir,
    mscp_data,
    remove_dir_contents,
    run_command,
)
from ..generate.guidance_support import (
    generate_ddm,
    generate_documents,
    generate_markdown_tree,
    generate_excel,
    generate_profiles,
    generate_script,
    generate_restore_script,
    generate_manifest,
)


def verify_signing_hash(cert_hash: str) -> bool:
    """Verify that *cert_hash* identifies an installed signing certificate.

    Writes a temporary file, attempts to sign it with ``security cms -SZ``,
    then removes the file.

    Args:
        cert_hash (str): Subject Key ID hash of the certificate to verify.

    Returns:
        bool: ``True`` if signing succeeds, ``False`` otherwise.
    """

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as in_file:
        unsigned_tmp_file_path = Path(in_file.name)
        in_file.write("temporary file for signing\n")
        in_file.flush()

    cmd: str = f"security cms -SZ {cert_hash} -i {unsigned_tmp_file_path}"

    stdout, error = run_command(cmd, text=False, check=False)

    unsigned_tmp_file_path.unlink()

    if error:
        logger.error(f"Verification failed for hash {cert_hash}. Error: {error}")
        return False

    logger.info(f"Certificate hash {cert_hash} verified successfully.")
    return True


def _auto_migrate_legacy(args: argparse.Namespace) -> Path:
    """Migrate a legacy baseline to the current format and return the new path.

    Called transparently by `generate_guidance` when the provided baseline
    file is detected as pre-2.0 format.  The migrated YAML is written to the
    custom baselines directory using the standard naming convention
    ``{parent_values}_{os_name}_{os_version}.yaml``.

    Platform is inferred from the baseline title.  If inference fails, the
    ``--os_name`` / ``--os_version`` flags on ``args`` are used as a fallback.

    Args:
        args (argparse.Namespace): Parsed CLI arguments. ``args.baseline``
            must be the path to the legacy YAML file; ``args.os_name`` and
            ``args.os_version`` serve as a platform fallback.

    Returns:
        Path: Path to the migrated baseline YAML.
    """
    source: Path = args.baseline
    baseline_dir: Path = Path(config["custom"].get("baseline_dir", ""))

    if not baseline_dir.exists():
        make_dir(baseline_dir)

    lb = LegacyBaseline.from_yaml(source)

    platform_override: dict | None = None
    try:
        inferred = lb.parse_platform()
        os_name_lower: str = inferred["os"].lower()
        os_version: float = inferred["version"]
    except ValueError:
        logger.warning(
            "Cannot infer platform from legacy baseline title {!r}. "
            "Using --os_name={} --os_version={} from command line.",
            lb.title,
            args.os_name,
            args.os_version,
        )
        platform_override = {"os": args.os_name, "version": args.os_version}
        os_name_lower = args.os_name
        os_version = args.os_version

    output_path: Path = (
        baseline_dir / f"{lb.parent_values}_{os_name_lower}_{os_version}.yaml"
    )

    missing = lb.migrate(output_path, platform=platform_override)

    logger.info(
        "Auto-migrated legacy baseline {} → {}", source.name, output_path.name
    )
    if missing:
        logger.warning(
            "{} rule(s) from the legacy baseline were not found in the "
            "current library and were skipped: {}",
            len(missing),
            ", ".join(missing),
        )

    return output_path


@conditional_inject_spinner()
def generate_guidance(sp: Yaspin, args: argparse.Namespace) -> None:
    """Orchestrate all guidance artifacts for a given baseline.

    Reads the baseline YAML and, based on ``args`` flags, delegates to the
    appropriate sub-generators: configuration profiles, DDM declarations,
    compliance scripts, Excel workbook, Markdown documents, JSON manifest,
    and the primary AsciiDoc/PDF/HTML guidance document.

    Args:
        sp (Yaspin): Spinner instance injected by `conditional_inject_spinner`.
        args (argparse.Namespace): Parsed CLI arguments. Expected attributes:
            ``baseline``, ``os_name``, ``language``, ``dark``, ``hash``,
            ``reference``, ``logo``, ``audit_name``, ``profiles``, ``ddm``,
            ``script``, ``xlsx``, ``gary``, ``markdown``, ``markdown_tree``,
            ``manifest``, ``all``, ``consolidated_profile``,
            ``granular_profiles``.
    """
    # Transparently migrate legacy (pre-2.0) baselines before deriving any
    # paths. Updating args.baseline here means all subsequent path derivations
    # (basename, build_path, adoc_output_file, …) use the migrated file
    # automatically.
    if LegacyBaseline.is_legacy(args.baseline):
        logger.info(
            "Legacy baseline detected: {}. Migrating before generating guidance.",
            args.baseline.name,
        )
        args.baseline = _auto_migrate_legacy(args)

    # Configure localization at the beginning based on the CLI language parameter
    logger.debug(f"Language parameter from CLI: {args.language}")

    sp.spinner = Spinners.dots
    signing: bool = False
    log_reference: str = "default"
    if args.dark:
        pdf_theme: str = "mscp_theme-dark.yml"
        html_css: str = "asciidoctor-dark.css"
    else:
        pdf_theme: str = "mscp_theme.yml"
        html_css: str = "asciidoctor.css"

    _custom_root = Path(config["custom"]["root_dir"])
    custom: bool = _custom_root.exists() and any(_custom_root.iterdir())
    show_all_tags: bool = False

    output_basename: str = args.baseline.name
    baseline_name: str = args.baseline.stem
    audit_name: str = str(baseline_name)
    if not args.language == "en":
        build_path: Path = Path(
            config.get("output_dir", ""), f"{baseline_name}_{args.language}"
        )
    else:
        build_path: Path = Path(config.get("output_dir", ""), baseline_name)
    adoc_output_file: Path = Path(build_path, f"{baseline_name}_{args.language}.adoc")
    md_output_file: Path = Path(build_path, f"{baseline_name}_{args.language}.md")
    spreadsheet_output_file: Path = Path(
        build_path, f"{baseline_name}_{args.language}.xlsx"
    )

    baseline: Baseline = Baseline.from_yaml(args.baseline, args.language)

    current_version_data: dict[str, Any] = get_version_data(
        baseline.platform["os"], baseline.platform["version"], mscp_data
    )

    if args.audit_name:
        audit_name = args.audit_name

    if args.logo:
        logo_path = args.logo
    else:
        _logo_filename = f"mscp_banner_{baseline.platform['os'].lower()}_{'dark' if args.dark else 'light'}.png"
        _custom_logo = Path(config["custom"]["images_dir"], _logo_filename)
        logo_path = (
            _custom_logo if _custom_logo.exists()
            else Path(config["images_dir"], _logo_filename)
        ).absolute()

    if not logo_path.exists():
        logger.warning(f"Logo not found at {logo_path}, using default instead.")
        logo_path = Path(config["images_dir"], "mscp_banner_macos_light.png").absolute()

    if args.hash:
        if sys.platform.startswith("darwin"):
            signing = True
            if not verify_signing_hash(args.hash):
                logger.error(
                    "Cannot use the provided hash to sign.  Please make sure you provide the subject key ID hash from an installed certificate"
                )
                sys.exit()
        else:
            logger.error(
                "Signing of configuration profiles is only supported when run natively on macOS, ignoring..."
            )
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
        sp.text = "Generating configuration profiles"
        time.sleep(1)
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
        sp.text = "Generating declarative components"
        time.sleep(1)
        generate_ddm(build_path, baseline, baseline_name)

    if args.script:
        logger.info("Generating compliance scripts")
        sp.text = "Generating compliance scripts"
        time.sleep(1)
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

    if args.xlsx:
        logger.info("Generating Excel document")
        sp.text = "Generating Excel document"
        time.sleep(1)
        generate_excel(spreadsheet_output_file, baseline)

    if args.gary:
        show_all_tags = True

    if args.markdown:
        logger.info("Generating markdown documents")
        sp.text = "Generating markdown documents"
        time.sleep(1)
        generate_documents(
            sp,
            md_output_file,
            baseline,
            b64logo,
            pdf_theme,
            html_css,
            logo_path,
            baseline.platform["os"],
            current_version_data,
            show_all_tags,
            output_format="markdown",
            language=args.language,
        )

    if args.markdown_tree:
        logger.info("Generating paginated Markdown tree")
        sp.text = "Generating Markdown tree"
        time.sleep(1)
        generate_markdown_tree(
            build_path,
            baseline,
            current_version_data,
            show_all_tags,
            language=args.language,
        )

    if args.manifest:
        logger.info("Generating JSON manifest")
        sp.text = "Generating JSON manifest"
        time.sleep(1)
        generate_manifest(build_path, baseline_name, baseline)

    if args.all:
        logger.info("Generating all support files")
        logger.info("Generating configuration profiles")
        sp.text = "Generating configuration profiles"
        time.sleep(1)
        generate_profiles(
            build_path,
            baseline_name,
            baseline,
            signing,
            args.hash,
            consolidated=args.consolidated_profile,
            granular=args.granular_profiles,
        )

        logger.info("Generating declarative components")
        sp.text = "Generating declarative components"
        time.sleep(1)
        generate_ddm(build_path, baseline, baseline_name)

        logger.info("Generating compliance scripts")
        sp.text = "Generating compliance scripts"
        time.sleep(1)
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
        sp.text = "Generating Excel document"
        time.sleep(1)
        generate_excel(spreadsheet_output_file, baseline)

        logger.info("Generating markdown documents")
        sp.text = "Generating markdown"
        time.sleep(1)
        generate_documents(
            sp,
            md_output_file,
            baseline,
            b64logo,
            pdf_theme,
            html_css,
            logo_path,
            baseline.platform["os"],
            current_version_data,
            show_all_tags,
            output_format="markdown",
            language=args.language,
        )

        logger.info("Generating paginated Markdown tree")
        sp.text = "Generating Markdown tree"
        time.sleep(1)
        generate_markdown_tree(
            build_path,
            baseline,
            current_version_data,
            show_all_tags,
            language=args.language,
        )

        logger.info("Generating JSON manifest")
        sp.text = "Generating JSON manifest"
        time.sleep(1)
        generate_manifest(build_path, baseline_name, baseline)

    logger.info("Generating asciidoctor, PDF, and HTML documents")
    generate_documents(
        sp,
        adoc_output_file,
        baseline,
        b64logo,
        pdf_theme,
        html_css,
        logo_path,
        baseline.platform["os"],
        current_version_data,
        show_all_tags,
        language=args.language,
    )
    try:
        display_path = Path(build_path).relative_to(Path.cwd())
    except ValueError:
        display_path = build_path
    sp.text = f"MSCP DOCUMENT GENERATION COMPLETE! All of the documents can be found in this folder: {display_path}/"
    sp.ok("✔")
