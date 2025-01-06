# mscp/generate/documents.py

# Standard python modules
import logging
import re
import sys

from pathlib import Path
from base64 import decode
from dataclasses import asdict
from typing import Dict, Any
from itertools import groupby
from icecream import ic

# Additional python modules
import pandas as pd

from jinja2 import Environment, FileSystemLoader

# Local python modules
from src.mscp.classes.baseline import Baseline
from src.mscp.common_utils.config import config
from src.mscp.common_utils.run_command import run_command
from src.mscp.common_utils.mobile_config_fix import format_mobileconfig_fix

# Initialize local logger
logger = logging.getLogger(__name__)

def group_ulify(elements):
    if elements == "N/A":
        return "- N/A"

    elements.sort()
    grouped = [list(i) for _, i in groupby(elements, lambda a: a.split("(")[0])]
    result = ""
    for group in grouped:
        result += "\n * " + ", ".join(group)
    return result.strip()

def generate_documents(
        output_file: Path,
        baseline: Baseline,
        b64logo: bytes,
        pdf_theme: str,
        logo_path: str,
        os_name: str,
        version_info: Dict[str, Any],
        show_all_tags: bool = False,
        custom: bool = False) -> None:

    env: Environment = Environment(loader=FileSystemLoader(config["defaults"]["adoc_templates_dir"]), trim_blocks=True, lstrip_blocks=True)
    env.filters['group_ulify'] = group_ulify
    env.filters['mobileconfig_fix'] = format_mobileconfig_fix

    styles_dir: str = config["defaults"]["misc_dir"]
    gems_asciidoctor: Path = Path("mscp_gems/bin/asciidoctor")
    gems_asciidoctor_pdf: Path = Path("mscp_gems/bin/asciidoctor-pdf")

    html_title: str = baseline.title.split(":")[0]
    html_subtitle: str = baseline.title.split(":")[1].strip()
    document_subtitle2: str = ":document-subtitle2:"
    extract_from_title = lambda title: (
        match.group() if (match := re.search(r'(?<=\()(.*?)(?=\s*\))', title, re.IGNORECASE)) else None
    )

    if custom:
        env = Environment(loader=FileSystemLoader(config["custom"]["adoc_templates_dir"]), trim_blocks=True, lstrip_blocks=True)
        env.filters['group_ulify'] = group_ulify
        env.filters['mobileconfig_fix'] = format_mobileconfig_fix
        styles_dir = config["custom"]["misc_dir"]

    main_template = env.get_template('main.adoc.jinja')

    baseline_dict: Dict[str, Any] = asdict(baseline)

    if "Talored from" in baseline.title:
        html_subtitle = html_subtitle.split("(")[0]
        html_subtitle2: str = str(extract_from_title(baseline.title))
        document_subtitle2 = f"{document_subtitle2} {html_subtitle2}"

    rendered_output = main_template.render(
        baseline=baseline_dict,
        html_title=html_title,
        html_subtitle=html_subtitle,
        document_subtitle2=document_subtitle2,
        styles_dir=styles_dir,
        logo=logo_path,
        pdflogo=b64logo.decode("ascii"),
        pdf_theme=pdf_theme,
        show_all_tags=show_all_tags,
        os_name=os_name.strip().lower(),
        os_version=str(version_info.get("os", None)),
        version=version_info.get("version", None),
        release_date=version_info.get("date", None),
        custom=custom
        )

    output_file.write_text(rendered_output)

    output, error = run_command("which asciidoctor")
    logger.debug(f"which asciidoctor output: {output}, error: {error}")

    if not output:
        if not gems_asciidoctor.exists():
            logger.error("Asciidoctor not installed!!")
            sys.exit()
        else:
            output = str(gems_asciidoctor)

    output, error = run_command(f"{output} {output_file}")
    if error:
        logger.error(f"Error converting to ADOC: {error}")
        sys.exit()

    if not show_all_tags:
        output, error = run_command("which asciidoctor-pdf")
        logger.debug(f"which asciidoctor-pdf output: {output}, error: {error}")

        if not output:
            if not gems_asciidoctor_pdf.exists():
                logger.error("Asciidoctor not installed!!")
                sys.exit()
            else:
                output = str(gems_asciidoctor_pdf)

        output, error = run_command(f"{output} {output_file}")
        if error:
            logger.error(f"Error converting to ADOC: {error}")
            sys.exit()
