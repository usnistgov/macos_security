# mscp/generate/documents.py

# Standard python modules
import re
import sys
from itertools import groupby
from pathlib import Path
from typing import Any

# Additional python modules
from jinja2 import Environment, FileSystemLoader, Template
from loguru import logger

# Local python modules
from src.mscp.classes import Baseline
from src.mscp.common_utils import config, run_command


def group_ulify(elements: list[str]) -> str:
    if elements == "N/A":
        return "- N/A"

    elements.sort()
    grouped = [list(i) for _, i in groupby(elements, lambda a: a.split("(")[0])]

    return "\n".join(" * " + ", ".join(group) for group in grouped).strip()


def extract_from_title(title: str) -> str:
    return (
        match.group()
        if (match := re.search(r"(?<=\()(.*?)(?=\s*\))", title, re.IGNORECASE))
        else ""
    )


def generate_documents(
    output_file: Path,
    baseline: Baseline,
    b64logo: bytes,
    pdf_theme: str,
    logo_path: str,
    os_name: str,
    version_info: dict[str, Any],
    show_all_tags: bool = False,
    custom: bool = False,
) -> None:
    """
    Generates documentation based on the provided baseline and other parameters.

    Args:
        output_file (Path): The path to the output file where the generated document will be saved.
        baseline (Baseline): The baseline object containing the data to be included in the document.
        b64logo (bytes): The base64 encoded logo to be included in the document.
        pdf_theme (str): The theme to be used for the PDF generation.
        logo_path (str): The path to the logo file.
        os_name (str): The name of the operating system.
        version_info (dict[str, Any]): A dictionary containing version information.
        show_all_tags (bool, optional): Flag to indicate whether to show all tags. Defaults to False.
        custom (bool, optional): Flag to indicate whether to use custom templates and styles. Defaults to False.

    Returns:
        None
    """
    env: Environment = Environment(
        loader=FileSystemLoader(config["defaults"]["adoc_templates_dir"])
    )

    styles_dir: str = config["defaults"]["misc_dir"]
    gems_asciidoctor: Path = Path("mscp_gems/bin/asciidoctor")
    gems_asciidoctor_pdf: Path = Path("mscp_gems/bin/asciidoctor-pdf")

    html_title: str = baseline.title.split(":")[0]
    html_subtitle: str = baseline.title.split(":")[1].strip()
    document_subtitle2: str = ":document-subtitle2:"
    # extract_from_title = lambda title: (
    #     match.group()
    #     if (match := re.search(r"(?<=\()(.*?)(?=\s*\))", title, re.IGNORECASE))
    #     else None
    # )

    if custom:
        env = Environment(
            loader=FileSystemLoader(config["custom"]["adoc_templates_dir"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        styles_dir = config["custom"]["misc_dir"]

    env.filters["group_ulify"] = group_ulify

    main_template: Template = env.get_template("main.adoc.jinja")

    baseline_dict: dict[str, Any] = baseline.model_dump()

    if "Talored from" in baseline.title:
        html_subtitle: str = html_subtitle.split("(")[0]
        html_subtitle2: str = extract_from_title(baseline.title)
        document_subtitle2: str = f"{document_subtitle2} {html_subtitle2}"

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
        custom=custom,
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
