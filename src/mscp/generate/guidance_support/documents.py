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
    """
    Converts a list of strings into a grouped unordered list (UL) format.

    If the list contains the string "N/A", it returns "- N/A".
    Otherwise, it sorts the list, groups elements by their prefix (before the first parenthesis),
    and returns a string where each group is represented as a bullet point with its elements
    separated by commas.

    Args:
        elements (list[str]): The list of strings to be converted.

    Returns:
        str: A string representing the grouped unordered list.
    """
    if "N/A" in elements:
        return "- N/A"

    elements.sort()
    grouped = [list(i) for _, i in groupby(elements, lambda a: a.split("(")[0])]

    return "\n".join("- " + ", ".join(group) for group in grouped).strip()


def group_ulify_md(elements: list[str]) -> str:
    """
    Converts a list of strings into a grouped unordered list (UL) format.

    If the list contains the string "N/A", it returns "- N/A".
    Otherwise, it sorts the list, groups elements by their prefix (before the first parenthesis),
    and returns a string where each group is represented as a bullet point with its elements
    separated by commas.

    Args:
        elements (list[str]): The list of strings to be converted.

    Returns:
        str: A string representing the grouped unordered list.
    """
    if "N/A" in elements:
        return "- N/A"

    elements.sort()
    grouped = [list(i) for _, i in groupby(elements, lambda a: a.split("(")[0])]

    return "<br>".join("- " + ", ".join(group) for group in grouped).strip()


def extract_from_title(title: str) -> str:
    return (
        match.group()
        if (match := re.search(r"(?<=\()(.*?)(?=\s*\))", title, re.IGNORECASE))
        else ""
    )


def render_rules(rule_set: list[str]) -> str:
    """
    Renders a list of rules as a string with each rule on a new line prefixed by a dash.

    Args:
        rule_set (list): A list of rules to be rendered.

    Returns:
        str: A string representation of the rules.
    """
    return "\n".join(f"- {rule}" for rule in rule_set)


def render_rules_md(rule_set: list[str]) -> str:
    """
    Renders a list of rules as a string with each rule on a new line prefixed by a dash.

    Args:
        rule_set (list): A list of rules to be rendered.

    Returns:
        str: A string representation of the rules.
    """
    return "<br>".join(f"- {rule}" for rule in rule_set)


def convert_source_blocks(text: str) -> str:
    """
    Converts [source,xml] and [source,bash] blocks to Markdown code blocks with appropriate highlighting.

    Args:
        text (str): The input text containing [source,xml] or [source,bash] blocks.

    Returns:
        str: The processed text with code blocks.
    """
    # Regular expression to match [source,xml] or [source,bash] blocks
    pattern = re.compile(r"\[source,(xml|bash)\]\n----\n(.*?)\n----", re.DOTALL)

    # Function to replace matched blocks with Markdown code blocks
    def replace_block(match):
        language = match.group(1)
        content = match.group(2).strip()
        return f"```{language}\n{content}\n```"

    # Replace all [source,xml] and [source,bash] blocks in the text
    return pattern.sub(replace_block, text)


def replace_include_with_file_content(text: str) -> str:
    """
    Searches the text for `include::` directives, extracts the filenames, reads the file content,
    and replaces the `include::` section with the file content.

    Args:
        text (str): The input text containing `include::` directives.
        base_path (Path): The base path to resolve relative file paths.

    Returns:
        str: The processed text with `include::` sections replaced by file content.
    """
    includes_dir: Path = Path(config["includes_dir"]).absolute()
    # Regular expression to match `include::` directives and extract filenames
    pattern = re.compile(r"include::(?:.*/)?([^/]+)\[\]")

    # Function to replace matched blocks with file content
    def replace_block(match):
        filename = match.group(1).strip()
        file_path = includes_dir / filename
        try:
            file_content = file_path.read_text()
            return file_content
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return f"<!-- File not found: {file_path} -->"

    # Replace all `include::` blocks in the text
    return pattern.sub(replace_block, text)


def render_template(
    output_file: Path,
    template_name: str,
    baseline: Baseline,
    b64logo: bytes,
    pdf_theme: str,
    logo_path: Path,
    os_name: str,
    version_info: dict[str, Any],
    show_all_tags: bool,
    custom: bool,
    template_dir: str,
    misc_dir: str,
) -> None:
    """
    Renders the template with the provided parameters and writes the output to a file.

    Args:
        output_file (Path): The path to the output file where the generated document will be saved.
        template_name (str): The name of the template to be rendered.
        baseline (Baseline): The baseline object containing the data to be included in the document.
        b64logo (bytes): The base64 encoded logo to be included in the document.
        pdf_theme (str): The theme to be used for the PDF generation.
        logo_path (Path): The path to the logo file.
        os_name (str): The name of the operating system.
        version_info (dict[str, Any]): A dictionary containing version information.
        show_all_tags (bool): Flag to indicate whether to show all tags.
        custom (bool): Flag to indicate whether to use custom templates and styles.
        template_dir (str): The directory containing the templates.
        misc_dir (str): The directory containing miscellaneous files.

    Returns:
        None
    """

    env: Environment = Environment(
        loader=FileSystemLoader(template_dir),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
        keep_trailing_newline=False,
    )

    styles_dir: Path = Path(misc_dir).absolute()

    env.filters["group_ulify"] = group_ulify
    env.filters["group_ulify_md"] = group_ulify_md
    env.filters["include_replace"] = replace_include_with_file_content
    env.filters["render_rules"] = render_rules
    env.filters["render_rules_md"] = render_rules_md
    env.filters["convert_source_blocks"] = convert_source_blocks
    env.filters["replace_include_with_file_content"] = replace_include_with_file_content

    template: Template = env.get_template(template_name)

    baseline_dict: dict[str, Any] = baseline.model_dump()

    html_title, html_subtitle = map(str.strip, baseline.title.split(":", 1))
    document_subtitle2: str = ":document-subtitle2:"

    if "Talored from" in baseline.title:
        html_subtitle: str = html_subtitle.split("(")[0]
        html_subtitle2: str = extract_from_title(baseline.title)
        document_subtitle2: str = f"{document_subtitle2} {html_subtitle2}"

    rendered_output = template.render(
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
        os_version=str(version_info.get("os_version", None)),
        version=version_info.get("compliance_version", None),
        release_date=version_info.get("date", None),
        custom=custom,
    )

    output_file.write_text(rendered_output)


def generate_asciidoc_documents(
    output_file: Path,
    baseline: Baseline,
    b64logo: bytes,
    pdf_theme: str,
    logo_path: Path,
    os_name: str,
    version_info: dict[str, Any],
    show_all_tags: bool = False,
    custom: bool = False,
) -> None:
    """
    Generates AsciiDoc documentation based on the provided baseline and other parameters.

    Args:
        output_file (Path): The path to the output file where the generated document will be saved.
        baseline (Baseline): The baseline object containing the data to be included in the document.
        b64logo (bytes): The base64 encoded logo to be included in the document.
        pdf_theme (str): The theme to be used for the PDF generation.
        logo_path (Path): The path to the logo file.
        os_name (str): The name of the operating system.
        version_info (dict[str, Any]): A dictionary containing version information.
        show_all_tags (bool, optional): Flag to indicate whether to show all tags. Defaults to False.
        custom (bool, optional): Flag to indicate whether to use custom templates and styles. Defaults to False.

    Returns:
        None
    """
    template_dir = config["defaults"]["adoc_templates_dir"]
    misc_dir = config["defaults"]["misc_dir"]

    if custom:
        template_dir = config["custom"]["adoc_templates_dir"]
        misc_dir = config["custom"]["misc_dir"]

    render_template(
        output_file,
        "main.adoc.jinja",
        baseline,
        b64logo,
        pdf_theme,
        logo_path,
        os_name,
        version_info,
        show_all_tags,
        custom,
        template_dir,
        misc_dir,
    )

    gems_asciidoctor: Path = Path("mscp_gems/bin/asciidoctor")
    gems_asciidoctor_pdf: Path = Path("mscp_gems/bin/asciidoctor-pdf")

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


def generate_markdown_documents(
    output_file: Path,
    baseline: Baseline,
    b64logo: bytes,
    pdf_theme: str,
    logo_path: Path,
    os_name: str,
    version_info: dict[str, Any],
    show_all_tags: bool = False,
    custom: bool = False,
) -> None:
    """
    Generates Markdown documentation based on the provided baseline and other parameters.

    Args:
        output_file (Path): The path to the output file where the generated document will be saved.
        baseline (Baseline): The baseline object containing the data to be included in the document.
        b64logo (bytes): The base64 encoded logo to be included in the document.
        pdf_theme (str): The theme to be used for the PDF generation.
        logo_path (Path): The path to the logo file.
        os_name (str): The name of the operating system.
        version_info (dict[str, Any]): A dictionary containing version information.
        show_all_tags (bool, optional): Flag to indicate whether to show all tags. Defaults to False.
        custom (bool, optional): Flag to indicate whether to use custom templates and styles. Defaults to False.

    Returns:
        None
    """
    template_dir = config["defaults"]["md_templates_dir"]
    misc_dir = config["defaults"]["misc_dir"]

    if custom:
        template_dir = config["custom"]["md_templates_dir"]
        misc_dir = config["custom"]["misc_dir"]

    render_template(
        output_file,
        "main.md.jinja",
        baseline,
        b64logo,
        pdf_theme,
        logo_path,
        os_name,
        version_info,
        show_all_tags,
        custom,
        template_dir,
        misc_dir,
    )
