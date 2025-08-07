# mscp/generate/documents.py

# Standard python modules
import re
import sys
from collections.abc import Mapping
from itertools import groupby
from pathlib import Path
from typing import Any

# Additional python modules
# import markdown2
from jinja2 import Environment, FileSystemLoader, Template

# Local python modules
from ...classes import Baseline, Macsecurityrule
from ...common_utils import config, logger, open_file, run_command


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

    return "<br />".join("- " + ", ".join(group) for group in grouped).strip()


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


def asciidoc_to_markdown(value: str) -> str:
    lines = value.splitlines()
    result = []
    i = 0

    link_pattern = re.compile(r"link:(\S+)\[(.*?)\]")

    def link_replacer(match):
        url, text = match.group(1), match.group(2)
        return f"[{text if text else url}]({url})"

    while i < len(lines):
        line = lines[i].rstrip()

        # Header: == -> ##, === -> ###, etc.
        if re.match(r"^(=+)\s+.+", line):
            level, content = re.match(r"^(=+)\s+(.+)", line).groups()
            result.append(f"{'#' * len(level)} {content}")

        # NOTE block
        elif line.startswith("NOTE:"):
            result.append(
                f"> **NOTE:** {link_pattern.sub(link_replacer, line[5:].strip())}"
            )

        # [IMPORTANT] block
        elif (
            line.strip() == "[IMPORTANT]"
            and i + 1 < len(lines)
            and lines[i + 1].strip() == "===="
        ):
            i += 2
            important_lines = []
            while i < len(lines) and lines[i].strip() != "====":
                important_lines.append(lines[i].strip())
                i += 1
            result.append("> **IMPORTANT:** " + " ".join(important_lines))

        # [source] blocks
        elif line.startswith("[source"):
            language = ""
            # Extract just the language before the first comma
            lang_match = re.match(r"\[source\s*,?\s*([a-zA-Z0-9_+-]+)?", line)
            if lang_match:
                language = lang_match.group(1) or ""

            if i + 1 < len(lines) and lines[i + 1].strip() in ("----", "...."):
                fence = lines[i + 1].strip()
                i += 2
                code_lines = []
                while i < len(lines) and lines[i].strip() != fence:
                    code_lines.append(lines[i])
                    i += 1

                result.append(f"```{language}".strip())
                result.extend(code_lines)
                result.append("```")

        # Code block without [source]
        elif line.strip() in ("----", "...."):
            fence = line.strip()
            i += 1
            code_lines = []
            while i < len(lines) and lines[i].strip() != fence:
                code_lines.append(lines[i])
                i += 1
            result.append("```")
            result.extend(code_lines)
            result.append("```")

        # Table with |===
        elif line.strip() == "|===":
            i += 1
            table_rows = []
            while i < len(lines) and lines[i].strip() != "|===":
                table_line = lines[i].strip()
                if table_line.startswith("|"):
                    cells = [cell.strip() for cell in table_line.lstrip("|").split("|")]
                    table_rows.append(cells)
                i += 1

            if table_rows:
                header = "| " + " | ".join(table_rows[0]) + " |"
                separator = "| " + " | ".join(["---"] * len(table_rows[0])) + " |"
                result.append(header)
                result.append(separator)
                for row in table_rows[1:]:
                    result.append("| " + " | ".join(row) + " |")

        # Skip AsciiDoc block attributes like [cols=...], [width=...], [options=...], etc.
        elif re.match(
            r"^\[(cols|width|options|grid|frame|stripes|halign|valign|%|role|.*)=.*\]$",
            line,
        ):
            pass

        # Handle AsciiDoc block titles like `.Some Title`
        elif re.match(r"^\.(?!\d+\s)(.+)$", line):
            block_title = re.match(r"^\.(.+)$", line).group(1).strip()
            result.append(f"**{block_title}**")

        # Unordered List (* -> -)
        elif line.strip().startswith("* "):
            result.append("- " + line.strip()[2:])

        # Ordered List (. or 1. 2. etc.)
        elif re.match(r"^\.\s+.+", line):
            result.append("1. " + line.strip()[2:])
        elif re.match(r"^\d+\.\s+.+", line):
            result.append(line.strip())

        else:
            result.append(link_pattern.sub(link_replacer, line.strip()))

        i += 1

    return "\n".join(result)


def get_nested(
    obj: Mapping[str, Any] | list, keys: list[str | int], default: Any = None
) -> Any:
    """
    Safely access nested dictionary keys (and optionally list indices).

    Args:
        obj: The base dictionary or mapping.
        keys: A list of keys or indices to access, in order.
        default: The value to return if any key/index is missing or invalid.

    Returns:
        The value at the nested path or the default.
    """
    current = obj
    for key in keys:
        if isinstance(current, Mapping) and isinstance(key, str):
            current = current.get(key, default)
        elif isinstance(current, list) and isinstance(key, int):
            if 0 <= key < len(current):
                current = current[key]
            else:
                return default
        else:
            return default
    return current


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
    logo_dir: str,
    output_format: str = "adoc",
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
    )

    styles_dir: Path = Path(misc_dir).absolute()
    images_dir: Path = Path(logo_dir).absolute()
    acronyms_file: Path = Path(config["includes_dir"], "acronyms.yaml").absolute()

    env.filters["group_ulify"] = group_ulify
    env.filters["include_replace"] = replace_include_with_file_content
    env.filters["render_rules"] = render_rules
    env.filters["get_nested"] = get_nested
    env.filters["mobileconfig_payloads_to_xml"] = (
        Macsecurityrule.mobileconfig_info_to_xml
    )

    if output_format == "markdown":
        env.filters["group_ulify"] = group_ulify_md
        env.filters["render_rules"] = render_rules_md
        env.filters["asciidoc_to_markdown"] = asciidoc_to_markdown

    template: Template = env.get_template(template_name)

    baseline_dict: dict[str, Any] = baseline.model_dump()
    acronyms_data: dict[str, Any] = open_file(acronyms_file)

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
        images_dir=images_dir,
        logo=logo_path.name,
        pdflogo=b64logo.decode("ascii"),
        pdf_theme=pdf_theme,
        show_all_tags=show_all_tags,
        os_name=os_name.strip().lower(),
        os_version=str(version_info.get("os_version", None)),
        version=version_info.get("compliance_version", None),
        release_date=version_info.get("date", None),
        custom=custom,
        format=output_format,
        acronyms=acronyms_data.get("acronyms", []),
        terminology=acronyms_data.get("terminology", []),
    )

    output_file.write_text(rendered_output)


def generate_documents(
    output_file: Path,
    baseline: Baseline,
    b64logo: bytes,
    pdf_theme: str,
    logo_path: Path,
    os_name: str,
    version_info: dict[str, Any],
    show_all_tags: bool = False,
    custom: bool = False,
    output_format: str = "adoc",
) -> None:
    template_dir: str = config["defaults"]["documents_templates_dir"]
    misc_dir: str = config["defaults"]["misc_dir"]
    logo_dir: str = config["defaults"]["images_dir"]

    if custom:
        template_dir = config["custom"]["documents_templates_dir"]
        misc_dir = config["custom"]["misc_dir"]
        logo_dir = config["custom"]["images_dir"]

    render_template(
        output_file,
        "main.jinja",
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
        logo_dir,
        output_format,
    )

    if output_format == "adoc":
        gems_asciidoctor: Path = Path("mscp_gems/bin/asciidoctor")
        gems_asciidoctor_pdf: Path = Path("mscp_gems/bin/asciidoctor-pdf")

    output, error = run_command("which asciidoctor")
    logger.debug(f"which asciidoctor output: {output}, error: {error}")

    if not output:
        if not gems_asciidoctor.exists():
            logger.error("Asciidoctor not installed!!")
            sys.exit()

    output, error = run_command(f"asciidoctor {output_file}")
    if error:
        logger.error(f"Error converting to ADOC: {error}")
        sys.exit()

    if not show_all_tags:
        output, error = run_command("which asciidoctor-pdf")
        logger.debug(f"which asciidoctor-pdf output: {output}, error: {error}")

        if not output:
            if not gems_asciidoctor.exists():
                logger.error("Asciidoctor not installed!!")
                sys.exit()

        output, error = run_command(f"asciidoctor-pdf {output_file}")
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

            output, error = run_command(f"asciidoctor-pdf {output_file}")
            if error:
                logger.error(f"Error converting to ADOC: {error}")
                sys.exit()
