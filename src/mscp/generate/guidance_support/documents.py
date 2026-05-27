# mscp/generate/documents.py
"""Guidance document rendering (AsciiDoc, PDF, HTML, Markdown) for mSCP.

Provides `generate_documents`, which renders a baseline through the main
Jinja template and optionally invokes AsciiDoctor to produce PDF and HTML
output.  `render_template` performs the actual Jinja render.  Helper Jinja
filters are also defined here: `group_ulify`, `group_ulify_md`,
`render_references`, `render_rules`, `render_rules_md`,
`replace_include_with_file_content`, `asciidoc_to_markdown`, and
`get_nested`.
"""

# Standard python modules
import gettext
import re
import sys
import time
from collections.abc import Mapping
from itertools import groupby
from pathlib import Path
from typing import Any, Sequence, Dict, List

# Additional python modules
from jinja2 import Environment, FileSystemLoader, Template
from yaspin.core import Yaspin
from yaspin.spinners import Spinners

# Local python modules
from ...classes import Baseline, Macsecurityrule
from ...common_utils import (
    config,
    logger,
    mscp_data,
    open_file,
    run_command,
    NIX_OS,
)


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
    """Convert a list of strings to a grouped ``<br />``-separated Markdown bullet list.

    Like `group_ulify` but uses HTML ``<br />`` between groups for inline
    Markdown rendering in tables.

    Args:
        elements (list[str]): Strings to group and format.

    Returns:
        str: ``"- N/A"`` if ``"N/A"`` is in *elements*, otherwise a
            ``<br />``-joined grouped bullet string.
    """
    if "N/A" in elements:
        return "- N/A"

    elements.sort()
    grouped = [list(i) for _, i in groupby(elements, lambda a: a.split("(")[0])]

    return "<br />".join("- " + ", ".join(group) for group in grouped).strip()


def extract_from_title(title: str) -> str:
    """Extract the text inside the first parenthesised group in *title*.

    Args:
        title (str): String that may contain a ``(…)`` group.

    Returns:
        str: The content inside the first ``(…)``, or ``""`` if not found.
    """
    return (
        match.group()
        if (match := re.search(r"(?<=\()(.*?)(?=\s*\))", title, re.IGNORECASE))
        else ""
    )


def render_references(reference_set: Sequence[Dict[str, Any]]) -> str:
    """Convert a sequence of dicts into AsciiDoc table rows (no header, no ``|===``).

    Args:
        reference_set (Sequence[Dict[str, Any]]): Dicts to render; list values
            are joined with ``"\\n- "``.

    Returns:
        str: Newline-separated AsciiDoc cell rows, or ``""`` if *reference_set* is empty.

    Raises:
        TypeError: If any element of *reference_set* is not a dict.
    """

    def _escape_cell(text: Any) -> str:
        s = str(text)
        return s.replace("|", r"\|")

    rows: List[List[str]] = []

    def _walk(path: List[str], value: Any) -> None:
        if isinstance(value, (list, tuple)):
            # Join list elements; str() for non-scalar reference_set
            joined = "\n- ".join(map(str, value))
            rows.append(path + [_escape_cell(joined)])
        else:
            rows.append(path + [_escape_cell(value)])

    # Validate and traverse each input dict
    for d in reference_set:
        if not isinstance(d, dict):
            raise TypeError("All elements of 'reference_set' must be dictionaries.")
        for k in d.keys():
            _walk([str(k)], d[k])

    if not rows:
        return ""  # nothing to emit

    # Determine deepest path and pad each row to keep a rectangular table
    max_cols = max(len(r) for r in rows)
    padded = [r + [""] * (max_cols - len(r)) for r in rows]

    # Assemble rows (each line starts with '| ')
    return "\n".join("!" + "\n!\n- ".join(r) for r in padded)


def render_rules(rule_set: list[str]) -> str:
    """Render a list of rule strings as newline-separated ``"- <rule>"`` lines.

    Args:
        rule_set (list[str]): Rule strings to render.

    Returns:
        str: Newline-joined bullet lines.
    """
    return "\n".join(f"- {rule}" for rule in rule_set)


def render_rules_md(rule_set: list[str]) -> str:
    """Render a list of rule strings as ``<br>``-joined ``"- <rule>"`` lines for Markdown.

    Args:
        rule_set (list[str]): Rule strings to render.

    Returns:
        str: ``<br>``-joined bullet lines.
    """
    return "<br>".join(f"- {rule}" for rule in rule_set)


def replace_include_with_file_content(text: str) -> str:
    """Replace AsciiDoc ``include::`` directives with the content of the referenced file.

    Files are resolved relative to the configured ``includes_dir``.  Missing
    files are logged and replaced with an HTML comment placeholder.

    Args:
        text (str): AsciiDoc source that may contain ``include::<path>[]`` directives.

    Returns:
        str: Source with all ``include::`` directives replaced by file contents.
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
    """Convert a subset of AsciiDoc syntax to GitHub-flavoured Markdown.

    Handles headers, NOTE/IMPORTANT admonitions, source code blocks,
    tables (``|===``), unordered/ordered lists, block titles, and
    ``link:url[text]`` macros.  Unsupported constructs are passed through
    with links replaced and trailing whitespace stripped.

    Args:
        value (str): AsciiDoc source text.

    Returns:
        str: Markdown-formatted text.
    """
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
    """Safely traverse a nested mapping / list using a sequence of keys or indices.

    Args:
        obj (Mapping | list): Root object to traverse.
        keys (list[str | int]): Ordered path of dict keys or list indices.
        default: Value returned when any key/index is missing or the wrong type.

    Returns:
        Any: The value at the nested path, or *default* if unreachable.
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
    html_css: str,
    logo_path: Path,
    os_name: str,
    version_info: dict[str, Any],
    show_all_tags: bool,
    custom: bool,
    template_dir: str,
    themes_dir: str,
    logo_dir: str,
    output_format: str = "adoc",
    language: str = "en",
) -> None:
    """Render a Jinja template against *baseline* data and write to *output_file*.

    Configures a Jinja ``Environment`` with all mSCP filters, installs
    gettext translations for *language*, renders the template, and writes
    the result as text.

    Args:
        output_file (Path): Destination for the rendered output.
        template_name (str): Filename of the template within *template_dir*.
        baseline (Baseline): Baseline data model.
        b64logo (bytes): Base64-encoded logo image bytes.
        pdf_theme (str): AsciiDoctor-PDF theme filename.
        html_css (str): CSS filename for HTML output.
        logo_path (Path): Absolute path to the logo file.
        os_name (str): Operating system name string.
        version_info (dict[str, Any]): OS/compliance version metadata.
        show_all_tags (bool): Whether to render all tags in the document.
        custom (bool): Whether the baseline uses a custom configuration.
        template_dir (str): Path to the Jinja templates directory.
        themes_dir (str): Path to the themes/styles directory.
        logo_dir (str): Path to the images directory.
        output_format (str): ``"adoc"`` (default) or ``"markdown"``.
        language (str): BCP-47 language code for gettext lookup. Defaults to ``"en"``.
    """
    translations = gettext.translation(
        domain="messages",
        localedir=config["locales_dir"],
        languages=[language],
        fallback=True,
    )

    env: Environment = Environment(
        loader=FileSystemLoader(template_dir),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
        extensions=["jinja2.ext.i18n"],
        keep_trailing_newline=True,
    )

    styles_dir: Path = Path(themes_dir).absolute()
    images_dir: Path = Path(logo_dir).absolute()
    acronyms_file: Path = Path(config["includes_dir"], "acronyms.yaml").absolute()

    env.filters["group_ulify"] = group_ulify
    env.filters["include_replace"] = replace_include_with_file_content
    env.filters["render_rules"] = render_rules
    env.filters["render_references"] = render_references
    env.filters["get_nested"] = get_nested
    env.filters["mobileconfig_payloads_to_xml"] = (
        Macsecurityrule.mobileconfig_info_to_xml
    )
    env.install_gettext_translations(translations)

    if output_format == "markdown":
        env.filters["group_ulify"] = group_ulify_md
        env.filters["render_rules"] = render_rules_md
        env.filters["asciidoc_to_markdown"] = asciidoc_to_markdown

    template: Template = env.get_template(template_name)

    baseline_dict: dict[str, Any] = baseline.model_dump()
    acronyms_data: dict[str, Any] = open_file(acronyms_file, language)

    html_title, html_subtitle = map(str.strip, baseline.title.split(":", 1))
    document_subtitle2: str = ":document-subtitle2:"

    if "Tailored from" in baseline.title:
        html_subtitle: str = html_subtitle.split("(")[0]
        html_subtitle2: str = extract_from_title(baseline.title)
        document_subtitle2: str = f"{document_subtitle2} {html_subtitle2}"
        baseline_dict["tailored"] = True
    else:
        benchmark = baseline.title.split()[-1]
        benchmarks = mscp_data.get("benchmarks", "")
        benchmark_description = next(
            (d["description"] for d in benchmarks if d.get("keyword") == benchmark),
            benchmark,
        )
        baseline_dict["tailored"] = False
        baseline_dict["benchmark_description"] = benchmark_description

    if any(author.is_additional for author in baseline.authors):
        baseline_dict["additional_authors"] = True

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
        html_css=html_css,
        show_all_tags=show_all_tags,
        os_name=os_name.strip().lower(),
        os_version=str(version_info.get("os_version", None)),
        version=version_info.get("compliance_version", None),
        release_date=version_info.get("date", None),
        custom=custom,
        format=output_format,
        acronyms=acronyms_data.get("acronyms", []),
        terminology=acronyms_data.get("terminology", []),
        NIX_OS=NIX_OS,
    )

    output_file.write_text(rendered_output)


def generate_documents(
    spinner: Yaspin,
    output_file: Path,
    baseline: Baseline,
    b64logo: bytes,
    pdf_theme: str,
    html_css: str,
    logo_path: Path,
    os_name: str,
    version_info: dict[str, Any],
    show_all_tags: bool = False,
    custom: bool = False,
    output_format: str = "adoc",
    language: str = "en",
) -> None:
    """Render guidance documents and, for AsciiDoc output, invoke AsciiDoctor.

    Selects standard or custom template/theme directories, calls
    `render_template`, then (when *output_format* is ``"adoc"``) runs
    ``bundle exec asciidoctor`` and ``bundle exec asciidoctor-pdf`` to
    produce HTML and PDF output.

    Args:
        spinner (Yaspin): Spinner for progress feedback.
        output_file (Path): Destination ``.adoc`` or ``.md`` file.
        baseline (Baseline): Baseline data model.
        b64logo (bytes): Base64-encoded logo image bytes.
        pdf_theme (str): AsciiDoctor-PDF theme filename.
        html_css (str): CSS filename for HTML output.
        logo_path (Path): Absolute path to the logo file.
        os_name (str): Operating system name string.
        version_info (dict[str, Any]): OS/compliance version metadata.
        show_all_tags (bool): Whether to render all tags. Defaults to ``False``.
        custom (bool): Whether to use the custom template directory. Defaults to ``False``.
        output_format (str): ``"adoc"`` (default) or ``"markdown"``.
        language (str): BCP-47 language code. Defaults to ``"en"``.
    """
    template_dir: str = config["documents_templates_dir"]
    themes_dir: str = config["themes_dir"]
    logo_dir: str = config["images_dir"]

    if custom:
        template_dir = config["custom"]["documents_templates_dir"]
        themes_dir = config["custom"]["themes_dir"]
        logo_dir = config["custom"]["images_dir"]

    render_template(
        output_file,
        "main.jinja",
        baseline,
        b64logo,
        pdf_theme,
        html_css,
        logo_path,
        os_name,
        version_info,
        show_all_tags,
        custom,
        template_dir,
        themes_dir,
        logo_dir,
        output_format,
        language,
    )

    if output_format == "adoc":
        spinner.spinner = Spinners.dots
        spinner.text = "Checking for asciidoctor components"
        time.sleep(1)
        asciidoctor_path, asciidoctor_err = run_command("bundle show asciidoctor")
        asciidoctor_pdf_path, asciidoctor_pdf_err = run_command(
            "bundle show asciidoctor-pdf"
        )

        if asciidoctor_err or asciidoctor_pdf_err:
            spinner.text = "Installing missing asciidoctor components"
            time.sleep(1)
            output, error = run_command(
                "bundle install --gemfile Gemfile --path mscp_gems --binstubs"
            )
            if error:
                logger.error(f"Bundle install failed: {error}")
                sys.exit()
        spinner.text = "Generating HTML file from adoc"
        time.sleep(1)
        output, error = run_command(f"bundle exec asciidoctor {output_file}")
        if error:
            logger.error(f"Error converting to ADOC: {error}")
            sys.exit()
        spinner.text = "Generating PDF file from adoc"
        output, error = run_command(f"bundle exec asciidoctor-pdf {output_file}")
        if error:
            logger.error(f"Error converting to ADOC: {error}")
            sys.exit()
