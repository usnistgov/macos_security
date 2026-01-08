# mscp/generate/documents.py

# Standard python modules
from __future__ import annotations

import gettext
import re
import sys
from collections.abc import Mapping
from itertools import groupby
from pathlib import Path
from typing import Any, Dict, List, Sequence

# Additional python modules
# import markdown2
from jinja2 import Environment, FileSystemLoader, Template

# Local python modules
from ...classes import Baseline, Macsecurityrule
from ...common_utils import (
    config,
    create_file,
    logger,
    mscp_data,
    open_file,
    run_command,
)

_LINK_RE = re.compile(r"link:(\S+)\[(.*?)\]")
_INLINE_ADMON_RE = re.compile(r"^(NOTE|TIP|IMPORTANT|WARNING|CAUTION):\s*(.*)$")
_BLOCK_ADMON_TAG_RE = re.compile(r"^\[(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$")
_SOURCE_RE = re.compile(r"^\[source\s*,?\s*([a-zA-Z0-9_+-]+)?\s*\]\s*$")


def _get_attr(mapping_or_obj, name, default=None):
    """
    Safely get an attribute or dict key from rule.
    Works if `rule` is a dict or an object.
    """
    if isinstance(mapping_or_obj, Mapping):
        return mapping_or_obj.get(name, default)
    return getattr(mapping_or_obj, name, default)


def _nonempty(value) -> bool:
    """True if value is not None and not just whitespace."""
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    return bool(value)


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


def extract_from_title(title: str) -> str:
    return (
        match.group()
        if (match := re.search(r"(?<=\()(.*?)(?=\s*\))", title, re.IGNORECASE))
        else ""
    )


def render_references(reference_set: Sequence[Dict[str, Any]]) -> str:
    """
    Convert a list of dictionaries into AsciiDoc table rows (no header, no |===).

    Parameters
    ----------
    reference_set : Sequence[Dict[str, Any]]
        A list (or tuple) of dictionaries.

    Returns
    -------
    str
        Newline-separated AsciiDoc table rows, e.g., '| key | value'.
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
    """
    Renders a list of rules as a string with each rule on a new line prefixed by a dash.

    Args:
        rule_set (list): A list of rules to be rendered.

    Returns:
        str: A string representation of the rules.
    """
    if not rule_set:
        return ""

    return "\n".join(f"- {rule}" for rule in rule_set)


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


def asciidoc_to_markdown(value: str | None) -> str:
    if not value:
        return ""

    lines = value.splitlines()
    out: list[str] = []
    i = 0

    def replace_links(text: str) -> str:
        def _repl(m: re.Match) -> str:
            url, label = m.group(1), m.group(2).strip()
            return f"[{label if label else url}]({url})"

        return _LINK_RE.sub(_repl, text)

    def emit(line: str) -> None:
        line = line.rstrip()
        # avoid inserting blank line between consecutive generated quote blocks
        if line == "" and out and out[-1].lstrip().startswith(">"):
            return
        out.append(line)

    def quote(line: str) -> str:
        # note: for blank quoted lines, use ">" (no trailing space)
        return ">" if line == "" else f"> {line}"

    def parse_inline_admon(line: str) -> str | None:
        m = _INLINE_ADMON_RE.match(line.strip())
        if not m:
            return None
        kind, body = m.group(1), replace_links(m.group(2).strip())
        return f"> **{kind}:** {body}" if body else f"> **{kind}:**"

    def parse_fenced_code(
        start: int, quoted: bool, language: str = ""
    ) -> tuple[int, list[str]] | None:
        fence = lines[start].strip()
        if fence not in ("----", "...."):
            return None

        j = start + 1
        code: list[str] = []
        while j < len(lines) and lines[j].strip() != fence:
            code.append(lines[j].rstrip("\n"))
            j += 1
        if j >= len(lines):
            return None  # no closing fence

        lang = language.strip()
        open_fence = f"```{lang}".rstrip()
        block = [open_fence, *code, "```"]

        if quoted:
            block = [quote(x) for x in block]

        return j + 1, block

    def parse_source_block(start: int, quoted: bool) -> tuple[int, list[str]] | None:
        # [source,bash]
        m = _SOURCE_RE.match(lines[start].strip())
        if not m:
            return None

        language = m.group(1) or ""
        if start + 1 >= len(lines):
            return None

        # next line must be ---- or ....
        fence_line = lines[start + 1].strip()
        if fence_line not in ("----", "...."):
            return None

        # parse the fenced code starting at the fence line, with language
        return parse_fenced_code(start + 1, quoted=quoted, language=language)

    def parse_code_block(start: int, quoted: bool) -> tuple[int, list[str]] | None:
        # try [source,lang] first, then bare fence
        src = parse_source_block(start, quoted=quoted)
        if src:
            next_i, block = src
            # src parser consumed starting at fence line; we need to advance one extra for the [source,...] line
            return next_i, block  # caller will set i appropriately depending on start
        return parse_fenced_code(start, quoted=quoted)

    def parse_block_admon(start: int) -> tuple[int, list[str]] | None:
        # [NOTE] \n ==== \n ... \n ====
        m = _BLOCK_ADMON_TAG_RE.match(lines[start].strip())
        if not m or start + 1 >= len(lines) or lines[start + 1].strip() != "====":
            return None

        kind = m.group(1)
        j = start + 2

        md_lines: list[str] = [f"> **{kind}:**"]
        # parse interior with awareness of code blocks
        while j < len(lines) and lines[j].strip() != "====":
            # blank line inside note
            if lines[j].strip() == "":
                md_lines.append(">")
                j += 1
                continue

            # code blocks inside admonition (quoted=True)
            # handle [source,bash] on current line
            if _SOURCE_RE.match(lines[j].strip()):
                parsed = parse_source_block(j, quoted=True)
                if parsed:
                    next_j, block = parsed
                    md_lines.extend(block)
                    j = next_j
                    continue

            # handle bare fenced code start inside admonition
            if lines[j].strip() in ("----", "...."):
                parsed = parse_fenced_code(j, quoted=True)
                if parsed:
                    next_j, block = parsed
                    md_lines.extend(block)
                    j = next_j
                    continue

            # normal text line inside admonition
            md_lines.append(quote(replace_links(lines[j].strip())))
            j += 1

        if j >= len(lines):
            return None  # no closing ====

        return j + 1, md_lines

    while i < len(lines):
        line = lines[i].rstrip()

        # block admonitions first
        block_admon = parse_block_admon(i)
        if block_admon:
            next_i, md = block_admon
            if out and out[-1] == "":
                out.pop()
            for x in md:
                emit(x)
            i = next_i
            continue

        # non-quoted code blocks (top-level)
        if _SOURCE_RE.match(lines[i].strip()):
            parsed = parse_source_block(i, quoted=False)
            if parsed:
                next_i, block = parsed
                # parsed consumed from fence line; advance past [source,...] too
                if out and out[-1] == "":
                    out.pop()
                for x in block:
                    emit(x)
                i = next_i  # already at line after closing fence
                continue

        if lines[i].strip() in ("----", "...."):
            parsed = parse_fenced_code(i, quoted=False)
            if parsed:
                next_i, block = parsed
                if out and out[-1] == "":
                    out.pop()
                for x in block:
                    emit(x)
                i = next_i
                continue

        # inline admonitions
        inline = parse_inline_admon(line)
        if inline is not None:
            if out and out[-1] == "":
                out.pop()
            emit(inline)
            i += 1
            continue

        # normal line
        emit(replace_links(line.strip()))
        i += 1

    # trim leading/trailing blanks
    while out and out[0] == "":
        out.pop(0)
    while out and out[-1] == "":
        out.pop()

    return "\n".join(out)


def rule_context(rule, baseline_title: str = "", show_all_tags: bool = False) -> dict:
    """
    Build a small context dict for a rule with all the derived values
    you were previously computing in Jinja.
    """
    os_type = _get_attr(rule, "os_type")

    check_tags = ["permanent", "inherent", "n_a", "not_applicable"]

    sat = bool(show_all_tags)

    tags = _get_attr(rule, "tags")
    if tags is None:
        is_supplemental = False
    else:
        # tags may be a list, tuple, or string
        if isinstance(tags, (list, tuple, set)):
            is_supplemental = "supplemental" in tags
            is_permanent = "permanent" in tags
            is_inherent = "inherent" in tags
            is_not_applicable = "n_a" in tags or "not_applicable" in tags
        else:
            # fallback for weird cases (e.g. comma-sep string)
            is_supplemental = "supplemental" in str(tags)

    title = baseline_title.upper()

    def _contains(token: str) -> bool:
        return token in title

    additional_info = get_nested(
        rule,
        ["platforms", os_type, "enforcement_info", "fix", "additional_info"],
        default=None,
    )

    check_shell = get_nested(
        rule,
        ["platforms", os_type, "enforcement_info", "check", "shell"],
        default=None,
    )

    fix_shell = get_nested(
        rule,
        ["platforms", os_type, "enforcement_info", "fix", "shell"],
        default=None,
    )

    fix_text = _get_attr(rule, "fix")
    mobileconfig_info = _get_attr(rule, "mobileconfig_info")

    has_fix_text = _nonempty(fix_text)
    has_fix_shell = _nonempty(fix_shell)
    has_additional = _nonempty(additional_info)
    has_mobileconfig = mobileconfig_info is not None and len(mobileconfig_info) > 0

    show_171 = _contains("800-171") or sat
    show_stig = _contains("STIG") or sat
    show_cis = _contains("CIS") or sat
    show_indigo = _contains("INDIGO") or sat
    show_cmmc = _contains("CMMC") or sat

    return {
        "check_tags": check_tags,
        "additional_info": additional_info,
        "check_shell": check_shell,
        "fix_shell": fix_shell,
        "has_fix_text": has_fix_text,
        "has_fix_shell": has_fix_shell,
        "has_additional": has_additional,
        "has_mobileconfig": has_mobileconfig,
        "is_supplemental": is_supplemental,
        "is_permanent": is_permanent,
        "is_inherent": is_inherent,
        "is_not_applicable": is_not_applicable,
        "show_171": show_171,
        "show_stig": show_stig,
        "show_cis": show_cis,
        "show_indigo": show_indigo,
        "show_cmmc": show_cmmc,
        "show_all_tags": sat,
    }


def make_env(template_dir: str, lang: str = "en") -> Environment:
    if not template_dir:
        template_dir = config["defaults"]["templates_dir"]

    translations = gettext.translation(
        domain="messages",
        localedir=config["localization_dir"],
        languages=[lang],
        fallback=True,
    )

    env: Environment = Environment(
        loader=FileSystemLoader(template_dir),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
        keep_trailing_newline=True,
        extensions=["jinja2.ext.i18n"],
    )

    env.filters["group_ulify"] = group_ulify
    env.filters["include_replace"] = replace_include_with_file_content
    env.filters["render_rules"] = render_rules
    env.filters["get_nested"] = get_nested
    env.filters["mobileconfig_payloads_to_xml"] = (
        Macsecurityrule.mobileconfig_info_to_xml
    )
    env.filters["rule_context"] = rule_context
    env.filters["asciidoc_to_markdown"] = asciidoc_to_markdown

    env.install_gettext_translations(translations)

    def t(key: str, default: str = "", **kwargs) -> str:
        s = translations.gettext(key)
        if s == key:  # missing translation
            s = default or key
        if kwargs:
            s = s % kwargs  # gettext-style interpolation
        return s

    env.globals["t"] = t

    return env


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
    language: str = "en",
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
        loader=FileSystemLoader(template_dir), trim_blocks=True, lstrip_blocks=True
    )

    styles_dir: Path = Path(misc_dir).absolute()
    images_dir: Path = Path(logo_dir).absolute()
    acronyms_file: Path = Path(config["includes_dir"], "acronyms.yaml").absolute()
    os_version_str: str = str(version_info.get("os_version", None))

    env: Environment = make_env(lang=language, template_dir=template_dir)

    template: Template = env.get_template(f"documents/{template_name}")

    baseline_dict: dict[str, Any] = baseline.model_dump()
    acronyms_data: dict[str, Any] = open_file(acronyms_file, language)

    html_title, html_subtitle = map(str.strip, baseline.title.split(":", 1))
    document_subtitle2: str = ":document-subtitle2:"

    if "Tailored from" in baseline.title:
        html_subtitle: str = html_subtitle.split("(")[0]
        html_subtitle2: str = extract_from_title(baseline.title)
        document_subtitle2 = f"{document_subtitle2} {html_subtitle2}"

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
        os_version=os_version_str,
        version=version_info.get("compliance_version", None),
        release_date=version_info.get("date", None),
        custom=custom,
        output_format=output_format,
        acronyms=acronyms_data.get("acronyms", []),
        terminology=acronyms_data.get("terminology", []),
        additional_links=mscp_data.get("additional_links", {})
        .get("platforms", {})
        .get(os_name, {})
        .get(os_version_str, []),
    )

    create_file(output_file, rendered_output)


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
    language: str = "en",
) -> None:
    template_dir: str = config["defaults"]["templates_dir"]
    misc_dir: str = config["defaults"]["misc_dir"]
    logo_dir: str = config["defaults"]["images_dir"]

    if custom:
        template_dir = config["custom"]["templates_dir"]
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
        language,
    )

    if output_format == "adoc":
        asciidoctor_path, _ = run_command("bundle show asciidoctor")
        asciidoctor_pdf_path, _ = run_command("bundle show asciidoctor-pdf")

        if (
            "Could not find gem" in asciidoctor_path
            or "Could not find gem" in asciidoctor_pdf_path
        ):
            output, error = run_command(
                "bundle install --gemfile Gemfile --path mscp_gems --binstubs"
            )
            if error:
                logger.error(f"Bundle install failed: {error}")
                sys.exit()

        output, error = run_command(f"bundle exec asciidoctor {output_file}")
        if error:
            logger.error(f"Error converting to ADOC: {error}")
            sys.exit()

        output, error = run_command(f"bundle exec asciidoctor-pdf {output_file}")
        if error:
            logger.error(f"Error converting to ADOC: {error}")
            sys.exit()
