# mscp/generate/documents.py
"""Guidance document rendering (AsciiDoc, PDF, HTML, Markdown) for mSCP.

Provides `generate_documents`, which renders a baseline through the main
Jinja template and optionally invokes AsciiDoctor to produce PDF and HTML
output.  `render_template` performs the actual Jinja render.  Helper Jinja
filters are also defined here: `group_ulify`, `group_ulify_md`,
`render_references`, `render_rules`, `render_rules_md`,
`replace_include_with_file_content`, `asciidoc_to_markdown`, and
`get_nested`.  The `ddm_info_to_json` filter is imported from `ddm` and
registered here alongside `mobileconfig_payloads_to_xml`.
"""

# Standard python modules
import gettext
import re
import shutil
import sys
import time
from html import escape as html_escape
from collections.abc import Mapping
from itertools import groupby
from pathlib import Path
from typing import Any, Sequence, Dict, List

# Additional python modules
from jinja2 import Environment, FileSystemLoader, Template
# from yaspin.core import Yaspin
# from yaspin.spinners import Spinners

# Local python modules
from ...classes import Baseline
from ...classes.mobileconfig import mobileconfig_info_to_xml
from .ddm import ddm_info_to_json
from ...common_utils import (
    config,
    logger,
    mscp_data,
    remove_file,
    open_file,
    search_paths,
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


def render_rules(rule_set: list[str] | None) -> str:
    """Render a list of rule strings as newline-separated ``"- <rule>"`` lines.

    Args:
        rule_set (list[str] | None): Rule strings to render. ``None`` or an
            empty value returns an empty string.

    Returns:
        str: Newline-joined bullet lines, or ``""`` when *rule_set* is empty
            or ``None``.
    """
    if not rule_set:
        return ""
    return "\n".join(f"- {rule}" for rule in rule_set)


def render_rules_md(rule_set: list[str] | None) -> str:
    """Render a list of rule strings as ``<br>``-joined ``"- <rule>"`` lines for Markdown.

    Args:
        rule_set (list[str] | None): Rule strings to render. ``None`` or an
            empty value returns an empty string.

    Returns:
        str: ``<br>``-joined bullet lines, or ``""`` when *rule_set* is empty
            or ``None``.
    """
    if not rule_set:
        return ""
    return "<br>".join(f"- {rule}" for rule in rule_set)


# ---------------------------------------------------------------------------
# Typst output helpers (PDF backend)
#
# Typst is a markup language where ``# $ * _ ` < > @ ~ [ ] \`` are
# significant.  Literal data (rule IDs full of underscores, references,
# titles) must be escaped before being injected into Typst markup, otherwise
# it silently renders as emphasis/code or fails to compile.
# ---------------------------------------------------------------------------

# Characters that must be backslash-escaped when emitting literal Typst text.
_TYPST_ESCAPE: dict[str, str] = {
    "\\": "\\\\",
    "#": "\\#",
    "$": "\\$",
    "*": "\\*",
    "_": "\\_",
    "`": "\\`",
    "<": "\\<",
    ">": "\\>",
    "@": "\\@",
    "~": "\\~",
    "[": "\\[",
    "]": "\\]",
}

def typst_escape(value: Any) -> str:
    """Backslash-escape every Typst-significant character in *value*.

    Used for short literal fields (rule IDs, references, titles, severity)
    that must appear verbatim in the rendered PDF.

    Args:
        value (Any): Value to escape; ``None`` becomes ``""``.

    Returns:
        str: Typst-safe literal text.
    """
    if value is None:
        return ""
    return "".join(_TYPST_ESCAPE.get(ch, ch) for ch in str(value))


def group_ulify_typst(elements: list[str]) -> str:
    """`group_ulify` for Typst: groups by prefix, escapes each element.

    Args:
        elements (list[str]): Strings to group and format.

    Returns:
        str: ``"- N/A"`` if ``"N/A"`` is present, otherwise a newline-joined
            Typst bullet list with every element escaped.
    """
    if "N/A" in elements:
        return "- N/A"

    elements.sort()
    grouped = [list(i) for _, i in groupby(elements, lambda a: a.split("(")[0])]

    return "\n".join(
        "- " + ", ".join(typst_escape(e) for e in group) for group in grouped
    ).strip()


def render_rules_typst(rule_set: list[str] | None) -> str:
    """`render_rules` for Typst: newline-separated escaped bullet lines.

    Args:
        rule_set (list[str] | None): Rule strings. ``None``/empty -> ``""``.

    Returns:
        str: Newline-joined ``"- <escaped rule>"`` lines.
    """
    if not rule_set:
        return ""
    return "\n".join(f"- {typst_escape(rule)}" for rule in rule_set)


def render_references_typst(reference_set: Sequence[Dict[str, Any]]) -> str:
    """`render_references` for Typst: flatten dicts to escaped bullet lines.

    Args:
        reference_set (Sequence[Dict[str, Any]]): Custom-reference dicts.

    Returns:
        str: Newline-joined ``"- key: value"`` Typst bullets, or ``""``.

    Raises:
        TypeError: If any element is not a dict.
    """
    lines: list[str] = []
    for d in reference_set:
        if not isinstance(d, dict):
            raise TypeError("All elements of 'reference_set' must be dictionaries.")
        for key, value in d.items():
            if isinstance(value, (list, tuple)):
                joined = ", ".join(map(str, value))
            else:
                joined = str(value)
            lines.append(f"- {typst_escape(key)}: {typst_escape(joined)}")
    return "\n".join(lines)


def asciidoc_to_typst(value: str) -> str:
    """Convert a subset of AsciiDoc to Typst markup.

    Handles source/code blocks (emitted as Typst raw fences, contents left
    verbatim), ``NOTE:``/``[IMPORTANT]`` admonitions, block titles,
    unordered/ordered lists, and ``link:url[text]`` macros.  Remaining prose
    is escaped for Typst while preserving ``*bold*`` / ``_italic_`` (shared
    between AsciiDoc and Typst).

    Args:
        value (str): AsciiDoc source text.

    Returns:
        str: Typst-formatted text.
    """
    if value is None:
        return ""

    lines = str(value).splitlines()
    result: list[str] = []
    i = 0

    link_pattern = re.compile(r"(?:link:)?(https?://\S+?)\[(.*?)\]")
    bold_pattern = re.compile(r"\*{1,2}([^*\n]+?)\*{1,2}")
    italic_pattern = re.compile(r"(?<![\w\\])_{1,2}([^_\n]+?)_{1,2}(?![\w])")
    sentinel_pattern = re.compile("\x00(\\d+)\x00")

    def _full_escape(text: str) -> str:
        return "".join(_TYPST_ESCAPE.get(ch, ch) for ch in text)

    def _inline(text: str) -> str:
        # Protect links and *balanced* bold/italic as sentinels, then fully
        # escape everything else.  This keeps intentional ``*bold*`` / ``_italic_``
        # markup while neutralising stray ``*`` ``_`` ``[`` ``]`` from regexes,
        # shell examples, or AsciiDoc artifacts (``***``) that would otherwise
        # leave an unclosed Typst delimiter and fail compilation.
        stash: list[str] = []

        def _put(rendered: str) -> str:
            stash.append(rendered)
            return f"\x00{len(stash) - 1}\x00"

        def _link(m: "re.Match[str]") -> str:
            url, label = m.group(1), m.group(2).strip()
            if label:
                return _put(f'#link("{url}")[{_full_escape(label)}]')
            return _put(f'#link("{url}")')

        text = link_pattern.sub(_link, text)
        text = bold_pattern.sub(lambda m: _put(f"*{_full_escape(m.group(1))}*"), text)
        text = italic_pattern.sub(
            lambda m: _put(f"_{_full_escape(m.group(1))}_"), text
        )
        escaped = _full_escape(text)
        return sentinel_pattern.sub(lambda m: stash[int(m.group(1))], escaped)

    while i < len(lines):
        line = lines[i].rstrip()

        # [source,lang] code block
        if line.startswith("[source"):
            lang_match = re.match(r"\[source\s*,?\s*([a-zA-Z0-9_+-]+)?", line)
            language = (lang_match.group(1) or "") if lang_match else ""
            if i + 1 < len(lines) and lines[i + 1].strip() in ("----", "...."):
                fence = lines[i + 1].strip()
                i += 2
                code_lines: list[str] = []
                while i < len(lines) and lines[i].strip() != fence:
                    code_lines.append(lines[i])
                    i += 1
                result.append(f"```{language}".rstrip())
                result.extend(code_lines)
                result.append("```")

        # Bare code block
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

        # NOTE: admonition -> tinted callout box (see admonition() in header.typ.jinja)
        elif line.startswith("NOTE:"):
            result.append(f'#admonition("NOTE")[{_inline(line[5:].strip())}]')

        # [IMPORTANT] admonition block -> tinted callout box
        elif (
            line.strip() == "[IMPORTANT]"
            and i + 1 < len(lines)
            and lines[i + 1].strip() == "===="
        ):
            i += 2
            important_lines: list[str] = []
            while i < len(lines) and lines[i].strip() != "====":
                important_lines.append(lines[i].strip())
                i += 1
            result.append(
                f'#admonition("IMPORTANT")[{_inline(" ".join(important_lines))}]'
            )

        # Skip AsciiDoc block attribute lines, e.g. [cols=...], [width=...]
        elif re.match(r"^\[(cols|width|options|grid|frame|stripes|%|role).*\]$", line):
            pass

        # Block title `.Some Title`
        elif re.match(r"^\.(?!\d+\s)(.+)$", line):
            title_text = re.match(r"^\.(.+)$", line).group(1).strip()
            result.append(f"*{_full_escape(title_text)}*")

        # Unordered list `* item` -> `- item`
        elif line.strip().startswith("* "):
            result.append("- " + _inline(line.strip()[2:]))

        # Ordered list `. item` -> `+ item`
        elif re.match(r"^\.\s+.+", line):
            result.append("+ " + _inline(line.strip()[2:]))

        else:
            result.append(_inline(line.strip()))

        i += 1

    return "\n".join(result)


# --------------------------------------------------------------------------- #
# HTML backend.  Mirrors the typst helpers but emits
# semantic HTML that reuses AsciiDoctor's CSS class names (``admonitionblock``,
# ``listingblock``, ``ulist`` ...) so the bundled ``asciidoctor.css`` styles it
# with no Ruby in the loop.
# --------------------------------------------------------------------------- #
def group_ulify_html(elements: list[str]) -> str:
    """`group_ulify` for HTML: grouped, escaped ``<ul>`` bullet list."""
    if "N/A" in elements:
        return "N/A"
    elements.sort()
    grouped = [list(i) for _, i in groupby(elements, lambda a: a.split("(")[0])]
    items = "".join(
        f"<li>{html_escape(', '.join(map(str, group)))}</li>" for group in grouped
    )
    return f'<ul class="ulist"><ul>{items}</ul></ul>' if items else ""


def render_rules_html(rule_set: list[str] | None) -> str:
    """`render_rules` for HTML: escaped ``<ul>`` bullet list."""
    if not rule_set:
        return ""
    # Values may be ints/floats (e.g. CIS control "3.3"); coerce before escaping.
    items = "".join(f"<li>{html_escape(str(r))}</li>" for r in rule_set)
    return f'<ul class="ulist"><ul>{items}</ul></ul>'


def render_references_html(reference_set: Sequence[Dict[str, Any]]) -> str:
    """`render_references` for HTML: ``<ul>`` of ``key: value`` bullets."""
    lines: list[str] = []
    for d in reference_set:
        if not isinstance(d, dict):
            raise TypeError("All elements of 'reference_set' must be dictionaries.")
        for key, value in d.items():
            joined = ", ".join(map(str, value)) if isinstance(value, (list, tuple)) else str(value)
            lines.append(f"<li>{html_escape(str(key))}: {html_escape(joined)}</li>")
    return f'<ul class="ulist"><ul>{"".join(lines)}</ul></ul>' if lines else ""


def asciidoc_to_html(value: str) -> str:
    """Convert a subset of AsciiDoc to HTML.

    Handles source/code blocks (``listingblock``), ``NOTE:``/``[IMPORTANT]``
    admonitions (``admonitionblock``), block titles, unordered/ordered lists,
    ``link:url[text]`` macros, and ``*bold*`` / ``_italic_`` inline markup.
    Prose is HTML-escaped; the emitted tags reuse AsciiDoctor's class names so
    the existing CSS applies.

    Args:
        value (str): AsciiDoc source text.

    Returns:
        str: HTML fragment.
    """
    if value is None:
        return ""

    link_pattern = re.compile(r"(?:link:)?(https?://\S+?)\[(.*?)\]")

    def _inline(text: str) -> str:
        # Escape first, then re-introduce the small set of markup we support so
        # user text can never inject tags.
        out: list[str] = []
        last = 0
        for m in link_pattern.finditer(text):
            out.append(html_escape(text[last : m.start()]))
            url, label = m.group(1), m.group(2).strip()
            out.append(f'<a href="{html_escape(url)}">{html_escape(label or url)}</a>')
            last = m.end()
        out.append(html_escape(text[last:]))
        joined = "".join(out)
        joined = re.sub(r"\*([^*]+)\*", r"<strong>\1</strong>", joined)
        joined = re.sub(r"(?<![\w/])_([^_]+)_(?![\w/])", r"<em>\1</em>", joined)
        return joined

    def _admonition(kind: str, body: str) -> str:
        return (
            f'<div class="admonitionblock {kind.lower()}"><table><tr>'
            f'<td class="icon"><div class="title">{kind.title()}</div></td>'
            f'<td class="content">{body}</td></tr></table></div>'
        )

    lines = str(value).splitlines()
    result: list[str] = []
    para: list[str] = []
    list_items: list[str] = []

    def flush_para() -> None:
        if para:
            result.append(f'<div class="paragraph"><p>{_inline(" ".join(para))}</p></div>')
            para.clear()

    def flush_list() -> None:
        if list_items:
            items = "".join(f"<li><p>{it}</p></li>" for it in list_items)
            result.append(f'<div class="ulist"><ul>{items}</ul></div>')
            list_items.clear()

    def flush_blocks() -> None:
        flush_para()
        flush_list()

    i = 0
    while i < len(lines):
        line = lines[i].rstrip()

        if line.startswith("[source") or line.strip() in ("----", "...."):
            flush_blocks()
            # Skip the [source] attribute line and/or the opening fence.
            i += 2 if line.startswith("[source") else 1
            code: list[str] = []
            while i < len(lines) and lines[i].strip() not in ("----", "...."):
                code.append(lines[i])
                i += 1
            body = html_escape("\n".join(code))
            result.append(
                '<div class="listingblock"><div class="content">'
                f'<pre class="highlight"><code>{body}</code></pre></div></div>'
            )
        elif line.startswith("NOTE:"):
            flush_blocks()
            result.append(_admonition("NOTE", _inline(line[5:].strip())))
        elif (
            line.strip() == "[IMPORTANT]"
            and i + 1 < len(lines)
            and lines[i + 1].strip() == "===="
        ):
            flush_blocks()
            i += 2
            imp: list[str] = []
            while i < len(lines) and lines[i].strip() != "====":
                imp.append(lines[i].strip())
                i += 1
            result.append(_admonition("IMPORTANT", _inline(" ".join(imp))))
        elif re.match(r"^\[(cols|width|options|grid|frame|stripes|%|role).*\]$", line):
            pass
        elif line.strip().startswith("* "):
            flush_para()
            list_items.append(_inline(line.strip()[2:]))
        elif not line.strip():
            flush_blocks()
        else:
            flush_list()
            para.append(line.strip())
        i += 1

    flush_blocks()
    return "\n".join(result)


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


def _resolve_asset_dir(filename: str, dir_key: str) -> str:
    """Return the directory that contains *filename*, preferring custom.

    Checks whether ``config["custom"][dir_key] / filename`` exists.  If so,
    returns the custom directory path; otherwise returns the bundled path
    from ``config[dir_key]``.  This allows a user to drop a single custom
    theme or image file into their custom directory and have it shadow the
    bundled default without replacing the entire directory.

    Args:
        filename (str): The asset filename to look up (e.g. ``"asciidoctor.css"``).
        dir_key (str): Config key shared between ``config`` and
            ``config["custom"]`` (e.g. ``"themes_dir"``).

    Returns:
        str: Absolute path to the directory that should be used.
    """
    custom_dir = Path(config["custom"].get(dir_key, ""))
    if custom_dir.exists() and (custom_dir / filename).exists():
        return str(custom_dir)
    return config[dir_key]


def render_template(
    output_file: Path,
    template_name: str,
    baseline: Baseline,
    b64logo: bytes,
    html_css: str,
    logo_path: Path,
    os_name: str,
    version_info: dict[str, Any],
    show_all_tags: bool,
    custom: bool,
    template_dirs: list[str],
    themes_dir: str,
    logo_dir: str,
    output_format: str = "html",
    language: str = "en",
) -> None:
    """Render a Jinja template against *baseline* data and write to *output_file*.

    Configures a Jinja ``Environment`` with all mSCP filters, installs
    gettext translations for *language*, renders the template, and writes
    the result as text.

    Args:
        output_file (Path): Destination for the rendered output.
        template_name (str): Filename of the template within *template_dirs*.
        baseline (Baseline): Baseline data model.
        b64logo (bytes): Base64-encoded logo image bytes.
        html_css (str): CSS filename for HTML output.
        logo_path (Path): Absolute path to the logo file.
        os_name (str): Operating system name string.
        version_info (dict[str, Any]): OS/compliance version metadata.
        show_all_tags (bool): Whether to render all tags in the document.
        custom (bool): Whether the baseline uses a custom configuration.
            Passed through to the Jinja template context.
        template_dirs (list[str]): Ordered list of directories for the Jinja
            ``FileSystemLoader``; earlier entries shadow later ones.
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
        loader=FileSystemLoader(template_dirs),
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
    env.filters["mobileconfig_payloads_to_xml"] = mobileconfig_info_to_xml
    env.filters["ddm_info_to_json"] = ddm_info_to_json
    env.install_gettext_translations(translations)

    if output_format == "markdown":
        env.filters["group_ulify"] = group_ulify_md
        env.filters["render_rules"] = render_rules_md
        env.filters["asciidoc_to_markdown"] = asciidoc_to_markdown

    if output_format == "typst":
        env.filters["group_ulify"] = group_ulify_typst
        env.filters["render_rules"] = render_rules_typst
        env.filters["render_references"] = render_references_typst
        env.filters["asciidoc_to_typst"] = asciidoc_to_typst
        env.filters["typst_escape"] = typst_escape

    css_content: str = ""
    dark_css_content: str = ""
    default_theme: str = "system"
    if output_format == "html":
        env.filters["group_ulify"] = group_ulify_html
        env.filters["render_rules"] = render_rules_html
        env.filters["render_references"] = render_references_html
        env.filters["asciidoc_to_html"] = asciidoc_to_html
        # Inline BOTH the light and dark stylesheets so the HTML is self-contained
        # and can switch theme at runtime with no network. The light sheet is the
        # cascade base; the dark sheet is overlaid via a toggled ``media`` attribute
        # in the template. ``html_css`` (set by ``--dark``) only picks the *initial*
        # theme -- the in-page toggle can still override it and persists the choice.
        if "-dark.css" in html_css:
            light_name = html_css.replace("-dark.css", ".css")
            dark_name = html_css
            default_theme = "dark"
        else:
            light_name = html_css
            dark_name = html_css.replace(".css", "-dark.css")

        _css_path = Path(themes_dir, light_name)
        if _css_path.exists():
            css_content = _css_path.read_text()
        else:
            logger.warning(f"CSS not found for HTML output: {_css_path}")

        _dark_css_path = Path(themes_dir, dark_name)
        if _dark_css_path.exists():
            dark_css_content = _dark_css_path.read_text()
        else:
            logger.warning(f"Dark CSS not found for HTML output: {_dark_css_path}")

    template: Template = env.get_template(template_name)

    baseline_dict: dict[str, Any] = baseline.model_dump()
    acronyms_data: dict[str, Any] = open_file(acronyms_file, language)

    _title_parts = baseline.title.split(":", 1)
    if len(_title_parts) == 2:
        html_title, html_subtitle = map(str.strip, _title_parts)
    else:
        html_title = baseline.title.strip()
        html_subtitle = ""
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
        html_css=html_css,
        show_all_tags=show_all_tags,
        os_name=os_name.strip().lower(),
        os_version=str(version_info.get("os_version", None)),
        version=version_info.get("compliance_version", None),
        release_date=mscp_data["mscp"].get("release_date", None),
        custom=custom,
        format=output_format,
        acronyms=acronyms_data.get("acronyms", []),
        terminology=acronyms_data.get("terminology", []),
        NIX_OS=NIX_OS,
        css_content=css_content,
        dark_css_content=dark_css_content,
        default_theme=default_theme,
    )

    output_file.write_text(rendered_output)


def _generate_typst_pdf(output_file: Path, logo_path: Path) -> None:
    """Compile a rendered ``.typ`` file to PDF using the ``typst`` package.

    typst is provided as a Python dependency (``uv sync``), so it is called via
    its binding rather than an external binary.  It is the only PDF engine, so a
    missing package or a failed compile is a hard error (``sys.exit``) with an
    actionable hint — there is no Ruby fallback.

    Args:
        output_file (Path): The rendered ``.typ`` file to compile.
        logo_path (Path): Absolute path to the title-page logo image.
    """
    try:
        import typst
    except ImportError:
        logger.error(
            "The 'typst' package is required to generate the PDF but is not "
            "installed. Run 'uv sync' (it is a project dependency), then re-run."
        )
        sys.exit(1)

    build_dir: Path = output_file.parent
    # Typst can only read files under its --root; copy the logo next to the
    # .typ and reference it by name from the template.
    try:
        dest_logo: Path = build_dir / logo_path.name
        if logo_path.resolve() != dest_logo.resolve():
            shutil.copy(logo_path, dest_logo)
    except OSError as e:
        logger.warning(f"Could not stage logo for typst: {e}")

    pdf_file: Path = output_file.with_suffix(".pdf")
    try:
        typst.compile(str(output_file), output=str(pdf_file), root=str(build_dir))
    except Exception as e:  # typst raises on compile errors
        logger.error(f"typst compile failed: {e}")
        sys.exit(1)
    if not pdf_file.exists():
        logger.error("typst compile produced no PDF.")
        sys.exit(1)
    logger.info(f"PDF generated: {pdf_file}")
    remove_file(dest_logo)
    remove_file(output_file)


def generate_documents(
    output_file: Path,
    baseline: Baseline,
    b64logo: bytes,
    html_css: str,
    logo_path: Path,
    os_name: str,
    version_info: dict[str, Any],
    show_all_tags: bool = False,
    output_format: str = "html",
    language: str = "en",
) -> None:
    """Render a guidance document in the requested format.

    Resolves template and image directories (custom dir shadows bundled
    defaults) and calls `render_template`.  For ``"typst"`` output it then
    compiles the rendered ``.typ`` to PDF via the ``typst`` binary.  HTML and
    Markdown are produced by Jinja alone — no external tools, no Ruby.

    Args:
        output_file (Path): Destination file (``.typ`` / ``.html`` / ``.md``).
        baseline (Baseline): Baseline data model.
        b64logo (bytes): Base64-encoded logo image bytes.
        html_css (str): CSS filename; also selects the light/dark theme.
        logo_path (Path): Absolute path to the logo file.
        os_name (str): Operating system name string.
        version_info (dict[str, Any]): OS/compliance version metadata.
        show_all_tags (bool): Whether to render all tags. Defaults to ``False``.
        output_format (str): ``"typst"``, ``"html"``, or ``"markdown"``.
        language (str): BCP-47 language code. Defaults to ``"en"``.
    """
    # Determine whether any custom content is active (for template context).
    _custom_root = Path(config["custom"]["root_dir"])
    custom: bool = _custom_root.exists() and any(_custom_root.iterdir())

    # Templates: custom files shadow bundled ones via ordered search paths.
    _template_dirs: list[str] = search_paths("documents_templates_dir")

    # Static assets: prefer the custom directory when it contains the file.
    # The stylesheet locates the themes dir for all formats now that PDF/HTML
    # both derive their look from the CSS / typst theme.
    _themes_dir: str = _resolve_asset_dir(html_css, "themes_dir")
    _logo_dir: str = _resolve_asset_dir(logo_path.name, "images_dir")

    # Each format uses its own self-contained template tree.
    main_template: str = {
        "typst": "typst/main.typ.jinja",
        "html": "html/main.html.jinja",
    }.get(output_format, "main.jinja")

    render_template(
        output_file,
        main_template,
        baseline,
        b64logo,
        html_css,
        logo_path,
        os_name,
        version_info,
        show_all_tags,
        custom,
        _template_dirs,
        _themes_dir,
        _logo_dir,
        output_format,
        language,
    )

    if output_format == "typst":
        _generate_typst_pdf(output_file, logo_path)

    elif output_format == "html":
        # Pure-Python HTML: render_template already wrote the self-contained
        # file (CSS inlined). No external tool, no Ruby.
        logger.info(f"HTML generated: {output_file}")