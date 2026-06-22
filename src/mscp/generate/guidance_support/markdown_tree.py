# mscp/generate/guidance_support/markdown_tree.py
"""Paginated Markdown tree output for mSCP guidance documents.

Provides `generate_markdown_tree`, which renders a baseline as a directory tree
suitable for any CommonMark-based static site generator (Docusaurus, Starlight,
MkDocs, VitePress, etc.):

    <build>/<baseline>/markdown_tree/
        index.md                 # overview: foreword, scope, authors, acronyms
        02-<section-slug>/
            index.md             # section description (category landing page)
            01-<rule-slug>.md    # one page per rule
        03-<section-slug>/
            ...

Ordering uses ``NN-`` numeric prefixes on directory and file names so all
generators that sort alphabetically by filename display sections and rules in the
correct order without any extra configuration.  The ``index.md`` naming
convention is honoured by Docusaurus (category-index doc), Starlight
(auto-generated sidebar root), MkDocs (default nav), and is also the natural
GitHub browsing entrypoint.

Frontmatter is kept minimal - ``title`` only - so it works across all
generators without modification.  Docusaurus-specific sidebar metadata
(``sidebar_position``,
``description``, ``_category_.json`` sidecars) is intentionally omitted; the
``NN-`` prefix scheme provides the same ordering guarantee without requiring any
framework-specific files.

Rendering reuses the existing shared Jinja includes and Markdown filters
(``asciidoc_to_markdown``, ``group_ulify_md``, ``render_rules_md``) plus the
shared ``markdown_tree/rule.md.jinja`` template (which extends
``markdown/rule.md.jinja`` with per-page structural changes).  A whole-page
MDX-safety pass is applied once per rendered page rather than per-field in the
template, giving complete coverage and a single point of maintenance.

MDX-safety notes (Docusaurus / Starlight compile ``.md`` through MDX by
default):
- ``{``/``}`` are entity-encoded outside fenced blocks (JSX expression syntax).
- Bare ``<`` not opening a known HTML tag is entity-encoded (JSX element syntax).
- HTML void tags (``<br>``, ``<hr>``, ``<img>``) are normalised to self-closing
  form (``<br />``) so MDX does not flag unclosed elements.

Known limitation: bare ``<https://…>`` autolinks in rule prose are
entity-encoded to visible text (AsciiDoc ``link:`` macros convert correctly).

No dependencies beyond what the project already uses (Jinja2 + stdlib).
"""

# Standard python modules
import gettext
import re
from pathlib import Path
from typing import Any

# Additional python modules
from jinja2 import Environment, FileSystemLoader

# Local python modules
from ...classes import Baseline
from ...classes.mobileconfig import mobileconfig_info_to_xml
from ...common_utils import (
    NIX_OS,
    config,
    logger,
    make_dir,
    mscp_data,
    open_file,
    search_paths,
)
from .documents import (
    asciidoc_to_markdown,
    get_nested,
    group_ulify_md,
    render_rules_md,
    replace_include_with_file_content,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def create_slug(text: str) -> str:
    """Convert *text* to a URL/filename-safe slug.

    Produces a lowercase, hyphen-separated identifier from arbitrary display
    text.  Used for section directory names and rule filenames so they are
    stable, ASCII-safe, and readable in the filesystem.

    Args:
        text (str): Arbitrary display text (section or rule title).

    Returns:
        str: Slug such as ``"system-settings"``.
    """
    slug = text.lower()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-{2,}", "-", slug)
    return slug.strip("-")


def mdx_escape(value: str) -> str:
    """Entity-encode MDX expression delimiters outside fenced code blocks.

    MDX parses ``{…}`` as a JSX expression and a bare ``<`` that does not open
    a valid element as a parse error, so prose containing shell snippets or
    plist fragments breaks the page.  Fenced code blocks are already literal in
    MDX; inline code spans are also left untouched.  Everything else gets ``{``,
    ``}`` and any ``<`` not opening a plausible HTML/JSX tag entity-encoded.

    This function is applied once to the fully-rendered page body (not per-field
    in templates) so coverage is complete.

    Args:
        value (str): Markdown text (may contain fenced code blocks).

    Returns:
        str: MDX- and CommonMark-safe Markdown.
    """
    if not value:
        return value

    # ``<`` is left alone only when it opens/closes a KNOWN HTML tag the
    # markdown templates emit.  Anything else - including plist fragments such
    # as ``<dict>`` or ``<key>`` - is entity-encoded, since MDX would otherwise
    # parse it as an (unclosed) JSX element.
    html_tags = (
        "a|br|hr|table|thead|tbody|tr|td|th|p|div|span|strong|em|b|i|u|code|pre"
        "|ul|ol|li|img|sub|sup|details|summary|h[1-6]"
    )
    tag_like = re.compile(rf"<(/?(?:{html_tags}))(\s[^<>]*)?/?>", re.IGNORECASE)
    # HTML void elements must be self-closing in MDX/JSX.  Applied to stashed
    # tags only (inside _escape_prose), so code blocks stay untouched.
    # The trailing ``/?`` makes the rewrite idempotent for already-self-closing.
    void_tag = re.compile(r"<(br|hr|img)((?:\s[^<>]*?)?)\s*/?\s*>", re.IGNORECASE)

    def _escape_prose(text: str) -> str:
        placeholders: list[str] = []

        def _stash(m: re.Match) -> str:
            tag = m.group(0)
            # Normalise allowlisted void tags to self-closing JSX form here -
            # never on raw input, which would mutate fenced/inline code.
            tag = void_tag.sub(
                lambda v: f"<{v.group(1)}{(v.group(2) or '').rstrip()} />", tag
            )
            placeholders.append(tag)
            return f"\x00TAG{len(placeholders) - 1}\x00"

        # Protect inline code spans (single-backtick) before escaping.
        # NOTE: double-backtick spans (``code``) are matched as two empty spans;
        # their interior is entity-encoded - semantically identical output for
        # braces, but documented here as a known limitation.
        spans: list[str] = []

        def _stash_span(m: re.Match) -> str:
            spans.append(m.group(0))
            return f"\x00SPAN{len(spans) - 1}\x00"

        text = re.sub(r"`[^`\n]*`", _stash_span, text)
        text = tag_like.sub(_stash, text)
        text = text.replace("{", "&#123;").replace("}", "&#125;").replace("<", "&lt;")
        for i, tag in enumerate(placeholders):
            text = text.replace(f"\x00TAG{i}\x00", tag)
        for i, span in enumerate(spans):
            text = text.replace(f"\x00SPAN{i}\x00", span)
        return text

    # Split on fenced code blocks; escape only the prose segments.
    parts = re.split(r"(```.*?```)", value, flags=re.DOTALL)
    return "".join(
        part if part.startswith("```") else _escape_prose(part) for part in parts
    )


def render_references_md(reference_set) -> str:
    """Render custom-reference dicts as a single GFM-table-safe cell string.

    The shared ``render_references`` emits AsciiDoc cell rows (newlines + ``!``
    markers), which terminate a GFM pipe-table row.  This variant flattens each
    dict to ``**key**: value`` pairs joined with ``<br />`` and escapes ``|``.

    Args:
        reference_set: Sequence of dicts (same contract as ``render_references``).

    Returns:
        str: ``<br />``-joined cell content, or ``""`` when empty.
    """
    if not reference_set:
        return ""
    parts: list[str] = []
    for d in reference_set:
        for key, val in d.items():
            if isinstance(val, (list, tuple)):
                rendered = ", ".join(str(v) for v in val)
            else:
                rendered = str(val)
            parts.append(f"**{key}**: {rendered}".replace("|", r"\|"))
    return "<br />".join(parts)


def _frontmatter(fields: dict[str, Any]) -> str:
    """Render a minimal YAML frontmatter block.

    Strings are single-quoted with embedded single-quotes doubled (YAML
    single-quote escaping); other scalars are emitted bare.

    Args:
        fields (dict[str, Any]): Frontmatter key/value pairs, in order.

    Returns:
        str: The complete ``---``-delimited frontmatter block.
    """
    lines = ["---"]
    for key, value in fields.items():
        if isinstance(value, str):
            sanitised = value.replace("\r", "").replace("\n", " ")
            quoted = sanitised.replace("'", "''")
            lines.append(f"{key}: '{quoted}'")
        else:
            lines.append(f"{key}: {value}")
    lines.append("---")
    return "\n".join(lines)


def _translations(language: str) -> gettext.NullTranslations:
    """Load gettext translations for *language* (with English fallback).

    Args:
        language (str): BCP-47 language code.

    Returns:
        gettext.NullTranslations: Translation catalogue for the language.
    """
    return gettext.translation(
        domain="messages",
        localedir=config["locales_dir"],
        languages=[language],
        fallback=True,
    )


def _build_env(template_dirs: list[str], language: str) -> Environment:
    """Construct the Jinja environment for markdown-tree rendering.

    Identical filter set to the existing Markdown rendering environment plus
    the GFM-table-safe ``render_references`` variant.  The ``mdx_escape``
    filter is registered but intentionally NOT called from templates - escaping
    is applied once per page in Python after the full body is rendered.

    Args:
        template_dirs (list[str]): Ordered template search paths (custom
            directories shadow bundled ones).
        language (str): BCP-47 language code for gettext lookup.

    Returns:
        Environment: Configured Jinja environment.
    """
    translations = _translations(language)
    env = Environment(
        loader=FileSystemLoader(template_dirs),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
        extensions=["jinja2.ext.i18n"],
        keep_trailing_newline=True,
    )
    env.filters["group_ulify"] = group_ulify_md
    env.filters["include_replace"] = replace_include_with_file_content
    env.filters["render_rules"] = render_rules_md
    env.filters["render_references"] = render_references_md
    env.filters["get_nested"] = get_nested
    env.filters["mobileconfig_payloads_to_xml"] = mobileconfig_info_to_xml
    env.filters["asciidoc_to_markdown"] = asciidoc_to_markdown
    # Registered for template compatibility; whole-page escaping is done in
    # Python rather than per-field to ensure complete coverage.
    env.filters["mdx_escape"] = mdx_escape
    env.install_gettext_translations(translations)
    return env


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def generate_markdown_tree(
    build_path: Path,
    baseline: Baseline,
    version_info: dict[str, Any],
    show_all_tags: bool = False,
    language: str = "en",
) -> None:
    """Render *baseline* as a paginated Markdown directory tree.

    Writes ``markdown_tree/`` under *build_path*: an ``index.md`` overview
    (foreword, scope, authors, acronyms) and one subdirectory per section, each
    containing a section ``index.md`` and one ``.md`` file per rule.

    Directory and file names carry ``NN-`` numeric prefixes so generators that
    sort alphabetically by filename display content in the correct order without
    extra configuration.  The ``index.md`` naming follows the category-index
    convention recognised by Docusaurus, Starlight, and MkDocs.

    Frontmatter is minimal - ``title`` only - and is safe to use in any
    CommonMark-based static site generator.  The rendered text is MDX-
    and CommonMark-safe by construction: ``{``/``}`` and bare ``<`` outside
    fenced code blocks are entity-encoded, and HTML void tags are normalised to
    self-closing form.

    Drop the entire ``markdown_tree/`` directory (or its contents) into the
    docs source folder of any CommonMark-based SSG - no post-processing
    required.

    Args:
        build_path (Path): Baseline build directory (e.g. ``build/<name>``).
        baseline (Baseline): Baseline data model.
        version_info (dict[str, Any]): OS/compliance version metadata.
        show_all_tags (bool): Render all reference tags regardless of
            benchmark.  Defaults to ``False``.
        language (str): BCP-47 language code.  Defaults to ``"en"``.
    """
    output_root = build_path / "markdown_tree"
    make_dir(output_root)

    template_dirs = search_paths("documents_templates_dir")
    env = _build_env(template_dirs, language)

    baseline_dict = baseline.model_dump()
    benchmark = baseline.title.split()[-1]
    benchmarks = mscp_data.get("benchmarks", "")
    baseline_dict["tailored"] = "Tailored from" in baseline.title
    baseline_dict["benchmark_description"] = next(
        (d["description"] for d in benchmarks if d.get("keyword") == benchmark),
        benchmark,
    )
    if any(author.is_additional for author in baseline.authors):
        baseline_dict["additional_authors"] = True

    acronyms_file = Path(config["includes_dir"], "acronyms.yaml").absolute()
    acronyms_data: dict[str, Any] = open_file(acronyms_file, language)

    context: dict[str, Any] = {
        "baseline": baseline_dict,
        "show_all_tags": show_all_tags,
        "os_name": baseline.platform["os"].strip().lower(),
        "os_version": str(version_info.get("os_version", None)),
        "version": version_info.get("compliance_version", None),
        "release_date": version_info.get("date", None),
        "format": "markdown",
        "markdown_tree": True,
        "acronyms": acronyms_data.get("acronyms", []),
        "terminology": acronyms_data.get("terminology", []),
        "NIX_OS": NIX_OS,
    }

    # Overview page: foreword / scope / authors / acronyms.
    # Rendered using the same shared includes as the single-file markdown mode.
    overview_template = env.get_template("markdown_tree/index.md.jinja")
    index_body = overview_template.render(**context)
    index_page = (
        _frontmatter({"title": baseline.title})
        + "\n\n"
        + mdx_escape(index_body)
    )
    (output_root / "index.md").write_text(index_page, encoding="utf-8")

    rule_template = env.get_template("markdown/rule.md.jinja")

    # Sections: position 2+ (overview is position 1 / no-prefix index.md).
    # The section directory carries a NN- prefix matching section_position so
    # the filesystem sort order matches the document order.
    for section_position, profile in enumerate(baseline.profile, start=2):
        section_slug = create_slug(profile.section)
        section_dir = output_root / f"{section_position:02d}-{section_slug}"
        make_dir(section_dir)

        section_description = asciidoc_to_markdown(profile.description).strip()
        section_index_body = section_description + "\n" if section_description else ""
        section_index = (
            _frontmatter({"title": profile.section})
            + "\n\n"
            + mdx_escape(section_index_body)
        )
        (section_dir / "index.md").write_text(section_index, encoding="utf-8")

        for rule_position, rule in enumerate(profile.rules, start=1):
            rule_dict = rule.model_dump()
            body = rule_template.render(rule=rule_dict, **context)
            page = (
                _frontmatter({"title": rule.title})
                + "\n\n"
                + mdx_escape(body)
            )
            rule_file = (
                section_dir / f"{rule_position:02d}-{create_slug(rule.title)}.md"
            )
            rule_file.write_text(page, encoding="utf-8")

        logger.debug(
            "Markdown tree: wrote {} rules for section '{}'",
            len(profile.rules),
            profile.section,
        )

    logger.success(f"Markdown tree output written to {output_root}")
