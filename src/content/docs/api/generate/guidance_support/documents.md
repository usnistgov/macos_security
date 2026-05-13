---
title: mscp.generate.guidance_support.documents
description: "Guidance document rendering (AsciiDoc, PDF, HTML, Markdown) for mSCP."
---

> Source: [`src/mscp/generate/guidance_support/documents.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/guidance_support/documents.py)

Guidance document rendering (AsciiDoc, PDF, HTML, Markdown) for mSCP.

Provides `generate_documents`, which renders a baseline through the main
Jinja template and optionally invokes AsciiDoctor to produce PDF and HTML
output.  `render_template` performs the actual Jinja render.  Helper Jinja
filters are also defined here: `group_ulify`, `group_ulify_md`,
`render_references`, `render_rules`, `render_rules_md`,
`replace_include_with_file_content`, `asciidoc_to_markdown`, and
`get_nested`.


## Functions

### group_ulify

```python
group_ulify(elements: list[str]) -> str
```

Converts a list of strings into a grouped unordered list (UL) format.

If the list contains the string "N/A", it returns "- N/A".
Otherwise, it sorts the list, groups elements by their prefix (before the first parenthesis),
and returns a string where each group is represented as a bullet point with its elements
separated by commas.

**Args**

- **`elements`** *(list[str])* — The list of strings to be converted.

**Returns**

- **`str`** — A string representing the grouped unordered list.


### group_ulify_md

```python
group_ulify_md(elements: list[str]) -> str
```

Convert a list of strings to a grouped ``<br />``-separated Markdown bullet list.

Like `group_ulify` but uses HTML ``<br />`` between groups for inline
Markdown rendering in tables.

**Args**

- **`elements`** *(list[str])* — Strings to group and format.

**Returns**

- **`str`** — ``"- N/A"`` if ``"N/A"`` is in *elements*, otherwise a ``<br />``-joined grouped bullet string.


### extract_from_title

```python
extract_from_title(title: str) -> str
```

Extract the text inside the first parenthesised group in *title*.

**Args**

- **`title`** *(str)* — String that may contain a ``(…)`` group.

**Returns**

- **`str`** — The content inside the first ``(…)``, or ``""`` if not found.


### render_references

```python
render_references(reference_set: Sequence[Dict[str, Any]]) -> str
```

Convert a sequence of dicts into AsciiDoc table rows (no header, no ``|===``).

**Args**

- **`reference_set`** *(Sequence[Dict[str, Any]])* — Dicts to render; list values are joined with ``"\n- "``.

**Returns**

- **`str`** — Newline-separated AsciiDoc cell rows, or ``""`` if *reference_set* is empty.

**Raises**

- **`TypeError`** — If any element of *reference_set* is not a dict.


### render_rules

```python
render_rules(rule_set: list[str]) -> str
```

Render a list of rule strings as newline-separated ``"- <rule>"`` lines.

**Args**

- **`rule_set`** *(list[str])* — Rule strings to render.

**Returns**

- **`str`** — Newline-joined bullet lines.


### render_rules_md

```python
render_rules_md(rule_set: list[str]) -> str
```

Render a list of rule strings as ``<br>``-joined ``"- <rule>"`` lines for Markdown.

**Args**

- **`rule_set`** *(list[str])* — Rule strings to render.

**Returns**

- **`str`** — ``<br>``-joined bullet lines.


### replace_include_with_file_content

```python
replace_include_with_file_content(text: str) -> str
```

Replace AsciiDoc ``include::`` directives with the content of the referenced file.

Files are resolved relative to the configured ``includes_dir``.  Missing
files are logged and replaced with an HTML comment placeholder.

**Args**

- **`text`** *(str)* — AsciiDoc source that may contain ``include::<path>[]`` directives.

**Returns**

- **`str`** — Source with all ``include::`` directives replaced by file contents.


### asciidoc_to_markdown

```python
asciidoc_to_markdown(value: str) -> str
```

Convert a subset of AsciiDoc syntax to GitHub-flavoured Markdown.

Handles headers, NOTE/IMPORTANT admonitions, source code blocks,
tables (``|===``), unordered/ordered lists, block titles, and
``link:url[text]`` macros.  Unsupported constructs are passed through
with links replaced and trailing whitespace stripped.

**Args**

- **`value`** *(str)* — AsciiDoc source text.

**Returns**

- **`str`** — Markdown-formatted text.


### get_nested

```python
get_nested(obj: Mapping[str, Any] | list, keys: list[str | int], default: Any=None) -> Any
```

Safely traverse a nested mapping / list using a sequence of keys or indices.

**Args**

- **`obj`** *(Mapping | list)* — Root object to traverse.
- **`keys`** *(list[str | int])* — Ordered path of dict keys or list indices.
- **`default`** — Value returned when any key/index is missing or the wrong type.

**Returns**

- **`Any`** — The value at the nested path, or *default* if unreachable.


### render_template

```python
render_template(output_file: Path, template_name: str, baseline: Baseline, b64logo: bytes, pdf_theme: str, html_css: str, logo_path: Path, os_name: str, version_info: dict[str, Any], show_all_tags: bool, custom: bool, template_dir: str, themes_dir: str, logo_dir: str, output_format: str='adoc', language: str='en') -> None
```

Render a Jinja template against *baseline* data and write to *output_file*.

Configures a Jinja ``Environment`` with all mSCP filters, installs
gettext translations for *language*, renders the template, and writes
the result as text.

**Args**

- **`output_file`** *(Path)* — Destination for the rendered output.
- **`template_name`** *(str)* — Filename of the template within *template_dir*.
- **`baseline`** *(Baseline)* — Baseline data model.
- **`b64logo`** *(bytes)* — Base64-encoded logo image bytes.
- **`pdf_theme`** *(str)* — AsciiDoctor-PDF theme filename.
- **`html_css`** *(str)* — CSS filename for HTML output.
- **`logo_path`** *(Path)* — Absolute path to the logo file.
- **`os_name`** *(str)* — Operating system name string.
- **`version_info`** *(dict[str, Any])* — OS/compliance version metadata.
- **`show_all_tags`** *(bool)* — Whether to render all tags in the document.
- **`custom`** *(bool)* — Whether the baseline uses a custom configuration.
- **`template_dir`** *(str)* — Path to the Jinja templates directory.
- **`themes_dir`** *(str)* — Path to the themes/styles directory.
- **`logo_dir`** *(str)* — Path to the images directory.
- **`output_format`** *(str)* — ``"adoc"`` (default) or ``"markdown"``.
- **`language`** *(str)* — BCP-47 language code for gettext lookup. Defaults to ``"en"``.


### generate_documents

```python
generate_documents(spinner: Yaspin, output_file: Path, baseline: Baseline, b64logo: bytes, pdf_theme: str, html_css: str, logo_path: Path, os_name: str, version_info: dict[str, Any], show_all_tags: bool=False, custom: bool=False, output_format: str='adoc', language: str='en') -> None
```

Render guidance documents and, for AsciiDoc output, invoke AsciiDoctor.

Selects standard or custom template/theme directories, calls
`render_template`, then (when *output_format* is ``"adoc"``) runs
``bundle exec asciidoctor`` and ``bundle exec asciidoctor-pdf`` to
produce HTML and PDF output.

**Args**

- **`spinner`** *(Yaspin)* — Spinner for progress feedback.
- **`output_file`** *(Path)* — Destination ``.adoc`` or ``.md`` file.
- **`baseline`** *(Baseline)* — Baseline data model.
- **`b64logo`** *(bytes)* — Base64-encoded logo image bytes.
- **`pdf_theme`** *(str)* — AsciiDoctor-PDF theme filename.
- **`html_css`** *(str)* — CSS filename for HTML output.
- **`logo_path`** *(Path)* — Absolute path to the logo file.
- **`os_name`** *(str)* — Operating system name string.
- **`version_info`** *(dict[str, Any])* — OS/compliance version metadata.
- **`show_all_tags`** *(bool)* — Whether to render all tags. Defaults to ``False``.
- **`custom`** *(bool)* — Whether to use the custom template directory. Defaults to ``False``.
- **`output_format`** *(str)* — ``"adoc"`` (default) or ``"markdown"``.
- **`language`** *(str)* — BCP-47 language code. Defaults to ``"en"``.
