#!/usr/bin/env python3
"""Generate Starlight API reference pages from the dev_2.0 branch.

Reads each Python module under ``src/mscp/`` from the ``dev_2.0`` branch via
``git show``, parses it with ``ast``, and emits one Markdown page per module
into ``src/content/docs/api/``. Run from the repository root::

    python3 scripts/gen_api_docs.py

The script has no third-party dependencies; standard library only.
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_BRANCH = "dev_2.0"
# Restrict generation to a single Python (sub)package within the source tree.
SOURCE_PREFIX = "src/mscp/"
# Dotted-name prefix corresponding to SOURCE_PREFIX (e.g. "mscp.classes.").
MODULE_PREFIX = (
    SOURCE_PREFIX.removeprefix("src/").rstrip("/").replace("/", ".") + "."
)
OUTPUT_DIR = REPO_ROOT / "src" / "content" / "docs" / "api"

# Paths (relative to repo root) to exclude from documentation entirely.
# These are internal implementation packages, not public library API.
SKIP_PATHS = {
    "src/mscp/generate",
    "src/mscp/admin_utils",
    "src/mscp/cli.py",
}


def run_git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def list_python_files() -> list[str]:
    out = run_git("ls-tree", "-r", SOURCE_BRANCH, "--name-only")
    files: list[str] = []
    for line in out.splitlines():
        rel = line.strip()
        if not (rel.startswith(SOURCE_PREFIX) and rel.endswith(".py")):
            continue
        # Astro excludes underscore-prefixed slugs from routing, so skip
        # entry-point shims like __main__.py that have no API surface anyway.
        if Path(rel).name == "__main__.py":
            continue
        if any(rel == p or rel.startswith(p + "/") for p in SKIP_PATHS):
            continue
        files.append(rel)
    return sorted(files)


def read_file(path: str) -> str:
    return run_git("show", f"{SOURCE_BRANCH}:{path}")


@dataclass
class FunctionDoc:
    name: str
    signature: str
    docstring: str | None
    decorators: list[str] = field(default_factory=list)
    is_async: bool = False


@dataclass
class ClassDoc:
    name: str
    bases: list[str]
    docstring: str | None
    methods: list[FunctionDoc] = field(default_factory=list)


@dataclass
class ModuleDoc:
    rel_path: str  # e.g. "macsecurityrule.py" (relative to SOURCE_PREFIX)
    module_dotted: str  # e.g. "mscp.classes.macsecurityrule"
    module_docstring: str | None
    functions: list[FunctionDoc]
    classes: list[ClassDoc]
    exports: list[str]  # __all__, if defined

    @property
    def is_init(self) -> bool:
        return Path(self.rel_path).name == "__init__.py"


def is_public(name: str) -> bool:
    if name == "__init__":
        return True
    return not name.startswith("_")


def format_signature(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = ast.unparse(func.args)
    if func.returns is not None:
        return f"{func.name}({args}) -> {ast.unparse(func.returns)}"
    return f"{func.name}({args})"


def extract_decorators(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [ast.unparse(d) for d in func.decorator_list]


def parse_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> FunctionDoc | None:
    if not is_public(node.name):
        return None
    return FunctionDoc(
        name=node.name,
        signature=format_signature(node),
        docstring=ast.get_docstring(node),
        decorators=extract_decorators(node),
        is_async=isinstance(node, ast.AsyncFunctionDef),
    )


def parse_class(node: ast.ClassDef) -> ClassDoc | None:
    if not is_public(node.name):
        return None
    methods: list[FunctionDoc] = []
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            method = parse_function(item)
            if method is not None:
                methods.append(method)
    return ClassDoc(
        name=node.name,
        bases=[ast.unparse(b) for b in node.bases],
        docstring=ast.get_docstring(node),
        methods=methods,
    )


def extract_dunder_all(tree: ast.Module) -> list[str]:
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__all__":
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    return [
                        elt.value
                        for elt in node.value.elts
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                    ]
    return []


def parse_module(rel_path: str, source: str) -> ModuleDoc:
    tree = ast.parse(source)
    exports = extract_dunder_all(tree)
    exports_set = set(exports)  # non-empty only when __all__ is defined

    functions: list[FunctionDoc] = []
    classes: list[ClassDoc] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if exports_set and node.name not in exports_set:
                continue
            func = parse_function(node)
            if func is not None:
                functions.append(func)
        elif isinstance(node, ast.ClassDef):
            if exports_set and node.name not in exports_set:
                continue
            cls = parse_class(node)
            if cls is not None:
                classes.append(cls)

    package_rel = rel_path[len(SOURCE_PREFIX):]  # e.g. "macsecurityrule.py"
    dotted = MODULE_PREFIX + package_rel.removesuffix(".py").replace("/", ".")
    if dotted.endswith(".__init__"):
        dotted = dotted.removesuffix(".__init__")
    dotted = dotted.rstrip(".")

    return ModuleDoc(
        rel_path=package_rel,
        module_dotted=dotted,
        module_docstring=ast.get_docstring(tree),
        functions=functions,
        classes=classes,
        exports=exports,
    )


# ---- Markdown rendering ---------------------------------------------------


def md_escape_frontmatter(text: str) -> str:
    return text.replace('"', '\\"').replace("\n", " ").strip()


def first_sentence(text: str | None) -> str:
    if not text:
        return ""
    cleaned = text.strip().split("\n\n", 1)[0]
    cleaned = " ".join(cleaned.split())
    for sep in (". ", "! ", "? "):
        if sep in cleaned:
            return cleaned.split(sep, 1)[0] + sep.strip()
    return cleaned


# Google-style docstring section headers we know how to render.
# Listed in lowercase for case-insensitive matching; canonical capitalisation
# is preserved when emitting the section header.
_LIST_SECTIONS = {
    "args", "arguments", "parameters", "params",
    "attributes", "attribute",
    "returns", "return",
    "yields", "yield",
    "raises", "raise", "exceptions", "except",
    "class methods", "methods",
    "side effects",
}
_BLOCK_SECTIONS = {
    "example", "examples",
    "note", "notes",
    "warning", "warnings",
    "see also", "references",
    "todo",
}
_KNOWN_SECTIONS = _LIST_SECTIONS | _BLOCK_SECTIONS

_SECTION_HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z ]*):\s*$")
_ITEM_RE = re.compile(
    r"^(?P<name>\S+?)\s*(?:\((?P<type>[^)]+)\))?\s*:\s*(?P<desc>.*)$"
)


def _split_into_items(body: str) -> list[str]:
    """Group lines under a Google-style section into individual items.

    Items are flush-left; continuation text is indented further. Returns a
    list of single-line item strings (continuation lines collapsed with
    spaces), preserving order.
    """
    items: list[list[str]] = []
    current: list[str] = []
    for line in body.split("\n"):
        if not line.strip():
            if current:
                current.append("")
            continue
        if line[0] not in (" ", "\t"):
            if current:
                items.append(current)
            current = [line.rstrip()]
        else:
            current.append(line.strip())

    if current:
        items.append(current)

    flattened: list[str] = []
    for item in items:
        joined = " ".join(part for part in item if part)
        if joined:
            flattened.append(joined)
    return flattened


def _render_list_section(header: str, body: str) -> str:
    items = _split_into_items(body)
    if not items:
        return f"**{header}**"

    bullets: list[str] = []
    for item in items:
        # Some docstrings already prefix items with "- " or "* " — drop it
        # so we don't end up with "- - foo".
        if item[:2] in ("- ", "* "):
            item = item[2:]
        m = _ITEM_RE.match(item)
        if m:
            name = m.group("name")
            type_ = m.group("type")
            desc = m.group("desc")
            type_part = f" *({type_})*" if type_ else ""
            desc_part = f" — {desc}" if desc else ""
            bullets.append(f"- **`{name}`**{type_part}{desc_part}")
        else:
            bullets.append(f"- {item}")
    return f"**{header}**\n\n" + "\n".join(bullets)


def _render_block_section(header: str, body: str) -> str:
    body = body.rstrip()
    if not body:
        return f"**{header}**"
    lower = header.lower()
    if lower in ("example", "examples"):
        return f"**{header}**\n\n```python\n{body}\n```"
    quoted = "\n".join(f"> {line}" if line else ">" for line in body.split("\n"))
    return f"**{header}**\n\n{quoted}"


def render_docstring(text: str | None) -> str:
    """Render a docstring as Markdown.

    Recognises Google-style sections (``Args:``, ``Returns:``, ``Attributes:``
    etc.) and emits them as bullet lists or block callouts so they don't
    collapse into a single paragraph. Free-form prose passes through.
    """
    if not text:
        return ""

    cleaned = textwrap.dedent(text).strip("\n")
    lines = cleaned.split("\n")

    blocks: list[str] = []
    paragraph: list[str] = []

    def flush_paragraph() -> None:
        if paragraph:
            blocks.append("\n".join(paragraph).strip())
            paragraph.clear()

    i = 0
    while i < len(lines):
        line = lines[i]
        m = _SECTION_HEADER_RE.match(line)
        if m and m.group(1).strip().lower() in _KNOWN_SECTIONS:
            flush_paragraph()
            header = m.group(1).strip()
            i += 1
            body_lines: list[str] = []
            while i < len(lines):
                bl = lines[i]
                if bl.strip() == "":
                    # Blank line ends the section unless the next non-blank
                    # line is still indented (i.e. a continuation).
                    j = i + 1
                    while j < len(lines) and lines[j].strip() == "":
                        j += 1
                    if j < len(lines) and lines[j][:1] in (" ", "\t"):
                        body_lines.append("")
                        i += 1
                        continue
                    break
                if bl[:1] not in (" ", "\t"):
                    break
                body_lines.append(bl)
                i += 1

            body = textwrap.dedent("\n".join(body_lines)).strip("\n")
            if header.lower() in _LIST_SECTIONS:
                blocks.append(_render_list_section(header, body))
            else:
                blocks.append(_render_block_section(header, body))
        elif line.strip() == "":
            flush_paragraph()
            i += 1
        else:
            paragraph.append(line)
            i += 1

    flush_paragraph()
    return "\n\n".join(b for b in blocks if b) + "\n"


def render_function(func: FunctionDoc, heading_level: int) -> str:
    h = "#" * heading_level
    prefix = "async " if func.is_async else ""
    parts: list[str] = [
        f"{h} {func.name}",
        "",
        "```python",
        f"{prefix}{func.signature}",
        "```",
        "",
    ]
    _IMPLICIT_DECORATORS = {"classmethod", "staticmethod", "property"}
    extra_decos = [
        d for d in func.decorators
        if d not in _IMPLICIT_DECORATORS and not d.endswith((".setter", ".deleter"))
    ]
    if extra_decos:
        decos = ", ".join(f"`@{d}`" for d in extra_decos)
        parts.append(f"*Decorators:* {decos}")
        parts.append("")
    if func.docstring:
        parts.append(render_docstring(func.docstring))
    return "\n".join(parts).rstrip() + "\n"


def _method_category(method: FunctionDoc) -> str:
    for d in method.decorators:
        if d == "classmethod":
            return "class_methods"
        if d == "staticmethod":
            return "static_methods"
        if d == "property" or d.endswith(".setter") or d.endswith(".deleter"):
            return "properties"
    if method.name == "__init__":
        return "constructor"
    return "methods"


_METHOD_SECTION_ORDER = [
    ("constructor", "Constructor"),
    ("class_methods", "Class Methods"),
    ("static_methods", "Static Methods"),
    ("properties", "Properties"),
    ("methods", "Methods"),
]


def render_class(cls: ClassDoc, heading_level: int) -> str:
    h = "#" * heading_level
    bases = f"({', '.join(cls.bases)})" if cls.bases else ""
    parts: list[str] = [
        f"{h} {cls.name}",
        "",
        "```python",
        f"class {cls.name}{bases}",
        "```",
        "",
    ]
    if cls.docstring:
        parts.append(render_docstring(cls.docstring))

    if cls.methods:
        buckets: dict[str, list[FunctionDoc]] = {key: [] for key, _ in _METHOD_SECTION_ORDER}
        for method in cls.methods:
            buckets[_method_category(method)].append(method)

        for key, label in _METHOD_SECTION_ORDER:
            if not buckets[key]:
                continue
            parts.append("")
            parts.append(f"{'#' * (heading_level + 1)} {label}")
            parts.append("")
            for method in buckets[key]:
                parts.append(render_function(method, heading_level + 2))

    return "\n".join(parts).rstrip() + "\n"


def render_module(module: ModuleDoc) -> str:
    description = first_sentence(module.module_docstring) or (
        f"API reference for `{module.module_dotted}`."
    )
    # Top-level package index gets the group label as its title.
    top_level_dotted = MODULE_PREFIX.rstrip(".")
    title = (
        "mSCP 2.0 API Reference"
        if module.module_dotted == top_level_dotted
        else module.module_dotted
    )

    # Groups (directory index pages) sort before flat module pages in the sidebar.
    sidebar_order = 0 if module.is_init else 1

    parts: list[str] = [
        "---",
        f"title: {title}",
        f'description: "{md_escape_frontmatter(description)}"',
        "sidebar:",
        f"  order: {sidebar_order}",
        "---",
        "",
        f"> Source: [`{SOURCE_PREFIX}{module.rel_path}`](https://github.com/usnistgov/macos_security/blob/{SOURCE_BRANCH}/{SOURCE_PREFIX}{module.rel_path})",
        "",
    ]
    if module.module_docstring:
        parts.append(render_docstring(module.module_docstring))
        parts.append("")

    if module.exports:
        parts.append("## Re-exports (`__all__`)")
        parts.append("")
        parts.append(", ".join(f"`{name}`" for name in module.exports))
        parts.append("")

    if module.classes:
        parts.append("## Classes")
        parts.append("")
        for cls in module.classes:
            parts.append(render_class(cls, heading_level=3))
            parts.append("")

    if module.functions:
        parts.append("## Functions")
        parts.append("")
        for func in module.functions:
            parts.append(render_function(func, heading_level=3))
            parts.append("")

    if not (module.classes or module.functions or module.module_docstring or module.exports):
        parts.append("_This module exposes no public API surface._")
        parts.append("")

    return "\n".join(parts).rstrip() + "\n"


def output_path_for(module: ModuleDoc) -> Path:
    rel = Path(module.rel_path)
    if rel.name == "__init__.py":
        # Subpackage index page lives at <pkg>/index.md
        if rel.parent == Path("."):
            return OUTPUT_DIR / "index.md"
        return OUTPUT_DIR / rel.parent / "index.md"
    return OUTPUT_DIR / rel.with_suffix(".md")


def write_landing_page() -> None:
    """Augment the top-level index page with a list of sibling modules."""
    landing = OUTPUT_DIR / "index.md"
    module_links = "\n".join(
        f"- [`{p.stem}`]({p.stem}/)"
        for p in sorted(OUTPUT_DIR.glob("*.md"))
        if p.name != "index.md"
    )
    addition = "\n## Modules\n\n" + module_links + "\n" if module_links else ""

    if landing.exists():
        existing = landing.read_text().rstrip() + "\n"
        if "## Modules" in existing or not addition:
            return
        landing.write_text(existing + addition)
        return

    landing.write_text(
        "---\n"
        "title: mSCP 2.0 API Reference\n"
        'description: "Python API reference for the mscp 2.0 classes package, generated from docstrings on the dev_2.0 branch."\n'
        "---\n\n"
        f"Reference for the `{MODULE_PREFIX.rstrip('.')}` package on the "
        f"`{SOURCE_BRANCH}` branch. These pages are generated directly from "
        "the source docstrings — run `python3 scripts/gen_api_docs.py` to "
        "regenerate.\n"
        + addition
    )


def main() -> int:
    if not (REPO_ROOT / ".git").exists():
        print(f"error: {REPO_ROOT} is not a git repository", file=sys.stderr)
        return 1

    try:
        files = list_python_files()
    except subprocess.CalledProcessError as exc:
        print(f"error: failed to list files on {SOURCE_BRANCH}: {exc.stderr}", file=sys.stderr)
        return 1

    if not files:
        print(f"error: no Python files found under {SOURCE_PREFIX} on {SOURCE_BRANCH}", file=sys.stderr)
        return 1

    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True)

    written = 0
    for rel in files:
        try:
            source = read_file(rel)
        except subprocess.CalledProcessError as exc:
            print(f"warning: could not read {rel}: {exc.stderr}", file=sys.stderr)
            continue
        try:
            module = parse_module(rel, source)
        except SyntaxError as exc:
            print(f"warning: skipping {rel} (syntax error: {exc})", file=sys.stderr)
            continue

        out_path = output_path_for(module)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(render_module(module))
        written += 1
        print(f"wrote {out_path.relative_to(REPO_ROOT)}")

    write_landing_page()
    print(f"\nGenerated {written} module pages in {OUTPUT_DIR.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
