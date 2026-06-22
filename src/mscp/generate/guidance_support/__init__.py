# generate/guidance/__init__.py
"""Guidance artifact sub-generators used by `generate_guidance`.

Re-exports: `generate_ddm` (DDM JSON/ZIP artifacts), `generate_documents`
(AsciiDoc / PDF / HTML / Markdown), `generate_markdown_tree` (paginated
Markdown tree for static site generators), `generate_excel` (Excel workbook),
`generate_profiles` (configuration profiles), `generate_script` and
`generate_restore_script` (compliance shell scripts), and
`generate_manifest` (JSON manifest).
"""

__all__ = [
    "generate_ddm",
    "generate_documents",
    "generate_markdown_tree",
    "generate_excel",
    "generate_profiles",
    "generate_script",
    "generate_restore_script",
    "generate_manifest",
]


from .ddm import generate_ddm
from .documents import generate_documents
from .markdown_tree import generate_markdown_tree
from .excel import generate_excel
from .profiles import generate_profiles
from .script import generate_script, generate_restore_script
from .manifest import generate_manifest
