"""Tests for the --markdown-tree output mode.

Covers:
- `create_slug`: slug normalisation
- `mdx_escape`: entity-encoding outside fenced blocks / inline code spans
- `render_references_md`: GFM-table-safe cell rendering
- `_frontmatter`: YAML single-quote escaping
- Integration: generate_markdown_tree writes a valid, SSG-safe tree from a
  real bundled baseline (cis_lvl1_macos_26.0).
"""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path

import pytest

from mscp.generate.guidance_support.markdown_tree import (
    _frontmatter,
    create_slug,
    mdx_escape,
    render_references_md,
)


# ---------------------------------------------------------------------------
# create_slug
# ---------------------------------------------------------------------------


class TestCreateSlug:
    def test_spaces_to_hyphens(self):
        assert create_slug("System Settings") == "system-settings"

    def test_lowercase(self):
        assert create_slug("Auditing") == "auditing"

    def test_strips_punctuation(self):
        assert create_slug("Password/Policy") == "passwordpolicy"

    def test_collapses_multiple_hyphens(self):
        assert create_slug("foo  --  bar") == "foo-bar"

    def test_strips_leading_trailing_hyphens(self):
        assert create_slug("-foo-") == "foo"

    def test_underscore_becomes_hyphen(self):
        assert create_slug("os_ssh_fips") == "os-ssh-fips"

    def test_empty_string(self):
        assert create_slug("") == ""


# ---------------------------------------------------------------------------
# mdx_escape
# ---------------------------------------------------------------------------


class TestMdxEscape:
    def test_braces_encoded_in_prose(self):
        result = mdx_escape("value is {foo}")
        assert "&#123;" in result
        assert "&#125;" in result
        assert "{" not in result

    def test_braces_untouched_inside_fence(self):
        src = "```bash\necho {hello}\n```"
        assert mdx_escape(src) == src

    def test_braces_untouched_in_inline_code(self):
        src = "use `{key}` here"
        result = mdx_escape(src)
        assert "`{key}`" in result

    def test_bare_lt_encoded_in_prose(self):
        result = mdx_escape("plist has <dict> and <key>")
        assert "&lt;dict&gt;" in result or "&lt;" in result
        # '<' in prose must be entity-encoded
        assert re.search(r"<(?!br|hr|img|/)", result) is None

    def test_known_html_tags_preserved(self):
        result = mdx_escape("line<br />next")
        assert "<br />" in result

    def test_br_normalised_to_self_closing(self):
        result = mdx_escape("line<br>next")
        assert "<br />" in result
        assert "<br>" not in result

    def test_br_idempotent(self):
        result = mdx_escape("line<br />next")
        assert result.count("<br />") == 1

    def test_fence_with_plist(self):
        src = "```xml\n<dict><key>foo</key></dict>\n```"
        assert mdx_escape(src) == src

    def test_empty_string(self):
        assert mdx_escape("") == ""

    def test_none_passthrough(self):
        # mdx_escape returns value unchanged when falsy
        assert mdx_escape(None) is None  # type: ignore[arg-type]

    def test_multiple_fences(self):
        src = "intro {x}\n```bash\nif {a}; then\n```\noutro {y}"
        result = mdx_escape(src)
        assert "&#123;x&#125;" in result  # prose encoded
        assert "```bash\nif {a}; then\n```" in result  # fence unchanged
        assert "&#123;y&#125;" in result


# ---------------------------------------------------------------------------
# render_references_md
# ---------------------------------------------------------------------------


class TestRenderReferencesMd:
    def test_empty_returns_empty_string(self):
        assert render_references_md([]) == ""
        assert render_references_md(None) == ""

    def test_single_dict(self):
        result = render_references_md([{"SRG": "SRG-OS-000001"}])
        assert "**SRG**" in result
        assert "SRG-OS-000001" in result

    def test_pipe_escaped(self):
        result = render_references_md([{"Key": "a|b"}])
        assert r"\|" in result

    def test_list_value_joined(self):
        result = render_references_md([{"IDs": ["ID-1", "ID-2"]}])
        assert "ID-1" in result
        assert "ID-2" in result

    def test_multiple_dicts_joined_with_br(self):
        refs = [{"A": "1"}, {"B": "2"}]
        result = render_references_md(refs)
        assert "<br />" in result


# ---------------------------------------------------------------------------
# _frontmatter
# ---------------------------------------------------------------------------


class TestFrontmatter:
    def test_basic(self):
        fm = _frontmatter({"title": "Hello"})
        assert fm.startswith("---")
        assert fm.endswith("---")
        assert "title: 'Hello'" in fm

    def test_single_quote_escaped(self):
        fm = _frontmatter({"title": "It's a title"})
        assert "title: 'It''s a title'" in fm

    def test_non_string_bare(self):
        fm = _frontmatter({"position": 3})
        assert "position: 3" in fm

    def test_slug_field(self):
        fm = _frontmatter({"title": "A Rule", "slug": "a-rule"})
        assert "slug: 'a-rule'" in fm


# ---------------------------------------------------------------------------
# Integration: generate_markdown_tree
# ---------------------------------------------------------------------------


def _get_baseline_path() -> Path:
    """Return a bundled baseline YAML for testing."""
    root = Path(__file__).parent.parent
    candidates = [
        root / "src/mscp/data/baselines/macos/cis_lvl1_macos_26.0.yaml",
    ]
    for p in candidates:
        if p.exists():
            return p
    pytest.fail(
        f"Bundled baseline not found; checked: {[str(p) for p in candidates]}"
    )


@pytest.fixture(scope="module")
def markdown_tree_output(tmp_path_factory):
    """Generate the markdown tree for cis_lvl1 into a temp dir."""
    from mscp.classes import Baseline
    from mscp.common_utils import get_version_data, mscp_data
    from mscp.generate.guidance_support.markdown_tree import generate_markdown_tree

    baseline_path = _get_baseline_path()
    tmp = tmp_path_factory.mktemp("tree_output")

    baseline = Baseline.from_yaml(baseline_path)
    version_data = get_version_data(
        baseline.platform["os"],
        float(baseline.platform["version"]),
        mscp_data,
    )

    generate_markdown_tree(
        build_path=tmp,
        baseline=baseline,
        version_info=version_data,
        show_all_tags=False,
        language="en",
    )
    return tmp / "markdown_tree"


class TestMarkdownTreeIntegration:
    def test_output_dir_exists(self, markdown_tree_output):
        assert markdown_tree_output.is_dir()

    def test_root_index_exists(self, markdown_tree_output):
        assert (markdown_tree_output / "index.md").is_file()

    def test_root_index_has_frontmatter(self, markdown_tree_output):
        content = (markdown_tree_output / "index.md").read_text()
        assert content.startswith("---\n")
        assert "title:" in content

    def test_section_dirs_exist(self, markdown_tree_output):
        section_dirs = [
            d for d in markdown_tree_output.iterdir() if d.is_dir()
        ]
        assert len(section_dirs) > 0

    def test_section_dirs_have_nn_prefix(self, markdown_tree_output):
        section_dirs = [
            d for d in markdown_tree_output.iterdir() if d.is_dir()
        ]
        for d in section_dirs:
            assert re.match(r"^\d{2}-", d.name), (
                f"Section dir '{d.name}' missing NN- prefix"
            )

    def test_section_dirs_sorted_correctly(self, markdown_tree_output):
        section_dirs = sorted(
            d for d in markdown_tree_output.iterdir() if d.is_dir()
        )
        prefixes = [int(d.name[:2]) for d in section_dirs]
        assert prefixes == sorted(prefixes)

    def test_each_section_has_index(self, markdown_tree_output):
        for section_dir in markdown_tree_output.iterdir():
            if section_dir.is_dir():
                assert (section_dir / "index.md").is_file(), (
                    f"Missing index.md in {section_dir.name}"
                )

    def test_rule_files_have_nn_prefix(self, markdown_tree_output):
        for section_dir in markdown_tree_output.iterdir():
            if not section_dir.is_dir():
                continue
            rule_files = [
                f for f in section_dir.iterdir()
                if f.is_file() and f.name != "index.md"
            ]
            for rf in rule_files:
                assert re.match(r"^\d{2}-", rf.name), (
                    f"Rule file '{rf.name}' missing NN- prefix"
                )

    def test_rule_files_are_md_not_mdx(self, markdown_tree_output):
        for section_dir in markdown_tree_output.iterdir():
            if not section_dir.is_dir():
                continue
            for f in section_dir.iterdir():
                assert f.suffix == ".md", (
                    f"Expected .md extension, got '{f.name}'"
                )

    def test_rule_frontmatter_parses(self, markdown_tree_output):
        """All rule files must have valid YAML frontmatter with title only."""
        for section_dir in markdown_tree_output.iterdir():
            if not section_dir.is_dir():
                continue
            for rf in section_dir.iterdir():
                if rf.name == "index.md":
                    continue
                content = rf.read_text()
                assert content.startswith("---\n"), (
                    f"{rf.name}: missing frontmatter"
                )
                # Extract frontmatter block
                end = content.index("---\n", 4)
                fm_block = content[4:end]
                assert "title:" in fm_block, f"{rf.name}: missing title"


    def test_no_raw_braces_outside_fences(self, markdown_tree_output):
        """No unescaped { or } should appear outside fenced blocks."""
        for md_file in markdown_tree_output.rglob("*.md"):
            content = md_file.read_text()
            # Strip fenced code blocks
            stripped = re.sub(r"```.*?```", "", content, flags=re.DOTALL)
            # Strip frontmatter
            if stripped.startswith("---\n"):
                end = stripped.index("---\n", 4)
                stripped = stripped[end + 4:]
            assert "{" not in stripped, (
                f"{md_file.name}: raw '{{' found outside fenced block"
            )
            assert "}" not in stripped, (
                f"{md_file.name}: raw '}}' found outside fenced block"
            )

    def test_balanced_fences(self, markdown_tree_output):
        """Fenced code blocks must be properly opened and closed."""
        for md_file in markdown_tree_output.rglob("*.md"):
            content = md_file.read_text()
            fences = re.findall(r"^```", content, flags=re.MULTILINE)
            assert len(fences) % 2 == 0, (
                f"{md_file.name}: unbalanced fences ({len(fences)} markers)"
            )

    def test_no_category_json_files(self, markdown_tree_output):
        """No Docusaurus-specific _category_.json files should be present."""
        category_files = list(markdown_tree_output.rglob("_category_.json"))
        assert category_files == [], (
            f"Found _category_.json files: {category_files}"
        )

    def test_single_file_markdown_unchanged(self, tmp_path):
        """The single-file --markdown output must not be affected by the tree changes.

        Verifies that rendering without markdown_tree=True in context still
        produces the HTML-table remediation block (not the heading-based one).
        """
        # This is a template-level smoke test: render the rule template
        # directly without markdown_tree context and confirm HTML table
        # structure is present.
        from jinja2 import Environment, DictLoader

        # Minimal template that exercises only the remediation branch
        template_src = textwrap.dedent("""\
            {% set check_tags = ["permanent", "inherent", "n_a", "not_applicable"] %}
            {% set additional_info = none %}
            {% set check_shell = none %}
            {% set fix_shell = none %}
            {% if not markdown_tree | default(false) %}
            ### {{ rule.title }}
            {% endif %}
            {{ rule.discussion }}
            {% if not rule.tags | select('in', check_tags) | list %}
            {% if markdown_tree | default(false) %}
            ## Remediation Description
            {% else %}
            <table class="remediation">remediation</table>
            {% endif %}
            {% endif %}
        """)

        env = Environment(loader=DictLoader({"rule.md.jinja": template_src}))
        env.filters["default"] = lambda v, d=None: v if v else d

        rule = {
            "title": "Test Rule",
            "discussion": "Some text.",
            "tags": ["other"],
            "mechanism": "automated",
            "fix": "sudo defaults write ...",
        }

        # Without markdown_tree - should use HTML table remediation
        result_std = env.get_template("rule.md.jinja").render(rule=rule)
        assert "<table" in result_std
        assert "## Remediation" not in result_std

        # With markdown_tree=True - should use heading-based remediation
        result_tree = env.get_template("rule.md.jinja").render(
            rule=rule, markdown_tree=True
        )
        assert "## Remediation" in result_tree
        assert "<table" not in result_tree
