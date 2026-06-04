"""Tests for the experimental ``--pdf-engine typst`` backend.

The PDF bytes themselves are non-deterministic, so we don't golden-file them.
Instead we test the layer that actually holds logic — the pure AsciiDoc->Typst
string transforms in ``documents.py`` — plus one integration test that proves
the converter's output is *valid, compilable* Typst (skipped when the ``typst``
binary is unavailable, so contributors without it still get a green run).

Run just the fast units:   uv run pytest tests/test_typst_backend.py -m "not integration"
Run everything:            uv run pytest tests/test_typst_backend.py
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mscp.generate.guidance_support.documents import (
    asciidoc_to_typst,
    group_ulify_typst,
    render_references_typst,
    render_rules_typst,
    typst_escape,
)


# --------------------------------------------------------------------------- #
# typst_escape — the full escape table (escapes * _ [ ] # $ too, since this is
# used for *literal data* like rule IDs that must not be read as markup).
# --------------------------------------------------------------------------- #
class TestTypstEscape:
    @pytest.mark.parametrize(
        "src,want",
        [
            ("os_sip_enable", r"os\_sip\_enable"),  # rule IDs: underscores are literal
            ("a*b", r"a\*b"),
            ("a[b]", r"a\[b\]"),
            ("a#b", r"a\#b"),
            (r"cost is $5", r"cost is \$5"),
            ("plain text", "plain text"),  # nothing significant -> unchanged
            ("", ""),
            (None, ""),  # None -> "" (guards Jinja passing a missing value)
        ],
    )
    def test_escape(self, src, want):
        assert typst_escape(src) == want

    def test_non_string_is_coerced(self):
        # render_references passes ints/lists through str(); escape must not crash.
        assert typst_escape(42) == "42"


# --------------------------------------------------------------------------- #
# asciidoc_to_typst — prose conversion. Crucially, prose escaping PRESERVES
# * and _ so that *bold*/_italic_ survive, unlike typst_escape above.
# --------------------------------------------------------------------------- #
class TestAsciidocToTypst:
    def test_none_and_empty(self):
        assert asciidoc_to_typst(None) == ""
        assert asciidoc_to_typst("") == ""

    def test_bold_markers_preserved(self):
        # Prose keeps * so Typst still renders bold (regression: escaping these
        # would print literal stars).
        assert asciidoc_to_typst("this is *bold* text") == "this is *bold* text"

    def test_hash_still_escaped_in_prose(self):
        # # is a Typst function sigil and must be escaped even in prose.
        assert asciidoc_to_typst("issue #5 here") == r"issue \#5 here"

    def test_link_macro_becomes_typst_link(self):
        assert (
            asciidoc_to_typst("See link:https://x.com/a[the docs] now")
            == 'See #link("https://x.com/a")[the docs] now'
        )

    def test_bare_url_no_double_wrap(self):
        # Regression: an empty-label link must NOT become #link("#link(...)").
        out = asciidoc_to_typst("https://x.com/a[]")
        assert out == '#link("https://x.com/a")'
        assert "#link(\"#link" not in out

    def test_url_inside_link_is_not_escaped(self):
        # The URL sits in a Typst string literal; underscores there stay literal.
        out = asciidoc_to_typst("link:https://x.com/a_b[lbl]")
        assert "https://x.com/a_b" in out  # not a\_b

    def test_note_admonition(self):
        # NOTE: now renders as a tinted callout via the admonition() helper.
        assert asciidoc_to_typst("NOTE: be careful") == '#admonition("NOTE")[be careful]'

    def test_unordered_list(self):
        assert asciidoc_to_typst("* one\n* two") == "- one\n- two"

    def test_source_block_becomes_raw_fence(self):
        out = asciidoc_to_typst("[source,bash]\n----\necho hi\n----")
        assert out == "```bash\necho hi\n```"

    def test_code_block_contents_left_verbatim(self):
        # Underscores inside code must NOT be escaped (they'd corrupt commands).
        out = asciidoc_to_typst("[source,zsh]\n----\nsudo /usr/bin/foo_bar\n----")
        assert "foo_bar" in out
        assert r"foo\_bar" not in out


# --------------------------------------------------------------------------- #
# Render helpers used directly as Jinja filters.
# --------------------------------------------------------------------------- #
class TestRenderHelpers:
    def test_group_ulify_na_shortcircuits(self):
        assert group_ulify_typst(["N/A"]) == "- N/A"

    def test_group_ulify_sorts_and_bullets(self):
        assert group_ulify_typst(["b", "a"]) == "- a\n- b"

    def test_render_rules_escapes_ids(self):
        assert render_rules_typst(["os_x", "os_y"]) == "- os\\_x\n- os\\_y"

    def test_render_rules_empty(self):
        assert render_rules_typst(None) == ""
        assert render_rules_typst([]) == ""

    def test_render_references_flattens_lists(self):
        assert render_references_typst([{"cce": ["a", "b"]}]) == "- cce: a, b"

    def test_render_references_rejects_non_dict(self):
        with pytest.raises(TypeError):
            render_references_typst(["not a dict"])


# --------------------------------------------------------------------------- #
# Integration: the converter's output must be VALID Typst. Wrap representative
# converted prose in a minimal document and compile it. This catches escaping
# bugs that a pure string-equality assertion would miss.
# --------------------------------------------------------------------------- #
try:
    import typst as _typst_pkg
except ImportError:
    _typst_pkg = None


@pytest.mark.integration
@pytest.mark.skipif(_typst_pkg is None, reason="typst package not installed")
class TestTypstCompiles:
    def _compile(self, body: str, tmp_path: Path) -> Path:
        # typst.compile raises on a compile error, so reaching the return is
        # itself the assertion that the document is valid Typst.
        typ = tmp_path / "doc.typ"
        typ.write_text(body, encoding="utf-8")
        out = tmp_path / "out.pdf"
        _typst_pkg.compile(str(typ), output=str(out), root=str(tmp_path))
        return out

    def test_converted_prose_compiles(self, tmp_path):
        # Feed the converter the kind of AsciiDoc a real rule contains, then
        # prove the result is something typst accepts.
        body = asciidoc_to_typst(
            "Disable *SIP* via link:https://support.apple.com/x[Apple's guide]. "
            "NOTE: the key os_sip_enable controls this.\n"
            "[source,zsh]\n----\n/usr/bin/csrutil status | grep -c 'enabled'\n----"
        )
        assert self._compile(body, tmp_path).exists()

    def test_escaped_rule_id_compiles(self, tmp_path):
        # A rule ID full of underscores must compile as literal text.
        body = typst_escape("os_account_modification_timeout") + "\n"
        assert self._compile(body, tmp_path).exists()


# --------------------------------------------------------------------------- #
# TODO(henry): add the edge cases that matter most to your real baselines.
# Good candidates pulled from actual rule discussion text:
#   - mixed bold + link on one line (*see* link:...[x])
#   - ordered lists (. step one / . step two)
#   - [IMPORTANT] / [WARNING] block admonitions vs inline "NOTE:"
#   - angle-bracket placeholders like <your-org> (escaping of < >)
#   - a real multi-paragraph discussion lifted from mscp/data/rules/*.yaml
# Each should be a one-liner asserting the converted output, ideally paired
# with a compile check in TestTypstCompiles for anything escaping-sensitive.
# --------------------------------------------------------------------------- #
