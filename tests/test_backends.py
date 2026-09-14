"""Tests for the experimental Ruby-free backends: ``--pdf-engine typst`` and
``--html-engine python``.

The PDF/HTML bytes themselves are non-deterministic or large, so we don't
golden-file them.  Instead we test the layer that actually holds logic — the
pure AsciiDoc->Typst and AsciiDoc->HTML string transforms in ``documents.py`` —
plus one integration test that proves the typst converter's output is *valid,
compilable* Typst (skipped when the ``typst`` package is unavailable, so
contributors without it still get a green run).

Run just the fast units:   uv run --extra dev pytest tests/test_backends.py -m "not integration"
Run everything:            uv run --extra dev pytest tests/test_backends.py
"""

from __future__ import annotations

import sys
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

import pytest

from mscp.generate.guidance_support.documents import (
    _generate_typst_pdf,
    _parse_asciidoc_table,
    _render_table_html,
    _render_table_typst,
    _table_colspecs,
    _table_colwidths,
    asciidoc_to_html,
    asciidoc_to_markdown,
    asciidoc_to_typst,
    group_ulify_typst,
    render_references_html,
    render_references_typst,
    render_rules_html,
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
# Shared `|===` PSV table parser — structure-only tests. This is the layer
# all three converters (typst/html/markdown) build their table rendering on,
# so bugs here would silently corrupt every output format at once.
# --------------------------------------------------------------------------- #
class TestTableColspecs:
    def test_style_letters_extracted(self):
        # "15%h" / "85%a" -> the trailing letter is the AsciiDoctor cell style.
        assert _table_colspecs('cols="15%h, 85%a"') == ["h", "a"]

    def test_width_only_columns_default_to_d(self):
        # "3,7" are pure relative widths, no style letter -> literal/folded.
        assert _table_colspecs('cols="3,7"') == ["d", "d"]

    def test_no_cols_attribute_returns_empty(self):
        assert _table_colspecs("") == []
        assert _table_colspecs("%header") == []


class TestTableColwidths:
    def test_percentage_widths_extracted(self):
        assert _table_colwidths('cols="15%h, 85%a"') == [15.0, 85.0]

    def test_bare_relative_weights_extracted(self):
        # AsciiDoctor treats "3,7" the same as "30%,70%" -- proportional to
        # the sum, not literal percentages.
        assert _table_colwidths('cols="3,7"') == [3.0, 7.0]

    def test_column_with_no_leading_number_defaults_to_weight_one(self):
        assert _table_colwidths('cols="h, 85%a"') == [1.0, 85.0]

    def test_no_cols_attribute_returns_empty(self):
        assert _table_colwidths("") == []


class TestParseAsciidocTable:
    def test_two_column_label_value_table(self):
        # Mirrors supplemental_cis_manual_27.yaml's discussion table: col 0
        # is a plain header-style label, col 1 is AsciiDoc-style ("a") prose.
        lines = [
            '[cols="15%h, 85%a"]',
            "|===",
            "|Section",
            "|System Settings",
            "",
            "|Recommendations",
            "|item one +",
            "item two",
            "|===",
        ]
        rows, header_row, end_i = _parse_asciidoc_table(lines, 1, 'cols="15%h, 85%a"')

        assert header_row is False
        assert lines[end_i] == "|==="  # stops ON the closing delimiter, doesn't consume it
        assert rows == [
            [
                {"style": "h", "text": "Section"},
                {"style": "a", "text": "System Settings"},
            ],
            [
                {"style": "h", "text": "Recommendations"},
                {"style": "a", "text": "item one +\nitem two"},
            ],
        ]

    def test_header_row_and_style_resolution(self):
        # Mirrors supplemental_smartcard.yaml: a `%header` row, alignment-only
        # prefixes (`<.^`, `^.^`) that must fall back to the column's default
        # style, and one cell with an explicit `a|` override even though its
        # column has no style letter of its own.
        lines = [
            '[%header,cols="2,1,7"]',
            "|===",
            "|Key",
            "|Type",
            "|Value",
            "",
            "<.^|userPairing",
            "^.^|bool",
            "a|Valid values:",
            "",
            "- 0: off",
            "|===",
        ]
        rows, header_row, _ = _parse_asciidoc_table(lines, 1, '%header,cols="2,1,7"')

        assert header_row is True
        assert [c["style"] for c in rows[0]] == ["d", "d", "d"]  # no letters in "2,1,7"
        key, type_, value = rows[1]
        assert key == {"style": "d", "text": "userPairing"}  # "<.^" is alignment-only
        assert type_ == {"style": "d", "text": "bool"}  # "^.^" is alignment-only
        assert value["style"] == "a"  # "a|" is an explicit override
        assert value["text"] == "Valid values:\n\n- 0: off"  # inner blank line preserved

    def test_bare_table_with_no_attribute_line_defaults_to_one_column(self):
        lines = ["|===", "|only cell", "|==="]
        rows, header_row, _ = _parse_asciidoc_table(lines, 0, "")

        assert header_row is False
        assert rows == [[{"style": "d", "text": "only cell"}]]


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

    def test_balanced_bold_and_italic_preserved(self):
        assert asciidoc_to_typst("the _MUST_ be *bold*") == "the _MUST_ be *bold*"

    def test_lone_star_is_escaped(self):
        # Regression (800-53r5_moderate): a lone "*" from a regex/example must be
        # escaped, not left as an unclosed Typst strong delimiter.
        assert asciidoc_to_typst("regex .*[A-Z] here") == r"regex .\*\[A-Z\] here"

    def test_triple_star_artifact_is_escaped(self):
        out = asciidoc_to_typst("***Enforcement actions")
        assert out == r"\*\*\*Enforcement actions"

    def test_brackets_escaped_outside_links(self):
        assert asciidoc_to_typst("array[0] and [x]") == r"array\[0\] and \[x\]"

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

    def test_table_becomes_table_call(self):
        src = '[cols="15%h, 85%a"]\n|===\n|Section\n|System Settings\n|==='
        out = asciidoc_to_typst(src)
        assert out.startswith("#table(")
        # Column proportions from "15%h, 85%a" carry through as Typst `fr` units.
        assert "columns: (15fr, 85fr)" in out
        assert "[Section]" in out
        assert "[System Settings]" in out

    def test_table_without_width_hints_falls_back_to_bare_column_count(self):
        # A width-only "cols=" spec ("3,7" -- no %/letter) still yields
        # explicit widths; a table with no cols= attribute at all has none,
        # so it falls back to a plain column count.
        rows = [[{"style": "d", "text": "a"}, {"style": "d", "text": "b"}]]
        out = _render_table_typst(rows, header_row=False, colwidths=None)
        assert "columns: 2," in out

    def test_table_header_row_uses_table_header(self):
        src = '[%header,cols="3,7"]\n|===\n^.^|Port\n^.^|Service\n\n|548\n|AFP\n|==='
        out = asciidoc_to_typst(src)
        assert "table.header([Port], [Service])" in out
        # The header cells must not also appear as an ordinary data row.
        assert out.count("[Port]") == 1

    def test_table_cell_hard_break_becomes_backslash(self):
        src = '[cols="15%h, 85%a"]\n|===\n|Label\n|first +\nsecond\n|==='
        out = asciidoc_to_typst(src)
        assert "first \\\nsecond" in out

    def test_table_cell_trailing_hard_break_has_no_dangling_backslash(self):
        # Regression: a " +" on the LAST line of a cell (nothing follows it)
        # must not leave a trailing "\" immediately before the closing "]" --
        # that is a dangling/invalid line-continuation and fails to compile.
        src = '[cols="15%h, 85%a"]\n|===\n|Label\n|only line +\n|==='
        out = asciidoc_to_typst(src)
        assert "[only line]" in out
        assert "\\]" not in out


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
# converted prose in a minimal document and compile it via the typst package.
# This catches escaping bugs that a pure string-equality assertion would miss.
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

    @pytest.mark.parametrize(
        "src",
        [
            "***Enforcement actions are listed here",  # 800-53: triple-star artifact
            r"complexity ^(?=.*[A-Z])(?=.*[a-z]).*\$",  # 800-53: regex with lone *
            "Examples include: ~ ! @ # $ % ^ *.",  # 800-53: trailing lone *
        ],
    )
    def test_unbalanced_delimiters_compile(self, src, tmp_path):
        # Regression: real 800-53r5_moderate discussion text that used to emit
        # an "unclosed delimiter" and fail to compile.
        assert self._compile(asciidoc_to_typst(src) + "\n", tmp_path).exists()

    def test_label_value_table_compiles(self, tmp_path):
        # supplemental_cis_manual_27.yaml's shape: a 2-col table whose value
        # column is a `+`-continued multi-line ("a"-style) cell, where every
        # line -- including the last -- ends in " +".
        src = (
            '[cols="15%h, 85%a"]\n'
            "|===\n"
            "|Section\n"
            "|System Settings\n"
            "\n"
            "|Recommendations\n"
            "|2.1.1.1 Audit iCloud Passwords & Keychain +\n"
            "2.1.1.2 Audit iCloud Drive +\n"
            "2.1.2 Audit App Store Password Settings +\n"
            "|===\n"
        )
        body = asciidoc_to_typst(src)
        assert self._compile(body, tmp_path).exists()

    def test_header_row_table_compiles(self, tmp_path):
        # supplemental_firewall_pf.yaml's shape: %header + alignment-prefixed
        # header cells, plain data cells with commas in them.
        src = (
            '[%header,width="100%",cols="3,7"]\n'
            "|===\n"
            "^.^|Port\n"
            "^.^|Service\n"
            "\n"
            "|20, 21\n"
            "|File Transfer Protocol (FTP)\n"
            "|===\n"
        )
        body = asciidoc_to_typst(src)
        assert self._compile(body, tmp_path).exists()


# --------------------------------------------------------------------------- #
# typst is the only PDF engine — a missing package must be a hard error, not a
# silent skip (there is no Ruby fallback anymore).
# --------------------------------------------------------------------------- #
class TestTypstRequired:
    def test_missing_typst_is_hard_error(self, tmp_path):
        # Simulate the typst package being absent: ``import typst`` raises.
        with mock.patch.dict(sys.modules, {"typst": None}):
            with pytest.raises(SystemExit) as exc:
                _generate_typst_pdf(
                    mock.MagicMock(), tmp_path / "x.typ", tmp_path / "logo.png"
                )
        assert exc.value.code != 0


# --------------------------------------------------------------------------- #
# asciidoc_to_html — the Ruby-free HTML converter. Emits AsciiDoctor-classed
# HTML; prose is escaped so user content can never inject markup.
# --------------------------------------------------------------------------- #
class TestAsciidocToHtml:
    def test_none_and_empty(self):
        assert asciidoc_to_html(None) == ""
        assert asciidoc_to_html("") == ""

    def test_paragraph_wrapping(self):
        assert asciidoc_to_html("hello world") == '<div class="paragraph"><p>hello world</p></div>'

    def test_bold_becomes_strong(self):
        assert "<strong>bold</strong>" in asciidoc_to_html("this is *bold* x")

    def test_link_macro(self):
        out = asciidoc_to_html("see link:https://x.com/a[docs]")
        assert '<a href="https://x.com/a">docs</a>' in out

    def test_prose_is_escaped(self):
        assert asciidoc_to_html("a < b & c") == '<div class="paragraph"><p>a &lt; b &amp; c</p></div>'

    def test_no_html_injection(self):
        # User text must never produce live tags (XSS guard).
        out = asciidoc_to_html("<script>alert(1)</script>")
        assert "<script>" not in out
        assert "&lt;script&gt;" in out

    def test_note_admonition(self):
        out = asciidoc_to_html("NOTE: be careful")
        assert 'class="admonitionblock note"' in out
        assert "be careful" in out

    def test_unordered_list(self):
        out = asciidoc_to_html("* one\n* two")
        assert out == '<div class="ulist"><ul><li><p>one</p></li><li><p>two</p></li></ul></div>'

    def test_source_block_listing(self):
        out = asciidoc_to_html("[source,bash]\n----\necho hi\n----")
        assert 'class="listingblock"' in out
        assert "<code>echo hi</code>" in out

    def test_table_renders_as_html_table(self):
        src = '[cols="15%h, 85%a"]\n|===\n|Section\n|System Settings\n|==='
        out = asciidoc_to_html(src)
        assert '<table class="tableblock frame-all grid-all stretch">' in out
        # Column 0 has style "h" -> renders as a header cell everywhere, not
        # just in a %header row.
        assert "<th" in out and ">Section</th>" in out
        assert "<td" in out and "System Settings" in out

    def test_table_header_row_uses_thead(self):
        src = '[%header,cols="3,7"]\n|===\n^.^|Port\n^.^|Service\n\n|548\n|AFP\n|==='
        out = asciidoc_to_html(src)
        assert "<thead>" in out
        assert out.index("<thead>") < out.index(">Port<") < out.index("</thead>")
        # Row 1 data cells are <td>, not <th>.
        assert ">548</td>" in out

    def test_table_cell_hard_break_becomes_br(self):
        src = '[cols="15%h, 85%a"]\n|===\n|Label\n|first +\nsecond\n|==='
        out = asciidoc_to_html(src)
        assert "first<br>second" in out
        assert "+" not in out  # the break marker itself must not leak into output

    def test_table_colgroup_matches_source_proportions(self):
        # Regression: without explicit widths, the browser auto-sizes each
        # <table> from its own content, so sibling tables sharing one
        # `cols=` spec can render with visibly different column widths.
        src = '[cols="15%h, 85%a"]\n|===\n|Section\n|System Settings\n|==='
        out = asciidoc_to_html(src)
        assert '<col style="width:15%">' in out
        assert '<col style="width:85%">' in out

    def test_table_without_width_hints_has_no_colgroup(self):
        rows = [[{"style": "d", "text": "a"}, {"style": "d", "text": "b"}]]
        out = _render_table_html(rows, header_row=False, colwidths=None)
        assert "<colgroup>" not in out

    def test_a_style_cell_recurses_into_nested_list(self):
        # An "a"-style cell is itself AsciiDoc prose and can contain block
        # content (mirrors supplemental_smartcard.yaml's checkCertificateTrust).
        src = '[cols="15%h, 85%a"]\n|===\n|Label\na|Options:\n\n- one\n- two\n|==='
        out = asciidoc_to_html(src)
        assert '<div class="ulist"><ul>' in out
        assert "<li><p>one</p></li>" in out

    def test_table_fragment_is_well_formed(self):
        # Same tag-balance guard as TestHtmlWellFormed, applied to a table
        # with every feature exercised at once (header row, alignment
        # prefixes, an "a"-style cell with a nested list, a hard break).
        src = (
            '[%header,cols="2,1,7"]\n'
            "|===\n"
            "|Key\n"
            "|Type\n"
            "|Value\n"
            "\n"
            "<.^|userPairing\n"
            "^.^|bool\n"
            "a|Valid values: +\n"
            "see below\n"
            "\n"
            "- one\n"
            "- two\n"
            "|===\n"
        )
        frag = asciidoc_to_html(src)
        depth = {"open": 0, "close": 0}
        void_elements = {"br", "hr", "img", "col"}  # never get a matching end tag

        class _P(HTMLParser):
            def handle_starttag(self, tag, attrs):
                if tag not in void_elements:
                    depth["open"] += 1

            def handle_endtag(self, tag):
                depth["close"] += 1

        p = _P()
        p.feed(f"<div>{frag}</div>")
        assert depth["open"] == depth["close"], frag


class TestHtmlRenderHelpers:
    def test_render_rules_coerces_non_strings(self):
        # CIS controls arrive as floats (e.g. 3.3) — must not crash html.escape.
        out = render_rules_html(["AU-9", 3.3])
        assert "<li>AU-9</li>" in out and "<li>3.3</li>" in out

    def test_render_rules_empty(self):
        assert render_rules_html(None) == ""
        assert render_rules_html([]) == ""

    def test_render_references_flattens(self):
        assert "cce: a, b" in render_references_html([{"cce": ["a", "b"]}])

    def test_render_references_rejects_non_dict(self):
        with pytest.raises(TypeError):
            render_references_html(["nope"])


class TestHtmlWellFormed:
    """A converted fragment wrapped in a minimal page must parse cleanly."""

    def test_fragment_parses(self):
        frag = asciidoc_to_html(
            "Disable *SIP*. See link:https://x[guide]. NOTE: os_sip_enable.\n"
            "[source,zsh]\n----\ncsrutil status | grep -c '<enabled>'\n----\n* a\n* b"
        )
        # HTMLParser raises on malformed markup; tag balance is the real check.
        depth = {"open": 0, "close": 0}

        class _P(HTMLParser):
            def handle_starttag(self, *a):
                depth["open"] += 1

            def handle_endtag(self, *a):
                depth["close"] += 1

        p = _P()
        p.feed(f"<div>{frag}</div>")
        assert depth["open"] == depth["close"], frag


# --------------------------------------------------------------------------- #
# asciidoc_to_markdown — the GitHub-flavoured Markdown converter.
# --------------------------------------------------------------------------- #
class TestAsciidocToMarkdown:
    def test_bold_and_link_pass_through(self):
        out = asciidoc_to_markdown("this is *bold* and link:https://x.com/a[docs]")
        assert "*bold*" in out
        assert "[docs](https://x.com/a)" in out

    def test_table_renders_as_pipe_table(self):
        src = '[cols="15%h, 85%a"]\n|===\n|Section\n|System Settings\n|==='
        out = asciidoc_to_markdown(src)
        lines = out.splitlines()
        assert lines[0] == "| Section | System Settings |"
        assert lines[1] == "| --- | --- |"

    def test_table_without_header_attr_still_uses_row0_as_header(self):
        # GFM tables require a header + separator line syntactically, even
        # though most of mSCP's label/value tables never set AsciiDoc's
        # `%header` -- row 0 is used as the header regardless.
        src = (
            '[cols="15%h, 85%a"]\n'
            "|===\n"
            "|Section\n"
            "|System Settings\n"
            "\n"
            "|Recommendations\n"
            "|item one\n"
            "|===\n"
        )
        out = asciidoc_to_markdown(src)
        lines = out.splitlines()
        assert lines[0] == "| Section | System Settings |"
        assert lines[1] == "| --- | --- |"
        assert lines[2] == "| Recommendations | item one |"

    def test_pipe_in_cell_content_is_escaped(self):
        # The parser is line-anchored (one cell per line, house style), so a
        # "|" mid-line is just literal cell text -- but GFM still requires it
        # be escaped on the way out, or it reads as a spurious column break.
        src = '[cols="15%h, 85%a"]\n|===\n|Cmd\n|cmd | grep foo\n|==='
        out = asciidoc_to_markdown(src)
        row = [line for line in out.splitlines() if line.startswith("| Cmd")][0]
        assert row == "| Cmd | cmd \\| grep foo |"

    def test_table_cell_hard_break_becomes_br(self):
        # cols="3,7" has no style letters -> default "d" (literal/folded)
        # cells, which fold through `_fold_table_cell_lines` directly.
        src = '[cols="3,7"]\n|===\n|Label\n|first +\nsecond\n|==='
        out = asciidoc_to_markdown(src)
        assert "first<br>second" in out

    def test_a_style_cell_collapses_to_single_line(self):
        # Regression: an "a"-style cell recurses into asciidoc_to_markdown,
        # whose output can itself contain "\n" between blocks (e.g. a forced
        # break becoming "text<br>" followed by "\n" before the next line).
        # That "\n" must fold to a space, not survive as a raw newline (which
        # would corrupt the pipe-table row) or stack into a doubled "<br><br>".
        src = '[cols="15%h, 85%a"]\n|===\n|Label\na|line one +\nline two\n|==='
        out = asciidoc_to_markdown(src)
        row = [line for line in out.splitlines() if line.startswith("| Label")][0]
        assert row == "| Label | line one<br> line two |"
        assert "<br><br>" not in row
        assert "\n" not in row


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
