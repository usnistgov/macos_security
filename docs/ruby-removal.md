# Removing the Ruby toolchain — DONE

> **Status: complete.** Ruby/AsciiDoctor has been removed. `mscp guidance`
> now renders PDF with **typst** and HTML/Markdown in **pure Python**. The
> `Gemfile`, the `adoc/` template tree, the asciidoctor-pdf themes, and the
> `bundle exec` calls are gone. This document is kept as the record of why and
> how. (Historical: the work landed across `feat/typst-pdf-backend` →
> `feat/drop-ruby`.)

The mSCP CLI was Python end-to-end (`uv` / `pyproject.toml`) **except** document
generation, which was the only reason a Ruby toolchain existed.

## Why Ruby was here

Guidance documents were rendered from Jinja templates to AsciiDoc, then
`documents.py` shelled out to AsciiDoctor:

| Step | Command | Output |
|------|---------|--------|
| HTML | `bundle exec asciidoctor <baseline>.adoc` | `<baseline>.html` |
| PDF  | `bundle exec asciidoctor-pdf <baseline>.adoc` | `<baseline>.pdf` |

The full footprint is six gems in `Gemfile` (`asciidoctor`, `asciidoctor-pdf`,
`rouge`, `logger`, `ostruct`, `bigdecimal`) plus the `bundle install` /
`mscp_gems/` vendoring dance.

## Ruby-free replacements (experimental, already in tree)

Both replacements are **additive** and opt-in — the AsciiDoctor path is the
default and is byte-for-byte unchanged.

| Output | Flag | How it works |
|--------|------|--------------|
| PDF  | `--pdf-engine typst`  | `typst/*.jinja` → `.typ` → compiled via the `typst` Python package (uv dependency) |
| HTML | `--html-engine python` | `html/*.jinja` → self-contained `.html` with the bundled `asciidoctor.css` inlined (pure Python, no external tool) |

Shared converter helpers live in `documents.py`: `asciidoc_to_typst` /
`asciidoc_to_html` and the `render_*_{typst,html}` Jinja filters. Tests:
`tests/test_backends.py`.

### Why not a single source?

Typst can export HTML (`typst compile --format html`), which would give one
template tree for both outputs. We tested it: it keeps tables/code/links but
**drops layout-based constructs** — the placed title page (logo), semantic
`<h1>`, and `#grid`/`#box` admonitions all vanish, because HTML has no fixed
pages. Typst also warns it is not production-ready. A dedicated Python HTML
template tree is more robust and reuses the existing CSS, so HTML and PDF stay
purpose-built.

## Migration sequence

1. **[done]** typst PDF backend + parity work (numbering, flow, admonitions,
   front matter).
2. **[done]** Python HTML backend prototype (cover page, TOC, sections, rules,
   references, admonitions; reuses `asciidoctor.css`).
3. **Reach parity** on both backends across all 14 baselines and both themes
   (light/dark); diff against the current AsciiDoctor output.
4. **Add syntax highlighting** for HTML code blocks (rouge was Ruby). Options:
   Pygments (Python, build-time) or highlight.js (client-side). Typst already
   highlights in the PDF path.
5. **Flip the defaults**: `--pdf-engine typst` and `--html-engine python`
   become the defaults; keep the AsciiDoctor path behind the flag for one
   release as a fallback.
6. **Remove Ruby**:
   - delete `Gemfile`, `Gemfile.lock`, `mscp_gems/`
   - remove the `bundle show` / `bundle install` / `bundle exec` calls and the
     `output_format == "adoc"` branch in `documents.py`
   - retire the `adoc/` template tree (and the `.adoc` intermediate) once
     nothing depends on it
   - drop any Ruby setup from CI / docs / Dockerfiles
7. **Result**: dependencies are **Python only** (`uv`), with typst pulled in as
   the `typst` PyPI package. No Ruby, no bundler, no gem vendoring, no separate
   binary to install.

## Open items / risks

- **Parity gaps** (HTML prototype): title splits onto two lines in AsciiDoctor
  vs one here; a couple of section/rule count deltas; admonition styling for the
  Remediation block. All tunable in the templates.
- **Syntax highlighting** parity (step 4) is the main net-new piece.
- **`**` double-stars** in some rule discussions trip an AsciiDoc→Typst/HTML
  edge case (cosmetic warning); worth fixing in the converters.
- **Localization**: both new trees use the same gettext `{% trans %}` strings,
  so translations carry over — verify non-`en` languages render.
