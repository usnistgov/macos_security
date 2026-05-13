---
title: mscp.generate.translation
description: "Localization template and compiled message-object generation for mSCP."
---

> Source: [`src/mscp/generate/translation.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/translation.py)

Localization template and compiled message-object generation for mSCP.

Provides `generate_localize_template` (builds a ``messages.pot``-style JSON
from section YAML, Jinja templates, and rule strings) and `generate_mo_from_json`
(compiles a translated JSON file to a Babel ``.mo`` / ``.po`` pair).


## Functions

### extract_trans_text

```python
extract_trans_text(template: str) -> list[str]
```

Extract translatable strings from ``{% trans %}…{% endtrans %}`` blocks.

Strips embedded ``{{ … }}`` expressions, leading table-pipe markers,
and excess whitespace from each captured chunk, then de-duplicates
and drops empty results.

**Args**

- **`template`** *(str)* — Raw Jinja template source.

**Returns**

- **`list[str]`** — Unique non-empty translatable strings found in the template.


### generate_localize_template

```python
generate_localize_template(args: argparse.Namespace) -> None
```

Build a JSON translation template from section, template, and rule strings.

Collects translatable strings from section YAML files (``name`` /
``description``), Jinja templates (``{% trans %}`` blocks), and rule YAML
files (``title`` / ``discussion``), then writes them as a context-keyed
JSON file suitable for hand-translation or machine translation.

**Args**

- **`args`** *(argparse.Namespace)* — Parsed CLI arguments. Expected attributes: ``os_name``, ``os_version``, ``domain``, ``output``.


### generate_mo_from_json

```python
generate_mo_from_json(args: argparse.Namespace) -> None
```

Compile a translated JSON file to a Babel ``.mo`` and ``.po`` pair.

Reads a translated JSON mapping (``{ context: { "en": …, "<locale>": … } }``),
builds a Babel catalog for the target locale, and writes both a binary
``.mo`` and a human-readable ``.po`` file under
``<output_dir>/locale/<locale>/LC_MESSAGES/``.

**Args**

- **`args`** *(argparse.Namespace)* — Parsed CLI arguments. Expected attributes: ``json_file``, ``domain``, ``locale``, ``mo_file``, ``use_fuzzy``.
