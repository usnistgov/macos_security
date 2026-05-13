---
title: mscp.generate.scap
description: "SCAP 1.4 / XCCDF / OVAL content generation for the macOS Security Compliance Project."
sidebar:
  order: 1
---

> Source: [`src/mscp/generate/scap.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/scap.py)

SCAP 1.4 / XCCDF / OVAL content generation for the macOS Security Compliance Project.

Provides `generate_scap`, which builds an XCCDF benchmark with profiles and
rules, an OVAL definitions document with shell-command tests, and (for macOS)
wraps them into a SCAP 1.4 data-stream XML file.  Standalone XCCDF-only and
OVAL-only outputs are also supported.


## Functions

### pretty_format_xml

```python
pretty_format_xml(xml_string: str) -> str
```

Format XML using minidom, without extra blank lines.


### disa_stig_rules

```python
disa_stig_rules(stig_id, stig)
```

Extract the SRG title and Rule ID prefix for a given STIG ID from raw STIG XML text.

Searches the raw XML string for a ``<title>SRG-…</title>`` element and
the matching ``Rule id`` attribute adjacent to *stig_id*, then returns
them joined by ``", "``.

**Args**

- **`stig_id`** *(str)* — STIG rule identifier to search for (e.g. ``"SV-257502r858765_rule"``).
- **`stig`** *(str)* — Raw STIG XML text.

**Returns**

- **`str`** — ``"<SRG-title>, <RuleID-prefix>"`` if both are found; partial or empty string otherwise.


### generate_scap

```python
generate_scap(sp: Yaspin, args: argparse.Namespace) -> None
```

*Decorators:* `@conditional_inject_spinner()`

Generate SCAP, XCCDF, or OVAL output for the specified OS and baseline.

Collects all rules, builds XCCDF profiles and rules with inline OVAL
shell-command checks, and writes the result as a SCAP 1.4 data-stream
(macOS only), a standalone XCCDF, or a standalone OVAL file depending
on ``args``.

**Args**

- **`sp`** *(Yaspin)* — Spinner instance injected by `conditional_inject_spinner`.
- **`args`** *(argparse.Namespace)* — Parsed CLI arguments. Expected attributes: ``os_name``, ``os_version``, ``baseline``, ``list_tags``, ``oval``, ``xccdf``, ``disa_stig``.
