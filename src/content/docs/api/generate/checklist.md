---
title: mscp.generate.checklist
description: "DISA STIG checklist (CKL/CKLB) generation for the macOS Security Compliance Project."
---

> Source: [`src/mscp/generate/checklist.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/checklist.py)

DISA STIG checklist (CKL/CKLB) generation for the macOS Security Compliance Project.

Provides `generate_checklist`, which reads a DISA STIG XML or ZIP file alongside
a compliance plist and writes a CKLB (v3 JSON) or CKL (v2 XML) checklist.
Helper functions handle XML extraction from ZIP archives, XML-to-dict conversion,
and STIG rule mapping.


## Functions

### extract_manual_xml

```python
extract_manual_xml(zip_path: Path) -> Element
```

*Decorators:* `@logger.catch`

Extract and parse the Manual XML file from a DISA STIG ZIP archive.

Scans the ZIP for an entry whose name contains ``"Manual"`` and ends
with ``".xml"``, decodes HTML entities (``&lt;`` / ``&gt;``), and
returns the parsed root element.

**Args**

- **`zip_path`** *(Path)* — Path to the DISA STIG ``.zip`` file.

**Returns**

- **`Element`** — Parsed lxml root element of the Manual XML.

**Raises**

- **`FileNotFoundError`** — If no matching XML entry is found in the archive.


### xml_to_dict

```python
xml_to_dict(element: Element) -> dict[str, Any]
```

Recursively convert an lxml Element tree to a nested dict.

Namespaces are stripped and tag names are lower-cased.  Sibling elements
with the same tag are collected into a list.  Attributes are merged into
the dict for their element; text content is stored under ``"text"`` when
other keys are already present.

**Args**

- **`element`** *(Element)* — Root element to convert.

**Returns**

- dict[str, Any]: Dictionary representation of the element tree.


### map_stig_data

```python
map_stig_data(stig_data: dict[str, Any], baseline: Baseline, stig_uuid: str, created: str, updated: str) -> list[dict[str, Any]]
```

*Decorators:* `@logger.catch`

Map STIG benchmark groups to CKLB rule dicts, merging baseline findings.

For each group in ``stig_data["benchmark"]["group"]``, builds a flat dict
matching the CKLB rule schema.  The ``status`` field is ``"not_a_finding"``
when the corresponding baseline rule has no finding, ``"open"`` otherwise.
Results are sorted by ``rule_version``.

**Args**

- **`stig_data`** *(dict[str, Any])* — Parsed STIG benchmark data (from `xml_to_dict`).
- **`baseline`** *(Baseline)* — Loaded baseline whose rules carry finding status.
- **`stig_uuid`** *(str)* — UUID assigned to the parent STIG in the output document.
- **`created`** *(str)* — ISO-8601 creation timestamp string.
- **`updated`** *(str)* — ISO-8601 last-updated timestamp string.

**Returns**

- list[dict[str, Any]]: List of CKLB-schema rule dicts sorted by rule version.


### generate_checklist_v2

```python
generate_checklist_v2(output_file: Path, stig_data: dict[str, Any], stig_filename: str, stig_description: str) -> None
```

*Decorators:* `@logger.catch`

Render a CKL v2 XML checklist using the Jinja checklist template.

**Args**

- **`output_file`** *(Path)* — Destination path for the rendered ``.ckl`` file.
- **`stig_data`** *(dict[str, Any])* — CKLB-schema rule data (``filename`` key is injected before rendering).
- **`stig_filename`** *(str)* — Original STIG filename, embedded in the output.
- **`stig_description`** *(str)* — Baseline description, embedded in the output.


### generate_checklist

```python
generate_checklist(args: argparse.Namespace) -> None
```

Generate a DISA STIG checklist file (CKLB v3 or CKL v2) from a compliance plist.

Loads the STIG XML (or extracts it from a ZIP), loads or locates the
baseline YAML, merges finding status from the compliance plist, and
writes either a JSON CKLB (``--checklist-version 3``) or an XML CKL
(earlier versions) to the output directory.

**Args**

- **`args`** *(argparse.Namespace)* — Parsed CLI arguments. Expected attributes: ``os_name``, ``os_version``, ``plist``, ``disastig``, ``baseline``, ``checklist_version``.
