---
title: mscp.generate.guidance_support.script
description: "Compliance and restore shell script generation for mSCP baselines."
---

> Source: [`src/mscp/generate/guidance_support/script.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/guidance_support/script.py)

Compliance and restore shell script generation for mSCP baselines.

Provides `generate_script` (audit compliance script) and
`generate_restore_script` (defaults-restore script), both rendered from
Jinja templates.  `generate_audit_plist` writes the companion audit plist.
Jinja filter helpers `group_ulify`, `generate_log_reference`, and
`quotify` are also defined here.


## Functions

### group_ulify

```python
group_ulify(elements: list[str]) -> str
```

Converts a list of strings into a grouped unordered list format.

This function is used as a Jinja filter to format a list of strings.
It groups the elements by their prefix (before the first parenthesis),
sorts them, and then formats them into a string with each group
represented as an unordered list.

**Args**

- **`elements`** *(list[str])* — The list of strings to be formatted.

**Returns**

- **`str`** — A formatted string representing the grouped unordered list.
- If the input is "N/A", it returns "- N/A".


### generate_log_reference

```python
generate_log_reference(rule: Macsecurityrule, reference: str) -> list[str] | str
```

Generate the log reference ID based on the rule and reference type.

**Note**

> This is used as a Jinja filter in the script template.


### quotify

```python
quotify(fix_code: str) -> str
```

Escape single quotes and format percentages for Bash.

**Note**

> This is used as a Jinja filter in the script template.


### generate_audit_plist

```python
generate_audit_plist(build_path: Path, baseline_name: str, baseline: Baseline) -> None
```

Write the default audit plist (``org.<baseline_name>.audit.plist``).

Creates a plist where each non-supplemental rule ID maps to
``{"exempt": False}``, used as the initial state for compliance auditing.

**Args**

- **`build_path`** *(Path)* — Root output directory; plist goes in ``preferences/``.
- **`baseline_name`** *(str)* — Baseline name used in the plist filename and ``/Library/Preferences`` path.
- **`baseline`** *(Baseline)* — Baseline whose rules populate the plist keys.


### generate_script

```python
generate_script(build_path: Path, baseline_name: str, audit_name: str, baseline: Baseline, log_reference: str, current_version_data: dict) -> None
```

Render and write the compliance audit shell script for *baseline*.

Uses the ``compliance_script.sh.jinja`` template and also calls
`generate_audit_plist`.  Skips non-Unix platforms.

**Args**

- **`build_path`** *(Path)* — Output directory; script written as ``<baseline_name>_compliance.sh`` with mode ``0755``.
- **`baseline_name`** *(str)* — Baseline name used in filenames and template variables.
- **`audit_name`** *(str)* — Audit identifier string passed to the template.
- **`baseline`** *(Baseline)* — Loaded baseline object.
- **`log_reference`** *(str)* — Log reference key (e.g. ``"default"`` or a framework name) passed to the template.
- **`current_version_data`** *(dict)* — Version metadata for the OS/baseline.


### generate_restore_script

```python
generate_restore_script(build_path: Path, baseline_name: str, audit_name: str, baseline: Baseline, log_reference: str, current_version_data: dict) -> None
```

Render and write the restore shell script for *baseline* (if applicable).

Uses the ``restore_script.sh.jinja`` template.  Only writes the file if at
least one rule has a ``default_state`` value, and skips non-Unix platforms.

**Args**

- **`build_path`** *(Path)* — Output directory; script written as ``<baseline_name>_restore.sh`` with mode ``0755``.
- **`baseline_name`** *(str)* — Baseline name used in filenames and template variables.
- **`audit_name`** *(str)* — Audit identifier string passed to the template.
- **`baseline`** *(Baseline)* — Loaded baseline object.
- **`log_reference`** *(str)* — Log reference key passed to the template.
- **`current_version_data`** *(dict)* — Version metadata for the OS/baseline.
