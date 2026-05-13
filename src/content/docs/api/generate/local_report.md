---
title: mscp.generate.local_report
description: "Local compliance report generation (Excel + HTML) for mSCP."
---

> Source: [`src/mscp/generate/local_report.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/local_report.py)

Local compliance report generation (Excel + HTML) for mSCP.

Provides `generate_local_report`, which reads a compliance audit plist,
produces an Excel workbook with a pie chart of pass/fail results, and
renders an HTML report using a Jinja template with the chart embedded as
a base64 image.


## Functions

### generate_local_report

```python
generate_local_report(args: argparse.Namespace) -> None
```

Generate an Excel and HTML compliance report from a local audit plist.

Loads the plist (from ``args.plist`` or interactively from
``/Library/Preferences``), builds a DataFrame of rule findings, writes
an ``.xlsx`` workbook with an embedded pie chart, and renders an HTML
report with the chart as a base64 image.

**Args**

- **`args`** *(argparse.Namespace)* — Parsed CLI arguments. Expected attributes: ``plist`` (optional path), ``output`` (optional output path override).

**Raises**

- **`SystemExit`** — If no plist files are found or an invalid selection is made.
