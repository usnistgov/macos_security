---
title: mscp.generate.guidance_support.manifest
description: "JSON manifest generation for mSCP baselines."
---

> Source: [`src/mscp/generate/guidance_support/manifest.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/guidance_support/manifest.py)

JSON manifest generation for mSCP baselines.

Provides `generate_manifest`, which serialises baseline metadata and
per-rule details (references, check command, fix payload) into a single
JSON file used by downstream tooling to identify and audit rules.


## Functions

### generate_manifest

```python
generate_manifest(build_path: Path, baseline_name: str, baseline) -> None
```

Write a JSON manifest summarising the baseline and all its rules.

The manifest includes platform metadata, release info, plist and log
paths, and a list of rules with their IDs, titles, references, tags,
check commands, and fix payloads (mobileconfig, DDM, or script).

**Args**

- **`build_path`** *(Path)* — Output directory; the manifest is written as ``<build_path>/<baseline_name>.json``.
- **`baseline_name`** *(str)* — Name of the baseline (used for file naming and plist/log path strings).
- **`baseline`** — Loaded ``Baseline`` object containing profiles and platform info.
