---
title: mscp.generate.guidance_support.ddm
description: "Declarative Device Management (DDM) artifact generation for mSCP."
sidebar:
  order: 1
---

> Source: [`src/mscp/generate/guidance_support/ddm.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/guidance_support/ddm.py)

Declarative Device Management (DDM) artifact generation for mSCP.

Provides `generate_ddm`, which processes ``ddm_info`` fields from baseline
rules and writes DDM JSON configurations, assets, activations, and service
ZIP archives under a ``declarative/`` subdirectory of the build path.


## Functions

### generate_ddm_activation

```python
generate_ddm_activation(output_path: Path, identifier: str) -> None
```

Write a DDM activation JSON file that references a single configuration.

Derives the activation identifier from *identifier* by replacing
``"config"`` and ``"asset"`` with ``"activation"``, then appends the
JSON payload to *output_path*.

**Args**

- **`output_path`** *(Path)* — Destination file path (created or appended to).
- **`identifier`** *(str)* — Configuration or asset DDM identifier to activate.


### zip_directory

```python
zip_directory(zip_path: Path, folder_path: Path) -> None
```

Recursively compress *folder_path* into *zip_path*, preserving relative paths.

**Args**

- **`zip_path`** *(Path)* — Destination ZIP file path.
- **`folder_path`** *(Path)* — Directory to compress.


### generate_ddm

```python
generate_ddm(build_path: Path, baseline: Baseline, baseline_name: str) -> None
```

Generate DDM configuration, asset, and activation JSON files for *baseline*.

Iterates rules with ``ddm_info``, writing service configuration files and
ZIP archives (``com.apple.configuration.services.configuration-files``) or
standard declaration JSONs into ``<build_path>/declarative/{configurations,
assets,activations}/``.  Skips non-Apple platforms and unknown services.

**Args**

- **`build_path`** *(Path)* — Root output directory for this baseline's artifacts.
- **`baseline`** *(Baseline)* — Baseline whose rules supply ``ddm_info`` payloads.
- **`baseline_name`** *(str)* — Baseline name used as part of DDM identifiers.
