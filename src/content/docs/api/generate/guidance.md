---
title: mscp.generate.guidance
description: "Main guidance document orchestration for the macOS Security Compliance Project."
sidebar:
  order: 1
---

> Source: [`src/mscp/generate/guidance.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/guidance.py)

Main guidance document orchestration for the macOS Security Compliance Project.

Provides `generate_guidance`, the top-level entry point that coordinates
profile generation, DDM declarations, compliance scripts, Excel output,
Markdown documents, JSON manifests, and AsciiDoc/PDF/HTML guidance documents
for a given baseline.  `verify_signing_hash` validates a certificate hash
before profile signing.


## Functions

### verify_signing_hash

```python
verify_signing_hash(cert_hash: str) -> bool
```

Verify that *cert_hash* identifies an installed signing certificate.

Writes a temporary file, attempts to sign it with ``security cms -SZ``,
then removes the file.

**Args**

- **`cert_hash`** *(str)* — Subject Key ID hash of the certificate to verify.

**Returns**

- **`bool`** — ``True`` if signing succeeds, ``False`` otherwise.


### generate_guidance

```python
generate_guidance(sp: Yaspin, args: argparse.Namespace) -> None
```

*Decorators:* `@conditional_inject_spinner()`

Orchestrate all guidance artifacts for a given baseline.

Reads the baseline YAML and, based on ``args`` flags, delegates to the
appropriate sub-generators: configuration profiles, DDM declarations,
compliance scripts, Excel workbook, Markdown documents, JSON manifest,
and the primary AsciiDoc/PDF/HTML guidance document.

**Args**

- **`sp`** *(Yaspin)* — Spinner instance injected by `conditional_inject_spinner`.
- **`args`** *(argparse.Namespace)* — Parsed CLI arguments. Expected attributes: ``baseline``, ``os_name``, ``language``, ``dark``, ``hash``, ``reference``, ``logo``, ``audit_name``, ``profiles``, ``ddm``, ``script``, ``xlsx``, ``gary``, ``markdown``, ``manifest``, ``all``, ``consolidated_profile``, ``granular_profiles``.
