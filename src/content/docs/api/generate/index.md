---
title: mscp.generate
description: "Baseline, guidance, and artifact generation entry points for mSCP."
sidebar:
  order: 0
---

> Source: [`src/mscp/generate/__init__.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/__init__.py)

Baseline, guidance, and artifact generation entry points for mSCP.

Re-exports the top-level generator functions: `generate_baseline`
(YAML baseline files), `generate_guidance` (human-readable guidance
documents), `generate_mapping` (control-mapping reports),
`generate_scap` (SCAP/XCCDF content), `generate_localize_template`
and `generate_mo_from_json` (localization support files).


## Re-exports (`__all__`)

`generate_baseline`, `generate_guidance`, `generate_mapping`, `generate_scap`, `generate_localize_template`, `generate_mo_from_json`
