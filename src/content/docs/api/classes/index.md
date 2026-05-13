---
title: mscp.classes
description: "Domain models for mSCP."
sidebar:
  order: 0
---

> Source: [`src/mscp/classes/__init__.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/classes/__init__.py)

Domain models for mSCP.

Re-exports the public model classes used throughout mSCP:

- `Baseline`, `Profile`, `Author` — baseline document and its sections.
- `Macsecurityrule`, `Sectionmap` — security rule model and its section
  enumeration.
- `Payload` — configuration profile payload model.
- `RuleLibrary` — ordered, indexed collection of `Macsecurityrule` objects.


## Re-exports (`__all__`)

`Baseline`, `Macsecurityrule`, `Payload`, `Author`, `Profile`, `RuleLibrary`, `Sectionmap`
