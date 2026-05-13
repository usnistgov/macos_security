---
title: mscp.generate.mapping
description: "Control-framework mapping and custom baseline generation for mSCP."
sidebar:
  order: 1
---

> Source: [`src/mscp/generate/mapping.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/mapping.py)

Control-framework mapping and custom baseline generation for mSCP.

Provides `generate_mapping`, which reads a CSV cross-walk between a known
security framework (e.g. NIST 800-53) and one or more target frameworks,
annotates matching rules with the mapped controls, writes per-rule YAML
files, and generates a custom baseline for each mapped framework column.


## Functions

### update_rule_with_custom_references

```python
update_rule_with_custom_references(rule: Macsecurityrule, references: list[str], reference_source: str) -> None
```

Update a rule with custom references.

**Args**

- **`rule`** *(Macsecurityrule)* — The rule to update.
- **`references`** *(List[str])* — The references to add.
- **`reference_source`** *(str)* — The reference source to map references to.


### generate_mapping

```python
generate_mapping(sp: Yaspin, args: argparse.Namespace) -> None
```

*Decorators:* `@conditional_inject_spinner()`

Map rules to a target framework via a CSV cross-walk and write custom baselines.

For each non-source column in the CSV, identifies rules whose
``args.framework`` references intersect the CSV rows, annotates them
with the mapped target controls, serializes updated rule YAML files,
and creates a custom baseline YAML for that column.

**Args**

- **`sp`** *(Yaspin)* — Spinner instance injected by `conditional_inject_spinner`.
- **`args`** *(argparse.Namespace)* — Parsed CLI arguments. Expected attributes: ``os_name``, ``os_version``, ``csv``, ``framework``.
