---
title: mscp.common_utils.customization
description: "Loader for per-rule customisation YAML overrides."
sidebar:
  order: 1
---

> Source: [`src/mscp/common_utils/customization.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/common_utils/customization.py)

Loader for per-rule customisation YAML overrides.

Customisation files live alongside the default rules but only contain
the keys the user wants to override. `collect_overrides` walks a
directory tree, gathers them, and returns a flat
``rule_id → override_dict`` mapping consumed by `Macsecurityrule.load_rules`.


## Functions

### collect_overrides

```python
collect_overrides(override_location: Path) -> dict[str, Any]
```

Collects all custom override yaml files from the provided overrides location.

**Args**

- **`override_location`** *(Path)* — The path to the folder containing the overrides to process.

**Returns**

- dict[str, Any]: Dictionary of discovered custom overrides data.

**Raises**

- **`Exception`** — If there is an error processing the overrides file.
