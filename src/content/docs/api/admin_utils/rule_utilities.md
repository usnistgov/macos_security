---
title: mscp.admin_utils.rule_utilities
description: "Interactive helpers for working with rule YAML files."
---

> Source: [`src/mscp/admin_utils/rule_utilities.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/admin_utils/rule_utilities.py)

Interactive helpers for working with rule YAML files.

Currently provides `add_new_rule`, which scaffolds a placeholder rule
file under the configured custom rules directory.


## Functions

### add_new_rule

```python
add_new_rule(args: argparse.Namespace) -> None
```

Scaffold a new placeholder rule YAML in the custom rules directory.

Prompts for a title and unique rule ID, builds a minimal
`Macsecurityrule` populated with placeholder values (mechanism
``"Configuration Profile"``, section ``"auditing"``, NIST references
empty), and serialises it to
``<custom_rules_dir>/<rule_id>.yaml`` for the user to fill in.

**Args**

- **`args`** *(argparse.Namespace)* — Parsed CLI arguments; only `os_name` is consumed (used for both `os_name` and `os_type` on the scaffolded rule).

**Side Effects**

- Writes a YAML file to disk and prompts on stdin via
- `sanitize_input`.
