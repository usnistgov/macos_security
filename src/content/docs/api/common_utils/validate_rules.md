---
title: mscp.common_utils.validate_rules
description: "Schema and folder-structure validators for rule YAML files."
---

> Source: [`src/mscp/common_utils/validate_rules.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/common_utils/validate_rules.py)

Schema and folder-structure validators for rule YAML files.

Wires up the ``mscp admin validate`` subcommand. `validate_yaml_file`
walks the configured rules directory (plus any custom rules) and
validates each file against ``schema/mscp_rule.json``;
`validate_rule_folder_structure` is an `argparse` type validator that
makes sure ``--rules_dir`` points at a properly organised tree.
`get_rule_identifier` is a small helper that prefers a rule file's
``id`` field, falling back to its filename stem.


## Functions

### get_rule_identifier

```python
get_rule_identifier(rule_file: Path) -> str
```

Return the rule's canonical ID, preferring the YAML ``id`` field.

Falls back to the filename stem when the YAML doesn't define one.

**Args**

- **`rule_file`** *(Path)* — Path to a rule YAML file.

**Returns**

- **`str`** — The rule's identifier.


### validate_yaml_file

```python
validate_yaml_file(args: argparse.Namespace) -> None
```

Validate every rule YAML against ``schema/mscp_rule.json``.

Loads the schema, then iterates either ``args.rules_dir`` (if set)
or the default rules tree plus any custom rules. Prints / logs a
line per file: ``✅ VALID``, ``❌ INVALID``, or ``⚠️ ERROR``. Files
with duplicate rule identifiers are flagged with a warning.

**Args**

- **`args`** *(argparse.Namespace)* — Parsed CLI arguments. Reads ``rules_dir`` (override) and ``all_validation`` (when true, successful files are also printed).


### validate_rule_folder_structure

```python
validate_rule_folder_structure(path_str: str) -> Path
```

Argparse 'type' validator:
- Ensures PATH exists and is a directory.
- Ensures root contains only subdirectories (no files).
- Ensures each subdir contains only YAML files and/or is empty.
- Disallows nested directories under subfolders (can be toggled).
