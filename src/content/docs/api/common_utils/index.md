---
title: mscp.common_utils
description: "Shared cross-cutting helpers used throughout mSCP."
sidebar:
  order: 0
---

> Source: [`src/mscp/common_utils/__init__.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/common_utils/__init__.py)

Shared cross-cutting helpers used throughout mSCP.

Re-exports the loguru logger (`logger`), file I/O helpers
(create / open / remove for YAML, JSON, plist, CSV, text), the
configuration model (`config`, `set_custom_dir`, `ensure_custom_dirs`),
input validation utilities (`sanitize_input`, `prompt_for_odv`,
`validate_yaml_file`, `validate_rule_folder_structure`), localization
helpers (`get_supported_languages`), version metadata accessors
(`get_version_data`, `get_mscp_data`, `mscp_data`), the shell-command
runner (`run_command`), and the spinner decorator
(`conditional_inject_spinner`).


## Re-exports (`__all__`)

`append_text`, `create_csv`, `create_file`, `create_json`, `create_plist`, `create_text`, `create_yaml`, `make_dir`, `open_csv`, `open_file`, `open_plist`, `open_text`, `open_yaml`, `remove_dir`, `remove_dir_contents`, `remove_file`, `run_command`, `sanitize_input`, `prompt_for_odv`, `get_version_data`, `mscp_data`, `get_mscp_data`, `set_logger`, `config`, `set_custom_dir`, `ensure_custom_dirs`, `CONFIG_PATH`, `SCHEMA_PATH`, `APPLE_OS`, `NIX_OS`, `validate_yaml_file`, `logger`, `get_supported_languages`, `collect_overrides`, `validate_rule_folder_structure`, `conditional_inject_spinner`
