---
title: mSCP 2.0 API Reference
description: "mSCP — macOS Security Compliance Project."
sidebar:
  order: 0
---

> Source: [`src/mscp/__init__.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/__init__.py)

mSCP — macOS Security Compliance Project.

Top-level package for the mSCP toolchain. Re-exports the domain models
(`Baseline`, `Macsecurityrule`, `Payload`, `LoguruFormatter`,
`RuleLibrary`), the command-line entry point `parse_cli`, the generator
entry points (`baseline`, `guidance`, `mapping`, `translation`), and the
file / config helpers used throughout the codebase.

The package's `loguru` logger is disabled by default; callers that want
mSCP log output should enable it (typically via `set_logger`).


## Re-exports (`__all__`)

`Baseline`, `Macsecurityrule`, `LoguruFormatter`, `Payload`, `RuleLibrary`, `config`, `append_text`, `create_csv`, `create_plist`, `create_yaml`, `make_dir`, `open_csv`, `open_file`, `open_plist`, `open_yaml`, `remove_dir`, `remove_dir_contents`, `remove_file`, `run_command`, `baseline`, `guidance`, `mapping`, `parse_cli`, `validate_yaml_file`, `set_logger`, `translation`
