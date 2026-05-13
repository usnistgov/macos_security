---
title: mscp.cli
description: "Command-line interface for mSCP."
sidebar:
  order: 1
---

> Source: [`src/mscp/cli.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/cli.py)

Command-line interface for mSCP.

Defines `parse_cli`, the top-level entry point invoked from
:mod:`mscp.__main__`. Builds an `argparse` tree with subcommands
``baseline`` / ``guidance`` / ``mapping`` / ``scap`` / ``admin`` (the
last with its own nested utilities) and dispatches to the matching
function in `mscp.generate` or `mscp.admin_utils`.


## Classes

### Customparser

```python
class Customparser(argparse.ArgumentParser)
```

`argparse.ArgumentParser` that logs errors via `loguru`.

Overrides `error` so usage failures are routed through the mSCP logger
(instead of stderr) before the help text is printed and the process
exits with status 2.


#### Methods

##### error

```python
error(self, message: str) -> None
```

Log `message` via `loguru`, print help, and exit with status 2.

**Args**

- **`message`** *(str)* — Error message reported by `argparse`.


### SmartFormatter

```python
class SmartFormatter(argparse.HelpFormatter)
```

Help formatter with two minor tweaks for the mSCP CLI.

- Single-letter / single-form options are indented to align with the
  long-form options for readability.
- Help strings prefixed with ``"R|"`` are emitted with their original
  newlines preserved (a common ``argparse`` recipe for raw text).


## Functions

### get_macos_version

```python
get_macos_version() -> float
```

Return the running host's major macOS version as a float.

Used as the default for the ``--os_version`` flag so the CLI assumes
the current host's version unless overridden. Falls back to ``26.0``
when `platform.mac_ver` returns an empty string (e.g. when run on a
non-macOS host).

**Returns**

- **`float`** — Major version (e.g. ``15.0``), or ``26.0`` on a non-macOS host.


### validate_file

```python
validate_file(arg: str) -> Path | None
```

`argparse` type validator: ensure ``arg`` points at an existing file.

Used as the ``type=`` argument on flags that take a path. Logs an
error and calls `sys.exit` if the path doesn't resolve to a file.

**Args**

- **`arg`** *(str)* — Raw command-line argument value.

**Returns**

- Path | None: The validated `Path`, or never returns when the file is missing (process exits).


### parse_cli

```python
parse_cli() -> None
```

Build the mSCP argument parser, parse `sys.argv`, and dispatch.

Constructs the top-level parser plus the ``baseline``, ``guidance``,
``mapping``, ``scap``, and ``admin`` subcommands (each with its own
flags), applies log-verbosity overrides, validates the platform/OS
arguments (rejects unsupported macOS / iOS versions), and then calls
the subcommand's bound ``func`` with the parsed `argparse.Namespace`.

**Side Effects**

- Reads ``sys.argv``; configures the global mSCP logger;
- mutates the global `config` dict for ``output_dir`` / ``rules_dir``;
- may call `sys.exit` on validation failure.
