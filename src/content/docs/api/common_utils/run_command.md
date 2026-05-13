---
title: mscp.common_utils.run_command
description: "Logged subprocess wrapper used across mSCP."
---

> Source: [`src/mscp/common_utils/run_command.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/common_utils/run_command.py)

Logged subprocess wrapper used across mSCP.

`run_command` runs a shell command via `subprocess.run` after splitting
it with `shlex.split`, logs the invocation, and returns
``(stdout, error)`` tuples so callers don't have to manage exceptions.


## Functions

### run_command

```python
run_command(command: str, capture_output: bool=True, text: bool=True, check: bool=True) -> tuple[str | None, str | None]
```

Run a shell command and return ``(stdout, error)``.

The command string is split with `shlex.split` (so simple quoting
works but shell features like pipes do not). All exceptions from
`subprocess.run` are caught and surfaced via the second tuple
element instead of being raised.

**Args**

- **`command`** *(str)* — Shell command to execute.
- **`capture_output`** *(bool)* — Forwarded to `subprocess.run`. When false, stdout / stderr go to the parent's streams. Defaults to ``True``.
- **`text`** *(bool)* — Forwarded to `subprocess.run`; when false the return tuple's first element is always ``None``. Defaults to ``True``.
- **`check`** *(bool)* — Forwarded to `subprocess.run`. When true (default), non-zero exits become a `CalledProcessError` that this function turns into a non-`None` second tuple element.

**Returns**

- tuple[str | None, str | None]: ``(stdout, None)`` on success, ``(None, error_message)`` on failure. With ``text=False`` the successful tuple is ``(None, None)``.
