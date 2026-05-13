---
title: mscp.common_utils.spinner_utils
description: "Verbosity-aware wrapper around `yaspin`'s `inject_spinner`."
sidebar:
  order: 1
---

> Source: [`src/mscp/common_utils/spinner_utils.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/common_utils/spinner_utils.py)

Verbosity-aware wrapper around `yaspin`'s `inject_spinner`.

When verbose logging is active, log lines and a spinner clobber each
other in the terminal. `conditional_inject_spinner` injects the spinner
only when `logging_config.verbose_logging` is false; otherwise it runs
the wrapped function with a stopped spinner so the log output stays
clean.


## Functions

### conditional_inject_spinner

```python
conditional_inject_spinner(**spinner_kwargs)
```

Decorator factory that injects a `yaspin` spinner only when quiet.

Behaves like `yaspin.inject_spinner` (the spinner is started before
the wrapped call and stopped after), but skips both start and stop
when `logging_config.verbose_logging` is true. The wrapped function
receives the spinner as its first positional argument.

**Args**

- **`**spinner_kwargs`** — Keyword arguments forwarded to `yaspin()` to configure the spinner (e.g. ``text=...``, ``color=...``).

**Returns**

- **`Callable`** — A decorator that wraps a function so it runs with a (possibly inert) spinner injected as its first argument.
