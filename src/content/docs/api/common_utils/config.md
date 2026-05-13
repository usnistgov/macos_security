---
title: mscp.common_utils.config
description: "Project configuration loader."
---

> Source: [`src/mscp/common_utils/config.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/common_utils/config.py)

Project configuration loader.

At import time this module loads ``config.yaml`` shipped under the
package's ``data/`` directory and resolves every relative path inside
it. Bundled package paths (rules, baselines, templates, etc.) are
rebased onto the package's data directory; user-facing paths
(``output_dir``, ``custom_dir``) are rebased onto the current working
directory unless absolute. The result is exposed as the module-level
`config` dict, which most other mSCP modules import directly.

`ensure_custom_dirs` creates the custom directory tree on disk
(typically called once at CLI startup), and `set_custom_dir` rebinds
every ``custom`` entry to a new base directory after `config` is
already loaded.


## Functions

### ensure_custom_dirs

```python
ensure_custom_dirs() -> None
```

Create the custom directory tree on disk if it isn't already there.

Iterates every value in ``config["custom"]`` (resolved at import
time from `custom_dir`) and `mkdir(parents=True, exist_ok=True)`s
it. Safe to call repeatedly; intended to run once on CLI startup.


### set_custom_dir

```python
set_custom_dir(path: Path) -> None
```

Rebase every ``config["custom"][...]`` entry onto a new directory.

Each existing custom path's relative offset from the previous
`_custom_base` is preserved underneath ``path``. Also updates
``config["custom_dir"]`` and the module-level `_custom_base` so
subsequent calls compose correctly.

**Args**

- **`path`** *(Path)* — New absolute base directory for custom files.
