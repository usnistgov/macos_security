---
title: mscp.common_utils.version_data
description: "Lookup helper for per-OS / per-version metadata."
---

> Source: [`src/mscp/common_utils/version_data.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/common_utils/version_data.py)

Lookup helper for per-OS / per-version metadata.

Exposes `get_version_data`, which resolves the entry for a given
``(os_name, os_version)`` from the ``versions.platforms`` block of the
project metadata loaded in `mscp_data`.


## Functions

### get_version_data

```python
get_version_data(os_name: str, os_version: float, mscp_data: dict[str, Any]) -> dict[str, Any]
```

Return the metadata entry for an OS / version pair.

Looks up ``mscp_data["versions"]["platforms"][os_name]`` and returns
the entry whose ``os_version`` matches. Unknown OS names or versions
raise `ValueError`; other parse errors are logged and yield an empty
dict so callers can proceed with defaults.

**Args**

- **`os_name`** *(str)* — Operating system family (e.g. ``"macOS"``, ``"ios"``); compared case-insensitively.
- **`os_version`** *(float)* — Version (e.g. ``15.0``).
- **`mscp_data`** *(dict[str, Any])* — Project metadata as produced by `get_mscp_data`.

**Returns**

- dict[str, Any]: The matching version entry, or ``{}`` on a non-`ValueError` parse failure.

**Raises**

- **`ValueError`** — If `os_name` isn't in the platforms dict, or no version entry has the requested `os_version`. The message includes the valid options.
