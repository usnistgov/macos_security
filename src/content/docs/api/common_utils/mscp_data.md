---
title: mscp.common_utils.mscp_data
description: "Loader for the mSCP project metadata file."
---

> Source: [`src/mscp/common_utils/mscp_data.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/common_utils/mscp_data.py)

Loader for the mSCP project metadata file.

Exposes `get_mscp_data` (re-readable accessor) and `mscp_data` (a
module-level dict populated at import time from the path configured
under `config["mscp_data"]`). This metadata holds version info,
supported platform lists, and other build constants consumed by the
CLI and generators.


## Functions

### get_mscp_data

```python
get_mscp_data() -> dict[str, Any]
```

Read and return the project metadata dict from disk.

The file path is taken from ``config["mscp_data"]``. Errors are
swallowed and an empty dict is returned (after a logger error) so
that import-time failure of this module doesn't take the whole CLI
down.

**Returns**

- dict[str, Any]: Parsed contents of the mSCP metadata file, or an empty dict if the file is missing or unparseable.
