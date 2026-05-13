---
title: mscp.admin_utils.build_baselines
description: "Bulk-rebuild every supported baseline."
sidebar:
  order: 1
---

> Source: [`src/mscp/admin_utils/build_baselines.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/admin_utils/build_baselines.py)

Bulk-rebuild every supported baseline.

Wires up the ``mscp admin baselines`` subcommand: discovers all rules
for the requested platform, derives the set of benchmarks and tags
they cover, then drives `generate_baseline` once per
benchmark-and-platform pair plus once per remaining tag-and-platform
pair.


## Functions

### build_all_baselines

```python
build_all_baselines(args: argparse.Namespace) -> None
```

Regenerate every default baseline file for the configured platforms.

Clears `config["baseline_dir"]`, collects every rule for
`args.os_name` / `args.os_version`, derives the set of benchmarks and
tags from those rules, and then calls `generate_baseline` once per
discovered benchmark (per its own platform list) and once per
remaining tag for every supported platform in
`mscp_data["versions"]["platforms"]`. A small set of housekeeping tags
(``arm64``, ``i368``, ``inherent``, ``manual``, ``n_a``, ``none``,
``permanent``) is excluded from the second pass.

**Args**

- **`args`** *(argparse.Namespace)* — Parsed CLI arguments. Required fields: ``os_name``, ``os_version``. The function additionally sets ``tailor``, ``list_tags``, ``controls``, ``keyword``, and ``os_name`` on the namespace as it iterates — callers should treat the namespace as scratch space.

**Side Effects**

- Deletes the contents of the default baseline directory and writes
- new baseline YAML files into it.
