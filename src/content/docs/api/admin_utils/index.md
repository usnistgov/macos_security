---
title: mscp.admin_utils
description: "Administrative utilities exposed via ``mscp admin``."
---

> Source: [`src/mscp/admin_utils/__init__.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/admin_utils/__init__.py)

Administrative utilities exposed via ``mscp admin``.

Re-exports `build_all_baselines` (rebuilds every supported baseline) and
`add_new_rule` (interactive helper to scaffold a new rule YAML). Both are
wired up as `argparse` subcommands in `mscp.cli`.


## Re-exports (`__all__`)

`build_all_baselines`, `add_new_rule`
