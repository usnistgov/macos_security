# admin/__init__.py
"""Administrative utilities exposed via ``mscp admin``.

Re-exports `build_all_baselines` (rebuilds every supported baseline) and
`add_new_rule` (interactive helper to scaffold a new rule YAML). Both are
wired up as `argparse` subcommands in `mscp.cli`.
"""

from .build_baselines import build_all_baselines
from .rule_utilities import add_new_rule
from .logo_generator import generate_mscp_banners


__all__ = [
    "build_all_baselines",
    "add_new_rule",
    "generate_mscp_banners",
]
