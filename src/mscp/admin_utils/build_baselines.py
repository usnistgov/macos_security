# mscp/admin_utils/build_all_baselines.py
"""Bulk-rebuild every supported baseline.

Wires up the ``mscp admin baselines`` subcommand: discovers all rules
for the requested platform, derives the set of benchmarks and tags
they cover, then drives `generate_baseline` once per
benchmark-and-platform pair plus once per remaining tag-and-platform
pair.
"""

# Standard python modules
import argparse
from pathlib import Path

# Local python modules
from ..common_utils import (
    config,
    logger,
    mscp_data,
    remove_dir_contents,
)
from ..common_utils import logging_config
from ..classes.rule_library import RuleLibrary
from ..generate import (
    generate_baseline,
)
from ..generate.baseline import (
    collect_tags_and_benchmarks,
)


def build_all_baselines(args: argparse.Namespace) -> None:
    """Regenerate every default baseline file for the configured platforms.

    Clears `config["baseline_dir"]`, collects every rule for
    `args.os_name` / `args.os_version`, derives the set of benchmarks and
    tags from those rules, and then calls `generate_baseline` once per
    discovered benchmark (per its own platform list) and once per
    remaining tag for every supported platform in
    `mscp_data["versions"]["platforms"]`. A small set of housekeeping tags
    (``arm64``, ``i368``, ``inherent``, ``manual``, ``n_a``, ``none``,
    ``permanent``) is excluded from the second pass.

    Args:
        args (argparse.Namespace): Parsed CLI arguments. Required fields:
            ``os_name``, ``os_version``. The function additionally sets
            ``tailor``, ``list_tags``, ``controls``, ``keyword``, and
            ``os_name`` on the namespace as it iterates — callers should
            treat the namespace as scratch space.

    Side Effects:
        Deletes the contents of the default baseline directory and writes
        new baseline YAML files into it.
    """
    logger.info("Building all supported baselines...")
    logging_config.suppress_spinner = True

    # clear existing default baselines
    baselines_dir = Path(config.get("baseline_dir", ""))
    remove_dir_contents(baselines_dir)

    # set default args expected by generate_baseline
    args.tailor = False
    args.list_tags = False
    args.controls = False

    # exclude generating baselines for these keys
    excluded_tags = {
        "arm64",
        "i386",
        "inherent",
        "manual",
        "n_a",
        "none",
        "permanent",
        "supplemental",
        "800-53r5_privacy",
    }

    library = RuleLibrary.from_rules_dir()
    all_tags, benchmark_map = collect_tags_and_benchmarks(list(library))

    all_tags[:] = [x for x in all_tags if x not in excluded_tags]

    # cache rules per (platform, version) so generate_baseline doesn't re-collect on every call
    platform_rules = {
        platform: list(library.by_platform(platform).by_os(os_version=float(args.os_version)))
        for platform in mscp_data["versions"]["platforms"]
    }

    # process every discovered benchmark and generate a baseline file
    for keyword, platforms in benchmark_map.items():
        args.keyword = keyword
        for platform in platforms:
            args.os_name = platform.lower()
            generate_baseline(args, admin=True, preloaded_rules=platform_rules.get(args.os_name, []))

    # process every discovered tag and generate a baseline file for every supported platform
    for platform in mscp_data["versions"]["platforms"]:
        args.os_name = platform

        for tag in all_tags:
            args.keyword = tag
            generate_baseline(args, admin=True, preloaded_rules=platform_rules[platform])
