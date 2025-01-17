# mscp/generate/baseline.py

# Standard python modules
import logging
import argparse
import sys
import re

from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict
from uuid import uuid4
from icecream import ic

# Additional python modules

# Local python modules
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_yaml, make_dir
from src.mscp.classes.baseline import Baseline, Author
from src.mscp.classes.macsecurityrule import MacSecurityRule
from src.mscp.common_utils.sanatize_input import sanitised_input


# Initialize local logger
logger = logging.getLogger(__name__)


def generate_baseline(args: argparse.Namespace) -> None:
    build_path: Path = Path(config.get("output_dir", ""), "baseline")
    baseline_output_file: Path = build_path / f"{args.keyword}.yaml"
    mscp_data: dict = open_yaml(Path(config.get("mspc_data", "")))
    baselines_data: dict = open_yaml(Path(config.get("includes_dir", ""), "800-53_baselines.yaml"))
    established_benchmarks: tuple = tuple(['stig', 'cis_lvl1', 'cis_lvl2'])
    benchmark: str = "recommended"
    full_title: str = args.keyword
    authors: List[Author] = []
    baseline_name: str = ""

    os_version: float = float(args.os_version)
    version_file: Path = Path(config["includes_dir"], "version.yaml")
    version_data: dict = open_yaml(version_file)
    current_version_data = next((entry for entry in version_data.get("platforms", {}).get(args.os_name, []) if entry.get("os") == os_version), {})
    all_rules: List[MacSecurityRule] = MacSecurityRule.collect_all_rules(args.os_name, args.os_version, parent_values="Default")

    uuid = lambda: uuid4().hex
    ic(str(uuid))
    print(uuid)
    sys.exit()
    if not build_path.exists():
        make_dir(build_path)
    else:
        for root,dirs,files in build_path.walk(top_down=False):
            for name in files:
                (root / name).unlink()
            for name in dirs:
                (root / name).rmdir()

    all_tags: List[str] = sorted(
        {tag for rule in all_rules for tag in rule.tags}
    )

    all_tags.append("all_rules")
    all_tags.sort()

    if args.list_tags:
        for tag in all_tags:
            print(tag)

        sys.exit()

    if args.controls:
        included_controls: List[str] = sorted(
            {control for rule in all_rules for control in rule.nist_controls}
        )

        needed_controls: List[str] = [control for control in baselines_data.get("low", [])]

        for control in needed_controls:
            if control not in included_controls:
                logger.info(f"{control} missing from any rule, needs a rule, or included in supplemental")

        sys.exit()

    found_rules: List[MacSecurityRule] = [
        rule for rule in all_rules
        if args.keyword in rule.tags or args.keyword == "all_rules"
    ]

    if not args.keyword:
        logger.info("No rules found for the keyword provided, please verify from the following list:")
        logger.info(all_tags)
        sys.exit()

    if any(bm in args.keyword for bm in established_benchmarks):
        benchmark = args.keyword

    if args.keyword in mscp_data.get("Author", {}):
        author_dicts: dict = mscp_data["Author"][args.keyword]["names"]
        authors = [Author(**author) for author in author_dicts]

    if args.keyword in mscp_data['titles'] and not args.tailor:
        full_title = mscp_data['titles'][args.keyword]

    if args.talor:
        full_title = ""
        tailored_filename: str = sanitised_input(f'Enter a name for your tailored benchmark or press Enter for the default value ({args.keyword}): ', str, default_=args.keyword)
        custom_author_name: str = sanitised_input('Enter your name: ')
        custom_author_org: str = sanitised_input('Enter your organization: ')
        baseline_output_file = build_path / f"{tailored_filename}.yaml"
        authors.append(Author(name=custom_author_name, organization=custom_author_org))

        if tailored_filename == args.keyword:
            baseline_name = f"{tailored_filename} (Tailored)"
        else:
            baseline_name = f"{tailored_filename.upper()} (Tailored from {args.keyword.upper()})"

        odv_baseline_rules: List[MacSecurityRule] = MacSecurityRule.odv_query(found_rules, benchmark)

    Baseline.create_new(
        output_file = baseline_output_file,
        rules = odv_baseline_rules if args.talor else found_rules,
        version_data = current_version_data,
        baseline_name = baseline_name,
        benchmark = benchmark,
        authors = authors,
        full_title = full_title
    )
