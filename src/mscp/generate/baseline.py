# mscp/generate/baseline.py

# Standard python modules
import argparse
import sys
from pathlib import Path

# Additional python modules
from loguru import logger

# Local python modules
from src.mscp.classes import Author, Baseline, Macsecurityrule

# from src.mscp.classes.macsecurityrule import Macsecurityrule
from src.mscp.common_utils import (
    config,
    get_version_data,
    make_dir,
    open_yaml,
    sanitize_input,
)


def generate_baseline(args: argparse.Namespace) -> None:
    build_path: Path = Path(config.get("output_dir", ""), "baselines")
    baseline_output_file: Path = build_path / f"{args.keyword}.yaml"
    mscp_data: dict = open_yaml(Path(config.get("mspc_data", "")))
    baselines_data: dict = open_yaml(
        Path(config.get("includes_dir", ""), "800-53_baselines.yaml")
    )
    established_benchmarks: tuple = tuple(["stig", "cis_lvl1", "cis_lvl2"])
    benchmark: str = "recommended"
    full_title: str = args.keyword
    authors: list[Author] = []
    baseline_name: str = ""

    current_version_data: dict = get_version_data(args.os_name, args.os_version)
    all_rules: list[Macsecurityrule] = Macsecurityrule.collect_all_rules(
        args.os_name, args.os_version, parent_values="Default"
    )
    all_tags: list[str] = Macsecurityrule.get_tags(all_rules)

    if not build_path.exists():
        make_dir(build_path)
    else:
        for root, dirs, files in build_path.walk(top_down=False):
            for name in files:
                (root / name).unlink()
            for name in dirs:
                (root / name).rmdir()

    if args.list_tags:
        for tag in all_tags:
            print(tag)

        sys.exit()

    if args.controls:
        included_controls: list[str] = sorted(
            {control for rule in all_rules for control in rule.references.nist_controls}
        )

        needed_controls: list[str] = [
            control for control in baselines_data.get("low", [])
        ]

        for control in needed_controls:
            if control not in included_controls:
                logger.info(
                    f"{control} missing from any rule, needs a rule, or included in supplemental"
                )

        sys.exit()

    found_rules: list[Macsecurityrule] = [
        rule
        for rule in all_rules
        if args.keyword in rule.tags or args.keyword == "all_rules"
    ]

    if not args.keyword:
        logger.info(
            "No rules found for the keyword provided, please verify from the following list:"
        )
        logger.info(all_tags)
        for tag in all_tags:
            print(tag)

        sys.exit()

    if any(bm in args.keyword for bm in established_benchmarks):
        benchmark = args.keyword

    if args.keyword in mscp_data.get("authors", {}):
        author_dicts: dict = mscp_data["authors"][args.keyword]["names"]
        authors = [Author(**author) for author in author_dicts]

    if args.keyword in mscp_data["titles"] and not args.tailor:
        full_title = mscp_data["titles"][args.keyword]

    if args.tailor:
        full_title = ""
        tailored_filename: str = sanitize_input(
            f"Enter a name for your tailored benchmark or press Enter for the default value ({args.keyword}): ",
            str,
            default_=args.keyword,
        )
        custom_author_name: str = sanitize_input("Enter your name: ")
        custom_author_org: str = sanitize_input("Enter your organization: ")
        baseline_output_file = build_path / f"{tailored_filename}.yaml"
        authors.append(Author(name=custom_author_name, organization=custom_author_org))

        if tailored_filename == args.keyword:
            baseline_name = f"{tailored_filename} (Tailored)"
        else:
            baseline_name = (
                f"{tailored_filename.upper()} (Tailored from {args.keyword.upper()})"
            )

        odv_baseline_rules: list[Macsecurityrule] = Macsecurityrule.odv_query(
            found_rules, benchmark
        )

    Baseline.create_new(
        output_file=baseline_output_file,
        rules=odv_baseline_rules if args.tailor else found_rules,
        version_data=current_version_data,
        baseline_name=baseline_name,
        benchmark=benchmark,
        authors=authors,
        full_title=full_title,
    )
