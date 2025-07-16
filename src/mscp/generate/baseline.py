# mscp/generate/baseline.py

# Standard python modules
import argparse
import sys
from pathlib import Path
from typing import Any

# Local python modules
from ..classes import Author, Baseline, Macsecurityrule
from ..common_utils import config, make_dir, open_file, sanitize_input
from ..common_utils.logger_instance import logger


def generate_baseline(args: argparse.Namespace) -> None:
    build_path: Path = Path(config.get("output_dir", ""), "baselines")
    baseline_output_file: Path = build_path / f"{args.keyword}.yaml"
    mscp_data: dict[str, Any] = open_file(Path(config.get("mspc_data", "")))
    baselines_data: dict = open_file(
        Path(config.get("includes_dir", ""), "800-53_baselines.yaml")
    )
    established_benchmarks: tuple[str, ...] = ("stig", "cis_lvl1", "cis_lvl2")
    benchmark: str = "recommended"
    full_title: str = args.keyword
    authors: list[Author] = []
    baseline_name: str | None = None

    def replace_vars(text: str) -> str:
        return text.replace("$os_type", str(args.os_name.replace("os", "OS"))).replace(
            "$os_version", str(args.os_version)
        )

    if not build_path.exists():
        make_dir(build_path)

    all_rules: list[Macsecurityrule] = Macsecurityrule.collect_all_rules(
        args.os_name, args.os_version, parent_values="Default"
    )

    all_tags: list[str] = sorted(
        set(
            tag
            for rule in all_rules
            for tag in (rule.tags or [])
            if "800-53r4" not in tag
        )
        | {"all_rules"}
    )

    if args.list_tags:
        logger.debug(all_tags)
        for tag in all_tags:
            print(tag)

        sys.exit()

    if args.controls:
        included_controls: list[str] = sorted(
            {
                control
                for rule in all_rules
                for control in (rule.references.nist.nist_800_53r5 or [])
            }
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

    if not args.keyword:
        logger.info(
            "No rules found for the keyword provided, please verify from the following list:"
        )
        logger.debug(all_tags)
        for tag in all_tags:
            print(tag)

        sys.exit()

    baseline_dict: dict[str, Any] = mscp_data.get("baselines", {}).get(args.keyword, {})

    if not baseline_dict:
        logger.warning(f"No baseline found for keyword: {args.keyword}")

    found_rules: list[Macsecurityrule] = [
        rule
        for rule in all_rules
        if args.keyword in rule.tags or args.keyword == "all_rules"
    ]

    baseline_dict["title"] = replace_vars(baseline_dict["title"])
    baseline_dict["description"] = replace_vars(baseline_dict["description"])

    if any(bm in args.keyword for bm in established_benchmarks):
        benchmark = args.keyword

    authors: list[Author] = [
        Author(**author)
        for group in baseline_dict.get("authors", [])
        for author in (group if isinstance(group, list) else [group])
    ]

    baseline_dict.pop("authors", None)

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
        baseline_name=baseline_name,
        benchmark=benchmark,
        authors=authors,
        full_title=full_title,
        os_type=args.os_name,
        os_version=args.os_version,
        baseline_dict=baseline_dict,
    )
