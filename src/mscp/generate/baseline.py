# mscp/generate/baseline.py
"""Baseline YAML generation for the macOS Security Compliance Project.

Provides `generate_baseline`, which queries the rule library for a
given OS / keyword combination and writes a YAML baseline file.
Helper functions collect available tags and benchmarks, filter rules,
and handle the interactive tailoring workflow.
"""

# Standard python modules
import argparse
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# Local python modules
from ..classes import Author, Baseline, Macsecurityrule
from ..common_utils import (
    config,
    logger,
    make_dir,
    mscp_data,
    open_file,
    sanitize_input,
)


def collect_tags_and_benchmarks(
    rules: list[Macsecurityrule],
) -> tuple[list[str], dict[str, set[str]]]:
    """Collect all tags and benchmark-to-platform mappings from a rule list.

    Iterates every rule's ``tags`` and ``platforms`` data to build a sorted
    list of unique tags (with ``"all_rules"`` always appended) and a dict
    mapping each benchmark name to the set of OS types that declare it.

    Args:
        rules (list[Macsecurityrule]): Rules to inspect.

    Returns:
        tuple[list[str], dict[str, set[str]]]: ``(sorted_tags, benchmark_platforms)``
            where *benchmark_platforms* maps benchmark name → set of OS-type strings.
    """
    tags_set: set[str] = set()
    benchmark_platforms: dict[str, set[str]] = defaultdict(set)

    for rule in rules:
        for tag in rule.tags or []:
            tags_set.add(tag)

        for os_type, versions in (rule.platforms or {}).items():
            if not isinstance(versions, dict):
                continue
            for version_info in versions.values():
                if not isinstance(version_info, dict):
                    continue
                for benchmark in version_info.get("benchmarks", []):
                    if isinstance(benchmark, dict) and isinstance(
                        benchmark.get("name"), str
                    ):
                        benchmark_platforms[benchmark["name"]].add(os_type)

    tags_set.add("all_rules")

    return sorted(tags_set), benchmark_platforms


def collect_established_benchmarks(
    rules: list[Macsecurityrule],
) -> list[str]:
    """
    Attempts to collect all established benchmarks in the MSCP library. An established
    benchmark is one where an ODV has been defined for a given benchmark.

    Args:
       rules (list[Macsecurityrule]): A list of collected rules from the library.

    Returns:
        list: A sorted set of discovered benchmarks
    """
    established_benchmarks_set: set[str] = set()

    for rule in rules:
        for odv in rule.odv or []:
            established_benchmarks_set.add(odv)

    # remove "hint" from available benchmarks
    if "hint" in established_benchmarks_set:
        established_benchmarks_set.remove("hint")

    return sorted(established_benchmarks_set)


def print_keyword_summary(
    tags: list[str], benchmark_platforms: dict[str, set[str]]
) -> None:
    """Print available tags and benchmarks to stdout, then exit.

    Args:
        tags (list[str]): Sorted list of all available tag strings.
        benchmark_platforms (dict[str, set[str]]): Mapping of benchmark name
            to the set of OS-type strings on which it is defined.
    """
    logger.debug(tags)
    logger.debug(benchmark_platforms)

    print("Available keywords (tags and benchmarks):\n")

    print("Tags (applicable to all platforms):")
    for tag in sorted(tags):
        print(f"  {tag}")
    print()

    print("Benchmarks (platform-specific):")
    for benchmark in sorted(benchmark_platforms):
        platforms_str = ", ".join(sorted(benchmark_platforms[benchmark]))
        print(f"  {benchmark} (Platforms: {platforms_str})")
    print()

    sys.exit()


def rule_has_benchmark_for_version(
    rule: Macsecurityrule, keyword: str, os_type: str, os_version: str
) -> bool:
    """Return True if *rule* declares *keyword* as a benchmark for the given OS version.

    Args:
        rule (Macsecurityrule): Rule to inspect.
        keyword (str): Benchmark name to look for.
        os_type (str): OS type string (e.g. ``"macos"``); ``"os"`` is
            normalised to ``"OS"`` before the lookup.
        os_version (str): OS version string (e.g. ``"15"``).

    Returns:
        bool: ``True`` if the benchmark is listed under the rule's platforms
            entry for that OS type and version, ``False`` otherwise.
    """
    os_type = os_type.replace("os", "OS")
    platforms = rule.platforms or {}
    version_map = platforms.get(os_type, {})
    if not isinstance(version_map, dict):
        return False

    version_info = version_map.get(os_version)
    if not isinstance(version_info, dict):
        return False

    for benchmark in version_info.get("benchmarks", []):
        if isinstance(benchmark, dict) and benchmark.get("name") == keyword:
            return True

    return False


@logger.catch
def generate_baseline(args: argparse.Namespace, admin=False) -> None:
    """Generate a YAML baseline file for the specified OS and keyword.

    Collects all rules matching ``args.keyword`` (tag or benchmark name),
    optionally runs the interactive tailoring workflow, and writes the
    resulting baseline YAML to disk.

    Args:
        args (argparse.Namespace): Parsed CLI arguments.  Expected attributes:
            ``os_name``, ``os_version``, ``keyword``, ``tailor``,
            ``list_tags``, ``controls``.
        admin (bool): When ``True`` the output is written to the library's
            default baseline directory instead of the custom directory.
            Defaults to ``False``.
    """
    if admin:
        build_path: Path = (
            Path(config["defaults"].get("baseline_dir", "")) / args.os_name
        )
    else:
        build_path: Path = Path(config["custom"].get("baseline_dir", ""))
    baseline_output_file: Path = (
        build_path / f"{args.keyword}_{args.os_name}_{args.os_version}.yaml"
    )

    baselines_data: dict = open_file(
        Path(config.get("includes_dir", ""), "800-53_baselines.yaml")
    )

    benchmark: str = "recommended"
    full_title: str = args.keyword
    authors: list[Author] = []
    baseline_name: str | None = ""

    def replace_vars(text: str) -> str:
        os_list = (
            mscp_data.get("versions", {}).get("platforms", {}).get(args.os_name, [])
        )

        for entry in os_list:
            if entry.get("os_version") == args.os_version:
                os_name = entry.get("os_name").capitalize()

        match args.os_name:
            case "macos":
                clean_text = (
                    text.replace("$os_type", "macOS")
                    .replace("$os_version", str(args.os_version))
                    .replace("$os_name", os_name)
                )
            case "ios":
                clean_text = (
                    text.replace("($os_name) ", "")
                    .replace("$os_type", "iOS/iPadOS")
                    .replace("$os_version", str(args.os_version))
                )
            case "visionos":
                clean_text = text.replace("$os_type", "visionOS").replace(
                    "$os_version", str(args.os_version)
                )

        return clean_text

    if not build_path.exists():
        make_dir(build_path)

    all_rules: list[Macsecurityrule] = Macsecurityrule.collect_all_rules(
        args.os_name, args.os_version, args.tailor, parent_values="Default"
    )
    all_tags, benchmark_map = collect_tags_and_benchmarks(all_rules)

    established_benchmarks: tuple[str, ...] = collect_established_benchmarks(all_rules)

    if args.list_tags:
        print_keyword_summary(all_tags, benchmark_map)

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

    if (
        args.keyword not in all_tags
        and not args.keyword
        and args.keyword not in benchmark_map
    ):
        logger.info(
            "No rules found for the keyword provided, please verify from the following list:"
        )
        print_keyword_summary(all_tags, benchmark_map)

    found_rules = [
        rule
        for rule in all_rules
        if rule_has_benchmark_for_version(
            rule, args.keyword, args.os_name, str(args.os_version)
        )
        or (rule.tags is not None and args.keyword in rule.tags)
        # or any(item in misc_tags for item in rule.tags or [])
        or args.keyword == "all_rules"
    ]

    baseline_dict = {}

    if any(bm in args.keyword for bm in established_benchmarks):
        benchmark = args.keyword

    authors_dict: dict[str, Any] = mscp_data.get("authors", {})

    authors: list[Author] = []
    for author in authors_dict:
        if "mscp" in author["benchmarks"] or args.keyword in author["benchmarks"]:
            normalized_authors = author if isinstance(author, list) else [author]

            for each_author in normalized_authors:
                authors.append(Author(**each_author))

    if args.tailor:
        full_title = ""
        tailored_filename: str = sanitize_input(
            f"Enter a name for your tailored benchmark or press Enter for the default value ({args.keyword}): ",
            str,
            default_=args.keyword,
        ).replace(" ", "_")
        custom_author_name: str = sanitize_input("Enter your name: ")
        custom_author_org: str = sanitize_input("Enter your organization: ")
        baseline_output_file: Path = (
            build_path / f"{tailored_filename}_{args.os_name}_{args.os_version}.yaml"
        )
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
    if found_rules:
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

        try:
            display_path = Path(baseline_output_file).relative_to(Path.cwd())
        except ValueError:
            display_path = baseline_output_file
        print(f"Generated new baseline file containing {len(found_rules)} rules: {display_path}")
    else:
        logger.error(
            f"No rules found for {args.keyword} on {args.os_name} version {args.os_version}, skipping baseline generation."
        )
