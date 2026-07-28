# src/mscp/validate_rules.py
"""Schema and folder-structure validators for rule YAML files.

Wires up the ``mscp admin validate`` subcommand. `validate_yaml_file`
walks the configured rules directory (plus any custom rules) and
validates each file against ``schema/mscp_rule.json``;
`validate_rule_folder_structure` is an `argparse` type validator that
makes sure ``--rules_dir`` points at a properly organized tree.
`get_rule_identifier` is a small helper that prefers a rule file's
``id`` field, falling back to its filename stem.
"""

# Standard python modules
import argparse
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

# Local python modules
from . import SCHEMA_PATH, config, open_file
from .logger_instance import logger

# Additional python modules


def get_rule_identifier(rule_file: Path) -> str:
    """Return the rule's canonical ID, preferring the YAML ``id`` field.

    Falls back to the filename stem when the YAML doesn't define one.

    Args:
        rule_file (Path): Path to a rule YAML file.

    Returns:
        str: The rule's identifier.
    """
    rule_yaml = open_file(rule_file)

    if "id" in rule_yaml:
        return rule_yaml["id"]
    else:
        return rule_file.stem


def get_benchmark_names(platforms: dict) -> set:
    """Collect every benchmark ``name`` referenced across a rule's platforms.

    Args:
        platforms (dict): The rule's ``platforms`` mapping (e.g. macOS,
            iOS, visionOS), each keyed by OS version.

    Returns:
        set: All benchmark names found under any platform/OS version.
    """
    names: set = set()
    for platform_data in platforms.values():
        if not isinstance(platform_data, dict):
            continue
        for os_data in platform_data.values():
            if not isinstance(os_data, dict):
                continue
            for benchmark in os_data.get("benchmarks", []) or []:
                if isinstance(benchmark, dict) and "name" in benchmark:
                    names.add(benchmark["name"])
    return names


def validate_odv_benchmarks(data: dict) -> list:
    """Check that non-``recommended`` odv keys map to a benchmark in platforms.

    ``odv`` keys other than ``hint`` and ``recommended`` are expected to
    correspond to a benchmark ``name`` listed somewhere under the rule's
    ``platforms`` object (e.g. ``cis_lvl1``, ``disa_stig``). Keys that
    don't match any benchmark usually indicate a typo or a stale odv
    entry left over from a benchmark that was removed from ``platforms``.

    Args:
        data (dict): A parsed rule YAML document.

    Returns:
        list: Human-readable error messages, one per unmatched odv key.
    """
    odv = data.get("odv")
    if not odv:
        return []

    benchmark_names = get_benchmark_names(data.get("platforms", {}))
    unknown_keys = sorted(
        key for key in odv if key not in ("hint", "recommended") and key not in benchmark_names
    )

    return [
        f"odv key '{key}' does not match any benchmark name under platforms "
        f"(available: {', '.join(sorted(benchmark_names)) or 'none'})"
        for key in unknown_keys
    ]


def validate_yaml_file(args: argparse.Namespace) -> None:
    """Validate every rule YAML against ``schema/mscp_rule.json``.

    Loads the schema, then iterates either ``args.rules_dir`` (if set)
    or the default rules tree plus any custom rules. Prints / logs a
    line per file: ``✅ VALID``, ``❌ INVALID``, or ``⚠️ ERROR``. Files
    with duplicate rule identifiers are flagged with a warning. Also
    cross-checks ``odv`` keys against the benchmark names declared under
    ``platforms`` (see `validate_odv_benchmarks`).

    Args:
        args (argparse.Namespace): Parsed CLI arguments. Reads
            ``rules_dir`` (override) and ``all_validation`` (when true,
            successful files are also printed).
    """
    schema: dict = open_file(Path(SCHEMA_PATH))
    validator = Draft202012Validator(schema)

    rules_path = Path(config["rules_dir"])
    yaml_files: list = list(rules_path.rglob("*.y*ml"))
    _custom_rules = Path(config["custom"]["rules_dir"])
    if _custom_rules.exists():
        yaml_files += list(_custom_rules.rglob("*.y*ml"))

    if not yaml_files:
        logger.error("No YAML files found in rules directory.")
        return

    logger.info(f"Validating {len(yaml_files)} YAML files in '{rules_path}'...\n")

    discovered_rules = []
    error_found = False
    for yaml in yaml_files:
        data: dict = open_file(yaml)
        rule_id: str = data.get("id", yaml.stem)

        if rule_id.startswith("supplemental"):
            continue

        if rule_id in discovered_rules:
            print(f"⚠️ WARNING:   {yaml} may be a duplicate or tailored rule")
        else:
            discovered_rules.append(rule_id)

        try:
            errors = list(validator.iter_errors(data))
        except Exception as e:
            print(f"⚠️ ERROR:   {yaml} → {e}")
            logger.error(f"⚠️ ERROR:   {yaml} → {e}")
            continue

        odv_issues = validate_odv_benchmarks(data)

        if errors or odv_issues:
            error_found = True
            for e in errors:
                path = " -> ".join(str(p) for p in e.path) if e.path else "root"
                print(f"❌ INVALID: {yaml} → [{path}] {e.message}")
                logger.warning(f"❌ INVALID: {yaml} → [{path}] {e.message}")
            for msg in odv_issues:
                print(f"❌ INVALID: {yaml} → [odv] {msg}")
                logger.warning(f"❌ INVALID: {yaml} → [odv] {msg}")
        else:
            if args.all_validation:
                print(f"✅ VALID:   {yaml}")
                logger.info(f"✅ VALID:   {yaml}")

    if error_found:
        sys.exit(1)

    print("✅ All YAML files passed validation.")
    logger.success("✅ All YAML files passed validation.")


def validate_rule_folder_structure(path_str: str) -> Path:
    """
    Argparse 'type' validator:
    - Ensures PATH exists and is a directory.
    - Ensures root contains only subdirectories (no files).
    - Ensures each subdir contains only YAML files and/or is empty.
    - Disallows nested directories under subfolders (can be toggled).
    """
    ALLOWED_EXTS = {".yaml", ".yml"}

    from ..classes.macsecurityrule import Sectionmap

    p = Path(path_str).expanduser().resolve()
    if not p.exists():
        raise argparse.ArgumentTypeError(f"Path does not exist: {p}")
    if not p.is_dir():
        raise argparse.ArgumentTypeError(f"Path is not a directory: {p}")

    # # Inspect contents of root
    root_entries = list(p.iterdir())

    # Root must contain only subdirectories (if you want to allow files, relax this).
    for e in root_entries:
        if e.name.startswith("."):
            continue
        if e.is_file():
            raise argparse.ArgumentTypeError(
                f"Rule files need to be organized in subfolders. '{e.name}' found in root of folder."
            )

    # For each subdirectory: must contain only .yaml/.yml files (or be empty)
    for sub in (e for e in root_entries if e.is_dir()):
        if not sub.name.upper() in Sectionmap.__members__:
            raise argparse.ArgumentTypeError(
                f"'{sub.name}' is not a valid folder name, please organize into the following folders [{', '.join([section.name.lower() for section in Sectionmap])}]. "
            )

        for child in sub.iterdir():
            if child.name.startswith("."):
                continue
            if child.is_dir():
                raise argparse.ArgumentTypeError(
                    f"'{sub.name}' contains a nested directory '{child.name}'. "
                    "Only YAML files are expected in subfolders."
                )
            if child.is_file() and child.suffix.lower() not in ALLOWED_EXTS:
                raise argparse.ArgumentTypeError(
                    f"'{sub.name}' contains non-YAML file '{child.name}'. "
                    "Allowed extensions: .yaml, .yml"
                )

    return p  # On success, return a canonical Path
