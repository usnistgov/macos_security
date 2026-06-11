# mscp/admin_utils/rule_utilities.py
"""Interactive helpers for working with rule YAML files.

Currently provides `add_new_rule`, which scaffolds a placeholder rule
file under the configured custom rules directory.
"""

# Standard python modules
import argparse
from pathlib import Path

# Local python modules
from ..common_utils import (
    config,
    logger,
    sanitize_input,
    mscp_data,
    open_file,
    create_file,
    PLATFORM_MAP,
    SCHEMA_PATH,
    conditional_inject_spinner,
)

from yaspin.core import Yaspin
from yaspin.spinners import Spinners
from ..classes import Macsecurityrule


def get_rule_file(rule_id: str, rules_dir: Path) -> Path | None:
    """Given a rule_id and rules_dir, return the path for the rule yaml file.
    If there is no direct match based on file name, review the contents of all the
    rule yaml files to return the possible rule file path.

    Args:
        rule_id (str): The ID of the rule to look up
        rules_dir (Path): The location to look for the rule files
    """
    rule_file = next(rules_dir.rglob(f"{rule_id}.y*ml"), None)

    if rule_file:
        return rule_file
    for possible_rule_file in rules_dir.rglob("*.y*ml"):
        if open_file(possible_rule_file).get("id") == rule_id:
            return possible_rule_file
    return None


def add_new_rule(args: argparse.Namespace) -> None:
    """Scaffold a new placeholder rule YAML in the custom rules directory.

    Prompts for a title and unique rule ID, builds a minimal
    `Macsecurityrule` populated with placeholder values (mechanism
    ``"Configuration Profile"``, section ``"auditing"``, NIST references
    empty), and serialises it to
    ``<custom_rules_dir>/<rule_id>.yaml`` for the user to fill in.

    Args:
        args (argparse.Namespace): Parsed CLI arguments; only `os_name`
            is consumed (used for both `os_name` and `os_type` on the
            scaffolded rule).

    Side Effects:
        Writes a YAML file to disk and prompts on stdin via
        `sanitize_input`.
    """
    logger.info("Building new rule for MSCP...")

    build_path: Path = Path(config["custom"].get("rules_dir", ""))

    rule_title: str = sanitize_input("Enter a title for the new rule: ")
    rule_id: str = sanitize_input("Enter a unique ID for the new rule: ")

    references = {"nist": {}}

    new_rule_dict = {
        "title": rule_title,
        "rule_id": rule_id,
        "discussion": "discuss all the things",
        "references": references,
        "mechanism": "Configuration Profile",
        "os_name": args.os_name,
        "os_type": args.os_name,
        "section": "auditing",
    }

    new_rule = Macsecurityrule(**new_rule_dict)

    rule_output_file: Path = build_path / f"{rule_id}.yaml"
    new_rule.to_yaml(rule_output_file)


def add_version_to_rules(
    platform: str, previous_version: float, new_version: float
) -> None:
    new_version_str = str(new_version)
    previous_version_str = str(previous_version)

    rules_dir = config["rules_dir"]
    platform = PLATFORM_MAP[platform]

    logger.info(f"Updating rules for {platform} to include {new_version}")

    updated_rules = []
    for rule in rules_dir.rglob("*.y*ml"):
        rule_yaml = open_file(rule)
        rule_platforms = rule_yaml.get("platforms", {})
        if platform not in rule_platforms:
            continue
        if previous_version_str in rule_platforms[platform]:
            new_platform = {new_version_str: {}}
            updated_platforms = dict(new_platform, **rule_yaml["platforms"][platform])
            rule_yaml["platforms"][platform] = updated_platforms
            updated_rules.append(rule)
            create_file(rule, rule_yaml)

    logger.info(f"Updated {len(updated_rules)} rules for {platform}")


def ensure_path(d, path):
    for key in path:
        d = d.setdefault(key, {})
    return d


def add_version_to_schema(
    platform: str, previous_version: float, new_version: float
) -> None:
    new_version_str = str(new_version)
    previous_version_str = str(previous_version)

    schema_data_file: Path = Path(SCHEMA_PATH)

    schema_data = open_file(schema_data_file)

    platform = PLATFORM_MAP[platform]
    schema_platforms = ensure_path(
        schema_data, ["properties", "platforms", "properties", platform, "properties"]
    )

    if previous_version_str in schema_platforms.keys():
        schema_platforms[new_version_str] = {"$ref": "#/$defs/osDef"}

        create_file(schema_data_file, schema_data)
    else:
        print(f"{previsou_version_str} not found in {schema_platforms.keys()}")


@conditional_inject_spinner()
def update_mscp_apple_release(sp: Yaspin, args: argparse.Namespace) -> None:
    sp.spinner = Spinners.dots

    mscp_data_file: Path = Path(config["mscp_data"])
    mscp_data_file_updated = False

    platforms = mscp_data.get("versions", {}).get("platforms", {})

    sp.text = f"Updating mscp_data.yaml with information for version {args.new_version}"
    for platform_name, items in platforms.items():
        current_latest = max(items, key=lambda x: float(x["os_version"]))

        if platform_name == "macos":
            new_name = args.new_name
        else:
            new_name = f"{platform_name}_{int(args.new_version)}"

        new_release = {
            "os_version": args.new_version,
            "os_name": new_name,
            "revision": 1.0,
            "cpe": f"o:apple:{platform_name}:{args.new_version}",
        }

        if not any(
            d["os_version"] == args.new_version
            for d in mscp_data["versions"]["platforms"][platform_name]
        ):
            logger.info(
                f"Updating mscp_data.yaml with {args.new_version} for {platform_name}"
            )

            mscp_data["versions"]["platforms"][platform_name].insert(0, new_release)

            sp.text = f"Updating MSCP rules with {args.new_version} for {platform_name}"
            add_version_to_rules(
                platform_name, current_latest["os_version"], args.new_version
            )
            add_version_to_schema(
                platform_name, current_latest["os_version"], args.new_version
            )
            mscp_data_file_updated = True
        else:
            logger.warning(
                f"{args.new_version} already exists for {platform_name}, skipping"
            )

    if mscp_data_file_updated:
        create_file(mscp_data_file, mscp_data)
        sp.text = f"DONE: mscp_data.yaml has been updated with information for version {args.new_version}"
        sp.ok("✔")
    else:
        sp.text = f"No updates needed for version {args.new_version}"
        sp.ok("✔")

    return
