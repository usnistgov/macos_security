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
    empty), and serializes it to
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
    """Add a new OS version entry to every rule that already carries the previous version.

    Scans all rule YAML files under `config["rules_dir"]`.  For each rule
    that targets `platform` and already has `previous_version` listed, a
    new empty-dict entry keyed on `new_version` is prepended to that
    platform's version map and the file is written back to disk.

    Args:
        platform (str): Short platform key (e.g. `"macos"`); resolved
            through `PLATFORM_MAP` before matching.
        previous_version (float): The existing version whose presence
            determines which rules are updated.
        new_version (float): The version entry to insert into qualifying
            rules.
    """
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
    """Walk a nested dict, creating intermediate dicts as needed, and return the deepest node.

    Args:
        d (dict): The root dictionary to traverse.
        path (Iterable): Sequence of keys forming the path to the target node.

    Returns:
        dict: The dict at the end of `path`, newly created if absent.
    """
    for key in path:
        d = d.setdefault(key, {})
    return d


def add_version_to_schema(
    platform: str, previous_version: float, new_version: float
) -> None:
    """Insert a new OS version entry into the MSCP JSON schema.

    Reads the schema file at `SCHEMA_PATH`, locates the properties block for
    `platform`, and — if `previous_version` is already present — adds a
    `$ref` entry for `new_version`.  The updated schema is written back to
    disk.  If `previous_version` is not found, a message is printed and no
    changes are made.

    Args:
        platform (str): Short platform key (e.g. `"macos"`); resolved
            through `PLATFORM_MAP` before matching.
        previous_version (float): The existing version that must be present
            in the schema before the new entry is added.
        new_version (float): The version to register under
            `#/properties/platforms/properties/<platform>/properties`.
    """
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
        logger.warning(f"{previous_version_str} not found in {schema_platforms.keys()}")


def remove_version_from_rules(platform: str, version: float) -> None:
    """Remove an OS version entry from every rule that carries it.

    Scans all rule YAML files under ``config["rules_dir"]``.  For each rule
    that targets ``platform`` and has ``version`` as a key, the entry is
    deleted and the file is written back to disk.

    Args:
        platform (str): Short platform key (e.g. ``"macos"``); resolved
            through ``PLATFORM_MAP`` before matching.
        version (float): The version entry to remove from qualifying rules.
    """
    version_str = str(version)
    rules_dir = config["rules_dir"]
    platform = PLATFORM_MAP[platform]

    logger.info(f"Removing {version_str} from rules for {platform}")

    updated_rules = []
    for rule in rules_dir.rglob("*.y*ml"):
        rule_yaml = open_file(rule)
        rule_platforms = rule_yaml.get("platforms", {})
        if platform not in rule_platforms:
            continue
        if version_str in rule_platforms[platform]:
            del rule_yaml["platforms"][platform][version_str]
            updated_rules.append(rule)
            create_file(rule, rule_yaml)

    logger.info(f"Removed {version_str} from {len(updated_rules)} rules for {platform}")


def remove_version_from_schema(platform: str, version: float) -> None:
    """Remove an OS version entry from the MSCP JSON schema.

    Reads the schema file at ``SCHEMA_PATH``, locates the properties block
    for ``platform``, and deletes the entry for ``version`` if present.
    The updated schema is written back to disk.

    Args:
        platform (str): Short platform key (e.g. ``"macos"``); resolved
            through ``PLATFORM_MAP`` before matching.
        version (float): The version to remove from the schema.
    """
    version_str = str(version)
    schema_data_file: Path = Path(SCHEMA_PATH)
    schema_data = open_file(schema_data_file)
    platform = PLATFORM_MAP[platform]

    schema_platforms = ensure_path(
        schema_data, ["properties", "platforms", "properties", platform, "properties"]
    )

    if version_str in schema_platforms:
        del schema_platforms[version_str]
        create_file(schema_data_file, schema_data)
    else:
        logger.warning(f"{version_str} not found in schema for {platform}, skipping")


@conditional_inject_spinner()
def remove_mscp_apple_release(sp: Yaspin, args: argparse.Namespace) -> None:
    """Remove an Apple OS release from mscp_data, rules, and the schema.

    For each platform tracked in ``mscp_data["versions"]["platforms"]``, if
    ``args.version`` is present, this function:

    1. Removes the release entry from ``mscp_data.yaml``.
    2. Calls ``remove_version_from_rules()`` to delete the version key from
       every applicable rule file.
    3. Calls ``remove_version_from_schema()`` to unregister the version from
       the MSCP JSON schema.

    Args:
        sp (Yaspin): Spinner instance injected by ``@conditional_inject_spinner``.
        args (argparse.Namespace): Parsed CLI arguments.  Consumed fields:

            * ``version`` — the OS version string to remove (e.g. ``"15.5"``).

    Side Effects:
        May update ``mscp_data.yaml``, rule YAML files, and the schema file
        on disk.
    """
    sp.spinner = Spinners.dots

    mscp_data_file: Path = Path(config["mscp_data"])
    mscp_data_file_updated = False

    platforms = mscp_data.get("versions", {}).get("platforms", {})

    sp.text = f"Removing version {args.version} from mscp_data.yaml"
    for platform_name, items in platforms.items():
        match = next((d for d in items if d["os_version"] == args.version), None)
        if match is None:
            logger.warning(f"{args.version} not found for {platform_name}, skipping")
            continue

        logger.info(f"Removing {args.version} from mscp_data.yaml for {platform_name}")
        mscp_data["versions"]["platforms"][platform_name].remove(match)

        sp.text = f"Removing {args.version} from rules for {platform_name}"
        remove_version_from_rules(platform_name, args.version)
        remove_version_from_schema(platform_name, args.version)
        mscp_data_file_updated = True

    if mscp_data_file_updated:
        create_file(mscp_data_file, mscp_data)
        sp.text = f"DONE: version {args.version} has been removed"
        sp.ok("✔")
    else:
        sp.text = f"No updates needed for version {args.version}"
        sp.ok("✔")


@conditional_inject_spinner()
def update_mscp_apple_release(sp: Yaspin, args: argparse.Namespace) -> None:
    """Register a new Apple OS release across mscp_data, rules, and the schema.

    For each platform tracked in ``mscp_data["versions"]["platforms"]``, if
    ``args.version`` is not already listed, this function:

    1. Prepends a new release entry to ``mscp_data.yaml``.
    2. Calls `add_version_to_rules()` to propagate the version into
       every applicable rule file.
    3. Calls `add_version_to_schema()` to register the version in the
       MSCP JSON schema.

    Progress is reported through the injected ``Yaspin`` spinner.

    Args:
        sp (Yaspin): Spinner instance injected by `@conditional_inject_spinner`;
            used for progress text and completion status.
        args (argparse.Namespace): Parsed CLI arguments.  Consumed fields:

            * ``version`` — the OS version string to add (e.g. ``"15.5"``).
            * ``new_name`` — the human-readable name used for macOS releases
              (e.g. ``"Sequoia"``); other platforms derive their name
              automatically.

    Side Effects:
        May update ``mscp_data.yaml``, rule YAML files, and the schema file
        on disk.
    """
    sp.spinner = Spinners.dots

    mscp_data_file: Path = Path(config["mscp_data"])
    mscp_data_file_updated = False

    platforms = mscp_data.get("versions", {}).get("platforms", {})

    sp.text = f"Updating mscp_data.yaml with information for version {args.version}"
    for platform_name, items in platforms.items():
        current_latest = max(items, key=lambda x: float(x["os_version"]))

        if platform_name == "macos":
            new_name = args.new_name
        else:
            new_name = f"{platform_name}_{int(args.version)}"

        new_release = {
            "os_version": args.version,
            "os_name": new_name,
            "cpe": f"o:apple:{platform_name}:{args.version}",
        }

        if not any(
            d["os_version"] == args.version
            for d in mscp_data["versions"]["platforms"][platform_name]
        ):
            logger.info(
                f"Updating mscp_data.yaml with {args.version} for {platform_name}"
            )

            mscp_data["versions"]["platforms"][platform_name].insert(0, new_release)

            sp.text = f"Updating MSCP rules with {args.version} for {platform_name}"
            add_version_to_rules(
                platform_name, current_latest["os_version"], args.version
            )
            add_version_to_schema(
                platform_name, current_latest["os_version"], args.version
            )
            mscp_data_file_updated = True
        else:
            logger.warning(
                f"{args.version} already exists for {platform_name}, skipping"
            )

    if mscp_data_file_updated:
        create_file(mscp_data_file, mscp_data)
        sp.text = f"DONE: mscp_data.yaml has been updated with information for version {args.version}"
        sp.ok("✔")
    else:
        sp.text = f"No updates needed for version {args.version}"
        sp.ok("✔")

    return
