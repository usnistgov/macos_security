# mscp/generate/script.py
"""Compliance and restore shell script generation for mSCP baselines.

Provides `generate_script` (audit compliance script) and
`generate_restore_script` (defaults-restore script), both rendered from
Jinja templates.  `generate_audit_plist` writes the companion audit plist.
Jinja filter helpers `group_ulify`, `generate_log_reference`, and
`quotify` are also defined here.
"""

# Standard python modules
from datetime import date
from itertools import groupby
from pathlib import Path
# Additional python modules
from jinja2 import Environment, FileSystemLoader

# Local python modules
from ...classes import Baseline, Macsecurityrule
from ...common_utils import config, create_file, logger, make_dir, mscp_data, search_paths, NIX_OS


def group_ulify(elements: list[str]) -> str:
    """
    Converts a list of strings into a grouped unordered list format.

    This function is used as a Jinja filter to format a list of strings.
    It groups the elements by their prefix (before the first parenthesis),
    sorts them, and then formats them into a string with each group
    represented as an unordered list.

    Args:
        elements (list[str]): The list of strings to be formatted.

    Returns:
        str: A formatted string representing the grouped unordered list.
        If the input is "N/A", it returns "- N/A".
    """
    if elements == "N/A":
        return "- N/A"

    elements.sort()
    grouped = [list(i) for _, i in groupby(elements, lambda a: a.split("(")[0])]
    result = ""
    for group in grouped:
        if not result:
            result += "\n# * " + ", ".join(group)
        else:
            result += "\n  # * " + ", ".join(group)
    return result.strip()


def generate_log_reference(rule: Macsecurityrule, reference: str) -> list[str] | str:
    """
    Generate the log reference ID based on the rule and reference type.

    Note:
        This is used as a Jinja filter in the script template.
    """
    log_reference_id: list[str] | str
    try:
        log_references = rule.references.get_ref(reference)
    except KeyError:
        logger.warning(
            f'Unable to find the reference "{reference}" in rule "{rule.rule_id}"'
        )
        log_references = []
    if reference == "default" or not log_references:
        log_reference_id = rule.rule_id
    else:
        log_reference_id = f"{', '.join(map(str, log_references))}"
    return log_reference_id


def quotify(fix_code: str) -> str:
    """
    Escape single quotes and format percentages for Bash.

    Note:
        This is used as a Jinja filter in the script template.
    """
    if not isinstance(fix_code, str):
        raise TypeError("Expected a string for fix_code")

    string = fix_code.replace("'", "'\"'\"'")
    string = string.replace("%", "%%")
    return string


def generate_audit_plist(
    build_path: Path, baseline_name: str, baseline: Baseline
) -> None:
    """Write the default audit plist (``org.<baseline_name>.audit.plist``).

    Creates a plist where each non-supplemental rule ID maps to
    ``{"exempt": False}``, used as the initial state for compliance auditing.

    Args:
        build_path (Path): Root output directory; plist goes in ``preferences/``.
        baseline_name (str): Baseline name used in the plist filename and
            ``/Library/Preferences`` path.
        baseline (Baseline): Baseline whose rules populate the plist keys.
    """
    plist_output_path: Path = build_path / "preferences"
    plist_file_path: Path = plist_output_path / f"org.{baseline_name}.audit.plist"

    logger.info("Generating default audit plist.")
    logger.debug(f"Output Path for default audit plist: {plist_file_path}")
    logger.debug(f"Output file for default audit plist: {plist_file_path}")

    if not plist_output_path.exists():
        make_dir(plist_output_path)

    plist_dict = {
        profile_rule.rule_id: {"exempt": False}
        for sections in baseline.profile
        for profile_rule in sections.rules
        if not profile_rule.rule_id.startswith("supplemental")
    }

    try:
        create_file(plist_file_path, plist_dict)

        logger.info("Generated default audit plist.")

    except IOError as e:
        logger.error(f"Error occurred: {e}")


def generate_script(
    build_path: Path,
    baseline_name: str,
    audit_name: str,
    baseline: Baseline,
    log_reference: str,
    current_version_data: dict,
) -> None:
    """Render and write the compliance audit shell script for *baseline*.

    Uses the ``compliance_script.sh.jinja`` template and also calls
    `generate_audit_plist`.  Skips non-Unix platforms.

    Args:
        build_path (Path): Output directory; script written as
            ``<baseline_name>_compliance.sh`` with mode ``0755``.
        baseline_name (str): Baseline name used in filenames and template variables.
        audit_name (str): Audit identifier string passed to the template.
        baseline (Baseline): Loaded baseline object.
        log_reference (str): Log reference key (e.g. ``"default"`` or a
            framework name) passed to the template.
        current_version_data (dict): Version metadata for the OS/baseline.
    """
    if not baseline.platform["os"].lower() in NIX_OS:
        logger.warning(
            f"Platform {baseline.platform['os']} does not support shell scripts, skipping generation."
        )
        return

    output_file: Path = Path(build_path, f"{baseline_name}_compliance.sh")
    env: Environment = Environment(
        loader=FileSystemLoader(search_paths("shell_template_dir")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    script_template = env.get_template("compliance_script.sh.jinja")

    env.filters["group_ulify"] = group_ulify
    env.filters["log_reference"] = generate_log_reference
    env.filters["quotify"] = quotify

    rendered_output = script_template.render(
        baseline=baseline,
        baseline_name=baseline_name,
        audit_name=audit_name,
        reference_log_id=log_reference,
        todays_date=date.today().strftime("%Y-%m-%d"),
        mscp_release=current_version_data["compliance_version"],
        mscp_version=mscp_data.get("mscp", {}),
    )

    generate_audit_plist(build_path, baseline_name, baseline)
    output_file.write_text(rendered_output, encoding="UTF-8")
    output_file.chmod(0o755)


def generate_restore_script(
    build_path: Path,
    baseline_name: str,
    audit_name: str,
    baseline: Baseline,
    log_reference: str,
    current_version_data: dict,
) -> None:
    """Render and write the restore shell script for *baseline* (if applicable).

    Uses the ``restore_script.sh.jinja`` template.  Only writes the file if at
    least one rule has a ``default_state`` value, and skips non-Unix platforms.

    Args:
        build_path (Path): Output directory; script written as
            ``<baseline_name>_restore.sh`` with mode ``0755``.
        baseline_name (str): Baseline name used in filenames and template variables.
        audit_name (str): Audit identifier string passed to the template.
        baseline (Baseline): Loaded baseline object.
        log_reference (str): Log reference key passed to the template.
        current_version_data (dict): Version metadata for the OS/baseline.
    """
    if not baseline.platform["os"].lower() in NIX_OS:
        logger.warning(
            f"Platform {baseline.platform['os']} does not support shell scripts, skipping generation."
        )
        return

    output_file: Path = Path(build_path, f"{baseline_name}_restore.sh")
    env: Environment = Environment(
        loader=FileSystemLoader(search_paths("shell_template_dir")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    script_template = env.get_template("restore_script.sh.jinja")

    env.filters["group_ulify"] = group_ulify
    env.filters["log_reference"] = generate_log_reference
    env.filters["quotify"] = quotify

    any_rendered = any(
        rule.default_state
        for p in baseline.profile
        for rule in p.rules
    )

    rendered_output = script_template.render(
        baseline=baseline,
        baseline_name=baseline_name,
        audit_name=audit_name,
        reference_log_id=log_reference,
        todays_date=date.today().strftime("%Y-%m-%d"),
        mscp_release=current_version_data["compliance_version"],
        mscp_version=mscp_data.get("mscp", {}),
    )

    if any_rendered:
        output_file.write_text(rendered_output, encoding="UTF-8")
        output_file.chmod(0o755)
