# mscp/generate/script.py

# Standard python modules
import re

from pathlib import Path
from icecream import ic
from itertools import groupby
from dataclasses import asdict
from typing import Dict, Any, List

# Additional python modules
from jinja2 import Environment, FileSystemLoader
from loguru import logger

# Local python modules
from src.mscp.common_utils.config import config
from src.mscp.classes.baseline import Baseline
from src.mscp.common_utils.file_handling import make_dir, create_plist


@logger.catch
def group_ulify(elements):
    if elements == "N/A":
        return "- N/A"

    elements.sort()
    grouped = [list(i) for _, i in groupby(elements, lambda a: a.split("(")[0])]
    result = ""
    for group in grouped:
        result += "\n# * " + ", ".join(group)
    return result.strip()


@logger.catch
def generate_log_reference(rule_yaml: Dict[str, Any], reference: str) -> List[str]:
    """
    Generate the log reference ID based on the rule_yaml and reference type.
    """
    if not isinstance(rule_yaml, dict):
        raise TypeError("Expected a dictionary for rule_yaml")
    if not isinstance(reference, str):
        raise TypeError("Expected a string for reference")

    cis_ref = ["cis", "cis_lvl1", "cis_lvl2", "cisv8"]

    if reference == "default":
        log_reference_id = [rule_yaml["rule_id"]]
    elif reference in cis_ref:
        if "v8" in reference:
            log_reference_id = [
                f"CIS Controls-{', '.join(map(str, rule_yaml['references']['cis']['controls v8']))}"
            ]
        else:
            log_reference_id = [
                f"CIS-{rule_yaml['references']['cis']['benchmark'][0]}"
            ]
    else:
        try:
            # Try to find the reference directly
            rule_yaml["references"][reference]
        except KeyError:
            try:
                # Try to find it in custom references
                rule_yaml["references"]["custom"][reference]
            except KeyError:
                # Fallback to default
                log_reference_id = [rule_yaml["rule_id"]]
            else:
                # If found in custom references
                if isinstance(rule_yaml["references"]["custom"][reference], list):
                    log_reference_id = (
                        rule_yaml["references"]["custom"][reference]
                        + [[rule_yaml["rule_id"]]]
                    )
                else:
                    log_reference_id = [
                        rule_yaml["references"]["custom"][reference],
                        [rule_yaml["rule_id"]],
                    ]
        else:
            # If found in standard references
            if isinstance(rule_yaml["references"][reference], list):
                log_reference_id = rule_yaml["references"][reference] + [rule_yaml["rule_id"]]
            else:
                log_reference_id = [rule_yaml["references"][reference]] + [rule_yaml["rule_id"]]

    return log_reference_id


@logger.catch
def quotify(fix_code: str) -> str:
    """Escape single quotes and format percentages for Bash."""
    if not isinstance(fix_code, str):
        raise TypeError("Expected a string for fix_code")

    string = fix_code.replace("'", "'\"'\"'")
    string = string.replace("%", "%%")
    return string


def get_fix_code(fix_yaml: str) -> str:
    """Extract fix code from the YAML block."""
    if not isinstance(fix_yaml, str):
        raise TypeError("Expected a string for fix_yaml")

    fix_string = fix_yaml.split("[source,bash]")[1]
    fix_code = re.search(r"(?:----((?:.*?\r?\n?)*)----)+", fix_string)

    if fix_code is None:
        raise ValueError("No fix code found in the provided YAML block")

    return fix_code.group(1)


@logger.catch
def escape_double_quotes(text: str) -> str:
    """Escape double quotes for Bash."""
    if not isinstance(text, str):
        raise TypeError("Expected a string for text")
    return text.replace('"', '\\"')


@logger.catch
def generate_audit_plist(build_path: Path, baseline_name: str, baseline: Baseline) -> None:
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
        create_plist(plist_file_path, plist_dict)

        logger.info("Generated default audit plist.")

    except IOError as e:
        logger.error(f"Error occurred: {e}")


def generate_script(build_path: Path, baseline_name: str, audit_name: str, baseline: Baseline, log_referance: str) -> None:
    output_file: Path = Path(build_path, f"{baseline_name}_compliance.sh")
    env: Environment = Environment(loader=FileSystemLoader(config["shell_template_dir"]), trim_blocks=True, lstrip_blocks=True)
    script_template = env.get_template('compliance_script.sh.jinja')

    env.filters['group_ulify'] = group_ulify
    env.filters['log_reference'] = generate_log_reference
    env.filters['get_fix_code'] = get_fix_code
    env.filters['quotify'] = quotify


    for profile in baseline.profile:
        for rule in profile.rules:
            rule.check = escape_double_quotes(rule.check)
            rule.fix = escape_double_quotes(rule.fix)

    baseline_dict: Dict[str, Any] = asdict(baseline)

    rendered_output = script_template.render(
        baseline=baseline_dict,
        baseline_name=baseline_name,
        audit_name=audit_name
    )

    output_file.write_text(rendered_output, encoding='UTF-8')
    output_file.chmod(0o755)
