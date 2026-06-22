# mscp/generate/guidance_support/manifest.py
"""JSON manifest generation for mSCP baselines.

Provides `generate_manifest`, which serializes baseline metadata and
per-rule details (references, check command, fix payload) into a single
JSON file used by downstream tooling to identify and audit rules.
"""

# Standard python modules
import datetime
from pathlib import Path
from typing import Any


# Additional python modules

# Local python modules
from ...common_utils import get_version_data, mscp_data, create_json

# TODO: add proper logging to module


def generate_manifest(build_path: Path, baseline_name: str, baseline) -> None:
    """Write a JSON manifest summarising the baseline and all its rules.

    The manifest includes platform metadata, release info, plist and log
    paths, and a list of rules with their IDs, titles, references, tags,
    check commands, and fix payloads (mobileconfig, DDM, or script).

    Args:
        build_path (Path): Output directory; the manifest is written as
            ``<build_path>/<baseline_name>.json``.
        baseline_name (str): Name of the baseline (used for file naming and
            plist/log path strings).
        baseline: Loaded ``Baseline`` object containing profiles and platform info.
    """

    audit_name: str = str(baseline_name)
    current_version_data: dict[str, Any] = get_version_data(
        baseline.platform["os"], baseline.platform["version"], mscp_data
    )
    manifest_output_file: Path = build_path / f"{baseline_name}.json"
    manifest = {}
    manifest["benchmark"] = audit_name
    manifest["parent_values"] = baseline.parent_values
    manifest["platform"] = {
        "os": baseline.platform["os"],
        "version": baseline.platform["version"],
        "cpe": current_version_data["cpe"],
    }
    manifest["release_info"] = {
        "version": mscp_data["mscp"]["version"],
        "build": mscp_data["mscp"]["build"],
        "date": mscp_data["mscp"]["build_date"],
    }
    manifest["plist_location"] = "/Library/Preferences/org.{}.audit.plist".format(
        baseline_name
    )
    manifest["log_location"] = "/Library/Logs/{}_baseline.log".format(baseline_name)
    manifest["creation_date"] = (
        datetime.datetime.now().replace(microsecond=0).isoformat()
    )
    manifest["rules"] = []
    for profile in baseline.profile:
        for rule in profile.rules:
            rule_manifest = {}
            rule_manifest["id"] = rule.rule_id
            rule_manifest["title"] = rule.title
            rule_manifest["discussion"] = rule.discussion
            ref_parts = []
            # TODO: visit this to properly handle the exception
            for _org, refs in rule.references:
                if refs:
                    for item in refs:
                        try:
                            k, v = item
                            if v is not None:
                                vals = ",".join(str(i) for i in v)
                                if k == "benchmark":
                                    k = "cis_benchmark"
                                if k == "controls_v8":
                                    k = "cis_controls_v8"
                                ref_parts.append(f"{k}|{vals}")
                        except ValueError:
                            continue
            rule_manifest["references"] = ";".join(str(x) for x in ref_parts)
            rule_manifest["tags"] = ",".join(str(x) for x in rule.tags)
            if rule.check:
                rule_manifest["check"] = rule.check
                rule_manifest["result"] = rule.result_value
            rule_manifest["fix"] = {}
            if rule.mobileconfig_info:
                rule_manifest["fix"]["mobile_config_info"] = []
                for mc_info in rule.mobileconfig_info:
                    profile = {}
                    for content in mc_info.payload_content:
                        profile["domain"] = mc_info.payload_type
                        for k, v in content.items():
                            profile["key"] = k
                            profile["value"] = v
                    rule_manifest["fix"]["mobile_config_info"].append(profile)
            if rule.ddm_info:
                rule_manifest["fix"]["ddm_info"] = {}
                for ddminfo, value in rule.ddm_info.items():
                    rule_manifest["fix"]["ddm_info"].update({ddminfo: value})
            if rule.fix:
                rule_manifest["fix"]["script"] = rule.fix
            manifest["rules"].append(rule_manifest)

    create_json(manifest_output_file, manifest)
