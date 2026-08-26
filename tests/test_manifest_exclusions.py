"""Regression proof for excluded rules leaking into the JSON manifest."""

from __future__ import annotations

import json
import plistlib
from pathlib import Path

import pytest

from mscp.classes import Baseline
from mscp.generate.guidance_support import generate_manifest, generate_profiles

INCLUDED_RULE_ID = "os_gatekeeper_enable"
EXCLUDED_RULE_ID = "os_airdrop_disable"
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "manifest_with_excluded_rule.yaml"


@pytest.fixture(scope="module")
def baseline_with_excluded_rule() -> Baseline:
    """Load the smallest native baseline with one included and one excluded rule."""
    return Baseline.from_yaml(FIXTURE_PATH)


def test_from_yaml_preserves_excluded_classification(
    baseline_with_excluded_rule: Baseline,
) -> None:
    sections = {
        rule.rule_id: rule.section
        for profile in baseline_with_excluded_rule.profile
        for rule in profile.rules
    }

    assert sections[INCLUDED_RULE_ID] == "Operating System"
    assert sections[EXCLUDED_RULE_ID] == "Excluded Rules"


def test_manifest_omits_excluded_rules(
    tmp_path: Path,
    baseline_with_excluded_rule: Baseline,
) -> None:
    generate_manifest(tmp_path, "v164_manifest", baseline_with_excluded_rule)

    manifest = json.loads((tmp_path / "v164_manifest.json").read_text())
    rule_ids = [rule["id"] for rule in manifest["rules"]]

    assert INCLUDED_RULE_ID in rule_ids
    assert EXCLUDED_RULE_ID not in rule_ids


def test_configuration_profiles_omit_excluded_rules(
    tmp_path: Path,
    baseline_with_excluded_rule: Baseline,
) -> None:
    generate_profiles(tmp_path, "v164_profiles", baseline_with_excluded_rule)

    unsigned = tmp_path / "mobileconfigs" / "unsigned"
    included_profile = unsigned / "com.apple.systempolicy.control.mobileconfig"
    excluded_profile = unsigned / "com.apple.applicationaccess.mobileconfig"

    assert included_profile.is_file()
    assert not excluded_profile.exists()

    with included_profile.open("rb") as profile_file:
        generated = plistlib.load(profile_file)

    assert any(
        payload.get("PayloadType") == "com.apple.systempolicy.control"
        and payload.get("EnableAssessment") is True
        for payload in generated["PayloadContent"]
    )
