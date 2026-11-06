"""Regression proof for the inherent / permanent / n_a enforcement mechanisms."""

from __future__ import annotations

from pathlib import Path

import pytest

from mscp.classes import Baseline, Macsecurityrule

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "special_section_rules.yaml"

INHERENT_RULE_ID = "os_application_sandboxing"
PERMANENT_RULE_ID = "audit_off_load_records"
NOT_APPLICABLE_RULE_ID = "os_information_validation"


@pytest.fixture(scope="module")
def rules_by_id() -> dict[str, Macsecurityrule]:
    """Load the fixture baseline and index its rules by rule ID."""
    baseline = Baseline.from_yaml(FIXTURE_PATH)
    return {
        rule.rule_id: rule for profile in baseline.profile for rule in profile.rules
    }


def test_inherent_rule(rules_by_id: dict[str, Macsecurityrule]) -> None:
    rule = rules_by_id[INHERENT_RULE_ID]

    assert "inherent" in rule.tags
    assert rule.mechanism == "Inherent"
    assert rule.fix == "The control cannot be configured out of compliance."


def test_permanent_rule(rules_by_id: dict[str, Macsecurityrule]) -> None:
    rule = rules_by_id[PERMANENT_RULE_ID]

    assert "permanent" in rule.tags
    assert rule.mechanism == "Permanent"
    assert rule.fix is not None
    assert "third-party solution" in rule.fix


def test_not_applicable_rule(rules_by_id: dict[str, Macsecurityrule]) -> None:
    rule = rules_by_id[NOT_APPLICABLE_RULE_ID]

    assert "n_a" in rule.tags
    assert rule.mechanism == "N/A"
    assert rule.fix == (
        "The control is not applicable when configuring a macOS system."
    )
