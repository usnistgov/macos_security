import shutil
from pathlib import Path

import pytest

from mscp.classes import Macsecurityrule
from mscp.common_utils.config import config, set_custom_dir

FIXTURE_RULE = Path(__file__).parent / "fixtures" / "rules" / "test_version_specific_check.yaml"


@pytest.fixture
def custom_rules_dir(tmp_path: Path)-> Path:
    original = Path(config["custom_dir"])
    set_custom_dir(tmp_path)
    try:
        rules_dir = Path(config["custom"]["rules_dir"])
        rules_dir.mkdir(parents=True)
        shutil.copy(FIXTURE_RULE, rules_dir)
        yield rules_dir
    finally:
        set_custom_dir(original)


def _load(version: float) -> Macsecurityrule:
    rules = Macsecurityrule.load_rules(
        ["test_version_specific_check"], "macOS", version, "cis_lvl1", "test"
    )
    assert len(rules) == 1
    return rules[0]


def test_version_specific_check_overrides_generic(custom_rules_dir) -> None:
    rule = _load(26.0)
    assert rule.check == "echo version-specific"
    assert rule.result_value == "true"

def test_version_not_set_check_overrides_generic(custom_rules_dir) -> None:
    rule = _load(27.0)
    assert rule.check == "echo generic"
    assert rule.result_value == 1

def test_generic_check_used_when_version_has_no_override(custom_rules_dir) -> None:
    rule = _load(15.0)
    assert rule.check == "echo generic"
    assert rule.result_value == 1