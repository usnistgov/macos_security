"""Regression tests for launchd-backed service-disable rules.

Issue #870 exposed a distinction that the original checks did not model:
``launchctl print-disabled`` reports persisted enable/disable overrides, not the
effective default from the service's launchd plist.  A default-disabled service
that has never been enabled therefore has no matching override and was reported
as noncompliant.  The checks must also distinguish a loaded but inactive job
from a running job; both produce nonempty ``launchctl print`` output.

The tests execute the shell stored in each production rule.  Only the absolute
``/bin/launchctl`` path is replaced with a temporary read-only test double, so
no service is loaded, enabled, disabled, started, or stopped.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

from mscp.classes import Baseline
from mscp.classes.macsecurityrule import resolve_enforcement_info
from mscp.common_utils import get_version_data, mscp_data
from mscp.generate.guidance_support.script import generate_script

REPOSITORY_ROOT = Path(__file__).parent.parent
RULES_DIRECTORY = REPOSITORY_ROOT / "src/mscp/data/rules/system_settings"
SERVICE_RULES = {
    "system_settings_smbd_disable": "com.apple.smbd",
    "system_settings_rae_disable": "com.apple.AEServer",
}
SUPPORTED_MACOS_VERSIONS = ("15.0", "26.0", "27.0")

ORIGINAL_SECURITY_METADATA = {
    "system_settings_smbd_disable": {
        "nist_800_53r5": ["AC-3", "AC-17"],
        "disa_cci": ["CCI-000213"],
        "cis_controls_v8": [4.1, 4.8, 5.4],
        "fix": "/bin/launchctl disable system/com.apple.smbd",
    },
    "system_settings_rae_disable": {
        "nist_800_53r5": ["AC-3", "AC-17"],
        "disa_cci": ["CCI-000213", "CCI-000382"],
        "cis_controls_v8": [4.1, 4.8],
        "fix": (
            "/usr/sbin/systemsetup -setremoteappleevents off\n"
            "/bin/launchctl disable system/com.apple.AEServer"
        ),
    },
}


def _load_rule(rule_id: str) -> dict:
    with (RULES_DIRECTORY / f"{rule_id}.yaml").open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def _disabled_output(*entries: tuple[str, str]) -> str:
    lines = ["", "\tdisabled services = {"]
    lines.extend(f'\t\t"{label}" => {state}' for label, state in entries)
    lines.append("\t}")
    return "\n".join(lines) + "\n"


def _missing_service_output(label: str) -> str:
    return f'Bad request.\nCould not find service "{label}" in domain for system\n'


def _service_output(label: str, state: str, *, pid: int | None = None) -> str:
    lines = [
        f"system/{label} = {{",
        "\tactive count = 0" if state == "not running" else "\tactive count = 1",
        f"\tpath = /System/Library/LaunchDaemons/{label}.plist",
        "\ttype = LaunchDaemon",
        f"\tstate = {state}",
        "",
    ]
    if pid is not None:
        lines.append(f"\tpid = {pid}")
    lines.extend(["", "\tproperties = system service", "}"])
    return "\n".join(lines) + "\n"


@pytest.fixture
def fake_launchctl(tmp_path: Path) -> Path:
    executable = tmp_path / "launchctl"
    executable.write_text(
        """#!/bin/sh
if [ "$1" = "print-disabled" ] && [ "$2" = "system" ]; then
    printf '%s' "$MOCK_DISABLED_STDOUT"
    printf '%s' "$MOCK_DISABLED_STDERR" >&2
    exit "${MOCK_DISABLED_STATUS:-0}"
fi

if [ "$1" = "print" ]; then
    printf '%s' "$MOCK_SERVICE_STDOUT"
    printf '%s' "$MOCK_SERVICE_STDERR" >&2
    exit "${MOCK_SERVICE_STATUS:-0}"
fi

printf '%s\n' "unexpected launchctl arguments: $*" >&2
exit 64
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def _run_check(
    rule_id: str,
    fake_launchctl: Path,
    *,
    disabled_stdout: str,
    disabled_status: int = 0,
    disabled_stderr: str = "",
    service_stdout: str = "",
    service_status: int = 0,
    service_stderr: str = "",
) -> str:
    rule = _load_rule(rule_id)
    enforcement = resolve_enforcement_info(rule["platforms"]["macOS"], "27.0")
    check = enforcement["check"]["shell"].replace("/bin/launchctl", str(fake_launchctl))
    environment = os.environ | {
        "MOCK_DISABLED_STDOUT": disabled_stdout,
        "MOCK_DISABLED_STDERR": disabled_stderr,
        "MOCK_DISABLED_STATUS": str(disabled_status),
        "MOCK_SERVICE_STDOUT": service_stdout,
        "MOCK_SERVICE_STDERR": service_stderr,
        "MOCK_SERVICE_STATUS": str(service_status),
    }
    completed = subprocess.run(
        ["/bin/bash", "-c", check],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    return completed.stdout.strip()


def _case_inputs(label: str, case: str) -> dict:
    absent = {
        "disabled_stdout": _disabled_output(),
        "service_status": 113,
        "service_stderr": _missing_service_output(label),
    }
    if case == "never_enabled":
        return absent
    if case == "explicitly_disabled":
        return absent | {"disabled_stdout": _disabled_output((label, "disabled"))}
    if case == "enabled_inactive":
        return {
            "disabled_stdout": _disabled_output((label, "enabled")),
            "service_stdout": _service_output(label, "not running"),
        }
    if case.startswith("running_"):
        override = case.removeprefix("running_")
        entries = () if override == "no_override" else ((label, override),)
        return {
            "disabled_stdout": _disabled_output(*entries),
            "service_stdout": _service_output(label, "running", pid=321),
        }
    if case == "loaded_inactive":
        output = _service_output(label, "not running").replace(
            "\tproperties = system service",
            f"\tproperties = system service\n\tmetadata = {label} is inactive",
        )
        return {"disabled_stdout": _disabled_output(), "service_stdout": output}
    if case == "service_query_failure":
        return {
            "disabled_stdout": _disabled_output(),
            "service_status": 1,
            "service_stderr": f"launchctl unavailable while querying {label}\n",
        }
    if case == "missing_service_nonstandard_status":
        return absent | {"service_status": 1}
    if case == "empty_service_output":
        return {"disabled_stdout": _disabled_output(), "service_stdout": ""}
    if case == "disabled_query_failure":
        return absent | {
            "disabled_stdout": "",
            "disabled_status": 1,
            "disabled_stderr": f"launchctl unavailable while querying {label}\n",
        }
    if case == "empty_disabled_output":
        return absent | {"disabled_stdout": ""}
    if case == "unrelated_overrides":
        return absent | {
            "disabled_stdout": _disabled_output(
                ("com.apple.unrelated", "enabled"),
                (f"{label}.helper", "enabled"),
            )
        }
    if case in {"duplicate_override", "ambiguous_override"}:
        states = (
            ("disabled", "disabled")
            if case == "duplicate_override"
            else ("disabled", "enabled")
        )
        return absent | {
            "disabled_stdout": _disabled_output(*((label, state) for state in states))
        }
    if case == "malformed_override":
        output = _disabled_output().replace("\t}", f'\t\t"{label}" = enabled\n\t}}')
        return absent | {"disabled_stdout": output}
    if case == "duplicate_service_state":
        output = _service_output(label, "not running").replace(
            "\tstate = not running",
            "\tstate = not running\n\tstate = not running",
        )
        return {"disabled_stdout": _disabled_output(), "service_stdout": output}
    if case == "mismatched_service_record":
        return {
            "disabled_stdout": _disabled_output(),
            "service_stdout": _service_output(f"{label}.helper", "not running"),
        }
    raise AssertionError(f"unknown test case: {case}")


@pytest.mark.parametrize("rule_id,label", SERVICE_RULES.items())
@pytest.mark.parametrize(
    "case,expected",
    [
        ("never_enabled", "PASS"),
        ("explicitly_disabled", "PASS"),
        ("enabled_inactive", "FAIL  ENABLED"),
        ("running_no_override", "FAIL  RUNNING"),
        ("running_enabled", "FAIL  RUNNING"),
        ("running_disabled", "FAIL  RUNNING"),
        ("loaded_inactive", "PASS"),
        ("service_query_failure", "FAIL  ERROR"),
        ("missing_service_nonstandard_status", "PASS"),
        ("empty_service_output", "FAIL  ERROR"),
        ("disabled_query_failure", "FAIL  ERROR"),
        ("empty_disabled_output", "FAIL  ERROR"),
        ("unrelated_overrides", "PASS"),
        ("duplicate_override", "FAIL  ERROR"),
        ("ambiguous_override", "FAIL  ERROR"),
        ("malformed_override", "FAIL  ERROR"),
        ("duplicate_service_state", "FAIL  ERROR"),
        ("mismatched_service_record", "FAIL  ERROR"),
    ],
)
def test_service_disable_state_matrix(
    rule_id: str,
    label: str,
    case: str,
    expected: str,
    fake_launchctl: Path,
) -> None:
    result = _run_check(rule_id, fake_launchctl, **_case_inputs(label, case))

    assert result == expected


@pytest.mark.parametrize("rule_id", SERVICE_RULES)
def test_yaml_result_is_the_string_pass(rule_id: str) -> None:
    rule = _load_rule(rule_id)
    for version in SUPPORTED_MACOS_VERSIONS:
        enforcement = resolve_enforcement_info(rule["platforms"]["macOS"], version)
        assert enforcement["check"]["result"] == {"string": "PASS"}


@pytest.mark.parametrize("rule_id", SERVICE_RULES)
def test_platforms_inherit_the_same_check_and_fix(rule_id: str) -> None:
    rule = _load_rule(rule_id)
    platform = rule["platforms"]["macOS"]
    resolved = [
        resolve_enforcement_info(platform, version)
        for version in SUPPORTED_MACOS_VERSIONS
    ]

    assert resolved[0] == resolved[1] == resolved[2]


@pytest.mark.parametrize("rule_id", SERVICE_RULES)
def test_security_metadata_and_remediation_are_preserved(rule_id: str) -> None:
    rule = _load_rule(rule_id)
    expected = ORIGINAL_SECURITY_METADATA[rule_id]
    enforcement = resolve_enforcement_info(rule["platforms"]["macOS"], "27.0")

    assert rule["id"] == rule_id
    assert rule["references"]["nist"]["800-53r5"] == expected["nist_800_53r5"]
    assert rule["references"]["disa"]["cci"] == expected["disa_cci"]
    assert rule["references"]["cis"]["controls_v8"] == expected["cis_controls_v8"]
    assert enforcement["fix"]["shell"] == expected["fix"]
    assert {
        "800-53r5_low",
        "800-53r5_moderate",
        "800-53r5_high",
        "800-171",
        "cisv8",
        "cmmc_lvl1",
        "cmmc_lvl2",
    } <= set(rule["tags"])


@pytest.mark.parametrize("version", SUPPORTED_MACOS_VERSIONS)
def test_generated_compliance_script_contains_correct_checks(
    version: str, tmp_path: Path
) -> None:
    baseline_path = tmp_path / "service-disable-regression.yaml"
    baseline_path.write_text(
        f"""title: Service disable regression
description: Test-only baseline for issue 870.
authors: []
parent_values: cis_lvl1
platform:
  os: macOS
  version: {version}
profile:
  - section: System Settings
    rules:
      - system_settings_smbd_disable
      - system_settings_rae_disable
""",
        encoding="utf-8",
    )
    baseline = Baseline.from_yaml(baseline_path)
    version_data = get_version_data("macOS", float(version), mscp_data)

    generate_script(
        build_path=tmp_path,
        baseline_name=baseline.name,
        audit_name=baseline.name,
        baseline=baseline,
        log_reference="default",
        current_version_data=version_data,
    )

    generated = (tmp_path / f"{baseline.name}_compliance.sh").read_text(
        encoding="utf-8"
    )
    loaded_rules = {
        rule.rule_id: rule for profile in baseline.profile for rule in profile.rules
    }
    assert set(loaded_rules) == set(SERVICE_RULES)
    for rule_id, label in SERVICE_RULES.items():
        rule = loaded_rules[rule_id]
        assert rule.check in generated
        assert f"rule_id={rule_id}" in generated
        assert 'expected_result="PASS"' in generated
        assert f"system/{label}" in generated
