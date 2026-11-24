"""Tests for the ``--quiet=1`` console filter in the generated compliance script.

``logmessage`` is copied out of the template and run under zsh, so the test
exercises the shell code the generated script actually contains.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "src/mscp/data/templates/shell_scripts/compliance_script.sh.jinja"
)

pytestmark = pytest.mark.skipif(shutil.which("zsh") is None, reason="requires zsh")


def _logmessage_function() -> str:
    match = re.search(
        r"^logmessage\(\)\{\n.*?^\}\n", TEMPLATE.read_text(), re.MULTILINE | re.DOTALL
    )
    assert match, "logmessage() not found in compliance_script.sh.jinja"
    return match.group(0)


def _console_output(message: str, tmp_path: Path) -> str:
    script = (
        'message="$1"\n'
        f'audit_log="{tmp_path}/audit.log"\n'
        # parsed the same way as the compliance script's own zparseopts call
        "set -- --quiet=1\n"
        "zparseopts -D -E -quiet:=quiet\n"
        f"{_logmessage_function()}\n"
        'logmessage "$message"\n'
    )
    result = subprocess.run(
        ["zsh", "-f", "-c", script, "zsh", message],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


@pytest.mark.parametrize(
    "message",
    [
        'audit_flags_fm_failed_configure passed (Result: 1, Expected: "1")',
        'os_gatekeeper_enable passed (Result: 1, Expected: "1")',
        "Beginning new compliance scan",
    ],
)
def test_quiet_hides_passed_rules(message: str, tmp_path: Path) -> None:
    assert _console_output(message, tmp_path) == ""


@pytest.mark.parametrize(
    "message",
    [
        'audit_flags_fm_failed_configure failed (Result: 0, Expected: "1")',
        (
            'os_gatekeeper_enable failed (Result: 0, Expected: "1") '
            '- Exemption Allowed (Reason: "test")'
        ),
        'os_gatekeeper_enable has an exemption, remediation skipped (Reason: "test")',
    ],
)
def test_quiet_shows_failures_and_exemptions(message: str, tmp_path: Path) -> None:
    assert message in _console_output(message, tmp_path)
