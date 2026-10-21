"""Tests for ``mscp.cli.parse_cli`` argument handling.

``--help`` exits from inside ``parse_args`` before any generation work runs,
so these tests can drive ``parse_cli`` directly with a patched ``sys.argv``.
"""

from __future__ import annotations

import sys

import pytest

from mscp.cli import parse_cli


def _run_help(monkeypatch, capsys, argv: list[str]) -> str:
    monkeypatch.setattr(sys, "argv", ["mscp", *argv])
    with pytest.raises(SystemExit) as exc:
        parse_cli()
    assert exc.value.code == 0
    return capsys.readouterr().out


@pytest.mark.parametrize(
    "argv,usage,expected_flags",
    [
        (["--help"], "usage: mscp [-h]", ["--os_name", "--output_dir"]),
        (["-h"], "usage: mscp [-h]", ["--os_name", "--output_dir"]),
        (["baseline", "--help"], "usage: mscp baseline", ["--keyword", "--list_tags"]),
        (["guidance", "--help"], "usage: mscp guidance", ["--audit_name", "--script"]),
        (["scap", "-h"], "usage: mscp scap", ["--baseline", "--xccdf"]),
        (["mapping", "--help"], "usage: mscp mapping", ["--csv", "--framework"]),
        (["admin", "--help"], "usage: mscp admin", ["validate"]),
        (["-v", "baseline", "-h"], "usage: mscp baseline", ["--keyword"]),
    ],
)
def test_help_shows_full_parser(monkeypatch, capsys, argv, usage, expected_flags):
    out = _run_help(monkeypatch, capsys, argv)

    assert out.startswith(usage)
    for flag in expected_flags:
        assert flag in out
