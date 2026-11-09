"""Generated-script regression tests for external APFS/HFS+ encryption."""

from __future__ import annotations

import os
import plistlib
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest

from mscp.classes import Baseline
from mscp.generate.guidance_support import generate_script

pytestmark = pytest.mark.macos

RULE_ID = "os_external_apfs_hfs_volumes_encrypted"
REPOSITORY_ROOT = Path(__file__).parents[1]
BASELINE_PATH = (
    REPOSITORY_ROOT / "src/mscp/data/baselines/macos/cis_lvl1_macos_27.0.yaml"
)
DISKUTIL_FIXTURES = Path(__file__).parent / "fixtures/diskutil"


def _generate_compliance_script(build_path: Path, baseline_path: Path) -> str:
    baseline = Baseline.from_yaml(baseline_path)
    generate_script(
        build_path,
        baseline_path.stem,
        baseline_path.stem,
        baseline,
        "default",
        {"compliance_version": "test"},
    )
    return (build_path / f"{baseline_path.stem}_compliance.sh").read_text()


def _extract_rule_block(script: str) -> str:
    marker = f"  #####----- Rule: {RULE_ID} -----#####"
    start = script.index(marker)
    next_rule = script.find("  #####----- Rule:", start + len(marker))
    assert next_rule != -1
    return script[start:next_rule]


@pytest.fixture(scope="module")
def generated_rule_block(tmp_path_factory: pytest.TempPathFactory) -> str:
    build_path = tmp_path_factory.mktemp("external-volume-script")
    script = _generate_compliance_script(build_path, BASELINE_PATH)
    return _extract_rule_block(script)


def _plist(data: dict[str, Any]) -> str:
    return plistlib.dumps(data, sort_keys=False).decode()


def _list_plist(*identifiers: str) -> str:
    return _plist(
        {
            "AllDisks": list(identifiers),
            "AllDisksAndPartitions": [],
            "VolumesFromDisks": [],
            "WholeDisks": [],
        }
    )


def _info_plist(
    name: str,
    identifier: str,
    *,
    filesystem_type: str = "apfs",
    protocol: str = "USB",
    writable_media: bool = True,
    writable_volume: bool = True,
    filevault: bool | None = True,
    corestorage_encrypted: bool | None = None,
) -> str:
    data: dict[str, Any] = {
        "BusProtocol": protocol,
        "DeviceIdentifier": identifier,
        "FilesystemType": filesystem_type,
        "VolumeName": name,
        "WritableMedia": writable_media,
        "WritableVolume": writable_volume,
    }
    if filevault is not None:
        data["FileVault"] = filevault
    if corestorage_encrypted is not None:
        data["CoreStorageLVUUID"] = "00000000-0000-0000-0000-000000000001"
        data["CoreStorageEncrypted"] = corestorage_encrypted
    return _plist(data)


def _load_fixture(name: str) -> str:
    return (DISKUTIL_FIXTURES / name).read_text()


def _updated_fixture(name: str, **updates: Any) -> str:
    data = plistlib.loads((DISKUTIL_FIXTURES / name).read_bytes())
    data.update(updates)
    return _plist(data)


def _write_diskutil_mock(
    tmp_path: Path,
    *,
    list_output: str,
    info_output: dict[str, str] | None = None,
    list_exit: int = 0,
    info_exit: dict[str, int] | None = None,
) -> tuple[Path, Path]:
    fixture_dir = tmp_path / "diskutil-fixture"
    fixture_dir.mkdir()
    (fixture_dir / "list.plist").write_text(list_output)
    (fixture_dir / "list.exit").write_text(str(list_exit))

    for identifier, output in (info_output or {}).items():
        (fixture_dir / f"info-{identifier}.plist").write_text(output)
    for identifier, exit_code in (info_exit or {}).items():
        (fixture_dir / f"info-{identifier}.exit").write_text(str(exit_code))

    mock_path = tmp_path / "diskutil"
    mock_path.write_text(
        """#!/bin/zsh --no-rcs
fixture_dir="$MSCP_DISKUTIL_FIXTURE"

if [[ "$1" == "list" && "$2" == "-plist" && "$3" == "external" ]]; then
  /bin/cat "$fixture_dir/list.plist"
  exit "$(<"$fixture_dir/list.exit")"
fi

if [[ "$1" == "info" && "$2" == "-plist" && -n "$3" ]]; then
  output_file="$fixture_dir/info-$3.plist"
  exit_file="$fixture_dir/info-$3.exit"
  [[ -f "$output_file" ]] && /bin/cat "$output_file"
  [[ -f "$exit_file" ]] && exit "$(<"$exit_file")"
  [[ -f "$output_file" ]] && exit 0
fi

exit 1
"""
    )
    mock_path.chmod(0o755)
    return mock_path, fixture_dir


def _run_generated_rule(
    generated_rule_block: str,
    tmp_path: Path,
    *,
    list_output: str,
    info_output: dict[str, str] | None = None,
    list_exit: int = 0,
    info_exit: dict[str, int] | None = None,
) -> dict[str, str]:
    mock_path, fixture_dir = _write_diskutil_mock(
        tmp_path,
        list_output=list_output,
        info_output=info_output,
        list_exit=list_exit,
        info_exit=info_exit,
    )
    block = generated_rule_block.replace(
        "/usr/sbin/diskutil", shlex.quote(str(mock_path))
    )
    for command in ("osascript", "defaults", "logger"):
        block = block.replace(f"/usr/bin/{command}", "/usr/bin/true")

    harness = f"""
run_generated_rule() {{
  arch=$(/usr/bin/arch)
  baseline_name=test
  audit_plist=/tmp/mscp-external-volume-test.plist
  typeset -A results_array
  logmessage() {{ :; }}
  logcsv() {{ :; }}
{block}
  /usr/bin/printf 'result=%s\\n' "${{results_array[$rule_id]}}"
  /usr/bin/printf 'status=%s\\n' "$result_status"
  /usr/bin/printf 'finding=%s\\n' "$finding"
}}
run_generated_rule
"""
    env = os.environ.copy()
    env["MSCP_DISKUTIL_FIXTURE"] = str(fixture_dir)
    completed = subprocess.run(
        ["/bin/zsh", "--no-rcs", "-c", harness],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return dict(line.split("=", 1) for line in completed.stdout.splitlines())


def _assert_passed(result: dict[str, str]) -> None:
    assert result == {"result": "Yes", "status": "passed", "finding": "NO"}


def _assert_failed(result: dict[str, str], expected_output: str) -> None:
    assert result == {
        "result": expected_output,
        "status": "failed",
        "finding": "YES",
    }


def test_generated_rule_passes_successful_empty_diskutil_list(
    generated_rule_block: str, tmp_path: Path
) -> None:
    result = _run_generated_rule(
        generated_rule_block, tmp_path, list_output=_list_plist()
    )

    _assert_passed(result)


def test_generated_rule_passes_multiple_encrypted_apfs_volumes(
    generated_rule_block: str, tmp_path: Path
) -> None:
    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("disk4s1", "disk5s1"),
        info_output={
            "disk4s1": _info_plist("Primary Backup", "disk4s1"),
            "disk5s1": _info_plist("Secondary Backup", "disk5s1"),
        },
    )

    _assert_passed(result)


@pytest.mark.parametrize("encrypted", [True, False])
def test_generated_rule_uses_corestorage_encryption_status(
    generated_rule_block: str, tmp_path: Path, encrypted: bool
) -> None:
    info = _updated_fixture(
        "corestorage_encrypted.plist", CoreStorageEncrypted=encrypted
    )
    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("disk6s1"),
        info_output={"disk6s1": info},
    )

    if encrypted:
        _assert_passed(result)
    else:
        _assert_failed(result, "Unencrypted external volumes: Legacy CoreStorage")


def test_generated_rule_reports_plain_hfs_as_unencrypted(
    generated_rule_block: str, tmp_path: Path
) -> None:
    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("disk5s1"),
        info_output={"disk5s1": _load_fixture("plain_hfs.plist")},
    )

    _assert_failed(result, "Unencrypted external volumes: Plain HFS Backup")


def test_generated_rule_excludes_realistic_read_only_disk_image(
    generated_rule_block: str, tmp_path: Path
) -> None:
    captured_text = _load_fixture("apfs_read_only_disk_image.txt")
    assert "Volume Read-Only:          Yes (read-only mount flag set)" in captured_text

    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("disk5s1"),
        info_output={"disk5s1": _load_fixture("apfs_read_only_disk_image.plist")},
    )

    _assert_passed(result)


def test_generated_rule_excludes_multiple_read_only_disk_images(
    generated_rule_block: str, tmp_path: Path
) -> None:
    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("disk5s1", "disk7s1"),
        info_output={
            "disk5s1": _load_fixture("apfs_read_only_disk_image.plist"),
            "disk7s1": _updated_fixture(
                "apfs_read_only_disk_image.plist",
                DeviceIdentifier="disk7s1",
                VolumeName="XROS 26.1 Simulator",
            ),
        },
    )

    _assert_passed(result)


def test_generated_rule_handles_mixed_apfs_hfs_and_corestorage(
    generated_rule_block: str, tmp_path: Path
) -> None:
    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("disk4s1", "disk5s1", "disk6s1"),
        info_output={
            "disk4s1": _info_plist("Encrypted APFS", "disk4s1"),
            "disk5s1": _load_fixture("plain_hfs.plist"),
            "disk6s1": _load_fixture("corestorage_encrypted.plist"),
        },
    )

    _assert_failed(result, "Unencrypted external volumes: Plain HFS Backup")


def test_generated_rule_reports_unencrypted_and_uncheckable_volumes(
    generated_rule_block: str, tmp_path: Path
) -> None:
    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("disk4s1", "disk5s1"),
        info_output={
            "disk4s1": _info_plist("Unencrypted APFS", "disk4s1", filevault=False),
            "disk5s1": _info_plist("Unknown APFS", "disk5s1", filevault=None),
        },
    )

    _assert_failed(
        result,
        "ERROR: Unable to determine encryption status for external volumes: "
        "disk5s1; Unencrypted external volumes: Unencrypted APFS",
    )


def test_generated_rule_reports_malformed_list_entry(
    generated_rule_block: str, tmp_path: Path
) -> None:
    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("not-a-disk-identifier"),
    )

    _assert_failed(
        result,
        "ERROR: Unable to determine encryption status for external volumes: "
        "disk list entry",
    )


@pytest.mark.parametrize("failed_command", ["list", "info"])
def test_generated_rule_reports_diskutil_command_failures(
    generated_rule_block: str, tmp_path: Path, failed_command: str
) -> None:
    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("disk10s1"),
        info_output={"disk10s1": _info_plist("Backup", "disk10s1")},
        list_exit=1 if failed_command == "list" else 0,
        info_exit={"disk10s1": 1} if failed_command == "info" else {},
    )

    assert result["result"].startswith("ERROR: Unable to ")
    assert result["status"] == "failed"
    assert result["finding"] == "YES"


@pytest.mark.parametrize("info_output", ["", "not a plist"])
def test_generated_rule_rejects_successful_malformed_info_output(
    generated_rule_block: str, tmp_path: Path, info_output: str
) -> None:
    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("disk9s1"),
        info_output={"disk9s1": info_output},
    )

    _assert_failed(
        result,
        "ERROR: Unable to determine encryption status for external volumes: disk9s1",
    )


@pytest.mark.parametrize(
    "missing_key",
    [
        "DeviceIdentifier",
        "FilesystemType",
        "VolumeName",
        "WritableVolume",
        "FileVault",
    ],
)
def test_generated_rule_reports_missing_required_fields(
    generated_rule_block: str, tmp_path: Path, missing_key: str
) -> None:
    info = plistlib.loads(_info_plist("Unknown", "disk9s1").encode())
    del info[missing_key]
    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("disk9s1"),
        info_output={"disk9s1": _plist(info)},
    )

    _assert_failed(
        result,
        "ERROR: Unable to determine encryption status for external volumes: disk9s1",
    )


def test_generated_rule_rejects_mismatched_info_identifier(
    generated_rule_block: str, tmp_path: Path
) -> None:
    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("disk9s1"),
        info_output={"disk9s1": _info_plist("Wrong Disk", "disk8s1")},
    )

    _assert_failed(
        result,
        "ERROR: Unable to determine encryption status for external volumes: disk9s1",
    )


@pytest.mark.parametrize("missing_key", ["CoreStorageLVUUID", "CoreStorageEncrypted"])
def test_generated_rule_rejects_partial_corestorage_information(
    generated_rule_block: str, tmp_path: Path, missing_key: str
) -> None:
    info = plistlib.loads(
        (DISKUTIL_FIXTURES / "corestorage_encrypted.plist").read_bytes()
    )
    del info[missing_key]
    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("disk6s1"),
        info_output={"disk6s1": _plist(info)},
    )

    _assert_failed(
        result,
        "ERROR: Unable to determine encryption status for external volumes: disk6s1",
    )


def test_generated_rule_preserves_volume_names_with_spaces(
    generated_rule_block: str, tmp_path: Path
) -> None:
    result = _run_generated_rule(
        generated_rule_block,
        tmp_path,
        list_output=_list_plist("disk8s1"),
        info_output={
            "disk8s1": _info_plist("Quarterly Backup 2026", "disk8s1", filevault=False)
        },
    )

    _assert_failed(result, "Unencrypted external volumes: Quarterly Backup 2026")


@pytest.mark.parametrize("version", ["15.0", "26.0", "27.0"])
def test_rule_renders_valid_shell_for_supported_macos_versions(
    tmp_path: Path, version: str
) -> None:
    baseline_path = tmp_path / f"external_volume_macos_{version}.yaml"
    baseline_path.write_text(
        f"""---
authors: []
title: External volume encryption test
description: Compatibility fixture.
platform:
  os: macOS
  version: {version}
parent_values: cis_lvl1
profile:
  - section: Operating System
    rules:
      - {RULE_ID}
"""
    )
    build_path = tmp_path / "build"
    script = _generate_compliance_script(build_path, baseline_path)
    completed = subprocess.run(
        ["/bin/zsh", "--no-rcs", "-n"],
        input=script,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert f"Rule: {RULE_ID}" in script
