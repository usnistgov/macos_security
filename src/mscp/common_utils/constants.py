# src/mscp/common_utils/constants.py
"""Top-level string and platform-list constants used across mSCP."""

#: Repo-relative path to the rule JSON Schema used by `validate_yaml_file`.
SCHEMA_PATH = "schema/mscp_rule.json"

#: Apple platforms mSCP targets.
APPLE_OS = ["macos", "ios", "visionos"]

#: Subset of `APPLE_OS` whose tooling expects POSIX-style commands.
NIX_OS = ["macos"]

#: Platform map for identifiers
PLATFORM_MAP = {"macos": "macOS", "ios": "iOS", "visionos": "visionOS"}
