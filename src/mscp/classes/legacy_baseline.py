# mscp/classes/legacy_baseline.py
"""Legacy baseline format support and migration to the current format.

Pre-2.0 mSCP baseline YAML files differ from the current format in three ways:

1. **authors** is a raw multiline AsciiDoc string (not a list of dicts).
2. **platform** is absent (the OS name and version are embedded in the title).
3. Profile **section** names are lowercase stems (``"auditing"``, ``"macos"``,
   …) rather than canonical display names, and section grouping may reflect
   an older version of the rule library.

Rather than attempting to map old section names to new ones, migration
re-resolves every rule ID against the *current* rule library for the target
platform.  Each found rule carries its up-to-date section assignment, so the
resulting baseline reflects the current structure.  Rule IDs that no longer
exist in the library are reported but do not abort the migration.

Typical usage::

    from mscp.classes.legacy_baseline import LegacyBaseline

    if LegacyBaseline.is_legacy(path):
        lb = LegacyBaseline.from_yaml(path)
        # platform is inferred from the title; pass platform= explicitly
        # if inference fails (e.g. non-standard title format).
        missing = lb.migrate(output_path)
        if missing:
            print("Rules not found in current library:", missing)
"""

# Standard python modules
import re
from pathlib import Path
from typing import Any

# Additional python modules
from pydantic import BaseModel

# Local python modules
from ..common_utils import open_file
from ..common_utils.logger_instance import logger
from .baseline import Author, Baseline
from .macsecurityrule import Macsecurityrule

__all__ = ["LegacyBaseline", "LegacyProfile"]

# Matches the OS family and version number embedded in a baseline title,
# e.g. "macOS 26.0", "iOS 17.0", "visionOS 2.0".
_PLATFORM_RE = re.compile(
    r"\b(macOS|iOS|iPadOS|visionOS)\s+(\d+(?:\.\d+)*)\b"
)


class LegacyProfile(BaseModel):
    """A profile section as stored in the legacy format.

    Unlike the current `Profile`, rules are kept as plain strings (rule IDs)
    rather than loaded `Macsecurityrule` objects.

    Attributes:
        section (str): Raw section name from the legacy YAML.
        rules (list[str]): Rule IDs in the order they appear in the file.
    """

    section: str
    rules: list[str]


class LegacyBaseline(BaseModel):
    """Parser and migrator for pre-2.0 mSCP baseline YAML files.

    Attributes:
        title (str): Full title string, used to infer the target platform.
        description (str): Baseline description text.
        authors (str): Raw AsciiDoc authors block.
        parent_values (str): Parent benchmark identifier.
        profile (list[LegacyProfile]): Profile sections with rule-ID lists.
    """

    title: str
    description: str = ""
    authors: str
    parent_values: str = ""
    profile: list[LegacyProfile]

    # ------------------------------------------------------------------
    # Construction / detection
    # ------------------------------------------------------------------

    @classmethod
    def is_legacy(cls, file_path: Path) -> bool:
        """Return ``True`` if *file_path* looks like a pre-2.0 baseline.

        The primary indicator is an ``authors`` value that is a plain string
        rather than a list of dicts.  A missing ``platform`` key is treated as
        a secondary indicator.

        Args:
            file_path (Path): Path to the baseline YAML to inspect.

        Returns:
            bool: ``True`` when the file appears to be in legacy format.
        """
        data: dict[str, Any] = open_file(file_path)
        return isinstance(data.get("authors"), str) or "platform" not in data

    @classmethod
    def from_yaml(cls, file_path: Path) -> "LegacyBaseline":
        """Load a legacy baseline YAML file.

        Args:
            file_path (Path): Path to the legacy baseline YAML.

        Returns:
            LegacyBaseline: The parsed legacy baseline.

        Raises:
            ValueError: If the file does not appear to be in legacy format.
                Use `Baseline.from_yaml` for current-format files.
        """
        data: dict[str, Any] = open_file(file_path)

        if not cls.is_legacy(file_path):
            raise ValueError(
                f"{file_path} does not appear to be a legacy baseline "
                "(authors is already a list and platform is present). "
                "Use Baseline.from_yaml() instead."
            )

        return cls(
            title=data.get("title", ""),
            description=data.get("description", ""),
            authors=data.get("authors", ""),
            parent_values=data.get("parent_values", ""),
            profile=[LegacyProfile(**p) for p in data.get("profile", [])],
        )

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def parse_authors(self) -> list[Author]:
        """Parse the raw AsciiDoc ``authors`` string into ``Author`` objects.

        Recognises the AsciiDoc simple table format used by early mSCP
        baselines::

            *macOS Security Compliance Project*

            |===
            |Jordy Witteman|Root3
            |Aron van den Herik|Root3
            |===

        Each row between the ``|===`` delimiters is split on ``|`` and the
        first two cells become ``name`` and ``organization``.

        If no table is present the entire string (stripped of AsciiDoc
        emphasis markers) is used as a single author name with no
        organization.

        Authors whose names do not appear in ``mscp_data["authors"]`` are
        marked ``additional=True``, matching the behaviour of tailored
        baselines generated by `Baseline.create_new`.

        Returns:
            list[Author]: Parsed author entries, with ``additional`` set
                appropriately for each.
        """
        from ..common_utils import mscp_data

        # Build a case-insensitive set of known MSCP author names.
        known_names: set[str] = {
            a["name"].strip().lower()
            for a in mscp_data.get("authors", [])
            if isinstance(a.get("name"), str)
        }

        raw_authors: list[tuple[str, str | None]] = []
        in_table: bool = False

        for raw_line in self.authors.splitlines():
            line = raw_line.strip()
            if line == "|===":
                in_table = not in_table
                continue
            if in_table and line.startswith("|"):
                parts = line.split("|")
                # parts: ["", "Name", "Organization"]
                name = parts[1].strip() if len(parts) > 1 else ""
                org = parts[2].strip() if len(parts) > 2 else ""
                if name:
                    raw_authors.append((name, org if org else None))

        if not raw_authors:
            # No table found — strip AsciiDoc markup and use what remains.
            clean = re.sub(r"\*[^*]*\*", "", self.authors).strip()
            if clean:
                raw_authors.append((clean, None))

        return [
            Author(
                name=name,
                organization=org,
                additional=True if name.strip().lower() not in known_names else None,
            )
            for name, org in raw_authors
        ]

    def parse_platform(self) -> dict[str, Any]:
        """Infer the ``platform`` dict from the baseline title.

        Looks for a pattern like ``macOS 26.0`` or ``iOS 17.0`` anywhere in
        the title.

        Returns:
            dict[str, Any]: ``{"os": "<family>", "version": <float>}``

        Raises:
            ValueError: If no recognisable platform string is found.  The
                caller should catch this and supply ``platform=`` explicitly
                when calling `migrate`.
        """
        match = _PLATFORM_RE.search(self.title)
        if not match:
            raise ValueError(
                f"Cannot infer platform from title {self.title!r}. "
                "Pass platform={'os': '<family>', 'version': <float>} "
                "explicitly to migrate()."
            )
        return {"os": match.group(1), "version": float(match.group(2))}

    # ------------------------------------------------------------------
    # Migration
    # ------------------------------------------------------------------

    def migrate(
        self,
        output_path: Path,
        platform: dict[str, Any] | None = None,
        language: str = "en",
    ) -> list[str]:
        """Convert this legacy baseline to the current format and write it.

        Collects every rule ID across all legacy profile sections, looks each
        one up in the *current* rule library for the target platform, and
        builds a new baseline via `Baseline.create_new`.  Rules are placed
        into the sections defined by the current library — the legacy section
        groupings are not preserved.  The original ``title`` and
        ``description`` are carried over unchanged.

        Args:
            output_path (Path): Destination file for the migrated baseline.
            platform (dict[str, Any] | None): Target platform as
                ``{"os": "<family>", "version": <float>}`` (e.g.
                ``{"os": "macOS", "version": 26.0}``).  When ``None``,
                the platform is inferred from `title` via `parse_platform`.
                Pass this explicitly when the title does not contain a
                recognisable platform string, or to override the inferred
                value.
            language (str): Language code forwarded to the rule loader.
                Defaults to ``"en"``.

        Returns:
            list[str]: Rule IDs from the legacy file that were **not** found
                in the current rule library for the target platform.  An
                empty list means every rule resolved successfully.

        Raises:
            ValueError: If *platform* is ``None`` and cannot be inferred
                from the title.
        """
        # 1. Resolve platform.
        resolved = platform if platform is not None else self.parse_platform()
        os_type: str = resolved["os"]
        os_version: float = float(resolved["version"])

        # 2. Collect all rule IDs, preserving first-seen order and
        #    deduplicating across sections.
        seen: set[str] = set()
        legacy_rule_ids: list[str] = []
        for prof in self.profile:
            for rule_id in prof.rules:
                if rule_id not in seen:
                    legacy_rule_ids.append(rule_id)
                    seen.add(rule_id)

        logger.info(
            "Migrating legacy baseline: {} rule IDs across {} sections",
            len(legacy_rule_ids),
            len(self.profile),
        )

        # 3. Load the current rule library for the target platform/version.
        #    collect_all_rules assigns each rule its current section, so the
        #    resulting baseline will reflect today's section structure.
        all_current_rules = Macsecurityrule.collect_all_rules(
            os_type=os_type,
            os_version=int(os_version),
            parent_values=self.parent_values or "default",
        )
        current_by_id: dict[str, Macsecurityrule] = {
            r.rule_id: r for r in all_current_rules
        }

        # 4. Match each legacy rule ID against the current library.
        found_rules: list[Macsecurityrule] = []
        missing: list[str] = []
        for rule_id in legacy_rule_ids:
            rule = current_by_id.get(rule_id)
            if rule is not None:
                found_rules.append(rule)
            else:
                missing.append(rule_id)
                logger.warning(
                    "Rule {!r} not found in current {} {} library — skipping",
                    rule_id,
                    os_type,
                    os_version,
                )

        logger.info(
            "{} rules resolved, {} not found in current library",
            len(found_rules),
            len(missing),
        )

        # 5. Build the new baseline, preserving the original title and
        #    description instead of synthesising them from the other args.
        Baseline.create_new(
            output_file=output_path,
            rules=found_rules,
            baseline_name=None,
            authors=self.parse_authors(),
            full_title="",
            benchmark=self.parent_values,
            os_type=os_type,
            os_version=os_version,
            baseline_dict={"title": self.title, "description": self.description},
            language=language,
        )

        return missing

    @classmethod
    def migrate_file(
        cls,
        source: Path,
        output: Path,
        platform: dict[str, Any] | None = None,
        language: str = "en",
    ) -> list[str]:
        """Convenience: load *source* and write the migrated YAML to *output*.

        Equivalent to ``LegacyBaseline.from_yaml(source).migrate(output, ...)``.

        Args:
            source (Path): Path to the legacy baseline YAML.
            output (Path): Destination path for the migrated file.
            platform (dict[str, Any] | None): Override the platform inferred
                from the title. See `migrate` for the expected format.
            language (str): Language code forwarded to the rule loader.

        Returns:
            list[str]: Rule IDs not found in the current library (see
                `migrate`).
        """
        return cls.from_yaml(source).migrate(output, platform=platform, language=language)
