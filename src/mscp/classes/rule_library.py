# mscp/classes/rule_library.py
"""Collection class for Macsecurityrule objects.

Provides `RuleLibrary`, an ordered, indexed container that supports
lookup by rule ID, positional access, and filtering by tag, mechanism,
and OS with method chaining.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from .macsecurityrule import Macsecurityrule


# ------------------------------------------------------------------
# File-level text patching helpers
#
# All mutation methods use these instead of rule.to_yaml() to avoid
# the lossy round-trip through the Pydantic model (which flattens
# per-version CCE/DISA dicts and renames YAML keys).
# ------------------------------------------------------------------


def _patch_list_remove(path: Path, value: str, item_indent: int) -> bool:
    """Remove every ``- {value}`` list item at ``item_indent`` spaces from a YAML file.

    Returns ``True`` if the file was modified.
    """
    text = path.read_text(encoding="utf-8")
    prefix = " " * item_indent
    new_text = re.sub(
        rf"^{re.escape(prefix)}- {re.escape(value)}\s*\n",
        "",
        text,
        flags=re.MULTILINE,
    )
    if new_text == text:
        return False
    path.write_text(new_text, encoding="utf-8")
    return True


def _patch_list_append(path: Path, list_key: str, value: str, key_indent: int) -> bool:
    """Append ``- {value}`` to the list under ``list_key`` in a YAML file.

    ``list_key`` must appear at exactly ``key_indent`` leading spaces.
    Appends after the last existing item in the block. Returns ``True`` if
    the file was modified.
    """
    text = path.read_text(encoding="utf-8")
    item_prefix = " " * (key_indent + 2)
    item_line = f"{item_prefix}- {value}\n"
    pattern = (
        rf"(^{re.escape(' ' * key_indent)}{re.escape(list_key)}:\n"
        rf"(?:{re.escape(item_prefix)}- [^\n]*\n)*)"
    )
    new_text = re.sub(
        pattern,
        lambda m: m.group(1) + item_line,
        text,
        flags=re.MULTILINE,
    )
    if new_text == text:
        return False
    path.write_text(new_text, encoding="utf-8")
    return True


def _patch_nist_control_add_sorted(path: Path, control: str) -> bool:
    """Add ``control`` to the ``800-53r5:`` list, keeping entries sorted.

    Returns ``True`` if the file was modified.
    """
    text = path.read_text(encoding="utf-8")
    match = re.search(r"(    800-53r5:\n)((?:      - [^\n]+\n)*)", text)
    if not match:
        return False
    header = match.group(1)
    items = re.findall(r"      - ([^\n]+)", match.group(2))
    if control in items:
        return False
    items.append(control)
    items.sort()
    new_block = header + "".join(f"      - {item}\n" for item in items)
    new_text = text[: match.start()] + new_block + text[match.end() :]
    path.write_text(new_text, encoding="utf-8")
    return True


def _patch_benchmark_remove(path: Path, name: str) -> bool:
    """Remove all benchmark entries with ``name`` from every ``benchmarks:`` block.

    Handles both single-line entries (``- name: X``) and entries with an
    optional ``severity:`` continuation line. Returns ``True`` if modified.
    """
    text = path.read_text(encoding="utf-8")
    new_text = re.sub(
        rf"^        - name: {re.escape(name)}\n(?:          severity: [^\n]+\n)?",
        "",
        text,
        flags=re.MULTILINE,
    )
    if new_text == text:
        return False
    path.write_text(new_text, encoding="utf-8")
    return True


def _normalize_control_id(control: str) -> str:
    """Normalize a NIST control ID to uppercase with no leading zeros.

    Examples: ``"au-09"`` → ``"AU-9"``, ``"AU-09(3)"`` → ``"AU-9(3)"``.
    """
    return re.sub(r"-0*(\d)", r"-\1", control.upper())


class RuleLibrary:
    """An ordered, indexed collection of `Macsecurityrule` objects.

    Maintains both a list (for ordered iteration and positional access)
    and a dict keyed by ``rule_id`` mapping to a list of rules. When the
    library spans multiple platforms the same ``rule_id`` may appear once
    per platform. String-key access via ``__getitem__`` and ``get`` raises
    ``KeyError`` in that case — call ``by_platform`` or ``by_os`` first to
    narrow to a single platform.

    Construct directly from a list of rules, or use ``from_rules_dir``
    to load every supported platform at once.

    Args:
        rules (list[Macsecurityrule]): Initial rules to populate the
            library with.
    """

    def __init__(self, rules: list[Macsecurityrule]) -> None:
        self._rules: list[Macsecurityrule] = list(rules)
        self._index: dict[str, list[Macsecurityrule]] = {}
        self._benchmarks: set[str] = set()
        for r in self._rules:
            self._index.setdefault(r.rule_id, []).append(r)
            version_str = str(float(r.os_version))
            for b in (
                r.platforms.get(r.os_type, {})
                .get(version_str, {})
                .get("benchmarks", [])
            ):
                name = b.get("name")
                if name:
                    self._benchmarks.add(name)

    @classmethod
    def from_rules_dir(cls) -> RuleLibrary:
        """Load all rules for every supported platform and OS version.

        Reads the platform/version matrix from the bundled
        ``mscp-data.yaml`` (via ``mscp_data``) and calls
        ``Macsecurityrule.collect_platform_rules`` once per combination. Use
        ``by_platform`` or ``by_os`` to narrow the result to a specific
        platform.

        Returns:
            RuleLibrary: A new library containing rules for all supported
                platforms and versions.
        """
        from ..common_utils import mscp_data

        all_rules: list[Macsecurityrule] = []
        platforms: dict = mscp_data.get("versions", {}).get("platforms", {})
        for os_type, versions in platforms.items():
            for version_info in versions:
                os_version = version_info.get("os_version")
                if os_version is None:
                    continue
                all_rules.extend(
                    Macsecurityrule.collect_platform_rules(
                        os_type=os_type,
                        os_version=os_version,
                    )
                )
        return cls(all_rules)

    # ------------------------------------------------------------------
    # Collection protocol
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self) -> Iterator[Macsecurityrule]:
        return iter(self._rules)

    def __contains__(self, item: object) -> bool:
        """Return True if the library contains the given rule or rule ID.

        Args:
            item (object): A ``rule_id`` string or a ``Macsecurityrule``
                instance.

        Returns:
            bool: ``True`` if found, ``False`` otherwise.
        """
        if isinstance(item, str):
            return item in self._index
        return item in self._rules

    def __repr__(self) -> str:
        return f"RuleLibrary({len(self._rules)} rules)"

    @property
    def rules(self) -> list[str]:
        """list[str]: The rule IDs of every rule in the library, in order."""
        return [r.rule_id for r in self._rules]

    # ------------------------------------------------------------------
    # Index access
    # ------------------------------------------------------------------

    def __getitem__(self, key: int | str) -> Macsecurityrule:
        """Return a rule by position or rule ID.

        String-key lookup raises ``KeyError`` if the ID matches rules from
        more than one platform; call ``by_platform`` or ``by_os`` first to
        resolve the ambiguity.

        Args:
            key (int | str): An integer index for positional access, or a
                ``rule_id`` string for ID-based lookup.

        Returns:
            Macsecurityrule: The matching rule.

        Raises:
            KeyError: If a ``rule_id`` string is not found, or matches
                rules from multiple platforms.
            IndexError: If an integer index is out of range.
            TypeError: If ``key`` is neither ``int`` nor ``str``.
        """
        if isinstance(key, str):
            return self._resolve(key)
        if isinstance(key, int):
            return self._rules[key]
        raise TypeError(f"indices must be int or str, not {type(key).__name__}")

    def get(
        self, rule_id: str, default: Macsecurityrule | None = None
    ) -> Macsecurityrule | None:
        """Return the rule with the given ``rule_id``, or ``default`` if absent.

        Raises ``KeyError`` if the ID matches rules from multiple platforms;
        call ``by_platform`` or ``by_os`` first in that case.

        Args:
            rule_id (str): The unique rule identifier to look up.
            default (Macsecurityrule | None): Value returned when the rule
                is not found. Defaults to ``None``.

        Returns:
            Macsecurityrule | None: The matching rule, or ``default``.

        Raises:
            KeyError: If ``rule_id`` matches rules from multiple platforms.
        """
        if rule_id not in self._index:
            return default
        return self._resolve(rule_id)

    def _resolve(self, rule_id: str) -> Macsecurityrule:
        """Return the single rule for ``rule_id``, or raise if ambiguous.

        Args:
            rule_id (str): Rule ID to resolve.

        Returns:
            Macsecurityrule: The matching rule.

        Raises:
            KeyError: If the rule ID maps to more than one platform.
        """
        matches = self._index[rule_id]
        if len(matches) == 1:
            return matches[0]
        platforms = ", ".join(f"{r.os_type} {r.os_version}" for r in matches)
        raise KeyError(
            f"{rule_id!r} matches multiple platforms ({platforms}); "
            "call by_platform() or by_os() first to narrow the library"
        )

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def has_odv(self) -> RuleLibrary:
        """Return a new library containing only rules that have an ODV.

        ODV (Organization Defined Value) rules require a value to be set
        by the deploying organization before enforcement.

        Returns:
            RuleLibrary: Matching rules in their original order.
        """
        return RuleLibrary([r for r in self._rules if r.odv is not None])

    def has_mobileconfig(self) -> RuleLibrary:
        """Return a new library containing only rules that have a mobileconfig payload.

        Rules with a mobileconfig payload are enforced via a configuration
        profile rather than a shell script or manual action.

        Returns:
            RuleLibrary: Matching rules in their original order.
        """
        return RuleLibrary([r for r in self._rules if r.mobileconfig_info])

    def has_ddm(self) -> RuleLibrary:
        """Return a new library containing only rules that have a DDM payload.

        DDM (Declarative Device Management) rules include a declaration
        payload for delivery via declarative management solutions.

        Returns:
            RuleLibrary: Matching rules in their original order.
        """
        return RuleLibrary([r for r in self._rules if r.ddm_info is not None])

    def by_nist_control(self, control: str) -> RuleLibrary:
        """Return a new library containing only rules mapped to the given NIST SP 800-53r5 control.

        Args:
            control (str): NIST SP 800-53r5 control identifier to match
                (e.g. ``"AU-9"``). Comparison is case-insensitive.

        Returns:
            RuleLibrary: Matching rules in their original order.
        """
        normalized = _normalize_control_id(control)
        return RuleLibrary(
            [
                r
                for r in self._rules
                if any(
                    _normalize_control_id(c) == normalized
                    for c in (r.references.nist.nist_800_53r5 or [])
                )
            ]
        )

    def by_tag(self, tag: str) -> RuleLibrary:
        """Return a new library containing only rules tagged with ``tag``.

        Args:
            tag (str): Tag string to match against each rule's ``tags`` list.

        Returns:
            RuleLibrary: Matching rules in their original order.
        """
        return RuleLibrary([r for r in self._rules if tag in r.tags])

    def by_mechanism(self, mechanism: str) -> RuleLibrary:
        """Return a new library containing only rules with the given enforcement mechanism.

        Valid values are ``"Manual"``, ``"Script"``, ``"Configuration
        Profile"``, ``"Inherent"``, ``"Permanent"``, and ``"N/A"``.

        Args:
            mechanism (str): Enforcement mechanism to filter on.
                Comparison is case-insensitive.

        Returns:
            RuleLibrary: Matching rules in their original order.
        """
        lower = mechanism.lower()
        return RuleLibrary([r for r in self._rules if r.mechanism.lower() == lower])

    def by_benchmark(self, benchmark: str) -> RuleLibrary:
        """Return a new library containing only rules that belong to the given benchmark.

        Benchmark membership is determined by the ``benchmarks`` list in
        the rule's platform/version entry (e.g. ``"cis_lvl1"``,
        ``"disa_stig"``). Comparison is case-insensitive.

        Args:
            benchmark (str): Benchmark keyword to match (e.g.
                ``"disa_stig"``, ``"cis_lvl1"``).

        Returns:
            RuleLibrary: Matching rules in their original order.

        Raises:
            ValueError: If no rules match, listing the available benchmark
                keywords for this library.
        """
        lower = benchmark.lower()
        result = []
        for r in self._rules:
            version_str = str(float(r.os_version))
            benchmarks = (
                r.platforms.get(r.os_type, {})
                .get(version_str, {})
                .get("benchmarks", [])
            )
            if any(b.get("name", "").lower() == lower for b in benchmarks):
                result.append(r)
        if not result:
            raise ValueError(
                f"benchmark {benchmark!r} not found in this library. "
                f"Available: {', '.join(sorted(self._benchmarks))}"
            )
        return RuleLibrary(result)

    def by_platform(self, platform: str) -> RuleLibrary:
        """Return a new library containing only rules for the given OS family.

        Args:
            platform (str): OS family to match — ``"macos"``, ``"ios"``,
                or ``"visionos"``. Comparison is case-insensitive.

        Returns:
            RuleLibrary: Matching rules in their original order.
        """
        lower = platform.lower()
        return RuleLibrary([r for r in self._rules if r.os_type.lower() == lower])

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def add_tag(self, tag: str) -> RuleLibrary:
        """Add ``tag`` to every rule in this library and write each source file once.

        Args:
            tag (str): Tag to add.

        Returns:
            RuleLibrary: ``self``, for method chaining.
        """
        seen: set = set()
        for rule in self._rules:
            if tag not in rule.tags:
                rule.tags.append(tag)
            if rule.source_file and rule.source_file not in seen:
                seen.add(rule.source_file)
                _patch_list_append(rule.source_file, "tags", tag, key_indent=0)
        return self

    def remove_tag(self, tag: str) -> RuleLibrary:
        """Remove ``tag`` from every rule in this library and write each source file once.

        Args:
            tag (str): Tag to remove.

        Returns:
            RuleLibrary: ``self``, for method chaining.
        """
        seen: set = set()
        for rule in self._rules:
            if tag in rule.tags:
                rule.tags.remove(tag)
            if rule.source_file and rule.source_file not in seen:
                seen.add(rule.source_file)
                _patch_list_remove(rule.source_file, tag, item_indent=2)
        return self

    def add_nist_control(self, control: str) -> RuleLibrary:
        """Add a NIST SP 800-53r5 control to every rule in this library and write each source file once.

        The control is inserted in sorted order within the ``800-53r5:`` list.

        Args:
            control (str): Control identifier to add (e.g. ``"AC-2"``).
                Normalized to uppercase with no leading zeros before comparison.

        Returns:
            RuleLibrary: ``self``, for method chaining.
        """
        normalized = _normalize_control_id(control)
        canonical = control.upper()
        seen: set = set()
        for rule in self._rules:
            controls = rule.references.nist.nist_800_53r5 or []
            if not any(_normalize_control_id(c) == normalized for c in controls):
                rule.references.nist.nist_800_53r5 = sorted(controls + [canonical])
            if rule.source_file and rule.source_file not in seen:
                seen.add(rule.source_file)
                _patch_nist_control_add_sorted(rule.source_file, canonical)
        return self

    def remove_nist_control(self, control: str) -> RuleLibrary:
        """Remove a NIST SP 800-53r5 control from every rule in this library and write each source file once.

        Args:
            control (str): Control identifier to remove (e.g. ``"AC-20"``).
                Normalized to uppercase with no leading zeros before comparison.

        Returns:
            RuleLibrary: ``self``, for method chaining.
        """
        normalized = _normalize_control_id(control)
        seen: set = set()
        for rule in self._rules:
            if rule.references.nist.nist_800_53r5:
                remaining = [
                    c
                    for c in rule.references.nist.nist_800_53r5
                    if _normalize_control_id(c) != normalized
                ]
                rule.references.nist.nist_800_53r5 = remaining or None
            if rule.source_file and rule.source_file not in seen:
                seen.add(rule.source_file)
                _patch_list_remove(rule.source_file, control, item_indent=6)
        return self

    def add_benchmark(self, name: str, severity: str | None = None) -> RuleLibrary:
        """Add a benchmark entry to every rule in this library and write each source file once.

        Appends ``- name: {name}`` (and optionally ``severity: {severity}``) to
        every ``benchmarks:`` block that corresponds to a version present in
        this library. Entries are added only if the benchmark is not already
        present.

        Args:
            name (str): Benchmark name (e.g. ``"cis_lvl1"``).
            severity (str | None): Optional severity string (e.g. ``"medium"``).

        Returns:
            RuleLibrary: ``self``, for method chaining.
        """
        by_file: dict = {}
        for rule in self._rules:
            if rule.source_file:
                by_file.setdefault(rule.source_file, []).append(rule)

        entry_suffix = (f"\n          severity: {severity}") if severity else ""

        for source_file, rules in by_file.items():
            text = source_file.read_text(encoding="utf-8")
            for rule in rules:
                version_str = str(float(rule.os_version))
                os_type = rule.os_type
                benchmarks_list = (
                    rule.platforms.get(os_type, {})
                    .get(version_str, {})
                    .get("benchmarks", [])
                )
                if any(b.get("name") == name for b in benchmarks_list):
                    continue
                rule.platforms.setdefault(os_type, {}).setdefault(
                    version_str, {}
                ).setdefault("benchmarks", []).append(
                    {"name": name, **({"severity": severity} if severity else {})}
                )
                # Find the benchmarks: block within the version's section and append
                version_pattern = (
                    rf"(    '{re.escape(version_str)}':\n"
                    rf"(?:(?!    (?:'[0-9]|[a-zA-Z]))[^\n]*\n)*?"
                    rf"      benchmarks:\n"
                    rf"(?:        - name: [^\n]+\n(?:          severity: [^\n]+\n)?)*)"
                )
                entry_line = f"        - name: {name}{entry_suffix}\n"
                text = re.sub(
                    version_pattern,
                    lambda m, entry_line=entry_line: m.group(0) + entry_line,
                    text,
                    flags=re.MULTILINE,
                )
            source_file.write_text(text, encoding="utf-8")

        return self

    def remove_benchmark(self, name: str) -> RuleLibrary:
        """Remove a benchmark entry from every rule in this library and write each source file once.

        Args:
            name (str): Benchmark name to remove (e.g. ``"cis_lvl1"``).

        Returns:
            RuleLibrary: ``self``, for method chaining.
        """
        seen: set = set()
        for rule in self._rules:
            version_str = str(float(rule.os_version))
            version_data = rule.platforms.get(rule.os_type, {}).get(version_str, {})
            version_data["benchmarks"] = [
                b for b in version_data.get("benchmarks", []) if b.get("name") != name
            ]
            if rule.source_file and rule.source_file not in seen:
                seen.add(rule.source_file)
                _patch_benchmark_remove(rule.source_file, name)
        return self

    def by_os(
        self,
        os_name: str | None = None,
        os_version: float | None = None,
    ) -> RuleLibrary:
        """Return a new library filtered by OS name, version, or both.

        To filter by OS family (macOS vs iOS vs visionOS) use
        ``by_platform`` instead.

        Args:
            os_name (str | None): OS marketing name to match (e.g.
                ``"sequoia"``). Comparison is case-insensitive. Omit to
                skip this filter.
            os_version (float | None): OS version to match (e.g.
                ``15.0``). Omit to skip this filter.

        Returns:
            RuleLibrary: Matching rules in their original order.

        Raises:
            ValueError: If neither argument is provided.
        """
        if os_name is None and os_version is None:
            raise ValueError("at least one of os_name or os_version must be provided")

        rules = self._rules
        if os_name is not None:
            lower = os_name.lower()
            rules = [r for r in rules if r.os_name.lower() == lower]
        if os_version is not None:
            rules = [r for r in rules if r.os_version == os_version]
        return RuleLibrary(rules)
