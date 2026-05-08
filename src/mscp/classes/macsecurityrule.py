# macsecurityrule.py
"""macOS security rule model and supporting reference types.

Defines `Macsecurityrule`, the top-level model for an mSCP rule, plus the
nested `References` graph (`NistReferences`, `DisaReferences`,
`CisReferences`, `bsiReferences`, `customReferences`) and the
`Mobileconfigpayload` model used to represent configuration profile
payloads. Also exposes the `Sectionmap` enum that maps rule directories to
their canonical section filenames.
"""

# Standard python modules
import base64
from collections import OrderedDict, defaultdict
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

# Additional python modules
from lxml import etree
from pydantic import BaseModel, ConfigDict, Field

# Local python modules
from ..common_utils import (
    config,
    create_yaml,
    get_version_data,
    make_dir,
    mscp_data,
    open_file,
    sanitize_input,
    prompt_for_odv,
    collect_overrides,
)
from ..common_utils.logger_instance import logger

_SENTINEL = object()


class Sectionmap(StrEnum):
    """Mapping from rule directory names to canonical section filenames.

    Each member corresponds to one of the per-section YAML files under
    ``config["sections_dir"]``. The string value is the stem of that file
    (e.g. ``"auditing"`` → ``auditing.yaml``). Members are looked up from
    folder names like ``Sectionmap[folder.upper()]`` during rule collection.
    """

    AUDIT = "auditing"
    AUTH = "authentication"
    ICLOUD = "icloud"
    INHERENT = "inherent"
    OS = "operatingsystem"
    MANUAL = "manual"
    NOT_APPLICABLE = "notapplicable"
    PWPOLICY = "passwordpolicy"
    PERMANENT = "permanent"
    SRG = "srg"
    SUPPLEMENTAL = "supplemental"
    SYSTEM_SETTINGS = "systemsettings"
    SETTINGS = "systemsettings"
    EXCLUDED = "excluded"


class BaseModelWithAccessors(BaseModel):
    """Pydantic base class with dict-style accessors.

    Adds `get` plus ``__getitem__`` / ``__setitem__`` so subclasses can be
    treated either as Pydantic models or as plain dict-like objects. This
    variant differs from the one in `mscp.classes.baseline` only in that
    `__getitem__` / `__setitem__` use `getattr` / `setattr` directly, so any
    attribute that exists on the instance (declared field or otherwise) is
    accessible.
    """

    def get(self, attr: str, default: Any = None) -> Any:
        """Return the value of `attr`, or `default` if it isn't set.

        Args:
            attr (str): Attribute name to read.
            default (Any): Value returned when ``attr`` is absent.
                Defaults to ``None``.

        Returns:
            Any: The attribute value, or ``default`` if no such attribute
                exists on the instance.
        """
        return getattr(self, attr, default)

    def __getitem__(self, key: str) -> Any:
        """Dict-style read; raises `KeyError` if the attribute is missing."""
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key) from None

    def __setitem__(self, key: str, value: Any) -> None:
        """Dict-style write; raises `KeyError` if the attribute is forbidden."""
        try:
            setattr(self, key, value)
        except AttributeError:
            # This triggers if Pydantic config is set to 'forbid'
            raise KeyError(f"{key} is not a valid attribute")


class NistReferences(BaseModelWithAccessors):
    """NIST reference identifiers for a rule.

    Each list is sorted in ascending order on construction to keep the
    serialised output stable.

    Attributes:
        cce (list[str] | None): CCE (Common Configuration Enumeration)
            identifiers, e.g. ``["CCE-94195-5"]``.
        nist_800_53r5 (list[str] | None): NIST SP 800-53 Rev. 5 control
            identifiers. Stored under the Python-friendly attribute name;
            serialised to YAML as ``800-53r5``.
        nist_800_171r3 (list[str] | None): NIST SP 800-171 Rev. 3 control
            identifiers. Serialised to YAML as ``800-171r3``.
    """

    cce: list[str] | None = None
    nist_800_53r5: list[str] | None = None
    nist_800_171r3: list[str] | None = None

    def __init__(self, **data):
        """Construct from kwargs and sort all reference lists."""
        super().__init__(**data)
        if self.cce:
            self.cce = sorted(self.cce)
        if self.nist_800_53r5:
            self.nist_800_53r5 = sorted(self.nist_800_53r5)
        if self.nist_800_171r3:
            self.nist_800_171r3 = sorted(self.nist_800_171r3)


class DisaReferences(BaseModelWithAccessors):
    """DISA reference identifiers for a rule.

    Each list is sorted in ascending order on construction.

    Attributes:
        cci (list[str] | None): CCI (Control Correlation Identifier)
            identifiers.
        srg (list[str] | None): Security Requirements Guide identifiers.
        disa_stig (list[str] | None): DISA STIG rule identifiers.
        cmmc (list[str] | None): CMMC practice identifiers.
        sfr (list[str] | None): Security Functional Requirement identifiers.
    """

    cci: list[str] | None = None
    srg: list[str] | None = None
    disa_stig: list[str] | None = None
    cmmc: list[str] | None = None
    sfr: list[str] | None = None

    def __init__(self, **data):
        """Construct from kwargs and sort all reference lists."""
        super().__init__(**data)
        if self.cci:
            self.cci = sorted(self.cci)
        if self.srg:
            self.srg = sorted(self.srg)
        if self.sfr:
            self.sfr = sorted(self.sfr)
        if self.disa_stig:
            self.disa_stig = sorted(self.disa_stig)
        if self.cmmc:
            self.cmmc = sorted(self.cmmc)


class CisReferences(BaseModelWithAccessors):
    """CIS reference identifiers for a rule.

    Each list is sorted in ascending order on construction.

    Attributes:
        benchmark (list[str] | None): CIS Benchmark recommendation
            identifiers (e.g. ``["1.2.3"]``).
        controls_v8 (list[float] | None): CIS Controls v8 mappings.
    """

    benchmark: list[str] | None = None
    controls_v8: list[float] | None = None

    def __init__(self, **data: Any) -> None:
        """Construct from kwargs and sort all reference lists."""
        super().__init__(**data)
        if self.benchmark:
            self.benchmark = sorted(self.benchmark)
        if self.controls_v8:
            self.controls_v8 = sorted(self.controls_v8)


class bsiReferences(BaseModelWithAccessors):
    """BSI (Bundesamt für Sicherheit in der Informationstechnik) references.

    Attributes:
        indigo (list[str] | None): BSI Indigo profile identifiers, sorted
            in ascending order on construction.
    """

    indigo: list[str] | None = None

    def __init__(self, **data: Any) -> None:
        """Construct from kwargs and sort the reference list."""
        super().__init__(**data)
        if self.indigo:
            self.indigo = sorted(self.indigo)


class customReferences(BaseModelWithAccessors):
    """Open-ended custom reference container.

    Holds project- or deployment-specific reference identifiers that
    don't fit the other reference namespaces. Permits arbitrary extra
    fields (``extra="allow"``) so unknown reference types pass through
    unchanged.

    Attributes:
        references (list[Any] | None): Free-form reference entries, sorted
            in ascending order on construction.
    """

    model_config = ConfigDict(extra="allow")
    references: list[Any] | None = None

    def __init__(self, **data: Any) -> None:
        """Construct from kwargs and sort the reference list."""
        super().__init__(**data)
        if self.references:
            self.references = sorted(self.references)


class Mobileconfigpayload(BaseModelWithAccessors):
    """A single payload inside a configuration profile.

    Configuration profiles ship one or more payloads (each identified by a
    ``PayloadType`` such as ``"com.apple.screensaver"``). This model holds
    the payload type plus its content as a list of key-value dicts.

    Attributes:
        payload_type (str): The ``PayloadType`` value (e.g.
            ``"com.apple.screensaver"``).
        payload_content (list[dict[str, Any]]): One or more dicts of
            preference settings to apply within the payload.
    """

    payload_type: str
    payload_content: list[dict[str, Any]]


class References(BaseModelWithAccessors):
    """Container for all reference namespaces attached to a rule.

    `nist` is required (every rule has at least a NIST mapping); the rest
    are optional. Extra fields are allowed so additional reference
    namespaces can be loaded without code changes.

    Attributes:
        nist (NistReferences): NIST identifiers (CCE, 800-53r5, 800-171r3).
        disa (DisaReferences | None): DISA identifiers, if applicable.
        cis (CisReferences | None): CIS identifiers, if applicable.
        bsi (bsiReferences | None): BSI identifiers, if applicable.
        custom_refs (customReferences | None): Project-specific custom
            references, if any.
    """

    model_config: ConfigDict = ConfigDict(extra="allow")

    nist: NistReferences
    disa: DisaReferences | None = None
    cis: CisReferences | None = None
    bsi: bsiReferences | None = None
    custom_refs: customReferences | None = None

    def get_ref(
        self,
        key: str,
        *,
        default: Any = _SENTINEL,
        case_insensitive: bool = True,
        search_order: Iterable[str] = ("nist", "disa", "cis", "bsi"),
    ) -> Any:
        """Look up a reference value by namespace-qualified or bare key.

        Two lookup styles are supported:

        - **Namespaced**: ``"nist.cce"`` reads the named field from a
          specific submodel.
        - **Unqualified**: ``"cce"`` scans submodels in `search_order` and
          returns the first match (values from the unqualified path are
          coerced to ``list[str]``).

        For convenience, three legacy keys are translated automatically:
        ``"800-53r5"`` → ``"nist_800_53r5"``, ``"800-171r3"`` →
        ``"nist_800_171r3"``, and ``"cis"`` → ``"benchmark"``.

        Args:
            key (str): Field name to look up, optionally namespace-prefixed
                with ``"."``.
            default (Any): Sentinel-defaulted; if supplied, returned when
                the key is missing instead of raising. Pass any value
                (including ``None``) to opt in to defaulting.
            case_insensitive (bool): If true (the default), field names are
                compared in lowercase.
            search_order (Iterable[str]): Submodel attribute names to scan
                in order for unqualified keys. Defaults to
                ``("nist", "disa", "cis", "bsi")``.

        Returns:
            Any: The matched reference value. For unqualified lookups the
                value is coerced to ``list[str]``.

        Raises:
            KeyError: If the key is not found and no `default` was given.
                The message indicates whether the namespace was missing
                or the field was missing within the namespace.
        """

        def _dump_fields(model) -> dict[str, Any]:
            # Use model_dump to get field values (including None)
            d = model.model_dump(exclude_none=False)
            if case_insensitive:
                return {k.lower(): v for k, v in d.items()}
            return d

        # account for python limitations for attribute names (800-53r5 and 800-171r2)
        if key == "800-53r5":
            key = "nist_800_53r5"
        if key == "800-171r3":
            key = "nist_800_171r3"
        if key == "cis":  # assume they want to pull the benchmark reference
            key = "benchmark"

        # 1) Namespaced key: 'nist.control_id'
        if "." in key:
            ns, field = key.split(".", 1)
            ns_attr = ns.strip()
            field_key = field.strip()
            if case_insensitive:
                field_key = field_key.lower()

            submodel = getattr(self, ns_attr, None)
            if submodel is None:
                if default is not _SENTINEL:
                    return default
                raise KeyError(f"Namespace '{ns_attr}' not present")

            fields = _dump_fields(submodel)
            if field_key in fields:
                return fields[field_key]

            if default is not _SENTINEL:
                return default
            raise KeyError(f"Field '{field}' not found in '{ns_attr}'")

        # 2) Unqualified field: scan submodels in the given order
        field_key = key.strip()
        if case_insensitive:
            field_key = field_key.lower()

        for ns_attr in search_order:
            submodel = getattr(self, ns_attr, None)
            if submodel is None:
                continue
            fields = _dump_fields(submodel)
            if field_key in fields:
                return [str(x) for x in (fields[field_key] or [])]

        # Not found
        if default is not _SENTINEL:
            return default

        raise KeyError(
            f"Field '{key}' not found in any namespace ({', '.join(search_order)})"
        )


class Macsecurityrule(BaseModelWithAccessors):
    """A macOS security rule.

    The top-level domain object for mSCP. Combines rule metadata (title,
    discussion, references), enforcement information (`check`, `fix`,
    `mechanism`), and platform / version targeting. Instances are normally
    constructed via `load_rules` or `collect_all_rules` rather than
    directly.

    Attributes:
        title (str): Human-readable title shown in generated guidance.
        rule_id (str): Unique identifier for the rule (matches the YAML
            file stem).
        discussion (str): Long-form discussion or rationale for the rule.
        references (References): NIST / DISA / CIS / BSI / custom
            reference identifiers grouped by namespace.
        odv (dict[str, Any] | None): Organizational Defined Values keyed
            by benchmark name, plus optional ``hint`` / ``custom`` entries.
        finding (bool): True if the rule is a finding rather than a
            configuration setting. Defaults to ``False``.
        tags (list[str]): Tag list categorising the rule (e.g.
            ``"inherent"``, ``"permanent"``, ``"n_a"``,
            ``"supplemental"``).
        result_value (str | int | bool | None): Expected result for
            compliance, when applicable.
        mobileconfig_info (list[Mobileconfigpayload] | None): Configuration
            profile payloads when the rule is enforced via a profile;
            ``None`` otherwise.
        ddm_info (dict[str, Any] | None): Declarative Device Management
            payload, when applicable.
        customized (list[str]): Field names that have been overridden by
            customisation files.
        mechanism (str): Enforcement mechanism — one of ``"Manual"``,
            ``"Script"``, ``"Configuration Profile"``, ``"Inherent"``,
            ``"Permanent"``, ``"N/A"``.
        section (str | None): Section name the rule belongs to (e.g.
            ``"Operating System"``, ``"Inherent"``).
        uuid (str): Per-instance UUID4 string. Generated automatically.
        platforms (dict[str, dict[str, Any]]): Platform-specific data
            from the YAML, keyed by OS family then version.
        os_name (str): OS marketing name resolved from version data
            (e.g. ``"Sequoia"``).
        os_type (str): OS family (e.g. ``"macOS"``).
        os_version (float): Target OS version as a float (e.g. ``15.0``).
            Defaults to ``0.0``.
        check (str | None): Shell command that evaluates rule state.
        fix (str | None): Shell command that brings the system into
            compliance, or instructional text for non-script mechanisms.
        severity (str | None): Severity for the matching benchmark, when
            specified.
        default_state (str | None): Shell command that restores the
            default configuration, when defined.
    """

    title: str
    rule_id: str
    discussion: str
    references: References
    odv: dict[str, Any] | None = None
    finding: bool = False
    tags: list[str] = Field(default_factory=list)
    result_value: str | int | bool | None = None
    mobileconfig_info: list[Mobileconfigpayload] | None = None
    ddm_info: dict[str, Any] | None = None
    customized: list[str] = Field(default_factory=list)
    mechanism: str
    section: str | None
    uuid: str = Field(default_factory=lambda: str(uuid4()))
    platforms: dict[str, dict[str, Any]] = Field(default_factory=dict)
    os_name: str
    os_type: str
    os_version: float = Field(default_factory=float)
    check: str | None = None
    fix: str | None = None
    severity: str | None = None
    default_state: str | None = None

    @classmethod
    def load_rules(
        cls,
        rule_ids: list[str],
        os_type: str,
        os_version: float,
        parent_values: str,
        section: str,
        tailoring: bool = False,
        language: str = "en",
    ) -> list["Macsecurityrule"]:
        """Load `Macsecurityrule` objects for a list of rule IDs.

        Resolves each rule ID against ``config["rules_dir"]`` (and the
        custom rules directory when not tailoring), parses the YAML, and
        applies any matching customisations (references / tags / platforms
        merge; other keys overwrite). Rules whose YAML lacks the requested
        ``os_type`` / ``os_version`` are skipped with a debug log.

        Args:
            rule_ids (list[str]): Rule IDs to load.
            os_type (str): Operating system family (e.g. ``"macOS"``).
            os_version (float): Operating system version (e.g. ``15.0``).
            parent_values (str): Benchmark name used as the ODV lookup key
                in `_fill_in_odv`.
            section (str): Section label assigned to the loaded rules
                (used for logging and falls through into the rule when
                no special-section override applies).
            tailoring (bool): If true, suppresses loading of customisation
                overrides (used when the caller is producing a tailored
                benchmark). Defaults to ``False``.
            language (str): Language code passed to `open_file` for
                localised text. Defaults to ``"en"``.

        Returns:
            list[Macsecurityrule]: Successfully loaded rules. Rules whose
                YAML file is missing or whose platform/version is not
                supported are skipped silently.
        """

        logger.info("=== LOADING {} RULES ===", section.upper())

        rules: list[Macsecurityrule] = []
        os_version_str: str = str(float(os_version))
        os_version_int: int = int(os_version)
        current_version_data: dict[str, Any] = get_version_data(
            os_type, os_version, mscp_data
        )
        os_name: str = current_version_data["os_name"]
        os_typeversion: str = f"{os_type}_{os_version_int}".lower()
        os_type = os_type.replace("os", "OS")

        rules_dirs: list[Path] = [
            Path(config["rules_dir"]),
        ]

        # collect custom rules if they exist
        if tailoring:
            custom_rule_dict = {}
        else:
            custom_rule_dict = collect_overrides(Path(config["custom"]["rules_dir"]))

        for rule_id in rule_ids:
            logger.debug("Transforming rule: {}", rule_id)

            result_value: str | int | bool | None = None
            check_value: str | None = None
            fix_value: str | None = None
            default_state_value: str | None = None
            mechanism: str = "Manual"
            payloads: list[Mobileconfigpayload] | None = []
            severity: str | None = None
            tags: list[str] = []

            rule_file = next(
                (
                    file
                    for rules_dir in rules_dirs
                    if rules_dir.exists()
                    for pattern in (f"{rule_id}.y*ml", f"{rule_id}.json")
                    for file in rules_dir.rglob(pattern)
                ),
                None,
            )

            if not rule_file:
                logger.warning("Rule file not found for rule: {}", rule_id)
                continue

            rule_yaml: dict[str, Any] = open_file(rule_file, language)

            tags: list[str] = rule_yaml.get("tags", [])

            if os_type not in rule_yaml.get("platforms", {}):
                logger.debug(
                    "Rule {} does not support the OS type: {}. Skipping rule.",
                    rule_id,
                    os_type,
                )
                continue

            if os_version_str not in rule_yaml["platforms"][os_type]:
                logger.debug(
                    "Rule {} does not support the OS version: {}. Skipping rule.",
                    rule_id,
                    os_version_str,
                )
                continue

            rule_yaml["rule_id"] = rule_yaml.pop("id", rule_id)

            # process any customized rules
            customized_fields = []

            if rule_yaml["rule_id"] in custom_rule_dict:
                logger.info(f"Found customization for {rule_yaml['rule_id']}")
                for custom_rule_key, custom_rule_value in custom_rule_dict[
                    rule_yaml["rule_id"]
                ].items():
                    logger.debug(
                        f"Found customization ({custom_rule_value}) for {custom_rule_key} in {rule_yaml['rule_id']}"
                    )
                    customized_fields.append(custom_rule_key)
                    if custom_rule_key == "references":
                        rule_yaml[custom_rule_key].update(custom_rule_value)
                        continue
                    if custom_rule_key == "tags":
                        if custom_rule_value not in rule_yaml[custom_rule_key]:
                            rule_yaml[custom_rule_key] += custom_rule_value
                        continue
                    if custom_rule_key == "platforms":
                        rule_yaml[custom_rule_key] |= custom_rule_value
                        continue
                    rule_yaml[custom_rule_key] = custom_rule_value

            enforcement_info = rule_yaml["platforms"][os_type].get(
                "enforcement_info", {}
            )
            if enforcement_info and "n_a" not in tags:
                check_shell = enforcement_info.get("check", {}).get("shell")
                check_result = enforcement_info.get("check", {}).get("result")
                fix_shell = enforcement_info.get("fix", {}).get("shell")
                additional_info = enforcement_info.get("fix", {}).get("additional_info")
                default_state_shell = enforcement_info.get("default_state", {}).get(
                    "shell"
                )

                if check_result:
                    for k, v in rule_yaml["platforms"][os_type]["enforcement_info"][
                        "check"
                    ]["result"].items():
                        if isinstance(v, (int, bool, str)):
                            result_value = v
                            break
                        elif k == "base64":
                            result_encoded: bytes = base64.b64encode(v.encode("UTF-8"))
                            result_value = result_encoded.decode("utf-8")
                            break

                if check_shell and fix_shell:
                    mechanism = "Script"

                    check_value = check_shell
                    fix_value = fix_shell

                if check_shell:
                    check_value = check_shell

                if default_state_shell:
                    default_state_value = default_state_shell

                if (
                    not check_shell
                    or not fix_shell
                    or not check_value
                    and additional_info
                ):
                    fix_value = None

            if "mobileconfig_info" in rule_yaml:
                mechanism = "Configuration Profile"

                for entry in rule_yaml["mobileconfig_info"]:
                    payload_type: str = str(
                        entry.get("PayloadType", entry.get("payload_type", ""))
                    )
                    payload_content: list[dict[str, Any]] = entry.get(
                        "PayloadContent", entry.get("payload_content", [])
                    )

                    payloads.append(
                        Mobileconfigpayload(
                            payload_type=payload_type,
                            payload_content=payload_content,
                        )
                    )

                # Not all mobile configs follow this pattern

                # if check_value and "osascript" in check_value:
                #     # Get the first key from the first payload_content dict
                #     first_key = list(payloads[0].payload_content[0].keys())[0]
                #     check_value = f"/usr/bin/osascript -l JavaScript -e \"$.NSUserDefaults.alloc.initWithSuiteName('{payloads[0].payload_type}').objectForKey('{first_key}').js\""

                rule_yaml.pop("mobileconfig_info", None)
            else:
                payloads = None

            benchmarks: list[dict[str, str]] = rule_yaml["platforms"][os_type][
                os_version_str
            ].get("benchmarks", [])

            if benchmarks:
                for benchmark in benchmarks:
                    name = benchmark.get("name")
                    if "severity" in benchmark and name == parent_values:
                        severity = benchmark.get("severity", "")

            match tags:
                case "inherent":
                    mechanism = "Inherent"
                    fix_value = "The control cannot be configured out of compliance."
                    section = Sectionmap.INHERENT
                case "permanent":
                    mechanism = "Permanent"
                    fix_value = "The control is not able to be configured to meet the requirement. It is recommended to implement a third-party solution to meet the control."
                    section = Sectionmap.PERMANENT
                case "not_applicable" | "n_a":
                    mechanism = "N/A"
                    fix_value = (
                        "The control is not applicable when configuring a macOS system."
                    )
                    section = Sectionmap.NOT_APPLICABLE

            reference_keys = rule_yaml["references"].keys()
            nist: dict[str, Any] = {}
            disa: dict[str, Any] = {}
            cis: dict[str, Any] = {}
            bsi: dict[str, Any] = {}
            custom_refs: dict[str, Any] = {}

            for ref_key in reference_keys:
                if ref_key == "nist":
                    nist: dict[str, Any] = rule_yaml["references"].get("nist", {})
                elif ref_key == "disa":
                    disa: dict[str, Any] = rule_yaml["references"].get("disa", {})
                elif ref_key == "cis":
                    cis: dict[str, Any] = rule_yaml["references"].get("cis", {})
                elif ref_key == "bsi":
                    bsi: dict[str, Any] = rule_yaml["references"].get("bsi", {})
                elif ref_key == "custom":  # support for 1.0 custom refs format
                    for custom_ref_key in rule_yaml["references"]["custom"]:
                        custom_refs[custom_ref_key] = rule_yaml["references"][
                            "custom"
                        ].get(custom_ref_key, {})
                else:
                    custom_refs[ref_key] = rule_yaml["references"].get(ref_key, {})

            # Map NIST references
            nist_map = {
                "800-53r5": "nist_800_53r5",
                "800-171r3": "nist_800_171r3",
                "cce": "cce",
            }

            for src, dst in nist_map.items():
                if src in nist and nist[src] is not None:
                    value = nist.pop(src)
                    if src == "cce" and isinstance(value, dict):
                        value = value.get(os_typeversion)
                        # print(value)
                        # if value is not None and not isinstance(value, dict):
                        #     # Ensure cce is always a dict[str, list[str]] or None
                        #     value = None
                    if dst in ("nist_800_53r5", "nist_800_171r3"):
                        if value is not None and not isinstance(value, list):
                            value = [value] if isinstance(value, str) else None
                    nist[dst] = value

            # Map CIS benchmark
            if cis and "benchmark" in cis:
                if isinstance(cis["benchmark"], dict):
                    cis["benchmark"] = cis["benchmark"].get(os_typeversion)
                if cis["benchmark"] is not None and not isinstance(
                    cis["benchmark"], list
                ):
                    cis["benchmark"] = [cis["benchmark"]]

            # Map DISA references
            if disa:
                if "disa_stig" in disa and isinstance(disa["disa_stig"], dict):
                    disa["disa_stig"] = disa["disa_stig"].get(os_typeversion)
                    if disa["disa_stig"] is not None and not isinstance(
                        disa["disa_stig"], list
                    ):
                        disa["disa_stig"] = [disa["disa_stig"]]

            # Map BSI references
            if bsi:
                if "indigo" in bsi and isinstance(bsi["indigo"], dict):
                    bsi["indigo"] = bsi["indigo"].get(os_typeversion)
                    if bsi["indigo"] is not None and not isinstance(
                        bsi["indigo"], list
                    ):
                        bsi["indigo"] = [bsi["indigo"]]
            # Map custom references
            if custom_refs:
                rule_yaml["references"]["custom_refs"] = {}
                rule_yaml["references"]["custom_refs"]["references"] = [custom_refs]

            rule = cls(
                **rule_yaml,
                result_value=result_value,
                customized=customized_fields,
                mobileconfig_info=payloads,
                mechanism=mechanism,
                section=section,
                os_name=os_name,
                os_type=os_type,
                os_version=os_version,
                check=check_value,
                fix=fix_value,
                default_state=default_state_value,
                severity=severity,
            )

            # removed to prevent any fix: code from being generated in compliance script for mobileconfigs
            # if rule.mobileconfig_info:
            #     logger.debug("Formatting mobileconfig_info for rule: {}", rule.rule_id)
            #     rule._format_mobileconfig_fix()
            #     logger.success("Formatted mobileconfig_info for rule: {}", rule.rule_id)

            if rule.odv is not None and parent_values is not None:
                rule._fill_in_odv(parent_values)

            logger.success("Transformed rule: {}", rule_id)

            rules.append(rule)

        logger.debug("NUMBER OF {} LOADED RULES: {}", section.upper(), len(rules))
        logger.info("=== RULES {} LOADED ===", section.upper())

        return rules

    @classmethod
    def collect_all_rules(
        cls,
        os_type: str,
        os_version: int,
        tailoring: bool = False,
        parent_values: str = "default",
    ) -> list["Macsecurityrule"]:
        """Load every rule under ``config["rules_dir"]`` for an OS/version.

        Walks each subfolder of the rules directory (skipping
        ``sysprefs``), maps each folder name through `Sectionmap` to the
        matching section file, and delegates per-section loading to
        `load_rules`.

        Args:
            os_type (str): Operating system family (e.g. ``"macOS"``).
            os_version (int): Operating system version.
            tailoring (bool): If true, skips customisation overrides.
                Defaults to ``False``.
            parent_values (str): ODV lookup key forwarded to `load_rules`.
                Defaults to ``"default"``.

        Returns:
            list[Macsecurityrule]: All rules across all sections that
                match the given platform.
        """

        logger.info("=== LOADING ALL RULES ===")

        rules: list[Macsecurityrule] = []
        rules_to_collect = defaultdict(list)

        section_dirs: list[Path] = [
            Path(config["custom"]["sections_dir"]),
            Path(config["sections_dir"]),
        ]

        rules_dirs: list[Path] = [
            Path(config["rules_dir"]),
        ]

        section_data: dict[str, str] = {
            section_file.stem: open_file(section_file).get("name", "")
            for section_dir in section_dirs
            for section_file in section_dir.glob("*.y*ml")
            if section_file.is_file()
        }

        for rule_dir in rules_dirs:
            if not rule_dir.exists() or not rule_dir.is_dir():
                logger.warning(
                    "Directory does not exist or is not a directory: {}", rule_dir
                )
                continue

            for folder in rule_dir.iterdir():
                if not folder.is_dir():
                    continue

                if folder.name == "sysprefs":
                    continue

                for rule_file in folder.rglob("*.y*ml"):
                    try:
                        rule_name: str = rule_file.stem
                        folder_name: str = rule_file.parent.name
                        logger.debug("{} folder: {}", rule_name, folder_name)
                        section_name: str = section_data.get(
                            Sectionmap[folder_name.upper()], ""
                        )
                        logger.debug("Section Name: {}", section_name)

                        if not section_name:
                            logger.warning(
                                "Folder '{}' not found in section mapping.", folder_name
                            )
                            continue

                        rules_to_collect[section_name].append(rule_name)

                    except Exception as e:
                        logger.error(
                            "Failed to load rule from file {}: {}", rule_file, e
                        )

        for section, collected_rules in rules_to_collect.items():
            rules += cls.load_rules(
                rule_ids=collected_rules,
                os_type=os_type,
                os_version=os_version,
                parent_values=parent_values,
                section=section,
                tailoring=tailoring,
            )
        logger.info("=== ALL RULES LOADED ===")

        return rules

    def _format_mobileconfig_fix(self) -> None:
        """
        Generate a formatted XML-like string for the `mobileconfig_info` field.

        Handles special cases such as `com.apple.ManagedClient.preferences`.

        This method updates the `fix` attribute of the instance but does not return anything.
        """
        if not self.mobileconfig_info:
            return

        rulefix = ""

        for payload in self.mobileconfig_info:
            if payload.payload_type == "com.apple.ManagedClient.preferences":
                rulefix += (
                    f"NOTE: The following settings are in the ({payload.payload_type}) payload. "
                    "This payload requires the additional settings to be sub-payloads within, "
                    "containing their defined payload types.\n\n"
                )

                if isinstance(payload.payload_content, list):
                    for item in payload.payload_content:
                        if isinstance(item, dict):
                            for (
                                nested_payload_type,
                                nested_payload_content,
                            ) in item.items():
                                nested_fix = self.format_payload(
                                    nested_payload_type, nested_payload_content
                                )
                                rulefix += nested_fix
                        else:
                            logger.warning(
                                "Unexpected item type in payload_content list: {}",
                                type(item),
                            )

                if isinstance(payload.payload_content, dict):
                    # Recursively process nested payloads
                    for (
                        nested_payload_type,
                        nested_payload_content,
                    ) in payload.payload_content.items():
                        nested_fix = self.format_payload(
                            nested_payload_type, nested_payload_content
                        )
                        rulefix += nested_fix

            rulefix += self.format_payload(
                payload.payload_type, payload.payload_content
            )

        self._update_fix_for_configuration_profile()

    def _update_fix_for_configuration_profile(self) -> None:
        """
        Update the `fix` attribute or the enforcement info for configuration profiles.
        """
        if self.mechanism == "Configuration Profile":
            if (
                not self.platforms.get(self.os_type, {})
                .get("enforcement_info", {})
                .get("fix")
            ):
                if self.mobileconfig_info and len(self.mobileconfig_info) > 0:
                    self.fix = (
                        f"Create a configuration profile containing the following keys in the "
                        f"({self.mobileconfig_info[0].payload_type}) payload type:\n\n"
                        + self.format_payload(
                            self.mobileconfig_info[0].payload_type,
                            self.mobileconfig_info[0].payload_content,
                        )
                    )
            else:
                if self.mobileconfig_info and len(self.mobileconfig_info) > 0:
                    self.platforms[self.os_type]["enforcement_info"]["fix"] = (
                        self.format_payload(
                            self.mobileconfig_info[0].payload_type,
                            self.mobileconfig_info[0].payload_content,
                        )
                    )

    @staticmethod
    def format_payload(
        payload_type: str,
        payload_content: list[dict] | dict,
        jinja_filter: bool = False,
    ) -> str:
        """Render a single payload as XML wrapped for AsciiDoc output.

        Builds a ``<Payload>`` XML tree from ``payload_content`` (each
        dict becomes a sequence of ``<key>`` / value-element pairs) and
        pretty-prints it. Unless ``jinja_filter`` is set, the output is
        wrapped in an AsciiDoc ``[source,xml]`` block delimited by
        ``----``.

        Args:
            payload_type (str): The ``PayloadType`` value (currently
                included only for symmetry with `Mobileconfigpayload` —
                the rendered XML uses a fixed ``<Payload>`` root).
            payload_content (list[dict] | dict): The payload's content
                section. Lists of dicts are unpacked; bare dicts are
                ignored at the moment (use a single-element list).
            jinja_filter (bool): If true, omit the AsciiDoc source-block
                wrappers and emit only the XML. Defaults to ``False``.

        Returns:
            str: The rendered payload, ready to splice into generated
                guidance.
        """

        output: str = ""

        if not jinja_filter:
            output = "[source,xml]\n----\n"

        # Generate XML for the payload content
        root = etree.Element("Payload", attrib=None, nsmap=None)
        if isinstance(payload_content, list):
            for payload in payload_content:
                if isinstance(payload, dict):
                    elements = []
                    for key, value in payload.items():
                        # Create a <key> element
                        key_element = etree.Element("key", attrib=None, nsmap=None)
                        key_element.text = key
                        elements.append(key_element)

                        # Create the corresponding value element
                        value_element = Macsecurityrule._create_value_element(value)
                        elements.append(value_element)

                    # Append all elements to the root element
                    for element in elements:
                        root.append(element)

        # Pretty-print the XML content
        output += (
            etree.tostring(root, encoding="unicode", pretty_print=True)
            .strip()
            .replace("<root>", "")
            .replace("</root>", "")
            + "\n"
        )

        if not jinja_filter:
            output += "----\n\n"

        return output

    @staticmethod
    def _add_payload_content(parent: etree.Element, content: dict) -> None:
        """
        Add payload content as XML elements to the parent node.

        Args:
            parent (etree.Element): The parent XML element.
            content (dict): The dictionary of key-value pairs to process.
        """
        for key, value in content.items():
            key_element = etree.SubElement(parent, "key", attrib=None, nsmap=None)
            key_element.text = key

            match value:
                case bool():
                    etree.SubElement(
                        parent, "true" if value else "false", attrib=None, nsmap=None
                    )
                case int():
                    int_element = etree.SubElement(
                        parent, "integer", attrib=None, nsmap=None
                    )
                    int_element.text = str(value)
                case str():
                    str_element = etree.SubElement(
                        parent, "string", attrib=None, nsmap=None
                    )
                    str_element.text = value
                case list():
                    array_element = etree.SubElement(
                        parent, "array", attrib=None, nsmap=None
                    )
                    for item in value:
                        item_element = etree.SubElement(
                            array_element, "string", attrib=None, nsmap=None
                        )
                        item_element.text = item
                case dict():
                    dict_element = etree.SubElement(
                        parent, "dict", attrib=None, nsmap=None
                    )
                    Macsecurityrule._add_payload_content(dict_element, value)
                case _:
                    logger.error(
                        "Unsupported value type: {} for value: {}", type(value), value
                    )
                    raise ValueError(
                        f"Unsupported value type: {type(value)} for key: {key}"
                    )

    @staticmethod
    def _create_value_element(value: Any) -> etree.Element:
        """
        Creates an XML element based on the type of the provided value.

        Args:
            value (Any): The value to be converted into an XML element. Supported types are:
                - bool: Creates an element with tag "true" or "false".
                - int: Creates an element with tag "integer" and the integer value as text.
                - str: Creates an element with tag "string" and the string value as text.
                - list: Creates an element with tag "array" and each item in the list as a "string" sub-element.
                - dict: Creates an element with tag "dict" and adds the dictionary content as sub-elements.

        Returns:
            etree.Element: The created XML element based on the provided value.

        Raises:
            ValueError: If the provided value type is not supported.
        """
        match value:
            case bool():
                return etree.Element(
                    "true" if value else "false", attrib=None, nsmap=None
                )
            case int():
                int_element = etree.Element("integer", attrib=None, nsmap=None)
                int_element.text = str(value)
                return int_element
            case float():
                float_element = etree.Element("real", attrib=None, nsmap=None)
                float_element.text = str(value)
                return float_element
            case str():
                str_element = etree.Element("string", attrib=None, nsmap=None)
                str_element.text = value
                return str_element
            case list():
                array_element = etree.Element("array", attrib=None, nsmap=None)
                for item in value:
                    item_element = etree.SubElement(
                        array_element, "string", attrib=None, nsmap=None
                    )
                    item_element.text = item
                return array_element
            case dict():
                dict_element = etree.Element("dict", attrib=None, nsmap=None)
                Macsecurityrule._add_payload_content(dict_element, value)
                return dict_element
            case _:
                logger.error(
                    "Unsupported value type: {} for value: {}", type(value), value
                )
                raise ValueError(f"Unsupported value type: {type(value)}")

    def _fill_in_odv(self, parent_values: str) -> None:
        """
        Replaces placeholders ('$ODV') in the instance attributes with the appropriate override value
        based on the parent_values key.

        Args:
            parent_values (str): The key to look up in the 'odv' dictionary. Expected format is a string
                                 representing the parent value category, such as 'custom', 'recommended',
                                 or any other specific category defined in the 'odv' dictionary.

        Returns:
            None: Modifies the instance attributes in place.
        """
        if self.odv is None:
            logger.warning("No ODV dictionary found for rule: {}", self.rule_id)
            return

        odv_lookup: dict[str, Any] = self.odv
        if "odv" in self.customized:
            odv_value: str | int | bool | None = odv_lookup.get("custom")
        else:
            odv_value: str | int | bool | None = odv_lookup.get(parent_values)
        if odv_value is None:
            return
        # Replace $ODV in text fields

        # Added check and result to the ODV fields processed
        fields_to_process: tuple[str, ...] = (
            "title",
            "discussion",
            "check",
            "fix",
            "result_value",
        )

        # Helper function to recursively replace $ODV in nested structures
        def replace_odv_in_obj(obj):
            if isinstance(obj, str) and "$ODV" in obj:
                if obj == "$ODV":
                    return odv_value
                return obj.replace("$ODV", str(odv_value))
            elif isinstance(obj, dict):
                return {k: replace_odv_in_obj(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_odv_in_obj(item) for item in obj]
            else:
                return obj

        for field in fields_to_process:
            value = getattr(self, field, None)
            if value is not None:
                setattr(self, field, replace_odv_in_obj(value))

        # Replace $ODV in mobileconfig_info
        if self.mobileconfig_info is not None:
            for payload in self.mobileconfig_info:
                payload.payload_content = replace_odv_in_obj(payload.payload_content)

        # Replace $ODV in ddm_info
        if self.ddm_info is not None:
            self.ddm_info = replace_odv_in_obj(self.ddm_info)

        if self.platforms is not None:
            self.platforms = replace_odv_in_obj(self.platforms)

    def write_odv_custom_rule(self, odv: Any) -> None:
        """Persist a custom ODV value for this rule.

        Updates ``self.odv["custom"]`` with ``odv``, clears the
        ``customized`` list, and writes a minimal YAML file containing
        only the ``odv`` key into ``config["custom"]["rules_dir"]``.

        Args:
            odv (Any): The custom ODV value to record. Stored verbatim
                under the ``"custom"`` key of `odv`.
        """
        rule_file_path: Path = Path(
            f"{config['custom']['rules_dir']}", f"{self.rule_id}.yaml"
        )

        make_dir(rule_file_path.parent)

        self["odv"]["custom"] = odv

        self.customized = []

        self.to_yaml(rule_file_path, "odv")

    def remove_custom_rule(self) -> None:
        """Delete the per-rule custom YAML, if it exists.

        Removes ``<custom_rules_dir>/<rule_id>.yaml`` from disk. Missing
        files are tolerated and produce only a warning log.
        """
        rule_file_path: Path = Path(
            f"{config['custom']['rules_dir']}", f"{self.rule_id}.yaml"
        )

        try:
            rule_file_path.unlink()
            logger.info("Custom rule file deleted: {}", rule_file_path)
        except FileNotFoundError:
            logger.warning("Rule file not found: {}", rule_file_path)

    def write_excluded_custom_rule_discussion(self) -> None:
        """Persist the modified discussion for an excluded rule.

        Writes a minimal YAML file under ``config["custom"]["rules_dir"]``
        containing only the ``discussion`` field. The caller is expected
        to have already prepended the exclusion notice to
        ``self.discussion``.
        """
        rule_file_path: Path = Path(
            f"{config['custom']['rules_dir']}", f"{self.rule_id}.yaml"
        )

        make_dir(rule_file_path.parent)

        self.to_yaml(rule_file_path, "discussion")

    @classmethod
    def odv_query(
        cls, rules: list["Macsecurityrule"], benchmark: str
    ) -> list["Macsecurityrule"]:
        """Walk a rule list interactively to include / exclude / set ODVs.

        For each rule, prompts whether to include it (with options ``y``,
        ``n``, ``all``, ``?``) and, when included and an ODV is defined,
        prompts for the ODV value. Excluded rules have an exclusion notice
        prepended to their `discussion`, are reassigned to the
        ``"Excluded"`` section, and are still returned in the result list
        (so callers can render them as exclusions). Rules tagged
        ``inherent`` are always included without prompting.

        This method writes to disk via `write_odv_custom_rule` and
        `write_excluded_custom_rule_discussion` as the user makes choices,
        and prints to stdout.

        Args:
            rules (list[Macsecurityrule]): Rules to walk.
            benchmark (str): Benchmark name being tailored. When equal to
                ``"recommended"`` the recommended ODV is used as the
                default; otherwise the benchmark-specific ODV is used and
                a warning is printed.

        Returns:
            list[Macsecurityrule]: Both included rules and excluded rules
                (with exclusion notices applied), ready to be written into
                a tailored baseline.
        """
        print(
            "The inclusion of any given rule is a risk-based-decision (RBD). "
            "While each rule is mapped to an 800-53 control, deploying it in your organization "
            "should be part of the decision-making process.\n"
        )

        if benchmark != "recommended":
            print(
                "WARNING: You are tailoring an established benchmark. Excluding rules or modifying ODVs "
                "may result in non-compliance with the benchmark.\n"
            )

        included_rules: list[Macsecurityrule] = []
        queried_rule_ids: list[str] = []
        include_all: bool = False
        _always_include: tuple[str, ...] = ("inherent",)

        for rule in rules:
            get_odv: bool = False

            # Default inclusion logic for certain tags
            if any(tag in rule.tags for tag in _always_include):
                include = "y"
            elif include_all:
                if rule.rule_id not in queried_rule_ids:
                    include = "y"
                    get_odv = True
                    queried_rule_ids.append(rule.rule_id)
            else:
                if rule.rule_id not in queried_rule_ids:
                    include = sanitize_input(
                        f'Would you like to include the rule for "{rule.rule_id}" in your benchmark? [Y/n/all/?]: ',
                        str,
                        range_=("Y", "y", "n", "all", "?"),
                        default_="y",
                    )
                    if include == "?":
                        print(f"Rule Details: \n{rule.discussion}")
                        include = sanitize_input(
                            f'Would you like to include the rule for "{rule.rule_id}" in your benchmark? [Y/n/all]: ',
                            str,
                            range_=("Y", "y", "n", "all"),
                            default_="y",
                        )
                    queried_rule_ids.append(rule.rule_id)
                    get_odv = True
                    if include.lower() == "all":
                        include_all = True
                        include = "y"

            if include.lower() == "y":
                included_rules.append(rule)
                rule.remove_custom_rule()
                if rule.odv == "missing":
                    continue
                elif get_odv and rule.odv:
                    # remove custom odv if there
                    rule.remove_custom_rule()
                    odv_hint = rule.odv.get("hint", "")
                    odv_recommended = rule.odv.get("recommended")
                    odv_benchmark = rule.odv.get(benchmark)
                    if benchmark == "recommended":
                        print(f"\nODV value: {odv_hint['description']}")
                        odv = prompt_for_odv(
                            f'Enter the ODV for "{rule.rule_id}" or press Enter for the recommended value ({odv_recommended}): ',
                            odv_hint=odv_hint,
                            default=odv_recommended,
                        )
                        if odv != odv_recommended:
                            rule.write_odv_custom_rule(odv)
                    else:
                        print(f"\nODV value: {odv_hint['description']}")
                        odv = prompt_for_odv(
                            f'Enter the ODV for "{rule.rule_id}" or press Enter for the default value ({odv_benchmark}): ',
                            odv_hint=odv_hint,
                            default=odv_benchmark,
                        )
                        if odv != odv_benchmark:
                            rule.write_odv_custom_rule(odv)
            else:
                reason: str = sanitize_input(
                    "Enter a reason for excluding this rule from your organization's benchmark (the reason will be added to the rule discussion): "
                )
                if reason:
                    rule.discussion = f"NOTE: This rule has been excluded from the benchmark for the following reason: {reason}\n\n{rule.discussion}"
                else:
                    rule.discussion = f"NOTE: This rule has been excluded from the benchmark.\n\n{rule.discussion}"
                rule.section = "Excluded"
                rule.write_excluded_custom_rule_discussion()
                included_rules.append(rule)

        return included_rules

    def to_yaml(self, output_path: Path, *fields) -> None:
        """Serialise this rule to a YAML file in canonical key order.

        Top-level keys are written in the order ``id``, ``title``,
        ``discussion``, ``references``, ``customized``, ``platforms``,
        ``tags``, ``odv``, ``mobileconfig``, ``mobileconfig_info``,
        ``ddm_info`` (any keys not in this list are dropped). NIST
        references that use Python-friendly attribute names
        (``nist_800_53r5`` / ``nist_800_171r3``) are renamed back to their
        canonical YAML keys (``800-53r5`` / ``800-171r3``), and reference
        list values are sorted with ``None`` / ``"NA"`` / ``"N/A"``
        entries dropped.

        If positional ``fields`` are supplied, only those keys are written
        (used by `write_odv_custom_rule` and
        `write_excluded_custom_rule_discussion` to write minimal
        per-customisation files). When no ``fields`` are given, empty
        sections are dropped except for the always-required keys
        ``id`` / ``title`` / ``discussion`` / ``references`` /
        ``platforms``.

        Args:
            output_path (Path): Destination YAML file.
            *fields (str): Optional whitelist of top-level keys to write.
                When supplied, all other keys are stripped. The ``odv``
                key is additionally restricted to ``hint`` / ``custom``.
        """
        key_order: list[str] = [
            "id",
            "title",
            "discussion",
            "references",
            "customized",
            "platforms",
            "tags",
            "odv",
            "mobileconfig",
            "mobileconfig_info",
            "ddm_info",
        ]

        required_keys: tuple[str, ...] = (
            "id",
            "title",
            "discussion",
            "references",
            "platforms",
        )

        rule_file_path: Path = output_path
        serialized_data: dict[str, Any] = self.model_dump(exclude_none=True)
        ordered_data = OrderedDict()

        self._clean_references()

        # handle NIST references that have keys that start with nist_

        # Ensure the structure exists
        refs = serialized_data.setdefault("references", {})
        nist = refs.setdefault("nist", {})

        # --- 800-53r5 ---
        if (v53 := nist.pop("nist_800_53r5", None)) is None:
            v53 = refs.pop("nist_800_53r5", 0)
        nist["800-53r5"] = v53

        # --- 800-171 ---
        if (v171 := nist.pop("nist_800_171r3", None)) is None:
            v171 = refs.pop("nist_800_171r3", 0)
        nist["800-171r3"] = v171

        for key in serialized_data["references"]:
            if isinstance(serialized_data["references"][key], list):
                serialized_data["references"][key] = sorted(
                    [
                        item
                        for item in serialized_data["references"][key]
                        if item not in [None, "NA", "N/A"]
                    ]
                )

        for key in key_order:
            if key in serialized_data:
                ordered_data[key] = serialized_data[key]

        if fields:
            for field in fields:
                clean_dict: dict = {
                    key: value for key, value in ordered_data.items() if key == field
                }
                if field == "odv":
                    odv_fields = ["hint", "custom"]
                    for key in list(clean_dict["odv"].keys()):
                        if key not in odv_fields:
                            del clean_dict["odv"][key]
        else:
            clean_dict: dict = {
                key: value
                for key, value in ordered_data.items()
                if value or key in required_keys
            }

        create_yaml(rule_file_path, clean_dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a plain-dict representation of this rule.

        Thin wrapper around `model_dump` for callers that want a
        non-Pydantic value (e.g. for JSON serialisation).

        Returns:
            dict[str, Any]: All declared fields, including their nested
                sub-models recursively dumped.
        """
        return self.model_dump()

    def _clean_references(self) -> None:
        """
        Clean the references dictionary by removing any keys with values that are None or in ("NA", "N/A").
        """

        def clean_dict(d: dict) -> dict:
            return {
                k: clean_dict(v) if isinstance(v, dict) else v
                for k, v in d.items()
                if v is not None and v not in ("NA", "N/A")
            }

        self.references = References(**clean_dict(self.references.model_dump()))

    @staticmethod
    def mobileconfig_info_to_xml(
        mobileconfig_info: list[dict[str, Any]],
    ) -> str:
        """Render a list of payloads as raw XML.

        Convenience wrapper around `format_payload` with
        ``jinja_filter=True`` so callers (typically Jinja templates) get
        XML without the AsciiDoc source-block delimiters.

        Args:
            mobileconfig_info (list[dict[str, Any]]): Payload dicts with at
                least ``payload_type`` and ``payload_content`` keys
                (matches `Mobileconfigpayload.model_dump()`).

        Returns:
            str: Concatenated XML for every payload, or the empty string
                if `mobileconfig_info` is empty.
        """
        if not mobileconfig_info:
            return ""

        output = ""
        for payload in mobileconfig_info:
            output += Macsecurityrule.format_payload(
                payload["payload_type"],
                payload["payload_content"],
                jinja_filter=True,
            )

        return output

    @staticmethod
    def _create_static_value_element(value: Any) -> etree.Element:
        """
        Static helper to create an XML element based on the type of the provided value.

        Args:
            value (Any): The value to be converted into an XML element.

        Returns:
            etree.Element: The created XML element.
        """
        match value:
            case bool():
                return etree.Element("true" if value else "false")
            case int():
                int_element = etree.Element("integer")
                int_element.text = str(value)
                return int_element
            case str():
                str_element = etree.Element("string")
                str_element.text = value
                return str_element
            case list():
                array_element = etree.Element("array")
                for item in value:
                    item_element = etree.SubElement(array_element, "string")
                    item_element.text = item
                return array_element
            case dict():
                dict_element = etree.Element("dict")
                for k, v in value.items():
                    key_elem = etree.SubElement(dict_element, "key")
                    key_elem.text = k
                    dict_element.append(Macsecurityrule._create_static_value_element(v))
                return dict_element
            case _:
                raise ValueError(f"Unsupported value type: {type(value)}")

    @classmethod
    def get_tags(
        cls,
        rules: list["Macsecurityrule"],
    ) -> list:
        """Return the unique set of tags across `rules`, sorted.

        Args:
            rules (list[Macsecurityrule]): Rules to scan.

        Returns:
            list[str]: All distinct tag values found across the input
                rules, in ascending order.
        """

        found_tags: list[str] = []

        for rule in rules:
            rule_tags = rule.get("tags")

            found_tags += rule_tags

        unique_tags = set(found_tags)

        return sorted(unique_tags)
