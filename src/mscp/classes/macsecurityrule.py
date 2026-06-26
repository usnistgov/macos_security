# macsecurityrule.py
"""macOS security rule model.

Defines `Macsecurityrule`, the top-level model for an mSCP rule, plus the
`Sectionmap` enum that maps rule directories to their canonical section
filenames.
"""

# Standard python modules
import base64
from collections import OrderedDict, defaultdict
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

# Additional python modules
from pydantic import Field, ValidationError, field_validator

# Local python modules
from ._base import BaseModelWithAccessors
from .enforcement_info import EnforcementInfo
from .mobileconfig import Mobileconfigpayload, format_payload
from .odv import OdvHint
from .references import References
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


def deep_merge(a, b):
    for key, value in b.items():
        if key in a and isinstance(a[key], dict) and isinstance(value, dict):
            deep_merge(a[key], value)
        else:
            a[key] = value
    return a


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


class Macsecurityrule(BaseModelWithAccessors):
    """A macOS security rule.

    The top-level domain object for mSCP. Combines rule metadata (title,
    discussion, references), enforcement information (`check`, `fix`,
    `mechanism`), and platform / version targeting. Instances are normally
    constructed via `load_rules` or `collect_platform_rules` rather than
    directly.

    Attributes:
        title: Human-readable title shown in generated guidance.
        rule_id: Unique identifier for the rule (matches the YAML file stem).
        discussion: Long-form discussion or rationale for the rule.
        references: NIST / DISA / CIS / BSI / custom reference identifiers
            grouped by namespace.
        odv: Organizational Defined Values keyed by benchmark name, plus
            optional ``hint`` / ``custom`` entries.
        tags: Tag list categorising the rule (e.g. ``"inherent"``,
            ``"permanent"``, ``"n_a"``, ``"supplemental"``).
        result_value: Expected result for compliance, when applicable.
        mobileconfig_info: Configuration profile payloads when the rule is
            enforced via a profile; ``None`` otherwise.
        ddm_info: Declarative Device Management payload, when applicable.
        customized: Field names that have been overridden by customization
            files.
        mechanism: Enforcement mechanism — one of ``"Manual"``,
            ``"Script"``, ``"Configuration Profile"``, ``"Inherent"``,
            ``"Permanent"``, ``"N/A"``.
        section: Section name the rule belongs to (e.g.
            ``"Operating System"``, ``"Inherent"``).
        uuid: Per-instance UUID4 string. Generated automatically.
        platforms: Platform-specific data from the YAML, keyed by OS family
            then version.
        os_name: OS marketing name resolved from version data
            (e.g. ``"Sequoia"``).
        os_type: OS family (e.g. ``"macOS"``).
        os_version: Target OS version as a float (e.g. ``15.0``). Defaults
            to ``0.0``.
        check: Shell command that evaluates rule state.
        fix: Shell command that brings the system into compliance, or
            instructional text for non-script mechanisms.
        severity: Severity for the matching benchmark, when specified.
        default_state: Shell command that restores the default
            configuration, when defined.
    """

    title: str
    rule_id: str
    discussion: str
    references: References
    odv: dict[str, Any] | None = None
    tags: list[str] = Field(default_factory=list)
    result_value: str | int | bool | None = None
    mobileconfig_info: list[Mobileconfigpayload] | None = None
    ddm_info: dict[str, Any] | None = None
    customized: list[str] = Field(default_factory=list)
    mechanism: str | None = None
    section: str | None
    uuid: str = Field(default_factory=lambda: str(uuid4()))
    platforms: dict[str, dict[str, Any]] = Field(default_factory=dict)
    os_name: str
    os_type: str
    os_version: float = Field(default_factory=float)
    check: str | None = None
    fix: str | None = None
    enforcement_info: EnforcementInfo | None = None
    severity: str | None = None
    default_state: str | None = None

    @field_validator("odv", mode="after")
    @classmethod
    def validate_odv_hint(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is None:
            return v
        hint = v.get("hint")
        if hint is not None and isinstance(hint, dict):
            OdvHint(**hint)
        return v

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
        applies any matching customizations (references / tags / platforms
        merge; other keys overwrite). Rules whose YAML lacks the requested
        ``os_type`` / ``os_version`` are skipped with a debug log.

        Args:
            rule_ids: Rule IDs to load.
            os_type: Operating system family (e.g. ``"macOS"``).
            os_version: Operating system version (e.g. ``15.0``).
            parent_values: Benchmark name used as the ODV lookup key in
                `_fill_in_odv`.
            section: Section label assigned to the loaded rules (used for
                logging and falls through into the rule when no
                special-section override applies).
            tailoring: If true, suppresses loading of customization
                overrides. Defaults to ``False``.
            language: Language code passed to `open_file` for localized
                text. Defaults to ``"en"``.

        Returns:
            Successfully loaded rules. Rules whose YAML file is missing or
            whose platform/version is not supported are skipped silently.
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
            Path(Path(config["custom"]["rules_dir"])),
        ]

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
                        platform_info = rule_yaml.get("platforms")
                        deep_merge(platform_info, custom_rule_value)
                        continue

                    rule_yaml[custom_rule_key] = custom_rule_value

            enforcement_info = rule_yaml["platforms"][os_type].get(
                "enforcement_info", {}
            )

            if enforcement_info:
                platform_enforcement_info = rule_yaml["platforms"][os_type][
                    os_version_str
                ].get("enforcement_info", {})
                deep_merge(enforcement_info, platform_enforcement_info)

            if enforcement_info and "n_a" not in tags:
                check_shell = enforcement_info.get("check", {}).get("shell")
                check_result = enforcement_info.get("check", {}).get("result")
                fix_shell = enforcement_info.get("fix", {}).get("shell")
                additional_info = enforcement_info.get("fix", {}).get("additional_info")
                default_state_shell = enforcement_info.get("default_state", {}).get(
                    "shell"
                )

                if check_result:
                    for k, v in enforcement_info["check"]["result"].items():
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

                mobileconfig_info = rule_yaml["platforms"][os_type][os_version_str].get(
                    "mobileconfig_info", rule_yaml["mobileconfig_info"]
                )
                for entry in mobileconfig_info:
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
                    if dst in ("nist_800_53r5", "nist_800_171r3"):
                        if value is not None and not isinstance(value, list):
                            value = [value] if isinstance(value, str) else None
                    nist[dst] = value

            if cis and "benchmark" in cis:
                if isinstance(cis["benchmark"], dict):
                    cis["benchmark"] = cis["benchmark"].get(os_typeversion)
                if cis["benchmark"] is not None and not isinstance(
                    cis["benchmark"], list
                ):
                    cis["benchmark"] = [cis["benchmark"]]

            if disa:
                if "disa_stig" in disa and isinstance(disa["disa_stig"], dict):
                    disa["disa_stig"] = disa["disa_stig"].get(os_typeversion)
                    if disa["disa_stig"] is not None and not isinstance(
                        disa["disa_stig"], list
                    ):
                        disa["disa_stig"] = [disa["disa_stig"]]

            if bsi:
                if "indigo" in bsi and isinstance(bsi["indigo"], dict):
                    bsi["indigo"] = bsi["indigo"].get(os_typeversion)
                    if bsi["indigo"] is not None and not isinstance(
                        bsi["indigo"], list
                    ):
                        bsi["indigo"] = [bsi["indigo"]]

            if custom_refs:
                rule_yaml["references"]["custom_refs"] = {}
                rule_yaml["references"]["custom_refs"]["references"] = [custom_refs]

            try:
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
                    enforcement_info=enforcement_info,
                    default_state=default_state_value,
                    severity=severity,
                )
            except ValidationError as e:
                issues = "; ".join(
                    "[{}] {}".format(
                        " -> ".join(str(p) for p in err["loc"]) or "root",
                        err["msg"],
                    )
                    for err in e.errors()
                )
                logger.error(
                    "Rule {} failed validation and will be skipped: {}", rule_id, issues
                )
                continue

            if rule.odv is not None and parent_values is not None:
                rule._fill_in_odv(parent_values)

            logger.success("Transformed rule: {}", rule_id)

            rules.append(rule)

        logger.debug("NUMBER OF {} LOADED RULES: {}", section.upper(), len(rules))
        logger.info("=== RULES {} LOADED ===", section.upper())

        return rules

    @classmethod
    def collect_platform_rules(
        cls,
        os_type: str,
        os_version: int,
        tailoring: bool = False,
        parent_values: str = "default",
    ) -> list["Macsecurityrule"]:
        """Load every rule under ``config["rules_dir"]`` for a specific OS type and version.

        Walks each subfolder of the rules directory (skipping
        ``sysprefs``), maps each folder name through `Sectionmap` to the
        matching section file, and delegates per-section loading to
        `load_rules`. Rules that do not declare support for the requested
        ``os_type`` / ``os_version`` are skipped.

        Args:
            os_type: Operating system family (e.g. ``"macos"``).
            os_version: Operating system version.
            tailoring: If true, skips customization overrides. Defaults to
                ``False``.
            parent_values: ODV lookup key forwarded to `load_rules`.
                Defaults to ``"default"``.

        Returns:
            All rules across all sections that match the given platform and version.
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
            Path(config["custom_dir"]) / "rules",
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
        """Generate a formatted XML string for the ``mobileconfig_info`` field.

        Handles special cases such as ``com.apple.ManagedClient.preferences``.
        Updates ``self.fix`` in place; does not return a value.
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
                                rulefix += format_payload(
                                    nested_payload_type, nested_payload_content
                                )
                        else:
                            logger.warning(
                                "Unexpected item type in payload_content list: {}",
                                type(item),
                            )

                if isinstance(payload.payload_content, dict):
                    for (
                        nested_payload_type,
                        nested_payload_content,
                    ) in payload.payload_content.items():
                        rulefix += format_payload(
                            nested_payload_type, nested_payload_content
                        )

            rulefix += format_payload(payload.payload_type, payload.payload_content)

        self._update_fix_for_configuration_profile()

    def _update_fix_for_configuration_profile(self) -> None:
        """Update ``self.fix`` or enforcement info for configuration profile rules."""
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
                        + format_payload(
                            self.mobileconfig_info[0].payload_type,
                            self.mobileconfig_info[0].payload_content,
                        )
                    )
            else:
                if self.mobileconfig_info and len(self.mobileconfig_info) > 0:
                    self.platforms[self.os_type]["enforcement_info"]["fix"] = (
                        format_payload(
                            self.mobileconfig_info[0].payload_type,
                            self.mobileconfig_info[0].payload_content,
                        )
                    )

    def _fill_in_odv(self, parent_values: str) -> None:
        """Replace ``$ODV`` placeholders in rule fields with the resolved value.

        Args:
            parent_values: Key to look up in ``self.odv``. Expected values
                include ``"custom"``, ``"recommended"``, or a specific
                benchmark name.
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

        fields_to_process: tuple[str, ...] = (
            "title",
            "discussion",
            "check",
            "fix",
            "result_value",
        )

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

        if self.mobileconfig_info is not None:
            for payload in self.mobileconfig_info:
                payload.payload_content = replace_odv_in_obj(payload.payload_content)

        if self.enforcement_info is not None:
            self.enforcement_info = replace_odv_in_obj(self.enforcement_info)

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
            odv: The custom ODV value to record. Stored verbatim under the
                ``"custom"`` key of ``self.odv``.
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
        containing only the ``discussion`` field. The caller is expected to
        have already prepended the exclusion notice to ``self.discussion``.
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
        prepended to their ``discussion``, are reassigned to the
        ``"Excluded"`` section, and are still returned in the result list
        so callers can render them as exclusions. Rules tagged ``inherent``
        are always included without prompting.

        This method writes to disk via `write_odv_custom_rule` and
        `write_excluded_custom_rule_discussion` as the user makes choices,
        and prints to stdout.

        Args:
            rules: Rules to walk.
            benchmark: Benchmark name being tailored. When equal to
                ``"recommended"`` the recommended ODV is used as the
                default; otherwise the benchmark-specific ODV is used and
                a warning is printed.

        Returns:
            Both included rules and excluded rules (with exclusion notices
            applied), ready to be written into a tailored baseline.
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
        """Serialize this rule to a YAML file in canonical key order.

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
        per-customization files). When no ``fields`` are given, empty
        sections are dropped except for the always-required keys
        ``id`` / ``title`` / ``discussion`` / ``references`` /
        ``platforms``.

        Args:
            output_path: Destination YAML file.
            *fields: Optional whitelist of top-level keys to write. When
                supplied, all other keys are stripped. The ``odv`` key is
                additionally restricted to ``hint`` / ``custom``.
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
        serialized_data: dict[str, Any] = self.model_dump(
            exclude_none=True, by_alias=True
        )
        ordered_data = OrderedDict()
        self._clean_references()

        # translate key "rule_id" to "id"
        serialized_data["id"] = serialized_data["rule_id"]

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

        Thin wrapper around ``model_dump`` for callers that want a
        non-Pydantic value (e.g. for JSON serialization).

        Returns:
            All declared fields, including their nested sub-models
            recursively dumped.
        """
        return self.model_dump()

    def _clean_references(self) -> None:
        """Remove reference entries whose value is ``None``, ``"NA"``, or ``"N/A"``."""

        def clean_dict(d: dict) -> dict:
            return {
                k: clean_dict(v) if isinstance(v, dict) else v
                for k, v in d.items()
                if v is not None and v not in ("NA", "N/A")
            }

        self.references = References(**clean_dict(self.references.model_dump()))

    @classmethod
    def get_tags(cls, rules: list["Macsecurityrule"]) -> list:
        """Return the unique set of tags across ``rules``, sorted.

        Args:
            rules: Rules to scan.

        Returns:
            All distinct tag values found across the input rules, in
            ascending order.
        """
        found_tags: list[str] = []

        for rule in rules:
            found_tags += rule.get("tags")

        return sorted(set(found_tags))
