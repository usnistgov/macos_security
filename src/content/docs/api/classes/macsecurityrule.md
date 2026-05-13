---
title: mscp.classes.macsecurityrule
description: "macOS security rule model and supporting reference types."
sidebar:
  order: 1
---

> Source: [`src/mscp/classes/macsecurityrule.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/classes/macsecurityrule.py)

macOS security rule model and supporting reference types.

Defines `Macsecurityrule`, the top-level model for an mSCP rule, plus the
nested `References` graph (`NistReferences`, `DisaReferences`,
`CisReferences`, `bsiReferences`, `customReferences`) and the
`Mobileconfigpayload` model used to represent configuration profile
payloads. Also exposes the `Sectionmap` enum that maps rule directories to
their canonical section filenames.


## Classes

### Sectionmap

```python
class Sectionmap(StrEnum)
```

Mapping from rule directory names to canonical section filenames.

Each member corresponds to one of the per-section YAML files under
``config["sections_dir"]``. The string value is the stem of that file
(e.g. ``"auditing"`` → ``auditing.yaml``). Members are looked up from
folder names like ``Sectionmap[folder.upper()]`` during rule collection.


### BaseModelWithAccessors

```python
class BaseModelWithAccessors(BaseModel)
```

Pydantic base class with dict-style accessors.

Adds `get` plus ``__getitem__`` / ``__setitem__`` so subclasses can be
treated either as Pydantic models or as plain dict-like objects. This
variant differs from the one in `mscp.classes.baseline` only in that
`__getitem__` / `__setitem__` use `getattr` / `setattr` directly, so any
attribute that exists on the instance (declared field or otherwise) is
accessible.


#### Methods

##### get

```python
get(self, attr: str, default: Any=None) -> Any
```

Return the value of `attr`, or `default` if it isn't set.

**Args**

- **`attr`** *(str)* — Attribute name to read.
- **`default`** *(Any)* — Value returned when ``attr`` is absent. Defaults to ``None``.

**Returns**

- **`Any`** — The attribute value, or ``default`` if no such attribute exists on the instance.


### NistReferences

```python
class NistReferences(BaseModelWithAccessors)
```

NIST reference identifiers for a rule.

Each list is sorted in ascending order on construction to keep the
serialised output stable.

**Attributes**

- **`cce`** *(list[str] | None)* — CCE (Common Configuration Enumeration) identifiers, e.g. ``["CCE-94195-5"]``.
- **`nist_800_53r5`** *(list[str] | None)* — NIST SP 800-53 Rev. 5 control identifiers. Stored under the Python-friendly attribute name; serialised to YAML as ``800-53r5``.
- **`nist_800_171r3`** *(list[str] | None)* — NIST SP 800-171 Rev. 3 control identifiers. Serialised to YAML as ``800-171r3``.


#### Constructor

##### __init__

```python
__init__(self, **data)
```

Construct from kwargs and sort all reference lists.


### DisaReferences

```python
class DisaReferences(BaseModelWithAccessors)
```

DISA reference identifiers for a rule.

Each list is sorted in ascending order on construction.

**Attributes**

- **`cci`** *(list[str] | None)* — CCI (Control Correlation Identifier) identifiers.
- **`srg`** *(list[str] | None)* — Security Requirements Guide identifiers.
- **`disa_stig`** *(list[str] | None)* — DISA STIG rule identifiers.
- **`cmmc`** *(list[str] | None)* — CMMC practice identifiers.
- **`sfr`** *(list[str] | None)* — Security Functional Requirement identifiers.


#### Constructor

##### __init__

```python
__init__(self, **data)
```

Construct from kwargs and sort all reference lists.


### CisReferences

```python
class CisReferences(BaseModelWithAccessors)
```

CIS reference identifiers for a rule.

Each list is sorted in ascending order on construction.

**Attributes**

- **`benchmark`** *(list[str] | None)* — CIS Benchmark recommendation identifiers (e.g. ``["1.2.3"]``).
- **`controls_v8`** *(list[float] | None)* — CIS Controls v8 mappings.


#### Constructor

##### __init__

```python
__init__(self, **data: Any) -> None
```

Construct from kwargs and sort all reference lists.


### bsiReferences

```python
class bsiReferences(BaseModelWithAccessors)
```

BSI (Bundesamt für Sicherheit in der Informationstechnik) references.

**Attributes**

- **`indigo`** *(list[str] | None)* — BSI Indigo profile identifiers, sorted in ascending order on construction.


#### Constructor

##### __init__

```python
__init__(self, **data: Any) -> None
```

Construct from kwargs and sort the reference list.


### bzkReferences

```python
class bzkReferences(BaseModelWithAccessors)
```

BZK (Ministerie van Binnenlandse Zaken en Koninkrijksrelaties (Netherlands
Ministry of the Interior and Kingdom Relations)) references.

**Attributes**

- **`bio`** *(list[str] | None)* — BIO identifiers, sorted in ascending order on construction.


#### Constructor

##### __init__

```python
__init__(self, **data: Any) -> None
```

Construct from kwargs, coerce items to str, and sort the reference list.

BIO identifiers such as ``8.27`` are parsed as floats by the YAML
loader; they are coerced to strings here before Pydantic validates.


### customReferences

```python
class customReferences(BaseModelWithAccessors)
```

Open-ended custom reference container.

Holds project- or deployment-specific reference identifiers that
don't fit the other reference namespaces. Permits arbitrary extra
fields (``extra="allow"``) so unknown reference types pass through
unchanged.

**Attributes**

- **`references`** *(list[Any] | None)* — Free-form reference entries, sorted in ascending order on construction.


#### Constructor

##### __init__

```python
__init__(self, **data: Any) -> None
```

Construct from kwargs and sort the reference list.


### Mobileconfigpayload

```python
class Mobileconfigpayload(BaseModelWithAccessors)
```

A single payload inside a configuration profile.

Configuration profiles ship one or more payloads (each identified by a
``PayloadType`` such as ``"com.apple.screensaver"``). This model holds
the payload type plus its content as a list of key-value dicts.

**Attributes**

- **`payload_type`** *(str)* — The ``PayloadType`` value (e.g. ``"com.apple.screensaver"``).
- **`payload_content`** *(list[dict[str, Any]])* — One or more dicts of preference settings to apply within the payload.


### References

```python
class References(BaseModelWithAccessors)
```

Container for all reference namespaces attached to a rule.

`nist` is required (every rule has at least a NIST mapping); the rest
are optional. Extra fields are allowed so additional reference
namespaces can be loaded without code changes.

**Attributes**

- **`nist`** *(NistReferences)* — NIST identifiers (CCE, 800-53r5, 800-171r3).
- **`disa`** *(DisaReferences | None)* — DISA identifiers, if applicable.
- **`cis`** *(CisReferences | None)* — CIS identifiers, if applicable.
- **`bsi`** *(bsiReferences | None)* — BSI identifiers, if applicable.
- **`bzk`** *(bzkReferences | None)* — BZK identifiers, if applicable.
- **`custom_refs`** *(customReferences | None)* — Project-specific custom references, if any.


#### Methods

##### get_ref

```python
get_ref(self, key: str, *, default: Any=_SENTINEL, case_insensitive: bool=True, search_order: Iterable[str]=('nist', 'disa', 'cis', 'bsi', 'bzk')) -> Any
```

Look up a reference value by namespace-qualified or bare key.

Two lookup styles are supported:

- **Namespaced**: ``"nist.cce"`` reads the named field from a
  specific submodel.
- **Unqualified**: ``"cce"`` scans submodels in `search_order` and
  returns the first match (values from the unqualified path are
  coerced to ``list[str]``).

For convenience, three legacy keys are translated automatically:
``"800-53r5"`` → ``"nist_800_53r5"``, ``"800-171r3"`` →
``"nist_800_171r3"``, and ``"cis"`` → ``"benchmark"``.

**Args**

- **`key`** *(str)* — Field name to look up, optionally namespace-prefixed with ``"."``.
- **`default`** *(Any)* — Sentinel-defaulted; if supplied, returned when the key is missing instead of raising. Pass any value (including ``None``) to opt in to defaulting.
- **`case_insensitive`** *(bool)* — If true (the default), field names are compared in lowercase.
- **`search_order`** *(Iterable[str])* — Submodel attribute names to scan in order for unqualified keys. Defaults to ``("nist", "disa", "cis", "bsi")``.

**Returns**

- **`Any`** — The matched reference value. For unqualified lookups the value is coerced to ``list[str]``.

**Raises**

- **`KeyError`** — If the key is not found and no `default` was given. The message indicates whether the namespace was missing or the field was missing within the namespace.


### Macsecurityrule

```python
class Macsecurityrule(BaseModelWithAccessors)
```

A macOS security rule.

The top-level domain object for mSCP. Combines rule metadata (title,
discussion, references), enforcement information (`check`, `fix`,
`mechanism`), and platform / version targeting. Instances are normally
constructed via `load_rules` or `collect_all_rules` rather than
directly.

**Attributes**

- **`title`** *(str)* — Human-readable title shown in generated guidance.
- **`rule_id`** *(str)* — Unique identifier for the rule (matches the YAML file stem).
- **`discussion`** *(str)* — Long-form discussion or rationale for the rule.
- **`references`** *(References)* — NIST / DISA / CIS / BSI / custom reference identifiers grouped by namespace.
- **`odv`** *(dict[str, Any] | None)* — Organizational Defined Values keyed by benchmark name, plus optional ``hint`` / ``custom`` entries.
- **`tags`** *(list[str])* — Tag list categorising the rule (e.g. ``"inherent"``, ``"permanent"``, ``"n_a"``, ``"supplemental"``).
- **`result_value`** *(str | int | bool | None)* — Expected result for compliance, when applicable.
- **`mobileconfig_info`** *(list[Mobileconfigpayload] | None)* — Configuration profile payloads when the rule is enforced via a profile; ``None`` otherwise.
- **`ddm_info`** *(dict[str, Any] | None)* — Declarative Device Management payload, when applicable.
- **`customized`** *(list[str])* — Field names that have been overridden by customisation files.
- **`mechanism`** *(str)* — Enforcement mechanism — one of ``"Manual"``, ``"Script"``, ``"Configuration Profile"``, ``"Inherent"``, ``"Permanent"``, ``"N/A"``.
- **`section`** *(str | None)* — Section name the rule belongs to (e.g. ``"Operating System"``, ``"Inherent"``).
- **`uuid`** *(str)* — Per-instance UUID4 string. Generated automatically.
- **`platforms`** *(dict[str, dict[str, Any]])* — Platform-specific data from the YAML, keyed by OS family then version.
- **`os_name`** *(str)* — OS marketing name resolved from version data (e.g. ``"Sequoia"``).
- **`os_type`** *(str)* — OS family (e.g. ``"macOS"``).
- **`os_version`** *(float)* — Target OS version as a float (e.g. ``15.0``). Defaults to ``0.0``.
- **`check`** *(str | None)* — Shell command that evaluates rule state.
- **`fix`** *(str | None)* — Shell command that brings the system into compliance, or instructional text for non-script mechanisms.
- **`severity`** *(str | None)* — Severity for the matching benchmark, when specified.
- **`default_state`** *(str | None)* — Shell command that restores the default configuration, when defined.


#### Class Methods

##### load_rules

```python
load_rules(cls, rule_ids: list[str], os_type: str, os_version: float, parent_values: str, section: str, tailoring: bool=False, language: str='en') -> list['Macsecurityrule']
```

Load `Macsecurityrule` objects for a list of rule IDs.

Resolves each rule ID against ``config["rules_dir"]`` (and the
custom rules directory when not tailoring), parses the YAML, and
applies any matching customisations (references / tags / platforms
merge; other keys overwrite). Rules whose YAML lacks the requested
``os_type`` / ``os_version`` are skipped with a debug log.

**Args**

- **`rule_ids`** *(list[str])* — Rule IDs to load.
- **`os_type`** *(str)* — Operating system family (e.g. ``"macOS"``).
- **`os_version`** *(float)* — Operating system version (e.g. ``15.0``).
- **`parent_values`** *(str)* — Benchmark name used as the ODV lookup key in `_fill_in_odv`.
- **`section`** *(str)* — Section label assigned to the loaded rules (used for logging and falls through into the rule when no special-section override applies).
- **`tailoring`** *(bool)* — If true, suppresses loading of customisation overrides (used when the caller is producing a tailored benchmark). Defaults to ``False``.
- **`language`** *(str)* — Language code passed to `open_file` for localised text. Defaults to ``"en"``.

**Returns**

- **`list[Macsecurityrule]`** — Successfully loaded rules. Rules whose YAML file is missing or whose platform/version is not supported are skipped silently.

##### collect_all_rules

```python
collect_all_rules(cls, os_type: str, os_version: int, tailoring: bool=False, parent_values: str='default') -> list['Macsecurityrule']
```

Load every rule under ``config["rules_dir"]`` for an OS/version.

Walks each subfolder of the rules directory (skipping
``sysprefs``), maps each folder name through `Sectionmap` to the
matching section file, and delegates per-section loading to
`load_rules`.

**Args**

- **`os_type`** *(str)* — Operating system family (e.g. ``"macOS"``).
- **`os_version`** *(int)* — Operating system version.
- **`tailoring`** *(bool)* — If true, skips customisation overrides. Defaults to ``False``.
- **`parent_values`** *(str)* — ODV lookup key forwarded to `load_rules`. Defaults to ``"default"``.

**Returns**

- **`list[Macsecurityrule]`** — All rules across all sections that match the given platform.

##### odv_query

```python
odv_query(cls, rules: list['Macsecurityrule'], benchmark: str) -> list['Macsecurityrule']
```

Walk a rule list interactively to include / exclude / set ODVs.

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

**Args**

- **`rules`** *(list[Macsecurityrule])* — Rules to walk.
- **`benchmark`** *(str)* — Benchmark name being tailored. When equal to ``"recommended"`` the recommended ODV is used as the default; otherwise the benchmark-specific ODV is used and a warning is printed.

**Returns**

- **`list[Macsecurityrule]`** — Both included rules and excluded rules (with exclusion notices applied), ready to be written into a tailored baseline.

##### get_tags

```python
get_tags(cls, rules: list['Macsecurityrule']) -> list
```

Return the unique set of tags across `rules`, sorted.

**Args**

- **`rules`** *(list[Macsecurityrule])* — Rules to scan.

**Returns**

- **`list[str]`** — All distinct tag values found across the input rules, in ascending order.


#### Static Methods

##### format_payload

```python
format_payload(payload_type: str, payload_content: list[dict] | dict, jinja_filter: bool=False) -> str
```

Render a single payload as XML wrapped for AsciiDoc output.

Builds a ``<Payload>`` XML tree from ``payload_content`` (each
dict becomes a sequence of ``<key>`` / value-element pairs) and
pretty-prints it. Unless ``jinja_filter`` is set, the output is
wrapped in an AsciiDoc ``[source,xml]`` block delimited by
``----``.

**Args**

- **`payload_type`** *(str)* — The ``PayloadType`` value (currently included only for symmetry with `Mobileconfigpayload` — the rendered XML uses a fixed ``<Payload>`` root).
- **`payload_content`** *(list[dict] | dict)* — The payload's content section. Lists of dicts are unpacked; bare dicts are ignored at the moment (use a single-element list).
- **`jinja_filter`** *(bool)* — If true, omit the AsciiDoc source-block wrappers and emit only the XML. Defaults to ``False``.

**Returns**

- **`str`** — The rendered payload, ready to splice into generated guidance.

##### mobileconfig_info_to_xml

```python
mobileconfig_info_to_xml(mobileconfig_info: list[dict[str, Any]]) -> str
```

Render a list of payloads as raw XML.

Convenience wrapper around `format_payload` with
``jinja_filter=True`` so callers (typically Jinja templates) get
XML without the AsciiDoc source-block delimiters.

**Args**

- **`mobileconfig_info`** *(list[dict[str, Any]])* — Payload dicts with at least ``payload_type`` and ``payload_content`` keys (matches `Mobileconfigpayload.model_dump()`).

**Returns**

- **`str`** — Concatenated XML for every payload, or the empty string if `mobileconfig_info` is empty.


#### Methods

##### write_odv_custom_rule

```python
write_odv_custom_rule(self, odv: Any) -> None
```

Persist a custom ODV value for this rule.

Updates ``self.odv["custom"]`` with ``odv``, clears the
``customized`` list, and writes a minimal YAML file containing
only the ``odv`` key into ``config["custom"]["rules_dir"]``.

**Args**

- **`odv`** *(Any)* — The custom ODV value to record. Stored verbatim under the ``"custom"`` key of `odv`.

##### remove_custom_rule

```python
remove_custom_rule(self) -> None
```

Delete the per-rule custom YAML, if it exists.

Removes ``<custom_rules_dir>/<rule_id>.yaml`` from disk. Missing
files are tolerated and produce only a warning log.

##### write_excluded_custom_rule_discussion

```python
write_excluded_custom_rule_discussion(self) -> None
```

Persist the modified discussion for an excluded rule.

Writes a minimal YAML file under ``config["custom"]["rules_dir"]``
containing only the ``discussion`` field. The caller is expected
to have already prepended the exclusion notice to
``self.discussion``.

##### to_yaml

```python
to_yaml(self, output_path: Path, *fields) -> None
```

Serialise this rule to a YAML file in canonical key order.

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

**Args**

- **`output_path`** *(Path)* — Destination YAML file.
- **`*fields`** *(str)* — Optional whitelist of top-level keys to write. When supplied, all other keys are stripped. The ``odv`` key is additionally restricted to ``hint`` / ``custom``.

##### to_dict

```python
to_dict(self) -> dict[str, Any]
```

Return a plain-dict representation of this rule.

Thin wrapper around `model_dump` for callers that want a
non-Pydantic value (e.g. for JSON serialisation).

**Returns**

- dict[str, Any]: All declared fields, including their nested sub-models recursively dumped.
