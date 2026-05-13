---
title: mscp.classes.rule_library
description: "Collection class for Macsecurityrule objects."
---

> Source: [`src/mscp/classes/rule_library.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/classes/rule_library.py)

Collection class for Macsecurityrule objects.

Provides `RuleLibrary`, an ordered, indexed container that supports
lookup by rule ID, positional access, and filtering by tag, mechanism,
and OS with method chaining.


## Classes

### RuleLibrary

```python
class RuleLibrary
```

An ordered, indexed collection of `Macsecurityrule` objects.

Maintains both a list (for ordered iteration and positional access)
and a dict keyed by ``rule_id`` mapping to a list of rules. When the
library spans multiple platforms the same ``rule_id`` may appear once
per platform. String-key access via ``__getitem__`` and ``get`` raises
``KeyError`` in that case — call ``by_platform`` or ``by_os`` first to
narrow to a single platform.

Construct directly from a list of rules, or use ``from_rules_dir``
to load every supported platform at once.

**Args**

- **`rules`** *(list[Macsecurityrule])* — Initial rules to populate the library with.


#### Methods

##### __init__

```python
__init__(self, rules: list[Macsecurityrule]) -> None
```

##### from_rules_dir

```python
from_rules_dir(cls) -> RuleLibrary
```

*Decorators:* `@classmethod`

Load all rules for every supported platform and OS version.

Reads the platform/version matrix from the bundled
``mscp-data.yaml`` (via ``mscp_data``) and calls
``Macsecurityrule.collect_all_rules`` once per combination. Use
``by_platform`` or ``by_os`` to narrow the result to a specific
platform.

**Returns**

- **`RuleLibrary`** — A new library containing rules for all supported platforms and versions.

##### rules

```python
rules(self) -> list[str]
```

*Decorators:* `@property`

list[str]: The rule IDs of every rule in the library, in order.

##### get

```python
get(self, rule_id: str, default: Macsecurityrule | None=None) -> Macsecurityrule | None
```

Return the rule with the given ``rule_id``, or ``default`` if absent.

Raises ``KeyError`` if the ID matches rules from multiple platforms;
call ``by_platform`` or ``by_os`` first in that case.

**Args**

- **`rule_id`** *(str)* — The unique rule identifier to look up.
- **`default`** *(Macsecurityrule | None)* — Value returned when the rule is not found. Defaults to ``None``.

**Returns**

- Macsecurityrule | None: The matching rule, or ``default``.

**Raises**

- **`KeyError`** — If ``rule_id`` matches rules from multiple platforms.

##### has_odv

```python
has_odv(self) -> RuleLibrary
```

Return a new library containing only rules that have an ODV.

ODV (Organization Defined Value) rules require a value to be set
by the deploying organization before enforcement.

**Returns**

- **`RuleLibrary`** — Matching rules in their original order.

##### has_mobileconfig

```python
has_mobileconfig(self) -> RuleLibrary
```

Return a new library containing only rules that have a mobileconfig payload.

Rules with a mobileconfig payload are enforced via a configuration
profile rather than a shell script or manual action.

**Returns**

- **`RuleLibrary`** — Matching rules in their original order.

##### has_ddm

```python
has_ddm(self) -> RuleLibrary
```

Return a new library containing only rules that have a DDM payload.

DDM (Declarative Device Management) rules include a declaration
payload for delivery via declarative management solutions.

**Returns**

- **`RuleLibrary`** — Matching rules in their original order.

##### by_nist_control

```python
by_nist_control(self, control: str) -> RuleLibrary
```

Return a new library containing only rules mapped to the given NIST SP 800-53r5 control.

**Args**

- **`control`** *(str)* — NIST SP 800-53r5 control identifier to match (e.g. ``"AU-9"``). Comparison is case-insensitive.

**Returns**

- **`RuleLibrary`** — Matching rules in their original order.

##### by_tag

```python
by_tag(self, tag: str) -> RuleLibrary
```

Return a new library containing only rules tagged with ``tag``.

**Args**

- **`tag`** *(str)* — Tag string to match against each rule's ``tags`` list.

**Returns**

- **`RuleLibrary`** — Matching rules in their original order.

##### by_mechanism

```python
by_mechanism(self, mechanism: str) -> RuleLibrary
```

Return a new library containing only rules with the given enforcement mechanism.

Valid values are ``"Manual"``, ``"Script"``, ``"Configuration
Profile"``, ``"Inherent"``, ``"Permanent"``, and ``"N/A"``.

**Args**

- **`mechanism`** *(str)* — Enforcement mechanism to filter on. Comparison is case-insensitive.

**Returns**

- **`RuleLibrary`** — Matching rules in their original order.

##### by_benchmark

```python
by_benchmark(self, benchmark: str) -> RuleLibrary
```

Return a new library containing only rules that belong to the given benchmark.

Benchmark membership is determined by the ``benchmarks`` list in
the rule's platform/version entry (e.g. ``"cis_lvl1"``,
``"disa_stig"``). Comparison is case-insensitive.

**Args**

- **`benchmark`** *(str)* — Benchmark keyword to match (e.g. ``"disa_stig"``, ``"cis_lvl1"``).

**Returns**

- **`RuleLibrary`** — Matching rules in their original order.

**Raises**

- **`ValueError`** — If no rules match, listing the available benchmark keywords for this library.

##### by_platform

```python
by_platform(self, platform: str) -> RuleLibrary
```

Return a new library containing only rules for the given OS family.

**Args**

- **`platform`** *(str)* — OS family to match — ``"macos"``, ``"ios"``, or ``"visionos"``. Comparison is case-insensitive.

**Returns**

- **`RuleLibrary`** — Matching rules in their original order.

##### by_os

```python
by_os(self, os_name: str | None=None, os_version: float | None=None) -> RuleLibrary
```

Return a new library filtered by OS name, version, or both.

To filter by OS family (macOS vs iOS vs visionOS) use
``by_platform`` instead.

**Args**

- **`os_name`** *(str | None)* — OS marketing name to match (e.g. ``"sequoia"``). Comparison is case-insensitive. Omit to skip this filter.
- **`os_version`** *(float | None)* — OS version to match (e.g. ``15.0``). Omit to skip this filter.

**Returns**

- **`RuleLibrary`** — Matching rules in their original order.

**Raises**

- **`ValueError`** — If neither argument is provided.
