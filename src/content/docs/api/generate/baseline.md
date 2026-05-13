---
title: mscp.generate.baseline
description: "Baseline YAML generation for the macOS Security Compliance Project."
---

> Source: [`src/mscp/generate/baseline.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/baseline.py)

Baseline YAML generation for the macOS Security Compliance Project.

Provides `generate_baseline`, which queries the rule library for a
given OS / keyword combination and writes a YAML baseline file.
Helper functions collect available tags and benchmarks, filter rules,
and handle the interactive tailoring workflow.


## Functions

### collect_tags_and_benchmarks

```python
collect_tags_and_benchmarks(rules: list[Macsecurityrule]) -> tuple[list[str], dict[str, set[str]]]
```

Collect all tags and benchmark-to-platform mappings from a rule list.

Iterates every rule's ``tags`` and ``platforms`` data to build a sorted
list of unique tags (with ``"all_rules"`` always appended) and a dict
mapping each benchmark name to the set of OS types that declare it.

**Args**

- **`rules`** *(list[Macsecurityrule])* — Rules to inspect.

**Returns**

- tuple[list[str], dict[str, set[str]]]: ``(sorted_tags, benchmark_platforms)`` where *benchmark_platforms* maps benchmark name → set of OS-type strings.


### collect_established_benchmarks

```python
collect_established_benchmarks(rules: list[Macsecurityrule]) -> list[str]
```

Attempts to collect all established benchmarks in the MSCP library. An established
benchmark is one where an ODV has been defined for a given benchmark.

**Args**

- **`rules`** *(list[Macsecurityrule])* — A list of collected rules from the library.

**Returns**

- **`list`** — A sorted set of discovered benchmarks


### print_keyword_summary

```python
print_keyword_summary(tags: list[str], benchmark_platforms: dict[str, set[str]]) -> None
```

Print available tags and benchmarks to stdout, then exit.

**Args**

- **`tags`** *(list[str])* — Sorted list of all available tag strings.
- **`benchmark_platforms`** *(dict[str, set[str]])* — Mapping of benchmark name to the set of OS-type strings on which it is defined.


### rule_has_benchmark_for_version

```python
rule_has_benchmark_for_version(rule: Macsecurityrule, keyword: str, os_type: str, os_version: str) -> bool
```

Return True if *rule* declares *keyword* as a benchmark for the given OS version.

**Args**

- **`rule`** *(Macsecurityrule)* — Rule to inspect.
- **`keyword`** *(str)* — Benchmark name to look for.
- **`os_type`** *(str)* — OS type string (e.g. ``"macos"``); ``"os"`` is normalised to ``"OS"`` before the lookup.
- **`os_version`** *(str)* — OS version string (e.g. ``"15"``).

**Returns**

- **`bool`** — ``True`` if the benchmark is listed under the rule's platforms entry for that OS type and version, ``False`` otherwise.


### generate_baseline

```python
generate_baseline(args: argparse.Namespace, admin=False) -> None
```

*Decorators:* `@logger.catch`

Generate a YAML baseline file for the specified OS and keyword.

Collects all rules matching ``args.keyword`` (tag or benchmark name),
optionally runs the interactive tailoring workflow, and writes the
resulting baseline YAML to disk.

**Args**

- **`args`** *(argparse.Namespace)* — Parsed CLI arguments.  Expected attributes: ``os_name``, ``os_version``, ``keyword``, ``tailor``, ``list_tags``, ``controls``.
- **`admin`** *(bool)* — When ``True`` the output is written to the library's default baseline directory instead of the custom directory. Defaults to ``False``.
