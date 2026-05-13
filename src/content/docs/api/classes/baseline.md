---
title: mscp.classes.baseline
description: "Baseline document model."
---

> Source: [`src/mscp/classes/baseline.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/classes/baseline.py)

Baseline document model.

A *baseline* is a top-level mSCP document that pairs metadata (authors,
title, description, target platform) with a set of `Profile` sections, each
of which groups one or more `Macsecurityrule` objects. This module defines
the `Baseline`, `Profile`, and `Author` Pydantic models, along with class
methods to load baselines from YAML and write them back out.


## Classes

### BaseModelWithAccessors

```python
class BaseModelWithAccessors(BaseModel)
```

Pydantic base class with dict-style accessors.

Adds `get` plus ``__getitem__`` / ``__setitem__`` so subclasses can be
treated either as Pydantic models or as plain dict-like objects. Item
access is restricted to declared model fields to keep typos from
silently creating new attributes.


#### Methods

##### get

```python
get(self, attr: str, default: Any=None) -> Any
```

Return the value of `attr`, or `default` if it isn't set.

Unlike ``__getitem__``, this never raises and is not restricted to
declared model fields — it just delegates to `getattr`.

**Args**

- **`attr`** *(str)* — Attribute name to read.
- **`default`** *(Any)* — Value returned when ``attr`` is absent. Defaults to ``None``.

**Returns**

- **`Any`** — The attribute value, or ``default`` if no such attribute exists on the instance.


### Author

```python
class Author(BaseModelWithAccessors)
```

One author or owning organisation of a baseline.

**Attributes**

- **`name`** *(str | None)* — Personal name of the author, if available.
- **`organization`** *(str | None)* — Organisation the author represents, if applicable.


### Profile

```python
class Profile(BaseModelWithAccessors)
```

A named section of a baseline grouping related rules.

Profiles correspond to the top-level groupings rendered in generated
guidance (``Auditing``, ``Authentication``, ``Operating System``,
etc.), plus the synthetic special sections (``Inherent``, ``Permanent``,
``Not Applicable``, ``Supplemental``).

**Attributes**

- **`section`** *(str)* — Display name of the section (e.g. ``"Operating System"``).
- **`description`** *(str)* — Section description copied from the matching section YAML file.
- **`rules`** *(list[Macsecurityrule])* — Rules included in this profile, generally sorted by `rule_id`.


### Baseline

```python
class Baseline(BaseModelWithAccessors)
```

An mSCP baseline document.

A baseline pairs metadata about a security guide (title, description,
authors, target platform) with the `Profile` sections that hold its
rules. Instances are normally constructed via `from_yaml` (loading an
existing baseline file) or `create_new` (assembling one from a rule
set).

**Attributes**

- **`authors`** *(list[Author])* — Authors and/or owning organisations.
- **`profile`** *(list[Profile])* — Section profiles holding the baseline's rules.
- **`name`** *(str)* — Short identifier, typically derived from the baseline filename stem.
- **`title`** *(str)* — Human-readable full title of the baseline.
- **`description`** *(str)* — Description rendered in generated guidance.
- **`platform`** *(dict[str, Any])* — Target platform metadata, e.g. ``{"os": "macOS", "version": 15.0}``.
- **`parent_values`** *(str)* — Name of the parent benchmark this baseline inherits from (e.g. ``"recommended"``), or empty.


#### Methods

##### from_yaml

```python
from_yaml(cls, file_path: Path, language: str='en', custom: bool=False) -> 'Baseline'
```

*Decorators:* `@classmethod`

Load a `Baseline` from a YAML file with rules resolved.

Reads the baseline document, then for each profile entry resolves
the matching section file (under ``config["sections_dir"]``, plus
``config["custom"]["sections_dir"]`` if `custom` is set) and
loads its rules via `Macsecurityrule.load_rules`.

**Args**

- **`file_path`** *(Path)* — Path to the baseline YAML file.
- **`language`** *(str)* — Language code passed through to the file loader for localised strings. Defaults to ``"en"``.
- **`custom`** *(bool)* — If true, also search the configured custom sections directory when resolving section files. Defaults to ``False``.

**Returns**

- **`Baseline`** — A fully populated baseline with all profiles and rules resolved. Profiles whose section file cannot be found are skipped with a warning.

##### create_new

```python
create_new(cls, output_file: Path, rules: list[Macsecurityrule], baseline_name: str | None, authors: list[Author], full_title: str, benchmark: str, os_type: str, os_version: float, baseline_dict: dict[str, Any], language: str='en') -> None
```

*Decorators:* `@classmethod`

Build a new baseline from a rule set and write it to YAML.

Groups ``rules`` into profiles by their `section` (or by special
section tags ``inherent``, ``permanent``, ``n_a``, ``supplemental``
when present), loads section descriptions from
``config["sections_dir"]``, and serialises the result via
`to_yaml`. If ``baseline_dict`` lacks a ``title`` or
``description`` they're synthesised from the other arguments.

**Args**

- **`output_file`** *(Path)* — Destination YAML file for the new baseline.
- **`rules`** *(list[Macsecurityrule])* — Rules to include.
- **`baseline_name`** *(str | None)* — Short identifier folded into the synthesised title/description if those aren't supplied.
- **`authors`** *(list[Author])* — Authors attributed to the baseline.
- **`full_title`** *(str)* — Long-form title prepended to the synthesised ``title`` and ``description`` when set.
- **`benchmark`** *(str)* — Benchmark identifier (e.g. ``"recommended"``); stored as ``parent_values`` and used to extend the synthesised description when equal to ``"recommended"``.
- **`os_type`** *(str)* — Operating-system family (e.g. ``"macOS"``).
- **`os_version`** *(float)* — Operating-system version (e.g. ``15.0``).
- **`baseline_dict`** *(dict[str, Any])* — Additional baseline metadata merged into the constructor; ``title`` and ``description`` are filled in if absent.
- **`language`** *(str)* — Language code for loaded section descriptions. Defaults to ``"en"``.

**Side Effects**

- Writes the generated baseline to ``output_file``. Reads every
- ``*.y*ml`` file in ``config["sections_dir"]`` to resolve
- section descriptions.

##### to_dataframe

```python
to_dataframe(self) -> pd.DataFrame
```

Flatten the baseline's rules into a `pandas.DataFrame`.

Each rule contributes one row. The nested ``references`` mapping
is unpacked so each reference namespace (``nist``, ``disa``, etc.)
becomes its own column.

**Returns**

- **`pd.DataFrame`** — One row per rule across all profiles, with rule fields and unpacked references as columns.

##### to_yaml

```python
to_yaml(self, output_path: Path) -> None
```

Serialise this baseline to YAML in canonical key order.

The serialised document orders top-level keys as ``title``,
``description``, ``authors``, ``parent_values``, ``platform``,
``profile`` (any other keys are dropped), and orders profiles by
a fixed sequence (``Auditing``, ``Authentication``, ``iCloud``,
``Operating System``, ``Password Policy``, ``System Settings``,
followed by the special sections). Within each profile, ``rules``
is reduced to a sorted list of rule IDs.

**Args**

- **`output_path`** *(Path)* — Destination YAML file.
