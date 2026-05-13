---
title: mscp.common_utils.localization
description: "Localisation glue for `gettext` and YAML."
---

> Source: [`src/mscp/common_utils/localization.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/common_utils/localization.py)

Localisation glue for `gettext` and YAML.

Wraps `gettext.translation` so the active language can be switched at
runtime, exposes a `localize_string` shortcut, registers a custom
``!localize`` YAML tag that translates scalars at load time, and
provides a `get_supported_languages` helper that enumerates the
language subdirectories under ``config["locales_dir"]``.


## Functions

### setup_gettext_localization

```python
setup_gettext_localization(language: str='en') -> None
```

Configure gettext for localizations.

**Args**

- **`domain`** *(str)* — The localization domain (usually "messages")
- **`localedir`** *(str)* — Path to the locales directory
- **`language`** *(str)* — Language code (e.g., "de", "fr", "es")


### get_localization_function

```python
get_localization_function()
```

Get the current localization function.

**Returns**

- **`callable`** — The current gettext localization function


### localize_string

```python
localize_string(text: str) -> str
```

localize a string using the configured localization function.

**Args**

- **`text`** *(str)* — The string to localize

**Returns**

- **`str`** — The localized string


### localize_constructor

```python
localize_constructor(loader, node)
```

Custom YAML constructor for !localize tag that uses gettext for localization.

**Args**

- **`loader`** — The YAML loader instance
- **`node`** — The YAML node containing the localize string

**Returns**

- **`str`** — The localized string using the configured gettext function


### register_yaml_constructors

```python
register_yaml_constructors() -> None
```

Register the !localize YAML constructor with YAML loaders.

This function should be called once to enable !localize tag support
in YAML files.


### configure_localization_for_yaml

```python
configure_localization_for_yaml(language: str | None=None) -> None
```

Configure localization and register YAML constructors in one call.

**Args**

- **`language`** *(str, optional)* — Language code for localization (e.g., "de", "fr"). If None, uses current gettext config.
- **`domain`** *(str)* — localization domain name. Defaults to "messages".
- **`localedir`** *(str)* — Path to the locales directory. Defaults to the bundled data/locales.


### get_supported_languages

```python
get_supported_languages() -> list[str]
```

Retrieve supported languages.

**Args**

- none

**Returns**

- **`list[str]`** — A list containing the available supported languages for localization.


### get_language_data

```python
get_language_data(language: str, category: str) -> dict[str, Any]
```

Load a language YAML file under ``locales_dir/<language>/<category>``.

Failures (missing file, parse error) are logged and yield an empty
dict so callers can fall back to defaults rather than crash.

**Args**

- **`language`** *(str)* — Language subdirectory (e.g. ``"en"``, ``"de"``).
- **`category`** *(str)* — YAML file stem within that directory; the ``.yaml`` suffix is appended automatically.

**Returns**

- dict[str, Any]: Parsed YAML contents, or ``{}`` on error.
