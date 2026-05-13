---
title: mscp.generate.guidance_support.profiles
description: "Configuration profile (mobileconfig) generation for mSCP baselines."
---

> Source: [`src/mscp/generate/guidance_support/profiles.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/guidance_support/profiles.py)

Configuration profile (mobileconfig) generation for mSCP baselines.

Provides `generate_profiles`, which groups rule payload data by type and
writes unsigned (and optionally signed) ``.mobileconfig`` files and
preferences plists.  `get_payload_content_by_type` groups rule payloads;
`sign_config_profile` CMS-signs a profile using a certificate hash.


## Functions

### get_payload_content_by_type

```python
get_payload_content_by_type(rules: list[Macsecurityrule]) -> dict[str, list[dict[str, Any]]]
```

Group mobileconfig payload content by payload type across a list of rules.

**Args**

- **`rules`** *(list[Macsecurityrule])* — Rules to inspect for ``mobileconfig_info``.

**Returns**

- dict[str, list[dict[str, Any]]]: Mapping of ``payload_type`` → list of ``payload_content`` dicts (duplicates are warned and skipped).


### sign_config_profile

```python
sign_config_profile(in_file: Path, out_file: Path, cert_hash: str) -> None
```

CMS-sign a configuration profile using the certificate identified by *cert_hash*.

**Args**

- **`in_file`** *(Path)* — Unsigned ``.mobileconfig`` file to sign.
- **`out_file`** *(Path)* — Destination path for the signed profile.
- **`cert_hash`** *(str)* — Subject Key ID hash of the signing certificate.


### generate_profiles

```python
generate_profiles(build_path: Path, baseline_name: str, baseline: Baseline, signing: bool=False, hash_value: str='', consolidated: bool=False, granular: bool=False) -> None
```

*Decorators:* `@logger.catch`

Generate mobileconfig profiles from baseline rules and write them to *build_path*.

Groups rule payload content by type, writes per-type unsigned profiles,
optionally produces signed copies, a consolidated all-in-one profile, and
per-setting granular profiles.  Skips non-Apple platforms.

**Args**

- **`build_path`** *(Path)* — Root output directory for this baseline's artifacts.
- **`baseline_name`** *(str)* — Baseline name used in identifiers and filenames.
- **`baseline`** *(Baseline)* — Baseline containing profile rules with payload info.
- **`signing`** *(bool)* — Sign generated profiles with *hash_value*. Defaults to ``False``.
- **`hash_value`** *(str)* — Certificate hash for signing. Defaults to ``""``.
- **`consolidated`** *(bool)* — Write a single profile containing all settings. Defaults to ``False``.
- **`granular`** *(bool)* — Write individual profiles per setting. Defaults to ``False``.
