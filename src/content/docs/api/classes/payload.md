---
title: mscp.classes.payload
description: "Configuration profile payload model."
---

> Source: [`src/mscp/classes/payload.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/classes/payload.py)

Configuration profile payload model.

Provides `Payload`, the in-memory representation of a macOS configuration
profile (or a per-domain preference plist). Payloads accumulate sub-payload
dictionaries and can be serialized to ``.mobileconfig`` or ``.plist`` files.


## Classes

### Payload

```python
class Payload(BaseModel)
```

A macOS configuration profile payload.

Holds the top-level metadata of a profile (identifier, organization,
scope, etc.) along with a list of sub-payloads accumulated via
`add_payload` / `add_mcx_payload`. The whole payload is serialized to
disk via `save_to_plist` (raw write) or `finalize_and_save_plist`
(which additionally splits Managed Client preference payloads into
per-domain plists).

**Attributes**

- **`identifier`** *(str)* — The ``PayloadIdentifier`` written to the profile.
- **`organization`** *(str)* — Owning organization written as ``PayloadOrganization``.
- **`description`** *(str)* — Human-readable description written as ``PayloadDescription``.
- **`displayname`** *(str)* — Display name written as ``PayloadDisplayName``.
- **`uuid`** *(str | None)* — The profile UUID. Defaults to a freshly generated UUID4 string.
- **`payload_version`** *(int)* — Profile schema version. Defaults to ``1``.
- **`payload_scope`** *(str)* — Profile scope (``"System"`` or ``"User"``). Defaults to ``"System"``.
- **`payload_type`** *(str)* — Top-level ``PayloadType``. Defaults to ``"Configuration"``.
- **`consent_text`** *(dict[str, str])* — Localised consent strings keyed by language code (e.g. ``"default"``, ``"en"``). Defaults to a built-in NIST disclaimer under ``"default"``.
- **`payload_content`** *(list[dict[str, Any]])* — Sub-payload dictionaries appended by `add_payload` / `add_mcx_payload`.


#### Methods

##### add_payload

```python
add_payload(self, payload_type: str, settings: dict[str, Any]) -> None
```

Append a generic sub-payload to `payload_content`.

Builds a payload dict with a fresh UUID and the standard
``PayloadVersion`` / ``PayloadType`` / ``PayloadIdentifier`` keys,
merges ``settings`` into it, and appends it to `payload_content`.

**Args**

- **`payload_type`** *(str)* — The ``PayloadType`` value (e.g. ``"com.apple.screensaver"``).
- **`settings`** *(dict[str, Any])* — Profile settings merged verbatim into the payload dict.

##### add_mcx_payload

```python
add_mcx_payload(self, domain: str, settings: dict[str, Any]) -> None
```

Append a Managed Client (MCX) preferences sub-payload.

Wraps ``settings`` in the MCX
``PayloadContent[domain]["Forced"][0]["mcx_preference_settings"]``
nesting expected by ``com.apple.ManagedClient.preferences`` and
appends the result to `payload_content`.

**Args**

- **`domain`** *(str)* — The preference domain to manage (e.g. ``"com.apple.screensaver"``).
- **`settings`** *(dict[str, Any])* — MCX preference settings to enforce for ``domain``.

##### save_to_plist

```python
save_to_plist(self, output_path: Path) -> None
```

Write the assembled payload to disk.

Behaviour depends on the file extension of ``output_path``:

- ``.mobileconfig``: writes the full top-level profile dictionary
  (identifier, scope, organisation, payload content, etc.).
- ``.plist``: writes only the merged inner settings, with the
  MDM-only keys (``PayloadVersion``, ``PayloadUUID``,
  ``PayloadType``, ``PayloadIdentifier``) stripped, in *append*
  mode.

**Args**

- **`output_path`** *(Path)* — Destination file. The extension determines which format is written; other extensions are silently skipped.

##### finalize_and_save_plist

```python
finalize_and_save_plist(self, output_path: Path) -> None
```

Write per-domain MCX plists, then save the main payload.

For each MCX sub-payload in `payload_content`, splits the forced
preference settings out into a sibling ``<domain>.plist`` next to
``output_path`` (creating the file if needed). After all MCX
payloads have been processed, calls `save_to_plist` to write
``output_path`` itself.

**Args**

- **`output_path`** *(Path)* — Destination of the main payload. Per-domain plists are written alongside it in the same directory.
