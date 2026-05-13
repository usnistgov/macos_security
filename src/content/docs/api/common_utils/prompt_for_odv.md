---
title: mscp.common_utils.prompt_for_odv
description: "Interactive prompt for Organization-Defined Values (ODVs)."
---

> Source: [`src/mscp/common_utils/prompt_for_odv.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/common_utils/prompt_for_odv.py)

Interactive prompt for Organization-Defined Values (ODVs).

Used by `Macsecurityrule.odv_query` when tailoring a baseline. Reads an
``odv_hint`` dict (datatype, description, validation rules), prompts
the user, validates the response against the rules, and re-prompts on
failure.


## Functions

### prompt_for_odv

```python
prompt_for_odv(prompt: str, odv_hint: Dict[str, Any], default: Optional[Any]=None) -> Any
```

Prompt the user for an 'organization defined value' (ODV) using a single hint dict
that defines datatype, description, and validation rules. Reprompts until valid.

**Args**

- **`prompt`** *(str)* — The prompt shown to the user.
- **`odv_hint`** *(dict)* — Hint metadata containing: - 'datatype' (str): one of 'number', 'string', 'enum', 'regex' - 'description' (str): guidance shown next to the prompt - 'validation' (dict): rule set keyed by datatype: * number: {'min': <int>, 'max': <int>} (both optional) * regex:  {'regex': <str>} (required for datatype='regex') * enum:   {'enumValues': [<str>, ...]} (required for datatype='enum') * string: {'regex': <str>} (optional; applied to raw input)
- **`default`** *(Any, optional)* — Value used when user hits Enter; will be validated.

**Returns**

- **`Any`** — The validated value (coerced according to the datatype).

Behavior:
    - Regex rules apply to the raw text first (if present).
    - Values are then coerced according to 'datatype'.
    - Range/membership rules apply after coercion.
    - If default is provided, it is validated before being returned.
