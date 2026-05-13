---
title: mscp.common_utils.sanitize_input
description: "Validated `input()` wrapper used for interactive CLI prompts."
---

> Source: [`src/mscp/common_utils/sanitize_input.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/common_utils/sanitize_input.py)

Validated `input()` wrapper used for interactive CLI prompts.

`sanitize_input` reads a line from stdin, casts it to a caller-specified
type, optionally checks it against a list / range of acceptable values,
and falls back to a default when the user just presses Enter.


## Functions

### sanitize_input

```python
sanitize_input(prompt: str, type_: Type[Any] | None=None, range_: Sequence[Any] | None=None, default_: Any | None=None) -> Any
```

Prompts the user for input, casts it to the specified type, validates it, and returns the validated input.

**Args**

- **`prompt`** *(str)* — The input prompt to display to the user.
- **`type_`** *(Type[Any], optional)* — The type to cast the input to (e.g., int, float, str). Defaults to None.
- **`range_`** *(Iterable[Any], optional)* — A range or list of acceptable values. Defaults to None.
- **`default_`** *(Any, optional)* — A default value to use if the user provides no input. Defaults to None.

**Returns**

- **`Any`** — The validated and type-cast input.

**Raises**

- **`ValueError`** — If the user input cannot be cast to the specified type or is out of range.
