---
title: mscp.classes.loguruformatter
description: "Custom log formatting for `loguru`."
sidebar:
  order: 1
---

> Source: [`src/mscp/classes/loguruformatter.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/classes/loguruformatter.py)

Custom log formatting for `loguru`.

Provides `LoguruFormatter`, which produces a fixed-width log line by padding
the ``name:function:line`` block to the longest value seen so far.


## Classes

### LoguruFormatter

```python
class LoguruFormatter(BaseModel)
```

Format `loguru` records with a self-widening location column.

Each call to `format_log` measures the length of
``"{name}:{function}:{line}"`` for the current record and grows `padding`
to the widest value seen so far, so columns line up across log lines
without truncating any of them.

**Attributes**

- **`padding`** *(int)* — Largest ``name:function:line`` width observed, used to right-pad shorter values. Starts at 0 and grows monotonically.
- **`log_format`** *(str)* — The `loguru` format string applied to each record. Includes ``{extra[padding]}`` so the padding spaces populated by `format_log` are inserted at format time.


#### Methods

##### format_log

```python
format_log(self, record) -> str
```

Compute the padding for ``record`` and return the format string.

Updates `self.padding` to the maximum of its current value and the
width of the record's ``name:function:line``, then writes the
difference into ``record["extra"]["padding"]`` so it can be
interpolated into `log_format`.

**Args**

- **`record`** *(dict)* — The `loguru` record being formatted. Must contain ``name``, ``function``, ``line``, and an ``extra`` dict; ``extra["padding"]`` is set as a side effect.

**Returns**

- **`str`** — The format string in `log_format`, ready for `loguru` to render with the now-populated record.
