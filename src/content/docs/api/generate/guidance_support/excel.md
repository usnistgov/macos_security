---
title: mscp.generate.guidance_support.excel
description: "Excel workbook generation for mSCP baselines."
sidebar:
  order: 1
---

> Source: [`src/mscp/generate/guidance_support/excel.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/generate/guidance_support/excel.py)

Excel workbook generation for mSCP baselines.

Provides `generate_excel`, which converts a baseline to a formatted
``.xlsx`` workbook with auto-fitted columns, bold headers, wrapped text,
and an Excel table style.  Helper functions handle column expansion,
list formatting, and cell-width calculation.


## Functions

### auto_fit_columns

```python
auto_fit_columns(sheet, threshold_length: int=120, buffer: int=2, wrap_multiline: bool=True)
```

Auto-fit width of each column in `sheet` based on the longest line per cell.
- threshold_length: max width to set for any column (your cap).
- buffer: add a few extra characters of padding.
- wrap_multiline: optionally enable wrapText for cells that contain newlines.


### format_list_cell

```python
format_list_cell(x, unwrap_single=True, sep='\n')
```

Format a cell that may be a list:
- Empty list -> pd.NA
- Single-item list (unwrap_single=True) -> that item
- Multi-item list -> newline-separated string (items coerced to string)
- Non-list values returned unchanged


### expand_dict_column

```python
expand_dict_column(df, col, unwrap_single_lists=True, list_sep='\n', drop_original=True, flatten_sep='.')
```

Expand dictionaries found in df[col] into new columns named '{col}:{keypath}',
flattening nested keys with `flatten_sep`. Lists encountered inside dict values
are formatted per `format_list_cell`. Original column can be dropped.


### expand_dicts_and_format_lists

```python
expand_dicts_and_format_lists(df, unwrap_single_lists=True, list_sep='\n', drop_original_dict_cols=True, flatten_sep='.')
```

Process the entire DataFrame:
  1) For every column that contains dictionaries in any row:
     - Expand into '{col}:{keypath}' columns.
     - Drop the original dict column (configurable).
     - Format lists found inside those dict values.
  2) For every remaining column that contains lists in any row:
     - Unwrap single-item lists.
     - Join multi-item lists with `list_sep`.


### generate_excel

```python
generate_excel(file_out: Path, baseline: Baseline) -> None
```

Generate a formatted Excel workbook from *baseline* rule data.

Converts the baseline to a DataFrame, drops internal-only columns,
expands nested dict/list columns, reorders and uppercases headers,
and writes the result to *file_out* with bold headers, top-aligned
cells, auto-fitted column widths, and an Excel table style.

**Args**

- **`file_out`** *(Path)* — Destination ``.xlsx`` path.
- **`baseline`** *(Baseline)* — Baseline whose rules populate the workbook.
