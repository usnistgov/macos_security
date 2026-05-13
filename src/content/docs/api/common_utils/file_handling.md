---
title: mscp.common_utils.file_handling
description: "API reference for `mscp.common_utils.file_handling`."
sidebar:
  order: 1
---

> Source: [`src/mscp/common_utils/file_handling.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/common_utils/file_handling.py)

## Functions

### open_file

```python
open_file(file_path: Path, language: str='en') -> Any
```

Attempts to open a file and read its contents with error checking and logging.

**Args**

- **`file_path`** *(Path)* — The path to the file to be opened.

**Returns**

- **`str`** — The content of the file if successful.

**Raises**

- **`FileNotFoundError`** — If the file does not exist.
- **`PermissionError`** — If there are insufficient permissions to access the file.
- **`IOError`** — If an I/O error occurs during file operations.
- **`Exception`** — For any other unexpected errors.


### open_text

```python
open_text(file_path: Path) -> str
```

Attempts to open a text file and read it's contents with error checking and logging

**Args**

- **`file_path`** *(Path)* — The path to the file to be opened.

**Returns**

- **`str`** — The content of the file if successful, None if otherwise.


### open_yaml

```python
open_yaml(file_path: Path, language: str=None) -> dict[str, Any]
```

Attempts to open a yaml file and read its contents with error checking and logging.
Supports automatic gettext localization for specified yaml fields defined in
the "fields_to_translate" list.

**Args**

- **`file_path`** *(Path)* — The path to the file to be opened.
- **`language`** *(str, optional)* — Language code for localization (e.g., "de", "fr"). If None, uses current gettext config.

**Returns**

- dict[str, Any]: The content of the file if successful, empty dict otherwise.


### open_csv

```python
open_csv(file_path: Path, *, dedupe=True) -> dict[str, list[str]]
```

Return a dict mapping column header -> list of column values for any number of columns.
- Empty/missing cells become "".
- Whitespace around values is stripped.
- If `dedupe=True`, duplicate headers are renamed: 'Header', 'Header_2', ...


### open_plist

```python
open_plist(file_path: Path) -> dict[str, dict[str, bool]] | None
```

Attempts to open a plist file and read its contents with error checking and logging.

This function uses the `plistlib` module to parse the contents of a plist file.
It includes error handling for various exceptions such as invalid file format,
file not found, permission issues, and other I/O errors. Errors are logged
appropriately before being raised.

file_path (Path): The path to the plist file to be opened.

dict[str, dict[str, bool]] | None: The parsed content of the plist file as a dictionary
    if successful, or None if an error occurs.

**Raises**

- **`plistlib.InvalidFileException`** — If the file is not a valid plist.
- **`FileNotFoundError`** — If the file does not exist.
- **`PermissionError`** — If there are insufficient permissions to read the file.
- **`IOError`** — If an I/O error occurs while accessing the file.
- **`Exception`** — For any other unexpected errors.


### open_json

```python
open_json(file_path: Path) -> dict[str, Any]
```

Opens a JSON file and returns its contents as a dictionary.

**Args**

- **`file_path`** *(Path)* — The path to the JSON file to be opened.

**Returns**

- dict[str, Any]: The contents of the JSON file as a dictionary.

**Raises**

- **`FileNotFoundError`** — If the file does not exist.
- **`PermissionError`** — If there is insufficient permission to read the file.
- **`IOError`** — If an I/O error occurs while reading the file.
- **`Exception`** — For any other exceptions that may occur during file handling.

Logs:
    Logs debug information when attempting to open the file.
    Logs an error message if an exception occurs during file handling.


### create_file

```python
create_file(file_path: Path, data: Any, append: bool=False) -> None
```

Attempts to create a file with error checking and logging.

**Args**

- **`file_path`** *(Path)* — The path to the file to be created.

**Returns**

- **`None`** — The function writes directly to the file and does not return a value.

**Raises**

- **`FileNotFoundError`** — If the file does not exist.
- **`PermissionError`** — If there are insufficient permissions to access the file.
- **`IOError`** — If an I/O error occurs during file operations.
- **`Exception`** — For any other unexpected errors.


### create_yaml

```python
create_yaml(file_path: Path, data: dict[str, Any], append: bool=False) -> None
```

Create YAML file.

**Args**

- **`file_path`** *(Path)* — The path to the file that the data will be added to.
- **`data`** *(dict)* — The data that will be added to the file.
- **`sort_keys`** *(bool)* — Sort the keys. Default is False

**Returns**

- **`None`** — The function writes directly to the file and does not return a value.


### create_text

```python
create_text(file_path: Path, data: str, append: bool=False) -> None
```

Write the supplied data to a file.

**Args**

- **`file_path`** *(Path)* — The path to the file to which data will be written.
- **`data`** *(str)* — The data to write to the file.

**Returns**

- **`None`** — The function writes directly to the file and does not return a value.


### create_plist

```python
create_plist(file_path: Path, data: dict[str, Any], append: bool=False) -> None
```


### create_json

```python
create_json(file_path: Path, data: dict[str, Any], append: bool=False) -> None
```

Creates a JSON file at the specified file path with the given data.

**Args**

- **`file_path`** *(Path)* — The path where the JSON file will be created.
- **`data`** *(dict[str, Any])* — The data to be written to the JSON file.

**Raises**

- **`Exception`** — If an error occurs while writing to the file, it logs the error and re-raises the exception.


### create_csv

```python
create_csv(file_path: Path, data: list[dict[str, Any]], append: bool=False) -> None
```

Creates a CSV file at the specified file path with the given data.

**Args**

- **`file_path`** *(Path)* — The path where the CSV file will be created.
- **`data`** *(list[dict[str, Any]])* — The data to be written to the CSV file.

**Raises**

- **`Exception`** — If an error occurs while writing to the file, it logs the error and re-raises the exception.


### make_dir

```python
make_dir(folder_path: Path) -> None
```

Creates a directory at the specified folder path if it does not already exist.

**Args**

- **`folder_path`** *(Path)* — The path of the folder to be created.

**Raises**

- **`OSError`** — If the directory creation fails.

Logs:
    Success message if the directory is created successfully.
    Error message if the directory creation fails.
    Debug message with the error details if the directory creation fails.


### append_text

```python
append_text(file_path: Path, text: str, encoding: str=ENCODING, errors=None, newline=None) -> None
```

Append text to a file, creating the file if it does not exist.

**Args**

- **`file_path`** *(Path)* — The path to the file to which text will be appended.
- **`text`** *(str)* — The text to append to the file.
- **`encoding`** *(str, optional)* — The encoding used to write the text. Defaults to 'utf-8'.
- **`errors`** *(str, optional)* — Specifies how encoding/decoding errors are handled. Defaults to 'strict'.
- **`newline`** *(str, optional)* — Specifies how newlines are handled. Defaults to None.

**Returns**

- **`None`** — The function writes directly to the file and does not return a value.


### remove_dir

```python
remove_dir(folder_path: Path) -> None
```

Remove a directory and all its contents.

This function removes the specified directory and all its files and subdirectories.
It logs the process of removal and handles any errors that may occur.

**Args**

- **`folder_path`** *(Path)* — The path to the directory to be removed.

**Raises**

- **`OSError`** — If an error occurs during the removal process.


### remove_dir_contents

```python
remove_dir_contents(folder_path: Path) -> None
```

Remove the contents of a directory without removing the directory itself.

This function removes all files and subdirectories within the specified directory.
It logs the process of removal and handles any errors that may occur.

**Args**

- **`folder_path`** *(Path)* — The path to the directory whose contents will be removed.

**Raises**

- **`OSError`** — If an error occurs during the removal process.


### remove_file

```python
remove_file(file_path: Path) -> None
```

Remove the specified file if it exists.

**Args**

- **`file_path`** *(Path)* — The path to the file to be removed.

**Raises**

- **`OSError`** — If an error occurs while removing the file.

Logs:
    Success: When the file is successfully removed.
    Warning: If the file is not found.
    Error: If an error occurs while removing the file.
