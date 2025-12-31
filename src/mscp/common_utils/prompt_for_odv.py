# mscp/common_utils/prompt_for_odv.py

# Standard python modules
from typing import Any, Dict, Optional
import re

# Local python modules
# from .logger_instance import logger


def prompt_for_odv(
    prompt: str,
    odv_hint: Dict[str, Any],
    default: Optional[Any] = None,
) -> Any:
    """
    Prompt the user for an 'organization defined value' (ODV) using a single hint dict
    that defines datatype, description, and validation rules. Reprompts until valid.

    Args:
        prompt (str): The prompt shown to the user.
        odv_hint (dict): Hint metadata containing:
            - 'datatype' (str): one of 'number', 'string', 'enum', 'regex'
            - 'description' (str): guidance shown next to the prompt
            - 'validation' (dict): rule set keyed by datatype:
                * number: {'min': <int>, 'max': <int>} (both optional)
                * regex:  {'regex': <str>} (required for datatype='regex')
                * enum:   {'enumValues': [<str>, ...]} (required for datatype='enum')
                * string: {'regex': <str>} (optional; applied to raw input)
        default (Any, optional): Value used when user hits Enter; will be validated.

    Returns:
        Any: The validated value (coerced according to the datatype).

    Behavior:
        - Regex rules apply to the raw text first (if present).
        - Values are then coerced according to 'datatype'.
        - Range/membership rules apply after coercion.
        - If default is provided, it is validated before being returned.
    """

    # ---- helpers ------------------------------------------------------------

    def _apply_regex(text: str, pattern: str) -> Optional[str]:
        """Return error message if text does NOT match the pattern; else None."""
        try:
            if re.fullmatch(pattern, text) is None:
                return f"Value must match the pattern: {pattern}"
            return None
        except re.error as ex:
            return f"Invalid regex pattern in hint: {ex}"

    def _coerce(text: str, dt: str) -> Any:
        """Coerce raw text to the target datatype."""
        # default to string if no datatype is provided
        dt_norm = (dt or "string").strip().lower()
        if dt_norm == "number":
            return int(text)  # will raise ValueError if invalid
        elif dt_norm in ("string", "enum", "regex"):
            return text  # keep as string; enum/regex validated separately
        else:
            raise ValueError(
                f"Unsupported datatype '{dt}'. Use 'number', 'string', 'enum', or 'regex'."
            )

    def _validate(
        value: Any, raw_text: str, dt: str, rules: Dict[str, Any]
    ) -> Optional[str]:
        """Return error message string if invalid; else None."""

        # if rules are not defined, accept any values
        if not rules:
            return None

        dt_norm = (dt or "").strip().lower()

        # 1) Regex on raw input if present (for both string and regex modes)
        regex = rules.get("regex")
        if regex:
            err = _apply_regex(raw_text, regex)
            if err:
                return err

        # 2) Datatype-specific checks after coercion
        if dt_norm == "number":
            min_v = rules.get("min", None)
            max_v = rules.get("max", None)
            if min_v is not None and value < min_v:
                return f"Value must be ≥ {min_v}."
            if max_v is not None and value > max_v:
                return f"Value must be ≤ {max_v}."

        elif dt_norm == "enum":
            opts = rules.get("enumValues")
            if not opts or not isinstance(opts, (list, tuple, set)):
                return "Missing 'enumValues' for datatype='enum'."
            # case-insensitive membership convenience
            lowered = {str(o).lower() for o in opts}
            if str(value).lower() not in lowered:
                return f"Value must be one of: {list(opts)}."

        elif dt_norm == "regex":
            # Already checked via regex above; enforce presence of rule
            if "regex" not in rules:
                return "Missing 'regex' rule for datatype='regex'."

        # string: nothing additional beyond optional regex
        return None

    # ---- main loop ----------------------------------------------------------

    dt = (odv_hint.get("datatype") or "").strip().lower()
    rules = odv_hint.get("validation", {}) or {}

    # Build a friendly prompt line
    # hint = f" — {desc}" if desc else ""
    # default_hint = f" [default: {default}]" if default not in (None, "") else ""
    # display = f"{prompt}{hint}{default_hint}"

    while True:
        raw = input(f"{prompt}").strip()

        # Handle default
        if raw == "":
            if default is not None:
                # Validate default too
                try:
                    coerced_default = (
                        _coerce(str(default), dt) if dt == "number" else default
                    )
                except ValueError as ex:
                    print(f"Default value cannot be coerced: {ex}")
                    # continue reprompting
                    continue
                err = _validate(coerced_default, str(default), dt, rules)
                if err is None:
                    return coerced_default
                else:
                    print(f"Default value invalid: {err}")
                    continue
            else:
                print("Please enter a value (or provide a default).")
                continue

        # Coerce user entry
        try:
            value = _coerce(raw, dt)
        except ValueError:
            print("\nERROR - Value must be a valid integer")
            continue

        # Validate combined rules
        error = _validate(value, raw_text=raw, dt=dt, rules=rules)
        if error is None:
            return value

        print(f"\nERROR - {error}")
        # loop continues
