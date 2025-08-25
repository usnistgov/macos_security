# mscp/common_utils/sanatize_input.py

# Standard python modules
from collections.abc import Sequence
from typing import Any

# Local python modules
from .logger_instance import logger

# Additional python modules


def sanitize_input(
    prompt: str,
    type_: type[Any] | None = None,
    range_: Sequence[Any] | None = None,
    default_: Any | None = None,
) -> Any:
    """
    Prompts the user for input, casts it to the specified type, validates it, and returns the validated input.

    Args:
        prompt (str): The input prompt to display to the user.
        type_ (type[Any], optional): The type to cast the input to (e.g., int, float, str). Defaults to None.
        range_ (Sequence[Any], optional): A range or list of acceptable values. Defaults to None.
        default_ (Any, optional): A default value to use if the user provides no input. Defaults to None.

    Returns:
        Any: The validated and type-cast input.

    Raises:
        ValueError: If the user input cannot be cast to the specified type or is out of range.
    """
    while True:
        # Prompt the user for input
        user_input = input(prompt).strip()
        if not user_input and default_ is not None:
            user_input = default_

        try:
            # Cast the input to the specified type if provided
            if type_:
                user_input = type_(user_input)

            # Check if it's a string but numeric when type_ is str
            if type_ is str and isinstance(user_input, str) and user_input.isnumeric():
                logger.error("Input must be a string, not a number.")
                raise ValueError("Input must be a string, not a number.")

            # Validate against the specified range
            if range_ is not None and user_input not in range_:
                if isinstance(range_, range):
                    if len(range_) > 1:
                        range_list = list(range_)
                        expected = ", ".join(map(str, range_list[:-1]))
                    else:
                        expected = str(range_[0])
                else:
                    range_list = list(range_)
                    expected = ", ".join(map(str, range_list[:-1]))
                    if len(range_) > 1:
                        expected += f", or {range_[-1]}"
                    logger.error(f"Input must be one of the following: {expected}.")
                    print(f"Input must be one of the following: {expected}.")
                continue

            return user_input

        except ValueError as e:
            logger.error(f"Invalid input: {e}")
            raise
