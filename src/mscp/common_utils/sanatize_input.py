# mscp/common_utils/sanatize_input.py

import logging

from typing import Type, Optional, Iterable, Any

# Initialize local logger
logger = logging.getLogger(__name__)


def sanitised_input(
    prompt: str,
    type_: Optional[Type[Any]] = None,
    range_: Optional[Iterable[Any]] = None,
    default_: Optional[Any] = None
) -> Any:
    """
    Prompts the user for input, casts it to the specified type, validates it, and returns the validated input.

    Args:
        prompt (str): The input prompt to display to the user.
        type_ (Type[Any], optional): The type to cast the input to (e.g., int, float, str). Defaults to None.
        range_ (Iterable[Any], optional): A range or list of acceptable values. Defaults to None.
        default_ (Any, optional): A default value to use if the user provides no input. Defaults to None.

    Returns:
        Any: The validated and type-cast input.

    Raises:
        ValueError: If the user input cannot be cast to the specified type or is out of range.
    """
    while True:
        # Prompt the user for input
        user_input = input(prompt).strip() or default_

        try:
            # Cast the input to the specified type if provided
            if type_:
                user_input = type_(user_input)

            # Check if it's a string but numeric when type_ is str
            if type_ is str and isinstance(user_input, str) and user_input.isnumeric():
                raise ValueError("Input must be a string, not a number.")

            # Validate against the specified range
            if range_ is not None and user_input not in range_:
                if isinstance(range_, range):
                    print(f"Input must be between {range_.start} and {range_.stop - 1}.")
                else:
                    expected = ", ".join(map(str, range_[:-1]))
                    if len(range_) > 1:
                        expected += f", or {range_[-1]}"
                    print(f"Input must be one of the following: {expected}.")
                continue

            return user_input

        except ValueError as e:
            print(f"Invalid input: {e}")
