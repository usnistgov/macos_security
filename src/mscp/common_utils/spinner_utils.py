# mscp/common_utils/spinner_utils.py
"""Verbosity-aware wrapper around `yaspin`'s `inject_spinner`.

When verbose logging is active, log lines and a spinner clobber each
other in the terminal. `conditional_inject_spinner` injects the spinner
only when `logging_config.verbose_logging` is false; otherwise it runs
the wrapped function with a no-op shim so calls like `sp.ok()` and
`sp.text =` are silently swallowed.
"""

import functools
from yaspin import yaspin
from . import logging_config


class _NoOpSpinner:
    """Silent drop-in for a yaspin spinner used when output is suppressed."""

    def __setattr__(self, name, value):
        pass

    def __getattr__(self, name):
        return lambda *a, **kw: None


def conditional_inject_spinner(**spinner_kwargs):
    """Decorator factory that injects a `yaspin` spinner only when quiet.

    Behaves like `yaspin.inject_spinner` (the spinner is started before
    the wrapped call and stopped after), but passes a no-op shim instead
    when `logging_config.verbose_logging` or `logging_config.suppress_spinner`
    is true, so calls like `sp.ok()` and `sp.text =` inside the wrapped
    function produce no output.

    Args:
        **spinner_kwargs: Keyword arguments forwarded to `yaspin()` to
            configure the spinner (e.g. ``text=...``, ``color=...``).

    Returns:
        Callable: A decorator that wraps a function so it runs with a
            (possibly inert) spinner injected as its first argument.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            suppress = logging_config.verbose_logging or logging_config.suppress_spinner

            if suppress:
                return func(_NoOpSpinner(), *args, **kwargs)

            sp = yaspin(**spinner_kwargs)
            sp.start()
            try:
                return func(sp, *args, **kwargs)
            finally:
                sp.stop()

        return wrapper

    return decorator
