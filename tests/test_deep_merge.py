"""Regression proof for deep_merge's preferred key dropping later override fields.

Issue #808: the ``preferred_key`` branch added in #736 replaced the key wholesale and
then returned, so every key listed after it in the same mapping was never merged. A
``custom/rules`` override that set ``result`` before ``shell`` kept the stock ``shell``,
pairing the stock check with the override's expected result — a rule that could not pass
on a correctly configured Mac. Fixed in #811.
"""

from __future__ import annotations

from mscp.classes.macsecurityrule import deep_merge


def _stock() -> dict:
    """A fresh stock check. deep_merge mutates its first argument, so never share one."""
    return {"check": {"shell": "stock-check", "result": {"string": "PASS"}}}


def test_preferred_key_is_replaced_whole_not_merged() -> None:
    """#736's behaviour: the override's result replaces the stock one entirely."""
    merged = deep_merge(_stock(), {"check": {"result": {"integer": 1}}}, preferred_key="result")

    assert merged["check"]["result"] == {"integer": 1}


def test_keys_after_the_preferred_key_are_still_merged() -> None:
    """#808 itself: shell follows result in the override and must survive."""
    override = {"check": {"result": {"integer": 1}, "shell": "override-check"}}

    merged = deep_merge(_stock(), override, preferred_key="result")

    assert merged["check"] == {"shell": "override-check", "result": {"integer": 1}}


def test_key_order_in_the_override_does_not_matter() -> None:
    """The same override written in either order produces the same merge."""
    result_first = deep_merge(
        _stock(),
        {"check": {"result": {"integer": 1}, "shell": "override-check"}},
        preferred_key="result",
    )
    shell_first = deep_merge(
        _stock(),
        {"check": {"shell": "override-check", "result": {"integer": 1}}},
        preferred_key="result",
    )

    assert result_first == shell_first


def test_siblings_of_the_preferred_key_are_untouched_when_absent_from_the_override() -> None:
    """An override that only sets result leaves the rest of the stock check alone."""
    merged = deep_merge(_stock(), {"check": {"result": {"integer": 1}}}, preferred_key="result")

    assert merged["check"]["shell"] == "stock-check"


def test_nested_keys_after_the_preferred_key_still_merge() -> None:
    """The drop was not limited to scalars: a nested mapping after result was lost too."""
    stock = {"check": {"result": {"string": "PASS"}, "fix": {"shell": "stock-fix", "keep": True}}}
    override = {"check": {"result": {"integer": 1}, "fix": {"shell": "override-fix"}}}

    merged = deep_merge(stock, override, preferred_key="result")

    assert merged["check"]["fix"] == {"shell": "override-fix", "keep": True}


def test_without_a_preferred_key_mappings_merge_as_before() -> None:
    """No preferred_key: plain recursive merge, unchanged by #736 and #811."""
    merged = deep_merge(_stock(), {"check": {"result": {"integer": 1}}})

    assert merged["check"]["result"] == {"string": "PASS", "integer": 1}
