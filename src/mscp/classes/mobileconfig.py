"""Configuration profile (mobileconfig) model and XML rendering utilities."""

from typing import Any

from lxml import etree

from ._base import BaseModelWithAccessors


class Mobileconfigpayload(BaseModelWithAccessors):
    """A single payload inside a configuration profile.

    Configuration profiles ship one or more payloads (each identified by a
    ``PayloadType`` such as ``"com.apple.screensaver"``). This model holds
    the payload type plus its content as a list of key-value dicts.

    Attributes:
        payload_type: The ``PayloadType`` value (e.g.
            ``"com.apple.screensaver"``).
        payload_content: One or more dicts of preference settings to apply
            within the payload.
    """

    payload_type: str
    payload_content: list[dict[str, Any]]


def create_value_element(value: Any) -> etree._Element:
    """Create a plist XML element from a Python value.

    Maps Python types to their plist XML equivalents:
    ``bool`` → ``<true>``/``<false>``, ``int`` → ``<integer>``,
    ``float`` → ``<real>``, ``str`` → ``<string>``,
    ``list`` → ``<array>`` of ``<string>`` children,
    ``dict`` → ``<dict>`` rendered recursively.

    Args:
        value: The value to convert.

    Returns:
        The corresponding XML element.

    Raises:
        ValueError: If ``value`` is not one of the supported types.
    """
    match value:
        case bool():
            return etree.Element("true" if value else "false")
        case int():
            elem = etree.Element("integer")
            elem.text = str(value)
            return elem
        case float():
            elem = etree.Element("real")
            elem.text = str(value)
            return elem
        case str():
            elem = etree.Element("string")
            elem.text = value
            return elem
        case list():
            array = etree.Element("array")
            for item in value:
                item_elem = etree.SubElement(array, "string")
                item_elem.text = item
            return array
        case dict():
            dict_elem = etree.Element("dict")
            for k, v in value.items():
                key_elem = etree.SubElement(dict_elem, "key")
                key_elem.text = k
                dict_elem.append(create_value_element(v))
            return dict_elem
        case _:
            raise ValueError(f"Unsupported value type: {type(value)}")


def format_payload(
    payload_type: str,
    payload_content: list[dict] | dict,
    jinja_filter: bool = False,
) -> str:
    """Render a single payload as XML, optionally wrapped for AsciiDoc.

    Builds a ``<Payload>`` XML tree from ``payload_content`` (each dict
    becomes a sequence of ``<key>`` / value-element pairs) and
    pretty-prints it. Unless ``jinja_filter`` is set, the output is
    wrapped in an AsciiDoc ``[source,xml]`` block delimited by ``----``.

    Args:
        payload_type: The ``PayloadType`` value. Passed for symmetry with
            `Mobileconfigpayload`; the rendered XML always uses a
            ``<Payload>`` root regardless of this value.
        payload_content: The payload's content section. Lists of dicts are
            unpacked into the root element; bare dicts are not currently
            rendered (use a single-element list instead).
        jinja_filter: If true, omit the AsciiDoc source-block wrappers
            and emit only the XML. Defaults to ``False``.

    Returns:
        The rendered payload, ready to splice into generated guidance.
    """
    output = "" if jinja_filter else "[source,xml]\n----\n"

    root = etree.Element("Payload")
    if isinstance(payload_content, list):
        for payload in payload_content:
            if isinstance(payload, dict):
                for key, value in payload.items():
                    key_elem = etree.SubElement(root, "key")
                    key_elem.text = key
                    root.append(create_value_element(value))

    output += (
        etree.tostring(root, encoding="unicode", pretty_print=True)
        .strip()
        .replace("<root>", "")
        .replace("</root>", "")
        + "\n"
    )

    if not jinja_filter:
        output += "----\n\n"

    return output


def mobileconfig_info_to_xml(mobileconfig_info: list[dict[str, Any]]) -> str:
    """Render a list of payloads as raw XML.

    Convenience wrapper around `format_payload` with ``jinja_filter=True``
    so callers (typically Jinja templates) get XML without the AsciiDoc
    source-block delimiters.

    Args:
        mobileconfig_info: Payload dicts with at least ``payload_type`` and
            ``payload_content`` keys (matches
            ``Mobileconfigpayload.model_dump()``).

    Returns:
        Concatenated XML for every payload, or the empty string if
        ``mobileconfig_info`` is empty.
    """
    if not mobileconfig_info:
        return ""

    return "".join(
        format_payload(p["payload_type"], p["payload_content"], jinja_filter=True)
        for p in mobileconfig_info
    )
