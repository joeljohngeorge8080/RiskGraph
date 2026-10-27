"""Small tree-sitter helpers shared by the extractor's passes (imports, calls, routes)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def walk(node: Any) -> Iterator[Any]:
    """Pre-order traversal without recursion (hostile files can nest very deeply)."""
    cursor = node.walk()
    while True:
        yield cursor.node
        if cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return


def text(node: Any) -> str:
    return bytes(node.text or b"").decode("utf-8", "replace")


def string_value(node: Any) -> str | None:
    """A plain string literal's value; None for anything interpolated or prefixed."""
    if node is None or node.type not in ("string", "template_string"):
        return None
    raw = text(node)
    if len(raw) >= 2 and raw[0] in "'\"`" and raw[-1] == raw[0]:
        inner = raw[1:-1]
        return None if "${" in inner else inner
    return None


def dotted(node: Any) -> str | None:
    """``a.b.c`` for an identifier chain; None for anything dynamic (subscripts, calls)."""
    if node is None:
        return None
    if node.type == "identifier":
        return text(node)
    if node.type == "attribute":
        head = dotted(node.child_by_field_name("object"))
        attr = node.child_by_field_name("attribute")
        if head and attr is not None and attr.type == "identifier":
            return f"{head}.{text(attr)}"
    return None
