"""SAST weakness category from CWE ids (used by the risk model's T factor)."""

from __future__ import annotations

import re

_CWE_CATEGORY: dict[int, str] = {
    89: "sql_injection",
    564: "sql_injection",
    943: "injection",
    77: "command_injection",
    78: "command_injection",
    88: "command_injection",
    94: "code_injection",
    95: "code_injection",
    1336: "code_injection",
    502: "deserialization",
    918: "ssrf",
    611: "xxe",
    22: "path_traversal",
    23: "path_traversal",
    73: "path_traversal",
    79: "xss",
    80: "xss",
    601: "open_redirect",
    287: "auth",
    306: "auth",
    285: "auth",
    862: "auth",
    863: "auth",
    352: "auth",
    798: "hardcoded_secret",
    259: "hardcoded_secret",
    321: "hardcoded_secret",
    326: "crypto",
    327: "crypto",
    328: "crypto",
    330: "crypto",
    338: "crypto",
    295: "crypto",
    200: "info_leak",
    209: "info_leak",
    532: "info_leak",
    250: "privilege",
    269: "privilege",
}
# Most specific first when a result carries several CWEs.
_ORDER = (
    "command_injection",
    "code_injection",
    "deserialization",
    "sql_injection",
    "injection",
    "ssrf",
    "xxe",
    "path_traversal",
    "auth",
    "hardcoded_secret",
    "privilege",
    "xss",
    "open_redirect",
    "crypto",
    "info_leak",
)
_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def cwe_ids(values: list[str] | str | None) -> tuple[str, ...]:
    if not values:
        return ()
    items = [values] if isinstance(values, str) else values
    found = {f"CWE-{int(m)}" for v in items for m in _CWE_RE.findall(str(v))}
    return tuple(sorted(found, key=lambda c: int(c[4:])))


def sast_category(cwes: tuple[str, ...]) -> str:
    cats = {_CWE_CATEGORY[int(c[4:])] for c in cwes if int(c[4:]) in _CWE_CATEGORY}
    for cat in _ORDER:
        if cat in cats:
            return cat
    return "other"
