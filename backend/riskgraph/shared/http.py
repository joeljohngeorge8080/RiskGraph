"""Outbound HTTP for threat-intel feeds (EPSS, KEV, NVD, endoflife.date).

The only place the backend talks to the Internet besides ``git clone``. Hosts are
allow-listed, redirects are refused and bodies are size-capped, so a compromised or
spoofed feed cannot turn the worker into a proxy or exhaust memory.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

import httpx

# (host, path prefix) pairs. raw.githubusercontent.com is only allowed for CISA's own
# KEV mirror, never for arbitrary repositories.
ALLOWED_TARGETS = (
    ("api.first.org", "/data/"),
    ("www.cisa.gov", "/sites/default/files/feeds/"),
    ("raw.githubusercontent.com", "/cisagov/kev-data/"),
    ("services.nvd.nist.gov", "/rest/json/cves/2.0"),
    ("endoflife.date", "/api/"),  # runtime end-of-life cycles (X2)
)
DEFAULT_TIMEOUT_S = 10.0
MAX_BODY_BYTES = 20 * 1024 * 1024


class OutboundError(Exception):
    """A feed could not be fetched; callers degrade gracefully."""


class OutboundClient:
    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_body_bytes: int = MAX_BODY_BYTES,
    ) -> None:
        self._client = httpx.Client(
            transport=transport,
            timeout=timeout_s,
            follow_redirects=False,
            headers={
                "User-Agent": "riskgraph/0.1 (+https://github.com/joeljohngeorge8080/RiskGraph)"
            },
        )
        self._max = max_body_bytes

    def get_json(
        self,
        url: str,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        parts = urlsplit(url)
        allowed = any(
            parts.hostname == host and parts.path.startswith(prefix)
            for host, prefix in ALLOWED_TARGETS
        )
        if parts.scheme != "https" or parts.port not in (None, 443) or not allowed:
            raise OutboundError(f"target not allowed: {parts.hostname}{parts.path}")
        try:
            with self._client.stream("GET", url, params=params, headers=headers) as resp:
                if resp.status_code != 200:
                    raise OutboundError(f"{parts.hostname} returned HTTP {resp.status_code}")
                body = bytearray()
                for chunk in resp.iter_bytes():
                    body.extend(chunk)
                    if len(body) > self._max:
                        raise OutboundError(f"{parts.hostname} response exceeds size cap")
        except httpx.HTTPError as exc:
            raise OutboundError(f"{parts.hostname}: {type(exc).__name__}") from exc
        try:
            return json.loads(bytes(body))
        except ValueError as exc:
            raise OutboundError(f"{parts.hostname} returned invalid JSON") from exc

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> OutboundClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
