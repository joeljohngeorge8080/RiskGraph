"""LLM adapters (blueprint §15): one protocol, Ollama by default, Null for tests.

An adapter turns (system, user, JSON schema) into the model's raw JSON text. It knows
nothing about evidence or validation; ``service.explain`` owns those.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

MAX_RESPONSE_BYTES = 256 * 1024
MAX_OUTPUT_TOKENS = 900


class AdapterError(Exception):
    """The model could not answer (down, timed out, malformed reply): fall back."""


class LlmAdapter(Protocol):
    @property
    def name(self) -> str: ...

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str: ...

    def close(self) -> None: ...


class OllamaAdapter:
    """``POST /api/chat`` with structured output, temperature 0 and thinking off.

    ``keep_alive`` is sent on every call: a call without it resets Ollama's unload timer to
    its 5-minute default, which would undo a model the stack preloaded to stay resident.

    With ``socket`` set, HTTP goes over that unix socket file and ``base_url`` is ignored:
    the request goes to ``localhost``, the only kind of Host header Ollama accepts. That is
    how containers reach the host's Ollama: a host firewall may drop container-to-host TCP,
    and a mounted socket file does not touch the network at all.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        timeout_s: float = 60.0,
        keep_alive: str = "10m",
        socket: str = "",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("ollama_url must be an http(s) URL")
        self._url = ("http://localhost" if socket else base_url.rstrip("/")) + "/api/chat"
        self._model = model
        text = keep_alive.strip()
        # Ollama takes a duration string ("10m") or a number of seconds (negative = forever)
        self._keep_alive: str | int = int(text) if text.lstrip("-").isdigit() else text
        if socket and transport is None:
            transport = httpx.HTTPTransport(uds=socket)
        self._client = httpx.Client(transport=transport, timeout=timeout_s, follow_redirects=False)

    @property
    def name(self) -> str:
        return f"ollama:{self._model}"

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        body = {
            "model": self._model,
            "stream": False,
            "think": False,
            "keep_alive": self._keep_alive,
            "format": schema,
            "options": {"temperature": 0, "num_predict": MAX_OUTPUT_TOKENS},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            with self._client.stream("POST", self._url, json=body) as resp:
                if resp.status_code != 200:
                    raise AdapterError(f"ollama returned HTTP {resp.status_code}")
                raw = bytearray()
                for chunk in resp.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise AdapterError("ollama response exceeds the size cap")
        except httpx.HTTPError as exc:
            raise AdapterError(f"ollama unreachable: {type(exc).__name__}") from exc
        try:
            content = json.loads(bytes(raw))["message"]["content"]
        except (ValueError, KeyError, TypeError) as exc:
            raise AdapterError("ollama reply has no message content") from exc
        if not isinstance(content, str):
            raise AdapterError("ollama reply content is not text")
        return content

    def close(self) -> None:
        self._client.close()


class NullAdapter:
    """Canned replies in order, for tests and golden evaluations (no network)."""

    def __init__(self, replies: Sequence[str | Exception] | Callable[[str], str]) -> None:
        self._replies = replies
        self.calls: list[str] = []

    @property
    def name(self) -> str:
        return "null"

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        self.calls.append(user)
        if callable(self._replies):
            return self._replies(user)
        index = len(self.calls) - 1
        if index >= len(self._replies):
            raise AdapterError("no canned reply left")
        reply = self._replies[index]
        if isinstance(reply, Exception):
            raise reply
        return reply

    def close(self) -> None:
        return None
