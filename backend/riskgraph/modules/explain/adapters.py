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
    """``POST /api/chat`` with structured output, temperature 0 and thinking off."""

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        timeout_s: float = 60.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("ollama_url must be an http(s) URL")
        self._url = base_url.rstrip("/") + "/api/chat"
        self._model = model
        self._client = httpx.Client(transport=transport, timeout=timeout_s, follow_redirects=False)

    @property
    def name(self) -> str:
        return f"ollama:{self._model}"

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        body = {
            "model": self._model,
            "stream": False,
            "think": False,
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
