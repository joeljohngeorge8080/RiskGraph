"""Secret handling for scanner reports (threat T-09, CLAUDE.md "never store raw secrets").

- ``secret_hmac``: keyed HMAC of a raw secret. Lets two scans (or two scanners)
  recognise the same secret without anyone being able to recover or brute-force it
  offline without the instance key.
- ``mask``: what a person sees instead of the secret: first 4 characters + length.
- ``scrub``: removes every known raw secret from any JSON-like value, recursively. The
  collector runs it over *all* reports with the secrets Gitleaks found, because other
  scanners echo source lines (Trivy ``Code``, Checkov ``code_block``) too.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from riskgraph.shared.config import Settings

_KEY_LABEL = b"riskgraph/secret-fingerprint/v1"
MASK = "[REDACTED]"
MIN_SCRUB_LEN = 6  # shorter "secrets" would scrub ordinary words out of reports


def derive_key(settings: Settings) -> bytes:
    """Instance key for secret HMACs; rotating ``secret_key`` changes all fingerprints."""
    return hmac.new(
        settings.secret_key.get_secret_value().encode(), _KEY_LABEL, hashlib.sha256
    ).digest()


def secret_hmac(key: bytes, secret: str) -> str:
    return hmac.new(key, secret.encode("utf-8", "replace"), hashlib.sha256).hexdigest()


def mask(secret: str) -> str:
    prefix = secret[:4] if len(secret) >= 12 else ""
    return f"{prefix}…{MASK} ({len(secret)} chars)"


def scrub(value: Any, secrets: set[str]) -> Any:
    candidates = sorted((s for s in secrets if len(s) >= MIN_SCRUB_LEN), key=len, reverse=True)
    if not candidates:
        return value
    return _scrub(value, candidates)


def _scrub(value: Any, secrets: list[str]) -> Any:
    if isinstance(value, str):
        for s in secrets:
            if s in value:
                value = value.replace(s, MASK)
        return value
    if isinstance(value, list):
        return [_scrub(v, secrets) for v in value]
    if isinstance(value, dict):
        return {k: _scrub(v, secrets) for k, v in value.items()}
    return value


def drop_keys(value: Any, keys: frozenset[str]) -> Any:
    """Recursively remove keys that carry source snippets."""
    if isinstance(value, list):
        return [drop_keys(v, keys) for v in value]
    if isinstance(value, dict):
        return {k: drop_keys(v, keys) for k, v in value.items() if k not in keys}
    return value


def clip(text: str | None, limit: int = 2000) -> str | None:
    if text is None:
        return None
    return text if len(text) <= limit else text[: limit - 1] + "…"
