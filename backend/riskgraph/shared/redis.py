"""Redis client factory (rate limiting, scanner slots, health). Celery has its own."""

from __future__ import annotations

from functools import lru_cache

import redis

from riskgraph.shared.config import get_settings


@lru_cache(maxsize=1)
def get_redis() -> redis.Redis:
    settings = get_settings()
    return redis.Redis.from_url(
        settings.redis_url, socket_connect_timeout=2, socket_timeout=2, decode_responses=True
    )


def check_redis() -> None:
    """Raise if Redis is unreachable. Used by readiness."""
    get_redis().ping()
