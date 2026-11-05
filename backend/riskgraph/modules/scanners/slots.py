"""Machine-wide cap on concurrent scanner containers (blueprint §9.2, "Concurrency cap").

A Redis sorted set holds one member per running container, scored by its lease expiry.
Acquire is one Lua script, so the check and the add are atomic across workers. Leases
expire on their own, so a crashed worker cannot hold a slot forever.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import redis

KEY = "riskgraph:scanner_slots"
_ACQUIRE = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
if redis.call('ZCARD', KEYS[1]) < tonumber(ARGV[3]) then
  redis.call('ZADD', KEYS[1], ARGV[2], ARGV[4])
  return 1
end
return 0
"""


class SlotTimeoutError(RuntimeError):
    """No slot became free before the wait ran out."""


class SlotLimiter:
    def __init__(
        self,
        client: redis.Redis,
        max_slots: int,
        lease_s: int,
        *,
        poll_s: float = 1.0,
    ) -> None:
        if max_slots < 1:
            raise ValueError("max_slots must be at least 1")
        self._redis = client
        self._max = max_slots
        self._lease_s = lease_s
        self._poll_s = poll_s
        self._acquire = client.register_script(_ACQUIRE)

    def _try(self, token: str) -> bool:
        now = time.time()
        return bool(
            self._acquire(
                keys=[KEY],
                args=[now, now + self._lease_s, self._max, token],
            )
        )

    @contextmanager
    def slot(self, wait_s: float) -> Iterator[None]:
        token = f"{uuid.uuid4()}"
        deadline = time.monotonic() + wait_s
        while not self._try(token):
            if time.monotonic() >= deadline:
                raise SlotTimeoutError("no scanner slot became free in time")
            time.sleep(self._poll_s)
        try:
            yield
        finally:
            self._redis.zrem(KEY, token)
