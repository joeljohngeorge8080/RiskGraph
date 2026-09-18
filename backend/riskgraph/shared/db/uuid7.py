"""UUID v7 (RFC 9562) generator (ADR-0003).

Python 3.14 ships ``uuid.uuid7``; until then this is a small, standard-conforming
implementation: 48-bit unix milliseconds, 4-bit version, 12 bits of sub-millisecond
monotonic counter, 2-bit variant, 62 random bits.
"""

from __future__ import annotations

import os
import threading
import time
import uuid

_lock = threading.Lock()
_last_ms = 0
_seq = 0


def uuid7() -> uuid.UUID:
    global _last_ms, _seq
    with _lock:
        now_ms = time.time_ns() // 1_000_000
        if now_ms <= _last_ms:
            _seq += 1
            if _seq > 0x0FFF:  # counter exhausted within one ms: borrow the next ms
                _last_ms += 1
                _seq = 0
            now_ms = _last_ms
        else:
            _last_ms = now_ms
            _seq = int.from_bytes(os.urandom(2), "big") & 0x07FF  # random start, room to grow
        rand = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)
        value = (now_ms << 80) | (0x7 << 76) | (_seq << 64) | (0b10 << 62) | rand
        return uuid.UUID(int=value)
