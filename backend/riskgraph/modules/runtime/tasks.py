"""Beat: end-of-life refresh from endoflife.date (expansion X2). Never on the scan path."""

from __future__ import annotations

import datetime as dt

from celery import shared_task

from riskgraph.modules.runtime.service import refresh_eol
from riskgraph.shared.config import get_settings
from riskgraph.shared.db import session_scope
from riskgraph.shared.http import OutboundClient


@shared_task(name="riskgraph.runtime.refresh_eol")
def refresh_eol_task() -> dict[str, int]:
    if not get_settings().enrichment_enabled:
        return {"skipped": 1}
    client = OutboundClient()
    try:
        with session_scope() as s:
            return refresh_eol(s, client, dt.datetime.now(dt.UTC))
    finally:
        client.close()
