"""Beat: vulnerability feed refresh (blueprint §11). Never on the scan path."""

from __future__ import annotations

import datetime as dt

from celery import shared_task

from riskgraph.modules.context.service import nvd_refresh
from riskgraph.shared.config import get_settings
from riskgraph.shared.db import session_scope
from riskgraph.shared.http import OutboundClient
from riskgraph.shared.logging import get_logger

log = get_logger(__name__)


@shared_task(name="riskgraph.context.refresh_feeds")
def refresh_feeds_task() -> dict[str, int]:
    settings = get_settings()
    if not settings.enrichment_enabled:
        return {"skipped": 1}
    client = OutboundClient()
    try:
        with session_scope() as s:
            return nvd_refresh(s, settings, client, dt.datetime.now(dt.UTC))
    finally:
        client.close()
