"""Store and read end-of-life cycles. Fetching happens in Beat, never on the scan path."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from riskgraph.modules.runtime.eol import FEED_URL, PRODUCTS, EolCycle, parse_cycles
from riskgraph.modules.runtime.models import RuntimeEol
from riskgraph.shared.http import OutboundClient, OutboundError
from riskgraph.shared.logging import get_logger

log = get_logger(__name__)


def store_cycles(session: Session, cycles: Iterable[EolCycle]) -> int:
    rows = {
        (c.product, c.cycle): {
            "product": c.product,
            "cycle": c.cycle,
            "eol_date": c.eol_date,
            "eol_flag": c.eol_flag,
            "latest": c.latest,
            "release_date": c.release_date,
            "fetched_at": c.fetched_at,
        }
        for c in cycles
    }
    if rows:
        stmt = insert(RuntimeEol).values(list(rows.values()))
        update = {
            k: stmt.excluded[k] for k in rows[next(iter(rows))] if k not in ("product", "cycle")
        }
        session.execute(
            stmt.on_conflict_do_update(index_elements=["product", "cycle"], set_=update)
        )
    return len(rows)


def refresh_eol(
    session: Session, client: OutboundClient, now: dt.datetime, products: Iterable[str] = PRODUCTS
) -> dict[str, int]:
    """Beat job. A product that fails keeps its last data; the others still refresh."""
    out: dict[str, int] = {}
    for product in products:
        try:
            doc = client.get_json(FEED_URL.format(product=product))
        except OutboundError as exc:
            log.warning("eol_unavailable", product=product, error=str(exc))
            out[product] = -1
            continue
        out[product] = store_cycles(session, parse_cycles(product, doc, now))
    return out


def load_feeds(
    session: Session, products: Iterable[str] = PRODUCTS
) -> dict[str, dict[str, EolCycle]]:
    feeds: dict[str, dict[str, EolCycle]] = {}
    for row in session.scalars(select(RuntimeEol).where(RuntimeEol.product.in_(list(products)))):
        feeds.setdefault(row.product, {})[row.cycle] = EolCycle(
            product=row.product,
            cycle=row.cycle,
            eol_date=row.eol_date,
            eol_flag=row.eol_flag,
            latest=row.latest,
            release_date=row.release_date,
            fetched_at=row.fetched_at,
        )
    return feeds
