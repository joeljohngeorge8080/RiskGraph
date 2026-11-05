"""Vulnerability intelligence: merge scanner CVSS with EPSS and KEV, cache in Postgres.

Feeds are refreshed only when the cached value is older than its TTL. Any feed failure
degrades to "unavailable" for that factor; it never fails a scan.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import redis
from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from riskgraph.modules.context.cvss import subscores
from riskgraph.modules.context.feeds import EpssScore, fetch_epss, fetch_kev, fetch_nvd
from riskgraph.modules.context.iac import IacAsset
from riskgraph.modules.context.models import Asset, Vulnerability
from riskgraph.shared.config import Settings
from riskgraph.shared.http import OutboundClient, OutboundError
from riskgraph.shared.logging import get_logger

log = get_logger(__name__)
KEV_CACHE_KEY = "riskgraph:kev:v1"


@dataclass(frozen=True, slots=True)
class VulnIntel:
    id: str
    cvss_vector: str | None = None
    cvss_source: str | None = None
    cvss_base: float | None = None
    cvss_impact: float | None = None
    cvss_exploitability: float | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    epss_status: str = "not_applicable"  # ok | not_scored | unavailable | disabled
    kev: bool | None = None
    kev_added: dt.date | None = None
    kev_status: str = "not_applicable"  # ok | unavailable | disabled


def _fresh(ts: dt.datetime | None, now: dt.datetime, ttl_hours: int) -> bool:
    return ts is not None and now - ts < dt.timedelta(hours=ttl_hours)


def _load_kev(client: OutboundClient, cache: redis.Redis | None, ttl_hours: int) -> dict[str, str]:
    if cache is not None:
        try:
            cached = cache.get(KEV_CACHE_KEY)
            if cached:
                return dict(json.loads(str(cached)))
        except (redis.RedisError, ValueError):
            pass
    catalogue = fetch_kev(client)
    if cache is not None:
        with contextlib.suppress(redis.RedisError):
            cache.set(KEV_CACHE_KEY, json.dumps(catalogue), ex=ttl_hours * 3600)
    return catalogue


def refresh_intel(
    session: Session,
    cvss_by_id: dict[str, dict[str, Any] | None],
    settings: Settings,
    client: OutboundClient | None,
    cache: redis.Redis | None = None,
    now: dt.datetime | None = None,
) -> dict[str, VulnIntel]:
    """Upsert one ``vulnerabilities`` row per id and return the intel used for scoring."""
    now = now or dt.datetime.now(dt.UTC)
    ids = sorted(cvss_by_id)
    if not ids:
        return {}
    rows = {
        v.id: v for v in session.scalars(select(Vulnerability).where(Vulnerability.id.in_(ids)))
    }
    cves = [i for i in ids if i.startswith("CVE-")]
    enabled = settings.enrichment_enabled and client is not None

    epss_new: dict[str, EpssScore] = {}
    epss_failed = False
    stale_epss = [
        c
        for c in cves
        if not _fresh(getattr(rows.get(c), "epss_fetched_at", None), now, settings.epss_ttl_hours)
    ]
    if enabled and stale_epss and client is not None:
        try:
            epss_new = fetch_epss(client, stale_epss)
        except OutboundError as exc:
            epss_failed = True
            log.warning("epss_unavailable", error=str(exc))

    kev_catalogue: dict[str, str] | None = None
    stale_kev = [
        c
        for c in cves
        if not _fresh(getattr(rows.get(c), "kev_checked_at", None), now, settings.kev_ttl_hours)
    ]
    if enabled and stale_kev and client is not None:
        try:
            kev_catalogue = _load_kev(client, cache, settings.kev_ttl_hours)
        except OutboundError as exc:
            log.warning("kev_unavailable", error=str(exc))

    intel: dict[str, VulnIntel] = {}
    for vid in ids:
        cvss = cvss_by_id.get(vid) or {}
        sub = subscores(str(cvss.get("vector") or "")) if cvss else None
        values: dict[str, Any] = {"id": vid}
        existing = rows.get(vid)
        # NVD outranks scanner-reported CVSS (blueprint §11.2): keep a cached NVD score.
        nvd_owned = existing is not None and existing.cvss_source == "nvd"
        if sub is not None and not nvd_owned:
            values |= {
                "cvss_version": str(cvss.get("version") or "")[:8] or None,
                "cvss_vector": cvss.get("vector"),
                "cvss_base": Decimal(str(cvss["base"])) if cvss.get("base") is not None else None,
                "cvss_impact": Decimal(str(sub.impact)),
                "cvss_exploitability": Decimal(str(sub.exploitability)),
                "cvss_source": cvss.get("source"),
            }
        if vid in epss_new:
            e = epss_new[vid]
            values |= {"epss": e.epss, "epss_percentile": e.percentile, "epss_date": e.date}
        if vid in stale_epss and enabled and not epss_failed:
            values["epss_fetched_at"] = now
        if kev_catalogue is not None and vid.startswith("CVE-"):
            added = kev_catalogue.get(vid)
            values |= {
                "kev": added is not None,
                "kev_added": dt.date.fromisoformat(added) if added else None,
                "kev_checked_at": now,
            }
        stmt = insert(Vulnerability).values(**values)
        update: dict[str, Any] = {k: stmt.excluded[k] for k in values if k != "id"}
        update["updated_at"] = now
        session.execute(stmt.on_conflict_do_update(index_elements=["id"], set_=update))

    session.flush()
    session.expire_all()
    fresh = {
        v.id: v for v in session.scalars(select(Vulnerability).where(Vulnerability.id.in_(ids)))
    }
    for vid in ids:
        v = fresh[vid]
        is_cve = vid.startswith("CVE-")
        if not is_cve:
            epss_status = kev_status = "not_applicable"
        elif not settings.enrichment_enabled:
            epss_status = kev_status = "disabled"
        else:
            if v.epss is not None:
                epss_status = "ok"
            elif v.epss_fetched_at is not None:
                epss_status = "not_scored"
            else:
                epss_status = "unavailable"
            kev_status = "ok" if v.kev_checked_at is not None else "unavailable"
        intel[vid] = VulnIntel(
            id=vid,
            cvss_vector=v.cvss_vector,
            cvss_source=v.cvss_source,
            cvss_base=float(v.cvss_base) if v.cvss_base is not None else None,
            cvss_impact=float(v.cvss_impact) if v.cvss_impact is not None else None,
            cvss_exploitability=(
                float(v.cvss_exploitability) if v.cvss_exploitability is not None else None
            ),
            epss=float(v.epss) if v.epss is not None else None,
            epss_percentile=float(v.epss_percentile) if v.epss_percentile is not None else None,
            epss_status=epss_status,
            kev=v.kev if kev_status == "ok" else None,
            kev_added=v.kev_added,
            kev_status=kev_status,
        )
    return intel


def nvd_refresh(
    session: Session,
    settings: Settings,
    client: OutboundClient,
    now: dt.datetime,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, int]:
    """Beat job: NVD CVSS for the oldest-checked CVEs, within the rate limit.

    A CVE NVD answers for is stored as ``cvss_source='nvd'``. A CVE NVD has no score for is
    still stamped with ``nvd_checked_at`` (negative cache), so it is not asked again every
    run. The first rate-limit or network error stops the run; the rest waits for the next.
    """
    min_interval = 0.7 if settings.nvd_api_key else 6.5
    stale = session.scalars(
        select(Vulnerability.id)
        .where(Vulnerability.id.startswith("CVE-"))
        .where(
            (Vulnerability.nvd_checked_at.is_(None))
            | (Vulnerability.nvd_checked_at < now - dt.timedelta(hours=settings.nvd_ttl_hours))
        )
        .order_by(Vulnerability.nvd_checked_at.asc().nulls_first(), Vulnerability.id)
        .limit(settings.nvd_refresh_limit)
    ).all()
    counts = {"fetched": 0, "scored": 0, "unscored": 0, "errors": 0}
    api_key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None
    for index, cve in enumerate(stale):
        if index:
            sleep(min_interval)
        try:
            found = fetch_nvd(client, cve, api_key)
        except OutboundError as exc:
            log.warning("nvd_unavailable", cve=cve, error=str(exc))
            counts["errors"] += 1
            break
        counts["fetched"] += 1
        values: dict[str, Any] = {"nvd_checked_at": now}
        if found is not None:
            sub = subscores(found.vector)
            values |= {
                "cvss_version": found.version,
                "cvss_vector": found.vector,
                "cvss_base": found.base,
                "cvss_source": "nvd",
                "cvss_impact": Decimal(str(sub.impact)) if sub else None,
                "cvss_exploitability": Decimal(str(sub.exploitability)) if sub else None,
            }
            counts["scored"] += 1
        else:
            counts["unscored"] += 1
        session.execute(update(Vulnerability).where(Vulnerability.id == cve).values(**values))
    session.flush()
    log.info("nvd_refresh", **counts)
    return counts


def persist_assets(session: Session, scan_id: uuid.UUID, assets: Sequence[IacAsset]) -> int:
    """Replace the scan's environment assets. One row per (kind, name); a repeat is dropped
    rather than failing the scan, because the same name can appear in two files."""
    session.execute(delete(Asset).where(Asset.scan_job_id == scan_id))
    seen: set[tuple[str, str]] = set()
    written = 0
    for a in assets:
        key = (a.kind, a.name)
        if key in seen:
            continue
        seen.add(key)
        session.add(
            Asset(
                id=uuid.uuid4(),
                scan_job_id=scan_id,
                kind=a.kind,
                name=a.name,
                source_path=a.source_path,
                attrs=dict(a.attrs),
            )
        )
        written += 1
    session.flush()
    return written


def list_assets(session: Session, scan_id: uuid.UUID) -> list[Asset]:
    return list(
        session.scalars(
            select(Asset).where(Asset.scan_job_id == scan_id).order_by(Asset.kind, Asset.name)
        )
    )
