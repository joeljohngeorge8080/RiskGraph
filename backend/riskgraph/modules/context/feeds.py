"""EPSS (FIRST) and KEV (CISA) feed clients. Failures raise ``OutboundError``; the
caller records the factor as unavailable and the scan carries on."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from riskgraph.shared.http import OutboundClient, OutboundError

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # CISA's official GitHub mirror of the same catalogue.
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
EPSS_BATCH = 100


@dataclass(frozen=True, slots=True)
class EpssScore:
    epss: Decimal
    percentile: Decimal | None
    date: dt.date | None


def _decimal(value: Any) -> Decimal | None:
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return d if Decimal(0) <= d <= Decimal(1) else None


def _date(value: Any) -> dt.date | None:
    try:
        return dt.date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def fetch_epss(client: OutboundClient, cve_ids: Iterable[str]) -> dict[str, EpssScore]:
    ids = sorted({c for c in cve_ids if c.startswith("CVE-")})
    out: dict[str, EpssScore] = {}
    for i in range(0, len(ids), EPSS_BATCH):
        batch = ids[i : i + EPSS_BATCH]
        body = client.get_json(EPSS_URL, params={"cve": ",".join(batch)})
        rows = body.get("data") if isinstance(body, dict) else None
        if not isinstance(rows, list):
            raise OutboundError("EPSS response has no data list")
        for row in rows:
            if not isinstance(row, dict) or row.get("cve") not in batch:
                continue
            epss = _decimal(row.get("epss"))
            if epss is not None:
                out[row["cve"]] = EpssScore(
                    epss, _decimal(row.get("percentile")), _date(row.get("date"))
                )
    return out


def fetch_kev(client: OutboundClient) -> dict[str, str]:
    """CVE id → dateAdded (ISO) for the whole KEV catalogue; tries each source in order."""
    errors: list[str] = []
    for url in KEV_URLS:
        try:
            body = client.get_json(url)
        except OutboundError as exc:
            errors.append(str(exc))
            continue
        rows = body.get("vulnerabilities") if isinstance(body, dict) else None
        if isinstance(rows, list) and rows:
            return _kev_index(rows)
        errors.append(f"{url}: no vulnerabilities list")
    raise OutboundError("; ".join(errors))


def _kev_index(rows: list[Any]) -> dict[str, str]:
    return {
        str(r["cveID"]): str(r.get("dateAdded", ""))
        for r in rows
        if isinstance(r, dict) and str(r.get("cveID", "")).startswith("CVE-")
    }
