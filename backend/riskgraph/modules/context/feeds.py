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
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_METRICS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40")


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


@dataclass(frozen=True, slots=True)
class NvdCvss:
    version: str
    vector: str
    base: Decimal


def _decimal_score(value: Any) -> Decimal | None:
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return d if Decimal(0) <= d <= Decimal(10) else None


def parse_nvd_cvss(body: Any) -> NvdCvss | None:
    """CVSS from one NVD 2.0 response. Prefers v3.1, then v3.0, then v4.0 (blueprint §11.2).

    Untrusted input: anything not shaped as expected is skipped, never raised.
    """
    vulns = body.get("vulnerabilities") if isinstance(body, dict) else None
    if not isinstance(vulns, list) or not vulns or not isinstance(vulns[0], dict):
        return None
    metrics = (vulns[0].get("cve") or {}).get("metrics")
    if not isinstance(metrics, dict):
        return None
    for key in NVD_METRICS:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        primary = next(
            (e for e in entries if isinstance(e, dict) and e.get("type") == "Primary"),
            entries[0],
        )
        data = primary.get("cvssData") if isinstance(primary, dict) else None
        if not isinstance(data, dict):
            continue
        vector = data.get("vectorString")
        base = _decimal_score(data.get("baseScore"))
        if not isinstance(vector, str) or base is None or len(vector) > 200:
            continue
        return NvdCvss(str(data.get("version") or key[-3:])[:8], vector, base)
    return None


def fetch_nvd(client: OutboundClient, cve_id: str, api_key: str | None = None) -> NvdCvss | None:
    """One CVE per request (NVD 2.0 has no batch lookup). ``None`` when NVD has no score."""
    if not cve_id.startswith("CVE-"):
        return None
    headers = {"apiKey": api_key} if api_key else None
    body = client.get_json(NVD_URL, params={"cveId": cve_id}, headers=headers)
    return parse_nvd_cvss(body)
