"""End-of-life data from endoflife.date and the findings it produces (expansion X2).

Pure. The feed is fetched by Beat (``service.refresh_eol``) and stored with its fetch
time; a scan only reads the stored cycles, so it never waits on the network and every
finding carries the date its data was fetched (``data_as_of``).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from riskgraph.modules.normalization import Location, RawFinding
from riskgraph.modules.runtime.declarations import RuntimeDecl
from riskgraph.shared.vocabulary import ScannerName, Severity, SourceType

RUNTIME_ANALYZER = "runtime.1"  # version of RiskGraph's runtime/EOL analysis
PRODUCTS = ("python", "nodejs", "go")
LABELS = {"python": "Python", "nodejs": "Node.js", "go": "Go"}
MAX_CYCLE = 32
FEED_URL = "https://endoflife.date/api/{product}.json"


@dataclass(frozen=True, slots=True)
class EolCycle:
    product: str
    cycle: str
    eol_date: dt.date | None  # when the feed gives a date
    eol_flag: bool | None  # when the feed gives true/false instead
    latest: str | None
    release_date: dt.date | None
    fetched_at: dt.datetime


@dataclass(frozen=True, slots=True)
class EolStatus:
    eol: bool
    eol_date: dt.date | None
    oldest_supported: str | None
    fetched_at: dt.datetime


def _date(value: object) -> dt.date | None:
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value[:10])
        except ValueError:
            return None
    return None


def parse_cycles(product: str, doc: Any, fetched_at: dt.datetime) -> list[EolCycle]:
    """One feed document; malformed entries are skipped, never fatal."""
    out: list[EolCycle] = []
    for item in doc if isinstance(doc, list) else []:
        if not isinstance(item, dict):
            continue
        cycle = item.get("cycle")
        if not isinstance(cycle, str | int) or not str(cycle) or len(str(cycle)) > MAX_CYCLE:
            continue
        eol = item.get("eol")
        latest = item.get("latest")
        out.append(
            EolCycle(
                product=product,
                cycle=str(cycle),
                eol_date=_date(eol),
                eol_flag=eol if isinstance(eol, bool) else None,
                latest=str(latest)[:64] if isinstance(latest, str | int) else None,
                release_date=_date(item.get("releaseDate")),
                fetched_at=fetched_at,
            )
        )
    return out


def _ended(c: EolCycle, today: dt.date) -> bool:
    return (c.eol_date is not None and c.eol_date <= today) or c.eol_flag is True


def _key(cycle: str) -> tuple[int, ...]:
    return tuple(int(p) if p.isdigit() else 0 for p in cycle.split("."))


def eol_status(
    product: str, cycle: str, cycles: Mapping[str, EolCycle], today: dt.date
) -> EolStatus | None:
    found = cycles.get(cycle)
    if found is None:
        return None
    supported = [
        c.cycle
        for c in cycles.values()
        if not _ended(c, today) and (c.release_date is None or c.release_date <= today)
    ]
    return EolStatus(
        eol=_ended(found, today),
        eol_date=found.eol_date,
        oldest_supported=min(supported, key=_key) if supported else None,
        fetched_at=found.fetched_at,
    )


def runtime_findings(
    decls: Iterable[RuntimeDecl],
    feeds: Mapping[str, Mapping[str, EolCycle]],
    today: dt.date,
) -> list[RawFinding]:
    """An EOL finding per exact declaration of a cycle the feed says has ended."""
    out: list[RawFinding] = []
    for d in decls:
        if not d.exact:
            continue
        status = eol_status(d.product, d.cycle, feeds.get(d.product, {}), today)
        if status is None or not status.eol:
            continue
        label = LABELS.get(d.product, d.product)
        since = f" since {status.eol_date.isoformat()}" if status.eol_date else ""
        fix = status.oldest_supported
        out.append(
            RawFinding(
                scanner=ScannerName.RISKGRAPH,
                source_type=SourceType.RUNTIME,
                rule_id=f"runtime-eol:{d.product}:{d.cycle}",
                title=f"{label} {d.cycle} is end-of-life{since}",
                severity=Severity.HIGH,  # no security fixes any more
                location=Location(d.file, d.line),
                category="runtime_eol",
                description=(
                    f"{label} {d.cycle} no longer receives security fixes (endoflife.date). "
                    f"Declared here as {d.version!r} ({d.source})."
                ),
                package={
                    "name": d.product,
                    "version": d.cycle,
                    "fixed_version": fix,
                    "ecosystem": "runtime",
                },
                remediation=(
                    f"Upgrade to {label} {fix} or later, the oldest cycle still supported."
                    if fix
                    else f"Upgrade to a supported {label} release."
                ),
                attrs={
                    "advisory": f"endoflife.date/{d.product}/{d.cycle}",
                    "eol_date": status.eol_date.isoformat() if status.eol_date else None,
                    "declared_by": d.source,
                    "data_as_of": status.fetched_at.isoformat(),
                },
            )
        )
    return out


def os_eol_finding(
    ref: str,
    family: str,
    name: str,
    declared_in: str,
    line: int | None,
    as_of: str | None,
) -> RawFinding:
    """An image whose base OS Trivy marks end-of-support (``Metadata.OS.EOSL``).

    The flag comes from the image report, not from endoflife.date, so ``data_as_of`` is
    the report's creation time. Same producer, severity and interim score as the other
    end-of-life findings (ADR-0018).
    """
    os_label = f"{family} {name}"[:80]
    return RawFinding(
        scanner=ScannerName.RISKGRAPH,
        source_type=SourceType.RUNTIME,
        rule_id=f"runtime-eol:os:{family}:{name}"[:300],
        title=f"Base OS {os_label} of {ref} is end-of-life"[:300],
        severity=Severity.HIGH,  # no security fixes any more
        location=Location(declared_in, line, line, ref),
        category="runtime_eol",
        description=(
            f"The image {ref} is built on {os_label}, which no longer receives security "
            "updates (Trivy's end-of-support flag for the OS)."
        ),
        package={
            "name": family,
            "version": name,
            "fixed_version": None,
            "ecosystem": "os",
            "image": ref,
        },
        remediation="Rebuild on a base image whose OS release is still supported.",
        attrs={
            "advisory": f"trivy/eosl/{family}/{name}"[:200],
            "eol_date": None,
            "declared_by": f"image {ref}"[:200],
            "data_as_of": as_of,
            "image": {"ref": ref, "os": os_label},
        },
    )
