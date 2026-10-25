"""Ranking methods compared in the evaluation (blueprint §26.2).

- M1 CVSS-only: CVSS base, descending. A finding without a CVSS base (SAST, secrets,
  IaC, or a CVE the scanner gave no vector) gets a fixed CVSS-equivalent of its
  canonical severity, so it is rankable.
- M2 CVSS + EPSS: ``cvss_norm * E``, with ``E`` RiskGraph's own EPSS transform
  (``epss_to_e``, shared by design so the comparison isolates context). Findings with no
  EPSS (non-CVE, or a CVE EPSS has not scored) get E = 0.5, the transform's value for
  EPSS 1 %, i.e. "unknown, neither likely nor unlikely".
- M4 RiskGraph: the order the product shows (priority rank, then score).

Ties break on the finding fingerprint (``findings.merge_key``), a hash that favours no
method. The blueprint says "scanner order", which depends on report layout; the
fingerprint is equally neutral and stable across runs.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol

from riskgraph.modules.risk import epss_to_e

CVSS_EQUIVALENT = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
E_UNKNOWN = 0.5


class Rankable(Protocol):
    @property
    def fingerprint(self) -> str: ...
    @property
    def severity(self) -> str: ...
    @property
    def cvss_base(self) -> float | None: ...
    @property
    def epss(self) -> float | None: ...
    @property
    def score(self) -> float: ...
    @property
    def priority_rank(self) -> int: ...


def cvss_equivalent(f: Rankable) -> float:
    return f.cvss_base if f.cvss_base is not None else CVSS_EQUIVALENT[f.severity]


def m1_key(f: Rankable) -> tuple[float, str]:
    return (-cvss_equivalent(f), f.fingerprint)


def m2_key(f: Rankable) -> tuple[float, str]:
    e = epss_to_e(f.epss) if f.epss is not None else E_UNKNOWN
    return (-(cvss_equivalent(f) / 10) * e, f.fingerprint)


def m4_key(f: Rankable) -> tuple[float, float, str]:
    return (-f.priority_rank, -f.score, f.fingerprint)


METHODS: dict[str, Callable[[Rankable], tuple[float | str, ...]]] = {
    "M1 CVSS-only": m1_key,
    "M2 CVSS+EPSS": m2_key,
    "M4 RiskGraph": m4_key,
}


def rank[R: Rankable](findings: Sequence[R], method: str) -> list[R]:
    return sorted(findings, key=METHODS[method])
