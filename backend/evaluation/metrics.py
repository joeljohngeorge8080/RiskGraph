"""Ranking metrics (blueprint §26.4) and bootstrap confidence intervals (§26.5).

Every metric takes ``rel``: the binary labels of a ranking, best-ranked first. Metrics
that divide by the number of important findings return ``None`` when there are none,
instead of a misleading 0 or 1.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass

BOOTSTRAP_RESAMPLES = 2_000
BOOTSTRAP_SEED = 20261025


def precision_at(rel: Sequence[bool], k: int) -> float:
    """Important findings in the top ``k``, over ``k`` (a short list still divides by k)."""
    if k <= 0:
        raise ValueError("k must be positive")
    return sum(rel[:k]) / k


def recall_at(rel: Sequence[bool], k: int) -> float | None:
    total = sum(rel)
    return sum(rel[:k]) / total if total else None


def ndcg_at(rel: Sequence[bool], k: int) -> float | None:
    """Binary-gain nDCG: DCG = sum(rel_i / log2(i + 1)) over ranks i = 1..k."""
    ideal = _dcg(sorted(rel, reverse=True)[:k])
    return _dcg(rel[:k]) / ideal if ideal else None


def _dcg(rel: Sequence[bool]) -> float:
    return sum(1 / math.log2(i + 2) for i, r in enumerate(rel) if r)


def average_precision(rel: Sequence[bool]) -> float | None:
    """Mean of precision@rank over the ranks of the important findings."""
    hits, total = 0, 0.0
    for i, r in enumerate(rel, start=1):
        if r:
            hits += 1
            total += hits / i
    return total / hits if hits else None


def effort_at(rel: Sequence[bool], recall: float = 0.9) -> int | None:
    """E90: findings read, from the top, until ``recall`` of the important ones are seen."""
    total = sum(rel)
    if not total:
        return None
    needed = math.ceil(recall * total - 1e-9)
    hits = 0
    for i, r in enumerate(rel, start=1):
        hits += r
        if hits >= needed:
            return i
    raise AssertionError("unreachable: every important finding is in the ranking")


@dataclass(frozen=True, slots=True)
class Estimate:
    value: float | None
    low: float | None  # 95 % percentile bootstrap interval
    high: float | None
    undefined: int  # resamples where the metric had no value (no important finding)


def bootstrap[T](
    items: Sequence[T],
    statistic: Callable[[Sequence[T]], float | None],
    *,
    resamples: int = BOOTSTRAP_RESAMPLES,
    seed: int = BOOTSTRAP_SEED,
) -> Estimate:
    """Percentile CI over items resampled with replacement; the same seed gives the same
    resamples for every statistic, so methods are compared on identical draws."""
    rng = random.Random(seed)  # noqa: S311 - seeded resampling, not cryptography
    n = len(items)
    values: list[float] = []
    undefined = 0
    for _ in range(resamples):
        v = statistic([items[rng.randrange(n)] for _ in range(n)])
        if v is None:
            undefined += 1
        else:
            values.append(v)
    point = statistic(items)
    if not values:
        return Estimate(point, None, None, undefined)
    values.sort()
    return Estimate(point, _percentile(values, 0.025), _percentile(values, 0.975), undefined)


def _percentile(sorted_values: Sequence[float], q: float) -> float:
    """Linear interpolation between closest ranks (numpy's default method)."""
    pos = q * (len(sorted_values) - 1)
    lo = math.floor(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)
