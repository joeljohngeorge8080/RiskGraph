"""Scan and scanner-run state machines (blueprint §9.1, MVP subset: no CANCELLED)."""

from __future__ import annotations

from collections.abc import Iterable

from riskgraph.shared.vocabulary import RunStatus, ScanStatus

_CANCEL = frozenset({ScanStatus.CANCELLED})
SCAN_TRANSITIONS: dict[ScanStatus, frozenset[ScanStatus]] = {
    ScanStatus.PENDING: frozenset({ScanStatus.QUEUED, ScanStatus.FAILED}) | _CANCEL,
    ScanStatus.QUEUED: frozenset({ScanStatus.CLONING, ScanStatus.FAILED}) | _CANCEL,
    ScanStatus.CLONING: frozenset({ScanStatus.SCANNING, ScanStatus.FAILED}) | _CANCEL,
    ScanStatus.SCANNING: frozenset({ScanStatus.ANALYZING, ScanStatus.FAILED}) | _CANCEL,
    ScanStatus.ANALYZING: frozenset({ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED}),
}
RUN_TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
    RunStatus.QUEUED: frozenset({RunStatus.RUNNING, RunStatus.SKIPPED, RunStatus.FAILED}),
    RunStatus.RUNNING: frozenset({RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.TIMED_OUT}),
    # collect may reject an unreadable report after the run itself succeeded
    RunStatus.SUCCEEDED: frozenset({RunStatus.FAILED}),
}


class InvalidTransitionError(ValueError):
    pass


def check_scan(from_: ScanStatus, to: ScanStatus) -> None:
    if to not in SCAN_TRANSITIONS.get(from_, frozenset()):
        raise InvalidTransitionError(f"scan {from_} -> {to}")


def check_run(from_: RunStatus, to: RunStatus) -> None:
    if to not in RUN_TRANSITIONS.get(from_, frozenset()):
        raise InvalidTransitionError(f"run {from_} -> {to}")


def final_status(run_statuses: Iterable[RunStatus]) -> tuple[ScanStatus, str | None]:
    statuses = list(run_statuses)
    ok = sum(1 for s in statuses if s is RunStatus.SUCCEEDED)
    if ok == 0:
        return ScanStatus.FAILED, "all scanners failed"
    bad = len(statuses) - ok
    if bad:
        return ScanStatus.PARTIAL, f"{bad} of {len(statuses)} scanners did not succeed"
    return ScanStatus.COMPLETED, None
