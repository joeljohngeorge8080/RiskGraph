from __future__ import annotations

import itertools

import pytest
from riskgraph.modules.scans.state import (
    InvalidTransitionError,
    check_run,
    check_scan,
    final_status,
)
from riskgraph.shared.vocabulary import RunStatus as R
from riskgraph.shared.vocabulary import ScanStatus as S


def test_happy_path_is_allowed() -> None:
    path = [S.PENDING, S.QUEUED, S.CLONING, S.SCANNING, S.ANALYZING, S.COMPLETED]
    for a, b in itertools.pairwise(path):
        check_scan(a, b)


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (S.COMPLETED, S.SCANNING),
        (S.FAILED, S.QUEUED),
        (S.PENDING, S.SCANNING),
        (S.QUEUED, S.ANALYZING),
    ],
)
def test_illegal_scan_transitions(a: S, b: S) -> None:
    with pytest.raises(InvalidTransitionError):
        check_scan(a, b)


def test_every_active_state_can_fail() -> None:
    for state in (S.PENDING, S.QUEUED, S.CLONING, S.SCANNING, S.ANALYZING):
        check_scan(state, S.FAILED)


def test_run_transitions() -> None:
    check_run(R.QUEUED, R.RUNNING)
    check_run(R.RUNNING, R.TIMED_OUT)
    with pytest.raises(InvalidTransitionError):
        check_run(R.SUCCEEDED, R.RUNNING)


def test_final_status() -> None:
    assert final_status([R.SUCCEEDED] * 4) == (S.COMPLETED, None)
    status, reason = final_status([R.SUCCEEDED, R.FAILED, R.SUCCEEDED, R.TIMED_OUT])
    assert status is S.PARTIAL and reason == "2 of 4 scanners did not succeed"
    assert final_status([R.FAILED, R.SKIPPED])[0] is S.FAILED
