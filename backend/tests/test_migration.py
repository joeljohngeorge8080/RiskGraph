from __future__ import annotations

import pytest
from riskgraph.shared.db import get_engine
from sqlalchemy import inspect

from tests.conftest import _alembic

pytestmark = pytest.mark.db


def test_migration_round_trip(db: None) -> None:
    # Empty tables: the round trip checks the schema. Downgrades that would lose data
    # (L3 rows, c4f0a7e2d913) refuse on purpose; that is not what this test is about.
    _alembic("downgrade", "base")
    assert "findings" not in inspect(get_engine()).get_table_names()
    _alembic("upgrade", "head")
    tables = set(inspect(get_engine()).get_table_names())
    assert {"repositories", "scan_jobs", "scanner_runs", "findings", "risk_factors"} <= tables
