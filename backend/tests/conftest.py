"""Test configuration.

Unit tests never need services. Tests marked ``db`` expect the compose test profile
(``make test-services``) or CI service containers on localhost.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Defaults must be in place before any riskgraph import reads settings.
os.environ.setdefault("RISKGRAPH_ENV", "test")
os.environ.setdefault("RISKGRAPH_LLM_PROVIDER", "none")  # tests never call a real model
os.environ.setdefault("RISKGRAPH_LOG_JSON", "false")
os.environ.setdefault(
    "RISKGRAPH_DATABASE_URL",
    "postgresql+psycopg://riskgraph:riskgraph@localhost:5432/riskgraph_test",
)
os.environ.setdefault("RISKGRAPH_REDIS_URL", "redis://:riskgraph@localhost:6379/1")
os.environ.setdefault("RISKGRAPH_SECRET_KEY", "test-secret-key-do-not-use-in-production!!")
_TEST_DATA_DIR = tempfile.mkdtemp(prefix="riskgraph-test-")
os.environ.setdefault("RISKGRAPH_DATA_DIR", _TEST_DATA_DIR)
# The default (/var/cache/riskgraph/trivy) is only writable inside the worker image.
_TEST_TRIVY_DIR = tempfile.mkdtemp(prefix="riskgraph-test-trivy-")
os.environ.setdefault("RISKGRAPH_TRIVY_CACHE_DIR", _TEST_TRIVY_DIR)
# Scans write a lot (clones, reports). Remove this run's temp trees when the run ends.
atexit.register(shutil.rmtree, _TEST_DATA_DIR, True)
atexit.register(shutil.rmtree, _TEST_TRIVY_DIR, True)
os.environ.setdefault("RISKGRAPH_ENRICHMENT_ENABLED", "false")

from riskgraph.entrypoints.api import create_app  # noqa: E402 - after environment defaults
from riskgraph.shared.config import (  # noqa: E402 - after environment defaults
    Settings,
    get_settings,
)
from riskgraph.shared.db import (  # noqa: E402 - after environment defaults
    dispose_engine,
    get_engine,
)
from sqlalchemy import text  # noqa: E402 - after environment defaults

BACKEND_DIR = Path(__file__).resolve().parent.parent
TABLES = (
    "edge_evidence",
    "finding_evidence",
    "evidence",
    "ai_explanations",
    "assets",
    "sbom_components",
    "audit_logs",
    "attack_path_findings",
    "attack_paths",
    "graph_edges",
    "graph_nodes",
    "reachability_results",
    "risk_factors",
    "risk_scores",
    "scan_findings",
    "finding_occurrences",
    "findings",
    "scanner_runs",
    "scan_jobs",
    "repositories",
    "vulnerabilities",
)


@pytest.fixture()
def settings() -> Settings:
    get_settings.cache_clear()
    return get_settings()


@pytest.fixture()
def client(settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    dispose_engine()


def _alembic(*args: str) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    getattr(command, args[0])(cfg, *args[1:])


@pytest.fixture(scope="session")
def migrated_db() -> Iterator[None]:
    """Schema at head for ``db`` tests (the test database is dedicated to tests)."""
    get_settings.cache_clear()
    _alembic("upgrade", "head")
    yield
    dispose_engine()


@pytest.fixture()
def db(migrated_db: None) -> Iterator[None]:
    """Empty tables before each test; tests then use session_scope()/the API."""
    with get_engine().begin() as conn:
        conn.execute(text(f"TRUNCATE {', '.join(TABLES)} CASCADE"))
    yield
