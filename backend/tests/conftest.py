"""Test configuration.

Unit tests never need services. Tests marked ``db`` expect the compose test profile
(``make test-services``) or CI service containers on localhost.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

# Defaults must be in place before any riskgraph import reads settings.
os.environ.setdefault("RISKGRAPH_ENV", "test")
os.environ.setdefault("RISKGRAPH_LOG_JSON", "false")
os.environ.setdefault(
    "RISKGRAPH_DATABASE_URL",
    "postgresql+psycopg://riskgraph:riskgraph@localhost:5432/riskgraph_test",
)
os.environ.setdefault("RISKGRAPH_REDIS_URL", "redis://:riskgraph@localhost:6379/1")
os.environ.setdefault("RISKGRAPH_SECRET_KEY", "test-secret-key-do-not-use-in-production!!")

from riskgraph.entrypoints.api import create_app
from riskgraph.shared.config import Settings, get_settings
from riskgraph.shared.db import dispose_engine


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
