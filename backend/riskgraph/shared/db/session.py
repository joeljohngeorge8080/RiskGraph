"""Engine and session management (synchronous, ADR-0008)."""

from __future__ import annotations

from collections.abc import Generator, Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from riskgraph.shared.config import get_settings


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    settings = get_settings()
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        connect_args={"connect_timeout": 5},
        future=True,
    )


@lru_cache(maxsize=1)
def _session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def dispose_engine() -> None:
    """Drop pooled connections (used by tests and at worker shutdown)."""
    if get_engine.cache_info().currsize:
        get_engine().dispose()
    get_engine.cache_clear()
    _session_factory.cache_clear()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Unit-of-work for services and tasks: commit on success, rollback on error."""
    session = _session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency. Routers pass the session to services; they do not query."""
    with session_scope() as session:
        yield session


def check_database() -> None:
    """Raise if the database is unreachable. Used by readiness."""
    with get_engine().connect() as conn:
        conn.execute(text("SELECT 1"))
