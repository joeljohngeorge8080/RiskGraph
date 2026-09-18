from __future__ import annotations

import pytest
from pydantic import ValidationError
from riskgraph.shared.config import Settings


def _base(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "env": "dev",
        "database_url": "postgresql+psycopg://u:p@h:5432/d",
        "redis_url": "redis://:p@h:6379/0",
        "secret_key": "x" * 32,
    }
    values.update(overrides)
    return values


def test_valid_settings_parse() -> None:
    s = Settings(_env_file=None, **_base())  # type: ignore[arg-type]
    assert s.env == "dev"
    assert s.is_prod is False
    assert "x" * 32 not in repr(s)  # SecretStr never leaks into repr/logs


def test_short_secret_rejected() -> None:
    with pytest.raises(ValidationError, match="at least 32"):
        Settings(_env_file=None, **_base(secret_key="short"))  # type: ignore[arg-type]


@pytest.mark.parametrize("url", ["postgresql://u:p@h/d", "mysql+pymysql://x", "sqlite:///x.db"])
def test_non_psycopg_database_url_rejected(url: str) -> None:
    with pytest.raises(ValidationError, match="postgresql\\+psycopg"):
        Settings(_env_file=None, **_base(database_url=url))  # type: ignore[arg-type]


def test_bad_redis_url_rejected() -> None:
    with pytest.raises(ValidationError, match="redis://"):
        Settings(_env_file=None, **_base(redis_url="http://h:6379"))  # type: ignore[arg-type]


def test_missing_required_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("RISKGRAPH_DATABASE_URL", "RISKGRAPH_REDIS_URL", "RISKGRAPH_SECRET_KEY"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
