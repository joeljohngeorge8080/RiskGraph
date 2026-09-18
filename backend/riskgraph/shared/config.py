"""Application settings.

Every process (api, worker, beat, cli) loads exactly one ``Settings`` instance from
environment variables prefixed ``RISKGRAPH_``. Validation failures raise at startup on
purpose: a misconfigured security product must not come up half-working.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["dev", "test", "prod"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RISKGRAPH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    env: Environment = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = True

    database_url: str = Field(description="postgresql+psycopg://user:pass@host:5432/db")
    redis_url: str = Field(description="redis://:password@host:6379/0")

    secret_key: SecretStr = Field(description="≥32 random chars; signs JWTs (Phase 2)")

    cors_origins: list[str] = ["http://localhost:5173"]
    api_docs_enabled: bool = True

    @field_validator("database_url")
    @classmethod
    def _postgres_only(cls, value: str) -> str:
        if not value.startswith("postgresql+psycopg://"):
            raise ValueError("database_url must use the postgresql+psycopg:// scheme")
        return value

    @field_validator("redis_url")
    @classmethod
    def _redis_only(cls, value: str) -> str:
        if not value.startswith(("redis://", "rediss://")):
            raise ValueError("redis_url must use the redis:// or rediss:// scheme")
        return value

    @field_validator("secret_key")
    @classmethod
    def _secret_long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 32:
            raise ValueError("secret_key must be at least 32 characters")
        return value

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton. Tests call ``get_settings.cache_clear()``."""
    return Settings()  # values come from the environment
