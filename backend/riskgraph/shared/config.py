"""Application settings.

Every process (api, worker, beat, cli) loads exactly one ``Settings`` instance from
environment variables prefixed ``RISKGRAPH_``. Validation failures raise at startup on
purpose: a misconfigured security product must not come up half-working.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
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

    # --- scanning (MVP, ADR-0009) ----------------------------------------------------
    data_dir: Path = Field(
        default=Path("/var/lib/riskgraph"),
        description="Holds workspaces/<scan_id>/ and scan_output/<scan_id>/",
    )
    scanner_bin_dir: Path = Path("/opt/scanners/bin")
    semgrep_rules_path: Path = Path("/opt/scanners/semgrep-rules")
    trivy_cache_dir: Path = Path("/var/cache/riskgraph/trivy")
    timeout_trivy_s: int = 600
    timeout_semgrep_s: int = 900
    timeout_checkov_s: int = 600
    timeout_gitleaks_s: int = 300
    clone_timeout_s: int = 180
    clone_max_bytes: int = 500 * 1024 * 1024
    clone_max_files: int = 100_000
    raw_report_max_bytes: int = 50 * 1024 * 1024
    max_active_scans: int = 3
    keep_workspaces: bool = False
    enrichment_enabled: bool = True
    epss_ttl_hours: int = 24
    kev_ttl_hours: int = 12

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

    @property
    def workspace_root(self) -> Path:
        return self.data_dir / "workspaces"

    @property
    def scan_output_root(self) -> Path:
        return self.data_dir / "scan_output"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton. Tests call ``get_settings.cache_clear()``."""
    return Settings()  # values come from the environment
