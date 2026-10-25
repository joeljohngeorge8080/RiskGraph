"""Application settings.

Every process (api, worker, beat, cli) loads exactly one ``Settings`` instance from
environment variables prefixed ``RISKGRAPH_``. Validation failures raise at startup on
purpose: a misconfigured security product must not come up half-working.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
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
    nvd_ttl_hours: int = 168
    # NVD is refreshed by Beat, never on the scan path (its rate limit is 5 requests per
    # 30 s without a key). Scans use cached NVD data and fall back to scanner CVSS.
    nvd_api_key: SecretStr | None = None
    nvd_refresh_limit: int = 200
    timeout_syft_s: int = 300
    timeout_trivy_db_s: int = 900

    # --- scanner containers (P3, ADR-0014) --------------------------------------------
    # "subprocess" is the MVP runner (host tools, dev only); "docker" runs every scanner
    # as a hardened container through docker-socket-proxy (DOCKER_HOST) and is required
    # for any deployment beyond localhost.
    scanner_runner: Literal["subprocess", "docker"] = "subprocess"
    # Host directories that back data_dir and trivy_cache_dir. The daemon binds host
    # paths, not the worker's, so the worker needs the mapping (docker runner only).
    host_data_dir: Path | None = None
    host_trivy_cache_dir: Path | None = None
    scanner_egress_network: str = "riskgraph_egress"
    scanner_max_slots: int = 4
    scanner_slot_lease_s: int = 3600
    scanner_slot_wait_s: int = 600

    # --- AI explanation (P12, blueprint §15) ------------------------------------------
    # "ollama" uses a local model; "none" always uses the deterministic template. When the
    # model is unreachable, explanations fall back to the template, never fail.
    llm_provider: Literal["none", "ollama"] = "ollama"
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen3:4b"
    ollama_timeout_s: float = 60.0
    explain_top_n: int = Field(default=10, ge=0, le=100)  # Critical findings per scan; 0 = off

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

    @model_validator(mode="after")
    def _docker_needs_host_paths(self) -> Settings:
        if self.scanner_runner == "docker":
            for name, value in (
                ("RISKGRAPH_HOST_DATA_DIR", self.host_data_dir),
                ("RISKGRAPH_HOST_TRIVY_CACHE_DIR", self.host_trivy_cache_dir),
            ):
                if value is None or not value.is_absolute():
                    raise ValueError(f"{name} must be an absolute host path for the docker runner")
        return self

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
