"""Alembic environment: URL from settings, metadata from ``riskgraph.shared.db.Base``.

Every ``modules/<x>/models.py`` is imported here so autogenerate sees all tables.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from riskgraph.modules.audit import models as _audit_models  # noqa: F401
from riskgraph.modules.context import models as _context_models  # noqa: F401
from riskgraph.modules.findings import models as _findings_models  # noqa: F401
from riskgraph.modules.graph import models as _graph_models  # noqa: F401
from riskgraph.modules.reachability import models as _reachability_models  # noqa: F401
from riskgraph.modules.repositories import models as _repositories_models  # noqa: F401
from riskgraph.modules.risk import models as _risk_models  # noqa: F401
from riskgraph.modules.scans import models as _scans_models  # noqa: F401
from riskgraph.shared.config import get_settings
from riskgraph.shared.db import Base
from sqlalchemy import engine_from_config, pool

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", get_settings().database_url)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
