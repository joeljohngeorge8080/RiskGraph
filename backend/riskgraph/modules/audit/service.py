"""Record audit entries inside the caller's transaction."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from riskgraph.modules.audit.models import AuditLog

LOCAL_ACTOR = "local"  # no authentication yet (ADR-0010)


def record(
    session: Session,
    *,
    action: str,
    entity: str,
    entity_id: uuid.UUID,
    before: dict[str, Any],
    after: dict[str, Any],
    reason: str | None = None,
    actor: str = LOCAL_ACTOR,
) -> AuditLog:
    entry = AuditLog(
        at=dt.datetime.now(dt.UTC),
        actor=actor,
        action=action,
        entity=entity,
        entity_id=entity_id,
        before=before,
        after=after,
        reason=reason,
    )
    session.add(entry)
    return entry


def history(session: Session, entity: str, entity_id: uuid.UUID, limit: int = 20) -> list[AuditLog]:
    return list(
        session.scalars(
            select(AuditLog)
            .where(AuditLog.entity == entity, AuditLog.entity_id == entity_id)
            .order_by(AuditLog.at.desc())
            .limit(limit)
        )
    )
