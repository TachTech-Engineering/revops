"""
Generic Webhook Ingest Buffer

Durable staging for events pushed to per-connector ingest webhooks
(POST /api/v1/ingest/{connector_type}/{connector_id}). Push-based connectors
drain these on their normal sync cycle, so persistence, dedup, and correlation
all reuse the standard connector sync path.

Generic sibling of falco_event_buffer (which predates it and keeps its own
table). Delivery is at-least-once with the same claim semantics: a drain
*claims* rows rather than deleting them, and a claim older than
``CLAIM_STALE_MINUTES`` is re-claimable, so a sync that crashes between
claiming and inserting recovers on the next tick. Re-processing is harmless
because push connectors build ``external_id`` from a content fingerprint, so a
repeat collides with ``uq_normalized_alerts_org_connector_external``.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, delete, func, or_, select, update

from app.core.time_utils import utcnow
from app.db.models import IngestEvent

logger = logging.getLogger(__name__)

# Per-connector cap on unclaimed events. A burst beyond this is dropped at the
# door (with a warning) rather than growing the table without bound.
MAX_EVENTS_PER_CONNECTOR = 10_000

# A claimed row this old is assumed to belong to a sync that died before
# inserting, and becomes re-claimable.
CLAIM_STALE_MINUTES = 15

# Claimed rows are kept this long for debugging, then reaped.
RETAIN_CLAIMED_HOURS = 24


@dataclass
class BufferedEvent:
    """A single event as received on a webhook."""

    payload: dict[str, Any]
    received_at: datetime


async def push_events(
    db,
    connector_id: UUID,
    organization_id: UUID,
    connector_type: str,
    events: list[dict[str, Any]],
) -> int:
    """Persist webhook events for a connector. Returns the number accepted.

    Caller supplies the session so the write joins the request's transaction.
    """
    pending = await count_pending(db, connector_id)
    capacity = MAX_EVENTS_PER_CONNECTOR - pending
    if capacity <= 0:
        logger.warning(
            "Ingest buffer for connector %s is full (%s pending); dropping %s events",
            connector_id,
            pending,
            len(events),
        )
        return 0

    accepted = events[:capacity]
    if len(accepted) < len(events):
        logger.warning(
            "Ingest buffer for connector %s near capacity; dropped %s of %s events",
            connector_id,
            len(events) - len(accepted),
            len(events),
        )

    now = utcnow()
    db.add_all(
        [
            IngestEvent(
                organization_id=organization_id,
                connector_id=connector_id,
                connector_type=connector_type,
                payload=event,
                received_at=now,
            )
            for event in accepted
        ]
    )
    await db.flush()
    return len(accepted)


def _unclaimed_or_stale():
    """Rows eligible to be claimed: never claimed, or claimed by a dead sync."""
    stale_before = utcnow() - timedelta(minutes=CLAIM_STALE_MINUTES)
    return or_(
        IngestEvent.claimed_at.is_(None),
        IngestEvent.claimed_at < stale_before,
    )


async def count_pending(db, connector_id: UUID) -> int:
    """Events for a connector still awaiting a successful sync."""
    result = await db.execute(
        select(func.count())
        .select_from(IngestEvent)
        .where(
            and_(
                IngestEvent.connector_id == connector_id,
                _unclaimed_or_stale(),
            )
        )
    )
    return result.scalar() or 0


async def claim_events(db, connector_id: UUID, limit: int = 100) -> list[BufferedEvent]:
    """Claim up to ``limit`` pending events for a connector.

    Uses SKIP LOCKED so concurrent syncs on different replicas take disjoint
    rows instead of blocking or double-processing.
    """
    candidate_ids = (
        select(IngestEvent.id)
        .where(
            and_(
                IngestEvent.connector_id == connector_id,
                _unclaimed_or_stale(),
            )
        )
        .order_by(IngestEvent.received_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )

    result = await db.execute(
        update(IngestEvent)
        .where(IngestEvent.id.in_(candidate_ids))
        .values(claimed_at=utcnow())
        .returning(IngestEvent.payload, IngestEvent.received_at)
    )
    rows = result.all()
    return [BufferedEvent(payload=row[0], received_at=row[1]) for row in rows]


async def purge_processed(db, older_than_hours: int = RETAIN_CLAIMED_HOURS) -> int:
    """Delete claimed rows past the retention window."""
    cutoff = utcnow() - timedelta(hours=older_than_hours)
    result = await db.execute(
        delete(IngestEvent).where(
            and_(
                IngestEvent.claimed_at.is_not(None),
                IngestEvent.claimed_at < cutoff,
            )
        )
    )
    return result.rowcount or 0
