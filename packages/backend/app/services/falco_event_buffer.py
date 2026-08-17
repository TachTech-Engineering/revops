"""
Falco Event Buffer

Durable staging for Falco alerts pushed to the ingest webhook
(POST /api/v1/ingest/falco/{connector_id}). The Falco connector drains these on
its normal sync cycle, so persistence, dedup, and correlation all reuse the
standard connector sync path.

This was an in-process deque. The ingest endpoint answers 202 Accepted
immediately, so with multiple replicas any pod restart between the webhook call
and the next sync tick silently discarded alerts the caller had been told were
accepted -- the same class of bug as password-reset tokens living in a module
dict. Events are now rows in ``falco_ingest_events``.

Delivery is at-least-once: a drain *claims* rows rather than deleting them, and
a claim older than ``CLAIM_STALE_MINUTES`` is re-claimable, so a sync that
crashes between claiming and inserting recovers on the next tick instead of
losing the events. Re-processing is harmless because the Falco connector builds
``external_id`` from a content fingerprint, so a repeat collides with
``uq_normalized_alerts_org_connector_external``.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, delete, func, or_, select, update

from app.core.time_utils import utcnow
from app.db.models import FalcoIngestEvent

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
class FalcoEvent:
    """A single Falco alert as received on the webhook."""

    payload: dict[str, Any]
    received_at: datetime


async def push_events(
    db,
    connector_id: UUID,
    organization_id: UUID,
    events: list[dict[str, Any]],
) -> int:
    """Persist webhook events for a connector. Returns the number accepted.

    Caller supplies the session so the write joins the request's transaction.
    """
    pending = await count_pending(db, connector_id)
    capacity = MAX_EVENTS_PER_CONNECTOR - pending
    if capacity <= 0:
        logger.warning(
            "Falco buffer for connector %s is full (%s pending); dropping %s events",
            connector_id,
            pending,
            len(events),
        )
        return 0

    accepted = events[:capacity]
    if len(accepted) < len(events):
        logger.warning(
            "Falco buffer for connector %s near capacity; dropped %s of %s events",
            connector_id,
            len(events) - len(accepted),
            len(events),
        )

    now = utcnow()
    db.add_all(
        [
            FalcoIngestEvent(
                organization_id=organization_id,
                connector_id=connector_id,
                payload=event,
                received_at=now,
            )
            for event in accepted
        ]
    )
    await db.flush()
    return len(accepted)


async def count_pending(db, connector_id: UUID) -> int:
    """Events for a connector still awaiting a successful sync."""
    result = await db.execute(
        select(func.count())
        .select_from(FalcoIngestEvent)
        .where(
            and_(
                FalcoIngestEvent.connector_id == connector_id,
                _unclaimed_or_stale(),
            )
        )
    )
    return result.scalar() or 0


def _unclaimed_or_stale():
    """Rows eligible to be claimed: never claimed, or claimed by a dead sync."""
    stale_before = utcnow() - timedelta(minutes=CLAIM_STALE_MINUTES)
    return or_(
        FalcoIngestEvent.claimed_at.is_(None),
        FalcoIngestEvent.claimed_at < stale_before,
    )


async def claim_events(db, connector_id: UUID, limit: int = 100) -> list[FalcoEvent]:
    """Claim up to ``limit`` pending events for a connector.

    Uses SKIP LOCKED so concurrent syncs on different replicas take disjoint
    rows instead of blocking or double-processing.
    """
    candidate_ids = (
        select(FalcoIngestEvent.id)
        .where(
            and_(
                FalcoIngestEvent.connector_id == connector_id,
                _unclaimed_or_stale(),
            )
        )
        .order_by(FalcoIngestEvent.received_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )

    result = await db.execute(
        update(FalcoIngestEvent)
        .where(FalcoIngestEvent.id.in_(candidate_ids))
        .values(claimed_at=utcnow())
        .returning(FalcoIngestEvent.payload, FalcoIngestEvent.received_at)
    )
    rows = result.all()
    return [FalcoEvent(payload=row[0], received_at=row[1]) for row in rows]


async def purge_processed(db, older_than_hours: int = RETAIN_CLAIMED_HOURS) -> int:
    """Delete claimed rows past the retention window."""
    cutoff = utcnow() - timedelta(hours=older_than_hours)
    result = await db.execute(
        delete(FalcoIngestEvent).where(
            and_(
                FalcoIngestEvent.claimed_at.is_not(None),
                FalcoIngestEvent.claimed_at < cutoff,
            )
        )
    )
    return result.rowcount or 0
