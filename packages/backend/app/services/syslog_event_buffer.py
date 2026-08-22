"""
Syslog Event Buffer

Durable staging for syslog messages received on the UDP/TCP listener. The
UniFi connector drains these on its normal sync cycle, so persistence, dedup,
and correlation all reuse the standard connector sync path.

This was a process-local dict in ``syslog_receiver``. Datagrams are
load-balanced across every backend replica while ``last_sync_at`` is a single
row, so the replica that ran the sync drained its own (usually empty) buffer
and marked the connector done, and the replica actually holding the messages
skipped. Nothing was ever written down, so those messages -- and the alerts
they would have become -- were lost silently while the sync reported success.
See docs/syslog-drain-2026-08-17.md for the measurements.

Delivery is at-least-once, exactly as in ``falco_event_buffer``: a drain
*claims* rows rather than deleting them, and a claim older than
``CLAIM_STALE_MINUTES`` is re-claimable, so a sync that dies between claiming
and inserting recovers on the next tick. Re-processing is harmless because the
UniFi connector builds ``external_id`` from a content fingerprint (see
``content_external_id``), so a repeat collides with
``uq_normalized_alerts_org_connector_external``.
"""

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, delete, func, or_, select, update

from app.core.time_utils import utcnow
from app.db.models import SyslogIngestEvent

logger = logging.getLogger(__name__)

# Per-connector cap on unclaimed messages. A flood beyond this is dropped with
# a warning rather than growing the table without bound. Syslog is chattier
# than a webhook, so this is larger than the Falco equivalent.
MAX_EVENTS_PER_CONNECTOR = 50_000

# A claimed row this old is assumed to belong to a sync that died before
# inserting, and becomes re-claimable.
CLAIM_STALE_MINUTES = 15

# Claimed rows are kept this long for debugging, then reaped.
RETAIN_CLAIMED_HOURS = 24


async def push_events(
    db,
    connector_id: UUID,
    organization_id: UUID,
    payloads: list[dict[str, Any]],
) -> int:
    """Persist received messages for a connector. Returns the number accepted.

    Caller supplies the session so the write joins its transaction.
    """
    if not payloads:
        return 0

    pending = await count_pending(db, connector_id)
    capacity = MAX_EVENTS_PER_CONNECTOR - pending
    if capacity <= 0:
        logger.warning(
            "Syslog buffer for connector %s is full (%s pending); dropping %s messages",
            connector_id,
            pending,
            len(payloads),
        )
        return 0

    accepted = payloads[:capacity]
    if len(accepted) < len(payloads):
        logger.warning(
            "Syslog buffer for connector %s near capacity; dropped %s of %s messages",
            connector_id,
            len(payloads) - len(accepted),
            len(payloads),
        )

    now = utcnow()
    db.add_all(
        [
            SyslogIngestEvent(
                organization_id=organization_id,
                connector_id=connector_id,
                payload=payload,
                # Preserve the receipt time the listener stamped; falling back
                # to now would relabel a batch that waited on a flush.
                received_at=_received_at(payload) or now,
            )
            for payload in accepted
        ]
    )
    await db.flush()
    return len(accepted)


def _received_at(payload: dict[str, Any]):
    """Receipt time recorded by the listener, if it survived serialization."""
    from datetime import datetime

    raw = payload.get("timestamp")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return None


async def count_pending(db, connector_id: UUID) -> int:
    """Messages for a connector still awaiting a successful sync."""
    result = await db.execute(
        select(func.count())
        .select_from(SyslogIngestEvent)
        .where(
            and_(
                SyslogIngestEvent.connector_id == connector_id,
                _unclaimed_or_stale(),
            )
        )
    )
    return result.scalar() or 0


def _unclaimed_or_stale():
    """Rows eligible to be claimed.

    Never claimed, or claimed by a sync that died before finishing. A row that
    has been *processed* is never eligible again, whatever its claim looks
    like: without that condition a successfully-drained row became re-claimable
    15 minutes later, and because claims are taken oldest-first the same rows
    cycled forever while newer ones were never reached.
    """
    stale_before = utcnow() - timedelta(minutes=CLAIM_STALE_MINUTES)
    return and_(
        SyslogIngestEvent.processed_at.is_(None),
        or_(
            SyslogIngestEvent.claimed_at.is_(None),
            SyslogIngestEvent.claimed_at < stale_before,
        ),
    )


@dataclass
class ClaimedEvent:
    """A staged row handed to a drain, with the id needed to close it out."""

    id: UUID
    payload: dict[str, Any]


async def claim_events(db, connector_id: UUID, limit: int = 100) -> list[ClaimedEvent]:
    """Claim up to ``limit`` pending messages for a connector.

    Uses SKIP LOCKED so concurrent syncs on different replicas take disjoint
    rows instead of blocking or double-processing. The caller must call
    ``mark_processed`` once it has handled them, or they will be re-claimed
    when the lease goes stale.
    """
    candidate_ids = (
        select(SyslogIngestEvent.id)
        .where(
            and_(
                SyslogIngestEvent.connector_id == connector_id,
                _unclaimed_or_stale(),
            )
        )
        .order_by(SyslogIngestEvent.received_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )

    result = await db.execute(
        update(SyslogIngestEvent)
        .where(SyslogIngestEvent.id.in_(candidate_ids))
        .values(claimed_at=utcnow())
        .returning(SyslogIngestEvent.id, SyslogIngestEvent.payload)
    )
    return [ClaimedEvent(id=row[0], payload=row[1]) for row in result.all()]


async def mark_processed(db, ids: list[UUID]) -> int:
    """Close out rows a drain has successfully handled.

    Until this is set the row is only *leased*, and a lease that goes stale is
    indistinguishable from a sync that died -- which is exactly how the same
    rows ended up being re-processed indefinitely.
    """
    if not ids:
        return 0
    result = await db.execute(
        update(SyslogIngestEvent)
        .where(SyslogIngestEvent.id.in_(ids))
        .values(processed_at=utcnow())
    )
    return result.rowcount or 0


async def purge_processed(db, older_than_hours: int = RETAIN_CLAIMED_HOURS) -> int:
    """Delete claimed rows past the retention window."""
    cutoff = utcnow() - timedelta(hours=older_than_hours)
    result = await db.execute(
        delete(SyslogIngestEvent).where(
            and_(
                # processed_at, not claimed_at: a re-claimed row had its
                # claimed_at refreshed on every pass, so it never aged out and
                # the table grew without bound.
                SyslogIngestEvent.processed_at.is_not(None),
                SyslogIngestEvent.processed_at < cutoff,
            )
        )
    )
    return result.rowcount or 0
