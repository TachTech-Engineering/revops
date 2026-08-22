"""
Falco ingest buffer durability (DB-backed).

The buffer was a process-global deque. The ingest webhook answers 202 Accepted
and the connector sync runs minutes later, so with multiple replicas any pod
restart in between silently discarded alerts the caller had been told were
accepted. Events are now rows in ``falco_ingest_events``.

Durability itself follows from using a table; what needs pinning is the claim
protocol built on top of it: an event is claimed exactly once, a claim
abandoned by a crashed sync becomes re-claimable rather than lost, and the
table cannot grow without bound.
"""

import uuid
from datetime import timedelta

import pytest

from app.core.time_utils import utcnow
from app.db.models import Connector, ConnectorCategory, FalcoIngestEvent
from app.services.falco_event_buffer import (
    CLAIM_STALE_MINUTES,
    claim_events,
    count_pending,
    mark_processed,
    purge_processed,
    push_events,
)

pytestmark = pytest.mark.asyncio


def _event(rule: str = "Terminal shell in container") -> dict:
    return {"hostname": "node-1", "rule": rule, "priority": "Critical", "output": "x"}


async def _falco_connector(db_session, org_id, name="falco-1") -> Connector:
    connector = Connector(
        organization_id=org_id,
        name=name,
        category=ConnectorCategory.DATA_SOURCE,
        connector_type="falco",
        created_by="test@example.com",
    )
    db_session.add(connector)
    await db_session.flush()
    return connector


async def test_pushed_event_is_pending_then_claimed_once(db_session, make_user):
    ctx = await make_user("falco-a")
    connector = await _falco_connector(db_session, ctx.org.id)

    await push_events(
        db_session,
        connector_id=connector.id,
        organization_id=ctx.org.id,
        events=[_event()],
    )
    assert await count_pending(db_session, connector.id) == 1

    claimed = await claim_events(db_session, connector.id, limit=10)
    assert len(claimed) == 1
    assert claimed[0].payload["rule"] == "Terminal shell in container"

    # A second sync (another replica, or the next tick) must not re-deliver it.
    assert await claim_events(db_session, connector.id) == []
    assert await count_pending(db_session, connector.id) == 0


async def test_stale_claim_is_reclaimable_so_a_crashed_sync_recovers(db_session, make_user):
    """A sync that dies between claiming and inserting must not lose events."""
    ctx = await make_user("falco-b")
    connector = await _falco_connector(db_session, ctx.org.id)
    await push_events(
        db_session, connector_id=connector.id, organization_id=ctx.org.id, events=[_event()]
    )

    await claim_events(db_session, connector.id)
    assert await claim_events(db_session, connector.id) == []

    # Age the claim past the staleness bound: the claiming process died.
    await db_session.execute(
        FalcoIngestEvent.__table__.update()
        .where(FalcoIngestEvent.connector_id == connector.id)
        .values(claimed_at=utcnow() - timedelta(minutes=CLAIM_STALE_MINUTES + 1))
    )

    reclaimed = await claim_events(db_session, connector.id)
    assert len(reclaimed) == 1, "a crashed sync's events must come back, not vanish"


async def test_events_are_scoped_per_connector(db_session, make_user):
    ctx = await make_user("falco-c")
    a = await _falco_connector(db_session, ctx.org.id, name="falco-a")
    b = await _falco_connector(db_session, ctx.org.id, name="falco-b")

    await push_events(db_session, connector_id=a.id, organization_id=ctx.org.id, events=[_event()])

    assert await count_pending(db_session, a.id) == 1
    assert await count_pending(db_session, b.id) == 0
    assert await claim_events(db_session, b.id) == []


async def test_push_records_the_owning_organization(db_session, make_user):
    """organization_id is NOT NULL and carries tenancy onto the resulting alerts."""
    ctx = await make_user("falco-d")
    connector = await _falco_connector(db_session, ctx.org.id)
    await push_events(
        db_session, connector_id=connector.id, organization_id=ctx.org.id, events=[_event()]
    )

    row = (
        await db_session.execute(
            FalcoIngestEvent.__table__.select().where(FalcoIngestEvent.connector_id == connector.id)
        )
    ).first()
    assert row.organization_id == ctx.org.id
    assert row.claimed_at is None


async def test_buffer_is_capped_per_connector(db_session, make_user, monkeypatch):
    monkeypatch.setattr("app.services.falco_event_buffer.MAX_EVENTS_PER_CONNECTOR", 3)
    ctx = await make_user("falco-e")
    connector = await _falco_connector(db_session, ctx.org.id)

    accepted = await push_events(
        db_session,
        connector_id=connector.id,
        organization_id=ctx.org.id,
        events=[_event(str(i)) for i in range(5)],
    )

    assert accepted == 3, "overflow is refused at the door rather than growing the table"
    assert await count_pending(db_session, connector.id) == 3


async def test_purge_removes_only_old_processed_rows(db_session, make_user):
    """Retention reaps rows a drain has *finished with* (processed_at), not
    merely claimed ones: a claimed-but-unprocessed row is recoverable work and
    must survive the purge (the processed-marker fix, d16f8b3a92c4)."""
    ctx = await make_user("falco-f")
    connector = await _falco_connector(db_session, ctx.org.id)
    await push_events(
        db_session,
        connector_id=connector.id,
        organization_id=ctx.org.id,
        events=[_event("a"), _event("b")],
    )
    claimed = await claim_events(db_session, connector.id, limit=1)
    await mark_processed(db_session, [e.id for e in claimed])

    # Nothing is old enough yet.
    assert await purge_processed(db_session, older_than_hours=24) == 0

    # Age the processed row past retention; an old claim alone must NOT purge.
    await db_session.execute(
        FalcoIngestEvent.__table__.update()
        .where(
            FalcoIngestEvent.connector_id == connector.id,
            FalcoIngestEvent.processed_at.is_not(None),
        )
        .values(
            claimed_at=utcnow() - timedelta(hours=48),
            processed_at=utcnow() - timedelta(hours=48),
        )
    )
    assert await purge_processed(db_session, older_than_hours=24) >= 1

    # The unclaimed event is untouched.
    assert await count_pending(db_session, connector.id) == 1


async def test_old_claim_without_processed_marker_survives_purge(db_session, make_user):
    ctx = await make_user("falco-g")
    connector = await _falco_connector(db_session, ctx.org.id)
    await push_events(
        db_session,
        connector_id=connector.id,
        organization_id=ctx.org.id,
        events=[_event("a")],
    )
    await claim_events(db_session, connector.id, limit=1)
    await db_session.execute(
        FalcoIngestEvent.__table__.update()
        .where(FalcoIngestEvent.connector_id == connector.id)
        .values(claimed_at=utcnow() - timedelta(hours=48))
    )

    # Claimed long ago but never marked processed: still recoverable work.
    assert await purge_processed(db_session, older_than_hours=24) == 0
    assert await count_pending(db_session, connector.id) == 1


async def test_unknown_connector_claims_nothing(db_session):
    assert await claim_events(db_session, uuid.uuid4()) == []
