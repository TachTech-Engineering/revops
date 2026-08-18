"""
Two cross-replica correctness properties.

1. Only one replica syncs a given connector at a time. The scheduler runs on
   every backend replica and guarded against double-syncing with a
   process-local set, which replicas do not share -- so all three could see a
   connector as due and sync it simultaneously, multiplying every upstream API
   call by the replica count.

2. Deleting a user works. refresh_tokens.user_id had no ON DELETE behaviour, so
   a user who had ever logged in could not be deleted at all -- the delete
   failed with a foreign-key violation. Offboarding and erasure requests both
   hit that.
"""

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select, text

from app.core.time_utils import utcnow
from app.db.models import Connector, ConnectorCategory, ConnectorStatus, RefreshToken, User
from app.jobs.connector_sync import SYNC_CLAIM_STALE_MINUTES, ConnectorSyncScheduler

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def connector(db_session, make_user):
    user = await make_user("sync-claim")
    conn = Connector(
        name="Claimed connector",
        connector_type="panther",
        category=ConnectorCategory.DATA_SOURCE,
        status=ConnectorStatus.CONNECTED,
        organization_id=user.org.id,
        created_by=str(user.user.id),
        config={},
        sync_interval_minutes=5,
    )
    db_session.add(conn)
    await db_session.flush()
    return conn


async def test_only_one_replica_claims_a_connector(db_session, connector):
    """The property. Three schedulers race; exactly one wins."""
    replicas = [ConnectorSyncScheduler() for _ in range(3)]

    results = [await r._claim_connector(db_session, connector.id) for r in replicas]

    assert sum(results) == 1, f"expected exactly one winner, got {results}"


async def test_a_released_claim_can_be_taken_again(db_session, connector):
    """A finished sync frees the connector for its next interval."""
    scheduler = ConnectorSyncScheduler()
    assert await scheduler._claim_connector(db_session, connector.id) is True
    assert await scheduler._claim_connector(db_session, connector.id) is False

    await db_session.execute(
        text("UPDATE connectors SET sync_claimed_at = NULL WHERE id = :cid"),
        {"cid": connector.id},
    )
    assert await scheduler._claim_connector(db_session, connector.id) is True


async def test_a_replica_that_died_mid_sync_does_not_strand_the_connector(db_session, connector):
    """A stale claim is reclaimable, or a killed pod blocks syncs forever."""
    scheduler = ConnectorSyncScheduler()
    assert await scheduler._claim_connector(db_session, connector.id) is True

    await db_session.execute(
        text("UPDATE connectors SET sync_claimed_at = :t WHERE id = :cid"),
        {"t": utcnow() - timedelta(minutes=SYNC_CLAIM_STALE_MINUTES + 1), "cid": connector.id},
    )

    assert await scheduler._claim_connector(db_session, connector.id) is True


async def test_claiming_does_not_touch_the_sync_window(db_session, connector):
    """last_sync_at is the window start; claiming must not move it.

    Writing the claim there would make every sync fetch from "now" and silently
    skip every alert since the previous run.
    """
    before = utcnow() - timedelta(hours=2)
    await db_session.execute(
        text("UPDATE connectors SET last_sync_at = :t WHERE id = :cid"),
        {"t": before, "cid": connector.id},
    )

    await ConnectorSyncScheduler()._claim_connector(db_session, connector.id)

    after = (
        await db_session.execute(
            text("SELECT last_sync_at FROM connectors WHERE id = :cid"), {"cid": connector.id}
        )
    ).scalar()
    assert after == before


async def test_claiming_is_scoped_to_one_connector(db_session, connector, make_user):
    other_user = await make_user("sync-claim-other")
    other = Connector(
        name="Other connector",
        connector_type="panther",
        category=ConnectorCategory.DATA_SOURCE,
        status=ConnectorStatus.CONNECTED,
        organization_id=other_user.org.id,
        created_by=str(other_user.user.id),
        config={},
        sync_interval_minutes=5,
    )
    db_session.add(other)
    await db_session.flush()

    scheduler = ConnectorSyncScheduler()
    assert await scheduler._claim_connector(db_session, connector.id) is True
    assert await scheduler._claim_connector(db_session, other.id) is True, (
        "claiming one connector must not block another"
    )


async def test_a_user_with_refresh_tokens_can_be_deleted(db_session, make_user):
    """The regression: this used to fail with a foreign-key violation."""
    person = await make_user("cascade")
    db_session.add(
        RefreshToken(
            user_id=person.user.id,
            token_hash=uuid.uuid4().hex,
            expires_at=utcnow() + timedelta(days=7),
        )
    )
    await db_session.flush()

    await db_session.delete(person.user)
    await db_session.flush()

    assert (
        await db_session.execute(select(User).where(User.id == person.user.id))
    ).scalar_one_or_none() is None
    remaining = (
        (
            await db_session.execute(
                select(RefreshToken).where(RefreshToken.user_id == person.user.id)
            )
        )
        .scalars()
        .all()
    )
    assert remaining == [], "the user's tokens must go with them"
