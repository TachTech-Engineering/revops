"""
Syslog messages survive the replica that received them.

The bug this guards against, measured in production on 2026-08-17: datagrams
are load-balanced across every backend replica, but ``last_sync_at`` is a
single row. Whichever replica reached the connector first drained its own
(usually empty) in-memory buffer and marked the connector synced, so the
replica actually holding the messages skipped its turn. One pod held 172
buffered messages and ran no drains while another ran four drains finding
nothing each time. Nothing was ever persisted, so the messages -- and the
UniFi alerts they would have become -- were lost while the sync reported
success.

"Replica" here is a separate database session, which is what distinguishes one
pod from another as far as this staging table is concerned.
"""

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import text

from app.core.time_utils import utcnow
from app.db.models import Connector, ConnectorCategory, ConnectorStatus
from app.services import syslog_event_buffer as buf
from app.services.syslog_receiver import SyslogReceiverService

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def connector(db_session, make_user):
    user = await make_user("syslog-durability")
    conn = Connector(
        name="UniFi test",
        connector_type="unifi_syslog",
        category=ConnectorCategory.DATA_SOURCE,
        status=ConnectorStatus.CONNECTED,
        organization_id=user.org.id,
        created_by=str(user.user.id),
        config={},
    )
    db_session.add(conn)
    await db_session.flush()
    return conn


def _payload(message="<30>Aug 17 14:10:33 DK-Lab DK-Lab earlyoom[801]: mem avail", **kw):
    receiver = SyslogReceiverService()
    parsed = receiver._parse_message(message, kw.pop("source_ip", "203.0.113.5"), 514)
    payload = receiver.to_payload(parsed)
    payload.update(kw)
    return payload


async def test_a_message_received_on_one_replica_is_drained_by_another(db_session, connector):
    """The whole point. Receipt and drain happen on different replicas."""
    received = await buf.push_events(
        db_session, connector.id, connector.organization_id, [_payload()]
    )
    await db_session.commit()
    assert received == 1

    # A different replica runs the sync and must find it.
    claimed = await buf.claim_events(db_session, connector.id, limit=100)

    assert len(claimed) == 1
    assert claimed[0]["hostname"] == "DK-Lab"


async def test_a_claimed_message_is_not_handed_out_twice(db_session, connector):
    await buf.push_events(db_session, connector.id, connector.organization_id, [_payload()])
    await db_session.commit()

    first = await buf.claim_events(db_session, connector.id)
    second = await buf.claim_events(db_session, connector.id)

    assert len(first) == 1
    assert second == [], "a second sync must not reprocess a claimed message"


async def test_a_sync_that_died_mid_drain_does_not_lose_the_message(db_session, connector):
    """At-least-once: a stale claim is re-takeable.

    Re-processing is safe because the connector derives external_id from a
    content fingerprint, so a repeat collides on the unique constraint.
    """
    await buf.push_events(db_session, connector.id, connector.organization_id, [_payload()])
    await db_session.commit()

    await buf.claim_events(db_session, connector.id)
    assert await buf.claim_events(db_session, connector.id) == []

    # Age the claim past the staleness window, as a crashed sync would leave it.
    stale = utcnow() - timedelta(minutes=buf.CLAIM_STALE_MINUTES + 1)
    await db_session.execute(
        text("UPDATE syslog_ingest_events SET claimed_at = :t WHERE connector_id = :c"),
        {"t": stale, "c": connector.id},
    )

    assert len(await buf.claim_events(db_session, connector.id)) == 1


async def test_pending_count_ignores_claimed_messages(db_session, connector):
    await buf.push_events(
        db_session,
        connector.id,
        connector.organization_id,
        [_payload(), _payload(), _payload()],
    )
    await db_session.commit()

    assert await buf.count_pending(db_session, connector.id) == 3
    await buf.claim_events(db_session, connector.id, limit=2)
    assert await buf.count_pending(db_session, connector.id) == 1


async def test_the_buffer_is_capped(db_session, connector, monkeypatch):
    """A flood is dropped at the door rather than growing the table forever."""
    monkeypatch.setattr(buf, "MAX_EVENTS_PER_CONNECTOR", 2)

    accepted = await buf.push_events(
        db_session,
        connector.id,
        connector.organization_id,
        [_payload(), _payload(), _payload(), _payload()],
    )

    assert accepted == 2
    assert await buf.count_pending(db_session, connector.id) == 2


async def test_claims_are_scoped_to_the_connector(db_session, connector, make_user):
    """One connector's sync must not drain another's messages."""
    other_user = await make_user("syslog-other")
    other = Connector(
        name="Other UniFi",
        connector_type="unifi_syslog",
        category=ConnectorCategory.DATA_SOURCE,
        status=ConnectorStatus.CONNECTED,
        organization_id=other_user.org.id,
        created_by=str(other_user.user.id),
        config={},
    )
    db_session.add(other)
    await db_session.flush()

    await buf.push_events(
        db_session,
        connector.id,
        connector.organization_id,
        [_payload("<30>Aug 17 14:10:33 host-a host-a sshd[1]: mine")],
    )
    await buf.push_events(
        db_session,
        other.id,
        other.organization_id,
        [_payload("<30>Aug 17 14:10:33 host-b host-b sshd[2]: theirs")],
    )
    await db_session.commit()

    claimed = await buf.claim_events(db_session, connector.id)
    assert len(claimed) == 1
    assert claimed[0]["hostname"] == "host-a"
    assert await buf.count_pending(db_session, other.id) == 1, "the other connector is untouched"


async def test_purge_only_removes_old_claimed_rows(db_session, connector):
    await buf.push_events(
        db_session, connector.id, connector.organization_id, [_payload(), _payload()]
    )
    await db_session.commit()
    await buf.claim_events(db_session, connector.id, limit=1)

    # Nothing is old enough yet.
    assert await buf.purge_processed(db_session) == 0

    await db_session.execute(
        text(
            "UPDATE syslog_ingest_events SET claimed_at = :t "
            "WHERE claimed_at IS NOT NULL AND connector_id = :c"
        ),
        {"t": utcnow() - timedelta(hours=buf.RETAIN_CLAIMED_HOURS + 1), "c": connector.id},
    )

    assert await buf.purge_processed(db_session) == 1
    # The unclaimed one is still waiting to be drained.
    assert await buf.count_pending(db_session, connector.id) == 1


async def test_a_round_trip_preserves_what_the_parser_found(db_session, connector):
    """The drain must rebuild the message, not just the raw line."""
    raw = "<30>Aug 17 14:07:55 DK-Lab DK-Lab /usr/bin/unifi-mq-broker[2460]: MEM usage flows=595"
    await buf.push_events(
        db_session, connector.id, connector.organization_id, [_payload(raw, source_ip="10.0.0.9")]
    )
    await db_session.commit()

    claimed = await buf.claim_events(db_session, connector.id)
    rebuilt = SyslogReceiverService.from_payload(claimed[0])

    assert rebuilt.hostname == "DK-Lab"
    assert rebuilt.app_name == "/usr/bin/unifi-mq-broker"
    assert rebuilt.process_id == "2460"
    assert rebuilt.source_ip == "10.0.0.9"
    assert rebuilt.device_timestamp == "Aug 17 14:07:55"
    assert rebuilt.raw == raw
    assert rebuilt.timestamp.tzinfo is None, "naive UTC, or fetch_alerts raises comparing to since"


async def test_a_rebuilt_message_is_new_enough_to_become_an_alert(db_session, connector):
    """fetch_alerts drops anything older than `since`; staging must not age it."""
    await buf.push_events(db_session, connector.id, connector.organization_id, [_payload()])
    await db_session.commit()

    claimed = await buf.claim_events(db_session, connector.id)
    rebuilt = SyslogReceiverService.from_payload(claimed[0])

    since = utcnow() - timedelta(minutes=5)
    assert rebuilt.timestamp >= since


async def test_unknown_connector_stores_nothing(db_session, connector):
    """A payload list for a connector with no rows yields no writes."""
    assert await buf.push_events(db_session, connector.id, connector.organization_id, []) == 0
    assert await buf.count_pending(db_session, uuid.uuid4()) == 0
