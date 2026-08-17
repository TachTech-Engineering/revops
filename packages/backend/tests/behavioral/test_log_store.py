"""
Raw log storage and search, against a real Postgres.

These are the properties that matter for this table, in priority order:

1. One tenant can never read another's logs. Logs are the most sensitive data
   in the product -- an alert says "something happened", a log line says what.
2. The store cannot take the application down. Logs share a volume with the
   operational database, so the size ceiling must actually engage, and a
   failed log write must never fail the caller's ingest.
3. Retention is a partition drop, and the partitions ingestion needs exist.

Two of these were broken when first written and are regression-guarded here:
``stored_bytes`` read ``pg_total_relation_size`` of the *partitioned parent*,
which is always 0, silently disabling the ceiling; and a failed insert aborted
the caller's transaction, so one log line for an unpartitioned day would have
500'd the Falco webhook and lost the alert it was attached to.
"""

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import text

from app.core.time_utils import utcnow
from app.services import log_store
from app.services.log_store import LogEvent

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def partitions(db_session):
    """Ensure today's partitions exist; the harness builds the parent empty."""
    await log_store.ensure_partitions(db_session)
    return db_session


def _event(org_id, connector_id=None, message="hello", **kw):
    return LogEvent(
        organization_id=org_id,
        connector_id=connector_id or uuid.uuid4(),
        source_type=kw.pop("source_type", "unifi_syslog"),
        event_time=kw.pop("event_time", utcnow()),
        message=message,
        **kw,
    )


async def _search(db, org_id, **kw):
    now = utcnow()
    return await log_store.search_logs(
        db,
        organization_id=org_id,
        start=kw.pop("start", now - timedelta(hours=1)),
        end=kw.pop("end", now + timedelta(hours=1)),
        **kw,
    )


async def test_store_and_search_round_trip(partitions):
    db = partitions
    org = uuid.uuid4()

    stored = await log_store.store_events(
        db,
        [
            _event(org, message="firewall blocked 10.0.0.5 on port 22", host="udm"),
            _event(org, message="admin authentication failed", host="udm"),
        ],
    )
    assert stored == 2

    rows, total = await _search(db, org)
    assert total == 2
    assert {r["message"] for r in rows} == {
        "firewall blocked 10.0.0.5 on port 22",
        "admin authentication failed",
    }


async def test_one_org_cannot_read_anothers_logs(partitions):
    """The isolation property. Org A must not see org B's logs by any route."""
    db = partitions
    org_a, org_b = uuid.uuid4(), uuid.uuid4()

    await log_store.store_events(db, [_event(org_a, message="org a private line")])
    await log_store.store_events(
        db, [_event(org_b, message="org b secret credential dump", host="b-host")]
    )

    _, a_total = await _search(db, org_a)
    assert a_total == 1

    # Not via full-text on the other tenant's content...
    _, cross = await _search(db, org_a, query="secret credential")
    assert cross == 0
    # ...nor by guessing their host...
    _, by_host = await _search(db, org_a, host="b-host")
    assert by_host == 0
    # ...and org B still sees exactly its own.
    rows_b, b_total = await _search(db, org_b)
    assert b_total == 1
    assert rows_b[0]["message"] == "org b secret credential dump"


async def test_full_text_and_filters(partitions):
    db = partitions
    org = uuid.uuid4()
    conn_a, conn_b = uuid.uuid4(), uuid.uuid4()

    await log_store.store_events(
        db,
        [
            _event(org, conn_a, "ssh login failure from 1.2.3.4", source_type="unifi_syslog"),
            _event(org, conn_b, "terminal shell spawned in container", source_type="falco"),
        ],
    )

    _, hit = await _search(db, org, query="login failure")
    assert hit == 1
    _, miss = await _search(db, org, query="nonexistentterm")
    assert miss == 0

    # websearch_to_tsquery takes user phrasing without raising on syntax.
    _, quoted = await _search(db, org, query='"terminal shell"')
    assert quoted == 1

    _, by_source = await _search(db, org, source_type="falco")
    assert by_source == 1
    _, by_connector = await _search(db, org, connector_id=conn_a)
    assert by_connector == 1


async def test_search_is_bounded_by_the_time_window(partitions):
    db = partitions
    org = uuid.uuid4()
    now = utcnow()

    await log_store.store_events(db, [_event(org, message="right now")])

    _, inside = await _search(db, org)
    assert inside == 1
    _, before = await _search(db, org, start=now - timedelta(hours=6), end=now - timedelta(hours=5))
    assert before == 0


async def test_search_limit_is_capped(partitions):
    """A caller cannot ask for an unbounded response."""
    db = partitions
    org = uuid.uuid4()
    await log_store.store_events(db, [_event(org, message=f"line {i}") for i in range(5)])

    rows, total = await _search(db, org, limit=2)
    assert len(rows) == 2 and total == 5

    rows, _ = await _search(db, org, limit=10**6)
    assert len(rows) <= log_store.MAX_SEARCH_LIMIT


async def test_size_ceiling_refuses_writes(partitions, monkeypatch):
    """The ceiling must engage against real on-disk size, not the empty parent.

    Regression: stored_bytes() measured the partitioned parent, which reports 0
    bytes no matter how much data the partitions hold.
    """
    db = partitions
    org = uuid.uuid4()
    await log_store.store_events(db, [_event(org, message="occupy some bytes")])

    assert await log_store.stored_bytes(db) > 0, "partition sizes must be counted"

    monkeypatch.setattr(log_store, "MAX_STORED_BYTES", 1)
    refused = await log_store.store_events(db, [_event(org, message="past the ceiling")])
    assert refused == 0

    _, total = await _search(db, org)
    assert total == 1, "the refused line must not have been written"


async def test_device_clock_skew_does_not_lose_the_line(partitions):
    """Syslog carries the sender's clock, and skewed clocks are routine.

    A device reporting 1970 or 2035 would otherwise land outside every
    partition and be dropped. It is filed at receipt time, with the claimed
    timestamp preserved so the skew is visible rather than laundered away.
    """
    db = partitions
    org = uuid.uuid4()
    skewed = utcnow() - timedelta(days=3650)

    stored = await log_store.store_events(
        db, [_event(org, message="log from a device stuck in 2016", event_time=skewed)]
    )
    assert stored == 1

    rows, total = await _search(db, org)
    assert total == 1
    assert rows[0]["attributes"]["reported_event_time"] == skewed.isoformat()
    assert "device clock" in rows[0]["attributes"]["event_time_source"]


async def test_oversized_fields_do_not_reject_the_batch(partitions):
    db = partitions
    org = uuid.uuid4()

    stored = await log_store.store_events(
        db,
        [
            _event(
                org,
                message="long metadata",
                host="h" * 900,
                source_ip="1.2.3.4" * 40,
                severity="critical" * 30,
            )
        ],
    )
    assert stored == 1

    rows, _ = await _search(db, org)
    assert len(rows[0]["host"]) == 255
    assert len(rows[0]["source_ip"]) == 45
    assert len(rows[0]["severity"]) == 20


async def test_failed_log_write_does_not_break_the_caller(partitions):
    """A log write is best-effort; the caller's own transaction must survive.

    Callers store logs inside the transaction that also writes the alert, then
    commit. Without SAVEPOINT isolation an unpartitioned event_time aborts that
    transaction and the alert is lost to protect a log line.
    """
    db = partitions
    org = uuid.uuid4()

    # Remove the partition this write would land in, so the insert genuinely
    # fails the way a missed maintenance run would cause.
    today = utcnow().date()
    await db.execute(text(f"DROP TABLE raw_log_events_{today.strftime('%Y%m%d')}"))

    stored = await log_store.store_events(db, [_event(org, message="no partition exists")])
    assert stored == 0, "must not raise, must not claim to have stored"

    # The caller's session is still usable and can still do its real work.
    assert (await db.execute(text("SELECT 1"))).scalar() == 1

    # And once maintenance restores the partition, ingestion resumes.
    await log_store.ensure_partitions(db)
    good = await log_store.store_events(db, [_event(org, message="healthy line")])
    assert good == 1
    _, total = await _search(db, org)
    assert total == 1


async def test_partition_lifecycle(partitions):
    db = partitions

    async def partition_count():
        return (
            await db.execute(
                text(
                    """
                    SELECT count(*) FROM pg_inherits i
                    JOIN pg_class p ON p.oid = i.inhparent
                    WHERE p.relname = 'raw_log_events'
                    """
                )
            )
        ).scalar()

    # Already ensured by the fixture, so a second run is a no-op.
    assert await log_store.ensure_partitions(db) == 0

    expired = utcnow().date() - timedelta(days=log_store.retention_days() + 30)
    name = f"raw_log_events_{expired.strftime('%Y%m%d')}"
    await db.execute(
        text(
            f"CREATE TABLE {name} PARTITION OF raw_log_events "
            f"FOR VALUES FROM ('{expired}') TO ('{expired + timedelta(days=1)}')"
        )
    )
    before = await partition_count()

    dropped = await log_store.drop_expired_partitions(db)
    assert name in dropped
    assert await partition_count() == before - len(dropped)


async def test_search_endpoint_is_org_scoped(app_client, make_user, partitions):
    """End to end: the API scopes to the caller's session, not to request input."""
    db = partitions
    alice = await make_user("logs-a")
    bob = await make_user("logs-b")

    await log_store.store_events(db, [_event(alice.org.id, message="alice only sees this")])
    await log_store.store_events(db, [_event(bob.org.id, message="bob confidential line")])

    resp = await app_client.get("/api/v1/logs/search", headers=alice.headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["results"][0]["message"] == "alice only sees this"

    # Searching for the other tenant's text returns nothing.
    resp = await app_client.get(
        "/api/v1/logs/search", headers=alice.headers, params={"q": "confidential"}
    )
    assert resp.json()["total"] == 0


async def test_search_endpoint_requires_auth(app_client):
    resp = await app_client.get("/api/v1/logs/search")
    assert resp.status_code in (401, 403)


async def test_search_endpoint_rejects_bad_windows(app_client, make_user, partitions):
    user = await make_user("logs-window")
    now = utcnow()

    resp = await app_client.get(
        "/api/v1/logs/search",
        headers=user.headers,
        params={"start": now.isoformat(), "end": (now - timedelta(hours=1)).isoformat()},
    )
    assert resp.status_code == 400

    resp = await app_client.get(
        "/api/v1/logs/search",
        headers=user.headers,
        params={
            "start": (now - timedelta(days=400)).isoformat(),
            "end": now.isoformat(),
        },
    )
    assert resp.status_code == 400
