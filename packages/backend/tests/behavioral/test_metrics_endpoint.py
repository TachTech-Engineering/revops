"""
The metrics endpoint must be useful and must not leak.

It is deliberately unauthenticated -- Google Managed Prometheus scrapes the pod
directly and cannot present a JWT -- so "carries no tenant data" is a property
that has to be enforced, not just asserted in a comment. In a multi-tenant
security product an unauthenticated endpoint that named organizations or echoed
log content would be a disclosure bug.
"""

import uuid

import pytest

from app.core import metrics
from app.core.time_utils import utcnow
from app.db.models import Connector, ConnectorCategory, ConnectorStatus

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _fresh_scrape():
    """Clear the 10s scrape cache between tests.

    render() reuses its last body briefly so frequent scrapes do not re-run
    every query. That is deliberate in production and makes tests
    order-dependent: without this, a test asserting on data it just created
    can be handed the previous test's payload.
    """
    metrics._cache["at"] = 0.0
    metrics._cache["body"] = ""
    yield


async def test_scrape_is_reachable_without_a_token(app_client):
    resp = await app_client.get("/metrics")

    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert "revops_up 1" in resp.text


async def test_the_metrics_that_would_have_caught_the_outages_are_present(app_client):
    """Each of these maps to a fault that ran unnoticed for a day or more."""
    body = (await app_client.get("/metrics")).text

    for name in (
        "revops_ingest_pending",  # the livelock and the undrained buffer
        "revops_ingest_oldest_pending_seconds",  # a stalled drain
        "revops_log_store_bytes",  # the cap that silently read zero
        "revops_log_store_max_bytes",
        "revops_connector_seconds_since_sync",  # a connector that stops syncing
        "revops_alerts_ingested_1h",  # "zero alerts for six hours"
    ):
        assert f"# TYPE {name} gauge" in body, f"{name} is missing"


async def test_no_tenant_data_leaks_into_the_scrape(db_session, make_user, app_client):
    """The safety property. Org ids and connector names must never appear."""
    user = await make_user("metrics-leak")
    secret_name = "Acme Production Firewall"
    db_session.add(
        Connector(
            name=secret_name,
            connector_type="unifi_syslog",
            category=ConnectorCategory.DATA_SOURCE,
            status=ConnectorStatus.CONNECTED,
            organization_id=user.org.id,
            created_by=str(user.user.id),
            config={},
            sync_interval_minutes=5,
            last_sync_at=utcnow(),
        )
    )
    await db_session.flush()

    body = (await app_client.get("/metrics")).text

    assert secret_name not in body, "connector names must not be exported"
    assert str(user.org.id) not in body, "organization ids must not be exported"
    assert user.user.email not in body, "user identifiers must not be exported"
    # The connector's *type* is fine and useful; its identity is not.
    assert "unifi_syslog" in body


async def test_a_broken_query_does_not_take_the_whole_scrape_down(db_session):
    """A blind exporter is bad; one that 500s hides the metrics explaining why.

    Exercised through the real failure path -- a query against a table that
    does not exist -- rather than by stubbing the helper that contains the
    protection, which would have tested nothing.
    """
    value = await metrics._scalar(db_session, "SELECT count(*) FROM table_that_does_not_exist")

    assert value == 0.0, "a failed metric degrades to its default"

    # The session must still be usable afterwards, or one bad metric would
    # poison every metric after it in the same scrape.
    metrics._cache["at"] = 0.0  # second render inside one test
    body = await metrics.render(db_session)
    assert "revops_up 1" in body


async def test_pending_depth_reflects_real_rows(db_session, make_user, app_client):
    """The number has to actually move, or the graph is decorative."""
    from app.services import syslog_event_buffer as buf

    user = await make_user("metrics-depth")
    connector = Connector(
        name="c",
        connector_type="unifi_syslog",
        category=ConnectorCategory.DATA_SOURCE,
        status=ConnectorStatus.CONNECTED,
        organization_id=user.org.id,
        created_by=str(user.user.id),
        config={},
        sync_interval_minutes=5,
    )
    db_session.add(connector)
    await db_session.flush()

    await buf.push_events(
        db_session,
        connector.id,
        user.org.id,
        [{"raw": "x", "message": "x", "timestamp": utcnow().isoformat()} for _ in range(3)],
    )
    await db_session.commit()

    body = (await app_client.get("/metrics")).text

    line = next(
        ln for ln in body.splitlines() if ln.startswith('revops_ingest_pending{buffer="syslog"}')
    )
    assert float(line.rsplit(" ", 1)[1]) >= 3


async def test_unknown_connector_ids_are_not_exported(app_client):
    """Guard against a future label that quietly reintroduces identifiers."""
    body = (await app_client.get("/metrics")).text

    # A UUID anywhere in the output means something identifying got exported.
    import re

    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", body), (
        "no UUIDs may appear in an unauthenticated scrape"
    )
    assert uuid.UUID  # keeps the import meaningful
