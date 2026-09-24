"""Cross-source alert grouping against a real Postgres.

The fingerprint rules are covered DB-free in tests/test_alert_grouping.py. What
needs a database is everything the schema enforces: the partial unique index
that settles two connectors racing to cluster the same event, the sliding
window over event time, and the collapsed alert list.
"""

import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import AlertCluster, AlertClusterKey, AlertClusterMember, NormalizedAlert
from app.services.alert_grouping_service import group_alerts

BASE_TIME = datetime(2026, 9, 24, 12, 0, 0)


def build_alert(
    organization_id,
    *,
    source_type,
    title="Password guessing against WEB-01",
    tags=None,
    techniques=("T1110",),
    severity="high",
    at=BASE_TIME,
    connector_id=None,
) -> NormalizedAlert:
    return NormalizedAlert(
        organization_id=organization_id,
        connector_id=connector_id or uuid.uuid4(),
        source_type=source_type,
        external_id=f"{source_type}-{uuid.uuid4()}",
        title=title,
        description=None,
        severity=severity,
        status="open",
        created_at_source=at,
        tags=list(tags) if tags is not None else ["host:web-01"],
        mitre_tactics=[],
        mitre_techniques=list(techniques),
        raw_data={},
    )


async def insert(db, *alerts):
    db.add_all(alerts)
    await db.flush()
    return list(alerts)


async def members_of(db, cluster_id):
    result = await db.execute(
        select(AlertClusterMember.alert_id).where(AlertClusterMember.cluster_id == cluster_id)
    )
    return {row[0] for row in result.all()}


@pytest.mark.asyncio
async def test_two_sources_reporting_one_event_share_one_cluster(db_session, make_user):
    """The headline case: CrowdStrike and Sentinel both see the brute force
    against web-01, and the analyst gets one thing to work, not two."""
    ctx = await make_user("grouping")
    org = ctx.org.id

    crowdstrike, sentinel = await insert(
        db_session,
        build_alert(org, source_type="crowdstrike", title="Password guessing against WEB-01"),
        build_alert(org, source_type="sentinel", title="Brute force attempt observed"),
    )

    stats = await group_alerts(db_session, [crowdstrike, sentinel], org)

    assert stats == {"clusters_created": 1, "alerts_grouped": 2}

    clusters = (
        (await db_session.execute(select(AlertCluster).where(AlertCluster.organization_id == org)))
        .scalars()
        .all()
    )
    assert len(clusters) == 1
    assert clusters[0].alert_count == 2
    assert await members_of(db_session, clusters[0].id) == {
        str(crowdstrike.id),
        str(sentinel.id),
    }
    # Both products are named, so the analyst can see who reported what.
    assert set(clusters[0].common_entities["sources"]) == {"crowdstrike", "sentinel"}


@pytest.mark.asyncio
async def test_both_source_alerts_survive(db_session, make_user):
    """Nothing is suppressed. Each row is the handle alert_status_sync uses to
    push a resolution back to the SIEM it came from; dropping the duplicates
    would silently strip that from every source but the first."""
    ctx = await make_user("grouping")
    org = ctx.org.id

    alerts = await insert(
        db_session,
        build_alert(org, source_type="crowdstrike"),
        build_alert(org, source_type="sentinel"),
    )
    await group_alerts(db_session, alerts, org)

    rows = (
        (
            await db_session.execute(
                select(NormalizedAlert).where(NormalizedAlert.organization_id == org)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 2
    assert {r.source_type for r in rows} == {"crowdstrike", "sentinel"}


@pytest.mark.asyncio
async def test_unrelated_events_stay_apart(db_session, make_user):
    ctx = await make_user("grouping")
    org = ctx.org.id

    alerts = await insert(
        db_session,
        build_alert(org, source_type="crowdstrike", tags=["host:web-01"]),
        build_alert(org, source_type="crowdstrike", tags=["host:db-02"]),
        build_alert(
            org,
            source_type="crowdstrike",
            tags=["host:web-01"],
            title="Ransomware encryption",
            techniques=["T1486"],
        ),
    )
    stats = await group_alerts(db_session, alerts, org)
    assert stats["clusters_created"] == 3


@pytest.mark.asyncio
async def test_the_cluster_carries_the_worst_severity_seen(db_session, make_user):
    """An analyst scanning the collapsed list should see the worst thing any
    product said, not whichever product happened to sync first."""
    ctx = await make_user("grouping")
    org = ctx.org.id

    low, critical = await insert(
        db_session,
        build_alert(org, source_type="okta", severity="low"),
        build_alert(
            org, source_type="sentinel", severity="critical", at=BASE_TIME + timedelta(minutes=5)
        ),
    )
    await group_alerts(db_session, [low, critical], org)

    cluster = (
        await db_session.execute(select(AlertCluster).where(AlertCluster.organization_id == org))
    ).scalar_one()
    assert cluster.severity == "critical"
    assert cluster.representative_alert_id == critical.id


@pytest.mark.asyncio
async def test_a_later_recurrence_starts_a_new_cluster(db_session, make_user):
    """The same brute force against the same host next month is a new
    investigation, not an append to a month-old cluster."""
    ctx = await make_user("grouping")
    org = ctx.org.id

    first, much_later = await insert(
        db_session,
        build_alert(org, source_type="crowdstrike", at=BASE_TIME),
        build_alert(org, source_type="crowdstrike", at=BASE_TIME + timedelta(days=30)),
    )
    stats = await group_alerts(db_session, [first, much_later], org)

    assert stats["clusters_created"] == 2
    # The lapsed fingerprint was released rather than deleted: it still records
    # which entity the closed cluster was about.
    keys = (
        (
            await db_session.execute(
                select(AlertClusterKey).where(AlertClusterKey.organization_id == org)
            )
        )
        .scalars()
        .all()
    )
    assert sum(1 for k in keys if k.expires_at is None) == 1
    assert sum(1 for k in keys if k.expires_at is not None) == 1


@pytest.mark.asyncio
async def test_the_window_slides_while_the_event_is_still_going(db_session, make_user):
    """A burst that keeps producing alerts stays one cluster, even when it runs
    for longer than the window, because each new member pushes the expiry out."""
    ctx = await make_user("grouping")
    org = ctx.org.id

    alerts = await insert(
        db_session,
        *[
            build_alert(org, source_type="crowdstrike", at=BASE_TIME + timedelta(hours=20 * i))
            for i in range(4)
        ],
    )
    stats = await group_alerts(db_session, alerts, org)

    assert stats["clusters_created"] == 1
    cluster = (
        await db_session.execute(select(AlertCluster).where(AlertCluster.organization_id == org))
    ).scalar_one()
    assert cluster.alert_count == 4
    assert cluster.last_alert_at == BASE_TIME + timedelta(hours=60)


@pytest.mark.asyncio
async def test_a_batch_is_grouped_in_event_order_not_arrival_order(db_session, make_user):
    """A full_sync hands over a month of history in one pass, in whatever order
    the vendor's API returned it. Grouping has to reproduce what live
    ingestion would have built -- so a recurrence four weeks before another is
    a separate investigation, even though both arrive in the same batch and the
    newer one is listed first."""
    ctx = await make_user("grouping")
    org = ctx.org.id

    recent, ancient = await insert(
        db_session,
        build_alert(org, source_type="crowdstrike", at=BASE_TIME),
        build_alert(org, source_type="sentinel", at=BASE_TIME - timedelta(days=28)),
    )
    stats = await group_alerts(db_session, [recent, ancient], org)

    assert stats["clusters_created"] == 2
    assert stats["alerts_grouped"] == 2

    # Every alert landed somewhere: an alert whose fingerprint is taken by a
    # cluster it cannot join must not fall out of grouping silently.
    members = (await db_session.execute(select(AlertClusterMember.alert_id))).scalars().all()
    assert set(members) == {str(recent.id), str(ancient.id)}


@pytest.mark.asyncio
async def test_a_slightly_late_arrival_still_joins(db_session, make_user):
    """The bound is on event time, not arrival order: two products reporting
    one event minutes apart group no matter which syncs first."""
    ctx = await make_user("grouping")
    org = ctx.org.id

    later, earlier = await insert(
        db_session,
        build_alert(org, source_type="crowdstrike", at=BASE_TIME + timedelta(minutes=10)),
        build_alert(org, source_type="sentinel", at=BASE_TIME),
    )
    stats = await group_alerts(db_session, [later, earlier], org)

    assert stats["clusters_created"] == 1
    cluster = (
        await db_session.execute(select(AlertCluster).where(AlertCluster.organization_id == org))
    ).scalar_one()
    assert cluster.first_alert_at == BASE_TIME
    assert cluster.last_alert_at == BASE_TIME + timedelta(minutes=10)


@pytest.mark.asyncio
async def test_regrouping_the_same_alert_does_not_double_count(db_session, make_user):
    """A re-sync must land the alert back in the cluster it is already in."""
    ctx = await make_user("grouping")
    org = ctx.org.id

    (alert,) = await insert(db_session, build_alert(org, source_type="crowdstrike"))
    await group_alerts(db_session, [alert], org)
    await group_alerts(db_session, [alert], org)

    cluster = (
        await db_session.execute(select(AlertCluster).where(AlertCluster.organization_id == org))
    ).scalar_one()
    assert cluster.alert_count == 1


@pytest.mark.asyncio
async def test_a_richer_report_pulls_in_a_sparser_one(db_session, make_user):
    """Sentinel knows the user and the address; Okta only the address. They are
    one event, and must group whichever order they arrive in."""
    ctx = await make_user("grouping")
    org = ctx.org.id

    sentinel, okta = await insert(
        db_session,
        build_alert(org, source_type="sentinel", tags=["user:alice", "ip:203.0.113.9"]),
        build_alert(org, source_type="okta", tags=["ip:203.0.113.9"]),
    )
    stats = await group_alerts(db_session, [sentinel, okta], org)
    assert stats["clusters_created"] == 1


@pytest.mark.asyncio
async def test_one_org_never_groups_into_another(db_session, make_user):
    ctx_a = await make_user("org-a")
    ctx_b = await make_user("org-b")

    a, b = await insert(
        db_session,
        build_alert(ctx_a.org.id, source_type="crowdstrike"),
        build_alert(ctx_b.org.id, source_type="crowdstrike"),
    )
    await group_alerts(db_session, [a], ctx_a.org.id)
    await group_alerts(db_session, [b], ctx_b.org.id)

    clusters = (await db_session.execute(select(AlertCluster))).scalars().all()
    assert len(clusters) == 2
    assert {c.organization_id for c in clusters} == {ctx_a.org.id, ctx_b.org.id}


@pytest.mark.asyncio
async def test_only_one_cluster_can_hold_a_fingerprint_at_a_time(db_session, make_user):
    """The partial unique index is what makes two connectors syncing the same
    event concurrently converge on one cluster instead of building two."""
    ctx = await make_user("grouping")
    org = ctx.org.id

    (alert,) = await insert(db_session, build_alert(org, source_type="crowdstrike"))
    await group_alerts(db_session, [alert], org)

    active = (
        (
            await db_session.execute(
                select(AlertClusterKey).where(
                    AlertClusterKey.organization_id == org,
                    AlertClusterKey.expires_at.is_not(None),
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(active) == 1

    from sqlalchemy.exc import IntegrityError

    other = AlertCluster(
        organization_id=org,
        name="Rival",
        summary="",
        severity="low",
        cluster_type="auto_correlated",
        alert_count=0,
        first_alert_at=BASE_TIME,
        last_alert_at=BASE_TIME,
        common_entities={},
    )
    db_session.add(other)
    await db_session.flush()

    with pytest.raises(IntegrityError):
        async with db_session.begin_nested():
            db_session.add(
                AlertClusterKey(
                    organization_id=org,
                    cluster_id=other.id,
                    fingerprint=active[0].fingerprint,
                    entity_kind=active[0].entity_kind,
                    entity_value=active[0].entity_value,
                    expires_at=BASE_TIME + timedelta(hours=24),
                )
            )
            await db_session.flush()


@pytest.mark.asyncio
async def test_collapsed_list_shows_one_row_per_event(db_session, make_user, app_client):
    """The end of the complaint: one thing seen by three products is one row."""
    ctx = await make_user("grouping")
    org = ctx.org.id

    alerts = await insert(
        db_session,
        build_alert(org, source_type="crowdstrike", severity="medium"),
        build_alert(
            org, source_type="sentinel", severity="critical", at=BASE_TIME + timedelta(minutes=1)
        ),
        build_alert(org, source_type="okta", severity="low", at=BASE_TIME + timedelta(minutes=2)),
    )
    await group_alerts(db_session, alerts, org)
    await db_session.flush()

    collapsed = await app_client.get("/api/v1/connectors/alerts/unified", headers=ctx.headers)
    assert collapsed.status_code == 200
    body = collapsed.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1

    row = body["items"][0]
    assert row["cluster_alert_count"] == 3
    assert set(row["cluster_sources"]) == {"crowdstrike", "sentinel", "okta"}
    # The representative is the most severe report, not the first to sync.
    assert row["severity"] == "critical"
    assert row["source_type"] == "sentinel"

    # Severity tiles have to agree with the rows beneath them.
    assert body["severity_counts"] == {"critical": 1}


@pytest.mark.asyncio
async def test_the_raw_per_source_list_is_still_available(db_session, make_user, app_client):
    ctx = await make_user("grouping")
    org = ctx.org.id

    alerts = await insert(
        db_session,
        build_alert(org, source_type="crowdstrike"),
        build_alert(org, source_type="sentinel", at=BASE_TIME + timedelta(minutes=1)),
    )
    await group_alerts(db_session, alerts, org)
    await db_session.flush()

    expanded = await app_client.get(
        "/api/v1/connectors/alerts/unified",
        params={"collapse_duplicates": "false"},
        headers=ctx.headers,
    )
    assert expanded.status_code == 200
    body = expanded.json()
    assert body["total"] == 2
    assert {i["source_type"] for i in body["items"]} == {"crowdstrike", "sentinel"}
    assert all(i["cluster_alert_count"] == 2 for i in body["items"])


@pytest.mark.asyncio
async def test_a_cluster_with_no_representative_hides_nothing(db_session, make_user, app_client):
    """Clusters that predate grouping -- and any the manual clusterer built
    before it learned to elect one -- name no representative. Collapsing must
    fall back to listing their members rather than hiding every one of them."""
    ctx = await make_user("grouping")
    org = ctx.org.id

    alerts = await insert(
        db_session,
        build_alert(org, source_type="crowdstrike"),
        build_alert(org, source_type="sentinel", at=BASE_TIME + timedelta(minutes=1)),
    )
    await group_alerts(db_session, alerts, org)

    cluster = (
        await db_session.execute(select(AlertCluster).where(AlertCluster.organization_id == org))
    ).scalar_one()
    cluster.representative_alert_id = None
    await db_session.flush()

    response = await app_client.get("/api/v1/connectors/alerts/unified", headers=ctx.headers)
    assert response.status_code == 200
    assert response.json()["total"] == 2


@pytest.mark.asyncio
async def test_an_ungrouped_alert_is_never_hidden_by_collapsing(db_session, make_user, app_client):
    """Alerts ingested before grouping existed have no cluster. Collapsing hides
    non-representative *members*, so an alert in no cluster always shows."""
    ctx = await make_user("grouping")
    org = ctx.org.id

    await insert(db_session, build_alert(org, source_type="legacy"))
    await db_session.flush()

    response = await app_client.get("/api/v1/connectors/alerts/unified", headers=ctx.headers)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["cluster_id"] is None
    assert body["items"][0]["cluster_alert_count"] == 1
