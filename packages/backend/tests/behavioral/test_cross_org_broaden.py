"""
Cross-org (tenant) isolation, broadened to more org-scoped routers.

Extends test_cross_org_isolation.py (feeds/rule_health/suppression) to iocs,
cases, alert_clusters and notifications. In every case a user in org A must get
404 (not 403, not the row) when reaching for org B's resource, and list
endpoints must return only the caller's own tenant rows. 404 -- indistinguishable
from a missing row -- is the documented behavior; a 403 or a leaked row would
confirm the resource exists across tenants.
"""

import pytest

from app.db.models import UserRoleType
from tests.behavioral.factories import (
    seed_alert_cluster,
    seed_case,
    seed_ioc,
    seed_notification,
)


@pytest.mark.asyncio
async def test_ioc_get_is_tenant_isolated(app_client, make_user, db_session):
    org_a = await make_user("ioc-a", role=UserRoleType.VIEWER)
    org_b = await make_user("ioc-b", role=UserRoleType.VIEWER)
    ioc_b = await seed_ioc(db_session, org_b.org.id, value="203.0.113.55")

    resp = await app_client.get(f"/api/v1/iocs/{ioc_b.id}", headers=org_a.headers)
    assert resp.status_code == 404
    assert "203.0.113.55" not in resp.text

    resp_owner = await app_client.get(f"/api/v1/iocs/{ioc_b.id}", headers=org_b.headers)
    assert resp_owner.status_code == 200
    assert resp_owner.json()["value"] == "203.0.113.55"


@pytest.mark.asyncio
async def test_ioc_list_returns_only_own_org(app_client, make_user, db_session):
    org_a = await make_user("ioc-list-a", role=UserRoleType.VIEWER)
    org_b = await make_user("ioc-list-b", role=UserRoleType.VIEWER)
    await seed_ioc(db_session, org_a.org.id, value="10.0.0.1")
    await seed_ioc(db_session, org_b.org.id, value="10.0.0.2")

    resp = await app_client.get("/api/v1/iocs", headers=org_a.headers)
    assert resp.status_code == 200
    body = resp.json()
    values = {item["value"] for item in body["items"]}
    assert values == {"10.0.0.1"}
    assert body["total"] == 1


@pytest.mark.asyncio
async def test_case_get_is_tenant_isolated(app_client, make_user, db_session):
    org_a = await make_user("case-a", role=UserRoleType.VIEWER)
    org_b = await make_user("case-b", role=UserRoleType.VIEWER)
    case_b = await seed_case(db_session, org_b.org.id, title="B confidential case")

    resp = await app_client.get(f"/api/v1/cases/{case_b.id}", headers=org_a.headers)
    assert resp.status_code == 404
    assert "confidential" not in resp.text

    resp_owner = await app_client.get(f"/api/v1/cases/{case_b.id}", headers=org_b.headers)
    assert resp_owner.status_code == 200
    assert resp_owner.json()["id"] == str(case_b.id)


@pytest.mark.asyncio
async def test_alert_cluster_get_is_tenant_isolated(app_client, make_user, db_session):
    org_a = await make_user("clu-a", role=UserRoleType.VIEWER)
    org_b = await make_user("clu-b", role=UserRoleType.VIEWER)
    cluster_b = await seed_alert_cluster(db_session, org_b.org.id, name="B secret cluster")

    resp = await app_client.get(
        f"/api/v1/alert-clusters/{cluster_b.id}", headers=org_a.headers
    )
    assert resp.status_code == 404
    assert "secret" not in resp.text

    resp_owner = await app_client.get(
        f"/api/v1/alert-clusters/{cluster_b.id}", headers=org_b.headers
    )
    assert resp_owner.status_code == 200
    assert resp_owner.json()["id"] == str(cluster_b.id)


@pytest.mark.asyncio
async def test_notification_get_is_tenant_isolated(app_client, make_user, db_session):
    org_a = await make_user("notif-a", role=UserRoleType.VIEWER)
    org_b = await make_user("notif-b", role=UserRoleType.VIEWER)
    notif_b = await seed_notification(
        db_session, org_b.org.id, user_email=org_b.user.email, title="B private note"
    )

    resp = await app_client.get(
        f"/api/v1/notifications/{notif_b.id}", headers=org_a.headers
    )
    assert resp.status_code == 404
    assert "private" not in resp.text

    resp_owner = await app_client.get(
        f"/api/v1/notifications/{notif_b.id}", headers=org_b.headers
    )
    assert resp_owner.status_code == 200
    assert resp_owner.json()["id"] == str(notif_b.id)
