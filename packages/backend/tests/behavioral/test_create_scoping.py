"""
Org stamping on create: resources created by an org-A analyst must persist with
organization_id == A (never NULL, never B), and must not be visible to org B.

This guards the create path directly -- the write side of tenant isolation. A
NULL organization_id would make the row leak into every tenant's queries (the
same class of bug the feed NULL-org fix addressed).
"""

import pytest
from sqlalchemy import select

from app.db.models import IOC, SuppressionRule, UserRoleType


@pytest.mark.asyncio
async def test_created_ioc_is_stamped_with_creating_org(app_client, make_user, db_session):
    org_a = await make_user("ioc-create-a", role=UserRoleType.ANALYST)
    org_b = await make_user("ioc-create-b", role=UserRoleType.VIEWER)

    resp = await app_client.post(
        "/api/v1/iocs",
        json={"ioc_type": "ip_address", "value": "198.51.100.7", "severity": "high"},
        headers=org_a.headers,
    )
    assert resp.status_code == 200, resp.text
    ioc_id = resp.json()["id"]

    # Persisted with organization_id == A, never NULL, never B.
    row = (await db_session.execute(select(IOC).where(IOC.value == "198.51.100.7"))).scalar_one()
    assert row.organization_id == org_a.org.id
    assert row.organization_id is not None
    assert row.organization_id != org_b.org.id

    # Org B cannot see it -- neither in the list nor by id.
    list_b = await app_client.get("/api/v1/iocs", headers=org_b.headers)
    assert list_b.status_code == 200
    assert all(item["value"] != "198.51.100.7" for item in list_b.json()["items"])

    get_b = await app_client.get(f"/api/v1/iocs/{ioc_id}", headers=org_b.headers)
    assert get_b.status_code == 404


@pytest.mark.asyncio
async def test_created_suppression_rule_is_stamped_with_creating_org(
    app_client, make_user, db_session
):
    org_a = await make_user("supp-create-a", role=UserRoleType.ANALYST)
    org_b = await make_user("supp-create-b", role=UserRoleType.VIEWER)

    resp = await app_client.post(
        "/api/v1/suppression-rules",
        json={"name": "org-a-only-rule"},
        headers=org_a.headers,
    )
    assert resp.status_code == 200, resp.text

    row = (
        await db_session.execute(
            select(SuppressionRule).where(SuppressionRule.name == "org-a-only-rule")
        )
    ).scalar_one()
    assert row.organization_id == org_a.org.id
    assert row.organization_id is not None
    assert row.organization_id != org_b.org.id

    # Org B's listing must not include it.
    list_b = await app_client.get("/api/v1/suppression-rules", headers=org_b.headers)
    assert list_b.status_code == 200
    assert all(item["name"] != "org-a-only-rule" for item in list_b.json())
