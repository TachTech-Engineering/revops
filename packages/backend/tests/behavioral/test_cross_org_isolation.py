"""
Cross-org (tenant) isolation, security-critical.

A user in org A must get 404 (not 403, not the row) when reaching for org B's
resource on the org-scoped routers, while the owning org still gets 200. Covers
rule_health, feeds, and suppression — the routers whose tenant-isolation was
recently reworked. 404 (indistinguishable from missing) is the documented
behavior; a 403 would confirm the resource exists across tenants and is itself
a leak.
"""

import pytest

from app.db.models import UserRoleType
from tests.behavioral.factories import seed_feed, seed_rule_health, seed_suppression


@pytest.mark.asyncio
async def test_feed_get_is_tenant_isolated(app_client, make_user, db_session):
    org_a = await make_user("feed-a", role=UserRoleType.VIEWER)
    org_b = await make_user("feed-b", role=UserRoleType.VIEWER)
    feed_b = await seed_feed(db_session, org_b.org.id, name="B's feed")

    # Org A cannot see org B's feed -> 404 (not 403, no row leaked).
    resp = await app_client.get(f"/api/v1/feeds/{feed_b.id}", headers=org_a.headers)
    assert resp.status_code == 404
    assert "B's feed" not in resp.text

    # The owning org gets 200 and the real row.
    resp_owner = await app_client.get(f"/api/v1/feeds/{feed_b.id}", headers=org_b.headers)
    assert resp_owner.status_code == 200
    assert resp_owner.json()["id"] == str(feed_b.id)


@pytest.mark.asyncio
async def test_rule_health_get_is_tenant_isolated(app_client, make_user, db_session):
    org_a = await make_user("rh-a", role=UserRoleType.VIEWER)
    org_b = await make_user("rh-b", role=UserRoleType.VIEWER)
    rh_b = await seed_rule_health(db_session, org_b.org.id, rule_id="Rule.OrgB.Only")

    resp = await app_client.get(
        f"/api/v1/rules/health/{rh_b.rule_id}", headers=org_a.headers
    )
    assert resp.status_code == 404

    resp_owner = await app_client.get(
        f"/api/v1/rules/health/{rh_b.rule_id}", headers=org_b.headers
    )
    assert resp_owner.status_code == 200
    assert resp_owner.json()["rule_id"] == "Rule.OrgB.Only"


@pytest.mark.asyncio
async def test_suppression_update_is_tenant_isolated(app_client, make_user, db_session):
    # Analysts are role-authorized to PATCH; the 404 therefore proves it is the
    # tenant scope (not the role gate) that blocks cross-org access.
    org_a = await make_user("supp-a", role=UserRoleType.ANALYST)
    org_b = await make_user("supp-b", role=UserRoleType.ANALYST)
    rule_b = await seed_suppression(db_session, org_b.org.id, name="B rule")

    resp = await app_client.patch(
        f"/api/v1/suppression-rules/{rule_b.id}",
        json={"name": "hijacked"},
        headers=org_a.headers,
    )
    assert resp.status_code == 404

    resp_owner = await app_client.patch(
        f"/api/v1/suppression-rules/{rule_b.id}",
        json={"name": "renamed-by-owner"},
        headers=org_b.headers,
    )
    assert resp_owner.status_code == 200
    assert resp_owner.json()["name"] == "renamed-by-owner"
