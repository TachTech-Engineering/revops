"""
Role-gating breadth: routes guarded by OrgAdminDep / OrgAnalystDep must refuse
the lower role with 403 and admit the sufficient role.

Includes the sso_config admin routes (the worst pre-hardening hole): a non-admin
org member must be refused before any SSO configuration is exposed.
"""

import pytest

from app.db.models import UserRoleType


@pytest.mark.asyncio
async def test_sso_config_list_forbidden_for_non_admin(app_client, make_user):
    """A non-admin org member must be refused the SSO config listing (403)."""
    analyst = await make_user("sso-analyst", role=UserRoleType.ANALYST)
    resp = await app_client.get(
        f"/api/v1/organizations/{analyst.org.id}/sso", headers=analyst.headers
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_sso_config_list_allowed_for_admin(app_client, make_user):
    admin = await make_user("sso-admin", role=UserRoleType.ADMIN)
    resp = await app_client.get(f"/api/v1/organizations/{admin.org.id}/sso", headers=admin.headers)
    assert resp.status_code == 200
    assert resp.json()["configs"] == []


@pytest.mark.asyncio
async def test_cluster_bulk_delete_forbidden_for_analyst(app_client, make_user):
    """POST /alert-clusters/bulk-delete is OrgAdminDep: an analyst gets 403."""
    analyst = await make_user("bulk-analyst", role=UserRoleType.ANALYST)
    resp = await app_client.post(
        "/api/v1/alert-clusters/bulk-delete",
        json={"cluster_ids": []},
        headers=analyst.headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_cluster_bulk_delete_allowed_for_admin(app_client, make_user):
    admin = await make_user("bulk-admin", role=UserRoleType.ADMIN)
    resp = await app_client.post(
        "/api/v1/alert-clusters/bulk-delete",
        json={"cluster_ids": []},
        headers=admin.headers,
    )
    assert resp.status_code == 200
    assert resp.json()["deleted_count"] == 0


@pytest.mark.asyncio
async def test_ioc_create_forbidden_for_viewer(app_client, make_user):
    """POST /iocs is OrgAnalystDep: a viewer (below analyst) gets 403."""
    viewer = await make_user("ioc-viewer", role=UserRoleType.VIEWER)
    resp = await app_client.post(
        "/api/v1/iocs",
        json={"ioc_type": "domain", "value": "evil.example"},
        headers=viewer.headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_ioc_create_allowed_for_analyst(app_client, make_user):
    analyst = await make_user("ioc-analyst-ok", role=UserRoleType.ANALYST)
    resp = await app_client.post(
        "/api/v1/iocs",
        json={"ioc_type": "domain", "value": "evil.example"},
        headers=analyst.headers,
    )
    assert resp.status_code == 200
    assert resp.json()["value"] == "evil.example"
