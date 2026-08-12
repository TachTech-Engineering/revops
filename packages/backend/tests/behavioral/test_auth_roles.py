"""
Role enforcement: an analyst hitting an admin-only route gets 403; an admin
performing the same action succeeds. POST /rules/health/refresh is guarded by
OrgAdminDep.
"""

import pytest

from app.db.models import UserRoleType


@pytest.mark.asyncio
async def test_analyst_forbidden_on_admin_route(app_client, make_user):
    analyst = await make_user("role-analyst", role=UserRoleType.ANALYST)
    resp = await app_client.post("/api/v1/rules/health/refresh", headers=analyst.headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_allowed_on_admin_route(app_client, make_user):
    admin = await make_user("role-admin", role=UserRoleType.ADMIN)
    resp = await app_client.post("/api/v1/rules/health/refresh", headers=admin.headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"
