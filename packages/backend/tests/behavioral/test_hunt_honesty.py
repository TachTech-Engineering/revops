"""
Threat-hunt result honesty: simulated results must be labeled as simulated so a
client can never mistake a placeholder for a real detection.

The hunt-query executor does not run against a real data lake yet -- it stores a
placeholder finding and flags it simulated at three levels (the API `simulated`
field, raw_results, and each finding). These tests lock that honesty labeling on
the read path, and (xfail) document a real bug that currently breaks the execute
path itself.
"""

import pytest
from sqlalchemy import select

from app.db.models import HuntResult, HuntResultStatus, UserRoleType
from tests.behavioral.factories import seed_hunt, seed_hunt_query, seed_hunt_result


@pytest.mark.asyncio
async def test_results_endpoint_surfaces_simulated_flag(app_client, make_user, db_session):
    org = await make_user("hunt-read", role=UserRoleType.ANALYST)
    hunt = await seed_hunt(db_session, org.org.id)
    query = await seed_hunt_query(db_session, hunt.id)
    await seed_hunt_result(db_session, org.org.id, hunt.id, query_id=query.id, simulated=True)

    resp = await app_client.get(
        f"/api/v1/threat-hunting/hunts/{hunt.id}/results", headers=org.headers
    )
    assert resp.status_code == 200, resp.text
    results = resp.json()
    assert len(results) == 1
    result = results[0]

    # Honesty flag surfaced at the API level.
    assert result["simulated"] is True
    # And every finding is itself marked simulated with a [SIMULATED] marker.
    assert result["findings"]
    for finding in result["findings"]:
        assert finding["simulated"] is True
        assert "[SIMULATED]" in finding["description"]


@pytest.mark.asyncio
async def test_execute_hunt_query_returns_simulated(app_client, make_user, db_session):
    org = await make_user("hunt-exec", role=UserRoleType.ANALYST)
    hunt = await seed_hunt(db_session, org.org.id)
    query = await seed_hunt_query(db_session, hunt.id)

    resp = await app_client.post(
        f"/api/v1/threat-hunting/hunts/{hunt.id}/queries/{query.id}/execute",
        json={"timeout_seconds": 30, "limit_results": 100},
        headers=org.headers,
    )
    # Desired behavior once the bug is fixed: a 200 with simulated:true.
    assert resp.status_code == 200, resp.text
    assert resp.json()["simulated"] is True

    # And it should persist a simulated result row.
    row = (
        await db_session.execute(select(HuntResult).where(HuntResult.hunt_id == hunt.id))
    ).scalar_one()
    assert row.status == HuntResultStatus.COMPLETED
    assert row.raw_results.get("simulated") is True
