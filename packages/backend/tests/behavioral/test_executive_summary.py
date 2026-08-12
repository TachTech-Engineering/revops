"""
executive_summary data honesty (fabricated-metrics fix).

For an org with no incident/alert data, metrics that cannot be computed from the
real schema (MTTR, MTTA, compliance, false-positive rate, SLA compliance, team
performance) must be reported as data_available=false with null values — never
as invented numbers. Metrics that CAN be counted (total_alerts) return a real 0.
"""

import pytest

from app.db.models import UserRoleType


@pytest.mark.asyncio
async def test_metrics_report_unavailable_not_fabricated(app_client, make_user):
    org = await make_user("exec", role=UserRoleType.VIEWER)

    resp = await app_client.get("/api/v1/executive/metrics", headers=org.headers)
    assert resp.status_code == 200
    data = resp.json()

    # Non-computable metrics: honest nulls, never fabricated 4.5 / 91.3 figures.
    for key in ("mttr_hours", "mtta_hours", "compliance_score", "false_positive_rate"):
        assert data[key]["data_available"] is False, key
        assert data[key]["value"] is None, key

    # Countable metrics remain real (0 for an empty org), flagged available.
    assert data["total_alerts"]["data_available"] is True
    assert data["total_alerts"]["value"] == 0
    assert data["open_incidents"]["value"] == 0


@pytest.mark.asyncio
async def test_sla_compliance_reports_unavailable(app_client, make_user):
    org = await make_user("exec-sla", role=UserRoleType.VIEWER)

    resp = await app_client.get("/api/v1/executive/sla-compliance", headers=org.headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["data_available"] is False
    assert data["overall_compliance_rate"] is None
    assert data["total_breaches"] is None
    assert data["sla_metrics"] == []


@pytest.mark.asyncio
async def test_team_performance_reports_unavailable(app_client, make_user):
    org = await make_user("exec-team", role=UserRoleType.VIEWER)

    resp = await app_client.get("/api/v1/executive/team-performance", headers=org.headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["data_available"] is False
    assert data["team_avg_resolution_hours"] is None
    assert data["team_members"] == []
