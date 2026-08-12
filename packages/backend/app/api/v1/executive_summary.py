"""
Executive Summary API

Provides high-level metrics, risk analysis, and team performance data
for executive dashboards and reporting.

NOTE: The Incident model is missing fields required for some metrics
(resolved_at, acknowledged_at, resolved_by, resolution_reason). Metrics
that cannot be computed from real data are returned as null with a
data_available=False flag — never as fabricated numbers. Schema updates
(a separate migration task) are needed for full functionality.
"""

from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgIdDep, OrgUserDep
from app.db import get_db
from app.db.models import (
    Incident,
    IncidentSeverity,
    IncidentStatus,
    NormalizedAlert,
)

router = APIRouter(prefix="/executive", tags=["executive"])


# ============================================================================
# Pydantic Models
# ============================================================================


class MetricValue(BaseModel):
    # value is None when the underlying data model cannot support the metric
    # (data_available=False). Clients must treat null as "not measured", not zero.
    value: float | None = None
    previous_value: float | None = None
    change_percent: float | None = None
    trend: str = "stable"
    data_available: bool = True


class ExecutiveMetrics(BaseModel):
    total_alerts: MetricValue
    critical_incidents: MetricValue
    mttr_hours: MetricValue
    mtta_hours: MetricValue
    compliance_score: MetricValue
    open_incidents: MetricValue
    resolved_incidents: MetricValue
    false_positive_rate: MetricValue
    period_start: datetime
    period_end: datetime


class RiskArea(BaseModel):
    category: str
    description: str
    alert_count: int
    incident_count: int
    severity_score: float
    trend: str
    change_percent: float
    top_sources: list[str] = []
    mitre_techniques: list[str] = []


class RiskAreasResponse(BaseModel):
    risk_areas: list[RiskArea]
    total_risk_score: float
    risk_trend: str
    period_start: datetime
    period_end: datetime


class TeamMemberPerformance(BaseModel):
    user_id: str
    username: str
    display_name: str
    alerts_handled: int
    incidents_resolved: int
    avg_resolution_hours: float
    escalation_rate: float
    false_positive_identifications: int
    accuracy_rate: float


class TeamPerformanceResponse(BaseModel):
    team_members: list[TeamMemberPerformance]
    # None when per-user attribution data does not exist (data_available=False).
    team_avg_resolution_hours: float | None = None
    team_total_alerts_handled: int | None = None
    team_total_incidents_resolved: int | None = None
    data_available: bool = True
    period_start: datetime
    period_end: datetime


class SLAMetric(BaseModel):
    sla_name: str
    target_hours: float
    actual_avg_hours: float
    compliance_rate: float
    breaches: int
    total_applicable: int
    trend: str


class SLAComplianceResponse(BaseModel):
    sla_metrics: list[SLAMetric]
    # None when SLA timing data cannot be computed (data_available=False).
    overall_compliance_rate: float | None = None
    total_breaches: int | None = None
    data_available: bool = True
    period_start: datetime
    period_end: datetime


# ============================================================================
# Helper Functions
# ============================================================================


def calculate_trend(current: float, previous: float) -> tuple[str, float]:
    if previous == 0:
        return ("up", 100.0) if current > 0 else ("stable", 0.0)
    change = ((current - previous) / previous) * 100
    if change > 5:
        return "up", round(change, 1)
    elif change < -5:
        return "down", round(change, 1)
    return "stable", round(change, 1)


def calculate_metric_value(current: float, previous: float | None = None) -> MetricValue:
    if previous is not None:
        trend, change = calculate_trend(current, previous)
        return MetricValue(
            value=current, previous_value=previous, change_percent=change, trend=trend
        )
    return MetricValue(value=current)


async def get_period_bounds(days: int, end_date: datetime | None = None):
    if end_date is None:
        end_date = datetime.utcnow()
    current_start = end_date - timedelta(days=days)
    current_end = end_date
    previous_end = current_start
    previous_start = previous_end - timedelta(days=days)
    return current_start, current_end, previous_start, previous_end


# ============================================================================
# Endpoints
# ============================================================================


@router.get("/metrics", response_model=ExecutiveMetrics)
async def get_executive_metrics(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    end_date: datetime | None = Query(None, description="End date for analysis"),
):
    """Get high-level executive metrics."""
    current_start, current_end, prev_start, prev_end = await get_period_bounds(days, end_date)

    # Current period alerts
    current_alerts = await db.execute(
        select(func.count(NormalizedAlert.id)).where(
            and_(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at_source >= current_start,
                NormalizedAlert.created_at_source <= current_end,
            )
        )
    )
    current_alert_count = current_alerts.scalar() or 0

    # Previous period alerts
    prev_alerts = await db.execute(
        select(func.count(NormalizedAlert.id)).where(
            and_(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at_source >= prev_start,
                NormalizedAlert.created_at_source <= prev_end,
            )
        )
    )
    prev_alert_count = prev_alerts.scalar() or 0

    # Current period critical incidents
    current_critical = await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.organization_id == org_id,
                Incident.severity == IncidentSeverity.CRITICAL,
                Incident.created_at >= current_start,
                Incident.created_at <= current_end,
            )
        )
    )
    current_critical_count = current_critical.scalar() or 0

    prev_critical = await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.organization_id == org_id,
                Incident.severity == IncidentSeverity.CRITICAL,
                Incident.created_at >= prev_start,
                Incident.created_at <= prev_end,
            )
        )
    )
    prev_critical_count = prev_critical.scalar() or 0

    # Open incidents
    open_incidents = await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status == IncidentStatus.OPEN,
            )
        )
    )
    open_count = open_incidents.scalar() or 0

    # Resolved incidents (using status=RESOLVED since resolved_at doesn't exist)
    resolved_current = await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status == IncidentStatus.RESOLVED,
                Incident.updated_at >= current_start,
                Incident.updated_at <= current_end,
            )
        )
    )
    resolved_count = resolved_current.scalar() or 0

    resolved_prev = await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status == IncidentStatus.RESOLVED,
                Incident.updated_at >= prev_start,
                Incident.updated_at <= prev_end,
            )
        )
    )
    prev_resolved_count = resolved_prev.scalar() or 0

    # MTTR/MTTA cannot be computed: the Incident model has no resolved_at or
    # acknowledged_at timestamps (adding them is a schema-migration task).
    # Compliance score and false-positive rate have no backing data either.
    # Return null with data_available=False instead of fabricated numbers.
    unavailable = MetricValue(value=None, data_available=False)

    return ExecutiveMetrics(
        total_alerts=calculate_metric_value(current_alert_count, prev_alert_count),
        critical_incidents=calculate_metric_value(current_critical_count, prev_critical_count),
        mttr_hours=unavailable,
        mtta_hours=unavailable,
        compliance_score=unavailable,
        open_incidents=calculate_metric_value(open_count),
        resolved_incidents=calculate_metric_value(resolved_count, prev_resolved_count),
        false_positive_rate=unavailable,
        period_start=current_start,
        period_end=current_end,
    )


@router.get("/risk-areas", response_model=RiskAreasResponse)
async def get_risk_areas(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    limit: int = Query(10, ge=1, le=50, description="Number of risk areas to return"),
):
    """Get top risk areas based on alert patterns."""
    current_start, current_end, prev_start, prev_end = await get_period_bounds(days)

    # Get alert counts by source type
    current_by_source = await db.execute(
        select(
            NormalizedAlert.source_type,
            func.count(NormalizedAlert.id).label("alert_count"),
            func.sum(
                case(
                    (NormalizedAlert.severity == "critical", 4),
                    (NormalizedAlert.severity == "high", 3),
                    (NormalizedAlert.severity == "medium", 2),
                    (NormalizedAlert.severity == "low", 1),
                    else_=0,
                )
            ).label("severity_sum"),
        )
        .where(
            and_(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at_source >= current_start,
                NormalizedAlert.created_at_source <= current_end,
            )
        )
        .group_by(NormalizedAlert.source_type)
        .order_by(func.count(NormalizedAlert.id).desc())
        .limit(limit)
    )
    current_sources = current_by_source.fetchall()

    # Previous period for trends
    prev_by_source = await db.execute(
        select(
            NormalizedAlert.source_type,
            func.count(NormalizedAlert.id).label("alert_count"),
        )
        .where(
            and_(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at_source >= prev_start,
                NormalizedAlert.created_at_source <= prev_end,
            )
        )
        .group_by(NormalizedAlert.source_type)
    )
    prev_source_map = {row.source_type: row.alert_count for row in prev_by_source.fetchall()}

    risk_areas = []
    total_severity = 0

    source_descriptions = {
        "crowdstrike": "Endpoint detection and response alerts",
        "sentinel": "Azure Sentinel SIEM alerts",
        "palo_alto": "Network firewall and threat prevention",
        "okta": "Identity and access management",
        "aws_guardduty": "AWS threat detection",
        "gcp_scc": "Google Cloud Security Command Center",
        "splunk": "SIEM correlation alerts",
    }

    for row in current_sources:
        source_type = row.source_type or "Unknown"
        alert_count = row.alert_count
        severity_sum = row.severity_sum or 0

        max_severity = alert_count * 4
        severity_score = (severity_sum / max_severity * 100) if max_severity > 0 else 0
        total_severity += severity_score

        prev_count = prev_source_map.get(source_type, 0)
        trend, change = calculate_trend(alert_count, prev_count)

        risk_areas.append(
            RiskArea(
                category=source_type,
                description=source_descriptions.get(
                    source_type.lower(), f"Alerts from {source_type}"
                ),
                alert_count=alert_count,
                incident_count=0,  # Placeholder - would need join with incidents
                severity_score=round(severity_score, 1),
                trend=trend,
                change_percent=change,
                top_sources=[source_type],
                mitre_techniques=[],
            )
        )

    total_current = sum(r.alert_count for r in risk_areas)
    total_prev = sum(prev_source_map.values())
    overall_trend, _ = calculate_trend(total_current, total_prev)
    avg_risk = total_severity / len(risk_areas) if risk_areas else 0

    return RiskAreasResponse(
        risk_areas=risk_areas,
        total_risk_score=round(avg_risk, 1),
        risk_trend=overall_trend,
        period_start=current_start,
        period_end=current_end,
    )


@router.get("/team-performance", response_model=TeamPerformanceResponse)
async def get_team_performance(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
):
    """Get team performance metrics.

    The current schema has no per-user attribution (NormalizedAlert lacks
    assigned_to; Incident lacks resolved_by/resolved_at), so per-member and
    aggregate performance cannot be measured. Returns an empty result with
    data_available=False rather than invented numbers.
    """
    current_start, current_end, _, _ = await get_period_bounds(days)

    return TeamPerformanceResponse(
        team_members=[],
        team_avg_resolution_hours=None,
        team_total_alerts_handled=None,
        team_total_incidents_resolved=None,
        data_available=False,
        period_start=current_start,
        period_end=current_end,
    )


@router.get("/sla-compliance", response_model=SLAComplianceResponse)
async def get_sla_compliance(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
):
    """Get SLA compliance metrics.

    SLA response/resolution times cannot be computed: the Incident model has
    no resolved_at or acknowledged_at timestamps (adding them is a
    schema-migration task). Returns an empty metric list with
    data_available=False rather than invented figures.
    """
    current_start, current_end, _, _ = await get_period_bounds(days)

    return SLAComplianceResponse(
        sla_metrics=[],
        overall_compliance_rate=None,
        total_breaches=None,
        data_available=False,
        period_start=current_start,
        period_end=current_end,
    )
