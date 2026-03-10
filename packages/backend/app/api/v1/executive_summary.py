"""
Executive Summary API

Provides high-level metrics, risk analysis, and team performance data
for executive dashboards and reporting.
"""

import io
import logging
from datetime import datetime, timedelta
from typing import Annotated, Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, case, extract
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.db.models import (
    NormalizedAlert,
    Incident,
    IncidentStatus,
    IncidentSeverity,
    ComplianceFramework,
    ComplianceControl,
    ComplianceStatus,
)
from app.api.v1.deps import OrgUserDep, OrgIdDep

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/executive", tags=["executive"])


# ============================================================================
# Pydantic Models
# ============================================================================

class TimeRange(BaseModel):
    """Time range for metrics queries."""
    start_date: datetime
    end_date: datetime


class MetricValue(BaseModel):
    """A single metric with value and trend."""
    value: float
    previous_value: Optional[float] = None
    change_percent: Optional[float] = None
    trend: str = "stable"  # up, down, stable


class ExecutiveMetrics(BaseModel):
    """High-level executive metrics."""
    total_alerts: MetricValue
    critical_incidents: MetricValue
    mttr_hours: MetricValue  # Mean Time To Resolution
    mtta_hours: MetricValue  # Mean Time To Acknowledge
    compliance_score: MetricValue
    open_incidents: MetricValue
    resolved_incidents: MetricValue
    false_positive_rate: MetricValue
    period_start: datetime
    period_end: datetime


class RiskArea(BaseModel):
    """A risk area with severity and trend data."""
    category: str
    description: str
    alert_count: int
    incident_count: int
    severity_score: float  # 0-100
    trend: str  # up, down, stable
    change_percent: float
    top_sources: List[str] = []
    mitre_techniques: List[str] = []


class RiskAreasResponse(BaseModel):
    """Response containing top risk areas."""
    risk_areas: List[RiskArea]
    total_risk_score: float
    risk_trend: str
    period_start: datetime
    period_end: datetime


class TeamMemberPerformance(BaseModel):
    """Performance metrics for a team member."""
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
    """Team performance metrics response."""
    team_members: List[TeamMemberPerformance]
    team_avg_resolution_hours: float
    team_total_alerts_handled: int
    team_total_incidents_resolved: int
    period_start: datetime
    period_end: datetime


class SLAMetric(BaseModel):
    """SLA compliance metric."""
    sla_name: str
    target_hours: float
    actual_avg_hours: float
    compliance_rate: float  # 0-100%
    breaches: int
    total_applicable: int
    trend: str


class SLAComplianceResponse(BaseModel):
    """SLA compliance response."""
    sla_metrics: List[SLAMetric]
    overall_compliance_rate: float
    total_breaches: int
    period_start: datetime
    period_end: datetime


class ExportRequest(BaseModel):
    """Request for exporting executive report."""
    start_date: datetime
    end_date: datetime
    include_metrics: bool = True
    include_risk_areas: bool = True
    include_team_performance: bool = True
    include_sla_compliance: bool = True
    format: str = "pdf"  # pdf, csv


# ============================================================================
# Helper Functions
# ============================================================================

def calculate_trend(current: float, previous: float) -> tuple[str, float]:
    """Calculate trend direction and percentage change."""
    if previous == 0:
        if current > 0:
            return "up", 100.0
        return "stable", 0.0

    change = ((current - previous) / previous) * 100
    if change > 5:
        return "up", round(change, 1)
    elif change < -5:
        return "down", round(change, 1)
    return "stable", round(change, 1)


def calculate_metric_value(
    current: float,
    previous: Optional[float] = None
) -> MetricValue:
    """Create a MetricValue with trend calculation."""
    if previous is not None:
        trend, change = calculate_trend(current, previous)
        return MetricValue(
            value=current,
            previous_value=previous,
            change_percent=change,
            trend=trend
        )
    return MetricValue(value=current)


async def get_period_bounds(
    days: int,
    end_date: Optional[datetime] = None
) -> tuple[datetime, datetime, datetime, datetime]:
    """Get current and previous period bounds for trend comparison."""
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
    end_date: Optional[datetime] = Query(None, description="End date for analysis"),
):
    """
    Get high-level executive metrics including alerts, incidents, MTTR, and compliance.

    Compares current period with previous period to show trends.
    """
    current_start, current_end, prev_start, prev_end = await get_period_bounds(
        days, end_date
    )

    # Current period alerts
    current_alerts = await db.execute(
        select(func.count(NormalizedAlert.id)).where(
            and_(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at >= current_start,
                NormalizedAlert.created_at <= current_end,
            )
        )
    )
    current_alert_count = current_alerts.scalar() or 0

    # Previous period alerts
    prev_alerts = await db.execute(
        select(func.count(NormalizedAlert.id)).where(
            and_(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at >= prev_start,
                NormalizedAlert.created_at <= prev_end,
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

    # Previous period critical incidents
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

    # MTTR (Mean Time To Resolution) - current period
    # Using resolved_at - created_at for resolved incidents
    mttr_query = await db.execute(
        select(
            func.avg(
                extract('epoch', Incident.resolved_at) -
                extract('epoch', Incident.created_at)
            ) / 3600  # Convert to hours
        ).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status == IncidentStatus.RESOLVED,
                Incident.resolved_at.isnot(None),
                Incident.resolved_at >= current_start,
                Incident.resolved_at <= current_end,
            )
        )
    )
    current_mttr = mttr_query.scalar() or 0

    # MTTR - previous period
    prev_mttr_query = await db.execute(
        select(
            func.avg(
                extract('epoch', Incident.resolved_at) -
                extract('epoch', Incident.created_at)
            ) / 3600
        ).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status == IncidentStatus.RESOLVED,
                Incident.resolved_at.isnot(None),
                Incident.resolved_at >= prev_start,
                Incident.resolved_at <= prev_end,
            )
        )
    )
    prev_mttr = prev_mttr_query.scalar() or 0

    # MTTA (Mean Time To Acknowledge) - using first assignment/status change
    # Approximated by time from creation to first update
    mtta_query = await db.execute(
        select(
            func.avg(
                extract('epoch', Incident.updated_at) -
                extract('epoch', Incident.created_at)
            ) / 3600
        ).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status != IncidentStatus.OPEN,
                Incident.created_at >= current_start,
                Incident.created_at <= current_end,
            )
        )
    )
    current_mtta = mtta_query.scalar() or 0

    prev_mtta_query = await db.execute(
        select(
            func.avg(
                extract('epoch', Incident.updated_at) -
                extract('epoch', Incident.created_at)
            ) / 3600
        ).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status != IncidentStatus.OPEN,
                Incident.created_at >= prev_start,
                Incident.created_at <= prev_end,
            )
        )
    )
    prev_mtta = prev_mtta_query.scalar() or 0

    # Open incidents count
    open_incidents = await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status == IncidentStatus.OPEN,
            )
        )
    )
    open_count = open_incidents.scalar() or 0

    # Resolved incidents in current period
    resolved_current = await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status == IncidentStatus.RESOLVED,
                Incident.resolved_at >= current_start,
                Incident.resolved_at <= current_end,
            )
        )
    )
    resolved_count = resolved_current.scalar() or 0

    resolved_prev = await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status == IncidentStatus.RESOLVED,
                Incident.resolved_at >= prev_start,
                Incident.resolved_at <= prev_end,
            )
        )
    )
    prev_resolved_count = resolved_prev.scalar() or 0

    # False positive rate (incidents closed as false positive / total closed)
    false_positives = await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status == IncidentStatus.CLOSED,
                Incident.resolution_reason == "false_positive",
                Incident.updated_at >= current_start,
                Incident.updated_at <= current_end,
            )
        )
    )
    fp_count = false_positives.scalar() or 0

    total_closed = await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status.in_([IncidentStatus.CLOSED, IncidentStatus.RESOLVED]),
                Incident.updated_at >= current_start,
                Incident.updated_at <= current_end,
            )
        )
    )
    total_closed_count = total_closed.scalar() or 0
    fp_rate = (fp_count / total_closed_count * 100) if total_closed_count > 0 else 0

    # Previous period FP rate
    prev_fp = await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status == IncidentStatus.CLOSED,
                Incident.resolution_reason == "false_positive",
                Incident.updated_at >= prev_start,
                Incident.updated_at <= prev_end,
            )
        )
    )
    prev_fp_count = prev_fp.scalar() or 0

    prev_total_closed = await db.execute(
        select(func.count(Incident.id)).where(
            and_(
                Incident.organization_id == org_id,
                Incident.status.in_([IncidentStatus.CLOSED, IncidentStatus.RESOLVED]),
                Incident.updated_at >= prev_start,
                Incident.updated_at <= prev_end,
            )
        )
    )
    prev_total_closed_count = prev_total_closed.scalar() or 0
    prev_fp_rate = (prev_fp_count / prev_total_closed_count * 100) if prev_total_closed_count > 0 else 0

    # Compliance score from compliance frameworks
    compliance_query = await db.execute(
        select(func.avg(ComplianceFramework.coverage_percentage)).where(
            and_(
                ComplianceFramework.organization_id == org_id,
                ComplianceFramework.is_active == True,
            )
        )
    )
    compliance_score = compliance_query.scalar() or 0

    return ExecutiveMetrics(
        total_alerts=calculate_metric_value(current_alert_count, prev_alert_count),
        critical_incidents=calculate_metric_value(current_critical_count, prev_critical_count),
        mttr_hours=calculate_metric_value(round(current_mttr, 2), round(prev_mttr, 2)),
        mtta_hours=calculate_metric_value(round(current_mtta, 2), round(prev_mtta, 2)),
        compliance_score=calculate_metric_value(round(compliance_score, 1)),
        open_incidents=calculate_metric_value(open_count),
        resolved_incidents=calculate_metric_value(resolved_count, prev_resolved_count),
        false_positive_rate=calculate_metric_value(round(fp_rate, 1), round(prev_fp_rate, 1)),
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
    """
    Get top risk areas based on alert/incident patterns.

    Risk areas are categorized by source type, with severity scoring and trends.
    """
    current_start, current_end, prev_start, prev_end = await get_period_bounds(days)

    # Get alert counts by source type for current period
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
                    else_=0
                )
            ).label("severity_sum"),
        ).where(
            and_(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at >= current_start,
                NormalizedAlert.created_at <= current_end,
            )
        ).group_by(NormalizedAlert.source_type)
        .order_by(func.count(NormalizedAlert.id).desc())
        .limit(limit)
    )
    current_sources = current_by_source.fetchall()

    # Get previous period data for trend comparison
    prev_by_source = await db.execute(
        select(
            NormalizedAlert.source_type,
            func.count(NormalizedAlert.id).label("alert_count"),
        ).where(
            and_(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at >= prev_start,
                NormalizedAlert.created_at <= prev_end,
            )
        ).group_by(NormalizedAlert.source_type)
    )
    prev_source_map = {row.source_type: row.alert_count for row in prev_by_source.fetchall()}

    # Build risk areas
    risk_areas = []
    total_severity = 0

    for row in current_sources:
        source_type = row.source_type or "Unknown"
        alert_count = row.alert_count
        severity_sum = row.severity_sum or 0

        # Calculate severity score (0-100)
        max_severity = alert_count * 4  # Maximum if all critical
        severity_score = (severity_sum / max_severity * 100) if max_severity > 0 else 0
        total_severity += severity_score

        # Calculate trend
        prev_count = prev_source_map.get(source_type, 0)
        trend, change = calculate_trend(alert_count, prev_count)

        # Get incident count for this source
        incident_query = await db.execute(
            select(func.count(Incident.id)).where(
                and_(
                    Incident.organization_id == org_id,
                    Incident.tags.contains([f"source:{source_type}"]),
                    Incident.created_at >= current_start,
                    Incident.created_at <= current_end,
                )
            )
        )
        incident_count = incident_query.scalar() or 0

        # Source type descriptions
        source_descriptions = {
            "crowdstrike": "Endpoint detection and response alerts",
            "sentinel": "Azure Sentinel SIEM alerts",
            "palo_alto": "Network firewall and threat prevention",
            "okta": "Identity and access management",
            "aws_guardduty": "AWS threat detection",
            "gcp_scc": "Google Cloud Security Command Center",
            "splunk": "SIEM correlation alerts",
        }

        risk_areas.append(RiskArea(
            category=source_type,
            description=source_descriptions.get(source_type.lower(), f"Alerts from {source_type}"),
            alert_count=alert_count,
            incident_count=incident_count,
            severity_score=round(severity_score, 1),
            trend=trend,
            change_percent=change,
            top_sources=[source_type],
            mitre_techniques=[],  # Would need MITRE mapping data
        ))

    # Calculate overall risk trend
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
    """
    Get team performance metrics for SOC analysts.

    Includes alerts handled, resolution times, and accuracy rates.
    """
    current_start, current_end, _, _ = await get_period_bounds(days)

    # Get all users in the organization who have handled incidents
    users_query = await db.execute(
        select(User).where(
            User.organization_id == org_id
        )
    )
    users = users_query.scalars().all()

    team_members = []
    total_resolution_hours = 0
    total_alerts = 0
    total_resolved = 0

    for user in users:
        # Alerts assigned to this user
        alerts_handled = await db.execute(
            select(func.count(NormalizedAlert.id)).where(
                and_(
                    NormalizedAlert.organization_id == org_id,
                    NormalizedAlert.assigned_to == str(user.id),
                    NormalizedAlert.created_at >= current_start,
                    NormalizedAlert.created_at <= current_end,
                )
            )
        )
        alert_count = alerts_handled.scalar() or 0

        if alert_count == 0:
            continue  # Skip users with no activity

        # Incidents resolved by this user
        resolved_query = await db.execute(
            select(func.count(Incident.id)).where(
                and_(
                    Incident.organization_id == org_id,
                    Incident.resolved_by == str(user.id),
                    Incident.resolved_at >= current_start,
                    Incident.resolved_at <= current_end,
                )
            )
        )
        incidents_resolved = resolved_query.scalar() or 0

        # Average resolution time for this user
        avg_resolution = await db.execute(
            select(
                func.avg(
                    extract('epoch', Incident.resolved_at) -
                    extract('epoch', Incident.created_at)
                ) / 3600
            ).where(
                and_(
                    Incident.organization_id == org_id,
                    Incident.resolved_by == str(user.id),
                    Incident.resolved_at.isnot(None),
                    Incident.resolved_at >= current_start,
                    Incident.resolved_at <= current_end,
                )
            )
        )
        avg_hours = avg_resolution.scalar() or 0

        # Escalation rate (incidents escalated / total incidents)
        escalated = await db.execute(
            select(func.count(Incident.id)).where(
                and_(
                    Incident.organization_id == org_id,
                    Incident.assigned_to == str(user.id),
                    Incident.tags.contains(["escalated"]),
                    Incident.created_at >= current_start,
                    Incident.created_at <= current_end,
                )
            )
        )
        escalated_count = escalated.scalar() or 0

        total_user_incidents = await db.execute(
            select(func.count(Incident.id)).where(
                and_(
                    Incident.organization_id == org_id,
                    Incident.assigned_to == str(user.id),
                    Incident.created_at >= current_start,
                    Incident.created_at <= current_end,
                )
            )
        )
        total_user_incident_count = total_user_incidents.scalar() or 0
        escalation_rate = (escalated_count / total_user_incident_count * 100) if total_user_incident_count > 0 else 0

        # False positive identifications
        fp_identified = await db.execute(
            select(func.count(Incident.id)).where(
                and_(
                    Incident.organization_id == org_id,
                    Incident.resolved_by == str(user.id),
                    Incident.resolution_reason == "false_positive",
                    Incident.resolved_at >= current_start,
                    Incident.resolved_at <= current_end,
                )
            )
        )
        fp_count = fp_identified.scalar() or 0

        # Accuracy rate (non-false-positive resolutions / total resolutions)
        accuracy = ((incidents_resolved - fp_count) / incidents_resolved * 100) if incidents_resolved > 0 else 100

        team_members.append(TeamMemberPerformance(
            user_id=str(user.id),
            username=user.username,
            display_name=user.display_name or user.username,
            alerts_handled=alert_count,
            incidents_resolved=incidents_resolved,
            avg_resolution_hours=round(avg_hours, 2),
            escalation_rate=round(escalation_rate, 1),
            false_positive_identifications=fp_count,
            accuracy_rate=round(accuracy, 1),
        ))

        total_resolution_hours += avg_hours * incidents_resolved
        total_alerts += alert_count
        total_resolved += incidents_resolved

    # Sort by incidents resolved descending
    team_members.sort(key=lambda x: x.incidents_resolved, reverse=True)

    team_avg = (total_resolution_hours / total_resolved) if total_resolved > 0 else 0

    return TeamPerformanceResponse(
        team_members=team_members,
        team_avg_resolution_hours=round(team_avg, 2),
        team_total_alerts_handled=total_alerts,
        team_total_incidents_resolved=total_resolved,
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
    """
    Get SLA compliance metrics.

    Tracks response and resolution times against defined SLA targets.
    """
    current_start, current_end, prev_start, prev_end = await get_period_bounds(days)

    # Define SLA targets by severity
    sla_targets = {
        "critical_response": {"name": "Critical Response", "target_hours": 0.25, "severity": "critical", "type": "response"},
        "critical_resolution": {"name": "Critical Resolution", "target_hours": 4, "severity": "critical", "type": "resolution"},
        "high_response": {"name": "High Response", "target_hours": 1, "severity": "high", "type": "response"},
        "high_resolution": {"name": "High Resolution", "target_hours": 8, "severity": "high", "type": "resolution"},
        "medium_response": {"name": "Medium Response", "target_hours": 4, "severity": "medium", "type": "response"},
        "medium_resolution": {"name": "Medium Resolution", "target_hours": 24, "severity": "medium", "type": "resolution"},
        "low_response": {"name": "Low Response", "target_hours": 8, "severity": "low", "type": "response"},
        "low_resolution": {"name": "Low Resolution", "target_hours": 72, "severity": "low", "type": "resolution"},
    }

    severity_map = {
        "critical": IncidentSeverity.CRITICAL,
        "high": IncidentSeverity.HIGH,
        "medium": IncidentSeverity.MEDIUM,
        "low": IncidentSeverity.LOW,
    }

    sla_metrics = []
    total_breaches = 0
    total_applicable = 0
    total_compliance = 0

    for sla_key, sla_config in sla_targets.items():
        severity_enum = severity_map.get(sla_config["severity"])
        target_hours = sla_config["target_hours"]

        if sla_config["type"] == "response":
            # Response time = first update - created
            time_query = await db.execute(
                select(
                    func.count(Incident.id).label("total"),
                    func.avg(
                        extract('epoch', Incident.updated_at) -
                        extract('epoch', Incident.created_at)
                    ).label("avg_seconds"),
                    func.sum(
                        case(
                            (
                                (extract('epoch', Incident.updated_at) -
                                 extract('epoch', Incident.created_at)) > target_hours * 3600,
                                1
                            ),
                            else_=0
                        )
                    ).label("breaches"),
                ).where(
                    and_(
                        Incident.organization_id == org_id,
                        Incident.severity == severity_enum,
                        Incident.status != IncidentStatus.OPEN,
                        Incident.created_at >= current_start,
                        Incident.created_at <= current_end,
                    )
                )
            )
        else:
            # Resolution time = resolved_at - created
            time_query = await db.execute(
                select(
                    func.count(Incident.id).label("total"),
                    func.avg(
                        extract('epoch', Incident.resolved_at) -
                        extract('epoch', Incident.created_at)
                    ).label("avg_seconds"),
                    func.sum(
                        case(
                            (
                                (extract('epoch', Incident.resolved_at) -
                                 extract('epoch', Incident.created_at)) > target_hours * 3600,
                                1
                            ),
                            else_=0
                        )
                    ).label("breaches"),
                ).where(
                    and_(
                        Incident.organization_id == org_id,
                        Incident.severity == severity_enum,
                        Incident.status == IncidentStatus.RESOLVED,
                        Incident.resolved_at.isnot(None),
                        Incident.resolved_at >= current_start,
                        Incident.resolved_at <= current_end,
                    )
                )
            )

        row = time_query.fetchone()
        total = row.total or 0
        avg_seconds = row.avg_seconds or 0
        breaches = row.breaches or 0

        avg_hours = avg_seconds / 3600 if avg_seconds else 0
        compliance_rate = ((total - breaches) / total * 100) if total > 0 else 100

        # Calculate trend by comparing with previous period
        if sla_config["type"] == "response":
            prev_query = await db.execute(
                select(
                    func.count(Incident.id).label("total"),
                    func.sum(
                        case(
                            (
                                (extract('epoch', Incident.updated_at) -
                                 extract('epoch', Incident.created_at)) > target_hours * 3600,
                                1
                            ),
                            else_=0
                        )
                    ).label("breaches"),
                ).where(
                    and_(
                        Incident.organization_id == org_id,
                        Incident.severity == severity_enum,
                        Incident.status != IncidentStatus.OPEN,
                        Incident.created_at >= prev_start,
                        Incident.created_at <= prev_end,
                    )
                )
            )
        else:
            prev_query = await db.execute(
                select(
                    func.count(Incident.id).label("total"),
                    func.sum(
                        case(
                            (
                                (extract('epoch', Incident.resolved_at) -
                                 extract('epoch', Incident.created_at)) > target_hours * 3600,
                                1
                            ),
                            else_=0
                        )
                    ).label("breaches"),
                ).where(
                    and_(
                        Incident.organization_id == org_id,
                        Incident.severity == severity_enum,
                        Incident.status == IncidentStatus.RESOLVED,
                        Incident.resolved_at.isnot(None),
                        Incident.resolved_at >= prev_start,
                        Incident.resolved_at <= prev_end,
                    )
                )
            )

        prev_row = prev_query.fetchone()
        prev_total = prev_row.total or 0
        prev_breaches = prev_row.breaches or 0
        prev_compliance = ((prev_total - prev_breaches) / prev_total * 100) if prev_total > 0 else 100

        trend, _ = calculate_trend(compliance_rate, prev_compliance)

        sla_metrics.append(SLAMetric(
            sla_name=sla_config["name"],
            target_hours=target_hours,
            actual_avg_hours=round(avg_hours, 2),
            compliance_rate=round(compliance_rate, 1),
            breaches=breaches,
            total_applicable=total,
            trend=trend,
        ))

        total_breaches += breaches
        total_applicable += total
        if total > 0:
            total_compliance += compliance_rate

    overall_compliance = (total_compliance / len(sla_metrics)) if sla_metrics else 100

    return SLAComplianceResponse(
        sla_metrics=sla_metrics,
        overall_compliance_rate=round(overall_compliance, 1),
        total_breaches=total_breaches,
        period_start=current_start,
        period_end=current_end,
    )


@router.post("/export")
async def export_executive_report(
    request: ExportRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    org_id: OrgIdDep,
    user: OrgUserDep,
):
    """
    Export executive report as PDF or CSV.

    Generates a comprehensive report with all selected sections.
    """
    days = (request.end_date - request.start_date).days

    # Gather all requested data
    report_data = {
        "generated_at": datetime.utcnow().isoformat(),
        "period_start": request.start_date.isoformat(),
        "period_end": request.end_date.isoformat(),
        "generated_by": user.username,
    }

    if request.include_metrics:
        metrics = await get_executive_metrics(
            days=days,
            end_date=request.end_date,
            db=db,
            organization_id=organization_id,
            current_user=current_user,
        )
        report_data["metrics"] = metrics.model_dump()

    if request.include_risk_areas:
        risk_areas = await get_risk_areas(
            days=days,
            limit=10,
            db=db,
            organization_id=organization_id,
            current_user=current_user,
        )
        report_data["risk_areas"] = risk_areas.model_dump()

    if request.include_team_performance:
        team_perf = await get_team_performance(
            days=days,
            db=db,
            organization_id=organization_id,
            current_user=current_user,
        )
        report_data["team_performance"] = team_perf.model_dump()

    if request.include_sla_compliance:
        sla_data = await get_sla_compliance(
            days=days,
            db=db,
            organization_id=organization_id,
            current_user=current_user,
        )
        report_data["sla_compliance"] = sla_data.model_dump()

    if request.format == "csv":
        # Generate CSV export
        output = io.StringIO()

        # Executive Summary Section
        output.write("EXECUTIVE SUMMARY REPORT\n")
        output.write(f"Period: {request.start_date.date()} to {request.end_date.date()}\n")
        output.write(f"Generated: {datetime.utcnow().isoformat()}\n\n")

        if "metrics" in report_data:
            output.write("KEY METRICS\n")
            output.write("Metric,Current Value,Previous Value,Change %,Trend\n")
            metrics = report_data["metrics"]
            for metric_name in ["total_alerts", "critical_incidents", "mttr_hours", "mtta_hours",
                               "compliance_score", "open_incidents", "resolved_incidents", "false_positive_rate"]:
                m = metrics.get(metric_name, {})
                output.write(f"{metric_name},{m.get('value', 0)},{m.get('previous_value', 'N/A')},"
                           f"{m.get('change_percent', 'N/A')},{m.get('trend', 'N/A')}\n")
            output.write("\n")

        if "risk_areas" in report_data:
            output.write("TOP RISK AREAS\n")
            output.write("Category,Alert Count,Incident Count,Severity Score,Trend,Change %\n")
            for area in report_data["risk_areas"].get("risk_areas", []):
                output.write(f"{area['category']},{area['alert_count']},{area['incident_count']},"
                           f"{area['severity_score']},{area['trend']},{area['change_percent']}\n")
            output.write("\n")

        if "team_performance" in report_data:
            output.write("TEAM PERFORMANCE\n")
            output.write("Name,Alerts Handled,Incidents Resolved,Avg Resolution Hours,Escalation Rate %,Accuracy Rate %\n")
            for member in report_data["team_performance"].get("team_members", []):
                output.write(f"{member['display_name']},{member['alerts_handled']},{member['incidents_resolved']},"
                           f"{member['avg_resolution_hours']},{member['escalation_rate']},{member['accuracy_rate']}\n")
            output.write("\n")

        if "sla_compliance" in report_data:
            output.write("SLA COMPLIANCE\n")
            output.write("SLA Name,Target Hours,Actual Avg Hours,Compliance Rate %,Breaches,Total Applicable\n")
            for sla in report_data["sla_compliance"].get("sla_metrics", []):
                output.write(f"{sla['sla_name']},{sla['target_hours']},{sla['actual_avg_hours']},"
                           f"{sla['compliance_rate']},{sla['breaches']},{sla['total_applicable']}\n")

        csv_content = output.getvalue()

        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=executive_report_{request.start_date.date()}_{request.end_date.date()}.csv"
            }
        )

    else:
        # For PDF, return JSON that frontend will convert to PDF
        # In production, use a library like reportlab or weasyprint
        return {
            "format": "json",
            "note": "PDF generation requires frontend rendering or server-side PDF library",
            "data": report_data
        }
