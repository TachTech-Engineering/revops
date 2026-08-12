from datetime import datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAnalystDep, OrgIdDep, OrgUserDep
from app.core.time_utils import utcnow
from app.db import SLAMetric, SLAPolicy, SLAStatus, get_db

router = APIRouter()


class SLAPolicyCreate(BaseModel):
    name: str
    description: str | None = None
    ack_time_critical: int = 15
    ack_time_high: int = 60
    ack_time_medium: int = 240
    ack_time_low: int = 1440
    resolve_time_critical: int = 240
    resolve_time_high: int = 480
    resolve_time_medium: int = 1440
    resolve_time_low: int = 4320
    is_default: bool = False
    is_active: bool = True
    rule_ids: list[str] = []


class SLAPolicyUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    ack_time_critical: int | None = None
    ack_time_high: int | None = None
    ack_time_medium: int | None = None
    ack_time_low: int | None = None
    resolve_time_critical: int | None = None
    resolve_time_high: int | None = None
    resolve_time_medium: int | None = None
    resolve_time_low: int | None = None
    is_default: bool | None = None
    is_active: bool | None = None
    rule_ids: list[str] | None = None


class SLAPolicyResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    ack_time_critical: int
    ack_time_high: int
    ack_time_medium: int
    ack_time_low: int
    resolve_time_critical: int
    resolve_time_high: int
    resolve_time_medium: int
    resolve_time_low: int
    is_default: bool
    is_active: bool
    rule_ids: list[str]
    created_by: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class SLAMetricResponse(BaseModel):
    id: UUID
    alert_id: str
    policy_id: UUID
    severity: str
    alert_created_at: str
    acknowledged_at: str | None
    resolved_at: str | None
    ack_target_minutes: int
    resolve_target_minutes: int
    ack_status: SLAStatus
    resolve_status: SLAStatus
    ack_time_minutes: int | None
    resolve_time_minutes: int | None
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class SLASummary(BaseModel):
    total_alerts: int
    on_track: int
    at_risk: int
    breached: int
    avg_ack_time_minutes: float | None
    avg_resolve_time_minutes: float | None
    ack_compliance_rate: float
    resolve_compliance_rate: float


class SLADashboardResponse(BaseModel):
    summary: SLASummary
    by_severity: dict[str, SLASummary]
    recent_breaches: list[SLAMetricResponse]


def format_policy(policy: SLAPolicy) -> SLAPolicyResponse:
    return SLAPolicyResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        ack_time_critical=policy.ack_time_critical,
        ack_time_high=policy.ack_time_high,
        ack_time_medium=policy.ack_time_medium,
        ack_time_low=policy.ack_time_low,
        resolve_time_critical=policy.resolve_time_critical,
        resolve_time_high=policy.resolve_time_high,
        resolve_time_medium=policy.resolve_time_medium,
        resolve_time_low=policy.resolve_time_low,
        is_default=policy.is_default,
        is_active=policy.is_active,
        rule_ids=policy.rule_ids,
        created_by=policy.created_by,
        created_at=policy.created_at.isoformat(),
        updated_at=policy.updated_at.isoformat(),
    )


def format_metric(metric: SLAMetric) -> SLAMetricResponse:
    return SLAMetricResponse(
        id=metric.id,
        alert_id=metric.alert_id,
        policy_id=metric.policy_id,
        severity=metric.severity,
        alert_created_at=metric.alert_created_at.isoformat(),
        acknowledged_at=metric.acknowledged_at.isoformat() if metric.acknowledged_at else None,
        resolved_at=metric.resolved_at.isoformat() if metric.resolved_at else None,
        ack_target_minutes=metric.ack_target_minutes,
        resolve_target_minutes=metric.resolve_target_minutes,
        ack_status=metric.ack_status,
        resolve_status=metric.resolve_status,
        ack_time_minutes=metric.ack_time_minutes,
        resolve_time_minutes=metric.resolve_time_minutes,
        created_at=metric.created_at.isoformat(),
        updated_at=metric.updated_at.isoformat(),
    )


@router.get("/policies")
async def list_policies(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    active_only: bool = False,
) -> list[SLAPolicyResponse]:
    """List all SLA policies."""
    query = (
        select(SLAPolicy)
        .where(SLAPolicy.organization_id == org_id)
        .order_by(SLAPolicy.is_default.desc(), SLAPolicy.name)
    )

    if active_only:
        query = query.where(SLAPolicy.is_active.is_(True))

    result = await db.execute(query)
    policies = result.scalars().all()

    return [format_policy(p) for p in policies]


@router.get("/policies/{policy_id}")
async def get_policy(
    policy_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SLAPolicyResponse:
    """Get a specific SLA policy."""
    result = await db.execute(
        select(SLAPolicy).where(
            and_(SLAPolicy.id == policy_id, SLAPolicy.organization_id == org_id)
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="SLA policy not found")

    return format_policy(policy)


@router.post("/policies")
async def create_policy(
    policy: SLAPolicyCreate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SLAPolicyResponse:
    """Create a new SLA policy. Requires analyst role."""
    # If setting as default, unset other defaults
    if policy.is_default:
        await db.execute(
            select(SLAPolicy).where(
                and_(
                    SLAPolicy.is_default.is_(True),
                    SLAPolicy.organization_id == analyst.organization_id,
                )
            )
        )
        result = await db.execute(
            select(SLAPolicy).where(
                and_(
                    SLAPolicy.is_default.is_(True),
                    SLAPolicy.organization_id == analyst.organization_id,
                )
            )
        )
        for existing in result.scalars():
            existing.is_default = False

    db_policy = SLAPolicy(
        name=policy.name,
        description=policy.description,
        ack_time_critical=policy.ack_time_critical,
        ack_time_high=policy.ack_time_high,
        ack_time_medium=policy.ack_time_medium,
        ack_time_low=policy.ack_time_low,
        resolve_time_critical=policy.resolve_time_critical,
        resolve_time_high=policy.resolve_time_high,
        resolve_time_medium=policy.resolve_time_medium,
        resolve_time_low=policy.resolve_time_low,
        is_default=policy.is_default,
        is_active=policy.is_active,
        rule_ids=policy.rule_ids,
        created_by=analyst.email,
        organization_id=analyst.organization_id,
    )
    db.add(db_policy)
    await db.flush()
    await db.refresh(db_policy)

    return format_policy(db_policy)


@router.patch("/policies/{policy_id}")
async def update_policy(
    policy_id: UUID,
    update: SLAPolicyUpdate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SLAPolicyResponse:
    """Update an SLA policy. Requires analyst role."""
    result = await db.execute(
        select(SLAPolicy).where(
            and_(SLAPolicy.id == policy_id, SLAPolicy.organization_id == analyst.organization_id)
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="SLA policy not found")

    # If setting as default, unset other defaults
    if update.is_default:
        result = await db.execute(
            select(SLAPolicy).where(
                and_(
                    SLAPolicy.is_default.is_(True),
                    SLAPolicy.id != policy_id,
                    SLAPolicy.organization_id == analyst.organization_id,
                )
            )
        )
        for existing in result.scalars():
            existing.is_default = False

    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(policy, field, value)

    await db.flush()
    await db.refresh(policy)

    return format_policy(policy)


@router.delete("/policies/{policy_id}")
async def delete_policy(
    policy_id: UUID,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete an SLA policy. Requires analyst role."""
    result = await db.execute(
        select(SLAPolicy).where(
            and_(SLAPolicy.id == policy_id, SLAPolicy.organization_id == analyst.organization_id)
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="SLA policy not found")

    if policy.is_default:
        raise HTTPException(status_code=400, detail="Cannot delete the default policy")

    await db.delete(policy)
    return {"status": "deleted"}


@router.get("/metrics")
async def list_metrics(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    severity: str | None = None,
    status: SLAStatus | None = None,
    days: int = 7,
    page: int = 1,
    page_size: int = 50,
) -> dict:
    """List SLA metrics with filtering."""
    since = utcnow() - timedelta(days=days)

    query = select(SLAMetric).where(
        and_(SLAMetric.created_at >= since, SLAMetric.organization_id == org_id)
    )

    if severity:
        query = query.where(SLAMetric.severity == severity.upper())

    if status:
        query = query.where((SLAMetric.ack_status == status) | (SLAMetric.resolve_status == status))

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    query = query.order_by(SLAMetric.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    metrics = result.scalars().all()

    return {
        "items": [format_metric(m) for m in metrics],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/metrics/{alert_id}")
async def get_alert_metric(
    alert_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SLAMetricResponse:
    """Get SLA metric for a specific alert."""
    result = await db.execute(
        select(SLAMetric).where(
            and_(SLAMetric.alert_id == alert_id, SLAMetric.organization_id == org_id)
        )
    )
    metric = result.scalar_one_or_none()
    if not metric:
        raise HTTPException(status_code=404, detail="SLA metric not found for this alert")

    return format_metric(metric)


@router.post("/metrics/track")
async def track_alert_sla(
    data: dict,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SLAMetricResponse:
    """Create or update SLA tracking for an alert."""
    alert_id = data.get("alert_id")
    severity = data.get("severity", "MEDIUM").upper()
    alert_created_at = datetime.fromisoformat(data.get("created_at", utcnow().isoformat()))
    rule_id = data.get("rule_id")

    # Find applicable policy
    if rule_id:
        result = await db.execute(
            select(SLAPolicy).where(
                and_(
                    SLAPolicy.is_active.is_(True),
                    SLAPolicy.rule_ids.contains([rule_id]),
                    SLAPolicy.organization_id == analyst.organization_id,
                )
            )
        )
        policy = result.scalar_one_or_none()
    else:
        policy = None

    # Fall back to default policy
    if not policy:
        result = await db.execute(
            select(SLAPolicy).where(
                and_(
                    SLAPolicy.is_active.is_(True),
                    SLAPolicy.is_default.is_(True),
                    SLAPolicy.organization_id == analyst.organization_id,
                )
            )
        )
        policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(status_code=400, detail="No applicable SLA policy found")

    # Get target times based on severity
    severity_lower = severity.lower()
    ack_target = getattr(policy, f"ack_time_{severity_lower}", policy.ack_time_medium)
    resolve_target = getattr(policy, f"resolve_time_{severity_lower}", policy.resolve_time_medium)

    # Check if metric already exists
    result = await db.execute(
        select(SLAMetric).where(
            and_(
                SLAMetric.alert_id == alert_id, SLAMetric.organization_id == analyst.organization_id
            )
        )
    )
    metric = result.scalar_one_or_none()

    if metric:
        # Update existing metric
        metric.severity = severity
        metric.ack_target_minutes = ack_target
        metric.resolve_target_minutes = resolve_target
    else:
        # Create new metric
        metric = SLAMetric(
            alert_id=alert_id,
            policy_id=policy.id,
            severity=severity,
            alert_created_at=alert_created_at,
            ack_target_minutes=ack_target,
            resolve_target_minutes=resolve_target,
            organization_id=analyst.organization_id,
        )
        db.add(metric)

    await db.flush()
    await db.refresh(metric)

    return format_metric(metric)


@router.post("/metrics/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SLAMetricResponse:
    """Record acknowledgment time for an alert."""
    result = await db.execute(
        select(SLAMetric).where(
            and_(
                SLAMetric.alert_id == alert_id, SLAMetric.organization_id == analyst.organization_id
            )
        )
    )
    metric = result.scalar_one_or_none()
    if not metric:
        raise HTTPException(status_code=404, detail="SLA metric not found for this alert")

    if metric.acknowledged_at:
        raise HTTPException(status_code=400, detail="Alert already acknowledged")

    now = utcnow()
    metric.acknowledged_at = now

    # Calculate ack time
    time_diff = now - metric.alert_created_at
    metric.ack_time_minutes = int(time_diff.total_seconds() / 60)

    # Update status
    if metric.ack_time_minutes <= metric.ack_target_minutes:
        metric.ack_status = SLAStatus.ON_TRACK
    else:
        metric.ack_status = SLAStatus.BREACHED

    await db.flush()
    await db.refresh(metric)

    return format_metric(metric)


@router.post("/metrics/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SLAMetricResponse:
    """Record resolution time for an alert."""
    result = await db.execute(
        select(SLAMetric).where(
            and_(
                SLAMetric.alert_id == alert_id, SLAMetric.organization_id == analyst.organization_id
            )
        )
    )
    metric = result.scalar_one_or_none()
    if not metric:
        raise HTTPException(status_code=404, detail="SLA metric not found for this alert")

    if metric.resolved_at:
        raise HTTPException(status_code=400, detail="Alert already resolved")

    now = utcnow()
    metric.resolved_at = now

    # Calculate resolve time
    time_diff = now - metric.alert_created_at
    metric.resolve_time_minutes = int(time_diff.total_seconds() / 60)

    # Update status
    if metric.resolve_time_minutes <= metric.resolve_target_minutes:
        metric.resolve_status = SLAStatus.ON_TRACK
    else:
        metric.resolve_status = SLAStatus.BREACHED

    await db.flush()
    await db.refresh(metric)

    return format_metric(metric)


@router.get("/dashboard")
async def get_sla_dashboard(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = 7,
) -> SLADashboardResponse:
    """Get SLA dashboard summary."""
    since = utcnow() - timedelta(days=days)

    # Get all metrics in the time range
    result = await db.execute(
        select(SLAMetric).where(
            and_(SLAMetric.created_at >= since, SLAMetric.organization_id == org_id)
        )
    )
    metrics = result.scalars().all()

    def calculate_summary(metric_list: list[SLAMetric]) -> SLASummary:
        if not metric_list:
            return SLASummary(
                total_alerts=0,
                on_track=0,
                at_risk=0,
                breached=0,
                avg_ack_time_minutes=None,
                avg_resolve_time_minutes=None,
                ack_compliance_rate=100.0,
                resolve_compliance_rate=100.0,
            )

        total = len(metric_list)
        on_track = sum(
            1
            for m in metric_list
            if m.ack_status == SLAStatus.ON_TRACK and m.resolve_status == SLAStatus.ON_TRACK
        )
        at_risk = sum(
            1
            for m in metric_list
            if m.ack_status == SLAStatus.AT_RISK or m.resolve_status == SLAStatus.AT_RISK
        )
        breached = sum(
            1
            for m in metric_list
            if m.ack_status == SLAStatus.BREACHED or m.resolve_status == SLAStatus.BREACHED
        )

        ack_times = [m.ack_time_minutes for m in metric_list if m.ack_time_minutes is not None]
        resolve_times = [
            m.resolve_time_minutes for m in metric_list if m.resolve_time_minutes is not None
        ]

        avg_ack = sum(ack_times) / len(ack_times) if ack_times else None
        avg_resolve = sum(resolve_times) / len(resolve_times) if resolve_times else None

        ack_compliant = sum(1 for m in metric_list if m.ack_status == SLAStatus.ON_TRACK)
        resolve_compliant = sum(1 for m in metric_list if m.resolve_status == SLAStatus.ON_TRACK)

        return SLASummary(
            total_alerts=total,
            on_track=on_track,
            at_risk=at_risk,
            breached=breached,
            avg_ack_time_minutes=round(avg_ack, 1) if avg_ack else None,
            avg_resolve_time_minutes=round(avg_resolve, 1) if avg_resolve else None,
            ack_compliance_rate=round((ack_compliant / total) * 100, 1) if total > 0 else 100.0,
            resolve_compliance_rate=round((resolve_compliant / total) * 100, 1)
            if total > 0
            else 100.0,
        )

    # Calculate overall summary
    summary = calculate_summary(metrics)

    # Calculate by severity
    by_severity = {}
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        severity_metrics = [m for m in metrics if m.severity == severity]
        by_severity[severity] = calculate_summary(severity_metrics)

    # Get recent breaches
    breached_metrics = [
        m
        for m in metrics
        if m.ack_status == SLAStatus.BREACHED or m.resolve_status == SLAStatus.BREACHED
    ]
    breached_metrics.sort(key=lambda m: m.created_at, reverse=True)
    recent_breaches = [format_metric(m) for m in breached_metrics[:10]]

    return SLADashboardResponse(
        summary=summary,
        by_severity=by_severity,
        recent_breaches=recent_breaches,
    )


@router.post("/metrics/update-status")
async def update_sla_statuses(
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Update SLA statuses for all active metrics (run periodically)."""
    now = utcnow()

    # Get all unresolved metrics for this organization
    result = await db.execute(
        select(SLAMetric).where(
            and_(
                SLAMetric.resolved_at.is_(None),
                SLAMetric.organization_id == analyst.organization_id,
            )
        )
    )
    metrics = result.scalars().all()

    updated_count = 0
    for metric in metrics:
        changed = False
        elapsed_minutes = int((now - metric.alert_created_at).total_seconds() / 60)

        # Update ack status if not yet acknowledged
        if not metric.acknowledged_at:
            if elapsed_minutes > metric.ack_target_minutes:
                if metric.ack_status != SLAStatus.BREACHED:
                    metric.ack_status = SLAStatus.BREACHED
                    changed = True
            elif elapsed_minutes > metric.ack_target_minutes * 0.75:
                if metric.ack_status != SLAStatus.AT_RISK:
                    metric.ack_status = SLAStatus.AT_RISK
                    changed = True

        # Update resolve status
        if elapsed_minutes > metric.resolve_target_minutes:
            if metric.resolve_status != SLAStatus.BREACHED:
                metric.resolve_status = SLAStatus.BREACHED
                changed = True
        elif elapsed_minutes > metric.resolve_target_minutes * 0.75:
            if metric.resolve_status != SLAStatus.AT_RISK:
                metric.resolve_status = SLAStatus.AT_RISK
                changed = True

        if changed:
            updated_count += 1

    await db.flush()

    return {"updated": updated_count, "total_checked": len(metrics)}
