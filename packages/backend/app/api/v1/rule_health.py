"""
Stale Rule Detection API - Feature 2
Find rules that haven't triggered alerts and monitor rule health.
"""
from datetime import datetime, timedelta
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgUserDep, OrgIdDep, OrgAdminDep
from app.db import get_db, RuleHealth

router = APIRouter()


class RuleHealthResponse(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    last_triggered_at: Optional[str]
    trigger_count_7d: int
    trigger_count_30d: int
    trigger_count_90d: int
    is_stale: bool
    health_score: float
    stale_reason: Optional[str]
    is_enabled: bool
    severity: Optional[str]
    owner_email: Optional[str]
    last_checked_at: str

    class Config:
        from_attributes = True


class RuleHealthListResponse(BaseModel):
    rules: list[RuleHealthResponse]
    total: int
    stale_count: int


class RuleHealthStats(BaseModel):
    total_rules: int
    healthy_rules: int
    stale_rules: int
    average_health_score: float
    rules_by_severity: dict


class UpdateRuleHealthRequest(BaseModel):
    rule_name: Optional[str] = None
    is_enabled: Optional[bool] = None
    severity: Optional[str] = None
    owner_email: Optional[str] = None


def serialize_rule_health(rh: RuleHealth) -> RuleHealthResponse:
    return RuleHealthResponse(
        id=str(rh.id),
        rule_id=rh.rule_id,
        rule_name=rh.rule_name,
        last_triggered_at=rh.last_triggered_at.isoformat() if rh.last_triggered_at else None,
        trigger_count_7d=rh.trigger_count_7d,
        trigger_count_30d=rh.trigger_count_30d,
        trigger_count_90d=rh.trigger_count_90d,
        is_stale=rh.is_stale,
        health_score=rh.health_score,
        stale_reason=rh.stale_reason,
        is_enabled=rh.is_enabled,
        severity=rh.severity,
        owner_email=rh.owner_email,
        last_checked_at=rh.last_checked_at.isoformat(),
    )


@router.get("", response_model=RuleHealthListResponse)
async def list_rule_health(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    is_stale: Optional[bool] = Query(None, description="Filter by stale status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    min_health_score: Optional[float] = Query(None, description="Minimum health score"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
):
    """List all rule health statuses."""
    query = select(RuleHealth).where(RuleHealth.organization_id == org_id)

    if is_stale is not None:
        query = query.where(RuleHealth.is_stale == is_stale)
    if severity:
        query = query.where(RuleHealth.severity == severity)
    if min_health_score is not None:
        query = query.where(RuleHealth.health_score >= min_health_score)

    # Count total
    count_query = select(func.count(RuleHealth.id)).where(RuleHealth.organization_id == org_id)
    if is_stale is not None:
        count_query = count_query.where(RuleHealth.is_stale == is_stale)
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Count stale
    stale_count_result = await db.execute(
        select(func.count(RuleHealth.id))
        .where(RuleHealth.organization_id == org_id)
        .where(RuleHealth.is_stale == True)
    )
    stale_count = stale_count_result.scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    query = query.order_by(RuleHealth.health_score.asc()).offset(offset).limit(page_size)

    result = await db.execute(query)
    rules = result.scalars().all()

    return RuleHealthListResponse(
        rules=[serialize_rule_health(r) for r in rules],
        total=total,
        stale_count=stale_count,
    )


@router.get("/stale", response_model=RuleHealthListResponse)
async def list_stale_rules(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
):
    """List only stale rules."""
    offset = (page - 1) * page_size

    result = await db.execute(
        select(RuleHealth)
        .where(RuleHealth.organization_id == org_id)
        .where(RuleHealth.is_stale == True)
        .order_by(RuleHealth.last_triggered_at.asc().nullsfirst())
        .offset(offset)
        .limit(page_size)
    )
    rules = result.scalars().all()

    count_result = await db.execute(
        select(func.count(RuleHealth.id))
        .where(RuleHealth.organization_id == org_id)
        .where(RuleHealth.is_stale == True)
    )
    total = count_result.scalar() or 0

    return RuleHealthListResponse(
        rules=[serialize_rule_health(r) for r in rules],
        total=total,
        stale_count=total,
    )


@router.get("/stats", response_model=RuleHealthStats)
async def get_rule_health_stats(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get aggregated rule health statistics."""
    # Total rules
    total_result = await db.execute(
        select(func.count(RuleHealth.id)).where(RuleHealth.organization_id == org_id)
    )
    total_rules = total_result.scalar() or 0

    # Stale count
    stale_result = await db.execute(
        select(func.count(RuleHealth.id))
        .where(RuleHealth.organization_id == org_id)
        .where(RuleHealth.is_stale == True)
    )
    stale_rules = stale_result.scalar() or 0

    # Average health score
    avg_result = await db.execute(
        select(func.avg(RuleHealth.health_score)).where(RuleHealth.organization_id == org_id)
    )
    avg_score = avg_result.scalar() or 100.0

    # By severity
    severity_result = await db.execute(
        select(RuleHealth.severity, func.count(RuleHealth.id))
        .where(RuleHealth.organization_id == org_id)
        .group_by(RuleHealth.severity)
    )
    rules_by_severity = {row[0] or "unknown": row[1] for row in severity_result.all()}

    return RuleHealthStats(
        total_rules=total_rules,
        healthy_rules=total_rules - stale_rules,
        stale_rules=stale_rules,
        average_health_score=round(float(avg_score), 2),
        rules_by_severity=rules_by_severity,
    )


@router.get("/{rule_id}", response_model=RuleHealthResponse)
async def get_rule_health(
    rule_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get health status for a specific rule."""
    result = await db.execute(
        select(RuleHealth)
        .where(RuleHealth.organization_id == org_id)
        .where(RuleHealth.rule_id == rule_id)
    )
    rule_health = result.scalar_one_or_none()

    if not rule_health:
        raise HTTPException(status_code=404, detail="Rule health record not found")

    return serialize_rule_health(rule_health)


@router.post("/refresh")
async def refresh_rule_health(
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Trigger a refresh of rule health data. In production, this would query alert data."""
    # This is a placeholder - in production, this would:
    # 1. Query all rules from the SIEM
    # 2. Count alerts per rule for 7d, 30d, 90d windows
    # 3. Update health scores and stale flags

    # For demo, mark rules as stale if no triggers in 90 days
    now = datetime.utcnow()
    stale_threshold = now - timedelta(days=90)

    await db.execute(
        update(RuleHealth)
        .where(RuleHealth.organization_id == org_id)
        .where(RuleHealth.last_triggered_at < stale_threshold)
        .values(
            is_stale=True,
            stale_reason="No alerts in 90 days",
            last_checked_at=now,
        )
    )

    await db.execute(
        update(RuleHealth)
        .where(RuleHealth.organization_id == org_id)
        .where(RuleHealth.last_triggered_at >= stale_threshold)
        .values(
            is_stale=False,
            stale_reason=None,
            last_checked_at=now,
        )
    )

    await db.commit()

    return {"status": "success", "message": "Rule health refresh triggered"}


@router.patch("/{rule_id}")
async def update_rule_health(
    rule_id: str,
    request: UpdateRuleHealthRequest,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update rule health metadata (owner, etc.)."""
    result = await db.execute(
        select(RuleHealth)
        .where(RuleHealth.organization_id == org_id)
        .where(RuleHealth.rule_id == rule_id)
    )
    rule_health = result.scalar_one_or_none()

    if not rule_health:
        raise HTTPException(status_code=404, detail="Rule health record not found")

    update_data = request.model_dump(exclude_none=True)
    for key, value in update_data.items():
        setattr(rule_health, key, value)

    await db.commit()
    await db.refresh(rule_health)

    return serialize_rule_health(rule_health)
