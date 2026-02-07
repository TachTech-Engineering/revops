"""
Shift Handoff API

Allows SOC analysts to document and transfer context between shifts.
"""
from datetime import datetime
from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

from app.api.v1.deps import OrgUserDep, OrgIdDep, OrgAnalystDep
from app.db import get_db, ShiftHandoff

router = APIRouter()


# ==================== Models ====================

class OngoingInvestigation(BaseModel):
    alert_id: str
    title: str
    severity: str
    status: str
    notes: Optional[str] = None


class PriorityItem(BaseModel):
    type: str  # alert, case, task
    id: str
    title: str
    priority: str  # critical, high, medium
    reason: str


class ShiftHandoffCreate(BaseModel):
    summary: str
    ongoing_investigations: List[OngoingInvestigation] = []
    priority_items: List[PriorityItem] = []
    notes: Optional[str] = None
    incoming_analyst: Optional[str] = None


class ShiftHandoffResponse(BaseModel):
    id: str
    shift_date: str
    outgoing_analyst: str
    incoming_analyst: Optional[str]
    summary: str
    ongoing_investigations: list
    priority_items: list
    notes: Optional[str]
    open_alerts_count: int
    open_cases_count: int
    critical_alerts_count: int
    is_acknowledged: bool
    acknowledged_at: Optional[str]
    acknowledged_by: Optional[str]
    created_at: str

    class Config:
        from_attributes = True


def serialize_handoff(h: ShiftHandoff) -> ShiftHandoffResponse:
    return ShiftHandoffResponse(
        id=str(h.id),
        shift_date=h.shift_date.isoformat(),
        outgoing_analyst=h.outgoing_analyst,
        incoming_analyst=h.incoming_analyst,
        summary=h.summary,
        ongoing_investigations=h.ongoing_investigations,
        priority_items=h.priority_items,
        notes=h.notes,
        open_alerts_count=h.open_alerts_count,
        open_cases_count=h.open_cases_count,
        critical_alerts_count=h.critical_alerts_count,
        is_acknowledged=h.is_acknowledged,
        acknowledged_at=h.acknowledged_at.isoformat() if h.acknowledged_at else None,
        acknowledged_by=h.acknowledged_by,
        created_at=h.created_at.isoformat(),
    )


# ==================== Endpoints ====================

@router.get("", response_model=List[ShiftHandoffResponse])
async def list_handoffs(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(10, ge=1, le=100),
    include_acknowledged: bool = Query(True),
):
    """List recent shift handoffs."""
    query = (
        select(ShiftHandoff)
        .where(ShiftHandoff.organization_id == org_id)
        .order_by(desc(ShiftHandoff.shift_date))
        .limit(limit)
    )

    if not include_acknowledged:
        query = query.where(ShiftHandoff.is_acknowledged == False)

    result = await db.execute(query)
    handoffs = result.scalars().all()

    return [serialize_handoff(h) for h in handoffs]


@router.get("/latest", response_model=Optional[ShiftHandoffResponse])
async def get_latest_handoff(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get the most recent unacknowledged handoff for the current user."""
    result = await db.execute(
        select(ShiftHandoff)
        .where(ShiftHandoff.organization_id == org_id)
        .where(ShiftHandoff.is_acknowledged == False)
        .order_by(desc(ShiftHandoff.shift_date))
        .limit(1)
    )
    handoff = result.scalar_one_or_none()

    if not handoff:
        return None

    return serialize_handoff(handoff)


@router.get("/{handoff_id}", response_model=ShiftHandoffResponse)
async def get_handoff(
    handoff_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific shift handoff."""
    result = await db.execute(
        select(ShiftHandoff)
        .where(ShiftHandoff.id == UUID(handoff_id))
        .where(ShiftHandoff.organization_id == org_id)
    )
    handoff = result.scalar_one_or_none()

    if not handoff:
        raise HTTPException(status_code=404, detail="Handoff not found")

    return serialize_handoff(handoff)


@router.post("", status_code=201, response_model=ShiftHandoffResponse)
async def create_handoff(
    request: ShiftHandoffCreate,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Create a new shift handoff."""
    # Get alert/case counts (simplified - in production would query actual counts)
    open_alerts = len([i for i in request.ongoing_investigations if i.status not in ['resolved', 'closed']])
    critical_alerts = len([i for i in request.ongoing_investigations if i.severity.lower() == 'critical'])

    handoff = ShiftHandoff(
        organization_id=org_id,
        shift_date=datetime.utcnow(),
        outgoing_analyst=user.email,
        incoming_analyst=request.incoming_analyst,
        summary=request.summary,
        ongoing_investigations=[i.model_dump() for i in request.ongoing_investigations],
        priority_items=[p.model_dump() for p in request.priority_items],
        notes=request.notes,
        open_alerts_count=open_alerts,
        open_cases_count=0,  # Would query cases in production
        critical_alerts_count=critical_alerts,
    )

    db.add(handoff)
    await db.commit()
    await db.refresh(handoff)

    return serialize_handoff(handoff)


@router.post("/{handoff_id}/acknowledge")
async def acknowledge_handoff(
    handoff_id: str,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Acknowledge receipt of a shift handoff."""
    result = await db.execute(
        select(ShiftHandoff)
        .where(ShiftHandoff.id == UUID(handoff_id))
        .where(ShiftHandoff.organization_id == org_id)
    )
    handoff = result.scalar_one_or_none()

    if not handoff:
        raise HTTPException(status_code=404, detail="Handoff not found")

    if handoff.is_acknowledged:
        raise HTTPException(status_code=400, detail="Handoff already acknowledged")

    handoff.is_acknowledged = True
    handoff.acknowledged_at = datetime.utcnow()
    handoff.acknowledged_by = user.email

    await db.commit()

    return {
        "status": "success",
        "message": "Handoff acknowledged",
        "acknowledged_by": user.email,
    }
