from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db, Incident, IncidentAlert, IncidentStatus, IncidentSeverity
from app.api.v1.deps import RequireAnalystDep, CurrentUserDep

router = APIRouter()


class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    assignee: Optional[str] = None
    tags: list[str] = []
    alert_ids: list[str] = []


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    assignee: Optional[str] = None
    tags: Optional[list[str]] = None


class IncidentResponse(BaseModel):
    id: UUID
    title: str
    description: Optional[str]
    status: IncidentStatus
    severity: IncidentSeverity
    assignee: Optional[str]
    tags: list[str]
    alert_count: int
    created_by: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class IncidentDetailResponse(IncidentResponse):
    alert_ids: list[str]


class AddAlertsRequest(BaseModel):
    alert_ids: list[str]


@router.get("")
async def list_incidents(
    user: CurrentUserDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    status: Optional[IncidentStatus] = None,
    severity: Optional[IncidentSeverity] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> dict:
    """List all incidents with pagination."""
    query = select(Incident)

    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Get incidents
    query = query.order_by(desc(Incident.created_at))
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    incidents = result.scalars().all()

    # Get alert counts
    items = []
    for incident in incidents:
        count_query = select(func.count()).where(IncidentAlert.incident_id == incident.id)
        count_result = await db.execute(count_query)
        alert_count = count_result.scalar() or 0

        items.append(IncidentResponse(
            id=incident.id,
            title=incident.title,
            description=incident.description,
            status=incident.status,
            severity=incident.severity,
            assignee=incident.assignee,
            tags=incident.tags,
            alert_count=alert_count,
            created_by=incident.created_by,
            created_at=incident.created_at.isoformat(),
            updated_at=incident.updated_at.isoformat(),
        ))

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{incident_id}")
async def get_incident(
    incident_id: UUID,
    user: CurrentUserDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> IncidentDetailResponse:
    """Get incident details."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Get alert IDs
    alerts_result = await db.execute(
        select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == incident_id)
    )
    alert_ids = [row[0] for row in alerts_result.all()]

    return IncidentDetailResponse(
        id=incident.id,
        title=incident.title,
        description=incident.description,
        status=incident.status,
        severity=incident.severity,
        assignee=incident.assignee,
        tags=incident.tags,
        alert_count=len(alert_ids),
        alert_ids=alert_ids,
        created_by=incident.created_by,
        created_at=incident.created_at.isoformat(),
        updated_at=incident.updated_at.isoformat(),
    )


@router.post("")
async def create_incident(
    incident: IncidentCreate,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> IncidentDetailResponse:
    """Create a new incident. Requires analyst role."""
    email, _ = analyst

    db_incident = Incident(
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        assignee=incident.assignee,
        tags=incident.tags,
        created_by=email,
    )
    db.add(db_incident)
    await db.flush()

    # Add alerts to incident
    for alert_id in incident.alert_ids:
        db_alert = IncidentAlert(
            incident_id=db_incident.id,
            alert_id=alert_id,
            added_by=email,
        )
        db.add(db_alert)

    await db.flush()
    await db.refresh(db_incident)

    return IncidentDetailResponse(
        id=db_incident.id,
        title=db_incident.title,
        description=db_incident.description,
        status=db_incident.status,
        severity=db_incident.severity,
        assignee=db_incident.assignee,
        tags=db_incident.tags,
        alert_count=len(incident.alert_ids),
        alert_ids=incident.alert_ids,
        created_by=db_incident.created_by,
        created_at=db_incident.created_at.isoformat(),
        updated_at=db_incident.updated_at.isoformat(),
    )


@router.patch("/{incident_id}")
async def update_incident(
    incident_id: UUID,
    update: IncidentUpdate,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> IncidentResponse:
    """Update an incident. Requires analyst role."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(incident, field, value)

    await db.flush()
    await db.refresh(incident)

    # Get alert count
    count_query = select(func.count()).where(IncidentAlert.incident_id == incident_id)
    count_result = await db.execute(count_query)
    alert_count = count_result.scalar() or 0

    return IncidentResponse(
        id=incident.id,
        title=incident.title,
        description=incident.description,
        status=incident.status,
        severity=incident.severity,
        assignee=incident.assignee,
        tags=incident.tags,
        alert_count=alert_count,
        created_by=incident.created_by,
        created_at=incident.created_at.isoformat(),
        updated_at=incident.updated_at.isoformat(),
    )


@router.delete("/{incident_id}")
async def delete_incident(
    incident_id: UUID,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete an incident. Requires analyst role."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Delete associated alerts
    await db.execute(
        IncidentAlert.__table__.delete().where(IncidentAlert.incident_id == incident_id)
    )

    await db.delete(incident)
    return {"status": "deleted"}


@router.post("/{incident_id}/alerts")
async def add_alerts_to_incident(
    incident_id: UUID,
    request: AddAlertsRequest,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Add alerts to an incident. Requires analyst role."""
    email, _ = analyst

    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    added = 0
    for alert_id in request.alert_ids:
        # Check if already exists
        existing = await db.execute(
            select(IncidentAlert).where(
                IncidentAlert.incident_id == incident_id,
                IncidentAlert.alert_id == alert_id,
            )
        )
        if not existing.scalar_one_or_none():
            db_alert = IncidentAlert(
                incident_id=incident_id,
                alert_id=alert_id,
                added_by=email,
            )
            db.add(db_alert)
            added += 1

    await db.flush()
    return {"added": added, "total": len(request.alert_ids)}


@router.delete("/{incident_id}/alerts/{alert_id}")
async def remove_alert_from_incident(
    incident_id: UUID,
    alert_id: str,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Remove an alert from an incident. Requires analyst role."""
    result = await db.execute(
        select(IncidentAlert).where(
            IncidentAlert.incident_id == incident_id,
            IncidentAlert.alert_id == alert_id,
        )
    )
    incident_alert = result.scalar_one_or_none()
    if not incident_alert:
        raise HTTPException(status_code=404, detail="Alert not found in incident")

    await db.delete(incident_alert)
    return {"status": "removed"}
