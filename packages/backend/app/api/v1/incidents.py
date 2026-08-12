from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAnalystDep, OrgIdDep, OrgUserDep
from app.db import Incident, IncidentAlert, IncidentSeverity, IncidentStatus, get_db

router = APIRouter()


class IncidentCreate(BaseModel):
    title: str
    description: str | None = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    assignee: str | None = None
    tags: list[str] = []
    alert_ids: list[str] = []


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: IncidentStatus | None = None
    severity: IncidentSeverity | None = None
    assignee: str | None = None
    tags: list[str] | None = None


class IncidentResponse(BaseModel):
    id: UUID
    title: str
    description: str | None
    status: IncidentStatus
    severity: IncidentSeverity
    assignee: str | None
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
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    status: IncidentStatus | None = None,
    severity: IncidentSeverity | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> dict:
    """List all incidents with pagination."""
    query = select(Incident).where(Incident.organization_id == org_id)

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

        items.append(
            IncidentResponse(
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
        )

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{incident_id}")
async def get_incident(
    incident_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> IncidentDetailResponse:
    """Get incident details."""
    result = await db.execute(
        select(Incident).where(and_(Incident.id == incident_id, Incident.organization_id == org_id))
    )
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
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> IncidentDetailResponse:
    """Create a new incident. Requires analyst role."""
    db_incident = Incident(
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        assignee=incident.assignee,
        tags=incident.tags,
        created_by=analyst.email,
        organization_id=analyst.organization_id,
    )
    db.add(db_incident)
    await db.flush()

    # Add alerts to incident
    for alert_id in incident.alert_ids:
        db_alert = IncidentAlert(
            incident_id=db_incident.id,
            alert_id=alert_id,
            added_by=analyst.email,
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
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> IncidentResponse:
    """Update an incident. Requires analyst role."""
    result = await db.execute(
        select(Incident).where(and_(Incident.id == incident_id, Incident.organization_id == org_id))
    )
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
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete an incident. Requires analyst role."""
    result = await db.execute(
        select(Incident).where(and_(Incident.id == incident_id, Incident.organization_id == org_id))
    )
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
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Add alerts to an incident. Requires analyst role."""
    result = await db.execute(
        select(Incident).where(and_(Incident.id == incident_id, Incident.organization_id == org_id))
    )
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
                added_by=analyst.email,
            )
            db.add(db_alert)
            added += 1

    await db.flush()
    return {"added": added, "total": len(request.alert_ids)}


@router.delete("/{incident_id}/alerts/{alert_id}")
async def remove_alert_from_incident(
    incident_id: UUID,
    alert_id: str,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Remove an alert from an incident. Requires analyst role."""
    # First verify the incident belongs to this organization
    incident_result = await db.execute(
        select(Incident).where(and_(Incident.id == incident_id, Incident.organization_id == org_id))
    )
    if not incident_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Incident not found")

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
