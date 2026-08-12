from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAnalystDep, OrgIdDep, OrgUserDep
from app.db import Case, CaseActivity, CaseActivityType, CasePriority, CaseStatus, get_db
from app.services.case_service import (
    add_case_activity,
    generate_case_number,
    get_case_timeline,
    track_field_change,
)

router = APIRouter()


class CaseCreate(BaseModel):
    title: str
    description: str | None = None
    priority: CasePriority = CasePriority.MEDIUM
    assignee: str | None = None
    tags: list[str] = []
    incident_ids: list[str] = []


class CaseUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: CaseStatus | None = None
    priority: CasePriority | None = None
    assignee: str | None = None
    tags: list[str] | None = None


class CaseResponse(BaseModel):
    id: UUID
    case_number: str
    title: str
    description: str | None
    status: CaseStatus
    priority: CasePriority
    assignee: str | None
    tags: list[str]
    incident_count: int
    created_by: str
    closed_at: str | None
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class CaseDetailResponse(CaseResponse):
    incident_ids: list[str]


class CaseActivityResponse(BaseModel):
    id: UUID
    activity_type: CaseActivityType
    description: str
    old_value: str | None
    new_value: str | None
    user_email: str
    created_at: str

    class Config:
        from_attributes = True


class AddCommentRequest(BaseModel):
    comment: str


class LinkIncidentRequest(BaseModel):
    incident_id: str


@router.get("")
async def list_cases(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    status: CaseStatus | None = None,
    priority: CasePriority | None = None,
    assignee: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> dict:
    """List all cases with pagination."""
    query = select(Case).where(Case.organization_id == org_id)

    if status:
        query = query.where(Case.status == status)
    if priority:
        query = query.where(Case.priority == priority)
    if assignee:
        query = query.where(Case.assignee == assignee)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Get cases
    query = query.order_by(desc(Case.created_at))
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    cases = result.scalars().all()

    items = [
        CaseResponse(
            id=c.id,
            case_number=c.case_number,
            title=c.title,
            description=c.description,
            status=c.status,
            priority=c.priority,
            assignee=c.assignee,
            tags=c.tags,
            incident_count=len(c.incident_ids),
            created_by=c.created_by,
            closed_at=c.closed_at.isoformat() if c.closed_at else None,
            created_at=c.created_at.isoformat(),
            updated_at=c.updated_at.isoformat(),
        )
        for c in cases
    ]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{case_id}")
async def get_case(
    case_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> CaseDetailResponse:
    """Get case details."""
    result = await db.execute(
        select(Case).where(and_(Case.id == case_id, Case.organization_id == org_id))
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    return CaseDetailResponse(
        id=case.id,
        case_number=case.case_number,
        title=case.title,
        description=case.description,
        status=case.status,
        priority=case.priority,
        assignee=case.assignee,
        tags=case.tags,
        incident_ids=case.incident_ids,
        incident_count=len(case.incident_ids),
        created_by=case.created_by,
        closed_at=case.closed_at.isoformat() if case.closed_at else None,
        created_at=case.created_at.isoformat(),
        updated_at=case.updated_at.isoformat(),
    )


@router.get("/{case_id}/timeline")
async def get_case_timeline_endpoint(
    case_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(50, ge=1, le=200),
) -> list[CaseActivityResponse]:
    """Get case activity timeline."""
    # Verify case exists
    result = await db.execute(
        select(Case).where(and_(Case.id == case_id, Case.organization_id == org_id))
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Case not found")

    activities = await get_case_timeline(db, case_id, limit)

    return [
        CaseActivityResponse(
            id=a.id,
            activity_type=a.activity_type,
            description=a.description,
            old_value=a.old_value,
            new_value=a.new_value,
            user_email=a.user_email,
            created_at=a.created_at.isoformat(),
        )
        for a in activities
    ]


@router.post("")
async def create_case(
    case_data: CaseCreate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> CaseDetailResponse:
    """Create a new case. Requires analyst role."""
    case_number = await generate_case_number(db)

    db_case = Case(
        case_number=case_number,
        title=case_data.title,
        description=case_data.description,
        priority=case_data.priority,
        assignee=case_data.assignee,
        tags=case_data.tags,
        incident_ids=case_data.incident_ids,
        created_by=analyst.email,
        organization_id=analyst.organization_id,
    )
    db.add(db_case)
    await db.flush()
    await db.refresh(db_case)

    # Add creation activity
    await add_case_activity(
        db=db,
        case_id=db_case.id,
        activity_type=CaseActivityType.CREATED,
        description=f"Case {case_number} created",
        user_email=analyst.email,
    )

    # Add activity for linked incidents
    for incident_id in case_data.incident_ids:
        await add_case_activity(
            db=db,
            case_id=db_case.id,
            activity_type=CaseActivityType.INCIDENT_LINKED,
            description=f"Linked incident {incident_id}",
            user_email=analyst.email,
            new_value=incident_id,
        )

    await db.flush()

    return CaseDetailResponse(
        id=db_case.id,
        case_number=db_case.case_number,
        title=db_case.title,
        description=db_case.description,
        status=db_case.status,
        priority=db_case.priority,
        assignee=db_case.assignee,
        tags=db_case.tags,
        incident_ids=db_case.incident_ids,
        incident_count=len(db_case.incident_ids),
        created_by=db_case.created_by,
        closed_at=None,
        created_at=db_case.created_at.isoformat(),
        updated_at=db_case.updated_at.isoformat(),
    )


@router.patch("/{case_id}")
async def update_case(
    case_id: UUID,
    update: CaseUpdate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> CaseResponse:
    """Update a case. Requires analyst role."""
    result = await db.execute(
        select(Case).where(
            and_(Case.id == case_id, Case.organization_id == analyst.organization_id)
        )
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    update_data = update.model_dump(exclude_unset=True)

    # Track changes for specific fields
    tracked_fields = ["status", "priority", "assignee"]
    for field in tracked_fields:
        if field in update_data:
            old_value = getattr(case, field)
            new_value = update_data[field]
            if old_value != new_value:
                # Convert enum values to strings for comparison
                old_str = old_value.value if hasattr(old_value, "value") else str(old_value)
                new_str = new_value.value if hasattr(new_value, "value") else str(new_value)
                await track_field_change(
                    db=db,
                    case_id=case_id,
                    field_name=field,
                    old_value=old_str,
                    new_value=new_str,
                    user_email=analyst.email,
                )

    # Handle status change to closed
    if "status" in update_data:
        if update_data["status"] == CaseStatus.CLOSED and case.status != CaseStatus.CLOSED:
            case.closed_at = datetime.utcnow()
        elif update_data["status"] != CaseStatus.CLOSED:
            case.closed_at = None

    for field, value in update_data.items():
        setattr(case, field, value)

    await db.flush()
    await db.refresh(case)

    return CaseResponse(
        id=case.id,
        case_number=case.case_number,
        title=case.title,
        description=case.description,
        status=case.status,
        priority=case.priority,
        assignee=case.assignee,
        tags=case.tags,
        incident_count=len(case.incident_ids),
        created_by=case.created_by,
        closed_at=case.closed_at.isoformat() if case.closed_at else None,
        created_at=case.created_at.isoformat(),
        updated_at=case.updated_at.isoformat(),
    )


@router.delete("/{case_id}")
async def delete_case(
    case_id: UUID,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a case. Requires analyst role."""
    result = await db.execute(
        select(Case).where(
            and_(Case.id == case_id, Case.organization_id == analyst.organization_id)
        )
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Delete associated activities
    await db.execute(CaseActivity.__table__.delete().where(CaseActivity.case_id == case_id))

    await db.delete(case)
    return {"status": "deleted"}


@router.post("/{case_id}/comments")
async def add_comment(
    case_id: UUID,
    request: AddCommentRequest,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> CaseActivityResponse:
    """Add a comment to a case. Requires analyst role."""
    result = await db.execute(
        select(Case).where(
            and_(Case.id == case_id, Case.organization_id == analyst.organization_id)
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Case not found")

    activity = await add_case_activity(
        db=db,
        case_id=case_id,
        activity_type=CaseActivityType.COMMENT_ADDED,
        description=request.comment,
        user_email=analyst.email,
    )

    await db.flush()

    return CaseActivityResponse(
        id=activity.id,
        activity_type=activity.activity_type,
        description=activity.description,
        old_value=activity.old_value,
        new_value=activity.new_value,
        user_email=activity.user_email,
        created_at=activity.created_at.isoformat(),
    )


@router.post("/{case_id}/incidents")
async def link_incident(
    case_id: UUID,
    request: LinkIncidentRequest,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Link an incident to a case. Requires analyst role."""
    result = await db.execute(
        select(Case).where(
            and_(Case.id == case_id, Case.organization_id == analyst.organization_id)
        )
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if request.incident_id in case.incident_ids:
        raise HTTPException(status_code=400, detail="Incident already linked to case")

    case.incident_ids = case.incident_ids + [request.incident_id]

    await add_case_activity(
        db=db,
        case_id=case_id,
        activity_type=CaseActivityType.INCIDENT_LINKED,
        description=f"Linked incident {request.incident_id}",
        user_email=analyst.email,
        new_value=request.incident_id,
    )

    await db.flush()
    return {"status": "linked", "incident_id": request.incident_id}


@router.delete("/{case_id}/incidents/{incident_id}")
async def unlink_incident(
    case_id: UUID,
    incident_id: str,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Unlink an incident from a case. Requires analyst role."""
    result = await db.execute(
        select(Case).where(
            and_(Case.id == case_id, Case.organization_id == analyst.organization_id)
        )
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if incident_id not in case.incident_ids:
        raise HTTPException(status_code=404, detail="Incident not linked to case")

    case.incident_ids = [i for i in case.incident_ids if i != incident_id]

    await add_case_activity(
        db=db,
        case_id=case_id,
        activity_type=CaseActivityType.INCIDENT_UNLINKED,
        description=f"Unlinked incident {incident_id}",
        user_email=analyst.email,
        old_value=incident_id,
    )

    await db.flush()
    return {"status": "unlinked"}
