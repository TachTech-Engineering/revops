from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAnalystDep, OrgIdDep, OrgUserDep
from app.db import ExecutionStatus, Playbook, PlaybookExecution, PlaybookStatus, get_db
from app.services.playbook_service import PlaybookService

router = APIRouter()


class ActionConfig(BaseModel):
    type: str
    name: str | None = None
    config: dict = {}
    stop_on_failure: bool = False


class TriggerConditions(BaseModel):
    severities: list[str] | None = None
    rule_ids: list[str] | None = None
    title_pattern: str | None = None


class PlaybookCreate(BaseModel):
    name: str
    description: str | None = None
    trigger_conditions: TriggerConditions | None = None
    actions: list[ActionConfig]
    auto_execute: bool = False


class PlaybookUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    trigger_conditions: TriggerConditions | None = None
    actions: list[ActionConfig] | None = None
    status: PlaybookStatus | None = None
    auto_execute: bool | None = None


class PlaybookResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    trigger_conditions: dict
    actions: list[dict]
    status: PlaybookStatus
    auto_execute: bool
    created_by: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class ExecutionResponse(BaseModel):
    id: UUID
    playbook_id: UUID
    alert_id: str
    status: ExecutionStatus
    started_at: str | None
    completed_at: str | None
    action_results: list[dict]
    error_message: str | None
    triggered_by: str
    created_at: str

    class Config:
        from_attributes = True


class ExecutePlaybookRequest(BaseModel):
    alert_id: str
    alert_data: dict | None = None


@router.get("")
async def list_playbooks(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    status: PlaybookStatus | None = None,
) -> list[PlaybookResponse]:
    """List all playbooks."""
    query = (
        select(Playbook)
        .where(Playbook.organization_id == org_id)
        .order_by(desc(Playbook.created_at))
    )
    if status:
        query = query.where(Playbook.status == status)

    result = await db.execute(query)
    playbooks = result.scalars().all()

    return [
        PlaybookResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            trigger_conditions=p.trigger_conditions,
            actions=p.actions,
            status=p.status,
            auto_execute=p.auto_execute,
            created_by=p.created_by,
            created_at=p.created_at.isoformat(),
            updated_at=p.updated_at.isoformat(),
        )
        for p in playbooks
    ]


@router.get("/{playbook_id}")
async def get_playbook(
    playbook_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> PlaybookResponse:
    """Get a playbook by ID."""
    result = await db.execute(
        select(Playbook).where(Playbook.id == playbook_id, Playbook.organization_id == org_id)
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    return PlaybookResponse(
        id=playbook.id,
        name=playbook.name,
        description=playbook.description,
        trigger_conditions=playbook.trigger_conditions,
        actions=playbook.actions,
        status=playbook.status,
        auto_execute=playbook.auto_execute,
        created_by=playbook.created_by,
        created_at=playbook.created_at.isoformat(),
        updated_at=playbook.updated_at.isoformat(),
    )


@router.post("")
async def create_playbook(
    playbook: PlaybookCreate,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> PlaybookResponse:
    """Create a new playbook. Requires analyst role."""
    email = analyst.email

    db_playbook = Playbook(
        # organization_id is NOT NULL on the model; omitting it made every
        # create fail with an IntegrityError.
        organization_id=org_id,
        name=playbook.name,
        description=playbook.description,
        trigger_conditions=playbook.trigger_conditions.model_dump()
        if playbook.trigger_conditions
        else {},
        actions=[a.model_dump() for a in playbook.actions],
        auto_execute=playbook.auto_execute,
        status=PlaybookStatus.DRAFT,
        created_by=email,
    )
    db.add(db_playbook)
    await db.flush()
    await db.refresh(db_playbook)

    return PlaybookResponse(
        id=db_playbook.id,
        name=db_playbook.name,
        description=db_playbook.description,
        trigger_conditions=db_playbook.trigger_conditions,
        actions=db_playbook.actions,
        status=db_playbook.status,
        auto_execute=db_playbook.auto_execute,
        created_by=db_playbook.created_by,
        created_at=db_playbook.created_at.isoformat(),
        updated_at=db_playbook.updated_at.isoformat(),
    )


@router.patch("/{playbook_id}")
async def update_playbook(
    playbook_id: UUID,
    update: PlaybookUpdate,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> PlaybookResponse:
    """Update a playbook. Requires analyst role."""
    result = await db.execute(
        select(Playbook).where(Playbook.id == playbook_id, Playbook.organization_id == org_id)
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    update_data = update.model_dump(exclude_unset=True)

    if "trigger_conditions" in update_data and update_data["trigger_conditions"]:
        update_data["trigger_conditions"] = update_data["trigger_conditions"]
    if "actions" in update_data and update_data["actions"]:
        update_data["actions"] = update_data["actions"]

    for field, value in update_data.items():
        setattr(playbook, field, value)

    await db.flush()
    await db.refresh(playbook)

    return PlaybookResponse(
        id=playbook.id,
        name=playbook.name,
        description=playbook.description,
        trigger_conditions=playbook.trigger_conditions,
        actions=playbook.actions,
        status=playbook.status,
        auto_execute=playbook.auto_execute,
        created_by=playbook.created_by,
        created_at=playbook.created_at.isoformat(),
        updated_at=playbook.updated_at.isoformat(),
    )


@router.delete("/{playbook_id}")
async def delete_playbook(
    playbook_id: UUID,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a playbook. Requires analyst role."""
    result = await db.execute(
        select(Playbook).where(Playbook.id == playbook_id, Playbook.organization_id == org_id)
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    await db.delete(playbook)
    return {"status": "deleted"}


@router.post("/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: UUID,
    request: ExecutePlaybookRequest,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ExecutionResponse:
    """Execute a playbook for an alert. Requires analyst role."""
    email = analyst.email

    # Get playbook
    result = await db.execute(
        select(Playbook).where(Playbook.id == playbook_id, Playbook.organization_id == org_id)
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if playbook.status != PlaybookStatus.ACTIVE:
        raise HTTPException(status_code=400, detail="Playbook is not active")

    # Prepare alert data
    alert_data = request.alert_data or {"id": request.alert_id}
    alert_data["id"] = request.alert_id

    # Execute playbook
    service = PlaybookService(db)
    execution = await service.execute_playbook(playbook_id, alert_data, triggered_by=email)

    return ExecutionResponse(
        id=execution.id,
        playbook_id=execution.playbook_id,
        alert_id=execution.alert_id,
        status=execution.status,
        started_at=execution.started_at.isoformat() if execution.started_at else None,
        completed_at=execution.completed_at.isoformat() if execution.completed_at else None,
        action_results=execution.action_results,
        error_message=execution.error_message,
        triggered_by=execution.triggered_by,
        created_at=execution.created_at.isoformat(),
    )


@router.get("/{playbook_id}/executions")
async def list_playbook_executions(
    playbook_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> dict:
    """List executions for a playbook."""
    from sqlalchemy import func

    # Count total
    count_query = (
        select(func.count())
        .select_from(PlaybookExecution)
        .where(
            PlaybookExecution.playbook_id == playbook_id,
            PlaybookExecution.organization_id == org_id,
        )
    )
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Get executions
    query = (
        select(PlaybookExecution)
        .where(
            PlaybookExecution.playbook_id == playbook_id,
            PlaybookExecution.organization_id == org_id,
        )
        .order_by(desc(PlaybookExecution.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(query)
    executions = result.scalars().all()

    return {
        "items": [
            ExecutionResponse(
                id=e.id,
                playbook_id=e.playbook_id,
                alert_id=e.alert_id,
                status=e.status,
                started_at=e.started_at.isoformat() if e.started_at else None,
                completed_at=e.completed_at.isoformat() if e.completed_at else None,
                action_results=e.action_results,
                error_message=e.error_message,
                triggered_by=e.triggered_by,
                created_at=e.created_at.isoformat(),
            )
            for e in executions
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/executions/recent")
async def list_recent_executions(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(10, ge=1, le=50),
) -> list[ExecutionResponse]:
    """List recent playbook executions across all playbooks."""
    query = (
        select(PlaybookExecution)
        .where(PlaybookExecution.organization_id == org_id)
        .order_by(desc(PlaybookExecution.created_at))
        .limit(limit)
    )
    result = await db.execute(query)
    executions = result.scalars().all()

    return [
        ExecutionResponse(
            id=e.id,
            playbook_id=e.playbook_id,
            alert_id=e.alert_id,
            status=e.status,
            started_at=e.started_at.isoformat() if e.started_at else None,
            completed_at=e.completed_at.isoformat() if e.completed_at else None,
            action_results=e.action_results,
            error_message=e.error_message,
            triggered_by=e.triggered_by,
            created_at=e.created_at.isoformat(),
        )
        for e in executions
    ]
