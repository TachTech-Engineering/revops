from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAnalystDep, OrgUserDep
from app.db import CorrelationRule, get_db

router = APIRouter()


class CorrelationConditions(BaseModel):
    time_window_minutes: int = 60
    min_alerts: int = 2
    field_matches: list[str] | None = None  # Fields that must match across alerts
    severity_filter: list[str] | None = None
    rule_id_filter: list[str] | None = None


class CorrelationRuleCreate(BaseModel):
    name: str
    description: str | None = None
    conditions: CorrelationConditions
    is_active: bool = True
    auto_create_incident: bool = False


class CorrelationRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    conditions: CorrelationConditions | None = None
    is_active: bool | None = None
    auto_create_incident: bool | None = None


class CorrelationRuleResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    conditions: dict
    is_active: bool
    auto_create_incident: bool
    created_by: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


@router.get("")
async def list_correlation_rules(
    user: OrgUserDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    active_only: bool = False,
) -> list[CorrelationRuleResponse]:
    """List all correlation rules."""
    query = select(CorrelationRule).order_by(CorrelationRule.created_at.desc())
    if active_only:
        query = query.where(CorrelationRule.is_active.is_(True))

    result = await db.execute(query)
    rules = result.scalars().all()

    return [
        CorrelationRuleResponse(
            id=r.id,
            name=r.name,
            description=r.description,
            conditions=r.conditions,
            is_active=r.is_active,
            auto_create_incident=r.auto_create_incident,
            created_by=r.created_by,
            created_at=r.created_at.isoformat(),
            updated_at=r.updated_at.isoformat(),
        )
        for r in rules
    ]


@router.get("/{rule_id}")
async def get_correlation_rule(
    rule_id: UUID,
    user: OrgUserDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> CorrelationRuleResponse:
    """Get a correlation rule by ID."""
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Correlation rule not found")

    return CorrelationRuleResponse(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        conditions=rule.conditions,
        is_active=rule.is_active,
        auto_create_incident=rule.auto_create_incident,
        created_by=rule.created_by,
        created_at=rule.created_at.isoformat(),
        updated_at=rule.updated_at.isoformat(),
    )


@router.post("")
async def create_correlation_rule(
    rule: CorrelationRuleCreate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> CorrelationRuleResponse:
    """Create a new correlation rule. Requires analyst role."""
    email = analyst.email

    db_rule = CorrelationRule(
        name=rule.name,
        description=rule.description,
        conditions=rule.conditions.model_dump(),
        is_active=rule.is_active,
        auto_create_incident=rule.auto_create_incident,
        created_by=email,
    )
    db.add(db_rule)
    await db.flush()
    await db.refresh(db_rule)

    return CorrelationRuleResponse(
        id=db_rule.id,
        name=db_rule.name,
        description=db_rule.description,
        conditions=db_rule.conditions,
        is_active=db_rule.is_active,
        auto_create_incident=db_rule.auto_create_incident,
        created_by=db_rule.created_by,
        created_at=db_rule.created_at.isoformat(),
        updated_at=db_rule.updated_at.isoformat(),
    )


@router.patch("/{rule_id}")
async def update_correlation_rule(
    rule_id: UUID,
    update: CorrelationRuleUpdate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> CorrelationRuleResponse:
    """Update a correlation rule. Requires analyst role."""
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Correlation rule not found")

    update_data = update.model_dump(exclude_unset=True)
    if "conditions" in update_data and update_data["conditions"]:
        update_data["conditions"] = update_data["conditions"]

    for field, value in update_data.items():
        setattr(rule, field, value)

    await db.flush()
    await db.refresh(rule)

    return CorrelationRuleResponse(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        conditions=rule.conditions,
        is_active=rule.is_active,
        auto_create_incident=rule.auto_create_incident,
        created_by=rule.created_by,
        created_at=rule.created_at.isoformat(),
        updated_at=rule.updated_at.isoformat(),
    )


@router.delete("/{rule_id}")
async def delete_correlation_rule(
    rule_id: UUID,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a correlation rule. Requires analyst role."""
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Correlation rule not found")

    await db.delete(rule)
    return {"status": "deleted"}
