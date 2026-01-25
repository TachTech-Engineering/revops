from typing import Annotated
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db, SuppressionRule

router = APIRouter()


class SuppressionRuleCreate(BaseModel):
    name: str
    description: str | None = None
    rule_id: str | None = None
    severity: str | None = None
    title_pattern: str | None = None
    is_active: bool = True
    expires_at: datetime | None = None


class SuppressionRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    rule_id: str | None = None
    severity: str | None = None
    title_pattern: str | None = None
    is_active: bool | None = None
    expires_at: datetime | None = None


class SuppressionRuleResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    rule_id: str | None
    severity: str | None
    title_pattern: str | None
    is_active: bool
    expires_at: str | None
    created_by: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


@router.get("")
async def list_suppression_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    active_only: bool = False,
) -> list[SuppressionRuleResponse]:
    """List all suppression rules."""
    query = select(SuppressionRule).order_by(SuppressionRule.created_at.desc())
    if active_only:
        query = query.where(SuppressionRule.is_active == True)
    result = await db.execute(query)
    rules = result.scalars().all()
    return [
        SuppressionRuleResponse(
            id=r.id,
            name=r.name,
            description=r.description,
            rule_id=r.rule_id,
            severity=r.severity,
            title_pattern=r.title_pattern,
            is_active=r.is_active,
            expires_at=r.expires_at.isoformat() if r.expires_at else None,
            created_by=r.created_by,
            created_at=r.created_at.isoformat(),
            updated_at=r.updated_at.isoformat(),
        )
        for r in rules
    ]


@router.post("")
async def create_suppression_rule(
    rule: SuppressionRuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SuppressionRuleResponse:
    """Create a new suppression rule."""
    db_rule = SuppressionRule(
        name=rule.name,
        description=rule.description,
        rule_id=rule.rule_id,
        severity=rule.severity,
        title_pattern=rule.title_pattern,
        is_active=rule.is_active,
        expires_at=rule.expires_at,
    )
    db.add(db_rule)
    await db.flush()
    await db.refresh(db_rule)
    return SuppressionRuleResponse(
        id=db_rule.id,
        name=db_rule.name,
        description=db_rule.description,
        rule_id=db_rule.rule_id,
        severity=db_rule.severity,
        title_pattern=db_rule.title_pattern,
        is_active=db_rule.is_active,
        expires_at=db_rule.expires_at.isoformat() if db_rule.expires_at else None,
        created_by=db_rule.created_by,
        created_at=db_rule.created_at.isoformat(),
        updated_at=db_rule.updated_at.isoformat(),
    )


@router.patch("/{rule_id}")
async def update_suppression_rule(
    rule_id: UUID,
    update: SuppressionRuleUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SuppressionRuleResponse:
    """Update a suppression rule."""
    result = await db.execute(select(SuppressionRule).where(SuppressionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Suppression rule not found")

    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)

    await db.flush()
    await db.refresh(rule)
    return SuppressionRuleResponse(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        rule_id=rule.rule_id,
        severity=rule.severity,
        title_pattern=rule.title_pattern,
        is_active=rule.is_active,
        expires_at=rule.expires_at.isoformat() if rule.expires_at else None,
        created_by=rule.created_by,
        created_at=rule.created_at.isoformat(),
        updated_at=rule.updated_at.isoformat(),
    )


@router.delete("/{rule_id}")
async def delete_suppression_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a suppression rule."""
    result = await db.execute(select(SuppressionRule).where(SuppressionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Suppression rule not found")

    await db.delete(rule)
    return {"status": "deleted"}
