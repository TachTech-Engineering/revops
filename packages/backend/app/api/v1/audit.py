from typing import Annotated, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db, AuditLog
from app.api.v1.deps import OrgAdminDep, OrgIdDep

router = APIRouter()


class AuditLogResponse(BaseModel):
    id: UUID
    user_email: str
    action: str
    resource_type: str
    resource_id: Optional[str]
    details: dict
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: str

    class Config:
        from_attributes = True


class AuditLogListResponse(BaseModel):
    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int


@router.get("")
async def list_audit_logs(
    admin: OrgAdminDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    user_email: Optional[str] = Query(None, description="Filter by user email"),
    action: Optional[str] = Query(None, description="Filter by action"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    resource_id: Optional[str] = Query(None, description="Filter by resource ID"),
    start_date: Optional[datetime] = Query(None, description="Filter by start date"),
    end_date: Optional[datetime] = Query(None, description="Filter by end date"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
) -> AuditLogListResponse:
    """List audit logs with filtering. Admin only."""
    query = select(AuditLog).where(AuditLog.organization_id == org_id)

    # Apply filters
    if user_email:
        query = query.where(AuditLog.user_email.ilike(f"%{user_email}%"))
    if action:
        query = query.where(AuditLog.action == action)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
    if resource_id:
        query = query.where(AuditLog.resource_id == resource_id)
    if start_date:
        query = query.where(AuditLog.created_at >= start_date)
    if end_date:
        query = query.where(AuditLog.created_at <= end_date)

    # Get total count
    from sqlalchemy import func
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Apply pagination and ordering
    query = query.order_by(desc(AuditLog.created_at))
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    logs = result.scalars().all()

    return AuditLogListResponse(
        items=[
            AuditLogResponse(
                id=log.id,
                user_email=log.user_email,
                action=log.action,
                resource_type=log.resource_type,
                resource_id=log.resource_id,
                details=log.details,
                ip_address=log.ip_address,
                user_agent=log.user_agent,
                created_at=log.created_at.isoformat(),
            )
            for log in logs
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/actions")
async def list_audit_actions(
    admin: OrgAdminDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[str]:
    """List distinct audit actions. Admin only."""
    from sqlalchemy import distinct
    result = await db.execute(
        select(distinct(AuditLog.action))
        .where(AuditLog.organization_id == org_id)
        .order_by(AuditLog.action)
    )
    return [row[0] for row in result.all()]


@router.get("/resource-types")
async def list_audit_resource_types(
    admin: OrgAdminDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[str]:
    """List distinct resource types. Admin only."""
    from sqlalchemy import distinct
    result = await db.execute(
        select(distinct(AuditLog.resource_type))
        .where(AuditLog.organization_id == org_id)
        .order_by(AuditLog.resource_type)
    )
    return [row[0] for row in result.all()]
