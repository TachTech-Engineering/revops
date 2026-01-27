from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db, SavedQuery
from app.api.v1.deps import OrgUserDep, OrgIdDep, OrgAnalystDep

router = APIRouter()


class SavedQueryCreate(BaseModel):
    name: str
    description: str | None = None
    sql: str
    is_shared: bool = False


class SavedQueryUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    sql: str | None = None
    is_shared: bool | None = None


class SavedQueryResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    sql: str
    is_shared: bool
    created_by: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


@router.get("")
async def list_saved_queries(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[SavedQueryResponse]:
    """List all saved queries."""
    result = await db.execute(
        select(SavedQuery)
        .where(SavedQuery.organization_id == org_id)
        .order_by(SavedQuery.updated_at.desc())
    )
    queries = result.scalars().all()
    return [
        SavedQueryResponse(
            id=q.id,
            name=q.name,
            description=q.description,
            sql=q.sql,
            is_shared=q.is_shared,
            created_by=q.created_by,
            created_at=q.created_at.isoformat(),
            updated_at=q.updated_at.isoformat(),
        )
        for q in queries
    ]


@router.post("")
async def create_saved_query(
    query: SavedQueryCreate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SavedQueryResponse:
    """Create a new saved query. Requires analyst role."""
    db_query = SavedQuery(
        name=query.name,
        description=query.description,
        sql=query.sql,
        is_shared=query.is_shared,
        created_by=analyst.email,
        organization_id=analyst.organization_id,
    )
    db.add(db_query)
    await db.flush()
    await db.refresh(db_query)
    return SavedQueryResponse(
        id=db_query.id,
        name=db_query.name,
        description=db_query.description,
        sql=db_query.sql,
        is_shared=db_query.is_shared,
        created_by=db_query.created_by,
        created_at=db_query.created_at.isoformat(),
        updated_at=db_query.updated_at.isoformat(),
    )


@router.get("/{query_id}")
async def get_saved_query(
    query_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SavedQueryResponse:
    """Get a saved query by ID."""
    result = await db.execute(
        select(SavedQuery).where(and_(SavedQuery.id == query_id, SavedQuery.organization_id == org_id))
    )
    query = result.scalar_one_or_none()
    if not query:
        raise HTTPException(status_code=404, detail="Query not found")
    return SavedQueryResponse(
        id=query.id,
        name=query.name,
        description=query.description,
        sql=query.sql,
        is_shared=query.is_shared,
        created_by=query.created_by,
        created_at=query.created_at.isoformat(),
        updated_at=query.updated_at.isoformat(),
    )


@router.patch("/{query_id}")
async def update_saved_query(
    query_id: UUID,
    update: SavedQueryUpdate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SavedQueryResponse:
    """Update a saved query. Requires analyst role."""
    result = await db.execute(
        select(SavedQuery).where(and_(SavedQuery.id == query_id, SavedQuery.organization_id == analyst.organization_id))
    )
    query = result.scalar_one_or_none()
    if not query:
        raise HTTPException(status_code=404, detail="Query not found")

    if update.name is not None:
        query.name = update.name
    if update.description is not None:
        query.description = update.description
    if update.sql is not None:
        query.sql = update.sql
    if update.is_shared is not None:
        query.is_shared = update.is_shared

    await db.flush()
    await db.refresh(query)
    return SavedQueryResponse(
        id=query.id,
        name=query.name,
        description=query.description,
        sql=query.sql,
        is_shared=query.is_shared,
        created_by=query.created_by,
        created_at=query.created_at.isoformat(),
        updated_at=query.updated_at.isoformat(),
    )


@router.delete("/{query_id}")
async def delete_saved_query(
    query_id: UUID,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a saved query. Requires analyst role."""
    result = await db.execute(
        select(SavedQuery).where(and_(SavedQuery.id == query_id, SavedQuery.organization_id == analyst.organization_id))
    )
    query = result.scalar_one_or_none()
    if not query:
        raise HTTPException(status_code=404, detail="Query not found")

    await db.delete(query)
    return {"status": "deleted"}
