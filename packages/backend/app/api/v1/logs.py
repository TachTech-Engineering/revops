"""
Raw log search.

Covers the sources RevOps ingests directly (UniFi syslog, the Falco webhook).
Panther-sourced logs live in Snowflake and are searched through the IOC search
endpoint instead.

The organization is taken from the caller's session and passed to the store as
a bind parameter; there is no way for a request to widen its own scope.
"""

from datetime import datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAnalystDep, OrgIdDep
from app.core.time_utils import utcnow
from app.db import get_db
from app.services import log_store

router = APIRouter()

# A search with no bound would scan every partition; the UI always sends a
# range, and this is the fallback for callers that do not.
DEFAULT_WINDOW_HOURS = 24
# Refuse windows longer than retention: the data cannot exist, and the query
# would scan every partition to prove it.
MAX_WINDOW_DAYS = 90


class LogEntry(BaseModel):
    id: UUID
    event_time: datetime
    received_at: datetime
    source_type: str
    connector_id: UUID
    host: str | None
    source_ip: str | None
    severity: str | None
    message: str
    attributes: dict | None


class LogSearchResponse(BaseModel):
    results: list[LogEntry]
    total: int
    limit: int
    offset: int
    start: datetime
    end: datetime


class LogStoreStats(BaseModel):
    stored_bytes: int
    max_stored_bytes: int
    retention_days: int
    partitions: int
    at_capacity: bool


@router.get("/search", response_model=LogSearchResponse)
async def search_logs(
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    q: str | None = Query(None, description="Full-text search over the message"),
    source_type: str | None = Query(None, description="e.g. unifi_syslog, falco"),
    host: str | None = Query(None),
    connector_id: UUID | None = Query(None),
    start: datetime | None = Query(None, description="Inclusive; defaults to 24h ago"),
    end: datetime | None = Query(None, description="Exclusive; defaults to now"),
    limit: int = Query(100, ge=1, le=log_store.MAX_SEARCH_LIMIT),
    offset: int = Query(0, ge=0),
) -> LogSearchResponse:
    """Search raw logs for the caller's organization. Requires analyst role."""
    end = end or utcnow()
    start = start or (end - timedelta(hours=DEFAULT_WINDOW_HOURS))

    if start >= end:
        raise HTTPException(status_code=400, detail="start must be before end")
    if (end - start) > timedelta(days=MAX_WINDOW_DAYS):
        raise HTTPException(
            status_code=400,
            detail=f"Time window cannot exceed {MAX_WINDOW_DAYS} days",
        )

    rows, total = await log_store.search_logs(
        db,
        organization_id=org_id,
        start=start,
        end=end,
        query=q,
        source_type=source_type,
        host=host,
        connector_id=connector_id,
        limit=limit,
        offset=offset,
    )

    return LogSearchResponse(
        results=[LogEntry(**row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
        start=start,
        end=end,
    )


@router.get("/stats", response_model=LogStoreStats)
async def log_store_stats(
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> LogStoreStats:
    """Storage headroom and retention.

    Deliberately reports the whole store rather than one tenant's share: it is
    an operational health signal (is ingestion about to start dropping lines?),
    and it exposes no tenant's data.
    """
    from sqlalchemy import text

    size = await log_store.stored_bytes(db)
    partitions = (
        await db.execute(
            text(
                """
                SELECT count(*) FROM pg_inherits i
                JOIN pg_class p ON p.oid = i.inhparent
                WHERE p.relname = 'raw_log_events'
                """
            )
        )
    ).scalar() or 0

    return LogStoreStats(
        stored_bytes=size,
        max_stored_bytes=log_store.MAX_STORED_BYTES,
        retention_days=log_store.retention_days(),
        partitions=int(partitions),
        at_capacity=size >= log_store.MAX_STORED_BYTES,
    )
