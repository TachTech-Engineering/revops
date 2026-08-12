"""
Threat Feed Management API endpoints.
"""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAnalystDep, OrgIdDep, OrgUserDep
from app.db.models import FeedStatus, FeedType
from app.db.session import get_db
from app.services.feed_service import feed_service

router = APIRouter()

# All endpoints are scoped to the caller's organization via OrgIdDep. Feeds
# belonging to another organization are indistinguishable from missing feeds
# (404), matching the cross-org behavior of the rule health endpoints.


# Request/Response models
class FeedCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    url: str = Field(..., min_length=1)
    feed_type: FeedType
    update_interval_minutes: int = Field(60, ge=5, le=1440)  # 5 min to 24 hours


class FeedUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    update_interval_minutes: int | None = None
    status: FeedStatus | None = None


class FeedResponse(BaseModel):
    id: str
    name: str
    url: str
    feed_type: str
    status: str
    update_interval_minutes: int
    last_sync_at: datetime | None = None
    next_sync_at: datetime | None = None
    ioc_count: int
    error_message: str | None = None
    created_by: str
    created_at: datetime
    updated_at: datetime


class SyncLogResponse(BaseModel):
    id: str
    feed_id: str
    status: str
    iocs_added: int
    iocs_updated: int
    duration_ms: int
    error: str | None = None
    synced_at: datetime


class SyncResult(BaseModel):
    feed_id: str
    feed_name: str
    status: str
    iocs_added: int
    iocs_updated: int
    error: str | None = None
    duration_ms: int | None = None


def feed_to_response(feed) -> FeedResponse:
    """Convert Feed model to response."""
    return FeedResponse(
        id=str(feed.id),
        name=feed.name,
        url=feed.url,
        feed_type=feed.feed_type.value,
        status=feed.status.value,
        update_interval_minutes=feed.update_interval_minutes,
        last_sync_at=feed.last_sync_at,
        next_sync_at=feed.next_sync_at,
        ioc_count=feed.ioc_count,
        error_message=feed.error_message,
        created_by=feed.created_by,
        created_at=feed.created_at,
        updated_at=feed.updated_at,
    )


def sync_log_to_response(log) -> SyncLogResponse:
    """Convert FeedSyncLog model to response."""
    return SyncLogResponse(
        id=str(log.id),
        feed_id=str(log.feed_id),
        status=log.status,
        iocs_added=log.iocs_added,
        iocs_updated=log.iocs_updated,
        duration_ms=log.duration_ms,
        error=log.error,
        synced_at=log.synced_at,
    )


@router.get("", response_model=list[FeedResponse])
async def list_feeds(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    status: FeedStatus | None = Query(None, description="Filter by status"),
):
    """List the organization's threat feed subscriptions."""
    feeds = await feed_service.list_feeds(db, organization_id=org_id, status=status)
    return [feed_to_response(feed) for feed in feeds]


@router.get("/types")
async def get_feed_types(user: OrgUserDep):
    """Get available feed types."""
    return [
        {
            "value": FeedType.ABUSECH_FEODO.value,
            "label": "Abuse.ch Feodo Tracker",
            "description": "Botnet C2 IP blocklist",
            "default_url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        },
        {
            "value": FeedType.ABUSECH_URLHAUS.value,
            "label": "Abuse.ch URLhaus",
            "description": "Malicious URL feed",
            "default_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        },
        {
            "value": FeedType.OTX.value,
            "label": "AlienVault OTX Pulse",
            "description": "OTX threat intelligence pulse (JSON)",
            "default_url": "",
        },
        {
            "value": FeedType.CUSTOM_CSV.value,
            "label": "Custom CSV",
            "description": "Generic CSV with IOC values in first column",
            "default_url": "",
        },
        {
            "value": FeedType.CUSTOM_STIX.value,
            "label": "Custom STIX",
            "description": "STIX 2.1 bundle feed",
            "default_url": "",
        },
    ]


@router.post("", response_model=FeedResponse)
async def create_feed(
    feed_create: FeedCreate,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new feed subscription. Requires analyst role."""
    feed = await feed_service.create_feed(
        db,
        name=feed_create.name,
        url=feed_create.url,
        feed_type=feed_create.feed_type,
        update_interval_minutes=feed_create.update_interval_minutes,
        created_by=analyst.email,
        organization_id=org_id,
    )
    return feed_to_response(feed)


@router.get("/{feed_id}", response_model=FeedResponse)
async def get_feed(
    feed_id: uuid.UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a single feed by ID."""
    feed = await feed_service.get_feed(db, feed_id, organization_id=org_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    return feed_to_response(feed)


@router.patch("/{feed_id}", response_model=FeedResponse)
async def update_feed(
    feed_id: uuid.UUID,
    feed_update: FeedUpdate,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update a feed. Requires analyst role."""
    updates = feed_update.model_dump(exclude_none=True)
    feed = await feed_service.update_feed(db, feed_id, organization_id=org_id, **updates)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    return feed_to_response(feed)


@router.delete("/{feed_id}")
async def delete_feed(
    feed_id: uuid.UUID,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Delete a feed and its associated IOCs. Requires analyst role."""
    success = await feed_service.delete_feed(db, feed_id, organization_id=org_id)
    if not success:
        raise HTTPException(status_code=404, detail="Feed not found")
    return {"status": "deleted"}


@router.post("/{feed_id}/sync", response_model=SyncResult)
async def sync_feed(
    feed_id: uuid.UUID,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Trigger a manual sync for a feed. Requires analyst role."""
    try:
        result = await feed_service.sync_feed(db, feed_id, organization_id=org_id)
        return SyncResult(**result)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{feed_id}/logs", response_model=list[SyncLogResponse])
async def get_sync_logs(
    feed_id: uuid.UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(20, ge=1, le=100),
):
    """Get sync history for a feed."""
    feed = await feed_service.get_feed(db, feed_id, organization_id=org_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    logs = await feed_service.get_sync_logs(db, feed_id, organization_id=org_id, limit=limit)
    return [sync_log_to_response(log) for log in logs]


@router.post("/sync-all", response_model=list[SyncResult])
async def sync_all_feeds(
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Trigger sync for the organization's active feeds that are due. Requires analyst role."""
    results = await feed_service.sync_all_active(db, organization_id=org_id)
    return [SyncResult(**r) for r in results]
