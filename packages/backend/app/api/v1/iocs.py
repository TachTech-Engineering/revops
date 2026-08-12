"""
IOC Management API endpoints.
"""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAnalystDep, OrgIdDep, OrgUserDep
from app.db.models import IOCSeverity, IOCType
from app.db.session import get_db
from app.services.ioc_service import ioc_service

router = APIRouter()


# Request/Response models
class IOCCreate(BaseModel):
    ioc_type: IOCType
    value: str = Field(..., min_length=1, max_length=2000)
    severity: IOCSeverity = IOCSeverity.MEDIUM
    description: str | None = None
    tags: list[str] | None = None
    expires_at: datetime | None = None


class IOCUpdate(BaseModel):
    severity: IOCSeverity | None = None
    description: str | None = None
    tags: list[str] | None = None
    is_active: bool | None = None
    expires_at: datetime | None = None


class IOCResponse(BaseModel):
    id: str
    ioc_type: str
    value: str
    severity: str
    source: str
    feed_id: str | None = None
    description: str | None = None
    tags: list[str]
    first_seen: datetime
    last_seen: datetime
    is_active: bool
    expires_at: datetime | None = None
    created_by: str
    created_at: datetime
    updated_at: datetime


class IOCListResponse(BaseModel):
    items: list[IOCResponse]
    total: int
    page: int
    page_size: int


class BulkImportRequest(BaseModel):
    iocs: list[IOCCreate]


class BulkImportResponse(BaseModel):
    added: int
    updated: int


class STIXImportRequest(BaseModel):
    bundle: dict


class IOCStatsResponse(BaseModel):
    total: int
    active: int
    by_type: dict[str, int]
    by_severity: dict[str, int]


def ioc_to_response(ioc) -> IOCResponse:
    """Convert IOC model to response."""
    return IOCResponse(
        id=str(ioc.id),
        ioc_type=ioc.ioc_type.value,
        value=ioc.value,
        severity=ioc.severity.value,
        source=ioc.source,
        feed_id=str(ioc.feed_id) if ioc.feed_id else None,
        description=ioc.description,
        tags=ioc.tags or [],
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
        is_active=ioc.is_active,
        expires_at=ioc.expires_at,
        created_by=ioc.created_by,
        created_at=ioc.created_at,
        updated_at=ioc.updated_at,
    )


@router.get("", response_model=IOCListResponse)
async def list_iocs(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    query: str | None = Query(None, description="Search query"),
    ioc_type: IOCType | None = Query(None, description="Filter by IOC type"),
    severity: IOCSeverity | None = Query(None, description="Filter by severity"),
    source: str | None = Query(None, description="Filter by source"),
    is_active: bool | None = Query(None, description="Filter by active status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    """List IOCs with filters and pagination."""
    iocs, total = await ioc_service.search(
        db,
        query=query,
        ioc_type=ioc_type,
        severity=severity,
        source=source,
        is_active=is_active,
        page=page,
        page_size=page_size,
        organization_id=org_id,
    )

    return IOCListResponse(
        items=[ioc_to_response(ioc) for ioc in iocs],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/stats", response_model=IOCStatsResponse)
async def get_ioc_stats(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get IOC statistics."""
    return await ioc_service.get_stats(db, organization_id=org_id)


@router.get("/types")
async def get_ioc_types():
    """Get available IOC types."""
    return [{"value": t.value, "label": t.value.replace("_", " ").title()} for t in IOCType]


@router.post("", response_model=IOCResponse)
async def create_ioc(
    ioc_create: IOCCreate,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new IOC. Requires analyst role."""
    ioc = await ioc_service.create_ioc(
        db,
        ioc_type=ioc_create.ioc_type,
        value=ioc_create.value,
        severity=ioc_create.severity,
        description=ioc_create.description,
        tags=ioc_create.tags,
        expires_at=ioc_create.expires_at,
        source="Manual",
        created_by=analyst.email,
        organization_id=org_id,
    )
    return ioc_to_response(ioc)


@router.post("/bulk", response_model=BulkImportResponse)
async def bulk_import_iocs(
    request: BulkImportRequest,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Bulk import IOCs from JSON array. Requires analyst role."""
    iocs_data = [
        {
            "ioc_type": ioc.ioc_type,
            "value": ioc.value,
            "severity": ioc.severity,
            "description": ioc.description,
            "tags": ioc.tags,
            "expires_at": ioc.expires_at,
        }
        for ioc in request.iocs
    ]

    result = await ioc_service.bulk_import(
        db,
        iocs=iocs_data,
        source="Bulk Import",
        created_by=analyst.email,
        organization_id=org_id,
    )
    return BulkImportResponse(**result)


@router.post("/import/stix", response_model=BulkImportResponse)
async def import_stix_bundle(
    request: STIXImportRequest,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Import IOCs from a STIX 2.1 bundle. Requires analyst role."""
    try:
        result = await ioc_service.import_stix(
            db,
            bundle_data=request.bundle,
            source="STIX Import",
            created_by=analyst.email,
            organization_id=org_id,
        )
        return BulkImportResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/export/stix")
async def export_stix_bundle(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    ioc_type: IOCType | None = Query(None, description="Filter by IOC type"),
    is_active: bool | None = Query(True, description="Filter by active status"),
):
    """Export IOCs as STIX 2.1 bundle."""
    bundle = await ioc_service.export_stix(
        db,
        ioc_type=ioc_type,
        is_active=is_active,
        organization_id=org_id,
    )
    return bundle


@router.get("/export/csv")
async def export_csv(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    ioc_type: IOCType | None = Query(None, description="Filter by IOC type"),
    is_active: bool | None = Query(True, description="Filter by active status"),
):
    """Export IOCs as CSV."""
    csv_content = await ioc_service.export_csv(
        db,
        ioc_type=ioc_type,
        is_active=is_active,
        organization_id=org_id,
    )
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=iocs.csv"},
    )


@router.get("/{ioc_id}", response_model=IOCResponse)
async def get_ioc(
    ioc_id: uuid.UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a single IOC by ID."""
    ioc = await ioc_service.get_ioc(db, ioc_id, organization_id=org_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    return ioc_to_response(ioc)


@router.patch("/{ioc_id}", response_model=IOCResponse)
async def update_ioc(
    ioc_id: uuid.UUID,
    ioc_update: IOCUpdate,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update an IOC. Requires analyst role."""
    updates = ioc_update.model_dump(exclude_none=True)
    ioc = await ioc_service.update_ioc(db, ioc_id, organization_id=org_id, **updates)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    return ioc_to_response(ioc)


@router.delete("/{ioc_id}")
async def delete_ioc(
    ioc_id: uuid.UUID,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Delete an IOC. Requires analyst role."""
    success = await ioc_service.delete_ioc(db, ioc_id, organization_id=org_id)
    if not success:
        raise HTTPException(status_code=404, detail="IOC not found")
    return {"status": "deleted"}
