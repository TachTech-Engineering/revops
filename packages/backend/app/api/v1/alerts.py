from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgIdDep, OrgUserDep
from app.core.time_utils import utcnow
from app.db import get_db
from app.db.models import NormalizedAlert

router = APIRouter()


class AlertUpdateRequest(BaseModel):
    status: str | None = None
    assigneeId: str | None = None


class CommentRequest(BaseModel):
    body: str


class BulkUpdateRequest(BaseModel):
    alert_ids: list[str]
    action: str  # acknowledge, resolve, close, set_severity, assign
    value: str | None = None  # for set_severity or assign


class BulkUpdateResult(BaseModel):
    success: list[str]
    failed: list[dict[str, str]]


class PaginatedResponse(BaseModel):
    results: list[dict[str, Any]]
    cursor: str | None = None
    hasMore: bool = False


@router.get("")
async def list_alerts(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    status: str | None = Query(None, description="Filter by status"),
    severity: str | None = Query(None, description="Filter by severity"),
    detectionId: str | None = Query(None, description="Filter by detection ID"),
    pageSize: int = Query(50, ge=1, le=100, description="Page size"),
    page: int = Query(1, ge=1, description="Page number"),
) -> PaginatedResponse:
    """List alerts from all connected data sources."""
    import logging

    logger = logging.getLogger(__name__)
    logger.info(
        f"Fetching alerts from connectors: status={status}, "
        f"severity={severity}, pageSize={pageSize}"
    )

    # Build query for normalized alerts from connectors
    query = select(NormalizedAlert).where(NormalizedAlert.organization_id == org_id)

    if status:
        query = query.where(NormalizedAlert.status == status.lower())
    if severity:
        query = query.where(NormalizedAlert.severity == severity.lower())
    if detectionId:
        query = query.where(NormalizedAlert.rule_id == detectionId)

    # Order by creation time descending
    query = query.order_by(desc(NormalizedAlert.created_at_source))

    # Pagination
    offset = (page - 1) * pageSize
    query = query.offset(offset).limit(pageSize + 1)  # Get one extra to check hasMore

    result = await db.execute(query)
    alerts = result.scalars().all()

    # Check if there are more results
    has_more = len(alerts) > pageSize
    if has_more:
        alerts = alerts[:pageSize]

    # Convert to response format matching the original Panther alert structure
    results = []
    for alert in alerts:
        results.append(
            {
                "id": str(alert.id),
                "externalId": alert.external_id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity.upper() if alert.severity else "MEDIUM",
                "status": alert.status.upper() if alert.status else "OPEN",
                "detectionId": alert.rule_id,
                "detectionName": alert.rule_name,
                "createdAt": alert.created_at_source.isoformat()
                if alert.created_at_source
                else None,
                "updatedAt": alert.updated_at_source.isoformat()
                if alert.updated_at_source
                else None,
                "sourceType": alert.source_type,
                "connectorId": str(alert.connector_id),
                "tags": alert.tags or [],
                "mitreTactics": alert.mitre_tactics or [],
                "mitreTechniques": alert.mitre_techniques or [],
            }
        )

    logger.info(f"Got {len(results)} alerts from connectors")
    return PaginatedResponse(
        results=results,
        cursor=str(page + 1) if has_more else None,
        hasMore=has_more,
    )


@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, Any]:
    """Get a single alert by ID."""
    try:
        alert_uuid = UUID(alert_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID format")

    result = await db.execute(
        select(NormalizedAlert).where(
            and_(
                NormalizedAlert.id == alert_uuid,
                NormalizedAlert.organization_id == org_id,
            )
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {
        "id": str(alert.id),
        "externalId": alert.external_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity.upper() if alert.severity else "MEDIUM",
        "status": alert.status.upper() if alert.status else "OPEN",
        "detectionId": alert.rule_id,
        "detectionName": alert.rule_name,
        "createdAt": alert.created_at_source.isoformat() if alert.created_at_source else None,
        "updatedAt": alert.updated_at_source.isoformat() if alert.updated_at_source else None,
        "sourceType": alert.source_type,
        "connectorId": str(alert.connector_id),
        "tags": alert.tags or [],
        "mitreTactics": alert.mitre_tactics or [],
        "mitreTechniques": alert.mitre_techniques or [],
        "rawData": alert.raw_data,
    }


@router.patch("/{alert_id}")
async def update_alert(
    alert_id: str,
    update: AlertUpdateRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, Any]:
    """Update alert status or assignee."""
    try:
        alert_uuid = UUID(alert_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID format")

    result = await db.execute(
        select(NormalizedAlert).where(
            and_(
                NormalizedAlert.id == alert_uuid,
                NormalizedAlert.organization_id == org_id,
            )
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if update.status:
        alert.status = update.status.lower()

    await db.flush()
    await db.refresh(alert)

    return {
        "id": str(alert.id),
        "status": alert.status.upper() if alert.status else "OPEN",
        "updatedAt": alert.updated_at_source.isoformat() if alert.updated_at_source else None,
    }


@router.get("/{alert_id}/events")
async def get_alert_events(
    alert_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    pageSize: int = Query(50, ge=1, le=100, description="Page size"),
) -> PaginatedResponse:
    """Get events associated with an alert (from raw_data if available)."""
    try:
        alert_uuid = UUID(alert_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID format")

    result = await db.execute(
        select(NormalizedAlert).where(
            and_(
                NormalizedAlert.id == alert_uuid,
                NormalizedAlert.organization_id == org_id,
            )
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Events might be in raw_data
    events = []
    if alert.raw_data and "events" in alert.raw_data:
        events = alert.raw_data["events"][:pageSize]

    return PaginatedResponse(
        results=events,
        cursor=None,
        hasMore=False,
    )


@router.post("/{alert_id}/comments")
async def add_comment(
    alert_id: str,
    request: CommentRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, Any]:
    """Add a comment to an alert (stored locally)."""
    try:
        alert_uuid = UUID(alert_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID format")

    result = await db.execute(
        select(NormalizedAlert).where(
            and_(
                NormalizedAlert.id == alert_uuid,
                NormalizedAlert.organization_id == org_id,
            )
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Store comment in raw_data
    if not alert.raw_data:
        alert.raw_data = {}
    if "comments" not in alert.raw_data:
        alert.raw_data["comments"] = []

    comment = {
        "id": str(UUID(int=len(alert.raw_data["comments"]))),
        "body": request.body,
        "author": user.email,
        "createdAt": utcnow().isoformat(),
    }
    alert.raw_data["comments"].append(comment)

    await db.flush()

    return comment


@router.post("/bulk-update")
async def bulk_update_alerts(
    request: BulkUpdateRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> BulkUpdateResult:
    """Bulk update multiple alerts at once."""
    success = []
    failed = []

    # Map actions to status values
    action_to_status = {
        "acknowledge": "acknowledged",
        "resolve": "resolved",
        "close": "closed",
        "reopen": "open",
    }

    for alert_id in request.alert_ids:
        try:
            alert_uuid = UUID(alert_id)
            result = await db.execute(
                select(NormalizedAlert).where(
                    and_(
                        NormalizedAlert.id == alert_uuid,
                        NormalizedAlert.organization_id == org_id,
                    )
                )
            )
            alert = result.scalar_one_or_none()
            if alert:
                # Handle different actions
                if request.action in action_to_status:
                    alert.status = action_to_status[request.action]
                elif request.action == "set_severity" and request.value:
                    alert.severity = request.value.lower()
                elif request.action == "assign" and request.value:
                    # Store assignee in raw_data
                    if not alert.raw_data:
                        alert.raw_data = {}
                    alert.raw_data["assignee"] = request.value
                else:
                    failed.append({"id": alert_id, "error": f"Unknown action: {request.action}"})
                    continue
                success.append(alert_id)
            else:
                failed.append({"id": alert_id, "error": "Not found"})
        except Exception as e:
            failed.append({"id": alert_id, "error": str(e)})

    await db.commit()
    return BulkUpdateResult(success=success, failed=failed)
