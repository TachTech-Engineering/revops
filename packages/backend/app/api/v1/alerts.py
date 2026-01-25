from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.api.v1.deps import PantherServiceDep

router = APIRouter()


class AlertUpdateRequest(BaseModel):
    status: Optional[str] = None
    assigneeId: Optional[str] = None


class CommentRequest(BaseModel):
    body: str


class BulkUpdateRequest(BaseModel):
    alert_ids: list[str]
    status: Optional[str] = None
    assigneeId: Optional[str] = None


class BulkUpdateResult(BaseModel):
    success: list[str]
    failed: list[dict[str, str]]


class PaginatedResponse(BaseModel):
    results: list[dict[str, Any]]
    cursor: Optional[str] = None
    hasMore: bool = False


@router.get("")
async def list_alerts(
    panther: PantherServiceDep,
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    detectionId: Optional[str] = Query(None, description="Filter by detection ID"),
    pageSize: int = Query(50, ge=1, le=100, description="Page size"),
) -> PaginatedResponse:
    """List alerts with optional filtering."""
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Fetching alerts: status={status}, severity={severity}, pageSize={pageSize}")
    try:
        alerts, cursor = await panther.list_alerts(
            status=status,
            severity=severity,
            detection_id=detectionId,
            page_size=pageSize,
        )
        logger.info(f"Got {len(alerts)} alerts from Panther API")
        return PaginatedResponse(
            results=alerts,
            cursor=cursor,
            hasMore=cursor is not None,
        )
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    panther: PantherServiceDep,
) -> dict[str, Any]:
    """Get a single alert by ID."""
    try:
        return await panther.get_alert(alert_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{alert_id}")
async def update_alert(
    alert_id: str,
    update: AlertUpdateRequest,
    panther: PantherServiceDep,
) -> dict[str, Any]:
    """Update alert status or assignee."""
    try:
        return await panther.update_alert(
            alert_id,
            status=update.status,
            assignee_id=update.assigneeId,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{alert_id}/events")
async def get_alert_events(
    alert_id: str,
    panther: PantherServiceDep,
    pageSize: int = Query(50, ge=1, le=100, description="Page size"),
) -> PaginatedResponse:
    """Get events associated with an alert."""
    try:
        events, cursor = await panther.get_alert_events(alert_id, page_size=pageSize)
        return PaginatedResponse(
            results=events,
            cursor=cursor,
            hasMore=cursor is not None,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{alert_id}/comments")
async def add_comment(
    alert_id: str,
    request: CommentRequest,
    panther: PantherServiceDep,
) -> dict[str, Any]:
    """Add a comment to an alert."""
    try:
        return await panther.add_alert_comment(alert_id, request.body)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bulk-update")
async def bulk_update_alerts(
    request: BulkUpdateRequest,
    panther: PantherServiceDep,
) -> BulkUpdateResult:
    """Bulk update multiple alerts at once."""
    success = []
    failed = []

    for alert_id in request.alert_ids:
        try:
            await panther.update_alert(
                alert_id,
                status=request.status,
                assignee_id=request.assigneeId,
            )
            success.append(alert_id)
        except Exception as e:
            failed.append({"id": alert_id, "error": str(e)})

    return BulkUpdateResult(success=success, failed=failed)
