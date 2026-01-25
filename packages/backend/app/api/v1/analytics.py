from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.api.v1.deps import PantherServiceDep

router = APIRouter()


class SeverityStats(BaseModel):
    INFO: int = 0
    LOW: int = 0
    MEDIUM: int = 0
    HIGH: int = 0
    CRITICAL: int = 0


class StatusStats(BaseModel):
    OPEN: int = 0
    TRIAGED: int = 0
    CLOSED: int = 0
    RESOLVED: int = 0


class RuleCount(BaseModel):
    name: str
    count: int


class AnalyticsResponse(BaseModel):
    totalAlerts: int
    bySeverity: SeverityStats
    byStatus: StatusStats
    byDay: dict[str, int]
    topRules: list[RuleCount]


@router.get("/alerts")
async def get_alert_analytics(
    panther: PantherServiceDep,
    days: int = Query(7, ge=1, le=90, description="Number of days to analyze"),
) -> AnalyticsResponse:
    """Get alert analytics and statistics."""
    try:
        stats = await panther.get_alert_stats(days=days)
        return AnalyticsResponse(
            totalAlerts=stats["totalAlerts"],
            bySeverity=SeverityStats(**stats["bySeverity"]),
            byStatus=StatusStats(**stats["byStatus"]),
            byDay=stats["byDay"],
            topRules=[RuleCount(**r) for r in stats["topRules"]],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
