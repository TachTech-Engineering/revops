import logging
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import Date, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgIdDep, OrgUserDep
from app.core.time_utils import utcnow
from app.db import get_db
from app.db.models import NormalizedAlert

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/debug/alerts")
async def debug_alerts(
    current_user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Debug endpoint to check alert data."""
    # Count all alerts for this org
    total_result = await db.execute(
        select(func.count(NormalizedAlert.id)).where(
            NormalizedAlert.organization_id == org_id,
        )
    )
    total = total_result.scalar() or 0

    # Get sample alerts
    sample_result = await db.execute(
        select(
            NormalizedAlert.id,
            NormalizedAlert.title,
            NormalizedAlert.severity,
            NormalizedAlert.status,
            NormalizedAlert.created_at_source,
            NormalizedAlert.connector_id,
        )
        .where(NormalizedAlert.organization_id == org_id)
        .order_by(NormalizedAlert.created_at_source.desc())
        .limit(5)
    )
    samples = [
        {
            "id": str(row[0]),
            "title": row[1],
            "severity": row[2],
            "status": row[3],
            "created_at_source": row[4].isoformat() if row[4] else None,
            "connector_id": str(row[5]) if row[5] else None,
        }
        for row in sample_result
    ]

    return {
        "organization_id": str(org_id),
        "total_alerts": total,
        "sample_alerts": samples,
    }


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


class DaySeverityBreakdown(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFO: int = 0


class AnalyticsResponse(BaseModel):
    totalAlerts: int
    bySeverity: SeverityStats
    byStatus: StatusStats
    byDay: dict[str, int]
    byDaySeverity: dict[str, DaySeverityBreakdown]
    topRules: list[RuleCount]


@router.get("/alerts")
async def get_alert_analytics(
    current_user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(7, ge=1, le=90, description="Number of days to analyze"),
) -> AnalyticsResponse:
    """Get alert analytics and statistics from normalized alerts."""
    try:
        since = utcnow() - timedelta(days=days)
        logger.info(f"Analytics query: org_id={org_id}, since={since}, days={days}")

        # Total alerts (no date filter first to see all alerts)
        all_alerts_result = await db.execute(
            select(func.count(NormalizedAlert.id)).where(
                NormalizedAlert.organization_id == org_id,
            )
        )
        all_alerts_count = all_alerts_result.scalar() or 0
        logger.info(f"Total alerts in org (all time): {all_alerts_count}")

        # Total alerts in date range
        total_result = await db.execute(
            select(func.count(NormalizedAlert.id)).where(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at_source >= since,
            )
        )
        total_alerts = total_result.scalar() or 0
        logger.info(f"Total alerts in date range: {total_alerts}")

        # By severity
        severity_result = await db.execute(
            select(NormalizedAlert.severity, func.count(NormalizedAlert.id))
            .where(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at_source >= since,
            )
            .group_by(NormalizedAlert.severity)
        )
        severity_counts = {
            row[0].upper() if row[0] else "MEDIUM": row[1] for row in severity_result
        }
        logger.info(f"Severity counts: {severity_counts}")
        by_severity = SeverityStats(
            INFO=severity_counts.get("INFO", 0),
            LOW=severity_counts.get("LOW", 0),
            MEDIUM=severity_counts.get("MEDIUM", 0),
            HIGH=severity_counts.get("HIGH", 0),
            CRITICAL=severity_counts.get("CRITICAL", 0),
        )

        # By status
        status_result = await db.execute(
            select(NormalizedAlert.status, func.count(NormalizedAlert.id))
            .where(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at_source >= since,
            )
            .group_by(NormalizedAlert.status)
        )
        status_counts = {row[0].upper() if row[0] else "OPEN": row[1] for row in status_result}
        logger.info(f"Status counts: {status_counts}")
        by_status = StatusStats(
            OPEN=status_counts.get("OPEN", 0),
            TRIAGED=status_counts.get("TRIAGED", 0) + status_counts.get("ACKNOWLEDGED", 0),
            CLOSED=status_counts.get("CLOSED", 0),
            RESOLVED=status_counts.get("RESOLVED", 0),
        )

        # By day - use cast to Date for PostgreSQL compatibility
        day_result = await db.execute(
            select(
                cast(NormalizedAlert.created_at_source, Date).label("day"),
                func.count(NormalizedAlert.id),
            )
            .where(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at_source >= since,
            )
            .group_by(cast(NormalizedAlert.created_at_source, Date))
            .order_by(cast(NormalizedAlert.created_at_source, Date))
        )
        by_day = {str(row[0]): row[1] for row in day_result}
        logger.info(f"By day: {by_day}")

        # By day and severity for stacked chart
        day_severity_result = await db.execute(
            select(
                cast(NormalizedAlert.created_at_source, Date).label("day"),
                NormalizedAlert.severity,
                func.count(NormalizedAlert.id),
            )
            .where(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at_source >= since,
            )
            .group_by(cast(NormalizedAlert.created_at_source, Date), NormalizedAlert.severity)
            .order_by(cast(NormalizedAlert.created_at_source, Date))
        )
        by_day_severity: dict[str, dict[str, int]] = {}
        for row in day_severity_result:
            day_str = str(row[0])
            severity = (row[1] or "MEDIUM").upper()
            if day_str not in by_day_severity:
                by_day_severity[day_str] = {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFO": 0,
                }
            by_day_severity[day_str][severity] = row[2]

        # Top rules (by rule_name or title)
        rule_result = await db.execute(
            select(NormalizedAlert.rule_name, func.count(NormalizedAlert.id).label("count"))
            .where(
                NormalizedAlert.organization_id == org_id,
                NormalizedAlert.created_at_source >= since,
                NormalizedAlert.rule_name.isnot(None),
            )
            .group_by(NormalizedAlert.rule_name)
            .order_by(func.count(NormalizedAlert.id).desc())
            .limit(10)
        )
        top_rules = [RuleCount(name=row[0] or "Unknown", count=row[1]) for row in rule_result]

        return AnalyticsResponse(
            totalAlerts=total_alerts,
            bySeverity=by_severity,
            byStatus=by_status,
            byDay=by_day,
            byDaySeverity={k: DaySeverityBreakdown(**v) for k, v in by_day_severity.items()},
            topRules=top_rules,
        )
    except Exception:
        logger.exception("Analytics error")
        raise HTTPException(status_code=500, detail="Failed to compute analytics")
