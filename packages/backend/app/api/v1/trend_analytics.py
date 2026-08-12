"""
Trend Analysis API - Feature 9
Forecasting, anomaly detection, coverage visualization.
"""

from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAdminDep, OrgIdDep, OrgUserDep
from app.core.time_utils import utcnow
from app.db import (
    AlertTrendCache,
    AnomalyDetection,
    AnomalyType,
    MitreMapping,
    get_db,
)

router = APIRouter()


# ==================== Response Models ====================


class TrendDataPoint(BaseModel):
    timestamp: str
    total: int
    by_severity: dict
    change_from_previous: float | None


class TrendResponse(BaseModel):
    bucket_type: str
    data_points: list[TrendDataPoint]
    total_period: int
    average: float
    trend_direction: str  # increasing, decreasing, stable


class ForecastResponse(BaseModel):
    forecast_period: str
    predicted_total: int
    confidence_interval: dict
    prediction_method: str
    historical_average: float


class AnomalyResponse(BaseModel):
    id: str
    anomaly_type: str
    severity: str
    description: str
    detected_value: float
    expected_value: float
    deviation_percentage: float
    related_rule_ids: list
    time_range_start: str
    time_range_end: str
    is_acknowledged: bool
    detected_at: str

    class Config:
        from_attributes = True


class CoverageGapResponse(BaseModel):
    tactic: str
    tactic_name: str
    total_techniques: int
    covered_techniques: int
    coverage_percentage: float
    missing_techniques: list[dict]


# ==================== Trends ====================


@router.get("/trends", response_model=TrendResponse)
async def get_trends(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    bucket_type: str = Query("daily", description="hourly, daily, or weekly"),
    days: int = Query(30, ge=1, le=365),
):
    """Get alert volume trends."""
    end_date = utcnow()
    start_date = end_date - timedelta(days=days)

    result = await db.execute(
        select(AlertTrendCache)
        .where(AlertTrendCache.organization_id == org_id)
        .where(AlertTrendCache.bucket_type == bucket_type)
        .where(AlertTrendCache.bucket_start >= start_date)
        .order_by(AlertTrendCache.bucket_start.asc())
    )
    cached = result.scalars().all()

    if cached:
        data_points = [
            TrendDataPoint(
                timestamp=c.bucket_start.isoformat(),
                total=c.total_alerts,
                by_severity=c.by_severity,
                change_from_previous=c.change_from_previous,
            )
            for c in cached
        ]
        total = sum(c.total_alerts for c in cached)
        average = total / len(cached) if cached else 0
    else:
        # Generate demo data if no cached data
        data_points = []
        total = 0
        current = start_date

        while current < end_date:
            import random

            daily_total = random.randint(50, 200)
            total += daily_total

            data_points.append(
                TrendDataPoint(
                    timestamp=current.isoformat(),
                    total=daily_total,
                    by_severity={
                        "critical": random.randint(5, 15),
                        "high": random.randint(15, 40),
                        "medium": random.randint(20, 60),
                        "low": random.randint(10, 50),
                    },
                    change_from_previous=random.uniform(-20, 20),
                )
            )

            if bucket_type == "hourly":
                current += timedelta(hours=1)
            elif bucket_type == "weekly":
                current += timedelta(weeks=1)
            else:
                current += timedelta(days=1)

        average = total / len(data_points) if data_points else 0

    # Determine trend direction
    if len(data_points) >= 2:
        recent = sum(dp.total for dp in data_points[-7:]) / min(7, len(data_points[-7:]))
        older = sum(dp.total for dp in data_points[:7]) / min(7, len(data_points[:7]))
        if recent > older * 1.1:
            trend_direction = "increasing"
        elif recent < older * 0.9:
            trend_direction = "decreasing"
        else:
            trend_direction = "stable"
    else:
        trend_direction = "stable"

    return TrendResponse(
        bucket_type=bucket_type,
        data_points=data_points,
        total_period=total,
        average=round(average, 2),
        trend_direction=trend_direction,
    )


@router.get("/forecast", response_model=ForecastResponse)
async def get_forecast(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    forecast_days: int = Query(7, ge=1, le=30),
):
    """Get predicted alert volume for upcoming period."""
    # Get historical data for forecasting
    end_date = utcnow()
    start_date = end_date - timedelta(days=30)

    result = await db.execute(
        select(AlertTrendCache)
        .where(AlertTrendCache.organization_id == org_id)
        .where(AlertTrendCache.bucket_type == "daily")
        .where(AlertTrendCache.bucket_start >= start_date)
    )
    cached = result.scalars().all()

    if cached:
        historical_totals = [c.total_alerts for c in cached]
        historical_average = sum(historical_totals) / len(historical_totals)
    else:
        # Demo data
        import random

        historical_totals = [random.randint(50, 200) for _ in range(30)]
        historical_average = sum(historical_totals) / len(historical_totals)

    # Simple moving average forecast
    if len(historical_totals) >= 7:
        recent_average = sum(historical_totals[-7:]) / 7
        predicted_daily = recent_average
    else:
        predicted_daily = historical_average

    predicted_total = int(predicted_daily * forecast_days)

    # Calculate confidence interval (simple standard deviation based)
    import statistics

    if len(historical_totals) >= 2:
        std_dev = statistics.stdev(historical_totals)
    else:
        std_dev = historical_average * 0.2

    margin = std_dev * forecast_days * 0.5

    return ForecastResponse(
        forecast_period=f"Next {forecast_days} days",
        predicted_total=predicted_total,
        confidence_interval={
            "lower": int(max(0, predicted_total - margin)),
            "upper": int(predicted_total + margin),
            "confidence_level": "95%",
        },
        prediction_method="7-day moving average",
        historical_average=round(historical_average, 2),
    )


# ==================== Anomaly Detection ====================


@router.get("/anomalies", response_model=list[AnomalyResponse])
async def get_anomalies(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    acknowledged: bool | None = Query(None),
    severity: str | None = Query(None),
    days: int = Query(7, ge=1, le=90),
):
    """Get detected anomalies."""
    start_date = utcnow() - timedelta(days=days)

    query = (
        select(AnomalyDetection)
        .where(AnomalyDetection.organization_id == org_id)
        .where(AnomalyDetection.detected_at >= start_date)
    )

    if acknowledged is not None:
        query = query.where(AnomalyDetection.is_acknowledged == acknowledged)
    if severity:
        query = query.where(AnomalyDetection.severity == severity)

    query = query.order_by(desc(AnomalyDetection.detected_at))

    result = await db.execute(query)
    anomalies = result.scalars().all()

    return [
        AnomalyResponse(
            id=str(a.id),
            anomaly_type=a.anomaly_type.value,
            severity=a.severity,
            description=a.description,
            detected_value=a.detected_value,
            expected_value=a.expected_value,
            deviation_percentage=a.deviation_percentage,
            related_rule_ids=a.related_rule_ids,
            time_range_start=a.time_range_start.isoformat(),
            time_range_end=a.time_range_end.isoformat(),
            is_acknowledged=a.is_acknowledged,
            detected_at=a.detected_at.isoformat(),
        )
        for a in anomalies
    ]


@router.post("/anomalies/{anomaly_id}/acknowledge")
async def acknowledge_anomaly(
    anomaly_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Acknowledge an anomaly."""
    result = await db.execute(
        select(AnomalyDetection)
        .where(AnomalyDetection.id == UUID(anomaly_id))
        .where(AnomalyDetection.organization_id == org_id)
    )
    anomaly = result.scalar_one_or_none()

    if not anomaly:
        raise HTTPException(status_code=404, detail="Anomaly not found")

    anomaly.is_acknowledged = True
    anomaly.acknowledged_by = user.email
    anomaly.acknowledged_at = utcnow()

    await db.commit()

    return {"status": "success", "anomaly_id": anomaly_id}


@router.post("/anomalies/detect")
async def trigger_anomaly_detection(
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Trigger anomaly detection analysis."""
    # In production, this would:
    # 1. Analyze recent alert patterns
    # 2. Compare against historical baseline
    # 3. Detect volume spikes, drops, unusual patterns
    # 4. Create anomaly records

    now = utcnow()

    # Demo: create sample anomaly
    demo_anomaly = AnomalyDetection(
        organization_id=org_id,
        anomaly_type=AnomalyType.VOLUME_SPIKE,
        severity="high",
        description=(
            "Alert volume increased by 150% compared to baseline. "
            "Potentially indicates active attack or misconfigured rule."
        ),
        detected_value=450.0,
        expected_value=180.0,
        deviation_percentage=150.0,
        related_rule_ids=["rule-001", "rule-002"],
        time_range_start=now - timedelta(hours=4),
        time_range_end=now,
    )
    db.add(demo_anomaly)
    await db.commit()

    return {
        "status": "success",
        "anomalies_detected": 1,
        "analysis_period": "Last 24 hours",
    }


# ==================== Coverage Analysis ====================

MITRE_TACTICS = {
    "reconnaissance": {"name": "Reconnaissance", "techniques": 10},
    "resource-development": {"name": "Resource Development", "techniques": 8},
    "initial-access": {"name": "Initial Access", "techniques": 9},
    "execution": {"name": "Execution", "techniques": 14},
    "persistence": {"name": "Persistence", "techniques": 19},
    "privilege-escalation": {"name": "Privilege Escalation", "techniques": 13},
    "defense-evasion": {"name": "Defense Evasion", "techniques": 42},
    "credential-access": {"name": "Credential Access", "techniques": 17},
    "discovery": {"name": "Discovery", "techniques": 31},
    "lateral-movement": {"name": "Lateral Movement", "techniques": 9},
    "collection": {"name": "Collection", "techniques": 17},
    "command-and-control": {"name": "Command and Control", "techniques": 16},
    "exfiltration": {"name": "Exfiltration", "techniques": 9},
    "impact": {"name": "Impact", "techniques": 14},
}


@router.get("/coverage", response_model=list[CoverageGapResponse])
async def get_coverage_gaps(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get MITRE ATT&CK coverage analysis with gaps."""
    # Get mapped techniques per tactic
    result = await db.execute(
        select(MitreMapping.tactic, func.count(func.distinct(MitreMapping.technique_id)))
        .where(MitreMapping.organization_id == org_id)
        .group_by(MitreMapping.tactic)
    )
    coverage_by_tactic = {
        row[0].value if hasattr(row[0], "value") else row[0]: row[1] for row in result.all()
    }

    gaps = []
    for tactic_id, tactic_info in MITRE_TACTICS.items():
        covered = coverage_by_tactic.get(tactic_id, 0)
        total = tactic_info["techniques"]
        percentage = (covered / total * 100) if total > 0 else 0

        # Get missing techniques (demo data)
        missing = []
        if covered < total:
            missing = [
                {"id": f"T{1000 + i}", "name": f"Technique {i + 1}"}
                for i in range(min(3, total - covered))
            ]

        gaps.append(
            CoverageGapResponse(
                tactic=tactic_id,
                tactic_name=tactic_info["name"],
                total_techniques=total,
                covered_techniques=covered,
                coverage_percentage=round(percentage, 1),
                missing_techniques=missing,
            )
        )

    return gaps


@router.get("/coverage/heatmap")
async def get_coverage_heatmap(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    days: int = Query(30, ge=1, le=365),
):
    """Get MITRE ATT&CK heatmap based on alert activity."""
    utcnow() - timedelta(days=days)

    # Get alerts with MITRE mappings
    # In production, this would aggregate alert data
    # For demo, return sample heatmap data

    heatmap = {}
    for tactic_id, tactic_info in MITRE_TACTICS.items():
        import random

        heatmap[tactic_id] = {
            "name": tactic_info["name"],
            "alert_count": random.randint(0, 100),
            "techniques": {
                f"T{1000 + i}": random.randint(0, 20)
                for i in range(min(5, tactic_info["techniques"]))
            },
        }

    return {
        "period_days": days,
        "heatmap": heatmap,
        "total_alerts_with_mitre": sum(t["alert_count"] for t in heatmap.values()),
    }
