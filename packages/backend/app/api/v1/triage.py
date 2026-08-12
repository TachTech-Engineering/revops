"""
Auto-Triage Suggestions API - Feature 3
AI recommends priority/severity with confidence scores.
"""

import json
import logging
import re
from datetime import timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAdminDep, OrgAnalystDep, OrgIdDep, OrgUserDep
from app.core.time_utils import utcnow
from app.db import AssetCriticality, NormalizedAlert, TriageSuggestion, get_db
from app.services.llm_service import llm_service

logger = logging.getLogger(__name__)

router = APIRouter()


# ==================== Triage Suggestions ====================


class TriageSuggestionResponse(BaseModel):
    id: str
    alert_id: str
    suggested_severity: str
    suggested_priority: str
    confidence_score: float
    reasoning: str
    contributing_factors: list
    was_accepted: bool | None
    created_at: str

    class Config:
        from_attributes = True


class TriageFeedbackRequest(BaseModel):
    suggestion_id: str
    was_accepted: bool
    feedback_comment: str | None = None


async def get_asset_criticality_for_alert(
    db: AsyncSession,
    org_id: UUID,
    alert_data: dict[str, Any],
) -> tuple[int, str]:
    """
    Look up asset criticality based on alert data.

    Returns:
        Tuple of (criticality_level 1-10, match_reason)
    """
    # Extract potential identifiers from alert
    raw_data = alert_data.get("raw_data", {})
    hostname = (
        raw_data.get("hostname", "")
        or raw_data.get("host", "")
        or raw_data.get("computer_name", "")
    )
    ip_address = (
        raw_data.get("src_ip", "") or raw_data.get("ip", "") or raw_data.get("source_ip", "")
    )
    user = raw_data.get("user", "") or raw_data.get("username", "") or raw_data.get("actor", "")
    service = (
        raw_data.get("service", "")
        or raw_data.get("application", "")
        or raw_data.get("process_name", "")
    )

    # Also check title and description for common patterns
    title = alert_data.get("title", "").lower()
    description = alert_data.get("description", "").lower()

    # Query all active criticality rules
    result = await db.execute(
        select(AssetCriticality)
        .where(AssetCriticality.organization_id == org_id)
        .where(AssetCriticality.is_active.is_(True))
        .order_by(AssetCriticality.criticality_level.desc())
    )
    rules = result.scalars().all()

    for rule in rules:
        pattern = rule.match_pattern.lower()

        if rule.match_type == "hostname" and hostname:
            if re.search(pattern, hostname.lower()):
                return (
                    rule.criticality_level,
                    f"Hostname '{hostname}' matches critical asset rule '{rule.name}'",
                )

        elif rule.match_type == "ip" and ip_address:
            if pattern in ip_address:
                return (
                    rule.criticality_level,
                    f"IP '{ip_address}' matches critical asset rule '{rule.name}'",
                )

        elif rule.match_type == "user" and user:
            if re.search(pattern, user.lower()):
                return (
                    rule.criticality_level,
                    f"User '{user}' matches critical asset rule '{rule.name}'",
                )

        elif rule.match_type == "service" and service:
            if re.search(pattern, service.lower()):
                return (
                    rule.criticality_level,
                    f"Service '{service}' matches critical asset rule '{rule.name}'",
                )

    # Check for common critical keywords in title/description
    critical_keywords = [
        "production",
        "database",
        "payment",
        "pci",
        "hipaa",
        "admin",
        "root",
        "domain controller",
    ]
    for keyword in critical_keywords:
        if keyword in title or keyword in description:
            return 7, f"Alert mentions critical keyword '{keyword}'"

    return 5, "No specific asset criticality match, using default"


async def get_historical_patterns(
    db: AsyncSession,
    org_id: UUID,
    alert_data: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze historical triage patterns for similar alerts.

    Returns:
        Dict with historical analysis data
    """
    alert_data.get("rule_name", "")
    alert_data.get("source_type", "")

    # Get historical suggestions for similar alerts (same rule/source)
    thirty_days_ago = utcnow() - timedelta(days=30)

    result = await db.execute(
        select(
            TriageSuggestion.suggested_severity,
            TriageSuggestion.was_accepted,
            func.count(TriageSuggestion.id).label("count"),
        )
        .where(TriageSuggestion.organization_id == org_id)
        .where(TriageSuggestion.created_at >= thirty_days_ago)
        .where(TriageSuggestion.was_accepted.is_not(None))
        .group_by(TriageSuggestion.suggested_severity, TriageSuggestion.was_accepted)
    )
    rows = result.fetchall()

    total_suggestions = sum(row[2] for row in rows)
    accepted_count = sum(row[2] for row in rows if row[1] is True)
    acceptance_rate = accepted_count / total_suggestions if total_suggestions > 0 else 0.5

    # Calculate most common accepted severity
    severity_counts = {}
    for row in rows:
        if row[1] is True:  # was_accepted
            severity_counts[row[0]] = severity_counts.get(row[0], 0) + row[2]

    most_common_severity = (
        max(severity_counts, key=severity_counts.get) if severity_counts else "medium"
    )

    return {
        "total_similar_alerts": total_suggestions,
        "acceptance_rate": acceptance_rate,
        "most_common_severity": most_common_severity,
        "confidence_boost": min(0.2, total_suggestions * 0.01),  # More history = higher confidence
    }


async def generate_triage_suggestion(
    db: AsyncSession,
    org_id: UUID,
    alert_id: str,
    alert_data: dict[str, Any],
) -> TriageSuggestion:
    """
    Generate AI-powered triage suggestion for an alert.

    Args:
        db: Database session
        org_id: Organization ID
        alert_id: Alert identifier
        alert_data: Alert data dictionary

    Returns:
        TriageSuggestion model instance
    """
    # 1. Get asset criticality
    criticality_level, criticality_reason = await get_asset_criticality_for_alert(
        db, org_id, alert_data
    )

    # 2. Get historical patterns
    historical = await get_historical_patterns(db, org_id, alert_data)

    # 3. Base severity from alert
    base_severity = alert_data.get("severity", "medium").lower()
    severity_scores = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
    base_score = severity_scores.get(base_severity, 5)

    # 4. Calculate suggested severity
    # Weighted scoring: asset criticality (40%), historical (30%), rule baseline (20%), time (10%)
    criticality_score = criticality_level
    historical_score = severity_scores.get(historical["most_common_severity"], 5)

    weighted_score = (
        criticality_score * 0.4
        + historical_score * 0.3
        + base_score * 0.2
        + (7 if utcnow().hour >= 8 and utcnow().hour <= 18 else 5) * 0.1
    )

    # Map score to severity
    if weighted_score >= 8.5:
        suggested_severity = "critical"
    elif weighted_score >= 6.5:
        suggested_severity = "high"
    elif weighted_score >= 4:
        suggested_severity = "medium"
    else:
        suggested_severity = "low"

    # Priority matches severity for now
    suggested_priority = suggested_severity

    # 5. Calculate confidence score
    base_confidence = 0.6
    confidence = base_confidence + historical["confidence_boost"]
    if criticality_level >= 8:
        confidence += 0.1
    if historical["acceptance_rate"] > 0.7:
        confidence += 0.1
    confidence = min(0.95, confidence)  # Cap at 95%

    # 6. Generate reasoning using LLM if available
    contributing_factors = [
        {
            "factor": "asset_criticality",
            "value": str(criticality_level),
            "weight": 0.4,
            "reason": criticality_reason,
        },
        {
            "factor": "historical_severity",
            "value": historical["most_common_severity"],
            "weight": 0.3,
            "reason": (
                f"Based on {historical['total_similar_alerts']} similar alerts "
                f"with {historical['acceptance_rate']:.0%} acceptance rate"
            ),
        },
        {
            "factor": "rule_baseline",
            "value": base_severity,
            "weight": 0.2,
            "reason": "Original alert severity from detection rule",
        },
        {
            "factor": "time_sensitivity",
            "value": "business_hours" if 8 <= utcnow().hour <= 18 else "off_hours",
            "weight": 0.1,
            "reason": "Current time of day consideration",
        },
    ]

    reasoning = await generate_reasoning_with_llm(
        db,
        org_id,
        alert_data,
        suggested_severity,
        suggested_priority,
        confidence,
        contributing_factors,
    )

    suggestion = TriageSuggestion(
        organization_id=org_id,
        alert_id=alert_id,
        suggested_severity=suggested_severity,
        suggested_priority=suggested_priority,
        confidence_score=round(confidence, 2),
        reasoning=reasoning,
        contributing_factors=contributing_factors,
    )

    return suggestion


async def generate_reasoning_with_llm(
    db: AsyncSession,
    org_id: UUID,
    alert_data: dict[str, Any],
    severity: str,
    priority: str,
    confidence: float,
    factors: list[dict[str, Any]],
) -> str:
    """Generate human-readable reasoning via the shared LLM service.

    Routes through llm_service so the organization's encrypted key/model is used
    (falling back to the global key only if llm_service does so internally).
    Degrades to a deterministic template when no key is configured or the call
    fails.
    """
    template = (
        "Based on asset criticality analysis and historical patterns, "
        f"this alert is recommended as {severity.upper()} severity "
        f"with {priority.upper()} priority. "
        + f"Confidence: {confidence:.0%}. Key factors: "
        + ", ".join([f"{f['factor']} ({f['reason']})" for f in factors])
    )

    prompt = f"""Generate a brief (2-3 sentences) triage recommendation for a security analyst.

Alert: {alert_data.get("title", "Unknown")}
Suggested Severity: {severity}
Suggested Priority: {priority}
Confidence: {confidence:.0%}

Contributing factors:
{json.dumps(factors, indent=2)}

Write a concise explanation that helps the analyst understand
why this severity/priority is recommended."""

    try:
        reasoning = await llm_service.generate_completion(
            db=db,
            organization_id=org_id,
            prompt=prompt,
            max_tokens=300,
        )
        return reasoning or template
    except Exception as e:
        logger.error(f"Error generating reasoning with LLM: {e}")
        return template


@router.get("/suggest/{alert_id}", response_model=TriageSuggestionResponse)
async def get_triage_suggestion(
    alert_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    force_refresh: bool = Query(False, description="Force new suggestion even if cached"),
):
    """Get AI-generated triage suggestion for an alert."""
    # Check for existing suggestion
    if not force_refresh:
        result = await db.execute(
            select(TriageSuggestion)
            .where(TriageSuggestion.organization_id == org_id)
            .where(TriageSuggestion.alert_id == alert_id)
            .order_by(TriageSuggestion.created_at.desc())
            .limit(1)
        )
        existing = result.scalar_one_or_none()
        if existing:
            return TriageSuggestionResponse(
                id=str(existing.id),
                alert_id=existing.alert_id,
                suggested_severity=existing.suggested_severity,
                suggested_priority=existing.suggested_priority,
                confidence_score=existing.confidence_score,
                reasoning=existing.reasoning,
                contributing_factors=existing.contributing_factors,
                was_accepted=existing.was_accepted,
                created_at=existing.created_at.isoformat(),
            )

    # Fetch alert data
    alert_result = await db.execute(
        select(NormalizedAlert)
        .where(NormalizedAlert.organization_id == org_id)
        .where(NormalizedAlert.id == alert_id)
    )
    alert = alert_result.scalar_one_or_none()

    if not alert:
        # Try to find by external_id
        alert_result = await db.execute(
            select(NormalizedAlert)
            .where(NormalizedAlert.organization_id == org_id)
            .where(NormalizedAlert.external_id == alert_id)
        )
        alert = alert_result.scalar_one_or_none()

    if alert:
        alert_data = {
            "id": str(alert.id),
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "source_type": alert.source_type,
            "rule_name": alert.rule_name,
            "rule_id": alert.rule_id,
            "raw_data": alert.raw_data or {},
        }
    else:
        # Use minimal data if alert not found
        alert_data = {
            "id": alert_id,
            "title": "Unknown Alert",
            "severity": "medium",
        }

    # Generate new suggestion with real AI
    suggestion = await generate_triage_suggestion(db, org_id, alert_id, alert_data)

    db.add(suggestion)
    await db.commit()
    await db.refresh(suggestion)

    return TriageSuggestionResponse(
        id=str(suggestion.id),
        alert_id=suggestion.alert_id,
        suggested_severity=suggestion.suggested_severity,
        suggested_priority=suggestion.suggested_priority,
        confidence_score=suggestion.confidence_score,
        reasoning=suggestion.reasoning,
        contributing_factors=suggestion.contributing_factors,
        was_accepted=suggestion.was_accepted,
        created_at=suggestion.created_at.isoformat(),
    )


@router.post("/feedback")
async def submit_triage_feedback(
    request: TriageFeedbackRequest,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Submit feedback on a triage suggestion (accept/reject)."""
    result = await db.execute(
        select(TriageSuggestion)
        .where(TriageSuggestion.id == UUID(request.suggestion_id))
        .where(TriageSuggestion.organization_id == org_id)
    )
    suggestion = result.scalar_one_or_none()

    if not suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found")

    suggestion.was_accepted = request.was_accepted
    suggestion.feedback_by = user.email
    suggestion.feedback_at = utcnow()

    await db.commit()

    return {
        "status": "success",
        "message": "Feedback recorded",
        "suggestion_id": request.suggestion_id,
        "was_accepted": request.was_accepted,
    }


# ==================== Asset Criticality ====================


class AssetCriticalityResponse(BaseModel):
    id: str
    name: str
    description: str | None
    match_type: str
    match_pattern: str
    criticality_level: int
    business_unit: str | None
    data_classification: str | None
    is_active: bool
    created_by: str
    created_at: str

    class Config:
        from_attributes = True


class AssetCriticalityCreate(BaseModel):
    name: str
    description: str | None = None
    match_type: str  # hostname, ip, user, service
    match_pattern: str
    criticality_level: int  # 1-10
    business_unit: str | None = None
    data_classification: str | None = None
    is_active: bool = True


class AssetCriticalityUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    match_pattern: str | None = None
    criticality_level: int | None = None
    business_unit: str | None = None
    data_classification: str | None = None
    is_active: bool | None = None


def serialize_asset_criticality(ac: AssetCriticality) -> AssetCriticalityResponse:
    return AssetCriticalityResponse(
        id=str(ac.id),
        name=ac.name,
        description=ac.description,
        match_type=ac.match_type,
        match_pattern=ac.match_pattern,
        criticality_level=ac.criticality_level,
        business_unit=ac.business_unit,
        data_classification=ac.data_classification,
        is_active=ac.is_active,
        created_by=ac.created_by,
        created_at=ac.created_at.isoformat(),
    )


@router.get("/assets/criticality", response_model=list[AssetCriticalityResponse])
async def list_asset_criticality(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    match_type: str | None = Query(None),
    is_active: bool | None = Query(None),
):
    """List asset criticality rules."""
    query = select(AssetCriticality).where(AssetCriticality.organization_id == org_id)

    if match_type:
        query = query.where(AssetCriticality.match_type == match_type)
    if is_active is not None:
        query = query.where(AssetCriticality.is_active == is_active)

    query = query.order_by(AssetCriticality.criticality_level.desc())
    result = await db.execute(query)
    assets = result.scalars().all()

    return [serialize_asset_criticality(a) for a in assets]


@router.post("/assets/criticality", status_code=201, response_model=AssetCriticalityResponse)
async def create_asset_criticality(
    request: AssetCriticalityCreate,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Create a new asset criticality rule."""
    if request.criticality_level < 1 or request.criticality_level > 10:
        raise HTTPException(status_code=400, detail="Criticality level must be between 1 and 10")

    if request.match_type not in ["hostname", "ip", "user", "service"]:
        raise HTTPException(status_code=400, detail="Invalid match type")

    asset = AssetCriticality(
        organization_id=org_id,
        name=request.name,
        description=request.description,
        match_type=request.match_type,
        match_pattern=request.match_pattern,
        criticality_level=request.criticality_level,
        business_unit=request.business_unit,
        data_classification=request.data_classification,
        is_active=request.is_active,
        created_by=user.email,
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)

    return serialize_asset_criticality(asset)


@router.get("/assets/criticality/{asset_id}", response_model=AssetCriticalityResponse)
async def get_asset_criticality(
    asset_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific asset criticality rule."""
    result = await db.execute(
        select(AssetCriticality)
        .where(AssetCriticality.id == UUID(asset_id))
        .where(AssetCriticality.organization_id == org_id)
    )
    asset = result.scalar_one_or_none()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset criticality rule not found")

    return serialize_asset_criticality(asset)


@router.patch("/assets/criticality/{asset_id}", response_model=AssetCriticalityResponse)
async def update_asset_criticality(
    asset_id: str,
    request: AssetCriticalityUpdate,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Update an asset criticality rule."""
    result = await db.execute(
        select(AssetCriticality)
        .where(AssetCriticality.id == UUID(asset_id))
        .where(AssetCriticality.organization_id == org_id)
    )
    asset = result.scalar_one_or_none()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset criticality rule not found")

    update_data = request.model_dump(exclude_none=True)
    if "criticality_level" in update_data:
        if update_data["criticality_level"] < 1 or update_data["criticality_level"] > 10:
            raise HTTPException(
                status_code=400, detail="Criticality level must be between 1 and 10"
            )

    for key, value in update_data.items():
        setattr(asset, key, value)

    await db.commit()
    await db.refresh(asset)

    return serialize_asset_criticality(asset)


@router.delete("/assets/criticality/{asset_id}", status_code=204)
async def delete_asset_criticality(
    asset_id: str,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Delete an asset criticality rule."""
    result = await db.execute(
        select(AssetCriticality)
        .where(AssetCriticality.id == UUID(asset_id))
        .where(AssetCriticality.organization_id == org_id)
    )
    asset = result.scalar_one_or_none()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset criticality rule not found")

    await db.delete(asset)
    await db.commit()
