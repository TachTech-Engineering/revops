"""
Auto-Triage Suggestions API - Feature 3
AI recommends priority/severity with confidence scores.
"""
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgUserDep, OrgIdDep, OrgAnalystDep, OrgAdminDep
from app.db import get_db, TriageSuggestion, AssetCriticality
from fastapi import Depends

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
    was_accepted: Optional[bool]
    created_at: str

    class Config:
        from_attributes = True


class TriageFeedbackRequest(BaseModel):
    suggestion_id: str
    was_accepted: bool
    feedback_comment: Optional[str] = None


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

    # Generate new suggestion (placeholder - integrate with LLM service)
    # In production, this would:
    # 1. Fetch alert data
    # 2. Check asset criticality rules
    # 3. Query historical triage patterns
    # 4. Call LLM for recommendation

    # Demo suggestion
    suggestion = TriageSuggestion(
        organization_id=org_id,
        alert_id=alert_id,
        suggested_severity="high",
        suggested_priority="high",
        confidence_score=0.85,
        reasoning="Based on historical patterns and asset criticality, this alert type typically requires high priority handling. The affected system appears to be in a critical infrastructure segment.",
        contributing_factors=[
            {"factor": "asset_criticality", "value": "high", "weight": 0.4},
            {"factor": "historical_severity", "value": "high", "weight": 0.3},
            {"factor": "rule_baseline", "value": "medium", "weight": 0.2},
            {"factor": "time_sensitivity", "value": "business_hours", "weight": 0.1},
        ],
    )
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
    suggestion.feedback_at = datetime.utcnow()

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
    description: Optional[str]
    match_type: str
    match_pattern: str
    criticality_level: int
    business_unit: Optional[str]
    data_classification: Optional[str]
    is_active: bool
    created_by: str
    created_at: str

    class Config:
        from_attributes = True


class AssetCriticalityCreate(BaseModel):
    name: str
    description: Optional[str] = None
    match_type: str  # hostname, ip, user, service
    match_pattern: str
    criticality_level: int  # 1-10
    business_unit: Optional[str] = None
    data_classification: Optional[str] = None
    is_active: bool = True


class AssetCriticalityUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    match_pattern: Optional[str] = None
    criticality_level: Optional[int] = None
    business_unit: Optional[str] = None
    data_classification: Optional[str] = None
    is_active: Optional[bool] = None


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
    match_type: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
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
            raise HTTPException(status_code=400, detail="Criticality level must be between 1 and 10")

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
