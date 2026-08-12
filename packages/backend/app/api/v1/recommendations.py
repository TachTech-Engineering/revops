"""
Rule Recommendations API endpoints.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAnalystDep, OrgIdDep, OrgUserDep, get_panther_service
from app.db.models import RecommendationStatus, RuleRecommendation
from app.db.session import get_db
from app.services.panther_service import PantherService
from app.services.rule_recommendation_service import rule_recommendation_service

router = APIRouter()


# Response models
class RecommendationResponse(BaseModel):
    id: str
    log_source: str
    rule_name: str
    rule_id: str
    rule_code: str
    description: str | None = None
    mitre_techniques: list[str]
    confidence_score: float
    status: str
    created_at: str
    updated_at: str


class RecommendationListResponse(BaseModel):
    items: list[RecommendationResponse]
    total: int
    page: int
    page_size: int


class CoverageGapResponse(BaseModel):
    log_source: str
    total_available_rules: int
    implemented_rules: int
    missing_rules: int
    coverage_percentage: float
    missing_rule_details: list[dict]


class DismissRequest(BaseModel):
    reason: str | None = None


class StatsResponse(BaseModel):
    total: int
    by_status: dict[str, int]
    pending_by_source: dict[str, int]
    catalog_version: str
    catalog_rules: int


def recommendation_to_response(rec) -> RecommendationResponse:
    """Convert recommendation model to response."""
    return RecommendationResponse(
        id=str(rec.id),
        log_source=rec.log_source,
        rule_name=rec.rule_name,
        rule_id=rec.rule_id,
        rule_code=rec.rule_code,
        description=rec.description,
        mitre_techniques=rec.mitre_techniques or [],
        confidence_score=rec.confidence_score,
        status=rec.status.value,
        created_at=rec.created_at.isoformat(),
        updated_at=rec.updated_at.isoformat(),
    )


@router.get("", response_model=RecommendationListResponse)
async def list_recommendations(
    user: OrgUserDep,
    org_id: OrgIdDep,
    log_source: str | None = Query(None, description="Filter by log source"),
    status: str | None = Query(None, description="Filter by status: pending, accepted, dismissed"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List rule recommendations with optional filters."""
    # Parse status
    rec_status = None
    if status:
        try:
            rec_status = RecommendationStatus(status)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status: {status}. Use 'pending', 'accepted', or 'dismissed'.",
            )

    # Parse log sources
    log_sources = [log_source] if log_source else None

    recommendations, total = await rule_recommendation_service.get_recommendations(
        db,
        organization_id=org_id,
        log_sources=log_sources,
        status=rec_status,
        page=page,
        page_size=page_size,
    )

    return RecommendationListResponse(
        items=[recommendation_to_response(r) for r in recommendations],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/stats", response_model=StatsResponse)
async def get_recommendation_stats(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get recommendation statistics."""
    stats = await rule_recommendation_service.get_stats(db, organization_id=org_id)
    return StatsResponse(**stats)


@router.get("/coverage", response_model=list[CoverageGapResponse])
async def get_coverage_gaps(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    panther: PantherService = Depends(get_panther_service),
):
    """
    Analyze detection coverage gaps for available log sources.

    Returns coverage percentage and missing rules for each log source.
    """
    gaps = await rule_recommendation_service.get_coverage_gaps(db, panther, organization_id=org_id)
    return [CoverageGapResponse(**g) for g in gaps]


@router.post("/generate")
async def generate_recommendations(
    analyst: OrgAnalystDep,
    log_sources: list[str] = Query(None, description="Specific log sources to analyze"),
    db: AsyncSession = Depends(get_db),
    panther: PantherService = Depends(get_panther_service),
):
    """
    Generate recommendations for log sources based on the rule catalog.

    If no log sources specified, analyzes all available sources.
    """
    # If no sources specified, get all available
    if not log_sources:
        analysis = await rule_recommendation_service.analyze_log_sources(panther)
        log_sources = [a["log_source"] for a in analysis]

    result = await rule_recommendation_service.generate_recommendations(
        db,
        log_sources,
        organization_id=analyst.organization_id,
    )
    return result


@router.get("/catalog")
async def get_catalog_info(user: OrgUserDep):
    """Get information about the rule catalog."""
    catalog = rule_recommendation_service.catalog
    return {
        "version": catalog.get("version"),
        "last_updated": catalog.get("last_updated"),
        "total_rules": len(catalog.get("rules", [])),
        "log_sources": list(
            set(
                source
                for rule in catalog.get("rules", [])
                for source in rule.get("log_sources", [])
            )
        ),
        "mitre_tactics": list(
            set(
                rule.get("mitre_tactic")
                for rule in catalog.get("rules", [])
                if rule.get("mitre_tactic")
            )
        ),
    }


@router.get("/{recommendation_id}", response_model=RecommendationResponse)
async def get_recommendation(
    recommendation_id: uuid.UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get a single recommendation by ID."""
    result = await db.execute(
        select(RuleRecommendation).where(
            and_(
                RuleRecommendation.id == recommendation_id,
                RuleRecommendation.organization_id == org_id,
            )
        )
    )
    rec = result.scalar_one_or_none()

    if not rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")

    return recommendation_to_response(rec)


@router.post("/{recommendation_id}/accept")
async def accept_recommendation(
    recommendation_id: uuid.UUID,
    analyst: OrgAnalystDep,
    db: AsyncSession = Depends(get_db),
    panther: PantherService = Depends(get_panther_service),
):
    """
    Accept a recommendation and create the rule in Panther.

    This will create a new detection rule based on the recommendation.
    """
    try:
        result = await rule_recommendation_service.accept_recommendation(
            db,
            recommendation_id=recommendation_id,
            organization_id=analyst.organization_id,
            panther_service=panther,
            user_email=analyst.email,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{recommendation_id}/dismiss")
async def dismiss_recommendation(
    recommendation_id: uuid.UUID,
    analyst: OrgAnalystDep,
    request: DismissRequest = DismissRequest(),
    db: AsyncSession = Depends(get_db),
):
    """
    Dismiss a recommendation with an optional reason.

    Dismissed recommendations won't appear in pending lists.
    """
    try:
        result = await rule_recommendation_service.dismiss_recommendation(
            db,
            recommendation_id=recommendation_id,
            organization_id=analyst.organization_id,
            user_email=analyst.email,
            reason=request.reason,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
