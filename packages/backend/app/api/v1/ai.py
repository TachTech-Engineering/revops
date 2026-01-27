"""
AI-powered summarization API endpoints.
"""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.db.models import LLMProvider, Incident, IncidentAlert, AISummaryCache
from app.services.llm_service import llm_service
from app.services.panther_service import PantherService
from app.api.v1.deps import get_panther_service, OrgUserDep, OrgIdDep, OrgAnalystDep, OrgAdminDep

router = APIRouter()


# Request/Response models
class SummarizeRequest(BaseModel):
    provider: Optional[str] = None  # openai, anthropic
    force_refresh: bool = False


class SummaryResponse(BaseModel):
    summary: str
    model: str
    provider: str
    cached: bool
    generated_at: str
    input_tokens: int
    output_tokens: int


class LLMSettingsResponse(BaseModel):
    default_provider: str
    openai: dict
    anthropic: dict


class TestConnectionResponse(BaseModel):
    status: str
    provider: str
    model: Optional[str] = None
    message: str


@router.post("/summarize/alert/{alert_id}", response_model=SummaryResponse)
async def summarize_alert(
    alert_id: str,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    request: SummarizeRequest = SummarizeRequest(),
    db: AsyncSession = Depends(get_db),
    panther: PantherService = Depends(get_panther_service),
):
    """
    Generate an AI-powered summary for an alert.

    The summary is cached for 24 hours. Use force_refresh=true to regenerate.
    """
    # Get alert data from Panther
    try:
        alert_data = await panther.get_alert(alert_id)
        if not alert_data:
            raise HTTPException(status_code=404, detail="Alert not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch alert: {str(e)}")

    # Determine provider
    provider = None
    if request.provider:
        try:
            provider = LLMProvider(request.provider.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid provider: {request.provider}. Use 'openai' or 'anthropic'."
            )

    # Generate summary
    try:
        result = await llm_service.summarize_alert(
            db,
            alert_id=alert_id,
            alert_data=alert_data,
            provider=provider,
            force_refresh=request.force_refresh,
            organization_id=analyst.organization_id,
        )
        return SummaryResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate summary: {str(e)}")


@router.post("/summarize/incident/{incident_id}", response_model=SummaryResponse)
async def summarize_incident(
    incident_id: str,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    request: SummarizeRequest = SummarizeRequest(),
    db: AsyncSession = Depends(get_db),
    panther: PantherService = Depends(get_panther_service),
):
    """
    Generate an AI-powered summary for an incident.

    The summary includes analysis of all related alerts.
    Cached for 24 hours. Use force_refresh=true to regenerate.
    """
    # Get incident from local DB filtered by organization
    result = await db.execute(
        select(Incident).where(
            and_(
                Incident.id == incident_id,
                Incident.organization_id == org_id
            )
        )
    )
    incident = result.scalar_one_or_none()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Get associated alerts filtered by organization
    alert_result = await db.execute(
        select(IncidentAlert).where(
            and_(
                IncidentAlert.incident_id == incident_id,
                IncidentAlert.organization_id == org_id
            )
        )
    )
    incident_alerts = list(alert_result.scalars().all())

    # Fetch alert details from Panther
    alerts_data = []
    for ia in incident_alerts[:10]:  # Limit to 10 alerts
        try:
            alert_data = await panther.get_alert(ia.alert_id)
            if alert_data:
                alerts_data.append(alert_data)
        except Exception:
            continue

    # Prepare incident data
    incident_data = {
        "id": str(incident.id),
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "created_at": incident.created_at.isoformat(),
        "alert_count": len(incident_alerts),
        "alerts": alerts_data,
    }

    # Determine provider
    provider = None
    if request.provider:
        try:
            provider = LLMProvider(request.provider.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid provider: {request.provider}. Use 'openai' or 'anthropic'."
            )

    # Generate summary
    try:
        result = await llm_service.summarize_incident(
            db,
            incident_id=str(incident.id),
            incident_data=incident_data,
            provider=provider,
            force_refresh=request.force_refresh,
            organization_id=analyst.organization_id,
        )
        return SummaryResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate summary: {str(e)}")


@router.get("/settings", response_model=LLMSettingsResponse)
async def get_ai_settings(
    user: OrgUserDep,
):
    """Get current LLM configuration."""
    return await llm_service.get_settings()


@router.post("/test/{provider}", response_model=TestConnectionResponse)
async def test_connection(
    provider: str,
    admin: OrgAdminDep,
):
    """Test connection to an LLM provider."""
    try:
        llm_provider = LLMProvider(provider.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid provider: {provider}. Use 'openai' or 'anthropic'."
        )

    result = await llm_service.test_connection(llm_provider)
    return TestConnectionResponse(**result)


@router.get("/summaries")
async def list_cached_summaries(
    user: OrgUserDep,
    org_id: OrgIdDep,
    resource_type: Optional[str] = Query(None, description="Filter by type: alert or incident"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """List cached AI summaries."""
    from datetime import datetime

    query = select(AISummaryCache).where(
        and_(
            AISummaryCache.organization_id == org_id,
            AISummaryCache.expires_at > datetime.utcnow()
        )
    )

    if resource_type:
        query = query.where(AISummaryCache.resource_type == resource_type)

    query = query.order_by(AISummaryCache.created_at.desc()).limit(limit)

    result = await db.execute(query)
    summaries = result.scalars().all()

    return [
        {
            "id": str(s.id),
            "resource_type": s.resource_type,
            "resource_id": s.resource_id,
            "model": s.model_used,
            "provider": s.provider.value,
            "input_tokens": s.input_tokens,
            "output_tokens": s.output_tokens,
            "created_at": s.created_at.isoformat(),
            "expires_at": s.expires_at.isoformat(),
        }
        for s in summaries
    ]
