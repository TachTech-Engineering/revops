"""
AI-powered summarization and conversion API endpoints.
"""
import json
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.db.models import LLMProvider, Incident, IncidentAlert, AISummaryCache, NormalizedAlert, OrganizationAPIKeys
from app.services.llm_service import llm_service
from app.services.encryption_service import encrypt_credential, decrypt_credential
from app.services.ai_converter_service import (
    ai_converter_service,
    ConversionFormat,
    LLMProvider as ConverterLLMProvider,
    FORMAT_DESCRIPTIONS,
)
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


# API Key Management Models
class SaveAPIKeyRequest(BaseModel):
    provider: str  # "openai" or "anthropic"
    api_key: str
    model: Optional[str] = None


class APIKeyResponse(BaseModel):
    provider: str
    configured: bool
    model: Optional[str] = None
    last_used_at: Optional[str] = None
    is_active: bool = True


class OrganizationSettingsResponse(BaseModel):
    default_provider: str
    openai: dict
    anthropic: dict
    organization_keys: list[APIKeyResponse]


# AI Converter Models
class AIConvertRequest(BaseModel):
    source_code: str
    source_format: str  # spl, yaral, sigma, kql, etc.
    target_format: str = "panther"  # Default to Panther
    context: Optional[str] = None
    provider: Optional[str] = None  # claude, openai


class AIConvertResponse(BaseModel):
    converted_code: str
    source_format: str
    target_format: str
    provider: str
    model: str
    success: bool
    error: Optional[str] = None


class AIExplainRequest(BaseModel):
    source_code: str
    source_format: str
    provider: Optional[str] = None


class AIExplainResponse(BaseModel):
    explanation: str
    provider: str
    model: str
    success: bool
    error: Optional[str] = None


class AIEnhanceRequest(BaseModel):
    source_code: str
    source_format: str
    provider: Optional[str] = None


class AIEnhanceResponse(BaseModel):
    suggestions: str
    provider: str
    model: str
    success: bool
    error: Optional[str] = None


class AIProvidersResponse(BaseModel):
    providers: list[dict]
    formats: list[dict]


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


@router.get("/settings", response_model=OrganizationSettingsResponse)
async def get_ai_settings(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get current LLM configuration including organization-specific API keys."""
    # Get base settings
    base_settings = await llm_service.get_settings()

    # Get organization-specific API keys
    result = await db.execute(
        select(OrganizationAPIKeys).where(
            OrganizationAPIKeys.organization_id == org_id
        )
    )
    org_keys = result.scalars().all()

    org_key_responses = []
    for key in org_keys:
        org_key_responses.append(APIKeyResponse(
            provider=key.provider,
            configured=True,
            model=key.model,
            last_used_at=key.last_used_at.isoformat() if key.last_used_at else None,
            is_active=key.is_active,
        ))

    # Merge organization keys with base settings
    return OrganizationSettingsResponse(
        default_provider=base_settings["default_provider"],
        openai=base_settings["openai"],
        anthropic=base_settings["anthropic"],
        organization_keys=org_key_responses,
    )


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


@router.post("/keys", response_model=APIKeyResponse)
async def save_api_key(
    request: SaveAPIKeyRequest,
    admin: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Save or update an organization's API key for an LLM provider.
    Only organization admins can manage API keys.
    """
    provider = request.provider.lower()
    if provider not in ["openai", "anthropic"]:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid provider: {provider}. Use 'openai' or 'anthropic'."
        )

    # Validate API key format (basic check)
    api_key = request.api_key.strip()
    if provider == "openai" and not api_key.startswith("sk-"):
        raise HTTPException(
            status_code=400,
            detail="Invalid OpenAI API key format. Key should start with 'sk-'"
        )
    if provider == "anthropic" and not api_key.startswith("sk-ant-"):
        raise HTTPException(
            status_code=400,
            detail="Invalid Anthropic API key format. Key should start with 'sk-ant-'"
        )

    # Encrypt the API key
    encrypted_key = encrypt_credential(api_key)

    # Check if key already exists for this org/provider
    result = await db.execute(
        select(OrganizationAPIKeys).where(
            and_(
                OrganizationAPIKeys.organization_id == org_id,
                OrganizationAPIKeys.provider == provider,
            )
        )
    )
    existing_key = result.scalar_one_or_none()

    if existing_key:
        # Update existing key
        existing_key.api_key_encrypted = encrypted_key
        existing_key.model = request.model
        existing_key.is_active = True
        existing_key.last_error = None
        existing_key.updated_at = datetime.utcnow()
    else:
        # Create new key
        new_key = OrganizationAPIKeys(
            organization_id=org_id,
            provider=provider,
            api_key_encrypted=encrypted_key,
            model=request.model,
            is_active=True,
            created_by=admin.email,
        )
        db.add(new_key)

    await db.commit()

    return APIKeyResponse(
        provider=provider,
        configured=True,
        model=request.model,
        is_active=True,
    )


class TestAPIKeyRequest(BaseModel):
    provider: str
    api_key: str
    model: Optional[str] = None


@router.post("/keys/test", response_model=TestConnectionResponse)
async def test_api_key_direct(
    request: TestAPIKeyRequest,
    user: OrgUserDep,
):
    """
    Test an API key directly without saving it.
    Use this to verify a key works before committing it.
    """
    provider = request.provider.lower()
    if provider not in ["openai", "anthropic"]:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid provider: {provider}. Use 'openai' or 'anthropic'."
        )

    api_key = request.api_key.strip()

    # Basic format validation
    if provider == "openai" and not api_key.startswith("sk-"):
        raise HTTPException(
            status_code=400,
            detail="Invalid OpenAI API key format. Key should start with 'sk-'"
        )
    if provider == "anthropic" and not api_key.startswith("sk-ant-"):
        raise HTTPException(
            status_code=400,
            detail="Invalid Anthropic API key format. Key should start with 'sk-ant-'"
        )

    try:
        result = await llm_service.test_connection_with_key(
            provider=LLMProvider(provider),
            api_key=api_key,
            model=request.model,
        )
        return TestConnectionResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Test failed: {str(e)}")


@router.delete("/keys/{provider}")
async def delete_api_key(
    provider: str,
    admin: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Delete an organization's API key for an LLM provider.
    Only organization admins can manage API keys.
    """
    provider = provider.lower()
    if provider not in ["openai", "anthropic"]:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid provider: {provider}. Use 'openai' or 'anthropic'."
        )

    result = await db.execute(
        select(OrganizationAPIKeys).where(
            and_(
                OrganizationAPIKeys.organization_id == org_id,
                OrganizationAPIKeys.provider == provider,
            )
        )
    )
    existing_key = result.scalar_one_or_none()

    if not existing_key:
        raise HTTPException(
            status_code=404,
            detail=f"No API key found for provider: {provider}"
        )

    await db.delete(existing_key)
    await db.commit()

    return {"message": f"API key for {provider} deleted successfully"}


@router.post("/keys/{provider}/test", response_model=TestConnectionResponse)
async def test_organization_api_key(
    provider: str,
    admin: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Test an organization's API key for an LLM provider.
    """
    provider = provider.lower()
    if provider not in ["openai", "anthropic"]:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid provider: {provider}. Use 'openai' or 'anthropic'."
        )

    # Get the organization's API key
    result = await db.execute(
        select(OrganizationAPIKeys).where(
            and_(
                OrganizationAPIKeys.organization_id == org_id,
                OrganizationAPIKeys.provider == provider,
            )
        )
    )
    org_key = result.scalar_one_or_none()

    if not org_key:
        raise HTTPException(
            status_code=404,
            detail=f"No API key configured for provider: {provider}"
        )

    # Decrypt and test the key
    try:
        api_key = decrypt_credential(org_key.api_key_encrypted)
        test_result = await llm_service.test_connection_with_key(
            provider=LLMProvider(provider),
            api_key=api_key,
            model=org_key.model,
        )

        # Update last_used_at and any errors
        org_key.last_used_at = datetime.utcnow()
        if test_result["status"] == "success":
            org_key.last_error = None
        else:
            org_key.last_error = test_result["message"]
        await db.commit()

        return TestConnectionResponse(**test_result)
    except Exception as e:
        org_key.last_error = str(e)
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")


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


# ==================== AI Converter Endpoints ====================

async def get_org_api_key(
    db: AsyncSession,
    org_id,
    provider: str
) -> tuple[Optional[str], Optional[str]]:
    """
    Get organization's API key and model for a provider.
    Returns (api_key, model) tuple, both may be None.
    """
    result = await db.execute(
        select(OrganizationAPIKeys).where(
            and_(
                OrganizationAPIKeys.organization_id == org_id,
                OrganizationAPIKeys.provider == provider,
                OrganizationAPIKeys.is_active == True,
            )
        )
    )
    org_key = result.scalar_one_or_none()

    if org_key:
        try:
            api_key = decrypt_credential(org_key.api_key_encrypted)
            return api_key, org_key.model
        except Exception:
            pass

    return None, None


async def get_org_has_keys(db: AsyncSession, org_id) -> tuple[bool, bool]:
    """Check if organization has configured API keys for each provider."""
    result = await db.execute(
        select(OrganizationAPIKeys.provider).where(
            and_(
                OrganizationAPIKeys.organization_id == org_id,
                OrganizationAPIKeys.is_active == True,
            )
        )
    )
    providers = [row[0] for row in result.all()]
    return 'anthropic' in providers, 'openai' in providers


@router.get("/converter/providers", response_model=AIProvidersResponse)
async def get_converter_providers(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get available AI providers and supported formats for conversion."""
    org_has_anthropic, org_has_openai = await get_org_has_keys(db, org_id)
    providers = ai_converter_service.get_available_providers(
        org_has_anthropic=org_has_anthropic,
        org_has_openai=org_has_openai,
    )
    formats = [
        {"value": fmt.value, "label": desc}
        for fmt, desc in FORMAT_DESCRIPTIONS.items()
    ]
    return AIProvidersResponse(providers=providers, formats=formats)


@router.post("/converter/convert", response_model=AIConvertResponse)
async def ai_convert_rule(
    request: AIConvertRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Convert a detection rule using AI.

    Supports conversion between multiple SIEM formats:
    - SPL (Splunk)
    - YARA-L (Google SecOps/Chronicle)
    - Sigma
    - KQL (Microsoft Sentinel)
    - EQL (Elastic)
    - Panther Python
    """
    # Validate formats
    try:
        source_fmt = ConversionFormat(request.source_format.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid source format: {request.source_format}. Supported: {[f.value for f in ConversionFormat]}"
        )

    try:
        target_fmt = ConversionFormat(request.target_format.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target format: {request.target_format}. Supported: {[f.value for f in ConversionFormat]}"
        )

    # Determine provider
    provider = ConverterLLMProvider.CLAUDE  # Default
    if request.provider:
        try:
            provider = ConverterLLMProvider(request.provider.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid provider: {request.provider}. Use 'claude' or 'openai'."
            )

    # Get organization's API key for this provider
    provider_name = "anthropic" if provider == ConverterLLMProvider.CLAUDE else "openai"
    org_api_key, org_model = await get_org_api_key(db, org_id, provider_name)

    # Check if provider is available (either org key or env key)
    org_has_anthropic, org_has_openai = await get_org_has_keys(db, org_id)
    available = ai_converter_service.get_available_providers(
        org_has_anthropic=org_has_anthropic,
        org_has_openai=org_has_openai,
    )
    if not any(p["id"] == provider.value for p in available):
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{provider.value}' is not configured. Configure API key in AI Settings."
        )

    result = ai_converter_service.convert(
        source_code=request.source_code,
        source_format=source_fmt,
        target_format=target_fmt,
        context=request.context,
        provider=provider,
        api_key=org_api_key,
        model_override=org_model,
    )

    return AIConvertResponse(**result)


@router.post("/converter/explain", response_model=AIExplainResponse)
async def ai_explain_rule(
    request: AIExplainRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Get an AI-powered explanation of what a detection rule does.

    Returns:
    - What the rule detects (threat/behavior)
    - Key conditions and filters
    - Aggregation/correlation logic
    - MITRE ATT&CK mapping if identifiable
    - Potential false positive scenarios
    """
    # Validate format
    try:
        source_fmt = ConversionFormat(request.source_format.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid source format: {request.source_format}. Supported: {[f.value for f in ConversionFormat]}"
        )

    # Determine provider
    provider = ConverterLLMProvider.CLAUDE  # Default
    if request.provider:
        try:
            provider = ConverterLLMProvider(request.provider.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid provider: {request.provider}. Use 'claude' or 'openai'."
            )

    # Get organization's API key for this provider
    provider_name = "anthropic" if provider == ConverterLLMProvider.CLAUDE else "openai"
    org_api_key, org_model = await get_org_api_key(db, org_id, provider_name)

    # Check if provider is available
    org_has_anthropic, org_has_openai = await get_org_has_keys(db, org_id)
    available = ai_converter_service.get_available_providers(
        org_has_anthropic=org_has_anthropic,
        org_has_openai=org_has_openai,
    )
    if not any(p["id"] == provider.value for p in available):
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{provider.value}' is not configured. Configure API key in AI Settings."
        )

    result = ai_converter_service.explain_rule(
        source_code=request.source_code,
        source_format=source_fmt,
        provider=provider,
        api_key=org_api_key,
        model_override=org_model,
    )

    return AIExplainResponse(**result)


@router.post("/converter/enhance", response_model=AIEnhanceResponse)
async def ai_enhance_rule(
    request: AIEnhanceRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Get AI-powered suggestions to improve a detection rule.

    Returns suggestions for:
    - Detection accuracy (reducing false positives/negatives)
    - Performance optimization
    - Additional conditions to consider
    - MITRE ATT&CK coverage
    - Best practices
    """
    # Validate format
    try:
        source_fmt = ConversionFormat(request.source_format.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid source format: {request.source_format}. Supported: {[f.value for f in ConversionFormat]}"
        )

    # Determine provider
    provider = ConverterLLMProvider.CLAUDE  # Default
    if request.provider:
        try:
            provider = ConverterLLMProvider(request.provider.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid provider: {request.provider}. Use 'claude' or 'openai'."
            )

    # Get organization's API key for this provider
    provider_name = "anthropic" if provider == ConverterLLMProvider.CLAUDE else "openai"
    org_api_key, org_model = await get_org_api_key(db, org_id, provider_name)

    # Check if provider is available
    org_has_anthropic, org_has_openai = await get_org_has_keys(db, org_id)
    available = ai_converter_service.get_available_providers(
        org_has_anthropic=org_has_anthropic,
        org_has_openai=org_has_openai,
    )
    if not any(p["id"] == provider.value for p in available):
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{provider.value}' is not configured. Configure API key in AI Settings."
        )

    result = ai_converter_service.suggest_improvements(
        source_code=request.source_code,
        source_format=source_fmt,
        provider=provider,
        api_key=org_api_key,
        model_override=org_model,
    )

    return AIEnhanceResponse(**result)


# ==================== AI Chat Endpoint ====================

class ChatAttachment(BaseModel):
    name: str
    content: str
    type: str


class ChatMessage(BaseModel):
    role: str
    content: str


class AIChatRequest(BaseModel):
    message: str
    attachments: Optional[list[ChatAttachment]] = None
    context: Optional[dict] = None
    history: Optional[list[ChatMessage]] = None
    provider: Optional[str] = None


class AIChatResponse(BaseModel):
    response: str
    context: Optional[dict] = None
    provider: str
    model: str
    action_taken: Optional[str] = None
    action_data: Optional[dict] = None


class NLQRequest(BaseModel):
    query: str
    provider: Optional[str] = None


class NLQResponse(BaseModel):
    answer: str
    sql: Optional[str] = None
    results: Optional[list] = None
    explanation: Optional[str] = None
    provider: str
    model: str


@router.post("/ask", response_model=NLQResponse)
async def ask_your_data(
    request: NLQRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Ask questions about your security data in natural language.
    Translates English to SQL and executes it safely.
    """
    # 1. Determine provider and get key
    provider_str = request.provider or "anthropic"
    provider_name = provider_str.lower()
    org_api_key, org_model = await get_org_api_key(db, org_id, provider_name)
    
    if not org_api_key and not settings.anthropic_api_key and not settings.openai_api_key:
        raise HTTPException(status_code=400, detail="No LLM provider configured")

    # 2. Define the schema context for the LLM
    schema_context = """
    Table: normalized_alerts
    Columns:
    - id (UUID)
    - organization_id (UUID)
    - title (String): Alert title
    - description (Text): Detailed description
    - severity (String): critical, high, medium, low, info
    - status (String): open, triaged, resolved, dismissed
    - source_type (String): e.g., cloudflare, crowdstrike, panther
    - rule_id (String): ID of the detection rule
    - rule_name (String): Human-readable rule name
    - timestamp (DateTime): When the event occurred
    - ingested_at (DateTime): When we received it
    - entities (JSONB): List of entities like IPs, emails, hostnames
    """

    prompt = f"""You are a specialized SQL assistant for a security platform.
    Translate the following natural language security question into a valid PostgreSQL query.
    
    Database Schema:
    {schema_context}
    
    Constraints:
    - Always include: WHERE organization_id = '{org_id}'
    - Use ILIKE for case-insensitive text search.
    - Return ONLY the SQL query, no explanation or other text.
    - Limit results to 50 unless specified otherwise.
    
    Question: {request.query}
    
    SQL:"""

    try:
        # 3. Call LLM to get SQL
        llm_provider = LLMProvider(provider_name)
        result = await llm_service._call_llm_with_key(prompt, llm_provider, org_api_key, org_model)
        generated_sql = result["summary"].strip().replace("```sql", "").replace("```", "").strip()
        
        # Security Check: Basic SQL injection prevention
        forbidden = ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "TRUNCATE", "GRANT", "REVOKE"]
        if any(word in generated_sql.upper() for word in forbidden):
            raise ValueError("Generated query contains forbidden keywords for safety.")

        # 4. Execute the SQL
        from sqlalchemy import text
        execution_result = await db.execute(text(generated_sql))
        rows = execution_result.mappings().all()
        
        # 5. Get a natural language explanation of the results
        explanation_prompt = f"""Given this security question: "{request.query}"
        And these results from the database: {json.dumps([dict(r) for r in rows[:5]], default=str)}
        
        Provide a concise (1-2 sentence) summary of what was found."""
        
        exp_result = await llm_service._call_llm_with_key(explanation_prompt, llm_provider, org_api_key, org_model)
        
        return NLQResponse(
            answer=exp_result["summary"].strip(),
            sql=generated_sql,
            results=[dict(r) for r in rows],
            explanation=None,
            provider=provider_name,
            model=result["model"]
        )
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"NLQ Failed: {str(e)}", exc_info=True)
        return NLQResponse(
            answer=f"I couldn't process that query: {str(e)}",
            provider=provider_name,
            model="error"
        )


async def _execute_alert_lookup(
    db: AsyncSession,
    org_id: UUID,
    query: str,
    limit: int = 10
) -> dict:
    """Look up alerts from the database."""
    # Build query
    stmt = select(NormalizedAlert).where(
        NormalizedAlert.organization_id == org_id
    )

    # Add search filters if query provided
    if query:
        search_filter = or_(
            NormalizedAlert.title.ilike(f"%{query}%"),
            NormalizedAlert.description.ilike(f"%{query}%"),
            NormalizedAlert.rule_name.ilike(f"%{query}%"),
        )
        stmt = stmt.where(search_filter)

    stmt = stmt.order_by(NormalizedAlert.timestamp.desc()).limit(limit)

    result = await db.execute(stmt)
    alerts = result.scalars().all()

    return {
        "count": len(alerts),
        "alerts": [
            {
                "id": str(a.id),
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "source": a.source_system,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "rule_name": a.rule_name,
            }
            for a in alerts
        ]
    }


async def _execute_incident_lookup(
    db: AsyncSession,
    org_id: UUID,
    query: str,
    limit: int = 10
) -> dict:
    """Look up incidents from the database."""
    stmt = select(Incident).where(
        Incident.organization_id == org_id
    )

    if query:
        search_filter = or_(
            Incident.title.ilike(f"%{query}%"),
            Incident.description.ilike(f"%{query}%"),
        )
        stmt = stmt.where(search_filter)

    stmt = stmt.order_by(Incident.created_at.desc()).limit(limit)

    result = await db.execute(stmt)
    incidents = result.scalars().all()

    return {
        "count": len(incidents),
        "incidents": [
            {
                "id": str(i.id),
                "title": i.title,
                "severity": i.severity.value if i.severity else None,
                "status": i.status.value if i.status else None,
                "created_at": i.created_at.isoformat() if i.created_at else None,
                "alert_count": i.alert_count,
            }
            for i in incidents
        ]
    }


async def _execute_conversion(
    source_code: str,
    source_format: str,
    target_format: str,
    provider: ConverterLLMProvider,
    api_key: Optional[str] = None,
    model_override: Optional[str] = None,
) -> dict:
    """Execute a rule conversion."""
    try:
        source_fmt = ConversionFormat(source_format.lower())
        target_fmt = ConversionFormat(target_format.lower())
    except ValueError:
        return {"success": False, "error": "Invalid format specified"}

    result = ai_converter_service.convert(
        source_code=source_code,
        source_format=source_fmt,
        target_format=target_fmt,
        provider=provider,
        api_key=api_key,
        model_override=model_override,
    )

    return result


async def _get_alert_stats(db: AsyncSession, org_id: UUID) -> dict:
    """Get alert statistics."""
    from datetime import datetime, timedelta

    # Get counts by severity
    severity_stmt = select(
        NormalizedAlert.severity,
        func.count(NormalizedAlert.id)
    ).where(
        NormalizedAlert.organization_id == org_id
    ).group_by(NormalizedAlert.severity)

    severity_result = await db.execute(severity_stmt)
    severity_counts = {row[0]: row[1] for row in severity_result.all()}

    # Get counts by status
    status_stmt = select(
        NormalizedAlert.status,
        func.count(NormalizedAlert.id)
    ).where(
        NormalizedAlert.organization_id == org_id
    ).group_by(NormalizedAlert.status)

    status_result = await db.execute(status_stmt)
    status_counts = {row[0]: row[1] for row in status_result.all()}

    # Get recent count (last 24h)
    yesterday = datetime.utcnow() - timedelta(hours=24)
    recent_stmt = select(func.count(NormalizedAlert.id)).where(
        and_(
            NormalizedAlert.organization_id == org_id,
            NormalizedAlert.timestamp >= yesterday
        )
    )
    recent_result = await db.execute(recent_stmt)
    recent_count = recent_result.scalar() or 0

    return {
        "by_severity": severity_counts,
        "by_status": status_counts,
        "last_24h": recent_count,
        "total": sum(severity_counts.values()) if severity_counts else 0,
    }


def _detect_intent(message: str, attachments: list = None) -> tuple[str, dict]:
    """Detect user intent from message."""
    message_lower = message.lower()

    # Check for conversion intent
    if any(word in message_lower for word in ['convert', 'translate', 'transform', 'change to', 'to yaral', 'to kql', 'to spl', 'to sigma', 'to eql']):
        # Detect target format
        target = None
        if 'yaral' in message_lower or 'yara-l' in message_lower or 'chronicle' in message_lower or 'secops' in message_lower:
            target = 'yaral'
        elif 'kql' in message_lower or 'sentinel' in message_lower or 'microsoft' in message_lower:
            target = 'kql'
        elif 'spl' in message_lower or 'splunk' in message_lower:
            target = 'spl'
        elif 'sigma' in message_lower:
            target = 'sigma'
        elif 'eql' in message_lower or 'elastic' in message_lower:
            target = 'eql'
        elif 'panther' in message_lower or 'python' in message_lower:
            target = 'panther'

        if attachments or '```' in message or 'index=' in message_lower or 'rule ' in message_lower:
            return 'convert', {'target_format': target}

    # Check for alert lookup intent
    if any(word in message_lower for word in ['show alerts', 'list alerts', 'find alerts', 'search alerts', 'get alerts', 'recent alerts', 'latest alerts', 'alert for', 'alerts about', 'alerts related']):
        # Extract search term if present
        search_term = None
        for phrase in ['about ', 'for ', 'related to ', 'containing ', 'with ']:
            if phrase in message_lower:
                idx = message_lower.index(phrase) + len(phrase)
                search_term = message[idx:].strip().strip('"\'')
                break
        return 'alert_lookup', {'search': search_term}

    # Check for alert stats intent
    if any(phrase in message_lower for phrase in ['alert stats', 'alert statistics', 'how many alerts', 'alert count', 'alert summary', 'alert overview']):
        return 'alert_stats', {}

    # Check for incident lookup intent
    if any(word in message_lower for word in ['show incidents', 'list incidents', 'find incidents', 'search incidents', 'get incidents', 'recent incidents', 'latest incidents']):
        search_term = None
        for phrase in ['about ', 'for ', 'related to ', 'containing ', 'with ']:
            if phrase in message_lower:
                idx = message_lower.index(phrase) + len(phrase)
                search_term = message[idx:].strip().strip('"\'')
                break
        return 'incident_lookup', {'search': search_term}

    # Check for explain intent
    if any(word in message_lower for word in ['explain', 'what does', 'how does', 'understand', 'describe']):
        if attachments or '```' in message:
            return 'explain', {}

    # Default to general chat
    return 'chat', {}


@router.post("/chat", response_model=AIChatResponse)
async def ai_chat(
    request: AIChatRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    AI-powered chat assistant for security detection help.

    Supports:
    - Rule conversions (actually performs the conversion)
    - Alert lookups from database
    - Incident lookups from database
    - Alert statistics
    - Rule explanations
    - Best practices guidance
    """
    # Determine provider
    provider = ConverterLLMProvider.CLAUDE  # Default
    if request.provider:
        try:
            provider = ConverterLLMProvider(request.provider.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid provider: {request.provider}. Use 'claude' or 'openai'."
            )

    # Get organization's API key for this provider
    provider_name = "anthropic" if provider == ConverterLLMProvider.CLAUDE else "openai"
    org_api_key, org_model = await get_org_api_key(db, org_id, provider_name)

    # Check if provider is available
    org_has_anthropic, org_has_openai = await get_org_has_keys(db, org_id)
    available = ai_converter_service.get_available_providers(
        org_has_anthropic=org_has_anthropic,
        org_has_openai=org_has_openai,
    )
    if not any(p["id"] == provider.value for p in available):
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{provider.value}' is not configured. Configure API key in AI Settings."
        )

    # Detect intent
    intent, intent_params = _detect_intent(
        request.message,
        request.attachments
    )

    action_taken = None
    action_data = None
    response_context = request.context or {}

    # Execute actions based on intent
    if intent == 'alert_lookup':
        action_taken = 'alert_lookup'
        search_query = intent_params.get('search', '')
        action_data = await _execute_alert_lookup(db, org_id, search_query)

        # Format response
        search_suffix = f' matching "{search_query}"' if search_query else ''
        if action_data['count'] == 0:
            response_text = f"No alerts found{search_suffix}."
        else:
            response_text = f"Found **{action_data['count']} alerts**{search_suffix}:\n\n"
            for alert in action_data['alerts']:
                severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(alert['severity'], '⚪')
                response_text += f"{severity_emoji} **{alert['title']}**\n"
                response_text += f"   - Severity: {alert['severity']} | Status: {alert['status']}\n"
                response_text += f"   - Source: {alert['source']} | Rule: {alert['rule_name']}\n"
                response_text += f"   - Time: {alert['timestamp']}\n\n"

        return AIChatResponse(
            response=response_text,
            context=response_context,
            provider=provider.value,
            model="database",
            action_taken=action_taken,
            action_data=action_data,
        )

    elif intent == 'alert_stats':
        action_taken = 'alert_stats'
        action_data = await _get_alert_stats(db, org_id)

        response_text = f"**Alert Statistics**\n\n"
        response_text += f"📊 **Total Alerts**: {action_data['total']}\n"
        response_text += f"🕐 **Last 24 hours**: {action_data['last_24h']}\n\n"

        if action_data['by_severity']:
            response_text += "**By Severity:**\n"
            for severity, count in action_data['by_severity'].items():
                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(severity, '⚪')
                response_text += f"  {emoji} {severity}: {count}\n"

        if action_data['by_status']:
            response_text += "\n**By Status:**\n"
            for status, count in action_data['by_status'].items():
                response_text += f"  • {status}: {count}\n"

        return AIChatResponse(
            response=response_text,
            context=response_context,
            provider=provider.value,
            model="database",
            action_taken=action_taken,
            action_data=action_data,
        )

    elif intent == 'incident_lookup':
        action_taken = 'incident_lookup'
        search_query = intent_params.get('search', '')
        action_data = await _execute_incident_lookup(db, org_id, search_query)

        search_suffix = f' matching "{search_query}"' if search_query else ''
        if action_data['count'] == 0:
            response_text = f"No incidents found{search_suffix}."
        else:
            response_text = f"Found **{action_data['count']} incidents**{search_suffix}:\n\n"
            for incident in action_data['incidents']:
                severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(incident['severity'], '⚪')
                response_text += f"{severity_emoji} **{incident['title']}**\n"
                response_text += f"   - Severity: {incident['severity']} | Status: {incident['status']}\n"
                response_text += f"   - Alerts: {incident['alert_count']} | Created: {incident['created_at']}\n\n"

        return AIChatResponse(
            response=response_text,
            context=response_context,
            provider=provider.value,
            model="database",
            action_taken=action_taken,
            action_data=action_data,
        )

    elif intent == 'convert':
        action_taken = 'convert'
        target_format = intent_params.get('target_format', 'sigma')

        # Extract source code from attachments or message
        source_code = None
        source_format = None

        if request.attachments:
            att = request.attachments[0]
            source_code = att.content
            source_format = att.type
        else:
            # Try to extract code block from message
            import re
            code_match = re.search(r'```(\w+)?\n(.*?)```', request.message, re.DOTALL)
            if code_match:
                source_format = code_match.group(1) or 'spl'
                source_code = code_match.group(2).strip()
            else:
                # Try to detect inline code
                if 'index=' in request.message:
                    source_format = 'spl'
                    source_code = request.message
                elif 'rule ' in request.message and 'events:' in request.message:
                    source_format = 'yaral'
                    source_code = request.message

        if source_code and source_format:
            if not target_format:
                target_format = 'sigma'  # Default

            action_data = await _execute_conversion(
                source_code, source_format, target_format, provider,
                api_key=org_api_key, model_override=org_model
            )

            if action_data.get('success'):
                response_text = f"✅ **Converted from {source_format.upper()} to {target_format.upper()}**\n\n"
                response_text += f"```{target_format}\n{action_data['converted_code']}\n```"
                response_context['lastConversion'] = action_data['converted_code']
                response_context['sourceFormat'] = source_format
                response_context['targetFormat'] = target_format
            else:
                response_text = f"❌ Conversion failed: {action_data.get('error', 'Unknown error')}"

            return AIChatResponse(
                response=response_text,
                context=response_context,
                provider=provider.value,
                model=action_data.get('model', 'unknown'),
                action_taken=action_taken,
                action_data=action_data,
            )

    # Default: Use AI for general chat/explanations
    system_prompt = """You are a helpful AI security assistant for a SecOps platform called RevOps. You help users with:

1. **Rule Explanations**: Explaining what detection rules do, their logic, and potential improvements
2. **Security Guidance**: Best practices for detection engineering, threat hunting, and SIEM management
3. **Platform Help**: Answering questions about the platform features

The platform can:
- Convert rules between formats (SPL, KQL, YARA-L, Sigma, EQL, Panther) - user can say "convert this to YARAL"
- Look up alerts - user can say "show recent alerts" or "find alerts about ransomware"
- Look up incidents - user can say "show incidents"
- Get alert statistics - user can say "how many alerts do we have"

When given a detection rule, explain what it detects and how it works.
Keep responses concise but helpful. Use markdown formatting for code blocks and lists."""

    # Build the user message with attachments
    user_message = request.message or ""

    if request.attachments:
        for att in request.attachments:
            user_message += f"\n\n**Attached File: {att.name}** (detected as {att.type.upper()}):\n```{att.type}\n{att.content}\n```"

    # Build conversation history
    messages = []
    if request.history:
        for msg in request.history[-6:]:
            messages.append({
                "role": msg.role,
                "content": msg.content
            })

    messages.append({
        "role": "user",
        "content": user_message
    })

    # Call the LLM
    result = ai_converter_service._call_llm(
        provider=provider,
        system_prompt=system_prompt,
        user_prompt=user_message,
        messages=messages if len(messages) > 1 else None,
        api_key=org_api_key,
        model_override=org_model,
    )

    return AIChatResponse(
        response=result.get("content", "I apologize, but I couldn't generate a response. Please try again."),
        context=response_context,
        provider=provider.value,
        model=result.get("model", "unknown"),
    )
