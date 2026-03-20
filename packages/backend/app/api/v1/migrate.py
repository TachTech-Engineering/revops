"""
Migration API - Detection rule conversion endpoints.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, status, UploadFile, File, Depends
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.migration_service import migration_service, SIEMFormat
from app.services.ai_converter_service import ai_converter_service, ConversionFormat, LLMProvider
from app.services.encryption_service import decrypt_credential
from app.config import settings
from app.db.session import get_db
from app.db.models import OrganizationAPIKeys
from app.api.v1.deps import OrgUserDep, OrgIdDep

router = APIRouter()


async def get_org_api_key(
    db: AsyncSession,
    org_id,
    provider: LLMProvider,
) -> Optional[str]:
    """Fetch and decrypt organization API key for the given provider."""
    provider_name = 'anthropic' if provider == LLMProvider.CLAUDE else 'openai'
    result = await db.execute(
        select(OrganizationAPIKeys).where(
            and_(
                OrganizationAPIKeys.organization_id == org_id,
                OrganizationAPIKeys.provider == provider_name,
                OrganizationAPIKeys.is_active == True,
            )
        )
    )
    org_key_record = result.scalar_one_or_none()
    if org_key_record:
        try:
            return decrypt_credential(org_key_record.api_key_encrypted)
        except Exception:
            pass
    return None


class ConvertRequest(BaseModel):
    source_format: str
    target_format: str
    source_code: str


class ConvertResponse(BaseModel):
    converted_code: str
    source_format: str
    target_format: str
    intermediate_sigma: Optional[str] = None


class BulkConvertRequest(BaseModel):
    source_format: str
    target_format: str
    rules: list[str]


class BulkConvertResponse(BaseModel):
    results: list[dict]
    success_count: int
    error_count: int


class FormatInfo(BaseModel):
    id: str
    name: str
    description: str


class AIConvertRequest(BaseModel):
    source_format: str
    target_format: str
    source_code: str
    context: Optional[str] = None
    provider: Optional[str] = "anthropic"  # anthropic or openai


class AIConvertResponse(BaseModel):
    converted_code: str
    source_format: str
    target_format: str
    provider: str
    model: str
    success: bool
    error: Optional[str] = None


class ExplainRequest(BaseModel):
    source_format: str
    source_code: str
    provider: Optional[str] = "anthropic"


class SuggestRequest(BaseModel):
    source_format: str
    source_code: str
    provider: Optional[str] = "anthropic"


class AIBulkConvertRequest(BaseModel):
    source_format: str
    target_format: str
    rules: list[str]
    context: Optional[str] = None
    provider: Optional[str] = "anthropic"


class AIBulkConvertResponse(BaseModel):
    results: list[dict]
    success_count: int
    error_count: int
    provider: str
    model: str


@router.get("/formats", response_model=list[FormatInfo])
async def get_supported_formats():
    """Get list of supported SIEM formats for conversion."""
    return migration_service.get_supported_formats()


@router.post("/convert", response_model=ConvertResponse)
async def convert_rule(request: ConvertRequest):
    """
    Convert a detection rule from one SIEM format to another.

    Uses Sigma as an intermediate format for accurate conversion:
    Source → Sigma → Target

    Supported formats:
    - sigma: Universal Sigma format (YAML)
    - spl: Splunk Search Processing Language
    - yaral: Google SecOps / Chronicle YARA-L
    - kql: Microsoft Sentinel KQL
    - eql: Elastic Security EQL
    - esql: Elastic ES|QL (new query language)
    - panther: Panther Python detection rules
    """
    try:
        source_format = SIEMFormat(request.source_format.lower())
        target_format = SIEMFormat(request.target_format.lower())
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format: {e}. Supported formats: {[f.value for f in SIEMFormat]}"
        )

    if not request.source_code.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source code cannot be empty"
        )

    try:
        converted = migration_service.convert(
            source_code=request.source_code,
            source_format=source_format,
            target_format=target_format,
        )

        # Also get Sigma intermediate if not converting to/from Sigma
        intermediate_sigma = None
        if source_format != SIEMFormat.SIGMA and target_format != SIEMFormat.SIGMA:
            intermediate_sigma = migration_service.convert(
                source_code=request.source_code,
                source_format=source_format,
                target_format=SIEMFormat.SIGMA,
            )

        return ConvertResponse(
            converted_code=converted,
            source_format=source_format.value,
            target_format=target_format.value,
            intermediate_sigma=intermediate_sigma,
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Conversion failed: {str(e)}"
        )


@router.post("/convert/bulk", response_model=BulkConvertResponse)
async def bulk_convert_rules(request: BulkConvertRequest):
    """
    Convert multiple detection rules in batch.

    Returns results for each rule with success/failure status.
    """
    try:
        source_format = SIEMFormat(request.source_format.lower())
        target_format = SIEMFormat(request.target_format.lower())
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format: {e}"
        )

    results = []
    success_count = 0
    error_count = 0

    for i, rule in enumerate(request.rules):
        try:
            converted = migration_service.convert(
                source_code=rule,
                source_format=source_format,
                target_format=target_format,
            )
            results.append({
                "index": i,
                "status": "success",
                "converted_code": converted,
            })
            success_count += 1
        except Exception as e:
            results.append({
                "index": i,
                "status": "error",
                "error": str(e),
            })
            error_count += 1

    return BulkConvertResponse(
        results=results,
        success_count=success_count,
        error_count=error_count,
    )


@router.post("/convert/file")
async def convert_file(
    file: UploadFile = File(...),
    source_format: str = "sigma",
    target_format: str = "spl",
):
    """
    Convert a detection rule file.

    Accepts: .yml, .yaml, .json, .txt, .spl, .kql, .eql, .py
    """
    try:
        src_format = SIEMFormat(source_format.lower())
        tgt_format = SIEMFormat(target_format.lower())
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format: {e}"
        )

    # Read file content
    content = await file.read()
    try:
        source_code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be UTF-8 encoded text"
        )

    try:
        converted = migration_service.convert(
            source_code=source_code,
            source_format=src_format,
            target_format=tgt_format,
        )

        return {
            "filename": file.filename,
            "source_format": src_format.value,
            "target_format": tgt_format.value,
            "converted_code": converted,
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Conversion failed: {str(e)}"
        )


@router.get("/examples/{format}")
async def get_format_example(format: str):
    """Get an example detection rule for a specific format."""
    examples = {
        "sigma": """title: Suspicious PowerShell Execution
status: experimental
description: Detects encoded PowerShell execution
author: Security Team
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
level: high
tags:
  - attack.execution
  - attack.t1059.001""",

        "spl": """index=windows sourcetype=WinEventLog:Security EventCode=4688
| where like(NewProcessName, "%powershell.exe")
| where like(CommandLine, "%-enc%")
| table _time, ComputerName, User, NewProcessName, CommandLine""",

        "yaral": """rule suspicious_powershell_execution {
  meta:
    author = "Security Team"
    description = "Detects encoded PowerShell execution"
    severity = "HIGH"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /powershell\\.exe$/
    $e.target.process.command_line = /\\-enc/

  condition:
    $e
}""",

        "kql": """SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where CommandLine contains "-enc"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine""",

        "eql": """process where process.name == "powershell.exe" and process.command_line : "*-enc*\"""",

        "esql": """FROM logs-windows.*
| WHERE process.name == "powershell.exe" AND process.command_line LIKE "%-enc%"
| KEEP @timestamp, host.name, user.name, process.name, process.command_line""",

        "panther": """def rule(event):
    \"\"\"
    Detects encoded PowerShell execution
    Severity: HIGH
    \"\"\"
    if event.get("process_name", "").endswith("powershell.exe"):
        command_line = event.get("command_line", "")
        if "-enc" in command_line.lower():
            return True
    return False


def title(event):
    return f"Suspicious PowerShell on {event.get('hostname', 'unknown')}"


def severity(event):
    return "HIGH\"""",

        "aql": """SELECT sourceip, destinationip, username, LOGSOURCENAME(logsourceid), starttime
FROM events
WHERE category = 'Authentication'
AND LOGSOURCETYPENAME(logsourceid) ILIKE '%windows%'
AND username ILIKE '%admin%'
AND eventcount > 5
GROUP BY sourceip, destinationip, username
LAST 24 HOURS""",

        "sql": """-- Suspicious authentication events
SELECT source_ip, destination_ip, username, log_source, timestamp
FROM security_events
WHERE category = 'Authentication'
AND username LIKE '%admin%'
AND event_count > 5
ORDER BY timestamp DESC
LIMIT 1000;""",
    }

    format_lower = format.lower()
    if format_lower not in examples:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No example available for format: {format}"
        )

    return {
        "format": format_lower,
        "example": examples[format_lower],
    }


# AI-Assisted Conversion Endpoints

@router.post("/convert/ai", response_model=AIConvertResponse)
async def ai_convert_rule(
    request: AIConvertRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Convert a detection rule using AI (Anthropic or OpenAI).

    Uses LLM to intelligently convert detection rules, handling
    edge cases, aggregations, and complex logic that rule-based
    conversion may not handle well.

    Uses organization API key if configured, otherwise falls back to env var.
    """
    # Validate provider
    try:
        provider = LLMProvider(request.provider.lower()) if request.provider else LLMProvider.CLAUDE
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid provider: {request.provider}. Supported: anthropic, openai"
        )

    # Try to get organization API key
    org_api_key = await get_org_api_key(db, org_id, provider)

    # Check if selected provider is available (org key OR env var)
    if provider == LLMProvider.CLAUDE and not settings.anthropic_api_key and not org_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Anthropic not available - no API key configured"
        )
    if provider == LLMProvider.OPENAI and not settings.openai_api_key and not org_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OpenAI not available - no API key configured"
        )

    try:
        source_format = ConversionFormat(request.source_format.lower())
        target_format = ConversionFormat(request.target_format.lower())
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format: {e}. Supported formats: {[f.value for f in ConversionFormat]}"
        )

    if not request.source_code.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source code cannot be empty"
        )

    result = ai_converter_service.convert(
        source_code=request.source_code,
        source_format=source_format,
        target_format=target_format,
        context=request.context,
        provider=provider,
        api_key=org_api_key,  # Pass org key if available
    )

    return AIConvertResponse(
        converted_code=result.get("converted_code", ""),
        source_format=result.get("source_format", request.source_format),
        target_format=result.get("target_format", request.target_format),
        provider=result.get("provider", provider.value),
        model=result.get("model", "unknown"),
        success=result.get("success", False),
        error=result.get("error"),
    )


@router.post("/convert/ai/bulk", response_model=AIBulkConvertResponse)
async def ai_bulk_convert_rules(request: AIBulkConvertRequest):
    """
    Convert multiple detection rules using AI (Anthropic or OpenAI).

    Processes each rule through the AI converter for intelligent handling
    of edge cases, aggregations, and complex logic.

    Requires ANTHROPIC_API_KEY or OPENAI_API_KEY to be configured.
    """
    # Validate provider
    try:
        provider = LLMProvider(request.provider.lower()) if request.provider else LLMProvider.CLAUDE
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid provider: {request.provider}. Supported: anthropic, openai"
        )

    # Check if selected provider is available
    if provider == LLMProvider.CLAUDE and not settings.anthropic_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Anthropic not available - ANTHROPIC_API_KEY not configured"
        )
    if provider == LLMProvider.OPENAI and not settings.openai_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OpenAI not available - OPENAI_API_KEY not configured"
        )

    try:
        source_format = ConversionFormat(request.source_format.lower())
        target_format = ConversionFormat(request.target_format.lower())
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format: {e}. Supported formats: {[f.value for f in ConversionFormat]}"
        )

    results = []
    success_count = 0
    error_count = 0
    model = "unknown"

    for i, rule in enumerate(request.rules):
        if not rule.strip():
            results.append({
                "index": i,
                "status": "error",
                "error": "Empty rule",
            })
            error_count += 1
            continue

        result = ai_converter_service.convert(
            source_code=rule,
            source_format=source_format,
            target_format=target_format,
            context=request.context,
            provider=provider,
        )

        model = result.get("model", model)

        if result.get("success"):
            results.append({
                "index": i,
                "status": "success",
                "converted_code": result.get("converted_code", ""),
            })
            success_count += 1
        else:
            results.append({
                "index": i,
                "status": "error",
                "error": result.get("error", "Conversion failed"),
            })
            error_count += 1

    return AIBulkConvertResponse(
        results=results,
        success_count=success_count,
        error_count=error_count,
        provider=provider.value,
        model=model,
    )


@router.post("/explain")
async def explain_rule(
    request: ExplainRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Get an AI-generated explanation of what a detection rule does.

    Returns a plain English explanation including:
    - What it's detecting
    - Key conditions
    - MITRE ATT&CK mapping
    - Potential false positives
    """
    # Validate provider
    try:
        provider = LLMProvider(request.provider.lower()) if request.provider else LLMProvider.CLAUDE
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid provider: {request.provider}. Supported: anthropic, openai"
        )

    # Get org API key
    org_api_key = await get_org_api_key(db, org_id, provider)

    # Check if selected provider is available
    if provider == LLMProvider.CLAUDE and not settings.anthropic_api_key and not org_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Anthropic not available - no API key configured"
        )
    if provider == LLMProvider.OPENAI and not settings.openai_api_key and not org_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OpenAI not available - no API key configured"
        )

    try:
        source_format = ConversionFormat(request.source_format.lower())
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format: {e}"
        )

    if not request.source_code.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source code cannot be empty"
        )

    result = ai_converter_service.explain_rule(
        source_code=request.source_code,
        source_format=source_format,
        provider=provider,
        api_key=org_api_key,
    )

    return {
        "explanation": result.get("explanation", ""),
        "source_format": source_format.value,
        "provider": result.get("provider", provider.value),
        "model": result.get("model"),
        "success": result.get("success", False),
        "error": result.get("error"),
    }


@router.post("/suggest")
async def suggest_improvements(
    request: SuggestRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Get AI-generated suggestions for improving a detection rule.

    Returns actionable suggestions for:
    - Detection accuracy
    - Performance optimization
    - MITRE ATT&CK coverage
    - Best practices
    """
    # Validate provider
    try:
        provider = LLMProvider(request.provider.lower()) if request.provider else LLMProvider.CLAUDE
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid provider: {request.provider}. Supported: anthropic, openai"
        )

    # Get org API key
    org_api_key = await get_org_api_key(db, org_id, provider)

    # Check if selected provider is available
    if provider == LLMProvider.CLAUDE and not settings.anthropic_api_key and not org_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Anthropic not available - no API key configured"
        )
    if provider == LLMProvider.OPENAI and not settings.openai_api_key and not org_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OpenAI not available - no API key configured"
        )

    try:
        source_format = ConversionFormat(request.source_format.lower())
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format: {e}"
        )

    if not request.source_code.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source code cannot be empty"
        )

    result = ai_converter_service.suggest_improvements(
        source_code=request.source_code,
        source_format=source_format,
        provider=provider,
        api_key=org_api_key,
    )

    return {
        "suggestions": result.get("suggestions", ""),
        "source_format": source_format.value,
        "provider": result.get("provider", provider.value),
        "model": result.get("model"),
        "success": result.get("success", False),
        "error": result.get("error"),
    }


@router.get("/ai/status")
async def get_ai_status(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Check if AI-assisted conversion is available and list providers."""
    # Check organization API keys
    result = await db.execute(
        select(OrganizationAPIKeys.provider).where(
            and_(
                OrganizationAPIKeys.organization_id == org_id,
                OrganizationAPIKeys.is_active == True,
            )
        )
    )
    org_providers = [row[0] for row in result.all()]
    org_has_anthropic = 'anthropic' in org_providers
    org_has_openai = 'openai' in org_providers

    providers = ai_converter_service.get_available_providers(
        org_has_anthropic=org_has_anthropic,
        org_has_openai=org_has_openai,
    )
    return {
        "available": len(providers) > 0,
        "providers": providers,
    }
