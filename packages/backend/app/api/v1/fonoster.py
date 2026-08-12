"""
Fonoster Integration API

Endpoints for configuring and testing Fonoster telephony integration.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.api.v1.deps import OrgAdminDep, OrgIdDep
from app.services.fonoster import (
    FonosterConfig,
    get_fonoster_service,
)

router = APIRouter()


class FonosterConfigRequest(BaseModel):
    api_endpoint: str
    access_key_id: str
    access_key_secret: str
    default_caller_id: str
    tts_voice: str = "en-US-Standard-A"
    enabled: bool = False


class FonosterConfigResponse(BaseModel):
    api_endpoint: str
    access_key_id: str  # Masked
    default_caller_id: str
    tts_voice: str
    enabled: bool


class TestCallRequest(BaseModel):
    phone_number: str
    message: str | None = "This is a test call from Panther Security Dashboard."


class TestSmsRequest(BaseModel):
    phone_number: str
    message: str | None = "[PANTHER TEST] This is a test SMS from Panther Security."


@router.get("/config", response_model=FonosterConfigResponse)
async def get_fonoster_config(
    user: OrgAdminDep,
    org_id: OrgIdDep,
):
    """Get current Fonoster configuration (secrets masked)."""
    service = get_fonoster_service()
    config = service.config

    return FonosterConfigResponse(
        api_endpoint=config.api_endpoint,
        access_key_id=config.access_key_id[:4] + "****" if config.access_key_id else "",
        default_caller_id=config.default_caller_id,
        tts_voice=config.tts_voice,
        enabled=config.enabled,
    )


@router.put("/config")
async def update_fonoster_config(
    request: FonosterConfigRequest,
    user: OrgAdminDep,
    org_id: OrgIdDep,
):
    """Update Fonoster configuration."""
    # In a real implementation, this would save to the database
    # For now, we update the service config directly
    service = get_fonoster_service()
    service.config = FonosterConfig(
        api_endpoint=request.api_endpoint,
        access_key_id=request.access_key_id,
        access_key_secret=request.access_key_secret,
        default_caller_id=request.default_caller_id,
        tts_voice=request.tts_voice,
        enabled=request.enabled,
    )

    return {"success": True, "message": "Configuration updated"}


@router.post("/test-connection")
async def test_fonoster_connection(
    user: OrgAdminDep,
    org_id: OrgIdDep,
):
    """Test the Fonoster connection."""
    service = get_fonoster_service()
    result = await service.test_connection()

    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])

    return result


@router.post("/test-call")
async def test_call(
    request: TestCallRequest,
    user: OrgAdminDep,
    org_id: OrgIdDep,
):
    """Make a test voice call."""
    service = get_fonoster_service()

    if not service.config.enabled:
        raise HTTPException(status_code=400, detail="Fonoster is not enabled")

    result = await service.make_call(
        to_number=request.phone_number,
        message=request.message,
    )

    if not result["success"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Call failed"))

    return result


@router.post("/test-sms")
async def test_sms(
    request: TestSmsRequest,
    user: OrgAdminDep,
    org_id: OrgIdDep,
):
    """Send a test SMS."""
    service = get_fonoster_service()

    if not service.config.enabled:
        raise HTTPException(status_code=400, detail="Fonoster is not enabled")

    result = await service.send_sms(
        to_number=request.phone_number,
        message=request.message,
    )

    if not result["success"]:
        raise HTTPException(status_code=400, detail=result.get("error", "SMS failed"))

    return result
