"""
Fonoster Integration API

Endpoints for configuring and testing Fonoster telephony integration.

Configuration is stored per organization (``organization_telephony_config``)
and resolved per request from the caller's org. It used to be written into a
process-global service singleton, so one tenant saving carrier credentials
overwrote every other tenant's -- and their escalation calls then dialled out
under the wrong account and caller ID.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAdminDep, OrgIdDep
from app.db import get_db
from app.db.models import OrganizationTelephonyConfig
from app.services.encryption_service import encrypt_credential
from app.services.fonoster import get_telephony_service_for_org

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


async def _get_org_config(db: AsyncSession, org_id: UUID) -> OrganizationTelephonyConfig | None:
    result = await db.execute(
        select(OrganizationTelephonyConfig).where(
            OrganizationTelephonyConfig.organization_id == org_id
        )
    )
    return result.scalar_one_or_none()


@router.get("/config", response_model=FonosterConfigResponse)
async def get_fonoster_config(
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get the calling organization's telephony configuration (secrets masked).

    The access key secret is never returned; the key id is masked.
    """
    config = await _get_org_config(db, org_id)

    if config is None:
        # Unconfigured organization: report empty/disabled rather than leaking
        # the deployment defaults (or, as before, another tenant's values).
        return FonosterConfigResponse(
            api_endpoint="",
            access_key_id="",
            default_caller_id="",
            tts_voice="en-US-Standard-A",
            enabled=False,
        )

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
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create or update the calling organization's telephony configuration."""
    config = await _get_org_config(db, org_id)

    if config is None:
        config = OrganizationTelephonyConfig(
            organization_id=org_id,
            api_endpoint=request.api_endpoint,
            access_key_id=request.access_key_id,
            access_key_secret_encrypted=encrypt_credential(request.access_key_secret),
            default_caller_id=request.default_caller_id,
            tts_voice=request.tts_voice,
            enabled=request.enabled,
            created_by=user.email,
        )
        db.add(config)
    else:
        config.api_endpoint = request.api_endpoint
        config.access_key_id = request.access_key_id
        config.access_key_secret_encrypted = encrypt_credential(request.access_key_secret)
        config.default_caller_id = request.default_caller_id
        config.tts_voice = request.tts_voice
        config.enabled = request.enabled

    await db.commit()

    return {"success": True, "message": "Configuration updated"}


@router.post("/test-connection")
async def test_fonoster_connection(
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Test the calling organization's telephony connection."""
    service = await get_telephony_service_for_org(db, org_id)
    result = await service.test_connection()

    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])

    return result


@router.post("/test-call")
async def test_call(
    request: TestCallRequest,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Make a test voice call using the calling organization's configuration."""
    service = await get_telephony_service_for_org(db, org_id)

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
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Send a test SMS using the calling organization's configuration."""
    service = await get_telephony_service_for_org(db, org_id)

    if not service.config.enabled:
        raise HTTPException(status_code=400, detail="Fonoster is not enabled")

    result = await service.send_sms(
        to_number=request.phone_number,
        message=request.message,
    )

    if not result["success"]:
        raise HTTPException(status_code=400, detail=result.get("error", "SMS failed"))

    return result
