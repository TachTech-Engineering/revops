from typing import Annotated
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAdminDep, OrgIdDep, OrgUserDep
from app.core.time_utils import utcnow
from app.db import WebhookConfig, get_db
from app.db.models import WebhookType

router = APIRouter()


class WebhookCreate(BaseModel):
    name: str
    description: str | None = None
    webhook_type: WebhookType = WebhookType.GENERIC
    url: str
    secret: str | None = None
    headers: dict[str, str] = {}
    severity_filter: list[str] = ["CRITICAL", "HIGH"]
    is_active: bool = True


class WebhookUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    webhook_type: WebhookType | None = None
    url: str | None = None
    secret: str | None = None
    headers: dict[str, str] | None = None
    severity_filter: list[str] | None = None
    is_active: bool | None = None


class WebhookResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    webhook_type: str
    url: str
    headers: dict[str, str]
    severity_filter: list[str]
    is_active: bool
    last_triggered_at: str | None
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class WebhookTestResult(BaseModel):
    success: bool
    status_code: int | None = None
    message: str


@router.get("")
async def list_webhooks(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: OrgUserDep,
    org_id: OrgIdDep,
) -> list[WebhookResponse]:
    """List all webhook configurations."""
    result = await db.execute(
        select(WebhookConfig)
        .where(WebhookConfig.organization_id == org_id)
        .order_by(WebhookConfig.created_at.desc())
    )
    webhooks = result.scalars().all()
    return [
        WebhookResponse(
            id=w.id,
            name=w.name,
            description=w.description,
            webhook_type=w.webhook_type.value,
            url=w.url,
            headers=w.headers,
            severity_filter=w.severity_filter,
            is_active=w.is_active,
            last_triggered_at=w.last_triggered_at.isoformat() if w.last_triggered_at else None,
            created_at=w.created_at.isoformat(),
            updated_at=w.updated_at.isoformat(),
        )
        for w in webhooks
    ]


@router.post("")
async def create_webhook(
    webhook: WebhookCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: OrgAdminDep,
) -> WebhookResponse:
    """Create a new webhook configuration."""
    db_webhook = WebhookConfig(
        name=webhook.name,
        description=webhook.description,
        webhook_type=webhook.webhook_type,
        url=webhook.url,
        secret=webhook.secret,
        headers=webhook.headers,
        severity_filter=webhook.severity_filter,
        is_active=webhook.is_active,
        organization_id=admin.organization_id,
    )
    db.add(db_webhook)
    await db.flush()
    await db.refresh(db_webhook)
    return WebhookResponse(
        id=db_webhook.id,
        name=db_webhook.name,
        description=db_webhook.description,
        webhook_type=db_webhook.webhook_type.value,
        url=db_webhook.url,
        headers=db_webhook.headers,
        severity_filter=db_webhook.severity_filter,
        is_active=db_webhook.is_active,
        last_triggered_at=None,
        created_at=db_webhook.created_at.isoformat(),
        updated_at=db_webhook.updated_at.isoformat(),
    )


@router.patch("/{webhook_id}")
async def update_webhook(
    webhook_id: UUID,
    update: WebhookUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: OrgAdminDep,
) -> WebhookResponse:
    """Update a webhook configuration."""
    result = await db.execute(
        select(WebhookConfig).where(
            and_(
                WebhookConfig.id == webhook_id,
                WebhookConfig.organization_id == admin.organization_id,
            )
        )
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(webhook, field, value)

    await db.flush()
    await db.refresh(webhook)
    return WebhookResponse(
        id=webhook.id,
        name=webhook.name,
        description=webhook.description,
        webhook_type=webhook.webhook_type.value,
        url=webhook.url,
        headers=webhook.headers,
        severity_filter=webhook.severity_filter,
        is_active=webhook.is_active,
        last_triggered_at=webhook.last_triggered_at.isoformat()
        if webhook.last_triggered_at
        else None,
        created_at=webhook.created_at.isoformat(),
        updated_at=webhook.updated_at.isoformat(),
    )


@router.delete("/{webhook_id}")
async def delete_webhook(
    webhook_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: OrgAdminDep,
) -> dict[str, str]:
    """Delete a webhook configuration."""
    result = await db.execute(
        select(WebhookConfig).where(
            and_(
                WebhookConfig.id == webhook_id,
                WebhookConfig.organization_id == admin.organization_id,
            )
        )
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    await db.delete(webhook)
    return {"status": "deleted"}


@router.post("/{webhook_id}/test")
async def test_webhook(
    webhook_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: OrgAdminDep,
) -> WebhookTestResult:
    """Test a webhook by sending a test payload."""
    result = await db.execute(
        select(WebhookConfig).where(
            and_(
                WebhookConfig.id == webhook_id,
                WebhookConfig.organization_id == admin.organization_id,
            )
        )
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    test_payload = {
        "type": "test",
        "message": "This is a test notification from PantherUtil",
        "timestamp": utcnow().isoformat(),
        "alert": {
            "id": "test-alert-id",
            "title": "Test Alert",
            "severity": "INFO",
            "status": "OPEN",
        },
    }

    # Format payload based on webhook type
    if webhook.webhook_type == WebhookType.SLACK:
        payload = {
            "text": f"*Test Alert*\n{test_payload['message']}",
            "attachments": [
                {
                    "color": "#36a64f",
                    "fields": [
                        {"title": "Severity", "value": "INFO", "short": True},
                        {"title": "Status", "value": "OPEN", "short": True},
                    ],
                }
            ],
        }
    elif webhook.webhook_type == WebhookType.TEAMS:
        payload = {
            "@type": "MessageCard",
            "summary": "Test Alert",
            "themeColor": "0076D7",
            "title": "Test Alert from PantherUtil",
            "text": test_payload["message"],
        }
    else:
        payload = test_payload

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook.url,
                json=payload,
                headers=webhook.headers,
                timeout=10.0,
            )

        if response.status_code < 400:
            webhook.last_triggered_at = utcnow()
            await db.flush()
            return WebhookTestResult(
                success=True,
                status_code=response.status_code,
                message="Webhook test successful",
            )
        else:
            return WebhookTestResult(
                success=False,
                status_code=response.status_code,
                message=f"Webhook returned error: {response.text[:200]}",
            )
    except Exception as e:
        return WebhookTestResult(
            success=False,
            message=f"Webhook test failed: {str(e)}",
        )
