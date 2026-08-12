"""
Real-time Presence API

Tracks which users are currently viewing alerts for collaboration awareness.
"""

from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgIdDep, OrgUserDep
from app.db import AlertPresence, get_db

router = APIRouter()

# Presence timeout - users inactive for this long are considered gone
PRESENCE_TIMEOUT_SECONDS = 60


# ==================== Models ====================


class PresenceUser(BaseModel):
    user_id: str
    user_email: str
    user_name: str | None
    started_viewing_at: str
    last_heartbeat: str


class AlertPresenceResponse(BaseModel):
    alert_id: str
    viewers: list[PresenceUser]
    viewer_count: int


class PresenceHeartbeat(BaseModel):
    alert_id: str


# ==================== Endpoints ====================


@router.get("/alert/{alert_id}", response_model=AlertPresenceResponse)
async def get_alert_presence(
    alert_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get list of users currently viewing an alert."""
    # Clean up stale presence records first
    cutoff = datetime.utcnow() - timedelta(seconds=PRESENCE_TIMEOUT_SECONDS)
    await db.execute(
        delete(AlertPresence)
        .where(AlertPresence.organization_id == org_id)
        .where(AlertPresence.last_heartbeat < cutoff)
    )
    await db.commit()

    # Get active viewers
    result = await db.execute(
        select(AlertPresence)
        .where(AlertPresence.organization_id == org_id)
        .where(AlertPresence.alert_id == alert_id)
    )
    presence_records = result.scalars().all()

    viewers = [
        PresenceUser(
            user_id=str(p.user_id),
            user_email=p.user_email,
            user_name=p.user_name,
            started_viewing_at=p.started_viewing_at.isoformat(),
            last_heartbeat=p.last_heartbeat.isoformat(),
        )
        for p in presence_records
    ]

    return AlertPresenceResponse(
        alert_id=alert_id,
        viewers=viewers,
        viewer_count=len(viewers),
    )


@router.post("/heartbeat")
async def send_heartbeat(
    request: PresenceHeartbeat,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Send a heartbeat to indicate user is still viewing an alert.
    Creates presence record if not exists, updates last_heartbeat if exists.
    """
    # Check for existing presence record
    result = await db.execute(
        select(AlertPresence)
        .where(AlertPresence.organization_id == org_id)
        .where(AlertPresence.alert_id == request.alert_id)
        .where(AlertPresence.user_id == UUID(user.id))
    )
    presence = result.scalar_one_or_none()

    if presence:
        # Update heartbeat
        presence.last_heartbeat = datetime.utcnow()
    else:
        # Create new presence record
        presence = AlertPresence(
            organization_id=org_id,
            alert_id=request.alert_id,
            user_id=UUID(user.id),
            user_email=user.email,
            user_name=user.name,
            started_viewing_at=datetime.utcnow(),
            last_heartbeat=datetime.utcnow(),
        )
        db.add(presence)

    await db.commit()

    return {"status": "ok", "alert_id": request.alert_id}


@router.post("/leave")
async def leave_alert(
    request: PresenceHeartbeat,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Remove user presence from an alert (user navigated away)."""
    await db.execute(
        delete(AlertPresence)
        .where(AlertPresence.organization_id == org_id)
        .where(AlertPresence.alert_id == request.alert_id)
        .where(AlertPresence.user_id == UUID(user.id))
    )
    await db.commit()

    return {"status": "ok", "alert_id": request.alert_id}


@router.delete("/clear-all")
async def clear_user_presence(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Clear all presence records for current user (e.g., on logout)."""
    await db.execute(
        delete(AlertPresence)
        .where(AlertPresence.organization_id == org_id)
        .where(AlertPresence.user_id == UUID(user.id))
    )
    await db.commit()

    return {"status": "ok", "message": "All presence cleared"}
