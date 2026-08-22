from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAdminDep, OrgIdDep, OrgUserDep
from app.core.time_utils import utcnow
from app.db import Notification, NotificationType, User, get_db

router = APIRouter()


class NotificationResponse(BaseModel):
    id: UUID
    notification_type: NotificationType
    title: str
    message: str
    resource_type: str | None
    resource_id: str | None
    is_read: bool
    read_at: str | None
    created_by: str | None
    created_at: str

    class Config:
        from_attributes = True


class NotificationListResponse(BaseModel):
    items: list[NotificationResponse]
    total: int
    unread_count: int


class NotificationCreate(BaseModel):
    """For creating notifications programmatically."""

    user_email: str
    notification_type: NotificationType
    title: str
    message: str
    resource_type: str | None = None
    resource_id: str | None = None


def format_notification(n: Notification) -> NotificationResponse:
    return NotificationResponse(
        id=n.id,
        notification_type=n.notification_type,
        title=n.title,
        message=n.message,
        resource_type=n.resource_type,
        resource_id=n.resource_id,
        is_read=n.is_read,
        read_at=n.read_at.isoformat() if n.read_at else None,
        created_by=n.created_by,
        created_at=n.created_at.isoformat(),
    )


@router.get("")
async def list_notifications(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    unread_only: bool = False,
    notification_type: NotificationType | None = None,
    page: int = 1,
    page_size: int = 20,
) -> NotificationListResponse:
    """List notifications for the current user."""
    query = select(Notification).where(
        and_(
            Notification.organization_id == org_id,
            Notification.user_email == user.email,
        )
    )

    if unread_only:
        query = query.where(Notification.is_read.is_(False))

    if notification_type:
        query = query.where(Notification.notification_type == notification_type)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Get unread count
    unread_result = await db.execute(
        select(func.count()).where(
            and_(
                Notification.organization_id == org_id,
                Notification.user_email == user.email,
                Notification.is_read.is_(False),
            )
        )
    )
    unread_count = unread_result.scalar() or 0

    # Get paginated results
    query = query.order_by(Notification.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    notifications = result.scalars().all()

    return NotificationListResponse(
        items=[format_notification(n) for n in notifications],
        total=total,
        unread_count=unread_count,
    )


@router.get("/unread-count")
async def get_unread_count(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Get the count of unread notifications."""
    result = await db.execute(
        select(func.count()).where(
            and_(
                Notification.organization_id == org_id,
                Notification.user_email == user.email,
                Notification.is_read.is_(False),
            )
        )
    )
    count = result.scalar() or 0

    return {"unread_count": count}


@router.get("/{notification_id}")
async def get_notification(
    notification_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> NotificationResponse:
    """Get a specific notification."""
    result = await db.execute(
        select(Notification).where(
            and_(
                Notification.id == notification_id,
                Notification.organization_id == org_id,
                Notification.user_email == user.email,
            )
        )
    )
    notification = result.scalar_one_or_none()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    return format_notification(notification)


@router.post("/{notification_id}/read")
async def mark_as_read(
    notification_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> NotificationResponse:
    """Mark a notification as read."""
    result = await db.execute(
        select(Notification).where(
            and_(
                Notification.id == notification_id,
                Notification.organization_id == org_id,
                Notification.user_email == user.email,
            )
        )
    )
    notification = result.scalar_one_or_none()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    if not notification.is_read:
        notification.is_read = True
        notification.read_at = utcnow()
        await db.flush()
        await db.refresh(notification)

    return format_notification(notification)


@router.post("/read-all")
async def mark_all_as_read(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Mark all notifications as read."""
    now = utcnow()
    result = await db.execute(
        update(Notification)
        .where(
            and_(
                Notification.organization_id == org_id,
                Notification.user_email == user.email,
                Notification.is_read.is_(False),
            )
        )
        .values(is_read=True, read_at=now)
    )

    return {"marked_read": result.rowcount}


@router.delete("/{notification_id}")
async def delete_notification(
    notification_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a notification."""
    result = await db.execute(
        select(Notification).where(
            and_(
                Notification.id == notification_id,
                Notification.organization_id == org_id,
                Notification.user_email == user.email,
            )
        )
    )
    notification = result.scalar_one_or_none()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    await db.delete(notification)
    return {"status": "deleted"}


@router.delete("")
async def clear_notifications(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    read_only: bool = True,
) -> dict:
    """Clear notifications. By default only clears read notifications."""
    query = select(Notification).where(
        and_(
            Notification.organization_id == org_id,
            Notification.user_email == user.email,
        )
    )

    if read_only:
        query = query.where(Notification.is_read.is_(True))

    result = await db.execute(query)
    notifications = result.scalars().all()

    count = len(notifications)
    for n in notifications:
        await db.delete(n)

    return {"deleted": count}


# Internal endpoint for creating notifications (used by other services)
@router.post("/internal/create")
async def create_notification_internal(
    data: NotificationCreate,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> NotificationResponse:
    """Create a notification for a user in the caller's organization.

    Admin-only: this endpoint had no role dependency at all, so any VIEWER could
    forge notifications attributed to an arbitrary ``user_email``. The recipient
    is now verified to be an active member of the caller's organization, and
    ``created_by`` is taken from the authenticated caller rather than trusted
    from the request body.
    """
    recipient = await db.execute(
        select(User).where(
            and_(
                func.lower(User.email) == data.user_email.strip().lower(),
                User.organization_id == org_id,
            )
        )
    )
    target_user = recipient.scalar_one_or_none()
    if not target_user:
        raise HTTPException(status_code=404, detail="No such user in this organization")

    notification = Notification(
        user_email=target_user.email,
        notification_type=data.notification_type,
        title=data.title,
        message=data.message,
        resource_type=data.resource_type,
        resource_id=data.resource_id,
        organization_id=org_id,
        created_by=user.email,
    )
    db.add(notification)
    await db.flush()
    await db.refresh(notification)

    return format_notification(notification)
