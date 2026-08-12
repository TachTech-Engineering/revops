from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUserJWTDep
from app.db import UserSettings, get_db

router = APIRouter()


class UserSettingsUpdate(BaseModel):
    theme: str | None = None
    default_time_range: int | None = None
    alerts_per_page: int | None = None
    notifications_enabled: bool | None = None
    notification_severities: list[str] | None = None
    keyboard_shortcuts_enabled: bool | None = None


class UserSettingsResponse(BaseModel):
    id: UUID
    user_id: str
    theme: str
    default_time_range: int
    alerts_per_page: int
    notifications_enabled: bool
    notification_severities: list[str]
    keyboard_shortcuts_enabled: bool

    class Config:
        from_attributes = True


async def get_or_create_settings(db: AsyncSession, user_id: str) -> UserSettings:
    """Get user settings or create default if not exists."""
    result = await db.execute(select(UserSettings).where(UserSettings.user_id == user_id))
    settings = result.scalar_one_or_none()
    if not settings:
        settings = UserSettings(user_id=user_id)
        db.add(settings)
        await db.flush()
        await db.refresh(settings)
    return settings


@router.get("")
async def get_settings(
    user: CurrentUserJWTDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> UserSettingsResponse:
    """Get settings for the authenticated user."""
    settings = await get_or_create_settings(db, str(user.id))
    return UserSettingsResponse(
        id=settings.id,
        user_id=settings.user_id,
        theme=settings.theme,
        default_time_range=settings.default_time_range,
        alerts_per_page=settings.alerts_per_page,
        notifications_enabled=settings.notifications_enabled,
        notification_severities=settings.notification_severities,
        keyboard_shortcuts_enabled=settings.keyboard_shortcuts_enabled,
    )


@router.patch("")
async def update_settings(
    update: UserSettingsUpdate,
    user: CurrentUserJWTDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> UserSettingsResponse:
    """Update settings for the authenticated user."""
    settings = await get_or_create_settings(db, str(user.id))

    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(settings, field, value)

    await db.flush()
    await db.refresh(settings)
    return UserSettingsResponse(
        id=settings.id,
        user_id=settings.user_id,
        theme=settings.theme,
        default_time_range=settings.default_time_range,
        alerts_per_page=settings.alerts_per_page,
        notifications_enabled=settings.notifications_enabled,
        notification_severities=settings.notification_severities,
        keyboard_shortcuts_enabled=settings.keyboard_shortcuts_enabled,
    )
