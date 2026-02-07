"""
On-Call Scheduling API - Feature 8
Native rotation management with auto-routing.
"""
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID
import pytz

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import OrgUserDep, OrgIdDep, OrgAnalystDep, OrgAdminDep
from app.db import get_db, OnCallSchedule, OnCallRotationMember, OnCallOverride, RotationType, OnCallRole
from fastapi import Depends

router = APIRouter()


# ==================== Response Models ====================

class OnCallMemberResponse(BaseModel):
    id: str
    user_email: str
    user_name: Optional[str]
    rotation_order: int
    role: str
    phone_number: Optional[str]
    slack_user_id: Optional[str]

    class Config:
        from_attributes = True


class OnCallScheduleResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    timezone: str
    rotation_type: str
    handoff_time: str
    handoff_day: Optional[int]
    rotation_length_days: Optional[int]
    is_active: bool
    members: list[OnCallMemberResponse]
    created_by: str
    created_at: str

    class Config:
        from_attributes = True


class OnCallOverrideResponse(BaseModel):
    id: str
    schedule_id: str
    override_user_email: str
    original_user_email: Optional[str]
    start_time: str
    end_time: str
    reason: Optional[str]
    created_by: str
    created_at: str

    class Config:
        from_attributes = True


class CurrentOnCallResponse(BaseModel):
    schedule_id: str
    schedule_name: str
    primary: Optional[OnCallMemberResponse]
    backup: Optional[OnCallMemberResponse]
    is_override: bool
    override_end: Optional[str]


# ==================== Request Models ====================

class OnCallMemberCreate(BaseModel):
    user_email: str
    user_name: Optional[str] = None
    rotation_order: int
    role: str = "primary"  # primary or backup
    phone_number: Optional[str] = None
    slack_user_id: Optional[str] = None


class OnCallScheduleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    timezone: str = "UTC"
    rotation_type: str = "weekly"  # daily, weekly, custom
    handoff_time: str = "09:00"
    handoff_day: Optional[int] = None  # 0=Monday for weekly
    rotation_length_days: Optional[int] = None  # for custom
    is_active: bool = True
    members: list[OnCallMemberCreate] = []


class OnCallScheduleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    timezone: Optional[str] = None
    handoff_time: Optional[str] = None
    handoff_day: Optional[int] = None
    is_active: Optional[bool] = None


class OnCallOverrideCreate(BaseModel):
    schedule_id: str
    override_user_email: str
    original_user_email: Optional[str] = None
    start_time: str  # ISO format
    end_time: str  # ISO format
    reason: Optional[str] = None


def serialize_member(member: OnCallRotationMember) -> OnCallMemberResponse:
    return OnCallMemberResponse(
        id=str(member.id),
        user_email=member.user_email,
        user_name=member.user_name,
        rotation_order=member.rotation_order,
        role=member.role.value,
        phone_number=member.phone_number,
        slack_user_id=member.slack_user_id,
    )


def serialize_schedule(schedule: OnCallSchedule) -> OnCallScheduleResponse:
    return OnCallScheduleResponse(
        id=str(schedule.id),
        name=schedule.name,
        description=schedule.description,
        timezone=schedule.timezone,
        rotation_type=schedule.rotation_type.value,
        handoff_time=schedule.handoff_time,
        handoff_day=schedule.handoff_day,
        rotation_length_days=schedule.rotation_length_days,
        is_active=schedule.is_active,
        members=[serialize_member(m) for m in sorted(schedule.members, key=lambda x: x.rotation_order)],
        created_by=schedule.created_by,
        created_at=schedule.created_at.isoformat(),
    )


# ==================== Schedules ====================

@router.get("/schedules", response_model=list[OnCallScheduleResponse])
async def list_schedules(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    is_active: Optional[bool] = Query(None),
):
    """List all on-call schedules."""
    query = (
        select(OnCallSchedule)
        .where(OnCallSchedule.organization_id == org_id)
        .options(selectinload(OnCallSchedule.members))
    )

    if is_active is not None:
        query = query.where(OnCallSchedule.is_active == is_active)

    result = await db.execute(query)
    schedules = result.scalars().unique().all()

    return [serialize_schedule(s) for s in schedules]


@router.get("/schedules/{schedule_id}", response_model=OnCallScheduleResponse)
async def get_schedule(
    schedule_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific on-call schedule."""
    result = await db.execute(
        select(OnCallSchedule)
        .where(OnCallSchedule.id == UUID(schedule_id))
        .where(OnCallSchedule.organization_id == org_id)
        .options(selectinload(OnCallSchedule.members))
    )
    schedule = result.scalar_one_or_none()

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    return serialize_schedule(schedule)


@router.post("/schedules", status_code=201, response_model=OnCallScheduleResponse)
async def create_schedule(
    request: OnCallScheduleCreate,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Create a new on-call schedule."""
    schedule = OnCallSchedule(
        organization_id=org_id,
        name=request.name,
        description=request.description,
        timezone=request.timezone,
        rotation_type=RotationType(request.rotation_type),
        handoff_time=request.handoff_time,
        handoff_day=request.handoff_day,
        rotation_length_days=request.rotation_length_days,
        is_active=request.is_active,
        created_by=user.email,
    )
    db.add(schedule)
    await db.flush()

    # Add members
    for member_data in request.members:
        member = OnCallRotationMember(
            schedule_id=schedule.id,
            user_email=member_data.user_email,
            user_name=member_data.user_name,
            rotation_order=member_data.rotation_order,
            role=OnCallRole(member_data.role),
            phone_number=member_data.phone_number,
            slack_user_id=member_data.slack_user_id,
        )
        db.add(member)

    await db.commit()

    # Refresh with members
    result = await db.execute(
        select(OnCallSchedule)
        .where(OnCallSchedule.id == schedule.id)
        .options(selectinload(OnCallSchedule.members))
    )
    schedule = result.scalar_one()

    return serialize_schedule(schedule)


@router.patch("/schedules/{schedule_id}", response_model=OnCallScheduleResponse)
async def update_schedule(
    schedule_id: str,
    request: OnCallScheduleUpdate,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Update an on-call schedule."""
    result = await db.execute(
        select(OnCallSchedule)
        .where(OnCallSchedule.id == UUID(schedule_id))
        .where(OnCallSchedule.organization_id == org_id)
        .options(selectinload(OnCallSchedule.members))
    )
    schedule = result.scalar_one_or_none()

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    update_data = request.model_dump(exclude_none=True)
    for key, value in update_data.items():
        setattr(schedule, key, value)

    await db.commit()
    await db.refresh(schedule)

    return serialize_schedule(schedule)


@router.delete("/schedules/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: str,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Delete an on-call schedule."""
    result = await db.execute(
        select(OnCallSchedule)
        .where(OnCallSchedule.id == UUID(schedule_id))
        .where(OnCallSchedule.organization_id == org_id)
    )
    schedule = result.scalar_one_or_none()

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    await db.delete(schedule)
    await db.commit()


# ==================== Current On-Call ====================

def calculate_current_oncall(schedule: OnCallSchedule, now: datetime) -> tuple[Optional[OnCallRotationMember], Optional[OnCallRotationMember]]:
    """Calculate who is currently on-call based on rotation."""
    primary_members = [m for m in schedule.members if m.role == OnCallRole.PRIMARY]
    backup_members = [m for m in schedule.members if m.role == OnCallRole.BACKUP]

    if not primary_members:
        return None, None

    # Sort by rotation order
    primary_members.sort(key=lambda x: x.rotation_order)
    backup_members.sort(key=lambda x: x.rotation_order)

    # Calculate rotation index based on schedule type
    tz = pytz.timezone(schedule.timezone)
    local_now = now.astimezone(tz) if now.tzinfo else tz.localize(now)

    if schedule.rotation_type == RotationType.DAILY:
        # Daily rotation - changes at handoff_time each day
        handoff_hour, handoff_minute = map(int, schedule.handoff_time.split(":"))
        days_since_epoch = (local_now.date() - datetime(2020, 1, 1).date()).days
        rotation_index = days_since_epoch % len(primary_members)

    elif schedule.rotation_type == RotationType.WEEKLY:
        # Weekly rotation - changes on handoff_day at handoff_time
        handoff_day = schedule.handoff_day or 0  # Default to Monday
        weeks_since_epoch = (local_now.date() - datetime(2020, 1, 6).date()).days // 7  # Monday Jan 6, 2020
        rotation_index = weeks_since_epoch % len(primary_members)

    else:  # Custom
        # Custom rotation length
        length = schedule.rotation_length_days or 7
        days_since_epoch = (local_now.date() - datetime(2020, 1, 1).date()).days
        rotation_index = (days_since_epoch // length) % len(primary_members)

    primary = primary_members[rotation_index]
    backup = backup_members[rotation_index % len(backup_members)] if backup_members else None

    return primary, backup


@router.get("/current", response_model=list[CurrentOnCallResponse])
async def get_current_oncall(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get who is currently on-call for all active schedules."""
    now = datetime.utcnow()

    result = await db.execute(
        select(OnCallSchedule)
        .where(OnCallSchedule.organization_id == org_id)
        .where(OnCallSchedule.is_active == True)
        .options(selectinload(OnCallSchedule.members))
    )
    schedules = result.scalars().unique().all()

    responses = []
    for schedule in schedules:
        # Check for active override
        override_result = await db.execute(
            select(OnCallOverride)
            .where(OnCallOverride.organization_id == org_id)
            .where(OnCallOverride.schedule_id == schedule.id)
            .where(OnCallOverride.start_time <= now)
            .where(OnCallOverride.end_time > now)
        )
        override = override_result.scalar_one_or_none()

        if override:
            # Return override user
            responses.append(
                CurrentOnCallResponse(
                    schedule_id=str(schedule.id),
                    schedule_name=schedule.name,
                    primary=OnCallMemberResponse(
                        id="override",
                        user_email=override.override_user_email,
                        user_name=None,
                        rotation_order=0,
                        role="primary",
                        phone_number=None,
                        slack_user_id=None,
                    ),
                    backup=None,
                    is_override=True,
                    override_end=override.end_time.isoformat(),
                )
            )
        else:
            # Calculate from rotation
            primary, backup = calculate_current_oncall(schedule, now)
            responses.append(
                CurrentOnCallResponse(
                    schedule_id=str(schedule.id),
                    schedule_name=schedule.name,
                    primary=serialize_member(primary) if primary else None,
                    backup=serialize_member(backup) if backup else None,
                    is_override=False,
                    override_end=None,
                )
            )

    return responses


# ==================== Overrides ====================

@router.post("/override", status_code=201, response_model=OnCallOverrideResponse)
async def create_override(
    request: OnCallOverrideCreate,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Create a temporary schedule override."""
    # Verify schedule exists
    result = await db.execute(
        select(OnCallSchedule)
        .where(OnCallSchedule.id == UUID(request.schedule_id))
        .where(OnCallSchedule.organization_id == org_id)
    )
    schedule = result.scalar_one_or_none()

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    override = OnCallOverride(
        organization_id=org_id,
        schedule_id=UUID(request.schedule_id),
        override_user_email=request.override_user_email,
        original_user_email=request.original_user_email,
        start_time=datetime.fromisoformat(request.start_time.replace("Z", "+00:00")),
        end_time=datetime.fromisoformat(request.end_time.replace("Z", "+00:00")),
        reason=request.reason,
        created_by=user.email,
    )
    db.add(override)
    await db.commit()
    await db.refresh(override)

    return OnCallOverrideResponse(
        id=str(override.id),
        schedule_id=str(override.schedule_id),
        override_user_email=override.override_user_email,
        original_user_email=override.original_user_email,
        start_time=override.start_time.isoformat(),
        end_time=override.end_time.isoformat(),
        reason=override.reason,
        created_by=override.created_by,
        created_at=override.created_at.isoformat(),
    )


@router.get("/calendar", response_model=list[dict])
async def get_oncall_calendar(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    schedule_id: Optional[str] = Query(None),
    start_date: str = Query(..., description="Start date (YYYY-MM-DD)"),
    end_date: str = Query(..., description="End date (YYYY-MM-DD)"),
):
    """Get calendar view of on-call schedule."""
    start = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")

    query = (
        select(OnCallSchedule)
        .where(OnCallSchedule.organization_id == org_id)
        .where(OnCallSchedule.is_active == True)
        .options(selectinload(OnCallSchedule.members))
    )

    if schedule_id:
        query = query.where(OnCallSchedule.id == UUID(schedule_id))

    result = await db.execute(query)
    schedules = result.scalars().unique().all()

    calendar_events = []
    current = start

    while current <= end:
        for schedule in schedules:
            primary, backup = calculate_current_oncall(schedule, current)
            if primary:
                calendar_events.append({
                    "date": current.strftime("%Y-%m-%d"),
                    "schedule_id": str(schedule.id),
                    "schedule_name": schedule.name,
                    "primary_email": primary.user_email,
                    "primary_name": primary.user_name,
                    "backup_email": backup.user_email if backup else None,
                    "backup_name": backup.user_name if backup else None,
                })
        current += timedelta(days=1)

    return calendar_events


@router.delete("/override/{override_id}", status_code=204)
async def delete_override(
    override_id: str,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Delete an override."""
    result = await db.execute(
        select(OnCallOverride)
        .where(OnCallOverride.id == UUID(override_id))
        .where(OnCallOverride.organization_id == org_id)
    )
    override = result.scalar_one_or_none()

    if not override:
        raise HTTPException(status_code=404, detail="Override not found")

    await db.delete(override)
    await db.commit()
