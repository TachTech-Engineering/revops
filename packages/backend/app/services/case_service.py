from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import Case, CaseActivity, CaseActivityType


async def generate_case_number(db: AsyncSession) -> str:
    """Generate a unique case number in format CASE-YYYY-NNNN."""
    year = datetime.utcnow().year
    prefix = f"CASE-{year}-"

    # Find the highest case number for this year
    result = await db.execute(
        select(Case.case_number)
        .where(Case.case_number.like(f"{prefix}%"))
        .order_by(Case.case_number.desc())
        .limit(1)
    )
    last_case = result.scalar_one_or_none()

    if last_case:
        try:
            last_number = int(last_case.split("-")[-1])
            next_number = last_number + 1
        except (ValueError, IndexError):
            next_number = 1
    else:
        next_number = 1

    return f"{prefix}{next_number:04d}"


async def add_case_activity(
    db: AsyncSession,
    case_id: UUID,
    activity_type: CaseActivityType,
    description: str,
    user_email: str,
    old_value: str | None = None,
    new_value: str | None = None,
) -> CaseActivity:
    """Add an activity entry to a case's timeline."""
    activity = CaseActivity(
        case_id=case_id,
        activity_type=activity_type,
        description=description,
        old_value=old_value,
        new_value=new_value,
        user_email=user_email,
    )
    db.add(activity)
    await db.flush()
    return activity


async def track_field_change(
    db: AsyncSession,
    case_id: UUID,
    field_name: str,
    old_value: str | None,
    new_value: str | None,
    user_email: str,
) -> CaseActivity | None:
    """Track a field change as an activity if the value actually changed."""
    if str(old_value) == str(new_value):
        return None

    activity_type_map = {
        "status": CaseActivityType.STATUS_CHANGED,
        "priority": CaseActivityType.PRIORITY_CHANGED,
        "assignee": CaseActivityType.ASSIGNEE_CHANGED,
    }

    activity_type = activity_type_map.get(field_name, CaseActivityType.UPDATED)
    description = f"Changed {field_name} from '{old_value or 'none'}' to '{new_value or 'none'}'"

    return await add_case_activity(
        db=db,
        case_id=case_id,
        activity_type=activity_type,
        description=description,
        user_email=user_email,
        old_value=str(old_value) if old_value else None,
        new_value=str(new_value) if new_value else None,
    )


async def get_case_timeline(
    db: AsyncSession,
    case_id: UUID,
    limit: int = 50,
) -> list[CaseActivity]:
    """Get the activity timeline for a case."""
    result = await db.execute(
        select(CaseActivity)
        .where(CaseActivity.case_id == case_id)
        .order_by(CaseActivity.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())
