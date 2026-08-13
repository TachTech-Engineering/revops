import logging
import zlib
from collections.abc import Iterable
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time_utils import utcnow
from app.db import Case, CaseActivity, CaseActivityType

logger = logging.getLogger(__name__)

# How many of the highest-sorting case numbers to inspect. The ordering below
# puts the true maximum first, but a malformed row (hand-written import, a
# renumbering) should not be able to pin the sequence, so we look at a few and
# take the largest value that parses.
_CANDIDATE_ROWS = 25

_INT4_RANGE = 2**32
_INT4_MAX = 2**31


def format_case_number(year: int, sequence: int) -> str:
    """Render a case number: ``CASE-2026-0042``.

    Zero-padded to four digits and *not* truncated past 9999, so the sequence
    keeps climbing (CASE-2026-10000) instead of wrapping.
    """
    return f"CASE-{year}-{sequence:04d}"


def next_case_sequence(case_numbers: Iterable[str], year: int) -> int:
    """Next free sequence number given existing case numbers for ``year``.

    The numeric suffix is compared as an integer. The old implementation took
    the lexicographic maximum, so once an organization reached CASE-2026-10000
    the string comparison ranked it *below* CASE-2026-9999: the counter stuck
    at 10000 and every subsequent create hit a duplicate-key error.
    """
    prefix = f"CASE-{year}-"
    highest = 0
    for number in case_numbers:
        if not number or not number.startswith(prefix):
            continue
        suffix = number[len(prefix) :]
        if not suffix.isdigit():
            continue
        highest = max(highest, int(suffix))
    return highest + 1


def _sequence_lock_key(organization_id: UUID | None, year: int) -> int:
    """Stable signed-int4 advisory-lock key for one org's yearly sequence."""
    key = zlib.crc32(f"case-number:{organization_id}:{year}".encode())
    return key - _INT4_RANGE if key >= _INT4_MAX else key


async def _lock_case_sequence(db: AsyncSession, organization_id: UUID | None, year: int) -> None:
    """Serialize case-number allocation for one organization and year.

    A transaction-scoped advisory lock, so it is held until the caller commits
    the new case. Two concurrent creates in the same organization therefore
    allocate different numbers instead of both reading the same maximum and
    racing to a duplicate key on ``ix_cases_org_number``.
    """
    try:
        dialect = db.get_bind().dialect.name
    except Exception:  # pragma: no cover - defensive
        dialect = ""

    if dialect != "postgresql":
        # SQLite and friends have no advisory locks; the unique index still
        # rejects a genuine collision.
        return

    await db.execute(
        text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": _sequence_lock_key(organization_id, year)},
    )


async def generate_case_number(db: AsyncSession, organization_id: UUID | None = None) -> str:
    """Generate the next case number for an organization: ``CASE-YYYY-NNNN``.

    The sequence is per-organization: a tenant's case numbers must not reveal
    the platform's total case volume, and ``ix_cases_org_number`` is unique on
    (organization_id, case_number) so per-org numbering is what the schema
    expects. ``organization_id`` is optional only so existing callers keep
    working; omitting it falls back to a cross-tenant sequence and is logged.
    """
    year = utcnow().year
    prefix = f"CASE-{year}-"

    if organization_id is None:
        logger.warning(
            "generate_case_number called without organization_id; "
            "falling back to a cross-tenant sequence"
        )

    await _lock_case_sequence(db, organization_id, year)

    # Longest-then-lexicographic descending puts the numerically largest
    # suffix first for any zero-padded width (CASE-2026-10000 sorts above
    # CASE-2026-9999 because it is one character longer).
    query = select(Case.case_number).where(Case.case_number.like(f"{prefix}%"))
    if organization_id is not None:
        query = query.where(Case.organization_id == organization_id)
    query = query.order_by(
        func.length(Case.case_number).desc(),
        Case.case_number.desc(),
    ).limit(_CANDIDATE_ROWS)

    result = await db.execute(query)
    return format_case_number(year, next_case_sequence(result.scalars().all(), year))


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
