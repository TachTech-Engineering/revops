import re
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAnalystDep, OrgIdDep, OrgUserDep
from app.db import Note, NoteResourceType, Notification, NotificationType, get_db

router = APIRouter()


class NoteCreate(BaseModel):
    resource_type: NoteResourceType
    resource_id: str
    content: str
    parent_id: UUID | None = None


class NoteUpdate(BaseModel):
    content: str


class NoteResponse(BaseModel):
    id: UUID
    resource_type: NoteResourceType
    resource_id: str
    content: str
    mentions: list[str]
    is_edited: bool
    parent_id: UUID | None
    created_by: str
    created_at: str
    updated_at: str
    reply_count: int = 0

    class Config:
        from_attributes = True


def extract_mentions(content: str) -> list[str]:
    """Extract @mentions from content."""
    # Match @email or @username patterns
    pattern = r"@([a-zA-Z0-9._-]+(?:@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})?)"
    matches = re.findall(pattern, content)
    # Filter out duplicates and normalize
    return list(set(m.lower() for m in matches))


async def create_mention_notifications(
    db: AsyncSession,
    note: Note,
    mentions: list[str],
    created_by: str,
    organization_id: UUID,
):
    """Create notifications for mentioned users."""
    resource_label = {
        NoteResourceType.ALERT: "alert",
        NoteResourceType.INCIDENT: "incident",
        NoteResourceType.CASE: "case",
        NoteResourceType.RULE: "rule",
    }

    for email in mentions:
        if email.lower() == created_by.lower():
            continue  # Don't notify yourself

        notification = Notification(
            user_email=email,
            notification_type=NotificationType.MENTION,
            title=f"You were mentioned in a {resource_label.get(note.resource_type, 'note')}",
            message=(
                f"{created_by} mentioned you: {note.content[:100]}"
                f"{'...' if len(note.content) > 100 else ''}"
            ),
            resource_type=note.resource_type.value,
            resource_id=note.resource_id,
            created_by=created_by,
            organization_id=organization_id,
        )
        db.add(notification)


@router.get("")
async def list_notes(
    resource_type: NoteResourceType,
    resource_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    include_replies: bool = True,
) -> list[NoteResponse]:
    """List notes for a resource."""
    query = select(Note).where(
        and_(
            Note.organization_id == org_id,
            Note.resource_type == resource_type,
            Note.resource_id == resource_id,
        )
    )

    if not include_replies:
        query = query.where(Note.parent_id.is_(None))

    query = query.order_by(Note.created_at.desc())

    result = await db.execute(query)
    notes = result.scalars().all()

    # Get reply counts for top-level notes
    reply_counts = {}
    if not include_replies:
        for note in notes:
            count_result = await db.execute(
                select(func.count(Note.id)).where(
                    and_(
                        Note.organization_id == org_id,
                        Note.parent_id == note.id,
                    )
                )
            )
            reply_counts[note.id] = count_result.scalar() or 0

    return [
        NoteResponse(
            id=n.id,
            resource_type=n.resource_type,
            resource_id=n.resource_id,
            content=n.content,
            mentions=n.mentions,
            is_edited=n.is_edited,
            parent_id=n.parent_id,
            created_by=n.created_by,
            created_at=n.created_at.isoformat(),
            updated_at=n.updated_at.isoformat(),
            reply_count=reply_counts.get(n.id, 0),
        )
        for n in notes
    ]


@router.get("/{note_id}")
async def get_note(
    note_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> NoteResponse:
    """Get a specific note."""
    result = await db.execute(
        select(Note).where(
            and_(
                Note.organization_id == org_id,
                Note.id == note_id,
            )
        )
    )
    note = result.scalar_one_or_none()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    return NoteResponse(
        id=note.id,
        resource_type=note.resource_type,
        resource_id=note.resource_id,
        content=note.content,
        mentions=note.mentions,
        is_edited=note.is_edited,
        parent_id=note.parent_id,
        created_by=note.created_by,
        created_at=note.created_at.isoformat(),
        updated_at=note.updated_at.isoformat(),
    )


@router.get("/{note_id}/replies")
async def get_note_replies(
    note_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[NoteResponse]:
    """Get replies to a note."""
    result = await db.execute(
        select(Note)
        .where(
            and_(
                Note.organization_id == org_id,
                Note.parent_id == note_id,
            )
        )
        .order_by(Note.created_at.asc())
    )
    notes = result.scalars().all()

    return [
        NoteResponse(
            id=n.id,
            resource_type=n.resource_type,
            resource_id=n.resource_id,
            content=n.content,
            mentions=n.mentions,
            is_edited=n.is_edited,
            parent_id=n.parent_id,
            created_by=n.created_by,
            created_at=n.created_at.isoformat(),
            updated_at=n.updated_at.isoformat(),
        )
        for n in notes
    ]


@router.post("")
async def create_note(
    note_data: NoteCreate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> NoteResponse:
    """Create a new note. Requires analyst role."""
    # Extract mentions from content
    mentions = extract_mentions(note_data.content)

    # If this is a reply, verify parent exists within the same organization
    if note_data.parent_id:
        result = await db.execute(
            select(Note).where(
                and_(
                    Note.organization_id == analyst.organization_id,
                    Note.id == note_data.parent_id,
                )
            )
        )
        parent = result.scalar_one_or_none()
        if not parent:
            raise HTTPException(status_code=404, detail="Parent note not found")

    note = Note(
        resource_type=note_data.resource_type,
        resource_id=note_data.resource_id,
        content=note_data.content,
        mentions=mentions,
        parent_id=note_data.parent_id,
        created_by=analyst.email,
        organization_id=analyst.organization_id,
    )
    db.add(note)
    await db.flush()
    await db.refresh(note)

    # Create notifications for mentions
    if mentions:
        await create_mention_notifications(
            db, note, mentions, analyst.email, analyst.organization_id
        )

    # If this is a reply, notify the parent note author
    if note_data.parent_id and parent.created_by.lower() != analyst.email.lower():
        notification = Notification(
            user_email=parent.created_by,
            notification_type=NotificationType.COMMENT_REPLY,
            title="Someone replied to your note",
            message=(
                f"{analyst.email} replied: {note.content[:100]}"
                f"{'...' if len(note.content) > 100 else ''}"
            ),
            resource_type=note.resource_type.value,
            resource_id=note.resource_id,
            created_by=analyst.email,
            organization_id=analyst.organization_id,
        )
        db.add(notification)

    return NoteResponse(
        id=note.id,
        resource_type=note.resource_type,
        resource_id=note.resource_id,
        content=note.content,
        mentions=note.mentions,
        is_edited=note.is_edited,
        parent_id=note.parent_id,
        created_by=note.created_by,
        created_at=note.created_at.isoformat(),
        updated_at=note.updated_at.isoformat(),
    )


@router.patch("/{note_id}")
async def update_note(
    note_id: UUID,
    update: NoteUpdate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> NoteResponse:
    """Update a note. Can only edit your own notes."""
    result = await db.execute(
        select(Note).where(
            and_(
                Note.organization_id == analyst.organization_id,
                Note.id == note_id,
            )
        )
    )
    note = result.scalar_one_or_none()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    if note.created_by.lower() != analyst.email.lower():
        raise HTTPException(status_code=403, detail="You can only edit your own notes")

    # Extract new mentions
    old_mentions = set(note.mentions)
    new_mentions = set(extract_mentions(update.content))

    note.content = update.content
    note.mentions = list(new_mentions)
    note.is_edited = True

    await db.flush()
    await db.refresh(note)

    # Notify newly mentioned users
    added_mentions = new_mentions - old_mentions
    if added_mentions:
        await create_mention_notifications(
            db, note, list(added_mentions), analyst.email, analyst.organization_id
        )

    return NoteResponse(
        id=note.id,
        resource_type=note.resource_type,
        resource_id=note.resource_id,
        content=note.content,
        mentions=note.mentions,
        is_edited=note.is_edited,
        parent_id=note.parent_id,
        created_by=note.created_by,
        created_at=note.created_at.isoformat(),
        updated_at=note.updated_at.isoformat(),
    )


@router.delete("/{note_id}")
async def delete_note(
    note_id: UUID,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a note. Can only delete your own notes."""
    result = await db.execute(
        select(Note).where(
            and_(
                Note.organization_id == analyst.organization_id,
                Note.id == note_id,
            )
        )
    )
    note = result.scalar_one_or_none()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    if note.created_by.lower() != analyst.email.lower():
        raise HTTPException(status_code=403, detail="You can only delete your own notes")

    # Delete replies first (within the same organization)
    reply_result = await db.execute(
        select(Note).where(
            and_(
                Note.organization_id == analyst.organization_id,
                Note.parent_id == note_id,
            )
        )
    )
    for reply in reply_result.scalars():
        await db.delete(reply)

    await db.delete(note)
    return {"status": "deleted"}
