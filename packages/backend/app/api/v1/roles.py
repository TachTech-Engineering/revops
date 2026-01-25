from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db, UserRole, UserRoleType
from app.api.v1.deps import RequireAdminDep
from app.config import settings

router = APIRouter()


class UserRoleCreate(BaseModel):
    email: EmailStr
    role: UserRoleType


class UserRoleUpdate(BaseModel):
    role: UserRoleType


class UserRoleResponse(BaseModel):
    id: UUID
    email: str
    role: UserRoleType
    created_by: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class CurrentUserRoleResponse(BaseModel):
    email: str
    role: UserRoleType
    is_admin_whitelisted: bool


@router.get("/me")
async def get_my_role(
    admin_check: RequireAdminDep = None,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
) -> CurrentUserRoleResponse:
    """Get the current user's role. Requires admin to access (for role management page)."""
    email, role = admin_check
    is_whitelisted = email in settings.admin_emails_list
    return CurrentUserRoleResponse(
        email=email,
        role=role,
        is_admin_whitelisted=is_whitelisted,
    )


@router.get("")
async def list_user_roles(
    admin_check: RequireAdminDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[UserRoleResponse]:
    """List all user roles. Admin only."""
    result = await db.execute(select(UserRole).order_by(UserRole.email))
    roles = result.scalars().all()
    return [
        UserRoleResponse(
            id=r.id,
            email=r.email,
            role=r.role,
            created_by=r.created_by,
            created_at=r.created_at.isoformat(),
            updated_at=r.updated_at.isoformat(),
        )
        for r in roles
    ]


@router.post("")
async def create_user_role(
    role_data: UserRoleCreate,
    admin_check: RequireAdminDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> UserRoleResponse:
    """Assign a role to a user. Admin only."""
    admin_email, _ = admin_check
    email = role_data.email.lower()

    # Check if user already has a role
    result = await db.execute(select(UserRole).where(UserRole.email == email))
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"User {email} already has a role assigned. Use PATCH to update.",
        )

    # Warn if trying to assign role to admin-whitelisted user
    if email in settings.admin_emails_list:
        raise HTTPException(
            status_code=400,
            detail=f"User {email} is in the admin whitelist and will always have admin access.",
        )

    db_role = UserRole(
        email=email,
        role=role_data.role,
        created_by=admin_email,
    )
    db.add(db_role)
    await db.flush()
    await db.refresh(db_role)

    return UserRoleResponse(
        id=db_role.id,
        email=db_role.email,
        role=db_role.role,
        created_by=db_role.created_by,
        created_at=db_role.created_at.isoformat(),
        updated_at=db_role.updated_at.isoformat(),
    )


@router.patch("/{role_id}")
async def update_user_role(
    role_id: UUID,
    update: UserRoleUpdate,
    admin_check: RequireAdminDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> UserRoleResponse:
    """Update a user's role. Admin only."""
    result = await db.execute(select(UserRole).where(UserRole.id == role_id))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="User role not found")

    role.role = update.role
    await db.flush()
    await db.refresh(role)

    return UserRoleResponse(
        id=role.id,
        email=role.email,
        role=role.role,
        created_by=role.created_by,
        created_at=role.created_at.isoformat(),
        updated_at=role.updated_at.isoformat(),
    )


@router.delete("/{role_id}")
async def delete_user_role(
    role_id: UUID,
    admin_check: RequireAdminDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a user role assignment. Admin only."""
    result = await db.execute(select(UserRole).where(UserRole.id == role_id))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="User role not found")

    await db.delete(role)
    return {"status": "deleted"}
