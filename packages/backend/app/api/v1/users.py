"""
User Management API endpoints.
Allows admins to view and manage user accounts.
"""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import User, UserRoleType
from app.api.v1.deps import OrgAdminDep, OrgIdDep, get_db
from fastapi import Depends

router = APIRouter()


class UserResponse(BaseModel):
    id: str
    email: str
    name: Optional[str]
    role: str
    is_active: bool
    sso_provider: Optional[str]
    created_at: str
    last_login_at: Optional[str]

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    items: list[UserResponse]
    total: int
    page: int
    page_size: int


class UserUpdateRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None


@router.get("", response_model=UserListResponse)
async def list_users(
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    search: Optional[str] = None,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
):
    """
    List all users in the organization.
    Requires admin role.
    """
    # Build query
    query = select(User).where(User.organization_id == org_id)

    if search:
        search_filter = f"%{search.lower()}%"
        query = query.where(
            (User.email.ilike(search_filter)) | (User.name.ilike(search_filter))
        )

    if role:
        try:
            role_enum = UserRoleType(role.upper())
            query = query.where(User.role == role_enum)
        except ValueError:
            pass

    if is_active is not None:
        query = query.where(User.is_active == is_active)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Get paginated results
    query = query.order_by(desc(User.created_at))
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    users = result.scalars().all()

    return UserListResponse(
        items=[
            UserResponse(
                id=str(u.id),
                email=u.email,
                name=u.name,
                role=u.role.value.lower(),
                is_active=u.is_active,
                sso_provider=u.sso_provider.value if u.sso_provider else None,
                created_at=u.created_at.isoformat(),
                last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
            )
            for u in users
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Get a specific user by ID.
    Requires admin role.
    """
    result = await db.execute(
        select(User).where(User.id == user_id, User.organization_id == org_id)
    )
    target_user = result.scalar_one_or_none()

    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserResponse(
        id=str(target_user.id),
        email=target_user.email,
        name=target_user.name,
        role=target_user.role.value.lower(),
        is_active=target_user.is_active,
        sso_provider=target_user.sso_provider.value if target_user.sso_provider else None,
        created_at=target_user.created_at.isoformat(),
        last_login_at=target_user.last_login_at.isoformat() if target_user.last_login_at else None,
    )


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    update: UserUpdateRequest,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Update a user's role or active status.
    Requires admin role.
    """
    result = await db.execute(
        select(User).where(User.id == user_id, User.organization_id == org_id)
    )
    target_user = result.scalar_one_or_none()

    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent self-deactivation
    if user.id == user_id and update.is_active is False:
        raise HTTPException(
            status_code=400,
            detail="You cannot deactivate your own account"
        )

    # Prevent self-demotion from admin
    if user.id == user_id and update.role and update.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=400,
            detail="You cannot remove your own admin role"
        )

    # Update fields
    if update.role is not None:
        try:
            target_user.role = UserRoleType(update.role.upper())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid role: {update.role}. Valid roles: admin, analyst, viewer"
            )

    if update.is_active is not None:
        target_user.is_active = update.is_active

    await db.commit()
    await db.refresh(target_user)

    return UserResponse(
        id=str(target_user.id),
        email=target_user.email,
        name=target_user.name,
        role=target_user.role.value.lower(),
        is_active=target_user.is_active,
        sso_provider=target_user.sso_provider.value if target_user.sso_provider else None,
        created_at=target_user.created_at.isoformat(),
        last_login_at=target_user.last_login_at.isoformat() if target_user.last_login_at else None,
    )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: UUID,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Delete a user account.
    Requires admin role.
    """
    # Prevent self-deletion
    if user.id == user_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot delete your own account"
        )

    result = await db.execute(
        select(User).where(User.id == user_id, User.organization_id == org_id)
    )
    target_user = result.scalar_one_or_none()

    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    await db.delete(target_user)
    await db.commit()
