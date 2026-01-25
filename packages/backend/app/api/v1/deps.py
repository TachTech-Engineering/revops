from typing import Annotated, Optional

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.panther_service import PantherService
from app.services.converter_service import ConverterService
from app.db import get_db, UserRole, UserRoleType
from app.config import settings


async def get_panther_credentials(
    x_panther_host: Optional[str] = Header(None),
    x_panther_token: Optional[str] = Header(None),
) -> tuple[str, str]:
    """Extract Panther credentials from request headers."""
    if not x_panther_host or not x_panther_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Panther credentials. Please provide X-Panther-Host and X-Panther-Token headers.",
        )
    return x_panther_host, x_panther_token


async def get_panther_service(
    credentials: tuple[str, str] = Depends(get_panther_credentials),
) -> PantherService:
    """Create a Panther service with credentials from headers."""
    host, token = credentials
    return PantherService(api_host=host, api_token=token)


def get_converter_service() -> ConverterService:
    """Get the converter service (stateless, no credentials needed)."""
    return ConverterService()


async def get_current_user_email(
    x_user_email: Optional[str] = Header(None),
) -> str:
    """Extract user email from request headers."""
    if not x_user_email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing user email. Please provide X-User-Email header.",
        )
    return x_user_email.lower()


async def get_current_user_role(
    email: str = Depends(get_current_user_email),
    db: AsyncSession = Depends(get_db),
) -> tuple[str, UserRoleType]:
    """Get the role for the current user."""
    # Check if user is in admin whitelist
    if email in settings.admin_emails_list:
        return email, UserRoleType.ADMIN

    # Check database for role assignment
    result = await db.execute(select(UserRole).where(UserRole.email == email))
    user_role = result.scalar_one_or_none()

    if user_role:
        return email, user_role.role

    # Default to viewer role
    return email, UserRoleType.VIEWER


async def get_optional_user_email(
    x_user_email: Optional[str] = Header(None),
) -> Optional[str]:
    """Extract user email from request headers (optional)."""
    return x_user_email.lower() if x_user_email else None


def require_role(min_role: UserRoleType):
    """Dependency factory that requires a minimum role level."""
    role_hierarchy = {
        UserRoleType.VIEWER: 0,
        UserRoleType.ANALYST: 1,
        UserRoleType.ADMIN: 2,
    }

    async def role_checker(
        user_role: tuple[str, UserRoleType] = Depends(get_current_user_role),
    ) -> tuple[str, UserRoleType]:
        email, role = user_role
        if role_hierarchy[role] < role_hierarchy[min_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {min_role.value}",
            )
        return user_role

    return role_checker


PantherServiceDep = Annotated[PantherService, Depends(get_panther_service)]
ConverterServiceDep = Annotated[ConverterService, Depends(get_converter_service)]
CurrentUserDep = Annotated[tuple[str, UserRoleType], Depends(get_current_user_role)]
OptionalUserEmailDep = Annotated[Optional[str], Depends(get_optional_user_email)]
RequireAdminDep = Annotated[tuple[str, UserRoleType], Depends(require_role(UserRoleType.ADMIN))]
RequireAnalystDep = Annotated[tuple[str, UserRoleType], Depends(require_role(UserRoleType.ANALYST))]
