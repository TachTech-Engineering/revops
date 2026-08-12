from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import User, UserRoleType, get_db
from app.services.auth_service import decode_access_token, get_user_by_id
from app.services.converter_service import ConverterService
from app.services.panther_service import PantherService

# JWT Bearer token security
security = HTTPBearer(auto_error=False)


async def get_panther_credentials(
    x_panther_host: str | None = Header(None),
    x_panther_token: str | None = Header(None),
) -> tuple[str, str]:
    """Extract Panther credentials from request headers."""
    if not x_panther_host or not x_panther_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Missing Panther credentials. "
                "Please provide X-Panther-Host and X-Panther-Token headers."
            ),
        )
    return x_panther_host, x_panther_token


async def get_panther_service(
    credentials: tuple[str, str] = Depends(get_panther_credentials),
) -> PantherService:
    """Create a Panther service with credentials from headers."""
    host, token = credentials
    return PantherService(api_host=host, api_token=token)


async def get_optional_panther_service(
    x_panther_host: str | None = Header(None),
    x_panther_token: str | None = Header(None),
) -> PantherService | None:
    """Create a Panther service if credentials are provided, otherwise return None."""
    if not x_panther_host or not x_panther_token:
        return None
    return PantherService(api_host=x_panther_host, api_token=x_panther_token)


def get_converter_service() -> ConverterService:
    """Get the converter service (stateless, no credentials needed)."""
    return ConverterService()


PantherServiceDep = Annotated[PantherService, Depends(get_panther_service)]
OptionalPantherServiceDep = Annotated[PantherService | None, Depends(get_optional_panther_service)]
ConverterServiceDep = Annotated[ConverterService, Depends(get_converter_service)]


# JWT-based authentication dependencies
async def get_current_user_jwt(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Get the current user from JWT token."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await get_user_by_id(db, UUID(user_id))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    return user


async def get_optional_user_jwt(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Get current user from JWT if provided, otherwise return None."""
    if not credentials:
        return None

    payload = decode_access_token(credentials.credentials)
    if not payload:
        return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    return await get_user_by_id(db, UUID(user_id))


async def get_user_from_token(db: AsyncSession, token: str) -> User | None:
    """
    Validate a raw JWT and return the active user, or None if invalid.

    Shared by transports that cannot use the HTTP Bearer dependency
    (e.g. WebSocket endpoints passing the token as a query parameter).
    """
    payload = decode_access_token(token)
    if not payload:
        return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    try:
        user = await get_user_by_id(db, UUID(user_id))
    except ValueError:
        return None

    if not user or not user.is_active:
        return None

    return user


def require_jwt_role(min_role: UserRoleType):
    """Dependency factory that requires JWT auth and a minimum role level."""
    role_hierarchy = {
        UserRoleType.VIEWER: 0,
        UserRoleType.ANALYST: 1,
        UserRoleType.ADMIN: 2,
    }

    async def role_checker(
        user: User = Depends(get_current_user_jwt),
    ) -> User:
        if role_hierarchy[user.role] < role_hierarchy[min_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {min_role.value}",
            )
        return user

    return role_checker


# JWT-based type aliases
CurrentUserJWTDep = Annotated[User, Depends(get_current_user_jwt)]
OptionalUserJWTDep = Annotated[User | None, Depends(get_optional_user_jwt)]
RequireAdminJWTDep = Annotated[User, Depends(require_jwt_role(UserRoleType.ADMIN))]
RequireAnalystJWTDep = Annotated[User, Depends(require_jwt_role(UserRoleType.ANALYST))]


# Organization-scoped authentication
async def get_current_user_with_org(
    user: User = Depends(get_current_user_jwt),
) -> User:
    """
    Get current user and verify they belong to an organization.
    Required for all tenant-scoped operations.
    """
    if not user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "User is not associated with an organization. "
                "Please contact your administrator."
            ),
        )
    return user


async def get_organization_id(
    user: User = Depends(get_current_user_with_org),
) -> UUID:
    """
    Get the current user's organization ID.
    Use this dependency in endpoints that need to filter by organization.
    """
    return user.organization_id


def require_org_role(min_role: UserRoleType):
    """
    Dependency factory that requires:
    1. JWT authentication
    2. User belongs to an organization
    3. User has at least the specified role
    """
    role_hierarchy = {
        UserRoleType.VIEWER: 0,
        UserRoleType.ANALYST: 1,
        UserRoleType.ADMIN: 2,
    }

    async def role_checker(
        user: User = Depends(get_current_user_with_org),
    ) -> User:
        if role_hierarchy[user.role] < role_hierarchy[min_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {min_role.value}",
            )
        return user

    return role_checker


# Organization-scoped type aliases (use these for tenant-scoped endpoints)
OrgUserDep = Annotated[User, Depends(get_current_user_with_org)]
OrgIdDep = Annotated[UUID, Depends(get_organization_id)]
OrgAdminDep = Annotated[User, Depends(require_org_role(UserRoleType.ADMIN))]
OrgAnalystDep = Annotated[User, Depends(require_org_role(UserRoleType.ANALYST))]
