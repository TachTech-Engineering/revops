"""
Authentication API endpoints.
"""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db, UserRoleType
from app.services.auth_service import (
    AuthError,
    authenticate_user,
    create_user,
    create_organization,
    create_refresh_token,
    store_refresh_token,
    validate_refresh_token,
    revoke_refresh_token,
    decode_access_token,
    get_user_by_id,
    generate_token_response,
)

router = APIRouter()
security = HTTPBearer(auto_error=False)


# Request/Response models
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None
    organization_name: Optional[str] = None
    organization_slug: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int


class UserResponse(BaseModel):
    id: str
    email: str
    name: Optional[str]
    role: str
    is_active: bool
    organization_id: Optional[str]
    organization_name: Optional[str]

    class Config:
        from_attributes = True


class MessageResponse(BaseModel):
    message: str


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new user account.

    Optionally creates a new organization if organization_name and organization_slug are provided.
    """
    try:
        organization_id = None
        user_role = None

        # Create organization if details provided
        if request.organization_name and request.organization_slug:
            org = await create_organization(
                db=db,
                name=request.organization_name,
                slug=request.organization_slug,
            )
            organization_id = org.id
            # Organization creator becomes admin
            user_role = UserRoleType.ADMIN

        # Create user
        user = await create_user(
            db=db,
            email=request.email,
            password=request.password,
            name=request.name,
            organization_id=organization_id,
            role=user_role,
        )

        # Generate tokens
        refresh_token = create_refresh_token()
        await store_refresh_token(db, user.id, refresh_token)

        return generate_token_response(user, refresh_token)

    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate a user and return access and refresh tokens.
    """
    user = await authenticate_user(db, request.email, request.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate tokens
    refresh_token = create_refresh_token()
    await store_refresh_token(db, user.id, refresh_token)

    return generate_token_response(user, refresh_token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_tokens(
    request: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Refresh access token using a valid refresh token.
    """
    user = await validate_refresh_token(db, request.refresh_token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Revoke old refresh token and create new one
    await revoke_refresh_token(db, request.refresh_token)
    new_refresh_token = create_refresh_token()
    await store_refresh_token(db, user.id, new_refresh_token)

    return generate_token_response(user, new_refresh_token)


@router.post("/logout", response_model=MessageResponse)
async def logout(
    request: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Logout by revoking the refresh token.
    """
    await revoke_refresh_token(db, request.refresh_token)
    return MessageResponse(message="Successfully logged out")


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
):
    """
    Get the current authenticated user's information.
    """
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

    return UserResponse(
        id=str(user.id),
        email=user.email,
        name=user.name,
        role=user.role.value,
        is_active=user.is_active,
        organization_id=str(user.organization_id) if user.organization_id else None,
        organization_name=user.organization.name if user.organization else None,
    )
