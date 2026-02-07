"""
Authentication API endpoints.
"""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db, UserRoleType, SSOProvider
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
    get_user_by_email,
    generate_token_response,
    create_password_reset_token,
    validate_password_reset_token,
    reset_user_password,
)
from app.services.sso_service import (
    get_global_providers,
    is_global_provider_configured,
    get_available_providers_for_org,
    get_sso_config_by_id,
    get_org_by_slug,
    get_org_by_email_domain,
    initiate_sso_flow,
    complete_sso_flow,
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


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class ForgotPasswordResponse(BaseModel):
    message: str
    # In production, don't return the token - send via email
    # This is for development/testing only
    reset_token: Optional[str] = None


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


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
async def forgot_password(
    request: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Request a password reset.

    In production, this would send an email with the reset link.
    For development, the token is returned in the response.
    """
    user = await get_user_by_email(db, request.email)

    # Always return success to prevent email enumeration
    if not user:
        return ForgotPasswordResponse(
            message="If an account with that email exists, a password reset link has been sent."
        )

    # Create reset token
    reset_token = await create_password_reset_token(db, user.id)

    # In production: send email with reset link
    # For dev: return token in response
    return ForgotPasswordResponse(
        message="If an account with that email exists, a password reset link has been sent.",
        reset_token=reset_token,  # Remove this in production!
    )


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
    request: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Reset password using a valid reset token.
    """
    if len(request.new_password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 6 characters",
        )

    success = await reset_user_password(db, request.token, request.new_password)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    return MessageResponse(message="Password has been reset successfully")


# ==================== SSO Endpoints ====================
# Supports per-organization SSO configuration

class SSOProviderResponse(BaseModel):
    id: str
    provider: Optional[str] = None
    name: str
    icon: str


class SSOProvidersResponse(BaseModel):
    providers: list[SSOProviderResponse]


@router.get("/sso/providers", response_model=SSOProvidersResponse)
async def list_sso_providers(
    organization_id: Optional[UUID] = None,
    organization_slug: Optional[str] = None,
    email: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    List available SSO providers.

    Can be filtered by:
    - organization_id: Get providers for a specific organization
    - organization_slug: Get providers by org slug (e.g., "acme-corp")
    - email: Auto-detect organization by email domain

    If no filter is provided, returns globally configured providers (if any).
    """
    org_id = None

    # Determine organization
    if organization_id:
        org_id = organization_id
    elif organization_slug:
        org = await get_org_by_slug(db, organization_slug)
        if org:
            org_id = org.id
    elif email:
        result = await get_org_by_email_domain(db, email)
        if result:
            org, _ = result
            org_id = org.id

    # Get per-org providers
    if org_id:
        providers = await get_available_providers_for_org(db, org_id)
        return SSOProvidersResponse(providers=[
            SSOProviderResponse(
                id=p["id"],
                provider=p["provider"],
                name=p["name"],
                icon=p["icon"],
            )
            for p in providers
        ])

    # Fall back to global providers
    global_providers = get_global_providers()
    return SSOProvidersResponse(providers=[
        SSOProviderResponse(
            id=p["id"],
            provider=p["provider"],
            name=p["name"],
            icon=p["icon"],
        )
        for p in global_providers
    ])


@router.get("/sso/{config_id}/authorize")
async def sso_authorize(
    config_id: str,
    request: Request,
    redirect_uri: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Initiate SSO OAuth2 authorization flow for a specific SSO configuration.

    The config_id is the UUID of the OrganizationSSO configuration.
    Redirects to the provider's authorization page.
    """
    # Store the config_id and redirect URI in session
    request.session["sso_config_id"] = config_id
    if redirect_uri:
        request.session["sso_redirect_uri"] = redirect_uri

    try:
        config_uuid = UUID(config_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid SSO configuration ID",
        )

    # Build callback URL
    callback_url = str(request.url_for("sso_callback", config_id=config_id))

    try:
        return await initiate_sso_flow(request, db, config_uuid, callback_url)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        import logging
        logging.error(f"SSO authorize error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate SSO flow",
        )


@router.get("/sso/{config_id}/callback")
async def sso_callback(
    config_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Handle SSO OAuth2 callback.

    Exchanges authorization code for tokens, creates/updates user, and redirects to frontend.
    """
    try:
        config_uuid = UUID(config_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid SSO configuration ID",
        )

    try:
        # Complete the SSO flow
        user, _ = await complete_sso_flow(request, db, config_uuid)

        # Generate tokens
        refresh_token = create_refresh_token()
        await store_refresh_token(db, user.id, refresh_token)

        token_response = generate_token_response(user, refresh_token)

        # Get frontend redirect URI from session or use default
        frontend_redirect = request.session.pop("sso_redirect_uri", "http://localhost:3000")
        request.session.pop("sso_config_id", None)

        # Redirect to frontend with tokens in URL fragment (for SPA)
        redirect_url = (
            f"{frontend_redirect}/auth/callback"
            f"#access_token={token_response['access_token']}"
            f"&refresh_token={token_response['refresh_token']}"
            f"&token_type={token_response['token_type']}"
            f"&expires_in={token_response['expires_in']}"
        )

        return RedirectResponse(url=redirect_url)

    except ValueError as e:
        # User creation disabled or validation error
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except Exception as e:
        import logging
        logging.error(f"SSO callback error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SSO authentication failed. Please try again.",
        )


@router.get("/sso/detect")
async def detect_sso_for_email(
    email: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Detect if SSO is available for an email address based on domain.

    Used by the frontend to auto-detect SSO options when a user enters their email.
    """
    result = await get_org_by_email_domain(db, email)

    if result:
        org, sso_config = result
        return {
            "sso_available": True,
            "organization_id": str(org.id),
            "organization_name": org.name,
            "provider": {
                "id": str(sso_config.id),
                "provider": sso_config.provider.value,
                "name": sso_config.display_name or sso_config.provider.value.title(),
                "icon": sso_config.provider.value,
            }
        }

    return {"sso_available": False}
