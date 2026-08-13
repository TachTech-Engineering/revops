"""
Authentication API endpoints.
"""

import logging
from urllib.parse import urlparse
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import SSOProvider, get_db
from app.services.auth_service import (
    AuthError,
    authenticate_user,
    create_password_reset_token,
    create_refresh_token,
    decode_access_token,
    generate_token_response,
    get_user_by_email,
    get_user_by_id,
    register_account,
    reset_user_password,
    revoke_refresh_token,
    rotate_refresh_token,
    store_refresh_token,
)
from app.services.sso_service import (
    complete_sso_flow,
    generate_sp_metadata,
    get_available_providers_for_org,
    get_global_providers,
    get_org_by_email_domain,
    get_org_by_slug,
    get_org_sso_provider_names,
    get_sso_config_by_id,
    # SAML-specific functions
    initiate_saml_flow,
    initiate_sso_flow,
    org_has_sso_enabled,
    prepare_saml_request,
    process_saml_logout,
    process_saml_response,
)

logger = logging.getLogger(__name__)

router = APIRouter()
security = HTTPBearer(auto_error=False)


def _safe_frontend_redirect(candidate: str | None) -> str:
    """Return `candidate` only if it is an allowed frontend origin.

    SSO/SAML completion appends the freshly minted access and refresh tokens
    to this URL as a fragment. An unvalidated value therefore hands a
    victim's session to any attacker-chosen host, so anything not explicitly
    allowlisted falls back to the configured frontend origin.

    The allowlist is CORS_ORIGINS (the origins already trusted to drive this
    API) plus PUBLIC_BASE_URL. Comparison is on scheme+host+port only.
    """
    allowed = {
        origin.strip().rstrip("/")
        for origin in settings.cors_origins_list
        if origin.strip() and origin.strip() != "*"
    }
    if settings.public_base_url:
        allowed.add(settings.public_base_url.rstrip("/"))

    default = next(iter(sorted(allowed)), "http://localhost:3000")

    if not candidate:
        return default
    try:
        parsed = urlparse(candidate)
    except ValueError:
        logger.warning("Rejected unparseable SSO redirect target")
        return default
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        logger.warning("Rejected non-absolute SSO redirect target: %r", parsed.scheme)
        return default
    origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    if origin not in allowed:
        logger.warning("Rejected SSO redirect to non-allowlisted origin: %s", origin)
        return default
    return origin


# Request/Response models
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str | None = None
    organization_name: str | None = None
    organization_slug: str | None = None


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
    name: str | None
    role: str
    is_active: bool
    organization_id: str | None
    organization_name: str | None

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
    reset_token: str | None = None


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new user account.

    Optionally creates a new organization if organization_name and organization_slug are provided.

    Organization and user are created in a single transaction: creating the org
    first and committing it meant a failing user insert (a duplicate email, say)
    left an empty organization behind and burnt its unique slug forever.
    """
    try:
        user = await register_account(
            db=db,
            email=request.email,
            password=request.password,
            name=request.name,
            organization_name=request.organization_name,
            organization_slug=request.organization_slug,
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

    If the user's organization has SSO enabled, password login is blocked
    and users must authenticate via SSO instead.

    The SSO check runs AFTER the password verifies. Doing it first meant an
    unauthenticated caller could tell a registered address in an SSO tenant
    (403 naming the IdP) from an unknown address (generic 401) -- a free
    account-enumeration oracle that also disclosed the organization's identity
    provider. Everything reachable without a correct password is now the same
    401; the provider hint survives for the user who actually proved they own
    the account.
    """
    user = await authenticate_user(db, request.email, request.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.organization_id and await org_has_sso_enabled(db, user.organization_id):
        providers = await get_org_sso_provider_names(db, user.organization_id)
        provider_list = ", ".join(providers) if providers else "SSO"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Password login is disabled for your organization. "
                f"Please sign in using {provider_list}."
            ),
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

    Rotation is a single compare-and-revoke inside auth_service (see
    ``rotate_refresh_token``); presenting an already-revoked token revokes the
    user's whole token family. Reuse and plain invalidity return the identical
    401 so a replaying attacker learns nothing.
    """
    try:
        user, new_refresh_token = await rotate_refresh_token(db, request.refresh_token)
    except AuthError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

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

    The reset token is NEVER returned in the response outside development:
    doing so lets any anonymous caller mint a reset token for an arbitrary
    email and take over the account. It is echoed only when
    settings.is_development is true (local/test), where no real accounts exist.
    """
    user = await get_user_by_email(db, request.email)

    # Always return success to prevent email enumeration
    if not user:
        return ForgotPasswordResponse(
            message="If an account with that email exists, a password reset link has been sent."
        )

    # Create reset token
    reset_token = await create_password_reset_token(db, user.id)

    # TODO: deliver the token by email. Until then it is only exposed in
    # development -- returning it in production is an account-takeover hole.
    if settings.is_development:
        return ForgotPasswordResponse(
            message="If an account with that email exists, a password reset link has been sent.",
            reset_token=reset_token,
        )

    logger.info("Password reset token issued for user %s", user.id)
    return ForgotPasswordResponse(
        message="If an account with that email exists, a password reset link has been sent."
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
    provider: str | None = None
    name: str
    icon: str


class SSOProvidersResponse(BaseModel):
    providers: list[SSOProviderResponse]


@router.get("/sso/providers", response_model=SSOProvidersResponse)
async def list_sso_providers(
    organization_id: UUID | None = None,
    organization_slug: str | None = None,
    email: str | None = None,
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
        return SSOProvidersResponse(
            providers=[
                SSOProviderResponse(
                    id=p["id"],
                    provider=p["provider"],
                    name=p["name"],
                    icon=p["icon"],
                )
                for p in providers
            ]
        )

    # Fall back to global providers
    global_providers = get_global_providers()
    return SSOProvidersResponse(
        providers=[
            SSOProviderResponse(
                id=p["id"],
                provider=p["provider"],
                name=p["name"],
                icon=p["icon"],
            )
            for p in global_providers
        ]
    )


@router.get("/sso/{config_id}/authorize")
async def sso_authorize(
    config_id: str,
    request: Request,
    redirect_uri: str | None = None,
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

    # Build callback URL - use public base URL if configured (for behind proxies/load balancers)
    if settings.public_base_url:
        callback_url = (
            f"{settings.public_base_url.rstrip('/')}/api/v1/auth/sso/{config_id}/callback"
        )
    else:
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

        # Get frontend redirect URI from session, allowlisted -- the tokens
        # are appended to this URL, so an arbitrary value exfiltrates them.
        frontend_redirect = _safe_frontend_redirect(request.session.pop("sso_redirect_uri", None))
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
            },
        }

    return {"sso_available": False}


# ==================== SAML Endpoints ====================
# Supports SP-initiated SAML 2.0 SSO flow


@router.get("/saml/{config_id}/metadata")
async def saml_metadata(
    config_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Get Service Provider (SP) metadata XML for SAML configuration.

    This metadata should be provided to the Identity Provider (IdP) when
    configuring the SAML integration. It contains the SP entity ID, ACS URL,
    and signing certificate.
    """
    try:
        config_uuid = UUID(config_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid SSO configuration ID",
        )

    sso_config = await get_sso_config_by_id(db, config_uuid)
    if not sso_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO configuration not found or disabled",
        )

    if sso_config.provider != SSOProvider.SAML:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Configuration is not a SAML provider",
        )

    try:
        request_data = prepare_saml_request(request)
        metadata_xml = generate_sp_metadata(sso_config, request_data)

        from fastapi.responses import Response

        return Response(
            content=metadata_xml,
            media_type="application/xml",
            headers={"Content-Disposition": f'attachment; filename="sp_metadata_{config_id}.xml"'},
        )

    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="SAML support requires python3-saml library",
        )
    except Exception as e:
        import logging

        logging.error(f"SAML metadata generation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate SP metadata",
        )


@router.get("/saml/{config_id}/login")
async def saml_login(
    config_id: str,
    request: Request,
    return_to: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Initiate SAML SP-initiated login flow.

    Redirects the user to the Identity Provider's SSO URL with a SAML AuthnRequest.

    Args:
        config_id: UUID of the SAML SSO configuration
        return_to: URL to redirect to after successful authentication
    """
    try:
        config_uuid = UUID(config_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid SSO configuration ID",
        )

    # Store return URL in session
    if return_to:
        request.session["saml_return_to"] = return_to
    request.session["saml_config_id"] = config_id

    try:
        redirect_url = await initiate_saml_flow(request, db, config_uuid, return_to)
        return RedirectResponse(url=redirect_url)

    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="SAML support requires python3-saml library",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        import logging

        logging.error(f"SAML login initiation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate SAML login",
        )


@router.post("/saml/{config_id}/acs")
async def saml_acs(
    config_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    SAML Assertion Consumer Service (ACS) endpoint.

    Receives and processes the SAML Response from the Identity Provider.
    Creates/updates user and redirects to the frontend with authentication tokens.
    """
    try:
        config_uuid = UUID(config_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid SSO configuration ID",
        )

    try:
        # Process SAML response
        user, saml_data = await process_saml_response(request, db, config_uuid)

        # Generate authentication tokens
        refresh_token = create_refresh_token()
        await store_refresh_token(db, user.id, refresh_token)

        token_response = generate_token_response(user, refresh_token)

        # Get return URL from session or form data
        return_to = request.session.pop("saml_return_to", None)
        request.session.pop("saml_config_id", None)

        # Check RelayState for return URL. RelayState is attacker-controllable
        # (it round-trips through the IdP), and the tokens are appended to this
        # URL -- so it must be allowlisted, not merely "starts with http".
        form = await request.form()
        relay_state = form.get("RelayState")
        return_to = _safe_frontend_redirect(relay_state or return_to)

        # Redirect to frontend with tokens in URL fragment (for SPA)
        redirect_url = (
            f"{return_to}/auth/callback"
            f"#access_token={token_response['access_token']}"
            f"&refresh_token={token_response['refresh_token']}"
            f"&token_type={token_response['token_type']}"
            f"&expires_in={token_response['expires_in']}"
        )

        return RedirectResponse(url=redirect_url, status_code=303)

    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="SAML support requires python3-saml library",
        )
    except ValueError as e:
        import logging

        logging.error(f"SAML ACS validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except Exception as e:
        import logging

        logging.error(f"SAML ACS error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SAML authentication failed. Please try again.",
        )


@router.get("/saml/{config_id}/sls")
@router.post("/saml/{config_id}/sls")
async def saml_sls(
    config_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    SAML Single Logout Service (SLS) endpoint.

    Handles logout requests/responses from the Identity Provider.
    Supports both GET and POST bindings.
    """
    try:
        config_uuid = UUID(config_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid SSO configuration ID",
        )

    try:
        redirect_url = await process_saml_logout(request, db, config_uuid)

        if redirect_url:
            return RedirectResponse(url=redirect_url)

        # Default redirect after logout
        return RedirectResponse(url="http://localhost:3000/login")

    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="SAML support requires python3-saml library",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        import logging

        logging.error(f"SAML SLS error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SAML logout failed",
        )
