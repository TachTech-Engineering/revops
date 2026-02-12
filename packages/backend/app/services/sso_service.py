"""
SSO authentication service for per-organization OAuth2/OIDC.
Supports Google, Okta, Azure AD, and generic SAML.
"""
from datetime import datetime
from typing import Optional
from uuid import UUID

from typing import Any
from authlib.integrations.starlette_client import OAuth
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.db import User, Organization, OrganizationSSO, SSOProvider, UserRoleType
from app.services.encryption_service import decrypt_credential

# Cache for OAuth clients (keyed by org_id + provider)
_oauth_client_cache: dict[str, Any] = {}


def _get_oauth_client(sso_config: OrganizationSSO) -> Any:
    """
    Get or create an OAuth client for the given SSO configuration.
    Clients are cached to avoid recreating them on every request.
    """
    cache_key = f"{sso_config.organization_id}_{sso_config.provider.value}"

    # Check cache (invalidate if config was updated)
    if cache_key in _oauth_client_cache:
        # For simplicity, we're not tracking config updates in cache
        # In production, you might want to invalidate on config update
        return _oauth_client_cache[cache_key]

    # Create new OAuth instance and register client
    oauth = OAuth()

    # Decrypt client secret
    client_secret = decrypt_credential(sso_config.client_secret_encrypted)

    # Build provider-specific configuration
    if sso_config.provider == SSOProvider.GOOGLE:
        oauth.register(
            name="sso",
            client_id=sso_config.client_id,
            client_secret=client_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    elif sso_config.provider == SSOProvider.OKTA:
        if not sso_config.domain:
            raise ValueError("Okta SSO requires domain configuration")
        oauth.register(
            name="sso",
            client_id=sso_config.client_id,
            client_secret=client_secret,
            server_metadata_url=f"https://{sso_config.domain}/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    elif sso_config.provider == SSOProvider.AZURE_AD:
        if not sso_config.tenant_id:
            raise ValueError("Azure AD SSO requires tenant_id configuration")
        oauth.register(
            name="sso",
            client_id=sso_config.client_id,
            client_secret=client_secret,
            server_metadata_url=f"https://login.microsoftonline.com/{sso_config.tenant_id}/v2.0/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    elif sso_config.provider == SSOProvider.SAML:
        # SAML requires different handling - for now, we'll use OIDC if available
        raise NotImplementedError("SAML support requires additional configuration")

    else:
        raise ValueError(f"Unsupported SSO provider: {sso_config.provider}")

    client = oauth.create_client("sso")
    _oauth_client_cache[cache_key] = client
    return client


def invalidate_oauth_cache(organization_id: UUID, provider: Optional[SSOProvider] = None):
    """
    Invalidate cached OAuth clients for an organization.
    Call this when SSO configuration is updated.
    """
    if provider:
        cache_key = f"{organization_id}_{provider.value}"
        _oauth_client_cache.pop(cache_key, None)
    else:
        # Invalidate all providers for this org
        keys_to_remove = [k for k in _oauth_client_cache if k.startswith(str(organization_id))]
        for key in keys_to_remove:
            _oauth_client_cache.pop(key, None)


async def get_sso_config_by_id(
    db: AsyncSession,
    config_id: UUID,
) -> Optional[OrganizationSSO]:
    """Get SSO configuration by ID."""
    result = await db.execute(
        select(OrganizationSSO)
        .options(selectinload(OrganizationSSO.organization))
        .where(OrganizationSSO.id == config_id, OrganizationSSO.is_enabled == True)
    )
    return result.scalar_one_or_none()


async def get_org_sso_configs(
    db: AsyncSession,
    organization_id: UUID,
) -> list[OrganizationSSO]:
    """Get all enabled SSO configurations for an organization."""
    result = await db.execute(
        select(OrganizationSSO)
        .where(
            OrganizationSSO.organization_id == organization_id,
            OrganizationSSO.is_enabled == True
        )
        .order_by(OrganizationSSO.provider)
    )
    return list(result.scalars().all())


async def org_has_sso_enabled(
    db: AsyncSession,
    organization_id: UUID,
) -> bool:
    """Check if an organization has any enabled SSO configuration."""
    result = await db.execute(
        select(OrganizationSSO.id)
        .where(
            OrganizationSSO.organization_id == organization_id,
            OrganizationSSO.is_enabled == True
        )
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


async def get_org_sso_provider_names(
    db: AsyncSession,
    organization_id: UUID,
) -> list[str]:
    """Get list of enabled SSO provider names for an organization."""
    result = await db.execute(
        select(OrganizationSSO.provider)
        .where(
            OrganizationSSO.organization_id == organization_id,
            OrganizationSSO.is_enabled == True
        )
    )
    return [row[0].value.title() for row in result.all()]


async def get_org_by_slug(
    db: AsyncSession,
    slug: str,
) -> Optional[Organization]:
    """Get organization by slug."""
    result = await db.execute(
        select(Organization).where(Organization.slug == slug.lower())
    )
    return result.scalar_one_or_none()


async def get_org_by_email_domain(
    db: AsyncSession,
    email: str,
) -> Optional[tuple[Organization, OrganizationSSO]]:
    """
    Find organization and SSO config by email domain.
    Used for email-based organization detection during login.
    """
    if "@" not in email:
        return None

    domain = email.split("@")[1].lower()

    # Find SSO configs that allow this email domain
    result = await db.execute(
        select(OrganizationSSO)
        .options(selectinload(OrganizationSSO.organization))
        .where(OrganizationSSO.is_enabled == True)
    )
    configs = result.scalars().all()

    for config in configs:
        if config.allowed_email_domains:
            allowed_domains = [d.strip().lower() for d in config.allowed_email_domains.split(",")]
            if domain in allowed_domains:
                return (config.organization, config)

    return None


async def get_available_providers_for_org(
    db: AsyncSession,
    organization_id: UUID,
) -> list[dict]:
    """Get list of available SSO providers for an organization."""
    configs = await get_org_sso_configs(db, organization_id)

    providers = []
    for config in configs:
        provider_info = {
            "id": str(config.id),
            "provider": config.provider.value,
            "name": config.display_name or _get_default_provider_name(config.provider),
            "icon": config.provider.value,
        }
        providers.append(provider_info)

    return providers


def _get_default_provider_name(provider: SSOProvider) -> str:
    """Get default display name for a provider."""
    names = {
        SSOProvider.GOOGLE: "Google",
        SSOProvider.OKTA: "Okta",
        SSOProvider.AZURE_AD: "Microsoft",
        SSOProvider.SAML: "SSO",
    }
    return names.get(provider, provider.value.title())


async def get_or_create_sso_user(
    db: AsyncSession,
    sso_config: OrganizationSSO,
    sso_id: str,
    email: str,
    name: Optional[str] = None,
) -> User:
    """
    Get an existing user by SSO ID or create a new one.
    Uses the organization's SSO configuration for settings.
    """
    provider = sso_config.provider
    organization_id = sso_config.organization_id

    # First, try to find user by SSO ID within this organization
    result = await db.execute(
        select(User)
        .options(selectinload(User.organization))
        .where(
            User.sso_provider == provider,
            User.sso_id == sso_id,
            User.organization_id == organization_id
        )
    )
    user = result.scalar_one_or_none()

    if user:
        # Update last login
        user.last_login_at = datetime.utcnow()
        if name and not user.name:
            user.name = name
        await db.commit()
        await db.refresh(user)
        return user

    # Try to find user by email within this organization
    result = await db.execute(
        select(User)
        .options(selectinload(User.organization))
        .where(
            User.email == email.lower(),
            User.organization_id == organization_id
        )
    )
    user = result.scalar_one_or_none()

    if user:
        # Link existing account to SSO
        user.sso_provider = provider
        user.sso_id = sso_id
        user.last_login_at = datetime.utcnow()
        if name and not user.name:
            user.name = name
        await db.commit()
        await db.refresh(user)
        return user

    # Also check for user with same email but no organization (migrate them)
    result = await db.execute(
        select(User)
        .options(selectinload(User.organization))
        .where(
            User.email == email.lower(),
            User.organization_id.is_(None)
        )
    )
    user = result.scalar_one_or_none()

    if user:
        # Migrate user to this organization and link SSO
        user.organization_id = organization_id
        user.sso_provider = provider
        user.sso_id = sso_id
        user.last_login_at = datetime.utcnow()
        if name and not user.name:
            user.name = name
        await db.commit()
        await db.refresh(user)
        return user

    # Create new user if auto-create is enabled
    if not sso_config.auto_create_users:
        raise ValueError("User does not exist and auto-creation is disabled for this organization")

    # Verify email domain if restrictions are configured
    if sso_config.allowed_email_domains:
        email_domain = email.split("@")[1].lower() if "@" in email else ""
        allowed_domains = [d.strip().lower() for d in sso_config.allowed_email_domains.split(",")]
        if email_domain not in allowed_domains:
            raise ValueError(f"Email domain '{email_domain}' is not allowed for this organization")

    user = User(
        email=email.lower(),
        hashed_password=None,  # SSO users don't have passwords
        name=name,
        sso_provider=provider,
        sso_id=sso_id,
        organization_id=organization_id,
        role=sso_config.default_role,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user, ["organization"])

    return user


async def initiate_sso_flow(
    request,
    db: AsyncSession,
    config_id: UUID,
    callback_url: str,
) -> str:
    """
    Initiate SSO OAuth flow for a specific configuration.
    Returns the authorization URL to redirect to.
    """
    sso_config = await get_sso_config_by_id(db, config_id)
    if not sso_config:
        raise ValueError("SSO configuration not found or disabled")

    client = _get_oauth_client(sso_config)
    return await client.authorize_redirect(request, callback_url)


async def complete_sso_flow(
    request,
    db: AsyncSession,
    config_id: UUID,
) -> tuple[User, dict]:
    """
    Complete SSO OAuth flow and return the authenticated user.
    Returns (user, token_data) tuple.
    """
    sso_config = await get_sso_config_by_id(db, config_id)
    if not sso_config:
        raise ValueError("SSO configuration not found or disabled")

    client = _get_oauth_client(sso_config)

    # Exchange authorization code for tokens
    token = await client.authorize_access_token(request)

    # Get user info from the ID token or userinfo endpoint
    if "userinfo" in token:
        user_info = token["userinfo"]
    else:
        user_info = await client.userinfo(token=token)

    # Extract user details
    email = user_info.get("email")
    if not email:
        raise ValueError("Email not provided by SSO provider")

    # Get SSO ID (sub claim is the unique identifier)
    sso_id = user_info.get("sub")
    if not sso_id:
        raise ValueError("User ID not provided by SSO provider")

    # Get or create user
    name = user_info.get("name") or user_info.get("given_name", "")
    user = await get_or_create_sso_user(
        db=db,
        sso_config=sso_config,
        sso_id=sso_id,
        email=email,
        name=name,
    )

    return user, token


# ==================== Legacy support for global SSO config ====================
# These functions support the original environment-variable based SSO
# They can be removed once all tenants are migrated to per-org SSO

def get_global_providers() -> list[dict]:
    """Get globally configured SSO providers (from environment variables)."""
    providers = []

    if settings.google_client_id and settings.google_client_secret:
        providers.append({
            "id": "global_google",
            "provider": "google",
            "name": "Google",
            "icon": "google",
        })

    if settings.okta_domain and settings.okta_client_id and settings.okta_client_secret:
        providers.append({
            "id": "global_okta",
            "provider": "okta",
            "name": "Okta",
            "icon": "okta",
        })

    return providers


def is_global_provider_configured(provider: str) -> bool:
    """Check if a global SSO provider is configured."""
    if provider == "google":
        return bool(settings.google_client_id and settings.google_client_secret)
    elif provider == "okta":
        return bool(settings.okta_domain and settings.okta_client_id and settings.okta_client_secret)
    return False
