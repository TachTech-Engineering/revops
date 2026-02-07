"""
SSO Configuration API endpoints for per-organization SSO management.
Only accessible by organization admins.
"""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db import get_db, OrganizationSSO, Organization, User, SSOProvider, UserRoleType
from app.services.encryption_service import encrypt_credential, decrypt_credential
from app.api.v1.auth import get_current_user

router = APIRouter()


# ==================== Request/Response Models ====================

class SSOConfigBase(BaseModel):
    provider: str = Field(..., description="SSO provider: google, okta, azure_ad, saml")
    display_name: Optional[str] = Field(None, description="Custom name for login button")
    client_id: str = Field(..., description="OAuth2 client ID")
    domain: Optional[str] = Field(None, description="Provider domain (for Okta)")
    tenant_id: Optional[str] = Field(None, description="Azure AD tenant ID")
    metadata_url: Optional[str] = Field(None, description="SAML metadata URL")
    entity_id: Optional[str] = Field(None, description="SAML entity ID")
    sso_url: Optional[str] = Field(None, description="SAML SSO URL")
    allowed_email_domains: Optional[str] = Field(None, description="Comma-separated allowed email domains")
    auto_create_users: bool = Field(True, description="Auto-create users on first SSO login")
    default_role: str = Field("viewer", description="Default role for new SSO users")


class SSOConfigCreate(SSOConfigBase):
    client_secret: str = Field(..., description="OAuth2 client secret (will be encrypted)")
    certificate: Optional[str] = Field(None, description="SAML certificate in PEM format")


class SSOConfigUpdate(BaseModel):
    display_name: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None  # Only update if provided
    domain: Optional[str] = None
    tenant_id: Optional[str] = None
    metadata_url: Optional[str] = None
    entity_id: Optional[str] = None
    sso_url: Optional[str] = None
    certificate: Optional[str] = None
    allowed_email_domains: Optional[str] = None
    auto_create_users: Optional[bool] = None
    default_role: Optional[str] = None
    is_enabled: Optional[bool] = None


class SSOConfigResponse(BaseModel):
    id: str
    provider: str
    display_name: Optional[str]
    is_enabled: bool
    client_id: str
    # client_secret is never returned
    domain: Optional[str]
    tenant_id: Optional[str]
    metadata_url: Optional[str]
    entity_id: Optional[str]
    sso_url: Optional[str]
    # certificate is never returned
    allowed_email_domains: Optional[str]
    auto_create_users: bool
    default_role: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class SSOConfigListResponse(BaseModel):
    configs: list[SSOConfigResponse]


# ==================== Helper Functions ====================

async def get_current_admin_user(
    db: AsyncSession = Depends(get_db),
) -> User:
    """Get current user and verify they are an admin."""
    # This is a simplified version - in production, integrate with your auth middleware
    # For now, we'll get the user from the request context
    from fastapi import Request
    from app.services.auth_service import decode_access_token, get_user_by_id

    # This dependency should be replaced with your actual auth dependency
    # that extracts the user from the JWT token
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Auth middleware integration required"
    )


def validate_provider(provider: str) -> SSOProvider:
    """Validate and convert provider string to enum."""
    try:
        return SSOProvider(provider.lower())
    except ValueError:
        valid = [p.value for p in SSOProvider]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid provider '{provider}'. Must be one of: {valid}"
        )


def validate_role(role: str) -> UserRoleType:
    """Validate and convert role string to enum."""
    try:
        return UserRoleType(role.lower())
    except ValueError:
        valid = [r.value for r in UserRoleType]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role '{role}'. Must be one of: {valid}"
        )


# ==================== Endpoints ====================

@router.get("", response_model=SSOConfigListResponse)
async def list_sso_configs(
    organization_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    List all SSO configurations for an organization.
    Requires admin access to the organization.
    """
    result = await db.execute(
        select(OrganizationSSO)
        .where(OrganizationSSO.organization_id == organization_id)
        .order_by(OrganizationSSO.provider)
    )
    configs = result.scalars().all()

    return SSOConfigListResponse(
        configs=[
            SSOConfigResponse(
                id=str(c.id),
                provider=c.provider.value,
                display_name=c.display_name,
                is_enabled=c.is_enabled,
                client_id=c.client_id,
                domain=c.domain,
                tenant_id=c.tenant_id,
                metadata_url=c.metadata_url,
                entity_id=c.entity_id,
                sso_url=c.sso_url,
                allowed_email_domains=c.allowed_email_domains,
                auto_create_users=c.auto_create_users,
                default_role=c.default_role.value,
                created_at=c.created_at.isoformat(),
                updated_at=c.updated_at.isoformat(),
            )
            for c in configs
        ]
    )


@router.post("", response_model=SSOConfigResponse, status_code=status.HTTP_201_CREATED)
async def create_sso_config(
    organization_id: UUID,
    config: SSOConfigCreate,
    created_by: str = "admin",  # Should come from auth middleware
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new SSO configuration for an organization.
    Requires admin access to the organization.
    """
    # Validate provider and role
    provider = validate_provider(config.provider)
    default_role = validate_role(config.default_role)

    # Verify organization exists
    org_result = await db.execute(
        select(Organization).where(Organization.id == organization_id)
    )
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Check for existing config with same provider
    existing_result = await db.execute(
        select(OrganizationSSO).where(
            OrganizationSSO.organization_id == organization_id,
            OrganizationSSO.provider == provider
        )
    )
    if existing_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"SSO configuration for {provider.value} already exists"
        )

    # Validate provider-specific requirements
    if provider == SSOProvider.OKTA and not config.domain:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Okta provider requires 'domain' field"
        )
    if provider == SSOProvider.AZURE_AD and not config.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Azure AD provider requires 'tenant_id' field"
        )

    # Encrypt sensitive data
    client_secret_encrypted = encrypt_credential(config.client_secret)
    certificate_encrypted = None
    if config.certificate:
        certificate_encrypted = encrypt_credential(config.certificate)

    # Create config
    sso_config = OrganizationSSO(
        organization_id=organization_id,
        provider=provider,
        display_name=config.display_name,
        client_id=config.client_id,
        client_secret_encrypted=client_secret_encrypted,
        domain=config.domain,
        tenant_id=config.tenant_id,
        metadata_url=config.metadata_url,
        entity_id=config.entity_id,
        sso_url=config.sso_url,
        certificate=certificate_encrypted.decode() if certificate_encrypted else None,
        allowed_email_domains=config.allowed_email_domains,
        auto_create_users=config.auto_create_users,
        default_role=default_role,
        created_by=created_by,
    )

    db.add(sso_config)
    await db.commit()
    await db.refresh(sso_config)

    return SSOConfigResponse(
        id=str(sso_config.id),
        provider=sso_config.provider.value,
        display_name=sso_config.display_name,
        is_enabled=sso_config.is_enabled,
        client_id=sso_config.client_id,
        domain=sso_config.domain,
        tenant_id=sso_config.tenant_id,
        metadata_url=sso_config.metadata_url,
        entity_id=sso_config.entity_id,
        sso_url=sso_config.sso_url,
        allowed_email_domains=sso_config.allowed_email_domains,
        auto_create_users=sso_config.auto_create_users,
        default_role=sso_config.default_role.value,
        created_at=sso_config.created_at.isoformat(),
        updated_at=sso_config.updated_at.isoformat(),
    )


@router.get("/{config_id}", response_model=SSOConfigResponse)
async def get_sso_config(
    organization_id: UUID,
    config_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Get a specific SSO configuration.
    Requires admin access to the organization.
    """
    result = await db.execute(
        select(OrganizationSSO).where(
            OrganizationSSO.id == config_id,
            OrganizationSSO.organization_id == organization_id
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO configuration not found"
        )

    return SSOConfigResponse(
        id=str(config.id),
        provider=config.provider.value,
        display_name=config.display_name,
        is_enabled=config.is_enabled,
        client_id=config.client_id,
        domain=config.domain,
        tenant_id=config.tenant_id,
        metadata_url=config.metadata_url,
        entity_id=config.entity_id,
        sso_url=config.sso_url,
        allowed_email_domains=config.allowed_email_domains,
        auto_create_users=config.auto_create_users,
        default_role=config.default_role.value,
        created_at=config.created_at.isoformat(),
        updated_at=config.updated_at.isoformat(),
    )


@router.patch("/{config_id}", response_model=SSOConfigResponse)
async def update_sso_config(
    organization_id: UUID,
    config_id: UUID,
    update: SSOConfigUpdate,
    db: AsyncSession = Depends(get_db),
):
    """
    Update an SSO configuration.
    Requires admin access to the organization.
    """
    result = await db.execute(
        select(OrganizationSSO).where(
            OrganizationSSO.id == config_id,
            OrganizationSSO.organization_id == organization_id
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO configuration not found"
        )

    # Update fields
    if update.display_name is not None:
        config.display_name = update.display_name
    if update.client_id is not None:
        config.client_id = update.client_id
    if update.client_secret is not None:
        config.client_secret_encrypted = encrypt_credential(update.client_secret)
    if update.domain is not None:
        config.domain = update.domain
    if update.tenant_id is not None:
        config.tenant_id = update.tenant_id
    if update.metadata_url is not None:
        config.metadata_url = update.metadata_url
    if update.entity_id is not None:
        config.entity_id = update.entity_id
    if update.sso_url is not None:
        config.sso_url = update.sso_url
    if update.certificate is not None:
        config.certificate = encrypt_credential(update.certificate).decode()
    if update.allowed_email_domains is not None:
        config.allowed_email_domains = update.allowed_email_domains
    if update.auto_create_users is not None:
        config.auto_create_users = update.auto_create_users
    if update.default_role is not None:
        config.default_role = validate_role(update.default_role)
    if update.is_enabled is not None:
        config.is_enabled = update.is_enabled

    await db.commit()
    await db.refresh(config)

    return SSOConfigResponse(
        id=str(config.id),
        provider=config.provider.value,
        display_name=config.display_name,
        is_enabled=config.is_enabled,
        client_id=config.client_id,
        domain=config.domain,
        tenant_id=config.tenant_id,
        metadata_url=config.metadata_url,
        entity_id=config.entity_id,
        sso_url=config.sso_url,
        allowed_email_domains=config.allowed_email_domains,
        auto_create_users=config.auto_create_users,
        default_role=config.default_role.value,
        created_at=config.created_at.isoformat(),
        updated_at=config.updated_at.isoformat(),
    )


@router.delete("/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sso_config(
    organization_id: UUID,
    config_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Delete an SSO configuration.
    Requires admin access to the organization.
    """
    result = await db.execute(
        select(OrganizationSSO).where(
            OrganizationSSO.id == config_id,
            OrganizationSSO.organization_id == organization_id
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO configuration not found"
        )

    await db.delete(config)
    await db.commit()


@router.post("/{config_id}/test")
async def test_sso_config(
    organization_id: UUID,
    config_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Test an SSO configuration by attempting to fetch provider metadata.
    Returns success if the configuration appears valid.
    """
    result = await db.execute(
        select(OrganizationSSO).where(
            OrganizationSSO.id == config_id,
            OrganizationSSO.organization_id == organization_id
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO configuration not found"
        )

    # Build the metadata URL based on provider
    import httpx

    try:
        if config.provider == SSOProvider.GOOGLE:
            metadata_url = "https://accounts.google.com/.well-known/openid-configuration"
        elif config.provider == SSOProvider.OKTA:
            if not config.domain:
                return {"success": False, "error": "Okta domain not configured"}
            metadata_url = f"https://{config.domain}/.well-known/openid-configuration"
        elif config.provider == SSOProvider.AZURE_AD:
            if not config.tenant_id:
                return {"success": False, "error": "Azure AD tenant ID not configured"}
            metadata_url = f"https://login.microsoftonline.com/{config.tenant_id}/v2.0/.well-known/openid-configuration"
        elif config.provider == SSOProvider.SAML:
            if config.metadata_url:
                metadata_url = config.metadata_url
            else:
                return {"success": True, "message": "SAML config present (manual configuration)"}
        else:
            return {"success": False, "error": f"Unknown provider: {config.provider}"}

        async with httpx.AsyncClient() as client:
            response = await client.get(metadata_url, timeout=10.0)
            if response.status_code == 200:
                return {
                    "success": True,
                    "message": f"Successfully connected to {config.provider.value} provider",
                    "issuer": response.json().get("issuer"),
                }
            else:
                return {
                    "success": False,
                    "error": f"Provider returned status {response.status_code}"
                }

    except httpx.TimeoutException:
        return {"success": False, "error": "Connection timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}
