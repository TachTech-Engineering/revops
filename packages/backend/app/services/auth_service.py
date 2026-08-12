"""
Authentication service for user management and JWT token handling.
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from uuid import UUID

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.db import Organization, RefreshToken, User, UserRoleType

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Token configuration
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes
REFRESH_TOKEN_EXPIRE_DAYS = 7  # Refresh tokens last 7 days


class AuthError(Exception):
    """Custom exception for authentication errors."""

    pass


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def hash_token(token: str) -> str:
    """Hash a refresh token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def create_refresh_token() -> str:
    """Create a cryptographically secure refresh token."""
    return secrets.token_urlsafe(32)


def decode_access_token(token: str) -> dict | None:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        if payload.get("type") != "access":
            return None
        return payload
    except JWTError:
        return None


async def authenticate_user(db: AsyncSession, email: str, password: str) -> User | None:
    """Authenticate a user by email and password."""
    result = await db.execute(
        select(User)
        .options(selectinload(User.organization))
        .where(and_(User.email == email.lower(), User.is_active.is_(True)))
    )
    user = result.scalar_one_or_none()

    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None

    # Update last login timestamp
    user.last_login_at = datetime.utcnow()
    await db.commit()

    return user


async def create_user(
    db: AsyncSession,
    email: str,
    password: str,
    name: str | None = None,
    organization_id: UUID | None = None,
    role: UserRoleType | None = None,
) -> User:
    """Create a new user."""

    # Check if email already exists
    result = await db.execute(select(User).where(User.email == email.lower()))
    existing = result.scalar_one_or_none()
    if existing:
        raise AuthError("Email already registered")

    user = User(
        email=email.lower(),
        hashed_password=hash_password(password),
        name=name,
        organization_id=organization_id,
        role=role or UserRoleType.VIEWER,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def create_organization(
    db: AsyncSession,
    name: str,
    slug: str,
) -> Organization:
    """Create a new organization."""
    # Check if slug already exists
    result = await db.execute(select(Organization).where(Organization.slug == slug.lower()))
    existing = result.scalar_one_or_none()
    if existing:
        raise AuthError("Organization slug already exists")

    org = Organization(
        name=name,
        slug=slug.lower(),
    )
    db.add(org)
    await db.commit()
    await db.refresh(org)

    return org


async def get_user_by_id(db: AsyncSession, user_id: UUID) -> User | None:
    """Get a user by their ID."""
    result = await db.execute(
        select(User).options(selectinload(User.organization)).where(User.id == user_id)
    )
    return result.scalar_one_or_none()


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    """Get a user by their email."""
    result = await db.execute(
        select(User).options(selectinload(User.organization)).where(User.email == email.lower())
    )
    return result.scalar_one_or_none()


async def store_refresh_token(db: AsyncSession, user_id: UUID, token: str) -> RefreshToken:
    """Store a refresh token for a user."""
    refresh_token = RefreshToken(
        user_id=user_id,
        token_hash=hash_token(token),
        expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(refresh_token)
    await db.commit()
    return refresh_token


async def validate_refresh_token(db: AsyncSession, token: str) -> User | None:
    """Validate a refresh token and return the associated user."""
    token_hash = hash_token(token)
    result = await db.execute(
        select(RefreshToken).where(
            and_(
                RefreshToken.token_hash == token_hash,
                RefreshToken.expires_at > datetime.utcnow(),
                RefreshToken.revoked_at.is_(None),
            )
        )
    )
    refresh_token = result.scalar_one_or_none()

    if not refresh_token:
        return None

    return await get_user_by_id(db, refresh_token.user_id)


async def revoke_refresh_token(db: AsyncSession, token: str) -> bool:
    """Revoke a refresh token."""
    token_hash = hash_token(token)
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    refresh_token = result.scalar_one_or_none()

    if not refresh_token:
        return False

    refresh_token.revoked_at = datetime.utcnow()
    await db.commit()
    return True


async def revoke_all_user_tokens(db: AsyncSession, user_id: UUID) -> int:
    """Revoke all refresh tokens for a user."""
    result = await db.execute(
        select(RefreshToken).where(
            and_(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked_at.is_(None),
            )
        )
    )
    tokens = result.scalars().all()

    count = 0
    for token in tokens:
        token.revoked_at = datetime.utcnow()
        count += 1

    await db.commit()
    return count


def generate_token_response(user: User, refresh_token: str) -> dict:
    """Generate a complete token response for a user."""
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "org_id": str(user.organization_id) if user.organization_id else None,
        }
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


# Password Reset Functions
PASSWORD_RESET_EXPIRE_HOURS = 24

# In-memory store for reset tokens (use Redis or DB in production)
_password_reset_tokens: dict[str, tuple[UUID, datetime]] = {}


async def create_password_reset_token(db: AsyncSession, user_id: UUID) -> str:
    """Create a password reset token for a user."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=PASSWORD_RESET_EXPIRE_HOURS)

    # Store token (in production, use database or Redis)
    _password_reset_tokens[token] = (user_id, expires_at)

    return token


async def validate_password_reset_token(token: str) -> UUID | None:
    """Validate a password reset token and return the user ID if valid."""
    if token not in _password_reset_tokens:
        return None

    user_id, expires_at = _password_reset_tokens[token]

    if datetime.utcnow() > expires_at:
        # Token expired, remove it
        del _password_reset_tokens[token]
        return None

    return user_id


async def reset_user_password(db: AsyncSession, token: str, new_password: str) -> bool:
    """Reset a user's password using a valid reset token."""
    user_id = await validate_password_reset_token(token)

    if not user_id:
        return False

    user = await get_user_by_id(db, user_id)
    if not user:
        return False

    # Update password
    user.hashed_password = hash_password(new_password)
    await db.commit()

    # Invalidate the token
    del _password_reset_tokens[token]

    # Optionally: revoke all refresh tokens for security
    await revoke_all_user_tokens(db, user_id)

    return True
