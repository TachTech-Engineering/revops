"""
Authentication service for user management and JWT token handling.
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.db import User, Organization, RefreshToken

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


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def create_refresh_token() -> str:
    """Create a cryptographically secure refresh token."""
    return secrets.token_urlsafe(32)


def decode_access_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        if payload.get("type") != "access":
            return None
        return payload
    except JWTError:
        return None


async def authenticate_user(
    db: AsyncSession, email: str, password: str
) -> Optional[User]:
    """Authenticate a user by email and password."""
    result = await db.execute(
        select(User)
        .options(selectinload(User.organization))
        .where(and_(User.email == email.lower(), User.is_active == True))
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
    name: Optional[str] = None,
    organization_id: Optional[UUID] = None,
    role: Optional["UserRoleType"] = None,
) -> User:
    """Create a new user."""
    from app.db import UserRoleType

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


async def get_user_by_id(db: AsyncSession, user_id: UUID) -> Optional[User]:
    """Get a user by their ID."""
    result = await db.execute(
        select(User)
        .options(selectinload(User.organization))
        .where(User.id == user_id)
    )
    return result.scalar_one_or_none()


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    """Get a user by their email."""
    result = await db.execute(
        select(User)
        .options(selectinload(User.organization))
        .where(User.email == email.lower())
    )
    return result.scalar_one_or_none()


async def store_refresh_token(
    db: AsyncSession, user_id: UUID, token: str
) -> RefreshToken:
    """Store a refresh token for a user."""
    refresh_token = RefreshToken(
        user_id=user_id,
        token_hash=hash_token(token),
        expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(refresh_token)
    await db.commit()
    return refresh_token


async def validate_refresh_token(
    db: AsyncSession, token: str
) -> Optional[User]:
    """Validate a refresh token and return the associated user."""
    token_hash = hash_token(token)
    result = await db.execute(
        select(RefreshToken)
        .where(
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
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
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
