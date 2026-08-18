"""
Authentication service for user management and JWT token handling.
"""

import hashlib
import logging
import re
import secrets
from datetime import timedelta
from uuid import UUID

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import and_, delete, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.core.time_utils import utcnow
from app.db import Organization, RefreshToken, User, UserRoleType
from app.db.models import PasswordResetToken

logger = logging.getLogger(__name__)

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Token configuration
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes
REFRESH_TOKEN_EXPIRE_DAYS = 7  # Refresh tokens last 7 days


class AuthError(Exception):
    """Custom exception for authentication errors."""

    pass


class RefreshTokenReuseError(AuthError):
    """A refresh token was presented after it had already been revoked.

    Either the token was stolen and replayed, or two clients raced on the same
    token. Both cases invalidate the whole token family; callers must not
    distinguish this from a plain invalid token in their response.
    """


def _duplicate_message(exc: IntegrityError, default: str) -> str:
    """Map a unique-constraint violation onto the user-facing 400 message.

    ``create_user``/``create_organization`` check-then-insert, so a concurrent
    duplicate slips between the SELECT and the INSERT and used to surface as a
    500 IntegrityError. The constraint name / detail text tells us which one
    lost the race.
    """
    detail = str(getattr(exc, "orig", exc)).lower()
    if "email" in detail:
        return "Email already registered"
    if "slug" in detail:
        return "Organization slug already exists"
    return default


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
    expire = utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
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


_dummy_password_hash: str | None = None


def _timing_equalization_hash() -> str:
    """A throwaway bcrypt hash used to keep the unknown-email path expensive.

    Returning early for a non-existent account makes login answer an order of
    magnitude faster than for a real one, which is an account-enumeration
    oracle on its own. Computed lazily (bcrypt is ~300ms) and cached.
    """
    global _dummy_password_hash
    if _dummy_password_hash is None:
        _dummy_password_hash = hash_password(secrets.token_urlsafe(16))
    return _dummy_password_hash


async def authenticate_user(db: AsyncSession, email: str, password: str) -> User | None:
    """Authenticate a user by email and password."""
    result = await db.execute(
        select(User)
        .options(selectinload(User.organization))
        .where(and_(User.email == email.lower(), User.is_active.is_(True)))
    )
    user = result.scalar_one_or_none()

    if not user:
        # Burn the same bcrypt work an existing account would, so response
        # time does not reveal whether the address is registered.
        verify_password(password, _timing_equalization_hash())
        return None
    if not verify_password(password, user.hashed_password):
        return None

    # Update last login timestamp
    user.last_login_at = utcnow()
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
    # The SELECT above is advisory only: a concurrent registration for the same
    # address commits between it and the INSERT. Catch the constraint violation
    # inside a SAVEPOINT so the caller gets a clean 400 instead of a 500 and the
    # surrounding transaction stays usable.
    try:
        async with db.begin_nested():
            db.add(user)
            await db.flush()
    except IntegrityError as exc:
        raise AuthError(_duplicate_message(exc, "Email already registered")) from exc

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
    try:
        async with db.begin_nested():
            db.add(org)
            await db.flush()
    except IntegrityError as exc:
        raise AuthError(_duplicate_message(exc, "Organization slug already exists")) from exc

    await db.commit()
    await db.refresh(org)

    return org


def slugify_organization(name: str) -> str:
    """Derive a URL-safe slug from an organization name.

    Lowercased, runs of anything that is not a letter or digit collapsed to a
    single hyphen, trimmed to the 100-character slug column. A name made
    entirely of punctuation (or of characters that do not survive this) yields
    an empty string, and the caller must ask for an explicit slug rather than
    inventing one.
    """
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug[:100].rstrip("-")


async def register_account(
    db: AsyncSession,
    email: str,
    password: str,
    name: str | None = None,
    organization_name: str | None = None,
    organization_slug: str | None = None,
) -> User:
    """Create the optional organization and the user in ONE transaction.

    ``/auth/register`` previously called ``create_organization`` (which commits)
    and then ``create_user``; a duplicate email -- or any other failure -- left
    the organization committed with nobody in it and its unique slug
    permanently burnt, so the same tenant could never register again. Both rows
    are now inserted inside a single SAVEPOINT and committed together, and a
    concurrent duplicate on either unique constraint comes back as an AuthError
    (400) rather than an IntegrityError (500).
    """
    email = email.lower()
    organization_id = None
    role: UserRoleType | None = None
    org: Organization | None = None

    if organization_name:
        # A slug used to be required for the organization to be created at all,
        # and asking for one is not obvious. Registering with just a name
        # therefore produced a user with organization_id NULL who could log in
        # and then got 403 "not associated with an organization" from every
        # endpoint -- an account that looks fine and does nothing. The slug is
        # now derived from the name when it is not supplied.
        slug = (organization_slug or slugify_organization(organization_name)).lower()
        if not slug:
            raise AuthError(
                "Could not derive an organization slug from that name; "
                "please supply organization_slug"
            )
        existing_org = await db.execute(select(Organization.id).where(Organization.slug == slug))
        if existing_org.scalar_one_or_none():
            raise AuthError("Organization slug already exists")
        org = Organization(name=organization_name, slug=slug)
        # Organization creator becomes admin
        role = UserRoleType.ADMIN

    existing_user = await db.execute(select(User.id).where(User.email == email))
    if existing_user.scalar_one_or_none():
        raise AuthError("Email already registered")

    user = User(
        email=email,
        hashed_password=hash_password(password),
        name=name,
        organization_id=organization_id,
        role=role or UserRoleType.VIEWER,
    )

    try:
        async with db.begin_nested():
            if org is not None:
                db.add(org)
                await db.flush()
                user.organization_id = org.id
            db.add(user)
            await db.flush()
    except IntegrityError as exc:
        raise AuthError(_duplicate_message(exc, "Registration failed")) from exc

    await db.commit()
    await db.refresh(user)

    return user


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
        expires_at=utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
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
                RefreshToken.expires_at > utcnow(),
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

    refresh_token.revoked_at = utcnow()
    await db.commit()
    return True


async def rotate_refresh_token(db: AsyncSession, token: str) -> tuple[User, str]:
    """Atomically consume `token` and mint its replacement.

    The old validate -> revoke -> store sequence was three separate awaits with
    no guard, so two concurrent refreshes with the same token both succeeded and
    a stolen token was never noticed. Rotation is now a compare-and-revoke: the
    conditional UPDATE only matches while ``revoked_at IS NULL``, so exactly one
    caller can ever claim a given token. Anyone presenting an already-revoked
    token is treated as reuse -- logged, and the user's entire refresh-token
    family is revoked.

    Raises:
        RefreshTokenReuseError: the token had already been revoked.
        AuthError: the token is unknown, expired, or its user cannot log in.
    """
    token_hash = hash_token(token)

    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    stored = result.scalar_one_or_none()

    if stored is None:
        raise AuthError("Invalid or expired refresh token")

    user_id = stored.user_id

    if stored.revoked_at is not None:
        logger.warning(
            "Refresh token reuse detected for user %s; revoking all refresh tokens", user_id
        )
        await revoke_all_user_tokens(db, user_id)
        raise RefreshTokenReuseError("Refresh token reuse detected")

    if stored.expires_at <= utcnow():
        raise AuthError("Invalid or expired refresh token")

    claimed = await db.execute(
        update(RefreshToken)
        .where(
            and_(
                RefreshToken.token_hash == token_hash,
                RefreshToken.revoked_at.is_(None),
            )
        )
        .values(revoked_at=utcnow())
        .execution_options(synchronize_session=False)
    )
    await db.commit()

    if claimed.rowcount != 1:
        # Another request revoked it between our SELECT and our UPDATE: a
        # concurrent refresh, which is indistinguishable from a replay.
        logger.warning(
            "Refresh token claimed concurrently for user %s; revoking all refresh tokens",
            user_id,
        )
        await revoke_all_user_tokens(db, user_id)
        raise RefreshTokenReuseError("Refresh token reuse detected")

    user = await get_user_by_id(db, user_id)
    if not user or not user.is_active:
        raise AuthError("Invalid or expired refresh token")

    new_token = create_refresh_token()
    await store_refresh_token(db, user.id, new_token)

    return user, new_token


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
        token.revoked_at = utcnow()
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
#
# These used to live in a module-level dict. With three replicas a token minted
# on pod A was rejected by pods B and C, every token was lost on restart, and
# expired entries were never reclaimed. They now live in `password_reset_tokens`
# keyed by a SHA-256 hash of the token: the raw token exists only in the
# response/email, so a database read (or a backup, or a log) never yields a
# usable one.
PASSWORD_RESET_EXPIRE_HOURS = 24


def hash_reset_token(token: str) -> str:
    """Hash a password reset token for storage (never store the token itself)."""
    return hashlib.sha256(token.encode()).hexdigest()


async def create_password_reset_token(db: AsyncSession, user_id: UUID) -> str:
    """Create a password reset token for a user and return the raw token."""
    token = secrets.token_urlsafe(32)

    # Issuing a new token invalidates every earlier one for this user, and
    # opportunistically reaps anyone else's expired rows so the table stays
    # bounded without a separate sweeper.
    await db.execute(
        delete(PasswordResetToken)
        .where(
            or_(
                PasswordResetToken.user_id == user_id,
                PasswordResetToken.expires_at <= utcnow(),
            )
        )
        .execution_options(synchronize_session=False)
    )

    db.add(
        PasswordResetToken(
            user_id=user_id,
            token_hash=hash_reset_token(token),
            expires_at=utcnow() + timedelta(hours=PASSWORD_RESET_EXPIRE_HOURS),
        )
    )
    await db.commit()

    return token


async def validate_password_reset_token(db: AsyncSession, token: str) -> UUID | None:
    """Validate a password reset token and return the user ID if valid.

    Read-only: the token is not consumed here. ``reset_user_password`` claims it
    atomically.
    """
    result = await db.execute(
        select(PasswordResetToken.user_id).where(
            and_(
                PasswordResetToken.token_hash == hash_reset_token(token),
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.expires_at > utcnow(),
            )
        )
    )
    return result.scalar_one_or_none()


async def reset_user_password(db: AsyncSession, token: str, new_password: str) -> bool:
    """Reset a user's password using a valid reset token.

    Single-use is enforced by the database, not by a subsequent delete: the
    ``used_at IS NULL`` predicate lives in the UPDATE, so of two callers
    redeeming the same token exactly one gets a row back.
    """
    claimed = await db.execute(
        update(PasswordResetToken)
        .where(
            and_(
                PasswordResetToken.token_hash == hash_reset_token(token),
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.expires_at > utcnow(),
            )
        )
        .values(used_at=utcnow())
        .returning(PasswordResetToken.user_id)
        .execution_options(synchronize_session=False)
    )
    user_id = claimed.scalar_one_or_none()

    if user_id is None:
        # Unknown, already used, or expired -- nothing was written.
        return False

    user = await get_user_by_id(db, user_id)
    if not user:
        # Token consumed regardless; it must not stay redeemable.
        await db.commit()
        return False

    user.hashed_password = hash_password(new_password)
    await db.commit()

    # A password reset invalidates every existing session.
    await revoke_all_user_tokens(db, user_id)

    return True
