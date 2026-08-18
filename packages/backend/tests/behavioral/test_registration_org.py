"""
Registering with an organization name must produce a usable account.

The organization was only created when BOTH organization_name and
organization_slug were supplied. Asking for a slug is not obvious, so
registering with just a name produced a user with organization_id NULL: they
could log in, receive a token, and then get 403 "User is not associated with
an organization" from every org-scoped endpoint. An account that looks fine
and does nothing.

Found 2026-08-17 by hitting it while seeding the staging environment.
"""

import pytest
from sqlalchemy import select

from app.db.models import Organization, User, UserRoleType
from app.services.auth_service import AuthError, register_account, slugify_organization

pytestmark = pytest.mark.asyncio


async def test_name_without_slug_still_creates_the_organization(db_session):
    """The regression. This used to yield an org-less, unusable account."""
    user = await register_account(
        db_session,
        email="founder@example.com",
        password="CorrectHorse1!",
        name="Founder",
        organization_name="Acme Security",
    )

    assert user.organization_id is not None, "an org-less account cannot use the app"
    assert user.role is UserRoleType.ADMIN, "the creator of an org is its admin"

    org = (
        await db_session.execute(
            select(Organization).where(Organization.id == user.organization_id)
        )
    ).scalar_one()
    assert org.name == "Acme Security"
    assert org.slug == "acme-security"


async def test_an_explicit_slug_still_wins(db_session):
    user = await register_account(
        db_session,
        email="explicit@example.com",
        password="CorrectHorse1!",
        organization_name="Acme Security",
        organization_slug="acme-prod",
    )

    org = (
        await db_session.execute(
            select(Organization).where(Organization.id == user.organization_id)
        )
    ).scalar_one()
    assert org.slug == "acme-prod"


async def test_a_derived_slug_that_collides_is_reported(db_session):
    """Two orgs of the same name must not silently share or overwrite a slug."""
    await register_account(
        db_session,
        email="first@example.com",
        password="CorrectHorse1!",
        organization_name="Acme Security",
    )

    with pytest.raises(AuthError, match="slug already exists"):
        await register_account(
            db_session,
            email="second@example.com",
            password="CorrectHorse1!",
            organization_name="Acme Security",
        )


async def test_a_name_with_no_usable_characters_asks_for_a_slug(db_session):
    """Better an actionable error than an account that cannot do anything."""
    with pytest.raises(AuthError, match="organization_slug"):
        await register_account(
            db_session,
            email="punct@example.com",
            password="CorrectHorse1!",
            organization_name="!!!",
        )


async def test_registering_with_no_organization_is_unchanged(db_session):
    """Joining an existing tenant is a separate flow; do not invent an org."""
    user = await register_account(
        db_session,
        email="solo@example.com",
        password="CorrectHorse1!",
        name="Solo",
    )

    assert user.organization_id is None
    assert user.role is UserRoleType.VIEWER


async def test_the_failed_registration_leaves_nothing_behind(db_session):
    """A rejected registration must not burn the slug or half-create a user."""
    with pytest.raises(AuthError):
        await register_account(
            db_session,
            email="ghost@example.com",
            password="CorrectHorse1!",
            organization_name="!!!",
        )

    assert (
        await db_session.execute(select(User).where(User.email == "ghost@example.com"))
    ).scalar_one_or_none() is None


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Staging Org", "staging-org"),
        ("ACME, Inc.", "acme-inc"),
        ("  Multi   Space  ", "multi-space"),
        ("Org--Name", "org-name"),
        ("!!!", ""),
    ],
)
def test_slugify(name, expected):
    assert slugify_organization(name) == expected


def test_slugify_fits_the_column_and_never_trails_a_hyphen():
    slug = slugify_organization("A" * 60 + " " + "B" * 60)
    assert len(slug) <= 100
    assert not slug.endswith("-")
