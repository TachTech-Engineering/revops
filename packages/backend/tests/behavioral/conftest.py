"""
DB-backed behavioral test harness (OPT-IN).

Everything collected under ``tests/behavioral/`` is auto-marked ``db`` and runs
against a real Postgres. When no database is reachable the fixtures call
``pytest.skip`` so the marker-free ``pytest tests`` invocation still succeeds and
the existing DB-free suite is never disturbed. Run only these with
``pytest -m db``; exclude them with ``pytest -m "not db"``.

Isolation model
---------------
* One engine per test (NullPool) so nothing is shared across event loops.
* The schema is created once (``Base.metadata.create_all``) on first use and
  reused thereafter (committed DDL survives the per-test rollback).
* Each test binds an ``AsyncSession`` to a single connection that is wrapped in
  an outer transaction; the session joins it with ``create_savepoint`` so any
  ``commit()`` the app code performs only releases a SAVEPOINT. Teardown rolls
  the outer transaction back, discarding all writes.
* ``app.dependency_overrides[get_db]`` yields that same session, so the ASGI
  request handler and the test assertions observe one shared transaction.

Auth model
----------
Real JWTs are minted with ``auth_service.create_access_token`` using the exact
claims the app issues in ``generate_token_response`` (``sub`` = user id, plus
``email``/``org_id``; ``type=access`` and ``exp`` are added by the helper). This
exercises the genuine ``get_current_user_jwt`` -> org-resolution path rather than
overriding the auth dependency.
"""

import os

os.environ.setdefault("ENVIRONMENT", "development")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost:5432/revops_test",
)

# Schema is created only once per process; committed DDL outlives the per-test
# transaction rollbacks.
_SCHEMA_READY = False


def pytest_collection_modifyitems(config, items):
    """Auto-mark every test under tests/behavioral/ with @pytest.mark.db."""
    for item in items:
        path = str(getattr(item, "fspath", "")).replace("\\", "/")
        if "/behavioral/" in path:
            item.add_marker(pytest.mark.db)


@pytest_asyncio.fixture
async def db_engine():
    """A fresh NullPool engine per test; skips the test if Postgres is absent."""
    global _SCHEMA_READY
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)

    # Connectivity probe: skip (never fail) when no test DB is available so the
    # marker-free suite stays green in DB-free environments.
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover - only hit without a DB
        await engine.dispose()
        pytest.skip(f"No test database available at {TEST_DATABASE_URL}: {exc}")

    if not _SCHEMA_READY:
        from app.db.models import Base

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        _SCHEMA_READY = True

    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    """Session bound to a rolled-back outer transaction (SAVEPOINT isolation)."""
    connection = await db_engine.connect()
    trans = await connection.begin()
    session = AsyncSession(
        bind=connection,
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )
    try:
        yield session
    finally:
        await session.close()
        if trans.is_active:
            await trans.rollback()
        await connection.close()


@pytest_asyncio.fixture
async def app_client(db_session):
    """httpx client wired to the real app with get_db overridden to db_session."""
    from app.db.session import get_db
    from app.main import app

    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest_asyncio.fixture
async def make_user(db_session):
    """Factory: create an org + user, return an object with real-JWT auth headers.

    Returns a SimpleNamespace(org, user, token, headers). Multiple orgs can be
    created in one test to drive cross-tenant checks.
    """
    from types import SimpleNamespace

    from app.db.models import Organization, User, UserRoleType
    from app.services.auth_service import create_access_token

    counter = {"n": 0}

    async def _make(slug: str, role: UserRoleType = UserRoleType.ANALYST, email: str | None = None):
        counter["n"] += 1
        unique = f"{slug}-{counter['n']}"
        org = Organization(name=f"Org {unique}", slug=unique)
        db_session.add(org)
        await db_session.flush()

        user = User(
            email=email or f"user-{unique}@example.com",
            hashed_password="not-used-real-jwt",
            name=f"User {unique}",
            role=role,
            is_active=True,
            organization_id=org.id,
        )
        db_session.add(user)
        await db_session.flush()

        token = create_access_token(
            {
                "sub": str(user.id),
                "email": user.email,
                "org_id": str(user.organization_id),
            }
        )
        return SimpleNamespace(
            org=org,
            user=user,
            token=token,
            headers={"Authorization": f"Bearer {token}"},
        )

    return _make
