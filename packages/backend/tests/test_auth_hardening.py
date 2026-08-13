"""
DB-free regression tests for the auth/session hardening pass.

Everything here exercises real application code with a stand-in session or a
dependency override -- no Postgres, no Redis. The DB-backed counterparts (does
the UPDATE actually only match one row under concurrency?) live under
tests/behavioral/.

Covered:
  * password reset tokens are stored hashed, single-use and expiring
    (auth_service.create_password_reset_token / reset_user_password)
  * refresh-token rotation is a compare-and-revoke and treats an already-revoked
    token as reuse (auth_service.rotate_refresh_token)
  * login returns an identical, provider-free 401 for an unknown address and a
    wrong password, and only names the IdP after the password verifies
  * a malformed ENCRYPTION_KEY is fatal; an unset one derives + warns
  * the websocket re-validates token expiry, is_active and org membership
"""

import uuid
from datetime import timedelta

import pytest
from sqlalchemy.exc import IntegrityError

from app.core.time_utils import utcnow
from app.services import auth_service


# --------------------------------------------------------------------------
# Minimal async-session stand-in
# --------------------------------------------------------------------------
class FakeResult:
    def __init__(self, scalar=None, rowcount=0, scalars_all=()):
        self._scalar = scalar
        self.rowcount = rowcount
        self._scalars_all = list(scalars_all)

    def scalar_one_or_none(self):
        return self._scalar

    def scalars(self):
        return self

    def all(self):
        return list(self._scalars_all)


class FakeSession:
    """Returns queued results in order and records every statement executed."""

    def __init__(self, results):
        self._results = list(results)
        self.statements = []
        self.added = []
        self.commits = 0

    async def execute(self, statement, *args, **kwargs):
        self.statements.append(statement)
        if not self._results:
            raise AssertionError(f"unexpected execute(): {statement}")
        return self._results.pop(0)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.commits += 1

    async def refresh(self, obj):
        pass


def sql(statement) -> str:
    return str(statement.compile(compile_kwargs={"literal_binds": False}))


# --------------------------------------------------------------------------
# 1. Password reset tokens
# --------------------------------------------------------------------------
def test_reset_token_is_hashed_not_stored_raw():
    token = "s3cret-reset-token"
    digest = auth_service.hash_reset_token(token)

    assert digest == auth_service.hash_reset_token(token)  # deterministic
    assert token not in digest
    assert len(digest) == 64  # sha256 hex, fits token_hash String(128)
    assert digest != auth_service.hash_reset_token(token + "x")


@pytest.mark.asyncio
async def test_create_password_reset_token_persists_only_the_hash():
    user_id = uuid.uuid4()
    db = FakeSession([FakeResult()])  # the DELETE of prior/expired tokens

    token = await auth_service.create_password_reset_token(db, user_id)

    assert len(db.added) == 1
    row = db.added[0]
    assert row.user_id == user_id
    assert row.token_hash == auth_service.hash_reset_token(token)
    assert token not in row.token_hash
    assert row.used_at is None
    # 24h TTL, allowing for clock drift across the call
    delta = row.expires_at - utcnow()
    assert timedelta(hours=23, minutes=59) < delta <= timedelta(hours=24)
    assert db.commits == 1


@pytest.mark.asyncio
async def test_create_password_reset_token_invalidates_prior_tokens():
    db = FakeSession([FakeResult()])
    await auth_service.create_password_reset_token(db, uuid.uuid4())

    statement = sql(db.statements[0])
    assert "DELETE FROM password_reset_tokens" in statement
    # Prior tokens for this user, plus anyone's expired rows.
    assert "user_id" in statement
    assert "expires_at" in statement


@pytest.mark.asyncio
async def test_reset_password_claims_the_token_atomically():
    """The single-use + expiry predicates must live in the UPDATE itself."""
    db = FakeSession([FakeResult(scalar=None)])

    assert await auth_service.reset_user_password(db, "whatever", "newpassword") is False

    statement = sql(db.statements[0])
    assert "UPDATE password_reset_tokens" in statement
    assert "used_at IS NULL" in statement
    assert "expires_at >" in statement
    assert "RETURNING" in statement.upper()
    # Nothing matched -> nothing written.
    assert db.commits == 0


@pytest.mark.asyncio
async def test_reset_password_rejects_a_second_redemption():
    """A token already carrying used_at matches nothing, so redemption fails."""
    db = FakeSession([FakeResult(scalar=None)])
    assert await auth_service.reset_user_password(db, "already-used", "newpassword") is False


def test_password_reset_module_dict_is_gone():
    assert not hasattr(auth_service, "_password_reset_tokens")


# --------------------------------------------------------------------------
# 2. Refresh-token rotation / reuse detection
# --------------------------------------------------------------------------
class FakeRefreshToken:
    def __init__(self, user_id, revoked_at=None, expires_at=None):
        self.user_id = user_id
        self.revoked_at = revoked_at
        self.expires_at = expires_at or (utcnow() + timedelta(days=7))


@pytest.mark.asyncio
async def test_unknown_refresh_token_is_a_plain_auth_error():
    db = FakeSession([FakeResult(scalar=None)])
    with pytest.raises(auth_service.AuthError) as exc:
        await auth_service.rotate_refresh_token(db, "nope")
    assert not isinstance(exc.value, auth_service.RefreshTokenReuseError)


@pytest.mark.asyncio
async def test_revoked_refresh_token_is_reuse_and_kills_the_family():
    user_id = uuid.uuid4()
    stored = FakeRefreshToken(user_id, revoked_at=utcnow())
    live = FakeRefreshToken(user_id)
    db = FakeSession(
        [
            FakeResult(scalar=stored),  # lookup
            FakeResult(scalars_all=[live]),  # revoke_all_user_tokens
        ]
    )

    with pytest.raises(auth_service.RefreshTokenReuseError):
        await auth_service.rotate_refresh_token(db, "stolen")

    assert live.revoked_at is not None  # whole family invalidated


@pytest.mark.asyncio
async def test_expired_refresh_token_is_rejected_without_family_revocation():
    stored = FakeRefreshToken(uuid.uuid4(), expires_at=utcnow() - timedelta(seconds=1))
    db = FakeSession([FakeResult(scalar=stored)])

    with pytest.raises(auth_service.AuthError) as exc:
        await auth_service.rotate_refresh_token(db, "old")
    assert not isinstance(exc.value, auth_service.RefreshTokenReuseError)


@pytest.mark.asyncio
async def test_lost_rotation_race_is_treated_as_reuse():
    """rowcount 0 means another request already claimed the token."""
    user_id = uuid.uuid4()
    stored = FakeRefreshToken(user_id)
    live = FakeRefreshToken(user_id)
    db = FakeSession(
        [
            FakeResult(scalar=stored),  # lookup: looks live
            FakeResult(rowcount=0),  # conditional UPDATE matched nothing
            FakeResult(scalars_all=[live]),  # revoke_all_user_tokens
        ]
    )

    with pytest.raises(auth_service.RefreshTokenReuseError):
        await auth_service.rotate_refresh_token(db, "raced")

    update_sql = sql(db.statements[1])
    assert "UPDATE refresh_tokens" in update_sql
    assert "revoked_at IS NULL" in update_sql  # compare-and-revoke, not SELECT-then-UPDATE
    assert live.revoked_at is not None


# --------------------------------------------------------------------------
# 3. Duplicate mapping for the get-then-create races
# --------------------------------------------------------------------------
def _integrity_error(detail: str) -> IntegrityError:
    return IntegrityError("INSERT ...", {}, Exception(detail))


def test_duplicate_message_maps_constraints_to_clean_400_text():
    assert (
        auth_service._duplicate_message(
            _integrity_error('duplicate key value violates unique constraint "ix_users_email"'),
            "fallback",
        )
        == "Email already registered"
    )
    assert (
        auth_service._duplicate_message(
            _integrity_error(
                'duplicate key value violates unique constraint "ix_organizations_slug"'
            ),
            "fallback",
        )
        == "Organization slug already exists"
    )
    assert auth_service._duplicate_message(_integrity_error("something else"), "fallback") == (
        "fallback"
    )


# --------------------------------------------------------------------------
# 4. Login must not enumerate accounts
# --------------------------------------------------------------------------
@pytest.fixture
def login_client(monkeypatch):
    """TestClient over the real app with get_db stubbed out (never connects)."""
    from fastapi.testclient import TestClient

    from app.api.v1 import auth as auth_api
    from app.db import get_db
    from app.main import app

    async def _fake_db():
        yield FakeSession([])

    app.dependency_overrides[get_db] = _fake_db
    try:
        yield TestClient(app, raise_server_exceptions=False), auth_api, monkeypatch
    finally:
        app.dependency_overrides.pop(get_db, None)


class FakeUser:
    def __init__(self, organization_id=None):
        self.id = uuid.uuid4()
        self.email = "victim@sso-tenant.example"
        self.organization_id = organization_id
        self.is_active = True


def test_login_unknown_email_and_sso_account_are_indistinguishable(login_client):
    client, auth_api, monkeypatch = login_client
    probed = []

    async def _no_user(db, email, password):
        return None

    async def _sso_enabled(db, org_id):
        probed.append(org_id)
        return True

    monkeypatch.setattr(auth_api, "authenticate_user", _no_user)
    monkeypatch.setattr(auth_api, "org_has_sso_enabled", _sso_enabled)

    unknown = client.post(
        "/api/v1/auth/login", json={"email": "nobody@example.com", "password": "x" * 12}
    )
    existing_sso = client.post(
        "/api/v1/auth/login",
        json={"email": "victim@sso-tenant.example", "password": "wrong-password"},
    )

    # Byte-identical: same status, same body.
    assert unknown.status_code == existing_sso.status_code == 401
    assert unknown.json() == existing_sso.json()
    assert unknown.json()["detail"] == "Invalid email or password"
    # And SSO was never probed before authentication -- no timing/DB side channel.
    assert probed == []


def test_login_reveals_sso_provider_only_after_the_password_verifies(login_client):
    client, auth_api, monkeypatch = login_client
    org_id = uuid.uuid4()

    async def _authenticated(db, email, password):
        return FakeUser(organization_id=org_id)

    async def _sso_enabled(db, oid):
        return True

    async def _provider_names(db, oid):
        return ["Okta"]

    monkeypatch.setattr(auth_api, "authenticate_user", _authenticated)
    monkeypatch.setattr(auth_api, "org_has_sso_enabled", _sso_enabled)
    monkeypatch.setattr(auth_api, "get_org_sso_provider_names", _provider_names)

    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "victim@sso-tenant.example", "password": "correct-horse"},
    )

    assert resp.status_code == 403
    assert "Okta" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_authenticate_user_burns_bcrypt_for_unknown_addresses(monkeypatch):
    """The unknown-email path must still pay for a password verification."""
    calls = []

    monkeypatch.setattr(
        auth_service,
        "verify_password",
        lambda plain, hashed: calls.append(hashed) or False,
    )

    db = FakeSession([FakeResult(scalar=None)])
    assert await auth_service.authenticate_user(db, "ghost@example.com", "pw") is None
    assert len(calls) == 1
    assert calls[0].startswith("$2")  # a real bcrypt hash, not a short-circuit


# --------------------------------------------------------------------------
# 5. Fernet key handling
# --------------------------------------------------------------------------
def _reset_encryption_cache():
    from app.services import encryption_service

    encryption_service._fernet_cache.clear()
    encryption_service._warned_derivations.clear()


def test_malformed_encryption_key_raises_instead_of_silently_deriving(monkeypatch):
    from app.config import settings
    from app.services import encryption_service

    _reset_encryption_cache()
    monkeypatch.setattr(settings, "encryption_key", "not-a-fernet-key")
    try:
        with pytest.raises(encryption_service.EncryptionKeyError) as exc:
            encryption_service.encrypt_credential("secret")
        assert "ENCRYPTION_KEY" in str(exc.value)
    finally:
        _reset_encryption_cache()


def test_valid_encryption_key_round_trips(monkeypatch):
    from app.config import settings
    from app.services import encryption_service

    _reset_encryption_cache()
    monkeypatch.setattr(settings, "encryption_key", encryption_service.generate_fernet_key())
    try:
        blob = encryption_service.encrypt_credential("client-secret")
        assert encryption_service.decrypt_credential(blob) == "client-secret"
        encryption_service.validate_encryption_config()  # must not raise
    finally:
        _reset_encryption_cache()


def test_unset_encryption_key_still_works_but_warns(monkeypatch, caplog):
    """Existing deployments that never set ENCRYPTION_KEY must keep working."""
    import logging

    from app.config import settings
    from app.services import encryption_service

    _reset_encryption_cache()
    monkeypatch.setattr(settings, "encryption_key", "")
    try:
        with caplog.at_level(logging.WARNING, logger="app.services.encryption_service"):
            blob = encryption_service.encrypt_credential("client-secret")
        assert encryption_service.decrypt_credential(blob) == "client-secret"
        assert any("ENCRYPTION_KEY is not set" in r.message for r in caplog.records)
    finally:
        _reset_encryption_cache()


# --------------------------------------------------------------------------
# 6. WebSocket re-validation
# --------------------------------------------------------------------------
class FakeWebSocket:
    def __init__(self, token=None):
        self.query_params = {"token": token} if token is not None else {}


class FakeDBUser:
    def __init__(self, is_active=True, organization_id=None):
        self.is_active = is_active
        self.organization_id = organization_id


class _NullSessionFactory:
    def __call__(self):
        return self

    async def __aenter__(self):
        return None

    async def __aexit__(self, *exc):
        return False


def _patch_ws_user(monkeypatch, user):
    from app.api.v1 import websocket as ws

    async def _get_user_by_id(db, user_id):
        return user

    monkeypatch.setattr(ws, "AsyncSessionLocal", _NullSessionFactory())
    monkeypatch.setattr(ws, "get_user_by_id", _get_user_by_id)
    return ws


@pytest.mark.asyncio
async def test_ws_revalidate_rejects_missing_token(monkeypatch):
    ws = _patch_ws_user(monkeypatch, None)
    result = await ws.revalidate_connection(FakeWebSocket(), uuid.uuid4(), None)
    assert result == (ws.WS_CLOSE_UNAUTHORIZED, "Missing authentication token")


@pytest.mark.asyncio
async def test_ws_revalidate_rejects_expired_token(monkeypatch):
    ws = _patch_ws_user(monkeypatch, FakeDBUser())
    user_id = uuid.uuid4()
    expired = auth_service.create_access_token(
        {"sub": str(user_id)}, expires_delta=timedelta(seconds=-5)
    )

    code, _ = await ws.revalidate_connection(FakeWebSocket(expired), user_id, None)
    assert code == ws.WS_CLOSE_UNAUTHORIZED


@pytest.mark.asyncio
async def test_ws_revalidate_rejects_token_for_a_different_subject(monkeypatch):
    ws = _patch_ws_user(monkeypatch, FakeDBUser())
    token = auth_service.create_access_token({"sub": str(uuid.uuid4())})

    code, _ = await ws.revalidate_connection(FakeWebSocket(token), uuid.uuid4(), None)
    assert code == ws.WS_CLOSE_UNAUTHORIZED


@pytest.mark.asyncio
async def test_ws_revalidate_closes_a_deactivated_account(monkeypatch):
    org_id = uuid.uuid4()
    ws = _patch_ws_user(monkeypatch, FakeDBUser(is_active=False, organization_id=org_id))
    user_id = uuid.uuid4()
    token = auth_service.create_access_token({"sub": str(user_id)})

    code, reason = await ws.revalidate_connection(FakeWebSocket(token), user_id, str(org_id))
    assert code == ws.WS_CLOSE_FORBIDDEN
    assert "active" in reason


@pytest.mark.asyncio
async def test_ws_revalidate_closes_when_the_user_moved_org(monkeypatch):
    """The org is snapshotted at connect; a move must not keep the old feed."""
    original_org = uuid.uuid4()
    ws = _patch_ws_user(monkeypatch, FakeDBUser(organization_id=uuid.uuid4()))
    user_id = uuid.uuid4()
    token = auth_service.create_access_token({"sub": str(user_id)})

    code, reason = await ws.revalidate_connection(
        FakeWebSocket(token), user_id, str(original_org)
    )
    assert code == ws.WS_CLOSE_FORBIDDEN
    assert "Organization" in reason


@pytest.mark.asyncio
async def test_ws_revalidate_allows_a_still_valid_connection(monkeypatch):
    org_id = uuid.uuid4()
    ws = _patch_ws_user(monkeypatch, FakeDBUser(organization_id=org_id))
    user_id = uuid.uuid4()
    token = auth_service.create_access_token({"sub": str(user_id)})

    assert await ws.revalidate_connection(FakeWebSocket(token), user_id, str(org_id)) is None
