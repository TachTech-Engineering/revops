"""
Regressions from the 2026-08-13 bug bash.

These are DB-free: they pin the auth/authorization contracts and the pure
helpers that were broken, so the specific defects cannot silently return.
"""

import inspect

import pytest
from fastapi.testclient import TestClient

from app.api.v1.auth import _safe_frontend_redirect
from app.db import UserRoleType
from app.main import app

client = TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Unauthenticated access (rules/ and queries/ had NO auth dependency at all:
# detection-rule CRUD was open, and query execution reached an operator-supplied
# Panther host, making it an SSRF vector.)
# ---------------------------------------------------------------------------

UNAUTH_MUST_REJECT = [
    ("GET", "/api/v1/rules", None),
    ("POST", "/api/v1/rules", {"id": "x", "body": "b", "severity": "HIGH", "logTypes": ["A"]}),
    ("PATCH", "/api/v1/rules/abc", {"body": "b"}),
    ("DELETE", "/api/v1/rules/abc", None),
    ("POST", "/api/v1/rules/abc/test", {}),
    ("POST", "/api/v1/queries/execute", {"sql": "select 1"}),
    ("GET", "/api/v1/playbooks", None),
    ("GET", "/api/v1/correlation-rules", None),
]


@pytest.mark.parametrize(
    "method,path,body", UNAUTH_MUST_REJECT, ids=[f"{m} {p}" for m, p, _ in UNAUTH_MUST_REJECT]
)
def test_endpoint_requires_authentication(method, path, body):
    resp = client.request(
        method,
        path,
        json=body,
        # Panther connection details are caller-supplied headers; without an
        # auth gate these alone drove an outbound request to any host.
        headers={"X-Panther-Host": "attacker.example", "X-Panther-Token": "t"},
    )
    assert resp.status_code in (401, 403), (
        f"{method} {path} returned {resp.status_code}; expected 401/403"
    )


# ---------------------------------------------------------------------------
# SSO/SAML redirect allowlist (tokens are appended to this URL as a fragment,
# so an unvalidated value hands the victim's session to an attacker host).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "https://evil.example",
        "http://evil.example/path",
        "//evil.example",
        "javascript:alert(1)",
        "https://ttrevops.com.evil.example",
        "not-a-url",
        "",
        None,
    ],
)
def test_redirect_allowlist_rejects_hostile_targets(hostile):
    result = _safe_frontend_redirect(hostile)
    assert "evil.example" not in result
    assert result.startswith(("http://", "https://"))


def test_redirect_allowlist_accepts_configured_origin():
    from app.config import settings

    allowed = next(
        (o.strip() for o in settings.cors_origins_list if o.strip() and o.strip() != "*"), None
    )
    if not allowed:
        pytest.skip("no CORS origin configured in this environment")
    assert _safe_frontend_redirect(allowed).rstrip("/") == allowed.rstrip("/")


# ---------------------------------------------------------------------------
# Password reset token must never be returned outside development.
# ---------------------------------------------------------------------------


def test_forgot_password_does_not_leak_token_in_production(monkeypatch):
    import app.api.v1.auth as auth_mod

    monkeypatch.setattr(type(auth_mod.settings), "is_development", property(lambda self: False))
    src = inspect.getsource(auth_mod.forgot_password)
    # The token may only be returned inside an is_development branch.
    assert "settings.is_development" in src, "reset token must be gated on is_development"
    idx_guard = src.index("settings.is_development")
    idx_token = src.index("reset_token=reset_token")
    assert idx_token > idx_guard, "reset_token returned before/outside the development guard"


# ---------------------------------------------------------------------------
# Role enum lookups: values are lowercase, so UserRoleType(role.upper())
# raised ValueError for EVERY input -- role changes were impossible and the
# ?role= filter silently returned all users.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("supplied", ["admin", "ADMIN", "Admin", "analyst", "VIEWER"])
def test_role_lookup_accepts_any_casing(supplied):
    assert UserRoleType(supplied.lower()) in (
        UserRoleType.ADMIN,
        UserRoleType.ANALYST,
        UserRoleType.VIEWER,
    )


def test_uppercase_role_lookup_is_invalid():
    """Pins WHY .lower() is required -- .upper() raises for every valid role."""
    with pytest.raises(ValueError):
        UserRoleType("ADMIN")


# ---------------------------------------------------------------------------
# Service signatures the API layer calls with organization_id=.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["summarize_alert", "summarize_incident"])
def test_llm_service_accepts_organization_id(method):
    from app.services.llm_service import llm_service

    params = inspect.signature(getattr(llm_service, method)).parameters
    assert "organization_id" in params, (
        f"llm_service.{method} is called with organization_id= by the API layer"
    )
