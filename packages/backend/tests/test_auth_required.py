"""
Default-deny authentication test.

Walks EVERY http route registered on the app and asserts that an
unauthenticated request is rejected with 401 (the JWT dependencies in
app/api/v1/deps.py use HTTPBearer(auto_error=False) and raise 401 themselves;
403 is also tolerated for role/HTTPBearer(auto_error=True) style rejections).

Any route that is deliberately public must be listed in PUBLIC_ROUTES below.
Adding a new unauthenticated route without touching the allowlist makes this
test fail: default-deny, allowlist-explicit.

Websocket routes are excluded (they authenticate via ?token= after accept).
"""
import re
import uuid

import pytest

from app.main import app
from tests.route_utils import iter_http_routes

# (method, path-template) pairs that are allowed to respond without a JWT.
PUBLIC_ROUTES: set[tuple[str, str]] = {
    # Health probes
    ("GET", "/health"),
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/health/ready"),
    # Auth: credential establishment / recovery (public by nature)
    ("POST", "/api/v1/auth/register"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/refresh"),
    ("POST", "/api/v1/auth/logout"),
    ("POST", "/api/v1/auth/forgot-password"),
    ("POST", "/api/v1/auth/reset-password"),
    # Auth: SSO/SAML browser flows (pre-authentication by definition)
    ("GET", "/api/v1/auth/sso/providers"),
    ("GET", "/api/v1/auth/sso/detect"),
    ("GET", "/api/v1/auth/sso/{config_id}/authorize"),
    ("GET", "/api/v1/auth/sso/{config_id}/callback"),
    ("GET", "/api/v1/auth/saml/{config_id}/metadata"),
    ("GET", "/api/v1/auth/saml/{config_id}/login"),
    ("POST", "/api/v1/auth/saml/{config_id}/acs"),
    ("GET", "/api/v1/auth/saml/{config_id}/sls"),
    ("POST", "/api/v1/auth/saml/{config_id}/sls"),
    # Static enum labels, deliberately open
    ("GET", "/api/v1/iocs/types"),
    # API docs
    ("GET", "/api/v1/docs"),
    ("GET", "/docs/oauth2-redirect"),
    ("GET", "/api/v1/redoc"),
    ("GET", "/api/v1/openapi.json"),
    # Twilio callbacks (app/api/v1/twilio_webhook.py) cannot carry a JWT
    # (Twilio calls them directly); they are authenticated by validating the
    # X-Twilio-Signature header instead (403 on missing/invalid signature,
    # 503 when TWILIO_AUTH_TOKEN is not configured), so they are intentionally
    # exempt from the JWT default-deny sweep.
    ("POST", "/api/v1/twilio/voice/alert"),
    ("POST", "/api/v1/twilio/voice/response"),
    ("POST", "/api/v1/twilio/sms/response"),
    # Falco ingest webhook (app/api/v1/falco_ingest.py) cannot carry a JWT
    # (Falco/Falcosidekick call it directly); it is authenticated by a
    # per-connector shared ingest token (401 on missing/invalid token), so it
    # is intentionally exempt from the JWT default-deny sweep.
    ("POST", "/api/v1/ingest/falco/{connector_id}"),
}

_PARAM_RE = re.compile(r"{([^}:]+)(?::[^}]+)?}")


def _fill_path_params(path: str) -> str:
    """Substitute every path parameter with a dummy UUID (auth dependencies
    run before path/body validation, so the value never needs to be valid)."""
    return _PARAM_RE.sub(str(uuid.uuid4()), path)


ALL_ROUTES = sorted({(route.method, route.path) for route in iter_http_routes(app)})
PROTECTED_ROUTES = [pair for pair in ALL_ROUTES if pair not in PUBLIC_ROUTES]


def test_route_walk_found_routes():
    """Sanity: the walk actually enumerated a large route surface. If this
    drops, the enumeration broke (e.g. a fastapi routing change) and the
    default-deny guarantee is void."""
    assert len(ALL_ROUTES) > 100


def test_allowlist_entries_are_real_routes():
    """Every allowlist entry must match a registered route, so stale entries
    are flagged when a public route is removed or renamed."""
    registered = set(ALL_ROUTES)
    for method, path in sorted(PUBLIC_ROUTES):
        assert (method, path) in registered, (
            f"Allowlist entry {method} {path} does not match any registered route"
        )


@pytest.mark.parametrize(
    "method,path",
    PROTECTED_ROUTES,
    ids=[f"{method} {path}" for method, path in PROTECTED_ROUTES],
)
def test_unauthenticated_request_is_rejected(client, method: str, path: str):
    response = client.request(method, _fill_path_params(path))
    assert response.status_code in (401, 403), (
        f"{method} {path} returned {response.status_code} without credentials; "
        "every route must require auth unless explicitly allowlisted in "
        "PUBLIC_ROUTES."
    )
