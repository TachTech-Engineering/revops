"""
Route-resolution tests for collision-prone prefixes.

Several prefixes are shared by two (or three) routers, and registration order
in app/api/v1/router.py decides which handler wins:

  /rules      -> rule_health (mounted at /rules/health, registered first),
                 rules (has GET /{rule_id}), rule_versions
  /queries    -> queries, nl_queries
  /playbooks  -> playbooks (has GET /{playbook_id}), playbook_templates
  /analytics  -> analytics, trend_analytics

These tests resolve representative literal paths using the same
first-full-match semantics as starlette's dispatch and assert which module
owns the endpoint, so a registration-order regression fails loudly.
"""

import pytest

from app.main import app
from tests.route_utils import resolve


def resolve_endpoint_module(path: str, method: str) -> str:
    route = resolve(app, path, method)
    assert route is not None, f"No route matched {method} {path}"
    return route.endpoint.__module__


CASES = [
    # /rules: rule_health is mounted at /rules/health BEFORE rules, so its
    # literal paths must win over rules' GET /{rule_id}.
    ("/api/v1/rules/health", "GET", "app.api.v1.rule_health"),
    ("/api/v1/rules/health/stale", "GET", "app.api.v1.rule_health"),
    ("/api/v1/rules/health/stats", "GET", "app.api.v1.rule_health"),
    ("/api/v1/rules/health/refresh", "POST", "app.api.v1.rule_health"),
    ("/api/v1/rules/Some.Rule.Id", "GET", "app.api.v1.rules"),
    ("/api/v1/rules/Some.Rule.Id/versions", "GET", "app.api.v1.rule_versions"),
    # /queries: queries vs nl_queries (all literal paths, no params -> no
    # shadowing possible, but keep the ownership pinned).
    ("/api/v1/queries/execute", "POST", "app.api.v1.queries"),
    ("/api/v1/queries/natural", "POST", "app.api.v1.nl_queries"),
    ("/api/v1/queries/natural/history", "GET", "app.api.v1.nl_queries"),
    ("/api/v1/queries/natural/examples", "GET", "app.api.v1.nl_queries"),
    # /playbooks: playbooks (GET /{playbook_id}) vs playbook_templates.
    ("/api/v1/playbooks/11111111-1111-1111-1111-111111111111", "GET", "app.api.v1.playbooks"),
    ("/api/v1/playbooks/executions/recent", "GET", "app.api.v1.playbooks"),
    ("/api/v1/playbooks/generate", "POST", "app.api.v1.playbook_templates"),
    (
        "/api/v1/playbooks/templates/22222222-2222-2222-2222-222222222222",
        "GET",
        "app.api.v1.playbook_templates",
    ),
    # playbook_templates is registered BEFORE playbooks in app/api/v1/router.py
    # (like rule_health before rules), so its literal paths /playbooks/templates
    # and /playbooks/suggestions must win over playbooks' GET /{playbook_id}.
    ("/api/v1/playbooks/templates", "GET", "app.api.v1.playbook_templates"),
    ("/api/v1/playbooks/suggestions", "GET", "app.api.v1.playbook_templates"),
    # /analytics: analytics vs trend_analytics (all literal paths).
    ("/api/v1/analytics/alerts", "GET", "app.api.v1.analytics"),
    ("/api/v1/analytics/trends", "GET", "app.api.v1.trend_analytics"),
    ("/api/v1/analytics/forecast", "GET", "app.api.v1.trend_analytics"),
    ("/api/v1/analytics/coverage", "GET", "app.api.v1.trend_analytics"),
]


@pytest.mark.parametrize("path,method,expected_module", CASES)
def test_path_resolves_to_expected_module(path: str, method: str, expected_module: str):
    assert resolve_endpoint_module(path, method) == expected_module


def test_rules_health_not_shadowed_by_get_rule(client):
    """GET /api/v1/rules/health must be handled by rule_health, not
    rules.get_rule treating "health" as a rule_id. Unauthenticated it must be
    a 401 from the JWT dependency, never a 404/422 from the wrong handler."""
    response = client.get("/api/v1/rules/health")
    assert response.status_code == 401
