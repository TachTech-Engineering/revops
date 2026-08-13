"""
Guard for LLM-generated SQL (app/core/sql_guard.py).

Two endpoints execute SQL written by a language model. The organization filter
in those prompts is only a soft instruction, and the previous checks were a
keyword blocklist (ai.py) and a substring test that ignored the org entirely
(nl_queries.validate_sql_safety accepted org_id and never used it). A query
filtering on ANOTHER tenant's organization id passed and executed.

These tests pin the bypasses, not just the happy path.
"""

import uuid

import pytest

from app.api.v1.ioc_search import (
    UnsafeIndicatorError,
    _validate_indicator,
    build_search_query,
)
from app.api.v1.nl_queries import validate_sql_safety
from app.core.sql_guard import validate_generated_sql

ORG = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER = uuid.UUID("22222222-2222-2222-2222-222222222222")


def ok(sql, org=ORG):
    return validate_generated_sql(sql, org)[0]


# --- the bug this guard exists for -----------------------------------------


def test_rejects_query_scoped_to_another_organization():
    sql = f"SELECT * FROM normalized_alerts WHERE organization_id = '{OTHER}'"
    safe, reason = validate_generated_sql(sql, ORG)
    assert not safe
    assert "different organization" in reason


def test_rejects_missing_org_filter():
    safe, reason = validate_generated_sql("SELECT * FROM normalized_alerts", ORG)
    assert not safe
    assert "organization_id" in reason


def test_accepts_query_scoped_to_caller_org():
    assert ok(f"SELECT title FROM normalized_alerts WHERE organization_id = '{ORG}' LIMIT 50")


@pytest.mark.parametrize(
    "sql",
    [
        # UNION bypass: correctly-filtered branch + unfiltered branch.
        "SELECT title FROM normalized_alerts WHERE organization_id = '{org}' "
        "UNION SELECT title FROM normalized_alerts",
        "SELECT title FROM a WHERE organization_id = '{org}' EXCEPT SELECT title FROM b",
        "SELECT title FROM a WHERE organization_id = '{org}' INTERSECT SELECT title FROM b",
    ],
)
def test_rejects_set_operation_bypass(sql):
    assert not ok(sql.format(org=ORG))


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 WHERE organization_id = '{org}'; DROP TABLE users",
        "SELECT 1 WHERE organization_id = '{org}' -- and comment",
        "SELECT 1 /* hide */ WHERE organization_id = '{org}'",
        "DELETE FROM normalized_alerts WHERE organization_id = '{org}'",
        "UPDATE users SET role='admin' WHERE organization_id = '{org}'",
        "SELECT * FROM pg_catalog.pg_tables WHERE organization_id = '{org}'",
        "SELECT * FROM information_schema.tables WHERE organization_id = '{org}'",
    ],
)
def test_rejects_dangerous_statements(sql):
    assert not ok(sql.format(org=ORG))


def test_rejects_org_id_compared_to_column_not_literal():
    # `organization_id = other.organization_id` mentions the column but pins
    # nothing -- it must not count as a tenant filter.
    sql = "SELECT a.title FROM alerts a JOIN other o ON a.organization_id = o.organization_id"
    assert not ok(sql)


@pytest.mark.parametrize(
    "variant",
    [
        "WHERE organization_id='{org}'",
        "WHERE organization_id = '{org}'::uuid",
        "WHERE a.organization_id = '{org}'",
        'WHERE organization_id = "{org}"',
    ],
)
def test_accepts_literal_spelling_variants(variant):
    assert ok(f"SELECT title FROM normalized_alerts a {variant.format(org=ORG)}")


def test_rejects_mixed_own_and_foreign_org():
    sql = f"SELECT title FROM alerts WHERE organization_id = '{ORG}' OR organization_id = '{OTHER}'"
    assert not ok(sql)


def test_empty_and_non_select():
    assert not ok("")
    assert not ok("   ")
    assert not ok(f"EXPLAIN SELECT 1 WHERE organization_id = '{ORG}'")


def test_trailing_semicolon_is_tolerated():
    assert ok(f"SELECT title FROM alerts WHERE organization_id = '{ORG}';")


# --- the nl_queries wrapper must delegate, not re-implement -----------------


def test_nl_queries_validator_rejects_foreign_org():
    """Regression: this validator took org_id and never used it."""
    safe, _ = validate_sql_safety(
        f"SELECT * FROM normalized_alerts WHERE organization_id = '{OTHER}'", ORG
    )
    assert not safe


def test_nl_queries_validator_accepts_own_org():
    safe, _ = validate_sql_safety(
        f"SELECT * FROM normalized_alerts WHERE organization_id = '{ORG}' LIMIT 10", ORG
    )
    assert safe


# =============================================================================
# IOC search: indicator is interpolated into Snowflake SQL (no bind-parameter
# channel through the Panther API), so it must be constrained, not trusted.
# =============================================================================


@pytest.mark.parametrize(
    "payload",
    [
        "1.1.1.1'::variant, p_any_ip_addresses) OR 1=1 --",  # the reported break-out
        "x' OR '1'='1",
        'x" OR 1=1',
        "1.1.1.1; DROP TABLE all_logs",
        "1.1.1.1/*comment*/",
        "1.1.1.1\nUNION SELECT 1",
        "a" * 300,  # length bound
        "",
    ],
)
def test_ioc_indicator_rejects_injection_payloads(payload):
    with pytest.raises(UnsafeIndicatorError):
        _validate_indicator(payload)


@pytest.mark.parametrize(
    "good",
    [
        "8.8.8.8",
        "2001:db8::1",
        "evil-domain.example.com",
        "a" * 64,  # sha256
        "user.name+tag@corp.example",
        "https://example.com/path?a=b&c=d",
    ],
)
def test_ioc_indicator_accepts_real_indicators(good):
    assert _validate_indicator(good) == good.strip()
    assert good.strip() in build_search_query(good, "ip", 7)


def test_ioc_indicator_rejects_backslash():
    """Backslash is an escape character in Snowflake string literals, so a
    value containing it could escape the closing quote. Windows-style
    DOMAIN\\user is deliberately rejected rather than widening the allowlist."""
    with pytest.raises(UnsafeIndicatorError):
        _validate_indicator("DOMAIN\\user")


def test_ioc_days_is_clamped():
    assert "interval '365'" in build_search_query("8.8.8.8", "ip", 10**6)
    assert "interval '1'" in build_search_query("8.8.8.8", "ip", -5)
