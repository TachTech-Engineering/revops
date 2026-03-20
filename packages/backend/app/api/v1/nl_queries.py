"""
Natural Language Queries API - Feature 4
"Show failed logins last week" → SQL/filters.
"""
import re
import time
from datetime import datetime
from typing import Optional, Tuple
from uuid import UUID

import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgUserDep, OrgIdDep
from app.db import get_db, NLQueryHistory
from app.config import settings
from fastapi import Depends
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

# SQL Safety validation
DANGEROUS_KEYWORDS = [
    "DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "CREATE", "TRUNCATE",
    "GRANT", "REVOKE", "EXEC", "EXECUTE", "MERGE", "CALL", "COPY",
    "pg_", "information_schema", "--", "/*", "*/", ";"
]


class NLQueryRequest(BaseModel):
    query: str
    execute: bool = True  # Whether to execute the generated SQL


class NLQueryResponse(BaseModel):
    id: str
    natural_query: str
    generated_sql: str
    explanation: Optional[str]
    results: Optional[list] = None
    row_count: Optional[int] = None
    execution_time_ms: Optional[int] = None
    error_message: Optional[str] = None


class NLQueryHistoryResponse(BaseModel):
    id: str
    natural_query: str
    generated_sql: str
    explanation: Optional[str]
    was_executed: bool
    row_count: Optional[int]
    was_helpful: Optional[bool]
    created_at: str

    class Config:
        from_attributes = True


class FeedbackRequest(BaseModel):
    query_id: str
    was_helpful: bool
    feedback_comment: Optional[str] = None


# Example queries for natural language to SQL translation
EXAMPLE_QUERIES = [
    {"nl": "Show failed logins from yesterday", "sql": "SELECT * FROM normalized_alerts WHERE title ILIKE '%failed login%' AND created_at_source >= NOW() - INTERVAL '1 day'"},
    {"nl": "Count alerts by severity this week", "sql": "SELECT severity, COUNT(*) as count FROM normalized_alerts WHERE created_at_source >= NOW() - INTERVAL '7 days' GROUP BY severity"},
    {"nl": "Find critical alerts from last 24 hours", "sql": "SELECT * FROM normalized_alerts WHERE severity = 'critical' AND created_at_source >= NOW() - INTERVAL '24 hours' ORDER BY created_at_source DESC"},
    {"nl": "Show top 10 rules by alert count", "sql": "SELECT rule_id, rule_name, COUNT(*) as alert_count FROM normalized_alerts GROUP BY rule_id, rule_name ORDER BY alert_count DESC LIMIT 10"},
]


def validate_sql_safety(sql: str, org_id: UUID) -> Tuple[bool, str]:
    """
    Validate that SQL is safe to execute.

    Args:
        sql: The SQL query to validate
        org_id: Organization ID for filter validation

    Returns:
        Tuple of (is_safe, error_message)
    """
    sql_upper = sql.upper().strip()

    # Must be a SELECT query
    if not sql_upper.startswith("SELECT"):
        return False, "Only SELECT queries are allowed"

    # Check for dangerous keywords
    for keyword in DANGEROUS_KEYWORDS:
        if keyword.upper() in sql_upper:
            return False, f"Query contains forbidden keyword: {keyword}"

    # Check for organization filter (required for multi-tenant safety)
    if "organization_id" not in sql.lower():
        return False, "Query must include organization_id filter"

    return True, ""


async def translate_nl_to_sql_llm(natural_query: str, org_id: UUID) -> Tuple[str, str]:
    """
    Translate natural language to SQL using Anthropic API.

    Args:
        natural_query: Natural language query from user
        org_id: Organization ID for filtering

    Returns:
        Tuple of (sql_query, explanation)
    """
    if not settings.anthropic_api_key:
        # Fall back to pattern matching if no API key
        return translate_nl_to_sql_fallback(natural_query, org_id)

    system_prompt = """You are a SQL query generator for a security operations center (SOC) platform.
You translate natural language queries into PostgreSQL queries.

Available tables and their key columns:
- normalized_alerts: id, organization_id, title, description, severity (critical/high/medium/low/info),
  status (open/acknowledged/resolved/closed), source_type, rule_id, rule_name, tags,
  mitre_tactics, mitre_techniques, created_at_source, ingested_at
- incidents: id, organization_id, title, description, status (open/investigating/contained/resolved/closed),
  severity (critical/high/medium/low), assignee, tags, created_by, created_at, updated_at
- cases: id, organization_id, case_number, title, description, status, priority, assignee, tags,
  incident_ids, created_by, closed_at, created_at

IMPORTANT RULES:
1. ALWAYS include WHERE organization_id = '{org_id}' in every query for security
2. Only generate SELECT queries
3. Use ILIKE for case-insensitive text matching
4. Limit results to 100 rows maximum unless specifically asked for more
5. Use appropriate time intervals (INTERVAL '1 day', '7 days', etc.)
6. Order by created_at_source DESC for alerts, created_at DESC for incidents/cases

Respond with ONLY a JSON object containing:
{
  "sql": "the SQL query",
  "explanation": "brief explanation of what the query does"
}"""

    user_prompt = f"Translate this to SQL for organization_id = '{org_id}':\n\n{natural_query}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": settings.anthropic_api_key,
                    "Content-Type": "application/json",
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": settings.anthropic_model or "claude-sonnet-4-20250514",
                    "max_tokens": 1000,
                    "system": system_prompt,
                    "messages": [
                        {"role": "user", "content": user_prompt}
                    ],
                },
                timeout=30.0,
            )

            if response.status_code != 200:
                logger.error(f"Anthropic API error: {response.status_code} - {response.text}")
                return translate_nl_to_sql_fallback(natural_query, org_id)

            data = response.json()
            content = data.get("content", [{}])[0].get("text", "{}")

            # Parse JSON response
            import json
            try:
                result = json.loads(content)
                sql = result.get("sql", "")
                explanation = result.get("explanation", "")

                # Validate the generated SQL
                is_safe, error = validate_sql_safety(sql, org_id)
                if not is_safe:
                    logger.warning(f"LLM generated unsafe SQL: {error}")
                    return translate_nl_to_sql_fallback(natural_query, org_id)

                return sql, explanation

            except json.JSONDecodeError:
                logger.error(f"Failed to parse LLM response: {content}")
                return translate_nl_to_sql_fallback(natural_query, org_id)

    except Exception as e:
        logger.error(f"Error calling Anthropic API: {e}")
        return translate_nl_to_sql_fallback(natural_query, org_id)


def translate_nl_to_sql_fallback(natural_query: str, org_id: UUID) -> Tuple[str, str]:
    """
    Fallback pattern-matching for NL to SQL translation.
    Used when LLM is unavailable.
    """
    query_lower = natural_query.lower()
    org_filter = f"organization_id = '{org_id}'"

    if "failed login" in query_lower:
        if "yesterday" in query_lower:
            sql = f"SELECT * FROM normalized_alerts WHERE {org_filter} AND title ILIKE '%failed login%' AND created_at_source >= NOW() - INTERVAL '1 day' ORDER BY created_at_source DESC LIMIT 100"
            explanation = "Searching for alerts with 'failed login' in the title from the last 24 hours"
        elif "last week" in query_lower or "past week" in query_lower:
            sql = f"SELECT * FROM normalized_alerts WHERE {org_filter} AND title ILIKE '%failed login%' AND created_at_source >= NOW() - INTERVAL '7 days' ORDER BY created_at_source DESC LIMIT 100"
            explanation = "Searching for alerts with 'failed login' in the title from the last 7 days"
        else:
            sql = f"SELECT * FROM normalized_alerts WHERE {org_filter} AND title ILIKE '%failed login%' ORDER BY created_at_source DESC LIMIT 100"
            explanation = "Searching for recent alerts with 'failed login' in the title"

    elif "critical" in query_lower and "alert" in query_lower:
        if "today" in query_lower or "24 hour" in query_lower:
            sql = f"SELECT * FROM normalized_alerts WHERE {org_filter} AND severity = 'critical' AND created_at_source >= NOW() - INTERVAL '24 hours' ORDER BY created_at_source DESC LIMIT 100"
            explanation = "Finding critical severity alerts from the last 24 hours"
        else:
            sql = f"SELECT * FROM normalized_alerts WHERE {org_filter} AND severity = 'critical' ORDER BY created_at_source DESC LIMIT 100"
            explanation = "Finding recent critical severity alerts"

    elif "count" in query_lower and "severity" in query_lower:
        if "week" in query_lower:
            sql = f"SELECT severity, COUNT(*) as count FROM normalized_alerts WHERE {org_filter} AND created_at_source >= NOW() - INTERVAL '7 days' GROUP BY severity ORDER BY count DESC"
            explanation = "Counting alerts by severity for the past week"
        else:
            sql = f"SELECT severity, COUNT(*) as count FROM normalized_alerts WHERE {org_filter} GROUP BY severity ORDER BY count DESC"
            explanation = "Counting all alerts by severity"

    elif "top" in query_lower and "rule" in query_lower:
        limit = 10
        for word in query_lower.split():
            if word.isdigit():
                limit = int(word)
                break
        sql = f"SELECT rule_id, rule_name, COUNT(*) as alert_count FROM normalized_alerts WHERE {org_filter} GROUP BY rule_id, rule_name ORDER BY alert_count DESC LIMIT {limit}"
        explanation = f"Finding the top {limit} rules by alert count"

    elif "open" in query_lower and "alert" in query_lower:
        sql = f"SELECT * FROM normalized_alerts WHERE {org_filter} AND status = 'open' ORDER BY created_at_source DESC LIMIT 100"
        explanation = "Finding alerts with open status"

    elif "incident" in query_lower:
        if "open" in query_lower:
            sql = f"SELECT * FROM incidents WHERE {org_filter} AND status = 'open' ORDER BY created_at DESC LIMIT 50"
            explanation = "Finding open incidents"
        else:
            sql = f"SELECT * FROM incidents WHERE {org_filter} ORDER BY created_at DESC LIMIT 50"
            explanation = "Finding recent incidents"

    else:
        # Default: search in alert titles
        search_terms = [w for w in natural_query.split() if len(w) > 3]
        if search_terms:
            conditions = " OR ".join([f"title ILIKE '%{term}%'" for term in search_terms[:3]])
            sql = f"SELECT * FROM normalized_alerts WHERE {org_filter} AND ({conditions}) ORDER BY created_at_source DESC LIMIT 100"
            explanation = f"Searching for alerts containing: {', '.join(search_terms[:3])}"
        else:
            sql = f"SELECT * FROM normalized_alerts WHERE {org_filter} ORDER BY created_at_source DESC LIMIT 50"
            explanation = "Showing recent alerts"

    return sql, explanation


@router.post("/natural", response_model=NLQueryResponse)
async def execute_natural_query(
    request: NLQueryRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Parse and execute a natural language query using LLM translation."""
    start_time = time.time()

    # Translate NL to SQL using LLM
    generated_sql, explanation = await translate_nl_to_sql_llm(request.query, org_id)

    # Create history entry
    history = NLQueryHistory(
        organization_id=org_id,
        user_email=user.email,
        natural_query=request.query,
        generated_sql=generated_sql,
        explanation=explanation,
        was_executed=request.execute,
    )

    results = None
    row_count = None
    error_message = None

    if request.execute:
        try:
            # Validate SQL safety
            is_safe, safety_error = validate_sql_safety(generated_sql, org_id)
            if not is_safe:
                raise HTTPException(status_code=400, detail=safety_error)

            # Execute the query with timeout
            try:
                # Use a raw connection for the query with statement timeout
                result = await db.execute(
                    text(f"SET statement_timeout = '30s'; {generated_sql}")
                )
                rows = result.fetchall()

                # Convert to list of dicts
                if rows:
                    columns = result.keys()
                    results = [
                        {col: (str(val) if val is not None else None) for col, val in zip(columns, row)}
                        for row in rows[:100]  # Limit to 100 results
                    ]
                else:
                    results = []

                row_count = len(rows)

            except Exception as query_error:
                # Reset statement timeout
                await db.execute(text("RESET statement_timeout"))
                raise query_error

            end_time = time.time()
            execution_time_ms = int((end_time - start_time) * 1000)

            history.row_count = row_count
            history.execution_time_ms = execution_time_ms

        except HTTPException:
            raise
        except Exception as e:
            error_message = str(e)
            history.error_message = error_message
            logger.error(f"Error executing NL query: {e}")

    db.add(history)
    await db.commit()
    await db.refresh(history)

    return NLQueryResponse(
        id=str(history.id),
        natural_query=request.query,
        generated_sql=generated_sql,
        explanation=explanation,
        results=results,
        row_count=row_count,
        execution_time_ms=history.execution_time_ms,
        error_message=error_message,
    )


@router.get("/natural/history", response_model=list[NLQueryHistoryResponse])
async def get_query_history(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
):
    """Get user's natural language query history."""
    result = await db.execute(
        select(NLQueryHistory)
        .where(NLQueryHistory.organization_id == org_id)
        .where(NLQueryHistory.user_email == user.email)
        .order_by(desc(NLQueryHistory.created_at))
        .limit(limit)
    )
    queries = result.scalars().all()

    return [
        NLQueryHistoryResponse(
            id=str(q.id),
            natural_query=q.natural_query,
            generated_sql=q.generated_sql,
            explanation=q.explanation,
            was_executed=q.was_executed,
            row_count=q.row_count,
            was_helpful=q.was_helpful,
            created_at=q.created_at.isoformat(),
        )
        for q in queries
    ]


@router.post("/natural/feedback")
async def submit_query_feedback(
    request: FeedbackRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Submit feedback on whether a query translation was helpful."""
    result = await db.execute(
        select(NLQueryHistory)
        .where(NLQueryHistory.id == UUID(request.query_id))
        .where(NLQueryHistory.organization_id == org_id)
    )
    query = result.scalar_one_or_none()

    if not query:
        raise HTTPException(status_code=404, detail="Query not found")

    query.was_helpful = request.was_helpful
    query.feedback_comment = request.feedback_comment

    await db.commit()

    return {
        "status": "success",
        "message": "Feedback recorded",
        "query_id": request.query_id,
    }


@router.get("/natural/examples")
async def get_example_queries():
    """Get example natural language queries."""
    return {
        "examples": EXAMPLE_QUERIES,
        "tips": [
            "Use time phrases like 'yesterday', 'last week', 'past 24 hours'",
            "Specify severity: 'critical alerts', 'high severity'",
            "Ask for counts: 'count alerts by severity'",
            "Find top items: 'top 10 rules by alert count'",
            "Search by status: 'open alerts', 'resolved incidents'",
        ],
    }
