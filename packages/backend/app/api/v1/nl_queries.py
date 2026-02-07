"""
Natural Language Queries API - Feature 4
"Show failed logins last week" → SQL/filters.
"""
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgUserDep, OrgIdDep
from app.db import get_db, NLQueryHistory
from fastapi import Depends

router = APIRouter()


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


def translate_nl_to_sql(natural_query: str) -> tuple[str, str]:
    """
    Translate natural language to SQL.
    In production, this would use an LLM service.
    """
    query_lower = natural_query.lower()

    # Simple pattern matching for demo
    if "failed login" in query_lower:
        if "yesterday" in query_lower:
            sql = "SELECT * FROM normalized_alerts WHERE title ILIKE '%failed login%' AND created_at_source >= NOW() - INTERVAL '1 day' ORDER BY created_at_source DESC"
            explanation = "Searching for alerts with 'failed login' in the title from the last 24 hours"
        elif "last week" in query_lower or "past week" in query_lower:
            sql = "SELECT * FROM normalized_alerts WHERE title ILIKE '%failed login%' AND created_at_source >= NOW() - INTERVAL '7 days' ORDER BY created_at_source DESC"
            explanation = "Searching for alerts with 'failed login' in the title from the last 7 days"
        else:
            sql = "SELECT * FROM normalized_alerts WHERE title ILIKE '%failed login%' ORDER BY created_at_source DESC LIMIT 100"
            explanation = "Searching for recent alerts with 'failed login' in the title"

    elif "critical" in query_lower and "alert" in query_lower:
        if "today" in query_lower or "24 hour" in query_lower:
            sql = "SELECT * FROM normalized_alerts WHERE severity = 'critical' AND created_at_source >= NOW() - INTERVAL '24 hours' ORDER BY created_at_source DESC"
            explanation = "Finding critical severity alerts from the last 24 hours"
        else:
            sql = "SELECT * FROM normalized_alerts WHERE severity = 'critical' ORDER BY created_at_source DESC LIMIT 100"
            explanation = "Finding recent critical severity alerts"

    elif "count" in query_lower and "severity" in query_lower:
        if "week" in query_lower:
            sql = "SELECT severity, COUNT(*) as count FROM normalized_alerts WHERE created_at_source >= NOW() - INTERVAL '7 days' GROUP BY severity ORDER BY count DESC"
            explanation = "Counting alerts by severity for the past week"
        else:
            sql = "SELECT severity, COUNT(*) as count FROM normalized_alerts GROUP BY severity ORDER BY count DESC"
            explanation = "Counting all alerts by severity"

    elif "top" in query_lower and "rule" in query_lower:
        limit = 10
        for word in query_lower.split():
            if word.isdigit():
                limit = int(word)
                break
        sql = f"SELECT rule_id, rule_name, COUNT(*) as alert_count FROM normalized_alerts GROUP BY rule_id, rule_name ORDER BY alert_count DESC LIMIT {limit}"
        explanation = f"Finding the top {limit} rules by alert count"

    elif "open" in query_lower and "alert" in query_lower:
        sql = "SELECT * FROM normalized_alerts WHERE status = 'open' ORDER BY created_at_source DESC LIMIT 100"
        explanation = "Finding alerts with open status"

    elif "incident" in query_lower:
        if "open" in query_lower:
            sql = "SELECT * FROM incidents WHERE status = 'open' ORDER BY created_at DESC LIMIT 50"
            explanation = "Finding open incidents"
        else:
            sql = "SELECT * FROM incidents ORDER BY created_at DESC LIMIT 50"
            explanation = "Finding recent incidents"

    else:
        # Default: search in alert titles
        search_terms = [w for w in natural_query.split() if len(w) > 3]
        if search_terms:
            conditions = " OR ".join([f"title ILIKE '%{term}%'" for term in search_terms[:3]])
            sql = f"SELECT * FROM normalized_alerts WHERE {conditions} ORDER BY created_at_source DESC LIMIT 100"
            explanation = f"Searching for alerts containing: {', '.join(search_terms[:3])}"
        else:
            sql = "SELECT * FROM normalized_alerts ORDER BY created_at_source DESC LIMIT 50"
            explanation = "Showing recent alerts"

    return sql, explanation


@router.post("/natural", response_model=NLQueryResponse)
async def execute_natural_query(
    request: NLQueryRequest,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Parse and execute a natural language query."""
    start_time = datetime.utcnow()

    # Translate NL to SQL
    generated_sql, explanation = translate_nl_to_sql(request.query)

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
            # In production, this would execute the query against the data lake
            # For safety, we only allow SELECT queries
            if not generated_sql.strip().upper().startswith("SELECT"):
                raise HTTPException(status_code=400, detail="Only SELECT queries are allowed")

            # Demo: return mock results
            results = [
                {"id": "alert-1", "title": "Sample Alert 1", "severity": "high"},
                {"id": "alert-2", "title": "Sample Alert 2", "severity": "medium"},
            ]
            row_count = len(results)

            end_time = datetime.utcnow()
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            history.row_count = row_count
            history.execution_time_ms = execution_time_ms

        except Exception as e:
            error_message = str(e)
            history.error_message = error_message

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
