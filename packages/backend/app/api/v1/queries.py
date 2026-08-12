from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.api.v1.deps import PantherServiceDep

router = APIRouter()


class QueryRequest(BaseModel):
    sql: str
    database: str | None = None
    timeout: float = 300.0


class QueryResponse(BaseModel):
    queryId: str
    status: str
    sql: str
    results: list[dict[str, Any]] = []
    columns: list[dict[str, str]] = []
    rowsScanned: int | None = None
    bytesScanned: int | None = None
    errorMessage: str | None = None


@router.post("/execute")
async def execute_query(
    request: QueryRequest,
    panther: PantherServiceDep,
) -> QueryResponse:
    """Execute a SQL query against the data lake."""
    try:
        result = await panther.execute_query(
            sql=request.sql,
            database=request.database,
            timeout=request.timeout,
        )
        return QueryResponse(
            queryId=result.get("queryId", ""),
            status=result.get("status", "UNKNOWN"),
            sql=result.get("sql", request.sql),
            results=result.get("results", []),
            columns=result.get("columns", []),
            rowsScanned=result.get("rowsScanned"),
            bytesScanned=result.get("bytesScanned"),
            errorMessage=result.get("errorMessage"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
