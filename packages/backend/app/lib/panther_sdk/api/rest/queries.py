"""Queries REST API resource."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field

from ...models.common import BaseModelConfig
from ..base import BaseClient


class QueryStatus(StrEnum):
    """Query execution status."""

    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class QueryResult(BaseModelConfig):
    """Query execution result."""

    query_id: str = Field(alias="queryId")
    status: QueryStatus
    sql: str
    started_at: datetime | None = Field(default=None, alias="startedAt")
    completed_at: datetime | None = Field(default=None, alias="completedAt")
    rows_scanned: int | None = Field(default=None, alias="rowsScanned")
    bytes_scanned: int | None = Field(default=None, alias="bytesScanned")
    error_message: str | None = Field(default=None, alias="errorMessage")
    results: list[dict[str, Any]] = Field(default_factory=list)
    columns: list[dict[str, str]] = Field(default_factory=list)


class QueriesResource:
    """REST API resource for running data lake queries."""

    def __init__(self, client: BaseClient) -> None:
        self._client = client
        self._path = "/queries"

    def create(
        self,
        sql: str,
        database: str | None = None,
    ) -> QueryResult:
        """
        Start a new query execution.

        Args:
            sql: SQL query to execute
            database: Database to query (defaults to panther_logs)

        Returns:
            QueryResult with query_id and initial status
        """
        payload: dict[str, Any] = {"sql": sql}
        if database:
            payload["database"] = database

        data = self._client.post(self._path, json=payload)
        return QueryResult.model_validate(data)

    async def acreate(
        self,
        sql: str,
        database: str | None = None,
    ) -> QueryResult:
        """Async version of create()."""
        payload: dict[str, Any] = {"sql": sql}
        if database:
            payload["database"] = database

        data = await self._client.apost(self._path, json=payload)
        return QueryResult.model_validate(data)

    def get_results(
        self,
        query_id: str,
        page_size: int = 1000,
        cursor: str | None = None,
    ) -> QueryResult:
        """
        Get results for a query.

        Args:
            query_id: The query ID
            page_size: Number of rows to return
            cursor: Pagination cursor

        Returns:
            QueryResult with status and results (if complete)
        """
        params: dict[str, Any] = {"pageSize": page_size}
        if cursor:
            params["cursor"] = cursor

        data = self._client.get(f"{self._path}/{query_id}", params=params)
        return QueryResult.model_validate(data)

    async def aget_results(
        self,
        query_id: str,
        page_size: int = 1000,
        cursor: str | None = None,
    ) -> QueryResult:
        """Async version of get_results()."""
        params: dict[str, Any] = {"pageSize": page_size}
        if cursor:
            params["cursor"] = cursor

        data = await self._client.aget(f"{self._path}/{query_id}", params=params)
        return QueryResult.model_validate(data)

    def cancel(self, query_id: str) -> QueryResult:
        """
        Cancel a running query.

        Args:
            query_id: The query ID to cancel

        Returns:
            QueryResult with updated status
        """
        data = self._client.post(f"{self._path}/{query_id}/cancel")
        return QueryResult.model_validate(data)

    async def acancel(self, query_id: str) -> QueryResult:
        """Async version of cancel()."""
        data = await self._client.apost(f"{self._path}/{query_id}/cancel")
        return QueryResult.model_validate(data)

    def execute(
        self,
        sql: str,
        database: str | None = None,
        poll_interval: float = 1.0,
        timeout: float = 300.0,
    ) -> QueryResult:
        """
        Execute a query and wait for results.

        This is a convenience method that creates a query and polls
        until it completes or times out.

        Args:
            sql: SQL query to execute
            database: Database to query
            poll_interval: Seconds between status checks
            timeout: Maximum seconds to wait

        Returns:
            QueryResult with results

        Raises:
            TimeoutError: If query doesn't complete within timeout
        """
        import time

        result = self.create(sql, database)
        start_time = time.time()

        while result.status == QueryStatus.RUNNING:
            if time.time() - start_time > timeout:
                self.cancel(result.query_id)
                raise TimeoutError(f"Query {result.query_id} timed out after {timeout}s")

            time.sleep(poll_interval)
            result = self.get_results(result.query_id)

        return result

    async def aexecute(
        self,
        sql: str,
        database: str | None = None,
        poll_interval: float = 1.0,
        timeout: float = 300.0,
    ) -> QueryResult:
        """Async version of execute()."""
        import asyncio
        import time

        result = await self.acreate(sql, database)
        start_time = time.time()

        while result.status == QueryStatus.RUNNING:
            if time.time() - start_time > timeout:
                await self.acancel(result.query_id)
                raise TimeoutError(f"Query {result.query_id} timed out after {timeout}s")

            await asyncio.sleep(poll_interval)
            result = await self.aget_results(result.query_id)

        return result
