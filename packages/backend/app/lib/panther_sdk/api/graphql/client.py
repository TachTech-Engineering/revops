"""GraphQL client for the Panther SDK."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import httpx

from ...config import PantherConfig
from ...exceptions import GraphQLError


class GraphQLClient:
    """GraphQL API client for Panther."""

    def __init__(self, config: PantherConfig) -> None:
        self.config = config
        self._client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "panther-sdk/0.1.0",
        }

    @property
    def client(self) -> httpx.Client:
        """Get or create the sync HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.config.graphql_url,
                headers=self._headers,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )
        return self._client

    @property
    def async_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                base_url=self.config.graphql_url,
                headers=self._headers,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )
        return self._async_client

    def close(self) -> None:
        """Close the sync HTTP client."""
        if self._client is not None:
            self._client.close()
            self._client = None

    async def aclose(self) -> None:
        """Close the async HTTP client."""
        if self._async_client is not None:
            await self._async_client.aclose()
            self._async_client = None

    def _handle_response(self, data: dict[str, Any]) -> dict[str, Any]:
        """Handle GraphQL response and raise appropriate exceptions."""
        if "errors" in data and data["errors"]:
            raise GraphQLError(data["errors"])
        return data.get("data", {})

    def execute(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
    ) -> dict[str, Any]:
        """
        Execute a GraphQL query or mutation synchronously.

        Args:
            query: The GraphQL query or mutation string
            variables: Optional variables for the query
            operation_name: Optional operation name

        Returns:
            The data from the GraphQL response

        Raises:
            GraphQLError: If the response contains errors
        """
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name

        response = self.client.post("", json=payload)
        response.raise_for_status()
        return self._handle_response(response.json())

    async def aexecute(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
    ) -> dict[str, Any]:
        """
        Execute a GraphQL query or mutation asynchronously.

        Args:
            query: The GraphQL query or mutation string
            variables: Optional variables for the query
            operation_name: Optional operation name

        Returns:
            The data from the GraphQL response

        Raises:
            GraphQLError: If the response contains errors
        """
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name

        response = await self.async_client.post("", json=payload)
        response.raise_for_status()
        return self._handle_response(response.json())

    # Convenience methods for common operations

    def query_alerts(
        self,
        status: list[str] | None = None,
        severity: list[str] | None = None,
        created_after: datetime | None = None,
        created_before: datetime | None = None,
        first: int = 50,
        after: str | None = None,
    ) -> dict[str, Any]:
        """
        Query alerts using GraphQL.

        Args:
            status: Filter by alert statuses
            severity: Filter by severities
            created_after: Filter alerts created after this datetime
            created_before: Filter alerts created before this datetime
            first: Number of results to return
            after: Cursor for pagination

        Returns:
            GraphQL response data
        """
        query = """
        query ListAlerts($input: AlertsInput!) {
            alerts(input: $input) {
                edges {
                    node {
                        id
                        title
                        severity
                        status
                        createdAt
                        updatedAt
                        detection {
                            id
                            displayName
                        }
                    }
                    cursor
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """
        # Default to last 30 days if no date range specified
        if created_after is None and created_before is None:
            created_after = datetime.utcnow() - timedelta(days=30)

        variables: dict[str, Any] = {
            "input": {
                "first": first,
                "createdAtAfter": created_after.isoformat() + "Z" if created_after else None,
            }
        }
        if created_before:
            variables["input"]["createdAtBefore"] = created_before.isoformat() + "Z"
        if status:
            variables["input"]["status"] = status
        if severity:
            variables["input"]["severity"] = severity
        if after:
            variables["input"]["after"] = after

        # Remove None values
        variables["input"] = {k: v for k, v in variables["input"].items() if v is not None}

        return self.execute(query, variables)

    async def aquery_alerts(
        self,
        status: list[str] | None = None,
        severity: list[str] | None = None,
        created_after: datetime | None = None,
        created_before: datetime | None = None,
        first: int = 50,
        after: str | None = None,
    ) -> dict[str, Any]:
        """Async version of query_alerts()."""
        query = """
        query ListAlerts($input: AlertsInput!) {
            alerts(input: $input) {
                edges {
                    node {
                        id
                        title
                        severity
                        status
                        createdAt
                        updatedAt
                        detection {
                            id
                            displayName
                        }
                    }
                    cursor
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """
        # Default to last 30 days if no date range specified
        if created_after is None and created_before is None:
            created_after = datetime.utcnow() - timedelta(days=30)

        variables: dict[str, Any] = {
            "input": {
                "first": first,
                "createdAtAfter": created_after.isoformat() + "Z" if created_after else None,
            }
        }
        if created_before:
            variables["input"]["createdAtBefore"] = created_before.isoformat() + "Z"
        if status:
            variables["input"]["status"] = status
        if severity:
            variables["input"]["severity"] = severity
        if after:
            variables["input"]["after"] = after

        # Remove None values
        variables["input"] = {k: v for k, v in variables["input"].items() if v is not None}

        return await self.aexecute(query, variables)

    def query_detections(
        self,
        enabled: bool | None = None,
        severity: list[str] | None = None,
        first: int = 50,
        after: str | None = None,
    ) -> dict[str, Any]:
        """
        Query detections (rules and policies) using GraphQL.

        Args:
            enabled: Filter by enabled status
            severity: Filter by severities
            first: Number of results to return
            after: Cursor for pagination

        Returns:
            GraphQL response data
        """
        query = """
        query ListDetections($input: DetectionsInput!) {
            detections(input: $input) {
                edges {
                    node {
                        ... on Rule {
                            id
                            displayName
                            severity
                            enabled
                            logTypes
                            createdAt
                            updatedAt
                        }
                        ... on Policy {
                            id
                            displayName
                            severity
                            enabled
                            resourceTypes
                            createdAt
                            updatedAt
                        }
                    }
                    cursor
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """
        variables: dict[str, Any] = {
            "input": {
                "first": first,
            }
        }
        if enabled is not None:
            variables["input"]["enabled"] = enabled
        if severity:
            variables["input"]["severity"] = severity
        if after:
            variables["input"]["after"] = after

        return self.execute(query, variables)

    async def aquery_detections(
        self,
        enabled: bool | None = None,
        severity: list[str] | None = None,
        first: int = 50,
        after: str | None = None,
    ) -> dict[str, Any]:
        """Async version of query_detections()."""
        query = """
        query ListDetections($input: DetectionsInput!) {
            detections(input: $input) {
                edges {
                    node {
                        ... on Rule {
                            id
                            displayName
                            severity
                            enabled
                            logTypes
                            createdAt
                            updatedAt
                        }
                        ... on Policy {
                            id
                            displayName
                            severity
                            enabled
                            resourceTypes
                            createdAt
                            updatedAt
                        }
                    }
                    cursor
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """
        variables: dict[str, Any] = {
            "input": {
                "first": first,
            }
        }
        if enabled is not None:
            variables["input"]["enabled"] = enabled
        if severity:
            variables["input"]["severity"] = severity
        if after:
            variables["input"]["after"] = after

        return await self.aexecute(query, variables)

    def get_organization_stats(self) -> dict[str, Any]:
        """
        Get organization statistics.

        Returns:
            GraphQL response data with org stats
        """
        query = """
        query GetOrgStats {
            organizationStats {
                alertStats {
                    total
                    byStatus {
                        status
                        count
                    }
                    bySeverity {
                        severity
                        count
                    }
                }
                detectionStats {
                    totalRules
                    totalPolicies
                    enabledRules
                    enabledPolicies
                }
                logStats {
                    totalSources
                    activeSources
                    bytesProcessedToday
                    eventsProcessedToday
                }
            }
        }
        """
        return self.execute(query)

    async def aget_organization_stats(self) -> dict[str, Any]:
        """Async version of get_organization_stats()."""
        query = """
        query GetOrgStats {
            organizationStats {
                alertStats {
                    total
                    byStatus {
                        status
                        count
                    }
                    bySeverity {
                        severity
                        count
                    }
                }
                detectionStats {
                    totalRules
                    totalPolicies
                    enabledRules
                    enabledPolicies
                }
                logStats {
                    totalSources
                    activeSources
                    bytesProcessedToday
                    eventsProcessedToday
                }
            }
        }
        """
        return await self.aexecute(query)
