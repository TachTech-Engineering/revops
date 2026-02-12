"""Main PantherClient class for the Panther SDK."""

from __future__ import annotations

from typing import Any

from .api.base import BaseClient
from .api.graphql import GraphQLClient
from .api.rest import (
    AlertsResource,
    DataModelsResource,
    GlobalsResource,
    LogSourcesResource,
    PoliciesResource,
    QueriesResource,
    RolesResource,
    RulesResource,
    UsersResource,
)
from .config import PantherConfig, load_config


class PantherClient:
    """
    Main client for interacting with the Panther API.

    This client provides access to all Panther API resources through
    a unified interface. It supports both REST and GraphQL APIs.

    Example:
        ```python
        from panther_sdk import PantherClient

        # Initialize with explicit credentials
        client = PantherClient(
            api_host="your-instance.runpanther.net",
            api_token="your-api-token"
        )

        # Or use environment variables (PANTHER_API_HOST, PANTHER_API_TOKEN)
        client = PantherClient()

        # Access REST API resources
        for alert in client.alerts.list(status="OPEN"):
            print(alert.title)

        # Access GraphQL API
        stats = client.graphql.get_organization_stats()

        # Don't forget to close when done
        client.close()
        ```

    Using as a context manager:
        ```python
        with PantherClient() as client:
            alerts = list(client.alerts.list(severity="CRITICAL"))
        ```
    """

    def __init__(
        self,
        api_host: str | None = None,
        api_token: str | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the Panther client.

        Args:
            api_host: The Panther instance hostname (e.g., "your-instance.runpanther.net")
                     Can also be set via PANTHER_API_HOST environment variable.
            api_token: The API token for authentication.
                      Can also be set via PANTHER_API_TOKEN environment variable.
            **kwargs: Additional configuration options:
                - api_version: API version (default: "v1")
                - timeout: Request timeout in seconds (default: 30.0)
                - max_retries: Maximum retry attempts (default: 3)
                - verify_ssl: Whether to verify SSL certificates (default: True)
                - debug: Enable debug logging (default: False)

        Raises:
            ConfigurationError: If required configuration is missing.
        """
        self.config = load_config(api_host=api_host, api_token=api_token, **kwargs)
        self._base_client = BaseClient(self.config)
        self._graphql_client: GraphQLClient | None = None

        # Initialize REST API resources
        self._alerts: AlertsResource | None = None
        self._rules: RulesResource | None = None
        self._policies: PoliciesResource | None = None
        self._queries: QueriesResource | None = None
        self._users: UsersResource | None = None
        self._roles: RolesResource | None = None
        self._data_models: DataModelsResource | None = None
        self._log_sources: LogSourcesResource | None = None
        self._globals: GlobalsResource | None = None

    def __enter__(self) -> "PantherClient":
        """Enter context manager."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context manager and close connections."""
        self.close()

    async def __aenter__(self) -> "PantherClient":
        """Enter async context manager."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit async context manager and close connections."""
        await self.aclose()

    def close(self) -> None:
        """Close all HTTP connections."""
        self._base_client.close()
        if self._graphql_client:
            self._graphql_client.close()

    async def aclose(self) -> None:
        """Close all async HTTP connections."""
        await self._base_client.aclose()
        if self._graphql_client:
            await self._graphql_client.aclose()

    # REST API Resources

    @property
    def alerts(self) -> AlertsResource:
        """Access the Alerts API resource."""
        if self._alerts is None:
            self._alerts = AlertsResource(self._base_client)
        return self._alerts

    @property
    def rules(self) -> RulesResource:
        """Access the Rules API resource."""
        if self._rules is None:
            self._rules = RulesResource(self._base_client)
        return self._rules

    @property
    def policies(self) -> PoliciesResource:
        """Access the Policies API resource."""
        if self._policies is None:
            self._policies = PoliciesResource(self._base_client)
        return self._policies

    @property
    def queries(self) -> QueriesResource:
        """Access the Queries API resource for data lake queries."""
        if self._queries is None:
            self._queries = QueriesResource(self._base_client)
        return self._queries

    @property
    def users(self) -> UsersResource:
        """Access the Users API resource."""
        if self._users is None:
            self._users = UsersResource(self._base_client)
        return self._users

    @property
    def roles(self) -> RolesResource:
        """Access the Roles API resource."""
        if self._roles is None:
            self._roles = RolesResource(self._base_client)
        return self._roles

    @property
    def data_models(self) -> DataModelsResource:
        """Access the Data Models API resource."""
        if self._data_models is None:
            self._data_models = DataModelsResource(self._base_client)
        return self._data_models

    @property
    def log_sources(self) -> LogSourcesResource:
        """Access the Log Sources API resource."""
        if self._log_sources is None:
            self._log_sources = LogSourcesResource(self._base_client)
        return self._log_sources

    @property
    def globals(self) -> GlobalsResource:
        """Access the Globals API resource for helper modules."""
        if self._globals is None:
            self._globals = GlobalsResource(self._base_client)
        return self._globals

    # GraphQL API

    @property
    def graphql(self) -> GraphQLClient:
        """Access the GraphQL API client."""
        if self._graphql_client is None:
            self._graphql_client = GraphQLClient(self.config)
        return self._graphql_client
