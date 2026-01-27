"""
Base classes for the Connector Framework.

Provides abstract base classes for data source connectors (SIEM integrations)
and action connectors (response integrations).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncGenerator, Optional
import uuid

from app.db.models import NormalizedAlert, ConnectorCategory


@dataclass
class ConnectionTestResult:
    """Result of testing a connector's connection."""
    success: bool
    message: str
    details: Optional[dict[str, Any]] = None
    latency_ms: Optional[int] = None


@dataclass
class ActionResult:
    """Result of executing an action via a connector."""
    success: bool
    message: str
    output: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time_ms: Optional[int] = None


@dataclass
class ConnectorMetadata:
    """Metadata describing a connector type."""
    connector_type: str
    category: ConnectorCategory
    display_name: str
    description: str
    icon: str  # Icon identifier or URL
    config_schema: dict[str, Any]  # JSON Schema for non-sensitive config
    credentials_schema: dict[str, Any]  # JSON Schema for credentials


class DataSourceConnector(ABC):
    """
    Base class for SIEM data source connectors.

    Implementations fetch alerts from various SIEM platforms and normalize
    them to a common schema for unified analysis and workflow triggering.
    """

    def __init__(self, connector_id: uuid.UUID, config: dict[str, Any], credentials: dict[str, Any]):
        """
        Initialize a data source connector.

        Args:
            connector_id: UUID of the connector record in database
            config: Non-sensitive configuration (base URL, etc.)
            credentials: Decrypted sensitive credentials (API keys, tokens, etc.)
        """
        self.connector_id = connector_id
        self.config = config
        self.credentials = credentials

    @classmethod
    @abstractmethod
    def get_metadata(cls) -> ConnectorMetadata:
        """
        Get metadata describing this connector type.

        Returns:
            ConnectorMetadata with display info and schemas
        """
        pass

    @abstractmethod
    async def test_connection(self) -> ConnectionTestResult:
        """
        Test the connection to the data source.

        Returns:
            ConnectionTestResult indicating success/failure with details
        """
        pass

    @abstractmethod
    async def fetch_alerts(
        self,
        since: datetime,
        limit: int = 100,
        cursor: Optional[str] = None
    ) -> tuple[list[NormalizedAlert], Optional[str]]:
        """
        Fetch alerts from the data source.

        Args:
            since: Only fetch alerts created after this timestamp
            limit: Maximum number of alerts to fetch
            cursor: Pagination cursor from previous fetch

        Returns:
            Tuple of (list of normalized alerts, next cursor or None)
        """
        pass

    @abstractmethod
    def normalize_alert(self, raw_alert: dict[str, Any]) -> NormalizedAlert:
        """
        Normalize a raw alert from the source to the unified schema.

        Args:
            raw_alert: Raw alert data from the source API

        Returns:
            NormalizedAlert with standardized fields
        """
        pass

    def normalize_severity(self, source_severity: str) -> str:
        """
        Normalize severity to standard values: critical, high, medium, low, info.
        Override in subclasses for source-specific mappings.

        Args:
            source_severity: Severity string from source system

        Returns:
            Normalized severity string
        """
        severity_map = {
            # Common variations
            "critical": "critical",
            "crit": "critical",
            "high": "high",
            "medium": "medium",
            "med": "medium",
            "low": "low",
            "info": "info",
            "informational": "info",
            # Numeric mappings
            "5": "critical",
            "4": "high",
            "3": "medium",
            "2": "low",
            "1": "info",
        }
        return severity_map.get(source_severity.lower(), "medium")

    def normalize_status(self, source_status: str) -> str:
        """
        Normalize status to standard values: open, acknowledged, resolved, closed.
        Override in subclasses for source-specific mappings.

        Args:
            source_status: Status string from source system

        Returns:
            Normalized status string
        """
        status_map = {
            # Common variations
            "open": "open",
            "new": "open",
            "pending": "open",
            "acknowledged": "acknowledged",
            "ack": "acknowledged",
            "in_progress": "acknowledged",
            "triaged": "acknowledged",
            "resolved": "resolved",
            "closed": "closed",
            "dismissed": "closed",
        }
        return status_map.get(source_status.lower(), "open")


class ActionConnector(ABC):
    """
    Base class for action connectors.

    Implementations execute response actions like creating tickets,
    sending notifications, or triggering EDR actions.
    """

    def __init__(self, connector_id: uuid.UUID, config: dict[str, Any], credentials: dict[str, Any]):
        """
        Initialize an action connector.

        Args:
            connector_id: UUID of the connector record in database
            config: Non-sensitive configuration
            credentials: Decrypted sensitive credentials
        """
        self.connector_id = connector_id
        self.config = config
        self.credentials = credentials

    @classmethod
    @abstractmethod
    def get_metadata(cls) -> ConnectorMetadata:
        """
        Get metadata describing this connector type.

        Returns:
            ConnectorMetadata with display info and schemas
        """
        pass

    @abstractmethod
    async def test_connection(self) -> ConnectionTestResult:
        """
        Test the connection to the action target.

        Returns:
            ConnectionTestResult indicating success/failure with details
        """
        pass

    @abstractmethod
    async def execute(self, action_config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """
        Execute an action.

        Args:
            action_config: Action-specific configuration (ticket fields, message content, etc.)
            context: Workflow execution context with trigger data and step outputs

        Returns:
            ActionResult with success status and output data
        """
        pass

    @classmethod
    @abstractmethod
    def get_action_schema(cls) -> dict[str, Any]:
        """
        Get JSON Schema for action configuration.

        Returns:
            JSON Schema describing available action parameters
        """
        pass


class ConnectorRegistry:
    """
    Registry for available connector types.

    Maintains a mapping of connector type strings to their implementation classes.
    Used by the connector service to instantiate connectors.
    """

    def __init__(self):
        self._data_sources: dict[str, type[DataSourceConnector]] = {}
        self._actions: dict[str, type[ActionConnector]] = {}

    def register_data_source(self, connector_type: str, cls: type[DataSourceConnector]) -> None:
        """Register a data source connector type."""
        self._data_sources[connector_type] = cls

    def register_action(self, connector_type: str, cls: type[ActionConnector]) -> None:
        """Register an action connector type."""
        self._actions[connector_type] = cls

    def get_data_source(self, connector_type: str) -> type[DataSourceConnector] | None:
        """Get data source connector class by type."""
        return self._data_sources.get(connector_type)

    def get_action(self, connector_type: str) -> type[ActionConnector] | None:
        """Get action connector class by type."""
        return self._actions.get(connector_type)

    def list_data_sources(self) -> list[ConnectorMetadata]:
        """List all registered data source types with metadata."""
        return [cls.get_metadata() for cls in self._data_sources.values()]

    def list_actions(self) -> list[ConnectorMetadata]:
        """List all registered action types with metadata."""
        return [cls.get_metadata() for cls in self._actions.values()]

    def list_all(self) -> list[ConnectorMetadata]:
        """List all registered connector types with metadata."""
        return self.list_data_sources() + self.list_actions()


# Global registry instance
_registry: ConnectorRegistry | None = None


def get_connector_registry() -> ConnectorRegistry:
    """
    Get the global connector registry.

    Returns:
        ConnectorRegistry singleton instance
    """
    global _registry
    if _registry is None:
        _registry = ConnectorRegistry()
        # Register all available connectors
        _register_all_connectors(_registry)
    return _registry


def _register_all_connectors(registry: ConnectorRegistry) -> None:
    """Register all available connector implementations."""
    # Import and register data sources
    from app.services.connectors.data_sources.panther import PantherDataSourceConnector
    from app.services.connectors.data_sources.google_secops import GoogleSecOpsConnector
    from app.services.connectors.data_sources.splunk import SplunkConnector
    from app.services.connectors.data_sources.sentinel import SentinelConnector
    from app.services.connectors.data_sources.elastic import ElasticConnector

    registry.register_data_source("panther", PantherDataSourceConnector)
    registry.register_data_source("google_secops", GoogleSecOpsConnector)
    registry.register_data_source("splunk", SplunkConnector)
    registry.register_data_source("sentinel", SentinelConnector)
    registry.register_data_source("elastic", ElasticConnector)

    # Import and register action connectors
    from app.services.connectors.actions.jira import JiraActionConnector
    from app.services.connectors.actions.slack import SlackActionConnector
    from app.services.connectors.actions.pagerduty import PagerDutyActionConnector
    from app.services.connectors.actions.teams import TeamsActionConnector
    from app.services.connectors.actions.crowdstrike import CrowdStrikeActionConnector
    from app.services.connectors.actions.sentinelone import SentinelOneActionConnector
    from app.services.connectors.actions.servicenow import ServiceNowActionConnector
    from app.services.connectors.actions.webhook import WebhookActionConnector
    from app.services.connectors.actions.http import HTTPActionConnector

    registry.register_action("jira", JiraActionConnector)
    registry.register_action("slack", SlackActionConnector)
    registry.register_action("pagerduty", PagerDutyActionConnector)
    registry.register_action("teams", TeamsActionConnector)
    registry.register_action("crowdstrike", CrowdStrikeActionConnector)
    registry.register_action("sentinelone", SentinelOneActionConnector)
    registry.register_action("servicenow", ServiceNowActionConnector)
    registry.register_action("webhook", WebhookActionConnector)
    registry.register_action("http", HTTPActionConnector)
