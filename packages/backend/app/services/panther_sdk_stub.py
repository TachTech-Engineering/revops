"""Stub module for panther_sdk - provides placeholder classes until real SDK is available."""
from typing import Any, Optional, AsyncIterator
from enum import Enum


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    CLOSED = "CLOSED"
    RESOLVED = "RESOLVED"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PantherError(Exception):
    """Base exception for Panther errors."""
    pass


class NotFoundError(PantherError):
    """Resource not found error."""
    pass


class AlertsClient:
    """Stub alerts client."""

    def __init__(self, api_host: str, api_token: str):
        self._api_host = api_host
        self._api_token = api_token

    async def alist(self, **kwargs) -> AsyncIterator[Any]:
        """List alerts - stub returns empty iterator."""
        return
        yield  # Make this a generator

    async def aget(self, alert_id: str) -> Any:
        raise NotFoundError(f"Alert not found: {alert_id}")

    async def aupdate(self, alert_id: str, **kwargs) -> Any:
        raise NotFoundError(f"Alert not found: {alert_id}")

    async def aget_events(self, alert_id: str, **kwargs) -> AsyncIterator[Any]:
        return
        yield

    async def aadd_comment(self, alert_id: str, body: str) -> Any:
        raise NotFoundError(f"Alert not found: {alert_id}")


class RulesClient:
    """Stub rules client."""

    def __init__(self, api_host: str, api_token: str):
        self._api_host = api_host
        self._api_token = api_token

    async def alist(self, **kwargs) -> AsyncIterator[Any]:
        return
        yield

    async def aget(self, rule_id: str) -> Any:
        raise NotFoundError(f"Rule not found: {rule_id}")

    async def acreate(self, **kwargs) -> Any:
        raise PantherError("Rule creation not implemented in stub")

    async def aupdate(self, rule_id: str, **kwargs) -> Any:
        raise NotFoundError(f"Rule not found: {rule_id}")

    async def adelete(self, rule_id: str) -> None:
        raise NotFoundError(f"Rule not found: {rule_id}")

    async def atest(self, rule_id: str) -> Any:
        raise NotFoundError(f"Rule not found: {rule_id}")


class QueriesClient:
    """Stub queries client."""

    def __init__(self, api_host: str, api_token: str):
        self._api_host = api_host
        self._api_token = api_token

    async def aexecute(self, sql: str, **kwargs) -> Any:
        raise PantherError("Query execution not implemented in stub")


class PantherClient:
    """Stub Panther client - placeholder until real SDK is available."""

    def __init__(self, api_host: str, api_token: str, debug: bool = False):
        self._api_host = api_host
        self._api_token = api_token
        self._debug = debug
        self.alerts = AlertsClient(api_host, api_token)
        self.rules = RulesClient(api_host, api_token)
        self.queries = QueriesClient(api_host, api_token)

    async def aclose(self) -> None:
        """Close the client."""
        pass
