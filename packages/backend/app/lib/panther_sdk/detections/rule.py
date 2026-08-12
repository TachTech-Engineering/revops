"""Base Rule class for detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from ..models.common import LogType, Severity


class Rule(ABC):
    """
    Base class for Panther detection rules.

    Subclass this to create custom detection rules. At minimum, you must
    define the `id`, `log_types`, `severity` class attributes and implement
    the `rule()` method.

    Example:
        ```python
        from panther_sdk.detections import Rule, Severity, LogType

        class SuspiciousLogin(Rule):
            id = "Custom.SuspiciousLogin"
            log_types = [LogType.OKTA_SYSTEM_LOG]
            severity = Severity.MEDIUM

            def rule(self, event):
                return (
                    event.get("eventType") == "user.session.start"
                    and event.get("client", {}).get("geographicalContext", {}).get("country")
                    == "RU"
                )

            def title(self, event):
                return f"Suspicious login from Russia for {event.get('actor', {}).get('email')}"
        ```
    """

    # Required class attributes
    id: ClassVar[str]
    log_types: ClassVar[list[str | LogType]]
    severity: ClassVar[Severity | str]

    # Optional class attributes with defaults
    enabled: ClassVar[bool] = True
    display_name: ClassVar[str | None] = None
    description: ClassVar[str | None] = None
    threshold: ClassVar[int] = 1
    dedup_period_minutes: ClassVar[int] = 60
    tags: ClassVar[list[str]] = []
    runbook: ClassVar[str | None] = None
    reference: ClassVar[str | None] = None
    reports: ClassVar[dict[str, list[str]]] = {}
    summary_attributes: ClassVar[list[str]] = []
    unit_tests: ClassVar[list[dict[str, Any]]] = []

    def __init__(self) -> None:
        """Initialize the rule and validate required attributes."""
        self._validate()

    def _validate(self) -> None:
        """Validate that required class attributes are defined."""
        if not hasattr(self, "id") or not self.id:
            raise ValueError(f"{self.__class__.__name__} must define 'id' class attribute")
        if not hasattr(self, "log_types") or not self.log_types:
            raise ValueError(f"{self.__class__.__name__} must define 'log_types' class attribute")
        if not hasattr(self, "severity"):
            raise ValueError(f"{self.__class__.__name__} must define 'severity' class attribute")

    @abstractmethod
    def rule(self, event: dict[str, Any]) -> bool:
        """
        The main detection logic.

        Args:
            event: The log event to analyze

        Returns:
            True if the rule matches (should alert), False otherwise
        """
        pass

    def title(self, event: dict[str, Any]) -> str:
        """
        Generate a dynamic title for the alert.

        Override this method to create context-aware titles.

        Args:
            event: The log event that triggered the rule

        Returns:
            Alert title string
        """
        return self.display_name or self.id

    def dedup(self, event: dict[str, Any]) -> str:
        """
        Generate a deduplication key for the alert.

        Events with the same dedup key within the dedup_period_minutes
        will be grouped into the same alert.

        Args:
            event: The log event

        Returns:
            Deduplication key string
        """
        return self.id

    def alert_context(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Add additional context to the alert.

        Override this to include relevant information in the alert.

        Args:
            event: The log event

        Returns:
            Dictionary of additional context
        """
        return {}

    def severity_override(self, event: dict[str, Any]) -> Severity | str | None:
        """
        Dynamically override the severity based on the event.

        Args:
            event: The log event

        Returns:
            New severity or None to use the default
        """
        return None

    def destinations(self, event: dict[str, Any]) -> list[str] | None:
        """
        Override alert destinations based on the event.

        Args:
            event: The log event

        Returns:
            List of destination IDs or None to use defaults
        """
        return None

    def runbook_override(self, event: dict[str, Any]) -> str | None:
        """
        Dynamically override the runbook based on the event.

        Args:
            event: The log event

        Returns:
            Runbook URL/text or None to use the default
        """
        return None

    def reference_override(self, event: dict[str, Any]) -> str | None:
        """
        Dynamically override the reference based on the event.

        Args:
            event: The log event

        Returns:
            Reference URL/text or None to use the default
        """
        return None

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the rule to a dictionary for API submission.

        Returns:
            Dictionary representation of the rule
        """
        return {
            "id": self.id,
            "displayName": self.display_name,
            "description": self.description,
            "enabled": self.enabled,
            "severity": self.severity if isinstance(self.severity, str) else self.severity.value,
            "logTypes": [lt if isinstance(lt, str) else lt.value for lt in self.log_types],
            "threshold": self.threshold,
            "dedupPeriodMinutes": self.dedup_period_minutes,
            "tags": self.tags,
            "runbook": self.runbook,
            "reference": self.reference,
            "reports": self.reports,
            "summaryAttributes": self.summary_attributes,
            "tests": self.unit_tests,
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.id}>"
