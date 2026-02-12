"""Scheduled Rule class for time-based detections."""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, ClassVar

from ..models.common import Severity
from .rule import Rule


class ScheduledRule(Rule):
    """
    Base class for Panther scheduled rules.

    Scheduled rules run on a schedule and query historical data rather than
    processing events in real-time. They're useful for:
    - Aggregation-based detections (e.g., more than N events in time window)
    - Correlation across multiple log sources
    - Detections that require historical context

    Example:
        ```python
        from panther_sdk.detections import ScheduledRule, Severity

        class ExcessiveFailedLogins(ScheduledRule):
            id = "Custom.ExcessiveFailedLogins"
            log_types = ["Okta.SystemLog"]
            severity = Severity.HIGH
            schedule_expression = "rate(15 minutes)"

            def rule(self, event):
                # event contains aggregated query results
                return event.get("failed_login_count", 0) > 10

            def title(self, event):
                return f"Excessive failed logins: {event.get('failed_login_count')} attempts"

            @property
            def scheduled_query(self):
                return '''
                SELECT
                    actor.alternateId as user,
                    COUNT(*) as failed_login_count
                FROM panther_logs.public.okta_systemlog
                WHERE
                    eventType = 'user.session.start'
                    AND outcome.result = 'FAILURE'
                    AND p_occurs_since('15 minutes')
                GROUP BY actor.alternateId
                HAVING COUNT(*) > 10
                '''
        ```
    """

    # Schedule configuration
    schedule_expression: ClassVar[str]  # e.g., "rate(15 minutes)" or "cron(0 * * * ? *)"
    timeout_minutes: ClassVar[int] = 5

    def __init__(self) -> None:
        """Initialize the scheduled rule."""
        super().__init__()
        self._validate_schedule()

    def _validate_schedule(self) -> None:
        """Validate schedule-specific attributes."""
        if not hasattr(self, "schedule_expression") or not self.schedule_expression:
            raise ValueError(
                f"{self.__class__.__name__} must define 'schedule_expression' class attribute"
            )

    @property
    @abstractmethod
    def scheduled_query(self) -> str:
        """
        The SQL query to run on schedule.

        This query should return rows that represent potential detections.
        Each row will be passed to the rule() method.

        Returns:
            SQL query string
        """
        pass

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the scheduled rule to a dictionary for API submission.

        Returns:
            Dictionary representation of the scheduled rule
        """
        base = super().to_dict()
        base.update({
            "scheduleExpression": self.schedule_expression,
            "timeoutMinutes": self.timeout_minutes,
            "scheduledQuery": self.scheduled_query,
        })
        return base
