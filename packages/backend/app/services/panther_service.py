"""Service layer wrapping the Panther SDK."""

from typing import Any

from app.lib.panther_sdk import (
    AlertStatus,
    NotFoundError,
    PantherClient,
    PantherError,
    Severity,
)


class PantherService:
    """
    Service layer wrapping the Panther SDK.

    Provides async interface and handles error translation.
    """

    def __init__(self, api_host: str, api_token: str):
        self._api_host = api_host
        self._api_token = api_token
        self._client: PantherClient | None = None

    @property
    def client(self) -> PantherClient:
        if self._client is None:
            self._client = PantherClient(
                api_host=self._api_host,
                api_token=self._api_token,
                debug=True,
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    # Alert methods
    async def list_alerts(
        self,
        status: str | None = None,
        severity: str | None = None,
        detection_id: str | None = None,
        created_after: Any | None = None,
        created_before: Any | None = None,
        page_size: int = 50,
        max_items: int | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """List alerts with pagination."""
        try:
            alerts = []
            async for alert in self.client.alerts.alist(
                status=AlertStatus(status) if status else None,
                severity=Severity(severity) if severity else None,
                detection_id=detection_id,
                created_after=created_after,
                created_before=created_before,
                page_size=page_size,
                max_items=max_items or page_size,
            ):
                alerts.append(alert.model_dump(by_alias=True))
            return alerts, None
        except PantherError as e:
            raise RuntimeError(str(e)) from e

    async def get_alert(self, alert_id: str) -> dict[str, Any]:
        """Get a single alert."""
        try:
            alert = await self.client.alerts.aget(alert_id)
            return alert.model_dump(by_alias=True)
        except NotFoundError as e:
            raise ValueError(f"Alert not found: {alert_id}") from e
        except PantherError as e:
            raise RuntimeError(str(e)) from e

    async def update_alert(
        self,
        alert_id: str,
        status: str | None = None,
        assignee_id: str | None = None,
    ) -> dict[str, Any]:
        """Update an alert."""
        try:
            alert = await self.client.alerts.aupdate(
                alert_id,
                status=AlertStatus(status) if status else None,
                assignee_id=assignee_id,
            )
            return alert.model_dump(by_alias=True)
        except NotFoundError as e:
            raise ValueError(f"Alert not found: {alert_id}") from e
        except PantherError as e:
            raise RuntimeError(str(e)) from e

    async def get_alert_events(
        self,
        alert_id: str,
        page_size: int = 50,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Get events for an alert."""
        try:
            events = []
            async for event in self.client.alerts.aget_events(
                alert_id, page_size=page_size, max_items=page_size
            ):
                events.append(event.model_dump(by_alias=True))
            return events, None
        except PantherError as e:
            raise RuntimeError(str(e)) from e

    async def add_alert_comment(self, alert_id: str, body: str) -> dict[str, Any]:
        """Add a comment to an alert."""
        try:
            comment = await self.client.alerts.aadd_comment(alert_id, body)
            return comment.model_dump(by_alias=True)
        except PantherError as e:
            raise RuntimeError(str(e)) from e

    # Rule methods
    async def list_rules(
        self,
        enabled: bool | None = None,
        severity: str | None = None,
        log_types: list[str] | None = None,
        tags: list[str] | None = None,
        page_size: int = 50,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """List rules with pagination."""
        try:
            rules = []
            async for rule in self.client.rules.alist(
                enabled=enabled,
                severity=Severity(severity) if severity else None,
                log_types=log_types,
                tags=tags,
                page_size=page_size,
                max_items=page_size,
            ):
                rules.append(rule.model_dump(by_alias=True))
            return rules, None
        except PantherError as e:
            raise RuntimeError(str(e)) from e

    async def get_rule(self, rule_id: str) -> dict[str, Any]:
        """Get a single rule."""
        try:
            rule = await self.client.rules.aget(rule_id)
            return rule.model_dump(by_alias=True)
        except NotFoundError as e:
            raise ValueError(f"Rule not found: {rule_id}") from e
        except PantherError as e:
            raise RuntimeError(str(e)) from e

    async def create_rule(self, rule_data: dict[str, Any]) -> dict[str, Any]:
        """Create a new rule."""
        try:
            rule = await self.client.rules.acreate(
                id=rule_data["id"],
                body=rule_data["body"],
                severity=Severity(rule_data["severity"]),
                log_types=rule_data["logTypes"],
                display_name=rule_data.get("displayName"),
                description=rule_data.get("description"),
                enabled=rule_data.get("enabled", True),
                dedup_period_minutes=rule_data.get("dedupPeriodMinutes", 60),
                threshold=rule_data.get("threshold", 1),
                tags=rule_data.get("tags", []),
                runbook=rule_data.get("runbook"),
                reference=rule_data.get("reference"),
            )
            return rule.model_dump(by_alias=True)
        except PantherError as e:
            raise RuntimeError(str(e)) from e

    async def update_rule(self, rule_id: str, update_data: dict[str, Any]) -> dict[str, Any]:
        """Update an existing rule."""
        try:
            rule = await self.client.rules.aupdate(
                rule_id,
                body=update_data.get("body"),
                severity=Severity(update_data["severity"]) if "severity" in update_data else None,
                log_types=update_data.get("logTypes"),
                display_name=update_data.get("displayName"),
                description=update_data.get("description"),
                enabled=update_data.get("enabled"),
                dedup_period_minutes=update_data.get("dedupPeriodMinutes"),
                threshold=update_data.get("threshold"),
                tags=update_data.get("tags"),
            )
            return rule.model_dump(by_alias=True)
        except NotFoundError as e:
            raise ValueError(f"Rule not found: {rule_id}") from e
        except PantherError as e:
            raise RuntimeError(str(e)) from e

    async def delete_rule(self, rule_id: str) -> None:
        """Delete a rule."""
        try:
            await self.client.rules.adelete(rule_id)
        except NotFoundError as e:
            raise ValueError(f"Rule not found: {rule_id}") from e
        except PantherError as e:
            raise RuntimeError(str(e)) from e

    async def test_rule(self, rule_id: str) -> dict[str, Any]:
        """Run tests for a rule."""
        try:
            result = await self.client.rules.atest(rule_id)
            return result
        except NotFoundError as e:
            raise ValueError(f"Rule not found: {rule_id}") from e
        except PantherError as e:
            raise RuntimeError(str(e)) from e

    # Query methods
    async def execute_query(
        self,
        sql: str,
        database: str | None = None,
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        """Execute a SQL query against the data lake."""
        try:
            result = await self.client.queries.aexecute(
                sql=sql,
                database=database,
                timeout=timeout,
            )
            return result.model_dump(by_alias=True)
        except TimeoutError as e:
            raise RuntimeError(f"Query timed out: {e}") from e
        except PantherError as e:
            raise RuntimeError(str(e)) from e

    async def get_alert_stats(
        self,
        days: int = 7,
    ) -> dict[str, Any]:
        """Get alert statistics for analytics."""
        try:
            # Get alerts for the time period

            alerts = []
            async for alert in self.client.alerts.alist(
                page_size=100,
                max_items=1000,
            ):
                alerts.append(alert.model_dump(by_alias=True))

            # Aggregate stats
            severity_counts = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            status_counts = {"OPEN": 0, "TRIAGED": 0, "CLOSED": 0, "RESOLVED": 0}
            daily_counts: dict[str, int] = {}
            rule_counts: dict[str, int] = {}

            for alert in alerts:
                # Count by severity
                sev = alert.get("severity", "INFO")
                if sev in severity_counts:
                    severity_counts[sev] += 1

                # Count by status
                status = alert.get("status", "OPEN")
                if status in status_counts:
                    status_counts[status] += 1

                # Count by day
                created = alert.get("createdAt")
                if created:
                    if isinstance(created, str):
                        day = created[:10]
                    else:
                        day = created.strftime("%Y-%m-%d")
                    daily_counts[day] = daily_counts.get(day, 0) + 1

                # Count by rule/detection
                detection = alert.get("detectionId") or alert.get("title", "Unknown")[:50]
                rule_counts[detection] = rule_counts.get(detection, 0) + 1

            # Sort and get top rules
            top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]

            return {
                "totalAlerts": len(alerts),
                "bySeverity": severity_counts,
                "byStatus": status_counts,
                "byDay": daily_counts,
                "topRules": [{"name": k, "count": v} for k, v in top_rules],
            }
        except PantherError as e:
            raise RuntimeError(str(e)) from e
