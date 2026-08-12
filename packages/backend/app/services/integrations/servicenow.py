import logging

import httpx

from app.config import settings
from app.services.integrations.base import ActionConnector, ActionResult

logger = logging.getLogger(__name__)


class ServiceNowConnector(ActionConnector):
    """Connector for creating ServiceNow incidents."""

    async def execute(self, config: dict, alert_data: dict) -> ActionResult:
        url = config.get("url") or settings.servicenow_url
        user = config.get("user") or settings.servicenow_user
        password = config.get("password") or settings.servicenow_password

        if not url or not user or not password:
            return ActionResult(
                success=False,
                message="ServiceNow configuration incomplete",
                error="Missing url, user, or password",
            )

        title = alert_data.get("title", "Security Alert")
        severity = alert_data.get("severity", "MEDIUM")

        # Map severity to ServiceNow impact/urgency
        impact_map = {"CRITICAL": "1", "HIGH": "2", "MEDIUM": "2", "LOW": "3", "INFO": "3"}
        urgency_map = {"CRITICAL": "1", "HIGH": "1", "MEDIUM": "2", "LOW": "3", "INFO": "3"}

        incident_data = {
            "short_description": f"[{severity}] {title}",
            "description": self._build_description(alert_data),
            "impact": impact_map.get(severity, "2"),
            "urgency": urgency_map.get(severity, "2"),
            "category": config.get("category", "Security"),
            "subcategory": config.get("subcategory", "Alert"),
            "assignment_group": config.get("assignment_group", ""),
            "caller_id": config.get("caller_id", ""),
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{url.rstrip('/')}/api/now/table/incident",
                    json=incident_data,
                    auth=(user, password),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                )

            if response.status_code == 201:
                result = response.json().get("result", {})
                incident_number = result.get("number", "unknown")
                return ActionResult(
                    success=True,
                    message=f"ServiceNow incident created: {incident_number}",
                    data={"incident_number": incident_number, "sys_id": result.get("sys_id")},
                )
            else:
                return ActionResult(
                    success=False,
                    message=(
                        f"Failed to create ServiceNow incident (status: {response.status_code})"
                    ),
                    error=response.text[:500],
                )
        except Exception as e:
            logger.error(f"ServiceNow error: {e}")
            return ActionResult(success=False, message="ServiceNow request failed", error=str(e))

    def validate_config(self, config: dict) -> tuple[bool, str | None]:
        if not (config.get("url") or settings.servicenow_url):
            return False, "ServiceNow URL is required"
        if not (config.get("user") or settings.servicenow_user):
            return False, "ServiceNow user is required"
        if not (config.get("password") or settings.servicenow_password):
            return False, "ServiceNow password is required"
        return True, None

    def _build_description(self, alert_data: dict) -> str:
        """Build ServiceNow description from alert data."""
        lines = [
            "=== Alert Details ===",
            f"Alert ID: {alert_data.get('id', 'N/A')}",
            f"Severity: {alert_data.get('severity', 'N/A')}",
            f"Status: {alert_data.get('status', 'N/A')}",
            f"Created: {alert_data.get('createdAt', 'N/A')}",
            "",
            "=== Description ===",
            alert_data.get("description", "No description provided"),
        ]

        rule = alert_data.get("rule", {})
        if rule:
            lines.extend(
                [
                    "",
                    "=== Rule Information ===",
                    f"Rule Name: {rule.get('displayName', rule.get('id', 'N/A'))}",
                    f"Rule ID: {rule.get('id', 'N/A')}",
                ]
            )

        return "\n".join(lines)
