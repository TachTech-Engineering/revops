import logging

import httpx

from app.config import settings
from app.services.integrations.base import ActionConnector, ActionResult

logger = logging.getLogger(__name__)


class JiraConnector(ActionConnector):
    """Connector for creating Jira tickets."""

    async def execute(self, config: dict, alert_data: dict) -> ActionResult:
        url = config.get("url") or settings.jira_url
        api_token = config.get("api_token") or settings.jira_api_token
        project_key = config.get("project_key") or settings.jira_project_key

        if not url or not api_token or not project_key:
            return ActionResult(
                success=False,
                message="Jira configuration incomplete",
                error="Missing url, api_token, or project_key",
            )

        title = alert_data.get("title", "Security Alert")
        severity = alert_data.get("severity", "MEDIUM")
        alert_data.get("id", "unknown")

        # Map severity to Jira priority
        priority_map = {
            "CRITICAL": "Highest",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Lowest",
        }

        issue_data = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[{severity}] {title}",
                "description": self._build_description(alert_data),
                "issuetype": {"name": config.get("issue_type", "Task")},
                "priority": {"name": priority_map.get(severity, "Medium")},
                "labels": config.get("labels", ["security", "panther-alert"]),
            }
        }

        # Add custom fields if specified
        if config.get("custom_fields"):
            issue_data["fields"].update(config["custom_fields"])

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{url.rstrip('/')}/rest/api/2/issue",
                    json=issue_data,
                    headers={
                        "Authorization": f"Bearer {api_token}",
                        "Content-Type": "application/json",
                    },
                )

            if response.status_code == 201:
                result = response.json()
                issue_key = result.get("key", "unknown")
                return ActionResult(
                    success=True,
                    message=f"Jira ticket created: {issue_key}",
                    data={"issue_key": issue_key, "issue_id": result.get("id")},
                )
            else:
                return ActionResult(
                    success=False,
                    message=f"Failed to create Jira ticket (status: {response.status_code})",
                    error=response.text[:500],
                )
        except Exception as e:
            logger.error(f"Jira error: {e}")
            return ActionResult(success=False, message="Jira request failed", error=str(e))

    def validate_config(self, config: dict) -> tuple[bool, str | None]:
        # Config is optional if environment vars are set
        if not (config.get("url") or settings.jira_url):
            return False, "Jira URL is required"
        if not (config.get("api_token") or settings.jira_api_token):
            return False, "Jira API token is required"
        if not (config.get("project_key") or settings.jira_project_key):
            return False, "Jira project key is required"
        return True, None

    def _build_description(self, alert_data: dict) -> str:
        """Build Jira description from alert data."""
        lines = [
            "h2. Alert Details",
            f"*Alert ID:* {alert_data.get('id', 'N/A')}",
            f"*Severity:* {alert_data.get('severity', 'N/A')}",
            f"*Status:* {alert_data.get('status', 'N/A')}",
            f"*Created:* {alert_data.get('createdAt', 'N/A')}",
            "",
            "h3. Description",
            alert_data.get("description", "No description provided"),
            "",
            "h3. Rule Information",
        ]

        rule = alert_data.get("rule", {})
        if rule:
            lines.extend(
                [
                    f"*Rule Name:* {rule.get('displayName', rule.get('id', 'N/A'))}",
                    f"*Rule ID:* {rule.get('id', 'N/A')}",
                ]
            )

        return "\n".join(lines)
