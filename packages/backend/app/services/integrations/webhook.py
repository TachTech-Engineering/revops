import logging

import httpx

from app.services.integrations.base import ActionConnector, ActionResult

logger = logging.getLogger(__name__)


class WebhookConnector(ActionConnector):
    """Connector for generic webhooks (Slack, Teams, PagerDuty, custom)."""

    async def execute(self, config: dict, alert_data: dict) -> ActionResult:
        url = config.get("url")
        if not url:
            return ActionResult(
                success=False, message="Missing webhook URL", error="url is required"
            )

        webhook_type = config.get("webhook_type", "generic")
        headers = config.get("headers", {})

        # Build payload based on webhook type
        payload = self._build_payload(webhook_type, config, alert_data)

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(url, json=payload, headers=headers)

            if response.status_code >= 200 and response.status_code < 300:
                return ActionResult(
                    success=True,
                    message=f"Webhook sent successfully (status: {response.status_code})",
                    data={"status_code": response.status_code, "response": response.text[:500]},
                )
            else:
                return ActionResult(
                    success=False,
                    message=f"Webhook failed with status {response.status_code}",
                    error=response.text[:500],
                )
        except Exception as e:
            logger.error(f"Webhook error: {e}")
            return ActionResult(success=False, message="Webhook request failed", error=str(e))

    def validate_config(self, config: dict) -> tuple[bool, str | None]:
        if not config.get("url"):
            return False, "Webhook URL is required"
        return True, None

    def _build_payload(self, webhook_type: str, config: dict, alert_data: dict) -> dict:
        """Build payload based on webhook type."""
        title = alert_data.get("title", "Alert")
        severity = alert_data.get("severity", "UNKNOWN")
        alert_id = alert_data.get("id", "unknown")

        if webhook_type == "slack":
            return {
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*:rotating_light: New Alert*\n*{title}*",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                            {"type": "mrkdwn", "text": f"*Alert ID:*\n{alert_id}"},
                        ],
                    },
                ],
            }
        elif webhook_type == "teams":
            color = {"CRITICAL": "FF0000", "HIGH": "FFA500", "MEDIUM": "FFFF00"}.get(
                severity, "808080"
            )
            return {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color,
                "summary": title,
                "sections": [
                    {
                        "activityTitle": f"Alert: {title}",
                        "facts": [
                            {"name": "Severity", "value": severity},
                            {"name": "Alert ID", "value": alert_id},
                        ],
                    }
                ],
            }
        elif webhook_type == "pagerduty":
            severity_map = {
                "CRITICAL": "critical",
                "HIGH": "error",
                "MEDIUM": "warning",
                "LOW": "info",
            }
            return {
                "routing_key": config.get("routing_key", ""),
                "event_action": "trigger",
                "payload": {
                    "summary": title,
                    "severity": severity_map.get(severity, "info"),
                    "source": "panther-dashboard",
                    "custom_details": alert_data,
                },
            }
        else:
            # Generic webhook - send full alert data
            return {
                "alert": alert_data,
                "message": config.get("message", f"Alert triggered: {title}"),
            }
