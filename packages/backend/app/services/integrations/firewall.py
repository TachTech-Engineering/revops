import logging

import httpx

from app.config import settings
from app.services.integrations.base import ActionConnector, ActionResult

logger = logging.getLogger(__name__)


class FirewallConnector(ActionConnector):
    """Connector for firewall IP blocking via generic API."""

    async def execute(self, config: dict, alert_data: dict) -> ActionResult:
        url = config.get("url") or settings.firewall_api_url
        api_token = config.get("api_token") or settings.firewall_api_token

        if not url or not api_token:
            return ActionResult(
                success=False,
                message="Firewall configuration incomplete",
                error="Missing url or api_token",
            )

        # Extract IP to block from alert data
        ip_address = config.get("ip_address") or self._extract_ip(alert_data)
        if not ip_address:
            return ActionResult(
                success=False,
                message="No IP address found",
                error="ip_address must be provided in config or alert data",
            )

        action = config.get("action", "block")  # block or unblock
        duration = config.get("duration", 3600)  # Default 1 hour
        comment = config.get(
            "comment", f"Blocked by Panther alert: {alert_data.get('id', 'unknown')}"
        )

        try:
            payload = {
                "action": action,
                "ip_address": ip_address,
                "duration": duration,
                "comment": comment,
                "alert_id": alert_data.get("id"),
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {api_token}",
                        "Content-Type": "application/json",
                    },
                )

            if response.status_code >= 200 and response.status_code < 300:
                return ActionResult(
                    success=True,
                    message=f"Firewall {action} completed for {ip_address}",
                    data={"ip_address": ip_address, "action": action, "duration": duration},
                )
            else:
                return ActionResult(
                    success=False,
                    message=f"Firewall action failed (status: {response.status_code})",
                    error=response.text[:500],
                )
        except Exception as e:
            logger.error(f"Firewall error: {e}")
            return ActionResult(success=False, message="Firewall request failed", error=str(e))

    def validate_config(self, config: dict) -> tuple[bool, str | None]:
        if not (config.get("url") or settings.firewall_api_url):
            return False, "Firewall API URL is required"
        if not (config.get("api_token") or settings.firewall_api_token):
            return False, "Firewall API token is required"
        return True, None

    def _extract_ip(self, alert_data: dict) -> str | None:
        """Try to extract IP address from alert data."""
        for field in ["ip_address", "source_ip", "src_ip", "attacker_ip", "remote_ip"]:
            if field in alert_data:
                return alert_data[field]

        entities = alert_data.get("entities", [])
        for entity in entities:
            if entity.get("type") in ["ip", "ip_address"]:
                return entity.get("value") or entity.get("id")

        return None
