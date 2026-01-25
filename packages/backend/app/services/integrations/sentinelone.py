import logging
from typing import Optional

import httpx

from app.services.integrations.base import ActionConnector, ActionResult
from app.config import settings

logger = logging.getLogger(__name__)


class SentinelOneConnector(ActionConnector):
    """Connector for SentinelOne host isolation."""

    async def execute(self, config: dict, alert_data: dict) -> ActionResult:
        url = config.get("url") or settings.sentinelone_url
        api_token = config.get("api_token") or settings.sentinelone_api_token

        if not url or not api_token:
            return ActionResult(
                success=False,
                message="SentinelOne configuration incomplete",
                error="Missing url or api_token",
            )

        # Extract agent ID from alert data
        agent_id = config.get("agent_id") or self._extract_agent_id(alert_data)
        if not agent_id:
            return ActionResult(
                success=False,
                message="No agent identifier found",
                error="agent_id must be provided in config or alert data",
            )

        action = config.get("action", "disconnect")  # disconnect or connect

        try:
            endpoint = "disconnect-from-network" if action == "disconnect" else "connect-to-network"

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{url.rstrip('/')}/web/api/v2.1/agents/actions/{endpoint}",
                    json={"filter": {"ids": [agent_id]}},
                    headers={
                        "Authorization": f"ApiToken {api_token}",
                        "Content-Type": "application/json",
                    },
                )

            if response.status_code == 200:
                result = response.json()
                affected = result.get("data", {}).get("affected", 0)
                return ActionResult(
                    success=True,
                    message=f"SentinelOne agent {action} completed ({affected} affected)",
                    data={"agent_id": agent_id, "action": action, "affected": affected},
                )
            else:
                return ActionResult(
                    success=False,
                    message=f"SentinelOne action failed (status: {response.status_code})",
                    error=response.text[:500],
                )
        except Exception as e:
            logger.error(f"SentinelOne error: {e}")
            return ActionResult(success=False, message="SentinelOne request failed", error=str(e))

    def validate_config(self, config: dict) -> tuple[bool, Optional[str]]:
        if not (config.get("url") or settings.sentinelone_url):
            return False, "SentinelOne URL is required"
        if not (config.get("api_token") or settings.sentinelone_api_token):
            return False, "SentinelOne API token is required"
        return True, None

    def _extract_agent_id(self, alert_data: dict) -> Optional[str]:
        """Try to extract agent identifier from alert data."""
        for field in ["agent_id", "sentinelone_agent_id", "endpoint_id"]:
            if field in alert_data:
                return alert_data[field]

        entities = alert_data.get("entities", [])
        for entity in entities:
            if entity.get("type") in ["agent", "endpoint"]:
                return entity.get("id")

        return None
