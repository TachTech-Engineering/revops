import logging

import httpx

from app.config import settings
from app.services.integrations.base import ActionConnector, ActionResult

logger = logging.getLogger(__name__)


class CrowdStrikeConnector(ActionConnector):
    """Connector for CrowdStrike host isolation."""

    def __init__(self):
        self._access_token: str | None = None

    async def execute(self, config: dict, alert_data: dict) -> ActionResult:
        client_id = config.get("client_id") or settings.crowdstrike_client_id
        client_secret = config.get("client_secret") or settings.crowdstrike_client_secret

        if not client_id or not client_secret:
            return ActionResult(
                success=False,
                message="CrowdStrike configuration incomplete",
                error="Missing client_id or client_secret",
            )

        # Extract host identifier from alert data
        host_id = config.get("host_id") or self._extract_host_id(alert_data)
        if not host_id:
            return ActionResult(
                success=False,
                message="No host identifier found",
                error="host_id must be provided in config or alert data",
            )

        action = config.get("action", "contain")  # contain or lift_containment
        base_url = config.get("base_url", "https://api.crowdstrike.com")

        try:
            # Get access token
            token = await self._get_access_token(base_url, client_id, client_secret)
            if not token:
                return ActionResult(
                    success=False,
                    message="Failed to authenticate with CrowdStrike",
                    error="Could not obtain access token",
                )

            # Perform host action
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{base_url}/devices/entities/devices-actions/v2",
                    params={"action_name": action},
                    json={"ids": [host_id]},
                    headers={"Authorization": f"Bearer {token}"},
                )

            if response.status_code == 202:
                return ActionResult(
                    success=True,
                    message=f"CrowdStrike host {action} initiated for {host_id}",
                    data={"host_id": host_id, "action": action},
                )
            else:
                return ActionResult(
                    success=False,
                    message=f"CrowdStrike action failed (status: {response.status_code})",
                    error=response.text[:500],
                )
        except Exception as e:
            logger.error(f"CrowdStrike error: {e}")
            return ActionResult(success=False, message="CrowdStrike request failed", error=str(e))

    def validate_config(self, config: dict) -> tuple[bool, str | None]:
        if not (config.get("client_id") or settings.crowdstrike_client_id):
            return False, "CrowdStrike client_id is required"
        if not (config.get("client_secret") or settings.crowdstrike_client_secret):
            return False, "CrowdStrike client_secret is required"
        return True, None

    async def _get_access_token(
        self, base_url: str, client_id: str, client_secret: str
    ) -> str | None:
        """Get OAuth2 access token from CrowdStrike."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{base_url}/oauth2/token",
                    data={"client_id": client_id, "client_secret": client_secret},
                )
            if response.status_code == 201:
                return response.json().get("access_token")
            return None
        except Exception as e:
            logger.error(f"Failed to get CrowdStrike token: {e}")
            return None

    def _extract_host_id(self, alert_data: dict) -> str | None:
        """Try to extract host identifier from alert data."""
        # Look in common fields
        for field in ["device_id", "host_id", "aid", "hostname"]:
            if field in alert_data:
                return alert_data[field]

        # Look in nested structures
        entities = alert_data.get("entities", [])
        for entity in entities:
            if entity.get("type") == "host":
                return entity.get("id") or entity.get("hostname")

        return None
