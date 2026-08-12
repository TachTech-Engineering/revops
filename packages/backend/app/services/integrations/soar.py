import logging

import httpx

from app.config import settings
from app.services.integrations.base import ActionConnector, ActionResult

logger = logging.getLogger(__name__)


class SOARConnector(ActionConnector):
    """Connector for triggering external SOAR playbooks."""

    async def execute(self, config: dict, alert_data: dict) -> ActionResult:
        url = config.get("url") or settings.soar_webhook_url
        api_token = config.get("api_token") or settings.soar_api_token

        if not url:
            return ActionResult(
                success=False,
                message="SOAR configuration incomplete",
                error="Missing webhook url",
            )

        playbook_id = config.get("playbook_id")
        custom_fields = config.get("custom_fields", {})

        payload = {
            "alert": alert_data,
            "playbook_id": playbook_id,
            "source": "panther-dashboard",
            **custom_fields,
        }

        headers = {"Content-Type": "application/json"}
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(url, json=payload, headers=headers)

            if response.status_code >= 200 and response.status_code < 300:
                return ActionResult(
                    success=True,
                    message="SOAR playbook triggered successfully",
                    data={
                        "playbook_id": playbook_id,
                        "response_status": response.status_code,
                    },
                )
            else:
                return ActionResult(
                    success=False,
                    message=f"SOAR trigger failed (status: {response.status_code})",
                    error=response.text[:500],
                )
        except Exception as e:
            logger.error(f"SOAR error: {e}")
            return ActionResult(success=False, message="SOAR request failed", error=str(e))

    def validate_config(self, config: dict) -> tuple[bool, str | None]:
        if not (config.get("url") or settings.soar_webhook_url):
            return False, "SOAR webhook URL is required"
        return True, None
