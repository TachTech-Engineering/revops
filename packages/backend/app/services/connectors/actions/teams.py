"""
Microsoft Teams Action Connector

Sends messages and notifications to Microsoft Teams channels.
"""

import time
from typing import Any

import httpx

from app.db.models import ConnectorCategory
from app.services.connectors.base import (
    ActionConnector,
    ConnectorMetadata,
    ConnectionTestResult,
    ActionResult,
)


class TeamsActionConnector(ActionConnector):
    """
    Microsoft Teams action connector for messaging.

    Uses incoming webhooks or Graph API for sending messages.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="teams",
            category=ConnectorCategory.ACTION,
            display_name="Microsoft Teams",
            description="Microsoft Teams - Team collaboration and messaging",
            icon="teams",
            config_schema={
                "type": "object",
                "properties": {
                    "webhook_url": {
                        "type": "string",
                        "title": "Webhook URL",
                        "description": "Teams incoming webhook URL",
                    },
                },
                "required": ["webhook_url"],
            },
            credentials_schema={
                "type": "object",
                "properties": {},
            },
        )

    @classmethod
    def get_action_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["send_message", "send_adaptive_card"],
                    "title": "Action",
                    "description": "Action to perform",
                    "default": "send_message",
                },
                "text": {
                    "type": "string",
                    "title": "Text",
                    "description": "Message text",
                },
                "title": {
                    "type": "string",
                    "title": "Title",
                    "description": "Message card title",
                },
                "theme_color": {
                    "type": "string",
                    "title": "Theme Color",
                    "description": "Card theme color (hex without #)",
                    "default": "0076D7",
                },
                "sections": {
                    "type": "array",
                    "title": "Sections",
                    "description": "Message card sections",
                },
                "adaptive_card": {
                    "type": "object",
                    "title": "Adaptive Card",
                    "description": "Full adaptive card payload",
                },
            },
            "required": ["action"],
        }

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to Teams webhook."""
        start_time = time.time()
        try:
            webhook_url = self.config.get("webhook_url", "")
            if not webhook_url:
                return ConnectionTestResult(
                    success=False,
                    message="Webhook URL is required",
                )

            # Send a test message
            payload = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": "Connection Test",
                "themeColor": "00FF00",
                "title": "Panther Dashboard - Connection Test",
                "text": "This is a test message to verify the Teams webhook connection.",
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(webhook_url, json=payload)

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to Microsoft Teams",
                    latency_ms=latency_ms,
                )
            else:
                return ConnectionTestResult(
                    success=False,
                    message=f"Webhook returned status {response.status_code}",
                    latency_ms=latency_ms,
                )

        except Exception as e:
            return ConnectionTestResult(
                success=False,
                message=f"Connection error: {str(e)}",
            )

    async def execute(self, action_config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Execute a Teams action."""
        start_time = time.time()
        action = action_config.get("action", "send_message")

        try:
            if action == "send_message":
                result = await self._send_message(action_config, context)
            elif action == "send_adaptive_card":
                result = await self._send_adaptive_card(action_config, context)
            else:
                return ActionResult(
                    success=False,
                    message=f"Unknown action: {action}",
                )

            execution_time_ms = int((time.time() - start_time) * 1000)
            result.execution_time_ms = execution_time_ms
            return result

        except Exception as e:
            return ActionResult(
                success=False,
                message=f"Teams action failed: {str(e)}",
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    async def _send_message(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Send a message card to Teams."""
        webhook_url = self.config.get("webhook_url")
        if not webhook_url:
            return ActionResult(
                success=False,
                message="Webhook URL is required",
                error="No webhook_url configured",
            )

        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": config.get("theme_color", "0076D7"),
        }

        if config.get("title"):
            payload["title"] = config["title"]
            payload["summary"] = config["title"]

        if config.get("text"):
            payload["text"] = config["text"]

        if config.get("sections"):
            payload["sections"] = config["sections"]

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(webhook_url, json=payload)

        if response.status_code == 200:
            return ActionResult(
                success=True,
                message="Message sent to Teams",
                output={"status": "sent"},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to send message: {response.status_code}",
                error=response.text,
            )

    async def _send_adaptive_card(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Send an adaptive card to Teams."""
        webhook_url = self.config.get("webhook_url")
        if not webhook_url:
            return ActionResult(
                success=False,
                message="Webhook URL is required",
                error="No webhook_url configured",
            )

        adaptive_card = config.get("adaptive_card")
        if not adaptive_card:
            return ActionResult(
                success=False,
                message="Adaptive card payload is required",
                error="No adaptive_card provided",
            )

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": adaptive_card,
                }
            ],
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(webhook_url, json=payload)

        if response.status_code == 200:
            return ActionResult(
                success=True,
                message="Adaptive card sent to Teams",
                output={"status": "sent"},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to send adaptive card: {response.status_code}",
                error=response.text,
            )
