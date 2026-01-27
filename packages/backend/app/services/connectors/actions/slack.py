"""
Slack Action Connector

Sends messages and notifications to Slack channels and users.
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


class SlackActionConnector(ActionConnector):
    """
    Slack action connector for messaging and notifications.

    Supports sending messages to channels, users, and threads.
    Uses Slack's Web API with Bot tokens.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="slack",
            category=ConnectorCategory.ACTION,
            display_name="Slack",
            description="Slack - Team messaging and collaboration platform",
            icon="slack",
            config_schema={
                "type": "object",
                "properties": {
                    "default_channel": {
                        "type": "string",
                        "title": "Default Channel",
                        "description": "Default channel ID for messages (e.g., C0123456789)",
                    },
                },
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "bot_token": {
                        "type": "string",
                        "title": "Bot Token",
                        "description": "Slack Bot OAuth token (xoxb-...)",
                        "format": "password",
                    },
                },
                "required": ["bot_token"],
            },
        )

    @classmethod
    def get_action_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["send_message", "upload_file", "add_reaction"],
                    "title": "Action",
                    "description": "Action to perform",
                    "default": "send_message",
                },
                "channel": {
                    "type": "string",
                    "title": "Channel",
                    "description": "Channel ID or user ID (uses default if not specified)",
                },
                "text": {
                    "type": "string",
                    "title": "Text",
                    "description": "Message text",
                },
                "blocks": {
                    "type": "array",
                    "title": "Blocks",
                    "description": "Rich message blocks (Block Kit format)",
                },
                "thread_ts": {
                    "type": "string",
                    "title": "Thread Timestamp",
                    "description": "Thread timestamp for replies",
                },
                "attachments": {
                    "type": "array",
                    "title": "Attachments",
                    "description": "Legacy message attachments",
                },
                "unfurl_links": {
                    "type": "boolean",
                    "title": "Unfurl Links",
                    "description": "Expand links in messages",
                    "default": True,
                },
                "reaction": {
                    "type": "string",
                    "title": "Reaction",
                    "description": "Emoji reaction name (without colons)",
                },
                "message_ts": {
                    "type": "string",
                    "title": "Message Timestamp",
                    "description": "Message timestamp for reactions",
                },
            },
            "required": ["action"],
        }

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        return {
            "Authorization": f"Bearer {self.credentials.get('bot_token', '')}",
            "Content-Type": "application/json; charset=utf-8",
        }

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to Slack API."""
        start_time = time.time()
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    "https://slack.com/api/auth.test",
                    headers=self._get_headers(),
                )

            latency_ms = int((time.time() - start_time) * 1000)
            data = response.json()

            if data.get("ok"):
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to Slack",
                    details={
                        "team": data.get("team"),
                        "user": data.get("user"),
                        "bot_id": data.get("bot_id"),
                    },
                    latency_ms=latency_ms,
                )
            else:
                return ConnectionTestResult(
                    success=False,
                    message=f"Slack API error: {data.get('error', 'Unknown error')}",
                    latency_ms=latency_ms,
                )

        except Exception as e:
            return ConnectionTestResult(
                success=False,
                message=f"Connection error: {str(e)}",
            )

    async def execute(self, action_config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Execute a Slack action."""
        start_time = time.time()
        action = action_config.get("action", "send_message")

        try:
            if action == "send_message":
                result = await self._send_message(action_config, context)
            elif action == "add_reaction":
                result = await self._add_reaction(action_config, context)
            else:
                return ActionResult(
                    success=False,
                    message=f"Unknown action: {action}",
                    error="Supported actions: send_message, add_reaction",
                )

            execution_time_ms = int((time.time() - start_time) * 1000)
            result.execution_time_ms = execution_time_ms
            return result

        except Exception as e:
            return ActionResult(
                success=False,
                message=f"Slack action failed: {str(e)}",
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    async def _send_message(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Send a message to a Slack channel."""
        channel = config.get("channel") or self.config.get("default_channel")
        if not channel:
            return ActionResult(
                success=False,
                message="Channel is required",
                error="No channel specified and no default channel configured",
            )

        payload = {
            "channel": channel,
            "text": config.get("text", ""),
        }

        if config.get("blocks"):
            payload["blocks"] = config["blocks"]

        if config.get("thread_ts"):
            payload["thread_ts"] = config["thread_ts"]

        if config.get("attachments"):
            payload["attachments"] = config["attachments"]

        if "unfurl_links" in config:
            payload["unfurl_links"] = config["unfurl_links"]

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://slack.com/api/chat.postMessage",
                headers=self._get_headers(),
                json=payload,
            )

        data = response.json()
        if data.get("ok"):
            return ActionResult(
                success=True,
                message="Message sent successfully",
                output={
                    "channel": data.get("channel"),
                    "ts": data.get("ts"),
                    "message_url": f"https://slack.com/archives/{data.get('channel')}/p{data.get('ts', '').replace('.', '')}",
                },
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to send message: {data.get('error', 'Unknown error')}",
                error=data.get("error"),
            )

    async def _add_reaction(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Add a reaction to a Slack message."""
        channel = config.get("channel")
        reaction = config.get("reaction")
        message_ts = config.get("message_ts")

        if not all([channel, reaction, message_ts]):
            return ActionResult(
                success=False,
                message="Channel, reaction, and message_ts are required",
                error="Missing required fields",
            )

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://slack.com/api/reactions.add",
                headers=self._get_headers(),
                json={
                    "channel": channel,
                    "name": reaction,
                    "timestamp": message_ts,
                },
            )

        data = response.json()
        if data.get("ok"):
            return ActionResult(
                success=True,
                message=f"Added reaction :{reaction}: to message",
                output={"channel": channel, "reaction": reaction, "ts": message_ts},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to add reaction: {data.get('error', 'Unknown error')}",
                error=data.get("error"),
            )
