import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any

import redis.asyncio as redis

from app.config import settings

logger = logging.getLogger(__name__)


class NotificationService:
    """Service for real-time notifications via Redis pub/sub."""

    CHANNEL_ALERTS = "panther:alerts"
    CHANNEL_NOTIFICATIONS = "panther:notifications"

    def __init__(self):
        self._redis: redis.Redis | None = None
        self._pubsub: redis.client.PubSub | None = None
        self._subscribers: dict[str, set[Callable]] = {}
        self._listen_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._started = False

    async def connect(self) -> None:
        """Connect to Redis."""
        if self._redis is None:
            self._redis = redis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                decode_responses=True,
            )
            logger.info(f"Connected to Redis at {settings.redis_host}:{settings.redis_port}")

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._listen_task:
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass
            self._listen_task = None
        if self._pubsub:
            await self._pubsub.close()
            self._pubsub = None
        if self._redis:
            await self._redis.close()
            self._redis = None
            logger.info("Disconnected from Redis")
        self._started = False

    @staticmethod
    def _resolve_organization_id(data: dict, organization_id: str | None) -> str | None:
        """Resolve the tenant for a payload, preferring the explicit argument."""
        org_id = organization_id if organization_id is not None else data.get("organization_id")
        return str(org_id) if org_id else None

    async def publish_alert(self, alert_data: dict, organization_id: str | None = None) -> None:
        """Publish a new alert notification for a specific organization.

        The organization_id is included in the published envelope so that
        WebSocket subscribers can deliver the alert only to connections
        belonging to that tenant. Payloads without an organization_id are
        still published, but subscribers drop them rather than broadcasting
        across tenants.
        """
        await self.connect()
        if self._redis:
            org_id = self._resolve_organization_id(alert_data, organization_id)
            if org_id is None:
                logger.warning(
                    f"Publishing alert {alert_data.get('id', 'unknown')} without "
                    "organization_id; subscribers will drop it (tenant isolation)"
                )
            message = json.dumps(
                {
                    "type": "new_alert",
                    "organization_id": org_id,
                    "data": alert_data,
                }
            )
            await self._redis.publish(self.CHANNEL_ALERTS, message)
            logger.debug(f"Published alert: {alert_data.get('id', 'unknown')}")

    async def publish_notification(
        self, notification_data: dict, organization_id: str | None = None
    ) -> None:
        """Publish a general notification for a specific organization."""
        await self.connect()
        if self._redis:
            org_id = self._resolve_organization_id(notification_data, organization_id)
            if org_id is None:
                logger.warning(
                    "Publishing notification without organization_id; "
                    "subscribers will drop it (tenant isolation)"
                )
            message = json.dumps(
                {
                    "type": "notification",
                    "organization_id": org_id,
                    "data": notification_data,
                }
            )
            await self._redis.publish(self.CHANNEL_NOTIFICATIONS, message)

    async def subscribe(self, channel: str, callback: Callable[[dict], Any]) -> None:
        """Subscribe to a channel with a callback."""
        async with self._lock:
            await self.connect()

            if self._redis and not self._pubsub:
                self._pubsub = self._redis.pubsub()

            if channel not in self._subscribers:
                self._subscribers[channel] = set()
                if self._pubsub:
                    await self._pubsub.subscribe(channel)

            self._subscribers[channel].add(callback)

            # Start the listener if not already running
            if not self._started and self._pubsub:
                self._started = True
                self._listen_task = asyncio.create_task(self._listen_loop())
                logger.info("Started global Redis listener task")

    async def unsubscribe(self, channel: str, callback: Callable[[dict], Any]) -> None:
        """Unsubscribe a callback from a channel."""
        async with self._lock:
            if channel in self._subscribers:
                self._subscribers[channel].discard(callback)
                # If no more subscribers for this channel, unsubscribe from Redis
                if not self._subscribers[channel] and self._pubsub:
                    await self._pubsub.unsubscribe(channel)
                    del self._subscribers[channel]

    async def _listen_loop(self) -> None:
        """Internal listener loop - runs as single background task."""
        if not self._pubsub:
            return

        logger.info("Redis listener loop started")
        try:
            async for message in self._pubsub.listen():
                if message["type"] == "message":
                    channel = message["channel"]
                    try:
                        data = json.loads(message["data"])
                        # Get subscribers snapshot under lock
                        async with self._lock:
                            callbacks = list(self._subscribers.get(channel, set()))

                        # Call callbacks outside lock
                        for callback in callbacks:
                            try:
                                result = callback(data)
                                if asyncio.iscoroutine(result):
                                    await result
                            except Exception as e:
                                logger.error(f"Error in subscriber callback: {e}")
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON in message: {message['data']}")
        except asyncio.CancelledError:
            logger.info("Redis listener loop cancelled")
            raise
        except Exception as e:
            logger.error(f"Redis listener loop error: {e}")
            self._started = False


# Global notification service instance
notification_service = NotificationService()


async def get_notification_service() -> NotificationService:
    """Get the global notification service."""
    await notification_service.connect()
    return notification_service
