import json
import asyncio
from typing import Optional, Callable, Any
import logging

import redis.asyncio as redis

from app.config import settings

logger = logging.getLogger(__name__)


class NotificationService:
    """Service for real-time notifications via Redis pub/sub."""

    CHANNEL_ALERTS = "panther:alerts"
    CHANNEL_NOTIFICATIONS = "panther:notifications"

    def __init__(self):
        self._redis: Optional[redis.Redis] = None
        self._pubsub: Optional[redis.client.PubSub] = None
        self._subscribers: dict[str, list[Callable]] = {}

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
        if self._pubsub:
            await self._pubsub.close()
            self._pubsub = None
        if self._redis:
            await self._redis.close()
            self._redis = None
            logger.info("Disconnected from Redis")

    async def publish_alert(self, alert_data: dict) -> None:
        """Publish a new alert notification."""
        await self.connect()
        if self._redis:
            message = json.dumps({
                "type": "new_alert",
                "data": alert_data,
            })
            await self._redis.publish(self.CHANNEL_ALERTS, message)
            logger.debug(f"Published alert: {alert_data.get('id', 'unknown')}")

    async def publish_notification(self, notification_data: dict) -> None:
        """Publish a general notification."""
        await self.connect()
        if self._redis:
            message = json.dumps({
                "type": "notification",
                "data": notification_data,
            })
            await self._redis.publish(self.CHANNEL_NOTIFICATIONS, message)

    async def subscribe(self, channel: str, callback: Callable[[dict], Any]) -> None:
        """Subscribe to a channel with a callback."""
        await self.connect()
        if self._redis and not self._pubsub:
            self._pubsub = self._redis.pubsub()

        if channel not in self._subscribers:
            self._subscribers[channel] = []
            if self._pubsub:
                await self._pubsub.subscribe(channel)

        self._subscribers[channel].append(callback)

    async def listen(self) -> None:
        """Listen for messages on subscribed channels."""
        if not self._pubsub:
            return

        async for message in self._pubsub.listen():
            if message["type"] == "message":
                channel = message["channel"]
                try:
                    data = json.loads(message["data"])
                    if channel in self._subscribers:
                        for callback in self._subscribers[channel]:
                            try:
                                result = callback(data)
                                if asyncio.iscoroutine(result):
                                    await result
                            except Exception as e:
                                logger.error(f"Error in subscriber callback: {e}")
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON in message: {message['data']}")


# Global notification service instance
notification_service = NotificationService()


async def get_notification_service() -> NotificationService:
    """Get the global notification service."""
    await notification_service.connect()
    return notification_service
