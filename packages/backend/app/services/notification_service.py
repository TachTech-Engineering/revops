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

    # Reconnect backoff for the single global listener task. One Redis blip
    # used to end the loop for the life of the process: subscribers stayed
    # registered, nothing was listening, and only a brand-new subscribe() could
    # revive it -- so every already-connected dashboard went silent.
    RECONNECT_BASE_DELAY = 1.0
    RECONNECT_MAX_DELAY = 30.0

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

    @classmethod
    def reconnect_delay(cls, attempt: int) -> float:
        """Seconds to wait before reconnect attempt ``attempt`` (1-based).

        Exponential from RECONNECT_BASE_DELAY, capped at RECONNECT_MAX_DELAY:
        1, 2, 4, 8, 16, 30, 30, ...
        """
        exponent = max(1, attempt) - 1
        return min(cls.RECONNECT_BASE_DELAY * (2**exponent), cls.RECONNECT_MAX_DELAY)

    async def _listen_loop(self) -> None:
        """Supervising listener loop - runs as the single background task.

        Consumes pub/sub messages and, on any failure, reconnects with backoff
        instead of exiting. ``_started`` stays True for the whole life of the
        task so ``subscribe()`` never spawns a second listener; only
        ``disconnect()`` (which cancels the task) ends it.
        """
        logger.info("Redis listener loop started")
        attempt = 0

        while self._started:
            try:
                if self._pubsub is None:
                    await self._reconnect()
                await self._consume_messages()
                # listen() returned without raising: the connection is gone.
                logger.warning("Redis listener stream ended; will reconnect")
            except asyncio.CancelledError:
                logger.info("Redis listener loop cancelled")
                raise
            except Exception as e:
                logger.error(f"Redis listener loop error: {e}")

            if not self._started:
                break

            attempt += 1
            delay = self.reconnect_delay(attempt)
            logger.warning(f"Reconnecting to Redis in {delay:.1f}s (attempt {attempt})")
            await asyncio.sleep(delay)

            try:
                await self._reconnect()
                logger.info("Redis listener reconnected")
                attempt = 0
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Redis reconnect failed: {e}")

        logger.info("Redis listener loop stopped")

    async def _consume_messages(self) -> None:
        """Dispatch pub/sub messages until the stream ends or errors."""
        pubsub = self._pubsub
        if pubsub is None:
            raise RuntimeError("Redis pubsub is not connected")

        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            channel = message["channel"]
            try:
                data = json.loads(message["data"])
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON in message: {message['data']}")
                continue

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

    async def _reconnect(self) -> None:
        """Rebuild the Redis connection and re-subscribe every live channel."""
        if self._pubsub is not None:
            try:
                await self._pubsub.close()
            except Exception as e:
                logger.debug(f"Error closing stale pubsub: {e}")
            self._pubsub = None

        if self._redis is not None:
            try:
                await self._redis.close()
            except Exception as e:
                logger.debug(f"Error closing stale Redis client: {e}")
            self._redis = None

        await self.connect()
        if self._redis is None:
            raise RuntimeError("Redis connection unavailable")

        pubsub = self._redis.pubsub()
        # The whole re-subscribe runs under the lock that subscribe() holds, so
        # a concurrent subscribe() either lands in this snapshot or runs after
        # self._pubsub has been swapped in -- never against the discarded one.
        async with self._lock:
            stale, self._pubsub = self._pubsub, None
            for channel in list(self._subscribers.keys()):
                await pubsub.subscribe(channel)
            self._pubsub = pubsub

        if stale is not None:
            try:
                await stale.close()
            except Exception as e:
                logger.debug(f"Error closing superseded pubsub: {e}")


# Global notification service instance
notification_service = NotificationService()


async def get_notification_service() -> NotificationService:
    """Get the global notification service."""
    await notification_service.connect()
    return notification_service
