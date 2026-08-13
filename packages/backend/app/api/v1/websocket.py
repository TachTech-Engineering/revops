import asyncio
import contextlib
import json
import logging
from uuid import UUID

import redis.asyncio as redis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from app.api.v1.deps import get_user_from_token
from app.config import settings
from app.db import User
from app.db.session import AsyncSessionLocal
from app.services.auth_service import decode_access_token, get_user_by_id
from app.services.notification_service import notification_service

logger = logging.getLogger(__name__)

router = APIRouter()

# Custom close code for authentication failures (4000-4999 is the app-defined range)
WS_CLOSE_UNAUTHORIZED = 4401
# The connection authenticated fine but the account is no longer entitled to
# this stream (deactivated, or moved to a different organization).
WS_CLOSE_FORBIDDEN = 4403

# How often an established connection re-checks that its authorization still
# holds. Sockets here live for hours; the access token they presented is valid
# for minutes.
REVALIDATE_INTERVAL_SECONDS = 60.0

CHANNEL_ALERTS = notification_service.CHANNEL_ALERTS
CHANNEL_NOTIFICATIONS = notification_service.CHANNEL_NOTIFICATIONS


class ConnectionManager:
    """Tracks WebSocket connections per channel, tagged with the tenant they
    belong to.

    Redis pub/sub is the fan-out bus across replicas: every process runs a
    single subscriber task (see RedisSubscriber) that forwards messages
    published on the alert/notification channels to this manager, which
    delivers each message only to local connections whose organization matches
    the payload's ``organization_id``.
    """

    def __init__(self):
        # channel -> {websocket: organization_id (str) or None}
        self._connections: dict[str, dict[WebSocket, str | None]] = {}
        self._lock = asyncio.Lock()

    async def connect(
        self, websocket: WebSocket, channel: str, organization_id: str | None
    ) -> None:
        """Register an already-accepted, authenticated connection."""
        async with self._lock:
            self._connections.setdefault(channel, {})[websocket] = organization_id
            total = sum(len(conns) for conns in self._connections.values())
        logger.info(f"WebSocket connected on {channel}. Total connections: {total}")

    async def disconnect(self, websocket: WebSocket, channel: str) -> None:
        """Remove a connection."""
        async with self._lock:
            conns = self._connections.get(channel)
            if conns is not None:
                conns.pop(websocket, None)
                if not conns:
                    del self._connections[channel]
            total = sum(len(conns) for conns in self._connections.values())
        logger.info(f"WebSocket disconnected from {channel}. Total connections: {total}")

    async def broadcast(self, channel: str, message: dict) -> None:
        """Deliver a message to local connections on `channel` belonging to the
        message's organization.

        Messages without an ``organization_id`` (e.g. old-format payloads
        published during a rolling deploy) are dropped: broadcasting them to
        every tenant would leak data across organizations.
        """
        organization_id = message.get("organization_id")
        if not organization_id:
            logger.warning(
                f"Dropping message on {channel} without organization_id "
                "(tenant isolation: refusing cross-org broadcast)"
            )
            return
        organization_id = str(organization_id)

        async with self._lock:
            targets = [
                ws
                for ws, ws_org in self._connections.get(channel, {}).items()
                if ws_org == organization_id
            ]

        if not targets:
            return

        message_str = json.dumps(message)
        for websocket in targets:
            try:
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_text(message_str)
            except Exception as e:
                logger.warning(f"Failed to send message: {e}")
                await self.disconnect(websocket, channel)


# Global connection manager
manager = ConnectionManager()


class RedisSubscriber:
    """Per-process Redis pub/sub subscriber.

    Starts lazily (once) on the first WebSocket connection, subscribes to the
    alert and notification channels, and forwards every message to the local
    ConnectionManager, which applies tenant filtering. Survives Redis outages
    with an exponential-backoff reconnect loop, and cleans up its connection
    when the task is cancelled (e.g. at event-loop shutdown).
    """

    CHANNELS = (CHANNEL_ALERTS, CHANNEL_NOTIFICATIONS)

    def __init__(self, connection_manager: ConnectionManager):
        self._manager = connection_manager
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    async def ensure_started(self) -> None:
        """Start the subscriber task if it is not already running."""
        async with self._lock:
            if self._task is None or self._task.done():
                self._task = asyncio.create_task(self._run(), name="ws-redis-subscriber")
                logger.info("Started Redis subscriber task")

    async def stop(self) -> None:
        """Cancel the subscriber task and wait for it to finish."""
        async with self._lock:
            if self._task is not None:
                self._task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._task
                self._task = None

    async def _run(self) -> None:
        backoff = 1.0
        try:
            while True:
                client = redis.Redis(
                    host=settings.redis_host,
                    port=settings.redis_port,
                    decode_responses=True,
                )
                pubsub = client.pubsub()
                try:
                    await pubsub.subscribe(*self.CHANNELS)
                    logger.info(f"Subscribed to Redis channels: {', '.join(self.CHANNELS)}")
                    backoff = 1.0
                    async for message in pubsub.listen():
                        if message.get("type") != "message":
                            continue
                        try:
                            data = json.loads(message["data"])
                        except (json.JSONDecodeError, TypeError):
                            logger.error(
                                f"Invalid JSON on channel {message.get('channel')}"
                            )
                            continue
                        if not isinstance(data, dict):
                            logger.warning(
                                f"Ignoring non-object message on {message.get('channel')}"
                            )
                            continue
                        await self._manager.broadcast(message["channel"], data)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.error(
                        f"Redis subscriber error: {e}; reconnecting in {backoff:.1f}s"
                    )
                finally:
                    with contextlib.suppress(Exception):
                        await pubsub.aclose()
                    with contextlib.suppress(Exception):
                        await client.aclose()

                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
        except asyncio.CancelledError:
            logger.info("Redis subscriber task cancelled")
            raise


# Global per-process subscriber
subscriber = RedisSubscriber(manager)


async def authenticate_websocket(websocket: WebSocket) -> User | None:
    """
    Authenticate a WebSocket connection via a `token` query parameter
    (browsers cannot set headers on WebSocket connections).

    Accepts the connection, then closes it with code 4401 if the token
    is missing or invalid. Returns the authenticated user, or None if
    the connection was rejected.
    """
    await websocket.accept()

    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=WS_CLOSE_UNAUTHORIZED, reason="Missing authentication token")
        return None

    async with AsyncSessionLocal() as db:
        user = await get_user_from_token(db, token)

    if not user:
        await websocket.close(code=WS_CLOSE_UNAUTHORIZED, reason="Invalid or expired token")
        return None

    return user


async def revalidate_connection(
    websocket: WebSocket, user_id: UUID, organization_id: str | None
) -> tuple[int, str] | None:
    """Re-check that this connection is still entitled to its stream.

    Returns None when the connection may continue, otherwise the
    ``(close_code, reason)`` to close with.

    Authorization used to be decided once, at connect, and never revisited:
    ``organization_id`` was snapshotted and the socket then sat in an unbounded
    keepalive loop. An expired token, a deactivated account, or a user moved to
    another tenant all kept streaming the *original* org's broadcasts for as
    long as the client stayed connected.
    """
    token = websocket.query_params.get("token")
    if not token:
        return WS_CLOSE_UNAUTHORIZED, "Missing authentication token"

    # decode_access_token enforces `exp`, so an expired token fails here.
    payload = decode_access_token(token)
    if not payload or payload.get("sub") != str(user_id):
        return WS_CLOSE_UNAUTHORIZED, "Token expired or invalid"

    async with AsyncSessionLocal() as db:
        user = await get_user_by_id(db, user_id)
        current_org = str(user.organization_id) if user and user.organization_id else None

    if not user or not user.is_active:
        return WS_CLOSE_FORBIDDEN, "Account is no longer active"

    if current_org != organization_id:
        # Never silently re-point the socket at the new org: the client must
        # reconnect and be re-authorized from scratch.
        return WS_CLOSE_FORBIDDEN, "Organization membership changed"

    return None


async def _serve_connection(websocket: WebSocket, channel: str, user: User) -> None:
    """Register an authenticated connection on `channel` and run the
    keepalive loop until the client disconnects.

    Message delivery happens out-of-band: the per-process RedisSubscriber
    forwards published messages to the ConnectionManager, which sends them to
    this connection only when the payload's organization_id matches the
    user's organization.

    Authorization is re-checked at most every REVALIDATE_INTERVAL_SECONDS; the
    30s receive timeout guarantees the loop comes round often enough to honour
    that even from a completely silent client.
    """
    organization_id = str(user.organization_id) if user.organization_id else None
    user_id = user.id

    # Ensure the process-wide Redis subscriber is running (lazy, once).
    await subscriber.ensure_started()
    await manager.connect(websocket, channel, organization_id)

    loop = asyncio.get_running_loop()
    last_validated = loop.time()

    try:
        while True:
            if loop.time() - last_validated >= REVALIDATE_INTERVAL_SECONDS:
                failure = await revalidate_connection(websocket, user_id, organization_id)
                last_validated = loop.time()
                if failure is not None:
                    code, reason = failure
                    logger.info(
                        "Closing WebSocket on %s for user %s: %s", channel, user_id, reason
                    )
                    with contextlib.suppress(Exception):
                        await websocket.close(code=code, reason=reason)
                    break

            try:
                # Wait for any client messages (like ping/pong)
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0,
                )
                # Handle client messages
                try:
                    message = json.loads(data)
                    if message.get("type") == "ping":
                        await websocket.send_text(json.dumps({"type": "pong"}))
                except json.JSONDecodeError:
                    pass
            except TimeoutError:
                # Send heartbeat
                try:
                    if websocket.client_state == WebSocketState.CONNECTED:
                        await websocket.send_text(json.dumps({"type": "heartbeat"}))
                    else:
                        break
                except Exception:
                    break

    except WebSocketDisconnect:
        logger.info("Client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await manager.disconnect(websocket, channel)


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alert notifications. Requires a valid JWT via ?token=."""
    user = await authenticate_websocket(websocket)
    if not user:
        return
    await _serve_connection(websocket, CHANNEL_ALERTS, user)


@router.websocket("/ws/notifications")
async def websocket_notifications(websocket: WebSocket):
    """WebSocket endpoint for general notifications. Requires a valid JWT via ?token=."""
    user = await authenticate_websocket(websocket)
    if not user:
        return
    await _serve_connection(websocket, CHANNEL_NOTIFICATIONS, user)
