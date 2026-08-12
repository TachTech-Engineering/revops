import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from app.api.v1.deps import get_user_from_token
from app.db import User
from app.db.session import AsyncSessionLocal
from app.services.notification_service import notification_service

logger = logging.getLogger(__name__)

router = APIRouter()

# Custom close code for authentication failures (4000-4999 is the app-defined range)
WS_CLOSE_UNAUTHORIZED = 4401


class ConnectionManager:
    """Manages WebSocket connections."""

    def __init__(self):
        self.active_connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Register an already-accepted connection."""
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a connection."""
        async with self._lock:
            self.active_connections.discard(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict) -> None:
        """Broadcast a message to all connected clients."""
        if not self.active_connections:
            return

        message_str = json.dumps(message)
        disconnected = set()

        async with self._lock:
            for connection in list(self.active_connections):
                try:
                    if connection.client_state == WebSocketState.CONNECTED:
                        await connection.send_text(message_str)
                except Exception as e:
                    logger.warning(f"Failed to send message: {e}")
                    disconnected.add(connection)

            # Remove disconnected clients
            self.active_connections -= disconnected


# Global connection manager
manager = ConnectionManager()


async def handle_redis_message(data: dict) -> None:
    """Handle messages from Redis and broadcast to WebSocket clients."""
    await manager.broadcast(data)


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


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alert notifications. Requires a valid JWT via ?token=."""
    user = await authenticate_websocket(websocket)
    if not user:
        return

    await manager.connect(websocket)

    # Subscribe to alerts channel - the service handles the listener internally
    try:
        await notification_service.subscribe(
            notification_service.CHANNEL_ALERTS,
            handle_redis_message,
        )

        # Keep connection alive and handle client messages
        while True:
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
        # Unsubscribe when client disconnects
        await notification_service.unsubscribe(
            notification_service.CHANNEL_ALERTS,
            handle_redis_message,
        )
        await manager.disconnect(websocket)


@router.websocket("/ws/notifications")
async def websocket_notifications(websocket: WebSocket):
    """WebSocket endpoint for general notifications. Requires a valid JWT via ?token=."""
    user = await authenticate_websocket(websocket)
    if not user:
        return

    await manager.connect(websocket)

    try:
        await notification_service.subscribe(
            notification_service.CHANNEL_NOTIFICATIONS,
            handle_redis_message,
        )

        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0,
                )
                try:
                    message = json.loads(data)
                    if message.get("type") == "ping":
                        await websocket.send_text(json.dumps({"type": "pong"}))
                except json.JSONDecodeError:
                    pass
            except TimeoutError:
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
        await notification_service.unsubscribe(
            notification_service.CHANNEL_NOTIFICATIONS,
            handle_redis_message,
        )
        await manager.disconnect(websocket)
