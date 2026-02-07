import json
import asyncio
import logging
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from app.services.notification_service import notification_service

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new connection."""
        await websocket.accept()
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


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alert notifications."""
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
            except asyncio.TimeoutError:
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
    """WebSocket endpoint for general notifications."""
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
            except asyncio.TimeoutError:
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
