"""
WebSocket authentication: connecting to /ws/alerts without a token must close the
connection with the app-defined 4401 (unauthorized) code -- never leave it open.

The no-token path in authenticate_websocket accepts, then immediately closes with
4401 BEFORE any Redis subscriber is started or any DB session is opened, so this
test needs no external infra. To avoid the full app's lifespan (init_db, syslog
receiver, connector scheduler), we mount only the websocket router on a minimal
FastAPI app -- exercising the real endpoint + authenticate_websocket code.
"""

from fastapi import FastAPI
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.api.v1 import websocket as ws_module


def _minimal_ws_app() -> FastAPI:
    app = FastAPI()
    app.include_router(ws_module.router, prefix="/api/v1")
    return app


def test_ws_alerts_without_token_closes_4401():
    app = _minimal_ws_app()
    with TestClient(app) as client:
        try:
            with client.websocket_connect("/api/v1/ws/alerts") as ws:
                # If not closed on connect, the first receive must surface the close.
                ws.receive_text()
            raise AssertionError("connection was not closed")
        except WebSocketDisconnect as exc:
            assert exc.code == ws_module.WS_CLOSE_UNAUTHORIZED == 4401


def test_ws_alerts_with_invalid_token_closes_4401():
    app = _minimal_ws_app()
    with TestClient(app) as client:
        try:
            with client.websocket_connect("/api/v1/ws/alerts?token=not-a-real-jwt") as ws:
                ws.receive_text()
            raise AssertionError("connection was not closed")
        except WebSocketDisconnect as exc:
            assert exc.code == 4401
