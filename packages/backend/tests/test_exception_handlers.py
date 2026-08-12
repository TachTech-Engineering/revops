"""
Global exception handlers (DB-free).

The app's real catch-all handlers must turn any unhandled error into a generic
500 carrying a correlation_id and leaking NO exception text or traceback. We
mount the ACTUAL registered handlers (imported from app.main) on a throwaway app
with routes engineered to raise, and assert on the response.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.main import sqlalchemy_exception_handler, unhandled_exception_handler

SECRET_MARKER = "super-secret-internal-detail-1234"


def _build_app() -> TestClient:
    app = FastAPI()
    app.add_exception_handler(Exception, unhandled_exception_handler)
    app.add_exception_handler(SQLAlchemyError, sqlalchemy_exception_handler)

    @app.get("/boom")
    async def boom():
        raise ValueError(SECRET_MARKER)

    @app.get("/db-boom")
    async def db_boom():
        raise SQLAlchemyError(SECRET_MARKER)

    return TestClient(app, raise_server_exceptions=False)


def _assert_generic_500(resp):
    assert resp.status_code == 500
    body = resp.json()
    assert body["detail"] == "Internal server error"
    assert isinstance(body.get("correlation_id"), str) and body["correlation_id"]
    # Nothing sensitive leaks to the client.
    text = resp.text
    assert SECRET_MARKER not in text
    assert "ValueError" not in text
    assert "SQLAlchemyError" not in text
    assert "Traceback" not in text


def test_unhandled_exception_returns_generic_500():
    client = _build_app()
    _assert_generic_500(client.get("/boom"))


def test_sqlalchemy_error_returns_generic_500():
    client = _build_app()
    _assert_generic_500(client.get("/db-boom"))
