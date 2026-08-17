"""
Shared test fixtures.

IMPORTANT: the app's lifespan (app.main.lifespan) initializes the database,
starts the connector-sync scheduler, and binds a syslog receiver. Tests must
never run it. Starlette's TestClient only executes the lifespan when it is
entered as a context manager (``with TestClient(app):``), so we deliberately
construct the client WITHOUT entering it. Each request then runs through the
ASGI app directly with no startup/shutdown events.

Auth dependencies run before any endpoint body executes, and get_db yields a
lazy AsyncSession (no connection is made until a statement executes), so
unauthenticated requests never touch postgres. The suite is run in a container
with no database available, which verifies that property: any accidental DB
connection attempt would surface as a 500 (raise_server_exceptions=False) and
fail the assertion on 401/403.
"""

import os

# Must be set before app.config is imported. The config defaults to the
# development environment (where the default SECRET_KEY is accepted); make
# that explicit so the suite is immune to leaked ENVIRONMENT values.
os.environ.setdefault("ENVIRONMENT", "development")

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="session")
def client() -> TestClient:
    # NOT a context manager on purpose: never triggers lifespan/DB init.
    return TestClient(app, raise_server_exceptions=False)
