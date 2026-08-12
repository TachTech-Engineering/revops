import asyncio
import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.sessions import SessionMiddleware

from app.api.v1.router import api_router
from app.config import settings
from app.db import init_db
from app.jobs.connector_sync import start_connector_sync_scheduler, stop_connector_sync_scheduler
from app.services.syslog_receiver import get_syslog_receiver

# Configure logging from settings (default INFO)
_log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
logging.basicConfig(level=_log_level)
logging.getLogger("panther_sdk").setLevel(_log_level)
# httpx logs request details (including auth headers) at DEBUG - never allow below INFO
logging.getLogger("httpx").setLevel(max(_log_level, logging.INFO))

logger = logging.getLogger(__name__)


async def register_syslog_handlers(syslog_receiver) -> None:
    """Register syslog handlers for all syslog-type connectors in the database."""
    from sqlalchemy import select

    from app.db.models import Connector
    from app.db.session import AsyncSessionLocal

    syslog_connector_types = ["unifi_syslog"]

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Connector).where(
                    Connector.connector_type.in_(syslog_connector_types),
                    Connector.sync_enabled.is_(True),
                )
            )
            connectors = result.scalars().all()

            for connector in connectors:
                source_ips = connector.config.get("source_ips", []) if connector.config else []
                syslog_receiver.register_handler(
                    connector_id=connector.id,
                    callback=None,  # Use buffering
                    source_ips=source_ips if source_ips else None,
                    hostname_patterns=None,
                    app_name_patterns=None,
                )
                logger.info(
                    f"Registered syslog handler for connector {connector.name} ({connector.id})"
                )

            logger.info(f"Registered {len(connectors)} syslog handlers")
    except Exception as e:
        logger.error(f"Failed to register syslog handlers: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing database...")
    await init_db()
    logger.info("Database initialized")

    # Start connector sync scheduler in background
    sync_task = asyncio.create_task(start_connector_sync_scheduler())
    logger.info("Connector sync scheduler started")

    # Start syslog receiver for UniFi and other syslog-based connectors
    syslog_receiver = get_syslog_receiver()
    syslog_port = getattr(settings, "syslog_port", 514)
    try:
        await syslog_receiver.start(udp_port=syslog_port, tcp_port=syslog_port)
        logger.info(f"Syslog receiver started on port {syslog_port}")

        # Register handlers for all syslog-type connectors
        await register_syslog_handlers(syslog_receiver)
    except Exception as e:
        logger.warning(f"Could not start syslog receiver: {e} (may require elevated privileges)")

    yield

    # Shutdown
    logger.info("Shutting down...")
    stop_connector_sync_scheduler()
    sync_task.cancel()
    try:
        await sync_task
    except asyncio.CancelledError:
        pass

    # Stop syslog receiver
    await syslog_receiver.stop()


app = FastAPI(
    title="Panther Dashboard API",
    description="Backend API for Panther Dashboard",
    version="1.0.0",
    openapi_url="/api/v1/openapi.json",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    lifespan=lifespan,
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
# Session middleware for OAuth state management
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)

# Global exception handlers
#
# FastAPI/Starlette handle HTTPException (and RequestValidationError) before these
# fire, so intended 4xx/5xx responses keep their status and detail. These catch-all
# handlers only run for otherwise-unhandled errors: they log the full traceback
# server-side under a generated correlation id and return a generic 500 that never
# echoes the exception text to the client.
@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
    correlation_id = uuid.uuid4().hex
    logger.exception(
        "Unhandled database error [correlation_id=%s] on %s %s",
        correlation_id,
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "correlation_id": correlation_id},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    correlation_id = uuid.uuid4().hex
    logger.exception(
        "Unhandled exception [correlation_id=%s] on %s %s",
        correlation_id,
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "correlation_id": correlation_id},
    )


# Routes
app.include_router(api_router, prefix="/api/v1")


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}
