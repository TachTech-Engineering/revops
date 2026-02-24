import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.api.v1.router import api_router
from app.config import settings
from app.db import init_db
from app.jobs.connector_sync import start_connector_sync_scheduler, stop_connector_sync_scheduler
from app.services.syslog_receiver import get_syslog_receiver

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("panther_sdk").setLevel(logging.DEBUG)
logging.getLogger("httpx").setLevel(logging.DEBUG)

logger = logging.getLogger(__name__)


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

# Routes
app.include_router(api_router, prefix="/api/v1")


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}
