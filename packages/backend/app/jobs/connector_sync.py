"""
Connector Sync Scheduler

Automatically syncs data source connectors based on their configured sync interval.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, select

from app.core.time_utils import utcnow
from app.db.models import Connector, ConnectorCategory, ConnectorStatus
from app.db.session import AsyncSessionLocal

logger = logging.getLogger(__name__)


class ConnectorSyncScheduler:
    """Schedules and runs automatic syncs for data source connectors."""

    def __init__(self):
        self._running = False
        self._check_interval = 60  # Check every 60 seconds for connectors due for sync
        # Strong references to the in-flight sync tasks. asyncio only keeps a
        # weak reference to a running task, so a task nobody holds can be
        # garbage collected mid-sync.
        self._tasks: set[asyncio.Task] = set()
        # Connectors with a sync already running. last_sync_at is only written
        # when a sync finishes, so without this a sync taking longer than the
        # check interval gets a duplicate spawned on every tick.
        self._in_flight: set[UUID] = set()

    async def start(self):
        """Start the sync scheduler."""
        if self._running:
            logger.warning("Connector sync scheduler already running")
            return

        self._running = True
        logger.info("Starting connector sync scheduler")

        while self._running:
            try:
                await self._check_and_sync_connectors()
            except Exception as e:
                logger.error(f"Error in connector sync scheduler: {e}")

            await asyncio.sleep(self._check_interval)

    def stop(self):
        """Stop the sync scheduler."""
        self._running = False
        logger.info("Connector sync scheduler stopped")

    async def _check_and_sync_connectors(self):
        """Check for connectors due for sync and trigger syncs."""
        async with AsyncSessionLocal() as db:
            # Get all active data source connectors
            result = await db.execute(
                select(Connector).where(
                    and_(
                        Connector.category == ConnectorCategory.DATA_SOURCE,
                        Connector.status == ConnectorStatus.CONNECTED,
                    )
                )
            )
            connectors = result.scalars().all()

            now = utcnow()

            for connector in connectors:
                try:
                    # Check if connector is due for sync
                    if not self._is_due_for_sync(connector, now):
                        continue

                    if connector.id in self._in_flight:
                        logger.info(
                            f"Skipping auto-sync for connector {connector.name}: "
                            "a sync is still running"
                        )
                        continue

                    logger.info(
                        f"Triggering auto-sync for connector {connector.name} "
                        f"(interval: {connector.sync_interval_minutes}m)"
                    )
                    # Marked in-flight here, not inside the task, so a second
                    # tick cannot slip in before the task gets scheduled.
                    self._in_flight.add(connector.id)
                    task = asyncio.create_task(
                        self._sync_connector(connector.id, connector.organization_id)
                    )
                    self._tasks.add(task)
                    task.add_done_callback(self._tasks.discard)
                except Exception as e:
                    logger.error(f"Error checking connector {connector.id}: {e}")

    def _is_due_for_sync(self, connector: Connector, now: datetime) -> bool:
        """Check if a connector is due for sync based on its interval."""
        if not connector.sync_interval_minutes:
            return False

        # If never synced, sync now
        if not connector.last_sync_at:
            return True

        # Check if enough time has passed since last sync
        next_sync_at = connector.last_sync_at + timedelta(minutes=connector.sync_interval_minutes)
        return now >= next_sync_at

    async def _sync_connector(self, connector_id: UUID, organization_id: UUID):
        """Trigger sync for a single connector."""
        from app.api.v1.connectors import sync_connector_alerts

        try:
            await sync_connector_alerts(connector_id, organization_id)
        except Exception as e:
            logger.error(f"Auto-sync failed for connector {connector_id}: {e}")
        finally:
            self._in_flight.discard(connector_id)


# Global scheduler instance
connector_sync_scheduler = ConnectorSyncScheduler()


async def start_connector_sync_scheduler():
    """Start the global connector sync scheduler."""
    await connector_sync_scheduler.start()


def stop_connector_sync_scheduler():
    """Stop the global connector sync scheduler."""
    connector_sync_scheduler.stop()
