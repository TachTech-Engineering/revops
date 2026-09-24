"""
CVE Feed Sync Job

Refreshes EPSS scores and the CISA KEV catalog daily and applies
exploitability tags to open vulnerability alerts. Cross-replica: the sweep is
guarded by an advisory lock so only one replica hits the public feeds per
cycle.
"""

import asyncio
import logging

from sqlalchemy import text

from app.db.session import AsyncSessionLocal
from app.services.cve_enrichment_service import sync_cve_feeds

logger = logging.getLogger(__name__)

# Advisory lock distinct from the schema lock (0x52564F50 "RVOP"), the
# escalation sweep (0x52455343 "RESC"), and connector maintenance
# (0x524D4E54 "RMNT"). 0x52435645 is ascii "RCVE".
CVE_SYNC_LOCK_ID = 0x52435645

SYNC_INTERVAL_SECONDS = 24 * 3600
# First sync shortly after boot so a fresh deploy gets enrichment quickly,
# without racing DB init.
INITIAL_DELAY_SECONDS = 120


class CveFeedSyncJob:
    """Daily EPSS/KEV refresh loop."""

    def __init__(self):
        self._running = False

    async def start(self):
        if self._running:
            logger.warning("CVE feed sync job already running")
            return
        self._running = True
        logger.info("Starting CVE feed sync job")

        await asyncio.sleep(INITIAL_DELAY_SECONDS)
        while self._running:
            try:
                await self._sync_once()
            except Exception:
                logger.exception("CVE feed sync failed; retrying next cycle")
            await asyncio.sleep(SYNC_INTERVAL_SECONDS)

    def stop(self):
        self._running = False
        logger.info("CVE feed sync job stopped")

    async def _sync_once(self):
        async with AsyncSessionLocal() as db:
            # Transaction-scoped advisory lock: released on commit, cannot be
            # leaked to a different pooled connection (same rationale as the
            # connector maintenance sweep).
            acquired = (
                await db.execute(
                    text("SELECT pg_try_advisory_xact_lock(:lock_id)"),
                    {"lock_id": CVE_SYNC_LOCK_ID},
                )
            ).scalar()
            if not acquired:
                logger.debug("CVE feed sync running on another replica; skipping")
                return

            stats = await sync_cve_feeds(db)
            await db.commit()
            logger.info(f"CVE feed sync completed: {stats}")


cve_feed_sync_job = CveFeedSyncJob()


async def start_cve_feed_sync():
    """Start the global CVE feed sync job."""
    await cve_feed_sync_job.start()


def stop_cve_feed_sync():
    """Stop the global CVE feed sync job."""
    cve_feed_sync_job.stop()
