"""
Correlation Window Cleanup Job

Periodically cleans up expired correlation windows to prevent database bloat.
Runs as a background job on a schedule.
"""

import logging

from app.core.time_utils import utcnow
from app.db.session import AsyncSessionLocal
from app.services.correlation_service import CorrelationService

logger = logging.getLogger(__name__)


async def cleanup_correlation_windows(max_age_hours: int = 24):
    """
    Clean up expired correlation windows.

    This job should be scheduled to run periodically (e.g., every hour).

    Args:
        max_age_hours: Maximum age in hours for windows to keep
    """
    start_time = utcnow()
    logger.info(f"Starting correlation window cleanup job at {start_time}")

    try:
        async with AsyncSessionLocal() as db:
            service = CorrelationService(db)
            deleted_count = await service.cleanup_expired_windows(max_age_hours)
            await db.commit()

            duration = (utcnow() - start_time).total_seconds()
            logger.info(
                f"Correlation cleanup completed: {deleted_count} windows deleted in {duration:.2f}s"
            )

    except Exception as e:
        logger.error(f"Error in correlation cleanup job: {e}")
        raise


# APScheduler job configuration
JOB_CONFIG = {
    "id": "correlation_cleanup",
    "func": cleanup_correlation_windows,
    "trigger": "interval",
    "hours": 1,  # Run every hour
    "kwargs": {"max_age_hours": 24},
    "max_instances": 1,
    "coalesce": True,
    "misfire_grace_time": 300,
}
