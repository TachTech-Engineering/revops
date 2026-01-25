import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Set

from app.services.notification_service import notification_service
from app.services.panther_service import PantherService
from app.config import settings

logger = logging.getLogger(__name__)


class AlertPoller:
    """Polls Panther for new alerts and broadcasts them via WebSocket."""

    def __init__(self):
        self._last_poll_time: Optional[datetime] = None
        self._seen_alert_ids: Set[str] = set()
        self._max_seen_ids = 10000  # Limit memory usage
        self._running = False

    async def start(self, panther_host: str, panther_token: str, interval_seconds: int = 30):
        """Start polling for alerts."""
        if self._running:
            logger.warning("Alert poller already running")
            return

        self._running = True
        logger.info(f"Starting alert poller with {interval_seconds}s interval")

        panther_service = PantherService(api_host=panther_host, api_token=panther_token)

        while self._running:
            try:
                await self._poll_alerts(panther_service)
            except Exception as e:
                logger.error(f"Error polling alerts: {e}")

            await asyncio.sleep(interval_seconds)

    def stop(self):
        """Stop polling."""
        self._running = False
        logger.info("Alert poller stopped")

    async def _poll_alerts(self, panther_service: PantherService):
        """Poll for new alerts and broadcast them."""
        try:
            # Calculate time range - poll for alerts in the last 5 minutes
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=5)

            # Fetch recent alerts
            result = await panther_service.list_alerts(
                created_at_after=start_time.isoformat() + "Z",
                created_at_before=end_time.isoformat() + "Z",
                page_size=100,
            )

            alerts = result.get("alerts", [])
            new_alerts = []

            for alert in alerts:
                alert_id = alert.get("id")
                if alert_id and alert_id not in self._seen_alert_ids:
                    self._seen_alert_ids.add(alert_id)
                    new_alerts.append(alert)

            # Trim seen IDs if too large
            if len(self._seen_alert_ids) > self._max_seen_ids:
                # Keep only the most recent half
                self._seen_alert_ids = set(list(self._seen_alert_ids)[self._max_seen_ids // 2:])

            # Broadcast new alerts
            for alert in new_alerts:
                await notification_service.publish_alert({
                    "id": alert.get("id"),
                    "title": alert.get("title"),
                    "severity": alert.get("severity"),
                    "status": alert.get("status"),
                    "createdAt": alert.get("createdAt"),
                    "ruleName": alert.get("rule", {}).get("displayName") or alert.get("rule", {}).get("id"),
                })

            if new_alerts:
                logger.info(f"Broadcasted {len(new_alerts)} new alerts")

        except Exception as e:
            logger.error(f"Failed to poll alerts: {e}")
            raise


# Global alert poller instance
alert_poller = AlertPoller()


async def start_alert_poller(panther_host: str, panther_token: str, interval_seconds: int = 30):
    """Start the global alert poller."""
    await alert_poller.start(panther_host, panther_token, interval_seconds)


def stop_alert_poller():
    """Stop the global alert poller."""
    alert_poller.stop()
