import asyncio
import logging
from datetime import datetime, timedelta
from uuid import UUID

from app.core.time_utils import utcnow
from app.db.session import AsyncSessionLocal
from app.services.notification_service import notification_service
from app.services.panther_service import PantherService

logger = logging.getLogger(__name__)


class AlertPoller:
    """Polls Panther for new alerts and broadcasts them via WebSocket."""

    def __init__(self):
        self._last_poll_time: datetime | None = None
        self._seen_alert_ids: set[str] = set()
        self._max_seen_ids = 10000  # Limit memory usage
        self._running = False
        self._organization_id: UUID | None = None

    async def start(
        self,
        panther_host: str,
        panther_token: str,
        interval_seconds: int = 30,
        organization_id: str | None = None,
    ):
        """Start polling for alerts."""
        if self._running:
            logger.warning("Alert poller already running")
            return

        self._running = True
        self._organization_id = UUID(organization_id) if organization_id else None
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
            end_time = utcnow()
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
                self._seen_alert_ids = set(list(self._seen_alert_ids)[self._max_seen_ids // 2 :])

            # Broadcast new alerts and trigger escalations
            for alert in new_alerts:
                title = alert.get("title", "")
                description = alert.get("description", "")

                # Infer source type
                source_type = "panther"
                if "cloudflare" in title.lower() or "cloudflare" in description.lower():
                    source_type = "cloudflare"
                elif "crowdstrike" in title.lower() or "falcon" in title.lower():
                    source_type = "crowdstrike_falcon"
                elif "okta" in title.lower():
                    source_type = "okta"

                organization_id = str(self._organization_id) if self._organization_id else None
                alert_data = {
                    "id": alert.get("id"),
                    "title": title,
                    "severity": alert.get("severity"),
                    "status": alert.get("status"),
                    "createdAt": alert.get("createdAt"),
                    "ruleName": alert.get("rule", {}).get("displayName")
                    or alert.get("rule", {}).get("id"),
                    "description": description,
                    "sourceType": source_type,
                    "organization_id": organization_id,
                }

                # Broadcast via WebSocket (fanned out per-tenant by subscribers)
                await notification_service.publish_alert(
                    alert_data, organization_id=organization_id
                )

                # Trigger escalation if organization is configured
                if self._organization_id:
                    await self._trigger_escalation(alert_data)

            if new_alerts:
                logger.info(f"Broadcasted {len(new_alerts)} new alerts")

        except Exception as e:
            logger.error(f"Failed to poll alerts: {e}")
            raise

    async def _trigger_escalation(self, alert_data: dict):
        """Trigger escalation for an alert if matching policy exists."""
        if not self._organization_id:
            return

        try:
            from app.services.escalation_service import trigger_escalation_for_alert

            async with AsyncSessionLocal() as db:
                escalation = await trigger_escalation_for_alert(
                    db=db,
                    organization_id=self._organization_id,
                    alert=alert_data,
                )
                if escalation:
                    logger.info(
                        f"Triggered escalation {escalation.id} for alert {alert_data.get('id')}"
                    )
        except Exception as e:
            logger.error(f"Failed to trigger escalation for alert {alert_data.get('id')}: {e}")


# Global alert poller instance
alert_poller = AlertPoller()


async def start_alert_poller(
    panther_host: str,
    panther_token: str,
    interval_seconds: int = 30,
    organization_id: str | None = None,
):
    """Start the global alert poller."""
    await alert_poller.start(
        panther_host, panther_token, interval_seconds, organization_id=organization_id
    )


def stop_alert_poller():
    """Stop the global alert poller."""
    alert_poller.stop()
