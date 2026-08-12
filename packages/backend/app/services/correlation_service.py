"""
Correlation Service

Evaluates alerts against correlation rules and auto-creates incidents
when rules match. Supports multi-alert time window correlation.
"""

import hashlib
import logging
from datetime import timedelta
from uuid import UUID

from sqlalchemy import and_, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time_utils import utcnow
from app.db.models import (
    AlertCorrelationWindow,
    CorrelationRule,
    Incident,
    IncidentAlert,
    IncidentSeverity,
    IncidentStatus,
    NormalizedAlert,
)

logger = logging.getLogger(__name__)


class CorrelationService:
    """Service for evaluating alerts against correlation rules."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def process_alert(
        self,
        alert: NormalizedAlert,
        organization_id: UUID,
    ) -> Incident | None:
        """
        Process a single alert against all active correlation rules.
        Supports both single-alert and multi-alert time window correlation.

        Args:
            alert: The normalized alert to evaluate
            organization_id: The organization this alert belongs to

        Returns:
            Created Incident if a rule matched with auto_create_incident=True, else None
        """
        # Use the new window-based processing that handles both single and multi-alert rules
        return await self.process_alert_with_windows(alert, organization_id)

    def _alert_matches_rule(self, alert: NormalizedAlert, rule: CorrelationRule) -> bool:
        """
        Check if an alert matches a correlation rule's conditions.

        Args:
            alert: The alert to check
            rule: The correlation rule with conditions

        Returns:
            True if alert matches the rule conditions
        """
        conditions = rule.conditions or {}

        # Check severity filter
        severity_filter = conditions.get("severity_filter")
        if severity_filter:
            # severity_filter is a list of allowed severities
            if alert.severity and alert.severity.lower() not in [
                s.lower() for s in severity_filter
            ]:
                return False

        # Check rule_id filter (matches against rule_name or title patterns)
        rule_id_filter = conditions.get("rule_id_filter")
        if rule_id_filter:
            matched = False
            alert_title = alert.title or ""
            alert_rule_name = alert.rule_name or ""
            for pattern in rule_id_filter:
                if (
                    pattern.lower() in alert_title.lower()
                    or pattern.lower() in alert_rule_name.lower()
                ):
                    matched = True
                    break
            if not matched:
                return False

        # Check source_type filter if present
        source_type_filter = conditions.get("source_type_filter")
        if source_type_filter:
            if alert.source_type and alert.source_type.lower() not in [
                s.lower() for s in source_type_filter
            ]:
                return False

        # For single-alert rules (min_alerts=1 or not set), match immediately
        min_alerts = conditions.get("min_alerts", 1)
        if min_alerts <= 1:
            return True

        # For multi-alert rules, we need time window tracking
        # This is handled asynchronously in process_alert_with_windows
        # Return True here to signal the alert should be tracked
        return True

    def _build_window_key(self, alert: NormalizedAlert, conditions: dict) -> str:
        """
        Build a unique key for the correlation window based on aggregation fields.

        Args:
            alert: The alert to build key from
            conditions: Rule conditions containing aggregation_fields

        Returns:
            SHA256 hash of the aggregation field values
        """
        aggregation_fields = conditions.get("aggregation_fields", ["source_type", "rule_name"])

        key_parts = []
        for field in aggregation_fields:
            value = None
            if field == "source_type":
                value = alert.source_type
            elif field == "rule_name":
                value = alert.rule_name
            elif field == "rule_id":
                value = alert.rule_id
            elif field == "severity":
                value = alert.severity
            elif field == "title":
                value = alert.title
            else:
                # Try to get from raw_data
                value = (alert.raw_data or {}).get(field)

            key_parts.append(f"{field}:{value or 'null'}")

        key_string = "|".join(sorted(key_parts))
        return hashlib.sha256(key_string.encode()).hexdigest()[:32]

    async def _get_or_create_window(
        self,
        alert: NormalizedAlert,
        rule: CorrelationRule,
        organization_id: UUID,
    ) -> tuple[AlertCorrelationWindow, bool]:
        """
        Get or create a correlation window for the alert and rule.

        Args:
            alert: The alert being processed
            rule: The correlation rule
            organization_id: Organization ID

        Returns:
            Tuple of (window, is_new)
        """
        conditions = rule.conditions or {}
        window_key = self._build_window_key(alert, conditions)

        # Get time window duration in minutes
        time_window_minutes = conditions.get("time_window_minutes", 60)
        window_start = utcnow() - timedelta(minutes=time_window_minutes)

        # Look for existing window
        result = await self.db.execute(
            select(AlertCorrelationWindow).where(
                and_(
                    AlertCorrelationWindow.organization_id == organization_id,
                    AlertCorrelationWindow.rule_id == rule.id,
                    AlertCorrelationWindow.window_key == window_key,
                    AlertCorrelationWindow.last_alert_at >= window_start,
                    AlertCorrelationWindow.triggered.is_(False),
                )
            )
        )
        existing_window = result.scalar_one_or_none()

        if existing_window:
            return existing_window, False

        # Create new window
        new_window = AlertCorrelationWindow(
            organization_id=organization_id,
            rule_id=rule.id,
            window_key=window_key,
            alert_count=0,
            alert_ids=[],
            first_alert_at=utcnow(),
            last_alert_at=utcnow(),
            triggered=False,
        )
        self.db.add(new_window)
        await self.db.flush()

        return new_window, True

    async def _check_window_threshold(
        self,
        window: AlertCorrelationWindow,
        alert: NormalizedAlert,
        rule: CorrelationRule,
    ) -> bool:
        """
        Update window with new alert and check if threshold is reached.

        Args:
            window: The correlation window
            alert: The new alert
            rule: The correlation rule

        Returns:
            True if threshold is reached and incident should be created
        """
        conditions = rule.conditions or {}
        min_alerts = conditions.get("min_alerts", 1)

        # Update window
        window.alert_count += 1
        alert_ids = window.alert_ids or []
        alert_ids.append(str(alert.id))
        window.alert_ids = alert_ids
        window.last_alert_at = utcnow()

        # Check threshold
        if window.alert_count >= min_alerts:
            window.triggered = True
            return True

        return False

    async def process_alert_with_windows(
        self,
        alert: NormalizedAlert,
        organization_id: UUID,
    ) -> Incident | None:
        """
        Process alert with multi-alert time window correlation.

        Args:
            alert: The normalized alert to evaluate
            organization_id: The organization this alert belongs to

        Returns:
            Created Incident if threshold reached, else None
        """
        # Get all active correlation rules
        result = await self.db.execute(
            select(CorrelationRule).where(
                and_(
                    CorrelationRule.organization_id == organization_id,
                    CorrelationRule.is_active.is_(True),
                    CorrelationRule.auto_create_incident.is_(True),
                )
            )
        )
        rules = result.scalars().all()

        if not rules:
            return None

        for rule in rules:
            conditions = rule.conditions or {}
            min_alerts = conditions.get("min_alerts", 1)

            # Check basic filters first
            if not self._alert_matches_basic_filters(alert, conditions):
                continue

            # For single-alert rules, create incident immediately
            if min_alerts <= 1:
                logger.info(
                    f"Alert {alert.id} matched single-alert rule '{rule.name}', creating incident"
                )
                return await self._create_incident_from_alert(alert, rule, organization_id)

            # For multi-alert rules, use time window tracking
            window, is_new = await self._get_or_create_window(alert, rule, organization_id)
            threshold_reached = await self._check_window_threshold(window, alert, rule)

            if threshold_reached:
                logger.info(
                    f"Correlation window reached threshold ({window.alert_count}/{min_alerts}) "
                    f"for rule '{rule.name}', creating incident"
                )
                return await self._create_incident_from_window(window, rule, organization_id)

        return None

    def _alert_matches_basic_filters(self, alert: NormalizedAlert, conditions: dict) -> bool:
        """Check if alert matches basic rule filters (severity, rule_id, source_type)."""
        # Check severity filter
        severity_filter = conditions.get("severity_filter")
        if severity_filter:
            if alert.severity and alert.severity.lower() not in [
                s.lower() for s in severity_filter
            ]:
                return False

        # Check rule_id filter
        rule_id_filter = conditions.get("rule_id_filter")
        if rule_id_filter:
            matched = False
            alert_title = alert.title or ""
            alert_rule_name = alert.rule_name or ""
            for pattern in rule_id_filter:
                if (
                    pattern.lower() in alert_title.lower()
                    or pattern.lower() in alert_rule_name.lower()
                ):
                    matched = True
                    break
            if not matched:
                return False

        # Check source_type filter
        source_type_filter = conditions.get("source_type_filter")
        if source_type_filter:
            if alert.source_type and alert.source_type.lower() not in [
                s.lower() for s in source_type_filter
            ]:
                return False

        return True

    async def _create_incident_from_window(
        self,
        window: AlertCorrelationWindow,
        rule: CorrelationRule,
        organization_id: UUID,
    ) -> Incident:
        """
        Create an incident from a correlation window that reached threshold.

        Args:
            window: The correlation window with alert data
            rule: The correlation rule that triggered
            organization_id: The organization ID

        Returns:
            The created Incident
        """
        # Create incident with details about the correlation
        incident = Incident(
            organization_id=organization_id,
            title=f"[Correlated] {rule.name} - {window.alert_count} alerts",
            description=(
                f"Incident auto-created by correlation rule '{rule.name}'.\n\n"
                f"**Correlation Details:**\n"
                f"- Alert count: {window.alert_count}\n"
                f"- Time window: {window.first_alert_at} to {window.last_alert_at}\n"
                f"- Correlation key: {window.window_key}\n"
            ),
            status=IncidentStatus.OPEN,
            severity=IncidentSeverity.HIGH,  # Correlated alerts typically warrant high severity
            tags=["auto-created", "correlated", f"rule:{rule.name}", f"count:{window.alert_count}"],
            created_by="correlation_service",
        )
        self.db.add(incident)
        await self.db.flush()

        # Link all alerts to incident
        for alert_id in window.alert_ids or []:
            incident_alert = IncidentAlert(
                organization_id=organization_id,
                incident_id=incident.id,
                alert_id=alert_id,
                added_by="correlation_service",
            )
            self.db.add(incident_alert)

        logger.info(f"Created correlated incident {incident.id} from {window.alert_count} alerts")
        return incident

    async def _create_incident_from_alert(
        self,
        alert: NormalizedAlert,
        rule: CorrelationRule,
        organization_id: UUID,
    ) -> Incident:
        """
        Create an incident from an alert that matched a correlation rule.

        Args:
            alert: The alert that triggered the rule
            rule: The correlation rule that matched
            organization_id: The organization ID

        Returns:
            The created Incident
        """
        # Map alert severity to incident severity
        severity_map = {
            "critical": IncidentSeverity.CRITICAL,
            "high": IncidentSeverity.HIGH,
            "medium": IncidentSeverity.MEDIUM,
            "low": IncidentSeverity.LOW,
            "info": IncidentSeverity.LOW,
        }
        incident_severity = severity_map.get(
            (alert.severity or "medium").lower(), IncidentSeverity.MEDIUM
        )

        # Create incident
        incident = Incident(
            organization_id=organization_id,
            title=f"[Auto] {alert.title}",
            description=(
                f"Incident auto-created by correlation rule '{rule.name}' "
                f"from {alert.source_type} alert.\n\nOriginal alert: {alert.title}"
            ),
            status=IncidentStatus.OPEN,
            severity=incident_severity,
            tags=["auto-created", f"source:{alert.source_type}", f"rule:{rule.name}"],
            created_by="correlation_service",
        )
        self.db.add(incident)
        await self.db.flush()

        # Link alert to incident
        incident_alert = IncidentAlert(
            organization_id=organization_id,
            incident_id=incident.id,
            alert_id=str(alert.id),
            added_by="correlation_service",
        )
        self.db.add(incident_alert)

        logger.info(f"Created incident {incident.id} from alert {alert.id}")
        return incident

    async def process_alerts_batch(
        self,
        alerts: list[NormalizedAlert],
        organization_id: UUID,
    ) -> list[Incident]:
        """
        Process a batch of alerts against correlation rules.

        Args:
            alerts: List of alerts to process
            organization_id: The organization these alerts belong to

        Returns:
            List of created incidents
        """
        incidents = []
        for alert in alerts:
            incident = await self.process_alert(alert, organization_id)
            if incident:
                incidents.append(incident)
        return incidents

    async def cleanup_expired_windows(self, max_age_hours: int = 24) -> int:
        """
        Clean up expired correlation windows.

        Args:
            max_age_hours: Maximum age in hours for windows to keep

        Returns:
            Number of windows deleted
        """
        cutoff = utcnow() - timedelta(hours=max_age_hours)

        result = await self.db.execute(
            delete(AlertCorrelationWindow).where(AlertCorrelationWindow.last_alert_at < cutoff)
        )

        deleted_count = result.rowcount
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} expired correlation windows")

        return deleted_count


async def get_correlation_service(db: AsyncSession) -> CorrelationService:
    """Factory function to get a CorrelationService instance."""
    return CorrelationService(db)
