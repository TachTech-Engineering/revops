"""
Correlation Service

Evaluates alerts against correlation rules and auto-creates incidents
when rules match.
"""

import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
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
    ) -> Optional[Incident]:
        """
        Process a single alert against all active correlation rules.

        Args:
            alert: The normalized alert to evaluate
            organization_id: The organization this alert belongs to

        Returns:
            Created Incident if a rule matched with auto_create_incident=True, else None
        """
        # Get all active correlation rules for this organization with auto_create_incident
        result = await self.db.execute(
            select(CorrelationRule).where(
                and_(
                    CorrelationRule.organization_id == organization_id,
                    CorrelationRule.is_active == True,
                    CorrelationRule.auto_create_incident == True,
                )
            )
        )
        rules = result.scalars().all()

        if not rules:
            return None

        for rule in rules:
            if self._alert_matches_rule(alert, rule):
                logger.info(
                    f"Alert {alert.id} matched correlation rule '{rule.name}', creating incident"
                )
                incident = await self._create_incident_from_alert(alert, rule, organization_id)
                return incident

        return None

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
            if alert.severity and alert.severity.lower() not in [s.lower() for s in severity_filter]:
                return False

        # Check rule_id filter (matches against rule_name or title patterns)
        rule_id_filter = conditions.get("rule_id_filter")
        if rule_id_filter:
            matched = False
            alert_title = alert.title or ""
            alert_rule_name = alert.rule_name or ""
            for pattern in rule_id_filter:
                if pattern.lower() in alert_title.lower() or pattern.lower() in alert_rule_name.lower():
                    matched = True
                    break
            if not matched:
                return False

        # Check source_type filter if present
        source_type_filter = conditions.get("source_type_filter")
        if source_type_filter:
            if alert.source_type and alert.source_type.lower() not in [s.lower() for s in source_type_filter]:
                return False

        # For single-alert rules (min_alerts=1 or not set), match immediately
        min_alerts = conditions.get("min_alerts", 1)
        if min_alerts <= 1:
            return True

        # For multi-alert rules, we would need to check the time window
        # This is a more complex scenario that requires tracking alerts over time
        # For now, we'll implement single-alert matching
        # TODO: Implement multi-alert correlation with time windows

        return True

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
            (alert.severity or "medium").lower(),
            IncidentSeverity.MEDIUM
        )

        # Create incident
        incident = Incident(
            organization_id=organization_id,
            title=f"[Auto] {alert.title}",
            description=f"Incident auto-created by correlation rule '{rule.name}' from {alert.source_type} alert.\n\nOriginal alert: {alert.title}",
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


async def get_correlation_service(db: AsyncSession) -> CorrelationService:
    """Factory function to get a CorrelationService instance."""
    return CorrelationService(db)
