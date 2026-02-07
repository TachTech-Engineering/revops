"""
Escalation Service

Handles automatic triggering and processing of escalation policies for alerts.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db import (
    EscalationPolicy,
    EscalationStep,
    AlertEscalation,
    EscalationStatus,
    EscalationNotificationType,
)
from app.services.fonoster import (
    send_escalation_call,
    send_escalation_sms,
)
from app.services.email_service import email_service

logger = logging.getLogger(__name__)


class EscalationService:
    """Service for managing alert escalations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def check_and_trigger_escalation(
        self,
        organization_id: UUID,
        alert_id: str,
        alert_title: str,
        alert_severity: str,
        alert_description: str = "",
        rule_name: str = "",
        alert_time: str = "",
        log_source: str = "",
    ) -> Optional[AlertEscalation]:
        """
        Check if an alert matches any escalation policy and trigger if so.

        Returns the created AlertEscalation if triggered, None otherwise.
        """
        # Check if there's already an active escalation for this alert
        existing = await self.db.execute(
            select(AlertEscalation)
            .where(AlertEscalation.organization_id == organization_id)
            .where(AlertEscalation.alert_id == alert_id)
            .where(AlertEscalation.status.in_([EscalationStatus.PENDING, EscalationStatus.ACTIVE]))
        )
        if existing.scalar_one_or_none():
            logger.debug(f"Alert {alert_id} already has an active escalation")
            return None

        # Find matching escalation policy
        policy = await self._find_matching_policy(organization_id, alert_severity, rule_name)
        if not policy:
            logger.debug(f"No matching escalation policy for alert {alert_id}")
            return None

        logger.info(f"Triggering escalation policy '{policy.name}' for alert {alert_id}")

        # Create escalation record
        escalation = AlertEscalation(
            organization_id=organization_id,
            alert_id=alert_id,
            policy_id=policy.id,
            status=EscalationStatus.ACTIVE,
            current_step=0,
            started_at=datetime.utcnow(),
            notification_history=[],
        )

        # Calculate next escalation time based on first step
        if policy.steps:
            first_step = sorted(policy.steps, key=lambda s: s.step_order)[0]
            escalation.next_escalation_at = datetime.utcnow() + timedelta(minutes=first_step.delay_minutes)

        self.db.add(escalation)
        await self.db.commit()
        await self.db.refresh(escalation)

        # Send first notification immediately
        await self._send_step_notification(
            escalation=escalation,
            policy=policy,
            step_index=0,
            alert_title=alert_title,
            alert_severity=alert_severity,
            alert_description=alert_description,
            rule_name=rule_name,
            alert_time=alert_time,
            log_source=log_source,
        )

        return escalation

    async def _find_matching_policy(
        self,
        organization_id: UUID,
        alert_severity: str,
        rule_name: str = "",
    ) -> Optional[EscalationPolicy]:
        """Find the first active escalation policy that matches the alert."""
        result = await self.db.execute(
            select(EscalationPolicy)
            .where(EscalationPolicy.organization_id == organization_id)
            .where(EscalationPolicy.is_active == True)
            .options(selectinload(EscalationPolicy.steps))
        )
        policies = result.scalars().unique().all()

        severity_lower = alert_severity.lower()

        for policy in policies:
            # Check severity filter (empty = match all)
            if policy.severity_filter:
                if severity_lower not in [s.lower() for s in policy.severity_filter]:
                    continue

            # Check rule filter (empty = match all)
            if policy.rule_filter:
                if rule_name and rule_name not in policy.rule_filter:
                    continue

            # Policy matches
            return policy

        return None

    async def _send_step_notification(
        self,
        escalation: AlertEscalation,
        policy: EscalationPolicy,
        step_index: int,
        alert_title: str,
        alert_severity: str,
        alert_description: str = "",
        rule_name: str = "",
        alert_time: str = "",
        log_source: str = "",
    ) -> bool:
        """Send notification for a specific escalation step."""
        if not policy.steps:
            return False

        sorted_steps = sorted(policy.steps, key=lambda s: s.step_order)
        if step_index >= len(sorted_steps):
            # No more steps, escalation complete
            escalation.status = EscalationStatus.ESCALATED
            await self.db.commit()
            return False

        step = sorted_steps[step_index]
        success = False

        for target in step.targets:
            try:
                result = await self._send_notification(
                    notification_type=step.notification_type,
                    target=target,
                    alert_id=escalation.alert_id,
                    alert_title=alert_title,
                    alert_severity=alert_severity,
                    alert_description=alert_description,
                    rule_name=rule_name,
                    alert_time=alert_time,
                    log_source=log_source,
                    escalation_id=str(escalation.id),
                    call_template=policy.call_message_template,
                    sms_template=policy.sms_message_template,
                )
                if result.get("success"):
                    success = True
                    logger.info(f"Sent {step.notification_type.value} to {target} for alert {escalation.alert_id}")
            except Exception as e:
                logger.error(f"Failed to send {step.notification_type.value} to {target}: {e}")

        # Record in history
        history_entry = {
            "step": step.step_order,
            "type": step.notification_type.value,
            "sent_at": datetime.utcnow().isoformat(),
            "targets": step.targets,
            "success": success,
        }
        escalation.notification_history = escalation.notification_history + [history_entry]
        escalation.current_step = step_index

        # Calculate next escalation time
        if step_index + 1 < len(sorted_steps):
            next_step = sorted_steps[step_index + 1]
            escalation.next_escalation_at = datetime.utcnow() + timedelta(minutes=next_step.delay_minutes)
        else:
            escalation.next_escalation_at = None

        await self.db.commit()
        return success

    async def _send_notification(
        self,
        notification_type: EscalationNotificationType,
        target: str,
        alert_id: str,
        alert_title: str,
        alert_severity: str,
        alert_description: str = "",
        rule_name: str = "",
        alert_time: str = "",
        log_source: str = "",
        escalation_id: str = "",
        call_template: Optional[str] = None,
        sms_template: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send a notification based on type."""
        if notification_type == EscalationNotificationType.PHONE_CALL:
            return await send_escalation_call(
                phone_number=target,
                alert_title=alert_title,
                alert_severity=alert_severity,
                alert_id=alert_id,
                alert_description=alert_description,
                rule_name=rule_name,
                alert_time=alert_time,
                log_source=log_source,
                message_template=call_template,
                escalation_id=escalation_id,
            )

        elif notification_type == EscalationNotificationType.SMS:
            return await send_escalation_sms(
                phone_number=target,
                alert_title=alert_title,
                alert_severity=alert_severity,
                alert_id=alert_id,
                alert_description=alert_description,
                rule_name=rule_name,
                alert_time=alert_time,
                log_source=log_source,
                message_template=sms_template,
            )

        elif notification_type == EscalationNotificationType.EMAIL:
            return await self._send_email_notification(
                email_address=target,
                alert_id=alert_id,
                alert_title=alert_title,
                alert_severity=alert_severity,
                alert_description=alert_description,
                rule_name=rule_name,
                alert_time=alert_time,
                log_source=log_source,
                escalation_id=escalation_id,
            )

        elif notification_type == EscalationNotificationType.SLACK:
            # TODO: Implement Slack notification
            logger.info(f"Would send Slack message to {target} for alert {alert_id}")
            return {"success": True, "type": "slack", "target": target}

        elif notification_type == EscalationNotificationType.WEBHOOK:
            # TODO: Implement webhook notification
            logger.info(f"Would send webhook to {target} for alert {alert_id}")
            return {"success": True, "type": "webhook", "target": target}

        else:
            logger.warning(f"Unknown notification type: {notification_type}")
            return {"success": False, "error": f"Unknown notification type: {notification_type}"}

    async def _send_email_notification(
        self,
        email_address: str,
        alert_id: str,
        alert_title: str,
        alert_severity: str,
        alert_description: str = "",
        rule_name: str = "",
        alert_time: str = "",
        log_source: str = "",
        escalation_id: str = "",
    ) -> Dict[str, Any]:
        """Send email notification for escalation."""
        if not email_service.is_configured():
            logger.warning("Email service not configured, skipping email notification")
            return {"success": False, "error": "Email not configured"}

        # Determine severity color
        severity_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#16a34a",
            "info": "#2563eb",
        }
        severity_color = severity_colors.get(alert_severity.lower(), "#6b7280")

        subject = f"[{alert_severity.upper()}] Alert Escalation: {alert_title}"

        body_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f3f4f6;">
            <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <div style="background-color: {severity_color}; color: white; padding: 20px;">
                    <h1 style="margin: 0; font-size: 20px;">⚠️ Alert Escalation</h1>
                </div>
                <div style="padding: 20px;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold; color: #374151;">Alert ID:</td>
                            <td style="padding: 8px 0; color: #6b7280;">{alert_id}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold; color: #374151;">Title:</td>
                            <td style="padding: 8px 0; color: #111827;">{alert_title}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold; color: #374151;">Severity:</td>
                            <td style="padding: 8px 0;">
                                <span style="display: inline-block; padding: 4px 12px; background-color: {severity_color}; color: white; border-radius: 4px; font-size: 12px; text-transform: uppercase;">{alert_severity}</span>
                            </td>
                        </tr>
                        {"<tr><td style='padding: 8px 0; font-weight: bold; color: #374151;'>Source:</td><td style='padding: 8px 0; color: #6b7280;'>" + log_source + "</td></tr>" if log_source else ""}
                        {"<tr><td style='padding: 8px 0; font-weight: bold; color: #374151;'>Rule:</td><td style='padding: 8px 0; color: #6b7280;'>" + rule_name + "</td></tr>" if rule_name else ""}
                        {"<tr><td style='padding: 8px 0; font-weight: bold; color: #374151;'>Time:</td><td style='padding: 8px 0; color: #6b7280;'>" + alert_time + "</td></tr>" if alert_time else ""}
                    </table>
                    {"<div style='margin-top: 16px; padding: 12px; background-color: #f9fafb; border-radius: 4px;'><strong>Description:</strong><br/>" + alert_description + "</div>" if alert_description else ""}
                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                        <p style="margin: 0; color: #6b7280; font-size: 14px;">
                            This alert has been escalated and requires immediate attention.
                            Please investigate and acknowledge the alert as soon as possible.
                        </p>
                    </div>
                </div>
                <div style="background-color: #f9fafb; padding: 12px 20px; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0; color: #9ca3af; font-size: 12px; text-align: center;">
                        Escalation ID: {escalation_id}
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

        body_text = f"""
Alert Escalation

Alert ID: {alert_id}
Title: {alert_title}
Severity: {alert_severity}
{"Source: " + log_source if log_source else ""}
{"Rule: " + rule_name if rule_name else ""}
{"Time: " + alert_time if alert_time else ""}

{"Description: " + alert_description if alert_description else ""}

This alert has been escalated and requires immediate attention.
Please investigate and acknowledge the alert as soon as possible.

Escalation ID: {escalation_id}
        """

        try:
            success = await email_service.send_email(
                to=[email_address],
                subject=subject,
                body_html=body_html,
                body_text=body_text,
            )
            if success:
                logger.info(f"Sent escalation email to {email_address} for alert {alert_id}")
                return {"success": True, "type": "email", "target": email_address}
            else:
                return {"success": False, "error": "Failed to send email"}
        except Exception as e:
            logger.error(f"Failed to send escalation email to {email_address}: {e}")
            return {"success": False, "error": str(e)}

    async def process_pending_escalations(self) -> int:
        """
        Process all pending escalations that are due for their next step.

        Returns the number of escalations processed.
        """
        now = datetime.utcnow()

        result = await self.db.execute(
            select(AlertEscalation)
            .where(AlertEscalation.status == EscalationStatus.ACTIVE)
            .where(AlertEscalation.next_escalation_at <= now)
        )
        escalations = result.scalars().all()

        processed = 0
        for escalation in escalations:
            # Get the policy
            policy_result = await self.db.execute(
                select(EscalationPolicy)
                .where(EscalationPolicy.id == escalation.policy_id)
                .options(selectinload(EscalationPolicy.steps))
            )
            policy = policy_result.scalar_one_or_none()

            if not policy:
                logger.warning(f"Escalation {escalation.id} references missing policy {escalation.policy_id}")
                escalation.status = EscalationStatus.EXPIRED
                await self.db.commit()
                continue

            # Send next step notification
            # Note: We'd need to fetch alert details here in production
            await self._send_step_notification(
                escalation=escalation,
                policy=policy,
                step_index=escalation.current_step + 1,
                alert_title=f"Alert {escalation.alert_id}",
                alert_severity="HIGH",
            )
            processed += 1

        return processed


async def trigger_escalation_for_alert(
    db: AsyncSession,
    organization_id: UUID,
    alert: Dict[str, Any],
) -> Optional[AlertEscalation]:
    """
    Convenience function to trigger escalation for an alert.

    Args:
        db: Database session
        organization_id: The organization ID
        alert: Alert data dict with id, title, severity, logSource, etc.
    """
    service = EscalationService(db)
    return await service.check_and_trigger_escalation(
        organization_id=organization_id,
        alert_id=alert.get("id", ""),
        alert_title=alert.get("title", "Unknown Alert"),
        alert_severity=alert.get("severity", "HIGH"),
        alert_description=alert.get("description", ""),
        rule_name=alert.get("ruleName", ""),
        alert_time=alert.get("createdAt", ""),
        log_source=alert.get("logSource", "") or alert.get("log_source", ""),
    )
