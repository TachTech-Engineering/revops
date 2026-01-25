import logging
import base64
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class ReportDeliveryService:
    """Service for delivering reports via webhooks."""

    async def deliver_to_slack(
        self,
        webhook_url: str,
        report_name: str,
        summary: dict,
        period: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
    ) -> bool:
        """Deliver report to Slack via webhook."""
        try:
            blocks = [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f":chart_with_upwards_trend: {report_name}"},
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Period:* {period}"},
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Total Alerts:*\n{summary.get('total_alerts', 0)}"},
                        {"type": "mrkdwn", "text": f"*Critical:*\n{summary.get('by_severity', {}).get('CRITICAL', 0)}"},
                        {"type": "mrkdwn", "text": f"*High:*\n{summary.get('by_severity', {}).get('HIGH', 0)}"},
                        {"type": "mrkdwn", "text": f"*Open:*\n{summary.get('by_status', {}).get('OPEN', 0)}"},
                    ],
                },
            ]

            payload = {"blocks": blocks}

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(webhook_url, json=payload)

            if response.status_code == 200:
                logger.info(f"Report delivered to Slack: {report_name}")
                return True
            else:
                logger.error(f"Slack delivery failed: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Slack delivery error: {e}")
            return False

    async def deliver_to_teams(
        self,
        webhook_url: str,
        report_name: str,
        summary: dict,
        period: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
    ) -> bool:
        """Deliver report to Microsoft Teams via webhook."""
        try:
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "0076D7",
                "summary": report_name,
                "sections": [
                    {
                        "activityTitle": report_name,
                        "activitySubtitle": f"Period: {period}",
                        "facts": [
                            {"name": "Total Alerts", "value": str(summary.get('total_alerts', 0))},
                            {"name": "Critical", "value": str(summary.get('by_severity', {}).get('CRITICAL', 0))},
                            {"name": "High", "value": str(summary.get('by_severity', {}).get('HIGH', 0))},
                            {"name": "Open", "value": str(summary.get('by_status', {}).get('OPEN', 0))},
                        ],
                        "markdown": True,
                    }
                ],
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(webhook_url, json=payload)

            if response.status_code == 200:
                logger.info(f"Report delivered to Teams: {report_name}")
                return True
            else:
                logger.error(f"Teams delivery failed: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Teams delivery error: {e}")
            return False

    async def deliver_to_webhook(
        self,
        webhook_url: str,
        report_name: str,
        summary: dict,
        period: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
    ) -> bool:
        """Deliver report to a generic webhook."""
        try:
            payload = {
                "report_name": report_name,
                "period": period,
                "summary": summary,
                "generated_at": "",
            }

            if file_content and filename:
                payload["attachment"] = {
                    "filename": filename,
                    "content_base64": base64.b64encode(file_content).decode('utf-8'),
                }

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(webhook_url, json=payload)

            if 200 <= response.status_code < 300:
                logger.info(f"Report delivered to webhook: {report_name}")
                return True
            else:
                logger.error(f"Webhook delivery failed: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Webhook delivery error: {e}")
            return False

    async def deliver(
        self,
        delivery_type: str,
        webhook_url: str,
        report_name: str,
        summary: dict,
        period: str,
        file_content: Optional[bytes] = None,
        filename: Optional[str] = None,
    ) -> bool:
        """Deliver report based on type."""
        if delivery_type == 'slack':
            return await self.deliver_to_slack(
                webhook_url, report_name, summary, period, file_content, filename
            )
        elif delivery_type == 'teams':
            return await self.deliver_to_teams(
                webhook_url, report_name, summary, period, file_content, filename
            )
        else:
            return await self.deliver_to_webhook(
                webhook_url, report_name, summary, period, file_content, filename
            )


report_delivery_service = ReportDeliveryService()


async def get_report_delivery_service() -> ReportDeliveryService:
    """Get the report delivery service."""
    return report_delivery_service
