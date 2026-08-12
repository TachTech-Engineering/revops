import csv
import io
import logging
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.db import ScheduledReport

logger = logging.getLogger(__name__)


class ReportService:
    """Service for generating reports."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate_report(
        self,
        report: ScheduledReport,
        panther_service=None,  # Optional PantherService for fetching data
    ) -> tuple[str, bytes, str]:
        """Generate a report and return (filename, content, mime_type)."""
        report_type = report.report_type
        filters = report.filters or {}

        if report_type == "alert_summary":
            return await self._generate_alert_summary(report, filters, panther_service)
        elif report_type == "rule_summary":
            return await self._generate_rule_summary(report, filters, panther_service)
        elif report_type == "sla_metrics":
            return await self._generate_sla_report(report, filters)
        else:
            return await self._generate_generic_report(report, filters)

    async def _generate_alert_summary(
        self,
        report: ScheduledReport,
        filters: dict,
        panther_service=None,
    ) -> tuple[str, bytes, str]:
        """Generate alert summary report."""
        # Calculate date range based on frequency
        end_date = datetime.utcnow()
        if report.frequency.value == "daily":
            start_date = end_date - timedelta(days=1)
        elif report.frequency.value == "weekly":
            start_date = end_date - timedelta(weeks=1)
        else:
            start_date = end_date - timedelta(days=30)

        # Mock data for report (would fetch from Panther in production)
        data = {
            "report_name": report.name,
            "period": f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}",
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_alerts": 150,
                "by_severity": {
                    "CRITICAL": 5,
                    "HIGH": 25,
                    "MEDIUM": 50,
                    "LOW": 50,
                    "INFO": 20,
                },
                "by_status": {
                    "OPEN": 30,
                    "TRIAGED": 40,
                    "RESOLVED": 60,
                    "CLOSED": 20,
                },
            },
        }

        # Generate CSV content
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["Alert Summary Report"])
        writer.writerow([f"Period: {data['period']}"])
        writer.writerow([f"Generated: {data['generated_at']}"])
        writer.writerow([])
        writer.writerow(["Severity", "Count"])
        for severity, count in data["summary"]["by_severity"].items():
            writer.writerow([severity, count])
        writer.writerow([])
        writer.writerow(["Status", "Count"])
        for status, count in data["summary"]["by_status"].items():
            writer.writerow([status, count])

        content = output.getvalue().encode("utf-8")
        filename = f"alert_summary_{end_date.strftime('%Y%m%d')}.csv"

        return filename, content, "text/csv"

    async def _generate_rule_summary(
        self,
        report: ScheduledReport,
        filters: dict,
        panther_service=None,
    ) -> tuple[str, bytes, str]:
        """Generate rule summary report."""
        end_date = datetime.utcnow()

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["Rule Summary Report"])
        writer.writerow([f"Generated: {end_date.isoformat()}"])
        writer.writerow([])
        writer.writerow(["Rule Name", "Alert Count", "Last Triggered"])
        # Mock data
        writer.writerow(["Suspicious Login", 45, "2024-01-15T10:30:00Z"])
        writer.writerow(["Brute Force Detection", 23, "2024-01-15T09:15:00Z"])
        writer.writerow(["Data Exfiltration", 12, "2024-01-14T22:45:00Z"])

        content = output.getvalue().encode("utf-8")
        filename = f"rule_summary_{end_date.strftime('%Y%m%d')}.csv"

        return filename, content, "text/csv"

    async def _generate_sla_report(
        self,
        report: ScheduledReport,
        filters: dict,
    ) -> tuple[str, bytes, str]:
        """Generate SLA metrics report."""
        end_date = datetime.utcnow()

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["SLA Metrics Report"])
        writer.writerow([f"Generated: {end_date.isoformat()}"])
        writer.writerow([])
        writer.writerow(["Metric", "Target", "Actual", "Status"])
        # Mock data
        writer.writerow(["CRITICAL Response Time", "15 min", "12 min", "MET"])
        writer.writerow(["HIGH Response Time", "1 hour", "45 min", "MET"])
        writer.writerow(["Resolution Rate", "95%", "92%", "NOT MET"])

        content = output.getvalue().encode("utf-8")
        filename = f"sla_metrics_{end_date.strftime('%Y%m%d')}.csv"

        return filename, content, "text/csv"

    async def _generate_generic_report(
        self,
        report: ScheduledReport,
        filters: dict,
    ) -> tuple[str, bytes, str]:
        """Generate a generic report."""
        end_date = datetime.utcnow()

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([f"{report.name} Report"])
        writer.writerow([f"Generated: {end_date.isoformat()}"])
        writer.writerow([])
        writer.writerow(["No data available"])

        content = output.getvalue().encode("utf-8")
        filename = f"report_{end_date.strftime('%Y%m%d')}.csv"

        return filename, content, "text/csv"

    def generate_html_email(
        self,
        report_name: str,
        summary: dict,
        period: str,
    ) -> str:
        """Generate HTML email body for report."""
        return f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background: #1a1a2e; color: white; padding: 20px; }}
                .content {{ padding: 20px; }}
                .metric {{ display: inline-block; margin: 10px; padding: 15px;
                    background: #f5f5f5; border-radius: 8px; }}
                .metric-value {{ font-size: 24px; font-weight: bold; }}
                .metric-label {{ color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{report_name}</h1>
                <p>Period: {period}</p>
            </div>
            <div class="content">
                <h2>Summary</h2>
                <div class="metric">
                    <div class="metric-value">{summary.get("total_alerts", 0)}</div>
                    <div class="metric-label">Total Alerts</div>
                </div>
                <p>See attached CSV for detailed data.</p>
            </div>
        </body>
        </html>
        """


async def get_report_service(db: AsyncSession) -> ReportService:
    """Factory function to create a report service."""
    return ReportService(db)
