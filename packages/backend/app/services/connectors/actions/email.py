"""
Email/SMTP Action Connector

Sends email notifications via SMTP servers (Gmail, Office 365, custom SMTP).
"""

import time
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any

from app.db.models import ConnectorCategory
from app.services.connectors.base import (
    ActionConnector,
    ConnectorMetadata,
    ConnectionTestResult,
    ActionResult,
)


# Common SMTP server configurations
SMTP_PRESETS = {
    "gmail": {"host": "smtp.gmail.com", "port": 587, "use_tls": True},
    "office365": {"host": "smtp.office365.com", "port": 587, "use_tls": True},
    "outlook": {"host": "smtp-mail.outlook.com", "port": 587, "use_tls": True},
    "sendgrid": {"host": "smtp.sendgrid.net", "port": 587, "use_tls": True},
    "ses": {"host": "email-smtp.us-east-1.amazonaws.com", "port": 587, "use_tls": True},
}


class EmailActionConnector(ActionConnector):
    """
    Email action connector for sending notifications via SMTP.

    Supports Gmail, Office 365, and custom SMTP servers.
    Can send plain text or HTML emails with configurable templates.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="email",
            category=ConnectorCategory.ACTION,
            display_name="Email (SMTP)",
            description="Send email notifications via SMTP (Gmail, Office 365, custom)",
            icon="mail",
            config_schema={
                "type": "object",
                "properties": {
                    "smtp_preset": {
                        "type": "string",
                        "title": "SMTP Preset",
                        "description": "Use preset SMTP settings (optional)",
                        "enum": ["", "gmail", "office365", "outlook", "sendgrid", "ses"],
                    },
                    "smtp_host": {
                        "type": "string",
                        "title": "SMTP Host",
                        "description": "SMTP server hostname (ignored if preset selected)",
                    },
                    "smtp_port": {
                        "type": "integer",
                        "title": "SMTP Port",
                        "description": "SMTP server port (default: 587)",
                        "default": 587,
                    },
                    "use_tls": {
                        "type": "boolean",
                        "title": "Use TLS",
                        "description": "Enable TLS encryption (STARTTLS)",
                        "default": True,
                    },
                    "use_ssl": {
                        "type": "boolean",
                        "title": "Use SSL",
                        "description": "Enable SSL encryption (for port 465)",
                        "default": False,
                    },
                    "from_email": {
                        "type": "string",
                        "title": "From Email",
                        "description": "Sender email address",
                    },
                    "from_name": {
                        "type": "string",
                        "title": "From Name",
                        "description": "Sender display name",
                        "default": "Panther Dashboard",
                    },
                    "default_to": {
                        "type": "string",
                        "title": "Default Recipients",
                        "description": "Default recipient emails (comma-separated)",
                    },
                },
                "required": ["from_email"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "title": "Username",
                        "description": "SMTP username (usually email address)",
                    },
                    "password": {
                        "type": "string",
                        "title": "Password",
                        "description": "SMTP password or app-specific password",
                        "format": "password",
                    },
                },
                "required": ["username", "password"],
            },
        )

    @classmethod
    def get_action_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["send_email"],
                    "title": "Action",
                    "description": "Action to perform",
                    "default": "send_email",
                },
                "to": {
                    "type": "string",
                    "title": "To",
                    "description": "Recipient email addresses (comma-separated)",
                },
                "cc": {
                    "type": "string",
                    "title": "CC",
                    "description": "CC email addresses (comma-separated)",
                },
                "bcc": {
                    "type": "string",
                    "title": "BCC",
                    "description": "BCC email addresses (comma-separated)",
                },
                "subject": {
                    "type": "string",
                    "title": "Subject",
                    "description": "Email subject line",
                },
                "body": {
                    "type": "string",
                    "title": "Body",
                    "description": "Email body (plain text)",
                },
                "html_body": {
                    "type": "string",
                    "title": "HTML Body",
                    "description": "Email body (HTML format)",
                },
                "priority": {
                    "type": "string",
                    "enum": ["low", "normal", "high"],
                    "title": "Priority",
                    "description": "Email priority",
                    "default": "normal",
                },
            },
            "required": ["action", "subject"],
        }

    def _get_smtp_settings(self) -> dict[str, Any]:
        """Get SMTP settings from config or preset."""
        preset = self.config.get("smtp_preset")
        if preset and preset in SMTP_PRESETS:
            settings = SMTP_PRESETS[preset].copy()
        else:
            settings = {
                "host": self.config.get("smtp_host", ""),
                "port": self.config.get("smtp_port", 587),
                "use_tls": self.config.get("use_tls", True),
            }

        # Allow config to override preset settings
        if self.config.get("smtp_host"):
            settings["host"] = self.config["smtp_host"]
        if self.config.get("smtp_port"):
            settings["port"] = self.config["smtp_port"]
        if "use_ssl" in self.config:
            settings["use_ssl"] = self.config["use_ssl"]

        return settings

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to SMTP server."""
        start_time = time.time()
        try:
            settings = self._get_smtp_settings()
            host = settings.get("host")
            port = settings.get("port", 587)
            use_tls = settings.get("use_tls", True)
            use_ssl = settings.get("use_ssl", False)

            if not host:
                return ConnectionTestResult(
                    success=False,
                    message="SMTP host is required. Select a preset or enter custom host.",
                )

            username = self.credentials.get("username", "")
            password = self.credentials.get("password", "")

            # Create SMTP connection
            if use_ssl:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(host, port, context=context, timeout=30)
            else:
                server = smtplib.SMTP(host, port, timeout=30)
                if use_tls:
                    server.starttls()

            # Login
            server.login(username, password)
            server.quit()

            latency_ms = int((time.time() - start_time) * 1000)
            return ConnectionTestResult(
                success=True,
                message="Successfully connected to SMTP server",
                details={
                    "host": host,
                    "port": port,
                    "tls": use_tls,
                    "ssl": use_ssl,
                },
                latency_ms=latency_ms,
            )

        except smtplib.SMTPAuthenticationError as e:
            return ConnectionTestResult(
                success=False,
                message=f"Authentication failed: {str(e)}",
            )
        except smtplib.SMTPConnectError as e:
            return ConnectionTestResult(
                success=False,
                message=f"Failed to connect to SMTP server: {str(e)}",
            )
        except Exception as e:
            return ConnectionTestResult(
                success=False,
                message=f"Connection error: {str(e)}",
            )

    async def execute(self, action_config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Execute an email action."""
        start_time = time.time()
        action = action_config.get("action", "send_email")

        try:
            if action == "send_email":
                result = await self._send_email(action_config, context)
            else:
                return ActionResult(
                    success=False,
                    message=f"Unknown action: {action}",
                    error="Supported actions: send_email",
                )

            execution_time_ms = int((time.time() - start_time) * 1000)
            result.execution_time_ms = execution_time_ms
            return result

        except Exception as e:
            return ActionResult(
                success=False,
                message=f"Email action failed: {str(e)}",
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    async def _send_email(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Send an email."""
        # Get recipients
        to_emails = config.get("to") or self.config.get("default_to")
        if not to_emails:
            return ActionResult(
                success=False,
                message="Recipients required",
                error="No 'to' addresses specified and no default recipients configured",
            )

        # Parse recipients
        to_list = [e.strip() for e in to_emails.split(",") if e.strip()]
        cc_list = [e.strip() for e in (config.get("cc") or "").split(",") if e.strip()]
        bcc_list = [e.strip() for e in (config.get("bcc") or "").split(",") if e.strip()]

        # Build email
        from_email = self.config.get("from_email", "")
        from_name = self.config.get("from_name", "Panther Dashboard")
        subject = config.get("subject", "Notification from Panther Dashboard")
        body = config.get("body", "")
        html_body = config.get("html_body", "")
        priority = config.get("priority", "normal")

        # Create message
        if html_body:
            msg = MIMEMultipart("alternative")
            if body:
                msg.attach(MIMEText(body, "plain"))
            msg.attach(MIMEText(html_body, "html"))
        else:
            msg = MIMEMultipart()
            msg.attach(MIMEText(body or "No content", "plain"))

        msg["Subject"] = subject
        msg["From"] = f"{from_name} <{from_email}>" if from_name else from_email
        msg["To"] = ", ".join(to_list)
        if cc_list:
            msg["Cc"] = ", ".join(cc_list)

        # Set priority
        if priority == "high":
            msg["X-Priority"] = "1"
            msg["X-MSMail-Priority"] = "High"
        elif priority == "low":
            msg["X-Priority"] = "5"
            msg["X-MSMail-Priority"] = "Low"

        # Get SMTP settings
        settings = self._get_smtp_settings()
        host = settings.get("host")
        port = settings.get("port", 587)
        use_tls = settings.get("use_tls", True)
        use_ssl = settings.get("use_ssl", False)

        username = self.credentials.get("username", "")
        password = self.credentials.get("password", "")

        # Send email
        try:
            if use_ssl:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(host, port, context=context, timeout=30)
            else:
                server = smtplib.SMTP(host, port, timeout=30)
                if use_tls:
                    server.starttls()

            server.login(username, password)

            all_recipients = to_list + cc_list + bcc_list
            server.sendmail(from_email, all_recipients, msg.as_string())
            server.quit()

            return ActionResult(
                success=True,
                message=f"Email sent successfully to {len(all_recipients)} recipient(s)",
                output={
                    "to": to_list,
                    "cc": cc_list,
                    "bcc": bcc_list,
                    "subject": subject,
                    "recipients_count": len(all_recipients),
                },
            )

        except smtplib.SMTPRecipientsRefused as e:
            return ActionResult(
                success=False,
                message="Some recipients were refused",
                error=str(e),
            )
        except smtplib.SMTPSenderRefused as e:
            return ActionResult(
                success=False,
                message="Sender address refused",
                error=str(e),
            )
        except smtplib.SMTPDataError as e:
            return ActionResult(
                success=False,
                message="Email data error",
                error=str(e),
            )
        except Exception as e:
            return ActionResult(
                success=False,
                message=f"Failed to send email: {str(e)}",
                error=str(e),
            )
