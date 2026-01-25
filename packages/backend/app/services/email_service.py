import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """Service for sending emails via SMTP."""

    def __init__(self):
        self.host = settings.smtp_host
        self.port = settings.smtp_port
        self.user = settings.smtp_user
        self.password = settings.smtp_password
        self.from_email = settings.smtp_from_email

    def is_configured(self) -> bool:
        """Check if SMTP is configured."""
        return bool(self.host and self.from_email)

    async def send_email(
        self,
        to: list[str],
        subject: str,
        body_html: str,
        body_text: Optional[str] = None,
        attachments: Optional[list[tuple[str, bytes, str]]] = None,  # (filename, content, mime_type)
    ) -> bool:
        """Send an email with optional attachments."""
        if not self.is_configured():
            logger.warning("SMTP not configured, cannot send email")
            return False

        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = ', '.join(to)

            # Add text body
            if body_text:
                msg.attach(MIMEText(body_text, 'plain'))

            # Add HTML body
            msg.attach(MIMEText(body_html, 'html'))

            # Add attachments
            if attachments:
                for filename, content, mime_type in attachments:
                    attachment = MIMEApplication(content)
                    attachment.add_header(
                        'Content-Disposition',
                        'attachment',
                        filename=filename,
                    )
                    attachment.add_header('Content-Type', mime_type)
                    msg.attach(attachment)

            # Send email
            with smtplib.SMTP(self.host, self.port) as server:
                if self.user and self.password:
                    server.starttls()
                    server.login(self.user, self.password)
                server.sendmail(self.from_email, to, msg.as_string())

            logger.info(f"Email sent to {to}: {subject}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False


email_service = EmailService()


async def get_email_service() -> EmailService:
    """Get the email service."""
    return email_service
