"""
Telephony Integration Service

Handles voice calls and SMS for escalation notifications.
Supports:
- Mock server (local dev)
- Twilio (production - recommended)
- Plivo (production - alternative)
"""

import logging
import os
from dataclasses import dataclass
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Provider constants
PROVIDER_MOCK = "mock"
PROVIDER_TWILIO = "twilio"
PROVIDER_PLIVO = "plivo"

# Default message templates
DEFAULT_CALL_TEMPLATE = "Alert from {source}: {title}. Severity: {severity}. {description}"
DEFAULT_SMS_TEMPLATE = "[{source}] {severity} Alert: {title}. ID: {id}"


def render_message_template(
    template: str,
    title: str = "",
    severity: str = "",
    alert_id: str = "",
    description: str = "",
    rule: str = "",
    time: str = "",
    source: str = "",
) -> str:
    """
    Render a message template with alert data.

    Supported placeholders:
    - {title} - Alert title
    - {severity} - Alert severity (e.g., CRITICAL, HIGH, MEDIUM, LOW)
    - {id} - Alert ID
    - {description} - Alert description
    - {rule} - Rule name that triggered the alert
    - {time} - Alert timestamp
    - {source} - Log source (e.g., AWS.CloudTrail, Okta, CrowdStrike)
    """
    try:
        return template.format(
            title=title or "Unknown Alert",
            severity=severity or "UNKNOWN",
            id=alert_id or "N/A",
            description=description or "No description available",
            rule=rule or "Unknown Rule",
            time=time or "N/A",
            source=source or "Security",
        )
    except KeyError as e:
        logger.warning(f"Unknown template placeholder: {e}")
        # Fall back to simple message
        return f"Alert: {title}. Severity: {severity}."


@dataclass
class TelephonyConfig:
    """Telephony connection configuration."""

    provider: str  # mock, twilio, plivo
    api_endpoint: str  # For mock server
    account_sid: str  # Twilio Account SID / Plivo Auth ID
    auth_token: str  # Twilio Auth Token / Plivo Auth Token
    default_caller_id: str  # Your phone number
    tts_voice: str = "alice"  # Twilio voice
    enabled: bool = False


# Alias for backwards compatibility
FonosterConfig = TelephonyConfig


class TelephonyService:
    """Service for making voice calls and sending SMS."""

    def __init__(self, config: TelephonyConfig | None = None):
        self.config = config or self._load_config_from_env()
        self._twilio_client = None

    def _load_config_from_env(self) -> TelephonyConfig:
        """Load configuration from environment variables."""
        return TelephonyConfig(
            provider=os.getenv("TELEPHONY_PROVIDER", PROVIDER_MOCK),
            api_endpoint=os.getenv("TELEPHONY_MOCK_ENDPOINT", "http://telephony-mock:50051"),
            account_sid=os.getenv("TWILIO_ACCOUNT_SID", ""),
            auth_token=os.getenv("TWILIO_AUTH_TOKEN", ""),
            default_caller_id=os.getenv("TWILIO_PHONE_NUMBER", "+1000000000"),
            tts_voice=os.getenv("TWILIO_VOICE", "alice"),
            enabled=os.getenv("TELEPHONY_ENABLED", "true").lower() == "true",
        )

    def _get_mock_base_url(self) -> str:
        """Get the mock API base URL."""
        endpoint = self.config.api_endpoint
        if not endpoint.startswith("http"):
            endpoint = f"http://{endpoint}"
        return endpoint

    def _get_twilio_client(self):
        """Get or create Twilio client."""
        if self._twilio_client is None:
            try:
                from twilio.rest import Client

                self._twilio_client = Client(self.config.account_sid, self.config.auth_token)
            except ImportError:
                logger.error("Twilio package not installed. Run: pip install twilio")
                raise
        return self._twilio_client

    async def make_call(
        self,
        to_number: str,
        message: str,
        caller_id: str | None = None,
        alert_id: str | None = None,
        alert_title: str | None = None,
        alert_severity: str | None = None,
        escalation_id: str | None = None,
        webhook_base_url: str | None = None,
    ) -> dict:
        """
        Make a voice call with text-to-speech message.

        Args:
            to_number: Phone number to call (E.164 format, e.g., +1234567890)
            message: Message to speak via TTS
            caller_id: Optional caller ID (uses default if not provided)
            alert_id: Optional alert ID for tracking
            alert_title: Optional alert title to speak
            alert_severity: Optional severity level
            escalation_id: Optional escalation ID for acknowledgment
            webhook_base_url: If provided, enables interactive mode (press 1 to ack, etc.)

        Returns:
            dict with call status and details
        """
        if not self.config.enabled:
            logger.warning("Telephony is not enabled, skipping call")
            return {"success": False, "error": "Telephony is not enabled"}

        caller = caller_id or self.config.default_caller_id

        if self.config.provider == PROVIDER_TWILIO:
            return await self._make_twilio_call(
                to_number,
                message,
                caller,
                alert_id=alert_id,
                alert_title=alert_title,
                alert_severity=alert_severity,
                escalation_id=escalation_id,
                webhook_base_url=webhook_base_url,
            )
        else:
            return await self._make_mock_call(to_number, message, caller)

    async def _make_twilio_call(
        self,
        to_number: str,
        message: str,
        caller: str,
        alert_id: str | None = None,
        alert_title: str | None = None,
        alert_severity: str | None = None,
        escalation_id: str | None = None,
        webhook_base_url: str | None = None,
    ) -> dict:
        """Make a call using Twilio."""
        try:
            client = self._get_twilio_client()

            # If webhook URL is provided, use interactive mode
            if webhook_base_url:
                # Use webhook for interactive response (press 1 to ack, etc.)
                import urllib.parse

                params = urllib.parse.urlencode(
                    {
                        "alert_id": alert_id or "",
                        "alert_title": alert_title or message[:100],
                        "alert_severity": alert_severity or "HIGH",
                        "escalation_id": escalation_id or "",
                    }
                )
                webhook_url = f"{webhook_base_url}/api/v1/twilio/voice/alert?{params}"

                call = client.calls.create(
                    to=to_number,
                    from_=caller,
                    url=webhook_url,
                    method="POST",
                )
            else:
                # Simple TwiML mode - just speaks the message
                twiml = f'<Response><Say voice="{self.config.tts_voice}">{message}</Say></Response>'
                call = client.calls.create(to=to_number, from_=caller, twiml=twiml)

            logger.info(f"Twilio call initiated: {to_number}, sid: {call.sid}")
            return {
                "success": True,
                "call_id": call.sid,
                "to": to_number,
                "from_number": caller,
                "status": call.status,
                "provider": "twilio",
            }
        except Exception as e:
            logger.error(f"Twilio call failed to {to_number}: {e}")
            return {"success": False, "error": str(e)}

    async def _make_mock_call(self, to_number: str, message: str, caller: str) -> dict:
        """Make a simulated call using mock service."""
        try:
            logger.info(f"Initiating mock call to {to_number} from {caller}")

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self._get_mock_base_url()}/calls",
                    json={
                        "to": to_number,
                        "from_number": caller,
                        "message": message,
                        "tts_voice": self.config.tts_voice,
                    },
                )
                response.raise_for_status()
                result = response.json()

            logger.info(f"Mock call initiated: {to_number}, call_id: {result.get('call_id')}")
            return result

        except httpx.ConnectError:
            logger.error("Cannot connect to mock telephony service")
            return {"success": False, "error": "Cannot connect to telephony service"}
        except Exception as e:
            logger.error(f"Failed to make call to {to_number}: {e}")
            return {"success": False, "error": str(e)}

    async def send_sms(
        self,
        to_number: str,
        message: str,
        sender_id: str | None = None,
    ) -> dict:
        """
        Send an SMS message.

        Args:
            to_number: Phone number to send to (E.164 format)
            message: SMS message content
            sender_id: Optional sender ID

        Returns:
            dict with SMS status and details
        """
        if not self.config.enabled:
            logger.warning("Telephony is not enabled, skipping SMS")
            return {"success": False, "error": "Telephony is not enabled"}

        sender = sender_id or self.config.default_caller_id

        if self.config.provider == PROVIDER_TWILIO:
            return await self._send_twilio_sms(to_number, message, sender)
        else:
            return await self._send_mock_sms(to_number, message, sender)

    async def _send_twilio_sms(self, to_number: str, message: str, sender: str) -> dict:
        """Send SMS using Twilio."""
        try:
            client = self._get_twilio_client()

            sms = client.messages.create(to=to_number, from_=sender, body=message)

            logger.info(f"Twilio SMS sent: {to_number}, sid: {sms.sid}")
            return {
                "success": True,
                "message_id": sms.sid,
                "to": to_number,
                "from_number": sender,
                "status": sms.status,
                "provider": "twilio",
            }
        except Exception as e:
            logger.error(f"Twilio SMS failed to {to_number}: {e}")
            return {"success": False, "error": str(e)}

    async def _send_mock_sms(self, to_number: str, message: str, sender: str) -> dict:
        """Send simulated SMS using mock service."""
        try:
            logger.info(f"Sending mock SMS to {to_number} from {sender}")

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self._get_mock_base_url()}/sms",
                    json={
                        "to": to_number,
                        "from_number": sender,
                        "message": message,
                    },
                )
                response.raise_for_status()
                result = response.json()

            logger.info(f"Mock SMS sent: {to_number}, message_id: {result.get('message_id')}")
            return result

        except httpx.ConnectError:
            logger.error("Cannot connect to mock telephony service")
            return {"success": False, "error": "Cannot connect to telephony service"}
        except Exception as e:
            logger.error(f"Failed to send SMS to {to_number}: {e}")
            return {"success": False, "error": str(e)}

    async def test_connection(self) -> dict:
        """Test the telephony service connection."""
        if self.config.provider == PROVIDER_TWILIO:
            return await self._test_twilio_connection()
        else:
            return await self._test_mock_connection()

    async def _test_twilio_connection(self) -> dict:
        """Test Twilio connection."""
        try:
            client = self._get_twilio_client()
            # Fetch account info to verify credentials
            account = client.api.accounts(self.config.account_sid).fetch()

            return {
                "success": True,
                "message": "Connected to Twilio",
                "provider": "twilio",
                "account_name": account.friendly_name,
                "account_status": account.status,
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Twilio connection failed: {e}",
                "provider": "twilio",
            }

    async def _test_mock_connection(self) -> dict:
        """Test mock service connection."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"{self._get_mock_base_url()}/health")
                response.raise_for_status()
                result = response.json()

            return {
                "success": True,
                "message": "Connected to mock telephony service",
                "provider": "mock",
                "endpoint": self.config.api_endpoint,
                "service_status": result.get("status"),
            }
        except httpx.ConnectError:
            return {
                "success": False,
                "message": "Cannot connect to mock telephony service",
                "provider": "mock",
                "endpoint": self.config.api_endpoint,
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Connection failed: {e}",
                "provider": "mock",
            }


# Alias for backwards compatibility
FonosterService = TelephonyService


def get_fonoster_service() -> TelephonyService:
    """Build a telephony service from the deployment's environment config.

    This deliberately returns a NEW instance every call rather than a cached
    module-level singleton. The singleton was process-global and mutable: the
    config endpoint wrote one tenant's carrier credentials into it, so the next
    tenant's escalation calls dialled out under the wrong account and caller ID.
    Per-organization credentials now live in ``organization_telephony_config``
    (see :func:`load_org_telephony_config`); this env-derived config is only the
    operator-level default for organizations that have not configured their own.
    """
    return TelephonyService()


# Alias
get_telephony_service = get_fonoster_service


async def load_org_telephony_config(
    db: AsyncSession, organization_id: UUID
) -> TelephonyConfig | None:
    """Load and decrypt an organization's telephony config, or None if unset.

    The provider (mock/twilio/plivo) stays a deployment-level setting; only the
    credentials, endpoint, caller ID and voice are per organization.
    """
    from app.db.models import OrganizationTelephonyConfig
    from app.services.encryption_service import decrypt_credential

    result = await db.execute(
        select(OrganizationTelephonyConfig).where(
            OrganizationTelephonyConfig.organization_id == organization_id
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        return None

    try:
        secret = decrypt_credential(row.access_key_secret_encrypted)
    except Exception:
        logger.error(
            "Failed to decrypt telephony secret for organization %s; treating as unconfigured",
            organization_id,
        )
        return None

    return TelephonyConfig(
        provider=os.getenv("TELEPHONY_PROVIDER", PROVIDER_MOCK),
        api_endpoint=row.api_endpoint,
        account_sid=row.access_key_id,
        auth_token=secret,
        default_caller_id=row.default_caller_id,
        tts_voice=row.tts_voice,
        enabled=row.enabled,
    )


async def resolve_telephony_config(db: AsyncSession, organization_id: UUID) -> TelephonyConfig:
    """Telephony config for an organization, falling back to the env defaults.

    The fallback is the operator's own configuration (mock server in dev), never
    another tenant's stored credentials.
    """
    config = await load_org_telephony_config(db, organization_id)
    if config is not None:
        return config
    return TelephonyService()._load_config_from_env()


async def get_telephony_service_for_org(
    db: AsyncSession, organization_id: UUID
) -> TelephonyService:
    """Build a telephony service bound to one organization's configuration."""
    return TelephonyService(await resolve_telephony_config(db, organization_id))


async def send_escalation_call(
    phone_number: str,
    alert_title: str,
    alert_severity: str,
    alert_id: str,
    alert_description: str = "",
    rule_name: str = "",
    alert_time: str = "",
    log_source: str = "",
    message_template: str | None = None,
    escalation_id: str | None = None,
    webhook_base_url: str | None = None,
    config: TelephonyConfig | None = None,
) -> dict:
    """
    Send an escalation voice call for an alert.

    This is the main entry point for the escalation system to trigger calls.

    Args:
        phone_number: Phone number to call (E.164 format)
        alert_title: Title of the alert
        alert_severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        alert_id: Unique alert identifier
        alert_description: Optional description of the alert
        rule_name: Optional name of the rule that triggered the alert
        alert_time: Optional timestamp of the alert
        log_source: Optional log source (e.g., AWS.CloudTrail, Okta)
        message_template: Optional custom message template with placeholders
        escalation_id: Optional escalation ID for tracking acknowledgments
        webhook_base_url: Optional webhook URL for interactive IVR
        config: The calling organization's telephony config. Callers that have an
            organization in hand MUST pass it; omitting it falls back to the
            deployment-level env config.
    """
    service = TelephonyService(config) if config else get_fonoster_service()

    # Use custom template or default
    template = message_template or DEFAULT_CALL_TEMPLATE
    message = render_message_template(
        template=template,
        title=alert_title,
        severity=alert_severity,
        alert_id=alert_id,
        description=alert_description,
        rule=rule_name,
        time=alert_time,
        source=log_source,
    )

    return await service.make_call(
        to_number=phone_number,
        message=message,
        alert_id=alert_id,
        alert_title=alert_title,
        alert_severity=alert_severity,
        escalation_id=escalation_id,
        webhook_base_url=webhook_base_url,
    )


async def send_escalation_sms(
    phone_number: str,
    alert_title: str,
    alert_severity: str,
    alert_id: str,
    alert_description: str = "",
    rule_name: str = "",
    alert_time: str = "",
    log_source: str = "",
    message_template: str | None = None,
    config: TelephonyConfig | None = None,
) -> dict:
    """
    Send an escalation SMS for an alert.

    This is the main entry point for the escalation system to trigger SMS.

    Args:
        phone_number: Phone number to send to (E.164 format)
        alert_title: Title of the alert
        alert_severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        alert_id: Unique alert identifier
        alert_description: Optional description of the alert
        rule_name: Optional name of the rule that triggered the alert
        alert_time: Optional timestamp of the alert
        log_source: Optional log source (e.g., AWS.CloudTrail, Okta)
        message_template: Optional custom message template with placeholders
        config: The calling organization's telephony config (see
            send_escalation_call).
    """
    service = TelephonyService(config) if config else get_fonoster_service()

    # Use custom template or default
    template = message_template or DEFAULT_SMS_TEMPLATE
    message = render_message_template(
        template=template,
        title=alert_title,
        severity=alert_severity,
        alert_id=alert_id,
        description=alert_description,
        rule=rule_name,
        time=alert_time,
        source=log_source,
    )

    return await service.send_sms(phone_number, message)
