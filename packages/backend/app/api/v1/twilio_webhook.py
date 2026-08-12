"""
Twilio Webhook Endpoints

Handles incoming webhooks from Twilio for interactive voice responses.

These endpoints cannot carry a JWT (Twilio calls them directly), so they are
authenticated by validating the X-Twilio-Signature header against the
configured TWILIO_AUTH_TOKEN instead (see validate_twilio_signature below).
"""

import logging
import os

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from twilio.request_validator import RequestValidator

from app.config import settings
from app.db import AlertEscalation, EscalationStatus, get_db

logger = logging.getLogger(__name__)


async def validate_twilio_signature(request: Request) -> None:
    """
    Authenticate a Twilio webhook by validating its X-Twilio-Signature header.

    Twilio signs each request with base64(HMAC-SHA1(auth_token, full public
    URL + sorted POST form params concatenated)); RequestValidator implements
    that scheme. The auth token comes from TWILIO_AUTH_TOKEN (same env var the
    calling side, app/services/fonoster.py, uses). If no token is configured
    the endpoints refuse to serve (503) rather than accept unsigned requests.

    URL construction caveat: the signature covers the PUBLIC URL Twilio
    requested. Behind a reverse proxy request.url is the internal address, so
    when settings.public_base_url is set we rebuild the URL from it (scheme +
    host) plus the request path and query string. Without it we fall back to
    str(request.url), which only validates correctly if the app is reached at
    its public address (or the proxy faithfully forwards scheme/host).
    """
    auth_token = os.getenv("TWILIO_AUTH_TOKEN", "")
    if not auth_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Twilio webhooks are not configured (TWILIO_AUTH_TOKEN is not set)",
        )

    signature = request.headers.get("X-Twilio-Signature")
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing X-Twilio-Signature header",
        )

    if settings.public_base_url:
        url = settings.public_base_url.rstrip("/") + request.url.path
        if request.url.query:
            url += "?" + request.url.query
    else:
        url = str(request.url)

    # Twilio signs the POST form parameters (x-www-form-urlencoded values).
    # Starlette caches the parsed form, so the endpoint's Form(...) params
    # still work after this read.
    form = await request.form()
    params = {key: value for key, value in form.items() if isinstance(value, str)}

    if not RequestValidator(auth_token).validate(url, params, signature):
        logger.warning("Rejected Twilio webhook with invalid signature for %s", request.url.path)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid Twilio signature",
        )


router = APIRouter(dependencies=[Depends(validate_twilio_signature)])


def twiml_response(twiml: str) -> Response:
    """Return a TwiML response."""
    return Response(content=twiml, media_type="application/xml")


@router.post("/voice/alert")
async def alert_voice_webhook(
    alert_id: str = Form(None),
    alert_title: str = Form("Security Alert"),
    alert_severity: str = Form("HIGH"),
    escalation_id: str = Form(None),
    alert_description: str = Form(""),
    custom_message: str = Form(None),
):
    """
    Initial voice webhook - speaks the alert and gathers response.
    Called when Twilio first connects the call.

    If custom_message is provided, it will be spoken instead of the default message.
    """
    logger.info(f"Voice webhook called for alert: {alert_id}")

    # Clean the title for TTS (remove special characters that might cause issues)
    safe_title = alert_title.replace("&", "and").replace("<", "").replace(">", "")
    safe_description = (
        (alert_description or "").replace("&", "and").replace("<", "").replace(">", "")
    )
    safe_custom = (
        (custom_message or "").replace("&", "and").replace("<", "").replace(">", "")
        if custom_message
        else None
    )

    # Build the alert message section
    if safe_custom:
        # Use custom message template (already rendered with alert data)
        alert_message = f"""<Say voice="alice">
        {safe_custom}
    </Say>"""
    else:
        # Use default structured message
        description_part = (
            f"""<Pause length="1"/>
    <Say voice="alice">
        Description: {safe_description}
    </Say>"""
            if safe_description
            else ""
        )

        alert_message = f"""<Say voice="alice">
        Attention! This is an urgent security alert from Panther Dashboard.
    </Say>
    <Pause length="1"/>
    <Say voice="alice">
        A {alert_severity} severity alert has been triggered.
    </Say>
    <Pause length="1"/>
    <Say voice="alice">
        Alert: {safe_title}
    </Say>{description_part}"""

    twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    {alert_message}
    <Pause length="1"/>
    <Gather numDigits="1"
    action="/api/v1/twilio/voice/response?alert_id={alert_id}&amp;escalation_id={escalation_id}"
    method="POST" timeout="10">
        <Say voice="alice">
            Press 1 to acknowledge this alert.
            Press 2 to escalate to the next responder.
            Press 3 to repeat this message.
        </Say>
    </Gather>
    <Say voice="alice">
        No response received. The alert will be escalated automatically.
    </Say>
</Response>"""

    return twiml_response(twiml)


@router.post("/voice/response")
async def alert_response_webhook(
    Digits: str = Form(None),
    alert_id: str = None,
    escalation_id: str = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Handle user's keypress response.
    1 = Acknowledge
    2 = Escalate
    3 = Repeat
    """
    logger.info(
        f"Response webhook: Digits={Digits}, alert_id={alert_id}, escalation_id={escalation_id}"
    )

    if Digits == "1":
        # Acknowledge the alert
        logger.info(f"Alert {alert_id} acknowledged via phone")

        # Update escalation status if we have an escalation_id
        if escalation_id and escalation_id != "None":
            try:
                from datetime import datetime
                from uuid import UUID

                result = await db.execute(
                    select(AlertEscalation).where(AlertEscalation.id == UUID(escalation_id))
                )
                escalation = result.scalar_one_or_none()
                if escalation:
                    escalation.status = EscalationStatus.ACKNOWLEDGED
                    escalation.acknowledged_at = datetime.utcnow()
                    escalation.acknowledged_by = "phone_response"
                    await db.commit()
                    logger.info(f"Escalation {escalation_id} marked as acknowledged")
            except Exception as e:
                logger.error(f"Failed to update escalation: {e}")

        twiml = """<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="alice">
        Alert acknowledged. Thank you for your response.
        Please check your dashboard for full details.
        Goodbye.
    </Say>
</Response>"""

    elif Digits == "2":
        # Escalate to next responder
        logger.info(f"Alert {alert_id} being escalated via phone request")

        twiml = """<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="alice">
        Understood. This alert will be escalated to the next responder.
        Goodbye.
    </Say>
</Response>"""

    elif Digits == "3":
        # Repeat the message - redirect back to the alert webhook
        twiml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<Response>\n"
            '    <Redirect method="POST">/api/v1/twilio/voice/alert'
            f"?alert_id={alert_id}&amp;escalation_id={escalation_id}</Redirect>\n"
            "</Response>"
        )

    else:
        # Invalid input
        twiml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<Response>\n"
            '    <Say voice="alice">\n'
            "        Invalid selection.\n"
            "    </Say>\n"
            '    <Redirect method="POST">/api/v1/twilio/voice/alert'
            f"?alert_id={alert_id}&amp;escalation_id={escalation_id}</Redirect>\n"
            "</Response>"
        )

    return twiml_response(twiml)


@router.post("/sms/response")
async def sms_response_webhook(
    From: str = Form(None),
    Body: str = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Handle SMS responses from users.
    Users can reply with ACK or 1 to acknowledge.
    """
    logger.info(f"SMS response from {From}: {Body}")

    body_lower = (Body or "").strip().lower()

    if body_lower in ["1", "ack", "acknowledge", "ok", "yes"]:
        # Try to find and acknowledge the most recent escalation for this phone number
        # This is a simplified lookup - in production you'd track alert_id in the SMS
        response = "Alert acknowledged. Check dashboard for details."
    else:
        response = "Reply ACK or 1 to acknowledge the alert."

    twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Message>{response}</Message>
</Response>"""

    return twiml_response(twiml)
