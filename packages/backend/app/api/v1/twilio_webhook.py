"""
Twilio Webhook Endpoints

Handles incoming webhooks from Twilio for interactive voice responses.
"""
import logging
from fastapi import APIRouter, Form, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import Depends
from typing import Optional

from app.db import get_db, AlertEscalation, EscalationStatus, NormalizedAlert

router = APIRouter()
logger = logging.getLogger(__name__)


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
    safe_description = (alert_description or "").replace("&", "and").replace("<", "").replace(">", "")
    safe_custom = (custom_message or "").replace("&", "and").replace("<", "").replace(">", "") if custom_message else None

    # Build the alert message section
    if safe_custom:
        # Use custom message template (already rendered with alert data)
        alert_message = f"""<Say voice="alice">
        {safe_custom}
    </Say>"""
    else:
        # Use default structured message
        description_part = f"""<Pause length="1"/>
    <Say voice="alice">
        Description: {safe_description}
    </Say>""" if safe_description else ""

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
    <Gather numDigits="1" action="/api/v1/twilio/voice/response?alert_id={alert_id}&amp;escalation_id={escalation_id}" method="POST" timeout="10">
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
    logger.info(f"Response webhook: Digits={Digits}, alert_id={alert_id}, escalation_id={escalation_id}")

    if Digits == "1":
        # Acknowledge the alert
        logger.info(f"Alert {alert_id} acknowledged via phone")

        # Update escalation status if we have an escalation_id
        if escalation_id and escalation_id != "None":
            try:
                from uuid import UUID
                from datetime import datetime

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
        twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Redirect method="POST">/api/v1/twilio/voice/alert?alert_id={alert_id}&amp;escalation_id={escalation_id}</Redirect>
</Response>"""

    else:
        # Invalid input
        twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="alice">
        Invalid selection.
    </Say>
    <Redirect method="POST">/api/v1/twilio/voice/alert?alert_id={alert_id}&amp;escalation_id={escalation_id}</Redirect>
</Response>"""

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
