"""
Mock Telephony Server for Local Development

This simulates phone calls and SMS for testing escalation notifications.
In production, replace with real Fonoster, Twilio, or other provider.
"""
import uuid
import logging
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("telephony-mock")

app = FastAPI(
    title="Mock Telephony Service",
    description="Simulates phone calls and SMS for local development",
    version="1.0.0",
)

# In-memory storage for call/SMS history
call_history = []
sms_history = []


class CallRequest(BaseModel):
    to: str
    from_number: Optional[str] = "+1000000000"
    message: str
    tts_voice: Optional[str] = "en-US-Standard-A"


class SmsRequest(BaseModel):
    to: str
    from_number: Optional[str] = "+1000000000"
    message: str


class CallResponse(BaseModel):
    success: bool
    call_id: str
    to: str
    from_number: str
    status: str
    message: str
    timestamp: str


class SmsResponse(BaseModel):
    success: bool
    message_id: str
    to: str
    from_number: str
    status: str
    message: str
    timestamp: str


@app.get("/")
async def root():
    return {
        "service": "Mock Telephony",
        "status": "running",
        "endpoints": {
            "POST /calls": "Make a voice call",
            "POST /sms": "Send an SMS",
            "GET /calls": "List call history",
            "GET /sms": "List SMS history",
            "GET /health": "Health check",
        }
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "telephony-mock"}


@app.post("/calls", response_model=CallResponse)
async def make_call(request: CallRequest):
    """Simulate making a voice call."""
    call_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()

    # Log the call (this is what you'd see in production logs)
    logger.info("=" * 60)
    logger.info("📞 OUTGOING VOICE CALL")
    logger.info("=" * 60)
    logger.info(f"   Call ID:  {call_id}")
    logger.info(f"   To:       {request.to}")
    logger.info(f"   From:     {request.from_number}")
    logger.info(f"   Voice:    {request.tts_voice}")
    logger.info(f"   Message:  {request.message}")
    logger.info(f"   Time:     {timestamp}")
    logger.info("=" * 60)

    call_record = {
        "call_id": call_id,
        "to": request.to,
        "from_number": request.from_number,
        "message": request.message,
        "tts_voice": request.tts_voice,
        "status": "completed",
        "timestamp": timestamp,
    }
    call_history.append(call_record)

    return CallResponse(
        success=True,
        call_id=call_id,
        to=request.to,
        from_number=request.from_number,
        status="completed",
        message="Call simulated successfully (mock mode)",
        timestamp=timestamp,
    )


@app.post("/sms", response_model=SmsResponse)
async def send_sms(request: SmsRequest):
    """Simulate sending an SMS."""
    message_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()

    # Log the SMS
    logger.info("=" * 60)
    logger.info("💬 OUTGOING SMS MESSAGE")
    logger.info("=" * 60)
    logger.info(f"   Message ID: {message_id}")
    logger.info(f"   To:         {request.to}")
    logger.info(f"   From:       {request.from_number}")
    logger.info(f"   Message:    {request.message}")
    logger.info(f"   Time:       {timestamp}")
    logger.info("=" * 60)

    sms_record = {
        "message_id": message_id,
        "to": request.to,
        "from_number": request.from_number,
        "message": request.message,
        "status": "delivered",
        "timestamp": timestamp,
    }
    sms_history.append(sms_record)

    return SmsResponse(
        success=True,
        message_id=message_id,
        to=request.to,
        from_number=request.from_number,
        status="delivered",
        message="SMS simulated successfully (mock mode)",
        timestamp=timestamp,
    )


@app.get("/calls")
async def list_calls(limit: int = 50):
    """Get recent call history."""
    return {
        "calls": call_history[-limit:],
        "total": len(call_history),
    }


@app.get("/sms")
async def list_sms(limit: int = 50):
    """Get recent SMS history."""
    return {
        "messages": sms_history[-limit:],
        "total": len(sms_history),
    }


@app.delete("/history")
async def clear_history():
    """Clear call and SMS history."""
    global call_history, sms_history
    call_history = []
    sms_history = []
    return {"message": "History cleared"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=50051)
