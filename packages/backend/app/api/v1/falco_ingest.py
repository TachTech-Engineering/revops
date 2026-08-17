"""
Falco Ingest Webhook

Receives alerts pushed by Falco (http_output) or Falcosidekick (webhook
output) and buffers them for the Falco connector's sync cycle.

These endpoints cannot carry a user JWT (Falco calls them directly), so they
are authenticated by a per-connector shared ingest token, accepted as an
Authorization: Bearer header, an X-Falco-Token header, or a ?token= query
param (Falco's http_output cannot set custom headers).
"""

import hmac
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.db.models import Connector, ConnectorCategory, ConnectorStatus
from app.services.encryption import get_encryption_service
from app.services.falco_event_buffer import count_pending, push_events

logger = logging.getLogger(__name__)

router = APIRouter()

# Cap events per request so one oversized POST cannot flood the buffer
MAX_EVENTS_PER_REQUEST = 500


def _extract_token(request: Request) -> str | None:
    """Pull the ingest token from header or query param."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    header_token = request.headers.get("X-Falco-Token")
    if header_token:
        return header_token.strip()

    return request.query_params.get("token")


@router.post("/falco/{connector_id}", status_code=status.HTTP_202_ACCEPTED)
async def ingest_falco_alerts(
    connector_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Accept Falco alerts (single object or list) and buffer them for sync."""
    result = await db.execute(
        select(Connector).where(
            and_(
                Connector.id == connector_id,
                Connector.connector_type == "falco",
                Connector.category == ConnectorCategory.DATA_SOURCE,
            )
        )
    )
    connector = result.scalar_one_or_none()
    # 404 for missing, wrong-type, and disabled connectors alike, so the
    # endpoint doesn't confirm which connector IDs exist to unauthenticated
    # callers.
    if not connector or connector.status == ConnectorStatus.DISABLED:
        raise HTTPException(status_code=404, detail="Connector not found")

    expected_token = None
    if connector.credentials_encrypted:
        try:
            credentials = get_encryption_service().decrypt(connector.credentials_encrypted)
            expected_token = credentials.get("ingest_token")
        except Exception:
            logger.exception(f"Failed to decrypt credentials for Falco connector {connector_id}")

    provided_token = _extract_token(request)
    if (
        not expected_token
        or not provided_token
        or not hmac.compare_digest(expected_token, provided_token)
    ):
        raise HTTPException(status_code=401, detail="Invalid ingest token")

    try:
        body: Any = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Body must be valid JSON")

    if isinstance(body, dict):
        events = [body]
    elif isinstance(body, list):
        events = [event for event in body if isinstance(event, dict)]
    else:
        raise HTTPException(
            status_code=400, detail="Body must be a JSON object or array of objects"
        )

    if not events:
        raise HTTPException(status_code=400, detail="No alert objects in body")
    if len(events) > MAX_EVENTS_PER_REQUEST:
        raise HTTPException(
            status_code=413,
            detail=f"Too many events in one request (max {MAX_EVENTS_PER_REQUEST})",
        )

    # Persisted, not held in process memory: this endpoint answers 202 and the
    # sync runs minutes later, so an in-memory buffer lost accepted alerts on
    # every pod restart.
    accepted = await push_events(
        db,
        connector_id=connector_id,
        organization_id=connector.organization_id,
        events=events,
    )
    pending = await count_pending(db, connector_id)
    await db.commit()

    return {
        "accepted": accepted,
        "buffered": pending,
    }
